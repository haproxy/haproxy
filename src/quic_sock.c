/*
 * QUIC socket management.
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE /* required for struct in6_pktinfo */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global-t.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/pool.h>
#include <haproxy/proto_quic.h>
#include <haproxy/proxy-t.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_quic

#define TRACE_SOURCE    &trace_quic

/* Retrieve a connection's source address. Returns -1 on failure. */
int quic_sock_get_src(struct connection *conn, struct sockaddr *addr, socklen_t len)
{
	struct quic_conn *qc;

	if (!conn || !conn->handle.qc)
		return -1;

	qc = conn->handle.qc;
	if (conn_is_back(conn)) {
		/* no source address defined for outgoing connections for now */
		return -1;
	} else {
		/* front connection, return the peer's address */
		if (len > sizeof(qc->peer_addr))
			len = sizeof(qc->peer_addr);
		memcpy(addr, &qc->peer_addr, len);
		return 0;
	}
}

/* Retrieve a connection's destination address. Returns -1 on failure. */
int quic_sock_get_dst(struct connection *conn, struct sockaddr *addr, socklen_t len)
{
	struct quic_conn *qc;

	if (!conn || !conn->handle.qc)
		return -1;

	qc = conn->handle.qc;
	if (conn_is_back(conn)) {
		/* back connection, return the peer's address */
		if (len > sizeof(qc->peer_addr))
			len = sizeof(qc->peer_addr);
		memcpy(addr, &qc->peer_addr, len);
	} else {
		struct sockaddr_storage *from;

		/* Return listener address if IP_PKTINFO or friends are not
		 * supported by the socket.
		 */
		BUG_ON(!qc->li);
		from = is_addr(&qc->local_addr) ? &qc->local_addr :
		                                  &qc->li->rx.addr;
		if (len > sizeof(*from))
			len = sizeof(*from);
		memcpy(addr, from, len);
	}
	return 0;
}

/*
 * Inspired from session_accept_fd().
 * Instantiate a new connection (connection struct) to be attached to <qc>
 * QUIC connection of <l> listener.
 * Returns 1 if succeeded, 0 if not.
 */
static int new_quic_cli_conn(struct quic_conn *qc, struct listener *l,
                             struct sockaddr_storage *saddr)
{
	struct connection *cli_conn;

	if (unlikely((cli_conn = conn_new(&l->obj_type)) == NULL))
		goto out;

	if (!sockaddr_alloc(&cli_conn->src, saddr, sizeof *saddr))
		goto out_free_conn;

	cli_conn->flags |= CO_FL_FDLESS;
	qc->conn = cli_conn;
	cli_conn->handle.qc = qc;

	cli_conn->target = &l->obj_type;

	return 1;

 out_free_conn:
	qc->conn = NULL;
	conn_stop_tracking(cli_conn);
	conn_xprt_close(cli_conn);
	conn_free(cli_conn);
 out:

	return 0;
}

/* Tests if the receiver supports accepting connections. Returns positive on
 * success, 0 if not possible
 */
int quic_sock_accepting_conn(const struct receiver *rx)
{
	return 1;
}

/* Accept an incoming connection from listener <l>, and return it, as well as
 * a CO_AC_* status code into <status> if not null. Null is returned on error.
 * <l> must be a valid listener with a valid frontend.
 */
struct connection *quic_sock_accept_conn(struct listener *l, int *status)
{
	struct quic_conn *qc;
	struct li_per_thread *lthr = &l->per_thr[tid];

	qc = MT_LIST_POP(&lthr->quic_accept.conns, struct quic_conn *, accept_list);
	if (!qc)
		goto done;

	if (!new_quic_cli_conn(qc, l, &qc->peer_addr))
		goto err;

 done:
	*status = CO_AC_DONE;
	return qc ? qc->conn : NULL;

 err:
	/* in case of error reinsert the element to process it later. */
	MT_LIST_INSERT(&lthr->quic_accept.conns, &qc->accept_list);

	*status = CO_AC_PAUSE;
	return NULL;
}

/* QUIC datagrams handler task. */
struct task *quic_lstnr_dghdlr(struct task *t, void *ctx, unsigned int state)
{
	struct quic_dghdlr *dghdlr = ctx;
	struct quic_dgram *dgram;
	int max_dgrams = global.tune.maxpollevents;

	TRACE_ENTER(QUIC_EV_CONN_LPKT);

	while ((dgram = MT_LIST_POP(&dghdlr->dgrams, typeof(dgram), handler_list))) {
		if (quic_dgram_parse(dgram, NULL, dgram->owner)) {
			/* TODO should we requeue the datagram ? */
			break;
		}

		if (--max_dgrams <= 0)
			goto stop_here;
	}

	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return t;

 stop_here:
	/* too much work done at once, come back here later */
	if (!MT_LIST_ISEMPTY(&dghdlr->dgrams))
		tasklet_wakeup((struct tasklet *)t);

	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return t;
}

/* Retrieve the DCID from the datagram found in <buf> and deliver it to the
 * correct datagram handler.
 * Return 1 if a correct datagram could be found, 0 if not.
 */
static int quic_lstnr_dgram_dispatch(unsigned char *buf, size_t len, void *owner,
                                     struct sockaddr_storage *saddr,
                                     struct sockaddr_storage *daddr,
                                     struct quic_dgram *new_dgram, struct list *dgrams)
{
	struct quic_dgram *dgram;
	const struct listener *l = owner;
	unsigned char *dcid;
	size_t dcid_len;
	int cid_tid;

	if (!len || !quic_get_dgram_dcid(buf, buf + len, &dcid, &dcid_len))
		goto err;

	dgram = new_dgram ? new_dgram : pool_alloc(pool_head_quic_dgram);
	if (!dgram)
		goto err;

	cid_tid = quic_get_cid_tid(dcid, &l->rx);

	/* All the members must be initialized! */
	dgram->owner = owner;
	dgram->buf = buf;
	dgram->len = len;
	dgram->dcid = dcid;
	dgram->dcid_len = dcid_len;
	dgram->saddr = *saddr;
	dgram->daddr = *daddr;
	dgram->qc = NULL;

	/* Attached datagram to its quic_receiver_buf and quic_dghdlrs. */
	LIST_APPEND(dgrams, &dgram->recv_list);
	MT_LIST_APPEND(&quic_dghdlrs[cid_tid].dgrams, &dgram->handler_list);

	/* typically quic_lstnr_dghdlr() */
	tasklet_wakeup(quic_dghdlrs[cid_tid].task);

	return 1;

 err:
	pool_free(pool_head_quic_dgram, new_dgram);
	return 0;
}

/* This function is responsible to remove unused datagram attached in front of
 * <buf>. Each instances will be freed until a not yet consumed datagram is
 * found or end of the list is hit. The last unused datagram found is not freed
 * and is instead returned so that the caller can reuse it if needed.
 *
 * Returns the last unused datagram or NULL if no occurrence found.
 */
static struct quic_dgram *quic_rxbuf_purge_dgrams(struct quic_receiver_buf *buf)
{
	struct quic_dgram *cur, *prev = NULL;

	while (!LIST_ISEMPTY(&buf->dgram_list)) {
		cur = LIST_ELEM(buf->dgram_list.n, struct quic_dgram *, recv_list);

		/* Loop until a not yet consumed datagram is found. */
		if (HA_ATOMIC_LOAD(&cur->buf))
			break;

		/* Clear buffer of current unused datagram. */
		LIST_DELETE(&cur->recv_list);
		b_del(&buf->buf, cur->len);

		/* Free last found unused datagram. */
		if (prev)
			pool_free(pool_head_quic_dgram, prev);
		prev = cur;
	}

	/* Return last unused datagram found. */
	return prev;
}

/* Receive data from datagram socket <fd>. Data are placed in <out> buffer of
 * length <len>.
 *
 * Datagram addresses will be returned via the next arguments. <from> will be
 * the peer address and <to> the reception one. Note that <to> can only be
 * retrieved if the socket supports IP_PKTINFO or affiliated options. If not,
 * <to> will be set as AF_UNSPEC. The caller must specify <to_port> to ensure
 * that <to> address is completely filled.
 *
 * Returns value from recvmsg syscall.
 */
static ssize_t quic_recv(int fd, void *out, size_t len,
                         struct sockaddr *from, socklen_t from_len,
                         struct sockaddr *to, socklen_t to_len,
                         uint16_t dst_port)
{
	union pktinfo {
#ifdef IP_PKTINFO
		struct in_pktinfo in;
#else /* !IP_PKTINFO */
		struct in_addr addr;
#endif
#ifdef IPV6_RECVPKTINFO
		struct in6_pktinfo in6;
#endif
	};
	char cdata[CMSG_SPACE(sizeof(union pktinfo))];
	struct msghdr msg;
	struct iovec vec;
	struct cmsghdr *cmsg;
	ssize_t ret;

	vec.iov_base = out;
	vec.iov_len  = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name    = from;
	msg.msg_namelen = from_len;
	msg.msg_iov     = &vec;
	msg.msg_iovlen  = 1;
	msg.msg_control = &cdata;
	msg.msg_controllen = sizeof(cdata);

	clear_addr((struct sockaddr_storage *)to);

	do {
		ret = recvmsg(fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	/* TODO handle errno. On EAGAIN/EWOULDBLOCK use fd_cant_recv() if
	 * using dedicated connection socket.
	 */

	if (ret < 0)
		goto end;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		switch (cmsg->cmsg_level) {
		case IPPROTO_IP:
#if defined(IP_PKTINFO)
			if (cmsg->cmsg_type == IP_PKTINFO) {
				struct sockaddr_in *in = (struct sockaddr_in *)to;
				struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);

				if (to_len >= sizeof(struct sockaddr_in)) {
					in->sin_family = AF_INET;
					in->sin_addr = info->ipi_addr;
					in->sin_port = dst_port;
				}
			}
#elif defined(IP_RECVDSTADDR)
			if (cmsg->cmsg_type == IP_RECVDSTADDR) {
				struct sockaddr_in *in = (struct sockaddr_in *)to;
				struct in_addr *info = (struct in_addr *)CMSG_DATA(cmsg);

				if (to_len >= sizeof(struct sockaddr_in)) {
					in->sin_family = AF_INET;
					in->sin_addr.s_addr = info->s_addr;
					in->sin_port = dst_port;
				}
			}
#endif /* IP_PKTINFO || IP_RECVDSTADDR */
			break;

		case IPPROTO_IPV6:
#ifdef IPV6_RECVPKTINFO
			if (cmsg->cmsg_type == IPV6_PKTINFO) {
				struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)to;
				struct in6_pktinfo *info6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);

				if (to_len >= sizeof(struct sockaddr_in6)) {
					in6->sin6_family = AF_INET6;
					memcpy(&in6->sin6_addr, &info6->ipi6_addr, sizeof(in6->sin6_addr));
					in6->sin6_port = dst_port;
				}
			}
#endif
			break;
		}
	}

 end:
	return ret;
}

/* Function called on a read event from a listening socket. It tries
 * to handle as many connections as possible.
 */
void quic_lstnr_sock_fd_iocb(int fd)
{
	ssize_t ret;
	struct quic_receiver_buf *rxbuf;
	struct buffer *buf;
	struct listener *l = objt_listener(fdtab[fd].owner);
	struct quic_transport_params *params;
	/* Source address */
	struct sockaddr_storage saddr = {0}, daddr = {0};
	size_t max_sz, cspace;
	struct quic_dgram *new_dgram;
	unsigned char *dgram_buf;
	int max_dgrams;

	BUG_ON(!l);

	new_dgram = NULL;
	if (!l)
		return;

	if (!(fdtab[fd].state & FD_POLL_IN) || !fd_recv_ready(fd))
		return;

	rxbuf = MT_LIST_POP(&l->rx.rxbuf_list, typeof(rxbuf), rxbuf_el);
	if (!rxbuf)
		goto out;

	buf = &rxbuf->buf;

	max_dgrams = global.tune.maxpollevents;
 start:
	/* Try to reuse an existing dgram. Note that there is always at
	 * least one datagram to pick, except the first time we enter
	 * this function for this <rxbuf> buffer.
	 */
	new_dgram = quic_rxbuf_purge_dgrams(rxbuf);

	params = &l->bind_conf->quic_params;
	max_sz = params->max_udp_payload_size;
	cspace = b_contig_space(buf);
	if (cspace < max_sz) {
		struct proxy *px = l->bind_conf->frontend;
		struct quic_counters *prx_counters = EXTRA_COUNTERS_GET(px->extra_counters_fe, &quic_stats_module);
		struct quic_dgram *dgram;

		/* Do no mark <buf> as full, and do not try to consume it
		 * if the contiguous remaining space is not at the end
		 */
		if (b_tail(buf) + cspace < b_wrap(buf)) {
			HA_ATOMIC_INC(&prx_counters->rxbuf_full);
			goto out;
		}

		/* Allocate a fake datagram, without data to locate
		 * the end of the RX buffer (required during purging).
		 */
		dgram = pool_alloc(pool_head_quic_dgram);
		if (!dgram)
			goto out;

		/* Initialize only the useful members of this fake datagram. */
		dgram->buf = NULL;
		dgram->len = cspace;
		/* Append this datagram only to the RX buffer list. It will
		 * not be treated by any datagram handler.
		 */
		LIST_APPEND(&rxbuf->dgram_list, &dgram->recv_list);

		/* Consume the remaining space */
		b_add(buf, cspace);
		if (b_contig_space(buf) < max_sz) {
			HA_ATOMIC_INC(&prx_counters->rxbuf_full);
			goto out;
		}
	}

	dgram_buf = (unsigned char *)b_tail(buf);
	ret = quic_recv(fd, dgram_buf, max_sz,
	                (struct sockaddr *)&saddr, sizeof(saddr),
	                (struct sockaddr *)&daddr, sizeof(daddr),
	                get_net_port(&l->rx.addr));
	if (ret <= 0)
		goto out;

	b_add(buf, ret);
	if (!quic_lstnr_dgram_dispatch(dgram_buf, ret, l, &saddr, &daddr,
	                               new_dgram, &rxbuf->dgram_list)) {
		/* If wrong, consume this datagram */
		b_sub(buf, ret);
	}
	new_dgram = NULL;
	if (--max_dgrams > 0)
		goto start;
 out:
	pool_free(pool_head_quic_dgram, new_dgram);
	MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->rxbuf_el);
}

/* FD-owned quic-conn socket callback. */
static void quic_conn_sock_fd_iocb(int fd)
{
	struct quic_conn *qc = fdtab[fd].owner;

	TRACE_ENTER(QUIC_EV_CONN_RCV, qc);

	tasklet_wakeup_after(NULL, qc->wait_event.tasklet);
	fd_stop_recv(fd);

	TRACE_LEAVE(QUIC_EV_CONN_RCV, qc);
}

/* Send a datagram stored into <buf> buffer with <sz> as size.
 * The caller must ensure there is at least <sz> bytes in this buffer.
 *
 * Returns 0 on success else non-zero. When failed, this function also
 * sets <*syscall_errno> to the errno only when the send*() syscall failed.
 * As the C library will never set errno to 0, the caller must set
 * <*syscall_errno> to 0 before calling this function to be sure to get
 * the correct errno in case a send*() syscall failure.
 *
 * TODO standardize this function for a generic UDP sendto wrapper. This can be
 * done by removing the <qc> arg and replace it with address/port.
 */
int qc_snd_buf(struct quic_conn *qc, const struct buffer *buf, size_t sz,
               int flags, int *syscall_errno)
{
	ssize_t ret;

	do {
		if (qc_test_fd(qc)) {
			ret = send(qc->fd, b_peek(buf, b_head_ofs(buf)), sz,
			           MSG_DONTWAIT | MSG_NOSIGNAL);
		}
#if defined(IP_PKTINFO) || defined(IP_RECVDSTADDR) || defined(IPV6_RECVPKTINFO)
		else if (is_addr(&qc->local_addr)) {
			struct msghdr msg = { 0 };
			struct iovec vec;
			struct cmsghdr *cmsg;
#ifdef IP_PKTINFO
			struct in_pktinfo in;
#endif /* IP_PKTINFO */
#ifdef IPV6_RECVPKTINFO
			struct in6_pktinfo in6;
#endif /* IPV6_RECVPKTINFO */
			union {
#ifdef IP_PKTINFO
				char buf[CMSG_SPACE(sizeof(in))];
#endif /* IP_PKTINFO */
#ifdef IPV6_RECVPKTINFO
				char buf6[CMSG_SPACE(sizeof(in6))];
#endif /* IPV6_RECVPKTINFO */
				char bufaddr[CMSG_SPACE(sizeof(struct in_addr))];
				struct cmsghdr align;
			} u;

			vec.iov_base = b_peek(buf, b_head_ofs(buf));
			vec.iov_len = sz;
			msg.msg_name = &qc->peer_addr;
			msg.msg_namelen = get_addr_len(&qc->peer_addr);
			msg.msg_iov = &vec;
			msg.msg_iovlen = 1;

			switch (qc->local_addr.ss_family) {
			case AF_INET:
#if defined(IP_PKTINFO)
				memset(&in, 0, sizeof(in));
				memcpy(&in.ipi_spec_dst,
				       &((struct sockaddr_in *)&qc->local_addr)->sin_addr,
				       sizeof(struct in_addr));

				msg.msg_control = u.buf;
				msg.msg_controllen = sizeof(u.buf);

				cmsg = CMSG_FIRSTHDR(&msg);
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
				memcpy(CMSG_DATA(cmsg), &in, sizeof(in));
#elif defined(IP_RECVDSTADDR)
				msg.msg_control = u.bufaddr;
				msg.msg_controllen = sizeof(u.bufaddr);

				cmsg = CMSG_FIRSTHDR(&msg);
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_SENDSRCADDR;
				cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
				memcpy(CMSG_DATA(cmsg),
				       &((struct sockaddr_in *)&qc->local_addr)->sin_addr,
				       sizeof(struct in_addr));
#endif /* IP_PKTINFO || IP_RECVDSTADDR */
				break;

			case AF_INET6:
#ifdef IPV6_RECVPKTINFO
				memset(&in6, 0, sizeof(in6));
				memcpy(&in6.ipi6_addr,
				       &((struct sockaddr_in6 *)&qc->local_addr)->sin6_addr,
				       sizeof(struct in6_addr));

				msg.msg_control = u.buf6;
				msg.msg_controllen = sizeof(u.buf6);

				cmsg = CMSG_FIRSTHDR(&msg);
				cmsg->cmsg_level = IPPROTO_IPV6;
				cmsg->cmsg_type = IPV6_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
				memcpy(CMSG_DATA(cmsg), &in6, sizeof(in6));
#endif /* IPV6_RECVPKTINFO */
				break;

			default:
				break;
			}

			ret = sendmsg(qc->li->rx.fd, &msg,
			              MSG_DONTWAIT|MSG_NOSIGNAL);
		}
#endif /* IP_PKTINFO || IP_RECVDSTADDR || IPV6_RECVPKTINFO */
		else {
			ret = sendto(qc->li->rx.fd, b_peek(buf, b_head_ofs(buf)), sz,
			             MSG_DONTWAIT|MSG_NOSIGNAL,
			             (struct sockaddr *)&qc->peer_addr,
			             get_addr_len(&qc->peer_addr));
		}
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		struct proxy *prx = qc->li->bind_conf->frontend;
		struct quic_counters *prx_counters =
		  EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                     &quic_stats_module);

		*syscall_errno = errno;
		/* TODO adjust errno for UDP context. */
		if (errno == EAGAIN || errno == EWOULDBLOCK ||
		    errno == ENOTCONN || errno == EINPROGRESS || errno == EBADF) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				HA_ATOMIC_INC(&prx_counters->socket_full);
			else
				HA_ATOMIC_INC(&prx_counters->sendto_err);
		}
		else if (errno) {
			/* TODO unlisted errno : handle it explicitly.
			 * ECONNRESET may be encounter on quic-conn socket.
			 */
			HA_ATOMIC_INC(&prx_counters->sendto_err_unknown);
		}

		/* Note that one must not consider that this macro will not modify errno. */
		TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_LPKT, qc, 0, 0, 0,
		             "syscall error (errno=%d)", *syscall_errno);

		return 1;
	}

	if (ret != sz)
		return 1;

	/* we count the total bytes sent, and the send rate for 32-byte blocks.
	 * The reason for the latter is that freq_ctr are limited to 4GB and
	 * that it's not enough per second.
	 */
	_HA_ATOMIC_ADD(&th_ctx->out_bytes, ret);
	update_freq_ctr(&th_ctx->out_32bps, (ret + 16) / 32);

	return 0;
}

/* Receive datagram on <qc> FD-owned socket.
 *
 * Returns the total number of bytes read or a negative value on error.
 */
int qc_rcv_buf(struct quic_conn *qc)
{
	struct sockaddr_storage saddr = {0}, daddr = {0};
	struct quic_transport_params *params;
	struct quic_dgram *new_dgram = NULL;
	struct buffer buf = BUF_NULL;
	size_t max_sz;
	unsigned char *dgram_buf;
	struct listener *l;
	ssize_t ret = 0;

	/* Do not call this if quic-conn FD is uninitialized. */
	BUG_ON(qc->fd < 0);

	TRACE_ENTER(QUIC_EV_CONN_RCV, qc);
	l = qc->li;

	params = &l->bind_conf->quic_params;
	max_sz = params->max_udp_payload_size;

	do {
		if (!b_alloc(&buf))
			break; /* TODO subscribe for memory again available. */

		b_reset(&buf);
		BUG_ON(b_contig_space(&buf) < max_sz);

		/* Allocate datagram on first loop or after requeuing. */
		if (!new_dgram && !(new_dgram = pool_alloc(pool_head_quic_dgram)))
			break; /* TODO subscribe for memory again available. */

		dgram_buf = (unsigned char *)b_tail(&buf);
		ret = quic_recv(qc->fd, dgram_buf, max_sz,
		                (struct sockaddr *)&saddr, sizeof(saddr),
		                (struct sockaddr *)&daddr, sizeof(daddr),
		                get_net_port(&qc->local_addr));
		if (ret <= 0) {
			/* Subscribe FD for future reception. */
			fd_want_recv(qc->fd);
			break;
		}

		b_add(&buf, ret);

		new_dgram->buf = dgram_buf;
		new_dgram->len = ret;
		new_dgram->dcid_len = 0;
		new_dgram->dcid = NULL;
		new_dgram->saddr = saddr;
		new_dgram->daddr = daddr;
		new_dgram->qc = NULL;  /* set later via quic_dgram_parse() */

		TRACE_DEVEL("read datagram", QUIC_EV_CONN_RCV, qc, new_dgram);

		if (!quic_get_dgram_dcid(new_dgram->buf,
		                         new_dgram->buf + new_dgram->len,
		                         &new_dgram->dcid, &new_dgram->dcid_len)) {
			continue;
		}

		if (!qc_check_dcid(qc, new_dgram->dcid, new_dgram->dcid_len)) {
			/* Datagram received by error on the connection FD, dispatch it
			 * to its associated quic-conn.
			 *
			 * TODO count redispatch datagrams.
			 */
			struct quic_receiver_buf *rxbuf;
			struct quic_dgram *tmp_dgram;
			unsigned char *rxbuf_tail;

			TRACE_STATE("datagram for other connection on quic-conn socket, requeue it", QUIC_EV_CONN_RCV, qc);

			rxbuf = MT_LIST_POP(&l->rx.rxbuf_list, typeof(rxbuf), rxbuf_el);

			tmp_dgram = quic_rxbuf_purge_dgrams(rxbuf);
			pool_free(pool_head_quic_dgram, tmp_dgram);

			if (b_contig_space(&rxbuf->buf) < new_dgram->len) {
				/* TODO count lost datagrams */
				MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->rxbuf_el);
				continue;
			}

			rxbuf_tail = (unsigned char *)b_tail(&rxbuf->buf);
			__b_putblk(&rxbuf->buf, (char *)dgram_buf, new_dgram->len);
			if (!quic_lstnr_dgram_dispatch(rxbuf_tail, ret, l, &qc->peer_addr, &daddr,
			                               new_dgram, &rxbuf->dgram_list)) {
				/* TODO count lost datagrams. */
				b_sub(&buf, ret);
			}
			else {
				/* datagram must not be freed as it was requeued. */
				new_dgram = NULL;
			}

			MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->rxbuf_el);
			continue;
		}

		quic_dgram_parse(new_dgram, qc, qc->li);
		/* A datagram must always be consumed after quic_parse_dgram(). */
		BUG_ON(new_dgram->buf);
	} while (ret > 0);

	pool_free(pool_head_quic_dgram, new_dgram);

	if (b_size(&buf)) {
		b_free(&buf);
		offer_buffers(NULL, 1);
	}

	TRACE_LEAVE(QUIC_EV_CONN_RCV, qc);
	return ret;
}

/* Allocate a socket file-descriptor specific for QUIC connection <qc>.
 * Endpoint addresses are specified by the two following arguments : <src> is
 * the local address and <dst> is the remote one.
 *
 * Return the socket FD or a negative error code. On error, socket is marked as
 * uninitialized.
 */
void qc_alloc_fd(struct quic_conn *qc, const struct sockaddr_storage *src,
                 const struct sockaddr_storage *dst)
{
	struct proxy *p = qc->li->bind_conf->frontend;
	int fd = -1;
	int ret;

	/* Must not happen. */
	BUG_ON(src->ss_family != dst->ss_family);

	qc_init_fd(qc);

	fd = socket(src->ss_family, SOCK_DGRAM, 0);
	if (fd < 0)
		goto err;

	if (fd >= global.maxsock) {
		send_log(p, LOG_EMERG,
		         "Proxy %s reached the configured maximum connection limit. Please check the global 'maxconn' value.\n",
		         p->id);
		goto err;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ret < 0)
		goto err;

	switch (src->ss_family) {
	case AF_INET:
#if defined(IP_PKTINFO)
		ret = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
#elif defined(IP_RECVDSTADDR)
		ret = setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &one, sizeof(one));
#endif /* IP_PKTINFO || IP_RECVDSTADDR */
		break;
	case AF_INET6:
#ifdef IPV6_RECVPKTINFO
		ret = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
		break;
	}
	if (ret < 0)
		goto err;

	ret = bind(fd, (struct sockaddr *)src, get_addr_len(src));
	if (ret < 0)
		goto err;

	ret = connect(fd, (struct sockaddr *)dst, get_addr_len(dst));
	if (ret < 0)
		goto err;

	qc->fd = fd;
	fd_set_nonblock(fd);
	fd_insert(fd, qc, quic_conn_sock_fd_iocb, tgid, ti->ltid_bit);
	fd_want_recv(fd);

	return;

 err:
	if (fd >= 0)
		close(fd);
}

/* Release socket file-descriptor specific for QUIC connection <qc>. Set
 * <reinit> if socket should be reinitialized after address migration.
 */
void qc_release_fd(struct quic_conn *qc, int reinit)
{
	if (qc_test_fd(qc)) {
		fd_delete(qc->fd);
		qc->fd = DEAD_FD_MAGIC;

		if (reinit)
			qc_init_fd(qc);
	}
}

/*********************** QUIC accept queue management ***********************/
/* per-thread accept queues */
struct quic_accept_queue *quic_accept_queues;

/* Install <qc> on the queue ready to be accepted. The queue task is then woken
 * up. If <qc> accept is already scheduled or done, nothing is done.
 */
void quic_accept_push_qc(struct quic_conn *qc)
{
	struct quic_accept_queue *queue = &quic_accept_queues[qc->tid];
	struct li_per_thread *lthr = &qc->li->per_thr[qc->tid];

	/* early return if accept is already in progress/done for this
	 * connection
	 */
	if (qc->flags & QUIC_FL_CONN_ACCEPT_REGISTERED)
		return;

	BUG_ON(MT_LIST_INLIST(&qc->accept_list));

	qc->flags |= QUIC_FL_CONN_ACCEPT_REGISTERED;
	/* 1. insert the listener in the accept queue
	 *
	 * Use TRY_APPEND as there is a possible race even with INLIST if
	 * multiple threads try to add the same listener instance from several
	 * quic_conn.
	 */
	if (!MT_LIST_INLIST(&(lthr->quic_accept.list)))
		MT_LIST_TRY_APPEND(&queue->listeners, &(lthr->quic_accept.list));

	/* 2. insert the quic_conn in the listener per-thread queue. */
	MT_LIST_APPEND(&lthr->quic_accept.conns, &qc->accept_list);

	/* 3. wake up the queue tasklet */
	tasklet_wakeup(quic_accept_queues[qc->tid].tasklet);
}

/* Tasklet handler to accept QUIC connections. Call listener_accept on every
 * listener instances registered in the accept queue.
 */
struct task *quic_accept_run(struct task *t, void *ctx, unsigned int i)
{
	struct li_per_thread *lthr;
	struct mt_list *elt1, elt2;
	struct quic_accept_queue *queue = &quic_accept_queues[tid];

	mt_list_for_each_entry_safe(lthr, &queue->listeners, quic_accept.list, elt1, elt2) {
		listener_accept(lthr->li);
		MT_LIST_DELETE_SAFE(elt1);
	}

	return NULL;
}

static int quic_alloc_accept_queues(void)
{
	int i;

	quic_accept_queues = calloc(global.nbthread,
				    sizeof(*quic_accept_queues));
	if (!quic_accept_queues) {
		ha_alert("Failed to allocate the quic accept queues.\n");
		return 0;
	}

	for (i = 0; i < global.nbthread; ++i) {
		struct tasklet *task;
		if (!(task = tasklet_new())) {
			ha_alert("Failed to allocate the quic accept queue on thread %d.\n", i);
			return 0;
		}

		tasklet_set_tid(task, i);
		task->process = quic_accept_run;
		quic_accept_queues[i].tasklet = task;

		MT_LIST_INIT(&quic_accept_queues[i].listeners);
	}

	return 1;
}
REGISTER_POST_CHECK(quic_alloc_accept_queues);

static int quic_deallocate_accept_queues(void)
{
	int i;

	if (quic_accept_queues) {
		for (i = 0; i < global.nbthread; ++i)
			tasklet_free(quic_accept_queues[i].tasklet);
		free(quic_accept_queues);
	}

	return 1;
}
REGISTER_POST_DEINIT(quic_deallocate_accept_queues);
