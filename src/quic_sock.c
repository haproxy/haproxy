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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/fd.h>
#include <haproxy/global-t.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/obj_type.h>
#include <haproxy/pool.h>
#include <haproxy/protocol-t.h>
#include <haproxy/proto_quic.h>
#include <haproxy/proxy-t.h>
#include <haproxy/quic_cid.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_rx.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/quic_trace.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

/* Log only first EACCES bind() error runtime occurrence. */
static volatile char quic_bind_eacces_warn = 0;

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
	struct li_per_thread *lthr = &l->per_thr[ti->ltid];

	qc = MT_LIST_POP(&lthr->quic_accept.conns, struct quic_conn *, accept_list);
	if (!qc || qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING))
		goto done;

	if (!new_quic_cli_conn(qc, l, &qc->peer_addr))
		goto err;

 done:
	*status = CO_AC_DONE;

	if (qc) {
		BUG_ON(l->rx.quic_curr_accept <= 0);
		HA_ATOMIC_DEC(&l->rx.quic_curr_accept);
		return qc->conn;
	}
	else {
		return NULL;
	}

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

/* Retrieve the DCID from a QUIC datagram or packet at <pos> position,
 * <end> being at one byte past the end of this datagram.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_get_dgram_dcid(unsigned char *pos, const unsigned char *end,
                               unsigned char **dcid, size_t *dcid_len)
{
	int ret = 0, long_header;
	size_t minlen, skip;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	if (!(*pos & QUIC_PACKET_FIXED_BIT)) {
		TRACE_PROTO("fixed bit not set", QUIC_EV_CONN_RXPKT);
		goto err;
	}

	long_header = *pos & QUIC_PACKET_LONG_HEADER_BIT;
	minlen = long_header ? QUIC_LONG_PACKET_MINLEN :
		QUIC_SHORT_PACKET_MINLEN + QUIC_HAP_CID_LEN + QUIC_TLS_TAG_LEN;
	skip = long_header ? QUIC_LONG_PACKET_DCID_OFF : QUIC_SHORT_PACKET_DCID_OFF;
	if (end - pos < minlen)
		goto err;

	pos += skip;
	*dcid_len = long_header ? *pos++ : QUIC_HAP_CID_LEN;
	if (*dcid_len > QUIC_CID_MAXLEN || end - pos <= *dcid_len)
		goto err;

	*dcid = pos;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT);
	return ret;

 err:
	TRACE_PROTO("wrong datagram", QUIC_EV_CONN_RXPKT);
	goto leave;
}


/* Retrieve the DCID from the datagram found at <pos> position and deliver it to the
 * correct datagram handler.
 * Return 1 if a correct datagram could be found, 0 if not.
 */
static int quic_lstnr_dgram_dispatch(unsigned char *pos, size_t len, void *owner,
                                     struct sockaddr_storage *saddr,
                                     struct sockaddr_storage *daddr,
                                     struct quic_dgram *new_dgram, struct list *dgrams)
{
	struct quic_dgram *dgram;
	unsigned char *dcid;
	size_t dcid_len;
	int cid_tid;

	if (!len || !quic_get_dgram_dcid(pos, pos + len, &dcid, &dcid_len))
		goto err;

	dgram = new_dgram ? new_dgram : pool_alloc(pool_head_quic_dgram);
	if (!dgram)
		goto err;

	if ((cid_tid = quic_get_cid_tid(dcid, dcid_len, saddr, pos, len)) < 0) {
		/* Use the current thread if CID not found. If a clients opens
		 * a connection with multiple packets, it is possible that
		 * several threads will deal with datagrams sharing the same
		 * CID. For this reason, the CID tree insertion will be
		 * conducted as an atomic operation and the datagram ultimately
		 * redispatch by the late thread.
		 */
		cid_tid = tid;
	}

	/* All the members must be initialized! */
	dgram->obj_type = OBJ_TYPE_DGRAM;
	dgram->owner = owner;
	dgram->buf = pos;
	dgram->len = len;
	dgram->dcid = dcid;
	dgram->dcid_len = dcid_len;
	dgram->saddr = *saddr;
	dgram->daddr = *daddr;
	dgram->qc = NULL;
	dgram->flags = 0;

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
static struct quic_dgram *quic_rxbuf_purge_dgrams(struct quic_receiver_buf *rbuf)
{
	struct quic_dgram *cur, *prev = NULL;

	while (!LIST_ISEMPTY(&rbuf->dgram_list)) {
		cur = LIST_ELEM(rbuf->dgram_list.n, struct quic_dgram *, recv_list);

		/* Loop until a not yet consumed datagram is found. */
		if (HA_ATOMIC_LOAD(&cur->buf))
			break;

		/* Clear buffer of current unused datagram. */
		LIST_DELETE(&cur->recv_list);
		b_del(&rbuf->buf, cur->len);

		/* Free last found unused datagram. */
		pool_free(pool_head_quic_dgram, prev);
		prev = cur;
	}

	/* Return last unused datagram found. */
	return prev;
}

/* Receive a single message from datagram socket <fd>. Data are placed in <out>
 * buffer of length <len>.
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

	if (unlikely(port_is_restricted((struct sockaddr_storage *)from, HA_PROTO_QUIC))) {
		ret = -1;
		goto end;
	}

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
void quic_conn_sock_fd_iocb(int fd)
{
	struct quic_conn *qc = fdtab[fd].owner;

	TRACE_ENTER(QUIC_EV_CONN_RCV, qc);

	if (fd_send_active(fd) && fd_send_ready(fd)) {
		TRACE_DEVEL("send ready", QUIC_EV_CONN_RCV, qc);
		fd_stop_send(fd);
		tasklet_wakeup_after(NULL, qc->wait_event.tasklet);
		qc_notify_send(qc);
	}

	if (fd_recv_ready(fd)) {
		TRACE_DEVEL("recv ready", QUIC_EV_CONN_RCV, qc);
		tasklet_wakeup_after(NULL, qc->wait_event.tasklet);
		fd_stop_recv(fd);
	}

	TRACE_LEAVE(QUIC_EV_CONN_RCV, qc);
}

static void cmsg_set_saddr(struct msghdr *msg, struct cmsghdr **cmsg,
                           struct sockaddr_storage *saddr)
{
	struct cmsghdr *c;
#ifdef IP_PKTINFO
	struct in_pktinfo *in;
#endif /* IP_PKTINFO */
#ifdef IPV6_RECVPKTINFO
	struct in6_pktinfo *in6;
#endif /* IPV6_RECVPKTINFO */
	size_t sz = 0;

	/* First determine size of ancillary data depending on the system support. */
	switch (saddr->ss_family) {
	case AF_INET:
#if defined(IP_PKTINFO)
		sz = sizeof(struct in_pktinfo);
#elif defined(IP_RECVDSTADDR)
		sz = sizeof(struct in_addr);
#endif /* IP_PKTINFO || IP_RECVDSTADDR */
		break;
	case AF_INET6:
#ifdef IPV6_RECVPKTINFO
		sz = sizeof(struct in6_pktinfo);
#endif /* IPV6_RECVPKTINFO */
		break;
	default:
		break;
	}

	/* Size is null if system does not support send source address setting. */
	if (!sz)
		return;

	/* Set first msg_controllen to be able to use CMSG_* macros. */
	msg->msg_controllen += CMSG_SPACE(sz);

	/* seems necessary to please gcc-13 */
	ASSUME_NONNULL(CMSG_FIRSTHDR(msg));

	*cmsg = !(*cmsg) ? CMSG_FIRSTHDR(msg) : CMSG_NXTHDR(msg, *cmsg);
	ASSUME_NONNULL(*cmsg);
	c = *cmsg;
	c->cmsg_len = CMSG_LEN(sz);

	switch (saddr->ss_family) {
	case AF_INET:
		c->cmsg_level = IPPROTO_IP;
#if defined(IP_PKTINFO)
		c->cmsg_type = IP_PKTINFO;
		in = (struct in_pktinfo *)CMSG_DATA(c);
		in->ipi_ifindex = 0;
		in->ipi_addr.s_addr = 0;
		memcpy(&in->ipi_spec_dst,
		       &((struct sockaddr_in *)saddr)->sin_addr,
		       sizeof(struct in_addr));
#elif defined(IP_RECVDSTADDR)
		c->cmsg_type = IP_SENDSRCADDR;
		memcpy(CMSG_DATA(c),
		       &((struct sockaddr_in *)saddr)->sin_addr,
		       sizeof(struct in_addr));
#endif /* IP_PKTINFO || IP_RECVDSTADDR */

		break;

	case AF_INET6:
#ifdef IPV6_RECVPKTINFO
		c->cmsg_level = IPPROTO_IPV6;
		c->cmsg_type = IPV6_PKTINFO;
		in6 = (struct in6_pktinfo *)CMSG_DATA(c);
		in6->ipi6_ifindex = 0;
		memcpy(&in6->ipi6_addr,
		       &((struct sockaddr_in6 *)saddr)->sin6_addr,
		       sizeof(struct in6_addr));
#endif /* IPV6_RECVPKTINFO */

		break;

	default:
		break;
	}
}

static void cmsg_set_gso(struct msghdr *msg, struct cmsghdr **cmsg,
                         uint16_t gso_size)
{
#ifdef UDP_SEGMENT
	struct cmsghdr *c;
	size_t sz = sizeof(gso_size);

	/* Set first msg_controllen to be able to use CMSG_* macros. */
	msg->msg_controllen += CMSG_SPACE(sz);

	/* seems necessary to please gcc-13 */
	ASSUME_NONNULL(CMSG_FIRSTHDR(msg));

	*cmsg = !(*cmsg) ? CMSG_FIRSTHDR(msg) : CMSG_NXTHDR(msg, *cmsg);
	ASSUME_NONNULL(*cmsg);
	c = *cmsg;
	c->cmsg_len = CMSG_LEN(sz);

	c->cmsg_level = SOL_UDP;
	c->cmsg_type = UDP_SEGMENT;
	c->cmsg_len = CMSG_LEN(sz);
	*((uint16_t *)CMSG_DATA(c)) = gso_size;
#endif
}

/* Send a datagram stored into <buf> buffer with <sz> as size. The caller must
 * ensure there is at least <sz> bytes in this buffer.
 *
 * If <gso_size> is non null, it will be used as value for UDP_SEGMENT option.
 * This allows to transmit multiple datagrams in a single syscall.
 *
 * Returns the total bytes sent over the socket. 0 is returned if a transient
 * error is encountered which allows send to be retry later. A negative value
 * is used for a fatal error which guarantee that all future send operation for
 * this connection will fail.
 *
 * TODO standardize this function for a generic UDP sendto wrapper. This can be
 * done by removing the <qc> arg and replace it with address/port.
 */
int qc_snd_buf(struct quic_conn *qc, const struct buffer *buf, size_t sz,
               int flags, uint16_t gso_size)
{
	ssize_t ret;
	struct msghdr msg;
	struct iovec vec;
	struct cmsghdr *cmsg __maybe_unused = NULL;

	union {
#ifdef IP_PKTINFO
		char buf[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(gso_size))];
#endif /* IP_PKTINFO */
#ifdef IPV6_RECVPKTINFO
		char buf6[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(gso_size))];
#endif /* IPV6_RECVPKTINFO */
		char bufaddr[CMSG_SPACE(sizeof(struct in_addr)) + CMSG_SPACE(sizeof(gso_size))];
		struct cmsghdr align;
	} ancillary_data;

	/* man 3 cmsg
	 *
	 * When initializing a buffer that will contain a
	 * series of cmsghdr structures (e.g., to be sent with
	 * sendmsg(2)), that buffer should first be
	 * zero-initialized to ensure the correct operation of
	 * CMSG_NXTHDR().
	 */
	memset(&ancillary_data, 0, sizeof(ancillary_data));

	vec.iov_base = b_peek(buf, b_head_ofs(buf));
	vec.iov_len = sz;

	/* man 2 sendmsg
	 *
	 * The msg_name field is used on an unconnected socket to specify the
	 * target address for a datagram. It points to a buffer containing the
	 * address; the msg_namelen field should  be  set to the size of the
	 * address. For a connected socket, these fields should be specified
	 * as NULL and 0, respectively.
         */
	if (!qc_test_fd(qc)) {
		msg.msg_name = &qc->peer_addr;
		msg.msg_namelen = get_addr_len(&qc->peer_addr);
	}
	else {
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
	}

	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	if (qc_test_fd(qc) && !fd_send_ready(qc->fd))
		return 0;

	/* Set source address when using listener socket if possible. */
	if (!qc_test_fd(qc) && is_addr(&qc->local_addr)) {
		msg.msg_control = ancillary_data.bufaddr;
		cmsg_set_saddr(&msg, &cmsg, &qc->local_addr);
	}

	/* Set GSO parameter if datagram size is bigger than MTU. */
	if (gso_size) {
		/* GSO size must be less than total data to sent for multiple datagrams. */
		BUG_ON_HOT(b_data(buf) <= gso_size);

		if (!msg.msg_control)
			msg.msg_control = ancillary_data.bufaddr;
		cmsg_set_gso(&msg, &cmsg, gso_size);
	}

	do {
		ret = sendmsg(qc_fd(qc), &msg, MSG_DONTWAIT|MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK ||
		    errno == ENOTCONN || errno == EINPROGRESS) {
			/* transient error */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				qc->cntrs.socket_full++;
			else
				qc->cntrs.sendto_err++;

			if (qc_test_fd(qc)) {
				fd_want_send(qc->fd);
				fd_cant_send(qc->fd);
			}
			TRACE_PRINTF(TRACE_LEVEL_USER, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
			             "UDP send failure errno=%d (%s)", errno, strerror(errno));
			return 0;
		}
		else {
			/* unrecoverable error */
			qc->cntrs.sendto_err_unknown++;
			TRACE_PRINTF(TRACE_LEVEL_USER, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
			             "UDP send failure errno=%d (%s)", errno, strerror(errno));
			return -errno;
		}
	}

	if (ret != sz)
		return 0;

	return ret;
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
		if (!b_alloc(&buf, DB_MUX_RX))
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
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN)
				fd_want_recv(qc->fd);
			/* TODO handle other error codes as fatal on the connection. */
			break;
		}

		b_add(&buf, ret);

		new_dgram->obj_type = OBJ_TYPE_DGRAM;
		new_dgram->buf = dgram_buf;
		new_dgram->len = ret;
		new_dgram->dcid_len = 0;
		new_dgram->dcid = NULL;
		new_dgram->saddr = saddr;
		new_dgram->daddr = daddr;
		new_dgram->qc = NULL;  /* set later via quic_dgram_parse() */
		new_dgram->flags = 0;

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
			size_t cspace;

			TRACE_STATE("datagram for other connection on quic-conn socket, requeue it", QUIC_EV_CONN_RCV, qc);

			rxbuf = MT_LIST_POP(&l->rx.rxbuf_list, typeof(rxbuf), rxbuf_el);
			ASSUME_NONNULL(rxbuf);
			cspace = b_contig_space(&rxbuf->buf);

			tmp_dgram = quic_rxbuf_purge_dgrams(rxbuf);
			pool_free(pool_head_quic_dgram, tmp_dgram);

			/* Insert a fake datagram if space wraps to consume it. */
			if (cspace < new_dgram->len && b_space_wraps(&rxbuf->buf)) {
				struct quic_dgram *fake_dgram = pool_alloc(pool_head_quic_dgram);
				if (!fake_dgram) {
					/* TODO count lost datagrams */
					MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->rxbuf_el);
					continue;
				}

				fake_dgram->buf = NULL;
				fake_dgram->len = cspace;
				LIST_APPEND(&rxbuf->dgram_list, &fake_dgram->recv_list);
				b_add(&rxbuf->buf, cspace);
			}

			/* Recheck contig space after fake datagram insert. */
			if (b_contig_space(&rxbuf->buf) < new_dgram->len) {
				/* TODO count lost datagrams */
				MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->rxbuf_el);
				continue;
			}

			rxbuf_tail = (unsigned char *)b_tail(&rxbuf->buf);
			__b_putblk(&rxbuf->buf, (char *)dgram_buf, new_dgram->len);
			if (!quic_lstnr_dgram_dispatch(rxbuf_tail, ret, l, &saddr, &daddr,
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
	struct bind_conf *bc = qc->li->bind_conf;
	struct proxy *p = bc->frontend;
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
	if (ret < 0) {
		if (errno == EACCES) {
			if (!quic_bind_eacces_warn) {
				send_log(p, LOG_WARNING,
					 "Permission error on QUIC socket binding for proxy %s. Consider using setcap cap_net_bind_service (Linux only) or running as root.\n",
					 p->id);
				quic_bind_eacces_warn = 1;
			}

			/* Fallback to listener socket for this receiver instance. */
			HA_ATOMIC_STORE(&qc->li->rx.quic_mode, QUIC_SOCK_MODE_LSTNR);
		}
		goto err;
	}

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

/* Wrapper for fd_want_recv(). Safe even if connection does not used its owned
 * socket.
 */
void qc_want_recv(struct quic_conn *qc)
{
	if (qc_test_fd(qc))
		fd_want_recv(qc->fd);
}

/*********************** QUIC accept queue management ***********************/
/* per-thread accept queues */
struct quic_accept_queue *quic_accept_queues;

/* Install <qc> on the queue ready to be accepted. The queue task is then woken
 * up.
 */
void quic_accept_push_qc(struct quic_conn *qc)
{
	struct quic_accept_queue *queue = &quic_accept_queues[tid];
	struct li_per_thread *lthr = &qc->li->per_thr[ti->ltid];

	/* A connection must only be accepted once per instance. */
	BUG_ON(qc->flags & QUIC_FL_CONN_ACCEPT_REGISTERED);

	BUG_ON(MT_LIST_INLIST(&qc->accept_list));
	HA_ATOMIC_INC(&qc->li->rx.quic_curr_accept);

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
	tasklet_wakeup(quic_accept_queues[tid].tasklet);
}

/* Tasklet handler to accept QUIC connections. Call listener_accept on every
 * listener instances registered in the accept queue.
 */
struct task *quic_accept_run(struct task *t, void *ctx, unsigned int i)
{
	struct li_per_thread *lthr;
	struct mt_list back;
	struct quic_accept_queue *queue = &quic_accept_queues[tid];

	MT_LIST_FOR_EACH_ENTRY_LOCKED(lthr, &queue->listeners, quic_accept.list, back) {
		listener_accept(lthr->li);
		if (!MT_LIST_ISEMPTY(&lthr->quic_accept.conns)) {
			/* entry is left in queue */
			tasklet_wakeup((struct tasklet*)t);
		}
		else {
			mt_list_unlock_self(&lthr->quic_accept.list);
			lthr = NULL; /* delete it */
		}
	}

	return NULL;
}

/* Returns the maximum number of QUIC connections waiting for handshake to
 * complete in parallel on listener <l> instance. This is directly based on
 * listener backlog value.
 */
int quic_listener_max_handshake(const struct listener *l)
{
	return listener_backlog(l) / 2;
}

/* Returns the value which is considered as the maximum number of QUIC
 * connections waiting to be accepted for listener <l> instance. This is
 * directly based on listener backlog value.
 */
int quic_listener_max_accept(const struct listener *l)
{
	return listener_backlog(l) / 2;
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
