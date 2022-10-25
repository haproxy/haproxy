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
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global-t.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/pool.h>
#include <haproxy/proto_quic.h>
#include <haproxy/proxy-t.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

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

	cid_tid = quic_get_cid_tid(dcid, l->bind_conf);

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
 * Returns the last unused datagram or NULL if no occurence found.
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
void quic_sock_fd_iocb(int fd)
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
		b_del(buf, ret);
	}
	new_dgram = NULL;
	if (--max_dgrams > 0)
		goto start;
 out:
	pool_free(pool_head_quic_dgram, new_dgram);
	MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->rxbuf_el);
}

/* Send a datagram stored into <buf> buffer with <sz> as size.
 * The caller must ensure there is at least <sz> bytes in this buffer.
 *
 * Returns 0 on success else non-zero.
 *
 * TODO standardize this function for a generic UDP sendto wrapper. This can be
 * done by removing the <qc> arg and replace it with address/port.
 */
int qc_snd_buf(struct quic_conn *qc, const struct buffer *buf, size_t sz,
               int flags)
{
	ssize_t ret;

	do {
		ret = sendto(qc->li->rx.fd, b_peek(buf, b_head_ofs(buf)), sz,
		             MSG_DONTWAIT | MSG_NOSIGNAL,
		             (struct sockaddr *)&qc->peer_addr, get_addr_len(&qc->peer_addr));
	} while (ret < 0 && errno == EINTR);

	if (ret < 0 || ret != sz) {
		struct proxy *prx = qc->li->bind_conf->frontend;
		struct quic_counters *prx_counters =
		  EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                     &quic_stats_module);

		/* TODO adjust errno for UDP context. */
		if (errno == EAGAIN || errno == EWOULDBLOCK ||
		    errno == ENOTCONN || errno == EINPROGRESS || errno == EBADF) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				HA_ATOMIC_INC(&prx_counters->socket_full);
			else
				HA_ATOMIC_INC(&prx_counters->sendto_err);
		}
		else if (errno) {
			/* TODO unlisted errno : handle it explicitly. */
			HA_ATOMIC_INC(&prx_counters->sendto_err_unknown);
		}

		return 1;
	}

	/* we count the total bytes sent, and the send rate for 32-byte blocks.
	 * The reason for the latter is that freq_ctr are limited to 4GB and
	 * that it's not enough per second.
	 */
	_HA_ATOMIC_ADD(&global.out_bytes, ret);
	update_freq_ctr(&global.out_32bps, (ret + 16) / 32);

	return 0;
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
