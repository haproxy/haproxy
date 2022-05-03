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

#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <haproxy/connection.h>
#include <haproxy/listener.h>
#include <haproxy/quic_sock.h>
#include <haproxy/session.h>
#include <haproxy/tools.h>
#include <haproxy/xprt_quic.h>

/* This function is called from the protocol layer accept() in order to
 * instantiate a new session on behalf of a given listener and frontend. It
 * returns a positive value upon success, 0 if the connection can be ignored,
 * or a negative value upon critical failure. The accepted connection is
 * closed if we return <= 0. If no handshake is needed, it immediately tries
 * to instantiate a new stream. The connection must already have been filled
 * with the incoming connection handle (a fd), a target (the listener) and a
 * source address.
 */
int quic_session_accept(struct connection *cli_conn)
{
	struct listener *l = __objt_listener(cli_conn->target);
	struct proxy *p = l->bind_conf->frontend;
	struct session *sess;

	cli_conn->proxy_netns = l->rx.settings->netns;
	/* This flag is ordinarily set by conn_ctrl_init() which cannot
	 * be called for now.
	 */
	cli_conn->flags |= CO_FL_CTRL_READY;

	/* wait for a PROXY protocol header */
	if (l->options & LI_O_ACC_PROXY)
		cli_conn->flags |= CO_FL_ACCEPT_PROXY;

	/* wait for a NetScaler client IP insertion protocol header */
	if (l->options & LI_O_ACC_CIP)
		cli_conn->flags |= CO_FL_ACCEPT_CIP;

	/* Add the handshake pseudo-XPRT */
	if (cli_conn->flags & (CO_FL_ACCEPT_PROXY | CO_FL_ACCEPT_CIP)) {
		if (xprt_add_hs(cli_conn) != 0)
			goto out_free_conn;
	}

	sess = session_new(p, l, &cli_conn->obj_type);
	if (!sess)
		goto out_free_conn;

	conn_set_owner(cli_conn, sess, NULL);

	if (conn_complete_session(cli_conn) < 0)
		goto out_free_sess;

	if (conn_xprt_start(cli_conn) < 0) {
		/* conn_complete_session has succeeded : conn is the owner of
		 * the session and the MUX is initialized.
		 * Let the MUX free all resources on error.
		 */
		cli_conn->mux->destroy(cli_conn->ctx);
		return -1;
	}

	return 1;

 out_free_sess:
	/* prevent call to listener_release during session_free. It will be
	* done below, for all errors. */
	sess->listener = NULL;
	session_free(sess);
 out_free_conn:
	cli_conn->handle.qc->conn = NULL;
	conn_stop_tracking(cli_conn);
	conn_xprt_close(cli_conn);
	conn_free(cli_conn);
 out:

	return -1;
}

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
		/* FIXME: front connection, no local address for now, we'll
		 * return the listener's address instead.
		 */
		BUG_ON(!qc->li);

		if (len > sizeof(qc->li->rx.addr))
			len = sizeof(qc->li->rx.addr);
		memcpy(addr, &qc->li->rx.addr, len);
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

	/* We need the xprt context before accepting (->accept()) the connection:
	 * we may receive packet before this connection acception.
	 */
	if (conn_prepare(cli_conn, l->rx.proto, l->bind_conf->xprt) < 0)
		goto out_free_conn;

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

/* Function called on a read event from a listening socket. It tries
 * to handle as many connections as possible.
 */
void quic_sock_fd_iocb(int fd)
{
	ssize_t ret;
	struct rxbuf *rxbuf;
	struct buffer *buf;
	struct listener *l = objt_listener(fdtab[fd].owner);
	struct quic_transport_params *params;
	/* Source address */
	struct sockaddr_storage saddr = {0};
	size_t max_sz, cspace;
	socklen_t saddrlen;
	struct quic_dgram *dgram, *dgramp, *new_dgram;
	unsigned char *dgram_buf;

	BUG_ON(!l);

	if (!l)
		return;

	if (!(fdtab[fd].state & FD_POLL_IN) || !fd_recv_ready(fd))
		return;

	rxbuf = MT_LIST_POP(&l->rx.rxbuf_list, typeof(rxbuf), mt_list);
	if (!rxbuf)
		goto out;

	buf = &rxbuf->buf;

	new_dgram = NULL;
	/* Remove all consumed datagrams of this buffer */
	list_for_each_entry_safe(dgram, dgramp, &rxbuf->dgrams, list) {
		if (HA_ATOMIC_LOAD(&dgram->buf))
			break;

		LIST_DELETE(&dgram->list);
		b_del(buf, dgram->len);
		if (!new_dgram)
			new_dgram = dgram;
		else
			pool_free(pool_head_quic_dgram, dgram);
	}

	params = &l->bind_conf->quic_params;
	max_sz = params->max_udp_payload_size;
	cspace = b_contig_space(buf);
	if (cspace < max_sz) {
		struct quic_dgram *dgram;

		/* Allocate a fake datagram, without data to locate
		 * the end of the RX buffer (required during purging).
		 */
		dgram = pool_zalloc(pool_head_quic_dgram);
		if (!dgram)
			goto out;

		dgram->len = cspace;
		LIST_APPEND(&rxbuf->dgrams, &dgram->list);
		/* Consume the remaining space */
		b_add(buf, cspace);
		if (b_contig_space(buf) < max_sz)
			goto out;

	}

	dgram_buf = (unsigned char *)b_tail(buf);
	saddrlen = sizeof saddr;
	do {
		ret = recvfrom(fd, dgram_buf, max_sz, 0,
		               (struct sockaddr *)&saddr, &saddrlen);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			fd_cant_recv(fd);
			goto out;
		}
	} while (ret < 0 && errno == EINTR);

	b_add(buf, ret);
	if (!quic_lstnr_dgram_dispatch(dgram_buf, ret, l, &saddr,
	                               new_dgram, &rxbuf->dgrams)) {
		/* If wrong, consume this datagram */
		b_del(buf, ret);
	}
 out:
	MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->mt_list);
}

/* TODO standardize this function for a generic UDP sendto wrapper. This can be
 * done by removing the <qc> arg and replace it with address/port.
 */
size_t qc_snd_buf(struct quic_conn *qc, const struct buffer *buf, size_t count,
                  int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	done = 0;
	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

		send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;
		if (try < count || flags & CO_SFL_MSG_MORE)
			send_flag |= MSG_MORE;

		ret = sendto(qc->li->rx.fd, b_peek(buf, done), try, send_flag,
		             (struct sockaddr *)&qc->peer_addr, get_addr_len(&qc->peer_addr));
		if (ret > 0) {
			/* TODO remove partial sending support for UDP */
			count -= ret;
			done += ret;

			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN || errno == EINPROGRESS) {
			/* TODO must be handle properly. It is justified for UDP ? */
			qc->sendto_err++;
		}
		else if (errno != EINTR) {
			/* TODO must be handle properly. It is justified for UDP ? */
			qc->sendto_err++;
		}
	}

	if (done > 0) {
		/* we count the total bytes sent, and the send rate for 32-byte
		 * blocks. The reason for the latter is that freq_ctr are
		 * limited to 4GB and that it's not enough per second.
		 */
		_HA_ATOMIC_ADD(&global.out_bytes, done);
		update_freq_ctr(&global.out_32bps, (done + 16) / 32);
	}
	return done;
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
static struct task *quic_accept_run(struct task *t, void *ctx, unsigned int i)
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

	quic_accept_queues = calloc(global.nbthread, sizeof(struct quic_accept_queue));
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
