/*
 * QUIC xprt layer. Act as an abstraction between quic_conn and MUX layers.
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/quic_trace.h>
#include <haproxy/trace.h>

static void quic_close(struct connection *conn, void *xprt_ctx)
{
	struct ssl_sock_ctx *conn_ctx = xprt_ctx;
	struct quic_conn *qc = conn_ctx->qc;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	qc->conn = NULL;

	/* Next application data can be dropped. */
	qc->mux_state = QC_MUX_RELEASED;

	/* If the quic-conn timer has already expired or if already in "connection close"
	 * state, free the quic-conn.
	 */
	if (qc->flags & (QUIC_FL_CONN_EXP_TIMER|QUIC_FL_CONN_CLOSING)) {
		quic_conn_release(qc);
		qc = NULL;
		goto leave;
	}

	/* Schedule a CONNECTION_CLOSE emission. If process stopping is in
	 * progress, quic-conn idle-timer will be scheduled immediately after
	 * its emission to ensure an immediate connection closing.
	 */
	qc_check_close_on_released_mux(qc);
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int quic_conn_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	struct quic_conn *qc = conn->handle.qc;

	TRACE_ENTER(QUIC_EV_CONN_SUB, qc);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qc->subs && qc->subs != es);

	es->events |= event_type;
	qc->subs = es;

	/* TODO implement a check_events to detect if subscriber should be
	 * woken up immediately ?
	 */

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", QUIC_EV_CONN_XPRTRECV, qc);

	if (event_type & SUB_RETRY_SEND)
		TRACE_DEVEL("subscribe(send)", QUIC_EV_CONN_XPRTSEND, qc);

	TRACE_LEAVE(QUIC_EV_CONN_SUB, qc);

	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int quic_conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	struct quic_conn *qc = conn->handle.qc;

	TRACE_ENTER(QUIC_EV_CONN_SUB, qc);

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", QUIC_EV_CONN_XPRTRECV, qc);
	if (event_type & SUB_RETRY_SEND)
		TRACE_DEVEL("unsubscribe(send)", QUIC_EV_CONN_XPRTSEND, qc);

	es->events &= ~event_type;
	if (!es->events)
		qc->subs = NULL;

	/* TODO implement ignore_events similar to conn_unsubscribe() ? */

	TRACE_LEAVE(QUIC_EV_CONN_SUB, qc);

	return 0;
}

/* Store in <xprt_ctx> the context attached to <conn>.
 * Returns always 0.
 */
static int qc_conn_init(struct connection *conn, void **xprt_ctx)
{
	int ret = -1;
	struct quic_conn *qc = NULL;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	if (objt_listener(conn->target)) {
		qc = conn->handle.qc;
	}
	else {
		int ipv4 = conn->dst->ss_family == AF_INET;
		struct server *srv = objt_server(conn->target);
		qc = qc_new_conn(quic_version_1, ipv4, NULL, NULL, NULL,
		                 NULL, NULL, &srv->addr, 0, srv, conn);
		if (qc)
			conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
	}

	if (!qc)
		goto out;

	ret = 0;
	/* Ensure thread connection migration is finalized ASAP. */
	if (qc->flags & QUIC_FL_CONN_TID_REBIND)
		qc_finalize_tid_rebind(qc);

	/* do not store the context if already set */
	if (*xprt_ctx)
		goto out;

	*xprt_ctx = qc->xprt_ctx;

 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);

	return ret;
}

/* Start the QUIC transport layer */
static int qc_xprt_start(struct connection *conn, void *ctx)
{
	int ret = -1;
	struct quic_conn *qc;

	qc = conn->handle.qc;
	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	if (objt_listener(conn->target)) {
		/* mux-quic can now be considered ready. */
		qc->mux_state = QC_MUX_READY;
	}
	else {
		/* This has as side effet to create a SSL_SESSION object attached to
		 * the SSL object.
		 */
		if (!qc_ssl_do_hanshake(qc, ctx))
			goto err;

		if (qc->eel) {
			struct ssl_sock_ctx *ssl_ctx = ctx;

			/* Start the mux asap when early data encryption level is available. */
			conn->flags |= CO_FL_WAIT_XPRT;
			if (conn_create_mux(ssl_ctx->conn, NULL) < 0) {
				TRACE_ERROR("mux creation failed", QUIC_EV_CONN_IO_CB, qc, &qc->state);
				goto err;
			}

			ssl_ctx->conn->flags &= ~CO_FL_WAIT_XPRT;
			qc->mux_state = QC_MUX_READY;
			/* Wake up MUX after its creation. Operation similar to TLS+ALPN on
			 * TCP stack.
			 */
			ssl_ctx->conn->mux->wake(ssl_ctx->conn);
		}
	}

	/* Schedule quic-conn to ensure post handshake frames are emitted. This
	 * is not done for 0-RTT as xprt->start happens before handshake
	 * completion.
	 */
	if (qc_is_back(qc) || (qc->flags & QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS))
		tasklet_wakeup(qc->wait_event.tasklet);

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
 err:
	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_NEW, qc);
	goto leave;
}

static struct ssl_sock_ctx *qc_get_ssl_sock_ctx(struct connection *conn)
{
	if (!conn || conn->xprt != xprt_get(XPRT_QUIC) || !conn->handle.qc || !conn->xprt_ctx)
		return NULL;

	return conn->handle.qc->xprt_ctx;
}

static void qc_xprt_dump_info(struct buffer *msg, const struct connection *conn)
{
	quic_dump_qc_info(msg, conn->handle.qc);
}

/* transport-layer operations for QUIC connections. */
static struct xprt_ops ssl_quic = {
	.close    = quic_close,
	.subscribe = quic_conn_subscribe,
	.unsubscribe = quic_conn_unsubscribe,
	.init     = qc_conn_init,
	.start    = qc_xprt_start,
	.prepare_bind_conf = ssl_sock_prepare_bind_conf,
	.destroy_bind_conf = ssl_sock_destroy_bind_conf,
	.prepare_srv = ssl_sock_prepare_srv_ctx,
	.destroy_srv = ssl_sock_free_srv_ctx,
	.get_alpn = ssl_sock_get_alpn,
	.get_ssl_sock_ctx = qc_get_ssl_sock_ctx,
	.dump_info = qc_xprt_dump_info,
	.name     = "QUIC",
};

static void __quic_conn_init(void)
{
	xprt_register(XPRT_QUIC, &ssl_quic);
}
INITCALL0(STG_REGISTER, __quic_conn_init);
