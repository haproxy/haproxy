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
#include <haproxy/connection.h>
#include <haproxy/quic_conn.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_quic

static void quic_close(struct connection *conn, void *xprt_ctx)
{
	struct ssl_sock_ctx *conn_ctx = xprt_ctx;
	struct quic_conn *qc = conn_ctx->qc;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	/* Next application data can be dropped. */
	qc->mux_state = QC_MUX_RELEASED;

	/* If the quic-conn timer has already expired free the quic-conn. */
	if (qc->flags & QUIC_FL_CONN_EXP_TIMER) {
		quic_conn_release(qc);
		goto leave;
	}

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
	struct qcc *qcc = qc->qcc;

	TRACE_ENTER(QUIC_EV_CONN_SUB, qc);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcc->subs && qcc->subs != es);

	es->events |= event_type;
	qcc->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", QUIC_EV_CONN_XPRTRECV, qc, qcc);

	if (event_type & SUB_RETRY_SEND)
		TRACE_DEVEL("subscribe(send)", QUIC_EV_CONN_XPRTSEND, qc, qcc);

	TRACE_LEAVE(QUIC_EV_CONN_SUB, qc);

	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int quic_conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	int ret;
	struct quic_conn *qc = conn->handle.qc;
	struct qcc *qcc = qc->qcc;

	TRACE_ENTER(QUIC_EV_CONN_SUB, qc);

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", QUIC_EV_CONN_XPRTRECV, qc, qcc);
	if (event_type & SUB_RETRY_SEND)
		TRACE_DEVEL("unsubscribe(send)", QUIC_EV_CONN_XPRTSEND, qc, qcc);

	ret = conn_unsubscribe(conn, xprt_ctx, event_type, es);

	TRACE_LEAVE(QUIC_EV_CONN_SUB, qc);

	return ret;
}

/* Store in <xprt_ctx> the context attached to <conn>.
 * Returns always 0.
 */
static int qc_conn_init(struct connection *conn, void **xprt_ctx)
{
	struct quic_conn *qc = NULL;

	TRACE_ENTER(QUIC_EV_CONN_NEW, conn);

	/* do not store the context if already set */
	if (*xprt_ctx)
		goto out;

	*xprt_ctx = conn->handle.qc->xprt_ctx;

 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);

	return 0;
}

/* Start the QUIC transport layer */
static int qc_xprt_start(struct connection *conn, void *ctx)
{
	int ret = 0;
	struct quic_conn *qc;
	struct ssl_sock_ctx *qctx = ctx;

	qc = conn->handle.qc;
	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);
	if (qcc_install_app_ops(qc->qcc, qc->app_ops)) {
		TRACE_PROTO("Cannot install app layer", QUIC_EV_CONN_LPKT, qc);
		/* prepare a CONNECTION_CLOSE frame */
		quic_set_connection_close(qc, quic_err_transport(QC_ERR_APPLICATION_ERROR));
		goto out;
	}

	/* mux-quic can now be considered ready. */
	qc->mux_state = QC_MUX_READY;

	tasklet_wakeup(qctx->wait_event.tasklet);

	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

static struct ssl_sock_ctx *qc_get_ssl_sock_ctx(struct connection *conn)
{
	if (!conn || conn->xprt != xprt_get(XPRT_QUIC) || !conn->handle.qc || !conn->xprt_ctx)
		return NULL;

	return conn->handle.qc->xprt_ctx;
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
	.get_alpn = ssl_sock_get_alpn,
	.get_ssl_sock_ctx = qc_get_ssl_sock_ctx,
	.name     = "QUIC",
};

static void __quic_conn_init(void)
{
	xprt_register(XPRT_QUIC, &ssl_quic);
}
INITCALL0(STG_REGISTER, __quic_conn_init);
