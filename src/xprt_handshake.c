/*
 * Pseudo-xprt to handle any handshake except the SSL handshake
 *
 * Copyright 2019 HAProxy Technologies, Olivier Houchard <ohouchard@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/connection.h>
#include <haproxy/stream_interface.h>

struct xprt_handshake_ctx {
	struct connection *conn;
	struct wait_event *subs;
	struct wait_event wait_event;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
};

DECLARE_STATIC_POOL(xprt_handshake_ctx_pool, "xprt_handshake_ctx_pool", sizeof(struct xprt_handshake_ctx));

/* This XPRT doesn't take care of sending or receiving data, once its handshake
 * is done, it just removes itself
 */
static size_t xprt_handshake_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	return 0;
}

static size_t xprt_handshake_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	return 0;
}

/* xprt_handshake_io_cb is exported to see it resolved in "show fd" */
struct task *xprt_handshake_io_cb(struct task *t, void *bctx, unsigned int state)
{
	struct xprt_handshake_ctx *ctx = bctx;
	struct connection *conn = ctx->conn;

	if (conn->flags & CO_FL_SOCKS4_SEND)
		if (!conn_send_socks4_proxy_request(conn)) {
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND,
			                     &ctx->wait_event);

			goto out;
		}

	if (conn->flags & CO_FL_SOCKS4_RECV)
		if (!conn_recv_socks4_proxy_response(conn)) {
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV,
			                     &ctx->wait_event);
			goto out;
		}

	if (conn->flags & CO_FL_ACCEPT_CIP)
		if (!conn_recv_netscaler_cip(conn, CO_FL_ACCEPT_CIP)) {
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV,
			    &ctx->wait_event);
			goto out;
		}

	if (conn->flags & CO_FL_ACCEPT_PROXY)
		if (!conn_recv_proxy(conn, CO_FL_ACCEPT_PROXY)) {
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV,
			    &ctx->wait_event);
			goto out;
		}

	if (conn->flags & CO_FL_SEND_PROXY)
		if (!conn_si_send_proxy(conn, CO_FL_SEND_PROXY)) {
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND,
			    &ctx->wait_event);
			goto out;
		}

out:
	/* Wake the stream if we're done with the handshake, or we have a
	 * connection error
	 * */
	if ((conn->flags & CO_FL_ERROR) ||
	    !(conn->flags & CO_FL_HANDSHAKE)) {
		int ret = 0;
		int woke = 0;
		int was_conn_ctx = 0;

		/* On error, wake any waiter */
		if (ctx->subs) {
			tasklet_wakeup(ctx->subs->tasklet);
			ctx->subs->events = 0;
			woke = 1;
			ctx->subs = NULL;
		}

		/* Remove ourself from the xprt chain */
		if (ctx->wait_event.events != 0)
			ctx->xprt->unsubscribe(ctx->conn,
			    ctx->xprt_ctx,
			    ctx->wait_event.events,
			    &ctx->wait_event);
		if (conn->xprt_ctx == ctx) {
			conn->xprt_ctx = ctx->xprt_ctx;
			conn->xprt = ctx->xprt;
			was_conn_ctx = 1;
		} else
			conn->xprt->remove_xprt(conn, conn->xprt_ctx, ctx,
			    ctx->xprt, ctx->xprt_ctx);
		/* If we're the first xprt for the connection, let the
		 * upper layers know. If no mux was set up yet, then call
		 * conn_create_mux, and if we have a mux, and it has a wake
		 * method, call it too.
		 */
		if (was_conn_ctx) {
			if (!ctx->conn->mux)
				ret = conn_create_mux(ctx->conn);
			if (ret >= 0 && !woke && ctx->conn->mux && ctx->conn->mux->wake)
				ret = ctx->conn->mux->wake(ctx->conn);
		}
		tasklet_free(ctx->wait_event.tasklet);
		pool_free(xprt_handshake_ctx_pool, ctx);
		t = NULL;
	}
	return t;
}

static int xprt_handshake_start(struct connection *conn, void *xprt_ctx)
{
	struct xprt_handshake_ctx *ctx = xprt_ctx;

	if (ctx->xprt->start) {
		int ret;

		ret = ctx->xprt->start(conn, ctx->xprt_ctx);
		if (ret < 0)
			return ret;
	}
	tasklet_wakeup(ctx->wait_event.tasklet);

	return 0;
}

static int xprt_handshake_init(struct connection *conn, void **xprt_ctx)
{
	struct xprt_handshake_ctx *ctx;
	/* already initialized */
	if (*xprt_ctx)
		return 0;

	ctx = pool_alloc(xprt_handshake_ctx_pool);
	if (!ctx) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		return -1;
	}
	ctx->conn = conn;
	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		pool_free(xprt_handshake_ctx_pool, ctx);
		return -1;
	}
	ctx->wait_event.tasklet->process = xprt_handshake_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;

	ctx->xprt = NULL;
	ctx->xprt_ctx = NULL;
	ctx->subs = NULL;
	*xprt_ctx = ctx;

	return 0;
}

static void xprt_handshake_close(struct connection *conn, void *xprt_ctx)
{
	struct xprt_handshake_ctx *ctx = xprt_ctx;

	if (ctx) {
		if (ctx->wait_event.events != 0)
			ctx->xprt->unsubscribe(ctx->conn, ctx->xprt_ctx,
			                       ctx->wait_event.events,
					       &ctx->wait_event);
		if (ctx->subs) {
			ctx->subs->events = 0;
			tasklet_wakeup(ctx->subs->tasklet);
		}

		if (ctx->xprt && ctx->xprt->close)
			ctx->xprt->close(conn, ctx->xprt_ctx);
		/* Remove any handshake flag, and if we were the connection
		 * xprt, get back to XPRT_RAW. If we're here because we
		 * failed an outoging connection, it will be retried using
		 * the same struct connection, and as xprt_handshake is a bit
		 * magic, because it requires a call to add_xprt(), it's better
		 * to fallback to the original XPRT to re-initiate the
		 * connection.
		 */
		conn->flags &= ~CO_FL_HANDSHAKE;
		if (conn->xprt == xprt_get(XPRT_HANDSHAKE))
			conn->xprt = xprt_get(XPRT_RAW);
		tasklet_free(ctx->wait_event.tasklet);
		pool_free(xprt_handshake_ctx_pool, ctx);
	}
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int xprt_handshake_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	struct xprt_handshake_ctx *ctx = xprt_ctx;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(ctx->subs && ctx->subs != es);

	ctx->subs = es;
	es->events |= event_type;
        return 0;

}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int xprt_handshake_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	struct xprt_handshake_ctx *ctx = xprt_ctx;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(ctx->subs && ctx->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		ctx->subs = NULL;

	return 0;
}

/* Use the provided XPRT as an underlying XPRT, and provide the old one.
 * Returns 0 on success, and non-zero on failure.
 */
static int xprt_handshake_add_xprt(struct connection *conn, void *xprt_ctx, void *toadd_ctx, const struct xprt_ops *toadd_ops, void **oldxprt_ctx, const struct xprt_ops **oldxprt_ops)
{
	struct xprt_handshake_ctx *ctx = xprt_ctx;

	if (oldxprt_ops)
		*oldxprt_ops = ctx->xprt;
	if (oldxprt_ctx)
		*oldxprt_ctx = ctx->xprt_ctx;
	ctx->xprt = toadd_ops;
	ctx->xprt_ctx = toadd_ctx;

	return 0;
}

/* Remove the specified xprt. If if it our underlying XPRT, remove it and
 * return 0, otherwise just call the remove_xprt method from the underlying
 * XPRT.
 */
static int xprt_handshake_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	struct xprt_handshake_ctx *ctx = xprt_ctx;

	if (ctx->xprt_ctx == toremove_ctx) {
		ctx->xprt_ctx = newctx;
		ctx->xprt = newops;
		return 0;
	}
	return (ctx->xprt->remove_xprt(conn, ctx->xprt_ctx, toremove_ctx, newops, newctx));
}

struct xprt_ops xprt_handshake = {
	.snd_buf  = xprt_handshake_from_buf,
	.rcv_buf  = xprt_handshake_to_buf,
	.subscribe = xprt_handshake_subscribe,
	.unsubscribe = xprt_handshake_unsubscribe,
	.remove_xprt = xprt_handshake_remove_xprt,
	.add_xprt = xprt_handshake_add_xprt,
	.init = xprt_handshake_init,
	.start = xprt_handshake_start,
	.close= xprt_handshake_close,
	.rcv_pipe = NULL,
	.snd_pipe = NULL,
	.shutr    = NULL,
	.shutw    = NULL,
	.name     = "HS",
};

__attribute__((constructor))
static void __xprt_handshake_init(void)
{
	xprt_register(XPRT_HANDSHAKE, &xprt_handshake);
}
