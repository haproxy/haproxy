/*
 * Pass-through mux-demux for connections
 *
 * Copyright 2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <proto/connection.h>
#include <proto/stream.h>
#include <proto/task.h>

static struct pool_head *pool_head_pt_ctx;

struct mux_pt_ctx {
	struct conn_stream *cs;
	struct connection *conn;
	struct wait_event wait_event;
};

static void mux_pt_destroy(struct mux_pt_ctx *ctx)
{
	struct connection *conn = ctx->conn;

	LIST_DEL(&conn->list);
	conn_stop_tracking(conn);
	conn_full_close(conn);
	if (conn->destroy_cb)
		conn->destroy_cb(conn);
	/* We don't bother unsubscribing here, as we're about to destroy
	 * both the connection and the mux_pt_ctx
	 */
	conn_free(conn);
	pool_free(pool_head_pt_ctx, ctx);
}

/* Callback, used when we get I/Os while in idle mode */
static struct task *mux_pt_io_cb(struct task *t, void *tctx, unsigned short status)
{
	struct mux_pt_ctx *ctx = tctx;

	conn_sock_drain(ctx->conn);
	if (ctx->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))
		mux_pt_destroy(ctx);
	else
		ctx->conn->xprt->subscribe(ctx->conn, SUB_CAN_RECV,
		    &ctx->wait_event);

	return NULL;
}

/* Initialize the mux once it's attached. It is expected that conn->mux_ctx
 * points to the existing conn_stream (for outgoing connections) or NULL (for
 * incoming ones, in which case one will be allocated and a new stream will be
 * instanciated). Returns < 0 on error.
 */
static int mux_pt_init(struct connection *conn, struct proxy *prx)
{
	struct conn_stream *cs = conn->mux_ctx;
	struct mux_pt_ctx *ctx = pool_alloc(pool_head_pt_ctx);

	if (!ctx)
		goto fail;

	ctx->wait_event.task = tasklet_new();
	if (!ctx->wait_event.task)
		goto fail_free_ctx;
	ctx->wait_event.task->context = ctx;
	ctx->wait_event.task->process = mux_pt_io_cb;
	ctx->wait_event.wait_reason = 0;
	ctx->conn = conn;

	if (!cs) {
		cs = cs_new(conn);
		if (!cs)
			goto fail_free_ctx;

		if (stream_create_from_cs(cs) < 0)
			goto fail_free;

	}
	conn->mux_ctx = ctx;
	ctx->cs = cs;
	return 0;

 fail_free:
	cs_free(cs);
fail_free_ctx:
	if (ctx->wait_event.task)
		tasklet_free(ctx->wait_event.task);
	pool_free(pool_head_pt_ctx, ctx);
 fail:
	return -1;
}

/* callback to be used by default for the pass-through mux. It calls the data
 * layer wake() callback if it is set otherwise returns 0.
 */
static int mux_pt_wake(struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->mux_ctx;
	struct conn_stream *cs = ctx->cs;
	int ret = 0;

	if (cs) {
		ret = cs->data_cb->wake ? cs->data_cb->wake(cs) : 0;

		if (ret < 0)
			return ret;
	} else {
		conn_sock_drain(conn);
		if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH)) {
			mux_pt_destroy(ctx);
			return -1;
		}
	}

	/* If we had early data, and we're done with the handshake
	 * then whe know the data are safe, and we can remove the flag.
	 */
	if ((conn->flags & (CO_FL_EARLY_DATA | CO_FL_EARLY_SSL_HS | CO_FL_HANDSHAKE)) ==
	    CO_FL_EARLY_DATA)
		conn->flags &= ~CO_FL_EARLY_DATA;
	return ret;
}

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *mux_pt_attach(struct connection *conn)
{
	return NULL;
}

/* Retrieves a valid conn_stream from this connection, or returns NULL. For
 * this mux, it's easy as we can only store a single conn_stream.
 */
static const struct conn_stream *mux_pt_get_first_cs(const struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->mux_ctx;
	struct conn_stream *cs = ctx->cs;

	return cs;
}

/* Destroy the mux and the associated connection */
static void mux_pt_destroy_meth(struct connection *conn)
{
	mux_pt_destroy(conn->mux_ctx);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void mux_pt_detach(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct mux_pt_ctx *ctx = cs->conn->mux_ctx;

	/* Subscribe, to know if we got disconnected */
	conn->xprt->subscribe(conn, SUB_CAN_RECV, &ctx->wait_event);
	ctx->cs = NULL;
	mux_pt_destroy(ctx);
}

static int mux_pt_avail_streams(struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->mux_ctx;

	return (ctx->cs == NULL ? 1 : 0);
}

static void mux_pt_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	if (cs->flags & CS_FL_SHR)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutr)
		cs->conn->xprt->shutr(cs->conn, (mode == CS_SHR_DRAIN));
	if (cs->flags & CS_FL_SHW)
		conn_full_close(cs->conn);
}

static void mux_pt_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	if (cs->flags & CS_FL_SHW)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutw)
		cs->conn->xprt->shutw(cs->conn, (mode == CS_SHW_NORMAL));
	if (!(cs->flags & CS_FL_SHR))
		conn_sock_shutw(cs->conn, (mode == CS_SHW_NORMAL));
	else
		conn_full_close(cs->conn);
}

/*
 * Called from the upper layer, to get more data
 */
static size_t mux_pt_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	size_t ret;

	if (!count) {
		cs->flags |= CS_FL_RCV_MORE;
		return 0;
	}
	cs->flags &= ~CS_FL_RCV_MORE;
	ret = cs->conn->xprt->rcv_buf(cs->conn, buf, count, flags);
	if (conn_xprt_read0_pending(cs->conn))
		cs->flags |= CS_FL_EOS;
	if (cs->conn->flags & CO_FL_ERROR)
		cs->flags |= CS_FL_ERROR;
	return ret;
}

/* Called from the upper layer, to send data */
static size_t mux_pt_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	size_t ret = cs->conn->xprt->snd_buf(cs->conn, buf, count, flags);

	if (ret > 0)
		b_del(buf, ret);
	return ret;
}

/* Called from the upper layer, to subscribe to events */
static int mux_pt_subscribe(struct conn_stream *cs, int event_type, void *param)
{
	return (cs->conn->xprt->subscribe(cs->conn, event_type, param));
}

static int mux_pt_unsubscribe(struct conn_stream *cs, int event_type, void *param)
{
	return (cs->conn->xprt->unsubscribe(cs->conn, event_type, param));
}

#if defined(CONFIG_HAP_LINUX_SPLICE)
/* Send and get, using splicing */
static int mux_pt_rcv_pipe(struct conn_stream *cs, struct pipe *pipe, unsigned int count)
{
	int ret;

	ret = cs->conn->xprt->rcv_pipe(cs->conn, pipe, count);
	if (conn_xprt_read0_pending(cs->conn))
		cs->flags |= CS_FL_EOS;
	if (cs->conn->flags & CO_FL_ERROR)
		cs->flags |= CS_FL_ERROR;
	return (ret);
}

static int mux_pt_snd_pipe(struct conn_stream *cs, struct pipe *pipe)
{
	return (cs->conn->xprt->snd_pipe(cs->conn, pipe));
}
#endif

/* The mux operations */
const struct mux_ops mux_pt_ops = {
	.init = mux_pt_init,
	.wake = mux_pt_wake,
	.rcv_buf = mux_pt_rcv_buf,
	.snd_buf = mux_pt_snd_buf,
	.subscribe = mux_pt_subscribe,
	.unsubscribe = mux_pt_unsubscribe,
#if defined(CONFIG_HAP_LINUX_SPLICE)
	.rcv_pipe = mux_pt_rcv_pipe,
	.snd_pipe = mux_pt_snd_pipe,
#endif
	.attach = mux_pt_attach,
	.get_first_cs = mux_pt_get_first_cs,
	.detach = mux_pt_detach,
	.avail_streams = mux_pt_avail_streams,
	.destroy = mux_pt_destroy_meth,
	.shutr = mux_pt_shutr,
	.shutw = mux_pt_shutw,
	.flags = MX_FL_NONE,
	.name = "PASS",
};

/* PROT selection : default mux has empty name */
static struct mux_proto_list mux_proto_pt =
	{ .token = IST(""), .mode = PROTO_MODE_ANY, .side = PROTO_SIDE_BOTH, .mux = &mux_pt_ops };

__attribute__((constructor))
static void __mux_pt_init(void)
{
	register_mux_proto(&mux_proto_pt);
	pool_head_pt_ctx = create_pool("mux_pt", sizeof(struct mux_pt_ctx),
	    MEM_F_SHARED);
}
