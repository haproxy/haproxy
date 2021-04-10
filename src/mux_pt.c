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

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/pipe-t.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>

struct mux_pt_ctx {
	struct conn_stream *cs;
	struct connection *conn;
	struct wait_event wait_event;
};

DECLARE_STATIC_POOL(pool_head_pt_ctx, "mux_pt", sizeof(struct mux_pt_ctx));

/* trace source and events */
static void pt_trace(enum trace_level level, uint64_t mask,
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   pt_ctx - internal PT context
 *   strm   - application layer
 */
static const struct trace_event pt_trace_events[] = {
#define           PT_EV_CONN_NEW      (1ULL <<  0)
	{ .mask = PT_EV_CONN_NEW,     .name = "pt_conn_new",  .desc = "new PT connection" },
#define           PT_EV_CONN_WAKE     (1ULL <<  1)
	{ .mask = PT_EV_CONN_WAKE,    .name = "pt_conn_wake", .desc = "PT connection woken up" },
#define           PT_EV_CONN_END      (1ULL <<  2)
	{ .mask = PT_EV_CONN_END,     .name = "pt_conn_end",  .desc = "PT connection terminated" },
#define           PT_EV_CONN_ERR      (1ULL <<  3)
	{ .mask = PT_EV_CONN_ERR,     .name = "pt_conn_err",  .desc = "error on PT connection" },
#define           PT_EV_STRM_NEW      (1ULL <<  4)
	{ .mask = PT_EV_STRM_NEW,     .name = "strm_new",      .desc = "app-layer stream creation" },
#define           PT_EV_STRM_SHUT     (1ULL <<  5)
	{ .mask = PT_EV_STRM_SHUT,    .name = "strm_shut",     .desc = "stream shutdown" },
#define           PT_EV_STRM_END      (1ULL <<  6)
	{ .mask = PT_EV_STRM_END,     .name = "strm_end",      .desc = "detaching app-layer stream" },
#define           PT_EV_STRM_ERR      (1ULL <<  7)
	{ .mask = PT_EV_STRM_ERR,     .name = "strm_err",      .desc = "stream error" },
#define           PT_EV_RX_DATA       (1ULL <<  8)
	{ .mask = PT_EV_RX_DATA,      .name = "pt_rx_data", .desc = "Rx on PT connection" },
#define           PT_EV_TX_DATA       (1ULL <<  9)
	{ .mask = PT_EV_TX_DATA,      .name = "pt_tx_data", .desc = "Tx on PT connection" },

	{}
};


static const struct name_desc pt_trace_decoding[] = {
#define PT_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define PT_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only h1c/h1s state and flags, no real decoding" },
#define PT_VERB_SIMPLE   3
	{ .name="simple",   .desc="add request/response status line or htx info when available" },
#define PT_VERB_ADVANCED 4
	{ .name="advanced", .desc="add header fields or frame decoding when available" },
#define PT_VERB_COMPLETE 5
	{ .name="complete", .desc="add full data dump when available" },
	{ /* end */ }
};

static struct trace_source trace_pt __read_mostly = {
	.name = IST("pt"),
	.desc = "Passthrough multiplexer",
	.arg_def = TRC_ARG1_CONN,  // TRACE()'s first argument is always a connection
	.default_cb = pt_trace,
	.known_events = pt_trace_events,
	.lockon_args = NULL,
	.decoding = pt_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_pt
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

static inline void pt_trace_buf(const struct buffer *buf, size_t ofs, size_t len)
{
	size_t block1, block2;
	int line, ptr, newptr;

	block1 = b_contig_data(buf, ofs);
	block2 = 0;
	if (block1 > len)
		block1 = len;
	block2 = len - block1;

	ofs = b_peek_ofs(buf, ofs);

	line = 0;
	ptr = ofs;
	while (ptr < ofs + block1) {
		newptr = dump_text_line(&trace_buf, b_orig(buf), b_size(buf), ofs + block1, &line, ptr);
		if (newptr == ptr)
			break;
		ptr = newptr;
	}

	line = ptr = 0;
	while (ptr < block2) {
		newptr = dump_text_line(&trace_buf, b_orig(buf), b_size(buf), block2, &line, ptr);
		if (newptr == ptr)
			break;
		ptr = newptr;
	}
}

/* the PT traces always expect that arg1, if non-null, is of type connection
 * (from which we can derive the pt context), that arg2, if non-null, is a
 * conn-stream, and that arg3, if non-null, is a buffer.
 */
static void pt_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct mux_pt_ctx *ctx = conn ? conn->ctx : NULL;
	const struct conn_stream *cs = a2;
	const struct buffer *buf = a3;
	const size_t *val = a4;

	if (!ctx|| src->verbosity < PT_VERB_CLEAN)
		return;

	/* Display frontend/backend info by default */
	chunk_appendf(&trace_buf, " : [%c]", (conn_is_back(conn) ? 'B' : 'F'));

	if (src->verbosity == PT_VERB_CLEAN)
		return;

	/* Display the value to the 4th argument (level > STATE) */
	if (src->level > TRACE_LEVEL_STATE && val)
		chunk_appendf(&trace_buf, " - VAL=%lu", (long)*val);

	/* Display conn and cs info, if defined (pointer + flags) */
	chunk_appendf(&trace_buf, " - conn=%p(0x%08x)", conn, conn->flags);
	if (cs)
		chunk_appendf(&trace_buf, " cs=%p(0x%08x)", cs, cs->flags);

	if (src->verbosity == PT_VERB_MINIMAL)
		return;

	/* Display buffer info, if defined (level > USER & verbosity > SIMPLE) */
	if (src->level > TRACE_LEVEL_USER && buf) {
		int full = 0, max = 3000, chunk = 1024;

		/* Full info (level > STATE && verbosity > SIMPLE) */
		if (src->level > TRACE_LEVEL_STATE) {
			if (src->verbosity == PT_VERB_COMPLETE)
				full = 1;
			else if (src->verbosity == PT_VERB_ADVANCED) {
				full = 1;
				max = 256;
				chunk = 64;
			}
		}

		chunk_appendf(&trace_buf, " buf=%u@%p+%u/%u",
			      (unsigned int)b_data(buf), b_orig(buf),
			      (unsigned int)b_head_ofs(buf), (unsigned int)b_size(buf));

		if (b_data(buf) && full) {
			chunk_memcat(&trace_buf, "\n", 1);
			if (b_data(buf) < max)
				pt_trace_buf(buf, 0, b_data(buf));
			else {
				pt_trace_buf(buf, 0, chunk);
				chunk_memcat(&trace_buf, "  ...\n", 6);
				pt_trace_buf(buf, b_data(buf) - chunk, chunk);
			}
		}
	}
}

static void mux_pt_destroy(struct mux_pt_ctx *ctx)
{
	struct connection *conn = NULL;

	TRACE_POINT(PT_EV_CONN_END);

	if (ctx) {
		/* The connection must be attached to this mux to be released */
		if (ctx->conn && ctx->conn->ctx == ctx)
			conn = ctx->conn;

		TRACE_DEVEL("freeing pt context", PT_EV_CONN_END, conn);

		tasklet_free(ctx->wait_event.tasklet);

		if (conn && ctx->wait_event.events != 0)
			conn->xprt->unsubscribe(conn, conn->xprt_ctx, ctx->wait_event.events,
						&ctx->wait_event);
		pool_free(pool_head_pt_ctx, ctx);
	}

	if (conn) {
		conn->mux = NULL;
		conn->ctx = NULL;
		TRACE_DEVEL("freeing conn", PT_EV_CONN_END, conn);

		conn_stop_tracking(conn);
		conn_full_close(conn);
		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}
}

/* Callback, used when we get I/Os while in idle mode. This one is exported so
 * that "show fd" can resolve it.
 */
struct task *mux_pt_io_cb(struct task *t, void *tctx, unsigned int status)
{
	struct mux_pt_ctx *ctx = tctx;

	TRACE_ENTER(PT_EV_CONN_WAKE, ctx->conn, ctx->cs);
	if (ctx->cs) {
		/* There's a small race condition.
		 * mux_pt_io_cb() is only supposed to be called if we have no
		 * stream attached. However, maybe the tasklet got woken up,
		 * and this connection was then attached to a new stream.
		 * If this happened, just wake the tasklet up if anybody
		 * subscribed to receive events, and otherwise call the wake
		 * method, to make sure the event is noticed.
		 */
		if (ctx->conn->subs) {
			ctx->conn->subs->events = 0;
			tasklet_wakeup(ctx->conn->subs->tasklet);
			ctx->conn->subs = NULL;
		} else if (ctx->cs->data_cb->wake)
			ctx->cs->data_cb->wake(ctx->cs);
		TRACE_DEVEL("leaving waking up CS", PT_EV_CONN_WAKE, ctx->conn, ctx->cs);
		return t;
	}
	conn_ctrl_drain(ctx->conn);
	if (ctx->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH)) {
		TRACE_DEVEL("leaving destroying pt context", PT_EV_CONN_WAKE, ctx->conn);
		mux_pt_destroy(ctx);
		t = NULL;
	}
	else {
		ctx->conn->xprt->subscribe(ctx->conn, ctx->conn->xprt_ctx, SUB_RETRY_RECV,
					   &ctx->wait_event);
		TRACE_DEVEL("leaving subscribing for reads", PT_EV_CONN_WAKE, ctx->conn);
	}

	return t;
}

/* Initialize the mux once it's attached. It is expected that conn->ctx
 * points to the existing conn_stream (for outgoing connections) or NULL (for
 * incoming ones, in which case one will be allocated and a new stream will be
 * instantiated). Returns < 0 on error.
 */
static int mux_pt_init(struct connection *conn, struct proxy *prx, struct session *sess,
		       struct buffer *input)
{
	struct conn_stream *cs = conn->ctx;
	struct mux_pt_ctx *ctx = pool_alloc(pool_head_pt_ctx);

	TRACE_ENTER(PT_EV_CONN_NEW);

	if (!ctx) {
		TRACE_ERROR("PT context allocation failure", PT_EV_CONN_NEW|PT_EV_CONN_END|PT_EV_CONN_ERR);
		goto fail;
	}

	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet)
		goto fail_free_ctx;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.tasklet->process = mux_pt_io_cb;
	ctx->wait_event.events = 0;
	ctx->conn = conn;

	if (!cs) {
		cs = cs_new(conn, conn->target);
		if (!cs) {
			TRACE_ERROR("CS allocation failure", PT_EV_STRM_NEW|PT_EV_STRM_END|PT_EV_STRM_ERR, conn);
			goto fail_free_ctx;
		}

		if (stream_create_from_cs(cs, &BUF_NULL) < 0) {
			TRACE_ERROR("stream creation failure", PT_EV_STRM_NEW|PT_EV_STRM_END|PT_EV_STRM_ERR, conn, cs);
			goto fail_free;
		}
		TRACE_POINT(PT_EV_STRM_NEW, conn, cs);
	}
	conn->ctx = ctx;
	ctx->cs = cs;
	cs->flags |= CS_FL_RCV_MORE;
	if (global.tune.options & GTUNE_USE_SPLICE)
		cs->flags |= CS_FL_MAY_SPLICE;

	TRACE_LEAVE(PT_EV_CONN_NEW, conn, cs);
	return 0;

 fail_free:
	cs_free(cs);
fail_free_ctx:
	if (ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	pool_free(pool_head_pt_ctx, ctx);
 fail:
	TRACE_DEVEL("leaving in error", PT_EV_CONN_NEW|PT_EV_CONN_END|PT_EV_CONN_ERR);
	return -1;
}

/* callback to be used by default for the pass-through mux. It calls the data
 * layer wake() callback if it is set otherwise returns 0.
 */
static int mux_pt_wake(struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->ctx;
	struct conn_stream *cs = ctx->cs;
	int ret = 0;

	TRACE_ENTER(PT_EV_CONN_WAKE, ctx->conn, cs);
	if (cs) {
		ret = cs->data_cb->wake ? cs->data_cb->wake(cs) : 0;

		if (ret < 0) {
			TRACE_DEVEL("leaving waking up CS", PT_EV_CONN_WAKE, ctx->conn, cs);
			return ret;
		}
	} else {
		conn_ctrl_drain(conn);
		if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH)) {
			TRACE_DEVEL("leaving destroying PT context", PT_EV_CONN_WAKE, ctx->conn);
			mux_pt_destroy(ctx);
			return -1;
		}
	}

	/* If we had early data, and we're done with the handshake
	 * then we know the data are safe, and we can remove the flag.
	 */
	if ((conn->flags & (CO_FL_EARLY_DATA | CO_FL_EARLY_SSL_HS | CO_FL_WAIT_XPRT)) ==
	    CO_FL_EARLY_DATA)
		conn->flags &= ~CO_FL_EARLY_DATA;

	TRACE_LEAVE(PT_EV_CONN_WAKE, ctx->conn);
	return ret;
}

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *mux_pt_attach(struct connection *conn, struct session *sess)
{
	struct conn_stream *cs;
	struct mux_pt_ctx *ctx = conn->ctx;

	TRACE_ENTER(PT_EV_STRM_NEW, conn);
	if (ctx->wait_event.events)
		conn->xprt->unsubscribe(ctx->conn, conn->xprt_ctx, SUB_RETRY_RECV, &ctx->wait_event);
	cs = cs_new(conn, conn->target);
	if (!cs) {
		TRACE_ERROR("CS allocation failure", PT_EV_STRM_NEW|PT_EV_STRM_END|PT_EV_STRM_ERR, conn);
		goto fail;
	}

	ctx->cs = cs;
	cs->flags |= CS_FL_RCV_MORE;

	TRACE_LEAVE(PT_EV_STRM_NEW, conn, cs);
	return (cs);
fail:
	TRACE_DEVEL("leaving on error", PT_EV_STRM_NEW|PT_EV_STRM_END|PT_EV_STRM_ERR, conn);
	return NULL;
}

/* Retrieves a valid conn_stream from this connection, or returns NULL. For
 * this mux, it's easy as we can only store a single conn_stream.
 */
static const struct conn_stream *mux_pt_get_first_cs(const struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->ctx;
	struct conn_stream *cs = ctx->cs;

	return cs;
}

/* Destroy the mux and the associated connection if still attached to this mux
 * and no longer used */
static void mux_pt_destroy_meth(void *ctx)
{
	struct mux_pt_ctx *pt = ctx;

	TRACE_POINT(PT_EV_CONN_END, pt->conn, pt->cs);
	if (!(pt->cs) || !(pt->conn) || pt->conn->ctx != pt)
		mux_pt_destroy(pt);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void mux_pt_detach(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct mux_pt_ctx *ctx = cs->conn->ctx;

	TRACE_ENTER(PT_EV_STRM_END, conn, cs);

	/* Subscribe, to know if we got disconnected */
	if (conn->owner != NULL &&
	    !(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH))) {
		ctx->cs = NULL;
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV, &ctx->wait_event);
	} else {
		/* There's no session attached to that connection, destroy it */
		TRACE_DEVEL("killing dead connection", PT_EV_STRM_END, conn, cs);
		mux_pt_destroy(ctx);
	}

	TRACE_LEAVE(PT_EV_STRM_END);
}

/* returns the number of streams in use on a connection */
static int mux_pt_used_streams(struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->ctx;

	return ctx->cs ? 1 : 0;
}

/* returns the number of streams still available on a connection */
static int mux_pt_avail_streams(struct connection *conn)
{
	return 1 - mux_pt_used_streams(conn);
}

static void mux_pt_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	TRACE_ENTER(PT_EV_STRM_SHUT, cs->conn, cs);

	if (cs->flags & CS_FL_SHR)
		return;
	cs->flags &= ~(CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutr)
		cs->conn->xprt->shutr(cs->conn, cs->conn->xprt_ctx,
		    (mode == CS_SHR_DRAIN));
	else if (mode == CS_SHR_DRAIN)
		conn_ctrl_drain(cs->conn);
	if (cs->flags & CS_FL_SHW)
		conn_full_close(cs->conn);

	TRACE_LEAVE(PT_EV_STRM_SHUT, cs->conn, cs);
}

static void mux_pt_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	TRACE_ENTER(PT_EV_STRM_SHUT, cs->conn, cs);

	if (cs->flags & CS_FL_SHW)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutw)
		cs->conn->xprt->shutw(cs->conn, cs->conn->xprt_ctx,
		    (mode == CS_SHW_NORMAL));
	if (!(cs->flags & CS_FL_SHR))
		conn_sock_shutw(cs->conn, (mode == CS_SHW_NORMAL));
	else
		conn_full_close(cs->conn);

	TRACE_LEAVE(PT_EV_STRM_SHUT, cs->conn, cs);
}

/*
 * Called from the upper layer, to get more data
 */
static size_t mux_pt_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	size_t ret = 0;

	TRACE_ENTER(PT_EV_RX_DATA, cs->conn, cs, buf, (size_t[]){count});

	if (!count) {
		cs->flags |= (CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
		goto end;
	}
	b_realign_if_empty(buf);
	ret = cs->conn->xprt->rcv_buf(cs->conn, cs->conn->xprt_ctx, buf, count, flags);
	if (conn_xprt_read0_pending(cs->conn)) {
		cs->flags &= ~(CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
		cs->flags |= CS_FL_EOS;
		TRACE_DEVEL("read0 on connection", PT_EV_RX_DATA, cs->conn, cs);
	}
	if (cs->conn->flags & CO_FL_ERROR) {
		cs->flags &= ~(CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
		cs->flags |= CS_FL_ERROR;
		TRACE_DEVEL("error on connection", PT_EV_RX_DATA|PT_EV_CONN_ERR, cs->conn, cs);
	}
  end:
	TRACE_LEAVE(PT_EV_RX_DATA, cs->conn, cs, buf, (size_t[]){ret});
	return ret;
}

/* Called from the upper layer, to send data */
static size_t mux_pt_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	size_t ret;

	TRACE_ENTER(PT_EV_TX_DATA, cs->conn, cs, buf, (size_t[]){count});

	ret = cs->conn->xprt->snd_buf(cs->conn, cs->conn->xprt_ctx, buf, count, flags);

	if (ret > 0)
		b_del(buf, ret);

	TRACE_LEAVE(PT_EV_TX_DATA, cs->conn, cs, buf, (size_t[]){ret});
	return ret;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int mux_pt_subscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	TRACE_POINT(PT_EV_RX_DATA|PT_EV_TX_DATA, cs->conn, cs, 0, (size_t[]){event_type});
	return cs->conn->xprt->subscribe(cs->conn, cs->conn->xprt_ctx, event_type, es);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int mux_pt_unsubscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	TRACE_POINT(PT_EV_RX_DATA|PT_EV_TX_DATA, cs->conn, cs, 0, (size_t[]){event_type});
	return cs->conn->xprt->unsubscribe(cs->conn, cs->conn->xprt_ctx, event_type, es);
}

#if defined(USE_LINUX_SPLICE)
/* Send and get, using splicing */
static int mux_pt_rcv_pipe(struct conn_stream *cs, struct pipe *pipe, unsigned int count)
{
	int ret;

	TRACE_ENTER(PT_EV_RX_DATA, cs->conn, cs, 0, (size_t[]){count});

	ret = cs->conn->xprt->rcv_pipe(cs->conn, cs->conn->xprt_ctx, pipe, count);
	if (conn_xprt_read0_pending(cs->conn))  {
		cs->flags |= CS_FL_EOS;
		TRACE_DEVEL("read0 on connection", PT_EV_RX_DATA, cs->conn, cs);
	}
	if (cs->conn->flags & CO_FL_ERROR) {
		cs->flags |= CS_FL_ERROR;
		TRACE_DEVEL("error on connection", PT_EV_RX_DATA|PT_EV_CONN_ERR, cs->conn, cs);
	}

	TRACE_LEAVE(PT_EV_RX_DATA, cs->conn, cs, 0, (size_t[]){ret});
	return (ret);
}

static int mux_pt_snd_pipe(struct conn_stream *cs, struct pipe *pipe)
{
	int ret;

	TRACE_ENTER(PT_EV_TX_DATA, cs->conn, cs, 0, (size_t[]){pipe->data});

	ret = cs->conn->xprt->snd_pipe(cs->conn, cs->conn->xprt_ctx, pipe);

	TRACE_LEAVE(PT_EV_TX_DATA, cs->conn, cs, 0, (size_t[]){ret});
	return ret;
}
#endif

static int mux_pt_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	int ret = 0;
	switch (mux_ctl) {
	case MUX_STATUS:
		if (!(conn->flags & CO_FL_WAIT_XPRT))
			ret |= MUX_STATUS_READY;
		return ret;
	case MUX_EXIT_STATUS:
		return MUX_ES_UNKNOWN;
	default:
		return -1;
	}
}

/* The mux operations */
const struct mux_ops mux_tcp_ops = {
	.init = mux_pt_init,
	.wake = mux_pt_wake,
	.rcv_buf = mux_pt_rcv_buf,
	.snd_buf = mux_pt_snd_buf,
	.subscribe = mux_pt_subscribe,
	.unsubscribe = mux_pt_unsubscribe,
#if defined(USE_LINUX_SPLICE)
	.rcv_pipe = mux_pt_rcv_pipe,
	.snd_pipe = mux_pt_snd_pipe,
#endif
	.attach = mux_pt_attach,
	.get_first_cs = mux_pt_get_first_cs,
	.detach = mux_pt_detach,
	.avail_streams = mux_pt_avail_streams,
	.used_streams = mux_pt_used_streams,
	.destroy = mux_pt_destroy_meth,
	.ctl = mux_pt_ctl,
	.shutr = mux_pt_shutr,
	.shutw = mux_pt_shutw,
	.flags = MX_FL_NONE,
	.name = "PASS",
};


const struct mux_ops mux_pt_ops = {
	.init = mux_pt_init,
	.wake = mux_pt_wake,
	.rcv_buf = mux_pt_rcv_buf,
	.snd_buf = mux_pt_snd_buf,
	.subscribe = mux_pt_subscribe,
	.unsubscribe = mux_pt_unsubscribe,
#if defined(USE_LINUX_SPLICE)
	.rcv_pipe = mux_pt_rcv_pipe,
	.snd_pipe = mux_pt_snd_pipe,
#endif
	.attach = mux_pt_attach,
	.get_first_cs = mux_pt_get_first_cs,
	.detach = mux_pt_detach,
	.avail_streams = mux_pt_avail_streams,
	.used_streams = mux_pt_used_streams,
	.destroy = mux_pt_destroy_meth,
	.ctl = mux_pt_ctl,
	.shutr = mux_pt_shutr,
	.shutw = mux_pt_shutw,
	.flags = MX_FL_NONE|MX_FL_NO_UPG,
	.name = "PASS",
};

/* PROT selection : default mux has empty name */
static struct mux_proto_list mux_proto_none =
	{ .token = IST("none"), .mode = PROTO_MODE_TCP, .side = PROTO_SIDE_BOTH, .mux = &mux_pt_ops };
static struct mux_proto_list mux_proto_tcp =
	{ .token = IST(""), .mode = PROTO_MODE_TCP, .side = PROTO_SIDE_BOTH, .mux = &mux_tcp_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_none);
INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_tcp);
