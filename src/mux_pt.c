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
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/pipe.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>

struct mux_pt_ctx {
	struct sedesc *sd;
	struct connection *conn;
	uint32_t term_evts_log;
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

/* returns the stconn associated to the stream */
static forceinline struct stconn *pt_sc(const struct mux_pt_ctx *pt)
{
	return pt->sd->sc;
}

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
 * stream connector, and that arg3, if non-null, is a buffer.
 */
static void pt_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct mux_pt_ctx *ctx = conn ? conn->ctx : NULL;
	const struct stconn *sc = a2;
	const struct buffer *buf = a3;
	const size_t *val = a4;

	if (!ctx || src->verbosity < PT_VERB_CLEAN)
		return;

	/* Display frontend/backend info by default */
	chunk_appendf(&trace_buf, " : [%c]", (conn_is_back(conn) ? 'B' : 'F'));

	if (src->verbosity == PT_VERB_CLEAN)
		return;

	if (!sc)
		sc = pt_sc(ctx);

	/* Display the value to the 4th argument (level > STATE) */
	if (src->level > TRACE_LEVEL_STATE && val)
		chunk_appendf(&trace_buf, " - VAL=%lu", (long)*val);

	/* Display conn and sc info, if defined (pointer + flags) */
	chunk_appendf(&trace_buf, " - conn=%p(0x%08x)", conn, conn->flags);
	chunk_appendf(&trace_buf, " sd=%p(0x%08x)", ctx->sd, se_fl_get(ctx->sd));
	if (sc)
		chunk_appendf(&trace_buf, " sc=%p(0x%08x)", sc, sc->flags);

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

static inline void mux_pt_report_term_evt(struct mux_pt_ctx *ctx, enum muxc_term_event_type type)
{
	struct connection *conn = ctx->conn;
	enum term_event_loc loc = tevt_loc_muxc;

	if (conn_is_back(conn))
		loc += 8;
	ctx->term_evts_log = tevt_report_event(ctx->term_evts_log, loc, type);
}

static void mux_pt_destroy(struct mux_pt_ctx *ctx)
{
	struct connection *conn = NULL;

	TRACE_POINT(PT_EV_CONN_END);

	/* The connection must be attached to this mux to be released */
	if (ctx->conn && ctx->conn->ctx == ctx)
		conn = ctx->conn;

	tasklet_free(ctx->wait_event.tasklet);

	if (conn && ctx->wait_event.events != 0)
		conn->xprt->unsubscribe(conn, conn->xprt_ctx, ctx->wait_event.events,
					&ctx->wait_event);
	BUG_ON(ctx->sd && !se_fl_test(ctx->sd, SE_FL_ORPHAN));
	sedesc_free(ctx->sd);
	pool_free(pool_head_pt_ctx, ctx);

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

	TRACE_ENTER(PT_EV_CONN_WAKE, ctx->conn);
	if (!se_fl_test(ctx->sd, SE_FL_ORPHAN)) {
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
		} else if (pt_sc(ctx)->app_ops->wake)
			pt_sc(ctx)->app_ops->wake(pt_sc(ctx));
		TRACE_DEVEL("leaving waking up SC", PT_EV_CONN_WAKE, ctx->conn);
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

/* Initialize the mux once it's attached. It is expected that conn->ctx points
 * to the existing stream connector (for outgoing connections) or NULL (for
 * incoming ones, in which case one will be allocated and a new stream will be
 * instantiated). Returns < 0 on error.
 */
static int mux_pt_init(struct connection *conn, struct proxy *prx, struct session *sess,
		       struct buffer *input)
{
	struct stconn *sc = conn->ctx;
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
	ctx->term_evts_log = 0;

	if (!sc) {
		ctx->sd = sedesc_new();
		if (!ctx->sd) {
			TRACE_ERROR("SC allocation failure", PT_EV_STRM_NEW|PT_EV_STRM_END|PT_EV_STRM_ERR, conn);
			goto fail_free_ctx;
		}
		ctx->sd->se     = ctx;
		ctx->sd->conn   = conn;
		se_fl_set(ctx->sd, SE_FL_T_MUX | SE_FL_ORPHAN);

		sc = sc_new_from_endp(ctx->sd, sess, input);
		if (!sc) {
			TRACE_ERROR("SC allocation failure", PT_EV_STRM_NEW|PT_EV_STRM_END|PT_EV_STRM_ERR, conn);
			goto fail_free_sd;
		}
		TRACE_POINT(PT_EV_STRM_NEW, conn, sc);
	}
	else {
		if (sc_attach_mux(sc, ctx, conn) < 0)
			goto fail_free_ctx;
		ctx->sd = sc->sedesc;
	}
	conn->ctx = ctx;
	se_fl_set(ctx->sd, SE_FL_RCV_MORE);
	if ((global.tune.options & GTUNE_USE_SPLICE) && !(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_PT))
		se_fl_set(ctx->sd, SE_FL_MAY_FASTFWD_PROD|SE_FL_MAY_FASTFWD_CONS);

	TRACE_LEAVE(PT_EV_CONN_NEW, conn);
	return 0;

 fail_free_sd:
	sedesc_free(ctx->sd);
 fail_free_ctx:
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
	int ret = 0;

	TRACE_ENTER(PT_EV_CONN_WAKE, ctx->conn);
	if (!se_fl_test(ctx->sd, SE_FL_ORPHAN)) {
		ret = pt_sc(ctx)->app_ops->wake ? pt_sc(ctx)->app_ops->wake(pt_sc(ctx)) : 0;

		if (ret < 0) {
			TRACE_DEVEL("leaving waking up SC", PT_EV_CONN_WAKE, ctx->conn);
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
static int mux_pt_attach(struct connection *conn, struct sedesc *sd, struct session *sess)
{
	struct mux_pt_ctx *ctx = conn->ctx;

	TRACE_ENTER(PT_EV_STRM_NEW, conn);
	if (ctx->wait_event.events)
		conn->xprt->unsubscribe(ctx->conn, conn->xprt_ctx, SUB_RETRY_RECV, &ctx->wait_event);
	if (sc_attach_mux(sd->sc, ctx, conn) < 0)
		return -1;
	ctx->sd = sd;
	se_fl_set(ctx->sd, SE_FL_RCV_MORE);
	if ((global.tune.options & GTUNE_USE_SPLICE) && !(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_PT))
		se_fl_set(ctx->sd, SE_FL_MAY_FASTFWD_PROD|SE_FL_MAY_FASTFWD_CONS);

	TRACE_LEAVE(PT_EV_STRM_NEW, conn, sd->sc);
	return 0;
}

/* Retrieves a valid stream connector from this connection, or returns NULL.
 * For this mux, it's easy as we can only store a single stream connector.
 */
static struct stconn *mux_pt_get_first_sc(const struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->ctx;

	return pt_sc(ctx);
}

/* Destroy the mux and the associated connection if still attached to this mux
 * and no longer used */
static void mux_pt_destroy_meth(void *ctx)
{
	struct mux_pt_ctx *pt = ctx;

	TRACE_POINT(PT_EV_CONN_END, pt->conn, pt_sc(pt));
	if (se_fl_test(pt->sd, SE_FL_ORPHAN) || pt->conn->ctx != pt) {
		if (pt->conn->ctx != pt) {
			pt->sd = NULL;
		}
		mux_pt_destroy(pt);
	}
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void mux_pt_detach(struct sedesc *sd)
{
	struct connection *conn = sd->conn;
	struct mux_pt_ctx *ctx;

	TRACE_ENTER(PT_EV_STRM_END, conn, sd->sc);

	ctx = conn->ctx;

	/* Subscribe, to know if we got disconnected */
	if (!conn_is_back(conn) && conn->owner != NULL &&
	    !(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH))) {
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV, &ctx->wait_event);
	} else {
		/* There's no session attached to that connection, destroy it */
		TRACE_DEVEL("killing dead connection", PT_EV_STRM_END, conn, sd->sc);
		mux_pt_destroy(ctx);
	}

	TRACE_LEAVE(PT_EV_STRM_END);
}

/* returns the number of streams in use on a connection */
static int mux_pt_used_streams(struct connection *conn)
{
	struct mux_pt_ctx *ctx = conn->ctx;

	return (!se_fl_test(ctx->sd, SE_FL_ORPHAN) ? 1 : 0);
}

/* returns the number of streams still available on a connection */
static int mux_pt_avail_streams(struct connection *conn)
{
	return 1 - mux_pt_used_streams(conn);
}

static void mux_pt_shut(struct stconn *sc, unsigned int mode, struct se_abort_info *reason)
{
	struct connection *conn = __sc_conn(sc);
	struct mux_pt_ctx *ctx = conn->ctx;

	TRACE_ENTER(PT_EV_STRM_SHUT, conn, sc);
	if (mode & (SE_SHW_SILENT|SE_SHW_NORMAL)) {
		mux_pt_report_term_evt(ctx, muxc_tevt_type_shutw);

		if (conn_xprt_ready(conn) && conn->xprt->shutw)
			conn->xprt->shutw(conn, conn->xprt_ctx, (mode & SE_SHW_NORMAL));
		if (!(conn->flags & CO_FL_SOCK_WR_SH))
			conn_sock_shutw(conn, (mode & SE_SHW_NORMAL));
	}

	if (mode & (SE_SHR_RESET|SE_SHR_DRAIN)) {
		se_fl_clr(ctx->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		if (conn_xprt_ready(conn) && conn->xprt->shutr)
			conn->xprt->shutr(conn, conn->xprt_ctx, (mode & SE_SHR_DRAIN));
		else if (mode & SE_SHR_DRAIN)
			conn_ctrl_drain(conn);
	}

	TRACE_LEAVE(PT_EV_STRM_SHUT, conn, sc);
}

/*
 * Called from the upper layer, to get more data
 *
 * The caller is responsible for defragmenting <buf> if necessary. But <flags>
 * must be tested to know the calling context. If CO_RFL_BUF_FLUSH is set, it
 * means the caller wants to flush input data (from the mux buffer and the
 * channel buffer) to be able to use kernel splicing or any kind of mux-to-mux
 * xfer. If CO_RFL_KEEP_RECV is set, the mux must always subscribe for read
 * events before giving back. CO_RFL_BUF_WET is set if <buf> is congested with
 * data scheduled for leaving soon. CO_RFL_BUF_NOT_STUCK is set to instruct the
 * mux it may optimize the data copy to <buf> if necessary. Otherwise, it should
 * copy as much data as possible.
 */
static size_t mux_pt_rcv_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct connection *conn = __sc_conn(sc);
	struct mux_pt_ctx *ctx = conn->ctx;
	size_t ret = 0;

	TRACE_ENTER(PT_EV_RX_DATA, conn, sc, buf, (size_t[]){count});

	if (!count) {
		se_fl_set(ctx->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		goto end;
	}
	b_realign_if_empty(buf);
	ret = conn->xprt->rcv_buf(conn, conn->xprt_ctx, buf, count, flags);
	if (conn->flags & CO_FL_ERROR) {
		mux_pt_report_term_evt(ctx, muxc_tevt_type_rcv_err);
		se_fl_clr(ctx->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		if (conn_xprt_read0_pending(conn))
			se_fl_set(ctx->sd, SE_FL_EOS);
		se_fl_set(ctx->sd, SE_FL_ERROR);
		TRACE_DEVEL("error on connection", PT_EV_RX_DATA|PT_EV_CONN_ERR, conn, sc);
	}
	else if (conn_xprt_read0_pending(conn)) {
		mux_pt_report_term_evt(ctx, muxc_tevt_type_shutr);
		se_fl_clr(ctx->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		se_fl_set(ctx->sd, (SE_FL_EOI|SE_FL_EOS));
		TRACE_DEVEL("read0 on connection", PT_EV_RX_DATA, conn, sc);
	}
  end:
	TRACE_LEAVE(PT_EV_RX_DATA, conn, sc, buf, (size_t[]){ret});
	return ret;
}

/* Called from the upper layer, to send data */
static size_t mux_pt_snd_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct connection *conn = __sc_conn(sc);
	struct mux_pt_ctx *ctx = conn->ctx;
	size_t ret;

	TRACE_ENTER(PT_EV_TX_DATA, conn, sc, buf, (size_t[]){count});

	ret = conn->xprt->snd_buf(conn, conn->xprt_ctx, buf, count, flags);

	if (ret > 0)
		b_del(buf, ret);

	if (conn->flags & CO_FL_ERROR) {
		mux_pt_report_term_evt(ctx, muxc_tevt_type_snd_err);
		if (conn_xprt_read0_pending(conn))
			se_fl_set(ctx->sd, SE_FL_EOS);
		se_fl_set_error(ctx->sd);
		TRACE_DEVEL("error on connection", PT_EV_TX_DATA|PT_EV_CONN_ERR, conn, sc);
	}

	TRACE_LEAVE(PT_EV_TX_DATA, conn, sc, buf, (size_t[]){ret});
	return ret;
}

static inline struct sedesc *mux_pt_opposite_sd(struct mux_pt_ctx *ctx)
{
	return se_opposite(ctx->sd);
}

static size_t mux_pt_nego_ff(struct stconn *sc, struct buffer *input, size_t count, unsigned int flags)
{
	struct connection *conn = __sc_conn(sc);
	struct mux_pt_ctx *ctx = conn->ctx;
	size_t ret = 0;

	TRACE_ENTER(PT_EV_TX_DATA, conn, sc, 0, (size_t[]){count});

	/* Use kernel splicing if it is supported by the sender and if there
	 * are no input data _AND_ no output data.
	 *
	 * TODO: It may be good to add a flag to send obuf data first if any,
	 *       and then data in pipe, or the opposite. For now, it is not
	 *       supported to mix data.
	 */
	if (!b_data(input) && (flags & NEGO_FF_FL_MAY_SPLICE)) {
		if (conn->xprt->snd_pipe && (ctx->sd->iobuf.pipe || (pipes_used < global.maxpipes && (ctx->sd->iobuf.pipe = get_pipe())))) {
			ctx->sd->iobuf.offset = 0;
			ctx->sd->iobuf.data = 0;
			ret = count;
			goto out;
		}
		ctx->sd->iobuf.flags |= IOBUF_FL_NO_SPLICING;
		TRACE_DEVEL("Unable to allocate pipe for splicing, fallback to buffer", PT_EV_TX_DATA, conn, sc);
	}

	/* No buffer case */

  out:
	TRACE_LEAVE(PT_EV_TX_DATA, conn, sc, 0, (size_t[]){ret});
	return ret;
}

static size_t mux_pt_done_ff(struct stconn *sc)
{
	struct connection *conn = __sc_conn(sc);
	struct mux_pt_ctx *ctx = conn->ctx;
	struct sedesc *sd = ctx->sd;
	size_t total = 0;

	TRACE_ENTER(PT_EV_TX_DATA, conn, sc);

	if (sd->iobuf.pipe) {
		total = conn->xprt->snd_pipe(conn, conn->xprt_ctx, sd->iobuf.pipe, sd->iobuf.pipe->data);
		if (!sd->iobuf.pipe->data) {
			put_pipe(sd->iobuf.pipe);
			sd->iobuf.pipe = NULL;
		}
	}
	else {
		BUG_ON(sd->iobuf.buf);
	}

  out:
	if (conn->flags & CO_FL_ERROR) {
		if (conn_xprt_read0_pending(conn))
			se_fl_set(ctx->sd, SE_FL_EOS);
		se_fl_set_error(ctx->sd);
		if (sd->iobuf.pipe) {
			put_pipe(sd->iobuf.pipe);
			sd->iobuf.pipe = NULL;
		}
		TRACE_DEVEL("error on connection", PT_EV_TX_DATA|PT_EV_CONN_ERR, conn, sc);
	}

	TRACE_LEAVE(PT_EV_TX_DATA, conn, sc, 0, (size_t[]){total});
	return total;
}

static int mux_pt_fastfwd(struct stconn *sc, unsigned int count, unsigned int flags)
{
	struct connection *conn = __sc_conn(sc);
	struct mux_pt_ctx *ctx = conn->ctx;
	struct sedesc *sdo = NULL;
	size_t total = 0, try = 0;
	unsigned int nego_flags = NEGO_FF_FL_NONE;
        int ret = 0;

	TRACE_ENTER(PT_EV_RX_DATA, conn, sc, 0, (size_t[]){count});

	se_fl_clr(ctx->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
	conn->flags &= ~CO_FL_WAIT_ROOM;
	sdo = mux_pt_opposite_sd(ctx);
	if (!sdo) {
		TRACE_STATE("Opposite endpoint not available yet", PT_EV_RX_DATA, conn, sc);
		goto out;
	}

	if (conn->xprt->rcv_pipe && !!(flags & CO_RFL_MAY_SPLICE) && !(sdo->iobuf.flags & IOBUF_FL_NO_SPLICING))
		nego_flags |= NEGO_FF_FL_MAY_SPLICE;

	try = se_nego_ff(sdo, &BUF_NULL, count, nego_flags);
	if (sdo->iobuf.flags & IOBUF_FL_NO_FF) {
		/* Fast forwarding is not supported by the consumer */
		se_fl_clr(ctx->sd, SE_FL_MAY_FASTFWD_PROD);
		TRACE_DEVEL("Fast-forwarding not supported by opposite endpoint, disable it", PT_EV_RX_DATA, conn, sc);
		goto end;
	}
	if (sdo->iobuf.flags & IOBUF_FL_FF_BLOCKED) {
		se_fl_set(ctx->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		TRACE_STATE("waiting for more room", PT_EV_RX_DATA|PT_EV_STRM_ERR, conn, sc);
		goto out;
	}

	total += sdo->iobuf.data;

	if (sdo->iobuf.pipe) {
		/* Here, not data was xferred */
		ret = conn->xprt->rcv_pipe(conn, conn->xprt_ctx, sdo->iobuf.pipe, try);
		if (ret < 0) {
			TRACE_ERROR("Error when trying to fast-forward data, disable it and abort",
				    PT_EV_RX_DATA|PT_EV_STRM_ERR|PT_EV_CONN_ERR, conn, sc);
			se_fl_clr(ctx->sd, SE_FL_MAY_FASTFWD_PROD);
			BUG_ON(sdo->iobuf.pipe->data);
			put_pipe(sdo->iobuf.pipe);
			sdo->iobuf.pipe = NULL;
			goto end;
		}
		total += ret;
	}
	else {
		BUG_ON(sdo->iobuf.buf);
		ret = -1; /* abort splicing for now and fallback to buffer mode */
		goto end;
	}

	ret = total;
	se_done_ff(sdo);

	if (sdo->iobuf.pipe) {
		se_fl_set(ctx->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
	}

	TRACE_DEVEL("Data fast-forwarded", PT_EV_RX_DATA, conn, sc, 0, (size_t[]){ret});


 out:
	if (conn->flags & CO_FL_ERROR) {
		mux_pt_report_term_evt(ctx, muxc_tevt_type_rcv_err);
		if (conn_xprt_read0_pending(conn))
			se_fl_set(ctx->sd, SE_FL_EOS);
		se_fl_set(ctx->sd, SE_FL_ERROR);
		TRACE_DEVEL("error on connection", PT_EV_RX_DATA|PT_EV_CONN_ERR, conn, sc);
	}
	else if (conn_xprt_read0_pending(conn))  {
		mux_pt_report_term_evt(ctx, muxc_tevt_type_shutr);
		se_fl_set(ctx->sd, (SE_FL_EOS|SE_FL_EOI));
		TRACE_DEVEL("read0 on connection", PT_EV_RX_DATA, conn, sc);
	}
  end:
	TRACE_LEAVE(PT_EV_RX_DATA, conn, sc, 0, (size_t[]){ret});
	return ret;
}

static int mux_pt_resume_fastfwd(struct stconn *sc, unsigned int flags)
{
	struct connection *conn = __sc_conn(sc);
	struct mux_pt_ctx *ctx = conn->ctx;
	struct sedesc *sd = ctx->sd;
	size_t total = 0;

	TRACE_ENTER(PT_EV_TX_DATA, conn, sc, 0, (size_t[]){flags});

	if (sd->iobuf.pipe) {
		total = conn->xprt->snd_pipe(conn, conn->xprt_ctx, sd->iobuf.pipe, sd->iobuf.pipe->data);
		if (!sd->iobuf.pipe->data) {
			put_pipe(sd->iobuf.pipe);
			sd->iobuf.pipe = NULL;
		}
	}
	else {
		BUG_ON(sd->iobuf.buf);
	}

  out:
	if (conn->flags & CO_FL_ERROR) {
		mux_pt_report_term_evt(ctx, muxc_tevt_type_snd_err);
		if (conn_xprt_read0_pending(conn))
			se_fl_set(ctx->sd, SE_FL_EOS);
		se_fl_set_error(ctx->sd);
		if (sd->iobuf.pipe) {
			put_pipe(sd->iobuf.pipe);
			sd->iobuf.pipe = NULL;
		}
		TRACE_DEVEL("error on connection", PT_EV_TX_DATA|PT_EV_CONN_ERR, conn, sc);
	}

	TRACE_LEAVE(PT_EV_TX_DATA, conn, sc, 0, (size_t[]){total});
	return total;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int mux_pt_subscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct connection *conn = __sc_conn(sc);

	TRACE_POINT(PT_EV_RX_DATA|PT_EV_TX_DATA, conn, sc, 0, (size_t[]){event_type});
	return conn->xprt->subscribe(conn, conn->xprt_ctx, event_type, es);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int mux_pt_unsubscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct connection *conn = __sc_conn(sc);

	TRACE_POINT(PT_EV_RX_DATA|PT_EV_TX_DATA, conn, sc, 0, (size_t[]){event_type});
	return conn->xprt->unsubscribe(conn, conn->xprt_ctx, event_type, es);
}

static int mux_pt_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	struct mux_pt_ctx *ctx = conn->ctx;
	int ret = 0;

	switch (mux_ctl) {
	case MUX_CTL_STATUS:
		if (!(conn->flags & CO_FL_WAIT_XPRT))
			ret |= MUX_STATUS_READY;
		return ret;
	case MUX_CTL_EXIT_STATUS:
		return MUX_ES_UNKNOWN;
	case MUX_CTL_GET_NBSTRM:
		return mux_pt_used_streams(conn);
	case MUX_CTL_GET_MAXSTRM:
		return 1;
	case MUX_CTL_TEVTS:
		return ctx->term_evts_log;
	default:
		return -1;
	}
}

static int mux_pt_sctl(struct stconn *sc, enum mux_sctl_type mux_sctl, void *output)
{
	int ret = 0;

	switch (mux_sctl) {
	case MUX_SCTL_SID:
		if (output)
			*((int64_t *)output) = 0;
		return ret;

	case MUX_SCTL_TEVTS:
		return sc->sedesc->term_evts_log;

	default:
		return -1;
	}
}

/* config parser for global "tune.pt.zero-copy-forwarding" */
static int cfg_parse_pt_zero_copy_fwd(char **args, int section_type, struct proxy *curpx,
				      const struct proxy *defpx, const char *file, int line,
				      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.no_zero_copy_fwd &= ~NO_ZERO_COPY_FWD_PT;
	else if (strcmp(args[1], "off") == 0)
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD_PT;
	else {
		memprintf(err, "'%s' expects 'on' or 'off'.", args[0]);
		return -1;
	}
	return 0;
}


/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.pt.zero-copy-forwarding", cfg_parse_pt_zero_copy_fwd },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);


/* The mux operations */
const struct mux_ops mux_tcp_ops = {
	.init = mux_pt_init,
	.wake = mux_pt_wake,
	.rcv_buf = mux_pt_rcv_buf,
	.snd_buf = mux_pt_snd_buf,
	.nego_fastfwd = mux_pt_nego_ff,
	.done_fastfwd = mux_pt_done_ff,
	.fastfwd = mux_pt_fastfwd,
	.resume_fastfwd = mux_pt_resume_fastfwd,
	.subscribe = mux_pt_subscribe,
	.unsubscribe = mux_pt_unsubscribe,
	.attach = mux_pt_attach,
	.get_first_sc = mux_pt_get_first_sc,
	.detach = mux_pt_detach,
	.avail_streams = mux_pt_avail_streams,
	.used_streams = mux_pt_used_streams,
	.destroy = mux_pt_destroy_meth,
	.ctl = mux_pt_ctl,
	.sctl = mux_pt_sctl,
	.shut = mux_pt_shut,
	.flags = MX_FL_NONE,
	.name = "PASS",
};


const struct mux_ops mux_pt_ops = {
	.init = mux_pt_init,
	.wake = mux_pt_wake,
	.rcv_buf = mux_pt_rcv_buf,
	.snd_buf = mux_pt_snd_buf,
	.nego_fastfwd = mux_pt_nego_ff,
	.done_fastfwd = mux_pt_done_ff,
	.fastfwd = mux_pt_fastfwd,
	.resume_fastfwd = mux_pt_resume_fastfwd,
	.subscribe = mux_pt_subscribe,
	.unsubscribe = mux_pt_unsubscribe,
	.attach = mux_pt_attach,
	.get_first_sc = mux_pt_get_first_sc,
	.detach = mux_pt_detach,
	.avail_streams = mux_pt_avail_streams,
	.used_streams = mux_pt_used_streams,
	.destroy = mux_pt_destroy_meth,
	.ctl = mux_pt_ctl,
	.sctl = mux_pt_sctl,
	.shut = mux_pt_shut,
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
