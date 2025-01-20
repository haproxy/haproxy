/*
 * HTTP/1 mux-demux for connections
 *
 * Copyright 2018 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <import/ebistree.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/h1.h>
#include <haproxy/h1_htx.h>
#include <haproxy/h2.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/istbuf.h>
#include <haproxy/log.h>
#include <haproxy/mux_h1-t.h>
#include <haproxy/pipe.h>
#include <haproxy/proxy.h>
#include <haproxy/session-t.h>
#include <haproxy/stats.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/trace.h>

/* H1 connection descriptor */
struct h1c {
	struct connection *conn;
	struct h1s *h1s;                 /* H1 stream descriptor */
	struct task *task;               /* timeout management task */

	uint32_t flags;                  /* Connection flags: H1C_F_* */
	enum h1_cs state;                /* Connection state */


	struct buffer ibuf;              /* Input buffer to store data before parsing */
	struct buffer obuf;              /* Output buffer to store data after reformatting */
	struct proxy *px;

	unsigned int errcode;            /* Status code when an error occurred at the H1 connection level */

	int idle_exp;                    /* idle expiration date (http-keep-alive or http-request timeout) */
	int timeout;                     /* client/server timeout duration */
	int shut_timeout;                /* client-fin/server-fin timeout duration */

	unsigned int req_count;          /* The number of requests handled by this H1 connection */

	uint32_t term_evts_log;        /* Termination events log: first 4 events reported */

	struct h1_counters *px_counters; /* h1 counters attached to proxy */
	struct buffer_wait buf_wait;     /* Wait list for buffer allocation */
	struct wait_event wait_event;    /* To be used if we're waiting for I/Os */
};

/* H1 stream descriptor */
struct h1s {
	struct h1c *h1c;
	struct sedesc *sd;
	uint32_t flags;                /* Connection flags: H1S_F_* */

	struct wait_event *subs;      /* Address of the wait_event the stream connector associated is waiting on */

	struct session *sess;         /* Associated session */
	struct buffer rxbuf;          /* receive buffer, always valid (buf_empty or real buffer) */
	struct h1m req;
	struct h1m res;

	enum http_meth_t meth; /* HTTP request method  */
	uint16_t status;       /* HTTP response status */

	char ws_key[25];       /* websocket handshake key */
};

/* Map of headers used to convert outgoing headers */
struct h1_hdrs_map {
	char *name;
	struct eb_root map;
};

/* An entry in a headers map */
struct h1_hdr_entry  {
	struct ist name;
	struct ebpt_node node;
};

/* Declare the headers map */
static struct h1_hdrs_map hdrs_map = { .name = NULL, .map  = EB_ROOT };
static int accept_payload_with_any_method = 0;

/* trace source and events */
static void h1_trace(enum trace_level level, uint64_t mask,
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4);

static void h1_trace_fill_ctx(struct trace_ctx *ctx, const struct trace_source *src,
                              const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   h1c   - internal H1 connection
 *   h1s   - internal H1 stream
 *   strm  - application layer
 *   rx    - data receipt
 *   tx    - data transmission
 *
 */
static const struct trace_event h1_trace_events[] = {
#define           H1_EV_H1C_NEW       (1ULL <<  0)
	{ .mask = H1_EV_H1C_NEW,      .name = "h1c_new",      .desc = "new H1 connection" },
#define           H1_EV_H1C_RECV      (1ULL <<  1)
	{ .mask = H1_EV_H1C_RECV,     .name = "h1c_recv",     .desc = "Rx on H1 connection" },
#define           H1_EV_H1C_SEND      (1ULL <<  2)
	{ .mask = H1_EV_H1C_SEND,     .name = "h1c_send",     .desc = "Tx on H1 connection" },
#define           H1_EV_H1C_BLK       (1ULL <<  3)
	{ .mask = H1_EV_H1C_BLK,      .name = "h1c_blk",      .desc = "H1 connection blocked" },
#define           H1_EV_H1C_WAKE      (1ULL <<  4)
	{ .mask = H1_EV_H1C_WAKE,     .name = "h1c_wake",     .desc = "H1 connection woken up" },
#define           H1_EV_H1C_END       (1ULL <<  5)
	{ .mask = H1_EV_H1C_END,      .name = "h1c_end",      .desc = "H1 connection terminated" },
#define           H1_EV_H1C_ERR       (1ULL <<  6)
	{ .mask = H1_EV_H1C_ERR,      .name = "h1c_err",      .desc = "error on H1 connection" },

#define           H1_EV_RX_DATA       (1ULL <<  7)
	{ .mask = H1_EV_RX_DATA,      .name = "rx_data",      .desc = "receipt of any H1 data" },
#define           H1_EV_RX_EOI        (1ULL <<  8)
	{ .mask = H1_EV_RX_EOI,       .name = "rx_eoi",       .desc = "receipt of end of H1 input" },
#define           H1_EV_RX_HDRS       (1ULL <<  9)
	{ .mask = H1_EV_RX_HDRS,      .name = "rx_headers",   .desc = "receipt of H1 headers" },
#define           H1_EV_RX_BODY       (1ULL << 10)
	{ .mask = H1_EV_RX_BODY,      .name = "rx_body",      .desc = "receipt of H1 body" },
#define           H1_EV_RX_TLRS       (1ULL << 11)
	{ .mask = H1_EV_RX_TLRS,      .name = "rx_trailerus", .desc = "receipt of H1 trailers" },

#define           H1_EV_TX_DATA       (1ULL << 12)
	{ .mask = H1_EV_TX_DATA,      .name = "tx_data",      .desc = "transmission of any H1 data" },
#define           H1_EV_TX_EOI        (1ULL << 13)
	{ .mask = H1_EV_TX_EOI,       .name = "tx_eoi",       .desc = "transmission of end of H1 input" },
#define           H1_EV_TX_HDRS       (1ULL << 14)
	{ .mask = H1_EV_TX_HDRS,      .name = "tx_headers",   .desc = "transmission of all headers" },
#define           H1_EV_TX_BODY       (1ULL << 15)
	{ .mask = H1_EV_TX_BODY,      .name = "tx_body",      .desc = "transmission of H1 body" },
#define           H1_EV_TX_TLRS       (1ULL << 16)
	{ .mask = H1_EV_TX_TLRS,      .name = "tx_trailerus", .desc = "transmission of H1 trailers" },

#define           H1_EV_H1S_NEW       (1ULL << 17)
	{ .mask = H1_EV_H1S_NEW,      .name = "h1s_new",     .desc = "new H1 stream" },
#define           H1_EV_H1S_BLK       (1ULL << 18)
	{ .mask = H1_EV_H1S_BLK,      .name = "h1s_blk",     .desc = "H1 stream blocked" },
#define           H1_EV_H1S_END       (1ULL << 19)
	{ .mask = H1_EV_H1S_END,      .name = "h1s_end",     .desc = "H1 stream terminated" },
#define           H1_EV_H1S_ERR       (1ULL << 20)
	{ .mask = H1_EV_H1S_ERR,      .name = "h1s_err",     .desc = "error on H1 stream" },

#define           H1_EV_STRM_NEW      (1ULL << 21)
	{ .mask = H1_EV_STRM_NEW,     .name = "strm_new",    .desc = "app-layer stream creation" },
#define           H1_EV_STRM_RECV     (1ULL << 22)
	{ .mask = H1_EV_STRM_RECV,    .name = "strm_recv",   .desc = "receiving data for stream" },
#define           H1_EV_STRM_SEND     (1ULL << 23)
	{ .mask = H1_EV_STRM_SEND,    .name = "strm_send",   .desc = "sending data for stream" },
#define           H1_EV_STRM_WAKE     (1ULL << 24)
	{ .mask = H1_EV_STRM_WAKE,    .name = "strm_wake",   .desc = "stream woken up" },
#define           H1_EV_STRM_SHUT     (1ULL << 25)
	{ .mask = H1_EV_STRM_SHUT,    .name = "strm_shut",   .desc = "stream shutdown" },
#define           H1_EV_STRM_END      (1ULL << 26)
	{ .mask = H1_EV_STRM_END,     .name = "strm_end",    .desc = "detaching app-layer stream" },
#define           H1_EV_STRM_ERR      (1ULL << 27)
	{ .mask = H1_EV_STRM_ERR,     .name = "strm_err",    .desc = "stream error" },

	{ }
};

static const struct name_desc h1_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="h1s", .desc="H1 stream" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc h1_trace_decoding[] = {
#define H1_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define H1_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only h1c/h1s state and flags, no real decoding" },
#define H1_VERB_SIMPLE   3
	{ .name="simple",   .desc="add request/response status line or htx info when available" },
#define H1_VERB_ADVANCED 4
	{ .name="advanced", .desc="add header fields or frame decoding when available" },
#define H1_VERB_COMPLETE 5
	{ .name="complete", .desc="add full data dump when available" },
	{ /* end */ }
};

static struct trace_source trace_h1 __read_mostly = {
	.name = IST("h1"),
	.desc = "HTTP/1 multiplexer",
	.arg_def = TRC_ARG1_CONN,  // TRACE()'s first argument is always a connection
	.default_cb = h1_trace,
	.fill_ctx = h1_trace_fill_ctx,
	.known_events = h1_trace_events,
	.lockon_args = h1_trace_lockon_args,
	.decoding = h1_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_h1
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);


/* h1 stats module */
enum {
	H1_ST_OPEN_CONN,
	H1_ST_OPEN_STREAM,
	H1_ST_TOTAL_CONN,
	H1_ST_TOTAL_STREAM,

	H1_ST_BYTES_IN,
	H1_ST_BYTES_OUT,
#if defined(USE_LINUX_SPLICE)
	H1_ST_SPLICED_BYTES_IN,
	H1_ST_SPLICED_BYTES_OUT,
#endif
	H1_STATS_COUNT /* must be the last member of the enum */
};


static struct stat_col h1_stats[] = {
	[H1_ST_OPEN_CONN]            = { .name = "h1_open_connections",
	                                 .desc = "Count of currently open connections" },
	[H1_ST_OPEN_STREAM]          = { .name = "h1_open_streams",
	                                 .desc = "Count of currently open streams" },
	[H1_ST_TOTAL_CONN]           = { .name = "h1_total_connections",
	                                 .desc = "Total number of connections" },
	[H1_ST_TOTAL_STREAM]         = { .name = "h1_total_streams",
	                                 .desc = "Total number of streams" },

	[H1_ST_BYTES_IN]             = { .name = "h1_bytes_in",
	                                 .desc = "Total number of bytes received" },
	[H1_ST_BYTES_OUT]            = { .name = "h1_bytes_out",
	                                 .desc = "Total number of bytes send" },
#if defined(USE_LINUX_SPLICE)
	[H1_ST_SPLICED_BYTES_IN]     = { .name = "h1_spliced_bytes_in",
		                         .desc = "Total number of bytes received using kernel splicing" },
	[H1_ST_SPLICED_BYTES_OUT]    = { .name = "h1_spliced_bytes_out",
		                         .desc = "Total number of bytes sendusing kernel splicing" },
#endif

};

static struct h1_counters {
	long long open_conns;          /* count of currently open connections */
	long long open_streams;       /* count of currently open streams */
	long long total_conns;        /* total number of connections */
	long long total_streams;      /* total number of streams */

	long long bytes_in;           /* number of bytes received */
	long long bytes_out;          /* number of bytes sent */
#if defined(USE_LINUX_SPLICE)
	long long spliced_bytes_in;   /* number of bytes received using kernel splicing */
	long long spliced_bytes_out;  /* number of bytes sent using kernel splicing */
#endif
} h1_counters;

static int h1_fill_stats(void *data, struct field *stats, unsigned int *selected_field)
{
	struct h1_counters *counters = data;
	unsigned int current_field = (selected_field != NULL ? *selected_field : 0);

	for (; current_field < H1_STATS_COUNT; current_field++) {
		struct field metric = { 0 };

		switch (current_field) {
		case H1_ST_OPEN_CONN:
			metric = mkf_u64(FN_GAUGE,   counters->open_conns);
			break;
		case H1_ST_OPEN_STREAM:
			metric = mkf_u64(FN_GAUGE,   counters->open_streams);
			break;
		case H1_ST_TOTAL_CONN:
			metric = mkf_u64(FN_COUNTER, counters->total_conns);
			break;
		case H1_ST_TOTAL_STREAM:
			metric = mkf_u64(FN_COUNTER, counters->total_streams);
			break;
		case H1_ST_BYTES_IN:
			metric = mkf_u64(FN_COUNTER, counters->bytes_in);
			break;
		case H1_ST_BYTES_OUT:
			metric = mkf_u64(FN_COUNTER, counters->bytes_out);
			break;
#if defined(USE_LINUX_SPLICE)
		case H1_ST_SPLICED_BYTES_IN:
			metric = mkf_u64(FN_COUNTER, counters->spliced_bytes_in);
			break;
		case H1_ST_SPLICED_BYTES_OUT:
			metric = mkf_u64(FN_COUNTER, counters->spliced_bytes_out);
			break;
#endif
		default:
			/* not used for frontends. If a specific metric
			 * is requested, return an error. Otherwise continue.
			 */
			if (selected_field != NULL)
				return 0;
			continue;
		}
		stats[current_field] = metric;
		if (selected_field != NULL)
			break;
	}
	return 1;
}

static struct stats_module h1_stats_module = {
	.name          = "h1",
	.fill_stats    = h1_fill_stats,
	.stats         = h1_stats,
	.stats_count   = H1_STATS_COUNT,
	.counters      = &h1_counters,
	.counters_size = sizeof(h1_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_FE|STATS_PX_CAP_BE),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &h1_stats_module);


/* the h1c and h1s pools */
DECLARE_STATIC_POOL(pool_head_h1c, "h1c", sizeof(struct h1c));
DECLARE_STATIC_POOL(pool_head_h1s, "h1s", sizeof(struct h1s));

static int h1_recv(struct h1c *h1c);
static int h1_send(struct h1c *h1c);
static int h1_process(struct h1c *h1c);
static void h1_release(struct h1c *h1c);

/* h1_io_cb is exported to see it resolved in "show fd" */
struct task *h1_io_cb(struct task *t, void *ctx, unsigned int state);
struct task *h1_timeout_task(struct task *t, void *context, unsigned int state);
static void h1_shutw_conn(struct connection *conn);
static void h1_wake_stream_for_recv(struct h1s *h1s);
static void h1_wake_stream_for_send(struct h1s *h1s);
static void h1s_destroy(struct h1s *h1s);
static int h1_dump_h1c_info(struct buffer *msg, struct h1c *h1c, const char *pfx);
static int h1_dump_h1s_info(struct buffer *msg, const struct h1s *h1s, const char *pfx);

/* returns the stconn associated to the H1 stream */
static forceinline struct stconn *h1s_sc(const struct h1s *h1s)
{
	return h1s->sd->sc;
}

/* the H1 traces always expect that arg1, if non-null, is of type connection
 * (from which we can derive h1c), that arg2, if non-null, is of type h1s, and
 * that arg3, if non-null, is a htx for rx/tx headers.
 */
static void h1_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct h1c *h1c = conn ? conn->ctx : NULL;
	const struct h1s *h1s = a2;
	const struct htx *htx = a3;
	const size_t     *val = a4;

	if (!h1c)
		h1c = (h1s ? h1s->h1c : NULL);

	if (!h1c || src->verbosity < H1_VERB_CLEAN)
		return;

	/* Display frontend/backend info by default */
	chunk_appendf(&trace_buf, " : [%c,%s]", ((h1c->flags & H1C_F_IS_BACK) ? 'B' : 'F'), h1c_st_to_str(h1c->state));

	/* Display request and response states if h1s is defined */
	if (h1s) {
		chunk_appendf(&trace_buf, " [%s, %s]",
			      h1m_state_str(h1s->req.state), h1m_state_str(h1s->res.state));

		if (src->verbosity > H1_VERB_SIMPLE) {
			chunk_appendf(&trace_buf, " - req=(.fl=0x%08x .curr_len=%lu .body_len=%lu)",
				      h1s->req.flags, (unsigned long)h1s->req.curr_len, (unsigned long)h1s->req.body_len);
			chunk_appendf(&trace_buf, "  res=(.fl=0x%08x .curr_len=%lu .body_len=%lu)",
				      h1s->res.flags, (unsigned long)h1s->res.curr_len, (unsigned long)h1s->res.body_len);
		}

	}

	if (src->verbosity == H1_VERB_CLEAN)
		return;

	/* Display the value to the 4th argument (level > STATE) */
	if (src->level > TRACE_LEVEL_STATE && val)
		chunk_appendf(&trace_buf, " - VAL=%lu", (long)*val);

	/* Display status-line if possible (verbosity > MINIMAL) */
	if (src->verbosity > H1_VERB_MINIMAL && htx && htx_nbblks(htx)) {
		const struct htx_blk *blk = htx_get_head_blk(htx);
		const struct htx_sl  *sl  = htx_get_blk_ptr(htx, blk);
		enum htx_blk_type    type = htx_get_blk_type(blk);

		if (type == HTX_BLK_REQ_SL || type == HTX_BLK_RES_SL)
			chunk_appendf(&trace_buf, " - \"%.*s %.*s %.*s\"",
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
	}

	/* Display h1c info and, if defined, h1s info (pointer + flags) */
	chunk_appendf(&trace_buf, " - h1c=%p(0x%08x)", h1c, h1c->flags);
	if (h1c->conn)
		chunk_appendf(&trace_buf, " conn=%p(0x%08x)", h1c->conn, h1c->conn->flags);
	chunk_appendf(&trace_buf, " .task=%p", h1c->task);
	if (h1c->task) {
		chunk_appendf(&trace_buf, " .exp=%s",
			      h1c->task->expire ? tick_is_expired(h1c->task->expire, now_ms) ? "<PAST>" :
			      human_time(TICKS_TO_MS(h1c->task->expire - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	}
	chunk_appendf(&trace_buf, " .idle_exp=%s",
		      h1c->idle_exp ? tick_is_expired(h1c->idle_exp, now_ms) ? "<PAST>" :
		      human_time(TICKS_TO_MS(h1c->idle_exp - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	if (h1s) {
		chunk_appendf(&trace_buf, " h1s=%p(0x%08x)", h1s, h1s->flags);
		if (h1s->sd)
			chunk_appendf(&trace_buf, " sd=%p(0x%08x)", h1s->sd, se_fl_get(h1s->sd));
		if (h1s->sd && h1s_sc(h1s))
			chunk_appendf(&trace_buf, " sc=%p(0x%08x)", h1s_sc(h1s), h1s_sc(h1s)->flags);
	}

	if (src->verbosity == H1_VERB_MINIMAL)
		return;

	/* Display input and output buffer info (level > USER & verbosity > SIMPLE) */
	if (src->level > TRACE_LEVEL_USER) {
		if (src->verbosity == H1_VERB_COMPLETE ||
		    (src->verbosity == H1_VERB_ADVANCED && (mask & (H1_EV_H1C_RECV|H1_EV_STRM_RECV))))
			chunk_appendf(&trace_buf, " ibuf=%u@%p+%u/%u",
				      (unsigned int)b_data(&h1c->ibuf), b_orig(&h1c->ibuf),
				      (unsigned int)b_head_ofs(&h1c->ibuf), (unsigned int)b_size(&h1c->ibuf));
		if (src->verbosity == H1_VERB_COMPLETE ||
		    (src->verbosity == H1_VERB_ADVANCED && (mask & (H1_EV_H1C_SEND|H1_EV_STRM_SEND)))) {
			chunk_appendf(&trace_buf, " obuf=%u@%p+%u/%u",
				      (unsigned int)b_data(&h1c->obuf), b_orig(&h1c->obuf),
				      (unsigned int)b_head_ofs(&h1c->obuf), (unsigned int)b_size(&h1c->obuf));

			if (h1s && h1s->sd)
				chunk_appendf(&trace_buf, " iobuf(.pipe=%d, .data=%u+%u, .flags=0x%x)",
					      (h1s->sd->iobuf.pipe ? h1s->sd->iobuf.pipe->data : 0),
					      (unsigned int)h1s->sd->iobuf.data, (unsigned int)h1s->sd->iobuf.offset,
					      h1s->sd->iobuf.flags);
		}
	}

	/* Display htx info if defined (level > USER) */
	if (src->level > TRACE_LEVEL_USER && htx) {
		int full = 0;

		/* Full htx info (level > STATE && verbosity > SIMPLE) */
		if (src->level > TRACE_LEVEL_STATE) {
			if (src->verbosity == H1_VERB_COMPLETE)
				full = 1;
			else if (src->verbosity == H1_VERB_ADVANCED && (mask & (H1_EV_RX_HDRS|H1_EV_TX_HDRS)))
				full = 1;
		}

		chunk_memcat(&trace_buf, "\n\t", 2);
		htx_dump(&trace_buf, htx, full);
	}
}

/* This fills the trace_ctx with extra info guessed from the args */
static void h1_trace_fill_ctx(struct trace_ctx *ctx, const struct trace_source *src,
                              const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct h1c *h1c = conn ? conn->ctx : NULL;
	const struct h1s *h1s = a2;

	if (!ctx->conn)
		ctx->conn = conn;

	if (h1c) {
		if (!ctx->fe && !(h1c->flags & H1C_F_IS_BACK))
			ctx->fe = h1c->px;

		if (!ctx->be && (h1c->flags & H1C_F_IS_BACK))
			ctx->be = h1c->px;
	}

	if (h1s) {
		if (!ctx->sess)
			ctx->sess = h1s->sess;
		if (!ctx->strm && h1s->sd && h1s_sc(h1s))
			ctx->strm = sc_strm(h1s_sc(h1s));
	}
}


/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/
/*
 * Indicates whether or not we may receive data. The rules are the following :
 *   - if an error or a shutdown for reads was detected on the H1 connection we
 *      must not attempt to receive
 *   - if we are waiting for the connection establishment, we must not attempt
 *      to receive
 *   - if reads are explicitly disabled, we must not attempt to receive
 *   - if the input buffer failed to be allocated or is full , we must not try
 *     to receive
 *   - if the mux is blocked on an input condition, we must may not attempt to
 *     receive
 *   - otherwise we may attempt to receive
 */
static inline int h1_recv_allowed(const struct h1c *h1c)
{
	if (h1c->flags & (H1C_F_EOS|H1C_F_ERROR)) {
		TRACE_DEVEL("recv not allowed because of (eos|error) on h1c", H1_EV_H1C_RECV|H1_EV_H1C_BLK, h1c->conn);
		return 0;
	}

	if (h1c->conn->flags & (CO_FL_WAIT_L4_CONN|CO_FL_WAIT_L6_CONN)) {
		TRACE_DEVEL("recv not allowed because of (waitl4|waitl6) on connection", H1_EV_H1C_RECV|H1_EV_H1C_BLK, h1c->conn);
		return 0;
	}

	if ((h1c->flags & (H1C_F_IN_ALLOC|H1C_F_IN_FULL|H1C_F_IN_SALLOC))) {
		TRACE_DEVEL("recv not allowed because input is blocked", H1_EV_H1C_RECV|H1_EV_H1C_BLK, h1c->conn);
		return 0;
	}

	return 1;
}

/*
 * Tries to grab a buffer and to re-enables processing on mux <target>. The h1
 * flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the connection is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
static int h1_buf_available(void *target)
{
	struct h1c *h1c = target;

	if (h1c->flags & H1C_F_IN_ALLOC) {
		h1c->flags &= ~H1C_F_IN_ALLOC;
		h1c->flags |=  H1C_F_IN_MAYALLOC;
	}

	if ((h1c->flags & H1C_F_OUT_ALLOC) && h1c->h1s) {
		TRACE_STATE("unblocking h1s, obuf allocatable", H1_EV_TX_DATA|H1_EV_H1S_BLK|H1_EV_STRM_WAKE, h1c->conn, h1c->h1s);
		h1c->flags &= ~H1C_F_OUT_ALLOC;
		h1c->flags |=  H1C_F_OUT_MAYALLOC;
		h1_wake_stream_for_send(h1c->h1s);
	}

	if ((h1c->flags & H1C_F_IN_SALLOC) && h1c->h1s) {
		TRACE_STATE("unblocking h1c, stream rxbuf allocatable", H1_EV_H1C_RECV|H1_EV_H1C_BLK|H1_EV_H1C_WAKE, h1c->conn);
		h1c->flags &= ~H1C_F_IN_SALLOC;
		h1c->flags |=  H1C_F_IN_SMAYALLOC;
		tasklet_wakeup(h1c->wait_event.tasklet);
	}

	if ((h1c->flags & H1C_F_IN_MAYALLOC) && h1_recv_allowed(h1c)) {
		TRACE_STATE("unblocking h1c, ibuf allocatable", H1_EV_H1C_RECV|H1_EV_H1C_BLK|H1_EV_H1C_WAKE, h1c->conn);
		tasklet_wakeup(h1c->wait_event.tasklet);
	}

	return 1;
}

/*
 * Allocate the h1c's ibuf. If if fails, it adds the mux in buffer wait queue,
 * and sets the H1C_F_IN_ALLOC flag on the connection. It will advertise a more
 * urgent allocation when a stream is already present than when none is present
 * since in one case a buffer might be needed to permit to release another one,
 * while in the other case we've simply not started anything.
 */
static inline struct buffer *h1_get_ibuf(struct h1c *h1c)
{
	struct buffer *buf;

	if (unlikely((buf = b_alloc(&h1c->ibuf, DB_MUX_RX |
				    ((h1c->flags & H1C_F_IN_MAYALLOC) ? DB_F_NOQUEUE : 0))) == NULL)) {
		b_queue(DB_MUX_RX, &h1c->buf_wait, h1c, h1_buf_available);
		h1c->flags |= H1C_F_IN_ALLOC;
	}
	else
		h1c->flags &= ~H1C_F_IN_MAYALLOC;

	return buf;
}

/*
 * Allocate the h1c's obuf. If if fails, it adds the mux in buffer wait queue,
 * and sets the H1C_F_OUT_ALLOC flag on the connection.
 */
static inline struct buffer *h1_get_obuf(struct h1c *h1c)
{
	struct buffer *buf;

	if (unlikely((buf = b_alloc(&h1c->obuf, DB_MUX_TX |
				    ((h1c->flags & H1C_F_OUT_MAYALLOC) ? DB_F_NOQUEUE : 0))) == NULL)) {
		b_queue(DB_MUX_TX, &h1c->buf_wait, h1c, h1_buf_available);
		h1c->flags |= H1C_F_OUT_ALLOC;
	}
	else
		h1c->flags &= ~H1C_F_OUT_MAYALLOC;

	return buf;
}

/*
 * Allocate the h1s's rxbuf. If if fails, it adds the mux in buffer wait queue,
 * and sets the H1C_F_IN_SALLOC flag on the connection.
 */
static inline struct buffer *h1_get_rxbuf(struct h1s *h1s)
{
	struct h1c *h1c = h1s->h1c;
	struct buffer *buf;

	if (unlikely((buf = b_alloc(&h1s->rxbuf, DB_SE_RX |
				    ((h1c->flags & H1C_F_IN_SMAYALLOC) ? DB_F_NOQUEUE : 0))) == NULL)) {
		b_queue(DB_SE_RX, &h1c->buf_wait, h1c, h1_buf_available);
		h1c->flags |= H1C_F_IN_SALLOC;
	}
	else
		h1c->flags &= ~H1C_F_IN_SMAYALLOC;

	return buf;
}

/*
 * Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
static inline void h1_release_buf(struct h1c *h1c, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(h1c->buf_wait.target, 1);
	}
}

static inline void h1c_report_term_evt(struct h1c *h1c, enum muxc_term_event_type type)
{
	enum term_event_loc loc = tevt_loc_muxc;

	if (h1c->flags & H1C_F_IS_BACK)
		loc += 8;
	h1c->term_evts_log = tevt_report_event(h1c->term_evts_log, loc, type);
}

/* Returns 1 if the H1 connection is alive (IDLE, EMBRYONIC, RUNNING or
 * DRAINING). Ortherwise 0 is returned.
 */
static inline int h1_is_alive(const struct h1c *h1c)
{
	return (h1c->state <= H1_CS_DRAINING);
}

/* Switch the H1 connection to CLOSING or CLOSED mode, depending on the output
 * buffer state and if there is still a H1 stream or not. If there are sill
 * pending outgoing data or if there is still a H1 stream, it is set to CLOSING
 * state. Otherwise it is set to CLOSED mode. */
static inline void h1_close(struct h1c *h1c)
{
	h1c->state = ((h1c->h1s || b_data(&h1c->obuf)) ? H1_CS_CLOSING : H1_CS_CLOSED);
}

/* returns the number of streams in use on a connection to figure if it's idle
 * or not. We rely on H1C state to know if the connection is in-use or not. It
 * is IDLE only when no H1 stream is attached and when the previous stream, if
 * any, was fully terminated without any error and in K/A mode.
 */
static int h1_used_streams(struct connection *conn)
{
	struct h1c *h1c = conn->ctx;

	return ((h1c->state == H1_CS_IDLE) ? 0 : 1);
}

/* returns the number of streams still available on a connection */
static int h1_avail_streams(struct connection *conn)
{
	return 1 - h1_used_streams(conn);
}

/* Refresh the h1c task timeout if necessary */
static void h1_refresh_timeout(struct h1c *h1c)
{
	int is_idle_conn = 0;

	if (h1c->task) {
		if (!h1_is_alive(h1c)) {
			/* half-closed or dead connections : switch to clientfin/serverfin
			 * timeouts so that we don't hang too long on clients that have
			 * gone away (especially in tunnel mode).
			 */
			h1c->task->expire = tick_add_ifset(now_ms, h1c->shut_timeout);
			TRACE_DEVEL("refreshing connection's timeout (dead or half-closed)", H1_EV_H1C_SEND|H1_EV_H1C_RECV, h1c->conn);
			is_idle_conn = 1;
		}
		else if (b_data(&h1c->obuf)) {
			/* alive connection with pending outgoing data, need a timeout (server or client). */
			h1c->task->expire = tick_add_ifset(now_ms, h1c->timeout);
			TRACE_DEVEL("refreshing connection's timeout (pending outgoing data)", H1_EV_H1C_SEND|H1_EV_H1C_RECV, h1c->conn);
		}
		else if (!(h1c->flags & H1C_F_IS_BACK) && (h1c->state == H1_CS_IDLE)) {
			/* idle front connections. */
			h1c->task->expire = (tick_isset(h1c->idle_exp) ? h1c->idle_exp : tick_add_ifset(now_ms, h1c->timeout));
			TRACE_DEVEL("refreshing connection's timeout (idle front h1c)", H1_EV_H1C_SEND|H1_EV_H1C_RECV, h1c->conn);
			is_idle_conn = 1;
		}
		else if (!(h1c->flags & H1C_F_IS_BACK) && (h1c->state != H1_CS_RUNNING)) {
			/* alive front connections waiting for a fully usable stream need a timeout. */
			h1c->task->expire = tick_first(h1c->idle_exp, tick_add_ifset(now_ms, h1c->timeout));
			TRACE_DEVEL("refreshing connection's timeout (alive front h1c but not ready)", H1_EV_H1C_SEND|H1_EV_H1C_RECV, h1c->conn);
			/* A frontend connection not yet ready could be treated the same way as an idle
			 * one in case of soft-close.
			 */
			is_idle_conn = 1;
		}
		else  {
			/* alive back connections of front connections with a stream connector attached */
			h1c->task->expire = TICK_ETERNITY;
			TRACE_DEVEL("no connection timeout (alive back h1c or front h1c with an SC)", H1_EV_H1C_SEND|H1_EV_H1C_RECV, h1c->conn);
		}

		if ((h1c->px->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) &&
		     is_idle_conn && tick_isset(global.close_spread_end)) {
			/* If a soft-stop is in progress and a close-spread-time
			 * is set, we want to spread idle connection closing roughly
			 * evenly across the defined window. This should only
			 * act on idle frontend connections.
			 * If the window end is already in the past, we wake the
			 * timeout task up immediately so that it can be closed.
			 */
			int remaining_window = tick_remain(now_ms, global.close_spread_end);
			if (remaining_window) {
				/* We don't need to reset the expire if it would
				 * already happen before the close window end.
				 */
				if (tick_is_le(global.close_spread_end, h1c->task->expire)) {
					/* Set an expire value shorter than the current value
					 * because the close spread window end comes earlier.
					 */
					h1c->task->expire = tick_add(now_ms, statistical_prng_range(remaining_window));
					TRACE_DEVEL("connection timeout set to value before close-spread window end", H1_EV_H1C_SEND|H1_EV_H1C_RECV, h1c->conn);
				}
			}
			else {
				/* We are past the soft close window end, wake the timeout
				 * task up immediately.
				 */
				task_wakeup(h1c->task, TASK_WOKEN_TIMER);
			}
		}
		TRACE_DEVEL("new expiration date", H1_EV_H1C_SEND|H1_EV_H1C_RECV, h1c->conn, 0, 0, (size_t[]){h1c->task->expire});
		task_queue(h1c->task);
	}
}

static void h1_set_idle_expiration(struct h1c *h1c)
{
	if (h1c->flags & H1C_F_IS_BACK || !h1c->task) {
		TRACE_DEVEL("no idle expiration (backend connection || no task)", H1_EV_H1C_RECV, h1c->conn);
		h1c->idle_exp = TICK_ETERNITY;
		return;
	}
	if (h1c->state == H1_CS_IDLE) {
		if (!tick_isset(h1c->idle_exp)) {
			if ((h1c->flags & H1C_F_WAIT_NEXT_REQ) &&   /* Not the first request */
			    !b_data(&h1c->ibuf) &&                 /*  No input data */
			    tick_isset(h1c->px->timeout.httpka)) { /*  K-A timeout set */
				h1c->idle_exp = tick_add_ifset(now_ms, h1c->px->timeout.httpka);
				TRACE_DEVEL("set idle expiration (keep-alive timeout)", H1_EV_H1C_RECV, h1c->conn);
			}
			else {
				h1c->idle_exp = tick_add_ifset(now_ms, h1c->px->timeout.httpreq);
				TRACE_DEVEL("set idle expiration (http-request timeout)", H1_EV_H1C_RECV, h1c->conn);
			}
		}
	}
	else if (h1c->state < H1_CS_RUNNING) {
		if (!tick_isset(h1c->idle_exp)) {
			h1c->idle_exp = tick_add_ifset(now_ms, h1c->px->timeout.httpreq);
			TRACE_DEVEL("set idle expiration (http-request timeout)", H1_EV_H1C_RECV, h1c->conn);
		}
	}
	else {
		h1c->idle_exp = TICK_ETERNITY;
		TRACE_DEVEL("unset idle expiration (running or closing)", H1_EV_H1C_RECV, h1c->conn);
	}
}
/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/
/* Set EOI on stream connector in DONE state iff:
 *  - it is a response
 *  - it is a request and the response is DONE too
 *  - it is a request but no a protocol upgrade nor a CONNECT
 *
 * If not set, Wait the response to do so or not depending on the status
 * code.
 */
static inline void h1s_set_se_eoi_cond(struct h1s *h1s, const struct h1m *h1m)
{

	if ((h1m->state == H1_MSG_DONE) && ((h1m->flags & H1_MF_RESP) ||
					    (h1s->res.state == H1_MSG_DONE) ||
					    ((h1s->meth != HTTP_METH_CONNECT) && !(h1m->flags & H1_MF_CONN_UPG))))
		se_fl_set(h1s->sd, SE_FL_EOI);
}

/* returns non-zero if there are input data pending for stream h1s. */
static inline size_t h1s_data_pending(const struct h1s *h1s)
{
	const struct h1m *h1m;

	h1m = ((h1s->h1c->flags & H1C_F_IS_BACK) ? &h1s->res : &h1s->req);
	return ((h1m->state == H1_MSG_DONE) ? 0 : b_data(&h1s->h1c->ibuf));
}

/* Creates a new stream connector and the associate stream. <input> is used as input
 * buffer for the stream. On success, it is transferred to the stream and the
 * mux is no longer responsible of it. On error, <input> is unchanged, thus the
 * mux must still take care of it. However, there is nothing special to do
 * because, on success, <input> is updated to points on BUF_NULL. Thus, calling
 * b_free() on it is always safe. This function returns the stream connector on
 * success or NULL on error. */
static struct stconn *h1s_new_sc(struct h1s *h1s, struct buffer *input)
{
	struct h1c *h1c = h1s->h1c;

	TRACE_ENTER(H1_EV_STRM_NEW, h1c->conn, h1s);

	if (h1s->flags & H1S_F_NOT_FIRST)
		se_fl_set(h1s->sd, SE_FL_NOT_FIRST);
	if (h1s->req.flags & H1_MF_UPG_WEBSOCKET)
		se_fl_set(h1s->sd, SE_FL_WEBSOCKET);

	if (!sc_new_from_endp(h1s->sd, h1c->conn->owner, input)) {
		TRACE_ERROR("SC allocation failure", H1_EV_STRM_NEW|H1_EV_STRM_END|H1_EV_STRM_ERR, h1c->conn, h1s);
		goto err;
	}

	h1c->state = H1_CS_RUNNING;
	TRACE_LEAVE(H1_EV_STRM_NEW, h1c->conn, h1s);
	return h1s_sc(h1s);

  err:
	TRACE_DEVEL("leaving on error", H1_EV_STRM_NEW|H1_EV_STRM_ERR, h1c->conn, h1s);
	return NULL;
}

static struct stconn *h1s_upgrade_sc(struct h1s *h1s, struct buffer *input)
{
	TRACE_ENTER(H1_EV_STRM_NEW, h1s->h1c->conn, h1s);

	if (stream_upgrade_from_sc(h1s_sc(h1s), input) < 0) {
		TRACE_ERROR("stream upgrade failure", H1_EV_STRM_NEW|H1_EV_STRM_END|H1_EV_STRM_ERR, h1s->h1c->conn, h1s);
		goto err;
	}

	TRACE_STATE("upgraded H1 stream", H1_EV_H1S_NEW, h1s->h1c->conn, h1s);

	h1s->h1c->state = H1_CS_RUNNING;
	TRACE_LEAVE(H1_EV_STRM_NEW, h1s->h1c->conn, h1s);
	return h1s_sc(h1s);

  err:
	TRACE_DEVEL("leaving on error", H1_EV_STRM_NEW|H1_EV_STRM_ERR, h1s->h1c->conn, h1s);
	return NULL;
}

static struct h1s *h1s_new(struct h1c *h1c)
{
	struct h1s *h1s;

	TRACE_ENTER(H1_EV_H1S_NEW, h1c->conn);

	h1s = pool_alloc(pool_head_h1s);
	if (!h1s) {
		TRACE_ERROR("H1S allocation failure", H1_EV_H1S_NEW|H1_EV_H1S_END|H1_EV_H1S_ERR, h1c->conn);
		goto fail;
	}
	h1s->h1c = h1c;
	h1c->h1s = h1s;
	h1s->sess = NULL;
	h1s->sd = NULL;
	h1s->flags = H1S_F_WANT_KAL;
	h1s->subs = NULL;
	h1s->rxbuf = BUF_NULL;
	memset(h1s->ws_key, 0, sizeof(h1s->ws_key));

	h1m_init_req(&h1s->req);
	h1s->req.flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);

	h1m_init_res(&h1s->res);
	h1s->res.flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);

	h1s->status = 0;
	h1s->meth   = HTTP_METH_OTHER;

	if (h1c->flags & H1C_F_WAIT_NEXT_REQ)
		h1s->flags |= H1S_F_NOT_FIRST;
	h1s->h1c->state = H1_CS_EMBRYONIC;
	h1s->h1c->flags &= ~H1C_F_WAIT_NEXT_REQ;
	TRACE_LEAVE(H1_EV_H1S_NEW, h1c->conn, h1s);
	return h1s;

  fail:
	TRACE_DEVEL("leaving on error", H1_EV_STRM_NEW|H1_EV_STRM_ERR, h1c->conn);
	return NULL;
}

static struct h1s *h1c_frt_stream_new(struct h1c *h1c, struct stconn *sc, struct session *sess)
{
	struct h1s *h1s;

	TRACE_ENTER(H1_EV_H1S_NEW, h1c->conn);

	h1s = h1s_new(h1c);
	if (!h1s)
		goto fail;

	if (sc) {
		if (sc_attach_mux(sc, h1s, h1c->conn) < 0)
			goto fail;
		h1s->sd = sc->sedesc;
	}
	else {
		h1s->sd = sedesc_new();
		if (!h1s->sd)
			goto fail;
		h1s->sd->se     = h1s;
		h1s->sd->conn   = h1c->conn;
		se_fl_set(h1s->sd, SE_FL_T_MUX | SE_FL_ORPHAN);
	}
	/* When a request starts, the H1S does not expect data while the request
	 * is not finished. It does not mean the response must not be received,
	 * especially if headers were already forwarded. But it is not
	 * mandatory.
	 */
	if (!(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_H1_SND))
		se_fl_set(h1s->sd, SE_FL_MAY_FASTFWD_CONS);
	se_expect_no_data(h1s->sd);
	h1s->sess = sess;

	if (h1c->px->options2 & PR_O2_REQBUG_OK)
		h1s->req.err_pos = -1;

	HA_ATOMIC_INC(&h1c->px_counters->open_streams);
	HA_ATOMIC_INC(&h1c->px_counters->total_streams);

	h1c->idle_exp = TICK_ETERNITY;
	h1_set_idle_expiration(h1c);

	TRACE_STATE("created new H1 front stream", H1_EV_H1S_NEW, h1c->conn, h1s);
	TRACE_LEAVE(H1_EV_H1S_NEW, h1c->conn, h1s);
	return h1s;

  fail:
	TRACE_DEVEL("leaving on error", H1_EV_STRM_NEW|H1_EV_STRM_ERR, h1c->conn);
	h1s_destroy(h1s);
	return NULL;
}

static struct h1s *h1c_bck_stream_new(struct h1c *h1c, struct stconn *sc, struct session *sess)
{
	struct h1s *h1s;

	TRACE_ENTER(H1_EV_H1S_NEW, h1c->conn);

	h1s = h1s_new(h1c);
	if (!h1s)
		goto fail;

	if (sc_attach_mux(sc, h1s, h1c->conn) < 0)
		goto fail;

	h1s->flags |= H1S_F_RX_BLK;
	h1s->sd = sc->sedesc;
	h1s->sess = sess;

	if (!(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_H1_SND))
		se_fl_set(h1s->sd, SE_FL_MAY_FASTFWD_CONS);
	h1c->state = H1_CS_RUNNING;

	if (h1c->px->options2 & PR_O2_RSPBUG_OK)
		h1s->res.err_pos = -1;

	HA_ATOMIC_INC(&h1c->px_counters->open_streams);
	HA_ATOMIC_INC(&h1c->px_counters->total_streams);

	TRACE_STATE("created new H1 back stream", H1_EV_H1S_NEW, h1c->conn, h1s);
	TRACE_LEAVE(H1_EV_H1S_NEW, h1c->conn, h1s);
	return h1s;

  fail:
	TRACE_DEVEL("leaving on error", H1_EV_STRM_NEW|H1_EV_STRM_ERR, h1c->conn);
	h1s_destroy(h1s);
	return NULL;
}

static void h1s_destroy(struct h1s *h1s)
{
	if (h1s) {
		struct h1c *h1c = h1s->h1c;

		TRACE_POINT(H1_EV_H1S_END, h1c->conn, h1s);
		h1c->h1s = NULL;

		if (h1s->subs)
			h1s->subs->events = 0;

		h1_release_buf(h1c, &h1s->rxbuf);

		h1c->flags &= ~(H1C_F_WANT_FASTFWD|
				H1C_F_OUT_FULL|H1C_F_OUT_ALLOC|H1C_F_OUT_MAYALLOC|
				H1C_F_IN_SALLOC|H1C_F_IN_SMAYALLOC|
				H1C_F_CO_MSG_MORE|H1C_F_CO_STREAMER);

		if (!(h1c->flags & (H1C_F_EOS|H1C_F_ERR_PENDING|H1C_F_ERROR|H1C_F_ABRT_PENDING|H1C_F_ABRTED)) &&  /* No error/read0/abort */
		    h1_is_alive(h1c) &&                                                      /* still alive */
		    (h1s->flags & H1S_F_WANT_KAL) &&                                         /* K/A possible */
		    h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE) {        /* req/res in DONE state */
			h1c->state = H1_CS_IDLE;
			h1c->flags |= H1C_F_WAIT_NEXT_REQ;
			h1c->req_count++;

			COUNT_IF(!(h1c->flags & H1C_F_IS_BACK) && b_data(&h1c->obuf), "front H1C switched in IDLE state with pending outgoing data");
			COUNT_IF((h1c->flags & H1C_F_IS_BACK) && b_data(&h1c->obuf), "back H1C switched in IDLE state with pending outgoing data");
			TRACE_STATE("set idle mode on h1c, waiting for the next request", H1_EV_H1C_ERR, h1c->conn, h1s);
		}
		else {
			h1_close(h1c);
			COUNT_IF(!(h1c->flags & H1C_F_IS_BACK) && b_data(&h1c->obuf), "front H1C swiched in CLOSED state with pending outgoing data");
			COUNT_IF((h1c->flags & H1C_F_IS_BACK) && b_data(&h1c->obuf), "back H1C switch in CLOSED state with pending outgoing data");
			TRACE_STATE("close h1c", H1_EV_H1S_END, h1c->conn, h1s);
		}

		HA_ATOMIC_DEC(&h1c->px_counters->open_streams);
		BUG_ON(h1s->sd && !se_fl_test(h1s->sd, SE_FL_ORPHAN));
		sedesc_free(h1s->sd);
		pool_free(pool_head_h1s, h1s);
	}
}


/* Check if shutdown performed of an an H1S must lead to a connection shutdown
 * of if it can be kept alive. It returns 1 if the connection must be shut down
 * and 0 it if can be kept alive.
 */
static int h1s_must_shut_conn(struct h1s *h1s)
{
	struct h1c *h1c = h1s->h1c;
	int ret;

	TRACE_ENTER(H1_EV_STRM_SHUT, h1c->conn, h1s);

	if (se_fl_test(h1s->sd, SE_FL_KILL_CONN)) {
		TRACE_STATE("stream wants to kill the connection", H1_EV_STRM_SHUT, h1c->conn, h1s);
		ret = 1;
	}
	else if (h1c->state == H1_CS_CLOSING || (h1c->flags & (H1C_F_EOS|H1C_F_ERR_PENDING|H1C_F_ERROR))) {
		TRACE_STATE("shutdown on connection (EOS || CLOSING || ERROR)", H1_EV_STRM_SHUT, h1c->conn, h1s);
		ret = 1;
	}
	else if (h1c->state == H1_CS_UPGRADING) {
		TRACE_STATE("keep connection alive (UPGRADING)", H1_EV_STRM_SHUT, h1c->conn, h1s);
		ret = 0;
	}
	else if (!(h1c->flags & H1C_F_IS_BACK) && h1s->req.state != H1_MSG_DONE && h1s->res.state == H1_MSG_DONE) {
		TRACE_STATE("defer shutdown to drain request first", H1_EV_STRM_SHUT, h1c->conn, h1s);
		ret = 0;
	}
	else if (((h1s->flags & H1S_F_WANT_KAL) && h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE)) {
		TRACE_STATE("keep connection alive (want_kal)", H1_EV_STRM_SHUT, h1c->conn, h1s);
		ret = 0;
	}
	else {
		/* The default case, do the shutdown */
		TRACE_STATE("shutdown on connection (abort || want_clo)", H1_EV_STRM_SHUT, h1c->conn, h1s);
		ret = 1;
	}

	TRACE_LEAVE(H1_EV_STRM_SHUT, h1c->conn, h1s);
	return ret;
}

/* Really detach the H1S. Most of time of it called from h1_detach() when the
 * stream is detached from the connection. But if the request message must be
 * drained first, the detach is deferred. Returns 0 if the h1s is detached but
 * h1c is still usable. -1 is returned if h1s was released.
 */
static int h1s_finish_detach(struct h1s *h1s)
{
	struct h1c *h1c;
	struct session *sess;
	int is_not_first;

	TRACE_ENTER(H1_EV_STRM_END, h1s ? h1s->h1c->conn : NULL, h1s);

	sess = h1s->sess;
	h1c = h1s->h1c;

	sess->accept_date = date;
	sess->accept_ts   = now_ns;
	sess->t_handshake = 0;
	sess->t_idle      = -1;

	is_not_first = h1s->flags & H1S_F_NOT_FIRST;
	h1s_destroy(h1s);

	if (h1c->state == H1_CS_IDLE && (h1c->flags & H1C_F_IS_BACK)) {
		/* this connection may be killed at any moment, we want it to
		 * die "cleanly" (i.e. only an RST).
		 */
		h1c->flags |= H1C_F_SILENT_SHUT;

		/* If there are any excess server data in the input buffer,
		 * release it and close the connection ASAP (some data may
		 * remain in the output buffer). This happens if a server sends
		 * invalid responses. So in such case, we don't want to reuse
		 * the connection
		 */
		if (b_data(&h1c->ibuf)) {
			h1_release_buf(h1c, &h1c->ibuf);
			h1_close(h1c);
			TRACE_DEVEL("remaining data on detach, kill connection", H1_EV_STRM_END|H1_EV_H1C_END);
			goto release;
		}

		if (h1c->conn->flags & CO_FL_PRIVATE) {
			/* Add the connection in the session server list, if not already done */
			if (!session_add_conn(sess, h1c->conn, h1c->conn->target)) {
				h1c->conn->owner = NULL;
				h1c->conn->mux->destroy(h1c);
				goto released;
			}
			/* Always idle at this step */

			/* mark that the tasklet may lose its context to another thread and
			 * that the handler needs to check it under the idle conns lock.
			 */
			HA_ATOMIC_OR(&h1c->wait_event.tasklet->state, TASK_F_USR1);
			if (session_check_idle_conn(sess, h1c->conn)) {
				/* The connection got destroyed, let's leave */
				TRACE_DEVEL("outgoing connection killed", H1_EV_STRM_END|H1_EV_H1C_END);
				goto released;
			}
		}
		else {
			if (h1c->conn->owner == sess)
				h1c->conn->owner = NULL;

			/* mark that the tasklet may lose its context to another thread and
			 * that the handler needs to check it under the idle conns lock.
			 */
			HA_ATOMIC_OR(&h1c->wait_event.tasklet->state, TASK_F_USR1);
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
			xprt_set_idle(h1c->conn, h1c->conn->xprt, h1c->conn->xprt_ctx);

			if (!srv_add_to_idle_list(objt_server(h1c->conn->target), h1c->conn, is_not_first)) {
				/* The server doesn't want it, let's kill the connection right away */
				h1c->conn->mux->destroy(h1c);
				TRACE_DEVEL("outgoing connection killed", H1_EV_STRM_END|H1_EV_H1C_END);
				goto released;
			}
			/* At this point, the connection has been added to the
			 * server idle list, so another thread may already have
			 * hijacked it, so we can't do anything with it.
			 */
			goto end;
		}
	}

  release:
	/* We don't want to close right now unless the connection is in error or shut down for writes */
	if ((h1c->flags & H1C_F_ERROR) ||
	    (h1c->state == H1_CS_CLOSED) ||
	    (h1c->state == H1_CS_CLOSING && !b_data(&h1c->obuf)) ||
	    !h1c->conn->owner) {
		TRACE_DEVEL("killing dead connection", H1_EV_STRM_END, h1c->conn);
		h1_release(h1c);
		goto released;
	}
	else {
		if (h1c->state == H1_CS_IDLE) {
			/* If we have a new request, process it immediately or
			 * subscribe for reads waiting for new data
			 */
			if (unlikely(b_data(&h1c->ibuf))) {
				if (h1_process(h1c) == -1) {
					/* h1c was released, don't reuse it anymore */
					goto released;
				}
			}
			else
				h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		}
		h1_set_idle_expiration(h1c);
		h1_refresh_timeout(h1c);
	}
  end:
	TRACE_LEAVE(H1_EV_STRM_END);
	return 0;

  released:
	TRACE_DEVEL("leaving after releasing the connection", H1_EV_STRM_END);
	return -1;
}


/*
 * Initialize the mux once it's attached. It is expected that conn->ctx points
 * to the existing stream connector (for outgoing connections or for incoming
 * ones during a mux upgrade) or NULL (for incoming ones during the connection
 * establishment). <input> is always used as Input buffer and may contain
 * data. It is the caller responsibility to not reuse it anymore. Returns < 0 on
 * error.
 */
static int h1_init(struct connection *conn, struct proxy *proxy, struct session *sess,
		   struct buffer *input)
{
	struct h1c *h1c;
	struct task *t = NULL;
	void *conn_ctx = conn->ctx;

	TRACE_ENTER(H1_EV_H1C_NEW);

	h1c = pool_alloc(pool_head_h1c);
	if (!h1c) {
		TRACE_ERROR("H1C allocation failure", H1_EV_H1C_NEW|H1_EV_H1C_END|H1_EV_H1C_ERR);
		goto fail_h1c;
	}
	h1c->conn = conn;
	h1c->px   = proxy;

	h1c->state = H1_CS_IDLE;
	h1c->flags = H1C_F_NONE;
	h1c->errcode = 0;
	h1c->ibuf  = *input;
	h1c->obuf  = BUF_NULL;
	h1c->h1s   = NULL;
	h1c->task  = NULL;
	h1c->req_count = 0;
	h1c->term_evts_log = 0;

	LIST_INIT(&h1c->buf_wait.list);
	h1c->wait_event.tasklet = tasklet_new();
	if (!h1c->wait_event.tasklet)
		goto fail;
	h1c->wait_event.tasklet->process = h1_io_cb;
	h1c->wait_event.tasklet->context = h1c;
	h1c->wait_event.events   = 0;
	h1c->idle_exp = TICK_ETERNITY;

	if (conn_is_back(conn)) {
		h1c->flags |= H1C_F_IS_BACK;
		h1c->shut_timeout = h1c->timeout = proxy->timeout.server;
		if (tick_isset(proxy->timeout.serverfin))
			h1c->shut_timeout = proxy->timeout.serverfin;

		h1c->px_counters = EXTRA_COUNTERS_GET(proxy->extra_counters_be,
		                                      &h1_stats_module);
	} else {
		h1c->shut_timeout = h1c->timeout = proxy->timeout.client;
		if (tick_isset(proxy->timeout.clientfin))
			h1c->shut_timeout = proxy->timeout.clientfin;

		h1c->px_counters = EXTRA_COUNTERS_GET(proxy->extra_counters_fe,
		                                      &h1_stats_module);

		LIST_APPEND(&mux_stopping_data[tid].list,
		            &h1c->conn->stopping_list);
	}

	t = task_new_here();
	if (!t) {
		TRACE_ERROR("H1C task allocation failure", H1_EV_H1C_NEW|H1_EV_H1C_END|H1_EV_H1C_ERR);
		goto fail;
	}
	h1c->task = t;
	t->process = h1_timeout_task;
	t->context = h1c;
	t->expire = tick_add_ifset(now_ms, h1c->timeout);

	conn->ctx = h1c;

	if (h1c->flags & H1C_F_IS_BACK) {
		/* Create a new H1S now for backend connection only */
		if (!h1c_bck_stream_new(h1c, conn_ctx, sess))
			goto fail;
	}
	else if (conn_ctx) {
		/* Upgraded frontend connection (from TCP) */
		if (!h1c_frt_stream_new(h1c, conn_ctx, h1c->conn->owner))
			goto fail;

		/* Attach the SC but Not ready yet */
		h1c->state = H1_CS_UPGRADING;
		TRACE_DEVEL("Inherit the SC from TCP connection to perform an upgrade",
			    H1_EV_H1C_NEW|H1_EV_STRM_NEW, h1c->conn, h1c->h1s);
	}

	if (t) {
		h1_set_idle_expiration(h1c);
		t->expire = tick_first(t->expire, h1c->idle_exp);
		task_queue(t);
	}

	/* prepare to read something */
	if (b_data(&h1c->ibuf))
		tasklet_wakeup(h1c->wait_event.tasklet);
	else if (h1_recv_allowed(h1c))
		h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);

	if (!conn_is_back(conn))
		proxy_inc_fe_cum_sess_ver_ctr(sess->listener, proxy, 1);
	HA_ATOMIC_INC(&h1c->px_counters->open_conns);
	HA_ATOMIC_INC(&h1c->px_counters->total_conns);

	/* mux->wake will be called soon to complete the operation */
	TRACE_LEAVE(H1_EV_H1C_NEW, conn, h1c->h1s);
	return 0;

  fail:
	task_destroy(t);
	tasklet_free(h1c->wait_event.tasklet);
	pool_free(pool_head_h1c, h1c);
 fail_h1c:
	if (!conn_is_back(conn))
		LIST_DEL_INIT(&conn->stopping_list);
	conn->ctx = conn_ctx; // restore saved context
	TRACE_DEVEL("leaving in error", H1_EV_H1C_NEW|H1_EV_H1C_END|H1_EV_H1C_ERR);
	return -1;
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void h1_release(struct h1c *h1c)
{
	struct connection *conn = NULL;

	TRACE_POINT(H1_EV_H1C_END);

	/* The connection must be aattached to this mux to be released */
	if (h1c->conn && h1c->conn->ctx == h1c)
		conn = h1c->conn;

	if (conn && h1c->flags & H1C_F_UPG_H2C) {
		TRACE_DEVEL("upgrading H1 to H2", H1_EV_H1C_END, conn);
		/* Make sure we're no longer subscribed to anything */
		if (h1c->wait_event.events)
			conn->xprt->unsubscribe(conn, conn->xprt_ctx,
						h1c->wait_event.events, &h1c->wait_event);
		if (conn_upgrade_mux_fe(conn, NULL, &h1c->ibuf, ist("h2"), PROTO_MODE_HTTP) != -1) {
			/* connection successfully upgraded to H2, this
			 * mux was already released */
			return;
		}
		TRACE_ERROR("h2 upgrade failed", H1_EV_H1C_END|H1_EV_H1C_ERR, conn);
		sess_log(conn->owner); /* Log if the upgrade failed */
	}

	COUNT_IF(b_data(&h1c->ibuf), "H1C released with pending input data");
	COUNT_IF(b_data(&h1c->obuf), "H1C released with pending output data");

	b_dequeue(&h1c->buf_wait);
	h1_release_buf(h1c, &h1c->ibuf);
	h1_release_buf(h1c, &h1c->obuf);

	if (h1c->task) {
		h1c->task->context = NULL;
		task_wakeup(h1c->task, TASK_WOKEN_OTHER);
		h1c->task = NULL;
	}

	if (h1c->wait_event.tasklet) {
		tasklet_free(h1c->wait_event.tasklet);
		h1c->wait_event.tasklet = NULL;
	}

	h1s_destroy(h1c->h1s);
	if (conn) {
		if (h1c->wait_event.events != 0)
			conn->xprt->unsubscribe(conn, conn->xprt_ctx, h1c->wait_event.events,
						&h1c->wait_event);
		h1_shutw_conn(conn);
	}

	HA_ATOMIC_DEC(&h1c->px_counters->open_conns);
	pool_free(pool_head_h1c, h1c);

	if (conn) {
		if (!conn_is_back(conn))
			LIST_DEL_INIT(&conn->stopping_list);

		conn->mux = NULL;
		conn->ctx = NULL;
		TRACE_DEVEL("freeing conn", H1_EV_H1C_END, conn);

		conn_stop_tracking(conn);
		conn_full_close(conn);
		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}
}

/******************************************************/
/* functions below are for the H1 protocol processing */
/******************************************************/
/* Parse the request version and set H1_MF_VER_11 on <h1m> if the version is
 * greater or equal to 1.1
 */
static void h1_parse_req_vsn(struct h1m *h1m, const struct htx_sl *sl)
{
	const char *p = HTX_SL_REQ_VPTR(sl);

	if ((HTX_SL_REQ_VLEN(sl) == 8) &&
	    (*(p + 5) > '1' ||
	     (*(p + 5) == '1' && *(p + 7) >= '1')))
		h1m->flags |= H1_MF_VER_11;
}

/* Parse the response version and set H1_MF_VER_11 on <h1m> if the version is
 * greater or equal to 1.1
 */
static void h1_parse_res_vsn(struct h1m *h1m, const struct htx_sl *sl)
{
	const char *p = HTX_SL_RES_VPTR(sl);

	if ((HTX_SL_RES_VLEN(sl) == 8) &&
	    (*(p + 5) > '1' ||
	     (*(p + 5) == '1' && *(p + 7) >= '1')))
		h1m->flags |= H1_MF_VER_11;
}

/* Deduce the connection mode of the client connection, depending on the
 * configuration and the H1 message flags. This function is called twice, the
 * first time when the request is parsed and the second time when the response
 * is parsed.
 */
static void h1_set_cli_conn_mode(struct h1s *h1s, struct h1m *h1m)
{
	struct proxy *fe = h1s->h1c->px;

	if (h1m->flags & H1_MF_RESP) {
		/* Output direction: second pass */
		if ((h1s->meth == HTTP_METH_CONNECT && h1s->status >= 200 && h1s->status < 300) ||
		    h1s->status == 101) {
			/* Either we've established an explicit tunnel, or we're
			 * switching the protocol. In both cases, we're very unlikely to
			 * understand the next protocols. We have to switch to tunnel
			 * mode, so that we transfer the request and responses then let
			 * this protocol pass unmodified. When we later implement
			 * specific parsers for such protocols, we'll want to check the
			 * Upgrade header which contains information about that protocol
			 * for responses with status 101 (eg: see RFC2817 about TLS).
			 */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_TUN;
			TRACE_STATE("set tunnel mode (resp)", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
		}
		else if (h1s->flags & H1S_F_WANT_KAL) {
			/* By default the client is in KAL mode. CLOSE mode mean
			 * it is imposed by the client itself. So only change
			 * KAL mode here. */
			if (!(h1m->flags & H1_MF_XFER_LEN) || (h1m->flags & H1_MF_CONN_CLO)) {
				/* no length known or explicit close => close */
				h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
				TRACE_STATE("detect close mode (resp)", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
			}
			else if (!(h1m->flags & H1_MF_CONN_KAL) &&
				 (fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO) {
				/* no explicit keep-alive and option httpclose => close */
				h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
				TRACE_STATE("force close mode (resp)", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
			}
		}
	}
	else {
		/* Input direction: first pass */
		if (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) || h1m->flags & H1_MF_CONN_CLO)  {
			/* no explicit keep-alive in HTTP/1.0 or explicit close => close*/
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
			TRACE_STATE("detect close mode (req)", H1_EV_RX_DATA|H1_EV_RX_HDRS, h1s->h1c->conn, h1s);
		}
	}

	/* If KAL, check if the frontend is stopping. If yes, switch in CLO mode
	 * unless a 'close-spread-time' option is set (either to define a
	 * soft-close window or to disable active closing (close-spread-time
	 * option set to 0).
	 */
	if (h1s->flags & H1S_F_WANT_KAL && (fe->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
		int want_clo = 1;
		/* If a close-spread-time option is set, we want to avoid
		 * closing all the active HTTP connections at once so we add a
		 * random factor that will spread the closing.
		 */
		if (tick_isset(global.close_spread_end)) {
			int remaining_window = tick_remain(now_ms, global.close_spread_end);
			if (remaining_window) {
				/* This should increase the closing rate the further along
				 * the window we are.
				 */
				want_clo = (remaining_window <= statistical_prng_range(global.close_spread_time));
			}
		}
		else if (global.tune.options & GTUNE_DISABLE_ACTIVE_CLOSE)
			want_clo = 0;

		if (want_clo) {
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
			TRACE_STATE("stopping, set close mode", H1_EV_RX_DATA|H1_EV_RX_HDRS|H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
		}
	}
}

/* Deduce the connection mode of the client connection, depending on the
 * configuration and the H1 message flags. This function is called twice, the
 * first time when the request is parsed and the second time when the response
 * is parsed.
 */
static void h1_set_srv_conn_mode(struct h1s *h1s, struct h1m *h1m)
{
	struct session *sess = h1s->sess;
	struct proxy *be = h1s->h1c->px;
	int fe_flags = sess ? sess->fe->options : 0;

	if (h1m->flags & H1_MF_RESP) {
		/* Input direction: second pass */
		if ((h1s->meth == HTTP_METH_CONNECT && h1s->status >= 200 && h1s->status < 300) ||
		    h1s->status == 101) {
			/* Either we've established an explicit tunnel, or we're
			 * switching the protocol. In both cases, we're very unlikely to
			 * understand the next protocols. We have to switch to tunnel
			 * mode, so that we transfer the request and responses then let
			 * this protocol pass unmodified. When we later implement
			 * specific parsers for such protocols, we'll want to check the
			 * Upgrade header which contains information about that protocol
			 * for responses with status 101 (eg: see RFC2817 about TLS).
			 */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_TUN;
			TRACE_STATE("set tunnel mode (resp)", H1_EV_RX_DATA|H1_EV_RX_HDRS, h1s->h1c->conn, h1s);
		}
		else if (h1s->flags & H1S_F_WANT_KAL) {
			/* By default the server is in KAL mode. CLOSE mode mean
			 * it is imposed by haproxy itself. So only change KAL
			 * mode here. */
			if (!(h1m->flags & H1_MF_XFER_LEN) || h1m->flags & H1_MF_CONN_CLO ||
			    !(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL))){
				/* no length known or explicit close or no explicit keep-alive in HTTP/1.0 => close */
				h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
				TRACE_STATE("detect close mode (resp)", H1_EV_RX_DATA|H1_EV_RX_HDRS, h1s->h1c->conn, h1s);
			}
		}
	}
	else {
		/* Output direction: first pass */
		if (h1m->flags & H1_MF_CONN_CLO) {
			/* explicit close => close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
			TRACE_STATE("detect close mode (req)", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
		}
		else if (!(h1m->flags & H1_MF_CONN_KAL) &&
			 ((fe_flags & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
			  (be->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
			  (be->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO)) {
			/* no explicit keep-alive option httpclose/server-close => close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
			TRACE_STATE("force close mode (req)", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
		}
	}

	/* If KAL, check if the backend is stopping. If yes, switch in CLO mode */
	if (h1s->flags & H1S_F_WANT_KAL && (be->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
		TRACE_STATE("stopping, set close mode", H1_EV_RX_DATA|H1_EV_RX_HDRS|H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
	}
}

static void h1_update_req_conn_value(struct h1s *h1s, struct h1m *h1m, struct ist *conn_val)
{
	struct proxy *px = h1s->h1c->px;

	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		return;

	if (h1s->flags & H1S_F_WANT_KAL || px->options2 & PR_O2_FAKE_KA) {
		if (!(h1m->flags & H1_MF_VER_11)) {
			TRACE_STATE("add \"Connection: keep-alive\"", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
			*conn_val = ist("keep-alive");
		}
	}
	else { /* H1S_F_WANT_CLO && !PR_O2_FAKE_KA */
		if (h1m->flags & H1_MF_VER_11) {
			TRACE_STATE("add \"Connection: close\"", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
			*conn_val = ist("close");
		}
	}
}

static void h1_update_res_conn_value(struct h1s *h1s, struct h1m *h1m, struct ist *conn_val)
{
	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		return;

	if (h1s->flags & H1S_F_WANT_KAL) {
		if (!(h1m->flags & H1_MF_VER_11) ||
		    !((h1m->flags & h1s->req.flags) & H1_MF_VER_11)) {
			TRACE_STATE("add \"Connection: keep-alive\"", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
			*conn_val = ist("keep-alive");
		}
	}
	else { /* H1S_F_WANT_CLO */
		if (h1m->flags & H1_MF_VER_11) {
			TRACE_STATE("add \"Connection: close\"", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
			*conn_val = ist("close");
		}
	}
}

static void h1_process_input_conn_mode(struct h1s *h1s, struct h1m *h1m, struct htx *htx)
{
	if (!(h1s->h1c->flags & H1C_F_IS_BACK))
		h1_set_cli_conn_mode(h1s, h1m);
	else
		h1_set_srv_conn_mode(h1s, h1m);
}

static void h1_process_output_conn_mode(struct h1s *h1s, struct h1m *h1m, struct ist *conn_val)
{
	if (!(h1s->h1c->flags & H1C_F_IS_BACK))
		h1_set_cli_conn_mode(h1s, h1m);
	else
		h1_set_srv_conn_mode(h1s, h1m);

	if (!(h1m->flags & H1_MF_RESP))
		h1_update_req_conn_value(h1s, h1m, conn_val);
	else
		h1_update_res_conn_value(h1s, h1m, conn_val);
}

/* Try to adjust the case of the message header name using the global map
 * <hdrs_map>.
 */
static void h1_adjust_case_outgoing_hdr(struct h1s *h1s, struct h1m *h1m, struct ist *name)
{
	struct ebpt_node *node;
	struct h1_hdr_entry *entry;

	/* No entry in the map, do nothing */
	if (eb_is_empty(&hdrs_map.map))
		return;

	/* No conversion for the request headers */
	if (!(h1m->flags & H1_MF_RESP) && !(h1s->h1c->px->options2 & PR_O2_H1_ADJ_BUGSRV))
		return;

	/* No conversion for the response headers */
	if ((h1m->flags & H1_MF_RESP) && !(h1s->h1c->px->options2 & PR_O2_H1_ADJ_BUGCLI))
		return;

	node = ebis_lookup_len(&hdrs_map.map, name->ptr, name->len);
	if (!node)
		return;
	entry = container_of(node, struct h1_hdr_entry, node);
	name->ptr = entry->name.ptr;
	name->len = entry->name.len;
}

/* Append the description of what is present in error snapshot <es> into <out>.
 * The description must be small enough to always fit in a buffer. The output
 * buffer may be the trash so the trash must not be used inside this function.
 */
static void h1_show_error_snapshot(struct buffer *out, const struct error_snapshot *es)
{
	chunk_appendf(out,
		      "  H1 connection flags 0x%08x, H1 stream flags 0x%08x\n"
		      "  H1 msg state %s(%d), H1 msg flags 0x%08x\n"
		      "  H1 chunk len %lld bytes, H1 body len %lld bytes :\n",
		      es->ctx.h1.c_flags, es->ctx.h1.s_flags,
		      h1m_state_str(es->ctx.h1.state), es->ctx.h1.state,
		      es->ctx.h1.m_flags, es->ctx.h1.m_clen, es->ctx.h1.m_blen);
}
/*
 * Capture a bad request or response and archive it in the proxy's structure.
 * By default it tries to report the error position as h1m->err_pos. However if
 * this one is not set, it will then report h1m->next, which is the last known
 * parsing point. The function is able to deal with wrapping buffers. It always
 * displays buffers as a contiguous area starting at buf->p. The direction is
 * determined thanks to the h1m's flags.
 */
static void h1_capture_bad_message(struct h1c *h1c, struct h1s *h1s,
				   struct h1m *h1m, struct buffer *buf)
{
	struct session *sess = h1s->sess;
	struct proxy *proxy = h1c->px;
	struct proxy *other_end;
	union error_snapshot_ctx ctx;

	if (h1c->state == H1_CS_UPGRADING || h1c->state == H1_CS_RUNNING) {
		if (sess == NULL)
			sess = __sc_strm(h1s_sc(h1s))->sess;
		if (!(h1m->flags & H1_MF_RESP))
			other_end = __sc_strm(h1s_sc(h1s))->be;
		else
			other_end = sess->fe;
	} else
		other_end = NULL;

	/* http-specific part now */
	ctx.h1.state   = h1m->state;
	ctx.h1.c_flags = h1c->flags;
	ctx.h1.s_flags = h1s->flags;
	ctx.h1.m_flags = h1m->flags;
	ctx.h1.m_clen  = h1m->curr_len;
	ctx.h1.m_blen  = h1m->body_len;

	proxy_capture_error(proxy, !!(h1m->flags & H1_MF_RESP), other_end,
			    h1c->conn->target, sess, buf, 0, 0,
			    (h1m->err_pos >= 0) ? h1m->err_pos : h1m->next,
			    &ctx, h1_show_error_snapshot);
}

/* Emit the chunk size <chksz> followed by a CRLF in front of data of the buffer
 * <buf>. It goes backwards and starts with the byte before the buffer's
 * head. The caller is responsible for ensuring there is enough room left before
 * the buffer's head for the string. if <length> is greater than 0, it
 * represents the expected total length of the chunk size, including the
 * CRLF. So it will be padded with 0 to resepct this length. It is the caller
 * responsibility to pass the right value. if <length> is set to 0 (or less that
 * the smallest size to represent the chunk size), it is ignored.
 */
static void h1_prepend_chunk_size(struct buffer *buf, size_t chksz, size_t length)
{
	char *beg, *end;

	beg = end = b_head(buf);
	*--beg = '\n';
	*--beg = '\r';
	if (length)
		length -= 2;
	do {
		*--beg = hextab[chksz & 0xF];
		if (length)
			--length;
	} while (chksz >>= 4);
	while (length) {
		*--beg = '0';
		--length;
	}
	buf->head -= (end - beg);
	b_add(buf, end - beg);
}

/* Emit the chunksize followed by a CRLF after the data of the buffer
 * <buf>. Returns 0 on error.
 */
static int h1_append_chunk_size(struct buffer *buf, size_t chksz)
{
	char     tmp[10];
	char    *beg, *end;

	beg = end = tmp+10;
	*--beg = '\n';
	*--beg = '\r';
	do {
		*--beg = hextab[chksz & 0xF];
	} while (chksz >>= 4);

	return chunk_memcat(buf, beg, end - beg);
}

/* Emit a CRLF in front of data of the buffer <buf>. It goes backwards and
 * starts with the byte before the buffer's head. The caller is responsible for
 * ensuring there is enough room left before the buffer's head for the string.
 */
static void h1_prepend_chunk_crlf(struct buffer *buf)
{
	char *head;

	head = b_head(buf);
	*--head = '\n';
	*--head = '\r';
	buf->head -= 2;
	b_add(buf, 2);
}


/* Emit a CRLF after the data of the buffer <buf>. The caller is responsible for
 * ensuring there is enough room left in the buffer for the string. */
static void h1_append_chunk_crlf(struct buffer *buf)
{
	*(b_peek(buf, b_data(buf)))     = '\r';
	*(b_peek(buf, b_data(buf) + 1)) = '\n';
	b_add(buf, 2);
}

/*
 * Switch the stream to tunnel mode. This function must only be called on 2xx
 * (successful) replies to CONNECT requests or on 101 (switching protocol).
 */
static void h1_set_tunnel_mode(struct h1s *h1s)
{
	struct h1c *h1c = h1s->h1c;

	h1s->req.state = H1_MSG_TUNNEL;
	h1s->req.flags &= ~(H1_MF_XFER_LEN|H1_MF_CLEN|H1_MF_CHNK);

	h1s->res.state = H1_MSG_TUNNEL;
	h1s->res.flags &= ~(H1_MF_XFER_LEN|H1_MF_CLEN|H1_MF_CHNK);

	TRACE_STATE("switch H1 stream in tunnel mode", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);

	if (h1s->flags & H1S_F_RX_BLK) {
		h1s->flags &= ~H1S_F_RX_BLK;
		h1_wake_stream_for_recv(h1s);
		TRACE_STATE("Re-enable input processing", H1_EV_RX_DATA|H1_EV_H1S_BLK|H1_EV_STRM_WAKE, h1c->conn, h1s);
	}
	if (h1s->flags & H1S_F_TX_BLK) {
		h1s->flags &= ~H1S_F_TX_BLK;
		h1_wake_stream_for_send(h1s);
		TRACE_STATE("Re-enable output processing", H1_EV_TX_DATA|H1_EV_H1S_BLK|H1_EV_STRM_WAKE, h1c->conn, h1s);
	}
}

/* Search for a websocket key header. The message should have been identified
 * as a valid websocket handshake.
 *
 * On the request side, if found the key is stored in the session. It might be
 * needed to calculate response key if the server side is using http/2.
 *
 * On the response side, the key might be verified if haproxy has been
 * responsible for the generation of a key. This happens when a h2 client is
 * interfaced with a h1 server.
 *
 * Returns 0 if no key found or invalid key
 */
static int h1_search_websocket_key(struct h1s *h1s, struct h1m *h1m, struct htx *htx)
{
	struct htx_blk *blk;
	enum htx_blk_type type;
	struct ist n, v;
	int ws_key_found = 0, idx;

	idx = htx_get_head(htx); // returns the SL that we skip
	while ((idx = htx_get_next(htx, idx)) != -1) {
		blk = htx_get_blk(htx, idx);
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type != HTX_BLK_HDR)
			break;

		n = htx_get_blk_name(htx, blk);
		v = htx_get_blk_value(htx, blk);

		/* Websocket key is base64 encoded of 16 bytes */
		if (isteqi(n, ist("sec-websocket-key")) && v.len == 24 &&
		    !(h1m->flags & H1_MF_RESP)) {
			/* Copy the key on request side
			 * we might need it if the server is using h2 and does
			 * not provide the response
			 */
			memcpy(h1s->ws_key, v.ptr, 24);
			ws_key_found = 1;
			break;
		}
		else if (isteqi(n, ist("sec-websocket-accept")) &&
		         h1m->flags & H1_MF_RESP) {
			/* Need to verify the response key if the input was
			 * generated by haproxy
			 */
			if (h1s->ws_key[0]) {
				char key[29];
				h1_calculate_ws_output_key(h1s->ws_key, key);
				if (!isteqi(ist(key), v))
					break;
			}
			ws_key_found = 1;
			break;
		}
	}

	/* missing websocket key, reject the message */
	if (!ws_key_found) {
		htx->flags |= HTX_FL_PARSING_ERROR;
		return 0;
	}

	return 1;
}

/*
 * Parse HTTP/1 headers. It returns the number of bytes parsed if > 0, or 0 if
 * it couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR
 * flag. If more room is requested, H1S_F_RX_CONGESTED flag is set. If relies on
 * the function http_parse_msg_hdrs() to do the parsing.
 */
static size_t h1_handle_headers(struct h1s *h1s, struct h1m *h1m, struct htx *htx,
				struct buffer *buf, size_t *ofs, size_t max)
{
	union h1_sl h1sl;
	int ret = 0;

	TRACE_ENTER(H1_EV_RX_DATA|H1_EV_RX_HDRS, h1s->h1c->conn, h1s, 0, (size_t[]){max});

	if (h1s->meth == HTTP_METH_CONNECT)
		h1m->flags |= H1_MF_METH_CONNECT;
	if (h1s->meth == HTTP_METH_HEAD)
		h1m->flags |= H1_MF_METH_HEAD;

	ret = h1_parse_msg_hdrs(h1m, &h1sl, htx, buf, *ofs, max);
	if (ret <= 0) {
		TRACE_DEVEL("leaving on missing data or error", H1_EV_RX_DATA|H1_EV_RX_HDRS, h1s->h1c->conn, h1s);
		if (ret == -1) {
			h1s->flags |= H1S_F_PARSING_ERROR;
			if (h1m->err_code)
				h1s->h1c->errcode = h1m->err_code;
			TRACE_ERROR("parsing error, reject H1 message", H1_EV_RX_DATA|H1_EV_RX_HDRS|H1_EV_H1S_ERR, h1s->h1c->conn, h1s);
			h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
		}
		else if (ret == -2) {
			TRACE_STATE("RX path congested, waiting for more space", H1_EV_RX_DATA|H1_EV_RX_HDRS|H1_EV_H1S_BLK, h1s->h1c->conn, h1s);
			h1s->flags |= H1S_F_RX_CONGESTED;
		}
		ret = 0;
		goto end;
	}


	/* Reject HTTP/1.0 GET/HEAD/DELETE requests with a payload except if
	 * accept_payload_with_any_method global option is set.
	 *There is a payload if the c-l is not null or the the payload is
	 * chunk-encoded.  A parsing error is reported but a A
	 * 413-Payload-Too-Large is returned instead of a 400-Bad-Request.
	 */
	if (!accept_payload_with_any_method &&
	    !(h1m->flags & (H1_MF_RESP|H1_MF_VER_11)) &&
	    (((h1m->flags & H1_MF_CLEN) && h1m->body_len) || (h1m->flags & H1_MF_CHNK)) &&
	    (h1sl.rq.meth == HTTP_METH_GET || h1sl.rq.meth == HTTP_METH_HEAD || h1sl.rq.meth == HTTP_METH_DELETE)) {
		h1s->flags |= H1S_F_PARSING_ERROR;
		htx->flags |= HTX_FL_PARSING_ERROR;
		h1s->h1c->errcode = 413;
		TRACE_ERROR("HTTP/1.0 GET/HEAD/DELETE request with a payload forbidden", H1_EV_RX_DATA|H1_EV_RX_HDRS|H1_EV_H1S_ERR, h1s->h1c->conn, h1s);
		h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
		ret = 0;
		goto end;
	}

	/* Reject any message with an unknown transfer-encoding. In fact if any
	 * encoding other than "chunked". A 422-Unprocessable-Content is
	 * returned for an invalid request, a 502-Bad-Gateway for an invalid
	 * response.
	 */
	if (h1m->flags & H1_MF_TE_OTHER) {
		h1s->flags |= H1S_F_PARSING_ERROR;
		htx->flags |= HTX_FL_PARSING_ERROR;
		if (!(h1m->flags & H1_MF_RESP))
			h1s->h1c->errcode = 422;
		TRACE_ERROR("Unknown transfer-encoding", H1_EV_RX_DATA|H1_EV_RX_HDRS|H1_EV_H1S_ERR, h1s->h1c->conn, h1s);
		h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
		ret = 0;
		goto end;
	}

	/* If websocket handshake, search for the websocket key */
	if ((h1m->flags & (H1_MF_CONN_UPG|H1_MF_UPG_WEBSOCKET)) ==
	    (H1_MF_CONN_UPG|H1_MF_UPG_WEBSOCKET)) {
		int ws_ret = h1_search_websocket_key(h1s, h1m, htx);
		if (!ws_ret) {
			h1s->flags |= H1S_F_PARSING_ERROR;
			TRACE_ERROR("missing/invalid websocket key, reject H1 message", H1_EV_RX_DATA|H1_EV_RX_HDRS|H1_EV_H1S_ERR, h1s->h1c->conn, h1s);
			h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);

			ret = 0;
			goto end;
		}
	}

	if (h1m->err_pos >= 0)  {
		/* Maybe we found an error during the parsing while we were
		 * configured not to block on that, so we have to capture it
		 * now.
		 */
		TRACE_STATE("Ignored parsing error", H1_EV_RX_DATA|H1_EV_RX_HDRS, h1s->h1c->conn, h1s);
		h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
	}

	if (!(h1m->flags & H1_MF_RESP)) {
		h1s->meth = h1sl.rq.meth;
		if (h1s->meth == HTTP_METH_HEAD)
			h1s->flags |= H1S_F_BODYLESS_RESP;
	}
	else {
		h1s->status = h1sl.st.status;
		if (h1s->status == 204 || h1s->status == 304)
			h1s->flags |= H1S_F_BODYLESS_RESP;
	}
	h1_process_input_conn_mode(h1s, h1m, htx);
	*ofs += ret;

  end:
	TRACE_LEAVE(H1_EV_RX_DATA|H1_EV_RX_HDRS, h1s->h1c->conn, h1s, 0, (size_t[]){ret});
	return ret;
}

/*
 * Parse HTTP/1 body. It returns the number of bytes parsed if > 0, or 0 if it
 * couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR flag.
 * If relies on the function http_parse_msg_data() to do the parsing.
 */
static size_t h1_handle_data(struct h1s *h1s, struct h1m *h1m, struct htx **htx,
			     struct buffer *buf, size_t *ofs, size_t max,
			     struct buffer *htxbuf)
{
	size_t ret;

	TRACE_ENTER(H1_EV_RX_DATA|H1_EV_RX_BODY, h1s->h1c->conn, h1s, 0, (size_t[]){max});
	ret = h1_parse_msg_data(h1m, htx, buf, *ofs, max, htxbuf);
	if (!ret) {
		TRACE_DEVEL("leaving on missing data or error", H1_EV_RX_DATA|H1_EV_RX_BODY, h1s->h1c->conn, h1s);
		if ((*htx)->flags & HTX_FL_PARSING_ERROR) {
			h1s->flags |= H1S_F_PARSING_ERROR;
			TRACE_ERROR("parsing error, reject H1 message", H1_EV_RX_DATA|H1_EV_RX_BODY|H1_EV_H1S_ERR, h1s->h1c->conn, h1s);
			h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
		}
		goto end;
	}

	*ofs += ret;

  end:
	if (b_data(buf) != *ofs && (h1m->state == H1_MSG_DATA || h1m->state == H1_MSG_TUNNEL)) {
		TRACE_STATE("RX path congested, waiting for more space", H1_EV_RX_DATA|H1_EV_RX_BODY|H1_EV_H1S_BLK, h1s->h1c->conn, h1s);
		h1s->flags |= H1S_F_RX_CONGESTED;
	}

	TRACE_LEAVE(H1_EV_RX_DATA|H1_EV_RX_BODY, h1s->h1c->conn, h1s, 0, (size_t[]){ret});
	return ret;
}

/*
 * Parse HTTP/1 trailers. It returns the number of bytes parsed if > 0, or 0 if
 * it couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR
 * flag and filling h1s->err_pos and h1s->err_state fields. This functions is
 * responsible to update the parser state <h1m>. If more room is requested,
 * H1S_F_RX_CONGESTED flag is set.
 */
static size_t h1_handle_trailers(struct h1s *h1s, struct h1m *h1m, struct htx *htx,
				 struct buffer *buf, size_t *ofs, size_t max)
{
	int ret;

	TRACE_ENTER(H1_EV_RX_DATA|H1_EV_RX_TLRS, h1s->h1c->conn, h1s, 0, (size_t[]){max});
	ret = h1_parse_msg_tlrs(h1m, htx, buf, *ofs, max);
	if (ret <= 0) {
		TRACE_DEVEL("leaving on missing data or error", H1_EV_RX_DATA|H1_EV_RX_BODY, h1s->h1c->conn, h1s);
		if (ret == -1) {
			h1s->flags |= H1S_F_PARSING_ERROR;
			TRACE_ERROR("parsing error, reject H1 message", H1_EV_RX_DATA|H1_EV_RX_TLRS|H1_EV_H1S_ERR, h1s->h1c->conn, h1s);
			h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
		}
		else if (ret == -2) {
			TRACE_STATE("RX path congested, waiting for more space", H1_EV_RX_DATA|H1_EV_RX_TLRS|H1_EV_H1S_BLK, h1s->h1c->conn, h1s);
			h1s->flags |= H1S_F_RX_CONGESTED;
		}
		ret = 0;
		goto end;
	}

	*ofs += ret;

  end:
	TRACE_LEAVE(H1_EV_RX_DATA|H1_EV_RX_TLRS, h1s->h1c->conn, h1s, 0, (size_t[]){ret});
	return ret;
}

/*
 * Process incoming data. It parses data and transfer them from h1c->ibuf into
 * <buf>. It returns the number of bytes parsed and transferred if > 0, or 0 if
 * it couldn't proceed.
 *
 * WARNING: H1S_F_RX_CONGESTED flag must be removed before processing input data.
 */
static size_t h1_process_demux(struct h1c *h1c, struct buffer *buf, size_t count)
{
	struct h1s *h1s = h1c->h1s;
	struct h1m *h1m;
	struct htx *htx;
	size_t data;
	size_t ret = 0;
	size_t total = 0;

	htx = htx_from_buf(buf);
	TRACE_ENTER(H1_EV_RX_DATA, h1c->conn, h1s, htx, (size_t[]){count});

	h1m = (!(h1c->flags & H1C_F_IS_BACK) ? &h1s->req : &h1s->res);
	data = htx->data;

	if (h1s->flags & H1S_F_DEMUX_ERROR)
		goto end;

	if (h1s->flags & H1S_F_RX_BLK)
		goto out;

	/* Always remove congestion flags and try to process more input data */
	h1s->flags &= ~H1S_F_RX_CONGESTED;

	do {
		size_t used = htx_used_space(htx);

		if (h1m->state <= H1_MSG_LAST_LF) {
			TRACE_PROTO("parsing message headers", H1_EV_RX_DATA|H1_EV_RX_HDRS, h1c->conn, h1s);
			ret = h1_handle_headers(h1s, h1m, htx, &h1c->ibuf, &total, count);
			if (!ret)
				break;

			TRACE_USER((!(h1m->flags & H1_MF_RESP) ? "rcvd H1 request headers" : "rcvd H1 response headers"),
				   H1_EV_RX_DATA|H1_EV_RX_HDRS, h1c->conn, h1s, htx, (size_t[]){ret});

			if ((h1m->flags & H1_MF_RESP) &&
			    h1s->status < 200 && (h1s->status == 100 || h1s->status >= 102)) {
				h1m_init_res(&h1s->res);
				h1m->flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);
				TRACE_STATE("1xx response rcvd", H1_EV_RX_DATA|H1_EV_RX_HDRS, h1c->conn, h1s);
			}
		}
		else if (h1m->state < H1_MSG_TRAILERS) {
			TRACE_PROTO("parsing message payload", H1_EV_RX_DATA|H1_EV_RX_BODY, h1c->conn, h1s);
			ret = h1_handle_data(h1s, h1m, &htx, &h1c->ibuf, &total, count, buf);
			if (h1m->state < H1_MSG_TRAILERS)
				break;

			TRACE_PROTO((!(h1m->flags & H1_MF_RESP) ? "rcvd H1 request payload data" : "rcvd H1 response payload data"),
				    H1_EV_RX_DATA|H1_EV_RX_BODY, h1c->conn, h1s, htx, (size_t[]){ret});
		}
		else if (h1m->state == H1_MSG_TRAILERS) {
			TRACE_PROTO("parsing message trailers", H1_EV_RX_DATA|H1_EV_RX_TLRS, h1c->conn, h1s);
			ret = h1_handle_trailers(h1s, h1m, htx, &h1c->ibuf, &total, count);
			if (h1m->state != H1_MSG_DONE)
				break;

			TRACE_PROTO((!(h1m->flags & H1_MF_RESP) ? "rcvd H1 request trailers" : "rcvd H1 response trailers"),
				    H1_EV_RX_DATA|H1_EV_RX_TLRS, h1c->conn, h1s, htx, (size_t[]){ret});
		}
		else if (h1m->state == H1_MSG_DONE) {
			TRACE_USER((!(h1m->flags & H1_MF_RESP) ? "H1 request fully rcvd" : "H1 response fully rcvd"),
				   H1_EV_RX_DATA|H1_EV_RX_EOI, h1c->conn, h1s, htx);

			if (!(h1c->flags & H1C_F_IS_BACK)) {
				/* The request was fully received. It means the H1S now
				 * expect data from the opposite side
				 */
				se_expect_data(h1s->sd);
			}

			if ((h1m->flags & H1_MF_RESP) &&
			    ((h1s->meth == HTTP_METH_CONNECT && h1s->status >= 200 && h1s->status < 300) || h1s->status == 101)) {
				if (h1s->req.state != H1_MSG_DONE) {
					TRACE_STATE("Reject tunnel because request is not finished", H1_EV_RX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
					h1s->flags |= H1S_F_PARSING_ERROR;
					htx->flags |= HTX_FL_PARSING_ERROR;
					h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
					break;
				}
				h1_set_tunnel_mode(h1s);
			}
			else {
				if (h1s->req.state < H1_MSG_DONE || h1s->res.state < H1_MSG_DONE) {
					/* Unfinished transaction: block this input side waiting the end of the output side */
					h1s->flags |= H1S_F_RX_BLK;
					TRACE_STATE("Disable input processing", H1_EV_RX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
				}
				if (h1s->flags & H1S_F_TX_BLK) {
					h1s->flags &= ~H1S_F_TX_BLK;
					h1_wake_stream_for_send(h1s);
					TRACE_STATE("Re-enable output processing", H1_EV_TX_DATA|H1_EV_H1S_BLK|H1_EV_STRM_WAKE, h1c->conn, h1s);
				}
				break;
			}
		}
		else if (h1m->state == H1_MSG_TUNNEL) {
			TRACE_PROTO("parsing tunneled data", H1_EV_RX_DATA, h1c->conn, h1s);
			ret = h1_handle_data(h1s, h1m, &htx, &h1c->ibuf, &total, count, buf);
			if (!ret)
				break;

			TRACE_PROTO((!(h1m->flags & H1_MF_RESP) ? "rcvd H1 request tunneled data" : "rcvd H1 response tunneled data"),
				    H1_EV_RX_DATA|H1_EV_RX_EOI, h1c->conn, h1s, htx, (size_t[]){ret});
		}
		else {
			h1s->flags |= H1S_F_PARSING_ERROR;
			break;
		}

		count -= htx_used_space(htx) - used;
	} while (!(h1s->flags & (H1S_F_DEMUX_ERROR|H1S_F_RX_BLK|H1S_F_RX_CONGESTED)));


	if (h1s->flags & H1S_F_DEMUX_ERROR) {
		TRACE_ERROR("parsing or not-implemented error", H1_EV_RX_DATA|H1_EV_H1S_ERR, h1c->conn, h1s);
		if (h1c->state < H1_CS_RUNNING) {
			if (h1s->flags & H1S_F_PARSING_ERROR)
				h1c_report_term_evt(h1c, muxc_tevt_type_proto_err);
			else if (h1s->flags & H1S_F_INTERNAL_ERROR)
				h1c_report_term_evt(h1c, muxc_tevt_type_internal_err);
			else
				h1c_report_term_evt(h1c, muxc_tevt_type_other_err);
		}
		else {
			if (h1s->flags & H1S_F_PARSING_ERROR)
				se_report_term_evt(h1s->sd, se_tevt_type_proto_err);
			else if (h1s->flags & H1S_F_INTERNAL_ERROR)
				se_report_term_evt(h1s->sd, se_tevt_type_internal_err);
			else
				se_report_term_evt(h1s->sd, se_tevt_type_other_err);
		}
		goto err;
	}

	b_del(&h1c->ibuf, total);

	TRACE_DEVEL("incoming data parsed", H1_EV_RX_DATA, h1c->conn, h1s, htx, (size_t[]){ret});

	ret = htx->data - data;
	if ((h1c->flags & H1C_F_IN_FULL) && buf_room_for_htx_data(&h1c->ibuf)) {
		h1c->flags &= ~H1C_F_IN_FULL;
		TRACE_STATE("h1c ibuf not full anymore", H1_EV_RX_DATA|H1_EV_H1C_BLK|H1_EV_H1C_WAKE, h1c->conn, h1s);
		h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
	}

	if (!b_data(&h1c->ibuf))
		h1_release_buf(h1c, &h1c->ibuf);

	if (h1m->state <= H1_MSG_LAST_LF)
		goto out;

	if (h1c->state < H1_CS_RUNNING) {
		/* The H1 connection is not ready. Most of time, there is no SC
		 * attached, except for TCP>H1 upgrade, from a TCP frontend. In both
		 * cases, it is only possible on the client side.
		 */
		BUG_ON(h1c->flags & H1C_F_IS_BACK);

		if (h1c->state == H1_CS_EMBRYONIC) {
			TRACE_DEVEL("request headers fully parsed, create and attach the SC", H1_EV_RX_DATA, h1c->conn, h1s);
			BUG_ON(h1s_sc(h1s));
			if (!h1s_new_sc(h1s, buf)) {
				h1s->flags |= H1S_F_INTERNAL_ERROR;
				goto err;
			}
		}
		else {
			TRACE_DEVEL("request headers fully parsed, upgrade the inherited SC", H1_EV_RX_DATA, h1c->conn, h1s);
			BUG_ON(h1s_sc(h1s) == NULL);
			if (!h1s_upgrade_sc(h1s, buf)) {
				h1s->flags |= H1S_F_INTERNAL_ERROR;
				TRACE_ERROR("H1S upgrade failure", H1_EV_RX_DATA|H1_EV_H1S_ERR, h1c->conn, h1s);
				goto err;
			}
		}
	}

	/* Here h1s_sc(h1s) is always defined */
	if (!(h1c->flags & H1C_F_CANT_FASTFWD) &&
	    (!(h1m->flags & H1_MF_RESP) || !(h1s->flags & H1S_F_BODYLESS_RESP)) &&
	    (h1m->state == H1_MSG_DATA || h1m->state == H1_MSG_TUNNEL) &&
	    !(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_H1_RCV)) {
		TRACE_STATE("notify the mux can use fast-forward", H1_EV_RX_DATA|H1_EV_RX_BODY, h1c->conn, h1s);
		se_fl_set(h1s->sd, SE_FL_MAY_FASTFWD_PROD);
	}
	else {
		TRACE_STATE("notify the mux can't use fast-forward anymore", H1_EV_RX_DATA|H1_EV_RX_BODY, h1c->conn, h1s);
		se_fl_clr(h1s->sd, SE_FL_MAY_FASTFWD_PROD);
		h1c->flags &= ~H1C_F_WANT_FASTFWD;
	}

	h1s_set_se_eoi_cond(h1s, h1m);

  out:
	/* When Input data are pending for this message, notify upper layer that
	 * the mux need more space in the HTX buffer to continue if :
	 *
	 *   - The parser is blocked in MSG_DATA or MSG_TUNNEL state
	 *   - Headers or trailers are pending to be copied.
	 */
	if (h1s->flags & (H1S_F_RX_CONGESTED)) {
		se_fl_set(h1s->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		TRACE_STATE("waiting for more room", H1_EV_RX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	}
	else {
		se_fl_clr(h1s->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);

		if (h1c->flags & H1C_F_EOS) {
			se_fl_set(h1s->sd, SE_FL_EOS);
			TRACE_STATE("report EOS to SE", H1_EV_RX_DATA, h1c->conn, h1s);
			if (h1m->state >= H1_MSG_DONE || (h1m->state > H1_MSG_LAST_LF && !(h1m->flags & H1_MF_XFER_LEN))) {
				/* DONE or TUNNEL or SHUTR without XFER_LEN, set
				 * EOI on the stream connector */
				se_fl_set(h1s->sd, SE_FL_EOI);
				TRACE_STATE("report EOI to SE", H1_EV_RX_DATA, h1c->conn, h1s);
			}
			else if (h1m->state < H1_MSG_DONE) {
				if (h1m->state <= H1_MSG_LAST_LF && b_data(&h1c->ibuf))
					htx->flags |= HTX_FL_PARSING_ERROR;
				se_fl_set(h1s->sd, SE_FL_ERROR);
				COUNT_IF(1, "H1C EOS before the end of the message");
				TRACE_ERROR("message aborted, set error on SC", H1_EV_RX_DATA|H1_EV_H1S_ERR, h1c->conn, h1s);
			}

			if (!(h1c->flags & H1C_F_ERROR)) {
				if (se_fl_test(h1c->h1s->sd, SE_FL_EOI)) {
					se_report_term_evt(h1s->sd, se_tevt_type_eos);
					h1c_report_term_evt(h1c, muxc_tevt_type_shutr);
				}
				else {
					se_report_term_evt(h1s->sd, se_tevt_type_truncated_eos);
					h1c_report_term_evt(h1c, muxc_tevt_type_truncated_shutr);
				}
			}

			if (h1s->flags & H1S_F_TX_BLK) {
				h1s->flags &= ~H1S_F_TX_BLK;
				h1_wake_stream_for_send(h1s);
				TRACE_STATE("Re-enable output processing", H1_EV_TX_DATA|H1_EV_H1S_BLK|H1_EV_STRM_WAKE, h1c->conn, h1s);
			}
		}
		if (h1c->flags & H1C_F_ERROR) {
			/* Report a terminal error to the SE if a previous read error was detected */
			se_fl_set(h1s->sd, SE_FL_ERROR);

			if (se_fl_test(h1c->h1s->sd, SE_FL_EOI)) {
				se_report_term_evt(h1s->sd, se_tevt_type_rcv_err);
				h1c_report_term_evt(h1c, muxc_tevt_type_rcv_err);
			}
			else {
				se_report_term_evt(h1s->sd, se_tevt_type_truncated_rcv_err);
				h1c_report_term_evt(h1c, muxc_tevt_type_truncated_rcv_err);
			}

			COUNT_IF(h1m->state < H1_MSG_DONE, "H1C ERROR before the end of the message");
			TRACE_STATE("report ERROR to SE", H1_EV_RX_DATA|H1_EV_H1S_ERR, h1c->conn, h1s);
		}
	}

  end:
	htx_to_buf(htx, buf);
	TRACE_LEAVE(H1_EV_RX_DATA, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;

  err:
	htx_to_buf(htx, buf);
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_DEVEL("leaving on error", H1_EV_RX_DATA|H1_EV_STRM_ERR, h1c->conn, h1s);
	return 0;
}

/* Try to send the request line from the HTX message <htx> for the stream
 * <h1s>. It returns the number of bytes consumed or zero if nothing was done or
 * if an error occurred. No more than <count> bytes can be sent.
 */
static size_t h1_make_reqline(struct h1s *h1s, struct h1m *h1m, struct htx *htx, size_t count)
{
	struct h1c *h1c = h1s->h1c;
        struct htx_blk *blk;
	struct buffer outbuf;
	struct htx_sl *sl;
	enum htx_blk_type type;
	uint32_t sz;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){count});

	while (1) {
		blk = htx_get_head_blk(htx);
		if (!blk)
			goto end;
		type = htx_get_blk_type(blk);
		sz = htx_get_blksz(blk);
		if (type == HTX_BLK_UNUSED)
			continue;
		if (type != HTX_BLK_REQ_SL || sz > count)
			goto error;
		break;
	}

	TRACE_USER("sending request headers", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx);

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);

	sl = htx_get_blk_ptr(htx, blk);
	if (!h1_format_htx_reqline(sl, &outbuf))
		goto full;

	b_add(&h1c->obuf, outbuf.data);

	h1s->meth = sl->info.req.meth;
	h1_parse_req_vsn(h1m, sl);

	h1m->flags |= H1_MF_XFER_LEN;
	if (sl->flags & HTX_SL_F_CHNK)
		h1m->flags |= H1_MF_CHNK;
	else if (sl->flags & HTX_SL_F_CLEN)
		h1m->flags |= H1_MF_CLEN;
	if (sl->flags & HTX_SL_F_XFER_ENC)
		h1m->flags |= H1_MF_XFER_ENC;

	if (sl->flags & HTX_SL_F_BODYLESS && !(h1m->flags & H1_MF_CLEN)) {
		h1m->flags = (h1m->flags & ~H1_MF_CHNK) | H1_MF_CLEN;
		h1s->flags |= H1S_F_HAVE_CLEN;
	}
	if ((sl->flags & HTX_SL_F_BODYLESS_RESP) || h1s->meth == HTTP_METH_HEAD)
		h1s->flags |= H1S_F_BODYLESS_RESP;

	if (h1s->flags & H1S_F_RX_BLK) {
		h1s->flags &= ~H1S_F_RX_BLK;
		h1_wake_stream_for_recv(h1s);
		TRACE_STATE("Re-enable input processing", H1_EV_TX_DATA|H1_EV_H1S_BLK|H1_EV_STRM_WAKE, h1c->conn, h1s);
	}

	h1m->state = H1_MSG_HDR_NAME;
	ret += sz;
	htx_remove_blk(htx, blk);

  end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;

  full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto end;

  error:
	htx->flags |= HTX_FL_PROCESSING_ERROR;
	h1s->flags |= H1S_F_PROCESSING_ERROR;
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_ERROR("processing error on request start-line",
		    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	goto end;
}

/* Try to send the status line from the HTX message <htx> for the stream
 * <h1s>. It returns the number of bytes consumed or zero if nothing was done or
 * if an error occurred. No more than <count> bytes can be sent.
 */
static size_t h1_make_stline(struct h1s *h1s, struct h1m *h1m, struct htx *htx, size_t count)
{
	struct h1c *h1c = h1s->h1c;
	struct htx_blk *blk;
	struct buffer outbuf;
	struct htx_sl *sl;
	enum htx_blk_type type;
	uint32_t sz;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){count});

	while (1) {
		blk = htx_get_head_blk(htx);
		if (!blk)
			goto end;

		type = htx_get_blk_type(blk);
		sz = htx_get_blksz(blk);

		if (type == HTX_BLK_UNUSED)
			continue;
		if (type != HTX_BLK_RES_SL || sz > count)
			goto error;
		break;
	}

	TRACE_USER("sending response headers", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx);

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);

	sl = htx_get_blk_ptr(htx, blk);
	if (!h1_format_htx_stline(sl, &outbuf))
		goto full;

	b_add(&h1c->obuf, outbuf.data);

	h1s->status = sl->info.res.status;
	h1_parse_res_vsn(h1m, sl);

	if (sl->flags & HTX_SL_F_XFER_LEN) {
		h1m->flags |= H1_MF_XFER_LEN;
		if (sl->flags & HTX_SL_F_CHNK)
			h1m->flags |= H1_MF_CHNK;
		else if (sl->flags & HTX_SL_F_CLEN)
			h1m->flags |= H1_MF_CLEN;
		if (sl->flags & HTX_SL_F_XFER_ENC)
			h1m->flags |= H1_MF_XFER_ENC;
	}
	if (h1s->status < 200)
		h1s->flags |= H1S_F_HAVE_O_CONN;
	else if ((sl->flags & HTX_SL_F_BODYLESS_RESP) || h1s->status == 204 || h1s->status == 304)
		h1s->flags |= H1S_F_BODYLESS_RESP;

	h1m->state = H1_MSG_HDR_NAME;
	ret += sz;
	htx_remove_blk(htx, blk);

  end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;

  full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto end;

  error:
	htx->flags |= HTX_FL_PROCESSING_ERROR;
	h1s->flags |= H1S_F_PROCESSING_ERROR;
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_ERROR("processing error on response start-line",
		    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	goto end;
}

/* Try to send the message headers from the HTX message <htx> for the stream
 * <h1s>. It returns the number of bytes consumed or zero if nothing was done or
 * if an error occurred. No more than <count> bytes can be sent.
 */
static size_t h1_make_headers(struct h1s *h1s, struct h1m *h1m, struct htx *htx, size_t count)
{
	struct h1c *h1c = h1s->h1c;
	struct htx_blk *blk;
	struct buffer outbuf;
	enum htx_blk_type type;
	struct ist n, v;
	uint32_t sz;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){count});

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);

	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		sz = htx_get_blksz(blk);

		if (type == HTX_BLK_HDR) {
			if (sz > count)
				goto error;

			n = htx_get_blk_name(htx, blk);
			v = htx_get_blk_value(htx, blk);

			/* Skip all pseudo-headers */
			if (*(n.ptr) == ':')
				goto nextblk;

			if (isteq(n, ist("transfer-encoding"))) {
				if ((h1m->flags & H1_MF_RESP) && (h1s->status < 200 || h1s->status == 204))
					goto nextblk;
				if (!(h1m->flags & H1_MF_CHNK))
					goto nextblk;
				if (h1s->flags & H1S_F_HAVE_CHNK)
					goto nextblk;
				v = ist("chunked");
				h1s->flags |= H1S_F_HAVE_CHNK;
                        }
			else if (isteq(n, ist("content-length"))) {
				if ((h1m->flags & H1_MF_RESP) && (h1s->status < 200 || h1s->status == 204))
					goto nextblk;
				if (!(h1m->flags & H1_MF_CLEN))
					goto nextblk;
				if (!(h1s->flags & H1S_F_HAVE_CLEN))
					h1m->flags &= ~H1_MF_CLEN;
				/* Only skip C-L header with invalid value. */
				if (h1_parse_cont_len_header(h1m, &v) < 0)
					goto error;
				if (h1s->flags & H1S_F_HAVE_CLEN)
					goto nextblk;
				h1s->flags |= H1S_F_HAVE_CLEN;
			}
			else if (isteq(n, ist("connection"))) {
				h1_parse_connection_header(h1m, &v);
				if (!v.len)
					goto nextblk;
			}
			else if (isteq(n, ist("upgrade"))) {
				h1_parse_upgrade_header(h1m, v);
			}
			else if ((isteq(n, ist("sec-websocket-accept")) && h1m->flags & H1_MF_RESP) ||
				 (isteq(n, ist("sec-websocket-key")) && !(h1m->flags & H1_MF_RESP))) {
				h1s->flags |= H1S_F_HAVE_WS_KEY;
			}
			else if (isteq(n, ist("te"))) {
				/* "te" may only be sent with "trailers" if this value
				 * is present, otherwise it must be deleted.
				 */
				v = istist(v, ist("trailers"));
				if (!isttest(v) || (v.len > 8 && v.ptr[8] != ','))
					goto nextblk;
				v = ist("trailers");
			}

			/* Skip header if same name is used to add the server name */
			if (!(h1m->flags & H1_MF_RESP) && isttest(h1c->px->server_id_hdr_name) &&
			    isteqi(n, h1c->px->server_id_hdr_name))
				goto nextblk;

			/* Try to adjust the case of the header name */
			if (h1c->px->options2 & (PR_O2_H1_ADJ_BUGCLI|PR_O2_H1_ADJ_BUGSRV))
				h1_adjust_case_outgoing_hdr(h1s, h1m, &n);
			if (!h1_format_htx_hdr(n, v, &outbuf))
				goto full;
		}
		else if (type == HTX_BLK_EOH) {
			h1m->state = H1_MSG_LAST_LF;
			break; /* Do not consume this block */
                }
		else if (type == HTX_BLK_UNUSED)
			goto nextblk;
		else
			goto error;

	  nextblk:
		ret += sz;
		count -= sz;
		blk = htx_remove_blk(htx, blk);
	}

  copy:
	b_add(&h1c->obuf, outbuf.data);

  end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;

  full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto copy;

  error:
	ret = 0;
	htx->flags |= HTX_FL_PROCESSING_ERROR;
	h1s->flags |= H1S_F_PROCESSING_ERROR;
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_ERROR("processing error on message headers",
		    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	goto end;
}

/* Handle the EOH and perform last processing before sending the data. It
 * returns the number of bytes consumed or zero if nothing was done or if an
 * error occurred. No more than <count> bytes can be sent.
 */
static size_t h1_make_eoh(struct h1s *h1s, struct h1m *h1m, struct htx *htx, size_t count)
{
	struct h1c *h1c = h1s->h1c;
	struct htx_blk *blk;
	struct buffer outbuf;
	enum htx_blk_type type;
	struct ist n, v;
	uint32_t sz;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){count});

	while (1) {
		blk = htx_get_head_blk(htx);
		if (!blk)
			goto end;

		type = htx_get_blk_type(blk);
		sz = htx_get_blksz(blk);

                if (type == HTX_BLK_UNUSED)
			continue;
		if (type != HTX_BLK_EOH || sz > count)
			goto error;
		break;
	}

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);

	/* Deal with removed "Content-Length" or "Transfer-Encoding" headers during analysis */
	if (((h1m->flags & H1_MF_CLEN) && !(h1s->flags & H1S_F_HAVE_CLEN))||
	    ((h1m->flags & H1_MF_CHNK) && !(h1s->flags & H1S_F_HAVE_CHNK))) {
		TRACE_STATE("\"Content-Length\" or \"Transfer-Encoding\" header removed during analysis", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);

		if (h1s->flags & (H1S_F_HAVE_CLEN|H1S_F_HAVE_CHNK)) {
			/* At least on header is present, we can continue */
			if (!(h1s->flags & H1S_F_HAVE_CLEN)) {
				h1m->curr_len = h1m->body_len = 0;
				h1m->flags &= ~H1_MF_CLEN;
			}
			else /* h1s->flags & H1S_F_HAVE_CHNK */
				h1m->flags &= ~(H1_MF_XFER_ENC|H1_MF_CHNK);
		}
		else {
			/* Both headers are missing */
			if (h1m->flags & H1_MF_RESP) {
				/* It is a esponse: Switch to unknown xfer length */
				h1m->flags &= ~(H1_MF_XFER_LEN|H1_MF_XFER_ENC|H1_MF_CLEN|H1_MF_CHNK);
				h1s->flags &= ~(H1S_F_HAVE_CLEN|H1S_F_HAVE_CHNK);
				TRACE_STATE("Switch response to unknown XFER length", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);
			}
			else {
				/* It is the request: Add "Content-Length: 0" header and skip payload */
				struct ist n = ist("content-length");
				if (h1c->px->options2 & (PR_O2_H1_ADJ_BUGCLI|PR_O2_H1_ADJ_BUGSRV))
					h1_adjust_case_outgoing_hdr(h1s, h1m, &n);
				if (!h1_format_htx_hdr(n, ist("0"), &outbuf))
					goto full;

				h1m->flags = (h1m->flags & ~(H1_MF_XFER_ENC|H1_MF_CHNK)) | H1_MF_CLEN;
				h1s->flags = (h1s->flags & ~H1S_F_HAVE_CHNK) | (H1S_F_HAVE_CLEN|H1S_F_BODYLESS_REQ);
				h1m->curr_len = h1m->body_len = 0;
				TRACE_STATE("Set request content-length to 0 and skip payload", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);
			}
		}
	}

	/* Deal with "Connection" header */
	if (!(h1s->flags & H1S_F_HAVE_O_CONN)) {
		if ((h1m->flags & (H1_MF_XFER_ENC|H1_MF_CLEN)) == (H1_MF_XFER_ENC|H1_MF_CLEN)) {
			/* T-E + C-L: force close */
			h1m->flags &= ~H1_MF_CLEN;
			if (!h1_do_not_close_on_insecure_t_e) {
				h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
				TRACE_STATE("force close mode (T-E + C-L)", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
			}
		}
		else if ((h1m->flags & (H1_MF_VER_11|H1_MF_XFER_ENC)) == H1_MF_XFER_ENC) {
			/* T-E + HTTP/1.0: force close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
			TRACE_STATE("force close mode (T-E + HTTP/1.0)", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1s->h1c->conn, h1s);
		}

		/* the conn_mode must be processed. So do it */
		n = ist("connection");
		v = ist("");
		h1_process_output_conn_mode(h1s, h1m, &v);
		if (v.len) {
			/* Try to adjust the case of the header name */
			if (h1c->px->options2 & (PR_O2_H1_ADJ_BUGCLI|PR_O2_H1_ADJ_BUGSRV))
				h1_adjust_case_outgoing_hdr(h1s, h1m, &n);
			if (!h1_format_htx_hdr(n, v, &outbuf))
				goto full;
		}
		h1s->flags |= H1S_F_HAVE_O_CONN;
	}

	/* Deal with "Transfer-Encoding" header */
	if ((h1s->meth != HTTP_METH_CONNECT &&
	     (h1m->flags & (H1_MF_VER_11|H1_MF_RESP|H1_MF_CLEN|H1_MF_CHNK|H1_MF_XFER_LEN)) ==
	     (H1_MF_VER_11|H1_MF_XFER_LEN)) ||
	    (h1s->status >= 200 && !(h1s->flags & H1S_F_BODYLESS_RESP) &&
	     !(h1s->meth == HTTP_METH_CONNECT && h1s->status >= 200 && h1s->status < 300) &&
	     (h1m->flags & (H1_MF_VER_11|H1_MF_RESP|H1_MF_CLEN|H1_MF_CHNK|H1_MF_XFER_LEN)) ==
	     (H1_MF_VER_11|H1_MF_RESP|H1_MF_XFER_LEN)))
		h1m->flags |= H1_MF_CHNK;

	if ((h1m->flags & H1_MF_CHNK) && !(h1s->flags & H1S_F_HAVE_CHNK)) {
		/* chunking needed but header not seen */
		n = ist("transfer-encoding");
		v = ist("chunked");
		if (h1c->px->options2 & (PR_O2_H1_ADJ_BUGCLI|PR_O2_H1_ADJ_BUGSRV))
			h1_adjust_case_outgoing_hdr(h1s, h1m, &n);
		if (!h1_format_htx_hdr(n, v, &outbuf))
			goto full;
		TRACE_STATE("add \"Transfer-Encoding: chunked\"", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);
		h1s->flags |= H1S_F_HAVE_CHNK;
	}

	/* Add the server name to a header (if requested) */
	if (!(h1s->flags & H1S_F_HAVE_SRV_NAME) &&
	    !(h1m->flags & H1_MF_RESP) && isttest(h1c->px->server_id_hdr_name)) {
		struct server *srv = objt_server(h1c->conn->target);

		if (srv) {
			n = h1c->px->server_id_hdr_name;
			v = ist(srv->id);

			/* Try to adjust the case of the header name */
			if (h1c->px->options2 & (PR_O2_H1_ADJ_BUGCLI|PR_O2_H1_ADJ_BUGSRV))
				h1_adjust_case_outgoing_hdr(h1s, h1m, &n);
			if (!h1_format_htx_hdr(n, v, &outbuf))
				goto full;
		}
		TRACE_STATE("add server name header", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);
		h1s->flags |= H1S_F_HAVE_SRV_NAME;
	}

	/* Add websocket handshake key if needed */
	if (!(h1s->flags & H1S_F_HAVE_WS_KEY) &&
	    (h1m->flags & (H1_MF_CONN_UPG|H1_MF_UPG_WEBSOCKET)) == (H1_MF_CONN_UPG|H1_MF_UPG_WEBSOCKET)) {
		if (!(h1m->flags & H1_MF_RESP)) {
			/* generate a random websocket key
			 * stored in the session to
			 * verify it on the response side
                         */
			h1_generate_random_ws_input_key(h1s->ws_key);

			if (!h1_format_htx_hdr(ist("Sec-Websocket-Key"),
					       ist(h1s->ws_key),
					       &outbuf)) {
				goto full;
			}
		}
		else {
			/* add the response header key */
			char key[29];

			h1_calculate_ws_output_key(h1s->ws_key, key);
			if (!h1_format_htx_hdr(ist("Sec-Websocket-Accept"),
					       ist(key),
					       &outbuf)) {
				goto full;
			}
		}
		h1s->flags |= H1S_F_HAVE_WS_KEY;
	}

	/*
	 * All  headers was sent, now process EOH
	 */
	if (!(h1m->flags & H1_MF_RESP) && h1s->meth == HTTP_METH_CONNECT) {
		if (!chunk_memcat(&outbuf, "\r\n", 2))
			goto full;
		/* a CONNECT request was sent. Output processing is now blocked
		 * waiting the server response.
		 */
		h1m->state = H1_MSG_DONE;
		h1s->flags |= H1S_F_TX_BLK;
		TRACE_STATE("CONNECT request waiting for tunnel mode", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	}
	else if ((h1m->flags & H1_MF_RESP) &&
		 ((h1s->meth == HTTP_METH_CONNECT && h1s->status >= 200 && h1s->status < 300) || h1s->status == 101)) {
		if (!chunk_memcat(&outbuf, "\r\n", 2))
			goto full;
		/* a successful reply to a CONNECT or a protocol switching is sent
		 * to the client. Switch the response to tunnel mode.
		 */
		h1_set_tunnel_mode(h1s);
	}
	else if ((h1m->flags & H1_MF_RESP) &&
		 h1s->status < 200 && (h1s->status == 100 || h1s->status >= 102)) {
		if (!chunk_memcat(&outbuf, "\r\n", 2))
			goto full;
		/* 1xx response was sent, reset response processing */
		h1m_init_res(h1m);
		h1m->flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);
		h1s->flags &= ~H1S_F_HAVE_O_CONN;
		TRACE_STATE("1xx response xferred", H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);
	}
	else if (htx_is_unique_blk(htx, blk) &&
		 ((htx->flags & HTX_FL_EOM) || ((h1m->flags & H1_MF_CLEN) && !h1m->curr_len))) {
		/* EOM flag is set and it is the last block or there is no
		 * payload. If cannot be removed now. We must emit the end of
		 * the message first to be sure the output buffer is not full
		 */
		if ((h1m->flags & H1_MF_CHNK) && !(h1s->flags & H1S_F_BODYLESS_RESP)) {
			if (!chunk_memcat(&outbuf, "\r\n0\r\n\r\n", 7))
				goto full;
		}
		else if (!chunk_memcat(&outbuf, "\r\n", 2))
			goto full;
		h1m->state = ((htx->flags & HTX_FL_EOM) ? H1_MSG_DONE : H1_MSG_TRAILERS);
	}
	else {
		if (!chunk_memcat(&outbuf, "\r\n", 2))
			goto full;
		h1m->state = ((h1m->flags & H1_MF_CHNK) ? H1_MSG_CHUNK_SIZE: H1_MSG_DATA);
	}

	TRACE_PROTO((!(h1m->flags & H1_MF_RESP) ? "H1 request headers xferred" : "H1 response headers xferred"),
		    H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s);
	ret += sz;
	htx_remove_blk(htx, blk);

  copy:
	b_add(&h1c->obuf, outbuf.data);
  end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_HDRS, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;

   full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto copy;

  error:
	htx->flags |= HTX_FL_PROCESSING_ERROR;
	h1s->flags |= H1S_F_PROCESSING_ERROR;
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_ERROR("processing error on message EOH",
		    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	goto end;
}

/* Try to send the message payload from the HTX message <htx> for the stream
 * <h1s>. In this case, we are not in TUNNEL mode. It returns the number of
 * bytes consumed or zero if nothing was done or if an error occurred. No more
 * than <count> bytes can be sent.
 */
static size_t h1_make_data(struct h1s *h1s, struct h1m *h1m, struct buffer *buf, size_t count)
{
	struct h1c *h1c = h1s->h1c;
	struct htx *htx = htx_from_buf(buf);
	struct htx_blk *blk;
	struct buffer outbuf;
	enum htx_blk_type type;
	struct ist v;
	uint32_t sz;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, htx, (size_t[]){count});
	blk = htx_get_head_blk(htx);

	/* Perform some optimizations to reduce the number of buffer copies.  If
	 * the mux's buffer is empty and the htx area contains exactly one data
	 * block of the same size as the requested count, then it's possible to
	 * simply swap the caller's buffer with the mux's output buffer and
	 * adjust offsets and length to match the entire DATA HTX block in the
	 * middle. In this case we perform a true zero-copy operation from
	 * end-to-end. This is the situation that happens all the time with
	 * large files.
	 */
	if (((!(h1m->flags & H1_MF_RESP) && !(h1s->flags & H1S_F_BODYLESS_REQ)) ||
	     ((h1m->flags & H1_MF_RESP) && !(h1s->flags & H1S_F_BODYLESS_RESP))) &&
	    !b_data(&h1c->obuf) &&
	    (!(h1m->flags & H1_MF_CHNK) || ((h1m->flags & H1_MF_CHNK) && (!h1m->curr_len || count == h1m->curr_len))) &&
	    htx_nbblks(htx) == 1 &&
	    htx_get_blk_type(blk) == HTX_BLK_DATA &&
	    htx_get_blk_value(htx, blk).len == count) {
		void *old_area;
		uint64_t extra;
		int eom = (htx->flags & HTX_FL_EOM);

		extra = htx->extra;
		old_area = h1c->obuf.area;
		h1c->obuf.area = buf->area;
		h1c->obuf.head = sizeof(struct htx) + blk->addr;
		h1c->obuf.data = count;

		buf->area = old_area;
		buf->data = buf->head = 0;

		htx = (struct htx *)buf->area;
		htx_reset(htx);
		htx->extra = extra;

		if (h1m->flags & H1_MF_CLEN) {
			if (count > h1m->curr_len) {
				COUNT_IF(1, "more payload than announced (0-copy)");
				TRACE_ERROR("more payload than announced",
					    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
				goto error;
			}
			h1m->curr_len -= count;
			if (!h1m->curr_len)
				h1m->state = (eom ? H1_MSG_DONE : H1_MSG_TRAILERS);
		}
		else if (h1m->flags & H1_MF_CHNK) {
			/* The message is chunked. We need to check if we must
			 * emit the chunk size, the CRLF marking the end of the
			 * current chunk and eventually the CRLF marking the end
			 * of the previous chunk (because of fast-forwarding).
			 * If it is the end of the message, we must
			 * also emit the last chunk.
			 *
			 *  We have at least the size of the struct htx to write
			 * the chunk envelope. It should be enough.
			 */

			/* If is a new chunk, prepend the chunk size */
			if (h1m->state == H1_MSG_CHUNK_CRLF || h1m->state == H1_MSG_CHUNK_SIZE) {
				if (h1m->curr_len) {
					COUNT_IF(1, "chunk bigger than announced (0-copy)");
					TRACE_ERROR("chunk bigger than announced",
						    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
					goto error;
				}
				h1m->curr_len = count + (htx->extra != HTX_UNKOWN_PAYLOAD_LENGTH ? htx->extra : 0);

				/* Because chunk meta-data are prepended, the chunk size of the current chunk
				 * must be handled before the end of the previous chunk.
				 */
				h1_prepend_chunk_size(&h1c->obuf, h1m->curr_len, 0);
				if (h1m->state == H1_MSG_CHUNK_CRLF)
					h1_prepend_chunk_crlf(&h1c->obuf);

				h1m->state = H1_MSG_DATA;
			}

			h1m->curr_len -= count;

			/* It is the end  of the chunk, append the CRLF */
			if (!h1m->curr_len) {
				h1_append_chunk_crlf(&h1c->obuf);
				h1m->state = H1_MSG_CHUNK_SIZE;
			}

			/* It is the end of the message, add the last chunk with the extra CRLF */
			if (eom) {
				if (h1m->curr_len) {
					COUNT_IF(1, "chunk smaller than announced (0-copy)");
					TRACE_ERROR("chunk smaller than announced",
						    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
					goto error;
				}
				/* Emit the last chunk too at the buffer's end */
				b_putblk(&h1c->obuf, "0\r\n\r\n", 5);
				h1m->state = H1_MSG_DONE;
			}
		}
		/* Nothing to do if XFER len is unknown */

		ret = count;
		TRACE_PROTO("H1 message payload data xferred (zero-copy)", H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, 0, (size_t[]){ret});
		goto end;
	}

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);


	/* Handle now case of CRLF at the end of a chun. */
	if ((h1m->flags & H1_MF_CHNK) && h1m->state == H1_MSG_CHUNK_CRLF) {
		if (h1m->curr_len) {
			COUNT_IF(1, "chunk bigger than announced");
			TRACE_ERROR("chunk bigger than announced",
				    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
			goto error;
		}
		if (!chunk_memcat(&outbuf, "\r\n", 2))
			goto full;
		h1m->state = H1_MSG_CHUNK_SIZE;
	}

	while (blk && count) {
                uint32_t vlen, chklen;
		int last_data = 0;

		type = htx_get_blk_type(blk);
		sz = htx_get_blksz(blk);
                vlen = sz;
		if (type == HTX_BLK_DATA) {
			if (vlen > count) {
				/* Get the maximum amount of data we can xferred */
				vlen = count;
			}
			else if (htx_is_unique_blk(htx, blk) && (htx->flags & HTX_FL_EOM)) {
				/* It is the last block of this message. After this one,
				 * only tunneled data may be forwarded. */
				TRACE_DEVEL("last message block", H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s);
				last_data = 1;
			}

			if ((!(h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_REQ)) ||
			    ((h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_RESP))) {
				TRACE_PROTO("Skip data for bodyless message", H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, htx);
				goto nextblk;
			}

			chklen = 0;
			if (h1m->flags & H1_MF_CHNK) {
				/* If is a new chunk, prepend the chunk size */
				if (h1m->state == H1_MSG_CHUNK_SIZE) {
					h1m->curr_len = (htx->extra && htx->extra != HTX_UNKOWN_PAYLOAD_LENGTH ? htx->data + htx->extra : vlen);
					if (!h1_append_chunk_size(&outbuf, h1m->curr_len)) {
						h1m->curr_len = 0;
						goto full;
					}
					h1m->state = H1_MSG_DATA;
				}

				if (vlen > h1m->curr_len) {
					vlen = h1m->curr_len;
					last_data = 0;
				}

				chklen = 0;
				if (h1m->curr_len == vlen)
					chklen += 2;
				if (last_data)
					chklen += 5;
			}

			if (vlen + chklen > b_room(&outbuf)) {
				/* too large for the buffer */
				if (chklen >= b_room(&outbuf))
					goto full;
				vlen = b_room(&outbuf) - chklen;
				last_data = 0;
			}

			v = htx_get_blk_value(htx, blk);
			v.len = vlen;
			if (!h1_format_htx_data(v, &outbuf, 0))
				goto full;

			if (h1m->flags & H1_MF_CLEN) {
				if (vlen > h1m->curr_len) {
					COUNT_IF(1, "more payload than announced");
					TRACE_ERROR("more payload than announced",
						    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
					goto error;
				}
				h1m->curr_len -= vlen;
			}
			else if (h1m->flags & H1_MF_CHNK) {
				h1m->curr_len -= vlen;
				/* Space already reserved, so it must succeed */
				if (!h1m->curr_len) {
					if (!chunk_memcat(&outbuf, "\r\n", 2))
						goto error;
					h1m->state = H1_MSG_CHUNK_SIZE;
				}
				if (last_data) {
					if (h1m->curr_len) {
						COUNT_IF(1, "chunk smaller than announced");
						TRACE_ERROR("chunk smaller than announced",
							    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
						goto error;
					}
					if (!chunk_memcat(&outbuf, "0\r\n\r\n", 5))
						goto error;
				}
			}


		}
		else if (type == HTX_BLK_EOT || type == HTX_BLK_TLR) {
			if ((!(h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_REQ)) ||
			    ((h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_RESP))) {
				/* Do nothing the payload must be skipped
				 * because it is a bodyless response
				 */
			}
			else if (h1m->flags & H1_MF_CHNK) {
				/* Emit last chunk for chunked messages only */
				if (!chunk_memcat(&outbuf, "0\r\n", 3))
                                        goto full;
			}
			h1m->state = H1_MSG_TRAILERS;
			break;
		}
		else if (type == HTX_BLK_UNUSED)
			goto nextblk;
		else
			goto error;

	nextblk:
		ret += vlen;
		count -= vlen;
		if (sz == vlen)
			blk = htx_remove_blk(htx, blk);
		else {
			htx_cut_data_blk(htx, blk, vlen);
			if (!b_room(&outbuf))
				goto full;
		}

		if (last_data)
			h1m->state = H1_MSG_DONE;
	}

  copy:
	TRACE_PROTO("H1 message payload data xferred", H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, 0, (size_t[]){ret});
	b_add(&h1c->obuf, outbuf.data);
  end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;
  full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto copy;
  error:
	ret = 0;
	htx->flags |= HTX_FL_PROCESSING_ERROR;
	h1s->flags |= H1S_F_PROCESSING_ERROR;
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_ERROR("processing error on message payload",
		    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	goto end;
}

/* Try to send the tunneled data from the HTX message <htx> for the stream
 * <h1s>. In this case, we are in TUNNEL mode. It returns the number of bytes
 * consumed or zero if nothing was done or if an error occurred. No more than
 * <count> bytes can be sent.
 */
static size_t h1_make_tunnel(struct h1s *h1s, struct h1m *h1m, struct buffer *buf, size_t count)
{
	struct h1c *h1c = h1s->h1c;
	struct htx *htx = htx_from_buf(buf);
	struct htx_blk *blk;
	struct buffer outbuf;
	enum htx_blk_type type;
	struct ist v;
	uint32_t sz;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, htx, (size_t[]){count});

	blk = htx_get_head_blk(htx);

	/* Perform some optimizations to reduce the number of buffer copies.  If
	 * the mux's buffer is empty and the htx area contains exactly one data
	 * block of the same size as the requested count, then it's possible to
	 * simply swap the caller's buffer with the mux's output buffer and
	 * adjust offsets and length to match the entire DATA HTX block in the
	 * middle. In this case we perform a true zero-copy operation from
	 * end-to-end. This is the situation that happens all the time with
	 * large files.
	 */
	if (!b_data(&h1c->obuf) &&
	    htx_nbblks(htx) == 1 &&
	    htx_get_blk_type(blk) == HTX_BLK_DATA &&
	    htx_get_blksz(blk) == count) {
		void *old_area;

		old_area = h1c->obuf.area;
		h1c->obuf.area = buf->area;
		h1c->obuf.head = sizeof(struct htx) + blk->addr;
		h1c->obuf.data = count;

		buf->area = old_area;
		buf->data = buf->head = 0;

		htx = (struct htx *)buf->area;
		htx_reset(htx);

		ret = count;
		TRACE_PROTO("H1 tunneled data xferred (zero-copy)", H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, 0, (size_t[]){ret});
		goto end;
	}

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);

	while (blk) {
		uint32_t vlen;

		type = htx_get_blk_type(blk);
		sz = htx_get_blksz(blk);
		vlen = sz;

		if (type == HTX_BLK_DATA) {
			if (vlen > count) {
				/* Get the maximum amount of data we can xferred */
				vlen = count;
			}

			if (vlen > b_room(&outbuf)) {
				/* too large for the buffer */
				vlen = b_room(&outbuf);
			}

			v = htx_get_blk_value(htx, blk);
			v.len = vlen;
			if (!h1_format_htx_data(v, &outbuf, 0))
				goto full;
		}
		else if (type == HTX_BLK_UNUSED)
			goto nextblk;
		else
			goto error;

	  nextblk:
		ret += vlen;
		count -= vlen;
		if (sz == vlen)
			blk = htx_remove_blk(htx, blk);
		else {
			htx_cut_data_blk(htx, blk, vlen);
                        break;
		}
	}

  copy:
	TRACE_PROTO("H1 tunneled data xferred", H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, 0, (size_t[]){ret});
	b_add(&h1c->obuf, outbuf.data);

  end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;

  full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto copy;

  error:
	ret = 0;
	htx->flags |= HTX_FL_PROCESSING_ERROR;
	h1s->flags |= H1S_F_PROCESSING_ERROR;
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_ERROR("processing error on tunneled",
		    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	goto end;
}

/* Try to send the trailers from the HTX message <htx> for the stream <h1s>. It
 * returns the number of bytes consumed or zero if nothing was done or if an
 * error occurred. No more than <count> bytes can be sent.
 */
static size_t h1_make_trailers(struct h1s *h1s, struct h1m *h1m, struct htx *htx, size_t count)
{
	struct h1c *h1c = h1s->h1c;
	struct htx_blk *blk;
	struct buffer outbuf;
	enum htx_blk_type type;
	struct ist n, v;
	uint32_t sz;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_TLRS, h1c->conn, h1s, htx, (size_t[]){count});

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	chunk_reset(&outbuf);
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);

	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		sz = htx_get_blksz(blk);

		if (type == HTX_BLK_TLR) {
			if (sz > count)
				goto error;

			if (!(h1m->flags & H1_MF_CHNK) ||
			    (!(h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_REQ)) ||
			    ((h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_RESP)))
				goto nextblk;

			n = htx_get_blk_name(htx, blk);
			v = htx_get_blk_value(htx, blk);

			/* Try to adjust the case of the header name */
			if (h1c->px->options2 & (PR_O2_H1_ADJ_BUGCLI|PR_O2_H1_ADJ_BUGSRV))
				h1_adjust_case_outgoing_hdr(h1s, h1m, &n);
			if (!h1_format_htx_hdr(n, v, &outbuf))
				goto full;
		}
		else if (type == HTX_BLK_EOT) {
			if (!(h1m->flags & H1_MF_CHNK) ||
			    (!(h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_REQ)) ||
			    ((h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_RESP))) {
				TRACE_PROTO((!(h1m->flags & H1_MF_RESP) ? "H1 request trailers skipped" : "H1 response trailers skipped"),
					    H1_EV_TX_DATA|H1_EV_TX_TLRS, h1c->conn, h1s);
			}
			else {
				if (!chunk_memcat(&outbuf, "\r\n", 2))
					goto full;
				TRACE_PROTO((!(h1m->flags & H1_MF_RESP) ? "H1 request trailers xferred" : "H1 response trailers xferred"),
					    H1_EV_TX_DATA|H1_EV_TX_TLRS, h1c->conn, h1s);
			}
			h1m->state = H1_MSG_DONE;
		}
		else if (type == HTX_BLK_UNUSED)
			goto nextblk;
		else
			goto error;

	  nextblk:
		ret += sz;
		count -= sz;
		blk = htx_remove_blk(htx, blk);
	}

  copy:
	b_add(&h1c->obuf, outbuf.data);

  end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_TLRS, h1c->conn, h1s, htx, (size_t[]){ret});
	return ret;

  full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto copy;

  error:
	ret = 0;
	htx->flags |= HTX_FL_PROCESSING_ERROR;
	h1s->flags |= H1S_F_PROCESSING_ERROR;
	se_fl_set(h1s->sd, SE_FL_ERROR);
	TRACE_ERROR("processing error on message trailers",
		    H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	goto end;
}

/* Try to send the header for a chunk of <len> bytes. It returns the number of
 * bytes consumed or zero if nothing was done or if an error occurred..
 */
static size_t h1_make_chunk(struct h1s *h1s, struct h1m * h1m, size_t len)
{
	struct h1c *h1c = h1s->h1c;
	struct buffer outbuf;
	size_t ret = 0;

	TRACE_ENTER(H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s);

	if (!h1_get_obuf(h1c)) {
		TRACE_STATE("waiting for h1c obuf allocation", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
		goto end;
	}

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));
	outbuf = b_make(b_tail(&h1c->obuf), b_contig_space(&h1c->obuf), 0, 0);

	if (h1m->state == H1_MSG_CHUNK_CRLF) {
		if (!chunk_memcat(&outbuf, "\r\n", 2))
			goto full;
		h1m->state = H1_MSG_CHUNK_SIZE;
	}
	if (!h1_append_chunk_size(&outbuf, len))
		goto full;

	h1m->state = H1_MSG_DATA;

	TRACE_PROTO("H1 chunk info xferred", H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, 0, (size_t[]){ret});
	b_add(&h1c->obuf, outbuf.data);
	ret = outbuf.data;

end:
	TRACE_LEAVE(H1_EV_TX_DATA|H1_EV_TX_BODY, h1c->conn, h1s, NULL, (size_t[]){ret});
	return ret;
full:
	TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
	h1c->flags |= H1C_F_OUT_FULL;
	goto end;
}

/*
 * Process outgoing data. It parses data and transfer them from the channel buffer into
 * h1c->obuf. It returns the number of bytes parsed and transferred if > 0, or
 * 0 if it couldn't proceed.
 */
static size_t h1_process_mux(struct h1c *h1c, struct buffer *buf, size_t count)
{
	struct h1s *h1s = h1c->h1s;
	struct h1m *h1m;
	struct htx *htx;
	size_t ret, total = 0;

	htx = htxbuf(buf);
	TRACE_ENTER(H1_EV_TX_DATA, h1c->conn, h1s, htx, (size_t[]){count});

	if (htx_is_empty(htx))
		goto end;

	if (h1s->flags & (H1S_F_MUX_ERROR|H1S_F_TX_BLK))
		goto end;

	if (!h1_get_obuf(h1c)) {
		TRACE_STATE("waiting for h1c obuf allocation", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
		goto end;
	}
	h1m = (!(h1c->flags & H1C_F_IS_BACK) ? &h1s->res : &h1s->req);

	while (!(h1c->flags & H1C_F_OUT_FULL) &&
	       !(h1s->flags & (H1S_F_MUX_ERROR|H1S_F_TX_BLK)) &&
	       !htx_is_empty(htx) && count) {
		switch (h1m->state) {
			case H1_MSG_RQBEFORE:
				ret = h1_make_reqline(h1s, h1m, htx, count);
				break;

			case H1_MSG_RPBEFORE:
				ret = h1_make_stline(h1s, h1m, htx, count);
				break;

			case H1_MSG_HDR_NAME:
				ret = h1_make_headers(h1s, h1m, htx, count);
				if (unlikely(h1m->state == H1_MSG_LAST_LF)) // in case of no header
					ret += h1_make_eoh(h1s, h1m, htx, count);
				break;

			case H1_MSG_LAST_LF:
				ret = h1_make_eoh(h1s, h1m, htx, count);
				break;

			case H1_MSG_CHUNK_SIZE:
			case H1_MSG_CHUNK_CRLF:
			case H1_MSG_DATA:
				ret = h1_make_data(h1s, h1m, buf, count);
				if (ret > 0)
					htx = htx_from_buf(buf);
				if (unlikely(h1m->state == H1_MSG_TRAILERS)) // in case of no data
					ret += h1_make_trailers(h1s, h1m, htx, count);
				break;

			case H1_MSG_TUNNEL:
				ret = h1_make_tunnel(h1s, h1m, buf, count);
				if (ret > 0)
					htx = htx_from_buf(buf);
				break;

			case H1_MSG_TRAILERS:
				ret = h1_make_trailers(h1s, h1m, htx, count);
				break;

			case H1_MSG_DONE:
				TRACE_STATE("unexpected data xferred in done state", H1_EV_TX_DATA|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
				__fallthrough;

			default:
				ret = 0;
				htx->flags |= HTX_FL_PROCESSING_ERROR;
				h1s->flags |= H1S_F_PROCESSING_ERROR;
				se_fl_set(h1s->sd, SE_FL_ERROR);
				COUNT_IF(1, "processing error during message formatting");
				TRACE_ERROR("processing error", H1_EV_TX_DATA|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
				break;
		}

		if (!ret)
                        break;
		total += ret;
		count -= ret;

		if (h1m->state == H1_MSG_DONE) {
			TRACE_USER((!(h1m->flags & H1_MF_RESP) ? "H1 request fully xferred" : "H1 response fully xferred"),
				   H1_EV_TX_DATA, h1c->conn, h1s);

			if (h1s->flags & H1S_F_RX_BLK) {
				h1s->flags &= ~H1S_F_RX_BLK;
				h1_wake_stream_for_recv(h1s);
				TRACE_STATE("Re-enable input processing", H1_EV_TX_DATA|H1_EV_H1S_BLK|H1_EV_STRM_WAKE, h1c->conn, h1s);
			}
		}
	}

	htx_to_buf(htx, buf);
	if (!buf_room_for_htx_data(&h1c->obuf)) {
		TRACE_STATE("h1c obuf full", H1_EV_TX_DATA|H1_EV_H1S_BLK, h1c->conn, h1s);
		h1c->flags |= H1C_F_OUT_FULL;
	}

	if (h1s->flags & H1S_F_MUX_ERROR) {
		if (h1s->flags & H1S_F_PROCESSING_ERROR)
			se_report_term_evt(h1s->sd, se_tevt_type_proto_err);
		else
			se_report_term_evt(h1s->sd, se_tevt_type_internal_err);
	}
  end:

	/* Both the request and the response reached the DONE state. So set EOI
	 * flag on the conn-stream. Most of time, the flag will already be set,
	 * except for protocol upgrades. Report an error if data remains blocked
	 * in the output buffer.
	 */
	if (h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE) {
		se_fl_set(h1s->sd, SE_FL_EOI);
		if (!htx_is_empty(htx)) {
			htx->flags |= HTX_FL_PROCESSING_ERROR;
			h1s->flags |= H1S_F_PROCESSING_ERROR;
			se_fl_set(h1s->sd, SE_FL_ERROR);
			h1c_report_term_evt(h1c, muxc_tevt_type_proto_err);
			TRACE_ERROR("txn done but data waiting to be sent, set error on h1c", H1_EV_H1C_ERR, h1c->conn, h1s);
		}
	}

	TRACE_LEAVE(H1_EV_TX_DATA, h1c->conn, h1s, htx, (size_t[]){total});
	return total;
}

/*********************************************************/
/* functions below are I/O callbacks from the connection */
/*********************************************************/
static void h1_wake_stream_for_recv(struct h1s *h1s)
{
	if (h1s && h1s->subs && h1s->subs->events & SUB_RETRY_RECV) {
		TRACE_POINT(H1_EV_STRM_WAKE, h1s->h1c->conn, h1s);
		tasklet_wakeup(h1s->subs->tasklet);
		h1s->subs->events &= ~SUB_RETRY_RECV;
		if (!h1s->subs->events)
			h1s->subs = NULL;
	}
}
static void h1_wake_stream_for_send(struct h1s *h1s)
{
	if (h1s && h1s->subs && h1s->subs->events & SUB_RETRY_SEND) {
		TRACE_POINT(H1_EV_STRM_WAKE, h1s->h1c->conn, h1s);
		tasklet_wakeup(h1s->subs->tasklet);
		h1s->subs->events &= ~SUB_RETRY_SEND;
		if (!h1s->subs->events)
			h1s->subs = NULL;
	}
}

/* alerts the data layer following this sequence :
 *   - if the h1s' data layer is subscribed to recv, then it's woken up for recv
 *   - if its subscribed to send, then it's woken up for send
 *   - if it was subscribed to neither, its ->wake() callback is called
 */
static void h1_alert(struct h1s *h1s)
{
	if (h1s->subs) {
		h1_wake_stream_for_recv(h1s);
		h1_wake_stream_for_send(h1s);
	}
	else if (h1s_sc(h1s) && h1s_sc(h1s)->app_ops->wake != NULL) {
		TRACE_POINT(H1_EV_STRM_WAKE, h1s->h1c->conn, h1s);
		h1s_sc(h1s)->app_ops->wake(h1s_sc(h1s));
	}
}

/* Try to send an HTTP error with h1c->errcode status code. It returns 1 on success
 * and 0 on error. The flag H1C_F_ABRT_PENDING is set on the H1 connection for
 * retryable errors (allocation error or buffer full). On success, the error is
 * copied in the output buffer.
*/
static int h1_send_error(struct h1c *h1c)
{
	int rc = http_get_status_idx(h1c->errcode);
	int ret = 0;

	TRACE_ENTER(H1_EV_H1C_ERR, h1c->conn, 0, 0, (size_t[]){h1c->errcode});

	/* Verify if the error is mapped on /dev/null or any empty file */
	/// XXX: do a function !
	if (h1c->px->replies[rc] &&
	    h1c->px->replies[rc]->type == HTTP_REPLY_ERRMSG &&
	    h1c->px->replies[rc]->body.errmsg &&
	    b_is_null(h1c->px->replies[rc]->body.errmsg)) {
		/* Empty error, so claim a success */
		ret = 1;
		goto out_abort;
	}

	if (h1c->flags & (H1C_F_OUT_ALLOC|H1C_F_OUT_FULL)) {
		h1c->flags |= H1C_F_ABRT_PENDING;
		goto out;
	}

	if (!h1_get_obuf(h1c)) {
		h1c->flags |= H1C_F_ABRT_PENDING;
		TRACE_STATE("waiting for h1c obuf allocation", H1_EV_H1C_ERR|H1_EV_H1C_BLK, h1c->conn);
		goto out;
	}
	ret = b_istput(&h1c->obuf, ist(http_err_msgs[rc]));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			h1c->flags |= (H1C_F_OUT_FULL|H1C_F_ABRT_PENDING);
			TRACE_STATE("h1c obuf full", H1_EV_H1C_ERR|H1_EV_H1C_BLK, h1c->conn);
			goto out;
		}
		else {
			/* we cannot report this error, so claim a success */
			ret = 1;
		}
	}

	if (h1c->state == H1_CS_EMBRYONIC) {
		BUG_ON(h1c->h1s == NULL || h1s_sc(h1c->h1s) != NULL);
		TRACE_DEVEL("Abort embryonic H1S", H1_EV_H1C_ERR, h1c->conn, h1c->h1s);
		h1s_destroy(h1c->h1s);
	}

  out_abort:
	h1c->flags = (h1c->flags & ~(H1C_F_WAIT_NEXT_REQ|H1C_F_ABRT_PENDING)) | H1C_F_ABRTED;
	h1_close(h1c);
  out:
	TRACE_LEAVE(H1_EV_H1C_ERR, h1c->conn);
	return ret;
}

/* Try to send a 500 internal error. It relies on h1_send_error to send the
 * error. This function takes care of incrementing stats and tracked counters.
 */
static int h1_handle_internal_err(struct h1c *h1c)
{
	struct session *sess = h1c->conn->owner;
	int ret = 0;

	if (h1c->state == H1_CS_DRAINING) {
		h1c->flags = (h1c->flags & ~H1C_F_WAIT_NEXT_REQ) | H1C_F_ABRTED;
		h1s_destroy(h1c->h1s);
		goto end;
	}
	session_inc_http_req_ctr(sess);
	proxy_inc_fe_req_ctr(sess->listener, sess->fe, 1);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.p.http.rsp[5]);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);

	h1c->errcode = 500;
	ret = h1_send_error(h1c);
	sess_log(sess);
  end:
	return ret;
}

/* Try to send an error because of a parsing error. By default a 400 bad request
 * error is returned. But the status code may be specified by setting
 * h1c->errcode. It relies on h1_send_error to send the error. This function
 * takes care of incrementing stats and tracked counters.
 */
static int h1_handle_parsing_error(struct h1c *h1c)
{
	struct session *sess = h1c->conn->owner;
	int ret = 0;

	if (h1c->state == H1_CS_DRAINING) {
		h1c->flags = (h1c->flags & ~H1C_F_WAIT_NEXT_REQ) | H1C_F_ABRTED;
		h1s_destroy(h1c->h1s);
		goto end;
	}
	if (!b_data(&h1c->ibuf) && ((h1c->flags & H1C_F_WAIT_NEXT_REQ) || (sess->fe->options & PR_O_IGNORE_PRB))) {
		h1c->flags = (h1c->flags & ~H1C_F_WAIT_NEXT_REQ) | H1C_F_ABRTED;
		h1_close(h1c);
		goto end;
	}

	session_inc_http_req_ctr(sess);
	session_inc_http_err_ctr(sess);
	proxy_inc_fe_req_ctr(sess->listener, sess->fe, 1);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.p.http.rsp[4]);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);

	if (!h1c->errcode)
		h1c->errcode = 400;
	ret = h1_send_error(h1c);
	if (b_data(&h1c->ibuf) || !(sess->fe->options & PR_O_NULLNOLOG))
		sess_log(sess);

  end:
	return ret;
}

/* Try to send a 501 not implemented error. It relies on h1_send_error to send
 * the error. This function takes care of incrementing stats and tracked
 * counters.
 */
static int h1_handle_not_impl_err(struct h1c *h1c)
{
	struct session *sess = h1c->conn->owner;
	int ret = 0;

	if (h1c->state == H1_CS_DRAINING) {
		h1c->flags = (h1c->flags & ~H1C_F_WAIT_NEXT_REQ) | H1C_F_ABRTED;
		h1s_destroy(h1c->h1s);
		goto end;
	}
	if (!b_data(&h1c->ibuf) && ((h1c->flags & H1C_F_WAIT_NEXT_REQ) || (sess->fe->options & PR_O_IGNORE_PRB))) {
		h1c->flags = (h1c->flags & ~H1C_F_WAIT_NEXT_REQ) | H1C_F_ABRTED;
		h1_close(h1c);
		goto end;
	}

	session_inc_http_req_ctr(sess);
	proxy_inc_fe_req_ctr(sess->listener, sess->fe, 1);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.p.http.rsp[4]);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);

	h1c->errcode = 501;
	ret = h1_send_error(h1c);
	if (b_data(&h1c->ibuf) || !(sess->fe->options & PR_O_NULLNOLOG))
		sess_log(sess);

  end:
	return ret;
}

/* Try to send a 408 timeout error. It relies on h1_send_error to send the
 * error. This function takes care of incrementing stats and tracked counters.
 */
static int h1_handle_req_tout(struct h1c *h1c)
{
	struct session *sess = h1c->conn->owner;
	int ret = 0;

	if (h1c->state == H1_CS_DRAINING) {
		h1c->flags = (h1c->flags & ~H1C_F_WAIT_NEXT_REQ) | H1C_F_ABRTED;
		h1s_destroy(h1c->h1s);
		goto end;
	}
	if (!b_data(&h1c->ibuf) && ((h1c->flags & H1C_F_WAIT_NEXT_REQ) || (sess->fe->options & PR_O_IGNORE_PRB))) {
		h1c->flags = (h1c->flags & ~H1C_F_WAIT_NEXT_REQ) | H1C_F_ABRTED;
		h1_close(h1c);
		goto end;
	}

	session_inc_http_req_ctr(sess);
	proxy_inc_fe_req_ctr(sess->listener, sess->fe, 1);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.p.http.rsp[4]);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);

	h1c->errcode = 408;
	ret = h1_send_error(h1c);
	if (b_data(&h1c->ibuf) || !(sess->fe->options & PR_O_NULLNOLOG))
		sess_log(sess);

  end:
	return ret;
}


/*
 * Attempt to read data, and subscribe if none available
 */
static int h1_recv(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	size_t ret = 0, max;
	int flags = 0;

	TRACE_ENTER(H1_EV_H1C_RECV, h1c->conn);

	if (h1c->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("leaving on sub_recv", H1_EV_H1C_RECV, h1c->conn);
		return (b_data(&h1c->ibuf));
	}

	if ((h1c->flags & H1C_F_WANT_FASTFWD) || !h1_recv_allowed(h1c)) {
		TRACE_DEVEL("leaving on (want_fastfwde|!recv_allowed)", H1_EV_H1C_RECV, h1c->conn);
		return 1;
	}

	if (!h1_get_ibuf(h1c)) {
		TRACE_STATE("waiting for h1c ibuf allocation", H1_EV_H1C_RECV|H1_EV_H1C_BLK, h1c->conn);
		return 0;
	}

	/*
	 * If we only have a small amount of data, realign it,
	 * it's probably cheaper than doing 2 recv() calls.
	 */
	if (b_data(&h1c->ibuf) > 0 && b_data(&h1c->ibuf) < 128)
		b_slow_realign_ofs(&h1c->ibuf, trash.area, sizeof(struct htx));

	max = buf_room_for_htx_data(&h1c->ibuf);

	/* avoid useless reads after first responses */
	if (!h1c->h1s ||
	    (!(h1c->flags & H1C_F_IS_BACK) && h1c->h1s->req.state == H1_MSG_RQBEFORE) ||
	    ((h1c->flags & H1C_F_IS_BACK) && h1c->h1s->res.state == H1_MSG_RPBEFORE)) {
		flags |= CO_RFL_READ_ONCE;

		/* we know that the first read will be constrained to a smaller
		 * read by the stream layer in order to respect the reserve.
		 * Reading too much will result in global.tune.maxrewrite being
		 * left at the end of the buffer, and in a very small read
		 * being performed again to complete them (typically 16 bytes
		 * freed in the index after headers were consumed) before
		 * another larger read. Instead, given that we know we're
		 * waiting for a header and we'll be limited, let's perform a
		 * shorter first read that the upper layer can retrieve by just
		 * a pointer swap and the next read will be doable at once in
		 * an empty buffer.
		 */
		if (max > global.tune.bufsize - global.tune.maxrewrite)
			max = global.tune.bufsize - global.tune.maxrewrite;
	}

	if (max) {
		if (h1c->flags & H1C_F_IN_FULL) {
			h1c->flags &= ~H1C_F_IN_FULL;
			TRACE_STATE("h1c ibuf not full anymore", H1_EV_H1C_RECV|H1_EV_H1C_BLK);
		}

		if (!b_data(&h1c->ibuf)) {
			/* try to pre-align the buffer like the rxbufs will be
			 * to optimize memory copies.
			 */
			h1c->ibuf.head  = sizeof(struct htx);
		}
		ret = conn->xprt->rcv_buf(conn, conn->xprt_ctx, &h1c->ibuf, max, flags);
		HA_ATOMIC_ADD(&h1c->px_counters->bytes_in, ret);
	}

	if (conn_xprt_read0_pending(conn)) {
		TRACE_DEVEL("read0 on connection", H1_EV_H1C_RECV, h1c->conn);
		h1c->flags |= H1C_F_EOS;
	}
	if (h1c->conn->flags & CO_FL_ERROR) {
		TRACE_DEVEL("connection error", H1_EV_H1C_RECV, h1c->conn);
		COUNT_IF(b_data(&h1c->obuf), "connection error (recv) with pending output data");
		h1c->flags |= H1C_F_ERROR;
	}

	if (max && !ret && h1_recv_allowed(h1c)) {
		TRACE_STATE("failed to receive data, subscribing", H1_EV_H1C_RECV, h1c->conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
	}
	else {
		TRACE_DATA("data received or pending or connection error", H1_EV_H1C_RECV, h1c->conn, 0, 0, (size_t[]){ret});
		h1_wake_stream_for_recv(h1c->h1s);
	}

	if (!b_data(&h1c->ibuf))
		h1_release_buf(h1c, &h1c->ibuf);
	else if (!buf_room_for_htx_data(&h1c->ibuf)) {
		h1c->flags |= H1C_F_IN_FULL;
		TRACE_STATE("h1c ibuf full", H1_EV_H1C_RECV|H1_EV_H1C_BLK);
	}

	TRACE_LEAVE(H1_EV_H1C_RECV, h1c->conn);
	return !!ret || (h1c->flags & (H1C_F_EOS|H1C_F_ERROR));
}


/*
 * Try to send data if possible
 */
static int h1_send(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	unsigned int flags = 0;
	size_t ret;
	int sent = 0;

	TRACE_ENTER(H1_EV_H1C_SEND, h1c->conn);

	if (h1c->flags & (H1C_F_ERROR|H1C_F_ERR_PENDING)) {
		TRACE_DEVEL("leaving on H1C error|err_pending", H1_EV_H1C_SEND, h1c->conn);
		COUNT_IF(b_data(&h1c->obuf), "connection error (send) with pending output data");
		b_reset(&h1c->obuf);
		if (h1c->flags & H1C_F_EOS)
			h1c->flags |= H1C_F_ERROR;
		goto end;
	}

	if (!b_data(&h1c->obuf))
		goto end;

	if (h1c->flags & H1C_F_CO_MSG_MORE)
		flags |= CO_SFL_MSG_MORE;
	if (h1c->flags & H1C_F_CO_STREAMER)
		flags |= CO_SFL_STREAMER;

	ret = conn->xprt->snd_buf(conn, conn->xprt_ctx, &h1c->obuf, b_data(&h1c->obuf), flags);
	if (ret > 0) {
		TRACE_DATA("data sent", H1_EV_H1C_SEND, h1c->conn, 0, 0, (size_t[]){ret});
		if (h1c->flags & H1C_F_OUT_FULL) {
			h1c->flags &= ~H1C_F_OUT_FULL;
			TRACE_STATE("h1c obuf not full anymore", H1_EV_STRM_SEND|H1_EV_H1S_BLK, h1c->conn);
		}
		HA_ATOMIC_ADD(&h1c->px_counters->bytes_out, ret);
		b_del(&h1c->obuf, ret);
		sent = 1;
	}

	if (conn->flags & CO_FL_ERROR) {
		/* connection error, nothing to send, clear the buffer to release it */
		TRACE_DEVEL("connection error", H1_EV_H1C_SEND, h1c->conn);
		COUNT_IF(b_data(&h1c->obuf), "connection error (send) with pending output data");
		h1c->flags |= H1C_F_ERR_PENDING;
		h1c_report_term_evt(h1c, muxc_tevt_type_snd_err);
		if (h1c->flags & H1C_F_EOS)
			h1c->flags |= H1C_F_ERROR;
		else if (!(h1c->wait_event.events & SUB_RETRY_RECV)) {
			/* EOS not seen, so subscribe for reads to be able to
			 * catch the error on the reading path. It is especially
			 * important if EOI was reached.
			 */
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		}
		b_reset(&h1c->obuf);
	}

  end:
	if (!(h1c->flags & (H1C_F_OUT_FULL|H1C_F_OUT_ALLOC)))
		h1_wake_stream_for_send(h1c->h1s);

	/* We're done, no more to send */
	if (!b_data(&h1c->obuf)) {
		TRACE_DEVEL("leaving with everything sent", H1_EV_H1C_SEND, h1c->conn);
		h1_release_buf(h1c, &h1c->obuf);
		if (h1c->state == H1_CS_CLOSING) {
			TRACE_STATE("process pending shutdown for writes", H1_EV_H1C_SEND, h1c->conn);
			h1_shutw_conn(conn);
		}
	}
	else if (!(h1c->wait_event.events & SUB_RETRY_SEND)) {
		TRACE_STATE("more data to send, subscribing", H1_EV_H1C_SEND, h1c->conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_SEND, &h1c->wait_event);
	}

	TRACE_LEAVE(H1_EV_H1C_SEND, h1c->conn);
	return sent || (h1c->flags & (H1C_F_ERR_PENDING|H1C_F_ERROR)) || (h1c->state == H1_CS_CLOSED);
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection.
 */
static int h1_process(struct h1c * h1c)
{
	struct connection *conn = h1c->conn;

	TRACE_ENTER(H1_EV_H1C_WAKE, conn);

	/* Try to parse now the first block of a request, creating the H1 stream if necessary */
	if (b_data(&h1c->ibuf) &&                                                /* Input data to be processed */
	    ((h1c->state < H1_CS_RUNNING) || (h1c->state == H1_CS_DRAINING)) &&  /* IDLE, EMBRYONIC, UPGRADING or DRAINING */
	    !(h1c->flags & (H1C_F_IN_SALLOC|H1C_F_ABRT_PENDING))) {              /* No allocation failure on the stream rxbuf and no ERROR on the H1C */
		struct h1s *h1s = h1c->h1s;
		struct buffer *buf;
		size_t count;

		/* When it happens for a backend connection, we may release it (it is probably a 408) */
		if (h1c->flags & H1C_F_IS_BACK)
			goto release;

		/* First of all handle H1 to H2 upgrade (no need to create the H1 stream) */
		if (h1c->state != H1_CS_DRAINING &&                /* Not draining message */
		    !(h1c->flags & H1C_F_WAIT_NEXT_REQ) &&         /* First request */
		    !(h1c->px->options2 & PR_O2_NO_H2_UPGRADE) &&  /* H2 upgrade supported by the proxy */
		    !(conn->mux->flags & MX_FL_NO_UPG)) {          /* the current mux supports upgrades */
			/* Try to match H2 preface before parsing the request headers. */
			if (b_isteq(&h1c->ibuf, 0, b_data(&h1c->ibuf), ist(H2_CONN_PREFACE)) > 0) {
				h1c->flags |= H1C_F_UPG_H2C;
				if (h1c->state == H1_CS_UPGRADING) {
					BUG_ON(!h1s);
					se_fl_set(h1s->sd, SE_FL_EOI|SE_FL_EOS); /* Set EOS here to release the SC */
				}
				TRACE_STATE("release h1c to perform H2 upgrade ", H1_EV_RX_DATA|H1_EV_H1C_WAKE);
				goto release;
			}
		}

		/* Create the H1 stream if not already there */
		if (!h1s) {
			h1s = h1c_frt_stream_new(h1c, NULL, h1c->conn->owner);
			if (!h1s) {
				b_reset(&h1c->ibuf);
				h1_handle_internal_err(h1c);
				TRACE_ERROR("alloc error", H1_EV_H1C_WAKE|H1_EV_H1C_ERR);
				goto no_parsing;
			}
		}

		if (h1s->sess->t_idle == -1)
			h1s->sess->t_idle = ns_to_ms(now_ns - h1s->sess->accept_ts) - h1s->sess->t_handshake;

		/* Get the stream rxbuf */
		buf = h1_get_rxbuf(h1s);
		if (!buf) {
			TRACE_STATE("waiting for stream rxbuf allocation", H1_EV_H1C_WAKE|H1_EV_H1C_BLK, h1c->conn);
			return 0;
		}

		count = (buf->size - sizeof(struct htx) - global.tune.maxrewrite);
		h1_process_demux(h1c, buf, count);
		h1_release_buf(h1c, &h1s->rxbuf);
		h1_set_idle_expiration(h1c);
		if (h1c->state != H1_CS_RUNNING) { // TODO: be sure state cannot change in h1_process_demux
			if (h1s->flags & H1S_F_INTERNAL_ERROR) {
				h1_handle_internal_err(h1c);
				TRACE_ERROR("internal error detected", H1_EV_H1C_WAKE|H1_EV_H1C_ERR);
			}
			else if (h1s->flags & H1S_F_NOT_IMPL_ERROR) {
				h1_handle_not_impl_err(h1c);
				TRACE_ERROR("not-implemented error detected", H1_EV_H1C_WAKE|H1_EV_H1C_ERR);
			}
			else if (h1s->flags & H1S_F_PARSING_ERROR || se_fl_test(h1s->sd, SE_FL_ERROR)) {
				h1_handle_parsing_error(h1c);
				TRACE_ERROR("parsing error detected", H1_EV_H1C_WAKE|H1_EV_H1C_ERR);
			}
			else {
				TRACE_STATE("Incomplete message, subscribing", H1_EV_RX_DATA|H1_EV_H1C_BLK|H1_EV_H1C_WAKE, h1c->conn, h1s);
				h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
			}
		}
	}

  no_parsing:
	h1_send(h1c);

	/* H1 connection must be released ASAP if:
	 *  - an error occurred on the H1C or
	 *  - a read0 was received or
	 *  - a silent shutdown was emitted and all outgoing data sent
	 */
	if ((h1c->flags & (H1C_F_EOS|H1C_F_ERROR|H1C_F_ABRT_PENDING|H1C_F_ABRTED)) ||
	    (h1c->state >= H1_CS_CLOSING && (h1c->flags & H1C_F_SILENT_SHUT) && !b_data(&h1c->obuf))) {
		if (h1c->state != H1_CS_RUNNING) {
			/* No stream connector or upgrading */
			if (h1c->state == H1_CS_IDLE)
				h1c_report_term_evt(h1c, ((h1c->flags & H1C_F_ERROR) ? muxc_tevt_type_rcv_err : muxc_tevt_type_shutr));

			if (h1c->state < H1_CS_RUNNING && !(h1c->flags & (H1C_F_IS_BACK|H1C_F_ABRT_PENDING))) {
				/* shutdown for reads and no error on the frontend connection: Send an error */
				if (h1_handle_parsing_error(h1c))
					h1_send(h1c);
			}
			else if (h1c->flags & H1C_F_ABRT_PENDING) {
				/* Handle pending error, if any (only possible on frontend connection) */
				BUG_ON(h1c->flags & H1C_F_IS_BACK);
				if (h1_send_error(h1c))
					h1_send(h1c);
			}
			else if (h1c->state == H1_CS_DRAINING) {
				BUG_ON(h1c->h1s->sd && !se_fl_test(h1c->h1s->sd, SE_FL_ORPHAN));
				h1s_destroy(h1c->h1s);
				TRACE_STATE("abort/error when draining message. destroy h1s and close h1c", H1_EV_H1S_END, h1c->conn);
			}
			else {
				h1_close(h1c);
				TRACE_STATE("close h1c", H1_EV_H1S_END, h1c->conn);
			}

			/* If there is some pending outgoing data or error, just wait */
			if (h1c->state == H1_CS_CLOSING || (h1c->flags & H1C_F_ABRT_PENDING))
				goto end;

			/* Otherwise we can release the H1 connection */
			goto release;
		}
		else {
			struct h1s *h1s = h1c->h1s;

			/* Here there is still a H1 stream with a stream connector.
			 * Report an error at the stream level and wake up the stream
			 */
			BUG_ON(!h1s);

			if (h1c->flags & (H1C_F_ERR_PENDING|H1C_F_ERROR)) {
				se_fl_set_error(h1s->sd);
				TRACE_STATE("report (ERR_PENDING|ERROR) to SE", H1_EV_H1C_RECV, conn, h1s);
			}
			TRACE_POINT(H1_EV_STRM_WAKE, h1c->conn, h1s);
			h1_alert(h1s);
		}
	}
	else if (h1c->state == H1_CS_DRAINING) {
		BUG_ON(!h1c->h1s);
		if (se_fl_test(h1c->h1s->sd, SE_FL_EOI)) {
			if (h1s_must_shut_conn(h1c->h1s)) {
				h1_shutw_conn(conn);
				goto release;
			}
			if (h1s_finish_detach(h1c->h1s) == -1)
				goto released;
		}
	}

	if (!b_data(&h1c->ibuf))
		h1_release_buf(h1c, &h1c->ibuf);

	/* Check if a soft-stop is in progress.
	 * Release idling front connection if this is the case.
	 */
	if (!(h1c->flags & H1C_F_IS_BACK)) {
		if (unlikely(h1c->px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
			if (!(h1c->px->options & PR_O_IDLE_CLOSE_RESP) &&
				h1c->flags & H1C_F_WAIT_NEXT_REQ) {

				int send_close = 1;
				/* If a close-spread-time option is set, we want to avoid
				 * closing all the active HTTP2 connections at once so we add a
				 * random factor that will spread the closing.
				 */
				if (tick_isset(global.close_spread_end)) {
					int remaining_window = tick_remain(now_ms, global.close_spread_end);
					if (remaining_window) {
						/* This should increase the closing rate the
						 * further along the window we are.
						 */
						send_close = (remaining_window <= statistical_prng_range(global.close_spread_time));
					}
				}
				else if (global.tune.options & GTUNE_DISABLE_ACTIVE_CLOSE)
					send_close = 0; /* let the client close his connection himself */
				if (send_close)
					goto release;
			}
		}
	}

	if (h1c->state >= H1_CS_RUNNING && (h1c->flags & H1C_F_WANT_FASTFWD) && !h1s_data_pending(h1c->h1s)) {
		TRACE_DEVEL("xprt rcv_buf blocked (want_fastfwd), notify h1s for recv", H1_EV_H1C_RECV, h1c->conn);
		h1_wake_stream_for_recv(h1c->h1s);
	}

  end:
	h1_refresh_timeout(h1c);
	TRACE_LEAVE(H1_EV_H1C_WAKE, conn);
	return 0;

  release:
	if (h1c->state == H1_CS_UPGRADING) {
		struct h1s *h1s = h1c->h1s;

		/* Don't release the H1 connection right now, we must destroy
		 * the attached SC first */
		BUG_ON(!h1s);

		if (h1c->flags & H1C_F_EOS) {
			se_fl_set(h1s->sd, SE_FL_EOI|SE_FL_EOS);
			TRACE_STATE("report EOS to SE", H1_EV_H1C_RECV, conn, h1s);
		}
		if (h1c->flags & (H1C_F_ERR_PENDING|H1C_F_ERROR)) {
			se_fl_set_error(h1s->sd);
			TRACE_STATE("report (ERR_PENDING|ERROR) to SE", H1_EV_H1C_RECV, conn, h1s);
		}
		h1_alert(h1s);
		TRACE_DEVEL("waiting to release the SC before releasing the connection", H1_EV_H1C_WAKE);
	}
	else {
		h1_release(h1c);
		TRACE_DEVEL("leaving after releasing the connection", H1_EV_H1C_WAKE);
	}
  released:
	return -1;
}

struct task *h1_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct connection *conn;
	struct tasklet *tl = (struct tasklet *)t;
	int conn_in_list;
	struct h1c *h1c = ctx;
	int ret = 0;

	if (state & TASK_F_USR1) {
		/* the tasklet was idling on an idle connection, it might have
		 * been stolen, let's be careful!
		 */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		if (tl->context == NULL) {
			/* The connection has been taken over by another thread,
			 * we're no longer responsible for it, so just free the
			 * tasklet, and do nothing.
			 */
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			tasklet_free(tl);
			return NULL;
		}
		conn = h1c->conn;
		TRACE_POINT(H1_EV_H1C_WAKE, conn);

		/* Remove the connection from the list, to be sure nobody attempts
		 * to use it while we handle the I/O events
		 */
		conn_in_list = conn->flags & CO_FL_LIST_MASK;
		if (conn_in_list)
			conn_delete_from_tree(conn);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	} else {
		/* we're certain the connection was not in an idle list */
		conn = h1c->conn;
		TRACE_ENTER(H1_EV_H1C_WAKE, conn);
		conn_in_list = 0;
	}

	if (!(h1c->wait_event.events & SUB_RETRY_SEND))
		ret = h1_send(h1c);
	if (!(h1c->wait_event.events & SUB_RETRY_RECV))
		ret |= h1_recv(h1c);
	if (ret || b_data(&h1c->ibuf))
		ret = h1_process(h1c);

	/* If we were in an idle list, we want to add it back into it,
	 * unless h1_process() returned -1, which mean it has destroyed
	 * the connection (testing !ret is enough, if h1_process() wasn't
	 * called then ret will be 0 anyway.
	 */
	if (ret < 0)
		t = NULL;

	if (!ret && conn_in_list) {
		struct server *srv = __objt_server(conn->target);

		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		_srv_add_idle(srv, conn, conn_in_list == CO_FL_SAFE_LIST);
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}
	return t;
}

static int h1_wake(struct connection *conn)
{
	struct h1c *h1c = conn->ctx;
	int ret;

	TRACE_POINT(H1_EV_H1C_WAKE, conn);

	h1_send(h1c);
	ret = h1_process(h1c);
	if (ret == 0) {
		struct h1s *h1s = h1c->h1s;

		if (h1c->state == H1_CS_UPGRADING || h1c->state == H1_CS_RUNNING)
			h1_alert(h1s);
	}
	return ret;
}

/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed.
 */
struct task *h1_timeout_task(struct task *t, void *context, unsigned int state)
{
	struct h1c *h1c = context;
	int expired = tick_is_expired(t->expire, now_ms);

	TRACE_ENTER(H1_EV_H1C_WAKE, h1c ? h1c->conn : NULL);

	if (h1c) {
		 /* Make sure nobody stole the connection from us */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

		/* Somebody already stole the connection from us, so we should not
		 * free it, we just have to free the task.
		 */
		if (!t->context) {
			h1c = NULL;
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			goto do_leave;
		}

		if (!expired) {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			TRACE_DEVEL("leaving (not expired)", H1_EV_H1C_WAKE, h1c->conn, h1c->h1s);
			return t;
		}

		/* If a stream connector is still attached and ready to the mux, wait for the
		 * stream's timeout
		 */
		if (h1c->state == H1_CS_RUNNING) {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			t->expire = TICK_ETERNITY;
			TRACE_DEVEL("leaving (SC still attached)", H1_EV_H1C_WAKE, h1c->conn, h1c->h1s);
			return t;
		}

		/* Try to send an error to the client */
		if (h1c->state != H1_CS_CLOSING && !(h1c->flags & (H1C_F_IS_BACK|H1C_F_ERROR|H1C_F_ABRT_PENDING))) {
			TRACE_DEVEL("timeout error detected", H1_EV_H1C_WAKE|H1_EV_H1C_ERR, h1c->conn, h1c->h1s);
			if (h1_handle_req_tout(h1c))
				h1_send(h1c);
			if (b_data(&h1c->obuf) || (h1c->flags & H1C_F_ABRT_PENDING)) {
				h1_refresh_timeout(h1c);
				HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
				return t;
			}
		}

		if (h1c->h1s && !se_fl_test(h1c->h1s->sd, SE_FL_ORPHAN)) {
			/* Don't release the H1 connection right now, we must destroy the
			 * attached SC first. */
			se_fl_set(h1c->h1s->sd, SE_FL_EOS | SE_FL_ERROR);
			h1_alert(h1c->h1s);
			h1_refresh_timeout(h1c);
			HA_SPIN_UNLOCK(OTHER_LOCK, &idle_conns[tid].idle_conns_lock);
			TRACE_DEVEL("waiting to release the SC before releasing the connection", H1_EV_H1C_WAKE);
			return t;
		}

		COUNT_IF(b_data(&h1c->ibuf), "H1C timed out with pending input data");
		COUNT_IF(b_data(&h1c->obuf), "H1C timed out with pending output data");

		/* We're about to destroy the connection, so make sure nobody attempts
		 * to steal it from us.
		 */
		if (h1c->conn->flags & CO_FL_LIST_MASK)
			conn_delete_from_tree(h1c->conn);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

		h1c_report_term_evt(h1c, muxc_tevt_type_tout);
	}

  do_leave:
	task_destroy(t);

	if (!h1c) {
		/* resources were already deleted */
		TRACE_DEVEL("leaving (not more h1c)", H1_EV_H1C_WAKE);
		return NULL;
	}

	h1c->task = NULL;
	h1_release(h1c);
	TRACE_LEAVE(H1_EV_H1C_WAKE);
	return NULL;
}

/*******************************************/
/* functions below are used by the streams */
/*******************************************/

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static int h1_attach(struct connection *conn, struct sedesc *sd, struct session *sess)
{
	struct h1c *h1c = conn->ctx;
	struct h1s *h1s;

	/* this connection is no more idle (if it was at all) */
	h1c->flags &= ~H1C_F_SILENT_SHUT;

	TRACE_ENTER(H1_EV_STRM_NEW, conn);
	if (h1c->flags & (H1C_F_ERR_PENDING|H1C_F_ERROR)) {
		TRACE_ERROR("h1c on error", H1_EV_STRM_NEW|H1_EV_STRM_END|H1_EV_STRM_ERR, conn);
		goto err;
	}

	h1s = h1c_bck_stream_new(h1c, sd->sc, sess);
	if (h1s == NULL) {
		TRACE_ERROR("h1s creation failure", H1_EV_STRM_NEW|H1_EV_STRM_END|H1_EV_STRM_ERR, conn);
		goto err;
	}

	/* the connection is not idle anymore, let's mark this */
	HA_ATOMIC_AND(&h1c->wait_event.tasklet->state, ~TASK_F_USR1);
	xprt_set_used(conn, conn->xprt, conn->xprt_ctx);

	TRACE_LEAVE(H1_EV_STRM_NEW, conn, h1s);
	return 0;
  err:
	TRACE_DEVEL("leaving on error", H1_EV_STRM_NEW|H1_EV_STRM_END|H1_EV_STRM_ERR, conn);
	return -1;
}

/* Retrieves a valid stream connector from this connection, or returns NULL.
 * For this mux, it's easy as we can only store a single stream connector.
 */
static struct stconn *h1_get_first_sc(const struct connection *conn)
{
	struct h1c *h1c = conn->ctx;
	struct h1s *h1s = h1c->h1s;

	if (h1s)
		return h1s_sc(h1s);

	return NULL;
}

static void h1_destroy(void *ctx)
{
	struct h1c *h1c = ctx;

	TRACE_POINT(H1_EV_H1C_END, h1c->conn);
	if (!h1c->h1s || h1c->conn->ctx != h1c)
		h1_release(h1c);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void h1_detach(struct sedesc *sd)
{
	struct h1s *h1s = sd->se;
	struct h1c *h1c;

	TRACE_ENTER(H1_EV_STRM_END, h1s ? h1s->h1c->conn : NULL, h1s);

	if (!h1s) {
		TRACE_LEAVE(H1_EV_STRM_END);
		return;
	}
	h1c = h1s->h1c;

	if (h1c->state == H1_CS_RUNNING && !(h1c->flags & H1C_F_IS_BACK) && h1s->req.state != H1_MSG_DONE) {
		h1c->state = H1_CS_DRAINING;
		h1c_report_term_evt(h1c, muxc_tevt_type_graceful_shut);
		COUNT_IF(1, "Deferring H1S destroy to drain message");
		TRACE_DEVEL("Deferring H1S destroy to drain message", H1_EV_STRM_END, h1s->h1c->conn, h1s);
		/* If we have a pending data, process it immediately or
		 * subscribe for reads waiting for new data
		 */
		if (unlikely(b_data(&h1c->ibuf))) {
			if (h1_process(h1c) == -1)
				goto end;
		}
		else
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		h1_set_idle_expiration(h1c);
		h1_refresh_timeout(h1c);
	}
	else
		h1s_finish_detach(h1s);

  end:
	TRACE_LEAVE(H1_EV_STRM_END);
}

static void h1_shut(struct stconn *sc, unsigned int mode, struct se_abort_info *reason)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c;

	if (!h1s || !(mode & (SE_SHW_SILENT|SE_SHW_NORMAL)))
		return;
	h1c = h1s->h1c;

	TRACE_ENTER(H1_EV_STRM_SHUT, h1c->conn, h1s, 0, (size_t[]){mode});

	if (!h1s_must_shut_conn(h1s))
		goto end;

  do_shutw:
	COUNT_IF((h1c->flags & H1C_F_IS_BACK) && (h1s->res.state < H1_MSG_DONE), "Abort sending of the response");
	COUNT_IF(!(h1c->flags & H1C_F_IS_BACK) && (h1s->req.state < H1_MSG_DONE), "Abort sending of the request");

	h1c_report_term_evt(h1c, muxc_tevt_type_shutw);
	h1_close(h1c);
	if (!(mode & SE_SHW_NORMAL))
		h1c->flags |= H1C_F_SILENT_SHUT;

	if (!b_data(&h1c->obuf))
		h1_shutw_conn(h1c->conn);
  end:
	TRACE_LEAVE(H1_EV_STRM_SHUT, h1c->conn, h1s);
}

static void h1_shutw_conn(struct connection *conn)
{
	struct h1c *h1c = conn->ctx;

	TRACE_ENTER(H1_EV_H1C_END, conn);
	h1_close(h1c);
	if (conn->flags & CO_FL_SOCK_WR_SH)
		return;

	COUNT_IF(b_data(&h1c->ibuf), "close connection with pending input data");
	COUNT_IF(b_data(&h1c->obuf), "close connection with pending output data");

	conn_xprt_shutw(conn);
	conn_sock_shutw(conn, !(h1c->flags & H1C_F_SILENT_SHUT));

	if (h1c->wait_event.tasklet && !h1c->wait_event.events)
		tasklet_wakeup(h1c->wait_event.tasklet);

	TRACE_LEAVE(H1_EV_H1C_END, conn);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int h1_unsubscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct h1s *h1s = __sc_mux_strm(sc);

	if (!h1s)
		return 0;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(h1s->subs && h1s->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		h1s->subs = NULL;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", H1_EV_STRM_RECV, h1s->h1c->conn, h1s);

	if (event_type & SUB_RETRY_SEND)
		TRACE_DEVEL("unsubscribe(send)", H1_EV_STRM_SEND, h1s->h1c->conn, h1s);

	return 0;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0, unless
 * the stream connector <sc> was already detached, in which case it will return
 * -1.
 */
static int h1_subscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c;

	if (!h1s)
		return -1;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(h1s->subs && h1s->subs != es);

	es->events |= event_type;
	h1s->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", H1_EV_STRM_RECV, h1s->h1c->conn, h1s);


	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", H1_EV_STRM_SEND, h1s->h1c->conn, h1s);
		/*
		 * If the stconn attempts to subscribe, and the
		 * mux isn't subscribed to the connection, then it
		 * probably means the connection wasn't established
		 * yet, so we have to subscribe.
		 */
		h1c = h1s->h1c;
		if (!(h1c->wait_event.events & SUB_RETRY_SEND))
			h1c->conn->xprt->subscribe(h1c->conn,
						   h1c->conn->xprt_ctx,
						   SUB_RETRY_SEND,
						   &h1c->wait_event);
	}
	return 0;
}

/* Called from the upper layer, to receive data.
 *
 * The caller is responsible for defragmenting <buf> if necessary. But <flags>
 * must be tested to know the calling context. If CO_RFL_BUF_FLUSH is set, it
 * means the caller wants to flush input data (from the mux buffer and the
 * channel buffer) to be able to use fast-forwarding.
 * If CO_RFL_KEEP_RECV is set, the mux must always subscribe for read
 * events before giving back. CO_RFL_BUF_WET is set if <buf> is congested with
 * data scheduled for leaving soon. CO_RFL_BUF_NOT_STUCK is set to instruct the
 * mux it may optimize the data copy to <buf> if necessary. Otherwise, it should
 * copy as much data as possible.
 */
static size_t h1_rcv_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c = h1s->h1c;
	struct h1m *h1m = (!(h1c->flags & H1C_F_IS_BACK) ? &h1s->req : &h1s->res);
	size_t ret = 0;

	TRACE_ENTER(H1_EV_STRM_RECV, h1c->conn, h1s, 0, (size_t[]){count});

	/* Do nothing for now if not RUNNING (implies UPGRADING) */
	if (h1c->state < H1_CS_RUNNING) {
		TRACE_DEVEL("h1c not ready yet", H1_EV_H1C_RECV|H1_EV_H1C_BLK, h1c->conn);
		goto end;
	}

	if (!(h1c->flags & H1C_F_IN_ALLOC))
		ret = h1_process_demux(h1c, buf, count);
	else
		TRACE_DEVEL("h1c ibuf not allocated", H1_EV_H1C_RECV|H1_EV_H1C_BLK, h1c->conn);

	if ((flags & CO_RFL_BUF_FLUSH) && se_fl_test(h1s->sd, SE_FL_MAY_FASTFWD_PROD)) {
		h1c->flags |= H1C_F_WANT_FASTFWD;
		TRACE_STATE("Block xprt rcv_buf to flush stream's buffer (want_fastfwd)", H1_EV_STRM_RECV, h1c->conn, h1s);
	}
	else {
		if (((flags & CO_RFL_KEEP_RECV) || (h1m->state != H1_MSG_DONE)) && !(h1c->wait_event.events & SUB_RETRY_RECV))
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
	}

  end:
	TRACE_LEAVE(H1_EV_STRM_RECV, h1c->conn, h1s, 0, (size_t[]){ret});
	return ret;
}


/* Called from the upper layer, to send data */
static size_t h1_snd_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c;
	size_t total = 0;

	if (!h1s)
		return 0;
	h1c = h1s->h1c;

	TRACE_ENTER(H1_EV_STRM_SEND, h1c->conn, h1s, 0, (size_t[]){count});

	/* If we're not connected yet, or we're waiting for a handshake, stop
	 * now, as we don't want to remove everything from the channel buffer
	 * before we're sure we can send it.
	 */
	if (h1c->conn->flags & CO_FL_WAIT_XPRT) {
		TRACE_LEAVE(H1_EV_STRM_SEND, h1c->conn, h1s);
		return 0;
	}

	if (h1c->flags & (H1C_F_ERR_PENDING|H1C_F_ERROR)) {
		se_fl_set_error(h1s->sd);
		TRACE_ERROR("H1C on error, leaving in error", H1_EV_STRM_SEND|H1_EV_H1C_ERR|H1_EV_H1S_ERR|H1_EV_STRM_ERR, h1c->conn, h1s);
		return 0;
	}

	/* Inherit some flags from the upper layer */
	h1c->flags &= ~(H1C_F_CO_MSG_MORE|H1C_F_CO_STREAMER);
	if (flags & CO_SFL_MSG_MORE)
		h1c->flags |= H1C_F_CO_MSG_MORE;
	if (flags & CO_SFL_STREAMER)
		h1c->flags |= H1C_F_CO_STREAMER;

	while (count) {
		size_t ret = 0;

		if (!(h1c->flags & (H1C_F_OUT_FULL|H1C_F_OUT_ALLOC)))
			ret = h1_process_mux(h1c, buf, count);
		else
			TRACE_DEVEL("h1c obuf not allocated", H1_EV_STRM_SEND|H1_EV_H1S_BLK, h1c->conn, h1s);

		if (!ret)
			break;

		if ((count - ret) > 0)
			h1c->flags |= H1C_F_CO_MSG_MORE;

		total += ret;
		count -= ret;

		if ((h1c->wait_event.events & SUB_RETRY_SEND) || !h1_send(h1c))
			break;

		if ((h1c->conn->flags & (CO_FL_ERROR|CO_FL_SOCK_WR_SH)))
			break;
	}

	if (h1c->flags & (H1C_F_ERR_PENDING|H1C_F_ERROR)) {
		// FIXME: following test was removed :
		// ((h1c->conn->flags & CO_FL_ERROR) && (se_fl_test(h1s->sd, SE_FL_EOI | SE_FL_EOS) || !b_data(&h1c->ibuf)))) {
		se_fl_set_error(h1s->sd);
		se_report_term_evt(h1s->sd, se_tevt_type_snd_err);
		TRACE_ERROR("reporting error to the app-layer stream", H1_EV_STRM_SEND|H1_EV_H1S_ERR|H1_EV_STRM_ERR, h1c->conn, h1s);
	}

	h1_refresh_timeout(h1c);
	TRACE_LEAVE(H1_EV_STRM_SEND, h1c->conn, h1s, 0, (size_t[]){total});
	return total;
}

static inline struct sedesc *h1s_opposite_sd(struct h1s *h1s)
{
	return se_opposite(h1s->sd);
}

static size_t h1_nego_ff(struct stconn *sc, struct buffer *input, size_t count, unsigned int flags)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c = h1s->h1c;
	struct h1m *h1m = (!(h1c->flags & H1C_F_IS_BACK) ? &h1s->res : &h1s->req);
	size_t sz, offset = 0, ret = 0;

	TRACE_ENTER(H1_EV_STRM_SEND, h1c->conn, h1s, 0, (size_t[]){count});


	if (global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_H1_SND) {
		h1s->sd->iobuf.flags |= IOBUF_FL_NO_FF;
		goto out;
	}

	if ((!(h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_REQ)) ||
	    ((h1m->flags & H1_MF_RESP) && (h1s->flags & H1S_F_BODYLESS_RESP))) {
		TRACE_STATE("Bodyless message, disable fastfwd", H1_EV_STRM_SEND|H1_EV_STRM_ERR, h1c->conn, h1s);
		h1s->sd->iobuf.flags |= IOBUF_FL_NO_FF;
		goto out;
	}

	if (h1m->flags & H1_MF_CLEN) {
		if ((flags & NEGO_FF_FL_EXACT_SIZE) && count > h1m->curr_len) {
			TRACE_ERROR("more payload than announced", H1_EV_STRM_SEND|H1_EV_STRM_ERR, h1c->conn, h1s);
			h1s->sd->iobuf.flags |= IOBUF_FL_NO_FF;
			goto out;
		}
	}
	else if (h1m->flags & H1_MF_CHNK) {
		if (h1m->curr_len) {
			BUG_ON(h1m->state != H1_MSG_DATA);
			if (count > h1m->curr_len) {
				if ((flags & NEGO_FF_FL_EXACT_SIZE) && count > h1m->curr_len) {
					TRACE_ERROR("chunk bigger than announced", H1_EV_STRM_SEND|H1_EV_STRM_ERR, h1c->conn, h1s);
					h1s->sd->iobuf.flags |= IOBUF_FL_NO_FF;
					goto out;
				}
				count = h1m->curr_len;
			}
		}
		else {
			BUG_ON(h1m->state != H1_MSG_CHUNK_CRLF && h1m->state != H1_MSG_CHUNK_SIZE);
			if (flags & NEGO_FF_FL_EXACT_SIZE) {
				if (!h1_make_chunk(h1s, h1m, count)) {
					h1s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
					goto out;
				}
				h1m->curr_len = count;
			}
			else {
				/* The producer does not know the chunk size, thus this will be emitted at the
				 * end, in done_ff(). So splicing cannot be used (see TODO below).
				 * We will reserve 10 bytes to handle at most 4Go chunk !
				 * (<8-bytes SIZE><CRLF><CHUNK-DATA>)
				 */
				if (count > MAX_RANGE(unsigned int))
					count = MAX_RANGE(unsigned int);
				offset = 10;
				/* Add 2 more bytes to finish the previous chunk */
				if (h1m->state == H1_MSG_CHUNK_CRLF)
					offset += 2;
				goto no_splicing;
			}
		}
	}

	/* Use kernel splicing if it is supported by the sender and if there
	 * are no input data _AND_ no output data.
	 *
	 * TODO: It may be good to add a flag to send obuf data first if any,
	 *       and then data in pipe, or the opposite. For now, it is not
	 *       supported to mix data.
	 */
	if (!b_data(input) && !b_data(&h1c->obuf) && (flags & NEGO_FF_FL_MAY_SPLICE)) {
#if defined(USE_LINUX_SPLICE)
		if (h1c->conn->xprt->snd_pipe && (h1s->sd->iobuf.pipe || (pipes_used < global.maxpipes && (h1s->sd->iobuf.pipe = get_pipe())))) {
			h1s->sd->iobuf.offset = 0;
			h1s->sd->iobuf.data = 0;
			ret = count;
			goto out;
		}
#endif
		h1s->sd->iobuf.flags |= IOBUF_FL_NO_SPLICING;
		TRACE_DEVEL("Unable to allocate pipe for splicing, fallback to buffer", H1_EV_STRM_SEND, h1c->conn, h1s);
	}

  no_splicing:
	if (!h1_get_obuf(h1c)) {
		h1s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("waiting for opposite h1c obuf allocation", H1_EV_STRM_SEND|H1_EV_H1S_BLK, h1c->conn, h1s);
		goto out;
	}

	if (b_space_wraps(&h1c->obuf))
		b_slow_realign(&h1c->obuf, trash.area, b_data(&h1c->obuf));

	if (b_contig_space(&h1c->obuf) <= offset) {
		h1c->flags |= H1C_F_OUT_FULL;
		h1s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("output buffer full", H1_EV_STRM_SEND|H1_EV_H1S_BLK, h1c->conn, h1s);
		goto out;
	}

	/* Cannot forward more than available room in output buffer */
	sz = b_contig_space(&h1c->obuf) - offset;
	if (count > sz)
		count = sz;

	h1s->sd->iobuf.buf = &h1c->obuf;
	h1s->sd->iobuf.offset = offset;
	h1s->sd->iobuf.data = 0;

	/* forward remaining input data */
	if (b_data(input)) {
		size_t xfer = count;

		if (xfer > b_data(input))
			xfer = b_data(input);
		h1c->obuf.head += offset;
		h1s->sd->iobuf.data = b_xfer(&h1c->obuf, input, xfer);
		h1c->obuf.head -= offset;

		/* Cannot forward more data, wait for room */
		if (b_data(input))
			goto out;
	}

	ret = count - h1s->sd->iobuf.data;

 out:
	TRACE_LEAVE(H1_EV_STRM_SEND, h1c->conn, h1s, 0, (size_t[]){ret});
	return ret;
}

static size_t h1_done_ff(struct stconn *sc)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c = h1s->h1c;
	struct h1m *h1m = (!(h1c->flags & H1C_F_IS_BACK) ? &h1s->res : &h1s->req);
	struct sedesc *sd = h1s->sd;
	size_t total = 0;

	TRACE_ENTER(H1_EV_STRM_SEND, h1c->conn, h1s);

#if defined(USE_LINUX_SPLICE)
	if (sd->iobuf.pipe) {
		total = h1c->conn->xprt->snd_pipe(h1c->conn, h1c->conn->xprt_ctx, sd->iobuf.pipe, sd->iobuf.pipe->data);
		if (total > 0)
			HA_ATOMIC_ADD(&h1c->px_counters->spliced_bytes_out, total);
		if (!sd->iobuf.pipe->data) {
			put_pipe(sd->iobuf.pipe);
			sd->iobuf.pipe = NULL;
		}
		goto out;
	}
#endif
	if (!sd->iobuf.pipe) {
		if (b_room(&h1c->obuf) == sd->iobuf.offset)
			h1c->flags |= H1C_F_OUT_FULL;

		if (sd->iobuf.data && sd->iobuf.offset) {
			struct buffer buf = b_make(b_orig(&h1c->obuf), b_size(&h1c->obuf),
						   b_peek_ofs(&h1c->obuf, b_data(&h1c->obuf) - sd->iobuf.data + sd->iobuf.offset),
						   sd->iobuf.data);
			h1_prepend_chunk_size(&buf, sd->iobuf.data, sd->iobuf.offset - ((h1m->state == H1_MSG_CHUNK_CRLF) ?  2 : 0));
			if (h1m->state == H1_MSG_CHUNK_CRLF)
				h1_prepend_chunk_crlf(&buf);
			b_add(&h1c->obuf, sd->iobuf.offset);
			h1m->state = H1_MSG_CHUNK_CRLF;
		}

		total = sd->iobuf.data;
		sd->iobuf.buf = NULL;
		sd->iobuf.offset = 0;
		sd->iobuf.data = 0;

		if (sd->iobuf.flags & IOBUF_FL_EOI)
			h1c->flags &= ~H1C_F_CO_MSG_MORE;

		/* Perform a synchronous send but in all cases, consider
		 * everything was already sent from the SC point of view.
		 */
		h1_send(h1c);
	}

  out:
	if (h1m->curr_len)
		h1m->curr_len -= total;

	if (!h1m->curr_len && (h1m->flags & H1_MF_CLEN))
		h1m->state = ((sd->iobuf.flags & IOBUF_FL_EOI) ? H1_MSG_DONE : H1_MSG_TRAILERS);
	else if (!h1m->curr_len && (h1m->flags & H1_MF_CHNK)) {
		if (h1m->state == H1_MSG_DATA)
			h1m->state = H1_MSG_CHUNK_CRLF;
	}

	HA_ATOMIC_ADD(&h1c->px_counters->bytes_out, total);

	// TODO: should we call h1_process() instead ?
	if (h1c->conn->flags & CO_FL_ERROR) {
		h1c->flags = (h1c->flags & ~H1C_F_WANT_FASTFWD) | H1C_F_ERR_PENDING;
		h1c_report_term_evt(h1c, muxc_tevt_type_snd_err);
		if (h1c->flags & H1C_F_EOS)
			h1c->flags |= H1C_F_ERROR;
		else if (!(h1c->wait_event.events & SUB_RETRY_RECV)) {
			/* EOS not seen, so subscribe for reads to be able to
			 * catch the error on the reading path. It is especially
			 * important if EOI was reached.
			 */
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		}
		COUNT_IF(b_data(&h1c->obuf) || (sd->iobuf.pipe && sd->iobuf.pipe->data), "connection error (done_ff) with pending output data");
		se_fl_set_error(h1s->sd);
		se_report_term_evt(h1s->sd, se_tevt_type_snd_err);
		if (sd->iobuf.pipe) {
			put_pipe(sd->iobuf.pipe);
			sd->iobuf.pipe = NULL;
		}
		TRACE_DEVEL("connection error", H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	}

	TRACE_LEAVE(H1_EV_STRM_RECV, h1c->conn, h1s, 0, (size_t[]){total});
	return total;
}

static int h1_fastfwd(struct stconn *sc, unsigned int count, unsigned int flags)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c = h1s->h1c;
	struct h1m *h1m = (!(h1c->flags & H1C_F_IS_BACK) ? &h1s->req : &h1s->res);
	struct sedesc *sdo = NULL;
	size_t total = 0, try = 0;
	unsigned int nego_flags = NEGO_FF_FL_NONE;
	int ret = 0;

	TRACE_ENTER(H1_EV_STRM_RECV, h1c->conn, h1s, 0, (size_t[]){count});

	if (h1m->state != H1_MSG_DATA && h1m->state != H1_MSG_TUNNEL) {
		h1c->flags &= ~H1C_F_WANT_FASTFWD;
		TRACE_STATE("Cannot fast-forwad data now !(msg_data|msg_tunnel)", H1_EV_STRM_RECV, h1c->conn, h1s);
		goto end;
	}

	se_fl_clr(h1s->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
	h1c->conn->flags &= ~CO_FL_WAIT_ROOM;
	h1c->flags |= H1C_F_WANT_FASTFWD;

	if (h1c->flags & (H1C_F_EOS|H1C_F_ERROR)) {
		h1c->flags &= ~H1C_F_WANT_FASTFWD;
		TRACE_DEVEL("leaving on (EOS|ERROR)", H1_EV_STRM_RECV, h1c->conn, h1s);
		goto end;
	}

	sdo = h1s_opposite_sd(h1s);
	if (!sdo) {
		TRACE_STATE("Opposite endpoint not available yet", H1_EV_STRM_RECV, h1c->conn, h1s);
		goto out;
	}

  retry:
	ret = 0;

	if (h1m->state == H1_MSG_DATA && (h1m->flags & (H1_MF_CHNK|H1_MF_CLEN)) &&  count > h1m->curr_len) {
		nego_flags |= NEGO_FF_FL_EXACT_SIZE;
		count = h1m->curr_len;
	}

	if (h1c->conn->xprt->rcv_pipe && !!(flags & CO_RFL_MAY_SPLICE) && !(sdo->iobuf.flags & IOBUF_FL_NO_SPLICING))
		nego_flags |= NEGO_FF_FL_MAY_SPLICE;

	try = se_nego_ff(sdo, &h1c->ibuf, count, nego_flags);
	if (b_room(&h1c->ibuf) && (h1c->flags & H1C_F_IN_FULL)) {
		h1c->flags &= ~H1C_F_IN_FULL;
		TRACE_STATE("h1c ibuf not full anymore", H1_EV_STRM_RECV|H1_EV_H1C_BLK);
	}
	if (!b_data(&h1c->ibuf))
		h1_release_buf(h1c, &h1c->ibuf);

	if (sdo->iobuf.flags & IOBUF_FL_NO_FF) {
		/* Fast forwarding is not supported by the consumer */
		h1c->flags = (h1c->flags & ~H1C_F_WANT_FASTFWD) | H1C_F_CANT_FASTFWD;
		TRACE_DEVEL("Fast-forwarding not supported by opposite endpoint, disable it", H1_EV_STRM_RECV, h1c->conn, h1s);
		goto end;
	}
	if (sdo->iobuf.flags & IOBUF_FL_FF_BLOCKED) {
		se_fl_set(h1s->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		TRACE_STATE("waiting for more room", H1_EV_STRM_RECV|H1_EV_H1S_ERR, h1c->conn, h1s);
		goto out;
	}

	total += sdo->iobuf.data;
	count -= sdo->iobuf.data;
#if defined(USE_LINUX_SPLICE)
	if (sdo->iobuf.pipe) {
		/* Here, not data was xferred */
		ret = h1c->conn->xprt->rcv_pipe(h1c->conn, h1c->conn->xprt_ctx, sdo->iobuf.pipe, try);
		if (ret < 0) {
			h1c->flags = (h1c->flags & ~H1C_F_WANT_FASTFWD) | H1C_F_CANT_FASTFWD;
			TRACE_ERROR("Error when trying to fast-forward data, disable it and abort",
				    H1_EV_STRM_RECV|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
			BUG_ON(sdo->iobuf.pipe->data);
			put_pipe(sdo->iobuf.pipe);
			sdo->iobuf.pipe = NULL;
			goto end;
		}
		total += ret;
		count -= ret;
		if (!ret) {
			TRACE_STATE("failed to receive data, subscribing", H1_EV_STRM_RECV, h1c->conn);
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		}
		HA_ATOMIC_ADD(&h1c->px_counters->spliced_bytes_in, ret);
	}
#endif
	if (!sdo->iobuf.pipe) {
		b_add(sdo->iobuf.buf, sdo->iobuf.offset);
		ret = h1c->conn->xprt->rcv_buf(h1c->conn, h1c->conn->xprt_ctx, sdo->iobuf.buf, try, flags);
		if (ret < try) {
			TRACE_STATE("failed to receive data, subscribing", H1_EV_STRM_RECV, h1c->conn);
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		}
		b_sub(sdo->iobuf.buf, sdo->iobuf.offset);
		total += ret;
		count -= ret;
		sdo->iobuf.data += ret;
	}

	/* Till now, we forwarded less than a buffer, we can immediately retry
	 * to fast-forward more data.  Instruct the consumer it is an interim
	 * fast-forward. It is of course only possible if there is still data to
	 * fast-forward (count > 0), if the previous attempt was a full success
	 * (0 > ret == try) and if we are not splicing (iobuf.buf != NULL).
	 */
	if (ret > 0 && ret == try && count && sdo->iobuf.buf && total < b_size(sdo->iobuf.buf)) {
		sdo->iobuf.flags |= IOBUF_FL_INTERIM_FF;
		se_done_ff(sdo);
		goto retry;
	}

 out:
	if (h1m->state == H1_MSG_DATA && (h1m->flags & (H1_MF_CHNK|H1_MF_CLEN))) {
		if (total > h1m->curr_len) {
			h1s->flags |= H1S_F_PARSING_ERROR;
			se_fl_set(h1s->sd, SE_FL_ERROR);
			COUNT_IF(1, "more payload than announced");
			TRACE_ERROR("too much payload, more than announced",
				    H1_EV_STRM_RECV|H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
			goto end;
		}
		h1m->curr_len -= total;
		if (!h1m->curr_len) {
			if (h1m->flags & H1_MF_CLEN) {
				h1m->state = H1_MSG_DONE;
				h1s_set_se_eoi_cond(h1s, h1m);
			}
			else
				h1m->state = H1_MSG_CHUNK_CRLF;
			h1c->flags &= ~H1C_F_WANT_FASTFWD;

			if (!(h1c->flags & H1C_F_IS_BACK)) {
				/* The request was fully received. It means the H1S now
				 * expect data from the opposite side
				 */
				se_expect_data(h1s->sd);
			}

			TRACE_STATE("payload fully received", H1_EV_STRM_RECV, h1c->conn, h1s);
		}
	}

	if (conn_xprt_read0_pending(h1c->conn)) {
		se_fl_set(h1s->sd, SE_FL_EOS);
		TRACE_STATE("report EOS to SE", H1_EV_STRM_RECV, h1c->conn, h1s);
		if (h1m->state >= H1_MSG_DONE || !(h1m->flags & H1_MF_XFER_LEN)) {
			/* DONE or TUNNEL or SHUTR without XFER_LEN, set
			 * EOI on the stream connector */
			se_fl_set(h1s->sd, SE_FL_EOI);
			if (!(h1c->conn->flags & CO_FL_ERROR))
				se_report_term_evt(h1s->sd, se_tevt_type_eos);
			TRACE_STATE("report EOI to SE", H1_EV_STRM_RECV, h1c->conn, h1s);
		}
		else {
			se_fl_set(h1s->sd, SE_FL_ERROR);
			h1c->flags = (h1c->flags & ~H1C_F_WANT_FASTFWD) | H1C_F_ERROR;
			if (!(h1c->conn->flags & CO_FL_ERROR))
				se_report_term_evt(h1s->sd, se_tevt_type_truncated_eos);
			COUNT_IF(1, "H1C EOS before the end of the message");
			TRACE_ERROR("message aborted, set error on SC", H1_EV_STRM_RECV|H1_EV_H1S_ERR, h1c->conn, h1s);
		}
		h1c->flags = (h1c->flags & ~H1C_F_WANT_FASTFWD) | H1C_F_EOS;

		if (!(h1c->conn->flags & CO_FL_ERROR)) {
			if (se_fl_test(h1c->h1s->sd, SE_FL_EOI)) {
				se_report_term_evt(h1s->sd, se_tevt_type_eos);
				h1c_report_term_evt(h1c, muxc_tevt_type_shutr);
			}
			else {
				se_report_term_evt(h1s->sd, se_tevt_type_truncated_eos);
				h1c_report_term_evt(h1c, muxc_tevt_type_truncated_shutr);
			}
		}

		TRACE_STATE("Allow xprt rcv_buf on read0", H1_EV_STRM_RECV, h1c->conn, h1s);
	}
	if (h1c->conn->flags & CO_FL_ERROR) {
		se_fl_set(h1s->sd, SE_FL_ERROR);
		h1c->flags = (h1c->flags & ~H1C_F_WANT_FASTFWD) | H1C_F_ERROR;

		if (se_fl_test(h1c->h1s->sd, SE_FL_EOI)) {
			se_report_term_evt(h1s->sd, se_tevt_type_rcv_err);
			h1c_report_term_evt(h1c, muxc_tevt_type_rcv_err);
		}
		else {
			se_report_term_evt(h1s->sd, se_tevt_type_truncated_rcv_err);
			h1c_report_term_evt(h1c, muxc_tevt_type_truncated_rcv_err);
		}

		COUNT_IF(h1m->state < H1_MSG_DONE, "H1C ERROR before the end of the message");
		COUNT_IF(b_data(&h1c->obuf) || (h1s->sd->iobuf.pipe && h1s->sd->iobuf.pipe->data), "connection error (fastfwd) with pending output data");
		TRACE_DEVEL("connection error", H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	}


	sdo->iobuf.flags &= ~IOBUF_FL_INTERIM_FF;
	if (se_fl_test(h1s->sd, SE_FL_EOI)) {
		sdo->iobuf.flags |= IOBUF_FL_EOI; /* TODO: it may be good to have a flag to be sure we can
						   *       forward the EOI the to consumer side
						   */
	}
	se_done_ff(sdo);

	ret = total;
	HA_ATOMIC_ADD(&h1c->px_counters->bytes_in, total);

	if (sdo->iobuf.pipe) {
		se_fl_set(h1s->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
	}

 end:

	if (!(h1c->flags & H1C_F_WANT_FASTFWD)) {
		TRACE_STATE("notify the mux can't use fast-forward anymore", H1_EV_STRM_RECV, h1c->conn, h1s);
		se_fl_clr(h1s->sd, SE_FL_MAY_FASTFWD_PROD);
		if (!(h1c->wait_event.events & SUB_RETRY_RECV)) {
			TRACE_STATE("restart receiving data, subscribing", H1_EV_STRM_RECV, h1c->conn, h1s);
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		}
	}

	TRACE_LEAVE(H1_EV_STRM_RECV, h1c->conn, h1s, 0, (size_t[]){ret});
	return ret;
}

static int h1_resume_fastfwd(struct stconn *sc, unsigned int flags)
{
	struct h1s *h1s = __sc_mux_strm(sc);
	struct h1c *h1c = h1s->h1c;
	int ret = 0;

	TRACE_ENTER(H1_EV_STRM_SEND, h1c->conn, h1s, 0, (size_t[]){flags});

#if defined(USE_LINUX_SPLICE)
	if (h1s->sd->iobuf.pipe) {
		struct h1m *h1m = (!(h1c->flags & H1C_F_IS_BACK) ? &h1s->res : &h1s->req);
		struct sedesc *sd = h1s->sd;

		ret = h1c->conn->xprt->snd_pipe(h1c->conn, h1c->conn->xprt_ctx, sd->iobuf.pipe, sd->iobuf.pipe->data);
		if (ret > 0)
			HA_ATOMIC_ADD(&h1c->px_counters->spliced_bytes_out, ret);
		if (!sd->iobuf.pipe->data) {
			put_pipe(sd->iobuf.pipe);
			sd->iobuf.pipe = NULL;
		}

		h1m->curr_len -= ret;

		if (!h1m->curr_len && (h1m->flags & H1_MF_CLEN))
			h1m->state = H1_MSG_DONE;
		else if (!h1m->curr_len && (h1m->flags & H1_MF_CHNK)) {
			if (h1m->state == H1_MSG_DATA)
				h1m->state = H1_MSG_CHUNK_CRLF;
		}

		HA_ATOMIC_ADD(&h1c->px_counters->bytes_out, ret);
	}
#endif

	// TODO: should we call h1_process() instead ?
	if (h1c->conn->flags & CO_FL_ERROR) {
		h1c->flags = (h1c->flags & ~H1C_F_WANT_FASTFWD) | H1C_F_ERR_PENDING;
		if (h1c->flags & H1C_F_EOS)
			h1c->flags |= H1C_F_ERROR;
		else if (!(h1c->wait_event.events & SUB_RETRY_RECV)) {
			/* EOS not seen, so subscribe for reads to be able to
			 * catch the error on the reading path. It is especially
			 * important if EOI was reached.
			 */
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		}
		se_fl_set_error(h1s->sd);
		COUNT_IF(b_data(&h1c->obuf) || (h1s->sd->iobuf.pipe && h1s->sd->iobuf.pipe->data), "connection error (resume_ff) with pending output data");
		if (h1s->sd->iobuf.pipe) {
			put_pipe(h1s->sd->iobuf.pipe);
			h1s->sd->iobuf.pipe = NULL;
		}
		TRACE_DEVEL("connection error", H1_EV_STRM_ERR|H1_EV_H1C_ERR|H1_EV_H1S_ERR, h1c->conn, h1s);
	}

	TRACE_LEAVE(H1_EV_STRM_RECV, h1c->conn, h1s, 0, (size_t[]){ret});
	return ret;
}

static int h1_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	struct h1c *h1c = conn->ctx;
	int ret = 0;

	switch (mux_ctl) {
	case MUX_CTL_STATUS:
		if (!(conn->flags & CO_FL_WAIT_XPRT))
			ret |= MUX_STATUS_READY;
		return ret;
	case MUX_CTL_EXIT_STATUS:
		if (output)
			*((int *)output) = h1c->errcode;
		ret = (h1c->errcode == 408 ? MUX_ES_TOUT_ERR :
		       (h1c->errcode == 501 ? MUX_ES_NOTIMPL_ERR :
			(h1c->errcode == 500 ? MUX_ES_INTERNAL_ERR :
			 ((h1c->errcode >= 400 && h1c->errcode <= 499) ? MUX_ES_INVALID_ERR :
			  MUX_ES_SUCCESS))));
		return ret;
	case MUX_CTL_SUBS_RECV:
		if (!(h1c->wait_event.events & SUB_RETRY_RECV))
			h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx, SUB_RETRY_RECV, &h1c->wait_event);
		return 0;
	case MUX_CTL_GET_NBSTRM:
		return h1_used_streams(conn);
	case MUX_CTL_GET_MAXSTRM:
		return 1;
	case MUX_CTL_TEVTS:
		return h1c->term_evts_log;
	default:
		return -1;
	}
}

static int h1_sctl(struct stconn *sc, enum mux_sctl_type mux_sctl, void *output)
{
	int ret = 0;
	struct h1s *h1s = __sc_mux_strm(sc);
	union mux_sctl_dbg_str_ctx *dbg_ctx;
	struct buffer *buf;

	switch (mux_sctl) {
	case MUX_SCTL_SID:
		if (output)
			*((int64_t *)output) = h1s->h1c->req_count;
		return ret;
	case MUX_SCTL_DBG_STR:
		dbg_ctx = output;
		buf = get_trash_chunk();

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_MUXS)
			h1_dump_h1s_info(buf, h1s, NULL);

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_MUXC)
			h1_dump_h1c_info(buf, h1s->h1c, NULL);

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_CONN)
			chunk_appendf(buf, " conn.flg=%#08x conn.err_code=%u conn.evts=%s",
				      h1s->h1c->conn->flags, h1s->h1c->conn->err_code,
				      tevt_evts2str(h1s->h1c->conn->term_evts_log));

		/* other layers not implemented */
		dbg_ctx->ret.buf = *buf;
		return ret;
	case MUX_SCTL_TEVTS:
		return h1s->sd->term_evts_log;
	default:
		return -1;
	}
}

/* appends some info about connection <h1c> to buffer <msg>, or does nothing if
 * <h1c> is NULL. Returns non-zero if the connection is considered suspicious.
 * May emit multiple lines, each new one being prefixed with <pfx>, if <pfx> is
 * not NULL, otherwise a single line is used.
 */
static int h1_dump_h1c_info(struct buffer *msg, struct h1c *h1c, const char *pfx)
{
	int ret = 0;

	if (!h1c)
		return ret;

	chunk_appendf(msg, " h1c.flg=0x%x .sub=%d .ibuf=%u@%p+%u/%u .obuf=%u@%p+%u/%u .evts=%s",
		      h1c->flags,  h1c->wait_event.events,
		      (unsigned int)b_data(&h1c->ibuf), b_orig(&h1c->ibuf),
		      (unsigned int)b_head_ofs(&h1c->ibuf), (unsigned int)b_size(&h1c->ibuf),
		      (unsigned int)b_data(&h1c->obuf), b_orig(&h1c->obuf),
		      (unsigned int)b_head_ofs(&h1c->obuf), (unsigned int)b_size(&h1c->obuf),
		      tevt_evts2str(h1c->term_evts_log));

	chunk_appendf(msg, " .task=%p", h1c->task);
	if (h1c->task) {
		chunk_appendf(msg, " .exp=%s",
			      h1c->task->expire ? tick_is_expired(h1c->task->expire, now_ms) ? "<PAST>" :
			      human_time(TICKS_TO_MS(h1c->task->expire - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	}

	return ret;
}

/* appends some info about stream <h1s> to buffer <msg>, or does nothing if
 * <h1s> is NULL. Returns non-zero if the stream is considered suspicious. May
 * emit multiple lines, each new one being prefixed with <pfx>, if <pfx> is not
 * NULL, otherwise a single line is used.
 */
static int h1_dump_h1s_info(struct buffer *msg, const struct h1s *h1s, const char *pfx)
{
	const char *method;
	int ret = 0;

	if (!h1s)
		return ret;

	if (h1s->meth < HTTP_METH_OTHER)
		method = http_known_methods[h1s->meth].ptr;
	else
		method = "UNKNOWN";

	chunk_appendf(msg, " h1s=%p h1s.flg=0x%x .sd.flg=0x%x", h1s, h1s->flags, se_fl_get(h1s->sd));
	chunk_appendf(msg, " .req.state=%s .res.state=%s", h1m_state_str(h1s->req.state), h1m_state_str(h1s->res.state));

	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);

	chunk_appendf(msg, " .meth=%s status=%d",
		      method, h1s->status);

	chunk_appendf(msg, " .sd.flg=0x%08x .sd.evts=%s", se_fl_get(h1s->sd), tevt_evts2str(h1s->sd->term_evts_log));
	if (!se_fl_test(h1s->sd, SE_FL_ORPHAN)) {
		chunk_appendf(msg, " .sc.flg=0x%08x .sc.app=%p .sc.evts=%s",
			      h1s_sc(h1s)->flags, h1s_sc(h1s)->app, tevt_evts2str(h1s_sc(h1s)->term_evts_log));
	}

	if (pfx && h1s->subs)
		chunk_appendf(msg, "\n%s", pfx);

	chunk_appendf(msg, " .subs=%p", h1s->subs);
	if (h1s->subs) {
		chunk_appendf(msg, "(ev=%d tl=%p", h1s->subs->events, h1s->subs->tasklet);
		chunk_appendf(msg, " tl.calls=%d tl.ctx=%p tl.fct=",
			      h1s->subs->tasklet->calls,
			      h1s->subs->tasklet->context);
		if (h1s->subs->tasklet->calls >= 1000000)
			ret = 1;
		resolve_sym_name(msg, NULL, h1s->subs->tasklet->process);
		chunk_appendf(msg, ")");
	}
	return ret;
}

/* for debugging with CLI's "show fd" command */
static int h1_show_fd(struct buffer *msg, struct connection *conn)
{
	struct h1c *h1c = conn->ctx;
	struct h1s *h1s = h1c->h1s;
	int ret = 0;

	ret |= h1_dump_h1c_info(msg, h1c, NULL);

	if (h1s)
		ret |= h1_dump_h1s_info(msg, h1s, NULL);

	return ret;
}

/* for debugging with CLI's "show sess" command. May emit multiple lines, each
 * new one being prefixed with <pfx>, if <pfx> is not NULL, otherwise a single
 * line is used. Each field starts with a space so it's safe to print it after
 * existing fields.
 */
static int h1_show_sd(struct buffer *msg, struct sedesc *sd, const char *pfx)
{
	struct h1s *h1s = sd->se;
	int ret = 0;

	if (!h1s)
		return ret;

	ret |= h1_dump_h1s_info(msg, h1s, pfx);
	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);
	chunk_appendf(msg, " h1c=%p", h1s->h1c);
	ret |= h1_dump_h1c_info(msg, h1s->h1c, pfx);
	return ret;
}


/* Add an entry in the headers map. Returns -1 on error and 0 on success. */
static int add_hdr_case_adjust(const char *from, const char *to, char **err)
{
	struct h1_hdr_entry *entry;

	/* Be sure there is a non-empty <to> */
	if (!strlen(to)) {
		memprintf(err, "expect <to>");
		return -1;
	}

	/* Be sure only the case differs between <from> and <to> */
	if (strcasecmp(from, to) != 0) {
		memprintf(err, "<from> and <to> must not differ except the case");
		return -1;
	}

	/* Be sure <from> does not already existsin the tree */
	if (ebis_lookup(&hdrs_map.map, from)) {
		memprintf(err, "duplicate entry '%s'", from);
		return -1;
	}

	/* Create the entry and insert it in the tree */
	entry = malloc(sizeof(*entry));
	if (!entry) {
		memprintf(err, "out of memory");
		return -1;
	}

	entry->node.key = strdup(from);
	entry->name = ist(strdup(to));
	if (!entry->node.key || !isttest(entry->name)) {
		free(entry->node.key);
		istfree(&entry->name);
		free(entry);
		memprintf(err, "out of memory");
		return -1;
	}
	ebis_insert(&hdrs_map.map, &entry->node);
	return 0;
}

/* Migrate the the connection to the current thread.
 * Return 0 if successful, non-zero otherwise.
 * Expected to be called with the old thread lock held.
 */
static int h1_takeover(struct connection *conn, int orig_tid, int release)
{
	struct h1c *h1c = conn->ctx;
	struct task *task;
	struct task *new_task = NULL;
	struct tasklet *new_tasklet = NULL;

	/* Pre-allocate tasks so that we don't have to roll back after the xprt
	 * has been migrated.
	 */
	if (!release) {
		/* If the connection is attached to a buffer_wait (extremely
		 * rare), it will be woken up at any instant by its own thread
		 * and we can't undo it anyway, so let's give up on this one.
		 * It's not interesting anyway since it's not usable right now.
		 */
		if (LIST_INLIST(&h1c->buf_wait.list))
			goto fail;

		new_task = task_new_here();
		new_tasklet = tasklet_new();
		if (!new_task || !new_tasklet)
			goto fail;
	}

	if (fd_takeover(conn->handle.fd, conn) != 0)
		goto fail;

	if (conn->xprt->takeover && conn->xprt->takeover(conn, conn->xprt_ctx, orig_tid, release) != 0) {
		/* We failed to takeover the xprt, even if the connection may
		 * still be valid, flag it as error'd, as we have already
		 * taken over the fd, and wake the tasklet, so that it will
		 * destroy it.
		 */
		conn->flags |= CO_FL_ERROR;
		tasklet_wakeup_on(h1c->wait_event.tasklet, orig_tid);
		goto fail;
	}

	if (h1c->wait_event.events)
		h1c->conn->xprt->unsubscribe(h1c->conn, h1c->conn->xprt_ctx,
		    h1c->wait_event.events, &h1c->wait_event);

	task = h1c->task;
	if (task) {
		/* only assign a task if there was already one, otherwise
		 * the preallocated new task will be released.
		 */
		task->context = NULL;
		h1c->task = NULL;
		__ha_barrier_store();
		task_kill(task);

		h1c->task = new_task;
		new_task = NULL;
		if (!release) {
			h1c->task->process = h1_timeout_task;
			h1c->task->context = h1c;
		}
	}

	/* To let the tasklet know it should free itself, and do nothing else,
	 * set its context to NULL.
	 */
	h1c->wait_event.tasklet->context = NULL;
	tasklet_wakeup_on(h1c->wait_event.tasklet, orig_tid);

	h1c->wait_event.tasklet = new_tasklet;
	if (!release) {
		h1c->wait_event.tasklet->process = h1_io_cb;
		h1c->wait_event.tasklet->context = h1c;
		h1c->conn->xprt->subscribe(h1c->conn, h1c->conn->xprt_ctx,
		                           SUB_RETRY_RECV, &h1c->wait_event);
	}

	if (release) {
		/* we're being called for a server deletion and are running
		 * under thread isolation. That's the only way we can
		 * unregister a possible subscription of the original
		 * connection from its owner thread's queue, as this involves
		 * manipulating thread-unsafe areas. Note that it is not
		 * possible to just call b_dequeue() here as it would update
		 * the current thread's bufq_map and not the original one.
		 */
		BUG_ON(!thread_isolated());
		if (LIST_INLIST(&h1c->buf_wait.list))
			_b_dequeue(&h1c->buf_wait, orig_tid);
	}

	if (new_task)
		__task_free(new_task);
	return 0;
 fail:
	if (new_task)
		__task_free(new_task);
	tasklet_free(new_tasklet);
	return -1;
}


static void h1_hdeaders_case_adjust_deinit()
{
	struct ebpt_node *node, *next;
	struct h1_hdr_entry *entry;

	node = ebpt_first(&hdrs_map.map);
	while (node) {
		next = ebpt_next(node);
		ebpt_delete(node);
		entry = container_of(node, struct h1_hdr_entry, node);
		free(entry->node.key);
		istfree(&entry->name);
		free(entry);
		node = next;
	}
	free(hdrs_map.name);
}

static int cfg_h1_headers_case_adjust_postparser()
{
	FILE *file = NULL;
	char *c, *key_beg, *key_end, *value_beg, *value_end;
	char *err;
	int rc, line = 0, err_code = 0;

	if (!hdrs_map.name)
		goto end;

	file = fopen(hdrs_map.name, "r");
	if (!file) {
		ha_alert("h1-headers-case-adjust-file '%s': failed to open file.\n",
			 hdrs_map.name);
                err_code |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* now parse all lines. The file may contain only two header name per
	 * line, separated by spaces. All heading and trailing spaces will be
	 * ignored. Lines starting with a # are ignored.
	 */
	while (fgets(trash.area, trash.size, file) != NULL) {
		line++;
		c = trash.area;

		/* strip leading spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;

		/* ignore emptu lines, or lines beginning with a dash */
		if (*c == '#' || *c == '\0' || *c == '\r' || *c == '\n')
			continue;

		/* look for the end of the key */
		key_beg = c;
		while (*c != '\0' && *c != ' ' && *c != '\t' && *c != '\n' && *c != '\r')
			c++;
		key_end = c;

		/* strip middle spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;

		/* look for the end of the value, it is the end of the line */
		value_beg = c;
		while (*c && *c != '\n' && *c != '\r')
			c++;
		value_end = c;

		/* trim possibly trailing spaces and tabs */
		while (value_end > value_beg && (value_end[-1] == ' ' || value_end[-1] == '\t'))
			value_end--;

		/* set final \0 and check entries */
		*key_end = '\0';
		*value_end = '\0';

		err = NULL;
		rc = add_hdr_case_adjust(key_beg, value_beg, &err);
		if (rc < 0) {
			ha_alert("h1-headers-case-adjust-file '%s' : %s at line %d.\n",
				 hdrs_map.name, err, line);
			err_code |= ERR_ALERT | ERR_FATAL;
			free(err);
			goto end;
		}
		if (rc > 0) {
			ha_warning("h1-headers-case-adjust-file '%s' : %s at line %d.\n",
				   hdrs_map.name, err, line);
			err_code |= ERR_WARN;
			free(err);
		}
	}

  end:
	if (file)
		fclose(file);
	hap_register_post_deinit(h1_hdeaders_case_adjust_deinit);
	return err_code;
}

/* config parser for global "h1-accept-payload_=-with-any-method" */
static int cfg_parse_h1_accept_payload_with_any_method(char **args, int section_type, struct proxy *curpx,
						       const struct proxy *defpx, const char *file, int line,
						       char **err)
{
        if (too_many_args(0, args, err, NULL))
                return -1;
	accept_payload_with_any_method = 1;
	return 0;
}


/* config parser for global "h1-header-case-adjust" */
static int cfg_parse_h1_header_case_adjust(char **args, int section_type, struct proxy *curpx,
					   const struct proxy *defpx, const char *file, int line,
					   char **err)
{
        if (too_many_args(2, args, err, NULL))
                return -1;
        if (!*(args[1]) || !*(args[2])) {
                memprintf(err, "'%s' expects <from> and <to> as argument.", args[0]);
		return -1;
	}
	return add_hdr_case_adjust(args[1], args[2], err);
}

/* config parser for global "h1-headers-case-adjust-file" */
static int cfg_parse_h1_headers_case_adjust_file(char **args, int section_type, struct proxy *curpx,
						 const struct proxy *defpx, const char *file, int line,
						 char **err)
{
        if (too_many_args(1, args, err, NULL))
                return -1;
        if (!*(args[1])) {
                memprintf(err, "'%s' expects <file> as argument.", args[0]);
		return -1;
	}
	free(hdrs_map.name);
	hdrs_map.name = strdup(args[1]);
	if  (!hdrs_map.name) {
		memprintf(err, "'%s %s' : out of memory", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h1.zero-copy-fwd-recv" */
static int cfg_parse_h1_zero_copy_fwd_rcv(char **args, int section_type, struct proxy *curpx,
					   const struct proxy *defpx, const char *file, int line,
					   char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.no_zero_copy_fwd &= ~NO_ZERO_COPY_FWD_H1_RCV;
	else if (strcmp(args[1], "off") == 0)
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD_H1_RCV;
	else {
		memprintf(err, "'%s' expects 'on' or 'off'.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h1.zero-copy-fwd-send" */
static int cfg_parse_h1_zero_copy_fwd_snd(char **args, int section_type, struct proxy *curpx,
					  const struct proxy *defpx, const char *file, int line,
					  char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.no_zero_copy_fwd &= ~NO_ZERO_COPY_FWD_H1_SND;
	else if (strcmp(args[1], "off") == 0)
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD_H1_SND;
	else {
		memprintf(err, "'%s' expects 'on' or 'off'.", args[0]);
		return -1;
	}
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {{ }, {
		{ CFG_GLOBAL, "h1-accept-payload-with-any-method", cfg_parse_h1_accept_payload_with_any_method },
		{ CFG_GLOBAL, "h1-case-adjust", cfg_parse_h1_header_case_adjust },
		{ CFG_GLOBAL, "h1-case-adjust-file", cfg_parse_h1_headers_case_adjust_file },
		{ CFG_GLOBAL, "tune.h1.zero-copy-fwd-recv", cfg_parse_h1_zero_copy_fwd_rcv },
		{ CFG_GLOBAL, "tune.h1.zero-copy-fwd-send", cfg_parse_h1_zero_copy_fwd_snd },
		{ 0, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
REGISTER_CONFIG_POSTPARSER("h1-headers-map", cfg_h1_headers_case_adjust_postparser);


/****************************************/
/* MUX initialization and instantiation */
/****************************************/

/* The mux operations */
static const struct mux_ops mux_http_ops = {
	.init        = h1_init,
	.wake        = h1_wake,
	.attach      = h1_attach,
	.get_first_sc = h1_get_first_sc,
	.detach      = h1_detach,
	.destroy     = h1_destroy,
	.avail_streams = h1_avail_streams,
	.used_streams = h1_used_streams,
	.rcv_buf     = h1_rcv_buf,
	.snd_buf     = h1_snd_buf,
	.nego_fastfwd = h1_nego_ff,
	.done_fastfwd = h1_done_ff,
	.fastfwd     = h1_fastfwd,
	.resume_fastfwd = h1_resume_fastfwd,
	.subscribe   = h1_subscribe,
	.unsubscribe = h1_unsubscribe,
	.shut        = h1_shut,
	.show_fd     = h1_show_fd,
	.show_sd     = h1_show_sd,
	.ctl         = h1_ctl,
	.sctl        = h1_sctl,
	.takeover    = h1_takeover,
	.flags       = MX_FL_HTX,
	.name        = "H1",
};

static const struct mux_ops mux_h1_ops = {
	.init        = h1_init,
	.wake        = h1_wake,
	.attach      = h1_attach,
	.get_first_sc = h1_get_first_sc,
	.detach      = h1_detach,
	.destroy     = h1_destroy,
	.avail_streams = h1_avail_streams,
	.used_streams = h1_used_streams,
	.rcv_buf     = h1_rcv_buf,
	.snd_buf     = h1_snd_buf,
	.nego_fastfwd = h1_nego_ff,
	.done_fastfwd = h1_done_ff,
	.fastfwd     = h1_fastfwd,
	.resume_fastfwd = h1_resume_fastfwd,
	.subscribe   = h1_subscribe,
	.unsubscribe = h1_unsubscribe,
	.shut        = h1_shut,
	.show_fd     = h1_show_fd,
	.show_sd     = h1_show_sd,
	.ctl         = h1_ctl,
	.sctl        = h1_sctl,
	.takeover    = h1_takeover,
	.flags       = MX_FL_HTX|MX_FL_NO_UPG,
	.name        = "H1",
};

/* this mux registers default HTX proto but also h1 proto (to be referenced in the conf */
static struct mux_proto_list mux_proto_h1 =
	{ .token = IST("h1"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_BOTH, .mux = &mux_h1_ops };
static struct mux_proto_list mux_proto_http =
	{ .token = IST(""), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_BOTH, .mux = &mux_http_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_h1);
INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_http);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
