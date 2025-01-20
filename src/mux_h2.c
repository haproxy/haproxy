/*
 * HTTP/2 mux-demux for connections
 *
 * Copyright 2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <import/eb32tree.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/h2.h>
#include <haproxy/hpack-dec.h>
#include <haproxy/hpack-enc.h>
#include <haproxy/hpack-tbl.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/istbuf.h>
#include <haproxy/log.h>
#include <haproxy/mux_h2-t.h>
#include <haproxy/net_helper.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/session-t.h>
#include <haproxy/stats.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/trace.h>
#include <haproxy/xref.h>


/* dummy streams returned for closed, error, refused, idle and states */
static const struct h2s *h2_closed_stream;
static const struct h2s *h2_error_stream;
static const struct h2s *h2_refused_stream;
static const struct h2s *h2_idle_stream;


/**** H2 connection descriptor ****/
struct h2c {
	struct connection *conn;

	enum h2_cs st0; /* mux state */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */

	/* 16 bit hole here */
	uint32_t flags; /* connection flags: H2_CF_* */
	uint32_t streams_limit; /* maximum number of concurrent streams the peer supports */
	int32_t max_id; /* highest ID known on this connection, <0 before preface */
	uint32_t rcvd_c; /* newly received data to ACK for the connection */
	uint32_t rcvd_s; /* newly received data for the current stream (dsi) or zero */
	uint32_t wu_s;   /* amount of data to write in the next WU frame for dsi, or zero */
	uint32_t receiving_streams; /* number of streams currently receiving data */

	/* states for the demux direction */
	struct hpack_dht *ddht; /* demux dynamic header table */
	struct buffer dbuf;    /* demux buffer */

	int32_t dsi; /* demux stream ID (<0 = idle) */
	int32_t dfl; /* demux frame length (if dsi >= 0) */
	int8_t  dft; /* demux frame type   (if dsi >= 0) */
	int8_t  dff; /* demux frame flags  (if dsi >= 0) */
	uint8_t dpl; /* demux pad length (part of dfl), init to 0 */
	/* 8 bit hole here */
	int32_t last_sid; /* last processed stream ID for GOAWAY, <0 before preface */

	/* states for the mux direction */
	struct buffer mbuf[H2C_MBUF_CNT];   /* mux buffers (ring) */
	struct bl_elem *shared_rx_bufs;     /* shared rx bufs */
	int32_t miw; /* mux initial window size for all new streams */
	int32_t mws; /* mux window size. Can be negative. */
	int32_t mfs; /* mux's max frame size */

	int timeout;        /* idle timeout duration in ticks */
	int shut_timeout;   /* idle timeout duration in ticks after GOAWAY was sent */
	int idle_start;     /* date of the last time the connection went idle (no stream + empty mbuf), or the start of current http req */

	unsigned int nb_streams;  /* number of streams in the tree */
	unsigned int nb_sc;       /* number of attached stream connectors */
	unsigned int nb_reserved; /* number of reserved streams */
	unsigned int stream_cnt;  /* total number of streams seen */
	int glitches;             /* total number of glitches on this connection */

	uint32_t term_evts_log;  /* Termination events log: first 4 events reported */

	struct proxy *proxy; /* the proxy this connection was created for */
	struct task *task;  /* timeout management task */
	struct h2_counters *px_counters; /* h2 counters attached to proxy */
	struct eb_root streams_by_id; /* all active streams by their ID */
	struct list send_list; /* list of blocked streams requesting to send */
	struct list fctl_list; /* list of streams blocked by connection's fctl */
	struct list blocked_list; /* list of streams blocked for other reasons (e.g. sfctl, dep) */
	struct buffer_wait buf_wait; /* wait list for buffer allocations */
	struct wait_event wait_event;  /* To be used if we're waiting for I/Os */

	struct list *next_tasklet; /* which applet to wake up next (NULL by default) */
};


/* H2 stream descriptor, describing the stream as it appears in the H2C, and as
 * it is being processed in the internal HTTP representation (HTX).
 */
struct h2s {
	struct sedesc *sd;
	struct session *sess;
	struct h2c *h2c;
	struct eb32_node by_id; /* place in h2c's streams_by_id */
	int32_t id; /* stream ID */
	uint32_t flags;      /* H2_SF_* */
	int sws;             /* stream window size, to be added to the mux's initial window size */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */
	enum h2_ss st;
	uint16_t status;     /* HTTP response status */
	unsigned long long body_len; /* remaining body length according to content-length if H2_SF_DATA_CLEN */
	uint64_t curr_rx_ofs;  /* stream offset at which next FC-data will arrive (includes padding) */
	uint64_t last_adv_ofs; /* stream offset corresponding to last emitted WU */
	uint64_t next_max_ofs; /* max stream offset that next WU must permit (curr_rx_ofs+rx_win) */
	uint rx_head, rx_tail; /* head and tail of rx buffer in the conn's shared rx buf */
	uint rx_count;         /* total number of allocated rxbufs */
	/* 4 bytes hole here */
	struct wait_event *subs;  /* recv wait_event the stream connector associated is waiting on (via h2_subscribe) */
	struct list list; /* To be used when adding in h2c->send_list or h2c->fctl_lsit */
	struct tasklet *shut_tl;  /* deferred shutdown tasklet, to retry to send an RST after we failed to,
				   * in case there's no other subscription to do it */

	char upgrade_protocol[16]; /* rfc 8441: requested protocol on Extended CONNECT */
};

/* descriptor for an h2 frame header */
struct h2_fh {
	uint32_t len;       /* length, host order, 24 bits */
	uint32_t sid;       /* stream id, host order, 31 bits */
	uint8_t ft;         /* frame type */
	uint8_t ff;         /* frame flags */
};

/* trace source and events */
static void h2_trace(enum trace_level level, uint64_t mask, \
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4);

static void h2_trace_fill_ctx(struct trace_ctx *ctx, const struct trace_source *src,
                              const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   strm  - application layer
 *   h2s   - internal H2 stream
 *   h2c   - internal H2 connection
 *   conn  - external connection
 *
 */
static const struct trace_event h2_trace_events[] = {
#define           H2_EV_H2C_NEW       (1ULL <<  0)
	{ .mask = H2_EV_H2C_NEW,      .name = "h2c_new",     .desc = "new H2 connection" },
#define           H2_EV_H2C_RECV      (1ULL <<  1)
	{ .mask = H2_EV_H2C_RECV,     .name = "h2c_recv",    .desc = "Rx on H2 connection" },
#define           H2_EV_H2C_SEND      (1ULL <<  2)
	{ .mask = H2_EV_H2C_SEND,     .name = "h2c_send",    .desc = "Tx on H2 connection" },
#define           H2_EV_H2C_FCTL      (1ULL <<  3)
	{ .mask = H2_EV_H2C_FCTL,     .name = "h2c_fctl",    .desc = "H2 connection flow-controlled" },
#define           H2_EV_H2C_BLK       (1ULL <<  4)
	{ .mask = H2_EV_H2C_BLK,      .name = "h2c_blk",     .desc = "H2 connection blocked" },
#define           H2_EV_H2C_WAKE      (1ULL <<  5)
	{ .mask = H2_EV_H2C_WAKE,     .name = "h2c_wake",    .desc = "H2 connection woken up" },
#define           H2_EV_H2C_END       (1ULL <<  6)
	{ .mask = H2_EV_H2C_END,      .name = "h2c_end",     .desc = "H2 connection terminated" },
#define           H2_EV_H2C_ERR       (1ULL <<  7)
	{ .mask = H2_EV_H2C_ERR,      .name = "h2c_err",     .desc = "error on H2 connection" },
#define           H2_EV_RX_FHDR       (1ULL <<  8)
	{ .mask = H2_EV_RX_FHDR,      .name = "rx_fhdr",     .desc = "H2 frame header received" },
#define           H2_EV_RX_FRAME      (1ULL <<  9)
	{ .mask = H2_EV_RX_FRAME,     .name = "rx_frame",    .desc = "receipt of any H2 frame" },
#define           H2_EV_RX_EOI        (1ULL << 10)
	{ .mask = H2_EV_RX_EOI,       .name = "rx_eoi",      .desc = "receipt of end of H2 input (ES or RST)" },
#define           H2_EV_RX_PREFACE    (1ULL << 11)
	{ .mask = H2_EV_RX_PREFACE,   .name = "rx_preface",  .desc = "receipt of H2 preface" },
#define           H2_EV_RX_DATA       (1ULL << 12)
	{ .mask = H2_EV_RX_DATA,      .name = "rx_data",     .desc = "receipt of H2 DATA frame" },
#define           H2_EV_RX_HDR        (1ULL << 13)
	{ .mask = H2_EV_RX_HDR,       .name = "rx_hdr",      .desc = "receipt of H2 HEADERS frame" },
#define           H2_EV_RX_PRIO       (1ULL << 14)
	{ .mask = H2_EV_RX_PRIO,      .name = "rx_prio",     .desc = "receipt of H2 PRIORITY frame" },
#define           H2_EV_RX_RST        (1ULL << 15)
	{ .mask = H2_EV_RX_RST,       .name = "rx_rst",      .desc = "receipt of H2 RST_STREAM frame" },
#define           H2_EV_RX_SETTINGS   (1ULL << 16)
	{ .mask = H2_EV_RX_SETTINGS,  .name = "rx_settings", .desc = "receipt of H2 SETTINGS frame" },
#define           H2_EV_RX_PUSH       (1ULL << 17)
	{ .mask = H2_EV_RX_PUSH,      .name = "rx_push",     .desc = "receipt of H2 PUSH_PROMISE frame" },
#define           H2_EV_RX_PING       (1ULL << 18)
	{ .mask = H2_EV_RX_PING,      .name = "rx_ping",     .desc = "receipt of H2 PING frame" },
#define           H2_EV_RX_GOAWAY     (1ULL << 19)
	{ .mask = H2_EV_RX_GOAWAY,    .name = "rx_goaway",   .desc = "receipt of H2 GOAWAY frame" },
#define           H2_EV_RX_WU         (1ULL << 20)
	{ .mask = H2_EV_RX_WU,        .name = "rx_wu",       .desc = "receipt of H2 WINDOW_UPDATE frame" },
#define           H2_EV_RX_CONT       (1ULL << 21)
	{ .mask = H2_EV_RX_CONT,      .name = "rx_cont",     .desc = "receipt of H2 CONTINUATION frame" },
#define           H2_EV_TX_FRAME      (1ULL << 22)
	{ .mask = H2_EV_TX_FRAME,     .name = "tx_frame",    .desc = "transmission of any H2 frame" },
#define           H2_EV_TX_EOI        (1ULL << 23)
	{ .mask = H2_EV_TX_EOI,       .name = "tx_eoi",      .desc = "transmission of H2 end of input (ES or RST)" },
#define           H2_EV_TX_PREFACE    (1ULL << 24)
	{ .mask = H2_EV_TX_PREFACE,   .name = "tx_preface",  .desc = "transmission of H2 preface" },
#define           H2_EV_TX_DATA       (1ULL << 25)
	{ .mask = H2_EV_TX_DATA,      .name = "tx_data",     .desc = "transmission of H2 DATA frame" },
#define           H2_EV_TX_HDR        (1ULL << 26)
	{ .mask = H2_EV_TX_HDR,       .name = "tx_hdr",      .desc = "transmission of H2 HEADERS frame" },
#define           H2_EV_TX_PRIO       (1ULL << 27)
	{ .mask = H2_EV_TX_PRIO,      .name = "tx_prio",     .desc = "transmission of H2 PRIORITY frame" },
#define           H2_EV_TX_RST        (1ULL << 28)
	{ .mask = H2_EV_TX_RST,       .name = "tx_rst",      .desc = "transmission of H2 RST_STREAM frame" },
#define           H2_EV_TX_SETTINGS   (1ULL << 29)
	{ .mask = H2_EV_TX_SETTINGS,  .name = "tx_settings", .desc = "transmission of H2 SETTINGS frame" },
#define           H2_EV_TX_PUSH       (1ULL << 30)
	{ .mask = H2_EV_TX_PUSH,      .name = "tx_push",     .desc = "transmission of H2 PUSH_PROMISE frame" },
#define           H2_EV_TX_PING       (1ULL << 31)
	{ .mask = H2_EV_TX_PING,      .name = "tx_ping",     .desc = "transmission of H2 PING frame" },
#define           H2_EV_TX_GOAWAY     (1ULL << 32)
	{ .mask = H2_EV_TX_GOAWAY,    .name = "tx_goaway",   .desc = "transmission of H2 GOAWAY frame" },
#define           H2_EV_TX_WU         (1ULL << 33)
	{ .mask = H2_EV_TX_WU,        .name = "tx_wu",       .desc = "transmission of H2 WINDOW_UPDATE frame" },
#define           H2_EV_TX_CONT       (1ULL << 34)
	{ .mask = H2_EV_TX_CONT,      .name = "tx_cont",     .desc = "transmission of H2 CONTINUATION frame" },
#define           H2_EV_H2S_NEW       (1ULL << 35)
	{ .mask = H2_EV_H2S_NEW,      .name = "h2s_new",     .desc = "new H2 stream" },
#define           H2_EV_H2S_RECV      (1ULL << 36)
	{ .mask = H2_EV_H2S_RECV,     .name = "h2s_recv",    .desc = "Rx for H2 stream" },
#define           H2_EV_H2S_SEND      (1ULL << 37)
	{ .mask = H2_EV_H2S_SEND,     .name = "h2s_send",    .desc = "Tx for H2 stream" },
#define           H2_EV_H2S_FCTL      (1ULL << 38)
	{ .mask = H2_EV_H2S_FCTL,     .name = "h2s_fctl",    .desc = "H2 stream flow-controlled" },
#define           H2_EV_H2S_BLK       (1ULL << 39)
	{ .mask = H2_EV_H2S_BLK,      .name = "h2s_blk",     .desc = "H2 stream blocked" },
#define           H2_EV_H2S_WAKE      (1ULL << 40)
	{ .mask = H2_EV_H2S_WAKE,     .name = "h2s_wake",    .desc = "H2 stream woken up" },
#define           H2_EV_H2S_END       (1ULL << 41)
	{ .mask = H2_EV_H2S_END,      .name = "h2s_end",     .desc = "H2 stream terminated" },
#define           H2_EV_H2S_ERR       (1ULL << 42)
	{ .mask = H2_EV_H2S_ERR,      .name = "h2s_err",     .desc = "error on H2 stream" },
#define           H2_EV_STRM_NEW      (1ULL << 43)
	{ .mask = H2_EV_STRM_NEW,     .name = "strm_new",    .desc = "app-layer stream creation" },
#define           H2_EV_STRM_RECV     (1ULL << 44)
	{ .mask = H2_EV_STRM_RECV,    .name = "strm_recv",   .desc = "receiving data for stream" },
#define           H2_EV_STRM_SEND     (1ULL << 45)
	{ .mask = H2_EV_STRM_SEND,    .name = "strm_send",   .desc = "sending data for stream" },
#define           H2_EV_STRM_FULL     (1ULL << 46)
	{ .mask = H2_EV_STRM_FULL,    .name = "strm_full",   .desc = "stream buffer full" },
#define           H2_EV_STRM_WAKE     (1ULL << 47)
	{ .mask = H2_EV_STRM_WAKE,    .name = "strm_wake",   .desc = "stream woken up" },
#define           H2_EV_STRM_SHUT     (1ULL << 48)
	{ .mask = H2_EV_STRM_SHUT,    .name = "strm_shut",   .desc = "stream shutdown" },
#define           H2_EV_STRM_END      (1ULL << 49)
	{ .mask = H2_EV_STRM_END,     .name = "strm_end",    .desc = "detaching app-layer stream" },
#define           H2_EV_STRM_ERR      (1ULL << 50)
	{ .mask = H2_EV_STRM_ERR,     .name = "strm_err",    .desc = "stream error" },
#define           H2_EV_PROTO_ERR     (1ULL << 51)
	{ .mask = H2_EV_PROTO_ERR,    .name = "proto_err",   .desc = "protocol error" },
	{ }
};

static const struct name_desc h2_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="h2s", .desc="H2 stream" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc h2_trace_decoding[] = {
#define H2_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define H2_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only h2c/h2s state and flags, no real decoding" },
#define H2_VERB_SIMPLE   3
	{ .name="simple",   .desc="add request/response status line or frame info when available" },
#define H2_VERB_ADVANCED 4
	{ .name="advanced", .desc="add header fields or frame decoding when available" },
#define H2_VERB_COMPLETE 5
	{ .name="complete", .desc="add full data dump when available" },
	{ /* end */ }
};

static struct trace_source trace_h2 __read_mostly = {
	.name = IST("h2"),
	.desc = "HTTP/2 multiplexer",
	.arg_def = TRC_ARG1_CONN,  // TRACE()'s first argument is always a connection
	.default_cb = h2_trace,
	.fill_ctx = h2_trace_fill_ctx,
	.known_events = h2_trace_events,
	.lockon_args = h2_trace_lockon_args,
	.decoding = h2_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_h2
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* h2 stats module */
enum {
	H2_ST_HEADERS_RCVD,
	H2_ST_DATA_RCVD,
	H2_ST_SETTINGS_RCVD,
	H2_ST_RST_STREAM_RCVD,
	H2_ST_GOAWAY_RCVD,

	H2_ST_CONN_PROTO_ERR,
	H2_ST_STRM_PROTO_ERR,
	H2_ST_RST_STREAM_RESP,
	H2_ST_GOAWAY_RESP,

	H2_ST_OPEN_CONN,
	H2_ST_OPEN_STREAM,
	H2_ST_TOTAL_CONN,
	H2_ST_TOTAL_STREAM,

	H2_STATS_COUNT /* must be the last member of the enum */
};

static struct stat_col h2_stats[] = {
	[H2_ST_HEADERS_RCVD]    = { .name = "h2_headers_rcvd",
	                            .desc = "Total number of received HEADERS frames" },
	[H2_ST_DATA_RCVD]       = { .name = "h2_data_rcvd",
	                            .desc = "Total number of received DATA frames" },
	[H2_ST_SETTINGS_RCVD]   = { .name = "h2_settings_rcvd",
	                            .desc = "Total number of received SETTINGS frames" },
	[H2_ST_RST_STREAM_RCVD] = { .name = "h2_rst_stream_rcvd",
	                            .desc = "Total number of received RST_STREAM frames" },
	[H2_ST_GOAWAY_RCVD]     = { .name = "h2_goaway_rcvd",
	                            .desc = "Total number of received GOAWAY frames" },

	[H2_ST_CONN_PROTO_ERR]  = { .name = "h2_detected_conn_protocol_errors",
	                            .desc = "Total number of connection protocol errors" },
	[H2_ST_STRM_PROTO_ERR]  = { .name = "h2_detected_strm_protocol_errors",
	                            .desc = "Total number of stream protocol errors" },
	[H2_ST_RST_STREAM_RESP] = { .name = "h2_rst_stream_resp",
	                            .desc = "Total number of RST_STREAM sent on detected error" },
	[H2_ST_GOAWAY_RESP]     = { .name = "h2_goaway_resp",
	                            .desc = "Total number of GOAWAY sent on detected error" },

	[H2_ST_OPEN_CONN]    = { .name = "h2_open_connections",
	                         .desc = "Count of currently open connections" },
	[H2_ST_OPEN_STREAM]  = { .name = "h2_backend_open_streams",
	                         .desc = "Count of currently open streams" },
	[H2_ST_TOTAL_CONN]   = { .name = "h2_total_connections",
	                         .desc = "Total number of connections" },
	[H2_ST_TOTAL_STREAM] = { .name = "h2_backend_total_streams",
	                         .desc = "Total number of streams" },
};

static struct h2_counters {
	long long headers_rcvd;    /* total number of HEADERS frame received */
	long long data_rcvd;       /* total number of DATA frame received */
	long long settings_rcvd;   /* total number of SETTINGS frame received */
	long long rst_stream_rcvd; /* total number of RST_STREAM frame received */
	long long goaway_rcvd;     /* total number of GOAWAY frame received */

	long long conn_proto_err;  /* total number of protocol errors detected */
	long long strm_proto_err;  /* total number of protocol errors detected */
	long long rst_stream_resp; /* total number of RST_STREAM frame sent on error */
	long long goaway_resp;     /* total number of GOAWAY frame sent on error */

	long long open_conns;    /* count of currently open connections */
	long long open_streams;  /* count of currently open streams */
	long long total_conns;   /* total number of connections */
	long long total_streams; /* total number of streams */
} h2_counters;

static int h2_fill_stats(void *data, struct field *stats, unsigned int *selected_field)
{
	struct h2_counters *counters = data;
	unsigned int current_field = (selected_field != NULL ? *selected_field : 0);

	for (; current_field < H2_STATS_COUNT; current_field++) {
		struct field metric = { 0 };

		switch (current_field) {
		case H2_ST_HEADERS_RCVD:
			metric = mkf_u64(FN_COUNTER, counters->headers_rcvd);
			break;
		case H2_ST_DATA_RCVD:
			metric = mkf_u64(FN_COUNTER, counters->data_rcvd);
			break;
		case H2_ST_SETTINGS_RCVD:
			metric = mkf_u64(FN_COUNTER, counters->settings_rcvd);
			break;
		case H2_ST_RST_STREAM_RCVD:
			metric = mkf_u64(FN_COUNTER, counters->rst_stream_rcvd);
			break;
		case H2_ST_GOAWAY_RCVD:
			metric = mkf_u64(FN_COUNTER, counters->goaway_rcvd);
			break;
		case H2_ST_CONN_PROTO_ERR:
			metric = mkf_u64(FN_COUNTER, counters->conn_proto_err);
			break;
		case H2_ST_STRM_PROTO_ERR:
			metric = mkf_u64(FN_COUNTER, counters->strm_proto_err);
			break;
		case H2_ST_RST_STREAM_RESP:
			metric = mkf_u64(FN_COUNTER, counters->rst_stream_resp);
			break;
		case H2_ST_GOAWAY_RESP:
			metric = mkf_u64(FN_COUNTER, counters->goaway_resp);
			break;
		case H2_ST_OPEN_CONN:
			metric = mkf_u64(FN_GAUGE,   counters->open_conns);
			break;
		case H2_ST_OPEN_STREAM:
			metric = mkf_u64(FN_GAUGE,   counters->open_streams);
			break;
		case H2_ST_TOTAL_CONN:
			metric = mkf_u64(FN_COUNTER, counters->total_conns);
			break;
		case H2_ST_TOTAL_STREAM:
			metric = mkf_u64(FN_COUNTER, counters->total_streams);
			break;
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

static struct stats_module h2_stats_module = {
	.name          = "h2",
	.fill_stats    = h2_fill_stats,
	.stats         = h2_stats,
	.stats_count   = H2_STATS_COUNT,
	.counters      = &h2_counters,
	.counters_size = sizeof(h2_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_FE|STATS_PX_CAP_BE),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &h2_stats_module);

/* the h2c connection pool */
DECLARE_STATIC_POOL(pool_head_h2c, "h2c", sizeof(struct h2c));

/* the h2s stream pool */
DECLARE_STATIC_POOL(pool_head_h2s, "h2s", sizeof(struct h2s));

/* the shared rx_bufs pool */
struct pool_head *pool_head_h2_rx_bufs __read_mostly = NULL;

/* The default connection window size is 65535, it may only be enlarged using
 * a WINDOW_UPDATE message. Since the window must never be larger than 2G-1,
 * we'll pretend we already received the difference between the two to send
 * an equivalent window update to enlarge it to 2G-1.
 */
#define H2_INITIAL_WINDOW_INCREMENT ((1U<<31)-1 - 65535)

/* maximum amount of data we're OK with re-aligning for buffer optimizations */
#define MAX_DATA_REALIGN 1024

/* a few settings from the global section */
static int h2_settings_header_table_size      =  4096; /* initial value */
static int h2_settings_initial_window_size    =     0; /* default initial value: bufsize */
static int h2_be_settings_initial_window_size =     0; /* backend's default initial value */
static int h2_fe_settings_initial_window_size =     0; /* frontend's default initial value */
static int h2_be_glitches_threshold           =     0; /* backend's max glitches: unlimited */
static int h2_fe_glitches_threshold           =     0; /* frontend's max glitches: unlimited */
static uint h2_be_rxbuf                       =     0; /* backend's default total rxbuf (bytes) */
static uint h2_fe_rxbuf                       =     0; /* frontend's default total rxbuf (bytes) */
static unsigned int h2_settings_max_concurrent_streams    = 100; /* default value */
static unsigned int h2_be_settings_max_concurrent_streams =   0; /* backend value */
static unsigned int h2_fe_settings_max_concurrent_streams =   0; /* frontend value */
static int h2_settings_max_frame_size         = 0;     /* unset */

/* other non-protocol settings */
static unsigned int h2_fe_max_total_streams =   0;      /* frontend value */

/* a dummy closed endpoint */
static const struct sedesc closed_ep = {
	.sc        = NULL,
	.flags     = SE_FL_DETACHED,
};

/* a dmumy closed stream */
static const struct h2s *h2_closed_stream = &(const struct h2s){
	.sd        = (struct sedesc *)&closed_ep,
	.h2c       = NULL,
	.st        = H2_SS_CLOSED,
	.errcode   = H2_ERR_STREAM_CLOSED,
	.flags     = H2_SF_RST_RCVD,
	.id        = 0,
};

/* a dmumy closed stream returning a PROTOCOL_ERROR error */
static const struct h2s *h2_error_stream = &(const struct h2s){
	.sd        = (struct sedesc *)&closed_ep,
	.h2c       = NULL,
	.st        = H2_SS_CLOSED,
	.errcode   = H2_ERR_PROTOCOL_ERROR,
	.flags     = 0,
	.id        = 0,
};

/* a dmumy closed stream returning a REFUSED_STREAM error */
static const struct h2s *h2_refused_stream = &(const struct h2s){
	.sd        = (struct sedesc *)&closed_ep,
	.h2c       = NULL,
	.st        = H2_SS_CLOSED,
	.errcode   = H2_ERR_REFUSED_STREAM,
	.flags     = 0,
	.id        = 0,
};

/* and a dummy idle stream for use with any unannounced stream */
static const struct h2s *h2_idle_stream = &(const struct h2s){
	.sd        = (struct sedesc *)&closed_ep,
	.h2c       = NULL,
	.st        = H2_SS_IDLE,
	.errcode   = H2_ERR_STREAM_CLOSED,
	.id        = 0,
};


struct task *h2_timeout_task(struct task *t, void *context, unsigned int state);
static int h2_send(struct h2c *h2c);
static int h2_recv(struct h2c *h2c);
static int h2_process(struct h2c *h2c);
/* h2_io_cb is exported to see it resolved in "show fd" */
struct task *h2_io_cb(struct task *t, void *ctx, unsigned int state);
static inline struct h2s *h2c_st_by_id(struct h2c *h2c, int id);
static int h2c_dec_hdrs(struct h2c *h2c, struct buffer *rxbuf, uint32_t *flags, unsigned long long *body_len, char *upgrade_protocol);
static int h2_frt_transfer_data(struct h2s *h2s);
struct task *h2_deferred_shut(struct task *t, void *ctx, unsigned int state);
static struct h2s *h2c_bck_stream_new(struct h2c *h2c, struct stconn *sc, struct session *sess);
static void h2s_alert(struct h2s *h2s);
static inline void h2_remove_from_list(struct h2s *h2s);
static int h2_dump_h2c_info(struct buffer *msg, struct h2c *h2c, const char *pfx);
static int h2_dump_h2s_info(struct buffer *msg, const struct h2s *h2s, const char *pfx);
static inline struct buffer *h2s_rxbuf_head(const struct h2s *h2s);
static inline struct buffer *h2s_rxbuf_tail(const struct h2s *h2s);
static inline struct buffer *h2s_rxbuf_head(const struct h2s *h2s);
static inline struct buffer *h2s_rxbuf_tail(const struct h2s *h2s);

/* returns the stconn associated to the H2 stream */
static forceinline struct stconn *h2s_sc(const struct h2s *h2s)
{
	return h2s->sd->sc;
}

/* the H2 traces always expect that arg1, if non-null, is of type connection
 * (from which we can derive h2c), that arg2, if non-null, is of type h2s, and
 * that arg3, if non-null, is either of type htx for tx headers, or of type
 * buffer for everything else.
 */
static void h2_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct buffer *hmbuf, *tmbuf;
	const struct connection *conn = a1;
	const struct h2c *h2c    = conn ? conn->ctx : NULL;
	const struct h2s *h2s    = a2;
	const struct buffer *buf = a3;
	const struct htx *htx;
	int pos;

	if (!h2c) // nothing to add
		return;

	if (src->verbosity > H2_VERB_CLEAN) {
		chunk_appendf(&trace_buf, " : h2c=%p(%c=%s,%s,%#x)",
		              h2c, conn_is_back(conn) ? 'B' : 'F', h2c->proxy->id,
		              h2c_st_to_str(h2c->st0), h2c->flags);

		if (mask & H2_EV_H2C_NEW) // inside h2_init, otherwise it's hard to match conn & h2c
			conn_append_debug_info(&trace_buf, conn, " : ");

		if (h2c->errcode)
			chunk_appendf(&trace_buf, " err=%s/%02x", h2_err_str(h2c->errcode), h2c->errcode);

		if (h2c->glitches)
			chunk_appendf(&trace_buf, " glitches=%d", h2c->glitches);

		if (h2c->flags & H2_CF_DEM_IN_PROGRESS && // frame processing has started, type and length are valid
		    (mask & (H2_EV_RX_FRAME|H2_EV_RX_FHDR)) == (H2_EV_RX_FRAME|H2_EV_RX_FHDR)) {
			chunk_appendf(&trace_buf, " dft=%s/%02x dfl=%d", h2_ft_str(h2c->dft), h2c->dff, h2c->dfl);
		}

		hmbuf = br_head((struct buffer*)h2c->mbuf);
		tmbuf = br_tail((struct buffer*)h2c->mbuf);
		chunk_appendf(&trace_buf, " .dbuf=%u@%p+%u/%u .mbuf=[%u..%u|%u],h=[%u@%p+%u/%u],t=[%u@%p+%u/%u]",
		              (uint)b_data(&h2c->dbuf), b_orig(&h2c->dbuf),
		              (uint)b_head_ofs(&h2c->dbuf), (uint)b_size(&h2c->dbuf),
		              br_head_idx(h2c->mbuf), br_tail_idx(h2c->mbuf), br_size(h2c->mbuf),
		              (uint)b_data(hmbuf), b_orig(hmbuf),
		              (uint)b_head_ofs(hmbuf), (uint)b_size(hmbuf),
		              (uint)b_data(tmbuf), b_orig(tmbuf),
		              (uint)b_head_ofs(tmbuf), (uint)b_size(tmbuf));

		if (h2s) {
			if (h2s->id <= 0)
				chunk_appendf(&trace_buf, " dsi=%d", h2c->dsi);
			if (h2s == h2_idle_stream)
				chunk_appendf(&trace_buf, " h2s=IDL");
			else if (h2s != h2_closed_stream && h2s != h2_refused_stream && h2s != h2_error_stream) {
				const struct buffer *head, *tail;

				head = h2s_rxbuf_head(h2s);
				tail = h2s_rxbuf_tail(h2s);
				chunk_appendf(&trace_buf, " h2s=%p(%d,%s,%#x) .txw=%d .rxw=%u .rxb.c=%u .h=%u@%p+%u/%u .t=%u@%p+%u/%u",
				              h2s, h2s->id, h2s_st_to_str(h2s->st), h2s->flags,
				              h2s->sws + h2c->miw, (uint)(h2s->next_max_ofs - h2s->curr_rx_ofs),
				              h2s->rx_count,
				              head ? (uint)b_data(head) : 0,
				              head ? b_orig(head) : NULL,
				              head ? (uint)b_head_ofs(head) : 0,
				              head ? (uint)b_size(head) : 0,
				              tail ? (uint)b_data(tail) : 0,
				              tail ? b_orig(tail) : NULL,
				              tail ? (uint)b_head_ofs(tail) : 0,
				              tail ? (uint)b_size(tail) : 0);
			}
			else if (h2c->dsi > 0) // don't show that before sid is known
				chunk_appendf(&trace_buf, " h2s=CLO");
			if (h2s->id && h2s->errcode)
				chunk_appendf(&trace_buf, " err=%s/%02x", h2_err_str(h2s->errcode), h2s->errcode);
		}

		if ((mask & H2_EV_RX_DATA) && level == TRACE_LEVEL_DATA)
			chunk_appendf(&trace_buf, " data=%lu", (ulong)a4);
	}

	/* Let's dump decoded requests and responses right after parsing. They
	 * are traced at level USER with a few recognizable flags.
	 */
	if ((mask == (H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW) ||
	     mask == (H2_EV_RX_FRAME|H2_EV_RX_HDR)) && buf)
		htx = htxbuf(buf); // recv req/res
	else if (mask == (H2_EV_TX_FRAME|H2_EV_TX_HDR))
		htx = a3; // send req/res
	else
		htx = NULL;

	if (level == TRACE_LEVEL_USER && src->verbosity != H2_VERB_MINIMAL && htx && (pos = htx_get_head(htx)) != -1) {
		const struct htx_blk    *blk  = htx_get_blk(htx, pos);
		const struct htx_sl     *sl   = htx_get_blk_ptr(htx, blk);
		enum htx_blk_type        type = htx_get_blk_type(blk);

		if (type == HTX_BLK_REQ_SL)
			chunk_appendf(&trace_buf, " : [%d] H2 REQ: %.*s %.*s %.*s",
				      h2s ? h2s->id : h2c->dsi,
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
		else if (type == HTX_BLK_RES_SL)
			chunk_appendf(&trace_buf, " : [%d] H2 RES: %.*s %.*s %.*s",
				      h2s ? h2s->id : h2c->dsi,
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
	}
}

/* This fills the trace_ctx with extra info guessed from the args */
static void h2_trace_fill_ctx(struct trace_ctx *ctx, const struct trace_source *src,
                              const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct h2c *h2c = conn ? conn->ctx : NULL;
	const struct h2s *h2s    = a2;

	if (!ctx->conn)
		ctx->conn = conn;

	if (h2c) {
		if (!ctx->fe && !(h2c->flags & H2_CF_IS_BACK))
			ctx->fe = h2c->proxy;

		if (!ctx->be && (h2c->flags & H2_CF_IS_BACK))
			ctx->be = h2c->proxy;
	}

	if (h2s) {
		if (!ctx->sess)
			ctx->sess = h2s->sess;
		if (!ctx->strm && h2s->sd && h2s_sc(h2s))
			ctx->strm = sc_strm(h2s_sc(h2s));
	}
}

static inline void h2c_report_term_evt(struct h2c *h2c, enum muxc_term_event_type type)
{
	enum term_event_loc loc = tevt_loc_muxc;

	if (h2c->flags & H2_CF_IS_BACK)
		loc += 8;
	h2c->term_evts_log = tevt_report_event(h2c->term_evts_log, loc, type);
}

/* Detect a pending read0 for a H2 connection. It happens if a read0 was
 * already reported on a previous xprt->rcvbuf() AND a frame parser failed
 * to parse pending data, confirming no more progress is possible because
 * we're facing a truncated frame. The function returns 1 to report a read0
 * or 0 otherwise.
 */
static inline int h2c_read0_pending(struct h2c *h2c)
{
	return !!(h2c->flags & H2_CF_END_REACHED);
}

/* returns true if the connection is allowed to expire, false otherwise. A
 * connection may expire when it has no attached streams. As long as streams
 * are attached, the application layer is responsible for timeout management,
 * and each layer will detach when it doesn't want to wait anymore. When the
 * last one leaves, the connection must take over timeout management.
 */
static inline int h2c_may_expire(const struct h2c *h2c)
{
	return !h2c->nb_sc;
}

/* returns the number of max concurrent streams permitted on a connection,
 * depending on its side (frontend or backend), falling back to the default
 * h2_settings_max_concurrent_streams. It may even be zero.
 */
static inline int h2c_max_concurrent_streams(const struct h2c *h2c)
{
	int ret;

	ret = (h2c->flags & H2_CF_IS_BACK) ?
		h2_be_settings_max_concurrent_streams :
		h2_fe_settings_max_concurrent_streams;

	ret = ret ? ret : h2_settings_max_concurrent_streams;
	return ret;
}

/* Returns a pointer to the oldest rxbuf of the stream, which must exist.
 * Note that this doesn't indicate that the buffer is allocated nor contains
 * any data.
 */
static inline struct buffer *_h2s_rxbuf_head(const struct h2s *h2s)
{
	return &h2s->h2c->shared_rx_bufs[h2s->rx_head].buf;
}

/* Returns a pointer to the newest rxbuf of the stream, which must exist.
 * Note that this doesn't indicate that the buffer is allocated nor contains
 * any data.
 */
static inline struct buffer *_h2s_rxbuf_tail(const struct h2s *h2s)
{
	return &h2s->h2c->shared_rx_bufs[h2s->rx_tail].buf;
}

/* Returns a pointer to the oldest rxbuf of the stream, or NULL if there is
 * none. Note that this doesn't indicate that the buffer is allocated nor
 * contains any data.
 */
static inline struct buffer *h2s_rxbuf_head(const struct h2s *h2s)
{
	return h2s->rx_head ? _h2s_rxbuf_head(h2s) : NULL;
}

/* Returns a pointer to the newest rxbuf of the stream, or NULL if there is
 * none. Note that this doesn't indicate that the buffer is allocated nor
 * contains any data.
 */
static inline struct buffer *h2s_rxbuf_tail(const struct h2s *h2s)
{
	return h2s->rx_tail ? _h2s_rxbuf_tail(h2s) : NULL;
}

/* Returns the number of allocated rxbuf slots for the stream */
static inline uint h2s_rxbuf_cnt(const struct h2s *h2s)
{
	return h2s->rx_count;
}

/* Tries to get an rxbuf slot from the connection for the stream, returns its
 * non-zero number on success, or 0 on failure. On success, it will update the
 * stream's tail and count, and possibly head (if there was no buffer before).
 * The buffer cell is not initialized, it's up to the caller to do it.
 */
static inline uint h2s_get_rxbuf(struct h2s *h2s)
{
	uint slot;

	slot = bl_get(h2s->h2c->shared_rx_bufs, h2s->rx_tail);
	if (!slot)
		return 0;

	h2s->rx_count++;
	h2s->rx_tail = slot;
	if (!h2s->rx_head)
		h2s->rx_head = slot;
	return slot;
}

/* Gives back the oldest rxbuf to the connection. It's the caller's
 * responsibility to make sure that the possible buffer there was released
 * prior to calling this function (it may change in the future). It's safe
 * to call this if no rxbufs are allocated. The index of the next remaining
 * rxbuf slot is returned, or 0 when none remain.
 */
static inline uint h2s_put_rxbuf(struct h2s *h2s)
{
	if (h2s->rx_head) {
		BUG_ON_HOT(({ const struct buffer *buf = h2s_rxbuf_head(h2s); !!(buf && b_size(buf)); }),
			   "Attempted to release a used buffer slot");
		h2s->rx_head = bl_put(h2s->h2c->shared_rx_bufs, h2s->rx_head);
		if (!h2s->rx_head)
			h2s->rx_tail = 0;
		h2s->rx_count--;
	}
	return h2s->rx_head;
}

/* Checks if the the HTX rxbuf still has available room. Returns 1 if OK, 0 if
 * it's full. The buffer is cast to HTX for the operation, but no buffer is
 * allocated if there is none (in which case 0 is returned).
 */
static inline int h2s_may_append_to_rxbuf(const struct h2s *h2s)
{
	struct buffer *rxbuf;
	struct htx *htx;

	rxbuf = h2s_rxbuf_tail(h2s);
	if (!rxbuf || b_is_null(rxbuf))
		return 0;

	htx = htxbuf(rxbuf);
	return !!htx_free_data_space(htx);
}

/* update h2c timeout if needed */
static void h2c_update_timeout(struct h2c *h2c)
{
	int is_idle_conn = 0;

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	if (!h2c->task)
		goto leave;

	if (h2c_may_expire(h2c)) {
		/* no more streams attached */
		if (br_data(h2c->mbuf)) {
			/* pending output data: always the regular data timeout */
			h2c->task->expire = tick_add_ifset(now_ms, h2c->timeout);
		} else {
			/* no stream, no output data */
			if (h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED)) {
				/* GOAWAY sent (or failed), closing in progress */
				int exp = tick_add_ifset(now_ms, h2c->shut_timeout);

				h2c->task->expire = tick_first(h2c->task->expire, exp);
				is_idle_conn = 1;
			}
			else if (!(h2c->flags & H2_CF_IS_BACK)) {
				int to;

				if (h2c->max_id > 0 && !b_data(&h2c->dbuf) &&
				    tick_isset(h2c->proxy->timeout.httpka)) {
					/* idle after having seen one stream => keep-alive */
					to = h2c->proxy->timeout.httpka;
				} else {
					/* before first request, or started to deserialize a
					 * new req => http-request.
					 */
					to = h2c->proxy->timeout.httpreq;
				}

				h2c->task->expire = tick_add_ifset(h2c->idle_start, to);
				is_idle_conn = 1;
			}

			/* if a timeout above was not set, fall back to the default one */
			if (!tick_isset(h2c->task->expire))
				h2c->task->expire = tick_add_ifset(now_ms, h2c->timeout);
		}

		if ((h2c->proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) &&
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
				if (tick_isset(h2c->task->expire) &&
				    tick_is_le(global.close_spread_end, h2c->task->expire)) {
					/* Set an expire value shorter than the current value
					 * because the close spread window end comes earlier.
					 */
					h2c->task->expire = tick_add(now_ms, statistical_prng_range(remaining_window));
				}
			}
			else {
				/* We are past the soft close window end, wake the timeout
				 * task up immediately.
				 */
				task_wakeup(h2c->task, TASK_WOKEN_TIMER);
			}
		}

	} else {
		h2c->task->expire = TICK_ETERNITY;
	}
	task_queue(h2c->task);
 leave:
	TRACE_LEAVE(H2_EV_H2C_WAKE);
}

static __inline int
h2c_is_dead(const struct h2c *h2c)
{
	if (eb_is_empty(&h2c->streams_by_id) &&     /* don't close if streams exist */
	    ((h2c->flags & H2_CF_ERROR) ||          /* errors close immediately */
	     (h2c->flags & H2_CF_ERR_PENDING && h2c->st0 < H2_CS_FRAME_H) || /* early error during connect */
	     (h2c->st0 >= H2_CS_ERROR && !h2c->task) || /* a timeout stroke earlier */
	     (!(h2c->conn->owner) && !conn_is_reverse(h2c->conn)) || /* Nobody's left to take care of the connection, drop it now */
	     (!br_data(h2c->mbuf) &&  /* mux buffer empty, also process clean events below */
	      ((h2c->flags & H2_CF_RCVD_SHUT) ||
	       (h2c->last_sid >= 0 && h2c->max_id >= h2c->last_sid)))))
		return 1;

	return 0;
}

/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/

/* indicates whether or not the we may call the h2_recv() function to attempt
 * to receive data into the buffer and/or demux pending data. The condition is
 * a bit complex due to some API limits for now. The rules are the following :
 *   - if an error or a shutdown was detected on the connection, we must not
 *     attempt to receive
 *   - if we're subscribed for receving, no need to try again
 *   - if the demux buf failed to be allocated, we must not try to receive and
 *     we know there is nothing pending (we'll be woken up once allocated)
 *   - if the demux buf is full, we will not be able to receive.
 *   - otherwise we may attempt to receive
 */
static inline int h2_recv_allowed(const struct h2c *h2c)
{
	if ((h2c->flags & (H2_CF_RCVD_SHUT|H2_CF_ERROR)) || h2c->st0 >= H2_CS_ERROR)
		return 0;

	if ((h2c->wait_event.events & SUB_RETRY_RECV))
		return 0;

	if (h2c->flags & (H2_CF_DEM_DALLOC | H2_CF_DEM_DFULL))
		return 0;

	return 1;
}

/* Indicates whether it's worth waking up the I/O handler to restart demuxing.
 * Its conditions are the following:
 *   - if the buffer is empty and the connection is in error, there's nothing
 *     to demux
 *   - if a short read was reported, no need to try demuxing again
 *   - if some blocking conditions remain, no need to try again
 *   - otherwise it's safe to try demuxing again
 */
static inline int h2_may_demux(const struct h2c *h2c)
{
	if (h2c->st0 >= H2_CS_ERROR && !b_data(&h2c->dbuf))
		return 0;

	if (h2c->flags & H2_CF_DEM_SHORT_READ)
		return 0;

	if (h2c->flags & H2_CF_DEM_BLOCK_ANY)
		return 0;

	return 1;
}

/* restarts reading/processing on the connection if we can receive or demux
 * (both are called from the same tasklet).
 */
static inline void h2c_restart_reading(const struct h2c *h2c, int consider_buffer)
{
	if (!h2_recv_allowed(h2c) && !h2_may_demux(h2c))
		return;
	tasklet_wakeup(h2c->wait_event.tasklet);
}


/* returns true if the front connection has too many stream connectors attached */
static inline int h2_frt_has_too_many_sc(const struct h2c *h2c)
{
	return h2c->nb_sc > h2c_max_concurrent_streams(h2c) ||
	       unlikely(conn_reverse_in_preconnect(h2c->conn));
}

/* Tries to grab a buffer and to re-enable processing on mux <target>. The h2c
 * flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the connection is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
static int h2_buf_available(void *target)
{
	struct h2c *h2c = target;
	struct h2s *h2s;

	if ((h2c->flags & H2_CF_DEM_DALLOC) && b_alloc(&h2c->dbuf, DB_MUX_RX)) {
		h2c->flags &= ~H2_CF_DEM_DALLOC;
		h2c_restart_reading(h2c, 1);
		return 1;
	}

	if ((h2c->flags & H2_CF_MUX_MALLOC) && b_alloc(br_tail(h2c->mbuf), DB_MUX_TX)) {
		h2c->flags &= ~H2_CF_MUX_MALLOC;

		if (h2c->flags & H2_CF_DEM_MROOM) {
			h2c->flags &= ~H2_CF_DEM_MROOM;
			h2c_restart_reading(h2c, 1);
		}
		return 1;
	}

	if ((h2c->flags & H2_CF_DEM_SALLOC) &&
	    (h2s = h2c_st_by_id(h2c, h2c->dsi)) && h2s_sc(h2s) &&
	    (h2s_rxbuf_tail(h2s) || h2s_get_rxbuf(h2s))) {
		h2c->flags &= ~(H2_CF_DEM_RXBUF | H2_CF_DEM_SFULL);
		if (b_alloc(_h2s_rxbuf_tail(h2s), DB_SE_RX)) {
			h2c->flags &= ~H2_CF_DEM_SALLOC;
			h2c_restart_reading(h2c, 1);
			return 1;
		}
	}

	return 0;
}

static inline struct buffer *h2_get_buf(struct h2c *h2c, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&h2c->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr, DB_MUX_RX)) == NULL)) {
		b_queue(DB_MUX_RX, &h2c->buf_wait, h2c, h2_buf_available);
	}
	return buf;
}

static inline void h2_release_buf(struct h2c *h2c, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(NULL, 1);
	}
}

static inline void h2_release_mbuf(struct h2c *h2c)
{
	struct buffer *buf;
	unsigned int count = 0;

	while (b_size(buf = br_head_pick(h2c->mbuf))) {
		b_free(buf);
		count++;
	}

	h2c->flags &= ~(H2_CF_MUX_MFULL | H2_CF_DEM_MROOM);

	if (count)
		offer_buffers(NULL, count);
}

/* returns the number of allocatable outgoing streams for the connection taking
 * the last_sid and the reserved ones into account.
 */
static inline int h2_streams_left(const struct h2c *h2c)
{
	int ret;

	/* consider the number of outgoing streams we're allowed to create before
	 * reaching the last GOAWAY frame seen. max_id is the last assigned id,
	 * nb_reserved is the number of streams which don't yet have an ID.
	 */
	ret = (h2c->last_sid >= 0) ? h2c->last_sid : 0x7FFFFFFF;
	ret = (unsigned int)(ret - h2c->max_id) / 2 - h2c->nb_reserved - 1;
	if (ret < 0)
		ret = 0;
	return ret;
}

/* returns the number of streams in use on a connection to figure if it's
 * idle or not. We check nb_sc and not nb_streams as the caller will want
 * to know if it was the last one after a detach().
 */
static int h2_used_streams(struct connection *conn)
{
	struct h2c *h2c = conn->ctx;

	return h2c->nb_sc;
}

/* returns the number of concurrent streams available on the connection */
static int h2_avail_streams(struct connection *conn)
{
	struct server *srv = objt_server(conn->target);
	struct h2c *h2c = conn->ctx;
	int ret1, ret2;

	/* RFC7540#6.8: Receivers of a GOAWAY frame MUST NOT open additional
	 * streams on the connection.
	 */
	if (h2c->last_sid >= 0)
		return 0;

	if (h2c->st0 >= H2_CS_ERROR)
		return 0;

	/* note: may be negative if a SETTINGS frame changes the limit */
	ret1 = h2c->streams_limit - h2c->nb_streams;

	/* we must also consider the limit imposed by stream IDs */
	ret2 = h2_streams_left(h2c);
	ret1 = MIN(ret1, ret2);
	if (ret1 > 0 && srv && srv->max_reuse >= 0) {
		ret2 = h2c->stream_cnt <= srv->max_reuse ? srv->max_reuse - h2c->stream_cnt + 1: 0;
		ret1 = MIN(ret1, ret2);
	}
	return ret1;
}

/* Unconditionally produce a trace of the header. Please do not call this one
 * and use h2_trace_header() instead which first checks if traces are enabled.
 */
void _h2_trace_header(const struct ist hn, const struct ist hv,
		      uint64_t mask, const struct ist trc_loc, const char *func,
		      const struct h2c *h2c, const struct h2s *h2s)
{
	struct ist n_ist, v_ist;
	const char *c_str, *s_str;

	chunk_reset(&trash);
	c_str = chunk_newstr(&trash);
	if (h2c) {
		chunk_appendf(&trash, "h2c=%p(%c,%s) ",
			      h2c, (h2c->flags & H2_CF_IS_BACK) ? 'B' : 'F', h2c_st_to_str(h2c->st0));
	}

	s_str = chunk_newstr(&trash);
	if (h2s) {
		if (h2s->id <= 0)
			chunk_appendf(&trash, "dsi=%d ", h2s->h2c->dsi);
		chunk_appendf(&trash, "h2s=%p(%d,%s) ", h2s, h2s->id, h2s_st_to_str(h2s->st));
	}
	else if (h2c)
		chunk_appendf(&trash, "dsi=%d ", h2c->dsi);

	n_ist = ist2(chunk_newstr(&trash), 0);
	istscpy(&n_ist, hn, 256);
	trash.data += n_ist.len;
	if (n_ist.len != hn.len)
		chunk_appendf(&trash, " (... +%ld)", (long)(hn.len - n_ist.len));

	v_ist = ist2(chunk_newstr(&trash), 0);
	istscpy(&v_ist, hv, 1024);
	trash.data += v_ist.len;
	if (v_ist.len != hv.len)
		chunk_appendf(&trash, " (... +%ld)", (long)(hv.len - v_ist.len));

	TRACE_PRINTF_LOC(TRACE_LEVEL_USER, mask, trc_loc, func,
	                 (h2c ? h2c->conn : 0), 0, 0, 0,
	                 "%s%s%s %s: %s", c_str, s_str,
	                 (mask & H2_EV_TX_HDR) ? "sndh" : "rcvh",
	                 n_ist.ptr, v_ist.ptr);
}

/* produce a trace of the header after checking that tracing is enabled */
static inline void h2_trace_header(const struct ist hn, const struct ist hv,
				   uint64_t mask, const struct ist trc_loc, const char *func,
				   const struct h2c *h2c, const struct h2s *h2s)
{
	if ((TRACE_SOURCE)->verbosity >= H2_VERB_ADVANCED &&
	    TRACE_ENABLED(TRACE_LEVEL_USER, mask, h2c ? h2c->conn : 0, h2s, 0, 0))
		_h2_trace_header(hn, hv, mask, trc_loc, func, h2c, h2s);
}

/* hpack-encode header name <hn> and value <hv>, possibly emitting a trace if
 * currently enabled. This is done on behalf of function <func> at <trc_loc>
 * passed as ist(TRC_LOC), h2c <h2c>, and h2s <h2s>, all of which may be NULL.
 * The trace is only emitted if the header is emitted (in which case non-zero
 * is returned). The trash is modified. In the traces, the header's name will
 * be truncated to 256 chars and the header's value to 1024 chars.
 */
static inline int h2_encode_header(struct buffer *buf, const struct ist hn, const struct ist hv,
				   uint64_t mask, const struct ist trc_loc, const char *func,
				   const struct h2c *h2c, const struct h2s *h2s)
{
	int ret;

	ret = hpack_encode_header(buf, hn, hv);
	if (ret)
		h2_trace_header(hn, hv, mask, trc_loc, func, h2c, h2s);

	return ret;
}

/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/

/* Initialize the mux once it's attached. For outgoing connections, the context
 * is already initialized before installing the mux, so we detect incoming
 * connections from the fact that the context is still NULL (even during mux
 * upgrades). <input> is always used as Input buffer and may contain data. It is
 * the caller responsibility to not reuse it anymore. Returns < 0 on error.
 */
static int h2_init(struct connection *conn, struct proxy *prx, struct session *sess,
		   struct buffer *input)
{
	struct h2c *h2c;
	struct task *t = NULL;
	void *conn_ctx = conn->ctx;
	uint nb_rxbufs;

	TRACE_ENTER(H2_EV_H2C_NEW);

	h2c = pool_alloc(pool_head_h2c);
	if (!h2c)
		goto fail_no_h2c;

	if (conn_is_back(conn)) {
		h2c->flags = H2_CF_IS_BACK;
		h2c->shut_timeout = h2c->timeout = prx->timeout.server;
		if (tick_isset(prx->timeout.serverfin))
			h2c->shut_timeout = prx->timeout.serverfin;

		h2c->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_be,
		                                      &h2_stats_module);
	} else {
		h2c->flags = H2_CF_NONE;
		h2c->shut_timeout = h2c->timeout = prx->timeout.client;
		if (tick_isset(prx->timeout.clientfin))
			h2c->shut_timeout = prx->timeout.clientfin;

		h2c->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                                      &h2_stats_module);
	}

	h2c->proxy = prx;
	h2c->task = NULL;
	h2c->wait_event.tasklet = NULL;
	h2c->next_tasklet = NULL;
	h2c->shared_rx_bufs = NULL;
	h2c->idle_start = now_ms;
	if (tick_isset(h2c->timeout)) {
		t = task_new_here();
		if (!t)
			goto fail;

		h2c->task = t;
		t->process = h2_timeout_task;
		t->context = h2c;
		t->expire = tick_add(now_ms, h2c->timeout);
	}

	h2c->wait_event.tasklet = tasklet_new();
	if (!h2c->wait_event.tasklet)
		goto fail;
	h2c->wait_event.tasklet->process = h2_io_cb;
	h2c->wait_event.tasklet->context = h2c;
	h2c->wait_event.events = 0;
	if (!conn_is_back(conn)) {
		/* Connection might already be in the stopping_list if subject
		 * to h1->h2 upgrade.
		 */
		if (!LIST_INLIST(&conn->stopping_list)) {
			LIST_APPEND(&mux_stopping_data[tid].list,
			            &conn->stopping_list);
		}
	}

	h2c->shared_rx_bufs = pool_alloc(pool_head_h2_rx_bufs);
	if (!h2c->shared_rx_bufs)
		goto fail;

	h2c->ddht = hpack_dht_alloc();
	if (!h2c->ddht)
		goto fail;

	/* Initialise the context. */
	h2c->st0 = H2_CS_PREFACE;
	h2c->conn = conn;
	h2c->streams_limit = h2c_max_concurrent_streams(h2c);
	nb_rxbufs = (h2c->flags & H2_CF_IS_BACK) ? h2_be_rxbuf : h2_fe_rxbuf;
	nb_rxbufs = (nb_rxbufs + global.tune.bufsize - 9 - 1) / (global.tune.bufsize - 9);
	nb_rxbufs = MAX(nb_rxbufs, h2c->streams_limit);
	bl_init(h2c->shared_rx_bufs, nb_rxbufs + 1);

	h2c->max_id = -1;
	h2c->errcode = H2_ERR_NO_ERROR;
	h2c->rcvd_c = 0;
	h2c->rcvd_s = 0;
	h2c->wu_s = 0;
	h2c->nb_streams = 0;
	h2c->nb_sc = 0;
	h2c->nb_reserved = 0;
	h2c->stream_cnt = 0;
	h2c->receiving_streams = 0;
	h2c->glitches = 0;
	h2c->term_evts_log = 0;

	h2c->dbuf = *input;
	h2c->dsi = -1;

	h2c->last_sid = -1;

	br_init(h2c->mbuf, sizeof(h2c->mbuf) / sizeof(h2c->mbuf[0]));
	h2c->miw = 65535; /* mux initial window size */
	h2c->mws = 65535; /* mux window size */
	h2c->mfs = 16384; /* initial max frame size */
	h2c->streams_by_id = EB_ROOT;
	LIST_INIT(&h2c->send_list);
	LIST_INIT(&h2c->fctl_list);
	LIST_INIT(&h2c->blocked_list);
	LIST_INIT(&h2c->buf_wait.list);

	conn->ctx = h2c;

	TRACE_USER("new H2 connection", H2_EV_H2C_NEW, conn);

	if (t)
		task_queue(t);

	if (h2c->flags & H2_CF_IS_BACK && likely(!conn_is_reverse(h2c->conn))) {
		/* FIXME: this is temporary, for outgoing connections we need
		 * to immediately allocate a stream until the code is modified
		 * so that the caller calls ->attach(). For now the outgoing sc
		 * is stored as conn->ctx by the caller and saved in conn_ctx.
		 */
		struct h2s *h2s;

		h2s = h2c_bck_stream_new(h2c, conn_ctx, sess);
		if (!h2s)
			goto fail_stream;
	}

	if (sess)
		proxy_inc_fe_cum_sess_ver_ctr(sess->listener, prx, 2);

	/* Rhttp connections are only accounted after reverse completion. */
	if (!conn_is_reverse(conn)) {
		HA_ATOMIC_INC(&h2c->px_counters->open_conns);
		HA_ATOMIC_INC(&h2c->px_counters->total_conns);
	}

	/* prepare to read something */
	h2c_restart_reading(h2c, 1);
	TRACE_LEAVE(H2_EV_H2C_NEW, conn);
	return 0;
  fail_stream:
	hpack_dht_free(h2c->ddht);
  fail:
	task_destroy(t);
	tasklet_free(h2c->wait_event.tasklet);
	pool_free(pool_head_h2c, h2c);
  fail_no_h2c:
	if (!conn_is_back(conn))
		LIST_DEL_INIT(&conn->stopping_list);
	conn->ctx = conn_ctx; /* restore saved ctx */
	TRACE_DEVEL("leaving in error", H2_EV_H2C_NEW|H2_EV_H2C_END|H2_EV_H2C_ERR);
	return -1;
}

/* returns the next allocatable outgoing stream ID for the H2 connection, or
 * -1 if no more is allocatable.
 */
static inline int32_t h2c_get_next_sid(const struct h2c *h2c)
{
	int32_t id = (h2c->max_id + 1) | 1;

	if ((id & 0x80000000U) || (h2c->last_sid >= 0 && id > h2c->last_sid))
		id = -1;
	return id;
}

/* returns the stream associated with id <id> or NULL if not found */
static inline struct h2s *h2c_st_by_id(struct h2c *h2c, int id)
{
	struct eb32_node *node;

	if (id == 0)
		return (struct h2s *)h2_closed_stream;

	if (id > h2c->max_id)
		return (struct h2s *)h2_idle_stream;

	node = eb32_lookup(&h2c->streams_by_id, id);
	if (!node)
		return (struct h2s *)h2_closed_stream;

	return container_of(node, struct h2s, by_id);
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void h2_release(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;

	TRACE_ENTER(H2_EV_H2C_END);

	hpack_dht_free(h2c->ddht);

	b_dequeue(&h2c->buf_wait);

	h2_release_buf(h2c, &h2c->dbuf);
	h2_release_mbuf(h2c);

	if (h2c->task) {
		h2c->task->context = NULL;
		task_wakeup(h2c->task, TASK_WOKEN_OTHER);
		h2c->task = NULL;
	}
	tasklet_free(h2c->wait_event.tasklet);
	if (conn) {
		if (h2c->wait_event.events != 0)
			conn->xprt->unsubscribe(conn, conn->xprt_ctx, h2c->wait_event.events,
						&h2c->wait_event);
		h2c_report_term_evt(h2c, muxc_tevt_type_shutw);
	}

	/* Rhttp connections are not accounted prior to their reverse. */
	if (!conn || !conn_is_reverse(conn))
		HA_ATOMIC_DEC(&h2c->px_counters->open_conns);

	pool_free(pool_head_h2_rx_bufs, h2c->shared_rx_bufs);
	pool_free(pool_head_h2c, h2c);

	if (conn) {
		if (!conn_is_back(conn))
			LIST_DEL_INIT(&conn->stopping_list);

		conn->mux = NULL;
		conn->ctx = NULL;
		TRACE_DEVEL("freeing conn", H2_EV_H2C_END, conn);

		conn_stop_tracking(conn);

		/* there might be a GOAWAY frame still pending in the TCP
		 * stack, and if the peer continues to send (i.e. window
		 * updates etc), this can result in losing the GOAWAY. For
		 * this reason we try to drain anything received in between.
		 */
		conn->flags |= CO_FL_WANT_DRAIN;

		conn_xprt_shutw(conn);
		conn_xprt_close(conn);
		conn_sock_shutw(conn, !conn_is_back(conn));
		conn_ctrl_close(conn);

		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}

	TRACE_LEAVE(H2_EV_H2C_END);
}


/******************************************************/
/* functions below are for the H2 protocol processing */
/******************************************************/

/* returns the stream if of stream <h2s> or 0 if <h2s> is NULL */
static inline __maybe_unused int h2s_id(const struct h2s *h2s)
{
	return h2s ? h2s->id : 0;
}

/* returns the sum of the stream's own window size and the mux's initial
 * window, which together form the stream's effective window size.
 */
static inline int h2s_mws(const struct h2s *h2s)
{
	return h2s->sws + h2s->h2c->miw;
}

/* Returns 1 if the H2 error of the opposite side is forwardable to the peer.
 * Otherwise 0 is returned.
 * For now, only CANCEL from the client is forwardable to the server.
 */
static inline int h2s_is_forwardable_abort(struct h2s *h2s, struct se_abort_info *reason)
{
	enum h2_err err = H2_ERR_NO_ERROR;

	if (reason && ((reason->info & SE_ABRT_SRC_MASK) >> SE_ABRT_SRC_SHIFT) == SE_ABRT_SRC_MUX_H2)
		err = reason->code;

	return ((h2s->h2c->flags & H2_CF_IS_BACK) && (err == H2_ERR_CANCEL));
}

/* marks an error on the connection. Before settings are sent, we must not send
 * a GOAWAY frame, and the error state will prevent h2c_send_goaway_error()
 * from verifying this so we set H2_CF_GOAWAY_FAILED to make sure it will not
 * even try.
 */
static inline __maybe_unused void h2c_error(struct h2c *h2c, enum h2_err err)
{
	TRACE_POINT(H2_EV_H2C_ERR, h2c->conn, 0, 0, (void *)(long)(err));
	h2c->errcode = err;
	if (h2c->st0 < H2_CS_SETTINGS1)
		h2c->flags |= H2_CF_GOAWAY_FAILED;
	h2c->st0 = H2_CS_ERROR;
}

/* marks an error on the stream. It may also update an already closed stream
 * (e.g. to report an error after an RST was received).
 */
static inline __maybe_unused void h2s_error(struct h2s *h2s, enum h2_err err)
{
	if (h2s->id && h2s->st != H2_SS_ERROR) {
		TRACE_POINT(H2_EV_H2S_ERR, h2s->h2c->conn, h2s, 0, (void *)(long)(err));
		h2s->errcode = err;
		if (h2s->st < H2_SS_ERROR)
			h2s->st = H2_SS_ERROR;
		se_fl_set_error(h2s->sd);
	}
}

/* attempt to notify the data layer of recv availability */
static void __maybe_unused h2s_notify_recv(struct h2s *h2s)
{
	if (h2s->subs && h2s->subs->events & SUB_RETRY_RECV) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		if (h2s->h2c->next_tasklet ||
		    (th_ctx->current && th_ctx->current->process == h2_io_cb))
			h2s->h2c->next_tasklet = tasklet_wakeup_after(h2s->h2c->next_tasklet, h2s->subs->tasklet);
		else
			tasklet_wakeup(h2s->subs->tasklet);
		h2s->subs->events &= ~SUB_RETRY_RECV;
		if (!h2s->subs->events)
			h2s->subs = NULL;
	}
}

/* attempt to notify the data layer of send availability */
static void __maybe_unused h2s_notify_send(struct h2s *h2s)
{
	if (h2s->subs && h2s->subs->events & SUB_RETRY_SEND) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		h2s->flags |= H2_SF_NOTIFIED;
		tasklet_wakeup(h2s->subs->tasklet);
		h2s->subs->events &= ~SUB_RETRY_SEND;
		if (!h2s->subs->events)
			h2s->subs = NULL;
	}
	else if (h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW)) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		tasklet_wakeup(h2s->shut_tl);
	}
}

/* alerts the data layer, trying to wake it up by all means, following
 * this sequence :
 *   - if the h2s' data layer is subscribed to recv, then it's woken up for recv
 *   - if its subscribed to send, then it's woken up for send
 *   - if it was subscribed to neither, its ->wake() callback is called
 * It is safe to call this function with a closed stream which doesn't have a
 * stream connector anymore.
 */
static void __maybe_unused h2s_alert(struct h2s *h2s)
{
	TRACE_ENTER(H2_EV_H2S_WAKE, h2s->h2c->conn, h2s);

	if (h2s->subs ||
	    (h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW))) {
		h2s_notify_recv(h2s);
		h2s_notify_send(h2s);
	}
	else if (h2s_sc(h2s) && h2s_sc(h2s)->app_ops->wake != NULL) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		h2s_sc(h2s)->app_ops->wake(h2s_sc(h2s));
	}

	TRACE_LEAVE(H2_EV_H2S_WAKE, h2s->h2c->conn, h2s);
}

/* report one or more glitches on the connection. That is any unexpected event
 * that may occasionally happen but if repeated a bit too much, might indicate
 * a misbehaving or completely bogus peer. It normally returns zero, unless the
 * glitch limit was reached, in which case an error is also reported on the
 * connection.
 */
#define h2c_report_glitch(h2c, inc, ...) ({		\
		COUNT_GLITCH(__VA_ARGS__);		\
		_h2c_report_glitch(h2c, inc); 		\
	})

static inline int _h2c_report_glitch(struct h2c *h2c, int increment)
{
	int thres = (h2c->flags & H2_CF_IS_BACK) ?
		h2_be_glitches_threshold : h2_fe_glitches_threshold;

	h2c->glitches += increment;
	if (thres && h2c->glitches >= thres) {
		h2c_error(h2c, H2_ERR_ENHANCE_YOUR_CALM);
		return 1;
	}
	return 0;
}

/* writes the 24-bit frame size <len> at address <frame> */
static inline __maybe_unused void h2_set_frame_size(void *frame, uint32_t len)
{
	uint8_t *out = frame;

	*out = len >> 16;
	write_n16(out + 1, len);
}

/* reads <bytes> bytes from buffer <b> starting at relative offset <o> from the
 * current pointer, dealing with wrapping, and stores the result in <dst>. It's
 * the caller's responsibility to verify that there are at least <bytes> bytes
 * available in the buffer's input prior to calling this function. The buffer
 * is assumed not to hold any output data.
 */
static inline __maybe_unused void h2_get_buf_bytes(void *dst, size_t bytes,
                                    const struct buffer *b, int o)
{
	readv_bytes(dst, bytes, b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint16_t h2_get_n16(const struct buffer *b, int o)
{
	return readv_n16(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint32_t h2_get_n32(const struct buffer *b, int o)
{
	return readv_n32(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint64_t h2_get_n64(const struct buffer *b, int o)
{
	return readv_n64(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}


/* Peeks an H2 frame header from offset <o> of buffer <b> into descriptor <h>.
 * The algorithm is not obvious. It turns out that H2 headers are neither
 * aligned nor do they use regular sizes. And to add to the trouble, the buffer
 * may wrap so each byte read must be checked. The header is formed like this :
 *
 *       b0         b1       b2     b3   b4         b5..b8
 *  +----------+---------+--------+----+----+----------------------+
 *  |len[23:16]|len[15:8]|len[7:0]|type|flag|sid[31:0] (big endian)|
 *  +----------+---------+--------+----+----+----------------------+
 *
 * Here we read a big-endian 64 bit word from h[1]. This way in a single read
 * we get the sid properly aligned and ordered, and 16 bits of len properly
 * ordered as well. The type and flags can be extracted using bit shifts from
 * the word, and only one extra read is needed to fetch len[16:23].
 * Returns zero if some bytes are missing, otherwise non-zero on success. The
 * buffer is assumed not to contain any output data.
 */
static __maybe_unused int h2_peek_frame_hdr(const struct buffer *b, int o, struct h2_fh *h)
{
	uint64_t w;

	if (b_data(b) < o + 9)
		return 0;

	w = h2_get_n64(b, o + 1);
	h->len = *(uint8_t*)b_peek(b, o) << 16;
	h->sid = w & 0x7FFFFFFF; /* RFC7540#4.1: R bit must be ignored */
	h->ff = w >> 32;
	h->ft = w >> 40;
	h->len += w >> 48;
	return 1;
}

/* skip the next 9 bytes corresponding to the frame header possibly parsed by
 * h2_peek_frame_hdr() above.
 */
static inline __maybe_unused void h2_skip_frame_hdr(struct buffer *b)
{
	b_del(b, 9);
}

/* same as above, automatically advances the buffer on success */
static inline __maybe_unused int h2_get_frame_hdr(struct buffer *b, struct h2_fh *h)
{
	int ret;

	ret = h2_peek_frame_hdr(b, 0, h);
	if (ret > 0)
		h2_skip_frame_hdr(b);
	return ret;
}


/* try to fragment the headers frame present at the beginning of buffer <b>,
 * enforcing a limit of <mfs> bytes per frame. Returns 0 on failure, 1 on
 * success. Typical causes of failure include a buffer not large enough to
 * add extra frame headers. The existing frame size is read in the current
 * frame. Its EH flag will be cleared if CONTINUATION frames need to be added,
 * and its length will be adjusted. The stream ID for continuation frames will
 * be copied from the initial frame's.
 */
static int h2_fragment_headers(struct buffer *b, uint32_t mfs)
{
	size_t remain    = b->data - 9;
	int extra_frames = (remain - 1) / mfs;
	size_t fsize;
	char *fptr;
	int frame;

	if (b->data <= mfs + 9)
		return 1;

	/* Too large a frame, we need to fragment it using CONTINUATION
	 * frames. We start from the end and move tails as needed.
	 */
	if (b->data + extra_frames * 9 > b->size)
		return 0;

	for (frame = extra_frames; frame; frame--) {
		fsize = ((remain - 1) % mfs) + 1;
		remain -= fsize;

		/* move data */
		fptr = b->area + 9 + remain + (frame - 1) * 9;
		memmove(fptr + 9, b->area + 9 + remain, fsize);
		b->data += 9;

		/* write new frame header */
		h2_set_frame_size(fptr, fsize);
		fptr[3] = H2_FT_CONTINUATION;
		fptr[4] = (frame == extra_frames) ? H2_F_HEADERS_END_HEADERS : 0;
		write_n32(fptr + 5, read_n32(b->area + 5));
	}

	b->area[4] &= ~H2_F_HEADERS_END_HEADERS;
	h2_set_frame_size(b->area, remain);
	return 1;
}

/* marks the h2s as receiving data. This will allow to update the number of
 * receiving streams in the connection.
 */
static inline void h2s_count_as_receiving(struct h2s *h2s)
{
	if (!(h2s->flags & H2_SF_EXPECT_RXDATA)) {
		TRACE_STATE("counting H2 stream as receiving data", H2_EV_H2S_RECV, h2s->h2c->conn, h2s);
		h2s->flags |= H2_SF_EXPECT_RXDATA;
		h2s->h2c->receiving_streams++;
	}
}

/* marks the h2s as no longer receiving data. This will allow to
 * update the number of receiving streams in the connection.
 */
static inline void h2s_no_longer_receiving(struct h2s *h2s)
{
	if (h2s->flags & H2_SF_EXPECT_RXDATA) {
		TRACE_STATE("counting H2 stream as not receiving data", H2_EV_H2S_RECV, h2s->h2c->conn, h2s);
		h2s->flags &= ~H2_SF_EXPECT_RXDATA;
		h2s->h2c->receiving_streams--;
	}
}

/* marks stream <h2s> as CLOSED and decrement the number of active streams for
 * its connection if the stream was not yet closed. Please use this exclusively
 * before closing a stream to ensure stream count is well maintained. Note that
 * it does explicitly support being called with a partially initialized h2s
 * (e.g. sd==NULL).
 */
static inline void h2s_close(struct h2s *h2s)
{
	if (h2s->st != H2_SS_CLOSED) {
		TRACE_ENTER(H2_EV_H2S_END, h2s->h2c->conn, h2s);
		TRACE_STATE("releasing H2 stream", H2_EV_H2S_NEW, h2s->h2c->conn, h2s);
		h2s->h2c->nb_streams--;
		if (!h2s->id)
			h2s->h2c->nb_reserved--;
		if (h2s->sd && h2s_sc(h2s)) {
			if (!se_fl_test(h2s->sd, SE_FL_EOS) &&
			    (!h2s_rxbuf_head(h2s) || !b_data(h2s_rxbuf_head(h2s))))
				h2s_notify_recv(h2s);
		}
		HA_ATOMIC_DEC(&h2s->h2c->px_counters->open_streams);

		TRACE_LEAVE(H2_EV_H2S_END, h2s->h2c->conn, h2s);
	}
	h2s->st = H2_SS_CLOSED;
	h2s_no_longer_receiving(h2s);
}

/* Check h2c and h2s flags to evaluate if EOI/EOS/ERR_PENDING/ERROR flags must
 * be set on the SE.
 */
static inline void h2s_propagate_term_flags(struct h2c *h2c, struct h2s *h2s)
{
	if (h2s->flags & H2_SF_ES_RCVD) {
		se_fl_set(h2s->sd, SE_FL_EOI);
		/* Add EOS flag for tunnel */
		if (h2s->flags & H2_SF_BODY_TUNNEL) {
			se_fl_set(h2s->sd, SE_FL_EOS);
			se_report_term_evt(h2s->sd, (h2c->flags & H2_CF_ERROR ? se_tevt_type_rcv_err : se_tevt_type_eos));
		}
	}
	if (h2c_read0_pending(h2c) || h2s->st == H2_SS_CLOSED) {
		se_fl_set(h2s->sd, SE_FL_EOS);
		if (!se_fl_test(h2s->sd, SE_FL_EOI)) {
			se_fl_set(h2s->sd, SE_FL_ERROR);
			se_report_term_evt(h2s->sd, (h2c->flags & H2_CF_ERROR ? se_tevt_type_rcv_err : se_tevt_type_eos));
		}
		else
			se_report_term_evt(h2s->sd, (h2c->flags & H2_CF_ERROR ? se_tevt_type_truncated_rcv_err : se_tevt_type_truncated_eos));
	}
	if (se_fl_test(h2s->sd, SE_FL_ERR_PENDING))
		se_fl_set(h2s->sd, SE_FL_ERROR);
}

/* detaches an H2 stream from its H2C and releases it to the H2S pool. */
/* h2s_destroy should only ever be called by the thread that owns the stream,
 * that means that a tasklet should be used if we want to destroy the h2s
 * from another thread
 */
static void h2s_destroy(struct h2s *h2s)
{
	struct connection *conn = h2s->h2c->conn;
	int freed = 0;

	TRACE_ENTER(H2_EV_H2S_END, conn, h2s);

	h2s_close(h2s);
	eb32_delete(&h2s->by_id);

	while (h2s->rx_head) {
		b_free(&h2s->h2c->shared_rx_bufs[h2s->rx_head].buf);
		h2s->rx_head = bl_put(h2s->h2c->shared_rx_bufs, h2s->rx_head);
		freed++;
	}

	if (freed) {
		offer_buffers(NULL, freed);
		if (h2s->h2c->flags & H2_CF_DEM_RXBUF) {
			/* just released resources the demux is waiting for */
			h2s->h2c->flags &= ~(H2_CF_DEM_SFULL | H2_CF_DEM_RXBUF);
			h2c_restart_reading(h2s->h2c, 1);
		}
	}

	if (h2s->subs)
		h2s->subs->events = 0;

	/* There's no need to explicitly call unsubscribe here, the only
	 * reference left would be in the h2c send_list/fctl_list, and if
	 * we're in it, we're getting out anyway
	 */
	h2_remove_from_list(h2s);

	/* ditto, calling tasklet_free() here should be ok */
	tasklet_free(h2s->shut_tl);
	BUG_ON(h2s->sd && !se_fl_test(h2s->sd, SE_FL_ORPHAN));
	sedesc_free(h2s->sd);
	pool_free(pool_head_h2s, h2s);

	TRACE_LEAVE(H2_EV_H2S_END, conn);
}

/* allocates a new stream <id> for connection <h2c> and adds it into h2c's
 * stream tree. In case of error, nothing is added and NULL is returned. The
 * causes of errors can be any failed memory allocation. The caller is
 * responsible for checking if the connection may support an extra stream
 * prior to calling this function.
 */
static struct h2s *h2s_new(struct h2c *h2c, int id)
{
	struct h2s *h2s;
	uint iws;

	TRACE_ENTER(H2_EV_H2S_NEW, h2c->conn);

	h2s = pool_alloc(pool_head_h2s);
	if (!h2s)
		goto out;

	h2s->shut_tl = tasklet_new();
	if (!h2s->shut_tl) {
		pool_free(pool_head_h2s, h2s);
		goto out;
	}
	h2s->subs = NULL;
	h2s->shut_tl->process = h2_deferred_shut;
	h2s->shut_tl->context = h2s;
	LIST_INIT(&h2s->list);
	h2s->h2c       = h2c;
	h2s->sess      = NULL;
	h2s->sd        = NULL;
	h2s->sws       = 0;
	h2s->flags     = H2_SF_NONE;
	h2s->errcode   = H2_ERR_NO_ERROR;
	h2s->st        = H2_SS_IDLE;
	h2s->status    = 0;
	h2s->body_len  = 0;
	h2s->rx_tail   = 0;
	h2s->rx_head   = 0;
	h2s->rx_count  = 0;
	memset(h2s->upgrade_protocol, 0, sizeof(h2s->upgrade_protocol));

	h2s->by_id.key = h2s->id = id;
	if (id > 0)
		h2c->max_id      = id;
	else
		h2c->nb_reserved++;

	/* calculate the max offset permitted by the currently active
	 * initial window size.
	 */
	iws = (h2c->flags & H2_CF_IS_BACK) ?
	      h2_be_settings_initial_window_size:
	      h2_fe_settings_initial_window_size;
	iws = iws ? iws : h2_settings_initial_window_size;
	h2s->last_adv_ofs = h2s->next_max_ofs = iws;
	h2s->curr_rx_ofs = 0;

	eb32_insert(&h2c->streams_by_id, &h2s->by_id);
	h2c->nb_streams++;

	HA_ATOMIC_INC(&h2c->px_counters->open_streams);
	HA_ATOMIC_INC(&h2c->px_counters->total_streams);

	TRACE_LEAVE(H2_EV_H2S_NEW, h2c->conn, h2s);
	return h2s;
 out:
	TRACE_DEVEL("leaving in error", H2_EV_H2S_ERR|H2_EV_H2S_END, h2c->conn);
	return NULL;
}

/* creates a new stream <id> on the h2c connection and returns it, or NULL in
 * case of memory allocation error. <input> is used as input buffer for the new
 * stream. On success, it is transferred to the stream and the mux is no longer
 * responsible of it. On error, <input> is unchanged, thus the mux must still
 * take care of it.
 */
static struct h2s *h2c_frt_stream_new(struct h2c *h2c, int id, struct buffer *input, uint32_t flags)
{
	struct session *sess = h2c->conn->owner;
	struct h2s *h2s;

	TRACE_ENTER(H2_EV_H2S_NEW, h2c->conn);

	/* Cannot handle stream if active reversed connection is not yet accepted. */
	BUG_ON(conn_reverse_in_preconnect(h2c->conn));

	if (h2c->nb_streams >= h2c_max_concurrent_streams(h2c)) {
		h2c_report_glitch(h2c, 1, "HEADERS frame causing MAX_CONCURRENT_STREAMS to be exceeded");
		TRACE_ERROR("HEADERS frame causing MAX_CONCURRENT_STREAMS to be exceeded", H2_EV_H2S_NEW|H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);
		session_inc_http_req_ctr(sess);
		session_inc_http_err_ctr(sess);
		goto out;
	}

	h2s = h2s_new(h2c, id);
	if (!h2s)
		goto out_alloc;

	h2s->sd = sedesc_new();
	if (!h2s->sd)
		goto out_close;
	h2s->sd->se   = h2s;
	h2s->sd->conn = h2c->conn;
	se_fl_set(h2s->sd, SE_FL_T_MUX | SE_FL_ORPHAN | SE_FL_NOT_FIRST);

	if (!(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_H2_SND))
		se_fl_set(h2s->sd, SE_FL_MAY_FASTFWD_CONS);

	/* The request is not finished, don't expect data from the opposite side
	 * yet
	 */
	if (!(h2c->dff & (H2_F_HEADERS_END_STREAM| H2_F_DATA_END_STREAM)) && !(flags & H2_SF_BODY_TUNNEL))
		se_expect_no_data(h2s->sd);

	/* FIXME wrong analogy between ext-connect and websocket, this need to
	 * be refine.
	 */
	if (flags & H2_SF_EXT_CONNECT_RCVD)
		se_fl_set(h2s->sd, SE_FL_WEBSOCKET);

	/* The stream will record the request's accept date (which is either the
	 * end of the connection's or the date immediately after the previous
	 * request) and the idle time, which is the delay since the previous
	 * request. We can set the value now, it will be copied by stream_new().
	 */
	sess->t_idle = ns_to_ms(now_ns - sess->accept_ts) - sess->t_handshake;

	if (!sc_new_from_endp(h2s->sd, sess, input))
		goto out_close;

	h2c->nb_sc++;

	/* We want the accept date presented to the next stream to be the one
	 * we have now, the handshake time to be null (since the next stream
	 * is not delayed by a handshake), and the idle time to count since
	 * right now.
	 */
	sess->accept_date = date;
	sess->accept_ts   = now_ns;
	sess->t_handshake = 0;
	sess->t_idle = 0;

	/* OK done, the stream lives its own life now */
	if (h2_frt_has_too_many_sc(h2c))
		h2c->flags |= H2_CF_DEM_TOOMANY;

	TRACE_STATE("created new H2 front stream", H2_EV_H2S_NEW, h2c->conn, h2s);
	TRACE_LEAVE(H2_EV_H2S_NEW, h2c->conn);
	return h2s;

 out_close:
	h2s_destroy(h2s);
 out_alloc:
	TRACE_ERROR("Failed to allocate a new stream", H2_EV_H2S_NEW|H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);
 out:
	sess_log(sess);
	TRACE_LEAVE(H2_EV_H2S_NEW|H2_EV_H2S_ERR|H2_EV_H2S_END, h2c->conn);
	return NULL;
}

/* allocates a new stream associated to stream connector <sc> on the h2c
 * connection and returns it, or NULL in case of memory allocation error or if
 * the highest possible stream ID was reached.
 */
static struct h2s *h2c_bck_stream_new(struct h2c *h2c, struct stconn *sc, struct session *sess)
{
	struct h2s *h2s = NULL;

	TRACE_ENTER(H2_EV_H2S_NEW, h2c->conn);

	/* Cannot handle stream if connection waiting to be reversed. */
	BUG_ON(conn_reverse_in_preconnect(h2c->conn));

	if (h2c->nb_streams >= h2c->streams_limit) {
		TRACE_ERROR("Aborting stream since negotiated limit is too low", H2_EV_H2S_NEW, h2c->conn);
		goto out;
	}

	if (h2_streams_left(h2c) < 1) {
		TRACE_ERROR("Aborting stream since no more streams left", H2_EV_H2S_NEW, h2c->conn);
		goto out;
	}

	/* Defer choosing the ID until we send the first message to create the stream */
	h2s = h2s_new(h2c, 0);
	if (!h2s) {
		TRACE_ERROR("Failed to allocate a new stream", H2_EV_H2S_NEW, h2c->conn);
		goto out;
	}

	if (sc_attach_mux(sc, h2s, h2c->conn) < 0) {
		TRACE_ERROR("Failed to allocate a new stream", H2_EV_H2S_NEW, h2c->conn);
		h2s_destroy(h2s);
		h2s = NULL;
		goto out;
	}
	h2s->sd = sc->sedesc;
	h2s->sess = sess;
	h2c->nb_sc++;

	if (!(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_H2_SND))
		se_fl_set(h2s->sd, SE_FL_MAY_FASTFWD_CONS);
	/* on the backend we can afford to only count total streams upon success */
	h2c->stream_cnt++;
	TRACE_STATE("created new H2 back stream", H2_EV_H2S_NEW, h2c->conn, h2s);

 out:
	if (likely(h2s))
		TRACE_LEAVE(H2_EV_H2S_NEW, h2c->conn, h2s);
	else
		TRACE_LEAVE(H2_EV_H2S_NEW|H2_EV_H2S_ERR|H2_EV_H2S_END, h2c->conn, h2s);
	return h2s;
}

/* try to send a settings frame on the connection. Returns > 0 on success, 0 if
 * it couldn't do anything. It may return an error in h2c. See RFC7540#11.3 for
 * the various settings codes.
 */
static int h2c_send_settings(struct h2c *h2c)
{
	struct buffer *res;
	char buf_data[100]; // enough for 15 settings
	struct buffer buf;
	int iws;
	int mfs;
	int mcs;
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);

	chunk_init(&buf, buf_data, sizeof(buf_data));
	chunk_memcpy(&buf,
	       "\x00\x00\x00"      /* length    : 0 for now */
	       "\x04\x00"          /* type      : 4 (settings), flags : 0 */
	       "\x00\x00\x00\x00", /* stream ID : 0 */
	       9);

	if (h2c->flags & H2_CF_IS_BACK) {
		/* send settings_enable_push=0 */
		chunk_memcat(&buf, "\x00\x02\x00\x00\x00\x00", 6);
	}

	/* rfc 8441 #3 SETTINGS_ENABLE_CONNECT_PROTOCOL=1,
	 * sent automatically unless disabled in the global config */
	if (!(global.tune.options & GTUNE_DISABLE_H2_WEBSOCKET))
		chunk_memcat(&buf, "\x00\x08\x00\x00\x00\x01", 6);

	if (h2_settings_header_table_size != 4096) {
		char str[6] = "\x00\x01"; /* header_table_size */

		write_n32(str + 2, h2_settings_header_table_size);
		chunk_memcat(&buf, str, 6);
	}

	iws = (h2c->flags & H2_CF_IS_BACK) ?
	      h2_be_settings_initial_window_size:
	      h2_fe_settings_initial_window_size;
	iws = iws ? iws : h2_settings_initial_window_size;

	if (iws != 65535) {
		char str[6] = "\x00\x04"; /* initial_window_size */

		write_n32(str + 2, iws);
		chunk_memcat(&buf, str, 6);
	}

	mcs = h2c_max_concurrent_streams(h2c);
	if (mcs != 0) {
		char str[6] = "\x00\x03"; /* max_concurrent_streams */

		/* Note: 0 means "unlimited" for haproxy's config but not for
		 * the protocol, so never send this value!
		 */
		write_n32(str + 2, mcs);
		chunk_memcat(&buf, str, 6);
	}

	mfs = h2_settings_max_frame_size;
	if (mfs > global.tune.bufsize)
		mfs = global.tune.bufsize;

	if (!mfs)
		mfs = global.tune.bufsize;

	if (mfs != 16384) {
		char str[6] = "\x00\x05"; /* max_frame_size */

		/* note: similarly we could also emit MAX_HEADER_LIST_SIZE to
		 * match bufsize - rewrite size, but at the moment it seems
		 * that clients don't take care of it.
		 */
		write_n32(str + 2, mfs);
		chunk_memcat(&buf, str, 6);
	}

	h2_set_frame_size(buf.area, buf.data - 9);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(buf.area, buf.data));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);
	return ret;
}

/* Try to receive a connection preface, then upon success try to send our
 * preface which is a SETTINGS frame. Returns > 0 on success or zero on
 * missing data. It may return an error in h2c.
 */
static int h2c_frt_recv_preface(struct h2c *h2c)
{
	int ret1;
	int ret2;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_PREFACE, h2c->conn);

	ret1 = b_isteq(&h2c->dbuf, 0, b_data(&h2c->dbuf), ist(H2_CONN_PREFACE));

	if (unlikely(ret1 <= 0)) {
		if (!ret1)
			h2c->flags |= H2_CF_DEM_SHORT_READ;
		if (ret1 < 0 || (h2c->flags & H2_CF_RCVD_SHUT)) {
			h2c_report_glitch(h2c, 1, "I/O error or short read on PREFACE");
			TRACE_ERROR("I/O error or short read on PREFACE", H2_EV_RX_FRAME|H2_EV_RX_PREFACE, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			if (b_data(&h2c->dbuf) ||
			    !(((const struct session *)h2c->conn->owner)->fe->options & PR_O_IGNORE_PRB))
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		}
		ret2 = 0;
		goto out;
	}

	ret2 = h2c_send_settings(h2c);
	if (ret2 > 0)
		b_del(&h2c->dbuf, ret1);
 out:
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_PREFACE, h2c->conn);
	return ret2;
}

/* Try to send a connection preface, then upon success try to send our
 * preface which is a SETTINGS frame. Returns > 0 on success or zero on
 * missing data. It may return an error in h2c.
 */
static int h2c_bck_send_preface(struct h2c *h2c)
{
	struct buffer *res;
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_PREFACE, h2c->conn);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	if (!b_data(res)) {
		/* preface not yet sent */
		ret = b_istput(res, ist(H2_CONN_PREFACE));
		if (unlikely(ret <= 0)) {
			if (!ret) {
				if ((res = br_tail_add(h2c->mbuf)) != NULL)
					goto retry;
				h2c->flags |= H2_CF_MUX_MFULL;
				h2c->flags |= H2_CF_DEM_MROOM;
				goto out;
			}
			else {
				h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
				ret = 0;
				goto out;
			}
		}
	}
	ret = h2c_send_settings(h2c);
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_PREFACE, h2c->conn);
	return ret;
}

/* try to send a GOAWAY frame on the connection to report an error or a graceful
 * shutdown, with h2c->errcode as the error code. Returns > 0 on success or zero
 * if nothing was done. It uses h2c->last_sid as the advertised ID, or copies it
 * from h2c->max_id if it's not set yet (<0). In case of lack of room to write
 * the message, it subscribes the requester (either <h2s> or <h2c>) to future
 * notifications. It sets H2_CF_GOAWAY_SENT on success, and H2_CF_GOAWAY_FAILED
 * on unrecoverable failure. It will not attempt to send one again in this last
 * case, nor will it send one if settings were not sent (e.g. still waiting for
 * a preface) so that it is safe to use h2c_error() to report such errors.
 */
static int h2c_send_goaway_error(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer *res;
	char str[17];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_GOAWAY, h2c->conn);

	if ((h2c->flags & H2_CF_GOAWAY_FAILED) || h2c->st0 < H2_CS_SETTINGS1) {
		ret = 1; // claim that it worked
		goto out;
	}

	/* len: 8, type: 7, flags: none, sid: 0 */
	memcpy(str, "\x00\x00\x08\x07\x00\x00\x00\x00\x00", 9);

	if (h2c->last_sid < 0)
		h2c->last_sid = h2c->max_id;

	write_n32(str + 9, h2c->last_sid);
	write_n32(str + 13, h2c->errcode);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		if (h2s)
			h2s->flags |= H2_SF_BLK_MROOM;
		else
			h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 17));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			if (h2s)
				h2s->flags |= H2_SF_BLK_MROOM;
			else
				h2c->flags |= H2_CF_DEM_MROOM;
			goto out;
		}
		else {
			/* we cannot report this error using GOAWAY, so we mark
			 * it and claim a success.
			 */
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			h2c->flags |= H2_CF_GOAWAY_FAILED;
			ret = 1;
			goto out;
		}
	}
	h2c->flags |= H2_CF_GOAWAY_SENT;

	/* some codes are not for real errors, just attempts to close cleanly */
	switch (h2c->errcode) {
	case H2_ERR_NO_ERROR:
	case H2_ERR_ENHANCE_YOUR_CALM:
		h2c_report_term_evt(h2c, muxc_tevt_type_graceful_shut);
		__fallthrough;
	case H2_ERR_REFUSED_STREAM:
	case H2_ERR_CANCEL:
		break;

	case H2_ERR_PROTOCOL_ERROR:
	case H2_ERR_FRAME_SIZE_ERROR:
	case H2_ERR_COMPRESSION_ERROR:
		h2c_report_term_evt(h2c, muxc_tevt_type_proto_err);
		HA_ATOMIC_INC(&h2c->px_counters->goaway_resp);
		break;

	case H2_ERR_INTERNAL_ERROR:
		h2c_report_term_evt(h2c, muxc_tevt_type_internal_err);
		HA_ATOMIC_INC(&h2c->px_counters->goaway_resp);
		break;

	default:
		h2c_report_term_evt(h2c, muxc_tevt_type_other_err);
		HA_ATOMIC_INC(&h2c->px_counters->goaway_resp);
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_GOAWAY, h2c->conn);
	return ret;
}

/* Try to send an RST_STREAM frame on the connection for the indicated stream
 * during mux operations. This stream must be valid and cannot be closed
 * already. h2s->id will be used for the stream ID and h2s->errcode will be
 * used for the error code. h2s->st will be update to H2_SS_CLOSED if it was
 * not yet.
 *
 * Returns > 0 on success or zero if nothing was done. In case of lack of room
 * to write the message, it subscribes the stream to future notifications.
 */
static int h2s_send_rst_stream(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer *res;
	char str[13];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);

	if (!h2s || h2s->st == H2_SS_CLOSED) {
		ret = 1;
		goto out;
	}

	/* RFC7540#5.4.2: To avoid looping, an endpoint MUST NOT send a
	 * RST_STREAM in response to a RST_STREAM frame.
	 *
	 * if h2s is not assigned yet (id == 0), don't send a RST_STREAM frame.
	 */
	if ((h2s->id == 0) || (h2c->dsi == h2s->id && h2c->dft == H2_FT_RST_STREAM)) {
		ret = 1;
		goto ignore;
	}

	/* len: 4, type: 3, flags: none */
	memcpy(str, "\x00\x00\x04\x03\x00", 5);
	write_n32(str + 5, h2s->id);
	write_n32(str + 9, h2s->errcode);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 13));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			goto out;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
			goto out;
		}
	}

 ignore:
	h2s->flags |= H2_SF_RST_SENT;
	h2s_close(h2s);
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);
	return ret;
}

/* Try to send an RST_STREAM frame on the connection for the stream being
 * demuxed using h2c->dsi for the stream ID. It will use h2s->errcode as the
 * error code, even if the stream is one of the dummy ones, and will update
 * h2s->st to H2_SS_CLOSED if it was not yet.
 *
 * Returns > 0 on success or zero if nothing was done. In case of lack of room
 * to write the message, it blocks the demuxer and subscribes it to future
 * notifications. It's worth mentioning that an RST may even be sent for a
 * closed stream.
 */
static int h2c_send_rst_stream(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer *res;
	char str[13];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);

	/* RFC7540#5.4.2: To avoid looping, an endpoint MUST NOT send a
	 * RST_STREAM in response to a RST_STREAM frame.
	 */
	if (h2c->dft == H2_FT_RST_STREAM) {
		ret = 1;
		goto ignore;
	}

	/* len: 4, type: 3, flags: none */
	memcpy(str, "\x00\x00\x04\x03\x00", 5);

	write_n32(str + 5, h2c->dsi);
	write_n32(str + 9, h2s->errcode);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 13));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
			goto out;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
			goto out;
		}
	}

	if (h2s->id) {
		switch (h2s->errcode) {
		case H2_ERR_REFUSED_STREAM:
			break;

		case H2_ERR_CANCEL:
			se_report_term_evt(h2s->sd, se_tevt_type_cancelled);
			break;

		case H2_ERR_STREAM_CLOSED:
		case H2_ERR_PROTOCOL_ERROR:
			se_report_term_evt(h2s->sd, se_tevt_type_proto_err);
			break;
		case H2_ERR_INTERNAL_ERROR:
			se_report_term_evt(h2s->sd, se_tevt_type_internal_err);
			break;
		default:
			se_report_term_evt(h2s->sd, se_tevt_type_other_err);
		}
	}
 ignore:
	if (h2s->id) {
		h2s->flags |= H2_SF_RST_SENT;
		h2s_close(h2s);
	}

 out:
	HA_ATOMIC_INC(&h2c->px_counters->rst_stream_resp);
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);
	return ret;
}

/* try to send an empty DATA frame with the ES flag set to notify about the
 * end of stream and match a shutdown(write). If an ES was already sent as
 * indicated by HLOC/ERROR/RESET/CLOSED states, nothing is done. Returns > 0
 * on success or zero if nothing was done. In case of lack of room to write the
 * message, it subscribes the requesting stream to future notifications.
 */
static int h2_send_empty_data_es(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;
	struct buffer *res;
	char str[9];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_TX_EOI, h2c->conn, h2s);

	if (h2s->st == H2_SS_HLOC || h2s->st == H2_SS_ERROR || h2s->st == H2_SS_CLOSED) {
		ret = 1;
		goto out;
	}

	/* len: 0x000000, type: 0(DATA), flags: ES=1 */
	memcpy(str, "\x00\x00\x00\x00\x01", 5);
	write_n32(str + 5, h2s->id);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 9));
	if (likely(ret > 0)) {
		h2s->flags |= H2_SF_ES_SENT;
	}
	else if (!ret) {
		if ((res = br_tail_add(h2c->mbuf)) != NULL)
			goto retry;
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
	}
	else {
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
		ret = 0;
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_TX_EOI, h2c->conn, h2s);
	return ret;
}

/* wake a specific stream and assign its stream connector some SE_FL_* flags
 * among SE_FL_ERR_PENDING and SE_FL_ERROR if needed. The stream's state
 * is automatically updated accordingly. If the stream is orphaned, it is
 * destroyed.
 */
static void h2s_wake_one_stream(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;

	TRACE_ENTER(H2_EV_H2S_WAKE, h2c->conn, h2s);

	if (!h2s_sc(h2s)) {
		/* this stream was already orphaned */
		h2s_destroy(h2s);
		TRACE_DEVEL("leaving with no h2s", H2_EV_H2S_WAKE, h2c->conn);
		return;
	}

	if (h2c_read0_pending(h2s->h2c)) {
		h2s_no_longer_receiving(h2s);
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else if (h2s->st == H2_SS_HLOC)
			h2s_close(h2s);
	}

	if ((h2s->st != H2_SS_CLOSED) &&
	    (h2s->h2c->st0 >= H2_CS_ERROR || (h2s->h2c->flags & H2_CF_ERROR) ||
	     (h2s->h2c->last_sid > 0 && (!h2s->id || h2s->id > h2s->h2c->last_sid)))) {
		se_fl_set_error(h2s->sd);
		h2s_propagate_term_flags(h2c, h2s);

		if (h2s->st < H2_SS_ERROR)
			h2s->st = H2_SS_ERROR;
	}

	h2s_alert(h2s);
	TRACE_LEAVE(H2_EV_H2S_WAKE, h2c->conn);
}

/* wake the streams attached to the connection, whose id is greater than <last>
 * or unassigned.
 */
static void h2_wake_some_streams(struct h2c *h2c, int last)
{
	struct eb32_node *node;
	struct h2s *h2s;

	TRACE_ENTER(H2_EV_H2S_WAKE, h2c->conn);

	/* Wake all streams with ID > last */
	node = eb32_lookup_ge(&h2c->streams_by_id, last + 1);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		node = eb32_next(node);
		h2s_wake_one_stream(h2s);
	}

	/* Wake all streams with unassigned ID (ID == 0) */
	node = eb32_lookup(&h2c->streams_by_id, 0);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		if (h2s->id > 0)
			break;
		node = eb32_next(node);
		h2s_wake_one_stream(h2s);
	}

	TRACE_LEAVE(H2_EV_H2S_WAKE, h2c->conn);
}

/* Wake up all blocked streams whose window size has become positive after the
 * mux's initial window was adjusted. This should be done after having processed
 * SETTINGS frames which have updated the mux's initial window size.
 */
static void h2c_unblock_sfctl(struct h2c *h2c)
{
	struct h2s *h2s;
	struct eb32_node *node;

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		if (h2s->flags & H2_SF_BLK_SFCTL && h2s_mws(h2s) > 0) {
			h2s->flags &= ~H2_SF_BLK_SFCTL;
			LIST_DEL_INIT(&h2s->list);
			if ((h2s->subs && h2s->subs->events & SUB_RETRY_SEND) ||
			    h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))
				LIST_APPEND(&h2c->send_list, &h2s->list);
		}
		node = eb32_next(node);
	}

	TRACE_LEAVE(H2_EV_H2C_WAKE, h2c->conn);
}

/* processes a SETTINGS frame whose payload is <payload> for <plen> bytes, and
 * ACKs it if needed. Returns > 0 on success or zero on missing data. It may
 * return an error in h2c. The caller must have already verified frame length
 * and stream ID validity. Described in RFC7540#6.5.
 */
static int h2c_handle_settings(struct h2c *h2c)
{
	unsigned int offset;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);

	if (h2c->dff & H2_F_SETTINGS_ACK) {
		if (h2c->dfl) {
			error = H2_ERR_FRAME_SIZE_ERROR;
			goto fail;
		}
		goto done;
	}

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out0;
	}

	/* parse the frame */
	for (offset = 0; offset < h2c->dfl; offset += 6) {
		uint16_t type = h2_get_n16(&h2c->dbuf, offset);
		int32_t  arg  = h2_get_n32(&h2c->dbuf, offset + 2);

		switch (type) {
		case H2_SETTINGS_INITIAL_WINDOW_SIZE:
			/* we need to update all existing streams with the
			 * difference from the previous iws.
			 */
			if (arg < 0) { // RFC7540#6.5.2
				error = H2_ERR_FLOW_CONTROL_ERROR;
				h2c_report_glitch(h2c, 1, "negative INITIAL_WINDOW_SIZE");
				TRACE_STATE("negative INITIAL_WINDOW_SIZE", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
				goto fail;
			}
			/* Let's count a glitch here in case of a reduction
			 * after H2_CS_SETTINGS1 because while it's not
			 * fundamentally invalid from a protocol's perspective,
			 * it's often suspicious.
			 */
			if (h2c->st0 != H2_CS_SETTINGS1 && arg < h2c->miw)
				if (h2c_report_glitch(h2c, 1, "reduced SETTINGS_INITIAL_WINDOW_SIZE")) {
					error = H2_ERR_ENHANCE_YOUR_CALM;
					TRACE_STATE("glitch limit reached on SETTINGS frame", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
					goto fail;
				}

			h2c->miw = arg;
			break;
		case H2_SETTINGS_MAX_FRAME_SIZE:
			if (arg < 16384 || arg > 16777215) { // RFC7540#6.5.2
				h2c_report_glitch(h2c, 1, "MAX_FRAME_SIZE out of range");
				TRACE_ERROR("MAX_FRAME_SIZE out of range", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
				error = H2_ERR_PROTOCOL_ERROR;
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto fail;
			}
			h2c->mfs = arg;
			break;
		case H2_SETTINGS_HEADER_TABLE_SIZE:
			h2c->flags |= H2_CF_SHTS_UPDATED;
			break;
		case H2_SETTINGS_ENABLE_PUSH:
			if (arg < 0 || arg > 1) { // RFC7540#6.5.2
				h2c_report_glitch(h2c, 1, "ENABLE_PUSH out of range");
				TRACE_ERROR("ENABLE_PUSH out of range", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
				error = H2_ERR_PROTOCOL_ERROR;
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto fail;
			}
			break;
		case H2_SETTINGS_MAX_CONCURRENT_STREAMS:
			if (h2c->flags & H2_CF_IS_BACK) {
				/* the limit is only for the backend; for the frontend it is our limit */
				if ((unsigned int)arg > h2c_max_concurrent_streams(h2c))
					arg = h2c_max_concurrent_streams(h2c);
				h2c->streams_limit = arg;
			}
			break;
		case H2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
			if (arg == 1)
				h2c->flags |= H2_CF_RCVD_RFC8441;
			break;
		}
	}

	/* need to ACK this frame now */
	h2c->st0 = H2_CS_FRAME_A;
 done:
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
	return 1;
 fail:
	if (!(h2c->flags & H2_CF_IS_BACK))
		sess_log(h2c->conn->owner);
	h2c_error(h2c, error);
 out0:
	TRACE_DEVEL("leaving with missing data or error", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
	return 0;
}

/* try to send an ACK for a settings frame on the connection. Returns > 0 on
 * success or one of the h2_status values.
 */
static int h2c_ack_settings(struct h2c *h2c)
{
	struct buffer *res;
	char str[9];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);

	memcpy(str,
	       "\x00\x00\x00"     /* length : 0 (no data)  */
	       "\x04" "\x01"      /* type   : 4, flags : ACK */
	       "\x00\x00\x00\x00" /* stream ID */, 9);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 9));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);
	return ret;
}

/* processes a PING frame and schedules an ACK if needed. The caller must pass
 * the pointer to the payload in <payload>. Returns > 0 on success or zero on
 * missing data. The caller must have already verified frame length
 * and stream ID validity.
 */
static int h2c_handle_ping(struct h2c *h2c)
{
	/* schedule a response */
	if (!(h2c->dff & H2_F_PING_ACK))
		h2c->st0 = H2_CS_FRAME_A;
	return 1;
}

/* Try to send a window update for stream id <sid> and value <increment>.
 * Returns > 0 on success or zero on missing room or failure. It may return an
 * error in h2c.
 */
static int h2c_send_window_update(struct h2c *h2c, int sid, uint32_t increment)
{
	struct buffer *res;
	char str[13];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);

	/* length: 4, type: 8, flags: none */
	memcpy(str, "\x00\x00\x04\x08\x00", 5);
	write_n32(str + 5, sid);
	write_n32(str + 9, increment);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 13));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
	return ret;
}

/* try to send pending window update for the connection. It's safe to call it
 * with no pending updates. Returns > 0 on success or zero on missing room or
 * failure. It may return an error in h2c.
 */
static int h2c_send_conn_wu(struct h2c *h2c)
{
	int ret = 1;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);

	if (h2c->rcvd_c <= 0)
		goto out;

	if (!(h2c->flags & H2_CF_WINDOW_OPENED)) {
		/* increase the advertised connection window to 2G on
		 * first update.
		 */
		h2c->flags |= H2_CF_WINDOW_OPENED;
		h2c->rcvd_c += H2_INITIAL_WINDOW_INCREMENT;
	}

	/* send WU for the connection */
	ret = h2c_send_window_update(h2c, 0, h2c->rcvd_c);
	if (ret > 0)
		h2c->rcvd_c = 0;

 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
	return ret;
}

/* Recalculate the current stream's rx window based on h2c->rcvd_s, which is
 * reset if consumed. The amount of bytes to ACK is the difference between
 * next_max_ofs and last_adv_ofs, and is put into h2c->wu_s. For dummy streams,
 * rcvd_s is directly transferred to wu_s so that it outlives the stream. The
 * function returns non-zero if the resulting wu_s is non-zero, indicating that
 * a WU is deserved, otherwise zero.
 */
static int h2c_update_strm_rx_win(struct h2c *h2c)
{
	struct h2s *h2s;
	int win = 0;
	int rxbsz;

	h2s = h2c_st_by_id(h2c, h2c->dsi);
	if (h2s && h2s->h2c) {
		/* This is real stream. Principle: We have a total number of
		 * allocatable rxbufs per connection (bl_size). We always grant
		 * one to any existing stream (as long as there are some left),
		 * so we deduce from those all non receiving streams. We
		 * further deduce 1/8 to assign to any new stream. The
		 * remaining ones can be evenly shared between receiving
		 * streams. Finally, for front streams, this is rounded
		 * up to the buffer size while for back streams we round
		 * it down. The rationale here is that front to back is
		 * very fast to flush and slow to refill while it's the
		 * opposite in the other way so we try to minimize HoL.
		 */
		if (h2s->st < H2_SS_ERROR) {
			int allocatable;
			int non_rx;
			int reserved;
			int to_share;
			int opt_size;

			/* let's use the configured static window size */
			win = (h2c->flags & H2_CF_IS_BACK) ?
				h2_be_settings_initial_window_size:
				h2_fe_settings_initial_window_size;
			win = win ? win : h2_settings_initial_window_size;

			/* try to optimally align incoming frames to align copies
			 * to HTX, but stick to 16384 if lower since that's what most
			 * implems use and some might refrain from sending until a
			 * full frame is permitted. We won't be causing HoL for 56
			 * extra bytes anyway.
			 */
			opt_size = global.tune.bufsize - sizeof(struct htx) - sizeof(struct htx_blk);
			if (opt_size < 16384)
				opt_size = 16384;

			/* default to one buffer when not receiving data */
			rxbsz = opt_size;

			/* only advertise a larger window if we really expect more data than
			 * the default window (or we don't know how much we expect).
			 */
			if ((h2s->flags & H2_SF_EXPECT_RXDATA) &&
			    (!(h2s->flags & H2_SF_DATA_CLEN) || h2s->body_len > (ullong)win)) {
				non_rx = MAX((int)(h2c->nb_sc - h2c->receiving_streams), 0);
				allocatable = MAX((int)(bl_size(h2c->shared_rx_bufs) - non_rx), 0);
				reserved = (h2c->streams_limit - h2c->nb_sc + 7) / 8;
				to_share = MAX(allocatable - reserved, 0);

				rxbsz = opt_size * to_share;
				rxbsz = (rxbsz + h2c->receiving_streams - 1) / h2c->receiving_streams;

				/* Only provide integral multiples of buffer size.
				 * On the front, we know that largest values are
				 * important for bandwidth, and that the data are
				 * quickly consumed by the servers. Also, any
				 * overestimate only impacts that client. On the
				 * backend, large values have little impact on
				 * performance (low latency), but they can cause
				 * HoL between multiple clients. Thus we round up
				 * on the front and down on the back.
				 */
				if (rxbsz) {
					if (!(h2c->flags & H2_CF_IS_BACK))
						rxbsz += opt_size - 1;

					rxbsz = rxbsz / opt_size * opt_size;
				}
			}

			if (rxbsz > win)
				win = rxbsz;
		}

		/* Principle below: the calculate the next max window offset
		 * from what was received added to the static window size. In
		 * practice, for a static window it makes the next max offset
		 * grow at the same speed as what was received, and
		 * WINDOW_UPDATE frames will also match one for one.
		 */
		h2s->curr_rx_ofs += h2c->rcvd_s;
		h2s->next_max_ofs = h2s->curr_rx_ofs + win;
		h2c->rcvd_s = 0;
		h2c->wu_s = (h2s->next_max_ofs > h2s->last_adv_ofs) ?
		            (h2s->next_max_ofs - h2s->last_adv_ofs) :
		            0;
	} else {
		/* non-existing stream */
		h2c->wu_s += h2c->rcvd_s;
		h2c->rcvd_s = 0;
	}

	return !!h2c->wu_s;
}

/* Try to send pending window update for the current dmux stream. It's safe to
 * call it with no pending updates. Returns > 0 on success or zero on missing
 * room or failure. It may return an error in h2c.
 */
static int h2c_send_strm_wu(struct h2c *h2c)
{
	struct h2s *h2s = NULL;
	int ret = 1;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);

	if (h2c->wu_s <= 0)
		goto out;

	/* send WU for the stream */
	ret = h2c_send_window_update(h2c, h2c->dsi, h2c->wu_s);
	if (ret > 0) {
		h2c->wu_s = 0;
		h2s = h2c_st_by_id(h2c, h2c->dsi);
		if (h2s && h2s->h2c)
			h2s->last_adv_ofs = h2s->next_max_ofs;
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
	return ret;
}

/* try to send an ACK for a ping frame on the connection. Returns > 0 on
 * success, 0 on missing data or one of the h2_status values.
 */
static int h2c_ack_ping(struct h2c *h2c)
{
	struct buffer *res;
	char str[17];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_PING, h2c->conn);

	if (b_data(&h2c->dbuf) < 8)
		goto out;

	memcpy(str,
	       "\x00\x00\x08"     /* length : 8 (same payload) */
	       "\x06" "\x01"      /* type   : 6, flags : ACK   */
	       "\x00\x00\x00\x00" /* stream ID */, 9);

	/* copy the original payload */
	h2_get_buf_bytes(str + 9, 8, &h2c->dbuf, 0);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 17));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_PING, h2c->conn);
	return ret;
}

/* processes a WINDOW_UPDATE frame whose payload is <payload> for <plen> bytes.
 * Returns > 0 on success or zero on missing data. It may return an error in
 * h2c or h2s. The caller must have already verified frame length and stream ID
 * validity. Described in RFC7540#6.9.
 */
static int h2c_handle_window_update(struct h2c *h2c, struct h2s *h2s)
{
	int32_t inc;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out0;
	}

	inc = h2_get_n32(&h2c->dbuf, 0);

	if (h2c->dsi != 0) {
		/* stream window update */

		/* it's not an error to receive WU on a closed stream */
		if (h2s->st == H2_SS_CLOSED)
			goto done;

		if (!inc) {
			h2c_report_glitch(h2c, 1, "stream WINDOW_UPDATE inc=0");
			TRACE_ERROR("stream WINDOW_UPDATE inc=0", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn, h2s);
			error = H2_ERR_PROTOCOL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
			goto strm_err;
		}

		/* WT: it would be tempting to count a glitch here for very small
		 * increments (less than a few tens of bytes), but that might be
		 * perfectly valid for many short streams, so better instead
		 * count the number of WU per frame maybe. That would be better
		 * dealt with using scores per frame.
		 */

		if (h2s_mws(h2s) >= 0 && h2s_mws(h2s) + inc < 0) {
			h2c_report_glitch(h2c, 1, "stream WINDOW_UPDATE inc<0");
			TRACE_ERROR("stream WINDOW_UPDATE inc<0", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn, h2s);
			error = H2_ERR_FLOW_CONTROL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
			goto strm_err;
		}

		h2s->sws += inc;
		if (h2s_mws(h2s) > 0 && (h2s->flags & H2_SF_BLK_SFCTL)) {
			h2s->flags &= ~H2_SF_BLK_SFCTL;
			LIST_DEL_INIT(&h2s->list);
			if ((h2s->subs && h2s->subs->events & SUB_RETRY_SEND) ||
			    h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))
				LIST_APPEND(&h2c->send_list, &h2s->list);
		}
	}
	else {
		/* connection window update */
		if (!inc) {
			h2c_report_glitch(h2c, 1, "conn WINDOW_UPDATE inc=0");
			TRACE_ERROR("conn WINDOW_UPDATE inc=0", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
			error = H2_ERR_PROTOCOL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto conn_err;
		}

		if (h2c->mws >= 0 && h2c->mws + inc < 0) {
			h2c_report_glitch(h2c, 1, "conn WINDOW_UPDATE inc<0");
			TRACE_ERROR("conn WINDOW_UPDATE inc<0", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
			error = H2_ERR_FLOW_CONTROL_ERROR;
			goto conn_err;
		}

		h2c->mws += inc;
	}

 done:
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
	return 1;

 conn_err:
	h2c_error(h2c, error);
 out0:
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
	return 0;

 strm_err:
	h2s_error(h2s, error);
	h2c->st0 = H2_CS_FRAME_E;
	TRACE_DEVEL("leaving on stream error", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
	return 0;
}

/* processes a GOAWAY frame, and signals all streams whose ID is greater than
 * the last ID. Returns > 0 on success or zero on missing data. The caller must
 * have already verified frame length and stream ID validity. Described in
 * RFC7540#6.8.
 */
static int h2c_handle_goaway(struct h2c *h2c)
{
	int last;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn);
	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		TRACE_DEVEL("leaving on missing data", H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn);
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		return 0;
	}

	last = h2_get_n32(&h2c->dbuf, 0);
	h2c->errcode = h2_get_n32(&h2c->dbuf, 4);
	if (h2c->last_sid < 0)
		h2c->last_sid = last;
	h2c_report_term_evt(h2c, muxc_tevt_type_goaway_rcvd);
	h2_wake_some_streams(h2c, last);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn);
	return 1;
}

/* processes a PRIORITY frame, and either skips it or rejects if it is
 * invalid. Returns > 0 on success or zero on missing data. It may return an
 * error in h2c. The caller must have already verified frame length and stream
 * ID validity. Described in RFC7540#6.3.
 */
static int h2c_handle_priority(struct h2c *h2c)
{
	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		TRACE_DEVEL("leaving on missing data", H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		return 0;
	}

	if (h2_get_n32(&h2c->dbuf, 0) == h2c->dsi) {
		/* 7540#5.3 : can't depend on itself */
		h2c_report_glitch(h2c, 1, "PRIORITY depends on itself");
		TRACE_ERROR("PRIORITY depends on itself", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		TRACE_DEVEL("leaving on error", H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);
		return 0;
	}
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);
	return 1;
}

/* processes an RST_STREAM frame, and sets the 32-bit error code on the stream.
 * Returns > 0 on success or zero on missing data. The caller must have already
 * verified frame length and stream ID validity. Described in RFC7540#6.4.
 */
static int h2c_handle_rst_stream(struct h2c *h2c, struct h2s *h2s)
{
	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		TRACE_DEVEL("leaving on missing data", H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		return 0;
	}

	/* late RST, already handled */
	if (h2s->st == H2_SS_CLOSED) {
		TRACE_DEVEL("leaving on stream closed", H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
		return 1;
	}

	h2s->errcode = h2_get_n32(&h2c->dbuf, 0);
	h2s_close(h2s);

	if (h2s_sc(h2s)) {
		se_fl_set_error(h2s->sd);
		se_report_term_evt(h2s->sd, se_tevt_type_rst_rcvd);
		if (!h2s->sd->abort_info.info) {
			h2s->sd->abort_info.info = (SE_ABRT_SRC_MUX_H2 << SE_ABRT_SRC_SHIFT);
			h2s->sd->abort_info.code = h2s->errcode;
		}
		h2s_alert(h2s);
	}

	h2s->flags |= H2_SF_RST_RCVD;
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
	return 1;
}

/* processes a HEADERS frame. Returns h2s on success or NULL on missing data.
 * It may return an error in h2c or h2s. The caller must consider that the
 * return value is the new h2s in case one was allocated (most common case).
 * Described in RFC7540#6.2. Most of the
 * errors here are reported as connection errors since it's impossible to
 * recover from such errors after the compression context has been altered.
 */
static struct h2s *h2c_frt_handle_headers(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer rxbuf = BUF_NULL;
	unsigned long long body_len = 0;
	uint32_t flags = 0;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);

	if (!b_size(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out; // empty buffer
	}

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out; // incomplete frame
	}

	/* now either the frame is complete or the buffer is complete */
	if (h2s->st != H2_SS_IDLE) {
		/* The stream exists/existed, this must be a trailers frame */
		if (h2s->st != H2_SS_CLOSED) {
			if (!h2s_rxbuf_tail(h2s) && !h2s_get_rxbuf(h2s)) {
				TRACE_USER("Not allowed to get an extra buffer for H2 request trailers", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, );
				h2c->flags |= H2_CF_DEM_RXBUF;
				goto out;
			}

			error = h2c_dec_hdrs(h2c, h2s_rxbuf_tail(h2s), &h2s->flags, &body_len, NULL);
			/* unrecoverable error ? */
			if (h2c->st0 >= H2_CS_ERROR) {
				TRACE_USER("Unrecoverable error decoding H2 trailers", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, 0, h2s_rxbuf_tail(h2s));
				sess_log(h2c->conn->owner);
				goto out;
			}

			if (error == 0) {
				/* Demux not blocked because of the stream, it is an incomplete frame,
				 * or the rxbuf is not empty (e.g. for trailers).
				 */
				if (!(h2c->flags & (H2_CF_DEM_BLOCK_ANY | H2_CF_DEM_DFULL)))
					h2c->flags |= H2_CF_DEM_SHORT_READ;
				goto out; // missing data
			}

			if (error < 0) {
				/* Failed to decode this frame (e.g. too large request)
				 * but the HPACK decompressor is still synchronized.
				 */
				sess_log(h2c->conn->owner);
				h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
				TRACE_USER("Stream error decoding H2 trailers", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, 0, h2s_rxbuf_tail(h2s));
				h2c->st0 = H2_CS_FRAME_E;
				goto out;
			}
			goto done;
		}
		/* the stream was already killed by an RST, let's consume
		 * the data and send another RST.
		 */
		error = h2c_dec_hdrs(h2c, &rxbuf, &flags, &body_len, NULL);
		sess_log(h2c->conn->owner);
		h2s = (struct h2s*)h2_error_stream;
		TRACE_USER("rcvd H2 trailers on closed stream", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, h2s, &rxbuf);
		goto send_rst;
	}
	else if (h2c->dsi <= h2c->max_id || !(h2c->dsi & 1)) {
		/* RFC7540#5.1.1 stream id > prev ones, and must be odd here */
		error = H2_ERR_PROTOCOL_ERROR;
		h2c_report_glitch(h2c, 1, "HEADERS on invalid stream ID");
		TRACE_ERROR("HEADERS on invalid stream ID", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		sess_log(h2c->conn->owner);
		session_inc_http_req_ctr(h2c->conn->owner);
		session_inc_http_err_ctr(h2c->conn->owner);
		goto conn_err;
	}
	else if (h2c->flags & H2_CF_DEM_TOOMANY) {
		goto out; // IDLE but too many sc still present
	}
	else if (h2_fe_max_total_streams &&
		 h2c->stream_cnt >= h2_fe_max_total_streams + h2c_max_concurrent_streams(h2c)) {
		/* We've already told this client we were going to close a
		 * while ago and apparently it didn't care, so it's time to
		 * stop processing its requests for real.
		 */
		error = H2_ERR_ENHANCE_YOUR_CALM;
		h2c_report_glitch(h2c, 1, "Stream limit violated");
		TRACE_STATE("Stream limit violated", H2_EV_STRM_SHUT, h2c->conn);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		sess_log(h2c->conn->owner);
		session_inc_http_req_ctr(h2c->conn->owner);
		session_inc_http_err_ctr(h2c->conn->owner);
		goto conn_err;
	}

	error = h2c_dec_hdrs(h2c, &rxbuf, &flags, &body_len, NULL);

	if (error == 0) {
		/* No error but missing data for demuxing, it is an incomplete frame */
		if (!(h2c->flags & (H2_CF_DEM_BLOCK_ANY | H2_CF_DEM_DFULL)))
			h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out;
	}

	/* Now we cannot roll back and we won't come back here anymore for this
	 * stream, so this stream ID is open from a protocol perspective, even
	 * if incomplete or broken, we want to count it as attempted.
	 */
	if (h2c->dsi > h2c->max_id)
		h2c->max_id = h2c->dsi;
	h2c->stream_cnt++;

	if (error < 0) {
		/* Failed to decode this stream. This might be due to a
		 * recoverable error affecting only the stream (e.g. too large
		 * request for buffer, that leaves the HPACK decompressor still
		 * synchronized), or a non-recoverable error such as an invalid
		 * frame type sequence (e.g. other frame type interleaved with
		 * CONTINUATION), in which h2c_dec_hdrs() has already set the
		 * error code in the connection and counted it in the relevant
		 * stats. We still count a req error in both cases.
		 */
		sess_log(h2c->conn->owner);
		session_inc_http_req_ctr(h2c->conn->owner);
		session_inc_http_err_ctr(h2c->conn->owner);

		if (h2c->st0 >= H2_CS_ERROR) {
			TRACE_USER("Unrecoverable error decoding H2 request", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, 0, &rxbuf);
			goto out;
		}

		/* recoverable stream error (e.g. too large request) */
		TRACE_USER("rcvd unparsable H2 request", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, h2s, &rxbuf);
		goto strm_err;
	}

	TRACE_USER("rcvd H2 request  ", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW, h2c->conn, 0, &rxbuf);

	/* Note: we don't emit any other logs below because if we return
	 * positively from h2c_frt_stream_new(), the stream will report the error,
	 * and if we return in error, h2c_frt_stream_new() will emit the error.
	 *
	 * Xfer the rxbuf to the stream. On success, the new stream owns the
	 * rxbuf. On error, it is released here.
	 */
	h2s = h2c_frt_stream_new(h2c, h2c->dsi, &rxbuf, flags);
	if (!h2s) {
		h2s = (struct h2s*)h2_refused_stream;
		TRACE_USER("refused H2 req.  ", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, h2s, &rxbuf);
		goto send_rst;
	}

	h2s->st = H2_SS_OPEN;
	h2s->flags |= flags;
	h2s->body_len = body_len;
	h2s_propagate_term_flags(h2c, h2s);

 done:
	if (h2s->flags & H2_SF_ES_RCVD) {
		h2s_no_longer_receiving(h2s);
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else
			h2s_close(h2s);
	}
	else
		h2s_count_as_receiving(h2s);

	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	goto leave;

 conn_err:
	h2c_error(h2c, error);
 out:
	h2_release_buf(h2c, &rxbuf);
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	h2s = NULL;
	goto leave;

 strm_err:
	h2s = (struct h2s*)h2_error_stream;

 send_rst:
	/* make the demux send an RST for the current stream. We may only
	 * do this if we're certain that the HEADERS frame was properly
	 * decompressed so that the HPACK decoder is still kept up to date.
	 */
	h2_release_buf(h2c, &rxbuf);
	h2c->st0 = H2_CS_FRAME_E;

	TRACE_DEVEL("leaving on error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);

 leave:
	if (h2_fe_max_total_streams && h2c->stream_cnt >= h2_fe_max_total_streams) {
		/* we've had enough streams on this connection, time to renew it.
		 * In order to gracefully do this, we'll advertise a stream limit
		 * of the current one plus the max concurrent streams value in the
		 * GOAWAY frame, so that we're certain that the client is aware of
		 * the limit before creating a new stream, but knows we won't harm
		 * the streams in flight. Remember that client stream IDs are odd
		 * so we apply twice the concurrent streams value to the current
		 * ID.
		 */
		if (h2c->last_sid <= 0 ||
		    h2c->last_sid > h2c->max_id + 2 * h2c_max_concurrent_streams(h2c)) {
			/* not set yet or was too high */
			h2c->last_sid = h2c->max_id + 2 * h2c_max_concurrent_streams(h2c);
			h2c_send_goaway_error(h2c, NULL);
		}
	}

	return h2s;
}

/* processes a HEADERS frame. Returns h2s on success or NULL on missing data.
 * It may return an error in h2c or h2s. Described in RFC7540#6.2. Most of the
 * errors here are reported as connection errors since it's impossible to
 * recover from such errors after the compression context has been altered.
 */
static struct h2s *h2c_bck_handle_headers(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer rxbuf = BUF_NULL;
	unsigned long long body_len = 0;
	uint32_t flags = 0;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);

	if (!b_size(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // empty buffer
	}

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // incomplete frame
	}

	if (h2s->st == H2_SS_CLOSED) {
		/* the connection was already killed by an RST, let's consume
		 * the data and send another RST.
		 */
		error = h2c_dec_hdrs(h2c, &rxbuf, &flags, &body_len, NULL);
		h2s = (struct h2s*)h2_error_stream;
		h2c->st0 = H2_CS_FRAME_E;
		goto send_rst;
	}

	if (!h2s_rxbuf_tail(h2s) && !h2s_get_rxbuf(h2s)) {
		TRACE_USER("Not allowed to get an extra buffer for H2 response HEADERS", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, );
		h2c->flags |= H2_CF_DEM_RXBUF;
		goto fail;
	}

	error = h2c_dec_hdrs(h2c, h2s_rxbuf_tail(h2s), &h2s->flags, &h2s->body_len, h2s->upgrade_protocol);

	/* unrecoverable error ? */
	if (h2c->st0 >= H2_CS_ERROR) {
		TRACE_USER("Unrecoverable error decoding H2 HEADERS", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
		goto fail;
	}

	if (h2s->st != H2_SS_OPEN && h2s->st != H2_SS_HLOC) {
		/* RFC7540#5.1 */
		h2c_report_glitch(h2c, 1, "response HEADERS in invalid state");
		TRACE_ERROR("response HEADERS in invalid state", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
		h2s_error(h2s, H2_ERR_STREAM_CLOSED);
		h2c->st0 = H2_CS_FRAME_E;
		HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
		goto fail;
	}

	if (error <= 0) {
		if (error == 0) {
			/* Demux not blocked because of the stream, it is an incomplete frame,
			 * or the rxbuf is not empty (e.g. for trailers).
			 */
			if (!(h2c->flags & (H2_CF_DEM_BLOCK_ANY | H2_CF_DEM_DFULL)))
				h2c->flags |= H2_CF_DEM_SHORT_READ;
			goto fail; // missing data
		}

		/* stream error : send RST_STREAM */
		TRACE_ERROR("couldn't decode response HEADERS", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
		h2s_error(h2s, H2_ERR_PROTOCOL_ERROR);
		h2c->st0 = H2_CS_FRAME_E;
		HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
		goto fail;
	}

	if (se_fl_test(h2s->sd, SE_FL_ERROR) && h2s->st < H2_SS_ERROR)
		h2s->st = H2_SS_ERROR;
	else if (h2s->flags & H2_SF_ES_RCVD) {
		h2s_no_longer_receiving(h2s);
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else if (h2s->st == H2_SS_HLOC)
			h2s_close(h2s);
	}
	else
		h2s_count_as_receiving(h2s);

	/* Unblock busy server h2s waiting for the response headers to validate
	 * the tunnel establishment or the end of the response of an oborted
	 * tunnel
	 */
	if ((h2s->flags & (H2_SF_BODY_TUNNEL|H2_SF_BLK_MBUSY)) == (H2_SF_BODY_TUNNEL|H2_SF_BLK_MBUSY) ||
	    (h2s->flags & (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) == (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) {
		TRACE_STATE("Unblock h2s blocked on tunnel establishment/abort", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		h2s->flags &= ~H2_SF_BLK_MBUSY;
	}

	TRACE_USER("rcvd H2 response ", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, 0, h2s_rxbuf_tail(h2s));
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return h2s;
 fail:
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return NULL;

 send_rst:
	/* make the demux send an RST for the current stream. We may only
	 * do this if we're certain that the HEADERS frame was properly
	 * decompressed so that the HPACK decoder is still kept up to date.
	 */
	h2_release_buf(h2c, &rxbuf);
	h2c->st0 = H2_CS_FRAME_E;

	TRACE_USER("rejected H2 response", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, 0, &rxbuf);
	TRACE_DEVEL("leaving on error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return h2s;
}

/* processes a DATA frame. Returns > 0 on success or zero on missing data.
 * It may return an error in h2c or h2s. Described in RFC7540#6.1.
 */
static int h2c_handle_data(struct h2c *h2c, struct h2s *h2s)
{
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);

	/* note that empty DATA frames are perfectly valid and sometimes used
	 * to signal an end of stream (with the ES flag).
	 */

	if (!b_size(&h2c->dbuf) && h2c->dfl) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // empty buffer
	}

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // incomplete frame
	}

	/* now either the frame is complete or the buffer is complete */

	if (h2s->st != H2_SS_OPEN && h2s->st != H2_SS_HLOC) {
		/* RFC7540#6.1 */
		error = H2_ERR_STREAM_CLOSED;
		goto strm_err_wu;
	}

	if (!(h2s->flags & H2_SF_HEADERS_RCVD)) {
		/* RFC9113#8.1: The header section must be received before the message content */
		h2c_report_glitch(h2c, 1, "Unexpected DATA frame before the message headers");
		TRACE_ERROR("Unexpected DATA frame before the message headers", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		error = H2_ERR_PROTOCOL_ERROR;
		HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
		goto strm_err_wu;
	}
	if ((h2s->flags & H2_SF_DATA_CLEN) && (h2c->dfl - h2c->dpl) > h2s->body_len) {
		/* RFC7540#8.1.2 */
		h2c_report_glitch(h2c, 1, "DATA frame larger than content-length");
		TRACE_ERROR("DATA frame larger than content-length", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		error = H2_ERR_PROTOCOL_ERROR;
		HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
		goto strm_err_wu;
	}
	if (!(h2c->flags & H2_CF_IS_BACK) &&
	    (h2s->flags & (H2_SF_TUNNEL_ABRT|H2_SF_ES_SENT)) == (H2_SF_TUNNEL_ABRT|H2_SF_ES_SENT) &&
	    ((h2c->dfl - h2c->dpl) || !(h2c->dff & H2_F_DATA_END_STREAM))) {
		/* a tunnel attempt was aborted but the client still try to send some raw data.
		 * Thus the stream is closed with the CANCEL error. Here we take care it is not
		 * an empty DATA Frame with the ES flag. The error is only handled if ES was
		 * already sent to the client because depending on the scheduling, these data may
		 * have been sent before the server response but not handle here.
		 */
		TRACE_ERROR("Request DATA frame for aborted tunnel", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		error = H2_ERR_CANCEL;
		goto strm_err_wu;
	}

	if (!h2_frt_transfer_data(h2s))
		goto fail;

	/* call the upper layers to process the frame, then let the upper layer
	 * notify the stream about any change.
	 */
	if (!h2s_sc(h2s)) {
		/* The upper layer has already closed, this may happen on
		 * 4xx/redirects during POST, or when receiving a response
		 * from an H2 server after the client has aborted.
		 */
		error = H2_ERR_CANCEL;
		goto strm_err;
	}

	if (h2c->st0 >= H2_CS_ERROR)
		goto fail;

	if (h2s->st >= H2_SS_ERROR) {
		/* stream error : send RST_STREAM */
		h2c->st0 = H2_CS_FRAME_E;
	}

	/* check for completion : the callee will change this to FRAME_A or
	 * FRAME_H once done.
	 */
	if (h2c->st0 == H2_CS_FRAME_P)
		goto fail;

	/* last frame */
	if (h2c->dff & H2_F_DATA_END_STREAM) {
		h2s->flags |= H2_SF_ES_RCVD;
		h2s_no_longer_receiving(h2s);
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else
			h2s_close(h2s);

		if (h2s->flags & H2_SF_DATA_CLEN && h2s->body_len) {
			/* RFC7540#8.1.2 */
			h2c_report_glitch(h2c, 1, "ES on DATA frame before content-length");
			TRACE_ERROR("ES on DATA frame before content-length", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
			error = H2_ERR_PROTOCOL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
			goto strm_err;
		}
	}

	/* Unblock busy server h2s waiting for the end of the response for an
	 * aborted tunnel
	 */
	if ((h2c->flags & H2_CF_IS_BACK) &&
	    (h2s->flags & (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) == (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) {
		TRACE_STATE("Unblock h2s blocked on tunnel abort", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		h2s->flags &= ~H2_SF_BLK_MBUSY;
	}

	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 1;

 strm_err_wu:
	/* stream error before the frame was taken into account, we're
	 * going to kill the stream but must still update the connection's
	 * window.
	 */
	h2c->rcvd_c += h2c->dfl - h2c->dpl;
 strm_err:
	h2s_error(h2s, error);
	h2c->st0 = H2_CS_FRAME_E;
 fail:
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 0;
}

/* check that the current frame described in h2c->{dsi,dft,dfl,dff,...} is
 * valid for the current stream state. This is needed only after parsing the
 * frame header but in practice it can be performed at any time during
 * H2_CS_FRAME_P since no state transition happens there. Returns >0 on success
 * or 0 in case of error, in which case either h2s or h2c will carry an error.
 */
static int h2_frame_check_vs_state(struct h2c *h2c, struct h2s *h2s)
{
	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);

	if (h2s->st == H2_SS_IDLE &&
	    h2c->dft != H2_FT_HEADERS && h2c->dft != H2_FT_PRIORITY) {
		/* RFC7540#5.1: any frame other than HEADERS or PRIORITY in
		 * this state MUST be treated as a connection error
		 */
		h2c_report_glitch(h2c, 1, "invalid frame type for IDLE state");
		TRACE_ERROR("invalid frame type for IDLE state", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		if (!h2c->nb_streams && !(h2c->flags & H2_CF_IS_BACK)) {
			/* only log if no other stream can report the error */
			sess_log(h2c->conn->owner);
		}
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		TRACE_DEVEL("leaving in error (idle&!hdrs&!prio)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
		return 0;
	}

	if (h2s->st == H2_SS_IDLE && (h2c->flags & H2_CF_IS_BACK)) {
		/* only PUSH_PROMISE would be permitted here */
		h2c_report_glitch(h2c, 1, "invalid frame type for IDLE state (back)");
		TRACE_ERROR("invalid frame type for IDLE state (back)", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		TRACE_DEVEL("leaving in error (idle&back)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
		return 0;
	}

	if (h2s->st == H2_SS_HREM && h2c->dft != H2_FT_WINDOW_UPDATE &&
	    h2c->dft != H2_FT_RST_STREAM && h2c->dft != H2_FT_PRIORITY) {
		/* RFC7540#5.1: any frame other than WU/PRIO/RST in
		 * this state MUST be treated as a stream error.
		 * 6.2, 6.6 and 6.10 further mandate that HEADERS/
		 * PUSH_PROMISE/CONTINUATION cause connection errors.
		 */
		if (h2_ft_bit(h2c->dft) & H2_FT_HDR_MASK) {
			h2c_report_glitch(h2c, 1, "invalid frame type for HREM state");
			TRACE_ERROR("invalid frame type for HREM state", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		}
		else {
			h2c_report_glitch(h2c, 1, "invalid frame type in HREM state");
			h2s_error(h2s, H2_ERR_STREAM_CLOSED);
		}
		TRACE_DEVEL("leaving in error (hrem&!wu&!rst&!prio)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
		return 0;
	}

	/* Below the management of frames received in closed state is a
	 * bit hackish because the spec makes strong differences between
	 * streams closed by receiving RST, sending RST, and seeing ES
	 * in both directions. In addition to this, the creation of a
	 * new stream reusing the identifier of a closed one will be
	 * detected here. Given that we cannot keep track of all closed
	 * streams forever, we consider that unknown closed streams were
	 * closed on RST received, which allows us to respond with an
	 * RST without breaking the connection (eg: to abort a transfer).
	 * Some frames have to be silently ignored as well.
	 */
	if (h2s->st == H2_SS_CLOSED && h2c->dsi) {
		if (!(h2c->flags & H2_CF_IS_BACK) && h2_ft_bit(h2c->dft) & H2_FT_HDR_MASK) {
			/* #5.1.1: The identifier of a newly
			 * established stream MUST be numerically
			 * greater than all streams that the initiating
			 * endpoint has opened or reserved. This
			 * governs streams that are opened using a
			 * HEADERS frame and streams that are reserved
			 * using PUSH_PROMISE. An endpoint that
			 * receives an unexpected stream identifier
			 * MUST respond with a connection error.
			 */
			h2c_report_glitch(h2c, 1, "invalid frame type in CLOSED state");
			h2c_error(h2c, H2_ERR_STREAM_CLOSED);
			TRACE_DEVEL("leaving in error (closed&hdrmask)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
			return 0;
		}

		if (h2s->flags & H2_SF_RST_RCVD &&
		    !(h2_ft_bit(h2c->dft) & (H2_FT_HDR_MASK | H2_FT_RST_STREAM_BIT | H2_FT_PRIORITY_BIT | H2_FT_WINDOW_UPDATE_BIT))) {
			/* RFC7540#5.1:closed: an endpoint that
			 * receives any frame other than PRIORITY after
			 * receiving a RST_STREAM MUST treat that as a
			 * stream error of type STREAM_CLOSED.
			 *
			 * Note that old streams fall into this category
			 * and will lead to an RST being sent.
			 *
			 * However, we cannot generalize this to all frame types. Those
			 * carrying compression state must still be processed before
			 * being dropped or we'll desynchronize the decoder. This can
			 * happen with request trailers received after sending an
			 * RST_STREAM, or with header/trailers responses received after
			 * sending RST_STREAM (aborted stream).
			 *
			 * In addition, since our CLOSED streams always carry the
			 * RST_RCVD bit, we don't want to accidentally catch valid
			 * frames for a closed stream, i.e. RST/PRIO/WU.
			 */
			if (h2c->dft == H2_FT_DATA) {
				/* even if we reject out-of-stream DATA, it must
				 * still count against the connection's flow control.
				 */
				h2c->rcvd_c += h2c->dfl - h2c->dpl;
			}

			h2c_report_glitch(h2c, 1, "invalid frame type after receiving RST_STREAM");
			h2s_error(h2s, H2_ERR_STREAM_CLOSED);
			h2c->st0 = H2_CS_FRAME_E;
			TRACE_DEVEL("leaving in error (rst_rcvd&!hdrmask)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
			return 0;
		}

		/* RFC7540#5.1:closed: if this state is reached as a
		 * result of sending a RST_STREAM frame, the peer that
		 * receives the RST_STREAM might have already sent
		 * frames on the stream that cannot be withdrawn. An
		 * endpoint MUST ignore frames that it receives on
		 * closed streams after it has sent a RST_STREAM
		 * frame. An endpoint MAY choose to limit the period
		 * over which it ignores frames and treat frames that
		 * arrive after this time as being in error.
		 */
		if (h2s->id && !(h2s->flags & H2_SF_RST_SENT)) {
			/* RFC7540#5.1:closed: any frame other than
			 * PRIO/WU/RST in this state MUST be treated as
			 * a connection error
			 */
			if (h2c->dft != H2_FT_RST_STREAM &&
			    h2c->dft != H2_FT_PRIORITY &&
			    h2c->dft != H2_FT_WINDOW_UPDATE) {
				h2c_report_glitch(h2c, 1, "ignoring unacceptable frame type after RST_STREAM sent");
				h2c_error(h2c, H2_ERR_STREAM_CLOSED);
				TRACE_DEVEL("leaving in error (rst_sent&!rst&!prio&!wu)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
				return 0;
			}
		}
	}
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
	return 1;
}

/* Reverse the connection <h2c>. Common operations are done for both active and
 * passive reversal. Timeouts are inverted and H2_CF_IS_BACK is set or unset
 * depending on the reversal direction.
 *
 * For active reversal, only minor steps are required. The connection should
 * then be accepted by its listener before being able to use it for transfers.
 *
 * For passive reversal, connection is inserted in its targeted server idle
 * pool. It can thus be reused immediately for future transfers on this server.
 *
 * Returns 1 on success else 0.
 */
static int h2_conn_reverse(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	if (conn_reverse(conn)) {
		TRACE_ERROR("reverse connection failed", H2_EV_H2C_WAKE, conn);
		goto err;
	}

	TRACE_USER("reverse connection", H2_EV_H2C_WAKE, conn);

	/* Check the connection new side after reversal. */
	if (conn_is_back(conn)) {
		struct server *srv = __objt_server(h2c->conn->target);
		struct proxy *prx = srv->proxy;

		h2c->flags |= H2_CF_IS_BACK;

		h2c->shut_timeout = h2c->timeout = prx->timeout.server;
		if (tick_isset(prx->timeout.serverfin))
			h2c->shut_timeout = prx->timeout.serverfin;

		h2c->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_be,
		                                      &h2_stats_module);

		HA_ATOMIC_OR(&h2c->wait_event.tasklet->state, TASK_F_USR1);
		xprt_set_idle(conn, conn->xprt, conn->xprt_ctx);
		if (!srv_add_to_idle_list(srv, conn, 1))
			goto err;
	}
	else {
		struct listener *l = __objt_listener(h2c->conn->target);
		struct proxy *prx = l->bind_conf->frontend;

		h2c->flags &= ~H2_CF_IS_BACK;

		h2c->shut_timeout = h2c->timeout = prx->timeout.client;
		if (tick_isset(prx->timeout.clientfin))
			h2c->shut_timeout = prx->timeout.clientfin;

		h2c->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                                      &h2_stats_module);

		proxy_inc_fe_cum_sess_ver_ctr(l, prx, 2);

		BUG_ON(LIST_INLIST(&h2c->conn->stopping_list));
		LIST_APPEND(&mux_stopping_data[tid].list,
		            &h2c->conn->stopping_list);
	}

	HA_ATOMIC_INC(&h2c->px_counters->open_conns);
	HA_ATOMIC_INC(&h2c->px_counters->total_conns);

	/* Check if stream creation is initially forbidden. This is the case
	 * for active preconnect until reversal is done.
	 */
	if (conn_reverse_in_preconnect(h2c->conn)) {
		TRACE_DEVEL("prevent stream demux until accept is done", H2_EV_H2C_WAKE, conn);
		h2c->flags |= H2_CF_DEM_TOOMANY;
	}

	/* If only the new side has a defined timeout, task must be allocated.
	 * On the contrary, if only old side has a timeout, it must be freed.
	 */
	if (!h2c->task && tick_isset(h2c->timeout)) {
		h2c->task = task_new_here();
		if (!h2c->task)
			goto err;

		h2c->task->process = h2_timeout_task;
		h2c->task->context = h2c;
	}
	else if (!tick_isset(h2c->timeout)) {
		task_destroy(h2c->task);
		h2c->task = NULL;
	}

	/* Requeue task if instantiated with the new timeout value. */
	if (h2c->task) {
		h2c->task->expire = tick_add(now_ms, h2c->timeout);
		task_queue(h2c->task);
	}

	TRACE_LEAVE(H2_EV_H2C_WAKE, h2c->conn);
	return 1;

 err:
	h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
	TRACE_DEVEL("leaving on error", H2_EV_H2C_WAKE);
	return 0;
}

/* process Rx frames to be demultiplexed */
static void h2_process_demux(struct h2c *h2c)
{
	struct h2s *h2s = NULL, *tmp_h2s;
	struct h2_fh hdr;
	unsigned int padlen = 0;
	int32_t old_iw = h2c->miw;

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	if (h2c->st0 >= H2_CS_ERROR)
		goto out;

	if (unlikely(h2c->st0 < H2_CS_FRAME_H)) {
		if (h2c->st0 == H2_CS_PREFACE) {
			TRACE_STATE("expecting preface", H2_EV_RX_PREFACE, h2c->conn);
			if (h2c->flags & H2_CF_IS_BACK)
				goto out;

			if (unlikely(h2c_frt_recv_preface(h2c) <= 0)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				if (h2c->st0 == H2_CS_ERROR) {
					if (b_data(&h2c->dbuf) ||
					    !(((const struct session *)h2c->conn->owner)->fe->options & (PR_O_NULLNOLOG|PR_O_IGNORE_PRB)))
						h2c_report_glitch(h2c, 1, "invalid preface received");

					TRACE_PROTO("failed to receive preface", H2_EV_RX_PREFACE|H2_EV_PROTO_ERR, h2c->conn);
					h2c->st0 = H2_CS_ERROR2;
					if (b_data(&h2c->dbuf) ||
					    !(((const struct session *)h2c->conn->owner)->fe->options & (PR_O_NULLNOLOG|PR_O_IGNORE_PRB)))
						sess_log(h2c->conn->owner);
				}
				goto done;
			}
			TRACE_PROTO("received preface", H2_EV_RX_PREFACE, h2c->conn);

			h2c->max_id = 0;
			TRACE_STATE("switching to SETTINGS1", H2_EV_RX_PREFACE, h2c->conn);
			h2c->st0 = H2_CS_SETTINGS1;
		}

		if (h2c->st0 == H2_CS_SETTINGS1) {
			/* ensure that what is pending is a valid SETTINGS frame
			 * without an ACK.
			 */
			TRACE_STATE("expecting settings", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS, h2c->conn);
			if (!h2_get_frame_hdr(&h2c->dbuf, &hdr)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				h2c->flags |= H2_CF_DEM_SHORT_READ;
				if (h2c->st0 == H2_CS_ERROR) {
					h2c_report_glitch(h2c, 1, "failed to receive settings");
					TRACE_ERROR("failed to receive settings", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS|H2_EV_PROTO_ERR, h2c->conn);
					h2c->st0 = H2_CS_ERROR2;
					if (!(h2c->flags & H2_CF_IS_BACK))
						sess_log(h2c->conn->owner);
				}
				goto done;
			}

			if (hdr.sid || hdr.ft != H2_FT_SETTINGS || hdr.ff & H2_F_SETTINGS_ACK) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				h2c_report_glitch(h2c, 1, "unexpected frame type or flags while waiting for SETTINGS");
				TRACE_ERROR("unexpected frame type or flags", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
				h2c->st0 = H2_CS_ERROR2;
				if (!(h2c->flags & H2_CF_IS_BACK))
					sess_log(h2c->conn->owner);
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto done;
			}

			if ((int)hdr.len < 0 || (int)hdr.len > global.tune.bufsize) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				h2c_report_glitch(h2c, 1, "invalid settings frame length");
				TRACE_ERROR("invalid settings frame length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
				h2c->st0 = H2_CS_ERROR2;
				if (!(h2c->flags & H2_CF_IS_BACK))
					sess_log(h2c->conn->owner);
				goto done;
			}

			/* that's OK, switch to FRAME_P to process it. This is
			 * a SETTINGS frame whose header has already been
			 * deleted above.
			 */
			padlen = 0;
			HA_ATOMIC_INC(&h2c->px_counters->settings_rcvd);
			goto new_frame;
		}
	}

	/* process as many incoming frames as possible below */
	while (1) {
		int ret = 0;

		/* Make sure to clear DFULL if contents were deleted */
		if (!b_full(&h2c->dbuf))
			h2c->flags &= ~H2_CF_DEM_DFULL;

		if (!b_data(&h2c->dbuf)) {
			TRACE_DEVEL("no more Rx data", H2_EV_RX_FRAME, h2c->conn);
			h2c->flags |= H2_CF_DEM_SHORT_READ;
			break;
		}

		if (h2c->st0 >= H2_CS_ERROR) {
			TRACE_STATE("end of connection reported", H2_EV_RX_FRAME|H2_EV_RX_EOI, h2c->conn);
			break;
		}

		if (h2c->st0 == H2_CS_FRAME_H) {
			TRACE_STATE("expecting H2 frame header", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn);
			if (!h2_peek_frame_hdr(&h2c->dbuf, 0, &hdr)) {
				h2c->flags |= H2_CF_DEM_SHORT_READ;
				break;
			}

			if ((int)hdr.len < 0 || (int)hdr.len > global.tune.bufsize) {
				h2c_report_glitch(h2c, 1, "invalid H2 frame length");
				TRACE_ERROR("invalid H2 frame length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
				if (!h2c->nb_streams && !(h2c->flags & H2_CF_IS_BACK)) {
					/* only log if no other stream can report the error */
					sess_log(h2c->conn->owner);
				}
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				break;
			}

			if (h2c_update_strm_rx_win(h2c) && h2c->dsi != hdr.sid) {
				/* changed stream with a pending WU, need to
				 * send it now.
				 */
				TRACE_PROTO("sending stream WINDOW_UPDATE frame on stream switch", H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
				ret = h2c_send_strm_wu(h2c);
				if (ret <= 0)
					break;
			}

			padlen = 0;
			if (h2_ft_bit(hdr.ft) & H2_FT_PADDED_MASK && hdr.ff & H2_F_PADDED) {
				/* If the frame is padded (HEADERS, PUSH_PROMISE or DATA),
				 * we read the pad length and drop it from the remaining
				 * payload (one byte + the 9 remaining ones = 10 total
				 * removed), so we have a frame payload starting after the
				 * pad len. Flow controlled frames (DATA) also count the
				 * padlen in the flow control, so it must be adjusted.
				 */
				if (hdr.len < 1) {
					h2c_report_glitch(h2c, 1, "invalid H2 padded frame length");
					TRACE_ERROR("invalid H2 padded frame length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
					h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
					if (!(h2c->flags & H2_CF_IS_BACK))
						sess_log(h2c->conn->owner);
					HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
					goto done;
				}
				hdr.len--;

				if (b_data(&h2c->dbuf) < 10) {
					h2c->flags |= H2_CF_DEM_SHORT_READ;
					break; // missing padlen
				}

				padlen = *(uint8_t *)b_peek(&h2c->dbuf, 9);

				if (padlen > hdr.len) {
					h2c_report_glitch(h2c, 1, "invalid H2 padding length");
					TRACE_ERROR("invalid H2 padding length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
					/* RFC7540#6.1 : pad length = length of
					 * frame payload or greater => error.
					 */
					h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
					if (!(h2c->flags & H2_CF_IS_BACK))
						sess_log(h2c->conn->owner);
					HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
					goto done;
				}

				if (h2_ft_bit(hdr.ft) & H2_FT_FC_MASK) {
					h2c->rcvd_c++;
					h2c->rcvd_s++;
				}
				b_del(&h2c->dbuf, 1);
			}
			h2_skip_frame_hdr(&h2c->dbuf);

		new_frame:
			h2c->dfl = hdr.len;
			h2c->dsi = hdr.sid;
			h2c->dft = hdr.ft;
			h2c->dff = hdr.ff;
			h2c->dpl = padlen;
			h2c->flags |= H2_CF_DEM_IN_PROGRESS;
			TRACE_STATE("rcvd H2 frame header, switching to FRAME_P state", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn);
			h2c->st0 = H2_CS_FRAME_P;

			/* check for minimum basic frame format validity */
			ret = h2_frame_check(h2c->dft, 1, h2c->dsi, h2c->dfl, global.tune.bufsize);
			if (ret != H2_ERR_NO_ERROR) {
				h2c_report_glitch(h2c, 1, "received invalid H2 frame header");
				TRACE_ERROR("received invalid H2 frame header", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, ret);
				if (!(h2c->flags & H2_CF_IS_BACK))
					sess_log(h2c->conn->owner);
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto done;
			}

			/* transition to HEADERS frame ends the keep-alive idle
			 * timer and starts the http-request idle delay. It uses
			 * the idle_start timer as well.
			 */
			if (hdr.ft == H2_FT_HEADERS)
				h2c->idle_start = now_ms;
		}

		/* Make sure to clear DFULL if contents were deleted */
		if (!b_full(&h2c->dbuf))
			h2c->flags &= ~H2_CF_DEM_DFULL;

		/* Only H2_CS_FRAME_P, H2_CS_FRAME_A and H2_CS_FRAME_E here.
		 * H2_CS_FRAME_P indicates an incomplete previous operation
		 * (most often the first attempt) and requires some validity
		 * checks for the frame and the current state. The two other
		 * ones are set after completion (or abortion) and must skip
		 * validity checks.
		 */
		tmp_h2s = h2c_st_by_id(h2c, h2c->dsi);

		if (tmp_h2s != h2s && h2s && h2s_sc(h2s) &&
		    ((h2s_rxbuf_head(h2s) && b_data(h2s_rxbuf_head(h2s))) ||
		     h2c_read0_pending(h2c) ||
		     h2s->st == H2_SS_CLOSED ||
		     (h2s->flags & H2_SF_ES_RCVD) ||
		     se_fl_test(h2s->sd, SE_FL_ERROR | SE_FL_ERR_PENDING | SE_FL_EOS))) {
			/* we may have to signal the upper layers */
			TRACE_DEVEL("notifying stream before switching SID", H2_EV_RX_FRAME|H2_EV_STRM_WAKE, h2c->conn, h2s);
			se_fl_set(h2s->sd, SE_FL_RCV_MORE);
			h2s_notify_recv(h2s);
		}
		h2s = tmp_h2s;

		if (h2c->st0 == H2_CS_FRAME_E ||
		    (h2c->st0 == H2_CS_FRAME_P && !h2_frame_check_vs_state(h2c, h2s))) {
			TRACE_PROTO("stream error reported", H2_EV_RX_FRAME|H2_EV_PROTO_ERR, h2c->conn, h2s);
			goto strm_err;
		}

		switch (h2c->dft) {
		case H2_FT_SETTINGS:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 SETTINGS frame", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn, h2s);
				ret = h2c_handle_settings(h2c);
			}
			HA_ATOMIC_INC(&h2c->px_counters->settings_rcvd);

			if (h2c->st0 == H2_CS_FRAME_A) {
				TRACE_PROTO("sending H2 SETTINGS ACK frame", H2_EV_TX_FRAME|H2_EV_RX_SETTINGS, h2c->conn, h2s);
				ret = h2c_ack_settings(h2c);

				if (ret > 0 && conn_is_reverse(h2c->conn)) {
					/* Initiate connection reversal after SETTINGS reception. */
					ret = h2_conn_reverse(h2c);
				}
			}
			break;

		case H2_FT_PING:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 PING frame", H2_EV_RX_FRAME|H2_EV_RX_PING, h2c->conn, h2s);
				ret = h2c_handle_ping(h2c);
			}

			if (h2c->st0 == H2_CS_FRAME_A) {
				TRACE_PROTO("sending H2 PING ACK frame", H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn, h2s);
				ret = h2c_ack_ping(h2c);
			}
			break;

		case H2_FT_WINDOW_UPDATE:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 WINDOW_UPDATE frame", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn, h2s);
				ret = h2c_handle_window_update(h2c, h2s);
			}
			break;

		case H2_FT_CONTINUATION:
			/* RFC7540#6.10: CONTINUATION may only be preceded by
			 * a HEADERS/PUSH_PROMISE/CONTINUATION frame. These
			 * frames' parsers consume all following CONTINUATION
			 * frames so this one is out of sequence.
			 */
			h2c_report_glitch(h2c, 1, "received unexpected H2 CONTINUATION frame");
			TRACE_ERROR("received unexpected H2 CONTINUATION frame", H2_EV_RX_FRAME|H2_EV_RX_CONT|H2_EV_H2C_ERR, h2c->conn, h2s);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			if (!(h2c->flags & H2_CF_IS_BACK))
				sess_log(h2c->conn->owner);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto done;

		case H2_FT_HEADERS:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 HEADERS frame", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
				if (h2c->flags & H2_CF_IS_BACK)
					tmp_h2s = h2c_bck_handle_headers(h2c, h2s);
				else
					tmp_h2s = h2c_frt_handle_headers(h2c, h2s);
				if (tmp_h2s) {
					h2s = tmp_h2s;
					ret = 1;
				}
			}
			HA_ATOMIC_INC(&h2c->px_counters->headers_rcvd);
			break;

		case H2_FT_DATA:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 DATA frame", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
				ret = h2c_handle_data(h2c, h2s);
			}
			HA_ATOMIC_INC(&h2c->px_counters->data_rcvd);

			if (h2c->st0 == H2_CS_FRAME_A) {
				/* rcvd_s will suffice to trigger the sending of a WU */
				h2c->st0 = H2_CS_FRAME_H;
			}
			break;

		case H2_FT_PRIORITY:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 PRIORITY frame", H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn, h2s);
				ret = h2c_handle_priority(h2c);
			}
			break;

		case H2_FT_RST_STREAM:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 RST_STREAM frame", H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
				ret = h2c_handle_rst_stream(h2c, h2s);
			}
			HA_ATOMIC_INC(&h2c->px_counters->rst_stream_rcvd);
			break;

		case H2_FT_GOAWAY:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 GOAWAY frame", H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn, h2s);
				ret = h2c_handle_goaway(h2c);
			}
			HA_ATOMIC_INC(&h2c->px_counters->goaway_rcvd);
			break;

			/* implement all extra frame types here */
		default:
			TRACE_PROTO("receiving H2 ignored frame", H2_EV_RX_FRAME, h2c->conn, h2s);
			/* drop frames that we ignore. They may be larger than
			 * the buffer so we drain all of their contents until
			 * we reach the end.
			 */
			ret = MIN(b_data(&h2c->dbuf), h2c->dfl);
			b_del(&h2c->dbuf, ret);
			h2c->dfl -= ret;
			ret = h2c->dfl == 0;
		}

	strm_err:
		/* We may have to send an RST if not done yet */
		if (h2s->st == H2_SS_ERROR) {
			TRACE_STATE("stream error, switching to FRAME_E", H2_EV_RX_FRAME|H2_EV_H2S_ERR, h2c->conn, h2s);
			h2c->st0 = H2_CS_FRAME_E;
		}

		if (h2c->st0 == H2_CS_FRAME_E) {
			TRACE_PROTO("sending H2 RST_STREAM frame", H2_EV_TX_FRAME|H2_EV_TX_RST|H2_EV_TX_EOI, h2c->conn, h2s);
			ret = h2c_send_rst_stream(h2c, h2s);
		}

		/* error or missing data condition met above ? */
		if (ret <= 0)
			break;

		if (h2c->st0 != H2_CS_FRAME_H) {
			if (h2c->dfl)
				TRACE_DEVEL("skipping remaining frame payload", H2_EV_RX_FRAME, h2c->conn, h2s);
			ret = MIN(b_data(&h2c->dbuf), h2c->dfl);
			b_del(&h2c->dbuf, ret);
			h2c->dfl -= ret;
			if (!h2c->dfl) {
				h2c->flags &= ~H2_CF_DEM_IN_PROGRESS;
				TRACE_STATE("switching to FRAME_H", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn);
				h2c->st0 = H2_CS_FRAME_H;
			}
		}
	}

	if (h2c_update_strm_rx_win(h2c) &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MROOM))) {
		TRACE_PROTO("sending stream WINDOW_UPDATE frame", H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn, h2s);
		h2c_send_strm_wu(h2c);
	}

	if (h2c->rcvd_c > 0 &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MROOM))) {
		TRACE_PROTO("sending H2 WINDOW_UPDATE frame", H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
		h2c_send_conn_wu(h2c);
	}

 done:
	if (h2c->st0 >= H2_CS_ERROR || (h2c->flags & H2_CF_DEM_SHORT_READ)) {
		if (h2c->flags & H2_CF_RCVD_SHUT)
			h2c->flags |= H2_CF_END_REACHED;
	}

	if (h2c->flags & H2_CF_ERROR)
		h2c_report_term_evt(h2c, ((eb_is_empty(&h2c->streams_by_id) && !(h2c->flags & H2_CF_DEM_IN_PROGRESS))
					  ? muxc_tevt_type_rcv_err
					  : muxc_tevt_type_truncated_rcv_err));
	else if (h2c->flags & H2_CF_END_REACHED)
		h2c_report_term_evt(h2c, ((eb_is_empty(&h2c->streams_by_id) && !(h2c->flags & H2_CF_DEM_IN_PROGRESS))
					  ? muxc_tevt_type_shutr
					  : muxc_tevt_type_truncated_shutr));

	/* Make sure to clear DFULL if contents were deleted */
	if (!b_full(&h2c->dbuf))
		h2c->flags &= ~H2_CF_DEM_DFULL;

	if (h2s && h2s_sc(h2s) &&
	    ((h2s_rxbuf_head(h2s) && b_data(h2s_rxbuf_head(h2s))) ||
	     h2c_read0_pending(h2c) ||
	     h2s->st == H2_SS_CLOSED ||
	     (h2s->flags & H2_SF_ES_RCVD) ||
	     se_fl_test(h2s->sd, SE_FL_ERROR | SE_FL_ERR_PENDING | SE_FL_EOS))) {
		/* we may have to signal the upper layers */
		TRACE_DEVEL("notifying stream before switching SID", H2_EV_RX_FRAME|H2_EV_H2S_WAKE, h2c->conn, h2s);
		se_fl_set(h2s->sd, SE_FL_RCV_MORE);
		h2s_notify_recv(h2s);
	}

	if (old_iw != h2c->miw) {
		TRACE_STATE("notifying streams about SFCTL increase", H2_EV_RX_FRAME|H2_EV_H2S_WAKE, h2c->conn);
		h2c_unblock_sfctl(h2c);
	}

 out:
	TRACE_LEAVE(H2_EV_H2C_WAKE, h2c->conn);
	return;
}

/* resume each h2s eligible for sending in list head <head> */
static void h2_resume_each_sending_h2s(struct h2c *h2c, struct list *head)
{
	struct h2s *h2s, *h2s_back;

	TRACE_ENTER(H2_EV_H2C_SEND|H2_EV_H2S_WAKE, h2c->conn);

	list_for_each_entry_safe(h2s, h2s_back, head, list) {
		if (h2c->mws <= 0 ||
		    h2c->flags & H2_CF_MUX_BLOCK_ANY ||
		    h2c->st0 >= H2_CS_ERROR)
			break;

		h2s->flags &= ~H2_SF_BLK_ANY;

		if (h2s->flags & H2_SF_NOTIFIED)
			continue;

		/* If the sender changed his mind and unsubscribed, let's just
		 * remove the stream from the send_list.
		 */
		if (!(h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW)) &&
		    (!h2s->subs || !(h2s->subs->events & SUB_RETRY_SEND))) {
			LIST_DEL_INIT(&h2s->list);
			continue;
		}

		if (h2s->subs && h2s->subs->events & SUB_RETRY_SEND) {
			h2s->flags |= H2_SF_NOTIFIED;
			tasklet_wakeup(h2s->subs->tasklet);
			h2s->subs->events &= ~SUB_RETRY_SEND;
			if (!h2s->subs->events)
				h2s->subs = NULL;
		}
		else if (h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW)) {
			tasklet_wakeup(h2s->shut_tl);
		}
	}

	TRACE_LEAVE(H2_EV_H2C_SEND|H2_EV_H2S_WAKE, h2c->conn);
}

/* removes a stream from the list it may be in. If a stream has recently been
 * appended to the send_list, it might have been waiting on this one when
 * entering h2_snd_buf() and expecting it to complete before starting to send
 * in turn. For this reason we check (and clear) H2_CF_WAIT_INLIST to detect
 * this condition, and we try to resume sending streams if it happens. Note
 * that we don't need to do it for fctl_list as this list is relevant before
 * (only consulted after) a window update on the connection, and not because
 * of any competition with other streams.
 */
static inline void h2_remove_from_list(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;

	if (!LIST_INLIST(&h2s->list))
		return;

	LIST_DEL_INIT(&h2s->list);
	if (h2c->flags & H2_CF_WAIT_INLIST) {
		h2c->flags &= ~H2_CF_WAIT_INLIST;
		h2_resume_each_sending_h2s(h2c, &h2c->send_list);
	}
}

/* process Tx frames from streams to be multiplexed. Returns > 0 if it reached
 * the end.
 */
static int h2_process_mux(struct h2c *h2c)
{
	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	if (unlikely(h2c->st0 < H2_CS_FRAME_H)) {
		if (unlikely(h2c->st0 == H2_CS_PREFACE && (h2c->flags & H2_CF_IS_BACK))) {
			if (unlikely(h2c_bck_send_preface(h2c) <= 0)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				if (h2c->st0 == H2_CS_ERROR)
					h2c->st0 = H2_CS_ERROR2;
				goto fail;
			}
			h2c->st0 = H2_CS_SETTINGS1;
		}
		/* need to wait for the other side */
		if (h2c->st0 < H2_CS_FRAME_H)
			goto done;
	}

	/* start by sending possibly pending window updates */
	if (h2c_update_strm_rx_win(h2c) &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_MUX_MALLOC)) &&
	    h2c_send_strm_wu(h2c) < 0)
		goto fail;

	if (h2c->rcvd_c > 0 &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_MUX_MALLOC)) &&
	    h2c_send_conn_wu(h2c) < 0)
		goto fail;

	/* First we always process the flow control list because the streams
	 * waiting there were already elected for immediate emission but were
	 * blocked just on this.
	 */
	h2c->flags &= ~H2_CF_WAIT_INLIST;
	h2_resume_each_sending_h2s(h2c, &h2c->fctl_list);
	h2_resume_each_sending_h2s(h2c, &h2c->send_list);

 fail:
	if (unlikely(h2c->st0 >= H2_CS_ERROR)) {
		if (h2c->st0 == H2_CS_ERROR) {
			if (h2c->max_id >= 0) {
				h2c_send_goaway_error(h2c, NULL);
				if (h2c->flags & H2_CF_MUX_BLOCK_ANY)
					goto out0;
			}

			h2c->st0 = H2_CS_ERROR2; // sent (or failed hard) !
		}
	}
 done:
	TRACE_LEAVE(H2_EV_H2C_WAKE, h2c->conn);
	return 1;
 out0:
	TRACE_DEVEL("leaving in blocked situation", H2_EV_H2C_WAKE, h2c->conn);
	return 0;
}


/* Attempt to read data, and subscribe if none available.
 * The function returns 1 if data has been received, otherwise zero.
 */
static int h2_recv(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;
	struct buffer *buf;
	int max;
	size_t ret;

	TRACE_ENTER(H2_EV_H2C_RECV, h2c->conn);

	if (h2c->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("leaving on sub_recv", H2_EV_H2C_RECV, h2c->conn);
		return (b_data(&h2c->dbuf));
	}

	if (!h2_recv_allowed(h2c)) {
		TRACE_DEVEL("leaving on !recv_allowed", H2_EV_H2C_RECV, h2c->conn);
		return 1;
	}

	buf = h2_get_buf(h2c, &h2c->dbuf);
	if (!buf) {
		h2c->flags |= H2_CF_DEM_DALLOC;
		TRACE_DEVEL("leaving on !alloc", H2_EV_H2C_RECV, h2c->conn);
		return 0;
	}

	if (!b_data(buf)) {
		/* try to pre-align the buffer like the
		 * rxbufs will be to optimize memory copies. We'll make
		 * sure that the frame header lands at the end of the
		 * HTX block to alias it upon recv. We cannot use the
		 * head because rcv_buf() will realign the buffer if
		 * it's empty. Thus we cheat and pretend we already
		 * have a few bytes there.
		 */
		max = buf_room_for_htx_data(buf) + 9;
		buf->head = sizeof(struct htx) - 9;
	}
	else
		max = b_room(buf);

	ret = max ? conn->xprt->rcv_buf(conn, conn->xprt_ctx, buf, max, 0) : 0;

	if (max && !ret && h2_recv_allowed(h2c)) {
		TRACE_DATA("failed to receive data, subscribing", H2_EV_H2C_RECV, h2c->conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV, &h2c->wait_event);
	} else if (ret) {
		TRACE_DATA("received data", H2_EV_H2C_RECV, h2c->conn, 0, 0, (void*)(long)ret);
		h2c->flags &= ~H2_CF_DEM_SHORT_READ;
	}

	if (conn_xprt_read0_pending(h2c->conn)) {
		TRACE_DATA("received read0", H2_EV_H2C_RECV, h2c->conn);
		h2c->flags |= H2_CF_RCVD_SHUT;
	}
	if (h2c->conn->flags & CO_FL_ERROR &&
	    (!b_data(&h2c->dbuf) || (h2c->flags & H2_CF_DEM_SHORT_READ))) {
		TRACE_DATA("connection error", H2_EV_H2C_RECV, h2c->conn);
		h2c->flags |= H2_CF_ERROR;
	}

	if (!b_data(buf)) {
		h2_release_buf(h2c, &h2c->dbuf);
		goto end;
	}

	if (b_data(buf) == buf->size) {
		h2c->flags |= H2_CF_DEM_DFULL;
		TRACE_STATE("demux buffer full", H2_EV_H2C_RECV|H2_EV_H2C_BLK, h2c->conn);
	}

  end:
	TRACE_LEAVE(H2_EV_H2C_RECV, h2c->conn);
	return !!ret || (h2c->flags & (H2_CF_RCVD_SHUT|H2_CF_ERROR));
}

/* Try to send data if possible.
 * The function returns 1 if data have been sent, otherwise zero.
 */
static int h2_send(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;
	int done;
	int sent = 0;

	TRACE_ENTER(H2_EV_H2C_SEND, h2c->conn);

	if (h2c->flags & (H2_CF_ERROR|H2_CF_ERR_PENDING)) {
		TRACE_DEVEL("leaving on error", H2_EV_H2C_SEND, h2c->conn);
		if (h2c->flags & H2_CF_END_REACHED)
			h2c->flags |= H2_CF_ERROR;
		b_reset(br_tail(h2c->mbuf));
		h2c->idle_start = now_ms;
		return 1;
	}

	/* This loop is quite simple : it tries to fill as much as it can from
	 * pending streams into the existing buffer until it's reportedly full
	 * or the end of send requests is reached. Then it tries to send this
	 * buffer's contents out, marks it not full if at least one byte could
	 * be sent, and tries again.
	 *
	 * The snd_buf() function normally takes a "flags" argument which may
	 * be made of a combination of CO_SFL_MSG_MORE to indicate that more
	 * data immediately comes and CO_SFL_STREAMER to indicate that the
	 * connection is streaming lots of data (used to increase TLS record
	 * size at the expense of latency). The former can be sent any time
	 * there's a buffer full flag, as it indicates at least one stream
	 * attempted to send and failed so there are pending data. An
	 * alternative would be to set it as long as there's an active stream
	 * but that would be problematic for ACKs until we have an absolute
	 * guarantee that all waiters have at least one byte to send. The
	 * latter should possibly not be set for now.
	 */

	done = 0;
	while (!(conn->flags & CO_FL_WAIT_XPRT) && !done) {
		unsigned int flags = 0;
		unsigned int released = 0;
		struct buffer *buf;
		uint to_send;

		/* fill as much as we can into the current buffer */
		while (((h2c->flags & (H2_CF_MUX_MFULL|H2_CF_MUX_MALLOC)) == 0) && !done)
			done = h2_process_mux(h2c);

		if (h2c->flags & H2_CF_MUX_MALLOC)
			done = 1; // we won't go further without extra buffers

		if ((conn->flags & (CO_FL_SOCK_WR_SH|CO_FL_ERROR)) ||
		    (h2c->flags & H2_CF_GOAWAY_FAILED))
			break;

		if (h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MROOM))
			flags |= CO_SFL_MSG_MORE;

		to_send = br_count(h2c->mbuf);
		if (to_send > 1) {
			/* usually we want to emit small TLS records to speed
			 * up the decoding on the client. That's what is being
			 * done by default. However if there is more than one
			 * buffer being allocated, we're streaming large data
			 * so we stich to large records.
			 */
			flags |= CO_SFL_STREAMER;
		}

		for (buf = br_head(h2c->mbuf); b_size(buf); buf = br_del_head(h2c->mbuf)) {
			if (b_data(buf)) {
				int ret = conn->xprt->snd_buf(conn, conn->xprt_ctx, buf, b_data(buf),
							      flags | (to_send > 1 ? CO_SFL_MSG_MORE : 0));
				if (!ret) {
					done = 1;
					break;
				}
				sent = 1;
				to_send--;
				TRACE_DATA("sent data", H2_EV_H2C_SEND, h2c->conn, 0, buf, (void*)(long)ret);
				b_del(buf, ret);
				if (b_data(buf)) {
					done = 1;
					break;
				}
			}
			b_free(buf);
			released++;
		}

		if (released)
			offer_buffers(NULL, released);

		/* Normally if wrote at least one byte, the buffer is not full
		 * anymore. However, if it was marked full because all of its
		 * buffers were used, we don't want to instantly wake up many
		 * streams because we'd create a thundering herd effect, notably
		 * when data are flushed in small chunks. Instead we wait for
		 * the buffer to be decongested again before allowing to send
		 * again. It also has the added benefit of not pumping more
		 * data from the other side when it's known that this one is
		 * still congested.
		 */
		if (br_single(h2c->mbuf))
			h2c->flags &= ~(H2_CF_MUX_MFULL | H2_CF_DEM_MROOM);
	}

	if (conn->flags & CO_FL_ERROR) {
		h2c->flags |= H2_CF_ERR_PENDING;
		h2c_report_term_evt(h2c, muxc_tevt_type_snd_err);
		if (h2c->flags & H2_CF_END_REACHED)
			h2c->flags |= H2_CF_ERROR;
		b_reset(br_tail(h2c->mbuf));
	}

	/* We're not full anymore, so we can wake any task that are waiting
	 * for us.
	 */
	if (!(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MROOM)) && h2c->st0 >= H2_CS_FRAME_H) {
		h2c->flags &= ~H2_CF_WAIT_INLIST;
		h2_resume_each_sending_h2s(h2c, &h2c->send_list);
	}

	/* We're done, no more to send */
	if (!(conn->flags & CO_FL_WAIT_XPRT) && !br_data(h2c->mbuf)) {
		TRACE_DEVEL("leaving with everything sent", H2_EV_H2C_SEND, h2c->conn);
		if (h2c->flags & H2_CF_MBUF_HAS_DATA && !h2c->nb_sc) {
			h2c->flags &= ~H2_CF_MBUF_HAS_DATA;
			h2c->idle_start = now_ms;
		}
		goto end;
	}

	if (!(conn->flags & CO_FL_ERROR) && !(h2c->wait_event.events & SUB_RETRY_SEND)) {
		TRACE_STATE("more data to send, subscribing", H2_EV_H2C_SEND, h2c->conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_SEND, &h2c->wait_event);
	}
	TRACE_DEVEL("leaving with some data left to send", H2_EV_H2C_SEND, h2c->conn);
end:
	return sent || (h2c->flags & (H2_CF_ERR_PENDING|H2_CF_ERROR));
}

/* this is the tasklet referenced in h2c->wait_event.tasklet */
struct task *h2_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct connection *conn;
	struct tasklet *tl = (struct tasklet *)t;
	int conn_in_list;
	struct h2c *h2c = ctx;
	int ret = 0;

	if (state & TASK_F_USR1) {
		/* the tasklet was idling on an idle connection, it might have
		 * been stolen, let's be careful!
		 */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		if (t->context == NULL) {
			/* The connection has been taken over by another thread,
			 * we're no longer responsible for it, so just free the
			 * tasklet, and do nothing.
			 */
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			tasklet_free(tl);
			t = NULL;
			goto leave;
		}
		conn = h2c->conn;
		TRACE_ENTER(H2_EV_H2C_WAKE, conn);

		/* Remove the connection from the list, to be sure nobody attempts
		 * to use it while we handle the I/O events
		 */
		conn_in_list = conn->flags & CO_FL_LIST_MASK;
		if (conn_in_list)
			conn_delete_from_tree(conn);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	} else {
		/* we're certain the connection was not in an idle list */
		conn = h2c->conn;
		TRACE_ENTER(H2_EV_H2C_WAKE, conn);
		conn_in_list = 0;
	}

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		ret = h2_send(h2c);
	if (!(h2c->wait_event.events & SUB_RETRY_RECV))
		ret |= h2_recv(h2c);
	if (ret || b_data(&h2c->dbuf))
		ret = h2_process(h2c);

	/* If we were in an idle list, we want to add it back into it,
	 * unless h2_process() returned -1, which mean it has destroyed
	 * the connection (testing !ret is enough, if h2_process() wasn't
	 * called then ret will be 0 anyway. Otherwise we reset the next
	 * tasklet to disable instant wakeups from external callers.
	 */
	if (ret < 0)
		t = NULL;
	else
		h2c->next_tasklet = NULL;

	if (!ret && conn_in_list) {
		struct server *srv = __objt_server(conn->target);

		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		_srv_add_idle(srv, conn, conn_in_list == CO_FL_SAFE_LIST);
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}

leave:
	TRACE_LEAVE(H2_EV_H2C_WAKE);
	return t;
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection (which normally doesn not happen in h2).
 */
static int h2_process(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;
	int extra_reads = MIN(MAX(bl_avail(h2c->shared_rx_bufs), 1) - 1, 12);

	TRACE_ENTER(H2_EV_H2C_WAKE, conn);

	if (!(h2c->flags & H2_CF_DEM_BLOCK_ANY) &&
	    (b_data(&h2c->dbuf) || (h2c->flags & H2_CF_RCVD_SHUT))) {
		int prev_glitches = h2c->glitches;

		do {
			h2_process_demux(h2c);
			if (!extra_reads--)
				break;

			/* hint: if we ended up aligned on a frame, we've very
			 * likely reached the end, no point trying again.
			 */
			if (h2c->st0 == H2_CS_FRAME_H)
				break;

			if (!h2_recv_allowed(h2c))
				break;

			/* OK, it's worth trying to grab a few more frames */
			h2_recv(h2c);
		} while ((b_data(&h2c->dbuf) && h2_may_demux(h2c)) || (h2c->flags & H2_CF_RCVD_SHUT));

		/* now's time to wake the task up */
		h2c_restart_reading(h2c, 0);

		if (h2c->glitches != prev_glitches && !(h2c->flags & H2_CF_IS_BACK))
			session_add_glitch_ctr(h2c->conn->owner, h2c->glitches - prev_glitches);

		if (h2c->st0 >= H2_CS_ERROR || (h2c->flags & H2_CF_ERROR))
			b_reset(&h2c->dbuf);
	}
	h2_send(h2c);

	if (unlikely(h2c->proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) && !(h2c->flags & H2_CF_IS_BACK)) {
		int send_goaway = 1;
		/* If a close-spread-time option is set, we want to avoid
		 * closing all the active HTTP2 connections at once so we add a
		 * random factor that will spread the closing.
		 */
		if (tick_isset(global.close_spread_end)) {
			int remaining_window = tick_remain(now_ms, global.close_spread_end);
			if (remaining_window) {
				/* This should increase the closing rate the
				 * further along the window we are. */
				send_goaway = (remaining_window <= statistical_prng_range(global.close_spread_time));
			}
		}
		else if (global.tune.options & GTUNE_DISABLE_ACTIVE_CLOSE)
			send_goaway = 0; /* let the client close his connection himself */
		/* frontend is stopping, reload likely in progress, let's try
		 * to announce a graceful shutdown if not yet done. We don't
		 * care if it fails, it will be tried again later.
		 */
		if (send_goaway) {
			TRACE_STATE("proxy stopped, sending GOAWAY", H2_EV_H2C_WAKE|H2_EV_TX_FRAME, conn);
			if (!(h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED))) {
				if (h2c->last_sid < 0)
					h2c->last_sid = (1U << 31) - 1;
				h2c_send_goaway_error(h2c, NULL);
			}
		}
	}

	/*
	 * If we received early data, and the handshake is done, wake
	 * any stream that was waiting for it.
	 */
	if (!(h2c->flags & H2_CF_WAIT_FOR_HS) &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_WAIT_XPRT | CO_FL_EARLY_DATA)) == CO_FL_EARLY_DATA) {
		struct eb32_node *node;
		struct h2s *h2s;

		h2c->flags |= H2_CF_WAIT_FOR_HS;
		node = eb32_lookup_ge(&h2c->streams_by_id, 1);

		while (node) {
			h2s = container_of(node, struct h2s, by_id);
			if (se_fl_test(h2s->sd, SE_FL_WAIT_FOR_HS))
				h2s_notify_recv(h2s);
			node = eb32_next(node);
		}
	}

	if ((h2c->flags & H2_CF_ERROR) || h2c_read0_pending(h2c) ||
	    h2c->st0 == H2_CS_ERROR2 || h2c->flags & H2_CF_GOAWAY_FAILED ||
	    (eb_is_empty(&h2c->streams_by_id) && h2c->last_sid >= 0 &&
	     h2c->max_id >= h2c->last_sid)) {
		h2_wake_some_streams(h2c, 0);

		if (eb_is_empty(&h2c->streams_by_id)) {
			/* no more stream, kill the connection now */
			h2_release(h2c);
			TRACE_DEVEL("leaving after releasing the connection", H2_EV_H2C_WAKE);
			return -1;
		}

		/* connections in error must be removed from the idle lists */
		if (conn->flags & CO_FL_LIST_MASK) {
			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			conn_delete_from_tree(conn);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}
	}
	else if (h2c->st0 == H2_CS_ERROR) {
		/* connections in error must be removed from the idle lists */
		if (conn->flags & CO_FL_LIST_MASK) {
			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			conn_delete_from_tree(conn);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}
	}

	if (!b_data(&h2c->dbuf))
		h2_release_buf(h2c, &h2c->dbuf);

	if (h2c->st0 == H2_CS_ERROR2 || (h2c->flags & H2_CF_GOAWAY_FAILED) ||
	    (h2c->st0 != H2_CS_ERROR &&
	     !br_data(h2c->mbuf) &&
	     (h2c->mws <= 0 || LIST_ISEMPTY(&h2c->fctl_list)) &&
	     ((h2c->flags & H2_CF_MUX_BLOCK_ANY) || LIST_ISEMPTY(&h2c->send_list))))
		h2_release_mbuf(h2c);

	h2c_update_timeout(h2c);
	h2_send(h2c);
	TRACE_LEAVE(H2_EV_H2C_WAKE, conn);
	return 0;
}

/* wake-up function called by the connection layer (mux_ops.wake) */
static int h2_wake(struct connection *conn)
{
	struct h2c *h2c = conn->ctx;
	int ret;

	TRACE_ENTER(H2_EV_H2C_WAKE, conn);
	ret = h2_process(h2c);
	if (ret >= 0) {
		h2_wake_some_streams(h2c, 0);

		/* For active reverse connection, an explicit check is required if an
		 * error is pending to propagate the error as demux process is blocked
		 * until reversal. This allows to quickly close the connection and
		 * prepare a new one.
		 */
		if (unlikely(conn_reverse_in_preconnect(conn)) && h2c_is_dead(h2c)) {
			TRACE_DEVEL("leaving and killing dead connection", H2_EV_STRM_END, h2c->conn);
			h2_release(h2c);
		}
	}

	TRACE_LEAVE(H2_EV_H2C_WAKE);
	return ret;
}

/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed. If the
 * MUX buffer still has lying data or is not allocatable, the connection is
 * immediately killed. If it's allocatable and empty, we attempt to send a
 * GOAWAY frame.
 */
struct task *h2_timeout_task(struct task *t, void *context, unsigned int state)
{
	struct h2c *h2c = context;
	int expired = tick_is_expired(t->expire, now_ms);

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c ? h2c->conn : NULL);

	if (h2c) {
		 /* Make sure nobody stole the connection from us */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

		/* Somebody already stole the connection from us, so we should not
		 * free it, we just have to free the task.
		 */
		if (!t->context) {
			h2c = NULL;
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			goto do_leave;
		}


		if (!expired) {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			TRACE_DEVEL("leaving (not expired)", H2_EV_H2C_WAKE, h2c->conn);
			return t;
		}

		if (!h2c_may_expire(h2c)) {
			/* we do still have streams but all of them are idle, waiting
			 * for the data layer, so we must not enforce the timeout here.
			 */
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			t->expire = TICK_ETERNITY;
			return t;
		}

		/* We're about to destroy the connection, so make sure nobody attempts
		 * to steal it from us.
		 */
		if (h2c->conn->flags & CO_FL_LIST_MASK)
			conn_delete_from_tree(h2c->conn);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

		/* Try to gracefully close idle connections by sending a GOAWAY first,
		 * and then waiting for the fin timeout.
		 */
		if (!br_data(h2c->mbuf) && h2c_may_expire(h2c) &&
		    !(h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED))) {
			h2c_error(h2c, H2_ERR_NO_ERROR);
			if (h2_send(h2c))
				tasklet_wakeup(h2c->wait_event.tasklet);
			t->expire = tick_add_ifset(now_ms, h2c->shut_timeout);
			if (!tick_isset(t->expire))
				t->expire = tick_add_ifset(now_ms, h2c->timeout);
			return t;
		}

		h2c_report_term_evt(h2c, muxc_tevt_type_tout);
	}

do_leave:
	task_destroy(t);

	if (!h2c) {
		/* resources were already deleted */
		TRACE_DEVEL("leaving (not more h2c)", H2_EV_H2C_WAKE);
		return NULL;
	}

	h2c->task = NULL;
	h2c_error(h2c, H2_ERR_NO_ERROR);
	h2_wake_some_streams(h2c, 0);

	if (br_data(h2c->mbuf)) {
		/* don't even try to send a GOAWAY, the buffer is stuck */
		h2c->flags |= H2_CF_GOAWAY_FAILED;
	}

	/* try to send but no need to insist */
	h2c->last_sid = h2c->max_id;
	if (h2c_send_goaway_error(h2c, NULL) <= 0)
		h2c->flags |= H2_CF_GOAWAY_FAILED;

	if (br_data(h2c->mbuf) && !(h2c->flags & H2_CF_GOAWAY_FAILED) && conn_xprt_ready(h2c->conn)) {
		unsigned int released = 0;
		struct buffer *buf;

		for (buf = br_head(h2c->mbuf); b_size(buf); buf = br_del_head(h2c->mbuf)) {
			if (b_data(buf)) {
				int ret = h2c->conn->xprt->snd_buf(h2c->conn, h2c->conn->xprt_ctx, buf, b_data(buf), 0);
				if (!ret)
					break;
				b_del(buf, ret);
				if (b_data(buf))
					break;
				b_free(buf);
				released++;
			}
		}

		if (released)
			offer_buffers(NULL, released);
	}

	/* Above we might have prepared a GOAWAY that was sent along with
	 * pending data, make sure to clear the FULL flags.
	 */
	if (br_single(h2c->mbuf))
		h2c->flags &= ~(H2_CF_MUX_MFULL | H2_CF_DEM_MROOM);

	/* in any case this connection must not be considered idle anymore */
	if (h2c->conn->flags & CO_FL_LIST_MASK) {
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		conn_delete_from_tree(h2c->conn);
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}

	/* either we can release everything now or it will be done later once
	 * the last stream closes.
	 */
	if (eb_is_empty(&h2c->streams_by_id))
		h2_release(h2c);

	TRACE_LEAVE(H2_EV_H2C_WAKE);
	return NULL;
}


/*******************************************/
/* functions below are used by the streams */
/*******************************************/

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static int h2_attach(struct connection *conn, struct sedesc *sd, struct session *sess)
{
	struct h2s *h2s;
	struct h2c *h2c = conn->ctx;

	TRACE_ENTER(H2_EV_H2S_NEW, conn);
	h2s = h2c_bck_stream_new(h2c, sd->sc, sess);
	if (!h2s) {
		TRACE_DEVEL("leaving on stream creation failure", H2_EV_H2S_NEW|H2_EV_H2S_ERR, conn);
		return -1;
	}

	/* the connection is not idle anymore, let's mark this */
	HA_ATOMIC_AND(&h2c->wait_event.tasklet->state, ~TASK_F_USR1);
	xprt_set_used(h2c->conn, h2c->conn->xprt, h2c->conn->xprt_ctx);

	TRACE_LEAVE(H2_EV_H2S_NEW, conn, h2s);
	return 0;
}

/* Retrieves the first valid stream connector from this connection, or returns
 * NULL. We have to scan because we may have some orphan streams. It might be
 * beneficial to scan backwards from the end to reduce the likeliness to find
 * orphans.
 */
static struct stconn *h2_get_first_sc(const struct connection *conn)
{
	struct h2c *h2c = conn->ctx;
	struct h2s *h2s;
	struct eb32_node *node;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		if (h2s_sc(h2s))
			return h2s_sc(h2s);
		node = eb32_next(node);
	}
	return NULL;
}

static int h2_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	int ret = 0;
	struct h2c *h2c = conn->ctx;

	switch (mux_ctl) {
	case MUX_CTL_STATUS:
		/* Only consider the mux to be ready if we're done with
		 * the preface and settings, and we had no error.
		 */
		if (h2c->st0 >= H2_CS_FRAME_H && h2c->st0 < H2_CS_ERROR)
			ret |= MUX_STATUS_READY;
		return ret;
	case MUX_CTL_EXIT_STATUS:
		return MUX_ES_UNKNOWN;

	case MUX_CTL_REVERSE_CONN:
		BUG_ON(h2c->flags & H2_CF_IS_BACK);

		TRACE_DEVEL("connection reverse done, restart demux", H2_EV_H2C_WAKE, h2c->conn);
		h2c->flags &= ~H2_CF_DEM_TOOMANY;
		tasklet_wakeup(h2c->wait_event.tasklet);
		return 0;

	case MUX_CTL_GET_GLITCHES:
		return h2c->glitches;

	case MUX_CTL_GET_NBSTRM:
		return h2c->nb_streams;

	case MUX_CTL_GET_MAXSTRM:
		return h2c->streams_limit;

	case MUX_CTL_TEVTS:
		return h2c->term_evts_log;

	default:
		return -1;
	}
}

static int h2_sctl(struct stconn *sc, enum mux_sctl_type mux_sctl, void *output)
{
	int ret = 0;
	struct h2s *h2s = __sc_mux_strm(sc);
	union mux_sctl_dbg_str_ctx *dbg_ctx;
	struct buffer *buf;

	switch (mux_sctl) {
	case MUX_SCTL_SID:
		if (output)
			*((int64_t *)output) = h2s->id;
		return ret;
	case MUX_SCTL_DBG_STR:
		dbg_ctx = output;
		buf = get_trash_chunk();

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_MUXS)
			h2_dump_h2s_info(buf, h2s, NULL);

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_MUXC)
			h2_dump_h2c_info(buf, h2s->h2c, NULL);

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_CONN)
			chunk_appendf(buf, " conn.flg=%#08x conn.err_code=%u conn.evts=%s",
				      h2s->h2c->conn->flags, h2s->h2c->conn->err_code,
				      tevt_evts2str(h2s->h2c->conn->term_evts_log));

		/* other layers not implemented */
		dbg_ctx->ret.buf = *buf;
		return ret;
	case MUX_SCTL_TEVTS:
		return h2s->sd->term_evts_log;

	default:
		return -1;
	}
}

/*
 * Destroy the mux and the associated connection, if it is no longer used
 */
static void h2_destroy(void *ctx)
{
	struct h2c *h2c = ctx;

	TRACE_ENTER(H2_EV_H2C_END, h2c->conn);
	if (eb_is_empty(&h2c->streams_by_id)) {
		BUG_ON(h2c->conn->ctx != h2c);
		h2_release(h2c);
	}
	TRACE_LEAVE(H2_EV_H2C_END);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void h2_detach(struct sedesc *sd)
{
	struct h2s *h2s = sd->se;
	struct h2c *h2c;
	struct session *sess;

	TRACE_ENTER(H2_EV_STRM_END, h2s ? h2s->h2c->conn : NULL, h2s);

	if (!h2s) {
		TRACE_LEAVE(H2_EV_STRM_END);
		return;
	}

	/* there's no txbuf so we're certain not to be able to send anything */
	h2s->flags &= ~H2_SF_NOTIFIED;

	sess = h2s->sess;
	h2c = h2s->h2c;
	h2c->nb_sc--;
	if (!h2c->nb_sc && !br_data(h2c->mbuf))
		h2c->idle_start = now_ms;

	if ((h2c->flags & (H2_CF_IS_BACK|H2_CF_DEM_TOOMANY)) == H2_CF_DEM_TOOMANY &&
	    !h2_frt_has_too_many_sc(h2c)) {
		/* frontend connection was blocking new streams creation */
		h2c->flags &= ~H2_CF_DEM_TOOMANY;
		h2c_restart_reading(h2c, 1);
	}

	/* this stream may be blocked waiting for some data to leave (possibly
	 * an ES or RST frame), so orphan it in this case.
	 */
	if (!(h2c->flags & (H2_CF_ERR_PENDING|H2_CF_ERROR)) &&
	    (h2c->st0 < H2_CS_ERROR) &&
	    (h2s->flags & (H2_SF_BLK_MBUSY | H2_SF_BLK_MROOM | H2_SF_BLK_MFCTL)) &&
	    ((h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW)) || h2s->subs)) {
		TRACE_DEVEL("leaving on stream blocked", H2_EV_STRM_END|H2_EV_H2S_BLK, h2c->conn, h2s);
		/* refresh the timeout if none was active, so that the last
		 * leaving stream may arm it.
		 */
		if (h2c->task && !tick_isset(h2c->task->expire))
			h2c_update_timeout(h2c);
		return;
	}

	if ((h2c->flags & H2_CF_DEM_BLOCK_ANY && h2s->id == h2c->dsi)) {
		/* unblock the connection if it was blocked on this
		 * stream.
		 */
		h2c->flags &= ~H2_CF_DEM_BLOCK_ANY;
		h2c->flags &= ~H2_CF_MUX_BLOCK_ANY;
		h2c_restart_reading(h2c, 1);
	}

	h2s_destroy(h2s);

	if (h2c->flags & H2_CF_IS_BACK) {
		if (!(h2c->flags & (H2_CF_RCVD_SHUT|H2_CF_ERR_PENDING|H2_CF_ERROR))) {
			if (h2c->conn->flags & CO_FL_PRIVATE) {
				/* Add the connection in the session server list, if not already done */
				if (!session_add_conn(sess, h2c->conn, h2c->conn->target)) {
					h2c->conn->owner = NULL;
					if (eb_is_empty(&h2c->streams_by_id)) {
						h2c->conn->mux->destroy(h2c);
						TRACE_DEVEL("leaving on error after killing outgoing connection", H2_EV_STRM_END|H2_EV_H2C_ERR);
						return;
					}
				}
				if (eb_is_empty(&h2c->streams_by_id)) {
					/* mark that the tasklet may lose its context to another thread and
					 * that the handler needs to check it under the idle conns lock.
					 */
					HA_ATOMIC_OR(&h2c->wait_event.tasklet->state, TASK_F_USR1);
					if (session_check_idle_conn(h2c->conn->owner, h2c->conn) != 0) {
						/* At this point either the connection is destroyed, or it's been added to the server idle list, just stop */
						TRACE_DEVEL("leaving without reusable idle connection", H2_EV_STRM_END);
						return;
					}
				}
			}
			else {
				if (eb_is_empty(&h2c->streams_by_id)) {
					/* If the connection is owned by the session, first remove it
					 * from its list
					 */
					if (h2c->conn->owner) {
						session_unown_conn(h2c->conn->owner, h2c->conn);
						h2c->conn->owner = NULL;
					}

					/* mark that the tasklet may lose its context to another thread and
					 * that the handler needs to check it under the idle conns lock.
					 */
					HA_ATOMIC_OR(&h2c->wait_event.tasklet->state, TASK_F_USR1);
					xprt_set_idle(h2c->conn, h2c->conn->xprt, h2c->conn->xprt_ctx);

					if (!srv_add_to_idle_list(objt_server(h2c->conn->target), h2c->conn, 1)) {
						/* The server doesn't want it, let's kill the connection right away */
						h2c->conn->mux->destroy(h2c);
						TRACE_DEVEL("leaving on error after killing outgoing connection", H2_EV_STRM_END|H2_EV_H2C_ERR);
						return;
					}
					/* At this point, the connection has been added to the
					 * server idle list, so another thread may already have
					 * hijacked it, so we can't do anything with it.
					 */
					TRACE_DEVEL("reusable idle connection", H2_EV_STRM_END);
					return;

				}
				else if (!h2c->conn->hash_node->node.node.leaf_p &&
					 h2_avail_streams(h2c->conn) > 0 && objt_server(h2c->conn->target) &&
					 !LIST_INLIST(&h2c->conn->sess_el)) {
					srv_add_to_avail_list(__objt_server(h2c->conn->target), h2c->conn);
				}
			}
		}
	}

	/* We don't want to close right now unless we're removing the
	 * last stream, and either the connection is in error, or it
	 * reached the ID already specified in a GOAWAY frame received
	 * or sent (as seen by last_sid >= 0).
	 */
	if (h2c_is_dead(h2c)) {
		/* no more stream will come, kill it now */
		TRACE_DEVEL("leaving and killing dead connection", H2_EV_STRM_END, h2c->conn);
		h2_release(h2c);
	}
	else if (h2c->task) {
		h2c_update_timeout(h2c);
		TRACE_DEVEL("leaving, refreshing connection's timeout", H2_EV_STRM_END, h2c->conn);
	}
	else
		TRACE_DEVEL("leaving", H2_EV_STRM_END, h2c->conn);
}

/* Performs a synchronous or asynchronous shutr(). */
static void h2_do_shutr(struct h2s *h2s, struct se_abort_info *reason)
{
	struct h2c *h2c = h2s->h2c;

	if (h2s->st == H2_SS_CLOSED)
		goto done;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2c->conn, h2s);

	if (h2s->flags & H2_SF_WANT_SHUTW)
		goto add_to_list;

	/* a connstream may require us to immediately kill the whole connection
	 * for example because of a "tcp-request content reject" rule that is
	 * normally used to limit abuse. In this case we schedule a goaway to
	 * close the connection.
	 */
	if (se_fl_test(h2s->sd, SE_FL_KILL_CONN) &&
	    !(h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED))) {
		TRACE_STATE("stream wants to kill the connection", H2_EV_STRM_SHUT, h2c->conn, h2s);
		h2c_error(h2c, H2_ERR_ENHANCE_YOUR_CALM);
		h2s_error(h2s, H2_ERR_ENHANCE_YOUR_CALM);
	}
	else if (h2s_is_forwardable_abort(h2s, reason)) {
		TRACE_STATE("shutr using opposite endp code", H2_EV_STRM_SHUT, h2c->conn, h2s);
		h2s_error(h2s, reason->code);
	}
	else if (!(h2s->flags & H2_SF_HEADERS_SENT)) {
		/* Nothing was never sent for this stream, so reset with
		 * REFUSED_STREAM error to let the client retry the
		 * request.
		 */
		TRACE_STATE("no headers sent yet, trying a retryable abort", H2_EV_STRM_SHUT, h2c->conn, h2s);
		h2s_error(h2s, H2_ERR_REFUSED_STREAM);
	}
	else {
		/* a final response was already provided, we don't want this
		 * stream anymore. This may happen when the server responds
		 * before the end of an upload and closes quickly (redirect,
		 * deny, ...)
		 */
		h2s_error(h2s, H2_ERR_CANCEL);
	}

	if (!(h2s->flags & H2_SF_RST_SENT) &&
	    h2s_send_rst_stream(h2c, h2s) <= 0)
		goto add_to_list;

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(h2c->wait_event.tasklet);
	h2s_close(h2s);
 done:
	h2s->flags &= ~H2_SF_WANT_SHUTR;
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);
	return;
add_to_list:
	/* Let the handler know we want to shutr, and add ourselves to the
	 * most relevant list if not yet done. h2_deferred_shut() will be
	 * automatically called via the shut_tl tasklet when there's room
	 * again.
	 */
	h2s->flags |= H2_SF_WANT_SHUTR;
	if (!LIST_INLIST(&h2s->list)) {
		if (h2s->flags & H2_SF_BLK_MFCTL)
			LIST_APPEND(&h2c->fctl_list, &h2s->list);
		else if (h2s->flags & (H2_SF_BLK_MBUSY|H2_SF_BLK_MROOM))
			LIST_APPEND(&h2c->send_list, &h2s->list);
	}
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);
	return;
}


/* Performs a synchronous or asynchronous shutw(). */
static void h2_do_shutw(struct h2s *h2s, struct se_abort_info *reason)
{
	struct h2c *h2c = h2s->h2c;

	if (h2s->st == H2_SS_HLOC || h2s->st == H2_SS_CLOSED)
		goto done;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2c->conn, h2s);

	if (h2s->st != H2_SS_ERROR &&
	    !h2s_is_forwardable_abort(h2s, reason) &&
	    (h2s->flags & (H2_SF_HEADERS_SENT | H2_SF_MORE_HTX_DATA)) == H2_SF_HEADERS_SENT) {
		/* we can cleanly close using an empty data frame only after headers
		 * and if no more data is expected to be sent.
		 */
		if (!(h2s->flags & (H2_SF_ES_SENT|H2_SF_RST_SENT)) &&
		    h2_send_empty_data_es(h2s) <= 0)
			goto add_to_list;

		if (h2s->st == H2_SS_HREM)
			h2s_close(h2s);
		else
			h2s->st = H2_SS_HLOC;
	} else {
		/* a connstream may require us to immediately kill the whole connection
		 * for example because of a "tcp-request content reject" rule that is
		 * normally used to limit abuse. In this case we schedule a goaway to
		 * close the connection.
		 */
		if (se_fl_test(h2s->sd, SE_FL_KILL_CONN) &&
		    !(h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED))) {
			TRACE_STATE("stream wants to kill the connection", H2_EV_STRM_SHUT, h2c->conn, h2s);
			h2c_error(h2c, H2_ERR_ENHANCE_YOUR_CALM);
			h2s_error(h2s, H2_ERR_ENHANCE_YOUR_CALM);
		}
		else if (h2s_is_forwardable_abort(h2s, reason)) {
			TRACE_STATE("shutw using opposite endp code", H2_EV_STRM_SHUT, h2c->conn, h2s);
			h2s_error(h2s, reason->code);
		}
		else if (h2s->flags & H2_SF_MORE_HTX_DATA) {
			/* some unsent data were pending (e.g. abort during an upload),
			 * let's send a CANCEL.
			 */
			TRACE_STATE("shutw before end of data, sending CANCEL", H2_EV_STRM_SHUT, h2c->conn, h2s);
			h2s_error(h2s, H2_ERR_CANCEL);
		}
		else {
			/* Nothing was never sent for this stream, so reset with
			 * REFUSED_STREAM error to let the client retry the
			 * request.
			 */
			TRACE_STATE("no headers sent yet, trying a retryable abort", H2_EV_STRM_SHUT, h2c->conn, h2s);
			h2s_error(h2s, H2_ERR_REFUSED_STREAM);
		}

		if (!(h2s->flags & H2_SF_RST_SENT) &&
		    h2s_send_rst_stream(h2c, h2s) <= 0)
			goto add_to_list;

		h2s_close(h2s);
	}

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(h2c->wait_event.tasklet);

	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);

 done:
	h2s->flags &= ~H2_SF_WANT_SHUTW;
	return;

 add_to_list:
	/* Let the handler know we want to shutw, and add ourselves to the
	 * most relevant list if not yet done. h2_deferred_shut() will be
	 * automatically called via the shut_tl tasklet when there's room
	 * again.
	 */
	h2s->flags |= H2_SF_WANT_SHUTW;
	if (!LIST_INLIST(&h2s->list)) {
		if (h2s->flags & H2_SF_BLK_MFCTL)
			LIST_APPEND(&h2c->fctl_list, &h2s->list);
		else if (h2s->flags & (H2_SF_BLK_MBUSY|H2_SF_BLK_MROOM))
			LIST_APPEND(&h2c->send_list, &h2s->list);
	}
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);
	return;
}

/* This is the tasklet referenced in h2s->shut_tl, it is used for
 * deferred shutdowns when the h2_detach() was done but the mux buffer was full
 * and prevented the last frame from being emitted.
 */
struct task *h2_deferred_shut(struct task *t, void *ctx, unsigned int state)
{
	struct h2s *h2s = ctx;
	struct h2c *h2c = h2s->h2c;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2c->conn, h2s);

	if (h2s->flags & H2_SF_NOTIFIED) {
		/* some data processing remains to be done first */
		goto end;
	}

	if (h2s->flags & H2_SF_WANT_SHUTW)
		h2_do_shutw(h2s, NULL);

	if (h2s->flags & H2_SF_WANT_SHUTR)
		h2_do_shutr(h2s, NULL);

	if (!(h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))) {
		/* We're done trying to send, remove ourself from the send_list */
		h2_remove_from_list(h2s);

		if (!h2s_sc(h2s)) {
			h2s_destroy(h2s);
			if (h2c_is_dead(h2c)) {
				h2_release(h2c);
				t = NULL;
			}
		}
	}
 end:
	TRACE_LEAVE(H2_EV_STRM_SHUT);
	return t;
}

static void h2_shut(struct stconn *sc, unsigned int mode, struct se_abort_info *reason)
{
	struct h2s *h2s = __sc_mux_strm(sc);

	TRACE_ENTER(H2_EV_STRM_SHUT, h2s->h2c->conn, h2s);
	if (mode & (SE_SHW_SILENT|SE_SHW_NORMAL)) {
		/* Pass the reason for silent shutw only (abort) */
		h2_do_shutw(h2s, (mode & SE_SHW_SILENT) ? reason : NULL);
	}
	if (mode & SE_SHR_RESET)
		h2_do_shutr(h2s, reason);
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2s->h2c->conn, h2s);
}

/* Decode the payload of a HEADERS frame and produce the HTX request or response
 * depending on the connection's side. Returns a positive value on success, a
 * negative value on failure, or 0 if it couldn't proceed. May report connection
 * errors in h2c->errcode if the frame is non-decodable and the connection
 * unrecoverable. In absence of connection error when a failure is reported, the
 * caller must assume a stream error.
 *
 * The function may fold CONTINUATION frames into the initial HEADERS frame
 * by removing padding and next frame header, then moving the CONTINUATION
 * frame's payload and adjusting h2c->dfl to match the new aggregated frame,
 * leaving a hole between the main frame and the beginning of the next one.
 * The possibly remaining incomplete or next frame at the end may be moved
 * if the aggregated frame is not deleted, in order to fill the hole. Wrapped
 * HEADERS frames are unwrapped into a temporary buffer before decoding.
 *
 * A buffer at the beginning of processing may look like this :
 *
 *  ,---.---------.-----.--------------.--------------.------.---.
 *  |///| HEADERS | PAD | CONTINUATION | CONTINUATION | DATA |///|
 *  `---^---------^-----^--------------^--------------^------^---'
 *  |   |         <----->                                    |   |
 * area |           dpl                                      |  wrap
 *      |<-------------->                                    |
 *      |       dfl                                          |
 *      |<-------------------------------------------------->|
 *    head                    data
 *
 * Padding is automatically overwritten when folding, participating to the
 * hole size after dfl :
 *
 *  ,---.------------------------.-----.--------------.------.---.
 *  |///| HEADERS : CONTINUATION |/////| CONTINUATION | DATA |///|
 *  `---^------------------------^-----^--------------^------^---'
 *  |   |                        <----->                     |   |
 * area |                          hole                      |  wrap
 *      |<----------------------->                           |
 *      |           dfl                                      |
 *      |<-------------------------------------------------->|
 *    head                    data
 *
 * Please note that the HEADERS frame is always deprived from its PADLEN byte
 * however it may start with the 5 stream-dep+weight bytes in case of PRIORITY
 * bit.
 *
 * The <flags> field must point to either the stream's flags or to a copy of it
 * so that the function can update the following flags :
 *   - H2_SF_DATA_CLEN when content-length is seen
 *   - H2_SF_HEADERS_RCVD once the frame is successfully decoded
 *
 * The H2_SF_HEADERS_RCVD flag is also looked at in the <flags> field prior to
 * decoding, in order to detect if we're dealing with a headers or a trailers
 * block (the trailers block appears after H2_SF_HEADERS_RCVD was seen). The
 * function takes care of counting glitches.
 */
static int h2c_dec_hdrs(struct h2c *h2c, struct buffer *rxbuf, uint32_t *flags, unsigned long long *body_len, char *upgrade_protocol)
{
	const uint8_t *hdrs = (uint8_t *)b_head(&h2c->dbuf);
	struct buffer *tmp = get_trash_chunk();
	struct http_hdr list[global.tune.max_http_hdr * 2];
	struct buffer *copy = NULL;
	unsigned int msgf;
	struct htx *htx = NULL;
	int flen = 0; // header frame len
	int fragments = 0;
	int hole = 0;
	int ret = 0;
	int outlen;
	int wrap;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);

next_frame:
	if (b_data(&h2c->dbuf) - hole < h2c->dfl)
		goto leave; // incomplete input frame

	/* No END_HEADERS means there's one or more CONTINUATION frames. In
	 * this case, we'll try to paste it immediately after the initial
	 * HEADERS frame payload and kill any possible padding. The initial
	 * frame's length will be increased to represent the concatenation
	 * of the two frames. The next frame is read from position <tlen>
	 * and written at position <flen> (minus padding if some is present).
	 */
	if (unlikely(!(h2c->dff & H2_F_HEADERS_END_HEADERS))) {
		struct h2_fh hdr;
		int clen; // CONTINUATION frame's payload length

		TRACE_STATE("EH missing, expecting continuation frame", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR, h2c->conn);
		if (!h2_peek_frame_hdr(&h2c->dbuf, h2c->dfl + hole, &hdr)) {
			/* no more data, the buffer may be full, either due to
			 * too large a frame or because of too large a hole that
			 * we're going to compact at the end.
			 */
			goto leave;
		}

		if (hdr.ft != H2_FT_CONTINUATION) {
			/* RFC7540#6.10: frame of unexpected type */
			h2c_report_glitch(h2c, 1, "not a CONTINUATION frame");
			TRACE_STATE("not a CONTINUATION frame", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR|H2_EV_RX_CONT|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto fail;
		}

		if (hdr.sid != h2c->dsi) {
			/* RFC7540#6.10: frame of different stream */
			h2c_report_glitch(h2c, 1, "CONTINUATION on different stream ID");
			TRACE_STATE("CONTINUATION on different stream ID", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR|H2_EV_RX_CONT|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto fail;
		}

		if ((unsigned)hdr.len > (unsigned)global.tune.bufsize) {
			/* RFC7540#4.2: invalid frame length */
			h2c_report_glitch(h2c, 1, "too large CONTINUATION frame");
			TRACE_STATE("too large CONTIUATION frame", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR|H2_EV_RX_CONT|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
			goto fail;
		}

		/* detect when we must stop aggregating frames */
		h2c->dff |= hdr.ff & H2_F_HEADERS_END_HEADERS;

		/* Take as much as we can of the CONTINUATION frame's payload */
		clen = b_data(&h2c->dbuf) - (h2c->dfl + hole + 9);
		if (clen > hdr.len)
			clen = hdr.len;

		/* Move the frame's payload over the padding, hole and frame
		 * header. At least one of hole or dpl is null (see diagrams
		 * above). The hole moves after the new aggregated frame.
		 */
		b_move(&h2c->dbuf, b_peek_ofs(&h2c->dbuf, h2c->dfl + hole + 9), clen, -(h2c->dpl + hole + 9));
		h2c->dfl += hdr.len - h2c->dpl;
		hole     += h2c->dpl + 9;
		h2c->dpl  = 0;
		TRACE_STATE("waiting for next continuation frame", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_CONT|H2_EV_RX_HDR, h2c->conn);
		fragments++;
		goto next_frame;
	}

	flen = h2c->dfl - h2c->dpl;

	/* if the input buffer wraps, take a temporary copy of it (rare) */
	wrap = b_wrap(&h2c->dbuf) - b_head(&h2c->dbuf);
	if (wrap < h2c->dfl) {
		copy = alloc_trash_chunk();
		if (!copy) {
			TRACE_DEVEL("failed to allocate temporary buffer", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			goto fail;
		}
		memcpy(copy->area, b_head(&h2c->dbuf), wrap);
		memcpy(copy->area + wrap, b_orig(&h2c->dbuf), h2c->dfl - wrap);
		hdrs = (uint8_t *) copy->area;
	}

	/* Skip StreamDep and weight for now (we don't support PRIORITY) */
	if (h2c->dff & H2_F_HEADERS_PRIORITY) {
		if (read_n32(hdrs) == h2c->dsi) {
			/* RFC7540#5.3.1 : stream dep may not depend on itself */
			h2c_report_glitch(h2c, 1, "PRIORITY frame referencing itself");
			TRACE_STATE("PRIORITY frame referencing itself", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto fail;
		}

		if (flen < 5) {
			h2c_report_glitch(h2c, 1, "too short PRIORITY frame");
			TRACE_STATE("too short PRIORITY frame", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
			goto fail;
		}

		hdrs += 5; // stream dep = 4, weight = 1
		flen -= 5;
	}

	if (!h2_get_buf(h2c, rxbuf)) {
		TRACE_STATE("waiting for h2c rxbuf allocation", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_BLK, h2c->conn);
		h2c->flags |= H2_CF_DEM_SALLOC;
		goto leave;
	}

	/* we can't retry a failed decompression operation so we must be very
	 * careful not to take any risks. In practice the output buffer is
	 * always empty except maybe for trailers, in which case we simply have
	 * to wait for the upper layer to finish consuming what is available.
	 */
	htx = htx_from_buf(rxbuf);
	if (!htx_is_empty(htx)) {
		TRACE_STATE("waiting for room in h2c rxbuf", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_BLK, h2c->conn);
		h2c->flags |= H2_CF_DEM_SFULL;
		goto leave;
	}

	/* past this point we cannot roll back in case of error */
	outlen = hpack_decode_frame(h2c->ddht, hdrs, flen, list,
	                            sizeof(list)/sizeof(list[0]), tmp);

	if (outlen > 0 &&
	    (TRACE_SOURCE)->verbosity >= H2_VERB_ADVANCED &&
	    TRACE_ENABLED(TRACE_LEVEL_USER, H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, 0, 0, 0)) {
		struct ist n;
		int i;

		for (i = 0; list[i].n.len; i++) {
			n = list[i].n;

			if (!isttest(n)) {
				/* this is in fact a pseudo header whose number is in n.len */
				n = h2_phdr_to_ist(n.len);
			}

			h2_trace_header(n, list[i].v, H2_EV_RX_FRAME|H2_EV_RX_HDR,
			                ist(TRC_LOC), __FUNCTION__, h2c, NULL);
		}
	}

	if (outlen < 0) {
		h2c_report_glitch(h2c, 1, "failed to decompress HPACK");
		TRACE_STATE("failed to decompress HPACK", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
		h2c_error(h2c, H2_ERR_COMPRESSION_ERROR);
		goto fail;
	}

	/* The PACK decompressor was updated, let's update the input buffer and
	 * the parser's state to commit these changes and allow us to later
	 * fail solely on the stream if needed.
	 */
	b_del(&h2c->dbuf, h2c->dfl + hole);
	h2c->dfl = hole = 0;
	h2c->st0 = H2_CS_FRAME_H;

	/* OK now we have our header list in <list> */
	msgf = (h2c->dff & H2_F_HEADERS_END_STREAM) ? 0 : H2_MSGF_BODY;
	msgf |= (*flags & H2_SF_BODY_TUNNEL) ? H2_MSGF_BODY_TUNNEL: 0;
	/* If an Extended CONNECT has been sent on this stream, set message flag
	 * to convert 200 response to 101 htx response */
	msgf |= (*flags & H2_SF_EXT_CONNECT_SENT) ? H2_MSGF_EXT_CONNECT: 0;

	if (*flags & H2_SF_HEADERS_RCVD)
		goto trailers;

	/* This is the first HEADERS frame so it's a headers block */
	if (h2c->flags & H2_CF_IS_BACK)
		outlen = h2_make_htx_response(list, htx, &msgf, body_len, upgrade_protocol);
	else
		outlen = h2_make_htx_request(list, htx, &msgf, body_len,
					     !!(((const struct session *)h2c->conn->owner)->fe->options2 & PR_O2_REQBUG_OK));

	if (outlen < 0 || htx_free_space(htx) < global.tune.maxrewrite) {
		/* too large headers? this is a stream error only */
		h2c_report_glitch(h2c, 1, "decompressed headers too large or invalid");
		TRACE_STATE("decompressed headers too large or invalid", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2S_ERR|H2_EV_PROTO_ERR, h2c->conn);
		htx->flags |= HTX_FL_PARSING_ERROR;
		goto fail;
	}

	if (msgf & H2_MSGF_BODY) {
		/* a payload is present */
		if (msgf & H2_MSGF_BODY_CL) {
			*flags |= H2_SF_DATA_CLEN;
			htx->extra = *body_len;
		}
	}
	if (msgf & H2_MSGF_BODYLESS_RSP)
		*flags |= H2_SF_BODYLESS_RESP;

	if (msgf & H2_MSGF_BODY_TUNNEL)
		*flags |= H2_SF_BODY_TUNNEL;
	else {
		/* Abort the tunnel attempt, if any */
		if (*flags & H2_SF_BODY_TUNNEL)
			*flags |= H2_SF_TUNNEL_ABRT;
		*flags &= ~H2_SF_BODY_TUNNEL;
	}

 done:
	/* indicate that a HEADERS frame was received for this stream, except
	 * for 1xx responses. For 1xx responses, another HEADERS frame is
	 * expected.
	 */
	if (!(msgf & H2_MSGF_RSP_1XX))
		*flags |= H2_SF_HEADERS_RCVD;

	if (h2c->dff & H2_F_HEADERS_END_STREAM) {
		if (msgf & H2_MSGF_RSP_1XX) {
			/* RFC9113#8.1 : HEADERS frame with the ES flag set that carries an informational status code is malformed */
			h2c_report_glitch(h2c, 1, "invalid interim response with ES flag");
			TRACE_STATE("invalid interim response with ES flag", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			goto fail;
		}
		/* no more data are expected for this message */
		htx->flags |= HTX_FL_EOM;
		*flags |= H2_SF_ES_RCVD;
	}

	if (msgf & H2_MSGF_EXT_CONNECT)
		*flags |= H2_SF_EXT_CONNECT_RCVD;

	/* success */
	ret = 1;

 leave:
	/* If there is a hole left and it's not at the end, we are forced to
	 * move the remaining data over it.
	 */
	if (hole) {
		if (b_data(&h2c->dbuf) > h2c->dfl + hole)
			b_move(&h2c->dbuf, b_peek_ofs(&h2c->dbuf, h2c->dfl + hole),
			       b_data(&h2c->dbuf) - (h2c->dfl + hole), -hole);
		b_sub(&h2c->dbuf, hole);
	}

	if (b_full(&h2c->dbuf) && h2c->dfl && (!htx || htx_is_empty(htx))) {
		/* too large frames */
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
		ret = -1;
	}

	if (htx)
		htx_to_buf(htx, rxbuf);
	free_trash_chunk(copy);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);

	/* Check for abuse of CONTINUATION: more than 4 fragments and less than
	 * 1kB per fragment is clearly unusual and suspicious enough to count
	 * one glitch per 1kB fragment in a 16kB buffer, which means that an
	 * abuser sending 1600 1-byte frames in a 16kB buffer would increment
	 * its counter by 100.
	 */
	if (unlikely(fragments > 4) && fragments > flen / 1024 && ret != 0) {
		if (h2c_report_glitch(h2c, (fragments + 15) / 16, "too many CONTINUATION frames")) {
			TRACE_STATE("glitch limit reached on CONTINUATION frame", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			ret = -1;
		}
	}

	return ret;

 fail:
	ret = -1;
	goto leave;

 trailers:
	/* This is the last HEADERS frame hence a trailer */
	if (!(h2c->dff & H2_F_HEADERS_END_STREAM)) {
		/* It's a trailer but it's missing ES flag */
		h2c_report_glitch(h2c, 1, "missing EH on trailers frame");
		TRACE_STATE("missing EH on trailers frame", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		goto fail;
	}

	/* Trailers terminate a DATA sequence */
	if (h2_make_htx_trailers(list, htx) <= 0) {
		TRACE_STATE("failed to append HTX trailers into rxbuf", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2S_ERR, h2c->conn);
		htx->flags |= HTX_FL_PARSING_ERROR;
		goto fail;
	}
	*flags |= H2_SF_ES_RCVD;
	goto done;
}

/* Transfer the payload of an H2 DATA frame to the HTX side. The HTTP/2 frame
 * parser state is automatically updated. Returns > 0 if it could completely
 * send the current frame, 0 if it couldn't complete, in which case
 * SE_FL_RCV_MORE must be checked to know if some data remain pending (an empty
 * DATA frame can return 0 as a valid result). Stream errors are reported in
 * h2s->errcode and connection errors in h2c->errcode. The caller must already
 * have checked the frame header and ensured that the frame was complete or the
 * buffer full. It changes the frame state to FRAME_A once done.
 */
static int h2_frt_transfer_data(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;
	int block;
	unsigned int flen = 0;
	struct htx *htx = NULL;
	struct buffer *scbuf = NULL;
	unsigned int sent;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);

	h2c->flags &= ~(H2_CF_DEM_SFULL | H2_CF_DEM_RXBUF);

	/* Note: the size estimate is approximative due to HTX fragmentation,
	 * so here we are optimistic and try to get the work done without
	 * allocating an rxbuf if possible. If we fail we'll more aggressively
	 * retry.
	 */
	if ((!h2s_rxbuf_tail(h2s) || !h2s_may_append_to_rxbuf(h2s)) && !h2s_get_rxbuf(h2s)) {
		h2c->flags |= H2_CF_DEM_RXBUF;
		TRACE_STATE("waiting for an h2s rxbuf slot", H2_EV_RX_FRAME|H2_EV_RX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto fail;
	}

 next_buffer:
	/* now we have a non-full rxbuf */
	scbuf = h2_get_buf(h2c, h2s_rxbuf_tail(h2s));
	if (!scbuf) {
		h2c->flags |= H2_CF_DEM_SALLOC;
		TRACE_STATE("waiting for an h2s rxbuf", H2_EV_RX_FRAME|H2_EV_RX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto fail;
	}
	htx = htx_from_buf(scbuf);

try_again:
	flen = h2c->dfl - h2c->dpl;
	if (!flen)
		goto end_transfer;

	if (flen > b_data(&h2c->dbuf)) {
		flen = b_data(&h2c->dbuf);
		if (!flen)
			goto fail;
	}

	block = htx_free_data_space(htx);
	if (!block) {
		if (h2s_get_rxbuf(h2s))
			goto next_buffer;

		h2c->flags |= H2_CF_DEM_SFULL;
		TRACE_STATE("h2s rxbuf is full", H2_EV_RX_FRAME|H2_EV_RX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto fail;
	}
	if (flen > block)
		flen = block;

	/* here, flen is the max we can copy into the output buffer */
	block = b_contig_data(&h2c->dbuf, 0);
	if (flen > block)
		flen = block;

	sent = htx_add_data(htx, ist2(b_head(&h2c->dbuf), flen));
	TRACE_DATA("move some data to h2s rxbuf", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s, 0, (void *)(long)sent);

	b_del(&h2c->dbuf, sent);
	h2c->dfl    -= sent;
	h2c->rcvd_c += sent;
	h2c->rcvd_s += sent;  // warning, this can also affect the closed streams!

	if (h2s->flags & H2_SF_DATA_CLEN) {
		h2s->body_len -= sent;
		htx->extra = h2s->body_len;
	}

	if (sent < flen) {
		if (h2s_get_rxbuf(h2s))
			goto next_buffer;

		h2c->flags |= H2_CF_DEM_SFULL;
		TRACE_STATE("h2s rxbuf is full", H2_EV_RX_FRAME|H2_EV_RX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto fail;
	}

	goto try_again;

 end_transfer:
	/* here we're done with the frame, all the payload (except padding) was
	 * transferred.
	 */

	if (!(h2s->flags & H2_SF_BODY_TUNNEL) && (h2c->dff & H2_F_DATA_END_STREAM)) {
		/* no more data are expected for this message. This add the EOM
		 * flag but only on the response path or if no tunnel attempt
		 * was aborted. Otherwise (request path + tunnel abrted), the
		 * EOM was already reported.
		 */
		if ((h2c->flags & H2_CF_IS_BACK) || !(h2s->flags & H2_SF_TUNNEL_ABRT)) {
			/* htx may be empty if receiving an empty DATA frame. */
			if (!htx_set_eom(htx))
				goto fail;
		}
	}

	h2c->rcvd_c += h2c->dpl;
	h2c->rcvd_s += h2c->dpl;
	h2c->dpl = 0;
	h2c->st0 = H2_CS_FRAME_A; // send the corresponding window update
	htx_to_buf(htx, scbuf);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 1;
 fail:
	if (htx)
		htx_to_buf(htx, scbuf);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 0;
}

/* Try to send a HEADERS frame matching HTX response present in HTX message
 * <htx> for the H2 stream <h2s>. Returns the number of bytes sent. The caller
 * must check the stream's status to detect any error which might have happened
 * subsequently to a successful send. The htx blocks are automatically removed
 * from the message. The htx message is assumed to be valid since produced from
 * the internal code, hence it contains a start line, an optional series of
 * header blocks and an end of header, otherwise an invalid frame could be
 * emitted and the resulting htx message could be left in an inconsistent state.
 */
static size_t h2s_snd_fhdrs(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[global.tune.max_http_hdr * 2];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct buffer outbuf;
	struct buffer *mbuf;
	struct htx_sl *sl;
	enum htx_blk_type type;
	int es_now = 0;
	int ret = 0;
	int hdr;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);

	/* get the start line (we do have one) and the rest of the headers,
	 * that we dump starting at header 0 */
	sl = NULL;
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOH)
			break;

		if (type == HTX_BLK_HDR) {
			BUG_ON(!sl); /* The start-line mut be defined before any headers */
			if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}

			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else if (type == HTX_BLK_RES_SL) {
			BUG_ON(sl); /* Only one start-line expected */
			sl = htx_get_blk_ptr(htx, blk);
			h2s->status = sl->info.res.status;
			if ((sl->flags & HTX_SL_F_BODYLESS_RESP) || h2s->status == 204 || h2s->status == 304)
				h2s->flags |= H2_SF_BODYLESS_RESP;
			if (h2s->status < 100 || h2s->status > 999) {
				TRACE_ERROR("will not encode an invalid status code", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}
			else if (h2s->status == 101) {
				if (unlikely(h2s->flags & H2_SF_EXT_CONNECT_RCVD)) {
					/* If an Extended CONNECT has been received, we need to convert 101 to 200 */
					h2s->status = 200;
					h2s->flags &= ~H2_SF_EXT_CONNECT_RCVD;
				}
				else {
					/* Otherwise, 101 responses are not supported in H2, so return a error (RFC7540#8.1.1) */
					TRACE_ERROR("will not encode an invalid status code", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
					goto fail;
				}
			}
			else if ((h2s->flags & H2_SF_BODY_TUNNEL) && h2s->status >= 300) {
				/* Abort the tunnel attempt */
				h2s->flags &= ~H2_SF_BODY_TUNNEL;
				h2s->flags |= H2_SF_TUNNEL_ABRT;
			}
		}
		else {
			TRACE_ERROR("will not encode unexpected htx block", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
			goto fail;
		}
	}

	/* The start-line me be defined */
	BUG_ON(!sl);

	/* marker for end of headers */
	list[hdr].n = ist("");

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
		return 0;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x04", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	if ((h2c->flags & (H2_CF_SHTS_UPDATED|H2_CF_DTSU_EMITTED)) == H2_CF_SHTS_UPDATED) {
		/* SETTINGS_HEADER_TABLE_SIZE changed, we must send an HPACK
		 * dynamic table size update so that some clients are not
		 * confused. In practice we only need to send the DTSU when the
		 * advertised size is lower than the current one, and since we
		 * don't use it and don't care about the default 4096 bytes,
		 * we only ack it with a zero size thus we at most have to deal
		 * with this once. See RFC7541#4.2 and #6.3 for the spec, and
		 * below for the whole context and interoperability risks:
		 * https://lists.w3.org/Archives/Public/ietf-http-wg/2021OctDec/0235.html
		 */
		if (b_room(&outbuf) < 1)
			goto full;
		outbuf.area[outbuf.data++] = 0x20; // HPACK DTSU 0 bytes

		/* let's not update the flags now but only once the buffer is
		 * really committed.
		 */
	}

	/* encode status, which necessarily is the first one */
	if (!hpack_encode_int_status(&outbuf, h2s->status)) {
		if (b_space_wraps(mbuf))
			goto realign_again;
		goto full;
	}

	if ((TRACE_SOURCE)->verbosity >= H2_VERB_ADVANCED) {
		char sts[4];

		h2_trace_header(ist(":status"), ist(ultoa_r(h2s->status, sts, sizeof(sts))),
				    H2_EV_TX_FRAME|H2_EV_TX_HDR, ist(TRC_LOC), __FUNCTION__,
				    h2c, h2s);
	}

	/* encode all headers, stop at empty name */
	for (hdr = 0; hdr < sizeof(list)/sizeof(list[0]); hdr++) {
		/* these ones do not exist in H2 and must be dropped. */
		if (isteq(list[hdr].n, ist("connection")) ||
		    isteq(list[hdr].n, ist("proxy-connection")) ||
		    isteq(list[hdr].n, ist("keep-alive")) ||
		    isteq(list[hdr].n, ist("upgrade")) ||
		    isteq(list[hdr].n, ist("transfer-encoding")))
			continue;

		/* Skip all pseudo-headers */
		if (*(list[hdr].n.ptr) == ':')
			continue;

		if (isteq(list[hdr].n, ist("")))
			break; // end

		if (!h2_encode_header(&outbuf, list[hdr].n, list[hdr].v, H2_EV_TX_FRAME|H2_EV_TX_HDR,
		                      ist(TRC_LOC), __FUNCTION__, h2c, h2s)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (outbuf.data > h2c->mfs + 9) {
		if (!h2_fragment_headers(&outbuf, h2c->mfs)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	TRACE_USER("sent H2 response ", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);

	/* remove all header blocks including the EOH and compute the
	 * corresponding size.
	 */
	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		/* The removed block is the EOH */
		if (type == HTX_BLK_EOH)
			break;
	}

	if (!h2s_sc(h2s) || se_fl_test(h2s->sd, SE_FL_SHW)) {
		/* Response already closed: add END_STREAM */
		es_now = 1;
	}
	else if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx) && h2s->status >= 200) {
		/* EOM+empty: we may need to add END_STREAM except for 1xx
		 * responses and tunneled response.
		 */
		if (!(h2s->flags & H2_SF_BODY_TUNNEL) || h2s->status >= 300)
			es_now = 1;
	}

	if (es_now)
		outbuf.area[4] |= H2_F_HEADERS_END_STREAM;

	/* commit the H2 response */
	b_add(mbuf, outbuf.data);
	h2c->flags |= H2_CF_MBUF_HAS_DATA;

	/* indicates the HEADERS frame was sent, except for 1xx responses. For
	 * 1xx responses, another HEADERS frame is expected.
	 */
	if (h2s->status >= 200)
		h2s->flags |= H2_SF_HEADERS_SENT;

	if (h2c->flags & H2_CF_SHTS_UPDATED) {
		/* was sent above */
		h2c->flags |= H2_CF_DTSU_EMITTED;
		h2c->flags &= ~H2_CF_SHTS_UPDATED;
	}

	if (es_now) {
		h2s->flags |= H2_SF_ES_SENT;
		TRACE_PROTO("setting ES on HEADERS frame", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);
	}

	/* OK we could properly deliver the response */
 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
	return ret;
 full:
	if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
		goto retry;
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	TRACE_STATE("mux buffer full", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
	goto end;
 fail:
	/* unparsable HTX messages, too large ones to be produced in the local
	 * list etc go here (unrecoverable errors).
	 */
	h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
	ret = 0;
	goto end;
}

/* Try to send a HEADERS frame matching HTX request present in HTX message
 * <htx> for the H2 stream <h2s>. Returns the number of bytes sent. The caller
 * must check the stream's status to detect any error which might have happened
 * subsequently to a successful send. The htx blocks are automatically removed
 * from the message. The htx message is assumed to be valid since produced from
 * the internal code, hence it contains a start line, an optional series of
 * header blocks and an end of header, otherwise an invalid frame could be
 * emitted and the resulting htx message could be left in an inconsistent state.
 */
static size_t h2s_snd_bhdrs(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[global.tune.max_http_hdr * 2];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct buffer outbuf;
	struct buffer *mbuf;
	struct htx_sl *sl;
	struct ist meth, uri, auth, host = IST_NULL;
	enum htx_blk_type type;
	int es_now = 0;
	int ret = 0;
	int hdr;
	int extended_connect = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);

	/* get the start line (we do have one) and the rest of the headers,
	 * that we dump starting at header 0 */
	sl = NULL;
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOH)
			break;

		if (type == HTX_BLK_HDR) {
			BUG_ON(!sl); /* The start-line mut be defined before any headers */
			if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}

			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);

			/* Skip header if same name is used to add the server name */
			if ((h2c->flags & H2_CF_IS_BACK) && isttest(h2c->proxy->server_id_hdr_name) &&
			    isteq(list[hdr].n, h2c->proxy->server_id_hdr_name))
				continue;

			/* Convert connection: upgrade to Extended connect from rfc 8441 */
			if ((sl->flags & HTX_SL_F_CONN_UPG) && isteqi(list[hdr].n, ist("connection"))) {
				/* rfc 7230 #6.1 Connection = list of tokens */
				struct ist connection_ist = list[hdr].v;

				if (!(sl->flags & HTX_SL_F_BODYLESS)) {
					TRACE_STATE("cannot convert upgrade for request with payload", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
					goto fail;
				}

				do {
					if (isteqi(iststop(connection_ist, ','),
					           ist("upgrade"))) {
						if (!(h2c->flags & H2_CF_RCVD_RFC8441)) {
							TRACE_STATE("reject upgrade because of no RFC8441 support", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
							goto fail;
						}

						TRACE_STATE("convert upgrade to extended connect method", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
						h2s->flags |= (H2_SF_BODY_TUNNEL|H2_SF_EXT_CONNECT_SENT);
						sl->info.req.meth = HTTP_METH_CONNECT;
						meth = ist("CONNECT");

						extended_connect = 1;
						break;
					}

					connection_ist = istadv(istfind(connection_ist, ','), 1);
				} while (istlen(connection_ist));
			}

			if ((sl->flags & HTX_SL_F_CONN_UPG) && isteq(list[hdr].n, ist("upgrade"))) {
				/* rfc 7230 #6.7 Upgrade = list of protocols
				 * rfc 8441 #4 Extended connect = :protocol is single-valued
				 *
				 * only first HTTP/1 protocol is preserved
				 */
				const struct ist protocol = iststop(list[hdr].v, ',');
				/* upgrade_protocol field is 16 bytes long in h2s */
				istpad(h2s->upgrade_protocol, isttrim(protocol, 15));
			}

			if (isteq(list[hdr].n, ist("host")))
				host = list[hdr].v;

			hdr++;
		}
		else if (type == HTX_BLK_REQ_SL) {
			BUG_ON(sl); /* Only one start-line expected */
			sl = htx_get_blk_ptr(htx, blk);
			meth = htx_sl_req_meth(sl);
			uri  = htx_sl_req_uri(sl);
			if ((sl->flags & HTX_SL_F_BODYLESS_RESP) || sl->info.req.meth == HTTP_METH_HEAD)
				h2s->flags |= H2_SF_BODYLESS_RESP;
			if (unlikely(uri.len == 0)) {
				TRACE_ERROR("no URI in HTX request", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}
		}
		else {
			TRACE_ERROR("will not encode unexpected htx block", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
			goto fail;
		}
	}

	/* The start-line me be defined */
	BUG_ON(!sl);

	/* Now add the server name to a header (if requested) */
	if ((h2c->flags & H2_CF_IS_BACK) && isttest(h2c->proxy->server_id_hdr_name)) {
		struct server *srv = objt_server(h2c->conn->target);

		if (srv) {
			list[hdr].n = h2c->proxy->server_id_hdr_name;
			list[hdr].v = ist(srv->id);
			hdr++;
		}
	}

	/* marker for end of headers */
	list[hdr].n = ist("");

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
		return 0;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x04", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode the method, which necessarily is the first one */
	if (!hpack_encode_method(&outbuf, sl->info.req.meth, meth)) {
		if (b_space_wraps(mbuf))
			goto realign_again;
		goto full;
	}

	h2_trace_header(ist(":method"), meth, H2_EV_TX_FRAME|H2_EV_TX_HDR, ist(TRC_LOC), __FUNCTION__, h2c, h2s);

	auth = ist(NULL);

	/* RFC7540 #8.3: the CONNECT method must have :
	 *   - :authority set to the URI part (host:port)
	 *   - :method set to CONNECT
	 *   - :scheme and :path omitted
	 *
	 *   Note that this is not applicable in case of the Extended CONNECT
	 *   protocol from rfc 8441.
	 */
	if (unlikely(sl->info.req.meth == HTTP_METH_CONNECT) && !extended_connect) {
		auth = uri;

		if (!h2_encode_header(&outbuf, ist(":authority"), auth, H2_EV_TX_FRAME|H2_EV_TX_HDR,
		                      ist(TRC_LOC), __FUNCTION__, h2c, h2s)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}

		h2s->flags |= H2_SF_BODY_TUNNEL;
	} else {
		/* other methods need a :scheme. If an authority is known from
		 * the request line, it must be sent, otherwise only host is
		 * sent. Host is never sent as the authority.
		 *
		 * This code is also applicable for Extended CONNECT protocol
		 * from rfc 8441.
		 */
		struct ist scheme = { };

		if (uri.ptr[0] != '/' && uri.ptr[0] != '*') {
			/* the URI seems to start with a scheme */
			int len = 1;

			while (len < uri.len && uri.ptr[len] != ':')
				len++;

			if (len + 2 < uri.len && uri.ptr[len + 1] == '/' && uri.ptr[len + 2] == '/') {
				/* make the uri start at the authority now */
				scheme = ist2(uri.ptr, len);
				uri = istadv(uri, len + 3);

				/* find the auth part of the URI */
				auth = ist2(uri.ptr, 0);
				while (auth.len < uri.len && auth.ptr[auth.len] != '/')
					auth.len++;

				uri = istadv(uri, auth.len);
			}
		}

		/* For Extended CONNECT, the :authority must be present.
		 * Use host value for it.
		 */
		if (unlikely(extended_connect) && isttest(host))
			auth = host;

		if (!scheme.len) {
			/* no explicit scheme, we're using an origin-form URI,
			 * probably from an H1 request transcoded to H2 via an
			 * external layer, then received as H2 without authority.
			 * So we have to look up the scheme from the HTX flags.
			 * In such a case only http and https are possible, and
			 * https is the default (sent by browsers).
			 */
			if ((sl->flags & (HTX_SL_F_HAS_SCHM|HTX_SL_F_SCHM_HTTP)) == (HTX_SL_F_HAS_SCHM|HTX_SL_F_SCHM_HTTP))
				scheme = ist("http");
			else
				scheme = ist("https");
		}

		if (!hpack_encode_scheme(&outbuf, scheme)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}

		if (auth.len &&
		    !h2_encode_header(&outbuf, ist(":authority"), auth, H2_EV_TX_FRAME|H2_EV_TX_HDR,
		                      ist(TRC_LOC), __FUNCTION__, h2c, h2s)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}

		/* encode the path. RFC7540#8.1.2.3: if path is empty it must
		 * be sent as '/' or '*'.
		 */
		if (unlikely(!uri.len)) {
			if (sl->info.req.meth == HTTP_METH_OPTIONS)
				uri = ist("*");
			else
				uri = ist("/");
		}

		if (!hpack_encode_path(&outbuf, uri)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}

		h2_trace_header(ist(":path"), uri, H2_EV_TX_FRAME|H2_EV_TX_HDR, ist(TRC_LOC), __FUNCTION__, h2c, h2s);

		/* encode the pseudo-header protocol from rfc8441 if using
		 * Extended CONNECT method.
		 */
		if (unlikely(extended_connect)) {
			const struct ist protocol = ist(h2s->upgrade_protocol);
			if (isttest(protocol)) {
				if (!h2_encode_header(&outbuf, ist(":protocol"), protocol, H2_EV_TX_FRAME|H2_EV_TX_HDR,
				                      ist(TRC_LOC), __FUNCTION__, h2c, h2s)) {
					/* output full */
					if (b_space_wraps(mbuf))
						goto realign_again;
					goto full;
				}
			}
		}
	}

	/* encode all headers, stop at empty name. Host is only sent if we
	 * do not provide an authority.
	 */
	for (hdr = 0; hdr < sizeof(list)/sizeof(list[0]); hdr++) {
		struct ist n = list[hdr].n;
		struct ist v = list[hdr].v;

		/* these ones do not exist in H2 and must be dropped. */
		if (isteq(n, ist("connection")) ||
		    (auth.len && isteq(n, ist("host"))) ||
		    isteq(n, ist("proxy-connection")) ||
		    isteq(n, ist("keep-alive")) ||
		    isteq(n, ist("upgrade")) ||
		    isteq(n, ist("transfer-encoding")))
			continue;

		if (isteq(n, ist("te"))) {
			/* "te" may only be sent with "trailers" if this value
			 * is present, otherwise it must be deleted.
			 */
			v = istist(v, ist("trailers"));
			if (!isttest(v) || (v.len > 8 && v.ptr[8] != ','))
				continue;
			v = ist("trailers");
		}

		/* Skip all pseudo-headers */
		if (*(n.ptr) == ':')
			continue;

		if (isteq(n, ist("")))
			break; // end

		if (!h2_encode_header(&outbuf, n, v, H2_EV_TX_FRAME|H2_EV_TX_HDR, ist(TRC_LOC), __FUNCTION__, h2c, h2s)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (outbuf.data > h2c->mfs + 9) {
		if (!h2_fragment_headers(&outbuf, h2c->mfs)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	TRACE_USER("sent H2 request  ", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);

	/* remove all header blocks including the EOH and compute the
	 * corresponding size.
	 */
	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		/* The removed block is the EOH */
		if (type == HTX_BLK_EOH)
			break;
	}

	if (!h2s_sc(h2s) || se_fl_test(h2s->sd, SE_FL_SHW)) {
		/* Request already closed: add END_STREAM */
		es_now = 1;
	}
	if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx)) {
		/* EOM+empty: we may need to add END_STREAM (except for CONNECT
		 * request)
		 */
		if (!(h2s->flags & H2_SF_BODY_TUNNEL))
			es_now = 1;
	}

	if (es_now)
		outbuf.area[4] |= H2_F_HEADERS_END_STREAM;

	/* commit the H2 response */
	b_add(mbuf, outbuf.data);
	h2c->flags |= H2_CF_MBUF_HAS_DATA;
	h2s->flags |= H2_SF_HEADERS_SENT;
	h2s->st = H2_SS_OPEN;

	if (es_now) {
		TRACE_PROTO("setting ES on HEADERS frame", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);
		// trim any possibly pending data (eg: inconsistent content-length)
		h2s->flags |= H2_SF_ES_SENT;
		h2s->st = H2_SS_HLOC;
	}

 end:
	return ret;
 full:
	if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
		goto retry;
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	TRACE_STATE("mux buffer full", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
	goto end;
 fail:
	/* unparsable HTX messages, too large ones to be produced in the local
	 * list etc go here (unrecoverable errors).
	 */
	h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
	ret = 0;
	goto end;
}

/* Try to send a DATA frame matching HTTP response present in HTX structure
 * present in <buf>, for stream <h2s>. The caller must check the stream's status
 * to detect any error which might have happened subsequently to a successful
 * send. Returns the number of data bytes consumed, or zero if nothing done.
 */
static size_t h2s_make_data(struct h2s *h2s, struct buffer *buf, size_t count)
{
	struct h2c *h2c = h2s->h2c;
	struct htx *htx;
	struct buffer outbuf;
	struct buffer *mbuf;
	size_t total = 0;
	int es_now = 0;
	int bsize; /* htx block size */
	int fsize; /* h2 frame size  */
	struct htx_blk *blk;
	enum htx_blk_type type;
	int trunc_out; /* non-zero if truncated on out buf */

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);

	htx = htx_from_buf(buf);

	/* We only come here with HTX_BLK_DATA blocks */

 new_frame:
	if (!count || htx_is_empty(htx))
		goto end;

	if ((h2c->flags & H2_CF_IS_BACK) &&
		 (h2s->flags & (H2_SF_HEADERS_RCVD|H2_SF_BODY_TUNNEL)) == H2_SF_BODY_TUNNEL) {
		/* The response HEADERS frame not received yet. Thus the tunnel
		 * is not fully established yet. In this situation, we block
		 * data sending.
		 */
		h2s->flags |= H2_SF_BLK_MBUSY;
		TRACE_STATE("Request DATA frame blocked waiting for tunnel establishment", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto end;
	}
	else if ((h2c->flags & H2_CF_IS_BACK) && (h2s->flags & H2_SF_TUNNEL_ABRT)) {
		/* a tunnel attempt was aborted but the is pending raw data to xfer to the server.
		 * Thus the stream is closed with the CANCEL error. The error will be reported to
		 * the upper layer as aserver abort. But at this stage there is nothing more we can
		 * do. We just wait for the end of the response to be sure to not truncate it.
		 */
		if (!(h2s->flags & H2_SF_ES_RCVD)) {
			TRACE_STATE("Request DATA frame blocked waiting end of aborted tunnel", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			h2s->flags |= H2_SF_BLK_MBUSY;
		}
		else {
			TRACE_ERROR("Request DATA frame for aborted tunnel", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
			h2s_error(h2s, H2_ERR_CANCEL);
		}
		goto end;
	}

	blk   = htx_get_head_blk(htx);
	type  = htx_get_blk_type(blk);
	bsize = htx_get_blksz(blk);
	fsize = bsize;
	trunc_out = 0;
	if (type != HTX_BLK_DATA)
		goto end;

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (br_count(h2c->mbuf) > h2c->nb_streams) {
		/* more buffers than streams allocated, pointless
		 * to continue, we'd use more RAM for no reason.
		 */
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	/* Perform some optimizations to reduce the number of buffer copies.
	 * First, if the mux's buffer is empty and the htx area contains
	 * exactly one data block of the same size as the requested count, and
	 * this count fits within the frame size, the stream's window size, and
	 * the connection's window size, then it's possible to simply swap the
	 * caller's buffer with the mux's output buffer and adjust offsets and
	 * length to match the entire DATA HTX block in the middle. In this
	 * case we perform a true zero-copy operation from end-to-end. This is
	 * the situation that happens all the time with large files. Second, if
	 * this is not possible, but the mux's output buffer is empty, we still
	 * have an opportunity to avoid the copy to the intermediary buffer, by
	 * making the intermediary buffer's area point to the output buffer's
	 * area. In this case we want to skip the HTX header to make sure that
	 * copies remain aligned and that this operation remains possible all
	 * the time. This goes for headers, data blocks and any data extracted
	 * from the HTX blocks.
	 */
	if (unlikely(fsize == count &&
	             htx_nbblks(htx) == 1 && type == HTX_BLK_DATA &&
	             fsize <= h2s_mws(h2s) && fsize <= h2c->mws && fsize <= h2c->mfs)) {
		void *old_area = mbuf->area;

		if (b_data(mbuf)) {
			/* Too bad there are data left there. We're willing to memcpy/memmove
			 * up to 1/4 of the buffer, which means that it's OK to copy a large
			 * frame into a buffer containing few data if it needs to be realigned,
			 * and that it's also OK to copy few data without realigning. Otherwise
			 * we'll pretend the mbuf is full and wait for it to become empty.
			 */
			if (fsize + 9 <= b_room(mbuf) &&
			    (b_data(mbuf) <= b_size(mbuf) / 4 ||
			     (fsize <= b_size(mbuf) / 4 && fsize + 9 <= b_contig_space(mbuf)))) {
				TRACE_STATE("small data present in output buffer, appending", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
				goto copy;
			}

			if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;

			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			TRACE_STATE("too large data present in output buffer, waiting for emptiness", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			goto end;
		}

		if (htx->flags & HTX_FL_EOM) {
			/* EOM+empty: we may need to add END_STREAM (except for tunneled
			 * message)
			 */
			if (!(h2s->flags & H2_SF_BODY_TUNNEL))
				es_now = 1;
		}
		/* map an H2 frame to the HTX block so that we can put the
		 * frame header there.
		 */
		*mbuf = b_make(buf->area, buf->size, sizeof(struct htx) + blk->addr - 9, fsize + 9);
		outbuf.area    = b_head(mbuf);

		/* prepend an H2 DATA frame header just before the DATA block */
		memcpy(outbuf.area, "\x00\x00\x00\x00\x00", 5);
		write_n32(outbuf.area + 5, h2s->id); // 4 bytes
		if (es_now)
			outbuf.area[4] |= H2_F_DATA_END_STREAM;
		h2_set_frame_size(outbuf.area, fsize);

		/* update windows */
		h2s->sws -= fsize;
		h2c->mws -= fsize;

		/* and exchange with our old area */
		buf->area = old_area;
		buf->data = buf->head = 0;
		total += fsize;
		fsize = 0;
		h2c->flags |= H2_CF_MBUF_HAS_DATA;

		TRACE_PROTO("sent H2 DATA frame (zero-copy)", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto out;
	}

 copy:
	/* for DATA and EOM we'll have to emit a frame, even if empty */

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9) {
		if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
			goto retry;
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("output buffer full", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto end;
	}

	/* len: 0x000000 (fill later), type: 0(DATA), flags: none=0 */
	memcpy(outbuf.area, "\x00\x00\x00\x00\x00", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* we have in <fsize> the exact number of bytes we need to copy from
	 * the HTX buffer. We need to check this against the connection's and
	 * the stream's send windows, and to ensure that this fits in the max
	 * frame size and in the buffer's available space minus 9 bytes (for
	 * the frame header). The connection's flow control is applied last so
	 * that we can use a separate list of streams which are immediately
	 * unblocked on window opening. Note: we don't implement padding.
	 */

	if (!fsize)
		goto send_empty;

	if (h2s_mws(h2s) <= 0) {
		h2s->flags |= H2_SF_BLK_SFCTL;
		if (LIST_INLIST(&h2s->list))
			h2_remove_from_list(h2s);
		LIST_APPEND(&h2c->blocked_list, &h2s->list);
		TRACE_STATE("stream window <=0, flow-controlled", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2S_FCTL, h2c->conn, h2s);
		goto end;
	}

	if (fsize > count)
		fsize = count;

	if (fsize > h2s_mws(h2s))
		fsize = h2s_mws(h2s); // >0

	if (h2c->mfs && fsize > h2c->mfs)
		fsize = h2c->mfs; // >0

	if (fsize + 9 > outbuf.size) {
		/* It doesn't fit at once. If it at least fits once split and
		 * the amount of data to move is low, let's defragment the
		 * buffer now.
		 */
		if (b_space_wraps(mbuf) &&
		    (fsize + 9 <= b_room(mbuf)) &&
		    b_data(mbuf) <= MAX_DATA_REALIGN)
			goto realign_again;
		fsize = outbuf.size - 9;
		trunc_out = 1;

		if (fsize <= 0) {
			/* no need to send an empty frame here */
			if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			TRACE_STATE("output buffer full", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			goto end;
		}
	}

	if (h2c->mws <= 0) {
		h2s->flags |= H2_SF_BLK_MFCTL;
		TRACE_STATE("connection window <=0, stream flow-controlled", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2C_FCTL, h2c->conn, h2s);
		goto end;
	}

	if (fsize > h2c->mws)
		fsize = h2c->mws;

	/* now let's copy this this into the output buffer */
	memcpy(outbuf.area + 9, htx_get_blk_ptr(htx, blk), fsize);
	h2s->sws -= fsize;
	h2c->mws -= fsize;
	count    -= fsize;

 send_empty:
	/* update the frame's size */
	h2_set_frame_size(outbuf.area, fsize);

	/* consume incoming HTX block */
	total += fsize;
	if (fsize == bsize) {
		htx_remove_blk(htx, blk);
		if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx)) {
			/* EOM+empty: we may need to add END_STREAM (except for tunneled
			 * message)
			 */
			if (!(h2s->flags & H2_SF_BODY_TUNNEL))
				es_now = 1;
		}
	}
	else {
		/* we've truncated this block */
		htx_cut_data_blk(htx, blk, fsize);
	}

	if (es_now)
		outbuf.area[4] |= H2_F_DATA_END_STREAM;

	/* commit the H2 response */
	b_add(mbuf, fsize + 9);
	h2c->flags |= H2_CF_MBUF_HAS_DATA;

 out:
	if (es_now) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);

		h2s->flags |= H2_SF_ES_SENT;
		TRACE_PROTO("ES flag set on outgoing frame", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_TX_EOI, h2c->conn, h2s);
	}
	else if (fsize) {
		if (fsize == bsize) {
			TRACE_DEVEL("more data may be available, trying to send another frame", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			goto new_frame;
		}
		else if (trunc_out) {
			/* we've truncated this block */
			goto new_frame;
		}
	}

 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
	return total;
}

/* Skip the message payload (DATA blocks) and emit an empty DATA frame with the
 * ES flag set for stream <h2s>. This function is called for response known to
 * have no payload. Only DATA blocks are skipped. This means the trailers are
 * still emitted. The caller must check the stream's status to detect any error
 * which might have happened subsequently to a successful send. Returns the
 * number of data bytes consumed, or zero if nothing done.
 */
static size_t h2s_skip_data(struct h2s *h2s, struct buffer *buf, size_t count)
{
	struct h2c *h2c = h2s->h2c;
	struct htx *htx;
	int bsize; /* htx block size */
	int fsize; /* h2 frame size  */
	struct htx_blk *blk;
	enum htx_blk_type type;
	size_t total = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);

	htx = htx_from_buf(buf);

 next_data:
	if (!count || htx_is_empty(htx))
		goto end;
	blk   = htx_get_head_blk(htx);
	type  = htx_get_blk_type(blk);
	bsize = htx_get_blksz(blk);
	fsize = bsize;
	if (type != HTX_BLK_DATA)
		goto end;

	if (fsize > count)
		fsize = count;

	if (fsize != bsize)
		goto skip_data;

	if (!(htx->flags & HTX_FL_EOM) || !htx_is_unique_blk(htx, blk))
		goto skip_data;

	/* Here, it is the last block and it is also the end of the message. So
	 * we can emit an empty DATA frame with the ES flag set
	 */
	if (h2_send_empty_data_es(h2s) <= 0)
		goto end;

	if (h2s->st == H2_SS_OPEN)
		h2s->st = H2_SS_HLOC;
	else
		h2s_close(h2s);

 skip_data:
	/* consume incoming HTX block */
	total += fsize;
	if (fsize == bsize) {
		TRACE_DEVEL("more data may be available, trying to skip another frame", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		htx_remove_blk(htx, blk);
		goto next_data;
	}
	else {
		/* we've truncated this block */
		htx_cut_data_blk(htx, blk, fsize);
	}

 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
	return total;
}

/* Try to send a HEADERS frame matching HTX_BLK_TLR series of blocks present in
 * HTX message <htx> for the H2 stream <h2s>. Returns the number of bytes
 * processed. The caller must check the stream's status to detect any error
 * which might have happened subsequently to a successful send. The htx blocks
 * are automatically removed from the message. The htx message is assumed to be
 * valid since produced from the internal code. Processing stops when meeting
 * the EOT, which *is* removed. All trailers are processed at once and sent as a
 * single frame. The ES flag is always set.
 */
static size_t h2s_make_trailers(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[global.tune.max_http_hdr * 2];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct buffer outbuf;
	struct buffer *mbuf;
	enum htx_blk_type type;
	int ret = 0;
	int hdr;
	int idx;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);

	/* get trailers. */
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOT)
			break;
		if (type == HTX_BLK_TLR) {
			if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}

			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else {
			TRACE_ERROR("will not encode unexpected htx block", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
			goto fail;
		}
	}

	/* marker for end of trailers */
	list[hdr].n = ist("");

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4,ES=1 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x05", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode all headers */
	for (idx = 0; idx < hdr; idx++) {
		/* these ones do not exist in H2 or must not appear in
		 * trailers and must be dropped.
		 */
		if (isteq(list[idx].n, ist("host")) ||
		    isteq(list[idx].n, ist("content-length")) ||
		    isteq(list[idx].n, ist("connection")) ||
		    isteq(list[idx].n, ist("proxy-connection")) ||
		    isteq(list[idx].n, ist("keep-alive")) ||
		    isteq(list[idx].n, ist("upgrade")) ||
		    isteq(list[idx].n, ist("te")) ||
		    isteq(list[idx].n, ist("transfer-encoding")))
			continue;

		/* Skip all pseudo-headers */
		if (*(list[idx].n.ptr) == ':')
			continue;

		if (!h2_encode_header(&outbuf, list[idx].n, list[idx].v, H2_EV_TX_FRAME|H2_EV_TX_HDR,
		                      ist(TRC_LOC), __FUNCTION__, h2c, h2s)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	if (outbuf.data == 9) {
		/* here we have a problem, we have nothing to emit (either we
		 * received an empty trailers block followed or we removed its
		 * contents above). Because of this we can't send a HEADERS
		 * frame, so we have to cheat and instead send an empty DATA
		 * frame conveying the ES flag.
		 */
		outbuf.area[3] = H2_FT_DATA;
		outbuf.area[4] = H2_F_DATA_END_STREAM;
	}

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (outbuf.data > h2c->mfs + 9) {
		if (!h2_fragment_headers(&outbuf, h2c->mfs)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* commit the H2 response */
	TRACE_PROTO("sent H2 trailers HEADERS frame", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_TX_EOI, h2c->conn, h2s);
	b_add(mbuf, outbuf.data);
	h2c->flags |= H2_CF_MBUF_HAS_DATA;
	h2s->flags |= H2_SF_ES_SENT;

	if (h2s->st == H2_SS_OPEN)
		h2s->st = H2_SS_HLOC;
	else
		h2s_close(h2s);

	/* OK we could properly deliver the response */
 done:
	/* remove all header blocks till the end and compute the corresponding size. */
	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		/* The removed block is the EOT */
		if (type == HTX_BLK_EOT)
			break;
	}

 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
	return ret;
 full:
	if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
		goto retry;
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	TRACE_STATE("mux buffer full", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
	goto end;
 fail:
	/* unparsable HTX messages, too large ones to be produced in the local
	 * list etc go here (unrecoverable errors).
	 */
	h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
	ret = 0;
	goto end;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int h2_subscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct h2s *h2s = __sc_mux_strm(sc);
	struct h2c *h2c = h2s->h2c;

	TRACE_ENTER(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2c->conn, h2s);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(h2s->subs && h2s->subs != es);

	es->events |= event_type;
	h2s->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", H2_EV_STRM_RECV, h2c->conn, h2s);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", H2_EV_STRM_SEND, h2c->conn, h2s);
		if (!(h2s->flags & H2_SF_BLK_SFCTL) &&
		    !LIST_INLIST(&h2s->list)) {
			if (h2s->flags & H2_SF_BLK_MFCTL) {
				TRACE_DEVEL("Adding to fctl list", H2_EV_STRM_SEND, h2c->conn, h2s);
				LIST_APPEND(&h2c->fctl_list, &h2s->list);
			}
			else {
				TRACE_DEVEL("Adding to send list", H2_EV_STRM_SEND, h2c->conn, h2s);
				LIST_APPEND(&h2c->send_list, &h2s->list);
			}
		}
	}
	TRACE_LEAVE(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2c->conn, h2s);
	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int h2_unsubscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct h2s *h2s = __sc_mux_strm(sc);

	TRACE_ENTER(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2s->h2c->conn, h2s);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(h2s->subs && h2s->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		h2s->subs = NULL;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", H2_EV_STRM_RECV, h2s->h2c->conn, h2s);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("unsubscribe(send)", H2_EV_STRM_SEND, h2s->h2c->conn, h2s);
		h2s->flags &= ~H2_SF_NOTIFIED;
		if (!(h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW)))
			h2_remove_from_list(h2s);
	}

	TRACE_LEAVE(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2s->h2c->conn, h2s);
	return 0;
}


/* Called from the upper layer, to receive data
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
static size_t h2_rcv_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct h2s *h2s = __sc_mux_strm(sc);
	struct h2c *h2c = h2s->h2c;
	struct htx *h2s_htx = NULL;
	struct htx *buf_htx = NULL;
	struct buffer *rxbuf = NULL;
	struct htx_ret htxret;
	size_t ret = 0;
	uint prev_h2c_flags = h2c->flags;

	TRACE_ENTER(H2_EV_STRM_RECV, h2c->conn, h2s);

	/* transfer possibly pending data to the upper layer */

 xfer_next_buf:
	rxbuf = h2s_rxbuf_head(h2s);
	if (!rxbuf)
		goto end; // may be NULL if empty

	h2s_htx = htx_from_buf(rxbuf);
	if (htx_is_empty(h2s_htx) && !(h2s_htx->flags & HTX_FL_PARSING_ERROR)) {
		/* Here htx_to_buf() will set buffer data to 0 because
		 * the HTX is empty.
		 */
		htx_to_buf(h2s_htx, rxbuf);
		goto end;
	}
	ret += h2s_htx->data;
	buf_htx = htx_from_buf(buf);

	/* <buf> is empty and the message is small enough, swap the
	 * buffers. */
	if (htx_is_empty(buf_htx) && htx_used_space(h2s_htx) <= count) {
		count -= h2s_htx->data;
		htx_to_buf(buf_htx, buf);
		htx_to_buf(h2s_htx, rxbuf);
		b_xfer(buf, rxbuf, b_data(rxbuf));
		goto end;
	}

	htxret = htx_xfer_blks(buf_htx, h2s_htx, count, HTX_BLK_UNUSED);
	count -= htxret.ret;

	if (h2s_htx->flags & HTX_FL_PARSING_ERROR) {
		buf_htx->flags |= HTX_FL_PARSING_ERROR;
		if (htx_is_empty(buf_htx))
			se_fl_set(h2s->sd, SE_FL_EOI);
	}
	else if (htx_is_empty(h2s_htx)) {
		buf_htx->flags |= (h2s_htx->flags & HTX_FL_EOM);
	}

	buf_htx->extra = (h2s_htx->extra ? (h2s_htx->data + h2s_htx->extra) : 0);
	htx_to_buf(buf_htx, buf);
	htx_to_buf(h2s_htx, rxbuf);
	ret -= h2s_htx->data;

  end:
	/* release the rxbuf if it's not used anymore */
	if (rxbuf && !b_data(rxbuf) && b_size(rxbuf)) {
		BUG_ON_HOT(rxbuf != _h2s_rxbuf_head(h2s));
		b_free(_h2s_rxbuf_head(h2s));
		offer_buffers(NULL, 1);
	}

	/* release the unused rxbuf slot */
	if (rxbuf && !b_size(rxbuf)) {
		h2s_put_rxbuf(h2s);
		h2c->flags &= ~(H2_CF_DEM_RXBUF | H2_CF_DEM_SFULL);
		/* Copied more data if possible */
		if (count)
			goto xfer_next_buf;
	}

	/* tell the stream layer whether there are data left or not */
	if (h2s_rxbuf_cnt(h2s)) {
		se_fl_set(h2s->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		BUG_ON_HOT(!buf->data);
	}
	else {
		if (!(h2c->flags & H2_CF_IS_BACK) && (h2s->flags & (H2_SF_BODY_TUNNEL|H2_SF_ES_RCVD))) {
			/* If request ES is reported to the upper layer, it means the
			 * H2S now expects data from the opposite side.
			 */
			se_expect_data(h2s->sd);
		}

		se_fl_clr(h2s->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		h2s_propagate_term_flags(h2c, h2s);
	}

	/* the demux might have been blocking on this stream's buffer */
	if (ret && h2c->dsi == h2s->id)
		h2c->flags &= ~H2_CF_DEM_SFULL;

	/* wake up processing if we've unblocked something */
	if ((prev_h2c_flags & ~h2c->flags) & ((H2_CF_DEM_SFULL | H2_CF_DEM_RXBUF)))
		h2c_restart_reading(h2c, 1);

	BUG_ON_HOT(!buf->data && se_fl_test(h2s->sd, SE_FL_WANT_ROOM));

	TRACE_LEAVE(H2_EV_STRM_RECV, h2c->conn, h2s);
	return ret;
}


/* Called from the upper layer, to send data from buffer <buf> for no more than
 * <count> bytes. Returns the number of bytes effectively sent. Some status
 * flags may be updated on the stream connector.
 */
static size_t h2_snd_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct h2s *h2s = __sc_mux_strm(sc);
	size_t total = 0;
	size_t ret;
	struct htx *htx;
	struct htx_blk *blk;
	enum htx_blk_type btype;
	uint32_t bsize;
	int32_t idx;

	TRACE_ENTER(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);

	/* If we were not just woken because we wanted to send but couldn't,
	 * and there's somebody else that is waiting to send, do nothing,
	 * we will subscribe later and be put at the end of the list
	 */
	if (!(h2s->flags & H2_SF_NOTIFIED) &&
	    (!LIST_ISEMPTY(&h2s->h2c->send_list) || !LIST_ISEMPTY(&h2s->h2c->fctl_list))) {
		if (LIST_INLIST(&h2s->list))
			TRACE_DEVEL("stream already waiting, leaving", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2s->h2c->conn, h2s);
		else {
			TRACE_DEVEL("other streams already waiting, going to the queue and leaving", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2s->h2c->conn, h2s);
			h2s->h2c->flags |= H2_CF_WAIT_INLIST;
		}
		return 0;
	}
	h2s->flags &= ~H2_SF_NOTIFIED;

	if (h2s->h2c->st0 < H2_CS_FRAME_H) {
		TRACE_DEVEL("connection not ready, leaving", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2s->h2c->conn, h2s);
		return 0;
	}

	if (h2s->h2c->st0 >= H2_CS_ERROR) {
		se_fl_set(h2s->sd, SE_FL_ERROR);
		TRACE_DEVEL("connection is in error, leaving in error", H2_EV_H2S_SEND|H2_EV_H2S_BLK|H2_EV_H2S_ERR|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
		return 0;
	}

	htx = htx_from_buf(buf);

	if (!(h2s->flags & H2_SF_OUTGOING_DATA) && count)
		h2s->flags |= H2_SF_OUTGOING_DATA;

	if (htx->extra && htx->extra != HTX_UNKOWN_PAYLOAD_LENGTH)
		h2s->flags |= H2_SF_MORE_HTX_DATA;
	else
		h2s->flags &= ~H2_SF_MORE_HTX_DATA;

	if (h2s->id == 0) {
		int32_t id = h2c_get_next_sid(h2s->h2c);

		if (id < 0) {
			se_fl_set(h2s->sd, SE_FL_ERROR);
			TRACE_DEVEL("couldn't get a stream ID, leaving in error", H2_EV_H2S_SEND|H2_EV_H2S_BLK|H2_EV_H2S_ERR|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
			return 0;
		}

		eb32_delete(&h2s->by_id);
		h2s->by_id.key = h2s->id = id;
		h2s->h2c->max_id = id;
		h2s->h2c->nb_reserved--;
		eb32_insert(&h2s->h2c->streams_by_id, &h2s->by_id);
	}

	while (h2s->st < H2_SS_HLOC && !(h2s->flags & H2_SF_BLK_ANY) &&
	       count && !htx_is_empty(htx)) {
		idx   = htx_get_head(htx);
		blk   = htx_get_blk(htx, idx);
		btype = htx_get_blk_type(blk);
		bsize = htx_get_blksz(blk);

		switch (btype) {
			case HTX_BLK_REQ_SL:
				/* start-line before headers */
				ret = h2s_snd_bhdrs(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_RES_SL:
				/* start-line before headers */
				ret = h2s_snd_fhdrs(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_DATA:
				/* all these cause the emission of a DATA frame (possibly empty) */
				if (!(h2s->h2c->flags & H2_CF_IS_BACK) &&
				    (h2s->flags & (H2_SF_BODY_TUNNEL|H2_SF_BODYLESS_RESP)) == H2_SF_BODYLESS_RESP)
					ret = h2s_skip_data(h2s, buf, count);
				else
					ret = h2s_make_data(h2s, buf, count);
				if (ret > 0) {
					htx = htx_from_buf(buf);
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_TLR:
			case HTX_BLK_EOT:
				/* This is the first trailers block, all the subsequent ones */
				ret = h2s_make_trailers(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			default:
				htx_remove_blk(htx, blk);
				total += bsize;
				count -= bsize;
				break;
		}
	}

  done:
	if (h2s->st >= H2_SS_HLOC) {
		/* trim any possibly pending data after we close (extra CR-LF,
		 * unprocessed trailers, abnormal extra data, ...)
		 */
		total += count;
		count = 0;
	}

	/* RST are sent similarly to frame acks */
	if (h2s->st == H2_SS_ERROR || h2s->flags & H2_SF_RST_RCVD) {
		TRACE_DEVEL("reporting RST/error to the app-layer stream", H2_EV_H2S_SEND|H2_EV_H2S_ERR|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
		se_fl_set_error(h2s->sd);
		se_report_term_evt(h2s->sd, se_tevt_type_snd_err);
		if (h2s_send_rst_stream(h2s->h2c, h2s) > 0)
			h2s_close(h2s);
	}

	htx_to_buf(htx, buf);

	if (total > 0) {
		if (!(h2s->h2c->wait_event.events & SUB_RETRY_SEND)) {
			TRACE_DEVEL("data queued, waking up h2c sender", H2_EV_H2S_SEND|H2_EV_H2C_SEND, h2s->h2c->conn, h2s);
			if (h2_send(h2s->h2c))
				tasklet_wakeup(h2s->h2c->wait_event.tasklet);
		}

	}
	/* If we're waiting for flow control, and we got a shutr on the
	 * connection, we will never be unlocked, so add an error on
	 * the stream connector.
	 */
	if ((h2s->h2c->flags & H2_CF_RCVD_SHUT) &&
	    !b_data(&h2s->h2c->dbuf) &&
	    (h2s->flags & (H2_SF_BLK_SFCTL | H2_SF_BLK_MFCTL))) {
		TRACE_DEVEL("fctl with shutr, reporting error to app-layer", H2_EV_H2S_SEND|H2_EV_STRM_SEND|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
		se_fl_set_error(h2s->sd);
	}

	if (total > 0 && !(h2s->flags & H2_SF_BLK_SFCTL) &&
	    !(h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))) {
		/* Ok we managed to send something, leave the send_list if we were still there */
		h2_remove_from_list(h2s);
		TRACE_DEVEL("Removed from h2s list", H2_EV_H2S_SEND|H2_EV_H2C_SEND, h2s->h2c->conn, h2s);
	}

	TRACE_LEAVE(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);
	return total;
}

static size_t h2_nego_ff(struct stconn *sc, struct buffer *input, size_t count, unsigned int flags)
{
	struct h2s *h2s = __sc_mux_strm(sc);
	struct h2c *h2c = h2s->h2c;
	struct buffer *mbuf;
	size_t sz , ret = 0;

	TRACE_ENTER(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);

	/* If we were not just woken because we wanted to send but couldn't,
	 * and there's somebody else that is waiting to send, do nothing,
	 * we will subscribe later and be put at the end of the list
	 *
	 * WARNING: h2_done_ff() is responsible to remove H2_SF_NOTIFIED flags
	 *          depending on iobuf flags.
	 */
	if (!(h2s->flags & H2_SF_NOTIFIED) &&
	    (!LIST_ISEMPTY(&h2c->send_list) || !LIST_ISEMPTY(&h2c->fctl_list))) {
		if (LIST_INLIST(&h2s->list))
			TRACE_DEVEL("stream already waiting, leaving", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2s->h2c->conn, h2s);
		else {
			TRACE_DEVEL("other streams already waiting, going to the queue and leaving", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2s->h2c->conn, h2s);
			h2s->h2c->flags |= H2_CF_WAIT_INLIST;
		}
		h2s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		goto end;
	}

	if (h2s_mws(h2s) <= 0) {
		h2s->flags |= H2_SF_BLK_SFCTL;
		if (LIST_INLIST(&h2s->list))
			LIST_DEL_INIT(&h2s->list);
		LIST_APPEND(&h2c->blocked_list, &h2s->list);
		h2s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("stream window <=0, flow-controlled", H2_EV_H2S_SEND|H2_EV_H2S_FCTL, h2c->conn, h2s);
		goto end;
	}
	if (h2c->mws <= 0) {
		h2s->flags |= H2_SF_BLK_MFCTL;
		h2s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("connection window <=0, stream flow-controlled", H2_EV_H2S_SEND|H2_EV_H2C_FCTL, h2c->conn, h2s);
		goto end;
	}

	sz = count;
	if (sz > h2s_mws(h2s))
		sz = h2s_mws(h2s);
	if (h2c->mfs && sz > h2c->mfs)
		sz = h2c->mfs; // >0
	if (sz > h2c->mws)
		sz = h2c->mws;

	if (count > sz)
		count = sz;

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (br_count(h2c->mbuf) > h2c->nb_streams) {
		/* more buffers than streams allocated, pointless
		 * to continue, we'd use more RAM for no reason.
		 */
		h2s->flags |= H2_SF_BLK_MROOM;
		h2s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		h2s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("waiting for room in output buffer", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	if (b_room(mbuf) < sz && b_room(mbuf) < b_size(mbuf) / 4) {
		if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
			goto retry;
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
		h2s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("too large data present in output buffer, waiting for emptiness", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	while (1) {
		if (b_contig_space(mbuf) >= 9 || !b_space_wraps(mbuf))
			break;
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (b_contig_space(mbuf) <= 9) {
		if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
			goto retry;
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
		h2s->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		TRACE_STATE("output buffer full", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	/* Cannot forward more than available room in output buffer */
	sz = b_contig_space(mbuf) - 9;
	if (count > sz)
		count = sz;

	/* len: 0x000000 (fill later), type: 0(DATA), flags: none=0 */
	memcpy(b_tail(mbuf), "\x00\x00\x00\x00\x00", 5);
	write_n32(b_tail(mbuf) + 5, h2s->id); // 4 bytes

	h2s->sd->iobuf.buf = mbuf;
	h2s->sd->iobuf.offset = 9;
	h2s->sd->iobuf.data = 0;

	/* forward remaining input data */
	if (b_data(input)) {
		size_t xfer = count;

		if (xfer > b_data(input))
			xfer = b_data(input);
		b_add(mbuf, 9);
		h2s->sd->iobuf.data = b_xfer(mbuf, input, xfer);
		b_sub(mbuf, 9);

		/* Cannot forward more data, wait for room */
		if (b_data(input))
			goto end;
	}

	ret = count - h2s->sd->iobuf.data;
 end:
	if (h2s->sd->iobuf.flags & IOBUF_FL_FF_BLOCKED)
		h2s->flags &= ~H2_SF_NOTIFIED;
	TRACE_LEAVE(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);
	return ret;
}

static size_t h2_done_ff(struct stconn *sc)
{
	struct h2s *h2s = __sc_mux_strm(sc);
	struct h2c *h2c = h2s->h2c;
	struct sedesc *sd = h2s->sd;
	struct buffer *mbuf;
	char *head;
	size_t total = 0;
	int es_now = 0;

	TRACE_ENTER(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);

	mbuf = sd->iobuf.buf;
	if (!mbuf)
		goto end;
	head = b_peek(mbuf, b_data(mbuf) - sd->iobuf.data);

	if (sd->iobuf.flags & IOBUF_FL_EOI) {
		es_now = 1;
		h2s->flags &= ~H2_SF_MORE_HTX_DATA;
	}

	if (!sd->iobuf.data)
		goto end;

	/* Perform a synchronous send but in all cases, consider
	 * everything was already sent from the SC point of view.
	 */
	total = sd->iobuf.data;
	h2_set_frame_size(head, total);
	if (es_now)
		head[4] |= H2_F_DATA_END_STREAM;
	b_add(mbuf, 9);
	h2s->sws -= total;
	h2c->mws -= total;
	if (h2_send(h2s->h2c))
		tasklet_wakeup(h2s->h2c->wait_event.tasklet);

	if (es_now) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);

		h2s->flags |= H2_SF_ES_SENT;
		TRACE_PROTO("ES flag set on outgoing frame", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_TX_EOI, h2c->conn, h2s);
	}

 end:
	sd->iobuf.buf = NULL;
	sd->iobuf.offset = 0;
	sd->iobuf.data = 0;

	if (!(sd->iobuf.flags & IOBUF_FL_INTERIM_FF))
	    h2s->flags &= ~H2_SF_NOTIFIED;

	if ((total || !(sd->iobuf.flags & IOBUF_FL_FF_BLOCKED)) &&
	    !(h2s->flags & H2_SF_BLK_SFCTL) &&
	    !(h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))) {
		/* Ok we managed to send something, leave the send_list if we were still there */
		h2_remove_from_list(h2s);
	}

	TRACE_LEAVE(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);
	return total;
}

static int h2_resume_ff(struct stconn *sc, unsigned int flags)
{
	return 0;
}

/* appends some info about stream <h2s> to buffer <msg>, or does nothing if
 * <h2s> is NULL. Returns non-zero if the stream is considered suspicious. May
 * emit multiple lines, each new one being prefixed with <pfx>, if <pfx> is not
 * NULL, otherwise a single line is used.
 */
static int h2_dump_h2s_info(struct buffer *msg, const struct h2s *h2s, const char *pfx)
{
	const struct buffer *head, *tail;
	int ret = 0;

	if (!h2s)
		return ret;

	head = h2s_rxbuf_head(h2s);
	tail = h2s_rxbuf_tail(h2s);

	chunk_appendf(msg, " h2s.id=%d .st=%s .flg=0x%04x .rxwin=%u .rxbuf.c=%u .t=%u@%p+%u/%u .h=%u@%p+%u/%u",
		      h2s->id, h2s_st_to_str(h2s->st), h2s->flags,
		      (uint)(h2s->next_max_ofs - h2s->curr_rx_ofs),
		      h2s_rxbuf_cnt(h2s),
		      tail ? (uint)b_data(tail) : 0,
		      tail ? b_orig(tail) : NULL,
		      tail ? (uint)b_head_ofs(tail) : 0,
		      tail ? (uint)b_size(tail) : 0,
		      head ? (uint)b_data(head) : 0,
		      head ? b_orig(head) : NULL,
		      head ? (uint)b_head_ofs(head) : 0,
		      head ? (uint)b_size(head) : 0);

	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);

	chunk_appendf(msg, " .sc=%p", h2s_sc(h2s));
	if (h2s_sc(h2s))
		chunk_appendf(msg, "(.flg=0x%08x .app=%p)",
			      h2s_sc(h2s)->flags, h2s_sc(h2s)->app);

	chunk_appendf(msg, " .sd=%p", h2s->sd);
	chunk_appendf(msg, "(.flg=0x%08x .evts=%s)", se_fl_get(h2s->sd), tevt_evts2str(h2s->sd->term_evts_log));

	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);

	chunk_appendf(msg, " .subs=%p", h2s->subs);
	if (h2s->subs) {
		chunk_appendf(msg, "(ev=%d tl=%p", h2s->subs->events, h2s->subs->tasklet);
		chunk_appendf(msg, " tl.calls=%d tl.ctx=%p tl.fct=",
			      h2s->subs->tasklet->calls,
			      h2s->subs->tasklet->context);
		if (h2s->subs->tasklet->calls >= 1000000)
			ret = 1;
		resolve_sym_name(msg, NULL, h2s->subs->tasklet->process);
		chunk_appendf(msg, ")");
	}
	return ret;
}

/* appends some info about connection <h2c> to buffer <msg>, or does nothing if
 * <h2c> is NULL. Returns non-zero if the connection is considered suspicious.
 * May emit multiple lines, each new one being prefixed with <pfx>, if <pfx> is
 * not NULL, otherwise a single line is used.
 */
static int h2_dump_h2c_info(struct buffer *msg, struct h2c *h2c, const char *pfx)
{
	const struct buffer *hmbuf, *tmbuf;
	const struct h2s *h2s = NULL;
	struct eb32_node *node;
	int fctl_cnt = 0;
	int send_cnt = 0;
	int tree_cnt = 0;
	int orph_cnt = 0;
	int ret = 0;

	if (!h2c)
		return ret;

	list_for_each_entry(h2s, &h2c->fctl_list, list)
		fctl_cnt++;

	list_for_each_entry(h2s, &h2c->send_list, list)
		send_cnt++;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		tree_cnt++;
		if (!h2s_sc(h2s))
			orph_cnt++;
		node = eb32_next(node);
	}

	hmbuf = br_head(h2c->mbuf);
	tmbuf = br_tail(h2c->mbuf);
	chunk_appendf(msg, " h2c.st0=%s .err=%d .maxid=%d .lastid=%d .flg=0x%04x"
		      " .nbst=%u .nbsc=%u .nbrcv=%u .glitches=%d .evts=%s",
		      h2c_st_to_str(h2c->st0), h2c->errcode, h2c->max_id, h2c->last_sid, h2c->flags,
		      h2c->nb_streams, h2c->nb_sc, h2c->receiving_streams, h2c->glitches,
		      tevt_evts2str(h2c->term_evts_log));

	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);

	chunk_appendf(msg, " .fctl_cnt=%d .send_cnt=%d .tree_cnt=%d"
		      " .orph_cnt=%d .sub=%d .dsi=%d .dbuf=%u@%p+%u/%u",
		      fctl_cnt, send_cnt, tree_cnt, orph_cnt,
		      h2c->wait_event.events, h2c->dsi,
		      (unsigned int)b_data(&h2c->dbuf), b_orig(&h2c->dbuf),
		      (unsigned int)b_head_ofs(&h2c->dbuf), (unsigned int)b_size(&h2c->dbuf));

	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);

	chunk_appendf(msg, " .mbuf=[%u..%u|%u],h=[%u@%p+%u/%u],t=[%u@%p+%u/%u]",
		      br_head_idx(h2c->mbuf), br_tail_idx(h2c->mbuf), br_size(h2c->mbuf),
		      (unsigned int)b_data(hmbuf), b_orig(hmbuf),
		      (unsigned int)b_head_ofs(hmbuf), (unsigned int)b_size(hmbuf),
		      (unsigned int)b_data(tmbuf), b_orig(tmbuf),
		      (unsigned int)b_head_ofs(tmbuf), (unsigned int)b_size(tmbuf));

	chunk_appendf(msg, " .task=%p", h2c->task);
	if (h2c->task) {
		chunk_appendf(msg, " .exp=%s",
			      h2c->task->expire ? tick_is_expired(h2c->task->expire, now_ms) ? "<PAST>" :
			      human_time(TICKS_TO_MS(h2c->task->expire - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	}

	return ret;
}

/* for debugging with CLI's "show fd" command */
static int h2_show_fd(struct buffer *msg, struct connection *conn)
{
	struct h2c *h2c = conn->ctx;
	const struct h2s *h2s;
	struct eb32_node *node;
	int ret = 0;

	if (!h2c)
		return ret;

	ret |= h2_dump_h2c_info(msg, h2c, NULL);

	node = eb32_last(&h2c->streams_by_id);
	if (node) {
		h2s = container_of(node, struct h2s, by_id);
		chunk_appendf(msg, " last_h2s=%p", h2s);
		ret |= h2_dump_h2s_info(msg, h2s, NULL);
	}

	return ret;
}

/* for debugging with CLI's "show sess" command. May emit multiple lines, each
 * new one being prefixed with <pfx>, if <pfx> is not NULL, otherwise a single
 * line is used. Each field starts with a space so it's safe to print it after
 * existing fields.
 */
static int h2_show_sd(struct buffer *msg, struct sedesc *sd, const char *pfx)
{
	struct h2s *h2s = sd->se;
	int ret = 0;

	if (!h2s)
		return ret;

	chunk_appendf(msg, " h2s=%p", h2s);
	ret |= h2_dump_h2s_info(msg, h2s, pfx);
	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);
	chunk_appendf(msg, " h2c=%p", h2s->h2c);
	ret |= h2_dump_h2c_info(msg, h2s->h2c, pfx);
	return ret;
}

/* Migrate the the connection to the current thread.
 * Return 0 if successful, non-zero otherwise.
 * Expected to be called with the old thread lock held.
 */
static int h2_takeover(struct connection *conn, int orig_tid, int release)
{
	struct h2c *h2c = conn->ctx;
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
		if (LIST_INLIST(&h2c->buf_wait.list))
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
		tasklet_wakeup_on(h2c->wait_event.tasklet, orig_tid);
		goto fail;
	}

	if (h2c->wait_event.events)
		h2c->conn->xprt->unsubscribe(h2c->conn, h2c->conn->xprt_ctx,
		    h2c->wait_event.events, &h2c->wait_event);

	task = h2c->task;
	if (task) {
		/* only assign a task if there was already one, otherwise
		 * the preallocated new task will be released.
		 */
		task->context = NULL;
		h2c->task = NULL;
		__ha_barrier_store();
		task_kill(task);

		h2c->task = new_task;
		new_task = NULL;
		if (!release) {
			h2c->task->process = h2_timeout_task;
			h2c->task->context = h2c;
		}
	}

	/* To let the tasklet know it should free itself, and do nothing else,
	 * set its context to NULL.
	 */
	h2c->wait_event.tasklet->context = NULL;
	tasklet_wakeup_on(h2c->wait_event.tasklet, orig_tid);

	h2c->wait_event.tasklet = new_tasklet;
	if (!release) {
		h2c->wait_event.tasklet->process = h2_io_cb;
		h2c->wait_event.tasklet->context = h2c;
		h2c->conn->xprt->subscribe(h2c->conn, h2c->conn->xprt_ctx,
		                           SUB_RETRY_RECV, &h2c->wait_event);
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
		if (LIST_INLIST(&h2c->buf_wait.list))
			_b_dequeue(&h2c->buf_wait, orig_tid);
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

/*******************************************************/
/* functions below are dedicated to the config parsers */
/*******************************************************/

/* config parser for global "tune.h2.{fe,be}.glitches-threshold" */
static int h2_parse_glitches_threshold(char **args, int section_type, struct proxy *curpx,
				       const struct proxy *defpx, const char *file, int line,
				       char **err)
{
	int *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend */
	vptr = (args[0][8] == 'b') ? &h2_be_glitches_threshold : &h2_fe_glitches_threshold;

	*vptr = atoi(args[1]);
	if (*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.header-table-size" */
static int h2_parse_header_table_size(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_header_table_size = atoi(args[1]);
	if (h2_settings_header_table_size < 4096 || h2_settings_header_table_size > 65536) {
		memprintf(err, "'%s' expects a numeric value between 4096 and 65536.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.{be.,fe.,}initial-window-size" */
static int h2_parse_initial_window_size(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	int *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend/default */
	vptr = (args[0][8] == 'b') ? &h2_be_settings_initial_window_size :
	       (args[0][8] == 'f') ? &h2_fe_settings_initial_window_size :
	       &h2_settings_initial_window_size;

	*vptr = atoi(args[1]);
	if (*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.{be.,fe.,}max-concurrent-streams" */
static int h2_parse_max_concurrent_streams(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	uint *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend/default */
	vptr = (args[0][8] == 'b') ? &h2_be_settings_max_concurrent_streams :
	       (args[0][8] == 'f') ? &h2_fe_settings_max_concurrent_streams :
	       &h2_settings_max_concurrent_streams;

	*vptr = atoi(args[1]);
	if ((int)*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.fe.max-total-streams" */
static int h2_parse_max_total_streams(char **args, int section_type, struct proxy *curpx,
				      const struct proxy *defpx, const char *file, int line,
				      char **err)
{
	uint *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* frontend only for now */
	vptr = &h2_fe_max_total_streams;

	*vptr = atoi(args[1]);
	if ((int)*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.max-frame-size" */
static int h2_parse_max_frame_size(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_max_frame_size = atoi(args[1]);
	if (h2_settings_max_frame_size < 16384 || h2_settings_max_frame_size > 16777215) {
		memprintf(err, "'%s' expects a numeric value between 16384 and 16777215.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.{be.,fe.}rxbuf" */
static int h2_parse_rxbuf(char **args, int section_type, struct proxy *curpx,
                          const struct proxy *defpx, const char *file, int line,
                          char **err)
{
	const char *errptr;
	uint *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend */
	vptr = (args[0][8] == 'b') ? &h2_be_rxbuf : &h2_fe_rxbuf;

	*vptr = atoi(args[1]);
	if ((errptr = parse_size_err(args[1], vptr)) != NULL) {
		memprintf(err, "'%s': unexpected character '%c' in size argument '%s'.", args[0], *errptr, args[1]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.zero-copy-fwd-send" */
static int h2_parse_zero_copy_fwd_snd(char **args, int section_type, struct proxy *curpx,
					  const struct proxy *defpx, const char *file, int line,
					  char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.no_zero_copy_fwd &= ~NO_ZERO_COPY_FWD_H2_SND;
	else if (strcmp(args[1], "off") == 0)
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD_H2_SND;
	else {
		memprintf(err, "'%s' expects 'on' or 'off'.", args[0]);
		return -1;
	}
	return 0;
}

/****************************************/
/* MUX initialization and instantiation */
/***************************************/

/* The mux operations */
static const struct mux_ops h2_ops = {
	.init = h2_init,
	.wake = h2_wake,
	.snd_buf = h2_snd_buf,
	.rcv_buf = h2_rcv_buf,
	.nego_fastfwd = h2_nego_ff,
	.done_fastfwd = h2_done_ff,
	.resume_fastfwd = h2_resume_ff,
	.subscribe = h2_subscribe,
	.unsubscribe = h2_unsubscribe,
	.attach = h2_attach,
	.get_first_sc = h2_get_first_sc,
	.detach = h2_detach,
	.destroy = h2_destroy,
	.avail_streams = h2_avail_streams,
	.used_streams = h2_used_streams,
	.shut = h2_shut,
	.ctl = h2_ctl,
	.sctl = h2_sctl,
	.show_fd = h2_show_fd,
	.show_sd = h2_show_sd,
	.takeover = h2_takeover,
	.flags = MX_FL_HTX|MX_FL_HOL_RISK|MX_FL_NO_UPG|MX_FL_REVERSABLE,
	.name = "H2",
};

static struct mux_proto_list mux_proto_h2 =
	{ .token = IST("h2"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_BOTH, .mux = &h2_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_h2);

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.h2.be.glitches-threshold",  h2_parse_glitches_threshold     },
	{ CFG_GLOBAL, "tune.h2.be.initial-window-size", h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.be.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ CFG_GLOBAL, "tune.h2.be.rxbuf",               h2_parse_rxbuf                  },
	{ CFG_GLOBAL, "tune.h2.fe.glitches-threshold",  h2_parse_glitches_threshold     },
	{ CFG_GLOBAL, "tune.h2.fe.initial-window-size", h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.fe.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ CFG_GLOBAL, "tune.h2.fe.max-total-streams",   h2_parse_max_total_streams      },
	{ CFG_GLOBAL, "tune.h2.fe.rxbuf",               h2_parse_rxbuf                  },
	{ CFG_GLOBAL, "tune.h2.header-table-size",      h2_parse_header_table_size      },
	{ CFG_GLOBAL, "tune.h2.initial-window-size",    h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ CFG_GLOBAL, "tune.h2.max-frame-size",         h2_parse_max_frame_size         },
	{ CFG_GLOBAL, "tune.h2.zero-copy-fwd-send",     h2_parse_zero_copy_fwd_snd },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* initialize internal structs after the config is parsed.
 * Returns zero on success, non-zero on error.
 */
static int init_h2()
{
	uint max_bufs;
	uint rx_bufs;

	pool_head_hpack_tbl = create_pool("hpack_tbl",
	                                  h2_settings_header_table_size,
	                                  MEM_F_SHARED|MEM_F_EXACT);
	if (!pool_head_hpack_tbl) {
		ha_alert("failed to allocate hpack_tbl memory pool\n");
		return (ERR_ALERT | ERR_FATAL);
	}

	if (!h2_settings_initial_window_size)
		h2_settings_initial_window_size =
			MAX(16384, global.tune.bufsize - sizeof(struct htx) - sizeof(struct htx_blk));

	max_bufs = h2_fe_settings_max_concurrent_streams ?
	           h2_fe_settings_max_concurrent_streams :
	           h2_settings_max_concurrent_streams;

	max_bufs = MAX(max_bufs,
	               h2_be_settings_max_concurrent_streams ?
	               h2_be_settings_max_concurrent_streams :
	               h2_settings_max_concurrent_streams);

	/* check for forced rxbufs */
	rx_bufs = MAX(h2_be_rxbuf, h2_fe_rxbuf);
	rx_bufs = (rx_bufs + global.tune.bufsize - 9 - 1) / (global.tune.bufsize - 9);
	max_bufs = MAX(max_bufs, rx_bufs);

	pool_head_h2_rx_bufs = create_pool("h2_rx_bufs",
	                                   (max_bufs + 1) * sizeof(struct bl_elem),
	                                   MEM_F_SHARED|MEM_F_EXACT);
	if (!pool_head_h2_rx_bufs) {
		ha_alert("failed to allocate h2_rx_bufs memory pool\n");
		return (ERR_ALERT | ERR_FATAL);
	}
	return ERR_NONE;
}

REGISTER_POST_CHECK(init_h2);
