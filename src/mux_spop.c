/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <import/ist.h>
#include <import/eb32tree.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/list.h>
#include <haproxy/mux_spop-t.h>
#include <haproxy/net_helper.h>
#include <haproxy/proxy.h>
#include <haproxy/spoe.h>
#include <haproxy/session.h>
#include <haproxy/stconn.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>

/* 32 buffers: one for the ring's root, rest for the mbuf itself */
#define SPOP_C_MBUF_CNT 32


/* SPOP connection descriptor */
struct spop_conn {
	struct connection *conn;

	enum spop_conn_st state;             /* SPOP connection state */
	enum spop_error errcode;             /* SPOP error code (SPOP_ERR_*) */
	uint32_t streams_limit;              /* maximum number of concurrent streams the peer supports */
	uint32_t max_id;                     /* highest ID known on this connection, <0 before HELLO handshake */
	uint32_t flags;                      /* Connection flags: SPOP_CF_* */

	uint32_t dsi;                        /* dmux stream ID (<0 = idle ) */
	uint32_t dfi;                        /* dmux frame ID (if dsi >= 0) */
	uint32_t dfl;                        /* demux frame length (if dsi >= 0) */
	uint32_t dff;                        /* demux frame flags */
	uint8_t  dft;                        /* demux frame type (if dsi >= 0) */

	struct buffer dbuf;                  /* demux buffer */
	struct buffer mbuf[SPOP_C_MBUF_CNT]; /* mux buffers (ring) */

	int timeout;                         /* idle timeout duration in ticks */
	int shut_timeout;                    /* idle timeout duration in ticks after shutdown */

	unsigned int max_frame_size;         /* the negotiated max-frame-size value */
	unsigned int nb_streams;             /* number of streams in the tree */
	unsigned int nb_sc;                  /* number of attached stream connectors */
	unsigned int nb_reserved;            /* number of reserved streams */
	unsigned int stream_cnt;             /* total number of streams seen */

	struct proxy *proxy;                 /* the proxy this connection was created for */
	struct spoe_agent *agent;            /* SPOE agent used by this mux */
	struct task *task;                   /* timeout management task */
	struct eb_root streams_by_id;        /* all active streams by their ID */

	struct list send_list;               /* list of blocked streams requesting to send */

	struct buffer_wait buf_wait;         /* Wait list for buffer allocation */
	struct wait_event wait_event;        /* To be used if we're waiting for I/Os */
};

/* SPOP stream descriptor */
struct spop_strm {
	struct sedesc *sd;
	struct session *sess;
	struct spop_conn *spop_conn;

	int32_t id;                   /* stream ID */
	uint32_t fid;                 /* frame ID */

	uint32_t flags;               /* Connection flags: SPOP_SF_* */
	enum spop_error errcode;      /* SPOP error code (SPOP_ERR_*) */
	enum spop_strm_st state;      /* SPOP stream state */

	struct buffer rxbuf;          /* receive buffer, always valid (buf_empty or real buffer) */

	struct eb32_node by_id;       /* place in spop_conn's streams_by_id */
	struct wait_event *subs;      /* Address of the wait_event the stream connector associated is waiting on */
	struct list list;        /* To be used when adding in spop_conn->send_list */
};

/* descriptor for an SPOP frame header */
struct spop_frame_header {
        uint32_t len;       /* length, host order */
        uint32_t flags;     /* frame flags */
        uint64_t sid;       /* stream id, host order */
        uint64_t fid;       /* frame id, host order */
        uint8_t  type;      /* frame type */
};

/* trace source and events */
static void spop_trace(enum trace_level level, uint64_t mask,
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   spop_conn - internal SPOP connection
 *   spop_strm - internal SPOP stream
 *   strm  - application layer
 *   rx    - data receipt
 *   tx    - data transmission
 */
static const struct trace_event spop_trace_events[] = {
#define           SPOP_EV_SPOP_CONN_NEW     (1ULL <<  0)
	{ .mask = SPOP_EV_SPOP_CONN_NEW,    .name = "spop_conn_new",  .desc = "new SPOP connection" },
#define           SPOP_EV_SPOP_CONN_RECV    (1ULL <<  1)
	{ .mask = SPOP_EV_SPOP_CONN_RECV,   .name = "spop_conn_recv", .desc = "Rx on SPOP connection" },
#define           SPOP_EV_SPOP_CONN_SEND    (1ULL <<  2)
	{ .mask = SPOP_EV_SPOP_CONN_SEND,   .name = "spop_conn_send", .desc = "Tx on SPOP connection" },
#define           SPOP_EV_SPOP_CONN_BLK     (1ULL <<  3)
	{ .mask = SPOP_EV_SPOP_CONN_BLK,    .name = "spop_conn_blk",  .desc = "SPOP connection blocked" },
#define           SPOP_EV_SPOP_CONN_WAKE    (1ULL <<  4)
	{ .mask = SPOP_EV_SPOP_CONN_WAKE,   .name = "spop_conn_wake", .desc = "SPOP connection woken up" },
#define           SPOP_EV_SPOP_CONN_END     (1ULL <<  5)
	{ .mask = SPOP_EV_SPOP_CONN_END,    .name = "spop_conn_end",  .desc = "SPOP connection terminated" },
#define           SPOP_EV_SPOP_CONN_ERR     (1ULL <<  6)
	{ .mask = SPOP_EV_SPOP_CONN_ERR,    .name = "spop_conn_err",  .desc = "error on SPOP connection" },

#define           SPOP_EV_RX_FHDR           (1ULL <<  7)
	{ .mask = SPOP_EV_RX_FHDR,          .name = "rx_fhdr",        .desc = "SPOP frame header received" },
#define           SPOP_EV_RX_FRAME          (1ULL <<  8)
	{ .mask = SPOP_EV_RX_FRAME,         .name = "rx_frame",       .desc = "receipt of any SPOP frame" },
#define           SPOP_EV_RX_EOI            (1ULL <<  9)
	{ .mask = SPOP_EV_RX_EOI,           .name = "rx_eoi",         .desc = "receipt of end of SPOP input" },
#define           SPOP_EV_RX_HELLO          (1ULL << 10)
	{ .mask = SPOP_EV_RX_HELLO,         .name = "rx_hello",       .desc = "receipt of SPOP AGENT HELLO frame" },
#define           SPOP_EV_RX_ACK            (1ULL << 11)
	{ .mask = SPOP_EV_RX_ACK,           .name = "rx_ack",         .desc = "receipt of SPOP AGENT ACK frame" },
#define           SPOP_EV_RX_DISCO          (1ULL << 12)
	{ .mask = SPOP_EV_RX_DISCO,         .name = "rx_disconnect",  .desc = "receipt of SPOP AGENT DISCONNECT frame" },

#define           SPOP_EV_TX_FRAME          (1ULL << 13)
	{ .mask = SPOP_EV_TX_FRAME,         .name = "tx_frame",       .desc = "transmission of any SPOP frame" },
#define           SPOP_EV_TX_EOI            (1ULL << 14)
	{ .mask = SPOP_EV_TX_EOI,           .name = "tx_eoi",         .desc = "transmission of SPOP end of input" },
#define           SPOP_EV_TX_HELLO          (1ULL << 15)
	{ .mask = SPOP_EV_TX_HELLO,         .name = "tx_hello",       .desc = "transmission of SPOP HAPROXY HELLO frame" },
#define           SPOP_EV_TX_NOTIFY         (1ULL << 16)
	{ .mask = SPOP_EV_TX_NOTIFY,        .name = "tx_notify",      .desc = "transmission of SPOP HAPROXY NOTIFY frame" },
#define           SPOP_EV_TX_DISCO          (1ULL << 17)
	{ .mask = SPOP_EV_TX_DISCO,         .name = "tx_disconnect",  .desc = "transmission of SPOP HAPROXY DISCONNECT frame" },

#define           SPOP_EV_SPOP_STRM_NEW     (1ULL << 18)
	{ .mask = SPOP_EV_SPOP_STRM_NEW,    .name = "spop_strm_new",  .desc = "new SPOP stream" },
#define           SPOP_EV_SPOP_STRM_BLK     (1ULL << 19)
	{ .mask = SPOP_EV_SPOP_STRM_BLK,    .name = "spop_strm_blk",  .desc = "SPOP stream blocked" },
#define           SPOP_EV_SPOP_STRM_END     (1ULL << 20)
	{ .mask = SPOP_EV_SPOP_STRM_END,    .name = "spop_strm_end",  .desc = "SPOP stream terminated" },
#define           SPOP_EV_SPOP_STRM_ERR     (1ULL << 21)
	{ .mask = SPOP_EV_SPOP_STRM_ERR,    .name = "spop_strm_err",  .desc = "error on SPOP stream" },

#define           SPOP_EV_STRM_NEW      (1ULL << 22)
	{ .mask = SPOP_EV_STRM_NEW,     .name = "strm_new",           .desc = "app-layer stream creation" },
#define           SPOP_EV_STRM_RECV     (1ULL << 23)
	{ .mask = SPOP_EV_STRM_RECV,    .name = "strm_recv",          .desc = "receiving data for stream" },
#define           SPOP_EV_STRM_SEND     (1ULL << 24)
	{ .mask = SPOP_EV_STRM_SEND,    .name = "strm_send",          .desc = "sending data for stream" },
#define           SPOP_EV_STRM_FULL     (1ULL << 25)
	{ .mask = SPOP_EV_STRM_FULL,    .name = "strm_full",          .desc = "stream buffer full" },
#define           SPOP_EV_STRM_WAKE     (1ULL << 26)
	{ .mask = SPOP_EV_STRM_WAKE,    .name = "strm_wake",          .desc = "stream woken up" },
#define           SPOP_EV_STRM_SHUT     (1ULL << 27)
	{ .mask = SPOP_EV_STRM_SHUT,    .name = "strm_shut",          .desc = "stream shutdown" },
#define           SPOP_EV_STRM_END      (1ULL << 28)
	{ .mask = SPOP_EV_STRM_END,     .name = "strm_end",           .desc = "detaching app-layer stream" },
#define           SPOP_EV_STRM_ERR      (1ULL << 29)
	{ .mask = SPOP_EV_STRM_ERR,     .name = "strm_err",           .desc = "stream error" },

	{ }
};

static const struct name_desc spop_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="spop_strm", .desc="SPOP stream" },
	/* arg3 */ { },
	/* arg4 */ { }
};


static const struct name_desc spop_trace_decoding[] = {
#define SPOP_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define SPOP_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only spop_conn/spop_strm state and flags, no real decoding" },
#define SPOP_VERB_SIMPLE   3
	{ .name="simple",   .desc="add request/response status line or htx info when available" },
#define SPOP_VERB_ADVANCED 4
	{ .name="advanced", .desc="add header fields or record decoding when available" },
#define SPOP_VERB_COMPLETE 5
	{ .name="complete", .desc="add full data dump when available" },
	{ /* end */ }
};

static struct trace_source trace_spop __read_mostly = {
	.name = IST("spop"),
	.desc = "SPOP multiplexer",
	.arg_def = TRC_ARG1_CONN,  // TRACE()'s first argument is always a connection
	.default_cb = spop_trace,
	.known_events = spop_trace_events,
	.lockon_args = spop_trace_lockon_args,
	.decoding = spop_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_spop
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* SPOP connection and stream pools */
DECLARE_STATIC_POOL(pool_head_spop_conn, "spop_conn", sizeof(struct spop_conn));
DECLARE_STATIC_POOL(pool_head_spop_strm, "spop_strm", sizeof(struct spop_strm));


const struct ist spop_err_reasons[SPOP_ERR_ENTRIES] = {
	[SPOP_ERR_NONE]               = IST("normal"),
	[SPOP_ERR_IO]                 = IST("I/O error"),
	[SPOP_ERR_TOUT]               = IST("a timeout occurred"),
	[SPOP_ERR_TOO_BIG]            = IST("frame is too big"),
	[SPOP_ERR_INVALID]            = IST("invalid frame received"),
	[SPOP_ERR_NO_VSN]             = IST("version value not found"),
	[SPOP_ERR_NO_FRAME_SIZE]      = IST("max-frame-size value not found"),
	[SPOP_ERR_NO_CAP]             = IST("capabilities value not found"),
	[SPOP_ERR_BAD_VSN]            = IST("unsupported version"),
	[SPOP_ERR_BAD_FRAME_SIZE]     = IST("max-frame-size too big or too small"),
	[SPOP_ERR_FRAG_NOT_SUPPORTED] = IST("fragmentation not supported"),
	[SPOP_ERR_INTERLACED_FRAMES]  = IST("invalid interlaced frames"),
	[SPOP_ERR_FRAMEID_NOTFOUND]   = IST("frame-id not found"),
	[SPOP_ERR_RES]                = IST("resource allocation error"),
	[SPOP_ERR_UNKNOWN]            = IST("an unknown error occurred"),
};


/* Helper to get static string length, excluding the terminating null byte */
#define SPOP_SLEN(str) (sizeof(str)-1)

/* Predefined key used in HELLO/DISCONNECT frames */
#define SPOP_SUPPORTED_VERSIONS_KEY     "supported-versions"
#define SPOP_VERSION_KEY                "version"
#define SPOP_MAX_FRAME_SIZE_KEY         "max-frame-size"
#define SPOP_CAPABILITIES_KEY           "capabilities"
#define SPOP_ENGINE_ID_KEY              "engine-id"
#define SPOP_HEALTHCHECK_KEY            "healthcheck"
#define SPOP_STATUS_CODE_KEY            "status-code"
#define SPOP_MSG_KEY                    "message"

/* All supported versions */
const struct spop_version spop_supported_versions[] = {
	/* 1.0 is now unsupported because of a bug about frame's flags*/
	{"2.0", 2000, 2000},
	{NULL,  0, 0}
};

/* Comma-separated list of supported versions */
#define SPOP_SUPPORTED_VERSIONS_VAL  "2.0"

static struct task *spop_timeout_task(struct task *t, void *context, unsigned int state);
static int spop_process(struct spop_conn *spop_conn);
static struct task *spop_io_cb(struct task *t, void *ctx, unsigned int state);
static inline struct spop_strm *spop_conn_st_by_id(struct spop_conn *spop_conn, int id);
static struct spop_strm *spop_stconn_new(struct spop_conn *spop_conn, struct stconn *sc, struct session *sess);
static void spop_strm_notify_recv(struct spop_strm *spop_strm);
static void spop_strm_notify_send(struct spop_strm *spop_strm);
static void spop_strm_alert(struct spop_strm *spop_strm);
static inline void spop_remove_from_list(struct spop_strm *spop_strm);
static inline void spop_conn_restart_reading(const struct spop_conn *spop_conn, int consider_buffer);

/* a dummy closed endpoint */
static const struct sedesc closed_ep = {
	.sc        = NULL,
	.flags     = SE_FL_DETACHED,
};

/* a dmumy closed stream */
static const struct spop_strm *spop_closed_stream = &(const struct spop_strm){
        .sd        = (struct sedesc *)&closed_ep,
        .spop_conn = NULL,
        .state     = SPOP_SS_CLOSED,
	.flags     = SPOP_SF_NONE, // TODO ?
        .id        = 0,
};

/* a dummy idle stream for use with any unknown stream */
static const struct spop_strm *spop_unknown_stream = &(const struct spop_strm){
	.sd        = (struct sedesc*)&closed_ep,
	.spop_conn = NULL,
	.state     = SPOP_SS_IDLE,
	.flags     = SPOP_SF_NONE,
	.id        = 0,
};

/* returns the stconn associated to the stream */
static forceinline struct stconn *spop_strm_sc(const struct spop_strm *spop_strm)
{
	return spop_strm->sd->sc;
}

static inline struct sedesc *spop_strm_opposite_sd(struct spop_strm *spop_strm)
{
	return se_opposite(spop_strm->sd);
}

static inline void spop_trace_buf(const struct buffer *buf, size_t ofs, size_t len)
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

/* the SPOP traces always expect that arg1, if non-null, is of type connection
 * (from which we can derive spop_conn), that arg2, if non-null, is of type spop_strm,
 * and that arg3, if non-null, is a buffer for rx/tx headers.
 */
static void spop_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
		       const struct ist where, const struct ist func,
		       const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	struct spop_conn *spop_conn = conn ? conn->ctx : NULL;
	const struct spop_strm *spop_strm = a2;
	const struct buffer *buf = a3;
	const size_t *val = a4;

	if (!spop_conn)
		spop_conn = (spop_strm ? spop_strm->spop_conn : NULL);

	if (!spop_conn || src->verbosity < SPOP_VERB_CLEAN)
		return;

	if (src->verbosity == SPOP_VERB_CLEAN)
		return;

	/* Display the value to the 4th argument (level > STATE) */
	if (src->level > TRACE_LEVEL_STATE && val)
		chunk_appendf(&trace_buf, " - VAL=%lu", (long)*val);

	/* Display spop_conn info and, if defined, spop_strm info */
	chunk_appendf(&trace_buf, " - spop_conn=%p(%s,0x%08x)", spop_conn, spop_conn_st_to_str(spop_conn->state), spop_conn->flags);
	if (spop_conn->conn)
		chunk_appendf(&trace_buf, " conn=%p(0x%08x)", spop_conn->conn, spop_conn->conn->flags);
	if (spop_conn->errcode)
		chunk_appendf(&trace_buf, " err=%02x", spop_conn->errcode);

	if (spop_strm) {
		if (spop_strm->id <= 0)
			chunk_appendf(&trace_buf, " dsi=%d dfi=%d", spop_conn->dsi, spop_conn->dfi);
		if (spop_strm != spop_closed_stream && spop_strm != spop_unknown_stream) {
			chunk_appendf(&trace_buf, " spop_strm=%p(%d,%s,0x%08x)", spop_strm, spop_strm->id, spop_strm_st_to_str(spop_strm->state), spop_strm->flags);
			if (spop_strm->sd) {
				chunk_appendf(&trace_buf, " sd=%p(0x%08x)", spop_strm->sd, se_fl_get(spop_strm->sd));
				if (spop_strm_sc(spop_strm))
					chunk_appendf(&trace_buf, " sc=%p(0x%08x)", spop_strm_sc(spop_strm), spop_strm_sc(spop_strm)->flags);
			}
			if (spop_strm->errcode)
				chunk_appendf(&trace_buf, " err=%02x", spop_strm->errcode);
		}
	}
	if (src->verbosity == SPOP_VERB_MINIMAL)
		return;

	/* Display mbuf and dbuf info (level > USER & verbosity > SIMPLE) */
	if (src->level > TRACE_LEVEL_USER) {
		if (src->verbosity == SPOP_VERB_COMPLETE ||
		    (src->verbosity == SPOP_VERB_ADVANCED && (mask & (SPOP_EV_SPOP_CONN_RECV|SPOP_EV_RX_FRAME))))
			chunk_appendf(&trace_buf, " dbuf=%u@%p+%u/%u",
				      (unsigned int)b_data(&spop_conn->dbuf), b_orig(&spop_conn->dbuf),
				      (unsigned int)b_head_ofs(&spop_conn->dbuf), (unsigned int)b_size(&spop_conn->dbuf));
		if (src->verbosity == SPOP_VERB_COMPLETE ||
		    (src->verbosity == SPOP_VERB_ADVANCED && (mask & (SPOP_EV_SPOP_CONN_SEND|SPOP_EV_TX_FRAME)))) {
			struct buffer *hmbuf = br_head(spop_conn->mbuf);
			struct buffer *tmbuf = br_tail(spop_conn->mbuf);

			chunk_appendf(&trace_buf, " .mbuf=[%u..%u|%u],h=[%u@%p+%u/%u],t=[%u@%p+%u/%u]",
				      br_head_idx(spop_conn->mbuf), br_tail_idx(spop_conn->mbuf), br_size(spop_conn->mbuf),
				      (unsigned int)b_data(hmbuf), b_orig(hmbuf),
				      (unsigned int)b_head_ofs(hmbuf), (unsigned int)b_size(hmbuf),
				      (unsigned int)b_data(tmbuf), b_orig(tmbuf),
				      (unsigned int)b_head_ofs(tmbuf), (unsigned int)b_size(tmbuf));
		}

		if (spop_strm && (src->verbosity == SPOP_VERB_COMPLETE ||
			      (src->verbosity == SPOP_VERB_ADVANCED && (mask & (SPOP_EV_STRM_RECV)))))
			chunk_appendf(&trace_buf, " rxbuf=%u@%p+%u/%u",
				      (unsigned int)b_data(&spop_strm->rxbuf), b_orig(&spop_strm->rxbuf),
				      (unsigned int)b_head_ofs(&spop_strm->rxbuf), (unsigned int)b_size(&spop_strm->rxbuf));
	}

	/* Display htx info if defined (level > USER) */
	if (src->level > TRACE_LEVEL_USER && buf) {
		int full = 0, max = 3000, chunk = 1024;

		/* Full info (level > STATE && verbosity > SIMPLE) */
		if (src->level > TRACE_LEVEL_STATE) {
			if (src->verbosity == SPOP_VERB_COMPLETE)
				full = 1;
			else if (src->verbosity == SPOP_VERB_ADVANCED) {
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
				spop_trace_buf(buf, 0, b_data(buf));
			else {
				spop_trace_buf(buf, 0, chunk);
				chunk_memcat(&trace_buf, "  ...\n", 6);
				spop_trace_buf(buf, b_data(buf) - chunk, chunk);
			}
		}
	}
}


/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/
/* Tries to grab a buffer and to re-enable processing on mux <target>. The
 * spop_conn flags are used to figure what buffer was requested. It returns 1 if
 * the allocation succeeds, in which case the connection is woken up, or 0 if
 * it's impossible to wake up and we prefer to be woken up later.
 */
static int spop_buf_available(void *target)
{
	struct spop_conn *spop_conn = target;
	struct spop_strm *spop_strm;

	if ((spop_conn->flags & SPOP_CF_DEM_DALLOC) && b_alloc(&spop_conn->dbuf, DB_MUX_RX)) {
		TRACE_STATE("unblocking spop_conn, dbuf allocated", SPOP_EV_SPOP_CONN_RECV|SPOP_EV_SPOP_CONN_BLK|SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);
		spop_conn->flags &= ~SPOP_CF_DEM_DALLOC;
		spop_conn_restart_reading(spop_conn, 1);
		return 1;
	}

	if ((spop_conn->flags & SPOP_CF_MUX_MALLOC) && b_alloc(br_tail(spop_conn->mbuf), DB_MUX_TX)) {
		TRACE_STATE("unblocking spop_conn, mbuf allocated", SPOP_EV_SPOP_CONN_SEND|SPOP_EV_SPOP_CONN_BLK|SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);
		spop_conn->flags &= ~SPOP_CF_MUX_MALLOC;
		if (spop_conn->flags & SPOP_CF_DEM_MROOM) {
			spop_conn->flags &= ~SPOP_CF_DEM_MROOM;
			spop_conn_restart_reading(spop_conn, 1);
		}
		return 1;
	}

	if ((spop_conn->flags & SPOP_CF_DEM_SALLOC) &&
	    (spop_strm = spop_conn_st_by_id(spop_conn, spop_conn->dsi)) && spop_strm_sc(spop_strm) &&
	    b_alloc(&spop_strm->rxbuf, DB_SE_RX)) {
		TRACE_STATE("unblocking spop_strm, rxbuf allocated", SPOP_EV_STRM_RECV|SPOP_EV_SPOP_STRM_BLK|SPOP_EV_STRM_WAKE, spop_conn->conn, spop_strm);
		spop_conn->flags &= ~SPOP_CF_DEM_SALLOC;
		spop_conn_restart_reading(spop_conn, 1);
		return 1;
	}

	return 0;
}

static inline struct buffer *spop_get_buf(struct spop_conn *spop_conn, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&spop_conn->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr, DB_MUX_RX)) == NULL)) {
		b_queue(DB_MUX_RX, &spop_conn->buf_wait, spop_conn, spop_buf_available);
	}
	return buf;
}

static inline void spop_release_buf(struct spop_conn *spop_conn, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(NULL, 1);
	}
}

static inline void spop_release_mbuf(struct spop_conn *spop_conn)
{
	struct buffer *buf;
	unsigned int count = 0;

	while (b_size(buf = br_head_pick(spop_conn->mbuf))) {
		b_free(buf);
		count++;
	}

	spop_conn->flags &= ~(SPOP_CF_MUX_MFULL | SPOP_CF_DEM_MROOM);

	if (count)
		offer_buffers(NULL, count);
}

/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/
/* Indicates whether or not the we may call the spop_recv() function to attempt
 * to receive data into the buffer and/or demux pending data. The condition is
 * a bit complex due to some API limits for now. The rules are the following :
 *   - if an error or a shutdown was detected on the connection and the buffer
 *     is empty, we must not attempt to receive
 *   - if the demux buf failed to be allocated, we must not try to receive and
 *     we know there is nothing pending
 *   - if no flag indicates a blocking condition, we may attempt to receive,
 *     regardless of whether the demux buffer is full or not, so that only
 *     de demux part decides whether or not to block. This is needed because
 *     the connection API indeed prevents us from re-enabling receipt that is
 *     already enabled in a polled state, so we must always immediately stop
 *     as soon as the demux can't proceed so as never to hit an end of read
 *     with data pending in the buffers.
 *   - otherwise must may not attempt
 */
static inline int spop_recv_allowed(const struct spop_conn *spop_conn)
{
	if (b_data(&spop_conn->dbuf) == 0 &&
	    ((spop_conn->flags & (SPOP_CF_RCVD_SHUT|SPOP_CF_ERROR)) || spop_conn->state == SPOP_CS_CLOSED))
		return 0;

	if (!(spop_conn->flags & SPOP_CF_DEM_DALLOC) &&
	    !(spop_conn->flags & SPOP_CF_DEM_BLOCK_ANY))
		return 1;

	return 0;
}

/* Restarts reading on the connection if it was not enabled */
static inline void spop_conn_restart_reading(const struct spop_conn *spop_conn, int consider_buffer)
{
	if (!spop_recv_allowed(spop_conn))
		return;
	if ((!consider_buffer || !b_data(&spop_conn->dbuf)) &&
	    (spop_conn->wait_event.events & SUB_RETRY_RECV))
		return;
	tasklet_wakeup(spop_conn->wait_event.tasklet);
}

/* Returns the number of allocatable outgoing streams for the connection taking
 * the number reserved streams into account.
 */
static inline int spop_streams_left(const struct spop_conn *spop_conn)
{
	int ret;

	ret = (unsigned int)(0x7FFFFFFF - spop_conn->max_id) - spop_conn->nb_reserved - 1;
	if (ret < 0)
		ret = 0;
	return ret;
}

/* Returns the number of streams in use on a connection to figure if it's
 * idle or not. We check nb_sc and not nb_streams as the caller will want
 * to know if it was the last one after a detach().
 */
static int spop_used_streams(struct connection *conn)
{
	struct spop_conn *spop_conn = conn->ctx;

	return spop_conn->nb_sc;
}

/* Returns the number of concurrent streams available on the connection */
static int spop_avail_streams(struct connection *conn)
{
	struct server *srv = objt_server(conn->target);
	struct spop_conn *spop_conn = conn->ctx;
	int ret1, ret2;

	/* Don't open new stream if the connection is closed */
	if (spop_conn->state == SPOP_CS_CLOSED)
		return 0;

	/* May be negative if this setting has changed */
	ret1 = (spop_conn->streams_limit - spop_conn->nb_streams);

	/* we must also consider the limit imposed by stream IDs */
	ret2 = spop_streams_left(spop_conn);
	ret1 = MIN(ret1, ret2);
	if (ret1 > 0 && srv && srv->max_reuse >= 0) {
		ret2 = ((spop_conn->stream_cnt <= srv->max_reuse) ? srv->max_reuse - spop_conn->stream_cnt + 1: 0);
		ret1 = MIN(ret1, ret2);
	}
	return ret1;
}

/* Initializes the mux once it's attached. Only outgoing connections are
 * supported. So the context is already initialized before installing the
 * mux. <input> is always used as Input buffer and may contain data. It is the
 * caller responsibility to not reuse it anymore. Returns < 0 on error.
 */
static int spop_init(struct connection *conn, struct proxy *px, struct session *sess,
		     struct buffer *input)
{
	struct spop_conn *spop_conn;
	struct spop_strm *spop_strm;
	struct sedesc *sdo = NULL;
	struct task *t = NULL;
	void *conn_ctx = conn->ctx;

	TRACE_ENTER(SPOP_EV_SPOP_CONN_NEW);

	spop_conn = pool_alloc(pool_head_spop_conn);
	if (!spop_conn) {
		TRACE_ERROR("spop_conn allocation failure", SPOP_EV_SPOP_CONN_NEW|SPOP_EV_SPOP_CONN_END|SPOP_EV_SPOP_CONN_ERR);
		goto fail_conn;
	}

	spop_conn->shut_timeout = spop_conn->timeout = px->timeout.server;
	if (tick_isset(px->timeout.serverfin))
		spop_conn->shut_timeout = px->timeout.serverfin;
	spop_conn->flags = SPOP_CF_NONE;

	spop_conn->proxy = px;
	spop_conn->agent = NULL;
	spop_conn->task = NULL;
	if (tick_isset(spop_conn->timeout)) {
		t = task_new_here();
		if (!t) {
			TRACE_ERROR("spop_conn task allocation failure", SPOP_EV_SPOP_CONN_NEW|SPOP_EV_SPOP_CONN_END|SPOP_EV_SPOP_CONN_ERR);
			goto fail;
		}

		spop_conn->task = t;
		t->process = spop_timeout_task;
		t->context = spop_conn;
		t->expire = tick_add(now_ms, spop_conn->timeout);
	}

	spop_conn->wait_event.tasklet = tasklet_new();
	if (!spop_conn->wait_event.tasklet)
		goto fail;
	spop_conn->wait_event.tasklet->process = spop_io_cb;
	spop_conn->wait_event.tasklet->context = spop_conn;
	spop_conn->wait_event.events = 0;

	/* Initialise the context. */
	spop_conn->state = SPOP_CS_HA_HELLO;
	spop_conn->errcode = SPOP_ERR_NONE;
	spop_conn->conn = conn;
	spop_conn->max_frame_size = SPOP_MAX_FRAME_SIZE;
	spop_conn->streams_limit = 1;
	spop_conn->max_id = -1;
	spop_conn->nb_streams = 0;
	spop_conn->nb_sc = 0;
	spop_conn->nb_reserved = 0;
	spop_conn->stream_cnt = 0;

	spop_conn->dbuf = *input;
	spop_conn->dsi = -1;

	br_init(spop_conn->mbuf, sizeof(spop_conn->mbuf) / sizeof(spop_conn->mbuf[0]));
	spop_conn->streams_by_id = EB_ROOT;
	LIST_INIT(&spop_conn->send_list);
	LIST_INIT(&spop_conn->buf_wait.list);

	conn->ctx = spop_conn;

	if (t)
		task_queue(t);

	/* FIXME: this is temporary, for outgoing connections we need to
	 * immediately allocate a stream until the code is modified so that the
	 * caller calls ->attach(). For now the outgoing sc is stored as
	 * conn->ctx by the caller and saved in conn_ctx.
	 */
	spop_strm = spop_stconn_new(spop_conn, conn_ctx, sess);
	if (!spop_strm)
		goto fail;

	/* Retrieve the SPOE agent attached to the opposite endpoint. Only
	 * undefined when there is no opposite endpoint (healthcheck)
	 */
	sdo = spop_strm_opposite_sd(spop_strm);
	if (sdo) {
		spop_conn->agent = spoe_appctx_agent(sc_appctx(sdo->sc));
		spop_conn->max_frame_size = spop_conn->agent->max_frame_size;
		if (spop_conn->agent->flags & SPOE_FL_PIPELINING)
			spop_conn->streams_limit = 20;
		BUG_ON(!spop_conn->agent);
	}

	/* Repare to read something */
	spop_conn_restart_reading(spop_conn, 1);
	TRACE_LEAVE(SPOP_EV_SPOP_CONN_NEW, conn);
	return 0;

  fail:
	task_destroy(t);
	tasklet_free(spop_conn->wait_event.tasklet);
	pool_free(pool_head_spop_conn, spop_conn);
  fail_conn:
	conn->ctx = conn_ctx; // restore saved ctx
	TRACE_DEVEL("leaving in error", SPOP_EV_SPOP_CONN_NEW|SPOP_EV_SPOP_CONN_END|SPOP_EV_SPOP_CONN_ERR);
	return -1;
}

/* Release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void spop_release(struct spop_conn *spop_conn)
{
	struct connection *conn = spop_conn->conn;

	TRACE_POINT(SPOP_EV_SPOP_CONN_END);

	b_dequeue(&spop_conn->buf_wait);

	spop_release_buf(spop_conn, &spop_conn->dbuf);
	spop_release_mbuf(spop_conn);

	if (spop_conn->task) {
		spop_conn->task->context = NULL;
		task_wakeup(spop_conn->task, TASK_WOKEN_OTHER);
		spop_conn->task = NULL;
	}
	tasklet_free(spop_conn->wait_event.tasklet);
	if (conn && spop_conn->wait_event.events != 0)
		conn->xprt->unsubscribe(conn, conn->xprt_ctx, spop_conn->wait_event.events,
					&spop_conn->wait_event);

	pool_free(pool_head_spop_conn, spop_conn);

	if (conn) {
		conn->mux = NULL;
		conn->ctx = NULL;
		TRACE_DEVEL("freeing conn", SPOP_EV_SPOP_CONN_END, conn);

		conn_stop_tracking(conn);
		conn_full_close(conn);
		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}
}


/* Returns the next allocatable outgoing stream ID for the SPOP connection, or
 * -1 if no more is allocatable.
 */
static inline int32_t spop_conn_get_next_sid(const struct spop_conn *spop_conn)
{
	int32_t id = (spop_conn->max_id + 1) | 1;

	if ((id & 0x80000000U))
		id = -1;
	return id;
}

/* Returns the stream associated with id <id> or NULL if not found */
static inline struct spop_strm *spop_conn_st_by_id(struct spop_conn *spop_conn, int id)
{
	struct eb32_node *node;

	if (id == 0)
		return (struct spop_strm *)spop_closed_stream;

	if (id > spop_conn->max_id)
		return (struct spop_strm *)spop_unknown_stream;

	node = eb32_lookup(&spop_conn->streams_by_id, id);
	if (!node)
		return (struct spop_strm *)spop_unknown_stream;
	return container_of(node, struct spop_strm, by_id);
}

/* Detect a pending read0 for a SPOP connection. It happens if a read0 was
 * already reported on a previous xprt->rcvbuf() AND a frame parser failed
 * to parse pending data, confirming no more progress is possible because
 * we're facing a truncated frame. The function returns 1 to report a read0
 * or 0 otherwise.
 */
static int spop_conn_read0_pending(struct spop_conn *spop_conn)
{
	return !!(spop_conn->flags & SPOP_CF_END_REACHED);
}

/* returns true if the connection is allowed to expire, false otherwise. A
 * connection may expire when it has no attached streams. As long as streams
 * are attached, the application layer is responsible for timeout management,
 * and each layer will detach when it doesn't want to wait anymore. When the
 * last one leaves, the connection must take over timeout management.
 */
static inline int spop_conn_may_expire(const struct spop_conn *spop_conn)
{
	return !spop_conn->nb_sc;
}

// TODO: spop_conn_max_concurrent_streams() : default 20 but add a agent parameter !

/* Returns true if the SPOP connection must be release */
static inline int spop_conn_is_dead(struct spop_conn *spop_conn)
{
	if (eb_is_empty(&spop_conn->streams_by_id) &&                   /* don't close if streams exist */
	    ((spop_conn->flags & SPOP_CF_ERROR) ||                      /* errors close immediately */
	     (spop_conn->flags & SPOP_CF_ERR_PENDING && spop_conn->state < SPOP_CS_FRAME_H) || /* early error during connect */
	     (spop_conn->state == SPOP_CS_CLOSED && !spop_conn->task) ||/* a timeout stroke earlier */
	     (!(spop_conn->conn->owner)) ||                             /* Nobody's left to take care of the connection, drop it now */
	     (!br_data(spop_conn->mbuf) &&                              /* mux buffer empty, also process clean events below */
	      (spop_conn->flags & SPOP_CF_RCVD_SHUT))))
	      return 1;
	return 0;
}

/* update spop_conn timeout if needed */
static void spop_conn_update_timeout(struct spop_conn *spop_conn)
{
	int is_idle_conn = 0;

	if (!spop_conn->task)
		goto leave;

	TRACE_ENTER(SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);

	if (spop_conn_may_expire(spop_conn)) {
		/* no more streams attached */
		if (br_data(spop_conn->mbuf)) {
			/* pending output data: always the regular data timeout */
			spop_conn->task->expire = tick_add_ifset(now_ms, spop_conn->timeout);
		}
		else {
			if (spop_conn->flags & (SPOP_CF_DISCO_SENT|SPOP_CF_DISCO_FAILED)) {
				/* DISCONNECT sent (or failed), closing in progress */
				int exp = tick_add_ifset(now_ms, spop_conn->shut_timeout);

				spop_conn->task->expire = tick_first(spop_conn->task->expire, exp);
				is_idle_conn = 1;
			}

			/* if a timeout above was not set, fall back to the default one */
			if (!tick_isset(spop_conn->task->expire))
				spop_conn->task->expire = tick_add_ifset(now_ms, spop_conn->timeout);
		}

		if ((spop_conn->proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) &&
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
				if (tick_isset(spop_conn->task->expire) &&
				    tick_is_le(global.close_spread_end, spop_conn->task->expire)) {
					/* Set an expire value shorter than the current value
					 * because the close spread window end comes earlier.
					 */
					spop_conn->task->expire = tick_add(now_ms, statistical_prng_range(remaining_window));
				}
			}
			else {
				/* We are past the soft close window end, wake the timeout
				 * task up immediately.
				 */
				task_wakeup(spop_conn->task, TASK_WOKEN_TIMER);
			}
		}
	}
	else
		spop_conn->task->expire = TICK_ETERNITY;
	task_queue(spop_conn->task);
	TRACE_LEAVE(SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn, 0, 0, (size_t[]){spop_conn->task->expire});
 leave:
	return;
}

/********************************************************/
/* functions below are for the SPOP protocol processing */
/********************************************************/
/* Marks an error on the connection. Before HELLO frame are sent, we must not send
 * a DISCONNECT frame, so we set SPOP_CF_DISCO_FAILED to make sure it will not
 * even try.. */
static inline void spop_conn_error(struct spop_conn *spop_conn, enum spop_error err)
{
	TRACE_POINT(SPOP_EV_SPOP_CONN_ERR, spop_conn->conn, 0, 0, (size_t[]){err});
	spop_conn->errcode = err;
	if (spop_conn->state == SPOP_CS_HA_HELLO)
		spop_conn->flags |= SPOP_CF_DISCO_FAILED;
	spop_conn->state = SPOP_CS_ERROR;
}

/* Marks an error on the stream */
static inline void spop_strm_error(struct spop_strm *spop_strm, enum spop_error err)
{
	if (spop_strm->id && spop_strm->state != SPOP_SS_ERROR) {
		TRACE_POINT(SPOP_EV_SPOP_STRM_ERR, spop_strm->spop_conn->conn, spop_strm);
		spop_strm->errcode = err;
		if (spop_strm->state < SPOP_SS_ERROR) {
			spop_strm->state = SPOP_SS_ERROR;
			TRACE_STATE("switching to ERROR", SPOP_EV_SPOP_STRM_ERR, spop_strm->spop_conn->conn, spop_strm);
		}
		se_fl_set_error(spop_strm->sd);
		if (!spop_strm->sd->abort_info.info) {
                        spop_strm->sd->abort_info.info = (SE_ABRT_SRC_MUX_SPOP << SE_ABRT_SRC_SHIFT);
                        spop_strm->sd->abort_info.code = spop_strm->errcode;
                }
	}
}

/* Attempts to notify the data layer of recv availability */
static void spop_strm_notify_recv(struct spop_strm *spop_strm)
{
	if (spop_strm->subs && (spop_strm->subs->events & SUB_RETRY_RECV)) {
		TRACE_POINT(SPOP_EV_STRM_WAKE, spop_strm->spop_conn->conn, spop_strm);
		tasklet_wakeup(spop_strm->subs->tasklet);
		spop_strm->subs->events &= ~SUB_RETRY_RECV;
		if (!spop_strm->subs->events)
			spop_strm->subs = NULL;
	}
}

/* Attempts to notify the data layer of send availability */
static void spop_strm_notify_send(struct spop_strm *spop_strm)
{
	if (spop_strm->subs && (spop_strm->subs->events & SUB_RETRY_SEND)) {
		TRACE_POINT(SPOP_EV_STRM_WAKE, spop_strm->spop_conn->conn, spop_strm);
		spop_strm->flags |= SPOP_SF_NOTIFIED;
		tasklet_wakeup(spop_strm->subs->tasklet);
		spop_strm->subs->events &= ~SUB_RETRY_SEND;
		if (!spop_strm->subs->events)
			spop_strm->subs = NULL;
	}
}

/* Alerts the data layer, trying to wake it up by all means, following
 * this sequence :
 *   - if the spop stream' data layer is subscribed to recv, then it's woken up
 *     for recv
 *   - if its subscribed to send, then it's woken up for send
 *   - if it was subscribed to neither, its ->wake() callback is called
 * It is safe to call this function with a closed stream which doesn't have a
 * stream connector anymore.
 */
static void spop_strm_alert(struct spop_strm *spop_strm)
{
	TRACE_POINT(SPOP_EV_STRM_WAKE, spop_strm->spop_conn->conn, spop_strm);
	if (spop_strm->subs) {
		spop_strm_notify_recv(spop_strm);
		spop_strm_notify_send(spop_strm);
	}
	else if (spop_strm_sc(spop_strm) && spop_strm_sc(spop_strm)->app_ops->wake != NULL) {
		TRACE_POINT(SPOP_EV_STRM_WAKE, spop_strm->spop_conn->conn, spop_strm);
		spop_strm_sc(spop_strm)->app_ops->wake(spop_strm_sc(spop_strm));
	}
}

/* Writes the 32-bit frame size <len> at address <frame> */
static inline void spop_set_frame_size(void *frame, uint32_t len)
{
        write_n32(frame, len);
}

/* reads <bytes> bytes from buffer <b> starting at relative offset <o> from the
 * current pointer, dealing with wrapping, and stores the result in <dst>. It's
 * the caller's responsibility to verify that there are at least <bytes> bytes
 * available in the buffer's input prior to calling this function. The buffer
 * is assumed not to hold any output data.
 */
static inline __maybe_unused void spop_get_buf_bytes(void *dst, size_t bytes,
                                    const struct buffer *b, int o)
{
        readv_bytes(dst, bytes, b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint16_t spop_get_n16(const struct buffer *b, int o)
{
        return readv_n16(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint32_t spop_get_n32(const struct buffer *b, int o)
{
        return readv_n32(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint64_t spop_get_n64(const struct buffer *b, int o)
{
        return readv_n64(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static __maybe_unused int spop_get_varint(const struct buffer *b, int o, uint64_t *i)
{
	unsigned char *p;
	size_t idx = o;
	int r;

	if (idx > b_data(b))
		return -1;

	p = (unsigned char *)b_peek(b, idx++);
	*i = (uint64_t)*p;
	if (*i < 240)
		return 1;

	r = 4;
	do {
		if (idx > b_data(b))
			return -1;
		p = (unsigned char *)b_peek(b, idx++);
		*i += (uint64_t)*p << r;
		r += 7;
	} while (*p >= 128);

	return (idx - o);
}

/* Peeks an SPOP frame header from offset <o> of buffer <b> into descriptor <h>.
 * Returns zero if some bytes are missing, otherwise the number of read bytes is
 * returned on success. The buffer is assumed not to contain any output data.
 */
static int spop_peek_frame_hdr(const struct buffer *b, int o, struct spop_frame_header *hdr)
{
	int o1, o2;

        if (b_data(b) < o + 11)
                return 0;

	o1 = o;
	hdr->len = spop_get_n32(b, o1);

	hdr->type = *(uint8_t*)b_peek(b, o1+4);
	hdr->flags = spop_get_n32(b, o1+5);
	o1 += 9;

	/* Get the stream-id and the frame-id */
	o2 = spop_get_varint(b, o1, &hdr->sid);
	if (o2 == -1)
		return 0;
	o1 += o2;
	o2 = spop_get_varint(b, o1, &hdr->fid);
	if (o2 == -1)
		return 0;
	o1 += o2;

	/* Remove the header length from the frame length */
	hdr->len -= o1 - (o + 4);
	return (o1 - o);
}

/* skip the <o> bytes corresponding to the frame header possibly parsed by
 * spop_peek_frame_hdr() above.
 */
static inline void spop_skip_frame_hdr(struct buffer *b, size_t o)
{
        b_del(b, o);
}

/* same as above, automatically advances the buffer on success */
static inline int spop_get_frame_hdr(struct buffer *b, struct spop_frame_header *hdr)
{
        int ret;

        ret = spop_peek_frame_hdr(b, 0, hdr);
        if (ret > 0)
                spop_skip_frame_hdr(b, ret);
        return ret;
}


/* Marks a SPOP stream as CLOSED and decrement the number of active streams for
 * its connection if the stream was not yet closed. Please use this exclusively
 * before closing a stream to ensure stream count is well maintained.
 */
static inline void spop_strm_close(struct spop_strm *spop_strm)
{
	if (spop_strm->state != SPOP_SS_CLOSED) {
		TRACE_ENTER(SPOP_EV_SPOP_STRM_END, spop_strm->spop_conn->conn, spop_strm);
		spop_strm->spop_conn->nb_streams--;
		if (!spop_strm->id)
			spop_strm->spop_conn->nb_reserved--;
		if (spop_strm_sc(spop_strm)) {
			if (!se_fl_test(spop_strm->sd, SE_FL_EOS) && !b_data(&spop_strm->rxbuf))
				spop_strm_notify_recv(spop_strm);
		}
		spop_strm->state = SPOP_SS_CLOSED;
		TRACE_STATE("switching to CLOSED", SPOP_EV_SPOP_STRM_END, spop_strm->spop_conn->conn, spop_strm);
		TRACE_LEAVE(SPOP_EV_SPOP_STRM_END, spop_strm->spop_conn->conn, spop_strm);
	}
}

/* Check spop_conn and spop_strm flags to evaluate if EOI/EOS/ERR_PENDING/ERROR flags must
 * be set on the SE.
 */
static inline void spop_strm_propagate_term_flags(struct spop_conn *spop_conn, struct spop_strm *spop_strm)
{
	if (spop_conn_read0_pending(spop_conn) || spop_strm->state == SPOP_SS_CLOSED) {
		se_fl_set(spop_strm->sd, SE_FL_EOS);
		if (spop_conn->errcode)
			se_fl_set(spop_strm->sd, SE_FL_ERROR);
	}
	if (se_fl_test(spop_strm->sd, SE_FL_ERR_PENDING))
		se_fl_set(spop_strm->sd, SE_FL_ERROR);
}


/* Detaches a SPOP stream from its SPOP connection and releases it to the
 * spop_strm pool.
 */
static void spop_strm_destroy(struct spop_strm *spop_strm)
{
	struct connection *conn = spop_strm->spop_conn->conn;

	TRACE_ENTER(SPOP_EV_SPOP_STRM_END, conn, spop_strm);

	spop_strm_close(spop_strm);
	eb32_delete(&spop_strm->by_id);
	if (b_size(&spop_strm->rxbuf)) {
		b_free(&spop_strm->rxbuf);
		offer_buffers(NULL, 1);
	}
	if (spop_strm->subs)
		spop_strm->subs->events = 0;

	/* There's no need to explicitly call unsubscribe here, the only
	 * reference left would be in the spop_conn send_list/fctl_list, and if
	 * we're in it, we're getting out anyway
	 */
	spop_remove_from_list(spop_strm);

	BUG_ON(spop_strm->sd && !se_fl_test(spop_strm->sd, SE_FL_ORPHAN));
	sedesc_free(spop_strm->sd);
	pool_free(pool_head_spop_strm, spop_strm);

	TRACE_LEAVE(SPOP_EV_SPOP_STRM_END, conn);
}

/* Allocates a new stream <id> for connection <spop_conn> and adds it into spop_conn's
 * stream tree. In case of error, nothing is added and NULL is returned. The
 * causes of errors can be any failed memory allocation. The caller is
 * responsible for checking if the connection may support an extra stream prior
 * to calling this function.
 */
static struct spop_strm *spop_strm_new(struct spop_conn *spop_conn, int id)
{
	struct spop_strm *spop_strm;

	TRACE_ENTER(SPOP_EV_SPOP_STRM_NEW, spop_conn->conn);

	spop_strm = pool_alloc(pool_head_spop_strm);
	if (!spop_strm) {
		TRACE_ERROR("spop_strm allocation failure", SPOP_EV_SPOP_STRM_NEW|SPOP_EV_SPOP_STRM_ERR|SPOP_EV_SPOP_STRM_END, spop_conn->conn);
		goto out;
	}

	spop_strm->subs = NULL;
	LIST_INIT(&spop_strm->list);
	spop_strm->spop_conn = spop_conn;
	spop_strm->sd = NULL;
	spop_strm->flags = SPOP_SF_NONE;
	spop_strm->state = SPOP_SS_IDLE;
	spop_strm->rxbuf = BUF_NULL;

	spop_strm->by_id.key = spop_strm->id = id;
	spop_strm->fid = 0;
	if (id > 0) {
		spop_conn->max_id = id;
		spop_strm->state = SPOP_SS_OPEN;
	}
	else
		spop_conn->nb_reserved++;

	eb32_insert(&spop_conn->streams_by_id, &spop_strm->by_id);
	spop_conn->nb_streams++;
	spop_conn->stream_cnt++;

	TRACE_LEAVE(SPOP_EV_SPOP_STRM_NEW, spop_conn->conn, spop_strm);
	return spop_strm;

  out:
	TRACE_DEVEL("leaving in error", SPOP_EV_SPOP_STRM_NEW|SPOP_EV_SPOP_STRM_ERR|SPOP_EV_SPOP_STRM_END, spop_conn->conn);
	return NULL;
}

/* Allocates a new stream associated to stream connector <sc> on the SPOP connection
 * <spop_conn> and returns it, or NULL in case of memory allocation error or if the
 * highest possible stream ID was reached.
 */
static struct spop_strm *spop_stconn_new(struct spop_conn *spop_conn, struct stconn *sc,
					 struct session *sess)
{
	struct spop_strm *spop_strm = NULL;

	TRACE_ENTER(SPOP_EV_SPOP_STRM_NEW, spop_conn->conn);
	if (spop_conn->nb_streams >= spop_conn->streams_limit) {
		TRACE_ERROR("streams_limit reached", SPOP_EV_SPOP_STRM_NEW|SPOP_EV_SPOP_STRM_END|SPOP_EV_SPOP_STRM_ERR, spop_conn->conn);
		goto out;
	}

	if (spop_streams_left(spop_conn) < 1) {
		TRACE_ERROR("!streams_left", SPOP_EV_SPOP_STRM_NEW|SPOP_EV_SPOP_STRM_END|SPOP_EV_SPOP_STRM_ERR, spop_conn->conn);
		goto out;
	}

	/* Defer choosing the ID until we send the first message to create the stream */
	spop_strm = spop_strm_new(spop_conn, 0);
	if (!spop_strm) {
		TRACE_ERROR("fstream allocation failure", SPOP_EV_SPOP_STRM_NEW|SPOP_EV_SPOP_STRM_END|SPOP_EV_SPOP_STRM_ERR, spop_conn->conn);
		goto out;
	}
	if (sc_attach_mux(sc, spop_strm, spop_conn->conn) < 0)
		goto out;
	spop_strm->sd = sc->sedesc;
	spop_strm->sess = sess;
	spop_conn->nb_sc++;
	TRACE_LEAVE(SPOP_EV_SPOP_STRM_NEW, spop_conn->conn, spop_strm);
	return spop_strm;

  out:
	TRACE_DEVEL("leaving on error", SPOP_EV_SPOP_STRM_NEW|SPOP_EV_SPOP_STRM_END|SPOP_EV_SPOP_STRM_ERR, spop_conn->conn);
	spop_strm_destroy(spop_strm);
	return NULL;
}

/* Wakes a specific stream and assign its stream connector some SE_FL_* flags among
 * SE_FL_ERR_PENDING and SE_FL_ERROR if needed. The stream's state is
 * automatically updated accordingly. If the stream is orphaned, it is
 * destroyed.
 */
static void spop_strm_wake_one_stream(struct spop_strm *spop_strm)
{
	struct spop_conn *spop_conn = spop_strm->spop_conn;

	TRACE_ENTER(SPOP_EV_STRM_WAKE, spop_conn->conn, spop_strm);

	if (!spop_strm_sc(spop_strm)) {
		/* this stream was already orphaned */
		spop_strm_destroy(spop_strm);
		TRACE_DEVEL("leaving with no spop_strm", SPOP_EV_STRM_WAKE, spop_conn->conn);
		return;
	}

	if (spop_conn_read0_pending(spop_conn)) {
		if (spop_strm->state == SPOP_SS_OPEN) {
			spop_strm->state = SPOP_SS_HREM;
			TRACE_STATE("switching to HREM", SPOP_EV_STRM_WAKE|SPOP_EV_SPOP_STRM_END, spop_conn->conn, spop_strm);
		}
		else if (spop_strm->state == SPOP_SS_HLOC)
			spop_strm_close(spop_strm);
	}

	if (spop_conn->state == SPOP_CS_CLOSED || (spop_conn->flags & (SPOP_CF_ERR_PENDING|SPOP_CF_ERROR))) {
		if (spop_conn->state == SPOP_CS_CLOSED || (spop_conn->flags & SPOP_CF_ERROR))
			se_fl_set(spop_strm->sd, SE_FL_EOS);
		se_fl_set_error(spop_strm->sd);
		if (!spop_strm->sd->abort_info.info) {
			spop_strm->sd->abort_info.info = (SE_ABRT_SRC_MUX_SPOP << SE_ABRT_SRC_SHIFT);
			spop_strm->sd->abort_info.code = spop_conn->errcode;
		}

		if (spop_strm->state < SPOP_SS_ERROR) {
			spop_strm->state = SPOP_SS_ERROR;
			TRACE_STATE("switching to ERROR", SPOP_EV_STRM_WAKE|SPOP_EV_SPOP_STRM_END, spop_conn->conn, spop_strm);
		}
	}

	spop_strm_alert(spop_strm);

	TRACE_LEAVE(SPOP_EV_STRM_WAKE, spop_conn->conn, spop_strm);
}

/* Wakes unassigned streams (ID == 0) attached to the connection. */
static void spop_wake_unassigned_streams(struct spop_conn *spop_conn)
{
	struct eb32_node *node;
	struct spop_strm *spop_strm;

	node = eb32_lookup(&spop_conn->streams_by_id, 0);
	while (node) {
		spop_strm = container_of(node, struct spop_strm, by_id);
		if (spop_strm->id > 0)
			break;
		node = eb32_next(node);
		spop_strm_wake_one_stream(spop_strm);
	}
}

/* Wakes the streams attached to the connection, whose id is greater than <last>
 * or unassigned.
 */
static void spop_wake_some_streams(struct spop_conn *spop_conn, int last)
{
	struct eb32_node *node;
	struct spop_strm *spop_strm;

	TRACE_ENTER(SPOP_EV_STRM_WAKE, spop_conn->conn);

	/* Wake all streams with ID > last */
	node = eb32_lookup_ge(&spop_conn->streams_by_id, last + 1);
	while (node) {
		spop_strm = container_of(node, struct spop_strm, by_id);
		node = eb32_next(node);
		spop_strm_wake_one_stream(spop_strm);
	}
	spop_wake_unassigned_streams(spop_conn);

	TRACE_LEAVE(SPOP_EV_STRM_WAKE, spop_conn->conn);
}

/* Sends a HAPROXY HELLO frame. Returns > 0 on success, 0 if it couldn't do
 * anything. It is highly unexpected, but if the frame is larger than a buffer
 * and cannot be encoded in one time, an error is triggered and the connection is
 * closed. HEELO frame cannot be split.
 */
static int spop_conn_send_hello(struct spop_conn *spop_conn)
{
	struct buffer outbuf;
	struct buffer *mbuf;
	struct buffer *chk;
	char *p, *end;
	size_t sz;
	int ret = 0;

	TRACE_ENTER(SPOP_EV_TX_FRAME|SPOP_EV_TX_HELLO, spop_conn->conn);

	mbuf = br_tail(spop_conn->mbuf);
  retry:
	if (!spop_get_buf(spop_conn, mbuf)) {
		spop_conn->flags |= SPOP_CF_MUX_MALLOC;
		spop_conn->flags |= SPOP_CF_DEM_MROOM;
		TRACE_STATE("waiting for fconn mbuf ring allocation", SPOP_EV_TX_FRAME|SPOP_EV_SPOP_CONN_BLK, spop_conn->conn);
		ret = 0;
		goto end;
	}

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 11 || !b_space_wraps(mbuf))
			break;
	  realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 11)
		goto full;

	/* len: 4-bytes (fill later) type: (1)HAPROXY-HELLO, flags: 4-bytes (FIN=1)
	 * stream-id: 0x00, frame-id: 0x00 */
	memcpy(outbuf.area, "\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00", 11);
	outbuf.data = 11;

	p = b_tail(&outbuf);
	end = b_orig(&outbuf) + b_size(&outbuf);

	/* "supported-versions" K/V item */
	sz = SPOP_SLEN(SPOP_SUPPORTED_VERSIONS_KEY);
	if (spoe_encode_buffer(SPOP_SUPPORTED_VERSIONS_KEY, sz, &p, end) == -1)
		goto full;

	*p++ = SPOP_DATA_T_STR;
	sz = SPOP_SLEN(SPOP_SUPPORTED_VERSIONS_VAL);
	if (spoe_encode_buffer(SPOP_SUPPORTED_VERSIONS_VAL, sz, &p, end) == -1)
		goto full;

	/* "max-fram-size" K/V item */
	sz = SPOP_SLEN(SPOP_MAX_FRAME_SIZE_KEY);
	if (spoe_encode_buffer(SPOP_MAX_FRAME_SIZE_KEY, sz, &p, end) == -1)
		goto full;

	*p++ = SPOP_DATA_T_UINT32;
	if (encode_varint(spop_conn->max_frame_size, &p, end) == -1)
		goto full;

	/* "capabilities" K/V item */
	sz = SPOP_SLEN(SPOP_CAPABILITIES_KEY);
	if (spoe_encode_buffer(SPOP_CAPABILITIES_KEY, sz, &p, end) == -1)
		goto full;

	*p++ = SPOP_DATA_T_STR;
	chk = get_trash_chunk();
	if (spop_conn->agent && (spop_conn->agent->flags & SPOE_FL_PIPELINING)) {
		memcpy(chk->area, "pipelining", 10);
		chk->data += 10;
	}
	if (spoe_encode_buffer(chk->area, chk->data, &p, end) == -1)
		goto full;

	/* (optional) "engine-id" K/V item, if present */
	if (spop_conn->agent && spop_conn->agent->engine_id != NULL) {
		sz = SPOP_SLEN(SPOP_ENGINE_ID_KEY);
		if (spoe_encode_buffer(SPOP_ENGINE_ID_KEY, sz, &p, end) == -1)
			goto full;

		*p++ = SPOP_DATA_T_STR;
		sz = strlen(spop_conn->agent->engine_id);
		if (spoe_encode_buffer(spop_conn->agent->engine_id, sz, &p, end) == -1)
			goto full;
	}
	/* If there is no agent attached to the opposite endpoint, it means it is a standalone connection.
	 * This only happens for healthchecks
	 */
	if (!spop_conn->agent) {
		/* Add "healthcheck" K/V item */
		sz = SPOP_SLEN(SPOP_HEALTHCHECK_KEY);
		if (spoe_encode_buffer(SPOP_HEALTHCHECK_KEY, sz, &p, end) == -1)
			goto full;
		*p++ = (SPOP_DATA_T_BOOL | SPOP_DATA_FL_TRUE);
	}

	outbuf.data += p - b_tail(&outbuf);

	/* update the frame's size now */
	TRACE_PROTO("SPOP HAPROXY HELLO frame xferred", SPOP_EV_TX_FRAME|SPOP_EV_TX_HELLO, spop_conn->conn, 0, 0, (size_t[]){outbuf.data});
	spop_set_frame_size(outbuf.area, outbuf.data - 4);
	b_add(mbuf, outbuf.data);
	ret = 1;

  end:
	TRACE_LEAVE(SPOP_EV_TX_FRAME|SPOP_EV_TX_HELLO, spop_conn->conn);
	return ret;
  full:
	/* Too large to be encoded. For HELLO frame, it is an error */
	if (!b_data(mbuf)) {
		TRACE_ERROR("HAPROXY HELLO frame too large", SPOP_EV_TX_FRAME|SPOP_EV_TX_HELLO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
		goto fail;
	}

	if ((mbuf = br_tail_add(spop_conn->mbuf)) != NULL)
		goto retry;
	spop_conn->flags |= SPOP_CF_MUX_MFULL;
	spop_conn->flags |= SPOP_CF_DEM_MROOM;
	TRACE_STATE("mbuf ring full", SPOP_EV_TX_FRAME|SPOP_EV_SPOP_CONN_BLK, spop_conn->conn);
	ret = 0;
	goto end;
  fail:
	spop_conn->state = SPOP_CS_CLOSED;
	TRACE_STATE("switching to CLOSED", SPOP_EV_TX_FRAME|SPOP_EV_TX_HELLO|SPOP_EV_SPOP_CONN_END, spop_conn->conn);
	TRACE_DEVEL("leaving on error", SPOP_EV_TX_FRAME|SPOP_EV_TX_HELLO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
	return 0;
}

/* Sends an DISCONNECT frame for each active streams. Closed streams are
 * excluded, as the streams which already received the end-of-stream. It returns
 * > 0 if the record was sent tp all streams. Otherwise it returns 0.
 */
static int spop_conn_send_disconnect(struct spop_conn *spop_conn)
{
	struct ist reason;
	struct buffer outbuf;
	struct buffer *mbuf;
	char *p, *end;
	size_t sz;
	int ret = 0;

	TRACE_ENTER(SPOP_EV_TX_FRAME|SPOP_EV_TX_DISCO, spop_conn->conn);

	mbuf = br_tail(spop_conn->mbuf);
  retry:
	if (!spop_get_buf(spop_conn, mbuf)) {
		spop_conn->flags |= SPOP_CF_MUX_MALLOC;
		spop_conn->flags |= SPOP_CF_DEM_MROOM;
		TRACE_STATE("waiting for fconn mbuf ring allocation", SPOP_EV_TX_FRAME|SPOP_EV_SPOP_CONN_BLK, spop_conn->conn);
		ret = 0;
		goto end;
	}

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 11 || !b_space_wraps(mbuf))
			break;
	  realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 11)
		goto full;

	/* len: 4-bytes (fill later) type: (2)HAPROXY-DISCONNECT, flags: 4-bytes (FIN=1)
	 * stream-id: 0x00, frame-id: 0x00 */
	memcpy(outbuf.area, "\x00\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00", 11);
	outbuf.data = 11;

	p = b_tail(&outbuf);
	end = b_orig(&outbuf) + b_size(&outbuf);

	/* "status-code" K/V item */
	sz = SPOP_SLEN(SPOP_STATUS_CODE_KEY);
	if (spoe_encode_buffer(SPOP_STATUS_CODE_KEY, sz, &p, end) == -1)
		goto full;

	*p++ = SPOP_DATA_T_UINT32;
	if (encode_varint(spop_conn->errcode, &p, end) == -1)
		goto full;

	/* "message" K/V item */
	sz = SPOP_SLEN(SPOP_MSG_KEY);
	if (spoe_encode_buffer(SPOP_MSG_KEY, sz, &p, end) == -1)
		goto full;

	/*Get the message corresponding to the status code */
	reason = spop_err_reasons[spop_conn->errcode];

	*p++ = SPOP_DATA_T_STR;
	if (spoe_encode_buffer(istptr(reason), istlen(reason), &p, end) == -1)
		goto full;

	outbuf.data += p - b_tail(&outbuf);

	/* update the frame's size now */
	TRACE_PROTO("SPOP HAPROXY DISCONNECT frame xferred", SPOP_EV_TX_FRAME|SPOP_EV_TX_DISCO, spop_conn->conn, 0, 0, (size_t[]){outbuf.data});
	spop_set_frame_size(outbuf.area, outbuf.data - 4);
	b_add(mbuf, outbuf.data);
	spop_conn->flags |= SPOP_CF_DISCO_SENT;
	ret = 1;

  end:
	TRACE_LEAVE(SPOP_EV_TX_FRAME|SPOP_EV_TX_DISCO, spop_conn->conn);
	return ret;
  full:
	/* Too large to be encoded. For DISCONNECT frame, it is an error */
	if (!b_data(mbuf)) {
		TRACE_ERROR("SPOP HAPROXY DISCO frame too large", SPOP_EV_TX_FRAME|SPOP_EV_TX_DISCO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
		goto fail;
	}

	if ((mbuf = br_tail_add(spop_conn->mbuf)) != NULL)
		goto retry;
	spop_conn->flags |= SPOP_CF_MUX_MFULL;
	spop_conn->flags |= SPOP_CF_DEM_MROOM;
	TRACE_STATE("mbuf ring full", SPOP_EV_TX_FRAME|SPOP_EV_SPOP_CONN_BLK, spop_conn->conn);
	ret = 0;
	goto end;
  fail:
	spop_conn->state = SPOP_CS_CLOSED;
	TRACE_STATE("switching to CLOSED", SPOP_EV_TX_FRAME|SPOP_EV_TX_DISCO|SPOP_EV_SPOP_CONN_END, spop_conn->conn);
	TRACE_DEVEL("leaving on error", SPOP_EV_TX_FRAME|SPOP_EV_TX_DISCO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
	return 0;
}

/* Processes an AGENT HELLO frame. Returns > 0 on success, 0 if it couldn't do
 * anything. It is highly unexpected, but if the frame is larger than a buffer
 * and cannot be decoded in one time, an error is triggered and the connection
 * is closed. HELLO frame cannot be split.
 */
static int spop_conn_handle_hello(struct spop_conn *spop_conn)
{
	struct buffer *dbuf;
	char *p, *end;
	int vsn, max_frame_size;
	unsigned int flags;

	TRACE_ENTER(SPOP_EV_RX_FRAME|SPOP_EV_RX_HELLO, spop_conn->conn);

	dbuf = &spop_conn->dbuf;

	/* Record too large to be fully decoded */
	if (b_size(dbuf) < (spop_conn->dfl))
		goto fail;

	/* process full record only */
	if (b_data(dbuf) < (spop_conn->dfl)) {
		TRACE_DEVEL("leaving on missing data", SPOP_EV_RX_FRAME|SPOP_EV_RX_HELLO, spop_conn->conn);
		return 0;
	}

	if (unlikely(b_contig_data(dbuf, b_head_ofs(dbuf)) < spop_conn->dfl)) {
		/* Realign the dmux buffer if the frame wraps. It is unexpected
		 * at this stage because it should be the first record received
		 * from the FCGI application.
		 */
		b_slow_realign_ofs(dbuf, trash.area, 0);
	}

	p = b_head(dbuf);
	end = p  + spop_conn->dfl;

	/* There are 3 mandatory items: "version", "max-frame-size" and
	 * "capabilities" */

	/* Loop on K/V items */
	vsn = flags = 0;
	max_frame_size = spop_conn->max_frame_size;
	while (p < end) {
		char  *str;
		uint64_t sz;
		int    ret;

		/* Decode the item key */
		ret = spoe_decode_buffer(&p, end, &str, &sz);
		if (ret == -1 || !sz) {
			spop_conn_error(spop_conn, SPOP_ERR_INVALID);
			goto fail;
		}

		/* Check "version" K/V item */
		if (sz >= strlen(SPOP_VERSION_KEY) && !memcmp(str, SPOP_VERSION_KEY, strlen(SPOP_VERSION_KEY))) {
			int type = *p++;

			/* The value must be a string */
			if ((type & SPOP_DATA_T_MASK) != SPOP_DATA_T_STR) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}

			vsn = spoe_str_to_vsn(str, sz);
			if (vsn == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}
			if (spoe_check_vsn(vsn) == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_BAD_VSN);
				goto fail;
			}
		}
		/* Check "max-frame-size" K/V item */
		else if (sz >= strlen(SPOP_MAX_FRAME_SIZE_KEY) && !memcmp(str, SPOP_MAX_FRAME_SIZE_KEY, SPOP_SLEN(SPOP_MAX_FRAME_SIZE_KEY))) {
			int type = *p++;

			/* The value must be integer */
			if ((type & SPOP_DATA_T_MASK) != SPOP_DATA_T_INT32 &&
			    (type & SPOP_DATA_T_MASK) != SPOP_DATA_T_INT64 &&
			    (type & SPOP_DATA_T_MASK) != SPOP_DATA_T_UINT32 &&
			    (type & SPOP_DATA_T_MASK) != SPOP_DATA_T_UINT64) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}
			if (decode_varint(&p, end, &sz) == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}
			if (sz < SPOP_MIN_FRAME_SIZE || sz > spop_conn->max_frame_size) {
				spop_conn_error(spop_conn, SPOP_ERR_BAD_FRAME_SIZE);
				goto fail;
			}
			max_frame_size = sz;
		}
		/* Check "capabilities" K/V item */
		else if (sz >= strlen(SPOP_CAPABILITIES_KEY) && !memcmp(str, SPOP_CAPABILITIES_KEY, SPOP_SLEN(SPOP_CAPABILITIES_KEY))) {
			int type = *p++;

			/* The value must be a string */
			if ((type & SPOP_DATA_T_MASK) != SPOP_DATA_T_STR) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}

			while (sz) {
				char *delim;

				/* Skip leading spaces */
				for (; isspace((unsigned char)*str) && sz; str++, sz--);

				if (sz >= 10 && !strncmp(str, "pipelining", 10)) {
					str += 10; sz -= 10;
					if (!sz || isspace((unsigned char)*str) || *str == ',')
						flags |= SPOE_FL_PIPELINING;
				}

				/* Get the next comma or break */
				if (!sz || (delim = memchr(str, ',', sz)) == NULL)
					break;
				delim++;
				sz -= (delim - str);
				str = delim;
			}
		}
		else {
			/* Silently ignore unknown item */
			if (spoe_skip_data(&p, end) == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
			}
		}
	}

	/* Final checks */
	if (!vsn) {
		spop_conn_error(spop_conn, SPOP_ERR_NO_VSN);
		goto fail;
	}
	if (!max_frame_size) {
		spop_conn_error(spop_conn, SPOP_ERR_NO_FRAME_SIZE);
		goto fail;
	}

	if (!(flags & SPOE_FL_PIPELINING))
		spop_conn->streams_limit = 1;
	spop_conn->max_frame_size = (unsigned int)max_frame_size;


	TRACE_PROTO("SPOP AGENT HELLO frame rcvd", SPOP_EV_RX_FRAME|SPOP_EV_RX_HELLO, spop_conn->conn, 0, 0, (size_t[]){spop_conn->dfl});
	b_del(&spop_conn->dbuf, spop_conn->dfl);
	spop_conn->dfl = 0;
	spop_wake_unassigned_streams(spop_conn);
	TRACE_LEAVE(SPOP_EV_RX_FRAME|SPOP_EV_RX_HELLO, spop_conn->conn);
	return 1;
  fail:
	spop_conn->state = SPOP_CS_CLOSED;
	spop_conn->flags |= SPOP_CF_ERROR;
	TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_HELLO, spop_conn->conn);
	TRACE_DEVEL("leaving on error", SPOP_EV_RX_FRAME|SPOP_EV_RX_HELLO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
	return 0;
}

/* Processes an AGENT DISCONNECT frame. Returns > 0 on success, 0 if it couldn't
 * do anything. It is highly unexpected, but if the frame is larger than a
 * buffer and cannot be decoded in one time, an error is triggered and the
 * connection is closed. DISCONNECT frame cannot be split.
 */
static int spop_conn_handle_disconnect(struct spop_conn *spop_conn)
{
	struct buffer *dbuf;
	char *p, *end;
	//struct ist reason;
	unsigned int status_code, flags;

	TRACE_ENTER(SPOP_EV_RX_FRAME|SPOP_EV_RX_DISCO, spop_conn->conn);

	dbuf = &spop_conn->dbuf;

	/* Record too large to be fully decoded */
	if (b_size(dbuf) < (spop_conn->dfl))
		goto fail;

	/* process full record only */
	if (b_data(dbuf) < (spop_conn->dfl)) {
		TRACE_DEVEL("leaving on missing data", SPOP_EV_RX_FRAME|SPOP_EV_RX_DISCO, spop_conn->conn);
		return 0;
	}

	if (unlikely(b_contig_data(dbuf, b_head_ofs(dbuf)) < spop_conn->dfl)) {
		/* Realign the dmux buffer if the frame wraps. It is unexpected
		 * at this stage because it should be the first record received
		 * from the FCGI application.
		 */
		b_slow_realign_ofs(dbuf, trash.area, 0);
	}

	p = b_head(dbuf);
	end = p  + spop_conn->dfl;

        /* There are 2 mandatory items: "status-code" and "message" */

	/* Loop on K/V items */
	status_code = flags = 0;
	while (p < end) {
		char  *str;
		uint64_t sz;
		int    ret;

		/* Decode the item key */
		ret = spoe_decode_buffer(&p, end, &str, &sz);
		if (ret == -1 || !sz) {
			spop_conn_error(spop_conn, SPOP_ERR_INVALID);
			goto fail;
		}

                /* Check "status-code" K/V item */
                if (sz >= strlen(SPOP_STATUS_CODE_KEY) && !memcmp(str, SPOP_STATUS_CODE_KEY, strlen(SPOP_STATUS_CODE_KEY))) {
                        int type = *p++;

                        /* The value must be an integer */
                        if ((type & SPOP_DATA_T_MASK) != SPOP_DATA_T_INT32 &&
                            (type & SPOP_DATA_T_MASK) != SPOP_DATA_T_INT64 &&
                            (type & SPOP_DATA_T_MASK) != SPOP_DATA_T_UINT32 &&
                            (type & SPOP_DATA_T_MASK) != SPOP_DATA_T_UINT64) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
                        }
                        if (decode_varint(&p, end, &sz) == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
                        }
                        status_code = sz;
                }
		// TODO: for now skip the reason
                /* /\* Check "message" K/V item *\/ */
                /* else if (sz >= strlen(SPOP_MSG_KEY) && !memcmp(str, SPOP_MSG_KEY, strlen(SPOP_MSG_KEY))) { */
                /*         int type = *p++; */

                /*         /\* The value must be a string *\/ */
                /*         if ((type & SPOP_DATA_T_MASK) != SPOP_DATA_T_STR) { */
		/* 		spop_conn_error(spop_conn, SPOP_ERR_INVALID); */
		/* 		goto fail; */
                /*         } */
                /*         ret = spoe_decode_buffer(&p, end, &str, &sz); */
                /*         if (ret == -1 || sz > 255) { */
		/* 		spop_conn_error(spop_conn, SPOP_ERR_INVALID); */
		/* 		goto fail; */
                /*         } */
		/* 	reason = ist2(str, sz); */
                /* } */
                else {
                        /* Silently ignore unknown item */
                        if (spoe_skip_data(&p, end) == -1) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				goto fail;
                        }
                }
	}

	TRACE_PROTO("SPOP AGENT DISCONNECT frame rcvd", SPOP_EV_RX_FRAME|SPOP_EV_RX_DISCO, spop_conn->conn, 0, 0, (size_t[]){spop_conn->dfl});
	b_del(&spop_conn->dbuf, spop_conn->dfl);
	spop_conn->dfl = 0;
	spop_conn_error(spop_conn, status_code);
	spop_conn->state = SPOP_CS_CLOSED;
	spop_wake_some_streams(spop_conn, 0/*last*/);
	TRACE_LEAVE(SPOP_EV_RX_FRAME|SPOP_EV_RX_DISCO, spop_conn->conn);
	return 1;
  fail:
	spop_conn->state = SPOP_CS_CLOSED;
	spop_conn->flags |= SPOP_CF_ERROR;
	TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_DISCO, spop_conn->conn);
	TRACE_DEVEL("leaving on error", SPOP_EV_RX_FRAME|SPOP_EV_RX_DISCO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
	return 0;
}

/* Processes an AGENT ACK frame. Returns > 0 on success, 0 if it couldn't
 * do anything.
 *
 * TODO: for now cannot be fragmented.
 */
static int spop_conn_handle_ack(struct spop_conn *spop_conn, struct spop_strm *spop_strm)
{
	struct buffer *dbuf, *rxbuf;
	unsigned int flen, sent = 0;

	TRACE_ENTER(SPOP_EV_RX_FRAME|SPOP_EV_RX_ACK, spop_conn->conn, spop_strm);

	dbuf = &spop_conn->dbuf;

	/* Record too large to be fully decoded */
	if (b_size(dbuf) < (spop_conn->dfl))
		goto fail;

	/* process full record only */
	if (b_data(dbuf) < (spop_conn->dfl)) {
		TRACE_DEVEL("leaving on missing data", SPOP_EV_RX_FRAME|SPOP_EV_RX_DISCO, spop_conn->conn);
		return 0;
	}

	if (unlikely(b_contig_data(dbuf, b_head_ofs(dbuf)) < spop_conn->dfl)) {
		/* Realign the dmux buffer if the frame wraps. It is unexpected
		 * at this stage because it should be the first record received
		 * from the FCGI application.
		 */
		b_slow_realign_ofs(dbuf, trash.area, 0);
	}

	spop_conn->flags &= ~SPOP_CF_DEM_SFULL;
	rxbuf = spop_get_buf(spop_conn, &spop_strm->rxbuf);
	if (!rxbuf) {
		spop_conn->flags |= SPOP_CF_DEM_SALLOC;
		TRACE_STATE("waiting for an spop_strm rxbuf", SPOP_EV_RX_FRAME|SPOP_EV_RX_ACK|SPOP_EV_SPOP_STRM_BLK, spop_conn->conn, spop_strm);
		goto fail;
	}

	flen = spop_conn->dfl;
	if (!flen)
		goto end;

	// TODO: For now we know all data were received
	/* if (flen > b_data(&h2c->dbuf)) { */
	/* 	flen = b_data(&h2c->dbuf); */
	/* 	if (!flen) */
	/* 		goto fail; */
	/* } */

	// TODO: for now, we take care to xfer all data at once !
	if (flen > b_room(rxbuf)) {
		spop_conn->flags |= SPOP_CF_DEM_SFULL;
		TRACE_STATE("spop_strm rxbuf is full", SPOP_EV_RX_FRAME|SPOP_EV_RX_ACK|SPOP_EV_SPOP_STRM_BLK, spop_conn->conn, spop_strm);
		goto fail;
	}

	sent = b_xfer(rxbuf, dbuf, flen);
	BUG_ON(sent != flen);
	/* b_del(&spop_conn->dbuf, sent); */
	spop_conn->dfl -= sent;

	// TODO: may happen or not ?
	/* /\* call the upper layers to process the frame, then let the upper layer */
	/*  * notify the stream about any change. */
	/*  *\/ */
	/* if (!spop_strm_sc(spop_strm)) { */
	/* 	/\* The upper layer has already closed *\/ */

	/* } */
	if (spop_strm->state == SPOP_SS_OPEN)
		spop_strm->state = SPOP_SS_HREM;
	else
		spop_strm_close(spop_strm);

  end:
	TRACE_PROTO("SPOP AGENT ACK frame rcvd", SPOP_EV_RX_FRAME|SPOP_EV_RX_ACK, spop_conn->conn, spop_strm, 0, (size_t[]){sent});
	spop_conn->state = SPOP_CS_FRAME_H;
	TRACE_LEAVE(SPOP_EV_RX_FRAME|SPOP_EV_RX_ACK, spop_conn->conn, spop_strm);
	return 1;

 fail:
	TRACE_DEVEL("leaving on error", SPOP_EV_RX_FRAME|SPOP_EV_RX_ACK|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn, spop_strm);
	return 0;
}

/* resume each spop_strm eligible for sending in list head <head> */
static void spop_resume_each_sending_spop_strm(struct spop_conn *spop_conn, struct list *head)
{
	struct spop_strm *spop_strm, *spop_strm_back;

	TRACE_ENTER(SPOP_EV_SPOP_CONN_SEND|SPOP_EV_STRM_WAKE, spop_conn->conn);

	list_for_each_entry_safe(spop_strm, spop_strm_back, head, list) {
		if (spop_conn->flags & SPOP_CF_MUX_BLOCK_ANY ||
		    spop_conn->state >= SPOP_CS_ERROR)
			break;

		spop_strm->flags &= ~SPOP_SF_BLK_ANY;

		if (spop_strm->flags & SPOP_SF_NOTIFIED)
			continue;

		/* If the sender changed his mind and unsubscribed, let's just
		 * remove the stream from the send_list.
		 */
		if (!spop_strm->subs || !(spop_strm->subs->events & SUB_RETRY_SEND)) {
			LIST_DEL_INIT(&spop_strm->list);
			continue;
		}

		if (spop_strm->subs && spop_strm->subs->events & SUB_RETRY_SEND) {
			spop_strm->flags |= SPOP_SF_NOTIFIED;
			tasklet_wakeup(spop_strm->subs->tasklet);
			spop_strm->subs->events &= ~SUB_RETRY_SEND;
			if (!spop_strm->subs->events)
				spop_strm->subs = NULL;
		}
	}

	TRACE_LEAVE(SPOP_EV_SPOP_CONN_SEND|SPOP_EV_STRM_WAKE, spop_conn->conn);
}

/* removes a stream from the list it may be in. If a stream has recently been
 * appended to the send_list, it might have been waiting on this one when
 * entering spop_snd_buf() and expecting it to complete before starting to send
 * in turn. For this reason we check (and clear) SPOP_CF_WAIT_INLIST to detect
 * this condition, and we try to resume sending streams if it happens. Note
 * that we don't need to do it for fctl_list as this list is relevant before
 * (only consulted after) a window update on the connection, and not because
 * of any competition with other streams.
 */
static inline void spop_remove_from_list(struct spop_strm *spop_strm)
{
	struct spop_conn *spop_conn = spop_strm->spop_conn;

	if (!LIST_INLIST(&spop_strm->list))
		return;

	LIST_DEL_INIT(&spop_strm->list);
	if (spop_conn->flags & SPOP_CF_WAIT_INLIST) {
		spop_conn->flags &= ~SPOP_CF_WAIT_INLIST;
		spop_resume_each_sending_spop_strm(spop_conn, &spop_conn->send_list);
	}
}


/* process Rx records to be demultiplexed */
static void spop_process_demux(struct spop_conn *spop_conn)
{
	struct spop_strm *spop_strm = NULL, *tmp_spop_strm;
	struct spop_frame_header hdr;

	TRACE_ENTER(SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);

	if (spop_conn->state >= SPOP_CS_ERROR)
		goto out;

	if (unlikely(spop_conn->state < SPOP_CS_FRAME_H)) {
		if (spop_conn->state == SPOP_CS_HA_HELLO) {
			TRACE_STATE("waiting AGENT HELLO frame to be sent", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_RX_HELLO, spop_conn->conn);
			goto out;
		}
		if (spop_conn->state == SPOP_CS_AGENT_HELLO) {
			/* ensure that what is pending is a valid AGENT HELLO frame. */
			TRACE_STATE("receiving AGENT HELLO frame header", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR, spop_conn->conn);
			if (!spop_get_frame_hdr(&spop_conn->dbuf, &hdr)) {
				spop_conn->flags |= SPOP_CF_DEM_SHORT_READ;
				TRACE_ERROR("header frame not available yet", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR, spop_conn->conn);
				goto done;
			}

			if (hdr.sid || hdr.fid || hdr.type != SPOP_FRM_T_AGENT_HELLO || !(hdr.flags & SPOP_FRM_FL_FIN)) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				spop_conn->state = SPOP_CS_CLOSED;
				TRACE_ERROR("unexpected frame type or flags", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_RX_HELLO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_RX_HELLO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				goto done;
			}

			if ((int)hdr.len < 0 || (int)hdr.len > spop_conn->max_frame_size) {
				spop_conn_error(spop_conn, SPOP_ERR_BAD_FRAME_SIZE);
				spop_conn->state = SPOP_CS_CLOSED;
				TRACE_ERROR("invalid AGENT HELLO frame length", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_RX_HELLO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_RX_HELLO|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				goto done;
			}

			goto new_frame;
		}
	}

	/* process as many incoming frames as possible below */
	while (1) {
		int ret = 0;

		if (!b_data(&spop_conn->dbuf)) {
			TRACE_DEVEL("no more Rx data", SPOP_EV_RX_FRAME, spop_conn->conn);
			spop_conn->flags |= SPOP_CF_DEM_SHORT_READ;
			break;
		}

		if (spop_conn->state >= SPOP_CS_ERROR) {
			TRACE_STATE("end of connection reported", SPOP_EV_RX_FRAME|SPOP_EV_RX_EOI, spop_conn->conn);
			break;
		}

		if (spop_conn->state == SPOP_CS_FRAME_H) {
			TRACE_PROTO("receiving SPOP frame header", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR, spop_conn->conn);
			if (!spop_get_frame_hdr(&spop_conn->dbuf, &hdr)) {
				spop_conn->flags |= SPOP_CF_DEM_SHORT_READ;
				break;
			}

			if ((int)hdr.len < 0 || (int)hdr.len > spop_conn->max_frame_size) {
				spop_conn_error(spop_conn, SPOP_ERR_BAD_FRAME_SIZE);
				TRACE_ERROR("invalid SPOP frame length", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				break;
			}

		  new_frame:
			spop_conn->dsi = hdr.sid;
			spop_conn->dfi = hdr.fid;
			spop_conn->dft = hdr.type;
			spop_conn->dfl = hdr.len;
			spop_conn->dff = hdr.flags;
			spop_conn->state = SPOP_CS_FRAME_P;
			TRACE_STATE("SPOP frame header rcvd, switching to FRAME_P", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR, spop_conn->conn);

			/* Perform sanity check on the frame header */
			if (!(spop_conn->dff & SPOP_FRM_FL_FIN)) {
				spop_conn_error(spop_conn, SPOP_ERR_FRAG_NOT_SUPPORTED);
				TRACE_ERROR("frame fragmentation not supported", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				break;
			}
			if (!spop_conn->dsi && spop_conn->dft == SPOP_FRM_T_AGENT_ACK) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				TRACE_ERROR("invalid SPOP frame (ACK && dsi == 0)", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				break;
			}
			if (spop_conn->dsi && !spop_conn->dfi) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				TRACE_ERROR("invalid SPOP frame (dsi != 0 && dfi == 0)", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				break;
			}
		}


		tmp_spop_strm = spop_conn_st_by_id(spop_conn, spop_conn->dsi);
		if (tmp_spop_strm != spop_strm && spop_strm && spop_strm_sc(spop_strm) &&
		    (b_data(&spop_strm->rxbuf) ||
		     spop_conn_read0_pending(spop_conn) ||
		     spop_strm->state == SPOP_SS_CLOSED ||
		     se_fl_test(spop_strm->sd, SE_FL_ERROR | SE_FL_ERR_PENDING | SE_FL_EOS))) {
			/* we may have to signal the upper layers */
			TRACE_DEVEL("notifying stream before switching SID", SPOP_EV_RX_FRAME|SPOP_EV_STRM_WAKE, spop_conn->conn, spop_strm);
			se_fl_set(spop_strm->sd, SE_FL_RCV_MORE);
			spop_strm_notify_recv(spop_strm);
		}
		spop_strm = tmp_spop_strm;

		/* Perform sanity checks on the SPOP stream */
		if (spop_strm == spop_unknown_stream) {
			if (spop_conn->dsi > spop_conn->max_id) {
				spop_conn_error(spop_conn, SPOP_ERR_FRAMEID_NOTFOUND);
				TRACE_ERROR("invalid SPOP frame (dsi > max_id)", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				break;
			}
			else {
				/* stream not found, probably because it aborted */
				goto ignore_frame;
			}
		}
		else if (spop_strm == spop_closed_stream) {
			if (spop_conn->dft != SPOP_FRM_T_AGENT_HELLO && spop_conn->dft != SPOP_FRM_T_AGENT_DISCON) {
				spop_conn_error(spop_conn, SPOP_ERR_INVALID);
				TRACE_ERROR("invalid SPOP frame (dsi == 0)", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				break;
			}
		}
		else {
			if (spop_conn->dfi == spop_strm->fid) {
				// OK, no problem
			}
			else if (spop_conn->dfi > spop_strm->fid) {
				spop_conn_error(spop_conn, SPOP_ERR_FRAMEID_NOTFOUND);
				TRACE_ERROR("invalid SPOP frame (dfi > frame-id)", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				TRACE_STATE("switching to CLOSED", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR|SPOP_EV_SPOP_CONN_ERR, spop_conn->conn);
				break;
			}
			else {
				/* frame id not found, probably because it aborted */
				goto ignore_frame;
			}
		}

		switch (spop_conn->dft) {
		case SPOP_FRM_T_AGENT_HELLO:
			if (spop_conn->state == SPOP_CS_FRAME_P)
				ret = spop_conn_handle_hello(spop_conn);
			break;
		case SPOP_FRM_T_AGENT_DISCON:
			if (spop_conn->state == SPOP_CS_FRAME_P)
				ret = spop_conn_handle_disconnect(spop_conn);
			break;
		case SPOP_FRM_T_AGENT_ACK:
			if (spop_conn->state == SPOP_CS_FRAME_P)
				ret = spop_conn_handle_ack(spop_conn, spop_strm);
			break;
		default:
		  ignore_frame:
			TRACE_PROTO("receiving SPOP ignored frame", SPOP_EV_RX_FRAME, spop_conn->conn, spop_strm);
			/* drop frames that we ignore. */
			ret = MIN(b_data(&spop_conn->dbuf), spop_conn->dfl);
			b_del(&spop_conn->dbuf, ret);
			spop_conn->dfl -= ret;
			ret = (spop_conn->dfl == 0);
			break;
		}

		// TODO: SS_ERROR to CS_ERROR ?

		if (spop_conn->state == SPOP_CS_ERROR) {
			TRACE_PROTO("sending SPOP HAPROXY DISCONNECT frame", SPOP_EV_TX_FRAME|SPOP_EV_TX_DISCO|SPOP_EV_TX_EOI, spop_conn->conn, spop_strm);
			ret = spop_conn_send_disconnect(spop_conn);
		}

		/* error or missing data condition met above ? */
		if (ret <= 0)
			break;

		if (spop_conn->state != SPOP_CS_FRAME_H) {
			if (spop_conn->dfl) {
				TRACE_DEVEL("skipping remaining frame payload", SPOP_EV_RX_FRAME, spop_conn->conn, spop_strm);
				ret = MIN(b_data(&spop_conn->dbuf), spop_conn->dfl);
				b_del(&spop_conn->dbuf, ret);
				spop_conn->dfl -= ret;
			}
			if (!spop_conn->dfl) {
				TRACE_STATE("switching to FRAME_H", SPOP_EV_RX_FRAME|SPOP_EV_RX_FHDR, spop_conn->conn);
				spop_conn->state = SPOP_CS_FRAME_H;
			}
		}
	}

  done:
	if (spop_conn->state >= SPOP_CS_ERROR || (spop_conn->flags & SPOP_CF_DEM_SHORT_READ)) {
		if (spop_conn->flags & SPOP_CF_RCVD_SHUT)
			spop_conn->flags |= SPOP_CF_END_REACHED;
	}

	if (spop_strm && spop_strm_sc(spop_strm) &&
	    (b_data(&spop_strm->rxbuf) ||
	     spop_conn_read0_pending(spop_conn) ||
	     spop_strm->state == SPOP_SS_CLOSED ||
	     se_fl_test(spop_strm->sd, SE_FL_ERROR | SE_FL_ERR_PENDING | SE_FL_EOS))) {
		/* we may have to signal the upper layers */
		TRACE_DEVEL("notifying stream before switching SID", SPOP_EV_RX_FRAME|SPOP_EV_STRM_WAKE, spop_conn->conn, spop_strm);
		se_fl_set(spop_strm->sd, SE_FL_RCV_MORE);
		spop_strm_notify_recv(spop_strm);
	}

	spop_conn_restart_reading(spop_conn, 0);
  out:
	TRACE_LEAVE(SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);
	return;
}


/* process Tx records from streams to be multiplexed. Returns > 0 if it reached
 * the end.
 */
static int spop_process_mux(struct spop_conn *spop_conn)
{
	TRACE_ENTER(SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);

	if (unlikely(spop_conn->state < SPOP_CS_FRAME_H)) {
		if (unlikely(spop_conn->state == SPOP_CS_HA_HELLO)) {
			TRACE_PROTO("sending SPOP HAPROXY HELLO fraame", SPOP_EV_TX_FRAME, spop_conn->conn);
			if (unlikely(!spop_conn_send_hello(spop_conn)))
				goto fail;
			spop_conn->state = SPOP_CS_AGENT_HELLO;
			TRACE_STATE("waiting for SPOP AGENT HELLO reply", SPOP_EV_TX_FRAME|SPOP_EV_RX_FRAME, spop_conn->conn);
		}
		/* need to wait for the other side */
		if (spop_conn->state < SPOP_CS_FRAME_H)
			goto done;
	}

	spop_conn->flags &= ~SPOP_CF_WAIT_INLIST;
	spop_resume_each_sending_spop_strm(spop_conn, &spop_conn->send_list);

  fail:
	/* Nothing to do */

  done:
	TRACE_LEAVE(SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);
	return 1;
}

/* Attempt to read data, and subscribe if none available.
 * The function returns 1 if data has been received, otherwise zero.
 */
static int spop_recv(struct spop_conn *spop_conn)
{
	struct connection *conn = spop_conn->conn;
	struct buffer *buf;
	int max;
	size_t ret;

	TRACE_ENTER(SPOP_EV_SPOP_CONN_RECV, conn);

	if (spop_conn->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("leaving on sub_recv", SPOP_EV_SPOP_CONN_RECV, conn);
		return (b_data(&spop_conn->dbuf));
	}

	if (!spop_recv_allowed(spop_conn)) {
		TRACE_DEVEL("leaving on !recv_allowed", SPOP_EV_SPOP_CONN_RECV, conn);
		return 1;
	}

	buf = spop_get_buf(spop_conn, &spop_conn->dbuf);
	if (!buf) {
		TRACE_DEVEL("waiting for spop_conn dbuf allocation", SPOP_EV_SPOP_CONN_RECV|SPOP_EV_SPOP_CONN_BLK, conn);
		spop_conn->flags |= SPOP_CF_DEM_DALLOC;
		return 0;
	}

	max = b_room(buf);
	ret = max ? conn->xprt->rcv_buf(conn, conn->xprt_ctx, buf, max, 0) : 0;

	if (max && !ret && spop_recv_allowed(spop_conn)) {
		TRACE_DATA("failed to receive data, subscribing", SPOP_EV_SPOP_CONN_RECV, conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV, &spop_conn->wait_event);
	}
	else
		TRACE_DATA("recv data", SPOP_EV_SPOP_CONN_RECV, conn, 0, 0, (size_t[]){ret});

	if (conn_xprt_read0_pending(conn)) {
		TRACE_DATA("received read0", SPOP_EV_SPOP_CONN_RECV, conn);
		spop_conn->flags |= SPOP_CF_RCVD_SHUT;
	}
	if (conn->flags & CO_FL_ERROR) {
		TRACE_DATA("connection error", SPOP_EV_SPOP_CONN_RECV, conn);
		spop_conn->flags |= SPOP_CF_ERROR;
	}

	if (!b_data(buf)) {
		spop_release_buf(spop_conn, &spop_conn->dbuf);
		goto end;
	}

	if (ret == max) {
		TRACE_DEVEL("spop_conn dbuf full", SPOP_EV_SPOP_CONN_RECV|SPOP_EV_SPOP_CONN_BLK, conn);
		spop_conn->flags |= SPOP_CF_DEM_DFULL;
	}

end:
	TRACE_LEAVE(SPOP_EV_SPOP_CONN_RECV, conn);
	return !!ret || (spop_conn->flags & (SPOP_CF_RCVD_SHUT|SPOP_CF_ERROR));
}

/* Try to send data if possible.
 * The function returns 1 if data have been sent, otherwise zero.
 */
static int spop_send(struct spop_conn *spop_conn)
{
	struct connection *conn = spop_conn->conn;
	int done;
	int sent = 0;

	TRACE_ENTER(SPOP_EV_SPOP_CONN_SEND, conn);

	if (spop_conn->flags & (SPOP_CF_ERROR|SPOP_CF_ERR_PENDING)) {
		TRACE_DEVEL("leaving on connection error", SPOP_EV_SPOP_CONN_SEND, conn);
		if (spop_conn->flags & SPOP_CF_END_REACHED)
			spop_conn->flags |= SPOP_CF_ERROR;
		b_reset(br_tail(spop_conn->mbuf));
		return 1;
	}


	if (conn->flags & CO_FL_WAIT_XPRT) {
		/* a handshake was requested */
		goto schedule;
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
	while (!done) {
		unsigned int flags = 0;
		unsigned int released = 0;
		struct buffer *buf;

		/* fill as much as we can into the current buffer */
		while (((spop_conn->flags & (SPOP_CF_MUX_MFULL|SPOP_CF_MUX_MALLOC)) == 0) && !done)
			done = spop_process_mux(spop_conn);

		if (spop_conn->flags & SPOP_CF_MUX_MALLOC)
			done = 1; // we won't go further without extra buffers

		if (conn->flags & CO_FL_ERROR)
			break;

		if (spop_conn->flags & (SPOP_CF_MUX_MFULL | SPOP_CF_DEM_MROOM))
			flags |= CO_SFL_MSG_MORE;

		for (buf = br_head(spop_conn->mbuf); b_size(buf); buf = br_del_head(spop_conn->mbuf)) {
			if (b_data(buf)) {
				int ret;

				ret = conn->xprt->snd_buf(conn, conn->xprt_ctx, buf, b_data(buf), flags);
				if (!ret) {
					done = 1;
					break;
				}
				sent = 1;
				TRACE_DATA("send data", SPOP_EV_SPOP_CONN_SEND, conn, 0, 0, (size_t[]){ret});
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

		/* wrote at least one byte, the buffer is not full anymore */
		if (spop_conn->flags & (SPOP_CF_MUX_MFULL | SPOP_CF_DEM_MROOM))
			TRACE_STATE("spop_conn mbuf ring not fill anymore", SPOP_EV_SPOP_CONN_SEND|SPOP_EV_SPOP_CONN_BLK, conn);
		spop_conn->flags &= ~(SPOP_CF_MUX_MFULL | SPOP_CF_DEM_MROOM);
	}

	if (conn->flags & CO_FL_ERROR) {
		spop_conn->flags |= SPOP_CF_ERR_PENDING;
		if (spop_conn->flags & SPOP_CF_END_REACHED)
			spop_conn->flags |= SPOP_CF_ERROR;
		b_reset(br_tail(spop_conn->mbuf));
	}

	/* We're not full anymore, so we can wake any task that are waiting
	 * for us.
	 */
	if (!(spop_conn->flags & (SPOP_CF_MUX_MFULL | SPOP_CF_DEM_MROOM)) && spop_conn->state >= SPOP_CS_FRAME_H) {
		spop_conn->flags &= ~SPOP_CF_WAIT_INLIST;
		spop_resume_each_sending_spop_strm(spop_conn, &spop_conn->send_list);
	}

	/* We're done, no more to send */
	if (!br_data(spop_conn->mbuf)) {
		TRACE_DEVEL("leaving with everything sent", SPOP_EV_SPOP_CONN_SEND, conn);
		goto end;
	}
schedule:
	if (!(conn->flags & CO_FL_ERROR) && !(spop_conn->wait_event.events & SUB_RETRY_SEND)) {
		TRACE_STATE("more data to send, subscribing", SPOP_EV_SPOP_CONN_SEND, conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_SEND, &spop_conn->wait_event);
	}

	TRACE_DEVEL("leaving with some data left to send", SPOP_EV_SPOP_CONN_SEND, conn);
end:
	return sent || (spop_conn->flags & (SPOP_CF_ERR_PENDING|SPOP_CF_ERROR));
}


/* this is the tasklet referenced in spop_conn->wait_event.tasklet */
static struct task *spop_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct connection *conn;
	struct spop_conn *spop_conn = ctx;
	struct tasklet *tl = (struct tasklet *)t;
	int conn_in_list;
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
		conn = spop_conn->conn;
		TRACE_POINT(SPOP_EV_SPOP_CONN_WAKE, conn);

		conn_in_list = conn->flags & CO_FL_LIST_MASK;
		if (conn_in_list)
			conn_delete_from_tree(conn);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	} else {
		/* we're certain the connection was not in an idle list */
		conn = spop_conn->conn;
		TRACE_ENTER(SPOP_EV_SPOP_CONN_WAKE, conn);
		conn_in_list = 0;
	}

	if (!(spop_conn->wait_event.events & SUB_RETRY_SEND))
		ret = spop_send(spop_conn);
	if (!(spop_conn->wait_event.events & SUB_RETRY_RECV))
		ret |= spop_recv(spop_conn);
	if (ret || b_data(&spop_conn->dbuf))
		ret = spop_process(spop_conn);

	/* If we were in an idle list, we want to add it back into it,
	 * unless spop_process() returned -1, which mean it has destroyed
	 * the connection (testing !ret is enough, if spop_process() wasn't
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

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection (which normally doesn not happen in SPOP).
 */
static int spop_process(struct spop_conn *spop_conn)
{
	struct connection *conn = spop_conn->conn;

	TRACE_POINT(SPOP_EV_SPOP_CONN_WAKE, conn);

	if (!(spop_conn->flags & SPOP_CF_DEM_BLOCK_ANY) &&
	    (b_data(&spop_conn->dbuf) || (spop_conn->flags & SPOP_CF_RCVD_SHUT))) {
		spop_process_demux(spop_conn);

		if (spop_conn->state >= SPOP_CS_ERROR || (spop_conn->flags & SPOP_CF_ERROR))
			b_reset(&spop_conn->dbuf);

		if (b_room(&spop_conn->dbuf))
			spop_conn->flags &= ~SPOP_CF_DEM_DFULL;
	}
	spop_send(spop_conn);

	/*
	 * If we received early data, and the handshake is done, wake
	 * any stream that was waiting for it.
	 */
	if (!(spop_conn->flags & SPOP_CF_WAIT_FOR_HS) &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_WAIT_XPRT | CO_FL_EARLY_DATA)) == CO_FL_EARLY_DATA) {
		struct eb32_node *node;
		struct spop_strm *spop_strm;

		spop_conn->flags |= SPOP_CF_WAIT_FOR_HS;
		node = eb32_lookup_ge(&spop_conn->streams_by_id, 1);

		while (node) {
			spop_strm = container_of(node, struct spop_strm, by_id);
			if (spop_strm_sc(spop_strm) && se_fl_test(spop_strm->sd, SE_FL_WAIT_FOR_HS))
				spop_strm_notify_recv(spop_strm);
			node = eb32_next(node);
		}
	}

	if ((spop_conn->flags & SPOP_CF_ERROR) || spop_conn_read0_pending(spop_conn) ||
	    spop_conn->state == SPOP_CS_CLOSED || (spop_conn->flags & SPOP_CF_DISCO_FAILED) /* || */
	    /* TODO: no sure ? eb_is_empty(&spop_conn->streams_by_id) */) {
		spop_wake_some_streams(spop_conn, 0);

		if (eb_is_empty(&spop_conn->streams_by_id)) {
			/* no more stream, kill the connection now */
			spop_release(spop_conn);
			TRACE_DEVEL("leaving after releasing the connection", SPOP_EV_SPOP_CONN_WAKE);
			return -1;
		}

		/* connections in error must be removed from the idle lists */
		if (conn->flags & CO_FL_LIST_MASK) {
			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			conn_delete_from_tree(conn);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}
	}

	if (!b_data(&spop_conn->dbuf))
		spop_release_buf(spop_conn, &spop_conn->dbuf);

	if (spop_conn->state == SPOP_CS_CLOSED  || (spop_conn->flags & SPOP_CF_DISCO_FAILED) ||
	    (!br_data(spop_conn->mbuf) && ((spop_conn->flags & SPOP_CF_MUX_BLOCK_ANY) || LIST_ISEMPTY(&spop_conn->send_list))))
		spop_release_mbuf(spop_conn);

	spop_conn_update_timeout(spop_conn);
	spop_send(spop_conn);
	TRACE_LEAVE(SPOP_EV_SPOP_CONN_WAKE, conn);
	return 0;
}

/* wake-up function called by the connection layer (mux_ops.wake) */
static int spop_wake(struct connection *conn)
{
	struct spop_conn *spop_conn = conn->ctx;

	TRACE_POINT(SPOP_EV_SPOP_CONN_WAKE, conn);
	return (spop_process(spop_conn));
}

static int spop_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	struct spop_conn *spop_conn = conn->ctx;
	int ret = 0;

	switch (mux_ctl) {
	case MUX_CTL_STATUS:
		if (!(conn->flags & CO_FL_WAIT_XPRT))
			ret |= MUX_STATUS_READY;
		return ret;
	case MUX_CTL_EXIT_STATUS:
		return MUX_ES_UNKNOWN;
	case MUX_CTL_GET_NBSTRM:
		return spop_conn->nb_streams;
	case MUX_CTL_GET_MAXSTRM:
		return spop_conn->streams_limit;
	default:
		return -1;
	}
}

static int spop_sctl(struct stconn *sc, enum mux_sctl_type mux_sctl, void *output)
{
	int ret = 0;
	struct spop_strm *spop_strm = __sc_mux_strm(sc);

	switch (mux_sctl) {
	case MUX_SCTL_SID:
		if (output)
			*((int64_t *)output) = spop_strm->id;
		return ret;

	default:
		return -1;
	}
}

/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed. If the
 * MUX buffer still has lying data or is not allocatable, the connection is
 * immediately killed. If it's allocatable and empty, we attempt to send a
 * ABORT records.
 */
static struct task *spop_timeout_task(struct task *t, void *context, unsigned int state)
{
	struct spop_conn *spop_conn = context;
	int expired = tick_is_expired(t->expire, now_ms);

	TRACE_ENTER(SPOP_EV_SPOP_CONN_WAKE, (spop_conn ? spop_conn->conn : NULL));

	if (spop_conn) {
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

		/* Somebody already stole the connection from us, so we should not
		 * free it, we just have to free the task.
		 */
		if (!t->context) {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			spop_conn = NULL;
			goto do_leave;
		}

		if (!expired) {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			TRACE_DEVEL("leaving (not expired)", SPOP_EV_SPOP_CONN_WAKE, spop_conn->conn);
			return t;
		}

		/* We're about to destroy the connection, so make sure nobody attempts
		 * to steal it from us.
		 */
		if (spop_conn->conn->flags & CO_FL_LIST_MASK)
			conn_delete_from_tree(spop_conn->conn);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}

do_leave:
	task_destroy(t);

	if (!spop_conn) {
		/* resources were already deleted */
		TRACE_DEVEL("leaving (not more spop_conn)", SPOP_EV_SPOP_CONN_WAKE);
		return NULL;
	}

	spop_conn->task = NULL;
	spop_conn->state = SPOP_CS_CLOSED;
	spop_wake_some_streams(spop_conn, 0);

	if (br_data(spop_conn->mbuf)) {
		/* don't even try to send aborts, the buffer is stuck */
		spop_conn->flags |= SPOP_CF_DISCO_FAILED;
		goto end;
	}

	/* try to send but no need to insist */
	if (!spop_conn_send_disconnect(spop_conn))
		spop_conn->flags |= SPOP_CF_DISCO_FAILED;

	if (br_data(spop_conn->mbuf) && !(spop_conn->flags & SPOP_CF_DISCO_FAILED) &&
	    conn_xprt_ready(spop_conn->conn)) {
		unsigned int released = 0;
		struct buffer *buf;

		for (buf = br_head(spop_conn->mbuf); b_size(buf); buf = br_del_head(spop_conn->mbuf)) {
			if (b_data(buf)) {
				int ret = spop_conn->conn->xprt->snd_buf(spop_conn->conn, spop_conn->conn->xprt_ctx,
									 buf, b_data(buf), 0);
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

  end:
	/* either we can release everything now or it will be done later once
	 * the last stream closes.
	 */
	if (eb_is_empty(&spop_conn->streams_by_id))
		spop_release(spop_conn);

	TRACE_LEAVE(SPOP_EV_SPOP_CONN_WAKE);
	return NULL;
}


/*******************************************/
/* functions below are used by the streams */
/*******************************************/

/* Append the description of what is present in error snapshot <es> into <out>.
 * The description must be small enough to always fit in a buffer. The output
 * buffer may be the trash so the trash must not be used inside this function.
 */
static __maybe_unused void spop_show_error_snapshot(struct buffer *out, const struct error_snapshot *es)
{

	// TODO !!!
}
/*
 * Capture a bad response and archive it in the proxy's structure.  By default
 * it tries to report the error position as h1m->err_pos. However if this one is
 * not set, it will then report h1m->next, which is the last known parsing
 * point. The function is able to deal with wrapping buffers. It always displays
 * buffers as a contiguous area starting at buf->p. The direction is determined
 * thanks to the h1m's flags.
 */
static __maybe_unused void spop_strm_capture_bad_message(struct spop_conn *spop_conn, struct spop_strm *spop_strm,
							 struct buffer *buf)
{
	// TODO !!!
}

// PARSING FUNCTIONS


/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static int spop_attach(struct connection *conn, struct sedesc *sd, struct session *sess)
{
	struct spop_strm *spop_strm;
	struct spop_conn *spop_conn = conn->ctx;

	TRACE_ENTER(SPOP_EV_SPOP_STRM_NEW, conn);
	spop_strm = spop_stconn_new(spop_conn, sd->sc, sess);
	if (!spop_strm)
		goto err;

	/* the connection is not idle anymore, let's mark this */
	HA_ATOMIC_AND(&spop_conn->wait_event.tasklet->state, ~TASK_F_USR1);
	xprt_set_used(conn, conn->xprt, conn->xprt_ctx);

	TRACE_LEAVE(SPOP_EV_SPOP_STRM_NEW, conn, spop_strm);
	return 0;

  err:
	TRACE_DEVEL("leaving on error", SPOP_EV_SPOP_STRM_NEW|SPOP_EV_SPOP_STRM_ERR, conn);
	return -1;
}

/* Retrieves the first valid stream connector from this connection, or returns NULL.
 * We have to scan because we may have some orphan streams. It might be
 * beneficial to scan backwards from the end to reduce the likeliness to find
 * orphans.
 */
static struct stconn *spop_get_first_sc(const struct connection *conn)
{
	struct spop_conn *spop_conn = conn->ctx;
	struct spop_strm *spop_strm;
	struct eb32_node *node;

	node = eb32_first(&spop_conn->streams_by_id);
	while (node) {
		spop_strm = container_of(node, struct spop_strm, by_id);
		if (spop_strm_sc(spop_strm))
			return spop_strm_sc(spop_strm);
		node = eb32_next(node);
	}
	return NULL;
}

/*
 * Destroy the mux and the associated connection, if it is no longer used
 */
static void spop_destroy(void *ctx)
{
	struct spop_conn *spop_conn = ctx;

	TRACE_POINT(SPOP_EV_SPOP_CONN_END, spop_conn->conn);
	if (eb_is_empty(&spop_conn->streams_by_id)) {
		BUG_ON(spop_conn->conn->ctx != spop_conn);
		spop_release(spop_conn);
	}
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void spop_detach(struct sedesc *sd)
{
	struct spop_strm *spop_strm = sd->se;
	struct spop_conn *spop_conn;
	struct session *sess;

	TRACE_ENTER(SPOP_EV_STRM_END, (spop_strm ? spop_strm->spop_conn->conn : NULL), spop_strm);

	if (!spop_strm) {
		TRACE_LEAVE(SPOP_EV_STRM_END);
		return;
	}

	/* there's no txbuf so we're certain no to be able to send anything */
	spop_strm->flags &= ~SPOP_SF_NOTIFIED;

	sess = spop_strm->sess;
	spop_conn = spop_strm->spop_conn;
	spop_conn->nb_sc--;

	/* this stream may be blocked waiting for some data to leave, so orphan
	 * it in this case.
	 */
	if (!(spop_conn->flags & (SPOP_CF_ERR_PENDING|SPOP_CF_ERROR)) && // FIXME: Be sure for ERR_PENDING
	    (spop_conn->state != SPOP_CS_CLOSED) &&
	    (spop_strm->flags & (SPOP_SF_BLK_MBUSY|SPOP_SF_BLK_MROOM)) &&
	    spop_strm->subs) {
		TRACE_DEVEL("leaving on stream blocked", SPOP_EV_STRM_END|SPOP_EV_SPOP_STRM_BLK, spop_conn->conn, spop_strm);
		/* refresh the timeout if none was active, so that the last
		 * leaving stream may arm it.
		 */
		if (spop_conn->task && !tick_isset(spop_conn->task->expire))
			spop_conn_update_timeout(spop_conn);
		return;
	}

	if ((spop_conn->flags & SPOP_CF_DEM_BLOCK_ANY && spop_strm->id == spop_conn->dsi)) {
		/* unblock the connection if it was blocked on this stream. */
		spop_conn->flags &= ~SPOP_CF_DEM_BLOCK_ANY;
		spop_conn->flags &= ~SPOP_CF_MUX_BLOCK_ANY;
		spop_conn_restart_reading(spop_conn, 1);
	}

	spop_strm_destroy(spop_strm);

	if (!(spop_conn->flags & (SPOP_CF_RCVD_SHUT|SPOP_CF_ERR_PENDING|SPOP_CF_ERROR))) {
		if (spop_conn->conn->flags & CO_FL_PRIVATE) {
			/* Add the connection in the session server list, if not already done */
			if (!session_add_conn(sess, spop_conn->conn, spop_conn->conn->target)) {
				spop_conn->conn->owner = NULL;
				if (eb_is_empty(&spop_conn->streams_by_id)) {
					spop_conn->conn->mux->destroy(spop_conn);
					TRACE_DEVEL("leaving on error after killing outgoing connection", SPOP_EV_STRM_END|SPOP_EV_SPOP_CONN_ERR);
					return;
				}
			}
			if (eb_is_empty(&spop_conn->streams_by_id)) {
				/* mark that the tasklet may lose its context to another thread and
				 * that the handler needs to check it under the idle conns lock.
				 */
				HA_ATOMIC_OR(&spop_conn->wait_event.tasklet->state, TASK_F_USR1);
				if (session_check_idle_conn(spop_conn->conn->owner, spop_conn->conn) != 0) {
					/* At this point either the connection is destroyed, or it's been added to the server idle list, just stop */
					TRACE_DEVEL("leaving without reusable idle connection", SPOP_EV_STRM_END);
					return;
				}
			}
		}
		else {
			if (eb_is_empty(&spop_conn->streams_by_id)) {
				/* If the connection is owned by the session, first remove it
				 * from its list
				 */
				if (spop_conn->conn->owner) {
					session_unown_conn(spop_conn->conn->owner, spop_conn->conn);
					spop_conn->conn->owner = NULL;
				}

				/* mark that the tasklet may lose its context to another thread and
				 * that the handler needs to check it under the idle conns lock.
				 */
				HA_ATOMIC_OR(&spop_conn->wait_event.tasklet->state, TASK_F_USR1);
				xprt_set_idle(spop_conn->conn, spop_conn->conn->xprt, spop_conn->conn->xprt_ctx);

				if (!srv_add_to_idle_list(objt_server(spop_conn->conn->target), spop_conn->conn, 1)) {
					/* The server doesn't want it, let's kill the connection right away */
					spop_conn->conn->mux->destroy(spop_conn);
					TRACE_DEVEL("leaving on error after killing outgoing connection", SPOP_EV_STRM_END|SPOP_EV_SPOP_CONN_ERR);
					return;
				}
				/* At this point, the connection has been added to the
				 * server idle list, so another thread may already have
				 * hijacked it, so we can't do anything with it.
				 */
				TRACE_DEVEL("reusable idle connection", SPOP_EV_STRM_END);
				return;
			}
			else if (!spop_conn->conn->hash_node->node.node.leaf_p &&
				 spop_avail_streams(spop_conn->conn) > 0 && objt_server(spop_conn->conn->target) &&
				 !LIST_INLIST(&spop_conn->conn->sess_el)) {
				srv_add_to_avail_list(__objt_server(spop_conn->conn->target), spop_conn->conn);
			}
		}
	}

	/* We don't want to close right now unless we're removing the last
	 * stream and the connection is in error.
	 */
	if (spop_conn_is_dead(spop_conn)) {
		/* no more stream will come, kill it now */
		TRACE_DEVEL("leaving, killing dead connection", SPOP_EV_STRM_END, spop_conn->conn);
		spop_release(spop_conn);
	}
	else if (spop_conn->task) {
		spop_conn_update_timeout(spop_conn);
		TRACE_DEVEL("leaving, refreshing connection's timeout", SPOP_EV_STRM_END, spop_conn->conn);
	}
	else
		TRACE_DEVEL("leaving", SPOP_EV_STRM_END, spop_conn->conn);
}

/* Performs a synchronous or asynchronous shutr(). */
static void spop_do_shutr(struct spop_strm *spop_strm)
{
	struct spop_conn *spop_conn = spop_strm->spop_conn;

	TRACE_ENTER(SPOP_EV_STRM_SHUT, spop_conn->conn, spop_strm);

	if (spop_strm->state == SPOP_SS_CLOSED)
		goto done;

	/* a connstream may require us to immediately kill the whole connection
	 * for example because of a "tcp-request content reject" rule that is
	 * normally used to limit abuse.
	 */
	if (se_fl_test(spop_strm->sd, SE_FL_KILL_CONN) &&
	    !(spop_conn->flags & (SPOP_CF_DISCO_SENT|SPOP_CF_DISCO_FAILED))) {
		TRACE_STATE("stream wants to kill the connection", SPOP_EV_STRM_SHUT, spop_conn->conn, spop_strm);
		spop_conn->state = SPOP_CS_CLOSED;
	}

	spop_strm_close(spop_strm);

	if (!(spop_conn->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(spop_conn->wait_event.tasklet);
  done:
	TRACE_LEAVE(SPOP_EV_STRM_SHUT, spop_conn->conn, spop_strm);
	return;
}

/* Performs a synchronous or asynchronous shutw(). */
static void spop_do_shutw(struct spop_strm *spop_strm)
{
	struct spop_conn *spop_conn = spop_strm->spop_conn;

	TRACE_ENTER(SPOP_EV_STRM_SHUT, spop_conn->conn, spop_strm);

	if (spop_strm->state == SPOP_SS_HLOC || spop_strm->state == SPOP_SS_CLOSED)
		goto done;

	if (spop_strm->state == SPOP_SS_OPEN)
		spop_strm->state = SPOP_SS_HLOC;
	else if (spop_strm->state == SPOP_SS_HREM)
		spop_strm_close(spop_strm);
	else {
		/* a connstream may require us to immediately kill the whole connection
		 * for example because of a "tcp-request content reject" rule that is
		 * normally used to limit abuse.
		 */
		if (se_fl_test(spop_strm->sd, SE_FL_KILL_CONN)) {
			TRACE_STATE("stream wants to kill the connection", SPOP_EV_STRM_SHUT, spop_conn->conn, spop_strm);
			spop_conn->state = SPOP_CS_CLOSED;
		}
	}

	if (!(spop_conn->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(spop_conn->wait_event.tasklet);
  done:
	TRACE_LEAVE(SPOP_EV_STRM_SHUT, spop_conn->conn, spop_strm);
	return;
}


static void spop_shut(struct stconn *sc, enum se_shut_mode mode, struct se_abort_info *reason)
{
	struct spop_strm *spop_strm = __sc_mux_strm(sc);

	TRACE_ENTER(SPOP_EV_STRM_SHUT, spop_strm->spop_conn->conn, spop_strm);
	if (mode & (SE_SHW_SILENT|SE_SHW_NORMAL))
		spop_do_shutw(spop_strm);
	if (mode & SE_SHR_RESET)
		spop_do_shutr(spop_strm);
	TRACE_LEAVE(SPOP_EV_STRM_SHUT, spop_strm->spop_conn->conn, spop_strm);
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int spop_subscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct spop_strm *spop_strm = __sc_mux_strm(sc);
	struct spop_conn *spop_conn = spop_strm->spop_conn;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(spop_strm->subs && spop_strm->subs != es);

	es->events |= event_type;
	spop_strm->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", SPOP_EV_STRM_RECV, spop_conn->conn, spop_strm);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("unsubscribe(send)", SPOP_EV_STRM_SEND, spop_conn->conn, spop_strm);
		if (!LIST_INLIST(&spop_strm->list))
			LIST_APPEND(&spop_conn->send_list, &spop_strm->list);
	}
	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>
 * (undo spop_subscribe). The <es> pointer is not allowed to differ from the one
 * passed to the subscribe() call. It always returns zero.
 */
static int spop_unsubscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct spop_strm *spop_strm = __sc_mux_strm(sc);
	struct spop_conn *spop_conn = spop_strm->spop_conn;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(spop_strm->subs && spop_strm->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		spop_strm->subs = NULL;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", SPOP_EV_STRM_RECV, spop_conn->conn, spop_strm);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", SPOP_EV_STRM_SEND, spop_conn->conn, spop_strm);
		spop_strm->flags &= ~SPOP_SF_NOTIFIED;
		LIST_DEL_INIT(&spop_strm->list);
	}
	return 0;
}

/* Try to send a NOTIFY frame. Returns the number of bytes sent. The caller
 * must check the stream's status to detect any error which might have happened
 * subsequently to a successful send. Data are automatically removed from the
 * buffer. Content of the frame is assumed to be valid since produced from
 * the internal code.
 */
static size_t spop_strm_send_notify(struct spop_strm *spop_strm, struct buffer *buf, size_t count)
{
	struct spop_conn *spop_conn = spop_strm->spop_conn;
	struct buffer outbuf;
	struct buffer *mbuf;
	char *p, *end;
	size_t sz;
	int ret = 0;

	TRACE_ENTER(SPOP_EV_TX_FRAME|SPOP_EV_TX_NOTIFY, spop_conn->conn, spop_strm);

	mbuf = br_tail(spop_conn->mbuf);
  retry:
	if (!spop_get_buf(spop_conn, mbuf)) {
		spop_conn->flags |= SPOP_CF_MUX_MALLOC;
		spop_strm->flags |= SPOP_SF_BLK_MROOM;
		TRACE_STATE("waiting for fconn mbuf ring allocation", SPOP_EV_TX_FRAME|SPOP_EV_TX_NOTIFY|SPOP_EV_SPOP_STRM_BLK, spop_conn->conn, spop_strm);
		ret = 0;
		goto end;
	}

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 11 || !b_space_wraps(mbuf))
			break;
	  realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 11)
		goto full;

	/* len: 4-bytes (fill later) type: (2)HAPROXY-NOTIFY, flags: 4-bytes (FIN=1) */
	memcpy(outbuf.area, "\x00\x00\x00\x00\x03\x00\x00\x00\x01", 9);
	outbuf.data = 9;

	p = b_tail(&outbuf);
	end = b_orig(&outbuf) + b_size(&outbuf);

	if (encode_varint(spop_strm->id, &p, end) == -1)
		goto full;
	if (encode_varint(spop_strm->fid+1, &p, end) == -1)
		goto full;

	sz = count - 1; /* Skip the frame type */
	if (p + sz > end)
		goto full;
	memcpy(p, b_peek(buf,1), sz);
	p += sz;

	outbuf.data += p - b_tail(&outbuf);

	/* update the frame's size now */
	TRACE_PROTO("SPOP HAPROXY NOTIFY frame xferred", SPOP_EV_TX_FRAME|SPOP_EV_TX_NOTIFY, spop_conn->conn, spop_strm, 0, (size_t[]){outbuf.data});
	spop_set_frame_size(outbuf.area, outbuf.data - 4);
	spop_strm->fid++;
	b_add(mbuf, outbuf.data);
	b_del(buf, count);
	ret = count;

  end:
	TRACE_LEAVE(SPOP_EV_TX_FRAME|SPOP_EV_TX_NOTIFY, spop_conn->conn, spop_strm);
	return ret;
  full:
	/* Too large to be encoded. For NOTIFY frame, it is an error */
	if (!b_data(mbuf)) {
		TRACE_ERROR("SPOP HAPROXY NOTIFY frame too large", SPOP_EV_TX_FRAME|SPOP_EV_TX_NOTIFY|SPOP_EV_SPOP_STRM_ERR, spop_conn->conn, spop_strm);
		spop_strm_error(spop_strm, SPOP_ERR_TOO_BIG);
		goto fail;
	}

	if ((mbuf = br_tail_add(spop_conn->mbuf)) != NULL)
		goto retry;
	spop_conn->flags |= SPOP_CF_MUX_MFULL;
	spop_strm->flags |= SPOP_SF_BLK_MROOM;
	TRACE_STATE("mbuf ring full", SPOP_EV_TX_FRAME|SPOP_EV_TX_NOTIFY|SPOP_EV_SPOP_STRM_BLK, spop_conn->conn, spop_strm);
	ret = 0;
	goto end;
  fail:
	TRACE_DEVEL("leaving on error", SPOP_EV_TX_FRAME|SPOP_EV_TX_NOTIFY|SPOP_EV_SPOP_STRM_ERR, spop_conn->conn, spop_strm);
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
static size_t spop_rcv_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct spop_strm *spop_strm = __sc_mux_strm(sc);
	struct spop_conn *spop_conn = spop_strm->spop_conn;
	size_t ret = 0;

	TRACE_ENTER(SPOP_EV_STRM_RECV, spop_conn->conn, spop_strm, 0, (size_t[]){count});

	ret = b_xfer(buf, &spop_strm->rxbuf, MIN(b_data(&spop_strm->rxbuf), count));
	if (b_data(&spop_strm->rxbuf))
		se_fl_set(spop_strm->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
	else {
		se_fl_clr(spop_strm->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		spop_strm_propagate_term_flags(spop_conn, spop_strm);
		if (b_size(&spop_strm->rxbuf)) {
			b_free(&spop_strm->rxbuf);
			offer_buffers(NULL, 1);
		}
	}

	if (ret && spop_conn->dsi == spop_strm->id) { // TODO must match the frame id too !!!!
		/* demux is blocking on this stream's buffer */
		spop_conn->flags &= ~SPOP_CF_DEM_SFULL;
		spop_conn_restart_reading(spop_conn, 1);
	}

	TRACE_LEAVE(SPOP_EV_STRM_RECV, spop_conn->conn, spop_strm, 0, (size_t[]){ret});
	return ret;
}


/* Called from the upper layer, to send data from buffer <buf> for no more than
 * <count> bytes. Returns the number of bytes effectively sent. Some status
 * flags may be updated on the stream connector.
 */
static size_t spop_snd_buf(struct stconn *sc, struct buffer *buf, size_t count, int flags)
{
	struct spop_strm *spop_strm = __sc_mux_strm(sc);
	struct spop_conn *spop_conn = spop_strm->spop_conn;
	size_t total = 0;
	size_t ret;

	TRACE_ENTER(SPOP_EV_STRM_SEND, spop_conn->conn, spop_strm, 0, (size_t[]){count});

	/* If we were not just woken because we wanted to send but couldn't,
	 * and there's somebody else that is waiting to send, do nothing,
	 * we will subscribe later and be put at the end of the list
	 */
	if (!(spop_strm->flags & SPOP_SF_NOTIFIED) && !LIST_ISEMPTY(&spop_conn->send_list)) {
		if (LIST_INLIST(&spop_strm->list))
			TRACE_DEVEL("stream already waiting, leaving", SPOP_EV_STRM_SEND|SPOP_EV_SPOP_STRM_BLK, spop_conn->conn, spop_strm);
		else {
			TRACE_DEVEL("other streams already waiting, going to the queue and leaving", SPOP_EV_STRM_SEND|SPOP_EV_SPOP_STRM_BLK,
				    spop_conn->conn, spop_strm);
			spop_conn->flags |= SPOP_CF_WAIT_INLIST;
		}
		return 0;
	}
	spop_strm->flags &= ~SPOP_SF_NOTIFIED;

	if (spop_conn->state < SPOP_CS_FRAME_H) {
		TRACE_DEVEL("connection not ready, leaving", SPOP_EV_STRM_SEND|SPOP_EV_SPOP_STRM_BLK, spop_conn->conn, spop_strm);
		return 0;
	}

	if (spop_conn->state >= SPOP_CS_ERROR) {
		se_fl_set(spop_strm->sd, SE_FL_ERROR);
		TRACE_DEVEL("connection is in error, leaving in error", SPOP_EV_STRM_SEND|SPOP_EV_SPOP_STRM_ERR|SPOP_EV_STRM_ERR,
			    spop_conn->conn, spop_strm);
		return 0;
	}

	if (spop_strm->id == 0) {
		int32_t id = spop_conn_get_next_sid(spop_conn);

		if (id < 0) {
			se_fl_set(spop_strm->sd, SE_FL_ERROR);
			TRACE_DEVEL("couldn't get a stream ID, leaving in error", SPOP_EV_STRM_SEND|SPOP_EV_SPOP_STRM_ERR|SPOP_EV_STRM_ERR,
				    spop_conn->conn, spop_strm);
			return 0;
		}

		eb32_delete(&spop_strm->by_id);
		spop_strm->by_id.key = spop_strm->id = id;
		spop_strm->state = SPOP_SS_OPEN;
		spop_conn->max_id = id;
		spop_conn->nb_reserved--;
		eb32_insert(&spop_conn->streams_by_id, &spop_strm->by_id);
	}

	while (spop_strm->state < SPOP_SS_HLOC && !(spop_strm->flags & SPOP_SF_BLK_ANY) && count) {
		enum spop_frame_type type = *b_peek(buf, 0);

		switch (type) {
		case SPOP_FRM_T_HAPROXY_NOTIFY:
			ret = spop_strm_send_notify(spop_strm, buf, count);
			if (ret > 0) {
				total += ret;
				count -= ret;
			}
			break;
		default:
			TRACE_DEVEL("Unsupported frame type", SPOP_EV_STRM_SEND|SPOP_EV_STRM_ERR|SPOP_EV_SPOP_STRM_ERR,
				    spop_conn->conn, spop_strm, 0, (size_t[]){type});
			spop_strm_error(spop_strm, SPOP_ERR_INVALID);
			break;
		}
	}

	if (spop_strm->state >= SPOP_SS_HLOC) {
		/* trim any possibly pending data after we close */
		total += count;
		count = 0;
	}
	/* RST are sent similarly to frame acks */
	if (spop_strm->state == SPOP_SS_ERROR) {
		TRACE_DEVEL("reporting error to the app-layer stream", SPOP_EV_STRM_SEND|SPOP_EV_STRM_ERR|SPOP_EV_SPOP_STRM_ERR, spop_conn->conn, spop_strm);
		se_fl_set_error(spop_strm->sd);
		spop_strm_close(spop_strm);
	}

	if (total > 0) {
		if (!(spop_conn->wait_event.events & SUB_RETRY_SEND)) {
			TRACE_DEVEL("data queued, waking up spop_conn sender", SPOP_EV_STRM_SEND|SPOP_EV_SPOP_CONN_SEND, spop_conn->conn, spop_strm);
			if (spop_send(spop_conn))
				tasklet_wakeup(spop_conn->wait_event.tasklet);
		}

	}

	if (total > 0) {
		/* Ok we managed to send something, leave the send_list if we were still there */
		spop_remove_from_list(spop_strm);
		TRACE_DEVEL("Removed from spop_strm list", SPOP_EV_STRM_SEND|SPOP_EV_SPOP_CONN_SEND, spop_conn->conn, spop_strm);
	}

	TRACE_LEAVE(SPOP_EV_STRM_SEND, spop_conn->conn, spop_strm, 0, (size_t[]){total});
	return total;
}


/* for debugging with CLI's "show fd" command */
static int spop_show_fd(struct buffer *msg, struct connection *conn)
{
	struct spop_conn *spop_conn = conn->ctx;
	struct spop_strm *spop_strm = NULL;
	struct eb32_node *node;
	int send_cnt = 0;
	int tree_cnt = 0;
	int orph_cnt = 0;
	struct buffer *hmbuf, *tmbuf;

	if (!spop_conn)
		return 0;

	list_for_each_entry(spop_strm, &spop_conn->send_list, list)
		send_cnt++;

	spop_strm = NULL;
	node = eb32_first(&spop_conn->streams_by_id);
	while (node) {
		spop_strm = container_of(node, struct spop_strm, by_id);
		tree_cnt++;
		if (!spop_strm_sc(spop_strm))
			orph_cnt++;
		node = eb32_next(node);
	}

	hmbuf = br_head(spop_conn->mbuf);
	tmbuf = br_tail(spop_conn->mbuf);
	chunk_appendf(msg, " spop_conn.st0=%d .maxid=%d .flg=0x%04x .nbst=%u"
		      " .nbcs=%u .send_cnt=%d .tree_cnt=%d .orph_cnt=%d .sub=%d "
		      ".dsi=%d .dbuf=%u@%p+%u/%u .mbuf=[%u..%u|%u],h=[%u@%p+%u/%u],t=[%u@%p+%u/%u]",
		      spop_conn->state, spop_conn->max_id, spop_conn->flags,
		      spop_conn->nb_streams, spop_conn->nb_sc, send_cnt, tree_cnt, orph_cnt,
		      spop_conn->wait_event.events, spop_conn->dsi,
		      (unsigned int)b_data(&spop_conn->dbuf), b_orig(&spop_conn->dbuf),
		      (unsigned int)b_head_ofs(&spop_conn->dbuf), (unsigned int)b_size(&spop_conn->dbuf),
		      br_head_idx(spop_conn->mbuf), br_tail_idx(spop_conn->mbuf), br_size(spop_conn->mbuf),
		      (unsigned int)b_data(hmbuf), b_orig(hmbuf),
		      (unsigned int)b_head_ofs(hmbuf), (unsigned int)b_size(hmbuf),
		      (unsigned int)b_data(tmbuf), b_orig(tmbuf),
		      (unsigned int)b_head_ofs(tmbuf), (unsigned int)b_size(tmbuf));

	if (spop_strm) {
		chunk_appendf(msg, " last_spop_strm=%p .id=%d .flg=0x%04x .rxbuf=%u@%p+%u/%u .sc=%p",
			      spop_strm, spop_strm->id, spop_strm->flags,
			      (unsigned int)b_data(&spop_strm->rxbuf), b_orig(&spop_strm->rxbuf),
			      (unsigned int)b_head_ofs(&spop_strm->rxbuf), (unsigned int)b_size(&spop_strm->rxbuf),
			      spop_strm_sc(spop_strm));

		chunk_appendf(msg, " .sd.flg=0x%08x", se_fl_get(spop_strm->sd));
		if (!se_fl_test(spop_strm->sd, SE_FL_ORPHAN))
			chunk_appendf(msg, " .sc.flg=0x%08x .sc.app=%p",
				      spop_strm_sc(spop_strm)->flags, spop_strm_sc(spop_strm)->app);

		chunk_appendf(msg, " .subs=%p", spop_strm->subs);
		if (spop_strm->subs) {
			chunk_appendf(msg, "(ev=%d tl=%p", spop_strm->subs->events, spop_strm->subs->tasklet);
			chunk_appendf(msg, " tl.calls=%d tl.ctx=%p tl.fct=",
				      spop_strm->subs->tasklet->calls,
				      spop_strm->subs->tasklet->context);
			resolve_sym_name(msg, NULL, spop_strm->subs->tasklet->process);
			chunk_appendf(msg, ")");
		}
	}
	return 0;
}

/* Migrate the the connection to the current thread.
 * Return 0 if successful, non-zero otherwise.
 * Expected to be called with the old thread lock held.
 */
static int spop_takeover(struct connection *conn, int orig_tid, int release)
{
	struct spop_conn *spop_conn = conn->ctx;
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
		if (LIST_INLIST(&spop_conn->buf_wait.list))
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
		tasklet_wakeup_on(spop_conn->wait_event.tasklet, orig_tid);
		goto fail;
	}

	if (spop_conn->wait_event.events)
		spop_conn->conn->xprt->unsubscribe(spop_conn->conn, spop_conn->conn->xprt_ctx,
		    spop_conn->wait_event.events, &spop_conn->wait_event);

	task = spop_conn->task;
	if (task) {
		/* only assign a task if there was already one, otherwise
		 * the preallocated new task will be released.
		 */
		task->context = NULL;
		spop_conn->task = NULL;
		__ha_barrier_store();
		task_kill(task);

		spop_conn->task = new_task;
		new_task = NULL;
		if (!release) {
			spop_conn->task->process = spop_timeout_task;
			spop_conn->task->context = spop_conn;
		}
	}

	/* To let the tasklet know it should free itself, and do nothing else,
	 * set its context to NULL;
	 */
	spop_conn->wait_event.tasklet->context = NULL;
	tasklet_wakeup_on(spop_conn->wait_event.tasklet, orig_tid);

	spop_conn->wait_event.tasklet = new_tasklet;
	if (!release) {
		spop_conn->wait_event.tasklet->process = spop_io_cb;
		spop_conn->wait_event.tasklet->context = spop_conn;
		spop_conn->conn->xprt->subscribe(spop_conn->conn, spop_conn->conn->xprt_ctx,
						 SUB_RETRY_RECV, &spop_conn->wait_event);
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
		if (LIST_INLIST(&spop_conn->buf_wait.list))
			_b_dequeue(&spop_conn->buf_wait, orig_tid);
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

static const struct mux_ops mux_spop_ops = {
	.init          = spop_init,
	.wake          = spop_wake,
	.attach        = spop_attach,
	.get_first_sc  = spop_get_first_sc,
	.detach        = spop_detach,
	.destroy       = spop_destroy,
	.avail_streams = spop_avail_streams,
	.used_streams  = spop_used_streams,
	.rcv_buf       = spop_rcv_buf,
	.snd_buf       = spop_snd_buf,
	.subscribe     = spop_subscribe,
	.unsubscribe   = spop_unsubscribe,
	.shut          = spop_shut,
	.ctl           = spop_ctl,
	.sctl          = spop_sctl,
	.show_fd       = spop_show_fd,
	.takeover      = spop_takeover,
	.flags         = MX_FL_HOL_RISK|MX_FL_NO_UPG,
	.name          = "SPOP",
};

static struct mux_proto_list mux_proto_spop =
	{ .token = IST("spop"), .mode = PROTO_MODE_SPOP, .side = PROTO_SIDE_BE, .mux = &mux_spop_ops };

static struct mux_proto_list mux_proto_default_spop =
	{ .token = IST(""), .mode = PROTO_MODE_SPOP, .side = PROTO_SIDE_BE, .mux = &mux_spop_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_spop);
INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_default_spop);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
