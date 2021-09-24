/*
 * QUIC mux-demux for connections
 *
 * Copyright 2021 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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
#include <haproxy/h3.h>
#include <haproxy/istbuf.h>
#include <haproxy/log.h>
#include <haproxy/mux_quic.h>
#include <haproxy/net_helper.h>
#include <haproxy/quic_frame.h>
#include <haproxy/session-t.h>
#include <haproxy/stats.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/trace.h>

/* dummy streams returned for closed, error, refused, idle and states */
static const struct qcs *qc_closed_stream;

#define QC_SS_MASK(state) (1UL << (state))
#define QC_SS_IDLE_BIT    (1UL << QC_SS_IDLE)
#define QC_SS_RLOC_BIT    (1UL << QC_SS_RLOC)
#define QC_SS_RREM_BIT    (1UL << QC_SS_RREM)
#define QC_SS_OPEN_BIT    (1UL << QC_SS_OPEN)
#define QC_SS_HREM_BIT    (1UL << QC_SS_HREM)
#define QC_SS_HLOC_BIT    (1UL << QC_SS_HLOC)
#define QC_SS_ERROR_BIT   (1UL << QC_SS_ERROR)
#define QC_SS_CLOSED_BIT  (1UL << QC_SS_CLOSED)


/* trace source and events */
static void qc_trace(enum trace_level level, uint64_t mask, \
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   strm  - application layer
 *   qcs   - internal QUIC stream
 *   qcc   - internal QUIC connection
 *   conn  - external connection
 *
 */
static const struct trace_event qc_trace_events[] = {
#define           QC_EV_QCC_NEW       (1ULL <<  0)
	{ .mask = QC_EV_QCC_NEW,      .name = "qcc_new",     .desc = "new QUIC connection" },
#define           QC_EV_QCC_RECV      (1ULL <<  1)
	{ .mask = QC_EV_QCC_RECV,     .name = "qcc_recv",    .desc = "Rx on QUIC connection" },
#define           QC_EV_QCC_SEND      (1ULL <<  2)
	{ .mask = QC_EV_QCC_SEND,     .name = "qcc_send",    .desc = "Tx on QUIC connection" },
#define           QC_EV_QCC_FCTL      (1ULL <<  3)
	{ .mask = QC_EV_QCC_FCTL,     .name = "qcc_fctl",    .desc = "QUIC connection flow-controlled" },
#define           QC_EV_QCC_BLK       (1ULL <<  4)
	{ .mask = QC_EV_QCC_BLK,      .name = "qcc_blk",     .desc = "QUIC connection blocked" },
#define           QC_EV_QCC_WAKE      (1ULL <<  5)
	{ .mask = QC_EV_QCC_WAKE,     .name = "qcc_wake",    .desc = "QUIC connection woken up" },
#define           QC_EV_QCC_END       (1ULL <<  6)
	{ .mask = QC_EV_QCC_END,      .name = "qcc_end",     .desc = "QUIC connection terminated" },
#define           QC_EV_QCC_ERR       (1ULL <<  7)
	{ .mask = QC_EV_QCC_ERR,      .name = "qcc_err",     .desc = "error on QUIC connection" },
#define           QC_EV_TX_FRAME      (1ULL <<  8)
	{ .mask = QC_EV_TX_FRAME,     .name = "tx_frame",    .desc = "transmission of any QUIC frame" },
#define           QC_EV_QCS_NEW       (1ULL <<  9)
	{ .mask = QC_EV_QCS_NEW,      .name = "qcs_new",     .desc = "new QUIC stream" },
#define           QC_EV_QCS_GET       (1ULL << 10)
	{ .mask = QC_EV_QCS_GET,      .name = "qcs_get",     .desc = "get QUIC stream by ID" },
#define           QC_EV_QCS_SEND      (1ULL << 11)
	{ .mask = QC_EV_QCS_SEND,     .name = "qcs_send",    .desc = "Tx for QUIC stream" },
#define           QC_EV_QCS_FCTL      (1ULL << 12)
	{ .mask = QC_EV_QCS_FCTL,     .name = "qcs_fctl",    .desc = "QUIC stream flow-controlled" },
#define           QC_EV_QCS_BLK       (1ULL << 13)
	{ .mask = QC_EV_QCS_BLK,      .name = "qcs_blk",     .desc = "QUIC stream blocked" },
#define           QC_EV_QCS_WAKE      (1ULL << 14)
	{ .mask = QC_EV_QCS_WAKE,     .name = "qcs_wake",    .desc = "QUIC stream woken up" },
#define           QC_EV_QCS_END       (1ULL << 15)
	{ .mask = QC_EV_QCS_END,      .name = "qcs_end",     .desc = "QUIC stream terminated" },
#define           QC_EV_QCS_ERR       (1ULL << 16)
	{ .mask = QC_EV_QCS_ERR,      .name = "qcs_err",     .desc = "error on QUIC stream" },
#define           QC_EV_STRM_NEW      (1ULL << 17)
	{ .mask = QC_EV_STRM_NEW,     .name = "strm_new",    .desc = "app-layer stream creation" },
#define           QC_EV_STRM_RECV     (1ULL << 18)
	{ .mask = QC_EV_STRM_RECV,    .name = "strm_recv",   .desc = "receiving data for stream" },
#define           QC_EV_STRM_SEND     (1ULL << 19)
	{ .mask = QC_EV_STRM_SEND,    .name = "strm_send",   .desc = "sending data for stream" },
#define           QC_EV_STRM_FULL     (1ULL << 20)
	{ .mask = QC_EV_STRM_FULL,    .name = "strm_full",   .desc = "stream buffer full" },
#define           QC_EV_STRM_WAKE     (1ULL << 21)
	{ .mask = QC_EV_STRM_WAKE,    .name = "strm_wake",   .desc = "stream woken up" },
#define           QC_EV_STRM_SHUT     (1ULL << 22)
	{ .mask = QC_EV_STRM_SHUT,    .name = "strm_shut",   .desc = "stream shutdown" },
#define           QC_EV_STRM_END      (1ULL << 23)
	{ .mask = QC_EV_STRM_END,     .name = "strm_end",    .desc = "detaching app-layer stream" },
#define           QC_EV_STRM_ERR      (1ULL << 24)
	{ .mask = QC_EV_STRM_ERR,     .name = "strm_err",    .desc = "stream error" },
	{ }
};

static const struct name_desc qc_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name = "qcs", .desc = "QUIC stream" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc qc_trace_decoding[] = {
#define QC_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define QC_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only qcc/qcs state and flags, no real decoding" },
#define QC_VERB_SIMPLE   3
	{ .name="simple",   .desc="add request/response status line or frame info when available" },
#define QC_VERB_ADVANCED 4
	{ .name="advanced", .desc="add header fields or frame decoding when available" },
#define QC_VERB_COMPLETE 5
	{ .name="complete", .desc="add full data dump when available" },
	{ /* end */ }
};

static struct trace_source trace_mux_quic = {
	.name = IST("mux_quic"),
	.desc = "QUIC multiplexer",
	.arg_def = TRC_ARG1_CONN,  // TRACE()'s first argument is always a connection
	.default_cb = qc_trace,
	.known_events = qc_trace_events,
	.lockon_args = qc_trace_lockon_args,
	.decoding = qc_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_mux_quic
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* quic stats module */
enum {
	QC_ST_RESET_STREAM_RCVD,

	QC_ST_CONN_PROTO_ERR,
	QC_ST_STRM_PROTO_ERR,
	QC_ST_RESET_STREAM_SENT,

	QC_ST_OPEN_CONN,
	QC_ST_OPEN_STREAM,
	QC_ST_TOTAL_CONN,
	QC_ST_TOTAL_STREAM,

	QC_STATS_COUNT /* must be the last member of the enum */
};

static struct name_desc qc_stats[] = {
	[QC_ST_RESET_STREAM_RCVD] = { .name = "qc_rst_stream_rcvd",
	                              .desc = "Total number of received RESET_STREAM frames" },

	[QC_ST_CONN_PROTO_ERR]    = { .name = "qc_detected_conn_protocol_errors",
	                              .desc = "Total number of connection protocol errors" },
	[QC_ST_STRM_PROTO_ERR]    = { .name = "qc_detected_strm_protocol_errors",
	                              .desc = "Total number of stream protocol errors" },
	[QC_ST_RESET_STREAM_SENT] = { .name = "qc_rst_stream_resp",
	                              .desc = "Total number of RESET_STREAM sent on detected error" },

	[QC_ST_OPEN_CONN]    = { .name = "qc_open_connections",
	                         .desc = "Count of currently open connections" },
	[QC_ST_OPEN_STREAM]  = { .name = "qc_backend_open_streams",
	                         .desc = "Count of currently open streams" },
	[QC_ST_TOTAL_CONN]   = { .name = "qc_open_connections",
	                         .desc = "Total number of connections" },
	[QC_ST_TOTAL_STREAM] = { .name = "qc_backend_open_streams",
	                         .desc = "Total number of streams" },
};

static struct qc_counters {
	long long rst_stream_rcvd; /* total number of RESET_STREAM frame received */

	long long conn_proto_err;  /* total number of protocol errors detected */
	long long strm_proto_err;  /* total number of protocol errors detected */
	long long rst_stream_resp; /* total number of RESET_STREAM frame sent on error */

	long long open_conns;    /* count of currently open connections */
	long long open_streams;  /* count of currently open streams */
	long long total_conns;   /* total number of connections */
	long long total_streams; /* total number of streams */
} qc_counters;

static void qc_fill_stats(void *data, struct field *stats)
{
	struct qc_counters *counters = data;

	stats[QC_ST_RESET_STREAM_RCVD] = mkf_u64(FN_COUNTER, counters->rst_stream_rcvd);

	stats[QC_ST_CONN_PROTO_ERR]  = mkf_u64(FN_COUNTER, counters->conn_proto_err);
	stats[QC_ST_STRM_PROTO_ERR]  = mkf_u64(FN_COUNTER, counters->strm_proto_err);
	stats[QC_ST_RESET_STREAM_SENT] = mkf_u64(FN_COUNTER, counters->rst_stream_resp);

	stats[QC_ST_OPEN_CONN]    = mkf_u64(FN_GAUGE,   counters->open_conns);
	stats[QC_ST_OPEN_STREAM]  = mkf_u64(FN_GAUGE,   counters->open_streams);
	stats[QC_ST_TOTAL_CONN]   = mkf_u64(FN_COUNTER, counters->total_conns);
	stats[QC_ST_TOTAL_STREAM] = mkf_u64(FN_COUNTER, counters->total_streams);
}

static struct stats_module qc_stats_module = {
	.name          = "quic",
	.fill_stats    = qc_fill_stats,
	.stats         = qc_stats,
	.stats_count   = QC_STATS_COUNT,
	.counters      = &qc_counters,
	.counters_size = sizeof(qc_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_FE|STATS_PX_CAP_BE),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &qc_stats_module);

/* the qcc connection pool */
DECLARE_STATIC_POOL(pool_head_qcc, "qcc", sizeof(struct qcc));
/* the qcs stream pool */
DECLARE_POOL(pool_head_qcs, "qcs", sizeof(struct qcs));

static struct task *qc_timeout_task(struct task *t, void *context, unsigned int state);
static int qc_send(struct qcc *qcc);
static int qc_recv(struct qcc *qcc);
static int qc_process(struct qcc *qcc);
static struct task *qc_io_cb(struct task *t, void *ctx, unsigned int state);
static inline struct qcs *qcc_st_by_id(struct qcc *qcc, int id);
static struct task *qc_deferred_shut(struct task *t, void *ctx, unsigned int state);
static struct qcs *qcc_bck_stream_new(struct qcc *qcc, int dir,
                                      struct conn_stream *cs, struct session *sess);
static void qcs_alert(struct qcs *qcs);

/* returns a qcc state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *qcc_st_to_str(enum qc_cs st)
{
	switch (st) {
	case QC_CS_NOERR:     return "NER";
	default:              return "???";
	}
}

/* marks an error on the connection */
void qc_error(struct qcc *qcc, int err)
{
	TRACE_POINT(QC_EV_QCC_ERR, qcc->conn, 0, 0, (void *)(long)(err));
	qcc->errcode = err;
	qcc->st0 = QC_CS_ERROR;
}

static inline const char *qcs_rx_st_to_str(enum qcs_rx_st st)
{
	switch (st) {
	case QC_RX_SS_IDLE:       return "IDL";
	case QC_RX_SS_RECV:       return "RCV";
	case QC_RX_SS_SIZE_KNOWN: return "SKNWN";
	case QC_RX_SS_DATA_RECVD: return "DATARCVD";
	case QC_RX_SS_DATA_READ : return "DATAREAD";
	case QC_RX_SS_RST_RECVD:  return "RSTRCVD";
	case QC_RX_SS_RST_READ:   return "RSTREAD";
	default:                  return "???";
	}
}

static inline const char *qcs_tx_st_to_str(enum qcs_tx_st st)
{
	switch (st) {
	case QC_TX_SS_IDLE:       return "IDL";
	case QC_TX_SS_READY:      return "READY";
	case QC_TX_SS_SEND:       return "SEND";
	case QC_TX_SS_DATA_SENT:  return "DATASENT";
	case QC_TX_SS_DATA_RECVD: return "DATARCVD";
	case QC_TX_SS_RST_SENT:   return "RSTSENT";
	case QC_TX_SS_RST_RECVD:  return "RSTRCVD";
    default:                  return "???";
	}
}

/* the QUIC traces always expect that arg1, if non-null, is of type connection
 * (from which we can derive qcc), that arg2, if non-null, is of type qcs.
 */
static void qc_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct qcc *qcc = conn ? conn->ctx : NULL;
	const struct qcs *qcs = a2;

	if (!qcc)
		return;

	if (src->verbosity > QC_VERB_CLEAN) {
		chunk_appendf(&trace_buf, " : qcc=%p(%c,%s)",
		              qcc, conn_is_back(conn) ? 'B' : 'F', qcc_st_to_str(qcc->st0));
		if (qcs) {
			chunk_appendf(&trace_buf, " qcs=%p(rx.%s,tx.%s)",
			              qcs, qcs_rx_st_to_str(qcs->rx.st), qcs_tx_st_to_str(qcs->tx.st));
		}
	}
}


/* Detect a pending read0 for a QUIC connection. It happens if a read0 is pending
 * on the connection AND if there is no more data in the demux buffer. The
 * function returns 1 to report a read0 or 0 otherwise.
 */
__maybe_unused
static int qcc_read0_pending(struct qcc *qcc)
{
	if (conn_xprt_read0_pending(qcc->conn) && !qcc->rx.inmux)
		return 1;
	return 0;
}

/* returns true if the connection is allowed to expire, false otherwise. A
 * connection may expire when:
 *   - it has no stream
 *   - it has data in the mux buffer
 *   - it has streams in the blocked list
 *   - it has streams in the fctl list
 *   - it has streams in the send list
 * Otherwise it means some streams are waiting in the data layer and it should
 * not expire.
 */
__maybe_unused
static inline int qcc_may_expire(const struct qcc *qcc)
{
	return eb_is_empty(&qcc->streams_by_id) ||
	       br_data(qcc->mbuf) ||
	       !LIST_ISEMPTY(&qcc->blocked_list) ||
	       !LIST_ISEMPTY(&qcc->fctl_list) ||
	       !LIST_ISEMPTY(&qcc->send_list);
}

static __inline int
qcc_is_dead(const struct qcc *qcc)
{
	if (eb_is_empty(&qcc->streams_by_id) &&     /* don't close if streams exist */
	    ((qcc->conn->flags & CO_FL_ERROR) ||    /* errors close immediately */
	     (qcc->st0 >= QC_CS_ERROR && !qcc->task) || /* a timeout stroke earlier */
	     (!(qcc->conn->owner)) || /* Nobody's left to take care of the connection, drop it now */
	     (!br_data(qcc->mbuf) &&  /* mux buffer empty, also process clean events below */
	      conn_xprt_read0_pending(qcc->conn))))
		return 1;

	return 0;
}

/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/

/* indicates whether or not the we may call the qc_recv() function to attempt
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
static inline int qc_recv_allowed(const struct qcc *qcc)
{
	if (qcc->rx.inmux == 0 &&
	    (qcc->st0 >= QC_CS_ERROR ||
	     qcc->conn->flags & CO_FL_ERROR ||
	     conn_xprt_read0_pending(qcc->conn)))
		return 0;

	if (!(qcc->flags & QC_CF_DEM_BLOCK_ANY))
		return 1;

	return 0;
}

/* restarts reading on the connection if it was not enabled */
static inline void qcc_restart_reading(const struct qcc *qcc, int consider_buffer)
{
	if (!qc_recv_allowed(qcc))
		return;

	if ((!consider_buffer || !qcc->rx.inmux)
	    && (qcc->wait_event.events & SUB_RETRY_RECV))
		return;

	tasklet_wakeup(qcc->wait_event.tasklet);
}

/* Tries to grab a buffer and to re-enable processing on mux <target>. The qcc
 * flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the connection is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
static int qc_buf_available(void *target)
{
	struct qcc *qcc = target;

	if ((qcc->flags & QC_CF_MUX_MALLOC) && b_alloc(br_tail(qcc->mbuf))) {
		qcc->flags &= ~QC_CF_MUX_MALLOC;

		if (qcc->flags & QC_CF_DEM_MROOM) {
			qcc->flags &= ~QC_CF_DEM_MROOM;
			qcc_restart_reading(qcc, 1);
		}
		return 1;
	}

#if 0
	if ((qcc->flags & QC_CF_DEM_SALLOC) &&
	    (qcs = qcc_st_by_id(qcc, qcc->dsi)) && qcs->cs &&
	    b_alloc_margin(&qcs->rxbuf, 0)) {
		qcc->flags &= ~QC_CF_DEM_SALLOC;
		qcc_restart_reading(qcc, 1);
		return 1;
	}
#endif

	return 0;
}

struct buffer *qc_get_buf(struct qcc *qcc, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&qcc->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr)) == NULL)) {
		qcc->buf_wait.target = qcc;
		qcc->buf_wait.wakeup_cb = qc_buf_available;
		LIST_APPEND(&ti->buffer_wq, &qcc->buf_wait.list);
	}

	return buf;
}

__maybe_unused
static inline void qc_release_buf(struct qcc *qcc, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(NULL, 1);
	}
}

static inline void qc_release_mbuf(struct qcc *qcc)
{
	struct buffer *buf;
	unsigned int count = 0;

	while (b_size(buf = br_head_pick(qcc->mbuf))) {
		b_free(buf);
		count++;
	}
	if (count)
		offer_buffers(NULL, count);
}

/* returns the number of streams in use on a connection to figure if it's
 * idle or not. We check nb_cs and not nb_streams as the caller will want
 * to know if it was the last one after a detach().
 */
static int qc_used_streams(struct connection *conn)
{
	struct qcc *qcc = conn->ctx;

	return qcc->nb_cs;
}

/* returns the number of concurrent streams available on the connection with <dir>
 * as direction
 */
static int qc_avail_streams(struct connection *conn, enum qcs_dir dir)
{
	struct qcc *qcc = conn->ctx;
	enum qcs_type qcs_type;

	if (qcc->st0 >= QC_CS_ERROR)
		return 0;

	qcs_type = qcs_type_from_dir(qcc, dir);

	return qcc->strms[qcs_type].max_streams - qcc->strms[qcs_type].nb_streams;
}


/* returns the number of concurrent bidirectional streams available on the
 * connection.
 */
static int qc_avail_streams_bidi(struct connection *conn)
{
	return qc_avail_streams(conn, QCS_BIDI);
}

/* returns the number of concurrent unidirectional streams available on the
 * connection.
 */
static int qc_avail_streams_uni(struct connection *conn)
{
	return qc_avail_streams(conn, QCS_UNI);
}

/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/

/* Update the mux transport parameter after having received remote transpot parameters */
void quic_mux_transport_params_update(struct qcc *qcc)
{
	if (objt_listener(qcc->conn->target)) {
		struct quic_transport_params *clt_params;

		/* Client parameters, params used to TX. */
		clt_params = &qcc->conn->qc->tx.params;

		qcc->tx.max_data = clt_params->initial_max_data;
		/* Client initiated streams must respect the server flow control. */
		qcc->strms[QCS_CLT_BIDI].rx.max_data = clt_params->initial_max_stream_data_bidi_local;
		qcc->strms[QCS_CLT_UNI].rx.max_data = clt_params->initial_max_stream_data_uni;

		/* Server initiated streams must respect the server flow control. */
		qcc->strms[QCS_SRV_BIDI].max_streams = clt_params->initial_max_streams_bidi;
		qcc->strms[QCS_SRV_BIDI].tx.max_data = clt_params->initial_max_stream_data_bidi_remote;

		qcc->strms[QCS_SRV_UNI].max_streams = clt_params->initial_max_streams_uni;
		qcc->strms[QCS_SRV_UNI].tx.max_data = clt_params->initial_max_stream_data_uni;
	}
	else {
		struct quic_transport_params *srv_params;

		/* server parameters, TX params. */
		srv_params = &qcc->conn->qc->tx.params;

		qcc->tx.max_data = srv_params->initial_max_data;
		/* Client initiated streams must respect the server flow control. */
		qcc->strms[QCS_CLT_BIDI].max_streams = srv_params->initial_max_streams_bidi;
		qcc->strms[QCS_CLT_BIDI].tx.max_data = srv_params->initial_max_stream_data_bidi_remote;

		qcc->strms[QCS_CLT_UNI].max_streams = srv_params->initial_max_streams_uni;
		qcc->strms[QCS_CLT_UNI].tx.max_data = srv_params->initial_max_stream_data_uni;

		/* Server initiated streams must respect the server flow control. */
		qcc->strms[QCS_SRV_BIDI].rx.max_data = srv_params->initial_max_stream_data_bidi_local;
		qcc->strms[QCS_SRV_UNI].rx.max_data = srv_params->initial_max_stream_data_uni;
	}

	/* Now that we have all the flow control information, we can finalize the application
	 * context.
	 */
	qcc->app_ops->finalize(qcc->ctx);
}

/* Initialize the mux once it's attached. For outgoing connections, the context
 * is already initialized before installing the mux, so we detect incoming
 * connections from the fact that the context is still NULL (even during mux
 * upgrades). <input> is always used as Input buffer and may contain data. It is
 * the caller responsibility to not reuse it anymore. Returns < 0 on error.
 */
static int qc_init(struct connection *conn, struct proxy *prx,
                   struct session *sess, struct buffer *input)
{
	struct qcc *qcc;
	struct task *t = NULL;
	void *conn_ctx = conn->ctx;

	TRACE_ENTER(QC_EV_QCC_NEW);

	qcc = pool_alloc(pool_head_qcc);
	if (!qcc)
		goto fail_no_qcc;

	if (conn_is_back(conn)) {
		qcc->flags = QC_CF_IS_BACK;
		qcc->shut_timeout = qcc->timeout = prx->timeout.server;
		if (tick_isset(prx->timeout.serverfin))
			qcc->shut_timeout = prx->timeout.serverfin;

		qcc->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_be,
		                                      &qc_stats_module);
	} else {
		qcc->flags = QC_CF_NONE;
		qcc->shut_timeout = qcc->timeout = prx->timeout.client;
		if (tick_isset(prx->timeout.clientfin))
			qcc->shut_timeout = prx->timeout.clientfin;

		qcc->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                                      &qc_stats_module);
	}

	qcc->proxy = prx;
	qcc->task = NULL;
	if (tick_isset(qcc->timeout)) {
		t = task_new_here();
		if (!t)
			goto fail;

		qcc->task = t;
		t->process = qc_timeout_task;
		t->context = qcc;
		t->expire = tick_add(now_ms, qcc->timeout);
	}

	qcc->subs = NULL;
	qcc->wait_event.tasklet = tasklet_new();
	if (!qcc->wait_event.tasklet)
		goto fail;

	qcc->wait_event.tasklet->process = qc_io_cb;
	qcc->wait_event.tasklet->context = qcc;
	qcc->wait_event.events = 0;

	/* Initialize the context. */
	qcc->st0 = QC_CS_NOERR;
	qcc->conn = conn;
	qcc->conn->qc->qcc = qcc;

	/* Application layer initialization. */
	qcc->app_ops = &h3_ops;
	if (!qcc->app_ops->init(qcc))
		goto fail;

	/* The transports parameters which control the data sent have been stored
	 * in ->tx.params. The ones which control the received data are stored in
	 * in ->rx.params.
	 */
	if (objt_listener(qcc->conn->target)) {
		struct quic_transport_params *srv_params;

		/* Server parameters, params used for RX flow control. */
		srv_params = &conn->qc->rx.params;

		qcc->rx.max_data = srv_params->initial_max_data;
		qcc->tx.max_data = 0;
		/* Client initiated streams must respect the server flow control. */
		qcc->strms[QCS_CLT_BIDI].max_streams = srv_params->initial_max_streams_bidi;
		qcc->strms[QCS_CLT_BIDI].nb_streams  = 0;
		qcc->strms[QCS_CLT_BIDI].largest_id  = -1;
		qcc->strms[QCS_CLT_BIDI].rx.max_data = 0;
		qcc->strms[QCS_CLT_BIDI].tx.max_data = srv_params->initial_max_stream_data_bidi_remote;

		qcc->strms[QCS_CLT_UNI].max_streams = srv_params->initial_max_streams_uni;
		qcc->strms[QCS_CLT_UNI].nb_streams = 0;
		qcc->strms[QCS_CLT_UNI].largest_id = -1;
		qcc->strms[QCS_CLT_UNI].rx.max_data = 0;
		qcc->strms[QCS_CLT_UNI].tx.max_data = srv_params->initial_max_stream_data_uni;

		/* Server initiated streams must respect the server flow control. */
		qcc->strms[QCS_SRV_BIDI].max_streams = 0;
		qcc->strms[QCS_SRV_BIDI].nb_streams  = 0;
		qcc->strms[QCS_SRV_BIDI].largest_id  = -1;
		qcc->strms[QCS_SRV_BIDI].rx.max_data = srv_params->initial_max_stream_data_bidi_local;
		qcc->strms[QCS_SRV_BIDI].tx.max_data = 0;

		qcc->strms[QCS_SRV_UNI].max_streams = 0;
		qcc->strms[QCS_SRV_UNI].nb_streams = 0;
		qcc->strms[QCS_SRV_UNI].largest_id = -1;
		qcc->strms[QCS_SRV_UNI].rx.max_data = srv_params->initial_max_stream_data_uni;
		qcc->strms[QCS_SRV_UNI].tx.max_data = 0;
	}
	else {
		struct quic_transport_params *clt_params;

		/* client parameters, RX params. */
		clt_params = &conn->qc->rx.params;

		qcc->rx.max_data = clt_params->initial_max_data;
		qcc->tx.max_data = 0;
		/* Client initiated streams must respect the server flow control. */
		qcc->strms[QCS_CLT_BIDI].max_streams = 0;
		qcc->strms[QCS_CLT_BIDI].nb_streams  = 0;
		qcc->strms[QCS_CLT_BIDI].largest_id  = -1;
		qcc->strms[QCS_CLT_BIDI].rx.max_data = clt_params->initial_max_stream_data_bidi_local;
		qcc->strms[QCS_CLT_BIDI].tx.max_data = 0;

		qcc->strms[QCS_CLT_UNI].max_streams = 0;
		qcc->strms[QCS_CLT_UNI].nb_streams = 0;
		qcc->strms[QCS_CLT_UNI].largest_id = -1;
		qcc->strms[QCS_CLT_UNI].rx.max_data = clt_params->initial_max_stream_data_uni;
		qcc->strms[QCS_CLT_UNI].tx.max_data = 0;

		/* Server initiated streams must respect the server flow control. */
		qcc->strms[QCS_SRV_BIDI].max_streams = clt_params->initial_max_streams_bidi;
		qcc->strms[QCS_SRV_BIDI].nb_streams  = 0;
		qcc->strms[QCS_SRV_BIDI].largest_id  = -1;
		qcc->strms[QCS_SRV_BIDI].rx.max_data = 0;
		qcc->strms[QCS_SRV_BIDI].tx.max_data = clt_params->initial_max_stream_data_bidi_remote;

		qcc->strms[QCS_SRV_UNI].max_streams = clt_params->initial_max_streams_uni;
		qcc->strms[QCS_SRV_UNI].nb_streams = 0;
		qcc->strms[QCS_SRV_UNI].largest_id = -1;
		qcc->strms[QCS_SRV_UNI].rx.max_data = 0;
		qcc->strms[QCS_SRV_UNI].tx.max_data = clt_params->initial_max_stream_data_uni;

	}

	/* Initialize the streams counters. */
	qcc->nb_cs = 0;
	qcc->stream_cnt = 0;

	br_init(qcc->mbuf, sizeof(qcc->mbuf) / sizeof(qcc->mbuf[0]));
	qcc->streams_by_id = EB_ROOT_UNIQUE;
	LIST_INIT(&qcc->send_list);
	LIST_INIT(&qcc->fctl_list);
	LIST_INIT(&qcc->blocked_list);
	LIST_INIT(&qcc->buf_wait.list);
	MT_LIST_INIT(&qcc->qcs_rxbuf_wlist);

	HA_ATOMIC_STORE(&conn->ctx, qcc);

	if (t)
		task_queue(t);

	if (qcc->flags & QC_CF_IS_BACK) {
		/* FIXME: For outgoing connections we need to immediately allocate streams.
		 * This highly depends on the QUIC application needs.
		 */
	}

	HA_ATOMIC_ADD(&qcc->px_counters->open_conns, 1);
	HA_ATOMIC_ADD(&qcc->px_counters->total_conns, 1);

	/* prepare to read something */
	qcc_restart_reading(qcc, 1);
	TRACE_LEAVE(QC_EV_QCC_NEW, conn);
	return 0;

  fail:
	task_destroy(t);
	if (qcc->wait_event.tasklet)
		tasklet_free(qcc->wait_event.tasklet);
	pool_free(pool_head_qcc, qcc);
  fail_no_qcc:
	conn->ctx = conn_ctx; /* restore saved ctx */
	TRACE_DEVEL("leaving in error", QC_EV_QCC_NEW|QC_EV_QCC_END|QC_EV_QCC_ERR);
	return -1;
}

/* returns the stream associated with id <id> or NULL if not found */
__maybe_unused
static inline struct qcs *qcc_st_by_id(struct qcc *qcc, int id)
{
	struct eb64_node *node;

	node = eb64_lookup(&qcc->streams_by_id, id);
	if (!node)
		return (struct qcs *)qc_closed_stream;

	return container_of(node, struct qcs, by_id);
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void qc_release(struct qcc *qcc)
{
	struct connection *conn = NULL;

	TRACE_ENTER(QC_EV_QCC_END);

	if (qcc) {
		/* The connection must be aattached to this mux to be released */
		if (qcc->conn && qcc->conn->ctx == qcc)
			conn = qcc->conn;

		TRACE_DEVEL("freeing qcc", QC_EV_QCC_END, conn);

		if (LIST_INLIST(&qcc->buf_wait.list))
			LIST_DELETE(&qcc->buf_wait.list);

		qc_release_mbuf(qcc);

		if (qcc->task) {
			qcc->task->context = NULL;
			task_wakeup(qcc->task, TASK_WOKEN_OTHER);
			qcc->task = NULL;
		}
		if (qcc->wait_event.tasklet)
			tasklet_free(qcc->wait_event.tasklet);
		if (conn && qcc->wait_event.events != 0)
			conn->xprt->unsubscribe(conn, conn->xprt_ctx, qcc->wait_event.events,
						&qcc->wait_event);

		HA_ATOMIC_SUB(&qcc->px_counters->open_conns, 1);

		pool_free(pool_head_qcc, qcc);
	}

	if (conn) {
		conn->mux = NULL;
		conn->ctx = NULL;
		TRACE_DEVEL("freeing conn", QC_EV_QCC_END, conn);

		conn_stop_tracking(conn);
		conn_full_close(conn);
		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}

	TRACE_LEAVE(QC_EV_QCC_END);
}


/******************************************************/
/* functions below are for the QUIC protocol processing */
/******************************************************/

/* attempt to notify the data layer of recv availability */
__maybe_unused
static void qcs_notify_recv(struct qcs *qcs)
{
	if (qcs->subs && qcs->subs->events & SUB_RETRY_RECV) {
		TRACE_POINT(QC_EV_STRM_WAKE, qcs->qcc->conn, qcs);
		tasklet_wakeup(qcs->subs->tasklet);
		qcs->subs->events &= ~SUB_RETRY_RECV;
		if (!qcs->subs->events)
			qcs->subs = NULL;
	}
}

/* attempt to notify the data layer of send availability */
__maybe_unused
static void qcs_notify_send(struct qcs *qcs)
{
	if (qcs->subs && qcs->subs->events & SUB_RETRY_SEND) {
		TRACE_POINT(QC_EV_STRM_WAKE, qcs->qcc->conn, qcs);
		qcs->flags |= QC_SF_NOTIFIED;
		tasklet_wakeup(qcs->subs->tasklet);
		qcs->subs->events &= ~SUB_RETRY_SEND;
		if (!qcs->subs->events)
			qcs->subs = NULL;
	}
	else if (qcs->flags & (QC_SF_WANT_SHUTR | QC_SF_WANT_SHUTW)) {
		TRACE_POINT(QC_EV_STRM_WAKE, qcs->qcc->conn, qcs);
		tasklet_wakeup(qcs->shut_tl);
	}
}

/* alerts the data layer, trying to wake it up by all means, following
 * this sequence :
 *   - if the qcs' data layer is subscribed to recv, then it's woken up for recv
 *   - if its subscribed to send, then it's woken up for send
 *   - if it was subscribed to neither, its ->wake() callback is called
 * It is safe to call this function with a closed stream which doesn't have a
 * conn_stream anymore.
 */
__maybe_unused
static void qcs_alert(struct qcs *qcs)
{
	TRACE_ENTER(QC_EV_QCS_WAKE, qcs->qcc->conn, qcs);

	if (qcs->subs ||
	    (qcs->flags & (QC_SF_WANT_SHUTR | QC_SF_WANT_SHUTW))) {
		qcs_notify_recv(qcs);
		qcs_notify_send(qcs);
	}
	else if (qcs->cs && qcs->cs->data_cb->wake != NULL) {
		TRACE_POINT(QC_EV_STRM_WAKE, qcs->qcc->conn, qcs);
		qcs->cs->data_cb->wake(qcs->cs);
	}

	TRACE_LEAVE(QC_EV_QCS_WAKE, qcs->qcc->conn, qcs);
}

/* marks stream <qcs> as CLOSED and decrement the number of active streams for
 * its connection if the stream was not yet closed. Please use this exclusively
 * before closing a stream to ensure stream count is well maintained.
 */
static inline void qcs_close(struct qcs *qcs)
{
	TRACE_ENTER(QC_EV_QCS_END, qcs->qcc->conn, qcs);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_QCS_END, qcs->qcc->conn, qcs);
}

/* detaches an QUIC stream from its QCC and releases it to the QCS pool. */
/* qcs_destroy should only ever be called by the thread that owns the stream,
 * that means that a tasklet should be used if we want to destroy the qcs
 * from another thread
 */
static void qcs_destroy(struct qcs *qcs)
{
	struct connection *conn = qcs->qcc->conn;

	TRACE_ENTER(QC_EV_QCS_END, conn, qcs);

	qcs_close(qcs);
	eb64_delete(&qcs->by_id);
	if (b_size(&qcs->rx.buf)) {
		b_free(&qcs->rx.buf);
		offer_buffers(NULL, 1);
	}

	if (qcs->subs)
		qcs->subs->events = 0;

	/* There's no need to explicitly call unsubscribe here, the only
	 * reference left would be in the qcc send_list/fctl_list, and if
	 * we're in it, we're getting out anyway
	 */
	LIST_DEL_INIT(&qcs->list);

	/* ditto, calling tasklet_free() here should be ok */
	tasklet_free(qcs->shut_tl);
	pool_free(pool_head_qcs, qcs);

	TRACE_LEAVE(QC_EV_QCS_END, conn);
}

/* allocates a new bidirection stream <id> for connection <qcc> and adds it into qcc's
 * stream tree. In case of error, nothing is added and NULL is returned. The
 * causes of errors can be any failed memory allocation. The caller is
 * responsible for checking if the connection may support an extra stream
 * prior to calling this function.
 */
struct qcs *bidi_qcs_new(struct qcc *qcc, uint64_t id)
{
	struct qcs *qcs;
	enum qcs_type qcs_type;

	TRACE_ENTER(QC_EV_QCS_NEW, qcc->conn);

	qcs = pool_alloc(pool_head_qcs);
	if (!qcs)
		goto out;

	qcs->shut_tl = tasklet_new();
	if (!qcs->shut_tl) {
		pool_free(pool_head_qcs, qcs);
		goto out;
	}

	qcs_type = qcs_id_type(id);
	qcs->qcc         = qcc;
	qcs->cs          = NULL;
	qcs->id = qcs->by_id.key = id;
	qcs->flags       = QC_SF_NONE;

	qcs->rx.buf      = BUF_NULL;
	qcs->rx.st       = QC_RX_SS_IDLE;
	qcs->rx.bytes    = qcs->rx.offset = 0;
	qcs->rx.max_data = qcc->strms[qcs_type].rx.max_data;
	qcs->rx.buf      = BUF_NULL;
	qcs->rx.frms     = EB_ROOT_UNIQUE;

	qcs->tx.st       = QC_TX_SS_IDLE;
	qcs->tx.bytes    = qcs->tx.offset = qcs->tx.ack_offset = 0;
	qcs->tx.acked_frms = EB_ROOT_UNIQUE;
	qcs->tx.max_data = qcc->strms[qcs_type].tx.max_data;
	qcs->tx.buf      = BUF_NULL;
	br_init(qcs->tx.mbuf, sizeof(qcs->tx.mbuf) / sizeof(qcs->tx.mbuf[0]));
	qcs->tx.left     = 0;

	eb64_insert(&qcc->streams_by_id, &qcs->by_id);
	qcc->strms[qcs_type].nb_streams++;
	qcc->stream_cnt++;
	qcs->subs = NULL;
	LIST_INIT(&qcs->list);
	qcs->shut_tl->process = qc_deferred_shut;
	qcs->shut_tl->context = qcs;

	HA_ATOMIC_ADD(&qcc->px_counters->open_streams, 1);
	HA_ATOMIC_ADD(&qcc->px_counters->total_streams, 1);

	TRACE_LEAVE(QC_EV_QCS_NEW, qcc->conn, qcs);
	return qcs;

 out:
	TRACE_DEVEL("leaving in error", QC_EV_QCS_ERR|QC_EV_QCS_END, qcc->conn);
	return NULL;
}

/* Release <qcs> outgoing uni-stream */
void qcs_release(struct qcs *qcs)
{
	eb64_delete(&qcs->by_id);
	pool_free(pool_head_qcs, qcs);
}

/* Allocates a locally initiated unidirectional stream. */
struct qcs *luqs_new(struct qcc *qcc)
{
	struct qcs *qcs;
	uint64_t next_id;
	enum qcs_type qcs_type;

	TRACE_ENTER(QC_EV_QCS_NEW, qcc->conn);

	qcs = NULL;
	/* QCS_ID_DIR_BIT bit is set for unidirectional stream. */
	if (objt_listener(qcc->conn->target))
	    qcs_type = QCS_ID_SRV_INTIATOR_BIT | QCS_ID_DIR_BIT;
	else
	    qcs_type = QCS_ID_DIR_BIT;

	next_id = qcs_next_id(qcc, qcs_type);
	if (next_id == (uint64_t)-1) {
		TRACE_PROTO("No more stream available", QC_EV_QCS_NEW, qcc->conn);
		goto out;
	}

	qcs = pool_alloc(pool_head_qcs);
	if (!qcs)
		goto out;

	qcs->qcc = qcc;
	qcs->cs = NULL;
	qcs->id = qcs->by_id.key = next_id;
	qcs->flags = QC_SF_NONE;

	qcs->tx.st         = QC_TX_SS_IDLE;
	qcs->tx.max_data   = qcc->strms[qcs_type].tx.max_data;
	qcs->tx.offset     = qcs->tx.bytes = qcs->tx.ack_offset = 0;
	qcs->tx.acked_frms = EB_ROOT_UNIQUE;
	qcs->tx.buf        = BUF_NULL;
	br_init(qcs->tx.mbuf, sizeof(qcs->tx.mbuf) / sizeof(qcs->tx.mbuf[0]));
	qcs->tx.left = 0;

	qcs->subs = NULL;
	LIST_INIT(&qcs->list);
	eb64_insert(&qcc->streams_by_id, &qcs->by_id);

	TRACE_LEAVE(QC_EV_QCS_NEW, qcc->conn);
	return qcs;

 out:
	if (qcs)
		pool_free(pool_head_qcs, qcs);
	TRACE_DEVEL("leaving in error", QC_EV_QCS_ERR|QC_EV_QCS_END, qcc->conn);
	return NULL;
}

/* Allocates a remotely initiated unidirectional stream. */
struct qcs *ruqs_new(struct qcc *qcc, uint64_t id)
{
	struct qcs *qcs;
	enum qcs_type qcs_type;

	TRACE_ENTER(QC_EV_QCS_NEW, qcc->conn);
	qcs = pool_alloc(pool_head_qcs);
	if (!qcs)
		goto out;

	qcs_type = qcs_id_type(id);

	qcs->qcc = qcc;
	qcs->cs = NULL;

	qcs->qcc = qcc;
	qcs->id = qcs->by_id.key = id;
	qcs->flags = QC_SF_NONE;

	qcs->rx.st = QC_RX_SS_IDLE;
	qcs->rx.max_data = qcc->strms[qcs_type].rx.max_data;
	qcs->rx.offset = qcs->rx.bytes = 0;
	qcs->rx.buf = BUF_NULL;
	qcs->rx.frms = EB_ROOT_UNIQUE;
	br_init(qcs->tx.mbuf, sizeof(qcs->tx.mbuf) / sizeof(qcs->tx.mbuf[0]));
	qcs->tx.left = 0;

	qcs->subs = NULL;
	LIST_INIT(&qcs->list);
	eb64_insert(&qcc->streams_by_id, &qcs->by_id);

	TRACE_LEAVE(QC_EV_QCS_NEW, qcc->conn);
	return qcs;

 out:
	TRACE_DEVEL("leaving in error", QC_EV_QCS_ERR|QC_EV_QCS_END, qcc->conn);
	return NULL;
}

/* attempt to notify the data layer of recv availability */
void ruqs_notify_recv(struct qcs *qcs)
{
	if (qcs->subs && qcs->subs->events & SUB_RETRY_RECV) {
		TRACE_POINT(QC_EV_STRM_WAKE, qcs->qcc->conn);
		tasklet_wakeup(qcs->subs->tasklet);
		qcs->subs->events &= ~SUB_RETRY_RECV;
		if (!qcs->subs->events)
			qcs->subs = NULL;
	}
}

/* Allocates a new stream associated to conn_stream <cs> on the qcc connection
 * with dir as direction and returns it, or NULL in case of memory allocation
 * error or if the highest possible stream ID was reached.
 */
static struct qcs *qcc_bck_stream_new(struct qcc *qcc, int dir,
                                      struct conn_stream *cs, struct session *sess)
{
	struct qcs *qcs = NULL;
	enum qcs_type qcs_type;

	TRACE_ENTER(QC_EV_QCS_NEW, qcc->conn);

	qcs_type = qcs_type_from_dir(qcc, dir);
	if (qcc->strms[qcs_type].largest_id + 1 >= qcc->strms[qcs_type].max_streams)
		goto out;

	/* Defer choosing the ID until we send the first message to create the stream */
	qcs = bidi_qcs_new(qcc, qcc->strms[qcs_type].largest_id + 1);
	if (!qcs)
		goto out;

	qcs->cs = cs;
	qcs->sess = sess;
	cs->ctx = qcs;
	qcc->nb_cs++;

 out:
	if (likely(qcs))
		TRACE_LEAVE(QC_EV_QCS_NEW, qcc->conn, qcs);
	else
		TRACE_LEAVE(QC_EV_QCS_NEW|QC_EV_QCS_ERR|QC_EV_QCS_END, qcc->conn, qcs);
	return qcs;
}

/* Allocates a new bidirectional stream associated to conn_stream <cs> on the <qcc> connection
 * and returns it, or NULL in case of memory allocation error or if the highest
 * possible stream ID was reached.
 */
__maybe_unused
static struct qcs *qcc_bck_stream_new_bidi(struct qcc *qcc,
                                           struct conn_stream *cs, struct session *sess)
{
	return qcc_bck_stream_new(qcc, QCS_BIDI, cs, sess);
}

/* Allocates a new unidirectional stream associated to conn_stream <cs> on the <qcc> connection
 * and returns it, or NULL in case of memory allocation error or if the highest
 * possible stream ID was reached.
 */
__maybe_unused
static struct qcs *qcc_bck_stream_new_uni(struct qcc *qcc,
                                          struct conn_stream *cs, struct session *sess)
{
	return qcc_bck_stream_new(qcc, QCS_UNI, cs, sess);
}


/* wake a specific stream and assign its conn_stream some CS_FL_* flags among
 * CS_FL_ERR_PENDING and CS_FL_ERROR if needed. The stream's state
 * is automatically updated accordingly. If the stream is orphaned, it is
 * destroyed.
 */
static void qcs_wake_one_stream(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_QCS_WAKE, qcc->conn, qcs);
	if (!qcs->cs) {
		/* this stream was already orphaned */
		qcs_destroy(qcs);
		TRACE_DEVEL("leaving with no qcs", QC_EV_QCS_WAKE, qcc->conn);
		return;
	}
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_QCS_WAKE, qcc->conn);
}

/* wake the streams attached to the connection, whose id is greater than <last>
 * or unassigned.
 */
static void qc_wake_some_streams(struct qcc *qcc, int last)
{
	struct eb64_node *node;
	struct qcs *qcs;

	TRACE_ENTER(QC_EV_QCS_WAKE, qcc->conn);

	/* Wake all streams with ID > last */
	node = eb64_lookup_ge(&qcc->streams_by_id, last + 1);
	while (node) {
		qcs = container_of(node, struct qcs, by_id);
		node = eb64_next(node);
		qcs_wake_one_stream(qcs);
	}

	/* Wake all streams with unassigned ID (ID == 0) */
	node = eb64_lookup(&qcc->streams_by_id, 0);
	while (node) {
		qcs = container_of(node, struct qcs, by_id);
		if (qcs->id > 0)
			break;
		node = eb64_next(node);
		qcs_wake_one_stream(qcs);
	}

	TRACE_LEAVE(QC_EV_QCS_WAKE, qcc->conn);
}

/* Wake up all blocked streams whose window size has become positive after the
 * mux's initial window was adjusted. This should be done after having processed
 * SETTINGS frames which have updated the mux's initial window size.
 */
__maybe_unused
static void qcc_unblock_sfctl(struct qcc *qcc)
{
	TRACE_ENTER(QC_EV_QCC_WAKE, qcc->conn);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_QCC_WAKE, qcc->conn);
}

/* process Rx frames to be demultiplexed */
__maybe_unused
static void qc_process_demux(struct qcc *qcc)
{
	TRACE_ENTER(QC_EV_QCC_WAKE, qcc->conn);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_QCC_WAKE, qcc->conn);
}

/* resume each qcs eligible for sending in list head <head> */
__maybe_unused
static void qc_resume_each_sending_qcs(struct qcc *qcc, struct list *head)
{
	struct qcs *qcs, *qcs_back;

	TRACE_ENTER(QC_EV_QCC_SEND|QC_EV_QCS_WAKE, qcc->conn);

	list_for_each_entry_safe(qcs, qcs_back, head, list) {
		if (qcc_wnd(qcc) <= 0 ||
		    qcc->flags & QC_CF_MUX_BLOCK_ANY ||
		    qcc->st0 >= QC_CS_ERROR)
			break;

		qcs->flags &= ~QC_SF_BLK_ANY;

		if (qcs->flags & QC_SF_NOTIFIED)
			continue;

		/* If the sender changed his mind and unsubscribed, let's just
		 * remove the stream from the send_list.
		 */
		if (!(qcs->flags & (QC_SF_WANT_SHUTR|QC_SF_WANT_SHUTW)) &&
		    (!qcs->subs || !(qcs->subs->events & SUB_RETRY_SEND))) {
			LIST_DEL_INIT(&qcs->list);
			continue;
		}

		if (qcs->subs && qcs->subs->events & SUB_RETRY_SEND) {
			qcs->flags |= QC_SF_NOTIFIED;
			tasklet_wakeup(qcs->subs->tasklet);
			qcs->subs->events &= ~SUB_RETRY_SEND;
			if (!qcs->subs->events)
				qcs->subs = NULL;
		}
		else if (qcs->flags & (QC_SF_WANT_SHUTR|QC_SF_WANT_SHUTW)) {
			tasklet_wakeup(qcs->shut_tl);
		}
	}

	TRACE_LEAVE(QC_EV_QCC_SEND|QC_EV_QCS_WAKE, qcc->conn);
}

/* process Tx frames from streams to be multiplexed. Returns > 0 if it reached
 * the end.
 */
__maybe_unused
static int qc_process_mux(struct qcc *qcc)
{
	TRACE_ENTER(QC_EV_QCC_WAKE, qcc->conn);

	/* First we always process the flow control list because the streams
	 * waiting there were already elected for immediate emission but were
	 * blocked just on this.
	 */
	qc_resume_each_sending_qcs(qcc, &qcc->fctl_list);
	qc_resume_each_sending_qcs(qcc, &qcc->send_list);

	TRACE_LEAVE(QC_EV_QCC_WAKE, qcc->conn);
	return 1;
}


/* Attempt to read data, and subscribe if none available.
 * The function returns 1 if data has been received, otherwise zero.
 */
__maybe_unused
static int qc_recv(struct qcc *qcc)
{
	TRACE_ENTER(QC_EV_QCC_RECV, qcc->conn);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_QCC_RECV, qcc->conn);
	return 0;
}

static int qcs_push_frame(struct qcs *qcs, struct buffer *payload, int fin, uint64_t offset)
{
	struct quic_frame *frm;
	struct buffer *buf = &qcs->tx.buf;
	struct quic_enc_level *qel = &qcs->qcc->conn->qc->els[QUIC_TLS_ENC_LEVEL_APP];
	int total = 0, to_xfer;

	qc_get_buf(qcs->qcc, buf);
	to_xfer = QUIC_MIN(b_data(payload), b_room(buf));
	if (!to_xfer)
		goto out;

	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm)
		goto err;

	total = b_force_xfer(buf, payload, to_xfer);
	fin = fin && !b_data(payload);
	frm->type = QUIC_FT_STREAM_8;
	if (fin)
		frm->type |= QUIC_STREAM_FRAME_TYPE_FIN_BIT;
	if (offset) {
		frm->type |= QUIC_STREAM_FRAME_TYPE_OFF_BIT;
		frm->stream.offset.key = offset;
	}
	frm->stream.qcs = qcs;
	frm->stream.buf = buf;
	frm->stream.id = qcs->by_id.key;
	if (total) {
		frm->type |= QUIC_STREAM_FRAME_TYPE_LEN_BIT;
		frm->stream.len = total;
	}

	MT_LIST_APPEND(&qel->pktns->tx.frms, &frm->mt_list);
 out:
	fprintf(stderr, "%s: total=%d fin=%d offset=%lu\n", __func__, total, fin, offset);
	return total;

 err:
	return -1;
}

/* Try to send data if possible.
 * The function returns 1 if data have been sent, otherwise zero.
 */
static int qc_send(struct qcc *qcc)
{
	struct qcs *qcs;
	struct eb64_node *node;
	int ret, done;

	TRACE_ENTER(QC_EV_QCC_SEND, qcc->conn);
	ret = done = 0;
	/* fill as much as we can into the current buffer */
	while (((qcc->flags & (QC_CF_MUX_MFULL|QC_CF_MUX_MALLOC)) == 0) && !done)
		done = qc_process_mux(qcc);

	/* TODO simple loop through all streams and check if there is frames to
	 * send
	 */
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct buffer *buf;
		qcs = container_of(node, struct qcs, by_id);
		for (buf = br_head(qcs->tx.mbuf); b_size(buf); buf = br_del_head(qcs->tx.mbuf)) {
			if (b_data(buf)) {
				char fin = 0;

				/* if FIN is activated, ensure the buffer to
				 * send is the last
				 */
				if (qcs->flags & QC_SF_FIN_STREAM) {
					BUG_ON(qcs->tx.left < b_data(buf));
					fin = !(qcs->tx.left - b_data(buf));
				}

				ret = qcs_push_frame(qcs, buf, fin, qcs->tx.offset);
				if (ret < 0)
					ABORT_NOW();

				qcs->tx.left -= ret;
				qcs->tx.offset += ret;
				if (b_data(buf)) {
					qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
											   SUB_RETRY_SEND, &qcc->wait_event);
					break;
				}
			}
			b_free(buf);
		}
		node = eb64_next(node);
	}
	if (ret > 0)
		tasklet_wakeup(((struct ssl_sock_ctx *)(qcc->conn->xprt_ctx))->wait_event.tasklet);


	TRACE_LEAVE(QC_EV_QCC_SEND, qcc->conn);
	return 0;
}

/* this is the tasklet referenced in qcc->wait_event.tasklet */
static struct task *qc_io_cb(struct task *t, void *ctx, unsigned int status)
{
	struct connection *conn;
	struct tasklet *tl = (struct tasklet *)t;
	int conn_in_list;
	struct qcc *qcc;
	int ret = 0;


	HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	if (t->context == NULL) {
		/* The connection has been taken over by another thread,
		 * we're no longer responsible for it, so just free the
		 * tasklet, and do nothing.
		 */
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		tasklet_free(tl);
		goto leave;
	}
	qcc = ctx;
	conn = qcc->conn;

	TRACE_ENTER(QC_EV_QCC_WAKE, conn);

	conn_in_list = conn->flags & CO_FL_LIST_MASK;

	/* Remove the connection from the list, to be sure nobody attempts
	 * to use it while we handle the I/O events
	 */
	if (conn_in_list)
		conn_delete_from_tree(&conn->hash_node->node);

	HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

	if (!(qcc->wait_event.events & SUB_RETRY_SEND))
		ret = qc_send(qcc);
#if 0
	if (!(qcc->wait_event.events & SUB_RETRY_RECV))
		ret |= qc_recv(qcc);
#endif
	// TODO redefine the proper condition here
	//if (ret || qcc->rx.inmux)
		ret = qc_process(qcc);

	/* If we were in an idle list, we want to add it back into it,
	 * unless qc_process() returned -1, which mean it has destroyed
	 * the connection (testing !ret is enough, if qc_process() wasn't
	 * called then ret will be 0 anyway.
	 */
	if (!ret && conn_in_list) {
		struct server *srv = objt_server(conn->target);

		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		if (conn_in_list == CO_FL_SAFE_LIST)
			ebmb_insert(&srv->per_thr[tid].safe_conns,
			            &conn->hash_node->node, sizeof(conn->hash_node->hash));
		else
			ebmb_insert(&srv->per_thr[tid].idle_conns,
			            &conn->hash_node->node, sizeof(conn->hash_node->hash));
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}

leave:
	TRACE_LEAVE(QC_EV_QCC_WAKE);
	return NULL;
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection (which normally doesn not happen in quic).
 */
static int qc_process(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;

	TRACE_ENTER(QC_EV_QCC_WAKE, conn);
	TRACE_LEAVE(QC_EV_QCC_WAKE, conn);
	return 0;
}

/* wake-up function called by the connection layer (mux_ops.wake) */
static int qc_wake(struct connection *conn)
{
	struct qcc *qcc = conn->ctx;
	int ret;

	TRACE_ENTER(QC_EV_QCC_WAKE, conn);
	ret = qc_process(qcc);
	if (ret >= 0)
		qc_wake_some_streams(qcc, 0);
	TRACE_LEAVE(QC_EV_QCC_WAKE);
	return ret;
}

/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed. If the
 * MUX buffer still has lying data or is not allocatable, the connection is
 * immediately killed. If it's allocatable and empty, we attempt to send a
 * GOAWAY frame.
 */
static struct task *qc_timeout_task(struct task *t, void *context, unsigned int state)
{
	TRACE_ENTER(QC_EV_QCC_WAKE);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_QCC_WAKE);
	return NULL;
}


/*******************************************/
/* functions below are used by the streams */
/*******************************************/

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *qc_attach(struct connection *conn, struct session *sess)
{
	struct conn_stream *cs;
	struct qcs *qcs;
	struct qcc *qcc = conn->ctx;

	TRACE_ENTER(QC_EV_QCS_NEW, conn);
	cs = cs_new(conn, conn->target);
	if (!cs) {
		TRACE_DEVEL("leaving on CS allocation failure", QC_EV_QCS_NEW|QC_EV_QCS_ERR, conn);
		return NULL;
	}
	qcs = qcc_bck_stream_new(qcc, QCS_BIDI, cs, sess);
	if (!qcs) {
		TRACE_DEVEL("leaving on stream creation failure", QC_EV_QCS_NEW|QC_EV_QCS_ERR, conn);
		cs_free(cs);
		return NULL;
	}
	TRACE_LEAVE(QC_EV_QCS_NEW, conn, qcs);
	return cs;
}

/* Retrieves the first valid conn_stream from this connection, or returns NULL.
 * We have to scan because we may have some orphan streams. It might be
 * beneficial to scan backwards from the end to reduce the likeliness to find
 * orphans.
 */
static const struct conn_stream *qc_get_first_cs(const struct connection *conn)
{
	struct qcc *qcc = conn->ctx;
	struct qcs *qcs;
	struct eb64_node *node;

	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		qcs = container_of(node, struct qcs, by_id);
		if (qcs->cs)
			return qcs->cs;
		node = eb64_next(node);
	}
	return NULL;
}

static int qc_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	int ret = 0;
	struct qcc *qcc = conn->ctx;

	switch (mux_ctl) {
	case MUX_STATUS:
		/* Only consider the mux to be ready if we had no error. */
		if (qcc->st0 < QC_CS_ERROR)
			ret |= MUX_STATUS_READY;
		return ret;
	case MUX_EXIT_STATUS:
		return MUX_ES_UNKNOWN;
	default:
		return -1;
	}
}

/*
 * Destroy the mux and the associated connection, if it is no longer used
 */
static void qc_destroy(void *ctx)
{
	struct qcc *qcc = ctx;

	TRACE_ENTER(QC_EV_QCC_END, qcc->conn);
	if (eb_is_empty(&qcc->streams_by_id) || !qcc->conn || qcc->conn->ctx != qcc)
		qc_release(qcc);
	TRACE_LEAVE(QC_EV_QCC_END);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void qc_detach(struct conn_stream *cs)
{
	struct qcs *qcs = cs->ctx;
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_END, qcs ? qcs->qcc->conn : NULL, qcs);
	qcs_destroy(qcs);
	if (eb_is_empty(&qcc->streams_by_id))
		qc_release(qcc);
	TRACE_LEAVE(QC_EV_STRM_END, qcs ? qcs->qcc->conn : NULL);
}

/* Performs a synchronous or asynchronous shutr(). */
static void qc_do_shutr(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_SHUT, qcc->conn, qcs);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_STRM_SHUT, qcc->conn, qcs);
	return;
}

/* Performs a synchronous or asynchronous shutw(). */
static void qc_do_shutw(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_SHUT, qcc->conn, qcs);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_STRM_SHUT, qcc->conn, qcs);
	return;
}

/* This is the tasklet referenced in qcs->shut_tl, it is used for
 * deferred shutdowns when the qc_detach() was done but the mux buffer was full
 * and prevented the last frame from being emitted.
 */
static struct task *qc_deferred_shut(struct task *t, void *ctx, unsigned int state)
{
	struct qcs *qcs = ctx;
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_SHUT, qcc->conn, qcs);

	if (qcs->flags & QC_SF_NOTIFIED) {
		/* some data processing remains to be done first */
		goto end;
	}

	if (qcs->flags & QC_SF_WANT_SHUTW)
		qc_do_shutw(qcs);

	if (qcs->flags & QC_SF_WANT_SHUTR)
		qc_do_shutr(qcs);

	if (!(qcs->flags & (QC_SF_WANT_SHUTR|QC_SF_WANT_SHUTW))) {
		/* We're done trying to send, remove ourself from the send_list */
		LIST_DEL_INIT(&qcs->list);

		if (!qcs->cs) {
			qcs_destroy(qcs);
			if (qcc_is_dead(qcc))
				qc_release(qcc);
		}
	}

 end:
	TRACE_LEAVE(QC_EV_STRM_SHUT);
	return NULL;
}

/* shutr() called by the conn_stream (mux_ops.shutr) */
static void qc_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{

	struct qcs *qcs = cs->ctx;

	TRACE_ENTER(QC_EV_STRM_SHUT, qcs->qcc->conn, qcs);
	if (cs->flags & CS_FL_KILL_CONN)
		qcs->flags |= QC_SF_KILL_CONN;

	if (mode)
		qc_do_shutr(qcs);

	TRACE_LEAVE(QC_EV_STRM_SHUT, qcs->qcc->conn, qcs);
}

/* shutw() called by the conn_stream (mux_ops.shutw) */
static void qc_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	struct qcs *qcs = cs->ctx;

	TRACE_ENTER(QC_EV_STRM_SHUT, qcs->qcc->conn, qcs);
	if (cs->flags & CS_FL_KILL_CONN)
		qcs->flags |= QC_SF_KILL_CONN;

	qc_do_shutw(qcs);
	TRACE_LEAVE(QC_EV_STRM_SHUT, qcs->qcc->conn, qcs);
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int qc_subscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	struct qcs *qcs = cs->ctx;
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_SEND|QC_EV_STRM_RECV, qcc->conn, qcs);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events |= event_type;
	qcs->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", QC_EV_STRM_RECV, qcc->conn, qcs);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", QC_EV_STRM_SEND, qcc->conn, qcs);
		if (!(qcs->flags & QC_SF_BLK_SFCTL) &&
		    !LIST_INLIST(&qcs->list)) {
			if (qcs->flags & QC_SF_BLK_MFCTL)
				LIST_APPEND(&qcc->fctl_list, &qcs->list);
			else
				LIST_APPEND(&qcc->send_list, &qcs->list);
		}
	}
	TRACE_LEAVE(QC_EV_STRM_SEND|QC_EV_STRM_RECV, qcc->conn, qcs);
	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int qc_unsubscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	struct qcs *qcs = cs->ctx;

	TRACE_ENTER(QC_EV_STRM_SEND|QC_EV_STRM_RECV, qcs->qcc->conn, qcs);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		qcs->subs = NULL;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", QC_EV_STRM_RECV, qcs->qcc->conn, qcs);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", QC_EV_STRM_SEND, qcs->qcc->conn, qcs);
		qcs->flags &= ~QC_SF_NOTIFIED;
		if (!(qcs->flags & (QC_SF_WANT_SHUTR | QC_SF_WANT_SHUTW)))
			LIST_DEL_INIT(&qcs->list);
	}

	TRACE_LEAVE(QC_EV_STRM_SEND|QC_EV_STRM_RECV, qcs->qcc->conn, qcs);
	return 0;
}


/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * SUB_RETRY_RECV. It always returns 0.
 */
static int ruqs_subscribe(struct qcs *qcs, int event_type, struct wait_event *es)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_RECV, qcc->conn, qcs);

	BUG_ON(event_type & ~SUB_RETRY_RECV);
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events |= event_type;
	qcs->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", QC_EV_STRM_RECV, qcc->conn, qcs);

	TRACE_LEAVE(QC_EV_STRM_RECV, qcc->conn, qcs);
	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int ruqs_unsubscribe(struct qcs *qcs, int event_type, struct wait_event *es)
{
	TRACE_ENTER(QC_EV_STRM_RECV, qcs->qcc->conn, qcs);

	BUG_ON(event_type & ~SUB_RETRY_RECV);
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		qcs->subs = NULL;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", QC_EV_STRM_RECV, qcs->qcc->conn, qcs);

	TRACE_LEAVE(QC_EV_STRM_RECV, qcs->qcc->conn, qcs);
	return 0;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be
 * SUB_RETRY_SEND. It always returns 0.
 */
static int luqs_subscribe(struct qcs *qcs, int event_type, struct wait_event *es)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_SEND, qcc->conn, qcs);

	BUG_ON(event_type & ~SUB_RETRY_SEND);
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events |= event_type;
	qcs->subs = es;

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", QC_EV_STRM_SEND, qcc->conn, qcs);
		if (!(qcs->flags & QC_SF_BLK_SFCTL) &&
		    !LIST_INLIST(&qcs->list)) {
			if (qcs->flags & QC_SF_BLK_MFCTL)
				LIST_APPEND(&qcc->fctl_list, &qcs->list);
			else
				LIST_APPEND(&qcc->send_list, &qcs->list);
		}
	}

	TRACE_LEAVE(QC_EV_STRM_SEND, qcc->conn, qcs);
	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int luqs_unsubscribe(struct qcs *qcs, int event_type, struct wait_event *es)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QC_EV_STRM_SEND, qcc->conn, qcs);

	BUG_ON(event_type & ~SUB_RETRY_SEND);
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		qcs->subs = NULL;

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", QC_EV_STRM_SEND, qcc->conn, qcs);
		qcs->flags &= ~QC_SF_NOTIFIED;
		if (!(qcs->flags & (QC_SF_WANT_SHUTR | QC_SF_WANT_SHUTW)))
			LIST_DEL_INIT(&qcs->list);
	}

	TRACE_LEAVE(QC_EV_STRM_SEND, qcc->conn, qcs);
	return 0;
}

/* Called from the upper layer, to receive data */
static size_t qc_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct qcs *qcs = cs->ctx;
	struct qcc *qcc = qcs->qcc;
	int ret;

	ret = 0;
	TRACE_ENTER(QC_EV_STRM_RECV, qcc->conn, qcs);
	/* XXX TO DO XXX */
	TRACE_LEAVE(QC_EV_STRM_RECV, qcc->conn, qcs);
	return ret;
}

/* Called from the upper layer, to send data from buffer <buf> for no more than
 * <count> bytes. Returns the number of bytes effectively sent. Some status
 * flags may be updated on the conn_stream.
 */
size_t qc_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct qcs *qcs = cs->ctx;

	TRACE_ENTER(QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn, qcs);

	if (count) {
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	TRACE_LEAVE(QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn, qcs);
	return count;
}

/* Called from the upper layer, to send data from buffer <buf> for no more than
 * <count> bytes. Returns the number of bytes effectively sent. Some status
 * flags may be updated on the outgoing uni-stream.
 */
__maybe_unused
static size_t _qcs_snd_buf(struct qcs *qcs, struct buffer *buf, size_t count, int flags)
{
	size_t total = 0;
	struct qcc *qcc = qcs->qcc;
	struct buffer *res;
	struct quic_tx_frm *frm;

	TRACE_ENTER(QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn);

	if (!count)
		goto out;

	res = br_tail(qcc->mbuf);
	if (!qc_get_buf(qcc, res)) {
		qcc->flags |= QC_CF_MUX_MALLOC;
		goto out;
	}

	while (count) {
		size_t try, room;

		room = b_room(res);
		if (!room) {
			if ((res = br_tail_add(qcc->mbuf)) != NULL)
				continue;

			qcc->flags |= QC_CF_MUX_MALLOC;
			break;
		}

		try = count;
		if (try > room)
			try = room;

		total += b_xfer(res, buf, try);
		count -= try;
	}

	if (total) {

		frm = pool_alloc(pool_head_quic_frame);
		if (!frm) { /* XXX XXX */ }
	}

 out:
	TRACE_LEAVE(QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn);
	return total;

 err:
	TRACE_DEVEL("leaving on stream error", QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn);
	return total;
}

/* Called from the upper layer, to send data from buffer <buf> for no more than
 * <count> bytes. Returns the number of bytes effectively sent. Some status
 * flags may be updated on the mux.
 */
size_t luqs_snd_buf(struct qcs *qcs, struct buffer *buf, size_t count, int flags)
{
	size_t room, total = 0;
	struct qcc *qcc = qcs->qcc;
	struct buffer *res;

	TRACE_ENTER(QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn);
	if (!count)
		goto out;

	res = &qcs->tx.buf;
	if (!qc_get_buf(qcc, res)) {
		qcc->flags |= QC_CF_MUX_MALLOC;
		goto out;
	}

	room = b_room(res);
	if (!room)
		goto out;

	if (count > room)
		count = room;

	total += b_xfer(res, buf, count);
	qcs_push_frame(qcs, res, 0, 0);

 out:
	TRACE_LEAVE(QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn);
	return total;

 err:
	TRACE_DEVEL("leaving on stream error", QC_EV_QCS_SEND|QC_EV_STRM_SEND, qcs->qcc->conn);
	return total;
}

/* for debugging with CLI's "show fd" command */
static int qc_show_fd(struct buffer *msg, struct connection *conn)
{
	struct qcc *qcc = conn->ctx;
	struct qcs *qcs = NULL;
	struct eb64_node *node;
	int fctl_cnt = 0;
	int send_cnt = 0;
	int tree_cnt = 0;
	int orph_cnt = 0;
	struct buffer *hmbuf, *tmbuf;

	if (!qcc)
		return 0;

	list_for_each_entry(qcs, &qcc->fctl_list, list)
		fctl_cnt++;

	list_for_each_entry(qcs, &qcc->send_list, list)
		send_cnt++;

	qcs = NULL;
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		qcs = container_of(node, struct qcs, by_id);
		tree_cnt++;
		if (!qcs->cs)
			orph_cnt++;
		node = eb64_next(node);
	}

	hmbuf = br_head(qcc->mbuf);
	tmbuf = br_tail(qcc->mbuf);
	chunk_appendf(msg, " qcc.st0=%s .flg=0x%04x"
	              " clt.nb_streams_bidi=%llu srv.nb_streams_bidi=%llu"
	              " clt.nb_streams_uni=%llu srv.nb_streams_uni=%llu"
	              " .nbcs=%u .fctl_cnt=%d .send_cnt=%d .tree_cnt=%d"
	              " .orph_cnt=%d .sub=%d"
	              " .mbuf=[%u..%u|%u],h=[%u@%p+%u/%u],t=[%u@%p+%u/%u]",
		      qcc_st_to_str(qcc->st0), qcc->flags,
		      (unsigned long long)qcc->strms[QCS_CLT_BIDI].nb_streams,
		      (unsigned long long)qcc->strms[QCS_SRV_BIDI].nb_streams,
		      (unsigned long long)qcc->strms[QCS_CLT_UNI].nb_streams,
		      (unsigned long long)qcc->strms[QCS_SRV_UNI].nb_streams,
		      qcc->nb_cs, fctl_cnt, send_cnt, tree_cnt, orph_cnt,
		      qcc->wait_event.events,
		      br_head_idx(qcc->mbuf), br_tail_idx(qcc->mbuf), br_size(qcc->mbuf),
		      (unsigned int)b_data(hmbuf), b_orig(hmbuf),
		      (unsigned int)b_head_ofs(hmbuf), (unsigned int)b_size(hmbuf),
		      (unsigned int)b_data(tmbuf), b_orig(tmbuf),
		      (unsigned int)b_head_ofs(tmbuf), (unsigned int)b_size(tmbuf));

	if (qcs) {
		chunk_appendf(msg, " last_qcs=%p .id=%llu rx.st=%s tx.st=%s .flg=0x%04x .rxbuf=%u@%p+%u/%u .cs=%p",
			      qcs, (unsigned long long)qcs->id,
			      qcs_rx_st_to_str(qcs->rx.st), qcs_tx_st_to_str(qcs->tx.st), qcs->flags,
			      (unsigned int)b_data(&qcs->rx.buf), b_orig(&qcs->rx.buf),
			      (unsigned int)b_head_ofs(&qcs->rx.buf), (unsigned int)b_size(&qcs->rx.buf),
			      qcs->cs);
		if (qcs->cs)
			chunk_appendf(msg, " .cs.flg=0x%08x .cs.data=%p",
				      qcs->cs->flags, qcs->cs->data);
	}

	return 0;
}

/* Migrate the the connection to the current thread.
 * Return 0 if successful, non-zero otherwise.
 * Expected to be called with the old thread lock held.
 */
static int qc_takeover(struct connection *conn, int orig_tid)
{
	struct qcc *qcc = conn->ctx;
	struct task *task;

	if (fd_takeover(conn->handle.fd, conn) != 0)
		return -1;

	if (conn->xprt->takeover && conn->xprt->takeover(conn, conn->xprt_ctx, orig_tid) != 0) {
		/* We failed to takeover the xprt, even if the connection may
		 * still be valid, flag it as error'd, as we have already
		 * taken over the fd, and wake the tasklet, so that it will
		 * destroy it.
		 */
		conn->flags |= CO_FL_ERROR;
		tasklet_wakeup_on(qcc->wait_event.tasklet, orig_tid);
		return -1;
	}

	if (qcc->wait_event.events)
		qcc->conn->xprt->unsubscribe(qcc->conn, qcc->conn->xprt_ctx,
		    qcc->wait_event.events, &qcc->wait_event);
	/* To let the tasklet know it should free itself, and do nothing else,
	 * set its context to NULL.
	 */
	qcc->wait_event.tasklet->context = NULL;
	tasklet_wakeup_on(qcc->wait_event.tasklet, orig_tid);

	task = qcc->task;
	if (task) {
		task->context = NULL;
		qcc->task = NULL;
		__ha_barrier_store();
		task_kill(task);

		qcc->task = task_new_here();
		if (!qcc->task) {
			qc_release(qcc);
			return -1;
		}

		qcc->task->process = qc_timeout_task;
		qcc->task->context = qcc;
	}

	qcc->wait_event.tasklet = tasklet_new();
	if (!qcc->wait_event.tasklet) {
		qc_release(qcc);
		return -1;
	}

	qcc->wait_event.tasklet->process = qc_io_cb;
	qcc->wait_event.tasklet->context = qcc;
	qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
		                   SUB_RETRY_RECV, &qcc->wait_event);

	return 0;
}

/****************************************/
/* MUX initialization and instantiation */
/***************************************/

/* The mux operations */
static const struct mux_ops qc_ops = {
	.init = qc_init,
	.wake = qc_wake,
	//.snd_buf = qc_snd_buf,
	.snd_buf = h3_snd_buf,
	.rcv_buf = qc_rcv_buf,
	.subscribe = qc_subscribe,
	.unsubscribe = qc_unsubscribe,
	.ruqs_subscribe = ruqs_subscribe,
	.ruqs_unsubscribe = ruqs_unsubscribe,
	.luqs_subscribe = luqs_subscribe,
	.luqs_unsubscribe = luqs_unsubscribe,
	.attach = qc_attach,
	.get_first_cs = qc_get_first_cs,
	.detach = qc_detach,
	.destroy = qc_destroy,
	.avail_streams_bidi = qc_avail_streams_bidi,
	.avail_streams_uni = qc_avail_streams_uni,
	.used_streams = qc_used_streams,
	.shutr = qc_shutr,
	.shutw = qc_shutw,
	.ctl = qc_ctl,
	.show_fd = qc_show_fd,
	.takeover = qc_takeover,
	.flags = MX_FL_CLEAN_ABRT|MX_FL_HTX|MX_FL_HOL_RISK,
	.name = "QUIC",
};

static struct mux_proto_list mux_proto_quic =
	{ .token = IST("quic"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_BOTH, .mux = &qc_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_quic);

