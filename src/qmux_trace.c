#include <haproxy/qmux_trace.h>

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/chunk.h>
#include <haproxy/mux_quic.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_frame-t.h>

/* trace source and events */
static void qmux_trace(enum trace_level level, uint64_t mask,
                       const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4);

static void qmux_trace_fill_ctx(struct trace_ctx *ctx, const struct trace_source *src,
                                const void *a1, const void *a2, const void *a3, const void *a4);

static const struct name_desc qmux_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="qcs", .desc="QUIC stream" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc qmux_trace_decoding[] = {
#define QMUX_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define QMUX_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only qcc/qcs state and flags, no real decoding" },
	{ /* end */ }
};

struct trace_source trace_qmux = {
	.name = IST("qmux"),
	.desc = "QUIC multiplexer",
	.arg_def = TRC_ARG1_CONN,  /* TRACE()'s first argument is always a connection */
	.default_cb = qmux_trace,
	.fill_ctx = qmux_trace_fill_ctx,
	.known_events = qmux_trace_events,
	.lockon_args = qmux_trace_lockon_args,
	.decoding = qmux_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};


static void qmux_trace_frm(const struct quic_frame *frm)
{
	switch (frm->type) {
	case QUIC_FT_MAX_STREAMS_BIDI:
		chunk_appendf(&trace_buf, " max_streams=%llu",
		              (ullong)frm->max_streams_bidi.max_streams);
		break;

	case QUIC_FT_MAX_STREAMS_UNI:
		chunk_appendf(&trace_buf, " max_streams=%llu",
		              (ullong)frm->max_streams_uni.max_streams);
		break;

	default:
		break;
	}
}

/* quic-mux trace handler */
static void qmux_trace(enum trace_level level, uint64_t mask,
                       const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct qcc *qcc   = conn ? conn->ctx : NULL;
	const struct qcs *qcs   = a2;

	if (!qcc)
		return;

	if (src->verbosity > QMUX_VERB_CLEAN) {
		qmux_dump_qcc_info(&trace_buf, qcc);

		if (qcs)
			qmux_dump_qcs_info(&trace_buf, qcs);

		if (mask & QMUX_EV_QCC_NQCS) {
			const uint64_t *id = a3;
			chunk_appendf(&trace_buf, " id=%llu", (ullong)*id);
		}

		if (mask & QMUX_EV_SEND_FRM)
			qmux_trace_frm(a3);

		if (mask & QMUX_EV_QCS_XFER_DATA) {
			const struct qcs_xfer_data_trace_arg *arg = a3;
			chunk_appendf(&trace_buf, " prep=%lu xfer=%d",
			              (ulong)arg->prep, arg->xfer);
		}

		if (mask & QMUX_EV_QCS_BUILD_STRM) {
			const struct qcs_build_stream_trace_arg *arg = a3;
			chunk_appendf(&trace_buf, " len=%lu fin=%d offset=%llu",
			              (ulong)arg->len, arg->fin, (ullong)arg->offset);
		}
	}
}

/* This fills the trace_ctx with extra info guessed from the args */
static void qmux_trace_fill_ctx(struct trace_ctx *ctx, const struct trace_source *src,
                               const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct qcc *qcc   = conn ? conn->ctx : NULL;
	const struct qcs *qcs   = a2;

	if (!ctx->conn)
		ctx->conn = conn;

	if (qcc) {
		if (!ctx->fe)
			ctx->fe = qcc->proxy;
	}

	if (qcs) {
		if (!ctx->strm && qcs->sd && qcs->sd->sc)
			ctx->strm = sc_strm(qcs->sd->sc);
	}
}


/* register qmux traces */
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

void qmux_dump_qcc_info(struct buffer *msg, const struct qcc *qcc)
{
	const struct quic_conn *qc = qcc->conn->handle.qc;

	chunk_appendf(msg, " qcc=%p(F)", qcc);
	if (qcc->conn->handle.qc)
		chunk_appendf(msg, " qc=%p", qcc->conn->handle.qc);
	chunk_appendf(msg, " .sc=%llu .hreq=%llu .flg=0x%04x", (ullong)qcc->nb_sc, (ullong)qcc->nb_hreq, qcc->flags);

	chunk_appendf(msg, " .tx=%llu %llu/%llu bwnd=%llu/%llu",
	              (ullong)qcc->tx.fc.off_soft, (ullong)qcc->tx.fc.off_real, (ullong)qcc->tx.fc.limit,
	              (ullong)qcc->tx.buf_in_flight, (ullong)qc->path->cwnd);
}

void qmux_dump_qcs_info(struct buffer *msg, const struct qcs *qcs)
{
	chunk_appendf(msg, " qcs=%p .id=%llu .st=%s .flg=0x%04x", qcs, (ullong)qcs->id,
	              qcs_st_to_str(qcs->st), qcs->flags);

	chunk_appendf(msg, " .rx=%llu/%llu", (ullong)qcs->rx.offset_max, (ullong)qcs->rx.msd);
	chunk_appendf(msg, " .tx=%llu %llu/%llu", (ullong)qcs->tx.fc.off_soft,
	                                          (ullong)qcs->tx.fc.off_real,
	                                          (ullong)qcs->tx.fc.limit);

	chunk_appendf(msg, " .ti=%u/%u/%u",
	              tot_time_read(&qcs->timer.base),
	              tot_time_read(&qcs->timer.buf),
	              tot_time_read(&qcs->timer.fctl));
}
