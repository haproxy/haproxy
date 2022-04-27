#include <haproxy/mux_quic.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/dynbuf.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/quic_stream.h>
#include <haproxy/sink.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/trace.h>
#include <haproxy/xprt_quic.h>

DECLARE_POOL(pool_head_qcc, "qcc", sizeof(struct qcc));
DECLARE_POOL(pool_head_qcs, "qcs", sizeof(struct qcs));

/* trace source and events */
static void qmux_trace(enum trace_level level, uint64_t mask,
                       const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event qmux_trace_events[] = {
#define           QMUX_EV_QCC_RECV      (1ULL << 1)
	{ .mask = QMUX_EV_QCC_RECV,     .name = "qcc_recv",     .desc = "Rx on QUIC connection" },
#define           QMUX_EV_QCC_SEND      (1ULL << 2)
	{ .mask = QMUX_EV_QCC_SEND,     .name = "qcc_send",     .desc = "Tx on QUIC connection" },
#define           QMUX_EV_QCC_WAKE      (1ULL << 3)
	{ .mask = QMUX_EV_QCC_WAKE,     .name = "qcc_wake",     .desc = "QUIC connection woken up" },
#define           QMUX_EV_QCC_END       (1ULL << 4)
	{ .mask = QMUX_EV_QCC_END,      .name = "qcc_end",      .desc = "QUIC connection terminated" },
#define           QMUX_EV_QCC_NQCS      (1ULL << 5)
	{ .mask = QMUX_EV_QCC_NQCS,     .name = "qcc_no_qcs",   .desc = "QUIC stream not found" },
#define           QMUX_EV_QCS_NEW       (1ULL << 6)
	{ .mask = QMUX_EV_QCS_NEW,      .name = "qcs_new",      .desc = "new QUIC stream" },
#define           QMUX_EV_QCS_RECV      (1ULL << 7)
	{ .mask = QMUX_EV_QCS_RECV,     .name = "qcs_recv",     .desc = "Rx on QUIC stream" },
#define           QMUX_EV_QCS_SEND      (1ULL << 8)
	{ .mask = QMUX_EV_QCS_SEND,     .name = "qcs_send",     .desc = "Tx on QUIC stream" },
#define           QMUX_EV_QCS_END       (1ULL << 9)
	{ .mask = QMUX_EV_QCS_END,      .name = "qcs_end",      .desc = "QUIC stream terminated" },
#define           QMUX_EV_STRM_RECV     (1ULL << 10)
	{ .mask = QMUX_EV_STRM_RECV,    .name = "strm_recv",    .desc = "receiving data for stream" },
#define           QMUX_EV_STRM_SEND     (1ULL << 11)
	{ .mask = QMUX_EV_STRM_SEND,    .name = "strm_send",    .desc = "sending data for stream" },
#define           QMUX_EV_STRM_END      (1ULL << 12)
	{ .mask = QMUX_EV_STRM_END,     .name = "strm_end",     .desc = "detaching app-layer stream" },
#define           QMUX_EV_SEND_FRM      (1ULL << 13)
	{ .mask = QMUX_EV_SEND_FRM,     .name = "send_frm",     .desc = "sending QUIC frame" },
/* special event dedicated to qcs_xfer_data */
#define           QMUX_EV_QCS_XFER_DATA  (1ULL << 14)
	{ .mask = QMUX_EV_QCS_XFER_DATA,  .name = "qcs_xfer_data", .desc = "qcs_xfer_data" },
/* special event dedicated to qcs_build_stream_frm */
#define           QMUX_EV_QCS_BUILD_STRM (1ULL << 15)
	{ .mask = QMUX_EV_QCS_BUILD_STRM, .name = "qcs_build_stream_frm", .desc = "qcs_build_stream_frm" },
	{ }
};

/* custom arg for QMUX_EV_QCS_XFER_DATA */
struct qcs_xfer_data_trace_arg {
	size_t prep;
	int xfer;
};
/* custom arg for QMUX_EV_QCS_BUILD_STRM */
struct qcs_build_stream_trace_arg {
	size_t len;
	char fin;
	uint64_t offset;
};

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
	.known_events = qmux_trace_events,
	.lockon_args = qmux_trace_lockon_args,
	.decoding = qmux_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

#define TRACE_SOURCE    &trace_qmux
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* Allocate a new QUIC streams with id <id> and type <type>. */
struct qcs *qcs_new(struct qcc *qcc, uint64_t id, enum qcs_type type)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCS_NEW, qcc->conn);

	qcs = pool_alloc(pool_head_qcs);
	if (!qcs)
		return NULL;

	qcs->stream = NULL;
	qcs->qcc = qcc;
	qcs->cs = NULL;
	qcs->flags = QC_SF_NONE;
	qcs->ctx = NULL;

	/* allocate transport layer stream descriptor
	 *
	 * TODO qc_stream_desc is only useful for Tx buffering. It should not
	 * be required for unidirectional remote streams.
	 */
	qcs->stream = qc_stream_desc_new(id, qcs, qcc->conn->handle.qc);
	if (!qcs->stream)
		goto err;

	if (qcc->app_ops->attach) {
		if (qcc->app_ops->attach(qcs))
			goto err;
	}

	qcs->endp = cs_endpoint_new();
	if (!qcs->endp) {
		pool_free(pool_head_qcs, qcs);
		goto err;
	}
	qcs->endp->target = qcs;
	qcs->endp->ctx = qcc->conn;
	qcs->endp->flags |= (CS_EP_T_MUX|CS_EP_ORPHAN|CS_EP_NOT_FIRST);

	qcs->id = qcs->by_id.key = id;
	/* store transport layer stream descriptor in qcc tree */
	eb64_insert(&qcc->streams_by_id, &qcs->by_id);

	qcc->strms[type].nb_streams++;

	/* If stream is local, use peer remote-limit, or else the opposite. */
	/* TODO use uni limit for unidirectional streams */
	qcs->tx.msd = quic_stream_is_local(qcc, id) ? qcc->rfctl.msd_bidi_r :
	                                              qcc->rfctl.msd_bidi_l;

	qcs->rx.buf = BUF_NULL;
	qcs->rx.app_buf = BUF_NULL;
	qcs->rx.offset = 0;
	qcs->rx.frms = EB_ROOT_UNIQUE;

	/* TODO use uni limit for unidirectional streams */
	qcs->rx.msd = quic_stream_is_local(qcc, id) ? qcc->lfctl.msd_bidi_l :
	                                              qcc->lfctl.msd_bidi_r;

	qcs->tx.buf = BUF_NULL;
	qcs->tx.offset = 0;
	qcs->tx.sent_offset = 0;

	qcs->wait_event.tasklet = NULL;
	qcs->wait_event.events = 0;
	qcs->subs = NULL;

 out:
	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn, qcs);
	return qcs;

 err:
	if (qcs->ctx && qcc->app_ops->detach)
		qcc->app_ops->detach(qcs);

	if (qcs->stream)
		qc_stream_desc_release(qcs->stream);

	pool_free(pool_head_qcs, qcs);
	return NULL;
}

/* Free a qcs. This function must only be done to remove a stream on allocation
 * error or connection shutdown. Else use qcs_destroy which handle all the
 * QUIC connection mechanism.
 */
void qcs_free(struct qcs *qcs)
{
	b_free(&qcs->rx.buf);
	b_free(&qcs->tx.buf);

	BUG_ON(!qcs->qcc->strms[qcs_id_type(qcs->id)].nb_streams);
	--qcs->qcc->strms[qcs_id_type(qcs->id)].nb_streams;

	if (qcs->ctx && qcs->qcc->app_ops->detach)
		qcs->qcc->app_ops->detach(qcs);

	qc_stream_desc_release(qcs->stream);

	BUG_ON(qcs->endp && !(qcs->endp->flags & CS_EP_ORPHAN));
	cs_endpoint_free(qcs->endp);

	eb64_delete(&qcs->by_id);
	pool_free(pool_head_qcs, qcs);
}

struct buffer *qc_get_buf(struct qcs *qcs, struct buffer *bptr)
{
	struct buffer *buf = b_alloc(bptr);
	BUG_ON(!buf);
	return buf;
}

int qcs_subscribe(struct qcs *qcs, int event_type, struct wait_event *es)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_STRM_SEND|QMUX_EV_STRM_RECV, qcc->conn, qcs);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events |= event_type;
	qcs->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", QMUX_EV_STRM_RECV, qcc->conn, qcs);

	if (event_type & SUB_RETRY_SEND)
		TRACE_DEVEL("subscribe(send)", QMUX_EV_STRM_SEND, qcc->conn, qcs);

	TRACE_LEAVE(QMUX_EV_STRM_SEND|QMUX_EV_STRM_RECV, qcc->conn, qcs);

	return 0;
}

void qcs_notify_recv(struct qcs *qcs)
{
	if (qcs->subs && qcs->subs->events & SUB_RETRY_RECV) {
		tasklet_wakeup(qcs->subs->tasklet);
		qcs->subs->events &= ~SUB_RETRY_RECV;
		if (!qcs->subs->events)
			qcs->subs = NULL;
	}
}

void qcs_notify_send(struct qcs *qcs)
{
	if (qcs->subs && qcs->subs->events & SUB_RETRY_SEND) {
		tasklet_wakeup(qcs->subs->tasklet);
		qcs->subs->events &= ~SUB_RETRY_SEND;
		if (!qcs->subs->events)
			qcs->subs = NULL;
	}
}

/* Retrieve as an ebtree node the stream with <id> as ID, possibly allocates
 * several streams, depending on the already open ones.
 * Return this node if succeeded, NULL if not.
 */
struct qcs *qcc_get_qcs(struct qcc *qcc, uint64_t id)
{
	unsigned int strm_type;
	int64_t sub_id;
	struct eb64_node *node;
	struct qcs *qcs = NULL;

	strm_type = id & QCS_ID_TYPE_MASK;
	sub_id = id >> QCS_ID_TYPE_SHIFT;
	node = NULL;
	if (quic_stream_is_local(qcc, id)) {
		/* Local streams: this stream must be already opened. */
		node = eb64_lookup(&qcc->streams_by_id, id);
		if (!node) {
			/* unknown stream id */
			goto out;
		}
		qcs = eb64_entry(node, struct qcs, by_id);
	}
	else {
		/* Remote streams. */
		struct eb_root *strms;
		uint64_t largest_id;
		enum qcs_type qcs_type;

		strms = &qcc->streams_by_id;
		qcs_type = qcs_id_type(id);

		/* TODO also checks max-streams for uni streams */
		if (quic_stream_is_bidi(id)) {
			if (sub_id + 1 > qcc->lfctl.ms_bidi) {
				/* streams limit reached */
				goto out;
			}
		}

		/* Note: ->largest_id was initialized with (uint64_t)-1 as value, 0 being a
		 * correct value.
		 */
		largest_id = qcc->strms[qcs_type].largest_id;
		if (sub_id > (int64_t)largest_id) {
			/* RFC: "A stream ID that is used out of order results in all streams
			 * of that type with lower-numbered stream IDs also being opened".
			 * So, let's "open" these streams.
			 */
			int64_t i;
			struct qcs *tmp_qcs;

			tmp_qcs = NULL;
			for (i = largest_id + 1; i <= sub_id; i++) {
				uint64_t id = (i << QCS_ID_TYPE_SHIFT) | strm_type;
				enum qcs_type type = id & QCS_ID_DIR_BIT ? QCS_CLT_UNI : QCS_CLT_BIDI;

				tmp_qcs = qcs_new(qcc, id, type);
				if (!tmp_qcs) {
					/* allocation failure */
					goto out;
				}

				qcc->strms[qcs_type].largest_id = i;
			}
			if (tmp_qcs)
				qcs = tmp_qcs;
		}
		else {
			node = eb64_lookup(strms, id);
			if (node)
				qcs = eb64_entry(node, struct qcs, by_id);
		}
	}

	return qcs;

 out:
	return NULL;
}

/* Handle a new STREAM frame <strm_frm>. The frame content will be copied in
 * the buffer of the stream instance. The stream instance will be stored in
 * <out_qcs>. In case of success, the caller can immediatly call qcc_decode_qcs
 * to process the frame content.
 *
 * Returns a code indicating how the frame was handled.
 * - 0: frame received completly and can be dropped.
 * - 1: frame not received but can be dropped.
 * - 2: frame cannot be handled, either partially or not at all. <done>
 *   indicated the number of bytes handled. The rest should be buffered.
 */
int qcc_recv(struct qcc *qcc, uint64_t id, uint64_t len, uint64_t offset,
             char fin, char *data, struct qcs **out_qcs, size_t *done)
{
	struct qcs *qcs;
	size_t total, diff;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	*out_qcs = NULL;
	*done = 0;

	qcs = qcc_get_qcs(qcc, id);
	if (!qcs) {
		TRACE_DEVEL("leaving on stream not found", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
		return 1;
	}

	*out_qcs = qcs;

	if (offset > qcs->rx.offset)
		return 2;

	if (offset + len <= qcs->rx.offset) {
		TRACE_DEVEL("leaving on already received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		return 1;
	}

	/* Last frame already handled for this stream. */
	BUG_ON(qcs->flags & QC_SF_FIN_RECV);
	/* TODO initial max-stream-data overflow. Implement FLOW_CONTROL_ERROR emission. */
	BUG_ON(offset + len > qcs->rx.msd);

	if (!qc_get_buf(qcs, &qcs->rx.buf) || b_full(&qcs->rx.buf)) {
		/* TODO should mark qcs as full */
		return 2;
	}

	TRACE_DEVEL("newly received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
	diff = qcs->rx.offset - offset;

	len -= diff;
	data += diff;

	/* TODO handle STREAM frames larger than RX buffer. */
	BUG_ON(len > b_size(&qcs->rx.buf));

	total = b_putblk(&qcs->rx.buf, data, len);
	qcs->rx.offset += total;
	*done = total;

	/* TODO initial max-stream-data reached. Implement MAX_STREAM_DATA emission. */
	BUG_ON(qcs->rx.offset == qcs->rx.msd);

	if (total < len) {
		TRACE_DEVEL("leaving on partially received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		return 2;
	}

	if (fin)
		qcs->flags |= QC_SF_FIN_RECV;

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;
}

/* Handle a new MAX_DATA frame. <max> must contains the maximum data field of
 * the frame.
 *
 * Returns 0 on success else non-zero.
 */
int qcc_recv_max_data(struct qcc *qcc, uint64_t max)
{
	if (qcc->rfctl.md < max) {
		qcc->rfctl.md = max;

		if (qcc->flags & QC_CF_BLK_MFCTL) {
			qcc->flags &= ~QC_CF_BLK_MFCTL;
			tasklet_wakeup(qcc->wait_event.tasklet);
		}
	}
	return 0;
}

/* Handle a new MAX_STREAM_DATA frame. <max> must contains the maximum data
 * field of the frame and <id> is the identifier of the QUIC stream.
 *
 * Returns 0 on success else non-zero.
 */
int qcc_recv_max_stream_data(struct qcc *qcc, uint64_t id, uint64_t max)
{
	struct qcs *qcs;
	struct eb64_node *node;

	node = eb64_lookup(&qcc->streams_by_id, id);
	if (node) {
		qcs = eb64_entry(node, struct qcs, by_id);
		if (max > qcs->tx.msd) {
			qcs->tx.msd = max;

			if (qcs->flags & QC_SF_BLK_SFCTL) {
				qcs->flags &= ~QC_SF_BLK_SFCTL;
				tasklet_wakeup(qcc->wait_event.tasklet);
			}
		}
	}

	return 0;
}

/* Decode the content of STREAM frames already received on the stream instance
 * <qcs>.
 *
 * Returns 0 on success else non-zero.
 */
int qcc_decode_qcs(struct qcc *qcc, struct qcs *qcs)
{
	TRACE_ENTER(QMUX_EV_QCS_RECV, qcc->conn, qcs);

	if (qcc->app_ops->decode_qcs(qcs, qcs->flags & QC_SF_FIN_RECV, qcc->ctx) < 0) {
		TRACE_DEVEL("leaving on decoding error", QMUX_EV_QCS_RECV, qcc->conn, qcs);
		return 1;
	}

	qcs_notify_recv(qcs);

	TRACE_LEAVE(QMUX_EV_QCS_RECV, qcc->conn, qcs);

	return 0;
}

static int qc_is_max_streams_needed(struct qcc *qcc)
{
	return qcc->lfctl.cl_bidi_r > qcc->lfctl.ms_bidi_init / 2;
}

/* detaches the QUIC stream from its QCC and releases it to the QCS pool. */
static void qcs_destroy(struct qcs *qcs)
{
	struct connection *conn = qcs->qcc->conn;
	const uint64_t id = qcs->id;

	TRACE_ENTER(QMUX_EV_QCS_END, conn, qcs);

	if (quic_stream_is_remote(qcs->qcc, id)) {
		if (quic_stream_is_bidi(id)) {
			++qcs->qcc->lfctl.cl_bidi_r;
			if (qc_is_max_streams_needed(qcs->qcc))
				tasklet_wakeup(qcs->qcc->wait_event.tasklet);
		}
	}

	qcs_free(qcs);

	TRACE_LEAVE(QMUX_EV_QCS_END, conn);
}

static inline int qcc_is_dead(const struct qcc *qcc)
{
	if (qcc->app_ops && qcc->app_ops->is_active &&
	    qcc->app_ops->is_active(qcc, qcc->ctx))
		return 0;

	if ((qcc->conn->flags & CO_FL_ERROR) || !qcc->task)
		return 1;

	return 0;
}

/* Return true if the mux timeout should be armed. */
static inline int qcc_may_expire(struct qcc *qcc)
{
	return !qcc->nb_cs;
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void qc_release(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;
	struct eb64_node *node;

	TRACE_ENTER(QMUX_EV_QCC_END);

	if (qcc->app_ops && qcc->app_ops->release)
		qcc->app_ops->release(qcc->ctx);

	if (qcc->task) {
		task_destroy(qcc->task);
		qcc->task = NULL;
	}

	if (qcc->wait_event.tasklet)
		tasklet_free(qcc->wait_event.tasklet);
	if (conn && qcc->wait_event.events) {
		conn->xprt->unsubscribe(conn, conn->xprt_ctx,
		                        qcc->wait_event.events,
		                        &qcc->wait_event);
	}

	/* liberate remaining qcs instances */
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = eb64_entry(node, struct qcs, by_id);
		node = eb64_next(node);
		qcs_free(qcs);
	}

	pool_free(pool_head_qcc, qcc);

	if (conn) {
		LIST_DEL_INIT(&conn->stopping_list);

		conn->handle.qc->conn = NULL;
		conn->mux = NULL;
		conn->ctx = NULL;

		TRACE_DEVEL("freeing conn", QMUX_EV_QCC_END, conn);

		conn_stop_tracking(conn);
		conn_full_close(conn);
		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}

	TRACE_LEAVE(QMUX_EV_QCC_END);
}

/* Transfer as much as possible data on <qcs> from <in> to <out>. <max_data> is
 * the current flow-control limit on the connection which must not be exceeded.
 *
 * Returns the total bytes of transferred data.
 */
static int qcs_xfer_data(struct qcs *qcs, struct buffer *out,
                         struct buffer *in, uint64_t max_data)
{
	struct qcc *qcc = qcs->qcc;
	int left, to_xfer;
	int total = 0;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	qc_get_buf(qcs, out);

	/*
	 * QCS out buffer diagram
	 *             head           left    to_xfer
	 *         -------------> ----------> ----->
	 * --------------------------------------------------
	 *       |...............|xxxxxxxxxxx|<<<<<
	 * --------------------------------------------------
	 *       ^ ack-off       ^ sent-off  ^ off
	 *
	 * STREAM frame
	 *                       ^                 ^
	 *                       |xxxxxxxxxxxxxxxxx|
	 */

	BUG_ON_HOT(qcs->tx.sent_offset < qcs->stream->ack_offset);
	BUG_ON_HOT(qcs->tx.offset < qcs->tx.sent_offset);

	left = qcs->tx.offset - qcs->tx.sent_offset;
	to_xfer = QUIC_MIN(b_data(in), b_room(out));

	BUG_ON_HOT(qcs->tx.offset > qcs->tx.msd);
	/* do not exceed flow control limit */
	if (qcs->tx.offset + to_xfer > qcs->tx.msd)
		to_xfer = qcs->tx.msd - qcs->tx.offset;

	BUG_ON_HOT(max_data > qcc->rfctl.md);
	/* do not overcome flow control limit on connection */
	if (max_data + to_xfer > qcc->rfctl.md)
		to_xfer = qcc->rfctl.md - max_data;

	if (!left && !to_xfer)
		goto out;

	total = b_force_xfer(out, in, to_xfer);

 out:
	{
		struct qcs_xfer_data_trace_arg arg = {
			.prep = b_data(out), .xfer = total,
		};
		TRACE_LEAVE(QMUX_EV_QCS_SEND|QMUX_EV_QCS_XFER_DATA,
		            qcc->conn, qcs, &arg);
	}

	return total;
}

/* Prepare a STREAM frame for <qcs> instance using <out> as payload. The frame
 * is appended in <frm_list>. Set <fin> if this is supposed to be the last
 * stream frame.
 *
 * Returns the length of the STREAM frame or a negative error code.
 */
static int qcs_build_stream_frm(struct qcs *qcs, struct buffer *out, char fin,
                                struct list *frm_list)
{
	struct qcc *qcc = qcs->qcc;
	struct quic_frame *frm;
	int head, total;
	uint64_t base_off;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	/* if ack_offset < buf_offset, it points to an older buffer. */
	base_off = MAX(qcs->stream->buf_offset, qcs->stream->ack_offset);
	BUG_ON(qcs->tx.sent_offset < base_off);

	head = qcs->tx.sent_offset - base_off;
	total = b_data(out) - head;
	BUG_ON(total < 0);

	if (!total) {
		TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
		return 0;
	}
	BUG_ON(qcs->tx.sent_offset >= qcs->tx.offset);
	BUG_ON(qcs->tx.sent_offset + total > qcs->tx.offset);

	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm)
		goto err;

	frm->type = QUIC_FT_STREAM_8;
	frm->stream.stream = qcs->stream;
	frm->stream.id = qcs->id;
	frm->stream.buf = out;
	frm->stream.data = (unsigned char *)b_peek(out, head);

	/* FIN is positioned only when the buffer has been totally emptied. */
	if (fin)
		frm->type |= QUIC_STREAM_FRAME_TYPE_FIN_BIT;

	if (qcs->tx.sent_offset) {
		frm->type |= QUIC_STREAM_FRAME_TYPE_OFF_BIT;
		frm->stream.offset.key = qcs->tx.sent_offset;
	}

	frm->type |= QUIC_STREAM_FRAME_TYPE_LEN_BIT;
	frm->stream.len = total;

	LIST_APPEND(frm_list, &frm->list);

 out:
	{
		struct qcs_build_stream_trace_arg arg = {
			.len = frm->stream.len, .fin = fin,
			.offset = frm->stream.offset.key,
		};
		TRACE_LEAVE(QMUX_EV_QCS_SEND|QMUX_EV_QCS_BUILD_STRM,
		            qcc->conn, qcs, &arg);
	}

	return total;

 err:
	TRACE_DEVEL("leaving in error", QMUX_EV_QCS_SEND, qcc->conn, qcs);
	return -1;
}

/* This function must be called by the upper layer to inform about the sending
 * of a STREAM frame for <qcs> instance. The frame is of <data> length and on
 * <offset>.
 */
void qcc_streams_sent_done(struct qcs *qcs, uint64_t data, uint64_t offset)
{
	struct qcc *qcc = qcs->qcc;
	uint64_t diff;

	BUG_ON(offset > qcs->tx.sent_offset);
	BUG_ON(offset >= qcs->tx.offset);

	/* check if the STREAM frame has already been notified. It can happen
	 * for retransmission.
	 */
	if (offset + data <= qcs->tx.sent_offset)
		return;

	diff = offset + data - qcs->tx.sent_offset;

	/* increase offset sum on connection */
	qcc->tx.sent_offsets += diff;
	BUG_ON_HOT(qcc->tx.sent_offsets > qcc->rfctl.md);
	if (qcc->tx.sent_offsets == qcc->rfctl.md)
		qcc->flags |= QC_CF_BLK_MFCTL;

	/* increase offset on stream */
	qcs->tx.sent_offset += diff;
	BUG_ON_HOT(qcs->tx.sent_offset > qcs->tx.msd);
	BUG_ON_HOT(qcs->tx.sent_offset > qcs->tx.offset);
	if (qcs->tx.sent_offset == qcs->tx.msd)
		qcs->flags |= QC_SF_BLK_SFCTL;

	if (qcs->tx.offset == qcs->tx.sent_offset && b_full(&qcs->stream->buf->buf)) {
		qc_stream_buf_release(qcs->stream);
		/* prepare qcs for immediate send retry if data to send */
		if (b_data(&qcs->tx.buf))
			LIST_APPEND(&qcc->send_retry_list, &qcs->el);
	}
}

/* Wrapper for send on transport layer. Send a list of frames <frms> for the
 * connection <qcc>.
 *
 * Returns 0 if all data sent with success else non-zero.
 */
static int qc_send_frames(struct qcc *qcc, struct list *frms)
{
	/* TODO implement an opportunistic retry mechanism. This is needed
	 * because qc_send_app_pkts is not completed. It will only prepare data
	 * up to its Tx buffer. The frames left are not send even if the Tx
	 * buffer is emptied by the sendto call.
	 *
	 * To overcome this, we call repeatedly qc_send_app_pkts until we
	 * detect that the transport layer has send nothing. This could happen
	 * on congestion or sendto syscall error.
	 *
	 * When qc_send_app_pkts is improved to handle retry by itself, we can
	 * remove the looping from the MUX.
	 */
	struct quic_frame *first_frm;
	uint64_t first_offset = 0;
	char first_stream_frame_type;

	TRACE_ENTER(QMUX_EV_QCC_SEND, qcc->conn);

	if (LIST_ISEMPTY(frms)) {
		TRACE_DEVEL("leaving with no frames to send", QMUX_EV_QCC_SEND, qcc->conn);
		return 1;
	}

	LIST_INIT(&qcc->send_retry_list);

 retry_send:
	first_frm = LIST_ELEM(frms->n, struct quic_frame *, list);
	if ((first_frm->type & QUIC_FT_STREAM_8) == QUIC_FT_STREAM_8) {
		first_offset = first_frm->stream.offset.key;
		first_stream_frame_type = 1;
	}
	else {
		first_stream_frame_type = 0;
	}

	if (!LIST_ISEMPTY(frms))
		qc_send_app_pkts(qcc->conn->handle.qc, frms);

	/* If there is frames left, check if the transport layer has send some
	 * data or is blocked.
	 */
	if (!LIST_ISEMPTY(frms)) {
		if (first_frm != LIST_ELEM(frms->n, struct quic_frame *, list))
			goto retry_send;

		/* If the first frame is STREAM, check if its offset has
		 * changed.
		 */
		if (first_stream_frame_type &&
		    first_offset != LIST_ELEM(frms->n, struct quic_frame *, list)->stream.offset.key) {
			goto retry_send;
		}
	}

	/* If there is frames left at this stage, transport layer is blocked.
	 * Subscribe on it to retry later.
	 */
	if (!LIST_ISEMPTY(frms)) {
		TRACE_DEVEL("leaving with remaining frames to send, subscribing", QMUX_EV_QCC_SEND, qcc->conn);
		qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
		                           SUB_RETRY_SEND, &qcc->wait_event);
		return 1;
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND);

	return 0;
}

/* Send a MAX_STREAM_BIDI frame to update the limit of bidirectional streams
 * allowed to be opened by the peer. The caller should have first checked if
 * this is required with qc_is_max_streams_needed.
 *
 * Returns 0 on success else non-zero.
 */
static int qc_send_max_streams(struct qcc *qcc)
{
	struct list frms = LIST_HEAD_INIT(frms);
	struct quic_frame *frm;

	frm = pool_zalloc(pool_head_quic_frame);
	BUG_ON(!frm); /* TODO handle this properly */

	frm->type = QUIC_FT_MAX_STREAMS_BIDI;
	frm->max_streams_bidi.max_streams = qcc->lfctl.ms_bidi +
	                                    qcc->lfctl.cl_bidi_r;
	TRACE_DEVEL("sending MAX_STREAMS frame", QMUX_EV_SEND_FRM, qcc->conn, NULL, frm);
	LIST_APPEND(&frms, &frm->list);

	if (qc_send_frames(qcc, &frms))
		return 1;

	/* save the new limit if the frame has been send. */
	qcc->lfctl.ms_bidi += qcc->lfctl.cl_bidi_r;
	qcc->lfctl.cl_bidi_r = 0;

	return 0;
}

/* Used internally by qc_send function. Proceed to send for <qcs>. This will
 * transfer data from qcs buffer to its quic_stream counterpart. A STREAM frame
 * is then generated and inserted in <frms> list. <qcc_max_data> is the current
 * flow-control max-data at the connection level which must not be surpassed.
 *
 * Returns the total bytes transferred between qcs and quic_stream buffers. Can
 * be null if out buffer cannot be allocated.
 */
static int _qc_send_qcs(struct qcs *qcs, struct list *frms,
                        uint64_t qcc_max_data)
{
	struct qcc *qcc = qcs->qcc;
	struct buffer *buf = &qcs->tx.buf;
	struct buffer *out = qc_stream_buf_get(qcs->stream);
	int xfer = 0;

	/* Allocate <out> buffer if necessary. */
	if (!out) {
		if (qcc->flags & QC_CF_CONN_FULL)
			return 0;

		out = qc_stream_buf_alloc(qcs->stream, qcs->tx.offset);
		if (!out) {
			qcc->flags |= QC_CF_CONN_FULL;
			return 0;
		}
	}

	/* Transfer data from <buf> to <out>. */
	if (b_data(buf)) {
		xfer = qcs_xfer_data(qcs, out, buf, qcc_max_data);
		if (xfer > 0) {
			qcs_notify_send(qcs);
			qcs->flags &= ~QC_SF_BLK_MROOM;
		}

		qcs->tx.offset += xfer;
	}

	/* out buffer cannot be emptied if qcs offsets differ. */
	BUG_ON(!b_data(out) && qcs->tx.sent_offset != qcs->tx.offset);

	/* Build a new STREAM frame with <out> buffer. */
	if (qcs->tx.sent_offset != qcs->tx.offset) {
		int ret;
		char fin = !!(qcs->flags & QC_SF_FIN_STREAM);

		/* FIN is set if all incoming data were transfered. */
		fin = !!(fin && !b_data(buf));

		ret = qcs_build_stream_frm(qcs, out, fin, frms);
		if (ret < 0) { ABORT_NOW(); /* TODO handle this properly */ }
	}

	return xfer;
}

/* Proceed to sending. Loop through all available streams for the <qcc>
 * instance and try to send as much as possible.
 *
 * Returns the total of bytes sent to the transport layer.
 */
static int qc_send(struct qcc *qcc)
{
	struct list frms = LIST_HEAD_INIT(frms);
	struct eb64_node *node;
	struct qcs *qcs, *qcs_tmp;
	int total = 0, tmp_total = 0;

	TRACE_ENTER(QMUX_EV_QCC_SEND);

	if (qcc->conn->flags & CO_FL_SOCK_WR_SH) {
		qcc->conn->flags |= CO_FL_ERROR;
		TRACE_DEVEL("leaving on error", QMUX_EV_QCC_SEND, qcc->conn);
		return 0;
	}

	if (qc_is_max_streams_needed(qcc))
		qc_send_max_streams(qcc);

	if (qcc->flags & QC_CF_BLK_MFCTL)
		return 0;

	/* loop through all streams, construct STREAM frames if data available.
	 * TODO optimize the loop to favor streams which are not too heavy.
	 */
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		int ret;
		qcs = eb64_entry(node, struct qcs, by_id);

		/* TODO
		 * for the moment, unidirectional streams have their own
		 * mechanism for sending. This should be unified in the future,
		 * in this case the next check will be removed.
		 */
		if (quic_stream_is_uni(qcs->id)) {
			node = eb64_next(node);
			continue;
		}

		if (qcs->flags & QC_SF_BLK_SFCTL) {
			node = eb64_next(node);
			continue;
		}

		if (!b_data(&qcs->tx.buf) && !qc_stream_buf_get(qcs->stream)) {
			node = eb64_next(node);
			continue;
		}

		ret = _qc_send_qcs(qcs, &frms, qcc->tx.sent_offsets + total);
		total += ret;
		node = eb64_next(node);
	}

	if (qc_send_frames(qcc, &frms)) {
		/* data rejected by transport layer, do not retry. */
		goto out;
	}

 retry:
	tmp_total = 0;
	list_for_each_entry_safe(qcs, qcs_tmp, &qcc->send_retry_list, el) {
		int ret;
		BUG_ON(!b_data(&qcs->tx.buf));
		BUG_ON(qc_stream_buf_get(qcs->stream));

		ret = _qc_send_qcs(qcs, &frms, qcc->tx.sent_offsets + tmp_total);
		tmp_total += ret;
		LIST_DELETE(&qcs->el);
	}

	total += tmp_total;
	if (!qc_send_frames(qcc, &frms) && !LIST_ISEMPTY(&qcc->send_retry_list))
		goto retry;

 out:
	TRACE_LEAVE(QMUX_EV_QCC_SEND);

	return total;
}

/* Release all streams that are already marked as detached. This is only done
 * if their TX buffers are empty or if a CONNECTION_CLOSE has been received.
 *
 * Return the number of released stream.
 */
static int qc_release_detached_streams(struct qcc *qcc)
{
	struct eb64_node *node;
	int release = 0;

	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = eb64_entry(node, struct qcs, by_id);
		node = eb64_next(node);

		if (qcs->flags & QC_SF_DETACH) {
			if (!b_data(&qcs->tx.buf) &&
			    qcs->tx.offset == qcs->tx.sent_offset) {
				qcs_destroy(qcs);
				release = 1;
			}
			else {
				qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
				                           SUB_RETRY_SEND, &qcc->wait_event);
			}
		}
	}

	return release;
}

static struct task *qc_io_cb(struct task *t, void *ctx, unsigned int status)
{
	struct qcc *qcc = ctx;

	TRACE_ENTER(QMUX_EV_QCC_WAKE);

	qc_send(qcc);

	if (qc_release_detached_streams(qcc)) {
		if (qcc_is_dead(qcc)) {
			qc_release(qcc);
		}
		else if (qcc->task) {
			if (qcc_may_expire(qcc))
				qcc->task->expire = tick_add(now_ms, qcc->timeout);
			else
				qcc->task->expire = TICK_ETERNITY;
			task_queue(qcc->task);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_WAKE);

	return NULL;
}

static struct task *qc_timeout_task(struct task *t, void *ctx, unsigned int state)
{
	struct qcc *qcc = ctx;
	int expired = tick_is_expired(t->expire, now_ms);

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc ? qcc->conn : NULL);

	if (qcc) {
		if (!expired) {
			TRACE_DEVEL("leaving (not expired)", QMUX_EV_QCC_WAKE, qcc->conn);
			return t;
		}

		if (!qcc_may_expire(qcc)) {
			TRACE_DEVEL("leaving (cannot expired)", QMUX_EV_QCC_WAKE, qcc->conn);
			t->expire = TICK_ETERNITY;
			return t;
		}
	}

	task_destroy(t);

	if (!qcc) {
		TRACE_DEVEL("leaving (not more qcc)", QMUX_EV_QCC_WAKE);
		return NULL;
	}

	qcc->task = NULL;

	if (qcc_is_dead(qcc))
		qc_release(qcc);

	TRACE_LEAVE(QMUX_EV_QCC_WAKE);

	return NULL;
}

static int qc_init(struct connection *conn, struct proxy *prx,
                   struct session *sess, struct buffer *input)
{
	struct qcc *qcc;
	struct quic_transport_params *lparams, *rparams;

	qcc = pool_alloc(pool_head_qcc);
	if (!qcc)
		goto fail_no_qcc;

	qcc->conn = conn;
	conn->ctx = qcc;
	qcc->nb_cs = 0;
	qcc->flags = 0;

	qcc->app_ops = NULL;

	qcc->streams_by_id = EB_ROOT_UNIQUE;

	/* Server parameters, params used for RX flow control. */
	lparams = &conn->handle.qc->rx.params;

	qcc->rx.max_data = lparams->initial_max_data;
	qcc->tx.sent_offsets = 0;

	/* Client initiated streams must respect the server flow control. */
	qcc->strms[QCS_CLT_BIDI].max_streams = lparams->initial_max_streams_bidi;
	qcc->strms[QCS_CLT_BIDI].nb_streams = 0;
	qcc->strms[QCS_CLT_BIDI].largest_id = -1;
	qcc->strms[QCS_CLT_BIDI].rx.max_data = 0;
	qcc->strms[QCS_CLT_BIDI].tx.max_data = lparams->initial_max_stream_data_bidi_remote;

	qcc->strms[QCS_CLT_UNI].max_streams = lparams->initial_max_streams_uni;
	qcc->strms[QCS_CLT_UNI].nb_streams = 0;
	qcc->strms[QCS_CLT_UNI].largest_id = -1;
	qcc->strms[QCS_CLT_UNI].rx.max_data = 0;
	qcc->strms[QCS_CLT_UNI].tx.max_data = lparams->initial_max_stream_data_uni;

	/* Server initiated streams must respect the server flow control. */
	qcc->strms[QCS_SRV_BIDI].max_streams = 0;
	qcc->strms[QCS_SRV_BIDI].nb_streams = 0;
	qcc->strms[QCS_SRV_BIDI].largest_id = -1;
	qcc->strms[QCS_SRV_BIDI].rx.max_data = lparams->initial_max_stream_data_bidi_local;
	qcc->strms[QCS_SRV_BIDI].tx.max_data = 0;

	qcc->strms[QCS_SRV_UNI].max_streams = 0;
	qcc->strms[QCS_SRV_UNI].nb_streams = 0;
	qcc->strms[QCS_SRV_UNI].largest_id = -1;
	qcc->strms[QCS_SRV_UNI].rx.max_data = lparams->initial_max_stream_data_uni;
	qcc->strms[QCS_SRV_UNI].tx.max_data = 0;

	qcc->lfctl.ms_bidi = qcc->lfctl.ms_bidi_init = lparams->initial_max_streams_bidi;
	qcc->lfctl.msd_bidi_l = lparams->initial_max_stream_data_bidi_local;
	qcc->lfctl.msd_bidi_r = lparams->initial_max_stream_data_bidi_remote;
	qcc->lfctl.cl_bidi_r = 0;

	rparams = &conn->handle.qc->tx.params;
	qcc->rfctl.md = rparams->initial_max_data;
	qcc->rfctl.msd_bidi_l = rparams->initial_max_stream_data_bidi_local;
	qcc->rfctl.msd_bidi_r = rparams->initial_max_stream_data_bidi_remote;

	qcc->wait_event.tasklet = tasklet_new();
	if (!qcc->wait_event.tasklet)
		goto fail_no_tasklet;

	LIST_INIT(&qcc->send_retry_list);

	qcc->subs = NULL;
	qcc->wait_event.tasklet->process = qc_io_cb;
	qcc->wait_event.tasklet->context = qcc;
	qcc->wait_event.events = 0;

	/* haproxy timeouts */
	qcc->task = NULL;
	qcc->timeout = prx->timeout.client;
	if (tick_isset(qcc->timeout)) {
		qcc->task = task_new_here();
		if (!qcc->task)
			goto fail_no_timeout_task;
		qcc->task->process = qc_timeout_task;
		qcc->task->context = qcc;
		qcc->task->expire = tick_add(now_ms, qcc->timeout);
	}

	if (!conn_is_back(conn)) {
		if (!LIST_INLIST(&conn->stopping_list)) {
			LIST_APPEND(&mux_stopping_data[tid].list,
			            &conn->stopping_list);
		}
	}

	HA_ATOMIC_STORE(&conn->handle.qc->qcc, qcc);
	/* init read cycle */
	tasklet_wakeup(qcc->wait_event.tasklet);

	return 0;

 fail_no_timeout_task:
	tasklet_free(qcc->wait_event.tasklet);
 fail_no_tasklet:
	pool_free(pool_head_qcc, qcc);
 fail_no_qcc:
	return -1;
}

static void qc_destroy(void *ctx)
{
	struct qcc *qcc = ctx;

	TRACE_ENTER(QMUX_EV_QCC_END, qcc->conn);
	qc_release(qcc);
	TRACE_LEAVE(QMUX_EV_QCC_END);
}

static void qc_detach(struct conn_stream *cs)
{
	struct qcs *qcs = __cs_mux(cs);
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_STRM_END, qcc->conn, qcs);

	qcs->cs = NULL;
	--qcc->nb_cs;

	if ((b_data(&qcs->tx.buf) || qcs->tx.offset > qcs->tx.sent_offset) &&
	    !(qcc->conn->flags & CO_FL_ERROR)) {
		TRACE_DEVEL("leaving with remaining data, detaching qcs", QMUX_EV_STRM_END, qcc->conn, qcs);
		qcs->flags |= QC_SF_DETACH;
		return;
	}

	qcs_destroy(qcs);

	if (qcc_is_dead(qcc)) {
		qc_release(qcc);
	}
	else if (qcc->task) {
		if (qcc_may_expire(qcc))
			qcc->task->expire = tick_add(now_ms, qcc->timeout);
		else
			qcc->task->expire = TICK_ETERNITY;
		task_queue(qcc->task);
	}

	TRACE_LEAVE(QMUX_EV_STRM_END);
}

/* Called from the upper layer, to receive data */
static size_t qc_rcv_buf(struct conn_stream *cs, struct buffer *buf,
                         size_t count, int flags)
{
	struct qcs *qcs = __cs_mux(cs);
	struct htx *qcs_htx = NULL;
	struct htx *cs_htx = NULL;
	size_t ret = 0;
	char fin = 0;

	TRACE_ENTER(QMUX_EV_STRM_RECV, qcs->qcc->conn, qcs);

	qcs_htx = htx_from_buf(&qcs->rx.app_buf);
	if (htx_is_empty(qcs_htx)) {
		/* Set buffer data to 0 as HTX is empty. */
		htx_to_buf(qcs_htx, &qcs->rx.app_buf);
		goto end;
	}

	ret = qcs_htx->data;

	cs_htx = htx_from_buf(buf);
	if (htx_is_empty(cs_htx) && htx_used_space(qcs_htx) <= count) {
		htx_to_buf(cs_htx, buf);
		htx_to_buf(qcs_htx, &qcs->rx.app_buf);
		b_xfer(buf, &qcs->rx.app_buf, b_data(&qcs->rx.app_buf));
		goto end;
	}

	htx_xfer_blks(cs_htx, qcs_htx, count, HTX_BLK_UNUSED);
	BUG_ON(qcs_htx->flags & HTX_FL_PARSING_ERROR);

	/* Copy EOM from src to dst buffer if all data copied. */
	if (htx_is_empty(qcs_htx) && (qcs_htx->flags & HTX_FL_EOM)) {
		cs_htx->flags |= HTX_FL_EOM;
		fin = 1;
	}

	cs_htx->extra = qcs_htx->extra ? (qcs_htx->data + qcs_htx->extra) : 0;
	htx_to_buf(cs_htx, buf);
	htx_to_buf(qcs_htx, &qcs->rx.app_buf);
	ret -= qcs_htx->data;

 end:
	if (b_data(&qcs->rx.app_buf)) {
		cs->endp->flags |= (CS_EP_RCV_MORE | CS_EP_WANT_ROOM);
	}
	else {
		cs->endp->flags &= ~(CS_EP_RCV_MORE | CS_EP_WANT_ROOM);
		if (cs->endp->flags & CS_EP_ERR_PENDING)
			cs->endp->flags |= CS_EP_ERROR;

		if (fin)
			cs->endp->flags |= CS_EP_EOI;

		if (b_size(&qcs->rx.app_buf)) {
			b_free(&qcs->rx.app_buf);
			offer_buffers(NULL, 1);
		}
	}

	if (ret)
		tasklet_wakeup(qcs->qcc->wait_event.tasklet);

	TRACE_LEAVE(QMUX_EV_STRM_RECV, qcs->qcc->conn, qcs);

	return ret;
}

static size_t qc_snd_buf(struct conn_stream *cs, struct buffer *buf,
                         size_t count, int flags)
{
	struct qcs *qcs = __cs_mux(cs);
	size_t ret;

	TRACE_ENTER(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	ret = qcs->qcc->app_ops->snd_buf(cs, buf, count, flags);

	TRACE_LEAVE(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	return ret;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int qc_subscribe(struct conn_stream *cs, int event_type,
                        struct wait_event *es)
{
	return qcs_subscribe(__cs_mux(cs), event_type, es);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int qc_unsubscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	struct qcs *qcs = __cs_mux(cs);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		qcs->subs = NULL;

	return 0;
}

/* Loop through all qcs from <qcc>. If CO_FL_ERROR is set on the connection,
 * report CS_EP_ERR_PENDING|CS_EP_ERROR on the attached conn-streams and wake
 * them.
 */
static int qc_wake_some_streams(struct qcc *qcc)
{
	struct qcs *qcs;
	struct eb64_node *node;

	for (node = eb64_first(&qcc->streams_by_id); node;
	     node = eb64_next(node)) {
		qcs = eb64_entry(node, struct qcs, by_id);

		if (!qcs->cs)
			continue;

		if (qcc->conn->flags & CO_FL_ERROR) {
			qcs->endp->flags |= CS_EP_ERR_PENDING;
			if (qcs->endp->flags & CS_EP_EOS)
				qcs->endp->flags |= CS_EP_ERROR;

			if (qcs->subs) {
				qcs_notify_recv(qcs);
				qcs_notify_send(qcs);
			}
			else if (qcs->cs->data_cb->wake) {
				qcs->cs->data_cb->wake(qcs->cs);
			}
		}
	}

	return 0;
}

static int qc_wake(struct connection *conn)
{
	struct qcc *qcc = conn->ctx;
	struct proxy *prx = conn->handle.qc->li->bind_conf->frontend;

	TRACE_ENTER(QMUX_EV_QCC_WAKE, conn);

	/* Check if a soft-stop is in progress.
	 * Release idling front connection if this is the case.
	 *
	 * TODO this is revelant for frontend connections only.
	 */
	if (unlikely(prx->flags & (PR_FL_DISABLED|PR_FL_STOPPED)))
		goto release;

	if (conn->handle.qc->flags & QUIC_FL_CONN_NOTIFY_CLOSE)
		qcc->conn->flags |= (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH);

	qc_send(qcc);

	qc_wake_some_streams(qcc);

	if (qcc_is_dead(qcc))
		goto release;

	TRACE_LEAVE(QMUX_EV_QCC_WAKE, conn);

	return 0;

 release:
	qc_release(qcc);
	TRACE_DEVEL("leaving after releasing the connection", QMUX_EV_QCC_WAKE);
	return 1;
}


static void qmux_trace_frm(const struct quic_frame *frm)
{
	switch (frm->type) {
	case QUIC_FT_MAX_STREAMS_BIDI:
		chunk_appendf(&trace_buf, " max_streams=%lu",
		              frm->max_streams_bidi.max_streams);
		break;

	case QUIC_FT_MAX_STREAMS_UNI:
		chunk_appendf(&trace_buf, " max_streams=%lu",
		              frm->max_streams_uni.max_streams);
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
		chunk_appendf(&trace_buf, " : qcc=%p(F)", qcc);

		if (qcs)
			chunk_appendf(&trace_buf, " qcs=%p(%lu)", qcs, qcs->id);

		if (mask & QMUX_EV_QCC_NQCS) {
			const uint64_t *id = a3;
			chunk_appendf(&trace_buf, " id=%lu", *id);
		}

		if (mask & QMUX_EV_SEND_FRM)
			qmux_trace_frm(a3);

		if (mask & QMUX_EV_QCS_XFER_DATA) {
			const struct qcs_xfer_data_trace_arg *arg = a3;
			chunk_appendf(&trace_buf, " prep=%lu xfer=%d",
			              arg->prep, arg->xfer);
		}

		if (mask & QMUX_EV_QCS_BUILD_STRM) {
			const struct qcs_build_stream_trace_arg *arg = a3;
			chunk_appendf(&trace_buf, " len=%lu fin=%d offset=%lu",
			              arg->len, arg->fin, arg->offset);
		}
	}
}

/* Function to automatically activate QUIC MUX traces on stdout.
 * Activated via the compilation flag -DENABLE_QUIC_STDOUT_TRACES.
 * Main use for now is in the docker image for QUIC interop testing.
 */
static void qmux_init_stdout_traces(void)
{
#ifdef ENABLE_QUIC_STDOUT_TRACES
	trace_qmux.sink = sink_find("stdout");
	trace_qmux.level = TRACE_LEVEL_DEVELOPER;
	trace_qmux.state = TRACE_STATE_RUNNING;
	trace_qmux.verbosity = QMUX_VERB_MINIMAL;
#endif
}
INITCALL0(STG_INIT, qmux_init_stdout_traces);


static const struct mux_ops qc_ops = {
	.init = qc_init,
	.destroy = qc_destroy,
	.detach = qc_detach,
	.rcv_buf = qc_rcv_buf,
	.snd_buf = qc_snd_buf,
	.subscribe = qc_subscribe,
	.unsubscribe = qc_unsubscribe,
	.wake = qc_wake,
	.flags = MX_FL_HTX|MX_FL_NO_UPG,
	.name = "QUIC",
};

static struct mux_proto_list mux_proto_quic =
  { .token = IST("quic"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_FE, .mux = &qc_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_quic);
