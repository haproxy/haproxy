#include <haproxy/mux_quic.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/ncbuf.h>
#include <haproxy/pool.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/stconn.h>
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

/* Emit a CONNECTION_CLOSE with error <err>. This will interrupt all future
 * send/receive operations.
 */
static void qcc_emit_cc(struct qcc *qcc, int err)
{
	quic_set_connection_close(qcc->conn->handle.qc, quic_err_transport(err));
	qcc->flags |= QC_CF_CC_EMIT;
	tasklet_wakeup(qcc->wait_event.tasklet);
}

/* Allocate a new QUIC streams with id <id> and type <type>. */
static struct qcs *qcs_new(struct qcc *qcc, uint64_t id, enum qcs_type type)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCS_NEW, qcc->conn);

	qcs = pool_alloc(pool_head_qcs);
	if (!qcs)
		return NULL;

	qcs->stream = NULL;
	qcs->qcc = qcc;
	qcs->sd = NULL;
	qcs->flags = QC_SF_NONE;
	qcs->st = QC_SS_IDLE;
	qcs->ctx = NULL;

	/* Allocate transport layer stream descriptor. Only needed for TX. */
	if (!quic_stream_is_uni(id) || !quic_stream_is_remote(qcc, id)) {
		struct quic_conn *qc = qcc->conn->handle.qc;
		qcs->stream = qc_stream_desc_new(id, type, qcs, qc);
		if (!qcs->stream)
			goto err;
	}

	qcs->id = qcs->by_id.key = id;
	if (qcc->app_ops->attach) {
		if (qcc->app_ops->attach(qcs, qcc->ctx))
			goto err;
	}

	/* store transport layer stream descriptor in qcc tree */
	eb64_insert(&qcc->streams_by_id, &qcs->by_id);

	qcc->strms[type].nb_streams++;

	/* If stream is local, use peer remote-limit, or else the opposite. */
	/* TODO use uni limit for unidirectional streams */
	qcs->tx.msd = quic_stream_is_local(qcc, id) ? qcc->rfctl.msd_bidi_r :
	                                              qcc->rfctl.msd_bidi_l;

	qcs->rx.ncbuf = NCBUF_NULL;
	qcs->rx.app_buf = BUF_NULL;
	qcs->rx.offset = qcs->rx.offset_max = 0;

	/* TODO use uni limit for unidirectional streams */
	qcs->rx.msd = quic_stream_is_local(qcc, id) ? qcc->lfctl.msd_bidi_l :
	                                              qcc->lfctl.msd_bidi_r;
	qcs->rx.msd_init = qcs->rx.msd;

	qcs->tx.buf = BUF_NULL;
	qcs->tx.offset = 0;
	qcs->tx.sent_offset = 0;

	qcs->wait_event.tasklet = NULL;
	qcs->wait_event.events = 0;
	qcs->subs = NULL;

	qcs->err = 0;

 out:
	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn, qcs);
	return qcs;

 err:
	if (qcs->ctx && qcc->app_ops->detach)
		qcc->app_ops->detach(qcs);

	qc_stream_desc_release(qcs->stream);
	pool_free(pool_head_qcs, qcs);
	return NULL;
}

static void qc_free_ncbuf(struct qcs *qcs, struct ncbuf *ncbuf)
{
	struct buffer buf;

	if (ncb_is_null(ncbuf))
		return;

	buf = b_make(ncbuf->area, ncbuf->size, 0, 0);
	b_free(&buf);
	offer_buffers(NULL, 1);

	*ncbuf = NCBUF_NULL;
}

/* Free a qcs. This function must only be done to remove a stream on allocation
 * error or connection shutdown. Else use qcs_destroy which handle all the
 * QUIC connection mechanism.
 */
static void qcs_free(struct qcs *qcs)
{
	qc_free_ncbuf(qcs, &qcs->rx.ncbuf);
	b_free(&qcs->tx.buf);

	BUG_ON(!qcs->qcc->strms[qcs_id_type(qcs->id)].nb_streams);
	--qcs->qcc->strms[qcs_id_type(qcs->id)].nb_streams;

	if (qcs->ctx && qcs->qcc->app_ops->detach)
		qcs->qcc->app_ops->detach(qcs);

	qc_stream_desc_release(qcs->stream);

	BUG_ON(qcs->sd && !se_fl_test(qcs->sd, SE_FL_ORPHAN));
	sedesc_free(qcs->sd);

	eb64_delete(&qcs->by_id);
	pool_free(pool_head_qcs, qcs);
}

static forceinline struct stconn *qcs_sc(const struct qcs *qcs)
{
	return qcs->sd ? qcs->sd->sc : NULL;
}

/* Reset the <qcc> inactivity timeout for http-keep-alive timeout. */
static forceinline void qcc_reset_idle_start(struct qcc *qcc)
{
	qcc->idle_start = now_ms;
}

/* Decrement <qcc> sc. */
static forceinline void qcc_rm_sc(struct qcc *qcc)
{
	BUG_ON_HOT(!qcc->nb_sc);
	--qcc->nb_sc;

	/* Reset qcc idle start for http-keep-alive timeout. Timeout will be
	 * refreshed after this on stream detach.
	 */
	if (!qcc->nb_sc && !qcc->nb_hreq)
		qcc_reset_idle_start(qcc);
}

/* Decrement <qcc> hreq. */
static forceinline void qcc_rm_hreq(struct qcc *qcc)
{
	BUG_ON_HOT(!qcc->nb_hreq);
	--qcc->nb_hreq;

	/* Reset qcc idle start for http-keep-alive timeout. Timeout will be
	 * refreshed after this on I/O handler.
	 */
	if (!qcc->nb_sc && !qcc->nb_hreq)
		qcc_reset_idle_start(qcc);
}

static inline int qcc_is_dead(const struct qcc *qcc)
{
	/* Mux connection is considered dead if :
	 * - all stream-desc are detached AND
	 *   = connection is on error OR
	 *   = mux timeout has already fired or is unset
	 */
	if (!qcc->nb_sc && ((qcc->conn->flags & CO_FL_ERROR) || !qcc->task))
		return 1;

	return 0;
}

/* Return true if the mux timeout should be armed. */
static inline int qcc_may_expire(struct qcc *qcc)
{
	return !qcc->nb_sc;
}

/* Refresh the timeout on <qcc> if needed depending on its state. */
static void qcc_refresh_timeout(struct qcc *qcc)
{
	const struct proxy *px = qcc->proxy;

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc->conn);

	if (!qcc->task)
		goto leave;

	/* Check if upper layer is responsible of timeout management. */
	if (!qcc_may_expire(qcc)) {
		TRACE_DEVEL("not eligible for timeout", QMUX_EV_QCC_WAKE, qcc->conn);
		qcc->task->expire = TICK_ETERNITY;
		task_queue(qcc->task);
		goto leave;
	}

	/* TODO if connection is idle on frontend and proxy is disabled, remove
	 * it with global close_spread delay applied.
	 */

	/* TODO implement specific timeouts
	 * - http-requset for waiting on incomplete streams
	 * - client-fin for graceful shutdown
	 */

	/* Frontend timeout management
	 * - detached streams with data left to send -> default timeout
	 * - idle after stream processing -> timeout http-keep-alive
	 */
	if (!conn_is_back(qcc->conn)) {
		int timeout;

		if (qcc->nb_hreq) {
			TRACE_DEVEL("one or more requests still in progress", QMUX_EV_QCC_WAKE, qcc->conn);
			qcc->task->expire = tick_add_ifset(now_ms, qcc->timeout);
			task_queue(qcc->task);
			goto leave;
		}

		/* Use http-request timeout if keep-alive timeout not set */
		timeout = tick_isset(px->timeout.httpka) ?
		            px->timeout.httpka : px->timeout.httpreq;

		TRACE_DEVEL("at least one request achieved but none currently in progress", QMUX_EV_QCC_WAKE, qcc->conn);
		qcc->task->expire = tick_add_ifset(qcc->idle_start, timeout);
	}

	/* fallback to default timeout if frontend specific undefined or for
	 * backend connections.
	 */
	if (!tick_isset(qcc->task->expire)) {
		TRACE_DEVEL("fallback to default timeout", QMUX_EV_QCC_WAKE, qcc->conn);
		qcc->task->expire = tick_add_ifset(now_ms, qcc->timeout);
	}

	task_queue(qcc->task);

 leave:
	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn);
}

/* Mark a stream as open if it was idle. This can be used on every
 * successful emission/reception operation to update the stream state.
 */
static void qcs_idle_open(struct qcs *qcs)
{
	/* This operation must not be used if the stream is already closed. */
	BUG_ON_HOT(qcs->st == QC_SS_CLO);

	if (qcs->st == QC_SS_IDLE) {
		qcs->st = QC_SS_OPEN;
		TRACE_DEVEL("opening stream", QMUX_EV_QCS_NEW, qcs->qcc->conn, qcs);
	}
}

/* Close the local channel of <qcs> instance. */
static void qcs_close_local(struct qcs *qcs)
{
	/* The stream must have already been opened. */
	BUG_ON_HOT(qcs->st == QC_SS_IDLE);

	/* This operation cannot be used multiple times. */
	BUG_ON_HOT(qcs->st == QC_SS_HLOC || qcs->st == QC_SS_CLO);

	if (quic_stream_is_bidi(qcs->id)) {
		qcs->st = (qcs->st == QC_SS_HREM) ? QC_SS_CLO : QC_SS_HLOC;
		qcc_rm_hreq(qcs->qcc);
	}
	else {
		/* Only local uni streams are valid for this operation. */
		BUG_ON_HOT(quic_stream_is_remote(qcs->qcc, qcs->id));
		qcs->st = QC_SS_CLO;
	}

	TRACE_DEVEL("closing stream locally", QMUX_EV_QCS_END, qcs->qcc->conn, qcs);
}

/* Close the remote channel of <qcs> instance. */
static void qcs_close_remote(struct qcs *qcs)
{
	/* The stream must have already been opened. */
	BUG_ON_HOT(qcs->st == QC_SS_IDLE);

	/* This operation cannot be used multiple times. */
	BUG_ON_HOT(qcs->st == QC_SS_HREM || qcs->st == QC_SS_CLO);

	if (quic_stream_is_bidi(qcs->id)) {
		qcs->st = (qcs->st == QC_SS_HLOC) ? QC_SS_CLO : QC_SS_HREM;
	}
	else {
		/* Only remote uni streams are valid for this operation. */
		BUG_ON_HOT(quic_stream_is_local(qcs->qcc, qcs->id));
		qcs->st = QC_SS_CLO;
	}

	TRACE_DEVEL("closing stream remotely", QMUX_EV_QCS_END, qcs->qcc->conn, qcs);
}

static int qcs_is_close_local(struct qcs *qcs)
{
	return qcs->st == QC_SS_HLOC || qcs->st == QC_SS_CLO;
}

static __maybe_unused int qcs_is_close_remote(struct qcs *qcs)
{
	return qcs->st == QC_SS_HREM || qcs->st == QC_SS_CLO;
}

struct buffer *qc_get_buf(struct qcs *qcs, struct buffer *bptr)
{
	struct buffer *buf = b_alloc(bptr);
	BUG_ON(!buf);
	return buf;
}

static struct ncbuf *qc_get_ncbuf(struct qcs *qcs, struct ncbuf *ncbuf)
{
	struct buffer buf = BUF_NULL;

	if (ncb_is_null(ncbuf)) {
		b_alloc(&buf);
		BUG_ON(b_is_null(&buf));

		*ncbuf = ncb_make(buf.area, buf.size, 0);
		ncb_init(ncbuf, 0);
	}

	return ncbuf;
}

/* Notify an eventual subscriber on <qcs> or else wakup up the stconn layer if
 * initialized.
 */
static void qcs_alert(struct qcs *qcs)
{
	if (qcs->subs) {
		qcs_notify_recv(qcs);
		qcs_notify_send(qcs);
	}
	else if (qcs_sc(qcs) && qcs->sd->sc->app_ops->wake) {
		qcs->sd->sc->app_ops->wake(qcs->sd->sc);
	}
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

/* Open a locally initiated stream for the connection <qcc>. Set <bidi> for a
 * bidirectional stream, else an unidirectional stream is opened. The next
 * available ID on the connection will be used according to the stream type.
 *
 * Returns the allocated stream instance or NULL on error.
 */
struct qcs *qcc_init_stream_local(struct qcc *qcc, int bidi)
{
	struct qcs *qcs;
	enum qcs_type type;
	uint64_t *next;

	TRACE_ENTER(QMUX_EV_QCS_NEW, qcc->conn);

	if (bidi) {
		next = &qcc->next_bidi_l;
		type = conn_is_back(qcc->conn) ? QCS_CLT_BIDI : QCS_SRV_BIDI;
	}
	else {
		next = &qcc->next_uni_l;
		type = conn_is_back(qcc->conn) ? QCS_CLT_UNI : QCS_SRV_UNI;
	}

	/* TODO ensure that we won't overflow remote peer flow control limit on
	 * streams. Else, we should emit a STREAMS_BLOCKED frame.
	 */

	qcs = qcs_new(qcc, *next, type);
	if (!qcs)
		return NULL;

	TRACE_DEVEL("opening local stream",  QMUX_EV_QCS_NEW, qcc->conn, qcs);
	*next += 4;

	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn);
	return qcs;
}

/* Open a remote initiated stream for the connection <qcc> with ID <id>. The
 * caller is responsible to ensure that a stream with the same ID was not
 * already opened. This function will also create all intermediaries streams
 * with ID smaller than <id> not already opened before.
 *
 * Returns the allocated stream instance or NULL on error.
 */
static struct qcs *qcc_init_stream_remote(struct qcc *qcc, uint64_t id)
{
	struct qcs *qcs = NULL;
	enum qcs_type type;
	uint64_t *largest;

	TRACE_ENTER(QMUX_EV_QCS_NEW, qcc->conn);

	BUG_ON_HOT(quic_stream_is_local(qcc, id));

	if (quic_stream_is_bidi(id)) {
		largest = &qcc->largest_bidi_r;
		type = conn_is_back(qcc->conn) ? QCS_SRV_BIDI : QCS_CLT_BIDI;
	}
	else {
		largest = &qcc->largest_uni_r;
		type = conn_is_back(qcc->conn) ? QCS_SRV_UNI : QCS_CLT_UNI;
	}

	/* TODO also checks max-streams for uni streams */
	if (quic_stream_is_bidi(id)) {
		if (id >= qcc->lfctl.ms_bidi * 4) {
			/* RFC 9000 4.6. Controlling Concurrency
			 *
			 * An endpoint that receives a frame with a
			 * stream ID exceeding the limit it has sent
			 * MUST treat this as a connection error of
			 * type STREAM_LIMIT_ERROR
			 */
			TRACE_DEVEL("leaving on flow control error", QMUX_EV_QCS_NEW, qcc->conn);
			qcc_emit_cc(qcc, QC_ERR_STREAM_LIMIT_ERROR);
			return NULL;
		}
	}

	/* Only stream ID not already opened can be used. */
	BUG_ON(id < *largest);

	while (id >= *largest) {
		const char *str = *largest < id ? "opening intermediary stream" :
		                                  "opening remote stream";

		qcs = qcs_new(qcc, *largest, type);
		if (!qcs) {
			/* TODO emit RESET_STREAM */
			TRACE_DEVEL("leaving on stream fallocation failure", QMUX_EV_QCS_NEW, qcc->conn);
			return NULL;
		}

		TRACE_DEVEL(str, QMUX_EV_QCS_NEW, qcc->conn, qcs);
		*largest += 4;
	}

	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn);
	return qcs;
}

/* Use this function for a stream <id> which is not in <qcc> stream tree. It
 * returns true if the associated stream is closed.
 */
static int qcc_stream_id_is_closed(struct qcc *qcc, uint64_t id)
{
	uint64_t *largest;

	/* This function must only be used for stream not present in the stream tree. */
	BUG_ON_HOT(eb64_lookup(&qcc->streams_by_id, id));

	if (quic_stream_is_local(qcc, id)) {
		largest = quic_stream_is_uni(id) ? &qcc->next_uni_l :
		                                   &qcc->next_bidi_l;
	}
	else {
		largest = quic_stream_is_uni(id) ? &qcc->largest_uni_r :
		                                   &qcc->largest_bidi_r;
	}

	return id < *largest;
}

/* Retrieve the stream instance from <id> ID. This can be used when receiving
 * STREAM, STREAM_DATA_BLOCKED, RESET_STREAM, MAX_STREAM_DATA or STOP_SENDING
 * frames. Set to false <receive_only> or <send_only> if these particular types
 * of streams are not allowed. If the stream instance is found, it is stored in
 * <out>.
 *
 * Returns 0 on success else non-zero. On error, a RESET_STREAM or a
 * CONNECTION_CLOSE is automatically emitted. Beware that <out> may be NULL
 * on success if the stream has already been closed.
 */
int qcc_get_qcs(struct qcc *qcc, uint64_t id, int receive_only, int send_only,
                struct qcs **out)
{
	struct eb64_node *node;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);
	*out = NULL;

	if (!receive_only && quic_stream_is_uni(id) && quic_stream_is_remote(qcc, id)) {
		TRACE_DEVEL("leaving on receive-only stream not allowed", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
		qcc_emit_cc(qcc, QC_ERR_STREAM_STATE_ERROR);
		return 1;
	}

	if (!send_only && quic_stream_is_uni(id) && quic_stream_is_local(qcc, id)) {
		TRACE_DEVEL("leaving on send-only stream not allowed", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
		qcc_emit_cc(qcc, QC_ERR_STREAM_STATE_ERROR);
		return 1;
	}

	/* Search the stream in the connection tree. */
	node = eb64_lookup(&qcc->streams_by_id, id);
	if (node) {
		*out = eb64_entry(node, struct qcs, by_id);
		TRACE_DEVEL("using stream from connection tree", QMUX_EV_QCC_RECV, qcc->conn, *out);
		return 0;
	}

	/* Check if stream is already closed. */
	if (qcc_stream_id_is_closed(qcc, id)) {
		TRACE_DEVEL("already released stream", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
		/* Consider this as a success even if <out> is left NULL. */
		return 0;
	}

	/* Create the stream. This is valid only for remote initiated one. A
	 * local stream must have already been explicitely created by the
	 * application protocol layer.
	 */
	if (quic_stream_is_local(qcc, id)) {
		/* RFC 9000 19.8. STREAM Frames
		 *
		 * An endpoint MUST terminate the connection with error
		 * STREAM_STATE_ERROR if it receives a STREAM frame for a locally
		 * initiated stream that has not yet been created, or for a send-only
		 * stream.
		 */
		TRACE_DEVEL("leaving on locally initiated stream not yet created", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
		qcc_emit_cc(qcc, QC_ERR_STREAM_STATE_ERROR);
		return 1;
	}
	else {
		/* Remote stream not found - try to open it. */
		*out = qcc_init_stream_remote(qcc, id);
		if (!*out) {
			TRACE_DEVEL("leaving on stream creation error", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
			return 1;
		}
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;
}

/* Simple function to duplicate a buffer */
static inline struct buffer qcs_b_dup(const struct ncbuf *b)
{
	return b_make(ncb_orig(b), b->size, b->head, ncb_data(b, 0));
}

/* Remove <bytes> from <qcs> Rx buffer. Flow-control for received offsets may
 * be allocated for the peer if needed.
 */
static void qcs_consume(struct qcs *qcs, uint64_t bytes)
{
	struct qcc *qcc = qcs->qcc;
	struct quic_frame *frm;
	struct ncbuf *buf = &qcs->rx.ncbuf;
	enum ncb_ret ret;

	ret = ncb_advance(buf, bytes);
	if (ret) {
		ABORT_NOW(); /* should not happens because removal only in data */
	}

	if (ncb_is_empty(buf))
		qc_free_ncbuf(qcs, buf);

	qcs->rx.offset += bytes;
	if (qcs->rx.msd - qcs->rx.offset < qcs->rx.msd_init / 2) {
		frm = pool_zalloc(pool_head_quic_frame);
		BUG_ON(!frm); /* TODO handle this properly */

		qcs->rx.msd = qcs->rx.offset + qcs->rx.msd_init;

		LIST_INIT(&frm->reflist);
		frm->type = QUIC_FT_MAX_STREAM_DATA;
		frm->max_stream_data.id = qcs->id;
		frm->max_stream_data.max_stream_data = qcs->rx.msd;

		LIST_APPEND(&qcc->lfctl.frms, &frm->list);
		tasklet_wakeup(qcc->wait_event.tasklet);
	}

	qcc->lfctl.offsets_consume += bytes;
	if (qcc->lfctl.md - qcc->lfctl.offsets_consume < qcc->lfctl.md_init / 2) {
		frm = pool_zalloc(pool_head_quic_frame);
		BUG_ON(!frm); /* TODO handle this properly */

		qcc->lfctl.md = qcc->lfctl.offsets_consume + qcc->lfctl.md_init;

		LIST_INIT(&frm->reflist);
		frm->type = QUIC_FT_MAX_DATA;
		frm->max_data.max_data = qcc->lfctl.md;

		LIST_APPEND(&qcs->qcc->lfctl.frms, &frm->list);
		tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}
}

/* Decode the content of STREAM frames already received on the stream instance
 * <qcs>.
 *
 * Returns 0 on success else non-zero.
 */
static int qcc_decode_qcs(struct qcc *qcc, struct qcs *qcs)
{
	struct buffer b;
	ssize_t ret;
	int fin = 0;

	TRACE_ENTER(QMUX_EV_QCS_RECV, qcc->conn, qcs);

	b = qcs_b_dup(&qcs->rx.ncbuf);

	/* Signal FIN to application if STREAM FIN received and there is no gap
	 * in the Rx buffer.
	 */
	if (qcs->flags & QC_SF_SIZE_KNOWN && !ncb_is_fragmented(&qcs->rx.ncbuf))
		fin = 1;

	ret = qcc->app_ops->decode_qcs(qcs, &b, fin);
	if (ret < 0) {
		TRACE_DEVEL("leaving on decoding error", QMUX_EV_QCS_RECV, qcc->conn, qcs);
		return 1;
	}

	if (ret) {
		qcs_consume(qcs, ret);
		qcs_notify_recv(qcs);
	}

	TRACE_LEAVE(QMUX_EV_QCS_RECV, qcc->conn, qcs);

	return 0;
}

/* Emit a CONNECTION_CLOSE_APP with error <err>. Reserved for application error
 * code. To close the connection right away, set <immediate> : this is useful
 * when dealing with a connection fatal error. Else a graceful shutdown will be
 * conducted : the error-code is only registered. The lower layer is
 * responsible to close the connection when deemed suitable. Note that in this
 * case the error code might be overwritten if an immediate close is requested
 * in the interval.
 */
void qcc_emit_cc_app(struct qcc *qcc, int err, int immediate)
{
	if (immediate) {
		quic_set_connection_close(qcc->conn->handle.qc, quic_err_app(err));
		qcc->flags |= QC_CF_CC_EMIT;
		tasklet_wakeup(qcc->wait_event.tasklet);
	}
	else {
		/* Only register the error code for graceful shutdown. */
		qcc->conn->handle.qc->err = quic_err_app(err);
	}
}

/* Prepare for the emission of RESET_STREAM on <qcs> with error code <err>. */
void qcc_reset_stream(struct qcs *qcs, int err)
{
	struct qcc *qcc = qcs->qcc;

	if ((qcs->flags & QC_SF_TO_RESET) || qcs_is_close_local(qcs))
		return;

	qcs->flags |= QC_SF_TO_RESET;
	qcs->err = err;
	tasklet_wakeup(qcc->wait_event.tasklet);
	TRACE_DEVEL("reset stream", QMUX_EV_QCS_END, qcc->conn, qcs);
}

/* Handle a new STREAM frame for stream with id <id>. Payload is pointed by
 * <data> with length <len> and represents the offset <offset>. <fin> is set if
 * the QUIC frame FIN bit is set.
 *
 * Returns 0 on success else non-zero. On error, the received frame should not
 * be acknowledged.
 */
int qcc_recv(struct qcc *qcc, uint64_t id, uint64_t len, uint64_t offset,
             char fin, char *data)
{
	struct qcs *qcs;
	enum ncb_ret ret;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	if (qcc->flags & QC_CF_CC_EMIT) {
		TRACE_DEVEL("leaving on error", QMUX_EV_QCC_RECV, qcc->conn);
		return 1;
	}

	/* RFC 9000 19.8. STREAM Frames
	 *
	 * An endpoint MUST terminate the connection with error
	 * STREAM_STATE_ERROR if it receives a STREAM frame for a locally
	 * initiated stream that has not yet been created, or for a send-only
	 * stream.
	 */
	if (qcc_get_qcs(qcc, id, 1, 0, &qcs)) {
		TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
		return 1;
	}

	if (!qcs) {
		/* Already closed stream. */
		TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
		return 0;
	}

	/* RFC 9000 4.5. Stream Final Size
	 *
	 * Once a final size for a stream is known, it cannot change.  If a
	 * RESET_STREAM or STREAM frame is received indicating a change in the
	 * final size for the stream, an endpoint SHOULD respond with an error
	 * of type FINAL_SIZE_ERROR; see Section 11 for details on error
	 * handling.
	 */
	if (qcs->flags & QC_SF_SIZE_KNOWN &&
	    (offset + len > qcs->rx.offset_max || (fin && offset + len < qcs->rx.offset_max))) {
		TRACE_DEVEL("leaving on final size error", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		qcc_emit_cc(qcc, QC_ERR_FINAL_SIZE_ERROR);
		return 1;
	}

	if (offset + len <= qcs->rx.offset) {
		TRACE_DEVEL("leaving on already received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		return 0;
	}

	qcs_idle_open(qcs);

	if (offset + len > qcs->rx.offset_max) {
		uint64_t diff = offset + len - qcs->rx.offset_max;
		qcs->rx.offset_max = offset + len;
		qcc->lfctl.offsets_recv += diff;

		if (offset + len > qcs->rx.msd ||
		    qcc->lfctl.offsets_recv > qcc->lfctl.md) {
			/* RFC 9000 4.1. Data Flow Control
			 *
			 * A receiver MUST close the connection with an error
			 * of type FLOW_CONTROL_ERROR if the sender violates
			 * the advertised connection or stream data limits
			 */
			TRACE_DEVEL("leaving on flow control error", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV,
				    qcc->conn, qcs);
			qcc_emit_cc(qcc, QC_ERR_FLOW_CONTROL_ERROR);
			return 1;
		}
	}

	if (!qc_get_ncbuf(qcs, &qcs->rx.ncbuf) || ncb_is_null(&qcs->rx.ncbuf)) {
		/* TODO should mark qcs as full */
		ABORT_NOW();
		return 1;
	}

	TRACE_DEVEL("newly received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
	if (offset < qcs->rx.offset) {
		size_t diff = qcs->rx.offset - offset;

		len -= diff;
		data += diff;
		offset = qcs->rx.offset;
	}

	ret = ncb_add(&qcs->rx.ncbuf, offset - qcs->rx.offset, data, len, NCB_ADD_COMPARE);
	if (ret != NCB_RET_OK) {
		if (ret == NCB_RET_DATA_REJ) {
			/* RFC 9000 2.2. Sending and Receiving Data
			 *
			 * An endpoint could receive data for a stream at the
			 * same stream offset multiple times. Data that has
			 * already been received can be discarded. The data at
			 * a given offset MUST NOT change if it is sent
			 * multiple times; an endpoint MAY treat receipt of
			 * different data at the same offset within a stream as
			 * a connection error of type PROTOCOL_VIOLATION.
			 */
			TRACE_DEVEL("leaving on data rejected", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV,
			            qcc->conn, qcs);
			qcc_emit_cc(qcc, QC_ERR_PROTOCOL_VIOLATION);
		}
		else if (ret == NCB_RET_GAP_SIZE) {
			TRACE_DEVEL("cannot bufferize frame due to gap size limit", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV,
			            qcc->conn, qcs);
		}
		return 1;
	}

	if (fin)
		qcs->flags |= QC_SF_SIZE_KNOWN;

	if (qcs->flags & QC_SF_SIZE_KNOWN && !ncb_is_fragmented(&qcs->rx.ncbuf))
		qcs_close_remote(qcs);

	if (ncb_data(&qcs->rx.ncbuf, 0) && !(qcs->flags & QC_SF_DEM_FULL)) {
		qcc_decode_qcs(qcc, qcs);
		qcc_refresh_timeout(qcc);
	}

	if (qcs->flags & QC_SF_READ_ABORTED) {
		/* TODO should send a STOP_SENDING */
		qcs_free(qcs);
	}

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
	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	if (qcc->rfctl.md < max) {
		qcc->rfctl.md = max;
		TRACE_DEVEL("increase remote max-data", QMUX_EV_QCC_RECV, qcc->conn);

		if (qcc->flags & QC_CF_BLK_MFCTL) {
			qcc->flags &= ~QC_CF_BLK_MFCTL;
			tasklet_wakeup(qcc->wait_event.tasklet);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;
}

/* Handle a new MAX_STREAM_DATA frame. <max> must contains the maximum data
 * field of the frame and <id> is the identifier of the QUIC stream.
 *
 * Returns 0 on success else non-zero. On error, the received frame should not
 * be acknowledged.
 */
int qcc_recv_max_stream_data(struct qcc *qcc, uint64_t id, uint64_t max)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	/* RFC 9000 19.10. MAX_STREAM_DATA Frames
	 *
	 * Receiving a MAX_STREAM_DATA frame for a locally
	 * initiated stream that has not yet been created MUST be treated as a
	 * connection error of type STREAM_STATE_ERROR.  An endpoint that
	 * receives a MAX_STREAM_DATA frame for a receive-only stream MUST
	 * terminate the connection with error STREAM_STATE_ERROR.
	 */
	if (qcc_get_qcs(qcc, id, 0, 1, &qcs)) {
		TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
		return 1;
	}

	if (qcs) {
		if (max > qcs->tx.msd) {
			qcs->tx.msd = max;
			TRACE_DEVEL("increase remote max-stream-data", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);

			if (qcs->flags & QC_SF_BLK_SFCTL) {
				qcs->flags &= ~QC_SF_BLK_SFCTL;
				tasklet_wakeup(qcc->wait_event.tasklet);
			}
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;
}

/* Handle a new STOP_SENDING frame for stream ID <id>. The error code should be
 * specified in <err>.
 *
 * Returns 0 on success else non-zero. On error, the received frame should not
 * be acknowledged.
 */
int qcc_recv_stop_sending(struct qcc *qcc, uint64_t id, uint64_t err)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	/* RFC 9000 19.5. STOP_SENDING Frames
	 *
	 * Receiving a STOP_SENDING frame for a
	 * locally initiated stream that has not yet been created MUST be
	 * treated as a connection error of type STREAM_STATE_ERROR.  An
	 * endpoint that receives a STOP_SENDING frame for a receive-only stream
	 * MUST terminate the connection with error STREAM_STATE_ERROR.
	 */
	if (qcc_get_qcs(qcc, id, 0, 1, &qcs)) {
		TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
		return 1;
	}

	if (!qcs)
		goto out;

	/* RFC 9000 3.5. Solicited State Transitions
	 *
	 * An endpoint that receives a STOP_SENDING frame
	 * MUST send a RESET_STREAM frame if the stream is in the "Ready" or
	 * "Send" state.  If the stream is in the "Data Sent" state, the
	 * endpoint MAY defer sending the RESET_STREAM frame until the packets
	 * containing outstanding data are acknowledged or declared lost.  If
	 * any outstanding data is declared lost, the endpoint SHOULD send a
	 * RESET_STREAM frame instead of retransmitting the data.
	 *
	 * An endpoint SHOULD copy the error code from the STOP_SENDING frame to
	 * the RESET_STREAM frame it sends, but it can use any application error
	 * code.
	 */
	TRACE_DEVEL("receiving STOP_SENDING on stream", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
	qcc_reset_stream(qcs, err);

 out:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;
}

/* Signal the closing of remote stream with id <id>. Flow-control for new
 * streams may be allocated for the peer if needed.
 */
static int qcc_release_remote_stream(struct qcc *qcc, uint64_t id)
{
	struct quic_frame *frm;

	if (quic_stream_is_bidi(id)) {
		++qcc->lfctl.cl_bidi_r;
		if (qcc->lfctl.cl_bidi_r > qcc->lfctl.ms_bidi_init / 2) {
			frm = pool_zalloc(pool_head_quic_frame);
			BUG_ON(!frm); /* TODO handle this properly */

			LIST_INIT(&frm->reflist);
			frm->type = QUIC_FT_MAX_STREAMS_BIDI;
			frm->max_streams_bidi.max_streams = qcc->lfctl.ms_bidi +
			                                    qcc->lfctl.cl_bidi_r;
			LIST_APPEND(&qcc->lfctl.frms, &frm->list);
			tasklet_wakeup(qcc->wait_event.tasklet);

			qcc->lfctl.ms_bidi += qcc->lfctl.cl_bidi_r;
			qcc->lfctl.cl_bidi_r = 0;
		}
	}
	else {
		/* TODO */
	}

	return 0;
}

/* detaches the QUIC stream from its QCC and releases it to the QCS pool. */
static void qcs_destroy(struct qcs *qcs)
{
	struct connection *conn = qcs->qcc->conn;
	const uint64_t id = qcs->id;

	TRACE_ENTER(QMUX_EV_QCS_END, conn, qcs);

	if (quic_stream_is_remote(qcs->qcc, id))
		qcc_release_remote_stream(qcs->qcc, id);

	qcs_free(qcs);

	TRACE_LEAVE(QMUX_EV_QCS_END, conn);
}

/* Transfer as much as possible data on <qcs> from <in> to <out>. This is done
 * in respect with available flow-control at stream and connection level.
 *
 * Returns the total bytes of transferred data.
 */
static int qcs_xfer_data(struct qcs *qcs, struct buffer *out, struct buffer *in)
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
	BUG_ON_HOT(qcc->tx.offsets < qcc->tx.sent_offsets);

	left = qcs->tx.offset - qcs->tx.sent_offset;
	to_xfer = QUIC_MIN(b_data(in), b_room(out));

	BUG_ON_HOT(qcs->tx.offset > qcs->tx.msd);
	/* do not exceed flow control limit */
	if (qcs->tx.offset + to_xfer > qcs->tx.msd)
		to_xfer = qcs->tx.msd - qcs->tx.offset;

	BUG_ON_HOT(qcc->tx.offsets > qcc->rfctl.md);
	/* do not overcome flow control limit on connection */
	if (qcc->tx.offsets + to_xfer > qcc->rfctl.md)
		to_xfer = qcc->rfctl.md - qcc->tx.offsets;

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

	if (!total && !fin) {
		/* No need to send anything if total is NULL and no FIN to signal. */
		TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
		return 0;
	}
	BUG_ON((!total && qcs->tx.sent_offset > qcs->tx.offset) ||
	       (total && qcs->tx.sent_offset >= qcs->tx.offset));
	BUG_ON(qcs->tx.sent_offset + total > qcs->tx.offset);
	BUG_ON(qcc->tx.sent_offsets + total > qcc->rfctl.md);

	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm)
		goto err;

	LIST_INIT(&frm->reflist);
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

/* Check after transfering data from qcs.tx.buf if FIN must be set on the next
 * STREAM frame for <qcs>.
 *
 * Returns true if FIN must be set else false.
 */
static int qcs_stream_fin(struct qcs *qcs)
{
	return qcs->flags & QC_SF_FIN_STREAM && !b_data(&qcs->tx.buf);
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
	BUG_ON(offset + data > qcs->tx.offset);

	/* check if the STREAM frame has already been notified. It can happen
	 * for retransmission.
	 */
	if (offset + data < qcs->tx.sent_offset)
		return;

	qcs_idle_open(qcs);

	diff = offset + data - qcs->tx.sent_offset;
	if (diff) {
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

		if (qcs->tx.offset == qcs->tx.sent_offset &&
		    b_full(&qcs->stream->buf->buf)) {
			qc_stream_buf_release(qcs->stream);
			/* prepare qcs for immediate send retry if data to send */
			if (b_data(&qcs->tx.buf))
				LIST_APPEND(&qcc->send_retry_list, &qcs->el);
		}
	}

	if (qcs->tx.offset == qcs->tx.sent_offset && qcs_stream_fin(qcs)) {
		/* Close stream locally. */
		qcs_close_local(qcs);
		/* Reset flag to not emit multiple FIN STREAM frames. */
		qcs->flags &= ~QC_SF_FIN_STREAM;
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
		qc_send_app_pkts(qcc->conn->handle.qc, 0, frms);

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

/* Emit a RESET_STREAM on <qcs>.
 *
 * Returns 0 if the frame has been successfully sent else non-zero.
 */
static int qcs_send_reset(struct qcs *qcs)
{
	struct list frms = LIST_HEAD_INIT(frms);
	struct quic_frame *frm;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);

	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm)
		return 1;

	LIST_INIT(&frm->reflist);
	frm->type = QUIC_FT_RESET_STREAM;
	frm->reset_stream.id = qcs->id;
	frm->reset_stream.app_error_code = qcs->err;
	frm->reset_stream.final_size = qcs->tx.sent_offset;

	LIST_APPEND(&frms, &frm->list);
	if (qc_send_frames(qcs->qcc, &frms)) {
		pool_free(pool_head_quic_frame, frm);
		TRACE_DEVEL("cannot send RESET_STREAM", QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
	}

	if (qcs_sc(qcs)) {
		se_fl_set_error(qcs->sd);
		qcs_alert(qcs);
	}

	qcs_close_local(qcs);
	qcs->flags &= ~QC_SF_TO_RESET;

	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
	return 0;
}

/* Used internally by qc_send function. Proceed to send for <qcs>. This will
 * transfer data from qcs buffer to its quic_stream counterpart. A STREAM frame
 * is then generated and inserted in <frms> list.
 *
 * Returns the total bytes transferred between qcs and quic_stream buffers. Can
 * be null if out buffer cannot be allocated.
 */
static int _qc_send_qcs(struct qcs *qcs, struct list *frms)
{
	struct qcc *qcc = qcs->qcc;
	struct buffer *buf = &qcs->tx.buf;
	struct buffer *out = qc_stream_buf_get(qcs->stream);
	int xfer = 0;
	char fin = 0;

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
		xfer = qcs_xfer_data(qcs, out, buf);
		if (xfer > 0) {
			qcs_notify_send(qcs);
			qcs->flags &= ~QC_SF_BLK_MROOM;
		}

		qcs->tx.offset += xfer;
		BUG_ON_HOT(qcs->tx.offset > qcs->tx.msd);
		qcc->tx.offsets += xfer;
		BUG_ON_HOT(qcc->tx.offsets > qcc->rfctl.md);
	}

	/* out buffer cannot be emptied if qcs offsets differ. */
	BUG_ON(!b_data(out) && qcs->tx.sent_offset != qcs->tx.offset);

	/* FIN is set if all incoming data were transfered. */
	fin = qcs_stream_fin(qcs);

	/* Build a new STREAM frame with <out> buffer. */
	if (qcs->tx.sent_offset != qcs->tx.offset || fin) {
		int ret;
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

	if (qcc->conn->flags & CO_FL_SOCK_WR_SH || qcc->flags & QC_CF_CC_EMIT) {
		qcc->conn->flags |= CO_FL_ERROR;
		TRACE_DEVEL("leaving on error", QMUX_EV_QCC_SEND, qcc->conn);
		return 0;
	}

	if (!LIST_ISEMPTY(&qcc->lfctl.frms)) {
		if (qc_send_frames(qcc, &qcc->lfctl.frms)) {
			TRACE_DEVEL("flow-control frames rejected by transport, aborting send", QMUX_EV_QCC_SEND, qcc->conn);
			goto out;
		}
	}

	if (qcc->flags & QC_CF_BLK_MFCTL)
		return 0;

	/* loop through all streams, construct STREAM frames if data available.
	 * TODO optimize the loop to favor streams which are not too heavy.
	 */
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		int ret;
		uint64_t id;

		qcs = eb64_entry(node, struct qcs, by_id);
		id = qcs->id;

		if (quic_stream_is_uni(id) && quic_stream_is_remote(qcc, id)) {
			node = eb64_next(node);
			continue;
		}

		if (qcs->flags & QC_SF_TO_RESET) {
			qcs_send_reset(qcs);
			node = eb64_next(node);
			continue;
		}

		if (qcs_is_close_local(qcs)) {
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

		ret = _qc_send_qcs(qcs, &frms);
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

		ret = _qc_send_qcs(qcs, &frms);
		tmp_total += ret;
		LIST_DELETE(&qcs->el);
	}

	total += tmp_total;
	if (!qc_send_frames(qcc, &frms) && !LIST_ISEMPTY(&qcc->send_retry_list))
		goto retry;

 out:
	/* Deallocate frames that the transport layer has rejected. */
	if (!LIST_ISEMPTY(&frms)) {
		struct quic_frame *frm, *frm2;
		list_for_each_entry_safe(frm, frm2, &frms, list) {
			LIST_DELETE(&frm->list);
			pool_free(pool_head_quic_frame, frm);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND);

	return total;
}

/* Proceed on receiving. Loop through all streams from <qcc> and use decode_qcs
 * operation.
 *
 * Returns 0 on success else non-zero.
 */
static int qc_recv(struct qcc *qcc)
{
	struct eb64_node *node;
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_RECV);

	if (qcc->flags & QC_CF_CC_EMIT) {
		TRACE_DEVEL("leaving on error", QMUX_EV_QCC_RECV, qcc->conn);
		return 0;
	}

	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		uint64_t id;

		qcs = eb64_entry(node, struct qcs, by_id);
		id = qcs->id;

		if (!ncb_data(&qcs->rx.ncbuf, 0) || (qcs->flags & QC_SF_DEM_FULL)) {
			node = eb64_next(node);
			continue;
		}

		if (quic_stream_is_uni(id) && quic_stream_is_local(qcc, id)) {
			node = eb64_next(node);
			continue;
		}

		qcc_decode_qcs(qcc, qcs);
		node = eb64_next(node);

		if (qcs->flags & QC_SF_READ_ABORTED) {
			/* TODO should send a STOP_SENDING */
			qcs_free(qcs);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV);
	return 0;
}


/* Release all streams which have their transfer operation achieved.
 *
 * Returns true if at least one stream is released.
 */
static int qc_purge_streams(struct qcc *qcc)
{
	struct eb64_node *node;
	int release = 0;

	TRACE_ENTER(QMUX_EV_QCC_WAKE);

	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = eb64_entry(node, struct qcs, by_id);
		node = eb64_next(node);

		/* Release not attached closed streams. */
		if (qcs->st == QC_SS_CLO && !qcs_sc(qcs)) {
			TRACE_DEVEL("purging closed stream", QMUX_EV_QCC_WAKE, qcs->qcc->conn, qcs);
			qcs_destroy(qcs);
			release = 1;
			continue;
		}

		/* Release detached streams with empty buffer. */
		if (qcs->flags & QC_SF_DETACH) {
			if (qcs_is_close_local(qcs)) {
				TRACE_DEVEL("purging detached stream", QMUX_EV_QCC_WAKE, qcs->qcc->conn, qcs);
				qcs_destroy(qcs);
				release = 1;
				continue;
			}

			qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
			                           SUB_RETRY_SEND, &qcc->wait_event);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_WAKE);
	return release;
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void qc_release(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;
	struct eb64_node *node;

	TRACE_ENTER(QMUX_EV_QCC_END);

	if (qcc->app_ops && qcc->app_ops->release) {
		/* Application protocol with dedicated connection closing
		 * procedure.
		 */
		qcc->app_ops->release(qcc->ctx);

		/* useful if application protocol should emit some closing
		 * frames. For example HTTP/3 GOAWAY frame.
		 */
		qc_send(qcc);
	}
	else {
		qcc_emit_cc_app(qcc, QC_ERR_NO_ERROR, 0);
	}

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

	while (!LIST_ISEMPTY(&qcc->lfctl.frms)) {
		struct quic_frame *frm = LIST_ELEM(qcc->lfctl.frms.n, struct quic_frame *, list);
		LIST_DELETE(&frm->list);
		pool_free(pool_head_quic_frame, frm);
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

static struct task *qc_io_cb(struct task *t, void *ctx, unsigned int status)
{
	struct qcc *qcc = ctx;

	TRACE_ENTER(QMUX_EV_QCC_WAKE);

	qc_send(qcc);

	if (qc_purge_streams(qcc)) {
		if (qcc_is_dead(qcc)) {
			qc_release(qcc);
			goto end;
		}
	}

	qc_recv(qcc);

	/* TODO check if qcc proxy is disabled. If yes, use graceful shutdown
	 * to close the connection.
	 */

	qcc_refresh_timeout(qcc);

 end:
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

	/* TODO depending on the timeout condition, different shutdown mode
	 * should be used. For http keep-alive or disabled proxy, a graceful
	 * shutdown should occurs. For all other cases, an immediate close
	 * seems legitimate.
	 */
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
	qcc->nb_hreq = qcc->nb_sc = 0;
	qcc->flags = 0;

	qcc->app_ops = NULL;

	qcc->streams_by_id = EB_ROOT_UNIQUE;

	/* Server parameters, params used for RX flow control. */
	lparams = &conn->handle.qc->rx.params;

	qcc->rx.max_data = lparams->initial_max_data;
	qcc->tx.sent_offsets = qcc->tx.offsets = 0;

	/* Client initiated streams must respect the server flow control. */
	qcc->strms[QCS_CLT_BIDI].max_streams = lparams->initial_max_streams_bidi;
	qcc->strms[QCS_CLT_BIDI].nb_streams = 0;
	qcc->strms[QCS_CLT_BIDI].rx.max_data = 0;
	qcc->strms[QCS_CLT_BIDI].tx.max_data = lparams->initial_max_stream_data_bidi_remote;

	qcc->strms[QCS_CLT_UNI].max_streams = lparams->initial_max_streams_uni;
	qcc->strms[QCS_CLT_UNI].nb_streams = 0;
	qcc->strms[QCS_CLT_UNI].rx.max_data = 0;
	qcc->strms[QCS_CLT_UNI].tx.max_data = lparams->initial_max_stream_data_uni;

	/* Server initiated streams must respect the server flow control. */
	qcc->strms[QCS_SRV_BIDI].max_streams = 0;
	qcc->strms[QCS_SRV_BIDI].nb_streams = 0;
	qcc->strms[QCS_SRV_BIDI].rx.max_data = lparams->initial_max_stream_data_bidi_local;
	qcc->strms[QCS_SRV_BIDI].tx.max_data = 0;

	qcc->strms[QCS_SRV_UNI].max_streams = 0;
	qcc->strms[QCS_SRV_UNI].nb_streams = 0;
	qcc->strms[QCS_SRV_UNI].rx.max_data = lparams->initial_max_stream_data_uni;
	qcc->strms[QCS_SRV_UNI].tx.max_data = 0;

	LIST_INIT(&qcc->lfctl.frms);
	qcc->lfctl.ms_bidi = qcc->lfctl.ms_bidi_init = lparams->initial_max_streams_bidi;
	qcc->lfctl.msd_bidi_l = lparams->initial_max_stream_data_bidi_local;
	qcc->lfctl.msd_bidi_r = lparams->initial_max_stream_data_bidi_remote;
	qcc->lfctl.cl_bidi_r = 0;

	qcc->lfctl.md = qcc->lfctl.md_init = lparams->initial_max_data;
	qcc->lfctl.offsets_recv = qcc->lfctl.offsets_consume = 0;

	rparams = &conn->handle.qc->tx.params;
	qcc->rfctl.md = rparams->initial_max_data;
	qcc->rfctl.msd_bidi_l = rparams->initial_max_stream_data_bidi_local;
	qcc->rfctl.msd_bidi_r = rparams->initial_max_stream_data_bidi_remote;

	if (conn_is_back(conn)) {
		qcc->next_bidi_l    = 0x00;
		qcc->largest_bidi_r = 0x01;
		qcc->next_uni_l     = 0x02;
		qcc->largest_uni_r  = 0x03;
	}
	else {
		qcc->largest_bidi_r = 0x00;
		qcc->next_bidi_l    = 0x01;
		qcc->largest_uni_r  = 0x02;
		qcc->next_uni_l     = 0x03;
	}

	qcc->wait_event.tasklet = tasklet_new();
	if (!qcc->wait_event.tasklet)
		goto fail_no_tasklet;

	LIST_INIT(&qcc->send_retry_list);

	qcc->subs = NULL;
	qcc->wait_event.tasklet->process = qc_io_cb;
	qcc->wait_event.tasklet->context = qcc;
	qcc->wait_event.events = 0;

	qcc->proxy = prx;
	/* haproxy timeouts */
	qcc->task = NULL;
	qcc->timeout = conn_is_back(qcc->conn) ? prx->timeout.server :
	                                         prx->timeout.client;
	if (tick_isset(qcc->timeout)) {
		qcc->task = task_new_here();
		if (!qcc->task)
			goto fail_no_timeout_task;
		qcc->task->process = qc_timeout_task;
		qcc->task->context = qcc;
		qcc->task->expire = tick_add(now_ms, qcc->timeout);
	}
	qcc_reset_idle_start(qcc);

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

static void qc_detach(struct sedesc *sd)
{
	struct qcs *qcs = sd->se;
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_STRM_END, qcc->conn, qcs);

	/* TODO this BUG_ON_HOT() is not correct as the stconn layer may detach
	 * from the stream even if it is not closed remotely at the QUIC layer.
	 * This happens for example when a stream must be closed due to a
	 * rejected request. To better handle these cases, it will be required
	 * to implement shutr/shutw MUX operations. Once this is done, this
	 * BUG_ON_HOT() statement can be adjusted.
	 */
	//BUG_ON_HOT(!qcs_is_close_remote(qcs));

	qcc_rm_sc(qcc);

	if (!qcs_is_close_local(qcs) && !(qcc->conn->flags & CO_FL_ERROR)) {
		TRACE_DEVEL("leaving with remaining data, detaching qcs", QMUX_EV_STRM_END, qcc->conn, qcs);
		qcs->flags |= QC_SF_DETACH;
		qcc_refresh_timeout(qcc);
		return;
	}

	qcs_destroy(qcs);

	if (qcc_is_dead(qcc)) {
		TRACE_DEVEL("leaving and killing dead connection", QMUX_EV_STRM_END, qcc->conn);
		qc_release(qcc);
	}
	else if (qcc->task) {
		TRACE_DEVEL("leaving, refreshing connection's timeout", QMUX_EV_STRM_END, qcc->conn);
		qcc_refresh_timeout(qcc);
	}
	else {
		TRACE_DEVEL("leaving", QMUX_EV_STRM_END, qcc->conn);
	}
}

/* Called from the upper layer, to receive data */
static size_t qc_rcv_buf(struct stconn *sc, struct buffer *buf,
                         size_t count, int flags)
{
	struct qcs *qcs = __sc_mux_strm(sc);
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
		/* EOM will be copied to cs_htx via b_xfer(). */
		if (qcs_htx->flags & HTX_FL_EOM)
			fin = 1;

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
		se_fl_set(qcs->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
	}
	else {
		se_fl_clr(qcs->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		if (se_fl_test(qcs->sd, SE_FL_ERR_PENDING))
			se_fl_set(qcs->sd, SE_FL_ERROR);

		/* Set end-of-input if FIN received and all data extracted. */
		if (fin)
			se_fl_set(qcs->sd, SE_FL_EOI);

		if (b_size(&qcs->rx.app_buf)) {
			b_free(&qcs->rx.app_buf);
			offer_buffers(NULL, 1);
		}
	}

	if (ret) {
		qcs->flags &= ~QC_SF_DEM_FULL;
		tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	TRACE_LEAVE(QMUX_EV_STRM_RECV, qcs->qcc->conn, qcs);

	return ret;
}

static size_t qc_snd_buf(struct stconn *sc, struct buffer *buf,
                         size_t count, int flags)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	size_t ret;

	TRACE_ENTER(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	if (qcs_is_close_local(qcs) || (qcs->flags & QC_SF_TO_RESET)) {
		ret = count;
		goto end;
	}

	ret = qcs->qcc->app_ops->snd_buf(sc, buf, count, flags);

 end:
	TRACE_LEAVE(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	return ret;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int qc_subscribe(struct stconn *sc, int event_type,
                        struct wait_event *es)
{
	return qcs_subscribe(__sc_mux_strm(sc), event_type, es);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int qc_unsubscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct qcs *qcs = __sc_mux_strm(sc);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		qcs->subs = NULL;

	return 0;
}

/* Loop through all qcs from <qcc>. If CO_FL_ERROR is set on the connection,
 * report SE_FL_ERR_PENDING|SE_FL_ERROR on the attached stream connectors and
 * wake them.
 */
static int qc_wake_some_streams(struct qcc *qcc)
{
	struct qcs *qcs;
	struct eb64_node *node;

	for (node = eb64_first(&qcc->streams_by_id); node;
	     node = eb64_next(node)) {
		qcs = eb64_entry(node, struct qcs, by_id);

		if (!qcs_sc(qcs))
			continue;

		if (qcc->conn->flags & CO_FL_ERROR) {
			se_fl_set(qcs->sd, SE_FL_ERR_PENDING);
			if (se_fl_test(qcs->sd, SE_FL_EOS))
				se_fl_set(qcs->sd, SE_FL_ERROR);

			qcs_alert(qcs);
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
	 *
	 * TODO this is revelant for frontend connections only.
	 *
	 * TODO Client should be notified with a H3 GOAWAY and then a
	 * CONNECTION_CLOSE. However, quic-conn uses the listener socket for
	 * sending which at this stage is already closed.
	 */
	if (unlikely(prx->flags & (PR_FL_DISABLED|PR_FL_STOPPED)))
		qcc->conn->flags |= (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH);

	if (conn->handle.qc->flags & QUIC_FL_CONN_NOTIFY_CLOSE)
		qcc->conn->flags |= (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH);

	qc_send(qcc);

	qc_wake_some_streams(qcc);

	if (qcc_is_dead(qcc))
		goto release;

	qcc_refresh_timeout(qcc);

	TRACE_LEAVE(QMUX_EV_QCC_WAKE, conn);

	return 0;

 release:
	qc_release(qcc);
	TRACE_DEVEL("leaving after releasing the connection", QMUX_EV_QCC_WAKE);
	return 1;
}


static char *qcs_st_to_str(enum qcs_state st)
{
	switch (st) {
	case QC_SS_IDLE: return "IDL";
	case QC_SS_OPEN: return "OPN";
	case QC_SS_HLOC: return "HCL";
	case QC_SS_HREM: return "HCR";
	case QC_SS_CLO:  return "CLO";
	default:         return "???";
	}
}

static void qmux_trace_frm(const struct quic_frame *frm)
{
	switch (frm->type) {
	case QUIC_FT_MAX_STREAMS_BIDI:
		chunk_appendf(&trace_buf, " max_streams=%llu",
		              (ull)frm->max_streams_bidi.max_streams);
		break;

	case QUIC_FT_MAX_STREAMS_UNI:
		chunk_appendf(&trace_buf, " max_streams=%llu",
		              (ull)frm->max_streams_uni.max_streams);
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
			chunk_appendf(&trace_buf, " qcs=%p .id=%llu .st=%s",
			              qcs, (ull)qcs->id,
			              qcs_st_to_str(qcs->st));

		if (mask & QMUX_EV_QCC_NQCS) {
			const uint64_t *id = a3;
			chunk_appendf(&trace_buf, " id=%llu", (ull)*id);
		}

		if (mask & QMUX_EV_SEND_FRM)
			qmux_trace_frm(a3);

		if (mask & QMUX_EV_QCS_XFER_DATA) {
			const struct qcs_xfer_data_trace_arg *arg = a3;
			chunk_appendf(&trace_buf, " prep=%llu xfer=%d",
			              (ull)arg->prep, arg->xfer);
		}

		if (mask & QMUX_EV_QCS_BUILD_STRM) {
			const struct qcs_build_stream_trace_arg *arg = a3;
			chunk_appendf(&trace_buf, " len=%llu fin=%d offset=%llu",
			              (ull)arg->len, arg->fin, (ull)arg->offset);
		}
	}
}


static const struct mux_ops qc_ops = {
	.init = qc_init,
	.destroy = qc_destroy,
	.detach = qc_detach,
	.rcv_buf = qc_rcv_buf,
	.snd_buf = qc_snd_buf,
	.subscribe = qc_subscribe,
	.unsubscribe = qc_unsubscribe,
	.wake = qc_wake,
	.flags = MX_FL_HTX|MX_FL_NO_UPG|MX_FL_FRAMED,
	.name = "QUIC",
};

static struct mux_proto_list mux_proto_quic =
  { .token = IST("quic"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_FE, .mux = &qc_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_quic);
