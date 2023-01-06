#include <haproxy/mux_quic.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/list.h>
#include <haproxy/ncbuf.h>
#include <haproxy/pool.h>
#include <haproxy/qmux_http.h>
#include <haproxy/qmux_trace.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/stconn.h>
#include <haproxy/trace.h>

DECLARE_POOL(pool_head_qcc, "qcc", sizeof(struct qcc));
DECLARE_POOL(pool_head_qcs, "qcs", sizeof(struct qcs));

/* Emit a CONNECTION_CLOSE with error <err>. This will interrupt all future
 * send/receive operations.
 */
static void qcc_emit_cc(struct qcc *qcc, int err)
{
	TRACE_ENTER(QMUX_EV_QCC_END, qcc->conn);

	TRACE_STATE("set CONNECTION_CLOSE on quic-conn", QMUX_EV_QCC_WAKE, qcc->conn);
	quic_set_connection_close(qcc->conn->handle.qc, quic_err_transport(err));
	qcc->flags |= QC_CF_CC_EMIT;
	tasklet_wakeup(qcc->wait_event.tasklet);

	TRACE_LEAVE(QMUX_EV_QCC_END, qcc->conn);
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

/* Free <qcs> instance. This function is reserved for internal usage : it must
 * only be called on qcs alloc error or on connection shutdown. Else
 * qcs_destroy must be prefered to handle QUIC flow-control increase.
 */
static void qcs_free(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_QCS_END, qcc->conn, qcs);

	/* Safe to use even if already removed from the list. */
	LIST_DEL_INIT(&qcs->el_opening);
	LIST_DEL_INIT(&qcs->el_send);

	/* Release stream endpoint descriptor. */
	BUG_ON(qcs->sd && !se_fl_test(qcs->sd, SE_FL_ORPHAN));
	sedesc_free(qcs->sd);

	/* Release app-layer context. */
	if (qcs->ctx && qcc->app_ops->detach)
		qcc->app_ops->detach(qcs);

	/* Release qc_stream_desc buffer from quic-conn layer. */
	qc_stream_desc_release(qcs->stream);

	/* Free Rx/Tx buffers. */
	qc_free_ncbuf(qcs, &qcs->rx.ncbuf);
	b_free(&qcs->tx.buf);

	BUG_ON(!qcc->strms[qcs_id_type(qcs->id)].nb_streams);
	--qcc->strms[qcs_id_type(qcs->id)].nb_streams;

	/* Remove qcs from qcc tree. */
	eb64_delete(&qcs->by_id);

	pool_free(pool_head_qcs, qcs);

	TRACE_LEAVE(QMUX_EV_QCS_END, qcc->conn);
}

/* Allocate a new QUIC streams with id <id> and type <type>. */
static struct qcs *qcs_new(struct qcc *qcc, uint64_t id, enum qcs_type type)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCS_NEW, qcc->conn);

	qcs = pool_alloc(pool_head_qcs);
	if (!qcs) {
		TRACE_ERROR("alloc failure", QMUX_EV_QCS_NEW, qcc->conn);
		return NULL;
	}

	qcs->stream = NULL;
	qcs->qcc = qcc;
	qcs->sd = NULL;
	qcs->flags = QC_SF_NONE;
	qcs->st = QC_SS_IDLE;
	qcs->ctx = NULL;

	/* App callback attach may register the stream for http-request wait.
	 * These fields must be initialed before.
	 */
	LIST_INIT(&qcs->el_opening);
	LIST_INIT(&qcs->el_send);
	qcs->start = TICK_ETERNITY;

	/* store transport layer stream descriptor in qcc tree */
	qcs->id = qcs->by_id.key = id;
	eb64_insert(&qcc->streams_by_id, &qcs->by_id);

	qcc->strms[type].nb_streams++;

	/* Allocate transport layer stream descriptor. Only needed for TX. */
	if (!quic_stream_is_uni(id) || !quic_stream_is_remote(qcc, id)) {
		struct quic_conn *qc = qcc->conn->handle.qc;
		qcs->stream = qc_stream_desc_new(id, type, qcs, qc);
		if (!qcs->stream) {
			TRACE_ERROR("qc_stream_desc alloc failure", QMUX_EV_QCS_NEW, qcc->conn, qcs);
			goto err;
		}
	}

	if (qcc->app_ops->attach) {
		if (qcc->app_ops->attach(qcs, qcc->ctx)) {
			TRACE_ERROR("app proto failure", QMUX_EV_QCS_NEW, qcc->conn, qcs);
			goto err;
		}
	}

	/* If stream is local, use peer remote-limit, or else the opposite. */
	if (quic_stream_is_bidi(id)) {
		qcs->tx.msd = quic_stream_is_local(qcc, id) ? qcc->rfctl.msd_bidi_r :
		                                              qcc->rfctl.msd_bidi_l;
	}
	else if (quic_stream_is_local(qcc, id)) {
		qcs->tx.msd = qcc->rfctl.msd_uni_l;
	}

	qcs->rx.ncbuf = NCBUF_NULL;
	qcs->rx.app_buf = BUF_NULL;
	qcs->rx.offset = qcs->rx.offset_max = 0;

	if (quic_stream_is_bidi(id)) {
		qcs->rx.msd = quic_stream_is_local(qcc, id) ? qcc->lfctl.msd_bidi_l :
		                                              qcc->lfctl.msd_bidi_r;
	}
	else if (quic_stream_is_remote(qcc, id)) {
		qcs->rx.msd = qcc->lfctl.msd_uni_r;
	}
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
	qcs_free(qcs);
	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn);
	return NULL;
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

	if (!qcc->task) {
		TRACE_DEVEL("already expired", QMUX_EV_QCC_WAKE, qcc->conn);
		goto leave;
	}

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

	/* TODO implement client/server-fin timeout for graceful shutdown */

	/* Frontend timeout management
	 * - detached streams with data left to send -> default timeout
	 * - stream waiting on incomplete request or no stream yet activated -> timeout http-request
	 * - idle after stream processing -> timeout http-keep-alive
	 */
	if (!conn_is_back(qcc->conn)) {
		if (qcc->nb_hreq) {
			TRACE_DEVEL("one or more requests still in progress", QMUX_EV_QCC_WAKE, qcc->conn);
			qcc->task->expire = tick_add_ifset(now_ms, qcc->timeout);
			task_queue(qcc->task);
			goto leave;
		}

		if (!LIST_ISEMPTY(&qcc->opening_list) || unlikely(!qcc->largest_bidi_r)) {
			int timeout = px->timeout.httpreq;
			struct qcs *qcs = NULL;
			int base_time;

			/* Use start time of first stream waiting on HTTP or
			 * qcc idle if no stream not yet used.
			 */
			if (likely(!LIST_ISEMPTY(&qcc->opening_list)))
				qcs = LIST_ELEM(qcc->opening_list.n, struct qcs *, el_opening);
			base_time = qcs ? qcs->start : qcc->idle_start;

			TRACE_DEVEL("waiting on http request", QMUX_EV_QCC_WAKE, qcc->conn, qcs);
			qcc->task->expire = tick_add_ifset(base_time, timeout);
		}
		else {
			/* Use http-request timeout if keep-alive timeout not set */
			int timeout = tick_isset(px->timeout.httpka) ?
			                px->timeout.httpka : px->timeout.httpreq;

			TRACE_DEVEL("at least one request achieved but none currently in progress", QMUX_EV_QCC_WAKE, qcc->conn);
			qcc->task->expire = tick_add_ifset(qcc->idle_start, timeout);
		}
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
		TRACE_STATE("opening stream", QMUX_EV_QCS_NEW, qcs->qcc->conn, qcs);
		qcs->st = QC_SS_OPEN;
	}
}

/* Close the local channel of <qcs> instance. */
static void qcs_close_local(struct qcs *qcs)
{
	TRACE_STATE("closing stream locally", QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);

	/* The stream must have already been opened. */
	BUG_ON_HOT(qcs->st == QC_SS_IDLE);

	/* This operation cannot be used multiple times. */
	BUG_ON_HOT(qcs->st == QC_SS_HLOC || qcs->st == QC_SS_CLO);

	if (quic_stream_is_bidi(qcs->id)) {
		qcs->st = (qcs->st == QC_SS_HREM) ? QC_SS_CLO : QC_SS_HLOC;

		if (qcs->flags & QC_SF_HREQ_RECV)
			qcc_rm_hreq(qcs->qcc);
	}
	else {
		/* Only local uni streams are valid for this operation. */
		BUG_ON_HOT(quic_stream_is_remote(qcs->qcc, qcs->id));
		qcs->st = QC_SS_CLO;
	}
}

/* Close the remote channel of <qcs> instance. */
static void qcs_close_remote(struct qcs *qcs)
{
	TRACE_STATE("closing stream remotely", QMUX_EV_QCS_RECV, qcs->qcc->conn, qcs);

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
}

static int qcs_is_close_local(struct qcs *qcs)
{
	return qcs->st == QC_SS_HLOC || qcs->st == QC_SS_CLO;
}

static int qcs_is_close_remote(struct qcs *qcs)
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

/* Notify an eventual subscriber on <qcs> or else wakeup up the stconn layer if
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
	if (!qcs) {
		TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn);
		return NULL;
	}

	TRACE_PROTO("opening local stream",  QMUX_EV_QCS_NEW, qcc->conn, qcs);
	*next += 4;

	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn, qcs);
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
	uint64_t *largest, max_id;

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

	/* RFC 9000 4.6. Controlling Concurrency
	 *
	 * An endpoint that receives a frame with a stream ID exceeding the
	 * limit it has sent MUST treat this as a connection error of type
	 * STREAM_LIMIT_ERROR
	 */
	max_id = quic_stream_is_bidi(id) ? qcc->lfctl.ms_bidi * 4 :
	                                   qcc->lfctl.ms_uni * 4;
	if (id >= max_id) {
		TRACE_ERROR("flow control error", QMUX_EV_QCS_NEW|QMUX_EV_PROTO_ERR, qcc->conn);
		qcc_emit_cc(qcc, QC_ERR_STREAM_LIMIT_ERROR);
		goto err;
	}

	/* Only stream ID not already opened can be used. */
	BUG_ON(id < *largest);

	while (id >= *largest) {
		const char *str = *largest < id ? "initializing intermediary remote stream" :
		                                  "initializing remote stream";

		qcs = qcs_new(qcc, *largest, type);
		if (!qcs) {
			/* TODO emit RESET_STREAM */
			TRACE_ERROR("stream fallocation failure", QMUX_EV_QCS_NEW, qcc->conn);
			goto err;
		}

		TRACE_PROTO(str, QMUX_EV_QCS_NEW, qcc->conn, qcs);
		*largest += 4;
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn, qcs);
	return qcs;

 err:
	TRACE_LEAVE(QMUX_EV_QCS_NEW, qcc->conn);
	return NULL;
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
		TRACE_ERROR("receive-only stream not allowed", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS|QMUX_EV_PROTO_ERR, qcc->conn, NULL, &id);
		qcc_emit_cc(qcc, QC_ERR_STREAM_STATE_ERROR);
		goto err;
	}

	if (!send_only && quic_stream_is_uni(id) && quic_stream_is_local(qcc, id)) {
		TRACE_ERROR("send-only stream not allowed", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS|QMUX_EV_PROTO_ERR, qcc->conn, NULL, &id);
		qcc_emit_cc(qcc, QC_ERR_STREAM_STATE_ERROR);
		goto err;
	}

	/* Search the stream in the connection tree. */
	node = eb64_lookup(&qcc->streams_by_id, id);
	if (node) {
		*out = eb64_entry(node, struct qcs, by_id);
		TRACE_DEVEL("using stream from connection tree", QMUX_EV_QCC_RECV, qcc->conn, *out);
		goto out;
	}

	/* Check if stream is already closed. */
	if (qcc_stream_id_is_closed(qcc, id)) {
		TRACE_DATA("already closed stream", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
		/* Consider this as a success even if <out> is left NULL. */
		goto out;
	}

	/* Create the stream. This is valid only for remote initiated one. A
	 * local stream must have already been explicitly created by the
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
		TRACE_ERROR("locally initiated stream not yet created", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS|QMUX_EV_PROTO_ERR, qcc->conn, NULL, &id);
		qcc_emit_cc(qcc, QC_ERR_STREAM_STATE_ERROR);
		goto err;
	}
	else {
		/* Remote stream not found - try to open it. */
		*out = qcc_init_stream_remote(qcc, id);
		if (!*out) {
			TRACE_ERROR("stream creation error", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS, qcc->conn, NULL, &id);
			goto err;
		}
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn, *out);
	return 0;

 err:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 1;
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

	TRACE_ENTER(QMUX_EV_QCS_RECV, qcc->conn, qcs);

	ret = ncb_advance(buf, bytes);
	if (ret) {
		ABORT_NOW(); /* should not happens because removal only in data */
	}

	if (ncb_is_empty(buf))
		qc_free_ncbuf(qcs, buf);

	qcs->rx.offset += bytes;
	/* Not necessary to emit a MAX_STREAM_DATA if all data received. */
	if (qcs->flags & QC_SF_SIZE_KNOWN)
		goto conn_fctl;

	if (qcs->rx.msd - qcs->rx.offset < qcs->rx.msd_init / 2) {
		TRACE_DATA("increase stream credit via MAX_STREAM_DATA", QMUX_EV_QCS_RECV, qcc->conn, qcs);
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

 conn_fctl:
	qcc->lfctl.offsets_consume += bytes;
	if (qcc->lfctl.md - qcc->lfctl.offsets_consume < qcc->lfctl.md_init / 2) {
		TRACE_DATA("increase conn credit via MAX_DATA", QMUX_EV_QCS_RECV, qcc->conn, qcs);
		frm = pool_zalloc(pool_head_quic_frame);
		BUG_ON(!frm); /* TODO handle this properly */

		qcc->lfctl.md = qcc->lfctl.offsets_consume + qcc->lfctl.md_init;

		LIST_INIT(&frm->reflist);
		frm->type = QUIC_FT_MAX_DATA;
		frm->max_data.max_data = qcc->lfctl.md;

		LIST_APPEND(&qcs->qcc->lfctl.frms, &frm->list);
		tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	TRACE_LEAVE(QMUX_EV_QCS_RECV, qcc->conn, qcs);
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

	/* Signal FIN to application if STREAM FIN received with all data. */
	if (qcs_is_close_remote(qcs))
		fin = 1;

	if (!(qcs->flags & QC_SF_READ_ABORTED)) {
		ret = qcc->app_ops->decode_qcs(qcs, &b, fin);
		if (ret < 0) {
			TRACE_ERROR("decoding error", QMUX_EV_QCS_RECV, qcc->conn, qcs);
			goto err;
		}
	}
	else {
		TRACE_DATA("ignore read on stream", QMUX_EV_QCS_RECV, qcc->conn, qcs);
		ret = b_data(&b);
	}

	if (ret) {
		qcs_consume(qcs, ret);
		qcs_notify_recv(qcs);
	}

	TRACE_LEAVE(QMUX_EV_QCS_RECV, qcc->conn, qcs);
	return 0;

 err:
	TRACE_LEAVE(QMUX_EV_QCS_RECV, qcc->conn, qcs);
	return 1;
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
	TRACE_ENTER(QMUX_EV_QCC_END, qcc->conn);

	if (immediate) {
		quic_set_connection_close(qcc->conn->handle.qc, quic_err_app(err));
		qcc->flags |= QC_CF_CC_EMIT;
		tasklet_wakeup(qcc->wait_event.tasklet);
	}
	else {
		/* Only register the error code for graceful shutdown. */
		qcc->conn->handle.qc->err = quic_err_app(err);
	}

	TRACE_LEAVE(QMUX_EV_QCC_END, qcc->conn);
}

/* Prepare for the emission of RESET_STREAM on <qcs> with error code <err>. */
void qcc_reset_stream(struct qcs *qcs, int err)
{
	struct qcc *qcc = qcs->qcc;

	if ((qcs->flags & QC_SF_TO_RESET) || qcs_is_close_local(qcs))
		return;

	TRACE_STATE("reset stream", QMUX_EV_QCS_END, qcc->conn, qcs);
	qcs->flags |= QC_SF_TO_RESET;
	qcs->err = err;

	qcc_send_stream(qcs, 1);
	tasklet_wakeup(qcc->wait_event.tasklet);
}

/* Register <qcs> stream for emission of STREAM, STOP_SENDING or RESET_STREAM.
 * Set <urg> to 1 if stream content should be treated in priority compared to
 * other streams.
 */
void qcc_send_stream(struct qcs *qcs, int urg)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	/* Cannot send if already closed. */
	BUG_ON(qcs_is_close_local(qcs));

	if (urg) {
		LIST_DEL_INIT(&qcs->el_send);
		LIST_INSERT(&qcc->send_list, &qcs->el_send);
	}
	else {
		if (!LIST_INLIST(&qcs->el_send))
			LIST_APPEND(&qcs->qcc->send_list, &qcs->el_send);
	}

	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
}

/* Prepare for the emission of STOP_SENDING on <qcs>. */
void qcc_abort_stream_read(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_QCC_NEW, qcc->conn, qcs);

	if ((qcs->flags & QC_SF_TO_STOP_SENDING) || qcs_is_close_remote(qcs))
		goto end;

	TRACE_STATE("abort stream read", QMUX_EV_QCS_END, qcc->conn, qcs);
	qcs->flags |= (QC_SF_TO_STOP_SENDING|QC_SF_READ_ABORTED);

	qcc_send_stream(qcs, 1);
	tasklet_wakeup(qcc->wait_event.tasklet);

 end:
	TRACE_LEAVE(QMUX_EV_QCC_NEW, qcc->conn, qcs);
}

/* Install the <app_ops> applicative layer of a QUIC connection on mux <qcc>.
 * Returns 0 on success else non-zero.
 */
int qcc_install_app_ops(struct qcc *qcc, const struct qcc_app_ops *app_ops)
{
	TRACE_ENTER(QMUX_EV_QCC_NEW, qcc->conn);

	qcc->app_ops = app_ops;
	if (qcc->app_ops->init && !qcc->app_ops->init(qcc)) {
		TRACE_ERROR("app ops init error", QMUX_EV_QCC_NEW, qcc->conn);
		goto err;
	}

	TRACE_PROTO("application layer initialized", QMUX_EV_QCC_NEW, qcc->conn);

	TRACE_LEAVE(QMUX_EV_QCC_NEW, qcc->conn);
	return 0;

 err:
	TRACE_LEAVE(QMUX_EV_QCC_NEW, qcc->conn);
	return 1;
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
		TRACE_DATA("connection closed", QMUX_EV_QCC_RECV, qcc->conn);
		goto err;
	}

	/* RFC 9000 19.8. STREAM Frames
	 *
	 * An endpoint MUST terminate the connection with error
	 * STREAM_STATE_ERROR if it receives a STREAM frame for a locally
	 * initiated stream that has not yet been created, or for a send-only
	 * stream.
	 */
	if (qcc_get_qcs(qcc, id, 1, 0, &qcs)) {
		TRACE_DATA("qcs retrieval error", QMUX_EV_QCC_RECV, qcc->conn);
		goto err;
	}

	if (!qcs) {
		TRACE_DATA("already closed stream", QMUX_EV_QCC_RECV, qcc->conn);
		goto out;
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
		TRACE_ERROR("final size error", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV|QMUX_EV_PROTO_ERR, qcc->conn, qcs);
		qcc_emit_cc(qcc, QC_ERR_FINAL_SIZE_ERROR);
		goto err;
	}

	if (qcs_is_close_remote(qcs)) {
		TRACE_DATA("skipping STREAM for remotely closed", QMUX_EV_QCC_RECV, qcc->conn);
		goto out;
	}

	if (offset + len <= qcs->rx.offset) {
		/* TODO offset may have been received without FIN first and now
		 * with it. In this case, it must be notified to be able to
		 * close the stream.
		 */
		TRACE_DATA("already received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		goto out;
	}

	TRACE_PROTO("receiving STREAM", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
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
			TRACE_ERROR("flow control error", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV|QMUX_EV_PROTO_ERR,
			            qcc->conn, qcs);
			qcc_emit_cc(qcc, QC_ERR_FLOW_CONTROL_ERROR);
			goto err;
		}
	}

	if (!qc_get_ncbuf(qcs, &qcs->rx.ncbuf) || ncb_is_null(&qcs->rx.ncbuf)) {
		/* TODO should mark qcs as full */
		ABORT_NOW();
		return 1;
	}

	TRACE_DATA("newly received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
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
			TRACE_ERROR("overlapping data rejected", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV|QMUX_EV_PROTO_ERR,
			            qcc->conn, qcs);
			qcc_emit_cc(qcc, QC_ERR_PROTOCOL_VIOLATION);
		}
		else if (ret == NCB_RET_GAP_SIZE) {
			TRACE_DATA("cannot bufferize frame due to gap size limit", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV,
			           qcc->conn, qcs);
		}
		return 1;
	}

	if (fin)
		qcs->flags |= QC_SF_SIZE_KNOWN;

	if (qcs->flags & QC_SF_SIZE_KNOWN &&
	    qcs->rx.offset_max == qcs->rx.offset + ncb_data(&qcs->rx.ncbuf, 0)) {
		qcs_close_remote(qcs);
	}

	if (ncb_data(&qcs->rx.ncbuf, 0) && !(qcs->flags & QC_SF_DEM_FULL)) {
		qcc_decode_qcs(qcc, qcs);
		qcc_refresh_timeout(qcc);
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;

 err:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 1;
}

/* Handle a new MAX_DATA frame. <max> must contains the maximum data field of
 * the frame.
 *
 * Returns 0 on success else non-zero.
 */
int qcc_recv_max_data(struct qcc *qcc, uint64_t max)
{
	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	TRACE_PROTO("receiving MAX_DATA", QMUX_EV_QCC_RECV, qcc->conn);
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
		TRACE_PROTO("receiving MAX_STREAM_DATA", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		if (max > qcs->tx.msd) {
			qcs->tx.msd = max;
			TRACE_DEVEL("increase remote max-stream-data", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);

			if (qcs->flags & QC_SF_BLK_SFCTL) {
				qcs->flags &= ~QC_SF_BLK_SFCTL;
				/* TODO optim: only wakeup IO-CB if stream has data to sent. */
				tasklet_wakeup(qcc->wait_event.tasklet);
			}
		}
	}

	if (qcc_may_expire(qcc) && !qcc->nb_hreq)
		qcc_refresh_timeout(qcc);

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;
}

/* Handle a new RESET_STREAM frame from stream ID <id> with error code <err>
 * and final stream size <final_size>.
 *
 * Returns 0 on success else non-zero. On error, the received frame should not
 * be acknowledged.
 */
int qcc_recv_reset_stream(struct qcc *qcc, uint64_t id, uint64_t err, uint64_t final_size)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	/* RFC 9000 19.4. RESET_STREAM Frames
	 *
	 * An endpoint that receives a RESET_STREAM frame for a send-only stream
	 * MUST terminate the connection with error STREAM_STATE_ERROR.
	 */
	if (qcc_get_qcs(qcc, id, 1, 0, &qcs)) {
		TRACE_ERROR("RESET_STREAM for send-only stream received", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		qcc_emit_cc(qcc, QC_ERR_STREAM_STATE_ERROR);
		goto err;
	}

	if (!qcs || qcs_is_close_remote(qcs))
		goto out;

	TRACE_PROTO("receiving RESET_STREAM", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
	qcs_idle_open(qcs);

	if (qcs->rx.offset_max > final_size ||
	    ((qcs->flags & QC_SF_SIZE_KNOWN) && qcs->rx.offset_max != final_size)) {
		TRACE_ERROR("final size error on RESET_STREAM", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		qcc_emit_cc(qcc, QC_ERR_FINAL_SIZE_ERROR);
		goto err;
	}

	qcs->flags |= QC_SF_SIZE_KNOWN;
	qcs_close_remote(qcs);
	qc_free_ncbuf(qcs, &qcs->rx.ncbuf);

	if (qcs_sc(qcs)) {
		se_fl_set_error(qcs->sd);
		qcs_alert(qcs);
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;

 err:
	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 1;
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

	TRACE_PROTO("receiving STOP_SENDING", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);

	/* RFC 9000 3.5. Solicited State Transitions
	 *
	 * An endpoint is expected to send another STOP_SENDING frame if a
	 * packet containing a previous STOP_SENDING is lost.  However, once
	 * either all stream data or a RESET_STREAM frame has been received for
	 * the stream -- that is, the stream is in any state other than "Recv"
	 * or "Size Known" -- sending a STOP_SENDING frame is unnecessary.
	 */

	/* TODO thanks to previous RFC clause, STOP_SENDING is ignored if current stream
	 * has already been closed locally. This is useful to not emit multiple
	 * RESET_STREAM for a single stream. This is functional if stream is
	 * locally closed due to all data transmitted, but in this case the RFC
	 * advices to use an explicit RESET_STREAM.
	 */
	if (qcs_is_close_local(qcs)) {
		TRACE_STATE("ignoring STOP_SENDING", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		goto out;
	}

	qcs_idle_open(qcs);

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
	qcc_reset_stream(qcs, err);

	if (qcc_may_expire(qcc) && !qcc->nb_hreq)
		qcc_refresh_timeout(qcc);

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

	TRACE_ENTER(QMUX_EV_QCS_END, qcc->conn);

	if (quic_stream_is_bidi(id)) {
		++qcc->lfctl.cl_bidi_r;
		if (qcc->lfctl.cl_bidi_r > qcc->lfctl.ms_bidi_init / 2) {
			TRACE_DATA("increase max stream limit with MAX_STREAMS_BIDI", QMUX_EV_QCC_SEND, qcc->conn);
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
		/* TODO unidirectional stream flow control with MAX_STREAMS_UNI
		 * emission not implemented. It should be unnecessary for
		 * HTTP/3 but may be required if other application protocols
		 * are supported.
		 */
	}

	TRACE_LEAVE(QMUX_EV_QCS_END, qcc->conn);

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

	TRACE_PROTO("sending STREAM frame", QMUX_EV_QCS_SEND, qcc->conn, qcs);
	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm) {
		TRACE_ERROR("frame alloc failure", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		goto err;
	}

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
	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
	return -1;
}

/* Check after transferring data from qcs.tx.buf if FIN must be set on the next
 * STREAM frame for <qcs>.
 *
 * Returns true if FIN must be set else false.
 */
static int qcs_stream_fin(struct qcs *qcs)
{
	return qcs->flags & QC_SF_FIN_STREAM && !b_data(&qcs->tx.buf);
}

/* Return true if <qcs> has data to send in new STREAM frames. */
static forceinline int qcs_need_sending(struct qcs *qcs)
{
	return b_data(&qcs->tx.buf) || qcs->tx.sent_offset < qcs->tx.offset ||
	       qcs_stream_fin(qcs);
}

/* This function must be called by the upper layer to inform about the sending
 * of a STREAM frame for <qcs> instance. The frame is of <data> length and on
 * <offset>.
 */
void qcc_streams_sent_done(struct qcs *qcs, uint64_t data, uint64_t offset)
{
	struct qcc *qcc = qcs->qcc;
	uint64_t diff;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	BUG_ON(offset > qcs->tx.sent_offset);
	BUG_ON(offset + data > qcs->tx.offset);

	/* check if the STREAM frame has already been notified. It can happen
	 * for retransmission.
	 */
	if (offset + data < qcs->tx.sent_offset) {
		TRACE_DEVEL("offset already notified", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		goto out;
	}

	qcs_idle_open(qcs);

	diff = offset + data - qcs->tx.sent_offset;
	if (diff) {
		/* increase offset sum on connection */
		qcc->tx.sent_offsets += diff;
		BUG_ON_HOT(qcc->tx.sent_offsets > qcc->rfctl.md);
		if (qcc->tx.sent_offsets == qcc->rfctl.md) {
			qcc->flags |= QC_CF_BLK_MFCTL;
			TRACE_STATE("connection flow-control reached", QMUX_EV_QCS_SEND, qcc->conn);
		}

		/* increase offset on stream */
		qcs->tx.sent_offset += diff;
		BUG_ON_HOT(qcs->tx.sent_offset > qcs->tx.msd);
		BUG_ON_HOT(qcs->tx.sent_offset > qcs->tx.offset);
		if (qcs->tx.sent_offset == qcs->tx.msd) {
			qcs->flags |= QC_SF_BLK_SFCTL;
			TRACE_STATE("stream flow-control reached", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		}

		/* If qcs.stream.buf is full, release it to the lower layer. */
		if (qcs->tx.offset == qcs->tx.sent_offset &&
		    b_full(&qcs->stream->buf->buf)) {
			qc_stream_buf_release(qcs->stream);
		}
	}

	if (qcs->tx.offset == qcs->tx.sent_offset && !b_data(&qcs->tx.buf)) {
		/* Remove stream from send_list if all was sent. */
		LIST_DEL_INIT(&qcs->el_send);
		TRACE_STATE("stream sent done", QMUX_EV_QCS_SEND, qcc->conn, qcs);

		if (qcs->flags & (QC_SF_FIN_STREAM|QC_SF_DETACH)) {
			/* Close stream locally. */
			qcs_close_local(qcs);
			/* Reset flag to not emit multiple FIN STREAM frames. */
			qcs->flags &= ~QC_SF_FIN_STREAM;
		}
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
}

/* Wrapper for send on transport layer. Send a list of frames <frms> for the
 * connection <qcc>.
 *
 * Returns 0 if all data sent with success else non-zero.
 */
static int qc_send_frames(struct qcc *qcc, struct list *frms)
{
	TRACE_ENTER(QMUX_EV_QCC_SEND, qcc->conn);

	if (LIST_ISEMPTY(frms)) {
		TRACE_DEVEL("no frames to send", QMUX_EV_QCC_SEND, qcc->conn);
		goto err;
	}

	if (!qc_send_mux(qcc->conn->handle.qc, frms))
		goto err;

	/* If there is frames left at this stage, transport layer is blocked.
	 * Subscribe on it to retry later.
	 */
	if (!LIST_ISEMPTY(frms)) {
		TRACE_DEVEL("remaining frames to send, subscribing", QMUX_EV_QCC_SEND, qcc->conn);
		qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
		                           SUB_RETRY_SEND, &qcc->wait_event);
		goto err;
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return 0;

 err:
	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return 1;
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
	if (!frm) {
		TRACE_LEAVE(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
	}

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

/* Emit a STOP_SENDING on <qcs>.
 *
 * Returns 0 if the frame has been successfully sent else non-zero.
 */
static int qcs_send_stop_sending(struct qcs *qcs)
{
	struct list frms = LIST_HEAD_INIT(frms);
	struct quic_frame *frm;
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);

	/* RFC 9000 3.3. Permitted Frame Types
	 *
	 * A
	 * receiver MAY send a STOP_SENDING frame in any state where it has not
	 * received a RESET_STREAM frame -- that is, states other than "Reset
	 * Recvd" or "Reset Read". However, there is little value in sending a
	 * STOP_SENDING frame in the "Data Recvd" state, as all stream data has
	 * been received. A sender could receive either of these two types of
	 * frames in any state as a result of delayed delivery of packets.¶
	 */
	if (qcs_is_close_remote(qcs)) {
		TRACE_STATE("skip STOP_SENDING on remote already closed", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		goto done;
	}

	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm) {
		TRACE_LEAVE(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
	}

	LIST_INIT(&frm->reflist);
	frm->type = QUIC_FT_STOP_SENDING;
	frm->stop_sending.id = qcs->id;
	frm->stop_sending.app_error_code = qcs->err;

	LIST_APPEND(&frms, &frm->list);
	if (qc_send_frames(qcs->qcc, &frms)) {
		pool_free(pool_head_quic_frame, frm);
		TRACE_DEVEL("cannot send STOP_SENDING", QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
	}

 done:
	qcs->flags &= ~QC_SF_TO_STOP_SENDING;

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

	/* Cannot send STREAM on remote unidirectional streams. */
	BUG_ON(quic_stream_is_uni(qcs->id) && quic_stream_is_remote(qcc, qcs->id));

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

	/* FIN is set if all incoming data were transferred. */
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
	struct qcs *qcs, *qcs_tmp;
	int total = 0;

	TRACE_ENTER(QMUX_EV_QCC_SEND, qcc->conn);

	if (qcc->conn->flags & CO_FL_SOCK_WR_SH || qcc->flags & QC_CF_CC_EMIT) {
		qcc->conn->flags |= CO_FL_ERROR;
		TRACE_DEVEL("connection on error", QMUX_EV_QCC_SEND, qcc->conn);
		goto err;
	}

	if (!LIST_ISEMPTY(&qcc->lfctl.frms)) {
		if (qc_send_frames(qcc, &qcc->lfctl.frms)) {
			TRACE_DEVEL("flow-control frames rejected by transport, aborting send", QMUX_EV_QCC_SEND, qcc->conn);
			goto out;
		}
	}

	if (qcc->flags & QC_CF_BLK_MFCTL)
		goto err;

	if (!(qcc->flags & QC_CF_APP_FINAL) && !eb_is_empty(&qcc->streams_by_id) &&
	    qcc->app_ops->finalize) {
		/* Finalize the application layer before sending any stream.
		 * For h3 this consists in preparing the control stream data (SETTINGS h3).
		 */
		qcc->app_ops->finalize(qcc->ctx);
		qcc->flags |= QC_CF_APP_FINAL;
	}

	/* Send STREAM/STOP_SENDING/RESET_STREAM data for registered streams. */
	list_for_each_entry_safe(qcs, qcs_tmp, &qcc->send_list, el_send) {
		/* Stream must not be present in send_list if it has nothing to send. */
		BUG_ON(!(qcs->flags & (QC_SF_TO_STOP_SENDING|QC_SF_TO_RESET)) &&
		       !qcs_need_sending(qcs));

		/* Each STOP_SENDING/RESET_STREAM frame is sent individually to
		 * guarantee its emission.
		 *
		 * TODO multiplex several frames in same datagram to optimize sending
		 */
		if (qcs->flags & QC_SF_TO_STOP_SENDING) {
			if (qcs_send_stop_sending(qcs))
				goto out;

			/* Remove stream from send_list if it had only STOP_SENDING
			 * to send.
			 */
			if (!(qcs->flags & QC_SF_TO_RESET) && !qcs_need_sending(qcs)) {
				LIST_DEL_INIT(&qcs->el_send);
				continue;
			}
		}

		if (qcs->flags & QC_SF_TO_RESET) {
			if (qcs_send_reset(qcs))
				goto out;

			/* RFC 9000 3.3. Permitted Frame Types
			 *
			 * A sender MUST NOT send
			 * a STREAM or STREAM_DATA_BLOCKED frame for a stream in the
			 * "Reset Sent" state or any terminal state -- that is, after
			 * sending a RESET_STREAM frame.
			 */
			LIST_DEL_INIT(&qcs->el_send);
			continue;
		}

		if (!(qcs->flags & QC_SF_BLK_SFCTL))
			total += _qc_send_qcs(qcs, &frms);
	}

	/* Retry sending until no frame to send, data rejected or connection
	 * flow-control limit reached.
	 */
	while (qc_send_frames(qcc, &frms) == 0 && !(qcc->flags & QC_CF_BLK_MFCTL)) {
		/* Reloop over <qcc.send_list>. Useful for streams which have
		 * fulfilled their qc_stream_desc buf and have now release it.
		 */
		list_for_each_entry(qcs, &qcc->send_list, el_send) {
			/* Only streams blocked on flow-control or waiting on a
			 * new qc_stream_desc should be present in send_list as
			 * long as transport layer can handle all data.
			 */
			BUG_ON(qcs->stream->buf && !(qcs->flags & QC_SF_BLK_SFCTL));

			if (!(qcs->flags & QC_SF_BLK_SFCTL))
				total += _qc_send_qcs(qcs, &frms);
		}
	}

 out:
	/* Deallocate frames that the transport layer has rejected. */
	if (!LIST_ISEMPTY(&frms)) {
		struct quic_frame *frm, *frm2;

		list_for_each_entry_safe(frm, frm2, &frms, list) {
			LIST_DELETE(&frm->list);
			pool_free(pool_head_quic_frame, frm);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return total;

 err:
	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return 0;
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

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	if (qcc->flags & QC_CF_CC_EMIT) {
		TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
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
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
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

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc->conn);

	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = eb64_entry(node, struct qcs, by_id);
		node = eb64_next(node);

		/* Release not attached closed streams. */
		if (qcs->st == QC_SS_CLO && !qcs_sc(qcs)) {
			TRACE_STATE("purging closed stream", QMUX_EV_QCC_WAKE, qcs->qcc->conn, qcs);
			qcs_destroy(qcs);
			release = 1;
			continue;
		}

		/* Release detached streams with empty buffer. */
		if (qcs->flags & QC_SF_DETACH) {
			if (qcs_is_close_local(qcs)) {
				TRACE_STATE("purging detached stream", QMUX_EV_QCC_WAKE, qcs->qcc->conn, qcs);
				qcs_destroy(qcs);
				release = 1;
				continue;
			}

			qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
			                           SUB_RETRY_SEND, &qcc->wait_event);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_WAKE, qcc->conn);
	return release;
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void qc_release(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;
	struct eb64_node *node;

	TRACE_ENTER(QMUX_EV_QCC_END, conn);

	if (qcc->app_ops && qcc->app_ops->shutdown) {
		/* Application protocol with dedicated connection closing
		 * procedure.
		 */
		qcc->app_ops->shutdown(qcc->ctx);

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

	if (qcc->app_ops && qcc->app_ops->release)
		qcc->app_ops->release(qcc->ctx);
	TRACE_PROTO("application layer released", QMUX_EV_QCC_END, conn);

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

struct task *qc_io_cb(struct task *t, void *ctx, unsigned int status)
{
	struct qcc *qcc = ctx;

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc->conn);

	qc_send(qcc);

	if (qc_purge_streams(qcc)) {
		if (qcc_is_dead(qcc)) {
			TRACE_STATE("releasing dead connection", QMUX_EV_QCC_WAKE, qcc->conn);
			goto release;
		}
	}

	qc_recv(qcc);

	/* TODO check if qcc proxy is disabled. If yes, use graceful shutdown
	 * to close the connection.
	 */

	qcc_refresh_timeout(qcc);

 end:
	TRACE_LEAVE(QMUX_EV_QCC_WAKE, qcc->conn);
	return NULL;

 release:
	qc_release(qcc);
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
			TRACE_DEVEL("not expired", QMUX_EV_QCC_WAKE, qcc->conn);
			goto requeue;
		}

		if (!qcc_may_expire(qcc)) {
			TRACE_DEVEL("cannot expired", QMUX_EV_QCC_WAKE, qcc->conn);
			t->expire = TICK_ETERNITY;
			goto requeue;
		}
	}

	task_destroy(t);

	if (!qcc) {
		TRACE_DEVEL("no more qcc", QMUX_EV_QCC_WAKE);
		goto out;
	}

	qcc->task = NULL;

	/* TODO depending on the timeout condition, different shutdown mode
	 * should be used. For http keep-alive or disabled proxy, a graceful
	 * shutdown should occurs. For all other cases, an immediate close
	 * seems legitimate.
	 */
	if (qcc_is_dead(qcc)) {
		TRACE_STATE("releasing dead connection", QMUX_EV_QCC_WAKE, qcc->conn);
		qc_release(qcc);
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCC_WAKE);
	return NULL;

 requeue:
	TRACE_LEAVE(QMUX_EV_QCC_WAKE);
	return t;
}

static int qc_init(struct connection *conn, struct proxy *prx,
                   struct session *sess, struct buffer *input)
{
	struct qcc *qcc;
	struct quic_transport_params *lparams, *rparams;

	TRACE_ENTER(QMUX_EV_QCC_NEW);

	qcc = pool_alloc(pool_head_qcc);
	if (!qcc) {
		TRACE_ERROR("alloc failure", QMUX_EV_QCC_NEW);
		goto fail_no_qcc;
	}

	qcc->conn = conn;
	conn->ctx = qcc;
	qcc->nb_hreq = qcc->nb_sc = 0;
	qcc->flags = 0;

	qcc->app_ops = NULL;
	if (qcc_install_app_ops(qcc, conn->handle.qc->app_ops)) {
		TRACE_PROTO("Cannot install app layer", QMUX_EV_QCC_NEW, qcc->conn);
		/* prepare a CONNECTION_CLOSE frame */
		quic_set_connection_close(conn->handle.qc, quic_err_transport(QC_ERR_APPLICATION_ERROR));
		goto fail_no_tasklet;
	}

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
	qcc->lfctl.ms_uni = lparams->initial_max_streams_uni;
	qcc->lfctl.msd_bidi_l = lparams->initial_max_stream_data_bidi_local;
	qcc->lfctl.msd_bidi_r = lparams->initial_max_stream_data_bidi_remote;
	qcc->lfctl.msd_uni_r = lparams->initial_max_stream_data_uni;
	qcc->lfctl.cl_bidi_r = 0;

	qcc->lfctl.md = qcc->lfctl.md_init = lparams->initial_max_data;
	qcc->lfctl.offsets_recv = qcc->lfctl.offsets_consume = 0;

	rparams = &conn->handle.qc->tx.params;
	qcc->rfctl.md = rparams->initial_max_data;
	qcc->rfctl.msd_bidi_l = rparams->initial_max_stream_data_bidi_local;
	qcc->rfctl.msd_bidi_r = rparams->initial_max_stream_data_bidi_remote;
	qcc->rfctl.msd_uni_l = rparams->initial_max_stream_data_uni;

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
	if (!qcc->wait_event.tasklet) {
		TRACE_ERROR("taslket alloc failure", QMUX_EV_QCC_NEW);
		goto fail_no_tasklet;
	}

	LIST_INIT(&qcc->send_list);

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
		if (!qcc->task) {
			TRACE_ERROR("timeout task alloc failure", QMUX_EV_QCC_NEW);
			goto fail_no_timeout_task;
		}
		qcc->task->process = qc_timeout_task;
		qcc->task->context = qcc;
		qcc->task->expire = tick_add(now_ms, qcc->timeout);
	}
	qcc_reset_idle_start(qcc);
	LIST_INIT(&qcc->opening_list);

	if (!conn_is_back(conn)) {
		if (!LIST_INLIST(&conn->stopping_list)) {
			LIST_APPEND(&mux_stopping_data[tid].list,
			            &conn->stopping_list);
		}
	}

	HA_ATOMIC_STORE(&conn->handle.qc->qcc, qcc);
	/* init read cycle */
	tasklet_wakeup(qcc->wait_event.tasklet);

	TRACE_LEAVE(QMUX_EV_QCC_NEW, qcc->conn);
	return 0;

 fail_no_timeout_task:
	tasklet_free(qcc->wait_event.tasklet);
 fail_no_tasklet:
	if (qcc->app_ops && qcc->app_ops->release)
		qcc->app_ops->release(qcc->ctx);
	pool_free(pool_head_qcc, qcc);
 fail_no_qcc:
	TRACE_LEAVE(QMUX_EV_QCC_NEW);
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
		TRACE_STATE("remaining data, detaching qcs", QMUX_EV_STRM_END, qcc->conn, qcs);
		qcs->flags |= QC_SF_DETACH;
		qcc_refresh_timeout(qcc);

		TRACE_LEAVE(QMUX_EV_STRM_END, qcc->conn, qcs);
		return;
	}

	qcs_destroy(qcs);

	if (qcc_is_dead(qcc)) {
		TRACE_STATE("killing dead connection", QMUX_EV_STRM_END, qcc->conn);
		goto release;
	}
	else if (qcc->task) {
		TRACE_DEVEL("refreshing connection's timeout", QMUX_EV_STRM_END, qcc->conn);
		qcc_refresh_timeout(qcc);
	}
	else {
		TRACE_DEVEL("completed", QMUX_EV_STRM_END, qcc->conn);
	}

	TRACE_LEAVE(QMUX_EV_STRM_END, qcc->conn);
	return;

 release:
	qc_release(qcc);
	TRACE_LEAVE(QMUX_EV_STRM_END);
	return;
}

/* Called from the upper layer, to receive data */
static size_t qc_recv_buf(struct stconn *sc, struct buffer *buf,
                          size_t count, int flags)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	size_t ret = 0;
	char fin = 0;

	TRACE_ENTER(QMUX_EV_STRM_RECV, qcs->qcc->conn, qcs);

	ret = qcs_http_rcv_buf(qcs, buf, count, &fin);

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

static size_t qc_send_buf(struct stconn *sc, struct buffer *buf,
                          size_t count, int flags)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	size_t ret;
	char fin;

	TRACE_ENTER(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	/* stream layer has been detached so no transfer must occur after. */
	BUG_ON_HOT(qcs->flags & QC_SF_DETACH);

	if (qcs_is_close_local(qcs) || (qcs->flags & QC_SF_TO_RESET)) {
		ret = qcs_http_reset_buf(qcs, buf, count);
		goto end;
	}

	ret = qcs_http_snd_buf(qcs, buf, count, &fin);
	if (fin)
		qcs->flags |= QC_SF_FIN_STREAM;

	if (ret || fin) {
		qcc_send_stream(qcs, 0);
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

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
	 * TODO this is relevant for frontend connections only.
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
	TRACE_STATE("releasing dead connection", QMUX_EV_QCC_WAKE, qcc->conn);
	qc_release(qcc);
	TRACE_LEAVE(QMUX_EV_QCC_WAKE);
	return 1;
}

static void qc_shutw(struct stconn *sc, enum co_shw_mode mode)
{
	struct qcs *qcs = __sc_mux_strm(sc);

	TRACE_ENTER(QMUX_EV_STRM_SHUT, qcs->qcc->conn, qcs);

	/* If QC_SF_FIN_STREAM is not set and stream is not closed locally, it
	 * means that upper layer reported an early closure. A RESET_STREAM is
	 * necessary if not already scheduled.
	 */

	if (!qcs_is_close_local(qcs) &&
	    !(qcs->flags & (QC_SF_FIN_STREAM|QC_SF_TO_RESET))) {
		qcc_reset_stream(qcs, 0);
		se_fl_set_error(qcs->sd);
	}

	TRACE_LEAVE(QMUX_EV_STRM_SHUT, qcs->qcc->conn, qcs);
}

/* for debugging with CLI's "show sess" command. May emit multiple lines, each
 * new one being prefixed with <pfx>, if <pfx> is not NULL, otherwise a single
 * line is used. Each field starts with a space so it's safe to print it after
 * existing fields.
 */
static int qc_show_sd(struct buffer *msg, struct sedesc *sd, const char *pfx)
{
	struct qcs *qcs = sd->se;
	struct qcc *qcc;
	int ret = 0;

	if (!qcs)
		return ret;

	chunk_appendf(msg, " qcs=%p .flg=%#x .id=%llu .st=%s .ctx=%p, .err=%#llx",
		      qcs, qcs->flags, (ull)qcs->id, qcs_st_to_str(qcs->st), qcs->ctx, (ull)qcs->err);

	if (pfx)
		chunk_appendf(msg, "\n%s", pfx);

	qcc = qcs->qcc;
	chunk_appendf(msg, " qcc=%p .flg=%#x .nbsc=%llu .nbhreq=%llu, .task=%p",
		      qcc, qcc->flags, (ull)qcc->nb_sc, (ull)qcc->nb_hreq, qcc->task);
	return ret;
}


static const struct mux_ops qc_ops = {
	.init = qc_init,
	.destroy = qc_destroy,
	.detach = qc_detach,
	.rcv_buf = qc_recv_buf,
	.snd_buf = qc_send_buf,
	.subscribe = qc_subscribe,
	.unsubscribe = qc_unsubscribe,
	.wake = qc_wake,
	.shutw = qc_shutw,
	.show_sd = qc_show_sd,
	.flags = MX_FL_HTX|MX_FL_NO_UPG|MX_FL_FRAMED,
	.name = "QUIC",
};

static struct mux_proto_list mux_proto_quic =
  { .token = IST("quic"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_FE, .mux = &qc_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_quic);
