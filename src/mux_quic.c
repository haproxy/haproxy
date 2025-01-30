#include <haproxy/mux_quic.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/global-t.h>
#include <haproxy/h3.h>
#include <haproxy/list.h>
#include <haproxy/ncbuf.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/qmux_http.h>
#include <haproxy/qmux_trace.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_fctl.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_pacing.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/quic_tune.h>
#include <haproxy/quic_tx.h>
#include <haproxy/session.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/stconn.h>
#include <haproxy/time.h>
#include <haproxy/trace.h>
#include <haproxy/xref.h>

DECLARE_POOL(pool_head_qcc, "qcc", sizeof(struct qcc));
DECLARE_POOL(pool_head_qcs, "qcs", sizeof(struct qcs));

static void qmux_ctrl_send(struct qc_stream_desc *, uint64_t data, uint64_t offset);
static void qmux_ctrl_room(struct qc_stream_desc *, uint64_t room);

/* Returns true if pacing should be used for <conn> connection. */
static int qcc_is_pacing_active(const struct connection *conn)
{
	return !(quic_tune.options & QUIC_TUNE_NO_PACING);
}

static void qcs_free_ncbuf(struct qcs *qcs, struct ncbuf *ncbuf)
{
	struct buffer buf;

	if (ncb_is_null(ncbuf))
		return;

	buf = b_make(ncbuf->area, ncbuf->size, 0, 0);
	b_free(&buf);
	offer_buffers(NULL, 1);

	*ncbuf = NCBUF_NULL;

	/* Reset DEM_FULL as buffer is released. This ensures mux is not woken
	 * up from rcv_buf stream callback when demux was previously blocked.
	 */
	qcs->flags &= ~QC_SF_DEM_FULL;
}

/* Free <qcs> instance. This function is reserved for internal usage : it must
 * only be called on qcs alloc error or on connection shutdown. Else
 * qcs_destroy must be preferred to handle QUIC flow-control increase.
 */
static void qcs_free(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_QCS_END, qcc->conn, qcs);
	TRACE_STATE("releasing QUIC stream", QMUX_EV_QCS_END, qcc->conn, qcs);

	/* Safe to use even if already removed from the list. */
	LIST_DEL_INIT(&qcs->el_opening);
	LIST_DEL_INIT(&qcs->el_recv);
	LIST_DEL_INIT(&qcs->el_send);
	LIST_DEL_INIT(&qcs->el_fctl);
	LIST_DEL_INIT(&qcs->el_buf);

	/* Release stream endpoint descriptor. */
	BUG_ON(qcs->sd && !se_fl_test(qcs->sd, SE_FL_ORPHAN));
	sedesc_free(qcs->sd);
	qcs->sd = NULL;

	/* Release app-layer context. */
	if (qcs->ctx && qcc->app_ops->detach)
		qcc->app_ops->detach(qcs);

	/* Release qc_stream_desc buffer from quic-conn layer. */
	if (qcs->stream) {
		qc_stream_desc_sub_send(qcs->stream, NULL);
		qc_stream_desc_release(qcs->stream, qcs->tx.fc.off_real, qcc);
	}

	/* Free Rx buffer. */
	qcs_free_ncbuf(qcs, &qcs->rx.ncbuf);

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
	qcs->flags = QC_SF_NONE;
	qcs->st = QC_SS_IDLE;
	qcs->ctx = NULL;

	/* App callback attach may register the stream for http-request wait.
	 * These fields must be initialed before.
	 */
	LIST_INIT(&qcs->el_opening);
	LIST_INIT(&qcs->el_recv);
	LIST_INIT(&qcs->el_send);
	LIST_INIT(&qcs->el_fctl);
	LIST_INIT(&qcs->el_buf);
	qcs->start = TICK_ETERNITY;

	/* store transport layer stream descriptor in qcc tree */
	qcs->id = qcs->by_id.key = id;
	eb64_insert(&qcc->streams_by_id, &qcs->by_id);

	/* Different limits can be set by the peer for local and remote bidi streams. */
	if (quic_stream_is_bidi(id)) {
		qfctl_init(&qcs->tx.fc, quic_stream_is_local(qcc, id) ?
		                        qcc->rfctl.msd_bidi_r : qcc->rfctl.msd_bidi_l);
	}
	else if (quic_stream_is_local(qcc, id)) {
		qfctl_init(&qcs->tx.fc, qcc->rfctl.msd_uni_l);
	}
	else {
		qfctl_init(&qcs->tx.fc, 0);
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

	qcs->wait_event.tasklet = NULL;
	qcs->wait_event.events = 0;
	qcs->subs = NULL;

	qcs->err = 0;

	/* Reset all timers and start base one. */
	tot_time_reset(&qcs->timer.base);
	tot_time_reset(&qcs->timer.buf);
	tot_time_reset(&qcs->timer.fctl);
	tot_time_start(&qcs->timer.base);

	qcs->sd = sedesc_new();
	if (!qcs->sd)
		goto err;
	qcs->sd->se   = qcs;
	qcs->sd->conn = qcc->conn;
	se_fl_set(qcs->sd, SE_FL_T_MUX | SE_FL_ORPHAN | SE_FL_NOT_FIRST);
	se_expect_no_data(qcs->sd);

	if (!(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_QUIC_SND))
		se_fl_set(qcs->sd, SE_FL_MAY_FASTFWD_CONS);

	/* Allocate transport layer stream descriptor. Only needed for TX. */
	if (!quic_stream_is_uni(id) || !quic_stream_is_remote(qcc, id)) {
		struct quic_conn *qc = qcc->conn->handle.qc;
		qcs->stream = qc_stream_desc_new(id, type, qcs, qc);
		if (!qcs->stream) {
			TRACE_ERROR("qc_stream_desc alloc failure", QMUX_EV_QCS_NEW, qcc->conn, qcs);
			goto err;
		}

		qc_stream_desc_sub_send(qcs->stream, qmux_ctrl_send);
		qc_stream_desc_sub_room(qcs->stream, qmux_ctrl_room);
	}

	if (qcc->app_ops->attach && qcc->app_ops->attach(qcs, qcc->ctx)) {
		TRACE_ERROR("app proto failure", QMUX_EV_QCS_NEW, qcc->conn, qcs);
		goto err;
	}

 out:
	TRACE_STATE("created new QUIC stream", QMUX_EV_QCS_NEW, qcc->conn, qcs);
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
	BUG_ON(!qcc->nb_sc); /* Ensure sc count is always valid (ie >=0). */
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
	BUG_ON(!qcc->nb_hreq); /* Ensure http req count is always valid (ie >=0). */
	--qcc->nb_hreq;

	/* Reset qcc idle start for http-keep-alive timeout. Timeout will be
	 * refreshed after this on I/O handler.
	 */
	if (!qcc->nb_sc && !qcc->nb_hreq)
		qcc_reset_idle_start(qcc);
}

static inline int qcc_is_dead(const struct qcc *qcc)
{
	/* Maintain connection if stream endpoints are still active. */
	if (qcc->nb_sc)
		return 0;

	/* Connection considered dead if either :
	 * - remote error detected at transport level
	 * - error detected locally
	 * - MUX timeout expired
	 */
	if (qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL_DONE) ||
	    !qcc->task) {
		return 1;
	}

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

	/* Frontend timeout management
	 * - shutdown done -> timeout client-fin
	 * - detached streams with data left to send -> default timeout
	 * - stream waiting on incomplete request or no stream yet activated -> timeout http-request
	 * - idle after stream processing -> timeout http-keep-alive
	 *
	 * If proxy stop-stop in progress, immediate or spread close will be
	 * processed if shutdown already one or connection is idle.
	 */
	if (!conn_is_back(qcc->conn)) {
		if (qcc->nb_hreq && !(qcc->flags & QC_CF_APP_SHUT)) {
			TRACE_DEVEL("one or more requests still in progress", QMUX_EV_QCC_WAKE, qcc->conn);
			qcc->task->expire = tick_add_ifset(now_ms, qcc->timeout);
			task_queue(qcc->task);
			goto leave;
		}

		if ((!LIST_ISEMPTY(&qcc->opening_list) || unlikely(!qcc->largest_bidi_r)) &&
		    !(qcc->flags & QC_CF_APP_SHUT)) {
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
			if (qcc->flags & QC_CF_APP_SHUT) {
				TRACE_DEVEL("connection in closing", QMUX_EV_QCC_WAKE, qcc->conn);
				qcc->task->expire = tick_add_ifset(now_ms,
				                                   qcc->shut_timeout);
			}
			else {
				/* Use http-request timeout if keep-alive timeout not set */
				int timeout = tick_isset(px->timeout.httpka) ?
				              px->timeout.httpka : px->timeout.httpreq;
				TRACE_DEVEL("at least one request achieved but none currently in progress", QMUX_EV_QCC_WAKE, qcc->conn);
				qcc->task->expire = tick_add_ifset(qcc->idle_start, timeout);
			}

			/* If proxy soft-stop in progress and connection is
			 * inactive, close the connection immediately. If a
			 * close-spread-time is configured, randomly spread the
			 * timer over a closing window.
			 */
			if ((qcc->proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) &&
			    !(global.tune.options & GTUNE_DISABLE_ACTIVE_CLOSE)) {

				/* Wake timeout task immediately if window already expired. */
				int remaining_window = tick_isset(global.close_spread_end) ?
				  tick_remain(now_ms, global.close_spread_end) : 0;

				TRACE_DEVEL("proxy disabled, prepare connection soft-stop", QMUX_EV_QCC_WAKE, qcc->conn);
				if (remaining_window) {
					/* We don't need to reset the expire if it would
					 * already happen before the close window end.
					 */
					if (!tick_isset(qcc->task->expire) ||
					    tick_is_le(global.close_spread_end, qcc->task->expire)) {
						/* Set an expire value shorter than the current value
						 * because the close spread window end comes earlier.
						 */
						qcc->task->expire = tick_add(now_ms,
						                             statistical_prng_range(remaining_window));
					}
				}
				else {
					/* We are past the soft close window end, wake the timeout
					 * task up immediately.
					 */
					qcc->task->expire = tick_add(now_ms, 0);
					task_wakeup(qcc->task, TASK_WOKEN_TIMER);
				}
			}
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

/* Returns true if <qcs> can be purged. */
static int qcs_is_completed(struct qcs *qcs)
{
	/* A stream is completed if fully closed and stconn released, or simply
	 * detached and everything already sent.
	 */
	return (qcs->st == QC_SS_CLO && !qcs_sc(qcs)) ||
	       (qcs_is_close_local(qcs) && (qcs->flags & QC_SF_DETACH));
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

	if (qcs_is_completed(qcs)) {
		BUG_ON(LIST_INLIST(&qcs->el_send));
		TRACE_STATE("add stream in purg_list", QMUX_EV_QCS_RECV, qcs->qcc->conn, qcs);
		LIST_APPEND(&qcs->qcc->purg_list, &qcs->el_send);
	}
}

int qcs_is_close_local(struct qcs *qcs)
{
	return qcs->st == QC_SS_HLOC || qcs->st == QC_SS_CLO;
}

int qcs_is_close_remote(struct qcs *qcs)
{
	return qcs->st == QC_SS_HREM || qcs->st == QC_SS_CLO;
}

/* Allocate if needed buffer <ncbuf> for stream <qcs>.
 *
 * Returns the buffer instance or NULL on allocation failure.
 */
static struct ncbuf *qcs_get_ncbuf(struct qcs *qcs, struct ncbuf *ncbuf)
{
	struct buffer buf = BUF_NULL;

	if (ncb_is_null(ncbuf)) {
		if (!b_alloc(&buf, DB_MUX_RX))
			return NULL;

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
		TRACE_POINT(QMUX_EV_STRM_WAKE, qcs->qcc->conn, qcs);
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
		TRACE_POINT(QMUX_EV_STRM_WAKE, qcs->qcc->conn, qcs);
		tasklet_wakeup(qcs->subs->tasklet);
		qcs->subs->events &= ~SUB_RETRY_RECV;
		if (!qcs->subs->events)
			qcs->subs = NULL;
	}
}

void qcs_notify_send(struct qcs *qcs)
{
	if (qcs->subs && qcs->subs->events & SUB_RETRY_SEND) {
		TRACE_POINT(QMUX_EV_STRM_WAKE, qcs->qcc->conn, qcs);
		tasklet_wakeup(qcs->subs->tasklet);
		qcs->subs->events &= ~SUB_RETRY_SEND;
		if (!qcs->subs->events)
			qcs->subs = NULL;
	}
}

/* Returns total number of bytes not already sent to quic-conn layer. */
static uint64_t qcs_prep_bytes(const struct qcs *qcs)
{
	struct buffer *out = qc_stream_buf_get(qcs->stream);
	uint64_t diff, base_off;

	if (!out)
		return 0;

	/* if ack_offset < buf_offset, it points to an older buffer. */
	base_off = MAX(qcs->stream->buf_offset, qcs->stream->ack_offset);
	diff = qcs->tx.fc.off_real - base_off;
	return b_data(out) - diff;
}

/* Used as a callback for qc_stream_desc layer to notify about emission of a
 * STREAM frame of <data> length starting at <offset>.
 */
static void qmux_ctrl_send(struct qc_stream_desc *stream, uint64_t data, uint64_t offset)
{
	struct qcs *qcs = stream->ctx;
	struct qcc *qcc = qcs->qcc;
	uint64_t diff;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	/* Real off MUST always be the greatest offset sent. */
	BUG_ON(offset > qcs->tx.fc.off_real);

	/* Check if the STREAM frame has already been notified. An empty FIN
	 * frame must not be considered retransmitted.
	 */
	if (data && offset + data <= qcs->tx.fc.off_real) {
		TRACE_DEVEL("offset already notified", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		goto out;
	}

	/* An empty STREAM frame is only used to notify FIN. A retransmitted
	 * empty FIN cannot be notified as QCS will be unsubscribed first.
	 */
	BUG_ON(!data && !(qcs->flags & QC_SF_FIN_STREAM));

	qcs_idle_open(qcs);

	diff = offset + data - qcs->tx.fc.off_real;
	if (diff) {
		struct quic_fctl *fc_conn = &qcc->tx.fc;
		struct quic_fctl *fc_strm = &qcs->tx.fc;

		/* Ensure real offset never exceeds soft value. */
		BUG_ON(fc_conn->off_real + diff > fc_conn->off_soft);
		BUG_ON(fc_strm->off_real + diff > fc_strm->off_soft);

		/* increase offset sum on connection */
		if (qfctl_rinc(fc_conn, diff)) {
			TRACE_STATE("connection flow-control reached",
			            QMUX_EV_QCS_SEND, qcc->conn);
		}

		/* increase offset on stream */
		if (qfctl_rinc(fc_strm, diff)) {
			TRACE_STATE("stream flow-control reached",
			            QMUX_EV_QCS_SEND, qcc->conn, qcs);
		}
		/* Release buffer if everything sent and buf is full or stream is waiting for room. */
		if (!qcs_prep_bytes(qcs) &&
		    (b_full(&qcs->stream->buf->buf) || qcs->flags & QC_SF_BLK_MROOM)) {
			qc_stream_buf_release(qcs->stream);
			qcs->flags &= ~QC_SF_BLK_MROOM;
			qcs_notify_send(qcs);
		}

		/* Add measurement for send rate. This is done at the MUX layer
		 * to account only for STREAM frames without retransmission.
		 */
		increment_send_rate(diff, 0);
	}

	if (!qc_stream_buf_get(qcs->stream) || !qcs_prep_bytes(qcs)) {
		/* Remove stream from send_list if all was sent. */
		LIST_DEL_INIT(&qcs->el_send);
		TRACE_STATE("stream sent done", QMUX_EV_QCS_SEND, qcc->conn, qcs);

		if (qcs->flags & (QC_SF_FIN_STREAM|QC_SF_DETACH)) {
			/* Close stream locally. */
			qcs_close_local(qcs);

			if (qcs->flags & QC_SF_FIN_STREAM) {
				qcs->stream->flags |= QC_SD_FL_WAIT_FOR_FIN;
				/* Reset flag to not emit multiple FIN STREAM frames. */
				qcs->flags &= ~QC_SF_FIN_STREAM;
			}

			/* Unsubscribe from streamdesc when everything sent. */
			qc_stream_desc_sub_send(qcs->stream, NULL);

			if (qcs_is_completed(qcs)) {
				TRACE_STATE("add stream in purg_list", QMUX_EV_QCS_SEND, qcc->conn, qcs);
				LIST_APPEND(&qcc->purg_list, &qcs->el_send);
			}
		}
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
}

/* Returns true if <qcc> buffer window does not have room for a new buffer. */
static inline int qcc_bufwnd_full(const struct qcc *qcc)
{
	const struct quic_conn *qc = qcc->conn->handle.qc;
	return qcc->tx.buf_in_flight >= qc->path->cwnd;
}

static void qmux_ctrl_room(struct qc_stream_desc *stream, uint64_t room)
{
	/* Context is different for active and released streams. */
	struct qcc *qcc = !(stream->flags & QC_SD_FL_RELEASE) ?
	  ((struct qcs *)stream->ctx)->qcc : stream->ctx;
	qcc_notify_buf(qcc, room);
}

/* Report that one or several stream-desc buffers have been released for <qcc>
 * connection. <free_size> represent the sum of freed buffers sizes. May also
 * be used to notify about congestion window increase, in which case
 * <free_size> can be nul.
 */
void qcc_notify_buf(struct qcc *qcc, uint64_t free_size)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc->conn);

	/* Cannot have a negative buf_in_flight counter */
	BUG_ON(qcc->tx.buf_in_flight < free_size);
	qcc->tx.buf_in_flight -= free_size;

	if (qcc_bufwnd_full(qcc))
		return;

	if (qcc->flags & QC_CF_CONN_FULL) {
		TRACE_STATE("buf window now available", QMUX_EV_QCC_WAKE, qcc->conn);
		qcc->flags &= ~QC_CF_CONN_FULL;
	}

	/* TODO an optimization would be to only wake up a limited count of QCS
	 * instances based on <free_size>. But it may not work if a woken QCS
	 * is in error and does not try to allocate a buffer, leaving the
	 * unwoken QCS indefinitely in the buflist.
	 */
	while (!LIST_ISEMPTY(&qcc->buf_wait_list)) {
		qcs = LIST_ELEM(qcc->buf_wait_list.n, struct qcs *, el_buf);
		LIST_DEL_INIT(&qcs->el_buf);
		tot_time_stop(&qcs->timer.buf);
		qcs_notify_send(qcs);
	}

	TRACE_LEAVE(QMUX_EV_QCC_WAKE, qcc->conn);
}

/* A fatal error is detected locally for <qcc> connection. It should be closed
 * with a CONNECTION_CLOSE using <err> code. Set <app> to true to indicate that
 * the code must be considered as an application level error. This function
 * must not be called more than once by connection.
 */
void qcc_set_error(struct qcc *qcc, int err, int app)
{
	/* This must not be called multiple times per connection. */
	BUG_ON(qcc->flags & QC_CF_ERRL);

	TRACE_STATE("connection on error", QMUX_EV_QCC_ERR, qcc->conn);

	qcc->flags |= QC_CF_ERRL;
	qcc->err = app ? quic_err_app(err) : quic_err_transport(err);

	/* TODO
	 * Ensure qcc_io_send() will be conducted to convert QC_CF_ERRL in
	 * QC_CF_ERRL_DONE with CONNECTION_CLOSE frame emission. This may be
	 * unnecessary if we are currently in the MUX tasklet context, but it
	 * is too tedious too not forget a wakeup outside of this function for
	 * the moment.
	 */
	tasklet_wakeup(qcc->wait_event.tasklet);
}

/* Increment glitch counter for <qcc> connection by <inc> steps. If configured
 * threshold reached, close the connection with an error code.
 */
int _qcc_report_glitch(struct qcc *qcc, int inc)
{
	const int max = global.tune.quic_frontend_glitches_threshold;

	qcc->glitches += inc;
	if (max && qcc->glitches >= max && !(qcc->flags & QC_CF_ERRL)) {
		if (qcc->app_ops->report_susp) {
			qcc->app_ops->report_susp(qcc->ctx);
			qcc_set_error(qcc, qcc->err.code, 1);
		}
		else {
			qcc_set_error(qcc, QC_ERR_INTERNAL_ERROR, 0);
		}
		return 1;
	}

	return 0;
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
		qcc_set_error(qcc, QC_ERR_INTERNAL_ERROR, 0);
		TRACE_DEVEL("leaving on error", QMUX_EV_QCS_NEW, qcc->conn);
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

	/* Function reserved to remote stream IDs. */
	BUG_ON(quic_stream_is_local(qcc, id));

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
		qcc_set_error(qcc, QC_ERR_STREAM_LIMIT_ERROR, 0);
		goto err;
	}

	/* Only stream ID not already opened can be used. */
	BUG_ON(id < *largest);

	/* MAX_STREAMS emission must not allowed too big stream ID. */
	BUG_ON(*largest > QUIC_VARINT_8_BYTE_MAX);

	while (id >= *largest) {
		const char *str = *largest < id ? "initializing intermediary remote stream" :
		                                  "initializing remote stream";

		qcs = qcs_new(qcc, *largest, type);
		if (!qcs) {
			TRACE_ERROR("stream fallocation failure", QMUX_EV_QCS_NEW, qcc->conn);
			qcc_set_error(qcc, QC_ERR_INTERNAL_ERROR, 0);
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

/* Mark <qcs> as reserved for metadata transfer. As such, future txbuf
 * allocation won't be accounted against connection limit.
 */
void qcs_send_metadata(struct qcs *qcs)
{
	/* Reserved for stream with Tx capability. */
	BUG_ON(!qcs->stream);
	/* Cannot use if some data already transferred for this stream. */
	BUG_ON(qcs->stream->ack_offset || !eb_is_empty(&qcs->stream->buf_tree));

	qcs->flags |= QC_SF_TXBUB_OOB;
	qc_stream_desc_sub_room(qcs->stream, NULL);
}

/* Instantiate a streamdesc instance for <qcs> stream. This is necessary to
 * transfer data after a new request reception. <buf> can be used to forward
 * the first received request data. <fin> must be set if the whole request is
 * already received.
 *
 * Note that if <qcs> is already fully closed, no streamdesc is instantiated.
 * This is useful if a RESET_STREAM was already emitted in response to a
 * STOP_SENDING.
 *
 * Returns 0 on success else a negative error code. If stream is already fully
 * closed and nothing is performed, it is considered as a success case.
 */
int qcs_attach_sc(struct qcs *qcs, struct buffer *buf, char fin)
{
	struct qcc *qcc = qcs->qcc;
	struct session *sess = qcc->conn->owner;

	TRACE_ENTER(QMUX_EV_STRM_RECV, qcc->conn, qcs);

	if (qcs->st == QC_SS_CLO) {
		TRACE_STATE("skip attach on already closed stream", QMUX_EV_STRM_RECV, qcc->conn, qcs);
		goto out;
	}

	/* TODO duplicated from mux_h2 */
	sess->t_idle = ns_to_ms(now_ns - sess->accept_ts) - sess->t_handshake;

	if (!sc_new_from_endp(qcs->sd, sess, buf)) {
		TRACE_DEVEL("leaving on error", QMUX_EV_STRM_RECV, qcc->conn, qcs);
		return -1;
	}

	/* QC_SF_HREQ_RECV must be set once for a stream. Else, nb_hreq counter
	 * will be incorrect for the connection.
	 */
	BUG_ON_HOT(qcs->flags & QC_SF_HREQ_RECV);
	qcs->flags |= QC_SF_HREQ_RECV;
	++qcc->nb_sc;
	++qcc->nb_hreq;

	/* TODO duplicated from mux_h2 */
	sess->accept_date = date;
	sess->accept_ts   = now_ns;
	sess->t_handshake = 0;
	sess->t_idle = 0;

	/* A stream must have been registered for HTTP wait before attaching
	 * it to sedesc. See <qcs_wait_http_req> for more info.
	 */
	BUG_ON_HOT(!LIST_INLIST(&qcs->el_opening));
	LIST_DEL_INIT(&qcs->el_opening);

	/* rcv_buf may be skipped if request is wholly received on attach.
	 * Ensure that similar flags are set for FIN both on rcv_buf and here.
	 */
	if (fin) {
		TRACE_STATE("report end-of-input", QMUX_EV_STRM_RECV, qcc->conn, qcs);
		se_fl_set(qcs->sd, SE_FL_EOI);
		se_expect_data(qcs->sd);
	}

	/* A QCS can be already locally closed before stream layer
	 * instantiation. This notably happens if STOP_SENDING was the first
	 * frame received for this instance. In this case, an error is
	 * immediately to the stream layer to prevent transmission.
	 *
	 * TODO it could be better to not instantiate at all the stream layer.
	 * However, extra care is required to ensure QCS instance is released.
	 */
	if (unlikely(qcs_is_close_local(qcs) || (qcs->flags & QC_SF_TO_RESET))) {
		TRACE_STATE("report early error", QMUX_EV_STRM_RECV, qcc->conn, qcs);
		se_fl_set_error(qcs->sd);
	}

 out:
	TRACE_LEAVE(QMUX_EV_STRM_RECV, qcc->conn, qcs);
	return 0;
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
		qcc_set_error(qcc, QC_ERR_STREAM_STATE_ERROR, 0);
		goto err;
	}

	if (!send_only && quic_stream_is_uni(id) && quic_stream_is_local(qcc, id)) {
		TRACE_ERROR("send-only stream not allowed", QMUX_EV_QCC_RECV|QMUX_EV_QCC_NQCS|QMUX_EV_PROTO_ERR, qcc->conn, NULL, &id);
		qcc_set_error(qcc, QC_ERR_STREAM_STATE_ERROR, 0);
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
		qcc_set_error(qcc, QC_ERR_STREAM_STATE_ERROR, 0);
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
		qcs_free_ncbuf(qcs, buf);

	qcs->rx.offset += bytes;
	/* Not necessary to emit a MAX_STREAM_DATA if all data received. */
	if (qcs->flags & QC_SF_SIZE_KNOWN)
		goto conn_fctl;

	if (qcs->rx.msd - qcs->rx.offset < qcs->rx.msd_init / 2) {
		TRACE_DATA("increase stream credit via MAX_STREAM_DATA", QMUX_EV_QCS_RECV, qcc->conn, qcs);
		frm = qc_frm_alloc(QUIC_FT_MAX_STREAM_DATA);
		if (!frm) {
			qcc_set_error(qcc, QC_ERR_INTERNAL_ERROR, 0);
			return;
		}

		qcs->rx.msd = qcs->rx.offset + qcs->rx.msd_init;

		frm->max_stream_data.id = qcs->id;
		frm->max_stream_data.max_stream_data = qcs->rx.msd;

		LIST_APPEND(&qcc->lfctl.frms, &frm->list);
		tasklet_wakeup(qcc->wait_event.tasklet);
	}

 conn_fctl:
	qcc->lfctl.offsets_consume += bytes;
	if (qcc->lfctl.md - qcc->lfctl.offsets_consume < qcc->lfctl.md_init / 2) {
		TRACE_DATA("increase conn credit via MAX_DATA", QMUX_EV_QCS_RECV, qcc->conn, qcs);
		frm = qc_frm_alloc(QUIC_FT_MAX_DATA);
		if (!frm) {
			qcc_set_error(qcc, QC_ERR_INTERNAL_ERROR, 0);
			return;
		}

		qcc->lfctl.md = qcc->lfctl.offsets_consume + qcc->lfctl.md_init;

		frm->max_data.max_data = qcc->lfctl.md;

		LIST_APPEND(&qcs->qcc->lfctl.frms, &frm->list);
		tasklet_wakeup(qcc->wait_event.tasklet);
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
	int prev_glitches = qcc->glitches;

	TRACE_ENTER(QMUX_EV_QCS_RECV, qcc->conn, qcs);

	b = qcs_b_dup(&qcs->rx.ncbuf);

	/* Signal FIN to application if STREAM FIN received with all data. */
	if (qcs_is_close_remote(qcs))
		fin = 1;

	if (!(qcs->flags & QC_SF_READ_ABORTED)) {
		ret = qcc->app_ops->rcv_buf(qcs, &b, fin);

		if (qcc->glitches != prev_glitches)
			session_add_glitch_ctr(qcc->conn->owner, qcc->glitches - prev_glitches);

		if (ret < 0) {
			TRACE_ERROR("decoding error", QMUX_EV_QCS_RECV, qcc->conn, qcs);
			goto err;
		}

		if (qcs->flags & QC_SF_TO_RESET) {
			if (qcs_sc(qcs) && !se_fl_test(qcs->sd, SE_FL_ERROR|SE_FL_ERR_PENDING)) {
				se_fl_set_error(qcs->sd);
				qcs_alert(qcs);
			}
		}
	}
	else {
		TRACE_DATA("ignore read on stream", QMUX_EV_QCS_RECV, qcc->conn, qcs);
		ret = b_data(&b);
	}

	if (ret)
		qcs_consume(qcs, ret);
	if (ret || (!b_data(&b) && fin))
		qcs_notify_recv(qcs);

	TRACE_LEAVE(QMUX_EV_QCS_RECV, qcc->conn, qcs);
	return 0;

 err:
	TRACE_LEAVE(QMUX_EV_QCS_RECV, qcc->conn, qcs);
	return 1;
}

/* Allocate if needed and retrieve <qcs> stream buffer for data reception.
 *
 * Returns buffer pointer. May be NULL on allocation failure.
 */
struct buffer *qcc_get_stream_rxbuf(struct qcs *qcs)
{
	return b_alloc(&qcs->rx.app_buf, DB_MUX_RX);
}

/* Allocate if needed and retrieve <qcs> stream buffer for data emission.
 *
 * <err> is an output argument which is useful to differentiate the failure
 * cause when the buffer cannot be allocated. It is set to 0 if the connection
 * buffer window is full. For fatal errors, its value is non-zero.
 *
 * Streams reserved for application protocol metadata transfer are not subject
 * to the buffer limit per connection. Hence, for them only a memory error
 * can prevent a buffer allocation.
 *
 * Returns buffer pointer. May be NULL on allocation failure, in which case
 * <err> will refer to the cause.
 */
struct buffer *qcc_get_stream_txbuf(struct qcs *qcs, int *err, int small)
{
	struct qcc *qcc = qcs->qcc;
	struct buffer *out = qc_stream_buf_get(qcs->stream);

	/* Stream must not try to reallocate a buffer if currently waiting for one. */
	BUG_ON(LIST_INLIST(&qcs->el_buf));

	*err = 0;

	if (!out) {
		if (likely(!(qcs->flags & QC_SF_TXBUB_OOB))) {
			if ((qcc->flags & QC_CF_CONN_FULL)) {
				LIST_APPEND(&qcc->buf_wait_list, &qcs->el_buf);
				tot_time_start(&qcs->timer.buf);
				goto out;
			}

			if (qcc_bufwnd_full(qcc)) {
				TRACE_STATE("no more room", QMUX_EV_QCS_SEND, qcc->conn, qcs);
				LIST_APPEND(&qcc->buf_wait_list, &qcs->el_buf);
				tot_time_start(&qcs->timer.buf);
				qcc->flags |= QC_CF_CONN_FULL;
				goto out;
			}
		}

		out = qc_stream_buf_alloc(qcs->stream, qcs->tx.fc.off_real, small);
		if (!out) {
			TRACE_ERROR("stream desc alloc failure", QMUX_EV_QCS_SEND, qcc->conn, qcs);
			*err = 1;
			goto out;
		}

		if (likely(!(qcs->flags & QC_SF_TXBUB_OOB)))
			qcc->tx.buf_in_flight += b_size(out);
	}

 out:
	return out;
}

/* Reallocate <qcs> stream buffer to convert a small buffer to a bigger one.
 * Contrary to standard allocation, this function will never stop due to a full
 * buffer window. The smaller buffer is released first which guarantee that the
 * buffer window has room left.
 *
 * Returns buffer pointer or NULL on allocation failure.
 */
struct buffer *qcc_realloc_stream_txbuf(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;
	struct buffer *out = qc_stream_buf_get(qcs->stream);

	/* Stream must not try to reallocate a buffer if currently waiting for one. */
	BUG_ON(LIST_INLIST(&qcs->el_buf));

	if (likely(!(qcs->flags & QC_SF_TXBUB_OOB))) {
		/* Reduce buffer window. As such there is always some space
		 * left for a new buffer allocation.
		 */
		BUG_ON(qcc->tx.buf_in_flight < b_size(out));
		qcc->tx.buf_in_flight -= b_size(out);
	}

	out = qc_stream_buf_realloc(qcs->stream);
	if (!out) {
		TRACE_ERROR("buffer alloc failure", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		goto out;
	}

	if (likely(!(qcs->flags & QC_SF_TXBUB_OOB)))
		qcc->tx.buf_in_flight += b_size(out);

 out:
	return out && b_size(out) ? out : NULL;
}

/* Try to realign <out> buffer for <qcs> stream. This is done only if there is
 * no data waiting for ACK.
 *
 * Returns 0 if realign was performed else non-zero.
 */
int qcc_realign_stream_txbuf(const struct qcs *qcs, struct buffer *out)
{
	if (qcs_prep_bytes(qcs) == b_data(out)) {
		b_slow_realign(out, trash.area, b_data(out));
		return 0;
	}

	return 1;
}

/* Release the current <qcs> Tx buffer. This is useful if space left is not
 * enough anymore. A new instance can then be allocated to continue sending.
 *
 * This operation fails if there is not yet sent bytes in the buffer. In this
 * case, stream layer should interrupt sending until further notification.
 *
 * Returns 0 if buffer is released and a new one can be allocated or non-zero
 * if there is still remaining data.
 */
int qcc_release_stream_txbuf(struct qcs *qcs)
{
	const uint64_t bytes = qcs_prep_bytes(qcs);

	/* Cannot release buffer if prepared data is not fully sent. */
	if (bytes) {
		qcs->flags |= QC_SF_BLK_MROOM;
		return 1;
	}

	qc_stream_buf_release(qcs->stream);
	return 0;
}

/* Returns true if stream layer can proceed to emission via <qcs>. */
int qcc_stream_can_send(const struct qcs *qcs)
{
	return !(qcs->flags & QC_SF_BLK_MROOM) && !LIST_INLIST(&qcs->el_buf);
}

/* Wakes up every streams of <qcc> which are currently waiting for sending but
 * are blocked on connection flow control.
 */
static void qcc_notify_fctl(struct qcc *qcc)
{
	struct qcs *qcs;

	while (!LIST_ISEMPTY(&qcc->fctl_list)) {
		qcs = LIST_ELEM(qcc->fctl_list.n, struct qcs *, el_fctl);
		LIST_DEL_INIT(&qcs->el_fctl);
		tot_time_stop(&qcs->timer.fctl);
		qcs_notify_send(qcs);
	}
}

/* Free <qcc> STREAM frames in Tx list. */
static void qcc_clear_frms(struct qcc *qcc)
{
	TRACE_STATE("resetting STREAM frames list", QMUX_EV_QCC_SEND, qcc->conn);
	while (!LIST_ISEMPTY(&qcc->tx.frms)) {
		struct quic_frame *frm = LIST_ELEM(qcc->tx.frms.n, struct quic_frame *, list);
		qc_frm_free(qcc->conn->handle.qc, &frm);
	}
}

/* Prepare for the emission of RESET_STREAM on <qcs> with error code <err>. */
void qcc_reset_stream(struct qcs *qcs, int err)
{
	struct qcc *qcc = qcs->qcc;
	const uint64_t diff = qcs_prep_bytes(qcs);

	if ((qcs->flags & QC_SF_TO_RESET) || qcs_is_close_local(qcs))
		return;

	/* TODO if QCS waiting for buffer, it could be removed from
	 * <qcc.buf_wait_list> if sending is closed now.
	 */

	TRACE_STATE("reset stream", QMUX_EV_QCS_END, qcc->conn, qcs);
	qcs->flags |= QC_SF_TO_RESET;
	qcs->err = err;

	if (diff) {
		const int soft_blocked = qfctl_sblocked(&qcc->tx.fc);

		/* Soft offset cannot be inferior to real one. */
		BUG_ON(qcc->tx.fc.off_soft - diff < qcc->tx.fc.off_real);

		/* Subtract to conn flow control data amount prepared on stream not yet sent. */
		qcc->tx.fc.off_soft -= diff;
		if (soft_blocked && !qfctl_sblocked(&qcc->tx.fc))
			qcc_notify_fctl(qcc);

		/* Reset QCS soft off to prevent BUG_ON() on qcs_destroy(). */
		qcs->tx.fc.off_soft = qcs->tx.fc.off_real;
	}

	/* Report send error to stream-endpoint layer. */
	if (qcs_sc(qcs)) {
		se_fl_set_error(qcs->sd);
		qcs_alert(qcs);
	}

	qcc_send_stream(qcs, 1, 0);
	tasklet_wakeup(qcc->wait_event.tasklet);
}

/* Register <qcs> stream for emission of STREAM, STOP_SENDING or RESET_STREAM.
 * Set <urg> to 1 if stream content should be treated in priority compared to
 * other streams. For STREAM emission, <count> must contains the size of the
 * frame payload. This is used for flow control accounting.
 */
void qcc_send_stream(struct qcs *qcs, int urg, int count)
{
	struct qcc *qcc = qcs->qcc;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	/* Cannot send if already closed. */
	BUG_ON(qcs_is_close_local(qcs));

	qcc_clear_frms(qcc);

	if (urg) {
		/* qcc_emit_rs_ss() relies on resetted/aborted streams in send_list front. */
		BUG_ON(!(qcs->flags & (QC_SF_TO_RESET|QC_SF_TO_STOP_SENDING|QC_SF_TXBUB_OOB)));

		LIST_DEL_INIT(&qcs->el_send);
		LIST_INSERT(&qcc->send_list, &qcs->el_send);
	}
	else {
		if (!LIST_INLIST(&qcs->el_send))
			LIST_APPEND(&qcs->qcc->send_list, &qcs->el_send);
	}

	if (count) {
		qfctl_sinc(&qcc->tx.fc, count);
		qfctl_sinc(&qcs->tx.fc, count);
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

	qcc_send_stream(qcs, 1, 0);
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

	if (app_ops->init && !app_ops->init(qcc)) {
		TRACE_ERROR("app ops init error", QMUX_EV_QCC_NEW, qcc->conn);
		goto err;
	}

	TRACE_PROTO("application layer initialized", QMUX_EV_QCC_NEW, qcc->conn);
	qcc->app_ops = app_ops;

	/* RFC 9114 7.2.4.2. Initialization
	 *
	 * Endpoints MUST NOT require any data to be
	 * received from the peer prior to sending the SETTINGS frame;
	 * settings MUST be sent as soon as the transport is ready to
	 * send data.
	 */
	if (qcc->app_ops->finalize) {
		if (qcc->app_ops->finalize(qcc->ctx)) {
			TRACE_ERROR("app ops finalize error", QMUX_EV_QCC_NEW, qcc->conn);
			goto err;
		}
		tasklet_wakeup(qcc->wait_event.tasklet);
	}

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

	if (qcc->flags & QC_CF_ERRL) {
		TRACE_DATA("connection on error", QMUX_EV_QCC_RECV, qcc->conn);
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
		qcc_set_error(qcc, QC_ERR_FINAL_SIZE_ERROR, 0);
		goto err;
	}

	if (qcs_is_close_remote(qcs)) {
		TRACE_DATA("skipping STREAM for remotely closed", QMUX_EV_QCC_RECV, qcc->conn);
		goto out;
	}

	if (offset + len < qcs->rx.offset ||
	    (offset + len == qcs->rx.offset && (!fin || (qcs->flags & QC_SF_SIZE_KNOWN)))) {
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
			qcc_set_error(qcc, QC_ERR_FLOW_CONTROL_ERROR, 0);
			goto err;
		}
	}

	if (!qcs_get_ncbuf(qcs, &qcs->rx.ncbuf) || ncb_is_null(&qcs->rx.ncbuf)) {
		TRACE_ERROR("receive ncbuf alloc failure", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		qcc_set_error(qcc, QC_ERR_INTERNAL_ERROR, 0);
		goto err;
	}

	TRACE_DATA("newly received offset", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
	if (offset < qcs->rx.offset) {
		size_t diff = qcs->rx.offset - offset;

		len -= diff;
		data += diff;
		offset = qcs->rx.offset;
	}

	if (len) {
		ret = ncb_add(&qcs->rx.ncbuf, offset - qcs->rx.offset, data, len, NCB_ADD_COMPARE);
		switch (ret) {
		case NCB_RET_OK:
			break;

		case NCB_RET_DATA_REJ:
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
			qcc_set_error(qcc, QC_ERR_PROTOCOL_VIOLATION, 0);
			return 1;

		case NCB_RET_GAP_SIZE:
			TRACE_DATA("cannot bufferize frame due to gap size limit", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV,
			           qcc->conn, qcs);
			return 1;
		}
	}

	if (fin)
		qcs->flags |= QC_SF_SIZE_KNOWN;

	if (qcs->flags & QC_SF_SIZE_KNOWN &&
	    qcs->rx.offset_max == qcs->rx.offset + ncb_data(&qcs->rx.ncbuf, 0)) {
		qcs_close_remote(qcs);
	}

	if ((ncb_data(&qcs->rx.ncbuf, 0) && !(qcs->flags & QC_SF_DEM_FULL)) || fin) {
		qcc_decode_qcs(qcc, qcs);
		LIST_DEL_INIT(&qcs->el_recv);
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
	const int blocked_soft = qfctl_sblocked(&qcc->tx.fc);
	int unblock_soft = 0, unblock_real = 0;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	TRACE_PROTO("receiving MAX_DATA", QMUX_EV_QCC_RECV, qcc->conn);
	if (qfctl_set_max(&qcc->tx.fc, max, &unblock_soft, &unblock_real)) {
		TRACE_DATA("increase remote max-data", QMUX_EV_QCC_RECV, qcc->conn);

		if (unblock_real)
			tasklet_wakeup(qcc->wait_event.tasklet);

		if (unblock_soft)
			qcc_notify_fctl(qcc);

		/* Refresh frms list only if this would result in newer data :
		 * a. flow-control is not real blocked
		 * b. soft off was equal or greater than previous limit
		 */
		if (!qfctl_rblocked(&qcc->tx.fc) && blocked_soft)
			qcc_clear_frms(qcc);
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

	if (qcc->flags & QC_CF_ERRL) {
		TRACE_DATA("connection on error", QMUX_EV_QCC_RECV, qcc->conn);
		goto err;
	}

	/* RFC 9000 19.10. MAX_STREAM_DATA Frames
	 *
	 * Receiving a MAX_STREAM_DATA frame for a locally
	 * initiated stream that has not yet been created MUST be treated as a
	 * connection error of type STREAM_STATE_ERROR.  An endpoint that
	 * receives a MAX_STREAM_DATA frame for a receive-only stream MUST
	 * terminate the connection with error STREAM_STATE_ERROR.
	 */
	if (qcc_get_qcs(qcc, id, 0, 1, &qcs))
		goto err;

	if (qcs) {
		const int blocked_soft = qfctl_sblocked(&qcs->tx.fc);
		int unblock_soft = 0, unblock_real = 0;

		TRACE_PROTO("receiving MAX_STREAM_DATA", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		if (qfctl_set_max(&qcs->tx.fc, max, &unblock_soft, &unblock_real)) {
			TRACE_DATA("increase remote max-stream-data", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
			if (unblock_real) {
				/* TODO optim: only wakeup IO-CB if stream has data to sent. */
				tasklet_wakeup(qcc->wait_event.tasklet);
			}

			if (unblock_soft) {
				tot_time_stop(&qcs->timer.fctl);
				qcs_notify_send(qcs);
			}

			/* Same refresh condition as qcc_recv_max_data(). */
			if (!qfctl_rblocked(&qcs->tx.fc) && blocked_soft)
				qcc_clear_frms(qcc);
		}
	}

	if (qcc_may_expire(qcc) && !qcc->nb_hreq)
		qcc_refresh_timeout(qcc);

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;

 err:
	TRACE_DEVEL("leaving on error", QMUX_EV_QCC_RECV, qcc->conn);
	return 1;
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
	int prev_glitches = qcc->glitches;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	if (qcc->flags & QC_CF_ERRL) {
		TRACE_DATA("connection on error", QMUX_EV_QCC_RECV, qcc->conn);
		goto err;
	}

	/* RFC 9000 19.4. RESET_STREAM Frames
	 *
	 * An endpoint that receives a RESET_STREAM frame for a send-only stream
	 * MUST terminate the connection with error STREAM_STATE_ERROR.
	 */
	if (qcc_get_qcs(qcc, id, 1, 0, &qcs)) {
		TRACE_ERROR("RESET_STREAM for send-only stream received", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		goto err;
	}

	/* RFC 9000 3.2. Receiving Stream States
	 *
	 * A RESET_STREAM signal might be suppressed or withheld
	 * if stream data is completely received and is buffered to be read by
	 * the application. If the RESET_STREAM is suppressed, the receiving
	 * part of the stream remains in "Data Recvd".
	 */
	if (!qcs || qcs_is_close_remote(qcs))
		goto out;

	TRACE_PROTO("receiving RESET_STREAM", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
	qcs_idle_open(qcs);

	/* Ensure stream closure is not forbidden by application protocol. */
	if (qcc->app_ops->close) {
		if (qcc->app_ops->close(qcs, QCC_APP_OPS_CLOSE_SIDE_RD)) {
			TRACE_ERROR("closure rejected by app layer", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
			goto out;
		}
	}

	if (qcs->rx.offset_max > final_size ||
	    ((qcs->flags & QC_SF_SIZE_KNOWN) && qcs->rx.offset_max != final_size)) {
		TRACE_ERROR("final size error on RESET_STREAM", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
		qcc_set_error(qcc, QC_ERR_FINAL_SIZE_ERROR, 0);
		goto err;
	}

	/* RFC 9000 3.2. Receiving Stream States
	 *
	 * An
	 * implementation MAY interrupt delivery of stream data, discard any
	 * data that was not consumed, and signal the receipt of the
	 * RESET_STREAM.
	 */
	qcs->flags |= QC_SF_SIZE_KNOWN|QC_SF_RECV_RESET;
	qcs_close_remote(qcs);
	qcs_free_ncbuf(qcs, &qcs->rx.ncbuf);

 out:
	if (qcc->glitches != prev_glitches)
		session_add_glitch_ctr(qcc->conn->owner, qcc->glitches - prev_glitches);

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
	int prev_glitches = qcc->glitches;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	if (qcc->flags & QC_CF_ERRL) {
		TRACE_DATA("connection on error", QMUX_EV_QCC_RECV, qcc->conn);
		goto err;
	}

	/* RFC 9000 19.5. STOP_SENDING Frames
	 *
	 * Receiving a STOP_SENDING frame for a
	 * locally initiated stream that has not yet been created MUST be
	 * treated as a connection error of type STREAM_STATE_ERROR.  An
	 * endpoint that receives a STOP_SENDING frame for a receive-only stream
	 * MUST terminate the connection with error STREAM_STATE_ERROR.
	 */
	if (qcc_get_qcs(qcc, id, 0, 1, &qcs))
		goto err;

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

	if (qcc->app_ops->close) {
		if (qcc->app_ops->close(qcs, QCC_APP_OPS_CLOSE_SIDE_WR)) {
			TRACE_ERROR("closure rejected by app layer", QMUX_EV_QCC_RECV|QMUX_EV_QCS_RECV, qcc->conn, qcs);
			goto out;
		}
	}

	/* Manually set EOS if FIN already reached as futures RESET_STREAM will be ignored in this case. */
	if (qcs_sc(qcs) && se_fl_test(qcs->sd, SE_FL_EOI)) {
		se_fl_set(qcs->sd, SE_FL_EOS);
		qcs_alert(qcs);
	}

	/* If not defined yet, set abort info for the sedesc */
	if (!qcs->sd->abort_info.info) {
		qcs->sd->abort_info.info = (SE_ABRT_SRC_MUX_QUIC << SE_ABRT_SRC_SHIFT);
		qcs->sd->abort_info.code = err;
	}

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
	if (qcc->glitches != prev_glitches)
		session_add_glitch_ctr(qcc->conn->owner, qcc->glitches - prev_glitches);

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;

 err:
	TRACE_DEVEL("leaving on error", QMUX_EV_QCC_RECV, qcc->conn);
	return 1;
}

#define QUIC_MAX_STREAMS_MAX_ID (1ULL<<60)

/* Signal the closing of remote stream with id <id>. Flow-control for new
 * streams may be allocated for the peer if needed.
 */
static int qcc_release_remote_stream(struct qcc *qcc, uint64_t id)
{
	struct quic_frame *frm;

	TRACE_ENTER(QMUX_EV_QCS_END, qcc->conn);

	if (quic_stream_is_bidi(id)) {
		/* RFC 9000 4.6. Controlling Concurrency
		 *
		 * If a max_streams transport parameter or a MAX_STREAMS frame is
		 * received with a value greater than 260, this would allow a maximum
		 * stream ID that cannot be expressed as a variable-length integer; see
		 * Section 16. If either is received, the connection MUST be closed
		 * immediately with a connection error of type TRANSPORT_PARAMETER_ERROR
		 * if the offending value was received in a transport parameter or of
		 * type FRAME_ENCODING_ERROR if it was received in a frame; see Section
		 * 10.2.
		 */
		if (qcc->lfctl.ms_bidi == QUIC_MAX_STREAMS_MAX_ID) {
			TRACE_DATA("maximum streams value reached", QMUX_EV_QCC_SEND, qcc->conn);
			goto out;
		}

		++qcc->lfctl.cl_bidi_r;
		/* MAX_STREAMS needed if closed streams value more than twice
		 * the initial window or reaching the stream ID limit.
		 */
		if (qcc->lfctl.cl_bidi_r > qcc->lfctl.ms_bidi_init / 2 ||
		    qcc->lfctl.cl_bidi_r + qcc->lfctl.ms_bidi == QUIC_MAX_STREAMS_MAX_ID) {
			TRACE_DATA("increase max stream limit with MAX_STREAMS_BIDI", QMUX_EV_QCC_SEND, qcc->conn);
			frm = qc_frm_alloc(QUIC_FT_MAX_STREAMS_BIDI);
			if (!frm) {
				qcc_set_error(qcc, QC_ERR_INTERNAL_ERROR, 0);
				goto err;
			}

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

 out:
	TRACE_LEAVE(QMUX_EV_QCS_END, qcc->conn);
	return 0;

 err:
	TRACE_DEVEL("leaving on error", QMUX_EV_QCS_END, qcc->conn);
	return 1;
}

/* detaches the QUIC stream from its QCC and releases it to the QCS pool. */
static void qcs_destroy(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;
	struct connection *conn = qcc->conn;
	const uint64_t id = qcs->id;

	TRACE_ENTER(QMUX_EV_QCS_END, conn, qcs);

	if (!(qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL))) {
		/* MUST not removed a stream with sending prepared data left. This is
		 * to ensure consistency on connection flow-control calculation.
		 */
		BUG_ON(qcs->tx.fc.off_soft != qcs->tx.fc.off_real);

		if (quic_stream_is_remote(qcc, id))
			qcc_release_remote_stream(qcc, id);
	}

	qcs_free(qcs);

	TRACE_LEAVE(QMUX_EV_QCS_END, conn);
}

/* Prepare a STREAM frame for <qcs> instance using <out> as payload. The frame
 * is appended in <frm_list>. Set <fin> if this is supposed to be the last
 * stream frame. If <out> is NULL an empty STREAM frame is built : this may be
 * useful if FIN needs to be sent without any data left. Frame length will be
 * truncated if greater than <fc_conn_wnd>. This allows to prepare several
 * frames in a loop while respecting connection flow control window.
 *
 * Returns the payload length of the STREAM frame or a negative error code.
 */
static int qcs_build_stream_frm(struct qcs *qcs, struct buffer *out, char fin,
                                struct list *frm_list, uint64_t window_conn)
{
	struct qcc *qcc = qcs->qcc;
	struct quic_frame *frm;
	const uint64_t window_stream = qfctl_rcap(&qcs->tx.fc);
	const uint64_t bytes = qcs_prep_bytes(qcs);
	uint64_t total;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	/* This must only be called if there is data left, or at least a standalone FIN. */
	BUG_ON((!out || !b_data(out)) && !fin);

	total = bytes;

	/* do not exceed stream flow control limit */
	if (total > window_stream) {
		TRACE_DATA("do not exceed stream flow control", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		total = window_stream;
	}

	/* do not exceed connection flow control limit */
	if (total > window_conn) {
		TRACE_DATA("do not exceed conn flow control", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		total = window_conn;
	}

	/* Reset FIN if bytes to send is capped by flow control. */
	if (total < bytes)
		fin = 0;

	if (!total && !fin) {
		/* No need to send anything if total is NULL and no FIN to signal. */
		TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
		return 0;
	}

	TRACE_PROTO("sending STREAM frame", QMUX_EV_QCS_SEND, qcc->conn, qcs);
	frm = qc_frm_alloc(QUIC_FT_STREAM_8);
	if (!frm) {
		TRACE_ERROR("frame alloc failure", QMUX_EV_QCS_SEND, qcc->conn, qcs);
		goto err;
	}

	frm->stream.stream = qcs->stream;
	frm->stream.id = qcs->id;
	frm->stream.offset = 0;
	frm->stream.dup = 0;

	if (total) {
		frm->stream.buf = out;
		frm->stream.data = (unsigned char *)b_peek(out, b_data(out) - bytes);
	}
	else {
		/* Empty STREAM frame. */
		frm->stream.buf = NULL;
		frm->stream.data = NULL;
	}

	/* FIN is positioned only when the buffer has been totally emptied. */
	if (fin)
		frm->type |= QUIC_STREAM_FRAME_TYPE_FIN_BIT;

	if (qcs->tx.fc.off_real) {
		frm->type |= QUIC_STREAM_FRAME_TYPE_OFF_BIT;
		frm->stream.offset = qcs->tx.fc.off_real;
	}

	/* Always set length bit as we do not know if there is remaining frames
	 * in the final packet after this STREAM.
	 */
	frm->type |= QUIC_STREAM_FRAME_TYPE_LEN_BIT;
	frm->stream.len = total;

	LIST_APPEND(frm_list, &frm->list);

 out:
	{
		struct qcs_build_stream_trace_arg arg = {
			.len = frm->stream.len, .fin = fin,
			.offset = frm->stream.offset,
		};
		TRACE_LEAVE(QMUX_EV_QCS_SEND|QMUX_EV_QCS_BUILD_STRM,
		            qcc->conn, qcs, &arg);
	}

	return total;

 err:
	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
	return -1;
}

/* Returns true if subscribe set, false otherwise. */
static int qcc_subscribe_send(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;

	/* Do not subscribe if lower layer in error. */
	if (conn->flags & CO_FL_ERROR)
		return 0;

	if (qcc->wait_event.events & SUB_RETRY_SEND)
		return 1;

	TRACE_DEVEL("subscribe for send", QMUX_EV_QCC_SEND, qcc->conn);
	conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_SEND, &qcc->wait_event);
	return 1;
}

/* Wrapper for send on transport layer. Send a list of frames <frms> for the
 * connection <qcc>.
 *
 * Returns 0 if all data sent with success. On fatal error, a negative error
 * code is returned. A positive 1 is used if emission should be paced.
 */
static int qcc_send_frames(struct qcc *qcc, struct list *frms, int stream)
{
	enum quic_tx_err ret;
	struct quic_pacer *pacer = NULL;

	TRACE_ENTER(QMUX_EV_QCC_SEND, qcc->conn);

	if (LIST_ISEMPTY(frms)) {
		TRACE_DEVEL("leaving on no frame to send", QMUX_EV_QCC_SEND, qcc->conn);
		return -1;
	}

	if (stream && qcc_is_pacing_active(qcc->conn))
		pacer = &qcc->tx.pacer;

	ret = qc_send_mux(qcc->conn->handle.qc, frms, pacer);
	if (ret == QUIC_TX_ERR_FATAL) {
		TRACE_DEVEL("error on sending", QMUX_EV_QCC_SEND, qcc->conn);
		qcc_subscribe_send(qcc);
		goto err;
	}

	/* If there is frames left at this stage, transport layer is blocked.
	 * Subscribe on it to retry later.
	 */
	if (!LIST_ISEMPTY(frms) && ret != QUIC_TX_ERR_PACING) {
		TRACE_DEVEL("remaining frames to send", QMUX_EV_QCC_SEND, qcc->conn);
		qcc_subscribe_send(qcc);
		goto err;
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return ret == QUIC_TX_ERR_PACING ? 1 : 0;

 err:
	TRACE_DEVEL("leaving on error", QMUX_EV_QCC_SEND, qcc->conn);
	return -1;
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

	frm = qc_frm_alloc(QUIC_FT_RESET_STREAM);
	if (!frm) {
		TRACE_LEAVE(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
	}

	frm->reset_stream.id = qcs->id;
	frm->reset_stream.app_error_code = qcs->err;
	frm->reset_stream.final_size = qcs->tx.fc.off_real;

	LIST_APPEND(&frms, &frm->list);
	if (qcc_send_frames(qcs->qcc, &frms, 0)) {
		if (!LIST_ISEMPTY(&frms))
			qc_frm_free(qcs->qcc->conn->handle.qc, &frm);
		TRACE_DEVEL("cannot send RESET_STREAM", QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
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

	frm = qc_frm_alloc(QUIC_FT_STOP_SENDING);
	if (!frm) {
		TRACE_LEAVE(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
	}

	frm->stop_sending.id = qcs->id;
	frm->stop_sending.app_error_code = qcs->err;

	LIST_APPEND(&frms, &frm->list);
	if (qcc_send_frames(qcs->qcc, &frms, 0)) {
		if (!LIST_ISEMPTY(&frms))
			qc_frm_free(qcc->conn->handle.qc, &frm);
		TRACE_DEVEL("cannot send STOP_SENDING", QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
		return 1;
	}

 done:
	qcs->flags &= ~QC_SF_TO_STOP_SENDING;

	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcs->qcc->conn, qcs);
	return 0;
}

/* Used internally by qcc_io_send function. Proceed to send for <qcs>. A STREAM
 * frame is generated pointing to QCS stream descriptor content and inserted in
 * <frms> list. Frame length will be truncated if greater than <window_conn>.
 * This allows to prepare several frames in a loop while respecting connection
 * flow control window.
 *
 * Returns the payload length of the STREAM frame or a negative error code.
 */
static int qcs_send(struct qcs *qcs, struct list *frms, uint64_t window_conn)
{
	struct qcc *qcc = qcs->qcc;
	struct buffer *out = qc_stream_buf_get(qcs->stream);
	int flen = 0;
	const char fin = qcs->flags & QC_SF_FIN_STREAM;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	/* Cannot send STREAM on remote unidirectional streams. */
	BUG_ON(quic_stream_is_uni(qcs->id) && quic_stream_is_remote(qcc, qcs->id));

	/* This function must not be called if there is nothing to send. */
	BUG_ON(!fin && !qcs_prep_bytes(qcs));

	/* Skip STREAM frame allocation if already subscribed for send.
	 * Happens on sendto transient error or network congestion.
	 */
	if (qcc->wait_event.events & SUB_RETRY_SEND) {
		TRACE_DEVEL("already subscribed for sending",
		            QMUX_EV_QCS_SEND, qcc->conn, qcs);
		goto err;
	}

	/* Build a new STREAM frame with <out> buffer. */
	flen = qcs_build_stream_frm(qcs, out, fin, frms, window_conn);
	if (flen < 0)
		goto err;

 out:
	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
	return flen;

 err:
	TRACE_DEVEL("leaving on error", QMUX_EV_QCS_SEND, qcc->conn, qcs);
	return -1;
}

/* Send RESET_STREAM/STOP_SENDING for streams in <qcc> send_list if requested.
 * Each frame is encoded and emitted separately for now. If a frame cannot be
 * sent, send_list looping is interrupted.
 *
 * Returns 0 on success else non-zero.
 */
static int qcc_emit_rs_ss(struct qcc *qcc)
{
	struct qcs *qcs, *qcs_tmp;

	TRACE_ENTER(QMUX_EV_QCC_END, qcc->conn);

	list_for_each_entry_safe(qcs, qcs_tmp, &qcc->send_list, el_send) {
		/* Stream must not be present in send_list if it has nothing to send. */
		BUG_ON(!(qcs->flags & (QC_SF_FIN_STREAM|QC_SF_TO_STOP_SENDING|QC_SF_TO_RESET)) &&
		       (!qcs->stream || !qcs_prep_bytes(qcs)));

		/* Interrupt looping for the first stream where no RS nor SS is
		 * necessary and is not use for "metadata" transfer. These
		 * streams are always in front of the send_list.
		 */
		if (!(qcs->flags & (QC_SF_TO_STOP_SENDING|QC_SF_TO_RESET|QC_SF_TXBUB_OOB)))
			break;

		TRACE_DATA("prepare for RS/SS transfer", QMUX_EV_QCC_SEND, qcc->conn, qcs);

		/* Each RS and SS frame is sent individually. Necessary to
		 * ensure it has been emitted as there is no transport callback
		 * for now.
		 *
		 * TODO multiplex frames to optimize sending. However, it may
		 * not be advisable to mix different streams in the same dgram
		 * to avoid interdependency in case of loss.
		 */

		if (qcs->flags & QC_SF_TO_STOP_SENDING) {
			if (qcs_send_stop_sending(qcs))
				goto err;

			/* Remove stream from send_list if only SS was necessary. */
			if (!(qcs->flags & (QC_SF_FIN_STREAM|QC_SF_TO_RESET)) &&
			    (!qcs->stream || !qcs_prep_bytes(qcs))) {
				LIST_DEL_INIT(&qcs->el_send);
				continue;
			}
		}

		if (qcs->flags & QC_SF_TO_RESET) {
			if (qcs_send_reset(qcs))
				goto err;

			/* RFC 9000 3.3. Permitted Frame Types
			 *
			 * A sender MUST NOT send
			 * a STREAM or STREAM_DATA_BLOCKED frame for a stream in the
			 * "Reset Sent" state or any terminal state -- that is, after
			 * sending a RESET_STREAM frame.
			 */
			LIST_DEL_INIT(&qcs->el_send);
			if (qcs_is_completed(qcs)) {
				TRACE_STATE("add stream in purg_list", QMUX_EV_QCC_SEND|QMUX_EV_QCS_SEND, qcc->conn, qcs);
				LIST_APPEND(&qcc->purg_list, &qcs->el_send);
			}
			continue;
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return 0;

 err:
	TRACE_DEVEL("leaving on error", QMUX_EV_QCC_SEND, qcc->conn);
	return 1;
}

/* Encode STREAM frames into <qcc> tx frms for streams registered into
 * send_list. On each error, related stream is removed from send_list and
 * inserted into <qcs_failed> list.
 *
 * This functions also serves to emit RESET_STREAM and STOP_SENDING frames. In
 * this case, frame is emitted immediately without using <qcc> tx frms. If an
 * error occured during this step, this is considered as fatal. Tx frms is
 * cleared and 0 is returned.
 *
 * Returns the sum of encoded payload STREAM frames length. Note that 0 can be
 * returned either if no frame was built or only empty payload frames were
 * encoded.
 */
static int qcc_build_frms(struct qcc *qcc, struct list *qcs_failed)
{
	struct list *frms = &qcc->tx.frms;
	struct qcs *qcs, *qcs_tmp, *first_qcs = NULL;
	uint64_t window_conn = qfctl_rcap(&qcc->tx.fc);
	int ret = 0, total = 0;

	TRACE_ENTER(QMUX_EV_QCC_END, qcc->conn);

	/* Frames list must first be cleared via qcc_clear_frms(). */
	BUG_ON(!LIST_ISEMPTY(&qcc->tx.frms));

	list_for_each_entry_safe(qcs, qcs_tmp, &qcc->send_list, el_send) {
		/* Check if all QCS were processed. */
		if (qcs == first_qcs)
			break;

		TRACE_DATA("prepare for data transfer", QMUX_EV_QCC_SEND, qcc->conn, qcs);

		/* Streams with RS/SS must be handled via qcc_emit_rs_ss(). */
		BUG_ON(qcs->flags & (QC_SF_TO_STOP_SENDING|QC_SF_TO_RESET));
		/* Stream must not be present in send_list if it has nothing to send. */
		BUG_ON(!(qcs->flags & QC_SF_FIN_STREAM) && (!qcs->stream || !qcs_prep_bytes(qcs)));

		/* Total sent bytes must not exceed connection window. */
		BUG_ON(total > window_conn);

		if (!qfctl_rblocked(&qcc->tx.fc) &&
		    !qfctl_rblocked(&qcs->tx.fc) && window_conn > total) {
			if ((ret = qcs_send(qcs, frms, window_conn - total)) < 0) {
				/* Temporarily remove QCS from send-list. */
				LIST_DEL_INIT(&qcs->el_send);
				LIST_APPEND(qcs_failed, &qcs->el_send);
				continue;
			}

			total += ret;
			if (ret) {
				/* Move QCS with some bytes transferred at the
				 * end of send-list for next iterations.
				 */
				LIST_DEL_INIT(&qcs->el_send);
				LIST_APPEND(&qcc->send_list, &qcs->el_send);
				/* Remember first moved QCS as checkpoint to interrupt loop */
				if (!first_qcs)
					first_qcs = qcs;
			}
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return total;
}

/* Schedule <qcc> after emission was interrupted on pacing. */
static void qcc_wakeup_pacing(struct qcc *qcc)
{
	/* Sleep to be able to reemit at least a single packet */
	const int inter = qcc->tx.pacer.cc->algo->pacing_inter(qcc->tx.pacer.cc);
	/* Convert nano to milliseconds rounded up, with 1ms as minimal value. */
	const int expire = MAX((inter + 999999) / 1000000, 1);
	qcc->pacing_task->expire = tick_add_ifset(now_ms, MS_TO_TICKS(expire));
	++qcc->tx.paced_sent_ctr;
}

/* Proceed to sending. Loop through all available streams for the <qcc>
 * instance and try to send as much as possible.
 *
 * Returns the total of bytes sent to the transport layer.
 */
static int qcc_io_send(struct qcc *qcc)
{
	struct list *frms = &qcc->tx.frms;
	/* Temporary list for QCS on error. */
	struct list qcs_failed = LIST_HEAD_INIT(qcs_failed);
	struct qcs *qcs, *qcs_tmp;
	uint64_t window_conn = qfctl_rcap(&qcc->tx.fc);
	int ret = 0, total = 0, resent;

	TRACE_ENTER(QMUX_EV_QCC_SEND, qcc->conn);

	if (qcc_is_pacing_active(qcc->conn)) {
		/* Always reset pacing_task timer to prevent unnecessary execution. */
		qcc->pacing_task->expire = TICK_ETERNITY;
	}

	/* TODO if socket in transient error, sending should be temporarily
	 * disabled for all frames. However, checking for send subscription is
	 * not valid as this may be caused by a congestion error which only
	 * apply for STREAM frames.
	 */

	/* Check for transport error. */
	if (qcc->flags & QC_CF_ERR_CONN || qcc->conn->flags & CO_FL_ERROR) {
		TRACE_DEVEL("connection on error", QMUX_EV_QCC_SEND, qcc->conn);
		goto out;
	}

	/* Check for locally detected connection error. */
	if (qcc->flags & QC_CF_ERRL) {
		/* Prepare a CONNECTION_CLOSE if not already done. */
		if (!(qcc->flags & QC_CF_ERRL_DONE)) {
			TRACE_DATA("report a connection error", QMUX_EV_QCC_SEND|QMUX_EV_QCC_ERR, qcc->conn);
			quic_set_connection_close(qcc->conn->handle.qc, qcc->err);
			qcc->flags |= QC_CF_ERRL_DONE;
		}
		goto out;
	}

	if (qcc->conn->flags & CO_FL_SOCK_WR_SH) {
		qcc->conn->flags |= CO_FL_ERROR;
		TRACE_DEVEL("connection on error", QMUX_EV_QCC_SEND, qcc->conn);
		goto out;
	}

	if (!LIST_ISEMPTY(&qcc->lfctl.frms)) {
		if (qcc_send_frames(qcc, &qcc->lfctl.frms, 0)) {
			TRACE_DEVEL("flow-control frames rejected by transport, aborting send", QMUX_EV_QCC_SEND, qcc->conn);
			goto out;
		}
	}

	if (qcc_emit_rs_ss(qcc)) {
		TRACE_DEVEL("emission interrupted on STOP_SENDING/RESET_STREAM send error", QMUX_EV_QCC_SEND, qcc->conn);
		goto out;
	}

	/* Encode new STREAM frames if list has been previously cleared. */
	if (LIST_ISEMPTY(frms) && !LIST_ISEMPTY(&qcc->send_list)) {
		total = qcc_build_frms(qcc, &qcs_failed);
		if (LIST_ISEMPTY(frms))
			goto out;
	}

	if (!LIST_ISEMPTY(frms) && qcc_is_pacing_active(qcc->conn)) {
		if (!quic_pacing_reload(&qcc->tx.pacer)) {
			qcc_wakeup_pacing(qcc);
			total = 0;
			goto out;
		}
	}

	/* Retry sending until no frame to send, data rejected or connection
	 * flow-control limit reached.
	 */
	while ((ret = qcc_send_frames(qcc, frms, 1)) == 0 && !qfctl_rblocked(&qcc->tx.fc)) {
		window_conn = qfctl_rcap(&qcc->tx.fc);
		resent = 0;

		/* Reloop over <qcc.send_list>. Useful for streams which have
		 * fulfilled their qc_stream_desc buf and have now release it.
		 */
		list_for_each_entry_safe(qcs, qcs_tmp, &qcc->send_list, el_send) {
			/* Only streams blocked on flow-control or waiting on a
			 * new qc_stream_desc should be present in send_list as
			 * long as transport layer can handle all data.
			 */
			BUG_ON(qcs->stream->buf && !qfctl_rblocked(&qcs->tx.fc));

			/* Total sent bytes must not exceed connection window. */
			BUG_ON(resent > window_conn);

			if (!qfctl_rblocked(&qcs->tx.fc) && window_conn > resent) {
				if ((ret = qcs_send(qcs, frms, window_conn - resent)) < 0) {
					LIST_DEL_INIT(&qcs->el_send);
					LIST_APPEND(&qcs_failed, &qcs->el_send);
					continue;
				}

				total += ret;
				resent += ret;
			}
		}
	}

	if (ret == 1) {
		/* qcc_send_frames cannot return 1 if pacing not used. */
		BUG_ON(!qcc_is_pacing_active(qcc->conn));
		qcc_wakeup_pacing(qcc);
	}

 out:
	/* Re-insert on-error QCS at the end of the send-list. */
	if (!LIST_ISEMPTY(&qcs_failed)) {
		list_for_each_entry_safe(qcs, qcs_tmp, &qcs_failed, el_send) {
			LIST_DEL_INIT(&qcs->el_send);
			LIST_APPEND(&qcc->send_list, &qcs->el_send);
		}

		if (!qfctl_rblocked(&qcc->tx.fc))
			tasklet_wakeup(qcc->wait_event.tasklet);
	}

	if (qcc->conn->flags & CO_FL_ERROR && !(qcc->flags & QC_CF_ERR_CONN)) {
		TRACE_ERROR("error reported by transport layer",
		            QMUX_EV_QCC_SEND, qcc->conn);
		qcc->flags |= QC_CF_ERR_CONN;
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return total;
}

/* Detects QUIC handshake completion. Any SE_FL_WAIT_FOR_HS streams are woken
 * up if wait-for-handshake is active.
 */
static void qcc_wait_for_hs(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;
	struct quic_conn *qc = conn->handle.qc;
	struct eb64_node *node;
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	if (qc->state >= QUIC_HS_ST_COMPLETE) {
		if (conn->flags & CO_FL_EARLY_SSL_HS) {
			TRACE_STATE("mark early data as ready", QMUX_EV_QCC_WAKE, conn);
			conn->flags &= ~CO_FL_EARLY_SSL_HS;
		}

		/* wake-up any stream blocked on early data transfer */
		node = eb64_first(&qcc->streams_by_id);
		while (node) {
			qcs = container_of(node, struct qcs, by_id);
			if (se_fl_test(qcs->sd, SE_FL_WAIT_FOR_HS))
				qcs_notify_recv(qcs);
			node = eb64_next(node);
		}

		qcc->flags &= ~QC_CF_WAIT_HS;
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
}

/* Proceed on receiving. Loop on streams subscribed in recv_list and performed
 * STREAM frames decoding upon them.
 *
 * Returns 0 on success else non-zero.
 */
static int qcc_io_recv(struct qcc *qcc)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	if (qcc->flags & QC_CF_ERRL) {
		TRACE_DATA("connection on error", QMUX_EV_QCC_RECV, qcc->conn);
		TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
		return 0;
	}

	if ((qcc->flags & QC_CF_WAIT_HS) && !(qcc->wait_event.events & SUB_RETRY_RECV))
		qcc_wait_for_hs(qcc);

	while (!LIST_ISEMPTY(&qcc->recv_list)) {
		qcs = LIST_ELEM(qcc->recv_list.n, struct qcs *, el_recv);
		/* No need to add an uni local stream in recv_list. */
		BUG_ON(quic_stream_is_uni(qcs->id) && quic_stream_is_local(qcc, qcs->id));
		qcc_decode_qcs(qcc, qcs);
		LIST_DEL_INIT(&qcs->el_recv);
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return 0;
}


/* Release all streams which have their transfer operation achieved. */
static void qcc_purge_streams(struct qcc *qcc)
{
	struct qcs *qcs;

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc->conn);

	while (!LIST_ISEMPTY(&qcc->purg_list)) {
		qcs = LIST_ELEM(qcc->purg_list.n, struct qcs *, el_send);

		TRACE_STATE("purging stream", QMUX_EV_QCC_WAKE, qcs->qcc->conn, qcs);
		BUG_ON_HOT(!qcs_is_completed(qcs));
		qcs_destroy(qcs);
	}

	TRACE_LEAVE(QMUX_EV_QCC_WAKE, qcc->conn);
}

/* Execute application layer shutdown. If this operation is not defined, a
 * CONNECTION_CLOSE will be prepared as a fallback. This function is protected
 * against multiple invocation with the flag QC_CF_APP_SHUT.
 */
static void qcc_shutdown(struct qcc *qcc)
{
	TRACE_ENTER(QMUX_EV_QCC_END, qcc->conn);

	if (qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL)) {
		TRACE_DATA("connection on error", QMUX_EV_QCC_END, qcc->conn);
		goto out;
	}

	if (qcc->flags & QC_CF_APP_SHUT)
		goto out;

	TRACE_STATE("perform graceful shutdown", QMUX_EV_QCC_END, qcc->conn);
	if (qcc->app_ops && qcc->app_ops->shutdown) {
		qcc->app_ops->shutdown(qcc->ctx);
		qcc_io_send(qcc);
	}
	else {
		qcc->err = quic_err_transport(QC_ERR_NO_ERROR);
	}

	/* Register "no error" code at transport layer. Do not use
	 * quic_set_connection_close() as retransmission may be performed to
	 * finalized transfers. Do not overwrite quic-conn existing code if
	 * already set.
	 *
	 * TODO implement a wrapper function for this in quic-conn module
	 */
	if (!(qcc->conn->handle.qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE))
		qcc->conn->handle.qc->err = qcc->err;

 out:
	qcc->flags |= QC_CF_APP_SHUT;
	TRACE_LEAVE(QMUX_EV_QCC_END, qcc->conn);
}

/* Loop through all qcs from <qcc>. Report error on stream endpoint if
 * connection on error and wake them.
 */
static int qcc_wake_some_streams(struct qcc *qcc)
{
	struct qcs *qcs;
	struct eb64_node *node;

	TRACE_POINT(QMUX_EV_QCC_WAKE, qcc->conn);

	for (node = eb64_first(&qcc->streams_by_id); node;
	     node = eb64_next(node)) {
		qcs = eb64_entry(node, struct qcs, by_id);

		if (!qcs_sc(qcs))
			continue;

		if (qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL)) {
			TRACE_POINT(QMUX_EV_QCC_WAKE, qcc->conn, qcs);
			se_fl_set_error(qcs->sd);
			qcs_alert(qcs);
		}
	}

	return 0;
}

/* Conduct operations which should be made for <qcc> connection after
 * input/output. Most notably, closed streams are purged which may leave the
 * connection has ready to be released.
 *
 * Returns 1 if <qcc> must be released else 0.
 */
static int qcc_io_process(struct qcc *qcc)
{
	if (!LIST_ISEMPTY(&qcc->purg_list))
		qcc_purge_streams(qcc);

	/* Check if a soft-stop is in progress.
	 *
	 * TODO this is relevant for frontend connections only.
	 */
	if (unlikely(qcc->proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
		int close = 1;

		/* If using listener socket, soft-stop is not supported. The
		 * connection must be closed immediately.
		 */
		if (!qc_test_fd(qcc->conn->handle.qc)) {
			TRACE_DEVEL("proxy disabled with listener socket, closing connection", QMUX_EV_QCC_WAKE, qcc->conn);
			qcc->conn->flags |= (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH);
			qcc_io_send(qcc);
			goto out;
		}

		TRACE_DEVEL("proxy disabled, prepare connection soft-stop", QMUX_EV_QCC_WAKE, qcc->conn);

		/* If a close-spread-time option is set, we want to avoid
		 * closing all the active HTTP3 connections at once so we add a
		 * random factor that will spread the closing.
		 */
		if (tick_isset(global.close_spread_end)) {
			int remaining_window = tick_remain(now_ms, global.close_spread_end);
			if (remaining_window) {
				/* This should increase the closing rate the
				 * further along the window we are. */
				close = (remaining_window <= statistical_prng_range(global.close_spread_time));
			}
		}
		else if (global.tune.options & GTUNE_DISABLE_ACTIVE_CLOSE) {
			close = 0; /* let the client close his connection himself */
		}

		if (close)
			qcc_shutdown(qcc);
	}

	/* Report error if set on stream endpoint layer. */
	if (qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL))
		qcc_wake_some_streams(qcc);

 out:
	if (qcc_is_dead(qcc))
		return 1;

	return 0;
}

/* Free all resources allocated for <qcc> connection. */
static void qcc_release(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;
	struct eb64_node *node;
	struct quic_conn *qc;

	TRACE_ENTER(QMUX_EV_QCC_END, conn);

	task_destroy(qcc->pacing_task);

	if (qcc->task) {
		task_destroy(qcc->task);
		qcc->task = NULL;
	}

	/* liberate remaining qcs instances */
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = eb64_entry(node, struct qcs, by_id);
		node = eb64_next(node);
		qcs_free(qcs);
	}

	/* unsubscribe from all remaining qc_stream_desc */
	if (conn) {
		qc = conn->handle.qc;
		node = eb64_first(&qc->streams_by_id);
		while (node) {
			struct qc_stream_desc *stream = eb64_entry(node, struct qc_stream_desc, by_id);
			qc_stream_desc_sub_room(stream, NULL);
			node = eb64_next(node);
		}
	}

	tasklet_free(qcc->wait_event.tasklet);
	if (conn && qcc->wait_event.events) {
		conn->xprt->unsubscribe(conn, conn->xprt_ctx,
		                        qcc->wait_event.events,
		                        &qcc->wait_event);
	}

	while (!LIST_ISEMPTY(&qcc->lfctl.frms)) {
		struct quic_frame *frm = LIST_ELEM(qcc->lfctl.frms.n, struct quic_frame *, list);
		qc_frm_free(qcc->conn->handle.qc, &frm);
	}

	qcc_clear_frms(qcc);

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

struct task *qcc_io_cb(struct task *t, void *ctx, unsigned int status)
{
	struct qcc *qcc = ctx;

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc->conn);

	if (!(qcc->wait_event.events & SUB_RETRY_SEND))
		qcc_io_send(qcc);

	qcc_io_recv(qcc);

	if (qcc_io_process(qcc)) {
		TRACE_STATE("releasing dead connection", QMUX_EV_QCC_WAKE, qcc->conn);
		goto release;
	}

	qcc_refresh_timeout(qcc);

	/* Trigger pacing task is emission should be retried after some delay. */
	if (qcc_is_pacing_active(qcc->conn)) {
		if (tick_isset(qcc->pacing_task->expire))
			task_queue(qcc->pacing_task);
	}

	TRACE_LEAVE(QMUX_EV_QCC_WAKE, qcc->conn);

	return NULL;

 release:
	qcc_shutdown(qcc);
	qcc_release(qcc);

	TRACE_LEAVE(QMUX_EV_QCC_WAKE);

	return NULL;
}

static struct task *qcc_pacing_task(struct task *t, void *ctx, unsigned int state)
{
	struct qcc *qcc = ctx;
	int expired = tick_is_expired(t->expire, now_ms);

	TRACE_ENTER(QMUX_EV_QCC_WAKE, qcc->conn);

	if (!expired) {
		if (!tick_isset(t->expire))
			TRACE_DEVEL("cancelled pacing task", QMUX_EV_QCC_WAKE, qcc->conn);
		goto requeue;
	}

	/* Reschedule I/O immediately. */
	tasklet_wakeup_after(NULL, qcc->wait_event.tasklet);

 requeue:
	TRACE_LEAVE(QMUX_EV_QCC_WAKE, qcc->conn);
	return t;
}

static struct task *qcc_timeout_task(struct task *t, void *ctx, unsigned int state)
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

	/* Mark timeout as triggered by setting task to NULL. */
	qcc->task = NULL;

	/* TODO depending on the timeout condition, different shutdown mode
	 * should be used. For http keep-alive or disabled proxy, a graceful
	 * shutdown should occurs. For all other cases, an immediate close
	 * seems legitimate.
	 */
	if (qcc_is_dead(qcc)) {
		TRACE_STATE("releasing dead connection", QMUX_EV_QCC_WAKE, qcc->conn);
		qcc_shutdown(qcc);
		qcc_release(qcc);
	}

 out:
	TRACE_LEAVE(QMUX_EV_QCC_WAKE);
	return NULL;

 requeue:
	TRACE_LEAVE(QMUX_EV_QCC_WAKE);
	return t;
}

/* Minimal initialization of <qcc> members to use qcc_release() safely. */
static void _qcc_init(struct qcc *qcc)
{
	qcc->conn = NULL;
	qcc->pacing_task = NULL;
	qcc->task = NULL;
	qcc->wait_event.tasklet = NULL;
	qcc->app_ops = NULL;
	qcc->streams_by_id = EB_ROOT_UNIQUE;
	LIST_INIT(&qcc->lfctl.frms);
	LIST_INIT(&qcc->tx.frms);
}

static int qmux_init(struct connection *conn, struct proxy *prx,
                     struct session *sess, struct buffer *input)
{
	struct qcc *qcc;
	struct quic_transport_params *lparams, *rparams;

	TRACE_ENTER(QMUX_EV_QCC_NEW);

	qcc = pool_alloc(pool_head_qcc);
	if (!qcc) {
		TRACE_ERROR("alloc failure", QMUX_EV_QCC_NEW);
		goto err;
	}

	_qcc_init(qcc);
	conn->ctx = qcc;
	qcc->nb_hreq = qcc->nb_sc = 0;
	qcc->flags = 0;
	qcc->glitches = 0;
	qcc->err = quic_err_transport(QC_ERR_NO_ERROR);

	/* Server parameters, params used for RX flow control. */
	lparams = &conn->handle.qc->rx.params;

	qcc->lfctl.ms_bidi = qcc->lfctl.ms_bidi_init = lparams->initial_max_streams_bidi;
	qcc->lfctl.ms_uni = lparams->initial_max_streams_uni;
	qcc->lfctl.msd_bidi_l = lparams->initial_max_stream_data_bidi_local;
	qcc->lfctl.msd_bidi_r = lparams->initial_max_stream_data_bidi_remote;
	qcc->lfctl.msd_uni_r = lparams->initial_max_stream_data_uni;
	qcc->lfctl.cl_bidi_r = 0;

	qcc->lfctl.md = qcc->lfctl.md_init = lparams->initial_max_data;
	qcc->lfctl.offsets_recv = qcc->lfctl.offsets_consume = 0;

	rparams = &conn->handle.qc->tx.params;
	qfctl_init(&qcc->tx.fc, rparams->initial_max_data);
	qcc->rfctl.msd_bidi_l = rparams->initial_max_stream_data_bidi_local;
	qcc->rfctl.msd_bidi_r = rparams->initial_max_stream_data_bidi_remote;
	qcc->rfctl.msd_uni_l = rparams->initial_max_stream_data_uni;

	qcc->tx.buf_in_flight = 0;

	if (qcc_is_pacing_active(conn)) {
		quic_pacing_init(&qcc->tx.pacer, &conn->handle.qc->path->cc);
		qcc->tx.paced_sent_ctr = 0;

		/* Initialize pacing_task. */
		qcc->pacing_task = task_new_here();
		if (!qcc->pacing_task) {
			TRACE_ERROR("pacing task alloc failure", QMUX_EV_QCC_NEW);
			goto err;
		}
		qcc->pacing_task->process = qcc_pacing_task;
		qcc->pacing_task->context = qcc;
		qcc->pacing_task->expire = TICK_ETERNITY;
		qcc->pacing_task->state |= TASK_F_WANTS_TIME;
	}

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
		goto err;
	}

	LIST_INIT(&qcc->recv_list);
	LIST_INIT(&qcc->send_list);
	LIST_INIT(&qcc->fctl_list);
	LIST_INIT(&qcc->buf_wait_list);
	LIST_INIT(&qcc->purg_list);

	qcc->wait_event.tasklet->process = qcc_io_cb;
	qcc->wait_event.tasklet->context = qcc;
	qcc->wait_event.tasklet->state  |= TASK_F_WANTS_TIME;
	qcc->wait_event.events = 0;

	qcc->proxy = prx;
	/* haproxy timeouts */
	if (conn_is_back(conn)) {
		qcc->timeout = prx->timeout.server;
		qcc->shut_timeout = tick_isset(prx->timeout.serverfin) ?
		                    prx->timeout.serverfin : prx->timeout.server;
	}
	else {
		qcc->timeout = prx->timeout.client;
		qcc->shut_timeout = tick_isset(prx->timeout.clientfin) ?
		                    prx->timeout.clientfin : prx->timeout.client;
	}

	/* Always allocate task even if timeout is unset. In MUX code, if task
	 * is NULL, it indicates that a timeout has stroke earlier.
	 */
	qcc->task = task_new_here();
	if (!qcc->task) {
		TRACE_ERROR("timeout task alloc failure", QMUX_EV_QCC_NEW);
		goto err;
	}
	qcc->task->process = qcc_timeout_task;
	qcc->task->context = qcc;
	qcc->task->expire = tick_add_ifset(now_ms, qcc->timeout);

	qcc_reset_idle_start(qcc);
	LIST_INIT(&qcc->opening_list);

	HA_ATOMIC_STORE(&conn->handle.qc->qcc, qcc);

	/* Register conn as app_ops may use it. */
	qcc->conn = conn;

	if (qcc_install_app_ops(qcc, conn->handle.qc->app_ops)) {
		TRACE_PROTO("Cannot install app layer", QMUX_EV_QCC_NEW|QMUX_EV_QCC_ERR, conn);
		goto err;
	}

	if (qcc->app_ops == &h3_ops)
		proxy_inc_fe_cum_sess_ver_ctr(sess->listener, prx, 3);

	/* Register conn for idle front closing. This is done once everything is allocated. */
	if (!conn_is_back(conn))
		LIST_APPEND(&mux_stopping_data[tid].list, &conn->stopping_list);

	/* init read cycle */
	tasklet_wakeup(qcc->wait_event.tasklet);

	/* MUX is initialized before QUIC handshake completion if early data
	 * received. Flag connection to delay stream processing if
	 * wait-for-handshake is active.
	 */
	if (conn->handle.qc->state < QUIC_HS_ST_COMPLETE) {
		if (!(conn->flags & CO_FL_EARLY_SSL_HS)) {
			TRACE_STATE("flag connection with early data", QMUX_EV_QCC_WAKE, conn);
			conn->flags |= CO_FL_EARLY_SSL_HS;
			/* subscribe for handshake completion */
			conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV,
			                      &qcc->wait_event);
			qcc->flags |= QC_CF_WAIT_HS;
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_NEW, conn);
	return 0;

 err:
	/* Prepare CONNECTION_CLOSE, using INTERNAL_ERROR as fallback code if unset. */
	if (!(conn->handle.qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE)) {
		struct quic_err err = qcc && qcc->err.code ?
		  qcc->err : quic_err_transport(QC_ERR_INTERNAL_ERROR);
		quic_set_connection_close(conn->handle.qc, err);
	}

	if (qcc) {
		/* In case of MUX init failure, session will ensure connection is freed. */
		qcc->conn = NULL;
		qcc_release(qcc);
	}

	TRACE_DEVEL("leaving on error", QMUX_EV_QCC_NEW, conn);
	return -1;
}

static void qmux_destroy(void *ctx)
{
	struct qcc *qcc = ctx;

	TRACE_ENTER(QMUX_EV_QCC_END, qcc->conn);
	qcc_release(qcc);
	TRACE_LEAVE(QMUX_EV_QCC_END);
}

static void qmux_strm_detach(struct sedesc *sd)
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

	if (!qcs_is_close_local(qcs) &&
	    !(qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL))) {
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
	else {
		TRACE_DEVEL("refreshing connection's timeout", QMUX_EV_STRM_END, qcc->conn);
		qcc_refresh_timeout(qcc);
	}

	TRACE_LEAVE(QMUX_EV_STRM_END, qcc->conn);
	return;

 release:
	qcc_shutdown(qcc);
	qcc_release(qcc);
	TRACE_LEAVE(QMUX_EV_STRM_END);
	return;
}

/* Called from the upper layer, to receive data */
static size_t qmux_strm_rcv_buf(struct stconn *sc, struct buffer *buf,
                                size_t count, int flags)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	struct qcc *qcc = qcs->qcc;
	size_t ret = 0;
	char fin = 0;

	TRACE_ENTER(QMUX_EV_STRM_RECV, qcc->conn, qcs);

	ret = qcs_http_rcv_buf(qcs, buf, count, &fin);

	if (b_data(&qcs->rx.app_buf)) {
		se_fl_set(qcs->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
	}
	else {
		se_fl_clr(qcs->sd, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);

		/* Set end-of-input when full message properly received. */
		if (fin) {
			TRACE_STATE("report end-of-input", QMUX_EV_STRM_RECV, qcc->conn, qcs);
			se_fl_set(qcs->sd, SE_FL_EOI);

			/* If request EOM is reported to the upper layer, it means the
			 * QCS now expects data from the opposite side.
			 */
			se_expect_data(qcs->sd);
		}

		/* Set end-of-stream on read closed. */
		if (qcs->flags & QC_SF_RECV_RESET ||
		    qcc->conn->flags & CO_FL_SOCK_RD_SH) {
			TRACE_STATE("report end-of-stream", QMUX_EV_STRM_RECV, qcc->conn, qcs);
			se_fl_set(qcs->sd, SE_FL_EOS);

			/* Set error if EOI not reached. This may happen on
			 * RESET_STREAM reception or connection error.
			 */
			if (!se_fl_test(qcs->sd, SE_FL_EOI)) {
				TRACE_STATE("report error on stream aborted", QMUX_EV_STRM_RECV, qcc->conn, qcs);
				se_fl_set(qcs->sd, SE_FL_ERROR);
			}
		}

		if (se_fl_test(qcs->sd, SE_FL_ERR_PENDING)) {
			TRACE_STATE("report error", QMUX_EV_STRM_RECV, qcc->conn, qcs);
			se_fl_set(qcs->sd, SE_FL_ERROR);
		}

		if (b_size(&qcs->rx.app_buf)) {
			b_free(&qcs->rx.app_buf);
			offer_buffers(NULL, 1);
		}
	}

	/* Restart demux if it was interrupted on full buffer. */
	if (ret && qcs->flags & QC_SF_DEM_FULL) {
		/* Ensure DEM_FULL is only set if there is available data to
		 * ensure we never do unnecessary wakeup here.
		 */
		BUG_ON(!ncb_data(&qcs->rx.ncbuf, 0));

		qcs->flags &= ~QC_SF_DEM_FULL;
		if (!(qcc->flags & QC_CF_ERRL)) {
			LIST_APPEND(&qcc->recv_list, &qcs->el_recv);
			tasklet_wakeup(qcc->wait_event.tasklet);
		}
	}

	TRACE_LEAVE(QMUX_EV_STRM_RECV, qcc->conn, qcs);

	return ret;
}

static size_t qmux_strm_snd_buf(struct stconn *sc, struct buffer *buf,
                                size_t count, int flags)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	const size_t old_data = qcs_prep_bytes(qcs);
	size_t ret = 0;
	char fin;

	TRACE_ENTER(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	/* Stream must not be woken up if already waiting for conn buffer. */
	BUG_ON(LIST_INLIST(&qcs->el_buf));

	/* Sending forbidden if QCS is locally closed (FIN or RESET_STREAM sent). */
	BUG_ON(qcs_is_close_local(qcs) || (qcs->flags & QC_SF_TO_RESET));

	/* stream layer has been detached so no transfer must occur after. */
	BUG_ON_HOT(qcs->flags & QC_SF_DETACH);

	/* Report error if set on stream endpoint layer. */
	if (qcs->qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL)) {
		se_fl_set(qcs->sd, SE_FL_ERROR);
		TRACE_DEVEL("connection in error", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		goto end;
	}

	if (qfctl_sblocked(&qcs->qcc->tx.fc)) {
		TRACE_DEVEL("leaving on connection flow control",
		            QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		if (!LIST_INLIST(&qcs->el_fctl)) {
			TRACE_DEVEL("append to fctl-list",
			            QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
			LIST_APPEND(&qcs->qcc->fctl_list, &qcs->el_fctl);
			tot_time_start(&qcs->timer.fctl);
		}
		goto end;
	}

	if (qfctl_sblocked(&qcs->tx.fc)) {
		TRACE_DEVEL("leaving on flow-control reached",
		            QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		tot_time_start(&qcs->timer.fctl);
		goto end;
	}

	ret = qcs_http_snd_buf(qcs, buf, count, &fin);
	if (fin) {
		TRACE_STATE("reached stream fin", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		qcs->flags |= QC_SF_FIN_STREAM;
	}

	if (ret || fin) {
		const size_t data = qcs_prep_bytes(qcs) - old_data;
		if (data || fin)
			qcc_send_stream(qcs, 0, data);

		/* Wake up MUX to emit newly transferred data. */
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

 end:
	TRACE_LEAVE(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	return ret;
}


static size_t qmux_strm_nego_ff(struct stconn *sc, struct buffer *input,
                                size_t count, unsigned int flags)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	size_t ret = 0;

	TRACE_ENTER(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	/* Stream must not be woken up if already waiting for conn buffer. */
	BUG_ON(LIST_INLIST(&qcs->el_buf));

	/* Sending forbidden if QCS is locally closed (FIN or RESET_STREAM sent). */
	BUG_ON(qcs_is_close_local(qcs) || (qcs->flags & QC_SF_TO_RESET));

	/* stream layer has been detached so no transfer must occur after. */
	BUG_ON_HOT(qcs->flags & QC_SF_DETACH);

	if (!qcs->qcc->app_ops->nego_ff || !qcs->qcc->app_ops->done_ff) {
		/* Fast forwarding is not supported by the QUIC application layer */
		qcs->sd->iobuf.flags |= IOBUF_FL_NO_FF;
		goto end;
	}

	if (qcs->qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL)) {
		/* Disable fast-forward if connection is on error. Eventually,
		 * error will be reported to stream-conn if snd_buf is invoked.
		 */
		TRACE_DEVEL("connection in error", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		qcs->sd->iobuf.flags |= IOBUF_FL_NO_FF;
		goto end;
	}

	if (qfctl_sblocked(&qcs->qcc->tx.fc)) {
		TRACE_DEVEL("leaving on connection flow control", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		if (!LIST_INLIST(&qcs->el_fctl)) {
			TRACE_DEVEL("append to fctl-list", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
			LIST_APPEND(&qcs->qcc->fctl_list, &qcs->el_fctl);
		}
		qcs->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		goto end;
	}

	if (qfctl_sblocked(&qcs->tx.fc)) {
		TRACE_DEVEL("leaving on flow-control reached", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		qcs->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		goto end;
	}

	/* Alawys disable splicing */
	qcs->sd->iobuf.flags |= IOBUF_FL_NO_SPLICING;

	ret = qcs->qcc->app_ops->nego_ff(qcs, count);
	if (!ret)
		goto end;

	/* forward remaining input data */
	if (b_data(input)) {
		size_t xfer = ret;

		if (xfer > b_data(input))
			xfer = b_data(input);
		b_add(qcs->sd->iobuf.buf, qcs->sd->iobuf.offset);
		qcs->sd->iobuf.data = b_xfer(qcs->sd->iobuf.buf, input, xfer);
		b_sub(qcs->sd->iobuf.buf, qcs->sd->iobuf.offset);

		/* Cannot forward more data, wait for room */
		if (b_data(input)) {
			ret = 0;
			goto end;
		}
	}
	ret -= qcs->sd->iobuf.data;

 end:
	TRACE_LEAVE(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
	return ret;
}

static size_t qmux_strm_done_ff(struct stconn *sc)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	struct qcc *qcc = qcs->qcc;
	struct sedesc *sd = qcs->sd;
	size_t total = 0, data = sd->iobuf.data;

	TRACE_ENTER(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

	if (sd->iobuf.flags & IOBUF_FL_EOI) {
		TRACE_STATE("reached stream fin", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
		qcs->flags |= QC_SF_FIN_STREAM;
	}

	if (!(qcs->flags & QC_SF_FIN_STREAM) && !sd->iobuf.data) {
		TRACE_STATE("no data sent", QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);

		/* There is nothing to forward and the SD was blocked after a
		 * successful nego by the producer. We can try to release the
		 * TXBUF to retry. In this case, the TX buf MUST exist.
		 */
		if ((qcs->sd->iobuf.flags & IOBUF_FL_FF_WANT_ROOM) && !qcc_release_stream_txbuf(qcs))
			qcs->sd->iobuf.flags &= ~(IOBUF_FL_FF_BLOCKED|IOBUF_FL_FF_WANT_ROOM);
		goto end;
	}

	total = qcs->qcc->app_ops->done_ff(qcs);
	if (total || qcs->flags & QC_SF_FIN_STREAM)
		qcc_send_stream(qcs, 0, total);

	/* Reset stconn iobuf information. */
	qcs->sd->iobuf.buf = NULL;
	qcs->sd->iobuf.offset = 0;
	qcs->sd->iobuf.data = 0;

	if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(qcc->wait_event.tasklet);

  end:
	TRACE_LEAVE(QMUX_EV_STRM_SEND, qcs->qcc->conn, qcs);
	return data;
}

static int qmux_strm_resume_ff(struct stconn *sc, unsigned int flags)
{
	return 0;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int qmux_strm_subscribe(struct stconn *sc, int event_type,
                               struct wait_event *es)
{
	return qcs_subscribe(__sc_mux_strm(sc), event_type, es);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int qmux_strm_unsubscribe(struct stconn *sc, int event_type, struct wait_event *es)
{
	struct qcs *qcs = __sc_mux_strm(sc);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		qcs->subs = NULL;

	return 0;
}

static int qmux_wake(struct connection *conn)
{
	struct qcc *qcc = conn->ctx;

	TRACE_ENTER(QMUX_EV_QCC_WAKE, conn);

	if (qcc_io_process(qcc)) {
		TRACE_STATE("releasing dead connection", QMUX_EV_QCC_WAKE, qcc->conn);
		goto release;
	}

	qcc_wake_some_streams(qcc);

	qcc_refresh_timeout(qcc);

	TRACE_LEAVE(QMUX_EV_QCC_WAKE, conn);
	return 0;

 release:
	qcc_shutdown(qcc);
	qcc_release(qcc);
	TRACE_LEAVE(QMUX_EV_QCC_WAKE);
	return 1;
}

static void qmux_strm_shut(struct stconn *sc, unsigned int mode, struct se_abort_info *reason)
{
	struct qcs *qcs = __sc_mux_strm(sc);
	struct qcc *qcc = qcs->qcc;

	if (!(mode & (SE_SHW_SILENT|SE_SHW_NORMAL)))
		return;

	TRACE_ENTER(QMUX_EV_STRM_SHUT, qcc->conn, qcs);

	/* Early closure reported if QC_SF_FIN_STREAM not yet set. */
	if (!qcs_is_close_local(qcs) &&
	    !(qcs->flags & (QC_SF_FIN_STREAM|QC_SF_TO_RESET))) {

		/* Close stream with FIN if length unknown and some data are
		 * ready to be/already transmitted.
		 * TODO select closure method on app proto layer
		 */
		if (qcs->flags & QC_SF_UNKNOWN_PL_LENGTH &&
		    qcs->tx.fc.off_soft) {
			if (!(qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL))) {
				TRACE_STATE("set FIN STREAM",
				            QMUX_EV_STRM_SHUT, qcc->conn, qcs);
				qcs->flags |= QC_SF_FIN_STREAM;
				qcc_send_stream(qcs, 0, 0);
			}
		}
		else {
			/* RESET_STREAM necessary. */
			qcc_reset_stream(qcs, 0);
		}

		tasklet_wakeup(qcc->wait_event.tasklet);
	}

 out:
	TRACE_LEAVE(QMUX_EV_STRM_SHUT, qcc->conn, qcs);
}

static int qmux_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	struct qcc *qcc = conn->ctx;

	switch (mux_ctl) {
	case MUX_CTL_EXIT_STATUS:
		return MUX_ES_UNKNOWN;

	case MUX_CTL_GET_GLITCHES:
		return qcc->glitches;

	case MUX_CTL_GET_NBSTRM: {
		struct qcs *qcs;
		unsigned int nb_strm = qcc->nb_sc;

		list_for_each_entry(qcs, &qcc->opening_list, el_opening)
			nb_strm++;
		return nb_strm;
	}

	case MUX_CTL_GET_MAXSTRM:
		return qcc->lfctl.ms_bidi_init;

	default:
		return -1;
	}
}

static int qmux_sctl(struct stconn *sc, enum mux_sctl_type mux_sctl, void *output)
{
	int ret = 0;
	const struct qcs *qcs = __sc_mux_strm(sc);
	const struct qcc *qcc = qcs->qcc;
	union mux_sctl_dbg_str_ctx *dbg_ctx;
	struct buffer *buf;

	switch (mux_sctl) {
	case MUX_SCTL_SID:
		if (output)
			*((int64_t *)output) = qcs->id;
		return ret;

	case MUX_SCTL_DBG_STR:
		dbg_ctx = output;
		buf = get_trash_chunk();

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_MUXS)
			qmux_dump_qcs_info(buf, qcs);

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_MUXC)
			qmux_dump_qcc_info(buf, qcc);

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_CONN)
			chunk_appendf(buf, " conn.flg=%#08x", qcc->conn->flags);

		if (dbg_ctx->arg.debug_flags & MUX_SCTL_DBG_STR_L_XPRT)
			qcc->conn->xprt->dump_info(buf, qcc->conn);

		dbg_ctx->ret.buf = *buf;
		return ret;

	default:
		return -1;
	}
}

/* for debugging with CLI's "show sess" command. May emit multiple lines, each
 * new one being prefixed with <pfx>, if <pfx> is not NULL, otherwise a single
 * line is used. Each field starts with a space so it's safe to print it after
 * existing fields.
 */
static int qmux_strm_show_sd(struct buffer *msg, struct sedesc *sd, const char *pfx)
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


static const struct mux_ops qmux_ops = {
	.init        = qmux_init,
	.destroy     = qmux_destroy,
	.detach      = qmux_strm_detach,
	.rcv_buf     = qmux_strm_rcv_buf,
	.snd_buf     = qmux_strm_snd_buf,
	.nego_fastfwd = qmux_strm_nego_ff,
	.done_fastfwd = qmux_strm_done_ff,
	.resume_fastfwd = qmux_strm_resume_ff,
	.subscribe   = qmux_strm_subscribe,
	.unsubscribe = qmux_strm_unsubscribe,
	.wake        = qmux_wake,
	.shut        = qmux_strm_shut,
	.ctl         = qmux_ctl,
	.sctl        = qmux_sctl,
	.show_sd     = qmux_strm_show_sd,
	.flags = MX_FL_HTX|MX_FL_NO_UPG|MX_FL_FRAMED,
	.name = "QUIC",
};

void qcc_show_quic(struct qcc *qcc)
{
	const struct quic_conn *qc = qcc->conn->handle.qc;
	struct eb64_node *node;

	chunk_appendf(&trash, "  qcc=0x%p flags=0x%x sc=%llu hreq=%llu bwnd=%llu/%llu\n",
	              qcc, qcc->flags, (ullong)qcc->nb_sc, (ullong)qcc->nb_hreq,
	              (ullong)qcc->tx.buf_in_flight, (ullong)qc->path->cwnd);

	if (qcc_is_pacing_active(qcc->conn)) {
		chunk_appendf(&trash, "  pacing int_sent=%d last_sent=%d\n",
		              qcc->tx.paced_sent_ctr,
		              qcc->tx.pacer.last_sent);
	}

	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = eb64_entry(node, struct qcs, by_id);
		chunk_appendf(&trash, "    qcs=0x%p id=%llu flags=0x%x st=%s",
		              qcs, (ullong)qcs->id, qcs->flags,
		              qcs_st_to_str(qcs->st));
		if (!quic_stream_is_uni(qcs->id) || !quic_stream_is_local(qcc, qcs->id))
			chunk_appendf(&trash, " rxoff=%llu", (ullong)qcs->rx.offset);
		if (!quic_stream_is_uni(qcs->id) || !quic_stream_is_remote(qcc, qcs->id))
			chunk_appendf(&trash, " txoff=%llu(%llu) msd=%llu",
			              (ullong)qcs->tx.fc.off_real,
			              (ullong)qcs->tx.fc.off_soft - (ullong)qcs->tx.fc.off_real,
			              (ullong)qcs->tx.fc.limit);
		chunk_appendf(&trash, "\n");
		node = eb64_next(node);
	}
}

static struct mux_proto_list mux_proto_quic =
  { .token = IST("quic"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_FE, .mux = &qmux_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_quic);
