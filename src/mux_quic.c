#include <haproxy/mux_quic.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/dynbuf.h>
#include <haproxy/htx.h>
#include <haproxy/pool.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/xprt_quic.h>

DECLARE_POOL(pool_head_qcc, "qcc", sizeof(struct qcc));
DECLARE_POOL(pool_head_qcs, "qcs", sizeof(struct qcs));

/* Allocate a new QUIC streams with id <id> and type <type>. */
struct qcs *qcs_new(struct qcc *qcc, uint64_t id, enum qcs_type type)
{
	struct qcs *qcs;

	qcs = pool_alloc(pool_head_qcs);
	if (!qcs)
		goto out;

	fprintf(stderr, "%s: stream ID %lu\n", __func__, id);

	qcs->qcc = qcc;
	qcs->cs = NULL;
	qcs->flags = QC_SF_NONE;

	qcs->by_id.key = id;
	eb64_insert(&qcc->streams_by_id, &qcs->by_id);
	qcc->strms[type].nb_streams++;

	qcs->rx.buf = BUF_NULL;
	qcs->rx.app_buf = BUF_NULL;
	qcs->rx.offset = 0;
	qcs->rx.frms = EB_ROOT_UNIQUE;

	qcs->tx.buf = BUF_NULL;
	qcs->tx.xprt_buf = BUF_NULL;
	qcs->tx.offset = 0;
	qcs->tx.ack_offset = 0;
	qcs->tx.acked_frms = EB_ROOT_UNIQUE;

	qcs->wait_event.tasklet = NULL;
	qcs->wait_event.events = 0;
	qcs->subs = NULL;

 out:
	return qcs;
}

/* Free a qcs. This function must only be used for unidirectional streams.
 * Bidirectional streams are released by the upper layer through qc_detach().
 */
void uni_qcs_free(struct qcs *qcs)
{
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
	fprintf(stderr, "%s\n", __func__);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events |= event_type;
	qcs->subs = es;

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
struct eb64_node *qcc_get_qcs(struct qcc *qcc, uint64_t id)
{
	unsigned int strm_type;
	int64_t sub_id;
	struct eb64_node *strm_node;

	strm_type = id & QCS_ID_TYPE_MASK;
	sub_id = id >> QCS_ID_TYPE_SHIFT;
	strm_node = NULL;
	if (quic_stream_is_local(qcc, id)) {
		/* Local streams: this stream must be already opened. */
		strm_node = eb64_lookup(&qcc->streams_by_id, id);
		if (!strm_node) {
			/* unknown stream id */
			goto out;
		}
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
			if (sub_id + 1 > qcc->lfctl.max_bidi_streams) {
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
			struct qcs *qcs;

			qcs = NULL;
			for (i = largest_id + 1; i <= sub_id; i++) {
				uint64_t id = (i << QCS_ID_TYPE_SHIFT) | strm_type;
				enum qcs_type type = id & QCS_ID_DIR_BIT ? QCS_CLT_UNI : QCS_CLT_BIDI;
				qcs = qcs_new(qcc, id, type);
				if (!qcs) {
					/* allocation failure */
					goto out;
				}

				qcc->strms[qcs_type].largest_id = i;
			}
			if (qcs)
				strm_node = &qcs->by_id;
		}
		else {
			strm_node = eb64_lookup(strms, id);
		}
	}

	return strm_node;

 out:
	return NULL;
}

/* Handle a new STREAM frame <strm_frm>. The frame content will be copied in
 * the buffer of the stream instance. The stream instance will be stored in
 * <out_qcs>. In case of success, the caller can immediatly call qcc_decode_qcs
 * to process the frame content.
 *
 * Returns 0 on success. On errors, two codes are present.
 * - 1 is returned if the frame cannot be decoded and must be discarded.
 * - 2 is returned if the stream cannot decode at the moment the frame. The
 *   frame should be buffered to be handled later.
 */
int qcc_recv(struct qcc *qcc, uint64_t id, uint64_t len, uint64_t offset,
             char fin, char *data, struct qcs **out_qcs)
{
	struct qcs *qcs;
	struct eb64_node *strm_node;
	size_t total, diff;

	strm_node = qcc_get_qcs(qcc, id);
	if (!strm_node) {
		fprintf(stderr, "%s: stream not found\n", __func__);
		return 1;
	}

	qcs = eb64_entry(&strm_node->node, struct qcs, by_id);
	*out_qcs = qcs;

	if (offset > qcs->rx.offset)
		return 2;

	if (offset + len <= qcs->rx.offset) {
		fprintf(stderr, "%s: already received STREAM data\n", __func__);
		return 1;
	}

	/* Last frame already handled for this stream. */
	BUG_ON(qcs->flags & QC_SF_FIN_RECV);

	if (!qc_get_buf(qcs, &qcs->rx.buf)) {
		/* TODO should mark qcs as full */
		return 2;
	}

	fprintf(stderr, "%s: new STREAM data\n", __func__);
	diff = qcs->rx.offset - offset;

	/* TODO do not partially copy a frame if not enough size left. Maybe
	 * this can be optimized.
	 */
	if (len > b_room(&qcs->rx.buf)) {
		/* TODO handle STREAM frames larger than RX buffer. */
		BUG_ON(len > b_size(&qcs->rx.buf));
		return 2;
	}

	len -= diff;
	data += diff;

	total = b_putblk(&qcs->rx.buf, data, len);
	/* TODO handle partial copy of a STREAM frame. */
	BUG_ON(len != total);

	qcs->rx.offset += total;

	if (fin)
		qcs->flags |= QC_SF_FIN_RECV;

 out:
	return 0;
}

/* Decode the content of STREAM frames already received on the stream instance
 * <qcs>.
 *
 * Returns 0 on success else non-zero.
 */
int qcc_decode_qcs(struct qcc *qcc, struct qcs *qcs)
{
	if (qcc->app_ops->decode_qcs(qcs, qcs->flags & QC_SF_FIN_RECV, qcc->ctx) < 0) {
		fprintf(stderr, "%s: decoding error\n", __func__);
		return 1;
	}

	return 0;
}

static int qc_is_max_streams_needed(struct qcc *qcc)
{
	return qcc->lfctl.closed_bidi_streams > qcc->lfctl.initial_max_bidi_streams / 2;
}

/* detaches the QUIC stream from its QCC and releases it to the QCS pool. */
static void qcs_destroy(struct qcs *qcs)
{
	const uint64_t id = qcs->by_id.key;

	fprintf(stderr, "%s: release stream %llu\n", __func__, qcs->by_id.key);

	if (quic_stream_is_remote(qcs->qcc, id)) {
		if (quic_stream_is_bidi(id)) {
			++qcs->qcc->lfctl.closed_bidi_streams;
			if (qc_is_max_streams_needed(qcs->qcc))
				tasklet_wakeup(qcs->qcc->wait_event.tasklet);
		}
	}

	eb64_delete(&qcs->by_id);

	b_free(&qcs->rx.buf);
	b_free(&qcs->tx.buf);
	b_free(&qcs->tx.xprt_buf);

	--qcs->qcc->strms[qcs_id_type(qcs->by_id.key)].nb_streams;

	pool_free(pool_head_qcs, qcs);
}

static inline int qcc_is_dead(const struct qcc *qcc)
{
	fprintf(stderr, "%s: %lu\n", __func__, qcc->strms[QCS_CLT_BIDI].nb_streams);

	if (!qcc->strms[QCS_CLT_BIDI].nb_streams && !qcc->task)
		return 1;

	return 0;
}

/* Return true if the mux timeout should be armed. */
static inline int qcc_may_expire(struct qcc *qcc)
{

	/* Consider that the timeout must be set if no bidirectional streams
	 * are opened.
	 */
	if (!qcc->strms[QCS_CLT_BIDI].nb_streams)
		return 1;

	return 0;
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void qc_release(struct qcc *qcc)
{
	struct connection *conn = NULL;

	if (qcc) {
		/* The connection must be aattached to this mux to be released */
		if (qcc->conn && qcc->conn->ctx == qcc)
			conn = qcc->conn;

		if (qcc->wait_event.tasklet)
			tasklet_free(qcc->wait_event.tasklet);

		pool_free(pool_head_qcc, qcc);
	}

	if (conn) {
		LIST_DEL_INIT(&conn->stopping_list);

		conn->qc->conn = NULL;
		conn->mux = NULL;
		conn->ctx = NULL;

		conn_stop_tracking(conn);
		conn_full_close(conn);
		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
		fprintf(stderr, "conn@%p released\n", conn);
	}
}

static int qcs_push_frame(struct qcs *qcs, struct buffer *payload, int fin, uint64_t offset,
                          struct list *frm_list)
{
	struct quic_frame *frm;
	struct buffer *buf = &qcs->tx.xprt_buf;
	int total = 0, to_xfer;
	unsigned char *btail;

	fprintf(stderr, "%s\n", __func__);

	qc_get_buf(qcs, buf);
	to_xfer = QUIC_MIN(b_data(payload), b_room(buf));
	if (!to_xfer)
		goto out;

	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm)
		goto err;

	/* store buffer end before transfering data for frm.stream.data */
	btail = (unsigned char *)b_tail(buf);
	total = b_force_xfer(buf, payload, to_xfer);
	/* FIN is positioned only when the buffer has been totally emptied. */
	fin = fin && !b_data(payload);
	frm->type = QUIC_FT_STREAM_8;
	if (fin)
		frm->type |= QUIC_STREAM_FRAME_TYPE_FIN_BIT;
	if (offset) {
		frm->type |= QUIC_STREAM_FRAME_TYPE_OFF_BIT;
		frm->stream.offset.key = offset;
	}
	frm->stream.qcs = (struct qcs *)qcs;
	frm->stream.buf = buf;
	frm->stream.data = btail;
	frm->stream.id = qcs->by_id.key;
	if (total) {
		frm->type |= QUIC_STREAM_FRAME_TYPE_LEN_BIT;
		frm->stream.len = total;
	}

	LIST_APPEND(frm_list, &frm->list);
 out:
	fprintf(stderr, "%s: total=%d fin=%d id=%llu offset=%lu\n",
	        __func__, total, fin, (ull)qcs->by_id.key, offset);
	return total;

 err:
	return -1;
}

/* This function must be called by the upper layer to inform about the sending
 * of a STREAM frame for <qcs> instance. The frame is of <data> length and on
 * <offset>.
 */
void qcc_streams_sent_done(struct qcs *qcs, uint64_t data, uint64_t offset)
{
	/* check if the STREAM frame has already been notified. It can happen
	 * for retransmission.
	 */
	if (offset + data <= qcs->tx.sent_offset)
		return;
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
		qc_send_app_pkts(qcc->conn->qc, frms);

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
		fprintf(stderr, "%s: remaining frames to send\n", __func__);
		qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
		                           SUB_RETRY_SEND, &qcc->wait_event);
		return 1;
	}

	return 0;
}

static int qc_send(struct qcc *qcc)
{
	struct eb64_node *node;
	int ret = 0;

	fprintf(stderr, "%s\n", __func__);

	/* loop through all streams, construct STREAM frames if data available.
	 * TODO optimize the loop to favor streams which are not too heavy.
	 */
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = container_of(node, struct qcs, by_id);
		struct buffer *buf = &qcs->tx.buf;

		/* TODO
		 * for the moment, unidirectional streams have their own
		 * mechanism for sending. This should be unified in the future,
		 * in this case the next check will be removed.
		 */
		if (quic_stream_is_uni(qcs->by_id.key)) {
			node = eb64_next(node);
			continue;
		}

		if (b_data(buf)) {
			char fin = qcs->flags & QC_SF_FIN_STREAM;
			ret = qcs_push_frame(qcs, buf, fin, qcs->tx.offset,
			                     &qcc->tx.frms);
			BUG_ON(ret < 0); /* TODO handle this properly */

			if (ret > 0) {
				qcs_notify_send(qcs);
				if (qcs->flags & QC_SF_BLK_MROOM)
					qcs->flags &= ~QC_SF_BLK_MROOM;
			}

			fprintf(stderr, "%s ret=%d\n", __func__, ret);
			qcs->tx.offset += ret;

			/* Subscribe if not all data can be send. */
			if (b_data(buf)) {
				qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
				                           SUB_RETRY_SEND, &qcc->wait_event);
			}
		}
		node = eb64_next(node);
	}

	qc_send_frames(qcc, &qcc->tx.frms);
	/* TODO adjust ret if not all frames are sent. */

	return ret;
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
		struct qcs *qcs = container_of(node, struct qcs, by_id);
		node = eb64_next(node);

		if (qcs->flags & QC_SF_DETACH) {
			if ((!b_data(&qcs->tx.buf) && !b_data(&qcs->tx.xprt_buf))) {
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
	frm->max_streams_bidi.max_streams = qcc->lfctl.max_bidi_streams +
	                                    qcc->lfctl.closed_bidi_streams;
	fprintf(stderr, "SET MAX_STREAMS %lu\n", frm->max_streams_bidi.max_streams);
	LIST_APPEND(&frms, &frm->list);

	if (qc_send_frames(qcc, &frms))
		return 1;

	/* save the new limit if the frame has been send. */
	qcc->lfctl.max_bidi_streams += qcc->lfctl.closed_bidi_streams;
	qcc->lfctl.closed_bidi_streams = 0;

	return 0;
}

static struct task *qc_io_cb(struct task *t, void *ctx, unsigned int status)
{
	struct qcc *qcc = ctx;

	fprintf(stderr, "%s\n", __func__);

	if (qc_is_max_streams_needed(qcc))
		qc_send_max_streams(qcc);

	qc_send(qcc);

	if (qc_release_detached_streams(qcc)) {
		/* Schedule the mux timeout if no bidirectional streams left. */
		if (qcc_may_expire(qcc)) {
			qcc->task->expire = tick_add(now_ms, qcc->timeout);
			task_queue(qcc->task);
		}
	}

	return NULL;
}

static struct task *qc_timeout_task(struct task *t, void *ctx, unsigned int state)
{
	struct qcc *qcc = ctx;
	int expired = tick_is_expired(t->expire, now_ms);

	fprintf(stderr, "%s\n", __func__);

	if (qcc) {
		if (!expired) {
			fprintf(stderr, "%s: not expired\n", __func__);
			return t;
		}

		if (!qcc_may_expire(qcc)) {
			fprintf(stderr, "%s: cannot expire\n", __func__);
			t->expire = TICK_ETERNITY;
			return t;
		}
	}

	fprintf(stderr, "%s: timeout\n", __func__);
	task_destroy(t);

	if (!qcc)
		return NULL;

	qcc->task = NULL;

	if (qcc_is_dead(qcc))
		qc_release(qcc);

	return NULL;
}

static int qc_init(struct connection *conn, struct proxy *prx,
                   struct session *sess, struct buffer *input)
{
	struct qcc *qcc;
	struct quic_transport_params *lparams;

	qcc = pool_alloc(pool_head_qcc);
	if (!qcc)
		goto fail_no_qcc;

	qcc->conn = conn;
	conn->ctx = qcc;
	qcc->flags = 0;

	qcc->app_ops = NULL;

	qcc->streams_by_id = EB_ROOT_UNIQUE;

	/* Server parameters, params used for RX flow control. */
	lparams = &conn->qc->rx.params;

	qcc->rx.max_data = lparams->initial_max_data;
	qcc->tx.max_data = 0;
	LIST_INIT(&qcc->tx.frms);

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

	qcc->lfctl.max_bidi_streams = qcc->lfctl.initial_max_bidi_streams = lparams->initial_max_streams_bidi;
	qcc->lfctl.closed_bidi_streams = 0;

	qcc->wait_event.tasklet = tasklet_new();
	if (!qcc->wait_event.tasklet)
		goto fail_no_tasklet;

	qcc->subs = NULL;
	qcc->wait_event.tasklet->process = qc_io_cb;
	qcc->wait_event.tasklet->context = qcc;

	/* haproxy timeouts */
	qcc->timeout = prx->timeout.client;
	qcc->task = task_new_here();
	if (!qcc->task)
		goto fail_no_timeout_task;
	qcc->task->process = qc_timeout_task;
	qcc->task->context = qcc;
	qcc->task->expire = tick_add(now_ms, qcc->timeout);

	if (!conn_is_back(conn)) {
		if (!LIST_INLIST(&conn->stopping_list)) {
			LIST_APPEND(&mux_stopping_data[tid].list,
			            &conn->stopping_list);
		}
	}

	HA_ATOMIC_STORE(&conn->qc->qcc, qcc);
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

static void qc_detach(struct conn_stream *cs)
{
	struct qcs *qcs = cs->ctx;
	struct qcc *qcc = qcs->qcc;

	fprintf(stderr, "%s: leaving with tx.buf.data=%lu, tx.xprt_buf.data=%lu\n",
	        __func__, b_data(&qcs->tx.buf), b_data(&qcs->tx.xprt_buf));

	/* TODO on CONNECTION_CLOSE reception, it should be possible to free
	 * qcs instances. This should be done once the buffering and ACK
	 * managment between xprt and mux is reorganized.
	 */

	if ((b_data(&qcs->tx.buf) || b_data(&qcs->tx.xprt_buf))) {
		qcs->flags |= QC_SF_DETACH;
		return;
	}

	qcs_destroy(qcs);

	/* Schedule the mux timeout if no bidirectional streams left. */
	if (qcc_may_expire(qcc)) {
		qcc->task->expire = tick_add(now_ms, qcc->timeout);
		task_queue(qcc->task);
	}
}

/* Called from the upper layer, to receive data */
static size_t qc_rcv_buf(struct conn_stream *cs, struct buffer *buf,
                         size_t count, int flags)
{
	struct qcs *qcs = cs->ctx;
	struct htx *qcs_htx = NULL;
	struct htx *cs_htx = NULL;
	size_t ret = 0;
	char fin = 0;

	fprintf(stderr, "%s\n", __func__);

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
		cs->flags |= (CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
	}
	else {
		cs->flags &= ~(CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
		if (cs->flags & CS_FL_ERR_PENDING)
			cs->flags |= CS_FL_ERROR;

		if (fin)
			cs->flags |= (CS_FL_EOI|CS_FL_EOS);

		if (b_size(&qcs->rx.app_buf)) {
			b_free(&qcs->rx.app_buf);
			offer_buffers(NULL, 1);
		}
	}

	if (ret)
		tasklet_wakeup(qcs->qcc->wait_event.tasklet);

	return ret;
}

static size_t qc_snd_buf(struct conn_stream *cs, struct buffer *buf,
                         size_t count, int flags)
{
	struct qcs *qcs = cs->ctx;

	fprintf(stderr, "%s\n", __func__);

	return qcs->qcc->app_ops->snd_buf(cs, buf, count, flags);
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int qc_subscribe(struct conn_stream *cs, int event_type,
                        struct wait_event *es)
{
	return qcs_subscribe(cs->ctx, event_type, es);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int qc_unsubscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	struct qcs *qcs = cs->ctx;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcs->subs && qcs->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		qcs->subs = NULL;

	return 0;
}

static int qc_wake(struct connection *conn)
{
	struct qcc *qcc = conn->ctx;

	/* Check if a soft-stop is in progress.
	 * Release idling front connection if this is the case.
	 */
	if (unlikely(conn->qc->li->bind_conf->frontend->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
		qc_release(qcc);
	}

	return 1;
}

static const struct mux_ops qc_ops = {
	.init = qc_init,
	.detach = qc_detach,
	.rcv_buf = qc_rcv_buf,
	.snd_buf = qc_snd_buf,
	.subscribe = qc_subscribe,
	.unsubscribe = qc_unsubscribe,
	.wake = qc_wake,
};

static struct mux_proto_list mux_proto_quic =
  { .token = IST("quic"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_FE, .mux = &qc_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_quic);
