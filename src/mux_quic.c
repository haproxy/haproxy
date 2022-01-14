#include <haproxy/mux_quic.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/pool.h>
#include <haproxy/ssl_sock-t.h>

DECLARE_POOL(pool_head_qcc, "qcc", sizeof(struct qcc));
DECLARE_POOL(pool_head_qcs, "qcs", sizeof(struct qcs));

void quic_mux_transport_params_update(struct qcc *qcc)
{
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
	if (qc_local_stream_id(qcc, id)) {
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
		if (sub_id + 1 > qcc->strms[qcs_type].max_streams) {
			/* streams limit reached */
			goto out;
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

/* detaches the QUIC stream from its QCC and releases it to the QCS pool. */
static void qcs_destroy(struct qcs *qcs)
{
	fprintf(stderr, "%s: release stream %llu\n", __func__, qcs->by_id.key);

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

static int qcs_push_frame(struct qcs *qcs, struct buffer *payload, int fin, uint64_t offset)
{
	struct quic_frame *frm;
	struct buffer *buf = &qcs->tx.xprt_buf;
	struct quic_enc_level *qel = &qcs->qcc->conn->qc->els[QUIC_TLS_ENC_LEVEL_APP];
	int total = 0, to_xfer;

	fprintf(stderr, "%s\n", __func__);

	qc_get_buf(qcs, buf);
	to_xfer = QUIC_MIN(b_data(payload), b_room(buf));
	if (!to_xfer)
		goto out;

	frm = pool_zalloc(pool_head_quic_frame);
	if (!frm)
		goto err;

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
	frm->stream.id = qcs->by_id.key;
	if (total) {
		frm->type |= QUIC_STREAM_FRAME_TYPE_LEN_BIT;
		frm->stream.len = total;
	}

	LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
 out:
	fprintf(stderr, "%s: total=%d fin=%d id=%llu offset=%lu\n",
	        __func__, total, fin, (ull)qcs->by_id.key, offset);
	return total;

 err:
	return -1;
}

static int qc_send(struct qcc *qcc)
{
	struct eb64_node *node;
	int xprt_wake = 0;
	int ret;

	fprintf(stderr, "%s\n", __func__);

	/* TODO simple loop through all streams and check if there is frames to
	 * send
	 */
	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = container_of(node, struct qcs, by_id);
		struct buffer *buf = &qcs->tx.buf;
		if (b_data(buf)) {
			char fin = qcs->flags & QC_SF_FIN_STREAM;
			ret = qcs_push_frame(qcs, buf, fin, qcs->tx.offset);
			if (ret < 0)
				ABORT_NOW();

			if (ret > 0) {
				qcs_notify_send(qcs);
				if (qcs->flags & QC_SF_BLK_MROOM)
					qcs->flags &= ~QC_SF_BLK_MROOM;

				xprt_wake = 1;
			}

			fprintf(stderr, "%s ret=%d\n", __func__, ret);
			qcs->tx.offset += ret;

			if (b_data(buf)) {
				qcc->conn->xprt->subscribe(qcc->conn, qcc->conn->xprt_ctx,
				                           SUB_RETRY_SEND, &qcc->wait_event);
			}
		}
		node = eb64_next(node);
	}

	if (xprt_wake)
		tasklet_wakeup(((struct ssl_sock_ctx *)(qcc->conn->xprt_ctx))->wait_event.tasklet);

	return ret;
}

static int qc_release_detached_streams(struct qcc *qcc)
{
	struct eb64_node *node;
	int release = 0;

	node = eb64_first(&qcc->streams_by_id);
	while (node) {
		struct qcs *qcs = container_of(node, struct qcs, by_id);
		node = eb64_next(node);

		if (qcs->flags & QC_SF_DETACH) {
			if ((!b_data(&qcs->tx.buf) && !b_data(&qcs->tx.xprt_buf)) ||
			    qcc->flags & QC_CF_CC_RECV) {
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

	fprintf(stderr, "%s\n", __func__);

	qc_send(qcc);

	if (qc_release_detached_streams(qcc)) {
		if (qcc_is_dead(qcc)) {
			qc_release(qcc);
			return NULL;
		}
	}

	return NULL;
}

static int qc_init(struct connection *conn, struct proxy *prx,
                   struct session *sess, struct buffer *input)
{
	struct qcc *qcc;
	struct quic_transport_params *srv_params;

	qcc = pool_alloc(pool_head_qcc);
	if (!qcc)
		goto fail_no_qcc;

	qcc->conn = conn;
	conn->ctx = qcc;

	qcc->app_ops = NULL;

	qcc->streams_by_id = EB_ROOT_UNIQUE;

	/* Server parameters, params used for RX flow control. */
	srv_params = &conn->qc->rx.params;

	qcc->rx.max_data = srv_params->initial_max_data;
	qcc->tx.max_data = 0;

	/* Client initiated streams must respect the server flow control. */
	qcc->strms[QCS_CLT_BIDI].max_streams = srv_params->initial_max_streams_bidi;
	qcc->strms[QCS_CLT_BIDI].nb_streams = 0;
	qcc->strms[QCS_CLT_BIDI].largest_id = -1;
	qcc->strms[QCS_CLT_BIDI].rx.max_data = 0;
	qcc->strms[QCS_CLT_BIDI].tx.max_data = srv_params->initial_max_stream_data_bidi_remote;

	qcc->strms[QCS_CLT_UNI].max_streams = srv_params->initial_max_streams_uni;
	qcc->strms[QCS_CLT_UNI].nb_streams = 0;
	qcc->strms[QCS_CLT_UNI].largest_id = -1;
	qcc->strms[QCS_CLT_UNI].rx.max_data = 0;
	qcc->strms[QCS_CLT_UNI].tx.max_data = srv_params->initial_max_stream_data_uni;

	/* Server initiated streams must respect the server flow control. */
	qcc->strms[QCS_SRV_BIDI].max_streams = 0;
	qcc->strms[QCS_SRV_BIDI].nb_streams = 0;
	qcc->strms[QCS_SRV_BIDI].largest_id = -1;
	qcc->strms[QCS_SRV_BIDI].rx.max_data = srv_params->initial_max_stream_data_bidi_local;
	qcc->strms[QCS_SRV_BIDI].tx.max_data = 0;

	qcc->strms[QCS_SRV_UNI].max_streams = 0;
	qcc->strms[QCS_SRV_UNI].nb_streams = 0;
	qcc->strms[QCS_SRV_UNI].largest_id = -1;
	qcc->strms[QCS_SRV_UNI].rx.max_data = srv_params->initial_max_stream_data_uni;
	qcc->strms[QCS_SRV_UNI].tx.max_data = 0;

	qcc->wait_event.tasklet = tasklet_new();
	if (!qcc->wait_event.tasklet)
		goto fail_no_tasklet;

	qcc->subs = NULL;
	qcc->wait_event.tasklet->process = qc_io_cb;
	qcc->wait_event.tasklet->context = qcc;

	HA_ATOMIC_STORE(&conn->qc->qcc, qcc);
	/* init read cycle */
	tasklet_wakeup(qcc->wait_event.tasklet);

	return 0;

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

	if ((b_data(&qcs->tx.buf) || b_data(&qcs->tx.xprt_buf)) &&
	    !(qcc->flags & QC_CF_CC_RECV)) {
		qcs->flags |= QC_SF_DETACH;
		return;
	}

	qcs_destroy(qcs);
	if (qcc_is_dead(qcc)) {
		qc_release(qcc);
		return;
	}
}

/* Called from the upper layer, to receive data */
static size_t qc_rcv_buf(struct conn_stream *cs, struct buffer *buf,
                         size_t count, int flags)
{
	/* XXX TODO XXX */
	fprintf(stderr, "%s\n", __func__);

	return 0;
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

static const struct mux_ops qc_ops = {
	.init = qc_init,
	.detach = qc_detach,
	.rcv_buf = qc_rcv_buf,
	.snd_buf = qc_snd_buf,
	.subscribe = qc_subscribe,
	.unsubscribe = qc_unsubscribe,
};

static struct mux_proto_list mux_proto_quic =
  { .token = IST("quic"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_FE, .mux = &qc_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_quic);
