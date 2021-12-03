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

	fprintf(stderr, "%s: stream ID %llu\n", __func__, qcs->by_id.key);

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

	MT_LIST_APPEND(&qel->pktns->tx.frms, &frm->mt_list);
 out:
	fprintf(stderr, "%s: total=%d fin=%d offset=%lu\n", __func__, total, fin, offset);
	return total;

 err:
	return -1;
}

static int qc_send(struct qcc *qcc)
{
	struct eb64_node *node;
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
			/* TODO handle the FIN parameter */
			ret = qcs_push_frame(qcs, buf, 0, qcs->tx.offset);
			if (ret < 0)
				ABORT_NOW();

			/* TODO wake-up xprt if data were transfered */

			fprintf(stderr, "%s ret=%d\n", __func__, ret);
			qcs->tx.offset += ret;
		}
		node = eb64_next(node);
	}

	return ret;
}

static struct task *qc_io_cb(struct task *t, void *ctx, unsigned int status)
{
	struct qcc *qcc = ctx;

	fprintf(stderr, "%s\n", __func__);

	qc_send(qcc);

	return NULL;
}

static int qc_init(struct connection *conn, struct proxy *prx,
                   struct session *sess, struct buffer *input)
{
	struct qcc *qcc;

	qcc = pool_alloc(pool_head_qcc);
	if (!qcc)
		goto fail_no_qcc;

	qcc->conn = conn;
	conn->ctx = qcc;
	conn->qc->qcc = qcc;

	qcc->app_ops = NULL;

	qcc->streams_by_id = EB_ROOT_UNIQUE;

	qcc->strms[QCS_CLT_BIDI].nb_streams = 0;
	qcc->strms[QCS_CLT_BIDI].largest_id = -1;
	qcc->strms[QCS_CLT_UNI].nb_streams = 0;
	qcc->strms[QCS_CLT_UNI].largest_id = -1;
	qcc->strms[QCS_SRV_BIDI].nb_streams = 0;
	qcc->strms[QCS_SRV_BIDI].largest_id = -1;
	qcc->strms[QCS_SRV_UNI].nb_streams = 0;
	qcc->strms[QCS_SRV_UNI].largest_id = -1;

	qcc->wait_event.tasklet = tasklet_new();
	if (!qcc->wait_event.tasklet)
		goto fail_no_tasklet;

	qcc->subs = NULL;
	qcc->wait_event.tasklet->process = qc_io_cb;
	qcc->wait_event.tasklet->context = qcc;

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
	/* XXX TO DO XXX */
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
	/* XXX TODO XXX */
	return 0;
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
