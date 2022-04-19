#include <haproxy/quic_stream.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/list.h>
#include <haproxy/dynbuf.h>
#include <haproxy/pool.h>
#include <haproxy/xprt_quic.h>

DECLARE_STATIC_POOL(pool_head_quic_conn_stream, "qc_stream_desc",
                    sizeof(struct qc_stream_desc));

/* Allocate a new stream descriptor with id <id>. The caller is responsible to
 * store the stream in the appropriate tree.
 *
 * Returns the newly allocated instance on success or else NULL.
 */
struct qc_stream_desc *qc_stream_desc_new(uint64_t id, void *ctx)
{
	struct qc_stream_desc *stream;

	stream = pool_alloc(pool_head_quic_conn_stream);
	if (!stream)
		return NULL;

	stream->by_id.key = id;
	stream->by_id.node.leaf_p = NULL;

	stream->buf = BUF_NULL;
	stream->acked_frms = EB_ROOT;
	stream->ack_offset = 0;
	stream->release = 0;
	stream->ctx = ctx;

	return stream;
}

/* Mark the stream descriptor <stream> as released by the upper layer. It will
 * be freed as soon as all its buffered data are acknowledged. In the meantime,
 * the stream is stored in the <qc> tree : thus it must have been removed from
 * any other tree before calling this function.
 */
void qc_stream_desc_release(struct qc_stream_desc *stream,
                            struct quic_conn *qc)
{
	BUG_ON(stream->by_id.node.leaf_p);

	stream->release = 1;
	stream->ctx = NULL;

	if (!b_data(&stream->buf))
		qc_stream_desc_free(stream);
	else
		eb64_insert(&qc->streams_by_id, &stream->by_id);
}

/* Free the stream descriptor <stream> buffer. This function should be used
 * when all its data have been acknowledged. If the stream was released by the
 * upper layer, the stream descriptor will be freed.
 *
 * Returns 0 if the stream was not freed else non-zero.
 */
int qc_stream_desc_free(struct qc_stream_desc *stream)
{
	b_free(&stream->buf);
	offer_buffers(NULL, 1);

	if (stream->release) {
		/* Free frames still waiting for an ACK. Even if the stream buf
		 * is NULL, some frames could still be not acknowledged. This
		 * is notably the case for retransmission where multiple frames
		 * points to the same buffer content.
		 */
		struct eb64_node *frm_node = eb64_first(&stream->acked_frms);
		while (frm_node) {
			struct quic_stream *strm;
			struct quic_frame *frm;

			strm = eb64_entry(&frm_node->node, struct quic_stream, offset);

			frm_node = eb64_next(frm_node);
			eb64_delete(&strm->offset);

			frm = container_of(strm, struct quic_frame, stream);
			LIST_DELETE(&frm->list);
			quic_tx_packet_refdec(frm->pkt);
			pool_free(pool_head_quic_frame, frm);
		}

		eb64_delete(&stream->by_id);
		pool_free(pool_head_quic_conn_stream, stream);

		return 1;
	}

	return 0;
}
