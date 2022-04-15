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
DECLARE_STATIC_POOL(pool_head_quic_conn_stream_buf, "qc_stream_buf",
                    sizeof(struct qc_stream_buf));


/* Allocate a new stream descriptor with id <id>. The caller is responsible to
 * store the stream in the appropriate tree.
 *
 * Returns the newly allocated instance on success or else NULL.
 */
struct qc_stream_desc *qc_stream_desc_new(uint64_t id, void *ctx,
                                          struct quic_conn *qc)
{
	struct qc_stream_desc *stream;

	stream = pool_alloc(pool_head_quic_conn_stream);
	if (!stream)
		return NULL;

	stream->by_id.key = id;
	eb64_insert(&qc->streams_by_id, &stream->by_id);
	stream->qc = qc;

	stream->buf = NULL;
	LIST_INIT(&stream->buf_list);
	stream->buf_offset = 0;

	stream->acked_frms = EB_ROOT;
	stream->ack_offset = 0;
	stream->release = 0;
	stream->ctx = ctx;

	return stream;
}

/* Mark the stream descriptor <stream> as released. It will be freed as soon as
 * all its buffered data are acknowledged.
 */
void qc_stream_desc_release(struct qc_stream_desc *stream)
{
	/* A stream can be released only one time. */
	BUG_ON(stream->release);

	stream->release = 1;
	stream->ctx = NULL;

	if (LIST_ISEMPTY(&stream->buf_list)) {
		/* if no buffer left we can free the stream. */
		qc_stream_desc_free(stream);
	}
	else {
		/* A released stream does not use <stream.buf>. */
		stream->buf = NULL;
	}
}

/* Free the stream descriptor <stream> content. This function should be used
 * when all its data have been acknowledged or on full connection closing. It
 * must only be called after the stream is released.
 */
void qc_stream_desc_free(struct qc_stream_desc *stream)
{
	struct qc_stream_buf *buf, *buf_back;
	struct eb64_node *frm_node;
	unsigned int free_count = 0;

	/* This function only deals with released streams. */
	BUG_ON(!stream->release);

	/* free remaining stream buffers */
	list_for_each_entry_safe(buf, buf_back, &stream->buf_list, list) {
		if (!(b_data(&buf->buf))) {
			b_free(&buf->buf);
			LIST_DELETE(&buf->list);
			pool_free(pool_head_quic_conn_stream_buf, buf);

			++free_count;
		}
	}

	if (free_count)
		offer_buffers(NULL, free_count);

	/* qc_stream_desc might be freed before having received all its ACKs.
	 * This is the case if some frames were retransmitted.
	 */
	frm_node = eb64_first(&stream->acked_frms);
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
}

/* Return the current buffer of <stream>. May be NULL if not allocated. */
struct buffer *qc_stream_buf_get(struct qc_stream_desc *stream)
{
	if (!stream->buf)
		return NULL;

	return &stream->buf->buf;
}

/* Allocate a new current buffer for <stream>. This function is not allowed if
 * current buffer is not NULL prior to this call. The new buffer represents
 * stream payload at offset <offset>.
 *
 * Returns the buffer or NULL.
 */
struct buffer *qc_stream_buf_alloc(struct qc_stream_desc *stream,
                                   uint64_t offset)
{
	/* current buffer must be released first before allocate a new one. */
	BUG_ON(stream->buf);

	stream->buf_offset = offset;
	stream->buf = pool_alloc(pool_head_quic_conn_stream_buf);
	if (!stream->buf)
		return NULL;

	stream->buf->buf = BUF_NULL;
	LIST_APPEND(&stream->buf_list, &stream->buf->list);

	return &stream->buf->buf;
}

/* Release the current buffer of <stream>. It will be kept internally by
 * the <stream>. The current buffer cannot be NULL.
 */
void qc_stream_buf_release(struct qc_stream_desc *stream)
{
	/* current buffer already released */
	BUG_ON(!stream->buf);

	stream->buf = NULL;
	stream->buf_offset = 0;
}

/* Free the oldest buffer of <stream>. If the stream was already released and
 * does not references any buffers, it is freed. This function must only be
 * called if at least one buffer is present. Use qc_stream_desc_free() to free
 * a released stream.
 *
 * Returns 0 if the stream is not yet freed else 1.
 */
int qc_stream_desc_free_buf(struct qc_stream_desc *stream)
{
	struct qc_stream_buf *stream_buf;

	BUG_ON(LIST_ISEMPTY(&stream->buf_list) && !stream->buf);

	if (!LIST_ISEMPTY(&stream->buf_list)) {
		/* get first buffer from buf_list and remove it */
		stream_buf = LIST_NEXT(&stream->buf_list, struct qc_stream_buf *,
		                       list);
		LIST_DELETE(&stream_buf->list);
	}
	else {
		stream_buf = stream->buf;
		stream->buf = NULL;
	}

	b_free(&stream_buf->buf);
	pool_free(pool_head_quic_conn_stream_buf, stream_buf);

	offer_buffers(NULL, 1);

	/* If qc_stream_desc is released and does not contains any buffers, we
	 * can free it now.
	 */
	if (stream->release && LIST_ISEMPTY(&stream->buf_list)) {
		qc_stream_desc_free(stream);
		return 1;
	}

	return 0;
}
