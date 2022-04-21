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

/* Acknowledge data at <offset> of length <len> for <stream>. It is handled
 * only if it covers a range corresponding to stream.ack_offset. After data
 * removal, if the stream does not contains data any more and is already
 * released, the instance stream is freed. <stream> is set to NULL to indicate
 * this.
 *
 * Returns the count of byte removed from stream. Do not forget to check if
 * <stream> is NULL after invocation.
 */
int qc_stream_desc_ack(struct qc_stream_desc **stream, size_t offset,
                       size_t len)
{
	struct qc_stream_desc *s = *stream;
	struct qc_stream_buf *stream_buf;
	struct buffer *buf;
	size_t diff;

	if (offset + len <= s->ack_offset || offset > s->ack_offset)
		return 0;

	/* There must be at least a buffer or we must not report an ACK. */
	BUG_ON(LIST_ISEMPTY(&s->buf_list));

	/* get oldest buffer from buf_list */
	stream_buf = LIST_NEXT(&s->buf_list, struct qc_stream_buf *, list);
	buf = &stream_buf->buf;

	diff = offset + len - s->ack_offset;
	s->ack_offset += diff;
	b_del(buf, diff);

	/* nothing more to do if buf still not empty. */
	if (b_data(buf))
		return diff;

	/* buf is empty and can now be freed. Do not forget to reset current
	 * buf ptr if we were working on it.
	 */
	LIST_DELETE(&stream_buf->list);
	if (stream_buf == s->buf) {
		/* current buf must always be last entry in buflist */
		BUG_ON(!LIST_ISEMPTY(&s->buf_list));
		s->buf = NULL;
	}

	b_free(buf);
	pool_free(pool_head_quic_conn_stream_buf, stream_buf);
	offer_buffers(NULL, 1);

	/* Free stream instance if already released and no buffers left. */
	if (s->release && LIST_ISEMPTY(&s->buf_list)) {
		qc_stream_desc_free(s);
		*stream = NULL;
	}

	return diff;
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
