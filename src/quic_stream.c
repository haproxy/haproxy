#include <haproxy/quic_stream.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/dynbuf.h>
#include <haproxy/list.h>
#include <haproxy/mux_quic.h>
#include <haproxy/pool.h>
#include <haproxy/quic_conn.h>
#include <haproxy/task.h>

DECLARE_STATIC_POOL(pool_head_quic_stream_desc, "qc_stream_desc",
                    sizeof(struct qc_stream_desc));
DECLARE_STATIC_POOL(pool_head_quic_stream_buf, "qc_stream_buf",
                    sizeof(struct qc_stream_buf));


/* Returns true if nothing to ack yet for stream <s> including FIN bit. */
static inline int qc_stream_desc_done(const struct qc_stream_desc *s)
{
	return !(s->flags & QC_SD_FL_WAIT_FOR_FIN) && LIST_ISEMPTY(&s->buf_list);
}

static void qc_stream_buf_free(struct qc_stream_desc *stream,
                               struct qc_stream_buf **stream_buf)
{
	struct quic_conn *qc = stream->qc;
	struct buffer *buf = &(*stream_buf)->buf;
	uint64_t free_size;

	LIST_DEL_INIT(&(*stream_buf)->list);

	/* Reset current buf ptr if deleted instance is the same one. */
	if (*stream_buf == stream->buf)
		stream->buf = NULL;

	free_size = b_size(buf);
	b_free(buf);
	offer_buffers(NULL, 1);
	pool_free(pool_head_quic_stream_buf, *stream_buf);
	*stream_buf = NULL;

	/* notify MUX about available buffers. */
	if (qc->mux_state == QC_MUX_READY) {
		if (!(stream->flags & QC_SD_FL_OOB_BUF)) {
			/* notify MUX about available buffers. */
			qcc_notify_buf(qc->qcc, free_size);
		}
	}
}

/* Allocate a new stream descriptor with id <id>. The caller is responsible to
 * store the stream in the appropriate tree. -1 special value must be used for
 * a CRYPTO data stream, the type being ignored.
 *
 * Returns the newly allocated instance on success or else NULL.
 */
struct qc_stream_desc *qc_stream_desc_new(uint64_t id, enum qcs_type type, void *ctx,
                                          struct quic_conn *qc)
{
	struct qc_stream_desc *stream;

	stream = pool_alloc(pool_head_quic_stream_desc);
	if (!stream)
		return NULL;

	if (id == (uint64_t)-1) {
		stream->by_id.key = (uint64_t)-1;
	}
	else {
		stream->by_id.key = id;
		eb64_insert(&qc->streams_by_id, &stream->by_id);
		qc->rx.strms[type].nb_streams++;
	}
	stream->qc = qc;

	stream->buf = NULL;
	LIST_INIT(&stream->buf_list);
	stream->buf_offset = 0;

	stream->acked_frms = EB_ROOT;
	stream->ack_offset = 0;
	stream->flags = 0;
	stream->ctx = ctx;

	return stream;
}

/* Mark the stream descriptor <stream> as released. It will be freed as soon as
 * all its buffered data are acknowledged. Does nothing if <stream> is already
 * NULL.
 *
 * <final_size> corresponds to the last offset sent for this stream. If there
 * is unsent data present, they will be remove first to guarantee that buffer
 * is freed after receiving all acknowledges.
 */
void qc_stream_desc_release(struct qc_stream_desc *stream,
                            uint64_t final_size)
{
	if (!stream)
		return;

	/* A stream can be released only one time. */
	BUG_ON(stream->flags & QC_SD_FL_RELEASE);

	stream->flags |= QC_SD_FL_RELEASE;
	stream->ctx = NULL;

	if (stream->buf) {
		struct qc_stream_buf *stream_buf = stream->buf;
		struct buffer *buf = &stream_buf->buf;
		const uint64_t tail_offset =
		  MAX(stream->buf_offset, stream->ack_offset) + b_data(buf);

		/* final_size cannot be greater than all currently stored data. */
		BUG_ON(final_size > tail_offset);

		/* Remove unsent data from current buffer. */
		if (final_size < tail_offset)
			b_sub(buf, tail_offset - final_size);

		if (!b_data(buf))
			qc_stream_buf_free(stream, &stream_buf);

		/* A released stream does not use <stream.buf>. */
		stream->buf = NULL;
	}

	if (qc_stream_desc_done(stream)) {
		/* if no buffer left we can free the stream. */
		qc_stream_desc_free(stream, 0);
	}
}

/* Acknowledge data at <offset> of length <len> for <stream> with <fin> set for
 * the final data. After data removal, if the stream does not contains data
 * any more and is already released, the instance stream is freed. <stream> is
 * set to NULL to indicate this.
 *
 * Returns the count of byte removed from stream. Do not forget to check if
 * <stream> is NULL after invocation.
 */
int qc_stream_desc_ack(struct qc_stream_desc **stream, size_t offset, size_t len,
                       int fin)
{
	struct qc_stream_desc *s = *stream;
	struct qc_stream_buf *stream_buf = NULL;
	struct buffer *buf = NULL;
	size_t diff;

	/* Cannot advertise FIN for an inferior data range. */
	BUG_ON(fin && offset + len < s->ack_offset);

	/* No support now for out-of-order ACK reporting. */
	BUG_ON(offset > s->ack_offset);

	if (offset + len < s->ack_offset)
		return 0;

	diff = offset + len - s->ack_offset;
	if (diff) {
		/* Buf list cannot be empty if there is still unacked data. */
		BUG_ON(LIST_ISEMPTY(&s->buf_list));

		/* get oldest buffer from buf_list */
		stream_buf = LIST_NEXT(&s->buf_list, struct qc_stream_buf *, list);
		buf = &stream_buf->buf;

		s->ack_offset += diff;
		b_del(buf, diff);

		/* Free oldest buffer if all data acknowledged. */
		if (!b_data(buf)) {
			qc_stream_buf_free(s, &stream_buf);
			buf = NULL;
		}
	}

	if (fin) {
		/* Mark FIN as acknowledged. */
		s->flags &= ~QC_SD_FL_WAIT_FOR_FIN;
	}

	/* Free stream instance if already released and everything acknowledged. */
	if ((s->flags & QC_SD_FL_RELEASE) && qc_stream_desc_done(s)) {
		qc_stream_desc_free(s, 0);
		*stream = NULL;
	}

	return diff;
}

/* Free the stream descriptor <stream> content. This function should be used
 * when all its data have been acknowledged or on full connection closing if <closing>
 * boolean is set to 1. It must only be called after the stream is released.
 */
void qc_stream_desc_free(struct qc_stream_desc *stream, int closing)
{
	struct qc_stream_buf *buf, *buf_back;
	struct quic_conn *qc = stream->qc;
	struct eb64_node *frm_node;
	unsigned int free_count = 0;
	uint64_t free_size = 0;

	/* This function only deals with released streams. */
	BUG_ON(!(stream->flags & QC_SD_FL_RELEASE));

	/* free remaining stream buffers */
	list_for_each_entry_safe(buf, buf_back, &stream->buf_list, list) {
		if (!(b_data(&buf->buf)) || closing) {
			free_size += b_size(&buf->buf);
			b_free(&buf->buf);
			LIST_DELETE(&buf->list);
			pool_free(pool_head_quic_stream_buf, buf);
			++free_count;
		}
	}

	if (free_count) {
		offer_buffers(NULL, free_count);

		if (qc->mux_state == QC_MUX_READY) {
			if (!(stream->flags & QC_SD_FL_OOB_BUF)) {
				/* notify MUX about available buffers. */
				qcc_notify_buf(qc->qcc, free_size);
			}
		}
	}

	/* qc_stream_desc might be freed before having received all its ACKs.
	 * This is the case if some frames were retransmitted.
	 */
	frm_node = eb64_first(&stream->acked_frms);
	while (frm_node) {
		struct qf_stream *strm_frm;
		struct quic_frame *frm;

		strm_frm = eb64_entry(frm_node, struct qf_stream, offset);

		frm_node = eb64_next(frm_node);
		eb64_delete(&strm_frm->offset);

		frm = container_of(strm_frm, struct quic_frame, stream);
		qc_release_frm(qc, frm);
	}

	if (stream->by_id.key != (uint64_t)-1)
		eb64_delete(&stream->by_id);
	pool_free(pool_head_quic_stream_desc, stream);
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
 * Returns the buffer or NULL on error.
 */
struct buffer *qc_stream_buf_alloc(struct qc_stream_desc *stream,
                                   uint64_t offset)
{
	/* current buffer must be released first before allocate a new one. */
	BUG_ON(stream->buf);

	stream->buf_offset = offset;
	stream->buf = pool_alloc(pool_head_quic_stream_buf);
	if (!stream->buf)
		return NULL;

	stream->buf->buf = BUF_NULL;
	if (!b_alloc(&stream->buf->buf, DB_MUX_TX)) {
		pool_free(pool_head_quic_stream_buf, stream->buf);
		stream->buf = NULL;
		return NULL;
	}

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
