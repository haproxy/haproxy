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


static void qc_stream_buf_free(struct qc_stream_desc *stream,
                               struct qc_stream_buf **stream_buf)
{
	struct quic_conn *qc = stream->qc;
	struct buffer *buf = &(*stream_buf)->buf;

	LIST_DEL_INIT(&(*stream_buf)->list);

	/* Reset current buf ptr if deleted instance is the same one. */
	if (*stream_buf == stream->buf)
		stream->buf = NULL;

	b_free(buf);
	offer_buffers(NULL, 1);
	pool_free(pool_head_quic_stream_buf, *stream_buf);
	*stream_buf = NULL;

	/* notify MUX about available buffers. */
	--qc->stream_buf_count;
	if (qc->mux_state == QC_MUX_READY) {
		/* notify MUX about available buffers.
		 *
		 * TODO several streams may be woken up even if a single buffer
		 * is available for now.
		 */
		while (qcc_notify_buf(qc->qcc))
			;
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
	stream->release = 0;
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
	BUG_ON(stream->release);

	stream->release = 1;
	stream->ctx = NULL;

	if (stream->buf) {
		struct qc_stream_buf *stream_buf = stream->buf;
		struct buffer *buf = &stream_buf->buf;
		const uint64_t tail_offset =
		  MAX(stream->buf_offset, stream->ack_offset) + b_data(buf);

		/* final_size cannot be greater than all currently stored data. */
		BUG_ON(final_size > tail_offset);

		/* Remove unsent data from current buffer. */
		if (final_size < tail_offset) {
			b_sub(buf, tail_offset - final_size);
			/* Remove buffer is all ACK already received. */
			if (!b_data(buf))
				qc_stream_buf_free(stream, &stream_buf);
		}

		/* A released stream does not use <stream.buf>. */
		stream->buf = NULL;
	}

	if (LIST_ISEMPTY(&stream->buf_list)) {
		/* if no buffer left we can free the stream. */
		qc_stream_desc_free(stream, 0);
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
int qc_stream_desc_ack(struct qc_stream_desc **stream, size_t offset, size_t len)
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

	/* Free oldest buffer if all data acknowledged. */
	if (!b_data(buf)) {
		qc_stream_buf_free(s, &stream_buf);

		/* Free stream instance if already released and no buffers left. */
		if (s->release && LIST_ISEMPTY(&s->buf_list)) {
			qc_stream_desc_free(s, 0);
			*stream = NULL;
		}
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

	/* This function only deals with released streams. */
	BUG_ON(!stream->release);

	/* free remaining stream buffers */
	list_for_each_entry_safe(buf, buf_back, &stream->buf_list, list) {
		if (!(b_data(&buf->buf)) || closing) {
			b_free(&buf->buf);
			LIST_DELETE(&buf->list);
			pool_free(pool_head_quic_stream_buf, buf);

			++free_count;
		}
	}

	if (free_count) {
		offer_buffers(NULL, free_count);

		qc->stream_buf_count -= free_count;
		if (qc->mux_state == QC_MUX_READY) {
			/* notify MUX about available buffers.
			 *
			 * TODO several streams may be woken up even if a single buffer
			 * is available for now.
			 */
			while (qcc_notify_buf(qc->qcc))
				;
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

/* Returns the count of available buffer left for <qc>. */
static int qc_stream_buf_avail(struct quic_conn *qc)
{
	BUG_ON(qc->stream_buf_count > global.tune.quic_streams_buf);
	return global.tune.quic_streams_buf - qc->stream_buf_count;
}

/* Allocate a new current buffer for <stream>. The buffer limit count for the
 * connection is checked first. This function is not allowed if current buffer
 * is not NULL prior to this call. The new buffer represents stream payload at
 * offset <offset>.
 *
 * Returns the buffer or NULL on error. Caller may check <avail> to ensure if
 * the connection buffer limit was reached or a fatal error was encountered.
 */
struct buffer *qc_stream_buf_alloc(struct qc_stream_desc *stream,
                                   uint64_t offset, int *avail)
{
	struct quic_conn *qc = stream->qc;

	/* current buffer must be released first before allocate a new one. */
	BUG_ON(stream->buf);

	*avail = qc_stream_buf_avail(qc);
	if (!*avail)
		return NULL;

	stream->buf_offset = offset;
	stream->buf = pool_alloc(pool_head_quic_stream_buf);
	if (!stream->buf)
		return NULL;

	++qc->stream_buf_count;

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
