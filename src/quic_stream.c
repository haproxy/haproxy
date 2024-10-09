#include <haproxy/quic_stream.h>

#include <import/eb64tree.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/dynbuf.h>
#include <haproxy/errors.h>
#include <haproxy/mux_quic.h>
#include <haproxy/pool.h>
#include <haproxy/quic_conn.h>
#include <haproxy/task.h>

DECLARE_STATIC_POOL(pool_head_quic_stream_desc, "qc_stream_desc",
                    sizeof(struct qc_stream_desc));
DECLARE_STATIC_POOL(pool_head_quic_stream_buf, "qc_stream_buf",
                    sizeof(struct qc_stream_buf));
DECLARE_STATIC_POOL(pool_head_quic_stream_ack, "qc_stream_ack",
                    sizeof(struct qc_stream_ack));

static struct pool_head *pool_head_sbuf;

static void qc_stream_buf_free(struct qc_stream_desc *stream,
                               struct qc_stream_buf **stream_buf)
{
	struct buffer *buf = &(*stream_buf)->buf;
	uint64_t room;

	/* Caller is responsible to remove buffered ACK frames before destroying a buffer instance. */
	BUG_ON(!eb_is_empty(&(*stream_buf)->ack_tree));

	eb64_delete(&(*stream_buf)->offset_node);

	if (*stream_buf == stream->buf) {
		/* Reset current buffer ptr. */
		stream->buf = NULL;
		room = b_size(buf);
	}
	else {
		/* For released buffer, acked data were already notified. */
		room = b_data(buf);
	}

	if ((*stream_buf)->sbuf) {
		pool_free(pool_head_sbuf, buf->area);
	}
	else {
		b_free(buf);
		offer_buffers(NULL, 1);
	}
	pool_free(pool_head_quic_stream_buf, *stream_buf);
	*stream_buf = NULL;

	/* notify MUX about available buffers. */
	if (stream->notify_room && room)
		stream->notify_room(stream, room);
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
	stream->buf_tree = EB_ROOT_UNIQUE;
	stream->buf_offset = 0;

	stream->ack_offset = 0;
	stream->flags = 0;
	stream->ctx = ctx;
	stream->notify_send = NULL;
	stream->notify_room = NULL;

	return stream;
}

/* Mark the stream descriptor <stream> as released. It will be freed as soon as
 * all its buffered data are acknowledged.
 *
 * <final_size> corresponds to the last offset sent for this stream. If there
 * is unsent data present, they will be remove first to guarantee that buffer
 * is freed after receiving all acknowledges.
 *
 * It is expected that upper layer instance related to <stream> may disappear
 * after this operation. As such, <new_ctx> must be set to reassociate <stream>
 * for notifications.
 */
void qc_stream_desc_release(struct qc_stream_desc *stream,
                            uint64_t final_size, void *new_ctx)
{
	/* A stream can be released only one time. */
	BUG_ON(stream->flags & QC_SD_FL_RELEASE);

	stream->flags |= QC_SD_FL_RELEASE;
	stream->ctx = new_ctx;

	/* Release active buffer if still present on streamdesc release. */
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

		/* Release active buffer, or delete it immediatly if there is
		 * no data to acknowledge. Both functions will reset active
		 * buf pointer and invoke <notify_room> if necessary.
		 */
		if (!b_data(buf))
			qc_stream_buf_free(stream, &stream_buf);
		else
			qc_stream_buf_release(stream);
	}

	if (qc_stream_desc_done(stream)) {
		/* if no buffer left we can free the stream. */
		qc_stream_desc_free(stream, 0);
	}
}

static int qc_stream_buf_is_released(const struct qc_stream_buf *buf,
                                     const struct qc_stream_desc *stream)
{
	return buf != stream->buf;
}

/* Store an out-of-order stream ACK for <buf>. This corresponds to a frame
 * starting at <offset> of length <len> with <fin> set if FIN is present.
 *
 * Returns the count of newly acknowledged data, or a negative error code if
 * the new range cannot be stored due to a fatal error.
 */
static int qc_stream_buf_store_ack(struct qc_stream_buf *buf,
                                   struct qc_stream_desc *stream,
                                   uint64_t offset, uint64_t len, int fin)
{
	struct eb64_node *less, *more;
	struct qc_stream_ack *ack, *ack_less = NULL, *ack_more = NULL;
	int newly_acked = len;

	more = eb64_lookup_ge(&buf->ack_tree, offset);
	if (more)
		ack_more = eb64_entry(more, struct qc_stream_ack, offset_node);

	/* Ranges are always merged before insertion so there could be no
	 * overlapping or just contiguous different ranges. No need to use
	 * <ack_less> if an existing range already starts at requested offset.
	 */
	less = eb64_lookup_le(&buf->ack_tree, offset);
	if (less && more != less)
		ack_less = eb64_entry(less, struct qc_stream_ack, offset_node);

	/* Ensure that offset:len range has not been already acknowledged, at least partially. */
	if ((ack_more && offset == ack_more->offset_node.key && offset + len <= ack_more->offset_node.key + ack_more->len) ||
	    (ack_less && ack_less->offset_node.key + ack_less->len >= offset + len)) {
		newly_acked = 0;
		goto end;
	}

	/* If current range is contiguous or overlapping with one or several
	 * superior ranges, extend current range and delete superior ranges.
	 */
	while (ack_more && offset + len >= ack_more->offset_node.key) {
		struct eb64_node *next;

		if (offset + len < ack_more->offset_node.key + ack_more->len) {
			newly_acked -= (offset + len) - ack_more->offset_node.key;
			/* Extend current range to cover the next entry. */
			len += (ack_more->offset_node.key + ack_more->len) - (offset + len);
			fin = ack_more->fin;
		}
		else {
			newly_acked -= ack_more->len;
		}

		/* Remove the next range as it is covered by the current one. */
		next = eb64_next(more);
		eb64_delete(more);
		pool_free(pool_head_quic_stream_ack, ack_more);

		more = next;
		ack_more = more ? eb64_entry(more, struct qc_stream_ack, offset_node) : NULL;
	}

	/* If there is a contiguous or overlapping smaller range, extend it
	 * without adding a new entry.
	 */
	if (ack_less &&
	    ack_less->offset_node.key + ack_less->len >= offset) {
		newly_acked -= (ack_less->offset_node.key + ack_less->len) - offset;
		/* Extend previous entry to fully cover the current range. */
		ack_less->len += (offset + len) -
		                 (ack_less->offset_node.key + ack_less->len);
		ack_less->fin = fin;
	}
	else {
		/* Store a new ACK stream range. */
		ack = pool_alloc(pool_head_quic_stream_ack);
		if (!ack) {
			newly_acked = -1;
			goto end;
		}

		ack->offset_node.key = offset;
		ack->len = len;
		ack->fin = fin;

		eb64_insert(&buf->ack_tree, &ack->offset_node);
	}

	buf->room += newly_acked;
	if (stream->notify_room && qc_stream_buf_is_released(buf, stream))
		stream->notify_room(stream, newly_acked);

 end:
	return newly_acked;
}

/* Acknowledges data for buffer <buf> attached to <stream> instance. This covers
 * the range strating at <offset> and of length <len>, with <fin> sets for the
 * last stream frame.
 *
 * Returns <buf> if there is still data to acknowledge or buffered ACK to
 * consume after completing the operation. Else, the next buffer instance of
 * stream is returned if it exists or NULL in the contrary case.
 */
static struct qc_stream_buf *qc_stream_buf_ack(struct qc_stream_buf *buf,
                                               struct qc_stream_desc *stream,
                                               uint64_t offset, uint64_t len, int fin)
{
	uint64_t diff;

	/* This function does not deal with out-of-order ACK. */
	BUG_ON(offset > stream->ack_offset);

	if (offset + len > stream->ack_offset) {
		diff = offset + len - stream->ack_offset;
		b_del(&buf->buf, diff);
		stream->ack_offset += diff;

		/* notify room from acked data if buffer has been released. */
		if (stream->notify_room && qc_stream_buf_is_released(buf, stream)) {
			if (diff >= buf->room) {
				diff -= buf->room;
				buf->room = 0;
				stream->notify_room(stream, diff);
			}
			else {
				buf->room -= diff;
			}
		}
	}

	if (fin) {
		/* Mark FIN as acknowledged. */
		stream->flags &= ~QC_SD_FL_WAIT_FOR_FIN;
	}

	if (!b_data(&buf->buf) && eb_is_empty(&buf->ack_tree)) {
		qc_stream_buf_free(stream, &buf);
		/* Retrieve next buffer instance. */
		buf = !eb_is_empty(&stream->buf_tree) ?
		  eb64_entry(eb64_first(&stream->buf_tree), struct qc_stream_buf, offset_node) :
		  NULL;
	}

	return buf;
}

/* Consume buffered ACK starting at <stream_buf>. If all buffer data is
 * removed, <stream_buf> is freed and consume will be conducted for following
 * streambufs from <stream> if present.
 */
static void qc_stream_buf_consume(struct qc_stream_buf *stream_buf,
                                  struct qc_stream_desc *stream)
{
	struct qc_stream_ack *ack;
	struct eb64_node *ack_node;

	ack_node = eb64_first(&stream_buf->ack_tree);
	while (ack_node) {
		ack = eb64_entry(ack_node, struct qc_stream_ack, offset_node);
		if (ack->offset_node.key > stream->ack_offset)
			break;

		/* For released buf, room count is decremented on buffered ACK consumption. */
		if (stream_buf == stream->buf)
			stream_buf->room = MAX((int64_t)(stream_buf->room - ack->len), 0);

		/* Delete range before acknowledged it. This prevents BUG_ON()
		 * on non-empty ack_tree tree when stream_buf is empty and removed.
		 */
		eb64_delete(ack_node);
		stream_buf = qc_stream_buf_ack(stream_buf, stream,
		                               ack->offset_node.key, ack->len, ack->fin);
		pool_free(pool_head_quic_stream_ack, ack);

		ack_node = stream_buf ? eb64_first(&stream_buf->ack_tree) : NULL;
	}
}

/* Acknowledge <frm> STREAM frame whose content is managed by <stream>
 * descriptor.
 *
 * Returns 0 if the frame has been handled and can be removed.
 * Returns a positive value if acknowledgement is out-of-order and
 * corresponding STREAM frame has been buffered.
 * Returns a negative value on fatal error.
 */
int qc_stream_desc_ack(struct qc_stream_desc *stream,
                       uint64_t offset, uint64_t len, int fin)
{
	struct qc_stream_buf *stream_buf = NULL;
	struct eb64_node *buf_node;
	int ret = 0;

	/* Cannot advertise FIN for an inferior data range. */
	BUG_ON(fin && offset + len < stream->ack_offset);

	/* Do nothing for offset + len < stream->ack_offset as data were
	 * already acknowledged and removed.
	 */

	if (!len) {
		BUG_ON(!fin); /* An empty STREAM frame is only needed for a late FIN reporting. */

		/* Empty STREAM frame with FIN can be acknowledged out-of-order. */
		stream->flags &= ~QC_SD_FL_WAIT_FOR_FIN;
	}
	else if (offset > stream->ack_offset) {
		buf_node = eb64_lookup_le(&stream->buf_tree, offset);
		BUG_ON(!buf_node); /* Cannot acknowledged a STREAM frame for a non existing buffer. */
		stream_buf = eb64_entry(buf_node, struct qc_stream_buf, offset_node);
		ret = qc_stream_buf_store_ack(stream_buf, stream, offset, len, fin);
	}
	else if (offset + len > stream->ack_offset) {
		/* Buf list cannot be empty if there is still unacked data. */
		BUG_ON(eb_is_empty(&stream->buf_tree));

		/* get oldest buffer from buf tree */
		stream_buf = eb64_entry(eb64_first(&stream->buf_tree), struct qc_stream_buf, offset_node);
		stream_buf = qc_stream_buf_ack(stream_buf, stream, offset, len, fin);

		/* some data were acknowledged, try to consume buffered ACKs */
		if (stream_buf)
			qc_stream_buf_consume(stream_buf, stream);
	}

	return ret;
}

/* Free the stream descriptor <stream> content. This function should be used
 * when all its data have been acknowledged or on full connection closing if <closing>
 * boolean is set to 1. It must only be called after the stream is released.
 */
void qc_stream_desc_free(struct qc_stream_desc *stream, int closing)
{
	struct qc_stream_buf *buf;
	struct eb64_node *ack_node, *buf_node;
	unsigned int free_count = 0;

	/* This function only deals with released streams. */
	BUG_ON(!(stream->flags & QC_SD_FL_RELEASE));

	/* free remaining stream buffers */
	while (!eb_is_empty(&stream->buf_tree)) {
		buf_node = eb64_first(&stream->buf_tree);
		buf = eb64_entry(buf_node, struct qc_stream_buf, offset_node);

		/* qc_stream_desc_free() can only be used after all data is
		 * acknowledged or on connection shutdown. In the contrary
		 * case, MUX must be notified about room available.
		 */
		BUG_ON(b_data(&buf->buf) && !closing);

		/* qc_stream_desc might be freed before having received all its ACKs. */
		while (!eb_is_empty(&buf->ack_tree)) {
			struct qc_stream_ack *ack;

			ack_node = eb64_first(&buf->ack_tree);
			eb64_delete(ack_node);

			ack = eb64_entry(ack_node, struct qc_stream_ack, offset_node);
			pool_free(pool_head_quic_stream_ack, ack);
		}

		if (buf->sbuf)
			pool_free(pool_head_sbuf, buf->buf.area);
		else
			b_free(&buf->buf);

		eb64_delete(&buf->offset_node);
		pool_free(pool_head_quic_stream_buf, buf);
		++free_count;
	}

	if (free_count)
		offer_buffers(NULL, free_count);

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
                                   uint64_t offset, int small)
{
	/* current buffer must be released first before allocate a new one. */
	BUG_ON(stream->buf);

	stream->buf_offset = offset;
	stream->buf = pool_alloc(pool_head_quic_stream_buf);
	if (!stream->buf)
		return NULL;

	stream->buf->ack_tree = EB_ROOT_UNIQUE;
	stream->buf->room = 0;
	stream->buf->buf = BUF_NULL;
	stream->buf->offset_node.key = offset;

	if (!small) {
		stream->buf->sbuf = 0;
		if (!b_alloc(&stream->buf->buf, DB_MUX_TX)) {
			pool_free(pool_head_quic_stream_buf, stream->buf);
			stream->buf = NULL;
			return NULL;
		}
	}
	else {
		char *area;

		if (!(area = pool_alloc(pool_head_sbuf))) {
			pool_free(pool_head_quic_stream_buf, stream->buf);
			stream->buf = NULL;
			return NULL;
		}

		stream->buf->sbuf = 1;
		stream->buf->buf = b_make(area, global.tune.bufsize_small, 0, 0);
	}

	eb64_insert(&stream->buf_tree, &stream->buf->offset_node);

	return &stream->buf->buf;
}

/* Free current <stream> buffer and allocate a new one. This function is reserved
 * to convert a small buffer to a standard one.
 *
 * Returns the buffer or NULL on error.
 */
struct buffer *qc_stream_buf_realloc(struct qc_stream_desc *stream)
{
	/* This function is reserved to convert a big buffer to a smaller one. */
	BUG_ON(!stream->buf || !stream->buf->sbuf);

	/* This function can only be used if targetted buffer is empty. */
	BUG_ON(b_data(&stream->buf->buf));

	/* Release buffer */
	pool_free(pool_head_sbuf, stream->buf->buf.area);
	stream->buf->buf = BUF_NULL;
	stream->buf->sbuf = 0;

	if (!b_alloc(&stream->buf->buf, DB_MUX_TX)) {
		eb64_delete(&stream->buf->offset_node);
		pool_free(pool_head_quic_stream_buf, stream->buf);
		stream->buf = NULL;
		return NULL;
	}

	return &stream->buf->buf;
}

/* Release the current buffer of <stream>. It will be kept internally by
 * the <stream>. The current buffer cannot be NULL.
 */
void qc_stream_buf_release(struct qc_stream_desc *stream)
{
	uint64_t room;

	/* current buffer already released */
	BUG_ON(!stream->buf);

	room = b_room(&stream->buf->buf) + stream->buf->room;
	stream->buf = NULL;
	stream->buf_offset = 0;

	/* Released buffer won't receive any new data. Reports non consumed
	 * space plus already stored out-of-order data range as available.
	 */
	if (stream->notify_room && room)
		stream->notify_room(stream, room);
}

static int create_sbuf_pool(void)
{
	if (global.tune.bufsize_small > global.tune.bufsize) {
		ha_warning("invalid small buffer size %d bytes which is greater to default bufsize %d bytes.\n",
		           global.tune.bufsize_small, global.tune.bufsize);
		return ERR_FATAL|ERR_ABORT;
	}

	pool_head_sbuf = create_pool("sbuf", global.tune.bufsize_small,
	                             MEM_F_SHARED|MEM_F_EXACT);
	if (!pool_head_sbuf) {
		ha_warning("error on small buffer pool allocation.\n");
		return ERR_FATAL|ERR_ABORT;
	}

	return ERR_NONE;
}

REGISTER_POST_CHECK(create_sbuf_pool);
