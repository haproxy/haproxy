#ifndef _HAPROXY_QUIC_STREAM_H_
#define _HAPROXY_QUIC_STREAM_H_

#ifdef USE_QUIC

#include <haproxy/mux_quic-t.h>
#include <haproxy/quic_stream-t.h>

struct quic_conn;

struct qc_stream_desc *qc_stream_desc_new(uint64_t id, enum qcs_type, void *ctx,
                                          struct quic_conn *qc);
void qc_stream_desc_release(struct qc_stream_desc *stream, uint64_t final_size,
                            void *new_ctx);
int qc_stream_desc_ack(struct qc_stream_desc *stream,
                       uint64_t offset, uint64_t len, int fin);
void qc_stream_desc_free(struct qc_stream_desc *stream, int closing);

struct buffer *qc_stream_buf_get(struct qc_stream_desc *stream);
struct buffer *qc_stream_buf_alloc(struct qc_stream_desc *stream,
                                   uint64_t offset, int small);
struct buffer *qc_stream_buf_realloc(struct qc_stream_desc *stream);
void qc_stream_buf_release(struct qc_stream_desc *stream);

/* Returns true if nothing to ack yet for stream <s> including FIN bit. */
static inline int qc_stream_desc_done(const struct qc_stream_desc *s)
{
	return (s->flags & (QC_SD_FL_RELEASE|QC_SD_FL_WAIT_FOR_FIN)) == QC_SD_FL_RELEASE &&
	       eb_is_empty(&s->buf_tree);
}

/* Reports emission of STREAM frame starting at <offset> and of length <len>,
 * related to <stream> data storage.
 */
static inline void qc_stream_desc_send(struct qc_stream_desc *stream,
                                       uint64_t offset, uint64_t len)
{
	if (stream->notify_send)
		stream->notify_send(stream, len, offset);
}

/* Subscribe for send notification on <stream>. */
static inline void qc_stream_desc_sub_send(struct qc_stream_desc *stream,
                                           void (*cb)(struct qc_stream_desc *s, uint64_t offset, uint64_t len))
{
	stream->notify_send = cb;
}

/* Subscribe for room notification on <stream>. */
static inline void qc_stream_desc_sub_room(struct qc_stream_desc *stream,
                                           void (*cb)(struct qc_stream_desc *s, uint64_t offset))
{
	stream->notify_room = cb;
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_H_ */
