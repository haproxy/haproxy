#ifndef _HAPROXY_QUIC_STREAM_H_
#define _HAPROXY_QUIC_STREAM_H_

#ifdef USE_QUIC

#include <haproxy/mux_quic-t.h>
#include <haproxy/quic_stream-t.h>

struct quic_conn;

struct qc_stream_desc *qc_stream_desc_new(uint64_t id, enum qcs_type, void *ctx,
                                          struct quic_conn *qc);
void qc_stream_desc_release(struct qc_stream_desc *stream, uint64_t final_size);
int qc_stream_desc_ack(struct qc_stream_desc **stream, size_t offset, size_t len);
void qc_stream_desc_free(struct qc_stream_desc *stream, int closing);

struct buffer *qc_stream_buf_get(struct qc_stream_desc *stream);
struct buffer *qc_stream_buf_alloc(struct qc_stream_desc *stream,
                                   uint64_t offset, int *avail);
void qc_stream_buf_release(struct qc_stream_desc *stream);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_H_ */
