#ifndef _HAPROXY_QUIC_STREAM_H_
#define _HAPROXY_QUIC_STREAM_H_

#ifdef USE_QUIC

#include <haproxy/quic_stream-t.h>

struct quic_conn;

struct qc_stream_desc *qc_stream_desc_new(uint64_t id, void *ctx,
                                          struct quic_conn *qc);
void qc_stream_desc_release(struct qc_stream_desc *stream);
int qc_stream_desc_free(struct qc_stream_desc *stream);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_H_ */
