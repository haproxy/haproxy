#ifndef _HAPROXY_MUX_QUIC_T_H
#define _HAPROXY_MUX_QUIC_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <import/ebtree-t.h>

#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h>

/* Stream types */
enum qcs_type {
	QCS_CLT_BIDI,
	QCS_SRV_BIDI,
	QCS_CLT_UNI,
	QCS_SRV_UNI,

	/* Must be the last one */
	QCS_MAX_TYPES
};

#define QC_CF_CC_RECV 0x00000001

struct qcc {
	struct connection *conn;
	uint32_t flags; /* QC_CF_* */

	struct {
		uint64_t max_streams; /* maximum number of concurrent streams */
		uint64_t largest_id;  /* Largest ID of the open streams */
		uint64_t nb_streams;  /* Number of open streams */
		struct {
			uint64_t max_data; /* Maximum number of bytes which may be received */
			uint64_t bytes;    /* Number of bytes received */
		} rx;
		struct {
			uint64_t max_data; /* Maximum number of bytes which may be sent */
			uint64_t bytes;    /* Number of bytes sent */
		} tx;
	} strms[QCS_MAX_TYPES];

	struct {
		uint64_t max_data; /* Maximum number of bytes which may be received */
	} rx;
	struct {
		uint64_t max_data; /* Maximum number of bytes which may be sent */
	} tx;

	struct eb_root streams_by_id; /* all active streams by their ID */

	struct wait_event wait_event;  /* To be used if we're waiting for I/Os */
	struct wait_event *subs;

	const struct qcc_app_ops *app_ops;
	void *ctx; /* Application layer context */
};

#define QC_SF_NONE              0x00000000
#define QC_SF_FIN_STREAM        0x00000001  // FIN bit must be set for last frame of the stream
#define QC_SF_BLK_MROOM         0x00000002  // app layer is blocked waiting for room in the qcs.tx.buf
#define QC_SF_DETACH            0x00000004  // cs is detached but there is remaining data to send

struct qcs {
	struct qcc *qcc;
	struct conn_stream *cs;
	uint32_t flags;      /* QC_SF_* */

	struct {
		struct eb_root frms; /* received frames ordered by their offsets */
		uint64_t offset; /* the current offset of received data */
		struct buffer buf; /* receive buffer, always valid (buf_empty or real buffer) */
	} rx;
	struct {
		uint64_t offset;   /* the current offset of received data */
		struct eb_root acked_frms; /* acked frames ordered by their offsets */
		uint64_t ack_offset; /* last acked ordered byte offset */
		struct buffer buf; /* transmit buffer before sending via xprt */
		struct buffer xprt_buf; /* buffer for xprt sending, cleared on ACK. */
	} tx;

	struct eb64_node by_id; /* place in qcc's streams_by_id */

	struct wait_event wait_event;
	struct wait_event *subs;
};

/* QUIC application layer operations */
struct qcc_app_ops {
	int (*init)(struct qcc *qcc);
	int (*attach_ruqs)(struct qcs *qcs, void *ctx);
	int (*decode_qcs)(struct qcs *qcs, int fin, void *ctx);
	size_t (*snd_buf)(struct conn_stream *cs, struct buffer *buf, size_t count, int flags);
	int (*finalize)(void *ctx);
};

#endif /* USE_QUIC */

#endif /* _HAPROXY_MUX_QUIC_T_H */
