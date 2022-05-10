#ifndef _HAPROXY_MUX_QUIC_T_H
#define _HAPROXY_MUX_QUIC_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <import/ebtree-t.h>

#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/list-t.h>
#include <haproxy/quic_stream-t.h>
#include <haproxy/conn_stream-t.h>

/* Stream types */
enum qcs_type {
	QCS_CLT_BIDI,
	QCS_SRV_BIDI,
	QCS_CLT_UNI,
	QCS_SRV_UNI,

	/* Must be the last one */
	QCS_MAX_TYPES
};

#define QC_CF_BLK_MFCTL 0x00000001 /* sending blocked due to connection flow-control */
#define QC_CF_CONN_FULL 0x00000002 /* no stream buffers available on connection */

struct qcc {
	struct connection *conn;
	uint64_t nb_cs; /* number of attached conn-streams */
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

	/* flow-control fields set by us enforced on our side. */
	struct {
		uint64_t ms_bidi_init; /* max initial sub-ID of bidi stream allowed for the peer */
		uint64_t ms_bidi; /* max sub-ID of bidi stream allowed for the peer */
		uint64_t msd_bidi_l; /* initial max-stream-data on local streams */
		uint64_t msd_bidi_r; /* initial max-stream-data on remote streams */
		uint64_t cl_bidi_r; /* total count of closed remote bidi stream since last MAX_STREAMS emission */
	} lfctl;

	/* flow-control fields set by the peer which we must respect. */
	struct {
		uint64_t md; /* connection flow control limit updated on MAX_DATA frames reception */
		uint64_t msd_bidi_l; /* initial max-stream-data for peer local streams */
		uint64_t msd_bidi_r; /* initial max-stream-data for peer remote streams */
	} rfctl;

	struct {
		uint64_t max_data; /* Maximum number of bytes which may be received */
	} rx;
	struct {
		uint64_t sent_offsets; /* sum of all offset sent */
	} tx;

	struct eb_root streams_by_id; /* all active streams by their ID */

	struct list send_retry_list; /* list of qcs eligible to send retry */

	struct wait_event wait_event;  /* To be used if we're waiting for I/Os */
	struct wait_event *subs;

	/* haproxy timeout management */
	struct task *task;
	int timeout;

	const struct qcc_app_ops *app_ops;
	void *ctx; /* Application layer context */
};

#define QC_SF_NONE              0x00000000
#define QC_SF_FIN_RECV          0x00000001  /* last frame received for this stream */
#define QC_SF_FIN_STREAM        0x00000002  /* FIN bit must be set for last frame of the stream */
#define QC_SF_BLK_MROOM         0x00000004  /* app layer is blocked waiting for room in the qcs.tx.buf */
#define QC_SF_DETACH            0x00000008  /* cs is detached but there is remaining data to send */
#define QC_SF_BLK_SFCTL         0x00000010  /* stream blocked due to stream flow control limit */
#define QC_SF_DEM_FULL          0x00000020  /* demux blocked on request channel buffer full */

struct qcs {
	struct qcc *qcc;
	struct cs_endpoint *endp;
	uint32_t flags;      /* QC_SF_* */
	void *ctx;           /* app-ops context */

	struct {
		struct eb_root frms; /* received frames ordered by their offsets */
		uint64_t offset; /* the current offset of received data */
		struct buffer buf; /* receive buffer, always valid (buf_empty or real buffer) */
		struct buffer app_buf; /* receive buffer used by conn_stream layer */
		uint64_t msd; /* fctl bytes limit to enforce */
	} rx;
	struct {
		uint64_t offset; /* last offset of data ready to be sent */
		uint64_t sent_offset; /* last offset sent by transport layer */
		struct buffer buf; /* transmit buffer before sending via xprt */
		uint64_t msd; /* fctl bytes limit to respect on emission */
	} tx;

	struct eb64_node by_id;
	uint64_t id;
	struct qc_stream_desc *stream;

	struct list el; /* element of qcc.send_retry_list */

	struct wait_event wait_event;
	struct wait_event *subs;
};

/* QUIC application layer operations */
struct qcc_app_ops {
	int (*init)(struct qcc *qcc);
	int (*attach)(struct qcs *qcs);
	int (*attach_ruqs)(struct qcs *qcs, void *ctx);
	int (*decode_qcs)(struct qcs *qcs, int fin, void *ctx);
	size_t (*snd_buf)(struct conn_stream *cs, struct buffer *buf, size_t count, int flags);
	void (*detach)(struct qcs *qcs);
	int (*finalize)(void *ctx);
	int (*is_active)(const struct qcc *qcc, void *ctx);
	void (*release)(void *ctx);
};

#endif /* USE_QUIC */

#endif /* _HAPROXY_MUX_QUIC_T_H */
