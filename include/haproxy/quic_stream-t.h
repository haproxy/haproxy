#ifndef _HAPROXY_QUIC_STREAM_T_H_
#define _HAPROXY_QUIC_STREAM_T_H_

#ifdef USE_QUIC

#include <import/ebtree-t.h>

#include <haproxy/buf-t.h>
#include <haproxy/list-t.h>

/* A QUIC STREAM buffer used for Tx.
 *
 * Currently, no offset is associated with an offset. The qc_stream_desc must
 * store them in order and keep the offset of the oldest buffer. The buffers
 * can be freed in strict order.
 */
struct qc_stream_buf {
	struct eb_root ack_tree; /* storage for out-of-order ACKs */
	struct eb64_node offset_node; /* node for qc_stream_desc buf tree */
	struct buffer buf; /* STREAM payload */
	uint64_t room; /* room already notified from buffered ACKs */
	int sbuf;
};

#define QC_SD_FL_RELEASE	0x00000001 /* set when MUX has finished to use this stream */
#define QC_SD_FL_WAIT_FOR_FIN	0x00000002 /* set if sent FIN is waiting for acknowledgement */

/* QUIC STREAM descriptor.
 *
 * This structure is the low-level counterpart of the QUIC STREAM at the MUX
 * layer. It is stored in the quic-conn and provides facility for Tx buffering.
 *
 * Once the MUX has finished to transfer data on a STREAM, it must release its
 * QUIC STREAM descriptor. The descriptor will be kept by the quic_conn until
 * all acknowledgement has been received.
 */
struct qc_stream_desc {
	struct eb64_node by_id; /* node for quic_conn tree */
	struct quic_conn *qc;

	struct qc_stream_buf *buf; /* current buffer used by the MUX */
	uint64_t buf_offset; /* base offset of current buffer */

	uint64_t ack_offset; /* last acknowledged offset */
	struct eb_root buf_tree; /* list of active and released buffers */

	int flags; /* QC_SD_FL_* values */

	void (*notify_send)(struct qc_stream_desc *, uint64_t offset, uint64_t len);
	void (*notify_room)(struct qc_stream_desc *, uint64_t room);
	void *ctx; /* notify context */
};

/* Represents a range of acknowledged data that cannot be immediately deleted. */
struct qc_stream_ack {
	struct eb64_node offset_node; /* range starting offset, used as attach point to streambuf <ack_tree>. */
	uint64_t len;                 /* length of the acknowledged range */
	int fin;                      /* set if the related STREAM frame had FIN bit set */
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_T_H_ */
