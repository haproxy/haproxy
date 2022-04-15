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
	struct buffer buf; /* STREAM payload */
	struct list list; /* element for qc_stream_desc list */
};

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

	struct list buf_list; /* buffers waiting for ACK, oldest offset first */
	struct qc_stream_buf *buf; /* current buffer used by the MUX */
	uint64_t buf_offset; /* base offset of current buffer */

	uint64_t ack_offset; /* last acknowledged offset */
	struct eb_root acked_frms; /* ACK frames tree for non-contiguous ACK ranges */

	int release; /* set to 1 when the MUX has finished to use this stream */

	void *ctx; /* MUX specific context */
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_T_H_ */
