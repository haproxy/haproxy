#ifndef _HAPROXY_QUIC_STREAM_T_H_
#define _HAPROXY_QUIC_STREAM_T_H_

#ifdef USE_QUIC

#include <import/ebtree-t.h>

#include <haproxy/buf-t.h>

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

	struct buffer buf; /* buffer for STREAM data on Tx, emptied on acknowledge */
	uint64_t ack_offset; /* last acknowledged offset */
	struct eb_root acked_frms; /* ACK frames tree for non-contiguous ACK ranges */

	int release; /* set to 1 when the MUX has finished to use this stream */

	void *ctx; /* MUX specific context */
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_T_H_ */
