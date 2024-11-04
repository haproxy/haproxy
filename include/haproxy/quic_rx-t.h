#ifndef _HAPROXY_RX_T_H
#define _HAPROXY_RX_T_H

extern struct pool_head *pool_head_quic_conn_rxbuf;
extern struct pool_head *pool_head_quic_dgram;
extern struct pool_head *pool_head_quic_rx_packet;

#include <import/eb64tree.h>
#include <haproxy/api-t.h>
#include <haproxy/quic_cid-t.h>
#include <inttypes.h>
#include <sys/socket.h>

struct quic_version;
/* Maximum number of ack-eliciting received packets since the last
 * ACK frame was sent
 */
#define QUIC_MAX_RX_AEPKTS_SINCE_LAST_ACK       2
#define QUIC_ACK_DELAY   (QUIC_TP_DFLT_MAX_ACK_DELAY - 5)
/* Flag a received packet as being an ack-eliciting packet. */
#define QUIC_FL_RX_PACKET_ACK_ELICITING (1UL << 0)
/* Packet is the first one in the containing datagram. */
#define QUIC_FL_RX_PACKET_DGRAM_FIRST   (1UL << 1)
/* Spin bit set */
#define QUIC_FL_RX_PACKET_SPIN_BIT   (1UL << 2)

struct quic_rx_packet {
	struct list list;
	struct list qc_rx_pkt_list;

	/* QUIC version used in packet. */
	const struct quic_version *version;

	unsigned char type;
	/* Initial desctination connection ID. */
	struct quic_cid dcid;
	struct quic_cid scid;
	/* Packet number offset : only valid for Initial/Handshake/0-RTT/1-RTT. */
	size_t pn_offset;
	/* Packet number */
	int64_t pn;
	/* Packet number length */
	uint32_t pnl;
	uint64_t token_len;
	unsigned char *token;
	/* Packet length */
	uint64_t len;
	/* Packet length before decryption */
	uint64_t raw_len;
	/* Additional authenticated data length */
	size_t aad_len;
	unsigned char *data;
	struct eb64_node pn_node;
	volatile unsigned int refcnt;
	/* Source address of this packet. */
	struct sockaddr_storage saddr;
	unsigned int flags;
	unsigned int time_received;
};

enum quic_rx_ret_frm {
	QUIC_RX_RET_FRM_DONE = 0, /* frame handled correctly */
	QUIC_RX_RET_FRM_DUP,      /* frame ignored as already handled previously */
	QUIC_RX_RET_FRM_AGAIN,    /* frame cannot be handled temporarily, caller may retry during another parsing round */
	QUIC_RX_RET_FRM_FATAL,    /* error during frame handling, packet must not be acknowledged */
};

#endif /* _HAPROXY_RX_T_H */
