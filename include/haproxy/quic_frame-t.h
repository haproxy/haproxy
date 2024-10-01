/*
 * include/types/quic_frame.h
 * This file contains QUIC frame definitions.
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _TYPES_QUIC_FRAME_H
#define _TYPES_QUIC_FRAME_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <inttypes.h>
#include <stdlib.h>

#include <import/ebtree-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/list.h>
#include <haproxy/quic_stream-t.h>
#include <haproxy/quic_token.h>

extern struct pool_head *pool_head_quic_frame;
extern struct pool_head *pool_head_qf_crypto;

/* forward declarations from xprt-quic */
struct quic_arngs;
struct quic_enc_level;
struct quic_tx_packet;

/* QUIC frame types. */
enum quic_frame_type {
	QUIC_FT_PADDING      = 0x00,
	QUIC_FT_PING         = 0x01,
	QUIC_FT_ACK          = 0x02,
	QUIC_FT_ACK_ECN      = 0x03,
	QUIC_FT_RESET_STREAM = 0x04,
	QUIC_FT_STOP_SENDING = 0x05,
	QUIC_FT_CRYPTO       = 0x06,
	QUIC_FT_NEW_TOKEN    = 0x07,

	QUIC_FT_STREAM_8     = 0x08,
	QUIC_FT_STREAM_9     = 0x09,
	QUIC_FT_STREAM_A     = 0x0a,
	QUIC_FT_STREAM_B     = 0x0b,
	QUIC_FT_STREAM_C     = 0x0c,
	QUIC_FT_STREAM_D     = 0x0d,
	QUIC_FT_STREAM_E     = 0x0e,
	QUIC_FT_STREAM_F     = 0x0f,

	QUIC_FT_MAX_DATA             = 0x10,
	QUIC_FT_MAX_STREAM_DATA      = 0x11,
	QUIC_FT_MAX_STREAMS_BIDI     = 0x12,
	QUIC_FT_MAX_STREAMS_UNI      = 0x13,
	QUIC_FT_DATA_BLOCKED         = 0x14,
	QUIC_FT_STREAM_DATA_BLOCKED  = 0x15,
	QUIC_FT_STREAMS_BLOCKED_BIDI = 0x16,
	QUIC_FT_STREAMS_BLOCKED_UNI  = 0x17,
	QUIC_FT_NEW_CONNECTION_ID    = 0x18,
	QUIC_FT_RETIRE_CONNECTION_ID = 0x19,
	QUIC_FT_PATH_CHALLENGE       = 0x1a,
	QUIC_FT_PATH_RESPONSE        = 0x1b,
	QUIC_FT_CONNECTION_CLOSE     = 0x1c,
	QUIC_FT_CONNECTION_CLOSE_APP = 0x1d,
	QUIC_FT_HANDSHAKE_DONE       = 0x1e,
	/* Do not insert enums after the following one. */
	QUIC_FT_MAX
};

#define QUIC_FT_PKT_TYPE_I_BITMASK (1 << QUIC_PACKET_TYPE_INITIAL)
#define QUIC_FT_PKT_TYPE_0_BITMASK (1 << QUIC_PACKET_TYPE_0RTT)
#define QUIC_FT_PKT_TYPE_H_BITMASK (1 << QUIC_PACKET_TYPE_HANDSHAKE)
#define QUIC_FT_PKT_TYPE_1_BITMASK (1 << QUIC_PACKET_TYPE_SHORT)

#define QUIC_FT_PKT_TYPE_IH01_BITMASK \
	(QUIC_FT_PKT_TYPE_I_BITMASK | QUIC_FT_PKT_TYPE_H_BITMASK | \
	 QUIC_FT_PKT_TYPE_0_BITMASK | QUIC_FT_PKT_TYPE_1_BITMASK)

#define QUIC_FT_PKT_TYPE_IH_1_BITMASK \
	(QUIC_FT_PKT_TYPE_I_BITMASK | QUIC_FT_PKT_TYPE_H_BITMASK | \
	 QUIC_FT_PKT_TYPE_1_BITMASK)

#define QUIC_FT_PKT_TYPE___01_BITMASK \
	(QUIC_FT_PKT_TYPE_0_BITMASK | QUIC_FT_PKT_TYPE_1_BITMASK)

#define QUIC_FT_PKT_TYPE____1_BITMASK QUIC_FT_PKT_TYPE_1_BITMASK


/* Flag a TX frame as acknowledged */
#define QUIC_FL_TX_FRAME_ACKED             0x01

#define QUIC_STREAM_FRAME_TYPE_FIN_BIT     0x01
#define QUIC_STREAM_FRAME_TYPE_LEN_BIT     0x02
#define QUIC_STREAM_FRAME_TYPE_OFF_BIT     0x04

/* Servers have the stream initiator bit set. */
#define QUIC_STREAM_FRAME_ID_INITIATOR_BIT 0x01
/* Unidirectional streams have the direction bit set. */
#define QUIC_STREAM_FRAME_ID_DIR_BIT       0x02

#define QUIC_PATH_CHALLENGE_LEN         8
/* Maximum phrase length in CONNECTION_CLOSE frame */
#define QUIC_CC_REASON_PHRASE_MAXLEN   64

struct qf_padding {
	size_t len;
};

struct qf_ack {
	uint64_t largest_ack;
	uint64_t ack_delay;
	uint64_t ack_range_num;
	uint64_t first_ack_range;
};

/* Structure used when emitting ACK frames. */
struct qf_tx_ack {
	uint64_t ack_delay;
	struct quic_arngs *arngs;
};

struct qf_reset_stream {
	uint64_t id;
	uint64_t app_error_code;
	uint64_t final_size;
};

struct qf_stop_sending {
	uint64_t id;
	uint64_t app_error_code;
};

struct qf_crypto {
	struct list list;
	uint64_t offset;
	uint64_t len;
	const struct quic_enc_level *qel;
	const unsigned char *data;
};

struct qf_new_token {
	uint64_t len;
	unsigned char data[QUIC_TOKEN_LEN];
};

struct qf_stream {
	uint64_t id;
	struct qc_stream_desc *stream;

	/* used only on TX when constructing frames.
	 * Data cleared when processing ACK related to this STREAM frame.
	 *
	 * A same buffer may be shared between several STREAM frames. The
	 * <data> field of each quic_stream serves to differentiate the payload
	 * of each of these.
	 */
	struct buffer *buf;

	uint64_t offset;
	uint64_t len;

	/* for TX pointer into <buf> field.
	 * for RX pointer into the packet buffer.
	 */
	const unsigned char *data;

	char dup; /* set for duplicated frame : this forces to check for the underlying qc_stream_buf instance before emitting it. */
};

struct qf_max_data {
	uint64_t max_data;
};

struct qf_max_stream_data {
	uint64_t id;
	uint64_t max_stream_data;
};

struct qf_max_streams {
	uint64_t max_streams;
};

struct qf_data_blocked {
	uint64_t limit;
};

struct qf_stream_data_blocked {
	uint64_t id;
	uint64_t limit;
};

struct qf_streams_blocked {
	uint64_t limit;
};

struct qf_new_connection_id {
	uint64_t seq_num;
	uint64_t retire_prior_to;
	struct {
		unsigned char len;
		const unsigned char *data;
	} cid;
	const unsigned char *stateless_reset_token;
};

struct qf_retire_connection_id {
	uint64_t seq_num;
};

struct qf_path_challenge {
	unsigned char data[QUIC_PATH_CHALLENGE_LEN];
};

struct qf_path_challenge_response {
	unsigned char data[QUIC_PATH_CHALLENGE_LEN];
};

struct qf_connection_close {
	uint64_t error_code;
	uint64_t frame_type;
	uint64_t reason_phrase_len;
	unsigned char reason_phrase[QUIC_CC_REASON_PHRASE_MAXLEN];
};

struct qf_connection_close_app {
	uint64_t error_code;
	uint64_t reason_phrase_len;
	unsigned char reason_phrase[QUIC_CC_REASON_PHRASE_MAXLEN];
};

struct quic_frame {
	struct list list;           /* List elem from parent elem (typically a Tx packet instance, a PKTNS or a MUX element). */
	struct quic_tx_packet *pkt; /* Last Tx packet used to send the frame. */
	unsigned char type;         /* QUIC frame type. */
	union {
		struct qf_padding padding;
		struct qf_ack ack;
		struct qf_tx_ack tx_ack;
		struct qf_crypto crypto;
		struct qf_reset_stream reset_stream;
		struct qf_stop_sending stop_sending;
		struct qf_new_token new_token;
		struct qf_stream stream;
		struct qf_max_data max_data;
		struct qf_max_stream_data max_stream_data;
		struct qf_max_streams max_streams_bidi;
		struct qf_max_streams max_streams_uni;
		struct qf_data_blocked data_blocked;
		struct qf_stream_data_blocked stream_data_blocked;
		struct qf_streams_blocked streams_blocked_bidi;
		struct qf_streams_blocked streams_blocked_uni;
		struct qf_new_connection_id new_connection_id;
		struct qf_retire_connection_id retire_connection_id;
		struct qf_path_challenge path_challenge;
		struct qf_path_challenge_response path_challenge_response;
		struct qf_connection_close connection_close;
		struct qf_connection_close_app connection_close_app;
	};
	struct quic_frame *origin;  /* Parent frame. Set if frame is a duplicate (used for retransmission). */
	struct list reflist;        /* List head containing duplicated children frames. */
	struct list ref;            /* List elem from parent frame reflist. Set if frame is a duplicate (used for retransmission). */
	unsigned int flags;         /* QUIC_FL_TX_FRAME_* */
	unsigned int loss_count;    /* Counter for each occurrence of this frame marked as lost. */
};


/* QUIC error codes */
struct quic_err {
	uint64_t code;  /* error code */
	int app;        /* set for Application error code */
};

/* Transport level error codes. */
#define QC_ERR_NO_ERROR                     0x00
#define QC_ERR_INTERNAL_ERROR               0x01
#define QC_ERR_CONNECTION_REFUSED           0x02
#define QC_ERR_FLOW_CONTROL_ERROR           0x03
#define QC_ERR_STREAM_LIMIT_ERROR           0x04
#define QC_ERR_STREAM_STATE_ERROR           0x05
#define QC_ERR_FINAL_SIZE_ERROR             0x06
#define QC_ERR_FRAME_ENCODING_ERROR         0x07
#define QC_ERR_TRANSPORT_PARAMETER_ERROR    0x08
#define QC_ERR_CONNECTION_ID_LIMIT_ERROR    0x09
#define QC_ERR_PROTOCOL_VIOLATION           0x0a
#define QC_ERR_INVALID_TOKEN                0x0b
#define QC_ERR_APPLICATION_ERROR            0x0c
#define QC_ERR_CRYPTO_BUFFER_EXCEEDED       0x0d
#define QC_ERR_KEY_UPDATE_ERROR             0x0e
#define QC_ERR_AEAD_LIMIT_REACHED           0x0f
#define QC_ERR_NO_VIABLE_PATH               0x10
/* 256 TLS reserved errors 0x100-0x1ff. */
#define QC_ERR_CRYPTO_ERROR                0x100

#endif /* USE_QUIC */
#endif /* _TYPES_QUIC_FRAME_H */
