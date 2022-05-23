/*
 * include/haproxy/h3.h
 * This file contains types for H3
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

#ifndef _HAPROXY_H3_T_H
#define _HAPROXY_H3_T_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/buf-t.h>
#include <haproxy/mux_quic-t.h>

/* H3 unidirecational stream types
 * Emitted as the first byte on the stream to differentiate it.
 */
#define H3_UNI_S_T_CTRL       0x00
#define H3_UNI_S_T_PUSH       0x01
#define H3_UNI_S_T_QPACK_ENC  0x02
#define H3_UNI_S_T_QPACK_DEC  0x03
/* Must be the last one */
#define H3_UNI_S_T_MAX        H3_UNI_S_T_QPACK_DEC

/* Settings */
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01
/* there is a hole here of reserved settings, matching the h2 settings */
#define H3_SETTINGS_RESERVED_2               0x02
#define H3_SETTINGS_RESERVED_3               0x03
#define H3_SETTINGS_RESERVED_4               0x04
#define H3_SETTINGS_RESERVED_5               0x05
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE   0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS    0x07

/* Errors. */
enum h3_err {
	H3_NO_ERROR                = 0x100,
	H3_GENERAL_PROTOCOL_ERROR  = 0x101,
	H3_INTERNAL_ERROR          = 0x102,
	H3_STREAM_CREATION_ERROR   = 0x103,
	H3_CLOSED_CRITICAL_STREAM  = 0x104,
	H3_FRAME_UNEXPECTED        = 0x105,
	H3_FRAME_ERROR             = 0x106,
	H3_EXCESSIVE_LOAD          = 0x107,
	H3_ID_ERROR                = 0x108,
	H3_SETTINGS_ERROR          = 0x109,
	H3_MISSING_SETTINGS        = 0x10a,
	H3_REQUEST_REJECTED        = 0x10b,
	H3_REQUEST_CANCELLED       = 0x10c,
	H3_REQUEST_INCOMPLETE      = 0x10d,
	H3_MESSAGE_ERROR           = 0x10e,
	H3_CONNECT_ERROR           = 0x10f,
	H3_VERSION_FALLBACK        = 0x110,

	QPACK_DECOMPRESSION_FAILED = 0x200,
	QPACK_ENCODER_STREAM_ERROR = 0x201,
	QPACK_DECODER_STREAM_ERROR = 0x202,
};

/* Frame types. */
enum h3_ft       {
	H3_FT_DATA         = 0x00,
	H3_FT_HEADERS      = 0x01,
	/* There is a hole here */
	H3_FT_CANCEL_PUSH  = 0x03,
	H3_FT_SETTINGS     = 0x04,
	H3_FT_PUSH_PROMISE = 0x05,
	H3_FT_GOAWAY       = 0x06,
	H3_FT_MAX_PUSH_ID  = 0x07,
};

/* H3 unidirectional QUIC stream */
struct h3_uqs {
	/* Underlying incoming QUIC uni-stream */
	struct qcs *qcs;
	/* Callback to tx/rx bytes */
	int (*cb)(struct qcs *qcs, void *ctx);
	struct wait_event wait_event;
};

extern const struct qcc_app_ops h3_ops;

size_t h3_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags);

#endif /* USE_QUIC */
#endif /* _HAPROXY_H3_T_H */
