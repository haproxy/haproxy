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
#define H3_SETTINGS_RESERVED_0               0x00
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01
/* there is a hole here of reserved settings, matching the h2 settings */
#define H3_SETTINGS_RESERVED_2               0x02
#define H3_SETTINGS_RESERVED_3               0x03
#define H3_SETTINGS_RESERVED_4               0x04
#define H3_SETTINGS_RESERVED_5               0x05
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE   0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS    0x07

/* RFC 9114 8. Error Handling */
enum h3_err {
	H3_ERR_NO_ERROR                = 0x100,
	H3_ERR_GENERAL_PROTOCOL_ERROR  = 0x101,
	H3_ERR_INTERNAL_ERROR          = 0x102,
	H3_ERR_STREAM_CREATION_ERROR   = 0x103,
	H3_ERR_CLOSED_CRITICAL_STREAM  = 0x104,
	H3_ERR_FRAME_UNEXPECTED        = 0x105,
	H3_ERR_FRAME_ERROR             = 0x106,
	H3_ERR_EXCESSIVE_LOAD          = 0x107,
	H3_ERR_ID_ERROR                = 0x108,
	H3_ERR_SETTINGS_ERROR          = 0x109,
	H3_ERR_MISSING_SETTINGS        = 0x10a,
	H3_ERR_REQUEST_REJECTED        = 0x10b,
	H3_ERR_REQUEST_CANCELLED       = 0x10c,
	H3_ERR_REQUEST_INCOMPLETE      = 0x10d,
	H3_ERR_MESSAGE_ERROR           = 0x10e,
	H3_ERR_CONNECT_ERROR           = 0x10f,
	H3_ERR_VERSION_FALLBACK        = 0x110,
};

/* Frame types. */
enum h3_ft       {
	/* internal value used to mark demuxing as inactive */
	H3_FT_UNINIT       = -1,

	H3_FT_DATA         = 0x00,
	H3_FT_HEADERS      = 0x01,
	/* hole */
	H3_FT_CANCEL_PUSH  = 0x03,
	H3_FT_SETTINGS     = 0x04,
	H3_FT_PUSH_PROMISE = 0x05,
	/* hole */
	H3_FT_GOAWAY       = 0x07,
	/* hole */
	H3_FT_MAX_PUSH_ID  = 0x0d,
};

/* Stream types */
enum h3s_t {
	/* unidirectional streams */
	H3S_T_CTRL,
	H3S_T_PUSH,
	H3S_T_QPACK_DEC,
	H3S_T_QPACK_ENC,

	/* bidirectional streams */
	H3S_T_REQ,

	H3S_T_UNKNOWN
};

/* State for request streams */
enum h3s_st_req {
	H3S_ST_REQ_BEFORE = 0, /* initial state */
	H3S_ST_REQ_HEADERS,    /* header section received */
	H3S_ST_REQ_DATA,       /* first DATA frame for content received */
	H3S_ST_REQ_TRAILERS,   /* trailer section received */
};

extern const struct qcc_app_ops h3_ops;

#endif /* USE_QUIC */
#endif /* _HAPROXY_H3_T_H */
