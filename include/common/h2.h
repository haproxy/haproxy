/*
 * include/common/h2.h
 * This file contains types and macros used for the HTTP/2 protocol
 *
 * Copyright (C) 2000-2017 Willy Tarreau - w@1wt.eu
 * Copyright (C) 2017 HAProxy Technologies
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

#ifndef _COMMON_H2_H
#define _COMMON_H2_H

#include <common/config.h>


/* frame types, from the standard */
enum h2_ft {
	H2_FT_DATA            = 0x00,     // RFC7540 #6.1
	H2_FT_HEADERS         = 0x01,     // RFC7540 #6.2
	H2_FT_PRIORITY        = 0x02,     // RFC7540 #6.3
	H2_FT_RST_STREAM      = 0x03,     // RFC7540 #6.4
	H2_FT_SETTINGS        = 0x04,     // RFC7540 #6.5
	H2_FT_PUSH_PROMISE    = 0x05,     // RFC7540 #6.6
	H2_FT_PING            = 0x06,     // RFC7540 #6.7
	H2_FT_GOAWAY          = 0x07,     // RFC7540 #6.8
	H2_FT_WINDOW_UPDATE   = 0x08,     // RFC7540 #6.9
	H2_FT_CONTINUATION    = 0x09,     // RFC7540 #6.10
	H2_FT_ENTRIES /* must be last */
} __attribute__((packed));

/* flags defined for each frame type */

// RFC7540 #6.1
#define H2_F_DATA_END_STREAM 0x01
#define H2_F_DATA_PADDED     0x08

// RFC7540 #6.2
#define H2_F_HEADERS_END_STREAM  0x01
#define H2_F_HEADERS_END_HEADERS 0x04
#define H2_F_HEADERS_PADDED      0x08
#define H2_F_HEADERS_PRIORITY    0x20

// RFC7540 #6.3 : PRIORITY defines no flags
// RFC7540 #6.4 : RST_STREAM defines no flags

// RFC7540 #6.5
#define H2_F_SETTINGS_ACK   0x01

// RFC7540 #6.6
#define H2_F_PUSH_PROMISE_END_HEADERS 0x04
#define H2_F_PUSH_PROMISE_PADDED      0x08

// RFC7540 #6.7
#define H2_F_PING_ACK   0x01

// RFC7540 #6.8 : GOAWAY defines no flags
// RFC7540 #6.9 : WINDOW_UPDATE defines no flags

/* HTTP/2 error codes - RFC7540 #7 */
enum h2_err {
	H2_ERR_NO_ERROR            = 0x0,
	H2_ERR_PROTOCOL_ERROR      = 0x1,
	H2_ERR_INTERNAL_ERROR      = 0x2,
	H2_ERR_FLOW_CONTROL_ERROR  = 0x3,
	H2_ERR_SETTINGS_TIMEOUT    = 0x4,
	H2_ERR_STREAM_CLOSED       = 0x5,
	H2_ERR_FRAME_SIZE_ERROR    = 0x6,
	H2_ERR_REFUSED_STREAM      = 0x7,
	H2_ERR_CANCEL              = 0x8,
	H2_ERR_COMPRESSION_ERROR   = 0x9,
	H2_ERR_CONNECT_ERROR       = 0xa,
	H2_ERR_ENHANCE_YOUR_CALM   = 0xb,
	H2_ERR_INADEQUATE_SECURITY = 0xc,
	H2_ERR_HTTP_1_1_REQUIRED   = 0xd,
} __attribute__((packed));

// RFC7540 #11.3 : Settings Registry
#define H2_SETTINGS_HEADER_TABLE_SIZE      0x0001
#define H2_SETTINGS_ENABLE_PUSH            0x0002
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x0003
#define H2_SETTINGS_INITIAL_WINDOW_SIZE    0x0004
#define H2_SETTINGS_MAX_FRAME_SIZE         0x0005
#define H2_SETTINGS_MAX_HEADER_LIST_SIZE   0x0006


/* some protocol constants */

// PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
#define H2_CONN_PREFACE                     \
	"\x50\x52\x49\x20\x2a\x20\x48\x54"  \
	"\x54\x50\x2f\x32\x2e\x30\x0d\x0a"  \
	"\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a"

/*
 * Some helpful debugging functions.
 */

/* returns the frame type as a string */
static inline const char *h2_ft_str(int type)
{
	switch (type) {
	case H2_FT_DATA          : return "DATA";
	case H2_FT_HEADERS       : return "HEADERS";
	case H2_FT_PRIORITY      : return "PRIORITY";
	case H2_FT_RST_STREAM    : return "RST_STREAM";
	case H2_FT_SETTINGS      : return "SETTINGS";
	case H2_FT_PUSH_PROMISE  : return "PUSH_PROMISE";
	case H2_FT_PING          : return "PING";
	case H2_FT_GOAWAY        : return "GOAWAY";
	case H2_FT_WINDOW_UPDATE : return "WINDOW_UPDATE";
	default                  : return "_UNKNOWN_";
	}
}

#endif /* _COMMON_H2_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
