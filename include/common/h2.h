/*
 * include/common/h2.h
 * This file contains types and macros used for the HTTP/2 protocol
 *
 * Copyright (C) 2000-2017 Willy Tarreau - w@1wt.eu
 * Copyright (C) 2017 HAProxy Technologies
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _COMMON_H2_H
#define _COMMON_H2_H

#include <common/config.h>
#include <common/http-hdr.h>
#include <common/ist.h>


/* indexes of most important pseudo headers can be simplified to an almost
 * linear array by dividing the index by 2 for all values from 1 to 9, and
 * caping to 4 for values up to 14 ; thus it fits in a single 24-bit array
 * shifted by 3 times the index value/2, or a 32-bit array shifted by 4x.
 * Don't change these values, they are assumed by hpack_idx_to_phdr(). There
 * is an entry for the Host header field which is not a pseudo-header but
 * needs to be tracked as we should only use :authority if it's absent.
 */
enum {
	H2_PHDR_IDX_NONE = 0,
	H2_PHDR_IDX_AUTH = 1, /* :authority = 1     */
	H2_PHDR_IDX_METH = 2, /* :method    = 2..3  */
	H2_PHDR_IDX_PATH = 3, /* :path      = 4..5  */
	H2_PHDR_IDX_SCHM = 4, /* :scheme    = 6..7  */
	H2_PHDR_IDX_STAT = 5, /* :status    = 8..14 */
	H2_PHDR_IDX_HOST = 6, /* Host, never returned, just a place-holder */
	H2_PHDR_NUM_ENTRIES   /* must be last */
};

/* bit fields indicating the pseudo-headers found. It also covers the HOST
 * header field as well as any non-pseudo-header field (NONE).
 */
enum {
	H2_PHDR_FND_NONE = 1 << H2_PHDR_IDX_NONE, /* found a regular header */
	H2_PHDR_FND_AUTH = 1 << H2_PHDR_IDX_AUTH,
	H2_PHDR_FND_METH = 1 << H2_PHDR_IDX_METH,
	H2_PHDR_FND_PATH = 1 << H2_PHDR_IDX_PATH,
	H2_PHDR_FND_SCHM = 1 << H2_PHDR_IDX_SCHM,
	H2_PHDR_FND_STAT = 1 << H2_PHDR_IDX_STAT,
	H2_PHDR_FND_HOST = 1 << H2_PHDR_IDX_HOST,
};

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


/* various protocol processing functions */

int h2_make_h1_request(struct http_hdr *list, char *out, int osize);

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

/* returns the pseudo-header <str> corresponds to among H2_PHDR_IDX_*, 0 if not a
 * pseudo-header, or -1 if not a valid pseudo-header.
 */
static inline int h2_str_to_phdr(const struct ist str)
{
	if (*str.ptr == ':') {
		if (isteq(str, ist(":path")))           return H2_PHDR_IDX_PATH;
		else if (isteq(str, ist(":method")))    return H2_PHDR_IDX_METH;
		else if (isteq(str, ist(":scheme")))    return H2_PHDR_IDX_SCHM;
		else if (isteq(str, ist(":status")))    return H2_PHDR_IDX_STAT;
		else if (isteq(str, ist(":authority"))) return H2_PHDR_IDX_AUTH;

		/* all other names starting with ':' */
		return -1;
	}

	/* not a pseudo header */
	return 0;
}


#endif /* _COMMON_H2_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
