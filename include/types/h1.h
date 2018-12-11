/*
 * include/types/h1.h
 * This file contains HTTP/1 protocol definitions.
 *
 * Copyright (C) 2000-2017 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_H1_H
#define _TYPES_H1_H

#include <common/http.h>
#include <common/ist.h>

/* Possible states while parsing HTTP/1 messages (request|response) */
enum h1m_state {
	H1_MSG_RQBEFORE     =  0, // request: leading LF, before start line
	H1_MSG_RQBEFORE_CR  =  1, // request: leading CRLF, before start line
	/* these ones define a request start line */
	H1_MSG_RQMETH       =  2, // parsing the Method
	H1_MSG_RQMETH_SP    =  3, // space(s) after the Method
	H1_MSG_RQURI        =  4, // parsing the Request URI
	H1_MSG_RQURI_SP     =  5, // space(s) after the Request URI
	H1_MSG_RQVER        =  6, // parsing the Request Version
	H1_MSG_RQLINE_END   =  7, // end of request line (CR or LF)

	H1_MSG_RPBEFORE     =  8, // response: leading LF, before start line
	H1_MSG_RPBEFORE_CR  =  9, // response: leading CRLF, before start line

	/* these ones define a response start line */
	H1_MSG_RPVER        = 10, // parsing the Response Version
	H1_MSG_RPVER_SP     = 11, // space(s) after the Response Version
	H1_MSG_RPCODE       = 12, // response code
	H1_MSG_RPCODE_SP    = 13, // space(s) after the response code
	H1_MSG_RPREASON     = 14, // response reason
	H1_MSG_RPLINE_END   = 15, // end of response line (CR or LF)

	/* common header processing */
	H1_MSG_HDR_FIRST    = 16, // waiting for first header or last CRLF (no LWS possible)
	H1_MSG_HDR_NAME     = 17, // parsing header name
	H1_MSG_HDR_COL      = 18, // parsing header colon
	H1_MSG_HDR_L1_SP    = 19, // parsing header LWS (SP|HT) before value
	H1_MSG_HDR_L1_LF    = 20, // parsing header LWS (LF) before value
	H1_MSG_HDR_L1_LWS   = 21, // checking whether it's a new header or an LWS
	H1_MSG_HDR_VAL      = 22, // parsing header value
	H1_MSG_HDR_L2_LF    = 23, // parsing header LWS (LF) inside/after value
	H1_MSG_HDR_L2_LWS   = 24, // checking whether it's a new header or an LWS

	H1_MSG_LAST_LF      = 25, // parsing last LF, last state for headers

	/* Body processing. */

	H1_MSG_CHUNK_SIZE   = 26, // parsing the chunk size (RFC7230 #4.1)
	H1_MSG_DATA         = 27, // skipping data chunk / content-length data
	H1_MSG_CHUNK_CRLF   = 28, // skipping CRLF after data chunk
	H1_MSG_TRAILERS     = 29, // trailers (post-data entity headers)
	/* we enter this state when we've received the end of the current message */
	H1_MSG_DONE         = 30, // message end received, waiting for resync or close
	H1_MSG_TUNNEL       = 31, // tunneled data after DONE
} __attribute__((packed));


/* HTTP/1 message flags (32 bit), for use in h1m->flags only */
#define H1_MF_NONE              0x00000000
#define H1_MF_CLEN              0x00000001 // content-length present
#define H1_MF_CHNK              0x00000002 // chunk present, exclusive with c-l
#define H1_MF_RESP              0x00000004 // this message is the response message
#define H1_MF_TOLOWER           0x00000008 // turn the header names to lower case
#define H1_MF_VER_11            0x00000010 // message indicates version 1.1 or above
#define H1_MF_CONN_CLO          0x00000020 // message contains "connection: close"
#define H1_MF_CONN_KAL          0x00000040 // message contains "connection: keep-alive"
#define H1_MF_CONN_UPG          0x00000080 // message contains "connection: upgrade"
#define H1_MF_XFER_LEN          0x00000100 // message xfer size can be determined
#define H1_MF_XFER_ENC          0x00000200 // transfer-encoding is present
#define H1_MF_NO_PHDR           0x00000400 // don't add pseudo-headers in the header list

/* Note: for a connection to be persistent, we need this for the request :
 *   - one of CLEN or CHNK
 *   - version 1.0 and KAL and not CLO
 *   - or version 1.1 and not CLO
 * For the response it's the same except that UPG must not appear either.
 * So in short, for a request it's (CLEN|CHNK) > 0 && !CLO && (VER_11 || KAL)
 * and for a response it's (CLEN|CHNK) > 0 && !(CLO|UPG) && (VER_11 || KAL)
 */


/* basic HTTP/1 message state for use in parsers. The err_pos field is special,
 * it is pre-set to a negative value (-1 or -2), and once non-negative it contains
 * the relative position in the message of the first parse error. -2 is used to tell
 * the parser that we want to block the invalid message. -1 is used to only perform
 * a silent capture.
 */
struct h1m {
	enum h1m_state state;       // H1 message state (H1_MSG_*)
	/* 24 bits available here */
	uint32_t flags;             // H1 message flags (H1_MF_*)
	uint64_t curr_len;          // content-length or last chunk length
	uint64_t body_len;          // total known size of the body length
	uint32_t next;              // next byte to parse, relative to buffer's head
	int err_pos;                // position in the byte stream of the first error (H1 or H2)
	int err_state;              // state where the first error was met (H1 or H2)
};

/* basic H1 start line, describes either the request and the response */
union h1_sl {                          /* useful start line pointers, relative to ->sol */
	struct {
		struct ist m;          /* METHOD */
		struct ist u;          /* URI */
		struct ist v;          /* VERSION */
		enum http_meth_t meth; /* method */
	} rq;                          /* request line : field, length */
	struct {
		struct ist v;          /* VERSION */
		struct ist c;          /* CODE */
		struct ist r;          /* REASON */
		uint16_t status;       /* status code */
	} st;                          /* status line : field, length */
};

#endif /* _TYPES_H1_H */
