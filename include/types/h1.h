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

/* Possible states while parsing HTTP/1 messages (request|response) */
enum h1_state {
	HTTP_MSG_RQBEFORE     =  0, // request: leading LF, before start line
	HTTP_MSG_RQBEFORE_CR  =  1, // request: leading CRLF, before start line
	/* these ones define a request start line */
	HTTP_MSG_RQMETH       =  2, // parsing the Method
	HTTP_MSG_RQMETH_SP    =  3, // space(s) after the Method
	HTTP_MSG_RQURI        =  4, // parsing the Request URI
	HTTP_MSG_RQURI_SP     =  5, // space(s) after the Request URI
	HTTP_MSG_RQVER        =  6, // parsing the Request Version
	HTTP_MSG_RQLINE_END   =  7, // end of request line (CR or LF)

	HTTP_MSG_RPBEFORE     =  8, // response: leading LF, before start line
	HTTP_MSG_RPBEFORE_CR  =  9, // response: leading CRLF, before start line

	/* these ones define a response start line */
	HTTP_MSG_RPVER        = 10, // parsing the Response Version
	HTTP_MSG_RPVER_SP     = 11, // space(s) after the Response Version
	HTTP_MSG_RPCODE       = 12, // response code
	HTTP_MSG_RPCODE_SP    = 13, // space(s) after the response code
	HTTP_MSG_RPREASON     = 14, // response reason
	HTTP_MSG_RPLINE_END   = 15, // end of response line (CR or LF)

	/* common header processing */
	HTTP_MSG_HDR_FIRST    = 16, // waiting for first header or last CRLF (no LWS possible)
	HTTP_MSG_HDR_NAME     = 17, // parsing header name
	HTTP_MSG_HDR_COL      = 18, // parsing header colon
	HTTP_MSG_HDR_L1_SP    = 19, // parsing header LWS (SP|HT) before value
	HTTP_MSG_HDR_L1_LF    = 20, // parsing header LWS (LF) before value
	HTTP_MSG_HDR_L1_LWS   = 21, // checking whether it's a new header or an LWS
	HTTP_MSG_HDR_VAL      = 22, // parsing header value
	HTTP_MSG_HDR_L2_LF    = 23, // parsing header LWS (LF) inside/after value
	HTTP_MSG_HDR_L2_LWS   = 24, // checking whether it's a new header or an LWS

	HTTP_MSG_LAST_LF      = 25, // parsing last LF

	/* error state : must be before HTTP_MSG_BODY so that (>=BODY) always indicates
	 * that data are being processed.
	 */
	HTTP_MSG_ERROR        = 26, // an error occurred
	/* Body processing.
	 * The state HTTP_MSG_BODY is a delimiter to know if we're waiting for headers
	 * or body. All the sub-states below also indicate we're processing the body,
	 * with some additional information.
	 */
	HTTP_MSG_BODY         = 27, // parsing body at end of headers
	HTTP_MSG_100_SENT     = 28, // parsing body after a 100-Continue was sent
	HTTP_MSG_CHUNK_SIZE   = 29, // parsing the chunk size (RFC7230 #4.1)
	HTTP_MSG_DATA         = 30, // skipping data chunk / content-length data
	HTTP_MSG_CHUNK_CRLF   = 31, // skipping CRLF after data chunk
	HTTP_MSG_TRAILERS     = 32, // trailers (post-data entity headers)
	/* we enter this state when we've received the end of the current message */
	HTTP_MSG_ENDING       = 33, // message end received, wait that the filters end too
	HTTP_MSG_DONE         = 34, // message end received, waiting for resync or close
	HTTP_MSG_CLOSING      = 35, // shutdown_w done, not all bytes sent yet
	HTTP_MSG_CLOSED       = 36, // shutdown_w done, all bytes sent
	HTTP_MSG_TUNNEL       = 37, // tunneled data after DONE
} __attribute__((packed));


/* HTTP/1 message flags (32 bit), for use in h1m->flags only */
#define H1_MF_NONE              0x00000000
#define H1_MF_CLEN              0x00000001 // content-length present
#define H1_MF_CHNK              0x00000002 // chunk present, exclusive with c-l


/* basic HTTP/1 message state for use in parsers */
struct h1m {
	enum h1_state state;        // H1 message state (HTTP_MSG_*)
	/* 8 bits available here */
	uint16_t status;            // HTTP status code
	uint32_t flags;             // H1 message flags (H1_MF_*)
	uint64_t curr_len;          // content-length or last chunk length
	uint64_t body_len;          // total known size of the body length
	int err_pos;                // position in the byte stream of the first error (H1 or H2)
	int err_state;              // state where the first error was met (H1 or H2)
};

#endif /* _TYPES_H1_H */
