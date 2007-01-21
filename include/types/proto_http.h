/*
  include/types/proto_http.h
  This file contains HTTP protocol definitions.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_PROTO_HTTP_H
#define _TYPES_PROTO_HTTP_H

#include <common/config.h>

/*
 * FIXME: break this into HTTP state and TCP socket state.
 * See server.h for the other end.
 */

/* different possible states for the client side */
#define CL_STHEADERS	0
#define CL_STDATA	1
#define CL_STSHUTR	2
#define CL_STSHUTW	3
#define CL_STCLOSE	4

/*
 * FIXME: break this into HTTP state and TCP socket state.
 * See client.h for the other end.
 */

/* different possible states for the server side */
#define SV_STIDLE	0
#define SV_STCONN	1
#define SV_STHEADERS	2
#define SV_STDATA	3
#define SV_STSHUTR	4
#define SV_STSHUTW	5
#define SV_STCLOSE	6


/* The HTTP parser is more complex than it looks like, because we have to
 * support multi-line headers and any number of spaces between the colon and
 * the value.
 *
 * All those examples must work :

 Hdr1:val1\r\n
 Hdr1: val1\r\n
 Hdr1:\t val1\r\n
 Hdr1: \r\n
  val1\r\n
 Hdr1:\r\n
  val1\n
 \tval2\r\n
  val3\n

 *
 */

/* Possible states while parsing HTTP messages (request|response) */
#define HTTP_MSG_RQBEFORE      0 // request: leading LF, before start line
#define HTTP_MSG_RQBEFORE_CR   1 // request: leading CRLF, before start line

/* these ones define a request start line */
#define HTTP_MSG_RQMETH        2 // parsing the Method
#define HTTP_MSG_RQMETH_SP     3 // space(s) after the ethod
#define HTTP_MSG_RQURI         4 // parsing the Request URI
#define HTTP_MSG_RQURI_SP      5 // space(s) after the Request URI
#define HTTP_MSG_RQVER         6 // parsing the Request Version
#define HTTP_MSG_RQLINE_END    7 // end of request line (CR or LF)

#define HTTP_MSG_RPBEFORE      8 // response: leading LF, before start line
#define HTTP_MSG_RPBEFORE_CR   9 // response: leading CRLF, before start line

/* these ones define a response start line */
#define HTTP_MSG_RPVER        10 // parsing the Response Version
#define HTTP_MSG_RPVER_SP     11 // space(s) after the Response Version
#define HTTP_MSG_RPCODE       12 // response code
#define HTTP_MSG_RPCODE_SP    13 // space(s) after the response code
#define HTTP_MSG_RPREASON     14 // response reason
#define HTTP_MSG_RPLINE_END   15 // end of response line (CR or LF)

/* common header processing */

#define HTTP_MSG_HDR_FIRST    16 // waiting for first header or last CRLF (no LWS possible)
#define HTTP_MSG_HDR_NAME     17 // parsing header name
#define HTTP_MSG_HDR_COL      18 // parsing header colon
#define HTTP_MSG_HDR_L1_SP    19 // parsing header LWS (SP|HT) before value
#define HTTP_MSG_HDR_L1_LF    20 // parsing header LWS (LF) before value
#define HTTP_MSG_HDR_L1_LWS   21 // checking whether it's a new header or an LWS
#define HTTP_MSG_HDR_VAL      22 // parsing header value
#define HTTP_MSG_HDR_L2_LF    23 // parsing header LWS (LF) inside/after value
#define HTTP_MSG_HDR_L2_LWS   24 // checking whether it's a new header or an LWS

#define HTTP_MSG_LAST_LF      25 // parsing last LF
#define HTTP_MSG_BODY         26 // parsing body at end of headers
#define HTTP_MSG_ERROR        27 // an error occurred


/* various data sources for the responses */
#define DATA_SRC_NONE	0
#define DATA_SRC_STATS	1

/* data transmission states for the stats responses */
enum {
	DATA_ST_INIT = 0,
	DATA_ST_HEAD,
	DATA_ST_INFO,
	DATA_ST_LIST,
	DATA_ST_END,
	DATA_ST_FIN,
};

/* data transmission states for the stats responses inside a proxy */
enum {
	DATA_ST_PX_INIT = 0,
	DATA_ST_PX_TH,
	DATA_ST_PX_FE,
	DATA_ST_PX_SV,
	DATA_ST_PX_BE,
	DATA_ST_PX_END,
	DATA_ST_PX_FIN,
};


#endif /* _TYPES_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
