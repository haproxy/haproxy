/*
 * include/types/proto_http.h
 * This file contains HTTP protocol definitions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_PROTO_HTTP_H
#define _TYPES_PROTO_HTTP_H

#include <common/config.h>

#include <types/buffers.h>
#include <types/hdr_idx.h>

/* These are the flags that are found in txn->flags */

/* action flags */
#define TX_CLDENY	0x00000001	/* a client header matches a deny regex */
#define TX_CLALLOW	0x00000002	/* a client header matches an allow regex */
#define TX_SVDENY	0x00000004	/* a server header matches a deny regex */
#define TX_SVALLOW	0x00000008	/* a server header matches an allow regex */
#define TX_CLTARPIT	0x00000010	/* the session is tarpitted (anti-dos) */

/* used only for keep-alive purposes, to indicate we're on a second transaction */
#define TX_NOT_FIRST	0x00000020	/* the transaction is not the first one */

/* transaction flags dedicated to cookies : bits values 0x40, 0x80 (0-3 shift 6) */
#define TX_CK_NONE	0x00000000	/* this session had no cookie */
#define TX_CK_INVALID	0x00000040	/* this session had a cookie which matches no server */
#define TX_CK_DOWN	0x00000080	/* this session had cookie matching a down server */
#define TX_CK_VALID	0x000000C0	/* this session had cookie matching a valid server */
#define TX_CK_MASK	0x000000C0	/* mask to get this session's cookie flags */
#define TX_CK_SHIFT	6		/* bit shift */

/* cookie information, bits values 0x100 to 0x800 (0-8 shift 8) */
#define TX_SCK_NONE	0x00000000	/* no set-cookie seen for the server cookie */
#define TX_SCK_DELETED	0x00000100	/* existing set-cookie deleted or changed */
#define TX_SCK_INSERTED	0x00000200	/* new set-cookie inserted or changed existing one */
#define TX_SCK_SEEN	0x00000400	/* set-cookie seen for the server cookie */
#define TX_SCK_MASK	0x00000700	/* mask to get the set-cookie field */
#define TX_SCK_ANY	0x00000800	/* at least one set-cookie seen (not to be counted) */
#define TX_SCK_SHIFT	8		/* bit shift */

/* cacheability management, bits values 0x1000 to 0x3000 (0-3 shift 12) */
#define TX_CACHEABLE	0x00001000	/* at least part of the response is cacheable */
#define TX_CACHE_COOK	0x00002000	/* a cookie in the response is cacheable */
#define TX_CACHE_SHIFT	12		/* bit shift */

/* request and response HTTP version */
#define TX_REQ_VER_11	0x00004000	/* the request is HTTP/1.1 or above */
#define TX_RES_VER_11	0x00008000	/* the response is HTTP/1.1 or above */

/* report presence of transfer-encoding:chunked and content-length headers */
#define TX_REQ_CNT_LEN	0x00010000	/* content-length present in the request */
#define TX_REQ_TE_CHNK	0x00020000	/* transfer-encoding: chunked present in the request */
#define TX_RES_CNT_LEN	0x00040000	/* content-length present in the response */
#define TX_RES_TE_CHNK	0x00080000	/* transfer-encoding: chunked present in the response */

/* indicate how we *want* the connection to behave, regardless of what is in
 * the headers. We have 4 possible values right now :
 * - WANT_TUN : will be a tunnel (default when nothing configured or with CONNECT).
 * - WANT_KAL : try to maintain keep-alive
 * - WANT_SCL : enforce close on the server side
 * - WANT_CLO : enforce close on both sides
 */
#define TX_CON_WANT_TUN 0x00000000	/* note: it's important that it is 0 (init) */
#define TX_CON_WANT_KAL 0x00100000
#define TX_CON_WANT_SCL 0x00200000
#define TX_CON_WANT_CLO 0x00300000
#define TX_CON_WANT_MSK 0x00300000	/* this is the mask to get the bits */

#define TX_CON_HDR_PARS	0x00400000	/* "connection" header already parsed (req or res) */
#define TX_REQ_CONN_CLO	0x00800000	/* request asks for "Connection: close" mode */

/* if either of these flags is not set, we may be forced to complete an
 * connection as a half-way tunnel. For instance, if no content-length
 * appears in a 1.1 response, but the request is correctly sized.
 */
#define TX_REQ_XFER_LEN	0x01000000	/* request xfer size can be determined */
#define TX_RES_XFER_LEN	0x02000000	/* response xfer size can be determined */
#define TX_WAIT_NEXT_RQ	0x04000000	/* waiting for the second request to start, use keep-alive timeout */

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

/* error state : must be before HTTP_MSG_BODY so that (>=BODY) always indicates
 * that data are being processed.
 */

#define HTTP_MSG_ERROR        26 // an error occurred

/* Body processing.
 * The state HTTP_MSG_BODY is a delimiter to know if we're waiting for headers
 * or body. All the sub-states below also indicate we're processing the body,
 * with some additional information.
 */
#define HTTP_MSG_BODY         27 // parsing body at end of headers
#define HTTP_MSG_100_SENT     28 // parsing body after a 100-Continue was sent
#define HTTP_MSG_CHUNK_SIZE   29 // parsing the chunk size (RFC2616 #3.6.1)
#define HTTP_MSG_DATA         30 // skipping data chunk / content-length data
#define HTTP_MSG_DATA_CRLF    31 // skipping CRLF after data chunk
#define HTTP_MSG_TRAILERS     32 // trailers (post-data entity headers)

/* we enter this state when we've received the end of the current message */
#define HTTP_MSG_DONE         33 // message end received, waiting for resync or close
#define HTTP_MSG_CLOSING      34 // shutdown_w done, not all bytes sent yet
#define HTTP_MSG_CLOSED       35 // shutdown_w done, all bytes sent
#define HTTP_MSG_TUNNEL       36 // tunneled data after DONE

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
	DATA_ST_PX_LI,
	DATA_ST_PX_SV,
	DATA_ST_PX_BE,
	DATA_ST_PX_END,
	DATA_ST_PX_FIN,
};

/* Redirect flags */
enum {
	REDIRECT_FLAG_NONE = 0,
	REDIRECT_FLAG_DROP_QS = 1,	/* drop query string */
	REDIRECT_FLAG_APPEND_SLASH = 2,	/* append a slash if missing at the end */
};

/* Redirect types (location, prefix, extended ) */
enum {
	REDIRECT_TYPE_NONE = 0,         /* no redirection */
	REDIRECT_TYPE_LOCATION,         /* location redirect */
	REDIRECT_TYPE_PREFIX,           /* prefix redirect */
};

/* Known HTTP methods */
typedef enum {
	HTTP_METH_NONE = 0,
	HTTP_METH_OPTIONS,
	HTTP_METH_GET,
	HTTP_METH_HEAD,
	HTTP_METH_POST,
	HTTP_METH_PUT,
	HTTP_METH_DELETE,
	HTTP_METH_TRACE,
	HTTP_METH_CONNECT,
	HTTP_METH_OTHER,
} http_meth_t;

/* This is an HTTP message, as described in RFC2616. It can be either a request
 * message or a response message.
 *
 * The values there are a little bit obscure, because their meaning can change
 * during the parsing :
 *
 *  - som (Start of Message) : relative offset in the buffer of first byte of
 *                             the request being processed or parsed. Reset to
 *                             zero during accept(), and changes while parsing
 *                             chunks.
 *  - eoh (End of Headers)   : relative offset in the buffer of first byte that
 *                             is not part of a completely processed header.
 *                             During parsing, it points to last header seen
 *                             for states after START. When in HTTP_MSG_BODY,
 *                             eoh points to the first byte of the last CRLF
 *                             preceeding data.
 *  - col and sov            : When in HTTP_MSG_BODY, will point to the first
 *                             byte of data (relative to buffer).
 *  - sol (start of line)    : start of line, also start of message when fully parsed.
 *  - eol (End of Line)      : relative offset in the buffer of the first byte
 *                             which marks the end of the line (LF or CRLF).
 * Note that all offsets are relative to the beginning of the buffer. To get
 * them relative to the current request, subtract ->som or ->sol.
 */
struct http_msg {
	unsigned int msg_state;                /* where we are in the current message parsing */
	unsigned int col, sov;                 /* current header: colon, start of value */
	unsigned int eoh;                      /* End Of Headers, relative to buffer */
	char *sol;                             /* start of line, also start of message when fully parsed */
	char *eol;                             /* end of line */
	unsigned int som;                      /* Start Of Message, relative to buffer */
	int err_pos;                           /* err handling: -2=block, -1=pass, 0+=detected */
	union {                                /* useful start line pointers, relative to ->sol */
		struct {
			int l;                 /* request line length (not including CR) */
			int m_l;               /* METHOD length (method starts at ->som) */
			int u, u_l;            /* URI, length */
			int v, v_l;            /* VERSION, length */
		} rq;                          /* request line : field, length */
		struct {
			int l;                 /* status line length (not including CR) */
			int v_l;               /* VERSION length (version starts at ->som) */
			int c, c_l;            /* CODE, length */
			int r, r_l;            /* REASON, length */
		} st;                          /* status line : field, length */
	} sl;                                  /* start line */
	unsigned long long hdr_content_len;    /* cache for parsed header value or for chunk-size if present */
	char **cap;                            /* array of captured headers (may be NULL) */
};

/* This is an HTTP transaction. It contains both a request message and a
 * response message (which can be empty).
 */
struct http_txn {
	struct http_msg req;            /* HTTP request message */
	struct hdr_idx hdr_idx;         /* array of header indexes (max: MAX_HTTP_HDR) */
	unsigned int flags;             /* transaction flags */
	http_meth_t meth;               /* HTTP method */

	int status;                     /* HTTP status from the server, negative if from proxy */
	struct http_msg rsp;            /* HTTP response message */

	char *uri;                      /* first line if log needed, NULL otherwise */
	char *cli_cookie;               /* cookie presented by the client, in capture mode */
	char *srv_cookie;               /* cookie presented by the server, in capture mode */
	char *sessid;                   /* the appsession id, if found in the request or in the response */

	struct chunk auth_hdr;          /* points to 'Authorization:' header */
};

/* This structure is used by http_find_header() to return values of headers.
 * The header starts at <line>, the value at <line>+<val> for <vlen> bytes, and
 * sets <line>+<del> to point to the last delimitor (colon or comma) before
 * this value. <prev> points to the index of the header whose next is this one.
 */
struct hdr_ctx {
	char *line;
	int  idx;
	int  val;  /* relative to line */
	int  vlen; /* relative to line+val */
	int  del;  /* relative to line */
	int  prev; /* index of previous header */
};

#endif /* _TYPES_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
