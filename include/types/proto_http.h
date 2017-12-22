/*
 * include/types/proto_http.h
 * This file contains HTTP protocol definitions.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
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

#include <common/chunk.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/regex.h>

#include <types/channel.h>
#include <types/h1.h>
#include <types/hdr_idx.h>
#include <types/filters.h>
#include <types/sample.h>

/* These are the flags that are found in txn->flags */

/* action flags */
#define TX_CLDENY	0x00000001	/* a client header matches a deny regex */
#define TX_CLALLOW	0x00000002	/* a client header matches an allow regex */
#define TX_SVDENY	0x00000004	/* a server header matches a deny regex */
#define TX_SVALLOW	0x00000008	/* a server header matches an allow regex */
#define TX_CLTARPIT	0x00000010	/* the transaction is tarpitted (anti-dos) */

/* transaction flags dedicated to cookies : bits values 0x20 to 0x80 (0-7 shift 5) */
#define TX_CK_NONE	0x00000000	/* this transaction had no cookie */
#define TX_CK_INVALID	0x00000020	/* this transaction had a cookie which matches no server */
#define TX_CK_DOWN	0x00000040	/* this transaction had cookie matching a down server */
#define TX_CK_VALID	0x00000060	/* this transaction had cookie matching a valid server */
#define TX_CK_EXPIRED	0x00000080	/* this transaction had an expired cookie (idle for too long) */
#define TX_CK_OLD	0x000000A0	/* this transaction had too old a cookie (offered too long ago) */
#define TX_CK_UNUSED	0x000000C0	/* this transaction had a cookie but it was not used (eg: use-server was preferred) */
#define TX_CK_MASK	0x000000E0	/* mask to get this transaction's cookie flags */
#define TX_CK_SHIFT	5		/* bit shift */

/* response cookie information, bits values 0x100 to 0x700 (0-7 shift 8) */
#define TX_SCK_NONE	0x00000000	/* no cookie found in the response */
#define TX_SCK_FOUND    0x00000100	/* a persistence cookie was found and forwarded */
#define TX_SCK_DELETED	0x00000200	/* an existing persistence cookie was deleted */
#define TX_SCK_INSERTED	0x00000300	/* a persistence cookie was inserted */
#define TX_SCK_REPLACED	0x00000400	/* a persistence cookie was present and rewritten */
#define TX_SCK_UPDATED	0x00000500	/* an expirable persistence cookie was updated */
#define TX_SCK_MASK	0x00000700	/* mask to get the set-cookie field */
#define TX_SCK_SHIFT	8		/* bit shift */

#define TX_SCK_PRESENT  0x00000800	/* a cookie was found in the server's response */

/* cacheability management, bits values 0x1000 to 0x3000 (0-3 shift 12) */
#define TX_CACHEABLE	0x00001000	/* at least part of the response is cacheable */
#define TX_CACHE_COOK	0x00002000	/* a cookie in the response is cacheable */
#define TX_CACHE_IGNORE 0x00004000	/* do not retrieve object from cache */
#define TX_CACHE_SHIFT	12		/* bit shift */

/* Unused: 0x8000 */

#define TX_WAIT_CLEANUP	0x0010000	/* this transaction is waiting for a clean up */

/* Unused: 0x20000, 0x80000 */


/* indicate how we *want* the connection to behave, regardless of what is in
 * the headers. We have 4 possible values right now :
 * - WANT_KAL : try to maintain keep-alive (default when nothing configured)
 * - WANT_TUN : will be a tunnel (CONNECT).
 * - WANT_SCL : enforce close on the server side
 * - WANT_CLO : enforce close on both sides
 */
#define TX_CON_WANT_KAL 0x00000000	/* note: it's important that it is 0 (init) */
#define TX_CON_WANT_TUN 0x00100000
#define TX_CON_WANT_SCL 0x00200000
#define TX_CON_WANT_CLO 0x00300000
#define TX_CON_WANT_MSK 0x00300000	/* this is the mask to get the bits */

#define TX_CON_CLO_SET  0x00400000	/* "connection: close" is now set */
#define TX_CON_KAL_SET  0x00800000	/* "connection: keep-alive" is now set */

#define TX_PREFER_LAST  0x01000000      /* try to stay on same server if possible (eg: after 401) */

#define TX_HDR_CONN_UPG 0x02000000	/* The "Upgrade" token was found in the "Connection" header */
#define TX_WAIT_NEXT_RQ	0x04000000	/* waiting for the second request to start, use keep-alive timeout */

#define TX_HDR_CONN_PRS	0x08000000	/* "connection" header already parsed (req or res), results below */
#define TX_HDR_CONN_CLO	0x10000000	/* "Connection: close" was present at least once */
#define TX_HDR_CONN_KAL	0x20000000	/* "Connection: keep-alive" was present at least once */
#define TX_USE_PX_CONN	0x40000000	/* Use "Proxy-Connection" instead of "Connection" */

/* used only for keep-alive purposes, to indicate we're on a second transaction */
#define TX_NOT_FIRST	0x80000000	/* the transaction is not the first one */
/* no more room for transaction flags ! */

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

/*
 * HTTP message status flags (msg->flags)
 */
#define HTTP_MSGF_CNT_LEN     0x00000001  /* content-length was found in the message */
#define HTTP_MSGF_TE_CHNK     0x00000002  /* transfer-encoding: chunked was found */

/* if this flags is not set in either direction, we may be forced to complete a
 * connection as a half-way tunnel (eg if no content-length appears in a 1.1
 * response, but the request is correctly sized)
 */
#define HTTP_MSGF_XFER_LEN    0x00000004  /* message xfer size can be determined */
#define HTTP_MSGF_VER_11      0x00000008  /* the message is HTTP/1.1 or above */

/* If this flag is set, we don't process the body until the connect() is confirmed.
 * This is only used by the request forwarding function to protect the buffer
 * contents if something needs them during a redispatch.
 */
#define HTTP_MSGF_WAIT_CONN   0x00000010  /* Wait for connect() to be confirmed before processing body */
#define HTTP_MSGF_COMPRESSING 0x00000020  /* data compression is in progress */


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
	REDIRECT_TYPE_SCHEME,           /* scheme redirect (eg: switch from http to https) */
};

/* Perist types (force-persist, ignore-persist) */
enum {
	PERSIST_TYPE_NONE = 0,          /* no persistence */
	PERSIST_TYPE_FORCE,             /* force-persist */
	PERSIST_TYPE_IGNORE,            /* ignore-persist */
};

enum ht_auth_m {
	HTTP_AUTH_WRONG		= -1,		/* missing or unknown */
	HTTP_AUTH_UNKNOWN	= 0,
	HTTP_AUTH_BASIC,
	HTTP_AUTH_DIGEST,
} __attribute__((packed));

/* final results for http-request rules */
enum rule_result {
	HTTP_RULE_RES_CONT = 0,  /* nothing special, continue rules evaluation */
	HTTP_RULE_RES_YIELD,     /* call me later because some data is missing. */
	HTTP_RULE_RES_STOP,      /* stopped processing on an accept */
	HTTP_RULE_RES_DENY,      /* deny (or tarpit if TX_CLTARPIT)  */
	HTTP_RULE_RES_ABRT,      /* abort request, msg already sent (eg: auth) */
	HTTP_RULE_RES_DONE,      /* processing done, stop processing (eg: redirect) */
	HTTP_RULE_RES_BADREQ,    /* bad request */
};

/*
 * All implemented return codes
 */
enum {
	HTTP_ERR_200 = 0,
	HTTP_ERR_400,
	HTTP_ERR_403,
	HTTP_ERR_405,
	HTTP_ERR_408,
	HTTP_ERR_425,
	HTTP_ERR_429,
	HTTP_ERR_500,
	HTTP_ERR_502,
	HTTP_ERR_503,
	HTTP_ERR_504,
	HTTP_ERR_SIZE
};

/* status codes available for the stats admin page */
enum {
	STAT_STATUS_INIT = 0,
	STAT_STATUS_DENY,	/* action denied */
	STAT_STATUS_DONE,	/* the action is successful */
	STAT_STATUS_ERRP,	/* an error occured due to invalid values in parameters */
	STAT_STATUS_EXCD,	/* an error occured because the buffer couldn't store all data */
	STAT_STATUS_NONE,	/* nothing happened (no action chosen or servers state didn't change) */
	STAT_STATUS_PART,	/* the action is partially successful */
	STAT_STATUS_UNKN,	/* an unknown error occured, shouldn't happen */
	STAT_STATUS_SIZE
};

/* This is an HTTP message, as described in RFC7230. It can be either a request
 * message or a response message.
 *
 * The values there are a little bit obscure, because their meaning can change
 * during the parsing. Please read carefully doc/internal/body-parsing.txt if
 * you need to manipulate them. Quick reminder :
 *
 *  - eoh (End of Headers)   : relative offset in the buffer of first byte that
 *                             is not part of a completely processed header.
 *                             During parsing, it points to last header seen
 *                             for states after START. When in HTTP_MSG_BODY,
 *                             eoh points to the first byte of the last CRLF
 *                             preceeding data. Relative to buffer's origin.
 *                             This value then remains unchanged till the end
 *                             so that we can rewind the buffer to change some
 *                             headers if needed (eg: http-send-name-header).
 *
 *  - sov (start of value)   : Before HTTP_MSG_BODY, points to the value of
 *                             the header being parsed. Starting from
 *                             HTTP_MSG_BODY, will point to the start of the
 *                             body (relative to buffer's origin). It can be
 *                             negative when forwarding data. It stops growing
 *                             once data start to leave the buffer.
 *
 *  - next (parse pointer)   : next relative byte to be parsed. Always points
 *                             to a byte matching the current state.
 *
 *  - sol (start of line)    : start of current line before MSG_BODY. Starting
 *                             from MSG_BODY and until MSG_TRAILERS, contains
 *                             the length of the last parsed chunk size so that
 *                             when added to sov it always points to the
 *                             beginning of the current data chunk.
 *                             in MSG_TRAILERS state, it contains the length of
 *                             the last parsed part of the trailer headers.
 *
 *  - eol (End of Line)      : Before HTTP_MSG_BODY, relative offset in the
 *                             buffer of the first byte which marks the end of
 *                             the line current (LF or CRLF).
 *                             From HTTP_MSG_BODY to the end, contains the
 *                             length of the last CRLF (1 for a plain LF, or 2
 *                             for a true CRLF). So eoh+eol always contain the
 *                             exact size of the header size.
 *
 * Note that all offsets are relative to the origin of the buffer (buf->p)
 * which always points to the beginning of the message (request or response).
 * Since a message may not wrap, pointer computations may be one without any
 * care for wrapping (no addition overflow nor subtract underflow).
 */
struct http_msg {
	enum h1_state msg_state;               /* where we are in the current message parsing */
	enum h1_state err_state;               /* the state where the parsing error was detected, only is MSG_ERROR */
	unsigned char flags;                   /* flags describing the message (HTTP version, ...) */
	/* 5 bytes unused here */
	struct channel *chn;                   /* pointer to the channel transporting the message */
	unsigned int next;                     /* pointer to next byte to parse, relative to buf->p */
	int sov;                               /* current header: start of value ; data: start of body */
	unsigned int eoh;                      /* End Of Headers, relative to buffer */
	unsigned int sol;                      /* start of current line during parsing otherwise zero */
	unsigned int eol;                      /* end of line */
	int err_pos;                           /* err handling: -2=block, -1=pass, 0+=detected */
	union {                                /* useful start line pointers, relative to ->sol */
		struct {
			int l;                 /* request line length (not including CR) */
			int m_l;               /* METHOD length (method starts at buf->p) */
			int u, u_l;            /* URI, length */
			int v, v_l;            /* VERSION, length */
		} rq;                          /* request line : field, length */
		struct {
			int l;                 /* status line length (not including CR) */
			int v_l;               /* VERSION length (version starts at buf->p) */
			int c, c_l;            /* CODE, length */
			int r, r_l;            /* REASON, length */
		} st;                          /* status line : field, length */
	} sl;                                  /* start line */
	unsigned long long chunk_len;          /* cache for last chunk size or content-length header value */
	unsigned long long body_len;           /* total known length of the body, excluding encoding */
};

struct http_auth_data {
	enum ht_auth_m method;                /* one of HTTP_AUTH_* */
	/* 7 bytes unused here */
	struct chunk method_data;             /* points to the creditial part from 'Authorization:' header */
	char *user, *pass;                    /* extracted username & password */
};

struct proxy;
struct http_txn;
struct stream;

/* This is an HTTP transaction. It contains both a request message and a
 * response message (which can be empty).
 */
struct http_txn {
	struct hdr_idx hdr_idx;         /* array of header indexes (max: global.tune.max_http_hdr) */
	struct http_msg rsp;            /* HTTP response message */
	struct http_msg req;            /* HTTP request message */
	unsigned int flags;             /* transaction flags */
	enum http_meth_t meth;          /* HTTP method */
	/* 1 unused byte here */
	short status;                   /* HTTP status from the server, negative if from proxy */

	char cache_hash[20];               /* Store the cache hash  */
	char *uri;                      /* first line if log needed, NULL otherwise */
	char *cli_cookie;               /* cookie presented by the client, in capture mode */
	char *srv_cookie;               /* cookie presented by the server, in capture mode */
	int cookie_first_date;          /* if non-zero, first date the expirable cookie was set/seen */
	int cookie_last_date;           /* if non-zero, last date the expirable cookie was set/seen */

	struct http_auth_data auth;	/* HTTP auth data */
};


/* This structure is used by http_find_header() to return values of headers.
 * The header starts at <line>, the value (excluding leading and trailing white
 * spaces) at <line>+<val> for <vlen> bytes, followed by optional <tws> trailing
 * white spaces, and sets <line>+<del> to point to the last delimitor (colon or
 * comma) before this value. <prev> points to the index of the header whose next
 * is this one.
 */
struct hdr_ctx {
	char *line;
	int  idx;
	int  val;  /* relative to line, may skip some leading white spaces */
	int  vlen; /* relative to line+val, stops before trailing white spaces */
	int  tws;  /* added to vlen if some trailing white spaces are present */
	int  del;  /* relative to line */
	int  prev; /* index of previous header */
};

struct http_method_name {
	char *name;
	int len;
};

extern struct action_kw_list http_req_keywords;
extern struct action_kw_list http_res_keywords;

extern const struct http_method_name http_known_methods[HTTP_METH_OTHER];

extern struct pool_head *pool_head_http_txn;

#endif /* _TYPES_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
