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

#include <types/hdr_idx.h>

/* These are the flags that are found in txn->flags */

/* action flags */
#define TX_CLDENY	0x00000001	/* a client header matches a deny regex */
#define TX_CLALLOW	0x00000002	/* a client header matches an allow regex */
#define TX_SVDENY	0x00000004	/* a server header matches a deny regex */
#define TX_SVALLOW	0x00000008	/* a server header matches an allow regex */
#define TX_CLTARPIT	0x00000010	/* the session is tarpitted (anti-dos) */

/* transaction flags dedicated to cookies : bits values 0x20 to 0x80 (0-7 shift 5) */
#define TX_CK_NONE	0x00000000	/* this session had no cookie */
#define TX_CK_INVALID	0x00000020	/* this session had a cookie which matches no server */
#define TX_CK_DOWN	0x00000040	/* this session had cookie matching a down server */
#define TX_CK_VALID	0x00000060	/* this session had cookie matching a valid server */
#define TX_CK_EXPIRED	0x00000080	/* this session had an expired cookie (idle for too long) */
#define TX_CK_OLD	0x000000A0	/* this session had too old a cookie (offered too long ago) */
#define TX_CK_UNUSED	0x000000C0	/* this session had a cookie but it was not used (eg: use-server was preferred) */
#define TX_CK_MASK	0x000000E0	/* mask to get this session's cookie flags */
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
#define TX_CACHE_SHIFT	12		/* bit shift */

/* Unused: 0x4000, 0x8000, 0x10000, 0x20000, 0x80000 */

/* indicate how we *want* the connection to behave, regardless of what is in
 * the headers. We have 4 possible values right now :
 * - WANT_KAL : try to maintain keep-alive (default hwen nothing configured)
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

/* Possible states while parsing HTTP messages (request|response) */
enum ht_state {
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
	HTTP_MSG_CHUNK_SIZE   = 29, // parsing the chunk size (RFC2616 #3.6.1)
	HTTP_MSG_DATA         = 30, // skipping data chunk / content-length data
	HTTP_MSG_CHUNK_CRLF   = 31, // skipping CRLF after data chunk
	HTTP_MSG_TRAILERS     = 32, // trailers (post-data entity headers)
	/* we enter this state when we've received the end of the current message */
	HTTP_MSG_DONE         = 33, // message end received, waiting for resync or close
	HTTP_MSG_CLOSING      = 34, // shutdown_w done, not all bytes sent yet
	HTTP_MSG_CLOSED       = 35, // shutdown_w done, all bytes sent
	HTTP_MSG_TUNNEL       = 36, // tunneled data after DONE
} __attribute__((packed));

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

/* Known HTTP methods */
enum http_meth_t {
	HTTP_METH_NONE = 0,
	HTTP_METH_OPTIONS,
	HTTP_METH_GET,
	HTTP_METH_HEAD,
	HTTP_METH_POST,
	HTTP_METH_PUT,
	HTTP_METH_DELETE,
	HTTP_METH_TRACE,
	HTTP_METH_CONNECT,
	HTTP_METH_OTHER, /* Must be the last entry */
} __attribute__((packed));

enum ht_auth_m {
	HTTP_AUTH_WRONG		= -1,		/* missing or unknown */
	HTTP_AUTH_UNKNOWN	= 0,
	HTTP_AUTH_BASIC,
	HTTP_AUTH_DIGEST,
} __attribute__((packed));

/* actions for "http-request" */
enum {
	HTTP_REQ_ACT_UNKNOWN = 0,
	HTTP_REQ_ACT_ALLOW,
	HTTP_REQ_ACT_DENY,
	HTTP_REQ_ACT_TARPIT,
	HTTP_REQ_ACT_AUTH,
	HTTP_REQ_ACT_ADD_HDR,
	HTTP_REQ_ACT_SET_HDR,
	HTTP_REQ_ACT_DEL_HDR,
	HTTP_REQ_ACT_REPLACE_HDR,
	HTTP_REQ_ACT_REPLACE_VAL,
	HTTP_REQ_ACT_REDIR,
	HTTP_REQ_ACT_SET_NICE,
	HTTP_REQ_ACT_SET_LOGL,
	HTTP_REQ_ACT_SET_TOS,
	HTTP_REQ_ACT_SET_MARK,
	HTTP_REQ_ACT_ADD_ACL,
	HTTP_REQ_ACT_DEL_ACL,
	HTTP_REQ_ACT_DEL_MAP,
	HTTP_REQ_ACT_SET_MAP,
	HTTP_REQ_ACT_CUSTOM_STOP,
	HTTP_REQ_ACT_CUSTOM_CONT,
	HTTP_REQ_ACT_MAX /* must always be last */
};

/* actions for "http-response" */
enum {
	HTTP_RES_ACT_UNKNOWN = 0,
	HTTP_RES_ACT_ALLOW,
	HTTP_RES_ACT_DENY,
	HTTP_RES_ACT_ADD_HDR,
	HTTP_RES_ACT_REPLACE_HDR,
	HTTP_RES_ACT_REPLACE_VAL,
	HTTP_RES_ACT_SET_HDR,
	HTTP_RES_ACT_DEL_HDR,
	HTTP_RES_ACT_SET_NICE,
	HTTP_RES_ACT_SET_LOGL,
	HTTP_RES_ACT_SET_TOS,
	HTTP_RES_ACT_SET_MARK,
	HTTP_RES_ACT_ADD_ACL,
	HTTP_RES_ACT_DEL_ACL,
	HTTP_RES_ACT_DEL_MAP,
	HTTP_RES_ACT_SET_MAP,
	HTTP_RES_ACT_CUSTOM_STOP,  /* used for module keywords */
	HTTP_RES_ACT_CUSTOM_CONT,  /* used for module keywords */
	HTTP_RES_ACT_MAX /* must always be last */
};

/* final results for http-request rules */
enum rule_result {
	HTTP_RULE_RES_CONT = 0,  /* nothing special, continue rules evaluation */
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
	HTTP_ERR_408,
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

/* This is an HTTP message, as described in RFC2616. It can be either a request
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
 *  - sol (start of line)    : start of current line before MSG_BODY, or zero.
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
	enum ht_state msg_state;               /* where we are in the current message parsing */
	unsigned char flags;                   /* flags describing the message (HTTP version, ...) */
	/* 6 bytes unused here */
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
	char **cap;                            /* array of captured headers (may be NULL) */
};

struct http_auth_data {
	enum ht_auth_m method;                /* one of HTTP_AUTH_* */
	/* 7 bytes unused here */
	struct chunk method_data;             /* points to the creditial part from 'Authorization:' header */
	char *user, *pass;                    /* extracted username & password */
};

struct proxy;
struct http_txn;
struct session;

struct http_req_rule {
	struct list list;
	struct acl_cond *cond;                 /* acl condition to meet */
	unsigned int action;                   /* HTTP_REQ_* */
	int (*action_ptr)(struct http_req_rule *rule, struct proxy *px, struct session *s, struct http_txn *http_txn);  /* ptr to custom action */
	union {
		struct {
			char *realm;
		} auth;                        /* arg used by "auth" */
		struct {
			char *name;            /* header name */
			int name_len;          /* header name's length */
			struct list fmt;       /* log-format compatible expression */
			struct my_regex re;    /* used by replace-header and replace-value */
		} hdr_add;                     /* args used by "add-header" and "set-header" */
		struct redirect_rule *redir;   /* redirect rule or "http-request redirect" */
		int nice;                      /* nice value for HTTP_REQ_ACT_SET_NICE */
		int loglevel;                  /* log-level value for HTTP_REQ_ACT_SET_LOGL */
		int tos;                       /* tos value for HTTP_REQ_ACT_SET_TOS */
		int mark;                      /* nfmark value for HTTP_REQ_ACT_SET_MARK */
		void *data;                    /* generic pointer for module or external rule */
		struct {
			char *ref;             /* MAP or ACL file name to update */
			struct list key;       /* pattern to retrieve MAP or ACL key */
			struct list value;     /* pattern to retrieve MAP value */
		} map;
	} arg;                                 /* arguments used by some actions */
};

struct http_res_rule {
	struct list list;
	struct acl_cond *cond;                 /* acl condition to meet */
	unsigned int action;                   /* HTTP_RES_* */
	int (*action_ptr)(struct http_res_rule *rule, struct proxy *px, struct session *s, struct http_txn *http_txn);  /* ptr to custom action */
	union {
		struct {
			char *name;            /* header name */
			int name_len;          /* header name's length */
			struct list fmt;       /* log-format compatible expression */
			struct my_regex re;    /* used by replace-header and replace-value */
		} hdr_add;                     /* args used by "add-header" and "set-header" */
		int nice;                      /* nice value for HTTP_RES_ACT_SET_NICE */
		int loglevel;                  /* log-level value for HTTP_RES_ACT_SET_LOGL */
		int tos;                       /* tos value for HTTP_RES_ACT_SET_TOS */
		int mark;                      /* nfmark value for HTTP_RES_ACT_SET_MARK */
		void *data;                    /* generic pointer for module or external rule */
		struct {
			char *ref;             /* MAP or ACL file name to update */
			struct list key;       /* pattern to retrieve MAP or ACL key */
			struct list value;     /* pattern to retrieve MAP value */
		} map;
	} arg;                                 /* arguments used by some actions */
};

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

	char *uri;                      /* first line if log needed, NULL otherwise */
	char *cli_cookie;               /* cookie presented by the client, in capture mode */
	char *srv_cookie;               /* cookie presented by the server, in capture mode */
	char *sessid;                   /* the appsession id, if found in the request or in the response */
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

struct http_req_action_kw {
       const char *kw;
       int (*parse)(const char **args, int *cur_arg, struct proxy *px, struct http_req_rule *rule, char **err);
};

struct http_res_action_kw {
       const char *kw;
       int (*parse)(const char **args, int *cur_arg, struct proxy *px, struct http_res_rule *rule, char **err);
};

struct http_req_action_kw_list {
       const char *scope;
       struct list list;
       struct http_req_action_kw kw[VAR_ARRAY];
};

struct http_res_action_kw_list {
       const char *scope;
       struct list list;
       struct http_res_action_kw kw[VAR_ARRAY];
};

extern struct http_req_action_kw_list http_req_keywords;
extern struct http_res_action_kw_list http_res_keywords;

extern const struct http_method_name http_known_methods[HTTP_METH_OTHER];

#endif /* _TYPES_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
