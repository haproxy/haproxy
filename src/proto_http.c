/*
 * HTTP protocol analyzer
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <common/base64.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/cli.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/cache.h>
#include <types/stats.h>

#include <proto/acl.h>
#include <proto/action.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/cli.h>
#include <proto/compression.h>
#include <proto/stats.h>
#include <proto/fd.h>
#include <proto/filters.h>
#include <proto/frontend.h>
#include <proto/h1.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/pattern.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/pattern.h>
#include <proto/vars.h>

const char HTTP_100[] =
	"HTTP/1.1 100 Continue\r\n\r\n";

const struct chunk http_100_chunk = {
	.str = (char *)&HTTP_100,
	.len = sizeof(HTTP_100)-1
};

/* Warning: no "connection" header is provided with the 3xx messages below */
const char *HTTP_301 =
	"HTTP/1.1 301 Moved Permanently\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

const char *HTTP_302 =
	"HTTP/1.1 302 Found\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 302 except that the browser MUST retry with the GET method */
const char *HTTP_303 =
	"HTTP/1.1 303 See Other\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */


/* same as 302 except that the browser MUST retry with the same method */
const char *HTTP_307 =
	"HTTP/1.1 307 Temporary Redirect\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 301 except that the browser MUST retry with the same method */
const char *HTTP_308 =
	"HTTP/1.1 308 Permanent Redirect\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* Warning: this one is an sprintf() fmt string, with <realm> as its only argument */
const char *HTTP_401_fmt =
	"HTTP/1.0 401 Unauthorized\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"WWW-Authenticate: Basic realm=\"%s\"\r\n"
	"\r\n"
	"<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n";

const char *HTTP_407_fmt =
	"HTTP/1.0 407 Unauthorized\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"Proxy-Authenticate: Basic realm=\"%s\"\r\n"
	"\r\n"
	"<html><body><h1>407 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n";


const int http_err_codes[HTTP_ERR_SIZE] = {
	[HTTP_ERR_200] = 200,  /* used by "monitor-uri" */
	[HTTP_ERR_400] = 400,
	[HTTP_ERR_403] = 403,
	[HTTP_ERR_405] = 405,
	[HTTP_ERR_408] = 408,
	[HTTP_ERR_425] = 425,
	[HTTP_ERR_429] = 429,
	[HTTP_ERR_500] = 500,
	[HTTP_ERR_502] = 502,
	[HTTP_ERR_503] = 503,
	[HTTP_ERR_504] = 504,
};

static const char *http_err_msgs[HTTP_ERR_SIZE] = {
	[HTTP_ERR_200] =
	"HTTP/1.0 200 OK\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n",

	[HTTP_ERR_400] =
	"HTTP/1.0 400 Bad request\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n",

	[HTTP_ERR_403] =
	"HTTP/1.0 403 Forbidden\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n",

	[HTTP_ERR_405] =
	"HTTP/1.0 405 Method Not Allowed\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>405 Method Not Allowed</h1>\nA request was made of a resource using a request method not supported by that resource\n</body></html>\n",

	[HTTP_ERR_408] =
	"HTTP/1.0 408 Request Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n",

	[HTTP_ERR_425] =
	"HTTP/1.0 425 Too Early\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>425 Too Early</h1>\nYour browser sent early data.\n</body></html>\n",

	[HTTP_ERR_429] =
	"HTTP/1.0 429 Too Many Requests\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>429 Too Many Requests</h1>\nYou have sent too many requests in a given amount of time.\n</body></html>\n",

	[HTTP_ERR_500] =
	"HTTP/1.0 500 Internal Server Error\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>500 Internal Server Error</h1>\nAn internal server error occured.\n</body></html>\n",

	[HTTP_ERR_502] =
	"HTTP/1.0 502 Bad Gateway\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n",

	[HTTP_ERR_503] =
	"HTTP/1.0 503 Service Unavailable\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n",

	[HTTP_ERR_504] =
	"HTTP/1.0 504 Gateway Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time.\n</body></html>\n",

};

/* status codes available for the stats admin page (strictly 4 chars length) */
const char *stat_status_codes[STAT_STATUS_SIZE] = {
	[STAT_STATUS_DENY] = "DENY",
	[STAT_STATUS_DONE] = "DONE",
	[STAT_STATUS_ERRP] = "ERRP",
	[STAT_STATUS_EXCD] = "EXCD",
	[STAT_STATUS_NONE] = "NONE",
	[STAT_STATUS_PART] = "PART",
	[STAT_STATUS_UNKN] = "UNKN",
};


/* List head of all known action keywords for "http-request" */
struct action_kw_list http_req_keywords = {
       .list = LIST_HEAD_INIT(http_req_keywords.list)
};

/* List head of all known action keywords for "http-response" */
struct action_kw_list http_res_keywords = {
       .list = LIST_HEAD_INIT(http_res_keywords.list)
};

/* We must put the messages here since GCC cannot initialize consts depending
 * on strlen().
 */
struct chunk http_err_chunks[HTTP_ERR_SIZE];

/* this struct is used between calls to smp_fetch_hdr() or smp_fetch_cookie() */
static THREAD_LOCAL struct hdr_ctx static_hdr_ctx;

#define FD_SETS_ARE_BITFIELDS
#ifdef FD_SETS_ARE_BITFIELDS
/*
 * This map is used with all the FD_* macros to check whether a particular bit
 * is set or not. Each bit represents an ACSII code. FD_SET() sets those bytes
 * which should be encoded. When FD_ISSET() returns non-zero, it means that the
 * byte should be encoded. Be careful to always pass bytes from 0 to 255
 * exclusively to the macros.
 */
fd_set hdr_encode_map[(sizeof(fd_set) > (256/8)) ? 1 : ((256/8) / sizeof(fd_set))];
fd_set url_encode_map[(sizeof(fd_set) > (256/8)) ? 1 : ((256/8) / sizeof(fd_set))];
fd_set http_encode_map[(sizeof(fd_set) > (256/8)) ? 1 : ((256/8) / sizeof(fd_set))];

#else
#error "Check if your OS uses bitfields for fd_sets"
#endif

static int http_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn);

static inline int http_msg_forward_body(struct stream *s, struct http_msg *msg);
static inline int http_msg_forward_chunked_body(struct stream *s, struct http_msg *msg);

/* This function returns a reason associated with the HTTP status.
 * This function never fails, a message is always returned.
 */
const char *get_reason(unsigned int status)
{
	switch (status) {
	case 100: return "Continue";
	case 101: return "Switching Protocols";
	case 102: return "Processing";
	case 200: return "OK";
	case 201: return "Created";
	case 202: return "Accepted";
	case 203: return "Non-Authoritative Information";
	case 204: return "No Content";
	case 205: return "Reset Content";
	case 206: return "Partial Content";
	case 207: return "Multi-Status";
	case 210: return "Content Different";
	case 226: return "IM Used";
	case 300: return "Multiple Choices";
	case 301: return "Moved Permanently";
	case 302: return "Moved Temporarily";
	case 303: return "See Other";
	case 304: return "Not Modified";
	case 305: return "Use Proxy";
	case 307: return "Temporary Redirect";
	case 308: return "Permanent Redirect";
	case 310: return "Too many Redirects";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 402: return "Payment Required";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 406: return "Not Acceptable";
	case 407: return "Proxy Authentication Required";
	case 408: return "Request Time-out";
	case 409: return "Conflict";
	case 410: return "Gone";
	case 411: return "Length Required";
	case 412: return "Precondition Failed";
	case 413: return "Request Entity Too Large";
	case 414: return "Request-URI Too Long";
	case 415: return "Unsupported Media Type";
	case 416: return "Requested range unsatisfiable";
	case 417: return "Expectation failed";
	case 418: return "I'm a teapot";
	case 422: return "Unprocessable entity";
	case 423: return "Locked";
	case 424: return "Method failure";
	case 425: return "Too Early";
	case 426: return "Upgrade Required";
	case 428: return "Precondition Required";
	case 429: return "Too Many Requests";
	case 431: return "Request Header Fields Too Large";
	case 449: return "Retry With";
	case 450: return "Blocked by Windows Parental Controls";
	case 451: return "Unavailable For Legal Reasons";
	case 456: return "Unrecoverable Error";
	case 499: return "client has closed connection";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway or Proxy Error";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Time-out";
	case 505: return "HTTP Version not supported";
	case 506: return "Variant also negociate";
	case 507: return "Insufficient storage";
	case 508: return "Loop detected";
	case 509: return "Bandwidth Limit Exceeded";
	case 510: return "Not extended";
	case 511: return "Network authentication required";
	case 520: return "Web server is returning an unknown error";
	default:
		switch (status) {
		case 100 ... 199: return "Informational";
		case 200 ... 299: return "Success";
		case 300 ... 399: return "Redirection";
		case 400 ... 499: return "Client Error";
		case 500 ... 599: return "Server Error";
		default:          return "Other";
		}
	}
}

/* This function returns HTTP_ERR_<num> (enum) matching http status code.
 * Returned value should match codes from http_err_codes.
 */
static const int http_get_status_idx(unsigned int status)
{
	switch (status) {
	case 200: return HTTP_ERR_200;
	case 400: return HTTP_ERR_400;
	case 403: return HTTP_ERR_403;
	case 405: return HTTP_ERR_405;
	case 408: return HTTP_ERR_408;
	case 425: return HTTP_ERR_425;
	case 429: return HTTP_ERR_429;
	case 500: return HTTP_ERR_500;
	case 502: return HTTP_ERR_502;
	case 503: return HTTP_ERR_503;
	case 504: return HTTP_ERR_504;
	default: return HTTP_ERR_500;
	}
}

void init_proto_http()
{
	int i;
	char *tmp;
	int msg;

	for (msg = 0; msg < HTTP_ERR_SIZE; msg++) {
		if (!http_err_msgs[msg]) {
			ha_alert("Internal error: no message defined for HTTP return code %d. Aborting.\n", msg);
			abort();
		}

		http_err_chunks[msg].str = (char *)http_err_msgs[msg];
		http_err_chunks[msg].len = strlen(http_err_msgs[msg]);
	}

	/* initialize the log header encoding map : '{|}"#' should be encoded with
	 * '#' as prefix, as well as non-printable characters ( <32 or >= 127 ).
	 * URL encoding only requires '"', '#' to be encoded as well as non-
	 * printable characters above.
	 */
	memset(hdr_encode_map, 0, sizeof(hdr_encode_map));
	memset(url_encode_map, 0, sizeof(url_encode_map));
	memset(http_encode_map, 0, sizeof(url_encode_map));
	for (i = 0; i < 32; i++) {
		FD_SET(i, hdr_encode_map);
		FD_SET(i, url_encode_map);
	}
	for (i = 127; i < 256; i++) {
		FD_SET(i, hdr_encode_map);
		FD_SET(i, url_encode_map);
	}

	tmp = "\"#{|}";
	while (*tmp) {
		FD_SET(*tmp, hdr_encode_map);
		tmp++;
	}

	tmp = "\"#";
	while (*tmp) {
		FD_SET(*tmp, url_encode_map);
		tmp++;
	}

	/* initialize the http header encoding map. The draft httpbis define the
	 * header content as:
	 *
	 *    HTTP-message   = start-line
	 *                     *( header-field CRLF )
	 *                     CRLF
	 *                     [ message-body ]
	 *    header-field   = field-name ":" OWS field-value OWS
	 *    field-value    = *( field-content / obs-fold )
	 *    field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
	 *    obs-fold       = CRLF 1*( SP / HTAB )
	 *    field-vchar    = VCHAR / obs-text
	 *    VCHAR          = %x21-7E
	 *    obs-text       = %x80-FF
	 *
	 * All the chars are encoded except "VCHAR", "obs-text", SP and HTAB.
	 * The encoded chars are form 0x00 to 0x08, 0x0a to 0x1f and 0x7f. The
	 * "obs-fold" is volontary forgotten because haproxy remove this.
	 */
	memset(http_encode_map, 0, sizeof(http_encode_map));
	for (i = 0x00; i <= 0x08; i++)
		FD_SET(i, http_encode_map);
	for (i = 0x0a; i <= 0x1f; i++)
		FD_SET(i, http_encode_map);
	FD_SET(0x7f, http_encode_map);

	/* memory allocations */
	pool_head_http_txn = create_pool("http_txn", sizeof(struct http_txn), MEM_F_SHARED);
	pool_head_uniqueid = create_pool("uniqueid", UNIQUEID_LEN, MEM_F_SHARED);
}

/*
 * We have 26 list of methods (1 per first letter), each of which can have
 * up to 3 entries (2 valid, 1 null).
 */
struct http_method_desc {
	enum http_meth_t meth;
	int len;
	const char text[8];
};

const struct http_method_desc http_methods[26][3] = {
	['C' - 'A'] = {
		[0] = {	.meth = HTTP_METH_CONNECT , .len=7, .text="CONNECT" },
	},
	['D' - 'A'] = {
		[0] = {	.meth = HTTP_METH_DELETE  , .len=6, .text="DELETE"  },
	},
	['G' - 'A'] = {
		[0] = {	.meth = HTTP_METH_GET     , .len=3, .text="GET"     },
	},
	['H' - 'A'] = {
		[0] = {	.meth = HTTP_METH_HEAD    , .len=4, .text="HEAD"    },
	},
	['O' - 'A'] = {
		[0] = {	.meth = HTTP_METH_OPTIONS , .len=7, .text="OPTIONS" },
	},
	['P' - 'A'] = {
		[0] = {	.meth = HTTP_METH_POST    , .len=4, .text="POST"    },
		[1] = {	.meth = HTTP_METH_PUT     , .len=3, .text="PUT"     },
	},
	['T' - 'A'] = {
		[0] = {	.meth = HTTP_METH_TRACE   , .len=5, .text="TRACE"   },
	},
	/* rest is empty like this :
	 *      [0] = {	.meth = HTTP_METH_OTHER   , .len=0, .text=""        },
	 */
};

const struct http_method_name http_known_methods[HTTP_METH_OTHER] = {
	[HTTP_METH_OPTIONS] = { "OPTIONS",  7 },
	[HTTP_METH_GET]     = { "GET",      3 },
	[HTTP_METH_HEAD]    = { "HEAD",     4 },
	[HTTP_METH_POST]    = { "POST",     4 },
	[HTTP_METH_PUT]     = { "PUT",      3 },
	[HTTP_METH_DELETE]  = { "DELETE",   6 },
	[HTTP_METH_TRACE]   = { "TRACE",    5 },
	[HTTP_METH_CONNECT] = { "CONNECT",  7 },
};

/*
 * Adds a header and its CRLF at the tail of the message's buffer, just before
 * the last CRLF. Text length is measured first, so it cannot be NULL.
 * The header is also automatically added to the index <hdr_idx>, and the end
 * of headers is automatically adjusted. The number of bytes added is returned
 * on success, otherwise <0 is returned indicating an error.
 */
int http_header_add_tail(struct http_msg *msg, struct hdr_idx *hdr_idx, const char *text)
{
	int bytes, len;

	len = strlen(text);
	bytes = buffer_insert_line2(msg->chn->buf, msg->chn->buf->p + msg->eoh, text, len);
	if (!bytes)
		return -1;
	http_msg_move_end(msg, bytes);
	return hdr_idx_add(len, 1, hdr_idx, hdr_idx->tail);
}

/*
 * Adds a header and its CRLF at the tail of the message's buffer, just before
 * the last CRLF. <len> bytes are copied, not counting the CRLF. If <text> is NULL, then
 * the buffer is only opened and the space reserved, but nothing is copied.
 * The header is also automatically added to the index <hdr_idx>, and the end
 * of headers is automatically adjusted. The number of bytes added is returned
 * on success, otherwise <0 is returned indicating an error.
 */
int http_header_add_tail2(struct http_msg *msg,
                          struct hdr_idx *hdr_idx, const char *text, int len)
{
	int bytes;

	bytes = buffer_insert_line2(msg->chn->buf, msg->chn->buf->p + msg->eoh, text, len);
	if (!bytes)
		return -1;
	http_msg_move_end(msg, bytes);
	return hdr_idx_add(len, 1, hdr_idx, hdr_idx->tail);
}

/*
 * Checks if <hdr> is exactly <name> for <len> chars, and ends with a colon.
 * If so, returns the position of the first non-space character relative to
 * <hdr>, or <end>-<hdr> if not found before. If no value is found, it tries
 * to return a pointer to the place after the first space. Returns 0 if the
 * header name does not match. Checks are case-insensitive.
 */
int http_header_match2(const char *hdr, const char *end,
		       const char *name, int len)
{
	const char *val;

	if (hdr + len >= end)
		return 0;
	if (hdr[len] != ':')
		return 0;
	if (strncasecmp(hdr, name, len) != 0)
		return 0;
	val = hdr + len + 1;
	while (val < end && HTTP_IS_SPHT(*val))
		val++;
	if ((val >= end) && (len + 2 <= end - hdr))
		return len + 2; /* we may replace starting from second space */
	return val - hdr;
}

/* Find the first or next occurrence of header <name> in message buffer <sol>
 * using headers index <idx>, and return it in the <ctx> structure. This
 * structure holds everything necessary to use the header and find next
 * occurrence. If its <idx> member is 0, the header is searched from the
 * beginning. Otherwise, the next occurrence is returned. The function returns
 * 1 when it finds a value, and 0 when there is no more. It is very similar to
 * http_find_header2() except that it is designed to work with full-line headers
 * whose comma is not a delimiter but is part of the syntax. As a special case,
 * if ctx->val is NULL when searching for a new values of a header, the current
 * header is rescanned. This allows rescanning after a header deletion.
 */
int http_find_full_header2(const char *name, int len,
                           char *sol, struct hdr_idx *idx,
                           struct hdr_ctx *ctx)
{
	char *eol, *sov;
	int cur_idx, old_idx;

	cur_idx = ctx->idx;
	if (cur_idx) {
		/* We have previously returned a header, let's search another one */
		sol = ctx->line;
		eol = sol + idx->v[cur_idx].len;
		goto next_hdr;
	}

	/* first request for this header */
	sol += hdr_idx_first_pos(idx);
	old_idx = 0;
	cur_idx = hdr_idx_first_idx(idx);
	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		if (len == 0) {
			/* No argument was passed, we want any header.
			 * To achieve this, we simply build a fake request. */
			while (sol + len < eol && sol[len] != ':')
				len++;
			name = sol;
		}

		if ((len < eol - sol) &&
		    (sol[len] == ':') &&
		    (strncasecmp(sol, name, len) == 0)) {
			ctx->del = len;
			sov = sol + len + 1;
			while (sov < eol && HTTP_IS_LWS(*sov))
				sov++;

			ctx->line = sol;
			ctx->prev = old_idx;
			ctx->idx  = cur_idx;
			ctx->val  = sov - sol;
			ctx->tws = 0;
			while (eol > sov && HTTP_IS_LWS(*(eol - 1))) {
				eol--;
				ctx->tws++;
			}
			ctx->vlen = eol - sov;
			return 1;
		}
	next_hdr:
		sol = eol + idx->v[cur_idx].cr + 1;
		old_idx = cur_idx;
		cur_idx = idx->v[cur_idx].next;
	}
	return 0;
}

/* Find the first or next header field in message buffer <sol> using headers
 * index <idx>, and return it in the <ctx> structure. This structure holds
 * everything necessary to use the header and find next occurrence. If its
 * <idx> member is 0, the first header is retrieved. Otherwise, the next
 * occurrence is returned. The function returns 1 when it finds a value, and
 * 0 when there is no more. It is equivalent to http_find_full_header2() with
 * no header name.
 */
int http_find_next_header(char *sol, struct hdr_idx *idx, struct hdr_ctx *ctx)
{
	char *eol, *sov;
	int cur_idx, old_idx;
	int len;

	cur_idx = ctx->idx;
	if (cur_idx) {
		/* We have previously returned a header, let's search another one */
		sol = ctx->line;
		eol = sol + idx->v[cur_idx].len;
		goto next_hdr;
	}

	/* first request for this header */
	sol += hdr_idx_first_pos(idx);
	old_idx = 0;
	cur_idx = hdr_idx_first_idx(idx);
	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		len = 0;
		while (1) {
			if (len >= eol - sol)
				goto next_hdr;
			if (sol[len] == ':')
				break;
			len++;
		}

		ctx->del = len;
		sov = sol + len + 1;
		while (sov < eol && HTTP_IS_LWS(*sov))
			sov++;

		ctx->line = sol;
		ctx->prev = old_idx;
		ctx->idx  = cur_idx;
		ctx->val  = sov - sol;
		ctx->tws = 0;

		while (eol > sov && HTTP_IS_LWS(*(eol - 1))) {
			eol--;
			ctx->tws++;
		}
		ctx->vlen = eol - sov;
		return 1;

	next_hdr:
		sol = eol + idx->v[cur_idx].cr + 1;
		old_idx = cur_idx;
		cur_idx = idx->v[cur_idx].next;
	}
	return 0;
}

/* Find the end of the header value contained between <s> and <e>. See RFC7230,
 * par 3.2 for more information. Note that it requires a valid header to return
 * a valid result. This works for headers defined as comma-separated lists.
 */
char *find_hdr_value_end(char *s, const char *e)
{
	int quoted, qdpair;

	quoted = qdpair = 0;

#if defined(__x86_64__) ||						\
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
	/* speedup: skip everything not a comma nor a double quote */
	for (; s <= e - sizeof(int); s += sizeof(int)) {
		unsigned int c = *(int *)s; // comma
		unsigned int q = c;         // quote

		c ^= 0x2c2c2c2c; // contains one zero on a comma
		q ^= 0x22222222; // contains one zero on a quote

		c = (c - 0x01010101) & ~c; // contains 0x80 below a comma
		q = (q - 0x01010101) & ~q; // contains 0x80 below a quote

		if ((c | q) & 0x80808080)
			break; // found a comma or a quote
	}
#endif
	for (; s < e; s++) {
		if (qdpair)                    qdpair = 0;
		else if (quoted) {
			if (*s == '\\')        qdpair = 1;
			else if (*s == '"')    quoted = 0;
		}
		else if (*s == '"')            quoted = 1;
		else if (*s == ',')            return s;
	}
	return s;
}

/* Find the first or next occurrence of header <name> in message buffer <sol>
 * using headers index <idx>, and return it in the <ctx> structure. This
 * structure holds everything necessary to use the header and find next
 * occurrence. If its <idx> member is 0, the header is searched from the
 * beginning. Otherwise, the next occurrence is returned. The function returns
 * 1 when it finds a value, and 0 when there is no more. It is designed to work
 * with headers defined as comma-separated lists. As a special case, if ctx->val
 * is NULL when searching for a new values of a header, the current header is
 * rescanned. This allows rescanning after a header deletion.
 */
int http_find_header2(const char *name, int len,
		      char *sol, struct hdr_idx *idx,
		      struct hdr_ctx *ctx)
{
	char *eol, *sov;
	int cur_idx, old_idx;

	cur_idx = ctx->idx;
	if (cur_idx) {
		/* We have previously returned a value, let's search
		 * another one on the same line.
		 */
		sol = ctx->line;
		ctx->del = ctx->val + ctx->vlen + ctx->tws;
		sov = sol + ctx->del;
		eol = sol + idx->v[cur_idx].len;

		if (sov >= eol)
			/* no more values in this header */
			goto next_hdr;

		/* values remaining for this header, skip the comma but save it
		 * for later use (eg: for header deletion).
		 */
		sov++;
		while (sov < eol && HTTP_IS_LWS((*sov)))
			sov++;

		goto return_hdr;
	}

	/* first request for this header */
	sol += hdr_idx_first_pos(idx);
	old_idx = 0;
	cur_idx = hdr_idx_first_idx(idx);
	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		if (len == 0) {
			/* No argument was passed, we want any header.
			 * To achieve this, we simply build a fake request. */
			while (sol + len < eol && sol[len] != ':')
				len++;
			name = sol;
		}

		if ((len < eol - sol) &&
		    (sol[len] == ':') &&
		    (strncasecmp(sol, name, len) == 0)) {
			ctx->del = len;
			sov = sol + len + 1;
			while (sov < eol && HTTP_IS_LWS(*sov))
				sov++;

			ctx->line = sol;
			ctx->prev = old_idx;
		return_hdr:
			ctx->idx  = cur_idx;
			ctx->val  = sov - sol;

			eol = find_hdr_value_end(sov, eol);
			ctx->tws = 0;
			while (eol > sov && HTTP_IS_LWS(*(eol - 1))) {
				eol--;
				ctx->tws++;
			}
			ctx->vlen = eol - sov;
			return 1;
		}
	next_hdr:
		sol = eol + idx->v[cur_idx].cr + 1;
		old_idx = cur_idx;
		cur_idx = idx->v[cur_idx].next;
	}
	return 0;
}

int http_find_header(const char *name,
		     char *sol, struct hdr_idx *idx,
		     struct hdr_ctx *ctx)
{
	return http_find_header2(name, strlen(name), sol, idx, ctx);
}

/* Remove one value of a header. This only works on a <ctx> returned by one of
 * the http_find_header functions. The value is removed, as well as surrounding
 * commas if any. If the removed value was alone, the whole header is removed.
 * The ctx is always updated accordingly, as well as the buffer and HTTP
 * message <msg>. The new index is returned. If it is zero, it means there is
 * no more header, so any processing may stop. The ctx is always left in a form
 * that can be handled by http_find_header2() to find next occurrence.
 */
int http_remove_header2(struct http_msg *msg, struct hdr_idx *idx, struct hdr_ctx *ctx)
{
	int cur_idx = ctx->idx;
	char *sol = ctx->line;
	struct hdr_idx_elem *hdr;
	int delta, skip_comma;

	if (!cur_idx)
		return 0;

	hdr = &idx->v[cur_idx];
	if (sol[ctx->del] == ':' && ctx->val + ctx->vlen + ctx->tws == hdr->len) {
		/* This was the only value of the header, we must now remove it entirely. */
		delta = buffer_replace2(msg->chn->buf, sol, sol + hdr->len + hdr->cr + 1, NULL, 0);
		http_msg_move_end(msg, delta);
		idx->used--;
		hdr->len = 0;   /* unused entry */
		idx->v[ctx->prev].next = idx->v[ctx->idx].next;
		if (idx->tail == ctx->idx)
			idx->tail = ctx->prev;
		ctx->idx = ctx->prev;    /* walk back to the end of previous header */
		ctx->line -= idx->v[ctx->idx].len + idx->v[ctx->idx].cr + 1;
		ctx->val = idx->v[ctx->idx].len; /* point to end of previous header */
		ctx->tws = ctx->vlen = 0;
		return ctx->idx;
	}

	/* This was not the only value of this header. We have to remove between
	 * ctx->del+1 and ctx->val+ctx->vlen+ctx->tws+1 included. If it is the
	 * last entry of the list, we remove the last separator.
	 */

	skip_comma = (ctx->val + ctx->vlen + ctx->tws == hdr->len) ? 0 : 1;
	delta = buffer_replace2(msg->chn->buf, sol + ctx->del + skip_comma,
				sol + ctx->val + ctx->vlen + ctx->tws + skip_comma,
				NULL, 0);
	hdr->len += delta;
	http_msg_move_end(msg, delta);
	ctx->val = ctx->del;
	ctx->tws = ctx->vlen = 0;
	return ctx->idx;
}

/* This function handles a server error at the stream interface level. The
 * stream interface is assumed to be already in a closed state. An optional
 * message is copied into the input buffer.
 * The error flags are set to the values in arguments. Any pending request
 * in this buffer will be lost.
 */
static void http_server_error(struct stream *s, struct stream_interface *si,
			      int err, int finst, const struct chunk *msg)
{
	FLT_STRM_CB(s, flt_http_reply(s, s->txn->status, msg));
	channel_auto_read(si_oc(si));
	channel_abort(si_oc(si));
	channel_auto_close(si_oc(si));
	channel_erase(si_oc(si));
	channel_auto_close(si_ic(si));
	channel_auto_read(si_ic(si));
	if (msg)
		co_inject(si_ic(si), msg->str, msg->len);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= finst;
}

/* This function returns the appropriate error location for the given stream
 * and message.
 */

struct chunk *http_error_message(struct stream *s)
{
	const int msgnum = http_get_status_idx(s->txn->status);

	if (s->be->errmsg[msgnum].str)
		return &s->be->errmsg[msgnum];
	else if (strm_fe(s)->errmsg[msgnum].str)
		return &strm_fe(s)->errmsg[msgnum];
	else
		return &http_err_chunks[msgnum];
}

void
http_reply_and_close(struct stream *s, short status, struct chunk *msg)
{
	s->txn->flags &= ~TX_WAIT_NEXT_RQ;
	FLT_STRM_CB(s, flt_http_reply(s, status, msg));
	stream_int_retnclose(&s->si[0], msg);
}

/*
 * returns a known method among HTTP_METH_* or HTTP_METH_OTHER for all unknown
 * ones.
 */
enum http_meth_t find_http_meth(const char *str, const int len)
{
	unsigned char m;
	const struct http_method_desc *h;

	m = ((unsigned)*str - 'A');

	if (m < 26) {
		for (h = http_methods[m]; h->len > 0; h++) {
			if (unlikely(h->len != len))
				continue;
			if (likely(memcmp(str, h->text, h->len) == 0))
				return h->meth;
		};
	}
	return HTTP_METH_OTHER;
}

/* Parse the URI from the given transaction (which is assumed to be in request
 * phase) and look for the "/" beginning the PATH. If not found, return NULL.
 * It is returned otherwise.
 */
char *http_get_path(struct http_txn *txn)
{
	char *ptr, *end;

	ptr = txn->req.chn->buf->p + txn->req.sl.rq.u;
	end = ptr + txn->req.sl.rq.u_l;

	if (ptr >= end)
		return NULL;

	/* RFC7230, par. 2.7 :
	 * Request-URI = "*" | absuri | abspath | authority
	 */

	if (*ptr == '*')
		return NULL;

	if (isalpha((unsigned char)*ptr)) {
		/* this is a scheme as described by RFC3986, par. 3.1 */
		ptr++;
		while (ptr < end &&
		       (isalnum((unsigned char)*ptr) || *ptr == '+' || *ptr == '-' || *ptr == '.'))
			ptr++;
		/* skip '://' */
		if (ptr == end || *ptr++ != ':')
			return NULL;
		if (ptr == end || *ptr++ != '/')
			return NULL;
		if (ptr == end || *ptr++ != '/')
			return NULL;
	}
	/* skip [user[:passwd]@]host[:[port]] */

	while (ptr < end && *ptr != '/')
		ptr++;

	if (ptr == end)
		return NULL;

	/* OK, we got the '/' ! */
	return ptr;
}

/* Parse the URI from the given string and look for the "/" beginning the PATH.
 * If not found, return NULL. It is returned otherwise.
 */
static char *
http_get_path_from_string(char *str)
{
	char *ptr = str;

	/* RFC2616, par. 5.1.2 :
	 * Request-URI = "*" | absuri | abspath | authority
	 */

	if (*ptr == '*')
		return NULL;

	if (isalpha((unsigned char)*ptr)) {
		/* this is a scheme as described by RFC3986, par. 3.1 */
		ptr++;
		while (isalnum((unsigned char)*ptr) || *ptr == '+' || *ptr == '-' || *ptr == '.')
			ptr++;
		/* skip '://' */
		if (*ptr == '\0' || *ptr++ != ':')
			return NULL;
		if (*ptr == '\0' || *ptr++ != '/')
			return NULL;
		if (*ptr == '\0' || *ptr++ != '/')
			return NULL;
	}
	/* skip [user[:passwd]@]host[:[port]] */

	while (*ptr != '\0' && *ptr != ' ' && *ptr != '/')
		ptr++;

	if (*ptr == '\0' || *ptr == ' ')
		return NULL;

	/* OK, we got the '/' ! */
	return ptr;
}

/* Returns a 302 for a redirectable request that reaches a server working in
 * in redirect mode. This may only be called just after the stream interface
 * has moved to SI_ST_ASS. Unprocessable requests are left unchanged and will
 * follow normal proxy processing. NOTE: this function is designed to support
 * being called once data are scheduled for forwarding.
 */
void http_perform_server_redirect(struct stream *s, struct stream_interface *si)
{
	struct http_txn *txn;
	struct server *srv;
	char *path;
	int len, rewind;

	/* 1: create the response header */
	trash.len = strlen(HTTP_302);
	memcpy(trash.str, HTTP_302, trash.len);

	srv = objt_server(s->target);

	/* 2: add the server's prefix */
	if (trash.len + srv->rdr_len > trash.size)
		return;

	/* special prefix "/" means don't change URL */
	if (srv->rdr_len != 1 || *srv->rdr_pfx != '/') {
		memcpy(trash.str + trash.len, srv->rdr_pfx, srv->rdr_len);
		trash.len += srv->rdr_len;
	}

	/* 3: add the request URI. Since it was already forwarded, we need
	 * to temporarily rewind the buffer.
	 */
	txn = s->txn;
	b_rew(s->req.buf, rewind = http_hdr_rewind(&txn->req));

	path = http_get_path(txn);
	len = buffer_count(s->req.buf, path, b_ptr(s->req.buf, txn->req.sl.rq.u + txn->req.sl.rq.u_l));

	b_adv(s->req.buf, rewind);

	if (!path)
		return;

	if (trash.len + len > trash.size - 4) /* 4 for CRLF-CRLF */
		return;

	memcpy(trash.str + trash.len, path, len);
	trash.len += len;

	if (unlikely(txn->flags & TX_USE_PX_CONN)) {
		memcpy(trash.str + trash.len, "\r\nProxy-Connection: close\r\n\r\n", 29);
		trash.len += 29;
	} else {
		memcpy(trash.str + trash.len, "\r\nConnection: close\r\n\r\n", 23);
		trash.len += 23;
	}

	/* prepare to return without error. */
	si_shutr(si);
	si_shutw(si);
	si->err_type = SI_ET_NONE;
	si->state    = SI_ST_CLO;

	/* send the message */
	txn->status = 302;
	http_server_error(s, si, SF_ERR_LOCAL, SF_FINST_C, &trash);

	/* FIXME: we should increase a counter of redirects per server and per backend. */
	srv_inc_sess_ctr(srv);
	srv_set_sess_last(srv);
}

/* Return the error message corresponding to si->err_type. It is assumed
 * that the server side is closed. Note that err_type is actually a
 * bitmask, where almost only aborts may be cumulated with other
 * values. We consider that aborted operations are more important
 * than timeouts or errors due to the fact that nobody else in the
 * logs might explain incomplete retries. All others should avoid
 * being cumulated. It should normally not be possible to have multiple
 * aborts at once, but just in case, the first one in sequence is reported.
 * Note that connection errors appearing on the second request of a keep-alive
 * connection are not reported since this allows the client to retry.
 */
void http_return_srv_error(struct stream *s, struct stream_interface *si)
{
	int err_type = si->err_type;

	/* set s->txn->status for http_error_message(s) */
	s->txn->status = 503;

	if (err_type & SI_ET_QUEUE_ABRT)
		http_server_error(s, si, SF_ERR_CLICL, SF_FINST_Q,
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_ABRT)
		http_server_error(s, si, SF_ERR_CLICL, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
	else if (err_type & SI_ET_QUEUE_TO)
		http_server_error(s, si, SF_ERR_SRVTO, SF_FINST_Q,
				  http_error_message(s));
	else if (err_type & SI_ET_QUEUE_ERR)
		http_server_error(s, si, SF_ERR_SRVCL, SF_FINST_Q,
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_TO)
		http_server_error(s, si, SF_ERR_SRVTO, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_ERR)
		http_server_error(s, si, SF_ERR_SRVCL, SF_FINST_C,
				  (s->flags & SF_SRV_REUSED) ? NULL :
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_RES)
		http_server_error(s, si, SF_ERR_RESOURCE, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
	else { /* SI_ET_CONN_OTHER and others */
		s->txn->status = 500;
		http_server_error(s, si, SF_ERR_INTERNAL, SF_FINST_C,
				  http_error_message(s));
	}
}

extern const char sess_term_cond[8];
extern const char sess_fin_state[8];
extern const char *monthname[12];
struct pool_head *pool_head_http_txn;
struct pool_head *pool_head_requri;
struct pool_head *pool_head_capture = NULL;
struct pool_head *pool_head_uniqueid;

/*
 * Capture headers from message starting at <som> according to header list
 * <cap_hdr>, and fill the <cap> pointers appropriately.
 */
void capture_headers(char *som, struct hdr_idx *idx,
		     char **cap, struct cap_hdr *cap_hdr)
{
	char *eol, *sol, *col, *sov;
	int cur_idx;
	struct cap_hdr *h;
	int len;

	sol = som + hdr_idx_first_pos(idx);
	cur_idx = hdr_idx_first_idx(idx);

	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		col = sol;
		while (col < eol && *col != ':')
			col++;

		sov = col + 1;
		while (sov < eol && HTTP_IS_LWS(*sov))
			sov++;
				
		for (h = cap_hdr; h; h = h->next) {
			if (h->namelen && (h->namelen == col - sol) &&
			    (strncasecmp(sol, h->name, h->namelen) == 0)) {
				if (cap[h->index] == NULL)
					cap[h->index] =
						pool_alloc(h->pool);

				if (cap[h->index] == NULL) {
					ha_alert("HTTP capture : out of memory.\n");
					continue;
				}
							
				len = eol - sov;
				if (len > h->len)
					len = h->len;
							
				memcpy(cap[h->index], sov, len);
				cap[h->index][len]=0;
			}
		}
		sol = eol + idx->v[cur_idx].cr + 1;
		cur_idx = idx->v[cur_idx].next;
	}
}

/*
 * Returns the data from Authorization header. Function may be called more
 * than once so data is stored in txn->auth_data. When no header is found
 * or auth method is unknown auth_method is set to HTTP_AUTH_WRONG to avoid
 * searching again for something we are unable to find anyway. However, if
 * the result if valid, the cache is not reused because we would risk to
 * have the credentials overwritten by another stream in parallel.
 */

int
get_http_auth(struct stream *s)
{

	struct http_txn *txn = s->txn;
	struct chunk auth_method;
	struct hdr_ctx ctx;
	char *h, *p;
	int len;

#ifdef DEBUG_AUTH
	printf("Auth for stream %p: %d\n", s, txn->auth.method);
#endif

	if (txn->auth.method == HTTP_AUTH_WRONG)
		return 0;

	txn->auth.method = HTTP_AUTH_WRONG;

	ctx.idx = 0;

	if (txn->flags & TX_USE_PX_CONN) {
		h = "Proxy-Authorization";
		len = strlen(h);
	} else {
		h = "Authorization";
		len = strlen(h);
	}

	if (!http_find_header2(h, len, s->req.buf->p, &txn->hdr_idx, &ctx))
		return 0;

	h = ctx.line + ctx.val;

	p = memchr(h, ' ', ctx.vlen);
	len = p - h;
	if (!p || len <= 0)
		return 0;

	if (chunk_initlen(&auth_method, h, 0, len) != 1)
		return 0;

	chunk_initlen(&txn->auth.method_data, p + 1, 0, ctx.vlen - len - 1);

	if (!strncasecmp("Basic", auth_method.str, auth_method.len)) {
		struct chunk *http_auth = get_trash_chunk();

		len = base64dec(txn->auth.method_data.str, txn->auth.method_data.len,
				http_auth->str, global.tune.bufsize - 1);

		if (len < 0)
			return 0;


		http_auth->str[len] = '\0';

		p = strchr(http_auth->str, ':');

		if (!p)
			return 0;

		txn->auth.user = http_auth->str;
		*p = '\0';
		txn->auth.pass = p+1;

		txn->auth.method = HTTP_AUTH_BASIC;
		return 1;
	}

	return 0;
}


/* convert an HTTP/0.9 request into an HTTP/1.0 request. Returns 1 if the
 * conversion succeeded, 0 in case of error. If the request was already 1.X,
 * nothing is done and 1 is returned.
 */
static int http_upgrade_v09_to_v10(struct http_txn *txn)
{
	int delta;
	char *cur_end;
	struct http_msg *msg = &txn->req;

	if (msg->sl.rq.v_l != 0)
		return 1;

	/* RFC 1945 allows only GET for HTTP/0.9 requests */
	if (txn->meth != HTTP_METH_GET)
		return 0;

	cur_end = msg->chn->buf->p + msg->sl.rq.l;

	if (msg->sl.rq.u_l == 0) {
		/* HTTP/0.9 requests *must* have a request URI, per RFC 1945 */
		return 0;
	}
	/* add HTTP version */
	delta = buffer_replace2(msg->chn->buf, cur_end, cur_end, " HTTP/1.0\r\n", 11);
	http_msg_move_end(msg, delta);
	cur_end += delta;
	cur_end = (char *)http_parse_reqline(msg,
					     HTTP_MSG_RQMETH,
					     msg->chn->buf->p, cur_end + 1,
					     NULL, NULL);
	if (unlikely(!cur_end))
		return 0;

	/* we have a full HTTP/1.0 request now and we know that
	 * we have either a CR or an LF at <ptr>.
	 */
	hdr_idx_set_start(&txn->hdr_idx, msg->sl.rq.l, *cur_end == '\r');
	return 1;
}

/* Parse the Connection: header of an HTTP request, looking for both "close"
 * and "keep-alive" values. If we already know that some headers may safely
 * be removed, we remove them now. The <to_del> flags are used for that :
 *  - bit 0 means remove "close" headers (in HTTP/1.0 requests/responses)
 *  - bit 1 means remove "keep-alive" headers (in HTTP/1.1 reqs/resp to 1.1).
 * Presence of the "Upgrade" token is also checked and reported.
 * The TX_HDR_CONN_* flags are adjusted in txn->flags depending on what was
 * found, and TX_CON_*_SET is adjusted depending on what is left so only
 * harmless combinations may be removed. Do not call that after changes have
 * been processed.
 */
void http_parse_connection_header(struct http_txn *txn, struct http_msg *msg, int to_del)
{
	struct hdr_ctx ctx;
	const char *hdr_val = "Connection";
	int hdr_len = 10;

	if (txn->flags & TX_HDR_CONN_PRS)
		return;

	if (unlikely(txn->flags & TX_USE_PX_CONN)) {
		hdr_val = "Proxy-Connection";
		hdr_len = 16;
	}

	ctx.idx = 0;
	txn->flags &= ~(TX_CON_KAL_SET|TX_CON_CLO_SET);
	while (http_find_header2(hdr_val, hdr_len, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
		if (ctx.vlen >= 10 && word_match(ctx.line + ctx.val, ctx.vlen, "keep-alive", 10)) {
			txn->flags |= TX_HDR_CONN_KAL;
			if (to_del & 2)
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
			else
				txn->flags |= TX_CON_KAL_SET;
		}
		else if (ctx.vlen >= 5 && word_match(ctx.line + ctx.val, ctx.vlen, "close", 5)) {
			txn->flags |= TX_HDR_CONN_CLO;
			if (to_del & 1)
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
			else
				txn->flags |= TX_CON_CLO_SET;
		}
		else if (ctx.vlen >= 7 && word_match(ctx.line + ctx.val, ctx.vlen, "upgrade", 7)) {
			txn->flags |= TX_HDR_CONN_UPG;
		}
	}

	txn->flags |= TX_HDR_CONN_PRS;
	return;
}

/* Apply desired changes on the Connection: header. Values may be removed and/or
 * added depending on the <wanted> flags, which are exclusively composed of
 * TX_CON_CLO_SET and TX_CON_KAL_SET, depending on what flags are desired. The
 * TX_CON_*_SET flags are adjusted in txn->flags depending on what is left.
 */
void http_change_connection_header(struct http_txn *txn, struct http_msg *msg, int wanted)
{
	struct hdr_ctx ctx;
	const char *hdr_val = "Connection";
	int hdr_len = 10;

	ctx.idx = 0;


	if (unlikely(txn->flags & TX_USE_PX_CONN)) {
		hdr_val = "Proxy-Connection";
		hdr_len = 16;
	}

	txn->flags &= ~(TX_CON_CLO_SET | TX_CON_KAL_SET);
	while (http_find_header2(hdr_val, hdr_len, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
		if (ctx.vlen >= 10 && word_match(ctx.line + ctx.val, ctx.vlen, "keep-alive", 10)) {
			if (wanted & TX_CON_KAL_SET)
				txn->flags |= TX_CON_KAL_SET;
			else
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
		}
		else if (ctx.vlen >= 5 && word_match(ctx.line + ctx.val, ctx.vlen, "close", 5)) {
			if (wanted & TX_CON_CLO_SET)
				txn->flags |= TX_CON_CLO_SET;
			else
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
		}
	}

	if (wanted == (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
		return;

	if ((wanted & TX_CON_CLO_SET) && !(txn->flags & TX_CON_CLO_SET)) {
		txn->flags |= TX_CON_CLO_SET;
		hdr_val = "Connection: close";
		hdr_len  = 17;
		if (unlikely(txn->flags & TX_USE_PX_CONN)) {
			hdr_val = "Proxy-Connection: close";
			hdr_len = 23;
		}
		http_header_add_tail2(msg, &txn->hdr_idx, hdr_val, hdr_len);
	}

	if ((wanted & TX_CON_KAL_SET) && !(txn->flags & TX_CON_KAL_SET)) {
		txn->flags |= TX_CON_KAL_SET;
		hdr_val = "Connection: keep-alive";
		hdr_len = 22;
		if (unlikely(txn->flags & TX_USE_PX_CONN)) {
			hdr_val = "Proxy-Connection: keep-alive";
			hdr_len = 28;
		}
		http_header_add_tail2(msg, &txn->hdr_idx, hdr_val, hdr_len);
	}
	return;
}

/* Parses a qvalue and returns it multipled by 1000, from 0 to 1000. If the
 * value is larger than 1000, it is bound to 1000. The parser consumes up to
 * 1 digit, one dot and 3 digits and stops on the first invalid character.
 * Unparsable qvalues return 1000 as "q=1.000".
 */
int parse_qvalue(const char *qvalue, const char **end)
{
	int q = 1000;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q = (*qvalue++ - '0') * 1000;

	if (*qvalue++ != '.')
		goto out;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q += (*qvalue++ - '0') * 100;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q += (*qvalue++ - '0') * 10;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q += (*qvalue++ - '0') * 1;
 out:
	if (q > 1000)
		q = 1000;
	if (end)
		*end = qvalue;
	return q;
}

void http_adjust_conn_mode(struct stream *s, struct http_txn *txn, struct http_msg *msg)
{
	struct proxy *fe = strm_fe(s);
	int tmp = TX_CON_WANT_KAL;

	if (!((fe->options2|s->be->options2) & PR_O2_FAKE_KA)) {
		if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN ||
		    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
			tmp = TX_CON_WANT_TUN;

		if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL ||
		    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL)
			tmp = TX_CON_WANT_TUN;
	}

	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL) {
		/* option httpclose + server_close => forceclose */
		if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL ||
		    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL)
			tmp = TX_CON_WANT_CLO;
		else
			tmp = TX_CON_WANT_SCL;
	}

	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_FCL ||
	    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_FCL)
		tmp = TX_CON_WANT_CLO;

	if ((txn->flags & TX_CON_WANT_MSK) < tmp)
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | tmp;

	if (!(txn->flags & TX_HDR_CONN_PRS) &&
	    (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		/* parse the Connection header and possibly clean it */
		int to_del = 0;
		if ((msg->flags & HTTP_MSGF_VER_11) ||
		    ((txn->flags & TX_CON_WANT_MSK) >= TX_CON_WANT_SCL &&
		     !((fe->options2|s->be->options2) & PR_O2_FAKE_KA)))
			to_del |= 2; /* remove "keep-alive" */
		if (!(msg->flags & HTTP_MSGF_VER_11))
			to_del |= 1; /* remove "close" */
		http_parse_connection_header(txn, msg, to_del);
	}

	/* check if client or config asks for explicit close in KAL/SCL */
	if (((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	     (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) &&
	    ((txn->flags & TX_HDR_CONN_CLO) ||                         /* "connection: close" */
	     (!(msg->flags & HTTP_MSGF_VER_11) && !(txn->flags & TX_HDR_CONN_KAL)) || /* no "connection: k-a" in 1.0 */
	     !(msg->flags & HTTP_MSGF_XFER_LEN) ||                     /* no length known => close */
	     fe->state == PR_STSTOPPED))                            /* frontend is stopping */
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_CLO;
}

/* This stream analyser waits for a complete HTTP request. It returns 1 if the
 * processing can continue on next analysers, or zero if it either needs more
 * data or wants to immediately abort the request (eg: timeout, error, ...). It
 * is tied to AN_REQ_WAIT_HTTP and may may remove itself from s->req.analysers
 * when it has nothing left to do, and may remove any analyser when it wants to
 * abort.
 */
int http_wait_for_request(struct stream *s, struct channel *req, int an_bit)
{
	/*
	 * We will parse the partial (or complete) lines.
	 * We will check the request syntax, and also join multi-line
	 * headers. An index of all the lines will be elaborated while
	 * parsing.
	 *
	 * For the parsing, we use a 28 states FSM.
	 *
	 * Here is the information we currently have :
	 *   req->buf->p             = beginning of request
	 *   req->buf->p + msg->eoh  = end of processed headers / start of current one
	 *   req->buf->p + req->buf->i    = end of input data
	 *   msg->eol           = end of current header or line (LF or CRLF)
	 *   msg->next          = first non-visited byte
	 *
	 * At end of parsing, we may perform a capture of the error (if any), and
	 * we will set a few fields (txn->meth, sn->flags/SF_REDIRECTABLE).
	 * We also check for monitor-uri, logging, HTTP/0.9 to 1.0 conversion, and
	 * finally headers capture.
	 */

	int cur_idx;
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct hdr_ctx ctx;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	/* we're speaking HTTP here, so let's speak HTTP to the client */
	s->srv_error = http_return_srv_error;

	/* There's a protected area at the end of the buffer for rewriting
	 * purposes. We don't want to start to parse the request if the
	 * protected area is affected, because we may have to move processed
	 * data later, which is much more complicated.
	 */
	if (buffer_not_empty(req->buf) && msg->msg_state < HTTP_MSG_ERROR) {

		/* This point is executed when some data is avalaible for analysis,
		 * so we log the end of the idle time. */
		if (s->logs.t_idle == -1)
			s->logs.t_idle = tv_ms_elapsed(&s->logs.tv_accept, &now) - s->logs.t_handshake;

		if (txn->flags & TX_NOT_FIRST) {
			if (unlikely(!channel_is_rewritable(req))) {
				if (req->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_WRITE_ERROR|CF_WRITE_TIMEOUT))
					goto failed_keep_alive;
				/* some data has still not left the buffer, wake us once that's done */
				channel_dont_connect(req);
				req->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
				req->flags |= CF_WAKE_WRITE;
				return 0;
			}
			if (unlikely(bi_end(req->buf) < b_ptr(req->buf, msg->next) ||
			             bi_end(req->buf) > req->buf->data + req->buf->size - global.tune.maxrewrite))
				buffer_slow_realign(req->buf);
		}

		if (likely(msg->next < req->buf->i)) /* some unparsed data are available */
			http_msg_analyzer(msg, &txn->hdr_idx);
	}

	/* 1: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
		     msg->msg_state >= HTTP_MSG_BODY)) {
		char *eol, *sol;

		sol = req->buf->p;
		/* this is a bit complex : in case of error on the request line,
		 * we know that rq.l is still zero, so we display only the part
		 * up to the end of the line (truncated by debug_hdr).
		 */
		eol = sol + (msg->sl.rq.l ? msg->sl.rq.l : req->buf->i);
		debug_hdr("clireq", s, sol, eol);

		sol += hdr_idx_first_pos(&txn->hdr_idx);
		cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

		while (cur_idx) {
			eol = sol + txn->hdr_idx.v[cur_idx].len;
			debug_hdr("clihdr", s, sol, eol);
			sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
			cur_idx = txn->hdr_idx.v[cur_idx].next;
		}
	}


	/*
	 * Now we quickly check if we have found a full valid request.
	 * If not so, we check the FD and buffer states before leaving.
	 * A full request is indicated by the fact that we have seen
	 * the double LF/CRLF, so the state is >= HTTP_MSG_BODY. Invalid
	 * requests are checked first. When waiting for a second request
	 * on a keep-alive stream, if we encounter and error, close, t/o,
	 * we note the error in the stream flags but don't set any state.
	 * Since the error will be noted there, it will not be counted by
	 * process_stream() as a frontend error.
	 * Last, we may increase some tracked counters' http request errors on
	 * the cases that are deliberately the client's fault. For instance,
	 * a timeout or connection reset is not counted as an error. However
	 * a bad request is.
	 */

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/*
		 * First, let's catch bad requests.
		 */
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			stream_inc_http_req_ctr(s);
			stream_inc_http_err_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			goto return_bad_req;
		}

		/* 1: Since we are in header mode, if there's no space
		 *    left for headers, we won't be able to free more
		 *    later, so the stream will never terminate. We
		 *    must terminate it now.
		 */
		if (unlikely(buffer_full(req->buf, global.tune.maxrewrite))) {
			/* FIXME: check if URI is set and return Status
			 * 414 Request URI too long instead.
			 */
			stream_inc_http_req_ctr(s);
			stream_inc_http_err_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			if (msg->err_pos < 0)
				msg->err_pos = req->buf->i;
			goto return_bad_req;
		}

		/* 2: have we encountered a read error ? */
		else if (req->flags & CF_READ_ERROR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			/* we cannot return any message on error */
			if (msg->err_pos >= 0) {
				http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, sess->fe);
				stream_inc_http_err_ctr(s);
			}

			txn->status = 400;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, NULL);
			req->analysers &= AN_REQ_FLT_END;
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 3: has the read timeout expired ? */
		else if (req->flags & CF_READ_TIMEOUT || tick_is_expired(req->analyse_exp, now_ms)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLITO;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			/* read timeout : give up with an error message. */
			if (msg->err_pos >= 0) {
				http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, sess->fe);
				stream_inc_http_err_ctr(s);
			}
			txn->status = 408;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;

			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 4: have we encountered a close ? */
		else if (req->flags & CF_SHUTR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			if (msg->err_pos >= 0)
				http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, sess->fe);
			txn->status = 400;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;
			stream_inc_http_err_ctr(s);
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		channel_dont_connect(req);
		req->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
#ifdef TCP_QUICKACK
		if (sess->listener->options & LI_O_NOQUICKACK && req->buf->i &&
		    objt_conn(sess->origin) && conn_ctrl_ready(__objt_conn(sess->origin))) {
			/* We need more data, we have to re-enable quick-ack in case we
			 * previously disabled it, otherwise we might cause the client
			 * to delay next data.
			 */
			setsockopt(__objt_conn(sess->origin)->handle.fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
		}
#endif

		if ((msg->msg_state != HTTP_MSG_RQBEFORE) && (txn->flags & TX_WAIT_NEXT_RQ)) {
			/* If the client starts to talk, let's fall back to
			 * request timeout processing.
			 */
			txn->flags &= ~TX_WAIT_NEXT_RQ;
			req->analyse_exp = TICK_ETERNITY;
		}

		/* just set the request timeout once at the beginning of the request */
		if (!tick_isset(req->analyse_exp)) {
			if ((msg->msg_state == HTTP_MSG_RQBEFORE) &&
			    (txn->flags & TX_WAIT_NEXT_RQ) &&
			    tick_isset(s->be->timeout.httpka))
				req->analyse_exp = tick_add(now_ms, s->be->timeout.httpka);
			else
				req->analyse_exp = tick_add_ifset(now_ms, s->be->timeout.httpreq);
		}

		/* we're not ready yet */
		return 0;

	failed_keep_alive:
		/* Here we process low-level errors for keep-alive requests. In
		 * short, if the request is not the first one and it experiences
		 * a timeout, read error or shutdown, we just silently close so
		 * that the client can try again.
		 */
		txn->status = 0;
		msg->msg_state = HTTP_MSG_RQBEFORE;
		req->analysers &= AN_REQ_FLT_END;
		s->logs.logwait = 0;
		s->logs.level = 0;
		s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
		http_reply_and_close(s, txn->status, NULL);
		return 0;
	}

	/* OK now we have a complete HTTP request with indexed headers. Let's
	 * complete the request parsing by setting a few fields we will need
	 * later. At this point, we have the last CRLF at req->buf->data + msg->eoh.
	 * If the request is in HTTP/0.9 form, the rule is still true, and eoh
	 * points to the CRLF of the request line. msg->next points to the first
	 * byte after the last LF. msg->sov points to the first byte of data.
	 * msg->eol cannot be trusted because it may have been left uninitialized
	 * (for instance in the absence of headers).
	 */

	stream_inc_http_req_ctr(s);
	proxy_inc_fe_req_ctr(sess->fe); /* one more valid request for this FE */

	if (txn->flags & TX_WAIT_NEXT_RQ) {
		/* kill the pending keep-alive timeout */
		txn->flags &= ~TX_WAIT_NEXT_RQ;
		req->analyse_exp = TICK_ETERNITY;
	}


	/* Maybe we found in invalid header name while we were configured not
	 * to block on that, so we have to capture it now.
	 */
	if (unlikely(msg->err_pos >= 0))
		http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, sess->fe);

	/*
	 * 1: identify the method
	 */
	txn->meth = find_http_meth(req->buf->p, msg->sl.rq.m_l);

	/* we can make use of server redirect on GET and HEAD */
	if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
		s->flags |= SF_REDIRECTABLE;
	else if (txn->meth == HTTP_METH_OTHER &&
		 msg->sl.rq.m_l == 3 && memcmp(req->buf->p, "PRI", 3) == 0) {
		/* PRI is reserved for the HTTP/2 preface */
		msg->err_pos = 0;
		goto return_bad_req;
	}

	/*
	 * 2: check if the URI matches the monitor_uri.
	 * We have to do this for every request which gets in, because
	 * the monitor-uri is defined by the frontend.
	 */
	if (unlikely((sess->fe->monitor_uri_len != 0) &&
		     (sess->fe->monitor_uri_len == msg->sl.rq.u_l) &&
		     !memcmp(req->buf->p + msg->sl.rq.u,
			     sess->fe->monitor_uri,
			     sess->fe->monitor_uri_len))) {
		/*
		 * We have found the monitor URI
		 */
		struct acl_cond *cond;

		s->flags |= SF_MONITOR;
		HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

		/* Check if we want to fail this monitor request or not */
		list_for_each_entry(cond, &sess->fe->mon_fail_cond, list) {
			int ret = acl_exec_cond(cond, sess->fe, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);

			ret = acl_pass(ret);
			if (cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				/* we fail this request, let's return 503 service unavail */
				txn->status = 503;
				http_reply_and_close(s, txn->status, http_error_message(s));
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_LOCAL; /* we don't want a real error here */
				goto return_prx_cond;
			}
		}

		/* nothing to fail, let's reply normaly */
		txn->status = 200;
		http_reply_and_close(s, txn->status, http_error_message(s));
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_LOCAL; /* we don't want a real error here */
		goto return_prx_cond;
	}

	/*
	 * 3: Maybe we have to copy the original REQURI for the logs ?
	 * Note: we cannot log anymore if the request has been
	 * classified as invalid.
	 */
	if (unlikely(s->logs.logwait & LW_REQ)) {
		/* we have a complete HTTP request that we must log */
		if ((txn->uri = pool_alloc(pool_head_requri)) != NULL) {
			int urilen = msg->sl.rq.l;

			if (urilen >= global.tune.requri_len )
				urilen = global.tune.requri_len - 1;
			memcpy(txn->uri, req->buf->p, urilen);
			txn->uri[urilen] = 0;

			if (!(s->logs.logwait &= ~(LW_REQ|LW_INIT)))
				s->do_log(s);
		} else {
			ha_alert("HTTP logging : out of memory.\n");
		}
	}

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (!(sess->fe->options2 & PR_O2_REQBUG_OK)) {
		if (msg->sl.rq.v_l != 8) {
			msg->err_pos = msg->sl.rq.v;
			goto return_bad_req;
		}

		if (req->buf->p[msg->sl.rq.v + 4] != '/' ||
		    !isdigit((unsigned char)req->buf->p[msg->sl.rq.v + 5]) ||
		    req->buf->p[msg->sl.rq.v + 6] != '.' ||
		    !isdigit((unsigned char)req->buf->p[msg->sl.rq.v + 7])) {
			msg->err_pos = msg->sl.rq.v + 4;
			goto return_bad_req;
		}
	}
	else {
		/* 4. We may have to convert HTTP/0.9 requests to HTTP/1.0 */
		if (unlikely(msg->sl.rq.v_l == 0) && !http_upgrade_v09_to_v10(txn))
			goto return_bad_req;
	}

	/* ... and check if the request is HTTP/1.1 or above */
	if ((msg->sl.rq.v_l == 8) &&
	    ((req->buf->p[msg->sl.rq.v + 5] > '1') ||
	     ((req->buf->p[msg->sl.rq.v + 5] == '1') &&
	      (req->buf->p[msg->sl.rq.v + 7] >= '1'))))
		msg->flags |= HTTP_MSGF_VER_11;

	/* "connection" has not been parsed yet */
	txn->flags &= ~(TX_HDR_CONN_PRS | TX_HDR_CONN_CLO | TX_HDR_CONN_KAL | TX_HDR_CONN_UPG);

	/* if the frontend has "option http-use-proxy-header", we'll check if
	 * we have what looks like a proxied connection instead of a connection,
	 * and in this case set the TX_USE_PX_CONN flag to use Proxy-connection.
	 * Note that this is *not* RFC-compliant, however browsers and proxies
	 * happen to do that despite being non-standard :-(
	 * We consider that a request not beginning with either '/' or '*' is
	 * a proxied connection, which covers both "scheme://location" and
	 * CONNECT ip:port.
	 */
	if ((sess->fe->options2 & PR_O2_USE_PXHDR) &&
	    req->buf->p[msg->sl.rq.u] != '/' && req->buf->p[msg->sl.rq.u] != '*')
		txn->flags |= TX_USE_PX_CONN;

	/* transfer length unknown*/
	msg->flags &= ~HTTP_MSGF_XFER_LEN;

	/* 5: we may need to capture headers */
	if (unlikely((s->logs.logwait & LW_REQHDR) && s->req_cap))
		capture_headers(req->buf->p, &txn->hdr_idx,
				s->req_cap, sess->fe->req_cap);

	/* 6: determine the transfer-length according to RFC2616 #4.4, updated
	 * by RFC7230#3.3.3 :
	 *
	 * The length of a message body is determined by one of the following
	 *   (in order of precedence):
	 *
	 *   1.  Any response to a HEAD request and any response with a 1xx
	 *       (Informational), 204 (No Content), or 304 (Not Modified) status
	 *       code is always terminated by the first empty line after the
	 *       header fields, regardless of the header fields present in the
	 *       message, and thus cannot contain a message body.
	 *
	 *   2.  Any 2xx (Successful) response to a CONNECT request implies that
	 *       the connection will become a tunnel immediately after the empty
	 *       line that concludes the header fields.  A client MUST ignore any
	 *       Content-Length or Transfer-Encoding header fields received in
	 *       such a message.
	 *
	 *   3.  If a Transfer-Encoding header field is present and the chunked
	 *       transfer coding (Section 4.1) is the final encoding, the message
	 *       body length is determined by reading and decoding the chunked
	 *       data until the transfer coding indicates the data is complete.
	 *
	 *       If a Transfer-Encoding header field is present in a response and
	 *       the chunked transfer coding is not the final encoding, the
	 *       message body length is determined by reading the connection until
	 *       it is closed by the server.  If a Transfer-Encoding header field
	 *       is present in a request and the chunked transfer coding is not
	 *       the final encoding, the message body length cannot be determined
	 *       reliably; the server MUST respond with the 400 (Bad Request)
	 *       status code and then close the connection.
	 *
	 *       If a message is received with both a Transfer-Encoding and a
	 *       Content-Length header field, the Transfer-Encoding overrides the
	 *       Content-Length.  Such a message might indicate an attempt to
	 *       perform request smuggling (Section 9.5) or response splitting
	 *       (Section 9.4) and ought to be handled as an error.  A sender MUST
	 *       remove the received Content-Length field prior to forwarding such
	 *       a message downstream.
	 *
	 *   4.  If a message is received without Transfer-Encoding and with
	 *       either multiple Content-Length header fields having differing
	 *       field-values or a single Content-Length header field having an
	 *       invalid value, then the message framing is invalid and the
	 *       recipient MUST treat it as an unrecoverable error.  If this is a
	 *       request message, the server MUST respond with a 400 (Bad Request)
	 *       status code and then close the connection.  If this is a response
	 *       message received by a proxy, the proxy MUST close the connection
	 *       to the server, discard the received response, and send a 502 (Bad
	 *       Gateway) response to the client.  If this is a response message
	 *       received by a user agent, the user agent MUST close the
	 *       connection to the server and discard the received response.
	 *
	 *   5.  If a valid Content-Length header field is present without
	 *       Transfer-Encoding, its decimal value defines the expected message
	 *       body length in octets.  If the sender closes the connection or
	 *       the recipient times out before the indicated number of octets are
	 *       received, the recipient MUST consider the message to be
	 *       incomplete and close the connection.
	 *
	 *   6.  If this is a request message and none of the above are true, then
	 *       the message body length is zero (no message body is present).
	 *
	 *   7.  Otherwise, this is a response message without a declared message
	 *       body length, so the message body length is determined by the
	 *       number of octets received prior to the server closing the
	 *       connection.
	 */

	ctx.idx = 0;
	/* set TE_CHNK and XFER_LEN only if "chunked" is seen last */
	while (http_find_header2("Transfer-Encoding", 17, req->buf->p, &txn->hdr_idx, &ctx)) {
		if (ctx.vlen == 7 && strncasecmp(ctx.line + ctx.val, "chunked", 7) == 0)
			msg->flags |= HTTP_MSGF_TE_CHNK;
		else if (msg->flags & HTTP_MSGF_TE_CHNK) {
			/* chunked not last, return badreq */
			goto return_bad_req;
		}
	}

	/* Chunked requests must have their content-length removed */
	ctx.idx = 0;
	if (msg->flags & HTTP_MSGF_TE_CHNK) {
		while (http_find_header2("Content-Length", 14, req->buf->p, &txn->hdr_idx, &ctx))
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
	}
	else while (http_find_header2("Content-Length", 14, req->buf->p, &txn->hdr_idx, &ctx)) {
		signed long long cl;

		if (!ctx.vlen) {
			msg->err_pos = ctx.line + ctx.val - req->buf->p;
			goto return_bad_req;
		}

		if (strl2llrc(ctx.line + ctx.val, ctx.vlen, &cl)) {
			msg->err_pos = ctx.line + ctx.val - req->buf->p;
			goto return_bad_req; /* parse failure */
		}

		if (cl < 0) {
			msg->err_pos = ctx.line + ctx.val - req->buf->p;
			goto return_bad_req;
		}

		if ((msg->flags & HTTP_MSGF_CNT_LEN) && (msg->chunk_len != cl)) {
			msg->err_pos = ctx.line + ctx.val - req->buf->p;
			goto return_bad_req; /* already specified, was different */
		}

		msg->flags |= HTTP_MSGF_CNT_LEN;
		msg->body_len = msg->chunk_len = cl;
	}

	/* even bodyless requests have a known length */
	msg->flags |= HTTP_MSGF_XFER_LEN;

	/* Until set to anything else, the connection mode is set as Keep-Alive. It will
	 * only change if both the request and the config reference something else.
	 * Option httpclose by itself sets tunnel mode where headers are mangled.
	 * However, if another mode is set, it will affect it (eg: server-close/
	 * keep-alive + httpclose = close). Note that we avoid to redo the same work
	 * if FE and BE have the same settings (common). The method consists in
	 * checking if options changed between the two calls (implying that either
	 * one is non-null, or one of them is non-null and we are there for the first
	 * time.
	 */
	if (!(txn->flags & TX_HDR_CONN_PRS) ||
	    ((sess->fe->options & PR_O_HTTP_MODE) != (s->be->options & PR_O_HTTP_MODE)))
		http_adjust_conn_mode(s, txn, msg);

	/* we may have to wait for the request's body */
	if ((s->be->options & PR_O_WREQ_BODY) &&
	    (msg->body_len || (msg->flags & HTTP_MSGF_TE_CHNK)))
		req->analysers |= AN_REQ_HTTP_BODY;

	/*
	 * RFC7234#4:
	 *   A cache MUST write through requests with methods
	 *   that are unsafe (Section 4.2.1 of [RFC7231]) to
	 *   the origin server; i.e., a cache is not allowed
	 *   to generate a reply to such a request before
	 *   having forwarded the request and having received
	 *   a corresponding response.
	 *
	 * RFC7231#4.2.1:
	 *   Of the request methods defined by this
	 *   specification, the GET, HEAD, OPTIONS, and TRACE
	 *   methods are defined to be safe.
	 */
	if (likely(txn->meth == HTTP_METH_GET ||
		   txn->meth == HTTP_METH_HEAD ||
		   txn->meth == HTTP_METH_OPTIONS ||
		   txn->meth == HTTP_METH_TRACE))
		txn->flags |= TX_CACHEABLE | TX_CACHE_COOK;

	/* end of job, return OK */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;

 return_bad_req:
	/* We centralize bad requests processing here */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	return 0;
}


/* This function prepares an applet to handle the stats. It can deal with the
 * "100-continue" expectation, check that admin rules are met for POST requests,
 * and program a response message if something was unexpected. It cannot fail
 * and always relies on the stats applet to complete the job. It does not touch
 * analysers nor counters, which are left to the caller. It does not touch
 * s->target which is supposed to already point to the stats applet. The caller
 * is expected to have already assigned an appctx to the stream.
 */
int http_handle_stats(struct stream *s, struct channel *req)
{
	struct stats_admin_rule *stats_admin_rule;
	struct stream_interface *si = &s->si[1];
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct uri_auth *uri_auth = s->be->uri_auth;
	const char *uri, *h, *lookup;
	struct appctx *appctx;

	appctx = si_appctx(si);
	memset(&appctx->ctx.stats, 0, sizeof(appctx->ctx.stats));
	appctx->st1 = appctx->st2 = 0;
	appctx->ctx.stats.st_code = STAT_STATUS_INIT;
	appctx->ctx.stats.flags |= STAT_FMT_HTML; /* assume HTML mode by default */
	if ((msg->flags & HTTP_MSGF_VER_11) && (s->txn->meth != HTTP_METH_HEAD))
		appctx->ctx.stats.flags |= STAT_CHUNKED;

	uri = msg->chn->buf->p + msg->sl.rq.u;
	lookup = uri + uri_auth->uri_len;

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 3; h++) {
		if (memcmp(h, ";up", 3) == 0) {
			appctx->ctx.stats.flags |= STAT_HIDE_DOWN;
			break;
		}
	}

	if (uri_auth->refresh) {
		for (h = lookup; h <= uri + msg->sl.rq.u_l - 10; h++) {
			if (memcmp(h, ";norefresh", 10) == 0) {
				appctx->ctx.stats.flags |= STAT_NO_REFRESH;
				break;
			}
		}
	}

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 4; h++) {
		if (memcmp(h, ";csv", 4) == 0) {
			appctx->ctx.stats.flags &= ~STAT_FMT_HTML;
			break;
		}
	}

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 6; h++) {
		if (memcmp(h, ";typed", 6) == 0) {
			appctx->ctx.stats.flags &= ~STAT_FMT_HTML;
			appctx->ctx.stats.flags |= STAT_FMT_TYPED;
			break;
		}
	}

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 8; h++) {
		if (memcmp(h, ";st=", 4) == 0) {
			int i;
			h += 4;
			appctx->ctx.stats.st_code = STAT_STATUS_UNKN;
			for (i = STAT_STATUS_INIT + 1; i < STAT_STATUS_SIZE; i++) {
				if (strncmp(stat_status_codes[i], h, 4) == 0) {
					appctx->ctx.stats.st_code = i;
					break;
				}
			}
			break;
		}
	}

	appctx->ctx.stats.scope_str = 0;
	appctx->ctx.stats.scope_len = 0;
	for (h = lookup; h <= uri + msg->sl.rq.u_l - 8; h++) {
		if (memcmp(h, STAT_SCOPE_INPUT_NAME "=", strlen(STAT_SCOPE_INPUT_NAME) + 1) == 0) {
			int itx = 0;
			const char *h2;
			char scope_txt[STAT_SCOPE_TXT_MAXLEN + 1];
			const char *err;

			h += strlen(STAT_SCOPE_INPUT_NAME) + 1;
			h2 = h;
			appctx->ctx.stats.scope_str = h2 - msg->chn->buf->p;
			while (*h != ';' && *h != '\0' && *h != '&' && *h != ' ' && *h != '\n') {
				itx++;
				h++;
			}

			if (itx > STAT_SCOPE_TXT_MAXLEN)
				itx = STAT_SCOPE_TXT_MAXLEN;
			appctx->ctx.stats.scope_len = itx;

			/* scope_txt = search query, appctx->ctx.stats.scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
			memcpy(scope_txt, h2, itx);
			scope_txt[itx] = '\0';
			err = invalid_char(scope_txt);
			if (err) {
				/* bad char in search text => clear scope */
				appctx->ctx.stats.scope_str = 0;
				appctx->ctx.stats.scope_len = 0;
			}
			break;
		}
	}

	/* now check whether we have some admin rules for this request */
	list_for_each_entry(stats_admin_rule, &uri_auth->admin_rules, list) {
		int ret = 1;

		if (stats_admin_rule->cond) {
			ret = acl_exec_cond(stats_admin_rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (stats_admin_rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* no rule, or the rule matches */
			appctx->ctx.stats.flags |= STAT_ADMIN;
			break;
		}
	}

	/* Was the status page requested with a POST ? */
	if (unlikely(txn->meth == HTTP_METH_POST && txn->req.body_len > 0)) {
		if (appctx->ctx.stats.flags & STAT_ADMIN) {
			/* we'll need the request body, possibly after sending 100-continue */
			if (msg->msg_state < HTTP_MSG_CHUNK_SIZE)
				req->analysers |= AN_REQ_HTTP_BODY;
			appctx->st0 = STAT_HTTP_POST;
		}
		else {
			appctx->ctx.stats.st_code = STAT_STATUS_DENY;
			appctx->st0 = STAT_HTTP_LAST;
		}
	}
	else {
		/* So it was another method (GET/HEAD) */
		appctx->st0 = STAT_HTTP_HEAD;
	}

	s->task->nice = -32; /* small boost for HTTP statistics */
	return 1;
}

/* Sets the TOS header in IPv4 and the traffic class header in IPv6 packets
 * (as per RFC3260 #4 and BCP37 #4.2 and #5.2).
 */
void inet_set_tos(int fd, const struct sockaddr_storage *from, int tos)
{
#ifdef IP_TOS
	if (from->ss_family == AF_INET)
		setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
#ifdef IPV6_TCLASS
	if (from->ss_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)from)->sin6_addr))
			/* v4-mapped addresses need IP_TOS */
			setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
		else
			setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
	}
#endif
}

int http_transform_header_str(struct stream* s, struct http_msg *msg,
                              const char* name, unsigned int name_len,
                              const char *str, struct my_regex *re,
                              int action)
{
	struct hdr_ctx ctx;
	char *buf = msg->chn->buf->p;
	struct hdr_idx *idx = &s->txn->hdr_idx;
	int (*http_find_hdr_func)(const char *name, int len, char *sol,
	                          struct hdr_idx *idx, struct hdr_ctx *ctx);
	struct chunk *output = get_trash_chunk();

	ctx.idx = 0;

	/* Choose the header browsing function. */
	switch (action) {
	case ACT_HTTP_REPLACE_VAL:
		http_find_hdr_func = http_find_header2;
		break;
	case ACT_HTTP_REPLACE_HDR:
		http_find_hdr_func = http_find_full_header2;
		break;
	default: /* impossible */
		return -1;
	}

	while (http_find_hdr_func(name, name_len, buf, idx, &ctx)) {
		struct hdr_idx_elem *hdr = idx->v + ctx.idx;
		int delta;
		char *val = ctx.line + ctx.val;
		char* val_end = val + ctx.vlen;

		if (!regex_exec_match2(re, val, val_end-val, MAX_MATCH, pmatch, 0))
			continue;

		output->len = exp_replace(output->str, output->size, val, str, pmatch);
		if (output->len == -1)
			return -1;

		delta = buffer_replace2(msg->chn->buf, val, val_end, output->str, output->len);

		hdr->len += delta;
		http_msg_move_end(msg, delta);

		/* Adjust the length of the current value of the index. */
		ctx.vlen += delta;
	}

	return 0;
}

static int http_transform_header(struct stream* s, struct http_msg *msg,
                                 const char* name, unsigned int name_len,
                                 struct list *fmt, struct my_regex *re,
                                 int action)
{
	struct chunk *replace;
	int ret = -1;

	replace = alloc_trash_chunk();
	if (!replace)
		goto leave;

	replace->len = build_logline(s, replace->str, replace->size, fmt);
	if (replace->len >= replace->size - 1)
		goto leave;

	ret = http_transform_header_str(s, msg, name, name_len, replace->str, re, action);

  leave:
	free_trash_chunk(replace);
	return ret;
}

/* Executes the http-request rules <rules> for stream <s>, proxy <px> and
 * transaction <txn>. Returns the verdict of the first rule that prevents
 * further processing of the request (auth, deny, ...), and defaults to
 * HTTP_RULE_RES_STOP if it executed all rules or stopped on an allow, or
 * HTTP_RULE_RES_CONT if the last rule was reached. It may set the TX_CLTARPIT
 * on txn->flags if it encounters a tarpit rule. If <deny_status> is not NULL
 * and a deny/tarpit rule is matched, it will be filled with this rule's deny
 * status.
 */
enum rule_result
http_req_get_intercept_rule(struct proxy *px, struct list *rules, struct stream *s, int *deny_status)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct connection *cli_conn;
	struct act_rule *rule;
	struct hdr_ctx ctx;
	const char *auth_realm;
	int act_flags = 0;
	int len;

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == rules)
			goto resume_execution;
	}
	s->current_rule_list = rules;

	list_for_each_entry(rule, rules, list) {

		/* check optional condition */
		if (rule->cond) {
			int ret;

			ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);

			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (!ret) /* condition not matched */
				continue;
		}

		act_flags |= ACT_FLAG_FIRST;
resume_execution:
		switch (rule->action) {
		case ACT_ACTION_ALLOW:
			return HTTP_RULE_RES_STOP;

		case ACT_ACTION_DENY:
			if (deny_status)
				*deny_status = rule->deny_status;
			return HTTP_RULE_RES_DENY;

		case ACT_HTTP_REQ_TARPIT:
			txn->flags |= TX_CLTARPIT;
			if (deny_status)
				*deny_status = rule->deny_status;
			return HTTP_RULE_RES_DENY;

		case ACT_HTTP_REQ_AUTH:
			/* Auth might be performed on regular http-req rules as well as on stats */
			auth_realm = rule->arg.auth.realm;
			if (!auth_realm) {
				if (px->uri_auth && rules == &px->uri_auth->http_req_rules)
					auth_realm = STATS_DEFAULT_REALM;
				else
					auth_realm = px->id;
			}
			/* send 401/407 depending on whether we use a proxy or not. We still
			 * count one error, because normal browsing won't significantly
			 * increase the counter but brute force attempts will.
			 */
			chunk_printf(&trash, (txn->flags & TX_USE_PX_CONN) ? HTTP_407_fmt : HTTP_401_fmt, auth_realm);
			txn->status = (txn->flags & TX_USE_PX_CONN) ? 407 : 401;
			http_reply_and_close(s, txn->status, &trash);
			stream_inc_http_err_ctr(s);
			return HTTP_RULE_RES_ABRT;

		case ACT_HTTP_REDIR:
			if (!http_apply_redirect_rule(rule->arg.redir, s, txn))
				return HTTP_RULE_RES_BADREQ;
			return HTTP_RULE_RES_DONE;

		case ACT_HTTP_SET_NICE:
			s->task->nice = rule->arg.nice;
			break;

		case ACT_HTTP_SET_TOS:
			if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn))
				inet_set_tos(cli_conn->handle.fd, &cli_conn->addr.from, rule->arg.tos);
			break;

		case ACT_HTTP_SET_MARK:
#ifdef SO_MARK
			if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn))
				setsockopt(cli_conn->handle.fd, SOL_SOCKET, SO_MARK, &rule->arg.mark, sizeof(rule->arg.mark));
#endif
			break;

		case ACT_HTTP_SET_LOGL:
			s->logs.level = rule->arg.loglevel;
			break;

		case ACT_HTTP_REPLACE_HDR:
		case ACT_HTTP_REPLACE_VAL:
			if (http_transform_header(s, &txn->req, rule->arg.hdr_add.name,
			                          rule->arg.hdr_add.name_len,
			                          &rule->arg.hdr_add.fmt,
			                          &rule->arg.hdr_add.re, rule->action))
				return HTTP_RULE_RES_BADREQ;
			break;

		case ACT_HTTP_DEL_HDR:
			ctx.idx = 0;
			/* remove all occurrences of the header */
			while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
						 txn->req.chn->buf->p, &txn->hdr_idx, &ctx)) {
				http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
			}
			break;

		case ACT_HTTP_SET_HDR:
		case ACT_HTTP_ADD_HDR: {
			/* The scope of the trash buffer must be limited to this function. The
			 * build_logline() function can execute a lot of other function which
			 * can use the trash buffer. So for limiting the scope of this global
			 * buffer, we build first the header value using build_logline, and
			 * after we store the header name.
			 */
			struct chunk *replace;

			replace = alloc_trash_chunk();
			if (!replace)
				return HTTP_RULE_RES_BADREQ;

			len = rule->arg.hdr_add.name_len + 2,
			len += build_logline(s, replace->str + len, replace->size - len, &rule->arg.hdr_add.fmt);
			memcpy(replace->str, rule->arg.hdr_add.name, rule->arg.hdr_add.name_len);
			replace->str[rule->arg.hdr_add.name_len] = ':';
			replace->str[rule->arg.hdr_add.name_len + 1] = ' ';
			replace->len = len;

			if (rule->action == ACT_HTTP_SET_HDR) {
				/* remove all occurrences of the header */
				ctx.idx = 0;
				while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
							 txn->req.chn->buf->p, &txn->hdr_idx, &ctx)) {
					http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
				}
			}

			http_header_add_tail2(&txn->req, &txn->hdr_idx, replace->str, replace->len);

			free_trash_chunk(replace);
			break;
			}

		case ACT_HTTP_DEL_ACL:
		case ACT_HTTP_DEL_MAP: {
			struct pat_ref *ref;
			struct chunk *key;

			/* collect reference */
			ref = pat_ref_lookup(rule->arg.map.ref);
			if (!ref)
				continue;

			/* allocate key */
			key = alloc_trash_chunk();
			if (!key)
				return HTTP_RULE_RES_BADREQ;

			/* collect key */
			key->len = build_logline(s, key->str, key->size, &rule->arg.map.key);
			key->str[key->len] = '\0';

			/* perform update */
			/* returned code: 1=ok, 0=ko */
			HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
			pat_ref_delete(ref, key->str);
			HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);

			free_trash_chunk(key);
			break;
			}

		case ACT_HTTP_ADD_ACL: {
			struct pat_ref *ref;
			struct chunk *key;

			/* collect reference */
			ref = pat_ref_lookup(rule->arg.map.ref);
			if (!ref)
				continue;

			/* allocate key */
			key = alloc_trash_chunk();
			if (!key)
				return HTTP_RULE_RES_BADREQ;

			/* collect key */
			key->len = build_logline(s, key->str, key->size, &rule->arg.map.key);
			key->str[key->len] = '\0';

			/* perform update */
			/* add entry only if it does not already exist */
			HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
			if (pat_ref_find_elt(ref, key->str) == NULL)
				pat_ref_add(ref, key->str, NULL, NULL);
			HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);

			free_trash_chunk(key);
			break;
			}

		case ACT_HTTP_SET_MAP: {
			struct pat_ref *ref;
			struct chunk *key, *value;

			/* collect reference */
			ref = pat_ref_lookup(rule->arg.map.ref);
			if (!ref)
				continue;

			/* allocate key */
			key = alloc_trash_chunk();
			if (!key)
				return HTTP_RULE_RES_BADREQ;

			/* allocate value */
			value = alloc_trash_chunk();
			if (!value) {
				free_trash_chunk(key);
				return HTTP_RULE_RES_BADREQ;
			}

			/* collect key */
			key->len = build_logline(s, key->str, key->size, &rule->arg.map.key);
			key->str[key->len] = '\0';

			/* collect value */
			value->len = build_logline(s, value->str, value->size, &rule->arg.map.value);
			value->str[value->len] = '\0';

			/* perform update */
			if (pat_ref_find_elt(ref, key->str) != NULL)
				/* update entry if it exists */
				pat_ref_set(ref, key->str, value->str, NULL);
			else
				/* insert a new entry */
				pat_ref_add(ref, key->str, value->str, NULL);

			free_trash_chunk(key);
			free_trash_chunk(value);
			break;
			}

		case ACT_CUSTOM:
			if ((s->req.flags & CF_READ_ERROR) ||
			    ((s->req.flags & (CF_SHUTR|CF_READ_NULL)) &&
			     !(s->si[0].flags & SI_FL_CLEAN_ABRT) &&
			     (px->options & PR_O_ABRT_CLOSE)))
				act_flags |= ACT_FLAG_FINAL;

			switch (rule->action_ptr(rule, px, s->sess, s, act_flags)) {
			case ACT_RET_ERR:
			case ACT_RET_CONT:
				break;
			case ACT_RET_STOP:
				return HTTP_RULE_RES_DONE;
			case ACT_RET_YIELD:
				s->current_rule = rule;
				return HTTP_RULE_RES_YIELD;
			}
			break;

		case ACT_ACTION_TRK_SC0 ... ACT_ACTION_TRK_SCMAX:
			/* Note: only the first valid tracking parameter of each
			 * applies.
			 */

			if (stkctr_entry(&s->stkctr[trk_idx(rule->action)]) == NULL) {
				struct stktable *t;
				struct stksess *ts;
				struct stktable_key *key;
				void *ptr1, *ptr2;

				t = rule->arg.trk_ctr.table.t;
				key = stktable_fetch_key(t, s->be, sess, s, SMP_OPT_DIR_REQ | SMP_OPT_FINAL, rule->arg.trk_ctr.expr, NULL);

				if (key && (ts = stktable_get_entry(t, key))) {
					stream_track_stkctr(&s->stkctr[trk_idx(rule->action)], t, ts);

					/* let's count a new HTTP request as it's the first time we do it */
					ptr1 = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_CNT);
					ptr2 = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_RATE);
					if (ptr1 || ptr2) {
						HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

						if (ptr1)
							stktable_data_cast(ptr1, http_req_cnt)++;

						if (ptr2)
							update_freq_ctr_period(&stktable_data_cast(ptr2, http_req_rate),
							                       t->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);

						HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

						/* If data was modified, we need to touch to re-schedule sync */
						stktable_touch_local(t, ts, 0);
					}

					stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_CONTENT);
					if (sess->fe != s->be)
						stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_BACKEND);
				}
			}
			break;

		/* other flags exists, but normaly, they never be matched. */
		default:
			break;
		}
	}

	/* we reached the end of the rules, nothing to report */
	return HTTP_RULE_RES_CONT;
}


/* Executes the http-response rules <rules> for stream <s> and proxy <px>. It
 * returns one of 5 possible statuses: HTTP_RULE_RES_CONT, HTTP_RULE_RES_STOP,
 * HTTP_RULE_RES_DONE, HTTP_RULE_RES_YIELD, or HTTP_RULE_RES_BADREQ. If *CONT
 * is returned, the process can continue the evaluation of next rule list. If
 * *STOP or *DONE is returned, the process must stop the evaluation. If *BADREQ
 * is returned, it means the operation could not be processed and a server error
 * must be returned. It may set the TX_SVDENY on txn->flags if it encounters a
 * deny rule. If *YIELD is returned, the caller must call again the function
 * with the same context.
 */
static enum rule_result
http_res_get_intercept_rule(struct proxy *px, struct list *rules, struct stream *s)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct connection *cli_conn;
	struct act_rule *rule;
	struct hdr_ctx ctx;
	int act_flags = 0;

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == rules)
			goto resume_execution;
	}
	s->current_rule_list = rules;

	list_for_each_entry(rule, rules, list) {

		/* check optional condition */
		if (rule->cond) {
			int ret;

			ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
			ret = acl_pass(ret);

			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (!ret) /* condition not matched */
				continue;
		}

		act_flags |= ACT_FLAG_FIRST;
resume_execution:
		switch (rule->action) {
		case ACT_ACTION_ALLOW:
			return HTTP_RULE_RES_STOP; /* "allow" rules are OK */

		case ACT_ACTION_DENY:
			txn->flags |= TX_SVDENY;
			return HTTP_RULE_RES_STOP;

		case ACT_HTTP_SET_NICE:
			s->task->nice = rule->arg.nice;
			break;

		case ACT_HTTP_SET_TOS:
			if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn))
				inet_set_tos(cli_conn->handle.fd, &cli_conn->addr.from, rule->arg.tos);
			break;

		case ACT_HTTP_SET_MARK:
#ifdef SO_MARK
			if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn))
				setsockopt(cli_conn->handle.fd, SOL_SOCKET, SO_MARK, &rule->arg.mark, sizeof(rule->arg.mark));
#endif
			break;

		case ACT_HTTP_SET_LOGL:
			s->logs.level = rule->arg.loglevel;
			break;

		case ACT_HTTP_REPLACE_HDR:
		case ACT_HTTP_REPLACE_VAL:
			if (http_transform_header(s, &txn->rsp, rule->arg.hdr_add.name,
			                          rule->arg.hdr_add.name_len,
			                          &rule->arg.hdr_add.fmt,
			                          &rule->arg.hdr_add.re, rule->action))
				return HTTP_RULE_RES_BADREQ;
			break;

		case ACT_HTTP_DEL_HDR:
			ctx.idx = 0;
			/* remove all occurrences of the header */
			while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
						 txn->rsp.chn->buf->p, &txn->hdr_idx, &ctx)) {
				http_remove_header2(&txn->rsp, &txn->hdr_idx, &ctx);
			}
			break;

		case ACT_HTTP_SET_HDR:
		case ACT_HTTP_ADD_HDR: {
			struct chunk *replace;

			replace = alloc_trash_chunk();
			if (!replace)
				return HTTP_RULE_RES_BADREQ;

			chunk_printf(replace, "%s: ", rule->arg.hdr_add.name);
			memcpy(replace->str, rule->arg.hdr_add.name, rule->arg.hdr_add.name_len);
			replace->len = rule->arg.hdr_add.name_len;
			replace->str[replace->len++] = ':';
			replace->str[replace->len++] = ' ';
			replace->len += build_logline(s, replace->str + replace->len, replace->size - replace->len,
			                              &rule->arg.hdr_add.fmt);

			if (rule->action == ACT_HTTP_SET_HDR) {
				/* remove all occurrences of the header */
				ctx.idx = 0;
				while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
							 txn->rsp.chn->buf->p, &txn->hdr_idx, &ctx)) {
					http_remove_header2(&txn->rsp, &txn->hdr_idx, &ctx);
				}
			}
			http_header_add_tail2(&txn->rsp, &txn->hdr_idx, replace->str, replace->len);

			free_trash_chunk(replace);
			break;
			}

		case ACT_HTTP_DEL_ACL:
		case ACT_HTTP_DEL_MAP: {
			struct pat_ref *ref;
			struct chunk *key;

			/* collect reference */
			ref = pat_ref_lookup(rule->arg.map.ref);
			if (!ref)
				continue;

			/* allocate key */
			key = alloc_trash_chunk();
			if (!key)
				return HTTP_RULE_RES_BADREQ;

			/* collect key */
			key->len = build_logline(s, key->str, key->size, &rule->arg.map.key);
			key->str[key->len] = '\0';

			/* perform update */
			/* returned code: 1=ok, 0=ko */
			HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
			pat_ref_delete(ref, key->str);
			HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);

			free_trash_chunk(key);
			break;
			}

		case ACT_HTTP_ADD_ACL: {
			struct pat_ref *ref;
			struct chunk *key;

			/* collect reference */
			ref = pat_ref_lookup(rule->arg.map.ref);
			if (!ref)
				continue;

			/* allocate key */
			key = alloc_trash_chunk();
			if (!key)
				return HTTP_RULE_RES_BADREQ;

			/* collect key */
			key->len = build_logline(s, key->str, key->size, &rule->arg.map.key);
			key->str[key->len] = '\0';

			/* perform update */
			/* check if the entry already exists */
			if (pat_ref_find_elt(ref, key->str) == NULL)
				pat_ref_add(ref, key->str, NULL, NULL);

			free_trash_chunk(key);
			break;
			}

		case ACT_HTTP_SET_MAP: {
			struct pat_ref *ref;
			struct chunk *key, *value;

			/* collect reference */
			ref = pat_ref_lookup(rule->arg.map.ref);
			if (!ref)
				continue;

			/* allocate key */
			key = alloc_trash_chunk();
			if (!key)
				return HTTP_RULE_RES_BADREQ;

			/* allocate value */
			value = alloc_trash_chunk();
			if (!value) {
				free_trash_chunk(key);
				return HTTP_RULE_RES_BADREQ;
			}

			/* collect key */
			key->len = build_logline(s, key->str, key->size, &rule->arg.map.key);
			key->str[key->len] = '\0';

			/* collect value */
			value->len = build_logline(s, value->str, value->size, &rule->arg.map.value);
			value->str[value->len] = '\0';

			/* perform update */
			HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
			if (pat_ref_find_elt(ref, key->str) != NULL)
				/* update entry if it exists */
				pat_ref_set(ref, key->str, value->str, NULL);
			else
				/* insert a new entry */
				pat_ref_add(ref, key->str, value->str, NULL);
			HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
			free_trash_chunk(key);
			free_trash_chunk(value);
			break;
			}

		case ACT_HTTP_REDIR:
			if (!http_apply_redirect_rule(rule->arg.redir, s, txn))
				return HTTP_RULE_RES_BADREQ;
			return HTTP_RULE_RES_DONE;

		case ACT_ACTION_TRK_SC0 ... ACT_ACTION_TRK_SCMAX:
			/* Note: only the first valid tracking parameter of each
			 * applies.
			 */

			if (stkctr_entry(&s->stkctr[trk_idx(rule->action)]) == NULL) {
				struct stktable *t;
				struct stksess *ts;
				struct stktable_key *key;
				void *ptr;

				t = rule->arg.trk_ctr.table.t;
				key = stktable_fetch_key(t, s->be, sess, s, SMP_OPT_DIR_RES | SMP_OPT_FINAL, rule->arg.trk_ctr.expr, NULL);

				if (key && (ts = stktable_get_entry(t, key))) {
					stream_track_stkctr(&s->stkctr[trk_idx(rule->action)], t, ts);

					HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

					/* let's count a new HTTP request as it's the first time we do it */
					ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_CNT);
					if (ptr)
						stktable_data_cast(ptr, http_req_cnt)++;

					ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_RATE);
					if (ptr)
						update_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
											   t->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);

					/* When the client triggers a 4xx from the server, it's most often due
					 * to a missing object or permission. These events should be tracked
					 * because if they happen often, it may indicate a brute force or a
					 * vulnerability scan. Normally this is done when receiving the response
					 * but here we're tracking after this ought to have been done so we have
					 * to do it on purpose.
					 */
					if ((unsigned)(txn->status - 400) < 100) {
						ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_ERR_CNT);
						if (ptr)
							stktable_data_cast(ptr, http_err_cnt)++;

						ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_ERR_RATE);
						if (ptr)
							update_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
									       t->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u, 1);
					}

					HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

					/* If data was modified, we need to touch to re-schedule sync */
					stktable_touch_local(t, ts, 0);

					stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_CONTENT);
					if (sess->fe != s->be)
						stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_BACKEND);

				}
			}
			break;

		case ACT_CUSTOM:
			if ((s->req.flags & CF_READ_ERROR) ||
			    ((s->req.flags & (CF_SHUTR|CF_READ_NULL)) &&
			     !(s->si[0].flags & SI_FL_CLEAN_ABRT) &&
			     (px->options & PR_O_ABRT_CLOSE)))
				act_flags |= ACT_FLAG_FINAL;

			switch (rule->action_ptr(rule, px, s->sess, s, act_flags)) {
			case ACT_RET_ERR:
			case ACT_RET_CONT:
				break;
			case ACT_RET_STOP:
				return HTTP_RULE_RES_STOP;
			case ACT_RET_YIELD:
				s->current_rule = rule;
				return HTTP_RULE_RES_YIELD;
			}
			break;

		/* other flags exists, but normaly, they never be matched. */
		default:
			break;
		}
	}

	/* we reached the end of the rules, nothing to report */
	return HTTP_RULE_RES_CONT;
}


/* Perform an HTTP redirect based on the information in <rule>. The function
 * returns non-zero on success, or zero in case of a, irrecoverable error such
 * as too large a request to build a valid response.
 */
static int http_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn)
{
	struct http_msg *req = &txn->req;
	struct http_msg *res = &txn->rsp;
	const char *msg_fmt;
	struct chunk *chunk;
	int ret = 0;

	chunk = alloc_trash_chunk();
	if (!chunk)
		goto leave;

	/* build redirect message */
	switch(rule->code) {
	case 308:
		msg_fmt = HTTP_308;
		break;
	case 307:
		msg_fmt = HTTP_307;
		break;
	case 303:
		msg_fmt = HTTP_303;
		break;
	case 301:
		msg_fmt = HTTP_301;
		break;
	case 302:
	default:
		msg_fmt = HTTP_302;
		break;
	}

	if (unlikely(!chunk_strcpy(chunk, msg_fmt)))
		goto leave;

	switch(rule->type) {
	case REDIRECT_TYPE_SCHEME: {
		const char *path;
		const char *host;
		struct hdr_ctx ctx;
		int pathlen;
		int hostlen;

		host = "";
		hostlen = 0;
		ctx.idx = 0;
		if (http_find_header2("Host", 4, req->chn->buf->p, &txn->hdr_idx, &ctx)) {
			host = ctx.line + ctx.val;
			hostlen = ctx.vlen;
		}

		path = http_get_path(txn);
		/* build message using path */
		if (path) {
			pathlen = req->sl.rq.u_l + (req->chn->buf->p + req->sl.rq.u) - path;
			if (rule->flags & REDIRECT_FLAG_DROP_QS) {
				int qs = 0;
				while (qs < pathlen) {
					if (path[qs] == '?') {
						pathlen = qs;
						break;
					}
					qs++;
				}
			}
		} else {
			path = "/";
			pathlen = 1;
		}

		if (rule->rdr_str) { /* this is an old "redirect" rule */
			/* check if we can add scheme + "://" + host + path */
			if (chunk->len + rule->rdr_len + 3 + hostlen + pathlen > chunk->size - 4)
				goto leave;

			/* add scheme */
			memcpy(chunk->str + chunk->len, rule->rdr_str, rule->rdr_len);
			chunk->len += rule->rdr_len;
		}
		else {
			/* add scheme with executing log format */
			chunk->len += build_logline(s, chunk->str + chunk->len, chunk->size - chunk->len, &rule->rdr_fmt);

			/* check if we can add scheme + "://" + host + path */
			if (chunk->len + 3 + hostlen + pathlen > chunk->size - 4)
				goto leave;
		}
		/* add "://" */
		memcpy(chunk->str + chunk->len, "://", 3);
		chunk->len += 3;

		/* add host */
		memcpy(chunk->str + chunk->len, host, hostlen);
		chunk->len += hostlen;

		/* add path */
		memcpy(chunk->str + chunk->len, path, pathlen);
		chunk->len += pathlen;

		/* append a slash at the end of the location if needed and missing */
		if (chunk->len && chunk->str[chunk->len - 1] != '/' &&
		    (rule->flags & REDIRECT_FLAG_APPEND_SLASH)) {
			if (chunk->len > chunk->size - 5)
				goto leave;
			chunk->str[chunk->len] = '/';
			chunk->len++;
		}

		break;
	}
	case REDIRECT_TYPE_PREFIX: {
		const char *path;
		int pathlen;

		path = http_get_path(txn);
		/* build message using path */
		if (path) {
			pathlen = req->sl.rq.u_l + (req->chn->buf->p + req->sl.rq.u) - path;
			if (rule->flags & REDIRECT_FLAG_DROP_QS) {
				int qs = 0;
				while (qs < pathlen) {
					if (path[qs] == '?') {
						pathlen = qs;
						break;
					}
					qs++;
				}
			}
		} else {
			path = "/";
			pathlen = 1;
		}

		if (rule->rdr_str) { /* this is an old "redirect" rule */
			if (chunk->len + rule->rdr_len + pathlen > chunk->size - 4)
				goto leave;

			/* add prefix. Note that if prefix == "/", we don't want to
			 * add anything, otherwise it makes it hard for the user to
			 * configure a self-redirection.
			 */
			if (rule->rdr_len != 1 || *rule->rdr_str != '/') {
				memcpy(chunk->str + chunk->len, rule->rdr_str, rule->rdr_len);
				chunk->len += rule->rdr_len;
			}
		}
		else {
			/* add prefix with executing log format */
			chunk->len += build_logline(s, chunk->str + chunk->len, chunk->size - chunk->len, &rule->rdr_fmt);

			/* Check length */
			if (chunk->len + pathlen > chunk->size - 4)
				goto leave;
		}

		/* add path */
		memcpy(chunk->str + chunk->len, path, pathlen);
		chunk->len += pathlen;

		/* append a slash at the end of the location if needed and missing */
		if (chunk->len && chunk->str[chunk->len - 1] != '/' &&
		    (rule->flags & REDIRECT_FLAG_APPEND_SLASH)) {
			if (chunk->len > chunk->size - 5)
				goto leave;
			chunk->str[chunk->len] = '/';
			chunk->len++;
		}

		break;
	}
	case REDIRECT_TYPE_LOCATION:
	default:
		if (rule->rdr_str) { /* this is an old "redirect" rule */
			if (chunk->len + rule->rdr_len > chunk->size - 4)
				goto leave;

			/* add location */
			memcpy(chunk->str + chunk->len, rule->rdr_str, rule->rdr_len);
			chunk->len += rule->rdr_len;
		}
		else {
			/* add location with executing log format */
			chunk->len += build_logline(s, chunk->str + chunk->len, chunk->size - chunk->len, &rule->rdr_fmt);

			/* Check left length */
			if (chunk->len > chunk->size - 4)
				goto leave;
		}
		break;
	}

	if (rule->cookie_len) {
		memcpy(chunk->str + chunk->len, "\r\nSet-Cookie: ", 14);
		chunk->len += 14;
		memcpy(chunk->str + chunk->len, rule->cookie_str, rule->cookie_len);
		chunk->len += rule->cookie_len;
	}

	/* add end of headers and the keep-alive/close status. */
	txn->status = rule->code;
	/* let's log the request time */
	s->logs.tv_request = now;

	if (((!(req->flags & HTTP_MSGF_TE_CHNK) && !req->body_len) || (req->msg_state == HTTP_MSG_DONE)) &&
	    ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL ||
	     (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL)) {
		/* keep-alive possible */
		if (!(req->flags & HTTP_MSGF_VER_11)) {
			if (unlikely(txn->flags & TX_USE_PX_CONN)) {
				memcpy(chunk->str + chunk->len, "\r\nProxy-Connection: keep-alive", 30);
				chunk->len += 30;
			} else {
				memcpy(chunk->str + chunk->len, "\r\nConnection: keep-alive", 24);
				chunk->len += 24;
			}
		}
		memcpy(chunk->str + chunk->len, "\r\n\r\n", 4);
		chunk->len += 4;
		FLT_STRM_CB(s, flt_http_reply(s, txn->status, chunk));
		co_inject(res->chn, chunk->str, chunk->len);
		/* "eat" the request */
		bi_fast_delete(req->chn->buf, req->sov);
		req->next -= req->sov;
		req->sov = 0;
		s->req.analysers = AN_REQ_HTTP_XFER_BODY | (s->req.analysers & AN_REQ_FLT_END);
		s->res.analysers = AN_RES_HTTP_XFER_BODY | (s->res.analysers & AN_RES_FLT_END);
		req->msg_state = HTTP_MSG_CLOSED;
		res->msg_state = HTTP_MSG_DONE;
		/* Trim any possible response */
		res->chn->buf->i = 0;
		res->next = res->sov = 0;
		/* let the server side turn to SI_ST_CLO */
		channel_shutw_now(req->chn);
	} else {
		/* keep-alive not possible */
		if (unlikely(txn->flags & TX_USE_PX_CONN)) {
			memcpy(chunk->str + chunk->len, "\r\nProxy-Connection: close\r\n\r\n", 29);
			chunk->len += 29;
		} else {
			memcpy(chunk->str + chunk->len, "\r\nConnection: close\r\n\r\n", 23);
			chunk->len += 23;
		}
		http_reply_and_close(s, txn->status, chunk);
		req->chn->analysers &= AN_REQ_FLT_END;
	}

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_LOCAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	ret = 1;
 leave:
	free_trash_chunk(chunk);
	return ret;
}

/* This stream analyser runs all HTTP request processing which is common to
 * frontends and backends, which means blocking ACLs, filters, connection-close,
 * reqadd, stats and redirects. This is performed for the designated proxy.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * either needs more data or wants to immediately abort the request (eg: deny,
 * error, ...).
 */
int http_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct redirect_rule *rule;
	struct cond_wordlist *wl;
	enum rule_result verdict;
	int deny_status = HTTP_ERR_403;
	struct connection *conn = objt_conn(sess->origin);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		goto return_prx_yield;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	/* just in case we have some per-backend tracking */
	stream_inc_be_http_req_ctr(s);

	/* evaluate http-request rules */
	if (!LIST_ISEMPTY(&px->http_req_rules)) {
		verdict = http_req_get_intercept_rule(px, &px->http_req_rules, s, &deny_status);

		switch (verdict) {
		case HTTP_RULE_RES_YIELD: /* some data miss, call the function later. */
			goto return_prx_yield;

		case HTTP_RULE_RES_CONT:
		case HTTP_RULE_RES_STOP: /* nothing to do */
			break;

		case HTTP_RULE_RES_DENY: /* deny or tarpit */
			if (txn->flags & TX_CLTARPIT)
				goto tarpit;
			goto deny;

		case HTTP_RULE_RES_ABRT: /* abort request, response already sent. Eg: auth */
			goto return_prx_cond;

		case HTTP_RULE_RES_DONE: /* OK, but terminate request processing (eg: redirect) */
			goto done;

		case HTTP_RULE_RES_BADREQ: /* failed with a bad request */
			goto return_bad_req;
		}
	}

	if (conn && conn->flags & CO_FL_EARLY_DATA) {
		struct hdr_ctx ctx;

		ctx.idx = 0;
		if (!http_find_header2("Early-Data", strlen("Early-Data"),
		    s->req.buf->p, &txn->hdr_idx, &ctx)) {
			if (unlikely(http_header_add_tail2(&txn->req,
			    &txn->hdr_idx, "Early-Data: 1",
			    strlen("Early-Data: 1"))) < 0) {
				goto return_bad_req;
			 }
		}

	}

	/* OK at this stage, we know that the request was accepted according to
	 * the http-request rules, we can check for the stats. Note that the
	 * URI is detected *before* the req* rules in order not to be affected
	 * by a possible reqrep, while they are processed *after* so that a
	 * reqdeny can still block them. This clearly needs to change in 1.6!
	 */
	if (stats_check_uri(&s->si[1], txn, px)) {
		s->target = &http_stats_applet.obj_type;
		if (unlikely(!stream_int_register_handler(&s->si[1], objt_applet(s->target)))) {
			txn->status = 500;
			s->logs.tv_request = now;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			goto return_prx_cond;
		}

		/* parse the whole stats request and extract the relevant information */
		http_handle_stats(s, req);
		verdict = http_req_get_intercept_rule(px, &px->uri_auth->http_req_rules, s, &deny_status);
		/* not all actions implemented: deny, allow, auth */

		if (verdict == HTTP_RULE_RES_DENY) /* stats http-request deny */
			goto deny;

		if (verdict == HTTP_RULE_RES_ABRT) /* stats auth / stats http-request auth */
			goto return_prx_cond;
	}

	/* evaluate the req* rules except reqadd */
	if (px->req_exp != NULL) {
		if (apply_filters_to_request(s, req, px) < 0)
			goto return_bad_req;

		if (txn->flags & TX_CLDENY)
			goto deny;

		if (txn->flags & TX_CLTARPIT) {
			deny_status = HTTP_ERR_500;
			goto tarpit;
		}
	}

	/* add request headers from the rule sets in the same order */
	list_for_each_entry(wl, &px->req_add, list) {
		if (wl->cond) {
			int ret = acl_exec_cond(wl->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (((struct acl_cond *)wl->cond)->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}

		if (unlikely(http_header_add_tail(&txn->req, &txn->hdr_idx, wl->s) < 0))
			goto return_bad_req;
	}


	/* Proceed with the stats now. */
	if (unlikely(objt_applet(s->target) == &http_stats_applet) ||
	    unlikely(objt_applet(s->target) == &http_cache_applet)) {
		/* process the stats request now */
		if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

		if (!(s->flags & SF_ERR_MASK))      // this is not really an error but it is
			s->flags |= SF_ERR_LOCAL;   // to mark that it comes from the proxy
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_R;

		/* enable the minimally required analyzers to handle keep-alive and compression on the HTTP response */
		req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
		req->analysers &= ~AN_REQ_FLT_XFER_DATA;
		req->analysers |= AN_REQ_HTTP_XFER_BODY;
		goto done;
	}

	/* check whether we have some ACLs set to redirect this request */
	list_for_each_entry(rule, &px->redirect_rules, list) {
		if (rule->cond) {
			int ret;

			ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}
		if (!http_apply_redirect_rule(rule, s, txn))
			goto return_bad_req;
		goto done;
	}

	/* POST requests may be accompanied with an "Expect: 100-Continue" header.
	 * If this happens, then the data will not come immediately, so we must
	 * send all what we have without waiting. Note that due to the small gain
	 * in waiting for the body of the request, it's easier to simply put the
	 * CF_SEND_DONTWAIT flag any time. It's a one-shot flag so it will remove
	 * itself once used.
	 */
	req->flags |= CF_SEND_DONTWAIT;

 done:	/* done with this analyser, continue with next ones that the calling
	 * points will have set, if any.
	 */
	req->analyse_exp = TICK_ETERNITY;
 done_without_exp: /* done with this analyser, but dont reset the analyse_exp. */
	req->analysers &= ~an_bit;
	return 1;

 tarpit:
	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	/* When a connection is tarpitted, we use the tarpit timeout,
	 * which may be the same as the connect timeout if unspecified.
	 * If unset, then set it to zero because we really want it to
	 * eventually expire. We build the tarpit as an analyser.
	 */
	channel_erase(&s->req);

	/* wipe the request out so that we can drop the connection early
	 * if the client closes first.
	 */
	channel_dont_connect(req);

	txn->status = http_err_codes[deny_status];

	req->analysers &= AN_REQ_FLT_END; /* remove switching rules etc... */
	req->analysers |= AN_REQ_HTTP_TARPIT;
	req->analyse_exp = tick_add_ifset(now_ms,  s->be->timeout.tarpit);
	if (!req->analyse_exp)
		req->analyse_exp = tick_add(now_ms, 0);
	stream_inc_http_err_ctr(s);
	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto done_without_exp;

 deny:	/* this request was blocked (denied) */

	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	txn->flags |= TX_CLDENY;
	txn->status = http_err_codes[deny_status];
	s->logs.tv_request = now;
	http_reply_and_close(s, txn->status, http_error_message(s));
	stream_inc_http_err_ctr(s);
	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto return_prx_cond;

 return_bad_req:
	/* We centralize bad requests processing here */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	return 0;

 return_prx_yield:
	channel_dont_connect(req);
	return 0;
}

/* This function performs all the processing enabled for the current request.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * needs more data, encounters an error, or wants to immediately abort the
 * request. It relies on buffers flags, and updates s->req.analysers.
 */
int http_process_request(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct connection *cli_conn = objt_conn(strm_sess(s)->origin);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		channel_dont_connect(req);
		return 0;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	/*
	 * Right now, we know that we have processed the entire headers
	 * and that unwanted requests have been filtered out. We can do
	 * whatever we want with the remaining request. Also, now we
	 * may have separate values for ->fe, ->be.
	 */

	/*
	 * If HTTP PROXY is set we simply get remote server address parsing
	 * incoming request. Note that this requires that a connection is
	 * allocated on the server side.
	 */
	if ((s->be->options & PR_O_HTTP_PROXY) && !(s->flags & SF_ADDR_SET)) {
		struct connection *conn;
		char *path;

		/* Note that for now we don't reuse existing proxy connections */
		if (unlikely((conn = cs_conn(si_alloc_cs(&s->si[1], NULL))) == NULL)) {
			txn->req.err_state = txn->req.msg_state;
			txn->req.msg_state = HTTP_MSG_ERROR;
			txn->status = 500;
			req->analysers &= AN_REQ_FLT_END;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;

			return 0;
		}

		path = http_get_path(txn);
		url2sa(req->buf->p + msg->sl.rq.u,
		       path ? path - (req->buf->p + msg->sl.rq.u) : msg->sl.rq.u_l,
		       &conn->addr.to, NULL);
		/* if the path was found, we have to remove everything between
		 * req->buf->p + msg->sl.rq.u and path (excluded). If it was not
		 * found, we need to replace from req->buf->p + msg->sl.rq.u for
		 * u_l characters by a single "/".
		 */
		if (path) {
			char *cur_ptr = req->buf->p;
			char *cur_end = cur_ptr + txn->req.sl.rq.l;
			int delta;

			delta = buffer_replace2(req->buf, req->buf->p + msg->sl.rq.u, path, NULL, 0);
			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			if (http_parse_reqline(&txn->req, HTTP_MSG_RQMETH,  cur_ptr, cur_end + 1, NULL, NULL) == NULL)
				goto return_bad_req;
		}
		else {
			char *cur_ptr = req->buf->p;
			char *cur_end = cur_ptr + txn->req.sl.rq.l;
			int delta;

			delta = buffer_replace2(req->buf, req->buf->p + msg->sl.rq.u,
						req->buf->p + msg->sl.rq.u + msg->sl.rq.u_l, "/", 1);
			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			if (http_parse_reqline(&txn->req, HTTP_MSG_RQMETH,  cur_ptr, cur_end + 1, NULL, NULL) == NULL)
				goto return_bad_req;
		}
	}

	/*
	 * 7: Now we can work with the cookies.
	 * Note that doing so might move headers in the request, but
	 * the fields will stay coherent and the URI will not move.
	 * This should only be performed in the backend.
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	/* add unique-id if "header-unique-id" is specified */

	if (!LIST_ISEMPTY(&sess->fe->format_unique_id) && !s->unique_id) {
		if ((s->unique_id = pool_alloc(pool_head_uniqueid)) == NULL)
			goto return_bad_req;
		s->unique_id[0] = '\0';
		build_logline(s, s->unique_id, UNIQUEID_LEN, &sess->fe->format_unique_id);
	}

	if (sess->fe->header_unique_id && s->unique_id) {
		chunk_printf(&trash, "%s: %s", sess->fe->header_unique_id, s->unique_id);
		if (trash.len < 0)
			goto return_bad_req;
		if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.str, trash.len) < 0))
		   goto return_bad_req;
	}

	/*
	 * 9: add X-Forwarded-For if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_FWDFOR) {
		struct hdr_ctx ctx = { .idx = 0 };
		if (!((sess->fe->options | s->be->options) & PR_O_FF_ALWAYS) &&
			http_find_header2(s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_name : sess->fe->fwdfor_hdr_name,
			                  s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_len : sess->fe->fwdfor_hdr_len,
			                  req->buf->p, &txn->hdr_idx, &ctx)) {
			/* The header is set to be added only if none is present
			 * and we found it, so don't do anything.
			 */
		}
		else if (cli_conn && cli_conn->addr.from.ss_family == AF_INET) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if ((!sess->fe->except_mask.s_addr ||
			     (((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr & sess->fe->except_mask.s_addr)
			     != sess->fe->except_net.s_addr) &&
			    (!s->be->except_mask.s_addr ||
			     (((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr & s->be->except_mask.s_addr)
			     != s->be->except_net.s_addr)) {
				int len;
				unsigned char *pn;
				pn = (unsigned char *)&((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (s->be->fwdfor_hdr_len) {
					len = s->be->fwdfor_hdr_len;
					memcpy(trash.str, s->be->fwdfor_hdr_name, len);
				} else {
					len = sess->fe->fwdfor_hdr_len;
					memcpy(trash.str, sess->fe->fwdfor_hdr_name, len);
				}
				len += snprintf(trash.str + len, trash.size - len, ": %d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);

				if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.str, len) < 0))
					goto return_bad_req;
			}
		}
		else if (cli_conn && cli_conn->addr.from.ss_family == AF_INET6) {
			/* FIXME: for the sake of completeness, we should also support
			 * 'except' here, although it is mostly useless in this case.
			 */
			int len;
			char pn[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6,
				  (const void *)&((struct sockaddr_in6 *)(&cli_conn->addr.from))->sin6_addr,
				  pn, sizeof(pn));

			/* Note: we rely on the backend to get the header name to be used for
			 * x-forwarded-for, because the header is really meant for the backends.
			 * However, if the backend did not specify any option, we have to rely
			 * on the frontend's header name.
			 */
			if (s->be->fwdfor_hdr_len) {
				len = s->be->fwdfor_hdr_len;
				memcpy(trash.str, s->be->fwdfor_hdr_name, len);
			} else {
				len = sess->fe->fwdfor_hdr_len;
				memcpy(trash.str, sess->fe->fwdfor_hdr_name, len);
			}
			len += snprintf(trash.str + len, trash.size - len, ": %s", pn);

			if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.str, len) < 0))
				goto return_bad_req;
		}
	}

	/*
	 * 10: add X-Original-To if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_ORGTO) {

		/* FIXME: don't know if IPv6 can handle that case too. */
		if (cli_conn && cli_conn->addr.from.ss_family == AF_INET) {
			/* Add an X-Original-To header unless the destination IP is
			 * in the 'except' network range.
			 */
			conn_get_to_addr(cli_conn);

			if (cli_conn->addr.to.ss_family == AF_INET &&
			    ((!sess->fe->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr & sess->fe->except_mask_to.s_addr)
			      != sess->fe->except_to.s_addr) &&
			     (!s->be->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr & s->be->except_mask_to.s_addr)
			      != s->be->except_to.s_addr))) {
				int len;
				unsigned char *pn;
				pn = (unsigned char *)&((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-original-to, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (s->be->orgto_hdr_len) {
					len = s->be->orgto_hdr_len;
					memcpy(trash.str, s->be->orgto_hdr_name, len);
				} else {
					len = sess->fe->orgto_hdr_len;
					memcpy(trash.str, sess->fe->orgto_hdr_name, len);
				}
				len += snprintf(trash.str + len, trash.size - len, ": %d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);

				if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.str, len) < 0))
					goto return_bad_req;
			}
		}
	}

	/* 11: add "Connection: close" or "Connection: keep-alive" if needed and not yet set.
	 * If an "Upgrade" token is found, the header is left untouched in order not to have
	 * to deal with some servers bugs : some of them fail an Upgrade if anything but
	 * "Upgrade" is present in the Connection header.
	 */
	if (!(txn->flags & TX_HDR_CONN_UPG) &&
	    (((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) ||
	     ((sess->fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL ||
	      (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL))) {
		unsigned int want_flags = 0;

		if (msg->flags & HTTP_MSGF_VER_11) {
			if (((txn->flags & TX_CON_WANT_MSK) >= TX_CON_WANT_SCL ||
			     ((sess->fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL ||
			      (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL)) &&
			    !((sess->fe->options2|s->be->options2) & PR_O2_FAKE_KA))
				want_flags |= TX_CON_CLO_SET;
		} else {
			if (((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL &&
			     ((sess->fe->options & PR_O_HTTP_MODE) != PR_O_HTTP_PCL &&
			      (s->be->options & PR_O_HTTP_MODE) != PR_O_HTTP_PCL)) ||
			    ((sess->fe->options2|s->be->options2) & PR_O2_FAKE_KA))
				want_flags |= TX_CON_KAL_SET;
		}

		if (want_flags != (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
			http_change_connection_header(txn, msg, want_flags);
	}


	/* If we have no server assigned yet and we're balancing on url_param
	 * with a POST request, we may be interested in checking the body for
	 * that parameter. This will be done in another analyser.
	 */
	if (!(s->flags & (SF_ASSIGNED|SF_DIRECT)) &&
	    s->txn->meth == HTTP_METH_POST && s->be->url_param_name != NULL &&
	    (msg->flags & (HTTP_MSGF_CNT_LEN|HTTP_MSGF_TE_CHNK))) {
		channel_dont_connect(req);
		req->analysers |= AN_REQ_HTTP_BODY;
	}

	req->analysers &= ~AN_REQ_FLT_XFER_DATA;
	req->analysers |= AN_REQ_HTTP_XFER_BODY;
#ifdef TCP_QUICKACK
	/* We expect some data from the client. Unless we know for sure
	 * we already have a full request, we have to re-enable quick-ack
	 * in case we previously disabled it, otherwise we might cause
	 * the client to delay further data.
	 */
	if ((sess->listener->options & LI_O_NOQUICKACK) &&
	    cli_conn && conn_ctrl_ready(cli_conn) &&
	    ((msg->flags & HTTP_MSGF_TE_CHNK) ||
	     (msg->body_len > req->buf->i - txn->req.eoh - 2)))
		setsockopt(cli_conn->handle.fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif

	/*************************************************************
	 * OK, that's finished for the headers. We have done what we *
	 * could. Let's switch to the DATA state.                    *
	 ************************************************************/
	req->analyse_exp = TICK_ETERNITY;
	req->analysers &= ~an_bit;

	s->logs.tv_request = now;
	/* OK let's go on with the BODY now */
	return 1;

 return_bad_req: /* let's centralize all bad requests */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	req->analysers &= AN_REQ_FLT_END;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;
	return 0;
}

/* This function is an analyser which processes the HTTP tarpit. It always
 * returns zero, at the beginning because it prevents any other processing
 * from occurring, and at the end because it terminates the request.
 */
int http_process_tarpit(struct stream *s, struct channel *req, int an_bit)
{
	struct http_txn *txn = s->txn;

	/* This connection is being tarpitted. The CLIENT side has
	 * already set the connect expiration date to the right
	 * timeout. We just have to check that the client is still
	 * there and that the timeout has not expired.
	 */
	channel_dont_connect(req);
	if ((req->flags & (CF_SHUTR|CF_READ_ERROR)) == 0 &&
	    !tick_is_expired(req->analyse_exp, now_ms))
		return 0;

	/* We will set the queue timer to the time spent, just for
	 * logging purposes. We fake a 500 server error, so that the
	 * attacker will not suspect his connection has been tarpitted.
	 * It will not cause trouble to the logs because we can exclude
	 * the tarpitted connections by filtering on the 'PT' status flags.
	 */
	s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

	if (!(req->flags & CF_READ_ERROR))
		http_reply_and_close(s, txn->status, http_error_message(s));

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_T;
	return 0;
}

/* This function is an analyser which waits for the HTTP request body. It waits
 * for either the buffer to be full, or the full advertised contents to have
 * reached the buffer. It must only be called after the standard HTTP request
 * processing has occurred, because it expects the request to be parsed and will
 * look for the Expect header. It may send a 100-Continue interim response. It
 * takes in input any state starting from HTTP_MSG_BODY and leaves with one of
 * HTTP_MSG_CHK_SIZE, HTTP_MSG_DATA or HTTP_MSG_TRAILERS. It returns zero if it
 * needs to read more data, or 1 once it has completed its analysis.
 */
int http_wait_for_request_body(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->req;

	/* We have to parse the HTTP request body to find any required data.
	 * "balance url_param check_post" should have been the only way to get
	 * into this. We were brought here after HTTP header analysis, so all
	 * related structures are ready.
	 */

	if (msg->msg_state < HTTP_MSG_CHUNK_SIZE) {
		/* This is the first call */
		if (msg->msg_state < HTTP_MSG_BODY)
			goto missing_data;

		if (msg->msg_state < HTTP_MSG_100_SENT) {
			/* If we have HTTP/1.1 and Expect: 100-continue, then we must
			 * send an HTTP/1.1 100 Continue intermediate response.
			 */
			if (msg->flags & HTTP_MSGF_VER_11) {
				struct hdr_ctx ctx;
				ctx.idx = 0;
				/* Expect is allowed in 1.1, look for it */
				if (http_find_header2("Expect", 6, req->buf->p, &txn->hdr_idx, &ctx) &&
				    unlikely(ctx.vlen == 12 && strncasecmp(ctx.line+ctx.val, "100-continue", 12) == 0)) {
					co_inject(&s->res, http_100_chunk.str, http_100_chunk.len);
					http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
				}
			}
			msg->msg_state = HTTP_MSG_100_SENT;
		}

		/* we have msg->sov which points to the first byte of message body.
		 * req->buf->p still points to the beginning of the message. We
		 * must save the body in msg->next because it survives buffer
		 * re-alignments.
		 */
		msg->next = msg->sov;

		if (msg->flags & HTTP_MSGF_TE_CHNK)
			msg->msg_state = HTTP_MSG_CHUNK_SIZE;
		else
			msg->msg_state = HTTP_MSG_DATA;
	}

	if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
		/* We're in content-length mode, we just have to wait for enough data. */
		if (http_body_bytes(msg) < msg->body_len)
			goto missing_data;

		/* OK we have everything we need now */
		goto http_end;
	}

	/* OK here we're parsing a chunked-encoded message */

	if (msg->msg_state == HTTP_MSG_CHUNK_SIZE) {
		/* read the chunk size and assign it to ->chunk_len, then
		 * set ->sov and ->next to point to the body and switch to DATA or
		 * TRAILERS state.
		 */
		unsigned int chunk;
		int ret = h1_parse_chunk_size(req->buf, msg->next, req->buf->i, &chunk);

		if (!ret)
			goto missing_data;
		else if (ret < 0) {
			msg->err_pos = req->buf->i + ret;
			if (msg->err_pos < 0)
				msg->err_pos += req->buf->size;
			stream_inc_http_err_ctr(s);
			goto return_bad_req;
		}

		msg->chunk_len = chunk;
		msg->body_len += chunk;

		msg->sol = ret;
		msg->next += ret;
		msg->msg_state = msg->chunk_len ? HTTP_MSG_DATA : HTTP_MSG_TRAILERS;
	}

	/* Now we're in HTTP_MSG_DATA or HTTP_MSG_TRAILERS state.
	 * We have the first data byte is in msg->sov + msg->sol. We're waiting
	 * for at least a whole chunk or the whole content length bytes after
	 * msg->sov + msg->sol.
	 */
	if (msg->msg_state == HTTP_MSG_TRAILERS)
		goto http_end;

	if (http_body_bytes(msg) >= msg->body_len)   /* we have enough bytes now */
		goto http_end;

 missing_data:
	/* we get here if we need to wait for more data. If the buffer is full,
	 * we have the maximum we can expect.
	 */
	if (buffer_full(req->buf, global.tune.maxrewrite))
		goto http_end;

	if ((req->flags & CF_READ_TIMEOUT) || tick_is_expired(req->analyse_exp, now_ms)) {
		txn->status = 408;
		http_reply_and_close(s, txn->status, http_error_message(s));

		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_CLITO;
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_D;
		goto return_err_msg;
	}

	/* we get here if we need to wait for more data */
	if (!(req->flags & (CF_SHUTR | CF_READ_ERROR))) {
		/* Not enough data. We'll re-use the http-request
		 * timeout here. Ideally, we should set the timeout
		 * relative to the accept() date. We just set the
		 * request timeout once at the beginning of the
		 * request.
		 */
		channel_dont_connect(req);
		if (!tick_isset(req->analyse_exp))
			req->analyse_exp = tick_add_ifset(now_ms, s->be->timeout.httpreq);
		return 0;
	}

 http_end:
	/* The situation will not evolve, so let's give up on the analysis. */
	s->logs.tv_request = now;  /* update the request timer to reflect full request */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;

 return_bad_req: /* let's centralize all bad requests */
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

 return_err_msg:
	req->analysers &= AN_REQ_FLT_END;
	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);
	return 0;
}

/* send a server's name with an outgoing request over an established connection.
 * Note: this function is designed to be called once the request has been scheduled
 * for being forwarded. This is the reason why it rewinds the buffer before
 * proceeding.
 */
int http_send_name_header(struct http_txn *txn, struct proxy* be, const char* srv_name) {

	struct hdr_ctx ctx;

	char *hdr_name = be->server_id_hdr_name;
	int hdr_name_len = be->server_id_hdr_len;
	struct channel *chn = txn->req.chn;
	char *hdr_val;
	unsigned int old_o, old_i;

	ctx.idx = 0;

	old_o = http_hdr_rewind(&txn->req);
	if (old_o) {
		/* The request was already skipped, let's restore it */
		b_rew(chn->buf, old_o);
		txn->req.next += old_o;
		txn->req.sov += old_o;
	}

	old_i = chn->buf->i;
	while (http_find_header2(hdr_name, hdr_name_len, txn->req.chn->buf->p, &txn->hdr_idx, &ctx)) {
		/* remove any existing values from the header */
	        http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
	}

	/* Add the new header requested with the server value */
	hdr_val = trash.str;
	memcpy(hdr_val, hdr_name, hdr_name_len);
	hdr_val += hdr_name_len;
	*hdr_val++ = ':';
	*hdr_val++ = ' ';
	hdr_val += strlcpy2(hdr_val, srv_name, trash.str + trash.size - hdr_val);
	http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.str, hdr_val - trash.str);

	if (old_o) {
		/* If this was a forwarded request, we must readjust the amount of
		 * data to be forwarded in order to take into account the size
		 * variations. Note that the current state is >= HTTP_MSG_BODY,
		 * so we don't have to adjust ->sol.
		 */
		old_o += chn->buf->i - old_i;
		b_adv(chn->buf, old_o);
		txn->req.next -= old_o;
		txn->req.sov  -= old_o;
	}

	return 0;
}

/* Terminate current transaction and prepare a new one. This is very tricky
 * right now but it works.
 */
void http_end_txn_clean_session(struct stream *s)
{
	int prev_status = s->txn->status;
	struct proxy *fe = strm_fe(s);
	struct proxy *be = s->be;
	struct conn_stream *cs;
	struct connection *srv_conn;
	struct server *srv;
	unsigned int prev_flags = s->txn->flags;

	/* FIXME: We need a more portable way of releasing a backend's and a
	 * server's connections. We need a safer way to reinitialize buffer
	 * flags. We also need a more accurate method for computing per-request
	 * data.
	 */
	/*
	 * XXX cognet: This is probably wrong, this is killing a whole
	 * connection, in the new world order, we probably want to just kill
	 * the stream, this is to be revisited the day we handle multiple
	 * streams in one server connection.
	 */
	cs = objt_cs(s->si[1].end);
	srv_conn = cs_conn(cs);

	/* unless we're doing keep-alive, we want to quickly close the connection
	 * to the server.
	 */
	if (((s->txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) ||
	    !si_conn_ready(&s->si[1])) {
		s->si[1].flags |= SI_FL_NOLINGER | SI_FL_NOHALF;
		si_shutr(&s->si[1]);
		si_shutw(&s->si[1]);
	}

	if (s->flags & SF_BE_ASSIGNED) {
		HA_ATOMIC_SUB(&be->beconn, 1);
		if (unlikely(s->srv_conn))
			sess_change_server(s, NULL);
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	stream_process_counters(s);

	if (s->txn->status) {
		int n;

		n = s->txn->status / 100;
		if (n < 1 || n > 5)
			n = 0;

		if (fe->mode == PR_MODE_HTTP) {
			HA_ATOMIC_ADD(&fe->fe_counters.p.http.rsp[n], 1);
		}
		if ((s->flags & SF_BE_ASSIGNED) &&
		    (be->mode == PR_MODE_HTTP)) {
			HA_ATOMIC_ADD(&be->be_counters.p.http.rsp[n], 1);
			HA_ATOMIC_ADD(&be->be_counters.p.http.cum_req, 1);
		}
	}

	/* don't count other requests' data */
	s->logs.bytes_in  -= s->req.buf->i;
	s->logs.bytes_out -= s->res.buf->i;

	/* let's do a final log if we need it */
	if (!LIST_ISEMPTY(&fe->logformat) && s->logs.logwait &&
	    !(s->flags & SF_MONITOR) &&
	    (!(fe->options & PR_O_NULLNOLOG) || s->req.total)) {
		s->do_log(s);
	}

	/* stop tracking content-based counters */
	stream_stop_content_counters(s);
	stream_update_time_stats(s);

	s->logs.accept_date = date; /* user-visible date for logging */
	s->logs.tv_accept = now;  /* corrected date for internal use */
	s->logs.t_handshake = 0; /* There are no handshake in keep alive connection. */
	s->logs.t_idle = -1;
	tv_zero(&s->logs.tv_request);
	s->logs.t_queue = -1;
	s->logs.t_connect = -1;
	s->logs.t_data = -1;
	s->logs.t_close = 0;
	s->logs.prx_queue_size = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_size = 0; /* we will get this number soon */

	s->logs.bytes_in = s->req.total = s->req.buf->i;
	s->logs.bytes_out = s->res.total = s->res.buf->i;

	if (s->pend_pos)
		pendconn_free(s->pend_pos);

	if (objt_server(s->target)) {
		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			HA_ATOMIC_SUB(&objt_server(s->target)->cur_sess, 1);
		}
		if (may_dequeue_tasks(objt_server(s->target), be))
			process_srv_queue(objt_server(s->target));
	}

	s->target = NULL;

	/* only release our endpoint if we don't intend to reuse the
	 * connection.
	 */
	if (((s->txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) ||
	    !si_conn_ready(&s->si[1])) {
		si_release_endpoint(&s->si[1]);
		srv_conn = NULL;
	}

	s->si[1].state     = s->si[1].prev_state = SI_ST_INI;
	s->si[1].err_type  = SI_ET_NONE;
	s->si[1].conn_retries = 0;  /* used for logging too */
	s->si[1].exp       = TICK_ETERNITY;
	s->si[1].flags    &= SI_FL_ISBACK | SI_FL_DONT_WAKE; /* we're in the context of process_stream */
	s->req.flags &= ~(CF_SHUTW|CF_SHUTW_NOW|CF_AUTO_CONNECT|CF_WRITE_ERROR|CF_STREAMER|CF_STREAMER_FAST|CF_NEVER_WAIT|CF_WAKE_CONNECT|CF_WROTE_DATA);
	s->res.flags &= ~(CF_SHUTR|CF_SHUTR_NOW|CF_READ_ATTACHED|CF_READ_ERROR|CF_READ_NOEXP|CF_STREAMER|CF_STREAMER_FAST|CF_WRITE_PARTIAL|CF_NEVER_WAIT|CF_WROTE_DATA|CF_WRITE_EVENT);
	s->flags &= ~(SF_DIRECT|SF_ASSIGNED|SF_ADDR_SET|SF_BE_ASSIGNED|SF_FORCE_PRST|SF_IGNORE_PRST);
	s->flags &= ~(SF_CURR_SESS|SF_REDIRECTABLE|SF_SRV_REUSED);
	s->flags &= ~(SF_ERR_MASK|SF_FINST_MASK|SF_REDISP);

	s->txn->meth = 0;
	http_reset_txn(s);
	s->txn->flags |= TX_NOT_FIRST | TX_WAIT_NEXT_RQ;

	if (prev_status == 401 || prev_status == 407) {
		/* In HTTP keep-alive mode, if we receive a 401, we still have
		 * a chance of being able to send the visitor again to the same
		 * server over the same connection. This is required by some
		 * broken protocols such as NTLM, and anyway whenever there is
		 * an opportunity for sending the challenge to the proper place,
		 * it's better to do it (at least it helps with debugging).
		 */
		s->txn->flags |= TX_PREFER_LAST;
		if (srv_conn)
			srv_conn->flags |= CO_FL_PRIVATE;
	}

	/* Never ever allow to reuse a connection from a non-reuse backend */
	if (srv_conn && (be->options & PR_O_REUSE_MASK) == PR_O_REUSE_NEVR)
		srv_conn->flags |= CO_FL_PRIVATE;

	if (fe->options2 & PR_O2_INDEPSTR)
		s->si[1].flags |= SI_FL_INDEP_STR;

	if (fe->options2 & PR_O2_NODELAY) {
		s->req.flags |= CF_NEVER_WAIT;
		s->res.flags |= CF_NEVER_WAIT;
	}

	/* we're removing the analysers, we MUST re-enable events detection.
	 * We don't enable close on the response channel since it's either
	 * already closed, or in keep-alive with an idle connection handler.
	 */
	channel_auto_read(&s->req);
	channel_auto_close(&s->req);
	channel_auto_read(&s->res);

	/* we're in keep-alive with an idle connection, monitor it if not already done */
	if (srv_conn && LIST_ISEMPTY(&srv_conn->list)) {
		srv = objt_server(srv_conn->target);
		if (!srv)
			si_idle_cs(&s->si[1], NULL);
		else if (srv_conn->flags & CO_FL_PRIVATE)
			si_idle_cs(&s->si[1], (srv->priv_conns ? &srv->priv_conns[tid] : NULL));
		else if (prev_flags & TX_NOT_FIRST)
			/* note: we check the request, not the connection, but
			 * this is valid for strategies SAFE and AGGR, and in
			 * case of ALWS, we don't care anyway.
			 */
			si_idle_cs(&s->si[1], (srv->safe_conns ? &srv->safe_conns[tid] : NULL));
		else
			si_idle_cs(&s->si[1], (srv->idle_conns ? &srv->idle_conns[tid] : NULL));
	}
	s->req.analysers = strm_li(s) ? strm_li(s)->analysers : 0;
	s->res.analysers = 0;
}


/* This function updates the request state machine according to the response
 * state machine and buffer flags. It returns 1 if it changes anything (flag
 * or state), otherwise zero. It ignores any state before HTTP_MSG_DONE, as
 * it is only used to find when a request/response couple is complete. Both
 * this function and its equivalent should loop until both return zero. It
 * can set its own state to DONE, CLOSING, CLOSED, TUNNEL, ERROR.
 */
int http_sync_req_state(struct stream *s)
{
	struct channel *chn = &s->req;
	struct http_txn *txn = s->txn;
	unsigned int old_flags = chn->flags;
	unsigned int old_state = txn->req.msg_state;

	if (unlikely(txn->req.msg_state < HTTP_MSG_DONE))
		return 0;

	if (txn->req.msg_state == HTTP_MSG_DONE) {
		/* No need to read anymore, the request was completely parsed.
		 * We can shut the read side unless we want to abort_on_close,
		 * or we have a POST request. The issue with POST requests is
		 * that some browsers still send a CRLF after the request, and
		 * this CRLF must be read so that it does not remain in the kernel
		 * buffers, otherwise a close could cause an RST on some systems
		 * (eg: Linux).
		 * Note that if we're using keep-alive on the client side, we'd
		 * rather poll now and keep the polling enabled for the whole
		 * stream's life than enabling/disabling it between each
		 * response and next request.
		 */
		if (((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_SCL) &&
		    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) &&
		    (!(s->be->options & PR_O_ABRT_CLOSE) ||
		     (s->si[0].flags & SI_FL_CLEAN_ABRT)) &&
		    txn->meth != HTTP_METH_POST)
			channel_dont_read(chn);

		/* if the server closes the connection, we want to immediately react
		 * and close the socket to save packets and syscalls.
		 */
		s->si[1].flags |= SI_FL_NOHALF;

		/* In any case we've finished parsing the request so we must
		 * disable Nagle when sending data because 1) we're not going
		 * to shut this side, and 2) the server is waiting for us to
		 * send pending data.
		 */
		chn->flags |= CF_NEVER_WAIT;

		if (txn->rsp.msg_state == HTTP_MSG_ERROR)
			goto wait_other_side;

		if (txn->rsp.msg_state < HTTP_MSG_DONE) {
			/* The server has not finished to respond, so we
			 * don't want to move in order not to upset it.
			 */
			goto wait_other_side;
		}

		/* When we get here, it means that both the request and the
		 * response have finished receiving. Depending on the connection
		 * mode, we'll have to wait for the last bytes to leave in either
		 * direction, and sometimes for a close to be effective.
		 */

		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) {
			/* Server-close mode : queue a connection close to the server */
			if (!(chn->flags & (CF_SHUTW|CF_SHUTW_NOW)))
				channel_shutw_now(chn);
		}
		else if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_CLO) {
			/* Option forceclose is set, or either side wants to close,
			 * let's enforce it now that we're not expecting any new
			 * data to come. The caller knows the stream is complete
			 * once both states are CLOSED.
			 *
			 *  However, there is an exception if the response
			 *  length is undefined. In this case, we need to wait
			 *  the close from the server. The response will be
			 *  switched in TUNNEL mode until the end.
			 */
			if (!(txn->rsp.flags & HTTP_MSGF_XFER_LEN) &&
			    txn->rsp.msg_state != HTTP_MSG_CLOSED)
				goto check_channel_flags;

			if (!(chn->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
				channel_shutr_now(chn);
				channel_shutw_now(chn);
			}
		}
		else {
			/* The last possible modes are keep-alive and tunnel. Tunnel mode
			 * will not have any analyser so it needs to poll for reads.
			 */
			if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_TUN) {
				channel_auto_read(chn);
				txn->req.msg_state = HTTP_MSG_TUNNEL;
			}
		}

		goto check_channel_flags;
	}

	if (txn->req.msg_state == HTTP_MSG_CLOSING) {
	http_msg_closing:
		/* nothing else to forward, just waiting for the output buffer
		 * to be empty and for the shutw_now to take effect.
		 */
		if (channel_is_empty(chn)) {
			txn->req.msg_state = HTTP_MSG_CLOSED;
			goto http_msg_closed;
		}
		else if (chn->flags & CF_SHUTW) {
			txn->req.err_state = txn->req.msg_state;
			txn->req.msg_state = HTTP_MSG_ERROR;
		}
		goto wait_other_side;
	}

	if (txn->req.msg_state == HTTP_MSG_CLOSED) {
	http_msg_closed:
		/* if we don't know whether the server will close, we need to hard close */
		if (txn->rsp.flags & HTTP_MSGF_XFER_LEN)
			s->si[1].flags |= SI_FL_NOLINGER;  /* we want to close ASAP */

		/* see above in MSG_DONE why we only do this in these states */
		if (((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_SCL) &&
		    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) &&
		    (!(s->be->options & PR_O_ABRT_CLOSE) ||
		     (s->si[0].flags & SI_FL_CLEAN_ABRT)))
			channel_dont_read(chn);
		goto wait_other_side;
	}

 check_channel_flags:
	/* Here, we are in HTTP_MSG_DONE or HTTP_MSG_TUNNEL */
	if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
		/* if we've just closed an output, let's switch */
		txn->req.msg_state = HTTP_MSG_CLOSING;
		goto http_msg_closing;
	}


 wait_other_side:
	return txn->req.msg_state != old_state || chn->flags != old_flags;
}


/* This function updates the response state machine according to the request
 * state machine and buffer flags. It returns 1 if it changes anything (flag
 * or state), otherwise zero. It ignores any state before HTTP_MSG_DONE, as
 * it is only used to find when a request/response couple is complete. Both
 * this function and its equivalent should loop until both return zero. It
 * can set its own state to DONE, CLOSING, CLOSED, TUNNEL, ERROR.
 */
int http_sync_res_state(struct stream *s)
{
	struct channel *chn = &s->res;
	struct http_txn *txn = s->txn;
	unsigned int old_flags = chn->flags;
	unsigned int old_state = txn->rsp.msg_state;

	if (unlikely(txn->rsp.msg_state < HTTP_MSG_DONE))
		return 0;

	if (txn->rsp.msg_state == HTTP_MSG_DONE) {
		/* In theory, we don't need to read anymore, but we must
		 * still monitor the server connection for a possible close
		 * while the request is being uploaded, so we don't disable
		 * reading.
		 */
		/* channel_dont_read(chn); */

		if (txn->req.msg_state == HTTP_MSG_ERROR)
			goto wait_other_side;

		if (txn->req.msg_state < HTTP_MSG_DONE) {
			/* The client seems to still be sending data, probably
			 * because we got an error response during an upload.
			 * We have the choice of either breaking the connection
			 * or letting it pass through. Let's do the later.
			 */
			goto wait_other_side;
		}

		/* When we get here, it means that both the request and the
		 * response have finished receiving. Depending on the connection
		 * mode, we'll have to wait for the last bytes to leave in either
		 * direction, and sometimes for a close to be effective.
		 */

		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) {
			/* Server-close mode : shut read and wait for the request
			 * side to close its output buffer. The caller will detect
			 * when we're in DONE and the other is in CLOSED and will
			 * catch that for the final cleanup.
			 */
			if (!(chn->flags & (CF_SHUTR|CF_SHUTR_NOW)))
				channel_shutr_now(chn);
		}
		else if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_CLO) {
			/* Option forceclose is set, or either side wants to close,
			 * let's enforce it now that we're not expecting any new
			 * data to come. The caller knows the stream is complete
			 * once both states are CLOSED.
			 *
			 * However, there is an exception if the response length
			 * is undefined. In this case, we switch in TUNNEL mode.
			 */
			if (!(txn->rsp.flags & HTTP_MSGF_XFER_LEN)) {
				channel_auto_read(chn);
				txn->rsp.msg_state = HTTP_MSG_TUNNEL;
				chn->flags |= CF_NEVER_WAIT;
			}
			else if (!(chn->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
				channel_shutr_now(chn);
				channel_shutw_now(chn);
			}
		}
		else {
			/* The last possible modes are keep-alive and tunnel. Tunnel will
			 * need to forward remaining data. Keep-alive will need to monitor
			 * for connection closing.
			 */
			channel_auto_read(chn);
			chn->flags |= CF_NEVER_WAIT;
			if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_TUN)
				txn->rsp.msg_state = HTTP_MSG_TUNNEL;
		}

		goto check_channel_flags;
	}

	if (txn->rsp.msg_state == HTTP_MSG_CLOSING) {
	http_msg_closing:
		/* nothing else to forward, just waiting for the output buffer
		 * to be empty and for the shutw_now to take effect.
		 */
		if (channel_is_empty(chn)) {
			txn->rsp.msg_state = HTTP_MSG_CLOSED;
			goto http_msg_closed;
		}
		else if (chn->flags & CF_SHUTW) {
			txn->rsp.err_state = txn->rsp.msg_state;
			txn->rsp.msg_state = HTTP_MSG_ERROR;
			HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);
		}
		goto wait_other_side;
	}

	if (txn->rsp.msg_state == HTTP_MSG_CLOSED) {
	http_msg_closed:
		/* drop any pending data */
		channel_truncate(chn);
		channel_auto_close(chn);
		channel_auto_read(chn);
		goto wait_other_side;
	}

 check_channel_flags:
	/* Here, we are in HTTP_MSG_DONE or HTTP_MSG_TUNNEL */
	if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
		/* if we've just closed an output, let's switch */
		txn->rsp.msg_state = HTTP_MSG_CLOSING;
		goto http_msg_closing;
	}

 wait_other_side:
	/* We force the response to leave immediately if we're waiting for the
	 * other side, since there is no pending shutdown to push it out.
	 */
	if (!channel_is_empty(chn))
		chn->flags |= CF_SEND_DONTWAIT;
	return txn->rsp.msg_state != old_state || chn->flags != old_flags;
}


/* Resync the request and response state machines. */
void http_resync_states(struct stream *s)
{
	struct http_txn *txn = s->txn;
#ifdef DEBUG_FULL
	int old_req_state = txn->req.msg_state;
	int old_res_state = txn->rsp.msg_state;
#endif

	http_sync_req_state(s);
	while (1) {
		if (!http_sync_res_state(s))
			break;
		if (!http_sync_req_state(s))
			break;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p old=%s,%s cur=%s,%s "
		"req->analysers=0x%08x res->analysers=0x%08x\n",
		now_ms, __FUNCTION__, s,
		h1_msg_state_str(old_req_state), h1_msg_state_str(old_res_state),
		h1_msg_state_str(txn->req.msg_state), h1_msg_state_str(txn->rsp.msg_state),
		s->req.analysers, s->res.analysers);


	/* OK, both state machines agree on a compatible state.
	 * There are a few cases we're interested in :
	 *  - HTTP_MSG_CLOSED on both sides means we've reached the end in both
	 *    directions, so let's simply disable both analysers.
	 *  - HTTP_MSG_CLOSED on the response only or HTTP_MSG_ERROR on either
	 *    means we must abort the request.
	 *  - HTTP_MSG_TUNNEL on either means we have to disable analyser on
	 *    corresponding channel.
	 *  - HTTP_MSG_DONE or HTTP_MSG_CLOSED on the request and HTTP_MSG_DONE
	 *    on the response with server-close mode means we've completed one
	 *    request and we must re-initialize the server connection.
	 */
	if (txn->req.msg_state == HTTP_MSG_CLOSED &&
	    txn->rsp.msg_state == HTTP_MSG_CLOSED) {
		s->req.analysers &= AN_REQ_FLT_END;
		channel_auto_close(&s->req);
		channel_auto_read(&s->req);
		s->res.analysers &= AN_RES_FLT_END;
		channel_auto_close(&s->res);
		channel_auto_read(&s->res);
	}
	else if (txn->rsp.msg_state == HTTP_MSG_CLOSED ||
		 txn->rsp.msg_state == HTTP_MSG_ERROR  ||
		 txn->req.msg_state == HTTP_MSG_ERROR) {
		s->res.analysers &= AN_RES_FLT_END;
		channel_auto_close(&s->res);
		channel_auto_read(&s->res);
		s->req.analysers &= AN_REQ_FLT_END;
		channel_abort(&s->req);
		channel_auto_close(&s->req);
		channel_auto_read(&s->req);
		channel_truncate(&s->req);
	}
	else if (txn->req.msg_state == HTTP_MSG_TUNNEL ||
		 txn->rsp.msg_state == HTTP_MSG_TUNNEL) {
		if (txn->req.msg_state == HTTP_MSG_TUNNEL) {
			s->req.analysers &= AN_REQ_FLT_END;
			if (HAS_REQ_DATA_FILTERS(s))
				s->req.analysers |= AN_REQ_FLT_XFER_DATA;
		}
		if (txn->rsp.msg_state == HTTP_MSG_TUNNEL) {
			s->res.analysers &= AN_RES_FLT_END;
			if (HAS_RSP_DATA_FILTERS(s))
				s->res.analysers |= AN_RES_FLT_XFER_DATA;
		}
		channel_auto_close(&s->req);
		channel_auto_read(&s->req);
		channel_auto_close(&s->res);
		channel_auto_read(&s->res);
	}
	else if ((txn->req.msg_state == HTTP_MSG_DONE ||
		  txn->req.msg_state == HTTP_MSG_CLOSED) &&
		 txn->rsp.msg_state == HTTP_MSG_DONE &&
		 ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL ||
		  (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL)) {
		/* server-close/keep-alive: terminate this transaction,
		 * possibly killing the server connection and reinitialize
		 * a fresh-new transaction, but only once we're sure there's
		 * enough room in the request and response buffer to process
		 * another request. They must not hold any pending output data
		 * and the response buffer must realigned
		 * (realign is done is http_end_txn_clean_session).
		 */
		if (s->req.buf->o)
			s->req.flags |= CF_WAKE_WRITE;
		else if (s->res.buf->o)
			s->res.flags |= CF_WAKE_WRITE;
		else {
			s->req.analysers = AN_REQ_FLT_END;
			s->res.analysers = AN_RES_FLT_END;
			txn->flags |= TX_WAIT_CLEANUP;
		}
	}
}

/* This function is an analyser which forwards request body (including chunk
 * sizes if any). It is called as soon as we must forward, even if we forward
 * zero byte. The only situation where it must not be called is when we're in
 * tunnel mode and we want to forward till the close. It's used both to forward
 * remaining data and to resync after end of body. It expects the msg_state to
 * be between MSG_BODY and MSG_DONE (inclusive). It returns zero if it needs to
 * read more data, or 1 once we can go on with next request or end the stream.
 * When in MSG_DATA or MSG_TRAILERS, it will automatically forward chunk_len
 * bytes of pending data + the headers if not already done.
 */
int http_request_forward_body(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->req;
	int ret;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))
		return 0;

	if ((req->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((req->flags & CF_SHUTW) && (req->to_forward || req->buf->o))) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 */
		msg->err_state = msg->msg_state;
		msg->msg_state = HTTP_MSG_ERROR;
		http_resync_states(s);
		return 1;
	}

	/* Note that we don't have to send 100-continue back because we don't
	 * need the data to complete our job, and it's up to the server to
	 * decide whether to return 100, 417 or anything else in return of
	 * an "Expect: 100-continue" header.
	 */
	if (msg->msg_state == HTTP_MSG_BODY) {
		msg->msg_state = ((msg->flags & HTTP_MSGF_TE_CHNK)
				  ? HTTP_MSG_CHUNK_SIZE
				  : HTTP_MSG_DATA);

		/* TODO/filters: when http-buffer-request option is set or if a
		 * rule on url_param exists, the first chunk size could be
		 * already parsed. In that case, msg->next is after the chunk
		 * size (including the CRLF after the size). So this case should
		 * be handled to */
	}

	/* Some post-connect processing might want us to refrain from starting to
	 * forward data. Currently, the only reason for this is "balance url_param"
	 * whichs need to parse/process the request after we've enabled forwarding.
	 */
	if (unlikely(msg->flags & HTTP_MSGF_WAIT_CONN)) {
		if (!(s->res.flags & CF_READ_ATTACHED)) {
			channel_auto_connect(req);
			req->flags |= CF_WAKE_CONNECT;
			goto missing_data_or_waiting;
		}
		msg->flags &= ~HTTP_MSGF_WAIT_CONN;
	}

	/* in most states, we should abort in case of early close */
	channel_auto_close(req);

	if (req->to_forward) {
		/* We can't process the buffer's contents yet */
		req->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	if (msg->msg_state < HTTP_MSG_DONE) {
		ret = ((msg->flags & HTTP_MSGF_TE_CHNK)
		       ? http_msg_forward_chunked_body(s, msg)
		       : http_msg_forward_body(s, msg));
		if (!ret)
			goto missing_data_or_waiting;
		if (ret < 0)
			goto return_bad_req;
	}

	/* other states, DONE...TUNNEL */
	/* we don't want to forward closes on DONE except in tunnel mode. */
	if ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN)
		channel_dont_close(req);

	http_resync_states(s);
	if (!(req->analysers & an_bit)) {
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (req->flags & CF_SHUTW) {
				/* request errors are most likely due to the
				 * server aborting the transfer. */
				goto aborted_xfer;
			}
			if (msg->err_pos >= 0)
				http_capture_bad_message(sess->fe, &sess->fe->invalid_req, s, msg, msg->err_state, s->be);
			goto return_bad_req;
		}
		return 1;
	}

	/* If "option abortonclose" is set on the backend, we want to monitor
	 * the client's connection and forward any shutdown notification to the
	 * server, which will decide whether to close or to go on processing the
	 * request. We only do that in tunnel mode, and not in other modes since
	 * it can be abused to exhaust source ports. */
	if ((s->be->options & PR_O_ABRT_CLOSE) && !(s->si[0].flags & SI_FL_CLEAN_ABRT)) {
		channel_auto_read(req);
		if ((req->flags & (CF_SHUTR|CF_READ_NULL)) &&
		    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN))
			s->si[1].flags |= SI_FL_NOLINGER;
		channel_auto_close(req);
	}
	else if (s->txn->meth == HTTP_METH_POST) {
		/* POST requests may require to read extra CRLF sent by broken
		 * browsers and which could cause an RST to be sent upon close
		 * on some systems (eg: Linux). */
		channel_auto_read(req);
	}
	return 0;

 missing_data_or_waiting:
	/* stop waiting for data if the input is closed before the end */
	if (msg->msg_state < HTTP_MSG_ENDING && req->flags & CF_SHUTR) {
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_CLICL;
		if (!(s->flags & SF_FINST_MASK)) {
			if (txn->rsp.msg_state < HTTP_MSG_ERROR)
				s->flags |= SF_FINST_H;
			else
				s->flags |= SF_FINST_D;
		}

		HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
		HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

		goto return_bad_req_stats_ok;
	}

	/* waiting for the last bits to leave the buffer */
	if (req->flags & CF_SHUTW)
		goto aborted_xfer;

	/* When TE: chunked is used, we need to get there again to parse remaining
	 * chunks even if the client has closed, so we don't want to set CF_DONTCLOSE.
	 * And when content-length is used, we never want to let the possible
	 * shutdown be forwarded to the other side, as the state machine will
	 * take care of it once the client responds. It's also important to
	 * prevent TIME_WAITs from accumulating on the backend side, and for
	 * HTTP/2 where the last frame comes with a shutdown.
	 */
	if (msg->flags & (HTTP_MSGF_TE_CHNK|HTTP_MSGF_CNT_LEN))
		channel_dont_close(req);

	/* We know that more data are expected, but we couldn't send more that
	 * what we did. So we always set the CF_EXPECT_MORE flag so that the
	 * system knows it must not set a PUSH on this first part. Interactive
	 * modes are already handled by the stream sock layer. We must not do
	 * this in content-length mode because it could present the MSG_MORE
	 * flag with the last block of forwarded data, which would cause an
	 * additional delay to be observed by the receiver.
	 */
	if (msg->flags & HTTP_MSGF_TE_CHNK)
		req->flags |= CF_EXPECT_MORE;

	return 0;

 return_bad_req: /* let's centralize all bad requests */
	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_bad_req_stats_ok:
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	if (txn->status) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = 400;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	req->analysers   &= AN_REQ_FLT_END;
	s->res.analysers &= AN_RES_FLT_END; /* we're in data phase, we want to abort both directions */

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK)) {
		if (txn->rsp.msg_state < HTTP_MSG_ERROR)
			s->flags |= SF_FINST_H;
		else
			s->flags |= SF_FINST_D;
	}
	return 0;

 aborted_xfer:
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	if (txn->status) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = 502;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	req->analysers   &= AN_REQ_FLT_END;
	s->res.analysers &= AN_RES_FLT_END; /* we're in data phase, we want to abort both directions */

	HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
	HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	if (!(s->flags & SF_FINST_MASK)) {
		if (txn->rsp.msg_state < HTTP_MSG_ERROR)
			s->flags |= SF_FINST_H;
		else
			s->flags |= SF_FINST_D;
	}
	return 0;
}

/* This stream analyser waits for a complete HTTP response. It returns 1 if the
 * processing can continue on next analysers, or zero if it either needs more
 * data or wants to immediately abort the response (eg: timeout, error, ...). It
 * is tied to AN_RES_WAIT_HTTP and may may remove itself from s->res.analysers
 * when it has nothing left to do, and may remove any analyser when it wants to
 * abort.
 */
int http_wait_for_response(struct stream *s, struct channel *rep, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct hdr_ctx ctx;
	int use_close_only;
	int cur_idx;
	int n;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		rep->buf->i,
		rep->analysers);

	/*
	 * Now parse the partial (or complete) lines.
	 * We will check the response syntax, and also join multi-line
	 * headers. An index of all the lines will be elaborated while
	 * parsing.
	 *
	 * For the parsing, we use a 28 states FSM.
	 *
	 * Here is the information we currently have :
	 *   rep->buf->p             = beginning of response
	 *   rep->buf->p + msg->eoh  = end of processed headers / start of current one
	 *   rep->buf->p + rep->buf->i    = end of input data
	 *   msg->eol           = end of current header or line (LF or CRLF)
	 *   msg->next          = first non-visited byte
	 */

 next_one:
	/* There's a protected area at the end of the buffer for rewriting
	 * purposes. We don't want to start to parse the request if the
	 * protected area is affected, because we may have to move processed
	 * data later, which is much more complicated.
	 */
	if (buffer_not_empty(rep->buf) && msg->msg_state < HTTP_MSG_ERROR) {
		if (unlikely(!channel_is_rewritable(rep))) {
			/* some data has still not left the buffer, wake us once that's done */
			if (rep->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_WRITE_ERROR|CF_WRITE_TIMEOUT))
				goto abort_response;
			channel_dont_close(rep);
			rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
			rep->flags |= CF_WAKE_WRITE;
			return 0;
		}

		if (unlikely(bi_end(rep->buf) < b_ptr(rep->buf, msg->next) ||
		             bi_end(rep->buf) > rep->buf->data + rep->buf->size - global.tune.maxrewrite))
			buffer_slow_realign(rep->buf);

		if (likely(msg->next < rep->buf->i))
			http_msg_analyzer(msg, &txn->hdr_idx);
	}

	/* 1: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
		     msg->msg_state >= HTTP_MSG_BODY)) {
		char *eol, *sol;

		sol = rep->buf->p;
		eol = sol + (msg->sl.st.l ? msg->sl.st.l : rep->buf->i);
		debug_hdr("srvrep", s, sol, eol);

		sol += hdr_idx_first_pos(&txn->hdr_idx);
		cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

		while (cur_idx) {
			eol = sol + txn->hdr_idx.v[cur_idx].len;
			debug_hdr("srvhdr", s, sol, eol);
			sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
			cur_idx = txn->hdr_idx.v[cur_idx].next;
		}
	}

	/*
	 * Now we quickly check if we have found a full valid response.
	 * If not so, we check the FD and buffer states before leaving.
	 * A full response is indicated by the fact that we have seen
	 * the double LF/CRLF, so the state is >= HTTP_MSG_BODY. Invalid
	 * responses are checked first.
	 *
	 * Depending on whether the client is still there or not, we
	 * may send an error response back or not. Note that normally
	 * we should only check for HTTP status there, and check I/O
	 * errors somewhere else.
	 */

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* Invalid response */
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			/* we detected a parsing error. We want to archive this response
			 * in the dedicated proxy area for later troubleshooting.
			 */
		hdr_response_bad:
			if (msg->msg_state == HTTP_MSG_ERROR || msg->err_pos >= 0)
				http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg, msg->err_state, sess->fe);

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_HDRRSP);
			}
		abort_response:
			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_PRXCOND;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			return 0;
		}

		/* too large response does not fit in buffer. */
		else if (buffer_full(rep->buf, global.tune.maxrewrite)) {
			if (msg->err_pos < 0)
				msg->err_pos = rep->buf->i;
			goto hdr_response_bad;
		}

		/* read error */
		else if (rep->flags & CF_READ_ERROR) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_READ_ERROR);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;

			/* Check to see if the server refused the early data.
			 * If so, just send a 425
			 */
			if (objt_cs(s->si[1].end)) {
				struct connection *conn = objt_cs(s->si[1].end)->conn;

				if (conn->err_code == CO_ER_SSL_EARLY_FAILED)
					txn->status = 425;
			}

			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* read timeout : return a 504 to the client. */
		else if (rep->flags & CF_READ_TIMEOUT) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg, msg->err_state, sess->fe);

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_READ_TIMEOUT);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 504;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVTO;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* client abort with an abortonclose */
		else if ((rep->flags & CF_SHUTR) && ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))) {
			HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
			HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

			rep->analysers &= AN_RES_FLT_END;
			channel_auto_close(rep);

			txn->status = 400;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			return 0;
		}

		/* close from server, capture the response if the server has started to respond */
		else if (rep->flags & CF_SHUTR) {
			if (msg->msg_state >= HTTP_MSG_RPVER || msg->err_pos >= 0)
				http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_BROKEN_PIPE);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* write error to client (we don't send any message then) */
		else if (rep->flags & CF_WRITE_ERROR) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			rep->analysers &= AN_RES_FLT_END;
			channel_auto_close(rep);

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			return 0;
		}

		channel_dont_close(rep);
		rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		return 0;
	}

	/* More interesting part now : we know that we have a complete
	 * response which at least looks like HTTP. We have an indicator
	 * of each header's length, so we can parse them quickly.
	 */

	if (unlikely(msg->err_pos >= 0))
		http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg, msg->err_state, sess->fe);

	/*
	 * 1: get the status code
	 */
	n = rep->buf->p[msg->sl.st.c] - '0';
	if (n < 1 || n > 5)
		n = 0;
	/* when the client triggers a 4xx from the server, it's most often due
	 * to a missing object or permission. These events should be tracked
	 * because if they happen often, it may indicate a brute force or a
	 * vulnerability scan.
	 */
	if (n == 4)
		stream_inc_http_err_ctr(s);

	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.p.http.rsp[n], 1);

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-response.
	 */
	if (!(s->be->options2 & PR_O2_RSPBUG_OK)) {
		if (msg->sl.st.v_l != 8) {
			msg->err_pos = 0;
			goto hdr_response_bad;
		}

		if (rep->buf->p[4] != '/' ||
		    !isdigit((unsigned char)rep->buf->p[5]) ||
		    rep->buf->p[6] != '.' ||
		    !isdigit((unsigned char)rep->buf->p[7])) {
			msg->err_pos = 4;
			goto hdr_response_bad;
		}
	}

	/* check if the response is HTTP/1.1 or above */
	if ((msg->sl.st.v_l == 8) &&
	    ((rep->buf->p[5] > '1') ||
	     ((rep->buf->p[5] == '1') && (rep->buf->p[7] >= '1'))))
		msg->flags |= HTTP_MSGF_VER_11;

	/* "connection" has not been parsed yet */
	txn->flags &= ~(TX_HDR_CONN_PRS|TX_HDR_CONN_CLO|TX_HDR_CONN_KAL|TX_HDR_CONN_UPG|TX_CON_CLO_SET|TX_CON_KAL_SET);

	/* transfer length unknown*/
	msg->flags &= ~HTTP_MSGF_XFER_LEN;

	txn->status = strl2ui(rep->buf->p + msg->sl.st.c, msg->sl.st.c_l);

	/* Adjust server's health based on status code. Note: status codes 501
	 * and 505 are triggered on demand by client request, so we must not
	 * count them as server failures.
	 */
	if (objt_server(s->target)) {
		if (txn->status >= 100 && (txn->status < 500 || txn->status == 501 || txn->status == 505))
			health_adjust(objt_server(s->target), HANA_STATUS_HTTP_OK);
		else
			health_adjust(objt_server(s->target), HANA_STATUS_HTTP_STS);
	}

	/*
	 * We may be facing a 100-continue response, or any other informational
	 * 1xx response which is non-final, in which case this is not the right
	 * response, and we're waiting for the next one. Let's allow this response
	 * to go to the client and wait for the next one. There's an exception for
	 * 101 which is used later in the code to switch protocols.
	 */
	if (txn->status < 200 &&
	    (txn->status == 100 || txn->status >= 102)) {
		hdr_idx_init(&txn->hdr_idx);
		msg->next -= channel_forward(rep, msg->next);
		msg->msg_state = HTTP_MSG_RPBEFORE;
		txn->status = 0;
		s->logs.t_data = -1; /* was not a response yet */
		FLT_STRM_CB(s, flt_http_reset(s, msg));
		goto next_one;
	}

	/*
	 * 2: check for cacheability.
	 */

	switch (txn->status) {
	case 200:
	case 203:
	case 204:
	case 206:
	case 300:
	case 301:
	case 404:
	case 405:
	case 410:
	case 414:
	case 501:
		break;
	default:
		/* RFC7231#6.1:
		 *   Responses with status codes that are defined as
		 *   cacheable by default (e.g., 200, 203, 204, 206,
		 *   300, 301, 404, 405, 410, 414, and 501 in this
		 *   specification) can be reused by a cache with
		 *   heuristic expiration unless otherwise indicated
		 *   by the method definition or explicit cache
		 *   controls [RFC7234]; all other status codes are
		 *   not cacheable by default.
		 */
		txn->flags &= ~(TX_CACHEABLE | TX_CACHE_COOK);
		break;
	}

	/*
	 * 3: we may need to capture headers
	 */
	s->logs.logwait &= ~LW_RESP;
	if (unlikely((s->logs.logwait & LW_RSPHDR) && s->res_cap))
		capture_headers(rep->buf->p, &txn->hdr_idx,
				s->res_cap, sess->fe->rsp_cap);

	/* 4: determine the transfer-length according to RFC2616 #4.4, updated
	 * by RFC7230#3.3.3 :
	 *
	 * The length of a message body is determined by one of the following
	 *   (in order of precedence):
	 *
	 *   1.  Any 2xx (Successful) response to a CONNECT request implies that
	 *       the connection will become a tunnel immediately after the empty
	 *       line that concludes the header fields.  A client MUST ignore
	 *       any Content-Length or Transfer-Encoding header fields received
	 *       in such a message. Any 101 response (Switching Protocols) is
	 *       managed in the same manner.
	 *
	 *   2.  Any response to a HEAD request and any response with a 1xx
	 *       (Informational), 204 (No Content), or 304 (Not Modified) status
	 *       code is always terminated by the first empty line after the
	 *       header fields, regardless of the header fields present in the
	 *       message, and thus cannot contain a message body.
	 *
	 *   3.  If a Transfer-Encoding header field is present and the chunked
	 *       transfer coding (Section 4.1) is the final encoding, the message
	 *       body length is determined by reading and decoding the chunked
	 *       data until the transfer coding indicates the data is complete.
	 *
	 *       If a Transfer-Encoding header field is present in a response and
	 *       the chunked transfer coding is not the final encoding, the
	 *       message body length is determined by reading the connection until
	 *       it is closed by the server.  If a Transfer-Encoding header field
	 *       is present in a request and the chunked transfer coding is not
	 *       the final encoding, the message body length cannot be determined
	 *       reliably; the server MUST respond with the 400 (Bad Request)
	 *       status code and then close the connection.
	 *
	 *       If a message is received with both a Transfer-Encoding and a
	 *       Content-Length header field, the Transfer-Encoding overrides the
	 *       Content-Length.  Such a message might indicate an attempt to
	 *       perform request smuggling (Section 9.5) or response splitting
	 *       (Section 9.4) and ought to be handled as an error.  A sender MUST
	 *       remove the received Content-Length field prior to forwarding such
	 *       a message downstream.
	 *
	 *   4.  If a message is received without Transfer-Encoding and with
	 *       either multiple Content-Length header fields having differing
	 *       field-values or a single Content-Length header field having an
	 *       invalid value, then the message framing is invalid and the
	 *       recipient MUST treat it as an unrecoverable error.  If this is a
	 *       request message, the server MUST respond with a 400 (Bad Request)
	 *       status code and then close the connection.  If this is a response
	 *       message received by a proxy, the proxy MUST close the connection
	 *       to the server, discard the received response, and send a 502 (Bad
	 *       Gateway) response to the client.  If this is a response message
	 *       received by a user agent, the user agent MUST close the
	 *       connection to the server and discard the received response.
	 *
	 *   5.  If a valid Content-Length header field is present without
	 *       Transfer-Encoding, its decimal value defines the expected message
	 *       body length in octets.  If the sender closes the connection or
	 *       the recipient times out before the indicated number of octets are
	 *       received, the recipient MUST consider the message to be
	 *       incomplete and close the connection.
	 *
	 *   6.  If this is a request message and none of the above are true, then
	 *       the message body length is zero (no message body is present).
	 *
	 *   7.  Otherwise, this is a response message without a declared message
	 *       body length, so the message body length is determined by the
	 *       number of octets received prior to the server closing the
	 *       connection.
	 */

	/* Skip parsing if no content length is possible. The response flags
	 * remain 0 as well as the chunk_len, which may or may not mirror
	 * the real header value, and we note that we know the response's length.
	 * FIXME: should we parse anyway and return an error on chunked encoding ?
	 */
	if (unlikely((txn->meth == HTTP_METH_CONNECT && txn->status == 200) ||
		     txn->status == 101)) {
		/* Either we've established an explicit tunnel, or we're
		 * switching the protocol. In both cases, we're very unlikely
		 * to understand the next protocols. We have to switch to tunnel
		 * mode, so that we transfer the request and responses then let
		 * this protocol pass unmodified. When we later implement specific
		 * parsers for such protocols, we'll want to check the Upgrade
		 * header which contains information about that protocol for
		 * responses with status 101 (eg: see RFC2817 about TLS).
		 */
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_TUN;
		msg->flags |= HTTP_MSGF_XFER_LEN;
		goto end;
	}

	if (txn->meth == HTTP_METH_HEAD ||
	    (txn->status >= 100 && txn->status < 200) ||
	    txn->status == 204 || txn->status == 304) {
		msg->flags |= HTTP_MSGF_XFER_LEN;
		goto skip_content_length;
	}

	use_close_only = 0;
	ctx.idx = 0;
	while (http_find_header2("Transfer-Encoding", 17, rep->buf->p, &txn->hdr_idx, &ctx)) {
		if (ctx.vlen == 7 && strncasecmp(ctx.line + ctx.val, "chunked", 7) == 0)
			msg->flags |= (HTTP_MSGF_TE_CHNK | HTTP_MSGF_XFER_LEN);
		else if (msg->flags & HTTP_MSGF_TE_CHNK) {
			/* bad transfer-encoding (chunked followed by something else) */
			use_close_only = 1;
			msg->flags &= ~(HTTP_MSGF_TE_CHNK | HTTP_MSGF_XFER_LEN);
			break;
		}
	}

	/* Chunked responses must have their content-length removed */
	ctx.idx = 0;
	if (use_close_only || (msg->flags & HTTP_MSGF_TE_CHNK)) {
		while (http_find_header2("Content-Length", 14, rep->buf->p, &txn->hdr_idx, &ctx))
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
	}
	else while (http_find_header2("Content-Length", 14, rep->buf->p, &txn->hdr_idx, &ctx)) {
		signed long long cl;

		if (!ctx.vlen) {
			msg->err_pos = ctx.line + ctx.val - rep->buf->p;
			goto hdr_response_bad;
		}

		if (strl2llrc(ctx.line + ctx.val, ctx.vlen, &cl)) {
			msg->err_pos = ctx.line + ctx.val - rep->buf->p;
			goto hdr_response_bad; /* parse failure */
		}

		if (cl < 0) {
			msg->err_pos = ctx.line + ctx.val - rep->buf->p;
			goto hdr_response_bad;
		}

		if ((msg->flags & HTTP_MSGF_CNT_LEN) && (msg->chunk_len != cl)) {
			msg->err_pos = ctx.line + ctx.val - rep->buf->p;
			goto hdr_response_bad; /* already specified, was different */
		}

		msg->flags |= HTTP_MSGF_CNT_LEN | HTTP_MSGF_XFER_LEN;
		msg->body_len = msg->chunk_len = cl;
	}

 skip_content_length:
	/* Now we have to check if we need to modify the Connection header.
	 * This is more difficult on the response than it is on the request,
	 * because we can have two different HTTP versions and we don't know
	 * how the client will interprete a response. For instance, let's say
	 * that the client sends a keep-alive request in HTTP/1.0 and gets an
	 * HTTP/1.1 response without any header. Maybe it will bound itself to
	 * HTTP/1.0 because it only knows about it, and will consider the lack
	 * of header as a close, or maybe it knows HTTP/1.1 and can consider
	 * the lack of header as a keep-alive. Thus we will use two flags
	 * indicating how a request MAY be understood by the client. In case
	 * of multiple possibilities, we'll fix the header to be explicit. If
	 * ambiguous cases such as both close and keepalive are seen, then we
	 * will fall back to explicit close. Note that we won't take risks with
	 * HTTP/1.0 clients which may not necessarily understand keep-alive.
	 * See doc/internals/connection-header.txt for the complete matrix.
	 */
	if ((txn->status >= 200) && !(txn->flags & TX_HDR_CONN_PRS) &&
	    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN ||
	     ((sess->fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL ||
	      (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL))) {
		int to_del = 0;

		/* this situation happens when combining pretend-keepalive with httpclose. */
		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL &&
		    ((sess->fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL ||
		     (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL))
			txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_CLO;

		/* on unknown transfer length, we must close */
		if (!(msg->flags & HTTP_MSGF_XFER_LEN) &&
		    (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN)
			txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_CLO;

		/* now adjust header transformations depending on current state */
		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_TUN ||
		    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_CLO) {
			to_del |= 2; /* remove "keep-alive" on any response */
			if (!(msg->flags & HTTP_MSGF_VER_11))
				to_del |= 1; /* remove "close" for HTTP/1.0 responses */
		}
		else { /* SCL / KAL */
			to_del |= 1; /* remove "close" on any response */
			if (txn->req.flags & msg->flags & HTTP_MSGF_VER_11)
				to_del |= 2; /* remove "keep-alive" on pure 1.1 responses */
		}

		/* Parse and remove some headers from the connection header */
		http_parse_connection_header(txn, msg, to_del);

		/* Some keep-alive responses are converted to Server-close if
		 * the server wants to close.
		 */
		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL) {
			if ((txn->flags & TX_HDR_CONN_CLO) ||
			    (!(txn->flags & TX_HDR_CONN_KAL) && !(msg->flags & HTTP_MSGF_VER_11)))
				txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_SCL;
		}
	}

 end:
	/* we want to have the response time before we start processing it */
	s->logs.t_data = tv_ms_elapsed(&s->logs.tv_accept, &now);

	/* end of job, return OK */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	channel_auto_close(rep);
	return 1;

 abort_keep_alive:
	/* A keep-alive request to the server failed on a network error.
	 * The client is required to retry. We need to close without returning
	 * any other information so that the client retries.
	 */
	txn->status = 0;
	rep->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END;
	channel_auto_close(rep);
	s->logs.logwait = 0;
	s->logs.level = 0;
	s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
	channel_truncate(rep);
	http_reply_and_close(s, txn->status, NULL);
	return 0;
}

/* This function performs all the processing enabled for the current response.
 * It normally returns 1 unless it wants to break. It relies on buffers flags,
 * and updates s->res.analysers. It might make sense to explode it into several
 * other functions. It works like process_request (see indications above).
 */
int http_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct proxy *cur_proxy;
	struct cond_wordlist *wl;
	enum rule_result ret = HTTP_RULE_RES_CONT;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		rep->buf->i,
		rep->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))	/* we need more data */
		return 0;

	/* The stats applet needs to adjust the Connection header but we don't
	 * apply any filter there.
	 */
	if (unlikely(objt_applet(s->target) == &http_stats_applet)) {
		rep->analysers &= ~an_bit;
		rep->analyse_exp = TICK_ETERNITY;
		goto skip_filters;
	}

	/*
	 * We will have to evaluate the filters.
	 * As opposed to version 1.2, now they will be evaluated in the
	 * filters order and not in the header order. This means that
	 * each filter has to be validated among all headers.
	 *
	 * Filters are tried with ->be first, then with ->fe if it is
	 * different from ->be.
	 *
	 * Maybe we are in resume condiion. In this case I choose the
	 * "struct proxy" which contains the rule list matching the resume
	 * pointer. If none of theses "struct proxy" match, I initialise
	 * the process with the first one.
	 *
	 * In fact, I check only correspondance betwwen the current list
	 * pointer and the ->fe rule list. If it doesn't match, I initialize
	 * the loop with the ->be.
	 */
	if (s->current_rule_list == &sess->fe->http_res_rules)
		cur_proxy = sess->fe;
	else
		cur_proxy = s->be;
	while (1) {
		struct proxy *rule_set = cur_proxy;

		/* evaluate http-response rules */
		if (ret == HTTP_RULE_RES_CONT) {
			ret = http_res_get_intercept_rule(cur_proxy, &cur_proxy->http_res_rules, s);

			if (ret == HTTP_RULE_RES_BADREQ)
				goto return_srv_prx_502;

			if (ret == HTTP_RULE_RES_DONE) {
				rep->analysers &= ~an_bit;
				rep->analyse_exp = TICK_ETERNITY;
				return 1;
			}
		}

		/* we need to be called again. */
		if (ret == HTTP_RULE_RES_YIELD) {
			channel_dont_close(rep);
			return 0;
		}

		/* try headers filters */
		if (rule_set->rsp_exp != NULL) {
			if (apply_filters_to_response(s, rep, rule_set) < 0) {
			return_bad_resp:
				if (objt_server(s->target)) {
					HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
					health_adjust(objt_server(s->target), HANA_STATUS_HTTP_RSP);
				}
				HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			return_srv_prx_502:
				rep->analysers &= AN_RES_FLT_END;
				txn->status = 502;
				s->logs.t_data = -1; /* was not a valid response */
				s->si[1].flags |= SI_FL_NOLINGER;
				channel_truncate(rep);
				http_reply_and_close(s, txn->status, http_error_message(s));
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_PRXCOND;
				if (!(s->flags & SF_FINST_MASK))
					s->flags |= SF_FINST_H;
				return 0;
			}
		}

		/* has the response been denied ? */
		if (txn->flags & TX_SVDENY) {
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_secu, 1);

			HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);

			goto return_srv_prx_502;
		}

		/* add response headers from the rule sets in the same order */
		list_for_each_entry(wl, &rule_set->rsp_add, list) {
			if (txn->status < 200 && txn->status != 101)
				break;
			if (wl->cond) {
				int ret = acl_exec_cond(wl->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
				ret = acl_pass(ret);
				if (((struct acl_cond *)wl->cond)->pol == ACL_COND_UNLESS)
					ret = !ret;
				if (!ret)
					continue;
			}
			if (unlikely(http_header_add_tail(&txn->rsp, &txn->hdr_idx, wl->s) < 0))
				goto return_bad_resp;
		}

		/* check whether we're already working on the frontend */
		if (cur_proxy == sess->fe)
			break;
		cur_proxy = sess->fe;
	}

	/* After this point, this anayzer can't return yield, so we can
	 * remove the bit corresponding to this analyzer from the list.
	 *
	 * Note that the intermediate returns and goto found previously
	 * reset the analyzers.
	 */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;

	/* OK that's all we can do for 1xx responses */
	if (unlikely(txn->status < 200 && txn->status != 101))
		goto skip_header_mangling;

	/*
	 * Now check for a server cookie.
	 */
	if (s->be->cookie_name || sess->fe->capture_name || (s->be->options & PR_O_CHK_CACHE))
		manage_server_side_cookies(s, rep);

	/*
	 * Check for cache-control or pragma headers if required.
	 */
	if ((s->be->options & PR_O_CHK_CACHE) || (s->be->ck_opts & PR_CK_NOC))
		check_response_for_cacheability(s, rep);

	/*
	 * Add server cookie in the response if needed
	 */
	if (objt_server(s->target) && (s->be->ck_opts & PR_CK_INS) &&
	    !((txn->flags & TX_SCK_FOUND) && (s->be->ck_opts & PR_CK_PSV)) &&
	    (!(s->flags & SF_DIRECT) ||
	     ((s->be->cookie_maxidle || txn->cookie_last_date) &&
	      (!txn->cookie_last_date || (txn->cookie_last_date - date.tv_sec) < 0)) ||
	     (s->be->cookie_maxlife && !txn->cookie_first_date) ||  // set the first_date
	     (!s->be->cookie_maxlife && txn->cookie_first_date)) && // remove the first_date
	    (!(s->be->ck_opts & PR_CK_POST) || (txn->meth == HTTP_METH_POST)) &&
	    !(s->flags & SF_IGNORE_PRST)) {
		/* the server is known, it's not the one the client requested, or the
		 * cookie's last seen date needs to be refreshed. We have to
		 * insert a set-cookie here, except if we want to insert only on POST
		 * requests and this one isn't. Note that servers which don't have cookies
		 * (eg: some backup servers) will return a full cookie removal request.
		 */
		if (!objt_server(s->target)->cookie) {
			chunk_printf(&trash,
				     "Set-Cookie: %s=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/",
				     s->be->cookie_name);
		}
		else {
			chunk_printf(&trash, "Set-Cookie: %s=%s", s->be->cookie_name, objt_server(s->target)->cookie);

			if (s->be->cookie_maxidle || s->be->cookie_maxlife) {
				/* emit last_date, which is mandatory */
				trash.str[trash.len++] = COOKIE_DELIM_DATE;
				s30tob64((date.tv_sec+3) >> 2, trash.str + trash.len);
				trash.len += 5;

				if (s->be->cookie_maxlife) {
					/* emit first_date, which is either the original one or
					 * the current date.
					 */
					trash.str[trash.len++] = COOKIE_DELIM_DATE;
					s30tob64(txn->cookie_first_date ?
						 txn->cookie_first_date >> 2 :
						 (date.tv_sec+3) >> 2, trash.str + trash.len);
					trash.len += 5;
				}
			}
			chunk_appendf(&trash, "; path=/");
		}

		if (s->be->cookie_domain)
			chunk_appendf(&trash, "; domain=%s", s->be->cookie_domain);

		if (s->be->ck_opts & PR_CK_HTTPONLY)
			chunk_appendf(&trash, "; HttpOnly");

		if (s->be->ck_opts & PR_CK_SECURE)
			chunk_appendf(&trash, "; Secure");

		if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx, trash.str, trash.len) < 0))
			goto return_bad_resp;

		txn->flags &= ~TX_SCK_MASK;
		if (objt_server(s->target)->cookie && (s->flags & SF_DIRECT))
			/* the server did not change, only the date was updated */
			txn->flags |= TX_SCK_UPDATED;
		else
			txn->flags |= TX_SCK_INSERTED;

		/* Here, we will tell an eventual cache on the client side that we don't
		 * want it to cache this reply because HTTP/1.0 caches also cache cookies !
		 * Some caches understand the correct form: 'no-cache="set-cookie"', but
		 * others don't (eg: apache <= 1.3.26). So we use 'private' instead.
		 */
		if ((s->be->ck_opts & PR_CK_NOC) && (txn->flags & TX_CACHEABLE)) {

			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;

			if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx,
			                                   "Cache-control: private", 22) < 0))
				goto return_bad_resp;
		}
	}

	/*
	 * Check if result will be cacheable with a cookie.
	 * We'll block the response if security checks have caught
	 * nasty things such as a cacheable cookie.
	 */
	if (((txn->flags & (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_PRESENT)) ==
	     (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_PRESENT)) &&
	    (s->be->options & PR_O_CHK_CACHE)) {
		/* we're in presence of a cacheable response containing
		 * a set-cookie header. We'll block it as requested by
		 * the 'checkcache' option, and send an alert.
		 */
		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_secu, 1);

		HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
		HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
		if (sess->listener->counters)
			HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);

		ha_alert("Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		send_log(s->be, LOG_ALERT,
			 "Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		goto return_srv_prx_502;
	}

 skip_filters:
	/*
	 * Adjust "Connection: close" or "Connection: keep-alive" if needed.
	 * If an "Upgrade" token is found, the header is left untouched in order
	 * not to have to deal with some client bugs : some of them fail an upgrade
	 * if anything but "Upgrade" is present in the Connection header. We don't
	 * want to touch any 101 response either since it's switching to another
	 * protocol.
	 */
	if ((txn->status != 101) && !(txn->flags & TX_HDR_CONN_UPG) &&
	    (((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) ||
	     ((sess->fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL ||
	      (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL))) {
		unsigned int want_flags = 0;

		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
		    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) {
			/* we want a keep-alive response here. Keep-alive header
			 * required if either side is not 1.1.
			 */
			if (!(txn->req.flags & msg->flags & HTTP_MSGF_VER_11))
				want_flags |= TX_CON_KAL_SET;
		}
		else {
			/* we want a close response here. Close header required if
			 * the server is 1.1, regardless of the client.
			 */
			if (msg->flags & HTTP_MSGF_VER_11)
				want_flags |= TX_CON_CLO_SET;
		}

		if (want_flags != (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
			http_change_connection_header(txn, msg, want_flags);
	}

 skip_header_mangling:
	/* Always enter in the body analyzer */
	rep->analysers &= ~AN_RES_FLT_XFER_DATA;
	rep->analysers |= AN_RES_HTTP_XFER_BODY;

	/* if the user wants to log as soon as possible, without counting
	 * bytes from the server, then this is the right moment. We have
	 * to temporarily assign bytes_out to log what we currently have.
	 */
	if (!LIST_ISEMPTY(&sess->fe->logformat) && !(s->logs.logwait & LW_BYTES)) {
		s->logs.t_close = s->logs.t_data; /* to get a valid end date */
		s->logs.bytes_out = txn->rsp.eoh;
		s->do_log(s);
		s->logs.bytes_out = 0;
	}
	return 1;
}

/* This function is an analyser which forwards response body (including chunk
 * sizes if any). It is called as soon as we must forward, even if we forward
 * zero byte. The only situation where it must not be called is when we're in
 * tunnel mode and we want to forward till the close. It's used both to forward
 * remaining data and to resync after end of body. It expects the msg_state to
 * be between MSG_BODY and MSG_DONE (inclusive). It returns zero if it needs to
 * read more data, or 1 once we can go on with next request or end the stream.
 *
 * It is capable of compressing response data both in content-length mode and
 * in chunked mode. The state machines follows different flows depending on
 * whether content-length and chunked modes are used, since there are no
 * trailers in content-length :
 *
 *       chk-mode        cl-mode
 *          ,----- BODY -----.
 *         /                  \
 *        V     size > 0       V    chk-mode
 *  .--> SIZE -------------> DATA -------------> CRLF
 *  |     | size == 0          | last byte         |
 *  |     v      final crlf    v inspected         |
 *  |  TRAILERS -----------> DONE                  |
 *  |                                              |
 *  `----------------------------------------------'
 *
 * Compression only happens in the DATA state, and must be flushed in final
 * states (TRAILERS/DONE) or when leaving on missing data. Normal forwarding
 * is performed at once on final states for all bytes parsed, or when leaving
 * on missing data.
 */
int http_response_forward_body(struct stream *s, struct channel *res, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->rsp;
	int ret;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		res,
		res->rex, res->wex,
		res->flags,
		res->buf->i,
		res->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))
		return 0;

	if ((res->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((res->flags & CF_SHUTW) && (res->to_forward || res->buf->o)) ||
	     !s->req.analysers) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 */
		msg->err_state = msg->msg_state;
		msg->msg_state = HTTP_MSG_ERROR;
		http_resync_states(s);
		return 1;
	}

	/* in most states, we should abort in case of early close */
	channel_auto_close(res);

	if (msg->msg_state == HTTP_MSG_BODY) {
		msg->msg_state = ((msg->flags & HTTP_MSGF_TE_CHNK)
				  ? HTTP_MSG_CHUNK_SIZE
				  : HTTP_MSG_DATA);
	}

	if (res->to_forward) {
                /* We can't process the buffer's contents yet */
		res->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	if (msg->msg_state < HTTP_MSG_DONE) {
		ret = ((msg->flags & HTTP_MSGF_TE_CHNK)
		       ? http_msg_forward_chunked_body(s, msg)
		       : http_msg_forward_body(s, msg));
		if (!ret)
			goto missing_data_or_waiting;
		if (ret < 0)
			goto return_bad_res;
	}

	/* other states, DONE...TUNNEL */
	/* for keep-alive we don't want to forward closes on DONE */
	if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL)
		channel_dont_close(res);

	http_resync_states(s);
	if (!(res->analysers & an_bit)) {
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (res->flags & CF_SHUTW) {
				/* response errors are most likely due to the
				 * client aborting the transfer. */
				goto aborted_xfer;
			}
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg, msg->err_state, strm_fe(s));
			goto return_bad_res;
		}
		return 1;
	}
	return 0;

  missing_data_or_waiting:
	if (res->flags & CF_SHUTW)
		goto aborted_xfer;

	/* stop waiting for data if the input is closed before the end. If the
	 * client side was already closed, it means that the client has aborted,
	 * so we don't want to count this as a server abort. Otherwise it's a
	 * server abort.
	 */
	if (msg->msg_state < HTTP_MSG_ENDING && res->flags & CF_SHUTR) {
		if ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))
			goto aborted_xfer;
		/* If we have some pending data, we continue the processing */
		if (!buffer_pending(res->buf)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);
			goto return_bad_res_stats_ok;
		}
	}

	/* we need to obey the req analyser, so if it leaves, we must too */
	if (!s->req.analysers)
		goto return_bad_res;

	/* When TE: chunked is used, we need to get there again to parse
	 * remaining chunks even if the server has closed, so we don't want to
	 * set CF_DONTCLOSE. Similarly, if keep-alive is set on the client side
	 * or if there are filters registered on the stream, we don't want to
	 * forward a close
	 */
	if ((msg->flags & HTTP_MSGF_TE_CHNK) ||
	    HAS_DATA_FILTERS(s, res) ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL)
		channel_dont_close(res);

	/* We know that more data are expected, but we couldn't send more that
	 * what we did. So we always set the CF_EXPECT_MORE flag so that the
	 * system knows it must not set a PUSH on this first part. Interactive
	 * modes are already handled by the stream sock layer. We must not do
	 * this in content-length mode because it could present the MSG_MORE
	 * flag with the last block of forwarded data, which would cause an
	 * additional delay to be observed by the receiver.
	 */
	if ((msg->flags & HTTP_MSGF_TE_CHNK) || (msg->flags & HTTP_MSGF_COMPRESSING))
		res->flags |= CF_EXPECT_MORE;

	/* the stream handler will take care of timeouts and errors */
	return 0;

 return_bad_res: /* let's centralize all bad responses */
	HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);

 return_bad_res_stats_ok:
	txn->rsp.err_state = txn->rsp.msg_state;
	txn->rsp.msg_state = HTTP_MSG_ERROR;
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	res->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END; /* we're in data phase, we want to abort both directions */
	if (objt_server(s->target))
		health_adjust(objt_server(s->target), HANA_STATUS_HTTP_HDRRSP);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	return 0;

 aborted_xfer:
	txn->rsp.err_state = txn->rsp.msg_state;
	txn->rsp.msg_state = HTTP_MSG_ERROR;
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	res->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END; /* we're in data phase, we want to abort both directions */

	HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
	HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	return 0;
}


static inline int
http_msg_forward_body(struct stream *s, struct http_msg *msg)
{
	struct channel *chn = msg->chn;
	int ret;

	/* Here we have the guarantee to be in HTTP_MSG_DATA or HTTP_MSG_ENDING state */

	if (msg->msg_state == HTTP_MSG_ENDING)
		goto ending;

	/* Neither content-length, nor transfer-encoding was found, so we must
	 * read the body until the server connection is closed. In that case, we
	 * eat data as they come. Of course, this happens for response only. */
	if (!(msg->flags & HTTP_MSGF_XFER_LEN)) {
		unsigned long long len = (chn->buf->i - msg->next);
		msg->chunk_len += len;
		msg->body_len  += len;
	}
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_data(s, msg),
			       /* default_ret */ MIN(msg->chunk_len, chn->buf->i - msg->next),
			       /* on_error    */ goto error);
	msg->next     += ret;
	msg->chunk_len -= ret;
	if (msg->chunk_len) {
		/* input empty or output full */
		if (chn->buf->i > msg->next)
			chn->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	/* This check can only be true for a response. HTTP_MSGF_XFER_LEN is
	 * always set for a request. */
	if (!(msg->flags & HTTP_MSGF_XFER_LEN)) {
		/* The server still sending data that should be filtered */
		if (!(chn->flags & CF_SHUTR) && HAS_DATA_FILTERS(s, chn))
			goto missing_data_or_waiting;
	}

	msg->msg_state = HTTP_MSG_ENDING;

  ending:
	/* we may have some pending data starting at res->buf->p such as a last
	 * chunk of data or trailers. */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			       /* default_ret */ msg->next,
			       /* on_error    */ goto error);
	b_adv(chn->buf, ret);
	msg->next -= ret;
	if (unlikely(!(chn->flags & CF_WROTE_DATA) || msg->sov > 0))
		msg->sov -= ret;
	if (msg->next)
		goto waiting;

	FLT_STRM_DATA_CB(s, chn, flt_http_end(s, msg),
			 /* default_ret */ 1,
			 /* on_error    */ goto error,
			 /* on_wait     */ goto waiting);
	msg->msg_state = HTTP_MSG_DONE;
	return 1;

  missing_data_or_waiting:
	/* we may have some pending data starting at chn->buf->p */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			       /* default_ret */ msg->next,
			       /* on_error    */ goto error);
	b_adv(chn->buf, ret);
	msg->next -= ret;
	if (!(chn->flags & CF_WROTE_DATA) || msg->sov > 0)
		msg->sov -= ret;
	if (!HAS_DATA_FILTERS(s, chn))
		msg->chunk_len -= channel_forward(chn, msg->chunk_len);
  waiting:
	return 0;
  error:
	return -1;
}

static inline int
http_msg_forward_chunked_body(struct stream *s, struct http_msg *msg)
{
	struct channel *chn = msg->chn;
	unsigned int chunk;
	int ret;

	/* Here we have the guarantee to be in one of the following state:
	 * HTTP_MSG_DATA, HTTP_MSG_CHUNK_SIZE, HTTP_MSG_CHUNK_CRLF,
	 * HTTP_MSG_TRAILERS or HTTP_MSG_ENDING. */

  switch_states:
	switch (msg->msg_state) {
		case HTTP_MSG_DATA:
			ret = FLT_STRM_DATA_CB(s, chn, flt_http_data(s, msg),
					       /* default_ret */ MIN(msg->chunk_len, chn->buf->i - msg->next),
					       /* on_error    */ goto error);
			msg->next      += ret;
			msg->chunk_len -= ret;
			if (msg->chunk_len) {
				/* input empty or output full */
				if (chn->buf->i > msg->next)
					chn->flags |= CF_WAKE_WRITE;
				goto missing_data_or_waiting;
			}

			/* nothing left to forward for this chunk*/
			msg->msg_state = HTTP_MSG_CHUNK_CRLF;
			/* fall through for HTTP_MSG_CHUNK_CRLF */

		case HTTP_MSG_CHUNK_CRLF:
			/* we want the CRLF after the data */
			ret = h1_skip_chunk_crlf(chn->buf, msg->next, chn->buf->i);
			if (ret == 0)
				goto missing_data_or_waiting;
			if (ret < 0) {
				msg->err_pos = chn->buf->i + ret;
				if (msg->err_pos < 0)
					msg->err_pos += chn->buf->size;
				goto chunk_parsing_error;
			}
			msg->next += ret;
			msg->msg_state = HTTP_MSG_CHUNK_SIZE;
			/* fall through for HTTP_MSG_CHUNK_SIZE */

		case HTTP_MSG_CHUNK_SIZE:
			/* read the chunk size and assign it to ->chunk_len,
			 * then set ->next to point to the body and switch to
			 * DATA or TRAILERS state.
			 */
			ret = h1_parse_chunk_size(chn->buf, msg->next, chn->buf->i, &chunk);
			if (ret == 0)
				goto missing_data_or_waiting;
			if (ret < 0) {
				msg->err_pos = chn->buf->i + ret;
				if (msg->err_pos < 0)
					msg->err_pos += chn->buf->size;
				goto chunk_parsing_error;
			}

			msg->sol = ret;
			msg->next += ret;
			msg->chunk_len = chunk;
			msg->body_len += chunk;

			if (msg->chunk_len) {
				msg->msg_state = HTTP_MSG_DATA;
				goto switch_states;
			}
			msg->msg_state = HTTP_MSG_TRAILERS;
			/* fall through for HTTP_MSG_TRAILERS */

		case HTTP_MSG_TRAILERS:
			ret = http_forward_trailers(msg);
			if (ret < 0)
				goto chunk_parsing_error;
			FLT_STRM_DATA_CB(s, chn, flt_http_chunk_trailers(s, msg),
					 /* default_ret */ 1,
					 /* on_error    */ goto error);
			msg->next += msg->sol;
			if (!ret)
				goto missing_data_or_waiting;
			break;

		case HTTP_MSG_ENDING:
			goto ending;

		default:
			/* This should no happen in this function */
			goto error;
	}

	msg->msg_state = HTTP_MSG_ENDING;
  ending:
	/* we may have some pending data starting at res->buf->p such as a last
	 * chunk of data or trailers. */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			  /* default_ret */ msg->next,
			  /* on_error    */ goto error);
	b_adv(chn->buf, ret);
	msg->next -= ret;
	if (unlikely(!(chn->flags & CF_WROTE_DATA) || msg->sov > 0))
		msg->sov -= ret;
	if (msg->next)
		goto waiting;

	FLT_STRM_DATA_CB(s, chn, flt_http_end(s, msg),
		    /* default_ret */ 1,
		    /* on_error    */ goto error,
		    /* on_wait     */ goto waiting);
	msg->msg_state = HTTP_MSG_DONE;
	return 1;

  missing_data_or_waiting:
	/* we may have some pending data starting at chn->buf->p */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			  /* default_ret */ msg->next,
			  /* on_error    */ goto error);
	b_adv(chn->buf, ret);
	msg->next -= ret;
	if (!(chn->flags & CF_WROTE_DATA) || msg->sov > 0)
		msg->sov -= ret;
	if (!HAS_DATA_FILTERS(s, chn))
		msg->chunk_len -= channel_forward(chn, msg->chunk_len);
  waiting:
	return 0;

  chunk_parsing_error:
	if (msg->err_pos >= 0) {
		if (chn->flags & CF_ISRESP)
			http_capture_bad_message(s->be, &s->be->invalid_rep, s, msg,
						 msg->msg_state, strm_fe(s));
		else
			http_capture_bad_message(strm_fe(s), &strm_fe(s)->invalid_req, s,
						 msg, msg->msg_state, s->be);
	}
  error:
	return -1;
}


/* Iterate the same filter through all request headers.
 * Returns 1 if this filter can be stopped upon return, otherwise 0.
 * Since it can manage the switch to another backend, it updates the per-proxy
 * DENY stats.
 */
int apply_filter_to_req_headers(struct stream *s, struct channel *req, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, last_hdr;
	struct http_txn *txn = s->txn;
	struct hdr_idx_elem *cur_hdr;
	int delta;

	last_hdr = 0;

	cur_next = req->buf->p + hdr_idx_first_pos(&txn->hdr_idx);
	old_idx = 0;

	while (!last_hdr) {
		if (unlikely(txn->flags & (TX_CLDENY | TX_CLTARPIT)))
			return 1;
		else if (unlikely(txn->flags & TX_CLALLOW) &&
			 (exp->action == ACT_ALLOW ||
			  exp->action == ACT_DENY ||
			  exp->action == ACT_TARPIT))
			return 0;

		cur_idx = txn->hdr_idx.v[old_idx].next;
		if (!cur_idx)
			break;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* Now we have one header between cur_ptr and cur_end,
		 * and the next header starts at cur_next.
		 */

		if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
			switch (exp->action) {
			case ACT_ALLOW:
				txn->flags |= TX_CLALLOW;
				last_hdr = 1;
				break;

			case ACT_DENY:
				txn->flags |= TX_CLDENY;
				last_hdr = 1;
				break;

			case ACT_TARPIT:
				txn->flags |= TX_CLTARPIT;
				last_hdr = 1;
				break;

			case ACT_REPLACE:
				trash.len = exp_replace(trash.str, trash.size, cur_ptr, exp->replace, pmatch);
				if (trash.len < 0)
					return -1;

				delta = buffer_replace2(req->buf, cur_ptr, cur_end, trash.str, trash.len);
				/* FIXME: if the user adds a newline in the replacement, the
				 * index will not be recalculated for now, and the new line
				 * will not be counted as a new header.
				 */

				cur_end += delta;
				cur_next += delta;
				cur_hdr->len += delta;
				http_msg_move_end(&txn->req, delta);
				break;

			case ACT_REMOVE:
				delta = buffer_replace2(req->buf, cur_ptr, cur_next, NULL, 0);
				cur_next += delta;

				http_msg_move_end(&txn->req, delta);
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_end = NULL; /* null-term has been rewritten */
				cur_idx = old_idx;
				break;

			}
		}

		/* keep the link from this header to next one in case of later
		 * removal of next header.
		 */
		old_idx = cur_idx;
	}
	return 0;
}


/* Apply the filter to the request line.
 * Returns 0 if nothing has been done, 1 if the filter has been applied,
 * or -1 if a replacement resulted in an invalid request line.
 * Since it can manage the switch to another backend, it updates the per-proxy
 * DENY stats.
 */
int apply_filter_to_req_line(struct stream *s, struct channel *req, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end;
	int done;
	struct http_txn *txn = s->txn;
	int delta;

	if (unlikely(txn->flags & (TX_CLDENY | TX_CLTARPIT)))
		return 1;
	else if (unlikely(txn->flags & TX_CLALLOW) &&
		 (exp->action == ACT_ALLOW ||
		  exp->action == ACT_DENY ||
		  exp->action == ACT_TARPIT))
		return 0;
	else if (exp->action == ACT_REMOVE)
		return 0;

	done = 0;

	cur_ptr = req->buf->p;
	cur_end = cur_ptr + txn->req.sl.rq.l;

	/* Now we have the request line between cur_ptr and cur_end */

	if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
		switch (exp->action) {
		case ACT_ALLOW:
			txn->flags |= TX_CLALLOW;
			done = 1;
			break;

		case ACT_DENY:
			txn->flags |= TX_CLDENY;
			done = 1;
			break;

		case ACT_TARPIT:
			txn->flags |= TX_CLTARPIT;
			done = 1;
			break;

		case ACT_REPLACE:
			trash.len = exp_replace(trash.str, trash.size, cur_ptr, exp->replace, pmatch);
			if (trash.len < 0)
				return -1;

			delta = buffer_replace2(req->buf, cur_ptr, cur_end, trash.str, trash.len);
			/* FIXME: if the user adds a newline in the replacement, the
			 * index will not be recalculated for now, and the new line
			 * will not be counted as a new header.
			 */

			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			cur_end = (char *)http_parse_reqline(&txn->req,
							     HTTP_MSG_RQMETH,
							     cur_ptr, cur_end + 1,
							     NULL, NULL);
			if (unlikely(!cur_end))
				return -1;

			/* we have a full request and we know that we have either a CR
			 * or an LF at <ptr>.
			 */
			txn->meth = find_http_meth(cur_ptr, txn->req.sl.rq.m_l);
			hdr_idx_set_start(&txn->hdr_idx, txn->req.sl.rq.l, *cur_end == '\r');
			/* there is no point trying this regex on headers */
			return 1;
		}
	}
	return done;
}



/*
 * Apply all the req filters of proxy <px> to all headers in buffer <req> of stream <s>.
 * Returns 0 if everything is alright, or -1 in case a replacement lead to an
 * unparsable request. Since it can manage the switch to another backend, it
 * updates the per-proxy DENY stats.
 */
int apply_filters_to_request(struct stream *s, struct channel *req, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct hdr_exp *exp;

	for (exp = px->req_exp; exp; exp = exp->next) {
		int ret;

		/*
		 * The interleaving of transformations and verdicts
		 * makes it difficult to decide to continue or stop
		 * the evaluation.
		 */

		if (txn->flags & (TX_CLDENY|TX_CLTARPIT))
			break;

		if ((txn->flags & TX_CLALLOW) &&
		    (exp->action == ACT_ALLOW || exp->action == ACT_DENY ||
		     exp->action == ACT_TARPIT || exp->action == ACT_PASS))
			continue;

		/* if this filter had a condition, evaluate it now and skip to
		 * next filter if the condition does not match.
		 */
		if (exp->cond) {
			ret = acl_exec_cond(exp->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (((struct acl_cond *)exp->cond)->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (!ret)
				continue;
		}

		/* Apply the filter to the request line. */
		ret = apply_filter_to_req_line(s, req, exp);
		if (unlikely(ret < 0))
			return -1;

		if (likely(ret == 0)) {
			/* The filter did not match the request, it can be
			 * iterated through all headers.
			 */
			if (unlikely(apply_filter_to_req_headers(s, req, exp) < 0))
				return -1;
		}
	}
	return 0;
}


/* Find the end of a cookie value contained between <s> and <e>. It works the
 * same way as with headers above except that the semi-colon also ends a token.
 * See RFC2965 for more information. Note that it requires a valid header to
 * return a valid result.
 */
char *find_cookie_value_end(char *s, const char *e)
{
	int quoted, qdpair;

	quoted = qdpair = 0;
	for (; s < e; s++) {
		if (qdpair)                    qdpair = 0;
		else if (quoted) {
			if (*s == '\\')        qdpair = 1;
			else if (*s == '"')    quoted = 0;
		}
		else if (*s == '"')            quoted = 1;
		else if (*s == ',' || *s == ';') return s;
	}
	return s;
}

/* Delete a value in a header between delimiters <from> and <next> in buffer
 * <buf>. The number of characters displaced is returned, and the pointer to
 * the first delimiter is updated if required. The function tries as much as
 * possible to respect the following principles :
 *  - replace <from> delimiter by the <next> one unless <from> points to a
 *    colon, in which case <next> is simply removed
 *  - set exactly one space character after the new first delimiter, unless
 *    there are not enough characters in the block being moved to do so.
 *  - remove unneeded spaces before the previous delimiter and after the new
 *    one.
 *
 * It is the caller's responsibility to ensure that :
 *   - <from> points to a valid delimiter or the colon ;
 *   - <next> points to a valid delimiter or the final CR/LF ;
 *   - there are non-space chars before <from> ;
 *   - there is a CR/LF at or after <next>.
 */
int del_hdr_value(struct buffer *buf, char **from, char *next)
{
	char *prev = *from;

	if (*prev == ':') {
		/* We're removing the first value, preserve the colon and add a
		 * space if possible.
		 */
		if (!HTTP_IS_CRLF(*next))
			next++;
		prev++;
		if (prev < next)
			*prev++ = ' ';

		while (HTTP_IS_SPHT(*next))
			next++;
	} else {
		/* Remove useless spaces before the old delimiter. */
		while (HTTP_IS_SPHT(*(prev-1)))
			prev--;
		*from = prev;

		/* copy the delimiter and if possible a space if we're
		 * not at the end of the line.
		 */
		if (!HTTP_IS_CRLF(*next)) {
			*prev++ = *next++;
			if (prev + 1 < next)
				*prev++ = ' ';
			while (HTTP_IS_SPHT(*next))
				next++;
		}
	}
	return buffer_replace2(buf, prev, next, NULL, 0);
}

/*
 * Manage client-side cookie. It can impact performance by about 2% so it is
 * desirable to call it only when needed. This code is quite complex because
 * of the multiple very crappy and ambiguous syntaxes we have to support. it
 * highly recommended not to touch this part without a good reason !
 */
void manage_client_side_cookies(struct stream *s, struct channel *req)
{
	struct http_txn *txn = s->txn;
	struct session *sess = s->sess;
	int preserve_hdr;
	int cur_idx, old_idx;
	char *hdr_beg, *hdr_end, *hdr_next, *del_from;
	char *prev, *att_beg, *att_end, *equal, *val_beg, *val_end, *next;

	/* Iterate through the headers, we start with the start line. */
	old_idx = 0;
	hdr_next = req->buf->p + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		hdr_beg  = hdr_next;
		hdr_end  = hdr_beg + cur_hdr->len;
		hdr_next = hdr_end + cur_hdr->cr + 1;

		/* We have one full header between hdr_beg and hdr_end, and the
		 * next header starts at hdr_next. We're only interested in
		 * "Cookie:" headers.
		 */

		val = http_header_match2(hdr_beg, hdr_end, "Cookie", 6);
		if (!val) {
			old_idx = cur_idx;
			continue;
		}

		del_from = NULL;  /* nothing to be deleted */
		preserve_hdr = 0; /* assume we may kill the whole header */

		/* Now look for cookies. Conforming to RFC2109, we have to support
		 * attributes whose name begin with a '$', and associate them with
		 * the right cookie, if we want to delete this cookie.
		 * So there are 3 cases for each cookie read :
		 * 1) it's a special attribute, beginning with a '$' : ignore it.
		 * 2) it's a server id cookie that we *MAY* want to delete : save
		 *    some pointers on it (last semi-colon, beginning of cookie...)
		 * 3) it's an application cookie : we *MAY* have to delete a previous
		 *    "special" cookie.
		 * At the end of loop, if a "special" cookie remains, we may have to
		 * remove it. If no application cookie persists in the header, we
		 * *MUST* delete it.
		 *
		 * Note: RFC2965 is unclear about the processing of spaces around
		 * the equal sign in the ATTR=VALUE form. A careful inspection of
		 * the RFC explicitly allows spaces before it, and not within the
		 * tokens (attrs or values). An inspection of RFC2109 allows that
		 * too but section 10.1.3 lets one think that spaces may be allowed
		 * after the equal sign too, resulting in some (rare) buggy
		 * implementations trying to do that. So let's do what servers do.
		 * Latest ietf draft forbids spaces all around. Also, earlier RFCs
		 * allowed quoted strings in values, with any possible character
		 * after a backslash, including control chars and delimitors, which
		 * causes parsing to become ambiguous. Browsers also allow spaces
		 * within values even without quotes.
		 *
		 * We have to keep multiple pointers in order to support cookie
		 * removal at the beginning, middle or end of header without
		 * corrupting the header. All of these headers are valid :
		 *
		 * Cookie:NAME1=VALUE1;NAME2=VALUE2;NAME3=VALUE3\r\n
		 * Cookie:NAME1=VALUE1;NAME2_ONLY ;NAME3=VALUE3\r\n
		 * Cookie:    NAME1  =  VALUE 1  ; NAME2 = VALUE2 ; NAME3 = VALUE3\r\n
		 * |     |    |    | |  |      | |                                |
		 * |     |    |    | |  |      | |                     hdr_end <--+
		 * |     |    |    | |  |      | +--> next
		 * |     |    |    | |  |      +----> val_end
		 * |     |    |    | |  +-----------> val_beg
		 * |     |    |    | +--------------> equal
		 * |     |    |    +----------------> att_end
		 * |     |    +---------------------> att_beg
		 * |     +--------------------------> prev
		 * +--------------------------------> hdr_beg
		 */

		for (prev = hdr_beg + 6; prev < hdr_end; prev = next) {
			/* Iterate through all cookies on this line */

			/* find att_beg */
			att_beg = prev + 1;
			while (att_beg < hdr_end && HTTP_IS_SPHT(*att_beg))
				att_beg++;

			/* find att_end : this is the first character after the last non
			 * space before the equal. It may be equal to hdr_end.
			 */
			equal = att_end = att_beg;

			while (equal < hdr_end) {
				if (*equal == '=' || *equal == ',' || *equal == ';')
					break;
				if (HTTP_IS_SPHT(*equal++))
					continue;
				att_end = equal;
			}

			/* here, <equal> points to '=', a delimitor or the end. <att_end>
			 * is between <att_beg> and <equal>, both may be identical.
			 */

			/* look for end of cookie if there is an equal sign */
			if (equal < hdr_end && *equal == '=') {
				/* look for the beginning of the value */
				val_beg = equal + 1;
				while (val_beg < hdr_end && HTTP_IS_SPHT(*val_beg))
					val_beg++;

				/* find the end of the value, respecting quotes */
				next = find_cookie_value_end(val_beg, hdr_end);

				/* make val_end point to the first white space or delimitor after the value */
				val_end = next;
				while (val_end > val_beg && HTTP_IS_SPHT(*(val_end - 1)))
					val_end--;
			} else {
				val_beg = val_end = next = equal;
			}

			/* We have nothing to do with attributes beginning with '$'. However,
			 * they will automatically be removed if a header before them is removed,
			 * since they're supposed to be linked together.
			 */
			if (*att_beg == '$')
				continue;

			/* Ignore cookies with no equal sign */
			if (equal == next) {
				/* This is not our cookie, so we must preserve it. But if we already
				 * scheduled another cookie for removal, we cannot remove the
				 * complete header, but we can remove the previous block itself.
				 */
				preserve_hdr = 1;
				if (del_from != NULL) {
					int delta = del_hdr_value(req->buf, &del_from, prev);
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->req, delta);
					prev     = del_from;
					del_from = NULL;
				}
				continue;
			}

			/* if there are spaces around the equal sign, we need to
			 * strip them otherwise we'll get trouble for cookie captures,
			 * or even for rewrites. Since this happens extremely rarely,
			 * it does not hurt performance.
			 */
			if (unlikely(att_end != equal || val_beg > equal + 1)) {
				int stripped_before = 0;
				int stripped_after = 0;

				if (att_end != equal) {
					stripped_before = buffer_replace2(req->buf, att_end, equal, NULL, 0);
					equal   += stripped_before;
					val_beg += stripped_before;
				}

				if (val_beg > equal + 1) {
					stripped_after = buffer_replace2(req->buf, equal + 1, val_beg, NULL, 0);
					val_beg += stripped_after;
					stripped_before += stripped_after;
				}

				val_end      += stripped_before;
				next         += stripped_before;
				hdr_end      += stripped_before;
				hdr_next     += stripped_before;
				cur_hdr->len += stripped_before;
				http_msg_move_end(&txn->req, stripped_before);
			}
			/* now everything is as on the diagram above */

			/* First, let's see if we want to capture this cookie. We check
			 * that we don't already have a client side cookie, because we
			 * can only capture one. Also as an optimisation, we ignore
			 * cookies shorter than the declared name.
			 */
			if (sess->fe->capture_name != NULL && txn->cli_cookie == NULL &&
			    (val_end - att_beg >= sess->fe->capture_namelen) &&
			    memcmp(att_beg, sess->fe->capture_name, sess->fe->capture_namelen) == 0) {
				int log_len = val_end - att_beg;

				if ((txn->cli_cookie = pool_alloc(pool_head_capture)) == NULL) {
					ha_alert("HTTP logging : out of memory.\n");
				} else {
					if (log_len > sess->fe->capture_len)
						log_len = sess->fe->capture_len;
					memcpy(txn->cli_cookie, att_beg, log_len);
					txn->cli_cookie[log_len] = 0;
				}
			}

			/* Persistence cookies in passive, rewrite or insert mode have the
			 * following form :
			 *
			 *    Cookie: NAME=SRV[|<lastseen>[|<firstseen>]]
			 *
			 * For cookies in prefix mode, the form is :
			 *
			 *    Cookie: NAME=SRV~VALUE
			 */
			if ((att_end - att_beg == s->be->cookie_len) && (s->be->cookie_name != NULL) &&
			    (memcmp(att_beg, s->be->cookie_name, att_end - att_beg) == 0)) {
				struct server *srv = s->be->srv;
				char *delim;

				/* if we're in cookie prefix mode, we'll search the delimitor so that we
				 * have the server ID between val_beg and delim, and the original cookie between
				 * delim+1 and val_end. Otherwise, delim==val_end :
				 *
				 * Cookie: NAME=SRV;          # in all but prefix modes
				 * Cookie: NAME=SRV~OPAQUE ;  # in prefix mode
				 * |      ||   ||  |      |+-> next
				 * |      ||   ||  |      +--> val_end
				 * |      ||   ||  +---------> delim
				 * |      ||   |+------------> val_beg
				 * |      ||   +-------------> att_end = equal
				 * |      |+-----------------> att_beg
				 * |      +------------------> prev
				 * +-------------------------> hdr_beg
				 */

				if (s->be->ck_opts & PR_CK_PFX) {
					for (delim = val_beg; delim < val_end; delim++)
						if (*delim == COOKIE_DELIM)
							break;
				} else {
					char *vbar1;
					delim = val_end;
					/* Now check if the cookie contains a date field, which would
					 * appear after a vertical bar ('|') just after the server name
					 * and before the delimiter.
					 */
					vbar1 = memchr(val_beg, COOKIE_DELIM_DATE, val_end - val_beg);
					if (vbar1) {
						/* OK, so left of the bar is the server's cookie and
						 * right is the last seen date. It is a base64 encoded
						 * 30-bit value representing the UNIX date since the
						 * epoch in 4-second quantities.
						 */
						int val;
						delim = vbar1++;
						if (val_end - vbar1 >= 5) {
							val = b64tos30(vbar1);
							if (val > 0)
								txn->cookie_last_date = val << 2;
						}
						/* look for a second vertical bar */
						vbar1 = memchr(vbar1, COOKIE_DELIM_DATE, val_end - vbar1);
						if (vbar1 && (val_end - vbar1 > 5)) {
							val = b64tos30(vbar1 + 1);
							if (val > 0)
								txn->cookie_first_date = val << 2;
						}
					}
				}

				/* if the cookie has an expiration date and the proxy wants to check
				 * it, then we do that now. We first check if the cookie is too old,
				 * then only if it has expired. We detect strict overflow because the
				 * time resolution here is not great (4 seconds). Cookies with dates
				 * in the future are ignored if their offset is beyond one day. This
				 * allows an admin to fix timezone issues without expiring everyone
				 * and at the same time avoids keeping unwanted side effects for too
				 * long.
				 */
				if (txn->cookie_first_date && s->be->cookie_maxlife &&
				    (((signed)(date.tv_sec - txn->cookie_first_date) > (signed)s->be->cookie_maxlife) ||
				     ((signed)(txn->cookie_first_date - date.tv_sec) > 86400))) {
					txn->flags &= ~TX_CK_MASK;
					txn->flags |= TX_CK_OLD;
					delim = val_beg; // let's pretend we have not found the cookie
					txn->cookie_first_date = 0;
					txn->cookie_last_date = 0;
				}
				else if (txn->cookie_last_date && s->be->cookie_maxidle &&
					 (((signed)(date.tv_sec - txn->cookie_last_date) > (signed)s->be->cookie_maxidle) ||
					  ((signed)(txn->cookie_last_date - date.tv_sec) > 86400))) {
					txn->flags &= ~TX_CK_MASK;
					txn->flags |= TX_CK_EXPIRED;
					delim = val_beg; // let's pretend we have not found the cookie
					txn->cookie_first_date = 0;
					txn->cookie_last_date = 0;
				}

				/* Here, we'll look for the first running server which supports the cookie.
				 * This allows to share a same cookie between several servers, for example
				 * to dedicate backup servers to specific servers only.
				 * However, to prevent clients from sticking to cookie-less backup server
				 * when they have incidentely learned an empty cookie, we simply ignore
				 * empty cookies and mark them as invalid.
				 * The same behaviour is applied when persistence must be ignored.
				 */
				if ((delim == val_beg) || (s->flags & (SF_IGNORE_PRST | SF_ASSIGNED)))
					srv = NULL;

				while (srv) {
					if (srv->cookie && (srv->cklen == delim - val_beg) &&
					    !memcmp(val_beg, srv->cookie, delim - val_beg)) {
						if ((srv->cur_state != SRV_ST_STOPPED) ||
						    (s->be->options & PR_O_PERSIST) ||
						    (s->flags & SF_FORCE_PRST)) {
							/* we found the server and we can use it */
							txn->flags &= ~TX_CK_MASK;
							txn->flags |= (srv->cur_state != SRV_ST_STOPPED) ? TX_CK_VALID : TX_CK_DOWN;
							s->flags |= SF_DIRECT | SF_ASSIGNED;
							s->target = &srv->obj_type;
							break;
						} else {
							/* we found a server, but it's down,
							 * mark it as such and go on in case
							 * another one is available.
							 */
							txn->flags &= ~TX_CK_MASK;
							txn->flags |= TX_CK_DOWN;
						}
					}
					srv = srv->next;
				}

				if (!srv && !(txn->flags & (TX_CK_DOWN|TX_CK_EXPIRED|TX_CK_OLD))) {
					/* no server matched this cookie or we deliberately skipped it */
					txn->flags &= ~TX_CK_MASK;
					if ((s->flags & (SF_IGNORE_PRST | SF_ASSIGNED)))
						txn->flags |= TX_CK_UNUSED;
					else
						txn->flags |= TX_CK_INVALID;
				}

				/* depending on the cookie mode, we may have to either :
				 * - delete the complete cookie if we're in insert+indirect mode, so that
				 *   the server never sees it ;
				 * - remove the server id from the cookie value, and tag the cookie as an
				 *   application cookie so that it does not get accidentely removed later,
				 *   if we're in cookie prefix mode
				 */
				if ((s->be->ck_opts & PR_CK_PFX) && (delim != val_end)) {
					int delta; /* negative */

					delta = buffer_replace2(req->buf, val_beg, delim + 1, NULL, 0);
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->req, delta);

					del_from = NULL;
					preserve_hdr = 1; /* we want to keep this cookie */
				}
				else if (del_from == NULL &&
					 (s->be->ck_opts & (PR_CK_INS | PR_CK_IND)) == (PR_CK_INS | PR_CK_IND)) {
					del_from = prev;
				}
			} else {
				/* This is not our cookie, so we must preserve it. But if we already
				 * scheduled another cookie for removal, we cannot remove the
				 * complete header, but we can remove the previous block itself.
				 */
				preserve_hdr = 1;

				if (del_from != NULL) {
					int delta = del_hdr_value(req->buf, &del_from, prev);
					if (att_beg >= del_from)
						att_beg += delta;
					if (att_end >= del_from)
						att_end += delta;
					val_beg  += delta;
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->req, delta);
					prev     = del_from;
					del_from = NULL;
				}
			}

			/* continue with next cookie on this header line */
			att_beg = next;
		} /* for each cookie */

		/* There are no more cookies on this line.
		 * We may still have one (or several) marked for deletion at the
		 * end of the line. We must do this now in two ways :
		 *  - if some cookies must be preserved, we only delete from the
		 *    mark to the end of line ;
		 *  - if nothing needs to be preserved, simply delete the whole header
		 */
		if (del_from) {
			int delta;
			if (preserve_hdr) {
				delta = del_hdr_value(req->buf, &del_from, hdr_end);
				hdr_end = del_from;
				cur_hdr->len += delta;
			} else {
				delta = buffer_replace2(req->buf, hdr_beg, hdr_next, NULL, 0);

				/* FIXME: this should be a separate function */
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_idx = old_idx;
			}
			hdr_next += delta;
			http_msg_move_end(&txn->req, delta);
		}

		/* check next header */
		old_idx = cur_idx;
	}
}


/* Iterate the same filter through all response headers contained in <rtr>.
 * Returns 1 if this filter can be stopped upon return, otherwise 0.
 */
int apply_filter_to_resp_headers(struct stream *s, struct channel *rtr, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, last_hdr;
	struct http_txn *txn = s->txn;
	struct hdr_idx_elem *cur_hdr;
	int delta;

	last_hdr = 0;

	cur_next = rtr->buf->p + hdr_idx_first_pos(&txn->hdr_idx);
	old_idx = 0;

	while (!last_hdr) {
		if (unlikely(txn->flags & TX_SVDENY))
			return 1;
		else if (unlikely(txn->flags & TX_SVALLOW) &&
			 (exp->action == ACT_ALLOW ||
			  exp->action == ACT_DENY))
			return 0;

		cur_idx = txn->hdr_idx.v[old_idx].next;
		if (!cur_idx)
			break;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* Now we have one header between cur_ptr and cur_end,
		 * and the next header starts at cur_next.
		 */

		if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
			switch (exp->action) {
			case ACT_ALLOW:
				txn->flags |= TX_SVALLOW;
				last_hdr = 1;
				break;

			case ACT_DENY:
				txn->flags |= TX_SVDENY;
				last_hdr = 1;
				break;

			case ACT_REPLACE:
				trash.len = exp_replace(trash.str, trash.size, cur_ptr, exp->replace, pmatch);
				if (trash.len < 0)
					return -1;

				delta = buffer_replace2(rtr->buf, cur_ptr, cur_end, trash.str, trash.len);
				/* FIXME: if the user adds a newline in the replacement, the
				 * index will not be recalculated for now, and the new line
				 * will not be counted as a new header.
				 */

				cur_end += delta;
				cur_next += delta;
				cur_hdr->len += delta;
				http_msg_move_end(&txn->rsp, delta);
				break;

			case ACT_REMOVE:
				delta = buffer_replace2(rtr->buf, cur_ptr, cur_next, NULL, 0);
				cur_next += delta;

				http_msg_move_end(&txn->rsp, delta);
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_end = NULL; /* null-term has been rewritten */
				cur_idx = old_idx;
				break;

			}
		}

		/* keep the link from this header to next one in case of later
		 * removal of next header.
		 */
		old_idx = cur_idx;
	}
	return 0;
}


/* Apply the filter to the status line in the response buffer <rtr>.
 * Returns 0 if nothing has been done, 1 if the filter has been applied,
 * or -1 if a replacement resulted in an invalid status line.
 */
int apply_filter_to_sts_line(struct stream *s, struct channel *rtr, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end;
	int done;
	struct http_txn *txn = s->txn;
	int delta;


	if (unlikely(txn->flags & TX_SVDENY))
		return 1;
	else if (unlikely(txn->flags & TX_SVALLOW) &&
		 (exp->action == ACT_ALLOW ||
		  exp->action == ACT_DENY))
		return 0;
	else if (exp->action == ACT_REMOVE)
		return 0;

	done = 0;

	cur_ptr = rtr->buf->p;
	cur_end = cur_ptr + txn->rsp.sl.st.l;

	/* Now we have the status line between cur_ptr and cur_end */

	if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
		switch (exp->action) {
		case ACT_ALLOW:
			txn->flags |= TX_SVALLOW;
			done = 1;
			break;

		case ACT_DENY:
			txn->flags |= TX_SVDENY;
			done = 1;
			break;

		case ACT_REPLACE:
			trash.len = exp_replace(trash.str, trash.size, cur_ptr, exp->replace, pmatch);
			if (trash.len < 0)
				return -1;

			delta = buffer_replace2(rtr->buf, cur_ptr, cur_end, trash.str, trash.len);
			/* FIXME: if the user adds a newline in the replacement, the
			 * index will not be recalculated for now, and the new line
			 * will not be counted as a new header.
			 */

			http_msg_move_end(&txn->rsp, delta);
			cur_end += delta;
			cur_end = (char *)http_parse_stsline(&txn->rsp,
							     HTTP_MSG_RPVER,
							     cur_ptr, cur_end + 1,
							     NULL, NULL);
			if (unlikely(!cur_end))
				return -1;

			/* we have a full respnse and we know that we have either a CR
			 * or an LF at <ptr>.
			 */
			txn->status = strl2ui(rtr->buf->p + txn->rsp.sl.st.c, txn->rsp.sl.st.c_l);
			hdr_idx_set_start(&txn->hdr_idx, txn->rsp.sl.st.l, *cur_end == '\r');
			/* there is no point trying this regex on headers */
			return 1;
		}
	}
	return done;
}



/*
 * Apply all the resp filters of proxy <px> to all headers in buffer <rtr> of stream <s>.
 * Returns 0 if everything is alright, or -1 in case a replacement lead to an
 * unparsable response.
 */
int apply_filters_to_response(struct stream *s, struct channel *rtr, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct hdr_exp *exp;

	for (exp = px->rsp_exp; exp; exp = exp->next) {
		int ret;

		/*
		 * The interleaving of transformations and verdicts
		 * makes it difficult to decide to continue or stop
		 * the evaluation.
		 */

		if (txn->flags & TX_SVDENY)
			break;

		if ((txn->flags & TX_SVALLOW) &&
		    (exp->action == ACT_ALLOW || exp->action == ACT_DENY ||
		     exp->action == ACT_PASS)) {
			exp = exp->next;
			continue;
		}

		/* if this filter had a condition, evaluate it now and skip to
		 * next filter if the condition does not match.
		 */
		if (exp->cond) {
			ret = acl_exec_cond(exp->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (((struct acl_cond *)exp->cond)->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}

		/* Apply the filter to the status line. */
		ret = apply_filter_to_sts_line(s, rtr, exp);
		if (unlikely(ret < 0))
			return -1;

		if (likely(ret == 0)) {
			/* The filter did not match the response, it can be
			 * iterated through all headers.
			 */
			if (unlikely(apply_filter_to_resp_headers(s, rtr, exp) < 0))
				return -1;
		}
	}
	return 0;
}


/*
 * Manage server-side cookies. It can impact performance by about 2% so it is
 * desirable to call it only when needed. This function is also used when we
 * just need to know if there is a cookie (eg: for check-cache).
 */
void manage_server_side_cookies(struct stream *s, struct channel *res)
{
	struct http_txn *txn = s->txn;
	struct session *sess = s->sess;
	struct server *srv;
	int is_cookie2;
	int cur_idx, old_idx, delta;
	char *hdr_beg, *hdr_end, *hdr_next;
	char *prev, *att_beg, *att_end, *equal, *val_beg, *val_end, *next;

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	old_idx = 0;
	hdr_next = res->buf->p + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		hdr_beg  = hdr_next;
		hdr_end  = hdr_beg + cur_hdr->len;
		hdr_next = hdr_end + cur_hdr->cr + 1;

		/* We have one full header between hdr_beg and hdr_end, and the
		 * next header starts at hdr_next. We're only interested in
		 * "Set-Cookie" and "Set-Cookie2" headers.
		 */

		is_cookie2 = 0;
		prev = hdr_beg + 10;
		val = http_header_match2(hdr_beg, hdr_end, "Set-Cookie", 10);
		if (!val) {
			val = http_header_match2(hdr_beg, hdr_end, "Set-Cookie2", 11);
			if (!val) {
				old_idx = cur_idx;
				continue;
			}
			is_cookie2 = 1;
			prev = hdr_beg + 11;
		}

		/* OK, right now we know we have a Set-Cookie* at hdr_beg, and
		 * <prev> points to the colon.
		 */
		txn->flags |= TX_SCK_PRESENT;

		/* Maybe we only wanted to see if there was a Set-Cookie (eg:
		 * check-cache is enabled) and we are not interested in checking
		 * them. Warning, the cookie capture is declared in the frontend.
		 */
		if (s->be->cookie_name == NULL && sess->fe->capture_name == NULL)
			return;

		/* OK so now we know we have to process this response cookie.
		 * The format of the Set-Cookie header is slightly different
		 * from the format of the Cookie header in that it does not
		 * support the comma as a cookie delimiter (thus the header
		 * cannot be folded) because the Expires attribute described in
		 * the original Netscape's spec may contain an unquoted date
		 * with a comma inside. We have to live with this because
		 * many browsers don't support Max-Age and some browsers don't
		 * support quoted strings. However the Set-Cookie2 header is
		 * clean.
		 *
		 * We have to keep multiple pointers in order to support cookie
		 * removal at the beginning, middle or end of header without
		 * corrupting the header (in case of set-cookie2). A special
		 * pointer, <scav> points to the beginning of the set-cookie-av
		 * fields after the first semi-colon. The <next> pointer points
		 * either to the end of line (set-cookie) or next unquoted comma
		 * (set-cookie2). All of these headers are valid :
		 *
		 * Set-Cookie:    NAME1  =  VALUE 1  ; Secure; Path="/"\r\n
		 * Set-Cookie:NAME=VALUE; Secure; Expires=Thu, 01-Jan-1970 00:00:01 GMT\r\n
		 * Set-Cookie: NAME = VALUE ; Secure; Expires=Thu, 01-Jan-1970 00:00:01 GMT\r\n
		 * Set-Cookie2: NAME1 = VALUE 1 ; Max-Age=0, NAME2=VALUE2; Discard\r\n
		 * |          | |   | | |     | |          |                      |
		 * |          | |   | | |     | |          +-> next    hdr_end <--+
		 * |          | |   | | |     | +------------> scav
		 * |          | |   | | |     +--------------> val_end
		 * |          | |   | | +--------------------> val_beg
		 * |          | |   | +----------------------> equal
		 * |          | |   +------------------------> att_end
		 * |          | +----------------------------> att_beg
		 * |          +------------------------------> prev
		 * +-----------------------------------------> hdr_beg
		 */

		for (; prev < hdr_end; prev = next) {
			/* Iterate through all cookies on this line */

			/* find att_beg */
			att_beg = prev + 1;
			while (att_beg < hdr_end && HTTP_IS_SPHT(*att_beg))
				att_beg++;

			/* find att_end : this is the first character after the last non
			 * space before the equal. It may be equal to hdr_end.
			 */
			equal = att_end = att_beg;

			while (equal < hdr_end) {
				if (*equal == '=' || *equal == ';' || (is_cookie2 && *equal == ','))
					break;
				if (HTTP_IS_SPHT(*equal++))
					continue;
				att_end = equal;
			}

			/* here, <equal> points to '=', a delimitor or the end. <att_end>
			 * is between <att_beg> and <equal>, both may be identical.
			 */

			/* look for end of cookie if there is an equal sign */
			if (equal < hdr_end && *equal == '=') {
				/* look for the beginning of the value */
				val_beg = equal + 1;
				while (val_beg < hdr_end && HTTP_IS_SPHT(*val_beg))
					val_beg++;

				/* find the end of the value, respecting quotes */
				next = find_cookie_value_end(val_beg, hdr_end);

				/* make val_end point to the first white space or delimitor after the value */
				val_end = next;
				while (val_end > val_beg && HTTP_IS_SPHT(*(val_end - 1)))
					val_end--;
			} else {
				/* <equal> points to next comma, semi-colon or EOL */
				val_beg = val_end = next = equal;
			}

			if (next < hdr_end) {
				/* Set-Cookie2 supports multiple cookies, and <next> points to
				 * a colon or semi-colon before the end. So skip all attr-value
				 * pairs and look for the next comma. For Set-Cookie, since
				 * commas are permitted in values, skip to the end.
				 */
				if (is_cookie2)
					next = find_hdr_value_end(next, hdr_end);
				else
					next = hdr_end;
			}

			/* Now everything is as on the diagram above */

			/* Ignore cookies with no equal sign */
			if (equal == val_end)
				continue;

			/* If there are spaces around the equal sign, we need to
			 * strip them otherwise we'll get trouble for cookie captures,
			 * or even for rewrites. Since this happens extremely rarely,
			 * it does not hurt performance.
			 */
			if (unlikely(att_end != equal || val_beg > equal + 1)) {
				int stripped_before = 0;
				int stripped_after = 0;

				if (att_end != equal) {
					stripped_before = buffer_replace2(res->buf, att_end, equal, NULL, 0);
					equal   += stripped_before;
					val_beg += stripped_before;
				}

				if (val_beg > equal + 1) {
					stripped_after = buffer_replace2(res->buf, equal + 1, val_beg, NULL, 0);
					val_beg += stripped_after;
					stripped_before += stripped_after;
				}

				val_end      += stripped_before;
				next         += stripped_before;
				hdr_end      += stripped_before;
				hdr_next     += stripped_before;
				cur_hdr->len += stripped_before;
				http_msg_move_end(&txn->rsp, stripped_before);
			}

			/* First, let's see if we want to capture this cookie. We check
			 * that we don't already have a server side cookie, because we
			 * can only capture one. Also as an optimisation, we ignore
			 * cookies shorter than the declared name.
			 */
			if (sess->fe->capture_name != NULL &&
			    txn->srv_cookie == NULL &&
			    (val_end - att_beg >= sess->fe->capture_namelen) &&
			    memcmp(att_beg, sess->fe->capture_name, sess->fe->capture_namelen) == 0) {
				int log_len = val_end - att_beg;
				if ((txn->srv_cookie = pool_alloc(pool_head_capture)) == NULL) {
					ha_alert("HTTP logging : out of memory.\n");
				}
				else {
					if (log_len > sess->fe->capture_len)
						log_len = sess->fe->capture_len;
					memcpy(txn->srv_cookie, att_beg, log_len);
					txn->srv_cookie[log_len] = 0;
				}
			}

			srv = objt_server(s->target);
			/* now check if we need to process it for persistence */
			if (!(s->flags & SF_IGNORE_PRST) &&
			    (att_end - att_beg == s->be->cookie_len) && (s->be->cookie_name != NULL) &&
			    (memcmp(att_beg, s->be->cookie_name, att_end - att_beg) == 0)) {
				/* assume passive cookie by default */
				txn->flags &= ~TX_SCK_MASK;
				txn->flags |= TX_SCK_FOUND;
			
				/* If the cookie is in insert mode on a known server, we'll delete
				 * this occurrence because we'll insert another one later.
				 * We'll delete it too if the "indirect" option is set and we're in
				 * a direct access.
				 */
				if (s->be->ck_opts & PR_CK_PSV) {
					/* The "preserve" flag was set, we don't want to touch the
					 * server's cookie.
					 */
				}
				else if ((srv && (s->be->ck_opts & PR_CK_INS)) ||
				    ((s->flags & SF_DIRECT) && (s->be->ck_opts & PR_CK_IND))) {
					/* this cookie must be deleted */
					if (*prev == ':' && next == hdr_end) {
						/* whole header */
						delta = buffer_replace2(res->buf, hdr_beg, hdr_next, NULL, 0);
						txn->hdr_idx.v[old_idx].next = cur_hdr->next;
						txn->hdr_idx.used--;
						cur_hdr->len = 0;
						cur_idx = old_idx;
						hdr_next += delta;
						http_msg_move_end(&txn->rsp, delta);
						/* note: while both invalid now, <next> and <hdr_end>
						 * are still equal, so the for() will stop as expected.
						 */
					} else {
						/* just remove the value */
						int delta = del_hdr_value(res->buf, &prev, next);
						next      = prev;
						hdr_end  += delta;
						hdr_next += delta;
						cur_hdr->len += delta;
						http_msg_move_end(&txn->rsp, delta);
					}
					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_DELETED;
					/* and go on with next cookie */
				}
				else if (srv && srv->cookie && (s->be->ck_opts & PR_CK_RW)) {
					/* replace bytes val_beg->val_end with the cookie name associated
					 * with this server since we know it.
					 */
					delta = buffer_replace2(res->buf, val_beg, val_end, srv->cookie, srv->cklen);
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->rsp, delta);

					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_REPLACED;
				}
				else if (srv && srv->cookie && (s->be->ck_opts & PR_CK_PFX)) {
					/* insert the cookie name associated with this server
					 * before existing cookie, and insert a delimiter between them..
					 */
					delta = buffer_replace2(res->buf, val_beg, val_beg, srv->cookie, srv->cklen + 1);
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->rsp, delta);

					val_beg[srv->cklen] = COOKIE_DELIM;
					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_REPLACED;
				}
			}
			/* that's done for this cookie, check the next one on the same
			 * line when next != hdr_end (only if is_cookie2).
			 */
		}
		/* check next header */
		old_idx = cur_idx;
	}
}


/*
 * Parses the Cache-Control and Pragma request header fields to determine if
 * the request may be served from the cache and/or if it is cacheable. Updates
 * s->txn->flags.
 */
void check_request_for_cacheability(struct stream *s, struct channel *chn)
{
	struct http_txn *txn = s->txn;
	char *p1, *p2;
	char *cur_ptr, *cur_end, *cur_next;
	int pragma_found;
	int cc_found;
	int cur_idx;

	if ((txn->flags & (TX_CACHEABLE|TX_CACHE_IGNORE)) == TX_CACHE_IGNORE)
		return; /* nothing more to do here */

	cur_idx = 0;
	pragma_found = cc_found = 0;
	cur_next = chn->buf->p + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[cur_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next.
		 */

		val = http_header_match2(cur_ptr, cur_end, "Pragma", 6);
		if (val) {
			if ((cur_end - (cur_ptr + val) >= 8) &&
			    strncasecmp(cur_ptr + val, "no-cache", 8) == 0) {
				pragma_found = 1;
				continue;
			}
		}

		val = http_header_match2(cur_ptr, cur_end, "Cache-control", 13);
		if (!val)
			continue;

		/* OK, right now we know we have a cache-control header at cur_ptr */
		cc_found = 1;
		p1 = cur_ptr + val; /* first non-space char after 'cache-control:' */

		if (p1 >= cur_end)	/* no more info */
			continue;

		/* p1 is at the beginning of the value */
		p2 = p1;
		while (p2 < cur_end && *p2 != '=' && *p2 != ',' && !isspace((unsigned char)*p2))
			p2++;

		/* we have a complete value between p1 and p2. We don't check the
		 * values after max-age, max-stale nor min-fresh, we simply don't
		 * use the cache when they're specified.
		 */
		if (((p2 - p1 == 7) && strncasecmp(p1, "max-age",   7) == 0) ||
		    ((p2 - p1 == 8) && strncasecmp(p1, "no-cache",  8) == 0) ||
		    ((p2 - p1 == 9) && strncasecmp(p1, "max-stale", 9) == 0) ||
		    ((p2 - p1 == 9) && strncasecmp(p1, "min-fresh", 9) == 0)) {
			txn->flags |= TX_CACHE_IGNORE;
			continue;
		}

		if ((p2 - p1 == 8) && strncasecmp(p1, "no-store", 8) == 0) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			continue;
		}
	}

	/* RFC7234#5.4:
	 *   When the Cache-Control header field is also present and
	 *   understood in a request, Pragma is ignored.
	 *   When the Cache-Control header field is not present in a
	 *   request, caches MUST consider the no-cache request
	 *   pragma-directive as having the same effect as if
	 *   "Cache-Control: no-cache" were present.
	 */
	if (!cc_found && pragma_found)
		txn->flags |= TX_CACHE_IGNORE;
}

/*
 * Check if response is cacheable or not. Updates s->txn->flags.
 */
void check_response_for_cacheability(struct stream *s, struct channel *rtr)
{
	struct http_txn *txn = s->txn;
	char *p1, *p2;

	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx;

	if (txn->status < 200) {
		/* do not try to cache interim responses! */
		txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
		return;
	}

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	cur_idx = 0;
	cur_next = rtr->buf->p + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[cur_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next.
		 */

		val = http_header_match2(cur_ptr, cur_end, "Pragma", 6);
		if (val) {
			if ((cur_end - (cur_ptr + val) >= 8) &&
			    strncasecmp(cur_ptr + val, "no-cache", 8) == 0) {
				txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
				return;
			}
		}

		val = http_header_match2(cur_ptr, cur_end, "Cache-control", 13);
		if (!val)
			continue;

		/* OK, right now we know we have a cache-control header at cur_ptr */

		p1 = cur_ptr + val; /* first non-space char after 'cache-control:' */

		if (p1 >= cur_end)	/* no more info */
			continue;

		/* p1 is at the beginning of the value */
		p2 = p1;

		while (p2 < cur_end && *p2 != '=' && *p2 != ',' && !isspace((unsigned char)*p2))
			p2++;

		/* we have a complete value between p1 and p2 */
		if (p2 < cur_end && *p2 == '=') {
			if (((cur_end - p2) > 1 && (p2 - p1 == 7) && strncasecmp(p1, "max-age=0", 9) == 0) ||
			    ((cur_end - p2) > 1 && (p2 - p1 == 8) && strncasecmp(p1, "s-maxage=0", 10) == 0)) {
				txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
				continue;
			}

			/* we have something of the form no-cache="set-cookie" */
			if ((cur_end - p1 >= 21) &&
			    strncasecmp(p1, "no-cache=\"set-cookie", 20) == 0
			    && (p1[20] == '"' || p1[20] == ','))
				txn->flags &= ~TX_CACHE_COOK;
			continue;
		}

		/* OK, so we know that either p2 points to the end of string or to a comma */
		if (((p2 - p1 ==  7) && strncasecmp(p1, "private", 7) == 0) ||
		    ((p2 - p1 ==  8) && strncasecmp(p1, "no-cache", 8) == 0) ||
		    ((p2 - p1 ==  8) && strncasecmp(p1, "no-store", 8) == 0)) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			return;
		}

		if ((p2 - p1 ==  6) && strncasecmp(p1, "public", 6) == 0) {
			txn->flags |= TX_CACHEABLE | TX_CACHE_COOK;
			continue;
		}
	}
}


/*
 * In a GET, HEAD or POST request, check if the requested URI matches the stats uri
 * for the current backend.
 *
 * It is assumed that the request is either a HEAD, GET, or POST and that the
 * uri_auth field is valid.
 *
 * Returns 1 if stats should be provided, otherwise 0.
 */
int stats_check_uri(struct stream_interface *si, struct http_txn *txn, struct proxy *backend)
{
	struct uri_auth *uri_auth = backend->uri_auth;
	struct http_msg *msg = &txn->req;
	const char *uri = msg->chn->buf->p+ msg->sl.rq.u;

	if (!uri_auth)
		return 0;

	if (txn->meth != HTTP_METH_GET && txn->meth != HTTP_METH_HEAD && txn->meth != HTTP_METH_POST)
		return 0;

	/* check URI size */
	if (uri_auth->uri_len > msg->sl.rq.u_l)
		return 0;

	if (memcmp(uri, uri_auth->uri_prefix, uri_auth->uri_len) != 0)
		return 0;

	return 1;
}

/*
 * Capture a bad request or response and archive it in the proxy's structure.
 * By default it tries to report the error position as msg->err_pos. However if
 * this one is not set, it will then report msg->next, which is the last known
 * parsing point. The function is able to deal with wrapping buffers. It always
 * displays buffers as a contiguous area starting at buf->p.
 */
void http_capture_bad_message(struct proxy *proxy, struct error_snapshot *es, struct stream *s,
                              struct http_msg *msg,
			      enum h1_state state, struct proxy *other_end)
{
	struct session *sess = strm_sess(s);
	struct channel *chn = msg->chn;
	int len1, len2;

	HA_SPIN_LOCK(PROXY_LOCK, &proxy->lock);
	es->len = MIN(chn->buf->i, global.tune.bufsize);
	len1 = chn->buf->data + chn->buf->size - chn->buf->p;
	len1 = MIN(len1, es->len);
	len2 = es->len - len1; /* remaining data if buffer wraps */

	if (!es->buf)
		es->buf = malloc(global.tune.bufsize);

	if (es->buf) {
		memcpy(es->buf, chn->buf->p, len1);
		if (len2)
			memcpy(es->buf + len1, chn->buf->data, len2);
	}

	if (msg->err_pos >= 0)
		es->pos = msg->err_pos;
	else
		es->pos = msg->next;

	es->when = date; // user-visible date
	es->sid  = s->uniq_id;
	es->srv  = objt_server(s->target);
	es->oe   = other_end;
	if (objt_conn(sess->origin))
		es->src  = __objt_conn(sess->origin)->addr.from;
	else
		memset(&es->src, 0, sizeof(es->src));

	es->state = state;
	es->ev_id = error_snapshot_id++;
	es->b_flags = chn->flags;
	es->s_flags = s->flags;
	es->t_flags = s->txn->flags;
	es->m_flags = msg->flags;
	es->b_out = chn->buf->o;
	es->b_wrap = chn->buf->data + chn->buf->size - chn->buf->p;
	es->b_tot = chn->total;
	es->m_clen = msg->chunk_len;
	es->m_blen = msg->body_len;
	HA_SPIN_UNLOCK(PROXY_LOCK, &proxy->lock);
}

/* Return in <vptr> and <vlen> the pointer and length of occurrence <occ> of
 * header whose name is <hname> of length <hlen>. If <ctx> is null, lookup is
 * performed over the whole headers. Otherwise it must contain a valid header
 * context, initialised with ctx->idx=0 for the first lookup in a series. If
 * <occ> is positive or null, occurrence #occ from the beginning (or last ctx)
 * is returned. Occ #0 and #1 are equivalent. If <occ> is negative (and no less
 * than -MAX_HDR_HISTORY), the occurrence is counted from the last one which is
 * -1. The value fetch stops at commas, so this function is suited for use with
 * list headers.
 * The return value is 0 if nothing was found, or non-zero otherwise.
 */
unsigned int http_get_hdr(const struct http_msg *msg, const char *hname, int hlen,
			  struct hdr_idx *idx, int occ,
			  struct hdr_ctx *ctx, char **vptr, int *vlen)
{
	struct hdr_ctx local_ctx;
	char *ptr_hist[MAX_HDR_HISTORY];
	int len_hist[MAX_HDR_HISTORY];
	unsigned int hist_ptr;
	int found;

	if (!ctx) {
		local_ctx.idx = 0;
		ctx = &local_ctx;
	}

	if (occ >= 0) {
		/* search from the beginning */
		while (http_find_header2(hname, hlen, msg->chn->buf->p, idx, ctx)) {
			occ--;
			if (occ <= 0) {
				*vptr = ctx->line + ctx->val;
				*vlen = ctx->vlen;
				return 1;
			}
		}
		return 0;
	}

	/* negative occurrence, we scan all the list then walk back */
	if (-occ > MAX_HDR_HISTORY)
		return 0;

	found = hist_ptr = 0;
	while (http_find_header2(hname, hlen, msg->chn->buf->p, idx, ctx)) {
		ptr_hist[hist_ptr] = ctx->line + ctx->val;
		len_hist[hist_ptr] = ctx->vlen;
		if (++hist_ptr >= MAX_HDR_HISTORY)
			hist_ptr = 0;
		found++;
	}
	if (-occ > found)
		return 0;
	/* OK now we have the last occurrence in [hist_ptr-1], and we need to
	 * find occurrence -occ. 0 <= hist_ptr < MAX_HDR_HISTORY, and we have
	 * -10 <= occ <= -1. So we have to check [hist_ptr%MAX_HDR_HISTORY+occ]
	 * to remain in the 0..9 range.
	 */
	hist_ptr += occ + MAX_HDR_HISTORY;
	if (hist_ptr >= MAX_HDR_HISTORY)
		hist_ptr -= MAX_HDR_HISTORY;
	*vptr = ptr_hist[hist_ptr];
	*vlen = len_hist[hist_ptr];
	return 1;
}

/* Return in <vptr> and <vlen> the pointer and length of occurrence <occ> of
 * header whose name is <hname> of length <hlen>. If <ctx> is null, lookup is
 * performed over the whole headers. Otherwise it must contain a valid header
 * context, initialised with ctx->idx=0 for the first lookup in a series. If
 * <occ> is positive or null, occurrence #occ from the beginning (or last ctx)
 * is returned. Occ #0 and #1 are equivalent. If <occ> is negative (and no less
 * than -MAX_HDR_HISTORY), the occurrence is counted from the last one which is
 * -1. This function differs from http_get_hdr() in that it only returns full
 * line header values and does not stop at commas.
 * The return value is 0 if nothing was found, or non-zero otherwise.
 */
unsigned int http_get_fhdr(const struct http_msg *msg, const char *hname, int hlen,
			   struct hdr_idx *idx, int occ,
			   struct hdr_ctx *ctx, char **vptr, int *vlen)
{
	struct hdr_ctx local_ctx;
	char *ptr_hist[MAX_HDR_HISTORY];
	int len_hist[MAX_HDR_HISTORY];
	unsigned int hist_ptr;
	int found;

	if (!ctx) {
		local_ctx.idx = 0;
		ctx = &local_ctx;
	}

	if (occ >= 0) {
		/* search from the beginning */
		while (http_find_full_header2(hname, hlen, msg->chn->buf->p, idx, ctx)) {
			occ--;
			if (occ <= 0) {
				*vptr = ctx->line + ctx->val;
				*vlen = ctx->vlen;
				return 1;
			}
		}
		return 0;
	}

	/* negative occurrence, we scan all the list then walk back */
	if (-occ > MAX_HDR_HISTORY)
		return 0;

	found = hist_ptr = 0;
	while (http_find_full_header2(hname, hlen, msg->chn->buf->p, idx, ctx)) {
		ptr_hist[hist_ptr] = ctx->line + ctx->val;
		len_hist[hist_ptr] = ctx->vlen;
		if (++hist_ptr >= MAX_HDR_HISTORY)
			hist_ptr = 0;
		found++;
	}
	if (-occ > found)
		return 0;

	/* OK now we have the last occurrence in [hist_ptr-1], and we need to
	 * find occurrence -occ. 0 <= hist_ptr < MAX_HDR_HISTORY, and we have
	 * -10 <= occ <= -1. So we have to check [hist_ptr%MAX_HDR_HISTORY+occ]
	 * to remain in the 0..9 range.
	 */
	hist_ptr += occ + MAX_HDR_HISTORY;
	if (hist_ptr >= MAX_HDR_HISTORY)
		hist_ptr -= MAX_HDR_HISTORY;
	*vptr = ptr_hist[hist_ptr];
	*vlen = len_hist[hist_ptr];
	return 1;
}

/*
 * Print a debug line with a header. Always stop at the first CR or LF char,
 * so it is safe to pass it a full buffer if needed. If <err> is not NULL, an
 * arrow is printed after the line which contains the pointer.
 */
void debug_hdr(const char *dir, struct stream *s, const char *start, const char *end)
{
	struct session *sess = strm_sess(s);
	int max;

	chunk_printf(&trash, "%08x:%s.%s[%04x:%04x]: ", s->uniq_id, s->be->id,
		      dir,
		     objt_conn(sess->origin) ? (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
		     objt_cs(s->si[1].end) ? (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

	for (max = 0; start + max < end; max++)
		if (start[max] == '\r' || start[max] == '\n')
			break;

	UBOUND(max, trash.size - trash.len - 3);
	trash.len += strlcpy2(trash.str + trash.len, start, max + 1);
	trash.str[trash.len++] = '\n';
	shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
}


/* Allocate a new HTTP transaction for stream <s> unless there is one already.
 * The hdr_idx is allocated as well. In case of allocation failure, everything
 * allocated is freed and NULL is returned. Otherwise the new transaction is
 * assigned to the stream and returned.
 */
struct http_txn *http_alloc_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;

	if (txn)
		return txn;

	txn = pool_alloc(pool_head_http_txn);
	if (!txn)
		return txn;

	txn->hdr_idx.size = global.tune.max_http_hdr;
	txn->hdr_idx.v    = pool_alloc(pool_head_hdr_idx);
	if (!txn->hdr_idx.v) {
		pool_free(pool_head_http_txn, txn);
		return NULL;
	}

	s->txn = txn;
	return txn;
}

void http_txn_reset_req(struct http_txn *txn)
{
	txn->req.flags = 0;
	txn->req.sol = txn->req.eol = txn->req.eoh = 0; /* relative to the buffer */
	txn->req.next = 0;
	txn->req.chunk_len = 0LL;
	txn->req.body_len = 0LL;
	txn->req.msg_state = HTTP_MSG_RQBEFORE; /* at the very beginning of the request */
}

void http_txn_reset_res(struct http_txn *txn)
{
	txn->rsp.flags = 0;
	txn->rsp.sol = txn->rsp.eol = txn->rsp.eoh = 0; /* relative to the buffer */
	txn->rsp.next = 0;
	txn->rsp.chunk_len = 0LL;
	txn->rsp.body_len = 0LL;
	txn->rsp.msg_state = HTTP_MSG_RPBEFORE; /* at the very beginning of the response */
}

/*
 * Initialize a new HTTP transaction for stream <s>. It is assumed that all
 * the required fields are properly allocated and that we only need to (re)init
 * them. This should be used before processing any new request.
 */
void http_init_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;
	struct proxy *fe = strm_fe(s);

	txn->flags = 0;
	txn->status = -1;

	txn->cookie_first_date = 0;
	txn->cookie_last_date = 0;

	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;
	txn->uri = NULL;

	http_txn_reset_req(txn);
	http_txn_reset_res(txn);

	txn->req.chn = &s->req;
	txn->rsp.chn = &s->res;

	txn->auth.method = HTTP_AUTH_UNKNOWN;

	txn->req.err_pos = txn->rsp.err_pos = -2; /* block buggy requests/responses */
	if (fe->options2 & PR_O2_REQBUG_OK)
		txn->req.err_pos = -1;            /* let buggy requests pass */

	if (txn->hdr_idx.v)
		hdr_idx_init(&txn->hdr_idx);

	vars_init(&s->vars_txn,    SCOPE_TXN);
	vars_init(&s->vars_reqres, SCOPE_REQ);
}

/* to be used at the end of a transaction */
void http_end_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;
	struct proxy *fe = strm_fe(s);

	/* these ones will have been dynamically allocated */
	pool_free(pool_head_requri, txn->uri);
	pool_free(pool_head_capture, txn->cli_cookie);
	pool_free(pool_head_capture, txn->srv_cookie);
	pool_free(pool_head_uniqueid, s->unique_id);

	s->unique_id = NULL;
	txn->uri = NULL;
	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;

	if (s->req_cap) {
		struct cap_hdr *h;
		for (h = fe->req_cap; h; h = h->next)
			pool_free(h->pool, s->req_cap[h->index]);
		memset(s->req_cap, 0, fe->nb_req_cap * sizeof(void *));
	}

	if (s->res_cap) {
		struct cap_hdr *h;
		for (h = fe->rsp_cap; h; h = h->next)
			pool_free(h->pool, s->res_cap[h->index]);
		memset(s->res_cap, 0, fe->nb_rsp_cap * sizeof(void *));
	}

	vars_prune(&s->vars_txn, s->sess, s);
	vars_prune(&s->vars_reqres, s->sess, s);
}

/* to be used at the end of a transaction to prepare a new one */
void http_reset_txn(struct stream *s)
{
	http_end_txn(s);
	http_init_txn(s);

	/* reinitialise the current rule list pointer to NULL. We are sure that
	 * any rulelist match the NULL pointer.
	 */
	s->current_rule_list = NULL;

	s->be = strm_fe(s);
	s->logs.logwait = strm_fe(s)->to_log;
	s->logs.level = 0;
	stream_del_srv_conn(s);
	s->target = NULL;
	/* re-init store persistence */
	s->store_count = 0;
	s->uniq_id = global.req_count++;

	s->pend_pos = NULL;

	s->req.flags |= CF_READ_DONTWAIT; /* one read is usually enough */

	/* We must trim any excess data from the response buffer, because we
	 * may have blocked an invalid response from a server that we don't
	 * want to accidentely forward once we disable the analysers, nor do
	 * we want those data to come along with next response. A typical
	 * example of such data would be from a buggy server responding to
	 * a HEAD with some data, or sending more than the advertised
	 * content-length.
	 */
	if (unlikely(s->res.buf->i))
		s->res.buf->i = 0;

	/* Now we can realign the response buffer */
	buffer_realign(s->res.buf);

	s->req.rto = strm_fe(s)->timeout.client;
	s->req.wto = TICK_ETERNITY;

	s->res.rto = TICK_ETERNITY;
	s->res.wto = strm_fe(s)->timeout.client;

	s->req.rex = TICK_ETERNITY;
	s->req.wex = TICK_ETERNITY;
	s->req.analyse_exp = TICK_ETERNITY;
	s->res.rex = TICK_ETERNITY;
	s->res.wex = TICK_ETERNITY;
	s->res.analyse_exp = TICK_ETERNITY;
	s->si[1].hcto = TICK_ETERNITY;
}

void free_http_res_rules(struct list *r)
{
	struct act_rule *tr, *pr;

	list_for_each_entry_safe(pr, tr, r, list) {
		LIST_DEL(&pr->list);
		regex_free(&pr->arg.hdr_add.re);
		free(pr);
	}
}

void free_http_req_rules(struct list *r)
{
	struct act_rule *tr, *pr;

	list_for_each_entry_safe(pr, tr, r, list) {
		LIST_DEL(&pr->list);
		if (pr->action == ACT_HTTP_REQ_AUTH)
			free(pr->arg.auth.realm);

		regex_free(&pr->arg.hdr_add.re);
		free(pr);
	}
}

/* parse an "http-request" rule */
struct act_rule *parse_http_req_cond(const char **args, const char *file, int linenum, struct proxy *proxy)
{
	struct act_rule *rule;
	struct action_kw *custom = NULL;
	int cur_arg;
	char *error;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		goto out_err;
	}

	if (!strcmp(args[0], "allow")) {
		rule->action = ACT_ACTION_ALLOW;
		cur_arg = 1;
	} else if (!strcmp(args[0], "deny") || !strcmp(args[0], "block") || !strcmp(args[0], "tarpit")) {
		int code;
		int hc;

		if (!strcmp(args[0], "tarpit")) {
		    rule->action = ACT_HTTP_REQ_TARPIT;
		    rule->deny_status = HTTP_ERR_500;
		}
		else {
			rule->action = ACT_ACTION_DENY;
			rule->deny_status = HTTP_ERR_403;
		}
		cur_arg = 1;
                if (strcmp(args[cur_arg], "deny_status") == 0) {
                        cur_arg++;
                        if (!args[cur_arg]) {
                                ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : missing status code.\n",
					 file, linenum, proxy_type_str(proxy), proxy->id, args[0]);
                                goto out_err;
                        }

                        code = atol(args[cur_arg]);
                        cur_arg++;
                        for (hc = 0; hc < HTTP_ERR_SIZE; hc++) {
                                if (http_err_codes[hc] == code) {
                                        rule->deny_status = hc;
                                        break;
                                }
                        }

                        if (hc >= HTTP_ERR_SIZE) {
                                ha_warning("parsing [%s:%d] : status code %d not handled, using default code %d.\n",
					   file, linenum, code, http_err_codes[rule->deny_status]);
                        }
                }
	} else if (!strcmp(args[0], "auth")) {
		rule->action = ACT_HTTP_REQ_AUTH;
		cur_arg = 1;

		while(*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "realm")) {
				rule->arg.auth.realm = strdup(args[cur_arg + 1]);
				cur_arg+=2;
				continue;
			} else
				break;
		}
	} else if (!strcmp(args[0], "set-nice")) {
		rule->action = ACT_HTTP_SET_NICE;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (integer value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		rule->arg.nice = atoi(args[cur_arg]);
		if (rule->arg.nice < -1024)
			rule->arg.nice = -1024;
		else if (rule->arg.nice > 1024)
			rule->arg.nice = 1024;
		cur_arg++;
	} else if (!strcmp(args[0], "set-tos")) {
#ifdef IP_TOS
		char *err;
		rule->action = ACT_HTTP_SET_TOS;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.tos = strtol(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-request %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
#else
		ha_alert("parsing [%s:%d]: 'http-request %s' is not supported on this platform (IP_TOS undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-mark")) {
#ifdef SO_MARK
		char *err;
		rule->action = ACT_HTTP_SET_MARK;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.mark = strtoul(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-request %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
		global.last_checks |= LSTCHK_NETADM;
#else
		ha_alert("parsing [%s:%d]: 'http-request %s' is not supported on this platform (SO_MARK undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-log-level")) {
		rule->action = ACT_HTTP_SET_LOGL;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
		bad_log_level:
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (log level name or 'silent').\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		if (strcmp(args[cur_arg], "silent") == 0)
			rule->arg.loglevel = -1;
		else if ((rule->arg.loglevel = get_log_level(args[cur_arg]) + 1) == 0)
			goto bad_log_level;
		cur_arg++;
	} else if (strcmp(args[0], "add-header") == 0 || strcmp(args[0], "set-header") == 0) {
		rule->action = *args[0] == 'a' ? ACT_HTTP_ADD_HDR : ACT_HTTP_SET_HDR;
		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);
		LIST_INIT(&rule->arg.hdr_add.fmt);

		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, &rule->arg.hdr_add.fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 2;
	} else if (strcmp(args[0], "replace-header") == 0 || strcmp(args[0], "replace-value") == 0) {
		rule->action = args[0][8] == 'h' ? ACT_HTTP_REPLACE_HDR : ACT_HTTP_REPLACE_VAL;
		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] || !*args[cur_arg+2] ||
		    (*args[cur_arg+3] && strcmp(args[cur_arg+3], "if") != 0 && strcmp(args[cur_arg+3], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 3 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);
		LIST_INIT(&rule->arg.hdr_add.fmt);

		error = NULL;
		if (!regex_comp(args[cur_arg + 1], &rule->arg.hdr_add.re, 1, 1, &error)) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 args[cur_arg + 1], error);
			free(error);
			goto out_err;
		}

		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 2], proxy, &rule->arg.hdr_add.fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 3;
	} else if (strcmp(args[0], "del-header") == 0) {
		rule->action = ACT_HTTP_DEL_HDR;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);

		proxy->conf.args.ctx = ARGC_HRQ;
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "track-sc", 8) == 0 &&
		 args[0][9] == '\0' && args[0][8] >= '0' &&
		 args[0][8] < '0' + MAX_SESS_STKCTR) { /* track-sc 0..9 */
		struct sample_expr *expr;
		unsigned int where;
		char *err = NULL;

		cur_arg = 1;
		proxy->conf.args.ctx = ARGC_TRK;

		expr = sample_parse_expr((char **)args, &cur_arg, file, linenum, &err, &proxy->conf.args);
		if (!expr) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], err);
			free(err);
			goto out_err;
		}

		where = 0;
		if (proxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (proxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;

		if (!(expr->fetch->val & where)) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule :"
				 " fetch method '%s' extracts information from '%s', none of which is available here.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0],
				 args[cur_arg-1], sample_src_names(expr->fetch->use));
			free(expr);
			goto out_err;
		}

		if (strcmp(args[cur_arg], "table") == 0) {
			cur_arg++;
			if (!args[cur_arg]) {
				ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : missing table name.\n",
					 file, linenum, proxy_type_str(proxy), proxy->id, args[0]);
				free(expr);
				goto out_err;
			}
			/* we copy the table name for now, it will be resolved later */
			rule->arg.trk_ctr.table.n = strdup(args[cur_arg]);
			cur_arg++;
		}
		rule->arg.trk_ctr.expr = expr;
		rule->action = ACT_ACTION_TRK_SC0 + args[0][8] - '0';
		rule->check_ptr = check_trk_action;
	} else if (strcmp(args[0], "redirect") == 0) {
		struct redirect_rule *redir;
		char *errmsg = NULL;

		if ((redir = http_parse_redirect_rule(file, linenum, proxy, (const char **)args + 1, &errmsg, 1, 0)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			goto out_err;
		}

		/* this redirect rule might already contain a parsed condition which
		 * we'll pass to the http-request rule.
		 */
		rule->action = ACT_HTTP_REDIR;
		rule->arg.redir = redir;
		rule->cond = redir->cond;
		redir->cond = NULL;
		cur_arg = 2;
		return rule;
	} else if (strncmp(args[0], "add-acl", 7) == 0) {
		/* http-request add-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_ADD_ACL;
		/*
		 * '+ 8' for 'add-acl('
		 * '- 9' for 'add-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "del-acl", 7) == 0) {
		/* http-request del-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_ACL;
		/*
		 * '+ 8' for 'del-acl('
		 * '- 9' for 'del-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "del-map", 7) == 0) {
		/* http-request del-map(<reference (map name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_MAP;
		/*
		 * '+ 8' for 'del-map('
		 * '- 9' for 'del-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "set-map", 7) == 0) {
		/* http-request set-map(<reference (map name)>) <key pattern> <value pattern> */
		rule->action = ACT_HTTP_SET_MAP;
		/*
		 * '+ 8' for 'set-map('
		 * '- 9' for 'set-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		LIST_INIT(&rule->arg.map.value);
		proxy->conf.args.ctx = ARGC_HRQ;

		/* key pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' key: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		/* value pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, &rule->arg.map.value, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' pattern: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;

		cur_arg += 2;
	} else if (((custom = action_http_req_custom(args[0])) != NULL)) {
		char *errmsg = NULL;
		cur_arg = 1;
		/* try in the module list */
		rule->from = ACT_F_HTTP_REQ;
		rule->kw = custom;
		if (custom->parse(args, &cur_arg, proxy, rule, &errmsg) == ACT_RET_PRS_ERR) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
	} else {
		action_build_list(&http_req_keywords.list, &trash);
		ha_alert("parsing [%s:%d]: 'http-request' expects 'allow', 'deny', 'auth', 'redirect', "
			 "'tarpit', 'add-header', 'set-header', 'replace-header', 'replace-value', 'set-nice', "
			 "'set-tos', 'set-mark', 'set-log-level', 'add-acl', 'del-acl', 'del-map', 'set-map', 'track-sc*'"
			 "%s%s, but got '%s'%s.\n",
			 file, linenum, *trash.str ? ", " : "", trash.str, args[0], *args[0] ? "" : " (missing argument)");
		goto out_err;
	}

	if (strcmp(args[cur_arg], "if") == 0 || strcmp(args[cur_arg], "unless") == 0) {
		struct acl_cond *cond;
		char *errmsg = NULL;

		if ((cond = build_acl_cond(file, linenum, &proxy->acl, proxy, args+cur_arg, &errmsg)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing an 'http-request %s' condition : %s.\n",
				 file, linenum, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		rule->cond = cond;
	}
	else if (*args[cur_arg]) {
		ha_alert("parsing [%s:%d]: 'http-request %s' expects 'realm' for 'auth' or"
			 " either 'if' or 'unless' followed by a condition but found '%s'.\n",
			 file, linenum, args[0], args[cur_arg]);
		goto out_err;
	}

	return rule;
 out_err:
	free(rule);
	return NULL;
}

/* parse an "http-respose" rule */
struct act_rule *parse_http_res_cond(const char **args, const char *file, int linenum, struct proxy *proxy)
{
	struct act_rule *rule;
	struct action_kw *custom = NULL;
	int cur_arg;
	char *error;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		goto out_err;
	}

	if (!strcmp(args[0], "allow")) {
		rule->action = ACT_ACTION_ALLOW;
		cur_arg = 1;
	} else if (!strcmp(args[0], "deny")) {
		rule->action = ACT_ACTION_DENY;
		cur_arg = 1;
	} else if (!strcmp(args[0], "set-nice")) {
		rule->action = ACT_HTTP_SET_NICE;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (integer value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		rule->arg.nice = atoi(args[cur_arg]);
		if (rule->arg.nice < -1024)
			rule->arg.nice = -1024;
		else if (rule->arg.nice > 1024)
			rule->arg.nice = 1024;
		cur_arg++;
	} else if (!strcmp(args[0], "set-tos")) {
#ifdef IP_TOS
		char *err;
		rule->action = ACT_HTTP_SET_TOS;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.tos = strtol(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-response %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
#else
		ha_alert("parsing [%s:%d]: 'http-response %s' is not supported on this platform (IP_TOS undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-mark")) {
#ifdef SO_MARK
		char *err;
		rule->action = ACT_HTTP_SET_MARK;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.mark = strtoul(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-response %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
		global.last_checks |= LSTCHK_NETADM;
#else
		ha_alert("parsing [%s:%d]: 'http-response %s' is not supported on this platform (SO_MARK undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-log-level")) {
		rule->action = ACT_HTTP_SET_LOGL;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
		bad_log_level:
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (log level name or 'silent').\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		if (strcmp(args[cur_arg], "silent") == 0)
			rule->arg.loglevel = -1;
		else if ((rule->arg.loglevel = get_log_level(args[cur_arg]) + 1) == 0)
			goto bad_log_level;
		cur_arg++;
	} else if (strcmp(args[0], "add-header") == 0 || strcmp(args[0], "set-header") == 0) {
		rule->action = *args[0] == 'a' ? ACT_HTTP_ADD_HDR : ACT_HTTP_SET_HDR;
		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);
		LIST_INIT(&rule->arg.hdr_add.fmt);

		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, &rule->arg.hdr_add.fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 2;
	} else if (strcmp(args[0], "replace-header") == 0 || strcmp(args[0], "replace-value") == 0) {
		rule->action = args[0][8] == 'h' ? ACT_HTTP_REPLACE_HDR : ACT_HTTP_REPLACE_VAL;
		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] || !*args[cur_arg+2] ||
		    (*args[cur_arg+3] && strcmp(args[cur_arg+3], "if") != 0 && strcmp(args[cur_arg+3], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 3 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);
		LIST_INIT(&rule->arg.hdr_add.fmt);

		error = NULL;
		if (!regex_comp(args[cur_arg + 1], &rule->arg.hdr_add.re, 1, 1, &error)) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 args[cur_arg + 1], error);
			free(error);
			goto out_err;
		}

		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 2], proxy, &rule->arg.hdr_add.fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 3;
	} else if (strcmp(args[0], "del-header") == 0) {
		rule->action = ACT_HTTP_DEL_HDR;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);

		proxy->conf.args.ctx = ARGC_HRS;
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "add-acl", 7) == 0) {
		/* http-request add-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_ADD_ACL;
		/*
		 * '+ 8' for 'add-acl('
		 * '- 9' for 'add-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;

		cur_arg += 1;
	} else if (strncmp(args[0], "del-acl", 7) == 0) {
		/* http-response del-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_ACL;
		/*
		 * '+ 8' for 'del-acl('
		 * '- 9' for 'del-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "del-map", 7) == 0) {
		/* http-response del-map(<reference (map name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_MAP;
		/*
		 * '+ 8' for 'del-map('
		 * '- 9' for 'del-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "set-map", 7) == 0) {
		/* http-response set-map(<reference (map name)>) <key pattern> <value pattern> */
		rule->action = ACT_HTTP_SET_MAP;
		/*
		 * '+ 8' for 'set-map('
		 * '- 9' for 'set-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		LIST_INIT(&rule->arg.map.value);

		proxy->conf.args.ctx = ARGC_HRS;

		/* key pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' name: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		/* value pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, &rule->arg.map.value, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' value: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;

		cur_arg += 2;
	} else if (strcmp(args[0], "redirect") == 0) {
		struct redirect_rule *redir;
		char *errmsg = NULL;

		if ((redir = http_parse_redirect_rule(file, linenum, proxy, (const char **)args + 1, &errmsg, 1, 1)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			goto out_err;
		}

		/* this redirect rule might already contain a parsed condition which
		 * we'll pass to the http-request rule.
		 */
		rule->action = ACT_HTTP_REDIR;
		rule->arg.redir = redir;
		rule->cond = redir->cond;
		redir->cond = NULL;
		cur_arg = 2;
		return rule;
	} else if (strncmp(args[0], "track-sc", 8) == 0 &&
	                   args[0][9] == '\0' && args[0][8] >= '0' &&
	                   args[0][8] < '0' + MAX_SESS_STKCTR) { /* track-sc 0..9 */
		struct sample_expr *expr;
		unsigned int where;
		char *err = NULL;

		cur_arg = 1;
		proxy->conf.args.ctx = ARGC_TRK;

		expr = sample_parse_expr((char **)args, &cur_arg, file, linenum, &err, &proxy->conf.args);
		if (!expr) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], err);
			free(err);
			goto out_err;
		}

		where = 0;
		if (proxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRS_HDR;
		if (proxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRS_HDR;

		if (!(expr->fetch->val & where)) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule :"
				 " fetch method '%s' extracts information from '%s', none of which is available here.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0],
				 args[cur_arg-1], sample_src_names(expr->fetch->use));
			free(expr);
			goto out_err;
		}

		if (strcmp(args[cur_arg], "table") == 0) {
			cur_arg++;
			if (!args[cur_arg]) {
				ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : missing table name.\n",
					 file, linenum, proxy_type_str(proxy), proxy->id, args[0]);
				free(expr);
				goto out_err;
			}
			/* we copy the table name for now, it will be resolved later */
			rule->arg.trk_ctr.table.n = strdup(args[cur_arg]);
			cur_arg++;
		}
		rule->arg.trk_ctr.expr = expr;
		rule->action = ACT_ACTION_TRK_SC0 + args[0][8] - '0';
		rule->check_ptr = check_trk_action;
	} else if (((custom = action_http_res_custom(args[0])) != NULL)) {
		char *errmsg = NULL;
		cur_arg = 1;
		/* try in the module list */
		rule->from = ACT_F_HTTP_RES;
		rule->kw = custom;
		if (custom->parse(args, &cur_arg, proxy, rule, &errmsg) == ACT_RET_PRS_ERR) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
	} else {
		action_build_list(&http_res_keywords.list, &trash);
		ha_alert("parsing [%s:%d]: 'http-response' expects 'allow', 'deny', 'redirect', "
			 "'add-header', 'del-header', 'set-header', 'replace-header', 'replace-value', 'set-nice', "
			 "'set-tos', 'set-mark', 'set-log-level', 'add-acl', 'del-acl', 'del-map', 'set-map', 'track-sc*'"
			 "%s%s, but got '%s'%s.\n",
			 file, linenum, *trash.str ? ", " : "", trash.str, args[0], *args[0] ? "" : " (missing argument)");
		goto out_err;
	}

	if (strcmp(args[cur_arg], "if") == 0 || strcmp(args[cur_arg], "unless") == 0) {
		struct acl_cond *cond;
		char *errmsg = NULL;

		if ((cond = build_acl_cond(file, linenum, &proxy->acl, proxy, args+cur_arg, &errmsg)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing an 'http-response %s' condition : %s.\n",
				 file, linenum, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		rule->cond = cond;
	}
	else if (*args[cur_arg]) {
		ha_alert("parsing [%s:%d]: 'http-response %s' expects"
			 " either 'if' or 'unless' followed by a condition but found '%s'.\n",
			 file, linenum, args[0], args[cur_arg]);
		goto out_err;
	}

	return rule;
 out_err:
	free(rule);
	return NULL;
}

/* Parses a redirect rule. Returns the redirect rule on success or NULL on error,
 * with <err> filled with the error message. If <use_fmt> is not null, builds a
 * dynamic log-format rule instead of a static string. Parameter <dir> indicates
 * the direction of the rule, and equals 0 for request, non-zero for responses.
 */
struct redirect_rule *http_parse_redirect_rule(const char *file, int linenum, struct proxy *curproxy,
                                               const char **args, char **errmsg, int use_fmt, int dir)
{
	struct redirect_rule *rule;
	int cur_arg;
	int type = REDIRECT_TYPE_NONE;
	int code = 302;
	const char *destination = NULL;
	const char *cookie = NULL;
	int cookie_set = 0;
	unsigned int flags = REDIRECT_FLAG_NONE;
	struct acl_cond *cond = NULL;

	cur_arg = 0;
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "location") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			type = REDIRECT_TYPE_LOCATION;
			cur_arg++;
			destination = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "prefix") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;
			type = REDIRECT_TYPE_PREFIX;
			cur_arg++;
			destination = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "scheme") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			type = REDIRECT_TYPE_SCHEME;
			cur_arg++;
			destination = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "set-cookie") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			cur_arg++;
			cookie = args[cur_arg];
			cookie_set = 1;
		}
		else if (strcmp(args[cur_arg], "clear-cookie") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			cur_arg++;
			cookie = args[cur_arg];
			cookie_set = 0;
		}
		else if (strcmp(args[cur_arg], "code") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			cur_arg++;
			code = atol(args[cur_arg]);
			if (code < 301 || code > 308 || (code > 303 && code < 307)) {
				memprintf(errmsg,
				          "'%s': unsupported HTTP code '%s' (must be one of 301, 302, 303, 307 or 308)",
				          args[cur_arg - 1], args[cur_arg]);
				return NULL;
			}
		}
		else if (!strcmp(args[cur_arg],"drop-query")) {
			flags |= REDIRECT_FLAG_DROP_QS;
		}
		else if (!strcmp(args[cur_arg],"append-slash")) {
			flags |= REDIRECT_FLAG_APPEND_SLASH;
		}
		else if (strcmp(args[cur_arg], "if") == 0 ||
			 strcmp(args[cur_arg], "unless") == 0) {
			cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + cur_arg, errmsg);
			if (!cond) {
				memprintf(errmsg, "error in condition: %s", *errmsg);
				return NULL;
			}
			break;
		}
		else {
			memprintf(errmsg,
			          "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'clear-cookie', 'drop-query' or 'append-slash' (was '%s')",
			          args[cur_arg]);
			return NULL;
		}
		cur_arg++;
	}

	if (type == REDIRECT_TYPE_NONE) {
		memprintf(errmsg, "redirection type expected ('prefix', 'location', or 'scheme')");
		return NULL;
	}

	if (dir && type != REDIRECT_TYPE_LOCATION) {
		memprintf(errmsg, "response only supports redirect type 'location'");
		return NULL;
	}

	rule = calloc(1, sizeof(*rule));
	rule->cond = cond;
	LIST_INIT(&rule->rdr_fmt);

	if (!use_fmt) {
		/* old-style static redirect rule */
		rule->rdr_str = strdup(destination);
		rule->rdr_len = strlen(destination);
	}
	else {
		/* log-format based redirect rule */

		/* Parse destination. Note that in the REDIRECT_TYPE_PREFIX case,
		 * if prefix == "/", we don't want to add anything, otherwise it
		 * makes it hard for the user to configure a self-redirection.
		 */
		curproxy->conf.args.ctx = ARGC_RDR;
		if (!(type == REDIRECT_TYPE_PREFIX && destination[0] == '/' && destination[1] == '\0')) {
			if (!parse_logformat_string(destination, curproxy, &rule->rdr_fmt, LOG_OPT_HTTP,
			                            dir ? (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRS_HDR : SMP_VAL_BE_HRS_HDR
			                                : (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
			                            errmsg)) {
				return  NULL;
			}
			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;
		}
	}

	if (cookie) {
		/* depending on cookie_set, either we want to set the cookie, or to clear it.
		 * a clear consists in appending "; path=/; Max-Age=0;" at the end.
		 */
		rule->cookie_len = strlen(cookie);
		if (cookie_set) {
			rule->cookie_str = malloc(rule->cookie_len + 10);
			memcpy(rule->cookie_str, cookie, rule->cookie_len);
			memcpy(rule->cookie_str + rule->cookie_len, "; path=/;", 10);
			rule->cookie_len += 9;
		} else {
			rule->cookie_str = malloc(rule->cookie_len + 21);
			memcpy(rule->cookie_str, cookie, rule->cookie_len);
			memcpy(rule->cookie_str + rule->cookie_len, "; path=/; Max-Age=0;", 21);
			rule->cookie_len += 20;
		}
	}
	rule->type = type;
	rule->code = code;
	rule->flags = flags;
	LIST_INIT(&rule->list);
	return rule;

 missing_arg:
	memprintf(errmsg, "missing argument for '%s'", args[cur_arg]);
	return NULL;
}

/************************************************************************/
/*        The code below is dedicated to ACL parsing and matching       */
/************************************************************************/


/* This function ensures that the prerequisites for an L7 fetch are ready,
 * which means that a request or response is ready. If some data is missing,
 * a parsing attempt is made. This is useful in TCP-based ACLs which are able
 * to extract data from L7. If <req_vol> is non-null during a request prefetch,
 * another test is made to ensure the required information is not gone.
 *
 * The function returns :
 *   0 with SMP_F_MAY_CHANGE in the sample flags if some data is missing to
 *     decide whether or not an HTTP message is present ;
 *   0 if the requested data cannot be fetched or if it is certain that
 *     we'll never have any HTTP message there ;
 *   1 if an HTTP message is ready
 */
int smp_prefetch_http(struct proxy *px, struct stream *s, unsigned int opt,
                  const struct arg *args, struct sample *smp, int req_vol)
{
	struct http_txn *txn;
	struct http_msg *msg;

	/* Note: it is possible that <s> is NULL when called before stream
	 * initialization (eg: tcp-request connection), so this function is the
	 * one responsible for guarding against this case for all HTTP users.
	 */
	if (!s)
		return 0;

	if (!s->txn) {
		if (unlikely(!http_alloc_txn(s)))
			return 0; /* not enough memory */
		http_init_txn(s);
	}
	txn = s->txn;
	msg = &txn->req;

	/* Check for a dependency on a request */
	smp->data.type = SMP_T_BOOL;

	if ((opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) {
		/* If the buffer does not leave enough free space at the end,
		 * we must first realign it.
		 */
		if (s->req.buf->p > s->req.buf->data &&
		    s->req.buf->i + s->req.buf->p > s->req.buf->data + s->req.buf->size - global.tune.maxrewrite)
			buffer_slow_realign(s->req.buf);

		if (unlikely(txn->req.msg_state < HTTP_MSG_BODY)) {
			if (msg->msg_state == HTTP_MSG_ERROR)
				return 0;

			/* Try to decode HTTP request */
			if (likely(msg->next < s->req.buf->i))
				http_msg_analyzer(msg, &txn->hdr_idx);

			/* Still no valid request ? */
			if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
				if ((msg->msg_state == HTTP_MSG_ERROR) ||
				    buffer_full(s->req.buf, global.tune.maxrewrite)) {
					return 0;
				}
				/* wait for final state */
				smp->flags |= SMP_F_MAY_CHANGE;
				return 0;
			}

			/* OK we just got a valid HTTP request. We have some minor
			 * preparation to perform so that further checks can rely
			 * on HTTP tests.
			 */

			/* If the request was parsed but was too large, we must absolutely
			 * return an error so that it is not processed. At the moment this
			 * cannot happen, but if the parsers are to change in the future,
			 * we want this check to be maintained.
			 */
			if (unlikely(s->req.buf->i + s->req.buf->p >
				     s->req.buf->data + s->req.buf->size - global.tune.maxrewrite)) {
				msg->err_state = msg->msg_state;
				msg->msg_state = HTTP_MSG_ERROR;
				smp->data.u.sint = 1;
				return 1;
			}

			txn->meth = find_http_meth(msg->chn->buf->p, msg->sl.rq.m_l);
			if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
				s->flags |= SF_REDIRECTABLE;

			if (unlikely(msg->sl.rq.v_l == 0) && !http_upgrade_v09_to_v10(txn))
				return 0;
		}

		if (req_vol && txn->rsp.msg_state != HTTP_MSG_RPBEFORE) {
			return 0;  /* data might have moved and indexes changed */
		}

		/* otherwise everything's ready for the request */
	}
	else {
		/* Check for a dependency on a response */
		if (txn->rsp.msg_state < HTTP_MSG_BODY) {
			smp->flags |= SMP_F_MAY_CHANGE;
			return 0;
		}
	}

	/* everything's OK */
	smp->data.u.sint = 1;
	return 1;
}

/* 1. Check on METHOD
 * We use the pre-parsed method if it is known, and store its number as an
 * integer. If it is unknown, we use the pointer and the length.
 */
static int pat_parse_meth(const char *text, struct pattern *pattern, int mflags, char **err)
{
	int len, meth;

	len  = strlen(text);
	meth = find_http_meth(text, len);

	pattern->val.i = meth;
	if (meth == HTTP_METH_OTHER) {
		pattern->ptr.str = (char *)text;
		pattern->len = len;
	}
	else {
		pattern->ptr.str = NULL;
		pattern->len = 0;
	}
	return 1;
}

/* This function fetches the method of current HTTP request and stores
 * it in the global pattern struct as a chunk. There are two possibilities :
 *   - if the method is known (not HTTP_METH_OTHER), its identifier is stored
 *     in <len> and <ptr> is NULL ;
 *   - if the method is unknown (HTTP_METH_OTHER), <ptr> points to the text and
 *     <len> to its length.
 * This is intended to be used with pat_match_meth() only.
 */
static int
smp_fetch_meth(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int meth;
	struct http_txn *txn;

	CHECK_HTTP_MESSAGE_FIRST_PERM();

	txn = smp->strm->txn;
	meth = txn->meth;
	smp->data.type = SMP_T_METH;
	smp->data.u.meth.meth = meth;
	if (meth == HTTP_METH_OTHER) {
		if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
			/* ensure the indexes are not affected */
			return 0;
		smp->flags |= SMP_F_CONST;
		smp->data.u.meth.str.len = txn->req.sl.rq.m_l;
		smp->data.u.meth.str.str = txn->req.chn->buf->p;
	}
	smp->flags |= SMP_F_VOL_1ST;
	return 1;
}

/* See above how the method is stored in the global pattern */
static struct pattern *pat_match_meth(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct pattern_list *lst;
	struct pattern *pattern;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		/* well-known method */
		if (pattern->val.i != HTTP_METH_OTHER) {
			if (smp->data.u.meth.meth == pattern->val.i)
				return pattern;
			else
				continue;
		}

		/* Other method, we must compare the strings */
		if (pattern->len != smp->data.u.meth.str.len)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.u.meth.str.str, smp->data.u.meth.str.len) == 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.u.meth.str.str, smp->data.u.meth.str.len) == 0))
			return pattern;
	}
	return NULL;
}

static int
smp_fetch_rqver(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	char *ptr;
	int len;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	len = txn->req.sl.rq.v_l;
	ptr = txn->req.chn->buf->p + txn->req.sl.rq.v;

	while ((len-- > 0) && (*ptr++ != '/'));
	if (len <= 0)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = ptr;
	smp->data.u.str.len = len;

	smp->flags = SMP_F_VOL_1ST | SMP_F_CONST;
	return 1;
}

static int
smp_fetch_stver(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	char *ptr;
	int len;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	if (txn->rsp.msg_state < HTTP_MSG_BODY)
		return 0;

	len = txn->rsp.sl.st.v_l;
	ptr = txn->rsp.chn->buf->p;

	while ((len-- > 0) && (*ptr++ != '/'));
	if (len <= 0)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = ptr;
	smp->data.u.str.len = len;

	smp->flags = SMP_F_VOL_1ST | SMP_F_CONST;
	return 1;
}

/* 3. Check on Status Code. We manipulate integers here. */
static int
smp_fetch_stcode(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	char *ptr;
	int len;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	if (txn->rsp.msg_state < HTTP_MSG_BODY)
		return 0;

	len = txn->rsp.sl.st.c_l;
	ptr = txn->rsp.chn->buf->p + txn->rsp.sl.st.c;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = __strl2ui(ptr, len);
	smp->flags = SMP_F_VOL_1ST;
	return 1;
}

static int
smp_fetch_uniqueid(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (LIST_ISEMPTY(&smp->sess->fe->format_unique_id))
		return 0;

	if (!smp->strm->unique_id) {
		if ((smp->strm->unique_id = pool_alloc(pool_head_uniqueid)) == NULL)
			return 0;
		smp->strm->unique_id[0] = '\0';
	}
	smp->data.u.str.len = build_logline(smp->strm, smp->strm->unique_id,
	                                    UNIQUEID_LEN, &smp->sess->fe->format_unique_id);

	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = smp->strm->unique_id;
	smp->flags = SMP_F_CONST;
	return 1;
}

/* Returns a string block containing all headers including the
 * empty line wich separes headers from the body. This is useful
 * form some headers analysis.
 */
static int
smp_fetch_hdrs(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_msg *msg;
	struct hdr_idx *idx;
	struct http_txn *txn;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	idx = &txn->hdr_idx;
	msg = &txn->req;

	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = msg->chn->buf->p + hdr_idx_first_pos(idx);
	smp->data.u.str.len = msg->eoh - hdr_idx_first_pos(idx) + 1 +
	                      (msg->chn->buf->p[msg->eoh] == '\r');

	return 1;
}

/* Returns the header request in a length/value encoded format.
 * This is useful for exchanges with the SPOE.
 *
 * A "length value" is a multibyte code encoding numbers. It uses the
 * SPOE format. The encoding is the following:
 *
 * Each couple "header name" / "header value" is composed
 * like this:
 *    "length value" "header name bytes"
 *    "length value" "header value bytes"
 * When the last header is reached, the header name and the header
 * value are empty. Their length are 0
 */
static int
smp_fetch_hdrs_bin(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_msg *msg;
	struct chunk *temp;
	struct hdr_idx *idx;
	const char *cur_ptr, *cur_next, *p;
	int old_idx, cur_idx;
	struct hdr_idx_elem *cur_hdr;
	const char *hn, *hv;
	int hnl, hvl;
	int ret;
	struct http_txn *txn;
	char *buf;
	char *end;

	CHECK_HTTP_MESSAGE_FIRST();

	temp = get_trash_chunk();
	buf = temp->str;
	end = temp->str + temp->size;

	txn = smp->strm->txn;
	idx = &txn->hdr_idx;
	msg = &txn->req;

	/* Build array of headers. */
	old_idx = 0;
	cur_next = msg->chn->buf->p + hdr_idx_first_pos(idx);
	while (1) {
		cur_idx = idx->v[old_idx].next;
		if (!cur_idx)
			break;
		old_idx = cur_idx;

		cur_hdr  = &idx->v[cur_idx];
		cur_ptr  = cur_next;
		cur_next = cur_ptr + cur_hdr->len + cur_hdr->cr + 1;

		/* Now we have one full header at cur_ptr of len cur_hdr->len,
		 * and the next header starts at cur_next. We'll check
		 * this header in the list as well as against the default
		 * rule.
		 */

		/* look for ': *'. */
		hn = cur_ptr;
		for (p = cur_ptr; p < cur_ptr + cur_hdr->len && *p != ':'; p++);
		if (p >= cur_ptr+cur_hdr->len)
			continue;
		hnl = p - hn;
		p++;
		while (p < cur_ptr + cur_hdr->len && (*p == ' ' || *p == '\t'))
			p++;
		if (p >= cur_ptr + cur_hdr->len)
			continue;
		hv = p;
		hvl = cur_ptr + cur_hdr->len-p;

		/* encode the header name. */
		ret = encode_varint(hnl, &buf, end);
		if (ret == -1)
			return 0;
		if (buf + hnl > end)
			return 0;
		memcpy(buf, hn, hnl);
		buf += hnl;

		/* encode and copy the value. */
		ret = encode_varint(hvl, &buf, end);
		if (ret == -1)
			return 0;
		if (buf + hvl > end)
			return 0;
		memcpy(buf, hv, hvl);
		buf += hvl;
	}

	/* encode the end of the header list with empty
	 * header name and header value.
	 */
	ret = encode_varint(0, &buf, end);
	if (ret == -1)
		return 0;
	ret = encode_varint(0, &buf, end);
	if (ret == -1)
		return 0;

	/* Initialise sample data which will be filled. */
	smp->data.type = SMP_T_BIN;
	smp->data.u.str.str = temp->str;
	smp->data.u.str.len = buf - temp->str;
	smp->data.u.str.size = temp->size;

	return 1;
}

/* returns the longest available part of the body. This requires that the body
 * has been waited for using http-buffer-request.
 */
static int
smp_fetch_body(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_msg *msg;
	unsigned long len;
	unsigned long block1;
	char *body;
	struct chunk *temp;

	CHECK_HTTP_MESSAGE_FIRST();

	if ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ)
		msg = &smp->strm->txn->req;
	else
		msg = &smp->strm->txn->rsp;

	len  = http_body_bytes(msg);
	body = b_ptr(msg->chn->buf, -http_data_rewind(msg));

	block1 = len;
	if (block1 > msg->chn->buf->data + msg->chn->buf->size - body)
		block1 = msg->chn->buf->data + msg->chn->buf->size - body;

	if (block1 == len) {
		/* buffer is not wrapped (or empty) */
		smp->data.type = SMP_T_BIN;
		smp->data.u.str.str = body;
		smp->data.u.str.len = len;
		smp->flags = SMP_F_VOL_TEST | SMP_F_CONST;
	}
	else {
		/* buffer is wrapped, we need to defragment it */
		temp = get_trash_chunk();
		memcpy(temp->str, body, block1);
		memcpy(temp->str + block1, msg->chn->buf->data, len - block1);
		smp->data.type = SMP_T_BIN;
		smp->data.u.str.str = temp->str;
		smp->data.u.str.len = len;
		smp->flags = SMP_F_VOL_TEST;
	}
	return 1;
}


/* returns the available length of the body. This requires that the body
 * has been waited for using http-buffer-request.
 */
static int
smp_fetch_body_len(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_msg *msg;

	CHECK_HTTP_MESSAGE_FIRST();

	if ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ)
		msg = &smp->strm->txn->req;
	else
		msg = &smp->strm->txn->rsp;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = http_body_bytes(msg);

	smp->flags = SMP_F_VOL_TEST;
	return 1;
}


/* returns the advertised length of the body, or the advertised size of the
 * chunks available in the buffer. This requires that the body has been waited
 * for using http-buffer-request.
 */
static int
smp_fetch_body_size(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_msg *msg;

	CHECK_HTTP_MESSAGE_FIRST();

	if ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ)
		msg = &smp->strm->txn->req;
	else
		msg = &smp->strm->txn->rsp;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = msg->body_len;

	smp->flags = SMP_F_VOL_TEST;
	return 1;
}


/* 4. Check on URL/URI. A pointer to the URI is stored. */
static int
smp_fetch_url(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	smp->data.type = SMP_T_STR;
	smp->data.u.str.len = txn->req.sl.rq.u_l;
	smp->data.u.str.str = txn->req.chn->buf->p + txn->req.sl.rq.u;
	smp->flags = SMP_F_VOL_1ST | SMP_F_CONST;
	return 1;
}

static int
smp_fetch_url_ip(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	struct sockaddr_storage addr;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	url2sa(txn->req.chn->buf->p + txn->req.sl.rq.u, txn->req.sl.rq.u_l, &addr, NULL);
	if (((struct sockaddr_in *)&addr)->sin_family != AF_INET)
		return 0;

	smp->data.type = SMP_T_IPV4;
	smp->data.u.ipv4 = ((struct sockaddr_in *)&addr)->sin_addr;
	smp->flags = 0;
	return 1;
}

static int
smp_fetch_url_port(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	struct sockaddr_storage addr;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	url2sa(txn->req.chn->buf->p + txn->req.sl.rq.u, txn->req.sl.rq.u_l, &addr, NULL);
	if (((struct sockaddr_in *)&addr)->sin_family != AF_INET)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = ntohs(((struct sockaddr_in *)&addr)->sin_port);
	smp->flags = 0;
	return 1;
}

/* Fetch an HTTP header. A pointer to the beginning of the value is returned.
 * Accepts an optional argument of type string containing the header field name,
 * and an optional argument of type signed or unsigned integer to request an
 * explicit occurrence of the header. Note that in the event of a missing name,
 * headers are considered from the first one. It does not stop on commas and
 * returns full lines instead (useful for User-Agent or Date for example).
 */
static int
smp_fetch_fhdr(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct hdr_idx *idx;
	struct hdr_ctx *ctx = smp->ctx.a[0];
	const struct http_msg *msg;
	int occ = 0;
	const char *name_str = NULL;
	int name_len = 0;

	if (!ctx) {
		/* first call */
		ctx = &static_hdr_ctx;
		ctx->idx = 0;
		smp->ctx.a[0] = ctx;
	}

	if (args) {
		if (args[0].type != ARGT_STR)
			return 0;
		name_str = args[0].data.str.str;
		name_len = args[0].data.str.len;

		if (args[1].type == ARGT_SINT)
			occ = args[1].data.sint;
	}

	CHECK_HTTP_MESSAGE_FIRST();

	idx = &smp->strm->txn->hdr_idx;
	msg = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) ? &smp->strm->txn->req : &smp->strm->txn->rsp;

	if (ctx && !(smp->flags & SMP_F_NOT_LAST))
		/* search for header from the beginning */
		ctx->idx = 0;

	if (!occ && !(smp->opt & SMP_OPT_ITERATE))
		/* no explicit occurrence and single fetch => last header by default */
		occ = -1;

	if (!occ)
		/* prepare to report multiple occurrences for ACL fetches */
		smp->flags |= SMP_F_NOT_LAST;

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_VOL_HDR | SMP_F_CONST;
	if (http_get_fhdr(msg, name_str, name_len, idx, occ, ctx, &smp->data.u.str.str, &smp->data.u.str.len))
		return 1;

	smp->flags &= ~SMP_F_NOT_LAST;
	return 0;
}

/* 6. Check on HTTP header count. The number of occurrences is returned.
 * Accepts exactly 1 argument of type string. It does not stop on commas and
 * returns full lines instead (useful for User-Agent or Date for example).
 */
static int
smp_fetch_fhdr_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct hdr_idx *idx;
	struct hdr_ctx ctx;
	const struct http_msg *msg;
	int cnt;
	const char *name = NULL;
	int len = 0;

	if (args && args->type == ARGT_STR) {
		name = args->data.str.str;
		len = args->data.str.len;
	}

	CHECK_HTTP_MESSAGE_FIRST();

	idx = &smp->strm->txn->hdr_idx;
	msg = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) ? &smp->strm->txn->req : &smp->strm->txn->rsp;

	ctx.idx = 0;
	cnt = 0;
	while (http_find_full_header2(name, len, msg->chn->buf->p, idx, &ctx))
		cnt++;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = cnt;
	smp->flags = SMP_F_VOL_HDR;
	return 1;
}

static int
smp_fetch_hdr_names(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct hdr_idx *idx;
	struct hdr_ctx ctx;
	const struct http_msg *msg;
	struct chunk *temp;
	char del = ',';

	if (args && args->type == ARGT_STR)
		del = *args[0].data.str.str;

	CHECK_HTTP_MESSAGE_FIRST();

	idx = &smp->strm->txn->hdr_idx;
	msg = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) ? &smp->strm->txn->req : &smp->strm->txn->rsp;

	temp = get_trash_chunk();

	ctx.idx = 0;
	while (http_find_next_header(msg->chn->buf->p, idx, &ctx)) {
		if (temp->len)
			temp->str[temp->len++] = del;
		memcpy(temp->str + temp->len, ctx.line, ctx.del);
		temp->len += ctx.del;
	}

	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = temp->str;
	smp->data.u.str.len = temp->len;
	smp->flags = SMP_F_VOL_HDR;
	return 1;
}

/* Fetch an HTTP header. A pointer to the beginning of the value is returned.
 * Accepts an optional argument of type string containing the header field name,
 * and an optional argument of type signed or unsigned integer to request an
 * explicit occurrence of the header. Note that in the event of a missing name,
 * headers are considered from the first one.
 */
static int
smp_fetch_hdr(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct hdr_idx *idx;
	struct hdr_ctx *ctx = smp->ctx.a[0];
	const struct http_msg *msg;
	int occ = 0;
	const char *name_str = NULL;
	int name_len = 0;

	if (!ctx) {
		/* first call */
		ctx = &static_hdr_ctx;
		ctx->idx = 0;
		smp->ctx.a[0] = ctx;
	}

	if (args) {
		if (args[0].type != ARGT_STR)
			return 0;
		name_str = args[0].data.str.str;
		name_len = args[0].data.str.len;

		if (args[1].type == ARGT_SINT)
			occ = args[1].data.sint;
	}

	CHECK_HTTP_MESSAGE_FIRST();

	idx = &smp->strm->txn->hdr_idx;
	msg = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) ? &smp->strm->txn->req : &smp->strm->txn->rsp;

	if (ctx && !(smp->flags & SMP_F_NOT_LAST))
		/* search for header from the beginning */
		ctx->idx = 0;

	if (!occ && !(smp->opt & SMP_OPT_ITERATE))
		/* no explicit occurrence and single fetch => last header by default */
		occ = -1;

	if (!occ)
		/* prepare to report multiple occurrences for ACL fetches */
		smp->flags |= SMP_F_NOT_LAST;

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_VOL_HDR | SMP_F_CONST;
	if (http_get_hdr(msg, name_str, name_len, idx, occ, ctx, &smp->data.u.str.str, &smp->data.u.str.len))
		return 1;

	smp->flags &= ~SMP_F_NOT_LAST;
	return 0;
}

/* 6. Check on HTTP header count. The number of occurrences is returned.
 * Accepts exactly 1 argument of type string.
 */
static int
smp_fetch_hdr_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct hdr_idx *idx;
	struct hdr_ctx ctx;
	const struct http_msg *msg;
	int cnt;
	const char *name = NULL;
	int len = 0;

	if (args && args->type == ARGT_STR) {
		name = args->data.str.str;
		len = args->data.str.len;
	}

	CHECK_HTTP_MESSAGE_FIRST();

	idx = &smp->strm->txn->hdr_idx;
	msg = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) ? &smp->strm->txn->req : &smp->strm->txn->rsp;

	ctx.idx = 0;
	cnt = 0;
	while (http_find_header2(name, len, msg->chn->buf->p, idx, &ctx))
		cnt++;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = cnt;
	smp->flags = SMP_F_VOL_HDR;
	return 1;
}

/* Fetch an HTTP header's integer value. The integer value is returned. It
 * takes a mandatory argument of type string and an optional one of type int
 * to designate a specific occurrence. It returns an unsigned integer, which
 * may or may not be appropriate for everything.
 */
static int
smp_fetch_hdr_val(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int ret = smp_fetch_hdr(args, smp, kw, private);

	if (ret > 0) {
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = strl2ic(smp->data.u.str.str, smp->data.u.str.len);
	}

	return ret;
}

/* Fetch an HTTP header's IP value. takes a mandatory argument of type string
 * and an optional one of type int to designate a specific occurrence.
 * It returns an IPv4 or IPv6 address.
 */
static int
smp_fetch_hdr_ip(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int ret;

	while ((ret = smp_fetch_hdr(args, smp, kw, private)) > 0) {
		if (url2ipv4((char *)smp->data.u.str.str, &smp->data.u.ipv4)) {
			smp->data.type = SMP_T_IPV4;
			break;
		} else {
			struct chunk *temp = get_trash_chunk();
			if (smp->data.u.str.len < temp->size - 1) {
				memcpy(temp->str, smp->data.u.str.str, smp->data.u.str.len);
				temp->str[smp->data.u.str.len] = '\0';
				if (inet_pton(AF_INET6, temp->str, &smp->data.u.ipv6)) {
					smp->data.type = SMP_T_IPV6;
					break;
				}
			}
		}

		/* if the header doesn't match an IP address, fetch next one */
		if (!(smp->flags & SMP_F_NOT_LAST))
			return 0;
	}
	return ret;
}

/* 8. Check on URI PATH. A pointer to the PATH is stored. The path starts at
 * the first '/' after the possible hostname, and ends before the possible '?'.
 */
static int
smp_fetch_path(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	char *ptr, *end;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	end = txn->req.chn->buf->p + txn->req.sl.rq.u + txn->req.sl.rq.u_l;
	ptr = http_get_path(txn);
	if (!ptr)
		return 0;

	/* OK, we got the '/' ! */
	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = ptr;

	while (ptr < end && *ptr != '?')
		ptr++;

	smp->data.u.str.len = ptr - smp->data.u.str.str;
	smp->flags = SMP_F_VOL_1ST | SMP_F_CONST;
	return 1;
}

/* This produces a concatenation of the first occurrence of the Host header
 * followed by the path component if it begins with a slash ('/'). This means
 * that '*' will not be added, resulting in exactly the first Host entry.
 * If no Host header is found, then the path is returned as-is. The returned
 * value is stored in the trash so it does not need to be marked constant.
 * The returned sample is of type string.
 */
static int
smp_fetch_base(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	char *ptr, *end, *beg;
	struct hdr_ctx ctx;
	struct chunk *temp;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	ctx.idx = 0;
	if (!http_find_header2("Host", 4, txn->req.chn->buf->p, &txn->hdr_idx, &ctx) || !ctx.vlen)
		return smp_fetch_path(args, smp, kw, private);

	/* OK we have the header value in ctx.line+ctx.val for ctx.vlen bytes */
	temp = get_trash_chunk();
	memcpy(temp->str, ctx.line + ctx.val, ctx.vlen);
	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = temp->str;
	smp->data.u.str.len = ctx.vlen;

	/* now retrieve the path */
	end = txn->req.chn->buf->p + txn->req.sl.rq.u + txn->req.sl.rq.u_l;
	beg = http_get_path(txn);
	if (!beg)
		beg = end;

	for (ptr = beg; ptr < end && *ptr != '?'; ptr++);

	if (beg < ptr && *beg == '/') {
		memcpy(smp->data.u.str.str + smp->data.u.str.len, beg, ptr - beg);
		smp->data.u.str.len += ptr - beg;
	}

	smp->flags = SMP_F_VOL_1ST;
	return 1;
}

/* This produces a 32-bit hash of the concatenation of the first occurrence of
 * the Host header followed by the path component if it begins with a slash ('/').
 * This means that '*' will not be added, resulting in exactly the first Host
 * entry. If no Host header is found, then the path is used. The resulting value
 * is hashed using the path hash followed by a full avalanche hash and provides a
 * 32-bit integer value. This fetch is useful for tracking per-path activity on
 * high-traffic sites without having to store whole paths.
 */
int
smp_fetch_base32(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	struct hdr_ctx ctx;
	unsigned int hash = 0;
	char *ptr, *beg, *end;
	int len;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	ctx.idx = 0;
	if (http_find_header2("Host", 4, txn->req.chn->buf->p, &txn->hdr_idx, &ctx)) {
		/* OK we have the header value in ctx.line+ctx.val for ctx.vlen bytes */
		ptr = ctx.line + ctx.val;
		len = ctx.vlen;
		while (len--)
			hash = *(ptr++) + (hash << 6) + (hash << 16) - hash;
	}

	/* now retrieve the path */
	end = txn->req.chn->buf->p + txn->req.sl.rq.u + txn->req.sl.rq.u_l;
	beg = http_get_path(txn);
	if (!beg)
		beg = end;

	for (ptr = beg; ptr < end && *ptr != '?'; ptr++);

	if (beg < ptr && *beg == '/') {
		while (beg < ptr)
			hash = *(beg++) + (hash << 6) + (hash << 16) - hash;
	}
	hash = full_hash(hash);

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = hash;
	smp->flags = SMP_F_VOL_1ST;
	return 1;
}

/* This concatenates the source address with the 32-bit hash of the Host and
 * path as returned by smp_fetch_base32(). The idea is to have per-source and
 * per-path counters. The result is a binary block from 8 to 20 bytes depending
 * on the source address length. The path hash is stored before the address so
 * that in environments where IPv6 is insignificant, truncating the output to
 * 8 bytes would still work.
 */
static int
smp_fetch_base32_src(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct chunk *temp;
	struct connection *cli_conn = objt_conn(smp->sess->origin);

	if (!cli_conn)
		return 0;

	if (!smp_fetch_base32(args, smp, kw, private))
		return 0;

	temp = get_trash_chunk();
	*(unsigned int *)temp->str = htonl(smp->data.u.sint);
	temp->len += sizeof(unsigned int);

	switch (cli_conn->addr.from.ss_family) {
	case AF_INET:
		memcpy(temp->str + temp->len, &((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr, 4);
		temp->len += 4;
		break;
	case AF_INET6:
		memcpy(temp->str + temp->len, &((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_addr, 16);
		temp->len += 16;
		break;
	default:
		return 0;
	}

	smp->data.u.str = *temp;
	smp->data.type = SMP_T_BIN;
	return 1;
}

/* Extracts the query string, which comes after the question mark '?'. If no
 * question mark is found, nothing is returned. Otherwise it returns a sample
 * of type string carrying the whole query string.
 */
static int
smp_fetch_query(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	char *ptr, *end;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	ptr = txn->req.chn->buf->p + txn->req.sl.rq.u;
	end = ptr + txn->req.sl.rq.u_l;

	/* look up the '?' */
	do {
		if (ptr == end)
			return 0;
	} while (*ptr++ != '?');

	smp->data.type = SMP_T_STR;
	smp->data.u.str.str = ptr;
	smp->data.u.str.len = end - ptr;
	smp->flags = SMP_F_VOL_1ST | SMP_F_CONST;
	return 1;
}

static int
smp_fetch_proto_http(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	/* Note: hdr_idx.v cannot be NULL in this ACL because the ACL is tagged
	 * as a layer7 ACL, which involves automatic allocation of hdr_idx.
	 */

	CHECK_HTTP_MESSAGE_FIRST_PERM();

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = 1;
	return 1;
}

/* return a valid test if the current request is the first one on the connection */
static int
smp_fetch_http_first_req(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = !(smp->strm->txn->flags & TX_NOT_FIRST);
	return 1;
}

/* Accepts exactly 1 argument of type userlist */
static int
smp_fetch_http_auth(const struct arg *args, struct sample *smp, const char *kw, void *private)
{

	if (!args || args->type != ARGT_USR)
		return 0;

	CHECK_HTTP_MESSAGE_FIRST();

	if (!get_http_auth(smp->strm))
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = check_user(args->data.usr, smp->strm->txn->auth.user,
	                            smp->strm->txn->auth.pass);
	return 1;
}

/* Accepts exactly 1 argument of type userlist */
static int
smp_fetch_http_auth_grp(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!args || args->type != ARGT_USR)
		return 0;

	CHECK_HTTP_MESSAGE_FIRST();

	if (!get_http_auth(smp->strm))
		return 0;

	/* if the user does not belong to the userlist or has a wrong password,
	 * report that it unconditionally does not match. Otherwise we return
	 * a string containing the username.
	 */
	if (!check_user(args->data.usr, smp->strm->txn->auth.user,
	                smp->strm->txn->auth.pass))
		return 0;

	/* pat_match_auth() will need the user list */
	smp->ctx.a[0] = args->data.usr;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.str = smp->strm->txn->auth.user;
	smp->data.u.str.len = strlen(smp->strm->txn->auth.user);

	return 1;
}

/* Try to find the next occurrence of a cookie name in a cookie header value.
 * The lookup begins at <hdr>. The pointer and size of the next occurrence of
 * the cookie value is returned into *value and *value_l, and the function
 * returns a pointer to the next pointer to search from if the value was found.
 * Otherwise if the cookie was not found, NULL is returned and neither value
 * nor value_l are touched. The input <hdr> string should first point to the
 * header's value, and the <hdr_end> pointer must point to the first character
 * not part of the value. <list> must be non-zero if value may represent a list
 * of values (cookie headers). This makes it faster to abort parsing when no
 * list is expected.
 */
char *
extract_cookie_value(char *hdr, const char *hdr_end,
		  char *cookie_name, size_t cookie_name_l, int list,
		  char **value, int *value_l)
{
	char *equal, *att_end, *att_beg, *val_beg, *val_end;
	char *next;

	/* we search at least a cookie name followed by an equal, and more
	 * generally something like this :
	 * Cookie:    NAME1  =  VALUE 1  ; NAME2 = VALUE2 ; NAME3 = VALUE3\r\n
	 */
	for (att_beg = hdr; att_beg + cookie_name_l + 1 < hdr_end; att_beg = next + 1) {
		/* Iterate through all cookies on this line */

		while (att_beg < hdr_end && HTTP_IS_SPHT(*att_beg))
			att_beg++;

		/* find att_end : this is the first character after the last non
		 * space before the equal. It may be equal to hdr_end.
		 */
		equal = att_end = att_beg;

		while (equal < hdr_end) {
			if (*equal == '=' || *equal == ';' || (list && *equal == ','))
				break;
			if (HTTP_IS_SPHT(*equal++))
				continue;
			att_end = equal;
		}

		/* here, <equal> points to '=', a delimitor or the end. <att_end>
		 * is between <att_beg> and <equal>, both may be identical.
		 */

		/* look for end of cookie if there is an equal sign */
		if (equal < hdr_end && *equal == '=') {
			/* look for the beginning of the value */
			val_beg = equal + 1;
			while (val_beg < hdr_end && HTTP_IS_SPHT(*val_beg))
				val_beg++;

			/* find the end of the value, respecting quotes */
			next = find_cookie_value_end(val_beg, hdr_end);

			/* make val_end point to the first white space or delimitor after the value */
			val_end = next;
			while (val_end > val_beg && HTTP_IS_SPHT(*(val_end - 1)))
				val_end--;
		} else {
			val_beg = val_end = next = equal;
		}

		/* We have nothing to do with attributes beginning with '$'. However,
		 * they will automatically be removed if a header before them is removed,
		 * since they're supposed to be linked together.
		 */
		if (*att_beg == '$')
			continue;

		/* Ignore cookies with no equal sign */
		if (equal == next)
			continue;

		/* Now we have the cookie name between att_beg and att_end, and
		 * its value between val_beg and val_end.
		 */

		if (att_end - att_beg == cookie_name_l &&
		    memcmp(att_beg, cookie_name, cookie_name_l) == 0) {
			/* let's return this value and indicate where to go on from */
			*value = val_beg;
			*value_l = val_end - val_beg;
			return next + 1;
		}

		/* Set-Cookie headers only have the name in the first attr=value part */
		if (!list)
			break;
	}

	return NULL;
}

/* Fetch a captured HTTP request header. The index is the position of
 * the "capture" option in the configuration file
 */
static int
smp_fetch_capture_header_req(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *fe = strm_fe(smp->strm);
	int idx;

	if (!args || args->type != ARGT_SINT)
		return 0;

	idx = args->data.sint;

	if (idx > (fe->nb_req_cap - 1) || smp->strm->req_cap == NULL || smp->strm->req_cap[idx] == NULL)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.str = smp->strm->req_cap[idx];
	smp->data.u.str.len = strlen(smp->strm->req_cap[idx]);

	return 1;
}

/* Fetch a captured HTTP response header. The index is the position of
 * the "capture" option in the configuration file
 */
static int
smp_fetch_capture_header_res(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *fe = strm_fe(smp->strm);
	int idx;

	if (!args || args->type != ARGT_SINT)
		return 0;

	idx = args->data.sint;

	if (idx > (fe->nb_rsp_cap - 1) || smp->strm->res_cap == NULL || smp->strm->res_cap[idx] == NULL)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.str = smp->strm->res_cap[idx];
	smp->data.u.str.len = strlen(smp->strm->res_cap[idx]);

	return 1;
}

/* Extracts the METHOD in the HTTP request, the txn->uri should be filled before the call */
static int
smp_fetch_capture_req_method(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct chunk *temp;
	struct http_txn *txn = smp->strm->txn;
	char *ptr;

	if (!txn || !txn->uri)
		return 0;

	ptr = txn->uri;

	while (*ptr != ' ' && *ptr != '\0')  /* find first space */
		ptr++;

	temp = get_trash_chunk();
	temp->str = txn->uri;
	temp->len = ptr - txn->uri;
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;

	return 1;

}

/* Extracts the path in the HTTP request, the txn->uri should be filled before the call  */
static int
smp_fetch_capture_req_uri(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct chunk *temp;
	struct http_txn *txn = smp->strm->txn;
	char *ptr;

	if (!txn || !txn->uri)
		return 0;

	ptr = txn->uri;

	while (*ptr != ' ' && *ptr != '\0')  /* find first space */
		ptr++;

	if (!*ptr)
		return 0;

	ptr++;  /* skip the space */

	temp = get_trash_chunk();
	ptr = temp->str = http_get_path_from_string(ptr);
	if (!ptr)
		return 0;
	while (*ptr != ' ' && *ptr != '\0')  /* find space after URI */
		ptr++;

	smp->data.u.str = *temp;
	smp->data.u.str.len = ptr - temp->str;
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;

	return 1;
}

/* Retrieves the HTTP version from the request (either 1.0 or 1.1) and emits it
 * as a string (either "HTTP/1.0" or "HTTP/1.1").
 */
static int
smp_fetch_capture_req_ver(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn = smp->strm->txn;

	if (!txn || txn->req.msg_state < HTTP_MSG_HDR_FIRST)
		return 0;

	if (txn->req.flags & HTTP_MSGF_VER_11)
		smp->data.u.str.str = "HTTP/1.1";
	else
		smp->data.u.str.str = "HTTP/1.0";

	smp->data.u.str.len = 8;
	smp->data.type  = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	return 1;

}

/* Retrieves the HTTP version from the response (either 1.0 or 1.1) and emits it
 * as a string (either "HTTP/1.0" or "HTTP/1.1").
 */
static int
smp_fetch_capture_res_ver(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn = smp->strm->txn;

	if (!txn || txn->rsp.msg_state < HTTP_MSG_HDR_FIRST)
		return 0;

	if (txn->rsp.flags & HTTP_MSGF_VER_11)
		smp->data.u.str.str = "HTTP/1.1";
	else
		smp->data.u.str.str = "HTTP/1.0";

	smp->data.u.str.len = 8;
	smp->data.type  = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	return 1;

}


/* Iterate over all cookies present in a message. The context is stored in
 * smp->ctx.a[0] for the in-header position, smp->ctx.a[1] for the
 * end-of-header-value, and smp->ctx.a[2] for the hdr_ctx. Depending on
 * the direction, multiple cookies may be parsed on the same line or not.
 * The cookie name is in args and the name length in args->data.str.len.
 * Accepts exactly 1 argument of type string. If the input options indicate
 * that no iterating is desired, then only last value is fetched if any.
 * The returned sample is of type CSTR. Can be used to parse cookies in other
 * files.
 */
int smp_fetch_cookie(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	struct hdr_idx *idx;
	struct hdr_ctx *ctx = smp->ctx.a[2];
	const struct http_msg *msg;
	const char *hdr_name;
	int hdr_name_len;
	char *sol;
	int occ = 0;
	int found = 0;

	if (!args || args->type != ARGT_STR)
		return 0;

	if (!ctx) {
		/* first call */
		ctx = &static_hdr_ctx;
		ctx->idx = 0;
		smp->ctx.a[2] = ctx;
	}

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	idx = &smp->strm->txn->hdr_idx;

	if ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) {
		msg = &txn->req;
		hdr_name = "Cookie";
		hdr_name_len = 6;
	} else {
		msg = &txn->rsp;
		hdr_name = "Set-Cookie";
		hdr_name_len = 10;
	}

	if (!occ && !(smp->opt & SMP_OPT_ITERATE))
		/* no explicit occurrence and single fetch => last cookie by default */
		occ = -1;

	/* OK so basically here, either we want only one value and it's the
	 * last one, or we want to iterate over all of them and we fetch the
	 * next one.
	 */

	sol = msg->chn->buf->p;
	if (!(smp->flags & SMP_F_NOT_LAST)) {
		/* search for the header from the beginning, we must first initialize
		 * the search parameters.
		 */
		smp->ctx.a[0] = NULL;
		ctx->idx = 0;
	}

	smp->flags |= SMP_F_VOL_HDR;

	while (1) {
		/* Note: smp->ctx.a[0] == NULL every time we need to fetch a new header */
		if (!smp->ctx.a[0]) {
			if (!http_find_header2(hdr_name, hdr_name_len, sol, idx, ctx))
				goto out;

			if (ctx->vlen < args->data.str.len + 1)
				continue;

			smp->ctx.a[0] = ctx->line + ctx->val;
			smp->ctx.a[1] = smp->ctx.a[0] + ctx->vlen;
		}

		smp->data.type = SMP_T_STR;
		smp->flags |= SMP_F_CONST;
		smp->ctx.a[0] = extract_cookie_value(smp->ctx.a[0], smp->ctx.a[1],
						 args->data.str.str, args->data.str.len,
						 (smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ,
						 &smp->data.u.str.str,
						 &smp->data.u.str.len);
		if (smp->ctx.a[0]) {
			found = 1;
			if (occ >= 0) {
				/* one value was returned into smp->data.u.str.{str,len} */
				smp->flags |= SMP_F_NOT_LAST;
				return 1;
			}
		}
		/* if we're looking for last occurrence, let's loop */
	}
	/* all cookie headers and values were scanned. If we're looking for the
	 * last occurrence, we may return it now.
	 */
 out:
	smp->flags &= ~SMP_F_NOT_LAST;
	return found;
}

/* Iterate over all cookies present in a request to count how many occurrences
 * match the name in args and args->data.str.len. If <multi> is non-null, then
 * multiple cookies may be parsed on the same line. The returned sample is of
 * type UINT. Accepts exactly 1 argument of type string.
 */
static int
smp_fetch_cookie_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	struct hdr_idx *idx;
	struct hdr_ctx ctx;
	const struct http_msg *msg;
	const char *hdr_name;
	int hdr_name_len;
	int cnt;
	char *val_beg, *val_end;
	char *sol;

	if (!args || args->type != ARGT_STR)
		return 0;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	idx = &smp->strm->txn->hdr_idx;

	if ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ) {
		msg = &txn->req;
		hdr_name = "Cookie";
		hdr_name_len = 6;
	} else {
		msg = &txn->rsp;
		hdr_name = "Set-Cookie";
		hdr_name_len = 10;
	}

	sol = msg->chn->buf->p;
	val_end = val_beg = NULL;
	ctx.idx = 0;
	cnt = 0;

	while (1) {
		/* Note: val_beg == NULL every time we need to fetch a new header */
		if (!val_beg) {
			if (!http_find_header2(hdr_name, hdr_name_len, sol, idx, &ctx))
				break;

			if (ctx.vlen < args->data.str.len + 1)
				continue;

			val_beg = ctx.line + ctx.val;
			val_end = val_beg + ctx.vlen;
		}

		smp->data.type = SMP_T_STR;
		smp->flags |= SMP_F_CONST;
		while ((val_beg = extract_cookie_value(val_beg, val_end,
						       args->data.str.str, args->data.str.len,
						       (smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ,
						       &smp->data.u.str.str,
						       &smp->data.u.str.len))) {
			cnt++;
		}
	}

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = cnt;
	smp->flags |= SMP_F_VOL_HDR;
	return 1;
}

/* Fetch an cookie's integer value. The integer value is returned. It
 * takes a mandatory argument of type string. It relies on smp_fetch_cookie().
 */
static int
smp_fetch_cookie_val(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int ret = smp_fetch_cookie(args, smp, kw, private);

	if (ret > 0) {
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = strl2ic(smp->data.u.str.str, smp->data.u.str.len);
	}

	return ret;
}

/************************************************************************/
/*           The code below is dedicated to sample fetches              */
/************************************************************************/

/*
 * Given a path string and its length, find the position of beginning of the
 * query string. Returns NULL if no query string is found in the path.
 *
 * Example: if path = "/foo/bar/fubar?yo=mama;ye=daddy", and n = 22:
 *
 * find_query_string(path, n, '?') points to "yo=mama;ye=daddy" string.
 */
static inline char *find_param_list(char *path, size_t path_l, char delim)
{
	char *p;

	p = memchr(path, delim, path_l);
	return p ? p + 1 : NULL;
}

static inline int is_param_delimiter(char c, char delim)
{
	return c == '&' || c == ';' || c == delim;
}

/* after increasing a pointer value, it can exceed the first buffer
 * size. This function transform the value of <ptr> according with
 * the expected position. <chunks> is an array of the one or two
 * avalaible chunks. The first value is the start of the first chunk,
 * the second value if the end+1 of the first chunks. The third value
 * is NULL or the start of the second chunk and the fourth value is
 * the end+1 of the second chunk. The function returns 1 if does a
 * wrap, else returns 0.
 */
static inline int fix_pointer_if_wrap(const char **chunks, const char **ptr)
{
	if (*ptr < chunks[1])
		return 0;
	if (!chunks[2])
		return 0;
	*ptr = chunks[2] + ( *ptr - chunks[1] );
	return 1;
}

/*
 * Given a url parameter, find the starting position of the first occurence,
 * or NULL if the parameter is not found.
 *
 * Example: if query_string is "yo=mama;ye=daddy" and url_param_name is "ye",
 * the function will return query_string+8.
 *
 * Warning: this function returns a pointer that can point to the first chunk
 * or the second chunk. The caller must be check the position before using the
 * result.
 */
static const char *
find_url_param_pos(const char **chunks,
                   const char* url_param_name, size_t url_param_name_l,
                   char delim)
{
	const char *pos, *last, *equal;
	const char **bufs = chunks;
	int l1, l2;


	pos  = bufs[0];
	last = bufs[1];
	while (pos < last) {
		/* Check the equal. */
		equal = pos + url_param_name_l;
		if (fix_pointer_if_wrap(chunks, &equal)) {
			if (equal >= chunks[3])
				return NULL;
		} else {
			if (equal >= chunks[1])
				return NULL;
		}
		if (*equal == '=') {
			if (pos + url_param_name_l > last) {
				/* process wrap case, we detect a wrap. In this case, the
				 * comparison is performed in two parts.
				 */

				/* This is the end, we dont have any other chunk. */
				if (bufs != chunks || !bufs[2])
					return NULL;

				/* Compute the length of each part of the comparison. */
				l1 = last - pos;
				l2 = url_param_name_l - l1;

				/* The second buffer is too short to contain the compared string. */
				if (bufs[2] + l2 > bufs[3])
					return NULL;

				if (memcmp(pos,     url_param_name,    l1) == 0 &&
				    memcmp(bufs[2], url_param_name+l1, l2) == 0)
					return pos;

				/* Perform wrapping and jump the string who fail the comparison. */
				bufs += 2;
				pos = bufs[0] + l2;
				last = bufs[1];

			} else {
				/* process a simple comparison. */
				if (memcmp(pos, url_param_name, url_param_name_l) == 0)
					return pos;
				pos += url_param_name_l + 1;
				if (fix_pointer_if_wrap(chunks, &pos))
					last = bufs[2];
			}
		}

		while (1) {
			/* Look for the next delimiter. */
			while (pos < last && !is_param_delimiter(*pos, delim))
				pos++;
			if (pos < last)
				break;
			/* process buffer wrapping. */
			if (bufs != chunks || !bufs[2])
				return NULL;
			bufs += 2;
			pos = bufs[0];
			last = bufs[1];
		}
		pos++;
	}
	return NULL;
}

/*
 * Given a url parameter name and a query string, find the next value.
 * An empty url_param_name matches the first available parameter.
 * If the parameter is found, 1 is returned and *vstart / *vend are updated to
 * respectively provide a pointer to the value and its end.
 * Otherwise, 0 is returned and vstart/vend are not modified.
 */
static int
find_next_url_param(const char **chunks,
                    const char* url_param_name, size_t url_param_name_l,
                    const char **vstart, const char **vend, char delim)
{
	const char *arg_start, *qs_end;
	const char *value_start, *value_end;

	arg_start = chunks[0];
	qs_end = chunks[1];
	if (url_param_name_l) {
		/* Looks for an argument name. */
		arg_start = find_url_param_pos(chunks,
		                               url_param_name, url_param_name_l,
		                               delim);
		/* Check for wrapping. */
		if (arg_start >= qs_end)
			qs_end = chunks[3];
	}
	if (!arg_start)
		return 0;

	if (!url_param_name_l) {
		while (1) {
			/* looks for the first argument. */
			value_start = memchr(arg_start, '=', qs_end - arg_start);
			if (!value_start) {
				/* Check for wrapping. */
				if (arg_start >= chunks[0] &&
				    arg_start < chunks[1] &&
				    chunks[2]) {
					arg_start = chunks[2];
					qs_end = chunks[3];
					continue;
				}
				return 0;
			}
			break;
		}
		value_start++;
	}
	else {
		/* Jump the argument length. */
		value_start = arg_start + url_param_name_l + 1;

		/* Check for pointer wrapping. */
		if (fix_pointer_if_wrap(chunks, &value_start)) {
			/* Update the end pointer. */
			qs_end = chunks[3];

			/* Check for overflow. */
			if (value_start >= qs_end)
				return 0;
		}
	}

	value_end = value_start;

	while (1) {
		while ((value_end < qs_end) && !is_param_delimiter(*value_end, delim))
			value_end++;
		if (value_end < qs_end)
			break;
		/* process buffer wrapping. */
		if (value_end >= chunks[0] &&
		    value_end < chunks[1] &&
		    chunks[2]) {
			value_end = chunks[2];
			qs_end = chunks[3];
			continue;
		}
		break;
	}

	*vstart = value_start;
	*vend = value_end;
	return 1;
}

/* This scans a URL-encoded query string. It takes an optionally wrapping
 * string whose first contigous chunk has its beginning in ctx->a[0] and end
 * in ctx->a[1], and the optional second part in (ctx->a[2]..ctx->a[3]). The
 * pointers are updated for next iteration before leaving.
 */
static int
smp_fetch_param(char delim, const char *name, int name_len, const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	const char *vstart, *vend;
	struct chunk *temp;
	const char **chunks = (const char **)smp->ctx.a;

	if (!find_next_url_param(chunks,
	                         name, name_len,
	                         &vstart, &vend,
	                         delim))
		return 0;

	/* Create sample. If the value is contiguous, return the pointer as CONST,
	 * if the value is wrapped, copy-it in a buffer.
	 */
	smp->data.type = SMP_T_STR;
	if (chunks[2] &&
	    vstart >= chunks[0] && vstart <= chunks[1] &&
	    vend >= chunks[2] && vend <= chunks[3]) {
		/* Wrapped case. */
		temp = get_trash_chunk();
		memcpy(temp->str, vstart, chunks[1] - vstart);
		memcpy(temp->str + ( chunks[1] - vstart ), chunks[2], vend - chunks[2]);
		smp->data.u.str.str = temp->str;
		smp->data.u.str.len = ( chunks[1] - vstart ) + ( vend - chunks[2] );
	} else {
		/* Contiguous case. */
		smp->data.u.str.str = (char *)vstart;
		smp->data.u.str.len = vend - vstart;
		smp->flags = SMP_F_VOL_1ST | SMP_F_CONST;
	}

	/* Update context, check wrapping. */
	chunks[0] = vend;
	if (chunks[2] && vend >= chunks[2] && vend <= chunks[3]) {
		chunks[1] = chunks[3];
		chunks[2] = NULL;
	}

	if (chunks[0] < chunks[1])
		smp->flags |= SMP_F_NOT_LAST;

	return 1;
}

/* This function iterates over each parameter of the query string. It uses
 * ctx->a[0] and ctx->a[1] to store the beginning and end of the current
 * parameter. Since it uses smp_fetch_param(), ctx->a[2..3] are both NULL.
 * An optional parameter name is passed in args[0], otherwise any parameter is
 * considered. It supports an optional delimiter argument for the beginning of
 * the string in args[1], which defaults to "?".
 */
static int
smp_fetch_url_param(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_msg *msg;
	char delim = '?';
	const char *name;
	int name_len;

	if (!args ||
	    (args[0].type && args[0].type != ARGT_STR) ||
	    (args[1].type && args[1].type != ARGT_STR))
		return 0;

	name = "";
	name_len = 0;
	if (args->type == ARGT_STR) {
		name     = args->data.str.str;
		name_len = args->data.str.len;
	}

	if (args[1].type)
		delim = *args[1].data.str.str;

	if (!smp->ctx.a[0]) { // first call, find the query string
		CHECK_HTTP_MESSAGE_FIRST();

		msg = &smp->strm->txn->req;

		smp->ctx.a[0] = find_param_list(msg->chn->buf->p + msg->sl.rq.u,
		                                msg->sl.rq.u_l, delim);
		if (!smp->ctx.a[0])
			return 0;

		smp->ctx.a[1] = msg->chn->buf->p + msg->sl.rq.u + msg->sl.rq.u_l;

		/* Assume that the context is filled with NULL pointer
		 * before the first call.
		 * smp->ctx.a[2] = NULL;
		 * smp->ctx.a[3] = NULL;
		 */
	}

	return smp_fetch_param(delim, name, name_len, args, smp, kw, private);
}

/* This function iterates over each parameter of the body. This requires
 * that the body has been waited for using http-buffer-request. It uses
 * ctx->a[0] and ctx->a[1] to store the beginning and end of the first
 * contigous part of the body, and optionally ctx->a[2..3] to reference the
 * optional second part if the body wraps at the end of the buffer. An optional
 * parameter name is passed in args[0], otherwise any parameter is considered.
 */
static int
smp_fetch_body_param(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_msg *msg;
	unsigned long len;
	unsigned long block1;
	char *body;
	const char *name;
	int name_len;

	if (!args || (args[0].type && args[0].type != ARGT_STR))
		return 0;

	name = "";
	name_len = 0;
	if (args[0].type == ARGT_STR) {
		name     = args[0].data.str.str;
		name_len = args[0].data.str.len;
	}

	if (!smp->ctx.a[0]) { // first call, find the query string
		CHECK_HTTP_MESSAGE_FIRST();

		if ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_REQ)
			msg = &smp->strm->txn->req;
		else
			msg = &smp->strm->txn->rsp;

		len  = http_body_bytes(msg);
		body = b_ptr(msg->chn->buf, -http_data_rewind(msg));

		block1 = len;
		if (block1 > msg->chn->buf->data + msg->chn->buf->size - body)
			block1 = msg->chn->buf->data + msg->chn->buf->size - body;

		if (block1 == len) {
			/* buffer is not wrapped (or empty) */
			smp->ctx.a[0] = body;
			smp->ctx.a[1] = body + len;

			/* Assume that the context is filled with NULL pointer
			 * before the first call.
			 * smp->ctx.a[2] = NULL;
			 * smp->ctx.a[3] = NULL;
			*/
		}
		else {
			/* buffer is wrapped, we need to defragment it */
			smp->ctx.a[0] = body;
			smp->ctx.a[1] = body + block1;
			smp->ctx.a[2] = msg->chn->buf->data;
			smp->ctx.a[3] = msg->chn->buf->data + ( len - block1 );
		}
	}
	return smp_fetch_param('&', name, name_len, args, smp, kw, private);
}

/* Return the signed integer value for the specified url parameter (see url_param
 * above).
 */
static int
smp_fetch_url_param_val(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int ret = smp_fetch_url_param(args, smp, kw, private);

	if (ret > 0) {
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = strl2ic(smp->data.u.str.str, smp->data.u.str.len);
	}

	return ret;
}

/* This produces a 32-bit hash of the concatenation of the first occurrence of
 * the Host header followed by the path component if it begins with a slash ('/').
 * This means that '*' will not be added, resulting in exactly the first Host
 * entry. If no Host header is found, then the path is used. The resulting value
 * is hashed using the url hash followed by a full avalanche hash and provides a
 * 32-bit integer value. This fetch is useful for tracking per-URL activity on
 * high-traffic sites without having to store whole paths.
 * this differs from the base32 functions in that it includes the url parameters
 * as well as the path
 */
static int
smp_fetch_url32(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct http_txn *txn;
	struct hdr_ctx ctx;
	unsigned int hash = 0;
	char *ptr, *beg, *end;
	int len;

	CHECK_HTTP_MESSAGE_FIRST();

	txn = smp->strm->txn;
	ctx.idx = 0;
	if (http_find_header2("Host", 4, txn->req.chn->buf->p, &txn->hdr_idx, &ctx)) {
		/* OK we have the header value in ctx.line+ctx.val for ctx.vlen bytes */
		ptr = ctx.line + ctx.val;
		len = ctx.vlen;
		while (len--)
			hash = *(ptr++) + (hash << 6) + (hash << 16) - hash;
	}

	/* now retrieve the path */
	end = txn->req.chn->buf->p + txn->req.sl.rq.u + txn->req.sl.rq.u_l;
	beg = http_get_path(txn);
	if (!beg)
		beg = end;

	for (ptr = beg; ptr < end ; ptr++);

	if (beg < ptr && *beg == '/') {
		while (beg < ptr)
			hash = *(beg++) + (hash << 6) + (hash << 16) - hash;
	}
	hash = full_hash(hash);

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = hash;
	smp->flags = SMP_F_VOL_1ST;
	return 1;
}

/* This concatenates the source address with the 32-bit hash of the Host and
 * URL as returned by smp_fetch_base32(). The idea is to have per-source and
 * per-url counters. The result is a binary block from 8 to 20 bytes depending
 * on the source address length. The URL hash is stored before the address so
 * that in environments where IPv6 is insignificant, truncating the output to
 * 8 bytes would still work.
 */
static int
smp_fetch_url32_src(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct chunk *temp;
	struct connection *cli_conn = objt_conn(smp->sess->origin);

	if (!cli_conn)
		return 0;

	if (!smp_fetch_url32(args, smp, kw, private))
		return 0;

	temp = get_trash_chunk();
	*(unsigned int *)temp->str = htonl(smp->data.u.sint);
	temp->len += sizeof(unsigned int);

	switch (cli_conn->addr.from.ss_family) {
	case AF_INET:
		memcpy(temp->str + temp->len, &((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr, 4);
		temp->len += 4;
		break;
	case AF_INET6:
		memcpy(temp->str + temp->len, &((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_addr, 16);
		temp->len += 16;
		break;
	default:
		return 0;
	}

	smp->data.u.str = *temp;
	smp->data.type = SMP_T_BIN;
	return 1;
}

/* This function is used to validate the arguments passed to any "hdr" fetch
 * keyword. These keywords support an optional positive or negative occurrence
 * number. We must ensure that the number is greater than -MAX_HDR_HISTORY. It
 * is assumed that the types are already the correct ones. Returns 0 on error,
 * non-zero if OK. If <err> is not NULL, it will be filled with a pointer to an
 * error message in case of error, that the caller is responsible for freeing.
 * The initial location must either be freeable or NULL.
 */
int val_hdr(struct arg *arg, char **err_msg)
{
	if (arg && arg[1].type == ARGT_SINT && arg[1].data.sint < -MAX_HDR_HISTORY) {
		memprintf(err_msg, "header occurrence must be >= %d", -MAX_HDR_HISTORY);
		return 0;
	}
	return 1;
}

/* takes an UINT value on input supposed to represent the time since EPOCH,
 * adds an optional offset found in args[0] and emits a string representing
 * the date in RFC-1123/5322 format.
 */
static int sample_conv_http_date(const struct arg *args, struct sample *smp, void *private)
{
	const char day[7][4] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct chunk *temp;
	struct tm *tm;
	/* With high numbers, the date returned can be negative, the 55 bits mask prevent this. */
	time_t curr_date = smp->data.u.sint & 0x007fffffffffffffLL;

	/* add offset */
	if (args && (args[0].type == ARGT_SINT))
		curr_date += args[0].data.sint;

	tm = gmtime(&curr_date);
	if (!tm)
		return 0;

	temp = get_trash_chunk();
	temp->len = snprintf(temp->str, temp->size - temp->len,
			     "%s, %02d %s %04d %02d:%02d:%02d GMT",
			     day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon], 1900+tm->tm_year,
			     tm->tm_hour, tm->tm_min, tm->tm_sec);

	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}

/* Match language range with language tag. RFC2616 14.4:
 *
 *    A language-range matches a language-tag if it exactly equals
 *    the tag, or if it exactly equals a prefix of the tag such
 *    that the first tag character following the prefix is "-".
 *
 * Return 1 if the strings match, else return 0.
 */
static inline int language_range_match(const char *range, int range_len,
                                       const char *tag, int tag_len)
{
	const char *end = range + range_len;
	const char *tend = tag + tag_len;
	while (range < end) {
		if (*range == '-' && tag == tend)
			return 1;
		if (*range != *tag || tag == tend)
			return 0;
		range++;
		tag++;
	}
	/* Return true only if the last char of the tag is matched. */
	return tag == tend;
}

/* Arguments: The list of expected value, the number of parts returned and the separator */
static int sample_conv_q_prefered(const struct arg *args, struct sample *smp, void *private)
{
	const char *al = smp->data.u.str.str;
	const char *end = al + smp->data.u.str.len;
	const char *token;
	int toklen;
	int qvalue;
	const char *str;
	const char *w;
	int best_q = 0;

	/* Set the constant to the sample, because the output of the
	 * function will be peek in the constant configuration string.
	 */
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.size = 0;
	smp->data.u.str.str = "";
	smp->data.u.str.len = 0;

	/* Parse the accept language */
	while (1) {

		/* Jump spaces, quit if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			break;

		/* Start of the fisrt word. */
		token = al;

		/* Look for separator: isspace(), ',' or ';'. Next value if 0 length word. */
		while (al < end && *al != ';' && *al != ',' && !isspace((unsigned char)*al))
			al++;
		if (al == token)
			goto expect_comma;

		/* Length of the token. */
		toklen = al - token;
		qvalue = 1000;

		/* Check if the token exists in the list. If the token not exists,
		 * jump to the next token.
		 */
		str = args[0].data.str.str;
		w = str;
		while (1) {
			if (*str == ';' || *str == '\0') {
				if (language_range_match(token, toklen, w, str-w))
					goto look_for_q;
				if (*str == '\0')
					goto expect_comma;
				w = str + 1;
			}
			str++;
		}
		goto expect_comma;

look_for_q:

		/* Jump spaces, quit if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* If ',' is found, process the result */
		if (*al == ',')
			goto process_value;

		/* If the character is different from ';', look
		 * for the end of the header part in best effort.
		 */
		if (*al != ';')
			goto expect_comma;

		/* Assumes that the char is ';', now expect "q=". */
		al++;

		/* Jump spaces, process value if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* Expect 'q'. If no 'q', continue in best effort */
		if (*al != 'q')
			goto process_value;
		al++;

		/* Jump spaces, process value if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* Expect '='. If no '=', continue in best effort */
		if (*al != '=')
			goto process_value;
		al++;

		/* Jump spaces, process value if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* Parse the q value. */
		qvalue = parse_qvalue(al, &al);

process_value:

		/* If the new q value is the best q value, then store the associated
		 * language in the response. If qvalue is the biggest value (1000),
		 * break the process.
		 */
		if (qvalue > best_q) {
			smp->data.u.str.str = (char *)w;
			smp->data.u.str.len = str - w;
			if (qvalue >= 1000)
				break;
			best_q = qvalue;
		}

expect_comma:

		/* Expect comma or end. If the end is detected, quit the loop. */
		while (al < end && *al != ',')
			al++;
		if (al >= end)
			break;

		/* Comma is found, jump it and restart the analyzer. */
		al++;
	}

	/* Set default value if required. */
	if (smp->data.u.str.len == 0 && args[1].type == ARGT_STR) {
		smp->data.u.str.str = args[1].data.str.str;
		smp->data.u.str.len = args[1].data.str.len;
	}

	/* Return true only if a matching language was found. */
	return smp->data.u.str.len != 0;
}

/* This fetch url-decode any input string. */
static int sample_conv_url_dec(const struct arg *args, struct sample *smp, void *private)
{
	/* If the constant flag is set or if not size is avalaible at
	 * the end of the buffer, copy the string in other buffer
	  * before decoding.
	 */
	if (smp->flags & SMP_F_CONST || smp->data.u.str.size <= smp->data.u.str.len) {
		struct chunk *str = get_trash_chunk();
		memcpy(str->str, smp->data.u.str.str, smp->data.u.str.len);
		smp->data.u.str.str = str->str;
		smp->data.u.str.size = str->size;
		smp->flags &= ~SMP_F_CONST;
	}

	/* Add final \0 required by url_decode(), and convert the input string. */
	smp->data.u.str.str[smp->data.u.str.len] = '\0';
	smp->data.u.str.len = url_decode(smp->data.u.str.str);
	return (smp->data.u.str.len >= 0);
}

static int smp_conv_req_capture(const struct arg *args, struct sample *smp, void *private)
{
	struct proxy *fe = strm_fe(smp->strm);
	int idx, i;
	struct cap_hdr *hdr;
	int len;

	if (!args || args->type != ARGT_SINT)
		return 0;

	idx = args->data.sint;

	/* Check the availibity of the capture id. */
	if (idx > fe->nb_req_cap - 1)
		return 0;

	/* Look for the original configuration. */
	for (hdr = fe->req_cap, i = fe->nb_req_cap - 1;
	     hdr != NULL && i != idx ;
	     i--, hdr = hdr->next);
	if (!hdr)
		return 0;

	/* check for the memory allocation */
	if (smp->strm->req_cap[hdr->index] == NULL)
		smp->strm->req_cap[hdr->index] = pool_alloc(hdr->pool);
	if (smp->strm->req_cap[hdr->index] == NULL)
		return 0;

	/* Check length. */
	len = smp->data.u.str.len;
	if (len > hdr->len)
		len = hdr->len;

	/* Capture input data. */
	memcpy(smp->strm->req_cap[idx], smp->data.u.str.str, len);
	smp->strm->req_cap[idx][len] = '\0';

	return 1;
}

static int smp_conv_res_capture(const struct arg *args, struct sample *smp, void *private)
{
	struct proxy *fe = strm_fe(smp->strm);
	int idx, i;
	struct cap_hdr *hdr;
	int len;

	if (!args || args->type != ARGT_SINT)
		return 0;

	idx = args->data.sint;

	/* Check the availibity of the capture id. */
	if (idx > fe->nb_rsp_cap - 1)
		return 0;

	/* Look for the original configuration. */
	for (hdr = fe->rsp_cap, i = fe->nb_rsp_cap - 1;
	     hdr != NULL && i != idx ;
	     i--, hdr = hdr->next);
	if (!hdr)
		return 0;

	/* check for the memory allocation */
	if (smp->strm->res_cap[hdr->index] == NULL)
		smp->strm->res_cap[hdr->index] = pool_alloc(hdr->pool);
	if (smp->strm->res_cap[hdr->index] == NULL)
		return 0;

	/* Check length. */
	len = smp->data.u.str.len;
	if (len > hdr->len)
		len = hdr->len;

	/* Capture input data. */
	memcpy(smp->strm->res_cap[idx], smp->data.u.str.str, len);
	smp->strm->res_cap[idx][len] = '\0';

	return 1;
}

/* This function executes one of the set-{method,path,query,uri} actions. It
 * takes the string from the variable 'replace' with length 'len', then modifies
 * the relevant part of the request line accordingly. Then it updates various
 * pointers to the next elements which were moved, and the total buffer length.
 * It finds the action to be performed in p[2], previously filled by function
 * parse_set_req_line(). It returns 0 in case of success, -1 in case of internal
 * error, though this can be revisited when this code is finally exploited.
 *
 * 'action' can be '0' to replace method, '1' to replace path, '2' to replace
 * query string and 3 to replace uri.
 *
 * In query string case, the mark question '?' must be set at the start of the
 * string by the caller, event if the replacement query string is empty.
 */
int http_replace_req_line(int action, const char *replace, int len,
                          struct proxy *px, struct stream *s)
{
	struct http_txn *txn = s->txn;
	char *cur_ptr, *cur_end;
	int offset = 0;
	int delta;

	switch (action) {
	case 0: // method
		cur_ptr = s->req.buf->p;
		cur_end = cur_ptr + txn->req.sl.rq.m_l;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.m_l += delta;
		txn->req.sl.rq.u   += delta;
		txn->req.sl.rq.v   += delta;
		break;

	case 1: // path
		cur_ptr = http_get_path(txn);
		if (!cur_ptr)
			cur_ptr = s->req.buf->p + txn->req.sl.rq.u;

		cur_end = cur_ptr;
		while (cur_end < s->req.buf->p + txn->req.sl.rq.u + txn->req.sl.rq.u_l && *cur_end != '?')
			cur_end++;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.u_l += delta;
		txn->req.sl.rq.v   += delta;
		break;

	case 2: // query
		offset = 1;
		cur_ptr = s->req.buf->p + txn->req.sl.rq.u;
		cur_end = cur_ptr + txn->req.sl.rq.u_l;
		while (cur_ptr < cur_end && *cur_ptr != '?')
			cur_ptr++;

		/* skip the question mark or indicate that we must insert it
		 * (but only if the format string is not empty then).
		 */
		if (cur_ptr < cur_end)
			cur_ptr++;
		else if (len > 1)
			offset = 0;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.u_l += delta;
		txn->req.sl.rq.v   += delta;
		break;

	case 3: // uri
		cur_ptr = s->req.buf->p + txn->req.sl.rq.u;
		cur_end = cur_ptr + txn->req.sl.rq.u_l;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.u_l += delta;
		txn->req.sl.rq.v   += delta;
		break;

	default:
		return -1;
	}

	/* commit changes and adjust end of message */
	delta = buffer_replace2(s->req.buf, cur_ptr, cur_end, replace + offset, len - offset);
	txn->req.sl.rq.l += delta;
	txn->hdr_idx.v[0].len += delta;
	http_msg_move_end(&txn->req, delta);
	return 0;
}

/* This function replace the HTTP status code and the associated message. The
 * variable <status> contains the new status code. This function never fails.
 */
void http_set_status(unsigned int status, const char *reason, struct stream *s)
{
	struct http_txn *txn = s->txn;
	char *cur_ptr, *cur_end;
	int delta;
	char *res;
	int c_l;
	const char *msg = reason;
	int msg_len;

	chunk_reset(&trash);

	res = ultoa_o(status, trash.str, trash.size);
	c_l = res - trash.str;

	trash.str[c_l] = ' ';
	trash.len = c_l + 1;

	/* Do we have a custom reason format string? */
	if (msg == NULL)
		msg = get_reason(status);
	msg_len = strlen(msg);
	strncpy(&trash.str[trash.len], msg, trash.size - trash.len);
	trash.len += msg_len;

	cur_ptr = s->res.buf->p + txn->rsp.sl.st.c;
	cur_end = s->res.buf->p + txn->rsp.sl.st.r + txn->rsp.sl.st.r_l;

	/* commit changes and adjust message */
	delta = buffer_replace2(s->res.buf, cur_ptr, cur_end, trash.str, trash.len);

	/* adjust res line offsets and lengths */
	txn->rsp.sl.st.r += c_l - txn->rsp.sl.st.c_l;
	txn->rsp.sl.st.c_l = c_l;
	txn->rsp.sl.st.r_l = msg_len;

	delta = trash.len - (cur_end - cur_ptr);
	txn->rsp.sl.st.l += delta;
	txn->hdr_idx.v[0].len += delta;
	http_msg_move_end(&txn->rsp, delta);
}

/* This function executes one of the set-{method,path,query,uri} actions. It
 * builds a string in the trash from the specified format string. It finds
 * the action to be performed in <http.action>, previously filled by function
 * parse_set_req_line(). The replacement action is excuted by the function
 * http_action_set_req_line(). It always returns ACT_RET_CONT. If an error
 * occurs the action is canceled, but the rule processing continue.
 */
enum act_return http_action_set_req_line(struct act_rule *rule, struct proxy *px,
                                         struct session *sess, struct stream *s, int flags)
{
	struct chunk *replace;
	enum act_return ret = ACT_RET_ERR;

	replace = alloc_trash_chunk();
	if (!replace)
		goto leave;

	/* If we have to create a query string, prepare a '?'. */
	if (rule->arg.http.action == 2)
		replace->str[replace->len++] = '?';
	replace->len += build_logline(s, replace->str + replace->len, replace->size - replace->len,
	                              &rule->arg.http.logfmt);

	http_replace_req_line(rule->arg.http.action, replace->str, replace->len, px, s);

	ret = ACT_RET_CONT;

leave:
	free_trash_chunk(replace);
	return ret;
}

/* This function is just a compliant action wrapper for "set-status". */
enum act_return action_http_set_status(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	http_set_status(rule->arg.status.code, rule->arg.status.reason, s);
	return ACT_RET_CONT;
}

/* parse an http-request action among :
 *   set-method
 *   set-path
 *   set-query
 *   set-uri
 *
 * All of them accept a single argument of type string representing a log-format.
 * The resulting rule makes use of arg->act.p[0..1] to store the log-format list
 * head, and p[2] to store the action as an int (0=method, 1=path, 2=query, 3=uri).
 * It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
enum act_parse_ret parse_set_req_line(const char **args, int *orig_arg, struct proxy *px,
                                      struct act_rule *rule, char **err)
{
	int cur_arg = *orig_arg;

	rule->action = ACT_CUSTOM;

	switch (args[0][4]) {
	case 'm' :
		rule->arg.http.action = 0;
		rule->action_ptr = http_action_set_req_line;
		break;
	case 'p' :
		rule->arg.http.action = 1;
		rule->action_ptr = http_action_set_req_line;
		break;
	case 'q' :
		rule->arg.http.action = 2;
		rule->action_ptr = http_action_set_req_line;
		break;
	case 'u' :
		rule->arg.http.action = 3;
		rule->action_ptr = http_action_set_req_line;
		break;
	default:
		memprintf(err, "internal error: unhandled action '%s'", args[0]);
		return ACT_RET_PRS_ERR;
	}

	if (!*args[cur_arg] ||
	    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
		memprintf(err, "expects exactly 1 argument <format>");
		return ACT_RET_PRS_ERR;
	}

	LIST_INIT(&rule->arg.http.logfmt);
	px->conf.args.ctx = ARGC_HRQ;
	if (!parse_logformat_string(args[cur_arg], px, &rule->arg.http.logfmt, LOG_OPT_HTTP,
	                            (px->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, err)) {
		return ACT_RET_PRS_ERR;
	}

	(*orig_arg)++;
	return ACT_RET_PRS_OK;
}

/* parse set-status action:
 * This action accepts a single argument of type int representing
 * an http status code. It returns ACT_RET_PRS_OK on success,
 * ACT_RET_PRS_ERR on error.
 */
enum act_parse_ret parse_http_set_status(const char **args, int *orig_arg, struct proxy *px,
                                         struct act_rule *rule, char **err)
{
	char *error;

	rule->action = ACT_CUSTOM;
	rule->action_ptr = action_http_set_status;

	/* Check if an argument is available */
	if (!*args[*orig_arg]) {
		memprintf(err, "expects 1 argument: <status>; or 3 arguments: <status> reason <fmt>");
		return ACT_RET_PRS_ERR;
	}

	/* convert status code as integer */
	rule->arg.status.code = strtol(args[*orig_arg], &error, 10);
	if (*error != '\0' || rule->arg.status.code < 100 || rule->arg.status.code > 999) {
		memprintf(err, "expects an integer status code between 100 and 999");
		return ACT_RET_PRS_ERR;
	}

	(*orig_arg)++;

	/* set custom reason string */
	rule->arg.status.reason = NULL; // If null, we use the default reason for the status code.
	if (*args[*orig_arg] && strcmp(args[*orig_arg], "reason") == 0 &&
	    (*args[*orig_arg + 1] && strcmp(args[*orig_arg + 1], "if") != 0 && strcmp(args[*orig_arg + 1], "unless") != 0)) {
		(*orig_arg)++;
		rule->arg.status.reason = strdup(args[*orig_arg]);
		(*orig_arg)++;
	}

	return ACT_RET_PRS_OK;
}

/* This function executes the "reject" HTTP action. It clears the request and
 * response buffer without sending any response. It can be useful as an HTTP
 * alternative to the silent-drop action to defend against DoS attacks, and may
 * also be used with HTTP/2 to close a connection instead of just a stream.
 * The txn status is unchanged, indicating no response was sent. The termination
 * flags will indicate "PR". It always returns ACT_RET_STOP.
 */
enum act_return http_action_reject(struct act_rule *rule, struct proxy *px,
                                   struct session *sess, struct stream *s, int flags)
{
	channel_abort(&s->req);
	channel_abort(&s->res);
	s->req.analysers = 0;
	s->res.analysers = 0;

	HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->listener && sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	return ACT_RET_CONT;
}

/* parse the "reject" action:
 * This action takes no argument and returns ACT_RET_PRS_OK on success,
 * ACT_RET_PRS_ERR on error.
 */
enum act_parse_ret parse_http_action_reject(const char **args, int *orig_arg, struct proxy *px,
                                            struct act_rule *rule, char **err)
{
	rule->action = ACT_CUSTOM;
	rule->action_ptr = http_action_reject;
	return ACT_RET_PRS_OK;
}

/* This function executes the "capture" action. It executes a fetch expression,
 * turns the result into a string and puts it in a capture slot. It always
 * returns 1. If an error occurs the action is cancelled, but the rule
 * processing continues.
 */
enum act_return http_action_req_capture(struct act_rule *rule, struct proxy *px,
                                        struct session *sess, struct stream *s, int flags)
{
	struct sample *key;
	struct cap_hdr *h = rule->arg.cap.hdr;
	char **cap = s->req_cap;
	int len;

	key = sample_fetch_as_type(s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.cap.expr, SMP_T_STR);
	if (!key)
		return ACT_RET_CONT;

	if (cap[h->index] == NULL)
		cap[h->index] = pool_alloc(h->pool);

	if (cap[h->index] == NULL) /* no more capture memory */
		return ACT_RET_CONT;

	len = key->data.u.str.len;
	if (len > h->len)
		len = h->len;

	memcpy(cap[h->index], key->data.u.str.str, len);
	cap[h->index][len] = 0;
	return ACT_RET_CONT;
}

/* This function executes the "capture" action and store the result in a
 * capture slot if exists. It executes a fetch expression, turns the result
 * into a string and puts it in a capture slot. It always returns 1. If an
 * error occurs the action is cancelled, but the rule processing continues.
 */
enum act_return http_action_req_capture_by_id(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct sample *key;
	struct cap_hdr *h;
	char **cap = s->req_cap;
	struct proxy *fe = strm_fe(s);
	int len;
	int i;

	/* Look for the original configuration. */
	for (h = fe->req_cap, i = fe->nb_req_cap - 1;
	     h != NULL && i != rule->arg.capid.idx ;
	     i--, h = h->next);
	if (!h)
		return ACT_RET_CONT;

	key = sample_fetch_as_type(s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.capid.expr, SMP_T_STR);
	if (!key)
		return ACT_RET_CONT;

	if (cap[h->index] == NULL)
		cap[h->index] = pool_alloc(h->pool);

	if (cap[h->index] == NULL) /* no more capture memory */
		return ACT_RET_CONT;

	len = key->data.u.str.len;
	if (len > h->len)
		len = h->len;

	memcpy(cap[h->index], key->data.u.str.str, len);
	cap[h->index][len] = 0;
	return ACT_RET_CONT;
}

/* Check an "http-request capture" action.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_http_req_capture(struct act_rule *rule, struct proxy *px, char **err)
{
	if (rule->action_ptr != http_action_req_capture_by_id)
		return 1;

	if (rule->arg.capid.idx >= px->nb_req_cap) {
		memprintf(err, "unable to find capture id '%d' referenced by http-request capture rule",
			  rule->arg.capid.idx);
		return 0;
	}

	return 1;
}

/* parse an "http-request capture" action. It takes a single argument which is
 * a sample fetch expression. It stores the expression into arg->act.p[0] and
 * the allocated hdr_cap struct or the preallocated "id" into arg->act.p[1].
 * It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
enum act_parse_ret parse_http_req_capture(const char **args, int *orig_arg, struct proxy *px,
                                          struct act_rule *rule, char **err)
{
	struct sample_expr *expr;
	struct cap_hdr *hdr;
	int cur_arg;
	int len = 0;

	for (cur_arg = *orig_arg; cur_arg < *orig_arg + 3 && *args[cur_arg]; cur_arg++)
		if (strcmp(args[cur_arg], "if") == 0 ||
		    strcmp(args[cur_arg], "unless") == 0)
			break;

	if (cur_arg < *orig_arg + 3) {
		memprintf(err, "expects <expression> [ 'len' <length> | id <idx> ]");
		return ACT_RET_PRS_ERR;
	}

	cur_arg = *orig_arg;
	expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args);
	if (!expr)
		return ACT_RET_PRS_ERR;

	if (!(expr->fetch->val & SMP_VAL_FE_HRQ_HDR)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  args[cur_arg-1], sample_src_names(expr->fetch->use));
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (!args[cur_arg] || !*args[cur_arg]) {
		memprintf(err, "expects 'len or 'id'");
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (strcmp(args[cur_arg], "len") == 0) {
		cur_arg++;

		if (!(px->cap & PR_CAP_FE)) {
			memprintf(err, "proxy '%s' has no frontend capability", px->id);
			return ACT_RET_PRS_ERR;
		}

		px->conf.args.ctx = ARGC_CAP;

		if (!args[cur_arg]) {
			memprintf(err, "missing length value");
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		/* we copy the table name for now, it will be resolved later */
		len = atoi(args[cur_arg]);
		if (len <= 0) {
			memprintf(err, "length must be > 0");
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		cur_arg++;

		if (!len) {
			memprintf(err, "a positive 'len' argument is mandatory");
			free(expr);
			return ACT_RET_PRS_ERR;
		}

		hdr = calloc(1, sizeof(*hdr));
		hdr->next = px->req_cap;
		hdr->name = NULL; /* not a header capture */
		hdr->namelen = 0;
		hdr->len = len;
		hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
		hdr->index = px->nb_req_cap++;

		px->req_cap = hdr;
		px->to_log |= LW_REQHDR;

		rule->action       = ACT_CUSTOM;
		rule->action_ptr   = http_action_req_capture;
		rule->arg.cap.expr = expr;
		rule->arg.cap.hdr  = hdr;
	}

	else if (strcmp(args[cur_arg], "id") == 0) {
		int id;
		char *error;

		cur_arg++;

		if (!args[cur_arg]) {
			memprintf(err, "missing id value");
			free(expr);
			return ACT_RET_PRS_ERR;
		}

		id = strtol(args[cur_arg], &error, 10);
		if (*error != '\0') {
			memprintf(err, "cannot parse id '%s'", args[cur_arg]);
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		cur_arg++;

		px->conf.args.ctx = ARGC_CAP;

		rule->action       = ACT_CUSTOM;
		rule->action_ptr   = http_action_req_capture_by_id;
		rule->check_ptr    = check_http_req_capture;
		rule->arg.capid.expr = expr;
		rule->arg.capid.idx  = id;
	}

	else {
		memprintf(err, "expects 'len' or 'id', found '%s'", args[cur_arg]);
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	*orig_arg = cur_arg;
	return ACT_RET_PRS_OK;
}

/* This function executes the "capture" action and store the result in a
 * capture slot if exists. It executes a fetch expression, turns the result
 * into a string and puts it in a capture slot. It always returns 1. If an
 * error occurs the action is cancelled, but the rule processing continues.
 */
enum act_return http_action_res_capture_by_id(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct sample *key;
	struct cap_hdr *h;
	char **cap = s->res_cap;
	struct proxy *fe = strm_fe(s);
	int len;
	int i;

	/* Look for the original configuration. */
	for (h = fe->rsp_cap, i = fe->nb_rsp_cap - 1;
	     h != NULL && i != rule->arg.capid.idx ;
	     i--, h = h->next);
	if (!h)
		return ACT_RET_CONT;

	key = sample_fetch_as_type(s->be, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL, rule->arg.capid.expr, SMP_T_STR);
	if (!key)
		return ACT_RET_CONT;

	if (cap[h->index] == NULL)
		cap[h->index] = pool_alloc(h->pool);

	if (cap[h->index] == NULL) /* no more capture memory */
		return ACT_RET_CONT;

	len = key->data.u.str.len;
	if (len > h->len)
		len = h->len;

	memcpy(cap[h->index], key->data.u.str.str, len);
	cap[h->index][len] = 0;
	return ACT_RET_CONT;
}

/* Check an "http-response capture" action.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_http_res_capture(struct act_rule *rule, struct proxy *px, char **err)
{
	if (rule->action_ptr != http_action_res_capture_by_id)
		return 1;

	if (rule->arg.capid.idx >= px->nb_rsp_cap) {
		memprintf(err, "unable to find capture id '%d' referenced by http-response capture rule",
			  rule->arg.capid.idx);
		return 0;
	}

	return 1;
}

/* parse an "http-response capture" action. It takes a single argument which is
 * a sample fetch expression. It stores the expression into arg->act.p[0] and
 * the allocated hdr_cap struct od the preallocated id into arg->act.p[1].
 * It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
enum act_parse_ret parse_http_res_capture(const char **args, int *orig_arg, struct proxy *px,
                                          struct act_rule *rule, char **err)
{
	struct sample_expr *expr;
	int cur_arg;
	int id;
	char *error;

	for (cur_arg = *orig_arg; cur_arg < *orig_arg + 3 && *args[cur_arg]; cur_arg++)
		if (strcmp(args[cur_arg], "if") == 0 ||
		    strcmp(args[cur_arg], "unless") == 0)
			break;

	if (cur_arg < *orig_arg + 3) {
		memprintf(err, "expects <expression> id <idx>");
		return ACT_RET_PRS_ERR;
	}

	cur_arg = *orig_arg;
	expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args);
	if (!expr)
		return ACT_RET_PRS_ERR;

	if (!(expr->fetch->val & SMP_VAL_FE_HRS_HDR)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  args[cur_arg-1], sample_src_names(expr->fetch->use));
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (!args[cur_arg] || !*args[cur_arg]) {
		memprintf(err, "expects 'id'");
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (strcmp(args[cur_arg], "id") != 0) {
		memprintf(err, "expects 'id', found '%s'", args[cur_arg]);
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	cur_arg++;

	if (!args[cur_arg]) {
		memprintf(err, "missing id value");
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	id = strtol(args[cur_arg], &error, 10);
	if (*error != '\0') {
		memprintf(err, "cannot parse id '%s'", args[cur_arg]);
		free(expr);
		return ACT_RET_PRS_ERR;
	}
	cur_arg++;

	px->conf.args.ctx = ARGC_CAP;

	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_res_capture_by_id;
	rule->check_ptr    = check_http_res_capture;
	rule->arg.capid.expr = expr;
	rule->arg.capid.idx  = id;

	*orig_arg = cur_arg;
	return ACT_RET_PRS_OK;
}

/*
 * Return the struct http_req_action_kw associated to a keyword.
 */
struct action_kw *action_http_req_custom(const char *kw)
{
	return action_lookup(&http_req_keywords.list, kw);
}

/*
 * Return the struct http_res_action_kw associated to a keyword.
 */
struct action_kw *action_http_res_custom(const char *kw)
{
	return action_lookup(&http_res_keywords.list, kw);
}


/* "show errors" handler for the CLI. Returns 0 if wants to continue, 1 to stop
 * now.
 */
static int cli_parse_show_errors(char **args, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (*args[2]) {
		struct proxy *px;

		px = proxy_find_by_name(args[2], 0, 0);
		if (px)
			appctx->ctx.errors.iid = px->uuid;
		else
			appctx->ctx.errors.iid = atoi(args[2]);

		if (!appctx->ctx.errors.iid) {
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "No such proxy.\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}
	}
	else
		appctx->ctx.errors.iid	= -1; // dump all proxies

	appctx->ctx.errors.flag = 0;
	if (strcmp(args[3], "request") == 0)
		appctx->ctx.errors.flag |= 4; // ignore response
	else if (strcmp(args[3], "response") == 0)
		appctx->ctx.errors.flag |= 2; // ignore request
	appctx->ctx.errors.px = NULL;
	return 0;
}

/* This function dumps all captured errors onto the stream interface's
 * read buffer. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_errors(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	extern const char *monthname[12];

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	if (!appctx->ctx.errors.px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		struct tm tm;

		get_localtime(date.tv_sec, &tm);
		chunk_appendf(&trash, "Total events captured on [%02d/%s/%04d:%02d:%02d:%02d.%03d] : %u\n",
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(date.tv_usec/1000),
			     error_snapshot_id);

		if (ci_putchk(si_ic(si), &trash) == -1) {
			/* Socket buffer full. Let's try again later from the same point */
			si_applet_cant_put(si);
			return 0;
		}

		appctx->ctx.errors.px = proxies_list;
		appctx->ctx.errors.bol = 0;
		appctx->ctx.errors.ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (appctx->ctx.errors.px) {
		struct error_snapshot *es;

		if ((appctx->ctx.errors.flag & 1) == 0) {
			es = &appctx->ctx.errors.px->invalid_req;
			if (appctx->ctx.errors.flag & 2) // skip req
				goto next;
		}
		else {
			es = &appctx->ctx.errors.px->invalid_rep;
			if (appctx->ctx.errors.flag & 4) // skip resp
				goto next;
		}

		if (!es->when.tv_sec)
			goto next;

		if (appctx->ctx.errors.iid >= 0 &&
		    appctx->ctx.errors.px->uuid != appctx->ctx.errors.iid &&
		    es->oe->uuid != appctx->ctx.errors.iid)
			goto next;

		if (appctx->ctx.errors.ptr < 0) {
			/* just print headers now */

			char pn[INET6_ADDRSTRLEN];
			struct tm tm;
			int port;

			get_localtime(es->when.tv_sec, &tm);
			chunk_appendf(&trash, " \n[%02d/%s/%04d:%02d:%02d:%02d.%03d]",
				     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
				     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(es->when.tv_usec/1000));

			switch (addr_to_str(&es->src, pn, sizeof(pn))) {
			case AF_INET:
			case AF_INET6:
				port = get_host_port(&es->src);
				break;
			default:
				port = 0;
			}

			switch (appctx->ctx.errors.flag & 1) {
			case 0:
				chunk_appendf(&trash,
					     " frontend %s (#%d): invalid request\n"
					     "  backend %s (#%d)",
					     appctx->ctx.errors.px->id, appctx->ctx.errors.px->uuid,
					     (es->oe->cap & PR_CAP_BE) ? es->oe->id : "<NONE>",
					     (es->oe->cap & PR_CAP_BE) ? es->oe->uuid : -1);
				break;
			case 1:
				chunk_appendf(&trash,
					     " backend %s (#%d): invalid response\n"
					     "  frontend %s (#%d)",
					     appctx->ctx.errors.px->id, appctx->ctx.errors.px->uuid,
					     es->oe->id, es->oe->uuid);
				break;
			}

			chunk_appendf(&trash,
				     ", server %s (#%d), event #%u\n"
				     "  src %s:%d, session #%d, session flags 0x%08x\n"
				     "  HTTP msg state %s(%d), msg flags 0x%08x, tx flags 0x%08x\n"
				     "  HTTP chunk len %lld bytes, HTTP body len %lld bytes\n"
				     "  buffer flags 0x%08x, out %d bytes, total %lld bytes\n"
				     "  pending %d bytes, wrapping at %d, error at position %d:\n \n",
				     es->srv ? es->srv->id : "<NONE>", es->srv ? es->srv->puid : -1,
				     es->ev_id,
				     pn, port, es->sid, es->s_flags,
				     h1_msg_state_str(es->state), es->state, es->m_flags, es->t_flags,
				     es->m_clen, es->m_blen,
				     es->b_flags, es->b_out, es->b_tot,
				     es->len, es->b_wrap, es->pos);

			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* Socket buffer full. Let's try again later from the same point */
				si_applet_cant_put(si);
				return 0;
			}
			appctx->ctx.errors.ptr = 0;
			appctx->ctx.errors.sid = es->sid;
		}

		if (appctx->ctx.errors.sid != es->sid) {
			/* the snapshot changed while we were dumping it */
			chunk_appendf(&trash,
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (ci_putchk(si_ic(si), &trash) == -1) {
				si_applet_cant_put(si);
				return 0;
			}
			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (es->buf && appctx->ctx.errors.ptr < es->len && appctx->ctx.errors.ptr < global.tune.bufsize) {
			int newptr;
			int newline;

			newline = appctx->ctx.errors.bol;
			newptr = dump_text_line(&trash, es->buf, global.tune.bufsize, es->len, &newline, appctx->ctx.errors.ptr);
			if (newptr == appctx->ctx.errors.ptr)
				return 0;

			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* Socket buffer full. Let's try again later from the same point */
				si_applet_cant_put(si);
				return 0;
			}
			appctx->ctx.errors.ptr = newptr;
			appctx->ctx.errors.bol = newline;
		};
	next:
		appctx->ctx.errors.bol = 0;
		appctx->ctx.errors.ptr = -1;
		appctx->ctx.errors.flag ^= 1;
		if (!(appctx->ctx.errors.flag & 1))
			appctx->ctx.errors.px = appctx->ctx.errors.px->next;
	}

	/* dump complete */
	return 1;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "errors", NULL },
	  "show errors    : report last request and response errors for each proxy",
	  cli_parse_show_errors, cli_io_handler_show_errors, NULL,
	},
	{{},}
}};

/************************************************************************/
/*          All supported ACL keywords must be declared here.           */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ "base",            "base",     PAT_MATCH_STR },
	{ "base_beg",        "base",     PAT_MATCH_BEG },
	{ "base_dir",        "base",     PAT_MATCH_DIR },
	{ "base_dom",        "base",     PAT_MATCH_DOM },
	{ "base_end",        "base",     PAT_MATCH_END },
	{ "base_len",        "base",     PAT_MATCH_LEN },
	{ "base_reg",        "base",     PAT_MATCH_REG },
	{ "base_sub",        "base",     PAT_MATCH_SUB },

	{ "cook",            "req.cook", PAT_MATCH_STR },
	{ "cook_beg",        "req.cook", PAT_MATCH_BEG },
	{ "cook_dir",        "req.cook", PAT_MATCH_DIR },
	{ "cook_dom",        "req.cook", PAT_MATCH_DOM },
	{ "cook_end",        "req.cook", PAT_MATCH_END },
	{ "cook_len",        "req.cook", PAT_MATCH_LEN },
	{ "cook_reg",        "req.cook", PAT_MATCH_REG },
	{ "cook_sub",        "req.cook", PAT_MATCH_SUB },

	{ "hdr",             "req.hdr",  PAT_MATCH_STR },
	{ "hdr_beg",         "req.hdr",  PAT_MATCH_BEG },
	{ "hdr_dir",         "req.hdr",  PAT_MATCH_DIR },
	{ "hdr_dom",         "req.hdr",  PAT_MATCH_DOM },
	{ "hdr_end",         "req.hdr",  PAT_MATCH_END },
	{ "hdr_len",         "req.hdr",  PAT_MATCH_LEN },
	{ "hdr_reg",         "req.hdr",  PAT_MATCH_REG },
	{ "hdr_sub",         "req.hdr",  PAT_MATCH_SUB },

	/* these two declarations uses strings with list storage (in place
	 * of tree storage). The basic match is PAT_MATCH_STR, but the indexation
	 * and delete functions are relative to the list management. The parse
	 * and match method are related to the corresponding fetch methods. This
	 * is very particular ACL declaration mode.
	 */
	{ "http_auth_group", NULL,       PAT_MATCH_STR, NULL,  pat_idx_list_str, pat_del_list_ptr, NULL, pat_match_auth },
	{ "method",          NULL,       PAT_MATCH_STR, pat_parse_meth, pat_idx_list_str, pat_del_list_ptr, NULL, pat_match_meth },

	{ "path",            "path",     PAT_MATCH_STR },
	{ "path_beg",        "path",     PAT_MATCH_BEG },
	{ "path_dir",        "path",     PAT_MATCH_DIR },
	{ "path_dom",        "path",     PAT_MATCH_DOM },
	{ "path_end",        "path",     PAT_MATCH_END },
	{ "path_len",        "path",     PAT_MATCH_LEN },
	{ "path_reg",        "path",     PAT_MATCH_REG },
	{ "path_sub",        "path",     PAT_MATCH_SUB },

	{ "req_ver",         "req.ver",  PAT_MATCH_STR },
	{ "resp_ver",        "res.ver",  PAT_MATCH_STR },

	{ "scook",           "res.cook", PAT_MATCH_STR },
	{ "scook_beg",       "res.cook", PAT_MATCH_BEG },
	{ "scook_dir",       "res.cook", PAT_MATCH_DIR },
	{ "scook_dom",       "res.cook", PAT_MATCH_DOM },
	{ "scook_end",       "res.cook", PAT_MATCH_END },
	{ "scook_len",       "res.cook", PAT_MATCH_LEN },
	{ "scook_reg",       "res.cook", PAT_MATCH_REG },
	{ "scook_sub",       "res.cook", PAT_MATCH_SUB },

	{ "shdr",            "res.hdr",  PAT_MATCH_STR },
	{ "shdr_beg",        "res.hdr",  PAT_MATCH_BEG },
	{ "shdr_dir",        "res.hdr",  PAT_MATCH_DIR },
	{ "shdr_dom",        "res.hdr",  PAT_MATCH_DOM },
	{ "shdr_end",        "res.hdr",  PAT_MATCH_END },
	{ "shdr_len",        "res.hdr",  PAT_MATCH_LEN },
	{ "shdr_reg",        "res.hdr",  PAT_MATCH_REG },
	{ "shdr_sub",        "res.hdr",  PAT_MATCH_SUB },

	{ "url",             "url",      PAT_MATCH_STR },
	{ "url_beg",         "url",      PAT_MATCH_BEG },
	{ "url_dir",         "url",      PAT_MATCH_DIR },
	{ "url_dom",         "url",      PAT_MATCH_DOM },
	{ "url_end",         "url",      PAT_MATCH_END },
	{ "url_len",         "url",      PAT_MATCH_LEN },
	{ "url_reg",         "url",      PAT_MATCH_REG },
	{ "url_sub",         "url",      PAT_MATCH_SUB },

	{ "urlp",            "urlp",     PAT_MATCH_STR },
	{ "urlp_beg",        "urlp",     PAT_MATCH_BEG },
	{ "urlp_dir",        "urlp",     PAT_MATCH_DIR },
	{ "urlp_dom",        "urlp",     PAT_MATCH_DOM },
	{ "urlp_end",        "urlp",     PAT_MATCH_END },
	{ "urlp_len",        "urlp",     PAT_MATCH_LEN },
	{ "urlp_reg",        "urlp",     PAT_MATCH_REG },
	{ "urlp_sub",        "urlp",     PAT_MATCH_SUB },

	{ /* END */ },
}};

/************************************************************************/
/*         All supported pattern keywords must be declared here.        */
/************************************************************************/
/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "base",            smp_fetch_base,           0,                NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "base32",          smp_fetch_base32,         0,                NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "base32+src",      smp_fetch_base32_src,     0,                NULL,    SMP_T_BIN,  SMP_USE_HRQHV },

	/* capture are allocated and are permanent in the stream */
	{ "capture.req.hdr", smp_fetch_capture_header_req, ARG1(1,SINT), NULL,   SMP_T_STR,  SMP_USE_HRQHP },

	/* retrieve these captures from the HTTP logs */
	{ "capture.req.method", smp_fetch_capture_req_method, 0,         NULL,   SMP_T_STR,  SMP_USE_HRQHP },
	{ "capture.req.uri",    smp_fetch_capture_req_uri,    0,         NULL,   SMP_T_STR,  SMP_USE_HRQHP },
	{ "capture.req.ver",    smp_fetch_capture_req_ver,    0,         NULL,   SMP_T_STR,  SMP_USE_HRQHP },

	{ "capture.res.hdr", smp_fetch_capture_header_res, ARG1(1,SINT), NULL,   SMP_T_STR,  SMP_USE_HRSHP },
	{ "capture.res.ver", smp_fetch_capture_res_ver,       0,         NULL,   SMP_T_STR,  SMP_USE_HRQHP },

	/* cookie is valid in both directions (eg: for "stick ...") but cook*
	 * are only here to match the ACL's name, are request-only and are used
	 * for ACL compatibility only.
	 */
	{ "cook",            smp_fetch_cookie,         ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "cookie",          smp_fetch_cookie,         ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRQHV|SMP_USE_HRSHV },
	{ "cook_cnt",        smp_fetch_cookie_cnt,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "cook_val",        smp_fetch_cookie_val,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRQHV },

	/* hdr is valid in both directions (eg: for "stick ...") but hdr_* are
	 * only here to match the ACL's name, are request-only and are used for
	 * ACL compatibility only.
	 */
	{ "hdr",             smp_fetch_hdr,            ARG2(0,STR,SINT), val_hdr, SMP_T_STR,  SMP_USE_HRQHV|SMP_USE_HRSHV },
	{ "hdr_cnt",         smp_fetch_hdr_cnt,        ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "hdr_ip",          smp_fetch_hdr_ip,         ARG2(0,STR,SINT), val_hdr, SMP_T_IPV4, SMP_USE_HRQHV },
	{ "hdr_val",         smp_fetch_hdr_val,        ARG2(0,STR,SINT), val_hdr, SMP_T_SINT, SMP_USE_HRQHV },

	{ "http_auth",       smp_fetch_http_auth,      ARG1(1,USR),      NULL,    SMP_T_BOOL, SMP_USE_HRQHV },
	{ "http_auth_group", smp_fetch_http_auth_grp,  ARG1(1,USR),      NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "http_first_req",  smp_fetch_http_first_req, 0,                NULL,    SMP_T_BOOL, SMP_USE_HRQHP },
	{ "method",          smp_fetch_meth,           0,                NULL,    SMP_T_METH, SMP_USE_HRQHP },
	{ "path",            smp_fetch_path,           0,                NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "query",           smp_fetch_query,          0,                NULL,    SMP_T_STR,  SMP_USE_HRQHV },

	/* HTTP protocol on the request path */
	{ "req.proto_http",  smp_fetch_proto_http,     0,                NULL,    SMP_T_BOOL, SMP_USE_HRQHP },
	{ "req_proto_http",  smp_fetch_proto_http,     0,                NULL,    SMP_T_BOOL, SMP_USE_HRQHP },

	/* HTTP version on the request path */
	{ "req.ver",         smp_fetch_rqver,          0,                NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "req_ver",         smp_fetch_rqver,          0,                NULL,    SMP_T_STR,  SMP_USE_HRQHV },

	{ "req.body",        smp_fetch_body,           0,                NULL,    SMP_T_BIN,  SMP_USE_HRQHV },
	{ "req.body_len",    smp_fetch_body_len,       0,                NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "req.body_size",   smp_fetch_body_size,      0,                NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "req.body_param",  smp_fetch_body_param,     ARG1(0,STR),      NULL,    SMP_T_BIN,  SMP_USE_HRQHV },

	{ "req.hdrs",        smp_fetch_hdrs,           0,                NULL,    SMP_T_BIN,  SMP_USE_HRQHV },
	{ "req.hdrs_bin",    smp_fetch_hdrs_bin,       0,                NULL,    SMP_T_BIN,  SMP_USE_HRQHV },

	/* HTTP version on the response path */
	{ "res.ver",         smp_fetch_stver,          0,                NULL,    SMP_T_STR,  SMP_USE_HRSHV },
	{ "resp_ver",        smp_fetch_stver,          0,                NULL,    SMP_T_STR,  SMP_USE_HRSHV },

	/* explicit req.{cook,hdr} are used to force the fetch direction to be request-only */
	{ "req.cook",        smp_fetch_cookie,         ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "req.cook_cnt",    smp_fetch_cookie_cnt,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "req.cook_val",    smp_fetch_cookie_val,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRQHV },

	{ "req.fhdr",        smp_fetch_fhdr,           ARG2(0,STR,SINT), val_hdr, SMP_T_STR,  SMP_USE_HRQHV },
	{ "req.fhdr_cnt",    smp_fetch_fhdr_cnt,       ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "req.hdr",         smp_fetch_hdr,            ARG2(0,STR,SINT), val_hdr, SMP_T_STR,  SMP_USE_HRQHV },
	{ "req.hdr_cnt",     smp_fetch_hdr_cnt,        ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "req.hdr_ip",      smp_fetch_hdr_ip,         ARG2(0,STR,SINT), val_hdr, SMP_T_IPV4, SMP_USE_HRQHV },
	{ "req.hdr_names",   smp_fetch_hdr_names,      ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "req.hdr_val",     smp_fetch_hdr_val,        ARG2(0,STR,SINT), val_hdr, SMP_T_SINT, SMP_USE_HRQHV },

	/* explicit req.{cook,hdr} are used to force the fetch direction to be response-only */
	{ "res.cook",        smp_fetch_cookie,         ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRSHV },
	{ "res.cook_cnt",    smp_fetch_cookie_cnt,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRSHV },
	{ "res.cook_val",    smp_fetch_cookie_val,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRSHV },

	{ "res.fhdr",        smp_fetch_fhdr,           ARG2(0,STR,SINT), val_hdr, SMP_T_STR,  SMP_USE_HRSHV },
	{ "res.fhdr_cnt",    smp_fetch_fhdr_cnt,       ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRSHV },
	{ "res.hdr",         smp_fetch_hdr,            ARG2(0,STR,SINT), val_hdr, SMP_T_STR,  SMP_USE_HRSHV },
	{ "res.hdr_cnt",     smp_fetch_hdr_cnt,        ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRSHV },
	{ "res.hdr_ip",      smp_fetch_hdr_ip,         ARG2(0,STR,SINT), val_hdr, SMP_T_IPV4, SMP_USE_HRSHV },
	{ "res.hdr_names",   smp_fetch_hdr_names,      ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRSHV },
	{ "res.hdr_val",     smp_fetch_hdr_val,        ARG2(0,STR,SINT), val_hdr, SMP_T_SINT, SMP_USE_HRSHV },

	/* scook is valid only on the response and is used for ACL compatibility */
	{ "scook",           smp_fetch_cookie,         ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRSHV },
	{ "scook_cnt",       smp_fetch_cookie_cnt,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRSHV },
	{ "scook_val",       smp_fetch_cookie_val,     ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRSHV },
	{ "set-cookie",      smp_fetch_cookie,         ARG1(0,STR),      NULL,    SMP_T_STR,  SMP_USE_HRSHV }, /* deprecated */

	/* shdr is valid only on the response and is used for ACL compatibility */
	{ "shdr",            smp_fetch_hdr,            ARG2(0,STR,SINT), val_hdr, SMP_T_STR,  SMP_USE_HRSHV },
	{ "shdr_cnt",        smp_fetch_hdr_cnt,        ARG1(0,STR),      NULL,    SMP_T_SINT, SMP_USE_HRSHV },
	{ "shdr_ip",         smp_fetch_hdr_ip,         ARG2(0,STR,SINT), val_hdr, SMP_T_IPV4, SMP_USE_HRSHV },
	{ "shdr_val",        smp_fetch_hdr_val,        ARG2(0,STR,SINT), val_hdr, SMP_T_SINT, SMP_USE_HRSHV },

	{ "status",          smp_fetch_stcode,         0,                NULL,    SMP_T_SINT, SMP_USE_HRSHP },
	{ "unique-id",       smp_fetch_uniqueid,       0,                NULL,    SMP_T_STR,  SMP_SRC_L4SRV },
	{ "url",             smp_fetch_url,            0,                NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "url32",           smp_fetch_url32,          0,                NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "url32+src",       smp_fetch_url32_src,      0,                NULL,    SMP_T_BIN,  SMP_USE_HRQHV },
	{ "url_ip",          smp_fetch_url_ip,         0,                NULL,    SMP_T_IPV4, SMP_USE_HRQHV },
	{ "url_port",        smp_fetch_url_port,       0,                NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ "url_param",       smp_fetch_url_param,      ARG2(0,STR,STR),  NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "urlp"     ,       smp_fetch_url_param,      ARG2(0,STR,STR),  NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "urlp_val",        smp_fetch_url_param_val,  ARG2(0,STR,STR),  NULL,    SMP_T_SINT, SMP_USE_HRQHV },
	{ /* END */ },
}};


/************************************************************************/
/*        All supported converter keywords must be declared here.       */
/************************************************************************/
/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "http_date", sample_conv_http_date,  ARG1(0,SINT),     NULL, SMP_T_SINT, SMP_T_STR},
	{ "language",  sample_conv_q_prefered, ARG2(1,STR,STR),  NULL, SMP_T_STR,  SMP_T_STR},
	{ "capture-req", smp_conv_req_capture, ARG1(1,SINT),     NULL, SMP_T_STR,  SMP_T_STR},
	{ "capture-res", smp_conv_res_capture, ARG1(1,SINT),     NULL, SMP_T_STR,  SMP_T_STR},
	{ "url_dec",   sample_conv_url_dec,    0,                NULL, SMP_T_STR,  SMP_T_STR},
	{ NULL, NULL, 0, 0, 0 },
}};


/************************************************************************/
/*   All supported http-request action keywords must be declared here.  */
/************************************************************************/
struct action_kw_list http_req_actions = {
	.kw = {
		{ "capture",    parse_http_req_capture },
		{ "reject",     parse_http_action_reject },
		{ "set-method", parse_set_req_line },
		{ "set-path",   parse_set_req_line },
		{ "set-query",  parse_set_req_line },
		{ "set-uri",    parse_set_req_line },
		{ NULL, NULL }
	}
};

struct action_kw_list http_res_actions = {
	.kw = {
		{ "capture",    parse_http_res_capture },
		{ "set-status", parse_http_set_status },
		{ NULL, NULL }
	}
};

__attribute__((constructor))
static void __http_protocol_init(void)
{
	acl_register_keywords(&acl_kws);
	sample_register_fetches(&sample_fetch_keywords);
	sample_register_convs(&sample_conv_kws);
	http_req_keywords_register(&http_req_actions);
	http_res_keywords_register(&http_res_actions);
	cli_register_kw(&cli_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
