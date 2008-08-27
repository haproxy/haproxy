/*
 * HTTP protocol analyzer
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
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

#include <common/appsession.h>
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
#include <types/global.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/queue.h>
#include <proto/senddata.h>
#include <proto/session.h>
#include <proto/task.h>

#ifdef CONFIG_HAP_TCPSPLICE
#include <libtcpsplice.h>
#endif

#define DEBUG_PARSE_NO_SPEEDUP
#undef DEBUG_PARSE_NO_SPEEDUP

/* This is used to perform a quick jump as an alternative to a break/continue
 * instruction. The first argument is the label for normal operation, and the
 * second one is the break/continue instruction in the no_speedup mode.
 */

#ifdef DEBUG_PARSE_NO_SPEEDUP
#define QUICK_JUMP(x,y) y
#else
#define QUICK_JUMP(x,y) goto x
#endif

/* This is used by remote monitoring */
const char HTTP_200[] =
	"HTTP/1.0 200 OK\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>200 OK</h1>\nHAProxy: service ready.\n</body></html>\n";

const struct chunk http_200_chunk = {
	.str = (char *)&HTTP_200,
	.len = sizeof(HTTP_200)-1
};

const char *HTTP_301 =
	"HTTP/1.0 301 Moved Permantenly\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

const char *HTTP_302 =
	"HTTP/1.0 302 Found\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 302 except that the browser MUST retry with the GET method */
const char *HTTP_303 =
	"HTTP/1.0 303 See Other\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
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


const int http_err_codes[HTTP_ERR_SIZE] = {
	[HTTP_ERR_400] = 400,
	[HTTP_ERR_403] = 403,
	[HTTP_ERR_408] = 408,
	[HTTP_ERR_500] = 500,
	[HTTP_ERR_502] = 502,
	[HTTP_ERR_503] = 503,
	[HTTP_ERR_504] = 504,
};

static const char *http_err_msgs[HTTP_ERR_SIZE] = {
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

	[HTTP_ERR_408] =
	"HTTP/1.0 408 Request Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n",

	[HTTP_ERR_500] =
	"HTTP/1.0 500 Server Error\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>500 Server Error</h1>\nAn internal server error occured.\n</body></html>\n",

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

/* We must put the messages here since GCC cannot initialize consts depending
 * on strlen().
 */
struct chunk http_err_chunks[HTTP_ERR_SIZE];

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

#else
#error "Check if your OS uses bitfields for fd_sets"
#endif

void init_proto_http()
{
	int i;
	char *tmp;
	int msg;

	for (msg = 0; msg < HTTP_ERR_SIZE; msg++) {
		if (!http_err_msgs[msg]) {
			Alert("Internal error: no message defined for HTTP return code %d. Aborting.\n", msg);
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

	/* memory allocations */
	pool2_requri = create_pool("requri", REQURI_LEN, MEM_F_SHARED);
	pool2_capture = create_pool("capture", CAPTURE_LEN, MEM_F_SHARED);
}

/*
 * We have 26 list of methods (1 per first letter), each of which can have
 * up to 3 entries (2 valid, 1 null).
 */
struct http_method_desc {
	http_meth_t meth;
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
	['P' - 'A'] = {
		[0] = {	.meth = HTTP_METH_POST    , .len=4, .text="POST"    },
		[1] = {	.meth = HTTP_METH_PUT     , .len=3, .text="PUT"     },
	},
	['T' - 'A'] = {
		[0] = {	.meth = HTTP_METH_TRACE   , .len=5, .text="TRACE"   },
	},
	/* rest is empty like this :
	 *      [1] = {	.meth = HTTP_METH_NONE    , .len=0, .text=""        },
	 */
};

/* It is about twice as fast on recent architectures to lookup a byte in a
 * table than to perform a boolean AND or OR between two tests. Refer to
 * RFC2616 for those chars.
 */

const char http_is_spht[256] = {
	[' '] = 1, ['\t'] = 1,
};

const char http_is_crlf[256] = {
	['\r'] = 1, ['\n'] = 1,
};

const char http_is_lws[256] = {
	[' '] = 1, ['\t'] = 1,
	['\r'] = 1, ['\n'] = 1,
};

const char http_is_sep[256] = {
	['('] = 1, [')']  = 1, ['<']  = 1, ['>'] = 1,
	['@'] = 1, [',']  = 1, [';']  = 1, [':'] = 1,
	['"'] = 1, ['/']  = 1, ['[']  = 1, [']'] = 1,
	['{'] = 1, ['}']  = 1, ['?']  = 1, ['='] = 1,
	[' '] = 1, ['\t'] = 1, ['\\'] = 1,
};

const char http_is_ctl[256] = {
	[0 ... 31] = 1,
	[127] = 1,
};

/*
 * A token is any ASCII char that is neither a separator nor a CTL char.
 * Do not overwrite values in assignment since gcc-2.95 will not handle
 * them correctly. Instead, define every non-CTL char's status.
 */
const char http_is_token[256] = {
	[' '] = 0, ['!'] = 1, ['"'] = 0, ['#'] = 1,
	['$'] = 1, ['%'] = 1, ['&'] = 1, ['\''] = 1,
	['('] = 0, [')'] = 0, ['*'] = 1, ['+'] = 1,
	[','] = 0, ['-'] = 1, ['.'] = 1, ['/'] = 0,
	['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1,
	['4'] = 1, ['5'] = 1, ['6'] = 1, ['7'] = 1,
	['8'] = 1, ['9'] = 1, [':'] = 0, [';'] = 0,
	['<'] = 0, ['='] = 0, ['>'] = 0, ['?'] = 0,
	['@'] = 0, ['A'] = 1, ['B'] = 1, ['C'] = 1,
	['D'] = 1, ['E'] = 1, ['F'] = 1, ['G'] = 1,
	['H'] = 1, ['I'] = 1, ['J'] = 1, ['K'] = 1,
	['L'] = 1, ['M'] = 1, ['N'] = 1, ['O'] = 1,
	['P'] = 1, ['Q'] = 1, ['R'] = 1, ['S'] = 1,
	['T'] = 1, ['U'] = 1, ['V'] = 1, ['W'] = 1,
	['X'] = 1, ['Y'] = 1, ['Z'] = 1, ['['] = 0,
	['\\'] = 0, [']'] = 0, ['^'] = 1, ['_'] = 1,
	['`'] = 1, ['a'] = 1, ['b'] = 1, ['c'] = 1,
	['d'] = 1, ['e'] = 1, ['f'] = 1, ['g'] = 1,
	['h'] = 1, ['i'] = 1, ['j'] = 1, ['k'] = 1,
	['l'] = 1, ['m'] = 1, ['n'] = 1, ['o'] = 1,
	['p'] = 1, ['q'] = 1, ['r'] = 1, ['s'] = 1,
	['t'] = 1, ['u'] = 1, ['v'] = 1, ['w'] = 1,
	['x'] = 1, ['y'] = 1, ['z'] = 1, ['{'] = 0,
	['|'] = 1, ['}'] = 0, ['~'] = 1, 
};


/*
 * An http ver_token is any ASCII which can be found in an HTTP version,
 * which includes 'H', 'T', 'P', '/', '.' and any digit.
 */
const char http_is_ver_token[256] = {
	['.'] = 1, ['/'] = 1,
	['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1, ['4'] = 1,
	['5'] = 1, ['6'] = 1, ['7'] = 1, ['8'] = 1, ['9'] = 1,
	['H'] = 1, ['P'] = 1, ['T'] = 1,
};


#ifdef DEBUG_FULL
static char *cli_stnames[4] = { "DAT", "SHR", "SHW", "CLS" };
#endif

static void http_sess_log(struct session *s);

/*
 * Adds a header and its CRLF at the tail of buffer <b>, just before the last
 * CRLF. Text length is measured first, so it cannot be NULL.
 * The header is also automatically added to the index <hdr_idx>, and the end
 * of headers is automatically adjusted. The number of bytes added is returned
 * on success, otherwise <0 is returned indicating an error.
 */
int http_header_add_tail(struct buffer *b, struct http_msg *msg,
			 struct hdr_idx *hdr_idx, const char *text)
{
	int bytes, len;

	len = strlen(text);
	bytes = buffer_insert_line2(b, b->data + msg->eoh, text, len);
	if (!bytes)
		return -1;
	msg->eoh += bytes;
	return hdr_idx_add(len, 1, hdr_idx, hdr_idx->tail);
}

/*
 * Adds a header and its CRLF at the tail of buffer <b>, just before the last
 * CRLF. <len> bytes are copied, not counting the CRLF. If <text> is NULL, then
 * the buffer is only opened and the space reserved, but nothing is copied.
 * The header is also automatically added to the index <hdr_idx>, and the end
 * of headers is automatically adjusted. The number of bytes added is returned
 * on success, otherwise <0 is returned indicating an error.
 */
int http_header_add_tail2(struct buffer *b, struct http_msg *msg,
			 struct hdr_idx *hdr_idx, const char *text, int len)
{
	int bytes;

	bytes = buffer_insert_line2(b, b->data + msg->eoh, text, len);
	if (!bytes)
		return -1;
	msg->eoh += bytes;
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

/* Find the end of the header value contained between <s> and <e>.
 * See RFC2616, par 2.2 for more information. Note that it requires
 * a valid header to return a valid result.
 */
const char *find_hdr_value_end(const char *s, const char *e)
{
	int quoted, qdpair;

	quoted = qdpair = 0;
	for (; s < e; s++) {
		if (qdpair)                    qdpair = 0;
		else if (quoted && *s == '\\') qdpair = 1;
		else if (quoted && *s == '"')  quoted = 0;
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
 * 1 when it finds a value, and 0 when there is no more.
 */
int http_find_header2(const char *name, int len,
		      const char *sol, struct hdr_idx *idx,
		      struct hdr_ctx *ctx)
{
	__label__ return_hdr, next_hdr;
	const char *eol, *sov;
	int cur_idx;

	if (ctx->idx) {
		/* We have previously returned a value, let's search
		 * another one on the same line.
		 */
		cur_idx = ctx->idx;
		sol = ctx->line;
		sov = sol + ctx->val + ctx->vlen;
		eol = sol + idx->v[cur_idx].len;

		if (sov >= eol)
			/* no more values in this header */
			goto next_hdr;

		/* values remaining for this header, skip the comma */
		sov++;
		while (sov < eol && http_is_lws[(unsigned char)*sov])
			sov++;

		goto return_hdr;
	}

	/* first request for this header */
	sol += hdr_idx_first_pos(idx);
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

			sov = sol + len + 1;
			while (sov < eol && http_is_lws[(unsigned char)*sov])
				sov++;
		return_hdr:
			ctx->line = sol;
			ctx->idx  = cur_idx;
			ctx->val  = sov - sol;

			eol = find_hdr_value_end(sov, eol);
			ctx->vlen = eol - sov;
			return 1;
		}
	next_hdr:
		sol = eol + idx->v[cur_idx].cr + 1;
		cur_idx = idx->v[cur_idx].next;
	}
	return 0;
}

int http_find_header(const char *name,
		     const char *sol, struct hdr_idx *idx,
		     struct hdr_ctx *ctx)
{
	return http_find_header2(name, strlen(name), sol, idx, ctx);
}

/* This function shuts down the buffers on the server side, and sets indicators
 * accordingly. The server's fd is supposed to already be closed. Note that if
 * <status> is 0, or if the message pointer is NULL, then no message is returned.
 */
void srv_close_with_err(struct session *t, int err, int finst,
			int status, const struct chunk *msg)
{
	t->rep->flags |= BF_MAY_FORWARD;
	buffer_shutw(t->req);
	buffer_shutr(t->rep);
	if (status > 0 && msg) {
		t->txn.status = status;
		if (t->fe->mode == PR_MODE_HTTP)
			client_return(t, msg);
	}
	if (!(t->flags & SN_ERR_MASK))
		t->flags |= err;
	if (!(t->flags & SN_FINST_MASK))
		t->flags |= finst;
}

/* This function returns the appropriate error location for the given session
 * and message.
 */

struct chunk *error_message(struct session *s, int msgnum)
{
	if (s->be->errmsg[msgnum].str)
		return &s->be->errmsg[msgnum];
	else if (s->fe->errmsg[msgnum].str)
		return &s->fe->errmsg[msgnum];
	else
		return &http_err_chunks[msgnum];
}

/*
 * returns HTTP_METH_NONE if there is nothing valid to read (empty or non-text
 * string), HTTP_METH_OTHER for unknown methods, or the identified method.
 */
static http_meth_t find_http_meth(const char *str, const int len)
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
		return HTTP_METH_OTHER;
	}
	return HTTP_METH_NONE;

}

/* Parse the URI from the given transaction (which is assumed to be in request
 * phase) and look for the "/" beginning the PATH. If not found, return NULL.
 * It is returned otherwise.
 */
static char *
http_get_path(struct http_txn *txn)
{
	char *ptr, *end;

	ptr = txn->req.sol + txn->req.sl.rq.u;
	end = ptr + txn->req.sl.rq.u_l;

	if (ptr >= end)
		return NULL;

	/* RFC2616, par. 5.1.2 :
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

/* Processes the client, server, request and response jobs of a session task,
 * then puts it back to the wait queue in a clean state, or cleans up its
 * resources if it must be deleted. Returns in <next> the date the task wants
 * to be woken up, or TICK_ETERNITY. In order not to call all functions for
 * nothing too many times, the request and response buffers flags are monitored
 * and each function is called only if at least another function has changed at
 * least one flag. If one of the functions called returns non-zero, then it
 * will be called once again after all other functions. This permits explicit
 * external loops which may be useful for complex state machines.
 */
#define PROCESS_CLI 0x1
#define PROCESS_SRV 0x2
#define PROCESS_REQ 0x4
#define PROCESS_RTR 0x8
#define PROCESS_ALL (PROCESS_CLI|PROCESS_SRV|PROCESS_REQ|PROCESS_RTR)

void process_session(struct task *t, int *next)
{
	struct session *s = t->context;
	unsigned resync = PROCESS_ALL;
	unsigned int rqf;
	unsigned int rpf;

	/* check timeout expiration only once and adjust buffer flags
	 * accordingly.
	 */
	if (unlikely(tick_is_expired(t->expire, now_ms))) {
		if (tick_is_expired(s->req->rex, now_ms))
			s->req->flags |= BF_READ_TIMEOUT;
	
		//if (tick_is_expired(s->req->wex, now_ms))
		//	s->req->flags |= BF_WRITE_TIMEOUT;
		//
		//if (tick_is_expired(s->rep->rex, now_ms))
		//	s->rep->flags |= BF_READ_TIMEOUT;
	
		if (tick_is_expired(s->rep->wex, now_ms))
			s->rep->flags |= BF_WRITE_TIMEOUT;
	}

	//if (fdtab[s->cli_fd].state == FD_STERROR) {
	//	fprintf(stderr, "s=%p fd=%d req=%p rep=%p cs=%d ss=%d, term=%08x\n",
	//		s, s->cli_fd, s->req, s->rep, s->cli_state,
	//		s->si[1].state, s->term_trace);
	//	sleep(1);
	//}
	do {
		if (resync & PROCESS_REQ) {
			resync &= ~PROCESS_REQ;
			rqf = s->req->flags;
			rpf = s->rep->flags;

			/* the analysers must block it themselves */
			s->req->flags |= BF_MAY_FORWARD;

			if (s->req->analysers) {
				if (process_request(s))
					resync |= PROCESS_REQ;

				if (rqf != s->req->flags || rpf != s->rep->flags)
					resync |= PROCESS_ALL & ~PROCESS_REQ;
			}
		}

		if (resync & PROCESS_RTR) {
			resync &= ~PROCESS_RTR;
			rqf = s->req->flags;
			rpf = s->rep->flags;

			/* the analysers must block it themselves */
			s->rep->flags |= BF_MAY_FORWARD;

			if (s->rep->analysers) {
				if (process_response(s))
					resync |= PROCESS_RTR;

				if (rqf != s->req->flags || rpf != s->rep->flags)
					resync |= PROCESS_ALL & ~PROCESS_RTR;
			}
		}

		if (resync & PROCESS_CLI) {
			rqf = s->req->flags;
			rpf = s->rep->flags;

			resync &= ~PROCESS_CLI;
			if (process_cli(s))
				resync |= PROCESS_CLI;

			if (rqf != s->req->flags || rpf != s->rep->flags)
				resync |= PROCESS_ALL & ~PROCESS_CLI;
		}

		if (resync & PROCESS_SRV) {
			rqf = s->req->flags;
			rpf = s->rep->flags;

			resync &= ~PROCESS_SRV;
			if (s->req->cons->state != SI_ST_CLO) {
				if (s->req->cons->state < SI_ST_EST && s->req->flags & BF_MAY_FORWARD)
					process_srv_conn(s);

				if (s->req->cons->state == SI_ST_EST) {
					if (process_srv_data(s))
						resync |= PROCESS_SRV;
				}

				if (unlikely((s->req->cons->state == SI_ST_CLO) &&
					     (global.mode & MODE_DEBUG) &&
					     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
						int len;
						len = sprintf(trash, "%08x:%s.srvcls[%04x:%04x]\n",
							      s->uniq_id, s->be->id, (unsigned short)s->cli_fd, (unsigned short)s->req->cons->fd);
						write(1, trash, len);
				}
			}
			if (rqf != s->req->flags || rpf != s->rep->flags)
				resync |= PROCESS_ALL & ~PROCESS_SRV;
		}
	} while (resync);

	if (likely(s->cli_state != CL_STCLOSE ||
		   (s->req->cons->state != SI_ST_CLO && s->req->cons->state != SI_ST_INI))) {

		if ((s->fe->options & PR_O_CONTSTATS) && (s->flags & SN_BE_ASSIGNED))
			session_process_counters(s);

		s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;

		/* Trick: if a request is being waiting for the server to respond,
		 * and if we know the server can timeout, we don't want the timeout
		 * to expire on the client side first, but we're still interested
		 * in passing data from the client to the server (eg: POST). Thus,
		 * we can cancel the client's request timeout if the server's
		 * request timeout is set and the server has not yet sent a response.
		 */

		if ((s->rep->flags & (BF_MAY_FORWARD|BF_SHUTR)) == 0 &&
		    (tick_isset(s->req->wex) || tick_isset(s->rep->rex)))
			s->req->rex = TICK_ETERNITY;

		t->expire = tick_first(tick_first(s->req->rex, s->req->wex),
				       tick_first(s->rep->rex, s->rep->wex));
		if (s->req->analysers)
			t->expire = tick_first(t->expire, s->req->analyse_exp);

		/* restore t to its place in the task list */
		task_queue(t);

#ifdef DEBUG_DEV
		/* this may only happen when no timeout is set or in case of an FSM bug */
		if (!t->expire)
			ABORT_NOW();
#endif
		*next = t->expire;
		return; /* nothing more to do */
	}

	s->fe->feconn--;
	if (s->flags & SN_BE_ASSIGNED)
		s->be->beconn--;
	actconn--;
    
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		int len;
		len = sprintf(trash, "%08x:%s.closed[%04x:%04x] (term_trace=0x%08x)\n",
			      s->uniq_id, s->be->id,
			      (unsigned short)s->cli_fd, (unsigned short)s->req->cons->fd,
			      s->term_trace);
		write(1, trash, len);
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	session_process_counters(s);

	/* let's do a final log if we need it */
	if (s->logs.logwait && 
	    !(s->flags & SN_MONITOR) &&
	    (!(s->fe->options & PR_O_NULLNOLOG) || s->req->total)) {
		if (s->fe->to_log & LW_REQ)
			http_sess_log(s);
		else
			tcp_sess_log(s);
	}

	/* the task MUST not be in the run queue anymore */
	task_delete(t);
	session_free(s);
	task_free(t);
	*next = TICK_ETERNITY;
}


extern const char sess_term_cond[8];
extern const char sess_fin_state[8];
extern const char *monthname[12];
const char sess_cookie[4]     = "NIDV";		/* No cookie, Invalid cookie, cookie for a Down server, Valid cookie */
const char sess_set_cookie[8] = "N1I3PD5R";	/* No set-cookie, unknown, Set-Cookie Inserted, unknown,
					    	   Set-cookie seen and left unchanged (passive), Set-cookie Deleted,
						   unknown, Set-cookie Rewritten */
struct pool_head *pool2_requri;
struct pool_head *pool2_capture;

/*
 * send a log for the session when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
static void http_sess_log(struct session *s)
{
	char pn[INET6_ADDRSTRLEN + strlen(":65535")];
	struct proxy *fe = s->fe;
	struct proxy *be = s->be;
	struct proxy *prx_log;
	struct http_txn *txn = &s->txn;
	int tolog;
	char *uri, *h;
	char *svid;
	struct tm tm;
	static char tmpline[MAX_SYSLOG_LEN];
	int t_request;
	int hdr;

	if (fe->logfac1 < 0 && fe->logfac2 < 0)
		return;
	prx_log = fe;

	if (s->cli_addr.ss_family == AF_INET)
		inet_ntop(AF_INET,
			  (const void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
			  pn, sizeof(pn));
	else
		inet_ntop(AF_INET6,
			  (const void *)&((struct sockaddr_in6 *)(&s->cli_addr))->sin6_addr,
			  pn, sizeof(pn));

	get_localtime(s->logs.accept_date.tv_sec, &tm);

	/* FIXME: let's limit ourselves to frontend logging for now. */
	tolog = fe->to_log;

	h = tmpline;
	if (fe->to_log & LW_REQHDR &&
	    txn->req.cap &&
	    (h < tmpline + sizeof(tmpline) - 10)) {
		*(h++) = ' ';
		*(h++) = '{';
		for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
			if (hdr)
				*(h++) = '|';
			if (txn->req.cap[hdr] != NULL)
				h = encode_string(h, tmpline + sizeof(tmpline) - 7,
						  '#', hdr_encode_map, txn->req.cap[hdr]);
		}
		*(h++) = '}';
	}

	if (fe->to_log & LW_RSPHDR &&
	    txn->rsp.cap &&
	    (h < tmpline + sizeof(tmpline) - 7)) {
		*(h++) = ' ';
		*(h++) = '{';
		for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
			if (hdr)
				*(h++) = '|';
			if (txn->rsp.cap[hdr] != NULL)
				h = encode_string(h, tmpline + sizeof(tmpline) - 4,
						  '#', hdr_encode_map, txn->rsp.cap[hdr]);
		}
		*(h++) = '}';
	}

	if (h < tmpline + sizeof(tmpline) - 4) {
		*(h++) = ' ';
		*(h++) = '"';
		uri = txn->uri ? txn->uri : "<BADREQ>";
		h = encode_string(h, tmpline + sizeof(tmpline) - 1,
				  '#', url_encode_map, uri);
		*(h++) = '"';
	}
	*h = '\0';

	svid = (tolog & LW_SVID) ?
		(s->data_source != DATA_SRC_STATS) ?
		(s->srv != NULL) ? s->srv->id : "<NOSRV>" : "<STATS>" : "-";

	t_request = -1;
	if (tv_isge(&s->logs.tv_request, &s->logs.tv_accept))
		t_request = tv_ms_elapsed(&s->logs.tv_accept, &s->logs.tv_request);

	send_log(prx_log, LOG_INFO,
		 "%s:%d [%02d/%s/%04d:%02d:%02d:%02d.%03d]"
		 " %s %s/%s %d/%d/%d/%d/%s%d %d %s%lld"
		 " %s %s %c%c%c%c %d/%d/%d/%d/%s%u %d/%d%s\n",
		 pn,
		 (s->cli_addr.ss_family == AF_INET) ?
		 ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port) :
		 ntohs(((struct sockaddr_in6 *)&s->cli_addr)->sin6_port),
		 tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
		 tm.tm_hour, tm.tm_min, tm.tm_sec, s->logs.accept_date.tv_usec/1000,
		 fe->id, be->id, svid,
		 t_request,
		 (s->logs.t_queue >= 0) ? s->logs.t_queue - t_request : -1,
		 (s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1,
		 (s->logs.t_data >= 0) ? s->logs.t_data - s->logs.t_connect : -1,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.t_close,
		 txn->status,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.bytes_out,
		 txn->cli_cookie ? txn->cli_cookie : "-",
		 txn->srv_cookie ? txn->srv_cookie : "-",
		 sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT],
		 sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT],
		 (be->options & PR_O_COOK_ANY) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-',
		 (be->options & PR_O_COOK_ANY) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-',
		 actconn, fe->feconn, be->beconn, s->srv ? s->srv->cur_sess : 0,
		 (s->flags & SN_REDISP)?"+":"",
		 (s->conn_retries>0)?(be->conn_retries - s->conn_retries):be->conn_retries,
		 s->logs.srv_queue_size, s->logs.prx_queue_size, tmpline);

	s->logs.logwait = 0;
}


/*
 * Capture headers from message starting at <som> according to header list
 * <cap_hdr>, and fill the <idx> structure appropriately.
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
		while (sov < eol && http_is_lws[(unsigned char)*sov])
			sov++;
				
		for (h = cap_hdr; h; h = h->next) {
			if ((h->namelen == col - sol) &&
			    (strncasecmp(sol, h->name, h->namelen) == 0)) {
				if (cap[h->index] == NULL)
					cap[h->index] =
						pool_alloc2(h->pool);

				if (cap[h->index] == NULL) {
					Alert("HTTP capture : out of memory.\n");
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


/* either we find an LF at <ptr> or we jump to <bad>.
 */
#define EXPECT_LF_HERE(ptr, bad)	do { if (unlikely(*(ptr) != '\n')) goto bad; } while (0)

/* plays with variables <ptr>, <end> and <state>. Jumps to <good> if OK,
 * otherwise to <http_msg_ood> with <state> set to <st>.
 */
#define EAT_AND_JUMP_OR_RETURN(good, st)   do { \
		ptr++;                          \
		if (likely(ptr < end))          \
			goto good;              \
		else {                          \
			state = (st);           \
			goto http_msg_ood;      \
		}                               \
	} while (0)


/*
 * This function parses a status line between <ptr> and <end>, starting with
 * parser state <state>. Only states HTTP_MSG_RPVER, HTTP_MSG_RPVER_SP,
 * HTTP_MSG_RPCODE, HTTP_MSG_RPCODE_SP and HTTP_MSG_RPREASON are handled. Others
 * will give undefined results.
 * Note that it is upon the caller's responsibility to ensure that ptr < end,
 * and that msg->sol points to the beginning of the response.
 * If a complete line is found (which implies that at least one CR or LF is
 * found before <end>, the updated <ptr> is returned, otherwise NULL is
 * returned indicating an incomplete line (which does not mean that parts have
 * not been updated). In the incomplete case, if <ret_ptr> or <ret_state> are
 * non-NULL, they are fed with the new <ptr> and <state> values to be passed
 * upon next call.
 *
 * This function was intentionally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names. Note that msg->sol is left unchanged.
 */
const char *http_parse_stsline(struct http_msg *msg, const char *msg_buf,
			       unsigned int state, const char *ptr, const char *end,
			       char **ret_ptr, unsigned int *ret_state)
{
	__label__
		http_msg_rpver,
		http_msg_rpver_sp,
		http_msg_rpcode,
		http_msg_rpcode_sp,
		http_msg_rpreason,
		http_msg_rpline_eol,
		http_msg_ood,     /* out of data */
		http_msg_invalid;

	switch (state)	{
	http_msg_rpver:
	case HTTP_MSG_RPVER:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rpver, HTTP_MSG_RPVER);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.st.v_l = (ptr - msg_buf) - msg->som;
			EAT_AND_JUMP_OR_RETURN(http_msg_rpver_sp, HTTP_MSG_RPVER_SP);
		}
		goto http_msg_invalid;
		
	http_msg_rpver_sp:
	case HTTP_MSG_RPVER_SP:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.st.c = ptr - msg_buf;
			goto http_msg_rpcode;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rpver_sp, HTTP_MSG_RPVER_SP);
		/* so it's a CR/LF, this is invalid */
		goto http_msg_invalid;

	http_msg_rpcode:
	case HTTP_MSG_RPCODE:
		if (likely(!HTTP_IS_LWS(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rpcode, HTTP_MSG_RPCODE);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.st.c_l = (ptr - msg_buf) - msg->sl.st.c;
			EAT_AND_JUMP_OR_RETURN(http_msg_rpcode_sp, HTTP_MSG_RPCODE_SP);
		}

		/* so it's a CR/LF, so there is no reason phrase */
		msg->sl.st.c_l = (ptr - msg_buf) - msg->sl.st.c;
	http_msg_rsp_reason:
		/* FIXME: should we support HTTP responses without any reason phrase ? */
		msg->sl.st.r = ptr - msg_buf;
		msg->sl.st.r_l = 0;
		goto http_msg_rpline_eol;

	http_msg_rpcode_sp:
	case HTTP_MSG_RPCODE_SP:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.st.r = ptr - msg_buf;
			goto http_msg_rpreason;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rpcode_sp, HTTP_MSG_RPCODE_SP);
		/* so it's a CR/LF, so there is no reason phrase */
		goto http_msg_rsp_reason;

	http_msg_rpreason:
	case HTTP_MSG_RPREASON:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rpreason, HTTP_MSG_RPREASON);
		msg->sl.st.r_l = (ptr - msg_buf) - msg->sl.st.r;
	http_msg_rpline_eol:
		/* We have seen the end of line. Note that we do not
		 * necessarily have the \n yet, but at least we know that we
		 * have EITHER \r OR \n, otherwise the response would not be
		 * complete. We can then record the response length and return
		 * to the caller which will be able to register it.
		 */
		msg->sl.st.l = ptr - msg->sol;
		return ptr;

#ifdef DEBUG_FULL
	default:
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
	}

 http_msg_ood:
	/* out of data */
	if (ret_state)
		*ret_state = state;
	if (ret_ptr)
		*ret_ptr = (char *)ptr;
	return NULL;

 http_msg_invalid:
	/* invalid message */
	if (ret_state)
		*ret_state = HTTP_MSG_ERROR;
	return NULL;
}


/*
 * This function parses a request line between <ptr> and <end>, starting with
 * parser state <state>. Only states HTTP_MSG_RQMETH, HTTP_MSG_RQMETH_SP,
 * HTTP_MSG_RQURI, HTTP_MSG_RQURI_SP and HTTP_MSG_RQVER are handled. Others
 * will give undefined results.
 * Note that it is upon the caller's responsibility to ensure that ptr < end,
 * and that msg->sol points to the beginning of the request.
 * If a complete line is found (which implies that at least one CR or LF is
 * found before <end>, the updated <ptr> is returned, otherwise NULL is
 * returned indicating an incomplete line (which does not mean that parts have
 * not been updated). In the incomplete case, if <ret_ptr> or <ret_state> are
 * non-NULL, they are fed with the new <ptr> and <state> values to be passed
 * upon next call.
 *
 * This function was intentionally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names. Note that msg->sol is left unchanged.
 */
const char *http_parse_reqline(struct http_msg *msg, const char *msg_buf,
			       unsigned int state, const char *ptr, const char *end,
			       char **ret_ptr, unsigned int *ret_state)
{
	__label__
		http_msg_rqmeth,
		http_msg_rqmeth_sp,
		http_msg_rquri,
		http_msg_rquri_sp,
		http_msg_rqver,
		http_msg_rqline_eol,
		http_msg_ood,     /* out of data */
		http_msg_invalid;

	switch (state)	{
	http_msg_rqmeth:
	case HTTP_MSG_RQMETH:
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rqmeth, HTTP_MSG_RQMETH);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.rq.m_l = (ptr - msg_buf) - msg->som;
			EAT_AND_JUMP_OR_RETURN(http_msg_rqmeth_sp, HTTP_MSG_RQMETH_SP);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* HTTP 0.9 request */
			msg->sl.rq.m_l = (ptr - msg_buf) - msg->som;
		http_msg_req09_uri:
			msg->sl.rq.u = ptr - msg_buf;
		http_msg_req09_uri_e:
			msg->sl.rq.u_l = (ptr - msg_buf) - msg->sl.rq.u;
		http_msg_req09_ver:
			msg->sl.rq.v = ptr - msg_buf;
			msg->sl.rq.v_l = 0;
			goto http_msg_rqline_eol;
		}
		goto http_msg_invalid;
		
	http_msg_rqmeth_sp:
	case HTTP_MSG_RQMETH_SP:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.rq.u = ptr - msg_buf;
			goto http_msg_rquri;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rqmeth_sp, HTTP_MSG_RQMETH_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_uri;

	http_msg_rquri:
	case HTTP_MSG_RQURI:
		if (likely(!HTTP_IS_LWS(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rquri, HTTP_MSG_RQURI);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.rq.u_l = (ptr - msg_buf) - msg->sl.rq.u;
			EAT_AND_JUMP_OR_RETURN(http_msg_rquri_sp, HTTP_MSG_RQURI_SP);
		}

		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_uri_e;

	http_msg_rquri_sp:
	case HTTP_MSG_RQURI_SP:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.rq.v = ptr - msg_buf;
			goto http_msg_rqver;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rquri_sp, HTTP_MSG_RQURI_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_ver;

	http_msg_rqver:
	case HTTP_MSG_RQVER:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_rqver, HTTP_MSG_RQVER);

		if (likely(HTTP_IS_CRLF(*ptr))) {
			msg->sl.rq.v_l = (ptr - msg_buf) - msg->sl.rq.v;
		http_msg_rqline_eol:
			/* We have seen the end of line. Note that we do not
			 * necessarily have the \n yet, but at least we know that we
			 * have EITHER \r OR \n, otherwise the request would not be
			 * complete. We can then record the request length and return
			 * to the caller which will be able to register it.
			 */
			msg->sl.rq.l = ptr - msg->sol;
			return ptr;
		}

		/* neither an HTTP_VER token nor a CRLF */
		goto http_msg_invalid;

#ifdef DEBUG_FULL
	default:
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
	}

 http_msg_ood:
	/* out of data */
	if (ret_state)
		*ret_state = state;
	if (ret_ptr)
		*ret_ptr = (char *)ptr;
	return NULL;

 http_msg_invalid:
	/* invalid message */
	if (ret_state)
		*ret_state = HTTP_MSG_ERROR;
	return NULL;
}


/*
 * This function parses an HTTP message, either a request or a response,
 * depending on the initial msg->msg_state. It can be preempted everywhere
 * when data are missing and recalled at the exact same location with no
 * information loss. The header index is re-initialized when switching from
 * MSG_R[PQ]BEFORE to MSG_RPVER|MSG_RQMETH. It modifies msg->sol among other
 * fields.
 */
void http_msg_analyzer(struct buffer *buf, struct http_msg *msg, struct hdr_idx *idx)
{
	__label__
		http_msg_rqbefore,
		http_msg_rqbefore_cr,
		http_msg_rqmeth,
		http_msg_rqline_end,
		http_msg_hdr_first,
		http_msg_hdr_name,
		http_msg_hdr_l1_sp,
		http_msg_hdr_l1_lf,
		http_msg_hdr_l1_lws,
		http_msg_hdr_val,
		http_msg_hdr_l2_lf,
		http_msg_hdr_l2_lws,
		http_msg_complete_header,
		http_msg_last_lf,
		http_msg_ood,     /* out of data */
		http_msg_invalid;

	unsigned int state;       /* updated only when leaving the FSM */
	register char *ptr, *end; /* request pointers, to avoid dereferences */

	state = msg->msg_state;
	ptr = buf->lr;
	end = buf->r;

	if (unlikely(ptr >= end))
		goto http_msg_ood;

	switch (state)	{
	/*
	 * First, states that are specific to the response only.
	 * We check them first so that request and headers are
	 * closer to each other (accessed more often).
	 */
	http_msg_rpbefore:
	case HTTP_MSG_RPBEFORE:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			if (likely(ptr == buf->data)) {
				msg->sol = ptr;
				msg->som = 0;
			} else {
#if PARSE_PRESERVE_EMPTY_LINES
				/* only skip empty leading lines, don't remove them */
				msg->sol = ptr;
				msg->som = ptr - buf->data;
#else
				/* Remove empty leading lines, as recommended by
				 * RFC2616. This takes a lot of time because we
				 * must move all the buffer backwards, but this
				 * is rarely needed. The method above will be
				 * cleaner when we'll be able to start sending
				 * the request from any place in the buffer.
				 */
				buf->lr = ptr;
				buffer_replace2(buf, buf->data, buf->lr, NULL, 0);
				msg->som = 0;
				msg->sol = buf->data;
				ptr = buf->data;
				end = buf->r;
#endif
			}
			hdr_idx_init(idx);
			state = HTTP_MSG_RPVER;
			goto http_msg_rpver;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr)))
			goto http_msg_invalid;

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(http_msg_rpbefore, HTTP_MSG_RPBEFORE);
		EAT_AND_JUMP_OR_RETURN(http_msg_rpbefore_cr, HTTP_MSG_RPBEFORE_CR);
		/* stop here */

	http_msg_rpbefore_cr:
	case HTTP_MSG_RPBEFORE_CR:
		EXPECT_LF_HERE(ptr, http_msg_invalid);
		EAT_AND_JUMP_OR_RETURN(http_msg_rpbefore, HTTP_MSG_RPBEFORE);
		/* stop here */

	http_msg_rpver:
	case HTTP_MSG_RPVER:
	case HTTP_MSG_RPVER_SP:
	case HTTP_MSG_RPCODE:
	case HTTP_MSG_RPCODE_SP:
	case HTTP_MSG_RPREASON:
		ptr = (char *)http_parse_stsline(msg, buf->data, state, ptr, end,
						 &buf->lr, &msg->msg_state);
		if (unlikely(!ptr))
			return;

		/* we have a full response and we know that we have either a CR
		 * or an LF at <ptr>.
		 */
		//fprintf(stderr,"som=%d rq.l=%d *ptr=0x%02x\n", msg->som, msg->sl.st.l, *ptr);
		hdr_idx_set_start(idx, msg->sl.st.l, *ptr == '\r');

		msg->sol = ptr;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(http_msg_rpline_end, HTTP_MSG_RPLINE_END);
		goto http_msg_rpline_end;

	http_msg_rpline_end:
	case HTTP_MSG_RPLINE_END:
		/* msg->sol must point to the first of CR or LF. */
		EXPECT_LF_HERE(ptr, http_msg_invalid);
		EAT_AND_JUMP_OR_RETURN(http_msg_hdr_first, HTTP_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Second, states that are specific to the request only
	 */
	http_msg_rqbefore:
	case HTTP_MSG_RQBEFORE:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			if (likely(ptr == buf->data)) {
				msg->sol = ptr;
				msg->som = 0;
			} else {
#if PARSE_PRESERVE_EMPTY_LINES
				/* only skip empty leading lines, don't remove them */
				msg->sol = ptr;
				msg->som = ptr - buf->data;
#else
				/* Remove empty leading lines, as recommended by
				 * RFC2616. This takes a lot of time because we
				 * must move all the buffer backwards, but this
				 * is rarely needed. The method above will be
				 * cleaner when we'll be able to start sending
				 * the request from any place in the buffer.
				 */
				buf->lr = ptr;
				buffer_replace2(buf, buf->data, buf->lr, NULL, 0);
				msg->som = 0;
				msg->sol = buf->data;
				ptr = buf->data;
				end = buf->r;
#endif
			}
			/* we will need this when keep-alive will be supported
			   hdr_idx_init(idx);
			 */
			state = HTTP_MSG_RQMETH;
			goto http_msg_rqmeth;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr)))
			goto http_msg_invalid;

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(http_msg_rqbefore, HTTP_MSG_RQBEFORE);
		EAT_AND_JUMP_OR_RETURN(http_msg_rqbefore_cr, HTTP_MSG_RQBEFORE_CR);
		/* stop here */

	http_msg_rqbefore_cr:
	case HTTP_MSG_RQBEFORE_CR:
		EXPECT_LF_HERE(ptr, http_msg_invalid);
		EAT_AND_JUMP_OR_RETURN(http_msg_rqbefore, HTTP_MSG_RQBEFORE);
		/* stop here */

	http_msg_rqmeth:
	case HTTP_MSG_RQMETH:
	case HTTP_MSG_RQMETH_SP:
	case HTTP_MSG_RQURI:
	case HTTP_MSG_RQURI_SP:
	case HTTP_MSG_RQVER:
		ptr = (char *)http_parse_reqline(msg, buf->data, state, ptr, end,
						 &buf->lr, &msg->msg_state);
		if (unlikely(!ptr))
			return;

		/* we have a full request and we know that we have either a CR
		 * or an LF at <ptr>.
		 */
		//fprintf(stderr,"som=%d rq.l=%d *ptr=0x%02x\n", msg->som, msg->sl.rq.l, *ptr);
		hdr_idx_set_start(idx, msg->sl.rq.l, *ptr == '\r');

		msg->sol = ptr;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(http_msg_rqline_end, HTTP_MSG_RQLINE_END);
		goto http_msg_rqline_end;

	http_msg_rqline_end:
	case HTTP_MSG_RQLINE_END:
		/* check for HTTP/0.9 request : no version information available.
		 * msg->sol must point to the first of CR or LF.
		 */
		if (unlikely(msg->sl.rq.v_l == 0))
			goto http_msg_last_lf;

		EXPECT_LF_HERE(ptr, http_msg_invalid);
		EAT_AND_JUMP_OR_RETURN(http_msg_hdr_first, HTTP_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Common states below
	 */
	http_msg_hdr_first:
	case HTTP_MSG_HDR_FIRST:
		msg->sol = ptr;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}
		
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(http_msg_last_lf, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	http_msg_hdr_name:
	case HTTP_MSG_HDR_NAME:
		/* assumes msg->sol points to the first char */
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_hdr_name, HTTP_MSG_HDR_NAME);

		if (likely(*ptr == ':')) {
			msg->col = ptr - buf->data;
			EAT_AND_JUMP_OR_RETURN(http_msg_hdr_l1_sp, HTTP_MSG_HDR_L1_SP);
		}

		goto http_msg_invalid;

	http_msg_hdr_l1_sp:
	case HTTP_MSG_HDR_L1_SP:
		/* assumes msg->sol points to the first char and msg->col to the colon */
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_hdr_l1_sp, HTTP_MSG_HDR_L1_SP);

		/* header value can be basically anything except CR/LF */
		msg->sov = ptr - buf->data;

		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_val;
		}
			
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(http_msg_hdr_l1_lf, HTTP_MSG_HDR_L1_LF);
		goto http_msg_hdr_l1_lf;

	http_msg_hdr_l1_lf:
	case HTTP_MSG_HDR_L1_LF:
		EXPECT_LF_HERE(ptr, http_msg_invalid);
		EAT_AND_JUMP_OR_RETURN(http_msg_hdr_l1_lws, HTTP_MSG_HDR_L1_LWS);

	http_msg_hdr_l1_lws:
	case HTTP_MSG_HDR_L1_LWS:
		if (likely(HTTP_IS_SPHT(*ptr))) {
			/* replace HT,CR,LF with spaces */
			for (; buf->data+msg->sov < ptr; msg->sov++)
				buf->data[msg->sov] = ' ';
			goto http_msg_hdr_l1_sp;
		}
		/* we had a header consisting only in spaces ! */
		msg->eol = buf->data + msg->sov;
		goto http_msg_complete_header;
		
	http_msg_hdr_val:
	case HTTP_MSG_HDR_VAL:
		/* assumes msg->sol points to the first char, msg->col to the
		 * colon, and msg->sov points to the first character of the
		 * value.
		 */
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(http_msg_hdr_val, HTTP_MSG_HDR_VAL);

		msg->eol = ptr;
		/* Note: we could also copy eol into ->eoh so that we have the
		 * real header end in case it ends with lots of LWS, but is this
		 * really needed ?
		 */
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(http_msg_hdr_l2_lf, HTTP_MSG_HDR_L2_LF);
		goto http_msg_hdr_l2_lf;

	http_msg_hdr_l2_lf:
	case HTTP_MSG_HDR_L2_LF:
		EXPECT_LF_HERE(ptr, http_msg_invalid);
		EAT_AND_JUMP_OR_RETURN(http_msg_hdr_l2_lws, HTTP_MSG_HDR_L2_LWS);

	http_msg_hdr_l2_lws:
	case HTTP_MSG_HDR_L2_LWS:
		if (unlikely(HTTP_IS_SPHT(*ptr))) {
			/* LWS: replace HT,CR,LF with spaces */
			for (; msg->eol < ptr; msg->eol++)
				*msg->eol = ' ';
			goto http_msg_hdr_val;
		}
	http_msg_complete_header:
		/*
		 * It was a new header, so the last one is finished.
		 * Assumes msg->sol points to the first char, msg->col to the
		 * colon, msg->sov points to the first character of the value
		 * and msg->eol to the first CR or LF so we know how the line
		 * ends. We insert last header into the index.
		 */
		/*
		  fprintf(stderr,"registering %-2d bytes : ", msg->eol - msg->sol);
		  write(2, msg->sol, msg->eol-msg->sol);
		  fprintf(stderr,"\n");
		*/

		if (unlikely(hdr_idx_add(msg->eol - msg->sol, *msg->eol == '\r',
					 idx, idx->tail) < 0))
			goto http_msg_invalid;

		msg->sol = ptr;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}
		
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(http_msg_last_lf, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	http_msg_last_lf:
	case HTTP_MSG_LAST_LF:
		/* Assumes msg->sol points to the first of either CR or LF */
		EXPECT_LF_HERE(ptr, http_msg_invalid);
		ptr++;
		buf->lr = ptr;
		msg->eoh = msg->sol - buf->data;
		msg->msg_state = HTTP_MSG_BODY;
		return;
#ifdef DEBUG_FULL
	default:
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
	}
 http_msg_ood:
	/* out of data */
	msg->msg_state = state;
	buf->lr = ptr;
	return;

 http_msg_invalid:
	/* invalid message */
	msg->msg_state = HTTP_MSG_ERROR;
	return;
}

/* This function performs all the processing enabled for the current request.
 * It normally returns zero, but may return 1 if it absolutely needs to be
 * called again after other functions. It relies on buffers flags, and updates
 * t->req->analysers. It might make sense to explode it into several other
 * functions. Its behaviour is rather simple :
 *  - all enabled analysers are called in turn from the lower to the higher
 *    bit.
 *  - if an analyser does not have enough data, it must return without calling
 *    other ones. It should also probably reset the BF_MAY_FORWARD bit to ensure
 *    that unprocessed data will not be forwarded. But that probably depends on
 *    the protocol. Generally it is not reset in case of errors.
 *  - if an analyser has enough data, it just has to pass on to the next
 *    analyser without touching BF_MAY_FORWARD (it is enabled prior to
 *    analysis).
 *  - if an analyser thinks it has no added value anymore staying here, it must
 *    reset its bit from the analysers flags in order not to be called anymore.
 *
 * In the future, analysers should be able to indicate that they want to be
 * called after XXX bytes have been received (or transfered), and the min of
 * all's wishes will be used to ring back (unless a special condition occurs).
 *
 *
 */
int process_request(struct session *t)
{
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;

	DPRINTF(stderr,"[%u] %s: c=%s set(r,w)=%d,%d exp(r,w)=%u,%u req=%08x rep=%08x analysers=%02x\n",
		now_ms, __FUNCTION__,
		cli_stnames[t->cli_state],
		t->cli_fd >= 0 && fdtab[t->cli_fd].state != FD_STCLOSE ? EV_FD_ISSET(t->cli_fd, DIR_RD) : 0,
		t->cli_fd >= 0 && fdtab[t->cli_fd].state != FD_STCLOSE ? EV_FD_ISSET(t->cli_fd, DIR_WR) : 0,
		req->rex, rep->wex, req->flags, rep->flags, req->analysers);

	/* The tcp-inspect analyser is always called alone */
	if (req->analysers & AN_REQ_INSPECT) {
		struct tcp_rule *rule;
		int partial;

		/* We will abort if we encounter a read error. In theory, we
		 * should not abort if we get a close, it might be valid,
		 * although very unlikely. FIXME: we'll abort for now, this
		 * will be easier to change later.
		 */
		if (req->flags & BF_READ_ERROR) {
			req->analysers = 0;
			t->fe->failed_req++;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLICL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_R;
			return 0;
		}

		/* Abort if client read timeout has expired */
		else if (req->flags & BF_READ_TIMEOUT) {
			req->analysers = 0;
			t->fe->failed_req++;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_R;
			return 0;
		}

		/* We don't know whether we have enough data, so must proceed
		 * this way :
		 * - iterate through all rules in their declaration order
		 * - if one rule returns MISS, it means the inspect delay is
		 *   not over yet, then return immediately, otherwise consider
		 *   it as a non-match.
		 * - if one rule returns OK, then return OK
		 * - if one rule returns KO, then return KO
		 */

		if (req->flags & (BF_READ_NULL | BF_SHUTR) || tick_is_expired(req->analyse_exp, now_ms))
			partial = 0;
		else
			partial = ACL_PARTIAL;

		list_for_each_entry(rule, &t->fe->tcp_req.inspect_rules, list) {
			int ret = ACL_PAT_PASS;

			if (rule->cond) {
				ret = acl_exec_cond(rule->cond, t->fe, t, NULL, ACL_DIR_REQ | partial);
				if (ret == ACL_PAT_MISS) {
					req->flags &= ~BF_MAY_FORWARD;
					/* just set the request timeout once at the beginning of the request */
					if (!tick_isset(req->analyse_exp))
						req->analyse_exp = tick_add_ifset(now_ms, t->fe->tcp_req.inspect_delay);
					return 0;
				}

				ret = acl_pass(ret);
				if (rule->cond->pol == ACL_COND_UNLESS)
					ret = !ret;
			}

			if (ret) {
				/* we have a matching rule. */
				if (rule->action == TCP_ACT_REJECT) {
					buffer_abort(req);
					buffer_abort(rep);
					//FIXME: this delete this
					//fd_delete(t->cli_fd);
					//t->cli_state = CL_STCLOSE;
					req->analysers = 0;
					t->fe->failed_req++;
					if (!(t->flags & SN_ERR_MASK))
						t->flags |= SN_ERR_PRXCOND;
					if (!(t->flags & SN_FINST_MASK))
						t->flags |= SN_FINST_R;
					return 0;
				}
				/* otherwise accept */
				break;
			}
		}
		
		/* if we get there, it means we have no rule which matches, or
		 * we have an explicit accept, so we apply the default accept.
		 */
		req->analysers &= ~AN_REQ_INSPECT;
		req->analyse_exp = TICK_ETERNITY;
	}

	if (req->analysers & AN_REQ_HTTP_HDR) {
		/*
		 * Now parse the partial (or complete) lines.
		 * We will check the request syntax, and also join multi-line
		 * headers. An index of all the lines will be elaborated while
		 * parsing.
		 *
		 * For the parsing, we use a 28 states FSM.
		 *
		 * Here is the information we currently have :
		 *   req->data + req->som  = beginning of request
		 *   req->data + req->eoh  = end of processed headers / start of current one
		 *   req->data + req->eol  = end of current header or line (LF or CRLF)
		 *   req->lr = first non-visited byte
		 *   req->r  = end of data
		 */

		int cur_idx;
		struct http_txn *txn = &t->txn;
		struct http_msg *msg = &txn->req;
		struct proxy *cur_proxy;

		if (likely(req->lr < req->r))
			http_msg_analyzer(req, msg, &txn->hdr_idx);

		/* 1: we might have to print this header in debug mode */
		if (unlikely((global.mode & MODE_DEBUG) &&
			     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
			     (msg->msg_state == HTTP_MSG_BODY || msg->msg_state == HTTP_MSG_ERROR))) {
			char *eol, *sol;

			sol = req->data + msg->som;
			eol = sol + msg->sl.rq.l;
			debug_hdr("clireq", t, sol, eol);

			sol += hdr_idx_first_pos(&txn->hdr_idx);
			cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

			while (cur_idx) {
				eol = sol + txn->hdr_idx.v[cur_idx].len;
				debug_hdr("clihdr", t, sol, eol);
				sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
				cur_idx = txn->hdr_idx.v[cur_idx].next;
			}
		}


		/*
		 * Now we quickly check if we have found a full valid request.
		 * If not so, we check the FD and buffer states before leaving.
		 * A full request is indicated by the fact that we have seen
		 * the double LF/CRLF, so the state is HTTP_MSG_BODY. Invalid
		 * requests are checked first.
		 *
		 */

		if (unlikely(msg->msg_state != HTTP_MSG_BODY)) {
			/*
			 * First, let's catch bad requests.
			 */
			if (unlikely(msg->msg_state == HTTP_MSG_ERROR))
				goto return_bad_req;

			/* 1: Since we are in header mode, if there's no space
			 *    left for headers, we won't be able to free more
			 *    later, so the session will never terminate. We
			 *    must terminate it now.
			 */
			if (unlikely(req->flags & BF_FULL)) {
				/* FIXME: check if URI is set and return Status
				 * 414 Request URI too long instead.
				 */
				goto return_bad_req;
			}

			/* 2: have we encountered a close ? */
			else if (req->flags & (BF_READ_NULL | BF_SHUTR)) {
				txn->status = 400;
				client_retnclose(t, error_message(t, HTTP_ERR_400));
				msg->msg_state = HTTP_MSG_ERROR;
				req->analysers = 0;
				t->fe->failed_req++;

				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLICL;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_R;
				return 0;
			}

			/* 3: has the read timeout expired ? */
			else if (req->flags & BF_READ_TIMEOUT || tick_is_expired(req->analyse_exp, now_ms)) {
				/* read timeout : give up with an error message. */
				txn->status = 408;
				client_retnclose(t, error_message(t, HTTP_ERR_408));
				msg->msg_state = HTTP_MSG_ERROR;
				req->analysers = 0;
				t->fe->failed_req++;
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLITO;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_R;
				return 0;
			}

			/* 4: have we encountered a read error ? */
			else if (req->flags & BF_READ_ERROR) {
				/* we cannot return any message on error */
				msg->msg_state = HTTP_MSG_ERROR;
				req->analysers = 0;
				t->fe->failed_req++;
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLICL;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_R;
				return 0;
			}

			req->flags &= ~BF_MAY_FORWARD;
			/* just set the request timeout once at the beginning of the request */
			if (!tick_isset(req->analyse_exp))
				req->analyse_exp = tick_add_ifset(now_ms, t->fe->timeout.httpreq);

			/* we're not ready yet */
			return 0;
		}


		/****************************************************************
		 * More interesting part now : we know that we have a complete  *
		 * request which at least looks like HTTP. We have an indicator *
		 * of each header's length, so we can parse them quickly.       *
		 ****************************************************************/

		req->analysers &= ~AN_REQ_HTTP_HDR;
		req->analyse_exp = TICK_ETERNITY;

		/* ensure we keep this pointer to the beginning of the message */
		msg->sol = req->data + msg->som;

		/*
		 * 1: identify the method
		 */
		txn->meth = find_http_meth(&req->data[msg->som], msg->sl.rq.m_l);

		/* we can make use of server redirect on GET and HEAD */
		if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
			t->flags |= SN_REDIRECTABLE;

		/*
		 * 2: check if the URI matches the monitor_uri.
		 * We have to do this for every request which gets in, because
		 * the monitor-uri is defined by the frontend.
		 */
		if (unlikely((t->fe->monitor_uri_len != 0) &&
			     (t->fe->monitor_uri_len == msg->sl.rq.u_l) &&
			     !memcmp(&req->data[msg->sl.rq.u],
				     t->fe->monitor_uri,
				     t->fe->monitor_uri_len))) {
			/*
			 * We have found the monitor URI
			 */
			struct acl_cond *cond;
			cur_proxy = t->fe;

			t->flags |= SN_MONITOR;

			/* Check if we want to fail this monitor request or not */
			list_for_each_entry(cond, &cur_proxy->mon_fail_cond, list) {
				int ret = acl_exec_cond(cond, cur_proxy, t, txn, ACL_DIR_REQ);

				ret = acl_pass(ret);
				if (cond->pol == ACL_COND_UNLESS)
					ret = !ret;

				if (ret) {
					/* we fail this request, let's return 503 service unavail */
					txn->status = 503;
					client_retnclose(t, error_message(t, HTTP_ERR_503));
					goto return_prx_cond;
				}
			}

			/* nothing to fail, let's reply normaly */
			txn->status = 200;
			client_retnclose(t, &http_200_chunk);
			goto return_prx_cond;
		}
			
		/*
		 * 3: Maybe we have to copy the original REQURI for the logs ?
		 * Note: we cannot log anymore if the request has been
		 * classified as invalid.
		 */
		if (unlikely(t->logs.logwait & LW_REQ)) {
			/* we have a complete HTTP request that we must log */
			if ((txn->uri = pool_alloc2(pool2_requri)) != NULL) {
				int urilen = msg->sl.rq.l;

				if (urilen >= REQURI_LEN)
					urilen = REQURI_LEN - 1;
				memcpy(txn->uri, &req->data[msg->som], urilen);
				txn->uri[urilen] = 0;

				if (!(t->logs.logwait &= ~LW_REQ))
					http_sess_log(t);
			} else {
				Alert("HTTP logging : out of memory.\n");
			}
		}


		/* 4. We may have to convert HTTP/0.9 requests to HTTP/1.0 */
		if (unlikely(msg->sl.rq.v_l == 0)) {
			int delta;
			char *cur_end;
			msg->sol = req->data + msg->som;
			cur_end = msg->sol + msg->sl.rq.l;
			delta = 0;

			if (msg->sl.rq.u_l == 0) {
				/* if no URI was set, add "/" */
				delta = buffer_replace2(req, cur_end, cur_end, " /", 2);
				cur_end += delta;
				msg->eoh += delta;
			}
			/* add HTTP version */
			delta = buffer_replace2(req, cur_end, cur_end, " HTTP/1.0\r\n", 11);
			msg->eoh += delta;
			cur_end += delta;
			cur_end = (char *)http_parse_reqline(msg, req->data,
							     HTTP_MSG_RQMETH,
							     msg->sol, cur_end + 1,
							     NULL, NULL);
			if (unlikely(!cur_end))
				goto return_bad_req;

			/* we have a full HTTP/1.0 request now and we know that
			 * we have either a CR or an LF at <ptr>.
			 */
			hdr_idx_set_start(&txn->hdr_idx, msg->sl.rq.l, *cur_end == '\r');
		}


		/* 5: we may need to capture headers */
		if (unlikely((t->logs.logwait & LW_REQHDR) && t->fe->req_cap))
			capture_headers(req->data + msg->som, &txn->hdr_idx,
					txn->req.cap, t->fe->req_cap);

		/*
		 * 6: we will have to evaluate the filters.
		 * As opposed to version 1.2, now they will be evaluated in the
		 * filters order and not in the header order. This means that
		 * each filter has to be validated among all headers.
		 *
		 * We can now check whether we want to switch to another
		 * backend, in which case we will re-check the backend's
		 * filters and various options. In order to support 3-level
		 * switching, here's how we should proceed :
		 *
		 *  a) run be.
		 *     if (switch) then switch ->be to the new backend.
		 *  b) run be if (be != fe).
		 *     There cannot be any switch from there, so ->be cannot be
		 *     changed anymore.
		 *
		 * => filters always apply to ->be, then ->be may change.
		 *
		 * The response path will be able to apply either ->be, or
		 * ->be then ->fe filters in order to match the reverse of
		 * the forward sequence.
		 */

		do {
			struct acl_cond *cond;
			struct redirect_rule *rule;
			struct proxy *rule_set = t->be;
			cur_proxy = t->be;

			/* first check whether we have some ACLs set to redirect this request */
			list_for_each_entry(rule, &cur_proxy->redirect_rules, list) {
				int ret = acl_exec_cond(rule->cond, cur_proxy, t, txn, ACL_DIR_REQ);

				ret = acl_pass(ret);
				if (rule->cond->pol == ACL_COND_UNLESS)
					ret = !ret;

				if (ret) {
					struct chunk rdr = { trash, 0 };
					const char *msg_fmt;

					/* build redirect message */
					switch(rule->code) {
						case 303:
							rdr.len = strlen(HTTP_303);
							msg_fmt = HTTP_303;
							break;
						case 301:
							rdr.len = strlen(HTTP_301);
							msg_fmt = HTTP_301;
							break;
						case 302:
						default:
							rdr.len = strlen(HTTP_302);
							msg_fmt = HTTP_302;
							break;
					}

					if (unlikely(rdr.len > sizeof(trash)))
						goto return_bad_req;
					memcpy(rdr.str, msg_fmt, rdr.len);

					switch(rule->type) {
						case REDIRECT_TYPE_PREFIX: {
							const char *path;
							int pathlen;

							path = http_get_path(txn);
							/* build message using path */
							if (path) {
								pathlen = txn->req.sl.rq.u_l + (txn->req.sol+txn->req.sl.rq.u) - path;
							} else {
								path = "/";
								pathlen = 1;
							}

							if (rdr.len + rule->rdr_len + pathlen > sizeof(trash) - 4)
								goto return_bad_req;

							/* add prefix */
							memcpy(rdr.str + rdr.len, rule->rdr_str, rule->rdr_len);
							rdr.len += rule->rdr_len;

							/* add path */
							memcpy(rdr.str + rdr.len, path, pathlen);
							rdr.len += pathlen;
							break;
						}
						case REDIRECT_TYPE_LOCATION:
						default:
							if (rdr.len + rule->rdr_len > sizeof(trash) - 4)
								goto return_bad_req;

							/* add location */
							memcpy(rdr.str + rdr.len, rule->rdr_str, rule->rdr_len);
							rdr.len += rule->rdr_len;
							break;
					}

					/* add end of headers */
					memcpy(rdr.str + rdr.len, "\r\n\r\n", 4);
					rdr.len += 4;

					txn->status = rule->code;
					/* let's log the request time */
					t->logs.tv_request = now;
					client_retnclose(t, &rdr);
					goto return_prx_cond;
				}
			}

			/* first check whether we have some ACLs set to block this request */
			list_for_each_entry(cond, &cur_proxy->block_cond, list) {
				int ret = acl_exec_cond(cond, cur_proxy, t, txn, ACL_DIR_REQ);

				ret = acl_pass(ret);
				if (cond->pol == ACL_COND_UNLESS)
					ret = !ret;

				if (ret) {
					txn->status = 403;
					/* let's log the request time */
					t->logs.tv_request = now;
					client_retnclose(t, error_message(t, HTTP_ERR_403));
					goto return_prx_cond;
				}
			}

			/* try headers filters */
			if (rule_set->req_exp != NULL) {
				if (apply_filters_to_request(t, req, rule_set->req_exp) < 0)
					goto return_bad_req;
			}

			if (!(t->flags & SN_BE_ASSIGNED) && (t->be != cur_proxy)) {
				/* to ensure correct connection accounting on
				 * the backend, we count the connection for the
				 * one managing the queue.
				 */
				t->be->beconn++;
				if (t->be->beconn > t->be->beconn_max)
					t->be->beconn_max = t->be->beconn;
				t->be->cum_beconn++;
				t->flags |= SN_BE_ASSIGNED;
			}

			/* has the request been denied ? */
			if (txn->flags & TX_CLDENY) {
				/* no need to go further */
				txn->status = 403;
				/* let's log the request time */
				t->logs.tv_request = now;
				client_retnclose(t, error_message(t, HTTP_ERR_403));
				goto return_prx_cond;
			}

			/* We might have to check for "Connection:" */
			if (((t->fe->options | t->be->options) & (PR_O_HTTP_CLOSE|PR_O_FORCE_CLO)) &&
			    !(t->flags & SN_CONN_CLOSED)) {
				char *cur_ptr, *cur_end, *cur_next;
				int cur_idx, old_idx, delta, val;
				struct hdr_idx_elem *cur_hdr;

				cur_next = req->data + txn->req.som + hdr_idx_first_pos(&txn->hdr_idx);
				old_idx = 0;

				while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
					cur_hdr  = &txn->hdr_idx.v[cur_idx];
					cur_ptr  = cur_next;
					cur_end  = cur_ptr + cur_hdr->len;
					cur_next = cur_end + cur_hdr->cr + 1;

					val = http_header_match2(cur_ptr, cur_end, "Connection", 10);
					if (val) {
						/* 3 possibilities :
						 * - we have already set Connection: close,
						 *   so we remove this line.
						 * - we have not yet set Connection: close,
						 *   but this line indicates close. We leave
						 *   it untouched and set the flag.
						 * - we have not yet set Connection: close,
						 *   and this line indicates non-close. We
						 *   replace it.
						 */
						if (t->flags & SN_CONN_CLOSED) {
							delta = buffer_replace2(req, cur_ptr, cur_next, NULL, 0);
							txn->req.eoh += delta;
							cur_next += delta;
							txn->hdr_idx.v[old_idx].next = cur_hdr->next;
							txn->hdr_idx.used--;
							cur_hdr->len = 0;
						} else {
							if (strncasecmp(cur_ptr + val, "close", 5) != 0) {
								delta = buffer_replace2(req, cur_ptr + val, cur_end,
											"close", 5);
								cur_next += delta;
								cur_hdr->len += delta;
								txn->req.eoh += delta;
							}
							t->flags |= SN_CONN_CLOSED;
						}
					}
					old_idx = cur_idx;
				}
			}
			/* add request headers from the rule sets in the same order */
			for (cur_idx = 0; cur_idx < rule_set->nb_reqadd; cur_idx++) {
				if (unlikely(http_header_add_tail(req,
								  &txn->req,
								  &txn->hdr_idx,
								  rule_set->req_add[cur_idx])) < 0)
					goto return_bad_req;
			}

			/* check if stats URI was requested, and if an auth is needed */
			if (rule_set->uri_auth != NULL &&
			    (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)) {
				/* we have to check the URI and auth for this request.
				 * FIXME!!! that one is rather dangerous, we want to
				 * make it follow standard rules (eg: clear req->analysers).
				 */
				if (stats_check_uri_auth(t, rule_set))
					return 1;
			}

			/* now check whether we have some switching rules for this request */
			if (!(t->flags & SN_BE_ASSIGNED)) {
				struct switching_rule *rule;

				list_for_each_entry(rule, &cur_proxy->switching_rules, list) {
					int ret;

					ret = acl_exec_cond(rule->cond, cur_proxy, t, txn, ACL_DIR_REQ);

					ret = acl_pass(ret);
					if (rule->cond->pol == ACL_COND_UNLESS)
						ret = !ret;

					if (ret) {
						t->be = rule->be.backend;
						t->be->beconn++;
						if (t->be->beconn > t->be->beconn_max)
							t->be->beconn_max = t->be->beconn;
						t->be->cum_beconn++;

						/* assign new parameters to the session from the new backend */
						t->rep->rto = t->req->wto = t->be->timeout.server;
						t->req->cto = t->be->timeout.connect;
						t->conn_retries = t->be->conn_retries;
						t->flags |= SN_BE_ASSIGNED;
						break;
					}
				}
			}

			if (!(t->flags & SN_BE_ASSIGNED) && cur_proxy->defbe.be) {
				/* No backend was set, but there was a default
				 * backend set in the frontend, so we use it and
				 * loop again.
				 */
				t->be = cur_proxy->defbe.be;
				t->be->beconn++;
				if (t->be->beconn > t->be->beconn_max)
					t->be->beconn_max = t->be->beconn;
				t->be->cum_beconn++;

				/* assign new parameters to the session from the new backend */
				t->rep->rto = t->req->wto = t->be->timeout.server;
				t->req->cto = t->be->timeout.connect;
				t->conn_retries = t->be->conn_retries;
				t->flags |= SN_BE_ASSIGNED;
			}
		} while (t->be != cur_proxy);  /* we loop only if t->be has changed */
		

		if (!(t->flags & SN_BE_ASSIGNED)) {
			/* To ensure correct connection accounting on
			 * the backend, we count the connection for the
			 * one managing the queue.
			 */
			t->be->beconn++;
			if (t->be->beconn > t->be->beconn_max)
				t->be->beconn_max = t->be->beconn;
			t->be->cum_beconn++;
			t->flags |= SN_BE_ASSIGNED;
		}

		/*
		 * Right now, we know that we have processed the entire headers
		 * and that unwanted requests have been filtered out. We can do
		 * whatever we want with the remaining request. Also, now we
		 * may have separate values for ->fe, ->be.
		 */

		/*
		 * If HTTP PROXY is set we simply get remote server address
		 * parsing incoming request.
		 */
		if ((t->be->options & PR_O_HTTP_PROXY) && !(t->flags & SN_ADDR_SET)) {
			url2sa(req->data + msg->sl.rq.u, msg->sl.rq.u_l, &t->srv_addr);
		}

		/*
		 * 7: the appsession cookie was looked up very early in 1.2,
		 * so let's do the same now.
		 */

		/* It needs to look into the URI */
		if (t->be->appsession_name) {
			get_srv_from_appsession(t, &req->data[msg->som], msg->sl.rq.l);
		}


		/*
		 * 8: Now we can work with the cookies.
		 * Note that doing so might move headers in the request, but
		 * the fields will stay coherent and the URI will not move.
		 * This should only be performed in the backend.
		 */
		if ((t->be->cookie_name || t->be->appsession_name || t->be->capture_name)
		    && !(txn->flags & (TX_CLDENY|TX_CLTARPIT)))
			manage_client_side_cookies(t, req);


		/*
		 * 9: add X-Forwarded-For if either the frontend or the backend
		 * asks for it.
		 */
		if ((t->fe->options | t->be->options) & PR_O_FWDFOR) {
			if (t->cli_addr.ss_family == AF_INET) {
				/* Add an X-Forwarded-For header unless the source IP is
				 * in the 'except' network range.
				 */
				if ((!t->fe->except_mask.s_addr ||
				     (((struct sockaddr_in *)&t->cli_addr)->sin_addr.s_addr & t->fe->except_mask.s_addr)
				     != t->fe->except_net.s_addr) &&
				    (!t->be->except_mask.s_addr ||
				     (((struct sockaddr_in *)&t->cli_addr)->sin_addr.s_addr & t->be->except_mask.s_addr)
				     != t->be->except_net.s_addr)) {
					int len;
					unsigned char *pn;
					pn = (unsigned char *)&((struct sockaddr_in *)&t->cli_addr)->sin_addr;

					/* Note: we rely on the backend to get the header name to be used for
					 * x-forwarded-for, because the header is really meant for the backends.
					 * However, if the backend did not specify any option, we have to rely
					 * on the frontend's header name.
					 */
					if (t->be->fwdfor_hdr_len) {
						len = t->be->fwdfor_hdr_len;
						memcpy(trash, t->be->fwdfor_hdr_name, len);
					} else {
						len = t->fe->fwdfor_hdr_len;
						memcpy(trash, t->fe->fwdfor_hdr_name, len);
					}
					len += sprintf(trash + len, ": %d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);

 					if (unlikely(http_header_add_tail2(req, &txn->req,
									   &txn->hdr_idx, trash, len)) < 0)
						goto return_bad_req;
				}
			}
			else if (t->cli_addr.ss_family == AF_INET6) {
				/* FIXME: for the sake of completeness, we should also support
				 * 'except' here, although it is mostly useless in this case.
				 */
				int len;
				char pn[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&t->cli_addr))->sin6_addr,
					  pn, sizeof(pn));

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (t->be->fwdfor_hdr_len) {
					len = t->be->fwdfor_hdr_len;
					memcpy(trash, t->be->fwdfor_hdr_name, len);
				} else {
					len = t->fe->fwdfor_hdr_len;
					memcpy(trash, t->fe->fwdfor_hdr_name, len);
				}
				len += sprintf(trash + len, ": %s", pn);
 
				if (unlikely(http_header_add_tail2(req, &txn->req,
								   &txn->hdr_idx, trash, len)) < 0)
					goto return_bad_req;
			}
		}

		/*
		 * 10: add "Connection: close" if needed and not yet set.
		 * Note that we do not need to add it in case of HTTP/1.0.
		 */
		if (!(t->flags & SN_CONN_CLOSED) &&
		    ((t->fe->options | t->be->options) & (PR_O_HTTP_CLOSE|PR_O_FORCE_CLO))) {
			if ((unlikely(msg->sl.rq.v_l != 8) ||
			     unlikely(req->data[msg->som + msg->sl.rq.v + 7] != '0')) &&
			    unlikely(http_header_add_tail2(req, &txn->req, &txn->hdr_idx,
							   "Connection: close", 17)) < 0)
				goto return_bad_req;
			t->flags |= SN_CONN_CLOSED;
		}
		/* Before we switch to data, was assignment set in manage_client_side_cookie?
		 * If not assigned, perhaps we are balancing on url_param, but this is a
		 * POST; and the parameters are in the body, maybe scan there to find our server.
		 * (unless headers overflowed the buffer?)
                 */
		if (!(t->flags & (SN_ASSIGNED|SN_DIRECT)) &&
		     t->txn.meth == HTTP_METH_POST && t->be->url_param_name != NULL &&
		     t->be->url_param_post_limit != 0 && !(req->flags & BF_FULL) &&
		     memchr(msg->sol + msg->sl.rq.u, '?', msg->sl.rq.u_l) == NULL) {
			/* are there enough bytes here? total == l || r || rlim ?
			 * len is unsigned, but eoh is int,
			 * how many bytes of body have we received?
			 * eoh is the first empty line of the header
			 */
                        /* already established CRLF or LF at eoh, move to start of message, find message length in buffer */
			unsigned long len = req->l - (msg->sol[msg->eoh] == '\r' ? msg->eoh + 2 : msg->eoh + 1);

			/* If we have HTTP/1.1 and Expect: 100-continue, then abort.
			 * We can't assume responsibility for the server's decision,
			 * on this URI and header set. See rfc2616: 14.20, 8.2.3,
			 * We also can't change our mind later, about which server to choose, so round robin.
			 */
			if ((likely(msg->sl.rq.v_l == 8) && req->data[msg->som + msg->sl.rq.v + 7] == '1')) {
				struct hdr_ctx ctx;
				ctx.idx = 0;
				/* Expect is allowed in 1.1, look for it */
				http_find_header2("Expect", 6, msg->sol, &txn->hdr_idx, &ctx);
				if (ctx.idx != 0  &&
                                    unlikely(ctx.vlen == 12 && strncasecmp(ctx.line+ctx.val, "100-continue", 12) == 0))
					/* We can't reliablly stall and wait for data, because of
					 * .NET clients that don't conform to rfc2616; so, no need for
					 * the next block to check length expectations.
                                         * We could send 100 status back to the client, but then we need to
                                         * re-write headers, and send the message. And this isn't the right
                                         * place for that action.
                                         * TODO: support Expect elsewhere and delete this block.
					 */
					goto end_check_maybe_wait_for_body;
			}

			if (likely(len > t->be->url_param_post_limit)) {
				/* nothing to do, we got enough */
			} else {
				/* limit implies we are supposed to need this many bytes
				 * to find the parameter. Let's see how many bytes we can wait for.
				 */
				long long hint = len;
				struct hdr_ctx ctx;
				ctx.idx = 0;
				http_find_header2("Transfer-Encoding", 17, msg->sol, &txn->hdr_idx, &ctx);
				if (ctx.idx && ctx.vlen >= 7 && strncasecmp(ctx.line+ctx.val, "chunked", 7) == 0) {
					req->flags &= ~BF_MAY_FORWARD;
					req->analysers |= AN_REQ_HTTP_BODY;
				}
				else {
					ctx.idx = 0;
					http_find_header2("Content-Length", 14, msg->sol, &txn->hdr_idx, &ctx);
					/* now if we have a length, we'll take the hint */
					if (ctx.idx) {
						/* We have Content-Length */
						if (strl2llrc(ctx.line+ctx.val,ctx.vlen, &hint))
							hint = 0;         /* parse failure, untrusted client */
						else {
							if (hint > 0)
								msg->hdr_content_len = hint;
							else
								hint = 0; /* bad client, sent negative length */
						}
					}
					/* but limited to what we care about, maybe we don't expect any entity data (hint == 0) */
					if (t->be->url_param_post_limit < hint)
						hint = t->be->url_param_post_limit;
					/* now do we really need to buffer more data? */
					if (len < hint) {
						req->flags &= ~BF_MAY_FORWARD;
						req->analysers |= AN_REQ_HTTP_BODY;
					}
					/* else... There are no body bytes to wait for */
				}
			}
		}
        end_check_maybe_wait_for_body:

		/*************************************************************
		 * OK, that's finished for the headers. We have done what we *
		 * could. Let's switch to the DATA state.                    *
		 ************************************************************/

		buffer_set_rlim(req, BUFSIZE); /* no more rewrite needed */
		t->logs.tv_request = now;

		/* When a connection is tarpitted, we use the tarpit timeout,
		 * which may be the same as the connect timeout if unspecified.
		 * If unset, then set it to zero because we really want it to
		 * eventually expire. We build the tarpit as an analyser.
		 */
		if (txn->flags & TX_CLTARPIT) {
			buffer_flush(t->req);
			/* flush the request so that we can drop the connection early
			 * if the client closes first.
			 */
			req->flags &= ~BF_MAY_FORWARD;
			req->analysers |= AN_REQ_HTTP_TARPIT;
			req->analyse_exp = tick_add_ifset(now_ms,  t->be->timeout.tarpit);
			if (!req->analyse_exp)
				req->analyse_exp = now_ms;
		}

		/* OK let's go on with the BODY now */
		goto end_of_headers;

	return_bad_req: /* let's centralize all bad requests */
		txn->req.msg_state = HTTP_MSG_ERROR;
		txn->status = 400;
		req->analysers = 0;
		client_retnclose(t, error_message(t, HTTP_ERR_400));
		t->fe->failed_req++;
	return_prx_cond:
		if (!(t->flags & SN_ERR_MASK))
			t->flags |= SN_ERR_PRXCOND;
		if (!(t->flags & SN_FINST_MASK))
			t->flags |= SN_FINST_R;
		return 0;
	end_of_headers:
		; // to keep gcc happy
	}

	if (req->analysers & AN_REQ_HTTP_TARPIT) {
		struct http_txn *txn = &t->txn;

		/* This connection is being tarpitted. The CLIENT side has
		 * already set the connect expiration date to the right
		 * timeout. We just have to check that the client is still
		 * there and that the timeout has not expired.
		 */
		if ((req->flags & (BF_READ_NULL|BF_READ_ERROR)) == 0 &&
		    !tick_is_expired(req->analyse_exp, now_ms))
			return 0;

		/* We will set the queue timer to the time spent, just for
		 * logging purposes. We fake a 500 server error, so that the
		 * attacker will not suspect his connection has been tarpitted.
		 * It will not cause trouble to the logs because we can exclude
		 * the tarpitted connections by filtering on the 'PT' status flags.
		 */
		trace_term(t, TT_HTTP_SRV_2);
		t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);

		txn->status = 500;
		if (req->flags != BF_READ_ERROR)
			client_retnclose(t, error_message(t, HTTP_ERR_500));

		req->analysers = 0;
		req->analyse_exp = TICK_ETERNITY;

		t->fe->failed_req++;
		if (!(t->flags & SN_ERR_MASK))
			t->flags |= SN_ERR_PRXCOND;
		if (!(t->flags & SN_FINST_MASK))
			t->flags |= SN_FINST_T;
		return 0;
	}

	if (req->analysers & AN_REQ_HTTP_BODY) {
		/* We have to parse the HTTP request body to find any required data.
		 * "balance url_param check_post" should have been the only way to get
		 * into this. We were brought here after HTTP header analysis, so all
		 * related structures are ready.
		 */
		struct http_msg *msg = &t->txn.req;
		unsigned long body = msg->sol[msg->eoh] == '\r' ? msg->eoh + 2 : msg->eoh + 1;
		long long limit = t->be->url_param_post_limit;
		struct hdr_ctx ctx;

		ctx.idx = 0;

		/* now if we have a length, we'll take the hint */
		http_find_header2("Transfer-Encoding", 17, msg->sol, &t->txn.hdr_idx, &ctx);
		if (ctx.idx && ctx.vlen >= 7 && strncasecmp(ctx.line+ctx.val, "chunked", 7) == 0) {
			unsigned int chunk = 0;
			while (body < req->l && !HTTP_IS_CRLF(msg->sol[body])) {
				char c = msg->sol[body];
				if (ishex(c)) {
					unsigned int hex = toupper(c) - '0';
					if (hex > 9)
						hex -= 'A' - '9' - 1;
					chunk = (chunk << 4) | hex;
				} else
					break;
				body++;
			}
			if (body + 2 >= req->l) /* we want CRLF too */
				goto http_body_end; /* end of buffer? data missing! */

			if (memcmp(msg->sol+body, "\r\n", 2) != 0)
				goto http_body_end; /* chunked encoding len ends with CRLF, and we don't have it yet */

			body += 2; // skip CRLF

			/* if we support more then one chunk here, we have to do it again when assigning server
			 * 1. how much entity data do we have? new var
			 * 2. should save entity_start, entity_cursor, elen & rlen in req; so we don't repeat scanning here
			 * 3. test if elen > limit, or set new limit to elen if 0 (end of entity found)
			 */

			if (chunk < limit)
				limit = chunk;                  /* only reading one chunk */
		} else {
			if (msg->hdr_content_len < limit)
				limit = msg->hdr_content_len;
		}

	http_body_end:
		/* we leave once we know we have nothing left to do. This means that we have
		 * enough bytes, or that we know we'll not get any more (buffer full, read
		 * buffer closed).
		 */
		if (req->l - body >= limit ||             /* enough bytes! */
		    req->flags & (BF_FULL | BF_READ_ERROR | BF_SHUTR | BF_READ_NULL | BF_READ_TIMEOUT) ||
		    tick_is_expired(req->analyse_exp, now_ms)) {
			/* The situation will not evolve, so let's give up on the analysis. */
			t->logs.tv_request = now;  /* update the request timer to reflect full request */
			req->analysers &= ~AN_REQ_HTTP_BODY;
			req->analyse_exp = TICK_ETERNITY;
		}
		else {
			/* Not enough data. We'll re-use the http-request
			 * timeout here. Ideally, we should set the timeout
			 * relative to the accept() date. We just set the
			 * request timeout once at the beginning of the
			 * request.
			 */
			req->flags &= ~BF_MAY_FORWARD;
			if (!tick_isset(req->analyse_exp))
				req->analyse_exp = tick_add_ifset(now_ms, t->fe->timeout.httpreq);
			return 0;
		}
	}

	/* Note: eventhough nobody should set an unknown flag, clearing them right now will
	 * probably reduce one day's debugging session.
	 */
#ifdef DEBUG_DEV
	if (req->analysers & ~(AN_REQ_INSPECT | AN_REQ_HTTP_HDR | AN_REQ_HTTP_TARPIT | AN_REQ_HTTP_BODY)) {
		fprintf(stderr, "FIXME !!!! unknown analysers flags %s:%d = 0x%08X\n",
			__FILE__, __LINE__, req->analysers);
		ABORT_NOW();
	}
#endif
	req->analysers &= AN_REQ_INSPECT | AN_REQ_HTTP_HDR | AN_REQ_HTTP_TARPIT | AN_REQ_HTTP_BODY;
	return 0;
}

/* This function performs all the processing enabled for the current response.
 * It normally returns zero, but may return 1 if it absolutely needs to be
 * called again after other functions. It relies on buffers flags, and updates
 * t->rep->analysers. It might make sense to explode it into several other
 * functions. It works like process_request (see indications above).
 */
int process_response(struct session *t)
{
	struct http_txn *txn = &t->txn;
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;

	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x analysers=%02x\n",
		now_ms, __FUNCTION__,
		cli_stnames[t->cli_state],
		req->rex, rep->wex, req->flags, rep->flags, rep->analysers);

	if (rep->analysers & AN_RTR_HTTP_HDR) { /* receiving server headers */
		/*
		 * Now parse the partial (or complete) lines.
		 * We will check the response syntax, and also join multi-line
		 * headers. An index of all the lines will be elaborated while
		 * parsing.
		 *
		 * For the parsing, we use a 28 states FSM.
		 *
		 * Here is the information we currently have :
		 *   rep->data + rep->som  = beginning of response
		 *   rep->data + rep->eoh  = end of processed headers / start of current one
		 *   rep->data + rep->eol  = end of current header or line (LF or CRLF)
		 *   rep->lr = first non-visited byte
		 *   rep->r  = end of data
		 */

		int cur_idx;
		struct http_msg *msg = &txn->rsp;
		struct proxy *cur_proxy;

		if (likely(rep->lr < rep->r))
			http_msg_analyzer(rep, msg, &txn->hdr_idx);

		/* 1: we might have to print this header in debug mode */
		if (unlikely((global.mode & MODE_DEBUG) &&
			     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
			     (msg->msg_state == HTTP_MSG_BODY || msg->msg_state == HTTP_MSG_ERROR))) {
			char *eol, *sol;

			sol = rep->data + msg->som;
			eol = sol + msg->sl.rq.l;
			debug_hdr("srvrep", t, sol, eol);

			sol += hdr_idx_first_pos(&txn->hdr_idx);
			cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

			while (cur_idx) {
				eol = sol + txn->hdr_idx.v[cur_idx].len;
				debug_hdr("srvhdr", t, sol, eol);
				sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
				cur_idx = txn->hdr_idx.v[cur_idx].next;
			}
		}

		/*
		 * Now we quickly check if we have found a full valid response.
		 * If not so, we check the FD and buffer states before leaving.
		 * A full response is indicated by the fact that we have seen
		 * the double LF/CRLF, so the state is HTTP_MSG_BODY. Invalid
		 * responses are checked first.
		 *
		 * Depending on whether the client is still there or not, we
		 * may send an error response back or not. Note that normally
		 * we should only check for HTTP status there, and check I/O
		 * errors somewhere else.
		 */

		if (unlikely(msg->msg_state != HTTP_MSG_BODY)) {
			/* Invalid response */
			if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			hdr_response_bad:
				//buffer_shutr(rep);
				//buffer_shutw(req);
				//fd_delete(req->cons->fd);
				//req->cons->state = SI_ST_CLO;
				buffer_shutr_now(rep);
				buffer_shutw_now(req);
				if (t->srv) {
					//t->srv->cur_sess--;
					t->srv->failed_resp++;
					//sess_change_server(t, NULL);
				}
				t->be->failed_resp++;
				rep->analysers = 0;
				txn->status = 502;
				client_return(t, error_message(t, HTTP_ERR_502));
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_PRXCOND;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_H;

				//if (t->srv && may_dequeue_tasks(t->srv, t->be))
				//	process_srv_queue(t->srv);

				return 0;
			}
			/* write error to client, read error or close from server */
			if (rep->flags & (BF_WRITE_ERROR|BF_SHUTW|BF_READ_ERROR|BF_SHUTR|BF_READ_NULL)) {
				buffer_shutr_now(rep);
				buffer_shutw_now(req);
				//fd_delete(req->cons->fd);
				//req->cons->state = SI_ST_CLO;
				if (t->srv) {
					//t->srv->cur_sess--;
					t->srv->failed_resp++;
					//sess_change_server(t, NULL);
				}
				t->be->failed_resp++;
				rep->analysers = 0;
				txn->status = 502;
				client_return(t, error_message(t, HTTP_ERR_502));
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_SRVCL;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_H;

				//if (t->srv && may_dequeue_tasks(t->srv, t->be))
				//	process_srv_queue(t->srv);

				return 0;
			}
			/* too large response does not fit in buffer. */
			else if (rep->flags & BF_FULL) {
				goto hdr_response_bad;
			}
			/* read timeout : return a 504 to the client. */
			else if (rep->flags & BF_READ_TIMEOUT) {
				buffer_shutr_now(rep);
				buffer_shutw_now(req);
				//fd_delete(req->cons->fd);
				//req->cons->state = SI_ST_CLO;
				if (t->srv) {
					//t->srv->cur_sess--;
					t->srv->failed_resp++;
					//sess_change_server(t, NULL);
				}
				t->be->failed_resp++;
				rep->analysers = 0;
				txn->status = 504;
				client_return(t, error_message(t, HTTP_ERR_504));
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_SRVTO;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_H;

				//if (t->srv && may_dequeue_tasks(t->srv, t->be))
				//	process_srv_queue(t->srv);
				return 0;
			}

			rep->flags &= ~BF_MAY_FORWARD;
			return 0;
		}


		/*****************************************************************
		 * More interesting part now : we know that we have a complete   *
		 * response which at least looks like HTTP. We have an indicator *
		 * of each header's length, so we can parse them quickly.        *
		 ****************************************************************/

		rep->analysers &= ~AN_RTR_HTTP_HDR;

		/* ensure we keep this pointer to the beginning of the message */
		msg->sol = rep->data + msg->som;

		/*
		 * 1: get the status code and check for cacheability.
		 */

		t->logs.logwait &= ~LW_RESP;
		txn->status = strl2ui(rep->data + msg->sl.st.c, msg->sl.st.c_l);

		switch (txn->status) {
		case 200:
		case 203:
		case 206:
		case 300:
		case 301:
		case 410:
			/* RFC2616 @13.4:
			 *   "A response received with a status code of
			 *    200, 203, 206, 300, 301 or 410 MAY be stored
			 *    by a cache (...) unless a cache-control
			 *    directive prohibits caching."
			 *   
			 * RFC2616 @9.5: POST method :
			 *   "Responses to this method are not cacheable,
			 *    unless the response includes appropriate
			 *    Cache-Control or Expires header fields."
			 */
			if (likely(txn->meth != HTTP_METH_POST) &&
			    (t->be->options & (PR_O_CHK_CACHE|PR_O_COOK_NOC)))
				txn->flags |= TX_CACHEABLE | TX_CACHE_COOK;
			break;
		default:
			break;
		}

		/*
		 * 2: we may need to capture headers
		 */
		if (unlikely((t->logs.logwait & LW_RSPHDR) && t->fe->rsp_cap))
			capture_headers(rep->data + msg->som, &txn->hdr_idx,
					txn->rsp.cap, t->fe->rsp_cap);

		/*
		 * 3: we will have to evaluate the filters.
		 * As opposed to version 1.2, now they will be evaluated in the
		 * filters order and not in the header order. This means that
		 * each filter has to be validated among all headers.
		 *
		 * Filters are tried with ->be first, then with ->fe if it is
		 * different from ->be.
		 */

		t->flags &= ~SN_CONN_CLOSED; /* prepare for inspection */

		cur_proxy = t->be;
		while (1) {
			struct proxy *rule_set = cur_proxy;

			/* try headers filters */
			if (rule_set->rsp_exp != NULL) {
				if (apply_filters_to_response(t, rep, rule_set->rsp_exp) < 0) {
				return_bad_resp:
					if (t->srv) {
						//t->srv->cur_sess--;
						t->srv->failed_resp++;
						//sess_change_server(t, NULL);
					}
					cur_proxy->failed_resp++;
				return_srv_prx_502:
					buffer_shutr_now(rep);
					buffer_shutw_now(req);
					//fd_delete(req->cons->fd);
					//req->cons->state = SI_ST_CLO;
					rep->analysers = 0;
					txn->status = 502;
					client_return(t, error_message(t, HTTP_ERR_502));
					if (!(t->flags & SN_ERR_MASK))
						t->flags |= SN_ERR_PRXCOND;
					if (!(t->flags & SN_FINST_MASK))
						t->flags |= SN_FINST_H;
					/* We used to have a free connection slot. Since we'll never use it,
					 * we have to inform the server that it may be used by another session.
					 */
					//if (t->srv && may_dequeue_tasks(t->srv, cur_proxy))
					//	process_srv_queue(t->srv);
					return 0;
				}
			}

			/* has the response been denied ? */
			if (txn->flags & TX_SVDENY) {
				if (t->srv) {
					//t->srv->cur_sess--;
					t->srv->failed_secu++;
					//sess_change_server(t, NULL);
				}
				cur_proxy->denied_resp++;
				goto return_srv_prx_502;
			}

			/* We might have to check for "Connection:" */
			if (((t->fe->options | t->be->options) & (PR_O_HTTP_CLOSE|PR_O_FORCE_CLO)) &&
			    !(t->flags & SN_CONN_CLOSED)) {
				char *cur_ptr, *cur_end, *cur_next;
				int cur_idx, old_idx, delta, val;
				struct hdr_idx_elem *cur_hdr;

				cur_next = rep->data + txn->rsp.som + hdr_idx_first_pos(&txn->hdr_idx);
				old_idx = 0;

				while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
					cur_hdr  = &txn->hdr_idx.v[cur_idx];
					cur_ptr  = cur_next;
					cur_end  = cur_ptr + cur_hdr->len;
					cur_next = cur_end + cur_hdr->cr + 1;

					val = http_header_match2(cur_ptr, cur_end, "Connection", 10);
					if (val) {
						/* 3 possibilities :
						 * - we have already set Connection: close,
						 *   so we remove this line.
						 * - we have not yet set Connection: close,
						 *   but this line indicates close. We leave
						 *   it untouched and set the flag.
						 * - we have not yet set Connection: close,
						 *   and this line indicates non-close. We
						 *   replace it.
						 */
						if (t->flags & SN_CONN_CLOSED) {
							delta = buffer_replace2(rep, cur_ptr, cur_next, NULL, 0);
							txn->rsp.eoh += delta;
							cur_next += delta;
							txn->hdr_idx.v[old_idx].next = cur_hdr->next;
							txn->hdr_idx.used--;
							cur_hdr->len = 0;
						} else {
							if (strncasecmp(cur_ptr + val, "close", 5) != 0) {
								delta = buffer_replace2(rep, cur_ptr + val, cur_end,
											"close", 5);
								cur_next += delta;
								cur_hdr->len += delta;
								txn->rsp.eoh += delta;
							}
							t->flags |= SN_CONN_CLOSED;
						}
					}
					old_idx = cur_idx;
				}
			}

			/* add response headers from the rule sets in the same order */
			for (cur_idx = 0; cur_idx < rule_set->nb_rspadd; cur_idx++) {
				if (unlikely(http_header_add_tail(rep, &txn->rsp, &txn->hdr_idx,
								  rule_set->rsp_add[cur_idx])) < 0)
					goto return_bad_resp;
			}

			/* check whether we're already working on the frontend */
			if (cur_proxy == t->fe)
				break;
			cur_proxy = t->fe;
		}

		/*
		 * 4: check for server cookie.
		 */
		if (t->be->cookie_name || t->be->appsession_name || t->be->capture_name
		    || (t->be->options & PR_O_CHK_CACHE))
			manage_server_side_cookies(t, rep);


		/*
		 * 5: check for cache-control or pragma headers if required.
		 */
		if ((t->be->options & (PR_O_COOK_NOC | PR_O_CHK_CACHE)) != 0)
			check_response_for_cacheability(t, rep);

		/*
		 * 6: add server cookie in the response if needed
		 */
		if ((t->srv) && !(t->flags & SN_DIRECT) && (t->be->options & PR_O_COOK_INS) &&
		    (!(t->be->options & PR_O_COOK_POST) || (txn->meth == HTTP_METH_POST))) {
			int len;

			/* the server is known, it's not the one the client requested, we have to
			 * insert a set-cookie here, except if we want to insert only on POST
			 * requests and this one isn't. Note that servers which don't have cookies
			 * (eg: some backup servers) will return a full cookie removal request.
			 */
			len = sprintf(trash, "Set-Cookie: %s=%s; path=/",
				      t->be->cookie_name,
				      t->srv->cookie ? t->srv->cookie : "; Expires=Thu, 01-Jan-1970 00:00:01 GMT");

			if (t->be->cookie_domain)
				len += sprintf(trash+len, "; domain=%s", t->be->cookie_domain);

			if (unlikely(http_header_add_tail2(rep, &txn->rsp, &txn->hdr_idx,
							   trash, len)) < 0)
				goto return_bad_resp;
			txn->flags |= TX_SCK_INSERTED;

			/* Here, we will tell an eventual cache on the client side that we don't
			 * want it to cache this reply because HTTP/1.0 caches also cache cookies !
			 * Some caches understand the correct form: 'no-cache="set-cookie"', but
			 * others don't (eg: apache <= 1.3.26). So we use 'private' instead.
			 */
			if ((t->be->options & PR_O_COOK_NOC) && (txn->flags & TX_CACHEABLE)) {

				txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;

				if (unlikely(http_header_add_tail2(rep, &txn->rsp, &txn->hdr_idx,
								   "Cache-control: private", 22)) < 0)
					goto return_bad_resp;
			}
		}


		/*
		 * 7: check if result will be cacheable with a cookie.
		 * We'll block the response if security checks have caught
		 * nasty things such as a cacheable cookie.
		 */
		if (((txn->flags & (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_ANY)) ==
		     (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_ANY)) &&
		    (t->be->options & PR_O_CHK_CACHE)) {

			/* we're in presence of a cacheable response containing
			 * a set-cookie header. We'll block it as requested by
			 * the 'checkcache' option, and send an alert.
			 */
			if (t->srv) {
				//t->srv->cur_sess--;
				t->srv->failed_secu++;
				//sess_change_server(t, NULL);
			}
			t->be->denied_resp++;

			Alert("Blocking cacheable cookie in response from instance %s, server %s.\n",
			      t->be->id, t->srv?t->srv->id:"<dispatch>");
			send_log(t->be, LOG_ALERT,
				 "Blocking cacheable cookie in response from instance %s, server %s.\n",
				 t->be->id, t->srv?t->srv->id:"<dispatch>");
			goto return_srv_prx_502;
		}

		/*
		 * 8: add "Connection: close" if needed and not yet set.
		 * Note that we do not need to add it in case of HTTP/1.0.
		 */
		if (!(t->flags & SN_CONN_CLOSED) &&
		    ((t->fe->options | t->be->options) & (PR_O_HTTP_CLOSE|PR_O_FORCE_CLO))) {
			if ((unlikely(msg->sl.st.v_l != 8) ||
			     unlikely(req->data[msg->som + 7] != '0')) &&
			    unlikely(http_header_add_tail2(rep, &txn->rsp, &txn->hdr_idx,
							   "Connection: close", 17)) < 0)
				goto return_bad_resp;
			t->flags |= SN_CONN_CLOSED;
		}

		/*************************************************************
		 * OK, that's finished for the headers. We have done what we *
		 * could. Let's switch to the DATA state.                    *
		 ************************************************************/

		buffer_set_rlim(rep, BUFSIZE); /* no more rewrite needed */
		t->logs.t_data = tv_ms_elapsed(&t->logs.tv_accept, &now);

#ifdef CONFIG_HAP_TCPSPLICE
		if ((t->fe->options & t->be->options) & PR_O_TCPSPLICE) {
			/* TCP splicing supported by both FE and BE */
			tcp_splice_splicefd(t->cli_fd, req->cons->fd, 0);
		}
#endif
		/* if the user wants to log as soon as possible, without counting
		 * bytes from the server, then this is the right moment. We have
		 * to temporarily assign bytes_out to log what we currently have.
		 */
		if (t->fe->to_log && !(t->logs.logwait & LW_BYTES)) {
			t->logs.t_close = t->logs.t_data; /* to get a valid end date */
			t->logs.bytes_out = txn->rsp.eoh;
			if (t->fe->to_log & LW_REQ)
				http_sess_log(t);
			else
				tcp_sess_log(t);
			t->logs.bytes_out = 0;
		}

		/* Note: we must not try to cheat by jumping directly to DATA,
		 * otherwise we would not let the client side wake up.
		 */

		return 0;
	}

	/* Note: eventhough nobody should set an unknown flag, clearing them right now will
	 * probably reduce one day's debugging session.
	 */
#ifdef DEBUG_DEV
	if (rep->analysers & ~(AN_RTR_HTTP_HDR)) {
		fprintf(stderr, "FIXME !!!! unknown analysers flags %s:%d = 0x%08X\n",
			__FILE__, __LINE__, rep->analysers);
		ABORT_NOW();
	}
#endif
	rep->analysers &= AN_RTR_HTTP_HDR;
	return 0;
}

/*
 * Manages the client FSM and its socket. It normally returns zero, but may
 * return 1 if it absolutely wants to be called again.
 *
 * Note: process_cli is the ONLY function allowed to set cli_state to anything
 *       but CL_STCLOSE.
 */
int process_cli(struct session *t)
{
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;

	DPRINTF(stderr,"[%u] %s: fd=%d[%d] c=%s set(r,w)=%d,%d exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
		now_ms, __FUNCTION__,
		t->cli_fd, t->cli_fd >= 0 ? fdtab[t->cli_fd].state : 0, /* fd,state*/
		cli_stnames[t->cli_state],
		t->cli_fd >= 0 && fdtab[t->cli_fd].state != FD_STCLOSE ? EV_FD_ISSET(t->cli_fd, DIR_RD) : 0,
		t->cli_fd >= 0 && fdtab[t->cli_fd].state != FD_STCLOSE ? EV_FD_ISSET(t->cli_fd, DIR_WR) : 0,
		req->rex, rep->wex,
		req->flags, rep->flags,
		req->l, rep->l);

 update_state:
	/* FIXME: we still have to check for CL_STSHUTR because client_retnclose
	 * still set this state (and will do until unix sockets are converted).
	 */
	if (t->cli_state == CL_STDATA || t->cli_state == CL_STSHUTR) {
		/* we can skip most of the tests at once if some conditions are not met */
		if (!((fdtab[t->cli_fd].state == FD_STERROR)   ||
		      (req->flags & (BF_READ_TIMEOUT|BF_READ_ERROR|BF_SHUTR_NOW))   ||
		      (rep->flags & (BF_WRITE_TIMEOUT|BF_WRITE_ERROR|BF_SHUTW_NOW)) ||
		      (!(req->flags & BF_SHUTR) && req->flags & (BF_READ_NULL|BF_SHUTW)) ||
		      (!(rep->flags & BF_SHUTW) &&
		       (rep->flags & (BF_EMPTY|BF_MAY_FORWARD|BF_SHUTR)) == (BF_EMPTY|BF_MAY_FORWARD|BF_SHUTR))))
			goto update_timeouts;

		/* read or write error */
		if (fdtab[t->cli_fd].state == FD_STERROR) {
			buffer_shutr(req);
			req->flags |= BF_READ_ERROR;
			buffer_shutw(rep);
			rep->flags |= BF_WRITE_ERROR;
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			trace_term(t, TT_HTTP_CLI_1);
			if (!req->analysers) {
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLICL;
				if (!(t->flags & SN_FINST_MASK)) {
					if (req->cons->err_type <= SI_ET_QUEUE_ABRT)
						t->flags |= SN_FINST_Q;
					else if (req->cons->err_type <= SI_ET_CONN_OTHER)
						t->flags |= SN_FINST_C;
					else
						t->flags |= SN_FINST_D;
				}
			}
			goto update_state;
		}
		/* last read, or end of server write */
		else if (!(req->flags & BF_SHUTR) &&   /* not already done */
			 req->flags & (BF_READ_NULL|BF_SHUTR_NOW|BF_SHUTW)) {
			buffer_shutr(req);
			if (!(rep->flags & BF_SHUTW)) {
				EV_FD_CLR(t->cli_fd, DIR_RD);
				trace_term(t, TT_HTTP_CLI_2);
			} else {
				/* output was already closed */
				fd_delete(t->cli_fd);
				t->cli_state = CL_STCLOSE;
				trace_term(t, TT_HTTP_CLI_3);
			}
			goto update_state;
		}	
		/* last server read and buffer empty : we only check them when we're
		 * allowed to forward the data.
		 */
		else if (!(rep->flags & BF_SHUTW) &&   /* not already done */
			 ((rep->flags & BF_SHUTW_NOW) ||
			  (rep->flags & BF_EMPTY && rep->flags & BF_MAY_FORWARD &&
			   rep->flags & BF_SHUTR && !(t->flags & SN_SELF_GEN)))) {
			buffer_shutw(rep);
			if (!(req->flags & BF_SHUTR)) {
				EV_FD_CLR(t->cli_fd, DIR_WR);
				shutdown(t->cli_fd, SHUT_WR);
				trace_term(t, TT_HTTP_CLI_4);
			} else {
				fd_delete(t->cli_fd);
				t->cli_state = CL_STCLOSE;
				trace_term(t, TT_HTTP_CLI_5);
			}
			goto update_state;
		}
		/* read timeout */
		else if ((req->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == BF_READ_TIMEOUT) {
			buffer_shutr(req);
			if (!(rep->flags & BF_SHUTW)) {
				EV_FD_CLR(t->cli_fd, DIR_RD);
				trace_term(t, TT_HTTP_CLI_6);
			} else {
				/* output was already closed */
				fd_delete(t->cli_fd);
				t->cli_state = CL_STCLOSE;
				trace_term(t, TT_HTTP_CLI_7);
			}
			if (!req->analysers) {
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLITO;
				if (!(t->flags & SN_FINST_MASK)) {
					if (req->cons->err_type <= SI_ET_QUEUE_ABRT)
						t->flags |= SN_FINST_Q;
					else if (req->cons->err_type <= SI_ET_CONN_OTHER)
						t->flags |= SN_FINST_C;
					else
						t->flags |= SN_FINST_D;
				}
			}
			goto update_state;
		}	
		/* write timeout */
		else if ((rep->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == BF_WRITE_TIMEOUT) {
			buffer_shutw(rep);
			if (!(req->flags & BF_SHUTR)) {
				EV_FD_CLR(t->cli_fd, DIR_WR);
				shutdown(t->cli_fd, SHUT_WR);
				trace_term(t, TT_HTTP_CLI_8);
			} else {
				fd_delete(t->cli_fd);
				t->cli_state = CL_STCLOSE;
				trace_term(t, TT_HTTP_CLI_9);
			}
			if (!req->analysers) {
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLITO;
				if (!(t->flags & SN_FINST_MASK)) {
					if (req->cons->err_type <= SI_ET_QUEUE_ABRT)
						t->flags |= SN_FINST_Q;
					else if (req->cons->err_type <= SI_ET_CONN_OTHER)
						t->flags |= SN_FINST_C;
					else
						t->flags |= SN_FINST_D;
				}
			}
			goto update_state;
		}

	update_timeouts:
		/* manage read timeout */
		if (!(req->flags & BF_SHUTR)) {
			if (req->flags & BF_FULL) {
				/* no room to read more data */
				if (EV_FD_COND_C(t->cli_fd, DIR_RD)) {
					/* stop reading until we get some space */
					req->rex = TICK_ETERNITY;
				}
			} else {
				EV_FD_COND_S(t->cli_fd, DIR_RD);
				req->rex = tick_add_ifset(now_ms, t->fe->timeout.client);
			}
		}

		/* manage write timeout */
		if (!(rep->flags & BF_SHUTW)) {
			/* first, we may have to produce data (eg: stats).
			 * right now, this is limited to the SHUTR state.
			 */
			if (req->flags & BF_SHUTR && t->flags & SN_SELF_GEN) {
				produce_content(t);
				if (rep->flags & BF_EMPTY) {
					buffer_shutw(rep);
					fd_delete(t->cli_fd);
					t->cli_state = CL_STCLOSE;
					trace_term(t, TT_HTTP_CLI_10);
					goto update_state;
				}
			}

			/* we don't enable client write if the buffer is empty, nor if the server has to analyze it */
			if ((rep->flags & (BF_EMPTY|BF_MAY_FORWARD)) != BF_MAY_FORWARD) {
				if (EV_FD_COND_C(t->cli_fd, DIR_WR)) {
					/* stop writing */
					rep->wex = TICK_ETERNITY;
				}
			} else {
				/* buffer not empty */
				EV_FD_COND_S(t->cli_fd, DIR_WR);
				if (!tick_isset(rep->wex)) {
					/* restart writing */
					rep->wex = tick_add_ifset(now_ms, t->fe->timeout.client);
					if (!(req->flags & BF_SHUTR) && tick_isset(rep->wex) && tick_isset(req->rex)) {
						/* FIXME: to prevent the client from expiring read timeouts during writes,
						 * we refresh it, except if it was already infinite. */
						req->rex = rep->wex;
					}
				}
			}
		}
		return 0; /* other cases change nothing */
	}
	else if (t->cli_state == CL_STCLOSE) { /* CL_STCLOSE: nothing to do */
		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			int len;
			len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n", t->uniq_id, t->be->id, (unsigned short)t->cli_fd, (unsigned short)req->cons->fd);
			write(1, trash, len);
		}
		return 0;
	}
#ifdef DEBUG_DEV
	fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, t->cli_state);
	ABORT_NOW();
#endif
	return 0;
}


/* Return 1 if the pending connection has failed and should be retried,
 * otherwise zero. We may only come here in SI_ST_CON state, which means that
 * the socket's file descriptor is known.
 */
int tcp_connection_status(struct session *t)
{
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;
	int conn_err = 0;

	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
		now_ms, __FUNCTION__,
		cli_stnames[t->cli_state],
		rep->rex, req->wex,
		req->flags, rep->flags,
		req->l, rep->l);

	if ((req->flags & BF_SHUTW_NOW) ||
	    (rep->flags & BF_SHUTW) ||
	    ((req->flags & BF_SHUTR) && /* FIXME: this should not prevent a connection from establishing */
	     ((req->flags & BF_EMPTY && !(req->flags & BF_WRITE_STATUS)) ||
	      t->be->options & PR_O_ABRT_CLOSE))) { /* give up */

		trace_term(t, TT_HTTP_SRV_5);
		req->wex = TICK_ETERNITY;
		fd_delete(req->cons->fd);
		if (t->srv) {
			t->srv->cur_sess--;
			sess_change_server(t, NULL);
		}
		/* note that this must not return any error because it would be able to
		 * overwrite the client_retnclose() output.
		 */
		//srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_C, 0, NULL);

		// FIXME: should we set rep->MAY_FORWARD ?
		buffer_shutw(req);
		buffer_shutr(rep);
		req->cons->state = SI_ST_CLO;
		if (!req->cons->err_type)
			req->cons->err_type = SI_ET_CONN_ABRT;
		req->cons->err_loc  = t->srv;
		return 0;
	}

	/* check for timeouts and asynchronous connect errors */
	if (fdtab[req->cons->fd].state == FD_STERROR) {
		conn_err = SI_ET_CONN_ERR;
		if (!req->cons->err_type)
			req->cons->err_type = SI_ET_CONN_ERR;
	}
	else if (!(req->flags & BF_WRITE_STATUS)) {
		/* nothing happened, maybe we timed out */
		if (tick_is_expired(req->wex, now_ms)) {
			conn_err = SI_ET_CONN_TO;
			if (!req->cons->err_type)
				req->cons->err_type = SI_ET_CONN_TO;
		}
		else
			return 0; /* let's wait a bit more */
	}

	if (conn_err) {
		fd_delete(req->cons->fd);
		req->cons->state = SI_ST_CLO;

		if (t->srv) {
			t->srv->cur_sess--;
			sess_change_server(t, NULL);
			req->cons->err_loc  = t->srv;
		}

		/* ensure that we have enough retries left */
		if (srv_count_retry_down(t, conn_err))
			return 0;

		if (conn_err == SI_ET_CONN_ERR) {
			/* we encountered an immediate connection error, and we
			 * will have to retry connecting to the same server, most
			 * likely leading to the same result. To avoid this, we
			 * fake a connection timeout to retry after a turn-around
			 * time of 1 second. We will wait in the previous if block.
			 */
			req->cons->state = SI_ST_TAR;
			req->wex = tick_add(now_ms, MS_TO_TICKS(1000));
			return 0;
		}

		if (t->srv && t->conn_retries == 0 && t->be->options & PR_O_REDISP) {
			/* We're on our last chance, and the REDISP option was specified.
			 * We will ignore cookie and force to balance or use the dispatcher.
			 */
			/* let's try to offer this slot to anybody */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			/* it's left to the dispatcher to choose a server */
			t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
			t->prev_srv = t->srv;
		} else {
			/* we just want to retry */
			if (t->srv)
				t->srv->retries++;
			t->be->retries++;

			/* Now we will try to either reconnect to the same server or
			 * connect to another server. If the connection gets queued
			 * because all servers are saturated, then we will go back to
			 * the idle state where the buffer's consumer is marked as
			 * unknown.
			 */
			if (srv_retryable_connect(t)) {
				/* success or unrecoverable error */
				t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
				return 0;
			}
		}

		/* We'll rely on the caller to try to get a connection again */
		return 1;
	}
	else {
		/* no error and write OK : connection succeeded */
		t->logs.t_connect = tv_ms_elapsed(&t->logs.tv_accept, &now);
		req->cons->state    = SI_ST_EST;
		req->cons->err_type = SI_ET_NONE;
		req->cons->err_loc  = NULL;

		if (req->flags & BF_EMPTY) {
			EV_FD_CLR(req->cons->fd, DIR_WR);
			req->wex = TICK_ETERNITY;
		} else {
			EV_FD_SET(req->cons->fd, DIR_WR);
			req->wex = tick_add_ifset(now_ms, t->be->timeout.server);
			if (tick_isset(req->wex)) {
				/* FIXME: to prevent the server from expiring read timeouts during writes,
				 * we refresh it. */
				rep->rex = req->wex;
			}
		}

		if (t->be->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
			if (!(rep->flags & BF_HIJACK)) {
				EV_FD_SET(req->cons->fd, DIR_RD);
				rep->rex = tick_add_ifset(now_ms, t->be->timeout.server);
			}
			buffer_set_rlim(rep, BUFSIZE); /* no rewrite needed */

			/* if the user wants to log as soon as possible, without counting
			   bytes from the server, then this is the right moment. */
			if (t->fe->to_log && !(t->logs.logwait & LW_BYTES)) {
				t->logs.t_close = t->logs.t_connect; /* to get a valid end date */
				tcp_sess_log(t);
			}
#ifdef CONFIG_HAP_TCPSPLICE
			if ((t->fe->options & t->be->options) & PR_O_TCPSPLICE) {
				/* TCP splicing supported by both FE and BE */
				tcp_splice_splicefd(t->cli_fd, req->cons->fd, 0);
			}
#endif
		}
		else {
			rep->analysers |= AN_RTR_HTTP_HDR;
			buffer_set_rlim(rep, BUFSIZE - MAXREWRITE); /* rewrite needed */
			t->txn.rsp.msg_state = HTTP_MSG_RPBEFORE;
			/* reset hdr_idx which was already initialized by the request.
			 * right now, the http parser does it.
			 * hdr_idx_init(&t->txn.hdr_idx);
			 */
		}

		if (!rep->analysers)
			t->rep->flags |= BF_MAY_FORWARD;
		req->wex = TICK_ETERNITY;
		return 0;
	}
}


/*
 * This function tries to assign a server to a stream_sock interface.
 * It may be called only for t->req->cons->state = one of { SI_ST_INI,
 * SI_ST_TAR, SI_ST_QUE }. It returns one of those states, SI_ST_ASS
 * in case of success, or SI_ST_CLO in case of failure. It returns 1 if
 * it returns SI_ST_ASS, otherwise zero.
 */
int stream_sock_assign_server(struct session *t)
{
	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
		now_ms, __FUNCTION__,
		cli_stnames[t->cli_state],
		t->rep->rex, t->req->wex,
		t->req->flags, t->rep->flags,
		t->req->l, t->rep->l);

	if (t->req->cons->state == SI_ST_TAR) {
		/* connection might be aborted */
		if ((t->req->flags & BF_SHUTW_NOW) ||
		    (t->rep->flags & BF_SHUTW) ||
		    ((t->req->flags & BF_SHUTR) && /* FIXME: this should not prevent a connection from establishing */
		     (t->req->flags & BF_EMPTY || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */

			trace_term(t, TT_HTTP_SRV_1);
			t->req->wex = TICK_ETERNITY;

			// FIXME: should we set rep->MAY_FORWARD ?
			buffer_shutr(t->rep);
			buffer_shutw(t->req);
			if (!t->req->cons->err_type)
				t->req->cons->err_type = SI_ET_CONN_ABRT;
			t->req->cons->state = SI_ST_CLO;
			return 0;
		}

		if (!tick_is_expired(t->req->wex, now_ms))
			return 0;  /* still in turn-around */

		t->req->cons->state = SI_ST_INI;
	}
	else if (t->req->cons->state == SI_ST_QUE) {
		if (t->pend_pos) {
			/* request still in queue... */
			if (tick_is_expired(t->req->wex, now_ms)) {
				/* ... and timeout expired */
				trace_term(t, TT_HTTP_SRV_3);
				t->req->wex = TICK_ETERNITY;
				t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
				if (t->srv)
					t->srv->failed_conns++;
				t->be->failed_conns++;

				// FIXME: should we set rep->MAY_FORWARD ?
				buffer_shutr(t->rep);
				buffer_shutw(t->req);
				t->req->flags |= BF_WRITE_TIMEOUT;
				if (!t->req->cons->err_type)
					t->req->cons->err_type = SI_ET_QUEUE_TO;
				t->req->cons->state = SI_ST_CLO;
				return 0;
			}
			/* connection remains in queue, check if we have to abort it */
			if ((t->req->flags & BF_SHUTW_NOW) ||
			    (t->rep->flags & BF_SHUTW) ||
			    ((t->req->flags & BF_SHUTR) && /* FIXME: this should not prevent a connection from establishing */
			     (t->req->flags & BF_EMPTY || t->be->options & PR_O_ABRT_CLOSE))) {
				/* give up */
				trace_term(t, TT_HTTP_SRV_1);
				t->req->wex = TICK_ETERNITY;
				t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);

				// FIXME: should we set rep->MAY_FORWARD ?
				buffer_shutr(t->rep);
				buffer_shutw(t->req);
				if (!t->req->cons->err_type)
					t->req->cons->err_type = SI_ET_QUEUE_ABRT;
				t->req->cons->state = SI_ST_CLO;
			}
			return 0;
		}
		/* The connection is not in the queue anymore */
		t->req->cons->state = SI_ST_INI;
	}

	/* we may get here from above */
	if (t->req->cons->state == SI_ST_INI) {
		/* no connection in progress, we have to get a new one */

		/* first, check if the connection has been aborted */
		if ((t->req->flags & BF_SHUTW_NOW) ||
		    (t->rep->flags & BF_SHUTW) ||
		    ((t->req->flags & BF_SHUTR) &&
		     (t->req->flags & BF_EMPTY || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */

			trace_term(t, TT_HTTP_SRV_1);
			t->req->wex = TICK_ETERNITY;

			// FIXME: should we set rep->MAY_FORWARD ?
			buffer_shutr(t->rep);
			buffer_shutw(t->req);
			if (!t->req->cons->err_type)
				t->req->cons->err_type = SI_ET_CONN_ABRT;
			t->req->cons->state = SI_ST_CLO;
			return 0;
		}

		/* try to get a server assigned */
		if (srv_redispatch_connect(t) != 0) {
			/* we did not get any server, let's check the cause */
			if (t->req->cons->state == SI_ST_QUE) {
				/* the connection was queued, that's OK */
				return 0;
			}

			trace_term(t, TT_HTTP_SRV_2);
			t->req->wex = TICK_ETERNITY;

			// FIXME: should we set rep->MAY_FORWARD ?
			buffer_shutr(t->rep);
			buffer_shutw(t->req);
			t->req->flags |= BF_WRITE_ERROR;
			if (!t->req->cons->err_type)
				t->req->cons->err_type = SI_ET_CONN_OTHER;
			t->req->cons->state = SI_ST_CLO;
			return 0;
		}

		t->req->cons->state = SI_ST_ASS;
		/* Once the server is assigned, we have to return because
		 * the caller might be interested in checking several
		 * things before connecting.
		 */
		return 1;
	}
	return 0;
}


/*
 * This function tries to establish a connection to an assigned server. It also
 * performs connection retries. It may only be called with t->req->cons->state
 * in { SI_ST_ASS, SI_ST_CON }. It may also set the state to SI_ST_INI,
 * SI_ST_EST, or SI_ST_CLO.
 */
int stream_sock_connect_server(struct session *t)
{
	if (t->req->cons->state == SI_ST_ASS) {
		/* server assigned to request, we have to try to connect now */

		if (!srv_retryable_connect(t)) {
			/* we need to redispatch */
			t->req->cons->state = SI_ST_INI;
			return 0;
		}

		t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
		if (t->req->cons->state != SI_ST_CON) {
			/* it was an error */
			trace_term(t, TT_HTTP_SRV_4);
			t->req->wex = TICK_ETERNITY;

			// FIXME: should we set rep->MAY_FORWARD ?
			buffer_shutr(t->rep);
			buffer_shutw(t->req);
			t->req->flags |= BF_WRITE_ERROR;
			if (!t->req->cons->err_type)
				t->req->cons->err_type = SI_ET_CONN_OTHER;
			t->req->cons->state = SI_ST_CLO;
			return 0;
		}
		/* We have a socket and switched to SI_ST_CON */
	}

	/* we may also get here from above */
	if (t->req->cons->state == SI_ST_CON) {
		/* connection in progress or just completed */
		if (!tcp_connection_status(t))
			return 0;
	}
	return 0;
}


/*
 * Tries to establish a connection to the server and associate it to the
 * request buffer's consumer side. It is assumed that this function will not be
 * be called with SI_ST_EST nor with BF_MAY_FORWARD cleared. It normally
 * returns zero, but may return 1 if it absolutely wants to be called again.
 */
int process_srv_conn(struct session *t)
{
	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
		now_ms, __FUNCTION__,
		cli_stnames[t->cli_state],
		t->rep->rex, t->req->wex,
		t->req->flags, t->rep->flags,
		t->req->l, t->rep->l);

	do {
		if (t->req->cons->state == SI_ST_INI ||
		    t->req->cons->state == SI_ST_TAR ||
		    t->req->cons->state == SI_ST_QUE)	{
			/* try to assign a server */
			if (!stream_sock_assign_server(t))
				return 0;
		}

		if (t->req->cons->state == SI_ST_ASS &&
		    t->srv && t->srv->rdr_len && t->flags & SN_REDIRECTABLE) {
			/* Server supporting redirection and it is possible.
			 * Invalid requests are reported as such. It concerns all
			 * the largest ones.
			 */
			struct http_txn *txn = &t->txn;
			struct chunk rdr;
			char *path;
			int len;

			/* 1: create the response header */
			rdr.len = strlen(HTTP_302);
			rdr.str = trash;
			memcpy(rdr.str, HTTP_302, rdr.len);

			/* 2: add the server's prefix */
			if (rdr.len + t->srv->rdr_len > sizeof(trash))
				goto cancel_redir;

			memcpy(rdr.str + rdr.len, t->srv->rdr_pfx, t->srv->rdr_len);
			rdr.len += t->srv->rdr_len;

			/* 3: add the request URI */
			path = http_get_path(txn);
			if (!path)
				goto cancel_redir;
			len = txn->req.sl.rq.u_l + (txn->req.sol+txn->req.sl.rq.u) - path;
			if (rdr.len + len > sizeof(trash) - 4) /* 4 for CRLF-CRLF */
				goto cancel_redir;

			memcpy(rdr.str + rdr.len, path, len);
			rdr.len += len;
			memcpy(rdr.str + rdr.len, "\r\n\r\n", 4);
			rdr.len += 4;

			srv_close_with_err(t, SN_ERR_PRXCOND, SN_FINST_C, 302, &rdr);
			trace_term(t, TT_HTTP_SRV_3);

			/* FIXME: we should increase a counter of redirects per server and per backend. */
			if (t->srv)
				t->srv->cum_sess++;

			t->req->cons->state = SI_ST_CLO;
			return 0;
		cancel_redir:
			//txn->status = 400;
			//t->fe->failed_req++;
			//srv_close_with_err(t, SN_ERR_PRXCOND, SN_FINST_C,
			//		   400, error_message(t, HTTP_ERR_400));
			trace_term(t, TT_HTTP_SRV_4);

			// FIXME: should we set rep->MAY_FORWARD ?
			buffer_shutw(t->req);
			buffer_shutr(t->rep);
			if (!t->req->cons->err_type)
				t->req->cons->err_type = SI_ET_CONN_OTHER;
			t->req->cons->state = SI_ST_CLO;
			return 0;
		}

		if (t->req->cons->state == SI_ST_CON ||
		    t->req->cons->state == SI_ST_ASS) {
			stream_sock_connect_server(t);
		}
	} while (t->req->cons->state != SI_ST_CLO &&
		 t->req->cons->state != SI_ST_CON &&
		 t->req->cons->state != SI_ST_EST);
	return 0;
}


/*
 * Manages the server FSM and its socket during the DATA phase. It must not be
 * called when a file descriptor is not attached to the buffer. It must only be
 * called during SI_ST_EST. It normally returns zero, but may return 1 if it
 * absolutely wants to be called again.
 */
int process_srv_data(struct session *t)
{
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;
	int fd = req->cons->fd;

	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
		now_ms, __FUNCTION__,
		cli_stnames[t->cli_state],
		rep->rex, req->wex,
		req->flags, rep->flags,
		req->l, rep->l);

	if (req->flags & (BF_WRITE_ERROR | BF_WRITE_TIMEOUT) ||
	    rep->flags & (BF_READ_ERROR | BF_READ_TIMEOUT)) {
		/* nothing more to be done here */
		fprintf(stderr, "Hey what are you doing there? t=%p fd=%d state=%d\n",
			t, t->req->cons->fd, t->req->cons->state);
		return 0;
	}

	/* we can skip most of the tests at once if some conditions are not met */
	/* FIXME: place req->BF_SHUTW_NOW here */
	//if (!((fdtab[fd].state == FD_STERROR) ||
	//      (!(req->flags & BF_SHUTW) &&
	//       (req->flags & (BF_EMPTY|BF_MAY_FORWARD)) == (BF_EMPTY|BF_MAY_FORWARD)) ||
	//      (rep->flags & (BF_READ_TIMEOUT|BF_READ_ERROR)) ||
	//      (!(rep->flags & BF_SHUTR) && rep->flags & (BF_READ_NULL|BF_SHUTR_NOW|BF_SHUTW))))
	//	goto update_timeouts;

	/* read or write error */
	/* FIXME: what happens when we have to deal with HTTP ??? */
	if (fdtab[fd].state == FD_STERROR) {
		trace_term(t, TT_HTTP_SRV_6);
		buffer_shutw(req);
		req->flags |= BF_WRITE_ERROR;
		buffer_shutr(rep);
		rep->flags |= BF_READ_ERROR;
		fd_delete(fd);
		req->cons->state = SI_ST_CLO;
		if (t->srv) {
			t->srv->cur_sess--;
			//t->srv->failed_resp++;
			//FIXME: si on ne traite pas l'erreur ici, le serveur est perdu et on ne la comptabilisera plus ensuite.
			//il va donc falloir stocker l'info du dernier serveur en erreur pour que les couches du dessus traitent.
			sess_change_server(t, NULL);
		}
		//t->be->failed_resp++;
		//if (!rep->analysers) {
		//	if (!(t->flags & SN_ERR_MASK))
		//		t->flags |= SN_ERR_SRVCL;
		//	if (!(t->flags & SN_FINST_MASK))
		//		t->flags |= SN_FINST_D;
		//}
		if (may_dequeue_tasks(t->srv, t->be))
			process_srv_queue(t->srv);

		return 0;
	}

	/* last read, or end of client write */
	if (!(rep->flags & BF_SHUTR) &&   /* not already done */
	    rep->flags & (BF_READ_NULL|BF_SHUTR_NOW|BF_SHUTW)) {
		buffer_shutr(rep);
		if (!(req->flags & BF_SHUTW)) {
			EV_FD_CLR(fd, DIR_RD);
			trace_term(t, TT_HTTP_SRV_7);
		} else {
			/* output was already closed */
			trace_term(t, TT_HTTP_SRV_8);
			fd_delete(fd);
			req->cons->state = SI_ST_CLO;
			if (t->srv) {
				t->srv->cur_sess--;
				sess_change_server(t, NULL);
			}

			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);
			return 0;
		}
	}
	/* end of client read and no more data to send. We can forward
	 * the close when we're allowed to forward data (anytime right
	 * now). If we're using option forceclose, then we may also
	 * shutdown the outgoing write channel once the response starts
	 * coming from the server.
	 */

	// FIXME: option FORCE_CLOSE should move to upper layer.
	if (!(req->flags & BF_SHUTW) && /* not already done */
	    (req->flags & BF_SHUTW_NOW ||
	     (req->flags & BF_EMPTY && req->flags & BF_MAY_FORWARD &&
	      (req->flags & BF_SHUTR ||
	       (t->be->options & PR_O_FORCE_CLO && rep->flags & BF_READ_STATUS))))) {
		buffer_shutw(req);
		if (!(rep->flags & BF_SHUTR)) {
			trace_term(t, TT_HTTP_SRV_9);
			EV_FD_CLR(fd, DIR_WR);
			shutdown(fd, SHUT_WR);
		} else {
			trace_term(t, TT_HTTP_SRV_10);
			fd_delete(fd);
			req->cons->state = SI_ST_CLO;
			if (t->srv) {
				t->srv->cur_sess--;
				sess_change_server(t, NULL);
			}

			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);
			return 0;
		}
	}

	/* read timeout */
	if ((rep->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == 0 &&
	    tick_is_expired(rep->rex, now_ms)) {
		rep->flags |= BF_READ_TIMEOUT;
		//if (!rep->analysers) {
		//	if (!(t->flags & SN_ERR_MASK))
		//		t->flags |= SN_ERR_SRVTO;
		//	if (!(t->flags & SN_FINST_MASK))
		//		t->flags |= SN_FINST_D;
		//}
		buffer_shutr(rep);
		if (!(req->flags & BF_SHUTW)) {
			trace_term(t, TT_HTTP_SRV_11);
			EV_FD_CLR(fd, DIR_RD);
		} else {
			trace_term(t, TT_HTTP_SRV_12);
			fd_delete(fd);
			req->cons->state = SI_ST_CLO;
			if (t->srv) {
				t->srv->cur_sess--;
				sess_change_server(t, NULL);
			}

			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);
			return 0;
		}
	}

	/* write timeout */
	if ((req->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == 0 &&
	    tick_is_expired(req->wex, now_ms)) {
		req->flags |= BF_WRITE_TIMEOUT;
		//if (!rep->analysers) {
		//	if (!(t->flags & SN_ERR_MASK))
		//		t->flags |= SN_ERR_SRVTO;
		//	if (!(t->flags & SN_FINST_MASK))
		//		t->flags |= SN_FINST_D;
		//}
		buffer_shutw(req);
		if (!(rep->flags & BF_SHUTR)) {
			trace_term(t, TT_HTTP_SRV_13);
			EV_FD_CLR(fd, DIR_WR);
			shutdown(fd, SHUT_WR);
		} else {
			trace_term(t, TT_HTTP_SRV_14);
			fd_delete(fd);
			req->cons->state = SI_ST_CLO;
			if (t->srv) {
				t->srv->cur_sess--;
				sess_change_server(t, NULL);
			}

			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);
			return 0;
		}
	}

 update_timeouts:
	/* manage read timeout */
	if (!(rep->flags & BF_SHUTR)) {
		if (rep->flags & (BF_FULL|BF_HIJACK)) {
			if (EV_FD_COND_C(fd, DIR_RD))
				rep->rex = TICK_ETERNITY;
		} else {
			EV_FD_COND_S(fd, DIR_RD);
			rep->rex = tick_add_ifset(now_ms, t->be->timeout.server);
		}
	}

	/* manage write timeout */
	if (!(req->flags & BF_SHUTW)) {
		if ((req->flags & (BF_EMPTY|BF_MAY_FORWARD)) != BF_MAY_FORWARD) {
			/* stop writing */
			if (EV_FD_COND_C(fd, DIR_WR))
				req->wex = TICK_ETERNITY;
		} else {
			/* buffer not empty, there are still data to be transferred */
			EV_FD_COND_S(fd, DIR_WR);
			if (!tick_isset(req->wex)) {
				/* restart writing */
				req->wex = tick_add_ifset(now_ms, t->be->timeout.server);
				if (!(rep->flags & BF_SHUTR) && tick_isset(req->wex) && tick_isset(rep->rex)) {
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it, except if it was already infinite.
					 */
					rep->rex = req->wex;
				}
			}
		}
	}
	return 0; /* other cases change nothing */
}


///*
// * Manages the client FSM and its socket. It normally returns zero, but may
// * return 1 if it absolutely wants to be called again.
// *
// * Note: process_cli is the ONLY function allowed to set cli_state to anything
// *       but CL_STCLOSE.
// */
//int process_cli(struct session *t)
//{
//	struct buffer *req = t->req;
//	struct buffer *rep = t->rep;
//
//	DPRINTF(stderr,"[%u] %s: c=%s set(r,w)=%d,%d exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
//		now_ms, __FUNCTION__,
//		cli_stnames[t->cli_state],
//		t->cli_fd >= 0 && fdtab[t->cli_fd].state != FD_STCLOSE ? EV_FD_ISSET(t->cli_fd, DIR_RD) : 0,
//		t->cli_fd >= 0 && fdtab[t->cli_fd].state != FD_STCLOSE ? EV_FD_ISSET(t->cli_fd, DIR_WR) : 0,
//		req->rex, rep->wex,
//		req->flags, rep->flags,
//		req->l, rep->l);
//
// update_state:
//	/* FIXME: we still have to check for CL_STSHUTR because client_retnclose
//	 * still set this state (and will do until unix sockets are converted).
//	 */
//	if (t->cli_state == CL_STDATA || t->cli_state == CL_STSHUTR) {
//		/* we can skip most of the tests at once if some conditions are not met */
//		if (!((req->flags & (BF_READ_TIMEOUT|BF_READ_ERROR))   ||
//		      (rep->flags & (BF_WRITE_TIMEOUT|BF_WRITE_ERROR)) ||
//		      (!(req->flags & BF_SHUTR) && req->flags & (BF_READ_NULL|BF_SHUTW)) ||
//		      (!(rep->flags & BF_SHUTW) &&
//		       (rep->flags & (BF_EMPTY|BF_MAY_FORWARD|BF_SHUTR)) == (BF_EMPTY|BF_MAY_FORWARD|BF_SHUTR))))
//			goto update_timeouts;
//
//		/* read or write error */
//		if (rep->flags & BF_WRITE_ERROR || req->flags & BF_READ_ERROR) {
//			buffer_shutr(req);
//			buffer_shutw(rep);
//			fd_delete(t->cli_fd);
//			t->cli_state = CL_STCLOSE;
//			trace_term(t, TT_HTTP_CLI_1);
//			if (!req->analysers) {
//				if (!(t->flags & SN_ERR_MASK))
//					t->flags |= SN_ERR_CLICL;
//				if (!(t->flags & SN_FINST_MASK)) {
//					if (t->pend_pos)
//						t->flags |= SN_FINST_Q;
//					else if (!(req->flags & BF_CONNECTED))
//						t->flags |= SN_FINST_C;
//					else
//						t->flags |= SN_FINST_D;
//				}
//			}
//			goto update_state;
//		}
//		/* last read, or end of server write */
//		else if (!(req->flags & BF_SHUTR) &&   /* not already done */
//			 req->flags & (BF_READ_NULL | BF_SHUTW)) {
//			buffer_shutr(req);
//			if (!(rep->flags & BF_SHUTW)) {
//				EV_FD_CLR(t->cli_fd, DIR_RD);
//				trace_term(t, TT_HTTP_CLI_2);
//			} else {
//				/* output was already closed */
//				fd_delete(t->cli_fd);
//				t->cli_state = CL_STCLOSE;
//				trace_term(t, TT_HTTP_CLI_3);
//			}
//			goto update_state;
//		}
//		/* last server read and buffer empty : we only check them when we're
//		 * allowed to forward the data.
//		 */
//		else if (!(rep->flags & BF_SHUTW) &&   /* not already done */
//			 rep->flags & BF_EMPTY && rep->flags & BF_MAY_FORWARD &&
//			 rep->flags & BF_SHUTR && !(t->flags & SN_SELF_GEN)) {
//			buffer_shutw(rep);
//			if (!(req->flags & BF_SHUTR)) {
//				EV_FD_CLR(t->cli_fd, DIR_WR);
//				shutdown(t->cli_fd, SHUT_WR);
//				/* We must ensure that the read part is still alive when switching to shutw */
//				/* FIXME: is this still true ? */
//				EV_FD_SET(t->cli_fd, DIR_RD);
//				req->rex = tick_add_ifset(now_ms, t->fe->timeout.client);
//				trace_term(t, TT_HTTP_CLI_4);
//			} else {
//				fd_delete(t->cli_fd);
//				t->cli_state = CL_STCLOSE;
//				trace_term(t, TT_HTTP_CLI_5);
//			}
//			goto update_state;
//		}
//		/* read timeout */
//		else if ((req->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == BF_READ_TIMEOUT) {
//			buffer_shutr(req);
//			if (!(rep->flags & BF_SHUTW)) {
//				EV_FD_CLR(t->cli_fd, DIR_RD);
//				trace_term(t, TT_HTTP_CLI_6);
//			} else {
//				/* output was already closed */
//				fd_delete(t->cli_fd);
//				t->cli_state = CL_STCLOSE;
//				trace_term(t, TT_HTTP_CLI_7);
//			}
//			if (!req->analysers) {
//				if (!(t->flags & SN_ERR_MASK))
//					t->flags |= SN_ERR_CLITO;
//				if (!(t->flags & SN_FINST_MASK)) {
//					if (t->pend_pos)
//						t->flags |= SN_FINST_Q;
//					else if (!(req->flags & BF_CONNECTED))
//						t->flags |= SN_FINST_C;
//					else
//						t->flags |= SN_FINST_D;
//				}
//			}
//			goto update_state;
//		}
//		/* write timeout */
//		else if ((rep->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == BF_WRITE_TIMEOUT) {
//			buffer_shutw(rep);
//			if (!(req->flags & BF_SHUTR)) {
//				EV_FD_CLR(t->cli_fd, DIR_WR);
//				shutdown(t->cli_fd, SHUT_WR);
//				/* We must ensure that the read part is still alive when switching to shutw */
//				/* FIXME: is this still true ? */
//				EV_FD_SET(t->cli_fd, DIR_RD);
//				req->rex = tick_add_ifset(now_ms, t->fe->timeout.client);
//				trace_term(t, TT_HTTP_CLI_8);
//			} else {
//				fd_delete(t->cli_fd);
//				t->cli_state = CL_STCLOSE;
//				trace_term(t, TT_HTTP_CLI_9);
//			}
//			if (!req->analysers) {
//				if (!(t->flags & SN_ERR_MASK))
//					t->flags |= SN_ERR_CLITO;
//				if (!(t->flags & SN_FINST_MASK)) {
//					if (t->pend_pos)
//						t->flags |= SN_FINST_Q;
//					else if (!(req->flags & BF_CONNECTED))
//						t->flags |= SN_FINST_C;
//					else
//						t->flags |= SN_FINST_D;
//				}
//			}
//			goto update_state;
//		}
//
//	update_timeouts:
//		/* manage read timeout */
//		if (!(req->flags & BF_SHUTR)) {
//			if (req->flags & BF_FULL) {
//				/* no room to read more data */
//				if (EV_FD_COND_C(t->cli_fd, DIR_RD)) {
//					/* stop reading until we get some space */
//					req->rex = TICK_ETERNITY;
//				}
//			} else {
//				EV_FD_COND_S(t->cli_fd, DIR_RD);
//				req->rex = tick_add_ifset(now_ms, t->fe->timeout.client);
//			}
//		}
//
//		/* manage write timeout */
//		if (!(rep->flags & BF_SHUTW)) {
//			/* first, we may have to produce data (eg: stats).
//			 * right now, this is limited to the SHUTR state.
//			 */
//			if (req->flags & BF_SHUTR && t->flags & SN_SELF_GEN) {
//				produce_content(t);
//				if (rep->flags & BF_EMPTY) {
//					buffer_shutw(rep);
//					fd_delete(t->cli_fd);
//					t->cli_state = CL_STCLOSE;
//					trace_term(t, TT_HTTP_CLI_10);
//					goto update_state;
//				}
//			}
//
//			/* we don't enable client write if the buffer is empty, nor if the server has to analyze it */
//			if ((rep->flags & BF_EMPTY) || !(rep->flags & BF_MAY_FORWARD)) {
//				if (EV_FD_COND_C(t->cli_fd, DIR_WR)) {
//					/* stop writing */
//					rep->wex = TICK_ETERNITY;
//				}
//			} else {
//				/* buffer not empty */
//				EV_FD_COND_S(t->cli_fd, DIR_WR);
//				if (!tick_isset(rep->wex)) {
//					/* restart writing */
//					rep->wex = tick_add_ifset(now_ms, t->fe->timeout.client);
//					if (!(req->flags & BF_SHUTR) && tick_isset(rep->wex) && tick_isset(req->rex)) {
//						/* FIXME: to prevent the client from expiring read timeouts during writes,
//						 * we refresh it, except if it was already infinite. */
//						req->rex = rep->wex;
//					}
//				}
//			}
//		}
//		return 0; /* other cases change nothing */
//	}
//	else if (t->cli_state == CL_STCLOSE) { /* CL_STCLOSE: nothing to do */
//		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
//			int len;
//			len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n", t->uniq_id, t->be->id, (unsigned short)t->cli_fd, (unsigned short)req->cons->fd);
//			write(1, trash, len);
//		}
//		return 0;
//	}
//#ifdef DEBUG_DEV
//	fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, t->cli_state);
//	ABORT_NOW();
//#endif
//	return 0;
//}
//
//
///* Return 1 if we could get a new connection for session t, otherwise zero */
//int tcp_get_connection(struct session *t)
//{
//	struct http_txn *txn = &t->txn;
//	struct buffer *req = t->req;
//	struct buffer *rep = t->rep;
//
//	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
//		now_ms, __FUNCTION__,
//		cli_stnames[t->cli_state],
//		rep->rex, req->wex,
//		req->flags, rep->flags,
//		req->l, rep->l);
//
//
//	if ((rep->flags & BF_SHUTW) ||
//	    ((req->flags & BF_SHUTR) &&
//	     (req->flags & BF_EMPTY || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
//		req->wex = TICK_ETERNITY;
//		if (t->pend_pos)
//			t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
//		/* note that this must not return any error because it would be able to
//		 * overwrite the client_retnclose() output.
//		 */
//		if (txn->flags & TX_CLTARPIT)
//			srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_T, 0, NULL);
//		else
//			srv_close_with_err(t, SN_ERR_CLICL, t->pend_pos ? SN_FINST_Q : SN_FINST_C, 0, NULL);
//
//		trace_term(t, TT_HTTP_SRV_1);
//		return 0;
//	}
//
//	/* stop here if we're not allowed to connect */
//	if (!(req->flags & BF_MAY_FORWARD))
//		return 0;
//
//	/* the client allows the server to connect */
//	if (txn->flags & TX_CLTARPIT) {
//		/* This connection is being tarpitted. The CLIENT side has
//		 * already set the connect expiration date to the right
//		 * timeout. We just have to check that it has not expired.
//		 */
//		if (!(req->flags & BF_WRITE_TIMEOUT))
//			return 0;
//
//		/* We will set the queue timer to the time spent, just for
//		 * logging purposes. We fake a 500 server error, so that the
//		 * attacker will not suspect his connection has been tarpitted.
//		 * It will not cause trouble to the logs because we can exclude
//		 * the tarpitted connections by filtering on the 'PT' status flags.
//		 */
//		req->wex = TICK_ETERNITY;
//		t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
//		srv_close_with_err(t, SN_ERR_PRXCOND, SN_FINST_T,
//				   500, error_message(t, HTTP_ERR_500));
//		trace_term(t, TT_HTTP_SRV_2);
//		return 0;
//	}
//
//	/* Right now, we will need to create a connection to the server.
//	 * We might already have tried, and got a connection pending, in
//	 * which case we will not do anything till it's pending. It's up
//	 * to any other session to release it and wake us up again.
//	 */
//	if (t->pend_pos) {
//		if (!(req->flags & BF_WRITE_TIMEOUT)) {
//			return 0;
//		} else {
//			/* we've been waiting too long here */
//			req->wex = TICK_ETERNITY;
//			t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
//			srv_close_with_err(t, SN_ERR_SRVTO, SN_FINST_Q,
//					   503, error_message(t, HTTP_ERR_503));
//			trace_term(t, TT_HTTP_SRV_3);
//			if (t->srv)
//				t->srv->failed_conns++;
//			t->be->failed_conns++;
//			return 0;
//		}
//	}
//
//	do {
//		if (srv_redispatch_connect(t) != 0)
//			return 0;
//
//		if (t->srv && t->srv->rdr_len && t->flags & SN_REDIRECTABLE) {
//			/* Server supporting redirection and it is possible.
//			 * Invalid requests are reported as such. It concerns all
//			 * the largest ones.
//			 */
//			struct chunk rdr;
//			char *path;
//			int len;
//
//			/* 1: create the response header */
//			rdr.len = strlen(HTTP_302);
//			rdr.str = trash;
//			memcpy(rdr.str, HTTP_302, rdr.len);
//
//			/* 2: add the server's prefix */
//			if (rdr.len + t->srv->rdr_len > sizeof(trash))
//				goto cancel_redir;
//
//			memcpy(rdr.str + rdr.len, t->srv->rdr_pfx, t->srv->rdr_len);
//			rdr.len += t->srv->rdr_len;
//
//			/* 3: add the request URI */
//			path = http_get_path(txn);
//			if (!path)
//				goto cancel_redir;
//			len = txn->req.sl.rq.u_l + (txn->req.sol+txn->req.sl.rq.u) - path;
//			if (rdr.len + len > sizeof(trash) - 4) /* 4 for CRLF-CRLF */
//				goto cancel_redir;
//
//			memcpy(rdr.str + rdr.len, path, len);
//			rdr.len += len;
//			memcpy(rdr.str + rdr.len, "\r\n\r\n", 4);
//			rdr.len += 4;
//
//			srv_close_with_err(t, SN_ERR_PRXCOND, SN_FINST_C, 302, &rdr);
//			trace_term(t, TT_HTTP_SRV_3);
//
//			/* FIXME: we should increase a counter of redirects per server and per backend. */
//			if (t->srv)
//				t->srv->cum_sess++;
//			return 0;
//		cancel_redir:
//			txn->status = 400;
//			t->fe->failed_req++;
//			srv_close_with_err(t, SN_ERR_PRXCOND, SN_FINST_C,
//					   400, error_message(t, HTTP_ERR_400));
//			trace_term(t, TT_HTTP_SRV_4);
//			return 0;
//		}
//
//		/* try to (re-)connect to the server, and fail if we expire the
//		 * number of retries.
//		 */
//		if (srv_retryable_connect(t)) {
//			t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
//			if (!(req->cons.flags & BC_KNOWN))
//				return 0;
//			/* We got an FD */
//			return 1;
//		}
//	} while (1);
//}
//
//
///* Return 1 if the pending connection has failed and should be retried,
// * otherwise zero.
// */
//int tcp_connection_failed(struct session *t)
//{
//	struct buffer *req = t->req;
//	struct buffer *rep = t->rep;
//	int conn_err;
//
//	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
//		now_ms, __FUNCTION__,
//		cli_stnames[t->cli_state],
//		rep->rex, req->wex,
//		req->flags, rep->flags,
//		req->l, rep->l);
//
//	if ((rep->flags & BF_SHUTW) ||
//	    ((req->flags & BF_SHUTR) &&
//	     ((req->flags & BF_EMPTY && !(req->flags & BF_WRITE_STATUS)) ||
//	      t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
//		req->wex = TICK_ETERNITY;
//		if (!(t->flags & SN_CONN_TAR)) {
//			/* if we are in turn-around, we have already closed the FD */
//			fd_delete(req->cons->fd);
//			req->cons->state = SI_ST_CLO;
//			if (t->srv) {
//				t->srv->cur_sess--;
//				sess_change_server(t, NULL);
//			}
//		}
//
//		/* note that this must not return any error because it would be able to
//		 * overwrite the client_retnclose() output.
//		 */
//		srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_C, 0, NULL);
//		trace_term(t, TT_HTTP_SRV_5);
//		return 0;
//	}
//
//	if (!(req->flags & (BF_WRITE_STATUS | BF_WRITE_TIMEOUT)))
//		return 0; /* nothing changed */
//
//	if (!(req->flags & BF_WRITE_STATUS) || (req->flags & BF_WRITE_ERROR)) {
//		/* timeout, asynchronous connect error or first write error */
//		if (t->flags & SN_CONN_TAR) {
//			/* We are doing a turn-around waiting for a new connection attempt. */
//			if (!(req->flags & BF_WRITE_TIMEOUT))
//				return 0;
//			t->flags &= ~SN_CONN_TAR;
//		}
//		else {
//			fd_delete(req->cons->fd);
//			req->cons->state = SI_ST_CLO;
//			if (t->srv) {
//				t->srv->cur_sess--;
//				sess_change_server(t, NULL);
//			}
//
//			if (!(req->flags & BF_WRITE_STATUS))
//				conn_err = SN_ERR_SRVTO; // it was a connect timeout.
//			else
//				conn_err = SN_ERR_SRVCL; // it was an asynchronous connect error.
//
//			/* ensure that we have enough retries left */
//			if (srv_count_retry_down(t, conn_err))
//				return 0;
//
//			if (req->flags & BF_WRITE_ERROR) {
//				/* we encountered an immediate connection error, and we
//				 * will have to retry connecting to the same server, most
//				 * likely leading to the same result. To avoid this, we
//				 * fake a connection timeout to retry after a turn-around
//				 * time of 1 second. We will wait in the previous if block.
//				 */
//				t->flags |= SN_CONN_TAR;
//				req->wex = tick_add(now_ms, MS_TO_TICKS(1000));
//				return 0;
//			}
//		}
//
//		if (t->srv && t->conn_retries == 0 && t->be->options & PR_O_REDISP) {
//			/* We're on our last chance, and the REDISP option was specified.
//			 * We will ignore cookie and force to balance or use the dispatcher.
//			 */
//			/* let's try to offer this slot to anybody */
//			if (may_dequeue_tasks(t->srv, t->be))
//				process_srv_queue(t->srv);
//
//			/* it's left to the dispatcher to choose a server */
//			t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
//			t->prev_srv = t->srv;
//
//			/* first, get a connection */
//			if (srv_redispatch_connect(t)) {
//				if (req->cons.flags & BC_KNOWN)
//					return 0;
//				/* we need to get a connection */
//				return 1;
//			}
//		} else {
//			if (t->srv)
//				t->srv->retries++;
//			t->be->retries++;
//		}
//
//		do {
//			/* Now we will try to either reconnect to the same server or
//			 * connect to another server. If the connection gets queued
//			 * because all servers are saturated, then we will go back to
//			 * the idle state where the buffer's consumer is marked as
//			 * unknown.
//			 */
//			if (srv_retryable_connect(t)) {
//				t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
//				if (req->cons.flags & BC_KNOWN)
//					return 0;
//				/* we did not get a connection */
//				return 1;
//			}
//
//			/* we need to redispatch the connection to another server */
//			if (srv_redispatch_connect(t)) {
//				if (req->cons.flags & BC_KNOWN)
//					return 0;
//				/* we need to get a connection */
//				return 1;
//			}
//		} while (1);
//	}
//	else { /* no error and write OK */
//		t->logs.t_connect = tv_ms_elapsed(&t->logs.tv_accept, &now);
//
//		if (req->flags & BF_EMPTY) {
//			EV_FD_CLR(req->cons->fd, DIR_WR);
//			req->wex = TICK_ETERNITY;
//		} else {
//			EV_FD_SET(req->cons->fd, DIR_WR);
//			req->wex = tick_add_ifset(now_ms, t->be->timeout.server);
//			if (tick_isset(req->wex)) {
//				/* FIXME: to prevent the server from expiring read timeouts during writes,
//				 * we refresh it. */
//				rep->rex = req->wex;
//			}
//		}
//
//		if (t->be->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
//			EV_FD_SET(req->cons->fd, DIR_RD);
//			rep->rex = tick_add_ifset(now_ms, t->be->timeout.server);
//			buffer_set_rlim(rep, BUFSIZE); /* no rewrite needed */
//
//			/* if the user wants to log as soon as possible, without counting
//			   bytes from the server, then this is the right moment. */
//			if (t->fe->to_log && !(t->logs.logwait & LW_BYTES)) {
//				t->logs.t_close = t->logs.t_connect; /* to get a valid end date */
//				tcp_sess_log(t);
//			}
//#ifdef CONFIG_HAP_TCPSPLICE
//			if ((t->fe->options & t->be->options) & PR_O_TCPSPLICE) {
//				/* TCP splicing supported by both FE and BE */
//				tcp_splice_splicefd(t->cli_fd, req->cons->fd, 0);
//			}
//#endif
//		}
//		else {
//			rep->analysers |= AN_RTR_HTTP_HDR;
//			buffer_set_rlim(rep, BUFSIZE - MAXREWRITE); /* rewrite needed */
//			t->txn.rsp.msg_state = HTTP_MSG_RPBEFORE;
//			/* reset hdr_idx which was already initialized by the request.
//			 * right now, the http parser does it.
//			 * hdr_idx_init(&t->txn.hdr_idx);
//			 */
//		}
//
//		req->flags |= BF_CONNECTED;
//		if (!rep->analysers)
//			t->rep->flags |= BF_MAY_FORWARD;
//		req->wex = TICK_ETERNITY;
//		return 0;
//	}
//}
//
//
///*
// * Tries to establish a connection to the server and associate it to the
// * request buffer's consumer side. It normally returns zero, but may return 1
// * if it absolutely wants to be called again.
// */
//int process_srv_conn(struct session *t)
//{
//	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
//		now_ms, __FUNCTION__,
//		cli_stnames[t->cli_state],
//		t->rep->rex, t->req->wex,
//		t->req->flags, t->rep->flags,
//		t->req->l, t->rep->l);
//
//	while (!(t->req->flags & BF_CONNECTED)) {
//		if (!(t->req->cons.flags & BC_KNOWN)) {
//			/* no connection in progress, get a new one */
//			if (!tcp_get_connection(t))
//				break;
//		} else {
//			/* connection in progress or just completed */
//			if (!tcp_connection_failed(t))
//				break;
//		}
//	}
//	return 0;
//}
//
//
///*
// * Manages the server FSM and its socket during the DATA phase. It must not
// * be called when a file descriptor is not attached to the buffer. It normally
// * returns zero, but may return 1 if it absolutely wants to be called again.
// */
//int process_srv_data(struct session *t)
//{
//	struct buffer *req = t->req;
//	struct buffer *rep = t->rep;
//
//	DPRINTF(stderr,"[%u] %s: c=%s exp(r,w)=%u,%u req=%08x rep=%08x rql=%d rpl=%d\n",
//		now_ms, __FUNCTION__,
//		cli_stnames[t->cli_state],
//		rep->rex, req->wex,
//		req->flags, rep->flags,
//		req->l, rep->l);
//
//	/* we can skip most of the tests at once if some conditions are not met */
//	if (!((req->flags & (BF_WRITE_TIMEOUT|BF_WRITE_ERROR)) ||
//	      (!(req->flags & BF_SHUTW) &&
//	       (req->flags & (BF_EMPTY|BF_MAY_FORWARD)) == (BF_EMPTY|BF_MAY_FORWARD)) ||
//	      (rep->flags & (BF_READ_TIMEOUT|BF_READ_ERROR)) ||
//	      (!(rep->flags & BF_SHUTR) && rep->flags & (BF_READ_NULL|BF_SHUTW))))
//		goto update_timeouts;
//
//	/* read or write error */
//	/* FIXME: what happens when we have to deal with HTTP ??? */
//	if (req->flags & BF_WRITE_ERROR || rep->flags & BF_READ_ERROR) {
//		buffer_shutr(rep);
//		buffer_shutw(req);
//		fd_delete(req->cons->fd);
//		req->cons->state = SI_ST_CLO;
//		if (t->srv) {
//			t->srv->cur_sess--;
//			t->srv->failed_resp++;
//			sess_change_server(t, NULL);
//		}
//		t->be->failed_resp++;
//		trace_term(t, TT_HTTP_SRV_6);
//		if (!rep->analysers) {
//			if (!(t->flags & SN_ERR_MASK))
//				t->flags |= SN_ERR_SRVCL;
//			if (!(t->flags & SN_FINST_MASK))
//				t->flags |= SN_FINST_D;
//		}
//		if (may_dequeue_tasks(t->srv, t->be))
//			process_srv_queue(t->srv);
//
//		return 0;
//	}
//
//	/* last read, or end of client write */
//	if (!(rep->flags & BF_SHUTR) &&   /* not already done */
//		 rep->flags & (BF_READ_NULL | BF_SHUTW)) {
//		buffer_shutr(rep);
//		if (!(req->flags & BF_SHUTW)) {
//			EV_FD_CLR(req->cons->fd, DIR_RD);
//			trace_term(t, TT_HTTP_SRV_7);
//		} else {
//			/* output was already closed */
//			fd_delete(req->cons->fd);
//			req->cons->state = SI_ST_CLO;
//			if (t->srv) {
//				t->srv->cur_sess--;
//				sess_change_server(t, NULL);
//			}
//			trace_term(t, TT_HTTP_SRV_8);
//
//			if (may_dequeue_tasks(t->srv, t->be))
//				process_srv_queue(t->srv);
//			return 0;
//		}
//	}
//	/* end of client read and no more data to send. We can forward
//	 * the close when we're allowed to forward data (anytime right
//	 * now). If we're using option forceclose, then we may also
//	 * shutdown the outgoing write channel once the response starts
//	 * coming from the server.
//	 */
//	if (!(req->flags & BF_SHUTW) && /* not already done */
//	    req->flags & BF_EMPTY && req->flags & BF_MAY_FORWARD &&
//	    (req->flags & BF_SHUTR ||
//	     (t->be->options & PR_O_FORCE_CLO && rep->flags & BF_READ_STATUS))) {
//		buffer_shutw(req);
//		if (!(rep->flags & BF_SHUTR)) {
//			EV_FD_CLR(req->cons->fd, DIR_WR);
//			shutdown(req->cons->fd, SHUT_WR);
//			trace_term(t, TT_HTTP_SRV_9);
//			/* We must ensure that the read part is still alive when switching to shutw */
//			/* FIXME: is this still true ? */
//			EV_FD_SET(req->cons->fd, DIR_RD);
//			rep->rex = tick_add_ifset(now_ms, t->be->timeout.server);
//		} else {
//			fd_delete(req->cons->fd);
//			req->cons->state = SI_ST_CLO;
//			if (t->srv) {
//				t->srv->cur_sess--;
//				sess_change_server(t, NULL);
//			}
//			trace_term(t, TT_HTTP_SRV_10);
//
//			if (may_dequeue_tasks(t->srv, t->be))
//				process_srv_queue(t->srv);
//			return 0;
//		}
//	}
//
//	/* read timeout */
//	if ((rep->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == BF_READ_TIMEOUT) {
//		if (!rep->analysers) {
//			if (!(t->flags & SN_ERR_MASK))
//				t->flags |= SN_ERR_SRVTO;
//			if (!(t->flags & SN_FINST_MASK))
//				t->flags |= SN_FINST_D;
//		}
//		buffer_shutr(rep);
//		if (!(req->flags & BF_SHUTW)) {
//			EV_FD_CLR(req->cons->fd, DIR_RD);
//			trace_term(t, TT_HTTP_SRV_11);
//		} else {
//			fd_delete(req->cons->fd);
//			req->cons->state = SI_ST_CLO;
//			if (t->srv) {
//				t->srv->cur_sess--;
//				sess_change_server(t, NULL);
//			}
//			trace_term(t, TT_HTTP_SRV_12);
//
//			if (may_dequeue_tasks(t->srv, t->be))
//				process_srv_queue(t->srv);
//			return 0;
//		}
//	}
//
//	/* write timeout */
//	if ((req->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == BF_WRITE_TIMEOUT) {
//		if (!rep->analysers) {
//			if (!(t->flags & SN_ERR_MASK))
//				t->flags |= SN_ERR_SRVTO;
//			if (!(t->flags & SN_FINST_MASK))
//				t->flags |= SN_FINST_D;
//		}
//		buffer_shutw(req);
//		if (!(rep->flags & BF_SHUTR)) {
//			EV_FD_CLR(req->cons->fd, DIR_WR);
//			shutdown(req->cons->fd, SHUT_WR);
//			/* We must ensure that the read part is still alive when switching to shutw */
//			/* FIXME: is this still needed ? */
//			EV_FD_SET(req->cons->fd, DIR_RD);
//			rep->rex = tick_add_ifset(now_ms, t->be->timeout.server);
//			trace_term(t, TT_HTTP_SRV_13);
//		} else {
//			fd_delete(req->cons->fd);
//			req->cons->state = SI_ST_CLO;
//			if (t->srv) {
//				t->srv->cur_sess--;
//				sess_change_server(t, NULL);
//			}
//			trace_term(t, TT_HTTP_SRV_14);
//
//			if (may_dequeue_tasks(t->srv, t->be))
//				process_srv_queue(t->srv);
//			return 0;
//		}
//	}
//
// update_timeouts:
//	/* manage read timeout */
//	if (!(rep->flags & BF_SHUTR)) {
//		if (rep->flags & BF_FULL) {
//			if (EV_FD_COND_C(req->cons->fd, DIR_RD))
//				rep->rex = TICK_ETERNITY;
//		} else {
//			EV_FD_COND_S(req->cons->fd, DIR_RD);
//			rep->rex = tick_add_ifset(now_ms, t->be->timeout.server);
//		}
//	}
//
//	/* manage write timeout */
//	if (!(req->flags & BF_SHUTW)) {
//		if (req->flags & BF_EMPTY || !(req->flags & BF_MAY_FORWARD)) {
//			/* stop writing */
//			if (EV_FD_COND_C(req->cons->fd, DIR_WR))
//				req->wex = TICK_ETERNITY;
//		} else {
//			/* buffer not empty, there are still data to be transferred */
//			EV_FD_COND_S(req->cons->fd, DIR_WR);
//			if (!tick_isset(req->wex)) {
//				/* restart writing */
//				req->wex = tick_add_ifset(now_ms, t->be->timeout.server);
//				if (!(rep->flags & BF_SHUTR) && tick_isset(req->wex) && tick_isset(rep->rex)) {
//					/* FIXME: to prevent the server from expiring read timeouts during writes,
//					 * we refresh it, except if it was already infinite.
//					 */
//					rep->rex = req->wex;
//				}
//			}
//		}
//	}
//	return 0; /* other cases change nothing */
//}
//

/*
 * Produces data for the session <s> depending on its source. Expects to be
 * called with client socket shut down on input. Right now, only statistics can
 * be produced. It stops by itself by unsetting the SN_SELF_GEN flag from the
 * session, which it uses to keep on being called when there is free space in
 * the buffer, or simply by letting an empty buffer upon return. It returns 1
 * when it wants to stop sending data, otherwise 0.
 */
int produce_content(struct session *s)
{
	if (s->data_source == DATA_SRC_NONE) {
		s->flags &= ~SN_SELF_GEN;
		return 1;
	}
	else if (s->data_source == DATA_SRC_STATS) {
		/* dump server statistics */
		int ret = stats_dump_http(s, s->be->uri_auth);
		if (ret >= 0)
			return ret;
		/* -1 indicates an error */
	}

	/* unknown data source or internal error */
	s->txn.status = 500;
	client_retnclose(s, error_message(s, HTTP_ERR_500));
	trace_term(s, TT_HTTP_CNT_1);
	if (!(s->flags & SN_ERR_MASK))
		s->flags |= SN_ERR_PRXCOND;
	if (!(s->flags & SN_FINST_MASK))
		s->flags |= SN_FINST_R;
	s->flags &= ~SN_SELF_GEN;
	return 1;
}


/* Iterate the same filter through all request headers.
 * Returns 1 if this filter can be stopped upon return, otherwise 0.
 * Since it can manage the switch to another backend, it updates the per-proxy
 * DENY stats.
 */
int apply_filter_to_req_headers(struct session *t, struct buffer *req, struct hdr_exp *exp)
{
	char term;
	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, last_hdr;
	struct http_txn *txn = &t->txn;
	struct hdr_idx_elem *cur_hdr;
	int len, delta;

	last_hdr = 0;

	cur_next = req->data + txn->req.som + hdr_idx_first_pos(&txn->hdr_idx);
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

		/* The annoying part is that pattern matching needs
		 * that we modify the contents to null-terminate all
		 * strings before testing them.
		 */

		term = *cur_end;
		*cur_end = '\0';

		if (regexec(exp->preg, cur_ptr, MAX_MATCH, pmatch, 0) == 0) {
			switch (exp->action) {
			case ACT_SETBE:
				/* It is not possible to jump a second time.
				 * FIXME: should we return an HTTP/500 here so that
				 * the admin knows there's a problem ?
				 */
				if (t->be != t->fe)
					break;

				/* Swithing Proxy */
				t->be = (struct proxy *) exp->replace;

				/* right now, the backend switch is not overly complicated
				 * because we have associated req_cap and rsp_cap to the
				 * frontend, and the beconn will be updated later.
				 */

				t->rep->rto = t->req->wto = t->be->timeout.server;
				t->req->cto = t->be->timeout.connect;
				t->conn_retries = t->be->conn_retries;
				last_hdr = 1;
				break;

			case ACT_ALLOW:
				txn->flags |= TX_CLALLOW;
				last_hdr = 1;
				break;

			case ACT_DENY:
				txn->flags |= TX_CLDENY;
				last_hdr = 1;
				t->be->denied_req++;
				break;

			case ACT_TARPIT:
				txn->flags |= TX_CLTARPIT;
				last_hdr = 1;
				t->be->denied_req++;
				break;

			case ACT_REPLACE:
				len = exp_replace(trash, cur_ptr, exp->replace, pmatch);
				delta = buffer_replace2(req, cur_ptr, cur_end, trash, len);
				/* FIXME: if the user adds a newline in the replacement, the
				 * index will not be recalculated for now, and the new line
				 * will not be counted as a new header.
				 */

				cur_end += delta;
				cur_next += delta;
				cur_hdr->len += delta;
				txn->req.eoh += delta;
				break;

			case ACT_REMOVE:
				delta = buffer_replace2(req, cur_ptr, cur_next, NULL, 0);
				cur_next += delta;

				/* FIXME: this should be a separate function */
				txn->req.eoh += delta;
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_end = NULL; /* null-term has been rewritten */
				break;

			}
		}
		if (cur_end)
			*cur_end = term; /* restore the string terminator */

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
int apply_filter_to_req_line(struct session *t, struct buffer *req, struct hdr_exp *exp)
{
	char term;
	char *cur_ptr, *cur_end;
	int done;
	struct http_txn *txn = &t->txn;
	int len, delta;


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

	cur_ptr = req->data + txn->req.som; /* should be equal to txn->sol */
	cur_end = cur_ptr + txn->req.sl.rq.l;

	/* Now we have the request line between cur_ptr and cur_end */

	/* The annoying part is that pattern matching needs
	 * that we modify the contents to null-terminate all
	 * strings before testing them.
	 */

	term = *cur_end;
	*cur_end = '\0';

	if (regexec(exp->preg, cur_ptr, MAX_MATCH, pmatch, 0) == 0) {
		switch (exp->action) {
		case ACT_SETBE:
			/* It is not possible to jump a second time.
			 * FIXME: should we return an HTTP/500 here so that
			 * the admin knows there's a problem ?
			 */
			if (t->be != t->fe)
				break;

			/* Swithing Proxy */
			t->be = (struct proxy *) exp->replace;

			/* right now, the backend switch is not too much complicated
			 * because we have associated req_cap and rsp_cap to the
			 * frontend, and the beconn will be updated later.
			 */

			t->rep->rto = t->req->wto = t->be->timeout.server;
			t->req->cto = t->be->timeout.connect;
			t->conn_retries = t->be->conn_retries;
			done = 1;
			break;

		case ACT_ALLOW:
			txn->flags |= TX_CLALLOW;
			done = 1;
			break;

		case ACT_DENY:
			txn->flags |= TX_CLDENY;
			t->be->denied_req++;
			done = 1;
			break;

		case ACT_TARPIT:
			txn->flags |= TX_CLTARPIT;
			t->be->denied_req++;
			done = 1;
			break;

		case ACT_REPLACE:
			*cur_end = term; /* restore the string terminator */
			len = exp_replace(trash, cur_ptr, exp->replace, pmatch);
			delta = buffer_replace2(req, cur_ptr, cur_end, trash, len);
			/* FIXME: if the user adds a newline in the replacement, the
			 * index will not be recalculated for now, and the new line
			 * will not be counted as a new header.
			 */

			txn->req.eoh += delta;
			cur_end += delta;

			txn->req.sol = req->data + txn->req.som; /* should be equal to txn->sol */
			cur_end = (char *)http_parse_reqline(&txn->req, req->data,
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
	*cur_end = term; /* restore the string terminator */
	return done;
}



/*
 * Apply all the req filters <exp> to all headers in buffer <req> of session <t>.
 * Returns 0 if everything is alright, or -1 in case a replacement lead to an
 * unparsable request. Since it can manage the switch to another backend, it
 * updates the per-proxy DENY stats.
 */
int apply_filters_to_request(struct session *t, struct buffer *req, struct hdr_exp *exp)
{
	struct http_txn *txn = &t->txn;
	/* iterate through the filters in the outer loop */
	while (exp && !(txn->flags & (TX_CLDENY|TX_CLTARPIT))) {
		int ret;

		/*
		 * The interleaving of transformations and verdicts
		 * makes it difficult to decide to continue or stop
		 * the evaluation.
		 */

		if ((txn->flags & TX_CLALLOW) &&
		    (exp->action == ACT_ALLOW || exp->action == ACT_DENY ||
		     exp->action == ACT_TARPIT || exp->action == ACT_PASS)) {
			exp = exp->next;
			continue;
		}

		/* Apply the filter to the request line. */
		ret = apply_filter_to_req_line(t, req, exp);
		if (unlikely(ret < 0))
			return -1;

		if (likely(ret == 0)) {
			/* The filter did not match the request, it can be
			 * iterated through all headers.
			 */
			apply_filter_to_req_headers(t, req, exp);
		}
		exp = exp->next;
	}
	return 0;
}



/*
 * Manage client-side cookie. It can impact performance by about 2% so it is
 * desirable to call it only when needed.
 */
void manage_client_side_cookies(struct session *t, struct buffer *req)
{
	struct http_txn *txn = &t->txn;
	char *p1, *p2, *p3, *p4;
	char *del_colon, *del_cookie, *colon;
	int app_cookies;

	appsess *asession_temp = NULL;
	appsess local_asession;

	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx;

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	old_idx = 0;
	cur_next = req->data + txn->req.som + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next. We're only interested in
		 * "Cookie:" headers.
		 */

		val = http_header_match2(cur_ptr, cur_end, "Cookie", 6);
		if (!val) {
			old_idx = cur_idx;
			continue;
		}

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
		 * *MUST* delete it
		 */

		colon = p1 = cur_ptr + val; /* first non-space char after 'Cookie:' */

		/* del_cookie == NULL => nothing to be deleted */
		del_colon = del_cookie = NULL;
		app_cookies = 0;
		
		while (p1 < cur_end) {
			/* skip spaces and colons, but keep an eye on these ones */
			while (p1 < cur_end) {
				if (*p1 == ';' || *p1 == ',')
					colon = p1;
				else if (!isspace((unsigned char)*p1))
					break;
				p1++;
			}

			if (p1 == cur_end)
				break;
		    
			/* p1 is at the beginning of the cookie name */
			p2 = p1;
			while (p2 < cur_end && *p2 != '=')
				p2++;

			if (p2 == cur_end)
				break;

			p3 = p2 + 1; /* skips the '=' sign */
			if (p3 == cur_end)
				break;
		    
			p4 = p3;
			while (p4 < cur_end && !isspace((unsigned char)*p4) && *p4 != ';' && *p4 != ',')
				p4++;

			/* here, we have the cookie name between p1 and p2,
			 * and its value between p3 and p4.
			 * we can process it :
			 *
			 * Cookie: NAME=VALUE;
			 * |      ||   ||    |
			 * |      ||   ||    +--> p4
			 * |      ||   |+-------> p3
			 * |      ||   +--------> p2
			 * |      |+------------> p1
			 * |      +-------------> colon
			 * +--------------------> cur_ptr
			 */
		    
			if (*p1 == '$') {
				/* skip this one */
			}
			else {
				/* first, let's see if we want to capture it */
				if (t->fe->capture_name != NULL &&
				    txn->cli_cookie == NULL &&
				    (p4 - p1 >= t->fe->capture_namelen) &&
				    memcmp(p1, t->fe->capture_name, t->fe->capture_namelen) == 0) {
					int log_len = p4 - p1;

					if ((txn->cli_cookie = pool_alloc2(pool2_capture)) == NULL) {
						Alert("HTTP logging : out of memory.\n");
					} else {
						if (log_len > t->fe->capture_len)
							log_len = t->fe->capture_len;
						memcpy(txn->cli_cookie, p1, log_len);
						txn->cli_cookie[log_len] = 0;
					}
				}

				if ((p2 - p1 == t->be->cookie_len) && (t->be->cookie_name != NULL) &&
				    (memcmp(p1, t->be->cookie_name, p2 - p1) == 0)) {
					/* Cool... it's the right one */
					struct server *srv = t->be->srv;
					char *delim;

					/* if we're in cookie prefix mode, we'll search the delimitor so that we
					 * have the server ID betweek p3 and delim, and the original cookie between
					 * delim+1 and p4. Otherwise, delim==p4 :
					 *
					 * Cookie: NAME=SRV~VALUE;
					 * |      ||   ||  |     |
					 * |      ||   ||  |     +--> p4
					 * |      ||   ||  +--------> delim
					 * |      ||   |+-----------> p3
					 * |      ||   +------------> p2
					 * |      |+----------------> p1
					 * |      +-----------------> colon
					 * +------------------------> cur_ptr
					 */

					if (t->be->options & PR_O_COOK_PFX) {
						for (delim = p3; delim < p4; delim++)
							if (*delim == COOKIE_DELIM)
								break;
					}
					else
						delim = p4;


					/* Here, we'll look for the first running server which supports the cookie.
					 * This allows to share a same cookie between several servers, for example
					 * to dedicate backup servers to specific servers only.
					 * However, to prevent clients from sticking to cookie-less backup server
					 * when they have incidentely learned an empty cookie, we simply ignore
					 * empty cookies and mark them as invalid.
					 */
					if (delim == p3)
						srv = NULL;

					while (srv) {
						if (srv->cookie && (srv->cklen == delim - p3) &&
						    !memcmp(p3, srv->cookie, delim - p3)) {
							if (srv->state & SRV_RUNNING || t->be->options & PR_O_PERSIST) {
								/* we found the server and it's usable */
								txn->flags &= ~TX_CK_MASK;
								txn->flags |= TX_CK_VALID;
								t->flags |= SN_DIRECT | SN_ASSIGNED;
								t->srv = srv;
								break;
							} else {
								/* we found a server, but it's down */
								txn->flags &= ~TX_CK_MASK;
								txn->flags |= TX_CK_DOWN;
							}
						}
						srv = srv->next;
					}

					if (!srv && !(txn->flags & TX_CK_DOWN)) {
						/* no server matched this cookie */
						txn->flags &= ~TX_CK_MASK;
						txn->flags |= TX_CK_INVALID;
					}

					/* depending on the cookie mode, we may have to either :
					 * - delete the complete cookie if we're in insert+indirect mode, so that
					 *   the server never sees it ;
					 * - remove the server id from the cookie value, and tag the cookie as an
					 *   application cookie so that it does not get accidentely removed later,
					 *   if we're in cookie prefix mode
					 */
					if ((t->be->options & PR_O_COOK_PFX) && (delim != p4)) {
						int delta; /* negative */

						delta = buffer_replace2(req, p3, delim + 1, NULL, 0);
						p4  += delta;
						cur_end += delta;
						cur_next += delta;
						cur_hdr->len += delta;
						txn->req.eoh += delta;

						del_cookie = del_colon = NULL;
						app_cookies++;	/* protect the header from deletion */
					}
					else if (del_cookie == NULL &&
						 (t->be->options & (PR_O_COOK_INS | PR_O_COOK_IND)) == (PR_O_COOK_INS | PR_O_COOK_IND)) {
						del_cookie = p1;
						del_colon = colon;
					}
				} else {
					/* now we know that we must keep this cookie since it's
					 * not ours. But if we wanted to delete our cookie
					 * earlier, we cannot remove the complete header, but we
					 * can remove the previous block itself.
					 */
					app_cookies++;

					if (del_cookie != NULL) {
						int delta; /* negative */

						delta = buffer_replace2(req, del_cookie, p1, NULL, 0);
						p4  += delta;
						cur_end += delta;
						cur_next += delta;
						cur_hdr->len += delta;
						txn->req.eoh += delta;
						del_cookie = del_colon = NULL;
					}
				}

				if ((t->be->appsession_name != NULL) &&
				    (memcmp(p1, t->be->appsession_name, p2 - p1) == 0)) {
					/* first, let's see if the cookie is our appcookie*/

					/* Cool... it's the right one */

					asession_temp = &local_asession;
			  
					if ((asession_temp->sessid = pool_alloc2(apools.sessid)) == NULL) {
						Alert("Not enough memory process_cli():asession->sessid:malloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession->sessid:malloc().\n");
						return;
					}

					memcpy(asession_temp->sessid, p3, t->be->appsession_len);
					asession_temp->sessid[t->be->appsession_len] = 0;
					asession_temp->serverid = NULL;

					/* only do insert, if lookup fails */
					asession_temp = appsession_hash_lookup(&(t->be->htbl_proxy), asession_temp->sessid);
					if (asession_temp == NULL) {
						if ((asession_temp = pool_alloc2(pool2_appsess)) == NULL) {
							/* free previously allocated memory */
							pool_free2(apools.sessid, local_asession.sessid);
							Alert("Not enough memory process_cli():asession:calloc().\n");
							send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
							return;
						}

						asession_temp->sessid = local_asession.sessid;
						asession_temp->serverid = local_asession.serverid;
						asession_temp->request_count = 0;
						appsession_hash_insert(&(t->be->htbl_proxy), asession_temp);
					} else {
						/* free previously allocated memory */
						pool_free2(apools.sessid, local_asession.sessid);
					}
					if (asession_temp->serverid == NULL) {
						/* TODO redispatch request */
						Alert("Found Application Session without matching server.\n");
					} else {
						struct server *srv = t->be->srv;
						while (srv) {
							if (strcmp(srv->id, asession_temp->serverid) == 0) {
								if (srv->state & SRV_RUNNING || t->be->options & PR_O_PERSIST) {
									/* we found the server and it's usable */
									txn->flags &= ~TX_CK_MASK;
									txn->flags |= TX_CK_VALID;
									t->flags |= SN_DIRECT | SN_ASSIGNED;
									t->srv = srv;
									break;
								} else {
									txn->flags &= ~TX_CK_MASK;
									txn->flags |= TX_CK_DOWN;
								}
							}
							srv = srv->next;
						}/* end while(srv) */
					}/* end else if server == NULL */

					asession_temp->expire = tick_add_ifset(now_ms, t->be->timeout.appsession);
					asession_temp->request_count++;
#if defined(DEBUG_HASH)
					Alert("manage_client_side_cookies\n");
					appsession_hash_dump(&(t->be->htbl_proxy));
#endif
				}/* end if ((t->proxy->appsession_name != NULL) ... */
			}

			/* we'll have to look for another cookie ... */
			p1 = p4;
		} /* while (p1 < cur_end) */

		/* There's no more cookie on this line.
		 * We may have marked the last one(s) for deletion.
		 * We must do this now in two ways :
		 *  - if there is no app cookie, we simply delete the header ;
		 *  - if there are app cookies, we must delete the end of the
		 *    string properly, including the colon/semi-colon before
		 *    the cookie name.
		 */
		if (del_cookie != NULL) {
			int delta;
			if (app_cookies) {
				delta = buffer_replace2(req, del_colon, cur_end, NULL, 0);
				cur_end = del_colon;
				cur_hdr->len += delta;
			} else {
				delta = buffer_replace2(req, cur_ptr, cur_next, NULL, 0);

				/* FIXME: this should be a separate function */
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
			}
			cur_next += delta;
			txn->req.eoh += delta;
		}

		/* keep the link from this header to next one */
		old_idx = cur_idx;
	} /* end of cookie processing on this header */
}


/* Iterate the same filter through all response headers contained in <rtr>.
 * Returns 1 if this filter can be stopped upon return, otherwise 0.
 */
int apply_filter_to_resp_headers(struct session *t, struct buffer *rtr, struct hdr_exp *exp)
{
	char term;
	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, last_hdr;
	struct http_txn *txn = &t->txn;
	struct hdr_idx_elem *cur_hdr;
	int len, delta;

	last_hdr = 0;

	cur_next = rtr->data + txn->rsp.som + hdr_idx_first_pos(&txn->hdr_idx);
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

		/* The annoying part is that pattern matching needs
		 * that we modify the contents to null-terminate all
		 * strings before testing them.
		 */

		term = *cur_end;
		*cur_end = '\0';

		if (regexec(exp->preg, cur_ptr, MAX_MATCH, pmatch, 0) == 0) {
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
				len = exp_replace(trash, cur_ptr, exp->replace, pmatch);
				delta = buffer_replace2(rtr, cur_ptr, cur_end, trash, len);
				/* FIXME: if the user adds a newline in the replacement, the
				 * index will not be recalculated for now, and the new line
				 * will not be counted as a new header.
				 */

				cur_end += delta;
				cur_next += delta;
				cur_hdr->len += delta;
				txn->rsp.eoh += delta;
				break;

			case ACT_REMOVE:
				delta = buffer_replace2(rtr, cur_ptr, cur_next, NULL, 0);
				cur_next += delta;

				/* FIXME: this should be a separate function */
				txn->rsp.eoh += delta;
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_end = NULL; /* null-term has been rewritten */
				break;

			}
		}
		if (cur_end)
			*cur_end = term; /* restore the string terminator */

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
int apply_filter_to_sts_line(struct session *t, struct buffer *rtr, struct hdr_exp *exp)
{
	char term;
	char *cur_ptr, *cur_end;
	int done;
	struct http_txn *txn = &t->txn;
	int len, delta;


	if (unlikely(txn->flags & TX_SVDENY))
		return 1;
	else if (unlikely(txn->flags & TX_SVALLOW) &&
		 (exp->action == ACT_ALLOW ||
		  exp->action == ACT_DENY))
		return 0;
	else if (exp->action == ACT_REMOVE)
		return 0;

	done = 0;

	cur_ptr = rtr->data + txn->rsp.som; /* should be equal to txn->sol */
	cur_end = cur_ptr + txn->rsp.sl.rq.l;

	/* Now we have the status line between cur_ptr and cur_end */

	/* The annoying part is that pattern matching needs
	 * that we modify the contents to null-terminate all
	 * strings before testing them.
	 */

	term = *cur_end;
	*cur_end = '\0';

	if (regexec(exp->preg, cur_ptr, MAX_MATCH, pmatch, 0) == 0) {
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
			*cur_end = term; /* restore the string terminator */
			len = exp_replace(trash, cur_ptr, exp->replace, pmatch);
			delta = buffer_replace2(rtr, cur_ptr, cur_end, trash, len);
			/* FIXME: if the user adds a newline in the replacement, the
			 * index will not be recalculated for now, and the new line
			 * will not be counted as a new header.
			 */

			txn->rsp.eoh += delta;
			cur_end += delta;

			txn->rsp.sol = rtr->data + txn->rsp.som; /* should be equal to txn->sol */
			cur_end = (char *)http_parse_stsline(&txn->rsp, rtr->data,
							     HTTP_MSG_RPVER,
							     cur_ptr, cur_end + 1,
							     NULL, NULL);
			if (unlikely(!cur_end))
				return -1;

			/* we have a full respnse and we know that we have either a CR
			 * or an LF at <ptr>.
			 */
			txn->status = strl2ui(rtr->data + txn->rsp.sl.st.c, txn->rsp.sl.st.c_l);
			hdr_idx_set_start(&txn->hdr_idx, txn->rsp.sl.rq.l, *cur_end == '\r');
			/* there is no point trying this regex on headers */
			return 1;
		}
	}
	*cur_end = term; /* restore the string terminator */
	return done;
}



/*
 * Apply all the resp filters <exp> to all headers in buffer <rtr> of session <t>.
 * Returns 0 if everything is alright, or -1 in case a replacement lead to an
 * unparsable response.
 */
int apply_filters_to_response(struct session *t, struct buffer *rtr, struct hdr_exp *exp)
{
	struct http_txn *txn = &t->txn;
	/* iterate through the filters in the outer loop */
	while (exp && !(txn->flags & TX_SVDENY)) {
		int ret;

		/*
		 * The interleaving of transformations and verdicts
		 * makes it difficult to decide to continue or stop
		 * the evaluation.
		 */

		if ((txn->flags & TX_SVALLOW) &&
		    (exp->action == ACT_ALLOW || exp->action == ACT_DENY ||
		     exp->action == ACT_PASS)) {
			exp = exp->next;
			continue;
		}

		/* Apply the filter to the status line. */
		ret = apply_filter_to_sts_line(t, rtr, exp);
		if (unlikely(ret < 0))
			return -1;

		if (likely(ret == 0)) {
			/* The filter did not match the response, it can be
			 * iterated through all headers.
			 */
			apply_filter_to_resp_headers(t, rtr, exp);
		}
		exp = exp->next;
	}
	return 0;
}



/*
 * Manage server-side cookies. It can impact performance by about 2% so it is
 * desirable to call it only when needed.
 */
void manage_server_side_cookies(struct session *t, struct buffer *rtr)
{
	struct http_txn *txn = &t->txn;
	char *p1, *p2, *p3, *p4;

	appsess *asession_temp = NULL;
	appsess local_asession;

	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, delta;

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	old_idx = 0;
	cur_next = rtr->data + txn->rsp.som + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next. We're only interested in
		 * "Cookie:" headers.
		 */

		val = http_header_match2(cur_ptr, cur_end, "Set-Cookie", 10);
		if (!val) {
			old_idx = cur_idx;
			continue;
		}

		/* OK, right now we know we have a set-cookie at cur_ptr */
		txn->flags |= TX_SCK_ANY;


		/* maybe we only wanted to see if there was a set-cookie */
		if (t->be->cookie_name == NULL &&
		    t->be->appsession_name == NULL &&
		    t->be->capture_name == NULL)
			return;

		p1 = cur_ptr + val; /* first non-space char after 'Set-Cookie:' */
		
		while (p1 < cur_end) { /* in fact, we'll break after the first cookie */
			if (p1 == cur_end || *p1 == ';') /* end of cookie */
				break;

			/* p1 is at the beginning of the cookie name */
			p2 = p1;

			while (p2 < cur_end && *p2 != '=' && *p2 != ';')
				p2++;

			if (p2 == cur_end || *p2 == ';') /* next cookie */
				break;

			p3 = p2 + 1; /* skip the '=' sign */
			if (p3 == cur_end)
				break;

			p4 = p3;
			while (p4 < cur_end && !isspace((unsigned char)*p4) && *p4 != ';')
				p4++;

			/* here, we have the cookie name between p1 and p2,
			 * and its value between p3 and p4.
			 * we can process it.
			 */

			/* first, let's see if we want to capture it */
			if (t->be->capture_name != NULL &&
			    txn->srv_cookie == NULL &&
			    (p4 - p1 >= t->be->capture_namelen) &&
			    memcmp(p1, t->be->capture_name, t->be->capture_namelen) == 0) {
				int log_len = p4 - p1;

				if ((txn->srv_cookie = pool_alloc2(pool2_capture)) == NULL) {
					Alert("HTTP logging : out of memory.\n");
				}

				if (log_len > t->be->capture_len)
					log_len = t->be->capture_len;
				memcpy(txn->srv_cookie, p1, log_len);
				txn->srv_cookie[log_len] = 0;
			}

			/* now check if we need to process it for persistence */
			if ((p2 - p1 == t->be->cookie_len) && (t->be->cookie_name != NULL) &&
			    (memcmp(p1, t->be->cookie_name, p2 - p1) == 0)) {
				/* Cool... it's the right one */
				txn->flags |= TX_SCK_SEEN;
			
				/* If the cookie is in insert mode on a known server, we'll delete
				 * this occurrence because we'll insert another one later.
				 * We'll delete it too if the "indirect" option is set and we're in
				 * a direct access. */
				if (((t->srv) && (t->be->options & PR_O_COOK_INS)) ||
				    ((t->flags & SN_DIRECT) && (t->be->options & PR_O_COOK_IND))) {
					/* this header must be deleted */
					delta = buffer_replace2(rtr, cur_ptr, cur_next, NULL, 0);
					txn->hdr_idx.v[old_idx].next = cur_hdr->next;
					txn->hdr_idx.used--;
					cur_hdr->len = 0;
					cur_next += delta;
					txn->rsp.eoh += delta;

					txn->flags |= TX_SCK_DELETED;
				}
				else if ((t->srv) && (t->srv->cookie) &&
					 (t->be->options & PR_O_COOK_RW)) {
					/* replace bytes p3->p4 with the cookie name associated
					 * with this server since we know it.
					 */
					delta = buffer_replace2(rtr, p3, p4, t->srv->cookie, t->srv->cklen);
					cur_hdr->len += delta;
					cur_next += delta;
					txn->rsp.eoh += delta;

					txn->flags |= TX_SCK_INSERTED | TX_SCK_DELETED;
				}
				else if ((t->srv) && (t->srv->cookie) &&
					 (t->be->options & PR_O_COOK_PFX)) {
					/* insert the cookie name associated with this server
					 * before existing cookie, and insert a delimitor between them..
					 */
					delta = buffer_replace2(rtr, p3, p3, t->srv->cookie, t->srv->cklen + 1);
					cur_hdr->len += delta;
					cur_next += delta;
					txn->rsp.eoh += delta;

					p3[t->srv->cklen] = COOKIE_DELIM;
					txn->flags |= TX_SCK_INSERTED | TX_SCK_DELETED;
				}
			}
			/* next, let's see if the cookie is our appcookie */
			else if ((t->be->appsession_name != NULL) &&
			         (memcmp(p1, t->be->appsession_name, p2 - p1) == 0)) {

				/* Cool... it's the right one */

				size_t server_id_len = strlen(t->srv->id) + 1;
				asession_temp = &local_asession;
		      
				if ((asession_temp->sessid = pool_alloc2(apools.sessid)) == NULL) {
					Alert("Not enough Memory process_srv():asession->sessid:malloc().\n");
					send_log(t->be, LOG_ALERT, "Not enough Memory process_srv():asession->sessid:malloc().\n");
					return;
				}
				memcpy(asession_temp->sessid, p3, t->be->appsession_len);
				asession_temp->sessid[t->be->appsession_len] = 0;
				asession_temp->serverid = NULL;

				/* only do insert, if lookup fails */
				asession_temp = appsession_hash_lookup(&(t->be->htbl_proxy), asession_temp->sessid);
				if (asession_temp == NULL) {
					if ((asession_temp = pool_alloc2(pool2_appsess)) == NULL) {
						Alert("Not enough Memory process_srv():asession:calloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough Memory process_srv():asession:calloc().\n");
						return;
					}
					asession_temp->sessid = local_asession.sessid;
					asession_temp->serverid = local_asession.serverid;
					asession_temp->request_count = 0;
					appsession_hash_insert(&(t->be->htbl_proxy), asession_temp);
				} else {
					/* free wasted memory */
					pool_free2(apools.sessid, local_asession.sessid);
				}

				if (asession_temp->serverid == NULL) {
					if ((asession_temp->serverid = pool_alloc2(apools.serverid)) == NULL) {
						Alert("Not enough Memory process_srv():asession->sessid:malloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough Memory process_srv():asession->sessid:malloc().\n");
						return;
					}
					asession_temp->serverid[0] = '\0';
				}
		      
				if (asession_temp->serverid[0] == '\0')
					memcpy(asession_temp->serverid, t->srv->id, server_id_len);
		      
				asession_temp->expire = tick_add_ifset(now_ms, t->be->timeout.appsession);
				asession_temp->request_count++;
#if defined(DEBUG_HASH)
				Alert("manage_server_side_cookies\n");
				appsession_hash_dump(&(t->be->htbl_proxy));
#endif
			}/* end if ((t->proxy->appsession_name != NULL) ... */
			break; /* we don't want to loop again since there cannot be another cookie on the same line */
		} /* we're now at the end of the cookie value */

		/* keep the link from this header to next one */
		old_idx = cur_idx;
	} /* end of cookie processing on this header */
}



/*
 * Check if response is cacheable or not. Updates t->flags.
 */
void check_response_for_cacheability(struct session *t, struct buffer *rtr)
{
	struct http_txn *txn = &t->txn;
	char *p1, *p2;

	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx;

	if (!(txn->flags & TX_CACHEABLE))
		return;

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	cur_idx = 0;
	cur_next = rtr->data + txn->rsp.som + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[cur_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next. We're only interested in
		 * "Cookie:" headers.
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
			/* we have something of the form no-cache="set-cookie" */
			if ((cur_end - p1 >= 21) &&
			    strncasecmp(p1, "no-cache=\"set-cookie", 20) == 0
			    && (p1[20] == '"' || p1[20] == ','))
				txn->flags &= ~TX_CACHE_COOK;
			continue;
		}

		/* OK, so we know that either p2 points to the end of string or to a comma */
		if (((p2 - p1 ==  7) && strncasecmp(p1, "private", 7) == 0) ||
		    ((p2 - p1 ==  8) && strncasecmp(p1, "no-store", 8) == 0) ||
		    ((p2 - p1 ==  9) && strncasecmp(p1, "max-age=0", 9) == 0) ||
		    ((p2 - p1 == 10) && strncasecmp(p1, "s-maxage=0", 10) == 0)) {
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
 * Try to retrieve a known appsession in the URI, then the associated server.
 * If the server is found, it's assigned to the session.
 */
void get_srv_from_appsession(struct session *t, const char *begin, int len)
{
	struct http_txn *txn = &t->txn;
	appsess *asession_temp = NULL;
	appsess local_asession;
	char *request_line;

	if (t->be->appsession_name == NULL ||
	    (t->txn.meth != HTTP_METH_GET && t->txn.meth != HTTP_METH_POST) ||
	    (request_line = memchr(begin, ';', len)) == NULL ||
	    ((1 + t->be->appsession_name_len + 1 + t->be->appsession_len) > (begin + len - request_line)))
		return;

	/* skip ';' */
	request_line++;

	/* look if we have a jsessionid */
	if (strncasecmp(request_line, t->be->appsession_name, t->be->appsession_name_len) != 0)
		return;

	/* skip jsessionid= */
	request_line += t->be->appsession_name_len + 1;
	
	/* First try if we already have an appsession */
	asession_temp = &local_asession;
	
	if ((asession_temp->sessid = pool_alloc2(apools.sessid)) == NULL) {
		Alert("Not enough memory process_cli():asession_temp->sessid:calloc().\n");
		send_log(t->be, LOG_ALERT, "Not enough Memory process_cli():asession_temp->sessid:calloc().\n");
		return;
	}
	
	/* Copy the sessionid */
	memcpy(asession_temp->sessid, request_line, t->be->appsession_len);
	asession_temp->sessid[t->be->appsession_len] = 0;
	asession_temp->serverid = NULL;
	
	/* only do insert, if lookup fails */
	asession_temp = appsession_hash_lookup(&(t->be->htbl_proxy), asession_temp->sessid);
	if (asession_temp == NULL) {
		if ((asession_temp = pool_alloc2(pool2_appsess)) == NULL) {
			/* free previously allocated memory */
			pool_free2(apools.sessid, local_asession.sessid);
			Alert("Not enough memory process_cli():asession:calloc().\n");
			send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
			return;
		}
		asession_temp->sessid = local_asession.sessid;
		asession_temp->serverid = local_asession.serverid;
		asession_temp->request_count=0;
		appsession_hash_insert(&(t->be->htbl_proxy), asession_temp);
	}
	else {
		/* free previously allocated memory */
		pool_free2(apools.sessid, local_asession.sessid);
	}

	asession_temp->expire = tick_add_ifset(now_ms, t->be->timeout.appsession);
	asession_temp->request_count++;

#if defined(DEBUG_HASH)
	Alert("get_srv_from_appsession\n");
	appsession_hash_dump(&(t->be->htbl_proxy));
#endif
	if (asession_temp->serverid == NULL) {
		/* TODO redispatch request */
		Alert("Found Application Session without matching server.\n");
	} else {
		struct server *srv = t->be->srv;
		while (srv) {
			if (strcmp(srv->id, asession_temp->serverid) == 0) {
				if (srv->state & SRV_RUNNING || t->be->options & PR_O_PERSIST) {
					/* we found the server and it's usable */
					txn->flags &= ~TX_CK_MASK;
					txn->flags |= TX_CK_VALID;
					t->flags |= SN_DIRECT | SN_ASSIGNED;
					t->srv = srv;
					break;
				} else {
					txn->flags &= ~TX_CK_MASK;
					txn->flags |= TX_CK_DOWN;
				}
			}
			srv = srv->next;
		}
	}
}


/*
 * In a GET or HEAD request, check if the requested URI matches the stats uri
 * for the current backend, and if an authorization has been passed and is valid.
 *
 * It is assumed that the request is either a HEAD or GET and that the
 * t->be->uri_auth field is valid. An HTTP/401 response may be sent, or
 * produce_content() can be called to start sending data.
 *
 * Returns 1 if the session's state changes, otherwise 0.
 */
int stats_check_uri_auth(struct session *t, struct proxy *backend)
{
	struct http_txn *txn = &t->txn;
	struct uri_auth *uri_auth = backend->uri_auth;
	struct user_auth *user;
	int authenticated, cur_idx;
	char *h;

	memset(&t->data_ctx.stats, 0, sizeof(t->data_ctx.stats));

	/* check URI size */
	if (uri_auth->uri_len > txn->req.sl.rq.u_l)
		return 0;

	h = t->req->data + txn->req.sl.rq.u;

	/* the URI is in h */
	if (memcmp(h, uri_auth->uri_prefix, uri_auth->uri_len) != 0)
		return 0;

	h += uri_auth->uri_len;
	while (h <= t->req->data + txn->req.sl.rq.u + txn->req.sl.rq.u_l - 3) {
		if (memcmp(h, ";up", 3) == 0) {
			t->data_ctx.stats.flags |= STAT_HIDE_DOWN;
			break;
		}
		h++;
	}

	if (uri_auth->refresh) {
		h = t->req->data + txn->req.sl.rq.u + uri_auth->uri_len;
		while (h <= t->req->data + txn->req.sl.rq.u + txn->req.sl.rq.u_l - 10) {
			if (memcmp(h, ";norefresh", 10) == 0) {
				t->data_ctx.stats.flags |= STAT_NO_REFRESH;
				break;
			}
			h++;
		}
	}

	h = t->req->data + txn->req.sl.rq.u + uri_auth->uri_len;
	while (h <= t->req->data + txn->req.sl.rq.u + txn->req.sl.rq.u_l - 4) {
		if (memcmp(h, ";csv", 4) == 0) {
			t->data_ctx.stats.flags |= STAT_FMT_CSV;
			break;
		}
		h++;
	}

	t->data_ctx.stats.flags |= STAT_SHOW_STAT | STAT_SHOW_INFO;

	/* we are in front of a interceptable URI. Let's check
	 * if there's an authentication and if it's valid.
	 */
	user = uri_auth->users;
	if (!user) {
		/* no user auth required, it's OK */
		authenticated = 1;
	} else {
		authenticated = 0;

		/* a user list is defined, we have to check.
		 * skip 21 chars for "Authorization: Basic ".
		 */

		/* FIXME: this should move to an earlier place */
		cur_idx = 0;
		h = t->req->data + txn->req.som + hdr_idx_first_pos(&txn->hdr_idx);
		while ((cur_idx = txn->hdr_idx.v[cur_idx].next)) {
			int len = txn->hdr_idx.v[cur_idx].len;
			if (len > 14 &&
			    !strncasecmp("Authorization:", h, 14)) {
				txn->auth_hdr.str = h;
				txn->auth_hdr.len = len;
				break;
			}
			h += len + txn->hdr_idx.v[cur_idx].cr + 1;
		}

		if (txn->auth_hdr.len < 21 ||
		    memcmp(txn->auth_hdr.str + 14, " Basic ", 7))
			user = NULL;

		while (user) {
			if ((txn->auth_hdr.len == user->user_len + 14 + 7)
			    && !memcmp(txn->auth_hdr.str + 14 + 7,
				       user->user_pwd, user->user_len)) {
				authenticated = 1;
				break;
			}
			user = user->next;
		}
	}

	if (!authenticated) {
		struct chunk msg;

		/* no need to go further */
		msg.str = trash;
		msg.len = sprintf(trash, HTTP_401_fmt, uri_auth->auth_realm);
		txn->status = 401;
		client_retnclose(t, &msg);
		trace_term(t, TT_HTTP_URI_1);
		t->req->analysers = 0;
		if (!(t->flags & SN_ERR_MASK))
			t->flags |= SN_ERR_PRXCOND;
		if (!(t->flags & SN_FINST_MASK))
			t->flags |= SN_FINST_R;
		return 1;
	}

	/* The request is valid, the user is authenticated. Let's start sending
	 * data.
	 */
	EV_FD_CLR(t->cli_fd, DIR_RD);
	buffer_shutr(t->req);
	buffer_shutr(t->rep);
	buffer_set_rlim(t->req, BUFSIZE); /* no more rewrite needed */
	t->logs.tv_request = now;
	t->data_source = DATA_SRC_STATS;
	t->data_state  = DATA_ST_INIT;
	t->task->nice = -32; /* small boost for HTTP statistics */
	produce_content(t);
	return 1;
}


/*
 * Print a debug line with a header
 */
void debug_hdr(const char *dir, struct session *t, const char *start, const char *end)
{
	int len, max;
	len = sprintf(trash, "%08x:%s.%s[%04x:%04x]: ", t->uniq_id, t->be->id,
		      dir, (unsigned  short)t->cli_fd, (unsigned short)t->req->cons->fd);
	max = end - start;
	UBOUND(max, sizeof(trash) - len - 1);
	len += strlcpy2(trash + len, start, max + 1);
	trash[len++] = '\n';
	write(1, trash, len);
}


/************************************************************************/
/*        The code below is dedicated to ACL parsing and matching       */
/************************************************************************/




/* 1. Check on METHOD
 * We use the pre-parsed method if it is known, and store its number as an
 * integer. If it is unknown, we use the pointer and the length.
 */
static int acl_parse_meth(const char **text, struct acl_pattern *pattern, int *opaque)
{
	int len, meth;

	len  = strlen(*text);
	meth = find_http_meth(*text, len);

	pattern->val.i = meth;
	if (meth == HTTP_METH_OTHER) {
		pattern->ptr.str = strdup(*text);
		if (!pattern->ptr.str)
			return 0;
		pattern->len = len;
	}
	return 1;
}

static int
acl_fetch_meth(struct proxy *px, struct session *l4, void *l7, int dir,
               struct acl_expr *expr, struct acl_test *test)
{
	int meth;
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	meth = txn->meth;
	test->i = meth;
	if (meth == HTTP_METH_OTHER) {
		if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
			/* ensure the indexes are not affected */
			return 0;
		test->len = txn->req.sl.rq.m_l;
		test->ptr = txn->req.sol;
	}
	test->flags = ACL_TEST_F_READ_ONLY | ACL_TEST_F_VOL_1ST;
	return 1;
}

static int acl_match_meth(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;

	if (test->i != pattern->val.i)
		return ACL_PAT_FAIL;

	if (test->i != HTTP_METH_OTHER)
		return ACL_PAT_PASS;

	/* Other method, we must compare the strings */
	if (pattern->len != test->len)
		return ACL_PAT_FAIL;

	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, test->ptr, test->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, test->ptr, test->len) != 0))
		return ACL_PAT_FAIL;
	return ACL_PAT_PASS;
}

/* 2. Check on Request/Status Version
 * We simply compare strings here.
 */
static int acl_parse_ver(const char **text, struct acl_pattern *pattern, int *opaque)
{
	pattern->ptr.str = strdup(*text);
	if (!pattern->ptr.str)
		return 0;
	pattern->len = strlen(*text);
	return 1;
}

static int
acl_fetch_rqver(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;
	char *ptr;
	int len;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	len = txn->req.sl.rq.v_l;
	ptr = txn->req.sol + txn->req.sl.rq.v - txn->req.som;

	while ((len-- > 0) && (*ptr++ != '/'));
	if (len <= 0)
		return 0;

	test->ptr = ptr;
	test->len = len;

	test->flags = ACL_TEST_F_READ_ONLY | ACL_TEST_F_VOL_1ST;
	return 1;
}

static int
acl_fetch_stver(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;
	char *ptr;
	int len;

	if (!txn)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_BODY)
		return 0;

	len = txn->rsp.sl.st.v_l;
	ptr = txn->rsp.sol;

	while ((len-- > 0) && (*ptr++ != '/'));
	if (len <= 0)
		return 0;

	test->ptr = ptr;
	test->len = len;

	test->flags = ACL_TEST_F_READ_ONLY | ACL_TEST_F_VOL_1ST;
	return 1;
}

/* 3. Check on Status Code. We manipulate integers here. */
static int
acl_fetch_stcode(struct proxy *px, struct session *l4, void *l7, int dir,
                 struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;
	char *ptr;
	int len;

	if (!txn)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_BODY)
		return 0;

	len = txn->rsp.sl.st.c_l;
	ptr = txn->rsp.sol + txn->rsp.sl.st.c - txn->rsp.som;

	test->i = __strl2ui(ptr, len);
	test->flags = ACL_TEST_F_VOL_1ST;
	return 1;
}

/* 4. Check on URL/URI. A pointer to the URI is stored. */
static int
acl_fetch_url(struct proxy *px, struct session *l4, void *l7, int dir,
              struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
		/* ensure the indexes are not affected */
		return 0;

	test->len = txn->req.sl.rq.u_l;
	test->ptr = txn->req.sol + txn->req.sl.rq.u;

	/* we do not need to set READ_ONLY because the data is in a buffer */
	test->flags = ACL_TEST_F_VOL_1ST;
	return 1;
}

static int
acl_fetch_url_ip(struct proxy *px, struct session *l4, void *l7, int dir,
		 struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
		/* ensure the indexes are not affected */
		return 0;

	/* Parse HTTP request */
	url2sa(txn->req.sol + txn->req.sl.rq.u, txn->req.sl.rq.u_l, &l4->srv_addr);
	test->ptr = (void *)&((struct sockaddr_in *)&l4->srv_addr)->sin_addr;
	test->i = AF_INET;

	/*
	 * If we are parsing url in frontend space, we prepare backend stage
	 * to not parse again the same url ! optimization lazyness...
	 */
	if (px->options & PR_O_HTTP_PROXY)
		l4->flags |= SN_ADDR_SET;

	test->flags = ACL_TEST_F_READ_ONLY;
	return 1;
}

static int
acl_fetch_url_port(struct proxy *px, struct session *l4, void *l7, int dir,
		   struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
		/* ensure the indexes are not affected */
		return 0;

	/* Same optimization as url_ip */
	url2sa(txn->req.sol + txn->req.sl.rq.u, txn->req.sl.rq.u_l, &l4->srv_addr);
	test->i = ntohs(((struct sockaddr_in *)&l4->srv_addr)->sin_port);

	if (px->options & PR_O_HTTP_PROXY)
		l4->flags |= SN_ADDR_SET;

	test->flags = ACL_TEST_F_READ_ONLY;
	return 1;
}

/* 5. Check on HTTP header. A pointer to the beginning of the value is returned.
 * This generic function is used by both acl_fetch_chdr() and acl_fetch_shdr().
 */
static int
acl_fetch_hdr(struct proxy *px, struct session *l4, void *l7, char *sol,
              struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;
	struct hdr_idx *idx = &txn->hdr_idx;
	struct hdr_ctx *ctx = (struct hdr_ctx *)test->ctx.a;

	if (!txn)
		return 0;

	if (!(test->flags & ACL_TEST_F_FETCH_MORE))
		/* search for header from the beginning */
		ctx->idx = 0;

	if (http_find_header2(expr->arg.str, expr->arg_len, sol, idx, ctx)) {
		test->flags |= ACL_TEST_F_FETCH_MORE;
		test->flags |= ACL_TEST_F_VOL_HDR;
		test->len = ctx->vlen;
		test->ptr = (char *)ctx->line + ctx->val;
		return 1;
	}

	test->flags &= ~ACL_TEST_F_FETCH_MORE;
	test->flags |= ACL_TEST_F_VOL_HDR;
	return 0;
}

static int
acl_fetch_chdr(struct proxy *px, struct session *l4, void *l7, int dir,
	       struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
		/* ensure the indexes are not affected */
		return 0;

	return acl_fetch_hdr(px, l4, txn, txn->req.sol, expr, test);
}

static int
acl_fetch_shdr(struct proxy *px, struct session *l4, void *l7, int dir,
	       struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_BODY)
		return 0;

	return acl_fetch_hdr(px, l4, txn, txn->rsp.sol, expr, test);
}

/* 6. Check on HTTP header count. The number of occurrences is returned.
 * This generic function is used by both acl_fetch_chdr* and acl_fetch_shdr*.
 */
static int
acl_fetch_hdr_cnt(struct proxy *px, struct session *l4, void *l7, char *sol,
                  struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;
	struct hdr_idx *idx = &txn->hdr_idx;
	struct hdr_ctx ctx;
	int cnt;

	if (!txn)
		return 0;

	ctx.idx = 0;
	cnt = 0;
	while (http_find_header2(expr->arg.str, expr->arg_len, sol, idx, &ctx))
		cnt++;

	test->i = cnt;
	test->flags = ACL_TEST_F_VOL_HDR;
	return 1;
}

static int
acl_fetch_chdr_cnt(struct proxy *px, struct session *l4, void *l7, int dir,
		   struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
		/* ensure the indexes are not affected */
		return 0;

	return acl_fetch_hdr_cnt(px, l4, txn, txn->req.sol, expr, test);
}

static int
acl_fetch_shdr_cnt(struct proxy *px, struct session *l4, void *l7, int dir,
		   struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_BODY)
		return 0;

	return acl_fetch_hdr_cnt(px, l4, txn, txn->rsp.sol, expr, test);
}

/* 7. Check on HTTP header's integer value. The integer value is returned.
 * FIXME: the type is 'int', it may not be appropriate for everything.
 * This generic function is used by both acl_fetch_chdr* and acl_fetch_shdr*.
 */
static int
acl_fetch_hdr_val(struct proxy *px, struct session *l4, void *l7, char *sol,
                  struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;
	struct hdr_idx *idx = &txn->hdr_idx;
	struct hdr_ctx *ctx = (struct hdr_ctx *)test->ctx.a;

	if (!txn)
		return 0;

	if (!(test->flags & ACL_TEST_F_FETCH_MORE))
		/* search for header from the beginning */
		ctx->idx = 0;

	if (http_find_header2(expr->arg.str, expr->arg_len, sol, idx, ctx)) {
		test->flags |= ACL_TEST_F_FETCH_MORE;
		test->flags |= ACL_TEST_F_VOL_HDR;
		test->i = strl2ic((char *)ctx->line + ctx->val, ctx->vlen);
		return 1;
	}

	test->flags &= ~ACL_TEST_F_FETCH_MORE;
	test->flags |= ACL_TEST_F_VOL_HDR;
	return 0;
}

static int
acl_fetch_chdr_val(struct proxy *px, struct session *l4, void *l7, int dir,
		   struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
		/* ensure the indexes are not affected */
		return 0;

	return acl_fetch_hdr_val(px, l4, txn, txn->req.sol, expr, test);
}

static int
acl_fetch_shdr_val(struct proxy *px, struct session *l4, void *l7, int dir,
		   struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;

	if (!txn)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_BODY)
		return 0;

	return acl_fetch_hdr_val(px, l4, txn, txn->rsp.sol, expr, test);
}

/* 8. Check on URI PATH. A pointer to the PATH is stored. The path starts at
 * the first '/' after the possible hostname, and ends before the possible '?'.
 */
static int
acl_fetch_path(struct proxy *px, struct session *l4, void *l7, int dir,
               struct acl_expr *expr, struct acl_test *test)
{
	struct http_txn *txn = l7;
	char *ptr, *end;

	if (!txn)
		return 0;

	if (txn->req.msg_state != HTTP_MSG_BODY)
		return 0;

	if (txn->rsp.msg_state != HTTP_MSG_RPBEFORE)
		/* ensure the indexes are not affected */
		return 0;

	end = txn->req.sol + txn->req.sl.rq.u + txn->req.sl.rq.u_l;
	ptr = http_get_path(txn);
	if (!ptr)
		return 0;

	/* OK, we got the '/' ! */
	test->ptr = ptr;

	while (ptr < end && *ptr != '?')
		ptr++;

	test->len = ptr - test->ptr;

	/* we do not need to set READ_ONLY because the data is in a buffer */
	test->flags = ACL_TEST_F_VOL_1ST;
	return 1;
}



/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
	{ "method",     acl_parse_meth,  acl_fetch_meth,   acl_match_meth, ACL_USE_L7REQ_PERMANENT },
	{ "req_ver",    acl_parse_ver,   acl_fetch_rqver,  acl_match_str,  ACL_USE_L7REQ_VOLATILE  },
	{ "resp_ver",   acl_parse_ver,   acl_fetch_stver,  acl_match_str,  ACL_USE_L7RTR_VOLATILE  },
	{ "status",     acl_parse_int,   acl_fetch_stcode, acl_match_int,  ACL_USE_L7RTR_PERMANENT },

	{ "url",        acl_parse_str,   acl_fetch_url,      acl_match_str,  ACL_USE_L7REQ_VOLATILE },
	{ "url_beg",    acl_parse_str,   acl_fetch_url,      acl_match_beg,  ACL_USE_L7REQ_VOLATILE },
	{ "url_end",    acl_parse_str,   acl_fetch_url,      acl_match_end,  ACL_USE_L7REQ_VOLATILE },
	{ "url_sub",    acl_parse_str,   acl_fetch_url,      acl_match_sub,  ACL_USE_L7REQ_VOLATILE },
	{ "url_dir",    acl_parse_str,   acl_fetch_url,      acl_match_dir,  ACL_USE_L7REQ_VOLATILE },
	{ "url_dom",    acl_parse_str,   acl_fetch_url,      acl_match_dom,  ACL_USE_L7REQ_VOLATILE },
	{ "url_reg",    acl_parse_reg,   acl_fetch_url,      acl_match_reg,  ACL_USE_L7REQ_VOLATILE },
	{ "url_ip",     acl_parse_ip,    acl_fetch_url_ip,   acl_match_ip,   ACL_USE_L7REQ_VOLATILE },
	{ "url_port",   acl_parse_int,   acl_fetch_url_port, acl_match_int,  ACL_USE_L7REQ_VOLATILE },

	/* note: we should set hdr* to use ACL_USE_HDR_VOLATILE, and chdr* to use L7REQ_VOLATILE */
	{ "hdr",        acl_parse_str,   acl_fetch_chdr,    acl_match_str, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_reg",    acl_parse_reg,   acl_fetch_chdr,    acl_match_reg, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_beg",    acl_parse_str,   acl_fetch_chdr,    acl_match_beg, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_end",    acl_parse_str,   acl_fetch_chdr,    acl_match_end, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_sub",    acl_parse_str,   acl_fetch_chdr,    acl_match_sub, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_dir",    acl_parse_str,   acl_fetch_chdr,    acl_match_dir, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_dom",    acl_parse_str,   acl_fetch_chdr,    acl_match_dom, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_cnt",    acl_parse_int,   acl_fetch_chdr_cnt,acl_match_int, ACL_USE_L7REQ_VOLATILE },
	{ "hdr_val",    acl_parse_int,   acl_fetch_chdr_val,acl_match_int, ACL_USE_L7REQ_VOLATILE },

	{ "shdr",       acl_parse_str,   acl_fetch_shdr,    acl_match_str, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_reg",   acl_parse_reg,   acl_fetch_shdr,    acl_match_reg, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_beg",   acl_parse_str,   acl_fetch_shdr,    acl_match_beg, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_end",   acl_parse_str,   acl_fetch_shdr,    acl_match_end, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_sub",   acl_parse_str,   acl_fetch_shdr,    acl_match_sub, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_dir",   acl_parse_str,   acl_fetch_shdr,    acl_match_dir, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_dom",   acl_parse_str,   acl_fetch_shdr,    acl_match_dom, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_cnt",   acl_parse_int,   acl_fetch_shdr_cnt,acl_match_int, ACL_USE_L7RTR_VOLATILE },
	{ "shdr_val",   acl_parse_int,   acl_fetch_shdr_val,acl_match_int, ACL_USE_L7RTR_VOLATILE },

	{ "path",       acl_parse_str,   acl_fetch_path,   acl_match_str, ACL_USE_L7REQ_VOLATILE },
	{ "path_reg",   acl_parse_reg,   acl_fetch_path,   acl_match_reg, ACL_USE_L7REQ_VOLATILE },
	{ "path_beg",   acl_parse_str,   acl_fetch_path,   acl_match_beg, ACL_USE_L7REQ_VOLATILE },
	{ "path_end",   acl_parse_str,   acl_fetch_path,   acl_match_end, ACL_USE_L7REQ_VOLATILE },
	{ "path_sub",   acl_parse_str,   acl_fetch_path,   acl_match_sub, ACL_USE_L7REQ_VOLATILE },
	{ "path_dir",   acl_parse_str,   acl_fetch_path,   acl_match_dir, ACL_USE_L7REQ_VOLATILE },
	{ "path_dom",   acl_parse_str,   acl_fetch_path,   acl_match_dom, ACL_USE_L7REQ_VOLATILE },

	{ NULL, NULL, NULL, NULL },

#if 0
	{ "line",       acl_parse_str,   acl_fetch_line,   acl_match_str   },
	{ "line_reg",   acl_parse_reg,   acl_fetch_line,   acl_match_reg   },
	{ "line_beg",   acl_parse_str,   acl_fetch_line,   acl_match_beg   },
	{ "line_end",   acl_parse_str,   acl_fetch_line,   acl_match_end   },
	{ "line_sub",   acl_parse_str,   acl_fetch_line,   acl_match_sub   },
	{ "line_dir",   acl_parse_str,   acl_fetch_line,   acl_match_dir   },
	{ "line_dom",   acl_parse_str,   acl_fetch_line,   acl_match_dom   },

	{ "cook",       acl_parse_str,   acl_fetch_cook,   acl_match_str   },
	{ "cook_reg",   acl_parse_reg,   acl_fetch_cook,   acl_match_reg   },
	{ "cook_beg",   acl_parse_str,   acl_fetch_cook,   acl_match_beg   },
	{ "cook_end",   acl_parse_str,   acl_fetch_cook,   acl_match_end   },
	{ "cook_sub",   acl_parse_str,   acl_fetch_cook,   acl_match_sub   },
	{ "cook_dir",   acl_parse_str,   acl_fetch_cook,   acl_match_dir   },
	{ "cook_dom",   acl_parse_str,   acl_fetch_cook,   acl_match_dom   },
	{ "cook_pst",   acl_parse_none,  acl_fetch_cook,   acl_match_pst   },

	{ "auth_user",  acl_parse_str,   acl_fetch_user,   acl_match_str   },
	{ "auth_regex", acl_parse_reg,   acl_fetch_user,   acl_match_reg   },
	{ "auth_clear", acl_parse_str,   acl_fetch_auth,   acl_match_str   },
	{ "auth_md5",   acl_parse_str,   acl_fetch_auth,   acl_match_md5   },
	{ NULL, NULL, NULL, NULL },
#endif
}};


__attribute__((constructor))
static void __http_protocol_init(void)
{
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
