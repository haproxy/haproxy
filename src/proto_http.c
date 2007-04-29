/*
 * HTTP protocol analyzer
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
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
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/client.h>
#include <types/global.h>
#include <types/httperr.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/server.h>

#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/proto_http.h>
#include <proto/queue.h>
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
 * table than two perform a boolean AND or OR between two tests. Refer to
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
static char *cli_stnames[5] = {"HDR", "DAT", "SHR", "SHW", "CLS" };
static char *srv_stnames[7] = {"IDL", "CON", "HDR", "DAT", "SHR", "SHW", "CLS" };
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

/*
 * returns a message to the client ; the connection is shut down for read,
 * and the request is cleared so that no server connection can be initiated.
 * The client must be in a valid state for this (HEADER, DATA ...).
 * Nothing is performed on the server side. The message is contained in a
 * "chunk". If it is null, then an empty message is used.
 * The reply buffer doesn't need to be empty before this.
 */
void client_retnclose(struct session *s, const struct chunk *msg)
{
	EV_FD_CLR(s->cli_fd, DIR_RD);
	EV_FD_SET(s->cli_fd, DIR_WR);
	tv_eternity(&s->req->rex);
	if (s->fe->clitimeout)
		tv_delayfrom(&s->rep->wex, &now, s->fe->clitimeout);
	else
		tv_eternity(&s->rep->wex);
	s->cli_state = CL_STSHUTR;
	buffer_flush(s->rep);
	if (msg->len)
		buffer_write(s->rep, msg->str, msg->len);
	s->req->l = 0;
}


/*
 * returns a message into the rep buffer, and flushes the req buffer.
 * The reply buffer doesn't need to be empty before this. The message
 * is contained in a "chunk". If it is null, then an empty message is
 * used.
 */
void client_return(struct session *s, const struct chunk *msg)
{
	buffer_flush(s->rep);
	if (msg->len)
		buffer_write(s->rep, msg->str, msg->len);
	s->req->l = 0;
}


/* This function turns the server state into the SV_STCLOSE, and sets
 * indicators accordingly. Note that if <status> is 0, or if the message
 * pointer is NULL, then no message is returned.
 */
void srv_close_with_err(struct session *t, int err, int finst,
			int status, const struct chunk *msg)
{
	t->srv_state = SV_STCLOSE;
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

/* Processes the client and server jobs of a session task, then
 * puts it back to the wait queue in a clean state, or
 * cleans up its resources if it must be deleted. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for
 * infinity.
 */
int process_session(struct task *t)
{
	struct session *s = t->context;
	int fsm_resync = 0;

	do {
		fsm_resync = 0;
		//fprintf(stderr,"before_cli:cli=%d, srv=%d\n", s->cli_state, s->srv_state);
		fsm_resync |= process_cli(s);
		//fprintf(stderr,"cli/srv:cli=%d, srv=%d\n", s->cli_state, s->srv_state);
		fsm_resync |= process_srv(s);
		//fprintf(stderr,"after_srv:cli=%d, srv=%d\n", s->cli_state, s->srv_state);
	} while (fsm_resync);

	if (s->cli_state != CL_STCLOSE || s->srv_state != SV_STCLOSE) {
		s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;

		t->expire = s->req->rex;
		tv_min(&t->expire, &s->req->rex, &s->req->wex);
		tv_bound(&t->expire, &s->req->cex);
		tv_bound(&t->expire, &s->rep->rex);
		tv_bound(&t->expire, &s->rep->wex);

		/* restore t to its place in the task list */
		task_queue(t);

#ifdef DEBUG_FULL
		/* DEBUG code : this should never ever happen, otherwise it indicates
		 * that a task still has something to do and will provoke a quick loop.
		 */
		if (tv_remain2(&now, &t->expire) <= 0)
			exit(100);
#endif

		return tv_remain2(&now, &t->expire); /* nothing more to do */
	}

	s->fe->feconn--;
	if (s->flags & SN_BE_ASSIGNED)
		s->be->beconn--;
	actconn--;
    
	if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
		int len;
		len = sprintf(trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->id,
			      (unsigned short)s->cli_fd, (unsigned short)s->srv_fd);
		write(1, trash, len);
	}

	s->logs.t_close = tv_diff(&s->logs.tv_accept, &now);
	if (s->req != NULL)
		s->logs.bytes_in = s->req->total;
	if (s->rep != NULL)
		s->logs.bytes_out = s->rep->total;

	s->fe->bytes_in  += s->logs.bytes_in;
	s->fe->bytes_out += s->logs.bytes_out;
	if (s->be != s->fe) {
		s->be->bytes_in  += s->logs.bytes_in;
		s->be->bytes_out += s->logs.bytes_out;
	}
	if (s->srv) {
		s->srv->bytes_in  += s->logs.bytes_in;
		s->srv->bytes_out += s->logs.bytes_out;
	}

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
	return TIME_ETERNITY; /* rest in peace for eternity */
}


extern const char sess_term_cond[8];
extern const char sess_fin_state[8];
extern const char *monthname[12];
const char sess_cookie[4]     = "NIDV";		/* No cookie, Invalid cookie, cookie for a Down server, Valid cookie */
const char sess_set_cookie[8] = "N1I3PD5R";	/* No set-cookie, unknown, Set-Cookie Inserted, unknown,
					    	   Set-cookie seen and left unchanged (passive), Set-cookie Deleted,
						   unknown, Set-cookie Rewritten */
void **pool_requri = NULL;

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
	struct tm *tm;
	static char tmpline[MAX_SYSLOG_LEN];
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

	tm = localtime((time_t *)&s->logs.tv_accept.tv_sec);


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

	send_log(prx_log, LOG_INFO,
		 "%s:%d [%02d/%s/%04d:%02d:%02d:%02d.%03d]"
		 " %s %s/%s %d/%d/%d/%d/%s%d %d %s%lld"
		 " %s %s %c%c%c%c %d/%d/%d/%d %d/%d%s\n",
		 pn,
		 (s->cli_addr.ss_family == AF_INET) ?
		 ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port) :
		 ntohs(((struct sockaddr_in6 *)&s->cli_addr)->sin6_port),
		 tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
		 tm->tm_hour, tm->tm_min, tm->tm_sec, s->logs.tv_accept.tv_usec/1000,
		 fe->id, be->id, svid,
		 s->logs.t_request,
		 (s->logs.t_queue >= 0) ? s->logs.t_queue - s->logs.t_request : -1,
		 (s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1,
		 (s->logs.t_data >= 0) ? s->logs.t_data - s->logs.t_connect : -1,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.t_close,
		 txn->status,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.bytes_in,
		 txn->cli_cookie ? txn->cli_cookie : "-",
		 txn->srv_cookie ? txn->srv_cookie : "-",
		 sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT],
		 sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT],
		 (be->options & PR_O_COOK_ANY) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-',
		 (be->options & PR_O_COOK_ANY) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-',
		 actconn, fe->feconn, be->beconn, s->srv ? s->srv->cur_sess : 0,
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
						pool_alloc_from(h->pool, h->len + 1);

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
 * This function was intentionnally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names.
 */
const char *http_parse_stsline(struct http_msg *msg, const char *msg_buf, int state,
			       const char *ptr, const char *end,
			       char **ret_ptr, int *ret_state)
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
 * This function was intentionnally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names.
 */
const char *http_parse_reqline(struct http_msg *msg, const char *msg_buf, int state,
			       const char *ptr, const char *end,
			       char **ret_ptr, int *ret_state)
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
 * MSG_R[PQ]BEFORE to MSG_RPVER|MSG_RQMETH.
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

	int state;                /* updated only when leaving the FSM */
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
    
/*
 * manages the client FSM and its socket. BTW, it also tries to handle the
 * cookie. It returns 1 if a state has changed (and a resync may be needed),
 * 0 else.
 */
int process_cli(struct session *t)
{
	int s = t->srv_state;
	int c = t->cli_state;
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;

	DPRINTF(stderr,"process_cli: c=%s s=%s set(r,w)=%d,%d exp(r,w)=%d.%d,%d.%d\n",
		cli_stnames[c], srv_stnames[s],
		EV_FD_ISSET(t->cli_fd, DIR_RD), EV_FD_ISSET(t->cli_fd, DIR_WR),
		req->rex.tv_sec, req->rex.tv_usec,
		rep->wex.tv_sec, rep->wex.tv_usec);

	if (c == CL_STHEADERS) {
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
			if (unlikely(req->l >= req->rlim - req->data)) {
				/* FIXME: check if URI is set and return Status
				 * 414 Request URI too long instead.
				 */
				goto return_bad_req;
			}

			/* 2: have we encountered a read error or a close ? */
			else if (unlikely(req->flags & (BF_READ_ERROR | BF_READ_NULL))) {
				/* read error, or last read : give up. */
				tv_eternity(&req->rex);
				fd_delete(t->cli_fd);
				t->cli_state = CL_STCLOSE;
				t->fe->failed_req++;
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLICL;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_R;
				return 1;
			}

			/* 3: has the read timeout expired ? */
			else if (unlikely(tv_cmp2_le(&req->rex, &now))) {
				/* read timeout : give up with an error message. */
				txn->status = 408;
				client_retnclose(t, error_message(t, HTTP_ERR_408));
				t->fe->failed_req++;
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLITO;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_R;
				return 1;
			}

			/* 4: do we need to re-enable the read socket ? */
			else if (unlikely(EV_FD_COND_S(t->cli_fd, DIR_RD))) {
				/* fd in DIR_RD was disabled, perhaps because of a previous buffer
				 * full. We cannot loop here since stream_sock_read will disable it only if
				 * req->l == rlim-data
				 */
				if (t->fe->clitimeout)
					tv_delayfrom(&req->rex, &now, t->fe->clitimeout);
				else
					tv_eternity(&req->rex);
			}
			return t->cli_state != CL_STHEADERS;
		}


		/****************************************************************
		 * More interesting part now : we know that we have a complete  *
		 * request which at least looks like HTTP. We have an indicator *
		 * of each header's length, so we can parse them quickly.       *
		 ****************************************************************/

		/*
		 * 1: identify the method
		 */
		txn->meth = find_http_meth(&req->data[msg->som], msg->sl.rq.m_l);

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
			t->flags |= SN_MONITOR;
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
			if ((txn->uri = pool_alloc(requri)) != NULL) {
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
			struct proxy *rule_set = t->be;
			cur_proxy = t->be;

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
				t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);
				client_retnclose(t, error_message(t, HTTP_ERR_403));
				goto return_prx_cond;
			}

			/* We might have to check for "Connection:" */
			if (((t->fe->options | t->be->options) & PR_O_HTTP_CLOSE) &&
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
				/* we have to check the URI and auth for this request */
				if (stats_check_uri_auth(t, rule_set))
					return 1;
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
		if (!(txn->flags & (TX_CLDENY|TX_CLTARPIT)))
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

					len = sprintf(trash, "X-Forwarded-For: %d.%d.%d.%d",
						      pn[0], pn[1], pn[2], pn[3]);

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
				len = sprintf(trash, "X-Forwarded-For: %s", pn);
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
		    ((t->fe->options | t->be->options) & PR_O_HTTP_CLOSE)) {
			if ((unlikely(msg->sl.rq.v_l != 8) ||
			     unlikely(req->data[msg->som + msg->sl.rq.v + 7] != '0')) &&
			    unlikely(http_header_add_tail2(req, &txn->req, &txn->hdr_idx,
							   "Connection: close", 17)) < 0)
				goto return_bad_req;
			t->flags |= SN_CONN_CLOSED;
		}

		/*************************************************************
		 * OK, that's finished for the headers. We have done what we *
		 * could. Let's switch to the DATA state.                    *
		 ************************************************************/

		t->cli_state = CL_STDATA;
		req->rlim = req->data + BUFSIZE; /* no more rewrite needed */

		t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);

		if (!t->fe->clitimeout ||
		    (t->srv_state < SV_STDATA && t->be->srvtimeout)) {
			/* If the client has no timeout, or if the server is not ready yet,
			 * and we know for sure that it can expire, then it's cleaner to
			 * disable the timeout on the client side so that too low values
			 * cannot make the sessions abort too early.
			 *
			 * FIXME-20050705: the server needs a way to re-enable this time-out
			 * when it switches its state, otherwise a client can stay connected
			 * indefinitely. This now seems to be OK.
			 */
			tv_eternity(&req->rex);
		}

		/* When a connection is tarpitted, we use the queue timeout for the
		 * tarpit delay, which currently happens to be the server's connect
		 * timeout. If unset, then set it to zero because we really want it
		 * to expire at one moment.
		 */
		if (txn->flags & TX_CLTARPIT) {
			t->req->l = 0;
			/* flush the request so that we can drop the connection early
			 * if the client closes first.
			 */
			tv_delayfrom(&req->cex, &now,
				     t->be->contimeout ? t->be->contimeout : 0);
		}

		/* OK let's go on with the BODY now */
		goto process_data;

	return_bad_req: /* let's centralize all bad requests */
		txn->req.msg_state = HTTP_MSG_ERROR;
		txn->status = 400;
		client_retnclose(t, error_message(t, HTTP_ERR_400));
		t->fe->failed_req++;
	return_prx_cond:
		if (!(t->flags & SN_ERR_MASK))
			t->flags |= SN_ERR_PRXCOND;
		if (!(t->flags & SN_FINST_MASK))
			t->flags |= SN_FINST_R;
		return 1;

	}
	else if (c == CL_STDATA) {
	process_data:
		/* FIXME: this error handling is partly buggy because we always report
		 * a 'DATA' phase while we don't know if the server was in IDLE, CONN
		 * or HEADER phase. BTW, it's not logical to expire the client while
		 * we're waiting for the server to connect.
		 */
		/* read or write error */
		if (rep->flags & BF_WRITE_ERROR || req->flags & BF_READ_ERROR) {
			tv_eternity(&req->rex);
			tv_eternity(&rep->wex);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLICL;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		/* last read, or end of server write */
		else if (req->flags & BF_READ_NULL || s == SV_STSHUTW || s == SV_STCLOSE) {
			EV_FD_CLR(t->cli_fd, DIR_RD);
			tv_eternity(&req->rex);
			t->cli_state = CL_STSHUTR;
			return 1;
		}	
		/* last server read and buffer empty */
		else if ((s == SV_STSHUTR || s == SV_STCLOSE) && (rep->l == 0)) {
			EV_FD_CLR(t->cli_fd, DIR_WR);
			tv_eternity(&rep->wex);
			shutdown(t->cli_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->cli_fd, DIR_RD);
			if (t->fe->clitimeout)
				tv_delayfrom(&req->rex, &now, t->fe->clitimeout);
			t->cli_state = CL_STSHUTW;
			//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			return 1;
		}
		/* read timeout */
		else if (tv_cmp2_le(&req->rex, &now)) {
			EV_FD_CLR(t->cli_fd, DIR_RD);
			tv_eternity(&req->rex);
			t->cli_state = CL_STSHUTR;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}	
		/* write timeout */
		else if (tv_cmp2_le(&rep->wex, &now)) {
			EV_FD_CLR(t->cli_fd, DIR_WR);
			tv_eternity(&rep->wex);
			shutdown(t->cli_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->cli_fd, DIR_RD);
			if (t->fe->clitimeout)
				tv_delayfrom(&req->rex, &now, t->fe->clitimeout);

			t->cli_state = CL_STSHUTW;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}

		if (req->l >= req->rlim - req->data) {
			/* no room to read more data */
			if (EV_FD_COND_C(t->cli_fd, DIR_RD)) {
				/* stop reading until we get some space */
				tv_eternity(&req->rex);
			}
		} else {
			/* there's still some space in the buffer */
			if (EV_FD_COND_S(t->cli_fd, DIR_RD)) {
				if (!t->fe->clitimeout ||
				    (t->srv_state < SV_STDATA && t->be->srvtimeout))
					/* If the client has no timeout, or if the server not ready yet, and we
					 * know for sure that it can expire, then it's cleaner to disable the
					 * timeout on the client side so that too low values cannot make the
					 * sessions abort too early.
					 */
					tv_eternity(&req->rex);
				else
					tv_delayfrom(&req->rex, &now, t->fe->clitimeout);
			}
		}

		if ((rep->l == 0) ||
		    ((s < SV_STDATA) /* FIXME: this may be optimized && (rep->w == rep->h)*/)) {
			if (EV_FD_COND_C(t->cli_fd, DIR_WR)) {
				/* stop writing */
				tv_eternity(&rep->wex);
			}
		} else {
			/* buffer not empty */
			if (EV_FD_COND_S(t->cli_fd, DIR_WR)) {
				/* restart writing */
				if (t->fe->clitimeout) {
					tv_delayfrom(&rep->wex, &now, t->fe->clitimeout);
					/* FIXME: to prevent the client from expiring read timeouts during writes,
					 * we refresh it. */
					req->rex = rep->wex;
				}
				else
					tv_eternity(&rep->wex);
			}
		}
		return 0; /* other cases change nothing */
	}
	else if (c == CL_STSHUTR) {
		if (rep->flags & BF_WRITE_ERROR) {
			tv_eternity(&rep->wex);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLICL;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		else if ((s == SV_STSHUTR || s == SV_STCLOSE) && (rep->l == 0)
			 && !(t->flags & SN_SELF_GEN)) {
			tv_eternity(&rep->wex);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			return 1;
		}
		else if (tv_cmp2_le(&rep->wex, &now)) {
			tv_eternity(&rep->wex);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}

		if (t->flags & SN_SELF_GEN) {
			produce_content(t);
			if (rep->l == 0) {
				tv_eternity(&rep->wex);
				fd_delete(t->cli_fd);
				t->cli_state = CL_STCLOSE;
				return 1;
			}
		}

		if ((rep->l == 0)
		    || ((s == SV_STHEADERS) /* FIXME: this may be optimized && (rep->w == rep->h)*/)) {
			if (EV_FD_COND_C(t->cli_fd, DIR_WR)) {
				/* stop writing */
				tv_eternity(&rep->wex);
			}
		} else {
			/* buffer not empty */
			if (EV_FD_COND_S(t->cli_fd, DIR_WR)) {
				/* restart writing */
				if (t->fe->clitimeout) {
					tv_delayfrom(&rep->wex, &now, t->fe->clitimeout);
					/* FIXME: to prevent the client from expiring read timeouts during writes,
					 * we refresh it. */
					req->rex = rep->wex;
				}
				else
					tv_eternity(&rep->wex);
			}
		}
		return 0;
	}
	else if (c == CL_STSHUTW) {
		if (req->flags & BF_READ_ERROR) {
			tv_eternity(&req->rex);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLICL;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		else if (req->flags & BF_READ_NULL || s == SV_STSHUTW || s == SV_STCLOSE) {
			tv_eternity(&req->rex);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			return 1;
		}
		else if (tv_cmp2_le(&req->rex, &now)) {
			tv_eternity(&req->rex);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		else if (req->l >= req->rlim - req->data) {
			/* no room to read more data */

			/* FIXME-20050705: is it possible for a client to maintain a session
			 * after the timeout by sending more data after it receives a close ?
			 */

			if (EV_FD_COND_C(t->cli_fd, DIR_RD)) {
				/* stop reading until we get some space */
				tv_eternity(&req->rex);
				//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			}
		} else {
			/* there's still some space in the buffer */
			if (EV_FD_COND_S(t->cli_fd, DIR_RD)) {
				if (t->fe->clitimeout)
					tv_delayfrom(&req->rex, &now, t->fe->clitimeout);
				else
					tv_eternity(&req->rex);
				//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			}
		}
		return 0;
	}
	else { /* CL_STCLOSE: nothing to do */
		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			int len;
			len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n", t->uniq_id, t->be->id, (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
			write(1, trash, len);
		}
		return 0;
	}
	return 0;
}


/*
 * manages the server FSM and its socket. It returns 1 if a state has changed
 * (and a resync may be needed), 0 else.
 */
int process_srv(struct session *t)
{
	int s = t->srv_state;
	int c = t->cli_state;
	struct http_txn *txn = &t->txn;
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;
	int conn_err;

#ifdef DEBUG_FULL
	fprintf(stderr,"process_srv: c=%s, s=%s\n", cli_stnames[c], srv_stnames[s]);
#endif
	//fprintf(stderr,"process_srv: c=%d, s=%d, cr=%d, cw=%d, sr=%d, sw=%d\n", c, s,
	//EV_FD_ISSET(t->cli_fd, DIR_RD), EV_FD_ISSET(t->cli_fd, DIR_WR),
	//EV_FD_ISSET(t->srv_fd, DIR_RD), EV_FD_ISSET(t->srv_fd, DIR_WR)
	//);
	if (s == SV_STIDLE) {
		if (c == CL_STHEADERS)
			return 0;	/* stay in idle, waiting for data to reach the client side */
		else if (c == CL_STCLOSE || c == CL_STSHUTW ||
			 (c == CL_STSHUTR &&
			  (t->req->l == 0 || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
			tv_eternity(&req->cex);
			if (t->pend_pos)
				t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
			/* note that this must not return any error because it would be able to
			 * overwrite the client_retnclose() output.
			 */
			if (txn->flags & TX_CLTARPIT)
				srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_T, 0, NULL);
			else
				srv_close_with_err(t, SN_ERR_CLICL, t->pend_pos ? SN_FINST_Q : SN_FINST_C, 0, NULL);

			return 1;
		}
		else {
			if (txn->flags & TX_CLTARPIT) {
				/* This connection is being tarpitted. The CLIENT side has
				 * already set the connect expiration date to the right
				 * timeout. We just have to check that it has not expired.
				 */
				if (!tv_cmp2_le(&req->cex, &now))
					return 0;

				/* We will set the queue timer to the time spent, just for
				 * logging purposes. We fake a 500 server error, so that the
				 * attacker will not suspect his connection has been tarpitted.
				 * It will not cause trouble to the logs because we can exclude
				 * the tarpitted connections by filtering on the 'PT' status flags.
				 */
				tv_eternity(&req->cex);
				t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
				srv_close_with_err(t, SN_ERR_PRXCOND, SN_FINST_T,
						   500, error_message(t, HTTP_ERR_500));
				return 1;
			}

			/* Right now, we will need to create a connection to the server.
			 * We might already have tried, and got a connection pending, in
			 * which case we will not do anything till it's pending. It's up
			 * to any other session to release it and wake us up again.
			 */
			if (t->pend_pos) {
				if (!tv_cmp2_le(&req->cex, &now))
					return 0;
				else {
					/* we've been waiting too long here */
					tv_eternity(&req->cex);
					t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
					srv_close_with_err(t, SN_ERR_SRVTO, SN_FINST_Q,
							   503, error_message(t, HTTP_ERR_503));
					if (t->srv)
						t->srv->failed_conns++;
					t->fe->failed_conns++;
					return 1;
				}
			}

			do {
				/* first, get a connection */
				if (srv_redispatch_connect(t))
					return t->srv_state != SV_STIDLE;

				/* try to (re-)connect to the server, and fail if we expire the
				 * number of retries.
				 */
				if (srv_retryable_connect(t)) {
					t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
					return t->srv_state != SV_STIDLE;
				}
			} while (1);
		}
	}
	else if (s == SV_STCONN) { /* connection in progress */
		if (c == CL_STCLOSE || c == CL_STSHUTW ||
		    (c == CL_STSHUTR &&
		     (t->req->l == 0 || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
			tv_eternity(&req->cex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;

			/* note that this must not return any error because it would be able to
			 * overwrite the client_retnclose() output.
			 */
			srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_C, 0, NULL);
			return 1;
		}
		if (!(req->flags & BF_WRITE_STATUS) && !tv_cmp2_le(&req->cex, &now)) {
			//fprintf(stderr,"1: c=%d, s=%d, now=%d.%06d, exp=%d.%06d\n", c, s, now.tv_sec, now.tv_usec, req->cex.tv_sec, req->cex.tv_usec);
			return 0; /* nothing changed */
		}
		else if (!(req->flags & BF_WRITE_STATUS) || (req->flags & BF_WRITE_ERROR)) {
			/* timeout, asynchronous connect error or first write error */
			//fprintf(stderr,"2: c=%d, s=%d\n", c, s);

			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;

			if (!(req->flags & BF_WRITE_STATUS))
				conn_err = SN_ERR_SRVTO; // it was a connect timeout.
			else
				conn_err = SN_ERR_SRVCL; // it was an asynchronous connect error.

			/* ensure that we have enough retries left */
			if (srv_count_retry_down(t, conn_err))
				return 1;

			if (t->srv && t->conn_retries == 0 && t->be->options & PR_O_REDISP) {
				/* We're on our last chance, and the REDISP option was specified.
				 * We will ignore cookie and force to balance or use the dispatcher.
				 */
				/* let's try to offer this slot to anybody */
				if (may_dequeue_tasks(t->srv, t->be))
					task_wakeup(t->srv->queue_mgt);

				if (t->srv)
					t->srv->failed_conns++;
				t->be->failed_conns++;

				t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
				t->srv = NULL; /* it's left to the dispatcher to choose a server */
				http_flush_cookie_flags(txn);

				/* first, get a connection */
				if (srv_redispatch_connect(t))
					return t->srv_state != SV_STIDLE;
			}

			do {
				/* Now we will try to either reconnect to the same server or
				 * connect to another server. If the connection gets queued
				 * because all servers are saturated, then we will go back to
				 * the SV_STIDLE state.
				 */
				if (srv_retryable_connect(t)) {
					t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
					return t->srv_state != SV_STCONN;
				}

				/* we need to redispatch the connection to another server */
				if (srv_redispatch_connect(t))
					return t->srv_state != SV_STCONN;
			} while (1);
		}
		else { /* no error or write 0 */
			t->logs.t_connect = tv_diff(&t->logs.tv_accept, &now);

			//fprintf(stderr,"3: c=%d, s=%d\n", c, s);
			if (req->l == 0) /* nothing to write */ {
				EV_FD_CLR(t->srv_fd, DIR_WR);
				tv_eternity(&req->wex);
			} else  /* need the right to write */ {
				EV_FD_SET(t->srv_fd, DIR_WR);
				if (t->be->srvtimeout) {
					tv_delayfrom(&req->wex, &now, t->be->srvtimeout);
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it. */
					rep->rex = req->wex;
				}
				else
					tv_eternity(&req->wex);
			}

			if (t->be->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
				EV_FD_SET(t->srv_fd, DIR_RD);
				if (t->be->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);
				else
					tv_eternity(&rep->rex);
		
				t->srv_state = SV_STDATA;
				if (t->srv)
					t->srv->cum_sess++;
				rep->rlim = rep->data + BUFSIZE; /* no rewrite needed */

				/* if the user wants to log as soon as possible, without counting
				   bytes from the server, then this is the right moment. */
				if (t->fe->to_log && !(t->logs.logwait & LW_BYTES)) {
					t->logs.t_close = t->logs.t_connect; /* to get a valid end date */
					tcp_sess_log(t);
				}
#ifdef CONFIG_HAP_TCPSPLICE
				if ((t->fe->options & t->be->options) & PR_O_TCPSPLICE) {
					/* TCP splicing supported by both FE and BE */
					tcp_splice_splicefd(t->cli_fd, t->srv_fd, 0);
				}
#endif
			}
			else {
				t->srv_state = SV_STHEADERS;
				if (t->srv)
					t->srv->cum_sess++;
				rep->rlim = rep->data + BUFSIZE - MAXREWRITE; /* rewrite needed */
				t->txn.rsp.msg_state = HTTP_MSG_RPBEFORE;
				/* reset hdr_idx which was already initialized by the request.
				 * right now, the http parser does it.
				 * hdr_idx_init(&t->txn.hdr_idx);
				 */
			}
			tv_eternity(&req->cex);
			return 1;
		}
	}
	else if (s == SV_STHEADERS) { /* receiving server headers */
		/*
		 * Now parse the partial (or complete) lines.
		 * We will check the response syntax, and also join multi-line
		 * headers. An index of all the lines will be elaborated while
		 * parsing.
		 *
		 * For the parsing, we use a 28 states FSM.
		 *
		 * Here is the information we currently have :
		 *   rep->data + req->som  = beginning of response
		 *   rep->data + req->eoh  = end of processed headers / start of current one
		 *   rep->data + req->eol  = end of current header or line (LF or CRLF)
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


		if ((rep->l < rep->rlim - rep->data) && EV_FD_COND_S(t->srv_fd, DIR_RD)) {
			/* fd in DIR_RD was disabled, perhaps because of a previous buffer
			 * full. We cannot loop here since stream_sock_read will disable it only if
			 * rep->l == rlim-data
			 */
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);
			else
				tv_eternity(&rep->rex);
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

			/* Invalid response, or read error or write error */
			if (unlikely((msg->msg_state == HTTP_MSG_ERROR) ||
			             (req->flags & BF_WRITE_ERROR) ||
			             (rep->flags & BF_READ_ERROR))) {
				tv_eternity(&rep->rex);
				tv_eternity(&req->wex);
				fd_delete(t->srv_fd);
				if (t->srv) {
					t->srv->cur_sess--;
					t->srv->failed_resp++;
				}
				t->be->failed_resp++;
				t->srv_state = SV_STCLOSE;
				txn->status = 502;
				client_return(t, error_message(t, HTTP_ERR_502));
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_SRVCL;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_H;
				/* We used to have a free connection slot. Since we'll never use it,
				 * we have to inform the server that it may be used by another session.
				 */
				if (t->srv && may_dequeue_tasks(t->srv, t->be))
					task_wakeup(t->srv->queue_mgt);

				return 1;
			}

			/* end of client write or end of server read.
			 * since we are in header mode, if there's no space left for headers, we
			 * won't be able to free more later, so the session will never terminate.
			 */
			else if (unlikely(rep->flags & BF_READ_NULL ||
			                  c == CL_STSHUTW || c == CL_STCLOSE ||
			                  rep->l >= rep->rlim - rep->data)) {
				EV_FD_CLR(t->srv_fd, DIR_RD);
				tv_eternity(&rep->rex);
				t->srv_state = SV_STSHUTR;
				//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
				return 1;
			}

			/* read timeout : return a 504 to the client.
			 */
			else if (unlikely(EV_FD_ISSET(t->srv_fd, DIR_RD) &&
			                  tv_cmp2_le(&rep->rex, &now))) {
				tv_eternity(&rep->rex);
				tv_eternity(&req->wex);
				fd_delete(t->srv_fd);
				if (t->srv) {
					t->srv->cur_sess--;
					t->srv->failed_resp++;
				}
				t->be->failed_resp++;
				t->srv_state = SV_STCLOSE;
				txn->status = 504;
				client_return(t, error_message(t, HTTP_ERR_504));
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_SRVTO;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_H;
				/* We used to have a free connection slot. Since we'll never use it,
				 * we have to inform the server that it may be used by another session.
				 */
				if (t->srv && may_dequeue_tasks(t->srv, t->be))
					task_wakeup(t->srv->queue_mgt);
				return 1;
			}

			/* last client read and buffer empty */
			/* FIXME!!! here, we don't want to switch to SHUTW if the
			 * client shuts read too early, because we may still have
			 * some work to do on the headers.
			 * The side-effect is that if the client completely closes its
			 * connection during SV_STHEADER, the connection to the server
			 * is kept until a response comes back or the timeout is reached.
			 */
			else if (unlikely((/*c == CL_STSHUTR ||*/ c == CL_STCLOSE) &&
			                  (req->l == 0))) {
				EV_FD_CLR(t->srv_fd, DIR_WR);
				tv_eternity(&req->wex);

				/* We must ensure that the read part is still
				 * alive when switching to shutw */
				EV_FD_SET(t->srv_fd, DIR_RD);
				if (t->be->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

				shutdown(t->srv_fd, SHUT_WR);
				t->srv_state = SV_STSHUTW;
				return 1;
			}

			/* write timeout */
			/* FIXME!!! here, we don't want to switch to SHUTW if the
			 * client shuts read too early, because we may still have
			 * some work to do on the headers.
			 */
			else if (unlikely(EV_FD_ISSET(t->srv_fd, DIR_WR) &&
					  tv_cmp2_le(&req->wex, &now))) {
				EV_FD_CLR(t->srv_fd, DIR_WR);
				tv_eternity(&req->wex);
				shutdown(t->srv_fd, SHUT_WR);
				/* We must ensure that the read part is still alive
				 * when switching to shutw */
				EV_FD_SET(t->srv_fd, DIR_RD);
				if (t->be->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

				t->srv_state = SV_STSHUTW;
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_SRVTO;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_H;
				return 1;
			}

			/*
			 * And now the non-error cases.
			 */

			/* Data remaining in the request buffer.
			 * This happens during the first pass here, and during
			 * long posts.
			 */
			else if (likely(req->l)) {
				if (EV_FD_COND_S(t->srv_fd, DIR_WR)) {
					/* restart writing */
					if (t->be->srvtimeout) {
						tv_delayfrom(&req->wex, &now, t->be->srvtimeout);
						/* FIXME: to prevent the server from expiring read timeouts during writes,
						 * we refresh it. */
						rep->rex = req->wex;
					}
					else
						tv_eternity(&req->wex);
				}
			}

			/* nothing left in the request buffer */
			else {
				if (EV_FD_COND_C(t->srv_fd, DIR_WR)) {
					/* stop writing */
					tv_eternity(&req->wex);
				}
			}

			return t->srv_state != SV_STHEADERS;
		}


		/*****************************************************************
		 * More interesting part now : we know that we have a complete   *
		 * response which at least looks like HTTP. We have an indicator *
		 * of each header's length, so we can parse them quickly.        *
		 ****************************************************************/

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
			    unlikely(t->be->options & PR_O_CHK_CACHE))
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
						t->srv->cur_sess--;
						t->srv->failed_resp++;
					}
					cur_proxy->failed_resp++;
				return_srv_prx_502:
					tv_eternity(&rep->rex);
					tv_eternity(&req->wex);
					fd_delete(t->srv_fd);
					t->srv_state = SV_STCLOSE;
					txn->status = 502;
					client_return(t, error_message(t, HTTP_ERR_502));
					if (!(t->flags & SN_ERR_MASK))
						t->flags |= SN_ERR_PRXCOND;
					if (!(t->flags & SN_FINST_MASK))
						t->flags |= SN_FINST_H;
					/* We used to have a free connection slot. Since we'll never use it,
					 * we have to inform the server that it may be used by another session.
					 */
					if (t->srv && may_dequeue_tasks(t->srv, cur_proxy))
						task_wakeup(t->srv->queue_mgt);
					return 1;
				}
			}

			/* has the response been denied ? */
			if (txn->flags & TX_SVDENY) {
				if (t->srv) {
					t->srv->cur_sess--;
					t->srv->failed_secu++;
				}
				cur_proxy->denied_resp++;
				goto return_srv_prx_502;
			}

			/* We might have to check for "Connection:" */
			if (((t->fe->options | t->be->options) & PR_O_HTTP_CLOSE) &&
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
		manage_server_side_cookies(t, rep);

		/*
		 * 5: add server cookie in the response if needed
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

			if (unlikely(http_header_add_tail2(rep, &txn->rsp, &txn->hdr_idx,
							   trash, len)) < 0)
				goto return_bad_resp;
			txn->flags |= TX_SCK_INSERTED;

			/* Here, we will tell an eventual cache on the client side that we don't
			 * want it to cache this reply because HTTP/1.0 caches also cache cookies !
			 * Some caches understand the correct form: 'no-cache="set-cookie"', but
			 * others don't (eg: apache <= 1.3.26). So we use 'private' instead.
			 */
			if (t->be->options & PR_O_COOK_NOC) {
				if (unlikely(http_header_add_tail2(rep, &txn->rsp, &txn->hdr_idx,
								   "Cache-control: private", 22)) < 0)
					goto return_bad_resp;
			}
		}


		/*
		 * 6: check for cache-control or pragma headers.
		 */
		check_response_for_cacheability(t, rep);


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
				t->srv->cur_sess--;
				t->srv->failed_secu++;
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
		    ((t->fe->options | t->be->options) & PR_O_HTTP_CLOSE)) {
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

		t->srv_state = SV_STDATA;
		rep->rlim = rep->data + BUFSIZE; /* no more rewrite needed */
		t->logs.t_data = tv_diff(&t->logs.tv_accept, &now);

		/* client connection already closed or option 'forceclose' required :
		 * we close the server's outgoing connection right now.
		 */
		if ((req->l == 0) &&
		    (c == CL_STSHUTR || c == CL_STCLOSE || t->be->options & PR_O_FORCE_CLO)) {
			EV_FD_CLR(t->srv_fd, DIR_WR);
			tv_eternity(&req->wex);

			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->srv_fd, DIR_RD);
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

			shutdown(t->srv_fd, SHUT_WR);
			t->srv_state = SV_STSHUTW;
		}

#ifdef CONFIG_HAP_TCPSPLICE
		if ((t->fe->options & t->be->options) & PR_O_TCPSPLICE) {
			/* TCP splicing supported by both FE and BE */
			tcp_splice_splicefd(t->cli_fd, t->srv_fd, 0);
		}
#endif
		/* if the user wants to log as soon as possible, without counting
		   bytes from the server, then this is the right moment. */
		if (t->fe->to_log && !(t->logs.logwait & LW_BYTES)) {
			t->logs.t_close = t->logs.t_data; /* to get a valid end date */
			t->logs.bytes_in = txn->rsp.eoh;
			if (t->fe->to_log & LW_REQ)
				http_sess_log(t);
			else
				tcp_sess_log(t);
		}

		/* Note: we must not try to cheat by jumping directly to DATA,
		 * otherwise we would not let the client side wake up.
		 */

		return 1;
	}
	else if (s == SV_STDATA) {
		/* read or write error */
		if (req->flags & BF_WRITE_ERROR || rep->flags & BF_READ_ERROR) {
			tv_eternity(&rep->rex);
			tv_eternity(&req->wex);
			fd_delete(t->srv_fd);
			if (t->srv) {
				t->srv->cur_sess--;
				t->srv->failed_resp++;
			}
			t->be->failed_resp++;
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVCL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);

			return 1;
		}
		/* last read, or end of client write */
		else if (rep->flags & BF_READ_NULL || c == CL_STSHUTW || c == CL_STCLOSE) {
			EV_FD_CLR(t->srv_fd, DIR_RD);
			tv_eternity(&rep->rex);
			t->srv_state = SV_STSHUTR;
			//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			return 1;
		}
		/* end of client read and no more data to send */
		else if ((c == CL_STSHUTR || c == CL_STCLOSE) && (req->l == 0)) {
			EV_FD_CLR(t->srv_fd, DIR_WR);
			tv_eternity(&req->wex);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->srv_fd, DIR_RD);
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

			t->srv_state = SV_STSHUTW;
			return 1;
		}
		/* read timeout */
		else if (tv_cmp2_le(&rep->rex, &now)) {
			EV_FD_CLR(t->srv_fd, DIR_RD);
			tv_eternity(&rep->rex);
			t->srv_state = SV_STSHUTR;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			return 1;
		}	
		/* write timeout */
		else if (tv_cmp2_le(&req->wex, &now)) {
			EV_FD_CLR(t->srv_fd, DIR_WR);
			tv_eternity(&req->wex);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->srv_fd, DIR_RD);
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);
			t->srv_state = SV_STSHUTW;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			return 1;
		}

		/* recompute request time-outs */
		if (req->l == 0) {
			if (EV_FD_COND_C(t->srv_fd, DIR_WR)) {
				/* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* buffer not empty, there are still data to be transferred */
			if (EV_FD_COND_S(t->srv_fd, DIR_WR)) {
				/* restart writing */
				if (t->be->srvtimeout) {
					tv_delayfrom(&req->wex, &now, t->be->srvtimeout);
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it. */
					rep->rex = req->wex;
				}
				else
					tv_eternity(&req->wex);
			}
		}

		/* recompute response time-outs */
		if (rep->l == BUFSIZE) { /* no room to read more data */
			if (EV_FD_COND_C(t->srv_fd, DIR_RD)) {
				tv_eternity(&rep->rex);
			}
		}
		else {
			if (EV_FD_COND_S(t->srv_fd, DIR_RD)) {
				if (t->be->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);
				else
					tv_eternity(&rep->rex);
			}
		}

		return 0; /* other cases change nothing */
	}
	else if (s == SV_STSHUTR) {
		if (req->flags & BF_WRITE_ERROR) {
			//EV_FD_CLR(t->srv_fd, DIR_WR);
			tv_eternity(&req->wex);
			fd_delete(t->srv_fd);
			if (t->srv) {
				t->srv->cur_sess--;
				t->srv->failed_resp++;
			}
			t->be->failed_resp++;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVCL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);

			return 1;
		}
		else if ((c == CL_STSHUTR || c == CL_STCLOSE) && (req->l == 0)) {
			//EV_FD_CLR(t->srv_fd, DIR_WR);
			tv_eternity(&req->wex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);

			return 1;
		}
		else if (tv_cmp2_le(&req->wex, &now)) {
			//EV_FD_CLR(t->srv_fd, DIR_WR);
			tv_eternity(&req->wex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);

			return 1;
		}
		else if (req->l == 0) {
			if (EV_FD_COND_C(t->srv_fd, DIR_WR)) {
				/* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* buffer not empty */
			if (EV_FD_COND_S(t->srv_fd, DIR_WR)) {
				/* restart writing */
				if (t->be->srvtimeout) {
					tv_delayfrom(&req->wex, &now, t->be->srvtimeout);
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it. */
					rep->rex = req->wex;
				}
				else
					tv_eternity(&req->wex);
			}
		}
		return 0;
	}
	else if (s == SV_STSHUTW) {
		if (rep->flags & BF_READ_ERROR) {
			//EV_FD_CLR(t->srv_fd, DIR_RD);
			tv_eternity(&rep->rex);
			fd_delete(t->srv_fd);
			if (t->srv) {
				t->srv->cur_sess--;
				t->srv->failed_resp++;
			}
			t->be->failed_resp++;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVCL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);

			return 1;
		}
		else if (rep->flags & BF_READ_NULL || c == CL_STSHUTW || c == CL_STCLOSE) {
			//EV_FD_CLR(t->srv_fd, DIR_RD);
			tv_eternity(&rep->rex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);

			return 1;
		}
		else if (tv_cmp2_le(&rep->rex, &now)) {
			//EV_FD_CLR(t->srv_fd, DIR_RD);
			tv_eternity(&rep->rex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);

			return 1;
		}
		else if (rep->l == BUFSIZE) { /* no room to read more data */
			if (EV_FD_COND_C(t->srv_fd, DIR_RD)) {
				tv_eternity(&rep->rex);
			}
		}
		else {
			if (EV_FD_COND_S(t->srv_fd, DIR_RD)) {
				if (t->be->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);
				else
					tv_eternity(&rep->rex);
			}
		}
		return 0;
	}
	else { /* SV_STCLOSE : nothing to do */
		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			int len;
			len = sprintf(trash, "%08x:%s.srvcls[%04x:%04x]\n",
				      t->uniq_id, t->be->id, (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
			write(1, trash, len);
		}
		return 0;
	}
	return 0;
}


/*
 * Produces data for the session <s> depending on its source. Expects to be
 * called with s->cli_state == CL_STSHUTR. Right now, only statistics can be
 * produced. It stops by itself by unsetting the SN_SELF_GEN flag from the
 * session, which it uses to keep on being called when there is free space in
 * the buffer, of simply by letting an empty buffer upon return. It returns 1
 * if it changes the session state from CL_STSHUTR, otherwise 0.
 */
int produce_content(struct session *s)
{
	if (s->data_source == DATA_SRC_NONE) {
		s->flags &= ~SN_SELF_GEN;
		return 1;
	}
	else if (s->data_source == DATA_SRC_STATS) {
		/* dump server statistics */
		return produce_content_stats(s);
	}
	else {
		/* unknown data source */
		s->txn.status = 500;
		client_retnclose(s, error_message(s, HTTP_ERR_500));
		if (!(s->flags & SN_ERR_MASK))
			s->flags |= SN_ERR_PRXCOND;
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;
		s->flags &= ~SN_SELF_GEN;
		return 1;
	}
}


/*
 * Produces statistics data for the session <s>. Expects to be called with
 * s->cli_state == CL_STSHUTR. It stops by itself by unsetting the SN_SELF_GEN
 * flag from the session, which it uses to keep on being called when there is
 * free space in the buffer, of simply by letting an empty buffer upon return.
 * It returns 1 if it changes the session state from CL_STSHUTR, otherwise 0.
 */
int produce_content_stats(struct session *s)
{
	struct buffer *rep = s->rep;
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	msg.len = 0;
	msg.str = trash;

	switch (s->data_state) {
	case DATA_ST_INIT:
		/* the function had not been called yet */
		s->flags |= SN_SELF_GEN;  // more data will follow

		chunk_printf(&msg, sizeof(trash),
			     "HTTP/1.0 200 OK\r\n"
			     "Cache-Control: no-cache\r\n"
			     "Connection: close\r\n"
			     "Content-Type: text/html\r\n"
			     "\r\n");

		s->txn.status = 200;
		client_retnclose(s, &msg); // send the start of the response.
		msg.len = 0;

		if (!(s->flags & SN_ERR_MASK))  // this is not really an error but it is
			s->flags |= SN_ERR_PRXCOND; // to mark that it comes from the proxy
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;

		if (s->txn.meth == HTTP_METH_HEAD) {
			/* that's all we return in case of HEAD request */
			s->data_state = DATA_ST_FIN;
			s->flags &= ~SN_SELF_GEN;
			return 1;
		}

		s->data_state = DATA_ST_HEAD; /* let's start producing data */
		/* fall through */

	case DATA_ST_HEAD:
		/* WARNING! This must fit in the first buffer !!! */	    
		chunk_printf(&msg, sizeof(trash),
			     "<html><head><title>Statistics Report for " PRODUCT_NAME "</title>\n"
			     "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n"
			     "<style type=\"text/css\"><!--\n"
			     "body {"
			     " font-family: helvetica, arial;"
			     " font-size: 12px;"
			     " font-weight: normal;"
			     " color: black;"
			     " background: white;"
			     "}\n"
			     "th,td {"
			     " font-size: 0.8em;"
			     " align: center;"
			     "}\n"
			     "h1 {"
			     " font-size: xx-large;"
			     " margin-bottom: 0.5em;"
			     "}\n"
			     "h2 {"
			     " font-family: helvetica, arial;"
			     " font-size: x-large;"
			     " font-weight: bold;"
			     " font-style: italic;"
			     " color: #6020a0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "h3 {"
			     " font-family: helvetica, arial;"
			     " font-size: 16px;"
			     " font-weight: bold;"
			     " color: #b00040;"
			     " background: #e8e8d0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "li {"
			     " margin-top: 0.25em;"
			     " margin-right: 2em;"
			     "}\n"
			     ".hr {margin-top: 0.25em;"
			     " border-color: black;"
			     " border-bottom-style: solid;"
			     "}\n"
			     ".pxname	{background: #b00040;color: #ffff40;font-weight: bold;}\n"
			     ".titre	{background: #20D0D0;color: #000000;font-weight: bold;}\n"
			     ".total	{background: #20D0D0;color: #ffff80;}\n"
			     ".frontend	{background: #e8e8d0;}\n"
			     ".backend	{background: #e8e8d0;}\n"
			     ".active0	{background: #ff9090;}\n"
			     ".active1	{background: #ffd020;}\n"
			     ".active2	{background: #ffffa0;}\n"
			     ".active3	{background: #c0ffc0;}\n"
			     ".active4	{background: #e0e0e0;}\n"
			     ".backup0	{background: #ff9090;}\n"
			     ".backup1	{background: #ff80ff;}\n"
			     ".backup2	{background: #c060ff;}\n"
			     ".backup3	{background: #b0d0ff;}\n"
			     ".backup4	{background: #e0e0e0;}\n"
			     "table.tbl { border-collapse: collapse; border-style: none;}\n"
			     "table.tbl td { border-width: 1px 1px 1px 1px; border-style: solid solid solid solid; padding: 2px 3px; border-color: gray;}\n"
			     "table.tbl th { border-width: 1px; border-style: solid solid solid solid; border-color: gray;}\n"
			     "table.tbl th.empty { border-style: none; empty-cells: hide;}\n"
			     "table.lgd { border-collapse: collapse; border-width: 1px; border-style: none none none solid; border-color: black;}\n"
			     "table.lgd td { border-width: 1px; border-style: solid solid solid solid; border-color: gray; padding: 2px;}\n"
			     "table.lgd td.noborder { border-style: none; padding: 2px; white-space: nowrap;}\n"
			     "-->\n"
			     "</style></head>\n");
			
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_state = DATA_ST_INFO;
		/* fall through */

	case DATA_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);

		/* WARNING! this has to fit the first packet too.
			 * We are around 3.5 kB, add adding entries will
			 * become tricky if we want to support 4kB buffers !
			 */
		chunk_printf(&msg, sizeof(trash),
			     "<body><h1><a href=\"" PRODUCT_URL "\" style=\"text-decoration: none;\">"
			     PRODUCT_NAME "</a></h1>\n"
			     "<h2>Statistics Report for pid %d</h2>\n"
			     "<hr width=\"100%%\" class=\"hr\">\n"
			     "<h3>&gt; General process information</h3>\n"
			     "<table border=0 cols=3><tr><td align=\"left\" nowrap width=\"1%%\">\n"
			     "<p><b>pid = </b> %d (nbproc = %d)<br>\n"
			     "<b>uptime = </b> %dd %dh%02dm%02ds<br>\n"
			     "<b>system limits :</b> memmax = %s%s ; ulimit-n = %d<br>\n"
			     "<b>maxsock = </b> %d<br>\n"
			     "<b>maxconn = </b> %d (current conns = %d)<br>\n"
			     "</td><td align=\"center\" nowrap>\n"
			     "<table class=\"lgd\"><tr>\n"
			     "<td class=\"active3\">&nbsp;</td><td class=\"noborder\">active UP </td>"
			     "<td class=\"backup3\">&nbsp;</td><td class=\"noborder\">backup UP </td>"
			     "</tr><tr>\n"
			     "<td class=\"active2\"></td><td class=\"noborder\">active UP, going down </td>"
			     "<td class=\"backup2\"></td><td class=\"noborder\">backup UP, going down </td>"
			     "</tr><tr>\n"
			     "<td class=\"active1\"></td><td class=\"noborder\">active DOWN, going up </td>"
			     "<td class=\"backup1\"></td><td class=\"noborder\">backup DOWN, going up </td>"
			     "</tr><tr>\n"
			     "<td class=\"active0\"></td><td class=\"noborder\">active or backup DOWN &nbsp;</td>"
			     "<td class=\"active4\"></td><td class=\"noborder\">not checked </td>"
			     "</tr></table>\n"
			     "</td>"
			     "<td align=\"left\" nowrap width=\"1%%\">"
			     "<b>External ressources:</b><ul style=\"margin-top: 0.25em;\">\n"
			     "<li><a href=\"" PRODUCT_URL "\">Primary site</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_UPD "\">Updates (v" PRODUCT_BRANCH ")</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_DOC "\">Online manual</a><br>\n"
			     "</ul>"
			     "</td>"
			     "</tr></table>\n"
			     "",
			     pid, pid, global.nbproc,
			     up / 86400, (up % 86400) / 3600,
			     (up % 3600) / 60, (up % 60),
			     global.rlimit_memmax ? ultoa(global.rlimit_memmax) : "unlimited",
			     global.rlimit_memmax ? " MB" : "",
			     global.rlimit_nofile,
			     global.maxsock,
			     global.maxconn,
			     actconn
			     );
	    
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		memset(&s->data_ctx, 0, sizeof(s->data_ctx));

		s->data_ctx.stats.px = proxy;
		s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
		s->data_state = DATA_ST_LIST;
		/* fall through */

	case DATA_ST_LIST:
		/* dump proxies */
		while (s->data_ctx.stats.px) {
			px = s->data_ctx.stats.px;
			/* skip the disabled proxies and non-networked ones */
			if (px->state != PR_STSTOPPED && (px->cap & (PR_CAP_FE | PR_CAP_BE)))
				if (produce_content_stats_proxy(s, px) == 0)
					return 0;

			s->data_ctx.stats.px = px->next;
			s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
		}
		/* here, we just have reached the last proxy */

		s->data_state = DATA_ST_END;
		/* fall through */

	case DATA_ST_END:
		chunk_printf(&msg, sizeof(trash), "</body></html>\n");
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_state = DATA_ST_FIN;
		/* fall through */

	case DATA_ST_FIN:
		s->flags &= ~SN_SELF_GEN;
		return 1;

	default:
		/* unknown state ! */
		s->txn.status = 500;
		client_retnclose(s, error_message(s, HTTP_ERR_500));
		if (!(s->flags & SN_ERR_MASK))
			s->flags |= SN_ERR_PRXCOND;
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;
		s->flags &= ~SN_SELF_GEN;
		return 1;
	}
}


/*
 * Dumps statistics for a proxy.
 * Returns 0 if it had to stop dumping data because of lack of buffer space,
 * ot non-zero if everything completed.
 */
int produce_content_stats_proxy(struct session *s, struct proxy *px)
{
	struct buffer *rep = s->rep;
	struct server *sv;
	struct chunk msg;

	msg.len = 0;
	msg.str = trash;

	switch (s->data_ctx.stats.px_st) {
	case DATA_ST_PX_INIT:
		/* we are on a new proxy */

		if (s->be->uri_auth && s->be->uri_auth->scope) {
			/* we have a limited scope, we have to check the proxy name */
			struct stat_scope *scope;
			int len;

			len = strlen(px->id);
			scope = s->be->uri_auth->scope;

			while (scope) {
				/* match exact proxy name */
				if (scope->px_len == len && !memcmp(px->id, scope->px_id, len))
					break;

				/* match '.' which means 'self' proxy */
				if (!strcmp(scope->px_id, ".") && px == s->fe)
					break;
				scope = scope->next;
			}

			/* proxy name not found : don't dump anything */
			if (scope == NULL)
				return 1;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_TH;
		/* fall through */

	case DATA_ST_PX_TH:
		/* print a new table */
		chunk_printf(&msg, sizeof(trash),
			     "<table cols=\"20\" class=\"tbl\" width=\"100%%\">\n"
			     "<tr align=\"center\" class=\"titre\">"
			     "<th colspan=2 class=\"pxname\">%s</th>"
			     "<th colspan=18 class=\"empty\"></th>"
			     "</tr>\n"
			     "<tr align=\"center\" class=\"titre\">"
			     "<th rowspan=2></th>"
			     "<th colspan=2>Queue</th><th colspan=4>Sessions</th>"
			     "<th colspan=2>Bytes</th><th colspan=2>Denied</th>"
			     "<th colspan=3>Errors</th><th colspan=6>Server</th>"
			     "</tr>\n"
			     "<tr align=\"center\" class=\"titre\">"
			     "<th>Cur</th><th>Max</th><th>Cur</th><th>Max</th>"
			     "<th>Limit</th><th>Cumul</th><th>In</th><th>Out</th>"
			     "<th>Req</th><th>Resp</th><th>Req</th><th>Conn</th>"
			     "<th>Resp</th><th>Status</th><th>Weight</th><th>Act</th>"
			     "<th>Bck</th><th>Check</th><th>Down</th></tr>\n"
			     "",
			     px->id);
		
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_ctx.stats.px_st = DATA_ST_PX_FE;
		/* fall through */

	case DATA_ST_PX_FE:
		/* print the frontend */
		if (px->cap & PR_CAP_FE) {
			chunk_printf(&msg, sizeof(trash),
				     /* name, queue */
				     "<tr align=center class=\"frontend\"><td>Frontend</td><td colspan=2></td>"
				     /* sessions : current, max, limit, cumul. */
				     "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>"
				     /* bytes : in, out */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     /* denied: req, resp */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* errors : request, connect, response */
				     "<td align=right>%d</td><td align=right></td><td align=right></td>"
				     /* server status : reflect backend status */
				     "<td align=center>%s</td>"
				     /* rest of server: nothing */
				     "<td align=center colspan=5></td></tr>"
				     "",
				     px->feconn, px->feconn_max, px->maxconn, px->cum_feconn,
				     px->bytes_in, px->bytes_out,
				     px->denied_req, px->denied_resp,
				     px->failed_req,
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP");

			if (buffer_write_chunk(rep, &msg) != 0)
				return 0;
		}

		s->data_ctx.stats.sv = px->srv; /* may be NULL */
		s->data_ctx.stats.px_st = DATA_ST_PX_SV;
		/* fall through */

	case DATA_ST_PX_SV:
		/* stats.sv has been initialized above */
		while (s->data_ctx.stats.sv != NULL) {
			static char *srv_hlt_st[5] = { "DOWN", "DN %d/%d &uarr;", "UP %d/%d &darr;", "UP", "<i>no check</i>" };
			int sv_state; /* 0=DOWN, 1=going up, 2=going down, 3=UP, 4=unchecked */

			sv = s->data_ctx.stats.sv;

			/* FIXME: produce some small strings for "UP/DOWN x/y &#xxxx;" */
			if (!(sv->state & SRV_CHECKED))
				sv_state = 4;
			else if (sv->state & SRV_RUNNING)
				if (sv->health == sv->rise + sv->fall - 1)
					sv_state = 3; /* UP */
				else
					sv_state = 2; /* going down */
			else
				if (sv->health)
					sv_state = 1; /* going up */
				else
					sv_state = 0; /* DOWN */

			chunk_printf(&msg, sizeof(trash),
				     /* name */
				     "<tr align=\"center\" class=\"%s%d\"><td>%s</td>"
				     /* queue : current, max */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* sessions : current, max, limit, cumul */
				     "<td align=right>%d</td><td align=right>%d</td><td align=right>%s</td><td align=right>%d</td>"
				     /* bytes : in, out */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     /* denied: req, resp */
				     "<td align=right></td><td align=right>%d</td>"
				     /* errors : request, connect, response */
				     "<td align=right></td><td align=right>%d</td><td align=right>%d</td>\n"
				     "",
				     (sv->state & SRV_BACKUP) ? "backup" : "active",
				     sv_state, sv->id,
				     sv->nbpend, sv->nbpend_max,
				     sv->cur_sess, sv->cur_sess_max, sv->maxconn ? ultoa(sv->maxconn) : "-", sv->cum_sess,
				     sv->bytes_in, sv->bytes_out,
				     sv->failed_secu,
				     sv->failed_conns, sv->failed_resp);
				     
			/* status */
			chunk_printf(&msg, sizeof(trash), "<td nowrap>");
			chunk_printf(&msg, sizeof(trash),
				     srv_hlt_st[sv_state],
				     (sv->state & SRV_RUNNING) ? (sv->health - sv->rise + 1) : (sv->health),
				     (sv->state & SRV_RUNNING) ? (sv->fall) : (sv->rise));

			chunk_printf(&msg, sizeof(trash),
				     /* weight */
				     "</td><td>%d</td>"
				     /* act, bck */
				     "<td>%s</td><td>%s</td>"
				     "",
				     sv->uweight,
				     (sv->state & SRV_BACKUP) ? "-" : "Y",
				     (sv->state & SRV_BACKUP) ? "Y" : "-");

			/* check failures : unique, fatal */
			if (sv->state & SRV_CHECKED)
				chunk_printf(&msg, sizeof(trash),
					     "<td align=right>%d</td><td align=right>%d</td></tr>\n",
					     sv->failed_checks, sv->down_trans);
			else
				chunk_printf(&msg, sizeof(trash),
					     "<td colspan=2></td></tr>\n");

			if (buffer_write_chunk(rep, &msg) != 0)
				return 0;

			s->data_ctx.stats.sv = sv->next;
		} /* while sv */

		s->data_ctx.stats.px_st = DATA_ST_PX_BE;
		/* fall through */

	case DATA_ST_PX_BE:
		/* print the backend */
		if (px->cap & PR_CAP_BE) {
			chunk_printf(&msg, sizeof(trash),
				     /* name */
				     "<tr align=center class=\"backend\"><td>Backend</td>"
				     /* queue : current, max */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* sessions : current, max, limit, cumul. */
				     "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>"
				     /* bytes : in, out */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     /* denied: req, resp */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* errors : request, connect, response */
				     "<td align=right></td><td align=right>%d</td><td align=right>%d</td>\n"
				     /* server status : reflect backend status (up/down) : we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Tthen we display the total weight, number of
				      * active and backups. */
				     "<td align=center>%s</td><td align=center>%d</td>"
				     "<td align=center>%d</td><td align=center>%d</td>"
				     /* rest of server: nothing */
				     "<td align=center colspan=2></td></tr>"
				     "",
				     px->nbpend /* or px->totpend ? */, px->nbpend_max,
				     px->beconn, px->beconn_max, px->fullconn, px->cum_beconn,
				     px->bytes_in, px->bytes_out,
				     px->denied_req, px->denied_resp,
				     px->failed_conns, px->failed_resp,
				     (px->srv_map_sz > 0 || !px->srv) ? "UP" : "DOWN",
				     px->srv_map_sz, px->srv_act, px->srv_bck);

			if (buffer_write_chunk(rep, &msg) != 0)
				return 0;
		}
		
		s->data_ctx.stats.px_st = DATA_ST_PX_END;
		/* fall through */

	case DATA_ST_PX_END:
		chunk_printf(&msg, sizeof(trash), "</table><p>\n");

		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_ctx.stats.px_st = DATA_ST_PX_FIN;
		/* fall through */

	case DATA_ST_PX_FIN:
		return 1;

	default:
		/* unknown state, we should put an abort() here ! */
		return 1;
	}
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

				/* right now, the backend switch is not too much complicated
				 * because we have associated req_cap and rsp_cap to the
				 * frontend, and the beconn will be updated later.
				 */

				t->rep->rto = t->req->wto = t->be->srvtimeout;
				t->req->cto = t->be->contimeout;
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

	cur_ptr = req->data + txn->req.som;
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

			t->rep->rto = t->req->wto = t->be->srvtimeout;
			t->req->cto = t->be->contimeout;
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

			txn->req.sol = req->data + txn->req.som;
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
 * Manager client-side cookie
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

	if (t->be->cookie_name == NULL &&
	    t->be->appsession_name == NULL &&
	    t->be->capture_name == NULL)
		return;

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
				else if (!isspace((int)*p1))
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
			while (p4 < cur_end && !isspace((int)*p4) && *p4 != ';' && *p4 != ',')
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

					if ((txn->cli_cookie = pool_alloc(capture)) == NULL) {
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
			  
					if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
						Alert("Not enough memory process_cli():asession->sessid:malloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession->sessid:malloc().\n");
						return;
					}

					memcpy(asession_temp->sessid, p3, t->be->appsession_len);
					asession_temp->sessid[t->be->appsession_len] = 0;
					asession_temp->serverid = NULL;
			    
					/* only do insert, if lookup fails */
					if (chtbl_lookup(&(t->be->htbl_proxy), (void *) &asession_temp) != 0) {
						if ((asession_temp = pool_alloc(appsess)) == NULL) {
							/* free previously allocated memory */
							pool_free_to(apools.sessid, local_asession.sessid);
							Alert("Not enough memory process_cli():asession:calloc().\n");
							send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
							return;
						}

						asession_temp->sessid = local_asession.sessid;
						asession_temp->serverid = local_asession.serverid;
						chtbl_insert(&(t->be->htbl_proxy), (void *) asession_temp);
					} else {
						/* free previously allocated memory */
						pool_free_to(apools.sessid, local_asession.sessid);
					}
			    
					if (asession_temp->serverid == NULL) {
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

					tv_delayfrom(&asession_temp->expire, &now, t->be->appsession_timeout);
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

	cur_ptr = rtr->data + txn->rsp.som;
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

			txn->rsp.sol = rtr->data + txn->rsp.som;
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
 * Manager server-side cookies
 */
void manage_server_side_cookies(struct session *t, struct buffer *rtr)
{
	struct http_txn *txn = &t->txn;
	char *p1, *p2, *p3, *p4;

	appsess *asession_temp = NULL;
	appsess local_asession;

	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, delta;

	if (t->be->cookie_name == NULL &&
	    t->be->appsession_name == NULL &&
	    t->be->capture_name == NULL &&
	    !(t->be->options & PR_O_CHK_CACHE))
		return;

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
			while (p4 < cur_end && !isspace((int)*p4) && *p4 != ';')
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

				if ((txn->srv_cookie = pool_alloc(capture)) == NULL) {
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
		      
				if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
					Alert("Not enough Memory process_srv():asession->sessid:malloc().\n");
					send_log(t->be, LOG_ALERT, "Not enough Memory process_srv():asession->sessid:malloc().\n");
					return;
				}
				memcpy(asession_temp->sessid, p3, t->be->appsession_len);
				asession_temp->sessid[t->be->appsession_len] = 0;
				asession_temp->serverid = NULL;

				/* only do insert, if lookup fails */
				if (chtbl_lookup(&(t->be->htbl_proxy), (void *) &asession_temp) != 0) {
					if ((asession_temp = pool_alloc(appsess)) == NULL) {
						Alert("Not enough Memory process_srv():asession:calloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough Memory process_srv():asession:calloc().\n");
						return;
					}
					asession_temp->sessid = local_asession.sessid;
					asession_temp->serverid = local_asession.serverid;
					chtbl_insert(&(t->be->htbl_proxy), (void *) asession_temp);
				}/* end if (chtbl_lookup()) */
				else {
					/* free wasted memory */
					pool_free_to(apools.sessid, local_asession.sessid);
				} /* end else from if (chtbl_lookup()) */
		      
				if (asession_temp->serverid == NULL) {
					if ((asession_temp->serverid = pool_alloc_from(apools.serverid, apools.ser_msize)) == NULL) {
						Alert("Not enough Memory process_srv():asession->sessid:malloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough Memory process_srv():asession->sessid:malloc().\n");
						return;
					}
					asession_temp->serverid[0] = '\0';
				}
		      
				if (asession_temp->serverid[0] == '\0')
					memcpy(asession_temp->serverid, t->srv->id, server_id_len);
		      
				tv_delayfrom(&asession_temp->expire, &now, t->be->appsession_timeout);

#if defined(DEBUG_HASH)
				print_table(&(t->be->htbl_proxy));
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

	if (!txn->flags & TX_CACHEABLE)
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

		while (p2 < cur_end && *p2 != '=' && *p2 != ',' && !isspace((int)*p2))
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
	
	if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
		Alert("Not enough memory process_cli():asession_temp->sessid:calloc().\n");
		send_log(t->be, LOG_ALERT, "Not enough Memory process_cli():asession_temp->sessid:calloc().\n");
		return;
	}
	
	/* Copy the sessionid */
	memcpy(asession_temp->sessid, request_line, t->be->appsession_len);
	asession_temp->sessid[t->be->appsession_len] = 0;
	asession_temp->serverid = NULL;
	
	/* only do insert, if lookup fails */
	if (chtbl_lookup(&(t->be->htbl_proxy), (void *)&asession_temp)) {
		if ((asession_temp = pool_alloc(appsess)) == NULL) {
			/* free previously allocated memory */
			pool_free_to(apools.sessid, local_asession.sessid);
			Alert("Not enough memory process_cli():asession:calloc().\n");
			send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
			return;
		}
		asession_temp->sessid = local_asession.sessid;
		asession_temp->serverid = local_asession.serverid;
		chtbl_insert(&(t->be->htbl_proxy), (void *) asession_temp);
	}
	else {
		/* free previously allocated memory */
		pool_free_to(apools.sessid, local_asession.sessid);
	}
	
	tv_delayfrom(&asession_temp->expire, &now, t->be->appsession_timeout);
	asession_temp->request_count++;
	
#if defined(DEBUG_HASH)
	print_table(&(t->proxy->htbl_proxy));
#endif
	if (asession_temp->serverid == NULL) {
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

	/* check URI size */
	if (uri_auth->uri_len > txn->req.sl.rq.u_l)
		return 0;

	h = t->req->data + txn->req.sl.rq.u;

	/* the URI is in h */
	if (memcmp(h, uri_auth->uri_prefix, uri_auth->uri_len) != 0)
		return 0;

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
		if (!(t->flags & SN_ERR_MASK))
			t->flags |= SN_ERR_PRXCOND;
		if (!(t->flags & SN_FINST_MASK))
			t->flags |= SN_FINST_R;
		return 1;
	}

	/* The request is valid, the user is authenticate. Let's start sending
	 * data.
	 */
	t->cli_state = CL_STSHUTR;
	t->req->rlim = t->req->data + BUFSIZE; /* no more rewrite needed */
	t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);
	t->data_source = DATA_SRC_STATS;
	t->data_state  = DATA_ST_INIT;
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
		      dir, (unsigned  short)t->cli_fd, (unsigned short)t->srv_fd);
	max = end - start;
	UBOUND(max, sizeof(trash) - len - 1);
	len += strlcpy2(trash + len, start, max + 1);
	trash[len++] = '\n';
	write(1, trash, len);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
