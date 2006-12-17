/*
 * HTTP protocol analyzer
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
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
const char *HTTP_200 =
	"HTTP/1.0 200 OK\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>200 OK</h1>\nHAProxy: service ready.\n</body></html>\n";

/* Warning: this one is an sprintf() fmt string, with <realm> as its only argument */
const char *HTTP_401_fmt =
	"HTTP/1.0 401 Unauthorized\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"WWW-Authenticate: Basic realm=\"%s\"\r\n"
	"\r\n"
	"<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n";


/*
 * We have 26 list of methods (1 per first letter), each of which can have
 * up to 3 entries (2 valid, 1 null).
 */
struct http_method_desc {
	http_meth_t meth;
	int len;
	const char text[8];
};

static struct http_method_desc http_methods[26][3] = {
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

#ifdef DEBUG_FULL
static char *cli_stnames[5] = {"HDR", "DAT", "SHR", "SHW", "CLS" };
static char *srv_stnames[7] = {"IDL", "CON", "HDR", "DAT", "SHR", "SHW", "CLS" };
#endif


/*
 * returns a message to the client ; the connection is shut down for read,
 * and the request is cleared so that no server connection can be initiated.
 * The client must be in a valid state for this (HEADER, DATA ...).
 * Nothing is performed on the server side.
 * The reply buffer doesn't need to be empty before this.
 */
void client_retnclose(struct session *s, int len, const char *msg)
{
	MY_FD_CLR(s->cli_fd, StaticReadEvent);
	MY_FD_SET(s->cli_fd, StaticWriteEvent);
	tv_eternity(&s->req->rex);
	if (s->fe->clitimeout)
		tv_delayfrom(&s->rep->wex, &now, s->fe->clitimeout);
	else
		tv_eternity(&s->rep->wex);
	shutdown(s->cli_fd, SHUT_RD);
	s->cli_state = CL_STSHUTR;
	buffer_flush(s->rep);
	buffer_write(s->rep, msg, len);
	s->req->l = 0;
}


/*
 * returns a message into the rep buffer, and flushes the req buffer.
 * The reply buffer doesn't need to be empty before this.
 */
void client_return(struct session *s, int len, const char *msg)
{
	buffer_flush(s->rep);
	buffer_write(s->rep, msg, len);
	s->req->l = 0;
}


/* This function turns the server state into the SV_STCLOSE, and sets
 * indicators accordingly. Note that if <status> is 0, no message is
 * returned.
 */
void srv_close_with_err(struct session *t, int err, int finst,
			int status, int msglen, const char *msg)
{
	t->srv_state = SV_STCLOSE;
	if (status > 0) {
		t->logs.status = status;
		if (t->fe->mode == PR_MODE_HTTP)
			client_return(t, msglen, msg);
	}
	if (!(t->flags & SN_ERR_MASK))
		t->flags |= err;
	if (!(t->flags & SN_FINST_MASK))
		t->flags |= finst;
}


/*
 * returns HTTP_METH_NONE if there is nothing valid to read (empty or non-text
 * string), HTTP_METH_OTHER for unknown methods, or the identified method.
 */
static http_meth_t find_http_meth(const char *str, const int len)
{
	unsigned char m;
	struct http_method_desc *h;

	m = ((unsigned)*str - 'A');

	if (m < 26) {
		int l;
		for (h = http_methods[m]; (l = (h->len)) > 0; h++) {
			if (len <= l)
				continue;

			if (str[l] != ' ' && str[l] != '\t')
				continue;

			if (memcmp(str, h->text, l) == 0) {
				return h->meth;
			}
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
		struct timeval min1, min2;
		s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;

		tv_min(&min1, &s->req->rex, &s->req->wex);
		tv_min(&min2, &s->rep->rex, &s->rep->wex);
		tv_min(&min1, &min1, &s->req->cex);
		tv_min(&t->expire, &min1, &min2);

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
		s->be->beprm->beconn--;
	actconn--;
    
	if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
		int len;
		len = sprintf(trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->beprm->id,
			      (unsigned short)s->cli_fd, (unsigned short)s->srv_fd);
		write(1, trash, len);
	}

	s->logs.t_close = tv_diff(&s->logs.tv_accept, &now);
	if (s->rep != NULL)
		s->logs.bytes = s->rep->total;

	/* let's do a final log if we need it */
	if (s->logs.logwait && 
	    !(s->flags & SN_MONITOR) &&
	    (!(s->fe->options & PR_O_NULLNOLOG) || s->req->total))
		sess_log(s);

	/* the task MUST not be in the run queue anymore */
	task_delete(t);
	session_free(s);
	task_free(t);
	return TIME_ETERNITY; /* rest in peace for eternity */
}


/*
 * FIXME: This should move to the HTTP_flow_analyzer code
 */
    
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
	int delete_header = 0;

	int cur_hdr;

	DPRINTF(stderr,"process_cli: c=%s s=%s set(r,w)=%d,%d exp(r,w)=%d.%d,%d.%d\n",
		cli_stnames[c], srv_stnames[s],
		MY_FD_ISSET(t->cli_fd, StaticReadEvent), MY_FD_ISSET(t->cli_fd, StaticWriteEvent),
		req->rex.tv_sec, req->rex.tv_usec,
		rep->wex.tv_sec, rep->wex.tv_usec);

	if (c == CL_STHEADERS) {
		/*
		 * Now parse the partial (or complete) lines.
		 * We will check the request syntax, and also join multi-line
		 * headers. An index of all the lines will be elaborated while
		 * parsing.
		 *
		 * For the parsing, we use a 10 states FSM.
		 *
		 * RFC2616 requires that both LF and CRLF are recognized as
		 * line breaks, but that any other combination is an error.
		 * To avoid duplicating all the states above to check for CR,
		 * we use a special bit HTTP_PA_LF_EXP that we 'OR' with the
		 * state we will switch to if the LF is seen, so that we know
		 * whether there's a pending CR or not. We can check it
		 * globally since all CR followed by anything but LF are
		 * errors. Each state is entered with the first character is
		 * has to process at req->lr. We also have HTTP_PA_CR_SKIP
		 * indicating that a CR has been seen on current line and
		 * skipped.
		 *
		 * Here is the information we currently have :
		 *   req->data + req->sor  = beginning of request
		 *   req->data + req->eoh  = end of (parsed) headers
		 *   req->lr = first non-visited byte
		 *   req->r  = end of data
		 */

		char *sol, *eol; /* Start Of Line, End Of Line */
		struct proxy *cur_proxy;

		eol = sol = req->data + t->hreq.eoh;

		while (req->lr < req->r) {
			int parse;

			FSM_PRINTF(stderr, "WHL: hdr_st=0x%02x, hdr_used=%d hdr_tail=%d hdr_last=%d, h=%d, lr=%d, r=%d, eoh=%d\n",
				   t->hreq.hdr_state, t->hreq.hdr_idx.used, t->hreq.hdr_idx.tail, t->hreq.hdr_idx.last,
				   sol - req->data, req->lr - req->data, req->r - req->data, t->hreq.eoh);
			
			if (t->hreq.hdr_state & HTTP_PA_LF_EXP) {
				if (*req->lr != '\n') {
					t->hreq.hdr_state = HTTP_PA_ERROR;
					break;
				}
				t->hreq.hdr_state &= ~HTTP_PA_LF_EXP;
			}

			parse = t->hreq.hdr_state & ~HTTP_PA_CR_SKIP;;

			if (parse == HTTP_PA_HDR_LF) {
			parse_hdr_lf:
				/* The LF validating last header, but it
				 * may also be an LWS, in which case we will
				 * need more data to know if we can close this
				 * header or not. However, we must check right
				 * now if this LF/CRLF closes an empty line, in
				 * which case it means the end of the request.
				 */
				eol = req->lr;
				if (t->hreq.hdr_state & HTTP_PA_CR_SKIP)
					eol--; /* Get back to the CR */

				if (eol == sol) {
					/* We have found the end of the headers.
					 * sol points to the ending LF/CRLF,
					 * and req->lr points to the first byte
					 * after the LF, so it is easy to append
					 * anything there.
					 */
					t->hreq.hdr_state = HTTP_PA_LFLF;
					QUICK_JUMP(parse_lflf, continue);
				}

				if (req->lr + 1 >= req->r) /* LF, ?? */
					break;
				req->lr++;

				/* Right now, we *know* that there is one char
				 * available at req->lr.
				 */

				if (*req->lr == ' ' || *req->lr == '\t') {
					/* We have an LWS, we will replace the
					 * CR and LF with spaces as RFC2616
					 * allows it. <lr> now points to the
					 * first space char of the LWS part.
					 */
					for (;eol < req->lr; eol++)
						*eol = ' ';

					t->hreq.hdr_state = HTTP_PA_HDR_LWS;
					QUICK_JUMP(parse_hdr_lws, continue);
				}

				/**********************************************
				 * We now have one complete header between    *
				 * sol and eol, with a possible CR at eol, *
				 * everything ending before req->lr. Some very*
				 * early processing can be applied.           *
				 **********************************************/

				/*
				 * FIXME: insert a REQHEADER hook here.
				 * For instance, we could check the header's
				 * syntax such as forbidding the leading space
				 * in the first header (Apache also has the same problem)
				 */


				/* 1: we might have to print this header */
				if ((global.mode & MODE_DEBUG) &&
				    (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))
					debug_hdr("clihdr", t, sol, eol);


				/* 2: maybe we have to copy this header for the logs ? */
				if (t->logs.logwait & LW_REQHDR) {
					/* FIXME: we must *search* the value after the ':' and not
					 * consider that it's necessary after one single space.*/
					struct cap_hdr *h;
					int len;
					for (h = t->fe->fiprm->req_cap; h; h = h->next) {
						if ((h->namelen + 2 <= eol - sol) &&
						    (sol[h->namelen] == ':') &&
						    (strncasecmp(sol, h->name, h->namelen) == 0)) {
							if (t->hreq.cap[h->index] == NULL)
								t->hreq.cap[h->index] =
									pool_alloc_from(h->pool, h->len + 1);

							if (t->hreq.cap[h->index] == NULL) {
								Alert("HTTP capture : out of memory.\n");
								continue;
							}
							
							len = eol - (sol + h->namelen + 2);
							if (len > h->len)
								len = h->len;
							
							memcpy(t->hreq.cap[h->index], sol + h->namelen + 2, len);
							t->hreq.cap[h->index][len]=0;
						}
					}
				}


				/* 3: We might need to remove "connection:" */
				if (!delete_header && (t->fe->options & PR_O_HTTP_CLOSE)
				    && (strncasecmp(sol, "Connection:", 11) == 0)) {
					delete_header = 1;
				}


				/* OK, that's enough processing for the first step.
				 * Now either we index this header or we remove it.
				 */

				if (!delete_header) {
					/* we insert it into the index */
					if (hdr_idx_add(eol - sol, req->lr - eol - 1,
							&t->hreq.hdr_idx, t->hreq.hdr_idx.tail) < 0) {
						t->hreq.hdr_state = HTTP_PA_ERROR;
						break;
					}
				} else {
					/* we remove it */
					delete_header = 0;
					buffer_replace2(req, sol, req->lr, NULL, 0);
					/* WARNING: eol is not valid anymore, since the
					 * header may have been deleted or truncated ! */
				}
				
				/* In any case, we set the next header pointer
				 * to the next line.
				 */
				sol = req->lr;

#ifdef DEBUG_PARSE_NO_SPEEDUP
				t->hreq.hdr_state = HTTP_PA_HEADER;
				continue;
#else
				/*
				 * We know that at least one character remains.
				 * It is interesting to directly branch to the
				 * matching state.
				 */
				eol = req->lr;
				if (IS_CTL(*req->lr)) {
					if (*eol == '\r') {
						req->lr++;
						t->hreq.hdr_state = HTTP_PA_LFLF | HTTP_PA_LF_EXP;
						continue;
					}
					else if (*eol == '\n') {
						t->hreq.hdr_state = HTTP_PA_LFLF;
						goto parse_lflf;
					}
					else {
						t->hreq.hdr_state = HTTP_PA_ERROR;
						break;
					}
				}
				t->hreq.hdr_state = HTTP_PA_HEADER;
				goto parse_inside_hdr;
#endif

			} else if (parse == HTTP_PA_STRT_LF) {
			parse_strt_lf:
				/* The LF validating the request line */

				eol = req->lr;
				if (t->hreq.hdr_state & HTTP_PA_CR_SKIP)
					eol--; /* Get back to the CR */

				/* We have the complete start line between
				 * sol and eol (excluded). lr points to
				 * the LF.
				 */

				/* FIXME: insert a REQUESTURI hook here. */


				/* 1: we might have to print this header */
				if ((global.mode & MODE_DEBUG) &&
				    (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))
					debug_hdr("clireq", t, sol, eol);

				/* 2: maybe we have to copy the original REQURI for the logs ? */
				if (t->logs.logwait & LW_REQ) {
					/* we have a complete HTTP request that we must log */
					if ((t->logs.uri = pool_alloc(requri)) != NULL) {
						int urilen = eol - sol;

						if (urilen >= REQURI_LEN)
							urilen = REQURI_LEN - 1;
						memcpy(t->logs.uri, sol, urilen);
						t->logs.uri[urilen] = 0;

						if (!(t->logs.logwait &= ~LW_REQ))
							sess_log(t);
					} else {
						Alert("HTTP logging : out of memory.\n");
					}
				}

				/* 3: reference this line as the start line */
				if (hdr_idx_add(eol - sol, req->lr - eol,
						&t->hreq.hdr_idx, t->hreq.hdr_idx.tail) < 0) {
					t->hreq.hdr_state = HTTP_PA_ERROR;
					break;
				}

				req->lr++;
				sol = req->lr;
				/* in fact, a state is missing here, we should
				 * be able to distinguish between an empty line
				 * and a header.
				 */
				t->hreq.hdr_state = HTTP_PA_HEADER;
#ifdef DEBUG_PARSE_NO_SPEEDUP
				continue;
#else
				if (req->lr < req->r)
					goto parse_inside_hdr;
				else
					break;
#endif

			} else if (parse == HTTP_PA_HEADER) {
				char *ptr;
				/* Inside a non-empty header */

			parse_inside_hdr:
				delete_header = 0;

				ptr = req->lr;

#ifdef GCC_FINALLY_PRODUCES_EFFICIENT_WHILE_LOOPS
				/* This code is disabled right now because
				 * eventhough it seems straightforward, the
				 * object code produced by GCC is so much
				 * suboptimal that about 10% of the time
				 * spend parsing header is there.
				 */
				while (ptr < req->r && !IS_CTL(*ptr))
					ptr++;
				req->lr = ptr;
				if (ptr == req->r)
					break;
#else
				/* Just by using this loop instead of the previous one,
				 * the global performance increases by about 2% ! The
				 * code is also smaller by about 50 bytes.
				 */
				goto reqhdr_loop_chk;
			reqhdr_loop:
				ptr++;
			reqhdr_loop_chk:
				if (ptr == req->r) {
					req->lr = ptr;
					break;
				}
				if (*ptr != 0x7F && (unsigned)*ptr >= 0x20)
					goto reqhdr_loop;
				req->lr = ptr;
#endif

				/* we have a CTL char */
				if (*ptr == '\r') {
					t->hreq.hdr_state = HTTP_PA_HDR_LF | HTTP_PA_CR_SKIP | HTTP_PA_LF_EXP;
					req->lr++;
					continue;
				}
				else if (*ptr == '\n') {
					t->hreq.hdr_state = HTTP_PA_HDR_LF;
					QUICK_JUMP(parse_hdr_lf, continue);
				}
				t->hreq.hdr_state = HTTP_PA_ERROR;
				break;

			} else if (parse == HTTP_PA_EMPTY) {
				/* leading empty lines */

				if (*req->lr == '\n') {
					req->lr ++;
					t->hreq.hdr_state = HTTP_PA_EMPTY;
					continue;
				}
				else if (*req->lr == '\r') {
					req->lr ++;
					t->hreq.hdr_state = HTTP_PA_EMPTY | HTTP_PA_CR_SKIP | HTTP_PA_LF_EXP;
					continue;
				}				

				FSM_PRINTF(stderr, "PA_EMPTY[0]: h=%d, lr=%d, r=%d\n",
					sol - req->data, req->lr - req->data, req->r - req->data);

#if PARSE_PRESERVE_EMPTY_LINES
				/* only skip empty leading lines, don't remove them */
				t->hreq.hdr_idx.v[0].len = req->lr - sol;
				t->hreq.sor = t->hreq.hdr_idx.v[0].len;
#else
				/* remove empty leading lines, as recommended by
				 * RFC2616. This takes a lot of time because we
				 * must move all the buffer backwards, but this
				 * is rarely needed. The method above will be
				 * cleaner when we'll be able to start sending
				 * the request from any place in the buffer.
				 */
				buffer_replace2(req, sol, req->lr, NULL, 0);
#endif
				sol = req->lr;
				FSM_PRINTF(stderr, "PA_EMPTY[1]: h=%d, lr=%d, r=%d\n",
					sol - req->data, req->lr - req->data, req->r - req->data);

				t->hreq.hdr_state = HTTP_PA_START;
				/* we know that we still have one char available */
				QUICK_JUMP(parse_start, continue);

			} else if (parse == HTTP_PA_START) {
				char *ptr;
				/* Inside the start line */

			parse_start:
				ptr = req->lr;

#ifdef GCC_FINALLY_PRODUCES_EFFICIENT_WHILE_LOOPS
				/* This code is disabled right now because
				 * eventhough it seems straightforward, the
				 * object code produced by GCC is so much
				 * suboptimal that about 10% of the time
				 * spend parsing header is there.
				 */
				while (ptr < req->r && !IS_CTL(*ptr))
					ptr++;
				req->lr = ptr;
				if (ptr == req->r)
					break;
#else
				/* Just by using this loop instead of the previous one,
				 * the global performance increases by about 2% ! The
				 * code is also smaller by about 50 bytes.
				 */
				goto reqstrt_loop_chk;
			reqstrt_loop:
				ptr++;
			reqstrt_loop_chk:
				if (ptr == req->r) {
					req->lr = ptr;
					break;
				}
				if (*ptr != 0x7F && (unsigned)*ptr >= 0x20)
					goto reqstrt_loop;
				req->lr = ptr;
#endif

				/* we have a CTL char */
				if (*ptr == '\r') {
					req->lr++;
					t->hreq.hdr_state = HTTP_PA_STRT_LF | HTTP_PA_CR_SKIP | HTTP_PA_LF_EXP;
					continue;
				}
				else if (*ptr == '\n') {
					t->hreq.hdr_state = HTTP_PA_STRT_LF;
					/* we know that we still have one char available */
					QUICK_JUMP(parse_strt_lf, continue);
				}
				t->hreq.hdr_state = HTTP_PA_ERROR;
				break;


			} else if (parse == HTTP_PA_LFLF) {
			parse_lflf:
				req->lr ++;
				/* sol points to either CR or CRLF, and
				 * req->lr points to 1 char after LF.
				 */

				/*
				 * FIXME: insert a hook here for the end of the headers
				 */
				break;

			} else if (parse == HTTP_PA_HDR_LWS) {
			parse_hdr_lws:
				/* Inside an LWS. We just replace tabs with
				 * spaces and fall back to the HEADER state
				 * at the first non-space character
				 */

				while (req->lr < req->r) {
					if (*req->lr == '\t')
						*req->lr = ' ';
					else if (*req->lr != ' ') {
						t->hreq.hdr_state = HTTP_PA_HEADER;
						QUICK_JUMP(parse_inside_hdr, break);
					}
					req->lr++;
				}
				continue;

			} else if (parse == HTTP_PA_ERROR) {
				break;
			}

		} /* end of the "while(req->lr < req->r)" loop */

		/* update the end of headers */
		t->hreq.eoh = sol - req->data;

		FSM_PRINTF(stderr, "END: hdr_st=0x%02x, hdr_used=%d hdr_tail=%d hdr_last=%d, h=%d, lr=%d, r=%d, eoh=%d\n",
			t->hreq.hdr_state, t->hreq.hdr_idx.used, t->hreq.hdr_idx.tail, t->hreq.hdr_idx.last,
			sol - req->data, req->lr - req->data, req->r - req->data, t->hreq.eoh);

		/*
		 * Now, let's catch bad requests.
		 */

		if (t->hreq.hdr_state == HTTP_PA_ERROR)
			goto return_bad_req;

		/*
		 * Now we quickly check if we have found a full request.
		 * If not so, we check the FD and buffer states before leaving.
		 * A full request is indicated by the fact that we have seen
		 * the double LF/CRLF, so the state is HTTP_PA_LFLF.
		 *
		 */

		if (t->hreq.hdr_state != HTTP_PA_LFLF) {	/* Request not complete yet */

			/* 1: Since we are in header mode, if there's no space
			 *    left for headers, we won't be able to free more
			 *    later, so the session will never terminate. We
			 *    must terminate it now.
			 */
			if (req->l >= req->rlim - req->data) {
				/* FIXME: check if hreq.hdr_state & mask < HTTP_PA_HEADER,
				 * and return Status 414 Request URI too long instead.
				 */
				goto return_bad_req;
			}

			/* 2: have we encountered a read error or a close ? */
			else if (req->flags & (BF_READ_ERROR | BF_READ_NULL)) {
				/* read error, or last read : give up.  */
				tv_eternity(&req->rex);
				fd_delete(t->cli_fd);
				t->cli_state = CL_STCLOSE;
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLICL;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_R;
				return 1;
			}

			/* 3: has the read timeout expired ? */
			else if (tv_cmp2_ms(&req->rex, &now) <= 0) {
				/* read timeout : give up with an error message. */
				t->logs.status = 408;
				client_retnclose(t, t->fe->errmsg.len408, t->fe->errmsg.msg408);
				if (!(t->flags & SN_ERR_MASK))
					t->flags |= SN_ERR_CLITO;
				if (!(t->flags & SN_FINST_MASK))
					t->flags |= SN_FINST_R;
				return 1;
			}

			/* 4: do we need to re-enable the read socket ? */
			else if (! MY_FD_ISSET(t->cli_fd, StaticReadEvent)) {
				/* fd in StaticReadEvent was disabled, perhaps because of a previous buffer
				 * full. We cannot loop here since stream_sock_read will disable it only if
				 * req->l == rlim-data
				 */
				MY_FD_SET(t->cli_fd, StaticReadEvent);
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
		 * 1: check if the URI matches the monitor_uri.
		 * We have to do this for every request which gets in, because
		 * the monitor-uri is defined by the frontend. To speed-up the
		 * test, we include the leading and trailing spaces in the
		 * comparison. This is generally not a problem because the
		 * monitor-uri is primarily used by external checkers which
		 * send pre-formatted requests too.
		 */

		t->hreq.start.str = req->data + t->hreq.sor;      /* start of the REQURI */
		t->hreq.start.len = t->hreq.hdr_idx.v[t->hreq.hdr_idx.v[0].next].len; /* end of the REQURI */
		t->hreq.meth = find_http_meth(t->hreq.start.str, t->hreq.start.len);

		if ((t->fe->monitor_uri_len != 0) &&
		    (t->hreq.start.len >= t->fe->monitor_uri_len)) {
			char *p = t->hreq.start.str;
			int idx = 0;

			/* skip the method so that we accept any method */
			while (idx < t->hreq.start.len && p[idx] != ' ')
				idx++;
			p += idx;
			
			if (t->hreq.start.len - idx >= t->fe->monitor_uri_len &&
			    !memcmp(p, t->fe->monitor_uri, t->fe->monitor_uri_len)) {
				/*
				 * We have found the monitor URI
				 */
				t->flags |= SN_MONITOR;
				t->logs.status = 200;
				client_retnclose(t, strlen(HTTP_200), HTTP_200);
				goto return_prx_cond;
			}
		}


		/*
		 * 2: we will have to evaluate the filters.
		 * As opposed to version 1.2, now they will be evaluated in the
		 * filters order and not in the header order. This means that
		 * each filter has to be validated among all headers.
		 *
		 * We can now check whether we want to switch to another
		 * backend, in which case we will re-check the backend's
		 * filters and various options. In order to support 3-level
		 * switching, here's how we should proceed :
		 *
		 *  a) run be->fiprm.
		 *     if (switch) then switch ->be to the new backend.
		 *  b) run be->fiprm if (be != fe).
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
			struct proxy *rule_set = t->be->fiprm;
			cur_proxy = t->be;

			/* try headers filters */
			if (rule_set->req_exp != NULL) {
				apply_filters_to_session(t, req, rule_set->req_exp);

				/* the start line might have been modified */
				t->hreq.start.len = t->hreq.hdr_idx.v[t->hreq.hdr_idx.v[0].next].len;
				t->hreq.meth = find_http_meth(t->hreq.start.str, t->hreq.start.len);
			}

			if (!(t->flags & SN_BE_ASSIGNED) && (t->be != cur_proxy)) {
				/* to ensure correct connection accounting on
				 * the backend, we count the connection for the
				 * one managing the queue.
				 */
				t->be->beprm->beconn++;
				if (t->be->beprm->beconn > t->be->beprm->beconn_max)
					t->be->beprm->beconn_max = t->be->beprm->beconn;
				t->be->beprm->cum_beconn++;
				t->flags |= SN_BE_ASSIGNED;
			}

			/* has the request been denied ? */
			if (t->flags & SN_CLDENY) {
				/* no need to go further */
				t->logs.status = 403;
				/* let's log the request time */
				t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);
				client_retnclose(t, t->fe->errmsg.len403, t->fe->errmsg.msg403);
				goto return_prx_cond;
			}

			/* add request headers from the rule sets in the same order */
			for (cur_hdr = 0; cur_hdr < rule_set->nb_reqadd; cur_hdr++) {
				int len;

				len = sprintf(trash, "%s\r\n", rule_set->req_add[cur_hdr]);
				len = buffer_replace2(req, req->data + t->hreq.eoh,
						      req->data + t->hreq.eoh, trash, len);
				t->hreq.eoh += len;
				
				if (hdr_idx_add(len - 2, 1, &t->hreq.hdr_idx, t->hreq.hdr_idx.tail) < 0)
					goto return_bad_req;
			}

			if (rule_set->uri_auth != NULL && t->hreq.meth == HTTP_METH_GET) {
				/* we have to check the URI and auth for this request */
				if (stats_check_uri_auth(t, rule_set))
					return 1;
			}

		} while (cur_proxy != t->be);  /* we loop only if t->be has changed */
		

		if (!(t->flags & SN_BE_ASSIGNED)) {
			/* To ensure correct connection accounting on
			 * the backend, we count the connection for the
			 * one managing the queue.
			 */
			t->be->beprm->beconn++;
			if (t->be->beprm->beconn > t->be->beprm->beconn_max)
				t->be->beprm->beconn_max = t->be->beprm->beconn;
			t->be->beprm->cum_beconn++;
			t->flags |= SN_BE_ASSIGNED;
		}


		/*
		 * Right now, we know that we have processed the entire headers
		 * and that unwanted requests have been filtered out. We can do
		 * whatever we want with the remaining request. Also, now we
		 * may have separate values for ->fe, ->be.
		 */




		/*
		 * 3: the appsession cookie was looked up very early in 1.2,
		 * so let's do the same now.
		 */

		/* It needs to look into the URI */
		if (t->be->beprm->appsession_name) {
			get_srv_from_appsession(t,
						t->hreq.start.str,
						t->hreq.start.str + t->hreq.start.len);
		}


		/*
		 * 4: Now we can work with the cookies.
		 * Note that doing so might move headers in the request, but
		 * the fields will stay coherent and the URI will not move.
		 * This should only be performed in the backend.
		 */
		if (!(t->flags & (SN_CLDENY|SN_CLTARPIT)))
			manage_client_side_cookies(t, req);


		/*
		 * 5: add X-Forwarded-For : Should depend on the backend only.
		 */
		if (t->be->beprm->options & PR_O_FWDFOR) {
			if (t->cli_addr.ss_family == AF_INET) {
				int len;
				unsigned char *pn;
				pn = (unsigned char *)&((struct sockaddr_in *)&t->cli_addr)->sin_addr;
				len = sprintf(trash, "X-Forwarded-For: %d.%d.%d.%d\r\n",
					      pn[0], pn[1], pn[2], pn[3]);
				len = buffer_replace2(req, req->data + t->hreq.eoh,
						      req->data + t->hreq.eoh, trash, len);
				t->hreq.eoh += len;

				if (hdr_idx_add(len - 2, 1, &t->hreq.hdr_idx, t->hreq.hdr_idx.tail) < 0)
					goto return_bad_req;
			}
			else if (t->cli_addr.ss_family == AF_INET6) {
				int len;
				char pn[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&t->cli_addr))->sin6_addr,
					  pn, sizeof(pn));
				len = sprintf(trash, "X-Forwarded-For: %s\r\n", pn);
				len = buffer_replace2(req, req->data + t->hreq.eoh,
						      req->data + t->hreq.eoh, trash, len);
				t->hreq.eoh += len;

				if (hdr_idx_add(len - 2, 1, &t->hreq.hdr_idx, t->hreq.hdr_idx.tail) < 0)
					goto return_bad_req;
			}
		}


		/*
		 * 6: add "Connection:"
		 */

		/* add a "connection: close" line if needed.
		 * FIXME: this should depend on both the frontend and the backend.
		 * Header removals should be performed when the filters are run.
		 */
		if (t->fe->options & PR_O_HTTP_CLOSE) {
			int len;
			len = buffer_replace2(req, req->data + t->hreq.eoh,
					      req->data + t->hreq.eoh, "Connection: close\r\n", 19);
			t->hreq.eoh += len;

			if (hdr_idx_add(17, 1, &t->hreq.hdr_idx, t->hreq.hdr_idx.tail) < 0)
				goto return_bad_req;
		}




		

		/*************************************************************
		 * OK, that's finished for the headers. We have done what we *
		 * could. Let's switch to the DATA state.                    *
		 ************************************************************/

		t->cli_state = CL_STDATA;
		req->rlim = req->data + BUFSIZE; /* no more rewrite needed */

		t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);


		if (!t->fe->clitimeout ||
		    (t->srv_state < SV_STDATA && t->be->beprm->srvtimeout)) {
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
		if (t->flags & SN_CLTARPIT) {
			t->req->l = 0;
			/* flush the request so that we can drop the connection early
			 * if the client closes first.
			 */
			tv_delayfrom(&req->cex, &now,
				     t->be->beprm->contimeout ? t->be->beprm->contimeout : 0);
		}

#if DEBUG_HTTP_PARSER
		/* example: dump each line */

		fprintf(stderr, "t->flags=0x%08x\n", t->flags & (SN_CLALLOW|SN_CLDENY|SN_CLTARPIT));

		fprintf(stderr, "sol=%d\n", sol - req->data);
		sol = req->data + t->hreq.sor;
		cur_hdr = 0;

		cur_idx = t->hreq.hdr_idx.v[0].next;
		cur_hdr = 1;

		while (cur_hdr < t->hreq.hdr_idx.used) {
			eol = sol + t->hreq.hdr_idx.v[cur_idx].len + t->hreq.hdr_idx.v[cur_idx].cr + 1;
			fprintf(stderr, "lr=%d r=%d hdr=%d idx=%d adr=%d..%d len=%d cr=%d data:\n",
				req->lr - req->data, req->r - req->data,
				cur_hdr, cur_idx,
				sol - req->data,
				sol - req->data + t->hreq.hdr_idx.v[cur_idx].len + t->hreq.hdr_idx.v[cur_idx].cr,
				t->hreq.hdr_idx.v[cur_idx].len,
				t->hreq.hdr_idx.v[cur_idx].cr);
			write(2, sol, eol - sol);

			sol = eol;
			cur_idx = t->hreq.hdr_idx.v[cur_idx].next;
			cur_hdr++;
		}
#endif

		goto process_data;

	return_bad_req: /* let's centralize all bad requests */
		t->hreq.hdr_state = HTTP_PA_ERROR;
		t->logs.status = 400;
		client_retnclose(t, t->fe->errmsg.len400, t->fe->errmsg.msg400);
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
			MY_FD_CLR(t->cli_fd, StaticReadEvent);
			tv_eternity(&req->rex);
			shutdown(t->cli_fd, SHUT_RD);
			t->cli_state = CL_STSHUTR;
			return 1;
		}	
		/* last server read and buffer empty */
		else if ((s == SV_STSHUTR || s == SV_STCLOSE) && (rep->l == 0)) {
			MY_FD_CLR(t->cli_fd, StaticWriteEvent);
			tv_eternity(&rep->wex);
			shutdown(t->cli_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->cli_fd, StaticReadEvent);
			if (t->fe->clitimeout)
				tv_delayfrom(&req->rex, &now, t->fe->clitimeout);
			t->cli_state = CL_STSHUTW;
			//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			return 1;
		}
		/* read timeout */
		else if (tv_cmp2_ms(&req->rex, &now) <= 0) {
			MY_FD_CLR(t->cli_fd, StaticReadEvent);
			tv_eternity(&req->rex);
			shutdown(t->cli_fd, SHUT_RD);
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
		else if (tv_cmp2_ms(&rep->wex, &now) <= 0) {
			MY_FD_CLR(t->cli_fd, StaticWriteEvent);
			tv_eternity(&rep->wex);
			shutdown(t->cli_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->cli_fd, StaticReadEvent);
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
			if (MY_FD_ISSET(t->cli_fd, StaticReadEvent)) {
				/* stop reading until we get some space */
				MY_FD_CLR(t->cli_fd, StaticReadEvent);
				tv_eternity(&req->rex);
			}
		} else {
			/* there's still some space in the buffer */
			if (! MY_FD_ISSET(t->cli_fd, StaticReadEvent)) {
				MY_FD_SET(t->cli_fd, StaticReadEvent);
				if (!t->fe->clitimeout ||
				    (t->srv_state < SV_STDATA && t->be->beprm->srvtimeout))
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
			if (MY_FD_ISSET(t->cli_fd, StaticWriteEvent)) {
				MY_FD_CLR(t->cli_fd, StaticWriteEvent); /* stop writing */
				tv_eternity(&rep->wex);
			}
		} else {
			/* buffer not empty */
			if (! MY_FD_ISSET(t->cli_fd, StaticWriteEvent)) {
				MY_FD_SET(t->cli_fd, StaticWriteEvent); /* restart writing */
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
		else if (tv_cmp2_ms(&rep->wex, &now) <= 0) {
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
			if (MY_FD_ISSET(t->cli_fd, StaticWriteEvent)) {
				MY_FD_CLR(t->cli_fd, StaticWriteEvent); /* stop writing */
				tv_eternity(&rep->wex);
			}
		} else {
			/* buffer not empty */
			if (! MY_FD_ISSET(t->cli_fd, StaticWriteEvent)) {
				MY_FD_SET(t->cli_fd, StaticWriteEvent); /* restart writing */
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
		else if (tv_cmp2_ms(&req->rex, &now) <= 0) {
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

			if (MY_FD_ISSET(t->cli_fd, StaticReadEvent)) {
				/* stop reading until we get some space */
				MY_FD_CLR(t->cli_fd, StaticReadEvent);
				tv_eternity(&req->rex);
				//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			}
		} else {
			/* there's still some space in the buffer */
			if (! MY_FD_ISSET(t->cli_fd, StaticReadEvent)) {
				MY_FD_SET(t->cli_fd, StaticReadEvent);
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
			len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n", t->uniq_id, t->be->beprm->id, (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
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
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;
	appsess *asession_temp = NULL;
	appsess local_asession;
	int conn_err;

#ifdef DEBUG_FULL
	fprintf(stderr,"process_srv: c=%s, s=%s\n", cli_stnames[c], srv_stnames[s]);
#endif
	//fprintf(stderr,"process_srv: c=%d, s=%d, cr=%d, cw=%d, sr=%d, sw=%d\n", c, s,
	//MY_FD_ISSET(t->cli_fd, StaticReadEvent), MY_FD_ISSET(t->cli_fd, StaticWriteEvent),
	//MY_FD_ISSET(t->srv_fd, StaticReadEvent), MY_FD_ISSET(t->srv_fd, StaticWriteEvent)
	//);
	if (s == SV_STIDLE) {
		if (c == CL_STHEADERS)
			return 0;	/* stay in idle, waiting for data to reach the client side */
		else if (c == CL_STCLOSE || c == CL_STSHUTW ||
			 (c == CL_STSHUTR &&
			  (t->req->l == 0 || t->be->beprm->options & PR_O_ABRT_CLOSE))) { /* give up */
			tv_eternity(&req->cex);
			if (t->pend_pos)
				t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
			/* note that this must not return any error because it would be able to
			 * overwrite the client_retnclose() output.
			 */
			if (t->flags & SN_CLTARPIT)
				srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_T, 0, 0, NULL);
			else
				srv_close_with_err(t, SN_ERR_CLICL, t->pend_pos ? SN_FINST_Q : SN_FINST_C, 0, 0, NULL);

			return 1;
		}
		else {
			if (t->flags & SN_CLTARPIT) {
				/* This connection is being tarpitted. The CLIENT side has
				 * already set the connect expiration date to the right
				 * timeout. We just have to check that it has not expired.
				 */
				if (tv_cmp2_ms(&req->cex, &now) > 0)
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
						   500, t->fe->errmsg.len500, t->fe->errmsg.msg500);
				return 1;
			}

			/* Right now, we will need to create a connection to the server.
			 * We might already have tried, and got a connection pending, in
			 * which case we will not do anything till it's pending. It's up
			 * to any other session to release it and wake us up again.
			 */
			if (t->pend_pos) {
				if (tv_cmp2_ms(&req->cex, &now) > 0)
					return 0;
				else {
					/* we've been waiting too long here */
					tv_eternity(&req->cex);
					t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
					srv_close_with_err(t, SN_ERR_SRVTO, SN_FINST_Q,
							   503, t->fe->errmsg.len503, t->fe->errmsg.msg503);
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
		     (t->req->l == 0 || t->be->beprm->options & PR_O_ABRT_CLOSE))) { /* give up */
			tv_eternity(&req->cex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;

			/* note that this must not return any error because it would be able to
			 * overwrite the client_retnclose() output.
			 */
			srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_C, 0, 0, NULL);
			return 1;
		}
		if (!(req->flags & BF_WRITE_STATUS) && tv_cmp2_ms(&req->cex, &now) > 0) {
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

			if (t->srv && t->conn_retries == 0 && t->be->beprm->options & PR_O_REDISP) {
				/* We're on our last chance, and the REDISP option was specified.
				 * We will ignore cookie and force to balance or use the dispatcher.
				 */
				/* let's try to offer this slot to anybody */
				if (may_dequeue_tasks(t->srv, t->be->beprm))
					task_wakeup(&rq, t->srv->queue_mgt);

				if (t->srv)
					t->srv->failed_conns++;
				t->be->beprm->failed_conns++;

				t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
				t->srv = NULL; /* it's left to the dispatcher to choose a server */
				if ((t->flags & SN_CK_MASK) == SN_CK_VALID) {
					t->flags &= ~SN_CK_MASK;
					t->flags |= SN_CK_DOWN;
				}

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
				MY_FD_CLR(t->srv_fd, StaticWriteEvent);
				tv_eternity(&req->wex);
			} else  /* need the right to write */ {
				MY_FD_SET(t->srv_fd, StaticWriteEvent);
				if (t->be->beprm->srvtimeout) {
					tv_delayfrom(&req->wex, &now, t->be->beprm->srvtimeout);
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it. */
					rep->rex = req->wex;
				}
				else
					tv_eternity(&req->wex);
			}

			if (t->be->beprm->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
				MY_FD_SET(t->srv_fd, StaticReadEvent);
				if (t->be->beprm->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);
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
					sess_log(t);
				}
			}
			else {
				t->srv_state = SV_STHEADERS;
				if (t->srv)
					t->srv->cum_sess++;
				rep->rlim = rep->data + BUFSIZE - MAXREWRITE; /* rewrite needed */
			}
			tv_eternity(&req->cex);
			return 1;
		}
	}
	else if (s == SV_STHEADERS) { /* receiving server headers */
		/* now parse the partial (or complete) headers */
		while (rep->lr < rep->r) { /* this loop only sees one header at each iteration */
			char *ptr;
			int delete_header;

			ptr = rep->lr;

			/* look for the end of the current header */
			while (ptr < rep->r && *ptr != '\n' && *ptr != '\r')
				ptr++;
	    
			if (ptr == rep->h) {
				int line, len;

				/* we can only get here after an end of headers */

				/* first, we'll block if security checks have caught nasty things */
				if (t->flags & SN_CACHEABLE) {
					if ((t->flags & SN_CACHE_COOK) &&
					    (t->flags & SN_SCK_ANY) &&
					    (t->be->beprm->options & PR_O_CHK_CACHE)) {

						/* we're in presence of a cacheable response containing
						 * a set-cookie header. We'll block it as requested by
						 * the 'checkcache' option, and send an alert.
						 */
						tv_eternity(&rep->rex);
						tv_eternity(&req->wex);
						fd_delete(t->srv_fd);
						if (t->srv) {
							t->srv->cur_sess--;
							t->srv->failed_secu++;
						}
						t->be->failed_secu++;
						t->srv_state = SV_STCLOSE;
						t->logs.status = 502;
						client_return(t, t->fe->errmsg.len502, t->fe->errmsg.msg502);
						if (!(t->flags & SN_ERR_MASK))
							t->flags |= SN_ERR_PRXCOND;
						if (!(t->flags & SN_FINST_MASK))
							t->flags |= SN_FINST_H;

						Alert("Blocking cacheable cookie in response from instance %s, server %s.\n", t->be->beprm->id, t->srv->id);
						send_log(t->be, LOG_ALERT, "Blocking cacheable cookie in response from instance %s, server %s.\n", t->be->beprm->id, t->srv->id);

						/* We used to have a free connection slot. Since we'll never use it,
						 * we have to inform the server that it may be used by another session.
						 */
						if (may_dequeue_tasks(t->srv, t->be->beprm))
							task_wakeup(&rq, t->srv->queue_mgt);

						return 1;
					}
				}

				/* next, we'll block if an 'rspideny' or 'rspdeny' filter matched */
				if (t->flags & SN_SVDENY) {
					tv_eternity(&rep->rex);
					tv_eternity(&req->wex);
					fd_delete(t->srv_fd);
					if (t->srv) {
						t->srv->cur_sess--;
						t->srv->failed_secu++;
					}
					t->be->failed_secu++;
					t->srv_state = SV_STCLOSE;
					t->logs.status = 502;
					client_return(t, t->fe->errmsg.len502, t->fe->errmsg.msg502);
					if (!(t->flags & SN_ERR_MASK))
						t->flags |= SN_ERR_PRXCOND;
					if (!(t->flags & SN_FINST_MASK))
						t->flags |= SN_FINST_H;
					/* We used to have a free connection slot. Since we'll never use it,
					 * we have to inform the server that it may be used by another session.
					 */
					if (may_dequeue_tasks(t->srv, t->be->beprm))
						task_wakeup(&rq, t->srv->queue_mgt);

					return 1;
				}

				/* we'll have something else to do here : add new headers ... */

				if ((t->srv) && !(t->flags & SN_DIRECT) && (t->be->beprm->options & PR_O_COOK_INS) &&
				    (!(t->be->beprm->options & PR_O_COOK_POST) || (t->hreq.meth == HTTP_METH_POST))) {
					/* the server is known, it's not the one the client requested, we have to
					 * insert a set-cookie here, except if we want to insert only on POST
					 * requests and this one isn't. Note that servers which don't have cookies
					 * (eg: some backup servers) will return a full cookie removal request.
					 */
					len = sprintf(trash, "Set-Cookie: %s=%s; path=/\r\n",
						      t->be->beprm->cookie_name,
						      t->srv->cookie ? t->srv->cookie : "; Expires=Thu, 01-Jan-1970 00:00:01 GMT");

					t->flags |= SN_SCK_INSERTED;

					/* Here, we will tell an eventual cache on the client side that we don't
					 * want it to cache this reply because HTTP/1.0 caches also cache cookies !
					 * Some caches understand the correct form: 'no-cache="set-cookie"', but
					 * others don't (eg: apache <= 1.3.26). So we use 'private' instead.
					 */
					if (t->be->beprm->options & PR_O_COOK_NOC)
						//len += sprintf(newhdr + len, "Cache-control: no-cache=\"set-cookie\"\r\n");
						len += sprintf(trash + len, "Cache-control: private\r\n");

					if (rep->data + rep->l < rep->h)
						/* The data has been stolen, we will crash cleanly instead of corrupting memory */
						*(int *)0 = 0;
					buffer_replace2(rep, rep->h, rep->h, trash, len);
				}

				/* headers to be added */
				/* FIXME: we should add headers from BE then from FE */
				for (line = 0; line < t->be->fiprm->nb_rspadd; line++) {
					len = sprintf(trash, "%s\r\n", t->be->fiprm->rsp_add[line]);
					buffer_replace2(rep, rep->h, rep->h, trash, len);
				}

				/* add a "connection: close" line if needed */
				if (t->fe->options & PR_O_HTTP_CLOSE)
					buffer_replace2(rep, rep->h, rep->h, "Connection: close\r\n", 19);

				t->srv_state = SV_STDATA;
				rep->rlim = rep->data + BUFSIZE; /* no more rewrite needed */
				t->logs.t_data = tv_diff(&t->logs.tv_accept, &now);

				/* client connection already closed or option 'httpclose' required :
				 * we close the server's outgoing connection right now.
				 */
				if ((req->l == 0) &&
				    (c == CL_STSHUTR || c == CL_STCLOSE || t->be->beprm->options & PR_O_FORCE_CLO)) {
					MY_FD_CLR(t->srv_fd, StaticWriteEvent);
					tv_eternity(&req->wex);

					/* We must ensure that the read part is still alive when switching
					 * to shutw */
					MY_FD_SET(t->srv_fd, StaticReadEvent);
					if (t->be->beprm->srvtimeout)
						tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);

					shutdown(t->srv_fd, SHUT_WR);
					t->srv_state = SV_STSHUTW;
				}

				/* if the user wants to log as soon as possible, without counting
				   bytes from the server, then this is the right moment. */
				if (t->fe->to_log && !(t->logs.logwait & LW_BYTES)) {
					t->logs.t_close = t->logs.t_data; /* to get a valid end date */
					t->logs.bytes = rep->h - rep->data;
					sess_log(t);
				}
				break;
			}

			/* to get a complete header line, we need the ending \r\n, \n\r, \r or \n too */
			if (ptr > rep->r - 2) {
				/* this is a partial header, let's wait for more to come */
				rep->lr = ptr;
				break;
			}

			//	    fprintf(stderr,"h=%p, ptr=%p, lr=%p, r=%p, *h=", rep->h, ptr, rep->lr, rep->r);
			//	    write(2, rep->h, ptr - rep->h);   fprintf(stderr,"\n");

			/* now we know that *ptr is either \r or \n,
			 * and that there are at least 1 char after it.
			 */
			if ((ptr[0] == ptr[1]) || (ptr[1] != '\r' && ptr[1] != '\n'))
				rep->lr = ptr + 1; /* \r\r, \n\n, \r[^\n], \n[^\r] */
			else
				rep->lr = ptr + 2; /* \r\n or \n\r */

			/*
			 * now we know that we have a full header ; we can do whatever
			 * we want with these pointers :
			 *   rep->h  = beginning of header
			 *   ptr     = end of header (first \r or \n)
			 *   rep->lr = beginning of next line (next rep->h)
			 *   rep->r  = end of data (not used at this stage)
			 */


			if (t->logs.status == -1) {
				t->logs.logwait &= ~LW_RESP;
				t->logs.status = atoi(rep->h + 9);
				switch (t->logs.status) {
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
					if (!(t->hreq.meth == HTTP_METH_POST) && (t->be->beprm->options & PR_O_CHK_CACHE))
						t->flags |= SN_CACHEABLE | SN_CACHE_COOK;
					break;
				default:
					break;
				}
			}
			else if (t->logs.logwait & LW_RSPHDR) {
				struct cap_hdr *h;
				int len;
				for (h = t->fe->fiprm->rsp_cap; h; h = h->next) {
					if ((h->namelen + 2 <= ptr - rep->h) &&
					    (rep->h[h->namelen] == ':') &&
					    (strncasecmp(rep->h, h->name, h->namelen) == 0)) {

						if (t->rsp_cap[h->index] == NULL)
							t->rsp_cap[h->index] = pool_alloc_from(h->pool, h->len + 1);

						len = ptr - (rep->h + h->namelen + 2);
						if (len > h->len)
							len = h->len;

						memcpy(t->rsp_cap[h->index], rep->h + h->namelen + 2, len);
						t->rsp_cap[h->index][len]=0;
					}
				}
		
			}

			delete_header = 0;

			if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))
				debug_hdr("srvhdr", t, rep->h, ptr);

			/* remove "connection: " if needed */
			if (!delete_header && (t->fe->options & PR_O_HTTP_CLOSE)
			    && (strncasecmp(rep->h, "Connection: ", 12) == 0)) {
				delete_header = 1;
			}

			/* try headers regexps */
			if (!delete_header && t->be->fiprm->rsp_exp != NULL
			    && !(t->flags & SN_SVDENY)) {
				struct hdr_exp *exp;
				char term;
		
				term = *ptr;
				*ptr = '\0';
				exp = t->be->fiprm->rsp_exp;
				do {
					if (regexec(exp->preg, rep->h, MAX_MATCH, pmatch, 0) == 0) {
						switch (exp->action) {
						case ACT_ALLOW:
							if (!(t->flags & SN_SVDENY))
								t->flags |= SN_SVALLOW;
							break;
						case ACT_REPLACE:
							if (!(t->flags & SN_SVDENY)) {
								int len = exp_replace(trash, rep->h, exp->replace, pmatch);
								ptr += buffer_replace2(rep, rep->h, ptr, trash, len);
							}
							break;
						case ACT_REMOVE:
							if (!(t->flags & SN_SVDENY))
								delete_header = 1;
							break;
						case ACT_DENY:
							if (!(t->flags & SN_SVALLOW))
								t->flags |= SN_SVDENY;
							break;
						case ACT_PASS: /* we simply don't deny this one */
							break;
						}
						break;
					}
				} while ((exp = exp->next) != NULL);
				*ptr = term; /* restore the string terminator */
			}
	    
			/* check for cache-control: or pragma: headers */
			if (!delete_header && (t->flags & SN_CACHEABLE)) {
				if (strncasecmp(rep->h, "Pragma: no-cache", 16) == 0)
					t->flags &= ~SN_CACHEABLE & ~SN_CACHE_COOK;
				else if (strncasecmp(rep->h, "Cache-control: ", 15) == 0) {
					if (strncasecmp(rep->h + 15, "no-cache", 8) == 0) {
						if (rep->h + 23 == ptr || rep->h[23] == ',')
							t->flags &= ~SN_CACHEABLE & ~SN_CACHE_COOK;
						else {
							if (strncasecmp(rep->h + 23, "=\"set-cookie", 12) == 0
							    && (rep->h[35] == '"' || rep->h[35] == ','))
								t->flags &= ~SN_CACHE_COOK;
						}
					} else if ((strncasecmp(rep->h + 15, "private", 7) == 0 &&
						    (rep->h + 22 == ptr || rep->h[22] == ','))
						   || (strncasecmp(rep->h + 15, "no-store", 8) == 0 &&
						       (rep->h + 23 == ptr || rep->h[23] == ','))) {
						t->flags &= ~SN_CACHEABLE & ~SN_CACHE_COOK;
					} else if (strncasecmp(rep->h + 15, "max-age=0", 9) == 0 &&
						   (rep->h + 24 == ptr || rep->h[24] == ',')) {
						t->flags &= ~SN_CACHEABLE & ~SN_CACHE_COOK;
					} else if (strncasecmp(rep->h + 15, "s-maxage=0", 10) == 0 &&
						   (rep->h + 25 == ptr || rep->h[25] == ',')) {
						t->flags &= ~SN_CACHEABLE & ~SN_CACHE_COOK;
					} else if (strncasecmp(rep->h + 15, "public", 6) == 0 &&
						   (rep->h + 21 == ptr || rep->h[21] == ',')) {
						t->flags |= SN_CACHEABLE | SN_CACHE_COOK;
					}
				}
			}

			/* check for server cookies */
			if (!delete_header /*&& (t->proxy->options & PR_O_COOK_ANY)*/
			    && (t->be->beprm->cookie_name != NULL ||
				t->be->fiprm->capture_name != NULL ||
				t->be->beprm->appsession_name !=NULL)
			    && (strncasecmp(rep->h, "Set-Cookie: ", 12) == 0)) {
				char *p1, *p2, *p3, *p4;
		
				t->flags |= SN_SCK_ANY;

				p1 = rep->h + 12; /* first char after 'Set-Cookie: ' */
		
				while (p1 < ptr) { /* in fact, we'll break after the first cookie */
					while (p1 < ptr && (isspace((int)*p1)))
						p1++;
		    
					if (p1 == ptr || *p1 == ';') /* end of cookie */
						break;
		    
					/* p1 is at the beginning of the cookie name */
					p2 = p1;
		    
					while (p2 < ptr && *p2 != '=' && *p2 != ';')
						p2++;
		    
					if (p2 == ptr || *p2 == ';') /* next cookie */
						break;
		    
					p3 = p2 + 1; /* skips the '=' sign */
					if (p3 == ptr)
						break;
		    
					p4 = p3;
					while (p4 < ptr && !isspace((int)*p4) && *p4 != ';')
						p4++;
		    
					/* here, we have the cookie name between p1 and p2,
					 * and its value between p3 and p4.
					 * we can process it.
					 */

					/* first, let's see if we want to capture it */
					if (t->be->fiprm->capture_name != NULL &&
					    t->logs.srv_cookie == NULL &&
					    (p4 - p1 >= t->be->fiprm->capture_namelen) &&
					    memcmp(p1, t->be->fiprm->capture_name, t->be->fiprm->capture_namelen) == 0) {
						int log_len = p4 - p1;

						if ((t->logs.srv_cookie = pool_alloc(capture)) == NULL) {
							Alert("HTTP logging : out of memory.\n");
						}

						if (log_len > t->be->fiprm->capture_len)
							log_len = t->be->fiprm->capture_len;
						memcpy(t->logs.srv_cookie, p1, log_len);
						t->logs.srv_cookie[log_len] = 0;
					}

					if ((p2 - p1 == t->be->beprm->cookie_len) && (t->be->beprm->cookie_name != NULL) &&
					    (memcmp(p1, t->be->beprm->cookie_name, p2 - p1) == 0)) {
						/* Cool... it's the right one */
						t->flags |= SN_SCK_SEEN;
			
						/* If the cookie is in insert mode on a known server, we'll delete
						 * this occurrence because we'll insert another one later.
						 * We'll delete it too if the "indirect" option is set and we're in
						 * a direct access. */
						if (((t->srv) && (t->be->beprm->options & PR_O_COOK_INS)) ||
						    ((t->flags & SN_DIRECT) && (t->be->beprm->options & PR_O_COOK_IND))) {
							/* this header must be deleted */
							delete_header = 1;
							t->flags |= SN_SCK_DELETED;
						}
						else if ((t->srv) && (t->be->beprm->options & PR_O_COOK_RW)) {
							/* replace bytes p3->p4 with the cookie name associated
							 * with this server since we know it.
							 */
							buffer_replace2(rep, p3, p4, t->srv->cookie, t->srv->cklen);
							t->flags |= SN_SCK_INSERTED | SN_SCK_DELETED;
						}
						else if ((t->srv) && (t->be->beprm->options & PR_O_COOK_PFX)) {
							/* insert the cookie name associated with this server
							 * before existing cookie, and insert a delimitor between them..
							 */
							buffer_replace2(rep, p3, p3, t->srv->cookie, t->srv->cklen + 1);
							p3[t->srv->cklen] = COOKIE_DELIM;
							t->flags |= SN_SCK_INSERTED | SN_SCK_DELETED;
						}
						break;
					}

					/* first, let's see if the cookie is our appcookie*/
					if ((t->be->beprm->appsession_name != NULL) &&
					    (memcmp(p1, t->be->beprm->appsession_name, p2 - p1) == 0)) {

						/* Cool... it's the right one */

						size_t server_id_len = strlen(t->srv->id) + 1;
						asession_temp = &local_asession;
		      
						if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
							Alert("Not enought Memory process_srv():asession->sessid:malloc().\n");
							send_log(t->be, LOG_ALERT, "Not enought Memory process_srv():asession->sessid:malloc().\n");
						}
						memcpy(asession_temp->sessid, p3, t->be->beprm->appsession_len);
						asession_temp->sessid[t->be->beprm->appsession_len] = 0;
						asession_temp->serverid = NULL;

						/* only do insert, if lookup fails */
						if (chtbl_lookup(&(t->be->htbl_proxy), (void *) &asession_temp) != 0) {
							if ((asession_temp = pool_alloc(appsess)) == NULL) {
								Alert("Not enought Memory process_srv():asession:calloc().\n");
								send_log(t->be, LOG_ALERT, "Not enought Memory process_srv():asession:calloc().\n");
								return 0;
							}
							asession_temp->sessid = local_asession.sessid;
							asession_temp->serverid = local_asession.serverid;
							chtbl_insert(&(t->be->beprm->htbl_proxy), (void *) asession_temp);
						}/* end if (chtbl_lookup()) */
						else {
							/* free wasted memory */
							pool_free_to(apools.sessid, local_asession.sessid);
						} /* end else from if (chtbl_lookup()) */
		      
						if (asession_temp->serverid == NULL) {
							if ((asession_temp->serverid = pool_alloc_from(apools.serverid, apools.ser_msize)) == NULL) {
								Alert("Not enought Memory process_srv():asession->sessid:malloc().\n");
								send_log(t->be, LOG_ALERT, "Not enought Memory process_srv():asession->sessid:malloc().\n");
							}
							asession_temp->serverid[0] = '\0';
						}
		      
						if (asession_temp->serverid[0] == '\0')
							memcpy(asession_temp->serverid,t->srv->id,server_id_len);
		      
						tv_delayfrom(&asession_temp->expire, &now, t->be->beprm->appsession_timeout);

#if defined(DEBUG_HASH)
						print_table(&(t->be->beprm->htbl_proxy));
#endif
						break;
					}/* end if ((t->proxy->appsession_name != NULL) ... */
					else {
						//	fprintf(stderr,"Ignoring unknown cookie : ");
						//	write(2, p1, p2-p1);
						//	fprintf(stderr," = ");
						//	write(2, p3, p4-p3);
						//	fprintf(stderr,"\n");
					}
					break; /* we don't want to loop again since there cannot be another cookie on the same line */
				} /* we're now at the end of the cookie value */
			} /* end of cookie processing */

			/* check for any set-cookie in case we check for cacheability */
			if (!delete_header && !(t->flags & SN_SCK_ANY) &&
			    (t->be->beprm->options & PR_O_CHK_CACHE) &&
			    (strncasecmp(rep->h, "Set-Cookie: ", 12) == 0)) {
				t->flags |= SN_SCK_ANY;
			}

			/* let's look if we have to delete this header */
			if (delete_header && !(t->flags & SN_SVDENY))
				buffer_replace2(rep, rep->h, rep->lr, "", 0);

			rep->h = rep->lr;
		} /* while (rep->lr < rep->r) */

		/* end of header processing (even if incomplete) */

		if ((rep->l < rep->rlim - rep->data) && ! MY_FD_ISSET(t->srv_fd, StaticReadEvent)) {
			/* fd in StaticReadEvent was disabled, perhaps because of a previous buffer
			 * full. We cannot loop here since stream_sock_read will disable it only if
			 * rep->l == rlim-data
			 */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->beprm->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);
			else
				tv_eternity(&rep->rex);
		}

		/* read error, write error */
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
			t->logs.status = 502;
			client_return(t, t->fe->errmsg.len502, t->fe->errmsg.msg502);
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVCL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_H;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		/* end of client write or end of server read.
		 * since we are in header mode, if there's no space left for headers, we
		 * won't be able to free more later, so the session will never terminate.
		 */
		else if (rep->flags & BF_READ_NULL || c == CL_STSHUTW || c == CL_STCLOSE || rep->l >= rep->rlim - rep->data) {
			MY_FD_CLR(t->srv_fd, StaticReadEvent);
			tv_eternity(&rep->rex);
			shutdown(t->srv_fd, SHUT_RD);
			t->srv_state = SV_STSHUTR;
			//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			return 1;
		}	
		/* read timeout : return a 504 to the client.
		 */
		else if (MY_FD_ISSET(t->srv_fd, StaticReadEvent) && tv_cmp2_ms(&rep->rex, &now) <= 0) {
			tv_eternity(&rep->rex);
			tv_eternity(&req->wex);
			fd_delete(t->srv_fd);
			if (t->srv) {
				t->srv->cur_sess--;
				t->srv->failed_resp++;
			}
			t->be->failed_resp++;
			t->srv_state = SV_STCLOSE;
			t->logs.status = 504;
			client_return(t, t->fe->errmsg.len504, t->fe->errmsg.msg504);
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_H;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

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
		else if ((/*c == CL_STSHUTR ||*/ c == CL_STCLOSE) && (req->l == 0)) {
			MY_FD_CLR(t->srv_fd, StaticWriteEvent);
			tv_eternity(&req->wex);

			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->beprm->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);

			shutdown(t->srv_fd, SHUT_WR);
			t->srv_state = SV_STSHUTW;
			return 1;
		}
		/* write timeout */
		/* FIXME!!! here, we don't want to switch to SHUTW if the
		 * client shuts read too early, because we may still have
		 * some work to do on the headers.
		 */
		else if (MY_FD_ISSET(t->srv_fd, StaticWriteEvent) && tv_cmp2_ms(&req->wex, &now) <= 0) {
			MY_FD_CLR(t->srv_fd, StaticWriteEvent);
			tv_eternity(&req->wex);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->beprm->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);

			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->beprm->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);

			t->srv_state = SV_STSHUTW;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_H;
			return 1;
		}

		if (req->l == 0) {
			if (MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_CLR(t->srv_fd, StaticWriteEvent); /* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* client buffer not empty */
			if (! MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_SET(t->srv_fd, StaticWriteEvent); /* restart writing */
				if (t->be->beprm->srvtimeout) {
					tv_delayfrom(&req->wex, &now, t->be->beprm->srvtimeout);
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it. */
					rep->rex = req->wex;
				}
				else
					tv_eternity(&req->wex);
			}
		}

		/* be nice with the client side which would like to send a complete header
		 * FIXME: COMPLETELY BUGGY !!! not all headers may be processed because the client
		 * would read all remaining data at once ! The client should not write past rep->lr
		 * when the server is in header state.
		 */
		//return header_processed;
		return t->srv_state != SV_STHEADERS;
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
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		/* last read, or end of client write */
		else if (rep->flags & BF_READ_NULL || c == CL_STSHUTW || c == CL_STCLOSE) {
			MY_FD_CLR(t->srv_fd, StaticReadEvent);
			tv_eternity(&rep->rex);
			shutdown(t->srv_fd, SHUT_RD);
			t->srv_state = SV_STSHUTR;
			//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			return 1;
		}
		/* end of client read and no more data to send */
		else if ((c == CL_STSHUTR || c == CL_STCLOSE) && (req->l == 0)) {
			MY_FD_CLR(t->srv_fd, StaticWriteEvent);
			tv_eternity(&req->wex);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->beprm->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);

			t->srv_state = SV_STSHUTW;
			return 1;
		}
		/* read timeout */
		else if (tv_cmp2_ms(&rep->rex, &now) <= 0) {
			MY_FD_CLR(t->srv_fd, StaticReadEvent);
			tv_eternity(&rep->rex);
			shutdown(t->srv_fd, SHUT_RD);
			t->srv_state = SV_STSHUTR;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			return 1;
		}	
		/* write timeout */
		else if (tv_cmp2_ms(&req->wex, &now) <= 0) {
			MY_FD_CLR(t->srv_fd, StaticWriteEvent);
			tv_eternity(&req->wex);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->beprm->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);
			t->srv_state = SV_STSHUTW;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			return 1;
		}

		/* recompute request time-outs */
		if (req->l == 0) {
			if (MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_CLR(t->srv_fd, StaticWriteEvent); /* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* buffer not empty, there are still data to be transferred */
			if (! MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_SET(t->srv_fd, StaticWriteEvent); /* restart writing */
				if (t->be->beprm->srvtimeout) {
					tv_delayfrom(&req->wex, &now, t->be->beprm->srvtimeout);
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
			if (MY_FD_ISSET(t->srv_fd, StaticReadEvent)) {
				MY_FD_CLR(t->srv_fd, StaticReadEvent);
				tv_eternity(&rep->rex);
			}
		}
		else {
			if (! MY_FD_ISSET(t->srv_fd, StaticReadEvent)) {
				MY_FD_SET(t->srv_fd, StaticReadEvent);
				if (t->be->beprm->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);
				else
					tv_eternity(&rep->rex);
			}
		}

		return 0; /* other cases change nothing */
	}
	else if (s == SV_STSHUTR) {
		if (req->flags & BF_WRITE_ERROR) {
			//MY_FD_CLR(t->srv_fd, StaticWriteEvent);
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
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		else if ((c == CL_STSHUTR || c == CL_STCLOSE) && (req->l == 0)) {
			//MY_FD_CLR(t->srv_fd, StaticWriteEvent);
			tv_eternity(&req->wex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		else if (tv_cmp2_ms(&req->wex, &now) <= 0) {
			//MY_FD_CLR(t->srv_fd, StaticWriteEvent);
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
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		else if (req->l == 0) {
			if (MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_CLR(t->srv_fd, StaticWriteEvent); /* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* buffer not empty */
			if (! MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_SET(t->srv_fd, StaticWriteEvent); /* restart writing */
				if (t->be->beprm->srvtimeout) {
					tv_delayfrom(&req->wex, &now, t->be->beprm->srvtimeout);
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
			//MY_FD_CLR(t->srv_fd, StaticReadEvent);
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
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		else if (rep->flags & BF_READ_NULL || c == CL_STSHUTW || c == CL_STCLOSE) {
			//MY_FD_CLR(t->srv_fd, StaticReadEvent);
			tv_eternity(&rep->rex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		else if (tv_cmp2_ms(&rep->rex, &now) <= 0) {
			//MY_FD_CLR(t->srv_fd, StaticReadEvent);
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
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);

			return 1;
		}
		else if (rep->l == BUFSIZE) { /* no room to read more data */
			if (MY_FD_ISSET(t->srv_fd, StaticReadEvent)) {
				MY_FD_CLR(t->srv_fd, StaticReadEvent);
				tv_eternity(&rep->rex);
			}
		}
		else {
			if (! MY_FD_ISSET(t->srv_fd, StaticReadEvent)) {
				MY_FD_SET(t->srv_fd, StaticReadEvent);
				if (t->be->beprm->srvtimeout)
					tv_delayfrom(&rep->rex, &now, t->be->beprm->srvtimeout);
				else
					tv_eternity(&rep->rex);
			}
		}
		return 0;
	}
	else { /* SV_STCLOSE : nothing to do */
		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			int len;
			len = sprintf(trash, "%08x:%s.srvcls[%04x:%04x]\n", t->uniq_id, t->be->beprm->id, (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
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
	struct buffer *rep = s->rep;
	struct proxy *px;
	struct server *sv;
	int msglen;

	if (s->data_source == DATA_SRC_NONE) {
		s->flags &= ~SN_SELF_GEN;
		return 1;
	}
	else if (s->data_source == DATA_SRC_STATS) {
		msglen = 0;

		if (s->data_state == DATA_ST_INIT) { /* the function had not been called yet */
			unsigned int up;

			s->flags |= SN_SELF_GEN;  // more data will follow

			/* send the start of the HTTP response */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "HTTP/1.0 200 OK\r\n"
					   "Cache-Control: no-cache\r\n"
					   "Connection: close\r\n"
					   "Content-Type: text/html\r\n"
					   "\r\n\r\n");
	    
			s->logs.status = 200;
			client_retnclose(s, msglen, trash); // send the start of the response.
			msglen = 0;

			if (!(s->flags & SN_ERR_MASK))  // this is not really an error but it is
				s->flags |= SN_ERR_PRXCOND; // to mark that it comes from the proxy
			if (!(s->flags & SN_FINST_MASK))
				s->flags |= SN_FINST_R;

			/* WARNING! This must fit in the first buffer !!! */	    
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<html><head><title>Statistics Report for " PRODUCT_NAME "</title>\n"
					   "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n"
					   "<style type=\"text/css\"><!--\n"
					   "body {"
					   "  font-family: helvetica, arial;"
					   "  font-size: 12px;"
					   "  font-weight: normal;"
					   "  color: black;"
					   "  background: white;"
					   "}\n"
					   "td {"
					   "  font-size: 12px;"
					   "  align: center;"
					   "}\n"
					   "h1 {"
					   "  font-size: xx-large;"
					   "  margin-bottom: 0.5em;"
					   "}\n"
					   "h2 {"
					   "	font-family: helvetica, arial;"
					   "	font-size: x-large;"
					   "	font-weight: bold;"
					   "  font-style: italic;"
					   "	color: #6020a0;"
					   "  margin-top: 0em;"
					   "  margin-bottom: 0em;"
					   "}\n"
					   "h3 {"
					   "	font-family: helvetica, arial;"
					   "	font-size: 16px;"
					   "	font-weight: bold;"
					   "	color: #b00040;"
					   "  background: #e8e8d0;"
					   "  margin-top: 0em;"
					   "  margin-bottom: 0em;"
					   "}\n"
					   "li {"
					   "  margin-top: 0.25em;"
					   "  margin-right: 2em;"
					   "}\n"
					   ".hr {"
					   "  margin-top: 0.25em;"
					   "  border-color: black;"
					   "  border-bottom-style: solid;"
					   "}\n"
					   "table.tbl { border-collapse: collapse; border-width: 1px; border-style: solid; border-color: gray;}\n"
					   "table.tbl td { border-width: 1px 1px 1px 1px; border-style: solid solid solid solid; border-color: gray; }\n"
					   "table.tbl th { border-width: 1px; border-style: solid solid solid solid; border-color: gray; }\n"
					   "table.lgd { border-collapse: collapse; border-width: 1px; border-style: none none none solid; border-color: black;}\n"
					   "table.lgd td { border-width: 1px; border-style: solid solid solid solid; border-color: gray; padding: 2px;}\n"
					   "-->"
					   "</style></head>");

			if (buffer_write(rep, trash, msglen) != 0)
				return 0;
			msglen = 0;

			up = (now.tv_sec - start_date.tv_sec);

			/* WARNING! this has to fit the first packet too */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<body><h1>" PRODUCT_NAME "</h1>\n"
					   "<h2>Statistics Report for pid %d</h2>\n"
					   "<hr width=\"100%%\" class=\"hr\">\n"
					   "<h3>&gt; General process information</h3>\n"
					   "<table border=0><tr><td align=\"left\">\n"
					   "<p><b>pid = </b> %d (nbproc = %d)<br>\n"
					   "<b>uptime = </b> %dd %dh%02dm%02ds<br>\n"
					   "<b>system limits :</b> memmax = %s%s ; ulimit-n = %d<br>\n"
					   "<b>maxsock = </b> %d<br>\n"
					   "<b>maxconn = </b> %d (current conns = %d)<br>\n"
					   "</td><td width=\"10%%\">\n"
					   "</td><td align=\"right\">\n"
					   "<table class=\"lgd\">"
					   "<tr><td bgcolor=\"#C0FFC0\">&nbsp;</td><td style=\"border-style: none;\">active UP </td>"
					   "<td bgcolor=\"#B0D0FF\">&nbsp;</td><td style=\"border-style: none;\">backup UP </td></tr>"
					   "<tr><td bgcolor=\"#FFFFA0\"></td><td style=\"border-style: none;\">active UP, going down </td>"
					   "<td bgcolor=\"#C060FF\"></td><td style=\"border-style: none;\">backup UP, going down </td></tr>"
					   "<tr><td bgcolor=\"#FFD020\"></td><td style=\"border-style: none;\">active DOWN, going up </td>"
					   "<td bgcolor=\"#FF80FF\"></td><td style=\"border-style: none;\">backup DOWN, going up </td></tr>"
					   "<tr><td bgcolor=\"#FF9090\"></td><td style=\"border-style: none;\">active or backup DOWN &nbsp;</td>"
					   "<td bgcolor=\"#E0E0E0\"></td><td style=\"border-style: none;\">not checked </td></tr>"
					   "</table>\n"
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
	    
			if (buffer_write(rep, trash, msglen) != 0)
				return 0;
			msglen = 0;

			s->data_state = DATA_ST_DATA;
			memset(&s->data_ctx, 0, sizeof(s->data_ctx));

			px = s->data_ctx.stats.px = proxy;
			s->data_ctx.stats.px_st = DATA_ST_INIT;
		}

		while (s->data_ctx.stats.px) {
			int dispatch_sess, dispatch_cum;
			int failed_checks, down_trans;
			int failed_secu, failed_conns, failed_resp;

			if (s->data_ctx.stats.px_st == DATA_ST_INIT) {
				/* we are on a new proxy */
				px = s->data_ctx.stats.px;

				/* skip the disabled proxies */
				if (px->state == PR_STSTOPPED)
					goto next_proxy;

				if (s->be->fiprm->uri_auth && s->be->fiprm->uri_auth->scope) {
					/* we have a limited scope, we have to check the proxy name */
					struct stat_scope *scope;
					int len;

					len = strlen(px->id);
					scope = s->be->fiprm->uri_auth->scope;

					while (scope) {
						/* match exact proxy name */
						if (scope->px_len == len && !memcmp(px->id, scope->px_id, len))
							break;

						/* match '.' which means 'self' proxy */
						if (!strcmp(scope->px_id, ".") && px == s->fe)
							break;
						scope = scope->next;
					}

					/* proxy name not found */
					if (scope == NULL)
						goto next_proxy;
				}

				msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
						   "<h3>&gt; Proxy instance %s : "
						   "%d front conns (max=%d), %d back, "
						   "%d queued (%d unassigned), %d total front conns, %d back</h3>\n"
						   "",
						   px->id,
						   px->feconn, px->maxconn, px->beconn,
						   px->totpend, px->nbpend, px->cum_feconn, px->cum_beconn);
		
				msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
						   "<table cols=\"16\" class=\"tbl\">\n"
						   "<tr align=\"center\" bgcolor=\"#20C0C0\">"
						   "<th colspan=5>Server</th>"
						   "<th colspan=2>Queue</th>"
						   "<th colspan=4>Sessions</th>"
						   "<th colspan=5>Errors</th></tr>\n"
						   "<tr align=\"center\" bgcolor=\"#20C0C0\">"
						   "<th>Name</th><th>Weight</th><th>Status</th><th>Act.</th><th>Bck.</th>"
						   "<th>Curr.</th><th>Max.</th>"
						   "<th>Curr.</th><th>Max.</th><th>Limit</th><th>Cumul.</th>"
						   "<th>Conn.</th><th>Resp.</th><th>Sec.</th><th>Check</th><th>Down</th></tr>\n");
		
				if (buffer_write(rep, trash, msglen) != 0)
					return 0;
				msglen = 0;

				s->data_ctx.stats.sv = px->srv;
				s->data_ctx.stats.px_st = DATA_ST_DATA;
			}

			px = s->data_ctx.stats.px;

			/* stats.sv has been initialized above */
			while (s->data_ctx.stats.sv != NULL) {
				static char *act_tab_bg[5] = { /*down*/"#FF9090", /*rising*/"#FFD020", /*failing*/"#FFFFA0", /*up*/"#C0FFC0", /*unchecked*/"#E0E0E0" };
				static char *bck_tab_bg[5] = { /*down*/"#FF9090", /*rising*/"#FF80ff", /*failing*/"#C060FF", /*up*/"#B0D0FF", /*unchecked*/"#E0E0E0" };
				static char *srv_hlt_st[5] = { "DOWN", "DN %d/%d &uarr;", "UP %d/%d &darr;", "UP", "<i>no check</i>" };
				int sv_state; /* 0=DOWN, 1=going up, 2=going down, 3=UP */

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

				/* name, weight */
				msglen += snprintf(trash, sizeof(trash),
						   "<tr align=center bgcolor=\"%s\"><td>%s</td><td>%d</td><td>",
						   (sv->state & SRV_BACKUP) ? bck_tab_bg[sv_state] : act_tab_bg[sv_state],
						   sv->id, sv->uweight+1);
				/* status */
				msglen += snprintf(trash + msglen, sizeof(trash) - msglen, srv_hlt_st[sv_state],
						   (sv->state & SRV_RUNNING) ? (sv->health - sv->rise + 1) : (sv->health),
						   (sv->state & SRV_RUNNING) ? (sv->fall) : (sv->rise));

				/* act, bck */
				msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
						   "</td><td>%s</td><td>%s</td>",
						   (sv->state & SRV_BACKUP) ? "-" : "Y",
						   (sv->state & SRV_BACKUP) ? "Y" : "-");

				/* queue : current, max */
				msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
						   "<td align=right>%d</td><td align=right>%d</td>",
						   sv->nbpend, sv->nbpend_max);

				/* sessions : current, max, limit, cumul */
				msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
						   "<td align=right>%d</td><td align=right>%d</td><td align=right>%s</td><td align=right>%d</td>",
						   sv->cur_sess, sv->cur_sess_max, sv->maxconn ? ultoa(sv->maxconn) : "-", sv->cum_sess);

				/* errors : connect, response, security */
				msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
						   "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>\n",
						   sv->failed_conns, sv->failed_resp, sv->failed_secu);

				/* check failures : unique, fatal */
				if (sv->state & SRV_CHECKED)
					msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
							   "<td align=right>%d</td><td align=right>%d</td></tr>\n",
							   sv->failed_checks, sv->down_trans);
				else
					msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
							   "<td align=right>-</td><td align=right>-</td></tr>\n");

				if (buffer_write(rep, trash, msglen) != 0)
					return 0;
				msglen = 0;

				s->data_ctx.stats.sv = sv->next;
			} /* while sv */

			/* now we are past the last server, we'll dump information about the dispatcher */

			/* We have to count down from the proxy to the servers to tell how
			 * many sessions are on the dispatcher, and how many checks have
			 * failed. We cannot count this during the servers dump because it
			 * might be interrupted multiple times.
			 */
			dispatch_sess = px->beconn;
			dispatch_cum  = px->cum_beconn;
			failed_secu   = px->failed_secu;
			failed_conns  = px->failed_conns;
			failed_resp   = px->failed_resp;
			failed_checks = down_trans = 0;

			sv = px->srv;
			while (sv) {
				dispatch_sess -= sv->cur_sess;
				dispatch_cum  -= sv->cum_sess;
				failed_conns  -= sv->failed_conns;
				failed_resp   -= sv->failed_resp;
				failed_secu   -= sv->failed_secu;
				if (sv->state & SRV_CHECKED) {
					failed_checks += sv->failed_checks;
					down_trans    += sv->down_trans;
				}
				sv = sv->next;
			}

			/* name, weight, status, act, bck */
			msglen += snprintf(trash + msglen, sizeof(trash),
					   "<tr align=center bgcolor=\"#e8e8d0\">"
					   "<td>Dispatcher</td><td>-</td>"
					   "<td>%s</td><td>-</td><td>-</td>",
					   px->state == PR_STRUN ? "UP" : "DOWN");

			/* queue : current, max */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right>%d</td><td align=right>%d</td>",
					   px->nbpend, px->nbpend_max);

			/* sessions : current, max, limit, cumul. */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right>%d</td><td align=right>%d</td><td align=right>-</td><td align=right>%d</td>",
					   dispatch_sess, px->beconn_max, dispatch_cum);

			/* errors : connect, response, security */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>\n",
					   failed_conns, failed_resp, failed_secu);

			/* check failures : unique, fatal */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right>-</td><td align=right>-</td></tr>\n");


			/* now the summary for the whole proxy */
			/* name, weight, status, act, bck */
			msglen += snprintf(trash + msglen, sizeof(trash),
					   "<tr align=center style=\"color: #ffff80;  background: #20C0C0;\">"
					   "<td><b>Total</b></td><td>-</td>"
					   "<td><b>%s</b></td><td><b>%d</b></td><td><b>%d</b></td>",
					   (px->state == PR_STRUN && ((px->srv == NULL) || px->srv_act || px->srv_bck)) ? "UP" : "DOWN",
					   px->srv_act, px->srv_bck);

			/* queue : current, max */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right><b>%d</b></td><td align=right><b>%d</b></td>",
					   px->totpend, px->nbpend_max);

			/* sessions : current, max, limit, cumul */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right><b>%d</b></td><td align=right><b>%d</b></td><td align=right><b>-</b></td><td align=right><b>%d</b></td>",
					   px->beconn, px->beconn_max, px->cum_beconn);

			/* errors : connect, response, security */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>\n",
					   px->failed_conns, px->failed_resp, px->failed_secu);

			/* check failures : unique, fatal */
			msglen += snprintf(trash + msglen, sizeof(trash) - msglen,
					   "<td align=right>%d</td><td align=right>%d</td></tr>\n",
					   failed_checks, down_trans);

			msglen += snprintf(trash + msglen, sizeof(trash) - msglen, "</table><p>\n");

			if (buffer_write(rep, trash, msglen) != 0)
				return 0;
			msglen = 0;
	    
			s->data_ctx.stats.px_st = DATA_ST_INIT;
		next_proxy:
			s->data_ctx.stats.px = px->next;
		} /* proxy loop */
		/* here, we just have reached the sv == NULL and px == NULL */
		s->flags &= ~SN_SELF_GEN;
		return 1;
	}
	else {
		/* unknown data source */
		s->logs.status = 500;
		client_retnclose(s, s->fe->errmsg.len500, s->fe->errmsg.msg500);
		if (!(s->flags & SN_ERR_MASK))
			s->flags |= SN_ERR_PRXCOND;
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;
		s->flags &= SN_SELF_GEN;
		return 1;
	}
}



/*
 * Apply all the req filters <exp> to all headers in buffer <req> of session <t>
 */

void apply_filters_to_session(struct session *t, struct buffer *req, struct hdr_exp *exp)
{
	/* iterate through the filters in the outer loop */
	while (exp && !(t->flags & (SN_CLDENY|SN_CLTARPIT))) {
		char term;
		char *cur_ptr, *cur_end, *cur_next;
		int cur_idx, old_idx, abort_filt;
		
				
		/*
		 * The interleaving of transformations and verdicts
		 * makes it difficult to decide to continue or stop
		 * the evaluation.
		 */

		if ((t->flags & SN_CLALLOW) &&
		    (exp->action == ACT_ALLOW || exp->action == ACT_DENY ||
		     exp->action == ACT_TARPIT || exp->action == ACT_PASS)) {
			exp = exp->next;
			continue;
		}

		/* Iterate through the headers in the inner loop.
		 * we start with the start line.
		 */
		old_idx = cur_idx = 0;
		cur_next = req->data + t->hreq.sor;
		abort_filt = 0;

		while (!abort_filt && (cur_idx = t->hreq.hdr_idx.v[cur_idx].next)) {
			struct hdr_idx_elem *cur_hdr = &t->hreq.hdr_idx.v[cur_idx];
			cur_ptr = cur_next;
			cur_end = cur_ptr + cur_hdr->len;
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

					if (!(t->flags & (SN_CLDENY | SN_CLTARPIT))) {
						struct proxy *target = (struct proxy *) exp->replace;

						/* Swithing Proxy */
						*cur_end = term;
						cur_end = NULL;

						/* right now, the backend switch is not too much complicated
						 * because we have associated req_cap and rsp_cap to the
						 * frontend, and the beconn will be updated later.
						 */

						t->rep->rto = t->req->wto = target->beprm->srvtimeout;
						t->req->cto = target->beprm->contimeout;

						t->be = target;

						//t->logs.logwait |= LW_REQ | (target->to_log & (LW_REQHDR | LW_COOKIE));
						t->logs.logwait |= (target->to_log | target->beprm->to_log);
						abort_filt = 1;
					}
					break;
				case ACT_ALLOW:
					if (!(t->flags & (SN_CLDENY | SN_CLTARPIT))) {
						t->flags |= SN_CLALLOW;
						abort_filt = 1;
					}
					break;
				case ACT_REPLACE:
					if (!(t->flags & (SN_CLDENY | SN_CLTARPIT))) {
						int len, delta;
						len = exp_replace(trash, cur_ptr, exp->replace, pmatch);
						delta = buffer_replace2(req, cur_ptr, cur_end, trash, len);
						/* FIXME: if the user adds a newline in the replacement, the
						 * index will not be recalculated for now, and the new line
						 * will not be counted for a new header.
						 */
						cur_end += delta;
						cur_next += delta;
						cur_hdr->len += delta;
						t->hreq.eoh += delta;
					}
					break;
				case ACT_REMOVE:
					if (!(t->flags & (SN_CLDENY | SN_CLTARPIT))) {
						int delta = buffer_replace2(req, cur_ptr, cur_next, NULL, 0);
						cur_next += delta;

						/* FIXME: this should be a separate function */
						t->hreq.eoh += delta;
						t->hreq.hdr_idx.v[old_idx].next = cur_hdr->next;
						t->hreq.hdr_idx.used--;
						cur_hdr->len = 0;

						cur_end = NULL; /* null-term has been rewritten */
					}
					break;
				case ACT_DENY:
					if (!(t->flags & (SN_CLALLOW | SN_CLTARPIT))) {
						t->flags |= SN_CLDENY;
						abort_filt = 1;
					}
					break;
				case ACT_TARPIT:
					if (!(t->flags & (SN_CLALLOW | SN_CLDENY))) {
						t->flags |= SN_CLTARPIT;
						abort_filt = 1;
					}
					break;
					//case ACT_PASS: /* FIXME: broken as of now. We should mark the header as "ignored". */
					//	break;
				}
			}
			if (cur_end)
				*cur_end = term; /* restore the string terminator */

			/* keep the link from this header to next one */
			old_idx = cur_idx;
		}
		exp = exp->next;
	}
}



/*
 * Manager client-side cookie
 */
void manage_client_side_cookies(struct session *t, struct buffer *req)
{
	char *p1, *p2, *p3, *p4;
	char *del_colon, *del_cookie, *colon;
	int app_cookies;

	appsess *asession_temp = NULL;
	appsess local_asession;

	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, abort_filt;

	if (t->be->beprm->cookie_name == NULL &&
	    t->be->beprm->appsession_name ==NULL &&
	    t->be->fiprm->capture_name != NULL)
		return;

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	old_idx = cur_idx = 0;
	cur_next = req->data + t->hreq.sor;
	abort_filt = 0;

	while ((cur_idx = t->hreq.hdr_idx.v[cur_idx].next)) {
		struct hdr_idx_elem *cur_hdr;

		cur_hdr  = &t->hreq.hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next. We're only interested in
		 * "Cookie:" headers.
		 */

		if ((cur_end - cur_ptr <= 7) ||
		    (strncasecmp(cur_ptr, "Cookie:", 7) != 0)) {
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


		p1 = cur_ptr + 7; /* first char after 'Cookie:' */
		if (isspace((int)*p1)) /* try to get the first space with it */
		    p1++;

		colon = p1;
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
				if (t->fe->fiprm->capture_name != NULL &&
				    t->logs.cli_cookie == NULL &&
				    (p4 - p1 >= t->fe->fiprm->capture_namelen) &&
				    memcmp(p1, t->fe->fiprm->capture_name, t->fe->fiprm->capture_namelen) == 0) {
					int log_len = p4 - p1;

					if ((t->logs.cli_cookie = pool_alloc(capture)) == NULL) {
						Alert("HTTP logging : out of memory.\n");
					} else {
						if (log_len > t->fe->fiprm->capture_len)
							log_len = t->fe->fiprm->capture_len;
						memcpy(t->logs.cli_cookie, p1, log_len);
						t->logs.cli_cookie[log_len] = 0;
					}
				}

				if ((p2 - p1 == t->be->beprm->cookie_len) && (t->be->beprm->cookie_name != NULL) &&
				    (memcmp(p1, t->be->beprm->cookie_name, p2 - p1) == 0)) {
					/* Cool... it's the right one */
					struct server *srv = t->be->beprm->srv;
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

					if (t->be->beprm->options & PR_O_COOK_PFX) {
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
						if ((srv->cklen == delim - p3) && !memcmp(p3, srv->cookie, delim - p3)) {
							if (srv->state & SRV_RUNNING || t->be->beprm->options & PR_O_PERSIST) {
								/* we found the server and it's usable */
								t->flags &= ~SN_CK_MASK;
								t->flags |= SN_CK_VALID | SN_DIRECT | SN_ASSIGNED;
								t->srv = srv;
								break;
							} else {
								/* we found a server, but it's down */
								t->flags &= ~SN_CK_MASK;
								t->flags |= SN_CK_DOWN;
							}
						}
						srv = srv->next;
					}

					if (!srv && !(t->flags & SN_CK_DOWN)) {
						/* no server matched this cookie */
						t->flags &= ~SN_CK_MASK;
						t->flags |= SN_CK_INVALID;
					}

					/* depending on the cookie mode, we may have to either :
					 * - delete the complete cookie if we're in insert+indirect mode, so that
					 *   the server never sees it ;
					 * - remove the server id from the cookie value, and tag the cookie as an
					 *   application cookie so that it does not get accidentely removed later,
					 *   if we're in cookie prefix mode
					 */
					if ((t->be->beprm->options & PR_O_COOK_PFX) && (delim != p4)) {
						int delta; /* negative */

						delta = buffer_replace2(req, p3, delim + 1, NULL, 0);
						p4  += delta;
						cur_end += delta;
						cur_next += delta;
						cur_hdr->len += delta;
						t->hreq.eoh += delta;

						del_cookie = del_colon = NULL;
						app_cookies++;	/* protect the header from deletion */
					}
					else if (del_cookie == NULL &&
						 (t->be->beprm->options & (PR_O_COOK_INS | PR_O_COOK_IND)) == (PR_O_COOK_INS | PR_O_COOK_IND)) {
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
						t->hreq.eoh += delta;
						del_cookie = del_colon = NULL;
					}
				}

				if ((t->be->beprm->appsession_name != NULL) &&
				    (memcmp(p1, t->be->beprm->appsession_name, p2 - p1) == 0)) {
					/* first, let's see if the cookie is our appcookie*/
			    
					/* Cool... it's the right one */

					asession_temp = &local_asession;
			  
					if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
						Alert("Not enough memory process_cli():asession->sessid:malloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession->sessid:malloc().\n");
						return;
					}

					memcpy(asession_temp->sessid, p3, t->be->beprm->appsession_len);
					asession_temp->sessid[t->be->beprm->appsession_len] = 0;
					asession_temp->serverid = NULL;
			    
					/* only do insert, if lookup fails */
					if (chtbl_lookup(&(t->be->beprm->htbl_proxy), (void *) &asession_temp) != 0) {
						if ((asession_temp = pool_alloc(appsess)) == NULL) {
							/* free previously allocated memory */
							pool_free_to(apools.sessid, local_asession.sessid);
							Alert("Not enough memory process_cli():asession:calloc().\n");
							send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
							return;
						}

						asession_temp->sessid = local_asession.sessid;
						asession_temp->serverid = local_asession.serverid;
						chtbl_insert(&(t->be->beprm->htbl_proxy), (void *) asession_temp);
					} else {
						/* free previously allocated memory */
						pool_free_to(apools.sessid, local_asession.sessid);
					}
			    
					if (asession_temp->serverid == NULL) {
						Alert("Found Application Session without matching server.\n");
					} else {
						struct server *srv = t->be->beprm->srv;
						while (srv) {
							if (strcmp(srv->id, asession_temp->serverid) == 0) {
								if (srv->state & SRV_RUNNING || t->be->beprm->options & PR_O_PERSIST) {
									/* we found the server and it's usable */
									t->flags &= ~SN_CK_MASK;
									t->flags |= SN_CK_VALID | SN_DIRECT | SN_ASSIGNED;
									t->srv = srv;
									break;
								} else {
									t->flags &= ~SN_CK_MASK;
									t->flags |= SN_CK_DOWN;
								}
							}
							srv = srv->next;
						}/* end while(srv) */
					}/* end else if server == NULL */

					tv_delayfrom(&asession_temp->expire, &now, t->be->beprm->appsession_timeout);
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
				t->hreq.hdr_idx.v[old_idx].next = cur_hdr->next;
				t->hreq.hdr_idx.used--;
				cur_hdr->len = 0;
			}
			cur_next += delta;
			t->hreq.eoh += delta;
		}

		/* keep the link from this header to next one */
		old_idx = cur_idx;
	} /* end of cookie processing on this header */
}



/*
 * Try to retrieve a known appsession in the URI, then the associated server.
 * If the server is found, it's assigned to the session.
 */

void get_srv_from_appsession(struct session *t, const char *begin, const char *end)
{
	appsess *asession_temp = NULL;
	appsess local_asession;
	char *request_line;

	if (t->be->beprm->appsession_name == NULL ||
	    (t->hreq.meth != HTTP_METH_GET && t->hreq.meth != HTTP_METH_POST) ||
	    (request_line = memchr(begin, ';', end - begin)) == NULL ||
	    ((1 + t->be->beprm->appsession_name_len + 1 + t->be->beprm->appsession_len) > (end - request_line)))
		return;

	/* skip ';' */
	request_line++;

	/* look if we have a jsessionid */
	if (strncasecmp(request_line, t->be->beprm->appsession_name, t->be->beprm->appsession_name_len) != 0)
		return;

	/* skip jsessionid= */
	request_line += t->be->beprm->appsession_name_len + 1;
	
	/* First try if we already have an appsession */
	asession_temp = &local_asession;
	
	if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
		Alert("Not enough memory process_cli():asession_temp->sessid:calloc().\n");
		send_log(t->be, LOG_ALERT, "Not enough Memory process_cli():asession_temp->sessid:calloc().\n");
		return;
	}
	
	/* Copy the sessionid */
	memcpy(asession_temp->sessid, request_line, t->be->beprm->appsession_len);
	asession_temp->sessid[t->be->beprm->appsession_len] = 0;
	asession_temp->serverid = NULL;
	
	/* only do insert, if lookup fails */
	if (chtbl_lookup(&(t->be->beprm->htbl_proxy), (void *)&asession_temp)) {
		if ((asession_temp = pool_alloc(appsess)) == NULL) {
			/* free previously allocated memory */
			pool_free_to(apools.sessid, local_asession.sessid);
			Alert("Not enough memory process_cli():asession:calloc().\n");
			send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
			return;
		}
		asession_temp->sessid = local_asession.sessid;
		asession_temp->serverid = local_asession.serverid;
		chtbl_insert(&(t->be->beprm->htbl_proxy), (void *) asession_temp);
	}
	else {
		/* free previously allocated memory */
		pool_free_to(apools.sessid, local_asession.sessid);
	}
	
	tv_delayfrom(&asession_temp->expire, &now, t->be->beprm->appsession_timeout);
	asession_temp->request_count++;
	
#if defined(DEBUG_HASH)
	print_table(&(t->proxy->htbl_proxy));
#endif
	if (asession_temp->serverid == NULL) {
		Alert("Found Application Session without matching server.\n");
	} else {
		struct server *srv = t->be->beprm->srv;
		while (srv) {
			if (strcmp(srv->id, asession_temp->serverid) == 0) {
				if (srv->state & SRV_RUNNING || t->be->beprm->options & PR_O_PERSIST) {
					/* we found the server and it's usable */
					t->flags &= ~SN_CK_MASK;
					t->flags |= SN_CK_VALID | SN_DIRECT | SN_ASSIGNED;
					t->srv = srv;
					break;
				} else {
					t->flags &= ~SN_CK_MASK;
					t->flags |= SN_CK_DOWN;
				}
			}
			srv = srv->next;
		}
	}
}



/*
 * In a GET request, check if the requested URI matches the stats uri for the
 * current backend, and if an authorization has been passed and is valid.
 *
 * It is assumed that the request is a GET and that the t->be->fiprm->uri_auth field
 * is valid. An HTTP/401 response may be sent, or produce_content() can be
 * called to start sending data.
 *
 * Returns 1 if the session's state changes, otherwise 0.
 */
int stats_check_uri_auth(struct session *t, struct proxy *backend)
{
	struct uri_auth *uri_auth = backend->uri_auth;
	struct user_auth *user;
	int authenticated, cur_idx;
	char *h;

	if (t->hreq.start.len < uri_auth->uri_len + 4)   /* +4 for "GET " */
		return 0;

	if (memcmp(t->hreq.start.str + 4, uri_auth->uri_prefix, uri_auth->uri_len) != 0)
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
		h = t->req->data + t->hreq.sor;
		while ((cur_idx = t->hreq.hdr_idx.v[cur_idx].next)) {
			int len = t->hreq.hdr_idx.v[cur_idx].len;
			if (len > 14 &&
			    !strncasecmp("Authorization:", h, 14)) {
				t->hreq.auth_hdr.str = h;
				t->hreq.auth_hdr.len = len;
				break;
			}
			h += len + t->hreq.hdr_idx.v[cur_idx].cr + 1;
		}

		if (t->hreq.auth_hdr.len < 21 ||
		    memcmp(t->hreq.auth_hdr.str + 14, " Basic ", 7))
			user = NULL;

		while (user) {
			if ((t->hreq.auth_hdr.len == user->user_len + 14 + 7)
			    && !memcmp(t->hreq.auth_hdr.str + 14 + 7,
				       user->user_pwd, user->user_len)) {
				authenticated = 1;
				break;
			}
			user = user->next;
		}
	}

	if (!authenticated) {
		int msglen;

		/* no need to go further */
		msglen = sprintf(trash, HTTP_401_fmt, uri_auth->auth_realm);
		t->logs.status = 401;
		client_retnclose(t, msglen, trash);
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
