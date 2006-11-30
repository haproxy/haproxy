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
#include <proto/proto_http.h>
#include <proto/queue.h>
#include <proto/session.h>
#include <proto/task.h>


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

	s->fe->nbconn--;
	actconn--;
    
	if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
		int len;
		len = sprintf(trash, "%08x:%s.closed[%04x:%04x]\n", s->uniq_id, s->be->id, (unsigned short)s->cli_fd, (unsigned short)s->srv_fd);
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
	int method_checked = 0;
	appsess *asession_temp = NULL;
	appsess local_asession;

#ifdef DEBUG_FULL
	fprintf(stderr,"process_cli: c=%s s=%s set(r,w)=%d,%d exp(r,w)=%d.%d,%d.%d\n",
		cli_stnames[c], srv_stnames[s],
		MY_FD_ISSET(t->cli_fd, StaticReadEvent), MY_FD_ISSET(t->cli_fd, StaticWriteEvent),
		req->rex.tv_sec, req->rex.tv_usec,
		rep->wex.tv_sec, rep->wex.tv_usec);
#endif
	//fprintf(stderr,"process_cli: c=%d, s=%d, cr=%d, cw=%d, sr=%d, sw=%d\n", c, s,
	//MY_FD_ISSET(t->cli_fd, StaticReadEvent), MY_FD_ISSET(t->cli_fd, StaticWriteEvent),
	//MY_FD_ISSET(t->srv_fd, StaticReadEvent), MY_FD_ISSET(t->srv_fd, StaticWriteEvent)
	//);
	if (c == CL_STHEADERS) {
		/* now parse the partial (or complete) headers */
		while (req->lr < req->r) { /* this loop only sees one header at each iteration */
			char *ptr;
			int delete_header;
			char *request_line = NULL;
	
			ptr = req->lr;

			/* look for the end of the current header */
			while (ptr < req->r && *ptr != '\n' && *ptr != '\r')
				ptr++;
	    
			if (ptr == req->h) { /* empty line, end of headers */
				int line, len;

				/*
				 * first, let's check that it's not a leading empty line, in
				 * which case we'll ignore and remove it (according to RFC2616).
				 */
				if (req->h == req->data) {
					/* to get a complete header line, we need the ending \r\n, \n\r, \r or \n too */
					if (ptr > req->r - 2) {
						/* this is a partial header, let's wait for more to come */
						req->lr = ptr;
						break;
					}

					/* now we know that *ptr is either \r or \n,
					 * and that there are at least 1 char after it.
					 */
					if ((ptr[0] == ptr[1]) || (ptr[1] != '\r' && ptr[1] != '\n'))
						req->lr = ptr + 1; /* \r\r, \n\n, \r[^\n], \n[^\r] */
					else
						req->lr = ptr + 2; /* \r\n or \n\r */
					/* ignore empty leading lines */
					buffer_replace2(req, req->h, req->lr, NULL, 0);
					req->h = req->lr;
					continue;
				}

				/* we can only get here after an end of headers */
				/* we'll have something else to do here : add new headers ... */

				if (t->flags & SN_CLDENY) {
					/* no need to go further */
					t->logs.status = 403;
					t->logs.t_request = tv_diff(&t->logs.tv_accept, &now); /* let's log the request time */
					client_retnclose(t, t->fe->errmsg.len403, t->fe->errmsg.msg403);
					if (!(t->flags & SN_ERR_MASK))
						t->flags |= SN_ERR_PRXCOND;
					if (!(t->flags & SN_FINST_MASK))
						t->flags |= SN_FINST_R;
					return 1;
				}

				/* Right now, we know that we have processed the entire headers
				 * and that unwanted requests have been filtered out. We can do
				 * whatever we want.
				 */


				/* check if the URI matches the monitor_uri. To speed-up the
				 * test, we include the leading and trailing spaces in the
				 * comparison.
				 */
				if ((t->be->monitor_uri_len != 0) &&
				    (t->req_line.len >= t->be->monitor_uri_len)) {
					char *p = t->req_line.str;
					int idx = 0;

					/* skip the method so that we accept any method */
					while (idx < t->req_line.len && p[idx] != ' ')
						idx++;
					p += idx;

					if (t->req_line.len - idx >= t->be->monitor_uri_len &&
					    !memcmp(p, t->be->monitor_uri, t->be->monitor_uri_len)) {
						/*
						 * We have found the monitor URI
						 */
						t->flags |= SN_MONITOR;
						t->logs.status = 200;
						client_retnclose(t, strlen(HTTP_200), HTTP_200);
						if (!(t->flags & SN_ERR_MASK))
							t->flags |= SN_ERR_PRXCOND;
						if (!(t->flags & SN_FINST_MASK))
							t->flags |= SN_FINST_R;
						return 1;
					}
				}

				if (t->fi->uri_auth != NULL
				    && t->req_line.len >= t->fi->uri_auth->uri_len + 4) {   /* +4 for "GET /" */
					if (!memcmp(t->req_line.str + 4,
						    t->fi->uri_auth->uri_prefix, t->fi->uri_auth->uri_len)
					    && !memcmp(t->req_line.str, "GET ", 4)) {
						struct user_auth *user;
						int authenticated;

						/* we are in front of a interceptable URI. Let's check
						 * if there's an authentication and if it's valid.
						 */
						user = t->fi->uri_auth->users;
						if (!user) {
							/* no user auth required, it's OK */
							authenticated = 1;
						} else {
							authenticated = 0;

							/* a user list is defined, we have to check.
							 * skip 21 chars for "Authorization: Basic ".
							 */
							if (t->auth_hdr.len < 21 || memcmp(t->auth_hdr.str + 14, " Basic ", 7))
								user = NULL;

							while (user) {
								if ((t->auth_hdr.len == user->user_len + 21)
								    && !memcmp(t->auth_hdr.str+21, user->user_pwd, user->user_len)) {
									authenticated = 1;
									break;
								}
								user = user->next;
							}
						}

						if (!authenticated) {
							int msglen;

							/* no need to go further */

							msglen = sprintf(trash, HTTP_401_fmt, t->fi->uri_auth->auth_realm);
							t->logs.status = 401;
							client_retnclose(t, msglen, trash);
							if (!(t->flags & SN_ERR_MASK))
								t->flags |= SN_ERR_PRXCOND;
							if (!(t->flags & SN_FINST_MASK))
								t->flags |= SN_FINST_R;
							return 1;
						}

						t->cli_state = CL_STSHUTR;
						req->rlim = req->data + BUFSIZE; /* no more rewrite needed */
						t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);
						t->data_source = DATA_SRC_STATS;
						t->data_state  = DATA_ST_INIT;
						produce_content(t);
						return 1;
					}
				}


				for (line = 0; line < t->fi->nb_reqadd; line++) {
					len = sprintf(trash, "%s\r\n", t->fi->req_add[line]);
					buffer_replace2(req, req->h, req->h, trash, len);
				}

				if (t->be->options & PR_O_FWDFOR) {
					if (t->cli_addr.ss_family == AF_INET) {
						unsigned char *pn;
						pn = (unsigned char *)&((struct sockaddr_in *)&t->cli_addr)->sin_addr;
						len = sprintf(trash, "X-Forwarded-For: %d.%d.%d.%d\r\n",
							      pn[0], pn[1], pn[2], pn[3]);
						buffer_replace2(req, req->h, req->h, trash, len);
					}
					else if (t->cli_addr.ss_family == AF_INET6) {
						char pn[INET6_ADDRSTRLEN];
						inet_ntop(AF_INET6,
							  (const void *)&((struct sockaddr_in6 *)(&t->cli_addr))->sin6_addr,
							  pn, sizeof(pn));
						len = sprintf(trash, "X-Forwarded-For: %s\r\n", pn);
						buffer_replace2(req, req->h, req->h, trash, len);
					}
				}

				/* add a "connection: close" line if needed */
				if (t->fe->options & PR_O_HTTP_CLOSE)
					buffer_replace2(req, req->h, req->h, "Connection: close\r\n", 19);

				if (!memcmp(req->data, "POST ", 5)) {
					/* this is a POST request, which is not cacheable by default */
					t->flags |= SN_POST;
				}
		    
				t->cli_state = CL_STDATA;
				req->rlim = req->data + BUFSIZE; /* no more rewrite needed */

				t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);
				/* FIXME: we'll set the client in a wait state while we try to
				 * connect to the server. Is this really needed ? wouldn't it be
				 * better to release the maximum of system buffers instead ?
				 * The solution is to enable the FD but set its time-out to
				 * eternity as long as the server-side does not enable data xfer.
				 * CL_STDATA also has to take care of this, which is done below.
				 */
				//MY_FD_CLR(t->cli_fd, StaticReadEvent);
				//tv_eternity(&req->rex);

				/* FIXME: if we break here (as up to 1.1.23), having the client
				 * shutdown its connection can lead to an abort further.
				 * it's better to either return 1 or even jump directly to the
				 * data state which will save one schedule.
				 */
				//break;

				if (!t->fe->clitimeout ||
				    (t->srv_state < SV_STDATA && t->be->srvtimeout))
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
						     t->be->contimeout ? t->be->contimeout : 0);
				}

				goto process_data;
			}

			/* to get a complete header line, we need the ending \r\n, \n\r, \r or \n too */
			if (ptr > req->r - 2) {
				/* this is a partial header, let's wait for more to come */
				req->lr = ptr;
				break;
			}

			/* now we know that *ptr is either \r or \n,
			 * and that there are at least 1 char after it.
			 */
			if ((ptr[0] == ptr[1]) || (ptr[1] != '\r' && ptr[1] != '\n'))
				req->lr = ptr + 1; /* \r\r, \n\n, \r[^\n], \n[^\r] */
			else
				req->lr = ptr + 2; /* \r\n or \n\r */

			/*
			 * now we know that we have a full header ; we can do whatever
			 * we want with these pointers :
			 *   req->h  = beginning of header
			 *   ptr     = end of header (first \r or \n)
			 *   req->lr = beginning of next line (next rep->h)
			 *   req->r  = end of data (not used at this stage)
			 */

			if (!method_checked && (t->be->appsession_name != NULL) &&
			    ((memcmp(req->h, "GET ", 4) == 0) || (memcmp(req->h, "POST ", 4) == 0)) &&
			    ((request_line = memchr(req->h, ';', req->lr - req->h)) != NULL)) {

				/* skip ; */
				request_line++;

				/* look if we have a jsessionid */

				if (strncasecmp(request_line, t->be->appsession_name, t->be->appsession_name_len) == 0) {

					/* skip jsessionid= */
					request_line += t->be->appsession_name_len + 1;
		
					/* First try if we allready have an appsession */
					asession_temp = &local_asession;
		
					if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
						Alert("Not enough memory process_cli():asession_temp->sessid:calloc().\n");
						send_log(t->be, LOG_ALERT, "Not enough Memory process_cli():asession_temp->sessid:calloc().\n");
						return 0;
					}

					/* Copy the sessionid */
					memcpy(asession_temp->sessid, request_line, t->be->appsession_len);
					asession_temp->sessid[t->be->appsession_len] = 0;
					asession_temp->serverid = NULL;

					/* only do insert, if lookup fails */
					if (chtbl_lookup(&(t->be->htbl_proxy), (void *)&asession_temp)) {
						if ((asession_temp = pool_alloc(appsess)) == NULL) {
							Alert("Not enough memory process_cli():asession:calloc().\n");
							send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
							return 0;
						}
						asession_temp->sessid = local_asession.sessid;
						asession_temp->serverid = local_asession.serverid;
						chtbl_insert(&(t->be->htbl_proxy), (void *) asession_temp);
					} /* end if (chtbl_lookup()) */
					else {
						/*free wasted memory;*/
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
									t->flags &= ~SN_CK_MASK;
									t->flags |= SN_CK_VALID | SN_DIRECT | SN_ASSIGNED;
									t->srv = srv;
									break;
								} else {
									t->flags &= ~SN_CK_MASK;
									t->flags |= SN_CK_DOWN;
								}
							} /* end if (strcmp()) */
							srv = srv->next;
						}/* end while(srv) */
					}/* end else of if (asession_temp->serverid == NULL) */
				}/* end if (strncasecmp(request_line,t->proxy->appsession_name,apssesion_name_len) == 0) */
				else {
					//fprintf(stderr,">>>>>>>>>>>>>>>>>>>>>>NO SESSION\n");
				}
				method_checked = 1;
			} /* end if (!method_checked ...) */
			else{
				//printf("No Methode-Header with Session-String\n");
			}
	    
			if (t->logs.logwait & LW_REQ) {
				/* we have a complete HTTP request that we must log */
				int urilen;

				if ((t->logs.uri = pool_alloc(requri)) == NULL) {
					Alert("HTTP logging : out of memory.\n");
					t->logs.status = 500;
					client_retnclose(t, t->fe->errmsg.len500, t->fe->errmsg.msg500);
					if (!(t->flags & SN_ERR_MASK))
						t->flags |= SN_ERR_PRXCOND;
					if (!(t->flags & SN_FINST_MASK))
						t->flags |= SN_FINST_R;
					return 1;
				}
		
				urilen = ptr - req->h;
				if (urilen >= REQURI_LEN)
					urilen = REQURI_LEN - 1;
				memcpy(t->logs.uri, req->h, urilen);
				t->logs.uri[urilen] = 0;

				if (!(t->logs.logwait &= ~LW_REQ))
					sess_log(t);
			}
			else if (t->logs.logwait & LW_REQHDR) {
				struct cap_hdr *h;
				int len;
				for (h = t->fi->req_cap; h; h = h->next) {
					if ((h->namelen + 2 <= ptr - req->h) &&
					    (req->h[h->namelen] == ':') &&
					    (strncasecmp(req->h, h->name, h->namelen) == 0)) {

						if (t->req_cap[h->index] == NULL)
							t->req_cap[h->index] = pool_alloc_from(h->pool, h->len + 1);

						len = ptr - (req->h + h->namelen + 2);
						if (len > h->len)
							len = h->len;

						memcpy(t->req_cap[h->index], req->h + h->namelen + 2, len);
						t->req_cap[h->index][len]=0;
					}
				}
		
			}

			delete_header = 0;

			if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
				int len, max;
				len = sprintf(trash, "%08x:%s.clihdr[%04x:%04x]: ", t->uniq_id, t->be->id, (unsigned  short)t->cli_fd, (unsigned short)t->srv_fd);
				max = ptr - req->h;
				UBOUND(max, sizeof(trash) - len - 1);
				len += strlcpy2(trash + len, req->h, max + 1);
				trash[len++] = '\n';
				write(1, trash, len);
			}


			/* remove "connection: " if needed */
			if (!delete_header && (t->fe->options & PR_O_HTTP_CLOSE)
			    && (strncasecmp(req->h, "Connection: ", 12) == 0)) {
				delete_header = 1;
			}

			/* try headers regexps */
			if (!delete_header && t->fi->req_exp != NULL
			    && !(t->flags & SN_CLDENY)) {
				struct hdr_exp *exp;
				char term;
		
				term = *ptr;
				*ptr = '\0';
				exp = t->fi->req_exp;
				do {
					if (regexec(exp->preg, req->h, MAX_MATCH, pmatch, 0) == 0) {
						switch (exp->action) {
						case ACT_ALLOW:
							if (!(t->flags & (SN_CLDENY | SN_CLTARPIT)))
								t->flags |= SN_CLALLOW;
							break;
						case ACT_REPLACE:
							if (!(t->flags & (SN_CLDENY | SN_CLTARPIT))) {
								int len = exp_replace(trash, req->h, exp->replace, pmatch);
								ptr += buffer_replace2(req, req->h, ptr, trash, len);
							}
							break;
						case ACT_REMOVE:
							if (!(t->flags & (SN_CLDENY | SN_CLTARPIT)))
								delete_header = 1;
							break;
						case ACT_DENY:
							if (!(t->flags & (SN_CLALLOW | SN_CLTARPIT)))
								t->flags |= SN_CLDENY;
							break;
						case ACT_TARPIT:
							if (!(t->flags & (SN_CLALLOW | SN_CLDENY)))
								t->flags |= SN_CLTARPIT;
							break;
						case ACT_PASS: /* we simply don't deny this one */
							break;
						}
						break;
					}
				} while ((exp = exp->next) != NULL);
				*ptr = term; /* restore the string terminator */
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
			if (!delete_header &&
			    (t->be->cookie_name != NULL || t->be->appsession_name !=NULL || t->fi->capture_name != NULL)
			    && !(t->flags & (SN_CLDENY|SN_CLTARPIT)) && (ptr >= req->h + 8)
			    && (strncasecmp(req->h, "Cookie: ", 8) == 0)) {
				char *p1, *p2, *p3, *p4;
				char *del_colon, *del_cookie, *colon;
				int app_cookies;

				p1 = req->h + 8; /* first char after 'Cookie: ' */
				colon = p1;
				/* del_cookie == NULL => nothing to be deleted */
				del_colon = del_cookie = NULL;
				app_cookies = 0;
		
				while (p1 < ptr) {
					/* skip spaces and colons, but keep an eye on these ones */
					while (p1 < ptr) {
						if (*p1 == ';' || *p1 == ',')
							colon = p1;
						else if (!isspace((int)*p1))
							break;
						p1++;
					}
		    
					if (p1 == ptr)
						break;
		    
					/* p1 is at the beginning of the cookie name */
					p2 = p1;
					while (p2 < ptr && *p2 != '=')
						p2++;
		    
					if (p2 == ptr)
						break;

					p3 = p2 + 1; /* skips the '=' sign */
					if (p3 == ptr)
						break;
		    
					p4 = p3;
					while (p4 < ptr && !isspace((int)*p4) && *p4 != ';' && *p4 != ',')
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
					 * +--------------------> req->h
					 */
		    
					if (*p1 == '$') {
						/* skip this one */
					}
					else {
						/* first, let's see if we want to capture it */
						if (t->fi->capture_name != NULL &&
						    t->logs.cli_cookie == NULL &&
						    (p4 - p1 >= t->fi->capture_namelen) &&
						    memcmp(p1, t->fi->capture_name, t->fi->capture_namelen) == 0) {
							int log_len = p4 - p1;

							if ((t->logs.cli_cookie = pool_alloc(capture)) == NULL) {
								Alert("HTTP logging : out of memory.\n");
							} else {
								if (log_len > t->fi->capture_len)
									log_len = t->fi->capture_len;
								memcpy(t->logs.cli_cookie, p1, log_len);
								t->logs.cli_cookie[log_len] = 0;
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
							 * +------------------------> req->h
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
								if ((srv->cklen == delim - p3) && !memcmp(p3, srv->cookie, delim - p3)) {
									if (srv->state & SRV_RUNNING || t->be->options & PR_O_PERSIST) {
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
							if ((t->be->options & PR_O_COOK_PFX) && (delim != p4)) {
								buffer_replace2(req, p3, delim + 1, NULL, 0);
								p4  -= (delim + 1 - p3);
								ptr -= (delim + 1 - p3);
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
								buffer_replace2(req, del_cookie, p1, NULL, 0);
								p4  -= (p1 - del_cookie);
								ptr -= (p1 - del_cookie);
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
								return 0;
							}
			  
							memcpy(asession_temp->sessid, p3, t->be->appsession_len);
							asession_temp->sessid[t->be->appsession_len] = 0;
							asession_temp->serverid = NULL;
			    
							/* only do insert, if lookup fails */
							if (chtbl_lookup(&(t->be->htbl_proxy), (void *) &asession_temp) != 0) {
								if ((asession_temp = pool_alloc(appsess)) == NULL) {
									Alert("Not enough memory process_cli():asession:calloc().\n");
									send_log(t->be, LOG_ALERT, "Not enough memory process_cli():asession:calloc().\n");
									return 0;
								}
				
								asession_temp->sessid = local_asession.sessid;
								asession_temp->serverid = local_asession.serverid;
								chtbl_insert(&(t->be->htbl_proxy), (void *) asession_temp);
							} else {
								/* free wasted memory */
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
			    
							tv_delayfrom(&asession_temp->expire, &now, t->be->appsession_timeout);
						}/* end if ((t->proxy->appsession_name != NULL) ... */
					}

					/* we'll have to look for another cookie ... */
					p1 = p4;
				} /* while (p1 < ptr) */

				/* There's no more cookie on this line.
				 * We may have marked the last one(s) for deletion.
				 * We must do this now in two ways :
				 *  - if there is no app cookie, we simply delete the header ;
				 *  - if there are app cookies, we must delete the end of the
				 *    string properly, including the colon/semi-colon before
				 *    the cookie name.
				 */
				if (del_cookie != NULL) {
					if (app_cookies) {
						buffer_replace2(req, del_colon, ptr, NULL, 0);
						/* WARNING! <ptr> becomes invalid for now. If some code
						 * below needs to rely on it before the end of the global
						 * header loop, we need to correct it with this code :
						 */
						ptr = del_colon;
					}
					else
						delete_header = 1;
				}
			} /* end of cookie processing on this header */

			/* let's look if we have to delete this header */
			if (delete_header && !(t->flags & (SN_CLDENY|SN_CLTARPIT))) {
				buffer_replace2(req, req->h, req->lr, NULL, 0);
				/* WARNING: ptr is not valid anymore, since the header may have
				 * been deleted or truncated ! */
			} else {
				/* try to catch the first line as the request */
				if (t->req_line.len < 0) {
					t->req_line.str = req->h;
					t->req_line.len = ptr - req->h;
				}

				/* We might also need the 'Authorization: ' header */
				if (t->auth_hdr.len < 0 &&
				    t->fi->uri_auth != NULL &&
				    ptr > req->h + 15 &&
				    !strncasecmp("Authorization: ", req->h, 15)) {
					t->auth_hdr.str = req->h;
					t->auth_hdr.len = ptr - req->h;
				}
			}

			req->h = req->lr;
		} /* while (req->lr < req->r) */

		/* end of header processing (even if incomplete) */

		if ((req->l < req->rlim - req->data) && ! MY_FD_ISSET(t->cli_fd, StaticReadEvent)) {
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

		/* Since we are in header mode, if there's no space left for headers, we
		 * won't be able to free more later, so the session will never terminate.
		 */
		if (req->l >= req->rlim - req->data) {
			t->logs.status = 400;
			client_retnclose(t, t->fe->errmsg.len400, t->fe->errmsg.msg400);
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_PRXCOND;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_R;
			return 1;
		}
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
		else if (tv_cmp2_ms(&req->rex, &now) <= 0) {

			/* read timeout : give up with an error message.
			 */
			t->logs.status = 408;
			client_retnclose(t, t->fe->errmsg.len408, t->fe->errmsg.msg408);
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_R;
			return 1;
		}

		return t->cli_state != CL_STHEADERS;
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
			  (t->req->l == 0 || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
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
		     (t->req->l == 0 || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
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

			if (t->srv && t->conn_retries == 0 && t->be->options & PR_O_REDISP) {
				/* We're on our last chance, and the REDISP option was specified.
				 * We will ignore cookie and force to balance or use the dispatcher.
				 */
				/* let's try to offer this slot to anybody */
				if (may_dequeue_tasks(t->srv, t->be))
					task_wakeup(&rq, t->srv->queue_mgt);

				if (t->srv)
					t->srv->failed_conns++;
				t->be->failed_conns++;

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
				MY_FD_SET(t->srv_fd, StaticReadEvent);
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
					    (t->be->options & PR_O_CHK_CACHE)) {

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

						Alert("Blocking cacheable cookie in response from instance %s, server %s.\n", t->be->id, t->srv->id);
						send_log(t->be, LOG_ALERT, "Blocking cacheable cookie in response from instance %s, server %s.\n", t->be->id, t->srv->id);

						/* We used to have a free connection slot. Since we'll never use it,
						 * we have to inform the server that it may be used by another session.
						 */
						if (may_dequeue_tasks(t->srv, t->be))
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
					if (may_dequeue_tasks(t->srv, t->be))
						task_wakeup(&rq, t->srv->queue_mgt);

					return 1;
				}

				/* we'll have something else to do here : add new headers ... */

				if ((t->srv) && !(t->flags & SN_DIRECT) && (t->be->options & PR_O_COOK_INS) &&
				    (!(t->be->options & PR_O_COOK_POST) || (t->flags & SN_POST))) {
					/* the server is known, it's not the one the client requested, we have to
					 * insert a set-cookie here, except if we want to insert only on POST
					 * requests and this one isn't. Note that servers which don't have cookies
					 * (eg: some backup servers) will return a full cookie removal request.
					 */
					len = sprintf(trash, "Set-Cookie: %s=%s; path=/\r\n",
						      t->be->cookie_name,
						      t->srv->cookie ? t->srv->cookie : "; Expires=Thu, 01-Jan-1970 00:00:01 GMT");

					t->flags |= SN_SCK_INSERTED;

					/* Here, we will tell an eventual cache on the client side that we don't
					 * want it to cache this reply because HTTP/1.0 caches also cache cookies !
					 * Some caches understand the correct form: 'no-cache="set-cookie"', but
					 * others don't (eg: apache <= 1.3.26). So we use 'private' instead.
					 */
					if (t->be->options & PR_O_COOK_NOC)
						//len += sprintf(newhdr + len, "Cache-control: no-cache=\"set-cookie\"\r\n");
						len += sprintf(trash + len, "Cache-control: private\r\n");

					if (rep->data + rep->l < rep->h)
						/* The data has been stolen, we will crash cleanly instead of corrupting memory */
						*(int *)0 = 0;
					buffer_replace2(rep, rep->h, rep->h, trash, len);
				}

				/* headers to be added */
				for (line = 0; line < t->fi->nb_rspadd; line++) {
					len = sprintf(trash, "%s\r\n", t->fi->rsp_add[line]);
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
				    (c == CL_STSHUTR || c == CL_STCLOSE || t->be->options & PR_O_FORCE_CLO)) {
					MY_FD_CLR(t->srv_fd, StaticWriteEvent);
					tv_eternity(&req->wex);

					/* We must ensure that the read part is still alive when switching
					 * to shutw */
					MY_FD_SET(t->srv_fd, StaticReadEvent);
					if (t->be->srvtimeout)
						tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

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
					if (!(t->flags & SN_POST) && (t->be->options & PR_O_CHK_CACHE))
						t->flags |= SN_CACHEABLE | SN_CACHE_COOK;
					break;
				default:
					break;
				}
			}
			else if (t->logs.logwait & LW_RSPHDR) {
				struct cap_hdr *h;
				int len;
				for (h = t->fi->rsp_cap; h; h = h->next) {
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

			if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
				int len, max;
				len = sprintf(trash, "%08x:%s.srvhdr[%04x:%04x]: ", t->uniq_id, t->be->id, (unsigned  short)t->cli_fd, (unsigned short)t->srv_fd);
				max = ptr - rep->h;
				UBOUND(max, sizeof(trash) - len - 1);
				len += strlcpy2(trash + len, rep->h, max + 1);
				trash[len++] = '\n';
				write(1, trash, len);
			}

			/* remove "connection: " if needed */
			if (!delete_header && (t->fe->options & PR_O_HTTP_CLOSE)
			    && (strncasecmp(rep->h, "Connection: ", 12) == 0)) {
				delete_header = 1;
			}

			/* try headers regexps */
			if (!delete_header && t->fi->rsp_exp != NULL
			    && !(t->flags & SN_SVDENY)) {
				struct hdr_exp *exp;
				char term;
		
				term = *ptr;
				*ptr = '\0';
				exp = t->fi->rsp_exp;
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
			    && (t->be->cookie_name != NULL || t->fi->capture_name != NULL || t->be->appsession_name !=NULL)
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
					if (t->fi->capture_name != NULL &&
					    t->logs.srv_cookie == NULL &&
					    (p4 - p1 >= t->fi->capture_namelen) &&
					    memcmp(p1, t->fi->capture_name, t->fi->capture_namelen) == 0) {
						int log_len = p4 - p1;

						if ((t->logs.srv_cookie = pool_alloc(capture)) == NULL) {
							Alert("HTTP logging : out of memory.\n");
						}

						if (log_len > t->fi->capture_len)
							log_len = t->fi->capture_len;
						memcpy(t->logs.srv_cookie, p1, log_len);
						t->logs.srv_cookie[log_len] = 0;
					}

					if ((p2 - p1 == t->be->cookie_len) && (t->be->cookie_name != NULL) &&
					    (memcmp(p1, t->be->cookie_name, p2 - p1) == 0)) {
						/* Cool... it's the right one */
						t->flags |= SN_SCK_SEEN;
			
						/* If the cookie is in insert mode on a known server, we'll delete
						 * this occurrence because we'll insert another one later.
						 * We'll delete it too if the "indirect" option is set and we're in
						 * a direct access. */
						if (((t->srv) && (t->be->options & PR_O_COOK_INS)) ||
						    ((t->flags & SN_DIRECT) && (t->be->options & PR_O_COOK_IND))) {
							/* this header must be deleted */
							delete_header = 1;
							t->flags |= SN_SCK_DELETED;
						}
						else if ((t->srv) && (t->be->options & PR_O_COOK_RW)) {
							/* replace bytes p3->p4 with the cookie name associated
							 * with this server since we know it.
							 */
							buffer_replace2(rep, p3, p4, t->srv->cookie, t->srv->cklen);
							t->flags |= SN_SCK_INSERTED | SN_SCK_DELETED;
						}
						else if ((t->srv) && (t->be->options & PR_O_COOK_PFX)) {
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
					if ((t->be->appsession_name != NULL) &&
					    (memcmp(p1, t->be->appsession_name, p2 - p1) == 0)) {

						/* Cool... it's the right one */

						size_t server_id_len = strlen(t->srv->id) + 1;
						asession_temp = &local_asession;
		      
						if ((asession_temp->sessid = pool_alloc_from(apools.sessid, apools.ses_msize)) == NULL) {
							Alert("Not enought Memory process_srv():asession->sessid:malloc().\n");
							send_log(t->be, LOG_ALERT, "Not enought Memory process_srv():asession->sessid:malloc().\n");
						}
						memcpy(asession_temp->sessid, p3, t->be->appsession_len);
						asession_temp->sessid[t->be->appsession_len] = 0;
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
							chtbl_insert(&(t->be->htbl_proxy), (void *) asession_temp);
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
		      
						tv_delayfrom(&asession_temp->expire, &now, t->be->appsession_timeout);

#if defined(DEBUG_HASH)
						print_table(&(t->be->htbl_proxy));
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
			    (t->be->options & PR_O_CHK_CACHE) &&
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
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);
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
			if (may_dequeue_tasks(t->srv, t->be))
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
			if (may_dequeue_tasks(t->srv, t->be))
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
		else if (MY_FD_ISSET(t->srv_fd, StaticWriteEvent) && tv_cmp2_ms(&req->wex, &now) <= 0) {
			MY_FD_CLR(t->srv_fd, StaticWriteEvent);
			tv_eternity(&req->wex);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			MY_FD_SET(t->srv_fd, StaticReadEvent);
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

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
			if (may_dequeue_tasks(t->srv, t->be))
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
			if (t->be->srvtimeout)
				tv_delayfrom(&rep->rex, &now, t->be->srvtimeout);

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
			if (MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_CLR(t->srv_fd, StaticWriteEvent); /* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* buffer not empty, there are still data to be transferred */
			if (! MY_FD_ISSET(t->srv_fd, StaticWriteEvent)) {
				MY_FD_SET(t->srv_fd, StaticWriteEvent); /* restart writing */
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
			if (MY_FD_ISSET(t->srv_fd, StaticReadEvent)) {
				MY_FD_CLR(t->srv_fd, StaticReadEvent);
				tv_eternity(&rep->rex);
			}
		}
		else {
			if (! MY_FD_ISSET(t->srv_fd, StaticReadEvent)) {
				MY_FD_SET(t->srv_fd, StaticReadEvent);
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
			if (may_dequeue_tasks(t->srv, t->be))
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
			if (may_dequeue_tasks(t->srv, t->be))
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
			if (may_dequeue_tasks(t->srv, t->be))
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
			if (may_dequeue_tasks(t->srv, t->be))
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
			if (may_dequeue_tasks(t->srv, t->be))
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
			if (may_dequeue_tasks(t->srv, t->be))
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
			len = sprintf(trash, "%08x:%s.srvcls[%04x:%04x]\n", t->uniq_id, t->be->id, (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
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

				if (s->fi->uri_auth && s->fi->uri_auth->scope) {
					/* we have a limited scope, we have to check the proxy name */
					struct stat_scope *scope;
					int len;

					len = strlen(px->id);
					scope = s->fi->uri_auth->scope;

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
						   "%d conns (maxconn=%d), %d queued (%d unassigned), %d total conns</h3>\n"
						   "",
						   px->id,
						   px->nbconn, px->maxconn, px->totpend, px->nbpend, px->cum_conn);
		
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
			dispatch_sess = px->nbconn;
			dispatch_cum  = px->cum_conn;
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
					   "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>",
					   dispatch_sess, px->nbconn_max, px->maxconn, dispatch_cum);

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
					   "<td align=right><b>%d</b></td><td align=right><b>%d</b></td><td align=right><b>%d</b></td><td align=right><b>%d</b></td>",
					   px->nbconn, px->nbconn_max, px->maxconn, px->cum_conn);

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
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
