/*
 * Client-side variables and functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/time.h>

#include <types/backend.h>
#include <types/buffers.h>
#include <types/global.h>
#include <types/httperr.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/session.h>

#include <proto/buffers.h>
#include <proto/client.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/stream_sock.h>
#include <proto/task.h>



/*
 * FIXME: This should move to the STREAM_SOCK code then split into TCP and HTTP.
 */
    
/*
 * this function is called on a read event from a listen socket, corresponding
 * to an accept. It tries to accept as many connections as possible.
 * It returns 0.
 */
int event_accept(int fd) {
	struct proxy *p = (struct proxy *)fdtab[fd].owner;
	struct session *s;
	struct task *t;
	int cfd;
	int max_accept;

	if (global.nbproc > 1)
		max_accept = 8; /* let other processes catch some connections too */
	else
		max_accept = -1;

	while (p->nbconn < p->maxconn && max_accept--) {
		struct sockaddr_storage addr;
		socklen_t laddr = sizeof(addr);

		if ((cfd = accept(fd, (struct sockaddr *)&addr, &laddr)) == -1) {
			switch (errno) {
			case EAGAIN:
			case EINTR:
			case ECONNABORTED:
				return 0;	    /* nothing more to accept */
			case ENFILE:
				send_log(p, LOG_EMERG,
					 "Proxy %s reached system FD limit at %d. Please check system tunables.\n",
					 p->id, maxfd);
				return 0;
			case EMFILE:
				send_log(p, LOG_EMERG,
					 "Proxy %s reached process FD limit at %d. Please check 'ulimit-n' and restart.\n",
					 p->id, maxfd);
				return 0;
			case ENOBUFS:
			case ENOMEM:
				send_log(p, LOG_EMERG,
					 "Proxy %s reached system memory limit at %d sockets. Please check system tunables.\n",
					 p->id, maxfd);
				return 0;
			default:
				return 0;
			}
		}

		if ((s = pool_alloc(session)) == NULL) { /* disable this proxy for a while */
			Alert("out of memory in event_accept().\n");
			MY_FD_CLR(fd, StaticReadEvent);
			p->state = PR_STIDLE;
			close(cfd);
			return 0;
		}

		/* if this session comes from a known monitoring system, we want to ignore
		 * it as soon as possible, which means closing it immediately for TCP.
		 */
		s->flags = 0;
		if (addr.ss_family == AF_INET &&
		    p->mon_mask.s_addr &&
		    (((struct sockaddr_in *)&addr)->sin_addr.s_addr & p->mon_mask.s_addr) == p->mon_net.s_addr) {
			if (p->mode == PR_MODE_TCP) {
				close(cfd);
				pool_free(session, s);
				continue;
			}
			s->flags |= SN_MONITOR;
		}

		if ((t = pool_alloc(task)) == NULL) { /* disable this proxy for a while */
			Alert("out of memory in event_accept().\n");
			MY_FD_CLR(fd, StaticReadEvent);
			p->state = PR_STIDLE;
			close(cfd);
			pool_free(session, s);
			return 0;
		}

		s->cli_addr = addr;
		if (cfd >= global.maxsock) {
			Alert("accept(): not enough free sockets. Raise -n argument. Giving up.\n");
			close(cfd);
			pool_free(task, t);
			pool_free(session, s);
			return 0;
		}

		if ((fcntl(cfd, F_SETFL, O_NONBLOCK) == -1) ||
		    (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
				(char *) &one, sizeof(one)) == -1)) {
			Alert("accept(): cannot set the socket in non blocking mode. Giving up\n");
			close(cfd);
			pool_free(task, t);
			pool_free(session, s);
			return 0;
		}

		if (p->options & PR_O_TCP_CLI_KA)
			setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

		t->next = t->prev = t->rqnext = NULL; /* task not in run queue yet */
		t->wq = LIST_HEAD(wait_queue[0]); /* but already has a wait queue assigned */
		t->state = TASK_IDLE;
		t->process = process_session;
		t->context = s;

		s->task = t;
#ifdef BUILD_WITH_PROXY
		s->proxy = p;
#endif
		s->be = s->fe = s->fi = p;

		s->cli_state = (p->mode == PR_MODE_HTTP) ?  CL_STHEADERS : CL_STDATA; /* no HTTP headers for non-HTTP proxies */
		s->srv_state = SV_STIDLE;
		s->req = s->rep = NULL; /* will be allocated later */

		s->cli_fd = cfd;
		s->srv_fd = -1;
		s->req_line.len = -1;
		s->auth_hdr.len = -1;
		s->srv = NULL;
		s->pend_pos = NULL;
		s->conn_retries = p->conn_retries;

		if (s->flags & SN_MONITOR)
			s->logs.logwait = 0;
		else
			s->logs.logwait = p->to_log;

		s->logs.tv_accept = now;
		s->logs.t_request = -1;
		s->logs.t_queue = -1;
		s->logs.t_connect = -1;
		s->logs.t_data = -1;
		s->logs.t_close = 0;
		s->logs.uri = NULL;
		s->logs.cli_cookie = NULL;
		s->logs.srv_cookie = NULL;
		s->logs.status = -1;
		s->logs.bytes = 0;
		s->logs.prx_queue_size = 0;  /* we get the number of pending conns before us */
		s->logs.srv_queue_size = 0; /* we will get this number soon */

		s->data_source = DATA_SRC_NONE;

		s->uniq_id = totalconn;
		p->cum_conn++;

		if (p->nb_req_cap > 0) {
			if ((s->req_cap =
			     pool_alloc_from(p->req_cap_pool, p->nb_req_cap*sizeof(char *)))
			    == NULL) { /* no memory */
				close(cfd); /* nothing can be done for this fd without memory */
				pool_free(task, t);
				pool_free(session, s);
				return 0;
			}
			memset(s->req_cap, 0, p->nb_req_cap*sizeof(char *));
		}
		else
			s->req_cap = NULL;

		if (p->nb_rsp_cap > 0) {
			if ((s->rsp_cap =
			     pool_alloc_from(p->rsp_cap_pool, p->nb_rsp_cap*sizeof(char *)))
			    == NULL) { /* no memory */
				if (s->req_cap != NULL)
					pool_free_to(p->req_cap_pool, s->req_cap);
				close(cfd); /* nothing can be done for this fd without memory */
				pool_free(task, t);
				pool_free(session, s);
				return 0;
			}
			memset(s->rsp_cap, 0, p->nb_rsp_cap*sizeof(char *));
		}
		else
			s->rsp_cap = NULL;

		if ((p->mode == PR_MODE_TCP || p->mode == PR_MODE_HTTP)
		    && (p->logfac1 >= 0 || p->logfac2 >= 0)) {
			struct sockaddr_storage sockname;
			socklen_t namelen = sizeof(sockname);

			if (addr.ss_family != AF_INET ||
			    !(s->fe->options & PR_O_TRANSP) ||
			    get_original_dst(cfd, (struct sockaddr_in *)&sockname, &namelen) == -1)
				getsockname(cfd, (struct sockaddr *)&sockname, &namelen);

			if (p->to_log) {
				/* we have the client ip */
				if (s->logs.logwait & LW_CLIP)
					if (!(s->logs.logwait &= ~LW_CLIP))
						sess_log(s);
			}
			else if (s->cli_addr.ss_family == AF_INET) {
				char pn[INET_ADDRSTRLEN], sn[INET_ADDRSTRLEN];
				if (inet_ntop(AF_INET, (const void *)&((struct sockaddr_in *)&sockname)->sin_addr,
					      sn, sizeof(sn)) &&
				    inet_ntop(AF_INET, (const void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
					      pn, sizeof(pn))) {
					send_log(p, LOG_INFO, "Connect from %s:%d to %s:%d (%s/%s)\n",
						 pn, ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port),
						 sn, ntohs(((struct sockaddr_in *)&sockname)->sin_port),
						 p->id, (p->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				}
			}
			else {
				char pn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];
				if (inet_ntop(AF_INET6, (const void *)&((struct sockaddr_in6 *)&sockname)->sin6_addr,
					      sn, sizeof(sn)) &&
				    inet_ntop(AF_INET6, (const void *)&((struct sockaddr_in6 *)&s->cli_addr)->sin6_addr,
					      pn, sizeof(pn))) {
					send_log(p, LOG_INFO, "Connect from %s:%d to %s:%d (%s/%s)\n",
						 pn, ntohs(((struct sockaddr_in6 *)&s->cli_addr)->sin6_port),
						 sn, ntohs(((struct sockaddr_in6 *)&sockname)->sin6_port),
						 p->id, (p->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				}
			}
		}

		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			struct sockaddr_in sockname;
			socklen_t namelen = sizeof(sockname);
			int len;
			if (addr.ss_family != AF_INET ||
			    !(s->fe->options & PR_O_TRANSP) ||
			    get_original_dst(cfd, (struct sockaddr_in *)&sockname, &namelen) == -1)
				getsockname(cfd, (struct sockaddr *)&sockname, &namelen);

			if (s->cli_addr.ss_family == AF_INET) {
				char pn[INET_ADDRSTRLEN];
				inet_ntop(AF_INET,
					  (const void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
					  pn, sizeof(pn));

				len = sprintf(trash, "%08x:%s.accept(%04x)=%04x from [%s:%d]\n",
					      s->uniq_id, p->id, (unsigned short)fd, (unsigned short)cfd,
					      pn, ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port));
			}
			else {
				char pn[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&s->cli_addr))->sin6_addr,
					  pn, sizeof(pn));

				len = sprintf(trash, "%08x:%s.accept(%04x)=%04x from [%s:%d]\n",
					      s->uniq_id, p->id, (unsigned short)fd, (unsigned short)cfd,
					      pn, ntohs(((struct sockaddr_in6 *)(&s->cli_addr))->sin6_port));
			}

			write(1, trash, len);
		}

		if ((s->req = pool_alloc(buffer)) == NULL) { /* no memory */
			if (s->rsp_cap != NULL)
				pool_free_to(p->rsp_cap_pool, s->rsp_cap);
			if (s->req_cap != NULL)
				pool_free_to(p->req_cap_pool, s->req_cap);
			close(cfd); /* nothing can be done for this fd without memory */
			pool_free(task, t);
			pool_free(session, s);
			return 0;
		}

		buffer_init(s->req);
		s->req->rlim += BUFSIZE;
		if (s->cli_state == CL_STHEADERS) /* reserve some space for header rewriting */
			s->req->rlim -= MAXREWRITE;

		s->req->rto = s->fe->clitimeout;
		s->req->wto = s->be->srvtimeout;
		s->req->cto = s->be->srvtimeout;

		if ((s->rep = pool_alloc(buffer)) == NULL) { /* no memory */
			pool_free(buffer, s->req);
			if (s->rsp_cap != NULL)
				pool_free_to(p->rsp_cap_pool, s->rsp_cap);
			if (s->req_cap != NULL)
				pool_free_to(p->req_cap_pool, s->req_cap);
			close(cfd); /* nothing can be done for this fd without memory */
			pool_free(task, t);
			pool_free(session, s);
			return 0;
		}

		buffer_init(s->rep);

		s->rep->rto = s->be->srvtimeout;
		s->rep->wto = s->be->clitimeout;
		s->rep->cto = 0;

		fdtab[cfd].owner = t;
		fdtab[cfd].state = FD_STREADY;
		fdtab[cfd].cb[DIR_RD].f = &stream_sock_read;
		fdtab[cfd].cb[DIR_RD].b = s->req;
		fdtab[cfd].cb[DIR_WR].f = &stream_sock_write;
		fdtab[cfd].cb[DIR_WR].b = s->rep;

		if ((p->mode == PR_MODE_HTTP && (s->flags & SN_MONITOR)) ||
		    (p->mode == PR_MODE_HEALTH && (p->options & PR_O_HTTP_CHK)))
			/* Either we got a request from a monitoring system on an HTTP instance,
			 * or we're in health check mode with the 'httpchk' option enabled. In
			 * both cases, we return a fake "HTTP/1.0 200 OK" response and we exit.
			 */
			client_retnclose(s, 19, "HTTP/1.0 200 OK\r\n\r\n"); /* forge a 200 response */
		else if (p->mode == PR_MODE_HEALTH) {  /* health check mode, no client reading */
			client_retnclose(s, 3, "OK\n"); /* forge an "OK" response */
		}
		else {
			MY_FD_SET(cfd, StaticReadEvent);
		}

#if defined(DEBUG_FULL) && defined(ENABLE_EPOLL)
		if (PrevReadEvent) {
			assert(!(MY_FD_ISSET(cfd, PrevReadEvent)));
			assert(!(MY_FD_ISSET(cfd, PrevWriteEvent)));
		}
#endif
		fd_insert(cfd);

		tv_eternity(&s->req->rex);
		tv_eternity(&s->req->wex);
		tv_eternity(&s->req->cex);
		tv_eternity(&s->rep->rex);
		tv_eternity(&s->rep->wex);

		if (s->fe->clitimeout) {
			if (MY_FD_ISSET(cfd, StaticReadEvent))
				tv_delayfrom(&s->req->rex, &now, s->fe->clitimeout);
			if (MY_FD_ISSET(cfd, StaticWriteEvent))
				tv_delayfrom(&s->rep->wex, &now, s->fe->clitimeout);
		}

		tv_min(&t->expire, &s->req->rex, &s->rep->wex);

		task_queue(t);

		if (p->mode != PR_MODE_HEALTH)
			task_wakeup(&rq, t);

		p->nbconn++;
		if (p->nbconn > p->nbconn_max)
			p->nbconn_max = p->nbconn;
		actconn++;
		totalconn++;

		// fprintf(stderr, "accepting from %p => %d conn, %d total, task=%p\n", p, actconn, totalconn, t);
	} /* end of while (p->nbconn < p->maxconn) */
	return 0;
}



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
