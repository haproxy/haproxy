/*
 * Client-side variables and functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
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

#include <types/acl.h>
#include <types/backend.h>
#include <types/buffers.h>
#include <types/global.h>
#include <types/httperr.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/session.h>

#include <proto/acl.h>
#include <proto/buffers.h>
#include <proto/client.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/proto_http.h>
#include <proto/session.h>
#include <proto/stream_sock.h>
#include <proto/task.h>


/* Retrieves the original destination address used by the client, and sets the
 * SN_FRT_ADDR_SET flag.
 */
void get_frt_addr(struct session *s)
{
	socklen_t namelen = sizeof(s->frt_addr);

	if (get_original_dst(s->cli_fd, (struct sockaddr_in *)&s->frt_addr, &namelen) == -1)
		getsockname(s->cli_fd, (struct sockaddr *)&s->frt_addr, &namelen);
	s->flags |= SN_FRT_ADDR_SET;
}

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
	struct http_txn *txn;
	struct task *t;
	int cfd;
	int max_accept;

	if (global.nbproc > 1)
		max_accept = 8; /* let other processes catch some connections too */
	else
		max_accept = -1;

	while (p->feconn < p->maxconn && max_accept--) {
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

		if ((s = pool_alloc2(pool2_session)) == NULL) { /* disable this proxy for a while */
			Alert("out of memory in event_accept().\n");
			EV_FD_CLR(fd, DIR_RD);
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
				pool_free2(pool2_session, s);
				continue;
			}
			s->flags |= SN_MONITOR;
		}

		if ((t = pool_alloc2(pool2_task)) == NULL) { /* disable this proxy for a while */
			Alert("out of memory in event_accept().\n");
			EV_FD_CLR(fd, DIR_RD);
			p->state = PR_STIDLE;
			close(cfd);
			pool_free2(pool2_session, s);
			return 0;
		}

		s->cli_addr = addr;
		if (cfd >= global.maxsock) {
			Alert("accept(): not enough free sockets. Raise -n argument. Giving up.\n");
			close(cfd);
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		if ((fcntl(cfd, F_SETFL, O_NONBLOCK) == -1) ||
		    (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
				(char *) &one, sizeof(one)) == -1)) {
			Alert("accept(): cannot set the socket in non blocking mode. Giving up\n");
			close(cfd);
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		if (p->options & PR_O_TCP_CLI_KA)
			setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

		t->wq = NULL;
		t->qlist.p = NULL;
		t->state = TASK_IDLE;
		t->process = process_session;
		t->context = s;

		s->task = t;
		s->be = s->fe = p;

		s->cli_state = (p->mode == PR_MODE_HTTP) ?  CL_STHEADERS : CL_STDATA; /* no HTTP headers for non-HTTP proxies */
		s->srv_state = SV_STIDLE;
		s->req = s->rep = NULL; /* will be allocated later */

		s->cli_fd = cfd;
		s->srv_fd = -1;
		s->srv = NULL;
		s->pend_pos = NULL;
		s->conn_retries = p->conn_retries;

		/* FIXME: the logs are horribly complicated now, because they are
		 * defined in <p>, <p>, and later <be> and <be>.
		 */

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
		s->logs.bytes_in = s->logs.bytes_out = 0;
		s->logs.prx_queue_size = 0;  /* we get the number of pending conns before us */
		s->logs.srv_queue_size = 0; /* we will get this number soon */

		s->data_source = DATA_SRC_NONE;

		s->uniq_id = totalconn;
		p->cum_feconn++;	/* cum_beconn will be increased once assigned */

		txn = &s->txn;
		txn->flags = 0;
		/* Those variables will be checked and freed if non-NULL in
		 * session.c:session_free(). It is important that they are
		 * properly initialized.
		 */
		txn->srv_cookie = NULL;
		txn->cli_cookie = NULL;
		txn->uri = NULL;
		txn->req.cap = NULL;
		txn->rsp.cap = NULL;
		txn->hdr_idx.v = NULL;
		txn->hdr_idx.size = txn->hdr_idx.used = 0;

		if (p->mode == PR_MODE_HTTP) {
			txn->status = -1;

			txn->req.msg_state = HTTP_MSG_RQBEFORE; /* at the very beginning of the request */
			txn->req.sol = txn->req.eol = NULL;
			txn->req.som = txn->req.eoh = 0; /* relative to the buffer */
			txn->auth_hdr.len = -1;

			txn->hdr_idx.size = MAX_HTTP_HDR;

			if (p->nb_req_cap > 0) {
				if ((txn->req.cap = pool_alloc2(p->req_cap_pool)) == NULL) {
					/* no memory */
					close(cfd); /* nothing can be done for this fd without memory */
					pool_free2(pool2_task, t);
					pool_free2(pool2_session, s);
					return 0;
				}
				memset(txn->req.cap, 0, p->nb_req_cap*sizeof(char *));
			}


			if (p->nb_rsp_cap > 0) {
				if ((txn->rsp.cap = pool_alloc2(p->rsp_cap_pool)) == NULL) {
					/* no memory */
					if (txn->req.cap != NULL)
						pool_free2(p->req_cap_pool, txn->req.cap);
					close(cfd); /* nothing can be done for this fd without memory */
					pool_free2(pool2_task, t);
					pool_free2(pool2_session, s);
					return 0;
				}
				memset(txn->rsp.cap, 0, p->nb_rsp_cap*sizeof(char *));
			}


			if ((txn->hdr_idx.v =
			     pool_alloc_from(p->hdr_idx_pool, txn->hdr_idx.size*sizeof(*txn->hdr_idx.v)))
			    == NULL) { /* no memory */
				if (txn->rsp.cap != NULL)
					pool_free2(p->rsp_cap_pool, txn->rsp.cap);
				if (txn->req.cap != NULL)
					pool_free2(p->req_cap_pool, txn->req.cap);
				close(cfd); /* nothing can be done for this fd without memory */
				pool_free2(pool2_task, t);
				pool_free2(pool2_session, s);
				return 0;
			}
			hdr_idx_init(&txn->hdr_idx);
		}

		if ((p->mode == PR_MODE_TCP || p->mode == PR_MODE_HTTP)
		    && (p->logfac1 >= 0 || p->logfac2 >= 0)) {
			if (p->to_log) {
				/* we have the client ip */
				if (s->logs.logwait & LW_CLIP)
					if (!(s->logs.logwait &= ~LW_CLIP))
						tcp_sess_log(s);
			}
			else if (s->cli_addr.ss_family == AF_INET) {
				char pn[INET_ADDRSTRLEN], sn[INET_ADDRSTRLEN];

				if (!(s->flags & SN_FRT_ADDR_SET))
					get_frt_addr(s);

				if (inet_ntop(AF_INET, (const void *)&((struct sockaddr_in *)&s->frt_addr)->sin_addr,
					      sn, sizeof(sn)) &&
				    inet_ntop(AF_INET, (const void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
					      pn, sizeof(pn))) {
					send_log(p, LOG_INFO, "Connect from %s:%d to %s:%d (%s/%s)\n",
						 pn, ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port),
						 sn, ntohs(((struct sockaddr_in *)&s->frt_addr)->sin_port),
						 p->id, (p->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				}
			}
			else {
				char pn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];

				if (!(s->flags & SN_FRT_ADDR_SET))
					get_frt_addr(s);

				if (inet_ntop(AF_INET6, (const void *)&((struct sockaddr_in6 *)&s->frt_addr)->sin6_addr,
					      sn, sizeof(sn)) &&
				    inet_ntop(AF_INET6, (const void *)&((struct sockaddr_in6 *)&s->cli_addr)->sin6_addr,
					      pn, sizeof(pn))) {
					send_log(p, LOG_INFO, "Connect from %s:%d to %s:%d (%s/%s)\n",
						 pn, ntohs(((struct sockaddr_in6 *)&s->cli_addr)->sin6_port),
						 sn, ntohs(((struct sockaddr_in6 *)&s->frt_addr)->sin6_port),
						 p->id, (p->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				}
			}
		}

		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			int len;

			if (!(s->flags & SN_FRT_ADDR_SET))
				get_frt_addr(s);

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

		if ((s->req = pool_alloc2(pool2_buffer)) == NULL) { /* no memory */
			if (txn->hdr_idx.v != NULL)
				pool_free_to(p->hdr_idx_pool, txn->hdr_idx.v);
			if (txn->rsp.cap != NULL)
				pool_free2(p->rsp_cap_pool, txn->rsp.cap);
			if (txn->req.cap != NULL)
				pool_free2(p->req_cap_pool, txn->req.cap);
			close(cfd); /* nothing can be done for this fd without memory */
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		buffer_init(s->req);
		s->req->rlim += BUFSIZE;
		if (s->cli_state == CL_STHEADERS) /* reserve some space for header rewriting */
			s->req->rlim -= MAXREWRITE;

		s->req->rto = s->fe->clitimeout;
		s->req->wto = s->be->srvtimeout;
		s->req->cto = s->be->srvtimeout;

		if ((s->rep = pool_alloc2(pool2_buffer)) == NULL) { /* no memory */
			pool_free2(pool2_buffer, s->req);
			if (txn->hdr_idx.v != NULL)
				pool_free_to(p->hdr_idx_pool, txn->hdr_idx.v);
			if (txn->rsp.cap != NULL)
				pool_free2(p->rsp_cap_pool, txn->rsp.cap);
			if (txn->req.cap != NULL)
				pool_free2(p->req_cap_pool, txn->req.cap);
			close(cfd); /* nothing can be done for this fd without memory */
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		buffer_init(s->rep);

		s->rep->rto = s->be->srvtimeout;
		s->rep->wto = s->fe->clitimeout;
		tv_zero(&s->rep->cto);

		fd_insert(cfd);
		fdtab[cfd].owner = t;
		fdtab[cfd].state = FD_STREADY;
		fdtab[cfd].cb[DIR_RD].f = &stream_sock_read;
		fdtab[cfd].cb[DIR_RD].b = s->req;
		fdtab[cfd].cb[DIR_WR].f = &stream_sock_write;
		fdtab[cfd].cb[DIR_WR].b = s->rep;
		fdtab[cfd].ev = 0;

		if ((p->mode == PR_MODE_HTTP && (s->flags & SN_MONITOR)) ||
		    (p->mode == PR_MODE_HEALTH && (p->options & PR_O_HTTP_CHK))) {
			/* Either we got a request from a monitoring system on an HTTP instance,
			 * or we're in health check mode with the 'httpchk' option enabled. In
			 * both cases, we return a fake "HTTP/1.0 200 OK" response and we exit.
			 */
			struct chunk msg = { .str = "HTTP/1.0 200 OK\r\n\r\n", .len = 19 };
			client_retnclose(s, &msg); /* forge a 200 response */
		}
		else if (p->mode == PR_MODE_HEALTH) {  /* health check mode, no client reading */
			struct chunk msg = { .str = "OK\n", .len = 3 };
			client_retnclose(s, &msg); /* forge an "OK" response */
		}
		else {
			EV_FD_SET(cfd, DIR_RD);
		}

		tv_eternity(&s->req->rex);
		tv_eternity(&s->req->wex);
		tv_eternity(&s->req->cex);
		tv_eternity(&s->rep->rex);
		tv_eternity(&s->rep->wex);
		tv_eternity(&t->expire);

		if (tv_isset(&s->fe->clitimeout)) {
			if (EV_FD_ISSET(cfd, DIR_RD)) {
				tv_add(&s->req->rex, &now, &s->fe->clitimeout);
				t->expire = s->req->rex;
			}
			if (EV_FD_ISSET(cfd, DIR_WR)) {
				tv_add(&s->rep->wex, &now, &s->fe->clitimeout);
				t->expire = s->req->rex;
			}
		}

		task_queue(t);

		if (p->mode != PR_MODE_HEALTH)
			task_wakeup(t);

		p->feconn++;  /* beconn will be increased later */
		if (p->feconn > p->feconn_max)
			p->feconn_max = p->feconn;
		actconn++;
		totalconn++;

		// fprintf(stderr, "accepting from %p => %d conn, %d total, task=%p\n", p, actconn, totalconn, t);
	} /* end of while (p->feconn < p->maxconn) */
	return 0;
}



/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* set test->ptr to point to the source IPv4/IPv6 address and test->i to the family */
static int acl_fetch_src(struct proxy *px, struct session *l4, void *l7, void *arg, struct acl_test *test)
{
	test->i = l4->cli_addr.ss_family;
	if (test->i == AF_INET)
		test->ptr = (void *)&((struct sockaddr_in *)&l4->cli_addr)->sin_addr;
	else
		test->ptr = (void *)&((struct sockaddr_in6 *)(&l4->cli_addr))->sin6_addr;
	test->flags = ACL_TEST_F_READ_ONLY;
	return 1;
}


/* set test->i to the connexion's source port */
static int acl_fetch_sport(struct proxy *px, struct session *l4, void *l7, void *arg, struct acl_test *test)
{
	if (l4->cli_addr.ss_family == AF_INET)
		test->i = ntohs(((struct sockaddr_in *)&l4->cli_addr)->sin_port);
	else
		test->i = ntohs(((struct sockaddr_in6 *)(&l4->cli_addr))->sin6_port);
	test->flags = 0;
	return 1;
}


/* set test->ptr to point to the frontend's IPv4/IPv6 address and test->i to the family */
static int acl_fetch_dst(struct proxy *px, struct session *l4, void *l7, void *arg, struct acl_test *test)
{
	if (!(l4->flags & SN_FRT_ADDR_SET))
		get_frt_addr(l4);

	test->i = l4->frt_addr.ss_family;
	if (test->i == AF_INET)
		test->ptr = (void *)&((struct sockaddr_in *)&l4->frt_addr)->sin_addr;
	else
		test->ptr = (void *)&((struct sockaddr_in6 *)(&l4->frt_addr))->sin6_addr;
	test->flags = ACL_TEST_F_READ_ONLY;
	return 1;
}


/* set test->i to the frontend connexion's destination port */
static int acl_fetch_dport(struct proxy *px, struct session *l4, void *l7, void *arg, struct acl_test *test)
{
	if (!(l4->flags & SN_FRT_ADDR_SET))
		get_frt_addr(l4);

	if (l4->frt_addr.ss_family == AF_INET)
		test->i = ntohs(((struct sockaddr_in *)&l4->frt_addr)->sin_port);
	else
		test->i = ntohs(((struct sockaddr_in6 *)(&l4->frt_addr))->sin6_port);
	test->flags = 0;
	return 1;
}

/* set test->i to the number of connexions to the proxy */
static int acl_fetch_dconn(struct proxy *px, struct session *l4, void *l7, void *arg, struct acl_test *test)
{
	test->i = px->feconn;
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
	{ "src_port",   acl_parse_range, acl_fetch_sport,  acl_match_range },
	{ "src",        acl_parse_ip,    acl_fetch_src,    acl_match_ip    },
	{ "dst",        acl_parse_ip,    acl_fetch_dst,    acl_match_ip    },
	{ "dst_port",   acl_parse_range, acl_fetch_dport,  acl_match_range },
#if 0
	{ "src_limit",  acl_parse_int,   acl_fetch_sconn,  acl_match_max   },
#endif
	{ "dst_limit",  acl_parse_int,   acl_fetch_dconn,  acl_match_max   },
	{ NULL, NULL, NULL, NULL },
}};


__attribute__((constructor))
static void __client_init(void)
{
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
