/*
 * Client-side variables and functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
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

#include <types/global.h>

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
	struct listener *l = fdtab[fd].owner;
	struct proxy *p = (struct proxy *)l->private; /* attached frontend */
	struct session *s;
	struct http_txn *txn;
	struct task *t;
	int cfd;
	int max_accept = global.tune.maxaccept;

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
			goto out_close;
		}

		s->flags = 0;
		s->term_trace = 0;

		/* if this session comes from a known monitoring system, we want to ignore
		 * it as soon as possible, which means closing it immediately for TCP.
		 */
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
			goto out_free_session;
		}

		s->cli_addr = addr;
		if (cfd >= global.maxsock) {
			Alert("accept(): not enough free sockets. Raise -n argument. Giving up.\n");
			goto out_free_task;
		}

		if ((fcntl(cfd, F_SETFL, O_NONBLOCK) == -1) ||
		    (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
				(char *) &one, sizeof(one)) == -1)) {
			Alert("accept(): cannot set the socket in non blocking mode. Giving up\n");
			goto out_free_task;
		}

		if (p->options & PR_O_TCP_CLI_KA)
			setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

		if (p->options & PR_O_TCP_NOLING)
			setsockopt(cfd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));

		task_init(t);
		t->process = process_session;
		t->context = s;

		s->task = t;
		s->be = s->fe = p;

		/* in HTTP mode, content switching requires that the backend
		 * first points to the same proxy as the frontend. However, in
		 * TCP mode there will be no header processing so any default
		 * backend must be assigned if set.
		 */
		if (p->mode == PR_MODE_TCP) {
			if (p->defbe.be)
				s->be = p->defbe.be;
			s->flags |= SN_BE_ASSIGNED;
		}

		s->cli_state = CL_STDATA;
		s->req = s->rep = NULL; /* will be allocated later */

		s->si[0].state = SI_ST_EST;
		s->si[0].err_type = SI_ET_NONE;
		s->si[0].err_loc = NULL;
		s->si[0].owner = t;
		s->si[0].shutw = stream_sock_shutw;
		s->si[0].fd = cfd;
		s->cli_fd = cfd;

		s->si[1].state = SI_ST_INI;
		s->si[1].err_type = SI_ET_NONE;
		s->si[1].err_loc = NULL;
		s->si[1].owner = t;
		s->si[1].shutw = stream_sock_shutw;
		s->si[1].fd = -1; /* just to help with debugging */

		s->srv = s->prev_srv = s->srv_conn = NULL;
		s->pend_pos = NULL;
		s->conn_retries = s->be->conn_retries;

		/* FIXME: the logs are horribly complicated now, because they are
		 * defined in <p>, <p>, and later <be> and <be>.
		 */

		if (s->flags & SN_MONITOR)
			s->logs.logwait = 0;
		else
			s->logs.logwait = p->to_log;

		s->logs.accept_date = date; /* user-visible date for logging */
		s->logs.tv_accept = now;  /* corrected date for internal use */
		tv_zero(&s->logs.tv_request);
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
			txn->req.hdr_content_len = 0LL;
			txn->rsp.hdr_content_len = 0LL;
			txn->req.msg_state = HTTP_MSG_RQBEFORE; /* at the very beginning of the request */
			txn->rsp.msg_state = HTTP_MSG_RPBEFORE; /* at the very beginning of the response */
			txn->req.sol = txn->req.eol = NULL;
			txn->req.som = txn->req.eoh = 0; /* relative to the buffer */
			txn->auth_hdr.len = -1;

			if (p->nb_req_cap > 0) {
				if ((txn->req.cap = pool_alloc2(p->req_cap_pool)) == NULL)
					goto out_fail_reqcap;	/* no memory */

				memset(txn->req.cap, 0, p->nb_req_cap*sizeof(char *));
			}


			if (p->nb_rsp_cap > 0) {
				if ((txn->rsp.cap = pool_alloc2(p->rsp_cap_pool)) == NULL)
					goto out_fail_rspcap;	/* no memory */

				memset(txn->rsp.cap, 0, p->nb_rsp_cap*sizeof(char *));
			}


			txn->hdr_idx.size = MAX_HTTP_HDR;

			if ((txn->hdr_idx.v = pool_alloc2(p->hdr_idx_pool)) == NULL)
				goto out_fail_idx; /* no memory */

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

		if ((s->req = pool_alloc2(pool2_buffer)) == NULL)
			goto out_fail_req; /* no memory */

		buffer_init(s->req);
		s->req->prod = &s->si[0];
		s->req->cons = &s->si[1];
		s->si[0].ib = s->si[1].ob = s->req;

		if (p->mode == PR_MODE_HTTP) /* reserve some space for header rewriting */
			s->req->rlim -= MAXREWRITE;

		if (s->fe->tcp_req.inspect_delay)
			s->req->analysers |= AN_REQ_INSPECT;

		if (p->mode == PR_MODE_HTTP)
			s->req->analysers |= AN_REQ_HTTP_HDR;

		if (!s->req->analysers)
			buffer_write_ena(s->req);  /* don't wait to establish connection */

		s->req->rto = s->fe->timeout.client;
		s->req->wto = s->be->timeout.server;
		s->req->cto = s->be->timeout.connect;

		if ((s->rep = pool_alloc2(pool2_buffer)) == NULL)
			goto out_fail_rep; /* no memory */

		buffer_init(s->rep);
		s->rep->prod = &s->si[1];
		s->rep->cons = &s->si[0];
		s->si[0].ob = s->si[1].ib = s->rep;

		s->rep->rto = s->be->timeout.server;
		s->rep->wto = s->fe->timeout.client;
		s->rep->cto = TICK_ETERNITY;

		s->req->rex = TICK_ETERNITY;
		s->req->wex = TICK_ETERNITY;
		s->req->analyse_exp = TICK_ETERNITY;
		s->rep->rex = TICK_ETERNITY;
		s->rep->wex = TICK_ETERNITY;
		s->rep->analyse_exp = TICK_ETERNITY;
		t->expire = TICK_ETERNITY;

		fd_insert(cfd);
		fdtab[cfd].owner = &s->si[0];
		fdtab[cfd].listener = l;
		fdtab[cfd].state = FD_STREADY;
		fdtab[cfd].cb[DIR_RD].f = l->proto->read;
		fdtab[cfd].cb[DIR_RD].b = s->req;
		fdtab[cfd].cb[DIR_WR].f = l->proto->write;
		fdtab[cfd].cb[DIR_WR].b = s->rep;
		fdtab[cfd].peeraddr = (struct sockaddr *)&s->cli_addr;
		fdtab[cfd].peerlen = sizeof(s->cli_addr);

		if ((p->mode == PR_MODE_HTTP && (s->flags & SN_MONITOR)) ||
		    (p->mode == PR_MODE_HEALTH && (p->options & PR_O_HTTP_CHK))) {
			/* Either we got a request from a monitoring system on an HTTP instance,
			 * or we're in health check mode with the 'httpchk' option enabled. In
			 * both cases, we return a fake "HTTP/1.0 200 OK" response and we exit.
			 */
			struct chunk msg = { .str = "HTTP/1.0 200 OK\r\n\r\n", .len = 19 };
			client_retnclose(s, &msg); /* forge a 200 response */
			trace_term(s, TT_CLIENT_1);
			t->expire = s->rep->wex;
		}
		else if (p->mode == PR_MODE_HEALTH) {  /* health check mode, no client reading */
			struct chunk msg = { .str = "OK\n", .len = 3 };
			client_retnclose(s, &msg); /* forge an "OK" response */
			trace_term(s, TT_CLIENT_2);
			t->expire = s->rep->wex;
		}
		else {
			EV_FD_SET(cfd, DIR_RD);
		}

		/* it is important not to call the wakeup function directly but to
		 * pass through task_wakeup(), because this one knows how to apply
		 * priorities to tasks.
		 */
		if (p->mode != PR_MODE_HEALTH)
			task_wakeup(t, TASK_WOKEN_INIT);

		p->feconn++;  /* beconn will be increased later */
		if (p->feconn > p->feconn_max)
			p->feconn_max = p->feconn;

		if (s->flags & SN_BE_ASSIGNED) {
			s->be->cum_beconn++;
			s->be->beconn++;
			if (s->be->beconn > s->be->beconn_max)
				s->be->beconn_max = s->be->beconn;
		}
		actconn++;
		totalconn++;

		// fprintf(stderr, "accepting from %p => %d conn, %d total, task=%p\n", p, actconn, totalconn, t);
	} /* end of while (p->feconn < p->maxconn) */
	return 0;

	/* Error unrolling */
 out_fail_rep:
	pool_free2(pool2_buffer, s->req);
 out_fail_req:
	pool_free2(p->hdr_idx_pool, txn->hdr_idx.v);
 out_fail_idx:
	pool_free2(p->rsp_cap_pool, txn->rsp.cap);
 out_fail_rspcap:
	pool_free2(p->req_cap_pool, txn->req.cap);
 out_fail_reqcap:
 out_free_task:
	pool_free2(pool2_task, t);
 out_free_session:
	pool_free2(pool2_session, s);
 out_close:
	close(cfd);
	return 0;
}



/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* set test->ptr to point to the source IPv4/IPv6 address and test->i to the family */
static int
acl_fetch_src(struct proxy *px, struct session *l4, void *l7, int dir,
              struct acl_expr *expr, struct acl_test *test)
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
static int
acl_fetch_sport(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	if (l4->cli_addr.ss_family == AF_INET)
		test->i = ntohs(((struct sockaddr_in *)&l4->cli_addr)->sin_port);
	else
		test->i = ntohs(((struct sockaddr_in6 *)(&l4->cli_addr))->sin6_port);
	test->flags = 0;
	return 1;
}


/* set test->ptr to point to the frontend's IPv4/IPv6 address and test->i to the family */
static int
acl_fetch_dst(struct proxy *px, struct session *l4, void *l7, int dir,
              struct acl_expr *expr, struct acl_test *test)
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
static int
acl_fetch_dport(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
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
static int
acl_fetch_dconn(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	test->i = px->feconn;
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
	{ "src_port",   acl_parse_int,   acl_fetch_sport,    acl_match_int, ACL_USE_TCP_PERMANENT  },
	{ "src",        acl_parse_ip,    acl_fetch_src,      acl_match_ip,  ACL_USE_TCP4_PERMANENT },
	{ "dst",        acl_parse_ip,    acl_fetch_dst,      acl_match_ip,  ACL_USE_TCP4_PERMANENT },
	{ "dst_port",   acl_parse_int,   acl_fetch_dport,    acl_match_int, ACL_USE_TCP_PERMANENT  },
#if 0
	{ "src_limit",  acl_parse_int,   acl_fetch_sconn,    acl_match_int },
#endif
	{ "dst_conn",   acl_parse_int,   acl_fetch_dconn,    acl_match_int, ACL_USE_NOTHING },
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
