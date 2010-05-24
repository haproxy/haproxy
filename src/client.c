/*
 * Client-side variables and functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/stream_interface.h>
#include <proto/stream_sock.h>
#include <proto/task.h>


/* Retrieves the original destination address used by the client, and sets the
 * SN_FRT_ADDR_SET flag.
 */
void get_frt_addr(struct session *s)
{
	socklen_t namelen = sizeof(s->frt_addr);

	if (get_original_dst(s->si[0].fd, (struct sockaddr_in *)&s->frt_addr, &namelen) == -1)
		getsockname(s->si[0].fd, (struct sockaddr *)&s->frt_addr, &namelen);
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

	if (p->fe_sps_lim) {
		int max = freq_ctr_remain(&p->fe_sess_per_sec, p->fe_sps_lim, 0);
		if (max_accept > max)
			max_accept = max;
	}

	while (p->feconn < p->maxconn && actconn < global.maxconn && max_accept--) {
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

		if (l->nbconn >= l->maxconn) {
			/* too many connections, we shoot this one and return.
			 * FIXME: it would be better to simply switch the listener's
			 * state to LI_FULL and disable the FD. We could re-enable
			 * it upon fd_delete(), but this requires all protocols to
			 * be switched.
			 */
			goto out_close;
		}

		if ((s = pool_alloc2(pool2_session)) == NULL) { /* disable this proxy for a while */
			Alert("out of memory in event_accept().\n");
			EV_FD_CLR(fd, DIR_RD);
			p->state = PR_STIDLE;
			goto out_close;
		}

		LIST_ADDQ(&sessions, &s->list);
		LIST_INIT(&s->back_refs);

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

		if ((t = task_new()) == NULL) { /* disable this proxy for a while */
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

		if (global.tune.client_sndbuf)
			setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &global.tune.client_sndbuf, sizeof(global.tune.client_sndbuf));

		if (global.tune.client_rcvbuf)
			setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &global.tune.client_rcvbuf, sizeof(global.tune.client_rcvbuf));

		t->process = l->handler;
		t->context = s;
		t->nice = l->nice;

		s->task = t;
		s->listener = l;

		/* Note: initially, the session's backend points to the frontend.
		 * This changes later when switching rules are executed or
		 * when the default backend is assigned.
		 */
		s->be = s->fe = p;

		s->req = s->rep = NULL; /* will be allocated later */

		s->si[0].state = s->si[0].prev_state = SI_ST_EST;
		s->si[0].err_type = SI_ET_NONE;
		s->si[0].err_loc = NULL;
		s->si[0].owner = t;
		s->si[0].update = stream_sock_data_finish;
		s->si[0].shutr = stream_sock_shutr;
		s->si[0].shutw = stream_sock_shutw;
		s->si[0].chk_rcv = stream_sock_chk_rcv;
		s->si[0].chk_snd = stream_sock_chk_snd;
		s->si[0].connect = NULL;
		s->si[0].iohandler = NULL;
		s->si[0].fd = cfd;
		s->si[0].flags = SI_FL_NONE | SI_FL_CAP_SPLTCP; /* TCP splicing capable */
		if (s->fe->options2 & PR_O2_INDEPSTR)
			s->si[0].flags |= SI_FL_INDEP_STR;
		s->si[0].exp = TICK_ETERNITY;

		s->si[1].state = s->si[1].prev_state = SI_ST_INI;
		s->si[1].err_type = SI_ET_NONE;
		s->si[1].err_loc = NULL;
		s->si[1].owner = t;
		s->si[1].update = stream_sock_data_finish;
		s->si[1].shutr = stream_sock_shutr;
		s->si[1].shutw = stream_sock_shutw;
		s->si[1].chk_rcv = stream_sock_chk_rcv;
		s->si[1].chk_snd = stream_sock_chk_snd;
		s->si[1].connect = tcpv4_connect_server;
		s->si[1].iohandler = NULL;
		s->si[1].exp = TICK_ETERNITY;
		s->si[1].fd = -1; /* just to help with debugging */
		s->si[1].flags = SI_FL_NONE;
		if (s->be->options2 & PR_O2_INDEPSTR)
			s->si[1].flags |= SI_FL_INDEP_STR;

		s->srv = s->prev_srv = s->srv_conn = NULL;
		s->pend_pos = NULL;
		s->conn_retries = s->be->conn_retries;

		/* init store persistence */
		s->store_count = 0;

		/* FIXME: the logs are horribly complicated now, because they are
		 * defined in <p>, <p>, and later <be> and <be>.
		 */

		if (s->flags & SN_MONITOR)
			s->logs.logwait = 0;
		else
			s->logs.logwait = p->to_log;

		if (s->logs.logwait & LW_REQ)
			s->do_log = http_sess_log;
		else
			s->do_log = tcp_sess_log;

		/* default error reporting function, may be changed by analysers */
		s->srv_error = default_srv_error;

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
		totalconn++;
		proxy_inc_fe_ctr(l, p);	/* note: cum_beconn will be increased once assigned */

		txn = &s->txn;
		/* Those variables will be checked and freed if non-NULL in
		 * session.c:session_free(). It is important that they are
		 * properly initialized.
		 */
		txn->sessid = NULL;
		txn->srv_cookie = NULL;
		txn->cli_cookie = NULL;
		txn->uri = NULL;
		txn->req.cap = NULL;
		txn->rsp.cap = NULL;
		txn->hdr_idx.v = NULL;
		txn->hdr_idx.size = txn->hdr_idx.used = 0;

		if (p->mode == PR_MODE_HTTP) {
			/* the captures are only used in HTTP frontends */
			if (p->nb_req_cap > 0 &&
			    (txn->req.cap = pool_alloc2(p->req_cap_pool)) == NULL)
					goto out_fail_reqcap;	/* no memory */

			if (p->nb_rsp_cap > 0 &&
			    (txn->rsp.cap = pool_alloc2(p->rsp_cap_pool)) == NULL)
					goto out_fail_rspcap;	/* no memory */
		}

		if (p->acl_requires & ACL_USE_L7_ANY) {
			/* we have to allocate header indexes only if we know
			 * that we may make use of them. This of course includes
			 * (mode == PR_MODE_HTTP).
			 */
			txn->hdr_idx.size = MAX_HTTP_HDR;

			if ((txn->hdr_idx.v = pool_alloc2(p->hdr_idx_pool)) == NULL)
				goto out_fail_idx; /* no memory */

			/* and now initialize the HTTP transaction state */
			http_init_txn(s);
		}

		if ((p->mode == PR_MODE_TCP || p->mode == PR_MODE_HTTP)
		    && (p->logfac1 >= 0 || p->logfac2 >= 0)) {
			if (p->to_log) {
				/* we have the client ip */
				if (s->logs.logwait & LW_CLIP)
					if (!(s->logs.logwait &= ~LW_CLIP))
						s->do_log(s);
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

		s->req->size = global.tune.bufsize;
		buffer_init(s->req);
		s->req->prod = &s->si[0];
		s->req->cons = &s->si[1];
		s->si[0].ib = s->si[1].ob = s->req;

		s->req->flags |= BF_READ_ATTACHED; /* the producer is already connected */

		if (p->mode == PR_MODE_HTTP)
			s->req->flags |= BF_READ_DONTWAIT; /* one read is usually enough */

		/* activate default analysers enabled for this listener */
		s->req->analysers = l->analysers;

		/* note: this should not happen anymore since there's always at least the switching rules */
		if (!s->req->analysers) {
			buffer_auto_connect(s->req);  /* don't wait to establish connection */
			buffer_auto_close(s->req);    /* let the producer forward close requests */
		}

		s->req->rto = s->fe->timeout.client;
		s->req->wto = s->be->timeout.server;
		s->req->cto = s->be->timeout.connect;

		if ((s->rep = pool_alloc2(pool2_buffer)) == NULL)
			goto out_fail_rep; /* no memory */

		s->rep->size = global.tune.bufsize;
		buffer_init(s->rep);
		s->rep->prod = &s->si[1];
		s->rep->cons = &s->si[0];
		s->si[0].ob = s->si[1].ib = s->rep;
		s->rep->analysers = 0;

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
		fdtab[cfd].state = FD_STREADY;
		fdtab[cfd].flags = FD_FL_TCP | FD_FL_TCP_NODELAY;
		if (p->options & PR_O_TCP_NOLING)
			fdtab[cfd].flags |= FD_FL_TCP_NOLING;

		fdtab[cfd].cb[DIR_RD].f = l->proto->read;
		fdtab[cfd].cb[DIR_RD].b = s->req;
		fdtab[cfd].cb[DIR_WR].f = l->proto->write;
		fdtab[cfd].cb[DIR_WR].b = s->rep;
		fdinfo[cfd].peeraddr = (struct sockaddr *)&s->cli_addr;
		fdinfo[cfd].peerlen = sizeof(s->cli_addr);

		if ((p->mode == PR_MODE_HTTP && (s->flags & SN_MONITOR)) ||
		    (p->mode == PR_MODE_HEALTH && (p->options & PR_O_HTTP_CHK))) {
			/* Either we got a request from a monitoring system on an HTTP instance,
			 * or we're in health check mode with the 'httpchk' option enabled. In
			 * both cases, we return a fake "HTTP/1.0 200 OK" response and we exit.
			 */
			struct chunk msg;
			chunk_initstr(&msg, "HTTP/1.0 200 OK\r\n\r\n");
			stream_int_retnclose(&s->si[0], &msg); /* forge a 200 response */
			s->req->analysers = 0;
			t->expire = s->rep->wex;
		}
		else if (p->mode == PR_MODE_HEALTH) {  /* health check mode, no client reading */
			struct chunk msg;
			chunk_initstr(&msg, "OK\n");
			stream_int_retnclose(&s->si[0], &msg); /* forge an "OK" response */
			s->req->analysers = 0;
			t->expire = s->rep->wex;
		}
		else {
			EV_FD_SET(cfd, DIR_RD);
		}

		/* it is important not to call the wakeup function directly but to
		 * pass through task_wakeup(), because this one knows how to apply
		 * priorities to tasks.
		 */
		task_wakeup(t, TASK_WOKEN_INIT);

		l->nbconn++; /* warning! right now, it's up to the handler to decrease this */
		if (l->nbconn >= l->maxconn) {
			EV_FD_CLR(l->fd, DIR_RD);
			l->state = LI_FULL;
		}

		p->feconn++;  /* beconn will be increased later */
		if (p->feconn > p->counters.feconn_max)
			p->counters.feconn_max = p->feconn;

		if (l->counters) {
			if (l->nbconn > l->counters->conn_max)
				l->counters->conn_max = l->nbconn;
		}

		actconn++;

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
	task_free(t);
 out_free_session:
	LIST_DEL(&s->list);
	pool_free2(pool2_session, s);
 out_close:
	close(cfd);
	return 0;
}

/* set test->i to the id of the frontend */
static int
acl_fetch_fe_id(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test) {

	test->flags = ACL_TEST_F_READ_ONLY;

	test->i = l4->fe->uuid;

	return 1;
}

/* set test->i to the number of connections per second reaching the frontend */
static int
acl_fetch_fe_sess_rate(struct proxy *px, struct session *l4, void *l7, int dir,
                       struct acl_expr *expr, struct acl_test *test)
{
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_FE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	test->i = read_freq_ctr(&px->fe_sess_per_sec);
	return 1;
}

/* set test->i to the number of concurrent connections on the frontend */
static int
acl_fetch_fe_conn(struct proxy *px, struct session *l4, void *l7, int dir,
		  struct acl_expr *expr, struct acl_test *test)
{
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_FE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	test->i = px->feconn;
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
	{ "fe_id",        acl_parse_int, acl_fetch_fe_id,        acl_match_int, ACL_USE_NOTHING },
	{ "fe_sess_rate", acl_parse_int, acl_fetch_fe_sess_rate, acl_match_int, ACL_USE_NOTHING },
	{ "fe_conn",      acl_parse_int, acl_fetch_fe_conn,      acl_match_int, ACL_USE_NOTHING },
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
