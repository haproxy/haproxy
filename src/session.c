/*
 * Session management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/checks.h>
#include <proto/dumpstats.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/hdr_idx.h>
#include <proto/log.h>
#include <proto/session.h>
#include <proto/pipe.h>
#include <proto/protocols.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/sample.h>
#include <proto/stick_table.h>
#include <proto/stream_interface.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

struct pool_head *pool2_session;
struct list sessions;

/* This function is called from the protocol layer accept() in order to instanciate
 * a new session on behalf of a given listener and frontend. It returns a positive
 * value upon success, 0 if the connection can be ignored, or a negative value upon
 * critical failure. The accepted file descriptor is closed if we return <= 0.
 */
int session_accept(struct listener *l, int cfd, struct sockaddr_storage *addr)
{
	struct proxy *p = l->frontend;
	struct session *s;
	struct http_txn *txn;
	struct task *t;
	int ret;


	ret = -1; /* assume unrecoverable error by default */

	if (unlikely((s = pool_alloc2(pool2_session)) == NULL))
		goto out_close;

	/* minimum session initialization required for monitor mode below */
	s->flags = 0;
	s->logs.logwait = p->to_log;
	s->stkctr1_entry = NULL;
	s->stkctr2_entry = NULL;
	s->stkctr1_table = NULL;
	s->stkctr2_table = NULL;

	/* if this session comes from a known monitoring system, we want to ignore
	 * it as soon as possible, which means closing it immediately for TCP, but
	 * cleanly.
	 */
	if (unlikely((l->options & LI_O_CHK_MONNET) &&
		     addr->ss_family == AF_INET &&
		     (((struct sockaddr_in *)addr)->sin_addr.s_addr & p->mon_mask.s_addr) == p->mon_net.s_addr)) {
		if (p->mode == PR_MODE_TCP) {
			ret = 0; /* successful termination */
			goto out_free_session;
		}
		s->flags |= SN_MONITOR;
		s->logs.logwait = 0;
	}

	if (unlikely((t = task_new()) == NULL))
		goto out_free_session;

	/* OK, we're keeping the session, so let's properly initialize the session */
	LIST_ADDQ(&sessions, &s->list);
	LIST_INIT(&s->back_refs);

	s->term_trace = 0;
	s->si[0].addr.from = *addr;
	s->logs.accept_date = date; /* user-visible date for logging */
	s->logs.tv_accept = now;  /* corrected date for internal use */
	s->uniq_id = totalconn;
	p->feconn++;  /* beconn will be increased once assigned */

	proxy_inc_fe_conn_ctr(l, p);	/* note: cum_beconn will be increased once assigned */

	t->process = l->handler;
	t->context = s;
	t->nice = l->nice;
	t->expire = TICK_ETERNITY;

	s->task = t;
	s->listener = l;

	/* Note: initially, the session's backend points to the frontend.
	 * This changes later when switching rules are executed or
	 * when the default backend is assigned.
	 */
	s->be  = s->fe  = p;
	s->req = s->rep = NULL; /* will be allocated later */

	/* now evaluate the tcp-request layer4 rules. Since we expect to be able
	 * to abort right here as soon as possible, we check the rules before
	 * even initializing the stream interfaces.
	 */
	if ((l->options & LI_O_TCP_RULES) && !tcp_exec_req_rules(s)) {
		/* let's do a no-linger now to close with a single RST. */
		setsockopt(cfd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
		ret = 0; /* successful termination */
		goto out_free_task;
	}

	/* This session was accepted, count it now */
	if (p->feconn > p->fe_counters.conn_max)
		p->fe_counters.conn_max = p->feconn;

	proxy_inc_fe_sess_ctr(l, p);
	if (s->stkctr1_entry) {
		void *ptr;

		ptr = stktable_data_ptr(s->stkctr1_table, s->stkctr1_entry, STKTABLE_DT_SESS_CNT);
		if (ptr)
			stktable_data_cast(ptr, sess_cnt)++;

		ptr = stktable_data_ptr(s->stkctr1_table, s->stkctr1_entry, STKTABLE_DT_SESS_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       s->stkctr1_table->data_arg[STKTABLE_DT_SESS_RATE].u, 1);
	}

	if (s->stkctr2_entry) {
		void *ptr;

		ptr = stktable_data_ptr(s->stkctr2_table, s->stkctr2_entry, STKTABLE_DT_SESS_CNT);
		if (ptr)
			stktable_data_cast(ptr, sess_cnt)++;

		ptr = stktable_data_ptr(s->stkctr2_table, s->stkctr2_entry, STKTABLE_DT_SESS_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       s->stkctr2_table->data_arg[STKTABLE_DT_SESS_RATE].u, 1);
	}

	/* this part should be common with other protocols */
	s->si[0].fd        = cfd;
	s->si[0].owner     = t;
	s->si[0].state     = s->si[0].prev_state = SI_ST_EST;
	s->si[0].err_type  = SI_ET_NONE;
	s->si[0].err_loc   = NULL;
	s->si[0].proto     = l->proto;
	s->si[0].release   = NULL;
	s->si[0].send_proxy_ofs = 0;
	clear_target(&s->si[0].target);
	s->si[0].exp       = TICK_ETERNITY;
	s->si[0].flags     = SI_FL_NONE;

	if (likely(s->fe->options2 & PR_O2_INDEPSTR))
		s->si[0].flags |= SI_FL_INDEP_STR;

	if (addr->ss_family == AF_INET || addr->ss_family == AF_INET6)
		s->si[0].flags = SI_FL_CAP_SPLTCP; /* TCP/TCPv6 splicing possible */

	/* add the various callbacks */
	stream_interface_prepare(&s->si[0], &stream_sock);

	/* pre-initialize the other side's stream interface to an INIT state. The
	 * callbacks will be initialized before attempting to connect.
	 */
	s->si[1].fd        = -1; /* just to help with debugging */
	s->si[1].owner     = t;
	s->si[1].state     = s->si[1].prev_state = SI_ST_INI;
	s->si[1].err_type  = SI_ET_NONE;
	s->si[1].conn_retries = 0;  /* used for logging too */
	s->si[1].err_loc   = NULL;
	s->si[1].proto     = NULL;
	s->si[1].release   = NULL;
	s->si[1].send_proxy_ofs = 0;
	clear_target(&s->si[1].target);
	s->si[1].sock.shutr= stream_int_shutr;
	s->si[1].sock.shutw= stream_int_shutw;
	s->si[1].exp       = TICK_ETERNITY;
	s->si[1].flags     = SI_FL_NONE;

	if (likely(s->fe->options2 & PR_O2_INDEPSTR))
		s->si[1].flags |= SI_FL_INDEP_STR;

	session_init_srv_conn(s);
	clear_target(&s->target);
	s->pend_pos = NULL;

	/* init store persistence */
	s->store_count = 0;

	/* Adjust some socket options */
	if (unlikely(fcntl(cfd, F_SETFL, O_NONBLOCK) == -1))
		goto out_free_task;

	if (unlikely((s->req = pool_alloc2(pool2_buffer)) == NULL))
		goto out_free_task; /* no memory */

	if (unlikely((s->rep = pool_alloc2(pool2_buffer)) == NULL))
		goto out_free_req; /* no memory */

	/* initialize the request buffer */
	s->req->size = global.tune.bufsize;
	buffer_init(s->req);
	s->req->prod = &s->si[0];
	s->req->cons = &s->si[1];
	s->si[0].ib = s->si[1].ob = s->req;
	s->req->flags |= BF_READ_ATTACHED; /* the producer is already connected */

	/* activate default analysers enabled for this listener */
	s->req->analysers = l->analysers;

	s->req->wto = TICK_ETERNITY;
	s->req->rto = TICK_ETERNITY;
	s->req->rex = TICK_ETERNITY;
	s->req->wex = TICK_ETERNITY;
	s->req->analyse_exp = TICK_ETERNITY;

	/* initialize response buffer */
	s->rep->size = global.tune.bufsize;
	buffer_init(s->rep);
	s->rep->prod = &s->si[1];
	s->rep->cons = &s->si[0];
	s->si[0].ob = s->si[1].ib = s->rep;
	s->rep->analysers = 0;

	if (s->fe->options2 & PR_O2_NODELAY) {
		s->req->flags |= BF_NEVER_WAIT;
		s->rep->flags |= BF_NEVER_WAIT;
	}

	s->rep->rto = TICK_ETERNITY;
	s->rep->wto = TICK_ETERNITY;
	s->rep->rex = TICK_ETERNITY;
	s->rep->wex = TICK_ETERNITY;
	s->rep->analyse_exp = TICK_ETERNITY;

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
	txn->req.flags = 0;
	txn->rsp.flags = 0;
	/* the HTTP messages need to know what buffer they're associated with */
	txn->req.buf = s->req;
	txn->rsp.buf = s->rep;

	/* finish initialization of the accepted file descriptor */
	fd_insert(cfd);
	fdtab[cfd].owner = &s->si[0];
	fdtab[cfd].state = FD_STREADY;
	fdtab[cfd].flags = 0;
	fdtab[cfd].cb[DIR_RD].f = s->si[0].sock.read;
	fdtab[cfd].cb[DIR_RD].b = s->req;
	fdtab[cfd].cb[DIR_WR].f = s->si[0].sock.write;
	fdtab[cfd].cb[DIR_WR].b = s->rep;
	fdinfo[cfd].peeraddr = (struct sockaddr *)&s->si[0].addr.from;
	fdinfo[cfd].peerlen  = sizeof(s->si[0].addr.from);
	EV_FD_SET(cfd, DIR_RD);

	if (p->accept && (ret = p->accept(s)) <= 0) {
		/* Either we had an unrecoverable error (<0) or work is
		 * finished (=0, eg: monitoring), in both situations,
		 * we can release everything and close.
		 */
		goto out_free_rep;
	}

	/* it is important not to call the wakeup function directly but to
	 * pass through task_wakeup(), because this one knows how to apply
	 * priorities to tasks.
	 */
	task_wakeup(t, TASK_WOKEN_INIT);
	return 1;

	/* Error unrolling */
 out_free_rep:
	pool_free2(pool2_buffer, s->rep);
 out_free_req:
	pool_free2(pool2_buffer, s->req);
 out_free_task:
	p->feconn--;
	if (s->stkctr1_entry || s->stkctr2_entry)
		session_store_counters(s);
	task_free(t);
	LIST_DEL(&s->list);
 out_free_session:
	pool_free2(pool2_session, s);
 out_close:
	if (ret < 0 && s->fe->mode == PR_MODE_HTTP) {
		/* critical error, no more memory, try to emit a 500 response */
		struct chunk *err_msg = error_message(s, HTTP_ERR_500);
		send(cfd, err_msg->str, err_msg->len, MSG_DONTWAIT|MSG_NOSIGNAL);
	}

	if (fdtab[cfd].state != FD_STCLOSE)
		fd_delete(cfd);
	else
		close(cfd);
	return ret;
}

/*
 * frees  the context associated to a session. It must have been removed first.
 */
static void session_free(struct session *s)
{
	struct http_txn *txn = &s->txn;
	struct proxy *fe = s->fe;
	struct bref *bref, *back;
	int i;

	if (s->pend_pos)
		pendconn_free(s->pend_pos);

	if (target_srv(&s->target)) { /* there may be requests left pending in queue */
		if (s->flags & SN_CURR_SESS) {
			s->flags &= ~SN_CURR_SESS;
			target_srv(&s->target)->cur_sess--;
		}
		if (may_dequeue_tasks(target_srv(&s->target), s->be))
			process_srv_queue(target_srv(&s->target));
	}

	if (unlikely(s->srv_conn)) {
		/* the session still has a reserved slot on a server, but
		 * it should normally be only the same as the one above,
		 * so this should not happen in fact.
		 */
		sess_change_server(s, NULL);
	}

	if (s->req->pipe)
		put_pipe(s->req->pipe);

	if (s->rep->pipe)
		put_pipe(s->rep->pipe);

	pool_free2(pool2_buffer, s->req);
	pool_free2(pool2_buffer, s->rep);

	http_end_txn(s);

	for (i = 0; i < s->store_count; i++) {
		if (!s->store[i].ts)
			continue;
		stksess_free(s->store[i].table, s->store[i].ts);
		s->store[i].ts = NULL;
	}

	pool_free2(pool2_hdr_idx, txn->hdr_idx.v);
	if (fe) {
		pool_free2(fe->rsp_cap_pool, txn->rsp.cap);
		pool_free2(fe->req_cap_pool, txn->req.cap);
	}

	if (s->stkctr1_entry || s->stkctr2_entry)
		session_store_counters(s);

	list_for_each_entry_safe(bref, back, &s->back_refs, users) {
		/* we have to unlink all watchers. We must not relink them if
		 * this session was the last one in the list.
		 */
		LIST_DEL(&bref->users);
		LIST_INIT(&bref->users);
		if (s->list.n != &sessions)
			LIST_ADDQ(&LIST_ELEM(s->list.n, struct session *, list)->back_refs, &bref->users);
		bref->ref = s->list.n;
	}
	LIST_DEL(&s->list);
	pool_free2(pool2_session, s);

	/* We may want to free the maximum amount of pools if the proxy is stopping */
	if (fe && unlikely(fe->state == PR_STSTOPPED)) {
		pool_flush2(pool2_buffer);
		pool_flush2(pool2_hdr_idx);
		pool_flush2(pool2_requri);
		pool_flush2(pool2_capture);
		pool_flush2(pool2_session);
		pool_flush2(fe->req_cap_pool);
		pool_flush2(fe->rsp_cap_pool);
	}
}


/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_session()
{
	LIST_INIT(&sessions);
	pool2_session = create_pool("session", sizeof(struct session), MEM_F_SHARED);
	return pool2_session != NULL;
}

void session_process_counters(struct session *s)
{
	unsigned long long bytes;

	if (s->req) {
		bytes = s->req->total - s->logs.bytes_in;
		s->logs.bytes_in = s->req->total;
		if (bytes) {
			s->fe->fe_counters.bytes_in			+= bytes;

			s->be->be_counters.bytes_in			+= bytes;

			if (target_srv(&s->target))
				target_srv(&s->target)->counters.bytes_in		+= bytes;

			if (s->listener->counters)
				s->listener->counters->bytes_in		+= bytes;

			if (s->stkctr2_entry) {
				void *ptr;

				ptr = stktable_data_ptr(s->stkctr2_table,
							s->stkctr2_entry,
							STKTABLE_DT_BYTES_IN_CNT);
				if (ptr)
					stktable_data_cast(ptr, bytes_in_cnt) += bytes;

				ptr = stktable_data_ptr(s->stkctr2_table,
							s->stkctr2_entry,
							STKTABLE_DT_BYTES_IN_RATE);
				if (ptr)
					update_freq_ctr_period(&stktable_data_cast(ptr, bytes_in_rate),
							       s->stkctr2_table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u, bytes);
			}

			if (s->stkctr1_entry) {
				void *ptr;

				ptr = stktable_data_ptr(s->stkctr1_table,
							s->stkctr1_entry,
							STKTABLE_DT_BYTES_IN_CNT);
				if (ptr)
					stktable_data_cast(ptr, bytes_in_cnt) += bytes;

				ptr = stktable_data_ptr(s->stkctr1_table,
							s->stkctr1_entry,
							STKTABLE_DT_BYTES_IN_RATE);
				if (ptr)
					update_freq_ctr_period(&stktable_data_cast(ptr, bytes_in_rate),
							       s->stkctr1_table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u, bytes);
			}
		}
	}

	if (s->rep) {
		bytes = s->rep->total - s->logs.bytes_out;
		s->logs.bytes_out = s->rep->total;
		if (bytes) {
			s->fe->fe_counters.bytes_out			+= bytes;

			s->be->be_counters.bytes_out			+= bytes;

			if (target_srv(&s->target))
				target_srv(&s->target)->counters.bytes_out		+= bytes;

			if (s->listener->counters)
				s->listener->counters->bytes_out	+= bytes;

			if (s->stkctr2_entry) {
				void *ptr;

				ptr = stktable_data_ptr(s->stkctr2_table,
							s->stkctr2_entry,
							STKTABLE_DT_BYTES_OUT_CNT);
				if (ptr)
					stktable_data_cast(ptr, bytes_out_cnt) += bytes;

				ptr = stktable_data_ptr(s->stkctr2_table,
							s->stkctr2_entry,
							STKTABLE_DT_BYTES_OUT_RATE);
				if (ptr)
					update_freq_ctr_period(&stktable_data_cast(ptr, bytes_out_rate),
							       s->stkctr2_table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u, bytes);
			}

			if (s->stkctr1_entry) {
				void *ptr;

				ptr = stktable_data_ptr(s->stkctr1_table,
							s->stkctr1_entry,
							STKTABLE_DT_BYTES_OUT_CNT);
				if (ptr)
					stktable_data_cast(ptr, bytes_out_cnt) += bytes;

				ptr = stktable_data_ptr(s->stkctr1_table,
							s->stkctr1_entry,
							STKTABLE_DT_BYTES_OUT_RATE);
				if (ptr)
					update_freq_ctr_period(&stktable_data_cast(ptr, bytes_out_rate),
							       s->stkctr1_table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u, bytes);
			}
		}
	}
}

/* This function is called with (si->state == SI_ST_CON) meaning that a
 * connection was attempted and that the file descriptor is already allocated.
 * We must check for establishment, error and abort. Possible output states
 * are SI_ST_EST (established), SI_ST_CER (error), SI_ST_DIS (abort), and
 * SI_ST_CON (no change). The function returns 0 if it switches to SI_ST_CER,
 * otherwise 1.
 */
static int sess_update_st_con_tcp(struct session *s, struct stream_interface *si)
{
	struct buffer *req = si->ob;
	struct buffer *rep = si->ib;

	/* If we got an error, or if nothing happened and the connection timed
	 * out, we must give up. The CER state handler will take care of retry
	 * attempts and error reports.
	 */
	if (unlikely(si->flags & (SI_FL_EXP|SI_FL_ERR))) {
		si->exp   = TICK_ETERNITY;
		si->state = SI_ST_CER;
		si->flags &= ~SI_FL_CAP_SPLICE;
		fd_delete(si->fd);

		if (si->release)
			si->release(si);

		if (si->err_type)
			return 0;

		si->err_loc = target_srv(&s->target);
		if (si->flags & SI_FL_ERR)
			si->err_type = SI_ET_CONN_ERR;
		else
			si->err_type = SI_ET_CONN_TO;
		return 0;
	}

	/* OK, maybe we want to abort */
	if (unlikely((rep->flags & BF_SHUTW) ||
		     ((req->flags & BF_SHUTW_NOW) && /* FIXME: this should not prevent a connection from establishing */
		      (((req->flags & (BF_OUT_EMPTY|BF_WRITE_ACTIVITY)) == BF_OUT_EMPTY) ||
		       s->be->options & PR_O_ABRT_CLOSE)))) {
		/* give up */
		si->sock.shutw(si);
		si->err_type |= SI_ET_CONN_ABRT;
		si->err_loc  = target_srv(&s->target);
		si->flags &= ~SI_FL_CAP_SPLICE;
		if (s->srv_error)
			s->srv_error(s, si);
		return 1;
	}

	/* we need to wait a bit more if there was no activity either */
	if (!(req->flags & BF_WRITE_ACTIVITY))
		return 1;

	/* OK, this means that a connection succeeded. The caller will be
	 * responsible for handling the transition from CON to EST.
	 */
	s->logs.t_connect = tv_ms_elapsed(&s->logs.tv_accept, &now);
	si->exp      = TICK_ETERNITY;
	si->state    = SI_ST_EST;
	si->err_type = SI_ET_NONE;
	si->err_loc  = NULL;
	return 1;
}

/* This function is called with (si->state == SI_ST_CER) meaning that a
 * previous connection attempt has failed and that the file descriptor
 * has already been released. Possible causes include asynchronous error
 * notification and time out. Possible output states are SI_ST_CLO when
 * retries are exhausted, SI_ST_TAR when a delay is wanted before a new
 * connection attempt, SI_ST_ASS when it's wise to retry on the same server,
 * and SI_ST_REQ when an immediate redispatch is wanted. The buffers are
 * marked as in error state. It returns 0.
 */
static int sess_update_st_cer(struct session *s, struct stream_interface *si)
{
	/* we probably have to release last session from the server */
	if (target_srv(&s->target)) {
		health_adjust(target_srv(&s->target), HANA_STATUS_L4_ERR);

		if (s->flags & SN_CURR_SESS) {
			s->flags &= ~SN_CURR_SESS;
			target_srv(&s->target)->cur_sess--;
		}
	}

	/* ensure that we have enough retries left */
	si->conn_retries--;
	if (si->conn_retries < 0) {
		if (!si->err_type) {
			si->err_type = SI_ET_CONN_ERR;
			si->err_loc = target_srv(&s->target);
		}

		if (target_srv(&s->target))
			target_srv(&s->target)->counters.failed_conns++;
		s->be->be_counters.failed_conns++;
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(target_srv(&s->target), s->be))
			process_srv_queue(target_srv(&s->target));

		/* shutw is enough so stop a connecting socket */
		si->sock.shutw(si);
		si->ob->flags |= BF_WRITE_ERROR;
		si->ib->flags |= BF_READ_ERROR;

		si->state = SI_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, si);
		return 0;
	}

	/* If the "redispatch" option is set on the backend, we are allowed to
	 * retry on another server for the last retry. In order to achieve this,
	 * we must mark the session unassigned, and eventually clear the DIRECT
	 * bit to ignore any persistence cookie. We won't count a retry nor a
	 * redispatch yet, because this will depend on what server is selected.
	 */
	if (target_srv(&s->target) && si->conn_retries == 0 &&
	    s->be->options & PR_O_REDISP && !(s->flags & SN_FORCE_PRST)) {
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(target_srv(&s->target), s->be))
			process_srv_queue(target_srv(&s->target));

		s->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
		si->state = SI_ST_REQ;
	} else {
		if (target_srv(&s->target))
			target_srv(&s->target)->counters.retries++;
		s->be->be_counters.retries++;
		si->state = SI_ST_ASS;
	}

	if (si->flags & SI_FL_ERR) {
		/* The error was an asynchronous connection error, and we will
		 * likely have to retry connecting to the same server, most
		 * likely leading to the same result. To avoid this, we wait
		 * one second before retrying.
		 */

		if (!si->err_type)
			si->err_type = SI_ET_CONN_ERR;

		si->state = SI_ST_TAR;
		si->exp = tick_add(now_ms, MS_TO_TICKS(1000));
		return 0;
	}
	return 0;
}

/*
 * This function handles the transition between the SI_ST_CON state and the
 * SI_ST_EST state. It must only be called after switching from SI_ST_CON (or
 * SI_ST_INI) to SI_ST_EST, but only when a ->proto is defined.
 */
static void sess_establish(struct session *s, struct stream_interface *si)
{
	struct buffer *req = si->ob;
	struct buffer *rep = si->ib;

	if (target_srv(&s->target))
		health_adjust(target_srv(&s->target), HANA_STATUS_L4_OK);

	if (s->be->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
		/* if the user wants to log as soon as possible, without counting
		 * bytes from the server, then this is the right moment. */
		if (s->fe->to_log && !(s->logs.logwait & LW_BYTES)) {
			s->logs.t_close = s->logs.t_connect; /* to get a valid end date */
			s->do_log(s);
		}
	}
	else {
		s->txn.rsp.msg_state = HTTP_MSG_RPBEFORE;
		/* reset hdr_idx which was already initialized by the request.
		 * right now, the http parser does it.
		 * hdr_idx_init(&s->txn.hdr_idx);
		 */
	}

	rep->analysers |= s->fe->fe_rsp_ana | s->be->be_rsp_ana;
	rep->flags |= BF_READ_ATTACHED; /* producer is now attached */
	if (si->proto) {
		/* real connections have timeouts */
		req->wto = s->be->timeout.server;
		rep->rto = s->be->timeout.server;
	}
	req->wex = TICK_ETERNITY;
}

/* Update stream interface status for input states SI_ST_ASS, SI_ST_QUE, SI_ST_TAR.
 * Other input states are simply ignored.
 * Possible output states are SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ, SI_ST_CON.
 * Flags must have previously been updated for timeouts and other conditions.
 */
static void sess_update_stream_int(struct session *s, struct stream_interface *si)
{
	struct server *srv = target_srv(&s->target);

	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->i, s->req->o, s->rep->i, s->rep->o, s->rep->cons->state, s->req->cons->state);

	if (si->state == SI_ST_ASS) {
		/* Server assigned to connection request, we have to try to connect now */
		int conn_err;

		conn_err = connect_server(s);
		srv = target_srv(&s->target);

		if (conn_err == SN_ERR_NONE) {
			/* state = SI_ST_CON now */
			if (srv)
				srv_inc_sess_ctr(srv);
			return;
		}

		/* We have received a synchronous error. We might have to
		 * abort, retry immediately or redispatch.
		 */
		if (conn_err == SN_ERR_INTERNAL) {
			if (!si->err_type) {
				si->err_type = SI_ET_CONN_OTHER;
				si->err_loc  = srv;
			}

			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv->counters.failed_conns++;
			s->be->be_counters.failed_conns++;

			/* release other sessions waiting for this server */
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(srv, s->be))
				process_srv_queue(srv);

			/* Failed and not retryable. */
			si->sock.shutr(si);
			si->sock.shutw(si);
			si->ob->flags |= BF_WRITE_ERROR;

			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

			/* no session was ever accounted for this server */
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		/* We are facing a retryable error, but we don't want to run a
		 * turn-around now, as the problem is likely a source port
		 * allocation problem, so we want to retry now.
		 */
		si->state = SI_ST_CER;
		si->flags &= ~SI_FL_ERR;
		sess_update_st_cer(s, si);
		/* now si->state is one of SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ */
		return;
	}
	else if (si->state == SI_ST_QUE) {
		/* connection request was queued, check for any update */
		if (!s->pend_pos) {
			/* The connection is not in the queue anymore. Either
			 * we have a server connection slot available and we
			 * go directly to the assigned state, or we need to
			 * load-balance first and go to the INI state.
			 */
			si->exp = TICK_ETERNITY;
			if (unlikely(!(s->flags & SN_ASSIGNED)))
				si->state = SI_ST_REQ;
			else {
				s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
				si->state = SI_ST_ASS;
			}
			return;
		}

		/* Connection request still in queue... */
		if (si->flags & SI_FL_EXP) {
			/* ... and timeout expired */
			si->exp = TICK_ETERNITY;
			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
			if (srv)
				srv->counters.failed_conns++;
			s->be->be_counters.failed_conns++;
			si->sock.shutr(si);
			si->sock.shutw(si);
			si->ob->flags |= BF_WRITE_TIMEOUT;
			if (!si->err_type)
				si->err_type = SI_ET_QUEUE_TO;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		/* Connection remains in queue, check if we have to abort it */
		if ((si->ob->flags & (BF_READ_ERROR)) ||
		    ((si->ob->flags & BF_SHUTW_NOW) &&   /* empty and client aborted */
		     (si->ob->flags & BF_OUT_EMPTY || s->be->options & PR_O_ABRT_CLOSE))) {
			/* give up */
			si->exp = TICK_ETERNITY;
			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
			si->sock.shutr(si);
			si->sock.shutw(si);
			si->err_type |= SI_ET_QUEUE_ABRT;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		/* Nothing changed */
		return;
	}
	else if (si->state == SI_ST_TAR) {
		/* Connection request might be aborted */
		if ((si->ob->flags & (BF_READ_ERROR)) ||
		    ((si->ob->flags & BF_SHUTW_NOW) &&  /* empty and client aborted */
		     (si->ob->flags & BF_OUT_EMPTY || s->be->options & PR_O_ABRT_CLOSE))) {
			/* give up */
			si->exp = TICK_ETERNITY;
			si->sock.shutr(si);
			si->sock.shutw(si);
			si->err_type |= SI_ET_CONN_ABRT;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		if (!(si->flags & SI_FL_EXP))
			return;  /* still in turn-around */

		si->exp = TICK_ETERNITY;

		/* we keep trying on the same server as long as the session is
		 * marked "assigned".
		 * FIXME: Should we force a redispatch attempt when the server is down ?
		 */
		if (s->flags & SN_ASSIGNED)
			si->state = SI_ST_ASS;
		else
			si->state = SI_ST_REQ;
		return;
	}
}

/* Set correct session termination flags in case no analyser has done it. It
 * also counts a failed request if the server state has not reached the request
 * stage.
 */
static void sess_set_term_flags(struct session *s)
{
	if (!(s->flags & SN_FINST_MASK)) {
		if (s->si[1].state < SI_ST_REQ) {

			s->fe->fe_counters.failed_req++;
			if (s->listener->counters)
				s->listener->counters->failed_req++;

			s->flags |= SN_FINST_R;
		}
		else if (s->si[1].state == SI_ST_QUE)
			s->flags |= SN_FINST_Q;
		else if (s->si[1].state < SI_ST_EST)
			s->flags |= SN_FINST_C;
		else if (s->si[1].state == SI_ST_EST || s->si[1].prev_state == SI_ST_EST)
			s->flags |= SN_FINST_D;
		else
			s->flags |= SN_FINST_L;
	}
}

/* This function initiates a server connection request on a stream interface
 * already in SI_ST_REQ state. Upon success, the state goes to SI_ST_ASS,
 * indicating that a server has been assigned. It may also return SI_ST_QUE,
 * or SI_ST_CLO upon error.
 */
static void sess_prepare_conn_req(struct session *s, struct stream_interface *si)
{
	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->i, s->req->o, s->rep->i, s->rep->o, s->rep->cons->state, s->req->cons->state);

	if (si->state != SI_ST_REQ)
		return;

	/* Try to assign a server */
	if (srv_redispatch_connect(s) != 0) {
		/* We did not get a server. Either we queued the
		 * connection request, or we encountered an error.
		 */
		if (si->state == SI_ST_QUE)
			return;

		/* we did not get any server, let's check the cause */
		si->sock.shutr(si);
		si->sock.shutw(si);
		si->ob->flags |= BF_WRITE_ERROR;
		if (!si->err_type)
			si->err_type = SI_ET_CONN_OTHER;
		si->state = SI_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, si);
		return;
	}

	/* The server is assigned */
	s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
	si->state = SI_ST_ASS;
}

/* This stream analyser checks the switching rules and changes the backend
 * if appropriate. The default_backend rule is also considered, then the
 * target backend's forced persistence rules are also evaluated last if any.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * either needs more data or wants to immediately abort the request.
 */
static int process_switching_rules(struct session *s, struct buffer *req, int an_bit)
{
	struct persist_rule *prst_rule;

	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->i,
		req->analysers);

	/* now check whether we have some switching rules for this request */
	if (!(s->flags & SN_BE_ASSIGNED)) {
		struct switching_rule *rule;

		list_for_each_entry(rule, &s->fe->switching_rules, list) {
			int ret;

			ret = acl_exec_cond(rule->cond, s->fe, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				if (!session_set_backend(s, rule->be.backend))
					goto sw_failed;
				break;
			}
		}

		/* To ensure correct connection accounting on the backend, we
		 * have to assign one if it was not set (eg: a listen). This
		 * measure also takes care of correctly setting the default
		 * backend if any.
		 */
		if (!(s->flags & SN_BE_ASSIGNED))
			if (!session_set_backend(s, s->fe->defbe.be ? s->fe->defbe.be : s->be))
				goto sw_failed;
	}

	/* we don't want to run the TCP or HTTP filters again if the backend has not changed */
	if (s->fe == s->be) {
		s->req->analysers &= ~AN_REQ_INSPECT_BE;
		s->req->analysers &= ~AN_REQ_HTTP_PROCESS_BE;
	}

	/* as soon as we know the backend, we must check if we have a matching forced or ignored
	 * persistence rule, and report that in the session.
	 */
	list_for_each_entry(prst_rule, &s->be->persist_rules, list) {
		int ret = 1;

		if (prst_rule->cond) {
	                ret = acl_exec_cond(prst_rule->cond, s->be, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (prst_rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* no rule, or the rule matches */
			if (prst_rule->type == PERSIST_TYPE_FORCE) {
				s->flags |= SN_FORCE_PRST;
			} else {
				s->flags |= SN_IGNORE_PRST;
			}
			break;
		}
	}

	return 1;

 sw_failed:
	/* immediately abort this request in case of allocation failure */
	buffer_abort(s->req);
	buffer_abort(s->rep);

	if (!(s->flags & SN_ERR_MASK))
		s->flags |= SN_ERR_RESOURCE;
	if (!(s->flags & SN_FINST_MASK))
		s->flags |= SN_FINST_R;

	s->txn.status = 500;
	s->req->analysers = 0;
	s->req->analyse_exp = TICK_ETERNITY;
	return 0;
}

/* This stream analyser works on a request. It applies all use-server rules on
 * it then returns 1. The data must already be present in the buffer otherwise
 * they won't match. It always returns 1.
 */
static int process_server_rules(struct session *s, struct buffer *req, int an_bit)
{
	struct proxy *px = s->be;
	struct server_rule *rule;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bl=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->i + req->o,
		req->analysers);

	if (!(s->flags & SN_ASSIGNED)) {
		list_for_each_entry(rule, &px->server_rules, list) {
			int ret;

			ret = acl_exec_cond(rule->cond, s->be, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				struct server *srv = rule->srv.ptr;

				if ((srv->state & SRV_RUNNING) ||
				    (px->options & PR_O_PERSIST) ||
				    (s->flags & SN_FORCE_PRST)) {
					s->flags |= SN_DIRECT | SN_ASSIGNED;
					set_target_server(&s->target, srv);
					break;
				}
				/* if the server is not UP, let's go on with next rules
				 * just in case another one is suited.
				 */
			}
		}
	}

	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This stream analyser works on a request. It applies all sticking rules on
 * it then returns 1. The data must already be present in the buffer otherwise
 * they won't match. It always returns 1.
 */
static int process_sticking_rules(struct session *s, struct buffer *req, int an_bit)
{
	struct proxy    *px   = s->be;
	struct sticking_rule  *rule;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->i,
		req->analysers);

	list_for_each_entry(rule, &px->sticking_rules, list) {
		int ret = 1 ;
		int i;

		for (i = 0; i < s->store_count; i++) {
			if (rule->table.t == s->store[i].table)
				break;
		}

		if (i !=  s->store_count)
			continue;

		if (rule->cond) {
	                ret = acl_exec_cond(rule->cond, px, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			struct stktable_key *key;

			key = stktable_fetch_key(rule->table.t, px, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->expr);
			if (!key)
				continue;

			if (rule->flags & STK_IS_MATCH) {
				struct stksess *ts;

				if ((ts = stktable_lookup_key(rule->table.t, key)) != NULL) {
					if (!(s->flags & SN_ASSIGNED)) {
						struct eb32_node *node;
						void *ptr;

						/* srv found in table */
						ptr = stktable_data_ptr(rule->table.t, ts, STKTABLE_DT_SERVER_ID);
						node = eb32_lookup(&px->conf.used_server_id, stktable_data_cast(ptr, server_id));
						if (node) {
							struct server *srv;

							srv = container_of(node, struct server, conf.id);
							if ((srv->state & SRV_RUNNING) ||
							    (px->options & PR_O_PERSIST) ||
							    (s->flags & SN_FORCE_PRST)) {
								s->flags |= SN_DIRECT | SN_ASSIGNED;
								set_target_server(&s->target, srv);
							}
						}
					}
					stktable_touch(rule->table.t, ts, 1);
				}
			}
			if (rule->flags & STK_IS_STORE) {
				if (s->store_count < (sizeof(s->store) / sizeof(s->store[0]))) {
					struct stksess *ts;

					ts = stksess_new(rule->table.t, key);
					if (ts) {
						s->store[s->store_count].table = rule->table.t;
						s->store[s->store_count++].ts = ts;
					}
				}
			}
		}
	}

	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This stream analyser works on a response. It applies all store rules on it
 * then returns 1. The data must already be present in the buffer otherwise
 * they won't match. It always returns 1.
 */
static int process_store_rules(struct session *s, struct buffer *rep, int an_bit)
{
	struct proxy    *px   = s->be;
	struct sticking_rule  *rule;
	int i;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		rep->i,
		rep->analysers);

	list_for_each_entry(rule, &px->storersp_rules, list) {
		int ret = 1 ;
		int storereqidx = -1;

		for (i = 0; i < s->store_count; i++) {
			if (rule->table.t == s->store[i].table) {
				if (!(s->store[i].flags))
					storereqidx = i;
				break;
			}
		}

		if ((i !=  s->store_count) && (storereqidx == -1))
			continue;

		if (rule->cond) {
	                ret = acl_exec_cond(rule->cond, px, s, &s->txn, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
	                ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			struct stktable_key *key;

			key = stktable_fetch_key(rule->table.t, px, s, &s->txn, SMP_OPT_DIR_RES|SMP_OPT_FINAL, rule->expr);
			if (!key)
				continue;

			if (storereqidx != -1) {
				stksess_setkey(s->store[storereqidx].table, s->store[storereqidx].ts, key);
				s->store[storereqidx].flags = 1;
			}
			else if (s->store_count < (sizeof(s->store) / sizeof(s->store[0]))) {
				struct stksess *ts;

				ts = stksess_new(rule->table.t, key);
				if (ts) {
					s->store[s->store_count].table = rule->table.t;
					s->store[s->store_count].flags = 1;
					s->store[s->store_count++].ts = ts;
				}
			}
		}
	}

	/* process store request and store response */
	for (i = 0; i < s->store_count; i++) {
		struct stksess *ts;
		void *ptr;

		if (target_srv(&s->target) && target_srv(&s->target)->state & SRV_NON_STICK) {
			stksess_free(s->store[i].table, s->store[i].ts);
			s->store[i].ts = NULL;
			continue;
		}

		ts = stktable_lookup(s->store[i].table, s->store[i].ts);
		if (ts) {
			/* the entry already existed, we can free ours */
			stktable_touch(s->store[i].table, ts, 1);
			stksess_free(s->store[i].table, s->store[i].ts);
		}
		else
			ts = stktable_store(s->store[i].table, s->store[i].ts, 1);

		s->store[i].ts = NULL;
		ptr = stktable_data_ptr(s->store[i].table, ts, STKTABLE_DT_SERVER_ID);
		stktable_data_cast(ptr, server_id) = target_srv(&s->target)->puid;
	}
	s->store_count = 0; /* everything is stored */

	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This macro is very specific to the function below. See the comments in
 * process_session() below to understand the logic and the tests.
 */
#define UPDATE_ANALYSERS(real, list, back, flag) {			\
		list = (((list) & ~(flag)) | ~(back)) & (real);		\
		back = real;						\
		if (!(list))						\
			break;						\
		if (((list) ^ ((list) & ((list) - 1))) < (flag))	\
			continue;					\
}

/* Processes the client, server, request and response jobs of a session task,
 * then puts it back to the wait queue in a clean state, or cleans up its
 * resources if it must be deleted. Returns in <next> the date the task wants
 * to be woken up, or TICK_ETERNITY. In order not to call all functions for
 * nothing too many times, the request and response buffers flags are monitored
 * and each function is called only if at least another function has changed at
 * least one flag it is interested in.
 */
struct task *process_session(struct task *t)
{
	struct server *srv;
	struct session *s = t->context;
	unsigned int rqf_last, rpf_last;
	unsigned int rq_prod_last, rq_cons_last;
	unsigned int rp_cons_last, rp_prod_last;
	unsigned int req_ana_back;

	//DPRINTF(stderr, "%s:%d: cs=%d ss=%d(%d) rqf=0x%08x rpf=0x%08x\n", __FUNCTION__, __LINE__,
	//        s->si[0].state, s->si[1].state, s->si[1].err_type, s->req->flags, s->rep->flags);

	/* this data may be no longer valid, clear it */
	memset(&s->txn.auth, 0, sizeof(s->txn.auth));

	/* This flag must explicitly be set every time */
	s->req->flags &= ~BF_READ_NOEXP;

	/* Keep a copy of req/rep flags so that we can detect shutdowns */
	rqf_last = s->req->flags & ~BF_MASK_ANALYSER;
	rpf_last = s->rep->flags & ~BF_MASK_ANALYSER;

	/* we don't want the stream interface functions to recursively wake us up */
	if (s->req->prod->owner == t)
		s->req->prod->flags |= SI_FL_DONT_WAKE;
	if (s->req->cons->owner == t)
		s->req->cons->flags |= SI_FL_DONT_WAKE;

	/* 1a: Check for low level timeouts if needed. We just set a flag on
	 * stream interfaces when their timeouts have expired.
	 */
	if (unlikely(t->state & TASK_WOKEN_TIMER)) {
		stream_int_check_timeouts(&s->si[0]);
		stream_int_check_timeouts(&s->si[1]);

		/* check buffer timeouts, and close the corresponding stream interfaces
		 * for future reads or writes. Note: this will also concern upper layers
		 * but we do not touch any other flag. We must be careful and correctly
		 * detect state changes when calling them.
		 */

		buffer_check_timeouts(s->req);

		if (unlikely((s->req->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == BF_WRITE_TIMEOUT)) {
			s->req->cons->flags |= SI_FL_NOLINGER;
			s->req->cons->sock.shutw(s->req->cons);
		}

		if (unlikely((s->req->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == BF_READ_TIMEOUT))
			s->req->prod->sock.shutr(s->req->prod);

		buffer_check_timeouts(s->rep);

		if (unlikely((s->rep->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == BF_WRITE_TIMEOUT)) {
			s->rep->cons->flags |= SI_FL_NOLINGER;
			s->rep->cons->sock.shutw(s->rep->cons);
		}

		if (unlikely((s->rep->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == BF_READ_TIMEOUT))
			s->rep->prod->sock.shutr(s->rep->prod);
	}

	/* 1b: check for low-level errors reported at the stream interface.
	 * First we check if it's a retryable error (in which case we don't
	 * want to tell the buffer). Otherwise we report the error one level
	 * upper by setting flags into the buffers. Note that the side towards
	 * the client cannot have connect (hence retryable) errors. Also, the
	 * connection setup code must be able to deal with any type of abort.
	 */
	srv = target_srv(&s->target);
	if (unlikely(s->si[0].flags & SI_FL_ERR)) {
		if (s->si[0].state == SI_ST_EST || s->si[0].state == SI_ST_DIS) {
			s->si[0].sock.shutr(&s->si[0]);
			s->si[0].sock.shutw(&s->si[0]);
			stream_int_report_error(&s->si[0]);
			if (!(s->req->analysers) && !(s->rep->analysers)) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				if (!(s->flags & SN_ERR_MASK))
					s->flags |= SN_ERR_CLICL;
				if (!(s->flags & SN_FINST_MASK))
					s->flags |= SN_FINST_D;
			}
		}
	}

	if (unlikely(s->si[1].flags & SI_FL_ERR)) {
		if (s->si[1].state == SI_ST_EST || s->si[1].state == SI_ST_DIS) {
			s->si[1].sock.shutr(&s->si[1]);
			s->si[1].sock.shutw(&s->si[1]);
			stream_int_report_error(&s->si[1]);
			s->be->be_counters.failed_resp++;
			if (srv)
				srv->counters.failed_resp++;
			if (!(s->req->analysers) && !(s->rep->analysers)) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				if (!(s->flags & SN_ERR_MASK))
					s->flags |= SN_ERR_SRVCL;
				if (!(s->flags & SN_FINST_MASK))
					s->flags |= SN_FINST_D;
			}
		}
		/* note: maybe we should process connection errors here ? */
	}

	if (s->si[1].state == SI_ST_CON) {
		/* we were trying to establish a connection on the server side,
		 * maybe it succeeded, maybe it failed, maybe we timed out, ...
		 */
		if (unlikely(!sess_update_st_con_tcp(s, &s->si[1])))
			sess_update_st_cer(s, &s->si[1]);
		else if (s->si[1].state == SI_ST_EST)
			sess_establish(s, &s->si[1]);

		/* state is now one of SI_ST_CON (still in progress), SI_ST_EST
		 * (established), SI_ST_DIS (abort), SI_ST_CLO (last error),
		 * SI_ST_ASS/SI_ST_TAR/SI_ST_REQ for retryable errors.
		 */
	}

	rq_prod_last = s->si[0].state;
	rq_cons_last = s->si[1].state;
	rp_cons_last = s->si[0].state;
	rp_prod_last = s->si[1].state;

 resync_stream_interface:
	/* Check for connection closure */

	DPRINTF(stderr,
		"[%u] %s:%d: task=%p s=%p, sfl=0x%08x, rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d, cet=0x%x set=0x%x retr=%d\n",
		now_ms, __FUNCTION__, __LINE__,
		t,
		s, s->flags,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->i, s->req->o, s->rep->i, s->rep->o, s->rep->cons->state, s->req->cons->state,
		s->rep->cons->err_type, s->req->cons->err_type,
		s->req->cons->conn_retries);

	/* nothing special to be done on client side */
	if (unlikely(s->req->prod->state == SI_ST_DIS))
		s->req->prod->state = SI_ST_CLO;

	/* When a server-side connection is released, we have to count it and
	 * check for pending connections on this server.
	 */
	if (unlikely(s->req->cons->state == SI_ST_DIS)) {
		s->req->cons->state = SI_ST_CLO;
		srv = target_srv(&s->target);
		if (srv) {
			if (s->flags & SN_CURR_SESS) {
				s->flags &= ~SN_CURR_SESS;
				srv->cur_sess--;
			}
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(srv, s->be))
				process_srv_queue(srv);
		}
	}

	/*
	 * Note: of the transient states (REQ, CER, DIS), only REQ may remain
	 * at this point.
	 */

 resync_request:
	/* Analyse request */
	if (((s->req->flags & ~rqf_last) & BF_MASK_ANALYSER) ||
	    ((s->req->flags ^ rqf_last) & BF_MASK_STATIC) ||
	    s->si[0].state != rq_prod_last ||
	    s->si[1].state != rq_cons_last) {
		unsigned int flags = s->req->flags;

		if (s->req->prod->state >= SI_ST_EST) {
			int max_loops = global.tune.maxpollevents;
			unsigned int ana_list;
			unsigned int ana_back;

			/* it's up to the analysers to stop new connections,
			 * disable reading or closing. Note: if an analyser
			 * disables any of these bits, it is responsible for
			 * enabling them again when it disables itself, so
			 * that other analysers are called in similar conditions.
			 */
			buffer_auto_read(s->req);
			buffer_auto_connect(s->req);
			buffer_auto_close(s->req);

			/* We will call all analysers for which a bit is set in
			 * s->req->analysers, following the bit order from LSB
			 * to MSB. The analysers must remove themselves from
			 * the list when not needed. Any analyser may return 0
			 * to break out of the loop, either because of missing
			 * data to take a decision, or because it decides to
			 * kill the session. We loop at least once through each
			 * analyser, and we may loop again if other analysers
			 * are added in the middle.
			 *
			 * We build a list of analysers to run. We evaluate all
			 * of these analysers in the order of the lower bit to
			 * the higher bit. This ordering is very important.
			 * An analyser will often add/remove other analysers,
			 * including itself. Any changes to itself have no effect
			 * on the loop. If it removes any other analysers, we
			 * want those analysers not to be called anymore during
			 * this loop. If it adds an analyser that is located
			 * after itself, we want it to be scheduled for being
			 * processed during the loop. If it adds an analyser
			 * which is located before it, we want it to switch to
			 * it immediately, even if it has already been called
			 * once but removed since.
			 *
			 * In order to achieve this, we compare the analyser
			 * list after the call with a copy of it before the
			 * call. The work list is fed with analyser bits that
			 * appeared during the call. Then we compare previous
			 * work list with the new one, and check the bits that
			 * appeared. If the lowest of these bits is lower than
			 * the current bit, it means we have enabled a previous
			 * analyser and must immediately loop again.
			 */

			ana_list = ana_back = s->req->analysers;
			while (ana_list && max_loops--) {
				/* Warning! ensure that analysers are always placed in ascending order! */

				if (ana_list & AN_REQ_DECODE_PROXY) {
					if (!frontend_decode_proxy_request(s, s->req, AN_REQ_DECODE_PROXY))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_DECODE_PROXY);
				}

				if (ana_list & AN_REQ_INSPECT_FE) {
					if (!tcp_inspect_request(s, s->req, AN_REQ_INSPECT_FE))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_INSPECT_FE);
				}

				if (ana_list & AN_REQ_WAIT_HTTP) {
					if (!http_wait_for_request(s, s->req, AN_REQ_WAIT_HTTP))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_WAIT_HTTP);
				}

				if (ana_list & AN_REQ_HTTP_PROCESS_FE) {
					if (!http_process_req_common(s, s->req, AN_REQ_HTTP_PROCESS_FE, s->fe))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_PROCESS_FE);
				}

				if (ana_list & AN_REQ_SWITCHING_RULES) {
					if (!process_switching_rules(s, s->req, AN_REQ_SWITCHING_RULES))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_SWITCHING_RULES);
				}

				if (ana_list & AN_REQ_INSPECT_BE) {
					if (!tcp_inspect_request(s, s->req, AN_REQ_INSPECT_BE))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_INSPECT_BE);
				}

				if (ana_list & AN_REQ_HTTP_PROCESS_BE) {
					if (!http_process_req_common(s, s->req, AN_REQ_HTTP_PROCESS_BE, s->be))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_PROCESS_BE);
				}

				if (ana_list & AN_REQ_HTTP_TARPIT) {
					if (!http_process_tarpit(s, s->req, AN_REQ_HTTP_TARPIT))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_TARPIT);
				}

				if (ana_list & AN_REQ_SRV_RULES) {
					if (!process_server_rules(s, s->req, AN_REQ_SRV_RULES))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_SRV_RULES);
				}

				if (ana_list & AN_REQ_HTTP_INNER) {
					if (!http_process_request(s, s->req, AN_REQ_HTTP_INNER))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_INNER);
				}

				if (ana_list & AN_REQ_HTTP_BODY) {
					if (!http_process_request_body(s, s->req, AN_REQ_HTTP_BODY))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_BODY);
				}

				if (ana_list & AN_REQ_PRST_RDP_COOKIE) {
					if (!tcp_persist_rdp_cookie(s, s->req, AN_REQ_PRST_RDP_COOKIE))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_PRST_RDP_COOKIE);
				}

				if (ana_list & AN_REQ_STICKING_RULES) {
					if (!process_sticking_rules(s, s->req, AN_REQ_STICKING_RULES))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_STICKING_RULES);
				}

				if (ana_list & AN_REQ_HTTP_XFER_BODY) {
					if (!http_request_forward_body(s, s->req, AN_REQ_HTTP_XFER_BODY))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_XFER_BODY);
				}
				break;
			}
		}

		rq_prod_last = s->si[0].state;
		rq_cons_last = s->si[1].state;
		s->req->flags &= ~BF_WAKE_ONCE;
		rqf_last = s->req->flags;

		if ((s->req->flags ^ flags) & BF_MASK_STATIC)
			goto resync_request;
	}

	/* we'll monitor the request analysers while parsing the response,
	 * because some response analysers may indirectly enable new request
	 * analysers (eg: HTTP keep-alive).
	 */
	req_ana_back = s->req->analysers;

 resync_response:
	/* Analyse response */

	if (unlikely(s->rep->flags & BF_HIJACK)) {
		/* In inject mode, we wake up everytime something has
		 * happened on the write side of the buffer.
		 */
		unsigned int flags = s->rep->flags;

		if ((s->rep->flags & (BF_WRITE_PARTIAL|BF_WRITE_ERROR|BF_SHUTW)) &&
		    !(s->rep->flags & BF_FULL)) {
			s->rep->hijacker(s, s->rep);
		}

		if ((s->rep->flags ^ flags) & BF_MASK_STATIC) {
			rpf_last = s->rep->flags;
			goto resync_response;
		}
	}
	else if (((s->rep->flags & ~rpf_last) & BF_MASK_ANALYSER) ||
		 (s->rep->flags ^ rpf_last) & BF_MASK_STATIC ||
		 s->si[0].state != rp_cons_last ||
		 s->si[1].state != rp_prod_last) {
		unsigned int flags = s->rep->flags;

		if ((s->rep->flags & BF_MASK_ANALYSER) &&
		    (s->rep->analysers & AN_REQ_WAIT_HTTP)) {
			/* Due to HTTP pipelining, the HTTP request analyser might be waiting
			 * for some free space in the response buffer, so we might need to call
			 * it when something changes in the response buffer, but still we pass
			 * it the request buffer. Note that the SI state might very well still
			 * be zero due to us returning a flow of redirects!
			 */
			s->rep->analysers &= ~AN_REQ_WAIT_HTTP;
			s->req->flags |= BF_WAKE_ONCE;
		}

		if (s->rep->prod->state >= SI_ST_EST) {
			int max_loops = global.tune.maxpollevents;
			unsigned int ana_list;
			unsigned int ana_back;

			/* it's up to the analysers to stop disable reading or
			 * closing. Note: if an analyser disables any of these
			 * bits, it is responsible for enabling them again when
			 * it disables itself, so that other analysers are called
			 * in similar conditions.
			 */
			buffer_auto_read(s->rep);
			buffer_auto_close(s->rep);

			/* We will call all analysers for which a bit is set in
			 * s->rep->analysers, following the bit order from LSB
			 * to MSB. The analysers must remove themselves from
			 * the list when not needed. Any analyser may return 0
			 * to break out of the loop, either because of missing
			 * data to take a decision, or because it decides to
			 * kill the session. We loop at least once through each
			 * analyser, and we may loop again if other analysers
			 * are added in the middle.
			 */

			ana_list = ana_back = s->rep->analysers;
			while (ana_list && max_loops--) {
				/* Warning! ensure that analysers are always placed in ascending order! */

				if (ana_list & AN_RES_INSPECT) {
					if (!tcp_inspect_response(s, s->rep, AN_RES_INSPECT))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_INSPECT);
				}

				if (ana_list & AN_RES_WAIT_HTTP) {
					if (!http_wait_for_response(s, s->rep, AN_RES_WAIT_HTTP))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_WAIT_HTTP);
				}

				if (ana_list & AN_RES_STORE_RULES) {
					if (!process_store_rules(s, s->rep, AN_RES_STORE_RULES))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_STORE_RULES);
				}

				if (ana_list & AN_RES_HTTP_PROCESS_BE) {
					if (!http_process_res_common(s, s->rep, AN_RES_HTTP_PROCESS_BE, s->be))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_HTTP_PROCESS_BE);
				}

				if (ana_list & AN_RES_HTTP_XFER_BODY) {
					if (!http_response_forward_body(s, s->rep, AN_RES_HTTP_XFER_BODY))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_HTTP_XFER_BODY);
				}
				break;
			}
		}

		rp_cons_last = s->si[0].state;
		rp_prod_last = s->si[1].state;
		rpf_last = s->rep->flags;

		if ((s->rep->flags ^ flags) & BF_MASK_STATIC)
			goto resync_response;
	}

	/* maybe someone has added some request analysers, so we must check and loop */
	if (s->req->analysers & ~req_ana_back)
		goto resync_request;

	if ((s->req->flags & ~rqf_last) & BF_MASK_ANALYSER)
		goto resync_request;

	/* FIXME: here we should call protocol handlers which rely on
	 * both buffers.
	 */


	/*
	 * Now we propagate unhandled errors to the session. Normally
	 * we're just in a data phase here since it means we have not
	 * seen any analyser who could set an error status.
	 */
	srv = target_srv(&s->target);
	if (unlikely(!(s->flags & SN_ERR_MASK))) {
		if (s->req->flags & (BF_READ_ERROR|BF_READ_TIMEOUT|BF_WRITE_ERROR|BF_WRITE_TIMEOUT)) {
			/* Report it if the client got an error or a read timeout expired */
			s->req->analysers = 0;
			if (s->req->flags & BF_READ_ERROR) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLICL;
			}
			else if (s->req->flags & BF_READ_TIMEOUT) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLITO;
			}
			else if (s->req->flags & BF_WRITE_ERROR) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVCL;
			}
			else {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVTO;
			}
			sess_set_term_flags(s);
		}
		else if (s->rep->flags & (BF_READ_ERROR|BF_READ_TIMEOUT|BF_WRITE_ERROR|BF_WRITE_TIMEOUT)) {
			/* Report it if the server got an error or a read timeout expired */
			s->rep->analysers = 0;
			if (s->rep->flags & BF_READ_ERROR) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVCL;
			}
			else if (s->rep->flags & BF_READ_TIMEOUT) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVTO;
			}
			else if (s->rep->flags & BF_WRITE_ERROR) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLICL;
			}
			else {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLITO;
			}
			sess_set_term_flags(s);
		}
	}

	/*
	 * Here we take care of forwarding unhandled data. This also includes
	 * connection establishments and shutdown requests.
	 */


	/* If noone is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking BF_SHUTR_NOW as an indication of a possible
	 * recent call to buffer_abort().
	 */
	if (!s->req->analysers &&
	    !(s->req->flags & (BF_HIJACK|BF_SHUTW|BF_SHUTR_NOW)) &&
	    (s->req->prod->state >= SI_ST_EST) &&
	    (s->req->to_forward != BUF_INFINITE_FORWARD)) {
		/* This buffer is freewheeling, there's no analyser nor hijacker
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		buffer_auto_read(s->req);
		buffer_auto_connect(s->req);
		buffer_auto_close(s->req);
		buffer_flush(s->req);

		/* We'll let data flow between the producer (if still connected)
		 * to the consumer (which might possibly not be connected yet).
		 */
		if (!(s->req->flags & (BF_SHUTR|BF_SHUTW_NOW)))
			buffer_forward(s->req, BUF_INFINITE_FORWARD);
	}

	/* check if it is wise to enable kernel splicing to forward request data */
	if (!(s->req->flags & (BF_KERN_SPLICING|BF_SHUTR)) &&
	    s->req->to_forward &&
	    (global.tune.options & GTUNE_USE_SPLICE) &&
	    (s->si[0].flags & s->si[1].flags & SI_FL_CAP_SPLICE) &&
	    (pipes_used < global.maxpipes) &&
	    (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_REQ) ||
	     (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (s->req->flags & BF_STREAMER_FAST)))) {
		s->req->flags |= BF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rqf_last = s->req->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/* first, let's check if the request buffer needs to shutdown(write), which may
	 * happen either because the input is closed or because we want to force a close
	 * once the server has begun to respond.
	 */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK|BF_AUTO_CLOSE|BF_SHUTR)) ==
		     (BF_AUTO_CLOSE|BF_SHUTR)))
			buffer_shutw_now(s->req);

	/* shutdown(write) pending */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_OUT_EMPTY)) == (BF_SHUTW_NOW|BF_OUT_EMPTY)))
		s->req->cons->sock.shutw(s->req->cons);

	/* shutdown(write) done on server side, we must stop the client too */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTW &&
		     !s->req->analysers))
		buffer_shutr_now(s->req);

	/* shutdown(read) pending */
	if (unlikely((s->req->flags & (BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTR_NOW))
		s->req->prod->sock.shutr(s->req->prod);

	/* it's possible that an upper layer has requested a connection setup or abort.
	 * There are 2 situations where we decide to establish a new connection :
	 *  - there are data scheduled for emission in the buffer
	 *  - the BF_AUTO_CONNECT flag is set (active connection)
	 */
	if (s->req->cons->state == SI_ST_INI) {
		if (!(s->req->flags & BF_SHUTW)) {
			if ((s->req->flags & (BF_AUTO_CONNECT|BF_OUT_EMPTY)) != BF_OUT_EMPTY) {
				/* If we have an applet without a connect method, we immediately
				 * switch to the connected state, otherwise we perform a connection
				 * request.
				 */
				s->req->cons->state = SI_ST_REQ; /* new connection requested */
				s->req->cons->conn_retries = s->be->conn_retries;
				if (unlikely(s->req->cons->target.type == TARG_TYPE_APPLET &&
					     !(s->req->cons->proto && s->req->cons->proto->connect))) {
					s->req->cons->state = SI_ST_EST; /* connection established */
					s->rep->flags |= BF_READ_ATTACHED; /* producer is now attached */
					s->req->wex = TICK_ETERNITY;
				}
			}
		}
		else {
			s->req->cons->state = SI_ST_CLO; /* shutw+ini = abort */
			buffer_shutw_now(s->req);        /* fix buffer flags upon abort */
			buffer_shutr_now(s->rep);
		}
	}


	/* we may have a pending connection request, or a connection waiting
	 * for completion.
	 */
	if (s->si[1].state >= SI_ST_REQ && s->si[1].state < SI_ST_CON) {
		do {
			/* nb: step 1 might switch from QUE to ASS, but we first want
			 * to give a chance to step 2 to perform a redirect if needed.
			 */
			if (s->si[1].state != SI_ST_REQ)
				sess_update_stream_int(s, &s->si[1]);
			if (s->si[1].state == SI_ST_REQ)
				sess_prepare_conn_req(s, &s->si[1]);

			srv = target_srv(&s->target);
			if (s->si[1].state == SI_ST_ASS && srv && srv->rdr_len && (s->flags & SN_REDIRECTABLE))
				perform_http_redirect(s, &s->si[1]);
		} while (s->si[1].state == SI_ST_ASS);

		/* Now we can add the server name to a header (if requested) */
		/* check for HTTP mode and proxy server_name_hdr_name != NULL */
		if ((s->flags & SN_BE_ASSIGNED) &&
		    (s->be->mode == PR_MODE_HTTP) &&
		    (s->be->server_id_hdr_name != NULL)) {
			http_send_name_header(&s->txn, s->be, target_srv(&s->target)->id);
		}
	}

	/* Benchmarks have shown that it's optimal to do a full resync now */
	if (s->req->prod->state == SI_ST_DIS || s->req->cons->state == SI_ST_DIS)
		goto resync_stream_interface;

	/* otherwise we want to check if we need to resync the req buffer or not */
	if ((s->req->flags ^ rqf_last) & BF_MASK_STATIC)
		goto resync_request;

	/* perform output updates to the response buffer */

	/* If noone is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking BF_SHUTR_NOW as an indication of a possible
	 * recent call to buffer_abort().
	 */
	if (!s->rep->analysers &&
	    !(s->rep->flags & (BF_HIJACK|BF_SHUTW|BF_SHUTR_NOW)) &&
	    (s->rep->prod->state >= SI_ST_EST) &&
	    (s->rep->to_forward != BUF_INFINITE_FORWARD)) {
		/* This buffer is freewheeling, there's no analyser nor hijacker
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		buffer_auto_read(s->rep);
		buffer_auto_close(s->rep);
		buffer_flush(s->rep);

		/* We'll let data flow between the producer (if still connected)
		 * to the consumer.
		 */
		if (!(s->rep->flags & (BF_SHUTR|BF_SHUTW_NOW)))
			buffer_forward(s->rep, BUF_INFINITE_FORWARD);
	}

	/* check if it is wise to enable kernel splicing to forward response data */
	if (!(s->rep->flags & (BF_KERN_SPLICING|BF_SHUTR)) &&
	    s->rep->to_forward &&
	    (global.tune.options & GTUNE_USE_SPLICE) &&
	    (s->si[0].flags & s->si[1].flags & SI_FL_CAP_SPLICE) &&
	    (pipes_used < global.maxpipes) &&
	    (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_RTR) ||
	     (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (s->rep->flags & BF_STREAMER_FAST)))) {
		s->rep->flags |= BF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rpf_last = s->rep->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/*
	 * FIXME: this is probably where we should produce error responses.
	 */

	/* first, let's check if the response buffer needs to shutdown(write) */
	if (unlikely((s->rep->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK|BF_AUTO_CLOSE|BF_SHUTR)) ==
		     (BF_AUTO_CLOSE|BF_SHUTR)))
		buffer_shutw_now(s->rep);

	/* shutdown(write) pending */
	if (unlikely((s->rep->flags & (BF_SHUTW|BF_OUT_EMPTY|BF_SHUTW_NOW)) == (BF_OUT_EMPTY|BF_SHUTW_NOW)))
		s->rep->cons->sock.shutw(s->rep->cons);

	/* shutdown(write) done on the client side, we must stop the server too */
	if (unlikely((s->rep->flags & (BF_SHUTW|BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTW) &&
	    !s->rep->analysers)
		buffer_shutr_now(s->rep);

	/* shutdown(read) pending */
	if (unlikely((s->rep->flags & (BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTR_NOW))
		s->rep->prod->sock.shutr(s->rep->prod);

	if (s->req->prod->state == SI_ST_DIS || s->req->cons->state == SI_ST_DIS)
		goto resync_stream_interface;

	if (s->req->flags != rqf_last)
		goto resync_request;

	if ((s->rep->flags ^ rpf_last) & BF_MASK_STATIC)
		goto resync_response;

	/* we're interested in getting wakeups again */
	s->req->prod->flags &= ~SI_FL_DONT_WAKE;
	s->req->cons->flags &= ~SI_FL_DONT_WAKE;

	/* This is needed only when debugging is enabled, to indicate
	 * client-side or server-side close. Please note that in the unlikely
	 * event where both sides would close at once, the sequence is reported
	 * on the server side first.
	 */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) ||
		      (global.mode & MODE_VERBOSE)))) {
		int len;

		if (s->si[1].state == SI_ST_CLO &&
		    s->si[1].prev_state == SI_ST_EST) {
			len = sprintf(trash, "%08x:%s.srvcls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
				      (unsigned short)s->si[0].fd,
				      (unsigned short)s->si[1].fd);
			if (write(1, trash, len) < 0) /* shut gcc warning */;
		}

		if (s->si[0].state == SI_ST_CLO &&
		    s->si[0].prev_state == SI_ST_EST) {
			len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
				      (unsigned short)s->si[0].fd,
				      (unsigned short)s->si[1].fd);
			if (write(1, trash, len) < 0) /* shut gcc warning */;
		}
	}

	if (likely((s->rep->cons->state != SI_ST_CLO) ||
		   (s->req->cons->state > SI_ST_INI && s->req->cons->state < SI_ST_CLO))) {

		if ((s->fe->options & PR_O_CONTSTATS) && (s->flags & SN_BE_ASSIGNED))
			session_process_counters(s);

		if (s->rep->cons->state == SI_ST_EST && s->rep->cons->target.type != TARG_TYPE_APPLET)
			s->rep->cons->sock.update(s->rep->cons);

		if (s->req->cons->state == SI_ST_EST && s->req->cons->target.type != TARG_TYPE_APPLET)
			s->req->cons->sock.update(s->req->cons);

		s->req->flags &= ~(BF_READ_NULL|BF_READ_PARTIAL|BF_WRITE_NULL|BF_WRITE_PARTIAL|BF_READ_ATTACHED);
		s->rep->flags &= ~(BF_READ_NULL|BF_READ_PARTIAL|BF_WRITE_NULL|BF_WRITE_PARTIAL|BF_READ_ATTACHED);
		s->si[0].prev_state = s->si[0].state;
		s->si[1].prev_state = s->si[1].state;
		s->si[0].flags &= ~(SI_FL_ERR|SI_FL_EXP);
		s->si[1].flags &= ~(SI_FL_ERR|SI_FL_EXP);

		/* Trick: if a request is being waiting for the server to respond,
		 * and if we know the server can timeout, we don't want the timeout
		 * to expire on the client side first, but we're still interested
		 * in passing data from the client to the server (eg: POST). Thus,
		 * we can cancel the client's request timeout if the server's
		 * request timeout is set and the server has not yet sent a response.
		 */

		if ((s->rep->flags & (BF_AUTO_CLOSE|BF_SHUTR)) == 0 &&
		    (tick_isset(s->req->wex) || tick_isset(s->rep->rex))) {
			s->req->flags |= BF_READ_NOEXP;
			s->req->rex = TICK_ETERNITY;
		}

		/* Call the stream interfaces' I/O handlers when embedded.
		 * Note that this one may wake the task up again.
		 */
		if (s->req->cons->target.type == TARG_TYPE_APPLET ||
		    s->rep->cons->target.type == TARG_TYPE_APPLET) {
			if (s->req->cons->target.type == TARG_TYPE_APPLET)
				s->req->cons->target.ptr.a->fct(s->req->cons);
			if (s->rep->cons->target.type == TARG_TYPE_APPLET)
				s->rep->cons->target.ptr.a->fct(s->rep->cons);
			if (task_in_rq(t)) {
				/* If we woke up, we don't want to requeue the
				 * task to the wait queue, but rather requeue
				 * it into the runqueue ASAP.
				 */
				t->expire = TICK_ETERNITY;
				return t;
			}
		}

		t->expire = tick_first(tick_first(s->req->rex, s->req->wex),
				       tick_first(s->rep->rex, s->rep->wex));
		if (s->req->analysers)
			t->expire = tick_first(t->expire, s->req->analyse_exp);

		if (s->si[0].exp)
			t->expire = tick_first(t->expire, s->si[0].exp);

		if (s->si[1].exp)
			t->expire = tick_first(t->expire, s->si[1].exp);

#ifdef DEBUG_FULL
		fprintf(stderr,
			"[%u] queuing with exp=%u req->rex=%u req->wex=%u req->ana_exp=%u"
			" rep->rex=%u rep->wex=%u, si[0].exp=%u, si[1].exp=%u, cs=%d, ss=%d\n",
			now_ms, t->expire, s->req->rex, s->req->wex, s->req->analyse_exp,
			s->rep->rex, s->rep->wex, s->si[0].exp, s->si[1].exp, s->si[0].state, s->si[1].state);
#endif

#ifdef DEBUG_DEV
		/* this may only happen when no timeout is set or in case of an FSM bug */
		if (!tick_isset(t->expire))
			ABORT_NOW();
#endif
		return t; /* nothing more to do */
	}

	s->fe->feconn--;
	if (s->flags & SN_BE_ASSIGNED)
		s->be->beconn--;
	if (!(s->listener->options & LI_O_UNLIMITED))
		actconn--;
	jobs--;
	s->listener->nbconn--;
	if (s->listener->state == LI_FULL)
		resume_listener(s->listener);

	/* Dequeues all of the listeners waiting for a resource */
	if (!LIST_ISEMPTY(&global_listener_queue))
		dequeue_all_listeners(&global_listener_queue);

	if (!LIST_ISEMPTY(&s->fe->listener_queue) &&
	    (!s->fe->fe_sps_lim || freq_ctr_remain(&s->fe->fe_sess_per_sec, s->fe->fe_sps_lim, 0) > 0))
		dequeue_all_listeners(&s->fe->listener_queue);

	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		int len;
		len = sprintf(trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->id,
			      (unsigned short)s->req->prod->fd, (unsigned short)s->req->cons->fd);
		if (write(1, trash, len) < 0) /* shut gcc warning */;
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	session_process_counters(s);

	if (s->txn.status) {
		int n;

		n = s->txn.status / 100;
		if (n < 1 || n > 5)
			n = 0;

		if (s->fe->mode == PR_MODE_HTTP)
			s->fe->fe_counters.p.http.rsp[n]++;

		if ((s->flags & SN_BE_ASSIGNED) &&
		    (s->be->mode == PR_MODE_HTTP))
			s->be->be_counters.p.http.rsp[n]++;
	}

	/* let's do a final log if we need it */
	if (s->logs.logwait &&
	    !(s->flags & SN_MONITOR) &&
	    (!(s->fe->options & PR_O_NULLNOLOG) || s->req->total)) {
		s->do_log(s);
	}

	/* the task MUST not be in the run queue anymore */
	session_free(s);
	task_delete(t);
	task_free(t);
	return NULL;
}

/*
 * This function adjusts sess->srv_conn and maintains the previous and new
 * server's served session counts. Setting newsrv to NULL is enough to release
 * current connection slot. This function also notifies any LB algo which might
 * expect to be informed about any change in the number of active sessions on a
 * server.
 */
void sess_change_server(struct session *sess, struct server *newsrv)
{
	if (sess->srv_conn == newsrv)
		return;

	if (sess->srv_conn) {
		sess->srv_conn->served--;
		if (sess->srv_conn->proxy->lbprm.server_drop_conn)
			sess->srv_conn->proxy->lbprm.server_drop_conn(sess->srv_conn);
		session_del_srv_conn(sess);
	}

	if (newsrv) {
		newsrv->served++;
		if (newsrv->proxy->lbprm.server_take_conn)
			newsrv->proxy->lbprm.server_take_conn(newsrv);
		session_add_srv_conn(sess, newsrv);
	}
}

/* Handle server-side errors for default protocols. It is called whenever a a
 * connection setup is aborted or a request is aborted in queue. It sets the
 * session termination flags so that the caller does not have to worry about
 * them. It's installed as ->srv_error for the server-side stream_interface.
 */
void default_srv_error(struct session *s, struct stream_interface *si)
{
	int err_type = si->err_type;
	int err = 0, fin = 0;

	if (err_type & SI_ET_QUEUE_ABRT) {
		err = SN_ERR_CLICL;
		fin = SN_FINST_Q;
	}
	else if (err_type & SI_ET_CONN_ABRT) {
		err = SN_ERR_CLICL;
		fin = SN_FINST_C;
	}
	else if (err_type & SI_ET_QUEUE_TO) {
		err = SN_ERR_SRVTO;
		fin = SN_FINST_Q;
	}
	else if (err_type & SI_ET_QUEUE_ERR) {
		err = SN_ERR_SRVCL;
		fin = SN_FINST_Q;
	}
	else if (err_type & SI_ET_CONN_TO) {
		err = SN_ERR_SRVTO;
		fin = SN_FINST_C;
	}
	else if (err_type & SI_ET_CONN_ERR) {
		err = SN_ERR_SRVCL;
		fin = SN_FINST_C;
	}
	else /* SI_ET_CONN_OTHER and others */ {
		err = SN_ERR_INTERNAL;
		fin = SN_FINST_C;
	}

	if (!(s->flags & SN_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SN_FINST_MASK))
		s->flags |= fin;
}

/* kill a session and set the termination flags to <why> (one of SN_ERR_*) */
void session_shutdown(struct session *session, int why)
{
	if (session->req->flags & (BF_SHUTW|BF_SHUTW_NOW))
		return;

	buffer_shutw_now(session->req);
	buffer_shutr_now(session->rep);
	session->task->nice = 1024;
	if (!(session->flags & SN_ERR_MASK))
		session->flags |= why;
	task_wakeup(session->task, TASK_WOKEN_OTHER);
}

/************************************************************************/
/*           All supported ACL keywords must be declared here.          */
/************************************************************************/

/* set temp integer to the General Purpose Counter 0 value in the stksess entry <ts> */
static int
acl_fetch_get_gpc0(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_GPC0);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, gpc0);
	}
	return 1;
}

/* set temp integer to the General Purpose Counter 0 value from the session's tracked
 * frontend counters.
 */
static int
acl_fetch_sc1_get_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;
	return acl_fetch_get_gpc0(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the General Purpose Counter 0 value from the session's tracked
 * backend counters.
 */
static int
acl_fetch_sc2_get_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;
	return acl_fetch_get_gpc0(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the General Purpose Counter 0 value from the session's source
 * address in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_get_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_get_gpc0(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* Increment the General Purpose Counter 0 value in the stksess entry <ts> and
 * return it into temp integer.
 */
static int
acl_fetch_inc_gpc0(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_GPC0);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = ++stktable_data_cast(ptr, gpc0);
	}
	return 1;
}

/* Increment the General Purpose Counter 0 value from the session's tracked
 * frontend counters and return it into temp integer.
 */
static int
acl_fetch_sc1_inc_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;
	return acl_fetch_inc_gpc0(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* Increment the General Purpose Counter 0 value from the session's tracked
 * backend counters and return it into temp integer.
 */
static int
acl_fetch_sc2_inc_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;
	return acl_fetch_inc_gpc0(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* Increment the General Purpose Counter 0 value from the session's source
 * address in the table pointed to by expr, and return it into temp integer.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_inc_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_inc_gpc0(&px->table, smp, stktable_update_key(&px->table, key));
}

/* Clear the General Purpose Counter 0 value in the stksess entry <ts> and
 * return its previous value into temp integer.
 */
static int
acl_fetch_clr_gpc0(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_GPC0);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, gpc0);
		stktable_data_cast(ptr, gpc0) = 0;
	}
	return 1;
}

/* Clear the General Purpose Counter 0 value from the session's tracked
 * frontend counters and return its previous value into temp integer.
 */
static int
acl_fetch_sc1_clr_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;
	return acl_fetch_clr_gpc0(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* Clear the General Purpose Counter 0 value from the session's tracked
 * backend counters and return its previous value into temp integer.
 */
static int
acl_fetch_sc2_clr_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;
	return acl_fetch_clr_gpc0(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* Clear the General Purpose Counter 0 value from the session's source address
 * in the table pointed to by expr, and return its previous value into temp integer.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_clr_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_clr_gpc0(&px->table, smp, stktable_update_key(&px->table, key));
}

/* set temp integer to the cumulated number of connections in the stksess entry <ts> */
static int
acl_fetch_conn_cnt(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_CONN_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, conn_cnt);
	}
	return 1;
}

/* set temp integer to the cumulated number of connections from the session's tracked FE counters */
static int
acl_fetch_sc1_conn_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_conn_cnt(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the cumulated number of connections from the session's tracked BE counters */
static int
acl_fetch_sc2_conn_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_conn_cnt(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the cumulated number of connections from the session's source
 * address in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_conn_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_conn_cnt(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the connection rate in the stksess entry <ts> over the configured period */
static int
acl_fetch_conn_rate(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_CONN_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, conn_rate),
					       table->data_arg[STKTABLE_DT_CONN_RATE].u);
	}
	return 1;
}

/* set temp integer to the connection rate from the session's tracked FE counters over
 * the configured period.
 */
static int
acl_fetch_sc1_conn_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_conn_rate(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the connection rate from the session's tracked BE counters over
 * the configured period.
 */
static int
acl_fetch_sc2_conn_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_conn_rate(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the connection rate from the session's source address in the
 * table pointed to by expr, over the configured period.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_conn_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_conn_rate(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the number of connections from the session's source address
 * in the table pointed to by expr, after updating it.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_updt_conn_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	struct stksess *ts;
	struct stktable_key *key;
	void *ptr;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;

	if ((ts = stktable_update_key(&px->table, key)) == NULL)
		/* entry does not exist and could not be created */
		return 0;

	ptr = stktable_data_ptr(&px->table, ts, STKTABLE_DT_CONN_CNT);
	if (!ptr)
		return 0; /* parameter not stored in this table */

	smp->type = SMP_T_UINT;
	smp->data.uint = ++stktable_data_cast(ptr, conn_cnt);
	smp->flags = SMP_F_VOL_TEST;
	return 1;
}

/* set temp integer to the number of concurrent connections in the stksess entry <ts> */
static int
acl_fetch_conn_cur(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;

	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_CONN_CUR);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, conn_cur);
	}
	return 1;
}

/* set temp integer to the number of concurrent connections from the session's tracked FE counters */
static int
acl_fetch_sc1_conn_cur(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_conn_cur(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the number of concurrent connections from the session's tracked BE counters */
static int
acl_fetch_sc2_conn_cur(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_conn_cur(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the number of concurrent connections from the session's source
 * address in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_conn_cur(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_conn_cur(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the cumulated number of sessions in the stksess entry <ts> */
static int
acl_fetch_sess_cnt(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_SESS_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, sess_cnt);
	}
	return 1;
}

/* set temp integer to the cumulated number of sessions from the session's tracked FE counters */
static int
acl_fetch_sc1_sess_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_sess_cnt(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the cumulated number of sessions from the session's tracked BE counters */
static int
acl_fetch_sc2_sess_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_sess_cnt(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the cumulated number of session from the session's source
 * address in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_sess_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_sess_cnt(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the session rate in the stksess entry <ts> over the configured period */
static int
acl_fetch_sess_rate(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_SESS_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       table->data_arg[STKTABLE_DT_SESS_RATE].u);
	}
	return 1;
}

/* set temp integer to the session rate from the session's tracked FE counters over
 * the configured period.
 */
static int
acl_fetch_sc1_sess_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_sess_rate(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the session rate from the session's tracked BE counters over
 * the configured period.
 */
static int
acl_fetch_sc2_sess_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_sess_rate(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the session rate from the session's source address in the
 * table pointed to by expr, over the configured period.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_sess_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_sess_rate(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the cumulated number of sessions in the stksess entry <ts> */
static int
acl_fetch_http_req_cnt(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_HTTP_REQ_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, http_req_cnt);
	}
	return 1;
}

/* set temp integer to the cumulated number of sessions from the session's tracked FE counters */
static int
acl_fetch_sc1_http_req_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_http_req_cnt(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the cumulated number of sessions from the session's tracked BE counters */
static int
acl_fetch_sc2_http_req_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_http_req_cnt(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the cumulated number of session from the session's source
 * address in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_http_req_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_http_req_cnt(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the session rate in the stksess entry <ts> over the configured period */
static int
acl_fetch_http_req_rate(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_HTTP_REQ_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
					       table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u);
	}
	return 1;
}

/* set temp integer to the session rate from the session's tracked FE counters over
 * the configured period.
 */
static int
acl_fetch_sc1_http_req_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_http_req_rate(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the session rate from the session's tracked BE counters over
 * the configured period.
 */
static int
acl_fetch_sc2_http_req_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_http_req_rate(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the session rate from the session's source address in the
 * table pointed to by expr, over the configured period.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_http_req_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_http_req_rate(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the cumulated number of sessions in the stksess entry <ts> */
static int
acl_fetch_http_err_cnt(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_HTTP_ERR_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, http_err_cnt);
	}
	return 1;
}

/* set temp integer to the cumulated number of sessions from the session's tracked FE counters */
static int
acl_fetch_sc1_http_err_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_http_err_cnt(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the cumulated number of sessions from the session's tracked BE counters */
static int
acl_fetch_sc2_http_err_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_http_err_cnt(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the cumulated number of session from the session's source
 * address in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_http_err_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_http_err_cnt(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the session rate in the stksess entry <ts> over the configured period */
static int
acl_fetch_http_err_rate(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_HTTP_ERR_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
					       table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u);
	}
	return 1;
}

/* set temp integer to the session rate from the session's tracked FE counters over
 * the configured period.
 */
static int
acl_fetch_sc1_http_err_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_http_err_rate(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the session rate from the session's tracked BE counters over
 * the configured period.
 */
static int
acl_fetch_sc2_http_err_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_http_err_rate(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the session rate from the session's source address in the
 * table pointed to by expr, over the configured period.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_http_err_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_http_err_rate(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the number of kbytes received from clients matching the stksess entry <ts> */
static int
acl_fetch_kbytes_in(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;

	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_BYTES_IN_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, bytes_in_cnt) >> 10;
	}
	return 1;
}

/* set temp integer to the number of kbytes received from clients according to the
 * session's tracked FE counters.
 */
static int
acl_fetch_sc1_kbytes_in(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_kbytes_in(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the number of kbytes received from clients according to the
 * session's tracked BE counters.
 */
static int
acl_fetch_sc2_kbytes_in(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_kbytes_in(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the number of kbytes received from the session's source
 * address in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_kbytes_in(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_kbytes_in(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the bytes rate from clients in the stksess entry <ts> over the
 * configured period.
 */
static int
acl_fetch_bytes_in_rate(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_BYTES_IN_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_in_rate),
					       table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u);
	}
	return 1;
}

/* set temp integer to the bytes rate from clients from the session's tracked FE
 * counters over the configured period.
 */
static int
acl_fetch_sc1_bytes_in_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_bytes_in_rate(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the bytes rate from clients from the session's tracked BE
 * counters over the configured period.
 */
static int
acl_fetch_sc2_bytes_in_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_bytes_in_rate(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the bytes rate from clients from the session's source address
 * in the table pointed to by expr, over the configured period.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_bytes_in_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_bytes_in_rate(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the number of kbytes sent to clients matching the stksess entry <ts> */
static int
acl_fetch_kbytes_out(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;

	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_BYTES_OUT_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, bytes_out_cnt) >> 10;
	}
	return 1;
}

/* set temp integer to the number of kbytes sent to clients according to the session's
 * tracked FE counters.
 */
static int
acl_fetch_sc1_kbytes_out(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                         const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_kbytes_out(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the number of kbytes sent to clients according to the session's
 * tracked BE counters.
 */
static int
acl_fetch_sc2_kbytes_out(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                         const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_kbytes_out(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the number of kbytes sent to the session's source address in
 * the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_kbytes_out(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                         const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_kbytes_out(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the bytes rate to clients in the stksess entry <ts> over the
 * configured period.
 */
static int
acl_fetch_bytes_out_rate(struct stktable *table, struct sample *smp, struct stksess *ts)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (ts != NULL) {
		void *ptr = stktable_data_ptr(table, ts, STKTABLE_DT_BYTES_OUT_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_out_rate),
					       table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u);
	}
	return 1;
}

/* set temp integer to the bytes rate to clients from the session's tracked FE counters
 * over the configured period.
 */
static int
acl_fetch_sc1_bytes_out_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                             const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr1_entry)
		return 0;

	return acl_fetch_bytes_out_rate(l4->stkctr1_table, smp, l4->stkctr1_entry);
}

/* set temp integer to the bytes rate to clients from the session's tracked BE counters
 * over the configured period.
 */
static int
acl_fetch_sc2_bytes_out_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                             const struct arg *args, struct sample *smp)
{
	if (!l4->stkctr2_entry)
		return 0;

	return acl_fetch_bytes_out_rate(l4->stkctr2_table, smp, l4->stkctr2_entry);
}

/* set temp integer to the bytes rate to client from the session's source address in
 * the table pointed to by expr, over the configured period.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_src_bytes_out_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                             const struct arg *args, struct sample *smp)
{
	struct stktable_key *key;

	key = tcp_src_to_stktable_key(l4);
	if (!key)
		return 0;

	px = args->data.prx;
	return acl_fetch_bytes_out_rate(&px->table, smp, stktable_lookup_key(&px->table, key));
}

/* set temp integer to the number of used entries in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_table_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                    const struct arg *args, struct sample *smp)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = args->data.prx->table.current;
	return 1;
}

/* set temp integer to the number of free entries in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
acl_fetch_table_avl(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                    const struct arg *args, struct sample *smp)
{
	px = args->data.prx;
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = px->table.size - px->table.current;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {{ },{
	{ "sc1_bytes_in_rate",  acl_parse_int,   acl_fetch_sc1_bytes_in_rate,  acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_bytes_out_rate", acl_parse_int,   acl_fetch_sc1_bytes_out_rate, acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_clr_gpc0",       acl_parse_int,   acl_fetch_sc1_clr_gpc0,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_conn_cnt",       acl_parse_int,   acl_fetch_sc1_conn_cnt,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_conn_cur",       acl_parse_int,   acl_fetch_sc1_conn_cur,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_conn_rate",      acl_parse_int,   acl_fetch_sc1_conn_rate,      acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_get_gpc0",       acl_parse_int,   acl_fetch_sc1_get_gpc0,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_http_err_cnt",   acl_parse_int,   acl_fetch_sc1_http_err_cnt,   acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_http_err_rate",  acl_parse_int,   acl_fetch_sc1_http_err_rate,  acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_http_req_cnt",   acl_parse_int,   acl_fetch_sc1_http_req_cnt,   acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_http_req_rate",  acl_parse_int,   acl_fetch_sc1_http_req_rate,  acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_inc_gpc0",       acl_parse_int,   acl_fetch_sc1_inc_gpc0,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_kbytes_in",      acl_parse_int,   acl_fetch_sc1_kbytes_in,      acl_match_int, ACL_USE_TCP4_VOLATILE, 0 },
	{ "sc1_kbytes_out",     acl_parse_int,   acl_fetch_sc1_kbytes_out,     acl_match_int, ACL_USE_TCP4_VOLATILE, 0 },
	{ "sc1_sess_cnt",       acl_parse_int,   acl_fetch_sc1_sess_cnt,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc1_sess_rate",      acl_parse_int,   acl_fetch_sc1_sess_rate,      acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_bytes_in_rate",  acl_parse_int,   acl_fetch_sc2_bytes_in_rate,  acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_bytes_out_rate", acl_parse_int,   acl_fetch_sc2_bytes_out_rate, acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_clr_gpc0",       acl_parse_int,   acl_fetch_sc2_clr_gpc0,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_conn_cnt",       acl_parse_int,   acl_fetch_sc2_conn_cnt,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_conn_cur",       acl_parse_int,   acl_fetch_sc2_conn_cur,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_conn_rate",      acl_parse_int,   acl_fetch_sc2_conn_rate,      acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_get_gpc0",       acl_parse_int,   acl_fetch_sc2_get_gpc0,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_http_err_cnt",   acl_parse_int,   acl_fetch_sc2_http_err_cnt,   acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_http_err_rate",  acl_parse_int,   acl_fetch_sc2_http_err_rate,  acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_http_req_cnt",   acl_parse_int,   acl_fetch_sc2_http_req_cnt,   acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_http_req_rate",  acl_parse_int,   acl_fetch_sc2_http_req_rate,  acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_inc_gpc0",       acl_parse_int,   acl_fetch_sc2_inc_gpc0,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_kbytes_in",      acl_parse_int,   acl_fetch_sc2_kbytes_in,      acl_match_int, ACL_USE_TCP4_VOLATILE, 0 },
	{ "sc2_kbytes_out",     acl_parse_int,   acl_fetch_sc2_kbytes_out,     acl_match_int, ACL_USE_TCP4_VOLATILE, 0 },
	{ "sc2_sess_cnt",       acl_parse_int,   acl_fetch_sc2_sess_cnt,       acl_match_int, ACL_USE_NOTHING,       0 },
	{ "sc2_sess_rate",      acl_parse_int,   acl_fetch_sc2_sess_rate,      acl_match_int, ACL_USE_NOTHING,       0 },
	{ "src_bytes_in_rate",  acl_parse_int,   acl_fetch_src_bytes_in_rate,  acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_bytes_out_rate", acl_parse_int,   acl_fetch_src_bytes_out_rate, acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_clr_gpc0",       acl_parse_int,   acl_fetch_src_clr_gpc0,       acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_conn_cnt",       acl_parse_int,   acl_fetch_src_conn_cnt,       acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_conn_cur",       acl_parse_int,   acl_fetch_src_conn_cur,       acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_conn_rate",      acl_parse_int,   acl_fetch_src_conn_rate,      acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_get_gpc0",       acl_parse_int,   acl_fetch_src_get_gpc0,       acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_http_err_cnt",   acl_parse_int,   acl_fetch_src_http_err_cnt,   acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_http_err_rate",  acl_parse_int,   acl_fetch_src_http_err_rate,  acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_http_req_cnt",   acl_parse_int,   acl_fetch_src_http_req_cnt,   acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_http_req_rate",  acl_parse_int,   acl_fetch_src_http_req_rate,  acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_inc_gpc0",       acl_parse_int,   acl_fetch_src_inc_gpc0,       acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_kbytes_in",      acl_parse_int,   acl_fetch_src_kbytes_in,      acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_kbytes_out",     acl_parse_int,   acl_fetch_src_kbytes_out,     acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_sess_cnt",       acl_parse_int,   acl_fetch_src_sess_cnt,       acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_sess_rate",      acl_parse_int,   acl_fetch_src_sess_rate,      acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "src_updt_conn_cnt",  acl_parse_int,   acl_fetch_src_updt_conn_cnt,  acl_match_int, ACL_USE_TCP4_VOLATILE, ARG1(1,TAB) },
	{ "table_avl",          acl_parse_int,   acl_fetch_table_avl,          acl_match_int, ACL_USE_NOTHING,       ARG1(1,TAB) },
	{ "table_cnt",          acl_parse_int,   acl_fetch_table_cnt,          acl_match_int, ACL_USE_NOTHING,       ARG1(1,TAB) },
	{ NULL, NULL, NULL, NULL },
}};


/* Parse a "track-sc[12]" line starting with "track-sc[12]" in args[arg-1].
 * Returns the number of warnings emitted, or -1 in case of fatal errors. The
 * <prm> struct is fed with the table name if any. If unspecified, the caller
 * will assume that the current proxy's table is used.
 */
int parse_track_counters(char **args, int *arg,
			 int section_type, struct proxy *curpx,
			 struct track_ctr_prm *prm,
			 struct proxy *defpx, char *err, int errlen)
{
	int sample_type = 0;
	char *kw = args[*arg - 1];

	/* parse the arguments of "track-sc[12]" before the condition in the
	 * following form :
	 *      track-sc[12] src [ table xxx ] [ if|unless ... ]
	 */
	while (args[*arg]) {
		if (strcmp(args[*arg], "src") == 0) {
			prm->type = STKTABLE_TYPE_IP;
			sample_type = 1;
		}
		else if (strcmp(args[*arg], "table") == 0) {
			if (!args[*arg + 1]) {
				snprintf(err, errlen,
					 "missing table for %s in %s '%s'.",
					 kw, proxy_type_str(curpx), curpx->id);
				return -1;
			}
			/* we copy the table name for now, it will be resolved later */
			prm->table.n = strdup(args[*arg + 1]);
			(*arg)++;
		}
		else {
			/* unhandled keywords are handled by the caller */
			break;
		}
		(*arg)++;
	}

	if (!sample_type) {
		snprintf(err, errlen,
			 "%s key not specified in %s '%s' (found %s, only 'src' is supported).",
			 kw, proxy_type_str(curpx), curpx->id, quote_arg(args[*arg]));
		return -1;
	}

	return 0;
}

__attribute__((constructor))
static void __session_init(void)
{
	acl_register_keywords(&acl_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
