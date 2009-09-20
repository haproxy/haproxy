/*
 * Server management functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>

#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/dumpstats.h>
#include <proto/hdr_idx.h>
#include <proto/log.h>
#include <proto/session.h>
#include <proto/pipe.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/stream_interface.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

struct pool_head *pool2_session;
struct list sessions;

/*
 * frees  the context associated to a session. It must have been removed first.
 */
void session_free(struct session *s)
{
	struct http_txn *txn = &s->txn;
	struct proxy *fe = s->fe;
	struct bref *bref, *back;

	if (s->pend_pos)
		pendconn_free(s->pend_pos);

	if (s->srv) { /* there may be requests left pending in queue */
		if (s->flags & SN_CURR_SESS) {
			s->flags &= ~SN_CURR_SESS;
			s->srv->cur_sess--;
		}
		if (may_dequeue_tasks(s->srv, s->be))
			process_srv_queue(s->srv);
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

	if (fe) {
		pool_free2(fe->hdr_idx_pool, txn->hdr_idx.v);

		if (txn->rsp.cap != NULL) {
			struct cap_hdr *h;
			for (h = fe->rsp_cap; h; h = h->next)
				pool_free2(h->pool, txn->rsp.cap[h->index]);
			pool_free2(fe->rsp_cap_pool, txn->rsp.cap);
		}
		if (txn->req.cap != NULL) {
			struct cap_hdr *h;
			for (h = fe->req_cap; h; h = h->next)
				pool_free2(h->pool, txn->req.cap[h->index]);
			pool_free2(fe->req_cap_pool, txn->req.cap);
		}
	}
	pool_free2(pool2_requri, txn->uri);
	pool_free2(pool2_capture, txn->cli_cookie);
	pool_free2(pool2_capture, txn->srv_cookie);

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
		pool_flush2(fe->hdr_idx_pool);
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
			s->fe->bytes_in          += bytes;

			if (s->be != s->fe)
				s->be->bytes_in  += bytes;

			if (s->srv)
				s->srv->bytes_in += bytes;
		}
	}

	if (s->rep) {
		bytes = s->rep->total - s->logs.bytes_out;
		s->logs.bytes_out = s->rep->total;
		if (bytes) {
			s->fe->bytes_out          += bytes;

			if (s->be != s->fe)
				s->be->bytes_out  += bytes;

			if (s->srv)
				s->srv->bytes_out += bytes;
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
int sess_update_st_con_tcp(struct session *s, struct stream_interface *si)
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

		if (si->err_type)
			return 0;

		si->err_loc = s->srv;
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
		si->shutw(si);
		si->err_type |= SI_ET_CONN_ABRT;
		si->err_loc  = s->srv;
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
int sess_update_st_cer(struct session *s, struct stream_interface *si)
{
	/* we probably have to release last session from the server */
	if (s->srv) {
		if (s->flags & SN_CURR_SESS) {
			s->flags &= ~SN_CURR_SESS;
			s->srv->cur_sess--;
		}
	}

	/* ensure that we have enough retries left */
	s->conn_retries--;
	if (s->conn_retries < 0) {
		if (!si->err_type) {
			si->err_type = SI_ET_CONN_ERR;
			si->err_loc = s->srv;
		}

		if (s->srv)
			s->srv->failed_conns++;
		s->be->failed_conns++;
		if (may_dequeue_tasks(s->srv, s->be))
			process_srv_queue(s->srv);

		/* shutw is enough so stop a connecting socket */
		si->shutw(si);
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
	if (s->srv && s->conn_retries == 0 && s->be->options & PR_O_REDISP) {
		if (may_dequeue_tasks(s->srv, s->be))
			process_srv_queue(s->srv);

		s->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
		s->prev_srv = s->srv;
		si->state = SI_ST_REQ;
	} else {
		if (s->srv)
			s->srv->retries++;
		s->be->retries++;
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
 * SI_ST_EST state. It must only be called after switching from SI_ST_CON to
 * SI_ST_EST.
 */
void sess_establish(struct session *s, struct stream_interface *si)
{
	struct buffer *req = si->ob;
	struct buffer *rep = si->ib;

	if (s->be->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
		buffer_set_rlim(rep, rep->size); /* no rewrite needed */

		/* if the user wants to log as soon as possible, without counting
		 * bytes from the server, then this is the right moment. */
		if (s->fe->to_log && !(s->logs.logwait & LW_BYTES)) {
			s->logs.t_close = s->logs.t_connect; /* to get a valid end date */
			s->do_log(s);
		}
	}
	else {
		buffer_set_rlim(rep, req->size - global.tune.maxrewrite); /* rewrite needed */
		s->txn.rsp.msg_state = HTTP_MSG_RPBEFORE;
		/* reset hdr_idx which was already initialized by the request.
		 * right now, the http parser does it.
		 * hdr_idx_init(&s->txn.hdr_idx);
		 */
	}

	rep->analysers |= s->fe->fe_rsp_ana | s->be->be_rsp_ana;
	rep->flags |= BF_READ_ATTACHED; /* producer is now attached */
	req->wex = TICK_ETERNITY;
}

/* Update stream interface status for input states SI_ST_ASS, SI_ST_QUE, SI_ST_TAR.
 * Other input states are simply ignored.
 * Possible output states are SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ, SI_ST_CON.
 * Flags must have previously been updated for timeouts and other conditions.
 */
void sess_update_stream_int(struct session *s, struct stream_interface *si)
{
	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rql=%d rpl=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->l, s->rep->l, s->rep->cons->state, s->req->cons->state);

	if (si->state == SI_ST_ASS) {
		/* Server assigned to connection request, we have to try to connect now */
		int conn_err;

		conn_err = connect_server(s);
		if (conn_err == SN_ERR_NONE) {
			/* state = SI_ST_CON now */
			if (s->srv)
				srv_inc_sess_ctr(s->srv);
			return;
		}

		/* We have received a synchronous error. We might have to
		 * abort, retry immediately or redispatch.
		 */
		if (conn_err == SN_ERR_INTERNAL) {
			if (!si->err_type) {
				si->err_type = SI_ET_CONN_OTHER;
				si->err_loc  = s->srv;
			}

			if (s->srv)
				srv_inc_sess_ctr(s->srv);
			if (s->srv)
				s->srv->failed_conns++;
			s->be->failed_conns++;

			/* release other sessions waiting for this server */
			if (may_dequeue_tasks(s->srv, s->be))
				process_srv_queue(s->srv);

			/* Failed and not retryable. */
			si->shutr(si);
			si->shutw(si);
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
			if (s->srv)
				s->srv->failed_conns++;
			s->be->failed_conns++;
			si->shutr(si);
			si->shutw(si);
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
			si->shutr(si);
			si->shutw(si);
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
			si->shutr(si);
			si->shutw(si);
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

/* This function initiates a server connection request on a stream interface
 * already in SI_ST_REQ state. Upon success, the state goes to SI_ST_ASS,
 * indicating that a server has been assigned. It may also return SI_ST_QUE,
 * or SI_ST_CLO upon error.
 */
static void sess_prepare_conn_req(struct session *s, struct stream_interface *si) {
	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rql=%d rpl=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->l, s->rep->l, s->rep->cons->state, s->req->cons->state);

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
		si->shutr(si);
		si->shutw(si);
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
 * if appropriate. The default_backend rule is also considered.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * either needs more data or wants to immediately abort the request.
 */
int process_switching_rules(struct session *s, struct buffer *req, int an_bit)
{
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bl=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->l,
		req->analysers);

	/* now check whether we have some switching rules for this request */
	if (!(s->flags & SN_BE_ASSIGNED)) {
		struct switching_rule *rule;

		list_for_each_entry(rule, &s->fe->switching_rules, list) {
			int ret;

			ret = acl_exec_cond(rule->cond, s->fe, s, &s->txn, ACL_DIR_REQ);
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

	/* we don't want to run the HTTP filters again if the backend has not changed */
	if (s->fe == s->be)
		s->req->analysers &= ~AN_REQ_HTTP_PROCESS_BE;

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
	struct session *s = t->context;
	unsigned int rqf_last, rpf_last;

	//DPRINTF(stderr, "%s:%d: cs=%d ss=%d(%d) rqf=0x%08x rpf=0x%08x\n", __FUNCTION__, __LINE__,
	//        s->si[0].state, s->si[1].state, s->si[1].err_type, s->req->flags, s->rep->flags);

	/* This flag must explicitly be set every time */
	s->req->flags &= ~BF_READ_NOEXP;

	/* Keep a copy of req/rep flags so that we can detect shutdowns */
	rqf_last = s->req->flags;
	rpf_last = s->rep->flags;

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

		if (unlikely((s->req->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == BF_READ_TIMEOUT))
			s->req->prod->shutr(s->req->prod);

		if (unlikely((s->req->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == BF_WRITE_TIMEOUT))
			s->req->cons->shutw(s->req->cons);

		buffer_check_timeouts(s->rep);

		if (unlikely((s->rep->flags & (BF_SHUTR|BF_READ_TIMEOUT)) == BF_READ_TIMEOUT))
			s->rep->prod->shutr(s->rep->prod);

		if (unlikely((s->rep->flags & (BF_SHUTW|BF_WRITE_TIMEOUT)) == BF_WRITE_TIMEOUT))
			s->rep->cons->shutw(s->rep->cons);
	}

	/* 1b: check for low-level errors reported at the stream interface.
	 * First we check if it's a retryable error (in which case we don't
	 * want to tell the buffer). Otherwise we report the error one level
	 * upper by setting flags into the buffers. Note that the side towards
	 * the client cannot have connect (hence retryable) errors. Also, the
	 * connection setup code must be able to deal with any type of abort.
	 */
	if (unlikely(s->si[0].flags & SI_FL_ERR)) {
		if (s->si[0].state == SI_ST_EST || s->si[0].state == SI_ST_DIS) {
			s->si[0].shutr(&s->si[0]);
			s->si[0].shutw(&s->si[0]);
			stream_int_report_error(&s->si[0]);
			if (!(s->req->analysers) && !(s->rep->analysers)) {
				if (!(s->flags & SN_ERR_MASK))
					s->flags |= SN_ERR_CLICL;
				if (!(s->flags & SN_FINST_MASK))
					s->flags |= SN_FINST_D;
			}
		}
	}

	if (unlikely(s->si[1].flags & SI_FL_ERR)) {
		if (s->si[1].state == SI_ST_EST || s->si[1].state == SI_ST_DIS) {
			s->si[1].shutr(&s->si[1]);
			s->si[1].shutw(&s->si[1]);
			stream_int_report_error(&s->si[1]);
			s->be->failed_resp++;
			if (s->srv)
				s->srv->failed_resp++;
			if (!(s->req->analysers) && !(s->rep->analysers)) {
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

resync_stream_interface:
	/* Check for connection closure */

	DPRINTF(stderr,
		"[%u] %s:%d: task=%p s=%p, sfl=0x%08x, rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rql=%d rpl=%d cs=%d ss=%d, cet=0x%x set=0x%x retr=%d\n",
		now_ms, __FUNCTION__, __LINE__,
		t,
		s, s->flags,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->l, s->rep->l, s->rep->cons->state, s->req->cons->state,
		s->rep->cons->err_type, s->req->cons->err_type,
		s->conn_retries);

	/* nothing special to be done on client side */
	if (unlikely(s->req->prod->state == SI_ST_DIS))
		s->req->prod->state = SI_ST_CLO;

	/* When a server-side connection is released, we have to count it and
	 * check for pending connections on this server.
	 */
	if (unlikely(s->req->cons->state == SI_ST_DIS)) {
		s->req->cons->state = SI_ST_CLO;
		if (s->srv) {
			if (s->flags & SN_CURR_SESS) {
				s->flags &= ~SN_CURR_SESS;
				s->srv->cur_sess--;
			}
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(s->srv, s->be))
				process_srv_queue(s->srv);
		}
	}

	/*
	 * Note: of the transient states (REQ, CER, DIS), only REQ may remain
	 * at this point.
	 */

 resync_request:
	/* Analyse request */
	if ((s->req->flags & BF_MASK_ANALYSER) ||
	    (s->req->flags ^ rqf_last) & BF_MASK_STATIC) {
		unsigned int flags = s->req->flags;

		if (s->req->prod->state >= SI_ST_EST) {
			unsigned int last_ana = 0;

			/* it's up to the analysers to stop new connections */
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
			 */
			while (s->req->analysers & ~last_ana) {
				last_ana = s->req->analysers;

				if (s->req->analysers & AN_REQ_INSPECT) {
					last_ana |= AN_REQ_INSPECT;
					if (!tcp_inspect_request(s, s->req, AN_REQ_INSPECT))
						break;
				}

				if (s->req->analysers & AN_REQ_WAIT_HTTP) {
					last_ana |= AN_REQ_WAIT_HTTP;
					if (!http_wait_for_request(s, s->req, AN_REQ_WAIT_HTTP))
						break;
				}

				if (s->req->analysers & AN_REQ_HTTP_PROCESS_FE) {
					last_ana |= AN_REQ_HTTP_PROCESS_FE;
					if (!http_process_req_common(s, s->req, AN_REQ_HTTP_PROCESS_FE, s->fe))
						break;
				}

				if (s->req->analysers & AN_REQ_SWITCHING_RULES) {
					last_ana |= AN_REQ_SWITCHING_RULES;
					if (!process_switching_rules(s, s->req, AN_REQ_SWITCHING_RULES))
						break;
					/* FIXME: we mait switch from TCP to HTTP and want to
					 * immediately loop back to the top. This is a dirty way
					 * of doing it, and we should find a cleaner method relying
					 * on a circular list of function pointers.
					 */
					if ((s->req->analysers & ~last_ana) & AN_REQ_WAIT_HTTP)
						continue;
				}

				if (s->req->analysers & AN_REQ_HTTP_PROCESS_BE) {
					last_ana |= AN_REQ_HTTP_PROCESS_BE;
					if (!http_process_req_common(s, s->req, AN_REQ_HTTP_PROCESS_BE, s->be))
						break;
				}

				if (s->req->analysers & AN_REQ_HTTP_TARPIT) {
					last_ana |= AN_REQ_HTTP_TARPIT;
					if (!http_process_tarpit(s, s->req, AN_REQ_HTTP_TARPIT))
						break;
				}

				if (s->req->analysers & AN_REQ_HTTP_INNER) {
					last_ana |= AN_REQ_HTTP_INNER;
					if (!http_process_request(s, s->req, AN_REQ_HTTP_INNER))
						break;
				}

				if (s->req->analysers & AN_REQ_HTTP_BODY) {
					last_ana |= AN_REQ_HTTP_BODY;
					if (!http_process_request_body(s, s->req, AN_REQ_HTTP_BODY))
						break;
				}

				if (s->req->analysers & AN_REQ_STATS_SOCK) {
					last_ana |= AN_REQ_STATS_SOCK;
					if (!stats_sock_req_analyser(s, s->req, AN_REQ_STATS_SOCK))
						break;
				}

				if (s->req->analysers & AN_REQ_PRST_RDP_COOKIE) {
					last_ana |= AN_REQ_PRST_RDP_COOKIE;
					if (!tcp_persist_rdp_cookie(s, s->req, AN_REQ_PRST_RDP_COOKIE))
						break;
				}
			}
		}

		if ((s->req->flags ^ flags) & BF_MASK_STATIC) {
			rqf_last = s->req->flags;
			goto resync_request;
		}
	}

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
	else if ((s->rep->flags & BF_MASK_ANALYSER) ||
		 (s->rep->flags ^ rpf_last) & BF_MASK_STATIC) {
		unsigned int flags = s->rep->flags;

		if (s->rep->prod->state >= SI_ST_EST) {
			/* it's up to the analysers to reset auto_close */
			buffer_auto_close(s->rep);
			if (s->rep->analysers)
				process_response(s);
		}

		if ((s->rep->flags ^ flags) & BF_MASK_STATIC) {
			rpf_last = s->rep->flags;
			goto resync_response;
		}
	}

	/* FIXME: here we should call protocol handlers which rely on
	 * both buffers.
	 */


	/*
	 * Now we propagate unhandled errors to the session
	 */
	if (!(s->flags & SN_ERR_MASK)) {
		if (s->req->flags & (BF_READ_ERROR|BF_READ_TIMEOUT|BF_WRITE_ERROR|BF_WRITE_TIMEOUT)) {
			/* Report it if the client got an error or a read timeout expired */
			s->req->analysers = 0;
			if (s->req->flags & BF_READ_ERROR)
				s->flags |= SN_ERR_CLICL;
			else if (s->req->flags & BF_READ_TIMEOUT)
				s->flags |= SN_ERR_CLITO;
			else if (s->req->flags & BF_WRITE_ERROR)
				s->flags |= SN_ERR_SRVCL;
			else
				s->flags |= SN_ERR_SRVTO;
			sess_set_term_flags(s);
		}
		else if (s->rep->flags & (BF_READ_ERROR|BF_READ_TIMEOUT|BF_WRITE_ERROR|BF_WRITE_TIMEOUT)) {
			/* Report it if the server got an error or a read timeout expired */
			s->rep->analysers = 0;
			if (s->rep->flags & BF_READ_ERROR)
				s->flags |= SN_ERR_SRVCL;
			else if (s->rep->flags & BF_READ_TIMEOUT)
				s->flags |= SN_ERR_SRVTO;
			else if (s->rep->flags & BF_WRITE_ERROR)
				s->flags |= SN_ERR_CLICL;
			else
			s->flags |= SN_ERR_CLITO;
			sess_set_term_flags(s);
		}
	}

	/*
	 * Here we take care of forwarding unhandled data. This also includes
	 * connection establishments and shutdown requests.
	 */


	/* If noone is interested in analysing data, it's time to forward
	 * everything. We will wake up from time to time when either send_max
	 * or to_forward are reached.
	 */
	if (!s->req->analysers &&
	    !(s->req->flags & (BF_HIJACK|BF_SHUTW)) &&
	    (s->req->prod->state >= SI_ST_EST)) {
		/* This buffer is freewheeling, there's no analyser nor hijacker
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		buffer_auto_connect(s->req);
		buffer_auto_close(s->req);
		buffer_flush(s->req);

		/* If the producer is still connected, we'll schedule large blocks
		 * of data to be forwarded from the producer to the consumer (which
		 * might possibly not be connected yet).
		 */
		if (!(s->req->flags & (BF_SHUTR|BF_SHUTW|BF_SHUTW_NOW)) &&
		    s->req->to_forward < FORWARD_DEFAULT_SIZE)
			buffer_forward(s->req, FORWARD_DEFAULT_SIZE);
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
	if ((s->req->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK|BF_AUTO_CLOSE)) == BF_AUTO_CLOSE) {
		if (unlikely((s->req->flags & BF_SHUTR) ||
			     ((s->req->cons->state == SI_ST_EST) &&
			      (s->be->options & PR_O_FORCE_CLO) &&
			      (s->rep->flags & BF_READ_ACTIVITY))))
			buffer_shutw_now(s->req);
	}

	/* shutdown(write) pending */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_OUT_EMPTY)) == (BF_SHUTW_NOW|BF_OUT_EMPTY)))
		s->req->cons->shutw(s->req->cons);

	/* shutdown(write) done on server side, we must stop the client too */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTW &&
		     !s->req->analysers))
		buffer_shutr_now(s->req);

	/* shutdown(read) pending */
	if (unlikely((s->req->flags & (BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTR_NOW))
		s->req->prod->shutr(s->req->prod);

	/* it's possible that an upper layer has requested a connection setup or abort.
	 * There are 2 situations where we decide to establish a new connection :
	 *  - there are data scheduled for emission in the buffer
	 *  - the BF_AUTO_CONNECT flag is set (active connection)
	 */
	if (s->req->cons->state == SI_ST_INI) {
		if (!(s->req->flags & (BF_SHUTW|BF_SHUTW_NOW))) {
			if ((s->req->flags & (BF_AUTO_CONNECT|BF_OUT_EMPTY)) != BF_OUT_EMPTY) {
				/* If we have a ->connect method, we need to perform a connection request,
				 * otherwise we immediately switch to the connected state.
				 */
				if (s->req->cons->connect)
					s->req->cons->state = SI_ST_REQ; /* new connection requested */
				else
					s->req->cons->state = SI_ST_EST; /* connection established */
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

			if (s->si[1].state == SI_ST_ASS && s->srv &&
			    s->srv->rdr_len && (s->flags & SN_REDIRECTABLE))
				perform_http_redirect(s, &s->si[1]);
		} while (s->si[1].state == SI_ST_ASS);
	}

	/* Benchmarks have shown that it's optimal to do a full resync now */
	if (s->req->prod->state == SI_ST_DIS || s->req->cons->state == SI_ST_DIS)
		goto resync_stream_interface;

	/* otherwise wewant to check if we need to resync the req buffer or not */
	if ((s->req->flags ^ rqf_last) & BF_MASK_STATIC)
		goto resync_request;

	/* perform output updates to the response buffer */

	/* If noone is interested in analysing data, it's time to forward
	 * everything. We will wake up from time to time when either send_max
	 * or to_forward are reached.
	 */
	if (!s->rep->analysers &&
	    !(s->rep->flags & (BF_HIJACK|BF_SHUTW)) &&
	    (s->rep->prod->state >= SI_ST_EST)) {
		/* This buffer is freewheeling, there's no analyser nor hijacker
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		buffer_auto_close(s->rep);
		buffer_flush(s->rep);

		/* If the producer is still connected, we'll schedule large blocks
		 * of data to be forwarded from the producer to the consumer (which
		 * might possibly not be connected yet).
		 */
		if (!(s->rep->flags & (BF_SHUTR|BF_SHUTW|BF_SHUTW_NOW)) &&
		    s->rep->to_forward < FORWARD_DEFAULT_SIZE)
			buffer_forward(s->rep, FORWARD_DEFAULT_SIZE);
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
		s->rep->cons->shutw(s->rep->cons);

	/* shutdown(write) done on the client side, we must stop the server too */
	if (unlikely((s->rep->flags & (BF_SHUTW|BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTW) &&
	    !s->rep->analysers)
		buffer_shutr_now(s->rep);

	/* shutdown(read) pending */
	if (unlikely((s->rep->flags & (BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTR_NOW))
		s->rep->prod->shutr(s->rep->prod);

	if (s->req->prod->state == SI_ST_DIS || s->req->cons->state == SI_ST_DIS)
		goto resync_stream_interface;

	if (s->req->flags != rqf_last)
		goto resync_request;

	if ((s->rep->flags ^ rpf_last) & BF_MASK_STATIC)
		goto resync_response;

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
			write(1, trash, len);
		}

		if (s->si[0].state == SI_ST_CLO &&
		    s->si[0].prev_state == SI_ST_EST) {
			len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
				      (unsigned short)s->si[0].fd,
				      (unsigned short)s->si[1].fd);
			write(1, trash, len);
		}
	}

	if (likely((s->rep->cons->state != SI_ST_CLO) ||
		   (s->req->cons->state > SI_ST_INI && s->req->cons->state < SI_ST_CLO))) {

		if ((s->fe->options & PR_O_CONTSTATS) && (s->flags & SN_BE_ASSIGNED))
			session_process_counters(s);

		if (s->rep->cons->state == SI_ST_EST)
			s->rep->cons->update(s->rep->cons);

		if (s->req->cons->state == SI_ST_EST)
			s->req->cons->update(s->req->cons);

		s->req->flags &= ~(BF_READ_NULL|BF_READ_PARTIAL|BF_WRITE_NULL|BF_WRITE_PARTIAL);
		s->rep->flags &= ~(BF_READ_NULL|BF_READ_PARTIAL|BF_WRITE_NULL|BF_WRITE_PARTIAL);
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
	actconn--;
	s->listener->nbconn--;
	if (s->listener->state == LI_FULL &&
	    s->listener->nbconn < s->listener->maxconn) {
		/* we should reactivate the listener */
		EV_FD_SET(s->listener->fd, DIR_RD);
		s->listener->state = LI_READY;
	}

	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		int len;
		len = sprintf(trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->id,
			      (unsigned short)s->req->prod->fd, (unsigned short)s->req->cons->fd);
		write(1, trash, len);
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	session_process_counters(s);

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
		sess->srv_conn = NULL;
	}

	if (newsrv) {
		newsrv->served++;
		if (newsrv->proxy->lbprm.server_take_conn)
			newsrv->proxy->lbprm.server_take_conn(newsrv);
		sess->srv_conn = newsrv;
	}
}

/* Set correct session termination flags in case no analyser has done it. It
 * also counts a failed request if the server state has not reached the request
 * stage.
 */
void sess_set_term_flags(struct session *s)
{
	if (!(s->flags & SN_FINST_MASK)) {
		if (s->si[1].state < SI_ST_REQ) {
			s->fe->failed_req++;
			s->flags |= SN_FINST_R;
		}
		else if (s->si[1].state == SI_ST_QUE)
			s->flags |= SN_FINST_Q;
		else if (s->si[1].state < SI_ST_EST)
			s->flags |= SN_FINST_C;
		else if (s->si[1].state == SI_ST_EST)
			s->flags |= SN_FINST_D;
		else
			s->flags |= SN_FINST_L;
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
