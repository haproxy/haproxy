/*
 * Stream management functions.
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

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/buffer.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/hathreads.h>

#include <types/applet.h>
#include <types/capture.h>
#include <types/cli.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/stats.h>

#include <proto/acl.h>
#include <proto/action.h>
#include <proto/arg.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/cli.h>
#include <proto/connection.h>
#include <proto/stats.h>
#include <proto/fd.h>
#include <proto/filters.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/raw_sock.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/pipe.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/sample.h>
#include <proto/stick_table.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/tcp_rules.h>
#include <proto/vars.h>

struct pool_head *pool_head_stream;
struct list streams;
__decl_hathreads(HA_SPINLOCK_T streams_lock);

/* List of all use-service keywords. */
static struct list service_keywords = LIST_HEAD_INIT(service_keywords);


/* Create a new stream for connection <conn>. Return < 0 on error. This is only
 * valid right after the handshake, before the connection's data layer is
 * initialized, because it relies on the session to be in conn->owner.
 */
int stream_create_from_cs(struct conn_stream *cs)
{
	struct stream *strm;

	strm = stream_new(cs->conn->owner, &cs->obj_type);
	if (strm == NULL)
		return -1;

	task_wakeup(strm->task, TASK_WOKEN_INIT);
	return 0;
}

/* This function is called from the session handler which detects the end of
 * handshake, in order to complete initialization of a valid stream. It must be
 * called with a completley initialized session. It returns the pointer to
 * the newly created stream, or NULL in case of fatal error. The client-facing
 * end point is assigned to <origin>, which must be valid. The stream's task
 * is configured with a nice value inherited from the listener's nice if any.
 * The task's context is set to the new stream, and its function is set to
 * process_stream(). Target and analysers are null.
 */
struct stream *stream_new(struct session *sess, enum obj_type *origin)
{
	struct stream *s;
	struct task *t;
	struct conn_stream *cs  = objt_cs(origin);
	struct appctx *appctx   = objt_appctx(origin);

	if (unlikely((s = pool_alloc(pool_head_stream)) == NULL))
		goto out_fail_alloc;

	/* minimum stream initialization required for an embryonic stream is
	 * fairly low. We need very little to execute L4 ACLs, then we need a
	 * task to make the client-side connection live on its own.
	 *  - flags
	 *  - stick-entry tracking
	 */
	s->flags = 0;
	s->logs.logwait = sess->fe->to_log;
	s->logs.level = 0;
	s->logs.accept_date = sess->accept_date; /* user-visible date for logging */
	s->logs.tv_accept = sess->tv_accept;   /* corrected date for internal use */
	/* This function is called just after the handshake, so the handshake duration is
	 * between the accept time and now.
	 */
	s->logs.t_handshake = tv_ms_elapsed(&sess->tv_accept, &now);
	s->logs.t_idle = -1;
	tv_zero(&s->logs.tv_request);
	s->logs.t_queue = -1;
	s->logs.t_connect = -1;
	s->logs.t_data = -1;
	s->logs.t_close = 0;
	s->logs.bytes_in = s->logs.bytes_out = 0;
	s->logs.prx_queue_size = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_size = 0; /* we will get this number soon */

	/* default logging function */
	s->do_log = strm_log;

	/* default error reporting function, may be changed by analysers */
	s->srv_error = default_srv_error;

	/* Initialise the current rule list pointer to NULL. We are sure that
	 * any rulelist match the NULL pointer.
	 */
	s->current_rule_list = NULL;
	s->current_rule = NULL;

	/* Copy SC counters for the stream. We don't touch refcounts because
	 * any reference we have is inherited from the session. Since the stream
	 * doesn't exist without the session, the session's existence guarantees
	 * we don't lose the entry. During the store operation, the stream won't
	 * touch these ones.
	 */
	memcpy(s->stkctr, sess->stkctr, sizeof(s->stkctr));

	s->sess = sess;
	s->si[0].flags = SI_FL_NONE;
	s->si[1].flags = SI_FL_ISBACK;

	s->uniq_id = global.req_count++;

	/* OK, we're keeping the stream, so let's properly initialize the stream */
	LIST_INIT(&s->back_refs);

	LIST_INIT(&s->buffer_wait.list);
	s->buffer_wait.target = s;
	s->buffer_wait.wakeup_cb = (int (*)(void *))stream_res_wakeup;

	s->flags |= SF_INITIALIZED;
	s->unique_id = NULL;

	if ((t = task_new(tid_bit)) == NULL)
		goto out_fail_alloc;

	s->task = t;
	s->pending_events = 0;
	t->process = process_stream;
	t->context = s;
	t->expire = TICK_ETERNITY;
	if (sess->listener)
		t->nice = sess->listener->nice;

	/* Note: initially, the stream's backend points to the frontend.
	 * This changes later when switching rules are executed or
	 * when the default backend is assigned.
	 */
	s->be  = sess->fe;
	s->req.buf = s->res.buf = NULL;
	s->req_cap = NULL;
	s->res_cap = NULL;

	/* Initialise all the variables contexts even if not used.
	 * This permits to prune these contexts without errors.
	 */
	vars_init(&s->vars_txn,    SCOPE_TXN);
	vars_init(&s->vars_reqres, SCOPE_REQ);

	/* this part should be common with other protocols */
	si_reset(&s->si[0]);
	si_set_state(&s->si[0], SI_ST_EST);
	s->si[0].hcto = sess->fe->timeout.clientfin;

	if (cs && cs->conn->mux && cs->conn->mux->flags & MX_FL_CLEAN_ABRT)
		s->si[0].flags |= SI_FL_CLEAN_ABRT;

	/* attach the incoming connection to the stream interface now. */
	if (cs)
		si_attach_cs(&s->si[0], cs);
	else if (appctx)
		si_attach_appctx(&s->si[0], appctx);

	if (likely(sess->fe->options2 & PR_O2_INDEPSTR))
		s->si[0].flags |= SI_FL_INDEP_STR;

	/* pre-initialize the other side's stream interface to an INIT state. The
	 * callbacks will be initialized before attempting to connect.
	 */
	si_reset(&s->si[1]);
	s->si[1].hcto = TICK_ETERNITY;

	if (likely(sess->fe->options2 & PR_O2_INDEPSTR))
		s->si[1].flags |= SI_FL_INDEP_STR;

	stream_init_srv_conn(s);
	s->target = sess->listener ? sess->listener->default_target : NULL;

	s->pend_pos = NULL;

	/* init store persistence */
	s->store_count = 0;

	channel_init(&s->req);
	s->req.flags |= CF_READ_ATTACHED; /* the producer is already connected */
	s->req.analysers = sess->listener ? sess->listener->analysers : 0;

	if (!sess->fe->fe_req_ana) {
		channel_auto_connect(&s->req);  /* don't wait to establish connection */
		channel_auto_close(&s->req);    /* let the producer forward close requests */
	}

	s->req.rto = sess->fe->timeout.client;
	s->req.wto = TICK_ETERNITY;
	s->req.rex = TICK_ETERNITY;
	s->req.wex = TICK_ETERNITY;
	s->req.analyse_exp = TICK_ETERNITY;

	channel_init(&s->res);
	s->res.flags |= CF_ISRESP;
	s->res.analysers = 0;

	if (sess->fe->options2 & PR_O2_NODELAY) {
		s->req.flags |= CF_NEVER_WAIT;
		s->res.flags |= CF_NEVER_WAIT;
	}

	s->res.wto = sess->fe->timeout.client;
	s->res.rto = TICK_ETERNITY;
	s->res.rex = TICK_ETERNITY;
	s->res.wex = TICK_ETERNITY;
	s->res.analyse_exp = TICK_ETERNITY;

	s->txn = NULL;
	s->hlua = NULL;

	HA_SPIN_LOCK(STRMS_LOCK, &streams_lock);
	LIST_ADDQ(&streams, &s->list);
	HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);

	if (flt_stream_init(s) < 0 || flt_stream_start(s) < 0)
		goto out_fail_accept;

	/* finish initialization of the accepted file descriptor */
	if (cs)
		cs_want_recv(cs);
	else if (appctx)
		si_applet_want_get(&s->si[0]);

	if (sess->fe->accept && sess->fe->accept(s) < 0)
		goto out_fail_accept;

	/* it is important not to call the wakeup function directly but to
	 * pass through task_wakeup(), because this one knows how to apply
	 * priorities to tasks. Using multi thread we must be sure that
	 * stream is fully initialized before calling task_wakeup. So
	 * the caller must handle the task_wakeup
	 */
	return s;

	/* Error unrolling */
 out_fail_accept:
	flt_stream_release(s, 0);
	task_free(t);
 out_fail_alloc:
	LIST_DEL(&s->list);
	pool_free(pool_head_stream, s);
	return NULL;
}

/*
 * frees  the context associated to a stream. It must have been removed first.
 */
static void stream_free(struct stream *s)
{
	struct session *sess = strm_sess(s);
	struct proxy *fe = sess->fe;
	struct bref *bref, *back;
	struct conn_stream *cli_cs = objt_cs(s->si[0].end);
	int must_free_sess;
	int i;

	if (s->pend_pos)
		pendconn_free(s->pend_pos);

	if (objt_server(s->target)) { /* there may be requests left pending in queue */
		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			HA_ATOMIC_SUB(&objt_server(s->target)->cur_sess, 1);
		}
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));
	}

	if (unlikely(s->srv_conn)) {
		/* the stream still has a reserved slot on a server, but
		 * it should normally be only the same as the one above,
		 * so this should not happen in fact.
		 */
		sess_change_server(s, NULL);
	}

	if (s->req.pipe)
		put_pipe(s->req.pipe);

	if (s->res.pipe)
		put_pipe(s->res.pipe);

	/* We may still be present in the buffer wait queue */
	if (!LIST_ISEMPTY(&s->buffer_wait.list)) {
		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_DEL(&s->buffer_wait.list);
		LIST_INIT(&s->buffer_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	}
	if (s->req.buf->size || s->res.buf->size) {
		b_drop(&s->req.buf);
		b_drop(&s->res.buf);
		offer_buffers(NULL, tasks_run_queue + applets_active_queue);
	}

	hlua_ctx_destroy(s->hlua);
	s->hlua = NULL;
	if (s->txn)
		http_end_txn(s);

	/* ensure the client-side transport layer is destroyed */
	if (cli_cs)
		cs_close(cli_cs);

	for (i = 0; i < s->store_count; i++) {
		if (!s->store[i].ts)
			continue;
		stksess_free(s->store[i].table, s->store[i].ts);
		s->store[i].ts = NULL;
	}

	if (s->txn) {
		pool_free(pool_head_hdr_idx, s->txn->hdr_idx.v);
		pool_free(pool_head_http_txn, s->txn);
		s->txn = NULL;
	}

	flt_stream_stop(s);
	flt_stream_release(s, 0);

	if (fe) {
		pool_free(fe->rsp_cap_pool, s->res_cap);
		pool_free(fe->req_cap_pool, s->req_cap);
	}

	/* Cleanup all variable contexts. */
	vars_prune(&s->vars_txn, s->sess, s);
	vars_prune(&s->vars_reqres, s->sess, s);

	stream_store_counters(s);

	HA_SPIN_LOCK(STRMS_LOCK, &streams_lock);
	list_for_each_entry_safe(bref, back, &s->back_refs, users) {
		/* we have to unlink all watchers. We must not relink them if
		 * this stream was the last one in the list.
		 */
		LIST_DEL(&bref->users);
		LIST_INIT(&bref->users);
		if (s->list.n != &streams)
			LIST_ADDQ(&LIST_ELEM(s->list.n, struct stream *, list)->back_refs, &bref->users);
		bref->ref = s->list.n;
	}
	LIST_DEL(&s->list);
	HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);

	/* applets do not release session yet */
	must_free_sess = objt_appctx(sess->origin) && sess->origin == s->si[0].end;

	si_release_endpoint(&s->si[1]);
	si_release_endpoint(&s->si[0]);

	if (must_free_sess)
		session_free(sess);

	pool_free(pool_head_stream, s);

	/* We may want to free the maximum amount of pools if the proxy is stopping */
	if (fe && unlikely(fe->state == PR_STSTOPPED)) {
		pool_flush(pool_head_buffer);
		pool_flush(pool_head_http_txn);
		pool_flush(pool_head_hdr_idx);
		pool_flush(pool_head_requri);
		pool_flush(pool_head_capture);
		pool_flush(pool_head_stream);
		pool_flush(pool_head_session);
		pool_flush(pool_head_connection);
		pool_flush(pool_head_pendconn);
		pool_flush(fe->req_cap_pool);
		pool_flush(fe->rsp_cap_pool);
	}
}


/* Allocates a work buffer for stream <s>. It is meant to be called inside
 * process_stream(). It will only allocate the side needed for the function
 * to work fine, which is the response buffer so that an error message may be
 * built and returned. Response buffers may be allocated from the reserve, this
 * is critical to ensure that a response may always flow and will never block a
 * server from releasing a connection. Returns 0 in case of failure, non-zero
 * otherwise.
 */
static int stream_alloc_work_buffer(struct stream *s)
{
	if (!LIST_ISEMPTY(&s->buffer_wait.list)) {
		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_DEL(&s->buffer_wait.list);
		LIST_INIT(&s->buffer_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	}

	if (b_alloc_margin(&s->res.buf, 0))
		return 1;

	HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	LIST_ADDQ(&buffer_wq, &s->buffer_wait.list);
	HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	return 0;
}

/* releases unused buffers after processing. Typically used at the end of the
 * update() functions. It will try to wake up as many tasks/applets as the
 * number of buffers that it releases. In practice, most often streams are
 * blocked on a single buffer, so it makes sense to try to wake two up when two
 * buffers are released at once.
 */
void stream_release_buffers(struct stream *s)
{
	int offer = 0;

	if (s->req.buf->size && buffer_empty(s->req.buf)) {
		offer = 1;
		b_free(&s->req.buf);
	}
	if (s->res.buf->size && buffer_empty(s->res.buf)) {
		offer = 1;
		b_free(&s->res.buf);
	}

	/* if we're certain to have at least 1 buffer available, and there is
	 * someone waiting, we can wake up a waiter and offer them.
	 */
	if (offer)
		offer_buffers(s, tasks_run_queue + applets_active_queue);
}

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_stream()
{
	LIST_INIT(&streams);
	HA_SPIN_INIT(&streams_lock);
	pool_head_stream = create_pool("stream", sizeof(struct stream), MEM_F_SHARED);
	return pool_head_stream != NULL;
}

void stream_process_counters(struct stream *s)
{
	struct session *sess = s->sess;
	unsigned long long bytes;
	void *ptr1,*ptr2;
	struct stksess *ts;
	int i;

	bytes = s->req.total - s->logs.bytes_in;
	s->logs.bytes_in = s->req.total;
	if (bytes) {
		HA_ATOMIC_ADD(&sess->fe->fe_counters.bytes_in, bytes);
		HA_ATOMIC_ADD(&s->be->be_counters.bytes_in,    bytes);

		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.bytes_in, bytes);

		if (sess->listener && sess->listener->counters)
			HA_ATOMIC_ADD(&sess->listener->counters->bytes_in, bytes);

		for (i = 0; i < MAX_SESS_STKCTR; i++) {
			struct stkctr *stkctr = &s->stkctr[i];

			ts = stkctr_entry(stkctr);
			if (!ts) {
				stkctr = &sess->stkctr[i];
				ts = stkctr_entry(stkctr);
				if (!ts)
					continue;
			}

			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
			ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_IN_CNT);
			if (ptr1)
				stktable_data_cast(ptr1, bytes_in_cnt) += bytes;

			ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_IN_RATE);
			if (ptr2)
				update_freq_ctr_period(&stktable_data_cast(ptr2, bytes_in_rate),
						       stkctr->table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u, bytes);
			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			if (ptr1 || ptr2)
				stktable_touch_local(stkctr->table, ts, 0);
		}
	}

	bytes = s->res.total - s->logs.bytes_out;
	s->logs.bytes_out = s->res.total;
	if (bytes) {
		HA_ATOMIC_ADD(&sess->fe->fe_counters.bytes_out, bytes);
		HA_ATOMIC_ADD(&s->be->be_counters.bytes_out,    bytes);

		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.bytes_out, bytes);

		if (sess->listener && sess->listener->counters)
			HA_ATOMIC_ADD(&sess->listener->counters->bytes_out, bytes);

		for (i = 0; i < MAX_SESS_STKCTR; i++) {
			struct stkctr *stkctr = &s->stkctr[i];

			ts = stkctr_entry(stkctr);
			if (!ts) {
				stkctr = &sess->stkctr[i];
				ts = stkctr_entry(stkctr);
				if (!ts)
					continue;
			}

			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
			ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_OUT_CNT);
			if (ptr1)
				stktable_data_cast(ptr1, bytes_out_cnt) += bytes;

			ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_OUT_RATE);
			if (ptr2)
				update_freq_ctr_period(&stktable_data_cast(ptr2, bytes_out_rate),
						       stkctr->table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u, bytes);
			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			if (ptr1 || ptr2)
				stktable_touch_local(stkctr->table, stkctr_entry(stkctr), 0);
		}
	}
}

/* This function is called with (si->state == SI_ST_CON) meaning that a
 * connection was attempted and that the file descriptor is already allocated.
 * We must check for establishment, error and abort. Possible output states
 * are SI_ST_EST (established), SI_ST_CER (error), SI_ST_DIS (abort), and
 * SI_ST_CON (no change). The function returns 0 if it switches to SI_ST_CER,
 * otherwise 1. This only works with connection-based streams.
 */
static int sess_update_st_con_tcp(struct stream *s)
{
	struct stream_interface *si = &s->si[1];
	struct channel *req = &s->req;
	struct channel *rep = &s->res;
	struct conn_stream *srv_cs = __objt_cs(si->end);

	/* If we got an error, or if nothing happened and the connection timed
	 * out, we must give up. The CER state handler will take care of retry
	 * attempts and error reports.
	 */
	if (unlikely(si->flags & (SI_FL_EXP|SI_FL_ERR))) {
		if (unlikely(req->flags & CF_WROTE_DATA)) {
			/* Some data were sent past the connection establishment,
			 * so we need to pretend we're established to log correctly
			 * and let later states handle the failure.
			 */
			si->state    = SI_ST_EST;
			si->err_type = SI_ET_DATA_ERR;
			rep->flags |= CF_READ_ERROR | CF_WRITE_ERROR;
			return 1;
		}
		si->exp   = TICK_ETERNITY;
		si->state = SI_ST_CER;

		/* XXX cognet: do we really want to kill the connection here ?
		 * Probably not for multiple streams.
		 */
		cs_close(srv_cs);

		if (si->err_type)
			return 0;

		if (si->flags & SI_FL_ERR)
			si->err_type = SI_ET_CONN_ERR;
		else
			si->err_type = SI_ET_CONN_TO;
		return 0;
	}

	/* OK, maybe we want to abort */
	if (!(req->flags & CF_WROTE_DATA) &&
	    unlikely((rep->flags & CF_SHUTW) ||
		     ((req->flags & CF_SHUTW_NOW) && /* FIXME: this should not prevent a connection from establishing */
		      ((!(req->flags & (CF_WRITE_ACTIVITY|CF_WRITE_EVENT)) && channel_is_empty(req)) ||
		       ((s->be->options & PR_O_ABRT_CLOSE) && !(s->si[0].flags & SI_FL_CLEAN_ABRT)))))) {
		/* give up */
		si_shutw(si);
		si->err_type |= SI_ET_CONN_ABRT;
		if (s->srv_error)
			s->srv_error(s, si);
		return 1;
	}

	/* we need to wait a bit more if there was no activity either */
	if (!(req->flags & (CF_WRITE_ACTIVITY|CF_WRITE_EVENT)))
		return 1;

	/* OK, this means that a connection succeeded. The caller will be
	 * responsible for handling the transition from CON to EST.
	 */
	si->state    = SI_ST_EST;
	si->err_type = SI_ET_NONE;
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
static int sess_update_st_cer(struct stream *s)
{
	struct stream_interface *si = &s->si[1];
	struct conn_stream *cs = objt_cs(si->end);
	struct connection *conn = cs_conn(cs);

	/* we probably have to release last stream from the server */
	if (objt_server(s->target)) {
		health_adjust(objt_server(s->target), HANA_STATUS_L4_ERR);

		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			HA_ATOMIC_SUB(&objt_server(s->target)->cur_sess, 1);
		}

		if ((si->flags & SI_FL_ERR) &&
		    conn && conn->err_code == CO_ER_SSL_MISMATCH_SNI) {
			/* We tried to connect to a server which is configured
			 * with "verify required" and which doesn't have the
			 * "verifyhost" directive. The server presented a wrong
			 * certificate (a certificate for an unexpected name),
			 * which implies that we have used SNI in the handshake,
			 * and that the server doesn't have the associated cert
			 * and presented a default one.
			 *
			 * This is a serious enough issue not to retry. It's
			 * especially important because this wrong name might
			 * either be the result of a configuration error, and
			 * retrying will only hammer the server, or is caused
			 * by the use of a wrong SNI value, most likely
			 * provided by the client and we don't want to let the
			 * client provoke retries.
			 */
			si->conn_retries = 0;
		}
	}

	/* ensure that we have enough retries left */
	si->conn_retries--;
	if (si->conn_retries < 0) {
		if (!si->err_type) {
			si->err_type = SI_ET_CONN_ERR;
		}

		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_conns, 1);
		HA_ATOMIC_ADD(&s->be->be_counters.failed_conns, 1);
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		/* shutw is enough so stop a connecting socket */
		si_shutw(si);
		s->req.flags |= CF_WRITE_ERROR;
		s->res.flags |= CF_READ_ERROR;

		si->state = SI_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, si);
		return 0;
	}

	/* If the "redispatch" option is set on the backend, we are allowed to
	 * retry on another server. By default this redispatch occurs on the
	 * last retry, but if configured we allow redispatches to occur on
	 * configurable intervals, e.g. on every retry. In order to achieve this,
	 * we must mark the stream unassigned, and eventually clear the DIRECT
	 * bit to ignore any persistence cookie. We won't count a retry nor a
	 * redispatch yet, because this will depend on what server is selected.
	 * If the connection is not persistent, the balancing algorithm is not
	 * determinist (round robin) and there is more than one active server,
	 * we accept to perform an immediate redispatch without waiting since
	 * we don't care about this particular server.
	 */
	if (objt_server(s->target) &&
	    (s->be->options & PR_O_REDISP) && !(s->flags & SF_FORCE_PRST) &&
	    ((__objt_server(s->target)->cur_state < SRV_ST_RUNNING) ||
	     (((s->be->redispatch_after > 0) &&
	       ((s->be->conn_retries - si->conn_retries) %
	        s->be->redispatch_after == 0)) ||
	      ((s->be->redispatch_after < 0) &&
	       ((s->be->conn_retries - si->conn_retries) %
	        (s->be->conn_retries + 1 + s->be->redispatch_after) == 0))) ||
	     (!(s->flags & SF_DIRECT) && s->be->srv_act > 1 &&
	      ((s->be->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_RR)))) {
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		s->flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);
		si->state = SI_ST_REQ;
	} else {
		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.retries, 1);
		HA_ATOMIC_ADD(&s->be->be_counters.retries, 1);
		si->state = SI_ST_ASS;
	}

	if (si->flags & SI_FL_ERR) {
		/* The error was an asynchronous connection error, and we will
		 * likely have to retry connecting to the same server, most
		 * likely leading to the same result. To avoid this, we wait
		 * MIN(one second, connect timeout) before retrying.
		 */

		int delay = 1000;

		if (s->be->timeout.connect && s->be->timeout.connect < delay)
			delay = s->be->timeout.connect;

		if (!si->err_type)
			si->err_type = SI_ET_CONN_ERR;

		/* only wait when we're retrying on the same server */
		if (si->state == SI_ST_ASS ||
		    (s->be->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_RR ||
		    (s->be->srv_act <= 1)) {
			si->state = SI_ST_TAR;
			si->exp = tick_add(now_ms, MS_TO_TICKS(delay));
		}
		return 0;
	}
	return 0;
}

/*
 * This function handles the transition between the SI_ST_CON state and the
 * SI_ST_EST state. It must only be called after switching from SI_ST_CON (or
 * SI_ST_INI) to SI_ST_EST, but only when a ->proto is defined.
 */
static void sess_establish(struct stream *s)
{
	struct stream_interface *si = &s->si[1];
	struct channel *req = &s->req;
	struct channel *rep = &s->res;

	/* First, centralize the timers information */
	s->logs.t_connect = tv_ms_elapsed(&s->logs.tv_accept, &now);
	si->exp      = TICK_ETERNITY;

	if (objt_server(s->target))
		health_adjust(objt_server(s->target), HANA_STATUS_L4_OK);

	if (s->be->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
		/* if the user wants to log as soon as possible, without counting
		 * bytes from the server, then this is the right moment. */
		if (!LIST_ISEMPTY(&strm_fe(s)->logformat) && !(s->logs.logwait & LW_BYTES)) {
			s->logs.t_close = s->logs.t_connect; /* to get a valid end date */
			s->do_log(s);
		}
	}
	else {
		rep->flags |= CF_READ_DONTWAIT; /* a single read is enough to get response headers */
	}

	if (!(s->flags & SF_TUNNEL)) {
		rep->analysers |= strm_fe(s)->fe_rsp_ana | s->be->be_rsp_ana;

		/* Be sure to filter response headers if the backend is an HTTP proxy
		 * and if there are filters attached to the stream. */
		if (s->be->mode == PR_MODE_HTTP && HAS_FILTERS(s))
			rep->analysers |= AN_RES_FLT_HTTP_HDRS;
	}

	rep->flags |= CF_READ_ATTACHED; /* producer is now attached */
	if (req->flags & CF_WAKE_CONNECT) {
		req->flags |= CF_WAKE_ONCE;
		req->flags &= ~CF_WAKE_CONNECT;
	}
	if (objt_cs(si->end)) {
		/* real connections have timeouts */
		req->wto = s->be->timeout.server;
		rep->rto = s->be->timeout.server;
	}
	req->wex = TICK_ETERNITY;
}

/* Check if the connection request is in such a state that it can be aborted. */
static int check_req_may_abort(struct channel *req, struct stream *s)
{
	return ((req->flags & (CF_READ_ERROR)) ||
	        ((req->flags & (CF_SHUTW_NOW|CF_SHUTW)) &&  /* empty and client aborted */
	         (channel_is_empty(req) ||
		  ((s->be->options & PR_O_ABRT_CLOSE) && !(s->si[0].flags & SI_FL_CLEAN_ABRT)))));
}

/* Update back stream interface status for input states SI_ST_ASS, SI_ST_QUE,
 * SI_ST_TAR. Other input states are simply ignored.
 * Possible output states are SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ, SI_ST_CON
 * and SI_ST_EST. Flags must have previously been updated for timeouts and other
 * conditions.
 */
static void sess_update_stream_int(struct stream *s)
{
	struct server *srv = objt_server(s->target);
	struct stream_interface *si = &s->si[1];
	struct channel *req = &s->req;

	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		req, &s->res,
		req->rex, s->res.wex,
		req->flags, s->res.flags,
		req->buf->i, req->buf->o, s->res.buf->i, s->res.buf->o, s->si[0].state, s->si[1].state);

	if (si->state == SI_ST_ASS) {
		/* Server assigned to connection request, we have to try to connect now */
		int conn_err;

		/* Before we try to initiate the connection, see if the
		 * request may be aborted instead.
		 */
		if (check_req_may_abort(req, s)) {
			si->err_type |= SI_ET_CONN_ABRT;
			goto abort_connection;
		}

		conn_err = connect_server(s);
		srv = objt_server(s->target);

		if (conn_err == SF_ERR_NONE) {
			/* state = SI_ST_CON or SI_ST_EST now */
			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			return;
		}

		/* We have received a synchronous error. We might have to
		 * abort, retry immediately or redispatch.
		 */
		if (conn_err == SF_ERR_INTERNAL) {
			if (!si->err_type) {
				si->err_type = SI_ET_CONN_OTHER;
			}

			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			if (srv)
				HA_ATOMIC_ADD(&srv->counters.failed_conns, 1);
			HA_ATOMIC_ADD(&s->be->be_counters.failed_conns, 1);

			/* release other streams waiting for this server */
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(srv, s->be))
				process_srv_queue(srv);

			/* Failed and not retryable. */
			si_shutr(si);
			si_shutw(si);
			req->flags |= CF_WRITE_ERROR;

			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

			/* no stream was ever accounted for this server */
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
		sess_update_st_cer(s);
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
			if (unlikely(!(s->flags & SF_ASSIGNED)))
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
				HA_ATOMIC_ADD(&srv->counters.failed_conns, 1);
			HA_ATOMIC_ADD(&s->be->be_counters.failed_conns, 1);
			si_shutr(si);
			si_shutw(si);
			req->flags |= CF_WRITE_TIMEOUT;
			if (!si->err_type)
				si->err_type = SI_ET_QUEUE_TO;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		/* Connection remains in queue, check if we have to abort it */
		if (check_req_may_abort(req, s)) {
			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
			si->err_type |= SI_ET_QUEUE_ABRT;
			goto abort_connection;
		}

		/* Nothing changed */
		return;
	}
	else if (si->state == SI_ST_TAR) {
		/* Connection request might be aborted */
		if (check_req_may_abort(req, s)) {
			si->err_type |= SI_ET_CONN_ABRT;
			goto abort_connection;
		}

		if (!(si->flags & SI_FL_EXP))
			return;  /* still in turn-around */

		si->exp = TICK_ETERNITY;

		/* we keep trying on the same server as long as the stream is
		 * marked "assigned".
		 * FIXME: Should we force a redispatch attempt when the server is down ?
		 */
		if (s->flags & SF_ASSIGNED)
			si->state = SI_ST_ASS;
		else
			si->state = SI_ST_REQ;
		return;
	}
	return;

abort_connection:
	/* give up */
	si->exp = TICK_ETERNITY;
	si_shutr(si);
	si_shutw(si);
	si->state = SI_ST_CLO;
	if (s->srv_error)
		s->srv_error(s, si);
	return;
}

/* Set correct stream termination flags in case no analyser has done it. It
 * also counts a failed request if the server state has not reached the request
 * stage.
 */
static void sess_set_term_flags(struct stream *s)
{
	if (!(s->flags & SF_FINST_MASK)) {
		if (s->si[1].state < SI_ST_REQ) {

			HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.failed_req, 1);
			if (strm_li(s) && strm_li(s)->counters)
				HA_ATOMIC_ADD(&strm_li(s)->counters->failed_req, 1);

			s->flags |= SF_FINST_R;
		}
		else if (s->si[1].state == SI_ST_QUE)
			s->flags |= SF_FINST_Q;
		else if (s->si[1].state < SI_ST_EST)
			s->flags |= SF_FINST_C;
		else if (s->si[1].state == SI_ST_EST || s->si[1].prev_state == SI_ST_EST)
			s->flags |= SF_FINST_D;
		else
			s->flags |= SF_FINST_L;
	}
}

/* This function initiates a server connection request on a stream interface
 * already in SI_ST_REQ state. Upon success, the state goes to SI_ST_ASS for
 * a real connection to a server, indicating that a server has been assigned,
 * or SI_ST_EST for a successful connection to an applet. It may also return
 * SI_ST_QUE, or SI_ST_CLO upon error.
 */
static void sess_prepare_conn_req(struct stream *s)
{
	struct stream_interface *si = &s->si[1];

	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		&s->req, &s->res,
		s->req.rex, s->res.wex,
		s->req.flags, s->res.flags,
		s->req.buf->i, s->req.buf->o, s->res.buf->i, s->res.buf->o, s->si[0].state, s->si[1].state);

	if (si->state != SI_ST_REQ)
		return;

	if (unlikely(obj_type(s->target) == OBJ_TYPE_APPLET)) {
		/* the applet directly goes to the EST state */
		struct appctx *appctx = objt_appctx(si->end);

		if (!appctx || appctx->applet != __objt_applet(s->target))
			appctx = stream_int_register_handler(si, objt_applet(s->target));

		if (!appctx) {
			/* No more memory, let's immediately abort. Force the
			 * error code to ignore the ERR_LOCAL which is not a
			 * real error.
			 */
			s->flags &= ~(SF_ERR_MASK | SF_FINST_MASK);

			si_shutr(si);
			si_shutw(si);
			s->req.flags |= CF_WRITE_ERROR;
			si->err_type = SI_ET_CONN_RES;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		if (tv_iszero(&s->logs.tv_request))
			s->logs.tv_request = now;
		s->logs.t_queue   = tv_ms_elapsed(&s->logs.tv_accept, &now);
		si->state         = SI_ST_EST;
		si->err_type      = SI_ET_NONE;
		be_set_sess_last(s->be);
		/* let sess_establish() finish the job */
		return;
	}

	/* Try to assign a server */
	if (srv_redispatch_connect(s) != 0) {
		/* We did not get a server. Either we queued the
		 * connection request, or we encountered an error.
		 */
		if (si->state == SI_ST_QUE)
			return;

		/* we did not get any server, let's check the cause */
		si_shutr(si);
		si_shutw(si);
		s->req.flags |= CF_WRITE_ERROR;
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
	be_set_sess_last(s->be);
}

/* This function parses the use-service action ruleset. It executes
 * the associated ACL and set an applet as a stream or txn final node.
 * it returns ACT_RET_ERR if an error occurs, the proxy left in
 * consistent state. It returns ACT_RET_STOP in succes case because
 * use-service must be a terminal action. Returns ACT_RET_YIELD
 * if the initialisation function require more data.
 */
enum act_return process_use_service(struct act_rule *rule, struct proxy *px,
                                    struct session *sess, struct stream *s, int flags)

{
	struct appctx *appctx;

	/* Initialises the applet if it is required. */
	if (flags & ACT_FLAG_FIRST) {
		/* Register applet. this function schedules the applet. */
		s->target = &rule->applet.obj_type;
		if (unlikely(!stream_int_register_handler(&s->si[1], objt_applet(s->target))))
			return ACT_RET_ERR;

		/* Initialise the context. */
		appctx = si_appctx(&s->si[1]);
		memset(&appctx->ctx, 0, sizeof(appctx->ctx));
		appctx->rule = rule;

		/* enable the minimally required analyzers in case of HTTP
		 * keep-alive to properly handle keep-alive and compression
		 * on the HTTP response.
		 */
		if (rule->from == ACT_F_HTTP_REQ) {
			s->req.analysers &= AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END;
			s->req.analysers |= AN_REQ_HTTP_XFER_BODY;
		}
	}
	else
		appctx = si_appctx(&s->si[1]);

	/* Stops the applet sheduling, in case of the init function miss
	 * some data.
	 */
	si_applet_stop_get(&s->si[1]);

	/* Call initialisation. */
	if (rule->applet.init)
		switch (rule->applet.init(appctx, px, s)) {
		case 0: return ACT_RET_ERR;
		case 1: break;
		default: return ACT_RET_YIELD;
	}

	/* Now we can schedule the applet. */
	si_applet_cant_get(&s->si[1]);
	appctx_wakeup(appctx);

	if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
		HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

	/* The flag SF_ASSIGNED prevent from server assignment. */
	s->flags |= SF_ASSIGNED;

	return ACT_RET_STOP;
}

/* This stream analyser checks the switching rules and changes the backend
 * if appropriate. The default_backend rule is also considered, then the
 * target backend's forced persistence rules are also evaluated last if any.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * either needs more data or wants to immediately abort the request.
 */
static int process_switching_rules(struct stream *s, struct channel *req, int an_bit)
{
	struct persist_rule *prst_rule;
	struct session *sess = s->sess;
	struct proxy *fe = sess->fe;

	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	/* now check whether we have some switching rules for this request */
	if (!(s->flags & SF_BE_ASSIGNED)) {
		struct switching_rule *rule;

		list_for_each_entry(rule, &fe->switching_rules, list) {
			int ret = 1;

			if (rule->cond) {
				ret = acl_exec_cond(rule->cond, fe, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
				ret = acl_pass(ret);
				if (rule->cond->pol == ACL_COND_UNLESS)
					ret = !ret;
			}

			if (ret) {
				/* If the backend name is dynamic, try to resolve the name.
				 * If we can't resolve the name, or if any error occurs, break
				 * the loop and fallback to the default backend.
				 */
				struct proxy *backend = NULL;

				if (rule->dynamic) {
					struct chunk *tmp;

					tmp = alloc_trash_chunk();
					if (!tmp)
						goto sw_failed;

					if (build_logline(s, tmp->str, tmp->size, &rule->be.expr))
						backend = proxy_be_by_name(tmp->str);

					free_trash_chunk(tmp);
					tmp = NULL;

					if (!backend)
						break;
				}
				else
					backend = rule->be.backend;

				if (!stream_set_backend(s, backend))
					goto sw_failed;
				break;
			}
		}

		/* To ensure correct connection accounting on the backend, we
		 * have to assign one if it was not set (eg: a listen). This
		 * measure also takes care of correctly setting the default
		 * backend if any.
		 */
		if (!(s->flags & SF_BE_ASSIGNED))
			if (!stream_set_backend(s, fe->defbe.be ? fe->defbe.be : s->be))
				goto sw_failed;
	}

	/* we don't want to run the TCP or HTTP filters again if the backend has not changed */
	if (fe == s->be) {
		s->req.analysers &= ~AN_REQ_INSPECT_BE;
		s->req.analysers &= ~AN_REQ_HTTP_PROCESS_BE;
		s->req.analysers &= ~AN_REQ_FLT_START_BE;
	}

	/* as soon as we know the backend, we must check if we have a matching forced or ignored
	 * persistence rule, and report that in the stream.
	 */
	list_for_each_entry(prst_rule, &s->be->persist_rules, list) {
		int ret = 1;

		if (prst_rule->cond) {
	                ret = acl_exec_cond(prst_rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (prst_rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* no rule, or the rule matches */
			if (prst_rule->type == PERSIST_TYPE_FORCE) {
				s->flags |= SF_FORCE_PRST;
			} else {
				s->flags |= SF_IGNORE_PRST;
			}
			break;
		}
	}

	return 1;

 sw_failed:
	/* immediately abort this request in case of allocation failure */
	channel_abort(&s->req);
	channel_abort(&s->res);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_RESOURCE;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	if (s->txn)
		s->txn->status = 500;
	s->req.analysers &= AN_REQ_FLT_END;
	s->req.analyse_exp = TICK_ETERNITY;
	return 0;
}

/* This stream analyser works on a request. It applies all use-server rules on
 * it then returns 1. The data must already be present in the buffer otherwise
 * they won't match. It always returns 1.
 */
static int process_server_rules(struct stream *s, struct channel *req, int an_bit)
{
	struct proxy *px = s->be;
	struct session *sess = s->sess;
	struct server_rule *rule;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bl=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i + req->buf->o,
		req->analysers);

	if (!(s->flags & SF_ASSIGNED)) {
		list_for_each_entry(rule, &px->server_rules, list) {
			int ret;

			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				struct server *srv = rule->srv.ptr;

				if ((srv->cur_state != SRV_ST_STOPPED) ||
				    (px->options & PR_O_PERSIST) ||
				    (s->flags & SF_FORCE_PRST)) {
					s->flags |= SF_DIRECT | SF_ASSIGNED;
					s->target = &srv->obj_type;
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
static int process_sticking_rules(struct stream *s, struct channel *req, int an_bit)
{
	struct proxy    *px   = s->be;
	struct session *sess  = s->sess;
	struct sticking_rule  *rule;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	list_for_each_entry(rule, &px->sticking_rules, list) {
		int ret = 1 ;
		int i;

		/* Only the first stick store-request of each table is applied
		 * and other ones are ignored. The purpose is to allow complex
		 * configurations which look for multiple entries by decreasing
		 * order of precision and to stop at the first which matches.
		 * An example could be a store of the IP address from an HTTP
		 * header first, then from the source if not found.
		 */
		for (i = 0; i < s->store_count; i++) {
			if (rule->table.t == s->store[i].table)
				break;
		}

		if (i !=  s->store_count)
			continue;

		if (rule->cond) {
	                ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			struct stktable_key *key;

			key = stktable_fetch_key(rule->table.t, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->expr, NULL);
			if (!key)
				continue;

			if (rule->flags & STK_IS_MATCH) {
				struct stksess *ts;

				if ((ts = stktable_lookup_key(rule->table.t, key)) != NULL) {
					if (!(s->flags & SF_ASSIGNED)) {
						struct eb32_node *node;
						void *ptr;

						/* srv found in table */
						HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
						ptr = stktable_data_ptr(rule->table.t, ts, STKTABLE_DT_SERVER_ID);
						node = eb32_lookup(&px->conf.used_server_id, stktable_data_cast(ptr, server_id));
						HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
						if (node) {
							struct server *srv;

							srv = container_of(node, struct server, conf.id);
							if ((srv->cur_state != SRV_ST_STOPPED) ||
							    (px->options & PR_O_PERSIST) ||
							    (s->flags & SF_FORCE_PRST)) {
								s->flags |= SF_DIRECT | SF_ASSIGNED;
								s->target = &srv->obj_type;
							}
						}
					}
					stktable_touch_local(rule->table.t, ts, 1);
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
static int process_store_rules(struct stream *s, struct channel *rep, int an_bit)
{
	struct proxy    *px   = s->be;
	struct session *sess  = s->sess;
	struct sticking_rule  *rule;
	int i;
	int nbreq = s->store_count;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		rep->buf->i,
		rep->analysers);

	list_for_each_entry(rule, &px->storersp_rules, list) {
		int ret = 1 ;

		/* Only the first stick store-response of each table is applied
		 * and other ones are ignored. The purpose is to allow complex
		 * configurations which look for multiple entries by decreasing
		 * order of precision and to stop at the first which matches.
		 * An example could be a store of a set-cookie value, with a
		 * fallback to a parameter found in a 302 redirect.
		 *
		 * The store-response rules are not allowed to override the
		 * store-request rules for the same table, but they may coexist.
		 * Thus we can have up to one store-request entry and one store-
		 * response entry for the same table at any time.
		 */
		for (i = nbreq; i < s->store_count; i++) {
			if (rule->table.t == s->store[i].table)
				break;
		}

		/* skip existing entries for this table */
		if (i < s->store_count)
			continue;

		if (rule->cond) {
	                ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
	                ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			struct stktable_key *key;

			key = stktable_fetch_key(rule->table.t, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL, rule->expr, NULL);
			if (!key)
				continue;

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

	/* process store request and store response */
	for (i = 0; i < s->store_count; i++) {
		struct stksess *ts;
		void *ptr;

		if (objt_server(s->target) && objt_server(s->target)->flags & SRV_F_NON_STICK) {
			stksess_free(s->store[i].table, s->store[i].ts);
			s->store[i].ts = NULL;
			continue;
		}

		ts = stktable_set_entry(s->store[i].table, s->store[i].ts);
		if (ts != s->store[i].ts) {
			/* the entry already existed, we can free ours */
			stksess_free(s->store[i].table, s->store[i].ts);
		}
		s->store[i].ts = NULL;

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
		ptr = stktable_data_ptr(s->store[i].table, ts, STKTABLE_DT_SERVER_ID);
		stktable_data_cast(ptr, server_id) = objt_server(s->target)->puid;
		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
		stktable_touch_local(s->store[i].table, ts, 1);
	}
	s->store_count = 0; /* everything is stored */

	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This macro is very specific to the function below. See the comments in
 * process_stream() below to understand the logic and the tests.
 */
#define UPDATE_ANALYSERS(real, list, back, flag) {			\
		list = (((list) & ~(flag)) | ~(back)) & (real);		\
		back = real;						\
		if (!(list))						\
			break;						\
		if (((list) ^ ((list) & ((list) - 1))) < (flag))	\
			continue;					\
}

/* These 2 following macros call an analayzer for the specified channel if the
 * right flag is set. The first one is used for "filterable" analyzers. If a
 * stream has some registered filters, pre and post analyaze callbacks are
 * called. The second are used for other analyzers (AN_REQ/RES_FLT_* and
 * AN_REQ/RES_HTTP_XFER_BODY) */
#define FLT_ANALYZE(strm, chn, fun, list, back, flag, ...)			\
	{									\
		if ((list) & (flag)) {						\
			if (HAS_FILTERS(strm)) {			        \
				if (!flt_pre_analyze((strm), (chn), (flag)))    \
					break;				        \
				if (!fun((strm), (chn), (flag), ##__VA_ARGS__))	\
					break;					\
				if (!flt_post_analyze((strm), (chn), (flag)))	\
					break;					\
			}							\
			else {							\
				if (!fun((strm), (chn), (flag), ##__VA_ARGS__))	\
					break;					\
			}							\
			UPDATE_ANALYSERS((chn)->analysers, (list),		\
					 (back), (flag));			\
		}								\
	}

#define ANALYZE(strm, chn, fun, list, back, flag, ...)			\
	{								\
		if ((list) & (flag)) {					\
			if (!fun((strm), (chn), (flag), ##__VA_ARGS__))	\
				break;					\
			UPDATE_ANALYSERS((chn)->analysers, (list),	\
					 (back), (flag));		\
		}							\
	}

/* Processes the client, server, request and response jobs of a stream task,
 * then puts it back to the wait queue in a clean state, or cleans up its
 * resources if it must be deleted. Returns in <next> the date the task wants
 * to be woken up, or TICK_ETERNITY. In order not to call all functions for
 * nothing too many times, the request and response buffers flags are monitored
 * and each function is called only if at least another function has changed at
 * least one flag it is interested in.
 */
struct task *process_stream(struct task *t)
{
	struct server *srv;
	struct stream *s = t->context;
	struct session *sess = s->sess;
	unsigned int rqf_last, rpf_last;
	unsigned int rq_prod_last, rq_cons_last;
	unsigned int rp_cons_last, rp_prod_last;
	unsigned int req_ana_back;
	struct channel *req, *res;
	struct stream_interface *si_f, *si_b;

	req = &s->req;
	res = &s->res;

	si_f = &s->si[0];
	si_b = &s->si[1];

	//DPRINTF(stderr, "%s:%d: cs=%d ss=%d(%d) rqf=0x%08x rpf=0x%08x\n", __FUNCTION__, __LINE__,
	//        si_f->state, si_b->state, si_b->err_type, req->flags, res->flags);

	/* this data may be no longer valid, clear it */
	if (s->txn)
		memset(&s->txn->auth, 0, sizeof(s->txn->auth));

	/* This flag must explicitly be set every time */
	req->flags &= ~(CF_READ_NOEXP|CF_WAKE_WRITE);
	res->flags &= ~(CF_READ_NOEXP|CF_WAKE_WRITE);

	/* Keep a copy of req/rep flags so that we can detect shutdowns */
	rqf_last = req->flags & ~CF_MASK_ANALYSER;
	rpf_last = res->flags & ~CF_MASK_ANALYSER;

	/* we don't want the stream interface functions to recursively wake us up */
	si_f->flags |= SI_FL_DONT_WAKE;
	si_b->flags |= SI_FL_DONT_WAKE;

	/* update pending events */
	s->pending_events |= (t->state & TASK_WOKEN_ANY);

	/* 1a: Check for low level timeouts if needed. We just set a flag on
	 * stream interfaces when their timeouts have expired.
	 */
	if (unlikely(s->pending_events & TASK_WOKEN_TIMER)) {
		stream_int_check_timeouts(si_f);
		stream_int_check_timeouts(si_b);

		/* check channel timeouts, and close the corresponding stream interfaces
		 * for future reads or writes. Note: this will also concern upper layers
		 * but we do not touch any other flag. We must be careful and correctly
		 * detect state changes when calling them.
		 */

		channel_check_timeouts(req);

		if (unlikely((req->flags & (CF_SHUTW|CF_WRITE_TIMEOUT)) == CF_WRITE_TIMEOUT)) {
			si_b->flags |= SI_FL_NOLINGER;
			si_shutw(si_b);
		}

		if (unlikely((req->flags & (CF_SHUTR|CF_READ_TIMEOUT)) == CF_READ_TIMEOUT)) {
			if (si_f->flags & SI_FL_NOHALF)
				si_f->flags |= SI_FL_NOLINGER;
			si_shutr(si_f);
		}

		channel_check_timeouts(res);

		if (unlikely((res->flags & (CF_SHUTW|CF_WRITE_TIMEOUT)) == CF_WRITE_TIMEOUT)) {
			si_f->flags |= SI_FL_NOLINGER;
			si_shutw(si_f);
		}

		if (unlikely((res->flags & (CF_SHUTR|CF_READ_TIMEOUT)) == CF_READ_TIMEOUT)) {
			if (si_b->flags & SI_FL_NOHALF)
				si_b->flags |= SI_FL_NOLINGER;
			si_shutr(si_b);
		}

		if (HAS_FILTERS(s))
			flt_stream_check_timeouts(s);

		/* Once in a while we're woken up because the task expires. But
		 * this does not necessarily mean that a timeout has been reached.
		 * So let's not run a whole stream processing if only an expiration
		 * timeout needs to be refreshed.
		 */
		if (!((req->flags | res->flags) &
		      (CF_SHUTR|CF_READ_ACTIVITY|CF_READ_TIMEOUT|CF_SHUTW|
		       CF_WRITE_ACTIVITY|CF_WRITE_EVENT|CF_WRITE_TIMEOUT|CF_ANA_TIMEOUT)) &&
		    !((si_f->flags | si_b->flags) & (SI_FL_EXP|SI_FL_ERR)) &&
		    ((s->pending_events & TASK_WOKEN_ANY) == TASK_WOKEN_TIMER)) {
			si_f->flags &= ~SI_FL_DONT_WAKE;
			si_b->flags &= ~SI_FL_DONT_WAKE;
			goto update_exp_and_leave;
		}
	}

	/* below we may emit error messages so we have to ensure that we have
	 * our buffers properly allocated.
	 */
	if (!stream_alloc_work_buffer(s)) {
		/* No buffer available, we've been subscribed to the list of
		 * buffer waiters, let's wait for our turn.
		 */
		si_f->flags &= ~SI_FL_DONT_WAKE;
		si_b->flags &= ~SI_FL_DONT_WAKE;
		goto update_exp_and_leave;
	}

	/* 1b: check for low-level errors reported at the stream interface.
	 * First we check if it's a retryable error (in which case we don't
	 * want to tell the buffer). Otherwise we report the error one level
	 * upper by setting flags into the buffers. Note that the side towards
	 * the client cannot have connect (hence retryable) errors. Also, the
	 * connection setup code must be able to deal with any type of abort.
	 */
	srv = objt_server(s->target);
	if (unlikely(si_f->flags & SI_FL_ERR)) {
		if (si_f->state == SI_ST_EST || si_f->state == SI_ST_DIS) {
			si_shutr(si_f);
			si_shutw(si_f);
			stream_int_report_error(si_f);
			if (!(req->analysers) && !(res->analysers)) {
				HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.cli_aborts, 1);
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_CLICL;
				if (!(s->flags & SF_FINST_MASK))
					s->flags |= SF_FINST_D;
			}
		}
	}

	if (unlikely(si_b->flags & SI_FL_ERR)) {
		if (si_b->state == SI_ST_EST || si_b->state == SI_ST_DIS) {
			si_shutr(si_b);
			si_shutw(si_b);
			stream_int_report_error(si_b);
			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (srv)
				HA_ATOMIC_ADD(&srv->counters.failed_resp, 1);
			if (!(req->analysers) && !(res->analysers)) {
				HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.srv_aborts, 1);
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_SRVCL;
				if (!(s->flags & SF_FINST_MASK))
					s->flags |= SF_FINST_D;
			}
		}
		/* note: maybe we should process connection errors here ? */
	}

	if (si_b->state == SI_ST_CON) {
		/* we were trying to establish a connection on the server side,
		 * maybe it succeeded, maybe it failed, maybe we timed out, ...
		 */
		if (unlikely(!sess_update_st_con_tcp(s)))
			sess_update_st_cer(s);
		else if (si_b->state == SI_ST_EST)
			sess_establish(s);

		/* state is now one of SI_ST_CON (still in progress), SI_ST_EST
		 * (established), SI_ST_DIS (abort), SI_ST_CLO (last error),
		 * SI_ST_ASS/SI_ST_TAR/SI_ST_REQ for retryable errors.
		 */
	}

	rq_prod_last = si_f->state;
	rq_cons_last = si_b->state;
	rp_cons_last = si_f->state;
	rp_prod_last = si_b->state;

 resync_stream_interface:
	/* Check for connection closure */

	DPRINTF(stderr,
		"[%u] %s:%d: task=%p s=%p, sfl=0x%08x, rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d, cet=0x%x set=0x%x retr=%d\n",
		now_ms, __FUNCTION__, __LINE__,
		t,
		s, s->flags,
		req, res,
		req->rex, res->wex,
		req->flags, res->flags,
		req->buf->i, req->buf->o, res->buf->i, res->buf->o, si_f->state, si_b->state,
		si_f->err_type, si_b->err_type,
		si_b->conn_retries);

	/* nothing special to be done on client side */
	if (unlikely(si_f->state == SI_ST_DIS))
		si_f->state = SI_ST_CLO;

	/* When a server-side connection is released, we have to count it and
	 * check for pending connections on this server.
	 */
	if (unlikely(si_b->state == SI_ST_DIS)) {
		si_b->state = SI_ST_CLO;
		srv = objt_server(s->target);
		if (srv) {
			if (s->flags & SF_CURR_SESS) {
				s->flags &= ~SF_CURR_SESS;
				HA_ATOMIC_SUB(&srv->cur_sess, 1);
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
	if (((req->flags & ~rqf_last) & CF_MASK_ANALYSER) ||
	    ((req->flags ^ rqf_last) & CF_MASK_STATIC) ||
	    (req->analysers && (req->flags & CF_SHUTW)) ||
	    si_f->state != rq_prod_last ||
	    si_b->state != rq_cons_last ||
	    s->pending_events & TASK_WOKEN_MSG) {
		unsigned int flags = req->flags;

		if (si_f->state >= SI_ST_EST) {
			int max_loops = global.tune.maxpollevents;
			unsigned int ana_list;
			unsigned int ana_back;

			/* it's up to the analysers to stop new connections,
			 * disable reading or closing. Note: if an analyser
			 * disables any of these bits, it is responsible for
			 * enabling them again when it disables itself, so
			 * that other analysers are called in similar conditions.
			 */
			channel_auto_read(req);
			channel_auto_connect(req);
			channel_auto_close(req);

			/* We will call all analysers for which a bit is set in
			 * req->analysers, following the bit order from LSB
			 * to MSB. The analysers must remove themselves from
			 * the list when not needed. Any analyser may return 0
			 * to break out of the loop, either because of missing
			 * data to take a decision, or because it decides to
			 * kill the stream. We loop at least once through each
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

			ana_list = ana_back = req->analysers;
			while (ana_list && max_loops--) {
				/* Warning! ensure that analysers are always placed in ascending order! */
				ANALYZE    (s, req, flt_start_analyze,          ana_list, ana_back, AN_REQ_FLT_START_FE);
				FLT_ANALYZE(s, req, tcp_inspect_request,        ana_list, ana_back, AN_REQ_INSPECT_FE);
				FLT_ANALYZE(s, req, http_wait_for_request,      ana_list, ana_back, AN_REQ_WAIT_HTTP);
				FLT_ANALYZE(s, req, http_wait_for_request_body, ana_list, ana_back, AN_REQ_HTTP_BODY);
				FLT_ANALYZE(s, req, http_process_req_common,    ana_list, ana_back, AN_REQ_HTTP_PROCESS_FE, sess->fe);
				FLT_ANALYZE(s, req, process_switching_rules,    ana_list, ana_back, AN_REQ_SWITCHING_RULES);
				ANALYZE    (s, req, flt_start_analyze,          ana_list, ana_back, AN_REQ_FLT_START_BE);
				FLT_ANALYZE(s, req, tcp_inspect_request,        ana_list, ana_back, AN_REQ_INSPECT_BE);
				FLT_ANALYZE(s, req, http_process_req_common,    ana_list, ana_back, AN_REQ_HTTP_PROCESS_BE, s->be);
				FLT_ANALYZE(s, req, http_process_tarpit,        ana_list, ana_back, AN_REQ_HTTP_TARPIT);
				FLT_ANALYZE(s, req, process_server_rules,       ana_list, ana_back, AN_REQ_SRV_RULES);
				FLT_ANALYZE(s, req, http_process_request,       ana_list, ana_back, AN_REQ_HTTP_INNER);
				FLT_ANALYZE(s, req, tcp_persist_rdp_cookie,     ana_list, ana_back, AN_REQ_PRST_RDP_COOKIE);
				FLT_ANALYZE(s, req, process_sticking_rules,     ana_list, ana_back, AN_REQ_STICKING_RULES);
				ANALYZE    (s, req, flt_analyze_http_headers,   ana_list, ana_back, AN_REQ_FLT_HTTP_HDRS);
				ANALYZE    (s, req, http_request_forward_body,  ana_list, ana_back, AN_REQ_HTTP_XFER_BODY);
				ANALYZE    (s, req, flt_xfer_data,              ana_list, ana_back, AN_REQ_FLT_XFER_DATA);
				ANALYZE    (s, req, flt_end_analyze,            ana_list, ana_back, AN_REQ_FLT_END);
				break;
			}
		}

		rq_prod_last = si_f->state;
		rq_cons_last = si_b->state;
		req->flags &= ~CF_WAKE_ONCE;
		rqf_last = req->flags;

		if ((req->flags ^ flags) & CF_MASK_STATIC)
			goto resync_request;
	}

	/* we'll monitor the request analysers while parsing the response,
	 * because some response analysers may indirectly enable new request
	 * analysers (eg: HTTP keep-alive).
	 */
	req_ana_back = req->analysers;

 resync_response:
	/* Analyse response */

	if (((res->flags & ~rpf_last) & CF_MASK_ANALYSER) ||
		 (res->flags ^ rpf_last) & CF_MASK_STATIC ||
		 (res->analysers && (res->flags & CF_SHUTW)) ||
		 si_f->state != rp_cons_last ||
		 si_b->state != rp_prod_last ||
		 s->pending_events & TASK_WOKEN_MSG) {
		unsigned int flags = res->flags;

		if (si_b->state >= SI_ST_EST) {
			int max_loops = global.tune.maxpollevents;
			unsigned int ana_list;
			unsigned int ana_back;

			/* it's up to the analysers to stop disable reading or
			 * closing. Note: if an analyser disables any of these
			 * bits, it is responsible for enabling them again when
			 * it disables itself, so that other analysers are called
			 * in similar conditions.
			 */
			channel_auto_read(res);
			channel_auto_close(res);

			/* We will call all analysers for which a bit is set in
			 * res->analysers, following the bit order from LSB
			 * to MSB. The analysers must remove themselves from
			 * the list when not needed. Any analyser may return 0
			 * to break out of the loop, either because of missing
			 * data to take a decision, or because it decides to
			 * kill the stream. We loop at least once through each
			 * analyser, and we may loop again if other analysers
			 * are added in the middle.
			 */

			ana_list = ana_back = res->analysers;
			while (ana_list && max_loops--) {
				/* Warning! ensure that analysers are always placed in ascending order! */
				ANALYZE    (s, res, flt_start_analyze,          ana_list, ana_back, AN_RES_FLT_START_FE);
				ANALYZE    (s, res, flt_start_analyze,          ana_list, ana_back, AN_RES_FLT_START_BE);
				FLT_ANALYZE(s, res, tcp_inspect_response,       ana_list, ana_back, AN_RES_INSPECT);
				FLT_ANALYZE(s, res, http_wait_for_response,     ana_list, ana_back, AN_RES_WAIT_HTTP);
				FLT_ANALYZE(s, res, process_store_rules,        ana_list, ana_back, AN_RES_STORE_RULES);
				FLT_ANALYZE(s, res, http_process_res_common,    ana_list, ana_back, AN_RES_HTTP_PROCESS_BE, s->be);
				ANALYZE    (s, res, flt_analyze_http_headers,   ana_list, ana_back, AN_RES_FLT_HTTP_HDRS);
				ANALYZE    (s, res, http_response_forward_body, ana_list, ana_back, AN_RES_HTTP_XFER_BODY);
				ANALYZE    (s, res, flt_xfer_data,              ana_list, ana_back, AN_RES_FLT_XFER_DATA);
				ANALYZE    (s, res, flt_end_analyze,            ana_list, ana_back, AN_RES_FLT_END);
				break;
			}
		}

		rp_cons_last = si_f->state;
		rp_prod_last = si_b->state;
		res->flags &= ~CF_WAKE_ONCE;
		rpf_last = res->flags;

		if ((res->flags ^ flags) & CF_MASK_STATIC)
			goto resync_response;
	}

	/* maybe someone has added some request analysers, so we must check and loop */
	if (req->analysers & ~req_ana_back)
		goto resync_request;

	if ((req->flags & ~rqf_last) & CF_MASK_ANALYSER)
		goto resync_request;

	/* FIXME: here we should call protocol handlers which rely on
	 * both buffers.
	 */


	/*
	 * Now we propagate unhandled errors to the stream. Normally
	 * we're just in a data phase here since it means we have not
	 * seen any analyser who could set an error status.
	 */
	srv = objt_server(s->target);
	if (unlikely(!(s->flags & SF_ERR_MASK))) {
		if (req->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) {
			/* Report it if the client got an error or a read timeout expired */
			req->analysers = 0;
			if (req->flags & CF_READ_ERROR) {
				HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.cli_aborts, 1);
				s->flags |= SF_ERR_CLICL;
			}
			else if (req->flags & CF_READ_TIMEOUT) {
				HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.cli_aborts, 1);
				s->flags |= SF_ERR_CLITO;
			}
			else if (req->flags & CF_WRITE_ERROR) {
				HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.srv_aborts, 1);
				s->flags |= SF_ERR_SRVCL;
			}
			else {
				HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.srv_aborts, 1);
				s->flags |= SF_ERR_SRVTO;
			}
			sess_set_term_flags(s);
		}
		else if (res->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) {
			/* Report it if the server got an error or a read timeout expired */
			res->analysers = 0;
			if (res->flags & CF_READ_ERROR) {
				HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.srv_aborts, 1);
				s->flags |= SF_ERR_SRVCL;
			}
			else if (res->flags & CF_READ_TIMEOUT) {
				HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.srv_aborts, 1);
				s->flags |= SF_ERR_SRVTO;
			}
			else if (res->flags & CF_WRITE_ERROR) {
				HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.cli_aborts, 1);
				s->flags |= SF_ERR_CLICL;
			}
			else {
				HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
				HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
				if (srv)
					HA_ATOMIC_ADD(&srv->counters.cli_aborts, 1);
				s->flags |= SF_ERR_CLITO;
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
	 * Note that we're checking CF_SHUTR_NOW as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely((!req->analysers || (req->analysers == AN_REQ_FLT_END && !(req->flags & CF_FLT_ANALYZE))) &&
	    !(req->flags & (CF_SHUTW|CF_SHUTR_NOW)) &&
	    (si_f->state >= SI_ST_EST) &&
	    (req->to_forward != CHN_INFINITE_FORWARD))) {
		/* This buffer is freewheeling, there's no analyser
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		channel_auto_read(req);
		channel_auto_connect(req);
		channel_auto_close(req);
		buffer_flush(req->buf);

		/* We'll let data flow between the producer (if still connected)
		 * to the consumer (which might possibly not be connected yet).
		 */
		if (!(req->flags & (CF_SHUTR|CF_SHUTW_NOW)))
			channel_forward_forever(req);

		/* Just in order to support fetching HTTP contents after start
		 * of forwarding when the HTTP forwarding analyser is not used,
		 * we simply reset msg->sov so that HTTP rewinding points to the
		 * headers.
		 */
		if (s->txn)
			s->txn->req.sov = s->txn->req.eoh + s->txn->req.eol - req->buf->o;
	}

	/* check if it is wise to enable kernel splicing to forward request data */
	if (!(req->flags & (CF_KERN_SPLICING|CF_SHUTR)) &&
	    req->to_forward &&
	    (global.tune.options & GTUNE_USE_SPLICE) &&
	    (objt_cs(si_f->end) && __objt_cs(si_f->end)->conn->xprt && __objt_cs(si_f->end)->conn->xprt->rcv_pipe) &&
	    (objt_cs(si_b->end) && __objt_cs(si_b->end)->conn->xprt && __objt_cs(si_b->end)->conn->xprt->snd_pipe) &&
	    (pipes_used < global.maxpipes) &&
	    (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_REQ) ||
	     (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (req->flags & CF_STREAMER_FAST)))) {
		req->flags |= CF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rqf_last = req->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/* first, let's check if the request buffer needs to shutdown(write), which may
	 * happen either because the input is closed or because we want to force a close
	 * once the server has begun to respond. If a half-closed timeout is set, we adjust
	 * the other side's timeout as well.
	 */
	if (unlikely((req->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_AUTO_CLOSE|CF_SHUTR)) ==
		     (CF_AUTO_CLOSE|CF_SHUTR))) {
		channel_shutw_now(req);
	}

	/* shutdown(write) pending */
	if (unlikely((req->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW &&
		     channel_is_empty(req))) {
		if (req->flags & CF_READ_ERROR)
			si_b->flags |= SI_FL_NOLINGER;
		si_shutw(si_b);
	}

	/* shutdown(write) done on server side, we must stop the client too */
	if (unlikely((req->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTW &&
		     !req->analysers))
		channel_shutr_now(req);

	/* shutdown(read) pending */
	if (unlikely((req->flags & (CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTR_NOW)) {
		if (si_f->flags & SI_FL_NOHALF)
			si_f->flags |= SI_FL_NOLINGER;
		si_shutr(si_f);
	}

	/* it's possible that an upper layer has requested a connection setup or abort.
	 * There are 2 situations where we decide to establish a new connection :
	 *  - there are data scheduled for emission in the buffer
	 *  - the CF_AUTO_CONNECT flag is set (active connection)
	 */
	if (si_b->state == SI_ST_INI) {
		if (!(req->flags & CF_SHUTW)) {
			if ((req->flags & CF_AUTO_CONNECT) || !channel_is_empty(req)) {
				/* If we have an appctx, there is no connect method, so we
				 * immediately switch to the connected state, otherwise we
				 * perform a connection request.
				 */
				si_b->state = SI_ST_REQ; /* new connection requested */
				si_b->conn_retries = s->be->conn_retries;
			}
		}
		else {
			si_release_endpoint(si_b);
			si_b->state = SI_ST_CLO; /* shutw+ini = abort */
			channel_shutw_now(req);        /* fix buffer flags upon abort */
			channel_shutr_now(res);
		}
	}


	/* we may have a pending connection request, or a connection waiting
	 * for completion.
	 */
	if (si_b->state >= SI_ST_REQ && si_b->state < SI_ST_CON) {

		/* prune the request variables and swap to the response variables. */
		if (s->vars_reqres.scope != SCOPE_RES) {
			vars_prune(&s->vars_reqres, s->sess, s);
			vars_init(&s->vars_reqres, SCOPE_RES);
		}

		do {
			/* nb: step 1 might switch from QUE to ASS, but we first want
			 * to give a chance to step 2 to perform a redirect if needed.
			 */
			if (si_b->state != SI_ST_REQ)
				sess_update_stream_int(s);
			if (si_b->state == SI_ST_REQ)
				sess_prepare_conn_req(s);

			/* applets directly go to the ESTABLISHED state. Similarly,
			 * servers experience the same fate when their connection
			 * is reused.
			 */
			if (unlikely(si_b->state == SI_ST_EST))
				sess_establish(s);

			/* Now we can add the server name to a header (if requested) */
			/* check for HTTP mode and proxy server_name_hdr_name != NULL */
			if ((si_b->state >= SI_ST_CON) && (si_b->state < SI_ST_CLO) &&
			    (s->be->server_id_hdr_name != NULL) &&
			    (s->be->mode == PR_MODE_HTTP) &&
			    objt_server(s->target)) {
				http_send_name_header(s->txn, s->be, objt_server(s->target)->id);
			}

			srv = objt_server(s->target);
			if (si_b->state == SI_ST_ASS && srv && srv->rdr_len && (s->flags & SF_REDIRECTABLE))
				http_perform_server_redirect(s, si_b);
		} while (si_b->state == SI_ST_ASS);
	}

	/* Benchmarks have shown that it's optimal to do a full resync now */
	if (si_f->state == SI_ST_DIS || si_b->state == SI_ST_DIS)
		goto resync_stream_interface;

	/* otherwise we want to check if we need to resync the req buffer or not */
	if ((req->flags ^ rqf_last) & CF_MASK_STATIC)
		goto resync_request;

	/* perform output updates to the response buffer */

	/* If noone is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking CF_SHUTR_NOW as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely((!res->analysers || (res->analysers == AN_RES_FLT_END && !(res->flags & CF_FLT_ANALYZE))) &&
	    !(res->flags & (CF_SHUTW|CF_SHUTR_NOW)) &&
	    (si_b->state >= SI_ST_EST) &&
	    (res->to_forward != CHN_INFINITE_FORWARD))) {
		/* This buffer is freewheeling, there's no analyser
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		channel_auto_read(res);
		channel_auto_close(res);
		buffer_flush(res->buf);

		/* We'll let data flow between the producer (if still connected)
		 * to the consumer.
		 */
		if (!(res->flags & (CF_SHUTR|CF_SHUTW_NOW)))
			channel_forward_forever(res);

		/* Just in order to support fetching HTTP contents after start
		 * of forwarding when the HTTP forwarding analyser is not used,
		 * we simply reset msg->sov so that HTTP rewinding points to the
		 * headers.
		 */
		if (s->txn)
			s->txn->rsp.sov = s->txn->rsp.eoh + s->txn->rsp.eol - res->buf->o;

		/* if we have no analyser anymore in any direction and have a
		 * tunnel timeout set, use it now. Note that we must respect
		 * the half-closed timeouts as well.
		 */
		if (!req->analysers && s->be->timeout.tunnel) {
			req->rto = req->wto = res->rto = res->wto =
				s->be->timeout.tunnel;

			if ((req->flags & CF_SHUTR) && tick_isset(sess->fe->timeout.clientfin))
				res->wto = sess->fe->timeout.clientfin;
			if ((req->flags & CF_SHUTW) && tick_isset(s->be->timeout.serverfin))
				res->rto = s->be->timeout.serverfin;
			if ((res->flags & CF_SHUTR) && tick_isset(s->be->timeout.serverfin))
				req->wto = s->be->timeout.serverfin;
			if ((res->flags & CF_SHUTW) && tick_isset(sess->fe->timeout.clientfin))
				req->rto = sess->fe->timeout.clientfin;

			req->rex = tick_add(now_ms, req->rto);
			req->wex = tick_add(now_ms, req->wto);
			res->rex = tick_add(now_ms, res->rto);
			res->wex = tick_add(now_ms, res->wto);
		}
	}

	/* check if it is wise to enable kernel splicing to forward response data */
	if (!(res->flags & (CF_KERN_SPLICING|CF_SHUTR)) &&
	    res->to_forward &&
	    (global.tune.options & GTUNE_USE_SPLICE) &&
	    (objt_cs(si_f->end) && __objt_cs(si_f->end)->conn->xprt && __objt_cs(si_f->end)->conn->xprt->snd_pipe) &&
	    (objt_cs(si_b->end) && __objt_cs(si_b->end)->conn->xprt && __objt_cs(si_b->end)->conn->xprt->rcv_pipe) &&
	    (pipes_used < global.maxpipes) &&
	    (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_RTR) ||
	     (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (res->flags & CF_STREAMER_FAST)))) {
		res->flags |= CF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rpf_last = res->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/*
	 * FIXME: this is probably where we should produce error responses.
	 */

	/* first, let's check if the response buffer needs to shutdown(write) */
	if (unlikely((res->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_AUTO_CLOSE|CF_SHUTR)) ==
		     (CF_AUTO_CLOSE|CF_SHUTR))) {
		channel_shutw_now(res);
	}

	/* shutdown(write) pending */
	if (unlikely((res->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW &&
		     channel_is_empty(res))) {
		si_shutw(si_f);
	}

	/* shutdown(write) done on the client side, we must stop the server too */
	if (unlikely((res->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTW) &&
	    !res->analysers)
		channel_shutr_now(res);

	/* shutdown(read) pending */
	if (unlikely((res->flags & (CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTR_NOW)) {
		if (si_b->flags & SI_FL_NOHALF)
			si_b->flags |= SI_FL_NOLINGER;
		si_shutr(si_b);
	}

	if (si_f->state == SI_ST_DIS || si_b->state == SI_ST_DIS)
		goto resync_stream_interface;

	if (req->flags != rqf_last)
		goto resync_request;

	if ((res->flags ^ rpf_last) & CF_MASK_STATIC)
		goto resync_response;

	/* we're interested in getting wakeups again */
	si_f->flags &= ~SI_FL_DONT_WAKE;
	si_b->flags &= ~SI_FL_DONT_WAKE;

	/* This is needed only when debugging is enabled, to indicate
	 * client-side or server-side close. Please note that in the unlikely
	 * event where both sides would close at once, the sequence is reported
	 * on the server side first.
	 */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) ||
		      (global.mode & MODE_VERBOSE)))) {
		if (si_b->state == SI_ST_CLO &&
		    si_b->prev_state == SI_ST_EST) {
			chunk_printf(&trash, "%08x:%s.srvcls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
			              objt_cs(si_f->end) ? (unsigned short)objt_cs(si_f->end)->conn->handle.fd : -1,
			              objt_cs(si_b->end) ? (unsigned short)objt_cs(si_b->end)->conn->handle.fd : -1);
			shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
		}

		if (si_f->state == SI_ST_CLO &&
		    si_f->prev_state == SI_ST_EST) {
			chunk_printf(&trash, "%08x:%s.clicls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
			              objt_cs(si_f->end) ? (unsigned short)objt_cs(si_f->end)->conn->handle.fd : -1,
			              objt_cs(si_b->end) ? (unsigned short)objt_cs(si_b->end)->conn->handle.fd : -1);
			shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
		}
	}

	if (likely((si_f->state != SI_ST_CLO) ||
		   (si_b->state > SI_ST_INI && si_b->state < SI_ST_CLO))) {

		if ((sess->fe->options & PR_O_CONTSTATS) && (s->flags & SF_BE_ASSIGNED))
			stream_process_counters(s);

		if (si_f->state == SI_ST_EST)
			si_update(si_f);

		if (si_b->state == SI_ST_EST)
			si_update(si_b);

		req->flags &= ~(CF_READ_NULL|CF_READ_PARTIAL|CF_WRITE_NULL|CF_WRITE_PARTIAL|CF_READ_ATTACHED|CF_WRITE_EVENT);
		res->flags &= ~(CF_READ_NULL|CF_READ_PARTIAL|CF_WRITE_NULL|CF_WRITE_PARTIAL|CF_READ_ATTACHED|CF_WRITE_EVENT);
		si_f->prev_state = si_f->state;
		si_b->prev_state = si_b->state;
		si_f->flags &= ~(SI_FL_ERR|SI_FL_EXP);
		si_b->flags &= ~(SI_FL_ERR|SI_FL_EXP);

		/* Trick: if a request is being waiting for the server to respond,
		 * and if we know the server can timeout, we don't want the timeout
		 * to expire on the client side first, but we're still interested
		 * in passing data from the client to the server (eg: POST). Thus,
		 * we can cancel the client's request timeout if the server's
		 * request timeout is set and the server has not yet sent a response.
		 */

		if ((res->flags & (CF_AUTO_CLOSE|CF_SHUTR)) == 0 &&
		    (tick_isset(req->wex) || tick_isset(res->rex))) {
			req->flags |= CF_READ_NOEXP;
			req->rex = TICK_ETERNITY;
		}

		/* Reset pending events now */
		s->pending_events = 0;

	update_exp_and_leave:
		/* Note: please ensure that if you branch here you disable SI_FL_DONT_WAKE */
		t->expire = tick_first((tick_is_expired(t->expire, now_ms) ? 0 : t->expire),
				       tick_first(tick_first(req->rex, req->wex),
						  tick_first(res->rex, res->wex)));
		if (!req->analysers)
			req->analyse_exp = TICK_ETERNITY;

		if ((sess->fe->options & PR_O_CONTSTATS) && (s->flags & SF_BE_ASSIGNED) &&
		          (!tick_isset(req->analyse_exp) || tick_is_expired(req->analyse_exp, now_ms)))
			req->analyse_exp = tick_add(now_ms, 5000);

		t->expire = tick_first(t->expire, req->analyse_exp);

		t->expire = tick_first(t->expire, res->analyse_exp);

		if (si_f->exp)
			t->expire = tick_first(t->expire, si_f->exp);

		if (si_b->exp)
			t->expire = tick_first(t->expire, si_b->exp);

		DPRINTF(stderr,
			"[%u] queuing with exp=%u req->rex=%u req->wex=%u req->ana_exp=%u"
			" rep->rex=%u rep->wex=%u, si[0].exp=%u, si[1].exp=%u, cs=%d, ss=%d\n",
			now_ms, t->expire, req->rex, req->wex, req->analyse_exp,
			res->rex, res->wex, si_f->exp, si_b->exp, si_f->state, si_b->state);

#ifdef DEBUG_DEV
		/* this may only happen when no timeout is set or in case of an FSM bug */
		if (!tick_isset(t->expire))
			ABORT_NOW();
#endif
		s->pending_events &= ~(TASK_WOKEN_TIMER | TASK_WOKEN_RES);
		stream_release_buffers(s);
		return t; /* nothing more to do */
	}

	if (s->flags & SF_BE_ASSIGNED)
		HA_ATOMIC_SUB(&s->be->beconn, 1);

	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		chunk_printf(&trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->id,
		              objt_cs(si_f->end) ? (unsigned short)objt_cs(si_f->end)->conn->handle.fd : -1,
		              objt_cs(si_b->end) ? (unsigned short)objt_cs(si_b->end)->conn->handle.fd : -1);
		shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	stream_process_counters(s);

	if (s->txn && s->txn->status) {
		int n;

		n = s->txn->status / 100;
		if (n < 1 || n > 5)
			n = 0;

		if (sess->fe->mode == PR_MODE_HTTP) {
			HA_ATOMIC_ADD(&sess->fe->fe_counters.p.http.rsp[n], 1);
		}
		if ((s->flags & SF_BE_ASSIGNED) &&
		    (s->be->mode == PR_MODE_HTTP)) {
			HA_ATOMIC_ADD(&s->be->be_counters.p.http.rsp[n], 1);
			HA_ATOMIC_ADD(&s->be->be_counters.p.http.cum_req, 1);
		}
	}

	/* let's do a final log if we need it */
	if (!LIST_ISEMPTY(&sess->fe->logformat) && s->logs.logwait &&
	    !(s->flags & SF_MONITOR) &&
	    (!(sess->fe->options & PR_O_NULLNOLOG) || req->total)) {
		s->do_log(s);
	}

	/* update time stats for this stream */
	stream_update_time_stats(s);

	/* the task MUST not be in the run queue anymore */
	stream_free(s);
	task_delete(t);
	task_free(t);
	return NULL;
}

/* Update the stream's backend and server time stats */
void stream_update_time_stats(struct stream *s)
{
	int t_request;
	int t_queue;
	int t_connect;
	int t_data;
	int t_close;
	struct server *srv;

	t_request = 0;
	t_queue   = s->logs.t_queue;
	t_connect = s->logs.t_connect;
	t_close   = s->logs.t_close;
	t_data    = s->logs.t_data;

	if (s->be->mode != PR_MODE_HTTP)
		t_data = t_connect;

	if (t_connect < 0 || t_data < 0)
		return;

	if (tv_isge(&s->logs.tv_request, &s->logs.tv_accept))
		t_request = tv_ms_elapsed(&s->logs.tv_accept, &s->logs.tv_request);

	t_data    -= t_connect;
	t_connect -= t_queue;
	t_queue   -= t_request;

	srv = objt_server(s->target);
	if (srv) {
		swrate_add(&srv->counters.q_time, TIME_STATS_SAMPLES, t_queue);
		swrate_add(&srv->counters.c_time, TIME_STATS_SAMPLES, t_connect);
		swrate_add(&srv->counters.d_time, TIME_STATS_SAMPLES, t_data);
		swrate_add(&srv->counters.t_time, TIME_STATS_SAMPLES, t_close);
	}
	HA_SPIN_LOCK(PROXY_LOCK, &s->be->lock);
	swrate_add(&s->be->be_counters.q_time, TIME_STATS_SAMPLES, t_queue);
	swrate_add(&s->be->be_counters.c_time, TIME_STATS_SAMPLES, t_connect);
	swrate_add(&s->be->be_counters.d_time, TIME_STATS_SAMPLES, t_data);
	swrate_add(&s->be->be_counters.t_time, TIME_STATS_SAMPLES, t_close);
	HA_SPIN_UNLOCK(PROXY_LOCK, &s->be->lock);
}

/*
 * This function adjusts sess->srv_conn and maintains the previous and new
 * server's served stream counts. Setting newsrv to NULL is enough to release
 * current connection slot. This function also notifies any LB algo which might
 * expect to be informed about any change in the number of active streams on a
 * server.
 */
void sess_change_server(struct stream *sess, struct server *newsrv)
{
	if (sess->srv_conn == newsrv)
		return;

	if (sess->srv_conn) {
		HA_ATOMIC_SUB(&sess->srv_conn->served, 1);
		HA_ATOMIC_SUB(&sess->srv_conn->proxy->served, 1);
		if (sess->srv_conn->proxy->lbprm.server_drop_conn)
			sess->srv_conn->proxy->lbprm.server_drop_conn(sess->srv_conn);
		stream_del_srv_conn(sess);
	}

	if (newsrv) {
		HA_ATOMIC_ADD(&newsrv->served, 1);
		HA_ATOMIC_ADD(&newsrv->proxy->served, 1);
		if (newsrv->proxy->lbprm.server_take_conn)
			newsrv->proxy->lbprm.server_take_conn(newsrv);
		stream_add_srv_conn(sess, newsrv);
	}
}

/* Handle server-side errors for default protocols. It is called whenever a a
 * connection setup is aborted or a request is aborted in queue. It sets the
 * stream termination flags so that the caller does not have to worry about
 * them. It's installed as ->srv_error for the server-side stream_interface.
 */
void default_srv_error(struct stream *s, struct stream_interface *si)
{
	int err_type = si->err_type;
	int err = 0, fin = 0;

	if (err_type & SI_ET_QUEUE_ABRT) {
		err = SF_ERR_CLICL;
		fin = SF_FINST_Q;
	}
	else if (err_type & SI_ET_CONN_ABRT) {
		err = SF_ERR_CLICL;
		fin = SF_FINST_C;
	}
	else if (err_type & SI_ET_QUEUE_TO) {
		err = SF_ERR_SRVTO;
		fin = SF_FINST_Q;
	}
	else if (err_type & SI_ET_QUEUE_ERR) {
		err = SF_ERR_SRVCL;
		fin = SF_FINST_Q;
	}
	else if (err_type & SI_ET_CONN_TO) {
		err = SF_ERR_SRVTO;
		fin = SF_FINST_C;
	}
	else if (err_type & SI_ET_CONN_ERR) {
		err = SF_ERR_SRVCL;
		fin = SF_FINST_C;
	}
	else if (err_type & SI_ET_CONN_RES) {
		err = SF_ERR_RESOURCE;
		fin = SF_FINST_C;
	}
	else /* SI_ET_CONN_OTHER and others */ {
		err = SF_ERR_INTERNAL;
		fin = SF_FINST_C;
	}

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= fin;
}

/* kill a stream and set the termination flags to <why> (one of SF_ERR_*) */
void stream_shutdown(struct stream *stream, int why)
{
	if (stream->req.flags & (CF_SHUTW|CF_SHUTW_NOW))
		return;

	channel_shutw_now(&stream->req);
	channel_shutr_now(&stream->res);
	stream->task->nice = 1024;
	if (!(stream->flags & SF_ERR_MASK))
		stream->flags |= why;
	task_wakeup(stream->task, TASK_WOKEN_OTHER);
}

/************************************************************************/
/*           All supported ACL keywords must be declared here.          */
/************************************************************************/

/* 0=OK, <0=Alert, >0=Warning */
static enum act_parse_ret stream_parse_use_service(const char **args, int *cur_arg,
                                                   struct proxy *px, struct act_rule *rule,
                                                   char **err)
{
	struct action_kw *kw;

	/* Check if the service name exists. */
	if (*(args[*cur_arg]) == 0) {
		memprintf(err, "'%s' expects a service name.", args[0]);
		return ACT_RET_PRS_ERR;
	}

	/* lookup for keyword corresponding to a service. */
	kw = action_lookup(&service_keywords, args[*cur_arg]);
	if (!kw) {
		memprintf(err, "'%s' unknown service name.", args[1]);
		return ACT_RET_PRS_ERR;
	}
	(*cur_arg)++;

	/* executes specific rule parser. */
	rule->kw = kw;
	if (kw->parse((const char **)args, cur_arg, px, rule, err) == ACT_RET_PRS_ERR)
		return ACT_RET_PRS_ERR;

	/* Register processing function. */
	rule->action_ptr = process_use_service;
	rule->action = ACT_CUSTOM;

	return ACT_RET_PRS_OK;
}

void service_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&service_keywords, &kw_list->list);
}


/* This function dumps a complete stream state onto the stream interface's
 * read buffer. The stream has to be set in strm. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero. It is
 * designed to be called from stats_dump_strm_to_buffer() below.
 */
static int stats_dump_full_strm_to_buffer(struct stream_interface *si, struct stream *strm)
{
	struct appctx *appctx = __objt_appctx(si->end);
	struct tm tm;
	extern const char *monthname[12];
	char pn[INET6_ADDRSTRLEN];
	struct conn_stream *cs;
	struct connection *conn;
	struct appctx *tmpctx;

	chunk_reset(&trash);

	if (appctx->ctx.sess.section > 0 && appctx->ctx.sess.uid != strm->uniq_id) {
		/* stream changed, no need to go any further */
		chunk_appendf(&trash, "  *** session terminated while we were watching it ***\n");
		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_applet_cant_put(si);
			return 0;
		}
		appctx->ctx.sess.uid = 0;
		appctx->ctx.sess.section = 0;
		return 1;
	}

	switch (appctx->ctx.sess.section) {
	case 0: /* main status of the stream */
		appctx->ctx.sess.uid = strm->uniq_id;
		appctx->ctx.sess.section = 1;
		/* fall through */

	case 1:
		get_localtime(strm->logs.accept_date.tv_sec, &tm);
		chunk_appendf(&trash,
			     "%p: [%02d/%s/%04d:%02d:%02d:%02d.%06d] id=%u proto=%s",
			     strm,
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(strm->logs.accept_date.tv_usec),
			     strm->uniq_id,
			     strm_li(strm) ? strm_li(strm)->proto->name : "?");

		conn = objt_conn(strm_orig(strm));
		switch (conn ? addr_to_str(&conn->addr.from, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " source=%s:%d\n",
			              pn, get_host_port(&conn->addr.from));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " source=unix:%d\n", strm_li(strm)->luid);
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		chunk_appendf(&trash,
			     "  flags=0x%x, conn_retries=%d, srv_conn=%p, pend_pos=%p\n",
			     strm->flags, strm->si[1].conn_retries, strm->srv_conn, strm->pend_pos);

		chunk_appendf(&trash,
			     "  frontend=%s (id=%u mode=%s), listener=%s (id=%u)",
			     strm_fe(strm)->id, strm_fe(strm)->uuid, strm_fe(strm)->mode ? "http" : "tcp",
			     strm_li(strm) ? strm_li(strm)->name ? strm_li(strm)->name : "?" : "?",
			     strm_li(strm) ? strm_li(strm)->luid : 0);

		if (conn)
			conn_get_to_addr(conn);

		switch (conn ? addr_to_str(&conn->addr.to, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(&conn->addr.to));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " addr=unix:%d\n", strm_li(strm)->luid);
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		if (strm->be->cap & PR_CAP_BE)
			chunk_appendf(&trash,
				     "  backend=%s (id=%u mode=%s)",
				     strm->be->id,
				     strm->be->uuid, strm->be->mode ? "http" : "tcp");
		else
			chunk_appendf(&trash, "  backend=<NONE> (id=-1 mode=-)");

		cs = objt_cs(strm->si[1].end);
		conn = cs_conn(cs);

		if (conn)
			conn_get_from_addr(conn);

		switch (conn ? addr_to_str(&conn->addr.from, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(&conn->addr.from));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " addr=unix\n");
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		if (strm->be->cap & PR_CAP_BE)
			chunk_appendf(&trash,
				     "  server=%s (id=%u)",
				     objt_server(strm->target) ? objt_server(strm->target)->id : "<none>",
				     objt_server(strm->target) ? objt_server(strm->target)->puid : 0);
		else
			chunk_appendf(&trash, "  server=<NONE> (id=-1)");

		if (conn)
			conn_get_to_addr(conn);

		switch (conn ? addr_to_str(&conn->addr.to, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(&conn->addr.to));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " addr=unix\n");
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		chunk_appendf(&trash,
			     "  task=%p (state=0x%02x nice=%d calls=%d exp=%s tmask=0x%lx%s",
			     strm->task,
			     strm->task->state,
			     strm->task->nice, strm->task->calls,
			     strm->task->expire ?
			             tick_is_expired(strm->task->expire, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(strm->task->expire - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     strm->task->thread_mask,
			     task_in_rq(strm->task) ? ", running" : "");

		chunk_appendf(&trash,
			     " age=%s)\n",
			     human_time(now.tv_sec - strm->logs.accept_date.tv_sec, 1));

		if (strm->txn)
			chunk_appendf(&trash,
			     "  txn=%p flags=0x%x meth=%d status=%d req.st=%s rsp.st=%s waiting=%d\n",
			      strm->txn, strm->txn->flags, strm->txn->meth, strm->txn->status,
			      h1_msg_state_str(strm->txn->req.msg_state), h1_msg_state_str(strm->txn->rsp.msg_state), !LIST_ISEMPTY(&strm->buffer_wait.list));

		chunk_appendf(&trash,
			     "  si[0]=%p (state=%s flags=0x%02x endp0=%s:%p exp=%s, et=0x%03x)\n",
			     &strm->si[0],
			     si_state_str(strm->si[0].state),
			     strm->si[0].flags,
			     obj_type_name(strm->si[0].end),
			     obj_base_ptr(strm->si[0].end),
			     strm->si[0].exp ?
			             tick_is_expired(strm->si[0].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(strm->si[0].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     strm->si[0].err_type);

		chunk_appendf(&trash,
			     "  si[1]=%p (state=%s flags=0x%02x endp1=%s:%p exp=%s, et=0x%03x)\n",
			     &strm->si[1],
			     si_state_str(strm->si[1].state),
			     strm->si[1].flags,
			     obj_type_name(strm->si[1].end),
			     obj_base_ptr(strm->si[1].end),
			     strm->si[1].exp ?
			             tick_is_expired(strm->si[1].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(strm->si[1].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     strm->si[1].err_type);

		if ((cs = objt_cs(strm->si[0].end)) != NULL) {
			conn = cs->conn;

			chunk_appendf(&trash,
			              "  co0=%p ctrl=%s xprt=%s mux=%s data=%s target=%s:%p\n",
				      conn,
				      conn_get_ctrl_name(conn),
				      conn_get_xprt_name(conn),
				      conn_get_mux_name(conn),
				      cs_get_data_name(cs),
			              obj_type_name(conn->target),
			              obj_base_ptr(conn->target));

			chunk_appendf(&trash,
			              "      flags=0x%08x fd=%d fd.state=%02x fd.cache=%d updt=%d fd.tmask=0x%lx\n",
			              conn->flags,
			              conn->handle.fd,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].state : 0,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].cache : 0,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].updated : 0,
				      conn->handle.fd >= 0 ? fdtab[conn->handle.fd].thread_mask: 0);
		}
		else if ((tmpctx = objt_appctx(strm->si[0].end)) != NULL) {
			chunk_appendf(&trash,
			              "  app0=%p st0=%d st1=%d st2=%d applet=%s tmask=0x%lx\n",
				      tmpctx,
				      tmpctx->st0,
				      tmpctx->st1,
				      tmpctx->st2,
			              tmpctx->applet->name,
				      tmpctx->thread_mask);
		}

		if ((cs = objt_cs(strm->si[1].end)) != NULL) {
			conn = cs->conn;

			chunk_appendf(&trash,
			              "  co1=%p ctrl=%s xprt=%s mux=%s data=%s target=%s:%p\n",
				      conn,
				      conn_get_ctrl_name(conn),
				      conn_get_xprt_name(conn),
				      conn_get_mux_name(conn),
				      cs_get_data_name(cs),
			              obj_type_name(conn->target),
			              obj_base_ptr(conn->target));

			chunk_appendf(&trash,
			              "      flags=0x%08x fd=%d fd.state=%02x fd.cache=%d updt=%d fd.tmask=0x%lx\n",
			              conn->flags,
			              conn->handle.fd,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].state : 0,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].cache : 0,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].updated : 0,
				      conn->handle.fd >= 0 ? fdtab[conn->handle.fd].thread_mask: 0);
		}
		else if ((tmpctx = objt_appctx(strm->si[1].end)) != NULL) {
			chunk_appendf(&trash,
			              "  app1=%p st0=%d st1=%d st2=%d applet=%s tmask=0x%lx\n",
				      tmpctx,
				      tmpctx->st0,
				      tmpctx->st1,
				      tmpctx->st2,
			              tmpctx->applet->name,
				      tmpctx->thread_mask);
		}

		chunk_appendf(&trash,
			     "  req=%p (f=0x%06x an=0x%x pipe=%d tofwd=%d total=%lld)\n"
			     "      an_exp=%s",
			     &strm->req,
			     strm->req.flags, strm->req.analysers,
			     strm->req.pipe ? strm->req.pipe->data : 0,
			     strm->req.to_forward, strm->req.total,
			     strm->req.analyse_exp ?
			     human_time(TICKS_TO_MS(strm->req.analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " rex=%s",
			     strm->req.rex ?
			     human_time(TICKS_TO_MS(strm->req.rex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " wex=%s\n"
			     "      buf=%p data=%p o=%d p=%d req.next=%d i=%d size=%d\n",
			     strm->req.wex ?
			     human_time(TICKS_TO_MS(strm->req.wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     strm->req.buf,
			     strm->req.buf->data, strm->req.buf->o,
			     (int)(strm->req.buf->p - strm->req.buf->data),
			     strm->txn ? strm->txn->req.next : 0, strm->req.buf->i,
			     strm->req.buf->size);

		chunk_appendf(&trash,
			     "  res=%p (f=0x%06x an=0x%x pipe=%d tofwd=%d total=%lld)\n"
			     "      an_exp=%s",
			     &strm->res,
			     strm->res.flags, strm->res.analysers,
			     strm->res.pipe ? strm->res.pipe->data : 0,
			     strm->res.to_forward, strm->res.total,
			     strm->res.analyse_exp ?
			     human_time(TICKS_TO_MS(strm->res.analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " rex=%s",
			     strm->res.rex ?
			     human_time(TICKS_TO_MS(strm->res.rex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " wex=%s\n"
			     "      buf=%p data=%p o=%d p=%d rsp.next=%d i=%d size=%d\n",
			     strm->res.wex ?
			     human_time(TICKS_TO_MS(strm->res.wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     strm->res.buf,
			     strm->res.buf->data, strm->res.buf->o,
			     (int)(strm->res.buf->p - strm->res.buf->data),
			     strm->txn ? strm->txn->rsp.next : 0, strm->res.buf->i,
			     strm->res.buf->size);

		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_applet_cant_put(si);
			return 0;
		}

		/* use other states to dump the contents */
	}
	/* end of dump */
	appctx->ctx.sess.uid = 0;
	appctx->ctx.sess.section = 0;
	return 1;
}


static int cli_parse_show_sess(char **args, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (*args[2] && strcmp(args[2], "all") == 0)
		appctx->ctx.sess.target = (void *)-1;
	else if (*args[2])
		appctx->ctx.sess.target = (void *)strtoul(args[2], NULL, 0);
	else
		appctx->ctx.sess.target = NULL;
	appctx->ctx.sess.section = 0; /* start with stream status */
	appctx->ctx.sess.pos = 0;

	return 0;
}

/* This function dumps all streams' states onto the stream interface's
 * read buffer. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero. It is designed to be called
 * from stats_dump_sess_to_buffer() below.
 */
static int cli_io_handler_dump_sess(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct connection *conn;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW))) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last stream being dumped.
		 */
		if (appctx->st2 == STAT_ST_LIST) {
			if (!LIST_ISEMPTY(&appctx->ctx.sess.bref.users)) {
				LIST_DEL(&appctx->ctx.sess.bref.users);
				LIST_INIT(&appctx->ctx.sess.bref.users);
			}
		}
		return 1;
	}

	chunk_reset(&trash);

	switch (appctx->st2) {
	case STAT_ST_INIT:
		/* the function had not been called yet, let's prepare the
		 * buffer for a response. We initialize the current stream
		 * pointer to the first in the global list. When a target
		 * stream is being destroyed, it is responsible for updating
		 * this pointer. We know we have reached the end when this
		 * pointer points back to the head of the streams list.
		 */
		LIST_INIT(&appctx->ctx.sess.bref.users);
		HA_SPIN_LOCK(STRMS_LOCK, &streams_lock);
		appctx->ctx.sess.bref.ref = streams.n;
		HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);
		appctx->st2 = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		HA_SPIN_LOCK(STRMS_LOCK, &streams_lock);
		/* first, let's detach the back-ref from a possible previous stream */
		if (!LIST_ISEMPTY(&appctx->ctx.sess.bref.users)) {
			LIST_DEL(&appctx->ctx.sess.bref.users);
			LIST_INIT(&appctx->ctx.sess.bref.users);
		}

		/* and start from where we stopped */
		while (appctx->ctx.sess.bref.ref != &streams) {
			char pn[INET6_ADDRSTRLEN];
			struct stream *curr_strm;

			curr_strm = LIST_ELEM(appctx->ctx.sess.bref.ref, struct stream *, list);

			if (appctx->ctx.sess.target) {
				if (appctx->ctx.sess.target != (void *)-1 && appctx->ctx.sess.target != curr_strm)
					goto next_sess;

				LIST_ADDQ(&curr_strm->back_refs, &appctx->ctx.sess.bref.users);
				/* call the proper dump() function and return if we're missing space */
				if (!stats_dump_full_strm_to_buffer(si, curr_strm)) {
					HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);
					return 0;
				}

				/* stream dump complete */
				LIST_DEL(&appctx->ctx.sess.bref.users);
				LIST_INIT(&appctx->ctx.sess.bref.users);
				if (appctx->ctx.sess.target != (void *)-1) {
					appctx->ctx.sess.target = NULL;
					break;
				}
				else
					goto next_sess;
			}

			chunk_appendf(&trash,
				     "%p: proto=%s",
				     curr_strm,
				     strm_li(curr_strm) ? strm_li(curr_strm)->proto->name : "?");

			conn = objt_conn(strm_orig(curr_strm));
			switch (conn ? addr_to_str(&conn->addr.from, pn, sizeof(pn)) : AF_UNSPEC) {
			case AF_INET:
			case AF_INET6:
				chunk_appendf(&trash,
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     get_host_port(&conn->addr.from),
					     strm_fe(curr_strm)->id,
					     (curr_strm->be->cap & PR_CAP_BE) ? curr_strm->be->id : "<NONE>",
					     objt_server(curr_strm->target) ? objt_server(curr_strm->target)->id : "<none>"
					     );
				break;
			case AF_UNIX:
				chunk_appendf(&trash,
					     " src=unix:%d fe=%s be=%s srv=%s",
					     strm_li(curr_strm)->luid,
					     strm_fe(curr_strm)->id,
					     (curr_strm->be->cap & PR_CAP_BE) ? curr_strm->be->id : "<NONE>",
					     objt_server(curr_strm->target) ? objt_server(curr_strm->target)->id : "<none>"
					     );
				break;
			}

			chunk_appendf(&trash,
				     " ts=%02x age=%s calls=%d",
				     curr_strm->task->state,
				     human_time(now.tv_sec - curr_strm->logs.tv_accept.tv_sec, 1),
				     curr_strm->task->calls);

			chunk_appendf(&trash,
				     " rq[f=%06xh,i=%d,an=%02xh,rx=%s",
				     curr_strm->req.flags,
				     curr_strm->req.buf->i,
				     curr_strm->req.analysers,
				     curr_strm->req.rex ?
				     human_time(TICKS_TO_MS(curr_strm->req.rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",wx=%s",
				     curr_strm->req.wex ?
				     human_time(TICKS_TO_MS(curr_strm->req.wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",ax=%s]",
				     curr_strm->req.analyse_exp ?
				     human_time(TICKS_TO_MS(curr_strm->req.analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     " rp[f=%06xh,i=%d,an=%02xh,rx=%s",
				     curr_strm->res.flags,
				     curr_strm->res.buf->i,
				     curr_strm->res.analysers,
				     curr_strm->res.rex ?
				     human_time(TICKS_TO_MS(curr_strm->res.rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",wx=%s",
				     curr_strm->res.wex ?
				     human_time(TICKS_TO_MS(curr_strm->res.wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",ax=%s]",
				     curr_strm->res.analyse_exp ?
				     human_time(TICKS_TO_MS(curr_strm->res.analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			conn = cs_conn(objt_cs(curr_strm->si[0].end));
			chunk_appendf(&trash,
				     " s0=[%d,%1xh,fd=%d,ex=%s]",
				     curr_strm->si[0].state,
				     curr_strm->si[0].flags,
				     conn ? conn->handle.fd : -1,
				     curr_strm->si[0].exp ?
				     human_time(TICKS_TO_MS(curr_strm->si[0].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			conn = cs_conn(objt_cs(curr_strm->si[1].end));
			chunk_appendf(&trash,
				     " s1=[%d,%1xh,fd=%d,ex=%s]",
				     curr_strm->si[1].state,
				     curr_strm->si[1].flags,
				     conn ? conn->handle.fd : -1,
				     curr_strm->si[1].exp ?
				     human_time(TICKS_TO_MS(curr_strm->si[1].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     " exp=%s",
				     curr_strm->task->expire ?
				     human_time(TICKS_TO_MS(curr_strm->task->expire - now_ms),
						TICKS_TO_MS(1000)) : "");
			if (task_in_rq(curr_strm->task))
				chunk_appendf(&trash, " run(nice=%d)", curr_strm->task->nice);

			chunk_appendf(&trash, "\n");

			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				si_applet_cant_put(si);
				LIST_ADDQ(&curr_strm->back_refs, &appctx->ctx.sess.bref.users);
				HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);
				return 0;
			}

		next_sess:
			appctx->ctx.sess.bref.ref = curr_strm->list.n;
		}

		if (appctx->ctx.sess.target && appctx->ctx.sess.target != (void *)-1) {
			/* specified stream not found */
			if (appctx->ctx.sess.section > 0)
				chunk_appendf(&trash, "  *** session terminated while we were watching it ***\n");
			else
				chunk_appendf(&trash, "Session not found.\n");

			if (ci_putchk(si_ic(si), &trash) == -1) {
				si_applet_cant_put(si);
				HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);
				return 0;
			}

			appctx->ctx.sess.target = NULL;
			appctx->ctx.sess.uid = 0;
			HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);
			return 1;
		}

		HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);
		appctx->st2 = STAT_ST_FIN;
		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		return 1;
	}
}

static void cli_release_show_sess(struct appctx *appctx)
{
	if (appctx->st2 == STAT_ST_LIST) {
		HA_SPIN_LOCK(STRMS_LOCK, &streams_lock);
		if (!LIST_ISEMPTY(&appctx->ctx.sess.bref.users))
			LIST_DEL(&appctx->ctx.sess.bref.users);
		HA_SPIN_UNLOCK(STRMS_LOCK, &streams_lock);
	}
}

/* Parses the "shutdown session" directive, it always returns 1 */
static int cli_parse_shutdown_session(char **args, struct appctx *appctx, void *private)
{
	struct stream *strm, *ptr;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[2]) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Session pointer expected (use 'show sess').\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	ptr = (void *)strtoul(args[2], NULL, 0);

	/* first, look for the requested stream in the stream table */
	list_for_each_entry(strm, &streams, list) {
		if (strm == ptr)
			break;
	}

	/* do we have the stream ? */
	if (strm != ptr) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "No such session (use 'show sess').\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	stream_shutdown(strm, SF_ERR_KILLED);
	return 1;
}

/* Parses the "shutdown session server" directive, it always returns 1 */
static int cli_parse_shutdown_sessions_server(char **args, struct appctx *appctx, void *private)
{
	struct server *sv;
	struct stream *strm, *strm_bck;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[3]);
	if (!sv)
		return 1;

	/* kill all the stream that are on this server */
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	list_for_each_entry_safe(strm, strm_bck, &sv->actconns, by_srv)
		if (strm->srv_conn == sv)
			stream_shutdown(strm, SF_ERR_KILLED);
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "sess",  NULL }, "show sess [id] : report the list of current sessions or dump this session", cli_parse_show_sess, cli_io_handler_dump_sess, cli_release_show_sess },
	{ { "shutdown", "session",  NULL }, "shutdown session : kill a specific session", cli_parse_shutdown_session, NULL, NULL },
	{ { "shutdown", "sessions",  "server" }, "shutdown sessions server : kill sessions on a server", cli_parse_shutdown_sessions_server, NULL, NULL },
	{{},}
}};

/* main configuration keyword registration. */
static struct action_kw_list stream_tcp_keywords = { ILH, {
	{ "use-service", stream_parse_use_service },
	{ /* END */ }
}};

static struct action_kw_list stream_http_keywords = { ILH, {
	{ "use-service", stream_parse_use_service },
	{ /* END */ }
}};

__attribute__((constructor))
static void __stream_init(void)
{
	tcp_req_cont_keywords_register(&stream_tcp_keywords);
	http_req_keywords_register(&stream_http_keywords);
	cli_register_kw(&cli_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
