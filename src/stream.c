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

#include <import/ebistree.h>

#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/arg.h>
#include <haproxy/backend.h>
#include <haproxy/capture.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/connection.h>
#include <haproxy/dict.h>
#include <haproxy/dynbuf.h>
#include <haproxy/fd.h>
#include <haproxy/filters.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/hlua.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_rules.h>
#include <haproxy/htx.h>
#include <haproxy/istbuf.h>
#include <haproxy/log.h>
#include <haproxy/pipe.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/queue.h>
#include <haproxy/server.h>
#include <haproxy/resolvers.h>
#include <haproxy/sample.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/thread.h>
#include <haproxy/trace.h>
#include <haproxy/vars.h>


DECLARE_POOL(pool_head_stream, "stream", sizeof(struct stream));
DECLARE_POOL(pool_head_uniqueid, "uniqueid", UNIQUEID_LEN);

/* incremented by each "show sess" to fix a delimiter between streams */
unsigned stream_epoch = 0;

/* List of all use-service keywords. */
static struct list service_keywords = LIST_HEAD_INIT(service_keywords);


/* trace source and events */
static void strm_trace(enum trace_level level, uint64_t mask,
		       const struct trace_source *src,
		       const struct ist where, const struct ist func,
		       const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   strm  - stream
 *   si    - stream interface
 *   http  - http analyzis
 *   tcp   - tcp analyzis
 *
 * STRM_EV_* macros are defined in <proto/stream.h>
 */
static const struct trace_event strm_trace_events[] = {
	{ .mask = STRM_EV_STRM_NEW,     .name = "strm_new",     .desc = "new stream" },
	{ .mask = STRM_EV_STRM_FREE,    .name = "strm_free",    .desc = "release stream" },
	{ .mask = STRM_EV_STRM_ERR,     .name = "strm_err",     .desc = "error during stream processing" },
	{ .mask = STRM_EV_STRM_ANA,     .name = "strm_ana",     .desc = "stream analyzers" },
	{ .mask = STRM_EV_STRM_PROC,    .name = "strm_proc",    .desc = "stream processing" },

	{ .mask = STRM_EV_SI_ST,        .name = "si_state",     .desc = "processing stream-interface states" },

	{ .mask = STRM_EV_HTTP_ANA,     .name = "http_ana",     .desc = "HTTP analyzers" },
	{ .mask = STRM_EV_HTTP_ERR,     .name = "http_err",     .desc = "error during HTTP analyzis" },

	{ .mask = STRM_EV_TCP_ANA,      .name = "tcp_ana",      .desc = "TCP analyzers" },
	{ .mask = STRM_EV_TCP_ERR,      .name = "tcp_err",      .desc = "error during TCP analyzis" },
	{}
};

static const struct name_desc strm_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the stream */ },
	/* arg2 */ { },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc strm_trace_decoding[] = {
#define STRM_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define STRM_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report info on stream and stream-interfaces" },
#define STRM_VERB_SIMPLE   3
	{ .name="simple",   .desc="add info on request and response channels" },
#define STRM_VERB_ADVANCED 4
	{ .name="advanced", .desc="add info on channel's buffer for data and developer levels only" },
#define STRM_VERB_COMPLETE 5
	{ .name="complete", .desc="add info on channel's buffer" },
	{ /* end */ }
};

struct trace_source trace_strm = {
	.name = IST("stream"),
	.desc = "Applicative stream",
	.arg_def = TRC_ARG1_STRM,  // TRACE()'s first argument is always a stream
	.default_cb = strm_trace,
	.known_events = strm_trace_events,
	.lockon_args = strm_trace_lockon_args,
	.decoding = strm_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_strm
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* the stream traces always expect that arg1, if non-null, is of a stream (from
 * which we can derive everything), that arg2, if non-null, is an http
 * transaction, that arg3, if non-null, is an http message.
 */
static void strm_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
		       const struct ist where, const struct ist func,
		       const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct stream *s = a1;
	const struct http_txn *txn = a2;
	const struct http_msg *msg = a3;
	struct task *task;
	const struct stream_interface *si_f, *si_b;
	const struct channel *req, *res;
	struct htx *htx;

	if (!s || src->verbosity < STRM_VERB_CLEAN)
		return;

	task = s->task;
	si_f = &s->si[0];
	si_b = &s->si[1];
	req  = &s->req;
	res  = &s->res;
	htx  = (msg ? htxbuf(&msg->chn->buf) : NULL);

	/* General info about the stream (htx/tcp, id...) */
	chunk_appendf(&trace_buf, " : [%u,%s]",
		      s->uniq_id, ((s->flags & SF_HTX) ? "HTX" : "TCP"));
	if (isttest(s->unique_id)) {
		chunk_appendf(&trace_buf, " id=");
		b_putist(&trace_buf, s->unique_id);
	}

	/* Front and back stream-int state */
	chunk_appendf(&trace_buf, " SI=(%s,%s)",
		      si_state_str(si_f->state), si_state_str(si_b->state));

	/* If txn is defined, HTTP req/rep states */
	if (txn)
		chunk_appendf(&trace_buf, " HTTP=(%s,%s)",
			      h1_msg_state_str(txn->req.msg_state), h1_msg_state_str(txn->rsp.msg_state));
	if (msg)
		chunk_appendf(&trace_buf, " %s", ((msg->chn->flags & CF_ISRESP) ? "RESPONSE" : "REQUEST"));

	if (src->verbosity == STRM_VERB_CLEAN)
		return;

	/* If msg defined, display status-line if possible (verbosity > MINIMAL) */
	if (src->verbosity > STRM_VERB_MINIMAL && htx && htx_nbblks(htx)) {
		const struct htx_blk *blk = htx_get_head_blk(htx);
		const struct htx_sl  *sl  = htx_get_blk_ptr(htx, blk);
		enum htx_blk_type    type = htx_get_blk_type(blk);

		if (type == HTX_BLK_REQ_SL || type == HTX_BLK_RES_SL)
			chunk_appendf(&trace_buf, " - \"%.*s %.*s %.*s\"",
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
	}


	/* If txn defined info about HTTP msgs, otherwise info about SI. */
	if (txn) {
		chunk_appendf(&trace_buf, " - t=%p s=(%p,0x%08x) txn.flags=0x%08x, http.flags=(0x%08x,0x%08x) status=%d",
			      task, s, s->flags, txn->flags, txn->req.flags, txn->rsp.flags, txn->status);
	}
	else {
		chunk_appendf(&trace_buf, " - t=%p s=(%p,0x%08x) si_f=(%p,0x%08x,0x%x) si_b=(%p,0x%08x,0x%x) retries=%d",
			      task, s, s->flags, si_f, si_f->flags, si_f->err_type,
			      si_b, si_b->flags, si_b->err_type, si_b->conn_retries);
	}

	if (src->verbosity == STRM_VERB_MINIMAL)
		return;


	/* If txn defined, don't display all channel info */
	if (src->verbosity == STRM_VERB_SIMPLE || txn) {
		chunk_appendf(&trace_buf, " req=(%p .fl=0x%08x .exp(r,w,a)=(%u,%u,%u))",
			      req, req->flags, req->rex, req->wex, req->analyse_exp);
		chunk_appendf(&trace_buf, " res=(%p .fl=0x%08x .exp(r,w,a)=(%u,%u,%u))",
			      res, res->flags, res->rex, res->wex, res->analyse_exp);
	}
	else {
		chunk_appendf(&trace_buf, " req=(%p .fl=0x%08x .ana=0x%08x .exp(r,w,a)=(%u,%u,%u) .o=%lu .tot=%llu .to_fwd=%u)",
			      req, req->flags, req->analysers, req->rex, req->wex, req->analyse_exp,
			      (long)req->output, req->total, req->to_forward);
		chunk_appendf(&trace_buf, " res=(%p .fl=0x%08x .ana=0x%08x .exp(r,w,a)=(%u,%u,%u) .o=%lu .tot=%llu .to_fwd=%u)",
			      res, res->flags, res->analysers, res->rex, res->wex, res->analyse_exp,
			      (long)res->output, res->total, res->to_forward);
	}

	if (src->verbosity == STRM_VERB_SIMPLE ||
	    (src->verbosity == STRM_VERB_ADVANCED && src->level < TRACE_LEVEL_DATA))
		return;

	/* channels' buffer info */
	if (s->flags & SF_HTX) {
		struct htx *rqhtx = htxbuf(&req->buf);
		struct htx *rphtx = htxbuf(&res->buf);

		chunk_appendf(&trace_buf, " htx=(%u/%u#%u, %u/%u#%u)",
			      rqhtx->data, rqhtx->size, htx_nbblks(rqhtx),
			      rphtx->data, rphtx->size, htx_nbblks(rphtx));
	}
	else {
		chunk_appendf(&trace_buf, " buf=(%u@%p+%u/%u, %u@%p+%u/%u)",
			      (unsigned int)b_data(&req->buf), b_orig(&req->buf),
			      (unsigned int)b_head_ofs(&req->buf), (unsigned int)b_size(&req->buf),
			      (unsigned int)b_data(&req->buf), b_orig(&req->buf),
			      (unsigned int)b_head_ofs(&req->buf), (unsigned int)b_size(&req->buf));
	}

	/* If msg defined, display htx info if defined (level > USER) */
	if (src->level > TRACE_LEVEL_USER && htx && htx_nbblks(htx)) {
		int full = 0;

		/* Full htx info (level > STATE && verbosity > SIMPLE) */
		if (src->level > TRACE_LEVEL_STATE) {
			if (src->verbosity == STRM_VERB_COMPLETE)
				full = 1;
		}

		chunk_memcat(&trace_buf, "\n\t", 2);
		htx_dump(&trace_buf, htx, full);
	}
}

/* Create a new stream for connection <conn>. Return < 0 on error. This is only
 * valid right after the handshake, before the connection's data layer is
 * initialized, because it relies on the session to be in conn->owner. On
 * success, <input> buffer is transferred to the stream and thus points to
 * BUF_NULL. On error, it is unchanged and it is the caller responsibility to
 * release it.
 */
int stream_create_from_cs(struct conn_stream *cs, struct buffer *input)
{
	struct stream *strm;

	strm = stream_new(cs->conn->owner, &cs->obj_type, input);
	if (strm == NULL)
		return -1;

	task_wakeup(strm->task, TASK_WOKEN_INIT);
	return 0;
}

/* Upgrade an existing TCP stream for connection <conn>. Return < 0 on error.
 * This is only valid right after a TCP to H1 upgrade. The stream should be
 * "reativated" by removing SF_IGNORE flag. And the right mode must be set.
 * On success, <input> buffer is transferred to the stream and thus points to
 * BUF_NULL. On error, it is unchanged and it is the caller responsibility to
 * release it (this never happens for now).
 */
int stream_upgrade_from_cs(struct conn_stream *cs, struct buffer *input)
{
	struct stream_interface *si = cs->data;
	struct stream *s = si_strm(si);

	if (cs->conn->mux->flags & MX_FL_HTX)
		s->flags |= SF_HTX;

	if (!b_is_null(input)) {
		/* Xfer the input buffer to the request channel. <input> will
		 * than point to BUF_NULL. From this point, it is the stream
		 * responsibility to release it.
		 */
		s->req.buf = *input;
		*input = BUF_NULL;
		s->req.total = (IS_HTX_STRM(s) ? htxbuf(&s->req.buf)->data : b_data(&s->req.buf));
		s->req.flags |= (s->req.total ? CF_READ_PARTIAL : 0);
	}

	s->flags &= ~SF_IGNORE;

	task_wakeup(s->task, TASK_WOKEN_INIT);
	return 0;
}

/* Callback used to wake up a stream when an input buffer is available. The
 * stream <s>'s stream interfaces are checked for a failed buffer allocation
 * as indicated by the presence of the SI_FL_RXBLK_ROOM flag and the lack of a
 * buffer, and and input buffer is assigned there (at most one). The function
 * returns 1 and wakes the stream up if a buffer was taken, otherwise zero.
 * It's designed to be called from __offer_buffer().
 */
int stream_buf_available(void *arg)
{
	struct stream *s = arg;

	if (!s->req.buf.size && !s->req.pipe && (s->si[0].flags & SI_FL_RXBLK_BUFF) &&
	    b_alloc(&s->req.buf))
		si_rx_buff_rdy(&s->si[0]);
	else if (!s->res.buf.size && !s->res.pipe && (s->si[1].flags & SI_FL_RXBLK_BUFF) &&
		 b_alloc(&s->res.buf))
		si_rx_buff_rdy(&s->si[1]);
	else
		return 0;

	task_wakeup(s->task, TASK_WOKEN_RES);
	return 1;

}

/* This function is called from the session handler which detects the end of
 * handshake, in order to complete initialization of a valid stream. It must be
 * called with a completely initialized session. It returns the pointer to
 * the newly created stream, or NULL in case of fatal error. The client-facing
 * end point is assigned to <origin>, which must be valid. The stream's task
 * is configured with a nice value inherited from the listener's nice if any.
 * The task's context is set to the new stream, and its function is set to
 * process_stream(). Target and analysers are null. <input> is used as input
 * buffer for the request channel and may contain data. On success, it is
 * transfer to the stream and <input> is set to BUF_NULL. On error, <input>
 * buffer is unchanged and it is the caller responsibility to release it.
 */
struct stream *stream_new(struct session *sess, enum obj_type *origin, struct buffer *input)
{
	struct stream *s;
	struct task *t;
	struct conn_stream *cs  = objt_cs(origin);
	struct appctx *appctx   = objt_appctx(origin);

	DBG_TRACE_ENTER(STRM_EV_STRM_NEW);
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
	tv_zero(&s->logs.tv_request);
	s->logs.t_queue = -1;
	s->logs.t_connect = -1;
	s->logs.t_data = -1;
	s->logs.t_close = 0;
	s->logs.bytes_in = s->logs.bytes_out = 0;
	s->logs.prx_queue_pos = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_pos = 0; /* we will get this number soon */
	s->obj_type = OBJ_TYPE_STREAM;

	s->logs.accept_date = sess->accept_date;
	s->logs.tv_accept = sess->tv_accept;
	s->logs.t_handshake = sess->t_handshake;
	s->logs.t_idle = sess->t_idle;

	/* default logging function */
	s->do_log = strm_log;

	/* default error reporting function, may be changed by analysers */
	s->srv_error = default_srv_error;

	/* Initialise the current rule list pointer to NULL. We are sure that
	 * any rulelist match the NULL pointer.
	 */
	s->current_rule_list = NULL;
	s->current_rule = NULL;
	s->rules_exp = TICK_ETERNITY;

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

	s->stream_epoch = _HA_ATOMIC_LOAD(&stream_epoch);
	s->uniq_id = _HA_ATOMIC_FETCH_ADD(&global.req_count, 1);

	/* OK, we're keeping the stream, so let's properly initialize the stream */
	LIST_INIT(&s->back_refs);

	LIST_INIT(&s->buffer_wait.list);
	s->buffer_wait.target = s;
	s->buffer_wait.wakeup_cb = stream_buf_available;

	s->call_rate.curr_tick = s->call_rate.curr_ctr = s->call_rate.prev_ctr = 0;
	s->pcli_next_pid = 0;
	s->pcli_flags = 0;
	s->unique_id = IST_NULL;

	if ((t = task_new_here()) == NULL)
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
	s->req_cap = NULL;
	s->res_cap = NULL;

	/* Initialise all the variables contexts even if not used.
	 * This permits to prune these contexts without errors.
	 */
	vars_init_head(&s->vars_txn,    SCOPE_TXN);
	vars_init_head(&s->vars_reqres, SCOPE_REQ);

	/* this part should be common with other protocols */
	if (si_reset(&s->si[0]) < 0)
		goto out_fail_alloc;
	si_set_state(&s->si[0], SI_ST_EST);
	s->si[0].hcto = sess->fe->timeout.clientfin;

	if (cs && cs->conn->mux) {
		if (cs->conn->mux->flags & MX_FL_CLEAN_ABRT)
			s->si[0].flags |= SI_FL_CLEAN_ABRT;
		if (cs->conn->mux->flags & MX_FL_HTX)
			s->flags |= SF_HTX;

		if (cs->flags & CS_FL_WEBSOCKET)
			s->flags |= SF_WEBSOCKET;
	}
        /* Set SF_HTX flag for HTTP frontends. */
	if (sess->fe->mode == PR_MODE_HTTP)
		s->flags |= SF_HTX;

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
	if (si_reset(&s->si[1]) < 0)
		goto out_fail_alloc_si1;
	s->si[1].hcto = TICK_ETERNITY;

	if (likely(sess->fe->options2 & PR_O2_INDEPSTR))
		s->si[1].flags |= SI_FL_INDEP_STR;

	stream_init_srv_conn(s);
	s->target = sess->listener ? sess->listener->default_target : NULL;

	s->pend_pos = NULL;
	s->priority_class = 0;
	s->priority_offset = 0;

	/* init store persistence */
	s->store_count = 0;

	channel_init(&s->req);
	s->req.flags |= CF_READ_ATTACHED; /* the producer is already connected */
	s->req.analysers = sess->listener ? sess->listener->analysers : 0;

	if (IS_HTX_STRM(s)) {
		/* Be sure to have HTTP analysers because in case of
		 * "destructive" stream upgrade, they may be missing (e.g
		 * TCP>H2)
		 */
		s->req.analysers |= AN_REQ_WAIT_HTTP|AN_REQ_HTTP_PROCESS_FE;
	}

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

	s->resolv_ctx.requester = NULL;
	s->resolv_ctx.hostname_dn = NULL;
	s->resolv_ctx.hostname_dn_len = 0;
	s->resolv_ctx.parent = NULL;

	s->tunnel_timeout = TICK_ETERNITY;

	LIST_APPEND(&th_ctx->streams, &s->list);

	if (flt_stream_init(s) < 0 || flt_stream_start(s) < 0)
		goto out_fail_accept;

	s->si[1].l7_buffer = BUF_NULL;
	/* finish initialization of the accepted file descriptor */
	if (appctx)
		si_want_get(&s->si[0]);

	if (sess->fe->accept && sess->fe->accept(s) < 0)
		goto out_fail_accept;

	if (!b_is_null(input)) {
		/* Xfer the input buffer to the request channel. <input> will
		 * than point to BUF_NULL. From this point, it is the stream
		 * responsibility to release it.
		 */
		s->req.buf = *input;
		*input = BUF_NULL;
		s->req.total = (IS_HTX_STRM(s) ? htxbuf(&s->req.buf)->data : b_data(&s->req.buf));
		s->req.flags |= (s->req.total ? CF_READ_PARTIAL : 0);
	}

	/* it is important not to call the wakeup function directly but to
	 * pass through task_wakeup(), because this one knows how to apply
	 * priorities to tasks. Using multi thread we must be sure that
	 * stream is fully initialized before calling task_wakeup. So
	 * the caller must handle the task_wakeup
	 */
	DBG_TRACE_LEAVE(STRM_EV_STRM_NEW, s);
	return s;

	/* Error unrolling */
 out_fail_accept:
	flt_stream_release(s, 0);
	task_destroy(t);
	tasklet_free(s->si[1].wait_event.tasklet);
	LIST_DELETE(&s->list);
out_fail_alloc_si1:
	tasklet_free(s->si[0].wait_event.tasklet);
 out_fail_alloc:
	pool_free(pool_head_stream, s);
	DBG_TRACE_DEVEL("leaving on error", STRM_EV_STRM_NEW|STRM_EV_STRM_ERR);
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

	DBG_TRACE_POINT(STRM_EV_STRM_FREE, s);

	/* detach the stream from its own task before even releasing it so
	 * that walking over a task list never exhibits a dying stream.
	 */
	s->task->context = NULL;
	__ha_barrier_store();

	pendconn_free(s);

	if (objt_server(s->target)) { /* there may be requests left pending in queue */
		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			_HA_ATOMIC_DEC(&__objt_server(s->target)->cur_sess);
		}
		if (may_dequeue_tasks(__objt_server(s->target), s->be))
			process_srv_queue(__objt_server(s->target));
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
	if (LIST_INLIST(&s->buffer_wait.list))
		LIST_DEL_INIT(&s->buffer_wait.list);

	if (s->req.buf.size || s->res.buf.size) {
		int count = !!s->req.buf.size + !!s->res.buf.size;

		b_free(&s->req.buf);
		b_free(&s->res.buf);
		offer_buffers(NULL, count);
	}

	pool_free(pool_head_uniqueid, s->unique_id.ptr);
	s->unique_id = IST_NULL;

	flt_stream_stop(s);
	flt_stream_release(s, 0);

	hlua_ctx_destroy(s->hlua);
	s->hlua = NULL;
	if (s->txn)
		http_destroy_txn(s);

	/* ensure the client-side transport layer is destroyed */
	if (cli_cs)
		cs_close(cli_cs);

	for (i = 0; i < s->store_count; i++) {
		if (!s->store[i].ts)
			continue;
		stksess_free(s->store[i].table, s->store[i].ts);
		s->store[i].ts = NULL;
	}

	if (s->resolv_ctx.requester) {
		__decl_thread(struct resolvers *resolvers = s->resolv_ctx.parent->arg.resolv.resolvers);

		HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);
		ha_free(&s->resolv_ctx.hostname_dn);
		s->resolv_ctx.hostname_dn_len = 0;
		resolv_unlink_resolution(s->resolv_ctx.requester);
		HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);

		pool_free(resolv_requester_pool, s->resolv_ctx.requester);
		s->resolv_ctx.requester = NULL;
	}

	if (fe) {
		if (s->req_cap) {
			struct cap_hdr *h;
			for (h = fe->req_cap; h; h = h->next)
				pool_free(h->pool, s->req_cap[h->index]);
		}

		if (s->res_cap) {
			struct cap_hdr *h;
			for (h = fe->rsp_cap; h; h = h->next)
				pool_free(h->pool, s->res_cap[h->index]);
		}

		pool_free(fe->rsp_cap_pool, s->res_cap);
		pool_free(fe->req_cap_pool, s->req_cap);
	}

	/* Cleanup all variable contexts. */
	if (!LIST_ISEMPTY(&s->vars_txn.head))
		vars_prune(&s->vars_txn, s->sess, s);
	if (!LIST_ISEMPTY(&s->vars_reqres.head))
		vars_prune(&s->vars_reqres, s->sess, s);

	stream_store_counters(s);

	list_for_each_entry_safe(bref, back, &s->back_refs, users) {
		/* we have to unlink all watchers. We must not relink them if
		 * this stream was the last one in the list. This is safe to do
		 * here because we're touching our thread's list so we know
		 * that other streams are not active, and the watchers will
		 * only touch their node under thread isolation.
		 */
		LIST_DEL_INIT(&bref->users);
		if (s->list.n != &th_ctx->streams)
			LIST_APPEND(&LIST_ELEM(s->list.n, struct stream *, list)->back_refs, &bref->users);
		bref->ref = s->list.n;
		__ha_barrier_store();
	}
	LIST_DELETE(&s->list);

	/* applets do not release session yet */
	must_free_sess = objt_appctx(sess->origin) && sess->origin == s->si[0].end;


	si_release_endpoint(&s->si[1]);
	si_release_endpoint(&s->si[0]);

	tasklet_free(s->si[0].wait_event.tasklet);
	tasklet_free(s->si[1].wait_event.tasklet);

	b_free(&s->si[1].l7_buffer);
	if (must_free_sess) {
		sess->origin = NULL;
		session_free(sess);
	}

	sockaddr_free(&s->si[0].src);
	sockaddr_free(&s->si[0].dst);
	sockaddr_free(&s->si[1].src);
	sockaddr_free(&s->si[1].dst);
	pool_free(pool_head_stream, s);

	/* We may want to free the maximum amount of pools if the proxy is stopping */
	if (fe && unlikely(fe->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
		pool_flush(pool_head_buffer);
		pool_flush(pool_head_http_txn);
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
	if (LIST_INLIST(&s->buffer_wait.list))
		LIST_DEL_INIT(&s->buffer_wait.list);

	if (b_alloc(&s->res.buf))
		return 1;

	LIST_APPEND(&th_ctx->buffer_wq, &s->buffer_wait.list);
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

	if (c_size(&s->req) && c_empty(&s->req)) {
		offer++;
		b_free(&s->req.buf);
	}
	if (c_size(&s->res) && c_empty(&s->res)) {
		offer++;
		b_free(&s->res.buf);
	}

	/* if we're certain to have at least 1 buffer available, and there is
	 * someone waiting, we can wake up a waiter and offer them.
	 */
	if (offer)
		offer_buffers(s, offer);
}

void stream_process_counters(struct stream *s)
{
	struct session *sess = s->sess;
	unsigned long long bytes;
	int i;

	bytes = s->req.total - s->logs.bytes_in;
	s->logs.bytes_in = s->req.total;
	if (bytes) {
		_HA_ATOMIC_ADD(&sess->fe->fe_counters.bytes_in, bytes);
		_HA_ATOMIC_ADD(&s->be->be_counters.bytes_in,    bytes);

		if (objt_server(s->target))
			_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.bytes_in, bytes);

		if (sess->listener && sess->listener->counters)
			_HA_ATOMIC_ADD(&sess->listener->counters->bytes_in, bytes);

		for (i = 0; i < MAX_SESS_STKCTR; i++) {
			if (!stkctr_inc_bytes_in_ctr(&s->stkctr[i], bytes))
				stkctr_inc_bytes_in_ctr(&sess->stkctr[i], bytes);
		}
	}

	bytes = s->res.total - s->logs.bytes_out;
	s->logs.bytes_out = s->res.total;
	if (bytes) {
		_HA_ATOMIC_ADD(&sess->fe->fe_counters.bytes_out, bytes);
		_HA_ATOMIC_ADD(&s->be->be_counters.bytes_out,    bytes);

		if (objt_server(s->target))
			_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.bytes_out, bytes);

		if (sess->listener && sess->listener->counters)
			_HA_ATOMIC_ADD(&sess->listener->counters->bytes_out, bytes);

		for (i = 0; i < MAX_SESS_STKCTR; i++) {
			if (!stkctr_inc_bytes_out_ctr(&s->stkctr[i], bytes))
				stkctr_inc_bytes_out_ctr(&sess->stkctr[i], bytes);
		}
	}
}

int stream_set_timeout(struct stream *s, enum act_timeout_name name, int timeout)
{
	switch (name) {
	case ACT_TIMEOUT_SERVER:
		s->req.wto = timeout;
		s->res.rto = timeout;
		return 1;

	case ACT_TIMEOUT_TUNNEL:
		s->tunnel_timeout = timeout;
		return 1;

	default:
		return 0;
	}
}

/*
 * This function handles the transition between the SI_ST_CON state and the
 * SI_ST_EST state. It must only be called after switching from SI_ST_CON (or
 * SI_ST_INI or SI_ST_RDY) to SI_ST_EST, but only when a ->proto is defined.
 * Note that it will switch the interface to SI_ST_DIS if we already have
 * the CF_SHUTR flag, it means we were able to forward the request, and
 * receive the response, before process_stream() had the opportunity to
 * make the switch from SI_ST_CON to SI_ST_EST. When that happens, we want
 * to go through back_establish() anyway, to make sure the analysers run.
 * Timeouts are cleared. Error are reported on the channel so that analysers
 * can handle them.
 */
static void back_establish(struct stream *s)
{
	struct stream_interface *si = &s->si[1];
	struct conn_stream *srv_cs = objt_cs(si->end);
	struct connection *conn = srv_cs ? srv_cs->conn : objt_conn(si->end);
	struct channel *req = &s->req;
	struct channel *rep = &s->res;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
	/* First, centralize the timers information, and clear any irrelevant
	 * timeout.
	 */
	s->logs.t_connect = tv_ms_elapsed(&s->logs.tv_accept, &now);
	si->exp = TICK_ETERNITY;
	si->flags &= ~SI_FL_EXP;

	/* errors faced after sending data need to be reported */
	if (si->flags & SI_FL_ERR && req->flags & CF_WROTE_DATA) {
		/* Don't add CF_WRITE_ERROR if we're here because
		 * early data were rejected by the server, or
		 * http_wait_for_response() will never be called
		 * to send a 425.
		 */
		if (conn && conn->err_code != CO_ER_SSL_EARLY_FAILED)
			req->flags |= CF_WRITE_ERROR;
		rep->flags |= CF_READ_ERROR;
		si->err_type = SI_ET_DATA_ERR;
		DBG_TRACE_STATE("read/write error", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
	}

	if (objt_server(s->target))
		health_adjust(__objt_server(s->target), HANA_STATUS_L4_OK);

	if (!IS_HTX_STRM(s)) { /* let's allow immediate data connection in this case */
		/* if the user wants to log as soon as possible, without counting
		 * bytes from the server, then this is the right moment. */
		if (!LIST_ISEMPTY(&strm_fe(s)->logformat) && !(s->logs.logwait & LW_BYTES)) {
			/* note: no pend_pos here, session is established */
			s->logs.t_close = s->logs.t_connect; /* to get a valid end date */
			s->do_log(s);
		}
	}
	else {
		rep->flags |= CF_READ_DONTWAIT; /* a single read is enough to get response headers */
	}

	rep->analysers |= strm_fe(s)->fe_rsp_ana | s->be->be_rsp_ana;

	si_rx_endp_more(si);
	rep->flags |= CF_READ_ATTACHED; /* producer is now attached */
	if (objt_cs(si->end)) {
		/* real connections have timeouts
		 * if already defined, it means that a set-timeout rule has
		 * been executed so do not overwrite them
		 */
		if (!tick_isset(req->wto))
			req->wto = s->be->timeout.server;
		if (!tick_isset(rep->rto))
			rep->rto = s->be->timeout.server;
		if (!tick_isset(s->tunnel_timeout))
			s->tunnel_timeout = s->be->timeout.tunnel;

		/* The connection is now established, try to read data from the
		 * underlying layer, and subscribe to recv events. We use a
		 * delayed recv here to give a chance to the data to flow back
		 * by the time we process other tasks.
		 */
		si_chk_rcv(si);
	}
	req->wex = TICK_ETERNITY;
	/* If we managed to get the whole response, and we don't have anything
	 * left to send, or can't, switch to SI_ST_DIS now. */
	if (rep->flags & (CF_SHUTR | CF_SHUTW)) {
		si->state = SI_ST_DIS;
		DBG_TRACE_STATE("response channel shutdwn for read/write", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
	}

	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
}

/* Set correct stream termination flags in case no analyser has done it. It
 * also counts a failed request if the server state has not reached the request
 * stage.
 */
static void sess_set_term_flags(struct stream *s)
{
	if (!(s->flags & SF_FINST_MASK)) {
		if (s->si[1].state == SI_ST_INI) {
			/* anything before REQ in fact */
			_HA_ATOMIC_INC(&strm_fe(s)->fe_counters.failed_req);
			if (strm_li(s) && strm_li(s)->counters)
				_HA_ATOMIC_INC(&strm_li(s)->counters->failed_req);

			s->flags |= SF_FINST_R;
		}
		else if (s->si[1].state == SI_ST_QUE)
			s->flags |= SF_FINST_Q;
		else if (si_state_in(s->si[1].state, SI_SB_REQ|SI_SB_TAR|SI_SB_ASS|SI_SB_CON|SI_SB_CER|SI_SB_RDY))
			s->flags |= SF_FINST_C;
		else if (s->si[1].state == SI_ST_EST || s->si[1].prev_state == SI_ST_EST)
			s->flags |= SF_FINST_D;
		else
			s->flags |= SF_FINST_L;
	}
}

/* This function parses the use-service action ruleset. It executes
 * the associated ACL and set an applet as a stream or txn final node.
 * it returns ACT_RET_ERR if an error occurs, the proxy left in
 * consistent state. It returns ACT_RET_STOP in success case because
 * use-service must be a terminal action. Returns ACT_RET_YIELD
 * if the initialisation function require more data.
 */
enum act_return process_use_service(struct act_rule *rule, struct proxy *px,
                                    struct session *sess, struct stream *s, int flags)

{
	struct appctx *appctx;

	/* Initialises the applet if it is required. */
	if (flags & ACT_OPT_FIRST) {
		/* Register applet. this function schedules the applet. */
		s->target = &rule->applet.obj_type;
		if (unlikely(!si_register_handler(&s->si[1], objt_applet(s->target))))
			return ACT_RET_ERR;

		/* Initialise the context. */
		appctx = si_appctx(&s->si[1]);
		memset(&appctx->ctx, 0, sizeof(appctx->ctx));
		appctx->rule = rule;
	}
	else
		appctx = si_appctx(&s->si[1]);

	/* Stops the applet scheduling, in case of the init function miss
	 * some data.
	 */
	si_stop_get(&s->si[1]);

	/* Call initialisation. */
	if (rule->applet.init)
		switch (rule->applet.init(appctx, px, s)) {
		case 0: return ACT_RET_ERR;
		case 1: break;
		default: return ACT_RET_YIELD;
	}

	if (rule->from != ACT_F_HTTP_REQ) {
		if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			_HA_ATOMIC_INC(&sess->fe->fe_counters.intercepted_req);

		/* The flag SF_ASSIGNED prevent from server assignment. */
		s->flags |= SF_ASSIGNED;
	}

	/* Now we can schedule the applet. */
	si_cant_get(&s->si[1]);
	appctx_wakeup(appctx);
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

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA, s);

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
					struct buffer *tmp;

					tmp = alloc_trash_chunk();
					if (!tmp)
						goto sw_failed;

					if (build_logline(s, tmp->area, tmp->size, &rule->be.expr))
						backend = proxy_be_by_name(tmp->area);

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
		 * backend if any. Don't do anything if an upgrade is already in
		 * progress.
		 */
		if (!(s->flags & (SF_BE_ASSIGNED|SF_IGNORE)))
			if (!stream_set_backend(s, fe->defbe.be ? fe->defbe.be : s->be))
				goto sw_failed;

		/* No backend assigned but no error reported. It happens when a
		 * TCP stream is upgraded to HTTP/2.
		 */
		if ((s->flags & (SF_BE_ASSIGNED|SF_IGNORE)) == SF_IGNORE) {
			DBG_TRACE_DEVEL("leaving with no backend because of a destructive upgrade", STRM_EV_STRM_ANA, s);
			return 0;
		}

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

	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA, s);
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
	DBG_TRACE_DEVEL("leaving on error", STRM_EV_STRM_ANA|STRM_EV_STRM_ERR, s);
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

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA, s);

	if (!(s->flags & SF_ASSIGNED)) {
		list_for_each_entry(rule, &px->server_rules, list) {
			int ret;

			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				struct server *srv;

				if (rule->dynamic) {
					struct buffer *tmp = get_trash_chunk();

					if (!build_logline(s, tmp->area, tmp->size, &rule->expr))
						break;

					srv = findserver(s->be, tmp->area);
					if (!srv)
						break;
				}
				else
					srv = rule->srv.ptr;

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
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA, s);
	return 1;
}

static inline void sticking_rule_find_target(struct stream *s,
                                             struct stktable *t, struct stksess *ts)
{
	struct proxy *px = s->be;
	struct eb32_node *node;
	struct dict_entry *de;
	void *ptr;
	struct server *srv;

	/* Look for the server name previously stored in <t> stick-table */
	HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
	ptr = __stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_KEY);
	de = stktable_data_cast(ptr, std_t_dict);
	HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);

	if (de) {
		struct ebpt_node *node;

		if (t->server_key_type == STKTABLE_SRV_NAME) {
			node = ebis_lookup(&px->conf.used_server_name, de->value.key);
			if (node) {
				srv = container_of(node, struct server, conf.name);
				goto found;
			}
		} else if (t->server_key_type == STKTABLE_SRV_ADDR) {
			HA_RWLOCK_RDLOCK(PROXY_LOCK, &px->lock);
			node = ebis_lookup(&px->used_server_addr, de->value.key);
			HA_RWLOCK_RDUNLOCK(PROXY_LOCK, &px->lock);
			if (node) {
				srv = container_of(node, struct server, addr_node);
				goto found;
			}
		}
	}

	/* Look for the server ID */
	HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
	ptr = __stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_ID);
	node = eb32_lookup(&px->conf.used_server_id, stktable_data_cast(ptr, std_t_sint));
	HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);

	if (!node)
		return;

	srv = container_of(node, struct server, conf.id);
 found:
	if ((srv->cur_state != SRV_ST_STOPPED) ||
	    (px->options & PR_O_PERSIST) || (s->flags & SF_FORCE_PRST)) {
		s->flags |= SF_DIRECT | SF_ASSIGNED;
		s->target = &srv->obj_type;
	}
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

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA, s);

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
		if (rule->flags & STK_IS_STORE) {
			for (i = 0; i < s->store_count; i++) {
				if (rule->table.t == s->store[i].table)
					break;
			}

			if (i !=  s->store_count)
				continue;
		}

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
					if (!(s->flags & SF_ASSIGNED))
						sticking_rule_find_target(s, rule->table.t, ts);
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
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA, s);
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

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA, s);

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
		char *key;
		struct dict_entry *de;
		struct stktable *t = s->store[i].table;

		if (objt_server(s->target) && __objt_server(s->target)->flags & SRV_F_NON_STICK) {
			stksess_free(s->store[i].table, s->store[i].ts);
			s->store[i].ts = NULL;
			continue;
		}

		ts = stktable_set_entry(t, s->store[i].ts);
		if (ts != s->store[i].ts) {
			/* the entry already existed, we can free ours */
			stksess_free(t, s->store[i].ts);
		}
		s->store[i].ts = NULL;

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
		ptr = __stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_ID);
		stktable_data_cast(ptr, std_t_sint) = __objt_server(s->target)->puid;
		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		if (t->server_key_type == STKTABLE_SRV_NAME)
			key = __objt_server(s->target)->id;
		else if (t->server_key_type == STKTABLE_SRV_ADDR)
			key = __objt_server(s->target)->addr_node.key;
		else
			continue;

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
		de = dict_insert(&server_key_dict, key);
		if (de) {
			ptr = __stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_KEY);
			stktable_data_cast(ptr, std_t_dict) = de;
		}
		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		stktable_touch_local(t, ts, 1);
	}
	s->store_count = 0; /* everything is stored */

	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;

	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA, s);
	return 1;
}

/* Set the stream to HTTP mode, if necessary. The minimal request HTTP analysers
 * are set and the client mux is upgraded. It returns 1 if the stream processing
 * may continue or 0 if it should be stopped. It happens on error or if the
 * upgrade required a new stream. The mux protocol may be specified.
 */
int stream_set_http_mode(struct stream *s, const struct mux_proto_list *mux_proto)
{
	struct connection  *conn;
	struct conn_stream *cs;

	/* Already an HTTP stream */
	if (IS_HTX_STRM(s))
		return 1;

	s->req.analysers |= AN_REQ_WAIT_HTTP|AN_REQ_HTTP_PROCESS_FE;

	if (unlikely(!s->txn && !http_create_txn(s)))
		return 0;

	conn = objt_conn(strm_sess(s)->origin);
	cs = objt_cs(s->si[0].end);
	if (conn && cs) {
		si_rx_endp_more(&s->si[0]);
		/* Make sure we're unsubscribed, the the new
		 * mux will probably want to subscribe to
		 * the underlying XPRT
		 */
		if (s->si[0].wait_event.events)
			conn->mux->unsubscribe(cs, s->si[0].wait_event.events,
					       &s->si[0].wait_event);

		if (conn->mux->flags & MX_FL_NO_UPG)
			return 0;
		if (conn_upgrade_mux_fe(conn, cs, &s->req.buf,
					(mux_proto ? mux_proto->token : ist("")),
					PROTO_MODE_HTTP)  == -1)
			return 0;

		s->req.flags &= ~(CF_READ_PARTIAL|CF_AUTO_CONNECT);
		s->req.total = 0;
		s->flags |= SF_IGNORE;
		if (strcmp(conn->mux->name, "H2") == 0) {
			/* For HTTP/2, destroy the conn_stream, disable logging,
			 * and abort the stream process. Thus it will be
			 * silently destroyed. The new mux will create new
			 * streams.
			 */
			cs_free(cs);
			si_detach_endpoint(&s->si[0]);
			s->logs.logwait = 0;
			s->logs.level = 0;
			channel_abort(&s->req);
			channel_abort(&s->res);
			s->req.analysers &= AN_REQ_FLT_END;
			s->req.analyse_exp = TICK_ETERNITY;
		}
	}

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
struct task *process_stream(struct task *t, void *context, unsigned int state)
{
	struct server *srv;
	struct stream *s = context;
	struct session *sess = s->sess;
	unsigned int rqf_last, rpf_last;
	unsigned int rq_prod_last, rq_cons_last;
	unsigned int rp_cons_last, rp_prod_last;
	unsigned int req_ana_back;
	struct channel *req, *res;
	struct stream_interface *si_f, *si_b;
	unsigned int rate;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC, s);

	activity[tid].stream_calls++;

	req = &s->req;
	res = &s->res;

	si_f = &s->si[0];
	si_b = &s->si[1];

	/* First, attempt to receive pending data from I/O layers */
	si_sync_recv(si_f);
	si_sync_recv(si_b);

	/* Let's check if we're looping without making any progress, e.g. due
	 * to a bogus analyser or the fact that we're ignoring a read0. The
	 * call_rate counter only counts calls with no progress made.
	 */
	if (!((req->flags | res->flags) & (CF_READ_PARTIAL|CF_WRITE_PARTIAL))) {
		rate = update_freq_ctr(&s->call_rate, 1);
		if (rate >= 100000 && s->call_rate.prev_ctr) // make sure to wait at least a full second
			stream_dump_and_crash(&s->obj_type, read_freq_ctr(&s->call_rate));
	}

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
	s->pending_events |= (state & TASK_WOKEN_ANY);

	/* 1a: Check for low level timeouts if needed. We just set a flag on
	 * stream interfaces when their timeouts have expired.
	 */
	if (unlikely(s->pending_events & TASK_WOKEN_TIMER)) {
		si_check_timeouts(si_f);
		si_check_timeouts(si_b);

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
		       CF_WRITE_ACTIVITY|CF_WRITE_TIMEOUT|CF_ANA_TIMEOUT)) &&
		    !((si_f->flags | si_b->flags) & (SI_FL_EXP|SI_FL_ERR)) &&
		    ((s->pending_events & TASK_WOKEN_ANY) == TASK_WOKEN_TIMER)) {
			si_f->flags &= ~SI_FL_DONT_WAKE;
			si_b->flags &= ~SI_FL_DONT_WAKE;
			goto update_exp_and_leave;
		}
	}

 resync_stream_interface:
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
		if (si_state_in(si_f->state, SI_SB_EST|SI_SB_DIS)) {
			si_shutr(si_f);
			si_shutw(si_f);
			si_report_error(si_f);
			if (!(req->analysers) && !(res->analysers)) {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_CLICL;
				if (!(s->flags & SF_FINST_MASK))
					s->flags |= SF_FINST_D;
			}
		}
	}

	if (unlikely(si_b->flags & SI_FL_ERR)) {
		if (si_state_in(si_b->state, SI_SB_EST|SI_SB_DIS)) {
			si_shutr(si_b);
			si_shutw(si_b);
			si_report_error(si_b);
			_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
			if (srv)
				_HA_ATOMIC_INC(&srv->counters.failed_resp);
			if (!(req->analysers) && !(res->analysers)) {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_SRVCL;
				if (!(s->flags & SF_FINST_MASK))
					s->flags |= SF_FINST_D;
			}
		}
		/* note: maybe we should process connection errors here ? */
	}

	if (si_state_in(si_b->state, SI_SB_CON|SI_SB_RDY)) {
		/* we were trying to establish a connection on the server side,
		 * maybe it succeeded, maybe it failed, maybe we timed out, ...
		 */
		if (si_b->state == SI_ST_RDY)
			back_handle_st_rdy(s);
		else if (si_b->state == SI_ST_CON)
			back_handle_st_con(s);

		if (si_b->state == SI_ST_CER)
			back_handle_st_cer(s);
		else if (si_b->state == SI_ST_EST)
			back_establish(s);

		/* state is now one of SI_ST_CON (still in progress), SI_ST_EST
		 * (established), SI_ST_DIS (abort), SI_ST_CLO (last error),
		 * SI_ST_ASS/SI_ST_TAR/SI_ST_REQ for retryable errors.
		 */
	}

	rq_prod_last = si_f->state;
	rq_cons_last = si_b->state;
	rp_cons_last = si_f->state;
	rp_prod_last = si_b->state;

	/* Check for connection closure */
	DBG_TRACE_POINT(STRM_EV_STRM_PROC, s);

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
				_HA_ATOMIC_DEC(&srv->cur_sess);
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

		if (si_state_in(si_f->state, SI_SB_EST|SI_SB_DIS|SI_SB_CLO)) {
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
				ANALYZE    (s, req, pcli_wait_for_request,      ana_list, ana_back, AN_REQ_WAIT_CLI);
				ANALYZE    (s, req, flt_xfer_data,              ana_list, ana_back, AN_REQ_FLT_XFER_DATA);
				ANALYZE    (s, req, flt_end_analyze,            ana_list, ana_back, AN_REQ_FLT_END);
				break;
			}
		}

		rq_prod_last = si_f->state;
		rq_cons_last = si_b->state;
		req->flags &= ~CF_WAKE_ONCE;
		rqf_last = req->flags;

		if ((req->flags ^ flags) & (CF_SHUTR|CF_SHUTW))
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

		if (si_state_in(si_b->state, SI_SB_EST|SI_SB_DIS|SI_SB_CLO)) {
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
				ANALYZE    (s, res, pcli_wait_for_response,     ana_list, ana_back, AN_RES_WAIT_CLI);
				ANALYZE    (s, res, flt_xfer_data,              ana_list, ana_back, AN_RES_FLT_XFER_DATA);
				ANALYZE    (s, res, flt_end_analyze,            ana_list, ana_back, AN_RES_FLT_END);
				break;
			}
		}

		rp_cons_last = si_f->state;
		rp_prod_last = si_b->state;
		res->flags &= ~CF_WAKE_ONCE;
		rpf_last = res->flags;

		if ((res->flags ^ flags) & (CF_SHUTR|CF_SHUTW))
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
			req->analysers &= AN_REQ_FLT_END;
			if (req->flags & CF_READ_ERROR) {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				s->flags |= SF_ERR_CLICL;
			}
			else if (req->flags & CF_READ_TIMEOUT) {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				s->flags |= SF_ERR_CLITO;
			}
			else if (req->flags & CF_WRITE_ERROR) {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				s->flags |= SF_ERR_SRVCL;
			}
			else {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				s->flags |= SF_ERR_SRVTO;
			}
			sess_set_term_flags(s);

			/* Abort the request if a client error occurred while
			 * the backend stream-interface is in the SI_ST_INI
			 * state. It is switched into the SI_ST_CLO state and
			 * the request channel is erased. */
			if (si_b->state == SI_ST_INI) {
				si_b->state = SI_ST_CLO;
				channel_abort(req);
				if (IS_HTX_STRM(s))
					channel_htx_erase(req, htxbuf(&req->buf));
				else
					channel_erase(req);
			}
		}
		else if (res->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) {
			/* Report it if the server got an error or a read timeout expired */
			res->analysers &= AN_RES_FLT_END;
			if (res->flags & CF_READ_ERROR) {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				s->flags |= SF_ERR_SRVCL;
			}
			else if (res->flags & CF_READ_TIMEOUT) {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				s->flags |= SF_ERR_SRVTO;
			}
			else if (res->flags & CF_WRITE_ERROR) {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				s->flags |= SF_ERR_CLICL;
			}
			else {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				s->flags |= SF_ERR_CLITO;
			}
			sess_set_term_flags(s);
		}
	}

	/*
	 * Here we take care of forwarding unhandled data. This also includes
	 * connection establishments and shutdown requests.
	 */


	/* If no one is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking CF_SHUTR_NOW as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely((!req->analysers || (req->analysers == AN_REQ_FLT_END && !(req->flags & CF_FLT_ANALYZE))) &&
	    !(req->flags & (CF_SHUTW|CF_SHUTR_NOW)) &&
	    (si_state_in(si_f->state, SI_SB_EST|SI_SB_DIS|SI_SB_CLO)) &&
	    (req->to_forward != CHN_INFINITE_FORWARD))) {
		/* This buffer is freewheeling, there's no analyser
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		channel_auto_read(req);
		channel_auto_connect(req);
		channel_auto_close(req);

		if (IS_HTX_STRM(s)) {
			struct htx *htx = htxbuf(&req->buf);

			/* We'll let data flow between the producer (if still connected)
			 * to the consumer.
			 */
			co_set_data(req, htx->data);
			if (!(req->flags & (CF_SHUTR|CF_SHUTW_NOW)))
				channel_htx_forward_forever(req, htx);
		}
		else {
			/* We'll let data flow between the producer (if still connected)
			 * to the consumer (which might possibly not be connected yet).
			 */
			c_adv(req, ci_data(req));
			if (!(req->flags & (CF_SHUTR|CF_SHUTW_NOW)))
				channel_forward_forever(req);
		}
	}

	/* check if it is wise to enable kernel splicing to forward request data */
	if (!(req->flags & (CF_KERN_SPLICING|CF_SHUTR)) &&
	    req->to_forward &&
	    (global.tune.options & GTUNE_USE_SPLICE) &&
	    (objt_cs(si_f->end) && __objt_cs(si_f->end)->conn->xprt && __objt_cs(si_f->end)->conn->xprt->rcv_pipe &&
	     __objt_cs(si_f->end)->conn->mux && __objt_cs(si_f->end)->conn->mux->rcv_pipe) &&
	    (objt_cs(si_b->end) && __objt_cs(si_b->end)->conn->xprt && __objt_cs(si_b->end)->conn->xprt->snd_pipe &&
	     __objt_cs(si_b->end)->conn->mux && __objt_cs(si_b->end)->conn->mux->snd_pipe) &&
	    (pipes_used < global.maxpipes) &&
	    (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_REQ) ||
	     (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (req->flags & CF_STREAMER_FAST)))) {
		req->flags |= CF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rqf_last = req->flags;

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
				if ((s->be->retry_type &~ PR_RE_CONN_FAILED) &&
				    (s->be->mode == PR_MODE_HTTP) &&
				    !(si_b->flags & SI_FL_D_L7_RETRY))
					si_b->flags |= SI_FL_L7_RETRY;
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
	if (si_state_in(si_b->state, SI_SB_REQ|SI_SB_QUE|SI_SB_TAR|SI_SB_ASS)) {
		/* prune the request variables and swap to the response variables. */
		if (s->vars_reqres.scope != SCOPE_RES) {
			if (!LIST_ISEMPTY(&s->vars_reqres.head))
				vars_prune(&s->vars_reqres, s->sess, s);
			vars_init_head(&s->vars_reqres, SCOPE_RES);
		}

		do {
			/* nb: step 1 might switch from QUE to ASS, but we first want
			 * to give a chance to step 2 to perform a redirect if needed.
			 */
			if (si_b->state != SI_ST_REQ)
				back_try_conn_req(s);
			if (si_b->state == SI_ST_REQ)
				back_handle_st_req(s);

			/* get a chance to complete an immediate connection setup */
			if (si_b->state == SI_ST_RDY)
				goto resync_stream_interface;

			/* applets directly go to the ESTABLISHED state. Similarly,
			 * servers experience the same fate when their connection
			 * is reused.
			 */
			if (unlikely(si_b->state == SI_ST_EST))
				back_establish(s);

			srv = objt_server(s->target);
			if (si_b->state == SI_ST_ASS && srv && srv->rdr_len && (s->flags & SF_REDIRECTABLE))
				http_perform_server_redirect(s, si_b);
		} while (si_b->state == SI_ST_ASS);
	}

	/* Let's see if we can send the pending request now */
	si_sync_send(si_b);

	/*
	 * Now forward all shutdown requests between both sides of the request buffer
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

	/* Benchmarks have shown that it's optimal to do a full resync now */
	if (si_f->state == SI_ST_DIS ||
	    si_state_in(si_b->state, SI_SB_RDY|SI_SB_DIS) ||
	    (si_f->flags & SI_FL_ERR && si_f->state != SI_ST_CLO) ||
	    (si_b->flags & SI_FL_ERR && si_b->state != SI_ST_CLO))
		goto resync_stream_interface;

	/* otherwise we want to check if we need to resync the req buffer or not */
	if ((req->flags ^ rqf_last) & (CF_SHUTR|CF_SHUTW))
		goto resync_request;

	/* perform output updates to the response buffer */

	/* If no one is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking CF_SHUTR_NOW as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely((!res->analysers || (res->analysers == AN_RES_FLT_END && !(res->flags & CF_FLT_ANALYZE))) &&
	    !(res->flags & (CF_SHUTW|CF_SHUTR_NOW)) &&
	    si_state_in(si_b->state, SI_SB_EST|SI_SB_DIS|SI_SB_CLO) &&
	    (res->to_forward != CHN_INFINITE_FORWARD))) {
		/* This buffer is freewheeling, there's no analyser
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		channel_auto_read(res);
		channel_auto_close(res);

		if (IS_HTX_STRM(s)) {
			struct htx *htx = htxbuf(&res->buf);

			/* We'll let data flow between the producer (if still connected)
			 * to the consumer.
			 */
			co_set_data(res, htx->data);
			if (!(res->flags & (CF_SHUTR|CF_SHUTW_NOW)))
				channel_htx_forward_forever(res, htx);
		}
		else {
			/* We'll let data flow between the producer (if still connected)
			 * to the consumer.
			 */
			c_adv(res, ci_data(res));
			if (!(res->flags & (CF_SHUTR|CF_SHUTW_NOW)))
				channel_forward_forever(res);
		}

		/* if we have no analyser anymore in any direction and have a
		 * tunnel timeout set, use it now. Note that we must respect
		 * the half-closed timeouts as well.
		 */
		if (!req->analysers && s->tunnel_timeout) {
			req->rto = req->wto = res->rto = res->wto =
				s->tunnel_timeout;

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
	    (objt_cs(si_f->end) && __objt_cs(si_f->end)->conn->xprt && __objt_cs(si_f->end)->conn->xprt->snd_pipe &&
	     __objt_cs(si_f->end)->conn->mux && __objt_cs(si_f->end)->conn->mux->snd_pipe) &&
	    (objt_cs(si_b->end) && __objt_cs(si_b->end)->conn->xprt && __objt_cs(si_b->end)->conn->xprt->rcv_pipe &&
	     __objt_cs(si_b->end)->conn->mux && __objt_cs(si_b->end)->conn->mux->rcv_pipe) &&
	    (pipes_used < global.maxpipes) &&
	    (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_RTR) ||
	     (((sess->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (res->flags & CF_STREAMER_FAST)))) {
		res->flags |= CF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rpf_last = res->flags;

	/* Let's see if we can send the pending response now */
	si_sync_send(si_f);

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

	if (si_f->state == SI_ST_DIS ||
	    si_state_in(si_b->state, SI_SB_RDY|SI_SB_DIS) ||
	    (si_f->flags & SI_FL_ERR && si_f->state != SI_ST_CLO) ||
	    (si_b->flags & SI_FL_ERR && si_b->state != SI_ST_CLO))
		goto resync_stream_interface;

	if ((req->flags & ~rqf_last) & CF_MASK_ANALYSER)
		goto resync_request;

	if ((res->flags ^ rpf_last) & CF_MASK_STATIC)
		goto resync_response;

	if (((req->flags ^ rqf_last) | (res->flags ^ rpf_last)) & CF_MASK_ANALYSER)
		goto resync_request;

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
			              objt_cs(si_f->end) ? (unsigned short)__objt_cs(si_f->end)->conn->handle.fd : -1,
			              objt_cs(si_b->end) ? (unsigned short)__objt_cs(si_b->end)->conn->handle.fd : -1);
			DISGUISE(write(1, trash.area, trash.data));
		}

		if (si_f->state == SI_ST_CLO &&
		    si_f->prev_state == SI_ST_EST) {
			chunk_printf(&trash, "%08x:%s.clicls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
			              objt_cs(si_f->end) ? (unsigned short)__objt_cs(si_f->end)->conn->handle.fd : -1,
			              objt_cs(si_b->end) ? (unsigned short)__objt_cs(si_b->end)->conn->handle.fd : -1);
			DISGUISE(write(1, trash.area, trash.data));
		}
	}

	if (likely((si_f->state != SI_ST_CLO) || !si_state_in(si_b->state, SI_SB_INI|SI_SB_CLO) ||
		   (req->analysers & AN_REQ_FLT_END) || (res->analysers & AN_RES_FLT_END))) {
		if ((sess->fe->options & PR_O_CONTSTATS) && (s->flags & SF_BE_ASSIGNED) && !(s->flags & SF_IGNORE))
			stream_process_counters(s);

		si_update_both(si_f, si_b);

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

		s->pending_events &= ~(TASK_WOKEN_TIMER | TASK_WOKEN_RES);
		stream_release_buffers(s);

		DBG_TRACE_DEVEL("queuing", STRM_EV_STRM_PROC, s);
		return t; /* nothing more to do */
	}

	DBG_TRACE_DEVEL("releasing", STRM_EV_STRM_PROC, s);

	if (s->flags & SF_BE_ASSIGNED)
		_HA_ATOMIC_DEC(&s->be->beconn);

	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		chunk_printf(&trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->id,
		              objt_cs(si_f->end) ? (unsigned short)__objt_cs(si_f->end)->conn->handle.fd : -1,
		              objt_cs(si_b->end) ? (unsigned short)__objt_cs(si_b->end)->conn->handle.fd : -1);
		DISGUISE(write(1, trash.area, trash.data));
	}

	if (!(s->flags & SF_IGNORE)) {
		s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);

		stream_process_counters(s);

		if (s->txn && s->txn->status) {
			int n;

			n = s->txn->status / 100;
			if (n < 1 || n > 5)
				n = 0;

			if (sess->fe->mode == PR_MODE_HTTP) {
				_HA_ATOMIC_INC(&sess->fe->fe_counters.p.http.rsp[n]);
			}
			if ((s->flags & SF_BE_ASSIGNED) &&
			    (s->be->mode == PR_MODE_HTTP)) {
				_HA_ATOMIC_INC(&s->be->be_counters.p.http.rsp[n]);
				_HA_ATOMIC_INC(&s->be->be_counters.p.http.cum_req);
			}
		}

		/* let's do a final log if we need it */
		if (!LIST_ISEMPTY(&sess->fe->logformat) && s->logs.logwait &&
		    !(s->flags & SF_MONITOR) &&
		    (!(sess->fe->options & PR_O_NULLNOLOG) || req->total)) {
			/* we may need to know the position in the queue */
			pendconn_free(s);
			s->do_log(s);
		}

		/* update time stats for this stream */
		stream_update_time_stats(s);
	}

	/* the task MUST not be in the run queue anymore */
	stream_free(s);
	task_destroy(t);
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
	unsigned int samples_window;

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
		samples_window = (((s->be->mode == PR_MODE_HTTP) ?
			srv->counters.p.http.cum_req : srv->counters.cum_lbconn) > TIME_STATS_SAMPLES) ? TIME_STATS_SAMPLES : 0;
		swrate_add_dynamic(&srv->counters.q_time, samples_window, t_queue);
		swrate_add_dynamic(&srv->counters.c_time, samples_window, t_connect);
		swrate_add_dynamic(&srv->counters.d_time, samples_window, t_data);
		swrate_add_dynamic(&srv->counters.t_time, samples_window, t_close);
		HA_ATOMIC_UPDATE_MAX(&srv->counters.qtime_max, t_queue);
		HA_ATOMIC_UPDATE_MAX(&srv->counters.ctime_max, t_connect);
		HA_ATOMIC_UPDATE_MAX(&srv->counters.dtime_max, t_data);
		HA_ATOMIC_UPDATE_MAX(&srv->counters.ttime_max, t_close);
	}
	samples_window = (((s->be->mode == PR_MODE_HTTP) ?
		s->be->be_counters.p.http.cum_req : s->be->be_counters.cum_lbconn) > TIME_STATS_SAMPLES) ? TIME_STATS_SAMPLES : 0;
	swrate_add_dynamic(&s->be->be_counters.q_time, samples_window, t_queue);
	swrate_add_dynamic(&s->be->be_counters.c_time, samples_window, t_connect);
	swrate_add_dynamic(&s->be->be_counters.d_time, samples_window, t_data);
	swrate_add_dynamic(&s->be->be_counters.t_time, samples_window, t_close);
	HA_ATOMIC_UPDATE_MAX(&s->be->be_counters.qtime_max, t_queue);
	HA_ATOMIC_UPDATE_MAX(&s->be->be_counters.ctime_max, t_connect);
	HA_ATOMIC_UPDATE_MAX(&s->be->be_counters.dtime_max, t_data);
	HA_ATOMIC_UPDATE_MAX(&s->be->be_counters.ttime_max, t_close);
}

/*
 * This function adjusts sess->srv_conn and maintains the previous and new
 * server's served stream counts. Setting newsrv to NULL is enough to release
 * current connection slot. This function also notifies any LB algo which might
 * expect to be informed about any change in the number of active streams on a
 * server.
 */
void sess_change_server(struct stream *strm, struct server *newsrv)
{
	struct server *oldsrv = strm->srv_conn;

	if (oldsrv == newsrv)
		return;

	if (oldsrv) {
		_HA_ATOMIC_DEC(&oldsrv->served);
		_HA_ATOMIC_DEC(&oldsrv->proxy->served);
		__ha_barrier_atomic_store();
		if (oldsrv->proxy->lbprm.server_drop_conn)
			oldsrv->proxy->lbprm.server_drop_conn(oldsrv);
		stream_del_srv_conn(strm);
	}

	if (newsrv) {
		_HA_ATOMIC_INC(&newsrv->served);
		_HA_ATOMIC_INC(&newsrv->proxy->served);
		__ha_barrier_atomic_store();
		if (newsrv->proxy->lbprm.server_take_conn)
			newsrv->proxy->lbprm.server_take_conn(newsrv);
		stream_add_srv_conn(strm, newsrv);
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

/* Appends a dump of the state of stream <s> into buffer <buf> which must have
 * preliminary be prepared by its caller, with each line prepended by prefix
 * <pfx>, and each line terminated by character <eol>.
 */
void stream_dump(struct buffer *buf, const struct stream *s, const char *pfx, char eol)
{
	const struct conn_stream *csf, *csb;
	const struct connection  *cof, *cob;
	const struct appctx      *acf, *acb;
	const struct server      *srv;
	const char *src = "unknown";
	const char *dst = "unknown";
	char pn[INET6_ADDRSTRLEN];
	const struct channel *req, *res;
	const struct stream_interface *si_f, *si_b;

	if (!s) {
		chunk_appendf(buf, "%sstrm=%p%c", pfx, s, eol);
		return;
	}

	if (s->obj_type != OBJ_TYPE_STREAM) {
		chunk_appendf(buf, "%sstrm=%p [invalid type=%d(%s)]%c",
		              pfx, s, s->obj_type, obj_type_name(&s->obj_type), eol);
		return;
	}

	si_f = &s->si[0];
	si_b = &s->si[1];
	req = &s->req;
	res = &s->res;

	csf = objt_cs(si_f->end);
	cof = cs_conn(csf);
	acf = objt_appctx(si_f->end);
	if (cof && cof->src && addr_to_str(cof->src, pn, sizeof(pn)) >= 0)
		src = pn;
	else if (acf)
		src = acf->applet->name;

	csb = objt_cs(si_b->end);
	cob = cs_conn(csb);
	acb = objt_appctx(si_b->end);
	srv = objt_server(s->target);
	if (srv)
		dst = srv->id;
	else if (acb)
		dst = acb->applet->name;

	chunk_appendf(buf,
	              "%sstrm=%p,%x src=%s fe=%s be=%s dst=%s%c"
		      "%stxn=%p,%x txn.req=%s,%x txn.rsp=%s,%x%c"
	              "%srqf=%x rqa=%x rpf=%x rpa=%x sif=%s,%x sib=%s,%x%c"
	              "%saf=%p,%u csf=%p,%x%c"
	              "%sab=%p,%u csb=%p,%x%c"
	              "%scof=%p,%x:%s(%p)/%s(%p)/%s(%d)%c"
	              "%scob=%p,%x:%s(%p)/%s(%p)/%s(%d)%c"
	              "",
	              pfx, s, s->flags, src, s->sess->fe->id, s->be->id, dst, eol,
		      pfx, s->txn, (s->txn ? s->txn->flags : 0),
		           (s->txn ? h1_msg_state_str(s->txn->req.msg_state): "-"), (s->txn ? s->txn->req.flags : 0),
		           (s->txn ? h1_msg_state_str(s->txn->rsp.msg_state): "-"), (s->txn ? s->txn->rsp.flags : 0), eol,
	              pfx, req->flags, req->analysers, res->flags, res->analysers,
	                   si_state_str(si_f->state), si_f->flags,
	                   si_state_str(si_b->state), si_b->flags, eol,
	              pfx, acf, acf ? acf->st0   : 0, csf, csf ? csf->flags : 0, eol,
	              pfx, acb, acb ? acb->st0   : 0, csb, csb ? csb->flags : 0, eol,
	              pfx, cof, cof ? cof->flags : 0, conn_get_mux_name(cof), cof?cof->ctx:0, conn_get_xprt_name(cof),
	                   cof ? cof->xprt_ctx : 0, conn_get_ctrl_name(cof), cof ? cof->handle.fd : 0, eol,
	              pfx, cob, cob ? cob->flags : 0, conn_get_mux_name(cob), cob?cob->ctx:0, conn_get_xprt_name(cob),
	                   cob ? cob->xprt_ctx : 0, conn_get_ctrl_name(cob), cob ? cob->handle.fd : 0, eol);
}

/* dumps an error message for type <type> at ptr <ptr> related to stream <s>,
 * having reached loop rate <rate>, then aborts hoping to retrieve a core.
 */
void stream_dump_and_crash(enum obj_type *obj, int rate)
{
	const struct stream *s;
	char *msg = NULL;
	const void *ptr;

	ptr = s = objt_stream(obj);
	if (!s) {
		const struct appctx *appctx = objt_appctx(obj);
		if (!appctx)
			return;
		ptr = appctx;
		s = si_strm(appctx->owner);
		if (!s)
			return;
	}

	chunk_reset(&trash);
	stream_dump(&trash, s, "", ' ');

	chunk_appendf(&trash, "filters={");
	if (HAS_FILTERS(s)) {
		struct filter *filter;

		list_for_each_entry(filter, &s->strm_flt.filters, list) {
			if (filter->list.p != &s->strm_flt.filters)
				chunk_appendf(&trash, ", ");
			chunk_appendf(&trash, "%p=\"%s\"", filter, FLT_ID(filter));
		}
	}
	chunk_appendf(&trash, "}");

	memprintf(&msg,
	          "A bogus %s [%p] is spinning at %d calls per second and refuses to die, "
	          "aborting now! Please report this error to developers "
	          "[%s]\n",
	          obj_type_name(obj), ptr, rate, trash.area);

	ha_alert("%s", msg);
	send_log(NULL, LOG_EMERG, "%s", msg);
	ABORT_NOW();
}

/* initialize the require structures */
static void init_stream()
{
	int thr;

	for (thr = 0; thr < MAX_THREADS; thr++)
		LIST_INIT(&ha_thread_ctx[thr].streams);
}
INITCALL0(STG_INIT, init_stream);

/* Generates a unique ID based on the given <format>, stores it in the given <strm> and
 * returns the unique ID.

 * If this function fails to allocate memory IST_NULL is returned.
 *
 * If an ID is already stored within the stream nothing happens existing unique ID is
 * returned.
 */
struct ist stream_generate_unique_id(struct stream *strm, struct list *format)
{
	if (isttest(strm->unique_id)) {
		return strm->unique_id;
	}
	else {
		char *unique_id;
		int length;
		if ((unique_id = pool_alloc(pool_head_uniqueid)) == NULL)
			return IST_NULL;

		length = build_logline(strm, unique_id, UNIQUEID_LEN, format);
		strm->unique_id = ist2(unique_id, length);

		return strm->unique_id;
	}
}

/************************************************************************/
/*           All supported ACL keywords must be declared here.          */
/************************************************************************/
static enum act_return stream_action_set_log_level(struct act_rule *rule, struct proxy *px,
						   struct session *sess, struct stream *s, int flags)
{
	s->logs.level = (uintptr_t)rule->arg.act.p[0];
	return ACT_RET_CONT;
}


/* Parse a "set-log-level" action. It takes the level value as argument. It
 * returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret stream_parse_set_log_level(const char **args, int *cur_arg, struct proxy *px,
						     struct act_rule *rule, char **err)
{
	int level;

	if (!*args[*cur_arg]) {
	  bad_log_level:
		memprintf(err, "expects exactly 1 argument (log level name or 'silent')");
		return ACT_RET_PRS_ERR;
	}
	if (strcmp(args[*cur_arg], "silent") == 0)
		level = -1;
	else if ((level = get_log_level(args[*cur_arg]) + 1) == 0)
		goto bad_log_level;

	(*cur_arg)++;

	/* Register processing function. */
	rule->action_ptr = stream_action_set_log_level;
	rule->action = ACT_CUSTOM;
	rule->arg.act.p[0] = (void *)(uintptr_t)level;
	return ACT_RET_PRS_OK;
}

static enum act_return stream_action_set_nice(struct act_rule *rule, struct proxy *px,
					      struct session *sess, struct stream *s, int flags)
{
	s->task->nice = (uintptr_t)rule->arg.act.p[0];
	return ACT_RET_CONT;
}


/* Parse a "set-nice" action. It takes the nice value as argument. It returns
 * ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret stream_parse_set_nice(const char **args, int *cur_arg, struct proxy *px,
						struct act_rule *rule, char **err)
{
	int nice;

	if (!*args[*cur_arg]) {
	  bad_log_level:
		memprintf(err, "expects exactly 1 argument (integer value)");
		return ACT_RET_PRS_ERR;
	}

	nice = atoi(args[*cur_arg]);
	if (nice < -1024)
		nice = -1024;
	else if (nice > 1024)
		nice = 1024;

	(*cur_arg)++;

	/* Register processing function. */
	rule->action_ptr = stream_action_set_nice;
	rule->action = ACT_CUSTOM;
	rule->arg.act.p[0] = (void *)(uintptr_t)nice;
	return ACT_RET_PRS_OK;
}


static enum act_return tcp_action_switch_stream_mode(struct act_rule *rule, struct proxy *px,
						  struct session *sess, struct stream *s, int flags)
{
	enum pr_mode mode = (uintptr_t)rule->arg.act.p[0];
	const struct mux_proto_list *mux_proto = rule->arg.act.p[1];

	if (!IS_HTX_STRM(s) && mode == PR_MODE_HTTP) {
		if (!stream_set_http_mode(s, mux_proto)) {
			channel_abort(&s->req);
			channel_abort(&s->res);
			return ACT_RET_ABRT;
		}
	}
	return ACT_RET_STOP;
}


static int check_tcp_switch_stream_mode(struct act_rule *rule, struct proxy *px, char **err)
{
	const struct mux_proto_list *mux_ent;
	const struct mux_proto_list *mux_proto = rule->arg.act.p[1];
	enum pr_mode pr_mode = (uintptr_t)rule->arg.act.p[0];
	enum proto_proxy_mode mode = (1 << (pr_mode == PR_MODE_HTTP));

	if (pr_mode == PR_MODE_HTTP)
		px->options |= PR_O_HTTP_UPG;

	if (mux_proto) {
		mux_ent = conn_get_best_mux_entry(mux_proto->token, PROTO_SIDE_FE, mode);
		if (!mux_ent || !isteq(mux_ent->token, mux_proto->token)) {
			memprintf(err, "MUX protocol '%.*s' is not compatible with the selected mode",
				  (int)mux_proto->token.len, mux_proto->token.ptr);
			return 0;
		}
	}
	else {
		mux_ent = conn_get_best_mux_entry(IST_NULL, PROTO_SIDE_FE, mode);
		if (!mux_ent) {
			memprintf(err, "Unable to find compatible MUX protocol with the selected mode");
			return 0;
		}
	}

	/* Update the mux */
	rule->arg.act.p[1] = (void *)mux_ent;
	return 1;

}

static enum act_parse_ret stream_parse_switch_mode(const char **args, int *cur_arg,
						   struct proxy *px, struct act_rule *rule,
						   char **err)
{
	const struct mux_proto_list *mux_proto = NULL;
	struct ist proto;
	enum pr_mode mode;

	/* must have at least the mode */
	if (*(args[*cur_arg]) == 0) {
		memprintf(err, "'%s %s' expects a mode as argument.", args[0], args[*cur_arg-1]);
		return ACT_RET_PRS_ERR;
	}

	if (!(px->cap & PR_CAP_FE)) {
		memprintf(err, "'%s %s' not allowed because %s '%s' has no frontend capability",
			  args[0], args[*cur_arg-1], proxy_type_str(px), px->id);
		return ACT_RET_PRS_ERR;
	}
	/* Check if the mode. For now "tcp" is disabled because downgrade is not
	 * supported and PT is the only TCP mux.
	 */
	if (strcmp(args[*cur_arg], "http") == 0)
		mode = PR_MODE_HTTP;
	else {
		memprintf(err, "'%s %s' expects a valid mode (got '%s').", args[0], args[*cur_arg-1], args[*cur_arg]);
		return ACT_RET_PRS_ERR;
	}

	/* check the proto, if specified */
	if (*(args[*cur_arg+1]) && strcmp(args[*cur_arg+1], "proto") == 0) {
		if (*(args[*cur_arg+2]) == 0) {
			memprintf(err, "'%s %s': '%s' expects a protocol as argument.",
				  args[0], args[*cur_arg-1], args[*cur_arg+1]);
			return ACT_RET_PRS_ERR;
		}

		proto = ist(args[*cur_arg + 2]);
		mux_proto = get_mux_proto(proto);
		if (!mux_proto) {
			memprintf(err, "'%s %s': '%s' expects a valid MUX protocol, if specified (got '%s')",
				  args[0], args[*cur_arg-1], args[*cur_arg+1], args[*cur_arg+2]);
			return ACT_RET_PRS_ERR;
		}
		*cur_arg += 2;
	}

	(*cur_arg)++;

	/* Register processing function. */
	rule->action_ptr = tcp_action_switch_stream_mode;
	rule->check_ptr  = check_tcp_switch_stream_mode;
	rule->action = ACT_CUSTOM;
	rule->arg.act.p[0] = (void *)(uintptr_t)mode;
	rule->arg.act.p[1] = (void *)mux_proto;
	return ACT_RET_PRS_OK;
}

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
	LIST_APPEND(&service_keywords, &kw_list->list);
}

struct action_kw *service_find(const char *kw)
{
	return action_lookup(&service_keywords, kw);
}

/* Lists the known services on <out> */
void list_services(FILE *out)
{
	struct action_kw_list *kw_list;
	int found = 0;
	int i;

	fprintf(out, "Available services :");
	list_for_each_entry(kw_list, &service_keywords, list) {
		for (i = 0; kw_list->kw[i].kw != NULL; i++) {
			found = 1;
			fprintf(out, " %s", kw_list->kw[i].kw);
		}
	}
	if (!found)
		fprintf(out, " none\n");
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
		if (ci_putchk(si_ic(si), &trash) == -1)
			goto full;
		goto done;
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
			     strm_li(strm) ? strm_li(strm)->rx.proto->name : "?");

		conn = objt_conn(strm_orig(strm));
		switch (conn && conn_get_src(conn) ? addr_to_str(conn->src, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " source=%s:%d\n",
			              pn, get_host_port(conn->src));
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
			     "  flags=0x%x, conn_retries=%d, srv_conn=%p, pend_pos=%p waiting=%d epoch=%#x\n",
			     strm->flags, strm->si[1].conn_retries, strm->srv_conn, strm->pend_pos,
			     LIST_INLIST(&strm->buffer_wait.list), strm->stream_epoch);

		chunk_appendf(&trash,
			     "  frontend=%s (id=%u mode=%s), listener=%s (id=%u)",
			     strm_fe(strm)->id, strm_fe(strm)->uuid, strm_fe(strm)->mode ? "http" : "tcp",
			     strm_li(strm) ? strm_li(strm)->name ? strm_li(strm)->name : "?" : "?",
			     strm_li(strm) ? strm_li(strm)->luid : 0);

		switch (conn && conn_get_dst(conn) ? addr_to_str(conn->dst, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(conn->dst));
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

		switch (conn && conn_get_src(conn) ? addr_to_str(conn->src, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(conn->src));
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
				     objt_server(strm->target) ? __objt_server(strm->target)->id : "<none>",
				     objt_server(strm->target) ? __objt_server(strm->target)->puid : 0);
		else
			chunk_appendf(&trash, "  server=<NONE> (id=-1)");

		switch (conn && conn_get_dst(conn) ? addr_to_str(conn->dst, pn, sizeof(pn)) : AF_UNSPEC) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(conn->dst));
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
			     "  task=%p (state=0x%02x nice=%d calls=%u rate=%u exp=%s tmask=0x%lx%s",
			     strm->task,
			     strm->task->state,
			     strm->task->nice, strm->task->calls, read_freq_ctr(&strm->call_rate),
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
			      "  txn=%p flags=0x%x meth=%d status=%d req.st=%s rsp.st=%s req.f=0x%02x rsp.f=0x%02x\n",
			      strm->txn, strm->txn->flags, strm->txn->meth, strm->txn->status,
			      h1_msg_state_str(strm->txn->req.msg_state), h1_msg_state_str(strm->txn->rsp.msg_state),
			      strm->txn->req.flags, strm->txn->rsp.flags);

		chunk_appendf(&trash,
			     "  si[0]=%p (state=%s flags=0x%02x endp0=%s:%p exp=%s et=0x%03x sub=%d)\n",
			     &strm->si[0],
			     si_state_str(strm->si[0].state),
			     strm->si[0].flags,
			     obj_type_name(strm->si[0].end),
			     obj_base_ptr(strm->si[0].end),
			     strm->si[0].exp ?
			             tick_is_expired(strm->si[0].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(strm->si[0].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			      strm->si[0].err_type, strm->si[0].wait_event.events);

		chunk_appendf(&trash,
			     "  si[1]=%p (state=%s flags=0x%02x endp1=%s:%p exp=%s et=0x%03x sub=%d)\n",
			     &strm->si[1],
			     si_state_str(strm->si[1].state),
			     strm->si[1].flags,
			     obj_type_name(strm->si[1].end),
			     obj_base_ptr(strm->si[1].end),
			     strm->si[1].exp ?
			             tick_is_expired(strm->si[1].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(strm->si[1].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     strm->si[1].err_type, strm->si[1].wait_event.events);

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
			              "      flags=0x%08x fd=%d fd.state=%02x updt=%d fd.tmask=0x%lx\n",
			              conn->flags,
			              conn->handle.fd,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].state : 0,
			              conn->handle.fd >= 0 ? !!(fdtab[conn->handle.fd].update_mask & tid_bit) : 0,
				      conn->handle.fd >= 0 ? fdtab[conn->handle.fd].thread_mask: 0);

			chunk_appendf(&trash, "      cs=%p csf=0x%08x ctx=%p\n", cs, cs->flags, cs->ctx);
		}
		else if ((tmpctx = objt_appctx(strm->si[0].end)) != NULL) {
			chunk_appendf(&trash,
			              "  app0=%p st0=%d st1=%d st2=%d applet=%s tmask=0x%lx nice=%d calls=%u rate=%u cpu=%llu lat=%llu\n",
				      tmpctx,
				      tmpctx->st0,
				      tmpctx->st1,
				      tmpctx->st2,
			              tmpctx->applet->name,
			              tmpctx->t->thread_mask,
			              tmpctx->t->nice, tmpctx->t->calls, read_freq_ctr(&tmpctx->call_rate),
			              (unsigned long long)tmpctx->t->cpu_time, (unsigned long long)tmpctx->t->lat_time);
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
			              "      flags=0x%08x fd=%d fd.state=%02x updt=%d fd.tmask=0x%lx\n",
			              conn->flags,
			              conn->handle.fd,
			              conn->handle.fd >= 0 ? fdtab[conn->handle.fd].state : 0,
			              conn->handle.fd >= 0 ? !!(fdtab[conn->handle.fd].update_mask & tid_bit) : 0,
				      conn->handle.fd >= 0 ? fdtab[conn->handle.fd].thread_mask: 0);

			chunk_appendf(&trash, "      cs=%p csf=0x%08x ctx=%p\n", cs, cs->flags, cs->ctx);
		}
		else if ((tmpctx = objt_appctx(strm->si[1].end)) != NULL) {
			chunk_appendf(&trash,
			              "  app1=%p st0=%d st1=%d st2=%d applet=%s tmask=0x%lx nice=%d calls=%u rate=%u cpu=%llu lat=%llu\n",
				      tmpctx,
				      tmpctx->st0,
				      tmpctx->st1,
				      tmpctx->st2,
			              tmpctx->applet->name,
			              tmpctx->t->thread_mask,
			              tmpctx->t->nice, tmpctx->t->calls, read_freq_ctr(&tmpctx->call_rate),
			              (unsigned long long)tmpctx->t->cpu_time, (unsigned long long)tmpctx->t->lat_time);
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
			     "      buf=%p data=%p o=%u p=%u i=%u size=%u\n",
			     strm->req.wex ?
			     human_time(TICKS_TO_MS(strm->req.wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     &strm->req.buf,
		             b_orig(&strm->req.buf), (unsigned int)co_data(&strm->req),
			     (unsigned int)ci_head_ofs(&strm->req), (unsigned int)ci_data(&strm->req),
			     (unsigned int)strm->req.buf.size);

		if (IS_HTX_STRM(strm)) {
			struct htx *htx = htxbuf(&strm->req.buf);

			chunk_appendf(&trash,
				      "      htx=%p flags=0x%x size=%u data=%u used=%u wrap=%s extra=%llu\n",
				      htx, htx->flags, htx->size, htx->data, htx_nbblks(htx),
				      (htx->tail >= htx->head) ? "NO" : "YES",
				      (unsigned long long)htx->extra);
		}
		if (HAS_FILTERS(strm) && strm_flt(strm)->current[0]) {
			struct filter *flt = strm_flt(strm)->current[0];

			chunk_appendf(&trash, "      current_filter=%p (id=\"%s\" flags=0x%x pre=0x%x post=0x%x) \n",
				      flt, flt->config->id, flt->flags, flt->pre_analyzers, flt->post_analyzers);
		}

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
			     "      buf=%p data=%p o=%u p=%u i=%u size=%u\n",
			     strm->res.wex ?
			     human_time(TICKS_TO_MS(strm->res.wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     &strm->res.buf,
		             b_orig(&strm->res.buf), (unsigned int)co_data(&strm->res),
		             (unsigned int)ci_head_ofs(&strm->res), (unsigned int)ci_data(&strm->res),
			     (unsigned int)strm->res.buf.size);

		if (IS_HTX_STRM(strm)) {
			struct htx *htx = htxbuf(&strm->res.buf);

			chunk_appendf(&trash,
				      "      htx=%p flags=0x%x size=%u data=%u used=%u wrap=%s extra=%llu\n",
				      htx, htx->flags, htx->size, htx->data, htx_nbblks(htx),
				      (htx->tail >= htx->head) ? "NO" : "YES",
				      (unsigned long long)htx->extra);
		}
		if (HAS_FILTERS(strm) && strm_flt(strm)->current[1]) {
			struct filter *flt = strm_flt(strm)->current[1];

			chunk_appendf(&trash, "      current_filter=%p (id=\"%s\" flags=0x%x pre=0x%x post=0x%x) \n",
				      flt, flt->config->id, flt->flags, flt->pre_analyzers, flt->post_analyzers);
		}

		if (strm->current_rule_list && strm->current_rule) {
			const struct act_rule *rule = strm->current_rule;
			chunk_appendf(&trash, "  current_rule=\"%s\" [%s:%d]\n", rule->kw->kw, rule->conf.file, rule->conf.line);
		}

		if (ci_putchk(si_ic(si), &trash) == -1)
			goto full;

		/* use other states to dump the contents */
	}
	/* end of dump */
 done:
	appctx->ctx.sess.uid = 0;
	appctx->ctx.sess.section = 0;
	return 1;
 full:
	return 0;
}


static int cli_parse_show_sess(char **args, char *payload, struct appctx *appctx, void *private)
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
	appctx->ctx.sess.thr = 0;

	/* let's set our own stream's epoch to the current one and increment
	 * it so that we know which streams were already there before us.
	 */
	si_strm(appctx->owner)->stream_epoch = _HA_ATOMIC_FETCH_ADD(&stream_epoch, 1);
	return 0;
}

/* This function dumps all streams' states onto the stream interface's
 * read buffer. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero. It proceeds in an isolated
 * thread so there is no thread safety issue here.
 */
static int cli_io_handler_dump_sess(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct connection *conn;

	thread_isolate();

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW))) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last stream being dumped.
		 */
		if (appctx->st2 == STAT_ST_LIST) {
			if (!LIST_ISEMPTY(&appctx->ctx.sess.bref.users)) {
				LIST_DELETE(&appctx->ctx.sess.bref.users);
				LIST_INIT(&appctx->ctx.sess.bref.users);
			}
		}
		goto done;
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
		appctx->ctx.sess.bref.ref = ha_thread_ctx[appctx->ctx.sess.thr].streams.n;
		appctx->st2 = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		/* first, let's detach the back-ref from a possible previous stream */
		if (!LIST_ISEMPTY(&appctx->ctx.sess.bref.users)) {
			LIST_DELETE(&appctx->ctx.sess.bref.users);
			LIST_INIT(&appctx->ctx.sess.bref.users);
		}

		/* and start from where we stopped */
		while (1) {
			char pn[INET6_ADDRSTRLEN];
			struct stream *curr_strm;
			int done= 0;

			if (appctx->ctx.sess.bref.ref == &ha_thread_ctx[appctx->ctx.sess.thr].streams)
				done = 1;
			else {
				/* check if we've found a stream created after issuing the "show sess" */
				curr_strm = LIST_ELEM(appctx->ctx.sess.bref.ref, struct stream *, list);
				if ((int)(curr_strm->stream_epoch - si_strm(appctx->owner)->stream_epoch) > 0)
					done = 1;
			}

			if (done) {
				appctx->ctx.sess.thr++;
				if (appctx->ctx.sess.thr >= global.nbthread)
					break;
				appctx->ctx.sess.bref.ref = ha_thread_ctx[appctx->ctx.sess.thr].streams.n;
				continue;
			}

			if (appctx->ctx.sess.target) {
				if (appctx->ctx.sess.target != (void *)-1 && appctx->ctx.sess.target != curr_strm)
					goto next_sess;

				LIST_APPEND(&curr_strm->back_refs, &appctx->ctx.sess.bref.users);
				/* call the proper dump() function and return if we're missing space */
				if (!stats_dump_full_strm_to_buffer(si, curr_strm))
					goto full;

				/* stream dump complete */
				LIST_DELETE(&appctx->ctx.sess.bref.users);
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
				     strm_li(curr_strm) ? strm_li(curr_strm)->rx.proto->name : "?");

			conn = objt_conn(strm_orig(curr_strm));
			switch (conn && conn_get_src(conn) ? addr_to_str(conn->src, pn, sizeof(pn)) : AF_UNSPEC) {
			case AF_INET:
			case AF_INET6:
				chunk_appendf(&trash,
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     get_host_port(conn->src),
					     strm_fe(curr_strm)->id,
					     (curr_strm->be->cap & PR_CAP_BE) ? curr_strm->be->id : "<NONE>",
					     objt_server(curr_strm->target) ? __objt_server(curr_strm->target)->id : "<none>"
					     );
				break;
			case AF_UNIX:
				chunk_appendf(&trash,
					     " src=unix:%d fe=%s be=%s srv=%s",
					     strm_li(curr_strm)->luid,
					     strm_fe(curr_strm)->id,
					     (curr_strm->be->cap & PR_CAP_BE) ? curr_strm->be->id : "<NONE>",
					     objt_server(curr_strm->target) ? __objt_server(curr_strm->target)->id : "<none>"
					     );
				break;
			}

			chunk_appendf(&trash,
				     " ts=%02x epoch=%#x age=%s calls=%u rate=%u cpu=%llu lat=%llu",
			             curr_strm->task->state, curr_strm->stream_epoch,
				     human_time(now.tv_sec - curr_strm->logs.tv_accept.tv_sec, 1),
			             curr_strm->task->calls, read_freq_ctr(&curr_strm->call_rate),
			             (unsigned long long)curr_strm->task->cpu_time, (unsigned long long)curr_strm->task->lat_time);

			chunk_appendf(&trash,
				     " rq[f=%06xh,i=%u,an=%02xh,rx=%s",
				     curr_strm->req.flags,
			             (unsigned int)ci_data(&curr_strm->req),
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
				     " rp[f=%06xh,i=%u,an=%02xh,rx=%s",
				     curr_strm->res.flags,
			             (unsigned int)ci_data(&curr_strm->res),
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
				LIST_APPEND(&curr_strm->back_refs, &appctx->ctx.sess.bref.users);
				goto full;
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

			if (ci_putchk(si_ic(si), &trash) == -1)
				goto full;

			appctx->ctx.sess.target = NULL;
			appctx->ctx.sess.uid = 0;
			goto done;
		}
		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		goto done;
	}
 done:
	thread_release();
	return 1;
 full:
	thread_release();
	si_rx_room_blk(si);
	return 0;
}

static void cli_release_show_sess(struct appctx *appctx)
{
	if (appctx->st2 == STAT_ST_LIST && appctx->ctx.sess.thr < global.nbthread) {
		/* a dump was aborted, either in error or timeout. We need to
		 * safely detach from the target stream's list. It's mandatory
		 * to lock because a stream on the target thread could be moving
		 * our node.
		 */
		thread_isolate();
		if (!LIST_ISEMPTY(&appctx->ctx.sess.bref.users))
			LIST_DELETE(&appctx->ctx.sess.bref.users);
		thread_release();
	}
}

/* Parses the "shutdown session" directive, it always returns 1 */
static int cli_parse_shutdown_session(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct stream *strm, *ptr;
	int thr;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[2])
		return cli_err(appctx, "Session pointer expected (use 'show sess').\n");

	ptr = (void *)strtoul(args[2], NULL, 0);
	strm = NULL;

	thread_isolate();

	/* first, look for the requested stream in the stream table */
	for (thr = 0; !strm && thr < global.nbthread; thr++) {
		list_for_each_entry(strm, &ha_thread_ctx[thr].streams, list) {
			if (strm == ptr) {
				stream_shutdown(strm, SF_ERR_KILLED);
				break;
			}
		}
	}

	thread_release();

	/* do we have the stream ? */
	if (!strm)
		return cli_err(appctx, "No such session (use 'show sess').\n");

	return 1;
}

/* Parses the "shutdown session server" directive, it always returns 1 */
static int cli_parse_shutdown_sessions_server(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[3]);
	if (!sv)
		return 1;

	/* kill all the stream that are on this server */
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	srv_shutdown_streams(sv, SF_ERR_KILLED);
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "sess",  NULL },             "show sess [id]                          : report the list of current sessions or dump this exact session", cli_parse_show_sess, cli_io_handler_dump_sess, cli_release_show_sess },
	{ { "shutdown", "session",  NULL },      "shutdown session [id]                   : kill a specific session",                                        cli_parse_shutdown_session, NULL, NULL },
	{ { "shutdown", "sessions",  "server" }, "shutdown sessions server <bk>/<srv>     : kill sessions on a server",                                      cli_parse_shutdown_sessions_server, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* main configuration keyword registration. */
static struct action_kw_list stream_tcp_req_keywords = { ILH, {
	{ "set-log-level", stream_parse_set_log_level },
	{ "set-nice",      stream_parse_set_nice },
	{ "switch-mode",   stream_parse_switch_mode },
	{ "use-service",   stream_parse_use_service },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &stream_tcp_req_keywords);

/* main configuration keyword registration. */
static struct action_kw_list stream_tcp_res_keywords = { ILH, {
	{ "set-log-level", stream_parse_set_log_level },
	{ "set-nice",     stream_parse_set_nice },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &stream_tcp_res_keywords);

static struct action_kw_list stream_http_req_keywords = { ILH, {
	{ "set-log-level", stream_parse_set_log_level },
	{ "set-nice",      stream_parse_set_nice },
	{ "use-service",   stream_parse_use_service },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &stream_http_req_keywords);

static struct action_kw_list stream_http_res_keywords = { ILH, {
	{ "set-log-level", stream_parse_set_log_level },
	{ "set-nice",      stream_parse_set_nice },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_res_keywords_register, &stream_http_res_keywords);

static int smp_fetch_cur_server_timeout(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	if (!smp->strm)
		return 0;

	smp->data.u.sint = TICKS_TO_MS(smp->strm->res.rto);
	return 1;
}

static int smp_fetch_cur_tunnel_timeout(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	if (!smp->strm)
		return 0;

	smp->data.u.sint = TICKS_TO_MS(smp->strm->tunnel_timeout);
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "cur_server_timeout", smp_fetch_cur_server_timeout, 0, NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ "cur_tunnel_timeout", smp_fetch_cur_tunnel_timeout, 0, NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
