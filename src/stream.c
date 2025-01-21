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
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/resolvers.h>
#include <haproxy/sample.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>
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
 *   sc    - stream connector
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

	{ .mask = STRM_EV_CS_ST,        .name = "sc_state",     .desc = "processing connector states" },

	{ .mask = STRM_EV_HTTP_ANA,     .name = "http_ana",     .desc = "HTTP analyzers" },
	{ .mask = STRM_EV_HTTP_ERR,     .name = "http_err",     .desc = "error during HTTP analyzis" },

	{ .mask = STRM_EV_TCP_ANA,      .name = "tcp_ana",      .desc = "TCP analyzers" },
	{ .mask = STRM_EV_TCP_ERR,      .name = "tcp_err",      .desc = "error during TCP analyzis" },

	{ .mask = STRM_EV_FLT_ANA,      .name = "flt_ana",      .desc = "Filter analyzers" },
	{ .mask = STRM_EV_FLT_ERR,      .name = "flt_err",      .desc = "error during filter analyzis" },
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
	{ .name="minimal",  .desc="report info on streams and connectors" },
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
	const struct channel *req, *res;
	struct htx *htx;

	if (!s || src->verbosity < STRM_VERB_CLEAN)
		return;

	task = s->task;
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

	/* Front and back stream connector state */
	chunk_appendf(&trace_buf, " SC=(%s,%s)",
		      sc_state_str(s->scf->state), sc_state_str(s->scb->state));

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
		const struct htx_blk *blk = __htx_get_head_blk(htx);
		const struct htx_sl  *sl  = htx_get_blk_ptr(htx, blk);
		enum htx_blk_type    type = htx_get_blk_type(blk);

		if (type == HTX_BLK_REQ_SL || type == HTX_BLK_RES_SL)
			chunk_appendf(&trace_buf, " - \"%.*s %.*s %.*s\"",
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
	}

		chunk_appendf(&trace_buf, " - t=%p t.exp=%d s=(%p,0x%08x,0x%x)",
			      task, tick_isset(task->expire) ? TICKS_TO_MS(task->expire - now_ms) : TICK_ETERNITY, s, s->flags, s->conn_err_type);

	/* If txn defined info about HTTP msgs, otherwise info about SI. */
	if (txn) {
		chunk_appendf(&trace_buf, " txn.flags=0x%08x, http.flags=(0x%08x,0x%08x) status=%d",
			      txn->flags, txn->req.flags, txn->rsp.flags, txn->status);
	}
	else {
		chunk_appendf(&trace_buf, " scf=(%p,%d,0x%08x,0x%x) scb=(%p,%d,0x%08x,0x%x) scf.exp(r,w)=(%d,%d) scb.exp(r,w)=(%d,%d) retries=%d",
			      s->scf, s->scf->state, s->scf->flags, s->scf->sedesc->flags,
			      s->scb, s->scb->state, s->scb->flags, s->scb->sedesc->flags,
			      tick_isset(sc_ep_rcv_ex(s->scf)) ? TICKS_TO_MS(sc_ep_rcv_ex(s->scf) - now_ms) : TICK_ETERNITY,
			      tick_isset(sc_ep_snd_ex(s->scf)) ? TICKS_TO_MS(sc_ep_snd_ex(s->scf) - now_ms) : TICK_ETERNITY,
			      tick_isset(sc_ep_rcv_ex(s->scb)) ? TICKS_TO_MS(sc_ep_rcv_ex(s->scb) - now_ms) : TICK_ETERNITY,
			      tick_isset(sc_ep_snd_ex(s->scb)) ? TICKS_TO_MS(sc_ep_snd_ex(s->scb) - now_ms) : TICK_ETERNITY,
			      s->conn_retries);
	}

	if (src->verbosity == STRM_VERB_MINIMAL)
		return;


	/* If txn defined, don't display all channel info */
	if (src->verbosity == STRM_VERB_SIMPLE || txn) {
		chunk_appendf(&trace_buf, " req=(%p .fl=0x%08x .exp=%d)",
			      req, req->flags, tick_isset(req->analyse_exp) ? TICKS_TO_MS(req->analyse_exp - now_ms) : TICK_ETERNITY);
		chunk_appendf(&trace_buf, " res=(%p .fl=0x%08x .exp=%d)",
			      res, res->flags, tick_isset(res->analyse_exp) ? TICKS_TO_MS(res->analyse_exp - now_ms) : TICK_ETERNITY);
	}
	else {
		chunk_appendf(&trace_buf, " req=(%p .fl=0x%08x .ana=0x%08x .exp=%u .o=%lu .tot=%llu .to_fwd=%u)",
			      req, req->flags, req->analysers, req->analyse_exp,
			      (long)req->output, req->total, req->to_forward);
		chunk_appendf(&trace_buf, " res=(%p .fl=0x%08x .ana=0x%08x .exp=%u .o=%lu .tot=%llu .to_fwd=%u)",
			      res, res->flags, res->analysers, res->analyse_exp,
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
			      (unsigned int)b_data(&res->buf), b_orig(&res->buf),
			      (unsigned int)b_head_ofs(&res->buf), (unsigned int)b_size(&res->buf));
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

/* Upgrade an existing stream for stream connector <sc>. Return < 0 on error. This
 * is only valid right after a TCP to H1 upgrade. The stream should be
 * "reativated" by removing SF_IGNORE flag. And the right mode must be set.  On
 * success, <input> buffer is transferred to the stream and thus points to
 * BUF_NULL. On error, it is unchanged and it is the caller responsibility to
 * release it (this never happens for now).
 */
int stream_upgrade_from_sc(struct stconn *sc, struct buffer *input)
{
	struct stream *s = __sc_strm(sc);
	const struct mux_ops *mux = sc_mux_ops(sc);

	if (mux) {
		if (mux->flags & MX_FL_HTX)
			s->flags |= SF_HTX;
	}

	if (!b_is_null(input)) {
		/* Xfer the input buffer to the request channel. <input> will
		 * than point to BUF_NULL. From this point, it is the stream
		 * responsibility to release it.
		 */
		s->req.buf = *input;
		*input = BUF_NULL;
		s->req.total = (IS_HTX_STRM(s) ? htxbuf(&s->req.buf)->data : b_data(&s->req.buf));
		sc_ep_report_read_activity(s->scf);
	}

	s->req.flags |= CF_READ_EVENT; /* Always report a read event */
	s->flags &= ~SF_IGNORE;

	task_wakeup(s->task, TASK_WOKEN_INIT);
	return 0;
}

/* Callback used to wake up a stream when an input buffer is available. The
 * stream <s>'s stream connectors are checked for a failed buffer allocation
 * as indicated by the presence of the SC_FL_NEED_BUFF flag and the lack of a
 * buffer, and and input buffer is assigned there (at most one). The function
 * returns 1 and wakes the stream up if a buffer was taken, otherwise zero.
 * It's designed to be called from __offer_buffer().
 */
int stream_buf_available(void *arg)
{
	struct stream *s = arg;

	if (!s->req.buf.size && !sc_ep_have_ff_data(s->scb) && s->scf->flags & SC_FL_NEED_BUFF)
		sc_have_buff(s->scf);

	if (!s->res.buf.size && !sc_ep_have_ff_data(s->scf) && s->scb->flags & SC_FL_NEED_BUFF)
		sc_have_buff(s->scb);

	s->flags |= SF_MAYALLOC;
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
struct stream *stream_new(struct session *sess, struct stconn *sc, struct buffer *input)
{
	struct stream *s;
	struct task *t;

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
	s->logs.request_ts = 0;
	s->logs.t_queue = -1;
	s->logs.t_connect = -1;
	s->logs.t_data = -1;
	s->logs.t_close = 0;
	s->logs.bytes_in = s->logs.bytes_out = 0;
	s->logs.prx_queue_pos = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_pos = 0; /* we will get this number soon */
	s->obj_type = OBJ_TYPE_STREAM;

	s->logs.accept_date = sess->accept_date;
	s->logs.accept_ts = sess->accept_ts;
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
	s->last_entity.type = STRM_ENTITY_NONE;
	s->last_entity.ptr = NULL;
	s->waiting_entity.type = STRM_ENTITY_NONE;
	s->waiting_entity.ptr = NULL;

	s->stkctr = NULL;
	if (pool_head_stk_ctr) {
		s->stkctr = pool_alloc(pool_head_stk_ctr);
		if (!s->stkctr)
			goto out_fail_alloc;

		/* Copy SC counters for the stream. We don't touch refcounts because
		 * any reference we have is inherited from the session. Since the stream
		 * doesn't exist without the session, the session's existence guarantees
		 * we don't lose the entry. During the store operation, the stream won't
		 * touch these ones.
		 */
		memcpy(s->stkctr, sess->stkctr, sizeof(s->stkctr[0]) * global.tune.nb_stk_ctr);
	}

	s->sess = sess;

	s->stream_epoch = _HA_ATOMIC_LOAD(&stream_epoch);
	s->uniq_id = _HA_ATOMIC_FETCH_ADD(&global.req_count, 1);
	s->term_evts_log = 0;

	/* OK, we're keeping the stream, so let's properly initialize the stream */
	LIST_INIT(&s->back_refs);

	LIST_INIT(&s->buffer_wait.list);
	s->buffer_wait.target = s;
	s->buffer_wait.wakeup_cb = stream_buf_available;

	s->lat_time = s->cpu_time = 0;
	s->call_rate.curr_tick = s->call_rate.curr_ctr = s->call_rate.prev_ctr = 0;
	s->passes_stconn = s->passes_reqana = s->passes_resana = s->passes_propag = 0;
	s->pcli_next_pid = 0;
	s->pcli_flags = 0;
	s->unique_id = IST_NULL;
	s->parent = NULL;
	if ((t = task_new_here()) == NULL)
		goto out_fail_alloc;

	s->task = t;
	s->pending_events = s->new_events = STRM_EVT_NONE;
	s->conn_retries = 0;
	s->max_retries = 0;
	s->conn_exp = TICK_ETERNITY;
	s->conn_err_type = STRM_ET_NONE;
	s->prev_conn_state = SC_ST_INI;
	t->process = process_stream;
	t->context = s;
	t->expire = TICK_ETERNITY;
	if (sess->listener)
		t->nice = sess->listener->bind_conf->nice;

	/* Note: initially, the stream's backend points to the frontend.
	 * This changes later when switching rules are executed or
	 * when the default backend is assigned.
	 */
	s->be  = sess->fe;
	s->req_cap = NULL;
	s->res_cap = NULL;

	/* Initialize all the variables contexts even if not used.
	 * This permits to prune these contexts without errors.
	 *
	 * We need to make sure that those lists are not re-initialized
	 * by stream-dependant underlying code because we could lose
	 * track of already defined variables, leading to data inconsistency
	 * and memory leaks...
	 *
	 * For reference: we had a very old bug caused by vars_txn and
	 * vars_reqres being accidentally re-initialized in http_create_txn()
	 * (https://github.com/haproxy/haproxy/issues/1935)
	 */
	vars_init_head(&s->vars_txn,    SCOPE_TXN);
	vars_init_head(&s->vars_reqres, SCOPE_REQ);

        /* Set SF_HTX flag for HTTP frontends. */
	if (sess->fe->mode == PR_MODE_HTTP)
		s->flags |= SF_HTX;

	s->scf = sc;
	if (sc_attach_strm(s->scf, s) < 0)
		goto out_fail_attach_scf;

	s->scb = sc_new_from_strm(s, SC_FL_ISBACK);
	if (!s->scb)
		goto out_fail_alloc_scb;

	sc_set_state(s->scf, SC_ST_EST);

	if (likely(sess->fe->options2 & PR_O2_INDEPSTR))
		s->scf->flags |= SC_FL_INDEP_STR;

	if (likely(sess->fe->options2 & PR_O2_INDEPSTR))
		s->scb->flags |= SC_FL_INDEP_STR;

	if (sc_ep_test(sc, SE_FL_WEBSOCKET))
		s->flags |= SF_WEBSOCKET;
	if (sc_conn(sc)) {
		const struct mux_ops *mux = sc_mux_ops(sc);

		if (mux && mux->flags & MX_FL_HTX)
			s->flags |= SF_HTX;
	}

	stream_init_srv_conn(s);
	s->target = sess->fe->default_target;

	s->pend_pos = NULL;
	s->priority_class = 0;
	s->priority_offset = 0;

	/* init store persistence */
	s->store_count = 0;

	channel_init(&s->req);
	s->req.flags |= CF_READ_EVENT; /* the producer is already connected */
	s->req.analysers = sess->listener ? sess->listener->bind_conf->analysers : sess->fe->fe_req_ana;

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

	s->scf->ioto = sess->fe->timeout.client;
	s->req.analyse_exp = TICK_ETERNITY;

	channel_init(&s->res);
	s->res.flags |= CF_ISRESP;
	s->res.analysers = 0;

	if (sess->fe->options2 & PR_O2_NODELAY) {
		s->scf->flags |= SC_FL_SND_NEVERWAIT;
		s->scb->flags |= SC_FL_SND_NEVERWAIT;
	}

	s->scb->ioto = TICK_ETERNITY;
	s->res.analyse_exp = TICK_ETERNITY;

	s->txn = NULL;
	s->hlua[0] = s->hlua[1] = NULL;

	s->resolv_ctx.requester = NULL;
	s->resolv_ctx.hostname_dn = NULL;
	s->resolv_ctx.hostname_dn_len = 0;
	s->resolv_ctx.parent = NULL;

	s->tunnel_timeout = TICK_ETERNITY;

	LIST_APPEND(&th_ctx->streams, &s->list);
	_HA_ATOMIC_INC(&th_ctx->total_streams);
	_HA_ATOMIC_INC(&th_ctx->stream_cnt);

	if (flt_stream_init(s) < 0 || flt_stream_start(s) < 0)
		goto out_fail_accept;

	/* just in case the caller would have pre-disabled it */
	se_will_consume(s->scf->sedesc);

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
		sc_ep_report_read_activity(s->scf);
	}

	/* it is important not to call the wakeup function directly but to
	 * pass through task_wakeup(), because this one knows how to apply
	 * priorities to tasks. Using multi thread we must be sure that
	 * stream is fully initialized before calling task_wakeup. So
	 * the caller must handle the task_wakeup
	 */
	DBG_TRACE_LEAVE(STRM_EV_STRM_NEW, s);
	task_wakeup(s->task, TASK_WOKEN_INIT);
	return s;

	/* Error unrolling */
 out_fail_accept:
	flt_stream_release(s, 0);
	LIST_DELETE(&s->list);
	sc_free(s->scb);
 out_fail_alloc_scb:
 out_fail_attach_scf:
	task_destroy(t);
 out_fail_alloc:
	if (s)
		pool_free(pool_head_stk_ctr, s->stkctr);
	pool_free(pool_head_stream, s);
	DBG_TRACE_DEVEL("leaving on error", STRM_EV_STRM_NEW|STRM_EV_STRM_ERR);
	return NULL;
}

/*
 * frees  the context associated to a stream. It must have been removed first.
 */
void stream_free(struct stream *s)
{
	struct session *sess = strm_sess(s);
	struct proxy *fe = sess->fe;
	struct bref *bref, *back;
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
		struct server *oldsrv = s->srv_conn;
		/* the stream still has a reserved slot on a server, but
		 * it should normally be only the same as the one above,
		 * so this should not happen in fact.
		 */
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(oldsrv, s->be))
			process_srv_queue(oldsrv);
	}

	/* We may still be present in the buffer wait queue */
	b_dequeue(&s->buffer_wait);

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

	hlua_ctx_destroy(s->hlua[0]);
	hlua_ctx_destroy(s->hlua[1]);
	s->hlua[0] = s->hlua[1] = NULL;

	if (s->txn)
		http_destroy_txn(s);

	/* ensure the client-side transport layer is destroyed */
	/* Be sure it is useless !! */
	/* if (cli_cs) */
	/* 	cs_close(cli_cs); */

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
			pool_free(fe->req_cap_pool, s->req_cap);
		}

		if (s->res_cap) {
			struct cap_hdr *h;
			for (h = fe->rsp_cap; h; h = h->next)
				pool_free(h->pool, s->res_cap[h->index]);
			pool_free(fe->rsp_cap_pool, s->res_cap);
		}
	}

	/* Cleanup all variable contexts. */
	vars_prune(&s->vars_txn, s->sess, s);
	vars_prune(&s->vars_reqres, s->sess, s);

	stream_store_counters(s);
	pool_free(pool_head_stk_ctr, s->stkctr);

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
	_HA_ATOMIC_DEC(&th_ctx->stream_cnt);

	sc_destroy(s->scb);
	sc_destroy(s->scf);

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
	if (b_alloc(&s->res.buf, DB_CHANNEL | ((s->flags & SF_MAYALLOC) ? DB_F_NOQUEUE : 0))) {
		s->flags &= ~SF_MAYALLOC;
		return 1;
	}

	b_requeue(DB_CHANNEL, &s->buffer_wait);
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

		for (i = 0; i < global.tune.nb_stk_ctr; i++) {
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

		for (i = 0; i < global.tune.nb_stk_ctr; i++) {
			if (!stkctr_inc_bytes_out_ctr(&s->stkctr[i], bytes))
				stkctr_inc_bytes_out_ctr(&sess->stkctr[i], bytes);
		}
	}
}

/* Abort processing on the both channels in same time */
void stream_abort(struct stream *s)
{
	channel_abort(&s->req);
	channel_abort(&s->res);
}

/*
 * Returns a message to the client ; the connection is shut down for read,
 * and the request is cleared so that no server connection can be initiated.
 * The buffer is marked for read shutdown on the other side to protect the
 * message, and the buffer write is enabled. The message is contained in a
 * "chunk". If it is null, then an empty message is used. The reply buffer does
 * not need to be empty before this, and its contents will not be overwritten.
 * The primary goal of this function is to return error messages to a client.
 */
void stream_retnclose(struct stream *s, const struct buffer *msg)
{
	struct channel *ic = &s->req;
	struct channel *oc = &s->res;

	channel_auto_read(ic);
	channel_abort(ic);
	channel_erase(ic);
	channel_truncate(oc);

	if (likely(msg && msg->data))
		co_inject(oc, msg->area, msg->data);

	channel_auto_read(oc);
	channel_auto_close(oc);
	sc_schedule_abort(s->scb);
}

int stream_set_timeout(struct stream *s, enum act_timeout_name name, int timeout)
{
	switch (name) {
	case ACT_TIMEOUT_CLIENT:
		s->scf->ioto = timeout;
		return 1;

	case ACT_TIMEOUT_SERVER:
		s->scb->ioto = timeout;
		return 1;

	case ACT_TIMEOUT_TUNNEL:
		s->tunnel_timeout = timeout;
		return 1;

	default:
		return 0;
	}
}

/*
 * This function handles the transition between the SC_ST_CON state and the
 * SC_ST_EST state. It must only be called after switching from SC_ST_CON (or
 * SC_ST_INI or SC_ST_RDY) to SC_ST_EST, but only when a ->proto is defined.
 * Note that it will switch the interface to SC_ST_DIS if we already have
 * the SC_FL_ABRT_DONE flag, it means we were able to forward the request, and
 * receive the response, before process_stream() had the opportunity to
 * make the switch from SC_ST_CON to SC_ST_EST. When that happens, we want
 * to go through back_establish() anyway, to make sure the analysers run.
 * Timeouts are cleared. Error are reported on the channel so that analysers
 * can handle them.
 */
void back_establish(struct stream *s)
{
	struct connection *conn = sc_conn(s->scb);
	struct channel *req = &s->req;
	struct channel *rep = &s->res;
	uint8_t do_log = 0;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
	/* First, centralize the timers information, and clear any irrelevant
	 * timeout.
	 */
	s->logs.t_connect = ns_to_ms(now_ns - s->logs.accept_ts);
	s->conn_exp = TICK_ETERNITY;
	s->flags &= ~SF_CONN_EXP;

	/* errors faced after sending data need to be reported */
	if ((s->scb->flags & SC_FL_ERROR) && req->flags & CF_WROTE_DATA) {
		s->req.flags |= CF_WRITE_EVENT;
		s->res.flags |= CF_READ_EVENT;
		s->conn_err_type = STRM_ET_DATA_ERR;
		DBG_TRACE_STATE("read/write error", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
	}

	if (objt_server(s->target))
		health_adjust(__objt_server(s->target), HANA_STATUS_L4_OK);

	if (strm_fe(s)->to_log == LW_LOGSTEPS) {
		if (log_orig_proxy(LOG_ORIG_TXN_CONNECT, strm_fe(s)))
			do_log = 1;
	}

	if (!IS_HTX_STRM(s)) { /* let's allow immediate data connection in this case */
		/* if the user wants to log as soon as possible, without counting
		 * bytes from the server, then this is the right moment. */
		if (strm_fe(s)->to_log != LW_LOGSTEPS &&
		    !lf_expr_isempty(&strm_fe(s)->logformat) && !(s->logs.logwait & LW_BYTES))
			do_log = 1;
	}
	else {
		s->scb->flags |= SC_FL_RCV_ONCE; /* a single read is enough to get response headers */
	}

	if (do_log) {
		/* note: no pend_pos here, session is established */
		s->logs.t_close = s->logs.t_connect; /* to get a valid end date */
		s->do_log(s, log_orig(LOG_ORIG_TXN_CONNECT, LOG_ORIG_FL_NONE));
	}

	rep->analysers |= strm_fe(s)->fe_rsp_ana | s->be->be_rsp_ana;

	se_have_more_data(s->scb->sedesc);
	rep->flags |= CF_READ_EVENT; /* producer is now attached */
	sc_ep_report_read_activity(s->scb);
	if (conn) {
		/* real connections have timeouts
		 * if already defined, it means that a set-timeout rule has
		 * been executed so do not overwrite them
		 */
		if (!tick_isset(s->scb->ioto))
			s->scb->ioto = s->be->timeout.server;
		if (!tick_isset(s->tunnel_timeout))
			s->tunnel_timeout = s->be->timeout.tunnel;

		/* The connection is now established, try to read data from the
		 * underlying layer, and subscribe to recv events. We use a
		 * delayed recv here to give a chance to the data to flow back
		 * by the time we process other tasks.
		 */
		sc_chk_rcv(s->scb);
	}
	/* If we managed to get the whole response, and we don't have anything
	 * left to send, or can't, switch to SC_ST_DIS now. */
	if ((s->scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) || (s->scf->flags & SC_FL_SHUT_DONE)) {
		s->scb->state = SC_ST_DIS;
		DBG_TRACE_STATE("response channel shutdwn for read/write", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
	}

	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
}

/* Set correct stream termination flags in case no analyser has done it. It
 * also counts a failed request if the server state has not reached the request
 * stage.
 */
void sess_set_term_flags(struct stream *s)
{
	if (!(s->flags & SF_FINST_MASK)) {
		if (s->scb->state == SC_ST_INI) {
			/* anything before REQ in fact */
			_HA_ATOMIC_INC(&strm_fe(s)->fe_counters.failed_req);
			if (strm_li(s) && strm_li(s)->counters)
				_HA_ATOMIC_INC(&strm_li(s)->counters->failed_req);

			s->flags |= SF_FINST_R;
		}
		else if (s->scb->state == SC_ST_QUE)
			s->flags |= SF_FINST_Q;
		else if (sc_state_in(s->scb->state, SC_SB_REQ|SC_SB_TAR|SC_SB_ASS|SC_SB_CON|SC_SB_CER|SC_SB_RDY))
			s->flags |= SF_FINST_C;
		else if (s->scb->state == SC_ST_EST || s->prev_conn_state == SC_ST_EST)
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
		appctx = sc_applet_create(s->scb, objt_applet(s->target));
		if (unlikely(!appctx))
			return ACT_RET_ERR;

		/* Finish initialisation of the context. */
		appctx->rule = rule;
		if (appctx_init(appctx) == -1)
			return ACT_RET_ERR;
	}
	else
		appctx = __sc_appctx(s->scb);

	if (rule->from != ACT_F_HTTP_REQ) {
		if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			_HA_ATOMIC_INC(&sess->fe->fe_counters.intercepted_req);

		/* The flag SF_ASSIGNED prevent from server assignment. */
		s->flags |= SF_ASSIGNED;
	}

	/* Now we can schedule the applet. */
	applet_need_more_data(appctx);
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
			struct proxy *backend = NULL;

			if (!acl_match_cond(rule->cond, fe, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL))
				continue;

			/* If the backend name is dynamic, try to resolve the name.
			 * If we can't resolve the name, or if any error occurs, break
			 * the loop and fallback to the default backend.
			 */

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

	/* Se the max connection retries for the stream. may be overwriten later */
	s->max_retries = s->be->conn_retries;

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
		if (!acl_match_cond(prst_rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL))
			continue;

		/* no rule, or the rule matches */
		if (prst_rule->type == PERSIST_TYPE_FORCE) {
			s->flags |= SF_FORCE_PRST;
		} else {
			s->flags |= SF_IGNORE_PRST;
		}
		break;
	}

	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA, s);
	return 1;

 sw_failed:
	/* immediately abort this request in case of allocation failure */
	stream_abort(s);

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
			struct server *srv;

			if (!acl_match_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL))
				continue;

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
		struct stktable_key *key;
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

		if (!acl_match_cond(rule->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL))
			continue;

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
		struct stktable_key *key;

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

		if (!acl_match_cond(rule->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL))
			continue;

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

	/* process store request and store response */
	for (i = 0; i < s->store_count; i++) {
		struct stksess *ts;
		void *ptr;
		char *key;
		struct dict_entry *de;
		struct stktable *t = s->store[i].table;

		if (!objt_server(s->target) || (__objt_server(s->target)->flags & SRV_F_NON_STICK)) {
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

		if (t->server_key_type == STKTABLE_SRV_NAME)
			key = __objt_server(s->target)->id;
		else if (t->server_key_type == STKTABLE_SRV_ADDR)
			key = __objt_server(s->target)->addr_node.key;
		else
			key = NULL;

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
		ptr = __stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_ID);
		stktable_data_cast(ptr, std_t_sint) = __objt_server(s->target)->puid;

		if (key) {
			de = dict_insert(&server_key_dict, key);
			if (de) {
				ptr = __stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_KEY);
				stktable_data_cast(ptr, std_t_dict) = de;
			}
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
	struct stconn *sc = s->scf;
	struct connection  *conn;

	/* Already an HTTP stream */
	if (IS_HTX_STRM(s))
		return 1;

	s->req.analysers |= AN_REQ_WAIT_HTTP|AN_REQ_HTTP_PROCESS_FE;

	if (unlikely(!s->txn && !http_create_txn(s)))
		return 0;

	conn = sc_conn(sc);

	if (!sc_conn_ready(sc))
		return 0;

	if (conn) {
		se_have_more_data(s->scf->sedesc);
		/* Make sure we're unsubscribed, the the new
		 * mux will probably want to subscribe to
		 * the underlying XPRT
		 */
		if (s->scf->wait_event.events)
			conn->mux->unsubscribe(sc, s->scf->wait_event.events, &(s->scf->wait_event));

		if (conn->mux->flags & MX_FL_NO_UPG)
			return 0;

		sc_conn_prepare_endp_upgrade(sc);
		if (conn_upgrade_mux_fe(conn, sc, &s->req.buf,
					(mux_proto ? mux_proto->token : ist("")),
					PROTO_MODE_HTTP)  == -1) {
			sc_conn_abort_endp_upgrade(sc);
			return 0;
		}
		sc_conn_commit_endp_upgrade(sc);

		s->req.flags &= ~(CF_READ_EVENT|CF_AUTO_CONNECT);
		s->req.total = 0;
		s->flags |= SF_IGNORE;
		if (sc_ep_test(sc, SE_FL_DETACHED)) {
			/* If stream connector is detached, it means it was not
			 * reused by the new mux. Son destroy it, disable
			 * logging, and abort the stream process. Thus the
			 * stream will be silently destroyed. The new mux will
			 * create new streams.
			 */
			s->logs.logwait = 0;
			s->logs.level = 0;
			stream_abort(s);
			s->req.analysers &= AN_REQ_FLT_END;
			s->req.analyse_exp = TICK_ETERNITY;
		}
	}

	return 1;
}


/* Updates at once the channel flags, and timers of both stream connectors of a
 * same stream, to complete the work after the analysers, then updates the data
 * layer below. This will ensure that any synchronous update performed at the
 * data layer will be reflected in the channel flags and/or stream connector.
 * Note that this does not change the stream connector's current state, though
 * it updates the previous state to the current one.
 */
void stream_update_both_sc(struct stream *s)
{
	struct stconn *scf = s->scf;
	struct stconn *scb = s->scb;
	struct channel *req = &s->req;
	struct channel *res = &s->res;

	req->flags &= ~(CF_READ_EVENT|CF_WRITE_EVENT);
	res->flags &= ~(CF_READ_EVENT|CF_WRITE_EVENT);

	s->prev_conn_state = scb->state;

	/* let's recompute both sides states */
	if (sc_state_in(scf->state, SC_SB_RDY|SC_SB_EST))
		sc_update(scf);

	if (sc_state_in(scb->state, SC_SB_RDY|SC_SB_EST))
		sc_update(scb);

	/* stream connectors are processed outside of process_stream() and must be
	 * handled at the latest moment.
	 */
	if (sc_appctx(scf)) {
		if (sc_is_recv_allowed(scf) || sc_is_send_allowed(scf))
			appctx_wakeup(__sc_appctx(scf));
	}
	if (sc_appctx(scb)) {
		if (sc_is_recv_allowed(scb) || sc_is_send_allowed(scb))
			appctx_wakeup(__sc_appctx(scb));
	}
}

/* check SC and channel timeouts, and close the corresponding stream connectors
 * for future reads or writes.
 * Note: this will also concern upper layers but we do not touch any other
 * flag. We must be careful and correctly detect state changes when calling
 * them.
 */
static void stream_handle_timeouts(struct stream *s)
{
	stream_check_conn_timeout(s);

	sc_check_timeouts(s->scf);
	channel_check_timeout(&s->req);
	sc_check_timeouts(s->scb);
	channel_check_timeout(&s->res);

	if (unlikely(!(s->scb->flags & SC_FL_SHUT_DONE) && (s->req.flags & CF_WRITE_TIMEOUT))) {
		stream_report_term_evt(s->scb, strm_tevt_type_tout);
		s->scb->flags |= SC_FL_NOLINGER;
		sc_shutdown(s->scb);
	}

	if (unlikely(!(s->scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) && (s->req.flags & CF_READ_TIMEOUT))) {
		stream_report_term_evt(s->scf, strm_tevt_type_tout);
		if (s->scf->flags & SC_FL_NOHALF)
			s->scf->flags |= SC_FL_NOLINGER;
		sc_abort(s->scf);
	}
	if (unlikely(!(s->scf->flags & SC_FL_SHUT_DONE) && (s->res.flags & CF_WRITE_TIMEOUT))) {
		stream_report_term_evt(s->scf, strm_tevt_type_tout);
		s->scf->flags |= SC_FL_NOLINGER;
		sc_shutdown(s->scf);
	}

	if (unlikely(!(s->scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) && (s->res.flags & CF_READ_TIMEOUT))) {
		stream_report_term_evt(s->scb, strm_tevt_type_tout);
		if (s->scb->flags & SC_FL_NOHALF)
			s->scb->flags |= SC_FL_NOLINGER;
		sc_abort(s->scb);
	}

	if (HAS_FILTERS(s))
		flt_stream_check_timeouts(s);
}

/* if the current task's wake_date was set, it's being profiled, thus we may
 * report latencies and CPU usages in logs, so it's desirable to update the
 * latency when entering process_stream().
 */
static void stream_cond_update_cpu_latency(struct stream *s)
{
	uint32_t lat;

	if (likely(!th_ctx->sched_wake_date))
		return;

	lat = th_ctx->sched_call_date - th_ctx->sched_wake_date;
	s->lat_time += lat;
}

/* if the current task's wake_date was set, it's being profiled, thus we may
 * report latencies and CPU usages in logs, so it's desirable to do that before
 * logging in order to report accurate CPU usage. In this case we count that
 * final part and reset the wake date so that the scheduler doesn't do it a
 * second time, and by doing so we also avoid an extra call to clock_gettime().
 * The CPU usage will be off by the little time needed to run over stream_free()
 * but that's only marginal.
 */
static void stream_cond_update_cpu_usage(struct stream *s)
{
	uint32_t cpu;

	/* stats are only registered for non-zero wake dates */
	if (likely(!th_ctx->sched_wake_date))
		return;

	cpu = now_mono_time() - th_ctx->sched_call_date;
	s->cpu_time += cpu;
	HA_ATOMIC_ADD(&th_ctx->sched_profile_entry->cpu_time, cpu);
	th_ctx->sched_wake_date = 0;
}

/* this functions is called directly by the scheduler for tasks whose
 * ->process points to process_stream(), and is used to keep latencies
 * and CPU usage measurements accurate.
 */
void stream_update_timings(struct task *t, uint64_t lat, uint64_t cpu)
{
	struct stream *s = t->context;
	s->lat_time += lat;
	s->cpu_time += cpu;
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
 *
 * TASK_WOKEN_* wake up reasons are mapped to STRM_EVT_*
 *
 * This task handler understands a few wake up events:
 *  - STRM_EVT_MSG forces analysers to be re-evaluated
 *  - STRM_EVT_TIMER forces timers to be re-evaluated
 *  - STRM_EVT_SHUT_SRV_DOWN shuts the stream down on server down
 *  - STRM_EVT_KILLED shuts the stream down on active kill
 *  - STRM_EVT_SHUT_SRV_UP shuts the stream down because a preferred backend became available
 */
struct task *process_stream(struct task *t, void *context, unsigned int state)
{
	struct server *srv;
	struct stream *s = context;
	struct session *sess = s->sess;
	unsigned int scf_flags, scb_flags;
	unsigned int rqf_last, rpf_last;
	unsigned int rq_prod_last, rq_cons_last;
	unsigned int rp_cons_last, rp_prod_last;
	unsigned int req_ana_back, res_ana_back;
	struct channel *req, *res;
	struct stconn *scf, *scb;
	unsigned int rate;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC, s);

	activity[tid].stream_calls++;
	stream_cond_update_cpu_latency(s);

	/* update pending events */
	s->pending_events |= stream_map_task_state(state);
	s->pending_events |= HA_ATOMIC_XCHG(&s->new_events, STRM_EVT_NONE);

	if (s->pending_events & (STRM_EVT_SHUT_SRV_DOWN|STRM_EVT_SHUT_SRV_UP|STRM_EVT_KILLED)) {
		/* that an instant kill message, the reason is in _UEVT* */
		stream_shutdown_self(s, ((s->pending_events & STRM_EVT_SHUT_SRV_DOWN) ? SF_ERR_DOWN :
					 (s->pending_events & STRM_EVT_SHUT_SRV_UP) ? SF_ERR_UP:
					 SF_ERR_KILLED));
	}

	req = &s->req;
	res = &s->res;

	scf = s->scf;
	scb = s->scb;

	/* First, attempt to receive pending data from I/O layers */
	sc_sync_recv(scf);
	sc_sync_recv(scb);

	/* Let's check if we're looping without making any progress, e.g. due
	 * to a bogus analyser or the fact that we're ignoring a read0. The
	 * call_rate counter only counts calls with no progress made.
	 */
	if (!((req->flags | res->flags) & (CF_READ_EVENT|CF_WRITE_EVENT))) {
		rate = update_freq_ctr(&s->call_rate, 1);
		if (rate >= 100000 && s->call_rate.prev_ctr) // make sure to wait at least a full second
			stream_dump_and_crash(&s->obj_type, read_freq_ctr(&s->call_rate));
	}

	/* this data may be no longer valid, clear it */
	if (s->txn)
		memset(&s->txn->auth, 0, sizeof(s->txn->auth));

	/* This flag must explicitly be set every time */
	req->flags &= ~CF_WAKE_WRITE;
	res->flags &= ~CF_WAKE_WRITE;

	/* Keep a copy of req/rep flags so that we can detect shutdowns */
	rqf_last = req->flags & ~CF_MASK_ANALYSER;
	rpf_last = res->flags & ~CF_MASK_ANALYSER;

	/* we don't want the stream connector functions to recursively wake us up */
	scf->flags |= SC_FL_DONT_WAKE;
	scb->flags |= SC_FL_DONT_WAKE;

	/* Keep a copy of SC flags */
	scf_flags = scf->flags;
	scb_flags = scb->flags;

	/* 1a: Check for low level timeouts if needed. We just set a flag on
	 * stream connectors when their timeouts have expired.
	 */
	if (unlikely(s->pending_events & STRM_EVT_TIMER)) {
		stream_handle_timeouts(s);

		/* Once in a while we're woken up because the task expires. But
		 * this does not necessarily mean that a timeout has been
		 * reached.  So let's not run a whole stream processing if only
		 * an expiration timeout needs to be refreshed. To do so, we
		 * must be sure only the TIMER event was triggered and not
		 * error/timeout/abort/shut occurred. on both sides.
		 */
		if (!((scf->flags | scb->flags) & (SC_FL_ERROR|SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_SHUT_DONE)) &&
		    !((req->flags | res->flags) & (CF_READ_EVENT|CF_READ_TIMEOUT|CF_WRITE_EVENT|CF_WRITE_TIMEOUT)) &&
		    !(s->flags & SF_CONN_EXP) &&
		    (s->pending_events  == STRM_EVT_TIMER)) {
			scf->flags &= ~SC_FL_DONT_WAKE;
			scb->flags &= ~SC_FL_DONT_WAKE;
			goto update_exp_and_leave;
		}
	}

 resync_stconns:
	if (!stream_alloc_work_buffer(s)) {
		scf->flags &= ~SC_FL_DONT_WAKE;
		scb->flags &= ~SC_FL_DONT_WAKE;
		/* we're stuck for now */
		t->expire = TICK_ETERNITY;
		goto leave;
	}

	/* 1b: check for low-level errors reported at the stream connector.
	 * First we check if it's a retryable error (in which case we don't
	 * want to tell the buffer). Otherwise we report the error one level
	 * upper by setting flags into the buffers. Note that the side towards
	 * the client cannot have connect (hence retryable) errors. Also, the
	 * connection setup code must be able to deal with any type of abort.
	 */
	s->passes_stconn++;
	srv = objt_server(s->target);
	if (unlikely(scf->flags & SC_FL_ERROR)) {
		if (sc_state_in(scf->state, SC_SB_EST|SC_SB_DIS)) {
			sc_abort(scf);
			sc_shutdown(scf);
			if (!(req->analysers) && !(res->analysers)) {
				COUNT_IF(1, "Report a client abort (no analysers)");
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

	if (unlikely(scb->flags & SC_FL_ERROR)) {
		if (sc_state_in(scb->state, SC_SB_EST|SC_SB_DIS)) {
			sc_abort(scb);
			sc_shutdown(scb);
			_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
			if (srv)
				_HA_ATOMIC_INC(&srv->counters.failed_resp);
			if (!(req->analysers) && !(res->analysers)) {
				COUNT_IF(1, "Report a client abort (no analysers)");
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

	if (sc_state_in(scb->state, SC_SB_CON|SC_SB_RDY)) {
		/* we were trying to establish a connection on the server side,
		 * maybe it succeeded, maybe it failed, maybe we timed out, ...
		 */
		if (scb->state == SC_ST_RDY)
			back_handle_st_rdy(s);
		else if (s->scb->state == SC_ST_CON)
			back_handle_st_con(s);

		if (scb->state == SC_ST_CER)
			back_handle_st_cer(s);
		else if (scb->state == SC_ST_EST)
			back_establish(s);

		/* state is now one of SC_ST_CON (still in progress), SC_ST_EST
		 * (established), SC_ST_DIS (abort), SC_ST_CLO (last error),
		 * SC_ST_ASS/SC_ST_TAR/SC_ST_REQ for retryable errors.
		 */
	}

	rq_prod_last = scf->state;
	rq_cons_last = scb->state;
	rp_cons_last = scf->state;
	rp_prod_last = scb->state;

	/* Check for connection closure */
	DBG_TRACE_POINT(STRM_EV_STRM_PROC, s);

	/* nothing special to be done on client side */
	if (unlikely(scf->state == SC_ST_DIS)) {
		scf->state = SC_ST_CLO;

		/* This is needed only when debugging is enabled, to indicate
		 * client-side close.
		 */
		if (unlikely((global.mode & MODE_DEBUG) &&
			     (!(global.mode & MODE_QUIET) ||
			      (global.mode & MODE_VERBOSE)))) {
			chunk_printf(&trash, "%08x:%s.clicls[%04x:%04x]\n",
				     s->uniq_id, s->be->id,
				     (unsigned short)conn_fd(sc_conn(scf)),
				     (unsigned short)conn_fd(sc_conn(scb)));
			DISGUISE(write(1, trash.area, trash.data));
		}
	}

	/* When a server-side connection is released, we have to count it and
	 * check for pending connections on this server.
	 */
	if (unlikely(scb->state == SC_ST_DIS)) {
		scb->state = SC_ST_CLO;
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

		/* This is needed only when debugging is enabled, to indicate
		 * server-side close.
		 */
		if (unlikely((global.mode & MODE_DEBUG) &&
			     (!(global.mode & MODE_QUIET) ||
			      (global.mode & MODE_VERBOSE)))) {
			if (s->prev_conn_state == SC_ST_EST) {
				chunk_printf(&trash, "%08x:%s.srvcls[%04x:%04x]\n",
					     s->uniq_id, s->be->id,
					     (unsigned short)conn_fd(sc_conn(scf)),
					     (unsigned short)conn_fd(sc_conn(scb)));
				DISGUISE(write(1, trash.area, trash.data));
			}
		}
	}

	/*
	 * Note: of the transient states (REQ, CER, DIS), only REQ may remain
	 * at this point.
	 */

 resync_request:
	s->passes_reqana++;
	/* Analyse request */
	if (((req->flags & ~rqf_last) & CF_MASK_ANALYSER) ||
	    ((scf->flags ^ scf_flags) & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) ||
	    ((scb->flags ^ scb_flags) & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) ||
	    (req->analysers && (scb->flags & SC_FL_SHUT_DONE)) ||
	    scf->state != rq_prod_last ||
	    scb->state != rq_cons_last ||
	    s->pending_events & STRM_EVT_MSG) {
		unsigned int scf_flags_ana = scf->flags;
		unsigned int scb_flags_ana = scb->flags;

		if (sc_state_in(scf->state, SC_SB_EST|SC_SB_DIS|SC_SB_CLO)) {
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

		rq_prod_last = scf->state;
		rq_cons_last = scb->state;
		req->flags &= ~CF_WAKE_ONCE;
		rqf_last = req->flags;
		scf_flags = (scf_flags & ~(SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) | (scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED));
		scb_flags = (scb_flags & ~(SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) | (scb->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED));

		if (((scf->flags ^ scf_flags_ana) & (SC_FL_EOS|SC_FL_ABRT_DONE)) || ((scb->flags ^ scb_flags_ana) & SC_FL_SHUT_DONE))
			goto resync_request;
	}

	/* we'll monitor the request analysers while parsing the response,
	 * because some response analysers may indirectly enable new request
	 * analysers (eg: HTTP keep-alive).
	 */
	req_ana_back = req->analysers;

 resync_response:
	s->passes_resana++;
	/* Analyse response */

	if (((res->flags & ~rpf_last) & CF_MASK_ANALYSER) ||
	    ((scb->flags ^ scb_flags) & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) ||
	    ((scf->flags ^ scf_flags) & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) ||
	    (res->analysers && (scf->flags & SC_FL_SHUT_DONE)) ||
	    scf->state != rp_cons_last ||
	    scb->state != rp_prod_last ||
	    s->pending_events & STRM_EVT_MSG) {
		unsigned int scb_flags_ana = scb->flags;
		unsigned int scf_flags_ana = scf->flags;

		if (sc_state_in(scb->state, SC_SB_EST|SC_SB_DIS|SC_SB_CLO)) {
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

		rp_cons_last = scf->state;
		rp_prod_last = scb->state;
		res->flags &= ~CF_WAKE_ONCE;
		rpf_last = res->flags;
		scb_flags = (scb_flags & ~(SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) | (scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED));
		scf_flags = (scf_flags & ~(SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) | (scf->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED));

		if (((scb->flags ^ scb_flags_ana) & (SC_FL_EOS|SC_FL_ABRT_DONE)) || ((scf->flags ^ scf_flags_ana) & SC_FL_SHUT_DONE))
			goto resync_response;
	}

	/* we'll monitor the response analysers because some response analysers
	 * may be enabled/disabled later
	 */
	res_ana_back = res->analysers;

	/* maybe someone has added some request analysers, so we must check and loop */
	if (req->analysers & ~req_ana_back)
		goto resync_request;

	if ((req->flags & ~rqf_last) & CF_MASK_ANALYSER)
		goto resync_request;

	/* FIXME: here we should call protocol handlers which rely on
	 * both buffers.
	 */

	s->passes_propag++;
	/*
	 * Now we propagate unhandled errors to the stream. Normally
	 * we're just in a data phase here since it means we have not
	 * seen any analyser who could set an error status.
	 */
	srv = objt_server(s->target);
	if (unlikely(!(s->flags & SF_ERR_MASK))) {
		if ((scf->flags & SC_FL_ERROR) || req->flags & (CF_READ_TIMEOUT|CF_WRITE_TIMEOUT)) {
			/* Report it if the client got an error or a read timeout expired */
			req->analysers &= AN_REQ_FLT_END;
			channel_auto_close(req);
			if (scf->flags & SC_FL_ERROR) {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				s->flags |= SF_ERR_CLICL;
				COUNT_IF(1, "Report unhandled client error");
			}
			else if (req->flags & CF_READ_TIMEOUT) {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				s->flags |= SF_ERR_CLITO;
				COUNT_IF(1, "Report unhandled client timeout (RD)");
			}
			else {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				s->flags |= SF_ERR_SRVTO;
				COUNT_IF(1, "Report unhandled server timeout (WR)");
			}
			sess_set_term_flags(s);

			/* Abort the request if a client error occurred while
			 * the backend stream connector is in the SC_ST_INI
			 * state. It is switched into the SC_ST_CLO state and
			 * the request channel is erased. */
			if (scb->state == SC_ST_INI) {
				s->scb->state = SC_ST_CLO;
				channel_abort(req);
				if (IS_HTX_STRM(s))
					channel_htx_erase(req, htxbuf(&req->buf));
				else
					channel_erase(req);
			}
		}
		else if ((scb->flags & SC_FL_ERROR) || res->flags & (CF_READ_TIMEOUT|CF_WRITE_TIMEOUT)) {
			/* Report it if the server got an error or a read timeout expired */
			res->analysers &= AN_RES_FLT_END;
			channel_auto_close(res);
			if (scb->flags & SC_FL_ERROR) {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				s->flags |= SF_ERR_SRVCL;
				COUNT_IF(1, "Report unhandled server error");
			}
			else if (res->flags & CF_READ_TIMEOUT) {
				_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.srv_aborts);
				s->flags |= SF_ERR_SRVTO;
				COUNT_IF(1, "Report unhandled server timeout (RD)");
			}
			else {
				_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
				_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
				if (srv)
					_HA_ATOMIC_INC(&srv->counters.cli_aborts);
				s->flags |= SF_ERR_CLITO;
				COUNT_IF(1, "Report unhandled client timeout (WR)");
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
	 * Note that we're checking SC_FL_ABRT_WANTED as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely((!req->analysers || (req->analysers == AN_REQ_FLT_END && !(req->flags & CF_FLT_ANALYZE))) &&
		     !(scf->flags & SC_FL_ABRT_WANTED) && !(scb->flags & SC_FL_SHUT_DONE) &&
		     (sc_state_in(scf->state, SC_SB_EST|SC_SB_DIS|SC_SB_CLO)) &&
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
			if ((global.tune.options & GTUNE_USE_FAST_FWD) &&
			    !(scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) && !(scb->flags & SC_FL_SHUT_WANTED))
				channel_htx_forward_forever(req, htx);
		}
		else {
			/* We'll let data flow between the producer (if still connected)
			 * to the consumer (which might possibly not be connected yet).
			 */
			c_adv(req, ci_data(req));
			if ((global.tune.options & GTUNE_USE_FAST_FWD) &&
			    !(scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) && !(scb->flags & SC_FL_SHUT_WANTED))
				channel_forward_forever(req);
		}
	}

	/* reflect what the L7 analysers have seen last */
	rqf_last = req->flags;
	scf_flags = (scf_flags & ~(SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) | (scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED));
	scb_flags = (scb_flags & ~(SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) | (scb->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED));

	/* it's possible that an upper layer has requested a connection setup or abort.
	 * There are 2 situations where we decide to establish a new connection :
	 *  - there are data scheduled for emission in the buffer
	 *  - the CF_AUTO_CONNECT flag is set (active connection)
	 */
	if (scb->state == SC_ST_INI) {
		if (!(scb->flags & SC_FL_SHUT_DONE)) {
			if ((req->flags & CF_AUTO_CONNECT) || co_data(req)) {
				/* If we have an appctx, there is no connect method, so we
				 * immediately switch to the connected state, otherwise we
				 * perform a connection request.
				 */
				scb->state = SC_ST_REQ; /* new connection requested */
				s->conn_retries = 0;
				if ((s->be->retry_type &~ PR_RE_CONN_FAILED) &&
				    (s->be->mode == PR_MODE_HTTP) &&
				    !(s->txn->flags & TX_D_L7_RETRY))
					s->txn->flags |= TX_L7_RETRY;

				if (s->be->options & PR_O_ABRT_CLOSE) {
					struct connection *conn = sc_conn(scf);

					se_have_more_data(scf->sedesc);
					if (conn && conn->mux && conn->mux->ctl)
						conn->mux->ctl(conn, MUX_CTL_SUBS_RECV, NULL);
				}
			}
		}
		else {
			s->scb->state = SC_ST_CLO; /* shutw+ini = abort */
			sc_schedule_shutdown(scb);
			sc_schedule_abort(scb);
		}
	}


	/* we may have a pending connection request, or a connection waiting
	 * for completion.
	 */
	if (sc_state_in(scb->state, SC_SB_REQ|SC_SB_QUE|SC_SB_TAR|SC_SB_ASS)) {
		/* prune the request variables and swap to the response variables. */
		if (s->vars_reqres.scope != SCOPE_RES) {
			vars_prune(&s->vars_reqres, s->sess, s);
			vars_init_head(&s->vars_reqres, SCOPE_RES);
		}

		do {
			/* nb: step 1 might switch from QUE to ASS, but we first want
			 * to give a chance to step 2 to perform a redirect if needed.
			 */
			if (scb->state != SC_ST_REQ)
				back_try_conn_req(s);
			if (scb->state == SC_ST_REQ)
				back_handle_st_req(s);

			/* get a chance to complete an immediate connection setup */
			if (scb->state == SC_ST_RDY)
				goto resync_stconns;

			/* applets directly go to the ESTABLISHED state. Similarly,
			 * servers experience the same fate when their connection
			 * is reused.
			 */
			if (unlikely(scb->state == SC_ST_EST))
				back_establish(s);

			srv = objt_server(s->target);
			if (scb->state == SC_ST_ASS && srv && srv->rdr_len && (s->flags & SF_REDIRECTABLE))
				http_perform_server_redirect(s, scb);
		} while (scb->state == SC_ST_ASS);
	}

	/* Let's see if we can send the pending request now */
	sc_sync_send(scb);

	/*
	 * Now forward all shutdown requests between both sides of the request buffer
	 */

	/* first, let's check if the request buffer needs to shutdown(write), which may
	 * happen either because the input is closed or because we want to force a close
	 * once the server has begun to respond. If a half-closed timeout is set, we adjust
	 * the other side's timeout as well. However this doesn't have effect during the
	 * connection setup unless the backend has abortonclose set.
	 */
	if (unlikely((req->flags & CF_AUTO_CLOSE) && (scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) &&
		     !(scb->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) &&
		     (scb->state != SC_ST_CON || (s->be->options & PR_O_ABRT_CLOSE)))) {
		sc_schedule_shutdown(scb);
	}

	/* shutdown(write) pending */
	if (unlikely((scb->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) == SC_FL_SHUT_WANTED &&
		     ((!co_data(req) && !sc_ep_have_ff_data(scb)) || (req->flags & CF_WRITE_TIMEOUT)))) {
		if (scf->flags & SC_FL_ERROR)
			scb->flags |= SC_FL_NOLINGER;
		sc_shutdown(scb);
	}

	/* shutdown(write) done on server side, we must stop the client too */
	if (unlikely((scb->flags & SC_FL_SHUT_DONE) && !(scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED))) &&
	    !req->analysers)
		sc_schedule_abort(scf);

	/* shutdown(read) pending */
	if (unlikely((scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) == SC_FL_ABRT_WANTED)) {
		if (scf->flags & SC_FL_NOHALF)
			scf->flags |= SC_FL_NOLINGER;
		sc_abort(scf);
	}

	/* Benchmarks have shown that it's optimal to do a full resync now */
	if (scf->state == SC_ST_DIS ||
	    sc_state_in(scb->state, SC_SB_RDY|SC_SB_DIS) ||
	    ((scf->flags & SC_FL_ERROR) && scf->state != SC_ST_CLO) ||
	    ((scb->flags & SC_FL_ERROR) && scb->state != SC_ST_CLO))
		goto resync_stconns;

	/* otherwise we want to check if we need to resync the req buffer or not */
	if (((scf->flags ^ scf_flags) & (SC_FL_EOS|SC_FL_ABRT_DONE)) || ((scb->flags ^ scb_flags) & SC_FL_SHUT_DONE))
		goto resync_request;

	/* perform output updates to the response buffer */

	/* If no one is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking SC_FL_ABRT_WANTED as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely((!res->analysers || (res->analysers == AN_RES_FLT_END && !(res->flags & CF_FLT_ANALYZE))) &&
		     !(scf->flags & SC_FL_ABRT_WANTED) && !(scb->flags & SC_FL_SHUT_WANTED) &&
		     sc_state_in(scb->state, SC_SB_EST|SC_SB_DIS|SC_SB_CLO) &&
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
			if ((global.tune.options & GTUNE_USE_FAST_FWD) &&
			    !(scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) && !(scb->flags & SC_FL_SHUT_WANTED))
				channel_htx_forward_forever(res, htx);
		}
		else {
			/* We'll let data flow between the producer (if still connected)
			 * to the consumer.
			 */
			c_adv(res, ci_data(res));
			if ((global.tune.options & GTUNE_USE_FAST_FWD) &&
			    !(scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) && !(scb->flags & SC_FL_SHUT_WANTED))
				channel_forward_forever(res);
		}

		/* if we have no analyser anymore in any direction and have a
		 * tunnel timeout set, use it now. Note that we must respect
		 * the half-closed timeouts as well.
		 */
		if (!req->analysers && s->tunnel_timeout) {
			scf->ioto = scb->ioto = s->tunnel_timeout;

			if (!IS_HTX_STRM(s)) {
				if ((scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_SHUT_DONE)) && tick_isset(sess->fe->timeout.clientfin))
					scf->ioto = sess->fe->timeout.clientfin;
				if ((scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_SHUT_DONE)) && tick_isset(s->be->timeout.serverfin))
					scb->ioto = s->be->timeout.serverfin;
			}
		}
	}

	/* reflect what the L7 analysers have seen last */
	rpf_last = res->flags;
	scb_flags = (scb_flags & ~(SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) | (scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED));
	scf_flags = (scf_flags & ~(SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) | (scf->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED));

	/* Let's see if we can send the pending response now */
	sc_sync_send(scf);

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/*
	 * FIXME: this is probably where we should produce error responses.
	 */

	/* first, let's check if the response buffer needs to shutdown(write) */
	if (unlikely((res->flags & CF_AUTO_CLOSE) && (scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) &&
		     !(scf->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)))) {
		sc_schedule_shutdown(scf);
	}

	/* shutdown(write) pending */
	if (unlikely((scf->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) == SC_FL_SHUT_WANTED &&
		     ((!co_data(res) && !sc_ep_have_ff_data(scf)) || (res->flags & CF_WRITE_TIMEOUT)))) {
		sc_shutdown(scf);
	}

	/* shutdown(write) done on the client side, we must stop the server too */
	if (unlikely((scf->flags & SC_FL_SHUT_DONE) && !(scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED))) &&
	    !res->analysers)
		sc_schedule_abort(scb);

	/* shutdown(read) pending */
	if (unlikely((scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) == SC_FL_ABRT_WANTED)) {
		if (scb->flags & SC_FL_NOHALF)
			scb->flags |= SC_FL_NOLINGER;
		sc_abort(scb);
	}

	if (scf->state == SC_ST_DIS ||
	    sc_state_in(scb->state, SC_SB_RDY|SC_SB_DIS) ||
	    ((scf->flags & SC_FL_ERROR) && scf->state != SC_ST_CLO) ||
	    ((scb->flags & SC_FL_ERROR) && scb->state != SC_ST_CLO))
		goto resync_stconns;

	if ((req->flags & ~rqf_last) & CF_MASK_ANALYSER)
		goto resync_request;

	if (((scb->flags ^ scb_flags) & (SC_FL_EOS|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED)) ||
	    ((scf->flags ^ scf_flags) & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)) ||
	    (res->analysers ^ res_ana_back))
		goto resync_response;

	if ((((req->flags ^ rqf_last) | (res->flags ^ rpf_last)) & CF_MASK_ANALYSER) ||
	    (req->analysers ^ req_ana_back))
		goto resync_request;

	/* we're interested in getting wakeups again */
	scf->flags &= ~SC_FL_DONT_WAKE;
	scb->flags &= ~SC_FL_DONT_WAKE;

	if (likely((scf->state != SC_ST_CLO) || !sc_state_in(scb->state, SC_SB_INI|SC_SB_CLO) ||
		   (req->analysers & AN_REQ_FLT_END) || (res->analysers & AN_RES_FLT_END))) {
		if ((sess->fe->options & PR_O_CONTSTATS) && (s->flags & SF_BE_ASSIGNED) && !(s->flags & SF_IGNORE))
			stream_process_counters(s);

		stream_update_both_sc(s);

		/* Reset pending events now */
		s->pending_events = STRM_EVT_NONE;

	update_exp_and_leave:
		/* Note: please ensure that if you branch here you disable SC_FL_DONT_WAKE */
		if (!req->analysers)
			req->analyse_exp = TICK_ETERNITY;
		if (!res->analysers)
			res->analyse_exp = TICK_ETERNITY;

		if ((sess->fe->options & PR_O_CONTSTATS) && (s->flags & SF_BE_ASSIGNED) &&
		          (!tick_isset(req->analyse_exp) || tick_is_expired(req->analyse_exp, now_ms)))
			req->analyse_exp = tick_add(now_ms, 5000);

		t->expire = (tick_is_expired(t->expire, now_ms) ? 0 : t->expire);
		t->expire = tick_first(t->expire, sc_ep_rcv_ex(scf));
		t->expire = tick_first(t->expire, sc_ep_snd_ex(scf));
		t->expire = tick_first(t->expire, sc_ep_rcv_ex(scb));
		t->expire = tick_first(t->expire, sc_ep_snd_ex(scb));
		t->expire = tick_first(t->expire, req->analyse_exp);
		t->expire = tick_first(t->expire, res->analyse_exp);
		t->expire = tick_first(t->expire, s->conn_exp);

		if (unlikely(tick_is_expired(t->expire, now_ms))) {
			/* Some events prevented the timeouts to be handled but nothing evolved.
			   So do it now and resyunc the stconns
			 */
			stream_handle_timeouts(s);
			goto resync_stconns;
		}
	leave:
		s->pending_events &= ~STRM_EVT_TIMER;
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
			     (unsigned short)conn_fd(sc_conn(scf)),
			     (unsigned short)conn_fd(sc_conn(scb)));
		DISGUISE(write(1, trash.area, trash.data));
	}

	if (!(s->flags & SF_IGNORE)) {
		uint8_t do_log = 0;

		s->logs.t_close = ns_to_ms(now_ns - s->logs.accept_ts);

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
		if (sess->fe->to_log == LW_LOGSTEPS) {
			if (log_orig_proxy(LOG_ORIG_TXN_CLOSE, sess->fe))
				do_log = 1;
		}
		else if (!lf_expr_isempty(&sess->fe->logformat) && s->logs.logwait)
			do_log = 1;

		if (do_log &&
		    !(s->flags & SF_MONITOR) &&
		    (!(sess->fe->options & PR_O_NULLNOLOG) || req->total)) {
			/* we may need to know the position in the queue */
			pendconn_free(s);

			stream_cond_update_cpu_usage(s);
			s->do_log(s, log_orig(LOG_ORIG_TXN_CLOSE, LOG_ORIG_FL_NONE));
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

	if ((llong)(s->logs.request_ts - s->logs.accept_ts) >= 0)
		t_request = ns_to_ms(s->logs.request_ts - s->logs.accept_ts);

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

	/* Dynamic servers may be deleted during process lifetime. This
	 * operation is always conducted under thread isolation. Several
	 * conditions prevent deletion, one of them is if server streams list
	 * is not empty. sess_change_server() uses stream_add_srv_conn() to
	 * ensure the latter condition.
	 *
	 * A race condition could exist for stream which referenced a server
	 * instance (s->target) without registering itself in its server list.
	 * This is notably the case for SF_DIRECT streams which referenced a
	 * server earlier during process_stream(). However at this time the
	 * code is deemed safe as process_stream() cannot be rescheduled before
	 * invocation of sess_change_server().
	 */

	/*
	 * It is assumed if the stream has a non-NULL srv_conn, then its
	 * served field has been incremented, so we have to decrement it now.
	 */
	if (oldsrv)
		_HA_ATOMIC_DEC(&oldsrv->served);

	if (oldsrv == newsrv)
		return;

	if (oldsrv) {
		_HA_ATOMIC_DEC(&oldsrv->proxy->served);
		__ha_barrier_atomic_store();
		if (oldsrv->proxy->lbprm.server_drop_conn)
			oldsrv->proxy->lbprm.server_drop_conn(oldsrv);
		stream_del_srv_conn(strm);
	}

	if (newsrv) {
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
 * them. It's installed as ->srv_error for the server-side stream connector.
 */
void default_srv_error(struct stream *s, struct stconn *sc)
{
	int err_type = s->conn_err_type;
	int err = 0, fin = 0;

	if (err_type & STRM_ET_QUEUE_ABRT) {
		err = SF_ERR_CLICL;
		fin = SF_FINST_Q;
	}
	else if (err_type & STRM_ET_CONN_ABRT) {
		err = SF_ERR_CLICL;
		fin = SF_FINST_C;
	}
	else if (err_type & STRM_ET_QUEUE_TO) {
		err = SF_ERR_SRVTO;
		fin = SF_FINST_Q;
	}
	else if (err_type & STRM_ET_QUEUE_ERR) {
		err = SF_ERR_SRVCL;
		fin = SF_FINST_Q;
	}
	else if (err_type & STRM_ET_CONN_TO) {
		err = SF_ERR_SRVTO;
		fin = SF_FINST_C;
	}
	else if (err_type & STRM_ET_CONN_ERR) {
		err = SF_ERR_SRVCL;
		fin = SF_FINST_C;
	}
	else if (err_type & STRM_ET_CONN_RES) {
		err = SF_ERR_RESOURCE;
		fin = SF_FINST_C;
	}
	else /* STRM_ET_CONN_OTHER and others */ {
		err = SF_ERR_INTERNAL;
		fin = SF_FINST_C;
	}

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= fin;
}

/* shutdown the stream from itself. It's also possible for another one from the
 * same thread but then an explicit wakeup will be needed since this function
 * does not perform it. <why> is a set of SF_ERR_* flags to pass as the cause
 * for shutting down.
 */
void stream_shutdown_self(struct stream *stream, int why)
{
	if (stream->scb->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED))
		return;

	sc_schedule_shutdown(stream->scb);
	sc_schedule_abort(stream->scb);
	stream->task->nice = 1024;
	if (!(stream->flags & SF_ERR_MASK))
		stream->flags |= why;
}

/* dumps an error message for type <type> at ptr <ptr> related to stream <s>,
 * having reached loop rate <rate>, then aborts hoping to retrieve a core.
 */
void stream_dump_and_crash(enum obj_type *obj, int rate)
{
	struct stream *s;
	char *msg = NULL;
	const void *ptr;

	ptr = s = objt_stream(obj);
	if (!s) {
		const struct appctx *appctx = objt_appctx(obj);
		if (!appctx)
			return;
		ptr = appctx;
		s = appctx_strm(appctx);
		if (!s)
			return;
	}

	chunk_reset(&trash);
	chunk_printf(&trash, "  ");
	strm_dump_to_buffer(&trash, s, " ", HA_ATOMIC_LOAD(&global.anon_key));

	if (ptr != s) { // that's an appctx
		const struct appctx *appctx = ptr;

		chunk_appendf(&trash, " applet=%p(", appctx->applet);
		resolve_sym_name(&trash, NULL, appctx->applet);
		chunk_appendf(&trash, ")");

		chunk_appendf(&trash, " handler=%p(", appctx->applet->fct);
		resolve_sym_name(&trash, NULL, appctx->applet->fct);
		chunk_appendf(&trash, ")");
	}

	memprintf(&msg,
	          "A bogus %s [%p] is spinning at %d calls per second and refuses to die, "
	          "aborting now! Please report this error to developers:\n"
	          "%s\n",
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
 *
 * If this function fails to allocate memory IST_NULL is returned.
 *
 * If an ID is already stored within the stream nothing happens existing unique ID is
 * returned.
 */
struct ist stream_generate_unique_id(struct stream *strm, struct lf_expr *format)
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
static enum act_return stream_action_set_retries(struct act_rule *rule, struct proxy *px,
						   struct session *sess, struct stream *s, int flags)
{
	struct sample *smp;

	if (!rule->arg.expr_int.expr)
		s->max_retries = rule->arg.expr_int.value;
	else  {
		smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr_int.expr, SMP_T_SINT);
		if (!smp || smp->data.u.sint < 0 || smp->data.u.sint > 100)
			goto end;
		s->max_retries = smp->data.u.sint;
	}

  end:
	return ACT_RET_CONT;
}


/* Parse a "set-retries" action. It takes the level value as argument. It
 * returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret stream_parse_set_retries(const char **args, int *cur_arg, struct proxy *px,
						   struct act_rule *rule, char **err)
{
	struct sample_expr *expr;
	char *endp;
	unsigned int where;

	if (!*args[*cur_arg]) {
	  bad_retries:
		memprintf(err, "expects exactly 1 argument (an expression or an integer between 1 and 100)");
		return ACT_RET_PRS_ERR;
	}
	if (!(px->cap & PR_CAP_BE)) {
		memprintf(err, "'%s' only available in backend or listen section", args[0]);
		return ACT_RET_PRS_ERR;
	}
	if (px->cap & PR_CAP_DEF) {
		memprintf(err, "'%s' is not allowed in 'defaults' sections", args[0]);
		return ACT_RET_PRS_ERR;
	}

	/* value may be either an unsigned integer or an expression */
	rule->arg.expr_int.expr = NULL;
	rule->arg.expr_int.value = strtol(args[*cur_arg], &endp, 0);
	if (*endp == '\0') {
		if (rule->arg.expr_int.value < 0  || rule->arg.expr_int.value > 100) {
			memprintf(err, "expects an expression or an integer between 1 and 100");
			return ACT_RET_PRS_ERR;
		}
		/* valid unsigned integer */
		(*cur_arg)++;
	}
	else {		/* invalid unsigned integer, fallback to expr */
		expr = sample_parse_expr((char **)args, cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args, NULL);
		if (!expr)
			return ACT_RET_PRS_ERR;
		where = 0;
		if (px->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (px->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;

		if (!(expr->fetch->val & where)) {
			memprintf(err,
				  "fetch method '%s' extracts information from '%s', none of which is available here",
				  args[*cur_arg-1], sample_src_names(expr->fetch->use));
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		rule->arg.expr_int.expr = expr;
	}

	/* Register processing function. */
	rule->action = ACT_CUSTOM;
	rule->action_ptr = stream_action_set_retries;
	rule->release_ptr = release_expr_int_action;
	return ACT_RET_PRS_OK;
}

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
			stream_abort(s);
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
	enum proto_proxy_mode mode = conn_pr_mode_to_proto_mode(pr_mode);

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

/* Lists the known services on <out>. If <out> is null, emit them on stdout one
 * per line.
 */
void list_services(FILE *out)
{
	const struct action_kw *akwp, *akwn;
	struct action_kw_list *kw_list;
	int found = 0;
	int i;

	if (out)
		fprintf(out, "Available services :");

	for (akwn = akwp = NULL;; akwp = akwn) {
		list_for_each_entry(kw_list, &service_keywords, list) {
			for (i = 0; kw_list->kw[i].kw != NULL; i++) {
				if (strordered(akwp ? akwp->kw : NULL,
					       kw_list->kw[i].kw,
					       akwn != akwp ? akwn->kw : NULL))
					akwn = &kw_list->kw[i];
				found = 1;
			}
		}
		if (akwn == akwp)
			break;
		if (out)
			fprintf(out, " %s", akwn->kw);
		else
			printf("%s\n", akwn->kw);
	}
	if (!found && out)
		fprintf(out, " none\n");
}

/* appctx context used by the "show sess" command */
/* flags used for show_sess_ctx.flags */
#define CLI_SHOWSESS_F_SUSP     0x00000001   /* show only suspicious streams */
#define CLI_SHOWSESS_F_DUMP_URI 0x00000002   /* Dump TXN's uri if available in dump */

struct show_sess_ctx {
	struct bref bref;	/* back-reference from the session being dumped */
	void *target;		/* session we want to dump, or NULL for all */
	unsigned int thr;       /* the thread number being explored (0..MAX_THREADS-1) */
	unsigned int uid;	/* if non-null, the uniq_id of the session being dumped */
	unsigned int min_age;   /* minimum age of streams to dump */
	unsigned int flags;     /* CLI_SHOWSESS_* */
	int section;		/* section of the session being dumped */
	int pos;		/* last position of the current session's buffer */
};

/* This function appends a complete dump of a stream state onto the buffer,
 * possibly anonymizing using the specified anon_key. The caller is responsible
 * for ensuring that enough room remains in the buffer to dump a complete stream
 * at once. Each new output line will be prefixed with <pfx> if non-null, which
 * is used to preserve indenting. The context <ctx>, if non-null, will be used
 * to customize the dump.
 */
static void __strm_dump_to_buffer(struct buffer *buf, const struct show_sess_ctx *ctx,
				  const struct stream *strm, const char *pfx, uint32_t anon_key)
{
	struct stconn *scf, *scb;
	struct tm tm;
	extern const char *monthname[12];
	char pn[INET6_ADDRSTRLEN];
	struct connection *conn;
	struct appctx *tmpctx;

	pfx = pfx ? pfx : "";

	get_localtime(strm->logs.accept_date.tv_sec, &tm);
	chunk_appendf(buf,
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
		chunk_appendf(buf, " source=%s:%d\n",
		              HA_ANON_STR(anon_key, pn), get_host_port(conn->src));
		break;
	case AF_UNIX:
	case AF_CUST_ABNS:
	case AF_CUST_ABNSZ:
		chunk_appendf(buf, " source=unix:%d\n", strm_li(strm)->luid);
		break;
	default:
		/* no more information to print right now */
		chunk_appendf(buf, "\n");
		break;
	}

	chunk_appendf(buf,
		     "%s  flags=0x%x, conn_retries=%d, conn_exp=%s conn_et=0x%03x srv_conn=%p, pend_pos=%p waiting=%d epoch=%#x\n", pfx,
		     strm->flags, strm->conn_retries,
		     strm->conn_exp ?
		             tick_is_expired(strm->conn_exp, now_ms) ? "<PAST>" :
		                     human_time(TICKS_TO_MS(strm->conn_exp - now_ms),
		                     TICKS_TO_MS(1000)) : "<NEVER>",
		     strm->conn_err_type, strm->srv_conn, strm->pend_pos,
		     LIST_INLIST(&strm->buffer_wait.list), strm->stream_epoch);

	chunk_appendf(buf, "%s  p_stc=%u p_req=%u p_res=%u p_prp=%u\n", pfx,
		      strm->passes_stconn, strm->passes_reqana, strm->passes_resana, strm->passes_propag);

	chunk_appendf(buf,
		     "%s  frontend=%s (id=%u mode=%s), listener=%s (id=%u)", pfx,
		     HA_ANON_STR(anon_key, strm_fe(strm)->id), strm_fe(strm)->uuid, proxy_mode_str(strm_fe(strm)->mode),
		     strm_li(strm) ? strm_li(strm)->name ? strm_li(strm)->name : "?" : "?",
		     strm_li(strm) ? strm_li(strm)->luid : 0);

	switch (conn && conn_get_dst(conn) ? addr_to_str(conn->dst, pn, sizeof(pn)) : AF_UNSPEC) {
	case AF_INET:
	case AF_INET6:
		chunk_appendf(buf, " addr=%s:%d\n",
			     HA_ANON_STR(anon_key, pn), get_host_port(conn->dst));
		break;
	case AF_UNIX:
	case AF_CUST_ABNS:
	case AF_CUST_ABNSZ:
		chunk_appendf(buf, " addr=unix:%d\n", strm_li(strm)->luid);
		break;
	default:
		/* no more information to print right now */
		chunk_appendf(buf, "\n");
		break;
	}

	if (strm->be->cap & PR_CAP_BE)
		chunk_appendf(buf,
			     "%s  backend=%s (id=%u mode=%s)", pfx,
			     HA_ANON_STR(anon_key, strm->be->id),
			     strm->be->uuid, proxy_mode_str(strm->be->mode));
	else
		chunk_appendf(buf, "%s  backend=<NONE> (id=-1 mode=-)", pfx);

	conn = sc_conn(strm->scb);
	switch (conn && conn_get_src(conn) ? addr_to_str(conn->src, pn, sizeof(pn)) : AF_UNSPEC) {
	case AF_INET:
	case AF_INET6:
		chunk_appendf(buf, " addr=%s:%d\n",
			     HA_ANON_STR(anon_key, pn), get_host_port(conn->src));
		break;
	case AF_UNIX:
	case AF_CUST_ABNS:
	case AF_CUST_ABNSZ:
		chunk_appendf(buf, " addr=unix\n");
		break;
	default:
		/* no more information to print right now */
		chunk_appendf(buf, "\n");
		break;
	}

	if (strm->be->cap & PR_CAP_BE)
		chunk_appendf(buf,
			     "%s  server=%s (id=%u)", pfx,
			     objt_server(strm->target) ? HA_ANON_STR(anon_key, __objt_server(strm->target)->id) : "<none>",
			     objt_server(strm->target) ? __objt_server(strm->target)->puid : 0);
	else
		chunk_appendf(buf, "%s  server=<NONE> (id=-1)", pfx);

	switch (conn && conn_get_dst(conn) ? addr_to_str(conn->dst, pn, sizeof(pn)) : AF_UNSPEC) {
	case AF_INET:
	case AF_INET6:
		chunk_appendf(buf, " addr=%s:%d\n",
			     HA_ANON_STR(anon_key, pn), get_host_port(conn->dst));
		break;
	case AF_UNIX:
	case AF_CUST_ABNS:
	case AF_CUST_ABNSZ:
		chunk_appendf(buf, " addr=unix\n");
		break;
	default:
		/* no more information to print right now */
		chunk_appendf(buf, "\n");
		break;
	}

	chunk_appendf(buf,
		      "%s  task=%p (state=0x%02x nice=%d calls=%u rate=%u exp=%s tid=%d(%d/%d)%s", pfx,
		     strm->task,
		     strm->task->state,
		     strm->task->nice, strm->task->calls, read_freq_ctr(&strm->call_rate),
		     strm->task->expire ?
		             tick_is_expired(strm->task->expire, now_ms) ? "<PAST>" :
		                     human_time(TICKS_TO_MS(strm->task->expire - now_ms),
		                     TICKS_TO_MS(1000)) : "<NEVER>",
	             strm->task->tid,
	             ha_thread_info[strm->task->tid].tgid,
	             ha_thread_info[strm->task->tid].ltid,
		     task_in_rq(strm->task) ? ", running" : "");

	chunk_appendf(buf,
		     " age=%s)\n",
		     human_time(ns_to_sec(now_ns) - ns_to_sec(strm->logs.request_ts), 1));

	if (strm->txn) {
		chunk_appendf(buf,
		      "%s  txn=%p flags=0x%x meth=%d status=%d req.st=%s rsp.st=%s req.f=0x%02x rsp.f=0x%02x", pfx,
		      strm->txn, strm->txn->flags, strm->txn->meth, strm->txn->status,
		      h1_msg_state_str(strm->txn->req.msg_state), h1_msg_state_str(strm->txn->rsp.msg_state),
		      strm->txn->req.flags, strm->txn->rsp.flags);
		if (ctx && (ctx->flags & CLI_SHOWSESS_F_DUMP_URI) && strm->txn->uri)
			chunk_appendf(buf, " uri=\"%s\"", HA_ANON_STR(anon_key, strm->txn->uri));
		chunk_memcat(buf, "\n", 1);
	}

	scf = strm->scf;
	chunk_appendf(buf, "%s  scf=%p flags=0x%08x ioto=%s state=%s endp=%s,%p,0x%08x sub=%d", pfx,
		      scf, scf->flags, human_time(scf->ioto, TICKS_TO_MS(1000)), sc_state_str(scf->state),
		      (sc_ep_test(scf, SE_FL_T_MUX) ? "CONN" : (sc_ep_test(scf, SE_FL_T_APPLET) ? "APPCTX" : "NONE")),
		      scf->sedesc->se, sc_ep_get(scf), scf->wait_event.events);
	chunk_appendf(buf, " rex=%s",
		      sc_ep_rcv_ex(scf) ? human_time(TICKS_TO_MS(sc_ep_rcv_ex(scf) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	chunk_appendf(buf, " wex=%s",
		      sc_ep_snd_ex(scf) ? human_time(TICKS_TO_MS(sc_ep_snd_ex(scf) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	chunk_appendf(buf, " rto=%s",
		      tick_isset(scf->sedesc->lra) ? human_time(TICKS_TO_MS(tick_add(scf->sedesc->lra, scf->ioto) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	chunk_appendf(buf, " wto=%s\n",
		      tick_isset(scf->sedesc->fsb) ? human_time(TICKS_TO_MS(tick_add(scf->sedesc->fsb, scf->ioto) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");

	chunk_appendf(&trash, "%s    iobuf.flags=0x%08x .pipe=%d .buf=%u@%p+%u/%u\n", pfx,
		      scf->sedesc->iobuf.flags,
		      scf->sedesc->iobuf.pipe ? scf->sedesc->iobuf.pipe->data : 0,
		      scf->sedesc->iobuf.buf ? (unsigned int)b_data(scf->sedesc->iobuf.buf): 0,
		      scf->sedesc->iobuf.buf ? b_orig(scf->sedesc->iobuf.buf): NULL,
		      scf->sedesc->iobuf.buf ? (unsigned int)b_head_ofs(scf->sedesc->iobuf.buf): 0,
		      scf->sedesc->iobuf.buf ? (unsigned int)b_size(scf->sedesc->iobuf.buf): 0);

	if ((conn = sc_conn(scf)) != NULL) {
		if (conn->mux && conn->mux->show_sd) {
			char muxpfx[100] = "";

			snprintf(muxpfx, sizeof(muxpfx), "%s      ", pfx);
			chunk_appendf(buf, "%s     ", pfx);
			conn->mux->show_sd(buf, scf->sedesc, muxpfx);
			chunk_appendf(buf, "\n");
		}

		chunk_appendf(buf,
		              "%s      co0=%p ctrl=%s xprt=%s mux=%s data=%s target=%s:%p\n", pfx,
			      conn,
			      conn_get_ctrl_name(conn),
			      conn_get_xprt_name(conn),
			      conn_get_mux_name(conn),
			      sc_get_data_name(scf),
		              obj_type_name(conn->target),
		              obj_base_ptr(conn->target));

		chunk_appendf(buf,
		              "%s      flags=0x%08x fd=%d fd.state=%02x updt=%d fd.tmask=0x%lx\n", pfx,
		              conn->flags,
		              conn_fd(conn),
		              conn_fd(conn) >= 0 ? fdtab[conn->handle.fd].state : 0,
		              conn_fd(conn) >= 0 ? !!(fdtab[conn->handle.fd].update_mask & ti->ltid_bit) : 0,
			      conn_fd(conn) >= 0 ? fdtab[conn->handle.fd].thread_mask: 0);
	}
	else if ((tmpctx = sc_appctx(scf)) != NULL) {
		chunk_appendf(buf,
		              "%s      app0=%p st0=%d st1=%d applet=%s tid=%d nice=%d calls=%u rate=%u\n", pfx,
			      tmpctx,
			      tmpctx->st0,
			      tmpctx->st1,
		              tmpctx->applet->name,
		              tmpctx->t->tid,
		              tmpctx->t->nice, tmpctx->t->calls, read_freq_ctr(&tmpctx->call_rate));
	}

	scb = strm->scb;
	chunk_appendf(buf, "%s  scb=%p flags=0x%08x ioto=%s state=%s endp=%s,%p,0x%08x sub=%d", pfx,
		      scb, scb->flags, human_time(scb->ioto, TICKS_TO_MS(1000)), sc_state_str(scb->state),
		      (sc_ep_test(scb, SE_FL_T_MUX) ? "CONN" : (sc_ep_test(scb, SE_FL_T_APPLET) ? "APPCTX" : "NONE")),
		      scb->sedesc->se, sc_ep_get(scb), scb->wait_event.events);
	chunk_appendf(buf, " rex=%s",
		      sc_ep_rcv_ex(scb) ? human_time(TICKS_TO_MS(sc_ep_rcv_ex(scb) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	chunk_appendf(buf, " wex=%s",
		      sc_ep_snd_ex(scb) ? human_time(TICKS_TO_MS(sc_ep_snd_ex(scb) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	chunk_appendf(buf, " rto=%s",
		      tick_isset(scb->sedesc->lra) ? human_time(TICKS_TO_MS(tick_add(scb->sedesc->lra, scb->ioto) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");
	chunk_appendf(buf, " wto=%s\n",
		      tick_isset(scb->sedesc->fsb) ? human_time(TICKS_TO_MS(tick_add(scb->sedesc->fsb, scb->ioto) - now_ms), TICKS_TO_MS(1000)) : "<NEVER>");

	chunk_appendf(&trash, "%s    iobuf.flags=0x%08x .pipe=%d .buf=%u@%p+%u/%u\n", pfx,
		      scb->sedesc->iobuf.flags,
		      scb->sedesc->iobuf.pipe ? scb->sedesc->iobuf.pipe->data : 0,
		      scb->sedesc->iobuf.buf ? (unsigned int)b_data(scb->sedesc->iobuf.buf): 0,
		      scb->sedesc->iobuf.buf ? b_orig(scb->sedesc->iobuf.buf): NULL,
		      scb->sedesc->iobuf.buf ? (unsigned int)b_head_ofs(scb->sedesc->iobuf.buf): 0,
		      scb->sedesc->iobuf.buf ? (unsigned int)b_size(scb->sedesc->iobuf.buf): 0);

	if ((conn = sc_conn(scb)) != NULL) {
		if (conn->mux && conn->mux->show_sd) {
			char muxpfx[100] = "";

			snprintf(muxpfx, sizeof(muxpfx), "%s      ", pfx);
			chunk_appendf(buf, "%s     ", pfx);
			conn->mux->show_sd(buf, scb->sedesc, muxpfx);
			chunk_appendf(buf, "\n");
		}

		chunk_appendf(buf,
		              "%s      co1=%p ctrl=%s xprt=%s mux=%s data=%s target=%s:%p\n", pfx,
			      conn,
			      conn_get_ctrl_name(conn),
			      conn_get_xprt_name(conn),
			      conn_get_mux_name(conn),
			      sc_get_data_name(scb),
		              obj_type_name(conn->target),
		              obj_base_ptr(conn->target));

		chunk_appendf(buf,
		              "%s      flags=0x%08x fd=%d fd.state=%02x updt=%d fd.tmask=0x%lx\n", pfx,
		              conn->flags,
		              conn_fd(conn),
		              conn_fd(conn) >= 0 ? fdtab[conn->handle.fd].state : 0,
		              conn_fd(conn) >= 0 ? !!(fdtab[conn->handle.fd].update_mask & ti->ltid_bit) : 0,
			      conn_fd(conn) >= 0 ? fdtab[conn->handle.fd].thread_mask: 0);
	}
	else if ((tmpctx = sc_appctx(scb)) != NULL) {
		chunk_appendf(buf,
		              "%s      app1=%p st0=%d st1=%d applet=%s tid=%d nice=%d calls=%u rate=%u\n", pfx,
			      tmpctx,
			      tmpctx->st0,
			      tmpctx->st1,
		              tmpctx->applet->name,
		              tmpctx->t->tid,
		              tmpctx->t->nice, tmpctx->t->calls, read_freq_ctr(&tmpctx->call_rate));
	}

	if (HAS_FILTERS(strm)) {
		const struct filter *flt;

		chunk_appendf(buf, "%s  filters={", pfx);
		list_for_each_entry(flt, &strm->strm_flt.filters, list) {
			if (flt->list.p != &strm->strm_flt.filters)
				chunk_appendf(buf, ", ");
			chunk_appendf(buf, "%p=\"%s\" [%u]", flt, FLT_ID(flt), flt->calls);
		}
		chunk_appendf(buf, "}\n");
	}

	chunk_appendf(buf,
		     "%s  req=%p (f=0x%06x an=0x%x tofwd=%d total=%lld)\n"
		     "%s      an_exp=%s buf=%p data=%p o=%u p=%u i=%u size=%u\n",
		     pfx,
		     &strm->req,
		     strm->req.flags, strm->req.analysers,
		     strm->req.to_forward, strm->req.total,
		     pfx,
		     strm->req.analyse_exp ?
		     human_time(TICKS_TO_MS(strm->req.analyse_exp - now_ms),
				TICKS_TO_MS(1000)) : "<NEVER>",
		     &strm->req.buf,
		     b_orig(&strm->req.buf), (unsigned int)co_data(&strm->req),
		     (unsigned int)ci_head_ofs(&strm->req), (unsigned int)ci_data(&strm->req),
		     (unsigned int)strm->req.buf.size);

	if (IS_HTX_STRM(strm)) {
		struct htx *htx = htxbuf(&strm->req.buf);

		chunk_appendf(buf,
			      "%s      htx=%p flags=0x%x size=%u data=%u used=%u wrap=%s extra=%llu\n", pfx,
			      htx, htx->flags, htx->size, htx->data, htx_nbblks(htx),
			      (htx->tail >= htx->head) ? "NO" : "YES",
			      (unsigned long long)htx->extra);
	}
	if (HAS_FILTERS(strm) && strm->strm_flt.current[0]) {
		const struct filter *flt = strm->strm_flt.current[0];

		chunk_appendf(buf, "%s      current_filter=%p (id=\"%s\" flags=0x%x pre=0x%x post=0x%x) \n", pfx,
			      flt, flt->config->id, flt->flags, flt->pre_analyzers, flt->post_analyzers);
	}

	chunk_appendf(buf,
		     "%s  res=%p (f=0x%06x an=0x%x tofwd=%d total=%lld)\n"
		     "%s      an_exp=%s buf=%p data=%p o=%u p=%u i=%u size=%u\n",
		     pfx,
		     &strm->res,
		     strm->res.flags, strm->res.analysers,
		     strm->res.to_forward, strm->res.total,
		     pfx,
		     strm->res.analyse_exp ?
		     human_time(TICKS_TO_MS(strm->res.analyse_exp - now_ms),
				TICKS_TO_MS(1000)) : "<NEVER>",
		     &strm->res.buf,
	             b_orig(&strm->res.buf), (unsigned int)co_data(&strm->res),
	             (unsigned int)ci_head_ofs(&strm->res), (unsigned int)ci_data(&strm->res),
		     (unsigned int)strm->res.buf.size);

	if (IS_HTX_STRM(strm)) {
		struct htx *htx = htxbuf(&strm->res.buf);

		chunk_appendf(buf,
			      "%s      htx=%p flags=0x%x size=%u data=%u used=%u wrap=%s extra=%llu\n", pfx,
			      htx, htx->flags, htx->size, htx->data, htx_nbblks(htx),
			      (htx->tail >= htx->head) ? "NO" : "YES",
			      (unsigned long long)htx->extra);
	}

	if (HAS_FILTERS(strm) && strm->strm_flt.current[1]) {
		const struct filter *flt = strm->strm_flt.current[1];

		chunk_appendf(buf, "%s      current_filter=%p (id=\"%s\" flags=0x%x pre=0x%x post=0x%x) \n", pfx,
			      flt, flt->config->id, flt->flags, flt->pre_analyzers, flt->post_analyzers);
	}

	if (strm->current_rule_list && strm->current_rule) {
		const struct act_rule *rule = strm->current_rule;
		chunk_appendf(buf, "%s  current_rule=\"%s\" [%s:%d]\n", pfx, rule->kw->kw, rule->conf.file, rule->conf.line);
	}
}

/* Context-less function to append a complet dump of a stream state onto the
 * buffer. It relies on __strm_dump_to_buffer.
 */
void strm_dump_to_buffer(struct buffer *buf, const struct stream *strm, const char *pfx, uint32_t anon_key)
{
	__strm_dump_to_buffer(buf, NULL, strm, pfx, anon_key);
}

/* This function dumps a complete stream state onto the stream connector's
 * read buffer. The stream has to be set in strm. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero. It is
 * designed to be called from stats_dump_strm_to_buffer() below.
 */
static int stats_dump_full_strm_to_buffer(struct appctx *appctx, struct stream *strm)
{
	struct show_sess_ctx *ctx = appctx->svcctx;

	chunk_reset(&trash);

	if (ctx->section > 0 && ctx->uid != strm->uniq_id) {
		/* stream changed, no need to go any further */
		chunk_appendf(&trash, "  *** session terminated while we were watching it ***\n");
		if (applet_putchk(appctx, &trash) == -1)
			goto full;
		goto done;
	}

	switch (ctx->section) {
	case 0: /* main status of the stream */
		ctx->uid = strm->uniq_id;
		ctx->section = 1;
		__fallthrough;

	case 1:
		__strm_dump_to_buffer(&trash, ctx, strm, "", appctx->cli_anon_key);
		if (applet_putchk(appctx, &trash) == -1)
			goto full;

		/* use other states to dump the contents */
	}
	/* end of dump */
 done:
	ctx->uid = 0;
	ctx->section = 0;
	return 1;
 full:
	return 0;
}

static int cli_parse_show_sess(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_sess_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int cur_arg = 2;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	/* now all sessions by default */
	ctx->target = NULL;
	ctx->min_age = 0;
	ctx->section = 0; /* start with stream status */
	ctx->pos = 0;
	ctx->thr = 0;

	if (*args[cur_arg] && strcmp(args[cur_arg], "older") == 0) {
		unsigned timeout;
		const char *res;

		if (!*args[cur_arg+1])
			return cli_err(appctx, "Expects a minimum age (in seconds by default).\n");

		res = parse_time_err(args[cur_arg+1], &timeout, TIME_UNIT_S);
		if (res != 0)
			return cli_err(appctx, "Invalid age.\n");

		ctx->min_age = timeout;
		ctx->target = (void *)-1; /* show all matching entries */
		cur_arg +=2;
	}
	else if (*args[cur_arg] && strcmp(args[cur_arg], "susp") == 0) {
		ctx->flags |= CLI_SHOWSESS_F_SUSP;
		ctx->target = (void *)-1; /* show all matching entries */
		cur_arg++;
	}
	else if (*args[cur_arg] && strcmp(args[cur_arg], "all") == 0) {
		ctx->target = (void *)-1;
		cur_arg++;
	}
	else if (*args[cur_arg] && strcmp(args[cur_arg], "help") == 0) {
		chunk_printf(&trash,
			     "Usage: show sess [<id> | older <age> | susp | all] [<options>*]\n"
			     "Dumps active streams (formerly called 'sessions'). Available selectors:\n"
			     "   <id>         dump only this stream identifier (0x...)\n"
			     "   all          dump all stream in large format\n"
			     "   older <age>  only display stream older than <age>\n"
			     "   susp         report streams considered suspicious\n"
			     "Available options: \n"
			     "   show-uri     also display the transaction URI, if available\n"
			     "Without any argument, all streams are dumped in a shorter format.");
		return cli_err(appctx, trash.area);
	}
	else if (*args[cur_arg]) {
		ctx->target = (void *)strtoul(args[cur_arg], NULL, 0);
		if (ctx->target)
			cur_arg++;
	}

	/* show-sess options parsing */
	while (*args[cur_arg]) {
		if (*args[cur_arg] && strcmp(args[cur_arg], "show-uri") == 0) {
			ctx->flags |= CLI_SHOWSESS_F_DUMP_URI;
		}
		else {
			chunk_printf(&trash, "Unsupported option '%s', try 'help' for more info.\n", args[cur_arg]);
			return cli_err(appctx, trash.area);
		}
		cur_arg++;
	}

	/* The back-ref must be reset, it will be detected and set by
	 * the dump code upon first invocation.
	 */
	LIST_INIT(&ctx->bref.users);

	/* let's set our own stream's epoch to the current one and increment
	 * it so that we know which streams were already there before us.
	 */
	appctx_strm(appctx)->stream_epoch = _HA_ATOMIC_FETCH_ADD(&stream_epoch, 1);
	return 0;
}

/* This function dumps all streams' states onto the stream connector's
 * read buffer. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero. It proceeds in an isolated
 * thread so there is no thread safety issue here.
 */
static int cli_io_handler_dump_sess(struct appctx *appctx)
{
	struct show_sess_ctx *ctx = appctx->svcctx;
	struct connection *conn;

	thread_isolate();

	if (ctx->thr >= global.nbthread) {
		/* already terminated */
		goto done;
	}

	chunk_reset(&trash);

	/* first, let's detach the back-ref from a possible previous stream */
	if (!LIST_ISEMPTY(&ctx->bref.users)) {
		LIST_DELETE(&ctx->bref.users);
		LIST_INIT(&ctx->bref.users);
	} else if (!ctx->bref.ref) {
		/* first call, start with first stream */
		ctx->bref.ref = ha_thread_ctx[ctx->thr].streams.n;
	}

	/* and start from where we stopped */
	while (1) {
		char pn[INET6_ADDRSTRLEN];
		struct stream *curr_strm;
		int done= 0;

		if (ctx->bref.ref == &ha_thread_ctx[ctx->thr].streams)
			done = 1;
		else {
			/* check if we've found a stream created after issuing the "show sess" */
			curr_strm = LIST_ELEM(ctx->bref.ref, struct stream *, list);
			if ((int)(curr_strm->stream_epoch - appctx_strm(appctx)->stream_epoch) > 0)
				done = 1;
		}

		if (done) {
			ctx->thr++;
			if (ctx->thr >= global.nbthread)
				break;
			ctx->bref.ref = ha_thread_ctx[ctx->thr].streams.n;
			continue;
		}

		if (ctx->min_age) {
			uint age = ns_to_sec(now_ns) - ns_to_sec(curr_strm->logs.request_ts);
			if (age < ctx->min_age)
				goto next_sess;
		}

		if (ctx->flags & CLI_SHOWSESS_F_SUSP) {
			/* only show suspicious streams. Non-suspicious ones have a valid
			 * expiration date in the future and a valid front endpoint.
			 */
			if (curr_strm->task->expire &&
			    !tick_is_expired(curr_strm->task->expire, now_ms) &&
			    curr_strm->scf && curr_strm->scf->sedesc && curr_strm->scf->sedesc->se)
				goto next_sess;
		}

		if (ctx->target) {
			if (ctx->target != (void *)-1 && ctx->target != curr_strm)
				goto next_sess;

			LIST_APPEND(&curr_strm->back_refs, &ctx->bref.users);
			/* call the proper dump() function and return if we're missing space */
			if (!stats_dump_full_strm_to_buffer(appctx, curr_strm))
				goto full;

			/* stream dump complete */
			LIST_DELETE(&ctx->bref.users);
			LIST_INIT(&ctx->bref.users);
			if (ctx->target != (void *)-1) {
				ctx->target = NULL;
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
				     HA_ANON_CLI(pn),
				     get_host_port(conn->src),
				     HA_ANON_CLI(strm_fe(curr_strm)->id),
				     (curr_strm->be->cap & PR_CAP_BE) ? HA_ANON_CLI(curr_strm->be->id) : "<NONE>",
				     objt_server(curr_strm->target) ? HA_ANON_CLI(__objt_server(curr_strm->target)->id) : "<none>"
				     );
			break;
		case AF_UNIX:
		case AF_CUST_ABNS:
		case AF_CUST_ABNSZ:
			chunk_appendf(&trash,
				     " src=unix:%d fe=%s be=%s srv=%s",
				     strm_li(curr_strm)->luid,
				     HA_ANON_CLI(strm_fe(curr_strm)->id),
				     (curr_strm->be->cap & PR_CAP_BE) ? HA_ANON_CLI(curr_strm->be->id) : "<NONE>",
				     objt_server(curr_strm->target) ? HA_ANON_CLI(__objt_server(curr_strm->target)->id) : "<none>"
				     );
			break;
		}

		chunk_appendf(&trash,
			     " ts=%02x epoch=%#x age=%s calls=%u rate=%u cpu=%llu lat=%llu",
		             curr_strm->task->state, curr_strm->stream_epoch,
		             human_time(ns_to_sec(now_ns) - ns_to_sec(curr_strm->logs.request_ts), 1),
		             curr_strm->task->calls, read_freq_ctr(&curr_strm->call_rate),
		             (unsigned long long)curr_strm->cpu_time, (unsigned long long)curr_strm->lat_time);

		chunk_appendf(&trash,
			     " rq[f=%06xh,i=%u,an=%02xh",
			     curr_strm->req.flags,
		             (unsigned int)ci_data(&curr_strm->req),
			     curr_strm->req.analysers);

		chunk_appendf(&trash,
			     ",ax=%s]",
			     curr_strm->req.analyse_exp ?
			     human_time(TICKS_TO_MS(curr_strm->req.analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "");

		chunk_appendf(&trash,
			     " rp[f=%06xh,i=%u,an=%02xh",
			     curr_strm->res.flags,
		             (unsigned int)ci_data(&curr_strm->res),
			     curr_strm->res.analysers);
		chunk_appendf(&trash,
			     ",ax=%s]",
			     curr_strm->res.analyse_exp ?
			     human_time(TICKS_TO_MS(curr_strm->res.analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "");

		conn = sc_conn(curr_strm->scf);
		chunk_appendf(&trash," scf=[%d,%1xh,fd=%d",
			      curr_strm->scf->state, curr_strm->scf->flags, conn_fd(conn));
		chunk_appendf(&trash, ",rex=%s",
			      sc_ep_rcv_ex(curr_strm->scf) ?
			      human_time(TICKS_TO_MS(sc_ep_rcv_ex(curr_strm->scf) - now_ms),
					 TICKS_TO_MS(1000)) : "");
		chunk_appendf(&trash,",wex=%s]",
			      sc_ep_snd_ex(curr_strm->scf) ?
			      human_time(TICKS_TO_MS(sc_ep_snd_ex(curr_strm->scf) - now_ms),
					 TICKS_TO_MS(1000)) : "");

		conn = sc_conn(curr_strm->scb);
		chunk_appendf(&trash, " scb=[%d,%1xh,fd=%d",
			      curr_strm->scb->state, curr_strm->scb->flags, conn_fd(conn));
		chunk_appendf(&trash, ",rex=%s",
			      sc_ep_rcv_ex(curr_strm->scb) ?
			      human_time(TICKS_TO_MS(sc_ep_rcv_ex(curr_strm->scb) - now_ms),
					 TICKS_TO_MS(1000)) : "");
		chunk_appendf(&trash, ",wex=%s]",
			      sc_ep_snd_ex(curr_strm->scb) ?
			      human_time(TICKS_TO_MS(sc_ep_snd_ex(curr_strm->scb) - now_ms),
					 TICKS_TO_MS(1000)) : "");

		chunk_appendf(&trash,
			     " exp=%s rc=%d c_exp=%s",
			     curr_strm->task->expire ?
			     human_time(TICKS_TO_MS(curr_strm->task->expire - now_ms),
					TICKS_TO_MS(1000)) : "",
			     curr_strm->conn_retries,
			     curr_strm->conn_exp ?
			     human_time(TICKS_TO_MS(curr_strm->conn_exp - now_ms),
					TICKS_TO_MS(1000)) : "");
		if (task_in_rq(curr_strm->task))
			chunk_appendf(&trash, " run(nice=%d)", curr_strm->task->nice);

		if ((ctx->flags & CLI_SHOWSESS_F_DUMP_URI) && curr_strm->txn && curr_strm->txn->uri)
			chunk_appendf(&trash, " uri=\"%s\"", HA_ANON_CLI(curr_strm->txn->uri));

		chunk_appendf(&trash, "\n");

		if (applet_putchk(appctx, &trash) == -1) {
			/* let's try again later from this stream. We add ourselves into
			 * this stream's users so that it can remove us upon termination.
			 */
			LIST_APPEND(&curr_strm->back_refs, &ctx->bref.users);
			goto full;
		}

	next_sess:
		ctx->bref.ref = curr_strm->list.n;
	}

	if (ctx->target && ctx->target != (void *)-1) {
		/* specified stream not found */
		if (ctx->section > 0)
			chunk_appendf(&trash, "  *** session terminated while we were watching it ***\n");
		else
			chunk_appendf(&trash, "Session not found.\n");

		if (applet_putchk(appctx, &trash) == -1)
			goto full;

		ctx->target = NULL;
		ctx->uid = 0;
		goto done;
	}

 done:
	thread_release();
	return 1;
 full:
	thread_release();
	return 0;
}

static void cli_release_show_sess(struct appctx *appctx)
{
	struct show_sess_ctx *ctx = appctx->svcctx;

	if (ctx->thr < global.nbthread) {
		/* a dump was aborted, either in error or timeout. We need to
		 * safely detach from the target stream's list. It's mandatory
		 * to lock because a stream on the target thread could be moving
		 * our node.
		 */
		thread_isolate();
		if (!LIST_ISEMPTY(&ctx->bref.users))
			LIST_DELETE(&ctx->bref.users);
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

	ptr = (void *)strtoul(args[2], NULL, 0);
	if (!ptr)
		return cli_err(appctx, "Session pointer expected (use 'show sess').\n");

	strm = NULL;

	thread_isolate();

	/* first, look for the requested stream in the stream table */
	for (thr = 0; strm != ptr && thr < global.nbthread; thr++) {
		list_for_each_entry(strm, &ha_thread_ctx[thr].streams, list) {
			if (strm == ptr) {
				stream_shutdown(strm, SF_ERR_KILLED);
				break;
			}
		}
	}

	thread_release();

	/* do we have the stream ? */
	if (strm != ptr)
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
	{ { "show", "sess",  NULL },             "show sess [help|<id>|all|susp|older...] : report the list of current streams or dump this exact stream", cli_parse_show_sess, cli_io_handler_dump_sess, cli_release_show_sess },
	{ { "shutdown", "session",  NULL },      "shutdown session [id]                   : kill a specific session",                                        cli_parse_shutdown_session, NULL, NULL },
	{ { "shutdown", "sessions",  "server" }, "shutdown sessions server <bk>/<srv>     : kill sessions on a server",                                      cli_parse_shutdown_sessions_server, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* main configuration keyword registration. */
static struct action_kw_list stream_tcp_req_keywords = { ILH, {
	{ "set-retries",   stream_parse_set_retries },
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
	{ "set-retries",   stream_parse_set_retries },
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

static struct action_kw_list stream_http_after_res_actions =  { ILH, {
	{ "set-log-level", stream_parse_set_log_level },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_after_res_keywords_register, &stream_http_after_res_actions);

static int smp_fetch_cur_client_timeout(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	if (!smp->strm)
		return 0;

	smp->data.u.sint = TICKS_TO_MS(smp->strm->scf->ioto);
	return 1;
}

static int smp_fetch_cur_server_timeout(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	if (!smp->strm)
		return 0;

	smp->data.u.sint = TICKS_TO_MS(smp->strm->scb->ioto);
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

static int smp_fetch_last_rule_file(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	struct act_rule *rule;

	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_STR;
	if (!smp->strm || smp->strm->last_entity.type != STRM_ENTITY_RULE)
		return 0;

	rule = smp->strm->last_entity.ptr;
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.area = (char *)rule->conf.file;
	smp->data.u.str.data = strlen(rule->conf.file);
	return 1;
}

static int smp_fetch_last_rule_line(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	struct act_rule *rule;

	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	if (!smp->strm || smp->strm->last_entity.type != STRM_ENTITY_RULE)
		return 0;

	rule = smp->strm->last_entity.ptr;
	smp->data.u.sint = rule->conf.line;
	return 1;
}

static int smp_fetch_last_entity(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_STR;
	if (!smp->strm)
		return 0;

	if (smp->strm->last_entity.type == STRM_ENTITY_RULE) {
		struct act_rule *rule = smp->strm->last_entity.ptr;
		struct buffer *trash = get_trash_chunk();

		trash->data = snprintf(trash->area, trash->size, "%s:%d", rule->conf.file, rule->conf.line);
		smp->data.u.str = *trash;
	}
	else if (smp->strm->last_entity.type == STRM_ENTITY_FILTER) {
		struct filter *filter = smp->strm->last_entity.ptr;

		if (FLT_ID(filter)) {
			smp->flags |= SMP_F_CONST;
			smp->data.u.str.area = (char *)FLT_ID(filter);
			smp->data.u.str.data = strlen(FLT_ID(filter));
		}
		else {
			struct buffer *trash = get_trash_chunk();

			trash->data = snprintf(trash->area, trash->size, "%p", filter->config);
			smp->data.u.str = *trash;
		}
	}
	else
		return 0;

	return 1;
}

static int smp_fetch_waiting_entity(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_STR;
	if (!smp->strm)
		return 0;

	if (smp->strm->waiting_entity.type == STRM_ENTITY_RULE) {
		struct act_rule *rule = smp->strm->waiting_entity.ptr;
		struct buffer *trash = get_trash_chunk();

		trash->data = snprintf(trash->area, trash->size, "%s:%d", rule->conf.file, rule->conf.line);
		smp->data.u.str = *trash;
	}
	else if (smp->strm->waiting_entity.type == STRM_ENTITY_FILTER) {
		struct filter *filter = smp->strm->waiting_entity.ptr;

		if (FLT_ID(filter)) {
			smp->flags |= SMP_F_CONST;
			smp->data.u.str.area = (char *)FLT_ID(filter);
			smp->data.u.str.data = strlen(FLT_ID(filter));
		}
		else {
			struct buffer *trash = get_trash_chunk();

			trash->data = snprintf(trash->area, trash->size, "%p", filter->config);
			smp->data.u.str = *trash;
		}
	}
	else if (smp->strm->waiting_entity.type == STRM_ENTITY_WREQ_BODY) {
		struct buffer *trash = get_trash_chunk();

		chunk_memcat(trash, "http-buffer-request", 19);
		smp->data.u.str = *trash;
	}
	else
		return 0;

	return 1;
}

static int smp_fetch_sess_term_state(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	struct buffer *trash = get_trash_chunk();

	smp->flags = SMP_F_VOLATILE;
	smp->data.type = SMP_T_STR;
	if (!smp->strm)
		return 0;

	trash->area[trash->data++] = sess_term_cond[(smp->strm->flags & SF_ERR_MASK) >> SF_ERR_SHIFT];
	trash->area[trash->data++] = sess_fin_state[(smp->strm->flags & SF_FINST_MASK) >> SF_FINST_SHIFT];

	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int smp_fetch_conn_retries(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	if (!smp->strm)
		return 0;

	if (!sc_state_in(smp->strm->scb->state, SC_SB_DIS|SC_SB_CLO))
		smp->flags |= SMP_F_VOL_TEST;
	smp->data.u.sint = smp->strm->conn_retries;
	return 1;
}

static int smp_fetch_tevts(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	struct buffer *trash = get_trash_chunk();
	struct connection *fconn, *bconn;
	int fc_mux_ret, bc_mux_ret;

	fconn = smp->sess ? objt_conn(smp->sess->origin) : NULL;
	bconn = smp->strm ? sc_conn(smp->strm->scb) : NULL;
	fc_mux_ret = bc_mux_ret = -1;

	if (fconn && fconn->mux && fconn->mux->ctl)
		fc_mux_ret = fconn->mux->ctl(fconn, MUX_CTL_TEVTS, NULL);
	if (bconn && bconn->mux && bconn->mux->ctl)
		bc_mux_ret = bconn->mux->ctl(bconn, MUX_CTL_TEVTS, NULL);

	chunk_printf(trash, "{%s,", tevt_evts2str(fconn ? fconn->term_evts_log : -1));
	chunk_appendf(trash, "%s,", tevt_evts2str(fc_mux_ret));
	chunk_appendf(trash, "%s,", tevt_evts2str(smp->strm ? smp->strm->scf->sedesc->term_evts_log : -1));
	chunk_appendf(trash, "%s,", tevt_evts2str(smp->strm ? smp->strm->term_evts_log : -1));
	chunk_appendf(trash, "%s,", tevt_evts2str(smp->strm ? smp->strm->scb->sedesc->term_evts_log : -1));
	chunk_appendf(trash, "%s,", tevt_evts2str(bc_mux_ret));
	chunk_appendf(trash, "%s}", tevt_evts2str(bconn ? bconn->term_evts_log : -1));

	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	return 1;
}

static int smp_fetch_id32(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	if (!smp->strm)
		return 0;
	smp->data.u.sint = smp->strm->uniq_id;
	return 1;
}

static int smp_fetch_redispatched(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_BOOL;
	if (!smp->strm)
		return 0;

	if (!sc_state_in(smp->strm->scb->state, SC_SB_DIS|SC_SB_CLO))
		smp->flags |= SMP_F_VOL_TEST;
	smp->data.u.sint = !!(smp->strm->flags & SF_REDISP);
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "cur_client_timeout", smp_fetch_cur_client_timeout, 0, NULL, SMP_T_SINT, SMP_USE_FTEND, },
	{ "cur_server_timeout", smp_fetch_cur_server_timeout, 0, NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ "cur_tunnel_timeout", smp_fetch_cur_tunnel_timeout, 0, NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ "last_entity",        smp_fetch_last_entity,        0, NULL, SMP_T_STR,  SMP_USE_INTRN, },
	{ "last_rule_file",     smp_fetch_last_rule_file,     0, NULL, SMP_T_STR,  SMP_USE_INTRN, },
	{ "last_rule_line",     smp_fetch_last_rule_line,     0, NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "term_events",        smp_fetch_tevts,              0, NULL, SMP_T_STR,  SMP_USE_INTRN, },
	{ "txn.conn_retries",   smp_fetch_conn_retries,       0, NULL, SMP_T_SINT, SMP_USE_L4SRV, },
	{ "txn.id32",           smp_fetch_id32,               0, NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "txn.redispatched",   smp_fetch_redispatched,       0, NULL, SMP_T_BOOL, SMP_USE_L4SRV, },
	{ "txn.sess_term_state",smp_fetch_sess_term_state,    0, NULL, SMP_T_STR,  SMP_USE_INTRN, },
	{ "waiting_entity",     smp_fetch_waiting_entity,     0, NULL, SMP_T_STR,  SMP_USE_INTRN, },
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
