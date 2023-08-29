/*
 * Functions managing applets
 *
 * Copyright 2000-2015 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/channel.h>
#include <haproxy/list.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>

unsigned int nb_applets = 0;

DECLARE_POOL(pool_head_appctx,  "appctx",  sizeof(struct appctx));


/* trace source and events */
static void applet_trace(enum trace_level level, uint64_t mask,
			 const struct trace_source *src,
			 const struct ist where, const struct ist func,
			 const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   app  - applet
  */
static const struct trace_event applet_trace_events[] = {
#define           APPLET_EV_NEW       (1ULL <<  0)
	{ .mask = APPLET_EV_NEW,      .name = "app_new",      .desc = "new appctx" },
#define           APPLET_EV_FREE      (1ULL <<  1)
	{ .mask = APPLET_EV_FREE,     .name = "app_free",     .desc = "free appctx" },
#define           APPLET_EV_RELEASE   (1ULL <<  2)
	{ .mask = APPLET_EV_RELEASE,  .name = "app_release",  .desc = "release appctx" },
#define           APPLET_EV_PROCESS   (1ULL <<  3)
	{ .mask = APPLET_EV_PROCESS,  .name = "app_proc",     .desc = "process appctx" },
#define           APPLET_EV_ERR       (1ULL <<  4)
	{ .mask = APPLET_EV_ERR,      .name = "app_err",      .desc = "error on appctx" },
#define           APPLET_EV_START     (1ULL <<  5)
	{ .mask = APPLET_EV_START,    .name = "app_start",   .desc = "start appctx" },
	{}
};

static const struct name_desc applet_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the applet */ },
	/* arg2 */ { },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc applet_trace_decoding[] = {
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

static struct trace_source trace_applet = {
	.name = IST("applet"),
	.desc = "Applet endpoint",
	.arg_def = TRC_ARG1_APPCTX,  // TRACE()'s first argument is always an appctx
	.default_cb = applet_trace,
	.known_events = applet_trace_events,
	.lockon_args = applet_trace_lockon_args,
	.decoding = applet_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_applet
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* the applet traces always expect that arg1, if non-null, is of a appctx (from
 * which we can derive everything).
 */
static void applet_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
			 const struct ist where, const struct ist func,
			 const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct appctx *appctx = a1;
	const struct stconn *sc = NULL, *sco = NULL;
	const struct stream *s = NULL;
	const struct channel *ic = NULL, *oc = NULL;

	if (!appctx || src->verbosity < STRM_VERB_CLEAN)
		return;

	sc = appctx_sc(appctx);
	if (sc) {
		s = __sc_strm(sc);
		sco = sc_opposite(sc);
		ic = sc_ic(sc);
		oc = sc_oc(sc);
	}

	/* General info about the stream (htx/tcp, id...) */
	if (s)
		chunk_appendf(&trace_buf, " : [%s,%s]",
			      appctx->applet->name, ((s->flags & SF_HTX) ? "HTX" : "TCP"));
	else
		chunk_appendf(&trace_buf, " : [%s]", appctx->applet->name);

	if (sc)
		/* local and opposite stream connector state */
		chunk_appendf(&trace_buf, " SC=(%s,%s)",
			      sc_state_str(sc->state), sc_state_str(sco->state));
	else
		/* local and opposite stream connector state */
		chunk_appendf(&trace_buf, " SC=(none,none)");

	if (src->verbosity == STRM_VERB_CLEAN)
		return;

	chunk_appendf(&trace_buf, " appctx=%p .t=%p .t.exp=%d .state=%d .st0=%d .st1=%d",
		      appctx, appctx->t, tick_isset(appctx->t->expire) ? TICKS_TO_MS(appctx->t->expire - now_ms) : TICK_ETERNITY,
		      appctx->state, appctx->st0, appctx->st1);

	if (!sc || src->verbosity == STRM_VERB_MINIMAL)
		return;

	chunk_appendf(&trace_buf, " - s=(%p,0x%08x,0x%x)", s, s->flags, s->conn_err_type);

	chunk_appendf(&trace_buf, " sc=(%p,%d,0x%08x,0x%x) sco=(%p,%d,0x%08x,0x%x) sc.exp(r,w)=(%d,%d) sco.exp(r,w)=(%d,%d)",
		      sc, sc->state, sc->flags, sc->sedesc->flags,
		      sco, sco->state, sco->flags, sco->sedesc->flags,
		      tick_isset(sc_ep_rcv_ex(sc)) ? TICKS_TO_MS(sc_ep_rcv_ex(sc) - now_ms) : TICK_ETERNITY,
		      tick_isset(sc_ep_snd_ex(sc)) ? TICKS_TO_MS(sc_ep_snd_ex(sc) - now_ms) : TICK_ETERNITY,
		      tick_isset(sc_ep_rcv_ex(sco)) ? TICKS_TO_MS(sc_ep_rcv_ex(sco) - now_ms) : TICK_ETERNITY,
		      tick_isset(sc_ep_snd_ex(sco)) ? TICKS_TO_MS(sc_ep_snd_ex(sco) - now_ms) : TICK_ETERNITY);


	/* If txn defined, don't display all channel info */
	if (src->verbosity == STRM_VERB_SIMPLE) {
		chunk_appendf(&trace_buf, " ic=(%p .fl=0x%08x .exp=%d)",
			      ic, ic->flags, tick_isset(ic->analyse_exp) ? TICKS_TO_MS(ic->analyse_exp - now_ms) : TICK_ETERNITY);
		chunk_appendf(&trace_buf, " oc=(%p .fl=0x%08x .exp=%d)",
			      oc, oc->flags, tick_isset(oc->analyse_exp) ? TICKS_TO_MS(oc->analyse_exp - now_ms) : TICK_ETERNITY);
	}
	else {
		chunk_appendf(&trace_buf, " ic=(%p .fl=0x%08x .ana=0x%08x .exp=%u .o=%lu .tot=%llu .to_fwd=%u)",
			      ic, ic->flags, ic->analysers, ic->analyse_exp,
			      (long)ic->output, ic->total, ic->to_forward);
		chunk_appendf(&trace_buf, " oc=(%p .fl=0x%08x .ana=0x%08x .exp=%u .o=%lu .tot=%llu .to_fwd=%u)",
			      oc, oc->flags, oc->analysers, oc->analyse_exp,
			      (long)oc->output, oc->total, oc->to_forward);
	}

	if (src->verbosity == STRM_VERB_SIMPLE ||
	    (src->verbosity == STRM_VERB_ADVANCED && src->level < TRACE_LEVEL_DATA))
		return;

	/* channels' buffer info */
	if (s->flags & SF_HTX) {
		struct htx *ichtx = htxbuf(&ic->buf);
		struct htx *ochtx = htxbuf(&oc->buf);

		chunk_appendf(&trace_buf, " htx=(%u/%u#%u, %u/%u#%u)",
			      ichtx->data, ichtx->size, htx_nbblks(ichtx),
			      ochtx->data, ochtx->size, htx_nbblks(ochtx));
	}
	else {
		chunk_appendf(&trace_buf, " buf=(%u@%p+%u/%u, %u@%p+%u/%u)",
			      (unsigned int)b_data(&ic->buf), b_orig(&ic->buf),
			      (unsigned int)b_head_ofs(&ic->buf), (unsigned int)b_size(&ic->buf),
			      (unsigned int)b_data(&oc->buf), b_orig(&oc->buf),
			      (unsigned int)b_head_ofs(&oc->buf), (unsigned int)b_size(&oc->buf));
	}
}

/* Tries to allocate a new appctx and initialize all of its fields. The appctx
 * is returned on success, NULL on failure. The appctx must be released using
 * appctx_free(). <applet> is assigned as the applet, but it can be NULL. <thr>
 * is the thread ID to start the applet on, and a negative value allows the
 * applet to start anywhere. Backend applets may only be created on the current
 * thread.
 */
struct appctx *appctx_new_on(struct applet *applet, struct sedesc *sedesc, int thr)
{
	struct appctx *appctx;

	/* Backend appctx cannot be started on another thread than the local one */
	BUG_ON(thr != tid && sedesc);

	TRACE_ENTER(APPLET_EV_NEW);

	appctx = pool_zalloc(pool_head_appctx);
	if (unlikely(!appctx)) {
		TRACE_ERROR("APPCTX allocation failure", APPLET_EV_NEW|APPLET_EV_ERR);
		goto fail_appctx;
	}

	LIST_INIT(&appctx->wait_entry);
	appctx->obj_type = OBJ_TYPE_APPCTX;
	appctx->applet = applet;
	appctx->sess = NULL;

	appctx->t = task_new_on(thr);
	if (unlikely(!appctx->t)) {
		TRACE_ERROR("APPCTX task allocation failure", APPLET_EV_NEW|APPLET_EV_ERR);
		goto fail_task;
	}

	if (!sedesc) {
		sedesc = sedesc_new();
		if (unlikely(!sedesc)) {
			TRACE_ERROR("APPCTX sedesc allocation failure", APPLET_EV_NEW|APPLET_EV_ERR);
			goto fail_endp;
		}
		sedesc->se = appctx;
		se_fl_set(sedesc, SE_FL_T_APPLET | SE_FL_ORPHAN);
	}

	appctx->sedesc = sedesc;
	appctx->t->process = task_run_applet;
	appctx->t->context = appctx;

	LIST_INIT(&appctx->buffer_wait.list);
	appctx->buffer_wait.target = appctx;
	appctx->buffer_wait.wakeup_cb = appctx_buf_available;

	_HA_ATOMIC_INC(&nb_applets);

	TRACE_LEAVE(APPLET_EV_NEW, appctx);
	return appctx;

  fail_endp:
	task_destroy(appctx->t);
  fail_task:
	pool_free(pool_head_appctx, appctx);
  fail_appctx:
	return NULL;
}

/* Finalize the frontend appctx startup. It must not be called for a backend
 * appctx. This function is responsible to create the appctx's session and the
 * frontend stream connector. By transitivity, the stream is also created.
 *
 * It returns 0 on success and -1 on error. In this case, it is the caller
 * responsibility to release the appctx. However, the session is released if it
 * was created. On success, if an error is encountered in the caller function,
 * the stream must be released instead of the appctx. To be sure,
 * appctx_free_on_early_error() must be called in this case.
 */
int appctx_finalize_startup(struct appctx *appctx, struct proxy *px, struct buffer *input)
{
	struct session *sess;

	/* async startup is only possible for frontend appctx. Thus for orphan
	 * appctx. Because no backend appctx can be orphan.
	 */
	BUG_ON(!se_fl_test(appctx->sedesc, SE_FL_ORPHAN));

	TRACE_ENTER(APPLET_EV_START, appctx);

	sess = session_new(px, NULL, &appctx->obj_type);
	if (!sess) {
		TRACE_ERROR("APPCTX session allocation failure", APPLET_EV_START|APPLET_EV_ERR, appctx);
		return -1;
	}
	if (!sc_new_from_endp(appctx->sedesc, sess, input)) {
		session_free(sess);
		TRACE_ERROR("APPCTX sc allocation failure", APPLET_EV_START|APPLET_EV_ERR, appctx);
		return -1;
	}

	appctx->sess = sess;
	TRACE_LEAVE(APPLET_EV_START, appctx);
	return 0;
}

/* Release function to call when an error occurred during init stage of a
 * frontend appctx. For a backend appctx, it just calls appctx_free()
 */
void appctx_free_on_early_error(struct appctx *appctx)
{
	/* If a frontend appctx is attached to a stream connector, release the stream
	 * instead of the appctx.
	 */
	if (!se_fl_test(appctx->sedesc, SE_FL_ORPHAN) && !(appctx_sc(appctx)->flags & SC_FL_ISBACK)) {
		stream_free(appctx_strm(appctx));
		return;
	}
	appctx_free(appctx);
}

void appctx_free(struct appctx *appctx)
{
	/* The task is supposed to be run on this thread, so we can just
	 * check if it's running already (or about to run) or not
	 */
	if (!(appctx->t->state & (TASK_QUEUED | TASK_RUNNING))) {
		TRACE_POINT(APPLET_EV_FREE, appctx);
		__appctx_free(appctx);
	}
	else {
		/* if it's running, or about to run, defer the freeing
		 * until the callback is called.
		 */
		appctx->state |= APPLET_WANT_DIE;
		task_wakeup(appctx->t, TASK_WOKEN_OTHER);
		TRACE_DEVEL("Cannot release APPCTX now, wake it up", APPLET_EV_FREE, appctx);
	}
}

/* reserves a command context of at least <size> bytes in the <appctx>, for
 * use by a CLI command or any regular applet. The pointer to this context is
 * stored in ctx.svcctx and is returned. The caller doesn't need to release
 * it as it's allocated from reserved space. If the size is larger than
 * APPLET_MAX_SVCCTX a crash will occur (hence that will never happen outside
 * of development).
 *
 * Note that the command does *not* initialize the area, so that it can easily
 * be used upon each entry in a function. It's left to the initialization code
 * to do it if needed. The CLI will always zero the whole area before calling
 * a keyword's ->parse() function.
 */
void *applet_reserve_svcctx(struct appctx *appctx, size_t size)
{
	BUG_ON(size > APPLET_MAX_SVCCTX);
	appctx->svcctx = &appctx->svc.storage;
	return appctx->svcctx;
}

/* This is used to reset an svcctx and the svc.storage without releasing the
 * appctx. In fact this is only used by the CLI applet between commands.
 */
void applet_reset_svcctx(struct appctx *appctx)
{
	memset(&appctx->svc.storage, 0, APPLET_MAX_SVCCTX);
	appctx->svcctx = NULL;
}

/* call the applet's release() function if any, and marks the sedesc as shut.
 * Needs to be called upon close().
 */
void appctx_shut(struct appctx *appctx)
{
	if (se_fl_test(appctx->sedesc, SE_FL_SHR | SE_FL_SHW))
		return;

	TRACE_ENTER(APPLET_EV_RELEASE, appctx);
	if (appctx->applet->release)
		appctx->applet->release(appctx);

	se_fl_set(appctx->sedesc, SE_FL_SHRR | SE_FL_SHWN);
	TRACE_LEAVE(APPLET_EV_RELEASE, appctx);
}

/* Callback used to wake up an applet when a buffer is available. The applet
 * <appctx> is woken up if an input buffer was requested for the associated
 * stream connector. In this case the buffer is immediately allocated and the
 * function returns 1. Otherwise it returns 0. Note that this automatically
 * covers multiple wake-up attempts by ensuring that the same buffer will not
 * be accounted for multiple times.
 */
int appctx_buf_available(void *arg)
{
	struct appctx *appctx = arg;
	struct stconn *sc = appctx_sc(appctx);

	/* allocation requested ? */
	if (!(sc->flags & SC_FL_NEED_BUFF))
		return 0;

	sc_have_buff(sc);

	/* was already allocated another way ? if so, don't take this one */
	if (c_size(sc_ic(sc)) || sc_ic(sc)->pipe)
		return 0;

	/* allocation possible now ? */
	if (!b_alloc(&sc_ic(sc)->buf)) {
		sc_need_buff(sc);
		return 0;
	}

	task_wakeup(appctx->t, TASK_WOKEN_RES);
	return 1;
}

/* Default applet handler */
struct task *task_run_applet(struct task *t, void *context, unsigned int state)
{
	struct appctx *app = context;
	struct stconn *sc, *sco;
	unsigned int rate;
	size_t count;

	TRACE_ENTER(APPLET_EV_PROCESS, app);

	if (app->state & APPLET_WANT_DIE) {
		TRACE_DEVEL("APPCTX want die, release it", APPLET_EV_FREE, app);
		__appctx_free(app);
		return NULL;
	}

	if (se_fl_test(app->sedesc, SE_FL_ORPHAN)) {
		/* Finalize init of orphan appctx. .init callback function must
		 * be defined and it must finalize appctx startup.
		 */
		BUG_ON(!app->applet->init);

		if (appctx_init(app) == -1) {
			TRACE_DEVEL("APPCTX init failed", APPLET_EV_FREE|APPLET_EV_ERR, app);
			appctx_free_on_early_error(app);
			return NULL;
		}
		BUG_ON(!app->sess || !appctx_sc(app) || !appctx_strm(app));
		TRACE_DEVEL("APPCTX initialized", APPLET_EV_PROCESS, app);
	}

	sc = appctx_sc(app);
	sco = sc_opposite(sc);

	/* We always pretend the applet can't get and doesn't want to
	 * put, it's up to it to change this if needed. This ensures
	 * that one applet which ignores any event will not spin.
	 */
	applet_need_more_data(app);
	applet_have_no_more_data(app);

	/* Now we'll try to allocate the input buffer. We wake up the applet in
	 * all cases. So this is the applet's responsibility to check if this
	 * buffer was allocated or not. This leaves a chance for applets to do
	 * some other processing if needed. The applet doesn't have anything to
	 * do if it needs the buffer, it will be called again upon readiness.
	 */
	if (!sc_alloc_ibuf(sc, &app->buffer_wait))
		applet_have_more_data(app);

	count = co_data(sc_oc(sc));
	app->applet->fct(app);

	TRACE_POINT(APPLET_EV_PROCESS, app);

	/* now check if the applet has released some room and forgot to
	 * notify the other side about it.
	 */
	if (count != co_data(sc_oc(sc))) {
		sc_oc(sc)->flags |= CF_WRITE_EVENT | CF_WROTE_DATA;
		if (sco->room_needed < 0 || channel_recv_max(sc_oc(sc)) >= sco->room_needed)
			sc_have_room(sco);
	}
	else if (!sco->room_needed)
		sc_have_room(sco);

	if (sc_ic(sc)->flags & CF_READ_EVENT)
		sc_ep_report_read_activity(sc);

	if (channel_is_empty(sc_oc(sc)))
		sc_ep_report_send_activity(sc);
	else
		sc_ep_report_blocked_send(sc);

	/* measure the call rate and check for anomalies when too high */
	if (((b_size(sc_ib(sc)) && sc->flags & SC_FL_NEED_BUFF) || // asks for a buffer which is present
	     (b_size(sc_ib(sc)) && !b_data(sc_ib(sc)) && sc->flags & SC_FL_NEED_ROOM) || // asks for room in an empty buffer
	     (b_data(sc_ob(sc)) && sc_is_send_allowed(sc)) || // asks for data already present
	     (!b_data(sc_ib(sc)) && b_data(sc_ob(sc)) && // didn't return anything ...
	      (!(sc_oc(sc)->flags & CF_WRITE_EVENT) && (sc->flags & SC_FL_SHUT_WANTED))))) { // ... and left data pending after a shut
		rate = update_freq_ctr(&app->call_rate, 1);
		if (rate >= 100000 && app->call_rate.prev_ctr) // looped like this more than 100k times over last second
			stream_dump_and_crash(&app->obj_type, read_freq_ctr(&app->call_rate));
	}

	sc->app_ops->wake(sc);
	channel_release_buffer(sc_ic(sc), &app->buffer_wait);
	TRACE_LEAVE(APPLET_EV_PROCESS, app);
	return t;
}
