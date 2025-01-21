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
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>
#include <haproxy/vecpair.h>

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
#define           APPLET_EV_RECV      (1ULL <<  6)
	{ .mask = APPLET_EV_START,    .name = "app_receive", .desc = "RX on appctx" },
#define           APPLET_EV_SEND      (1ULL <<  7)
	{ .mask = APPLET_EV_START,    .name = "app_send",    .desc = "TX on appctx" },
#define           APPLET_EV_BLK       (1ULL <<  8)
	{ .mask = APPLET_EV_START,    .name = "app_blk",     .desc = "appctx blocked" },
#define           APPLET_EV_WAKE      (1ULL <<  9)
	{ .mask = APPLET_EV_START,    .name = "app_wake",    .desc = "appctx woken up" },
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

	chunk_appendf(&trace_buf, " appctx=%p .t=%p .t.exp=%d .flags=0x%x .st0=%d .st1=%d to_fwd=%lu",
		      appctx, appctx->t, tick_isset(appctx->t->expire) ? TICKS_TO_MS(appctx->t->expire - now_ms) : TICK_ETERNITY,
		      appctx->flags, appctx->st0, appctx->st1, (ulong)appctx->to_forward);

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

	if (appctx->t->process == task_run_applet) {
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
	else {
		/* RX/TX buffer info */
		if (s->flags & SF_HTX) {
			struct htx *rxhtx = htxbuf(&appctx->inbuf);
			struct htx *txhtx = htxbuf(&appctx->outbuf);

			chunk_appendf(&trace_buf, " htx=(%u/%u#%u, %u/%u#%u)",
				      rxhtx->data, rxhtx->size, htx_nbblks(rxhtx),
				      txhtx->data, txhtx->size, htx_nbblks(txhtx));
		}
		else {
			chunk_appendf(&trace_buf, " buf=(%u@%p+%u/%u, %u@%p+%u/%u)",
				      (unsigned int)b_data(&appctx->inbuf), b_orig(&appctx->inbuf),
				      (unsigned int)b_head_ofs(&appctx->inbuf), (unsigned int)b_size(&appctx->inbuf),
				      (unsigned int)b_data(&appctx->outbuf), b_orig(&appctx->outbuf),
				      (unsigned int)b_head_ofs(&appctx->outbuf), (unsigned int)b_size(&appctx->outbuf));
		}
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

	MT_LIST_INIT(&appctx->wait_entry);
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

	appctx->flags = 0;
	appctx->inbuf = BUF_NULL;
	appctx->outbuf = BUF_NULL;
	appctx->to_forward = 0;

	if (applet->rcv_buf != NULL && applet->snd_buf != NULL) {
		appctx->t->process = task_process_applet;
		applet_fl_set(appctx, APPCTX_FL_INOUT_BUFS);
	}
	else
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
	__appctx_free(appctx);
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
		applet_fl_set(appctx, APPCTX_FL_WANT_DIE);
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

/* call the applet's release() function if any, and marks the sedesc as shut
 * once both read and write side are shut.  Needs to be called upon close().
 */
void appctx_shut(struct appctx *appctx)
{
	if (applet_fl_test(appctx, APPCTX_FL_SHUTDOWN))
		return;

	TRACE_ENTER(APPLET_EV_RELEASE, appctx);

	if (appctx->applet->release)
		appctx->applet->release(appctx);
	applet_fl_set(appctx, APPCTX_FL_SHUTDOWN);

	b_dequeue(&appctx->buffer_wait);

	TRACE_LEAVE(APPLET_EV_RELEASE, appctx);
}

/* releases unused buffers after processing. It will try to wake up as many
 * entities as the number of buffers that it releases.
 */
static void appctx_release_buffers(struct appctx * appctx)
{
	int offer = 0;

	if (b_size(&appctx->inbuf) && !b_data(&appctx->inbuf)) {
		offer++;
		b_free(&appctx->inbuf);
	}
	if (b_size(&appctx->outbuf) && !b_data(&appctx->outbuf)) {
		offer++;
		b_free(&appctx->outbuf);
	}

	/* if we're certain to have at least 1 buffer available, and there is
	 * someone waiting, we can wake up a waiter and offer them.
	 */
	if (offer)
		offer_buffers(appctx, offer);
}

/* Callback used to wake up an applet when a buffer is available. The applet
 * <appctx> is woken up if an input buffer was requested for the associated
 * stream connector. In this case the buffer is expected to be allocated later,
 * the applet is woken up, and the function returns 1 to mention this buffer is
 * expected to be used. Otherwise it returns 0.
 */
int appctx_buf_available(void *arg)
{
	struct appctx *appctx = arg;
	struct stconn *sc = appctx_sc(appctx);
	int ret = 0;

	if (applet_fl_test(appctx, APPCTX_FL_INBLK_ALLOC)) {
		applet_fl_clr(appctx, APPCTX_FL_INBLK_ALLOC);
		applet_fl_set(appctx, APPCTX_FL_IN_MAYALLOC);
		TRACE_STATE("unblocking appctx on inbuf allocation", APPLET_EV_RECV|APPLET_EV_BLK|APPLET_EV_WAKE, appctx);
		ret = 1;
	}

	if (applet_fl_test(appctx, APPCTX_FL_OUTBLK_ALLOC)) {
		applet_fl_clr(appctx, APPCTX_FL_OUTBLK_ALLOC);
		applet_fl_set(appctx, APPCTX_FL_OUT_MAYALLOC);
		TRACE_STATE("unblocking appctx on outbuf allocation", APPLET_EV_SEND|APPLET_EV_BLK|APPLET_EV_WAKE, appctx);
		ret = 1;
	}

	/* allocation requested ? if no, give up. */
	if (sc->flags & SC_FL_NEED_BUFF) {
		sc_have_buff(sc);
		ret = 1;
	}

	/* The requested buffer might already have been allocated (channel,
	 * fast-forward etc), in which case we won't need to take that one.
	 * Otherwise we expect to take it.
	 */
	if (!c_size(sc_ic(sc)) && !sc_ep_have_ff_data(sc_opposite(sc)))
		ret = 1;
 leave:
	if (ret)
		task_wakeup(appctx->t, TASK_WOKEN_RES);
	return ret;
}

size_t appctx_htx_rcv_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags)
{
	struct htx *appctx_htx = htx_from_buf(&appctx->outbuf);
	struct htx *buf_htx = NULL;
	size_t ret = 0;

	if (htx_is_empty(appctx_htx)) {
		htx_to_buf(appctx_htx, &appctx->outbuf);
		goto out;
	}

	ret = appctx_htx->data;
	buf_htx = htx_from_buf(buf);
	if (htx_is_empty(buf_htx) && htx_used_space(appctx_htx) <= count) {
		htx_to_buf(buf_htx, buf);
		htx_to_buf(appctx_htx, &appctx->outbuf);
		b_xfer(buf, &appctx->outbuf, b_data(&appctx->outbuf));
		goto out;
	}

	htx_xfer_blks(buf_htx, appctx_htx, count, HTX_BLK_UNUSED);
	buf_htx->flags |= (appctx_htx->flags & (HTX_FL_PARSING_ERROR|HTX_FL_PROCESSING_ERROR));
	if (htx_is_empty(appctx_htx)) {
		buf_htx->flags |= (appctx_htx->flags & HTX_FL_EOM);
	}
	buf_htx->extra = (appctx_htx->extra ? (appctx_htx->data + appctx_htx->extra) : 0);
	htx_to_buf(buf_htx, buf);
	htx_to_buf(appctx_htx, &appctx->outbuf);
	ret -= appctx_htx->data;

  out:
	return ret;
}

size_t appctx_raw_rcv_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags)
{
	return b_xfer(buf, &appctx->outbuf, MIN(count, b_data(&appctx->outbuf)));
}

size_t appctx_rcv_buf(struct stconn *sc, struct buffer *buf, size_t count, unsigned int flags)
{
	struct appctx *appctx = __sc_appctx(sc);
	size_t ret = 0;

	TRACE_ENTER(APPLET_EV_RECV, appctx);

	if (applet_fl_test(appctx, APPCTX_FL_OUTBLK_ALLOC))
		goto end;

	if (!count)
		goto end;

	if (!appctx_get_buf(appctx, &appctx->outbuf)) {
		TRACE_STATE("waiting for appctx outbuf allocation", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
		goto end;
	}

	if (flags & CO_RFL_BUF_FLUSH)
		applet_fl_set(appctx, APPCTX_FL_FASTFWD);

	ret = appctx->applet->rcv_buf(appctx, buf, count, flags);
	if (ret)
		applet_fl_clr(appctx, APPCTX_FL_OUTBLK_FULL);

	if (b_data(&appctx->outbuf)) {
		se_fl_set(appctx->sedesc, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		TRACE_STATE("waiting for more room", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
	}
	else {
		se_fl_clr(appctx->sedesc, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
		if (applet_fl_test(appctx, APPCTX_FL_EOI)) {
			se_fl_set(appctx->sedesc, SE_FL_EOI);
			TRACE_STATE("report EOI to SE", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
		}
		if (applet_fl_test(appctx, APPCTX_FL_EOS)) {
			se_fl_set(appctx->sedesc, SE_FL_EOS);
			TRACE_STATE("report EOS to SE", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
		}
		if (applet_fl_test(appctx, APPCTX_FL_ERROR)) {
			se_fl_set(appctx->sedesc, SE_FL_ERROR);
			TRACE_STATE("report ERROR to SE", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
		}

		if (applet_fl_test(appctx, APPCTX_FL_ERROR))
			se_report_term_evt(appctx->sedesc, !applet_fl_test(appctx, APPCTX_FL_EOI) ? se_tevt_type_truncated_rcv_err : se_tevt_type_rcv_err);
		else if (applet_fl_test(appctx, APPCTX_FL_EOS))
			se_report_term_evt(appctx->sedesc, !applet_fl_test(appctx, APPCTX_FL_EOI) ? se_tevt_type_truncated_eos : se_tevt_type_eos);
	}

  end:
	TRACE_LEAVE(APPLET_EV_RECV, appctx);
	return ret;
}

size_t appctx_htx_snd_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags)
{
	struct htx *appctx_htx = htx_from_buf(&appctx->inbuf);
	struct htx *buf_htx = htx_from_buf(buf);
	size_t ret = 0;

	ret = buf_htx->data;
	if (htx_is_empty(appctx_htx) && buf_htx->data == count) {
		htx_to_buf(appctx_htx, &appctx->inbuf);
		htx_to_buf(buf_htx, buf);
		b_xfer(&appctx->inbuf, buf, b_data(buf));
		goto end;
	}

	htx_xfer_blks(appctx_htx, buf_htx, count, HTX_BLK_UNUSED);
	if (htx_is_empty(buf_htx)) {
		appctx_htx->flags |= (buf_htx->flags & HTX_FL_EOM);
	}

	appctx_htx->extra = (buf_htx->extra ? (buf_htx->data + buf_htx->extra) : 0);
	htx_to_buf(appctx_htx, &appctx->outbuf);
	htx_to_buf(buf_htx, buf);
	ret -= buf_htx->data;
end:
	if (ret < count) {
		applet_fl_set(appctx, APPCTX_FL_INBLK_FULL);
		TRACE_STATE("report appctx inbuf is full", APPLET_EV_SEND|APPLET_EV_BLK, appctx);
	}
	return ret;
}

size_t appctx_raw_snd_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned flags)
{
	size_t ret = 0;

	ret = b_xfer(&appctx->inbuf, buf, MIN(b_room(&appctx->inbuf), count));
	if (ret < count) {
		applet_fl_set(appctx, APPCTX_FL_INBLK_FULL);
		TRACE_STATE("report appctx inbuf is full", APPLET_EV_SEND|APPLET_EV_BLK, appctx);
	}
  end:
	return ret;
}

size_t appctx_snd_buf(struct stconn *sc, struct buffer *buf, size_t count, unsigned int flags)
{
	struct appctx *appctx = __sc_appctx(sc);
	size_t ret = 0;

	TRACE_ENTER(APPLET_EV_SEND, appctx);

	if (applet_fl_test(appctx, (APPCTX_FL_ERROR|APPCTX_FL_ERR_PENDING)))
		goto end;

	if (applet_fl_test(appctx, (APPCTX_FL_INBLK_FULL|APPCTX_FL_INBLK_ALLOC)))
		goto end;

	if (!count)
		goto end;

	if (!appctx_get_buf(appctx, &appctx->inbuf)) {
		TRACE_STATE("waiting for appctx inbuf allocation", APPLET_EV_SEND|APPLET_EV_BLK, appctx);
		goto end;
	}

	ret = appctx->applet->snd_buf(appctx, buf, count, flags);

	if (applet_fl_test(appctx, (APPCTX_FL_ERROR|APPCTX_FL_ERR_PENDING)))
		se_report_term_evt(appctx->sedesc, se_tevt_type_snd_err);

  end:
	if (applet_fl_test(appctx, (APPCTX_FL_ERROR|APPCTX_FL_ERR_PENDING))) {
		BUG_ON((applet_fl_get(appctx) & (APPCTX_FL_EOS|APPCTX_FL_ERROR|APPCTX_FL_ERR_PENDING)) == (APPCTX_FL_EOS|APPCTX_FL_ERR_PENDING));
		applet_set_error(appctx);
		TRACE_STATE("report ERR_PENDING/ERROR to SE", APPLET_EV_SEND, appctx);
	}
	TRACE_LEAVE(APPLET_EV_SEND, appctx);
	return ret;
}

int appctx_fastfwd(struct stconn *sc, unsigned int count, unsigned int flags)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct sedesc *sdo = NULL;
	unsigned int len, nego_flags = NEGO_FF_FL_NONE;
	int ret = 0;

	TRACE_ENTER(APPLET_EV_RECV, appctx);

	applet_fl_set(appctx, APPCTX_FL_FASTFWD);

	/* TODO: outbuf must be empty. Find a better way to handle that but for now just return -1 */
	if (b_data(&appctx->outbuf)) {
		TRACE_STATE("Output buffer not empty, cannot fast-forward data", APPLET_EV_RECV, appctx);
		return -1;
	}

	sdo = se_opposite(appctx->sedesc);
	if (!sdo) {
		TRACE_STATE("Opposite endpoint not available yet", APPLET_EV_RECV, appctx);
		goto end;
	}

	if (appctx->to_forward && count > appctx->to_forward) {
		count = appctx->to_forward;
		nego_flags |= NEGO_FF_FL_EXACT_SIZE;
	}

	len = se_nego_ff(sdo, &BUF_NULL, count, nego_flags);
	if (sdo->iobuf.flags & IOBUF_FL_NO_FF) {
		sc_ep_clr(sc, SE_FL_MAY_FASTFWD_PROD);
		applet_fl_clr(appctx, APPCTX_FL_FASTFWD);
		TRACE_DEVEL("Fast-forwarding not supported by opposite endpoint, disable it", APPLET_EV_RECV, appctx);
		goto end;
	}
	if (sdo->iobuf.flags & IOBUF_FL_FF_BLOCKED) {
		sc_ep_set(sc, /* SE_FL_RCV_MORE |  */SE_FL_WANT_ROOM);
		TRACE_STATE("waiting for more room", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
		goto end;
	}

	b_add(sdo->iobuf.buf, sdo->iobuf.offset);
	ret = appctx->applet->fastfwd(appctx, sdo->iobuf.buf, len, 0);
	b_sub(sdo->iobuf.buf, sdo->iobuf.offset);
	sdo->iobuf.data += ret;

	if (se_fl_test(appctx->sedesc, SE_FL_WANT_ROOM)) {
		/* The applet request more room, report the info at the iobuf level */
		sdo->iobuf.flags |= (IOBUF_FL_FF_BLOCKED|IOBUF_FL_FF_WANT_ROOM);
		TRACE_STATE("waiting for more room", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
	}

	if (applet_fl_test(appctx, APPCTX_FL_EOI)) {
		se_fl_set(appctx->sedesc, SE_FL_EOI);
		sdo->iobuf.flags |= IOBUF_FL_EOI; /* TODO: it may be good to have a flag to be sure we can
						   *       forward the EOI the to consumer side
						   */
		TRACE_STATE("report EOI to SE", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
	}
	if (applet_fl_test(appctx, APPCTX_FL_EOS)) {
		se_fl_set(appctx->sedesc, SE_FL_EOS);
		TRACE_STATE("report EOS to SE", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
	}
	if (applet_fl_test(appctx, APPCTX_FL_ERROR)) {
		se_fl_set(appctx->sedesc, SE_FL_ERROR);
		TRACE_STATE("report ERROR to SE", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
	}
	/* else */
	/* 	applet_have_more_data(appctx); */

	if (applet_fl_test(appctx, APPCTX_FL_ERROR))
		se_report_term_evt(appctx->sedesc, !applet_fl_test(appctx, APPCTX_FL_EOI) ? se_tevt_type_truncated_rcv_err : se_tevt_type_rcv_err);
	else if (applet_fl_test(appctx, APPCTX_FL_EOS))
		se_report_term_evt(appctx->sedesc, !applet_fl_test(appctx, APPCTX_FL_EOI) ? se_tevt_type_truncated_eos : se_tevt_type_eos);

	if (se_done_ff(sdo) != 0 || !(sdo->iobuf.flags & (IOBUF_FL_FF_BLOCKED|IOBUF_FL_FF_WANT_ROOM))) {
		/* Something was forwarding or the consumer states it is not
		 * blocked anyore, don't reclaim more room */
		se_fl_clr(appctx->sedesc, SE_FL_WANT_ROOM);
		TRACE_STATE("more room available", APPLET_EV_RECV|APPLET_EV_BLK, appctx);
	}

end:
	TRACE_LEAVE(APPLET_EV_RECV, appctx);
	return ret;
}

/* Atomically append a line to applet <ctx>'s output, appending a trailing LF.
 * The line is read from vectors <v1> and <v2> at offset <ofs> relative to the
 * area's origin, for <len> bytes. It returns the number of bytes consumed from
 * the input vectors on success, -1 if it temporarily cannot (buffer full), -2
 * if it will never be able to (too large msg). The vectors are not modified.
 * The caller is responsible for making sure that there are at least ofs+len
 * bytes in the input vectors.
 */
ssize_t applet_append_line(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len)
{
	struct appctx *appctx = ctx;

	if (unlikely(len + 1 > b_size(&trash))) {
		/* too large a message to ever fit, let's skip it */
		return -2;
	}

	chunk_reset(&trash);
	vp_peek_ofs(v1, v2, ofs, trash.area, len);
	trash.data += len;
	trash.area[trash.data++] = '\n';
	if (applet_putchk(appctx, &trash) == -1)
		return -1;
	return len;
}

/* Default applet handler */
struct task *task_run_applet(struct task *t, void *context, unsigned int state)
{
	struct appctx *app = context;
	struct stconn *sc, *sco;
	struct channel *ic, *oc;
	unsigned int rate;
	size_t input, output;
	int did_send = 0;

	TRACE_ENTER(APPLET_EV_PROCESS, app);

	if (applet_fl_test(app, APPCTX_FL_WANT_DIE)) {
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

	ic = sc_ic(sc);
	oc = sc_oc(sc);

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

	channel_check_idletimer(ic);

	input  = ic->total;
	output = co_data(oc);
	app->applet->fct(app);

	TRACE_POINT(APPLET_EV_PROCESS, app);

	/* now check if the applet has released some room and forgot to
	 * notify the other side about it.
	 */
	if (output != co_data(oc)) {
		oc->flags |= CF_WRITE_EVENT | CF_WROTE_DATA;
		if (sco->room_needed < 0 || channel_recv_max(oc) >= sco->room_needed)
			sc_have_room(sco);
		did_send = 1;
	}
	else {
		if (!sco->room_needed)
			sc_have_room(sco);
	}

	input = ic->total - input;
	if (input) {
		channel_check_xfer(ic, input);
		sc_ep_report_read_activity(sc);
	}

	/* TODO: May be move in appctx_rcv_buf or sc_applet_process ? */
	if (sc_waiting_room(sc) && (sc->flags & SC_FL_ABRT_DONE)) {
		sc_ep_set(sc, SE_FL_EOS|SE_FL_ERROR);
	}

	if (!co_data(oc)) {
		if (did_send)
			sc_ep_report_send_activity(sc);
	}
	else
		sc_ep_report_blocked_send(sc, did_send);

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
	channel_release_buffer(ic, &app->buffer_wait);
	TRACE_LEAVE(APPLET_EV_PROCESS, app);
	return t;
}


/* Default applet handler based on IN/OUT buffers. It is a true task here, no a tasklet  */
struct task *task_process_applet(struct task *t, void *context, unsigned int state)
{
	struct appctx *app = context;
	struct stconn *sc;
	unsigned int rate;

	TRACE_ENTER(APPLET_EV_PROCESS, app);

	if (applet_fl_test(app, APPCTX_FL_WANT_DIE)) {
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

	sc_applet_sync_send(sc);

	/* We always pretend the applet can't get and doesn't want to
	 * put, it's up to it to change this if needed. This ensures
	 * that one applet which ignores any event will not spin.
	 */
	applet_need_more_data(app);
	applet_have_no_more_data(app);

	app->applet->fct(app);

	TRACE_POINT(APPLET_EV_PROCESS, app);

	if (b_data(&app->outbuf) || se_fl_test(app->sedesc, SE_FL_MAY_FASTFWD_PROD) ||
	    applet_fl_test(app, APPCTX_FL_EOI|APPCTX_FL_EOS|APPCTX_FL_ERROR))
		applet_have_more_data(app);

	sc_applet_sync_recv(sc);

	/* TODO: May be move in appctx_rcv_buf or sc_applet_process ? */
	if (sc_waiting_room(sc) && (sc->flags & SC_FL_ABRT_DONE)) {
		sc_ep_set(sc, SE_FL_EOS|SE_FL_ERROR);
	}

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
	appctx_release_buffers(app);
	TRACE_LEAVE(APPLET_EV_PROCESS, app);
	return t;
}

/* config parser for global "tune.applet.zero-copy-forwarding" */
static int cfg_parse_applet_zero_copy_fwd(char **args, int section_type, struct proxy *curpx,
					  const struct proxy *defpx, const char *file, int line,
					  char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.no_zero_copy_fwd &= ~NO_ZERO_COPY_FWD_APPLET;
	else if (strcmp(args[1], "off") == 0)
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD_APPLET;
	else {
		memprintf(err, "'%s' expects 'on' or 'off'.", args[0]);
		return -1;
	}
	return 0;
}


/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.applet.zero-copy-forwarding", cfg_parse_applet_zero_copy_fwd },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
