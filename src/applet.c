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
#include <haproxy/conn_stream.h>
#include <haproxy/list.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>

unsigned int nb_applets = 0;

DECLARE_POOL(pool_head_appctx,  "appctx",  sizeof(struct appctx));

/* Tries to allocate a new appctx and initialize all of its fields. The appctx
 * is returned on success, NULL on failure. The appctx must be released using
 * appctx_free(). <applet> is assigned as the applet, but it can be NULL. The
 * applet's task is always created on the current thread.
 */
struct appctx *appctx_new(struct applet *applet, struct sedesc *sedesc, unsigned long thread_mask)
{
	struct appctx *appctx;

	/* Backend appctx cannot be started on another thread than the local one */
	BUG_ON(thread_mask != tid_bit && sedesc);

	appctx = pool_zalloc(pool_head_appctx);
	if (unlikely(!appctx))
		goto fail_appctx;

	LIST_INIT(&appctx->wait_entry);
	appctx->obj_type = OBJ_TYPE_APPCTX;
	appctx->applet = applet;
	appctx->sess = NULL;
	if (!sedesc) {
		sedesc = sedesc_new();
		if (!sedesc)
			goto fail_endp;
		sedesc->se = appctx;
		se_fl_set(sedesc, SE_FL_T_APPLET | SE_FL_ORPHAN);
	}
	appctx->sedesc = sedesc;

	appctx->t = task_new(thread_mask);
	if (unlikely(!appctx->t))
		goto fail_task;
	appctx->t->process = task_run_applet;
	appctx->t->context = appctx;

	LIST_INIT(&appctx->buffer_wait.list);
	appctx->buffer_wait.target = appctx;
	appctx->buffer_wait.wakeup_cb = appctx_buf_available;

	_HA_ATOMIC_INC(&nb_applets);
	return appctx;

  fail_task:
	sedesc_free(appctx->sedesc);
  fail_endp:
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

	sess = session_new(px, NULL, &appctx->obj_type);
	if (!sess)
		return -1;
	if (!sc_new_from_endp(appctx->sedesc, sess, input)) {
		session_free(sess);
		return -1;
	}
	appctx->sess = sess;
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
	if (!se_fl_test(appctx->sedesc, SE_FL_ORPHAN) && !(appctx_cs(appctx)->flags & SC_FL_ISBACK)) {
		stream_free(appctx_strm(appctx));
		return;
	}
	appctx_free(appctx);
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

/* call the applet's release() function if any, and marks the sedesc as shut.
 * Needs to be called upon close().
 */
void appctx_shut(struct appctx *appctx)
{
	if (se_fl_test(appctx->sedesc, SE_FL_SHR | SE_FL_SHW))
		return;

	if (appctx->applet->release)
		appctx->applet->release(appctx);

	se_fl_set(appctx->sedesc, SE_FL_SHRR | SE_FL_SHWN);
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
	struct stconn *cs = appctx_cs(appctx);

	/* allocation requested ? */
	if (!(cs->flags & SC_FL_NEED_BUFF))
		return 0;

	sc_have_buff(cs);

	/* was already allocated another way ? if so, don't take this one */
	if (c_size(sc_ic(cs)) || sc_ic(cs)->pipe)
		return 0;

	/* allocation possible now ? */
	if (!b_alloc(&sc_ic(cs)->buf)) {
		sc_need_buff(cs);
		return 0;
	}

	task_wakeup(appctx->t, TASK_WOKEN_RES);
	return 1;
}

/* Default applet handler */
struct task *task_run_applet(struct task *t, void *context, unsigned int state)
{
	struct appctx *app = context;
	struct stconn *cs;
	unsigned int rate;
	size_t count;

	if (app->state & APPLET_WANT_DIE) {
		__appctx_free(app);
		return NULL;
	}

	if (se_fl_test(app->sedesc, SE_FL_ORPHAN)) {
		/* Finalize init of orphan appctx. .init callback function must
		 * be defined and it must finalize appctx startup.
		 */
		BUG_ON(!app->applet->init);

		if (appctx_init(app) == -1) {
			appctx_free_on_early_error(app);
			return NULL;
		}
		BUG_ON(!app->sess || !appctx_cs(app) || !appctx_strm(app));
	}

	cs = appctx_cs(app);

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
	if (!sc_alloc_ibuf(cs, &app->buffer_wait))
		applet_have_more_data(app);

	count = co_data(sc_oc(cs));
	app->applet->fct(app);

	/* now check if the applet has released some room and forgot to
	 * notify the other side about it.
	 */
	if (count != co_data(sc_oc(cs))) {
		sc_oc(cs)->flags |= CF_WRITE_PARTIAL | CF_WROTE_DATA;
		sc_have_room(sc_opposite(cs));
	}

	/* measure the call rate and check for anomalies when too high */
	rate = update_freq_ctr(&app->call_rate, 1);
	if (rate >= 100000 && app->call_rate.prev_ctr && // looped more than 100k times over last second
	    ((b_size(sc_ib(cs)) && cs->flags & SC_FL_NEED_ROOM) || // asks for a buffer which is present
	     (b_size(sc_ib(cs)) && !b_data(sc_ib(cs)) && cs->flags & SC_FL_NEED_ROOM) || // asks for room in an empty buffer
	     (b_data(sc_ob(cs)) && sc_is_send_allowed(cs)) || // asks for data already present
	     (!b_data(sc_ib(cs)) && b_data(sc_ob(cs)) && // didn't return anything ...
	      (sc_oc(cs)->flags & (CF_WRITE_PARTIAL|CF_SHUTW_NOW)) == CF_SHUTW_NOW))) { // ... and left data pending after a shut
		stream_dump_and_crash(&app->obj_type, read_freq_ctr(&app->call_rate));
	}

	cs->app_ops->wake(cs);
	channel_release_buffer(sc_ic(cs), &app->buffer_wait);
	return t;
}
