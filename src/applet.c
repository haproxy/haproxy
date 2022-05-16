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
#include <haproxy/cs_utils.h>
#include <haproxy/list.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>

unsigned int nb_applets = 0;

DECLARE_POOL(pool_head_appctx,  "appctx",  sizeof(struct appctx));

/* Tries to allocate a new appctx and initialize all of its fields. The appctx
 * is returned on success, NULL on failure. The appctx must be released using
 * appctx_free(). <applet> is assigned as the applet, but it can be NULL. The
 * applet's task is always created on the current thread.
 */
struct appctx *appctx_new(struct applet *applet, struct cs_endpoint *endp, unsigned long thread_mask)
{
	struct appctx *appctx;

	/* Backend appctx cannot be started on another thread than the local one */
	BUG_ON(thread_mask != tid_bit && endp);

	appctx = pool_zalloc(pool_head_appctx);
	if (unlikely(!appctx))
		goto fail_appctx;

	LIST_INIT(&appctx->wait_entry);
	appctx->obj_type = OBJ_TYPE_APPCTX;
	appctx->applet = applet;
	appctx->sess = NULL;
	if (!endp) {
		endp = cs_endpoint_new();
		if (!endp)
			goto fail_endp;
		endp->target = appctx;
		endp->ctx = appctx;
		endp->flags |= (CS_EP_T_APPLET|CS_EP_ORPHAN);
	}
	appctx->endp = endp;

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
	cs_endpoint_free(appctx->endp);
  fail_endp:
	pool_free(pool_head_appctx, appctx);
  fail_appctx:
	return NULL;
}

/* Finalize the frontend appctx startup. It must not be called for a backend
 * appctx. This function is responsible to create the appctx's session and the
 * frontend conn-stream. By transitivity, the stream is also created.
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
	BUG_ON(!(appctx->endp->flags & CS_EP_ORPHAN));

	sess = session_new(px, NULL, &appctx->obj_type);
	if (!sess)
		return -1;
	if (!cs_new_from_endp(appctx->endp, sess, input)) {
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
	/* If a frontend apctx is attached to a conn-stream, release the stream
	 * instead of the appctx.
	 */
	if (!(appctx->endp->flags & CS_EP_ORPHAN) && !(appctx_cs(appctx)->flags & CS_FL_ISBACK)) {
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

/* call the applet's release() function if any, and marks the endp as shut.
 * Needs to be called upon close().
 */
void appctx_shut(struct appctx *appctx)
{
	if (appctx->endp->flags & (CS_EP_SHR|CS_EP_SHW))
		return;

	if (appctx->applet->release)
		appctx->applet->release(appctx);

	appctx->endp->flags |= CS_EP_SHRR | CS_EP_SHWN;
}

/* Callback used to wake up an applet when a buffer is available. The applet
 * <appctx> is woken up if an input buffer was requested for the associated
 * conn-stream. In this case the buffer is immediately allocated and the
 * function returns 1. Otherwise it returns 0. Note that this automatically
 * covers multiple wake-up attempts by ensuring that the same buffer will not
 * be accounted for multiple times.
 */
int appctx_buf_available(void *arg)
{
	struct appctx *appctx = arg;
	struct conn_stream *cs = appctx_cs(appctx);

	/* allocation requested ? */
	if (!(appctx->endp->flags & CS_EP_RXBLK_BUFF))
		return 0;

	cs_rx_buff_rdy(cs);

	/* was already allocated another way ? if so, don't take this one */
	if (c_size(cs_ic(cs)) || cs_ic(cs)->pipe)
		return 0;

	/* allocation possible now ? */
	if (!b_alloc(&cs_ic(cs)->buf)) {
		cs_rx_buff_blk(cs);
		return 0;
	}

	task_wakeup(appctx->t, TASK_WOKEN_RES);
	return 1;
}

/* Default applet handler */
struct task *task_run_applet(struct task *t, void *context, unsigned int state)
{
	struct appctx *app = context;
	struct conn_stream *cs;
	unsigned int rate;
	size_t count;

	if (app->state & APPLET_WANT_DIE) {
		__appctx_free(app);
		return NULL;
	}

	if (app->endp->flags & CS_EP_ORPHAN) {
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
	cs_cant_get(cs);
	cs_rx_endp_done(cs);

	/* Now we'll try to allocate the input buffer. We wake up the applet in
	 * all cases. So this is the applet's responsibility to check if this
	 * buffer was allocated or not. This leaves a chance for applets to do
	 * some other processing if needed. The applet doesn't have anything to
	 * do if it needs the buffer, it will be called again upon readiness.
	 */
	if (!cs_alloc_ibuf(cs, &app->buffer_wait))
		cs_rx_endp_more(cs);

	count = co_data(cs_oc(cs));
	app->applet->fct(app);

	/* now check if the applet has released some room and forgot to
	 * notify the other side about it.
	 */
	if (count != co_data(cs_oc(cs))) {
		cs_oc(cs)->flags |= CF_WRITE_PARTIAL | CF_WROTE_DATA;
		cs_rx_room_rdy(cs_opposite(cs));
	}

	/* measure the call rate and check for anomalies when too high */
	rate = update_freq_ctr(&app->call_rate, 1);
	if (rate >= 100000 && app->call_rate.prev_ctr && // looped more than 100k times over last second
	    ((b_size(cs_ib(cs)) && app->endp->flags & CS_EP_RXBLK_BUFF) || // asks for a buffer which is present
	     (b_size(cs_ib(cs)) && !b_data(cs_ib(cs)) && app->endp->flags & CS_EP_RXBLK_ROOM) || // asks for room in an empty buffer
	     (b_data(cs_ob(cs)) && cs_tx_endp_ready(cs) && !cs_tx_blocked(cs)) || // asks for data already present
	     (!b_data(cs_ib(cs)) && b_data(cs_ob(cs)) && // didn't return anything ...
	      (cs_oc(cs)->flags & (CF_WRITE_PARTIAL|CF_SHUTW_NOW)) == CF_SHUTW_NOW))) { // ... and left data pending after a shut
		stream_dump_and_crash(&app->obj_type, read_freq_ctr(&app->call_rate));
	}

	cs->data_cb->wake(cs);
	channel_release_buffer(cs_ic(cs), &app->buffer_wait);
	return t;
}
