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

#include <common/config.h>
#include <common/mini-clist.h>
#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

unsigned int nb_applets = 0;

/* Callback used to wake up an applet when a buffer is available. The applet
 * <appctx> is woken up if an input buffer was requested for the associated
 * stream interface. In this case the buffer is immediately allocated and the
 * function returns 1. Otherwise it returns 0. Note that this automatically
 * covers multiple wake-up attempts by ensuring that the same buffer will not
 * be accounted for multiple times.
 */
int appctx_buf_available(void *arg)
{
	struct appctx *appctx = arg;
	struct stream_interface *si = appctx->owner;

	/* allocation requested ? */
	if (!(si->flags & SI_FL_RXBLK_BUFF))
		return 0;

	si_rx_buff_rdy(si);

	/* was already allocated another way ? if so, don't take this one */
	if (c_size(si_ic(si)) || si_ic(si)->pipe)
		return 0;

	/* allocation possible now ? */
	if (!b_alloc_margin(&si_ic(si)->buf, global.tune.reserved_bufs)) {
		si_rx_buff_blk(si);
		return 0;
	}

	task_wakeup(appctx->t, TASK_WOKEN_RES);
	return 1;
}

/* Default applet handler */
struct task *task_run_applet(struct task *t, void *context, unsigned short state)
{
	struct appctx *app = context;
	struct stream_interface *si = app->owner;

	if (app->state & APPLET_WANT_DIE) {
		__appctx_free(app);
		return NULL;
	}

	/* We always pretend the applet can't get and doesn't want to
	 * put, it's up to it to change this if needed. This ensures
	 * that one applet which ignores any event will not spin.
	 */
	si_cant_get(si);
	si_rx_endp_done(si);

	/* Now we'll try to allocate the input buffer. We wake up the applet in
	 * all cases. So this is the applet's responsibility to check if this
	 * buffer was allocated or not. This leaves a chance for applets to do
	 * some other processing if needed. The applet doesn't have anything to
	 * do if it needs the buffer, it will be called again upon readiness.
	 */
	if (!si_alloc_ibuf(si, &app->buffer_wait))
		si_rx_endp_more(si);

	app->applet->fct(app);
	si_applet_wake_cb(si);
	channel_release_buffer(si_ic(si), &app->buffer_wait);
	return t;
}

