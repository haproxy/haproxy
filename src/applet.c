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

struct task *task_run_applet(struct task *t, void *context, unsigned short state)
{
	struct appctx *app = context;
	struct stream_interface *si = app->owner;

	if (app->state & APPLET_WANT_DIE) {
		__appctx_free(app);
		return NULL;
	}
	/* Now we'll try to allocate the input buffer. We wake up the
	 * applet in all cases. So this is the applet responsibility to
	 * check if this buffer was allocated or not. This let a chance
	 * for applets to do some other processing if needed. */
	if (!channel_alloc_buffer(si_ic(si), &app->buffer_wait))
		si_applet_cant_put(si);

	/* We always pretend the applet can't get and doesn't want to
	 * put, it's up to it to change this if needed. This ensures
	 * that one applet which ignores any event will not spin.
	 */
	si_applet_cant_get(si);
	si_applet_stop_put(si);

	app->applet->fct(app);
	si_applet_wake_cb(si);
	channel_release_buffer(si_ic(si), &app->buffer_wait);
	return t;
}

