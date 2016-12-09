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

unsigned int nb_applets = 0;
unsigned int applets_active_queue = 0;

struct list applet_active_queue = LIST_HEAD_INIT(applet_active_queue);
struct list applet_cur_queue    = LIST_HEAD_INIT(applet_cur_queue);

void applet_run_active()
{
	struct appctx *curr;
	struct stream_interface *si;

	if (LIST_ISEMPTY(&applet_active_queue))
		return;

	/* move active queue to run queue */
	applet_active_queue.n->p = &applet_cur_queue;
	applet_active_queue.p->n = &applet_cur_queue;

	applet_cur_queue = applet_active_queue;
	LIST_INIT(&applet_active_queue);

	/* The list is only scanned from the head. This guarantees that if any
	 * applet removes another one, there is no side effect while walking
	 * through the list.
	 */
	while (!LIST_ISEMPTY(&applet_cur_queue)) {
		curr = LIST_ELEM(applet_cur_queue.n, typeof(curr), runq);
		si = curr->owner;

		/* Now we'll try to allocate the input buffer. We wake up the
		 * applet in all cases. So this is the applet responsibility to
		 * check if this buffer was allocated or not. This let a chance
		 * for applets to do some other processing if needed. */
		if (!channel_alloc_buffer(si_ic(si), &curr->buffer_wait))
			si_applet_cant_put(si);

		/* We always pretend the applet can't get and doesn't want to
		 * put, it's up to it to change this if needed. This ensures
		 * that one applet which ignores any event will not spin.
		 */
		si_applet_cant_get(si);
		si_applet_stop_put(si);

		curr->applet->fct(curr);
		si_applet_wake_cb(si);
		channel_release_buffer(si_ic(si), &curr->buffer_wait);

		if (applet_cur_queue.n == &curr->runq) {
			/* curr was left in the list, move it back to the active list */
			LIST_DEL(&curr->runq);
			LIST_ADDQ(&applet_active_queue, &curr->runq);
		}
	}
}
