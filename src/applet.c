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
#include <proto/stream.h>
#include <proto/stream_interface.h>

struct list applet_active_queue = LIST_HEAD_INIT(applet_active_queue);
struct list applet_run_queue    = LIST_HEAD_INIT(applet_run_queue);

void applet_run_active()
{
	struct appctx *curr;
	struct stream_interface *si;

	if (LIST_ISEMPTY(&applet_active_queue))
		return;

	/* move active queue to run queue */
	applet_active_queue.n->p = &applet_run_queue;
	applet_active_queue.p->n = &applet_run_queue;

	applet_run_queue = applet_active_queue;
	LIST_INIT(&applet_active_queue);

	/* The list is only scanned from the head. This guarantees that if any
	 * applet removes another one, there is no side effect while walking
	 * through the list.
	 */
	while (!LIST_ISEMPTY(&applet_run_queue)) {
		curr = LIST_ELEM(applet_run_queue.n, typeof(curr), runq);
		si = curr->owner;

		/* now we'll need a buffer */
		if (!stream_alloc_recv_buffer(si_ic(si))) {
			si->flags |= SI_FL_WAIT_ROOM;
			LIST_DEL(&curr->runq);
			LIST_INIT(&curr->runq);
			continue;
		}

		/* We always pretend the applet can't get and doesn't want to
		 * put, it's up to it to change this if needed. This ensures
		 * that one applet which ignores any event will not spin.
		 */
		si_applet_cant_get(si);
		si_applet_stop_put(si);

		curr->applet->fct(curr);
		si_applet_wake_cb(si);

		if (applet_run_queue.n == &curr->runq) {
			/* curr was left in the list, move it back to the active list */
			LIST_DEL(&curr->runq);
			LIST_ADDQ(&applet_active_queue, &curr->runq);
		}
	}
}
