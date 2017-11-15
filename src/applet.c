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
unsigned long active_applets_mask = 0;
unsigned int applets_active_queue = 0;
__decl_hathreads(HA_SPINLOCK_T applet_active_lock);  /* spin lock related to applet active queue */

struct list applet_active_queue = LIST_HEAD_INIT(applet_active_queue);

void applet_run_active()
{
	struct appctx *curr, *next;
	struct stream_interface *si;
	struct list applet_cur_queue = LIST_HEAD_INIT(applet_cur_queue);
	int max_processed;

	max_processed = applets_active_queue;
	if (max_processed > 200)
		max_processed = 200;

	HA_SPIN_LOCK(APPLETS_LOCK, &applet_active_lock);
	if (!(active_applets_mask & tid_bit)) {
		HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
		return;
	}
	active_applets_mask &= ~tid_bit;
	curr = LIST_NEXT(&applet_active_queue, typeof(curr), runq);
	while (&curr->runq != &applet_active_queue) {
		next = LIST_NEXT(&curr->runq, typeof(next), runq);
		if (curr->thread_mask & tid_bit) {
			LIST_DEL(&curr->runq);
			curr->state = APPLET_RUNNING;
			LIST_ADDQ(&applet_cur_queue, &curr->runq);
			applets_active_queue--;
			max_processed--;
		}
		curr = next;
		if (max_processed <= 0) {
			active_applets_mask |= tid_bit;
			break;
		}
	}
	HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);

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
			LIST_INIT(&curr->runq);
			HA_SPIN_LOCK(APPLETS_LOCK, &applet_active_lock);
			if (curr->state & APPLET_WANT_DIE) {
				curr->state = APPLET_SLEEPING;
				__appctx_free(curr);
			}
			else {
				if (curr->state & APPLET_WOKEN_UP) {
					curr->state = APPLET_SLEEPING;
					__appctx_wakeup(curr);
				}
				else {
					curr->state = APPLET_SLEEPING;
				}
			}
			HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
		}
	}
}

__attribute__((constructor))
static void __applet_init(void)
{
	HA_SPIN_INIT(&applet_active_lock);
}
