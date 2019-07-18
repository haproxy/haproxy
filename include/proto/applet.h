/*
 * include/proto/applet.h
 * This file contains applet function prototypes
 *
 * Copyright (C) 2000-2015 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_APPLET_H
#define _PROTO_APPLET_H

#include <stdlib.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <types/applet.h>
#include <proto/task.h>

extern unsigned int nb_applets;
extern struct pool_head *pool_head_appctx;

struct task *task_run_applet(struct task *t, void *context, unsigned short state);

int appctx_buf_available(void *arg);


/* Initializes all required fields for a new appctx. Note that it does the
 * minimum acceptable initialization for an appctx. This means only the
 * 3 integer states st0, st1, st2 and the chunk used to gather unfinished
 * commands are zeroed
 */
static inline void appctx_init(struct appctx *appctx, unsigned long thread_mask)
{
	appctx->st0 = appctx->st1 = appctx->st2 = 0;
	appctx->chunk = NULL;
	appctx->io_release = NULL;
	appctx->thread_mask = thread_mask;
	appctx->call_rate.curr_sec = 0;
	appctx->call_rate.curr_ctr = 0;
	appctx->call_rate.prev_ctr = 0;
	appctx->state = 0;
}

/* Tries to allocate a new appctx and initialize its main fields. The appctx
 * is returned on success, NULL on failure. The appctx must be released using
 * appctx_free(). <applet> is assigned as the applet, but it can be NULL.
 */
static inline struct appctx *appctx_new(struct applet *applet, unsigned long thread_mask)
{
	struct appctx *appctx;

	appctx = pool_alloc(pool_head_appctx);
	if (likely(appctx != NULL)) {
		appctx->obj_type = OBJ_TYPE_APPCTX;
		appctx->applet = applet;
		appctx_init(appctx, thread_mask);
		appctx->t = task_new(thread_mask);
		if (unlikely(appctx->t == NULL)) {
			pool_free(pool_head_appctx, appctx);
			return NULL;
		}
		appctx->t->process = task_run_applet;
		appctx->t->context = appctx;
		LIST_INIT(&appctx->buffer_wait.list);
		appctx->buffer_wait.target = appctx;
		appctx->buffer_wait.wakeup_cb = appctx_buf_available;
		_HA_ATOMIC_ADD(&nb_applets, 1);
	}
	return appctx;
}

/* Releases an appctx previously allocated by appctx_new(). */
static inline void __appctx_free(struct appctx *appctx)
{
	task_destroy(appctx->t);
	if (!LIST_ISEMPTY(&appctx->buffer_wait.list)) {
		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_DEL(&appctx->buffer_wait.list);
		LIST_INIT(&appctx->buffer_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	}

	pool_free(pool_head_appctx, appctx);
	_HA_ATOMIC_SUB(&nb_applets, 1);
}

static inline void appctx_free(struct appctx *appctx)
{
	/* The task is supposed to be run on this thread, so we can just
	 * check if it's running already (or about to run) or not
	 */
	if (!(appctx->t->state & (TASK_QUEUED | TASK_RUNNING)))
		__appctx_free(appctx);
	else {
		/* if it's running, or about to run, defer the freeing
		 * until the callback is called.
		 */
		appctx->state |= APPLET_WANT_DIE;
		task_wakeup(appctx->t, TASK_WOKEN_OTHER);
	}
}

/* wakes up an applet when conditions have changed */
static inline void appctx_wakeup(struct appctx *appctx)
{
	task_wakeup(appctx->t, TASK_WOKEN_OTHER);
}

#endif /* _PROTO_APPLET_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
