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
#include <common/mini-clist.h>
#include <types/applet.h>
#include <proto/connection.h>

extern unsigned int nb_applets;
extern unsigned long active_applets_mask;
extern unsigned int applets_active_queue;
__decl_hathreads(extern HA_SPINLOCK_T applet_active_lock);
extern struct list applet_active_queue;

void applet_run_active();


static int inline appctx_res_wakeup(struct appctx *appctx);


/* Initializes all required fields for a new appctx. Note that it does the
 * minimum acceptable initialization for an appctx. This means only the
 * 3 integer states st0, st1, st2 are zeroed.
 */
static inline void appctx_init(struct appctx *appctx, unsigned long thread_mask)
{
	appctx->st0 = appctx->st1 = appctx->st2 = 0;
	appctx->io_release = NULL;
	appctx->thread_mask = thread_mask;
	appctx->state = APPLET_SLEEPING;
}

/* Tries to allocate a new appctx and initialize its main fields. The appctx
 * is returned on success, NULL on failure. The appctx must be released using
 * pool_free(connection) or appctx_free(), since it's allocated from the
 * connection pool. <applet> is assigned as the applet, but it can be NULL.
 */
static inline struct appctx *appctx_new(struct applet *applet, unsigned long thread_mask)
{
	struct appctx *appctx;

	appctx = pool_alloc(pool_head_connection);
	if (likely(appctx != NULL)) {
		appctx->obj_type = OBJ_TYPE_APPCTX;
		appctx->applet = applet;
		appctx_init(appctx, thread_mask);
		LIST_INIT(&appctx->runq);
		LIST_INIT(&appctx->buffer_wait.list);
		appctx->buffer_wait.target = appctx;
		appctx->buffer_wait.wakeup_cb = (int (*)(void *))appctx_res_wakeup;
		HA_ATOMIC_ADD(&nb_applets, 1);
	}
	return appctx;
}

/* Releases an appctx previously allocated by appctx_new(). Note that
 * we share the connection pool.
 */
static inline void __appctx_free(struct appctx *appctx)
{
	if (!LIST_ISEMPTY(&appctx->runq)) {
		LIST_DEL(&appctx->runq);
		applets_active_queue--;
	}

	if (!LIST_ISEMPTY(&appctx->buffer_wait.list)) {
		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_DEL(&appctx->buffer_wait.list);
		LIST_INIT(&appctx->buffer_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	}

	pool_free(pool_head_connection, appctx);
	HA_ATOMIC_SUB(&nb_applets, 1);
}
static inline void appctx_free(struct appctx *appctx)
{
	HA_SPIN_LOCK(APPLETS_LOCK, &applet_active_lock);
	if (appctx->state & APPLET_RUNNING) {
		appctx->state |= APPLET_WANT_DIE;
		HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
		return;
	}
	__appctx_free(appctx);
	HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
}

/* wakes up an applet when conditions have changed */
static inline void __appctx_wakeup(struct appctx *appctx)
{
	if (LIST_ISEMPTY(&appctx->runq)) {
		LIST_ADDQ(&applet_active_queue, &appctx->runq);
		applets_active_queue++;
		active_applets_mask |= appctx->thread_mask;
	}
}

static inline void appctx_wakeup(struct appctx *appctx)
{
	HA_SPIN_LOCK(APPLETS_LOCK, &applet_active_lock);
	if (appctx->state & APPLET_RUNNING) {
		appctx->state |= APPLET_WOKEN_UP;
		HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
		return;
	}
	__appctx_wakeup(appctx);
	HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
}

/* Callback used to wake up an applet when a buffer is available. The applet
 * <appctx> is woken up is if it is not already in the list of "active"
 * applets. This functions returns 1 is the stream is woken up, otherwise it
 * returns 0. If task is running we request we check if woken was already
 * requested */
static inline int appctx_res_wakeup(struct appctx *appctx)
{
	HA_SPIN_LOCK(APPLETS_LOCK, &applet_active_lock);
	if (appctx->state & APPLET_RUNNING) {
		if (appctx->state & APPLET_WOKEN_UP) {
			HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
			return 0;
		}
		appctx->state |= APPLET_WOKEN_UP;
		HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
		return 1;
	}
	__appctx_wakeup(appctx);
	HA_SPIN_UNLOCK(APPLETS_LOCK, &applet_active_lock);
	return 1;
}


#endif /* _PROTO_APPLET_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
