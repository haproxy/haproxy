/*
 * include/haproxy/applet.h
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

#ifndef _HAPROXY_APPLET_H
#define _HAPROXY_APPLET_H

#include <stdlib.h>

#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/conn_stream.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/session.h>
#include <haproxy/task.h>

extern unsigned int nb_applets;
extern struct pool_head *pool_head_appctx;

struct task *task_run_applet(struct task *t, void *context, unsigned int state);
int appctx_buf_available(void *arg);
void *applet_reserve_svcctx(struct appctx *appctx, size_t size);
void appctx_shut(struct appctx *appctx);

struct appctx *appctx_new(struct applet *applet, struct cs_endpoint *endp, unsigned long thread_mask);
int appctx_finalize_startup(struct appctx *appctx, struct proxy *px, struct buffer *input);
void appctx_free_on_early_error(struct appctx *appctx);

static inline struct appctx *appctx_new_on(struct applet *applet, struct cs_endpoint *endp, uint thr)
{
	return appctx_new(applet, endp, 1UL << thr);
}

static inline struct appctx *appctx_new_here(struct applet *applet, struct cs_endpoint *endp)
{
	return appctx_new(applet, endp, tid_bit);
}

static inline struct appctx *appctx_new_anywhere(struct applet *applet, struct cs_endpoint *endp)
{
	return appctx_new(applet, endp, MAX_THREADS_MASK);
}

/* Helper function to call .init applet callback function, if it exists. Returns 0
 * on success and -1 on error.
 */
static inline int appctx_init(struct appctx *appctx)
{
	/* Set appctx affinity to the current thread. Because, after this call,
	 * the appctx will be fully initialized. The session and the stream will
	 * eventually be created. The affinity must be set now !
	 */
	BUG_ON((appctx->t->thread_mask & tid_bit) == 0);
	task_set_affinity(appctx->t, tid_bit);

	if (appctx->applet->init)
		return appctx->applet->init(appctx);
	return 0;
}

/* Releases an appctx previously allocated by appctx_new(). */
static inline void __appctx_free(struct appctx *appctx)
{
	task_destroy(appctx->t);
	if (LIST_INLIST(&appctx->buffer_wait.list))
		LIST_DEL_INIT(&appctx->buffer_wait.list);
	if (appctx->sess)
		session_free(appctx->sess);
	BUG_ON(appctx->endp && !(appctx->endp->flags & CS_EP_ORPHAN));
	cs_endpoint_free(appctx->endp);
	pool_free(pool_head_appctx, appctx);
	_HA_ATOMIC_DEC(&nb_applets);
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

/* returns the conn_stream the appctx is attached to, via the endp */
static inline struct conn_stream *appctx_cs(const struct appctx *appctx)
{
	return appctx->endp->cs;
}

/* returns the stream the appctx is attached to. Note that a stream *must*
 * be attached, as we use an unchecked dereference via __cs_strm().
 */
static inline struct stream *appctx_strm(const struct appctx *appctx)
{
	return __cs_strm(appctx->endp->cs);
}

#endif /* _HAPROXY_APPLET_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
