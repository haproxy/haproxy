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
#include <haproxy/channel.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/sc_strm.h>
#include <haproxy/session.h>
#include <haproxy/stconn.h>
#include <haproxy/task.h>

extern unsigned int nb_applets;
extern struct pool_head *pool_head_appctx;

struct task *task_run_applet(struct task *t, void *context, unsigned int state);
int appctx_buf_available(void *arg);
void *applet_reserve_svcctx(struct appctx *appctx, size_t size);
void appctx_shut(struct appctx *appctx);

struct appctx *appctx_new(struct applet *applet, struct sedesc *sedesc, unsigned long thread_mask);
int appctx_finalize_startup(struct appctx *appctx, struct proxy *px, struct buffer *input);
void appctx_free_on_early_error(struct appctx *appctx);

static inline struct appctx *appctx_new_on(struct applet *applet, struct sedesc *sedesc, uint thr)
{
	return appctx_new(applet, sedesc, 1UL << thr);
}

static inline struct appctx *appctx_new_here(struct applet *applet, struct sedesc *sedesc)
{
	return appctx_new(applet, sedesc, tid_bit);
}

static inline struct appctx *appctx_new_anywhere(struct applet *applet, struct sedesc *sedesc)
{
	return appctx_new(applet, sedesc, MAX_THREADS_MASK);
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
	BUG_ON(appctx->sedesc && !se_fl_test(appctx->sedesc, SE_FL_ORPHAN));
	sedesc_free(appctx->sedesc);
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

/* returns the stream connector the appctx is attached to, via the sedesc */
static inline struct stconn *appctx_sc(const struct appctx *appctx)
{
	return appctx->sedesc->sc;
}

/* returns the stream the appctx is attached to. Note that a stream *must*
 * be attached, as we use an unchecked dereference via __sc_strm().
 */
static inline struct stream *appctx_strm(const struct appctx *appctx)
{
	return __sc_strm(appctx->sedesc->sc);
}

/* The applet announces it has more data to deliver to the stream's input
 * buffer.
 */
static inline void applet_have_more_data(struct appctx *appctx)
{
	se_fl_clr(appctx->sedesc, SE_FL_HAVE_NO_DATA);
}

/* The applet announces it doesn't have more data for the stream's input
 * buffer.
 */
static inline void applet_have_no_more_data(struct appctx *appctx)
{
	se_fl_set(appctx->sedesc, SE_FL_HAVE_NO_DATA);
}

/* The applet indicates that it's ready to consume data from the stream's
 * output buffer.
 */
static inline void applet_will_consume(struct appctx *appctx)
{
	se_fl_set(appctx->sedesc, SE_FL_WILL_CONSUME);
}

/* The applet indicates that it's not willing to consume data from the stream's
 * output buffer.
 */
static inline void applet_wont_consume(struct appctx *appctx)
{
	se_fl_clr(appctx->sedesc, SE_FL_WILL_CONSUME);
}

/* The applet indicates that it's willing to consume data from the stream's
 * output buffer, but that there's not enough, so it doesn't want to be woken
 * up until more are presented.
 */
static inline void applet_need_more_data(struct appctx *appctx)
{
	se_fl_set(appctx->sedesc, SE_FL_WILL_CONSUME | SE_FL_WAIT_DATA);
}

/* writes chunk <chunk> into the input channel of the stream attached to this
 * appctx's endpoint, and marks the SC_FL_NEED_ROOM on a channel full error.
 * See ci_putchk() for the list of return codes.
 */
static inline int applet_putchk(struct appctx *appctx, struct buffer *chunk)
{
	struct sedesc *se = appctx->sedesc;
	int ret;

	ret = ci_putchk(sc_ic(se->sc), chunk);
	if (ret == -1)
		sc_need_room(se->sc);

	return ret;
}

/* writes <len> chars from <blk> into the input channel of the stream attached
 * to this appctx's endpoint, and marks the SC_FL_NEED_ROOM on a channel full
 * error. See ci_putblk() for the list of return codes.
 */
static inline int applet_putblk(struct appctx *appctx, const char *blk, int len)
{
	struct sedesc *se = appctx->sedesc;
	int ret;

	ret = ci_putblk(sc_ic(se->sc), blk, len);
	if (ret == -1)
		sc_need_room(se->sc);

	return ret;
}

/* writes chars from <str> up to the trailing zero (excluded) into the input
 * channel of the stream attached to this appctx's endpoint, and marks the
 * SC_FL_NEED_ROOM on a channel full error. See ci_putstr() for the list of
 * return codes.
 */
static inline int applet_putstr(struct appctx *appctx, const char *str)
{
	struct sedesc *se = appctx->sedesc;
	int ret;

	ret = ci_putstr(sc_ic(se->sc), str);
	if (ret == -1)
		sc_need_room(se->sc);

	return ret;
}

/* writes character <chr> into the input channel of the stream attached to this
 * appctx's endpoint, and marks the SC_FL_NEED_ROOM on a channel full error.
 * See ci_putchr() for the list of return codes.
 */
static inline int applet_putchr(struct appctx *appctx, char chr)
{
	struct sedesc *se = appctx->sedesc;
	int ret;

	ret = ci_putchr(sc_ic(se->sc), chr);
	if (ret == -1)
		sc_need_room(se->sc);

	return ret;
}

#endif /* _HAPROXY_APPLET_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
