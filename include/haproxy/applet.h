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
struct task *task_process_applet(struct task *t, void *context, unsigned int state);
int appctx_buf_available(void *arg);
void *applet_reserve_svcctx(struct appctx *appctx, size_t size);
void applet_reset_svcctx(struct appctx *appctx);
void appctx_shut(struct appctx *appctx);

struct appctx *appctx_new_on(struct applet *applet, struct sedesc *sedesc, int thr);
int appctx_finalize_startup(struct appctx *appctx, struct proxy *px, struct buffer *input);
void appctx_free_on_early_error(struct appctx *appctx);
void appctx_free(struct appctx *appctx);

size_t appctx_htx_rcv_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags);
size_t appctx_raw_rcv_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags);
size_t appctx_rcv_buf(struct stconn *sc, struct buffer *buf, size_t count, unsigned int flags);

size_t appctx_htx_snd_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags);
size_t appctx_raw_snd_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags);
size_t appctx_snd_buf(struct stconn *sc, struct buffer *buf, size_t count, unsigned int flags);

int appctx_fastfwd(struct stconn *sc, unsigned int count, unsigned int flags);
ssize_t applet_append_line(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len, char delim);
static forceinline void applet_fl_set(struct appctx *appctx, uint on);
static forceinline void applet_fl_clr(struct appctx *appctx, uint off);


static forceinline uint appctx_app_test(const struct appctx *appctx, uint test)
{
	return (appctx->applet->flags & test);
}

static inline struct appctx *appctx_new_here(struct applet *applet, struct sedesc *sedesc)
{
	return appctx_new_on(applet, sedesc, tid);
}

static inline struct appctx *appctx_new_anywhere(struct applet *applet, struct sedesc *sedesc)
{
	return appctx_new_on(applet, sedesc, -1);
}


/*
 * Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
static inline void appctx_release_buf(struct appctx *appctx, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(appctx->buffer_wait.target, 1);
	}
}

/*
 * Allocate a buffer. If if fails, it adds the appctx in buffer wait queue and
 * sets the relevant blocking flag depending on the side (assuming that bptr is
 * either &appctx->inbuf or &appctx->outbuf). Upon success it will also clear
 * the equivalent MAYALLOC flags.
 */
static inline struct buffer *appctx_get_buf(struct appctx *appctx, struct buffer *bptr)
{
	struct buffer *buf = NULL;
	int is_inbuf = (bptr == &appctx->inbuf);

	if (likely(!LIST_INLIST(&appctx->buffer_wait.list))) {
		if (unlikely((buf = b_alloc(bptr, is_inbuf ? DB_MUX_TX : DB_SE_RX)) == NULL)) {
			b_queue(is_inbuf ? DB_MUX_TX : DB_SE_RX, &appctx->buffer_wait, appctx, appctx_buf_available);
			applet_fl_set(appctx, is_inbuf ? APPCTX_FL_INBLK_ALLOC : APPCTX_FL_OUTBLK_ALLOC);
		} else {
			applet_fl_clr(appctx, is_inbuf ? APPCTX_FL_IN_MAYALLOC : APPCTX_FL_OUT_MAYALLOC);
		}
	}
	return buf;
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
	BUG_ON(appctx->t->tid != -1 && appctx->t->tid != tid);
	task_set_thread(appctx->t, tid);

	if (appctx->applet->init)
		return appctx->applet->init(appctx);
	return 0;
}

/* Releases an appctx previously allocated by appctx_new(). */
static inline void __appctx_free(struct appctx *appctx)
{
	appctx_release_buf(appctx, &appctx->inbuf);
	appctx_release_buf(appctx, &appctx->outbuf);

	task_destroy(appctx->t);
	b_dequeue(&appctx->buffer_wait);
	if (appctx->sess)
		session_free(appctx->sess);
	BUG_ON(appctx->sedesc && !se_fl_test(appctx->sedesc, SE_FL_ORPHAN));
	sedesc_free(appctx->sedesc);
	pool_free(pool_head_appctx, appctx);
	_HA_ATOMIC_DEC(&nb_applets);
}

/* wakes up an applet when conditions have changed. We're using a macro here in
 * order to retrieve the caller's place.
 */
#define appctx_wakeup(ctx) \
	_task_wakeup((ctx)->t, TASK_WOKEN_OTHER, MK_CALLER(WAKEUP_TYPE_APPCTX_WAKEUP, 0, 0))

#define appctx_schedule(ctx, w) \
        _task_schedule((ctx)->t, w, MK_CALLER(WAKEUP_TYPE_TASK_SCHEDULE, 0, 0))

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

/* returns 1 if the appctx is attached on the backend side or 0 if it is
 * attached on the frontend side. Note that only frontend appctx may have no SC.
 */
static inline int appctx_is_back(const struct appctx *appctx)
{
	struct stconn *sc = appctx_sc(appctx);

	return !!(sc && (sc->flags & SC_FL_ISBACK));
}

static forceinline void applet_fl_zero(struct appctx *appctx)
{
	appctx->flags = 0;
}

static forceinline void applet_fl_setall(struct appctx *appctx, uint all)
{
	appctx->flags = all;
}

static forceinline void applet_fl_set(struct appctx *appctx, uint on)
{
	if (((on & (APPCTX_FL_EOS|APPCTX_FL_EOI)) && appctx->flags & APPCTX_FL_ERR_PENDING) ||
	    ((on & APPCTX_FL_ERR_PENDING) && appctx->flags & (APPCTX_FL_EOI|APPCTX_FL_EOS)))
		on |= APPCTX_FL_ERROR;
	appctx->flags |= on;
}

static forceinline void applet_fl_clr(struct appctx *appctx, uint off)
{
	appctx->flags &= ~off;
}

static forceinline uint applet_fl_test(const struct appctx *appctx, uint test)
{
	return !!(appctx->flags & test);
}

static forceinline uint applet_fl_get(const struct appctx *appctx)
{
	return appctx->flags;
}

static inline void applet_set_eoi(struct appctx *appctx)
{
	applet_fl_set(appctx, APPCTX_FL_EOI);
}

static inline void applet_set_eos(struct appctx *appctx)
{
	applet_fl_set(appctx, APPCTX_FL_EOS);
}

static inline void applet_set_error(struct appctx *appctx)
{
	if (applet_fl_test(appctx, (APPCTX_FL_EOS|APPCTX_FL_EOI)))
		applet_fl_set(appctx, APPCTX_FL_ERROR);
	else
		applet_fl_set(appctx, APPCTX_FL_ERR_PENDING);
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
 * output buffer. Rely on the corresponding SE function
 */
static inline void applet_will_consume(struct appctx *appctx)
{
	se_will_consume(appctx->sedesc);
}

/* The applet indicates that it's not willing to consume data from the stream's
 * output buffer.  Rely on the corresponding SE function
 */
static inline void applet_wont_consume(struct appctx *appctx)
{
	se_wont_consume(appctx->sedesc);
}

/* The applet indicates that it's willing to consume data from the stream's
 * output buffer, but that there's not enough, so it doesn't want to be woken
 * up until more are presented. Rely on the corresponding SE function
 */
static inline void applet_need_more_data(struct appctx *appctx)
{
	se_need_more_data(appctx->sedesc);
}

/* The applet indicates that it does not expect data from the opposite endpoint.
 * This way the stream know it should not trigger read timeout on the other
 * side.
 */
static inline void applet_expect_no_data(struct appctx *appctx)
{
	se_fl_set(appctx->sedesc, SE_FL_EXP_NO_DATA);
}

/* The applet indicates that it expects data from the opposite endpoint. This
 * way the stream know it may trigger read timeout on the other side.
 */
static inline void applet_expect_data(struct appctx *appctx)
{
	se_fl_clr(appctx->sedesc, SE_FL_EXP_NO_DATA);
}

/* Returns the buffer containing data pushed to the applet by the stream. For
 * applets using its own buffers it is the appctx input buffer. For legacy
 * applet, it is the output channel buffer.
 */
static inline struct buffer *applet_get_inbuf(struct appctx *appctx)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (applet_fl_test(appctx, APPCTX_FL_INBLK_ALLOC) || !appctx_get_buf(appctx, &appctx->inbuf))
			return NULL;
		return &appctx->inbuf;
	}
	else
		return sc_ob(appctx_sc(appctx));
}

/* Returns the buffer containing data pushed by the applets to the stream. For
 * applets using its own buffer it is the appctx output buffer. For legacy
 * applet, it is the input channel buffer.
 */
static inline struct buffer *applet_get_outbuf(struct appctx *appctx)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (applet_fl_test(appctx, APPCTX_FL_OUTBLK_ALLOC|APPCTX_FL_OUTBLK_FULL) ||
		    !appctx_get_buf(appctx, &appctx->outbuf))
			return NULL;
		return &appctx->outbuf;
	}
	else
		return sc_ib(appctx_sc(appctx));
}

/* Returns the amount of HTX data in the input buffer (see applet_get_inbuf) */
static inline size_t applet_htx_input_data(const struct appctx *appctx)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API))
		return htx_used_space(htxbuf(&appctx->inbuf));
	else
		return co_data(sc_oc(appctx_sc(appctx)));
}

/* Returns the amount of data in the input buffer (see applet_get_inbuf) */
static inline size_t applet_input_data(const struct appctx *appctx)
{
	if (appctx_app_test(appctx, APPLET_FL_HTX))
		return applet_htx_input_data(appctx);

	if (appctx_app_test(appctx, APPLET_FL_NEW_API))
		return b_data(&appctx->inbuf);
	else
		return co_data(sc_oc(appctx_sc(appctx)));
}

/* Skips <len> bytes from the input buffer (see applet_get_inbuf).
 *
 * This is useful when data have been read directly from the buffer. It is
 * illegal to call this function with <len> causing a wrapping at the end of the
 * buffer. It's the caller's responsibility to ensure that <len> is never larger
 * than available ouput data.
 *
 * This function is not HTX aware.
 */
static inline void applet_skip_input(struct appctx *appctx, size_t len)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		b_del(&appctx->inbuf, len);
		applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
	}
	else
		co_skip(sc_oc(appctx_sc(appctx)), len);
}

/* Removes all bytes from the input buffer (see applet_get_inbuf).
 */
static inline void applet_reset_input(struct appctx *appctx)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		b_reset(&appctx->inbuf);
		applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
	}
	else
		co_skip(sc_oc(appctx_sc(appctx)), co_data(sc_oc(appctx_sc(appctx))));
}

/* Returns the amout of space available at the HTX output buffer (see applet_get_outbuf).
 */
static inline size_t applet_htx_output_room(const struct appctx *appctx)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API))
		return htx_free_data_space(htxbuf(&appctx->outbuf));
	else
		return channel_recv_max(sc_ic(appctx_sc(appctx)));
}

/* Returns the amout of space available at the output buffer (see applet_get_outbuf).
 */
static inline size_t applet_output_room(const struct appctx *appctx)
{
	if (appctx_app_test(appctx, APPLET_FL_HTX))
		return applet_htx_output_room(appctx);

	if (appctx_app_test(appctx, APPLET_FL_NEW_API))
		return b_room(&appctx->outbuf);
	else
		return channel_recv_max(sc_ic(appctx_sc(appctx)));
}

/*Indicates that the applet have more data to deliver and it needs more room in
 * the output buffer to do so (see applet_get_outbuf).
 *
 * For applets using its own buffers, <room_needed> is not used and only
 * <appctx> flags are updated. For legacy applets, the amount of free space
 * required must be specified. In this last case, it is the caller
 * responsibility to be sure <room_needed> is valid.
 */
static inline void applet_need_room(struct appctx *appctx, size_t room_needed)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API))
		applet_have_more_data(appctx);
	else
		sc_need_room(appctx_sc(appctx), room_needed);
}

/* Should only be used via wrappers applet_putchk() / applet_putchk_stress(). */
static inline int _applet_putchk(struct appctx *appctx, struct buffer *chunk,
                                 int stress)
{
	int ret;

	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (unlikely(stress) ?
		    b_data(&appctx->outbuf) :
		    b_data(chunk) > b_room(&appctx->outbuf)) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			ret = -1;
		}
		else {
			ret = b_putblk(&appctx->outbuf, b_head(chunk), b_data(chunk));
			chunk->data -= ret;
		}
	}
	else {
		struct sedesc *se = appctx->sedesc;

		if ((unlikely(stress) && ci_data(sc_ic(se->sc))) ||
		    (ret = ci_putchk(sc_ic(se->sc), chunk)) < 0) {
			/* XXX: Handle all errors as a lack of space because callers
			 * don't handles other cases for now. So applets must be
			 * careful to handles shutdown (-2) and invalid calls (-3) by
			 * themselves.
			 */
			sc_need_room(se->sc, chunk->data);
			ret = -1;
		}
	}

	return ret;
}

/* writes chunk <chunk> into the applet output buffer (see applet_get_outbuf).
 *
 * Returns the number of written bytes on success or -1 on error (lake of space,
 * shutdown, invalid call...)
 */
static inline int applet_putchk(struct appctx *appctx, struct buffer *chunk)
{
	return _applet_putchk(appctx, chunk, 0);
}

/* Equivalent of applet_putchk() but with stress condition alternatives activated. */
static inline int applet_putchk_stress(struct appctx *appctx, struct buffer *chunk)
{
	return _applet_putchk(appctx, chunk, 1);
}

/* writes <len> chars from <blk> into the applet output buffer (see applet_get_outbuf).
 *
 * Returns the number of written bytes on success or -1 on error (lake of space,
 * shutdown, invalid call...)
 */
static inline int applet_putblk(struct appctx *appctx, const char *blk, int len)
{
	int ret;

	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (len > b_room(&appctx->outbuf)) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			ret = -1;
		}
		else
			ret = b_putblk(&appctx->outbuf, blk, len);
	}
	else {
		struct sedesc *se = appctx->sedesc;

		ret = ci_putblk(sc_ic(se->sc), blk, len);
		if (ret < 0) {
			/* XXX: Handle all errors as a lack of space because callers
			 * don't handles other cases for now. So applets must be
			 * careful to handles shutdown (-2) and invalid calls (-3) by
			 * themselves.
			 */
			sc_need_room(se->sc, len);
			ret = -1;
		}
	}

	return ret;
}

/* writes chars from <str> up to the trailing zero (excluded) into the applet
 * output buffer (see applet_get_outbuf).
 *
 * Returns the number of written bytes on success or -1 on error (lake of space,
 * shutdown, invalid call...)
 */
static inline int applet_putstr(struct appctx *appctx, const char *str)
{
	int ret;

	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		int len = strlen(str);

		if (len > b_room(&appctx->outbuf)) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			ret = -1;
		}
		else
			ret = b_putblk(&appctx->outbuf, str, len);
	}
	else {
		struct sedesc *se = appctx->sedesc;

		ret = ci_putstr(sc_ic(se->sc), str);
		if (ret < 0) {
			/* XXX: Handle all errors as a lack of space because callers
			 * don't handles other cases for now. So applets must be
			 * careful to handles shutdown (-2) and invalid calls (-3) by
			 * themselves.
			 */
			sc_need_room(se->sc, strlen(str));
			ret = -1;
		}
	}
	return ret;
}

/* writes character <chr> into the applet's output buffer (see applet_get_outbuf).
 *
 * Returns the number of written bytes on success or -1 on error (lake of space,
 * shutdown, invalid call...)
 */
static inline int applet_putchr(struct appctx *appctx, char chr)
{
	int ret;

	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (b_full(&appctx->outbuf)) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			ret = -1;
		}
		else {
			 b_putchr(&appctx->outbuf, chr);
			 ret = 1;
		}
	}
	else {
		struct sedesc *se = appctx->sedesc;

		ret = ci_putchr(sc_ic(se->sc), chr);
		if (ret < 0) {
			/* XXX: Handle all errors as a lack of space because callers
			 * don't handles other cases for now. So applets must be
			 * careful to handles shutdown (-2) and invalid calls (-3) by
			 * themselves.
			 */
			sc_need_room(se->sc, 1);
			ret = -1;
		}
	}
	return ret;
}

static inline int applet_may_get(const struct appctx *appctx, size_t len)
{
	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (len > b_data(&appctx->inbuf)) {
			if (se_fl_test(appctx->sedesc, SE_FL_SHW))
				return -1;
			return 0;
		}
	}
	else {
		const struct stconn *sc = appctx_sc(appctx);

		if ((sc->flags & SC_FL_SHUT_DONE) || len > co_data(sc_oc(sc))) {
			if (sc->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED))
				return -1;
			return 0;
		}
	}
	return 1;
}
/* Gets one char from the applet input buffer (see appet_get_inbuf),
 *
 * Return values :
 *    1 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <c> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 *
 * The status of the corresponding buffer is not changed. The caller must call
 * applet_skip_input() to update it.
 */
static inline int applet_getchar(const struct appctx *appctx, char *c)
{
	int ret;

	ret = applet_may_get(appctx, 1);
	if (ret <= 0)
		return ret;
	*c = ((appctx_app_test(appctx, APPLET_FL_NEW_API))
	      ? *(b_head(&appctx->inbuf))
	      : *(co_head(sc_oc(appctx_sc(appctx)))));

	return 1;
}

/* Copies one full block of data from the applet input buffer (see
 * appet_get_inbuf).
 *
 * <len> bytes are capied, starting at the offset <offset>.
 *
 * Return values :
 *   >0 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <blk> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 *
 * The status of the corresponding buffer is not changed. The caller must call
 * applet_skip_input() to update it.
 */
static inline int applet_getblk(const struct appctx *appctx, char *blk, int len, int offset)
{
	const struct buffer *buf;
	int ret;

	ret = applet_may_get(appctx, len+offset);
	if (ret <= 0)
		return ret;

	buf = ((appctx_app_test(appctx, APPLET_FL_NEW_API))
	       ? &appctx->inbuf
	       : sc_ob(appctx_sc(appctx)));
	return b_getblk(buf, blk, len, offset);
}

/* Gets one text block representing a word from the applet input buffer (see
 * appet_get_inbuf).
 *
 * The separator is waited for as long as some data can still be received and the
 * destination is not full. Otherwise, the string may be returned as is, without
 * the separator.
 *
 * Return values :
 *   >0 : number of bytes read. Includes the separator if present before len or end.
 *   =0 : no separator before end found. <str> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 *
 * The status of the corresponding buffer is not changed. The caller must call
 * applet_skip_input() to update it.
 */
static inline int applet_getword(const struct appctx *appctx, char *str, int len, char sep)
{
	const struct buffer *buf;
	char *p;
	size_t input, max = len;
	int ret = 0;

	ret = applet_may_get(appctx, 1);
	if (ret <= 0)
		goto out;

	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		buf = &appctx->inbuf;
		input = b_data(buf);
	}
	else {
		struct stconn *sc = appctx_sc(appctx);

		buf = sc_ob(sc);
		input = co_data(sc_oc(sc));
	}

	if (max > input) {
		max = input;
		str[max-1] = 0;
	}

	p = b_head(buf);
	ret = 0;
	while (max) {
		*str++ = *p;
		ret++;
		max--;
		if (*p == sep)
			goto out;
		p = b_next(buf, p);
	}

	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (ret < len && (ret < input || b_room(buf)) &&
		    !se_fl_test(appctx->sedesc, SE_FL_SHW))
			ret = 0;
	}
	else {
		struct stconn *sc = appctx_sc(appctx);

		if (ret < len && (ret < input || channel_may_recv(sc_oc(sc))) &&
		    !(sc->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED)))
			ret = 0;
	}
 out:
	if (max)
		*str = 0;
	return ret;
}

/* Gets one text block representing a line from the applet input buffer (see
 * appet_get_inbuf).
 *
 * The '\n' is waited for as long as some data can still be received and the
 * destination is not full. Otherwise, the string may be returned as is, without
 * the '\n'.
 *
 * Return values :
 *   >0 : number of bytes read. Includes the \n if present before len or end.
 *   =0 : no '\n' before end found. <str> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 *
 * The status of the corresponding buffer is not changed. The caller must call
 * applet_skip_input() to update it.
 */
static inline int applet_getline(const struct appctx *appctx, char *str, int len)
{
	return applet_getword(appctx, str, len, '\n');
}

/* Gets one or two blocks of data at once from the applet input buffer (see appet_get_inbuf),
 *
 * Data are not copied.
 *
 * Return values :
 *   >0 : number of blocks filled (1 or 2). blk1 is always filled before blk2.
 *   =0 : not enough data available. <blk*> are left undefined.
 *   <0 : no more bytes readable because output is shut.
 *
 * The status of the corresponding buffer is not changed. The caller must call
 * applet_skip_input() to update it.
 */
static inline int applet_getblk_nc(const struct appctx *appctx, const char **blk1, size_t *len1, const char **blk2, size_t *len2)
{
	const struct buffer *buf;
	size_t max;
	int ret;

	ret = applet_may_get(appctx, 1);
	if (ret <= 0)
		return ret;

	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		buf = &appctx->inbuf;
		max = b_data(buf);
	}
	else {
		struct stconn *sc = appctx_sc(appctx);

		buf = sc_ob(sc);
		max = co_data(sc_oc(sc));
	}

	return b_getblk_nc(buf, blk1, len1, blk2, len2, 0, max);
}

/* Gets one or two blocks of text representing a word from the applet input
 * buffer (see appet_get_inbuf).
 *
 * Data are not copied. The separator is waited for as long as some data can
 * still be received and the destination is not full. Otherwise, the string may
 * be returned as is, without the separator.
 *
 * Return values :
 *   >0 : number of bytes read. Includes the separator if present before len or end.
 *   =0 : no separator before end found. <str> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 *
 * The status of the corresponding buffer is not changed. The caller must call
 * applet_skip_input() to update it.
 */
static inline int applet_getword_nc(const struct appctx *appctx, const char **blk1, size_t *len1, const char **blk2, size_t *len2, char sep)
{
	int ret;
	size_t l;

	ret = applet_getblk_nc(appctx, blk1, len1, blk2, len2);
	if (unlikely(ret <= 0))
		return ret;

	for (l = 0; l < *len1 && (*blk1)[l] != sep; l++);
	if (l < *len1 && (*blk1)[l] == sep) {
		*len1 = l + 1;
		return 1;
	}

	if (ret >= 2) {
		for (l = 0; l < *len2 && (*blk2)[l] != sep; l++);
		if (l < *len2 && (*blk2)[l] == sep) {
			*len2 = l + 1;
			return 2;
		}
	}

	/* If we have found no LF and the buffer is full or the SC is shut, then
	 * the resulting string is made of the concatenation of the pending
	 * blocks (1 or 2).
	 */
	if (appctx_app_test(appctx, APPLET_FL_NEW_API)) {
		if (b_full(&appctx->inbuf) || se_fl_test(appctx->sedesc, SE_FL_SHW))
			return ret;
	}
	else {
		struct stconn *sc = appctx_sc(appctx);

		if (!channel_may_recv(sc_oc(sc)) || sc->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED))
			return ret;
	}

	/* No LF yet and not shut yet */
	return 0;
}


/* Gets one or two blocks of text representing a line from the applet input
 * buffer (see appet_get_inbuf).
 *
 * Data are not copied. The '\n' is waited for as long as some data can still be
 * received and the destination is not full. Otherwise, the string may be
 * returned as is, without the '\n'.
 *
 * Return values :
 *   >0 : number of bytes read. Includes the \n if present before len or end.
 *   =0 : no '\n' before end found. <str> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 *
 * The status of the corresponding buffer is not changed. The caller must call
 * applet_skip_input() to update it.
 */
static inline int applet_getline_nc(const struct appctx *appctx, const char **blk1, size_t *len1, const char **blk2, size_t *len2)
{
	return applet_getword_nc(appctx, blk1, len1, blk2, len2, '\n');
}

#endif /* _HAPROXY_APPLET_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
