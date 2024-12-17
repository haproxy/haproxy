/*
 * include/haproxy/trace.h
 * This file provides functions for runtime tracing
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_TRACE_H
#define _HAPROXY_TRACE_H

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/list.h>
#include <haproxy/sink-t.h>
#include <haproxy/tools.h>
#include <haproxy/trace-t.h>

/* Make a string from the location of the trace producer as "file:line" */
#define TRC_LOC  _TRC_LOC(__FILE__, __LINE__)
#define _TRC_LOC(f,l) __TRC_LOC(f, ":", l)
#define __TRC_LOC(f,c,l) f c #l

/* truncate a macro arg list to exactly 5 args and replace missing ones with NULL.
 * The first one (a0) is always ignored.
 */
#define TRC_5ARGS(a0,a1,a2,a3,a4,a5,...) DEFNULL(a1),DEFNULL(a2),DEFNULL(a3),DEFNULL(a4),DEFNULL(a5)

/* reports whether trace is active for the source and the arguments. It uses
 * the same criteria as trace() (locking, filtering etc) so it's safe to use
 * from application code to decide whether or not to engage in heavier data
 * preparation processing.
 */
#define _trace_enabled(level, mask, src, args...)			\
	(unlikely(((src)->state != TRACE_STATE_STOPPED || (src)->follow) && \
		  __trace_enabled(level, mask, src, ##args, NULL) > 0))

/* sends a trace for the given source. Arguments are passed in the exact same
 * order as in the __trace() function, which is only called if (src)->state is
 * not TRACE_STATE_STOPPED. This is the only case where arguments are evaluated.
 */
#define _trace(level, mask, src, args...)				\
	do {								\
		if (unlikely((src)->state != TRACE_STATE_STOPPED || (src)->follow)) \
			__trace(level, mask, src, ##args);		\
	} while (0)

/* For convenience, TRACE() alone uses the file's default TRACE_LEVEL, most
 * likely TRACE_LEVEL_DEVELOPER, though the other explicit variants specify
 * the desired level and will work when TRACE_LEVEL is not set. The 5 optional
 * arguments are the 4 source-specific arguments that are passed to the cb()
 * callback dedicated to decoding, and which may be used for special tracking.
 * These 4 arguments as well as the cb() function pointer may all be NULL, or
 * simply omitted (in which case they will be replaced by a NULL). This
 * ordering allows many TRACE() calls to be placed using copy-paste and just
 * change the message at the beginning. Only TRACE_DEVEL(), TRACE_ENTER() and
 * TRACE_LEAVE() will report the calling function's name. TRACE_PRINTF() does
 * require all the optional a1..a4 to be passed (possibly zero) so that they're
 * always followed by the format string, then the values to be formatted.
 *
 * TRACE_* will call the _trace() macro which will test if the trace is enabled
 * before calling the __trace() function. _trace() shouldn't be a function (nor
 * inline) itself because we don't want the caller to compute its arguments if
 * traces are not enabled.
 *
 * TRACE_ENABLED() reports whether or not trace is enabled for the current
 * source, level, mask and arguments.
 */
#define TRACE_ENABLED(level, mask, args...) (_trace_enabled((level), (mask), TRACE_SOURCE, ist(TRC_LOC), __FUNCTION__, ##args))

#define TRACE(msg, mask, args...)    \
	_trace(TRACE_LEVEL,           (mask), TRACE_SOURCE, ist(TRC_LOC), NULL, TRC_5ARGS(0,##args,0,0,0,0,0), ist(msg))

#define TRACE_ERROR(msg, mask, args...)			\
	_trace(TRACE_LEVEL_ERROR,     (mask), TRACE_SOURCE, ist(TRC_LOC), NULL, TRC_5ARGS(0,##args,0,0,0,0,0), ist(msg))

#define TRACE_USER(msg, mask, args...)			\
	_trace(TRACE_LEVEL_USER,      (mask), TRACE_SOURCE, ist(TRC_LOC), NULL, TRC_5ARGS(0,##args,0,0,0,0,0), ist(msg))

#define TRACE_DATA(msg, mask, args...)  \
	_trace(TRACE_LEVEL_DATA,   (mask), TRACE_SOURCE, ist(TRC_LOC), NULL, TRC_5ARGS(0,##args,0,0,0,0,0), ist(msg))

#define TRACE_PROTO(msg, mask, args...)    \
	_trace(TRACE_LEVEL_PROTO,     (mask), TRACE_SOURCE, ist(TRC_LOC), NULL, TRC_5ARGS(0,##args,0,0,0,0,0), ist(msg))

#define TRACE_STATE(msg, mask, args...)    \
	_trace(TRACE_LEVEL_STATE,     (mask), TRACE_SOURCE, ist(TRC_LOC), NULL, TRC_5ARGS(0,##args,0,0,0,0,0), ist(msg))

#define TRACE_DEVEL(msg, mask, args...)    \
	_trace(TRACE_LEVEL_DEVELOPER, (mask), TRACE_SOURCE, ist(TRC_LOC), __FUNCTION__, TRC_5ARGS(0,##args,0,0,0,0,0), ist(msg))

#define TRACE_ENTER(mask, args...)  \
	_trace(TRACE_LEVEL_DEVELOPER, (mask), TRACE_SOURCE, ist(TRC_LOC), __FUNCTION__, TRC_5ARGS(0,##args,0,0,0,0,0), ist("entering"))

#define TRACE_LEAVE(mask, args...)  \
	_trace(TRACE_LEVEL_DEVELOPER, (mask), TRACE_SOURCE, ist(TRC_LOC), __FUNCTION__, TRC_5ARGS(0,##args,0,0,0,0,0), ist("leaving"))

#define TRACE_POINT(mask, args...)  \
	_trace(TRACE_LEVEL_DEVELOPER, (mask), TRACE_SOURCE, ist(TRC_LOC), __FUNCTION__, TRC_5ARGS(0,##args,0,0,0,0,0), ist("in"))

/* This produces a printf-like trace at level <level> for event mask <mask> and
 * trace arguments <a1..a4>. All args mandatory, but may be zero. No output
 * callback will be used since we expect the caller to pass a fully formatted
 * message that must not be degraded. The output will be truncated to
 * TRACE_MAX_MSG-1 bytes (1023 by default). Caller must include <stdio.h> for
 * snprintf(). One call will lead to one independent message, which means that
 * multiple messages may be interleaved between threads, hence the caller is
 * encouraged to prepend a context at the beginning of the format string when
 * dumping lists or arrays. The _LOC variation takes the caller's location and
 * function name as an ist and a (const char *) respectively, it is meant for
 * being called from wrapper function which will work on behalf of a caller.
 */
#define TRACE_PRINTF(level, mask, a1, a2, a3, a4, fmt, args...)		\
	TRACE_PRINTF_LOC(level, mask, ist(TRC_LOC), __FUNCTION__, a1, a2, a3, a4, fmt, ##args)

#define TRACE_PRINTF_LOC(level, mask, trc_loc, func, a1, a2, a3, a4, fmt, args...) \
	do {									\
		if (TRACE_ENABLED((level), (mask), a1, a2, a3, a4)) {		\
			char _msg[TRACE_MAX_MSG];				\
			size_t _msg_len;					\
			_msg_len = snprintf(_msg, sizeof(_msg), (fmt), ##args);	\
			if (_msg_len >= sizeof(_msg))				\
				_msg_len = sizeof(_msg) - 1;			\
			_trace((level), (mask), TRACE_SOURCE,	\
			       trc_loc, func, a1, a2, a3, a4,			\
			       &trace_no_cb, ist2(_msg, _msg_len));		\
		}								\
	} while (0)

#if defined(DEBUG_DEV) || defined(DEBUG_FULL)
#    define DBG_TRACE(msg, mask, args...)        TRACE(msg, mask, ##args)
#    define DBG_TRACE_ERROR(msg, mask, args...)  TRACE_ERROR(msg, mask, ##args)
#    define DBG_TRACE_USER(msg, mask, args...)   TRACE_USER(msg, mask, ##args)
#    define DBG_TRACE_DATA(msg, mask, args...)   TRACE_DATA(msg, mask, ##args)
#    define DBG_TRACE_PROTO(msg, mask, args...)  TRACE_PROTO(msg, mask, ##args)
#    define DBG_TRACE_STATE(msg, mask, args...)  TRACE_STATE(msg, mask, ##args)
#    define DBG_TRACE_DEVEL(msg, mask, args...)  TRACE_DEVEL(msg, mask, ##args)
#    define DBG_TRACE_ENTER(mask, args...)       TRACE_ENTER(mask, ##args)
#    define DBG_TRACE_LEAVE(mask, args...)       TRACE_LEAVE(mask, ##args)
#    define DBG_TRACE_POINT(mask, args...)       TRACE_POINT(mask, ##args)
#    define DBG_TRACE_PRINTF(level, args...)     TRACE_PRINTF(level, ##args)
#    define DBG_TRACE_PRINTF_LOC(level, args...) TRACE_PRINTF_LOC(level, ##args)
#else
#    define DBG_TRACE(msg, mask, args...)        do { /* do nothing */ } while(0)
#    define DBG_TRACE_ERROR(msg, mask, args...)  do { /* do nothing */ } while(0)
#    define DBG_TRACE_USER(msg, mask, args...)   do { /* do nothing */ } while(0)
#    define DBG_TRACE_DATA(msg, mask, args...)   do { /* do nothing */ } while(0)
#    define DBG_TRACE_PROTO(msg, mask, args...)  do { /* do nothing */ } while(0)
#    define DBG_TRACE_STATE(msg, mask, args...)  do { /* do nothing */ } while(0)
#    define DBG_TRACE_DEVEL(msg, mask, args...)  do { /* do nothing */ } while(0)
#    define DBG_TRACE_ENTER(mask, args...)       do { /* do nothing */ } while(0)
#    define DBG_TRACE_LEAVE(mask, args...)       do { /* do nothing */ } while(0)
#    define DBG_TRACE_POINT(mask, args...)       do { /* do nothing */ } while(0)
#    define DBG_TRACE_PRINTF(level, args...)     do { /* do nothing */ } while(0)
#    define DBG_TRACE_PRINTF_LOC(level, args...) do { /* do nothing */ } while(0)
#endif

extern struct list trace_sources;
extern THREAD_LOCAL struct buffer trace_buf;

int __trace_enabled(enum trace_level level, uint64_t mask, struct trace_source *src,
		    const struct ist where, const char *func,
		    const void *a1, const void *a2, const void *a3, const void *a4,
		    const void **plockptr);

void __trace(enum trace_level level, uint64_t mask, struct trace_source *src,
             const struct ist where, const char *func,
             const void *a1, const void *a2, const void *a3, const void *a4,
             void (*cb)(enum trace_level level, uint64_t mask, const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4),
             const struct ist msg);

void trace_no_cb(enum trace_level level, uint64_t mask, const struct trace_source *src,
		 const struct ist where, const struct ist func,
		 const void *a1, const void *a2, const void *a3, const void *a4);

void trace_register_source(struct trace_source *source);

int trace_parse_cmd(const char *arg_src, char **errmsg);

/* return a single char to describe a trace state */
static inline char trace_state_char(enum trace_state st)
{
	return (st == TRACE_STATE_RUNNING) ? 'R' :
	       (st == TRACE_STATE_WAITING) ? 'w' :
	                                     '.';
}

/* return a single char to describe an event state */
static inline char trace_event_char(uint64_t conf, uint64_t ev)
{
	return (conf & ev) ? '+' : '-';
}

/* Temporarily disable trace using a cumulative counter. If called multiple
 * times, the same number of resume must be used to reactivate tracing.
 *
 * Returns the incremented counter value or 0 if already at the maximum value.
 */
static inline uint8_t trace_disable(void)
{
	if (unlikely(th_ctx->trc_disable_ctr == UCHAR_MAX))
		return 0;
	return ++th_ctx->trc_disable_ctr;
}

/* Resume tracing after a temporarily disabling. It may be called several times
 * as disable operation is cumulative.
 */
static inline void trace_resume(void)
{
	if (th_ctx->trc_disable_ctr)
		--th_ctx->trc_disable_ctr;
}

/* Resume tracing immediately even after multiple disable operations.
 *
 * Returns the old counter value. Useful to reactivate trace disabling at the
 * previous level.
 */
static inline uint8_t trace_force_resume(void)
{
	const int val = th_ctx->trc_disable_ctr;
	th_ctx->trc_disable_ctr = 0;
	return val;
}

/* Set trace disabling counter to <disable>. Mostly useful with the value
 * returned from trace_force_resume() to restore tracing disable status to the
 * previous level.
 */
static inline void trace_reset_disable(uint8_t disable)
{
	th_ctx->trc_disable_ctr = disable;
}

#endif /* _HAPROXY_TRACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
