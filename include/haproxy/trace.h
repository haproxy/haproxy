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

/* sends a trace for the given source. Arguments are passed in the exact same
 * order as in the __trace() function, which is only called if (src)->state is
 * not TRACE_STATE_STOPPED. This is the only case where arguments are evaluated.
 */
#define _trace(level, mask, src, args...)				\
	do {								\
		if (unlikely((src)->state != TRACE_STATE_STOPPED))	\
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
 * TRACE_LEAVE() will report the calling function's name.
 *
 * TRACE_* will call the _trace() macro which will test if the trace is enabled
 * before calling the __trace() function. _trace() shouldn't be a function (nor
 * inline) itself because we don't want the caller to compute its arguments if
 * traces are not enabled.
 */
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
#endif

extern struct list trace_sources;
extern THREAD_LOCAL struct buffer trace_buf;

void __trace(enum trace_level level, uint64_t mask, struct trace_source *src,
             const struct ist where, const char *func,
             const void *a1, const void *a2, const void *a3, const void *a4,
             void (*cb)(enum trace_level level, uint64_t mask, const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4),
             const struct ist msg);

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

/* registers trace source <source>. Modifies the list element!
 * The {start,pause,stop,report} events are not changed so the source may
 * preset them.
 */
static inline void trace_register_source(struct trace_source *source)
{
	source->lockon = TRACE_LOCKON_NOTHING;
	source->level = TRACE_LEVEL_USER;
	source->verbosity = 1;
	source->sink = NULL;
	source->state = TRACE_STATE_STOPPED;
	source->lockon_ptr = NULL;
	LIST_APPEND(&trace_sources, &source->source_link);
}

#endif /* _HAPROXY_TRACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
