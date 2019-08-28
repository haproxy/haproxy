/*
 * include/proto/trace.h
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

#ifndef _PROTO_TRACE_H
#define _PROTO_TRACE_H

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/mini-clist.h>
#include <types/log.h>
#include <types/sink.h>
#include <types/trace.h>

/* Make a string from the location of the trace producer as "file:line" */
#define TRC_LOC  _TRC_LOC(__FILE__, __LINE__)
#define _TRC_LOC(f,l) __TRC_LOC(f, ":", l)
#define __TRC_LOC(f,c,l) f c #l

/* truncate a macro arg list to exactly 5 args and replace missing ones with NULL */
#define TRC_5ARGS(a1,a2,a3,a4,a5,...) DEFNULL(a1),DEFNULL(a2),DEFNULL(a3),DEFNULL(a4),DEFNULL(a5)

/* For convenience, TRACE() alone uses the file's default TRACE_LEVEL, most
 * likely TRACE_LEVEL_DEVELOPER, though the other explicit variants specify
 * the desired level and will work when TRACE_LEVEL is not set. The 5 optional
 * arguments are the 4 source-specific arguments that are passed to the cb()
 * callback dedicated to decoding, and which may be used for special tracking.
 * These 4 arguments as well as the cb() function pointer may all be NULL, or
 * simply omitted (in which case they will be replaced by a NULL). This
 * ordering allows many TRACE() calls to be placed using copy-paste and just
 * change the message at the beginning.
 */
#define TRACE(msg, mask, ...)    \
	trace(TRACE_LEVEL,           (mask), TRACE_SOURCE, ist(TRC_LOC), TRC_5ARGS(__VA_ARGS__,,,,,), ist(msg))

#define TRACE_USER(msg, mask, ...)			\
	trace(TRACE_LEVEL_USER,      (mask), TRACE_SOURCE, ist(TRC_LOC), TRC_5ARGS(__VA_ARGS__,,,,,), ist(msg))

#define TRACE_PAYLOAD(msg, mask, ...)  \
	trace(TRACE_LEVEL_PAYLOAD,   (mask), TRACE_SOURCE, ist(TRC_LOC), TRC_5ARGS(__VA_ARGS__,,,,,), ist(msg))

#define TRACE_PROTO(msg, mask, ...)    \
	trace(TRACE_LEVEL_PROTO,     (mask), TRACE_SOURCE, ist(TRC_LOC), TRC_5ARGS(__VA_ARGS__,,,,,), ist(msg))

#define TRACE_STATE(msg, mask, ...)    \
	trace(TRACE_LEVEL_STATE,     (mask), TRACE_SOURCE, ist(TRC_LOC), TRC_5ARGS(__VA_ARGS__,,,,,), ist(msg))

#define TRACE_DEVEL(msg, mask, ...)    \
	trace(TRACE_LEVEL_DEVELOPER, (mask), TRACE_SOURCE, ist(TRC_LOC), TRC_5ARGS(__VA_ARGS__,,,,,), ist(msg))

extern struct list trace_sources;
extern THREAD_LOCAL struct buffer trace_buf;

void __trace(enum trace_level level, uint64_t mask, struct trace_source *src, const struct ist where,
             const void *a1, const void *a2, const void *a3, const void *a4,
             void (*cb)(enum trace_level level, uint64_t mask, const struct trace_source *src, const struct ist where,
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
	source->detail_level = LOG_NOTICE;
	source->sink = NULL;
	source->state = TRACE_STATE_STOPPED;
	source->lockon_ptr = NULL;
	LIST_ADDQ(&trace_sources, &source->source_link);
}

/* sends a trace for the given source */
static inline void trace(enum trace_level level, uint64_t mask, struct trace_source *src, const struct ist where,
                         const void *a1, const void *a2, const void *a3, const void *a4,
                         void (*cb)(enum trace_level level, uint64_t mask, const struct trace_source *src, const struct ist where,
                                    const void *a1, const void *a2, const void *a3, const void *a4),
                         const struct ist msg)
{
	if (unlikely(src->state != TRACE_STATE_STOPPED))
		__trace(level, mask, src, where, a1, a2, a3, a4, cb, msg);
}

#endif /* _PROTO_TRACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
