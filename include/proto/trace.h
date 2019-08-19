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

extern struct list trace_sources;
extern THREAD_LOCAL struct buffer trace_buf;

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

#endif /* _PROTO_TRACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
