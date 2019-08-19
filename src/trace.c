/*
 * Runtime tracing API
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

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/mini-clist.h>
#include <proto/log.h>
#include <proto/trace.h>

struct list trace_sources = LIST_HEAD_INIT(trace_sources);
THREAD_LOCAL struct buffer trace_buf = { };

/* allocates the trace buffers. Returns 0 in case of failure. It is safe to
 * call to call this function multiple times if the size changes.
 */
static int alloc_trace_buffers_per_thread()
{
	chunk_init(&trace_buf, my_realloc2(trace_buf.area, global.tune.bufsize), global.tune.bufsize);
	return !!trash.area;
}

static void free_trace_buffers_per_thread()
{
	chunk_destroy(&trace_buf);
}

REGISTER_PER_THREAD_ALLOC(alloc_trace_buffers_per_thread);
REGISTER_PER_THREAD_FREE(free_trace_buffers_per_thread);
/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
