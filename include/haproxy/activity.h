/*
 * include/haproxy/activity.h
 * This file contains macros and inline functions for activity measurements.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_ACTIVITY_H
#define _HAPROXY_ACTIVITY_H

#include <haproxy/activity-t.h>
#include <haproxy/api.h>

extern unsigned int profiling;
extern struct activity activity[MAX_THREADS];
extern struct sched_activity sched_activity[SCHED_ACT_HASH_BUCKETS];

void report_stolen_time(uint64_t stolen);
void activity_count_runtime(uint32_t run_time);
struct sched_activity *sched_activity_entry(struct sched_activity *array, const void *func, const void *caller);

#ifdef USE_MEMORY_PROFILING
struct memprof_stats *memprof_get_bin(const void *ra, enum memprof_method meth);
void memprof_remove_stale_info(const void *info);
#else
static inline void memprof_remove_stale_info(const void *info)
{
	/* nothing to do */
}
#endif

#endif /* _HAPROXY_ACTIVITY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
