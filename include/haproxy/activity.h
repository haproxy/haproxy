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
#include <haproxy/freq_ctr.h>
#include <haproxy/xxhash.h>

extern unsigned int profiling;
extern unsigned long task_profiling_mask;
extern struct activity activity[MAX_THREADS];
extern struct sched_activity sched_activity[256];

void report_stolen_time(uint64_t stolen);
void activity_count_runtime();

/* Computes the index of function pointer <func> for use with sched_activity[]
 * or any other similar array passed in <array>, and returns a pointer to the
 * entry after having atomically assigned it to this function pointer. Note
 * that in case of collision, the first entry is returned instead ("other").
 */
static inline struct sched_activity *sched_activity_entry(struct sched_activity *array, const void *func)
{
	uint64_t hash = XXH64_avalanche(XXH64_mergeRound((size_t)func, (size_t)func));
	struct sched_activity *ret;
	const void *old = NULL;

	hash ^= (hash >> 32);
	hash ^= (hash >> 16);
	hash ^= (hash >> 8);
	hash &= 0xff;
	ret = &array[hash];

	if (likely(ret->func == func))
		return ret;

	if (HA_ATOMIC_CAS(&ret->func, &old, func))
		return ret;

	return array;
}

#endif /* _HAPROXY_ACTIVITY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
