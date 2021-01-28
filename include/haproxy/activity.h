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

#include <import/xxhash.h>
#include <haproxy/activity-t.h>
#include <haproxy/api.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/time.h>

extern unsigned int profiling;
extern unsigned long task_profiling_mask;
extern struct activity activity[MAX_THREADS];
extern struct sched_activity sched_activity[256];

void report_stolen_time(uint64_t stolen);

/* Collect date and time information before calling poll(). This will be used
 * to count the run time of the past loop and the sleep time of the next poll.
 * It also makes use of the just updated before_poll timer to count the loop's
 * run time and feed the average loop time metric (in microseconds).
 */
static inline void activity_count_runtime()
{
	uint64_t new_mono_time;
	uint64_t new_cpu_time;
	int64_t stolen;
	uint32_t run_time;
	uint32_t up, down;

	/* 1 millisecond per loop on average over last 1024 iterations is
	 * enough to turn on profiling.
	 */
	up = 1000;
	down = up * 99 / 100;

	new_cpu_time   = now_cpu_time();
	new_mono_time  = now_mono_time();

	if (ti->prev_cpu_time && ti->prev_mono_time) {
		new_cpu_time  -= ti->prev_cpu_time;
		new_mono_time -= ti->prev_mono_time;
		stolen = new_mono_time - new_cpu_time;
		if (unlikely(stolen >= 500000)) {
			stolen /= 500000;
			/* more than half a millisecond difference might
			 * indicate an undesired preemption.
			 */
			report_stolen_time(stolen);
		}
	}

	run_time = (before_poll.tv_sec - after_poll.tv_sec) * 1000000U + (before_poll.tv_usec - after_poll.tv_usec);
	run_time = swrate_add(&activity[tid].avg_loop_us, TIME_STATS_SAMPLES, run_time);

	/* In automatic mode, reaching the "up" threshold on average switches
	 * profiling to "on" when automatic, and going back below the "down"
	 * threshold switches to off. The forced modes don't check the load.
	 */
	if (!(task_profiling_mask & tid_bit)) {
		if (unlikely((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_ON ||
		             ((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_AON &&
		             swrate_avg(run_time, TIME_STATS_SAMPLES) >= up)))
			_HA_ATOMIC_OR(&task_profiling_mask, tid_bit);
	} else {
		if (unlikely((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_OFF ||
		             ((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_AOFF &&
		             swrate_avg(run_time, TIME_STATS_SAMPLES) <= down)))
			_HA_ATOMIC_AND(&task_profiling_mask, ~tid_bit);
	}
}

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
