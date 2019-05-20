/*
 * include/proto/activity.h
 * This file contains macros and inline functions for activity measurements.
 *
 * Copyright (C) 2000-2018 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_ACTIVITY_H
#define _PROTO_ACTIVITY_H

#include <common/config.h>
#include <common/hathreads.h>
#include <common/time.h>
#include <types/activity.h>
#include <proto/freq_ctr.h>

/* bit fields for "profiling" */
#define HA_PROF_TASKS_OFF   0x00000000     /* per-task CPU profiling forced disabled */
#define HA_PROF_TASKS_AUTO  0x00000001     /* per-task CPU profiling automatic */
#define HA_PROF_TASKS_ON    0x00000002     /* per-task CPU profiling forced enabled */
#define HA_PROF_TASKS_MASK  0x00000003     /* per-task CPU profiling mask */

extern unsigned int profiling;
extern unsigned long task_profiling_mask;
extern struct activity activity[MAX_THREADS];


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
	swrate_add(&activity[tid].avg_loop_us, TIME_STATS_SAMPLES, run_time);

	/* reaching the "up" threshold on average switches profiling to "on"
	 * when automatic, and going back below the "down" threshold switches
	 * to off.
	 */
	if (!(task_profiling_mask & tid_bit)) {
		if (unlikely((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_ON ||
			     ((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_AUTO && run_time >= up))) {
			if (swrate_avg(activity[tid].avg_loop_us, TIME_STATS_SAMPLES) >= up)
				_HA_ATOMIC_OR(&task_profiling_mask, tid_bit);
		}
	} else {
		if (unlikely((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_OFF ||
			     ((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_AUTO && run_time <= down))) {
			if (swrate_avg(activity[tid].avg_loop_us, TIME_STATS_SAMPLES) <= down)
				_HA_ATOMIC_AND(&task_profiling_mask, ~tid_bit);
		}
	}
}


#endif /* _PROTO_ACTIVITY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
