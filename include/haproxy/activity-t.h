/*
 * include/haproxy/activity-t.h
 * This file contains structure declarations for activity measurements.
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

#ifndef _HAPROXY_ACTIVITY_T_H
#define _HAPROXY_ACTIVITY_T_H

#include <haproxy/api-t.h>
#include <haproxy/freq_ctr-t.h>

/* bit fields for the "profiling" global variable */
#define HA_PROF_TASKS_OFF   0x00000000     /* per-task CPU profiling forced disabled */
#define HA_PROF_TASKS_AOFF  0x00000001     /* per-task CPU profiling off (automatic) */
#define HA_PROF_TASKS_AON   0x00000002     /* per-task CPU profiling on (automatic) */
#define HA_PROF_TASKS_ON    0x00000003     /* per-task CPU profiling forced enabled */
#define HA_PROF_TASKS_MASK  0x00000003     /* per-task CPU profiling mask */

#define HA_PROF_MEMORY      0x00000004     /* memory profiling */

/* per-thread activity reports. It's important that it's aligned on cache lines
 * because some elements will be updated very often. Most counters are OK on
 * 32-bit since this will be used during debugging sessions for troubleshooting
 * in iterative mode.
 */
struct activity {
	unsigned int loops;        // complete loops in run_poll_loop()
	unsigned int wake_tasks;   // active tasks prevented poll() from sleeping
	unsigned int wake_signal;  // pending signal prevented poll() from sleeping
	unsigned int poll_io;      // number of times poll() reported I/O events
	unsigned int poll_exp;     // number of times poll() sees an expired timeout (includes wake_*)
	unsigned int poll_drop_fd; // poller dropped a dead FD from the update list
	unsigned int poll_dead_fd; // poller woke up with a dead FD
	unsigned int poll_skip_fd; // poller skipped another thread's FD
	unsigned int conn_dead;    // conn_fd_handler woke up on an FD indicating a dead connection
	unsigned int stream_calls; // calls to process_stream()
	unsigned int ctxsw;        // total number of context switches
	unsigned int tasksw;       // total number of task switches
	unsigned int empty_rq;     // calls to process_runnable_tasks() with nothing for the thread
	unsigned int long_rq;      // process_runnable_tasks() left with tasks in the run queue
	unsigned int cpust_total;  // sum of half-ms stolen per thread
	unsigned int fd_takeover;  // number of times this thread stole another one's FD
	ALWAYS_ALIGN(64);

	struct freq_ctr cpust_1s;  // avg amount of half-ms stolen over last second
	struct freq_ctr cpust_15s; // avg amount of half-ms stolen over last 15s
	unsigned int avg_loop_us;  // average run time per loop over last 1024 runs
	unsigned int accepted;     // accepted incoming connections
	unsigned int accq_pushed;  // accept queue connections pushed
	unsigned int accq_full;    // accept queue connection not pushed because full
	unsigned int pool_fail;    // failed a pool allocation
	unsigned int buf_wait;     // waited on a buffer allocation
#if defined(DEBUG_DEV)
	/* keep these ones at the end */
	unsigned int ctr0;         // general purposee debug counter
	unsigned int ctr1;         // general purposee debug counter
	unsigned int ctr2;         // general purposee debug counter
#endif
	char __pad[0]; // unused except to check remaining room
	char __end[0] __attribute__((aligned(64))); // align size to 64.
};


/* global profiling stats from the scheduler: each entry corresponds to a
 * task or tasklet ->process function pointer, with a number of calls and
 * a total time. Each entry is unique, except entry 0 which is for colliding
 * hashes (i.e. others). All of these must be accessed atomically.
 */
struct sched_activity {
	const void *func;
	uint64_t calls;
	uint64_t cpu_time;
	uint64_t lat_time;
};

#endif /* _HAPROXY_ACTIVITY_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
