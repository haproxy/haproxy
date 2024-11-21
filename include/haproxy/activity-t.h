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


#ifdef USE_MEMORY_PROFILING

enum memprof_method {
	MEMPROF_METH_UNKNOWN = 0,
	MEMPROF_METH_MALLOC,
	MEMPROF_METH_CALLOC,
	MEMPROF_METH_REALLOC,
	MEMPROF_METH_STRDUP,
	MEMPROF_METH_FREE,
	MEMPROF_METH_P_ALLOC, // pool_alloc()
	MEMPROF_METH_P_FREE,  // pool_free()
	MEMPROF_METH_STRNDUP,        // _POSIX_C_SOURCE >= 200809L || glibc >= 2.10
	MEMPROF_METH_VALLOC,         // _BSD_SOURCE || _XOPEN_SOURCE>=500 || glibc >= 2.12
	MEMPROF_METH_ALIGNED_ALLOC,  // _ISOC11_SOURCE
	MEMPROF_METH_POSIX_MEMALIGN, // _POSIX_C_SOURCE >= 200112L
	MEMPROF_METH_MEMALIGN,       // obsolete
	MEMPROF_METH_PVALLOC,        // obsolete
	MEMPROF_METH_METHODS /* count, must be last */
};

/* mask of 1 << method to match those which free. Note that we don't count
 * p_alloc among them since p_alloc only has an optionally valid free counter
 * but which is reported by another call in any case since p_alloc itself does
 * not free.
 */
#define MEMPROF_FREE_MASK   ((1UL << MEMPROF_METH_REALLOC) | \
                             (1UL << MEMPROF_METH_FREE)    | \
                             (1UL << MEMPROF_METH_P_FREE))

/* stats:
 *   - malloc increases alloc
 *   - free increases free (if non null)
 *   - realloc increases either depending on the size change.
 * when the real size is known (malloc_usable_size()), it's used in free_tot
 * and alloc_tot, otherwise the requested size is reported in alloc_tot and
 * zero in free_tot.
 */
struct memprof_stats {
	const void *caller;
	enum memprof_method method;
	/* 4-7 bytes hole here */
	unsigned long long alloc_calls;
	unsigned long long free_calls;
	unsigned long long alloc_tot;
	unsigned long long free_tot;
	void *info; // for pools, ptr to the pool
	void *pad;  // pad to 64
};
#endif

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
	unsigned int poll_skip_fd; // poller skipped another thread's FD
	unsigned int conn_dead;    // conn_fd_handler woke up on an FD indicating a dead connection
	unsigned int stream_calls; // calls to process_stream()
	unsigned int ctxsw;        // total number of context switches
	unsigned int tasksw;       // total number of task switches
	unsigned int empty_rq;     // calls to process_runnable_tasks() with nothing for the thread
	unsigned int long_rq;      // process_runnable_tasks() left with tasks in the run queue
	unsigned int cpust_total;  // sum of half-ms stolen per thread
	unsigned int fd_takeover;  // number of times this thread stole another one's FD
	unsigned int check_adopted;// number of times a check was migrated to this thread
	ALWAYS_ALIGN(64);

	struct freq_ctr cpust_1s;  // avg amount of half-ms stolen over last second
	struct freq_ctr cpust_15s; // avg amount of half-ms stolen over last 15s
	unsigned int avg_loop_us;  // average run time per loop over last 1024 runs
	unsigned int accepted;     // accepted incoming connections
	unsigned int accq_pushed;  // accept queue connections pushed
	unsigned int accq_full;    // accept queue connection not pushed because full
	unsigned int pool_fail;    // failed a pool allocation
	unsigned int buf_wait;     // waited on a buffer allocation
	unsigned int check_started;// number of times a check was started on this thread
#if defined(DEBUG_DEV)
	/* keep these ones at the end */
	unsigned int ctr0;         // general purposee debug counter
	unsigned int ctr1;         // general purposee debug counter
	unsigned int ctr2;         // general purposee debug counter
#endif
	char __pad[0]; // unused except to check remaining room
	char __end[0] __attribute__((aligned(64))); // align size to 64.
};

/* 256 entries for callers * callees should be highly sufficient (~45 seen usually) */
#define SCHED_ACT_HASH_BITS 8
#define SCHED_ACT_HASH_BUCKETS (1U << SCHED_ACT_HASH_BITS)

/* global profiling stats from the scheduler: each entry corresponds to a
 * task or tasklet ->process function pointer, with a number of calls and
 * a total time. Each entry is unique, except entry 0 which is for colliding
 * hashes (i.e. others). All of these must be accessed atomically.
 */
struct sched_activity {
	const void *func;
	const struct ha_caller *caller;
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
