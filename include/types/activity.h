/*
 * include/types/activity.h
 * This file contains structure declarations for activity measurements.
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

#ifndef _TYPES_ACTIVITY_H
#define _TYPES_ACTIVITY_H

#include <common/config.h>
#include <types/freq_ctr.h>

/* per-thread activity reports. It's important that it's aligned on cache lines
 * because some elements will be updated very often. Most counters are OK on
 * 32-bit since this will be used during debugging sessions for troubleshooting
 * in iterative mode.
 */
struct activity {
	unsigned int loops;        // complete loops in run_poll_loop()
	unsigned int wake_tasks;   // active tasks prevented poll() from sleeping
	unsigned int wake_signal;  // pending signal prevented poll() from sleeping
	unsigned int poll_exp;     // number of times poll() sees an expired timeout (includes wake_*)
	unsigned int poll_drop;    // poller dropped a dead FD from the update list
	unsigned int poll_dead;    // poller woke up with a dead FD
	unsigned int poll_skip;    // poller skipped another thread's FD
	unsigned int fd_lock;      // fd cache skipped a locked FD
	unsigned int conn_dead;    // conn_fd_handler woke up on an FD indicating a dead connection
	unsigned int stream;       // calls to process_stream()
	unsigned int ctxsw;        // total number of context switches
	unsigned int tasksw;       // total number of task switches
	unsigned int empty_rq;     // calls to process_runnable_tasks() with nothing for the thread
	unsigned int long_rq;      // process_runnable_tasks() left with tasks in the run queue
	unsigned int cpust_total;  // sum of half-ms stolen per thread
	/* one cache line */
	struct freq_ctr cpust_1s;  // avg amount of half-ms stolen over last second
	struct freq_ctr_period cpust_15s; // avg amount of half-ms stolen over last 15s
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

#endif /* _TYPES_ACTIVITY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
