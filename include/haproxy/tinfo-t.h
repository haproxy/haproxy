/*
 * include/haproxy/tinfo-t.h
 * Definitions of the thread_info structure.
 *
 * Copyright (C) 2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_TINFO_T_H
#define _HAPROXY_TINFO_T_H

#include <import/ebtree-t.h>

#include <haproxy/api-t.h>

/* tasklet classes */
enum {
	TL_URGENT = 0,   /* urgent tasklets (I/O callbacks) */
	TL_NORMAL = 1,   /* normal tasks */
	TL_BULK   = 2,   /* bulk task/tasklets, streaming I/Os */
	TL_HEAVY  = 3,   /* heavy computational tasklets (e.g. TLS handshakes) */
	TL_CLASSES       /* must be last */
};

/* thread info flags, for ha_thread_info[].flags */
#define TI_FL_STUCK             0x00000001

/* This structure describes all the per-thread info we need. When threads are
 * disabled, it contains the same info for the single running thread.
 */
struct thread_info {
	unsigned int flags;        /* thread info flags, TI_FL_* */

#ifdef CONFIG_HAP_POOLS
	struct list pool_lru_head;                         /* oldest objects   */
#endif
	struct list buffer_wq;     /* buffer waiters */
	struct list streams;       /* list of streams attached to this thread */

	/* pad to cache line (64B) */
	char __pad[0];            /* unused except to check remaining room */
	char __end[0] __attribute__((aligned(64)));
};

/* This structure describes all the per-thread context we need. This is
 * essentially the scheduler-specific stuff and a few important per-thread
 * lists that need to be thread-local. We take care of splitting this into
 * separate cache lines.
 */
struct thread_ctx {
	// first and second cache lines on 64 bits: thread-local operations only.
	struct eb_root timers;              /* tree constituting the per-thread wait queue */
	struct eb_root rqueue;              /* tree constituting the per-thread run queue */
	struct task *current;               /* current task (not tasklet) */
	unsigned int rqueue_ticks;          /* Insertion counter for the run queue */
	int current_queue;                  /* points to current tasklet list being run, -1 if none */
	unsigned int nb_tasks;              /* number of tasks allocated on this thread */
	uint8_t tl_class_mask;              /* bit mask of non-empty tasklets classes */

	// 11 bytes hole here
	ALWAYS_ALIGN(2*sizeof(void*));
	struct list tasklets[TL_CLASSES];   /* tasklets (and/or tasks) to run, by class */

	// third cache line here on 64 bits: accessed mostly using atomic ops
	ALWAYS_ALIGN(64);
	struct mt_list shared_tasklet_list; /* Tasklet to be run, woken up by other threads */
	unsigned int rq_total;              /* total size of the run queue, prio_tree + tasklets */
	int tasks_in_list;                  /* Number of tasks in the per-thread tasklets list */
	uint64_t prev_cpu_time;             /* previous per thread CPU time */
	uint64_t prev_mono_time;            /* previous system wide monotonic time  */
	uint idle_pct;                      /* idle to total ratio over last sample (percent) */
	ALWAYS_ALIGN(128);
};


#endif /* _HAPROXY_TINFO_T_H */
