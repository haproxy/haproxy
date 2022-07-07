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
#include <haproxy/thread-t.h>

/* tasklet classes */
enum {
	TL_URGENT = 0,   /* urgent tasklets (I/O callbacks) */
	TL_NORMAL = 1,   /* normal tasks */
	TL_BULK   = 2,   /* bulk task/tasklets, streaming I/Os */
	TL_HEAVY  = 3,   /* heavy computational tasklets (e.g. TLS handshakes) */
	TL_CLASSES       /* must be last */
};

/* thread_ctx flags, for ha_thread_ctx[].flags. These flags describe the
 * thread's state and are visible to other threads, so they must be used
 * with atomic ops.
 */
#define TH_FL_STUCK             0x00000001
#define TH_FL_TASK_PROFILING    0x00000002
#define TH_FL_NOTIFIED          0x00000004  /* task was notified about the need to wake up */
#define TH_FL_SLEEPING          0x00000008  /* thread won't check its task list before next wakeup */


/* Thread group information. This defines a base and a count of global thread
 * IDs which belong to it, and which can be looked up into thread_info/ctx. It
 * is set up during parsing and is stable during operation. Thread groups start
 * at 1 so tgroup[0] describes thread group 1.
 */
struct tgroup_info {
	ulong threads_enabled;     /* mask of threads enabled in this group */
	uint base;                 /* first thread in this group */
	uint count;                /* number of threads in this group */
	ulong tgid_bit;            /* bit corresponding to the tgroup ID */

	/* pad to cache line (64B) */
	char __pad[0];            /* unused except to check remaining room */
	char __end[0] __attribute__((aligned(64)));
};

/* This structure describes the group-specific context (e.g. active threads
 * etc). It uses one cache line per thread to limit false sharing.
 */
struct tgroup_ctx {
	ulong threads_harmless;           /* mask of threads that are not modifying anything */
	ulong threads_idle;               /* mask of threads idling in the poller */
	ulong stopping_threads;           /* mask of threads currently stopping */

	HA_RWLOCK_T wq_lock;              /* RW lock related to the wait queue below */
	struct eb_root timers;            /* wait queue (sorted timers tree, global, accessed under wq_lock) */

	/* pad to cache line (64B) */
	char __pad[0];                    /* unused except to check remaining room */
	char __end[0] __attribute__((aligned(64)));
};

/* This structure describes all the per-thread info we need. When threads are
 * disabled, it contains the same info for the single running thread. This is
 * stable across all of a thread's life, and is being pointed to by the
 * thread-local "ti" pointer.
 */
struct thread_info {
	const struct tgroup_info *tg;     /* config of the thread-group this thread belongs to */
	struct tgroup_ctx *tg_ctx;        /* context of the thread-group this thread belongs to */
	uint tid, ltid;                   /* process-wide and group-wide thread ID (start at 0) */
	ulong ltid_bit;                   /* bit masks for the tid/ltid */
	uint tgid;                        /* ID of the thread group this thread belongs to (starts at 1; 0=unset) */

	/* pad to cache line (64B) */
	char __pad[0];                    /* unused except to check remaining room */
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
	int current_queue;                  /* points to current tasklet list being run, -1 if none */
	unsigned int nb_tasks;              /* number of tasks allocated on this thread */
	uint8_t tl_class_mask;              /* bit mask of non-empty tasklets classes */

	// 7 bytes hole here
	struct list pool_lru_head;          /* oldest objects in thread-local pool caches */
	struct list buffer_wq;              /* buffer waiters */
	struct list streams;                /* list of streams attached to this thread */

	ALWAYS_ALIGN(2*sizeof(void*));
	struct list tasklets[TL_CLASSES];   /* tasklets (and/or tasks) to run, by class */

	// third cache line here on 64 bits: accessed mostly using atomic ops
	ALWAYS_ALIGN(64);
	struct mt_list shared_tasklet_list; /* Tasklet to be run, woken up by other threads */
	unsigned int rqueue_ticks;          /* Insertion counter for the run queue */
	unsigned int rq_total;              /* total size of the run queue, prio_tree + tasklets */
	int tasks_in_list;                  /* Number of tasks in the per-thread tasklets list */
	uint idle_pct;                      /* idle to total ratio over last sample (percent) */
	uint flags;                         /* thread flags, TH_FL_*, atomic! */
	/* 32-bit hole here */

	uint64_t prev_cpu_time;             /* previous per thread CPU time */
	uint64_t prev_mono_time;            /* previous system wide monotonic time  */

	struct eb_root rqueue_shared;       /* run queue fed by other threads */
	__decl_thread(HA_SPINLOCK_T rqsh_lock); /* lock protecting the shared runqueue */

	ALWAYS_ALIGN(128);
};


#endif /* _HAPROXY_TINFO_T_H */
