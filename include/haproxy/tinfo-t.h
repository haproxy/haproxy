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
#include <haproxy/freq_ctr-t.h>
#include <haproxy/thread-t.h>

/* forward declarations for types used below */
struct buffer;

/* Threads sets are known either by a set of absolute thread numbers, or by a
 * set of relative thread numbers within a group, for each group. The default
 * is the absolute mode and corresponds to the case where no group is known
 * (nbgrp == 0). The mode may only be changed when the set is empty (use
 * thread_set_is_empty() for this).
 */
struct thread_set {
	union {
		ulong abs[(MAX_THREADS + LONGBITS - 1) / LONGBITS];
		ulong rel[MAX_TGROUPS];
	};
	ulong grps; /* bit field of all non-empty groups, 0 for abs */
};

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
#define TH_FL_STARTED           0x00000010  /* set once the thread starts */
#define TH_FL_IN_LOOP           0x00000020  /* set only inside the polling loop */

/* we have 4 buffer-wait queues, in highest to lowest emergency order */
#define DYNBUF_NBQ              4

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

	struct eb_root timers;            /* wait queue (sorted timers tree, global, accessed under wq_lock) */

	uint niced_tasks;                 /* number of niced tasks in this group's run queues */

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
	uint ring_queue;                  /* queue number for the rings */

	ullong pth_id;                    /* the pthread_t cast to a ullong */
	void *stack_top;                  /* the top of the stack when entering the thread */

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
	uint8_t bufq_map;                   /* one bit per non-empty buffer_wq */
	uint8_t trc_disable_ctr;            /* cumulative counter to temporarily disable tracing */

	// 1 byte hole here
	unsigned int nb_rhttp_conns;        /* count of current conns used for active reverse HTTP */
	struct sched_activity *sched_profile_entry; /* profile entry in use by the current task/tasklet, only if sched_wake_date>0 */

	ALWAYS_ALIGN(2*sizeof(void*));
	struct list buffer_wq[DYNBUF_NBQ];  /* buffer waiters, 4 criticality-based queues */
	struct list pool_lru_head;          /* oldest objects in thread-local pool caches */
	struct list streams;                /* list of streams attached to this thread */
	struct list quic_conns;             /* list of active quic-conns attached to this thread */
	struct list quic_conns_clo;         /* list of closing quic-conns attached to this thread */
	struct list queued_checks;          /* checks waiting for a connection slot */
	struct list tasklets[TL_CLASSES];   /* tasklets (and/or tasks) to run, by class */

	void **emergency_bufs;              /* array of buffers allocated at boot. Next free one is [emergency_bufs_left-1] */
	uint emergency_bufs_left;           /* number of emergency buffers left in magic_bufs[] */

	uint32_t sched_wake_date;           /* current task/tasklet's wake date in 32-bit ns or 0 if not supported */
	uint64_t sched_call_date;           /* current task/tasklet's call date in ns */

	uint64_t prev_mono_time;            /* previous system wide monotonic time (leaving poll) */
	uint64_t curr_mono_time;            /* latest system wide monotonic time (leaving poll) */

	// around 8 bytes here for thread-local variables

	// third cache line here on 64 bits: accessed mostly using atomic ops
	ALWAYS_ALIGN(64);
	struct mt_list shared_tasklet_list; /* Tasklet to be run, woken up by other threads */
	unsigned int rqueue_ticks;          /* Insertion counter for the run queue */
	unsigned int rq_total;              /* total size of the run queue, prio_tree + tasklets */
	int tasks_in_list;                  /* Number of tasks in the per-thread tasklets list */
	uint idle_pct;                      /* idle to total ratio over last sample (percent) */
	uint flags;                         /* thread flags, TH_FL_*, atomic! */
	uint active_checks;                 /* number of active health checks on this thread, incl migrated */

	uint64_t prev_cpu_time;             /* previous per thread CPU time */

	struct eb_root rqueue_shared;       /* run queue fed by other threads */
	__decl_thread(HA_SPINLOCK_T rqsh_lock); /* lock protecting the shared runqueue */

	struct freq_ctr out_32bps;              /* #of 32-byte blocks emitted per second */
	uint running_checks;                    /* number of health checks currently running on this thread */

	unsigned long long out_bytes;           /* total #of bytes emitted */
	unsigned long long spliced_out_bytes;   /* total #of bytes emitted though a kernel pipe */
	struct buffer *thread_dump_buffer;      /* NULL out of dump, 0x02=to alloc, valid during a dump, |0x01 once done */
	unsigned long long total_streams;       /* Total number of streams created on this thread */
	unsigned int stream_cnt;                /* Number of streams attached to this thread */

	// around 68 bytes here for shared variables

	ALWAYS_ALIGN(128);
};


#endif /* _HAPROXY_TINFO_T_H */
