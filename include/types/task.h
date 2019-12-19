/*
 * include/types/task.h
 * Macros, variables and structures for task management.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_TASK_H
#define _TYPES_TASK_H

#include <sys/time.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <eb32sctree.h>
#include <eb32tree.h>

/* values for task->state */
#define TASK_SLEEPING     0x0000  /* task sleeping */
#define TASK_RUNNING      0x0001  /* the task is currently running */
#define TASK_GLOBAL       0x0002  /* The task is currently in the global runqueue */
#define TASK_QUEUED       0x0004  /* The task has been (re-)added to the run queue */
#define TASK_SHARED_WQ    0x0008  /* The task's expiration may be updated by other
                                   * threads, must be set before first queue/wakeup */

#define TASK_WOKEN_INIT   0x0100  /* woken up for initialisation purposes */
#define TASK_WOKEN_TIMER  0x0200  /* woken up because of expired timer */
#define TASK_WOKEN_IO     0x0400  /* woken up because of completed I/O */
#define TASK_WOKEN_SIGNAL 0x0800  /* woken up by a system signal */
#define TASK_WOKEN_MSG    0x1000  /* woken up by another task's message */
#define TASK_WOKEN_RES    0x2000  /* woken up because of available resource */
#define TASK_WOKEN_OTHER  0x4000  /* woken up for an unspecified reason */

/* use this to check a task state or to clean it up before queueing */
#define TASK_WOKEN_ANY    (TASK_WOKEN_OTHER|TASK_WOKEN_INIT|TASK_WOKEN_TIMER| \
                           TASK_WOKEN_IO|TASK_WOKEN_SIGNAL|TASK_WOKEN_MSG| \
                           TASK_WOKEN_RES)

struct notification {
	struct list purge_me; /* Part of the list of signals to be purged in the
	                         case of the LUA execution stack crash. */
	struct list wake_me; /* Part of list of signals to be targeted if an
	                        event occurs. */
	struct task *task; /* The task to be wake if an event occurs. */
	__decl_hathreads(HA_SPINLOCK_T lock);
};

/* force to split per-thread stuff into separate cache lines */
struct task_per_thread {
	struct eb_root timers;  /* tree constituting the per-thread wait queue */
	struct eb_root rqueue;  /* tree constituting the per-thread run queue */
	struct list task_list;  /* List of tasks to be run, mixing tasks and tasklets */
	struct mt_list shared_tasklet_list; /* Tasklet to be run, woken up by other threads */
	int task_list_size;     /* Number of tasks in the task_list */
	int rqueue_size;        /* Number of elements in the per-thread run queue */
	struct task *current;   /* current task (not tasklet) */
	__attribute__((aligned(64))) char end[0];
};

/* This part is common between struct task and struct tasklet so that tasks
 * can be used as-is as tasklets.
 */
#define TASK_COMMON							\
	struct {							\
		unsigned short state; /* task state : bitfield of TASK_	*/ \
		short nice; /* task prio from -1024 to +1024, or -32768 for tasklets */ \
		unsigned int calls; /* number of times process was called */ \
		struct task *(*process)(struct task *t, void *ctx, unsigned short state); /* the function which processes the task */ \
		void *context; /* the task's context */			\
	}

/* The base for all tasks */
struct task {
	TASK_COMMON;			/* must be at the beginning! */
	struct eb32sc_node rq;		/* ebtree node used to hold the task in the run queue */
	struct eb32_node wq;		/* ebtree node used to hold the task in the wait queue */
	int expire;			/* next expiration date for this task, in ticks */
	unsigned long thread_mask;	/* mask of thread IDs authorized to process the task */
	uint64_t call_date;		/* date of the last task wakeup or call */
	uint64_t lat_time;		/* total latency time experienced */
	uint64_t cpu_time;              /* total CPU time consumed */
};

/* lightweight tasks, without priority, mainly used for I/Os */
struct tasklet {
	TASK_COMMON;			/* must be at the beginning! */
	struct list list;
	int tid;                        /* TID of the tasklet owner, <0 if local */
};

#define TASK_IS_TASKLET(t) ((t)->nice == -32768)

/*
 * The task callback (->process) is responsible for updating ->expire. It must
 * return a pointer to the task itself, except if the task has been deleted, in
 * which case it returns NULL so that the scheduler knows it must not check the
 * expire timer. The scheduler will requeue the task at the proper location.
 */


/* A work_list is a thread-safe way to enqueue some work to be run on another
 * thread. It consists of a list, a task and a general-purpose argument.
 * A work is appended to the list by atomically adding a list element to the
 * list and waking up the associated task, which is done using work_add(). The
 * caller must be careful about how operations are run as it will definitely
 * happen that the element being enqueued is processed by the other thread
 * before the call returns. Some locking conventions between the caller and the
 * callee might sometimes be necessary. The task is always woken up with reason
 * TASK_WOKEN_OTHER and a context pointing to the work_list entry.
 */
struct work_list {
	struct mt_list head;
	struct task *task;
	void *arg;
};

#endif /* _TYPES_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
