/*
 * include/haproxy/task-t.h
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

#ifndef _HAPROXY_TASK_T_H
#define _HAPROXY_TASK_T_H

#include <sys/time.h>

#include <import/ebtree-t.h>

#include <haproxy/api-t.h>
#include <haproxy/thread-t.h>

/* values for task->state (32 bits) */
#define TASK_SLEEPING     0x00000000  /* task sleeping */
#define TASK_RUNNING      0x00000001  /* the task is currently running */
#define TASK_GLOBAL       0x00000002  /* The task is currently in the global runqueue */
#define TASK_QUEUED       0x00000004  /* The task has been (re-)added to the run queue */
#define TASK_SHARED_WQ    0x00000008  /* The task's expiration may be updated by other
                                       * threads, must be set before first queue/wakeup */
#define TASK_SELF_WAKING  0x00000010  /* task/tasklet found waking itself */
#define TASK_KILLED       0x00000020  /* task/tasklet killed, may now be freed */
#define TASK_IN_LIST      0x00000040  /* tasklet is in a tasklet list */
#define TASK_HEAVY        0x00000080  /* this task/tasklet is extremely heavy */

#define TASK_WOKEN_INIT   0x00000100  /* woken up for initialisation purposes */
#define TASK_WOKEN_TIMER  0x00000200  /* woken up because of expired timer */
#define TASK_WOKEN_IO     0x00000400  /* woken up because of completed I/O */
#define TASK_WOKEN_SIGNAL 0x00000800  /* woken up by a system signal */
#define TASK_WOKEN_MSG    0x00001000  /* woken up by another task's message */
#define TASK_WOKEN_RES    0x00002000  /* woken up because of available resource */
#define TASK_WOKEN_OTHER  0x00004000  /* woken up for an unspecified reason */

/* use this to check a task state or to clean it up before queueing */
#define TASK_WOKEN_ANY    (TASK_WOKEN_OTHER|TASK_WOKEN_INIT|TASK_WOKEN_TIMER| \
                           TASK_WOKEN_IO|TASK_WOKEN_SIGNAL|TASK_WOKEN_MSG| \
                           TASK_WOKEN_RES)

#define TASK_F_TASKLET    0x00008000  /* nature of this task: 0=task 1=tasklet */
#define TASK_F_USR1       0x00010000  /* preserved user flag 1, application-specific, def:0 */
/* unused: 0x20000..0x80000000 */

/* These flags are persistent across scheduler calls */
#define TASK_PERSISTENT   (TASK_SHARED_WQ | TASK_SELF_WAKING | TASK_KILLED | \
                           TASK_HEAVY | TASK_F_TASKLET | TASK_F_USR1)

struct notification {
	struct list purge_me; /* Part of the list of signals to be purged in the
	                         case of the LUA execution stack crash. */
	struct list wake_me; /* Part of list of signals to be targeted if an
	                        event occurs. */
	struct task *task; /* The task to be wake if an event occurs. */
	__decl_thread(HA_SPINLOCK_T lock);
};

#ifdef DEBUG_TASK
#define TASK_DEBUG_STORAGE                   \
	struct {                             \
		const char *caller_file[2];  \
		int caller_line[2];          \
		int caller_idx;              \
	} debug
#else
#define TASK_DEBUG_STORAGE
#endif

/* This part is common between struct task and struct tasklet so that tasks
 * can be used as-is as tasklets.
 *
 * Note that the process() function must ALWAYS return the task/tasklet's
 * pointer if the task/tasklet remains valid, and return NULL if it has been
 * deleted. The scheduler relies on this to know if it should update its state
 * on return.
 */
#define TASK_COMMON							\
	struct {							\
		unsigned int state; /* task state : bitfield of TASK_	*/ \
		/* 16-bit hole here */ \
		unsigned int calls; /* number of times process was called */ \
		struct task *(*process)(struct task *t, void *ctx, unsigned int state); /* the function which processes the task */ \
		void *context; /* the task's context */			\
		TASK_DEBUG_STORAGE;					\
	}

/* The base for all tasks */
struct task {
	TASK_COMMON;			/* must be at the beginning! */
	struct eb32sc_node rq;		/* ebtree node used to hold the task in the run queue */
	/* WARNING: the struct task is often aliased as a struct tasklet when
	 * it is NOT in the run queue. The tasklet has its struct list here
	 * where rq starts and this works because both are exclusive. Never
	 * ever reorder these fields without taking this into account!
	 */
	struct eb32_node wq;		/* ebtree node used to hold the task in the wait queue */
	int expire;			/* next expiration date for this task, in ticks */
	short nice;                     /* task prio from -1024 to +1024 */
	/* 16-bit hole here */
	unsigned long thread_mask;	/* mask of thread IDs authorized to process the task */
	uint64_t call_date;		/* date of the last task wakeup or call */
	uint64_t lat_time;		/* total latency time experienced */
	uint64_t cpu_time;              /* total CPU time consumed */
};

/* lightweight tasks, without priority, mainly used for I/Os */
struct tasklet {
	TASK_COMMON;			/* must be at the beginning! */
	struct list list;
	/* WARNING: the struct task is often aliased as a struct tasklet when
	 * it is not in the run queue. The task has its struct rq here where
	 * list starts and this works because both are exclusive. Never ever
	 * reorder these fields without taking this into account!
	 */
#ifdef DEBUG_TASK
	uint64_t call_date;		/* date of the last tasklet wakeup or call */
#endif
	int tid;                        /* TID of the tasklet owner, <0 if local */
};

/*
 * The task callback (->process) is responsible for updating ->expire. It must
 * return a pointer to the task itself, except if the task has been deleted, in
 * which case it returns NULL so that the scheduler knows it must not check the
 * expire timer. The scheduler will requeue the task at the proper location.
 */


#endif /* _HAPROXY_TASK_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
