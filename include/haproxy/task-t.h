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
#include <haproxy/show_flags-t.h>
#include <haproxy/thread-t.h>

/* values for task->state (32 bits).
 * Please also update the task_show_state() function below in case of changes.
 */
#define TASK_SLEEPING     0x00000000  /* task sleeping */
#define TASK_RUNNING      0x00000001  /* the task is currently running */
/* unused                 0x00000002 */
#define TASK_QUEUED       0x00000004  /* The task has been (re-)added to the run queue */
/* unused                 0x00000008 */
#define TASK_SELF_WAKING  0x00000010  /* task/tasklet found waking itself */
#define TASK_KILLED       0x00000020  /* task/tasklet killed, may now be freed */
#define TASK_IN_LIST      0x00000040  /* tasklet is in a tasklet list */
#define TASK_HEAVY        0x00000080  /* this task/tasklet is extremely heavy */

#define TASK_WOKEN_INIT   0x00000100  /* woken up for initialisation purposes */
#define TASK_WOKEN_TIMER  0x00000200  /* woken up because of expired timer */
#define TASK_WOKEN_IO     0x00000400  /* woken up because of completed I/O */
#define TASK_WOKEN_SIGNAL 0x00000800  /* woken up by a system signal */
#define TASK_WOKEN_MSG    0x00001000  /* woken up by another task's message (see also UEVT/USR1) */
#define TASK_WOKEN_RES    0x00002000  /* woken up because of available resource */
#define TASK_WOKEN_OTHER  0x00004000  /* woken up for an unspecified reason (see also UEVT/USR1) */

/* use this to check a task state or to clean it up before queueing */
#define TASK_WOKEN_ANY    (TASK_WOKEN_OTHER|TASK_WOKEN_INIT|TASK_WOKEN_TIMER| \
                           TASK_WOKEN_IO|TASK_WOKEN_SIGNAL|TASK_WOKEN_MSG| \
                           TASK_WOKEN_RES)

#define TASK_F_TASKLET    0x00008000  /* nature of this task: 0=task 1=tasklet */
#define TASK_F_USR1       0x00010000  /* preserved user flag 1, application-specific, def:0 */
#define TASK_F_UEVT1      0x00020000  /* one-shot user event type 1, application specific, def:0 */
#define TASK_F_UEVT2      0x00040000  /* one-shot user event type 2, application specific, def:0 */
#define TASK_F_WANTS_TIME 0x00080000  /* task/tasklet wants th_ctx->sched_call_date to be set */
#define TASK_F_UEVT3      0x00100000  /* one-shot user event type 3, application specific, def:0 */
/* unused: 0x200000..0x80000000 */

/* These flags are persistent across scheduler calls */
#define TASK_PERSISTENT   (TASK_SELF_WAKING | TASK_KILLED | \
                           TASK_HEAVY | TASK_F_TASKLET | TASK_F_USR1 | \
                           TASK_F_WANTS_TIME)

/* This function is used to report state in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *task_show_state(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(TASK_RUNNING, _(TASK_QUEUED, _(TASK_SELF_WAKING,
	_(TASK_KILLED, _(TASK_IN_LIST, _(TASK_HEAVY, _(TASK_WOKEN_INIT,
	_(TASK_WOKEN_TIMER, _(TASK_WOKEN_IO, _(TASK_WOKEN_SIGNAL,
	_(TASK_WOKEN_MSG, _(TASK_WOKEN_RES, _(TASK_WOKEN_OTHER,
	_(TASK_F_TASKLET, _(TASK_F_USR1)))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* these wakeup types are used to indicate how a task/tasklet was woken up, for
 * debugging purposes.
 */
enum {
	WAKEUP_TYPE_UNSET = 0,
	WAKEUP_TYPE_TASK_WAKEUP,
	WAKEUP_TYPE_TASK_INSTANT_WAKEUP,
	WAKEUP_TYPE_TASKLET_WAKEUP,
	WAKEUP_TYPE_TASKLET_WAKEUP_AFTER,
	WAKEUP_TYPE_TASK_SCHEDULE,
	WAKEUP_TYPE_TASK_QUEUE,
	WAKEUP_TYPE_APPCTX_WAKEUP,
};

struct notification {
	struct list purge_me; /* Part of the list of signals to be purged in the
	                         case of the LUA execution stack crash. */
	struct list wake_me; /* Part of list of signals to be targeted if an
	                        event occurs. */
	struct task *task; /* The task to be wake if an event occurs. */
	__decl_thread(HA_SPINLOCK_T lock);
};

#ifdef DEBUG_TASK
/* prev_caller keeps a copy of the previous value of the <caller> field. */
#define TASK_DEBUG_STORAGE                   \
	struct {                             \
		const struct ha_caller *prev_caller; \
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
		int tid;            /* tid of task/tasklet. <0 = local for tasklet, unbound for task */ \
		struct task *(*process)(struct task *t, void *ctx, unsigned int state); /* the function which processes the task */ \
		void *context; /* the task's context */			\
		const struct ha_caller *caller;	 /* call place of last wakeup(); 0 on init, -1 on free */ \
		uint32_t wake_date;              /* date of the last task wakeup */ \
		unsigned int calls;              /* number of times process was called */ \
		TASK_DEBUG_STORAGE;					\
	}

/* The base for all tasks */
struct task {
	TASK_COMMON;			/* must be at the beginning! */
	struct eb32_node rq;		/* ebtree node used to hold the task in the run queue */
	/* WARNING: the struct task is often aliased as a struct tasklet when
	 * it is NOT in the run queue. The tasklet has its struct list here
	 * where rq starts and this works because both are exclusive. Never
	 * ever reorder these fields without taking this into account!
	 */
	struct eb32_node wq;		/* ebtree node used to hold the task in the wait queue */
	int expire;			/* next expiration date for this task, in ticks */
	short nice;                     /* task prio from -1024 to +1024 */
	/* 16-bit hole here */
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
};

/* Note: subscribing to these events is only valid after the caller has really
 * attempted to perform the operation, and failed to proceed or complete.
 */
enum sub_event_type {
	SUB_RETRY_RECV       = 0x00000001,  /* Schedule the tasklet when we can attempt to recv again */
	SUB_RETRY_SEND       = 0x00000002,  /* Schedule the tasklet when we can attempt to send again */
};

/* Describes a set of subscriptions. Multiple events may be registered at the
 * same time. The callee should assume everything not pending for completion is
 * implicitly possible. It's illegal to change the tasklet if events are still
 * registered.
 */
struct wait_event {
	struct tasklet *tasklet;
	int events;             /* set of enum sub_event_type above */
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
