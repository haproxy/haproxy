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
#include <eb32tree.h>

/* values for task->state */
#define TASK_SLEEPING     0x00  /* task sleeping */
#define TASK_RUNNING      0x01  /* the task is currently running */
#define TASK_WOKEN_INIT   0x02  /* woken up for initialisation purposes */
#define TASK_WOKEN_TIMER  0x04  /* woken up because of expired timer */
#define TASK_WOKEN_IO     0x08  /* woken up because of completed I/O */
#define TASK_WOKEN_SIGNAL 0x10  /* woken up by a system signal */
#define TASK_WOKEN_MSG    0x20  /* woken up by another task's message */
#define TASK_WOKEN_RES    0x40  /* woken up because of available resource */
#define TASK_WOKEN_OTHER  0x80  /* woken up for an unspecified reason */

/* use this to check a task state or to clean it up before queueing */
#define TASK_WOKEN_ANY    (TASK_WOKEN_OTHER|TASK_WOKEN_INIT|TASK_WOKEN_TIMER| \
                           TASK_WOKEN_IO|TASK_WOKEN_SIGNAL|TASK_WOKEN_MSG| \
                           TASK_WOKEN_RES)

/* Additional wakeup info may be passed in the state by lef-shifting the value
 * by this number of bits. Not more than 8 bits are guaranteed to be delivered.
 * System signals may use that too.
 */
#define TASK_REASON_SHIFT 8

/* The base for all tasks */
struct task {
	struct eb32_node rq;		/* ebtree node used to hold the task in the run queue */
	unsigned short state;		/* task state : bit field of TASK_* */
	short nice;			/* the task's current nice value from -1024 to +1024 */
	unsigned int calls;		/* number of times ->process() was called */
	struct task * (*process)(struct task *t);  /* the function which processes the task */
	void *context;			/* the task's context */
	struct eb32_node wq;		/* ebtree node used to hold the task in the wait queue */
	int expire;			/* next expiration date for this task, in ticks */
};

/*
 * The task callback (->process) is responsible for updating ->expire. It must
 * return a pointer to the task itself, except if the task has been deleted, in
 * which case it returns NULL so that the scheduler knows it must not check the
 * expire timer. The scheduler will requeue the task at the proper location.
 */

#endif /* _TYPES_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
