/*
  include/types/task.h
  Macros, variables and structures for task management.

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_TASK_H
#define _TYPES_TASK_H

#include <sys/time.h>

#include <common/config.h>
#include <common/eb32tree.h>
#include <common/mini-clist.h>

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

/* The base for all tasks */
struct task {
	struct eb32_node wq;		/* ebtree node used to hold the task in the wait queue */
	struct eb32_node rq;		/* ebtree node used to hold the task in the run queue */
	int state;			/* task state : bit field of TASK_* */
	unsigned int expire;		/* next expiration time for this task */
	void (*process)(struct task *t, int *next);  /* the function which processes the task */
	void *context;			/* the task's context */
	int nice;			/* the task's current nice value from -1024 to +1024 */
};

#endif /* _TYPES_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
