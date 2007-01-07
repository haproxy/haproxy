/*
  include/types/task.h
  Macros, variables and structures for task management.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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
#include <common/rbtree.h>

/* values for task->state */
#define TASK_IDLE	0
#define TASK_RUNNING	1

/* The base for all tasks */
struct task {
	struct rb_node rb_node;
	struct rb_root *wq;
	struct task *rqnext;		/* chaining in run queue ... */
	int state;				/* task state : IDLE or RUNNING */
	struct timeval expire;		/* next expiration time for this task, use only for fast sorting */
	int (*process)(struct task *t);	/* the function which processes the task */
	void *context;			/* the task's context */
};

#define sizeof_task     sizeof(struct task)
extern void **pool_task;

extern struct rb_root wait_queue[2];
extern struct task *rq;


#endif /* _TYPES_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
