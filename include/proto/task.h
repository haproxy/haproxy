/*
  include/proto/task.h
  Functions for task management.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
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

#ifndef _PROTO_TASK_H
#define _PROTO_TASK_H


#include <sys/time.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/task.h>

extern unsigned int run_queue;    /* run queue size */
extern unsigned int niced_tasks;  /* number of niced tasks in the run queue */
extern struct pool_head *pool2_task;

/* perform minimal initializations, report 0 in case of error, 1 if OK. */
int init_task();

/* puts the task <t> in run queue <q>, and returns <t> */
struct task *task_wakeup(struct task *t);

/* removes the task <t> from the run queue if it was in it.
 * returns <t>.
 */
static inline struct task *task_sleep(struct task *t)
{
	if (t->state == TASK_RUNNING) {
		t->state = TASK_IDLE;
		eb32_delete(&t->eb);
		run_queue--;
		if (likely(t->nice))
			niced_tasks--;
	}
	return t;
}

/*
 * unlinks the task from wherever it is queued :
 *  - run_queue
 *  - wait queue
 * A pointer to the task itself is returned.
 */
static inline struct task *task_delete(struct task *t)
{
	if (t->eb.node.leaf_p)
		eb32_delete(&t->eb);

	if (t->state == TASK_RUNNING) {
		run_queue--;
		if (likely(t->nice))
			niced_tasks--;
	}
	return t;
}

/*
 * Initialize a new task. The bare minimum is performed (queue pointers and state).
 * The task is returned.
 */
static inline struct task *task_init(struct task *t)
{
	t->eb.node.leaf_p = NULL;
	t->state = TASK_IDLE;
	t->nice = 0;
	return t;
}

/*
 * frees a task. Its context must have been freed since it will be lost.
 */
static inline void task_free(struct task *t)
{
	pool_free2(pool2_task, t);
}

/* inserts <task> into its assigned wait queue, where it may already be. In this case, it
 * may be only moved or left where it was, depending on its timing requirements.
 * <task> is returned.
 */
struct task *task_queue(struct task *task);

/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - call maintain_proxies() to enable/disable the listeners
 *   - return the date of next event in <next> or eternity.
 */

void process_runnable_tasks(struct timeval *next);

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 */
void wake_expired_tasks(struct timeval *next);


#endif /* _PROTO_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
