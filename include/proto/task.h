/*
  include/proto/task.h
  Functions for task management.

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
extern struct task *last_timer;   /* optimization: last queued timer */

/* perform minimal initializations, report 0 in case of error, 1 if OK. */
int init_task();

/* return 0 if task is in run queue, otherwise non-zero */
static inline int task_in_rq(struct task *t)
{
	return t->rq.node.leaf_p != NULL;
}

/* return 0 if task is in wait queue, otherwise non-zero */
static inline int task_in_wq(struct task *t)
{
	return t->wq.node.leaf_p != NULL;
}

/* puts the task <t> in run queue with reason flags <f>, and returns <t> */
struct task *__task_wakeup(struct task *t);
static inline struct task *task_wakeup(struct task *t, unsigned int f)
{
	if (likely(!task_in_rq(t)))
		__task_wakeup(t);
	t->state |= f;
	return t;
}

/*
 * Unlink the task from the wait queue, and possibly update the last_timer
 * pointer. A pointer to the task itself is returned. The task *must* already
 * be in the wait queue before calling this function. If unsure, use the safer
 * task_unlink_wq() function.
 */
static inline struct task *__task_unlink_wq(struct task *t)
{
	eb32_delete(&t->wq);
	if (last_timer == t)
		last_timer = NULL;
	return t;
}

static inline struct task *task_unlink_wq(struct task *t)
{
	if (likely(task_in_wq(t)))
		__task_unlink_wq(t);
	return t;
}

/*
 * Unlink the task from the run queue. The run_queue size and number of niced
 * tasks are updated too. A pointer to the task itself is returned. The task
 * *must* already be in the wait queue before calling this function. If unsure,
 * use the safer task_unlink_rq() function.
 */
static inline struct task *__task_unlink_rq(struct task *t)
{
	eb32_delete(&t->rq);
	run_queue--;
	if (likely(t->nice))
		niced_tasks--;
	return t;
}

static inline struct task *task_unlink_rq(struct task *t)
{
	if (likely(task_in_rq(t)))
		__task_unlink_rq(t);
	return t;
}

/*
 * Unlinks the task and adjusts run queue stats.
 * A pointer to the task itself is returned.
 */
static inline struct task *task_delete(struct task *t)
{
	task_unlink_wq(t);
	task_unlink_rq(t);
	return t;
}

/*
 * Initialize a new task. The bare minimum is performed (queue pointers and state).
 * The task is returned.
 */
static inline struct task *task_init(struct task *t)
{
	t->wq.node.leaf_p = NULL;
	t->rq.node.leaf_p = NULL;
	t->state = TASK_SLEEPING;
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

/* Place <task> into the wait queue, where it may already be. If the expiration
 * timer is infinite, the task is dequeued.
 */
void task_queue(struct task *task);

/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - call maintain_proxies() to enable/disable the listeners
 *   - return the date of next event in <next> or eternity.
 */

void process_runnable_tasks(int *next);

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 */
void wake_expired_tasks(int *next);


#endif /* _PROTO_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
