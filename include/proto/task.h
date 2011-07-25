/*
 * include/proto/task.h
 * Functions for task management.
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

#ifndef _PROTO_TASK_H
#define _PROTO_TASK_H


#include <sys/time.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <eb32tree.h>

#include <types/task.h>

/* Principle of the wait queue.
 *
 * We want to be able to tell whether an expiration date is before of after the
 * current time <now>. We KNOW that expiration dates are never too far apart,
 * because they are measured in ticks (milliseconds). We also know that almost
 * all dates will be in the future, and that a very small part of them will be
 * in the past, they are the ones which have expired since last time we checked
 * them. Using ticks, we know if a date is in the future or in the past, but we
 * cannot use that to store sorted information because that reference changes
 * all the time.
 *
 * We'll use the fact that the time wraps to sort timers. Timers above <now>
 * are in the future, timers below <now> are in the past. Here, "above" and
 * "below" are to be considered modulo 2^31.
 *
 * Timers are stored sorted in an ebtree. We use the new ability for ebtrees to
 * lookup values starting from X to only expire tasks between <now> - 2^31 and
 * <now>. If the end of the tree is reached while walking over it, we simply
 * loop back to the beginning. That way, we have no problem keeping sorted
 * wrapping timers in a tree, between (now - 24 days) and (now + 24 days). The
 * keys in the tree always reflect their real position, none can be infinite.
 * This reduces the number of checks to be performed.
 *
 * Another nice optimisation is to allow a timer to stay at an old place in the
 * queue as long as it's not further than the real expiration date. That way,
 * we use the tree as a place holder for a minorant of the real expiration
 * date. Since we have a very low chance of hitting a timeout anyway, we can
 * bounce the nodes to their right place when we scan the tree if we encounter
 * a misplaced node once in a while. This even allows us not to remove the
 * infinite timers from the wait queue.
 *
 * So, to summarize, we have :
 *   - node->key always defines current position in the wait queue
 *   - timer is the real expiration date (possibly infinite)
 *   - node->key is always before or equal to timer
 *
 * The run queue works similarly to the wait queue except that the current date
 * is replaced by an insertion counter which can also wrap without any problem.
 */

/* The farthest we can look back in a timer tree */
#define TIMER_LOOK_BACK       (1U << 31)

/* a few exported variables */
extern unsigned int nb_tasks;     /* total number of tasks */
extern unsigned int run_queue;    /* run queue size */
extern unsigned int run_queue_cur;
extern unsigned int nb_tasks_cur;
extern unsigned int niced_tasks;  /* number of niced tasks in the run queue */
extern struct pool_head *pool2_task;
extern struct eb32_node *last_timer;   /* optimization: last queued timer */

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
	if (last_timer == &t->wq)
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
 * Initialize a new task. The bare minimum is performed (queue pointers and
 * state).  The task is returned. This function should not be used outside of
 * task_new().
 */
static inline struct task *task_init(struct task *t)
{
	t->wq.node.leaf_p = NULL;
	t->rq.node.leaf_p = NULL;
	t->state = TASK_SLEEPING;
	t->nice = 0;
	t->calls = 0;
	return t;
}

/*
 * Allocate and initialise a new task. The new task is returned, or NULL in
 * case of lack of memory. The task count is incremented. Tasks should only
 * be allocated this way, and must be freed using task_free().
 */
static inline struct task *task_new(void)
{
	struct task *t = pool_alloc2(pool2_task);
	if (t) {
		nb_tasks++;
		task_init(t);
	}
	return t;
}

/*
 * Free a task. Its context must have been freed since it will be lost.
 * The task count is decremented.
 */
static inline void task_free(struct task *t)
{
	pool_free2(pool2_task, t);
	nb_tasks--;
}

/* Place <task> into the wait queue, where it may already be. If the expiration
 * timer is infinite, do nothing and rely on wake_expired_task to clean up.
 */
void __task_queue(struct task *task);
static inline void task_queue(struct task *task)
{
	/* If we already have a place in the wait queue no later than the
	 * timeout we're trying to set, we'll stay there, because it is very
	 * unlikely that we will reach the timeout anyway. If the timeout
	 * has been disabled, it's useless to leave the queue as well. We'll
	 * rely on wake_expired_tasks() to catch the node and move it to the
	 * proper place should it ever happen. Finally we only add the task
	 * to the queue if it was not there or if it was further than what
	 * we want.
	 */
	if (!tick_isset(task->expire))
		return;

	if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key))
		__task_queue(task);
}

/* Ensure <task> will be woken up at most at <when>. If the task is already in
 * the run queue (but not running), nothing is done. It may be used that way
 * with a delay :  task_schedule(task, tick_add(now_ms, delay));
 */
static inline void task_schedule(struct task *task, int when)
{
	if (task_in_rq(task))
		return;

	if (task_in_wq(task))
		when = tick_first(when, task->expire);

	task->expire = when;
	if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key))
		__task_queue(task);
}

/*
 * This does 3 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - return the date of next event in <next> or eternity.
 */

void process_runnable_tasks(int *next);

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 */
void wake_expired_tasks(int *next);

/* Perform minimal initializations, report 0 in case of error, 1 if OK. */
int init_task();

#endif /* _PROTO_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
