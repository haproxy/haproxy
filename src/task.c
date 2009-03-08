/*
 * Task management functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/eb32tree.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/task.h>

struct pool_head *pool2_task;

unsigned int run_queue = 0;
unsigned int niced_tasks = 0; /* number of niced tasks in the run queue */
struct task *last_timer = NULL;  /* optimization: last queued timer */

static struct eb_root timers[TIMER_TREES];  /* trees with MSB 00, 01, 10 and 11 */
static struct eb_root rqueue[TIMER_TREES];  /* trees constituting the run queue */
static unsigned int rqueue_ticks;           /* insertion count */

/* Puts the task <t> in run queue at a position depending on t->nice. <t> is
 * returned. The nice value assigns boosts in 32th of the run queue size. A
 * nice value of -1024 sets the task to -run_queue*32, while a nice value of
 * 1024 sets the task to run_queue*32. The state flags are cleared, so the
 * caller will have to set its flags after this call.
 * The task must not already be in the run queue. If unsure, use the safer
 * task_wakeup() function.
 */
struct task *__task_wakeup(struct task *t)
{
	run_queue++;
	t->rq.key = ++rqueue_ticks;

	if (likely(t->nice)) {
		int offset;

		niced_tasks++;
		if (likely(t->nice > 0))
			offset = (unsigned)((run_queue * (unsigned int)t->nice) / 32U);
		else
			offset = -(unsigned)((run_queue * (unsigned int)-t->nice) / 32U);
		t->rq.key += offset;
	}

	/* clear state flags at the same time */
	t->state &= ~TASK_WOKEN_ANY;

	eb32_insert(&rqueue[timer_to_tree(t->rq.key)], &t->rq);
	return t;
}

/*
 * __task_queue()
 *
 * Inserts a task into the wait queue at the position given by its expiration
 * date. It does not matter if the task was already in the wait queue or not,
 * as it will be unlinked. The task must not have an infinite expiration timer.
 * Last, tasks must not be queued further than the end of the next tree, which
 * is between <now_ms> and <now_ms> + TIMER_SIGN_BIT ms (now+12days..24days in
 * 32bit).
 *
 * This function should not be used directly, it is meant to be called by the
 * inline version of task_queue() which performs a few cheap preliminary tests
 * before deciding to call __task_queue().
 */
void __task_queue(struct task *task)
{
	if (likely(task_in_wq(task)))
		__task_unlink_wq(task);

	/* the task is not in the queue now */
	if (unlikely(!tick_isset(task->expire)))
		return;

	task->wq.key = tick_to_timer(task->expire);
#ifdef DEBUG_CHECK_INVALID_EXPIRATION_DATES
	if ((task->wq.key - tick_to_timer(now_ms)) & TIMER_SIGN_BIT)
		/* we're queuing too far away or in the past (most likely) */
		return;
#endif

	if (likely(last_timer &&
		   last_timer->wq.key == task->wq.key &&
		   last_timer->wq.node.bit == -1 &&
		   last_timer->wq.node.node_p)) {
		/* Most often, last queued timer has the same expiration date, so
		 * if it's not queued at the root, let's queue a dup directly there.
		 * Note that we can only use dups at the dup tree's root (bit==-1).
		 */
		eb_insert_dup(&last_timer->wq.node, &task->wq.node);
		return;
	}
	eb32_insert(&timers[timer_to_tree(task->wq.key)], &task->wq);
	if (task->wq.node.bit == -1)
		last_timer = task; /* we only want dup a tree's root */
	return;
}

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 */
void wake_expired_tasks(int *next)
{
	struct task *task;
	struct eb32_node *eb;
	unsigned int now_tree;
	unsigned int tree;

	/* In theory, we should :
	 *   - wake all tasks from the <previous> tree
	 *   - wake all expired tasks from the <current> tree
	 *   - scan <next> trees for next expiration date if not found earlier.
	 * But we can do all this more easily : we scan all 3 trees before we
	 * wrap, and wake everything expired from there, then stop on the first
	 * non-expired entry.
	 */

	now_tree = timer_to_tree(tick_to_timer(now_ms));
	tree = (now_tree - 1) & TIMER_TREE_MASK;
	do {
		eb = eb32_first(&timers[tree]);
		while (eb) {
			task = eb32_entry(eb, struct task, wq);
			if (likely((tick_to_timer(now_ms) - eb->key) & TIMER_SIGN_BIT)) {
				/* note that we don't need this check for the <previous>
				 * tree, but it's cheaper than duplicating the code.
				 */
				*next = timer_to_tick(eb->key);
				return;
			}

			/* detach the task from the queue and add the task to the run queue */
			eb = eb32_next(eb);
			__task_unlink_wq(task);

			/* It is possible that this task was left at an earlier place in the
			 * tree because a recent call to task_queue() has not moved it. This
			 * happens when the new expiration date is later than the old one.
			 * Since it is very unlikely that we reach a timeout anyway, it's a
			 * lot cheaper to proceed like this because we almost never update
			 * the tree. We may also find disabled expiration dates there. Since
			 * we have detached the task from the tree, we simply call task_queue
			 * to take care of this.
			 */
			if (!tick_is_expired(task->expire, now_ms)) {
				task_queue(task);
				continue;
			}
			task_wakeup(task, TASK_WOKEN_TIMER);
		}
		tree = (tree + 1) & TIMER_TREE_MASK;
	} while (((tree - now_tree) & TIMER_TREE_MASK) < TIMER_TREES/2);

	/* We have found no task to expire in any tree */
	*next = TICK_ETERNITY;
	return;
}

/* The run queue is chronologically sorted in a tree. An insertion counter is
 * used to assign a position to each task. This counter may be combined with
 * other variables (eg: nice value) to set the final position in the tree. The
 * counter may wrap without a problem, of course. We then limit the number of
 * tasks processed at once to 1/4 of the number of tasks in the queue, and to
 * 200 max in any case, so that general latency remains low and so that task
 * positions have a chance to be considered. It also reduces the number of
 * trees to be evaluated when no task remains.
 *
 * Just like with timers, we start with tree[(current - 1)], which holds past
 * values, and stop when we reach the middle of the list. In practise, we visit
 * 3 out of 4 trees.
 *
 * The function adjusts <next> if a new event is closer.
 */
void process_runnable_tasks(int *next)
{
	struct task *t;
	struct eb32_node *eb;
	unsigned int tree, stop;
	unsigned int max_processed;
	int expire;

	if (!run_queue)
		return;

	max_processed = run_queue;
	if (max_processed > 200)
		max_processed = 200;

	if (likely(niced_tasks))
		max_processed /= 4;

	tree = timer_to_tree(rqueue_ticks);
	stop = (tree + TIMER_TREES / 2) & TIMER_TREE_MASK;
	tree = (tree - 1) & TIMER_TREE_MASK;

	expire = *next;
	do {
		eb = eb32_first(&rqueue[tree]);
		while (eb) {
			/* Note: this loop is one of the fastest code path in
			 * the whole program. It should not be re-arranged
			 * without a good reason.
			 */
			t = eb32_entry(eb, struct task, rq);

			/* detach the task from the queue and add the task to the run queue */
			eb = eb32_next(eb);
			__task_unlink_rq(t);

			t->state |= TASK_RUNNING;
			/* This is an optimisation to help the processor's branch
			 * predictor take this most common call.
			 */
			if (likely(t->process == process_session))
				t = process_session(t);
			else
				t = t->process(t);

			if (likely(t != NULL)) {
				t->state &= ~TASK_RUNNING;
				if (t->expire) {
					task_queue(t);
					expire = tick_first_2nz(expire, t->expire);
				}
			}

			if (!--max_processed)
				goto out;
		}
		tree = (tree + 1) & TIMER_TREE_MASK;
	} while (tree != stop);
 out:
	*next = expire;
}

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_task()
{
	memset(&timers, 0, sizeof(timers));
	memset(&rqueue, 0, sizeof(rqueue));
	pool2_task = create_pool("task", sizeof(struct task), MEM_F_SHARED);
	return pool2_task != NULL;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
