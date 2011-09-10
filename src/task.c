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

#include <string.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>
#include <eb32tree.h>

#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/task.h>

struct pool_head *pool2_task;

unsigned int nb_tasks = 0;
unsigned int run_queue = 0;
unsigned int run_queue_cur = 0;    /* copy of the run queue size */
unsigned int nb_tasks_cur = 0;     /* copy of the tasks count */
unsigned int niced_tasks = 0;      /* number of niced tasks in the run queue */
struct eb32_node *last_timer = NULL;  /* optimization: last queued timer */

static struct eb_root timers;      /* sorted timers tree */
static struct eb_root rqueue;      /* tree constituting the run queue */
static unsigned int rqueue_ticks;  /* insertion count */

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

	eb32_insert(&rqueue, &t->rq);
	return t;
}

/*
 * __task_queue()
 *
 * Inserts a task into the wait queue at the position given by its expiration
 * date. It does not matter if the task was already in the wait queue or not,
 * as it will be unlinked. The task must not have an infinite expiration timer.
 * Last, tasks must not be queued further than the end of the tree, which is
 * between <now_ms> and <now_ms> + 2^31 ms (now+24days in 32bit).
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
	task->wq.key = task->expire;
#ifdef DEBUG_CHECK_INVALID_EXPIRATION_DATES
	if (tick_is_lt(task->wq.key, now_ms))
		/* we're queuing too far away or in the past (most likely) */
		return;
#endif

	if (likely(last_timer &&
		   last_timer->node.bit < 0 &&
		   last_timer->key == task->wq.key &&
		   last_timer->node.node_p)) {
		/* Most often, last queued timer has the same expiration date, so
		 * if it's not queued at the root, let's queue a dup directly there.
		 * Note that we can only use dups at the dup tree's root (most
		 * negative bit).
		 */
		eb_insert_dup(&last_timer->node, &task->wq.node);
		if (task->wq.node.bit < last_timer->node.bit)
			last_timer = &task->wq;
		return;
	}
	eb32_insert(&timers, &task->wq);

	/* Make sure we don't assign the last_timer to a node-less entry */
	if (task->wq.node.node_p && (!last_timer || (task->wq.node.bit < last_timer->node.bit)))
		last_timer = &task->wq;
	return;
}

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity) in <next>.
 */
void wake_expired_tasks(int *next)
{
	struct task *task;
	struct eb32_node *eb;

	eb = eb32_lookup_ge(&timers, now_ms - TIMER_LOOK_BACK);
	while (1) {
		if (unlikely(!eb)) {
			/* we might have reached the end of the tree, typically because
			* <now_ms> is in the first half and we're first scanning the last
			* half. Let's loop back to the beginning of the tree now.
			*/
			eb = eb32_first(&timers);
			if (likely(!eb))
				break;
		}

		if (likely(tick_is_lt(now_ms, eb->key))) {
			/* timer not expired yet, revisit it later */
			*next = eb->key;
			return;
		}

		/* timer looks expired, detach it from the queue */
		task = eb32_entry(eb, struct task, wq);
		eb = eb32_next(eb);
		__task_unlink_wq(task);

		/* It is possible that this task was left at an earlier place in the
		 * tree because a recent call to task_queue() has not moved it. This
		 * happens when the new expiration date is later than the old one.
		 * Since it is very unlikely that we reach a timeout anyway, it's a
		 * lot cheaper to proceed like this because we almost never update
		 * the tree. We may also find disabled expiration dates there. Since
		 * we have detached the task from the tree, we simply call task_queue
		 * to take care of this. Note that we might occasionally requeue it at
		 * the same place, before <eb>, so we have to check if this happens,
		 * and adjust <eb>, otherwise we may skip it which is not what we want.
		 * We may also not requeue the task (and not point eb at it) if its
		 * expiration time is not set.
		 */
		if (!tick_is_expired(task->expire, now_ms)) {
			if (!tick_isset(task->expire))
				continue;
			__task_queue(task);
			if (!eb || eb->key > task->wq.key)
				eb = &task->wq;
			continue;
		}
		task_wakeup(task, TASK_WOKEN_TIMER);
	}

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
 * positions have a chance to be considered.
 *
 * The function adjusts <next> if a new event is closer.
 */
void process_runnable_tasks(int *next)
{
	struct task *t;
	struct eb32_node *eb;
	unsigned int max_processed;
	int expire;

	run_queue_cur = run_queue; /* keep a copy for reporting */
	nb_tasks_cur = nb_tasks;
	max_processed = run_queue;

	if (!run_queue)
		return;

	if (max_processed > 200)
		max_processed = 200;

	if (likely(niced_tasks))
		max_processed = (max_processed + 3) / 4;

	expire = *next;
	eb = eb32_lookup_ge(&rqueue, rqueue_ticks - TIMER_LOOK_BACK);
	while (max_processed--) {
		/* Note: this loop is one of the fastest code path in
		 * the whole program. It should not be re-arranged
		 * without a good reason.
		 */

		if (unlikely(!eb)) {
			/* we might have reached the end of the tree, typically because
			* <rqueue_ticks> is in the first half and we're first scanning
			* the last half. Let's loop back to the beginning of the tree now.
			*/
			eb = eb32_first(&rqueue);
			if (likely(!eb))
				break;
		}

		/* detach the task from the queue */
		t = eb32_entry(eb, struct task, rq);
		eb = eb32_next(eb);
		__task_unlink_rq(t);

		t->state |= TASK_RUNNING;
		/* This is an optimisation to help the processor's branch
		 * predictor take this most common call.
		 */
		t->calls++;
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

			/* if the task has put itself back into the run queue, we want to ensure
			 * it will be served at the proper time, especially if it's reniced.
			 */
			if (unlikely(task_in_rq(t)) && (!eb || tick_is_lt(t->rq.key, eb->key))) {
				eb = eb32_lookup_ge(&rqueue, rqueue_ticks - TIMER_LOOK_BACK);
			}
		}
	}
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
