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
#include <eb32sctree.h>
#include <eb32tree.h>

#include <proto/proxy.h>
#include <proto/stream.h>
#include <proto/task.h>

struct pool_head *pool_head_task;

/* This is the memory pool containing all the signal structs. These
 * struct are used to store each requiered signal between two tasks.
 */
struct pool_head *pool_head_notification;

unsigned int nb_tasks = 0;
unsigned long active_tasks_mask = 0; /* Mask of threads with active tasks */
unsigned int tasks_run_queue = 0;
unsigned int tasks_run_queue_cur = 0;    /* copy of the run queue size */
unsigned int nb_tasks_cur = 0;     /* copy of the tasks count */
unsigned int niced_tasks = 0;      /* number of niced tasks in the run queue */

THREAD_LOCAL struct task *curr_task = NULL; /* task currently running or NULL */
THREAD_LOCAL struct eb32sc_node *rq_next = NULL; /* Next task to be potentially run */

__decl_hathreads(HA_SPINLOCK_T __attribute__((aligned(64))) rq_lock); /* spin lock related to run queue */
__decl_hathreads(HA_SPINLOCK_T __attribute__((aligned(64))) wq_lock); /* spin lock related to wait queue */

static struct eb_root timers;      /* sorted timers tree */
static struct eb_root rqueue;      /* tree constituting the run queue */
static unsigned int rqueue_ticks;  /* insertion count */

/* Puts the task <t> in run queue at a position depending on t->nice. <t> is
 * returned. The nice value assigns boosts in 32th of the run queue size. A
 * nice value of -1024 sets the task to -tasks_run_queue*32, while a nice value
 * of 1024 sets the task to tasks_run_queue*32. The state flags are cleared, so
 * the caller will have to set its flags after this call.
 * The task must not already be in the run queue. If unsure, use the safer
 * task_wakeup() function.
 */
struct task *__task_wakeup(struct task *t)
{
	tasks_run_queue++;
	active_tasks_mask |= t->thread_mask;
	t->rq.key = ++rqueue_ticks;

	if (likely(t->nice)) {
		int offset;

		niced_tasks++;
		if (likely(t->nice > 0))
			offset = (unsigned)((tasks_run_queue * (unsigned int)t->nice) / 32U);
		else
			offset = -(unsigned)((tasks_run_queue * (unsigned int)-t->nice) / 32U);
		t->rq.key += offset;
	}

	/* reset flag to pending ones
	 * Note: __task_wakeup must not be called
	 * if task is running
	 */
	t->state = t->pending_state;
	eb32sc_insert(&rqueue, &t->rq, t->thread_mask);
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

	eb32_insert(&timers, &task->wq);

	return;
}

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 */
int wake_expired_tasks()
{
	struct task *task;
	struct eb32_node *eb;
	int ret = TICK_ETERNITY;

	while (1) {
		HA_SPIN_LOCK(TASK_WQ_LOCK, &wq_lock);
  lookup_next:
		eb = eb32_lookup_ge(&timers, now_ms - TIMER_LOOK_BACK);
		if (!eb) {
			/* we might have reached the end of the tree, typically because
			* <now_ms> is in the first half and we're first scanning the last
			* half. Let's loop back to the beginning of the tree now.
			*/
			eb = eb32_first(&timers);
			if (likely(!eb))
				break;
		}

		if (tick_is_lt(now_ms, eb->key)) {
			/* timer not expired yet, revisit it later */
			ret = eb->key;
			break;
		}

		/* timer looks expired, detach it from the queue */
		task = eb32_entry(eb, struct task, wq);
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
			if (tick_isset(task->expire))
				__task_queue(task);
			goto lookup_next;
		}
		task_wakeup(task, TASK_WOKEN_TIMER);
		HA_SPIN_UNLOCK(TASK_WQ_LOCK, &wq_lock);
	}

	HA_SPIN_UNLOCK(TASK_WQ_LOCK, &wq_lock);
	return ret;
}

/* The run queue is chronologically sorted in a tree. An insertion counter is
 * used to assign a position to each task. This counter may be combined with
 * other variables (eg: nice value) to set the final position in the tree. The
 * counter may wrap without a problem, of course. We then limit the number of
 * tasks processed to 200 in any case, so that general latency remains low and
 * so that task positions have a chance to be considered.
 *
 * The function adjusts <next> if a new event is closer.
 */
void process_runnable_tasks()
{
	struct task *t;
	int i;
	int max_processed;
	struct task *local_tasks[16];
	int local_tasks_count;
	int final_tasks_count;

	tasks_run_queue_cur = tasks_run_queue; /* keep a copy for reporting */
	nb_tasks_cur = nb_tasks;
	max_processed = 200;
	if (unlikely(global.nbthread <= 1)) {
		/* when no lock is needed, this loop is much faster */
		if (!(active_tasks_mask & tid_bit)) {
			activity[tid].empty_rq++;
			return;
		}

		active_tasks_mask &= ~tid_bit;
		rq_next = eb32sc_lookup_ge(&rqueue, rqueue_ticks - TIMER_LOOK_BACK, tid_bit);
		while (1) {
			if (!rq_next) {
				/* we might have reached the end of the tree, typically because
				 * <rqueue_ticks> is in the first half and we're first scanning
				 * the last half. Let's loop back to the beginning of the tree now.
				 */
				rq_next = eb32sc_first(&rqueue, tid_bit);
				if (!rq_next)
					break;
			}

			t = eb32sc_entry(rq_next, struct task, rq);
			rq_next = eb32sc_next(rq_next, tid_bit);
			__task_unlink_rq(t);
			t->state |= TASK_RUNNING;
			t->pending_state = 0;

			t->calls++;
			curr_task = t;
			/* This is an optimisation to help the processor's branch
			 * predictor take this most common call.
			 */
			if (likely(t->process == process_stream))
				t = process_stream(t);
			else {
				if (t->process != NULL)
					t = t->process(t);
				else {
					__task_free(t);
					t = NULL;
				}
			}
			curr_task = NULL;

			if (likely(t != NULL)) {
				t->state &= ~TASK_RUNNING;
				/* If there is a pending state
				 * we have to wake up the task
				 * immediatly, else we defer
				 * it into wait queue
				 */
				if (t->pending_state)
					__task_wakeup(t);
				else
					task_queue(t);
			}

			max_processed--;
			if (max_processed <= 0) {
				active_tasks_mask |= tid_bit;
				activity[tid].long_rq++;
				break;
			}
		}
		return;
	}

	HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);
	if (!(active_tasks_mask & tid_bit)) {
		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
		activity[tid].empty_rq++;
		return;
	}

	active_tasks_mask &= ~tid_bit;
	while (1) {
		/* Note: this loop is one of the fastest code path in
		 * the whole program. It should not be re-arranged
		 * without a good reason.
		 */

		/* we have to restart looking up after every batch */
		rq_next = eb32sc_lookup_ge(&rqueue, rqueue_ticks - TIMER_LOOK_BACK, tid_bit);
		for (local_tasks_count = 0; local_tasks_count < 16; local_tasks_count++) {
			if (unlikely(!rq_next)) {
				/* either we just started or we reached the end
				 * of the tree, typically because <rqueue_ticks>
				 * is in the first half and we're first scanning
				 * the last half. Let's loop back to the beginning
				 * of the tree now.
				 */
				rq_next = eb32sc_first(&rqueue, tid_bit);
				if (!rq_next)
					break;
			}

			t = eb32sc_entry(rq_next, struct task, rq);
			rq_next = eb32sc_next(rq_next, tid_bit);

			/* detach the task from the queue */
			__task_unlink_rq(t);
			local_tasks[local_tasks_count] = t;
			t->state |= TASK_RUNNING;
			t->pending_state = 0;
			t->calls++;
			max_processed--;
		}

		if (!local_tasks_count)
			break;

		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);

		final_tasks_count = 0;
		for (i = 0; i < local_tasks_count ; i++) {
			t = local_tasks[i];
			/* This is an optimisation to help the processor's branch
			 * predictor take this most common call.
			 */
			curr_task = t;
			if (likely(t->process == process_stream))
				t = process_stream(t);
			else {
				if (t->process != NULL)
					t = t->process(t);
				else {
					__task_free(t);
					t = NULL;
				}
			}
			curr_task = NULL;
			if (t)
				local_tasks[final_tasks_count++] = t;
		}

		for (i = 0; i < final_tasks_count ; i++) {
			t = local_tasks[i];
			/* If there is a pending state
			 * we have to wake up the task
			 * immediatly, else we defer
			 * it into wait queue
			 */
			HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);
			t->state &= ~TASK_RUNNING;
			if (t->pending_state) {
				__task_wakeup(t);
				HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
			}
			else {
				/* we must never hold the RQ lock before the WQ lock */
				HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
				task_queue(t);
			}
		}

		HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);
		if (max_processed <= 0) {
			active_tasks_mask |= tid_bit;
			activity[tid].long_rq++;
			break;
		}
	}
	HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
}

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_task()
{
	memset(&timers, 0, sizeof(timers));
	memset(&rqueue, 0, sizeof(rqueue));
	HA_SPIN_INIT(&wq_lock);
	HA_SPIN_INIT(&rq_lock);
	pool_head_task = create_pool("task", sizeof(struct task), MEM_F_SHARED);
	if (!pool_head_task)
		return 0;
	pool_head_notification = create_pool("notification", sizeof(struct notification), MEM_F_SHARED);
	if (!pool_head_notification)
		return 0;
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
