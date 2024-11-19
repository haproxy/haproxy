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

#include <import/eb32tree.h>

#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/cfgparse.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

extern struct task *process_stream(struct task *t, void *context, unsigned int state);
extern void stream_update_timings(struct task *t, uint64_t lat, uint64_t cpu);

DECLARE_POOL(pool_head_task,    "task",    sizeof(struct task));
DECLARE_POOL(pool_head_tasklet, "tasklet", sizeof(struct tasklet));

/* This is the memory pool containing all the signal structs. These
 * struct are used to store each required signal between two tasks.
 */
DECLARE_POOL(pool_head_notification, "notification", sizeof(struct notification));

/* The lock protecting all wait queues at once. For now we have no better
 * alternative since a task may have to be removed from a queue and placed
 * into another one. Storing the WQ index into the task doesn't seem to be
 * sufficient either.
 */
__decl_aligned_rwlock(wq_lock);

/* Flags the task <t> for immediate destruction and puts it into its first
 * thread's shared tasklet list if not yet queued/running. This will bypass
 * the priority scheduling and make the task show up as fast as possible in
 * the other thread's queue. Note that this operation isn't idempotent and is
 * not supposed to be run on the same task from multiple threads at once. It's
 * the caller's responsibility to make sure it is the only one able to kill the
 * task.
 */
void task_kill(struct task *t)
{
	unsigned int state = t->state;
	unsigned int thr;

	BUG_ON(state & TASK_KILLED);

	while (1) {
		while (state & (TASK_RUNNING | TASK_QUEUED)) {
			/* task already in the queue and about to be executed,
			 * or even currently running. Just add the flag and be
			 * done with it, the process loop will detect it and kill
			 * it. The CAS will fail if we arrive too late.
			 */
			if (_HA_ATOMIC_CAS(&t->state, &state, state | TASK_KILLED))
				return;
		}

		/* We'll have to wake it up, but we must also secure it so that
		 * it doesn't vanish under us. TASK_QUEUED guarantees nobody will
		 * add past us.
		 */
		if (_HA_ATOMIC_CAS(&t->state, &state, state | TASK_QUEUED | TASK_KILLED)) {
			/* Bypass the tree and go directly into the shared tasklet list.
			 * Note: that's a task so it must be accounted for as such. Pick
			 * the task's first thread for the job.
			 */
			thr = t->tid >= 0 ? t->tid : tid;

			/* Beware: tasks that have never run don't have their ->list empty yet! */
			MT_LIST_APPEND(&ha_thread_ctx[thr].shared_tasklet_list,
			               list_to_mt_list(&((struct tasklet *)t)->list));
			_HA_ATOMIC_INC(&ha_thread_ctx[thr].rq_total);
			_HA_ATOMIC_INC(&ha_thread_ctx[thr].tasks_in_list);
			wake_thread(thr);
			return;
		}
	}
}

/* Equivalent of task_kill for tasklets. Mark the tasklet <t> for destruction.
 * It will be deleted on the next scheduler invocation. This function is
 * thread-safe : a thread can kill a tasklet of another thread.
 */
void tasklet_kill(struct tasklet *t)
{
	unsigned int state = t->state;
	unsigned int thr;

	BUG_ON(state & TASK_KILLED);

	while (1) {
		while (state & (TASK_IN_LIST)) {
			/* Tasklet already in the list ready to be executed. Add
			 * the killed flag and wait for the process loop to
			 * detect it.
			 */
			if (_HA_ATOMIC_CAS(&t->state, &state, state | TASK_KILLED))
				return;
		}

		/* Mark the tasklet as killed and wake the thread to process it
		 * as soon as possible.
		 */
		if (_HA_ATOMIC_CAS(&t->state, &state, state | TASK_IN_LIST | TASK_KILLED)) {
			thr = t->tid >= 0 ? t->tid : tid;
			MT_LIST_APPEND(&ha_thread_ctx[thr].shared_tasklet_list,
			               list_to_mt_list(&t->list));
			_HA_ATOMIC_INC(&ha_thread_ctx[thr].rq_total);
			wake_thread(thr);
			return;
		}
	}
}

/* Do not call this one, please use tasklet_wakeup_on() instead, as this one is
 * the slow path of tasklet_wakeup_on() which performs some preliminary checks
 * and sets TASK_IN_LIST before calling this one. A negative <thr> designates
 * the current thread.
 */
void __tasklet_wakeup_on(struct tasklet *tl, int thr)
{
	if (likely(thr < 0)) {
		/* this tasklet runs on the caller thread */
		if (tl->state & TASK_HEAVY) {
			LIST_APPEND(&th_ctx->tasklets[TL_HEAVY], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_HEAVY;
		}
		else if (tl->state & TASK_SELF_WAKING) {
			LIST_APPEND(&th_ctx->tasklets[TL_BULK], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_BULK;
		}
		else if ((struct task *)tl == th_ctx->current) {
			_HA_ATOMIC_OR(&tl->state, TASK_SELF_WAKING);
			LIST_APPEND(&th_ctx->tasklets[TL_BULK], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_BULK;
		}
		else if (th_ctx->current_queue < 0) {
			LIST_APPEND(&th_ctx->tasklets[TL_URGENT], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_URGENT;
		}
		else {
			LIST_APPEND(&th_ctx->tasklets[th_ctx->current_queue], &tl->list);
			th_ctx->tl_class_mask |= 1 << th_ctx->current_queue;
		}
		_HA_ATOMIC_INC(&th_ctx->rq_total);
	} else {
		/* this tasklet runs on a specific thread. */
		MT_LIST_APPEND(&ha_thread_ctx[thr].shared_tasklet_list, list_to_mt_list(&tl->list));
		_HA_ATOMIC_INC(&ha_thread_ctx[thr].rq_total);
		wake_thread(thr);
	}
}

/* Do not call this one, please use tasklet_wakeup_after_on() instead, as this one is
 * the slow path of tasklet_wakeup_after() which performs some preliminary checks
 * and sets TASK_IN_LIST before calling this one.
 */
struct list *__tasklet_wakeup_after(struct list *head, struct tasklet *tl)
{
	BUG_ON(tl->tid >= 0 && tid != tl->tid);
	/* this tasklet runs on the caller thread */
	if (!head) {
		if (tl->state & TASK_HEAVY) {
			LIST_INSERT(&th_ctx->tasklets[TL_HEAVY], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_HEAVY;
		}
		else if (tl->state & TASK_SELF_WAKING) {
			LIST_INSERT(&th_ctx->tasklets[TL_BULK], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_BULK;
		}
		else if ((struct task *)tl == th_ctx->current) {
			_HA_ATOMIC_OR(&tl->state, TASK_SELF_WAKING);
			LIST_INSERT(&th_ctx->tasklets[TL_BULK], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_BULK;
		}
		else if (th_ctx->current_queue < 0) {
			LIST_INSERT(&th_ctx->tasklets[TL_URGENT], &tl->list);
			th_ctx->tl_class_mask |= 1 << TL_URGENT;
		}
		else {
			LIST_INSERT(&th_ctx->tasklets[th_ctx->current_queue], &tl->list);
			th_ctx->tl_class_mask |= 1 << th_ctx->current_queue;
		}
	}
	else {
		LIST_APPEND(head, &tl->list);
	}
	_HA_ATOMIC_INC(&th_ctx->rq_total);
	return &tl->list;
}

/* Puts the task <t> in run queue at a position depending on t->nice. <t> is
 * returned. The nice value assigns boosts in 32th of the run queue size. A
 * nice value of -1024 sets the task to -tasks_run_queue*32, while a nice value
 * of 1024 sets the task to tasks_run_queue*32. The state flags are cleared, so
 * the caller will have to set its flags after this call.
 * The task must not already be in the run queue. If unsure, use the safer
 * task_wakeup() function.
 */
void __task_wakeup(struct task *t)
{
	struct eb_root *root = &th_ctx->rqueue;
	int thr __maybe_unused = t->tid >= 0 ? t->tid : tid;

#ifdef USE_THREAD
	if (thr != tid) {
		root = &ha_thread_ctx[thr].rqueue_shared;

		_HA_ATOMIC_INC(&ha_thread_ctx[thr].rq_total);
		HA_SPIN_LOCK(TASK_RQ_LOCK, &ha_thread_ctx[thr].rqsh_lock);

		t->rq.key = _HA_ATOMIC_ADD_FETCH(&ha_thread_ctx[thr].rqueue_ticks, 1);
		__ha_barrier_store();
	} else
#endif
	{
		_HA_ATOMIC_INC(&th_ctx->rq_total);
		t->rq.key = _HA_ATOMIC_ADD_FETCH(&th_ctx->rqueue_ticks, 1);
	}

	if (likely(t->nice)) {
		int offset;

		_HA_ATOMIC_INC(&tg_ctx->niced_tasks);
		offset = t->nice * (int)global.tune.runqueue_depth;
		t->rq.key += offset;
	}

	if (_HA_ATOMIC_LOAD(&th_ctx->flags) & TH_FL_TASK_PROFILING)
		t->wake_date = now_mono_time();

	eb32_insert(root, &t->rq);

#ifdef USE_THREAD
	if (thr != tid) {
		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &ha_thread_ctx[thr].rqsh_lock);

		/* If all threads that are supposed to handle this task are sleeping,
		 * wake one.
		 */
		wake_thread(thr);
	}
#endif
	return;
}

/*
 * __task_queue()
 *
 * Inserts a task into wait queue <wq> at the position given by its expiration
 * date. It does not matter if the task was already in the wait queue or not,
 * as it will be unlinked. The task MUST NOT have an infinite expiration timer.
 * Last, tasks must not be queued further than the end of the tree, which is
 * between <now_ms> and <now_ms> + 2^31 ms (now+24days in 32bit).
 *
 * This function should not be used directly, it is meant to be called by the
 * inline version of task_queue() which performs a few cheap preliminary tests
 * before deciding to call __task_queue(). Moreover this function doesn't care
 * at all about locking so the caller must be careful when deciding whether to
 * lock or not around this call.
 */
void __task_queue(struct task *task, struct eb_root *wq)
{
#ifdef USE_THREAD
	BUG_ON((wq == &tg_ctx->timers && task->tid >= 0) ||
	       (wq == &th_ctx->timers && task->tid < 0) ||
	       (wq != &tg_ctx->timers && wq != &th_ctx->timers));
#endif
	/* if this happens the process is doomed anyway, so better catch it now
	 * so that we have the caller in the stack.
	 */
	BUG_ON(task->expire == TICK_ETERNITY);

	if (likely(task_in_wq(task)))
		__task_unlink_wq(task);

	/* the task is not in the queue now */
	task->wq.key = task->expire;
#ifdef DEBUG_CHECK_INVALID_EXPIRATION_DATES
	if (tick_is_lt(task->wq.key, now_ms))
		/* we're queuing too far away or in the past (most likely) */
		return;
#endif

	eb32_insert(wq, &task->wq);
}

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks.
 */
void wake_expired_tasks()
{
	struct thread_ctx * const tt = th_ctx; // thread's tasks
	int max_processed = global.tune.runqueue_depth;
	struct task *task;
	struct eb32_node *eb;
	__decl_thread(int key);

	while (1) {
		if (max_processed-- <= 0)
			goto leave;

		eb = eb32_lookup_ge(&tt->timers, now_ms - TIMER_LOOK_BACK);
		if (!eb) {
			/* we might have reached the end of the tree, typically because
			* <now_ms> is in the first half and we're first scanning the last
			* half. Let's loop back to the beginning of the tree now.
			*/
			eb = eb32_first(&tt->timers);
			if (likely(!eb))
				break;
		}

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
		 * expiration time is not set. We also make sure we leave the real
		 * expiration date for the next task in the queue so that when calling
		 * next_timer_expiry() we're guaranteed to see the next real date and
		 * not the next apparent date. This is in order to avoid useless
		 * wakeups.
		 */

		task = eb32_entry(eb, struct task, wq);
		if (tick_is_expired(task->expire, now_ms)) {
			/* expired task, wake it up */
			__task_unlink_wq(task);
			_task_wakeup(task, TASK_WOKEN_TIMER, 0);
		}
		else if (task->expire != eb->key) {
			/* task is not expired but its key doesn't match so let's
			 * update it and skip to next apparently expired task.
			 */
			__task_unlink_wq(task);
			if (tick_isset(task->expire))
				__task_queue(task, &tt->timers);
		}
		else {
			/* task not expired and correctly placed. It may not be eternal. */
			BUG_ON(task->expire == TICK_ETERNITY);
			break;
		}
	}

#ifdef USE_THREAD
	if (eb_is_empty(&tg_ctx->timers))
		goto leave;

	HA_RWLOCK_RDLOCK(TASK_WQ_LOCK, &wq_lock);
	eb = eb32_lookup_ge(&tg_ctx->timers, now_ms - TIMER_LOOK_BACK);
	if (!eb) {
		eb = eb32_first(&tg_ctx->timers);
		if (likely(!eb)) {
			HA_RWLOCK_RDUNLOCK(TASK_WQ_LOCK, &wq_lock);
			goto leave;
		}
	}
	key = eb->key;

	if (tick_is_lt(now_ms, key)) {
		HA_RWLOCK_RDUNLOCK(TASK_WQ_LOCK, &wq_lock);
		goto leave;
	}

	/* There's really something of interest here, let's visit the queue */

	if (HA_RWLOCK_TRYRDTOSK(TASK_WQ_LOCK, &wq_lock)) {
		/* if we failed to grab the lock it means another thread is
		 * already doing the same here, so let it do the job.
		 */
		HA_RWLOCK_RDUNLOCK(TASK_WQ_LOCK, &wq_lock);
		goto leave;
	}

	while (1) {
  lookup_next:
		if (max_processed-- <= 0)
			break;
		eb = eb32_lookup_ge(&tg_ctx->timers, now_ms - TIMER_LOOK_BACK);
		if (!eb) {
			/* we might have reached the end of the tree, typically because
			* <now_ms> is in the first half and we're first scanning the last
			* half. Let's loop back to the beginning of the tree now.
			*/
			eb = eb32_first(&tg_ctx->timers);
			if (likely(!eb))
				break;
		}

		task = eb32_entry(eb, struct task, wq);

		/* Check for any competing run of the task (quite rare but may
		 * involve a dangerous concurrent access on task->expire). In
		 * order to protect against this, we'll take an exclusive access
		 * on TASK_RUNNING before checking/touching task->expire. If the
		 * task is already RUNNING on another thread, it will deal by
		 * itself with the requeuing so we must not do anything and
		 * simply quit the loop for now, because we cannot wait with the
		 * WQ lock held as this would prevent the running thread from
		 * requeuing the task. One annoying effect of holding RUNNING
		 * here is that a concurrent task_wakeup() will refrain from
		 * waking it up. This forces us to check for a wakeup after
		 * releasing the flag.
		 */
		if (HA_ATOMIC_FETCH_OR(&task->state, TASK_RUNNING) & TASK_RUNNING)
			break;

		if (tick_is_expired(task->expire, now_ms)) {
			/* expired task, wake it up */
			HA_RWLOCK_SKTOWR(TASK_WQ_LOCK, &wq_lock);
			__task_unlink_wq(task);
			HA_RWLOCK_WRTOSK(TASK_WQ_LOCK, &wq_lock);
			task_drop_running(task, TASK_WOKEN_TIMER);
		}
		else if (task->expire != eb->key) {
			/* task is not expired but its key doesn't match so let's
			 * update it and skip to next apparently expired task.
			 */
			HA_RWLOCK_SKTOWR(TASK_WQ_LOCK, &wq_lock);
			__task_unlink_wq(task);
			if (tick_isset(task->expire))
				__task_queue(task, &tg_ctx->timers);
			HA_RWLOCK_WRTOSK(TASK_WQ_LOCK, &wq_lock);
			task_drop_running(task, 0);
			goto lookup_next;
		}
		else {
			/* task not expired and correctly placed. It may not be eternal. */
			BUG_ON(task->expire == TICK_ETERNITY);
			task_drop_running(task, 0);
			break;
		}
	}

	HA_RWLOCK_SKUNLOCK(TASK_WQ_LOCK, &wq_lock);
#endif
leave:
	return;
}

/* Checks the next timer for the current thread by looking into its own timer
 * list and the global one. It may return TICK_ETERNITY if no timer is present.
 * Note that the next timer might very well be slightly in the past.
 */
int next_timer_expiry()
{
	struct thread_ctx * const tt = th_ctx; // thread's tasks
	struct eb32_node *eb;
	int ret = TICK_ETERNITY;
	__decl_thread(int key = TICK_ETERNITY);

	/* first check in the thread-local timers */
	eb = eb32_lookup_ge(&tt->timers, now_ms - TIMER_LOOK_BACK);
	if (!eb) {
		/* we might have reached the end of the tree, typically because
		 * <now_ms> is in the first half and we're first scanning the last
		 * half. Let's loop back to the beginning of the tree now.
		 */
		eb = eb32_first(&tt->timers);
	}

	if (eb)
		ret = eb->key;

#ifdef USE_THREAD
	if (!eb_is_empty(&tg_ctx->timers)) {
		HA_RWLOCK_RDLOCK(TASK_WQ_LOCK, &wq_lock);
		eb = eb32_lookup_ge(&tg_ctx->timers, now_ms - TIMER_LOOK_BACK);
		if (!eb)
			eb = eb32_first(&tg_ctx->timers);
		if (eb)
			key = eb->key;
		HA_RWLOCK_RDUNLOCK(TASK_WQ_LOCK, &wq_lock);
		if (eb)
			ret = tick_first(ret, key);
	}
#endif
	return ret;
}

/* Walks over tasklet lists th_ctx->tasklets[0..TL_CLASSES-1] and run at most
 * budget[TL_*] of them. Returns the number of entries effectively processed
 * (tasks and tasklets merged). The count of tasks in the list for the current
 * thread is adjusted.
 */
unsigned int run_tasks_from_lists(unsigned int budgets[])
{
	struct task *(*process)(struct task *t, void *ctx, unsigned int state);
	struct list *tl_queues = th_ctx->tasklets;
	struct task *t;
	uint8_t budget_mask = (1 << TL_CLASSES) - 1;
	struct sched_activity *profile_entry = NULL;
	unsigned int done = 0;
	unsigned int queue;
	unsigned int state;
	void *ctx;

	for (queue = 0; queue < TL_CLASSES;) {
		th_ctx->current_queue = queue;

		/* global.tune.sched.low-latency is set */
		if (global.tune.options & GTUNE_SCHED_LOW_LATENCY) {
			if (unlikely(th_ctx->tl_class_mask & budget_mask & ((1 << queue) - 1))) {
				/* a lower queue index has tasks again and still has a
				 * budget to run them. Let's switch to it now.
				 */
				queue = (th_ctx->tl_class_mask & 1) ? 0 :
					(th_ctx->tl_class_mask & 2) ? 1 : 2;
				continue;
			}

			if (unlikely(queue > TL_URGENT &&
				     budget_mask & (1 << TL_URGENT) &&
				     !MT_LIST_ISEMPTY(&th_ctx->shared_tasklet_list))) {
				/* an urgent tasklet arrived from another thread */
				break;
			}

			if (unlikely(queue > TL_NORMAL &&
				     budget_mask & (1 << TL_NORMAL) &&
				     (!eb_is_empty(&th_ctx->rqueue) || !eb_is_empty(&th_ctx->rqueue_shared)))) {
				/* a task was woken up by a bulk tasklet or another thread */
				break;
			}
		}

		if (LIST_ISEMPTY(&tl_queues[queue])) {
			th_ctx->tl_class_mask &= ~(1 << queue);
			queue++;
			continue;
		}

		if (!budgets[queue]) {
			budget_mask &= ~(1 << queue);
			queue++;
			continue;
		}

		budgets[queue]--;
		activity[tid].ctxsw++;

		t = (struct task *)LIST_ELEM(tl_queues[queue].n, struct tasklet *, list);
		ctx = t->context;
		process = t->process;
		t->calls++;

		th_ctx->sched_wake_date = t->wake_date;
		if (th_ctx->sched_wake_date || (t->state & TASK_F_WANTS_TIME)) {
			/* take the most accurate clock we have, either
			 * mono_time() or last now_ns (monotonic but only
			 * incremented once per poll loop).
			 */
			th_ctx->sched_call_date = now_mono_time();
			if (unlikely(!th_ctx->sched_call_date))
				th_ctx->sched_call_date = now_ns;
		}

		if (th_ctx->sched_wake_date) {
			t->wake_date = 0;
			profile_entry = sched_activity_entry(sched_activity, t->process, t->caller);
			th_ctx->sched_profile_entry = profile_entry;
			HA_ATOMIC_ADD(&profile_entry->lat_time, (uint32_t)(th_ctx->sched_call_date - th_ctx->sched_wake_date));
			HA_ATOMIC_INC(&profile_entry->calls);
		}

		__ha_barrier_store();

		th_ctx->current = t;
		_HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_STUCK); // this thread is still running

		_HA_ATOMIC_DEC(&th_ctx->rq_total);
		LIST_DEL_INIT(&((struct tasklet *)t)->list);
		__ha_barrier_store();

		if (t->state & TASK_F_TASKLET) {
			/* this is a tasklet */
			state = _HA_ATOMIC_FETCH_AND(&t->state, TASK_PERSISTENT);
			__ha_barrier_atomic_store();

			if (likely(!(state & TASK_KILLED))) {
				process(t, ctx, state);
			}
			else {
				done++;
				th_ctx->current = NULL;
				pool_free(pool_head_tasklet, t);
				__ha_barrier_store();
				continue;
			}
		} else {
			/* This is a regular task */

			/* We must be the exclusive owner of the TASK_RUNNING bit, and
			 * have to be careful that the task is not being manipulated on
			 * another thread finding it expired in wake_expired_tasks().
			 * The TASK_RUNNING bit will be set during these operations,
			 * they are extremely rare and do not last long so the best to
			 * do here is to wait.
			 */
			state = _HA_ATOMIC_LOAD(&t->state);
			do {
				while (unlikely(state & TASK_RUNNING)) {
					__ha_cpu_relax();
					state = _HA_ATOMIC_LOAD(&t->state);
				}
			} while (!_HA_ATOMIC_CAS(&t->state, &state, (state & TASK_PERSISTENT) | TASK_RUNNING));

			__ha_barrier_atomic_store();

			_HA_ATOMIC_DEC(&ha_thread_ctx[tid].tasks_in_list);

			/* Note for below: if TASK_KILLED arrived before we've read the state, we
			 * directly free the task. Otherwise it will be seen after processing and
			 * it's freed on the exit path.
			 */
			if (likely(!(state & TASK_KILLED) && process == process_stream))
				t = process_stream(t, ctx, state);
			else if (!(state & TASK_KILLED) && process != NULL)
				t = process(t, ctx, state);
			else {
				task_unlink_wq(t);
				__task_free(t);
				th_ctx->current = NULL;
				__ha_barrier_store();
				/* We don't want max_processed to be decremented if
				 * we're just freeing a destroyed task, we should only
				 * do so if we really ran a task.
				 */
				continue;
			}

			/* If there is a pending state  we have to wake up the task
			 * immediately, else we defer it into wait queue
			 */
			if (t != NULL) {
				state = _HA_ATOMIC_LOAD(&t->state);
				if (unlikely(state & TASK_KILLED)) {
					task_unlink_wq(t);
					__task_free(t);
				}
				else {
					task_queue(t);
					task_drop_running(t, 0);
				}
			}
		}

		th_ctx->current = NULL;
		__ha_barrier_store();

		/* stats are only registered for non-zero wake dates */
		if (unlikely(th_ctx->sched_wake_date))
			HA_ATOMIC_ADD(&profile_entry->cpu_time, (uint32_t)(now_mono_time() - th_ctx->sched_call_date));
		done++;
	}
	th_ctx->current_queue = -1;

	return done;
}

/* The run queue is chronologically sorted in a tree. An insertion counter is
 * used to assign a position to each task. This counter may be combined with
 * other variables (eg: nice value) to set the final position in the tree. The
 * counter may wrap without a problem, of course. We then limit the number of
 * tasks processed to 200 in any case, so that general latency remains low and
 * so that task positions have a chance to be considered. The function scans
 * both the global and local run queues and picks the most urgent task between
 * the two. We need to grab the global runqueue lock to touch it so it's taken
 * on the very first access to the global run queue and is released as soon as
 * it reaches the end.
 *
 * The function adjusts <next> if a new event is closer.
 */
void process_runnable_tasks()
{
	struct thread_ctx * const tt = th_ctx;
	struct eb32_node *lrq; // next local run queue entry
	struct eb32_node *grq; // next global run queue entry
	struct task *t;
	const unsigned int default_weights[TL_CLASSES] = {
		[TL_URGENT] = 64, // ~50% of CPU bandwidth for I/O
		[TL_NORMAL] = 48, // ~37% of CPU bandwidth for tasks
		[TL_BULK]   = 16, // ~13% of CPU bandwidth for self-wakers
		[TL_HEAVY]  = 1,  // never more than 1 heavy task at once
	};
	unsigned int max[TL_CLASSES]; // max to be run per class
	unsigned int max_total;       // sum of max above
	struct mt_list *tmp_list;
	unsigned int queue;
	int max_processed;
	int lpicked, gpicked;
	int heavy_queued = 0;
	int budget;

	_HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_STUCK); // this thread is still running

	if (!thread_has_tasks()) {
		activity[tid].empty_rq++;
		return;
	}

	max_processed = global.tune.runqueue_depth;

	if (likely(tg_ctx->niced_tasks))
		max_processed = (max_processed + 3) / 4;

	if (max_processed < th_ctx->rq_total && th_ctx->rq_total <= 2*max_processed) {
		/* If the run queue exceeds the budget by up to 50%, let's cut it
		 * into two identical halves to improve latency.
		 */
		max_processed = th_ctx->rq_total / 2;
	}

 not_done_yet:
	max[TL_URGENT] = max[TL_NORMAL] = max[TL_BULK] = 0;

	/* urgent tasklets list gets a default weight of ~50% */
	if ((tt->tl_class_mask & (1 << TL_URGENT)) ||
	    !MT_LIST_ISEMPTY(&tt->shared_tasklet_list))
		max[TL_URGENT] = default_weights[TL_URGENT];

	/* normal tasklets list gets a default weight of ~37% */
	if ((tt->tl_class_mask & (1 << TL_NORMAL)) ||
	    !eb_is_empty(&th_ctx->rqueue) || !eb_is_empty(&th_ctx->rqueue_shared))
		max[TL_NORMAL] = default_weights[TL_NORMAL];

	/* bulk tasklets list gets a default weight of ~13% */
	if ((tt->tl_class_mask & (1 << TL_BULK)))
		max[TL_BULK] = default_weights[TL_BULK];

	/* heavy tasks are processed only once and never refilled in a
	 * call round. That budget is not lost either as we don't reset
	 * it unless consumed.
	 */
	if (!heavy_queued) {
		if ((tt->tl_class_mask & (1 << TL_HEAVY)))
			max[TL_HEAVY] = default_weights[TL_HEAVY];
		else
			max[TL_HEAVY] = 0;
		heavy_queued = 1;
	}

	/* Now compute a fair share of the weights. Total may slightly exceed
	 * 100% due to rounding, this is not a problem. Note that while in
	 * theory the sum cannot be NULL as we cannot get there without tasklets
	 * to process, in practice it seldom happens when multiple writers
	 * conflict and rollback on MT_LIST_TRY_APPEND(shared_tasklet_list), causing
	 * a first MT_LIST_ISEMPTY() to succeed for thread_has_task() and the
	 * one above to finally fail. This is extremely rare and not a problem.
	 */
	max_total = max[TL_URGENT] + max[TL_NORMAL] + max[TL_BULK] + max[TL_HEAVY];
	if (!max_total)
		goto leave;

	for (queue = 0; queue < TL_CLASSES; queue++)
		max[queue]  = ((unsigned)max_processed * max[queue] + max_total - 1) / max_total;

	/* The heavy queue must never process more than very few tasks at once
	 * anyway. We set the limit to 1 if running on low_latency scheduling,
	 * given that we know that other values can have an impact on latency
	 * (~500us end-to-end connection achieved at 130kcps in SSL), 1 + one
	 * per 1024 tasks if there is at least one non-heavy task while still
	 * respecting the ratios above, or 1 + one per 128 tasks if only heavy
	 * tasks are present. This allows to drain excess SSL handshakes more
	 * efficiently if the queue becomes congested.
	 */
	if (max[TL_HEAVY] > 1) {
		if (global.tune.options & GTUNE_SCHED_LOW_LATENCY)
			budget = 1;
		else if (tt->tl_class_mask & ~(1 << TL_HEAVY))
			budget = 1 + tt->rq_total / 1024;
		else
			budget = 1 + tt->rq_total / 128;

		if (max[TL_HEAVY] > budget)
			max[TL_HEAVY] = budget;
	}

	lrq = grq = NULL;

	/* pick up to max[TL_NORMAL] regular tasks from prio-ordered run queues */
	/* Note: the grq lock is always held when grq is not null */
	lpicked = gpicked = 0;
	budget = max[TL_NORMAL] - tt->tasks_in_list;
	while (lpicked + gpicked < budget) {
		if (!eb_is_empty(&th_ctx->rqueue_shared) && !grq) {
#ifdef USE_THREAD
			HA_SPIN_LOCK(TASK_RQ_LOCK, &th_ctx->rqsh_lock);
			grq = eb32_lookup_ge(&th_ctx->rqueue_shared, _HA_ATOMIC_LOAD(&tt->rqueue_ticks) - TIMER_LOOK_BACK);
			if (unlikely(!grq)) {
				grq = eb32_first(&th_ctx->rqueue_shared);
				if (!grq)
					HA_SPIN_UNLOCK(TASK_RQ_LOCK, &th_ctx->rqsh_lock);
			}
#endif
		}

		/* If a global task is available for this thread, it's in grq
		 * now and the global RQ is locked.
		 */

		if (!lrq) {
			lrq = eb32_lookup_ge(&tt->rqueue, _HA_ATOMIC_LOAD(&tt->rqueue_ticks) - TIMER_LOOK_BACK);
			if (unlikely(!lrq))
				lrq = eb32_first(&tt->rqueue);
		}

		if (!lrq && !grq)
			break;

		if (likely(!grq || (lrq && (int)(lrq->key - grq->key) <= 0))) {
			t = eb32_entry(lrq, struct task, rq);
			lrq = eb32_next(lrq);
			eb32_delete(&t->rq);
			lpicked++;
		}
#ifdef USE_THREAD
		else {
			t = eb32_entry(grq, struct task, rq);
			grq = eb32_next(grq);
			eb32_delete(&t->rq);

			if (unlikely(!grq)) {
				grq = eb32_first(&th_ctx->rqueue_shared);
				if (!grq)
					HA_SPIN_UNLOCK(TASK_RQ_LOCK, &th_ctx->rqsh_lock);
			}
			gpicked++;
		}
#endif
		if (t->nice)
			_HA_ATOMIC_DEC(&tg_ctx->niced_tasks);

		/* Add it to the local task list */
		LIST_APPEND(&tt->tasklets[TL_NORMAL], &((struct tasklet *)t)->list);
	}

	/* release the rqueue lock */
	if (grq) {
		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &th_ctx->rqsh_lock);
		grq = NULL;
	}

	if (lpicked + gpicked) {
		tt->tl_class_mask |= 1 << TL_NORMAL;
		_HA_ATOMIC_ADD(&tt->tasks_in_list, lpicked + gpicked);
		activity[tid].tasksw += lpicked + gpicked;
	}

	/* Merge the list of tasklets waken up by other threads to the
	 * main list.
	 */
	tmp_list = MT_LIST_BEHEAD(&tt->shared_tasklet_list);
	if (tmp_list) {
		LIST_SPLICE_END_DETACHED(&tt->tasklets[TL_URGENT], (struct list *)tmp_list);
		if (!LIST_ISEMPTY(&tt->tasklets[TL_URGENT]))
			tt->tl_class_mask |= 1 << TL_URGENT;
	}

	/* execute tasklets in each queue */
	max_processed -= run_tasks_from_lists(max);

	/* some tasks may have woken other ones up */
	if (max_processed > 0 && thread_has_tasks())
		goto not_done_yet;

 leave:
	if (tt->tl_class_mask)
		activity[tid].long_rq++;
}

/*
 * Delete every tasks before running the master polling loop
 */
void mworker_cleantasks()
{
	struct task *t;
	int i;
	struct eb32_node *tmp_wq = NULL;
	struct eb32_node *tmp_rq = NULL;

#ifdef USE_THREAD
	/* cleanup the global run queue */
	tmp_rq = eb32_first(&th_ctx->rqueue_shared);
	while (tmp_rq) {
		t = eb32_entry(tmp_rq, struct task, rq);
		tmp_rq = eb32_next(tmp_rq);
		task_destroy(t);
	}
	/* cleanup the timers queue */
	tmp_wq = eb32_first(&tg_ctx->timers);
	while (tmp_wq) {
		t = eb32_entry(tmp_wq, struct task, wq);
		tmp_wq = eb32_next(tmp_wq);
		task_destroy(t);
	}
#endif
	/* clean the per thread run queue */
	for (i = 0; i < global.nbthread; i++) {
		tmp_rq = eb32_first(&ha_thread_ctx[i].rqueue);
		while (tmp_rq) {
			t = eb32_entry(tmp_rq, struct task, rq);
			tmp_rq = eb32_next(tmp_rq);
			task_destroy(t);
		}
		/* cleanup the per thread timers queue */
		tmp_wq = eb32_first(&ha_thread_ctx[i].timers);
		while (tmp_wq) {
			t = eb32_entry(tmp_wq, struct task, wq);
			tmp_wq = eb32_next(tmp_wq);
			task_destroy(t);
		}
	}
}

/* perform minimal initializations */
static void init_task()
{
	int i, q;

	for (i = 0; i < MAX_TGROUPS; i++)
		memset(&ha_tgroup_ctx[i].timers, 0, sizeof(ha_tgroup_ctx[i].timers));

	for (i = 0; i < MAX_THREADS; i++) {
		for (q = 0; q < TL_CLASSES; q++)
			LIST_INIT(&ha_thread_ctx[i].tasklets[q]);
		MT_LIST_INIT(&ha_thread_ctx[i].shared_tasklet_list);
	}
}

/* config parser for global "tune.sched.low-latency", accepts "on" or "off" */
static int cfg_parse_tune_sched_low_latency(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.options |= GTUNE_SCHED_LOW_LATENCY;
	else if (strcmp(args[1], "off") == 0)
		global.tune.options &= ~GTUNE_SCHED_LOW_LATENCY;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.sched.low-latency", cfg_parse_tune_sched_low_latency },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
INITCALL0(STG_PREPARE, init_task);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
