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

#include <import/eb32sctree.h>
#include <import/eb32tree.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/fd.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

extern struct task *process_stream(struct task *t, void *context, unsigned int state);

DECLARE_POOL(pool_head_task,    "task",    sizeof(struct task));
DECLARE_POOL(pool_head_tasklet, "tasklet", sizeof(struct tasklet));

/* This is the memory pool containing all the signal structs. These
 * struct are used to store each required signal between two tasks.
 */
DECLARE_POOL(pool_head_notification, "notification", sizeof(struct notification));

volatile unsigned long global_tasks_mask = 0; /* Mask of threads with tasks in the global runqueue */
unsigned int niced_tasks = 0;      /* number of niced tasks in the run queue */

THREAD_LOCAL struct task_per_thread *sched = &task_per_thread[0]; /* scheduler context for the current thread */

__decl_aligned_spinlock(rq_lock); /* spin lock related to run queue */
__decl_aligned_rwlock(wq_lock);   /* RW lock related to the wait queue */

#ifdef USE_THREAD
struct eb_root timers;      /* sorted timers tree, global, accessed under wq_lock */
struct eb_root rqueue;      /* tree constituting the global run queue, accessed under rq_lock */
unsigned int grq_total;     /* total number of entries in the global run queue, atomic */
static unsigned int global_rqueue_ticks;  /* insertion count in the grq, use rq_lock */
#endif


struct task_per_thread task_per_thread[MAX_THREADS];


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
			thr = my_ffsl(t->thread_mask) - 1;

			/* Beware: tasks that have never run don't have their ->list empty yet! */
			MT_LIST_APPEND(&task_per_thread[thr].shared_tasklet_list,
			             (struct mt_list *)&((struct tasklet *)t)->list);
			_HA_ATOMIC_INC(&task_per_thread[thr].rq_total);
			_HA_ATOMIC_INC(&task_per_thread[thr].tasks_in_list);
			if (sleeping_thread_mask & (1UL << thr)) {
				_HA_ATOMIC_AND(&sleeping_thread_mask, ~(1UL << thr));
				wake_thread(thr);
			}
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
			LIST_APPEND(&sched->tasklets[TL_HEAVY], &tl->list);
			sched->tl_class_mask |= 1 << TL_HEAVY;
		}
		else if (tl->state & TASK_SELF_WAKING) {
			LIST_APPEND(&sched->tasklets[TL_BULK], &tl->list);
			sched->tl_class_mask |= 1 << TL_BULK;
		}
		else if ((struct task *)tl == sched->current) {
			_HA_ATOMIC_OR(&tl->state, TASK_SELF_WAKING);
			LIST_APPEND(&sched->tasklets[TL_BULK], &tl->list);
			sched->tl_class_mask |= 1 << TL_BULK;
		}
		else if (sched->current_queue < 0) {
			LIST_APPEND(&sched->tasklets[TL_URGENT], &tl->list);
			sched->tl_class_mask |= 1 << TL_URGENT;
		}
		else {
			LIST_APPEND(&sched->tasklets[sched->current_queue], &tl->list);
			sched->tl_class_mask |= 1 << sched->current_queue;
		}
		_HA_ATOMIC_INC(&sched->rq_total);
	} else {
		/* this tasklet runs on a specific thread. */
		MT_LIST_APPEND(&task_per_thread[thr].shared_tasklet_list, (struct mt_list *)&tl->list);
		_HA_ATOMIC_INC(&task_per_thread[thr].rq_total);
		if (sleeping_thread_mask & (1UL << thr)) {
			_HA_ATOMIC_AND(&sleeping_thread_mask, ~(1UL << thr));
			wake_thread(thr);
		}
	}
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
	struct eb_root *root = &sched->rqueue;

#ifdef USE_THREAD
	if (t->thread_mask != tid_bit && global.nbthread != 1) {
		root = &rqueue;

		_HA_ATOMIC_INC(&grq_total);
		HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);

		global_tasks_mask |= t->thread_mask;
		t->rq.key = ++global_rqueue_ticks;
		__ha_barrier_store();
	} else
#endif
	{
		_HA_ATOMIC_INC(&sched->rq_total);
		t->rq.key = ++sched->rqueue_ticks;
	}

	if (likely(t->nice)) {
		int offset;

		_HA_ATOMIC_INC(&niced_tasks);
		offset = t->nice * (int)global.tune.runqueue_depth;
		t->rq.key += offset;
	}

	if (task_profiling_mask & tid_bit)
		t->call_date = now_mono_time();

	eb32sc_insert(root, &t->rq, t->thread_mask);

#ifdef USE_THREAD
	if (root == &rqueue) {
		_HA_ATOMIC_OR(&t->state, TASK_GLOBAL);
		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);

		/* If all threads that are supposed to handle this task are sleeping,
		 * wake one.
		 */
		if ((((t->thread_mask & all_threads_mask) & sleeping_thread_mask) ==
		     (t->thread_mask & all_threads_mask))) {
			unsigned long m = (t->thread_mask & all_threads_mask) &~ tid_bit;

			m = (m & (m - 1)) ^ m; // keep lowest bit set
			_HA_ATOMIC_AND(&sleeping_thread_mask, ~m);
			wake_thread(my_ffsl(m) - 1);
		}
	}
#endif
	return;
}

/*
 * __task_queue()
 *
 * Inserts a task into wait queue <wq> at the position given by its expiration
 * date. It does not matter if the task was already in the wait queue or not,
 * as it will be unlinked. The task must not have an infinite expiration timer.
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
	BUG_ON((wq == &timers && !(task->state & TASK_SHARED_WQ)) ||
	       (wq == &sched->timers && (task->state & TASK_SHARED_WQ)) ||
	       (wq != &timers && wq != &sched->timers));
#endif

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
	struct task_per_thread * const tt = sched; // thread's tasks
	int max_processed = global.tune.runqueue_depth;
	struct task *task;
	struct eb32_node *eb;
	__decl_thread(int key);

	while (max_processed-- > 0) {
  lookup_next_local:
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
			task_wakeup(task, TASK_WOKEN_TIMER);
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
			/* task not expired and correctly placed */
			break;
		}
	}

#ifdef USE_THREAD
	if (eb_is_empty(&timers))
		goto leave;

	HA_RWLOCK_RDLOCK(TASK_WQ_LOCK, &wq_lock);
	eb = eb32_lookup_ge(&timers, now_ms - TIMER_LOOK_BACK);
	if (!eb) {
		eb = eb32_first(&timers);
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

		task = eb32_entry(eb, struct task, wq);
		if (tick_is_expired(task->expire, now_ms)) {
			/* expired task, wake it up */
			HA_RWLOCK_SKTOWR(TASK_WQ_LOCK, &wq_lock);
			__task_unlink_wq(task);
			HA_RWLOCK_WRTOSK(TASK_WQ_LOCK, &wq_lock);
			task_wakeup(task, TASK_WOKEN_TIMER);
		}
		else if (task->expire != eb->key) {
			/* task is not expired but its key doesn't match so let's
			 * update it and skip to next apparently expired task.
			 */
			HA_RWLOCK_SKTOWR(TASK_WQ_LOCK, &wq_lock);
			__task_unlink_wq(task);
			if (tick_isset(task->expire))
				__task_queue(task, &timers);
			HA_RWLOCK_WRTOSK(TASK_WQ_LOCK, &wq_lock);
			goto lookup_next;
		}
		else {
			/* task not expired and correctly placed */
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
	struct task_per_thread * const tt = sched; // thread's tasks
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
	if (!eb_is_empty(&timers)) {
		HA_RWLOCK_RDLOCK(TASK_WQ_LOCK, &wq_lock);
		eb = eb32_lookup_ge(&timers, now_ms - TIMER_LOOK_BACK);
		if (!eb)
			eb = eb32_first(&timers);
		if (eb)
			key = eb->key;
		HA_RWLOCK_RDUNLOCK(TASK_WQ_LOCK, &wq_lock);
		if (eb)
			ret = tick_first(ret, key);
	}
#endif
	return ret;
}

/* Walks over tasklet lists sched->tasklets[0..TL_CLASSES-1] and run at most
 * budget[TL_*] of them. Returns the number of entries effectively processed
 * (tasks and tasklets merged). The count of tasks in the list for the current
 * thread is adjusted.
 */
unsigned int run_tasks_from_lists(unsigned int budgets[])
{
	struct task *(*process)(struct task *t, void *ctx, unsigned int state);
	struct list *tl_queues = sched->tasklets;
	struct task *t;
	uint8_t budget_mask = (1 << TL_CLASSES) - 1;
	struct sched_activity *profile_entry = NULL;
	unsigned int done = 0;
	unsigned int queue;
	unsigned int state;
	void *ctx;

	for (queue = 0; queue < TL_CLASSES;) {
		sched->current_queue = queue;

		/* global.tune.sched.low-latency is set */
		if (global.tune.options & GTUNE_SCHED_LOW_LATENCY) {
			if (unlikely(sched->tl_class_mask & budget_mask & ((1 << queue) - 1))) {
				/* a lower queue index has tasks again and still has a
				 * budget to run them. Let's switch to it now.
				 */
				queue = (sched->tl_class_mask & 1) ? 0 :
					(sched->tl_class_mask & 2) ? 1 : 2;
				continue;
			}

			if (unlikely(queue > TL_URGENT &&
				     budget_mask & (1 << TL_URGENT) &&
				     !MT_LIST_ISEMPTY(&sched->shared_tasklet_list))) {
				/* an urgent tasklet arrived from another thread */
				break;
			}

			if (unlikely(queue > TL_NORMAL &&
				     budget_mask & (1 << TL_NORMAL) &&
				     (!eb_is_empty(&sched->rqueue) ||
				      (global_tasks_mask & tid_bit)))) {
				/* a task was woken up by a bulk tasklet or another thread */
				break;
			}
		}

		if (LIST_ISEMPTY(&tl_queues[queue])) {
			sched->tl_class_mask &= ~(1 << queue);
			queue++;
			continue;
		}

		if (!budgets[queue]) {
			budget_mask &= ~(1 << queue);
			queue++;
			continue;
		}

		budgets[queue]--;
		t = (struct task *)LIST_ELEM(tl_queues[queue].n, struct tasklet *, list);
		state = t->state & (TASK_SHARED_WQ|TASK_SELF_WAKING|TASK_HEAVY|TASK_F_TASKLET|TASK_KILLED|TASK_F_USR1);

		ti->flags &= ~TI_FL_STUCK; // this thread is still running
		activity[tid].ctxsw++;
		ctx = t->context;
		process = t->process;
		t->calls++;
		sched->current = t;

		_HA_ATOMIC_DEC(&sched->rq_total);

		if (state & TASK_F_TASKLET) {
			uint64_t before = 0;

			LIST_DEL_INIT(&((struct tasklet *)t)->list);
			__ha_barrier_store();

			if (unlikely(task_profiling_mask & tid_bit)) {
				profile_entry = sched_activity_entry(sched_activity, t->process);
				before = now_mono_time();
#ifdef DEBUG_TASK
				if (((struct tasklet *)t)->call_date) {
					HA_ATOMIC_ADD(&profile_entry->lat_time, before - ((struct tasklet *)t)->call_date);
					((struct tasklet *)t)->call_date = 0;
				}
#endif
			}

			state = _HA_ATOMIC_XCHG(&t->state, state);
			__ha_barrier_atomic_store();

			process(t, ctx, state);

			if (unlikely(task_profiling_mask & tid_bit)) {
				HA_ATOMIC_INC(&profile_entry->calls);
				HA_ATOMIC_ADD(&profile_entry->cpu_time, now_mono_time() - before);
			}

			done++;
			sched->current = NULL;
			__ha_barrier_store();
			continue;
		}

		LIST_DEL_INIT(&((struct tasklet *)t)->list);
		__ha_barrier_store();
		state = _HA_ATOMIC_XCHG(&t->state, state|TASK_RUNNING|TASK_F_USR1);
		__ha_barrier_atomic_store();

		/* OK then this is a regular task */

		_HA_ATOMIC_DEC(&task_per_thread[tid].tasks_in_list);
		if (unlikely(t->call_date)) {
			uint64_t now_ns = now_mono_time();
			uint64_t lat = now_ns - t->call_date;

			t->lat_time += lat;
			t->call_date = now_ns;
			profile_entry = sched_activity_entry(sched_activity, t->process);
			HA_ATOMIC_ADD(&profile_entry->lat_time, lat);
			HA_ATOMIC_INC(&profile_entry->calls);
		}

		__ha_barrier_store();

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
			sched->current = NULL;
			__ha_barrier_store();
			/* We don't want max_processed to be decremented if
			 * we're just freeing a destroyed task, we should only
			 * do so if we really ran a task.
			 */
			continue;
		}
		sched->current = NULL;
		__ha_barrier_store();
		/* If there is a pending state  we have to wake up the task
		 * immediately, else we defer it into wait queue
		 */
		if (t != NULL) {
			if (unlikely(t->call_date)) {
				uint64_t cpu = now_mono_time() - t->call_date;

				t->cpu_time += cpu;
				t->call_date = 0;
				HA_ATOMIC_ADD(&profile_entry->cpu_time, cpu);
			}

			state = _HA_ATOMIC_AND_FETCH(&t->state, ~TASK_RUNNING);
			if (unlikely(state & TASK_KILLED)) {
				task_unlink_wq(t);
				__task_free(t);
			}
			else if (state & TASK_WOKEN_ANY)
				task_wakeup(t, 0);
			else
				task_queue(t);
		}
		done++;
	}
	sched->current_queue = -1;

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
	struct task_per_thread * const tt = sched;
	struct eb32sc_node *lrq; // next local run queue entry
	struct eb32sc_node *grq; // next global run queue entry
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

	ti->flags &= ~TI_FL_STUCK; // this thread is still running

	if (!thread_has_tasks()) {
		activity[tid].empty_rq++;
		return;
	}

	max_processed = global.tune.runqueue_depth;

	if (likely(niced_tasks))
		max_processed = (max_processed + 3) / 4;

	if (max_processed < sched->rq_total && sched->rq_total <= 2*max_processed) {
		/* If the run queue exceeds the budget by up to 50%, let's cut it
		 * into two identical halves to improve latency.
		 */
		max_processed = sched->rq_total / 2;
	}

 not_done_yet:
	max[TL_URGENT] = max[TL_NORMAL] = max[TL_BULK] = 0;

	/* urgent tasklets list gets a default weight of ~50% */
	if ((tt->tl_class_mask & (1 << TL_URGENT)) ||
	    !MT_LIST_ISEMPTY(&tt->shared_tasklet_list))
		max[TL_URGENT] = default_weights[TL_URGENT];

	/* normal tasklets list gets a default weight of ~37% */
	if ((tt->tl_class_mask & (1 << TL_NORMAL)) ||
	    !eb_is_empty(&sched->rqueue) || (global_tasks_mask & tid_bit))
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
		return;

	for (queue = 0; queue < TL_CLASSES; queue++)
		max[queue]  = ((unsigned)max_processed * max[queue] + max_total - 1) / max_total;

	/* The heavy queue must never process more than one task at once
	 * anyway.
	 */
	if (max[TL_HEAVY] > 1)
		max[TL_HEAVY] = 1;

	lrq = grq = NULL;

	/* pick up to max[TL_NORMAL] regular tasks from prio-ordered run queues */
	/* Note: the grq lock is always held when grq is not null */
	lpicked = gpicked = 0;
	budget = max[TL_NORMAL] - tt->tasks_in_list;
	while (lpicked + gpicked < budget) {
		if ((global_tasks_mask & tid_bit) && !grq) {
#ifdef USE_THREAD
			HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);
			grq = eb32sc_lookup_ge(&rqueue, global_rqueue_ticks - TIMER_LOOK_BACK, tid_bit);
			if (unlikely(!grq)) {
				grq = eb32sc_first(&rqueue, tid_bit);
				if (!grq) {
					global_tasks_mask &= ~tid_bit;
					HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
				}
			}
#endif
		}

		/* If a global task is available for this thread, it's in grq
		 * now and the global RQ is locked.
		 */

		if (!lrq) {
			lrq = eb32sc_lookup_ge(&tt->rqueue, tt->rqueue_ticks - TIMER_LOOK_BACK, tid_bit);
			if (unlikely(!lrq))
				lrq = eb32sc_first(&tt->rqueue, tid_bit);
		}

		if (!lrq && !grq)
			break;

		if (likely(!grq || (lrq && (int)(lrq->key - grq->key) <= 0))) {
			t = eb32sc_entry(lrq, struct task, rq);
			lrq = eb32sc_next(lrq, tid_bit);
			eb32sc_delete(&t->rq);
			lpicked++;
		}
#ifdef USE_THREAD
		else {
			t = eb32sc_entry(grq, struct task, rq);
			grq = eb32sc_next(grq, tid_bit);
			_HA_ATOMIC_AND(&t->state, ~TASK_GLOBAL);
			eb32sc_delete(&t->rq);

			if (unlikely(!grq)) {
				grq = eb32sc_first(&rqueue, tid_bit);
				if (!grq) {
					global_tasks_mask &= ~tid_bit;
					HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
				}
			}
			gpicked++;
		}
#endif
		if (t->nice)
			_HA_ATOMIC_DEC(&niced_tasks);

		/* Add it to the local task list */
		LIST_APPEND(&tt->tasklets[TL_NORMAL], &((struct tasklet *)t)->list);
	}

	/* release the rqueue lock */
	if (grq) {
		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
		grq = NULL;
	}

	if (lpicked + gpicked) {
		tt->tl_class_mask |= 1 << TL_NORMAL;
		_HA_ATOMIC_ADD(&tt->tasks_in_list, lpicked + gpicked);
#ifdef USE_THREAD
		if (gpicked) {
			_HA_ATOMIC_SUB(&grq_total, gpicked);
			_HA_ATOMIC_ADD(&tt->rq_total, gpicked);
		}
#endif
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

	if (tt->tl_class_mask)
		activity[tid].long_rq++;
}

/* create a work list array for <nbthread> threads, using tasks made of
 * function <fct>. The context passed to the function will be the pointer to
 * the thread's work list, which will contain a copy of argument <arg>. The
 * wake up reason will be TASK_WOKEN_OTHER. The pointer to the work_list array
 * is returned on success, otherwise NULL on failure.
 */
struct work_list *work_list_create(int nbthread,
                                   struct task *(*fct)(struct task *, void *, unsigned int),
                                   void *arg)
{
	struct work_list *wl;
	int i;

	wl = calloc(nbthread, sizeof(*wl));
	if (!wl)
		goto fail;

	for (i = 0; i < nbthread; i++) {
		MT_LIST_INIT(&wl[i].head);
		wl[i].task = task_new(1UL << i);
		if (!wl[i].task)
			goto fail;
		wl[i].task->process = fct;
		wl[i].task->context = &wl[i];
		wl[i].arg = arg;
	}
	return wl;

 fail:
	work_list_destroy(wl, nbthread);
	return NULL;
}

/* destroy work list <work> */
void work_list_destroy(struct work_list *work, int nbthread)
{
	int t;

	if (!work)
		return;
	for (t = 0; t < nbthread; t++)
		task_destroy(work[t].task);
	free(work);
}

/*
 * Delete every tasks before running the master polling loop
 */
void mworker_cleantasks()
{
	struct task *t;
	int i;
	struct eb32_node *tmp_wq = NULL;
	struct eb32sc_node *tmp_rq = NULL;

#ifdef USE_THREAD
	/* cleanup the global run queue */
	tmp_rq = eb32sc_first(&rqueue, MAX_THREADS_MASK);
	while (tmp_rq) {
		t = eb32sc_entry(tmp_rq, struct task, rq);
		tmp_rq = eb32sc_next(tmp_rq, MAX_THREADS_MASK);
		task_destroy(t);
	}
	/* cleanup the timers queue */
	tmp_wq = eb32_first(&timers);
	while (tmp_wq) {
		t = eb32_entry(tmp_wq, struct task, wq);
		tmp_wq = eb32_next(tmp_wq);
		task_destroy(t);
	}
#endif
	/* clean the per thread run queue */
	for (i = 0; i < global.nbthread; i++) {
		tmp_rq = eb32sc_first(&task_per_thread[i].rqueue, MAX_THREADS_MASK);
		while (tmp_rq) {
			t = eb32sc_entry(tmp_rq, struct task, rq);
			tmp_rq = eb32sc_next(tmp_rq, MAX_THREADS_MASK);
			task_destroy(t);
		}
		/* cleanup the per thread timers queue */
		tmp_wq = eb32_first(&task_per_thread[i].timers);
		while (tmp_wq) {
			t = eb32_entry(tmp_wq, struct task, wq);
			tmp_wq = eb32_next(tmp_wq);
			task_destroy(t);
		}
	}
}

/* perform minimal intializations */
static void init_task()
{
	int i, q;

#ifdef USE_THREAD
	memset(&timers, 0, sizeof(timers));
	memset(&rqueue, 0, sizeof(rqueue));
#endif
	memset(&task_per_thread, 0, sizeof(task_per_thread));
	for (i = 0; i < MAX_THREADS; i++) {
		for (q = 0; q < TL_CLASSES; q++)
			LIST_INIT(&task_per_thread[i].tasklets[q]);
		MT_LIST_INIT(&task_per_thread[i].shared_tasklet_list);
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
