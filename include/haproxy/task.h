/*
 * include/haproxy/task.h
 * Functions for task management.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_TASK_H
#define _HAPROXY_TASK_H


#include <sys/time.h>

#include <import/eb32tree.h>

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/intops.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/task-t.h>
#include <haproxy/thread.h>
#include <haproxy/ticks.h>


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

/* tasklets are recognized with nice==-32768 */
#define TASK_IS_TASKLET(t) ((t)->state & TASK_F_TASKLET)

/* a few exported variables */
extern struct pool_head *pool_head_task;
extern struct pool_head *pool_head_tasklet;
extern struct pool_head *pool_head_notification;

__decl_thread(extern HA_RWLOCK_T wq_lock THREAD_ALIGNED(64));

void __tasklet_wakeup_on(struct tasklet *tl, int thr);
struct list *__tasklet_wakeup_after(struct list *head, struct tasklet *tl);
void task_kill(struct task *t);
void tasklet_kill(struct tasklet *t);
void __task_wakeup(struct task *t);
void __task_queue(struct task *task, struct eb_root *wq);

unsigned int run_tasks_from_lists(unsigned int budgets[]);

/*
 * This does 3 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - return the date of next event in <next> or eternity.
 */

void process_runnable_tasks(void);

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks.
 */
void wake_expired_tasks(void);

/* Checks the next timer for the current thread by looking into its own timer
 * list and the global one. It may return TICK_ETERNITY if no timer is present.
 * Note that the next timer might very well be slightly in the past.
 */
int next_timer_expiry(void);

/*
 * Delete every tasks before running the master polling loop
 */
void mworker_cleantasks(void);

/* returns the number of running tasks+tasklets on the whole process. Note
 * that this *is* racy since a task may move from the global to a local
 * queue for example and be counted twice. This is only for statistics
 * reporting.
 */
static inline int total_run_queues()
{
	int thr, ret = 0;

	for (thr = 0; thr < global.nbthread; thr++)
		ret += _HA_ATOMIC_LOAD(&ha_thread_ctx[thr].rq_total);
	return ret;
}

/* returns the number of allocated tasks across all threads. Note that this
 * *is* racy since some threads might be updating their counts while we're
 * looking, but this is only for statistics reporting.
 */
static inline int total_allocated_tasks()
{
	int thr, ret;

	for (thr = ret = 0; thr < global.nbthread; thr++)
		ret += _HA_ATOMIC_LOAD(&ha_thread_ctx[thr].nb_tasks);
	return ret;
}

/* returns the number of running niced tasks+tasklets on the whole process.
 * Note that this *is* racy since a task may move from the global to a local
 * queue for example and be counted twice. This is only for statistics
 * reporting.
 */
static inline int total_niced_running_tasks()
{
	int tgrp, ret = 0;

	for (tgrp = 0; tgrp < global.nbtgroups; tgrp++)
		ret += _HA_ATOMIC_LOAD(&ha_tgroup_ctx[tgrp].niced_tasks);
	return ret;
}

/* return 0 if task is in run queue, otherwise non-zero */
static inline int task_in_rq(struct task *t)
{
	/* Check if leaf_p is NULL, in case he's not in the runqueue, and if
	 * it's not 0x1, which would mean it's in the tasklet list.
	 */
	return t->rq.node.leaf_p != NULL;
}

/* return 0 if task is in wait queue, otherwise non-zero */
static inline int task_in_wq(struct task *t)
{
	return t->wq.node.leaf_p != NULL;
}

/* returns true if the current thread has some work to do */
static inline int thread_has_tasks(void)
{
	return ((int)!eb_is_empty(&th_ctx->rqueue) |
	        (int)!eb_is_empty(&th_ctx->rqueue_shared) |
	        (int)!!th_ctx->tl_class_mask |
		(int)!MT_LIST_ISEMPTY(&th_ctx->shared_tasklet_list));
}

/* returns the most recent known date of the task's call from the scheduler */
static inline uint64_t task_mono_time(void)
{
	return th_ctx->sched_call_date;
}

/* puts the task <t> in run queue with reason flags <f>, and returns <t> */
/* This will put the task in the local runqueue if the task is only runnable
 * by the current thread, in the global runqueue otherwies. With DEBUG_TASK,
 * the <file>:<line> from the call place are stored into the task for tracing
 * purposes.
 */
#define task_wakeup(t, f) \
	_task_wakeup(t, f, MK_CALLER(WAKEUP_TYPE_TASK_WAKEUP, 0, 0))

static inline void _task_wakeup(struct task *t, unsigned int f, const struct ha_caller *caller)
{
	unsigned int state;

	state = _HA_ATOMIC_OR_FETCH(&t->state, f);
	while (!(state & (TASK_RUNNING | TASK_QUEUED))) {
		if (_HA_ATOMIC_CAS(&t->state, &state, state | TASK_QUEUED)) {
			if (likely(caller)) {
				caller = HA_ATOMIC_XCHG(&t->caller, caller);
				BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
				HA_ATOMIC_STORE(&t->debug.prev_caller, caller);
#endif
			}
			__task_wakeup(t);
			break;
		}
	}
}

/* Atomically drop the TASK_RUNNING bit while ensuring that any wakeup that
 * happened since the flag was set will result in the task being queued (if
 * it wasn't already). This is used to safely drop the flag from within the
 * scheduler. The flag <f> is combined with existing flags before the test so
 * that it's possible to unconditionally wakeup the task and drop the RUNNING
 * flag if needed.
 */
static inline void task_drop_running(struct task *t, unsigned int f)
{
	unsigned int state, new_state;

	state = _HA_ATOMIC_LOAD(&t->state);

	while (1) {
		new_state = state | f;
		if (new_state & TASK_WOKEN_ANY)
			new_state |= TASK_QUEUED;

		if (_HA_ATOMIC_CAS(&t->state, &state, new_state & ~TASK_RUNNING))
			break;
		__ha_cpu_relax();
	}

	if ((new_state & ~state) & TASK_QUEUED)
		__task_wakeup(t);
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
	return t;
}

/* remove a task from its wait queue. It may either be the local wait queue if
 * the task is bound to a single thread or the global queue. If the task uses a
 * shared wait queue, the global wait queue lock is used.
 */
static inline struct task *task_unlink_wq(struct task *t)
{
	unsigned long locked;

	if (likely(task_in_wq(t))) {
		locked = t->tid < 0;
		BUG_ON(t->tid >= 0 && t->tid != tid && !(global.mode & MODE_STOPPING));
		if (locked)
			HA_RWLOCK_WRLOCK(TASK_WQ_LOCK, &wq_lock);
		__task_unlink_wq(t);
		if (locked)
			HA_RWLOCK_WRUNLOCK(TASK_WQ_LOCK, &wq_lock);
	}
	return t;
}

/* Place <task> into the wait queue, where it may already be. If the expiration
 * timer is infinite, do nothing and rely on wake_expired_task to clean up.
 * If the task uses a shared wait queue, it's queued into the global wait queue,
 * protected by the global wq_lock, otherwise by it necessarily belongs to the
 * current thread'sand is queued without locking.
 */
#define task_queue(t) \
	_task_queue(t, MK_CALLER(WAKEUP_TYPE_TASK_QUEUE, 0, 0))

static inline void _task_queue(struct task *task, const struct ha_caller *caller)
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

#ifdef USE_THREAD
	if (task->tid < 0) {
		HA_RWLOCK_WRLOCK(TASK_WQ_LOCK, &wq_lock);
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key)) {
			if (likely(caller)) {
				caller = HA_ATOMIC_XCHG(&task->caller, caller);
				BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
				HA_ATOMIC_STORE(&task->debug.prev_caller, caller);
#endif
			}
			__task_queue(task, &tg_ctx->timers);
		}
		HA_RWLOCK_WRUNLOCK(TASK_WQ_LOCK, &wq_lock);
	} else
#endif
	{
		BUG_ON(task->tid != tid);
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key)) {
			if (likely(caller)) {
				caller = HA_ATOMIC_XCHG(&task->caller, caller);
				BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
				HA_ATOMIC_STORE(&task->debug.prev_caller, caller);
#endif
			}
			__task_queue(task, &th_ctx->timers);
		}
	}
}

/* Change the thread affinity of a task to <thr>, which may either be a valid
 * thread number from 0 to nbthread-1, or a negative value to allow the task
 * to run on any thread.
 *
 * This may only be done from within the running task itself or during its
 * initialization. It will unqueue and requeue the task from the wait queue
 * if it was in it. This is safe against a concurrent task_queue() call because
 * task_queue() itself will unlink again if needed after taking into account
 * the new thread_mask.
 */
static inline void task_set_thread(struct task *t, int thr)
{
#ifndef USE_THREAD
	/* no shared queue without threads */
	thr = 0;
#endif
	if (unlikely(task_in_wq(t))) {
		task_unlink_wq(t);
		t->tid = thr;
		task_queue(t);
	}
	else {
		t->tid = thr;
	}
}

/* schedules tasklet <tl> to run onto thread <thr> or the current thread if
 * <thr> is negative. Note that it is illegal to wakeup a foreign tasklet if
 * its tid is negative and it is illegal to self-assign a tasklet that was
 * at least once scheduled on a specific thread. With DEBUG_TASK, the
 * <file>:<line> from the call place are stored into the tasklet for tracing
 * purposes.
 *
 * The macro accepts an optional 3rd argument that is passed as a set of flags
 * to be set on the tasklet, among TASK_WOKEN_*, TASK_F_UEVT* etc to indicate a
 * wakeup cause to the tasklet. When not set, the arg defaults to zero (i.e. no
 * flag is added).
 */
#define tasklet_wakeup_on(tl, thr, ...)					\
	_tasklet_wakeup_on(tl, thr, DEFVAL(TASK_WOKEN_OTHER, ##__VA_ARGS__), MK_CALLER(WAKEUP_TYPE_TASKLET_WAKEUP, 0, 0))

static inline void _tasklet_wakeup_on(struct tasklet *tl, int thr, uint f, const struct ha_caller *caller)
{
	unsigned int state = _HA_ATOMIC_OR_FETCH(&tl->state, f);

	do {
		/* do nothing if someone else already added it */
		if (state & TASK_IN_LIST)
			return;
	} while (!_HA_ATOMIC_CAS(&tl->state, &state, state | TASK_IN_LIST));

	/* at this point we're the first ones to add this task to the list */
	if (likely(caller)) {
		caller = HA_ATOMIC_XCHG(&tl->caller, caller);
		BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
		HA_ATOMIC_STORE(&tl->debug.prev_caller, caller);
#endif
	}

	if (_HA_ATOMIC_LOAD(&th_ctx->flags) & TH_FL_TASK_PROFILING)
		tl->wake_date = now_mono_time();
	__tasklet_wakeup_on(tl, thr);
}

/* schedules tasklet <tl> to run onto the thread designated by tl->tid, which
 * is either its owner thread if >= 0 or the current thread if < 0. When
 * DEBUG_TASK is set, the <file>:<line> from the call place are stored into the
 * task for tracing purposes.
 *
 * The macro accepts an optional 3rd argument that is passed as a set of flags
 * to be set on the tasklet, among TASK_WOKEN_*, TASK_F_UEVT* etc to indicate a
 * wakeup cause to the tasklet. When not set, the arg defaults to zero (i.e. no
 * flag is added).
 */
#define tasklet_wakeup(tl, ...)						\
	_tasklet_wakeup_on(tl, (tl)->tid, DEFVAL(TASK_WOKEN_OTHER, ##__VA_ARGS__), MK_CALLER(WAKEUP_TYPE_TASKLET_WAKEUP, 0, 0))

/* instantly wakes up task <t> on its owner thread even if it's not the current
 * one, bypassing the run queue. The purpose is to be able to avoid contention
 * in the global run queue for massively remote tasks (e.g. queue) when there's
 * no value in passing the task again through the priority ordering since it has
 * already been subject to it once (e.g. before entering process_stream). The
 * task goes directly into the shared mt_list as a tasklet and will run as
 * TL_URGENT. Great care is taken to be certain it's not queued nor running
 * already.
 */
#define task_instant_wakeup(t, f) \
	_task_instant_wakeup(t, f, MK_CALLER(WAKEUP_TYPE_TASK_INSTANT_WAKEUP, 0, 0))

static inline void _task_instant_wakeup(struct task *t, unsigned int f, const struct ha_caller *caller)
{
	int thr = t->tid;
	unsigned int state;

	if (thr < 0)
		thr = tid;

	/* first, let's update the task's state with the wakeup condition */
	state = _HA_ATOMIC_OR_FETCH(&t->state, f);

	/* next we need to make sure the task was not/will not be added to the
	 * run queue because the tasklet list's mt_list uses the same storage
	 * as the task's run_queue.
	 */
	do {
		/* do nothing if someone else already added it */
		if (state & (TASK_QUEUED|TASK_RUNNING))
			return;
	} while (!_HA_ATOMIC_CAS(&t->state, &state, state | TASK_QUEUED));

	BUG_ON_HOT(task_in_rq(t));

	/* at this point we're the first ones to add this task to the list */
	if (likely(caller)) {
		caller = HA_ATOMIC_XCHG(&t->caller, caller);
		BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
		HA_ATOMIC_STORE(&t->debug.prev_caller, caller);
#endif
	}

	if (_HA_ATOMIC_LOAD(&th_ctx->flags) & TH_FL_TASK_PROFILING)
		t->wake_date = now_mono_time();
	__tasklet_wakeup_on((struct tasklet *)t, thr);
}

/* schedules tasklet <tl> to run immediately after the current one is done
 * <tl> will be queued after entry <head>, or at the head of the task list. Return
 * the new head to be used to queue future tasks. This is used to insert multiple entries
 * at the head of the tasklet list, typically to transfer processing from a tasklet
 * to another one or a set of other ones. If <head> is NULL, the tasklet list of <thr>
 * thread will be used.
 * With DEBUG_TASK, the <file>:<line> from the call place are stored into the tasklet
 * for tracing purposes.
 *
 * The macro accepts an optional 3rd argument that is passed as a set of flags
 * to be set on the tasklet, among TASK_WOKEN_*, TASK_F_UEVT* etc to indicate a
 * wakeup cause to the tasklet. When not set, the arg defaults to
 * TASK_WOKEN_OTHER, so that tasklets can differentiate a unique explicit wakeup
 * cause from a wakeup cause combined with other implicit ones. I.e. that may be
 * used by muxes to decide whether or not to perform a short path for certain
 * operations, or a complete one that also covers regular I/O.
 */
#define tasklet_wakeup_after(head, tl, ...)					\
	_tasklet_wakeup_after(head, tl, DEFVAL(TASK_WOKEN_OTHER, ##__VA_ARGS__), MK_CALLER(WAKEUP_TYPE_TASKLET_WAKEUP_AFTER, 0, 0))

static inline struct list *_tasklet_wakeup_after(struct list *head, struct tasklet *tl,
                                                 uint f, const struct ha_caller *caller)
{
	unsigned int state = _HA_ATOMIC_OR_FETCH(&tl->state, f);

	do {
		/* do nothing if someone else already added it */
		if (state & TASK_IN_LIST)
			return head;
	} while (!_HA_ATOMIC_CAS(&tl->state, &state, state | TASK_IN_LIST));

	/* at this point we're the first one to add this task to the list */
	if (likely(caller)) {
		caller = HA_ATOMIC_XCHG(&tl->caller, caller);
		BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
		HA_ATOMIC_STORE(&tl->debug.prev_caller, caller);
#endif
	}

	if (th_ctx->flags & TH_FL_TASK_PROFILING)
		tl->wake_date = now_mono_time();
	return __tasklet_wakeup_after(head, tl);
}

/* This macro shows the current function name and the last known caller of the
 * task (or tasklet) wakeup.
 */
#ifdef DEBUG_TASK
#define DEBUG_TASK_PRINT_CALLER(t) do {						\
	const struct ha_caller *__caller = (t)->caller;			\
	printf("%s woken up from %s(%s:%d)\n", __FUNCTION__,		\
	       __caller ? __caller->func : NULL, \
	       __caller ? __caller->file : NULL, \
	       __caller ? __caller->line : 0); \
} while (0)
#else
#define DEBUG_TASK_PRINT_CALLER(t) do { } while (0)
#endif


/* Try to remove a tasklet from the list. This call is inherently racy and may
 * only be performed on the thread that was supposed to dequeue this tasklet.
 * This way it is safe to call MT_LIST_DELETE without first removing the
 * TASK_IN_LIST bit, which must absolutely be removed afterwards in case
 * another thread would want to wake this tasklet up in parallel.
 */
static inline void tasklet_remove_from_tasklet_list(struct tasklet *t)
{
	if (MT_LIST_DELETE(list_to_mt_list(&t->list))) {
		_HA_ATOMIC_AND(&t->state, ~TASK_IN_LIST);
		_HA_ATOMIC_DEC(&ha_thread_ctx[t->tid >= 0 ? t->tid : tid].rq_total);
	}
}

/*
 * Initialize a new task. The bare minimum is performed (queue pointers and
 * state).  The task is returned. This function should not be used outside of
 * task_new(). If the thread ID is < 0, the task may run on any thread.
 */
static inline struct task *task_init(struct task *t, int tid)
{
	t->wq.node.leaf_p = NULL;
	t->rq.node.leaf_p = NULL;
	t->state = TASK_SLEEPING;
#ifndef USE_THREAD
	/* no shared wq without threads */
	tid = 0;
#endif
	t->tid = tid;
	t->nice = 0;
	t->calls = 0;
	t->wake_date = 0;
	t->expire = TICK_ETERNITY;
	t->caller = NULL;
	return t;
}

/* Initialize a new tasklet. It's identified as a tasklet by its flags
 * TASK_F_TASKLET. It is expected to run on the calling thread by default,
 * it's up to the caller to change ->tid if it wants to own it.
 */
static inline void tasklet_init(struct tasklet *t)
{
	t->calls = 0;
	t->state = TASK_F_TASKLET;
	t->process = NULL;
	t->tid = -1;
	t->wake_date = 0;
	t->caller = NULL;
	LIST_INIT(&t->list);
}

/* Allocate and initialize a new tasklet, local to the thread by default. The
 * caller may assign its tid if it wants to own the tasklet.
 */
static inline struct tasklet *tasklet_new(void)
{
	struct tasklet *t = pool_alloc(pool_head_tasklet);

	if (t) {
		tasklet_init(t);
	}
	return t;
}

/*
 * Allocate and initialize a new task, to run on global thread <thr>, or any
 * thread if negative. The task count is incremented. The new task is returned,
 * or NULL in case of lack of memory. It's up to the caller to pass a valid
 * thread number (in tid space, 0 to nbthread-1, or <0 for any). Tasks created
 * this way must be freed using task_destroy().
 */
static inline struct task *task_new_on(int thr)
{
	struct task *t = pool_alloc(pool_head_task);
	if (t) {
		th_ctx->nb_tasks++;
		task_init(t, thr);
	}
	return t;
}

/* Allocate and initialize a new task, to run on the calling thread. The new
 * task is returned, or NULL in case of lack of memory. The task count is
 * incremented.
 */
static inline struct task *task_new_here()
{
	return task_new_on(tid);
}

/* Allocate and initialize a new task, to run on any thread. The new task is
 * returned, or NULL in case of lack of memory. The task count is incremented.
 */
static inline struct task *task_new_anywhere()
{
	return task_new_on(-1);
}

/*
 * Free a task. Its context must have been freed since it will be lost. The
 * task count is decremented. It it is the current task, this one is reset.
 */
static inline void __task_free(struct task *t)
{
	if (t == th_ctx->current) {
		th_ctx->current = NULL;
		__ha_barrier_store();
	}
	BUG_ON(task_in_wq(t) || task_in_rq(t));

	BUG_ON((ulong)t->caller & 1);
#ifdef DEBUG_TASK
	HA_ATOMIC_STORE(&t->debug.prev_caller, HA_ATOMIC_LOAD(&t->caller));
#endif
	HA_ATOMIC_STORE(&t->caller, (void*)1); // make sure to crash if used after free

	pool_free(pool_head_task, t);
	th_ctx->nb_tasks--;
	if (unlikely(stopping))
		pool_flush(pool_head_task);
}

/* Destroys a task : it's unlinked from the wait queues and is freed if it's
 * the current task or not queued otherwise it's marked to be freed by the
 * scheduler. It does nothing if <t> is NULL.
 */
static inline void task_destroy(struct task *t)
{
	if (!t)
		return;

	task_unlink_wq(t);
	/* We don't have to explicitly remove from the run queue.
	 * If we are in the runqueue, the test below will set t->process
	 * to NULL, and the task will be free'd when it'll be its turn
	 * to run.
	 */

	/* There's no need to protect t->state with a lock, as the task
	 * has to run on the current thread.
	 */
	if (t == th_ctx->current || !(t->state & (TASK_QUEUED | TASK_RUNNING)))
		__task_free(t);
	else
		t->process = NULL;
}

/* Should only be called by the thread responsible for the tasklet */
static inline void tasklet_free(struct tasklet *tl)
{
	if (!tl)
		return;

	if (MT_LIST_DELETE(list_to_mt_list(&tl->list)))
		_HA_ATOMIC_DEC(&ha_thread_ctx[tl->tid >= 0 ? tl->tid : tid].rq_total);

	BUG_ON((ulong)tl->caller & 1);
#ifdef DEBUG_TASK
	HA_ATOMIC_STORE(&tl->debug.prev_caller, HA_ATOMIC_LOAD(&tl->caller));
#endif
	HA_ATOMIC_STORE(&tl->caller, (void*)1); // make sure to crash if used after free
	pool_free(pool_head_tasklet, tl);
	if (unlikely(stopping))
		pool_flush(pool_head_tasklet);
}

static inline void tasklet_set_tid(struct tasklet *tl, int tid)
{
	tl->tid = tid;
}

/* Ensure <task> will be woken up at most at <when>. If the task is already in
 * the run queue (but not running), nothing is done. It may be used that way
 * with a delay :  task_schedule(task, tick_add(now_ms, delay));
 * It MUST NOT be used with a timer in the past, and even less with
 * TICK_ETERNITY (which would block all timers). Note that passing it directly
 * now_ms without using tick_add() will definitely make this happen once every
 * 49.7 days.
 */
#define task_schedule(t, w) \
	_task_schedule(t, w, MK_CALLER(WAKEUP_TYPE_TASK_SCHEDULE, 0, 0))

static inline void _task_schedule(struct task *task, int when, const struct ha_caller *caller)
{
	/* TODO: mthread, check if there is no tisk with this test */
	if (task_in_rq(task))
		return;

#ifdef USE_THREAD
	if (task->tid < 0) {
		/* FIXME: is it really needed to lock the WQ during the check ? */
		HA_RWLOCK_WRLOCK(TASK_WQ_LOCK, &wq_lock);
		if (task_in_wq(task))
			when = tick_first(when, task->expire);

		task->expire = when;
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key)) {
			if (likely(caller)) {
				caller = HA_ATOMIC_XCHG(&task->caller, caller);
				BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
				HA_ATOMIC_STORE(&task->debug.prev_caller, caller);
#endif
			}
			__task_queue(task, &tg_ctx->timers);
		}
		HA_RWLOCK_WRUNLOCK(TASK_WQ_LOCK, &wq_lock);
	} else
#endif
	{
		BUG_ON(task->tid != tid);
		if (task_in_wq(task))
			when = tick_first(when, task->expire);

		task->expire = when;
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key)) {
			if (likely(caller)) {
				caller = HA_ATOMIC_XCHG(&task->caller, caller);
				BUG_ON((ulong)caller & 1);
#ifdef DEBUG_TASK
				HA_ATOMIC_STORE(&task->debug.prev_caller, caller);
#endif
			}
			__task_queue(task, &th_ctx->timers);
		}
	}
}

/* returns the string corresponding to a task type as found in the task caller
 * locations.
 */
static inline const char *task_wakeup_type_str(uint t)
{
	switch (t) {
	case WAKEUP_TYPE_TASK_WAKEUP          : return "task_wakeup";
	case WAKEUP_TYPE_TASK_INSTANT_WAKEUP  : return "task_instant_wakeup";
	case WAKEUP_TYPE_TASKLET_WAKEUP       : return "tasklet_wakeup";
	case WAKEUP_TYPE_TASKLET_WAKEUP_AFTER : return "tasklet_wakeup_after";
	case WAKEUP_TYPE_TASK_QUEUE           : return "task_queue";
	case WAKEUP_TYPE_TASK_SCHEDULE        : return "task_schedule";
	case WAKEUP_TYPE_APPCTX_WAKEUP        : return "appctx_wakeup";
	default                               : return "?";
	}
}

/* This function register a new signal. "lua" is the current lua
 * execution context. It contains a pointer to the associated task.
 * "link" is a list head attached to an other task that must be wake
 * the lua task if an event occurs. This is useful with external
 * events like TCP I/O or sleep functions. This function allocate
 * memory for the signal.
 */
static inline struct notification *notification_new(struct list *purge, struct list *event, struct task *wakeup)
{
	struct notification *com = pool_alloc(pool_head_notification);
	if (!com)
		return NULL;
	LIST_APPEND(purge, &com->purge_me);
	LIST_APPEND(event, &com->wake_me);
	HA_SPIN_INIT(&com->lock);
	com->task = wakeup;
	return com;
}

/* This function purge all the pending signals when the LUA execution
 * is finished. This prevent than a coprocess try to wake a deleted
 * task. This function remove the memory associated to the signal.
 * The purge list is not locked because it is owned by only one
 * process. before browsing this list, the caller must ensure to be
 * the only one browser.
 */
static inline void notification_purge(struct list *purge)
{
	struct notification *com, *back;

	/* Delete all pending communication signals. */
	list_for_each_entry_safe(com, back, purge, purge_me) {
		HA_SPIN_LOCK(NOTIF_LOCK, &com->lock);
		LIST_DELETE(&com->purge_me);
		if (!com->task) {
			HA_SPIN_UNLOCK(NOTIF_LOCK, &com->lock);
			pool_free(pool_head_notification, com);
			continue;
		}
		com->task = NULL;
		HA_SPIN_UNLOCK(NOTIF_LOCK, &com->lock);
	}
}

/* In some cases, the disconnected notifications must be cleared.
 * This function just release memory blocks. The purge list is not
 * locked because it is owned by only one process. Before browsing
 * this list, the caller must ensure to be the only one browser.
 * The "com" is not locked because when com->task is NULL, the
 * notification is no longer used.
 */
static inline void notification_gc(struct list *purge)
{
	struct notification *com, *back;

	/* Delete all pending communication signals. */
	list_for_each_entry_safe (com, back, purge, purge_me) {
		if (com->task)
			continue;
		LIST_DELETE(&com->purge_me);
		pool_free(pool_head_notification, com);
	}
}

/* This function sends signals. It wakes all the tasks attached
 * to a list head, and remove the signal, and free the used
 * memory. The wake list is not locked because it is owned by
 * only one process. before browsing this list, the caller must
 * ensure to be the only one browser.
 */
static inline void notification_wake(struct list *wake)
{
	struct notification *com, *back;

	/* Wake task and delete all pending communication signals. */
	list_for_each_entry_safe(com, back, wake, wake_me) {
		HA_SPIN_LOCK(NOTIF_LOCK, &com->lock);
		LIST_DELETE(&com->wake_me);
		if (!com->task) {
			HA_SPIN_UNLOCK(NOTIF_LOCK, &com->lock);
			pool_free(pool_head_notification, com);
			continue;
		}
		task_wakeup(com->task, TASK_WOKEN_MSG);
		com->task = NULL;
		HA_SPIN_UNLOCK(NOTIF_LOCK, &com->lock);
	}
}

/* This function returns true is some notification are pending
 */
static inline int notification_registered(struct list *wake)
{
	return !LIST_ISEMPTY(wake);
}

#endif /* _HAPROXY_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
