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
#include <common/hathreads.h>

#include <eb32sctree.h>
#include <eb32tree.h>

#include <types/global.h>
#include <types/task.h>

#include <proto/fd.h>

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
extern volatile unsigned long global_tasks_mask; /* Mask of threads with tasks in the global runqueue */
extern unsigned int tasks_run_queue;    /* run queue size */
extern unsigned int tasks_run_queue_cur;
extern unsigned int nb_tasks_cur;
extern unsigned int niced_tasks;  /* number of niced tasks in the run queue */
extern struct pool_head *pool_head_task;
extern struct pool_head *pool_head_tasklet;
extern struct pool_head *pool_head_notification;
extern THREAD_LOCAL struct task_per_thread *sched; /* current's thread scheduler context */
#ifdef USE_THREAD
extern struct eb_root timers;      /* sorted timers tree, global */
extern struct eb_root rqueue;      /* tree constituting the run queue */
extern int global_rqueue_size; /* Number of element sin the global runqueue */
#endif

extern struct task_per_thread task_per_thread[MAX_THREADS];

__decl_hathreads(extern HA_SPINLOCK_T rq_lock);  /* spin lock related to run queue */
__decl_hathreads(extern HA_RWLOCK_T wq_lock);    /* RW lock related to the wait queue */


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

/* puts the task <t> in run queue with reason flags <f>, and returns <t> */
/* This will put the task in the local runqueue if the task is only runnable
 * by the current thread, in the global runqueue otherwies.
 */
void __task_wakeup(struct task *t, struct eb_root *);
static inline void task_wakeup(struct task *t, unsigned int f)
{
	unsigned short state;

#ifdef USE_THREAD
	struct eb_root *root;

	if (t->thread_mask == tid_bit || global.nbthread == 1)
		root = &sched->rqueue;
	else
		root = &rqueue;
#else
	struct eb_root *root = &sched->rqueue;
#endif

	state = _HA_ATOMIC_OR(&t->state, f);
	while (!(state & (TASK_RUNNING | TASK_QUEUED))) {
		if (_HA_ATOMIC_CAS(&t->state, &state, state | TASK_QUEUED)) {
			__task_wakeup(t, root);
			break;
		}
	}
}

/* change the thread affinity of a task to <thread_mask> */
static inline void task_set_affinity(struct task *t, unsigned long thread_mask)
{
	t->thread_mask = thread_mask;
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
 * the task is bound to a single thread (in which case there's no locking
 * involved) or the global queue, with locking.
 */
static inline struct task *task_unlink_wq(struct task *t)
{
	unsigned long locked;

	if (likely(task_in_wq(t))) {
		locked = atleast2(t->thread_mask);
		if (locked)
			HA_RWLOCK_WRLOCK(TASK_WQ_LOCK, &wq_lock);
		__task_unlink_wq(t);
		if (locked)
			HA_RWLOCK_WRUNLOCK(TASK_WQ_LOCK, &wq_lock);
	}
	return t;
}

/*
 * Unlink the task from the run queue. The tasks_run_queue size and number of
 * niced tasks are updated too. A pointer to the task itself is returned. The
 * task *must* already be in the run queue before calling this function. If
 * unsure, use the safer task_unlink_rq() function. Note that the pointer to the
 * next run queue entry is neither checked nor updated.
 */
static inline struct task *__task_unlink_rq(struct task *t)
{
	_HA_ATOMIC_SUB(&tasks_run_queue, 1);
#ifdef USE_THREAD
	if (t->state & TASK_GLOBAL) {
		_HA_ATOMIC_AND(&t->state, ~TASK_GLOBAL);
		global_rqueue_size--;
	} else
#endif
		sched->rqueue_size--;
	eb32sc_delete(&t->rq);
	if (likely(t->nice))
		_HA_ATOMIC_SUB(&niced_tasks, 1);
	return t;
}

/* This function unlinks task <t> from the run queue if it is in it. It also
 * takes care of updating the next run queue task if it was this task.
 */
static inline struct task *task_unlink_rq(struct task *t)
{
	int is_global = t->state & TASK_GLOBAL;

	if (is_global)
		HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);
	if (likely(task_in_rq(t)))
		__task_unlink_rq(t);
	if (is_global)
		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
	return t;
}

static inline void tasklet_wakeup(struct tasklet *tl)
{
	if (likely(tl->tid < 0)) {
		/* this tasklet runs on the caller thread */
		if (LIST_ISEMPTY(&tl->list)) {
			LIST_ADDQ(&task_per_thread[tid].task_list, &tl->list);
			_HA_ATOMIC_ADD(&tasks_run_queue, 1);
		}
	} else {
		/* this tasklet runs on a specific thread */
		if (MT_LIST_ADDQ(&task_per_thread[tl->tid].shared_tasklet_list, (struct mt_list *)&tl->list) == 1) {
			_HA_ATOMIC_ADD(&tasks_run_queue, 1);
			if (sleeping_thread_mask & (1UL << tl->tid)) {
				_HA_ATOMIC_AND(&sleeping_thread_mask, ~(1UL << tl->tid));
				wake_thread(tl->tid);
			}
		}
	}

}

/* Insert a tasklet into the tasklet list. If used with a plain task instead,
 * the caller must update the task_list_size.
 */
static inline void tasklet_insert_into_tasklet_list(struct tasklet *tl)
{
	_HA_ATOMIC_ADD(&tasks_run_queue, 1);
	LIST_ADDQ(&sched->task_list, &tl->list);
}

/* Remove the tasklet from the tasklet list. The tasklet MUST already be there.
 * If unsure, use tasklet_remove_from_tasklet_list() instead. If used with a
 * plain task, the caller must update the task_list_size.
 * This should only be used by the thread that owns the tasklet, any other
 * thread should use tasklet_cancel().
 */
static inline void __tasklet_remove_from_tasklet_list(struct tasklet *t)
{
	LIST_DEL_INIT(&t->list);
	_HA_ATOMIC_SUB(&tasks_run_queue, 1);
}

static inline void tasklet_remove_from_tasklet_list(struct tasklet *t)
{
	if (likely(!LIST_ISEMPTY(&t->list)))
		__tasklet_remove_from_tasklet_list(t);
}

/*
 * Initialize a new task. The bare minimum is performed (queue pointers and
 * state).  The task is returned. This function should not be used outside of
 * task_new().
 */
static inline struct task *task_init(struct task *t, unsigned long thread_mask)
{
	t->wq.node.leaf_p = NULL;
	t->rq.node.leaf_p = NULL;
	t->state = TASK_SLEEPING;
	t->thread_mask = thread_mask;
	t->nice = 0;
	t->calls = 0;
	t->call_date = 0;
	t->cpu_time = 0;
	t->lat_time = 0;
	t->expire = TICK_ETERNITY;
	return t;
}

/* Initialize a new tasklet. It's identified as a tasklet by ->nice=-32768. It
 * is expected to run on the calling thread by default, it's up to the caller
 * to change ->tid if it wants to own it.
 */
static inline void tasklet_init(struct tasklet *t)
{
	t->nice = -32768;
	t->calls = 0;
	t->state = 0;
	t->process = NULL;
	t->tid = -1;
	LIST_INIT(&t->list);
}

/* Allocate and initialize a new tasklet, local to the thread by default. The
 * caller may assing its tid if it wants to own the tasklet.
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
 * Allocate and initialise a new task. The new task is returned, or NULL in
 * case of lack of memory. The task count is incremented. Tasks should only
 * be allocated this way, and must be freed using task_free().
 */
static inline struct task *task_new(unsigned long thread_mask)
{
	struct task *t = pool_alloc(pool_head_task);
	if (t) {
		_HA_ATOMIC_ADD(&nb_tasks, 1);
		task_init(t, thread_mask);
	}
	return t;
}

/*
 * Free a task. Its context must have been freed since it will be lost. The
 * task count is decremented. It it is the current task, this one is reset.
 */
static inline void __task_free(struct task *t)
{
	if (t == sched->current) {
		sched->current = NULL;
		__ha_barrier_store();
	}
	pool_free(pool_head_task, t);
	if (unlikely(stopping))
		pool_flush(pool_head_task);
	_HA_ATOMIC_SUB(&nb_tasks, 1);
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
	/* We don't have to explicitely remove from the run queue.
	 * If we are in the runqueue, the test below will set t->process
	 * to NULL, and the task will be free'd when it'll be its turn
	 * to run.
	 */

	/* There's no need to protect t->state with a lock, as the task
	 * has to run on the current thread.
	 */
	if (t == sched->current || !(t->state & (TASK_QUEUED | TASK_RUNNING)))
		__task_free(t);
	else
		t->process = NULL;
}

/* Should only be called by the thread responsible for the tasklet */
static inline void tasklet_free(struct tasklet *tl)
{
	if (!LIST_ISEMPTY(&tl->list)) {
		LIST_DEL(&tl->list);
		_HA_ATOMIC_SUB(&tasks_run_queue, 1);
	}

	pool_free(pool_head_tasklet, tl);
	if (unlikely(stopping))
		pool_flush(pool_head_tasklet);
}

static inline void tasklet_set_tid(struct tasklet *tl, int tid)
{
	tl->tid = tid;
}

void __task_queue(struct task *task, struct eb_root *wq);

/* Place <task> into the wait queue, where it may already be. If the expiration
 * timer is infinite, do nothing and rely on wake_expired_task to clean up.
 * If the task is bound to a single thread, it's assumed to be bound to the
 * current thread's queue and is queued without locking. Otherwise it's queued
 * into the global wait queue, protected by locks.
 */
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

#ifdef USE_THREAD
	if (atleast2(task->thread_mask)) {
		HA_RWLOCK_WRLOCK(TASK_WQ_LOCK, &wq_lock);
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key))
			__task_queue(task, &timers);
		HA_RWLOCK_WRUNLOCK(TASK_WQ_LOCK, &wq_lock);
	} else
#endif
	{
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key))
			__task_queue(task, &sched->timers);
	}
}

/* Ensure <task> will be woken up at most at <when>. If the task is already in
 * the run queue (but not running), nothing is done. It may be used that way
 * with a delay :  task_schedule(task, tick_add(now_ms, delay));
 */
static inline void task_schedule(struct task *task, int when)
{
	/* TODO: mthread, check if there is no tisk with this test */
	if (task_in_rq(task))
		return;

#ifdef USE_THREAD
	if (atleast2(task->thread_mask)) {
		/* FIXME: is it really needed to lock the WQ during the check ? */
		HA_RWLOCK_WRLOCK(TASK_WQ_LOCK, &wq_lock);
		if (task_in_wq(task))
			when = tick_first(when, task->expire);

		task->expire = when;
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key))
			__task_queue(task, &timers);
		HA_RWLOCK_WRUNLOCK(TASK_WQ_LOCK, &wq_lock);
	} else
#endif
	{
		if (task_in_wq(task))
			when = tick_first(when, task->expire);

		task->expire = when;
		if (!task_in_wq(task) || tick_is_lt(task->expire, task->wq.key))
			__task_queue(task, &sched->timers);
	}
}

/* This function register a new signal. "lua" is the current lua
 * execution context. It contains a pointer to the associated task.
 * "link" is a list head attached to an other task that must be wake
 * the lua task if an event occurs. This is useful with external
 * events like TCP I/O or sleep functions. This funcion allocate
 * memory for the signal.
 */
static inline struct notification *notification_new(struct list *purge, struct list *event, struct task *wakeup)
{
	struct notification *com = pool_alloc(pool_head_notification);
	if (!com)
		return NULL;
	LIST_ADDQ(purge, &com->purge_me);
	LIST_ADDQ(event, &com->wake_me);
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
		LIST_DEL(&com->purge_me);
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
 * This function just release memory blocs. The purge list is not
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
		LIST_DEL(&com->purge_me);
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
		LIST_DEL(&com->wake_me);
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

static inline int thread_has_tasks(void)
{
	return (!!(global_tasks_mask & tid_bit) |
	        (sched->rqueue_size > 0) |
	        !LIST_ISEMPTY(&sched->task_list) | !MT_LIST_ISEMPTY(&sched->shared_tasklet_list));
}

/* adds list item <item> to work list <work> and wake up the associated task */
static inline void work_list_add(struct work_list *work, struct mt_list *item)
{
	MT_LIST_ADDQ(&work->head, item);
	task_wakeup(work->task, TASK_WOKEN_OTHER);
}

struct work_list *work_list_create(int nbthread,
                                   struct task *(*fct)(struct task *, void *, unsigned short),
                                   void *arg);

void work_list_destroy(struct work_list *work, int nbthread);

/*
 * This does 3 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - return the date of next event in <next> or eternity.
 */

void process_runnable_tasks();

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 */
int wake_expired_tasks();

/*
 * Delete every tasks before running the master polling loop
 */
void mworker_cleantasks();

#endif /* _PROTO_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
