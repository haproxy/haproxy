/*
 * Task management functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
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
#include <proto/task.h>
#include <types/task.h>

struct pool_head *pool2_task;

void *run_queue = NULL;

/* Principle of the wait queue.
 *
 * We want to be able to tell whether an expiration date is before of after the
 * current time <now>. We KNOW that expiration dates are never too far apart,
 * because they are already computed by adding integer numbers of milliseconds
 * to the current date.
 * We also know that almost all dates will be in the future, and that a very
 * small part of them will be in the past, they are the ones which have expired
 * since last time we checked them.
 *
 * The current implementation uses a wrapping time cut into 3 ranges :
 *   - previous : those ones are expired by definition
 *   - current  : some are expired, some are not
 *   - next     : none are expired
 *
 * We use the higher two bits of the timers expressed in ticks (milliseconds)
 * to determine which range a timer is in, compared to <now> :
 *
 *   now     previous     current      next0     next1
 * [31:30]   [31:30]      [31:30]     [31:30]   [31:30]
 *    00        11           00          01        10
 *    01        00           01          10        11
 *    10        01           10          11        00
 *    11        10           11          00        01
 *
 * By definition, <current> is the range containing <now> as well as all timers
 * which have the same 2 high bits as <now>, <previous> is the range just
 * before, which contains all timers whose high bits equal those of <now> minus
 * 1. Last, <next> is composed of the two remaining ranges.
 *
 * For ease of implementation, the timers will then be stored into 4 queues 0-3
 * determined by the 2 higher bits of the timer. The expiration algorithm is
 * very simple :
 *  - expire everything in <previous>=queue[((now>>30)-1)&3]
 *  - expire from <current>=queue[(now>>30)&3] everything where timer >= now
 *
 * With this algorithm, it's possible to queue tasks meant to expire 24.8 days
 * in the future, and still be able to detect events remaining unprocessed for
 * the last 12.4 days! Note that the principle might be extended to any number
 * of higher bits as long as there is only one range for expired tasks. For
 * instance, using the 8 higher bits to index the range, we would have one past
 * range of 4.6 hours (24 bits in ms), and 254 ranges in the future totalizing
 * 49.3 days. This would eat more memory for a very little added benefit.
 *
 * Also, in order to maintain the ability to perform time comparisons, it is
 * recommended to avoid using the <next1> range above, as values in this range
 * may not easily be compared to <now> outside of these functions as it is the
 * opposite of the <current> range, and <timer>-<now> may randomly be positive
 * or negative. That means we're left with +/- 12 days timers.
 *
 * To keep timers ordered, we use 4 ebtrees [0..3]. To keep computation low, we
 * may use (seconds*1024)+milliseconds, which preserves ordering eventhough we
 * can't do real computations on it. Future evolutions could make use of 1024th
 * of seconds instead of milliseconds, with the special value 0 avoided (and
 * replaced with 1), so that zero indicates the timer is not set.
 */

#define TIMER_TICK_BITS       32
#define TIMER_TREE_BITS        2
#define TIMER_TREES           (1 << TIMER_TREE_BITS)
#define TIMER_TREE_SHIFT      (TIMER_TICK_BITS - TIMER_TREE_BITS)
#define TIMER_TREE_MASK       (TIMER_TREES - 1)
#define TIMER_TICK_MASK       ((1U << (TIMER_TICK_BITS-1)) * 2 - 1)
#define TIMER_SIGN_BIT        (1 << (TIMER_TICK_BITS - 1))

static struct eb_root timers[TIMER_TREES];  /* trees with MSB 00, 01, 10 and 11 */

/* returns an ordered key based on an expiration date. */
static inline unsigned int timeval_to_ticks(const struct timeval *t)
{
	unsigned int key;

	key  = ((unsigned int)t->tv_sec  * 1000) + ((unsigned int)t->tv_usec / 1000);
	key &= TIMER_TICK_MASK;
	return key;
}       

/* returns a tree number based on a ticks value */
static inline unsigned int ticks_to_tree(unsigned int ticks)
{
	return (ticks >> TIMER_TREE_SHIFT) & TIMER_TREE_MASK;
}       

/* returns a tree number based on an expiration date. */
static inline unsigned int timeval_to_tree(const struct timeval *t)
{
	return ticks_to_tree(timeval_to_ticks(t));
}       

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_task()
{
	memset(&timers, 0, sizeof(timers));
	pool2_task = create_pool("task", sizeof(struct task), MEM_F_SHARED);
	return pool2_task != NULL;
}

struct task *_task_wakeup(struct task *t)
{
	return __task_wakeup(t);
}

/*
 * task_queue()
 *
 * Inserts a task into the wait queue at the position given by its expiration
 * date. Note that the task must *not* already be in the wait queue nor in the
 * run queue, otherwise unpredictable results may happen. Tasks queued with an
 * eternity expiration date are simply returned. Last, tasks must not be queued
 * further than the end of the next tree, which is between <now_ms> and
 * <now_ms> + TIMER_SIGN_BIT ms (now+12days..24days in 32bit).
 */
struct task *task_queue(struct task *task)
{
	if (unlikely(tv_iseternity(&task->expire)))
		return task;

	task->eb.key = timeval_to_ticks(&task->expire);
#ifdef DEBUG_CHECK_INVALID_EXPIRATION_DATES
	if ((task->eb.key - now_ms) & TIMER_SIGN_BIT)
		/* we're queuing too far away or in the past (most likely) */
		return task;
#endif
	eb32_insert(&timers[ticks_to_tree(task->eb.key)], &task->eb);
	return task;
}


/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 *
 */
void wake_expired_tasks(struct timeval *next)
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

	now_tree = ticks_to_tree(now_ms);
	tree = (now_tree - 1) & TIMER_TREE_MASK;
	do {
		eb = eb32_first(&timers[tree]);
		while (eb) {
			task = eb32_entry(eb, struct task, eb);
			if ((now_ms - eb->key) & TIMER_SIGN_BIT) {
				/* note that we don't need this check for the <previous>
				 * tree, but it's cheaper than duplicating the code.
				 */
				*next = task->expire;
				return;
			}

			/* detach the task from the queue and add the task to the run queue */
			eb = eb32_next(eb);
			_task_wakeup(task);
		}
		tree = (tree + 1) & TIMER_TREE_MASK;
	} while (((tree - now_tree) & TIMER_TREE_MASK) < TIMER_TREES/2);

	/* We have found no task to expire in any tree */
	tv_eternity(next);
	return;
}

/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - call maintain_proxies() to enable/disable the listeners
 *   - return the date of next event in <next> or eternity.
 *
 */
void process_runnable_tasks(struct timeval *next)
{
	struct timeval temp;
	struct task *t;
	void *queue;

	wake_expired_tasks(next);
	/* process each task in the run queue now. Each task may be deleted
	 * since we only use the run queue's head. Note that any task can be
	 * woken up by any other task and it will be processed immediately
	 * after as it will be queued on the run queue's head !
	 */

	queue = run_queue;
	foreach_dlist_item(t, queue, struct task *, qlist) {
		DLIST_DEL(&t->qlist);
		t->qlist.p = NULL;

		t->state = TASK_IDLE;
		t->process(t, &temp);
		tv_bound(next, &temp);
	}

	/* maintain all proxies in a consistent state. This should quickly
	 * become a task because it becomes expensive when there are huge
	 * numbers of proxies. */
	maintain_proxies(&temp);
	tv_bound(next, &temp);
	return;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
