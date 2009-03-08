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
#include <proto/task.h>

struct pool_head *pool2_task;

unsigned int run_queue = 0;
unsigned int niced_tasks = 0; /* number of niced tasks in the run queue */
struct task *last_timer = NULL;  /* optimization: last queued timer */

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
 *
 * Another nice optimisation is to allow a timer to stay at an old place in the
 * queue as long as it's not further than the real expected timeout. We really
 * use the tree as a place holder for a minorant of the real expiration date.
 * Since we have very low chance of hitting a timeout anyway, we can bounce the
 * nodes to their right place when we scan the tree and encounter a misplaced
 * node once in a while. This even allows us not to remove the infinite timers.
 *
 * So, to summarize, we have :
 *   - node->key always defines current position in the tree
 *   - timer is the real expiration date (possibly infinite)
 *   - node->key <= timer
 */

#define TIMER_TICK_BITS       32
#define TIMER_TREE_BITS        2
#define TIMER_TREES           (1 << TIMER_TREE_BITS)
#define TIMER_TREE_SHIFT      (TIMER_TICK_BITS - TIMER_TREE_BITS)
#define TIMER_TREE_MASK       (TIMER_TREES - 1)
#define TIMER_TICK_MASK       ((1U << (TIMER_TICK_BITS-1)) * 2 - 1)
#define TIMER_SIGN_BIT        (1 << (TIMER_TICK_BITS - 1))

static struct eb_root timers[TIMER_TREES];  /* trees with MSB 00, 01, 10 and 11 */
static struct eb_root rqueue[TIMER_TREES];  /* trees constituting the run queue */
static unsigned int rqueue_ticks;           /* insertion count */

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

	eb32_insert(&rqueue[ticks_to_tree(t->rq.key)], &t->rq);
	return t;
}

/*
 * task_queue()
 *
 * Inserts a task into the wait queue at the position given by its expiration
 * date. It does not matter if the task was already in the wait queue or not,
 * and it may even help if its position has not changed because we'll be able
 * to return without doing anything. Tasks queued with an eternity expiration
 * are just unlinked from the WQ. Last, tasks must not be queued further than
 * the end of the next tree, which is between <now_ms> and <now_ms> +
 * TIMER_SIGN_BIT ms (now+12days..24days in 32bit).
 */
void task_queue(struct task *task)
{
	/* if the task is already in the wait queue, we may reuse its position
	 * or we will at least have to unlink it first.
	 */
	if (task_in_wq(task)) {
		/* If we already have a place in the wait queue no later than the
		 * timeout we're trying to set, we'll stay there, because it is very
		 * unlikely that we will reach the timeout anyway. If the timeout
		 * has been disabled, it's useless to leave the queue as well. We'll
		 * rely on wake_expired_tasks() to catch the node and move it to the
		 * proper place should it ever happen.
		 */
		if (!task->expire || ((task->wq.key - task->expire) & TIMER_SIGN_BIT))
			return;
		__task_unlink_wq(task);
	}

	/* the task is not in the queue now */
	if (unlikely(!task->expire))
		return;

	task->wq.key = task->expire;
#ifdef DEBUG_CHECK_INVALID_EXPIRATION_DATES
	if ((task->wq.key - now_ms) & TIMER_SIGN_BIT)
		/* we're queuing too far away or in the past (most likely) */
		return;
#endif

	if (likely(last_timer &&
		   last_timer->wq.key == task->wq.key &&
		   last_timer->wq.node.node_p &&
		   last_timer->wq.node.bit == -1)) {
		/* Most often, last queued timer has the same expiration date, so
		 * if it's not queued at the root, let's queue a dup directly there.
		 * Note that we can only use dups at the dup tree's root (bit==-1).
		 */
		eb_insert_dup(&last_timer->wq.node, &task->wq.node);
		return;
	}
	eb32_insert(&timers[ticks_to_tree(task->wq.key)], &task->wq);
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

	now_tree = ticks_to_tree(now_ms);
	tree = (now_tree - 1) & TIMER_TREE_MASK;
	do {
		eb = eb32_first(&timers[tree]);
		while (eb) {
			task = eb32_entry(eb, struct task, wq);
			if ((now_ms - eb->key) & TIMER_SIGN_BIT) {
				/* note that we don't need this check for the <previous>
				 * tree, but it's cheaper than duplicating the code.
				 */
				*next = eb->key;  /* when we want to revisit the tree */
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

	tree = ticks_to_tree(rqueue_ticks);
	stop = (tree + TIMER_TREES / 2) & TIMER_TREE_MASK;
	tree = (tree - 1) & TIMER_TREE_MASK;

	expire = *next;
	do {
		eb = eb32_first(&rqueue[tree]);
		while (eb) {
			t = eb32_entry(eb, struct task, rq);

			/* detach the task from the queue and add the task to the run queue */
			eb = eb32_next(eb);
			__task_unlink_rq(t);

			t->state |= TASK_RUNNING;
			if (likely(t->process(t) != NULL)) {
				t->state &= ~TASK_RUNNING;
				expire = tick_first(expire, t->expire);
				task_queue(t);
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
