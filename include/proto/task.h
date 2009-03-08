/*
  include/proto/task.h
  Functions for task management.

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_TASK_H
#define _PROTO_TASK_H


#include <sys/time.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>

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
 * So we cut the time in 3 ranges, only one of which <now> can be. The base of
 * the range holding <now> serves as a reference for as long as <now> remains
 * in this range :
 *   - previous : those ones are expired by definition (all before <now>)
 *   - current  : some are expired, some are not (holds <now>)
 *   - next     : none are expired (all after <now>)
 *
 * We use the higher two bits of the timers expressed in ticks to determine
 * which range a timer is in, compared to <now> :
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
 * 49.3 days. This would eat more memory for very little added benefit though.
 *
 * Also, in order to maintain the ability to perform time comparisons, it is
 * preferable to avoid using the <next1> range above, as values in this range
 * may not easily be compared to <now> outside of these functions as it is the
 * opposite of the <current> range, and <timer>-<now> may randomly be positive
 * or negative. That means we're left with +/- 12.4 days timers.
 *
 * To keep timers ordered, we use 4 ebtrees [0..3]. We could have used instead
 * of ticks, (seconds*1024)+milliseconds, as well as 1024th of seconds, but
 * that makes comparisons with ticks more difficult, so in the end it's better
 * to stick to the ticks.
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
 *   - node->key <= timer
 *
 * The run queue works similarly to the wait queue except that the current date
 * is replaced by an insertion counter which can also wrap without any problem.
 */

/* the timers are stored as 32-bit values in the queues */
#define TIMER_TICK_BITS       32
#define TIMER_TREE_BITS        2
#define TIMER_TREES           (1 << TIMER_TREE_BITS)
#define TIMER_TREE_SHIFT      (TIMER_TICK_BITS - TIMER_TREE_BITS)
#define TIMER_TREE_MASK       (TIMER_TREES - 1)
#define TIMER_TICK_MASK       ((1U << (TIMER_TICK_BITS-1)) * 2 - 1)
#define TIMER_SIGN_BIT        (1 << (TIMER_TICK_BITS - 1))

/* a few exported variables */
extern unsigned int run_queue;    /* run queue size */
extern unsigned int niced_tasks;  /* number of niced tasks in the run queue */
extern struct pool_head *pool2_task;
extern struct task *last_timer;   /* optimization: last queued timer */

/* Convert ticks to timers. Must not be called with TICK_ETERNITY, which is not
 * a problem inside tree scanning functions. Note that ticks are signed while
 * timers are not.
 */
static inline unsigned int tick_to_timer(int tick)
{
	return tick & TIMER_TICK_MASK;
}

/* Convert timer to ticks. This operation will be correct only as long as
 * timers are stored on a minimum of 32-bit. We take care of not returning zero
 * which would mean "eternity" for a tick. Also note that ticks are signed and
 * timers are not.
 */
static inline int timer_to_tick(unsigned int timer)
{
	return timer ? timer : 1;
}

/* returns a tree number based on a ticks value */
static inline unsigned int timer_to_tree(unsigned int timer)
{
	return (timer >> TIMER_TREE_SHIFT) & TIMER_TREE_MASK;
}       

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
	if (last_timer == t)
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
 * Initialize a new task. The bare minimum is performed (queue pointers and state).
 * The task is returned.
 */
static inline struct task *task_init(struct task *t)
{
	t->wq.node.leaf_p = NULL;
	t->rq.node.leaf_p = NULL;
	t->state = TASK_SLEEPING;
	t->nice = 0;
	return t;
}

/*
 * frees a task. Its context must have been freed since it will be lost.
 */
static inline void task_free(struct task *t)
{
	pool_free2(pool2_task, t);
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

	if (((tick_to_timer(task->expire) - task->wq.key) & TIMER_SIGN_BIT)
		|| !task_in_wq(task))
		__task_queue(task);
}

/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - call maintain_proxies() to enable/disable the listeners
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
