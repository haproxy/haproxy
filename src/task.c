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

/* Principle of the wait queue : we have two trees ordered by time. On of them
 * contains all timers for current time-frame, and the other one for next
 * time-frame. Each time-frame is TIMER_KEY_BITS bits wide in number of
 * milliseconds, which is 49 days for 32 bits. Values are stored into and
 * retrieved from the tree using a key of TIMER_KEY_BITS bits. A pointer
 * always designates the current tree, which is the one we read from, until
 * it is exhausted and <now> has its high bit designate the new tree.
 * An improvement would consist in holding too large timers in a side tree
 * consulted only once a switch. It could also be a simple list BTW.
 */
#define TIMER_KEY_BITS        32
#define TIMER_SUBSEC_BITS     10
#define TIMER_SECOND_BITS     (TIMER_KEY_BITS - TIMER_SUBSEC_BITS)

static struct {
	struct eb_root *curr; /* current time frame (t[0],t[1]) */
	struct eb_root t[2];  /* trees with MSB 0 and 1 */
	struct timeval first; /* first value in the tree when known */
} timers;

/* returns an ordered key based on an expiration date. */
static inline unsigned int timeval_to_key(const struct timeval *t)
{
	unsigned int key;

	/* We choose sec << 10 + usec / 1000 below to keep the precision at the
	 * millisecond, but we might as well divide by 1024 and have a slightly
	 * lower precision of 1.024 ms.
	 */

	key   = ((unsigned int)t->tv_sec << TIMER_SUBSEC_BITS) +
		((unsigned int)t->tv_usec / 1000);

#if TIMER_KEY_BITS != 32
	key  &= (1 << TIMER_KEY_BITS) - 1;
#endif
	return key;
}       

/* returns a tree number based on an expiration date. */
static inline unsigned int timeval_to_tree(const struct timeval *t)
{
	return (t->tv_sec >> TIMER_SECOND_BITS) & 1;
}       

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_task()
{
	memset(&timers, 0, sizeof(timers));

	/* note: we never queue in the past, so we start with <now> */
	timers.curr = &timers.t[timeval_to_tree(&now)];

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
 * further than the end of the next tree, which is between now and
 * now+1<<TIMER_KEY_BITS ms (now+49days in 32bit).
 */
struct task *task_queue(struct task *task)
{
	struct eb_root *tmp;
	unsigned int key;

	if (unlikely(tv_iseternity(&task->expire)))
		return task;

	if (tv_islt(&task->expire, &timers.first))
		timers.first = task->expire;

	key = timeval_to_key(&task->expire);
	tmp = &timers.t[timeval_to_tree(&task->expire)];
	eb32_insert(tmp, &task->eb);
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
	unsigned int now_key;
	unsigned int now_tree;


	now_tree = timeval_to_tree(&now);

	/* This is a speedup: we immediately check for an expirable task in the
	 * timer's index. Warning: if nothing is found, we still may have to
	 * switch the trees.
	 */
	if (likely(tv_isgt(&timers.first, &now))) {
		*next = timers.first;
		if (timers.curr != &timers.t[now_tree])
			timers.curr = &timers.t[now_tree];
		return;
	}

	now_key = timeval_to_key(&now);
	do {
		eb = eb32_first(timers.curr);
		while (eb) {
			struct eb32_node *next_eb;

			task = eb32_entry(eb, struct task, eb);
			if ((signed)(eb->key - now_key) > 0) {
				*next = task->expire;
				timers.first = task->expire;
				return;
			}

			/* detach the task from the queue */
			next_eb = eb32_next(eb);
			eb32_delete(eb);
			eb = next_eb;

			/* and add the task to the run queue */
			DLIST_ADD(run_queue, &task->qlist);
			task->state = TASK_RUNNING;
		}

		/* OK we have reached the end of the <curr> tree. It might mean
		 * that we must now switch, which is indicated by the fact that
		 * the current tree pointer does not match <now> anymore.
		 */
		if (timers.curr == &timers.t[now_tree]) {
			/* We cannot switch now, so we have to find the first
			 * timer of the next tree.
			 */
			eb = eb32_first(&timers.t[now_tree ^ 1]);
			if (eb) {
				task = eb32_entry(eb, struct task, eb);
				*next = task->expire;
				timers.first = task->expire;
			} else {
				tv_eternity(next);
				tv_eternity(&timers.first);
			}
			return;
		}
		timers.curr = &timers.t[now_tree];
	} while (1);
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
