/*
 * Task management functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <proto/proxy.h>
#include <proto/task.h>
#include <types/task.h>

// FIXME: check 8bitops.c for faster FLS
#include <import/bitops.h>
#include <import/tree.h>

static struct ultree *stack[LLONGBITS];

struct pool_head *pool2_task, *pool2_tree64;

UL2TREE_HEAD(timer_wq);
void *eternity_queue = NULL;
void *run_queue = NULL;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_task()
{
	pool2_task = create_pool("task", sizeof(struct task), MEM_F_SHARED);
	pool2_tree64 = create_pool("tree64", sizeof(struct tree64), MEM_F_SHARED);
	return pool2_task && pool2_tree64;
}

struct ultree *ul2tree_insert(struct ultree *root, unsigned long h, unsigned long l)
{
	return __ul2tree_insert(root, h, l);
}

void *tree_delete(void *node) {
    return __tree_delete(node);
}

struct task *_task_wakeup(struct task *t)
{
	return __task_wakeup(t);
}

/*
 * task_queue()
 *
 * Inserts a task into the wait queue at the position given by its expiration
 * date.
 *
 */
struct task *task_queue(struct task *task)
{
	if (unlikely(task->qlist.p != NULL)) {
		DLIST_DEL(&task->qlist);
		task->qlist.p = NULL;
	}

	if (unlikely(task->wq)) {
		tree_delete(task->wq);
		task->wq = NULL;
	}

	if (unlikely(tv_iseternity(&task->expire))) {
		task->wq = NULL;
		DLIST_ADD(eternity_queue, &task->qlist);
		return task;
	}

	task->wq = ul2tree_insert(&timer_wq, task->expire.tv_sec, task->expire.tv_usec);
	DLIST_ADD(task->wq->data, &task->qlist);
	return task;
}


/*
 * Extract all expired timers from the wait queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 *
 */
void wake_expired_tasks(struct timeval *next)
{
	int slen;
	struct task *task;
	void *data;

	/*
	 * Hint: tasks are *rarely* expired. So we can try to optimize
	 * by not scanning the tree at all in most cases.
	 */

	if (likely(timer_wq.data != NULL)) {
		task = LIST_ELEM(timer_wq.data, struct task *, qlist);
		if (likely(tv_isgt(&task->expire, &now))) {
			tv_remain(&now, &task->expire, next);
			return;
		}
	}

	/* OK we lose. Let's scan the tree then. */
	tv_eternity(next);

	tree64_foreach(&timer_wq, data, stack, slen) {
		task = LIST_ELEM(data, struct task *, qlist);

		if (tv_isgt(&task->expire, &now)) {
			tv_remain(&now, &task->expire, next);
			break;
		}

		/*
		 * OK, all tasks linked to this node will be unlinked, as well
		 * as the node itself, so we do not need to care about correct
		 * unlinking.
		 */
		foreach_dlist_item(task, data, struct task *, qlist) {
			DLIST_DEL(&task->qlist);
			task->wq = NULL;
			DLIST_ADD(run_queue, &task->qlist);
			task->state = TASK_RUNNING;
		}
	}
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
