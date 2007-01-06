/*
 * Task management functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/time.h>

#include <proto/task.h>


/* FIXME : this should be removed very quickly ! */
extern int maintain_proxies(void);

void **pool_task= NULL;
struct task *rq = NULL;		/* global run queue */

struct rb_root wait_queue[2] = {
	RB_ROOT,
	RB_ROOT,
};


static inline void __rb_insert_task_queue(struct task *newtask)
{
	struct rb_node **p = &newtask->wq->rb_node;
	struct rb_node *parent = NULL;
	struct task * task;

	while (*p)
	{
		parent = *p;
		task = rb_entry(parent, struct task, rb_node);
		if (tv_cmp2(&task->expire, &newtask->expire) >= 0)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&newtask->rb_node, parent, p);
}

static inline void rb_insert_task_queue(struct task *newtask)
{
	__rb_insert_task_queue(newtask);
	rb_insert_color(&newtask->rb_node, newtask->wq);
}


struct task *task_queue(struct task *task)
{
	struct rb_node *node;
	struct task *next, *prev;

	if (tv_iseternity(&task->expire)) {
		if (task->wq) {
			if (task->wq == &wait_queue[1])
				return task;
			else
				task_delete(task);
		}
		task->wq = &wait_queue[1];
		rb_insert_task_queue(task);
		return task;
	} else {
		if (task->wq != &wait_queue[0]) {
			if (task->wq)
				task_delete(task);
			task->wq = &wait_queue[0];
			rb_insert_task_queue(task);
			return task;
		}

		// check whether task should be re insert
		node = rb_prev(&task->rb_node);
		if (node) {
			prev = rb_entry(node, struct task, rb_node);
			if (tv_cmp2(&prev->expire, &task->expire) >= 0) {
				task_delete(task);
				task->wq = &wait_queue[0];
				rb_insert_task_queue(task);
				return task;
			}
		}

		node = rb_next(&task->rb_node);
		if (node) {
			next = rb_entry(node, struct task, rb_node);
			if (tv_cmp2(&task->expire, &next->expire) > 0) {
				task_delete(task);
				task->wq = &wait_queue[0];
				rb_insert_task_queue(task);
				return task;
			}
		}
		return task;
	}
}

/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - call maintain_proxies() to enable/disable the listeners
 *   - return the delay till next event in ms, -1 = wait indefinitely
 *
 */
int process_runnable_tasks()
{
	int next_time;
	int time2;
	struct task *t;
	struct rb_node *node;

	next_time = TIME_ETERNITY;
	for (node = rb_first(&wait_queue[0]);
		node != NULL; node = rb_next(node)) {
		t = rb_entry(node, struct task, rb_node);
		if (t->state & TASK_RUNNING)
			continue;
		if (tv_iseternity(&t->expire))
			continue;
		if (tv_cmp_ms(&t->expire, &now) <= 0) {
			task_wakeup(&rq, t);
		} else {
			int temp_time = tv_remain(&now, &t->expire);
			if (temp_time)
				next_time = temp_time;
			break;
		}
	}

	/* process each task in the run queue now. Each task may be deleted
	 * since we only use the run queue's head. Note that any task can be
	 * woken up by any other task and it will be processed immediately
	 * after as it will be queued on the run queue's head !
	 */
	while ((t = rq) != NULL) {
		int temp_time;

		task_sleep(&rq, t);
		temp_time = t->process(t);
		next_time = MINTIME(temp_time, next_time);
	}

	/* maintain all proxies in a consistent state. This should quickly
	 * become a task because it becomes expensive when there are huge
	 * numbers of proxies. */
	time2 = maintain_proxies();
	return MINTIME(time2, next_time);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
