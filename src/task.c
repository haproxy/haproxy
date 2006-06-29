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
struct task wait_queue[2] = {	/* global wait queue */
    {
	prev:LIST_HEAD(wait_queue[0]),  /* expirable tasks */
	next:LIST_HEAD(wait_queue[0]),
    },
    {
	prev:LIST_HEAD(wait_queue[1]),  /* non-expirable tasks */
	next:LIST_HEAD(wait_queue[1]),
    },
};


/* inserts <task> into its assigned wait queue, where it may already be. In this case, it
 * may be only moved or left where it was, depending on its timing requirements.
 * <task> is returned.
 */
struct task *task_queue(struct task *task)
{
	struct task *list = task->wq;
	struct task *start_from;

	/* This is a very dirty hack to queue non-expirable tasks in another queue
	 * in order to avoid pulluting the tail of the standard queue. This will go
	 * away with the new O(log(n)) scheduler anyway.
	 */
	if (tv_iseternity(&task->expire)) {
		/* if the task was queued in the standard wait queue, we must dequeue it */
		if (task->prev) {
			if (task->wq == LIST_HEAD(wait_queue[1]))
				return task;
			else {
				task_delete(task);
				task->prev = NULL;
			}
		}
		list = task->wq = LIST_HEAD(wait_queue[1]);
	} else {
		/* if the task was queued in the eternity queue, we must dequeue it */
		if (task->prev && (task->wq == LIST_HEAD(wait_queue[1]))) {
			task_delete(task);
			task->prev = NULL;
			list = task->wq = LIST_HEAD(wait_queue[0]);
		}
	}

	/* next, test if the task was already in a list */
	if (task->prev == NULL) {
		//	start_from = list;
		start_from = list->prev;
		/* insert the unlinked <task> into the list, searching back from the last entry */
		while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
			start_from = start_from->prev;
		}
	
		//	  while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
		//	      start_from = start_from->next;
		//	      stats_tsk_nsrch++;
		//	  }
	}	
	else if (task->prev == list ||
		 tv_cmp2(&task->expire, &task->prev->expire) >= 0) { /* walk right */
		start_from = task->next;
		if (start_from == list || tv_cmp2(&task->expire, &start_from->expire) <= 0) {
			return task; /* it's already in the right place */
		}

		/* if the task is not at the right place, there's little chance that
		 * it has only shifted a bit, and it will nearly always be queued
		 * at the end of the list because of constant timeouts
		 * (observed in real case).
		 */
#ifndef WE_REALLY_THINK_THAT_THIS_TASK_MAY_HAVE_SHIFTED
		start_from = list->prev; /* assume we'll queue to the end of the list */
		while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
			start_from = start_from->prev;
		}
#else /* WE_REALLY_... */
		/* insert the unlinked <task> into the list, searching after position <start_from> */
		while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
			start_from = start_from->next;
		}
#endif /* WE_REALLY_... */

		/* we need to unlink it now */
		task_delete(task);
	}
	else { /* walk left. */
#ifdef LEFT_TO_TOP	/* not very good */
		start_from = list;
		while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
			start_from = start_from->next;
		}
#else
		start_from = task->prev->prev; /* valid because of the previous test above */
		while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
			start_from = start_from->prev;
		}
#endif
		/* we need to unlink it now */
		task_delete(task);
	}
	task->prev = start_from;
	task->next = start_from->next;
	task->next->prev = task;
	start_from->next = task;
	return task;
}

/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - call maintain_proxies() to enable/disable the listeners
 *   - return the delay till next event in ms, -1 = wait indefinitely
 * Note: this part should be rewritten with the O(ln(n)) scheduler.
 *
 */

int process_runnable_tasks()
{
	int next_time;
	int time2;
	struct task *t, *tnext;

	next_time = TIME_ETERNITY; /* set the timer to wait eternally first */

	/* look for expired tasks and add them to the run queue.
	 */
	tnext = ((struct task *)LIST_HEAD(wait_queue[0]))->next;
	while ((t = tnext) != LIST_HEAD(wait_queue[0])) { /* we haven't looped ? */
		tnext = t->next;
		if (t->state & TASK_RUNNING)
			continue;
      
		if (tv_iseternity(&t->expire))
			continue;

		/* wakeup expired entries. It doesn't matter if they are
		 * already running because of a previous event
		 */
		if (tv_cmp_ms(&t->expire, &now) <= 0) {
			task_wakeup(&rq, t);
		}
		else {
			/* first non-runnable task. Use its expiration date as an upper bound */
			int temp_time = tv_remain(&now, &t->expire);
			if (temp_time)
				next_time = temp_time;
			break;
		}
	}

	/* process each task in the run queue now. Each task may be deleted
	 * since we only use the run queue's head. Note that any task can be
	 * woken up by any other task and it will be processed immediately
	 * after as it will be queued on the run queue's head.
	 */
	while ((t = rq) != NULL) {
		int temp_time;

		task_sleep(&rq, t);
		temp_time = t->process(t);
		next_time = MINTIME(temp_time, next_time);
	}
  
	/* maintain all proxies in a consistent state. This should quickly become a task */
	time2 = maintain_proxies();
	return MINTIME(time2, next_time);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
