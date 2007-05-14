/*
  include/proto/task.h
  Functions for task management.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
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

#include <types/task.h>

extern void *run_queue;
extern struct pool_head *pool2_task;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_task();

/* needed later */
void *tree_delete(void *node);

/* puts the task <t> in run queue <q>, and returns <t> */
#define task_wakeup _task_wakeup
struct task *_task_wakeup(struct task *t);
static inline struct task *__task_wakeup(struct task *t)
{
	if (t->state == TASK_RUNNING)
		return t;

	if (t->qlist.p != NULL)
		DLIST_DEL(&t->qlist);

	DLIST_ADD(run_queue, &t->qlist);
	t->state = TASK_RUNNING;

	if (likely(t->wq)) {
		tree_delete(t->wq);
		t->wq = NULL;
	}

	return t;
}

/* removes the task <t> from the run queue if it was in it.
 * returns <t>.
 */
static inline struct task *task_sleep(struct task *t)
{
	if (t->state == TASK_RUNNING) {
		DLIST_DEL(&t->qlist);
		t->qlist.p = NULL;
		t->state = TASK_IDLE;
	}
	return t;
}

/*
 * unlinks the task from wherever it is queued :
 *  - eternity_queue, run_queue
 *  - wait queue : wq not null => remove carrier node too
 * A pointer to the task itself is returned.
 */
static inline struct task *task_delete(struct task *t)
{
	if (t->qlist.p != NULL) {
		DLIST_DEL(&t->qlist);
		t->qlist.p = NULL;
	}

	if (t->wq) {
		tree_delete(t->wq);
		t->wq = NULL;
	}
	return t;
}

/*
 * frees a task. Its context must have been freed since it will be lost.
 */
static inline void task_free(struct task *t)
{
	pool_free2(pool2_task, t);
}

/* inserts <task> into its assigned wait queue, where it may already be. In this case, it
 * may be only moved or left where it was, depending on its timing requirements.
 * <task> is returned.
 */
struct task *task_queue(struct task *task);

/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - call maintain_proxies() to enable/disable the listeners
 *   - return the date of next event in <next> or eternity.
 */

void process_runnable_tasks(struct timeval *next);


#endif /* _PROTO_TASK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
