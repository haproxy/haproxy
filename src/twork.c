/*
 * Cross-thread/thread-group deferred work.
 *
 * Lets any thread ask another thread, or any thread of another thread
 * group, to run a function on its behalf. This is mostly meant for
 * operations which must be performed in the context of a specific thread
 * group, such as anything related to file descriptors when FD tables are
 * not shared between groups.
 *
 * Each thread and each thread group has a dedicated MT_LIST work queue
 * drained by a permanent tasklet. Posting allocates a small item from a
 * pool, appends it and wakes the target's tasklet, so ordering is FIFO
 * per queue. Group queues are drained by a designated runner thread of
 * the group (the first one started); since all the threads of a group
 * share the same FD table, any of them is a suitable runner.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 */

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/global.h>
#include <haproxy/pool.h>
#include <haproxy/task.h>
#include <haproxy/tinfo.h>
#include <haproxy/tools.h>
#include <haproxy/twork.h>

DECLARE_STATIC_POOL(pool_head_twork, "twork", sizeof(struct twork));

struct twork_queue {
	struct mt_list queue;      /* pending twork items */
	struct tasklet *tl;        /* permanent runner tasklet, NULL when not started, bit 0 set once closed */
	int runner;                /* runner tid (groups only), -1 when none */
} __attribute__((aligned(64)));

static struct twork_queue twork_thr[MAX_THREADS];
static struct twork_queue twork_grp[MAX_TGROUPS];

/* returns the queue's runner tasklet, or NULL when not started or closed */
static inline struct tasklet *twork_queue_tl(struct twork_queue *q)
{
	struct tasklet *tl = HA_ATOMIC_LOAD(&q->tl);

	return ((ulong)tl & 1) ? NULL : tl;
}

/* Pops the next item of <queue>, marking it busy before it appears
 * detached, so that a concurrent twork_cancel() can never mistake an
 * item about to run for an idle one. Returns NULL if the queue is empty.
 */
static struct twork *twork_pop(struct mt_list *queue)
{
	struct twork *tw;

	tw = MT_LIST_POP_LOCKED(queue, struct twork *, link);
	if (tw) {
		HA_ATOMIC_OR(&tw->flags, TWORK_FL_BUSY);
		mt_list_unlock_self(&tw->link);
	}
	return tw;
}

static void twork_run_item(struct twork *tw)
{
	struct twork_queue *q;
	struct tasklet *tl;

	if (!(tw->flags & TWORK_FL_REPLY)) {
		tw->ret = tw->fn(tw->arg);
		if (tw->done) {
			/* the item must not look idle between the flag changes
			 * and the requeuing, so set REPLY before dropping BUSY.
			 */
			HA_ATOMIC_OR(&tw->flags, TWORK_FL_REPLY);
			HA_ATOMIC_AND(&tw->flags, ~TWORK_FL_BUSY);
			/* the MAX_THREADS test lets the compiler see the index
			 * is within bounds in single-thread builds.
			 */
			q = &twork_thr[MAX_THREADS > 1 ? tw->caller_tid : 0];
			tl = twork_queue_tl(q);
			if (tl) {
				MT_LIST_APPEND(&q->queue, &tw->link);
				tasklet_wakeup(tl);
				return;
			}

			/* the caller's thread is gone (process stopping): the
			 * completion must only ever run there, so drop it and
			 * release the item; a caller-provided one becomes idle.
			 */
			HA_ATOMIC_AND(&tw->flags, ~(TWORK_FL_BUSY | TWORK_FL_REPLY));
			if (tw->flags & TWORK_FL_DYN)
				pool_free(pool_head_twork, tw);
			return;
		}
	}

	/*
	 * We executed the work already, let the caller know about that
	 */
	if (tw->flags & TWORK_FL_DYN) {
		if (tw->done)
			tw->done(tw->arg, tw->ret);
		pool_free(pool_head_twork, tw);
	}
	else {
		HA_ATOMIC_AND(&tw->flags, ~(TWORK_FL_BUSY | TWORK_FL_REPLY));
		if (tw->done)
			tw->done(tw->arg, tw->ret);
	}
}

/* runs up to tune.sched.remote-work-budget pending items of a queue, then
 * reschedules itself if some remain, to preserve latency.
 */
static struct task *twork_process(struct task *t, void *ctx, unsigned int state)
{
	struct twork_queue *q = ctx;
	struct twork *tw;
	uint budget = global.tune.twork_budget;

	while ((tw = twork_pop(&q->queue))) {
		twork_run_item(tw);
		if (!--budget)
			break;
	}

	if (!MT_LIST_ISEMPTY(&q->queue))
		tasklet_wakeup((struct tasklet *)t);

	return t;
}

/* posts one item to <q>. Returns non-zero on success, 0 on failure. */
static int twork_call_queue(struct twork_queue *q, struct twork *tw,
                            union twork_arg (*fn)(union twork_arg),
                            union twork_arg arg,
                            void (*done)(union twork_arg arg, union twork_arg ret))
{
	struct tasklet *tl;

	tl = twork_queue_tl(q);
	if (!tl)
		return 0;

	if (!tw) {
		tw = pool_alloc(pool_head_twork);
		if (!tw)
			return 0;
		MT_LIST_INIT(&tw->link);
		tw->flags = TWORK_FL_DYN;
	}
	else if (HA_ATOMIC_LOAD(&tw->flags) & (TWORK_FL_BUSY | TWORK_FL_REPLY)) {
		/* A caller-provided item expecting a completion must not be
		 * reposted before that completion was delivered, otherwise it
		 * could be queued here while the runner is about to queue it
		 * back to us, corrupting both lists.
		 */
		BUG_ON(done);

		/* Reposting an item which is still running is only permitted
		 * with strictly identical parameters, since the runner may be
		 * reading them right now (see the reuse rules in twork-t.h).
		 * Otherwise the fields rewritten below would be lost or picked
		 * up by the wrong run.
		 */
		BUG_ON(tw->fn != fn || tw->arg.u64 != arg.u64 || tw->done != done);
	}

	tw->fn         = fn;
	tw->arg        = arg;
	tw->ret        = twk_u64(0);
	tw->done       = done;
	tw->caller_tid = tid;

	if (MT_LIST_TRY_APPEND(&q->queue, &tw->link))
		tasklet_wakeup(tl);
	return 1;
}

int twork_call_on(struct twork *tw, int tid,
                  union twork_arg (*fn)(union twork_arg),
                  union twork_arg arg,
                  void (*done)(union twork_arg arg, union twork_arg ret))
{
	if (tid < 0 || tid >= MAX_THREADS || tid >= global.nbthread)
		return 0;
	return twork_call_queue(&twork_thr[tid], tw, fn, arg, done);
}

int twork_call_tgroup(struct twork *tw, uint tgid,
                      union twork_arg (*fn)(union twork_arg),
                      union twork_arg arg,
                      void (*done)(union twork_arg arg, union twork_arg ret))
{
	if (tgid < 1 || tgid > MAX_TGROUPS || tgid > global.nbtgroups)
		return 0;
	return twork_call_queue(&twork_grp[tgid - 1], tw, fn, arg, done);
}

int twork_cancel(struct twork *tw)
{
	/* dequeued before its next phase: nothing will run anymore */
	if (MT_LIST_DELETE(&tw->link)) {
		HA_ATOMIC_AND(&tw->flags, ~TWORK_FL_REPLY);
		return 1;
	}

	/* detached: either a runner holds it (busy/reply in flight), or
	 * it's idle (never posted, or fully completed).
	 */
	if (HA_ATOMIC_LOAD(&tw->flags) & (TWORK_FL_BUSY | TWORK_FL_REPLY))
		return 0;
	return 1;
}

/* drains a queue in place, running the pending items. Only to be used by
 * the owner (or last surviving) thread when tearing the queue down.
 */
static void twork_drain(struct twork_queue *q)
{
	struct twork *tw;

	while ((tw = twork_pop(&q->queue)))
		twork_run_item(tw);
}

static int twork_init_per_thread(void)
{
	struct twork_queue *q = &twork_thr[tid];
	struct twork_queue *gq = &twork_grp[tgid - 1];
	struct tasklet *tl;
	int expected;

	tl = tasklet_new();
	if (!tl)
		return 0;
	tl->process = twork_process;
	tl->context = q;
	tasklet_set_tid(tl, tid);
	HA_ATOMIC_STORE(&q->tl, tl);

	/* the first started thread of each group becomes the group's runner */
	expected = -1;
	if (HA_ATOMIC_CAS(&gq->runner, &expected, tid)) {
		tl = tasklet_new();
		if (!tl)
			return 0;
		tl->process = twork_process;
		tl->context = gq;
		tasklet_set_tid(tl, tid);
		HA_ATOMIC_STORE(&gq->tl, tl);
	}
	return 1;
}

static void twork_deinit_per_thread(void)
{
	struct twork_queue *q = &twork_thr[tid];
	struct twork_queue *gq = &twork_grp[tgid - 1];

	/* We only get here when the whole process is stopping, so refuse new
	 * work first, then run whatever was already queued: for the group
	 * queue this is correct on any thread of the group. Work posted after
	 * the drain is simply dropped, the process is about to leave.
	 *
	 * Closing only tags bit 0 of the tasklet pointer: another thread may
	 * be in twork_call_queue() having already loaded it, and would wake
	 * a freed tasklet. They are released by twork_deinit() once all the
	 * threads have been joined, where no such user may remain.
	 *
	 * TODO: if individual threads ever get to stop at runtime, the group
	 * runner role must instead be handed over to a surviving thread.
	 */
	HA_ATOMIC_STORE(&q->tl, (struct tasklet *)((ulong)q->tl | 1));
	twork_drain(q);

	if (HA_ATOMIC_LOAD(&gq->runner) == tid) {
		HA_ATOMIC_STORE(&gq->tl, (struct tasklet *)((ulong)gq->tl | 1));
		twork_drain(gq);
	}
}

/* Releases the runner tasklets and whatever work was left pending. This runs
 * from deinit(), after all the threads were joined, so nothing may be posting
 * anymore nor holding a reference to these tasklets.
 */
static void twork_deinit(void)
{
	struct twork_queue *queues[2] = { twork_thr, twork_grp };
	int nb[2] = { MAX_THREADS, MAX_TGROUPS };
	struct twork *tw;
	int i, j;

	for (j = 0; j < 2; j++) {
		for (i = 0; i < nb[j]; i++) {
			struct twork_queue *q = &queues[j][i];

			/* work posted after the queue was closed was never
			 * run, just release what we own.
			 */
			while ((tw = MT_LIST_POP(&q->queue, struct twork *, link))) {
				if (tw->flags & TWORK_FL_DYN)
					pool_free(pool_head_twork, tw);
			}

			tasklet_free((struct tasklet *)((ulong)q->tl & ~1UL));
			q->tl = NULL;
		}
	}
}

REGISTER_PER_THREAD_INIT(twork_init_per_thread);
REGISTER_PER_THREAD_DEINIT(twork_deinit_per_thread);
REGISTER_POST_DEINIT(twork_deinit);

static void twork_queues_init(void)
{
	int i;

	global.tune.twork_budget = TWORK_BUDGET;
	for (i = 0; i < MAX_THREADS; i++) {
		MT_LIST_INIT(&twork_thr[i].queue);
		twork_thr[i].runner = -1;
	}
	for (i = 0; i < MAX_TGROUPS; i++) {
		MT_LIST_INIT(&twork_grp[i].queue);
		twork_grp[i].runner = -1;
	}
}

INITCALL0(STG_PREPARE, twork_queues_init);

/* config parser for global "tune.sched.remote-work-budget" */
static int cfg_parse_tune_sched_remote_work_budget(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	char *end;
	long val;

	if (too_many_args(1, args, err, NULL))
		return -1;

	val = strtol(args[1], &end, 0);
	if (*args[1] == '\0' || *end != '\0' || val <= 0 || val > INT_MAX) {
		memprintf(err, "'%s' expects a positive integer but got '%s'.", args[0], args[1]);
		return -1;
	}
	global.tune.twork_budget = val;
	return 0;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.sched.remote-work-budget", cfg_parse_tune_sched_remote_work_budget },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
