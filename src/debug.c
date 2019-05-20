/*
 * Process debugging functions.
 *
 * Copyright 2000-2019 Willy Tarreau <willy@haproxy.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <signal.h>
#include <time.h>
#include <stdio.h>

#include <common/buf.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/hathreads.h>
#include <common/initcall.h>
#include <common/standard.h>

#include <types/global.h>

#include <proto/cli.h>
#include <proto/fd.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

/* Dumps to the buffer some known information for the desired thread, and
 * optionally extra info for the current thread. The dump will be appended to
 * the buffer, so the caller is responsible for preliminary initializing it.
 * The calling thread ID needs to be passed in <calling_tid> to display a star
 * in front of the calling thread's line (usually it's tid).
 */
void ha_thread_dump(struct buffer *buf, int thr, int calling_tid)
{
	unsigned long thr_bit = 1UL << thr;

	chunk_appendf(buf,
	              "%c Thread %-2u: act=%d glob=%d wq=%d rq=%d tl=%d tlsz=%d rqsz=%d\n"
	              "             fdcache=%d prof=%d",
	              (thr == calling_tid) ? '*' : ' ', thr + 1,
	              !!(active_tasks_mask & thr_bit),
	              !!(global_tasks_mask & thr_bit),
	              !eb_is_empty(&task_per_thread[thr].timers),
	              !eb_is_empty(&task_per_thread[thr].rqueue),
	              !LIST_ISEMPTY(&task_per_thread[thr].task_list),
	              task_per_thread[thr].task_list_size,
	              task_per_thread[thr].rqueue_size,
	              !!(fd_cache_mask & thr_bit),
	              !!(task_profiling_mask & thr_bit));

#ifdef USE_THREAD
	chunk_appendf(buf,
	              " harmless=%d wantrdv=%d",
	              !!(threads_harmless_mask & thr_bit),
	              !!(threads_want_rdv_mask & thr_bit));
#endif

	chunk_appendf(buf, "\n");

	/* this is the end of what we can dump from outside the thread */

	if (thr != tid)
		return;

	chunk_appendf(buf, "             curr_task=");
	ha_task_dump(buf, curr_task, "             ");
}


/* dumps into the buffer some information related to task <task> (which may
 * either be a task or a tasklet, and prepend each line except the first one
 * with <pfx>. The buffer is only appended and the first output starts by the
 * pointer itself. The caller is responsible for making sure the task is not
 * going to vanish during the dump.
 */
void ha_task_dump(struct buffer *buf, const struct task *task, const char *pfx)
{
	if (!task) {
		chunk_appendf(buf, "0\n");
		return;
	}

	if (TASK_IS_TASKLET(task))
		chunk_appendf(buf,
		              "%p (tasklet) calls=%u\n",
		              task,
		              task->calls);
	else
		chunk_appendf(buf,
		              "%p (task) calls=%u last=%llu%s\n",
		              task,
		              task->calls,
		              task->call_date ? (unsigned long long)(now_mono_time() - task->call_date) : 0,
		              task->call_date ? " ns ago" : "");

	chunk_appendf(buf, "%s"
	              "  fct=%p (%s) ctx=%p\n",
	              pfx,
	              task->process,
	              task->process == process_stream ? "process_stream" :
	              task->process == task_run_applet ? "task_run_applet" :
	              task->process == si_cs_io_cb ? "si_cs_io_cb" :
		      "?",
	              task->context);
}

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_threads(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	int thr;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	if (appctx->st0)
		thr = appctx->st1;
	else
		thr = 0;

	chunk_reset(&trash);
	ha_thread_dump_all_to_trash();

	if (ci_putchk(si_ic(si), &trash) == -1) {
		/* failed, try again */
		si_rx_room_blk(si);
		appctx->st1 = thr;
		return 0;
	}
	return 1;
}

/* dumps a state of all threads into the trash and on fd #2, then aborts. */
void ha_panic()
{
	chunk_reset(&trash);
	chunk_appendf(&trash, "Thread %u is about to kill the process.\n", tid);
	ha_thread_dump_all_to_trash();
	write(2, trash.area, trash.data);
	for (;;)
		abort();
}

#ifndef USE_THREAD_DUMP

/* This function dumps all threads' state to the trash. This version is the
 * most basic one, which doesn't inspect other threads.
 */
void ha_thread_dump_all_to_trash()
{
	unsigned int thr;

	for (thr = 0; thr < global.nbthread; thr++)
		ha_thread_dump(&trash, thr, tid);
}

#else /* below USE_THREAD_DUMP is set */

/* The signal to trigger a debug dump on a thread is SIGPWR */
#define DEBUGSIG SIGPWR

/* mask of threads still having to dump, used to respect ordering */
static volatile unsigned long threads_to_dump;

/* ID of the thread requesting the dump */
static unsigned int thread_dump_tid;

/* points to the buffer where the dump functions should write. It must
 * have already been initialized by the requester. Nothing is done if
 * it's NULL.
 */
struct buffer *thread_dump_buffer = NULL;

void ha_thread_dump_all_to_trash()
{
	__maybe_unused unsigned int thr;
	unsigned long old;

	while (1) {
		old = 0;
		if (HA_ATOMIC_CAS(&threads_to_dump, &old, all_threads_mask))
			break;
		ha_thread_relax();
	}

	thread_dump_buffer = &trash;
	thread_dump_tid = tid;

#ifdef USE_THREAD
	for (thr = 0; thr < global.nbthread; thr++) {
		if (thr != tid)
			pthread_kill(thread_info[thr].pthread, DEBUGSIG);
	}
#endif
	/* dump ourselves last */
	raise(DEBUGSIG);
}

/* handles DEBUGSIG to dump the state of the thread it's working on */
void debug_handler(int sig, siginfo_t *si, void *arg)
{
	/* There are 4 phases in the dump process:
	 *   1- wait for our turn, i.e. when all lower bits are gone.
	 *   2- perform the action if our bit is set
	 *   3- remove our bit to let the next one go, unless we're
	 *      the last one and have to put them all but ours
	 *   4- wait for zero and clear our bit if it's set
	 */

	/* wait for all previous threads to finish first */
	while (threads_to_dump & (tid_bit - 1))
		ha_thread_relax();

	/* dump if needed */
	if (threads_to_dump & tid_bit) {
		if (thread_dump_buffer)
			ha_thread_dump(thread_dump_buffer, tid, thread_dump_tid);
		if ((threads_to_dump & all_threads_mask) == tid_bit) {
			/* last one */
			HA_ATOMIC_STORE(&threads_to_dump, all_threads_mask & ~tid_bit);
			thread_dump_buffer = NULL;
		}
		else
			HA_ATOMIC_AND(&threads_to_dump, ~tid_bit);
	}

	/* now wait for all others to finish dumping. The last one will set all
	 * bits again to broadcast the leaving condition.
	 */
	while (threads_to_dump & all_threads_mask) {
		if (threads_to_dump & tid_bit)
			HA_ATOMIC_AND(&threads_to_dump, ~tid_bit);
		else
			ha_thread_relax();
	}
}

static int init_debug_per_thread()
{
	sigset_t set;

	/* unblock the DEBUGSIG signal we intend to use */
	sigemptyset(&set);
	sigaddset(&set, DEBUGSIG);
	ha_sigmask(SIG_UNBLOCK, &set, NULL);
	return 1;
}

static int init_debug()
{
	struct sigaction sa;

	sa.sa_handler = NULL;
	sa.sa_sigaction = debug_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(DEBUGSIG, &sa, NULL);
	return 0;
}

REGISTER_POST_CHECK(init_debug);
REGISTER_PER_THREAD_INIT(init_debug_per_thread);

#endif /* USE_THREAD_DUMP */

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "threads", NULL },    "show threads   : show some threads debugging information",   NULL, cli_io_handler_show_threads, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
