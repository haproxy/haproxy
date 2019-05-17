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

/* Dumps to the trash some known information for the desired thread, and
 * optionally extra info for the current thread.
 */
void ha_thread_dump(int thr)
{
	unsigned long thr_bit = 1UL << thr;

	chunk_reset(&trash);
	chunk_appendf(&trash,
	              "%c Thread %-2u: act=%d glob=%d wq=%d rq=%d tl=%d tlsz=%d rqsz=%d\n"
	              "             fdcache=%d prof=%d",
	              (thr == tid) ? '*' : ' ', thr + 1,
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
	chunk_appendf(&trash,
	              " harmless=%d wantrdv=%d",
	              !!(threads_harmless_mask & thr_bit),
	              !!(threads_want_rdv_mask & thr_bit));
#endif

	chunk_appendf(&trash, "\n");

	/* this is the end of what we can dump from outside the thread */

	if (thr != tid)
		return;

	chunk_appendf(&trash, "             curr_task=");
	ha_task_dump(curr_task, "             ");
}


/* dumps into the trash some information related to task <task> (which may
 * either be a task or a tasklet, and prepend each line except the first one
 * with <pfx>. The trash is only appended and the first output starts by the
 * pointer itself.
 */
void ha_task_dump(const struct task *task, const char *pfx)
{
	if (!task) {
		chunk_appendf(&trash, "0\n");
		return;
	}

	chunk_appendf(&trash,
	              "%p (%s) calls=%u last=%llu%s\n",
	              task, TASK_IS_TASKLET(task) ? "tasklet" : "task",
	              task->calls,
	              task->call_date ? (unsigned long long)(now_mono_time() - task->call_date) : 0,
	              task->call_date ? " ns ago" : "");

	chunk_appendf(&trash, "%s"
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

	while (thr < global.nbthread) {
		ha_thread_dump(thr);

		if (ci_putchk(si_ic(si), &trash) == -1) {
			/* failed, try again */
			si_rx_room_blk(si);
			appctx->st1 = thr;
			return 0;
		}
		thr++;
	}
	return 1;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "threads", NULL },    "show threads   : show some threads debugging information",   NULL, cli_io_handler_show_threads, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
