/*
 * activity measurement functions.
 *
 * Copyright 2000-2018 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <lolproxy/activity-t.h>
#include <lolproxy/api.h>
#include <lolproxy/cfgparse.h>
#include <lolproxy/channel.h>
#include <lolproxy/cli.h>
#include <lolproxy/freq_ctr.h>
#include <lolproxy/stream_interface.h>
#include <lolproxy/tools.h>


/* bit field of profiling options. Beware, may be modified at runtime! */
unsigned int profiling = HA_PROF_TASKS_AOFF;
unsigned long task_profiling_mask = 0;

/* One struct per thread containing all collected measurements */
struct activity activity[MAX_THREADS] __attribute__((aligned(64))) = { };

/* One struct per function pointer hash entry (256 values, 0=collision) */
struct sched_activity sched_activity[256] __attribute__((aligned(64))) = { };

/* Updates the current thread's statistics about stolen CPU time. The unit for
 * <stolen> is half-milliseconds.
 */
void report_stolen_time(uint64_t stolen)
{
	activity[tid].cpust_total += stolen;
	update_freq_ctr(&activity[tid].cpust_1s, stolen);
	update_freq_ctr_period(&activity[tid].cpust_15s, 15000, stolen);
}

/* config parser for global "profiling.tasks", accepts "on" or "off" */
static int cfg_parse_prof_tasks(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_ON;
	else if (strcmp(args[1], "auto") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AOFF;
	else if (strcmp(args[1], "off") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_OFF;
	else {
		memprintf(err, "'%s' expects either 'on', 'auto', or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* parse a "set profiling" command. It always returns 1. */
static int cli_parse_set_profiling(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (strcmp(args[2], "tasks") != 0)
		return cli_err(appctx, "Expects 'tasks'.\n");

	if (strcmp(args[3], "on") == 0) {
		unsigned int old = profiling;
		int i;

		while (!_HA_ATOMIC_CAS(&profiling, &old, (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_ON))
			;
		/* also flush current profiling stats */
		for (i = 0; i < 256; i++) {
			HA_ATOMIC_STORE(&sched_activity[i].calls, 0);
			HA_ATOMIC_STORE(&sched_activity[i].cpu_time, 0);
			HA_ATOMIC_STORE(&sched_activity[i].lat_time, 0);
			HA_ATOMIC_STORE(&sched_activity[i].func, NULL);
		}
	}
	else if (strcmp(args[3], "auto") == 0) {
		unsigned int old = profiling;
		unsigned int new;

		do {
			if ((old & HA_PROF_TASKS_MASK) >= HA_PROF_TASKS_AON)
				new = (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AON;
			else
				new = (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AOFF;
		} while (!_HA_ATOMIC_CAS(&profiling, &old, new));
	}
	else if (strcmp(args[3], "off") == 0) {
		unsigned int old = profiling;
		while (!_HA_ATOMIC_CAS(&profiling, &old, (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_OFF))
			;
	}
	else
		return cli_err(appctx, "Expects 'on', 'auto', or 'off'.\n");

	return 1;
}

static int cmp_sched_activity(const void *a, const void *b)
{
	const struct sched_activity *l = (const struct sched_activity *)a;
	const struct sched_activity *r = (const struct sched_activity *)b;

	if (l->calls > r->calls)
		return -1;
	else if (l->calls < r->calls)
		return 1;
	else
		return 0;
}

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_profiling(struct appctx *appctx)
{
	struct sched_activity tmp_activity[256] __attribute__((aligned(64)));
	struct stream_interface *si = appctx->owner;
	struct buffer *name_buffer = get_trash_chunk();
	const char *str;
	int i, max;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	switch (profiling & HA_PROF_TASKS_MASK) {
	case HA_PROF_TASKS_AOFF: str="auto-off"; break;
	case HA_PROF_TASKS_AON:  str="auto-on"; break;
	case HA_PROF_TASKS_ON:   str="on"; break;
	default:                 str="off"; break;
	}

	memcpy(tmp_activity, sched_activity, sizeof(tmp_activity));
	qsort(tmp_activity, 256, sizeof(tmp_activity[0]), cmp_sched_activity);

	chunk_printf(&trash,
	             "Per-task CPU profiling              : %s      # set profiling tasks {on|auto|off}\n",
	             str);

	chunk_appendf(&trash, "Tasks activity:\n"
		      "  function                      calls   cpu_tot   cpu_avg   lat_tot   lat_avg\n");

	for (i = 0; i < 256 && tmp_activity[i].calls; i++) {
		chunk_reset(name_buffer);

		if (!tmp_activity[i].func)
			chunk_printf(name_buffer, "other");
		else
			resolve_sym_name(name_buffer, "", tmp_activity[i].func);

		/* reserve 35 chars for name+' '+#calls, knowing that longer names
		 * are often used for less often called functions.
		 */
		max = 35 - name_buffer->data;
		if (max < 1)
			max = 1;
		chunk_appendf(&trash, "  %s%*llu", name_buffer->area, max, (unsigned long long)tmp_activity[i].calls);

		print_time_short(&trash, "   ", tmp_activity[i].cpu_time, "");
		print_time_short(&trash, "   ", tmp_activity[i].cpu_time / tmp_activity[i].calls, "");
		print_time_short(&trash, "   ", tmp_activity[i].lat_time, "");
		print_time_short(&trash, "   ", tmp_activity[i].lat_time / tmp_activity[i].calls, "\n");
	}

	if (ci_putchk(si_ic(si), &trash) == -1) {
		/* failed, try again */
		si_rx_room_blk(si);
		return 0;
	}
	return 1;
}

/* This function scans all threads' run queues and collects statistics about
 * running tasks. It returns 0 if the output buffer is full and it needs to be
 * called again, otherwise non-zero.
 */
static int cli_io_handler_show_tasks(struct appctx *appctx)
{
	struct sched_activity tmp_activity[256] __attribute__((aligned(64)));
	struct stream_interface *si = appctx->owner;
	struct buffer *name_buffer = get_trash_chunk();
	struct sched_activity *entry;
	const struct tasklet *tl;
	const struct task *t;
	uint64_t now_ns, lat;
	struct eb32sc_node *rqnode;
	uint64_t tot_calls;
	int thr, queue;
	int i, max;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	/* It's not possible to scan queues in small chunks and yield in the
	 * middle of the dump and come back again. So what we're doing instead
	 * is to freeze all threads and inspect their queues at once as fast as
	 * possible, using a sched_activity array to collect metrics with
	 * limited collision, then we'll report statistics only. The tasks'
	 * #calls will reflect the number of occurrences, and the lat_time will
	 * reflect the latency when set. We prefer to take the time before
	 * calling thread_isolate() so that the wait time doesn't impact the
	 * measurement accuracy. However this requires to take care of negative
	 * times since tasks might be queued after we retrieve it.
	 */

	now_ns = now_mono_time();
	memset(tmp_activity, 0, sizeof(tmp_activity));

	thread_isolate();

	/* 1. global run queue */

#ifdef USE_THREAD
	rqnode = eb32sc_first(&rqueue, ~0UL);
	while (rqnode) {
		t = eb32sc_entry(rqnode, struct task, rq);
		entry = sched_activity_entry(tmp_activity, t->process);
		if (t->call_date) {
			lat = now_ns - t->call_date;
			if ((int64_t)lat > 0)
				entry->lat_time += lat;
		}
		entry->calls++;
		rqnode = eb32sc_next(rqnode, ~0UL);
	}
#endif
	/* 2. all threads's local run queues */
	for (thr = 0; thr < global.nbthread; thr++) {
		/* task run queue */
		rqnode = eb32sc_first(&task_per_thread[thr].rqueue, ~0UL);
		while (rqnode) {
			t = eb32sc_entry(rqnode, struct task, rq);
			entry = sched_activity_entry(tmp_activity, t->process);
			if (t->call_date) {
				lat = now_ns - t->call_date;
				if ((int64_t)lat > 0)
					entry->lat_time += lat;
			}
			entry->calls++;
			rqnode = eb32sc_next(rqnode, ~0UL);
		}

		/* shared tasklet list */
		list_for_each_entry(tl, mt_list_to_list(&task_per_thread[thr].shared_tasklet_list), list) {
			t = (const struct task *)tl;
			entry = sched_activity_entry(tmp_activity, t->process);
			if (!TASK_IS_TASKLET(t) && t->call_date) {
				lat = now_ns - t->call_date;
				if ((int64_t)lat > 0)
					entry->lat_time += lat;
			}
			entry->calls++;
		}

		/* classful tasklets */
		for (queue = 0; queue < TL_CLASSES; queue++) {
			list_for_each_entry(tl, &task_per_thread[thr].tasklets[queue], list) {
				t = (const struct task *)tl;
				entry = sched_activity_entry(tmp_activity, t->process);
				if (!TASK_IS_TASKLET(t) && t->call_date) {
					lat = now_ns - t->call_date;
					if ((int64_t)lat > 0)
						entry->lat_time += lat;
				}
				entry->calls++;
			}
		}
	}

	/* hopefully we're done */
	thread_release();

	chunk_reset(&trash);

	tot_calls = 0;
	for (i = 0; i < 256; i++)
		tot_calls += tmp_activity[i].calls;

	qsort(tmp_activity, 256, sizeof(tmp_activity[0]), cmp_sched_activity);

	chunk_appendf(&trash, "Running tasks: %d (%d threads)\n"
		      "  function                     places     %%    lat_tot   lat_avg\n",
		      (int)tot_calls, global.nbthread);

	for (i = 0; i < 256 && tmp_activity[i].calls; i++) {
		chunk_reset(name_buffer);

		if (!tmp_activity[i].func)
			chunk_printf(name_buffer, "other");
		else
			resolve_sym_name(name_buffer, "", tmp_activity[i].func);

		/* reserve 35 chars for name+' '+#calls, knowing that longer names
		 * are often used for less often called functions.
		 */
		max = 35 - name_buffer->data;
		if (max < 1)
			max = 1;
		chunk_appendf(&trash, "  %s%*llu  %3d.%1d",
		              name_buffer->area, max, (unsigned long long)tmp_activity[i].calls,
		              (int)(100ULL * tmp_activity[i].calls / tot_calls),
		              (int)((1000ULL * tmp_activity[i].calls / tot_calls)%10));
		print_time_short(&trash, "   ", tmp_activity[i].lat_time, "");
		print_time_short(&trash, "   ", tmp_activity[i].lat_time / tmp_activity[i].calls, "\n");
	}

	if (ci_putchk(si_ic(si), &trash) == -1) {
		/* failed, try again */
		si_rx_room_blk(si);
		return 0;
	}
	return 1;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "profiling.tasks",      cfg_parse_prof_tasks      },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "profiling", NULL }, "show profiling : show CPU profiling options",   NULL, cli_io_handler_show_profiling, NULL },
	{ { "show", "tasks", NULL },     "show tasks     : show running tasks",           NULL, cli_io_handler_show_tasks,     NULL },
	{ { "set",  "profiling", NULL }, "set  profiling : enable/disable CPU profiling", cli_parse_set_profiling,  NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
