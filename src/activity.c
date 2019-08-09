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

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/standard.h>
#include <common/hathreads.h>
#include <common/initcall.h>
#include <types/activity.h>
#include <proto/channel.h>
#include <proto/cli.h>
#include <proto/freq_ctr.h>
#include <proto/stream_interface.h>


/* bit field of profiling options. Beware, may be modified at runtime! */
unsigned int profiling = HA_PROF_TASKS_AUTO;
unsigned long task_profiling_mask = 0;

/* One struct per thread containing all collected measurements */
struct activity activity[MAX_THREADS] __attribute__((aligned(64))) = { };


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
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_ON;
	else if (strcmp(args[1], "auto") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AUTO;
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
		while (!_HA_ATOMIC_CAS(&profiling, &old, (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_ON))
			;
	}
	else if (strcmp(args[3], "auto") == 0) {
		unsigned int old = profiling;
		while (!_HA_ATOMIC_CAS(&profiling, &old, (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AUTO))
			;
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

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_profiling(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	const char *str;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	switch (profiling & HA_PROF_TASKS_MASK) {
	case HA_PROF_TASKS_AUTO: str="auto"; break;
	case HA_PROF_TASKS_ON:   str="on"; break;
	default:                 str="off"; break;
	}

	chunk_printf(&trash,
	             "Per-task CPU profiling              : %s      # set profiling tasks {on|auto|off}\n",
	             str);

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
	{ { "set",  "profiling", NULL }, "set  profiling : enable/disable CPU profiling", cli_parse_set_profiling,  NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
