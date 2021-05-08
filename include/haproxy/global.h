/*
 * include/haproxy/global.h
 * Exported global variables and functions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_GLOBAL_H
#define _HAPROXY_GLOBAL_H

#include <haproxy/api-t.h>
#include <haproxy/global-t.h>

extern const char *build_features;
extern struct global global;
extern int  pid;                /* current process id */
extern int  relative_pid;       /* process id starting at 1 */
extern unsigned long pid_bit;   /* bit corresponding to the process id */
extern unsigned long all_proc_mask; /* mask of all processes */
extern int  actconn;            /* # of active sessions */
extern int  listeners;
extern int  jobs;               /* # of active jobs (listeners, sessions, open devices) */
extern int  unstoppable_jobs;   /* # of active jobs that can't be stopped during a soft stop */
extern int  active_peers;       /* # of active peers (connection attempts and successes) */
extern int  connected_peers;    /* # of really connected peers */
extern int nb_oldpids;          /* contains the number of old pids found */
extern const int zero;
extern const int one;
extern const struct linger nolinger;
extern int stopping;	/* non zero means stopping in progress */
extern int killed;	/* >0 means a hard-stop is triggered, >1 means hard-stop immediately */
extern char hostname[MAX_HOSTNAME_LEN];
extern char *localpeer;
extern unsigned int warned;     /* bitfield of a few warnings to emit just once */
extern volatile unsigned long sleeping_thread_mask;
extern struct list proc_list; /* list of process in mworker mode */
extern int master; /* 1 if in master, 0 otherwise */
extern unsigned int rlim_fd_cur_at_boot;
extern unsigned int rlim_fd_max_at_boot;
extern int atexit_flag;
extern unsigned char boot_seed[20];  // per-boot random seed (160 bits initially)
extern THREAD_LOCAL struct buffer trash;

extern struct task *stopping_task[MAX_PROCS];

struct proxy;
struct server;
int main(int argc, char **argv);
void deinit(void);
__attribute__((noreturn)) void deinit_and_exit(int);
void run_poll_loop(void);
int tell_old_pids(int sig);
int delete_oldpid(int pid);
void hap_register_build_opts(const char *str, int must_free);
int split_version(const char *version, unsigned int *value);
int compare_current_version(const char *version);

void mworker_accept_wrapper(int fd);
void mworker_reload();

/* to be used with warned and WARN_* */
static inline int already_warned(unsigned int warning)
{
	if (warned & warning)
		return 1;
	warned |= warning;
	return 0;
}

/* returns a mask if set, otherwise all_proc_mask */
static inline unsigned long proc_mask(unsigned long mask)
{
	return mask ? mask : all_proc_mask;
}

/* handle 'tainted' status */
enum tainted_flags {
	TAINTED_CONFIG_EXP_KW_DECLARED = 0x1,
	TAINTED_ACTION_EXP_EXECUTED    = 0x2,
	TAINTED_CLI_EXPERT_MODE        = 0x4,
	TAINTED_CLI_EXPERIMENTAL_MODE  = 0x8,
};
void mark_tainted(const enum tainted_flags flag);
unsigned int get_tainted();

extern unsigned int experimental_directives_allowed;

struct cfg_keyword;
int check_kw_experimental(struct cfg_keyword *kw, const char *file, int linenum,
                          char **errmsg);

/* simplified way to declare static build options in a file */
#define REGISTER_BUILD_OPTS(str) \
	INITCALL2(STG_REGISTER, hap_register_build_opts, (str), 0)

#endif /* _HAPROXY_GLOBAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
