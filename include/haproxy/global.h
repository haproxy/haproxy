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
#include <haproxy/mworker-t.h>
#include <haproxy/vars-t.h>

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
extern struct mworker_proc *proc_self; /* process structure of current process */
extern int master; /* 1 if in master, 0 otherwise */
extern unsigned int rlim_fd_cur_at_boot;
extern unsigned int rlim_fd_max_at_boot;
extern int atexit_flag;
extern unsigned char boot_seed[20];  // per-boot random seed (160 bits initially)
extern THREAD_LOCAL struct buffer trash;

struct proxy;
struct server;
int main(int argc, char **argv);
void deinit(void);
__attribute__((noreturn)) void deinit_and_exit(int);
void run_poll_loop(void);
int tell_old_pids(int sig);
int delete_oldpid(int pid);
void hap_register_build_opts(const char *str, int must_free);
void hap_register_post_check(int (*fct)());
void hap_register_post_proxy_check(int (*fct)(struct proxy *));
void hap_register_post_server_check(int (*fct)(struct server *));
void hap_register_post_deinit(void (*fct)());
void hap_register_proxy_deinit(void (*fct)(struct proxy *));
void hap_register_server_deinit(void (*fct)(struct server *));

void hap_register_per_thread_alloc(int (*fct)());
void hap_register_per_thread_init(int (*fct)());
void hap_register_per_thread_deinit(void (*fct)());
void hap_register_per_thread_free(void (*fct)());

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

/* returns a mask if set, otherwise all_threads_mask */
static inline unsigned long thread_mask(unsigned long mask)
{
	return mask ? mask : all_threads_mask;
}

/* simplified way to declare static build options in a file */
#define REGISTER_BUILD_OPTS(str) \
	INITCALL2(STG_REGISTER, hap_register_build_opts, (str), 0)

/* simplified way to declare a post-check callback in a file */
#define REGISTER_POST_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_check, (fct))

/* simplified way to declare a post-proxy-check callback in a file */
#define REGISTER_POST_PROXY_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_proxy_check, (fct))

/* simplified way to declare a post-server-check callback in a file */
#define REGISTER_POST_SERVER_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_server_check, (fct))

/* simplified way to declare a post-deinit callback in a file */
#define REGISTER_POST_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_deinit, (fct))

/* simplified way to declare a proxy-deinit callback in a file */
#define REGISTER_PROXY_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_proxy_deinit, (fct))

/* simplified way to declare a proxy-deinit callback in a file */
#define REGISTER_SERVER_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_server_deinit, (fct))

/* simplified way to declare a per-thread allocation callback in a file */
#define REGISTER_PER_THREAD_ALLOC(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_alloc, (fct))

/* simplified way to declare a per-thread init callback in a file */
#define REGISTER_PER_THREAD_INIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_init, (fct))

/* simplified way to declare a per-thread deinit callback in a file */
#define REGISTER_PER_THREAD_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_deinit, (fct))

/* simplified way to declare a per-thread free callback in a file */
#define REGISTER_PER_THREAD_FREE(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_free, (fct))

#endif /* _HAPROXY_GLOBAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
