/*
 * HA-Proxy : High Availability-enabled HTTP/TCP proxy
 * Copyright 2000-2017 Willy Tarreau <willy@haproxy.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Please refer to RFC7230 - RFC7235 informations about HTTP protocol, and
 * RFC6265 for informations about cookies usage. More generally, the IETF HTTP
 * Working Group's web site should be consulted for protocol related changes :
 *
 *     http://ftp.ics.uci.edu/pub/ietf/http/
 *
 * Pending bugs (may be not fixed because never reproduced) :
 *   - solaris only : sometimes, an HTTP proxy with only a dispatch address causes
 *     the proxy to terminate (no core) if the client breaks the connection during
 *     the response. Seen on 1.1.8pre4, but never reproduced. May not be related to
 *     the snprintf() bug since requests were simple (GET / HTTP/1.0), but may be
 *     related to missing setsid() (fixed in 1.1.15)
 *   - a proxy with an invalid config will prevent the startup even if disabled.
 *
 * ChangeLog has moved to the CHANGELOG file.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <syslog.h>
#include <grp.h>
#ifdef USE_CPU_AFFINITY
#include <sched.h>
#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
#include <pthread_np.h>
#endif
#endif

#ifdef DEBUG_FULL
#include <assert.h>
#endif
#if defined(USE_SYSTEMD)
#include <systemd/sd-daemon.h>
#endif

#include <common/base64.h>
#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/defaults.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/namespace.h>
#include <common/regex.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>
#include <common/hathreads.h>

#include <types/capture.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/acl.h>
#include <types/peers.h>

#include <proto/acl.h>
#include <proto/applet.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/filters.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/protocol.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/signal.h>
#include <proto/task.h>
#include <proto/dns.h>
#include <proto/vars.h>
#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif

/* list of config files */
static struct list cfg_cfgfiles = LIST_HEAD_INIT(cfg_cfgfiles);
int  pid;			/* current process id */
int  relative_pid = 1;		/* process id starting at 1 */
unsigned long pid_bit = 1;      /* bit corresponding to the process id */

/* global options */
struct global global = {
	.hard_stop_after = TICK_ETERNITY,
	.nbproc = 1,
	.nbthread = 1,
	.req_count = 0,
	.logsrvs = LIST_HEAD_INIT(global.logsrvs),
	.maxzlibmem = 0,
	.comp_rate_lim = 0,
	.ssl_server_verify = SSL_SERVER_VERIFY_REQUIRED,
	.unix_bind = {
		 .ux = {
			 .uid = -1,
			 .gid = -1,
			 .mode = 0,
		 }
	},
	.tune = {
		.bufsize = BUFSIZE,
		.maxrewrite = -1,
		.chksize = BUFSIZE,
		.reserved_bufs = RESERVED_BUFS,
		.pattern_cache = DEFAULT_PAT_LRU_SIZE,
#ifdef USE_OPENSSL
		.sslcachesize = SSLCACHESIZE,
#endif
		.comp_maxlevel = 1,
#ifdef DEFAULT_IDLE_TIMER
		.idle_timer = DEFAULT_IDLE_TIMER,
#else
		.idle_timer = 1000, /* 1 second */
#endif
	},
#ifdef USE_OPENSSL
#ifdef DEFAULT_MAXSSLCONN
	.maxsslconn = DEFAULT_MAXSSLCONN,
#endif
#endif
	/* others NULL OK */
};

/*********************************************************************/

int stopping;	/* non zero means stopping in progress */
int killed;	/* non zero means a hard-stop is triggered */
int jobs = 0;   /* number of active jobs (conns, listeners, active tasks, ...) */

/* Here we store informations about the pids of the processes we may pause
 * or kill. We will send them a signal every 10 ms until we can bind to all
 * our ports. With 200 retries, that's about 2 seconds.
 */
#define MAX_START_RETRIES	200
static int *oldpids = NULL;
static int oldpids_sig; /* use USR1 or TERM */

/* Path to the unix socket we use to retrieve listener sockets from the old process */
static const char *old_unixsocket;

static char *cur_unixsocket = NULL;

int atexit_flag = 0;

int nb_oldpids = 0;
const int zero = 0;
const int one = 1;
const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };

char hostname[MAX_HOSTNAME_LEN];
char localpeer[MAX_HOSTNAME_LEN];

/* used from everywhere just to drain results we don't want to read and which
 * recent versions of gcc increasingly and annoyingly complain about.
 */
int shut_your_big_mouth_gcc_int = 0;

int *children = NULL; /* store PIDs of children in master workers mode */

static volatile sig_atomic_t caught_signal = 0;
static char **next_argv = NULL;

int mworker_pipe[2];

/* list of the temporarily limited listeners because of lack of resource */
struct list global_listener_queue = LIST_HEAD_INIT(global_listener_queue);
struct task *global_listener_queue_task;
static struct task *manage_global_listener_queue(struct task *t);

/* bitfield of a few warnings to emit just once (WARN_*) */
unsigned int warned = 0;


/* These are strings to be reported in the output of "haproxy -vv". They may
 * either be constants (in which case must_free must be zero) or dynamically
 * allocated strings to pass to free() on exit, and in this case must_free
 * must be non-zero.
 */
struct list build_opts_list = LIST_HEAD_INIT(build_opts_list);
struct build_opts_str {
	struct list list;
	const char *str;
	int must_free;
};

/* These functions are called just after the point where the program exits
 * after a config validity check, so they are generally suited for resource
 * allocation and slow initializations that should be skipped during basic
 * config checks. The functions must return 0 on success, or a combination
 * of ERR_* flags (ERR_WARN, ERR_ABORT, ERR_FATAL, ...). The 2 latter cause
 * and immediate exit, so the function must have emitted any useful error.
 */
struct list post_check_list = LIST_HEAD_INIT(post_check_list);
struct post_check_fct {
	struct list list;
	int (*fct)();
};

/* These functions are called when freeing the global sections at the end
 * of deinit, after everything is stopped. They don't return anything, and
 * they work in best effort mode as their sole goal is to make valgrind
 * mostly happy.
 */
struct list post_deinit_list = LIST_HEAD_INIT(post_deinit_list);
struct post_deinit_fct {
	struct list list;
	void (*fct)();
};

/* These functions are called for each thread just after the thread creation
 * and before running the scheduler. They should be used to do per-thread
 * initializations. They must return 0 if an error occurred. */
struct list per_thread_init_list = LIST_HEAD_INIT(per_thread_init_list);
struct per_thread_init_fct {
	struct list list;
	int (*fct)();
};

/* These functions are called for each thread just after the scheduler loop and
 * before exiting the thread. They don't return anything and, as for post-deinit
 * functions, they work in best effort mode as their sole goal is to make
 * valgrind mostly happy. */
struct list per_thread_deinit_list = LIST_HEAD_INIT(per_thread_deinit_list);
struct per_thread_deinit_fct {
	struct list list;
	void (*fct)();
};

/*********************************************************************/
/*  general purpose functions  ***************************************/
/*********************************************************************/

/* used to register some build option strings at boot. Set must_free to
 * non-zero if the string must be freed upon exit.
 */
void hap_register_build_opts(const char *str, int must_free)
{
	struct build_opts_str *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->str = str;
	b->must_free = must_free;
	LIST_ADDQ(&build_opts_list, &b->list);
}

/* used to register some initialization functions to call after the checks. */
void hap_register_post_check(int (*fct)())
{
	struct post_check_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_ADDQ(&post_check_list, &b->list);
}

/* used to register some de-initialization functions to call after everything
 * has stopped.
 */
void hap_register_post_deinit(void (*fct)())
{
	struct post_deinit_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_ADDQ(&post_deinit_list, &b->list);
}

/* used to register some initialization functions to call for each thread. */
void hap_register_per_thread_init(int (*fct)())
{
	struct per_thread_init_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_ADDQ(&per_thread_init_list, &b->list);
}

/* used to register some de-initialization functions to call for each thread. */
void hap_register_per_thread_deinit(void (*fct)())
{
	struct per_thread_deinit_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_ADDQ(&per_thread_deinit_list, &b->list);
}

static void display_version()
{
	printf("HA-Proxy version " HAPROXY_VERSION " " HAPROXY_DATE"\n");
	printf("Copyright 2000-2017 Willy Tarreau <willy@haproxy.org>\n\n");
}

static void display_build_opts()
{
	struct build_opts_str *item;

	printf("Build options :"
#ifdef BUILD_TARGET
	       "\n  TARGET  = " BUILD_TARGET
#endif
#ifdef BUILD_CPU
	       "\n  CPU     = " BUILD_CPU
#endif
#ifdef BUILD_CC
	       "\n  CC      = " BUILD_CC
#endif
#ifdef BUILD_CFLAGS
	       "\n  CFLAGS  = " BUILD_CFLAGS
#endif
#ifdef BUILD_OPTIONS
	       "\n  OPTIONS = " BUILD_OPTIONS
#endif
	       "\n\nDefault settings :"
	       "\n  maxconn = %d, bufsize = %d, maxrewrite = %d, maxpollevents = %d"
	       "\n\n",
	       DEFAULT_MAXCONN, BUFSIZE, MAXREWRITE, MAX_POLL_EVENTS);

	list_for_each_entry(item, &build_opts_list, list) {
		puts(item->str);
	}

	putchar('\n');

	list_pollers(stdout);
	putchar('\n');
	list_filters(stdout);
	putchar('\n');
}

/*
 * This function prints the command line usage and exits
 */
static void usage(char *name)
{
	display_version();
	fprintf(stderr,
		"Usage : %s [-f <cfgfile|cfgdir>]* [ -vdV"
		"D ] [ -n <maxconn> ] [ -N <maxpconn> ]\n"
		"        [ -p <pidfile> ] [ -m <max megs> ] [ -C <dir> ] [-- <cfgfile>*]\n"
		"        -v displays version ; -vv shows known build options.\n"
		"        -d enters debug mode ; -db only disables background mode.\n"
		"        -dM[<byte>] poisons memory with <byte> (defaults to 0x50)\n"
		"        -V enters verbose mode (disables quiet mode)\n"
		"        -D goes daemon ; -C changes to <dir> before loading files.\n"
		"        -W master-worker mode.\n"
#if defined(USE_SYSTEMD)
		"        -Ws master-worker mode with systemd notify support.\n"
#endif
		"        -q quiet mode : don't display messages\n"
		"        -c check mode : only check config files and exit\n"
		"        -n sets the maximum total # of connections (%d)\n"
		"        -m limits the usable amount of memory (in MB)\n"
		"        -N sets the default, per-proxy maximum # of connections (%d)\n"
		"        -L set local peer name (default to hostname)\n"
		"        -p writes pids of all children to this file\n"
#if defined(ENABLE_EPOLL)
		"        -de disables epoll() usage even when available\n"
#endif
#if defined(ENABLE_KQUEUE)
		"        -dk disables kqueue() usage even when available\n"
#endif
#if defined(ENABLE_POLL)
		"        -dp disables poll() usage even when available\n"
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE)
		"        -dS disables splice usage (broken on old kernels)\n"
#endif
#if defined(USE_GETADDRINFO)
		"        -dG disables getaddrinfo() usage\n"
#endif
#if defined(SO_REUSEPORT)
		"        -dR disables SO_REUSEPORT usage\n"
#endif
		"        -dr ignores server address resolution failures\n"
		"        -dV disables SSL verify on servers side\n"
		"        -sf/-st [pid ]* finishes/terminates old pids.\n"
		"        -x <unix_socket> get listening sockets from a unix socket\n"
		"\n",
		name, DEFAULT_MAXCONN, cfg_maxpconn);
	exit(1);
}



/*********************************************************************/
/*   more specific functions   ***************************************/
/*********************************************************************/

/* sends the signal <sig> to all pids found in <oldpids>. Returns the number of
 * pids the signal was correctly delivered to.
 */
static int tell_old_pids(int sig)
{
	int p;
	int ret = 0;
	for (p = 0; p < nb_oldpids; p++)
		if (kill(oldpids[p], sig) == 0)
			ret++;
	return ret;
}

/* return 1 if a pid is a current child otherwise 0 */

int current_child(int pid)
{
	int i;

	for (i = 0; i < global.nbproc; i++) {
		if (children[i] == pid)
			return 1;
	}
	return 0;
}

static void mworker_signalhandler(int signum)
{
	caught_signal = signum;
}

static void mworker_register_signals()
{
	struct sigaction sa;
	/* Here we are not using the haproxy async way
	for signals because it does not exists in
	the master */
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = &mworker_signalhandler;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void mworker_block_signals()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_SETMASK, &set, NULL);
}

static void mworker_unblock_signals()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &set, NULL);
}

static void mworker_unregister_signals()
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGHUP,  SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
}

/*
 * Send signal to every known children.
 */

static void mworker_kill(int sig)
{
	int i;

	tell_old_pids(sig);
	if (children) {
		for (i = 0; i < global.nbproc; i++)
			kill(children[i], sig);
	}
}

/*
 * Upon a reload, the master worker needs to close all listeners FDs but the mworker_pipe
 * fd, and the FD provided by fd@
 */
static void mworker_cleanlisteners()
{
	struct listener *l, *l_next;
	struct proxy *curproxy;
	struct peers *curpeers;

	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		/* we might have to unbind some peers sections from some processes */
		for (curpeers = cfg_peers; curpeers; curpeers = curpeers->next) {
			if (!curpeers->peers_fe)
				continue;

			stop_proxy(curpeers->peers_fe);
			/* disable this peer section so that it kills itself */
			signal_unregister_handler(curpeers->sighandler);
			task_delete(curpeers->sync_task);
			task_free(curpeers->sync_task);
			curpeers->sync_task = NULL;
			task_free(curpeers->peers_fe->task);
			curpeers->peers_fe->task = NULL;
			curpeers->peers_fe = NULL;
		}

		list_for_each_entry_safe(l, l_next, &curproxy->conf.listeners, by_fe) {
			/* does not close if the FD is inherited with fd@
			 * from the parent process */
			if (!(l->options & LI_O_INHERITED)) {
				close(l->fd);
				LIST_DEL(&l->by_fe);
				LIST_DEL(&l->by_bind);
				free(l->name);
				free(l->counters);
				free(l);
			}
		}
	}
}


/*
 * remove a pid forom the olpid array and decrease nb_oldpids
 * return 1 pid was found otherwise return 0
 */

int delete_oldpid(int pid)
{
	int i;

	for (i = 0; i < nb_oldpids; i++) {
		if (oldpids[i] == pid) {
			oldpids[i] = oldpids[nb_oldpids - 1];
			oldpids[nb_oldpids - 1] = 0;
			nb_oldpids--;
			return 1;
		}
	}
	return 0;
}


static void get_cur_unixsocket()
{
	/* if -x was used, try to update the stat socket if not available anymore */
	if (global.stats_fe) {
		struct bind_conf *bind_conf;

		/* pass through all stats socket */
		list_for_each_entry(bind_conf, &global.stats_fe->conf.bind, by_fe) {
			struct listener *l;

			list_for_each_entry(l, &bind_conf->listeners, by_bind) {

				if (l->addr.ss_family == AF_UNIX &&
				    (bind_conf->level & ACCESS_FD_LISTENERS)) {
					const struct sockaddr_un *un;

					un = (struct sockaddr_un *)&l->addr;
					/* priority to old_unixsocket */
					if (!cur_unixsocket) {
						cur_unixsocket = strdup(un->sun_path);
					} else {
						if (old_unixsocket && !strcmp(un->sun_path, old_unixsocket)) {
							free(cur_unixsocket);
							cur_unixsocket = strdup(old_unixsocket);
							return;
						}
					}
				}
			}
		}
	}
	if (!cur_unixsocket && old_unixsocket)
		cur_unixsocket = strdup(old_unixsocket);
}

/*
 * When called, this function reexec haproxy with -sf followed by current
 * children PIDs and possibily old children PIDs if they didn't leave yet.
 */
static void mworker_reload()
{
	int next_argc = 0;
	int j;
	char *msg = NULL;

	mworker_block_signals();
	mworker_unregister_signals();
#if defined(USE_SYSTEMD)
	if (global.tune.options & GTUNE_USE_SYSTEMD)
		sd_notify(0, "RELOADING=1");
#endif
	setenv("HAPROXY_MWORKER_REEXEC", "1", 1);

	/* compute length  */
	while (next_argv[next_argc])
		next_argc++;

	/* 1 for haproxy -sf, 2 for -x /socket */
	next_argv = realloc(next_argv, (next_argc + 1 + 2 + global.nbproc + nb_oldpids + 1) * sizeof(char *));
	if (next_argv == NULL)
		goto alloc_error;


	/* add -sf <PID>*  to argv */
	if (children || nb_oldpids > 0)
		next_argv[next_argc++] = "-sf";
	if (children) {
		for (j = 0; j < global.nbproc; next_argc++,j++) {
			next_argv[next_argc] = memprintf(&msg, "%d", children[j]);
			if (next_argv[next_argc] == NULL)
				goto alloc_error;
			msg = NULL;
		}
	}
	/* copy old process PIDs */
	for (j = 0; j < nb_oldpids; next_argc++,j++) {
		next_argv[next_argc] = memprintf(&msg, "%d", oldpids[j]);
		if (next_argv[next_argc] == NULL)
			goto alloc_error;
		msg = NULL;
	}
	next_argv[next_argc] = NULL;

	/* add the -x option with the stat socket */
	if (cur_unixsocket) {

		next_argv[next_argc++] = "-x";
		next_argv[next_argc++] = (char *)cur_unixsocket;
		next_argv[next_argc++] = NULL;
	}

	ha_warning("Reexecuting Master process\n");
	execvp(next_argv[0], next_argv);

	ha_warning("Failed to reexecute the master process [%d]: %s\n", pid, strerror(errno));
	return;

alloc_error:
	ha_warning("Failed to reexecute the master processs [%d]: Cannot allocate memory\n", pid);
	return;
}


/*
 * Wait for every children to exit
 */

static void mworker_wait()
{
	int exitpid = -1;
	int status = 0;

restart_wait:

#if defined(USE_SYSTEMD)
	if (global.tune.options & GTUNE_USE_SYSTEMD)
		sd_notifyf(0, "READY=1\nMAINPID=%lu", (unsigned long)getpid());
#endif

	mworker_register_signals();
	mworker_unblock_signals();

	while (1) {

		while (((exitpid = wait(&status)) == -1) && errno == EINTR) {
			int sig = caught_signal;
			if (sig == SIGUSR2 || sig == SIGHUP) {
				mworker_reload();
				/* should reach there only if it fail */
				goto restart_wait;
			} else {
#if defined(USE_SYSTEMD)
				if ((global.tune.options & GTUNE_USE_SYSTEMD) && (sig == SIGUSR1 || sig == SIGTERM)) {
					sd_notify(0, "STOPPING=1");
				}
#endif
				ha_warning("Exiting Master process...\n");
				mworker_kill(sig);
				mworker_unregister_signals();
			}
			caught_signal = 0;
		}

		if (exitpid == -1 && errno == ECHILD) {
			ha_warning("All workers exited. Exiting... (%d)\n", status);
			atexit_flag = 0;
			exit(status); /* parent must leave using the latest status code known */
		}

		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			status = 128 + WTERMSIG(status);
		else if (WIFSTOPPED(status))
			status = 128 + WSTOPSIG(status);
		else
			status = 255;

		if (!children) {
			ha_warning("Worker %d exited with code %d\n", exitpid, status);
		} else {
			/* check if exited child was in the current children list */
			if (current_child(exitpid)) {
				ha_alert("Current worker %d exited with code %d\n", exitpid, status);
				if (status != 0 && status != 130 && status != 143
				    && !(global.tune.options & GTUNE_NOEXIT_ONFAILURE)) {
					ha_alert("exit-on-failure: killing every workers with SIGTERM\n");
					mworker_kill(SIGTERM);
				}
			} else {
				ha_warning("Former worker %d exited with code %d\n", exitpid, status);
				delete_oldpid(exitpid);
			}
		}
	}
}


/*
 * Reexec the process in failure mode, instead of exiting
 */
void reexec_on_failure()
{
	if (!atexit_flag)
		return;

	setenv("HAPROXY_MWORKER_WAIT_ONLY", "1", 1);

	ha_warning("Reexecuting Master process in waitpid mode\n");
	mworker_reload();
}


/*
 * upon SIGUSR1, let's have a soft stop. Note that soft_stop() broadcasts
 * a signal zero to all subscribers. This means that it's as easy as
 * subscribing to signal 0 to get informed about an imminent shutdown.
 */
static void sig_soft_stop(struct sig_handler *sh)
{
	soft_stop();
	signal_unregister_handler(sh);
	pool_gc(NULL);
}

/*
 * upon SIGTTOU, we pause everything
 */
static void sig_pause(struct sig_handler *sh)
{
	pause_proxies();
	pool_gc(NULL);
}

/*
 * upon SIGTTIN, let's have a soft stop.
 */
static void sig_listen(struct sig_handler *sh)
{
	resume_proxies();
}

/*
 * this function dumps every server's state when the process receives SIGHUP.
 */
static void sig_dump_state(struct sig_handler *sh)
{
	struct proxy *p = proxies_list;

	ha_warning("SIGHUP received, dumping servers states.\n");
	while (p) {
		struct server *s = p->srv;

		send_log(p, LOG_NOTICE, "SIGHUP received, dumping servers states for proxy %s.\n", p->id);
		while (s) {
			chunk_printf(&trash,
			             "SIGHUP: Server %s/%s is %s. Conn: %d act, %d pend, %lld tot.",
			             p->id, s->id,
			             (s->cur_state != SRV_ST_STOPPED) ? "UP" : "DOWN",
			             s->cur_sess, s->nbpend, s->counters.cum_sess);
			ha_warning("%s\n", trash.str);
			send_log(p, LOG_NOTICE, "%s\n", trash.str);
			s = s->next;
		}

		/* FIXME: those info are a bit outdated. We should be able to distinguish between FE and BE. */
		if (!p->srv) {
			chunk_printf(&trash,
			             "SIGHUP: Proxy %s has no servers. Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
			             p->id,
			             p->feconn, p->beconn, p->totpend, p->nbpend, p->fe_counters.cum_conn, p->be_counters.cum_conn);
		} else if (p->srv_act == 0) {
			chunk_printf(&trash,
			             "SIGHUP: Proxy %s %s ! Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
			             p->id,
			             (p->srv_bck) ? "is running on backup servers" : "has no server available",
			             p->feconn, p->beconn, p->totpend, p->nbpend, p->fe_counters.cum_conn, p->be_counters.cum_conn);
		} else {
			chunk_printf(&trash,
			             "SIGHUP: Proxy %s has %d active servers and %d backup servers available."
			             " Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
			             p->id, p->srv_act, p->srv_bck,
			             p->feconn, p->beconn, p->totpend, p->nbpend, p->fe_counters.cum_conn, p->be_counters.cum_conn);
		}
		ha_warning("%s\n", trash.str);
		send_log(p, LOG_NOTICE, "%s\n", trash.str);

		p = p->next;
	}
}

static void dump(struct sig_handler *sh)
{
	/* dump memory usage then free everything possible */
	dump_pools();
	pool_gc(NULL);
}

/*
 *  This function dup2 the stdio FDs (0,1,2) with <fd>, then closes <fd>
 *  If <fd> < 0, it opens /dev/null and use it to dup
 *
 *  In the case of chrooting, you have to open /dev/null before the chroot, and
 *  pass the <fd> to this function
 */
static void stdio_quiet(int fd)
{
	if (fd < 0)
		fd = open("/dev/null", O_RDWR, 0);

	if (fd > -1) {
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
		return;
	}

	ha_alert("Cannot open /dev/null\n");
	exit(EXIT_FAILURE);
}


/* This function check if cfg_cfgfiles containes directories.
 * If it find one, it add all the files (and only files) it containes
 * in cfg_cfgfiles in place of the directory (and remove the directory).
 * It add the files in lexical order.
 * It add only files with .cfg extension.
 * It doesn't add files with name starting with '.'
 */
static void cfgfiles_expand_directories(void)
{
	struct wordlist *wl, *wlb;
	char *err = NULL;

	list_for_each_entry_safe(wl, wlb, &cfg_cfgfiles, list) {
		struct stat file_stat;
		struct dirent **dir_entries = NULL;
		int dir_entries_nb;
		int dir_entries_it;

		if (stat(wl->s, &file_stat)) {
			ha_alert("Cannot open configuration file/directory %s : %s\n",
				 wl->s,
				 strerror(errno));
			exit(1);
		}

		if (!S_ISDIR(file_stat.st_mode))
			continue;

		/* from this point wl->s is a directory */

		dir_entries_nb = scandir(wl->s, &dir_entries, NULL, alphasort);
		if (dir_entries_nb < 0) {
			ha_alert("Cannot open configuration directory %s : %s\n",
				 wl->s,
				 strerror(errno));
			exit(1);
		}

		/* for each element in the directory wl->s */
		for (dir_entries_it = 0; dir_entries_it < dir_entries_nb; dir_entries_it++) {
			struct dirent *dir_entry = dir_entries[dir_entries_it];
			char *filename = NULL;
			char *d_name_cfgext = strstr(dir_entry->d_name, ".cfg");

			/* don't add filename that begin with .
			 * only add filename with .cfg extention
			 */
			if (dir_entry->d_name[0] == '.' ||
			    !(d_name_cfgext && d_name_cfgext[4] == '\0'))
				goto next_dir_entry;

			if (!memprintf(&filename, "%s/%s", wl->s, dir_entry->d_name)) {
				ha_alert("Cannot load configuration files %s : out of memory.\n",
					 filename);
				exit(1);
			}

			if (stat(filename, &file_stat)) {
				ha_alert("Cannot open configuration file %s : %s\n",
					 wl->s,
					 strerror(errno));
				exit(1);
			}

			/* don't add anything else than regular file in cfg_cfgfiles
			 * this way we avoid loops
			 */
			if (!S_ISREG(file_stat.st_mode))
				goto next_dir_entry;

			if (!list_append_word(&wl->list, filename, &err)) {
				ha_alert("Cannot load configuration files %s : %s\n",
					 filename,
					 err);
				exit(1);
			}

next_dir_entry:
			free(filename);
			free(dir_entry);
		}

		free(dir_entries);

		/* remove the current directory (wl) from cfg_cfgfiles */
		free(wl->s);
		LIST_DEL(&wl->list);
		free(wl);
	}

	free(err);
}

static int get_old_sockets(const char *unixsocket)
{
	char *cmsgbuf = NULL, *tmpbuf = NULL;
	int *tmpfd = NULL;
	struct sockaddr_un addr;
	struct cmsghdr *cmsg;
	struct msghdr msghdr;
	struct iovec iov;
	struct xfer_sock_list *xfer_sock = NULL;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	int sock = -1;
	int ret = -1;
	int ret2 = -1;
	int fd_nb;
	int got_fd = 0;
	int i = 0;
	size_t maxoff = 0, curoff = 0;

	memset(&msghdr, 0, sizeof(msghdr));
	cmsgbuf = malloc(CMSG_SPACE(sizeof(int)) * MAX_SEND_FD);
	if (!cmsgbuf) {
		ha_warning("Failed to allocate memory to send sockets\n");
		goto out;
	}
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		ha_warning("Failed to connect to the old process socket '%s'\n",
			   unixsocket);
		goto out;
	}
	strncpy(addr.sun_path, unixsocket, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
	addr.sun_family = PF_UNIX;
	ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		ha_warning("Failed to connect to the old process socket '%s'\n",
			   unixsocket);
		goto out;
	}
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
	iov.iov_base = &fd_nb;
	iov.iov_len = sizeof(fd_nb);
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	send(sock, "_getsocks\n", strlen("_getsocks\n"), 0);
	/* First, get the number of file descriptors to be received */
	if (recvmsg(sock, &msghdr, MSG_WAITALL) != sizeof(fd_nb)) {
		ha_warning("Failed to get the number of sockets to be transferred !\n");
		goto out;
	}
	if (fd_nb == 0) {
		ret = 0;
		goto out;
	}
	tmpbuf = malloc(fd_nb * (1 + MAXPATHLEN + 1 + IFNAMSIZ + sizeof(int)));
	if (tmpbuf == NULL) {
		ha_warning("Failed to allocate memory while receiving sockets\n");
		goto out;
	}
	tmpfd = malloc(fd_nb * sizeof(int));
	if (tmpfd == NULL) {
		ha_warning("Failed to allocate memory while receiving sockets\n");
		goto out;
	}
	msghdr.msg_control = cmsgbuf;
	msghdr.msg_controllen = CMSG_SPACE(sizeof(int)) * MAX_SEND_FD;
	iov.iov_len = MAX_SEND_FD * (1 + MAXPATHLEN + 1 + IFNAMSIZ + sizeof(int));
	do {
		int ret3;

		iov.iov_base = tmpbuf + curoff;
		ret = recvmsg(sock, &msghdr, 0);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret <= 0)
			break;
		/* Send an ack to let the sender know we got the sockets
		 * and it can send some more
		 */
		do {
			ret3 = send(sock, &got_fd, sizeof(got_fd), 0);
		} while (ret3 == -1 && errno == EINTR);
		for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_RIGHTS) {
				size_t totlen = cmsg->cmsg_len -
				    CMSG_LEN(0);
				if (totlen / sizeof(int) + got_fd > fd_nb) {
					ha_warning("Got to many sockets !\n");
					goto out;
				}
				/*
				 * Be paranoid and use memcpy() to avoid any
				 * potential alignement issue.
				 */
				memcpy(&tmpfd[got_fd], CMSG_DATA(cmsg), totlen);
				got_fd += totlen / sizeof(int);
			}
		}
		curoff += ret;
	} while (got_fd < fd_nb);

	if (got_fd != fd_nb) {
		ha_warning("We didn't get the expected number of sockets (expecting %d got %d)\n",
			   fd_nb, got_fd);
		goto out;
	}
	maxoff = curoff;
	curoff = 0;
	for (i = 0; i < got_fd; i++) {
		int fd = tmpfd[i];
		socklen_t socklen;
		int len;

		xfer_sock = calloc(1, sizeof(*xfer_sock));
		if (!xfer_sock) {
			ha_warning("Failed to allocate memory in get_old_sockets() !\n");
			break;
		}
		xfer_sock->fd = -1;

		socklen = sizeof(xfer_sock->addr);
		if (getsockname(fd, (struct sockaddr *)&xfer_sock->addr, &socklen) != 0) {
			ha_warning("Failed to get socket address\n");
			free(xfer_sock);
			xfer_sock = NULL;
			continue;
		}
		if (curoff >= maxoff) {
			ha_warning("Inconsistency while transferring sockets\n");
			goto out;
		}
		len = tmpbuf[curoff++];
		if (len > 0) {
			/* We have a namespace */
			if (curoff + len > maxoff) {
				ha_warning("Inconsistency while transferring sockets\n");
				goto out;
			}
			xfer_sock->namespace = malloc(len + 1);
			if (!xfer_sock->namespace) {
				ha_warning("Failed to allocate memory while transferring sockets\n");
				goto out;
			}
			memcpy(xfer_sock->namespace, &tmpbuf[curoff], len);
			xfer_sock->namespace[len] = 0;
			curoff += len;
		}
		if (curoff >= maxoff) {
			ha_warning("Inconsistency while transferring sockets\n");
			goto out;
		}
		len = tmpbuf[curoff++];
		if (len > 0) {
			/* We have an interface */
			if (curoff + len > maxoff) {
				ha_warning("Inconsistency while transferring sockets\n");
				goto out;
			}
			xfer_sock->iface = malloc(len + 1);
			if (!xfer_sock->iface) {
				ha_warning("Failed to allocate memory while transferring sockets\n");
				goto out;
			}
			memcpy(xfer_sock->iface, &tmpbuf[curoff], len);
			xfer_sock->namespace[len] = 0;
			curoff += len;
		}
		if (curoff + sizeof(int) > maxoff) {
			ha_warning("Inconsistency while transferring sockets\n");
			goto out;
		}
		memcpy(&xfer_sock->options, &tmpbuf[curoff],
		    sizeof(xfer_sock->options));
		curoff += sizeof(xfer_sock->options);

		xfer_sock->fd = fd;
		if (xfer_sock_list)
			xfer_sock_list->prev = xfer_sock;
		xfer_sock->next = xfer_sock_list;
		xfer_sock->prev = NULL;
		xfer_sock_list = xfer_sock;
		xfer_sock = NULL;
	}

	ret2 = 0;
out:
	/* If we failed midway make sure to close the remaining
	 * file descriptors
	 */
	if (tmpfd != NULL && i < got_fd) {
		for (; i < got_fd; i++) {
			close(tmpfd[i]);
		}
	}
	free(tmpbuf);
	free(tmpfd);
	free(cmsgbuf);
	if (sock != -1)
		close(sock);
	if (xfer_sock) {
		free(xfer_sock->namespace);
		free(xfer_sock->iface);
		if (xfer_sock->fd != -1)
			close(xfer_sock->fd);
		free(xfer_sock);
	}
	return (ret2);
}

/*
 * copy and cleanup the current argv
 * Remove the -sf /-st parameters
 * Return an allocated copy of argv
 */

static char **copy_argv(int argc, char **argv)
{
	char **newargv;
	int i = 0, j = 0;

	newargv = calloc(argc + 2, sizeof(char *));
	if (newargv == NULL) {
		ha_warning("Cannot allocate memory\n");
		return NULL;
	}

	while (i < argc) {
		/* -sf or -st or -x */
		if (i > 0 && argv[i][0] == '-' &&
		    ((argv[i][1] == 's' && (argv[i][2] == 'f' || argv[i][2] == 't')) || argv[i][1] == 'x' )) {
			/* list of pids to finish ('f') or terminate ('t') or unix socket (-x) */
			i++;
			while (i < argc && argv[i][0] != '-') {
				i++;
			}
			continue;
		}

		newargv[j++] = argv[i++];
	}

	return newargv;
}

/*
 * This function initializes all the necessary variables. It only returns
 * if everything is OK. If something fails, it exits.
 */
static void init(int argc, char **argv)
{
	int arg_mode = 0;	/* MODE_DEBUG, ... */
	char *tmp;
	char *cfg_pidfile = NULL;
	int err_code = 0;
	char *err_msg = NULL;
	struct wordlist *wl;
	char *progname;
	char *change_dir = NULL;
	struct proxy *px;
	struct post_check_fct *pcf;

	global.mode = MODE_STARTING;
	next_argv = copy_argv(argc, argv);

	if (!init_trash_buffers(1)) {
		ha_alert("failed to initialize trash buffers.\n");
		exit(1);
	}

	/* NB: POSIX does not make it mandatory for gethostname() to NULL-terminate
	 * the string in case of truncation, and at least FreeBSD appears not to do
	 * it.
	 */
	memset(hostname, 0, sizeof(hostname));
	gethostname(hostname, sizeof(hostname) - 1);
	memset(localpeer, 0, sizeof(localpeer));
	memcpy(localpeer, hostname, (sizeof(hostname) > sizeof(localpeer) ? sizeof(localpeer) : sizeof(hostname)) - 1);

	/*
	 * Initialize the previously static variables.
	 */

	totalconn = actconn = maxfd = listeners = stopping = 0;
	killed = 0;


#ifdef HAPROXY_MEMMAX
	global.rlimit_memmax_all = HAPROXY_MEMMAX;
#endif

	tzset();
	tv_update_date(-1,-1);
	start_date = now;

	srandom(now_ms - getpid());

	init_log();
	signal_init();
	if (init_acl() != 0)
		exit(1);
	init_task();
	init_stream();
	init_session();
	init_connection();
	/* warning, we init buffers later */
	init_pendconn();
	init_proto_http();

	/* Initialise lua. */
	hlua_init();

	/* Initialize process vars */
	vars_init(&global.vars, SCOPE_PROC);

	global.tune.options |= GTUNE_USE_SELECT;  /* select() is always available */
#if defined(ENABLE_POLL)
	global.tune.options |= GTUNE_USE_POLL;
#endif
#if defined(ENABLE_EPOLL)
	global.tune.options |= GTUNE_USE_EPOLL;
#endif
#if defined(ENABLE_KQUEUE)
	global.tune.options |= GTUNE_USE_KQUEUE;
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE)
	global.tune.options |= GTUNE_USE_SPLICE;
#endif
#if defined(USE_GETADDRINFO)
	global.tune.options |= GTUNE_USE_GAI;
#endif
#if defined(SO_REUSEPORT)
	global.tune.options |= GTUNE_USE_REUSEPORT;
#endif

	pid = getpid();
	progname = *argv;
	while ((tmp = strchr(progname, '/')) != NULL)
		progname = tmp + 1;

	/* the process name is used for the logs only */
	chunk_initstr(&global.log_tag, strdup(progname));

	argc--; argv++;
	while (argc > 0) {
		char *flag;

		if (**argv == '-') {
			flag = *argv+1;

			/* 1 arg */
			if (*flag == 'v') {
				display_version();
				if (flag[1] == 'v')  /* -vv */
					display_build_opts();
				exit(0);
			}
#if defined(ENABLE_EPOLL)
			else if (*flag == 'd' && flag[1] == 'e')
				global.tune.options &= ~GTUNE_USE_EPOLL;
#endif
#if defined(ENABLE_POLL)
			else if (*flag == 'd' && flag[1] == 'p')
				global.tune.options &= ~GTUNE_USE_POLL;
#endif
#if defined(ENABLE_KQUEUE)
			else if (*flag == 'd' && flag[1] == 'k')
				global.tune.options &= ~GTUNE_USE_KQUEUE;
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE)
			else if (*flag == 'd' && flag[1] == 'S')
				global.tune.options &= ~GTUNE_USE_SPLICE;
#endif
#if defined(USE_GETADDRINFO)
			else if (*flag == 'd' && flag[1] == 'G')
				global.tune.options &= ~GTUNE_USE_GAI;
#endif
#if defined(SO_REUSEPORT)
			else if (*flag == 'd' && flag[1] == 'R')
				global.tune.options &= ~GTUNE_USE_REUSEPORT;
#endif
			else if (*flag == 'd' && flag[1] == 'V')
				global.ssl_server_verify = SSL_SERVER_VERIFY_NONE;
			else if (*flag == 'V')
				arg_mode |= MODE_VERBOSE;
			else if (*flag == 'd' && flag[1] == 'b')
				arg_mode |= MODE_FOREGROUND;
			else if (*flag == 'd' && flag[1] == 'M')
				mem_poison_byte = flag[2] ? strtol(flag + 2, NULL, 0) : 'P';
			else if (*flag == 'd' && flag[1] == 'r')
				global.tune.options |= GTUNE_RESOLVE_DONTFAIL;
			else if (*flag == 'd')
				arg_mode |= MODE_DEBUG;
			else if (*flag == 'c')
				arg_mode |= MODE_CHECK;
			else if (*flag == 'D')
				arg_mode |= MODE_DAEMON;
			else if (*flag == 'W' && flag[1] == 's') {
				arg_mode |= MODE_MWORKER | MODE_FOREGROUND;
#if defined(USE_SYSTEMD)
				global.tune.options |= GTUNE_USE_SYSTEMD;
#else
				ha_alert("master-worker mode with systemd support (-Ws) requested, but not compiled. Use master-worker mode (-W) if you are not using Type=notify in your unit file or recompile with USE_SYSTEMD=1.\n\n");
				usage(progname);
#endif
			}
			else if (*flag == 'W')
				arg_mode |= MODE_MWORKER;
			else if (*flag == 'q')
				arg_mode |= MODE_QUIET;
			else if (*flag == 'x') {
				if (argc <= 1 || argv[1][0] == '-') {
					ha_alert("Unix socket path expected with the -x flag\n\n");
					usage(progname);
				}
				if (old_unixsocket)
					ha_warning("-x option already set, overwriting the value\n");
				old_unixsocket = argv[1];

				argv++;
				argc--;
			}
			else if (*flag == 's' && (flag[1] == 'f' || flag[1] == 't')) {
				/* list of pids to finish ('f') or terminate ('t') */

				if (flag[1] == 'f')
					oldpids_sig = SIGUSR1; /* finish then exit */
				else
					oldpids_sig = SIGTERM; /* terminate immediately */
				while (argc > 1 && argv[1][0] != '-') {
					oldpids = realloc(oldpids, (nb_oldpids + 1) * sizeof(int));
					if (!oldpids) {
						ha_alert("Cannot allocate old pid : out of memory.\n");
						exit(1);
					}
					argc--; argv++;
					oldpids[nb_oldpids] = atol(*argv);
					if (oldpids[nb_oldpids] <= 0)
						usage(progname);
					nb_oldpids++;
				}
			}
			else if (flag[0] == '-' && flag[1] == 0) { /* "--" */
				/* now that's a cfgfile list */
				argv++; argc--;
				while (argc > 0) {
					if (!list_append_word(&cfg_cfgfiles, *argv, &err_msg)) {
						ha_alert("Cannot load configuration file/directory %s : %s\n",
							 *argv,
							 err_msg);
						exit(1);
					}
					argv++; argc--;
				}
				break;
			}
			else { /* >=2 args */
				argv++; argc--;
				if (argc == 0)
					usage(progname);

				switch (*flag) {
				case 'C' : change_dir = *argv; break;
				case 'n' : cfg_maxconn = atol(*argv); break;
				case 'm' : global.rlimit_memmax_all = atol(*argv); break;
				case 'N' : cfg_maxpconn = atol(*argv); break;
				case 'L' : strncpy(localpeer, *argv, sizeof(localpeer) - 1); break;
				case 'f' :
					if (!list_append_word(&cfg_cfgfiles, *argv, &err_msg)) {
						ha_alert("Cannot load configuration file/directory %s : %s\n",
							 *argv,
							 err_msg);
						exit(1);
					}
					break;
				case 'p' : cfg_pidfile = *argv; break;
				default: usage(progname);
				}
			}
		}
		else
			usage(progname);
		argv++; argc--;
	}

	global.mode |= (arg_mode & (MODE_DAEMON | MODE_MWORKER | MODE_FOREGROUND | MODE_VERBOSE
				    | MODE_QUIET | MODE_CHECK | MODE_DEBUG));

	/* Master workers wait mode */
	if ((global.mode & MODE_MWORKER) && (getenv("HAPROXY_MWORKER_WAIT_ONLY") != NULL)) {

		unsetenv("HAPROXY_MWORKER_WAIT_ONLY");
		mworker_wait();
	}

	if ((global.mode & MODE_MWORKER) && (getenv("HAPROXY_MWORKER_REEXEC") != NULL)) {
		atexit_flag = 1;
		atexit(reexec_on_failure);
	}

	if (change_dir && chdir(change_dir) < 0) {
		ha_alert("Could not change to directory %s : %s\n", change_dir, strerror(errno));
		exit(1);
	}

	/* handle cfgfiles that are actualy directories */
	cfgfiles_expand_directories();

	if (LIST_ISEMPTY(&cfg_cfgfiles))
		usage(progname);

	global.maxsock = 10; /* reserve 10 fds ; will be incremented by socket eaters */

	init_default_instance();

	list_for_each_entry(wl, &cfg_cfgfiles, list) {
		int ret;

		ret = readcfgfile(wl->s);
		if (ret == -1) {
			ha_alert("Could not open configuration file %s : %s\n",
				 wl->s, strerror(errno));
			exit(1);
		}
		if (ret & (ERR_ABORT|ERR_FATAL))
			ha_alert("Error(s) found in configuration file : %s\n", wl->s);
		err_code |= ret;
		if (err_code & ERR_ABORT)
			exit(1);
	}

	/* do not try to resolve arguments nor to spot inconsistencies when
	 * the configuration contains fatal errors caused by files not found
	 * or failed memory allocations.
	 */
	if (err_code & (ERR_ABORT|ERR_FATAL)) {
		ha_alert("Fatal errors found in configuration.\n");
		exit(1);
	}

	pattern_finalize_config();

	err_code |= check_config_validity();
	if (err_code & (ERR_ABORT|ERR_FATAL)) {
		ha_alert("Fatal errors found in configuration.\n");
		exit(1);
	}

	/* recompute the amount of per-process memory depending on nbproc and
	 * the shared SSL cache size (allowed to exist in all processes).
	 */
	if (global.rlimit_memmax_all) {
#if defined (USE_OPENSSL) && !defined(USE_PRIVATE_CACHE)
		int64_t ssl_cache_bytes = global.tune.sslcachesize * 200LL;

		global.rlimit_memmax =
			((((int64_t)global.rlimit_memmax_all * 1048576LL) -
			  ssl_cache_bytes) / global.nbproc +
			 ssl_cache_bytes + 1048575LL) / 1048576LL;
#else
		global.rlimit_memmax = global.rlimit_memmax_all / global.nbproc;
#endif
	}

#ifdef CONFIG_HAP_NS
        err_code |= netns_init();
        if (err_code & (ERR_ABORT|ERR_FATAL)) {
                ha_alert("Failed to initialize namespace support.\n");
                exit(1);
        }
#endif

	/* Apply server states */
	apply_server_state();

	for (px = proxies_list; px; px = px->next)
		srv_compute_all_admin_states(px);

	/* Apply servers' configured address */
	err_code |= srv_init_addr();
	if (err_code & (ERR_ABORT|ERR_FATAL)) {
		ha_alert("Failed to initialize server(s) addr.\n");
		exit(1);
	}

	if (global.mode & MODE_CHECK) {
		struct peers *pr;
		struct proxy *px;

		for (pr = cfg_peers; pr; pr = pr->next)
			if (pr->peers_fe)
				break;

		for (px = proxies_list; px; px = px->next)
			if (px->state == PR_STNEW && !LIST_ISEMPTY(&px->conf.listeners))
				break;

		if (pr || px) {
			/* At least one peer or one listener has been found */
			qfprintf(stdout, "Configuration file is valid\n");
			exit(0);
		}
		qfprintf(stdout, "Configuration file has no error but will not start (no listener) => exit(2).\n");
		exit(2);
	}

	global_listener_queue_task = task_new(MAX_THREADS_MASK);
	if (!global_listener_queue_task) {
		ha_alert("Out of memory when initializing global task\n");
		exit(1);
	}
	/* very simple initialization, users will queue the task if needed */
	global_listener_queue_task->context = NULL; /* not even a context! */
	global_listener_queue_task->process = manage_global_listener_queue;

	/* now we know the buffer size, we can initialize the channels and buffers */
	init_buffer();

	list_for_each_entry(pcf, &post_check_list, list) {
		err_code |= pcf->fct();
		if (err_code & (ERR_ABORT|ERR_FATAL))
			exit(1);
	}

	if (cfg_maxconn > 0)
		global.maxconn = cfg_maxconn;

	if (cfg_pidfile) {
		free(global.pidfile);
		global.pidfile = strdup(cfg_pidfile);
	}

	/* Now we want to compute the maxconn and possibly maxsslconn values.
	 * It's a bit tricky. If memmax is not set, maxconn defaults to
	 * DEFAULT_MAXCONN and maxsslconn defaults to DEFAULT_MAXSSLCONN.
	 *
	 * If memmax is set, then it depends on which values are set. If
	 * maxsslconn is set, we use memmax to determine how many cleartext
	 * connections may be added, and set maxconn to the sum of the two.
	 * If maxconn is set and not maxsslconn, maxsslconn is computed from
	 * the remaining amount of memory between memmax and the cleartext
	 * connections. If neither are set, then it is considered that all
	 * connections are SSL-capable, and maxconn is computed based on this,
	 * then maxsslconn accordingly. We need to know if SSL is used on the
	 * frontends, backends, or both, because when it's used on both sides,
	 * we need twice the value for maxsslconn, but we only count the
	 * handshake once since it is not performed on the two sides at the
	 * same time (frontend-side is terminated before backend-side begins).
	 * The SSL stack is supposed to have filled ssl_session_cost and
	 * ssl_handshake_cost during its initialization. In any case, if
	 * SYSTEM_MAXCONN is set, we still enforce it as an upper limit for
	 * maxconn in order to protect the system.
	 */
	if (!global.rlimit_memmax) {
		if (global.maxconn == 0) {
			global.maxconn = DEFAULT_MAXCONN;
			if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
				fprintf(stderr, "Note: setting global.maxconn to %d.\n", global.maxconn);
		}
	}
#ifdef USE_OPENSSL
	else if (!global.maxconn && !global.maxsslconn &&
		 (global.ssl_used_frontend || global.ssl_used_backend)) {
		/* memmax is set, compute everything automatically. Here we want
		 * to ensure that all SSL connections will be served. We take
		 * care of the number of sides where SSL is used, and consider
		 * the worst case : SSL used on both sides and doing a handshake
		 * simultaneously. Note that we can't have more than maxconn
		 * handshakes at a time by definition, so for the worst case of
		 * two SSL conns per connection, we count a single handshake.
		 */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;

		mem -= global.tune.sslcachesize * 200; // about 200 bytes per SSL cache entry
		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		global.maxconn = mem /
			((STREAM_MAX_COST + 2 * global.tune.bufsize) +    // stream + 2 buffers per stream
			 sides * global.ssl_session_max_cost + // SSL buffers, one per side
			 global.ssl_handshake_max_cost);       // 1 handshake per connection max

		global.maxconn = round_2dig(global.maxconn);
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > DEFAULT_MAXCONN)
			global.maxconn = DEFAULT_MAXCONN;
#endif /* SYSTEM_MAXCONN */
		global.maxsslconn = sides * global.maxconn;
		if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
			fprintf(stderr, "Note: setting global.maxconn to %d and global.maxsslconn to %d.\n",
			        global.maxconn, global.maxsslconn);
	}
	else if (!global.maxsslconn &&
		 (global.ssl_used_frontend || global.ssl_used_backend)) {
		/* memmax and maxconn are known, compute maxsslconn automatically.
		 * maxsslconn being forced, we don't know how many of it will be
		 * on each side if both sides are being used. The worst case is
		 * when all connections use only one SSL instance because
		 * handshakes may be on two sides at the same time.
		 */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;
		int64_t sslmem;

		mem -= global.tune.sslcachesize * 200; // about 200 bytes per SSL cache entry
		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		sslmem = mem - global.maxconn * (int64_t)(STREAM_MAX_COST + 2 * global.tune.bufsize);
		global.maxsslconn = sslmem / (global.ssl_session_max_cost + global.ssl_handshake_max_cost);
		global.maxsslconn = round_2dig(global.maxsslconn);

		if (sslmem <= 0 || global.maxsslconn < sides) {
			ha_alert("Cannot compute the automatic maxsslconn because global.maxconn is already too "
				 "high for the global.memmax value (%d MB). The absolute maximum possible value "
				 "without SSL is %d, but %d was found and SSL is in use.\n",
				 global.rlimit_memmax,
				 (int)(mem / (STREAM_MAX_COST + 2 * global.tune.bufsize)),
				 global.maxconn);
			exit(1);
		}

		if (global.maxsslconn > sides * global.maxconn)
			global.maxsslconn = sides * global.maxconn;

		if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
			fprintf(stderr, "Note: setting global.maxsslconn to %d\n", global.maxsslconn);
	}
#endif
	else if (!global.maxconn) {
		/* memmax and maxsslconn are known/unused, compute maxconn automatically */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;
		int64_t clearmem;

		if (global.ssl_used_frontend || global.ssl_used_backend)
			mem -= global.tune.sslcachesize * 200; // about 200 bytes per SSL cache entry

		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		clearmem = mem;
		if (sides)
			clearmem -= (global.ssl_session_max_cost + global.ssl_handshake_max_cost) * (int64_t)global.maxsslconn;

		global.maxconn = clearmem / (STREAM_MAX_COST + 2 * global.tune.bufsize);
		global.maxconn = round_2dig(global.maxconn);
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > DEFAULT_MAXCONN)
			global.maxconn = DEFAULT_MAXCONN;
#endif /* SYSTEM_MAXCONN */

		if (clearmem <= 0 || !global.maxconn) {
			ha_alert("Cannot compute the automatic maxconn because global.maxsslconn is already too "
				 "high for the global.memmax value (%d MB). The absolute maximum possible value "
				 "is %d, but %d was found.\n",
				 global.rlimit_memmax,
				 (int)(mem / (global.ssl_session_max_cost + global.ssl_handshake_max_cost)),
				 global.maxsslconn);
			exit(1);
		}

		if (global.mode & (MODE_VERBOSE|MODE_DEBUG)) {
			if (sides && global.maxsslconn > sides * global.maxconn) {
				fprintf(stderr, "Note: global.maxsslconn is forced to %d which causes global.maxconn "
				        "to be limited to %d. Better reduce global.maxsslconn to get more "
				        "room for extra connections.\n", global.maxsslconn, global.maxconn);
			}
			fprintf(stderr, "Note: setting global.maxconn to %d\n", global.maxconn);
		}
	}

	if (!global.maxpipes) {
		/* maxpipes not specified. Count how many frontends and backends
		 * may be using splicing, and bound that to maxconn.
		 */
		struct proxy *cur;
		int nbfe = 0, nbbe = 0;

		for (cur = proxies_list; cur; cur = cur->next) {
			if (cur->options2 & (PR_O2_SPLIC_ANY)) {
				if (cur->cap & PR_CAP_FE)
					nbfe += cur->maxconn;
				if (cur->cap & PR_CAP_BE)
					nbbe += cur->fullconn ? cur->fullconn : global.maxconn;
			}
		}
		global.maxpipes = MAX(nbfe, nbbe);
		if (global.maxpipes > global.maxconn)
			global.maxpipes = global.maxconn;
		global.maxpipes /= 4;
	}


	global.hardmaxconn = global.maxconn;  /* keep this max value */
	global.maxsock += global.maxconn * 2; /* each connection needs two sockets */
	global.maxsock += global.maxpipes * 2; /* each pipe needs two FDs */
	/* compute fd used by async engines */
	if (global.ssl_used_async_engines) {
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		global.maxsock += global.maxconn * sides * global.ssl_used_async_engines;
	}

	if (global.stats_fe)
		global.maxsock += global.stats_fe->maxconn;

	if (cfg_peers) {
		/* peers also need to bypass global maxconn */
		struct peers *p = cfg_peers;

		for (p = cfg_peers; p; p = p->next)
			if (p->peers_fe)
				global.maxsock += p->peers_fe->maxconn;
	}

	if (global.tune.maxpollevents <= 0)
		global.tune.maxpollevents = MAX_POLL_EVENTS;

	if (global.tune.recv_enough == 0)
		global.tune.recv_enough = MIN_RECV_AT_ONCE_ENOUGH;

	if (global.tune.maxrewrite < 0)
		global.tune.maxrewrite = MAXREWRITE;

	if (global.tune.maxrewrite >= global.tune.bufsize / 2)
		global.tune.maxrewrite = global.tune.bufsize / 2;

	if (arg_mode & (MODE_DEBUG | MODE_FOREGROUND)) {
		/* command line debug mode inhibits configuration mode */
		global.mode &= ~(MODE_DAEMON | MODE_QUIET);
		global.mode |= (arg_mode & (MODE_DEBUG | MODE_FOREGROUND));
	}

	if (arg_mode & MODE_DAEMON) {
		/* command line daemon mode inhibits foreground and debug modes mode */
		global.mode &= ~(MODE_DEBUG | MODE_FOREGROUND);
		global.mode |= arg_mode & MODE_DAEMON;
	}

	global.mode |= (arg_mode & (MODE_QUIET | MODE_VERBOSE));

	if ((global.mode & MODE_DEBUG) && (global.mode & (MODE_DAEMON | MODE_QUIET))) {
		ha_warning("<debug> mode incompatible with <quiet> and <daemon>. Keeping <debug> only.\n");
		global.mode &= ~(MODE_DAEMON | MODE_QUIET);
	}

	if ((global.nbproc > 1) && !(global.mode & (MODE_DAEMON | MODE_MWORKER))) {
		if (!(global.mode & (MODE_FOREGROUND | MODE_DEBUG)))
			ha_warning("<nbproc> is only meaningful in daemon mode or master-worker mode. Setting limit to 1 process.\n");
		global.nbproc = 1;
	}

	if (global.nbproc < 1)
		global.nbproc = 1;

	if (global.nbthread < 1)
		global.nbthread = 1;

	/* Realloc trash buffers because global.tune.bufsize may have changed */
	if (!init_trash_buffers(0)) {
		ha_alert("failed to initialize trash buffers.\n");
		exit(1);
	}

	if (!init_log_buffers()) {
		ha_alert("failed to initialize log buffers.\n");
		exit(1);
	}

	/*
	 * Note: we could register external pollers here.
	 * Built-in pollers have been registered before main().
	 */

	if (!(global.tune.options & GTUNE_USE_KQUEUE))
		disable_poller("kqueue");

	if (!(global.tune.options & GTUNE_USE_EPOLL))
		disable_poller("epoll");

	if (!(global.tune.options & GTUNE_USE_POLL))
		disable_poller("poll");

	if (!(global.tune.options & GTUNE_USE_SELECT))
		disable_poller("select");

	/* Note: we could disable any poller by name here */

	if (global.mode & (MODE_VERBOSE|MODE_DEBUG)) {
		list_pollers(stderr);
		fprintf(stderr, "\n");
		list_filters(stderr);
	}

	if (!init_pollers()) {
		ha_alert("No polling mechanism available.\n"
			 "  It is likely that haproxy was built with TARGET=generic and that FD_SETSIZE\n"
			 "  is too low on this platform to support maxconn and the number of listeners\n"
			 "  and servers. You should rebuild haproxy specifying your system using TARGET=\n"
			 "  in order to support other polling systems (poll, epoll, kqueue) or reduce the\n"
			 "  global maxconn setting to accommodate the system's limitation. For reference,\n"
			 "  FD_SETSIZE=%d on this system, global.maxconn=%d resulting in a maximum of\n"
			 "  %d file descriptors. You should thus reduce global.maxconn by %d. Also,\n"
			 "  check build settings using 'haproxy -vv'.\n\n",
			 FD_SETSIZE, global.maxconn, global.maxsock, (global.maxsock + 1 - FD_SETSIZE) / 2);
		exit(1);
	}
	if (global.mode & (MODE_VERBOSE|MODE_DEBUG)) {
		printf("Using %s() as the polling mechanism.\n", cur_poller.name);
	}

	if (!global.node)
		global.node = strdup(hostname);

	if (!hlua_post_init())
		exit(1);

	free(err_msg);
}

static void deinit_acl_cond(struct acl_cond *cond)
{
	struct acl_term_suite *suite, *suiteb;
	struct acl_term *term, *termb;

	if (!cond)
		return;

	list_for_each_entry_safe(suite, suiteb, &cond->suites, list) {
		list_for_each_entry_safe(term, termb, &suite->terms, list) {
			LIST_DEL(&term->list);
			free(term);
		}
		LIST_DEL(&suite->list);
		free(suite);
	}

	free(cond);
}

static void deinit_tcp_rules(struct list *rules)
{
	struct act_rule *trule, *truleb;

	list_for_each_entry_safe(trule, truleb, rules, list) {
		LIST_DEL(&trule->list);
		deinit_acl_cond(trule->cond);
		free(trule);
	}
}

static void deinit_stick_rules(struct list *rules)
{
	struct sticking_rule *rule, *ruleb;

	list_for_each_entry_safe(rule, ruleb, rules, list) {
		LIST_DEL(&rule->list);
		deinit_acl_cond(rule->cond);
		release_sample_expr(rule->expr);
		free(rule);
	}
}

void deinit(void)
{
	struct proxy *p = proxies_list, *p0;
	struct cap_hdr *h,*h_next;
	struct server *s,*s_next;
	struct listener *l,*l_next;
	struct acl_cond *cond, *condb;
	struct hdr_exp *exp, *expb;
	struct acl *acl, *aclb;
	struct switching_rule *rule, *ruleb;
	struct server_rule *srule, *sruleb;
	struct redirect_rule *rdr, *rdrb;
	struct wordlist *wl, *wlb;
	struct cond_wordlist *cwl, *cwlb;
	struct uri_auth *uap, *ua = NULL;
	struct logsrv *log, *logb;
	struct logformat_node *lf, *lfb;
	struct bind_conf *bind_conf, *bind_back;
	struct build_opts_str *bol, *bolb;
	struct post_deinit_fct *pdf;
	int i;

	deinit_signals();
	while (p) {
		free(p->conf.file);
		free(p->id);
		free(p->check_req);
		free(p->cookie_name);
		free(p->cookie_domain);
		free(p->url_param_name);
		free(p->capture_name);
		free(p->monitor_uri);
		free(p->rdp_cookie_name);
		if (p->conf.logformat_string != default_http_log_format &&
		    p->conf.logformat_string != default_tcp_log_format &&
		    p->conf.logformat_string != clf_http_log_format)
			free(p->conf.logformat_string);

		free(p->conf.lfs_file);
		free(p->conf.uniqueid_format_string);
		free(p->conf.uif_file);
		free(p->lbprm.map.srv);

		if (p->conf.logformat_sd_string != default_rfc5424_sd_log_format)
			free(p->conf.logformat_sd_string);
		free(p->conf.lfsd_file);

		for (i = 0; i < HTTP_ERR_SIZE; i++)
			chunk_destroy(&p->errmsg[i]);

		list_for_each_entry_safe(cwl, cwlb, &p->req_add, list) {
			LIST_DEL(&cwl->list);
			free(cwl->s);
			free(cwl);
		}

		list_for_each_entry_safe(cwl, cwlb, &p->rsp_add, list) {
			LIST_DEL(&cwl->list);
			free(cwl->s);
			free(cwl);
		}

		list_for_each_entry_safe(cond, condb, &p->mon_fail_cond, list) {
			LIST_DEL(&cond->list);
			prune_acl_cond(cond);
			free(cond);
		}

		for (exp = p->req_exp; exp != NULL; ) {
			if (exp->preg) {
				regex_free(exp->preg);
				free(exp->preg);
			}

			free((char *)exp->replace);
			expb = exp;
			exp = exp->next;
			free(expb);
		}

		for (exp = p->rsp_exp; exp != NULL; ) {
			if (exp->preg) {
				regex_free(exp->preg);
				free(exp->preg);
			}

			free((char *)exp->replace);
			expb = exp;
			exp = exp->next;
			free(expb);
		}

		/* build a list of unique uri_auths */
		if (!ua)
			ua = p->uri_auth;
		else {
			/* check if p->uri_auth is unique */
			for (uap = ua; uap; uap=uap->next)
				if (uap == p->uri_auth)
					break;

			if (!uap && p->uri_auth) {
				/* add it, if it is */
				p->uri_auth->next = ua;
				ua = p->uri_auth;
			}
		}

		list_for_each_entry_safe(acl, aclb, &p->acl, list) {
			LIST_DEL(&acl->list);
			prune_acl(acl);
			free(acl);
		}

		list_for_each_entry_safe(srule, sruleb, &p->server_rules, list) {
			LIST_DEL(&srule->list);
			prune_acl_cond(srule->cond);
			free(srule->cond);
			free(srule);
		}

		list_for_each_entry_safe(rule, ruleb, &p->switching_rules, list) {
			LIST_DEL(&rule->list);
			if (rule->cond) {
				prune_acl_cond(rule->cond);
				free(rule->cond);
				free(rule->file);
			}
			free(rule);
		}

		list_for_each_entry_safe(rdr, rdrb, &p->redirect_rules, list) {
			LIST_DEL(&rdr->list);
			if (rdr->cond) {
				prune_acl_cond(rdr->cond);
				free(rdr->cond);
			}
			free(rdr->rdr_str);
			list_for_each_entry_safe(lf, lfb, &rdr->rdr_fmt, list) {
				LIST_DEL(&lf->list);
				free(lf);
			}
			free(rdr);
		}

		list_for_each_entry_safe(log, logb, &p->logsrvs, list) {
			LIST_DEL(&log->list);
			free(log);
		}

		list_for_each_entry_safe(lf, lfb, &p->logformat, list) {
			LIST_DEL(&lf->list);
			free(lf);
		}

		list_for_each_entry_safe(lf, lfb, &p->logformat_sd, list) {
			LIST_DEL(&lf->list);
			free(lf);
		}

		deinit_tcp_rules(&p->tcp_req.inspect_rules);
		deinit_tcp_rules(&p->tcp_req.l4_rules);

		deinit_stick_rules(&p->storersp_rules);
		deinit_stick_rules(&p->sticking_rules);

		h = p->req_cap;
		while (h) {
			h_next = h->next;
			free(h->name);
			pool_destroy(h->pool);
			free(h);
			h = h_next;
		}/* end while(h) */

		h = p->rsp_cap;
		while (h) {
			h_next = h->next;
			free(h->name);
			pool_destroy(h->pool);
			free(h);
			h = h_next;
		}/* end while(h) */

		s = p->srv;
		while (s) {
			s_next = s->next;

			if (s->check.task) {
				task_delete(s->check.task);
				task_free(s->check.task);
			}
			if (s->agent.task) {
				task_delete(s->agent.task);
				task_free(s->agent.task);
			}

			if (s->warmup) {
				task_delete(s->warmup);
				task_free(s->warmup);
			}

			free(s->id);
			free(s->cookie);
			free(s->check.bi);
			free(s->check.bo);
			free(s->agent.bi);
			free(s->agent.bo);
			free(s->agent.send_string);
			free(s->hostname_dn);
			free((char*)s->conf.file);

			if (s->use_ssl || s->check.use_ssl) {
				if (xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->destroy_srv)
					xprt_get(XPRT_SSL)->destroy_srv(s);
			}
			HA_SPIN_DESTROY(&s->lock);
			free(s);
			s = s_next;
		}/* end while(s) */

		list_for_each_entry_safe(l, l_next, &p->conf.listeners, by_fe) {
			/*
			 * Zombie proxy, the listener just pretend to be up
			 * because they still hold an opened fd.
			 * Close it and give the listener its real state.
			 */
			if (p->state == PR_STSTOPPED && l->state >= LI_ZOMBIE) {
				close(l->fd);
				l->state = LI_INIT;
			}
			unbind_listener(l);
			delete_listener(l);
			LIST_DEL(&l->by_fe);
			LIST_DEL(&l->by_bind);
			free(l->name);
			free(l->counters);
			free(l);
		}

		/* Release unused SSL configs. */
		list_for_each_entry_safe(bind_conf, bind_back, &p->conf.bind, by_fe) {
			if (bind_conf->xprt->destroy_bind_conf)
				bind_conf->xprt->destroy_bind_conf(bind_conf);
			free(bind_conf->file);
			free(bind_conf->arg);
			LIST_DEL(&bind_conf->by_fe);
			free(bind_conf);
		}

		flt_deinit(p);

		free(p->desc);
		free(p->fwdfor_hdr_name);

		free_http_req_rules(&p->http_req_rules);
		free_http_res_rules(&p->http_res_rules);
		task_free(p->task);

		pool_destroy(p->req_cap_pool);
		pool_destroy(p->rsp_cap_pool);
		pool_destroy(p->table.pool);

		p0 = p;
		p = p->next;
		HA_SPIN_DESTROY(&p0->lbprm.lock);
		HA_SPIN_DESTROY(&p0->lock);
		free(p0);
	}/* end while(p) */

	while (ua) {
		uap = ua;
		ua = ua->next;

		free(uap->uri_prefix);
		free(uap->auth_realm);
		free(uap->node);
		free(uap->desc);

		userlist_free(uap->userlist);
		free_http_req_rules(&uap->http_req_rules);

		free(uap);
	}

	userlist_free(userlist);

	cfg_unregister_sections();

	deinit_log_buffers();
	deinit_trash_buffers();

	protocol_unbind_all();

	list_for_each_entry(pdf, &post_deinit_list, list)
		pdf->fct();

	free(global.log_send_hostname); global.log_send_hostname = NULL;
	chunk_destroy(&global.log_tag);
	free(global.chroot);  global.chroot = NULL;
	free(global.pidfile); global.pidfile = NULL;
	free(global.node);    global.node = NULL;
	free(global.desc);    global.desc = NULL;
	free(oldpids);        oldpids = NULL;
	task_free(global_listener_queue_task); global_listener_queue_task = NULL;

	list_for_each_entry_safe(log, logb, &global.logsrvs, list) {
			LIST_DEL(&log->list);
			free(log);
		}
	list_for_each_entry_safe(wl, wlb, &cfg_cfgfiles, list) {
		free(wl->s);
		LIST_DEL(&wl->list);
		free(wl);
	}

	list_for_each_entry_safe(bol, bolb, &build_opts_list, list) {
		if (bol->must_free)
			free((void *)bol->str);
		LIST_DEL(&bol->list);
		free(bol);
	}

	vars_prune(&global.vars, NULL, NULL);

	deinit_buffer();

	pool_destroy(pool_head_stream);
	pool_destroy(pool_head_session);
	pool_destroy(pool_head_connection);
	pool_destroy(pool_head_connstream);
	pool_destroy(pool_head_requri);
	pool_destroy(pool_head_task);
	pool_destroy(pool_head_capture);
	pool_destroy(pool_head_pendconn);
	pool_destroy(pool_head_sig_handlers);
	pool_destroy(pool_head_hdr_idx);
	pool_destroy(pool_head_http_txn);
	deinit_pollers();
} /* end deinit() */

void mworker_pipe_handler(int fd)
{
	char c;

	while (read(fd, &c, 1) == -1) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN) {
			fd_cant_recv(fd);
			return;
		}
		break;
	}

	deinit();
	exit(EXIT_FAILURE);
	return;
}

void mworker_pipe_register(int pipefd[2])
{
	close(mworker_pipe[1]); /* close the write end of the master pipe in the children */

	fcntl(mworker_pipe[0], F_SETFL, O_NONBLOCK);
	fdtab[mworker_pipe[0]].owner = mworker_pipe;
	fdtab[mworker_pipe[0]].iocb = mworker_pipe_handler;
	fd_insert(mworker_pipe[0], MAX_THREADS_MASK);
	fd_want_recv(mworker_pipe[0]);
}

static void sync_poll_loop()
{
	if (THREAD_NO_SYNC())
		return;

	THREAD_ENTER_SYNC();

	if (!THREAD_NEED_SYNC())
		goto exit;

	/* *** { */
	/* Put here all sync functions */

	servers_update_status(); /* Commit server status changes */

	/* *** } */
  exit:
	THREAD_EXIT_SYNC();
}

/* Runs the polling loop */
static void run_poll_loop()
{
	int next;

	tv_update_date(0,1);
	while (1) {
		/* Process a few tasks */
		process_runnable_tasks();

		/* check if we caught some signals and process them */
		signal_process_queue();

		/* Check if we can expire some tasks */
		next = wake_expired_tasks();

		/* stop when there's nothing left to do */
		if (jobs == 0)
			break;

		/* expire immediately if events are pending */
		if (fd_cache_num || (active_tasks_mask & tid_bit) || signal_queue_len || (active_applets_mask & tid_bit))
			next = now_ms;

		/* The poller will ensure it returns around <next> */
		cur_poller.poll(&cur_poller, next);
		fd_process_cached_events();
		applet_run_active();


		/* Synchronize all polling loops */
		sync_poll_loop();

	}
}

static void *run_thread_poll_loop(void *data)
{
	struct per_thread_init_fct   *ptif;
	struct per_thread_deinit_fct *ptdf;

	tid     = *((unsigned int *)data);
	tid_bit = (1UL << tid);
	tv_update_date(-1,-1);

	list_for_each_entry(ptif, &per_thread_init_list, list) {
		if (!ptif->fct()) {
			ha_alert("failed to initialize thread %u.\n", tid);
			exit(1);
		}
	}

	if (global.mode & MODE_MWORKER)
		mworker_pipe_register(mworker_pipe);

	protocol_enable_all();
	THREAD_SYNC_ENABLE();
	run_poll_loop();

	list_for_each_entry(ptdf, &per_thread_deinit_list, list)
		ptdf->fct();

#ifdef USE_THREAD
	if (tid > 0)
		pthread_exit(NULL);
#endif
	return NULL;
}

/* This is the global management task for listeners. It enables listeners waiting
 * for global resources when there are enough free resource, or at least once in
 * a while. It is designed to be called as a task.
 */
static struct task *manage_global_listener_queue(struct task *t)
{
	int next = TICK_ETERNITY;
	/* queue is empty, nothing to do */
	if (LIST_ISEMPTY(&global_listener_queue))
		goto out;

	/* If there are still too many concurrent connections, let's wait for
	 * some of them to go away. We don't need to re-arm the timer because
	 * each of them will scan the queue anyway.
	 */
	if (unlikely(actconn >= global.maxconn))
		goto out;

	/* We should periodically try to enable listeners waiting for a global
	 * resource here, because it is possible, though very unlikely, that
	 * they have been blocked by a temporary lack of global resource such
	 * as a file descriptor or memory and that the temporary condition has
	 * disappeared.
	 */
	dequeue_all_listeners(&global_listener_queue);

 out:
	t->expire = next;
	task_queue(t);
	return t;
}

int main(int argc, char **argv)
{
	int err, retry;
	struct rlimit limit;
	char errmsg[100];
	int pidfd = -1;

	init(argc, argv);
	signal_register_fct(SIGQUIT, dump, SIGQUIT);
	signal_register_fct(SIGUSR1, sig_soft_stop, SIGUSR1);
	signal_register_fct(SIGHUP, sig_dump_state, SIGHUP);
	signal_register_fct(SIGUSR2, NULL, 0);

	/* Always catch SIGPIPE even on platforms which define MSG_NOSIGNAL.
	 * Some recent FreeBSD setups report broken pipes, and MSG_NOSIGNAL
	 * was defined there, so let's stay on the safe side.
	 */
	signal_register_fct(SIGPIPE, NULL, 0);

	/* ulimits */
	if (!global.rlimit_nofile)
		global.rlimit_nofile = global.maxsock;

	if (global.rlimit_nofile) {
		limit.rlim_cur = limit.rlim_max = global.rlimit_nofile;
		if (setrlimit(RLIMIT_NOFILE, &limit) == -1) {
			/* try to set it to the max possible at least */
			getrlimit(RLIMIT_NOFILE, &limit);
			limit.rlim_cur = limit.rlim_max;
			if (setrlimit(RLIMIT_NOFILE, &limit) != -1)
				getrlimit(RLIMIT_NOFILE, &limit);

			ha_warning("[%s.main()] Cannot raise FD limit to %d, limit is %d.\n", argv[0], global.rlimit_nofile, (int)limit.rlim_cur);
			global.rlimit_nofile = limit.rlim_cur;
		}
	}

	if (global.rlimit_memmax) {
		limit.rlim_cur = limit.rlim_max =
			global.rlimit_memmax * 1048576ULL;
#ifdef RLIMIT_AS
		if (setrlimit(RLIMIT_AS, &limit) == -1) {
			ha_warning("[%s.main()] Cannot fix MEM limit to %d megs.\n",
				   argv[0], global.rlimit_memmax);
		}
#else
		if (setrlimit(RLIMIT_DATA, &limit) == -1) {
			ha_warning("[%s.main()] Cannot fix MEM limit to %d megs.\n",
				   argv[0], global.rlimit_memmax);
		}
#endif
	}

	if (old_unixsocket) {
		if (strcmp("/dev/null", old_unixsocket) != 0) {
			if (get_old_sockets(old_unixsocket) != 0) {
				ha_alert("Failed to get the sockets from the old process!\n");
				if (!(global.mode & MODE_MWORKER))
					exit(1);
			}
		}
	}
	get_cur_unixsocket();

	/* We will loop at most 100 times with 10 ms delay each time.
	 * That's at most 1 second. We only send a signal to old pids
	 * if we cannot grab at least one port.
	 */
	retry = MAX_START_RETRIES;
	err = ERR_NONE;
	while (retry >= 0) {
		struct timeval w;
		err = start_proxies(retry == 0 || nb_oldpids == 0);
		/* exit the loop on no error or fatal error */
		if ((err & (ERR_RETRYABLE|ERR_FATAL)) != ERR_RETRYABLE)
			break;
		if (nb_oldpids == 0 || retry == 0)
			break;

		/* FIXME-20060514: Solaris and OpenBSD do not support shutdown() on
		 * listening sockets. So on those platforms, it would be wiser to
		 * simply send SIGUSR1, which will not be undoable.
		 */
		if (tell_old_pids(SIGTTOU) == 0) {
			/* no need to wait if we can't contact old pids */
			retry = 0;
			continue;
		}
		/* give some time to old processes to stop listening */
		w.tv_sec = 0;
		w.tv_usec = 10*1000;
		select(0, NULL, NULL, NULL, &w);
		retry--;
	}

	/* Note: start_proxies() sends an alert when it fails. */
	if ((err & ~ERR_WARN) != ERR_NONE) {
		if (retry != MAX_START_RETRIES && nb_oldpids) {
			protocol_unbind_all(); /* cleanup everything we can */
			tell_old_pids(SIGTTIN);
		}
		exit(1);
	}

	if (listeners == 0) {
		ha_alert("[%s.main()] No enabled listener found (check for 'bind' directives) ! Exiting.\n", argv[0]);
		/* Note: we don't have to send anything to the old pids because we
		 * never stopped them. */
		exit(1);
	}

	err = protocol_bind_all(errmsg, sizeof(errmsg));
	if ((err & ~ERR_WARN) != ERR_NONE) {
		if ((err & ERR_ALERT) || (err & ERR_WARN))
			ha_alert("[%s.main()] %s.\n", argv[0], errmsg);

		ha_alert("[%s.main()] Some protocols failed to start their listeners! Exiting.\n", argv[0]);
		protocol_unbind_all(); /* cleanup everything we can */
		if (nb_oldpids)
			tell_old_pids(SIGTTIN);
		exit(1);
	} else if (err & ERR_WARN) {
		ha_alert("[%s.main()] %s.\n", argv[0], errmsg);
	}
	/* Ok, all listener should now be bound, close any leftover sockets
	 * the previous process gave us, we don't need them anymore
	 */
	while (xfer_sock_list != NULL) {
		struct xfer_sock_list *tmpxfer = xfer_sock_list->next;
		close(xfer_sock_list->fd);
		free(xfer_sock_list->iface);
		free(xfer_sock_list->namespace);
		free(xfer_sock_list);
		xfer_sock_list = tmpxfer;
	}

	/* prepare pause/play signals */
	signal_register_fct(SIGTTOU, sig_pause, SIGTTOU);
	signal_register_fct(SIGTTIN, sig_listen, SIGTTIN);

	/* MODE_QUIET can inhibit alerts and warnings below this line */

	if (getenv("HAPROXY_MWORKER_REEXEC") != NULL) {
		/* either stdin/out/err are already closed or should stay as they are. */
		if ((global.mode & MODE_DAEMON)) {
			/* daemon mode re-executing, stdin/stdout/stderr are already closed so keep quiet */
			global.mode &= ~MODE_VERBOSE;
			global.mode |= MODE_QUIET; /* ensure that we won't say anything from now */
		}
	} else {
		if ((global.mode & MODE_QUIET) && !(global.mode & MODE_VERBOSE)) {
			/* detach from the tty */
			stdio_quiet(-1);
		}
	}

	/* open log & pid files before the chroot */
	if ((global.mode & MODE_DAEMON || global.mode & MODE_MWORKER) && global.pidfile != NULL) {
		unlink(global.pidfile);
		pidfd = open(global.pidfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (pidfd < 0) {
			ha_alert("[%s.main()] Cannot create pidfile %s\n", argv[0], global.pidfile);
			if (nb_oldpids)
				tell_old_pids(SIGTTIN);
			protocol_unbind_all();
			exit(1);
		}
	}

	if ((global.last_checks & LSTCHK_NETADM) && global.uid) {
		ha_alert("[%s.main()] Some configuration options require full privileges, so global.uid cannot be changed.\n"
			 "", argv[0]);
		protocol_unbind_all();
		exit(1);
	}

	/* If the user is not root, we'll still let him try the configuration
	 * but we inform him that unexpected behaviour may occur.
	 */
	if ((global.last_checks & LSTCHK_NETADM) && getuid())
		ha_warning("[%s.main()] Some options which require full privileges"
			   " might not work well.\n"
			   "", argv[0]);

	if ((global.mode & (MODE_MWORKER|MODE_DAEMON)) == 0) {

		/* chroot if needed */
		if (global.chroot != NULL) {
			if (chroot(global.chroot) == -1 || chdir("/") == -1) {
				ha_alert("[%s.main()] Cannot chroot(%s).\n", argv[0], global.chroot);
				if (nb_oldpids)
					tell_old_pids(SIGTTIN);
				protocol_unbind_all();
				exit(1);
			}
		}
	}

	if (nb_oldpids)
		nb_oldpids = tell_old_pids(oldpids_sig);

	if ((getenv("HAPROXY_MWORKER_REEXEC") == NULL)) {
		nb_oldpids = 0;
		free(oldpids);
		oldpids = NULL;
	}


	/* Note that any error at this stage will be fatal because we will not
	 * be able to restart the old pids.
	 */

	if ((global.mode & (MODE_MWORKER|MODE_DAEMON)) == 0) {
		/* setgid / setuid */
		if (global.gid) {
			if (getgroups(0, NULL) > 0 && setgroups(0, NULL) == -1)
				ha_warning("[%s.main()] Failed to drop supplementary groups. Using 'gid'/'group'"
					   " without 'uid'/'user' is generally useless.\n", argv[0]);

			if (setgid(global.gid) == -1) {
				ha_alert("[%s.main()] Cannot set gid %d.\n", argv[0], global.gid);
				protocol_unbind_all();
				exit(1);
			}
		}

		if (global.uid && setuid(global.uid) == -1) {
			ha_alert("[%s.main()] Cannot set uid %d.\n", argv[0], global.uid);
			protocol_unbind_all();
			exit(1);
		}
	}
	/* check ulimits */
	limit.rlim_cur = limit.rlim_max = 0;
	getrlimit(RLIMIT_NOFILE, &limit);
	if (limit.rlim_cur < global.maxsock) {
		ha_warning("[%s.main()] FD limit (%d) too low for maxconn=%d/maxsock=%d. Please raise 'ulimit-n' to %d or more to avoid any trouble.\n",
			   argv[0], (int)limit.rlim_cur, global.maxconn, global.maxsock, global.maxsock);
	}

	if (global.mode & (MODE_DAEMON | MODE_MWORKER)) {
		struct proxy *px;
		struct peers *curpeers;
		int ret = 0;
		int proc;
		int devnullfd = -1;

		children = calloc(global.nbproc, sizeof(int));
		/*
		 * if daemon + mworker: must fork here to let a master
		 * process live in background before forking children
		 */

		if ((getenv("HAPROXY_MWORKER_REEXEC") == NULL)
		    && (global.mode & MODE_MWORKER)
		    && (global.mode & MODE_DAEMON)) {
			ret = fork();
			if (ret < 0) {
				ha_alert("[%s.main()] Cannot fork.\n", argv[0]);
				protocol_unbind_all();
				exit(1); /* there has been an error */
			}
			/* parent leave to daemonize */
			if (ret > 0)
				exit(0);
		}

		if (global.mode & MODE_MWORKER) {
			if ((getenv("HAPROXY_MWORKER_REEXEC") == NULL)) {
				char *msg = NULL;
				/* master pipe to ensure the master is still alive  */
				ret = pipe(mworker_pipe);
				if (ret < 0) {
					ha_alert("[%s.main()] Cannot create master pipe.\n", argv[0]);
					exit(EXIT_FAILURE);
				} else {
					memprintf(&msg, "%d", mworker_pipe[0]);
					setenv("HAPROXY_MWORKER_PIPE_RD", msg, 1);
					memprintf(&msg, "%d", mworker_pipe[1]);
					setenv("HAPROXY_MWORKER_PIPE_WR", msg, 1);
					free(msg);
				}
			} else {
				char* rd = getenv("HAPROXY_MWORKER_PIPE_RD");
				char* wr = getenv("HAPROXY_MWORKER_PIPE_WR");
				if (!rd || !wr) {
					ha_alert("[%s.main()] Cannot get master pipe FDs.\n", argv[0]);
					atexit_flag = 0;// dont reexecute master process
					exit(EXIT_FAILURE);
				}
				mworker_pipe[0] = atoi(rd);
				mworker_pipe[1] = atoi(wr);
			}
		}

		/* if in master-worker mode, write the PID of the father */
		if (global.mode & MODE_MWORKER) {
			char pidstr[100];
			snprintf(pidstr, sizeof(pidstr), "%d\n", getpid());
			shut_your_big_mouth_gcc(write(pidfd, pidstr, strlen(pidstr)));
		}

		/* the father launches the required number of processes */
		for (proc = 0; proc < global.nbproc; proc++) {
			ret = fork();
			if (ret < 0) {
				ha_alert("[%s.main()] Cannot fork.\n", argv[0]);
				protocol_unbind_all();
				exit(1); /* there has been an error */
			}
			else if (ret == 0) /* child breaks here */
				break;
			children[proc] = ret;
			if (pidfd >= 0 && !(global.mode & MODE_MWORKER)) {
				char pidstr[100];
				snprintf(pidstr, sizeof(pidstr), "%d\n", ret);
				shut_your_big_mouth_gcc(write(pidfd, pidstr, strlen(pidstr)));
			}
			relative_pid++; /* each child will get a different one */
			pid_bit <<= 1;
		}

#ifdef USE_CPU_AFFINITY
		if (proc < global.nbproc &&  /* child */
		    proc < LONGBITS &&       /* only the first 32/64 processes may be pinned */
		    global.cpu_map.proc[proc])    /* only do this if the process has a CPU map */
#ifdef __FreeBSD__
		{
			cpuset_t cpuset;
			int i;
			unsigned long cpu_map = global.cpu_map.proc[proc];

			CPU_ZERO(&cpuset);
			while ((i = ffsl(cpu_map)) > 0) {
				CPU_SET(i - 1, &cpuset);
				cpu_map &= ~(1 << (i - 1));
			}
			ret = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(cpuset), &cpuset);
		}
#else
			sched_setaffinity(0, sizeof(unsigned long), (void *)&global.cpu_map.proc[proc]);
#endif
#endif
		/* close the pidfile both in children and father */
		if (pidfd >= 0) {
			//lseek(pidfd, 0, SEEK_SET);  /* debug: emulate eglibc bug */
			close(pidfd);
		}

		/* We won't ever use this anymore */
		free(global.pidfile); global.pidfile = NULL;

		if (proc == global.nbproc) {
			if (global.mode & MODE_MWORKER) {
				mworker_cleanlisteners();
				deinit_pollers();

				if ((!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
					(global.mode & MODE_DAEMON)) {
					/* detach from the tty, this is required to properly daemonize. */
					if ((getenv("HAPROXY_MWORKER_REEXEC") == NULL))
						stdio_quiet(-1);

					global.mode &= ~MODE_VERBOSE;
					global.mode |= MODE_QUIET; /* ensure that we won't say anything from now */
					setsid();
				}

				mworker_wait();
				/* should never get there */
				exit(EXIT_FAILURE);
			}
#if defined(USE_OPENSSL) && !defined(OPENSSL_NO_DH)
			ssl_free_dh();
#endif
			exit(0); /* parent must leave */
		}

		/* child must never use the atexit function */
		atexit_flag = 0;

		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
			devnullfd = open("/dev/null", O_RDWR, 0);
			if (devnullfd < 0) {
				ha_alert("Cannot open /dev/null\n");
				exit(EXIT_FAILURE);
			}
		}

		/* Must chroot and setgid/setuid in the children */
		/* chroot if needed */
		if (global.chroot != NULL) {
			if (chroot(global.chroot) == -1 || chdir("/") == -1) {
				ha_alert("[%s.main()] Cannot chroot1(%s).\n", argv[0], global.chroot);
				if (nb_oldpids)
					tell_old_pids(SIGTTIN);
				protocol_unbind_all();
				exit(1);
			}
		}

		free(global.chroot);
		global.chroot = NULL;

		/* setgid / setuid */
		if (global.gid) {
			if (getgroups(0, NULL) > 0 && setgroups(0, NULL) == -1)
				ha_warning("[%s.main()] Failed to drop supplementary groups. Using 'gid'/'group'"
					   " without 'uid'/'user' is generally useless.\n", argv[0]);

			if (setgid(global.gid) == -1) {
				ha_alert("[%s.main()] Cannot set gid %d.\n", argv[0], global.gid);
				protocol_unbind_all();
				exit(1);
			}
		}

		if (global.uid && setuid(global.uid) == -1) {
			ha_alert("[%s.main()] Cannot set uid %d.\n", argv[0], global.uid);
			protocol_unbind_all();
			exit(1);
		}

		/* pass through every cli socket, and check if it's bound to
		 * the current process and if it exposes listeners sockets.
		 * Caution: the GTUNE_SOCKET_TRANSFER is now set after the fork.
		 * */

		if (global.stats_fe) {
			struct bind_conf *bind_conf;

			list_for_each_entry(bind_conf, &global.stats_fe->conf.bind, by_fe) {
				if (bind_conf->level & ACCESS_FD_LISTENERS) {
					if (!bind_conf->bind_proc || bind_conf->bind_proc & (1UL << proc)) {
						global.tune.options |= GTUNE_SOCKET_TRANSFER;
						break;
					}
				}
			}
		}

		/* we might have to unbind some proxies from some processes */
		px = proxies_list;
		while (px != NULL) {
			if (px->bind_proc && px->state != PR_STSTOPPED) {
				if (!(px->bind_proc & (1UL << proc))) {
					if (global.tune.options & GTUNE_SOCKET_TRANSFER)
						zombify_proxy(px);
					else
						stop_proxy(px);
				}
			}
			px = px->next;
		}

		/* we might have to unbind some peers sections from some processes */
		for (curpeers = cfg_peers; curpeers; curpeers = curpeers->next) {
			if (!curpeers->peers_fe)
				continue;

			if (curpeers->peers_fe->bind_proc & (1UL << proc))
				continue;

			stop_proxy(curpeers->peers_fe);
			/* disable this peer section so that it kills itself */
			signal_unregister_handler(curpeers->sighandler);
			task_delete(curpeers->sync_task);
			task_free(curpeers->sync_task);
			curpeers->sync_task = NULL;
			task_free(curpeers->peers_fe->task);
			curpeers->peers_fe->task = NULL;
			curpeers->peers_fe = NULL;
		}

		/* if we're NOT in QUIET mode, we should now close the 3 first FDs to ensure
		 * that we can detach from the TTY. We MUST NOT do it in other cases since
		 * it would have already be done, and 0-2 would have been affected to listening
		 * sockets
		 */
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
			/* detach from the tty */
			stdio_quiet(devnullfd);
			global.mode &= ~MODE_VERBOSE;
			global.mode |= MODE_QUIET; /* ensure that we won't say anything from now */
		}
		pid = getpid(); /* update child's pid */
		setsid();
		fork_poller();
	}

	global.mode &= ~MODE_STARTING;
	/*
	 * That's it : the central polling loop. Run until we stop.
	 */
#ifdef USE_THREAD
	{
		unsigned int *tids    = calloc(global.nbthread, sizeof(unsigned int));
		pthread_t    *threads = calloc(global.nbthread, sizeof(pthread_t));
		int          i;

		THREAD_SYNC_INIT((1UL << global.nbthread) - 1);

		/* Init tids array */
		for (i = 0; i < global.nbthread; i++)
			tids[i] = i;

		/* Create nbthread-1 thread. The first thread is the current process */
		threads[0] = pthread_self();
		for (i = 1; i < global.nbthread; i++)
			pthread_create(&threads[i], NULL, &run_thread_poll_loop, &tids[i]);

#ifdef USE_CPU_AFFINITY
		/* Now the CPU affinity for all threads */
		for (i = 0; i < global.nbthread; i++) {
			if (global.cpu_map.proc[relative_pid-1])
				global.cpu_map.thread[relative_pid-1][i] &= global.cpu_map.proc[relative_pid-1];

			if (i < LONGBITS &&       /* only the first 32/64 threads may be pinned */
			    global.cpu_map.thread[relative_pid-1][i]) {/* only do this if the thread has a THREAD map */
#if defined(__FreeBSD__) || defined(__NetBSD__)
				cpuset_t cpuset;
#else
				cpu_set_t cpuset;
#endif
				int j;
				unsigned long cpu_map = global.cpu_map.thread[relative_pid-1][i];

				CPU_ZERO(&cpuset);

				while ((j = ffsl(cpu_map)) > 0) {
					CPU_SET(j - 1, &cpuset);
					cpu_map &= ~(1 << (j - 1));
				}
				pthread_setaffinity_np(threads[i],
						       sizeof(cpuset), &cpuset);
			}
		}
#endif /* !USE_CPU_AFFINITY */

		/* Finally, start the poll loop for the first thread */
		run_thread_poll_loop(&tids[0]);

		/* Wait the end of other threads */
		for (i = 1; i < global.nbthread; i++)
			pthread_join(threads[i], NULL);

		free(tids);
		free(threads);

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
		show_lock_stats();
#endif
	}
#else /* ! USE_THREAD */

	run_thread_poll_loop((int []){0});

#endif

	/* Do some cleanup */
	deinit();

	exit(0);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
