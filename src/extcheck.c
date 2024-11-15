/*
 * External health-checks functions.
 *
 * Copyright 2000-2009,2020 Willy Tarreau <w@1wt.eu>
 * Copyright 2014 Horms Solutions Ltd, Simon Horman <horms@verge.net.au>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/limits.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/signal.h>
#include <haproxy/stream-t.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>


static struct list pid_list = LIST_HEAD_INIT(pid_list);
static struct pool_head *pool_head_pid_list __read_mostly;
__decl_spinlock(pid_list_lock);

struct extcheck_env {
	char *name;	/* environment variable name */
	int vmaxlen;	/* value maximum length, used to determine the required memory allocation */
};

/* environment variables memory requirement for different types of data */
#define EXTCHK_SIZE_EVAL_INIT 0                  /* size determined during the init phase,
                                                  * such environment variables are not updatable. */
#define EXTCHK_SIZE_ULONG     20                 /* max string length for an unsigned long value */
#define EXTCHK_SIZE_UINT      11                 /* max string length for an unsigned int value */
#define EXTCHK_SIZE_ADDR      256                /* max string length for an IPv4/IPv6/UNIX address */

/* external checks environment variables */
enum {
	EXTCHK_PATH = 0,

	/* Proxy specific environment variables */
	EXTCHK_HAPROXY_PROXY_NAME,	/* the backend name */
	EXTCHK_HAPROXY_PROXY_ID,	/* the backend id */
	EXTCHK_HAPROXY_PROXY_ADDR,	/* the first bind address if available (or empty) */
	EXTCHK_HAPROXY_PROXY_PORT,	/* the first bind port if available (or empty) */

	/* Server specific environment variables */
	EXTCHK_HAPROXY_SERVER_NAME,	/* the server name */
	EXTCHK_HAPROXY_SERVER_ID,	/* the server id */
	EXTCHK_HAPROXY_SERVER_ADDR,	/* the server address */
	EXTCHK_HAPROXY_SERVER_PORT,	/* the server port if available (or empty) */
	EXTCHK_HAPROXY_SERVER_MAXCONN,	/* the server max connections */
	EXTCHK_HAPROXY_SERVER_CURCONN,	/* the current number of connections on the server */
	EXTCHK_HAPROXY_SERVER_SSL,	/* "1" if the server supports SSL, otherwise zero */
	EXTCHK_HAPROXY_SERVER_PROTO,	/* the server's configured proto, if any */

	EXTCHK_SIZE
};

const struct extcheck_env extcheck_envs[EXTCHK_SIZE] = {
	[EXTCHK_PATH]                   = { "PATH",                   EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_NAME]     = { "HAPROXY_PROXY_NAME",     EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_ID]       = { "HAPROXY_PROXY_ID",       EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_ADDR]     = { "HAPROXY_PROXY_ADDR",     EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_PORT]     = { "HAPROXY_PROXY_PORT",     EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_NAME]    = { "HAPROXY_SERVER_NAME",    EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_ID]      = { "HAPROXY_SERVER_ID",      EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_ADDR]    = { "HAPROXY_SERVER_ADDR",    EXTCHK_SIZE_ADDR },
	[EXTCHK_HAPROXY_SERVER_PORT]    = { "HAPROXY_SERVER_PORT",    EXTCHK_SIZE_UINT },
	[EXTCHK_HAPROXY_SERVER_MAXCONN] = { "HAPROXY_SERVER_MAXCONN", EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_CURCONN] = { "HAPROXY_SERVER_CURCONN", EXTCHK_SIZE_ULONG },
	[EXTCHK_HAPROXY_SERVER_SSL]     = { "HAPROXY_SERVER_SSL",     EXTCHK_SIZE_UINT },
	[EXTCHK_HAPROXY_SERVER_PROTO]   = { "HAPROXY_SERVER_PROTO",   EXTCHK_SIZE_EVAL_INIT },
};

void block_sigchld(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	assert(ha_sigmask(SIG_BLOCK, &set, NULL) == 0);
}

void unblock_sigchld(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	assert(ha_sigmask(SIG_UNBLOCK, &set, NULL) == 0);
}

static struct pid_list *pid_list_add(pid_t pid, struct task *t)
{
	struct pid_list *elem;
	struct check *check = t->context;

	elem = pool_alloc(pool_head_pid_list);
	if (!elem)
		return NULL;
	elem->pid = pid;
	elem->t = t;
	elem->exited = 0;
	check->curpid = elem;
	LIST_INIT(&elem->list);

	HA_SPIN_LOCK(PID_LIST_LOCK, &pid_list_lock);
	LIST_INSERT(&pid_list, &elem->list);
	HA_SPIN_UNLOCK(PID_LIST_LOCK, &pid_list_lock);

	return elem;
}

static void pid_list_del(struct pid_list *elem)
{
	struct check *check;

	if (!elem)
		return;

	HA_SPIN_LOCK(PID_LIST_LOCK, &pid_list_lock);
	LIST_DELETE(&elem->list);
	HA_SPIN_UNLOCK(PID_LIST_LOCK, &pid_list_lock);

	if (!elem->exited)
		kill(elem->pid, SIGTERM);

	check = elem->t->context;
	check->curpid = NULL;
	pool_free(pool_head_pid_list, elem);
}

/* Called from inside SIGCHLD handler, SIGCHLD is blocked */
static void pid_list_expire(pid_t pid, int status)
{
	struct pid_list *elem;

	HA_SPIN_LOCK(PID_LIST_LOCK, &pid_list_lock);
	list_for_each_entry(elem, &pid_list, list) {
		if (elem->pid == pid) {
			elem->t->expire = tick_add(now_ms, 0);
			elem->status = status;
			elem->exited = 1;
			task_wakeup(elem->t, TASK_WOKEN_IO);
			break;
		}
	}
	HA_SPIN_UNLOCK(PID_LIST_LOCK, &pid_list_lock);
}

static void sigchld_handler(struct sig_handler *sh)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(0, &status, WNOHANG)) > 0)
		pid_list_expire(pid, status);
}

int init_pid_list(void)
{
	if (pool_head_pid_list != NULL)
		/* Nothing to do */
		return 0;

	if (!signal_register_fct(SIGCHLD, sigchld_handler, SIGCHLD)) {
		ha_alert("Failed to set signal handler for external health checks: %s. Aborting.\n",
			 strerror(errno));
		return 1;
	}

	pool_head_pid_list = create_pool("pid_list", sizeof(struct pid_list), MEM_F_SHARED);
	if (pool_head_pid_list == NULL) {
		ha_alert("Failed to allocate memory pool for external health checks: %s. Aborting.\n",
			 strerror(errno));
		return 1;
	}

	return 0;
}

/* helper macro to set an environment variable and jump to a specific label on failure. */
#define EXTCHK_SETENV(check, envidx, value, fail) { if (extchk_setenv(check, envidx, value)) goto fail; }

/*
 * helper function to allocate enough memory to store an environment variable.
 * It will also check that the environment variable is updatable, and silently
 * fail if not.
 */
static int extchk_setenv(struct check *check, int idx, const char *value)
{
	int len, ret;
	char *envname;
	int vmaxlen;

	if (idx < 0 || idx >= EXTCHK_SIZE) {
		ha_alert("Illegal environment variable index %d. Aborting.\n", idx);
		return 1;
	}

	envname = extcheck_envs[idx].name;
	vmaxlen = extcheck_envs[idx].vmaxlen;

	/* Check if the environment variable is already set, and silently reject
	 * the update if this one is not updatable. */
	if ((vmaxlen == EXTCHK_SIZE_EVAL_INIT) && (check->envp[idx]))
		return 0;

	/* Instead of sending NOT_USED, sending an empty value is preferable */
	if (strcmp(value, "NOT_USED") == 0) {
		value = "";
	}

	len = strlen(envname) + 1;
	if (vmaxlen == EXTCHK_SIZE_EVAL_INIT)
		len += strlen(value);
	else
		len += vmaxlen;

	if (!check->envp[idx])
		check->envp[idx] = malloc(len + 1);

	if (!check->envp[idx]) {
		ha_alert("Failed to allocate memory for the environment variable '%s'. Aborting.\n", envname);
		return 1;
	}
	ret = snprintf(check->envp[idx], len + 1, "%s=%s", envname, value);
	if (ret < 0) {
		ha_alert("Failed to store the environment variable '%s'. Reason : %s. Aborting.\n", envname, strerror(errno));
		return 1;
	}
	else if (ret > len) {
		ha_alert("Environment variable '%s' was truncated. Aborting.\n", envname);
		return 1;
	}
	return 0;
}

int prepare_external_check(struct check *check)
{
	struct server *s = check->server;
	struct proxy *px = s->proxy;
	struct listener *listener = NULL, *l;
	int i;
	const char *path = px->check_path ? px->check_path : DEF_CHECK_PATH;
	char buf[256];
	const char *svmode = NULL;

	list_for_each_entry(l, &px->conf.listeners, by_fe)
		/* Use the first INET, INET6 or UNIX listener */
		if (l->rx.addr.ss_family == AF_INET ||
		    l->rx.addr.ss_family == AF_INET6 ||
		    l->rx.addr.ss_family == AF_UNIX) {
			listener = l;
			break;
		}

	check->curpid = NULL;
	check->envp = calloc((EXTCHK_SIZE + 1), sizeof(*check->envp));
	if (!check->envp) {
		ha_alert("Failed to allocate memory for environment variables. Aborting\n");
		goto err;
	}

	check->argv = calloc(6, sizeof(*check->argv));
	if (!check->argv) {
		ha_alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
		goto err;
	}

	check->argv[0] = px->check_command;

	if (!listener) {
		check->argv[1] = strdup("NOT_USED");
		check->argv[2] = strdup("NOT_USED");
	}
	else if (listener->rx.addr.ss_family == AF_INET ||
	    listener->rx.addr.ss_family == AF_INET6) {
		addr_to_str(&listener->rx.addr, buf, sizeof(buf));
		check->argv[1] = strdup(buf);
		port_to_str(&listener->rx.addr, buf, sizeof(buf));
		check->argv[2] = strdup(buf);
	}
	else if (listener->rx.addr.ss_family == AF_UNIX ||
	         listener->rx.addr.ss_family == AF_CUST_ABNS ||
	         listener->rx.addr.ss_family == AF_CUST_ABNSZ) {
		const struct sockaddr_un *un;

		un = (struct sockaddr_un *)&listener->rx.addr;
		check->argv[1] = strdup(un->sun_path);
		check->argv[2] = strdup("NOT_USED");
	}
	else {
		ha_alert("Starting [%s:%s] check: unsupported address family.\n", px->id, s->id);
		goto err;
	}

	/* args 3 and 4 are the address, they're replaced on each check */
	check->argv[3] = calloc(EXTCHK_SIZE_ADDR, sizeof(*check->argv[3]));
	check->argv[4] = calloc(EXTCHK_SIZE_UINT, sizeof(*check->argv[4]));

	for (i = 0; i < 5; i++) {
		if (!check->argv[i]) {
			ha_alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
			goto err;
		}
	}

	EXTCHK_SETENV(check, EXTCHK_PATH, path, err);
	/* Add proxy environment variables */
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_NAME, px->id, err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_ID, ultoa_r(px->uuid, buf, sizeof(buf)), err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_ADDR, check->argv[1], err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_PORT, check->argv[2], err);
	/* Add server environment variables */
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_NAME, s->id, err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_ID, ultoa_r(s->puid, buf, sizeof(buf)), err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_ADDR, check->argv[3], err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_PORT, check->argv[4], err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_MAXCONN, ultoa_r(s->maxconn, buf, sizeof(buf)), err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_CURCONN, ultoa_r(s->cur_sess, buf, sizeof(buf)), err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_SSL, s->use_ssl ? "1" : "0", err);

	switch (px->mode) {
	case PR_MODE_CLI:    svmode = "cli"; break;
	case PR_MODE_SYSLOG: svmode = "syslog"; break;
	case PR_MODE_PEERS:  svmode = "peers"; break;
	case PR_MODE_HTTP:   svmode = (s->mux_proto) ? s->mux_proto->token.ptr : "h1"; break;
	case PR_MODE_TCP:    svmode = "tcp"; break;
	case PR_MODE_SPOP:   svmode = "spop"; break;
	/* all valid cases must be enumerated above, below is to avoid a warning */
	case PR_MODES:       svmode = "?"; break;
	}
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_PROTO, svmode, err);

	/* Ensure that we don't leave any hole in check->envp */
	for (i = 0; i < EXTCHK_SIZE; i++)
		if (!check->envp[i])
			EXTCHK_SETENV(check, i, "", err);

	return 1;
err:
	if (check->envp) {
		for (i = 0; i < EXTCHK_SIZE; i++)
			free(check->envp[i]);
		ha_free(&check->envp);
	}

	if (check->argv) {
		for (i = 1; i < 5; i++)
			free(check->argv[i]);
		ha_free(&check->argv);
	}
	return 0;
}

/*
 * establish a server health-check that makes use of a process.
 *
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 *
 * Blocks and then unblocks SIGCHLD
 */
static int connect_proc_chk(struct task *t)
{
	char buf[256];
	struct check *check = t->context;
	struct server *s = check->server;
	struct proxy *px = s->proxy;
	int status;
	pid_t pid;

	status = SF_ERR_RESOURCE;

	block_sigchld();

	pid = fork();
	if (pid < 0) {
		ha_alert("Failed to fork process for external health check%s: %s. Aborting.\n",
			 (global.tune.options & GTUNE_INSECURE_FORK) ?
			 "" : " (likely caused by missing 'insecure-fork-wanted')",
			 strerror(errno));
		set_server_check_status(check, HCHK_STATUS_SOCKERR, strerror(errno));
		goto out;
	}
	if (pid == 0) {
		/* Child */
		extern char **environ;
		struct rlimit limit;
		int fd;
		sa_family_t family;

		/* close all FDs. Keep stdin/stdout/stderr in verbose mode */
		fd = (global.mode & (MODE_QUIET|MODE_VERBOSE)) == MODE_QUIET ? 0 : 3;

		my_closefrom(fd);

		/* restore the initial FD limits */
		limit.rlim_cur = rlim_fd_cur_at_boot;
		limit.rlim_max = rlim_fd_max_at_boot;
		if (raise_rlim_nofile(NULL, &limit) != 0) {
			getrlimit(RLIMIT_NOFILE, &limit);
			ha_warning("External check: failed to restore initial FD limits (cur=%u max=%u), using cur=%u max=%u\n",
				   rlim_fd_cur_at_boot, rlim_fd_max_at_boot,
				   (unsigned int)limit.rlim_cur, (unsigned int)limit.rlim_max);
		}

		if (global.external_check < 2) {
			/* fresh new env for each check */
			environ = check->envp;
		}

		/* Update some environment variables and command args: curconn, server addr and server port */
		EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_CURCONN, ultoa_r(s->cur_sess, buf, sizeof(buf)), fail);

		family = real_family(s->addr.ss_family);
		if (family == AF_UNIX) {
			const struct sockaddr_un *un = (struct sockaddr_un *)&s->addr;
			strlcpy2(check->argv[3], un->sun_path, EXTCHK_SIZE_ADDR);
			memcpy(check->argv[4], "NOT_USED", 9);
		} else {
			addr_to_str(&s->addr, check->argv[3], EXTCHK_SIZE_ADDR);
			*check->argv[4] = 0; // just in case the address family changed
			if (family == AF_INET || family == AF_INET6)
				snprintf(check->argv[4], EXTCHK_SIZE_UINT, "%u", s->svc_port);
		}

		EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_ADDR, check->argv[3], fail);
		EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_PORT, check->argv[4], fail);

		if (global.external_check >= 2) {
			/* environment is preserved, let's merge new vars */
			int i;

			for (i = 0; check->envp[i] && *check->envp[i]; i++) {
				char *delim = strchr(check->envp[i], '=');
				if (!delim)
					continue;
				*(delim++) = 0;
				if (setenv(check->envp[i], delim, 1) != 0)
					goto fail;
			}
		}
		haproxy_unblock_signals();
		execvp(px->check_command, check->argv);
		ha_alert("Failed to exec process for external health check: %s. Aborting.\n",
			 strerror(errno));
	fail:
		exit(-1);
	}

	/* Parent */
	if (check->result == CHK_RES_UNKNOWN) {
		if (pid_list_add(pid, t) != NULL) {
			t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));

			if (px->timeout.check && px->timeout.connect) {
				int t_con = tick_add(now_ms, px->timeout.connect);
				t->expire = tick_first(t->expire, t_con);
			}
			status = SF_ERR_NONE;
			goto out;
		}
		else {
			set_server_check_status(check, HCHK_STATUS_SOCKERR, strerror(errno));
		}
		kill(pid, SIGTERM); /* process creation error */
	}
	else
		set_server_check_status(check, HCHK_STATUS_SOCKERR, strerror(errno));

out:
	unblock_sigchld();
	return status;
}

/*
 * manages a server health-check that uses an external process. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out_unlock label.
 */
struct task *process_chk_proc(struct task *t, void *context, unsigned int state)
{
	struct check *check = context;
	struct server *s = check->server;
	int rv;
	int ret;
	int expired = tick_is_expired(t->expire, now_ms);

	HA_SPIN_LOCK(SERVER_LOCK, &check->server->lock);
	if (!(check->state & CHK_ST_INPROGRESS)) {
		/* no check currently running */
		if (!expired) /* woke up too early */
			goto out_unlock;

		/* we don't send any health-checks when the proxy is
		 * stopped, the server should not be checked or the check
		 * is disabled.
		 */
		if (((check->state & (CHK_ST_ENABLED | CHK_ST_PAUSED)) != CHK_ST_ENABLED) ||
		    (s->proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)))
			goto reschedule;

		/* we'll initiate a new check */
		set_server_check_status(check, HCHK_STATUS_START, NULL);

		check->state |= CHK_ST_INPROGRESS;

		ret = connect_proc_chk(t);
		if (ret == SF_ERR_NONE) {
			/* the process was forked, we allow up to min(inter,
			 * timeout.connect) for it to report its status, but
			 * only when timeout.check is set as it may be to short
			 * for a full check otherwise.
			 */
			t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));

			if (s->proxy->timeout.check && s->proxy->timeout.connect) {
				int t_con = tick_add(now_ms, s->proxy->timeout.connect);
				t->expire = tick_first(t->expire, t_con);
			}
			task_set_thread(t, tid);
			goto reschedule;
		}

		/* here, we failed to start the check */

		check->state &= ~CHK_ST_INPROGRESS;
		check_notify_failure(check);

		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set
		 * as it may be to short for a full check otherwise
		 */
		while (tick_is_expired(t->expire, now_ms)) {
			int t_con;

			t_con = tick_add(t->expire, s->proxy->timeout.connect);
			t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));

			if (s->proxy->timeout.check)
				t->expire = tick_first(t->expire, t_con);
		}
	}
	else {
		/* there was a test running.
		 * First, let's check whether there was an uncaught error,
		 * which can happen on connect timeout or error.
		 */
		if (check->result == CHK_RES_UNKNOWN) {
			/* good connection is enough for pure TCP check */
			struct pid_list *elem = check->curpid;
			int status = HCHK_STATUS_UNKNOWN;

			if (elem->exited) {
				status = elem->status; /* Save in case the process exits between use below */
				if (!WIFEXITED(status))
					check->code = -1;
				else
					check->code = WEXITSTATUS(status);
				if (!WIFEXITED(status) || WEXITSTATUS(status))
					status = HCHK_STATUS_PROCERR;
				else
					status = HCHK_STATUS_PROCOK;
			} else if (expired) {
				status = HCHK_STATUS_PROCTOUT;
				ha_warning("kill %d\n", (int)elem->pid);
				kill(elem->pid, SIGTERM);
			}
			set_server_check_status(check, status, NULL);
		}

		if (check->result == CHK_RES_FAILED) {
			/* a failure or timeout detected */
			check_notify_failure(check);
		}
		else if (check->result == CHK_RES_CONDPASS) {
			/* check is OK but asks for stopping mode */
			check_notify_stopping(check);
		}
		else if (check->result == CHK_RES_PASSED) {
			/* a success was detected */
			check_notify_success(check);
		}
		task_set_thread(t, 0);
		check->state &= ~CHK_ST_INPROGRESS;

		pid_list_del(check->curpid);

		rv = 0;
		if (global.spread_checks > 0) {
			rv = srv_getinter(check) * global.spread_checks / 100;
			rv -= (int) (2 * rv * (statistical_prng() / 4294967295.0));
		}
		t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(check) + rv));
	}

 reschedule:
	while (tick_is_expired(t->expire, now_ms))
		t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));

 out_unlock:
	HA_SPIN_UNLOCK(SERVER_LOCK, &check->server->lock);
	return t;
}

/* Parses the "external-check" proxy keyword */
int proxy_parse_extcheck(char **args, int section, struct proxy *curpx,
                         const struct proxy *defpx, const char *file, int line,
                         char **errmsg)
{
	int cur_arg, ret = 0;

	cur_arg = 1;
	if (!*(args[cur_arg])) {
		memprintf(errmsg, "missing argument after '%s'.\n", args[0]);
		goto error;
	}

	if (strcmp(args[cur_arg], "command") == 0) {
		if (too_many_args(2, args, errmsg, NULL))
			goto error;
		if (!*(args[cur_arg+1])) {
			memprintf(errmsg, "missing argument after '%s'.", args[cur_arg]);
			goto error;
		}
		free(curpx->check_command);
		curpx->check_command = strdup(args[cur_arg+1]);
	}
	else if (strcmp(args[cur_arg], "path") == 0) {
		if (too_many_args(2, args, errmsg, NULL))
			goto error;
		if (!*(args[cur_arg+1])) {
			memprintf(errmsg, "missing argument after '%s'.", args[cur_arg]);
			goto error;
		}
		free(curpx->check_path);
		curpx->check_path = strdup(args[cur_arg+1]);
	}
	else {
		memprintf(errmsg, "'%s' only supports 'command' and 'path'. but got '%s'.",
			  args[0], args[1]);
		goto error;
	}

	ret = (*errmsg != NULL); /* Handle warning */
	return ret;

error:
	return -1;
}

int proxy_parse_external_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
				   const char *file, int line)
{
	int err_code = 0;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_EXT_CHK;
	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

  out:
	return err_code;
}

static struct cfg_kw_list cfg_kws = {ILH, {
        { CFG_LISTEN, "external-check", proxy_parse_extcheck },
        { 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
