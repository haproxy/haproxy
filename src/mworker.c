/*
 * Master Worker
 *
 * Copyright HAProxy Technologies 2019 - William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/listener.h>
#include <haproxy/mworker.h>
#include <haproxy/peers.h>
#include <haproxy/proto_sockpair.h>
#include <haproxy/proxy.h>
#include <haproxy/ring.h>
#include <haproxy/sc_strm.h>
#include <haproxy/signal.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>

#if defined(USE_SYSTEMD)
#include <haproxy/systemd.h>
#endif

static int exitcode = -1;
static int max_reloads = -1; /* number max of reloads a worker can have until they are killed */
struct mworker_proc *proc_self = NULL; /* process structure of current process */
struct list mworker_cli_conf = LIST_HEAD_INIT(mworker_cli_conf); /* master CLI configuration (-S flag) */

/* ----- children processes handling ----- */

/*
 * Send signal to every known children.
 */

static void mworker_kill(int sig)
{
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		/* careful there, we must be sure that the pid > 0, we don't want to emit a kill -1 */
		if ((child->options & (PROC_O_TYPE_WORKER|PROC_O_TYPE_PROG)) && (child->pid > 0))
			kill(child->pid, sig);
	}
}

void mworker_kill_max_reloads(int sig)
{
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		if (max_reloads != -1 && (child->options & PROC_O_TYPE_WORKER) &&
		    (child->pid > 0) && (child->reloads > max_reloads))
			kill(child->pid, sig);
	}
}

/* return 1 if a pid is a current child otherwise 0 */
int mworker_current_child(int pid)
{
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		if ((child->options & (PROC_O_TYPE_WORKER|PROC_O_TYPE_PROG)) && (!(child->options & PROC_O_LEAVING)) && (child->pid == pid))
			return 1;
	}
	return 0;
}

/*
 * Return the number of new and old children (including workers and external
 * processes)
 */
int mworker_child_nb()
{
	struct mworker_proc *child;
	int ret = 0;

	list_for_each_entry(child, &proc_list, list) {
		if (child->options & (PROC_O_TYPE_WORKER|PROC_O_TYPE_PROG))
			ret++;
	}

	return ret;
}


/*
 * serialize the proc list and put it in the environment
 */
void mworker_proc_list_to_env()
{
	char *msg = NULL;
	struct mworker_proc *child;
	int minreloads = INT_MAX; /* minimum number of reloads to chose which processes are "current" ones */

	list_for_each_entry(child, &proc_list, list) {
		char type = '?';

		if (child->options & PROC_O_TYPE_MASTER)
			type = 'm';
		else if (child->options & PROC_O_TYPE_PROG)
			type = 'e';
		else if (child->options &= PROC_O_TYPE_WORKER)
			type = 'w';

		if (child->reloads < minreloads)
			minreloads = child->reloads;

		if (child->pid > -1)
			memprintf(&msg, "%s|type=%c;fd=%d;cfd=%d;pid=%d;reloads=%d;failedreloads=%d;timestamp=%d;id=%s;version=%s", msg ? msg : "", type, child->ipc_fd[0], child->ipc_fd[1], child->pid, child->reloads, child->failedreloads, child->timestamp, child->id ? child->id : "", child->version);
	}
	if (msg)
		setenv("HAPROXY_PROCESSES", msg, 1);

	list_for_each_entry(child, &proc_list, list) {
		if (child->reloads > minreloads && !(child->options & PROC_O_TYPE_MASTER)) {
			child->options |= PROC_O_LEAVING;
		}
	}


}

struct mworker_proc *mworker_proc_new()
{
	struct mworker_proc *child;

	child = calloc(1, sizeof(*child));
	if (!child)
		return NULL;

	child->failedreloads = 0;
	child->reloads = 0;
	child->pid = -1;
	child->ipc_fd[0] = -1;
	child->ipc_fd[1] = -1;
	child->timestamp = -1;

	return child;
}


/*
 * unserialize the proc list from the environment
 * Return < 0 upon error.
 */
int mworker_env_to_proc_list()
{
	char *env, *msg, *omsg = NULL, *token = NULL, *s1;
	struct mworker_proc *child;
	int minreloads = INT_MAX; /* minimum number of reloads to chose which processes are "current" ones */
	int err = 0;

	env = getenv("HAPROXY_PROCESSES");
	if (!env)
		goto no_env;

	omsg = msg = strdup(env);
	if (!msg) {
		ha_alert("Out of memory while trying to allocate a worker process structure.");
		err = -1;
		goto out;
	}

	while ((token = strtok_r(msg, "|", &s1))) {
		char *subtoken = NULL;
		char *s2;

		msg = NULL;

		child = mworker_proc_new();
		if (!child) {
			ha_alert("out of memory while trying to allocate a worker process structure.");
			err = -1;
			goto out;
		}

		while ((subtoken = strtok_r(token, ";", &s2))) {

			token = NULL;

			if (strncmp(subtoken, "type=", 5) == 0) {
				char type;

				type = *(subtoken+5);
				if (type == 'm') { /* we are in the master, assign it */
					proc_self = child;
					child->options |= PROC_O_TYPE_MASTER;
				} else if (type == 'e') {
					child->options |= PROC_O_TYPE_PROG;
				} else if (type == 'w') {
					child->options |= PROC_O_TYPE_WORKER;
				}

			} else if (strncmp(subtoken, "fd=", 3) == 0) {
				child->ipc_fd[0] = atoi(subtoken+3);
				if (child->ipc_fd[0] > -1)
					global.maxsock++;
			} else if (strncmp(subtoken, "cfd=", 4) == 0) {
				child->ipc_fd[1] = atoi(subtoken+4);
				if (child->ipc_fd[1] > -1)
					global.maxsock++;
			} else if (strncmp(subtoken, "pid=", 4) == 0) {
				child->pid = atoi(subtoken+4);
			} else if (strncmp(subtoken, "reloads=", 8) == 0) {
				/* we only increment the number of asked reload */
				child->reloads = atoi(subtoken+8);

				if (child->reloads < minreloads)
					minreloads = child->reloads;
			} else if (strncmp(subtoken, "failedreloads=", 14) == 0) {
				child->failedreloads = atoi(subtoken+14);
			} else if (strncmp(subtoken, "timestamp=", 10) == 0) {
				child->timestamp = atoi(subtoken+10);
			} else if (strncmp(subtoken, "id=", 3) == 0) {
				child->id = strdup(subtoken+3);
			} else if (strncmp(subtoken, "version=", 8) == 0) {
				child->version = strdup(subtoken+8);
			}
		}
		if (child->pid) {
			LIST_APPEND(&proc_list, &child->list);
		} else {
			mworker_free_child(child);
		}
	}

	/* set the leaving processes once we know which number of reloads are the current processes */

	list_for_each_entry(child, &proc_list, list) {
		if (child->reloads > minreloads)
			child->options |= PROC_O_LEAVING;
	}

	unsetenv("HAPROXY_PROCESSES");

no_env:

	if (!proc_self) {

		proc_self = mworker_proc_new();
		if (!proc_self) {
			ha_alert("Cannot allocate process structures.\n");
			err = -1;
			goto out;
		}
		proc_self->options |= PROC_O_TYPE_MASTER;
		proc_self->pid = pid;
		proc_self->timestamp = 0; /* we don't know the startime anymore */

		LIST_APPEND(&proc_list, &proc_self->list);
		ha_warning("The master internals are corrupted or it was started with a too old version (< 1.9). Please restart the master process.\n");
	}

out:
	free(omsg);
	return err;
}

/* Signal blocking and unblocking */

void mworker_block_signals()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGTTIN);
	sigaddset(&set, SIGTTOU);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGCHLD);
	ha_sigmask(SIG_SETMASK, &set, NULL);
}

void mworker_unblock_signals()
{
	haproxy_unblock_signals();
}

/* ----- mworker signal handlers ----- */

/* broadcast the configured signal to the workers */
void mworker_broadcast_signal(struct sig_handler *sh)
{
	mworker_kill(sh->arg);
}

/*
 * When called, this function reexec haproxy with -sf followed by current
 * children PIDs and possibly old children PIDs if they didn't leave yet.
 */
void mworker_catch_sighup(struct sig_handler *sh)
{
	mworker_reload(0);
}

void mworker_catch_sigterm(struct sig_handler *sh)
{
	int sig = sh->arg;

#if defined(USE_SYSTEMD)
	if (global.tune.options & GTUNE_USE_SYSTEMD) {
		sd_notify(0, "STOPPING=1");
	}
#endif
	ha_warning("Exiting Master process...\n");
	mworker_kill(sig);
}

/*
 * Wait for every children to exit
 */

void mworker_catch_sigchld(struct sig_handler *sh)
{
	int exitpid = -1;
	int status = 0;
	int childfound;

restart_wait:

	childfound = 0;

	exitpid = waitpid(-1, &status, WNOHANG);
	if (exitpid > 0) {
		struct mworker_proc *child, *it;

		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			status = 128 + WTERMSIG(status);
		else if (WIFSTOPPED(status))
			status = 128 + WSTOPSIG(status);
		else
			status = 255;

		/* delete the child from the process list */
		list_for_each_entry_safe(child, it, &proc_list, list) {
			if (child->pid != exitpid)
				continue;

			LIST_DELETE(&child->list);
			close(child->ipc_fd[0]);
			childfound = 1;
			break;
		}

		if (!childfound) {
			/* We didn't find the PID in the list, that shouldn't happen but we can emit a warning */
			ha_warning("Process %d exited with code %d (%s)\n", exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
		} else {
			/* check if exited child is a current child */
			if (!(child->options & PROC_O_LEAVING)) {
				if (child->options & PROC_O_TYPE_WORKER) {
					if (status < 128)
						ha_warning("Current worker (%d) exited with code %d (%s)\n", exitpid, status, "Exit");
					else
						ha_alert("Current worker (%d) exited with code %d (%s)\n", exitpid, status, strsignal(status - 128));
				}
				else if (child->options & PROC_O_TYPE_PROG)
					ha_alert("Current program '%s' (%d) exited with code %d (%s)\n", child->id, exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");

				if (status != 0 && status != 130 && status != 143) {
					if (child->options & PROC_O_TYPE_WORKER) {
						ha_warning("A worker process unexpectedly died and this can only be explained by a bug in haproxy or its dependencies.\nPlease check that you are running an up to date and maintained version of haproxy and open a bug report.\n");
						display_version();
					}
					if (!(global.tune.options & GTUNE_NOEXIT_ONFAILURE)) {
						ha_alert("exit-on-failure: killing every processes with SIGTERM\n");
						mworker_kill(SIGTERM);
					}
				}
				/* 0 & SIGTERM (143) are normal, but we should report SIGINT (130) and other signals */
				if (exitcode < 0 && status != 0 && status != 143)
					exitcode = status;
			} else {
				if (child->options & PROC_O_TYPE_WORKER) {
					ha_warning("Former worker (%d) exited with code %d (%s)\n", exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
					delete_oldpid(exitpid);
				} else if (child->options & PROC_O_TYPE_PROG) {
					ha_warning("Former program '%s' (%d) exited with code %d (%s)\n", child->id, exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
				}
			}
			mworker_free_child(child);
			child = NULL;
		}

		/* do it again to check if it was the last worker */
		goto restart_wait;
	}
	/* Better rely on the system than on a list of process to check if it was the last one */
	else if (exitpid == -1 && errno == ECHILD) {
		ha_warning("All workers exited. Exiting... (%d)\n", (exitcode > 0) ? exitcode : EXIT_SUCCESS);
		atexit_flag = 0;
		if (exitcode > 0)
			exit(exitcode); /* parent must leave using the status code that provoked the exit */
		exit(EXIT_SUCCESS);
	}

}

/* ----- IPC FD (sockpair) related ----- */

/* This wrapper is called from the workers. It is registered instead of the
 * normal listener_accept() so the worker can exit() when it detects that the
 * master closed the IPC FD. If it's not a close, we just call the regular
 * listener_accept() function.
 */
void mworker_accept_wrapper(int fd)
{
	char c;
	int ret;

	while (1) {
		ret = recv(fd, &c, 1, MSG_PEEK);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_cant_recv(fd);
				return;
			}
			break;
		} else if (ret > 0) {
			struct listener *l = fdtab[fd].owner;

			if (l)
				listener_accept(l);
			return;
		} else if (ret == 0) {
			/* At this step the master is down before
			 * this worker perform a 'normal' exit.
			 * So we want to exit with an error but
			 * other threads could currently process
			 * some stuff so we can't perform a clean
			 * deinit().
			 */
			exit(EXIT_FAILURE);
		}
	}
	return;
}

/*
 * This function registers the accept wrapper for the sockpair of the master
 * worker. It's only handled by worker thread #0. Other threads and master do
 * nothing here. It always returns 1 (success).
 */
static int mworker_sockpair_register_per_thread()
{
	if (!(global.mode & MODE_MWORKER) || master)
		return 1;

	if (tid != 0)
		return 1;

	if (proc_self->ipc_fd[1] < 0) /* proc_self was incomplete and we can't find the socketpair */
		return 1;

	fd_set_nonblock(proc_self->ipc_fd[1]);
	/* register the wrapper to handle read 0 when the master exits */
	fdtab[proc_self->ipc_fd[1]].iocb = mworker_accept_wrapper;
	fd_want_recv(proc_self->ipc_fd[1]);
	return 1;
}

REGISTER_PER_THREAD_INIT(mworker_sockpair_register_per_thread);

/* ----- proxies ----- */
/*
 * Upon a reload, the master worker needs to close all listeners FDs but the mworker_pipe
 * fd, and the FD provided by fd@
 */
void mworker_cleanlisteners()
{
	struct listener *l, *l_next;
	struct proxy *curproxy;
	struct peers *curpeers;

	/* peers proxies cleanup */
	for (curpeers = cfg_peers; curpeers; curpeers = curpeers->next) {
		if (!curpeers->peers_fe)
			continue;

		stop_proxy(curpeers->peers_fe);
		/* disable this peer section so that it kills itself */
		if (curpeers->sighandler)
			signal_unregister_handler(curpeers->sighandler);
		task_destroy(curpeers->sync_task);
		curpeers->sync_task = NULL;
		curpeers->peers_fe = NULL;
	}

	/* main proxies cleanup */
	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		int listen_in_master = 0;

		list_for_each_entry_safe(l, l_next, &curproxy->conf.listeners, by_fe) {
			/* remove the listener, but not those we need in the master... */
			if (!(l->rx.flags & RX_F_MWORKER)) {
				unbind_listener(l);
				delete_listener(l);
			} else {
				listen_in_master = 1;
			}
		}
		/* if the proxy shouldn't be in the master, we stop it */
		if (!listen_in_master)
			curproxy->flags |= PR_FL_DISABLED;
	}
}

/* Upon a configuration loading error some mworker_proc and FDs/server were
 * assigned but the worker was never forked, we must close the FDs and
 * remove the server
 */
void mworker_cleanup_proc()
{
	struct mworker_proc *child, *it;

	list_for_each_entry_safe(child, it, &proc_list, list) {

		if (child->pid == -1) {
			/* Close the socketpairs. */
			if (child->ipc_fd[0] > -1)
				close(child->ipc_fd[0]);
			if (child->ipc_fd[1] > -1)
				close(child->ipc_fd[1]);
			if (child->srv) {
				/* only exists if we created a master CLI listener */
				srv_drop(child->srv);
			}
			LIST_DELETE(&child->list);
			mworker_free_child(child);
		}
	}
}


/*  Displays workers and processes  */
static int cli_io_handler_show_proc(struct appctx *appctx)
{
	struct mworker_proc *child;
	int old = 0;
	int up = date.tv_sec - proc_self->timestamp;
	char *uptime = NULL;
	char *reloadtxt = NULL;

	if (up < 0) /* must never be negative because of clock drift */
		up = 0;

	chunk_reset(&trash);

	memprintf(&reloadtxt, "%d [failed: %d]", proc_self->reloads, proc_self->failedreloads);
	chunk_printf(&trash, "#%-14s %-15s %-15s %-15s %-15s\n", "<PID>", "<type>", "<reloads>", "<uptime>", "<version>");
	memprintf(&uptime, "%dd%02dh%02dm%02ds", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
	chunk_appendf(&trash, "%-15u %-15s %-15s %-15s %-15s\n", (unsigned int)getpid(), "master", reloadtxt, uptime, haproxy_version);
	ha_free(&reloadtxt);
	ha_free(&uptime);

	/* displays current processes */

	chunk_appendf(&trash, "# workers\n");
	list_for_each_entry(child, &proc_list, list) {
		up = date.tv_sec - child->timestamp;
		if (up < 0) /* must never be negative because of clock drift */
			up = 0;

		if (!(child->options & PROC_O_TYPE_WORKER))
			continue;

		if (child->options & PROC_O_LEAVING) {
			old++;
			continue;
		}
		memprintf(&uptime, "%dd%02dh%02dm%02ds", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
		chunk_appendf(&trash, "%-15u %-15s %-15d %-15s %-15s\n", child->pid, "worker", child->reloads, uptime, child->version);
		ha_free(&uptime);
	}

	/* displays old processes */

	if (old) {
		char *msg = NULL;

		chunk_appendf(&trash, "# old workers\n");
		list_for_each_entry(child, &proc_list, list) {
			up = date.tv_sec - child->timestamp;
			if (up <= 0) /* must never be negative because of clock drift */
				up = 0;

			if (!(child->options & PROC_O_TYPE_WORKER))
				continue;

			if (child->options & PROC_O_LEAVING) {
				memprintf(&uptime, "%dd%02dh%02dm%02ds", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
				chunk_appendf(&trash, "%-15u %-15s %-15d %-15s %-15s\n", child->pid, "worker", child->reloads, uptime, child->version);
				ha_free(&uptime);
			}
		}
		free(msg);
	}

	/* displays external process */
	chunk_appendf(&trash, "# programs\n");
	old = 0;
	list_for_each_entry(child, &proc_list, list) {
		up = date.tv_sec - child->timestamp;
		if (up < 0) /* must never be negative because of clock drift */
			up = 0;

		if (!(child->options & PROC_O_TYPE_PROG))
			continue;

		if (child->options & PROC_O_LEAVING) {
			old++;
			continue;
		}
		memprintf(&uptime, "%dd%02dh%02dm%02ds", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
		chunk_appendf(&trash, "%-15u %-15s %-15d %-15s %-15s\n", child->pid, child->id, child->reloads, uptime, "-");
		ha_free(&uptime);
	}

	if (old) {
		chunk_appendf(&trash, "# old programs\n");
		list_for_each_entry(child, &proc_list, list) {
			up = date.tv_sec - child->timestamp;
			if (up < 0) /* must never be negative because of clock drift */
				up = 0;

			if (!(child->options & PROC_O_TYPE_PROG))
				continue;

			if (child->options & PROC_O_LEAVING) {
				memprintf(&uptime, "%dd%02dh%02dm%02ds", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
				chunk_appendf(&trash, "%-15u %-15s %-15d %-15s %-15s\n", child->pid, child->id, child->reloads, uptime, "-");
				ha_free(&uptime);
			}
		}
	}



	if (applet_putchk(appctx, &trash) == -1)
		return 0;

	/* dump complete */
	return 1;
}

/* reload the master process */
static int cli_parse_reload(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct stconn *scb = NULL;
	struct stream *strm = NULL;
	struct connection *conn = NULL;
	int fd = -1;
	int hardreload = 0;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	/* hard reload requested */
	if (*args[0] == 'h')
		hardreload = 1;

	/* This ask for a synchronous reload, which means we will keep this FD
	   instead of closing it. */

	scb = appctx_sc(appctx);
	if (scb)
		strm = sc_strm(scb);
	if (strm && strm->scf)
		conn = sc_conn(strm->scf);
	if (conn)
		fd = conn_fd(conn);

	/* Send the FD of the current session to the "cli_reload" FD, which won't be polled */
	if (fd != -1 && send_fd_uxst(proc_self->ipc_fd[0], fd) == 0) {
		fd_delete(fd); /* avoid the leak of the FD after sending it via the socketpair */
	}
	mworker_reload(hardreload);

	return 1;
}

/* Displays if the current reload failed or succeed.
 * If the startup-logs is available, dump it.  */
static int cli_io_handler_show_loadstatus(struct appctx *appctx)
{
	char *env;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	env = getenv("HAPROXY_LOAD_SUCCESS");
	if (!env)
		return 1;

	if (strcmp(env, "0") == 0) {
		chunk_printf(&trash, "Success=0\n");
	} else if (strcmp(env, "1") == 0) {
		chunk_printf(&trash, "Success=1\n");
	}
#ifdef USE_SHM_OPEN
	if (startup_logs && ring_data(startup_logs) > 1)
		chunk_appendf(&trash, "--\n");

	if (applet_putchk(appctx, &trash) == -1)
		return 0;

	if (startup_logs) {
		appctx->io_handler = NULL;
		ring_attach_cli(startup_logs, appctx, 0);
		return 0;
	}
#else
	if (applet_putchk(appctx, &trash) == -1)
		return 0;
#endif
	return 1;
}

static int mworker_parse_global_max_reloads(char **args, int section_type, struct proxy *curpx,
           const struct proxy *defpx, const char *file, int linenum, char **err)
{

	int err_code = 0;

	if (alertif_too_many_args(1, file, linenum, args, &err_code))
		goto out;

	if (*(args[1]) == 0) {
		memprintf(err, "%sparsing [%s:%d] : '%s' expects an integer argument.\n", *err, file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	max_reloads = atol(args[1]);
	if (max_reloads < 0) {
		memprintf(err, "%sparsing [%s:%d] '%s' : invalid value %d, must be >= 0", *err, file, linenum, args[0], max_reloads);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

out:
	return err_code;
}

void mworker_free_child(struct mworker_proc *child)
{
	int i;

	if (child == NULL)
		return;

	for (i = 0; child->command && child->command[i]; i++)
		ha_free(&child->command[i]);

	ha_free(&child->command);
	ha_free(&child->id);
	ha_free(&child->version);
	free(child);
}

/* Creates and binds dedicated master CLI 'reload' sockpair and listeners */
void mworker_create_master_cli(void)
{
	struct wordlist *it, *c;

	/* get the info of the children in the env */
	if (mworker_env_to_proc_list() < 0) {
		exit(EXIT_FAILURE);
	}

	if (!LIST_ISEMPTY(&mworker_cli_conf)) {
		char *path = NULL;

		if (mworker_cli_proxy_create() < 0) {
			ha_alert("Can't create the master's CLI.\n");
			exit(EXIT_FAILURE);
		}

		list_for_each_entry_safe(c, it, &mworker_cli_conf, list) {

			if (mworker_cli_proxy_new_listener(c->s) == NULL) {
				ha_alert("Can't create the master's CLI.\n");
				exit(EXIT_FAILURE);
			}
			LIST_DELETE(&c->list);
			free(c->s);
			free(c);
		}
		/* Creates the mcli_reload listener, which is the listener used
		 * to retrieve the master CLI session which asked for the reload.
		 *
		 * ipc_fd[1] will be used as a listener, and ipc_fd[0]
		 * will be used to send the FD of the session.
		 *
		 * Both FDs will be kept in the master. The sockets are
		 * created only if they weren't inherited.
		 */
		if ((proc_self->ipc_fd[1] == -1) &&
		     socketpair(AF_UNIX, SOCK_STREAM, 0, proc_self->ipc_fd) < 0) {
			ha_alert("Can't create the mcli_reload socketpair.\n");
			exit(EXIT_FAILURE);
		}

		/* Create the mcli_reload listener from the proc_self struct */
		memprintf(&path, "sockpair@%d", proc_self->ipc_fd[1]);
		mcli_reload_bind_conf = mworker_cli_proxy_new_listener(path);
		if (mcli_reload_bind_conf == NULL) {
			ha_alert("Can't create the mcli_reload listener.\n");
			exit(EXIT_FAILURE);
		}
		ha_free(&path);
	}
}

static struct cfg_kw_list mworker_kws = {{ }, {
	{ CFG_GLOBAL, "mworker-max-reloads", mworker_parse_global_max_reloads },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &mworker_kws);


/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "@<relative pid>", NULL }, "@<relative pid>                         : send a command to the <relative pid> process", NULL, cli_io_handler_show_proc, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "@!<pid>", NULL },         "@!<pid>                                 : send a command to the <pid> process", cli_parse_default, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "@master", NULL },         "@master                                 : send a command to the master process", cli_parse_default, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "show", "proc", NULL },    "show proc                               : show processes status", cli_parse_default, cli_io_handler_show_proc, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "reload", NULL },          "reload                                  : achieve a soft-reload (-sf) of haproxy", cli_parse_reload, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "hard-reload", NULL },     "hard-reload                             : achieve a hard-reload (-st) of haproxy", cli_parse_reload, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "_loadstatus", NULL },     NULL,                                                             cli_parse_default, cli_io_handler_show_loadstatus, NULL, NULL, ACCESS_MASTER_ONLY},
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
