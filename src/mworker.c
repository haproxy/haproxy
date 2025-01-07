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
#include <haproxy/ssl_sock.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/systemd.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>


static int exitcode = -1;
int max_reloads = INT_MAX; /* max number of reloads a worker can have until they are killed */
int load_status; /* worker process startup status: 1 - loaded successfully; 0 - load failed */
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

	list_for_each_entry(child, &proc_list, list) {
		char type = '?';

		if (child->options & PROC_O_TYPE_MASTER)
			type = 'm';
		else if (child->options & PROC_O_TYPE_PROG)
			type = 'e';
		else if (child->options &= PROC_O_TYPE_WORKER)
			type = 'w';

		if (child->pid > -1)
			memprintf(&msg, "%s|type=%c;fd=%d;cfd=%d;pid=%d;reloads=%d;failedreloads=%d;timestamp=%d;id=%s;version=%s", msg ? msg : "", type, child->ipc_fd[0], child->ipc_fd[1], child->pid, child->reloads, child->failedreloads, child->timestamp, child->id ? child->id : "", child->version);
	}
	if (msg)
		setenv("HAPROXY_PROCESSES", msg, 1);
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
		char *s2 = NULL;

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
		if (child->reloads > 0)
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
static void mworker_reexec(int hardreload)
{
	char **next_argv = NULL;
	int old_argc = 0; /* previous number of argument */
	int next_argc = 0;
	int i = 0;
	char *msg = NULL;
	struct rlimit limit;
	struct mworker_proc *current_child = NULL;
	int x_off = 0; /* disable -x by putting -x /dev/null */

	mworker_block_signals();

	/* restore initial environment (before parsing the config) and do re-exec.
	 * The initial process environment should be restored here, preceded by
	 * clean_env(), which do the same job as clearenv().
	 * Otherwise, after the re-exec we will start the new worker in the
	 * environment modified by '*env' keywords from the previous configuration,
	 * i.e. existed before the reload.
	 */
	if (clean_env() != 0) {
		ha_alert("Master encountered a non-recoverable error, exiting.\n");
		exit(EXIT_FAILURE);
	}

	if (restore_env() != 0) {
		ha_alert("Master encountered a non-recoverable error, exiting.\n");
		exit(EXIT_FAILURE);
	}

	setenv("HAPROXY_MWORKER_REEXEC", "1", 1);

	mworker_proc_list_to_env(); /* put the children description in the env */

	/* during the reload we must ensure that every FDs that can't be
	 * reuse (ie those that are not referenced in the proc_list)
	 * are closed or they will leak. */

	/* close the listeners FD */
	mworker_cli_proxy_stop();

	if (fdtab)
		deinit_pollers();

#ifdef HAVE_SSL_RAND_KEEP_RANDOM_DEVICES_OPEN
	/* close random device FDs */
	RAND_keep_random_devices_open(0);
#endif

	/* restore the initial FD limits */
	limit.rlim_cur = rlim_fd_cur_at_boot;
	limit.rlim_max = rlim_fd_max_at_boot;
	if (raise_rlim_nofile(&limit, &limit) != 0) {
		ha_warning("Failed to restore initial FD limits (cur=%u max=%u), using cur=%u max=%u\n",
			   rlim_fd_cur_at_boot, rlim_fd_max_at_boot,
			   (unsigned int)limit.rlim_cur, (unsigned int)limit.rlim_max);
	}

	/* compute length  */
	while (old_argv[old_argc])
		old_argc++;

	/* 1 for haproxy -sf, 2 for -x /socket */
	next_argv = calloc(old_argc + 1 + 2 + mworker_child_nb() + 1,
			   sizeof(*next_argv));
	if (next_argv == NULL)
		goto alloc_error;

	/* copy the program name */
	next_argv[next_argc++] = old_argv[0];

	/* we need to reintroduce /dev/null every time */
	if (old_unixsocket && strcmp(old_unixsocket, "/dev/null") == 0)
		x_off = 1;

	/* insert the new options just after argv[0] in case we have a -- */

	/* add -sf <PID>*  to argv */
	if (mworker_child_nb() > 0) {
		struct mworker_proc *child;

		if (hardreload)
			next_argv[next_argc++] = "-st";
		else
			next_argv[next_argc++] = "-sf";

		list_for_each_entry(child, &proc_list, list) {
			if (!(child->options & PROC_O_LEAVING) && (child->options & PROC_O_TYPE_WORKER))
				current_child = child;

			if (!(child->options & (PROC_O_TYPE_WORKER)) || child->pid <= -1)
				continue;
			if ((next_argv[next_argc++] = memprintf(&msg, "%d", child->pid)) == NULL)
				goto alloc_error;
			msg = NULL;
		}
	}
	if (!x_off && current_child) {
		/* add the -x option with the socketpair of the current worker */
		next_argv[next_argc++] = "-x";
		if ((next_argv[next_argc++] = memprintf(&msg, "sockpair@%d", current_child->ipc_fd[0])) == NULL)
			goto alloc_error;
		msg = NULL;
	}

	if (x_off) {
		/* if the cmdline contained a -x /dev/null, continue to use it */
		next_argv[next_argc++] = "-x";
		next_argv[next_argc++] = "/dev/null";
	}

	/* copy the previous options */
	for (i = 1; i < old_argc; i++)
		next_argv[next_argc++] = old_argv[i];

	/* need to withdraw MODE_STARTING from master, because we have to free
	 * the startup logs ring here, see more details in print_message()
	 */
	global.mode &= ~MODE_STARTING;
	startup_logs_free(startup_logs);

	signal(SIGPROF, SIG_IGN);
	execvp(next_argv[0], next_argv);
	ha_warning("Failed to reexecute the master process [%d]: %s\n", pid, strerror(errno));
	ha_free(&next_argv);
	return;

alloc_error:
	ha_free(&next_argv);
	ha_warning("Failed to reexecute the master process [%d]: Cannot allocate memory\n", pid);
	return;
}

/* reload haproxy and emit a warning */
static void mworker_reload(int hardreload)
{
	struct mworker_proc *child;
	struct per_thread_deinit_fct *ptdf;

	ha_notice("Reloading HAProxy%s\n", hardreload?" (hard-reload)":"");

	/* close the poller FD and the thread waker pipe FD */
	list_for_each_entry(ptdf, &per_thread_deinit_list, list)
		ptdf->fct();

	/* increment the number of reloads, child->reloads is checked in
	 * mworker_env_to_proc_list() (after reload) in order to set
	 * PROC_O_LEAVING flag for the process
	 */
	list_for_each_entry(child, &proc_list, list) {
		child->reloads++;
	}

	if (global.tune.options & GTUNE_USE_SYSTEMD) {
		struct timespec ts;

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);

		sd_notifyf(0,
		           "RELOADING=1\n"
		               "STATUS=Reloading Configuration.\n"
		               "MONOTONIC_USEC=%" PRIu64 "\n",
		           (ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL));
	}
	mworker_reexec(hardreload);
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

	if (global.tune.options & GTUNE_USE_SYSTEMD) {
		sd_notify(0, "STOPPING=1");
	}
	ha_warning("Exiting Master process...\n");
	mworker_kill(sig);
}

/*
 * Performs some routines for the worker process, which has failed the reload,
 * updates the global load_status.
 */
static void mworker_on_new_child_failure()
{
	struct mworker_proc *child;

	/* increment the number of failed reloads */
	list_for_each_entry(child, &proc_list, list) {
		child->failedreloads++;
	}

	/* do not keep unused FDs retrieved from the previous process */
	sock_drop_unused_old_sockets();

	usermsgs_clr(NULL);
	load_status = 0;
	ha_warning("Failed to load worker!\n");
	/* the sd_notify API is not able to send a reload failure signal. So
	 * the READY=1 signal still need to be sent */
	if (global.tune.options & GTUNE_USE_SYSTEMD)
		sd_notify(0, "READY=1\nSTATUS=Reload failed!\n");
}

/*
 * Wait for every children to exit
 */

void mworker_catch_sigchld(struct sig_handler *sh)
{
	int exitpid = -1;
	int status = 0;
	int childfound;
	struct listener *l, *l_next;
	struct proxy *curproxy;

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
			childfound = 1;
			break;
		}

		if (!childfound) {
			/* We didn't find the PID in the list, that shouldn't happen but we can emit a warning */
			ha_warning("Process %d exited with code %d (%s)\n", exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
		} else if (child->options & PROC_O_INIT) {
			mworker_on_new_child_failure();

			/* Detach all listeners */
			for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
				list_for_each_entry_safe(l, l_next, &curproxy->conf.listeners, by_fe) {
					if ((l->rx.fd == child->ipc_fd[0]) || (l->rx.fd == child->ipc_fd[1])) {
						unbind_listener(l);
						delete_listener(l);
					}
				}
			}

			/* Drop server */
			if (child->srv)
				srv_drop(child->srv);

			/* Delete fd from poller fdtab, which will close it */
			fd_delete(child->ipc_fd[0]);
			child->ipc_fd[0] = -1;
			mworker_free_child(child);
			child = NULL;

			/* When worker fails during the first startup, there is
			 * no previous workers with state PROC_O_LEAVING, master
			 * process should exit here as well to keep the
			 * previous behaviour
			 */
			if ((proc_self->options & PROC_O_TYPE_MASTER) && (proc_self->reloads == 0))
				exit(status);
		} else {
			/* check if exited child is a current child */
			if (!(child->options & PROC_O_LEAVING)) {
				if (child->options & PROC_O_TYPE_WORKER) {
					fd_delete(child->ipc_fd[0]);
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
					/* new worker, which has been launched at reload has status PROC_O_INIT */
					if (!(global.tune.options & GTUNE_NOEXIT_ONFAILURE) && !(child->options & PROC_O_INIT)) {
						ha_alert("exit-on-failure: killing every processes with SIGTERM\n");
						mworker_kill(SIGTERM);
					}
				}
				/* 0 & SIGTERM (143) are normal, but we should report SIGINT (130) and other signals */
				if (exitcode < 0 && status != 0 && status != 143)
					exitcode = status;
			} else {
				if (child->options & PROC_O_TYPE_WORKER) {
					if (child->reloads > max_reloads)
						ha_warning("Former worker (%d) exited with code %d (%s), as it exceeds max reloads (%d)\n", exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit", max_reloads);
					else
						ha_warning("Former worker (%d) exited with code %d (%s)\n", exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
					/* Delete fd from poller fdtab, which will close it */
					fd_delete(child->ipc_fd[0]);
					delete_oldpid(exitpid);
				} else if (child->options & PROC_O_TYPE_PROG) {
					/* ipc_fd[0] and ipc_fd[1] are not used for PROC_O_TYPE_PROG and kept as -1,
					 * thus they are never inserted in fdtab (otherwise, BUG_ON in fd_insert if fd <0)
					 */
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

struct cli_showproc_ctx {
	int debug;
};

/*  Displays workers and processes  */
static int cli_io_handler_show_proc(struct appctx *appctx)
{
	struct mworker_proc *child;
	int old = 0;
	int up = date.tv_sec - proc_self->timestamp;
	struct cli_showproc_ctx *ctx = appctx->svcctx;
	char *uptime = NULL;
	char *reloadtxt = NULL;
	int program_nb = 0;

	if (up < 0) /* must never be negative because of clock drift */
		up = 0;

	chunk_reset(&trash);

	memprintf(&reloadtxt, "%d [failed: %d]", proc_self->reloads, proc_self->failedreloads);
	chunk_printf(&trash, "#%-14s %-15s %-15s %-15s %-15s", "<PID>", "<type>", "<reloads>", "<uptime>", "<version>");
	if (ctx->debug)
		chunk_appendf(&trash, "\t\t %-15s %-15s", "<ipc_fd[0]>", "<ipc_fd[1]>");
	chunk_appendf(&trash, "\n");
	memprintf(&uptime, "%dd%02dh%02dm%02ds", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
	chunk_appendf(&trash, "%-15u %-15s %-15s %-15s %-15s", (unsigned int)getpid(), "master", reloadtxt, uptime, haproxy_version);
	if (ctx->debug)
		chunk_appendf(&trash, "\t\t %-15d %-15d", proc_self->ipc_fd[0], proc_self->ipc_fd[1]);
	chunk_appendf(&trash, "\n");
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
		chunk_appendf(&trash, "%-15u %-15s %-15d %-15s %-15s", child->pid, "worker", child->reloads, uptime, child->version);
		if (ctx->debug)
			chunk_appendf(&trash, "\t\t %-15d %-15d", child->ipc_fd[0], child->ipc_fd[1]);
		chunk_appendf(&trash, "\n");
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
				chunk_appendf(&trash, "%-15u %-15s %-15d %-15s %-15s", child->pid, "worker", child->reloads, uptime, child->version);
				if (ctx->debug)
					chunk_appendf(&trash, "\t\t %-15d %-15d", child->ipc_fd[0], child->ipc_fd[1]);
				chunk_appendf(&trash, "\n");
				ha_free(&uptime);
			}
		}
		free(msg);
	}

	/* displays external process */
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
		if (program_nb == 0)
			chunk_appendf(&trash, "# programs\n");
		program_nb++;
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
static int cli_parse_show_proc(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cli_showproc_ctx *ctx;

	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (*args[2]) {

		if (strcmp(args[2], "debug") == 0)
			ctx->debug = 1;
		else
			return cli_err(appctx, "'show proc' only supports 'debug' as argument\n");
	}

	return 0;
}

/* reload the master process */
static int cli_parse_reload(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct stconn *scb = NULL;
	struct stream *strm = NULL;
	struct connection *conn = NULL;
	int fd = -1;
	int hardreload = 0;
	struct mworker_proc *proc;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	list_for_each_entry(proc, &proc_list, list) {
		/* if there is a process with PROC_O_INIT, i.e. new worker is
		 * doing its init routine, block the reload
		 */
		if (proc->options & PROC_O_INIT) {
			chunk_printf(&trash, "Success=0\n");
			chunk_appendf(&trash, "--\n");
			chunk_appendf(&trash, "Another reload is still in progress.\n");

			if (applet_putchk(appctx, &trash) == -1)
				return 0;

			return 1;
		}
	}

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
	struct mworker_proc *proc;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	/* if the worker is still in the process of starting, we have to
	 * wait a little bit before trying again to get a final status.
	 */
	list_for_each_entry(proc, &proc_list, list) {
		if (proc->options & PROC_O_INIT) {
			appctx->t->expire = tick_add(now_ms, 50);
			return 0;
		}
	}

	if (load_status == 0)
		chunk_printf(&trash, "Success=0\n");
	else
		chunk_printf(&trash, "Success=1\n");

	if (startup_logs && ring_data(startup_logs) > 1)
		chunk_appendf(&trash, "--\n");

	if (applet_putchk(appctx, &trash) == -1)
		return 0;

	if (startup_logs) {
		appctx->io_handler = NULL;
		ring_attach_cli(startup_logs, appctx, 0);
		return 0;
	}
	return 1;
}

static int mworker_parse_global_max_reloads(char **args, int section_type, struct proxy *curpx,
           const struct proxy *defpx, const char *file, int linenum, char **err)
{
	if (!(global.mode & MODE_DISCOVERY))
		return 0;

	if (strcmp(args[0], "mworker-max-reloads") == 0) {
		if (too_many_args(1, args, err, NULL))
			return -1;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}

		max_reloads = atol(args[1]);
		if (max_reloads < 0) {
			memprintf(err, "'%s' expects a positive value or zero.", args[0]);
			return -1;
		}
	} else {
		BUG_ON(1, "Triggered in mworker_parse_global_max_reloads() by unsupported keyword.\n");
		return -1;
	}

	return 0;
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

	if (!LIST_ISEMPTY(&mworker_cli_conf)) {
		char *path = NULL;

		list_for_each_entry_safe(c, it, &mworker_cli_conf, list) {
			if (mworker_cli_master_proxy_new_listener(c->s) == NULL) {
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
		if (proc_self->ipc_fd[1] == -1) {
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, proc_self->ipc_fd) < 0) {
				ha_alert("Can't create the mcli_reload socketpair.\n");
				exit(EXIT_FAILURE);
			}
		}

		/* Create the mcli_reload listener from the proc_self struct */
		memprintf(&path, "sockpair@%d", proc_self->ipc_fd[1]);

		mcli_reload_bind_conf = mworker_cli_master_proxy_new_listener(path);
		if (mcli_reload_bind_conf == NULL) {
			ha_alert("Can't create the mcli_reload listener.\n");
			exit(EXIT_FAILURE);
		}
		ha_free(&path);
	}
}

/* This function fills proc_list for master-worker mode and creates a sockpair,
 * copied after master-worker fork() to each process context to enable master
 * CLI at worker side (worker can send its status to master).It only returns if
 * everything is OK. If something fails, it exits.
 */
void mworker_prepare_master(void)
{
	struct mworker_proc *tmproc;

	setenv("HAPROXY_MWORKER", "1", 1);

	if (getenv("HAPROXY_MWORKER_REEXEC") == NULL) {

		tmproc = mworker_proc_new();
		if (!tmproc) {
			ha_alert("Cannot allocate process structures.\n");
			exit(EXIT_FAILURE);
		}
		tmproc->options |= PROC_O_TYPE_MASTER; /* master */
		tmproc->pid = pid;
		tmproc->timestamp = start_date.tv_sec;
		proc_self = tmproc;

		LIST_APPEND(&proc_list, &tmproc->list);
	}

	tmproc = mworker_proc_new();
	if (!tmproc) {
		ha_alert("Cannot allocate process structures.\n");
		exit(EXIT_FAILURE);
	}
	/* worker */
	tmproc->options |= (PROC_O_TYPE_WORKER | PROC_O_INIT);

	/* create a sockpair to copy it via fork(), thus it will be in
	 * master and in worker processes
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, tmproc->ipc_fd) < 0) {
		ha_alert("Cannot create worker master CLI socketpair.\n");
		exit(EXIT_FAILURE);
	}
	LIST_APPEND(&proc_list, &tmproc->list);
}

static void mworker_loop()
{

	/* Busy polling makes no sense in the master :-) */
	global.tune.options &= ~GTUNE_BUSY_POLLING;


	signal_unregister(SIGTTIN);
	signal_unregister(SIGTTOU);
	signal_unregister(SIGUSR1);
	signal_unregister(SIGHUP);
	signal_unregister(SIGQUIT);

	signal_register_fct(SIGTERM, mworker_catch_sigterm, SIGTERM);
	signal_register_fct(SIGUSR1, mworker_catch_sigterm, SIGUSR1);
	signal_register_fct(SIGTTIN, mworker_broadcast_signal, SIGTTIN);
	signal_register_fct(SIGTTOU, mworker_broadcast_signal, SIGTTOU);
	signal_register_fct(SIGINT, mworker_catch_sigterm, SIGINT);
	signal_register_fct(SIGHUP, mworker_catch_sighup, SIGHUP);
	signal_register_fct(SIGUSR2, mworker_catch_sighup, SIGUSR2);
	signal_register_fct(SIGCHLD, mworker_catch_sigchld, SIGCHLD);

	mworker_unblock_signals();
	mworker_cleantasks();

	mworker_catch_sigchld(NULL); /* ensure we clean the children in case
				     some SIGCHLD were lost */

	jobs++; /* this is the "master" job, we want to take care of the
		signals even if there is no listener so the poll loop don't
		leave */

	fork_poller();
	run_thread_poll_loop(NULL);
}

void mworker_run_master(void)
{
	struct mworker_proc *child, *it;

	proc_self->failedreloads = 0; /* reset the number of failure */
	mworker_loop();
#if defined(USE_OPENSSL) && !defined(OPENSSL_NO_DH)
	ssl_free_dh();
#endif
	master = 0;
	/* close useless master sockets */
	mworker_cli_proxy_stop();

	/* free proc struct of other processes  */
	list_for_each_entry_safe(child, it, &proc_list, list) {
		/* close the FD of the master side for all
		 * workers, we don't need to close the worker
		 * side of other workers since it's done with
		 * the bind_proc */
		if (child->ipc_fd[0] >= 0) {
			close(child->ipc_fd[0]);
			child->ipc_fd[0] = -1;
		}
		LIST_DELETE(&child->list);
		mworker_free_child(child);
		child = NULL;
	}
	/* master must leave */
	exit(0);
}

/* This function at first does master-worker fork. It creates then GLOBAL and
 * MASTER proxies, allocates listeners for these proxies and binds a GLOBAL
 * proxy listener in worker process on ipc_fd[1] and MASTER proxy listener
 * in master process on ipc_fd[0]. ipc_fd[0] and ipc_fd[1] are the "ends" of the
 * sockpair, created in prepare_master(). This sockpair is copied via fork to
 * each process and serves as communication channel between master and worker
 * (master CLI applet is attached in master process to MASTER proxy). This
 * function returns only if everything is OK. If something fails, it exits.
 */
void mworker_apply_master_worker_mode(void)
{
	int worker_pid;
	struct mworker_proc *child;
	char *sock_name = NULL;
	char *errmsg = NULL;

	worker_pid = fork();
	switch (worker_pid) {
	case -1:
		ha_alert("[%s.main()] Cannot fork.\n", progname);

		exit(EXIT_FAILURE);
	case 0:
		if (daemon_fd[1] >= 0) {
			close(daemon_fd[1]);
			daemon_fd[1] = -1;
		}

		/* This one must not be exported, it's internal! */
		unsetenv("HAPROXY_MWORKER_REEXEC");
		ha_random_jump96(1);

		list_for_each_entry(child, &proc_list, list) {
			if ((child->options & PROC_O_TYPE_WORKER) && (child->options & PROC_O_INIT)) {
				close(child->ipc_fd[0]);
				child->ipc_fd[0] = -1;
				/* proc_self needs to point to the new forked worker in
				 * worker's context, as it's dereferenced in
				 * mworker_sockpair_register_per_thread(), called for
				 * master and for worker.
				 */
				proc_self = child;
				/* attach listener to GLOBAL proxy on child->ipc_fd[1] */
				if (mworker_cli_global_proxy_new_listener(child) < 0)
					exit(EXIT_FAILURE);

				break;
			}

			/* need to close reload sockpair fds, inherited after master's execvp and fork(),
			 * we can't close these fds in master before the fork(), as ipc_fd[1] serves after
			 * the mworker_reexec to obtain the MCLI client connection fd, like this we can
			 * write to this connection fd the content of the startup_logs ring.
			 */
			if (child->options & PROC_O_TYPE_MASTER) {
				if (child->ipc_fd[0] > 0)
					close(child->ipc_fd[0]);
				if (child->ipc_fd[1] > 0)
					close(child->ipc_fd[1]);
			}
		}
		break;
	default:
		/* in parent */
		ha_notice("Initializing new worker (%d)\n", worker_pid);
		master = 1;

		/* in exec mode, there's always exactly one thread. Failure to
		 * set these ones now will result in nbthread being detected
		 * automatically.
		 */
		global.nbtgroups = 1;
		global.nbthread = 1;

		/* creates MASTER proxy */
		if (mworker_cli_create_master_proxy(&errmsg) < 0) {
			ha_alert("Can't create MASTER proxy: %s\n", errmsg);
			free(errmsg);
			exit(EXIT_FAILURE);
		}

		/* attaches servers to all existed workers on its shared MCLI sockpair ends, ipc_fd[0] */
		if (mworker_cli_attach_server(&errmsg) < 0) {
			ha_alert("Can't attach servers needed for master CLI %s\n", errmsg ? errmsg : "");
			free(errmsg);
			exit(EXIT_FAILURE);
		}

		/* creates reload sockpair and listeners for master CLI (-S) */
		mworker_create_master_cli();

		/* find the right mworker_proc */
		list_for_each_entry(child, &proc_list, list) {
			if ((child->options & PROC_O_TYPE_WORKER) && (child->options & PROC_O_INIT)) {
				child->timestamp = date.tv_sec;
				child->pid = worker_pid;
				child->version = strdup(haproxy_version);

				close(child->ipc_fd[1]);
				child->ipc_fd[1] = -1;

				/* attach listener to MASTER proxy on child->ipc_fd[0] */
				memprintf(&sock_name, "sockpair@%d", child->ipc_fd[0]);
				if (mworker_cli_master_proxy_new_listener(sock_name) == NULL) {
					ha_free(&sock_name);
					exit(EXIT_FAILURE);
				}
				ha_free(&sock_name);

				break;
			}
		}
	}
}

static struct cfg_kw_list mworker_kws = {{ }, {
	{ CFG_GLOBAL, "mworker-max-reloads", mworker_parse_global_max_reloads, KWF_DISCOVERY },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &mworker_kws);


/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "@<relative pid>", NULL }, "@<relative pid>                         : send a command to the <relative pid> process", NULL, cli_io_handler_show_proc, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "@!<pid>", NULL },         "@!<pid>                                 : send a command to the <pid> process", cli_parse_default, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "@master", NULL },         "@master                                 : send a command to the master process", cli_parse_default, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "show", "proc", NULL },    "show proc                               : show processes status", cli_parse_show_proc, cli_io_handler_show_proc, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "reload", NULL },          "reload                                  : achieve a soft-reload (-sf) of haproxy", cli_parse_reload, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "hard-reload", NULL },     "hard-reload                             : achieve a hard-reload (-st) of haproxy", cli_parse_reload, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "_loadstatus", NULL },     NULL,                                                             cli_parse_default, cli_io_handler_show_loadstatus, NULL, NULL, ACCESS_MASTER_ONLY},
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
