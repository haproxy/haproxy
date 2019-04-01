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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <common/mini-clist.h>

#include <proto/fd.h>
#include <proto/listener.h>
#include <proto/mworker.h>
#include <proto/signal.h>

#include <types/global.h>


/*
 * serialize the proc list and put it in the environment
 */
void mworker_proc_list_to_env()
{
	char *msg = NULL;
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		if (child->pid > -1)
			memprintf(&msg, "%s|type=%c;fd=%d;pid=%d;rpid=%d;reloads=%d;timestamp=%d", msg ? msg : "", child->type, child->ipc_fd[0], child->pid, child->relative_pid, child->reloads, child->timestamp);
	}
	if (msg)
		setenv("HAPROXY_PROCESSES", msg, 1);
}

/*
 * unserialize the proc list from the environment
 */
void mworker_env_to_proc_list()
{
	char *msg, *token = NULL, *s1;

	msg = getenv("HAPROXY_PROCESSES");
	if (!msg)
		return;

	while ((token = strtok_r(msg, "|", &s1))) {
		struct mworker_proc *child;
		char *subtoken = NULL;
		char *s2;

		msg = NULL;

		child = calloc(1, sizeof(*child));

		while ((subtoken = strtok_r(token, ";", &s2))) {

			token = NULL;

			if (strncmp(subtoken, "type=", 5) == 0) {
				child->type = *(subtoken+5);
				if (child->type == 'm') /* we are in the master, assign it */
					proc_self = child;
			} else if (strncmp(subtoken, "fd=", 3) == 0) {
				child->ipc_fd[0] = atoi(subtoken+3);
			} else if (strncmp(subtoken, "pid=", 4) == 0) {
				child->pid = atoi(subtoken+4);
			} else if (strncmp(subtoken, "rpid=", 5) == 0) {
				child->relative_pid = atoi(subtoken+5);
			} else if (strncmp(subtoken, "reloads=", 8) == 0) {
				/* we reloaded this process once more */
				child->reloads = atoi(subtoken+8) + 1;
			} else if (strncmp(subtoken, "timestamp=", 10) == 0) {
				child->timestamp = atoi(subtoken+10);
			}
		}
		if (child->pid)
			LIST_ADDQ(&proc_list, &child->list);
		else
			free(child);
	}

	unsetenv("HAPROXY_PROCESSES");
}

/* Signal blocking and unblocking */

void mworker_block_signals()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGCHLD);
	ha_sigmask(SIG_SETMASK, &set, NULL);
}

void mworker_unblock_signals()
{
	haproxy_unblock_signals();
}

/* ----- IPC FD (sockpair) related ----- */

/* This wrapper is called from the workers. It is registered instead of the
 * normal listener_accept() so the worker can exit() when it detects that the
 * master closed the IPC FD. If it's not a close, we just call the regular
 * listener_accept() function */
void mworker_accept_wrapper(int fd)
{
	char c;
	int ret;

	while (1) {
		ret = recv(fd, &c, 1, MSG_PEEK);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				fd_cant_recv(fd);
				return;
			}
			break;
		} else if (ret > 0) {
			listener_accept(fd);
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
 * This function register the accept wrapper for the sockpair of the master worker
 */
void mworker_pipe_register()
{
	/* The iocb should be already initialized with listener_accept */
	if (fdtab[proc_self->ipc_fd[1]].iocb == mworker_accept_wrapper)
		return;

	fcntl(proc_self->ipc_fd[1], F_SETFL, O_NONBLOCK);
	/* In multi-tread, we need only one thread to process
	 * events on the pipe with master
	 */
	fd_insert(proc_self->ipc_fd[1], fdtab[proc_self->ipc_fd[1]].owner, mworker_accept_wrapper, 1);
	fd_want_recv(proc_self->ipc_fd[1]);
}
