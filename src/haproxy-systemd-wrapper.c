/*
 * Wrapper to make haproxy systemd-compliant.
 *
 * Copyright 2013 Marc-Antoine Perennou <Marc-Antoine@Perennou.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define REEXEC_FLAG "HAPROXY_SYSTEMD_REEXEC"
#define SD_DEBUG "<7>"
#define SD_NOTICE "<5>"

static volatile sig_atomic_t caught_signal;

static char *pid_file = "/run/haproxy.pid";
static int wrapper_argc;
static char **wrapper_argv;

static void setup_signal_handler();
static void pause_signal_handler();
static void reset_signal_handler();


/* returns the path to the haproxy binary into <buffer>, whose size indicated
 * in <buffer_size> must be at least 1 byte long.
 */
static void locate_haproxy(char *buffer, size_t buffer_size)
{
	char *end = NULL;
	int len;

	len = readlink("/proc/self/exe", buffer, buffer_size - 1);
	if (len == -1)
		goto fail;

	buffer[len] = 0;
	end = strrchr(buffer, '/');
	if (end == NULL)
		goto fail;

	if (strcmp(end + strlen(end) - 16, "-systemd-wrapper") == 0) {
		end[strlen(end) - 16] = '\0';
		return;
	}

	end[1] = '\0';
	strncpy(end + 1, "haproxy", buffer + buffer_size - (end + 1));
	buffer[buffer_size - 1] = '\0';
	return;
 fail:
	strncpy(buffer, "/usr/sbin/haproxy", buffer_size);
	buffer[buffer_size - 1] = '\0';
	return;
}

/* Note: this function must not exit in case of error (except in the child), as
 * it is only dedicated the starting a new haproxy process. By keeping the
 * process alive it will ensure that future signal delivery may get rid of
 * the issue. If the first startup fails, the wrapper will notice it and
 * return an error thanks to wait() returning ECHILD.
 */
static void spawn_haproxy(char **pid_strv, int nb_pid)
{
	char haproxy_bin[512];
	pid_t pid;
	int main_argc;
	char **main_argv;
	int pipefd[2];
	char fdstr[20];
	int ret;

	main_argc = wrapper_argc - 1;
	main_argv = wrapper_argv + 1;

	if (pipe(pipefd) != 0) {
		fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: failed to create a pipe, please try again later.\n");
		return;
	}

	pid = fork();
	if (!pid) {
		char **argv;
		char *stats_socket = NULL;
		int i;
		int argno = 0;

		/* 3 for "haproxy -Ds -sf" */
		if (nb_pid > 0)
			stats_socket = getenv("HAPROXY_STATS_SOCKET");
		argv = calloc(4 + main_argc + nb_pid + 1 +
		    (stats_socket != NULL ? 2 : 0), sizeof(char *));
		if (!argv) {
			fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: failed to calloc(), please try again later.\n");
			exit(1);
		}

		reset_signal_handler();

		close(pipefd[0]); /* close the read side */

		snprintf(fdstr, sizeof(fdstr), "%d", pipefd[1]);
		if (setenv("HAPROXY_WRAPPER_FD", fdstr, 1) != 0) {
			fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: failed to setenv(), please try again later.\n");
			exit(1);
		}

		locate_haproxy(haproxy_bin, 512);
		argv[argno++] = haproxy_bin;
		for (i = 0; i < main_argc; ++i)
			argv[argno++] = main_argv[i];
		argv[argno++] = "-Ds";
		if (nb_pid > 0) {
			argv[argno++] = "-sf";
			for (i = 0; i < nb_pid; ++i)
				argv[argno++] = pid_strv[i];
			if (stats_socket != NULL) {
				argv[argno++] = "-x";
				argv[argno++] = stats_socket;
			}
		}
		argv[argno] = NULL;

		fprintf(stderr, SD_DEBUG "haproxy-systemd-wrapper: executing ");
		for (i = 0; argv[i]; ++i)
			fprintf(stderr, "%s ", argv[i]);
		fprintf(stderr, "\n");

		execv(argv[0], argv);
		fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: execv(%s) failed, please try again later.\n", argv[0]);
		exit(1);
	}
	else if (pid == -1) {
		fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: failed to fork(), please try again later.\n");
	}

	/* The parent closes the write side and waits for the child to close it
	 * as well. Also deal the case where the fd would unexpectedly be 1 or 2
	 * by silently draining all data.
	 */
	close(pipefd[1]);

	do {
		char c;
		ret = read(pipefd[0], &c, sizeof(c));
	} while ((ret > 0) || (ret == -1 && errno == EINTR));
	/* the child has finished starting up */
	close(pipefd[0]);
}

static int read_pids(char ***pid_strv)
{
	FILE *f = fopen(pid_file, "r");
	int read = 0, allocated = 8;
	char pid_str[10];

	if (!f)
		return 0;

	*pid_strv = malloc(allocated * sizeof(char *));
	while (1 == fscanf(f, "%s\n", pid_str)) {
		if (read == allocated) {
			allocated *= 2;
			*pid_strv = realloc(*pid_strv, allocated * sizeof(char *));
		}
		(*pid_strv)[read++] = strdup(pid_str);
	}

	fclose(f);

	return read;
}

static void signal_handler(int signum)
{
	if (caught_signal != SIGINT && caught_signal != SIGTERM)
		caught_signal = signum;
}

static void setup_signal_handler()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = &signal_handler;
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void pause_signal_handler()
{
	signal(SIGUSR2, SIG_IGN);
	signal(SIGHUP,  SIG_IGN);
	signal(SIGINT,  SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

static void reset_signal_handler()
{
	signal(SIGUSR2, SIG_DFL);
	signal(SIGHUP,  SIG_DFL);
	signal(SIGINT,  SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

/* handles SIGUSR2 and SIGHUP only */
static void do_restart(int sig)
{
	setenv(REEXEC_FLAG, "1", 1);
	fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: re-executing on %s.\n",
	        sig == SIGUSR2 ? "SIGUSR2" : "SIGHUP");

	/* don't let the other process take one of those signals by accident */
	pause_signal_handler();
	execv(wrapper_argv[0], wrapper_argv);
	/* failed, let's reinstall the signal handler and continue */
	setup_signal_handler();
	fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: re-exec(%s) failed.\n", wrapper_argv[0]);
}

/* handles SIGTERM and SIGINT only */
static void do_shutdown(int sig)
{
	int i, pid;
	char **pid_strv = NULL;
	int nb_pid = read_pids(&pid_strv);
	for (i = 0; i < nb_pid; ++i) {
		pid = atoi(pid_strv[i]);
		if (pid > 0) {
			fprintf(stderr, SD_DEBUG "haproxy-systemd-wrapper: %s -> %d.\n",
			        sig == SIGTERM ? "SIGTERM" : "SIGINT", pid);
			kill(pid, sig);
			free(pid_strv[i]);
		}
	}
	free(pid_strv);
}

static void init(int argc, char **argv)
{
	while (argc > 1) {
		if ((*argv)[0] == '-' && (*argv)[1] == 'p') {
			pid_file = *(argv + 1);
		}
		--argc; ++argv;
	}
}

int main(int argc, char **argv)
{
	int status;

	setup_signal_handler();

	wrapper_argc = argc;
	wrapper_argv = argv;

	--argc; ++argv;
	init(argc, argv);

	if (getenv(REEXEC_FLAG) != NULL) {
		/* We are being re-executed: restart HAProxy gracefully */
		int i;
		char **pid_strv = NULL;
		int nb_pid = read_pids(&pid_strv);

		unsetenv(REEXEC_FLAG);
		spawn_haproxy(pid_strv, nb_pid);

		for (i = 0; i < nb_pid; ++i)
			free(pid_strv[i]);
		free(pid_strv);
	}
	else {
		/* Start a fresh copy of HAProxy */
		spawn_haproxy(NULL, 0);
	}

	status = -1;
	while (caught_signal || wait(&status) != -1 || errno == EINTR) {
		int sig = caught_signal;

		if (caught_signal == SIGUSR2 || caught_signal == SIGHUP) {
			caught_signal = 0;
			do_restart(sig);
		}
		else if (caught_signal == SIGINT || caught_signal == SIGTERM) {
			caught_signal = 0;
			do_shutdown(sig);
		}
	}

	/* return either exit code or signal+128 */
	if (WIFEXITED(status))
		status = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		status = 128 + WTERMSIG(status);
	else if (WIFSTOPPED(status))
		status = 128 + WSTOPSIG(status);
	else
		status = 255;

	fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: exit, haproxy RC=%d\n",
			status);
	return status;
}
