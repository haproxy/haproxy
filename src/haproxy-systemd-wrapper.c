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

static char *pid_file = "/run/haproxy.pid";
static int main_argc;
static char **main_argv;

static void locate_haproxy(char *buffer, size_t buffer_size)
{
	char* end;
	readlink("/proc/self/exe", buffer, buffer_size);
	end = strrchr(buffer, '/');
	if (end == NULL)
		strncpy(buffer, "/usr/sbin/haproxy", buffer_size);
	end[1] = '\0';
	strncat(buffer, "haproxy", buffer_size);
}

static void spawn_haproxy(char **pid_strv, int nb_pid)
{
	char haproxy_bin[512];
	pid_t pid;

	pid = fork();
	if (!pid) {
		/* 3 for "haproxy -Ds -sf" */
		char **argv = calloc(4 + main_argc + nb_pid + 1, sizeof(char *));
		int i;
		int argno = 0;
		locate_haproxy(haproxy_bin, 512);
		argv[argno++] = haproxy_bin;
		for (i = 0; i < main_argc; ++i)
			argv[argno++] = main_argv[i];
		argv[argno++] = "-Ds";
		if (nb_pid > 0) {
			argv[argno++] = "-sf";
			for (i = 0; i < nb_pid; ++i)
				argv[argno++] = pid_strv[i];
		}
		argv[argno] = NULL;

		printf("%s", "haproxy-systemd-wrapper: executing ");
		for (i = 0; argv[i]; ++i)
			printf("%s ", argv[i]);
		puts("");

		execv(argv[0], argv);
		exit(0);
	}
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

static void sigusr2_handler(int signum __attribute__((unused)))
{
	int i;
	char **pid_strv = NULL;
	int nb_pid = read_pids(&pid_strv);

	spawn_haproxy(pid_strv, nb_pid);

	for (i = 0; i < nb_pid; ++i)
		free(pid_strv[i]);
	free(pid_strv);
}

static void sigint_handler(int signum __attribute__((unused)))
{
	int i, pid;
	char **pid_strv = NULL;
	int nb_pid = read_pids(&pid_strv);
	for (i = 0; i < nb_pid; ++i) {
		pid = atoi(pid_strv[i]);
		if (pid > 0) {
			printf("haproxy-systemd-wrapper: SIGINT -> %d\n", pid);
			kill(pid, SIGINT);
			free(pid_strv[i]);
		}
	}
	free(pid_strv);
}

static void init(int argc, char **argv)
{
	while (argc > 1) {
		if (**argv == '-') {
			char *flag = *argv + 1;
			--argc; ++argv;
			if (*flag == 'p')
				pid_file = *argv;
		}
		--argc; ++argv;
	}
}

int main(int argc, char **argv)
{
	int status;

	--argc; ++argv;
	main_argc = argc;
	main_argv = argv;

	init(argc, argv);

	signal(SIGINT, &sigint_handler);
	signal(SIGUSR2, &sigusr2_handler);

	spawn_haproxy(NULL, 0);
	status = -1;
	while (-1 != wait(&status) || errno == EINTR)
		;

	printf("haproxy-systemd-wrapper: exit, haproxy RC=%d\n", status);
	return EXIT_SUCCESS;
}
