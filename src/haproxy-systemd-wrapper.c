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

static void spawn_haproxy(char **pid_strv, int nb_pid)
{
	pid_t pid = fork();
	if (!pid) {
		/* 3 for "haproxy -Ds -sf" */
		char **argv = calloc(4 + main_argc + nb_pid + 1, sizeof(char *));
		int i;
		int argno = 0;
		argv[argno++] = SBINDIR"/haproxy";
		for (i = 0; i < main_argc; ++i)
			argv[argno++] = main_argv[i];
		argv[argno++] = "-Ds";
		if (nb_pid > 0) {
			argv[argno++] = "-sf";
			for (i = 0; i < nb_pid; ++i)
				argv[argno++] = pid_strv[i];
		}
		argv[argno] = NULL;
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

static void signal_handler(int signum __attribute__((unused)))
{
	int i;
	char **pid_strv = NULL;
	int nb_pid = read_pids(&pid_strv);

	spawn_haproxy(pid_strv, nb_pid);

	for (i = 0; i < nb_pid; ++i)
		free(pid_strv[i]);
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
	--argc; ++argv;
        main_argc = argc;
        main_argv = argv;

	init(argc, argv);

	signal(SIGUSR2, &signal_handler);

	spawn_haproxy(NULL, 0);
	while (-1 != wait(NULL) || errno == EINTR);

	return EXIT_SUCCESS;
}
