#define _GNU_SOURCE
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// gcc -fPIC -shared -O2 -o ncpu{.so,.c}
// NCPU=16 LD_PRELOAD=$PWD/ncpu.so command args...

static char prog_full_path[PATH_MAX];

/* return a cpu_set having the first $NCPU set */
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
{
	const char *ncpu;
	int i, n;

	CPU_ZERO_S(cpusetsize, mask);

	ncpu = getenv("NCPU");
	n = ncpu ? atoi(ncpu) : CPU_SETSIZE;
	if (n < 0 || n > CPU_SETSIZE)
		n = CPU_SETSIZE;

	for (i = 0; i < n; i++)
		CPU_SET_S(i, cpusetsize, mask);

	return 0;
}

/* silently ignore the operation */
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)
{
	return 0;
}

void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-n ncpu] [cmd [args...]]\n"
		"       Will install itself in LD_PRELOAD before calling <cmd> with args.\n"
		"       The number of CPUs may also come from variable NCPU or default to %d.\n"
		"\n"
		"",
		argv0, CPU_SETSIZE);
	exit(1);
}

/* Called in wrapper mode, no longer supported on recent glibc */
int main(int argc, char **argv)
{
	const char *argv0 = argv[0];
	char *preload;
	int plen;

	prog_full_path[0] = 0;
	plen = readlink("/proc/self/exe", prog_full_path, sizeof(prog_full_path) - 1);
	if (plen != -1)
		prog_full_path[plen] = 0;
	else
		plen = snprintf(prog_full_path, sizeof(prog_full_path), "%s", argv[0]);

	while (1) {
		argc--;
		argv++;

		if (argc < 1)
			usage(argv0);

		if (strcmp(argv[0], "--") == 0) {
			argc--;
			argv++;
			break;
		}
		else if (strcmp(argv[0], "-n") == 0) {
			if (argc < 2)
				usage(argv0);

			if (setenv("NCPU", argv[1], 1) != 0)
				usage(argv0);
			argc--;
			argv++;
		}
		else {
			/* unknown arg, that's the command */
			break;
		}
	}

	/* here the only args left start with the cmd name */

	/* now we'll concatenate ourselves at the end of the LD_PRELOAD variable */
	preload = getenv("LD_PRELOAD");
	if (preload) {
		int olen = strlen(preload);
		preload = realloc(preload, olen + 1 + plen + 1);
		if (!preload) {
			perror("realloc");
			exit(2);
		}
		preload[olen] = ' ';
		memcpy(preload + olen + 1, prog_full_path, plen);
		preload[olen + 1 + plen] = 0;
	}
	else {
		preload = prog_full_path;
	}

	if (setenv("LD_PRELOAD", preload, 1) < 0) {
		perror("setenv");
		exit(2);
	}

	execvp(*argv, argv);
	perror("execve");
	exit(2);
}
