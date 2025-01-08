#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <string.h>

// gcc -fPIC -shared -O2 -o ncpu{.so,.c}
// NCPU=16 LD_PRELOAD=$PWD/ncpu.so command args...

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
