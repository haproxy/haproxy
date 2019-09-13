/*
 * functions about threads.
 *
 * Copyright (C) 2017 Christopher Fauet - cfaulet@haproxy.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#ifdef USE_CPU_AFFINITY
#include <sched.h>
#endif

#ifdef __FreeBSD__
#include <sys/cpuset.h>
#endif

#include <common/cfgparse.h>
#include <common/hathreads.h>
#include <common/standard.h>
#include <types/global.h>
#include <proto/fd.h>

struct thread_info ha_thread_info[MAX_THREADS] = { };
THREAD_LOCAL struct thread_info *ti = &ha_thread_info[0];

#ifdef USE_THREAD

volatile unsigned long threads_want_rdv_mask = 0;
volatile unsigned long threads_harmless_mask = 0;
volatile unsigned long threads_sync_mask = 0;
volatile unsigned long all_threads_mask  = 1; // nbthread 1 assumed by default
THREAD_LOCAL unsigned int  tid           = 0;
THREAD_LOCAL unsigned long tid_bit       = (1UL << 0);
int thread_cpus_enabled_at_boot          = 1;


#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
struct lock_stat lock_stats[LOCK_LABELS];
#endif

/* Marks the thread as harmless until the last thread using the rendez-vous
 * point quits. Given that we can wait for a long time, sched_yield() is used
 * when available to offer the CPU resources to competing threads if needed.
 */
void thread_harmless_till_end()
{
		_HA_ATOMIC_OR(&threads_harmless_mask, tid_bit);
		while (threads_want_rdv_mask & all_threads_mask) {
			ha_thread_relax();
		}
}

/* Isolates the current thread : request the ability to work while all other
 * threads are harmless. Only returns once all of them are harmless, with the
 * current thread's bit in threads_harmless_mask cleared. Needs to be completed
 * using thread_release().
 */
void thread_isolate()
{
	unsigned long old;

	_HA_ATOMIC_OR(&threads_harmless_mask, tid_bit);
	__ha_barrier_atomic_store();
	_HA_ATOMIC_OR(&threads_want_rdv_mask, tid_bit);

	/* wait for all threads to become harmless */
	old = threads_harmless_mask;
	while (1) {
		if (unlikely((old & all_threads_mask) != all_threads_mask))
			old = threads_harmless_mask;
		else if (_HA_ATOMIC_CAS(&threads_harmless_mask, &old, old & ~tid_bit))
			break;

		ha_thread_relax();
	}
	/* one thread gets released at a time here, with its harmess bit off.
	 * The loss of this bit makes the other one continue to spin while the
	 * thread is working alone.
	 */
}

/* Cancels the effect of thread_isolate() by releasing the current thread's bit
 * in threads_want_rdv_mask and by marking this thread as harmless until the
 * last worker finishes.
 */
void thread_release()
{
	_HA_ATOMIC_AND(&threads_want_rdv_mask, ~tid_bit);
	while (threads_want_rdv_mask & all_threads_mask) {
		_HA_ATOMIC_OR(&threads_harmless_mask, tid_bit);
		while (threads_want_rdv_mask & all_threads_mask)
			ha_thread_relax();
		HA_ATOMIC_AND(&threads_harmless_mask, ~tid_bit);
	}
}

/* Cancels the effect of thread_isolate() by releasing the current thread's bit
 * in threads_want_rdv_mask and by marking this thread as harmless until the
 * last worker finishes. The difference with thread_release() is that this one
 * will not leave the function before others are notified to do the same, so it
 * guarantees that the current thread will not pass through a subsequent call
 * to thread_isolate() before others finish.
 */
void thread_sync_release()
{
	_HA_ATOMIC_OR(&threads_sync_mask, tid_bit);
	__ha_barrier_atomic_store();
	_HA_ATOMIC_AND(&threads_want_rdv_mask, ~tid_bit);

	while (threads_want_rdv_mask & all_threads_mask) {
		_HA_ATOMIC_OR(&threads_harmless_mask, tid_bit);
		while (threads_want_rdv_mask & all_threads_mask)
			ha_thread_relax();
		HA_ATOMIC_AND(&threads_harmless_mask, ~tid_bit);
	}

	/* the current thread is not harmless anymore, thread_isolate()
	 * is forced to wait till all waiters finish.
	 */
	_HA_ATOMIC_AND(&threads_sync_mask, ~tid_bit);
	while (threads_sync_mask & all_threads_mask)
		ha_thread_relax();
}

/* send signal <sig> to thread <thr> */
void ha_tkill(unsigned int thr, int sig)
{
	pthread_kill(ha_thread_info[thr].pthread, sig);
}

/* send signal <sig> to all threads. The calling thread is signaled last in
 * order to allow all threads to synchronize in the handler.
 */
void ha_tkillall(int sig)
{
	unsigned int thr;

	for (thr = 0; thr < global.nbthread; thr++) {
		if (!(all_threads_mask & (1UL << thr)))
			continue;
		if (thr == tid)
			continue;
		pthread_kill(ha_thread_info[thr].pthread, sig);
	}
	raise(sig);
}

/* these calls are used as callbacks at init time */
void ha_spin_init(HA_SPINLOCK_T *l)
{
	HA_SPIN_INIT(l);
}

/* these calls are used as callbacks at init time */
void ha_rwlock_init(HA_RWLOCK_T *l)
{
	HA_RWLOCK_INIT(l);
}

/* returns the number of CPUs the current process is enabled to run on */
static int thread_cpus_enabled()
{
	int ret = 1;

#ifdef USE_CPU_AFFINITY
#if defined(__linux__) && defined(CPU_COUNT)
	cpu_set_t mask;

	if (sched_getaffinity(0, sizeof(mask), &mask) == 0)
		ret = CPU_COUNT(&mask);
#elif defined(__FreeBSD__) && defined(USE_CPU_AFFINITY)
	cpuset_t cpuset;
	if (cpuset_getaffinity(CPU_LEVEL_CPUSET, CPU_WHICH_PID, -1,
	    sizeof(cpuset), &cpuset) == 0)
		ret = CPU_COUNT(&cpuset);
#endif
#endif
	ret = MAX(ret, 1);
	ret = MIN(ret, MAX_THREADS);
	return ret;
}

__attribute__((constructor))
static void __hathreads_init(void)
{
	char *ptr = NULL;

	if (MAX_THREADS < 1 || MAX_THREADS > LONGBITS) {
		ha_alert("MAX_THREADS value must be between 1 and %d inclusive; "
		         "HAProxy was built with value %d, please fix it and rebuild.\n",
			 LONGBITS, MAX_THREADS);
		exit(1);
	}

	thread_cpus_enabled_at_boot = thread_cpus_enabled();

	memprintf(&ptr, "Built with multi-threading support (MAX_THREADS=%d, default=%d).",
		  MAX_THREADS, thread_cpus_enabled_at_boot);
	hap_register_build_opts(ptr, 1);

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
	memset(lock_stats, 0, sizeof(lock_stats));
#endif
}

#else

REGISTER_BUILD_OPTS("Built without multi-threading support (USE_THREAD not set).");

#endif // USE_THREAD


/* Parse the number of threads in argument <arg>, returns it and adjusts a few
 * internal variables accordingly, or fails and returns zero with an error
 * reason in <errmsg>. May be called multiple times while parsing.
 */
int parse_nbthread(const char *arg, char **err)
{
	long nbthread;
	char *errptr;

	nbthread = strtol(arg, &errptr, 10);
	if (!*arg || *errptr) {
		memprintf(err, "passed a missing or unparsable integer value in '%s'", arg);
		return 0;
	}

#ifndef USE_THREAD
	if (nbthread != 1) {
		memprintf(err, "specified with a value other than 1 while HAProxy is not compiled with threads support. Please check build options for USE_THREAD");
		return 0;
	}
#else
	if (nbthread < 1 || nbthread > MAX_THREADS) {
		memprintf(err, "value must be between 1 and %d (was %ld)", MAX_THREADS, nbthread);
		return 0;
	}

	all_threads_mask = nbits(nbthread);
#endif
	return nbthread;
}
