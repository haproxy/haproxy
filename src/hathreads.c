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

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include <common/cfgparse.h>
#include <common/hathreads.h>
#include <common/standard.h>
#include <types/global.h>
#include <proto/fd.h>


#ifdef USE_THREAD

volatile unsigned long threads_want_rdv_mask = 0;
volatile unsigned long threads_harmless_mask = 0;
volatile unsigned long all_threads_mask  = 1; // nbthread 1 assumed by default
THREAD_LOCAL unsigned int  tid           = 0;
THREAD_LOCAL unsigned long tid_bit       = (1UL << 0);


#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
struct lock_stat lock_stats[LOCK_LABELS];
#endif

/* Marks the thread as harmless until the last thread using the rendez-vous
 * point quits. Given that we can wait for a long time, sched_yield() is used
 * when available to offer the CPU resources to competing threads if needed.
 */
void thread_harmless_till_end()
{
		HA_ATOMIC_OR(&threads_harmless_mask, tid_bit);
		while (threads_want_rdv_mask & all_threads_mask) {
#if _POSIX_PRIORITY_SCHEDULING
			sched_yield();
#else
			pl_cpu_relax();
#endif
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

	HA_ATOMIC_OR(&threads_harmless_mask, tid_bit);
	__ha_barrier_store();
	HA_ATOMIC_OR(&threads_want_rdv_mask, tid_bit);

	/* wait for all threads to become harmless */
	old = threads_harmless_mask;
	while (1) {
		if (unlikely((old & all_threads_mask) != all_threads_mask))
			old = threads_harmless_mask;
		else if (HA_ATOMIC_CAS(&threads_harmless_mask, &old, old & ~tid_bit))
			break;

#if _POSIX_PRIORITY_SCHEDULING
		sched_yield();
#else
		pl_cpu_relax();
#endif
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
	HA_ATOMIC_AND(&threads_want_rdv_mask, ~tid_bit);
	thread_harmless_end();
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

__attribute__((constructor))
static void __hathreads_init(void)
{
#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
	memset(lock_stats, 0, sizeof(lock_stats));
#endif
}

REGISTER_BUILD_OPTS("Built with multi-threading support.");

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

	/* we proceed like this to be sure never to overflow the left shift */
	all_threads_mask = 1UL << (nbthread - 1);
	all_threads_mask |= all_threads_mask - 1;
#endif
	return nbthread;
}
