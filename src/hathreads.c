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
#include <fcntl.h>

#include <common/cfgparse.h>
#include <common/hathreads.h>
#include <common/standard.h>
#include <proto/fd.h>

THREAD_LOCAL unsigned int tid      = 0;
THREAD_LOCAL unsigned long tid_bit = (1UL << 0);

#ifdef USE_THREAD

static HA_SPINLOCK_T sync_lock;
static int           threads_sync_pipe[2];
static unsigned long threads_want_sync = 0;
static unsigned long all_threads_mask  = 0;

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
struct lock_stat lock_stats[LOCK_LABELS];
#endif

/* Dummy I/O handler used by the sync pipe.*/
static void thread_sync_io_handler(int fd) { }

/* Initializes the sync point. It creates a pipe used by threads to wakup all
 * others when a sync is requested. It also initialize the mask of all create
 * threads. It returns 0 on success and -1 if an error occurred.
 */
int thread_sync_init(unsigned long mask)
{
	int rfd;

	if (pipe(threads_sync_pipe) < 0)
		return -1;

	rfd = threads_sync_pipe[0];
	fcntl(rfd, F_SETFL, O_NONBLOCK);

	fdtab[rfd].owner = NULL;
	fdtab[rfd].iocb = thread_sync_io_handler;
	fd_insert(rfd, MAX_THREADS_MASK);

	all_threads_mask = mask;
	return 0;
}

/* Enables the sync point. */
void thread_sync_enable(void)
{
	fd_want_recv(threads_sync_pipe[0]);
}

/* Called when a thread want to pass into the sync point. It subscribes the
 * current thread in threads waiting for sync by update a bit-field. It this is
 * the first one, it wakeup all other threads by writing on the sync pipe.
 */
void thread_want_sync()
{
	if (all_threads_mask) {
		if (threads_want_sync & tid_bit)
			return;
		if (HA_ATOMIC_OR(&threads_want_sync, tid_bit) == tid_bit)
			shut_your_big_mouth_gcc(write(threads_sync_pipe[1], "S", 1));
	}
	else {
		threads_want_sync = 1;
	}
}

/* Returns 1 if no thread has requested a sync. Otherwise, it returns 0. */
int thread_no_sync()
{
	return (threads_want_sync == 0);
}

/* Returns 1 if the current thread has requested a sync. Otherwise, it returns
 * 0.
 */
int thread_need_sync()
{
	return (threads_want_sync & tid_bit);
}

/* Thread barrier. Synchronizes all threads at the barrier referenced by
 * <barrier>. The calling thread shall block until all other threads have called
 * thread_sync_barrier specifying the same barrier.
 *
 * If you need to use several barriers at differnt points, you need to use a
 * different <barrier> for each point.
 */
static inline void thread_sync_barrier(volatile unsigned long *barrier)
{
	unsigned long old = all_threads_mask;

	HA_ATOMIC_CAS(barrier, &old, 0);
	HA_ATOMIC_OR(barrier, tid_bit);
	while (*barrier != all_threads_mask)
		pl_cpu_relax();
}

/* Enter into the sync point and lock it if the current thread has requested a
 * sync. */
void thread_enter_sync()
{
	static volatile unsigned long barrier = 0;

	if (!all_threads_mask)
		return;

	thread_sync_barrier(&barrier);
	if (threads_want_sync & tid_bit)
		HA_SPIN_LOCK(THREAD_SYNC_LOCK, &sync_lock);
}

/* Exit from the sync point and unlock it if it was previously locked. If the
 * current thread is the last one to have requested a sync, the sync pipe is
 * flushed.
 */
void thread_exit_sync()
{
	static volatile unsigned long barrier = 0;

	if (!all_threads_mask)
		return;

	if (threads_want_sync & tid_bit)
		HA_SPIN_UNLOCK(THREAD_SYNC_LOCK, &sync_lock);

	if (HA_ATOMIC_AND(&threads_want_sync, ~tid_bit) == 0) {
		char c;

		shut_your_big_mouth_gcc(read(threads_sync_pipe[0], &c, 1));
		fd_done_recv(threads_sync_pipe[0]);
	}

	thread_sync_barrier(&barrier);
}


__attribute__((constructor))
static void __hathreads_init(void)
{
	HA_SPIN_INIT(&sync_lock);
#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
	memset(lock_stats, 0, sizeof(lock_stats));
#endif
	hap_register_build_opts("Built with multi-threading support.", 0);
}

#endif
