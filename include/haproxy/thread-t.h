/*
 * include/haproxy/thread-t.h
 * Definitions and types for thread support.
 *
 * Copyright (C) 2017 Christopher Faulet - cfaulet@haproxy.com
 * Copyright (C) 2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_THREAD_T_H
#define _HAPROXY_THREAD_T_H

#ifdef USE_THREAD
#include <pthread.h>
#endif
#include <time.h>


/* Note: this file mainly contains 3 sections:
 *   - one used solely when USE_THREAD is *not* set
 *   - one used solely when USE_THREAD is set
 *   - a common one.
 */

#ifndef USE_THREAD

/********************** THREADS DISABLED ************************/

#define THREAD_LOCAL  /* empty */
#define MAX_THREADS 1
#define MAX_THREADS_MASK 1

/* These macros allow to make some struct fields or local variables optional */
#define __decl_hathreads(decl)
#define __decl_spinlock(lock)
#define __decl_aligned_spinlock(lock)
#define __decl_rwlock(lock)
#define __decl_aligned_rwlock(lock)

#else /* !USE_THREAD */

/********************** THREADS ENABLED ************************/

#define THREAD_LOCAL __thread

#ifndef MAX_THREADS
#define MAX_THREADS LONGBITS
#endif

#define MAX_THREADS_MASK (~0UL >> (LONGBITS - MAX_THREADS))

#define __decl_hathreads(decl) decl

/* declare a self-initializing spinlock */
#define __decl_spinlock(lock)                               \
	HA_SPINLOCK_T (lock);                               \
	INITCALL1(STG_LOCK, ha_spin_init, &(lock))

/* declare a self-initializing spinlock, aligned on a cache line */
#define __decl_aligned_spinlock(lock)                       \
	HA_SPINLOCK_T (lock) __attribute__((aligned(64)));  \
	INITCALL1(STG_LOCK, ha_spin_init, &(lock))

/* declare a self-initializing rwlock */
#define __decl_rwlock(lock)                                 \
	HA_RWLOCK_T   (lock);                               \
	INITCALL1(STG_LOCK, ha_rwlock_init, &(lock))

/* declare a self-initializing rwlock, aligned on a cache line */
#define __decl_aligned_rwlock(lock)                         \
	HA_RWLOCK_T   (lock) __attribute__((aligned(64)));  \
	INITCALL1(STG_LOCK, ha_rwlock_init, &(lock))

#endif /* USE_THREAD */


/*** Common parts below ***/

/* thread info flags, for ha_thread_info[].flags */
#define TI_FL_STUCK             0x00000001

/* This structure describes all the per-thread info we need. When threads are
 * disabled, it contains the same info for the single running thread (except
 * the pthread identifier which does not exist).
 */
struct thread_info {
	__decl_hathreads(pthread_t pthread);
	clockid_t clock_id;
	timer_t wd_timer;          /* valid timer or TIMER_INVALID if not set */
	uint64_t prev_cpu_time;    /* previous per thread CPU time */
	uint64_t prev_mono_time;   /* previous system wide monotonic time  */
	unsigned int idle_pct;     /* idle to total ratio over last sample (percent) */
	unsigned int flags;        /* thread info flags, TI_FL_* */
	/* pad to cache line (64B) */
	char __pad[0];            /* unused except to check remaining room */
	char __end[0] __attribute__((aligned(64)));
};

/* storage types used by spinlocks and RW locks */
#define __HA_SPINLOCK_T     unsigned long
#define __HA_RWLOCK_T       unsigned long


/* When thread debugging is enabled, we remap HA_SPINLOCK_T and HA_RWLOCK_T to
 * complex structures which embed debugging info.
 */
#if !defined(DEBUG_THREAD) && !defined(DEBUG_FULL)

#define HA_SPINLOCK_T        __HA_SPINLOCK_T
#define HA_RWLOCK_T          __HA_RWLOCK_T

#else /* !DEBUG_THREAD */

#define HA_SPINLOCK_T       struct ha_spinlock
#define HA_RWLOCK_T         struct ha_rwlock

/* Debugging information that is only used when thread debugging is enabled */

struct lock_stat {
	uint64_t nsec_wait_for_write;
	uint64_t nsec_wait_for_read;
	uint64_t num_write_locked;
	uint64_t num_write_unlocked;
	uint64_t num_read_locked;
	uint64_t num_read_unlocked;
};

struct ha_spinlock {
	__HA_SPINLOCK_T lock;
	struct {
		unsigned long owner; /* a bit is set to 1 << tid for the lock owner */
		unsigned long waiters; /* a bit is set to 1 << tid for waiting threads  */
		struct {
			const char *function;
			const char *file;
			int line;
		} last_location; /* location of the last owner */
	} info;
};

struct ha_rwlock {
	__HA_RWLOCK_T lock;
	struct {
		unsigned long cur_writer; /* a bit is set to 1 << tid for the lock owner */
		unsigned long wait_writers; /* a bit is set to 1 << tid for waiting writers */
		unsigned long cur_readers; /* a bit is set to 1 << tid for current readers */
		unsigned long wait_readers; /* a bit is set to 1 << tid for waiting waiters */
		struct {
			const char *function;
			const char *file;
			int line;
		} last_location; /* location of the last write owner */
	} info;
};

#endif  /* DEBUG_THREAD */

#endif /* _HAPROXY_THREAD_T_H */
