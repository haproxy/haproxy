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

#include <haproxy/defaults.h>

/* Note: this file mainly contains 3 sections:
 *   - one used solely when USE_THREAD is *not* set
 *   - one used solely when USE_THREAD is set
 *   - a common one.
 */

#ifndef USE_THREAD

/********************** THREADS DISABLED ************************/

/* These macros allow to make some struct fields or local variables optional */
#define __decl_spinlock(lock)
#define __decl_aligned_spinlock(lock)
#define __decl_rwlock(lock)
#define __decl_aligned_rwlock(lock)

#elif !defined(DEBUG_THREAD) && !defined(DEBUG_FULL)

/************** THREADS ENABLED WITHOUT DEBUGGING **************/

/* declare a self-initializing spinlock */
#define __decl_spinlock(lock)                                  \
	HA_SPINLOCK_T (lock) = 0;

/* declare a self-initializing spinlock, aligned on a cache line */
#define __decl_aligned_spinlock(lock)                          \
	HA_SPINLOCK_T (lock) __attribute__((aligned(64))) = 0;

/* declare a self-initializing rwlock */
#define __decl_rwlock(lock)                                    \
	HA_RWLOCK_T   (lock) = 0;

/* declare a self-initializing rwlock, aligned on a cache line */
#define __decl_aligned_rwlock(lock)                            \
	HA_RWLOCK_T   (lock) __attribute__((aligned(64))) = 0;

#else /* !USE_THREAD */

/**************** THREADS ENABLED WITH DEBUGGING ***************/

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
	uint64_t nsec_wait_for_seek;
	uint64_t num_write_locked;
	uint64_t num_write_unlocked;
	uint64_t num_read_locked;
	uint64_t num_read_unlocked;
	uint64_t num_seek_locked;
	uint64_t num_seek_unlocked;
};

struct ha_spinlock_state {
	unsigned long owner; /* a bit is set to 1 << tid for the lock owner */
	unsigned long waiters; /* a bit is set to 1 << tid for waiting threads  */
};

struct ha_rwlock_state {
	unsigned long cur_writer;   /* a bit is set to 1 << tid for the lock owner */
	unsigned long wait_writers; /* a bit is set to 1 << tid for waiting writers */
	unsigned long cur_readers;  /* a bit is set to 1 << tid for current readers */
	unsigned long wait_readers; /* a bit is set to 1 << tid for waiting waiters */
	unsigned long cur_seeker;   /* a bit is set to 1 << tid for the lock seekers */
	unsigned long wait_seekers; /* a bit is set to 1 << tid for waiting seekers */
};

struct ha_spinlock {
	__HA_SPINLOCK_T lock;
	struct {
		struct ha_spinlock_state st[MAX_TGROUPS];
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
		struct ha_rwlock_state st[MAX_TGROUPS];
		struct {
			const char *function;
			const char *file;
			int line;
		} last_location; /* location of the last write owner */
	} info;
};

#endif  /* DEBUG_THREAD */

/* WARNING!!! if you update this enum, please also keep lock_label() up to date
 * below.
 */
enum lock_label {
	TASK_RQ_LOCK,
	TASK_WQ_LOCK,
	LISTENER_LOCK,
	PROXY_LOCK,
	SERVER_LOCK,
	LBPRM_LOCK,
	SIGNALS_LOCK,
	STK_TABLE_LOCK,
	STK_SESS_LOCK,
	APPLETS_LOCK,
	PEER_LOCK,
	SHCTX_LOCK,
	SSL_LOCK,
	SSL_GEN_CERTS_LOCK,
	PATREF_LOCK,
	PATEXP_LOCK,
	VARS_LOCK,
	COMP_POOL_LOCK,
	LUA_LOCK,
	NOTIF_LOCK,
	SPOE_APPLET_LOCK,
	DNS_LOCK,
	PID_LIST_LOCK,
	EMAIL_ALERTS_LOCK,
	PIPES_LOCK,
	TLSKEYS_REF_LOCK,
	AUTH_LOCK,
	RING_LOCK,
	DICT_LOCK,
	PROTO_LOCK,
	QUEUE_LOCK,
	CKCH_LOCK,
	SNI_LOCK,
	SSL_SERVER_LOCK,
	SFT_LOCK, /* sink forward target */
	IDLE_CONNS_LOCK,
	OCSP_LOCK,
	QC_CID_LOCK,
	CACHE_LOCK,
	GUID_LOCK,
	OTHER_LOCK,
	/* WT: make sure never to use these ones outside of development,
	 * we need them for lock profiling!
	 */
	DEBUG1_LOCK,
	DEBUG2_LOCK,
	DEBUG3_LOCK,
	DEBUG4_LOCK,
	DEBUG5_LOCK,
	LOCK_LABELS
};

#endif /* _HAPROXY_THREAD_T_H */
