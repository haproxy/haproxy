/*
 * include/common/hathreads.h
 * definitions, macros and inline functions about threads.
 *
 * Copyright (C) 2017 Christopher Fauet - cfaulet@haproxy.com
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

#ifndef _COMMON_HATHREADS_H
#define _COMMON_HATHREADS_H

#include <signal.h>
#include <unistd.h>
#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif

#include <common/config.h>
#include <common/initcall.h>

/* Note about all_threads_mask :
 *    - this variable is comprised between 1 and LONGBITS.
 *    - with threads support disabled, this symbol is defined as constant 1UL.
 *    - with threads enabled, it contains the mask of enabled threads. Thus if
 *      only one thread is enabled, it equals 1.
 */

/* thread info flags, for ha_thread_info[].flags */
#define TI_FL_STUCK             0x00000001


#ifndef USE_THREAD

#define MAX_THREADS 1
#define MAX_THREADS_MASK 1

/* Only way found to replace variables with constants that are optimized away
 * at build time.
 */
enum { all_threads_mask = 1UL };
enum { threads_harmless_mask = 0 };
enum { threads_want_rdv_mask = 0 };
enum { threads_sync_mask = 0 };
enum { tid_bit = 1UL };
enum { tid = 0 };

extern struct thread_info {
	clockid_t clock_id;
	timer_t wd_timer;          /* valid timer or TIMER_INVALID if not set */
	uint64_t prev_cpu_time;    /* previous per thread CPU time */
	uint64_t prev_mono_time;   /* previous system wide monotonic time  */
	unsigned int idle_pct;     /* idle to total ratio over last sample (percent) */
	unsigned int flags;        /* thread info flags, TI_FL_* */
	/* pad to cache line (64B) */
	char __pad[0];            /* unused except to check remaining room */
	char __end[0] __attribute__((aligned(64)));
} ha_thread_info[MAX_THREADS];

extern THREAD_LOCAL struct thread_info *ti; /* thread_info for the current thread */

#define __decl_hathreads(decl)
#define __decl_spinlock(lock)
#define __decl_aligned_spinlock(lock)
#define __decl_rwlock(lock)
#define __decl_aligned_rwlock(lock)

#define HA_ATOMIC_CAS(val, old, new) ({((*val) == (*old)) ? (*(val) = (new) , 1) : (*(old) = *(val), 0);})

/* warning, n is a pointer to the double value for dwcas */
#define HA_ATOMIC_DWCAS(val, o, n)				       \
	({                                                             \
		long *_v = (long*)(val);                               \
		long *_o = (long*)(o);				       \
		long *_n = (long*)(n);				       \
		long _v0 = _v[0], _v1 = _v[1];			       \
		(_v0 == _o[0] && _v1 == _o[1]) ?                       \
			(_v[0] = _n[0], _v[1] = _n[1], 1) :	       \
			(_o[0] = _v0,   _o[1] = _v1,   0);	       \
	})

#define HA_ATOMIC_ADD(val, i)        ({*(val) += (i);})
#define HA_ATOMIC_SUB(val, i)        ({*(val) -= (i);})
#define HA_ATOMIC_XADD(val, i)						\
	({								\
		typeof((val)) __p_xadd = (val);				\
		typeof(*(val)) __old_xadd = *__p_xadd;			\
		*__p_xadd += i;						\
		__old_xadd;						\
	})
#define HA_ATOMIC_AND(val, flags)    ({*(val) &= (flags);})
#define HA_ATOMIC_OR(val, flags)     ({*(val) |= (flags);})
#define HA_ATOMIC_XCHG(val, new)					\
	({								\
		typeof(*(val)) __old_xchg = *(val);			\
		*(val) = new;						\
		__old_xchg;						\
	})
#define HA_ATOMIC_BTS(val, bit)						\
	({								\
		typeof((val)) __p_bts = (val);				\
		typeof(*__p_bts)  __b_bts = (1UL << (bit));		\
		typeof(*__p_bts)  __t_bts = *__p_bts & __b_bts;		\
		if (!__t_bts)						\
			*__p_bts |= __b_bts;				\
		__t_bts;						\
	})
#define HA_ATOMIC_BTR(val, bit)						\
	({								\
		typeof((val)) __p_btr = (val);				\
		typeof(*__p_btr)  __b_btr = (1UL << (bit));		\
		typeof(*__p_btr)  __t_btr = *__p_btr & __b_btr;		\
		if (__t_btr)						\
			*__p_btr &= ~__b_btr;				\
		__t_btr;						\
	})
#define HA_ATOMIC_LOAD(val)          *(val)
#define HA_ATOMIC_STORE(val, new)    ({*(val) = new;})
#define HA_ATOMIC_UPDATE_MAX(val, new)					\
	({								\
		typeof(*(val)) __new_max = (new);			\
									\
		if (*(val) < __new_max)					\
			*(val) = __new_max;				\
		*(val);							\
	})

#define HA_ATOMIC_UPDATE_MIN(val, new)					\
	({								\
		typeof(*(val)) __new_min = (new);			\
									\
		if (*(val) > __new_min)					\
			*(val) = __new_min;				\
		*(val);							\
	})

#define HA_BARRIER() do { } while (0)

#define HA_SPIN_INIT(l)         do { /* do nothing */ } while(0)
#define HA_SPIN_DESTROY(l)      do { /* do nothing */ } while(0)
#define HA_SPIN_LOCK(lbl, l)    do { /* do nothing */ } while(0)
#define HA_SPIN_TRYLOCK(lbl, l) ({ 0; })
#define HA_SPIN_UNLOCK(lbl, l)  do { /* do nothing */ } while(0)

#define HA_RWLOCK_INIT(l)          do { /* do nothing */ } while(0)
#define HA_RWLOCK_DESTROY(l)       do { /* do nothing */ } while(0)
#define HA_RWLOCK_WRLOCK(lbl, l)   do { /* do nothing */ } while(0)
#define HA_RWLOCK_TRYWRLOCK(lbl, l)   ({ 0; })
#define HA_RWLOCK_WRUNLOCK(lbl, l) do { /* do nothing */ } while(0)
#define HA_RWLOCK_RDLOCK(lbl, l)   do { /* do nothing */ } while(0)
#define HA_RWLOCK_TRYRDLOCK(lbl, l)   ({ 0; })
#define HA_RWLOCK_RDUNLOCK(lbl, l) do { /* do nothing */ } while(0)

#define ha_sigmask(how, set, oldset)  sigprocmask(how, set, oldset)

static inline void ha_set_tid(unsigned int tid)
{
	ti = &ha_thread_info[tid];
}

static inline void ha_thread_relax(void)
{
#if _POSIX_PRIORITY_SCHEDULING
	sched_yield();
#endif
}

/* send signal <sig> to thread <thr> */
static inline void ha_tkill(unsigned int thr, int sig)
{
	raise(sig);
}

/* send signal <sig> to all threads */
static inline void ha_tkillall(int sig)
{
	raise(sig);
}

static inline void __ha_barrier_atomic_load(void)
{
}

static inline void __ha_barrier_atomic_store(void)
{
}

static inline void __ha_barrier_atomic_full(void)
{
}

static inline void __ha_barrier_load(void)
{
}

static inline void __ha_barrier_store(void)
{
}

static inline void __ha_barrier_full(void)
{
}

static inline void thread_harmless_now()
{
}

static inline void thread_harmless_end()
{
}

static inline void thread_isolate()
{
}

static inline void thread_release()
{
}

static inline void thread_sync_release()
{
}

static inline unsigned long thread_isolated()
{
	return 1;
}

#else /* USE_THREAD */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <import/plock.h>

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

/* TODO: thread: For now, we rely on GCC builtins but it could be a good idea to
 * have a header file regrouping all functions dealing with threads. */

#if defined(__GNUC__) && (__GNUC__ < 4 || __GNUC__ == 4 && __GNUC_MINOR__ < 7) && !defined(__clang__)
/* gcc < 4.7 */

#define HA_ATOMIC_ADD(val, i)        __sync_add_and_fetch(val, i)
#define HA_ATOMIC_SUB(val, i)        __sync_sub_and_fetch(val, i)
#define HA_ATOMIC_XADD(val, i)       __sync_fetch_and_add(val, i)
#define HA_ATOMIC_AND(val, flags)    __sync_and_and_fetch(val, flags)
#define HA_ATOMIC_OR(val, flags)     __sync_or_and_fetch(val,  flags)

/* the CAS is a bit complicated. The older API doesn't support returning the
 * value and the swap's result at the same time. So here we take what looks
 * like the safest route, consisting in using the boolean version guaranteeing
 * that the operation was performed or not, and we snoop a previous value. If
 * the compare succeeds, we return. If it fails, we return the previous value,
 * but only if it differs from the expected one. If it's the same it's a race
 * thus we try again to avoid confusing a possibly sensitive caller.
 */
#define HA_ATOMIC_CAS(val, old, new)					\
	({								\
		typeof((val)) __val_cas = (val);			\
		typeof((old)) __oldp_cas = (old);			\
		typeof(*(old)) __oldv_cas;				\
		typeof((new)) __new_cas = (new);			\
		int __ret_cas;						\
		do {							\
			__oldv_cas = *__val_cas;			\
			__ret_cas = __sync_bool_compare_and_swap(__val_cas, *__oldp_cas, __new_cas); \
		} while (!__ret_cas && *__oldp_cas == __oldv_cas);	\
		if (!__ret_cas)						\
			*__oldp_cas = __oldv_cas;			\
		__ret_cas;						\
	})

/* warning, n is a pointer to the double value for dwcas */
#define HA_ATOMIC_DWCAS(val, o, n) __ha_cas_dw(val, o, n)

#define HA_ATOMIC_XCHG(val, new)					\
	({								\
		typeof((val)) __val_xchg = (val);			\
		typeof(*(val)) __old_xchg;				\
		typeof((new)) __new_xchg = (new);			\
		do { __old_xchg = *__val_xchg;				\
		} while (!__sync_bool_compare_and_swap(__val_xchg, __old_xchg, __new_xchg)); \
		__old_xchg;						\
	})

#define HA_ATOMIC_BTS(val, bit)						\
	({								\
		typeof(*(val)) __b_bts = (1UL << (bit));		\
		__sync_fetch_and_or((val), __b_bts) & __b_bts;		\
	})

#define HA_ATOMIC_BTR(val, bit)						\
	({								\
		typeof(*(val)) __b_btr = (1UL << (bit));		\
		__sync_fetch_and_and((val), ~__b_btr) & __b_btr;	\
	})

#define HA_ATOMIC_LOAD(val)                                             \
        ({                                                              \
	        typeof(*(val)) ret;                                     \
		__sync_synchronize();                                   \
		ret = *(volatile typeof(val))val;                       \
		__sync_synchronize();                                   \
		ret;                                                    \
	})

#define HA_ATOMIC_STORE(val, new)					\
	({								\
		typeof((val)) __val_store = (val);			\
		typeof(*(val)) __old_store;				\
		typeof((new)) __new_store = (new);			\
		do { __old_store = *__val_store;			\
		} while (!__sync_bool_compare_and_swap(__val_store, __old_store, __new_store));	\
	})
#else
/* gcc >= 4.7 */
#define HA_ATOMIC_CAS(val, old, new) __atomic_compare_exchange_n(val, old, new, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
/* warning, n is a pointer to the double value for dwcas */
#define HA_ATOMIC_DWCAS(val, o, n)   __ha_cas_dw(val, o, n)
#define HA_ATOMIC_ADD(val, i)        __atomic_add_fetch(val, i, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_XADD(val, i)       __atomic_fetch_add(val, i, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_SUB(val, i)        __atomic_sub_fetch(val, i, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_AND(val, flags)    __atomic_and_fetch(val, flags, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_OR(val, flags)     __atomic_or_fetch(val,  flags, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_BTS(val, bit)						\
	({								\
		typeof(*(val)) __b_bts = (1UL << (bit));		\
		__sync_fetch_and_or((val), __b_bts) & __b_bts;		\
	})

#define HA_ATOMIC_BTR(val, bit)						\
	({								\
		typeof(*(val)) __b_btr = (1UL << (bit));		\
		__sync_fetch_and_and((val), ~__b_btr) & __b_btr;	\
	})

#define HA_ATOMIC_XCHG(val, new)     __atomic_exchange_n(val, new, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_STORE(val, new)    __atomic_store_n(val, new, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_LOAD(val)          __atomic_load_n(val, __ATOMIC_SEQ_CST)

/* Variants that don't generate any memory barrier.
 * If you're unsure how to deal with barriers, just use the HA_ATOMIC_* version,
 * that will always generate correct code.
 * Usually it's fine to use those when updating data that have no dependency,
 * ie updating a counter. Otherwise a barrier is required.
 */
#define _HA_ATOMIC_CAS(val, old, new) __atomic_compare_exchange_n(val, old, new, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)
/* warning, n is a pointer to the double value for dwcas */
#define _HA_ATOMIC_DWCAS(val, o, n)   __ha_cas_dw(val, o, n)
#define _HA_ATOMIC_ADD(val, i)        __atomic_add_fetch(val, i, __ATOMIC_RELAXED)
#define _HA_ATOMIC_XADD(val, i)       __atomic_fetch_add(val, i, __ATOMIC_RELAXED)
#define _HA_ATOMIC_SUB(val, i)        __atomic_sub_fetch(val, i, __ATOMIC_RELAXED)
#define _HA_ATOMIC_AND(val, flags)    __atomic_and_fetch(val, flags, __ATOMIC_RELAXED)
#define _HA_ATOMIC_OR(val, flags)     __atomic_or_fetch(val,  flags, __ATOMIC_RELAXED)
#define _HA_ATOMIC_XCHG(val, new)     __atomic_exchange_n(val, new, __ATOMIC_RELAXED)
#define _HA_ATOMIC_STORE(val, new)    __atomic_store_n(val, new, __ATOMIC_RELAXED)
#define _HA_ATOMIC_LOAD(val)          __atomic_load_n(val, __ATOMIC_RELAXED)

#endif /* gcc >= 4.7 */

#define HA_ATOMIC_UPDATE_MAX(val, new)					\
	({								\
		typeof(*(val)) __old_max = *(val);			\
		typeof(*(val)) __new_max = (new);			\
									\
		while (__old_max < __new_max &&				\
		       !HA_ATOMIC_CAS(val, &__old_max, __new_max));	\
		*(val);							\
	})
#define HA_ATOMIC_UPDATE_MIN(val, new)					\
	({								\
		typeof(*(val)) __old_min = *(val);			\
		typeof(*(val)) __new_min = (new);			\
									\
		while (__old_min > __new_min &&				\
		       !HA_ATOMIC_CAS(val, &__old_min, __new_min));	\
		*(val);							\
	})

#define HA_BARRIER() pl_barrier()

void thread_harmless_till_end();
void thread_isolate();
void thread_release();
void thread_sync_release();
void ha_tkill(unsigned int thr, int sig);
void ha_tkillall(int sig);

extern struct thread_info {
	pthread_t pthread;
	clockid_t clock_id;
	timer_t wd_timer;          /* valid timer or TIMER_INVALID if not set */
	uint64_t prev_cpu_time;    /* previous per thread CPU time */
	uint64_t prev_mono_time;   /* previous system wide monotonic time  */
	unsigned int idle_pct;     /* idle to total ratio over last sample (percent) */
	unsigned int flags;        /* thread info flags, TI_FL_* */
	/* pad to cache line (64B) */
	char __pad[0];            /* unused except to check remaining room */
	char __end[0] __attribute__((aligned(64)));
} ha_thread_info[MAX_THREADS];

extern THREAD_LOCAL unsigned int tid;     /* The thread id */
extern THREAD_LOCAL unsigned long tid_bit; /* The bit corresponding to the thread id */
extern THREAD_LOCAL struct thread_info *ti; /* thread_info for the current thread */
extern volatile unsigned long all_threads_mask;
extern volatile unsigned long threads_want_rdv_mask;
extern volatile unsigned long threads_harmless_mask;
extern volatile unsigned long threads_sync_mask;

/* explanation for threads_want_rdv_mask, threads_harmless_mask, and
 * threads_sync_mask :
 * - threads_want_rdv_mask is a bit field indicating all threads that have
 *   requested a rendez-vous of other threads using thread_isolate().
 * - threads_harmless_mask is a bit field indicating all threads that are
 *   currently harmless in that they promise not to access a shared resource.
 * - threads_sync_mask is a bit field indicating that a thread waiting for
 *   others to finish wants to leave synchronized with others and as such
 *   promises to do so as well using thread_sync_release().
 *
 * For a given thread, its bits in want_rdv and harmless can be translated like
 * this :
 *
 *  ----------+----------+----------------------------------------------------
 *   want_rdv | harmless | description
 *  ----------+----------+----------------------------------------------------
 *       0    |     0    | thread not interested in RDV, possibly harmful
 *       0    |     1    | thread not interested in RDV but harmless
 *       1    |     1    | thread interested in RDV and waiting for its turn
 *       1    |     0    | thread currently working isolated from others
 *  ----------+----------+----------------------------------------------------
 *
 * thread_sync_mask only delays the leaving of threads_sync_release() to make
 * sure that each thread's harmless bit is cleared before leaving the function.
 */

#define ha_sigmask(how, set, oldset)  pthread_sigmask(how, set, oldset)

/* sets the thread ID and the TID bit for the current thread */
static inline void ha_set_tid(unsigned int data)
{
	tid     = data;
	tid_bit = (1UL << tid);
	ti      = &ha_thread_info[tid];
}

static inline void ha_thread_relax(void)
{
#if _POSIX_PRIORITY_SCHEDULING
	sched_yield();
#else
	pl_cpu_relax();
#endif
}

/* Marks the thread as harmless. Note: this must be true, i.e. the thread must
 * not be touching any unprotected shared resource during this period. Usually
 * this is called before poll(), but it may also be placed around very slow
 * calls (eg: some crypto operations). Needs to be terminated using
 * thread_harmless_end().
 */
static inline void thread_harmless_now()
{
	HA_ATOMIC_OR(&threads_harmless_mask, tid_bit);
}

/* Ends the harmless period started by thread_harmless_now(). Usually this is
 * placed after the poll() call. If it is discovered that a job was running and
 * is relying on the thread still being harmless, the thread waits for the
 * other one to finish.
 */
static inline void thread_harmless_end()
{
	while (1) {
		HA_ATOMIC_AND(&threads_harmless_mask, ~tid_bit);
		if (likely((threads_want_rdv_mask & all_threads_mask) == 0))
			break;
		thread_harmless_till_end();
	}
}

/* an isolated thread has harmless cleared and want_rdv set */
static inline unsigned long thread_isolated()
{
	return threads_want_rdv_mask & ~threads_harmless_mask & tid_bit;
}


#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)

/* WARNING!!! if you update this enum, please also keep lock_label() up to date below */
enum lock_label {
	FD_LOCK,
	TASK_RQ_LOCK,
	TASK_WQ_LOCK,
	POOL_LOCK,
	LISTENER_LOCK,
	PROXY_LOCK,
	SERVER_LOCK,
	LBPRM_LOCK,
	SIGNALS_LOCK,
	STK_TABLE_LOCK,
	STK_SESS_LOCK,
	APPLETS_LOCK,
	PEER_LOCK,
	BUF_WQ_LOCK,
	STRMS_LOCK,
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
	LOGSRV_LOCK,
	DICT_LOCK,
	PROTO_LOCK,
	CKCH_LOCK,
	SNI_LOCK,
	OTHER_LOCK,
	LOCK_LABELS
};
struct lock_stat {
	uint64_t nsec_wait_for_write;
	uint64_t nsec_wait_for_read;
	uint64_t num_write_locked;
	uint64_t num_write_unlocked;
	uint64_t num_read_locked;
	uint64_t num_read_unlocked;
};

extern struct lock_stat lock_stats[LOCK_LABELS];

#define __HA_SPINLOCK_T      unsigned long

#define __SPIN_INIT(l)         ({ (*l) = 0; })
#define __SPIN_DESTROY(l)      ({ (*l) = 0; })
#define __SPIN_LOCK(l)         pl_take_s(l)
#define __SPIN_TRYLOCK(l)      !pl_try_s(l)
#define __SPIN_UNLOCK(l)       pl_drop_s(l)

#define __HA_RWLOCK_T		unsigned long

#define __RWLOCK_INIT(l)          ({ (*l) = 0; })
#define __RWLOCK_DESTROY(l)       ({ (*l) = 0; })
#define __RWLOCK_WRLOCK(l)        pl_take_w(l)
#define __RWLOCK_TRYWRLOCK(l)     !pl_try_w(l)
#define __RWLOCK_WRUNLOCK(l)      pl_drop_w(l)
#define __RWLOCK_RDLOCK(l)        pl_take_r(l)
#define __RWLOCK_TRYRDLOCK(l)     !pl_try_r(l)
#define __RWLOCK_RDUNLOCK(l)      pl_drop_r(l)

#define HA_SPINLOCK_T       struct ha_spinlock

#define HA_SPIN_INIT(l)        __spin_init(l)
#define HA_SPIN_DESTROY(l)      __spin_destroy(l)

#define HA_SPIN_LOCK(lbl, l)    __spin_lock(lbl, l, __func__, __FILE__, __LINE__)
#define HA_SPIN_TRYLOCK(lbl, l) __spin_trylock(lbl, l, __func__, __FILE__, __LINE__)
#define HA_SPIN_UNLOCK(lbl, l)  __spin_unlock(lbl, l, __func__, __FILE__, __LINE__)

#define HA_RWLOCK_T         struct ha_rwlock

#define HA_RWLOCK_INIT(l)          __ha_rwlock_init((l))
#define HA_RWLOCK_DESTROY(l)       __ha_rwlock_destroy((l))
#define HA_RWLOCK_WRLOCK(lbl,l)    __ha_rwlock_wrlock(lbl, l, __func__, __FILE__, __LINE__)
#define HA_RWLOCK_TRYWRLOCK(lbl,l) __ha_rwlock_trywrlock(lbl, l, __func__, __FILE__, __LINE__)
#define HA_RWLOCK_WRUNLOCK(lbl,l)  __ha_rwlock_wrunlock(lbl, l, __func__, __FILE__, __LINE__)
#define HA_RWLOCK_RDLOCK(lbl,l)    __ha_rwlock_rdlock(lbl, l)
#define HA_RWLOCK_TRYRDLOCK(lbl,l) __ha_rwlock_tryrdlock(lbl, l)
#define HA_RWLOCK_RDUNLOCK(lbl,l)  __ha_rwlock_rdunlock(lbl, l)

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

static inline const char *lock_label(enum lock_label label)
{
	switch (label) {
	case FD_LOCK:              return "FD";
	case TASK_RQ_LOCK:         return "TASK_RQ";
	case TASK_WQ_LOCK:         return "TASK_WQ";
	case POOL_LOCK:            return "POOL";
	case LISTENER_LOCK:        return "LISTENER";
	case PROXY_LOCK:           return "PROXY";
	case SERVER_LOCK:          return "SERVER";
	case LBPRM_LOCK:           return "LBPRM";
	case SIGNALS_LOCK:         return "SIGNALS";
	case STK_TABLE_LOCK:       return "STK_TABLE";
	case STK_SESS_LOCK:        return "STK_SESS";
	case APPLETS_LOCK:         return "APPLETS";
	case PEER_LOCK:            return "PEER";
	case BUF_WQ_LOCK:          return "BUF_WQ";
	case STRMS_LOCK:           return "STRMS";
	case SSL_LOCK:             return "SSL";
	case SSL_GEN_CERTS_LOCK:   return "SSL_GEN_CERTS";
	case PATREF_LOCK:          return "PATREF";
	case PATEXP_LOCK:          return "PATEXP";
	case VARS_LOCK:            return "VARS";
	case COMP_POOL_LOCK:       return "COMP_POOL";
	case LUA_LOCK:             return "LUA";
	case NOTIF_LOCK:           return "NOTIF";
	case SPOE_APPLET_LOCK:     return "SPOE_APPLET";
	case DNS_LOCK:             return "DNS";
	case PID_LIST_LOCK:        return "PID_LIST";
	case EMAIL_ALERTS_LOCK:    return "EMAIL_ALERTS";
	case PIPES_LOCK:           return "PIPES";
	case TLSKEYS_REF_LOCK:     return "TLSKEYS_REF";
	case AUTH_LOCK:            return "AUTH";
	case LOGSRV_LOCK:          return "LOGSRV";
	case DICT_LOCK:            return "DICT";
	case PROTO_LOCK:           return "PROTO";
	case CKCH_LOCK:            return "CKCH";
	case SNI_LOCK:             return "SNI";
	case OTHER_LOCK:           return "OTHER";
	case LOCK_LABELS:          break; /* keep compiler happy */
	};
	/* only way to come here is consecutive to an internal bug */
	abort();
}

static inline void show_lock_stats()
{
	int lbl;

	for (lbl = 0; lbl < LOCK_LABELS; lbl++) {
		fprintf(stderr,
			"Stats about Lock %s: \n"
			"\t # write lock  : %lu\n"
			"\t # write unlock: %lu (%ld)\n"
			"\t # wait time for write     : %.3f msec\n"
			"\t # wait time for write/lock: %.3f nsec\n"
			"\t # read lock   : %lu\n"
			"\t # read unlock : %lu (%ld)\n"
			"\t # wait time for read      : %.3f msec\n"
			"\t # wait time for read/lock : %.3f nsec\n",
			lock_label(lbl),
			lock_stats[lbl].num_write_locked,
			lock_stats[lbl].num_write_unlocked,
			lock_stats[lbl].num_write_unlocked - lock_stats[lbl].num_write_locked,
			(double)lock_stats[lbl].nsec_wait_for_write / 1000000.0,
			lock_stats[lbl].num_write_locked ? ((double)lock_stats[lbl].nsec_wait_for_write / (double)lock_stats[lbl].num_write_locked) : 0,
			lock_stats[lbl].num_read_locked,
			lock_stats[lbl].num_read_unlocked,
			lock_stats[lbl].num_read_unlocked - lock_stats[lbl].num_read_locked,
			(double)lock_stats[lbl].nsec_wait_for_read / 1000000.0,
			lock_stats[lbl].num_read_locked ? ((double)lock_stats[lbl].nsec_wait_for_read / (double)lock_stats[lbl].num_read_locked) : 0);
	}
}

/* Following functions are used to collect some stats about locks. We wrap
 * pthread functions to known how much time we wait in a lock. */

static uint64_t nsec_now(void) {
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ((uint64_t) ts.tv_sec * 1000000000ULL +
                (uint64_t) ts.tv_nsec);
}

static inline void __ha_rwlock_init(struct ha_rwlock *l)
{
	memset(l, 0, sizeof(struct ha_rwlock));
	__RWLOCK_INIT(&l->lock);
}

static inline void __ha_rwlock_destroy(struct ha_rwlock *l)
{
	__RWLOCK_DESTROY(&l->lock);
	memset(l, 0, sizeof(struct ha_rwlock));
}


static inline void __ha_rwlock_wrlock(enum lock_label lbl, struct ha_rwlock *l,
				      const char *func, const char *file, int line)
{
	uint64_t start_time;

	if (unlikely(l->info.cur_writer & tid_bit)) {
		/* the thread is already owning the lock for write */
		abort();
	}

	if (unlikely(l->info.cur_readers & tid_bit)) {
		/* the thread is already owning the lock for read */
		abort();
	}

	HA_ATOMIC_OR(&l->info.wait_writers, tid_bit);

	start_time = nsec_now();
	__RWLOCK_WRLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_write, (nsec_now() - start_time));

	HA_ATOMIC_ADD(&lock_stats[lbl].num_write_locked, 1);

	l->info.cur_writer             = tid_bit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&l->info.wait_writers, ~tid_bit);
}

static inline int __ha_rwlock_trywrlock(enum lock_label lbl, struct ha_rwlock *l,
				        const char *func, const char *file, int line)
{
	uint64_t start_time;
	int r;

	if (unlikely(l->info.cur_writer & tid_bit)) {
		/* the thread is already owning the lock for write */
		abort();
	}

	if (unlikely(l->info.cur_readers & tid_bit)) {
		/* the thread is already owning the lock for read */
		abort();
	}

	/* We set waiting writer because trywrlock could wait for readers to quit */
	HA_ATOMIC_OR(&l->info.wait_writers, tid_bit);

	start_time = nsec_now();
	r = __RWLOCK_TRYWRLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_write, (nsec_now() - start_time));
	if (unlikely(r)) {
		HA_ATOMIC_AND(&l->info.wait_writers, ~tid_bit);
		return r;
	}
	HA_ATOMIC_ADD(&lock_stats[lbl].num_write_locked, 1);

	l->info.cur_writer             = tid_bit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&l->info.wait_writers, ~tid_bit);

	return 0;
}

static inline void __ha_rwlock_wrunlock(enum lock_label lbl,struct ha_rwlock *l,
				        const char *func, const char *file, int line)
{
	if (unlikely(!(l->info.cur_writer & tid_bit))) {
		/* the thread is not owning the lock for write */
		abort();
	}

	l->info.cur_writer             = 0;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	__RWLOCK_WRUNLOCK(&l->lock);

	HA_ATOMIC_ADD(&lock_stats[lbl].num_write_unlocked, 1);
}

static inline void __ha_rwlock_rdlock(enum lock_label lbl,struct ha_rwlock *l)
{
	uint64_t start_time;

	if (unlikely(l->info.cur_writer & tid_bit)) {
		/* the thread is already owning the lock for write */
		abort();
	}

	if (unlikely(l->info.cur_readers & tid_bit)) {
		/* the thread is already owning the lock for read */
		abort();
	}

	HA_ATOMIC_OR(&l->info.wait_readers, tid_bit);

	start_time = nsec_now();
	__RWLOCK_RDLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_read, (nsec_now() - start_time));
	HA_ATOMIC_ADD(&lock_stats[lbl].num_read_locked, 1);

	HA_ATOMIC_OR(&l->info.cur_readers, tid_bit);

	HA_ATOMIC_AND(&l->info.wait_readers, ~tid_bit);
}

static inline int __ha_rwlock_tryrdlock(enum lock_label lbl,struct ha_rwlock *l)
{
	int r;

	if (unlikely(l->info.cur_writer & tid_bit)) {
		/* the thread is already owning the lock for write */
		abort();
	}

	if (unlikely(l->info.cur_readers & tid_bit)) {
		/* the thread is already owning the lock for read */
		abort();
	}

	/* try read should never wait */
	r = __RWLOCK_TRYRDLOCK(&l->lock);
	if (unlikely(r))
		return r;
	HA_ATOMIC_ADD(&lock_stats[lbl].num_read_locked, 1);

	HA_ATOMIC_OR(&l->info.cur_readers, tid_bit);

	return 0;
}

static inline void __ha_rwlock_rdunlock(enum lock_label lbl,struct ha_rwlock *l)
{
	if (unlikely(!(l->info.cur_readers & tid_bit))) {
		/* the thread is not owning the lock for read */
		abort();
	}

	HA_ATOMIC_AND(&l->info.cur_readers, ~tid_bit);

	__RWLOCK_RDUNLOCK(&l->lock);

	HA_ATOMIC_ADD(&lock_stats[lbl].num_read_unlocked, 1);
}

static inline void __spin_init(struct ha_spinlock *l)
{
	memset(l, 0, sizeof(struct ha_spinlock));
	__SPIN_INIT(&l->lock);
}

static inline void __spin_destroy(struct ha_spinlock *l)
{
	__SPIN_DESTROY(&l->lock);
	memset(l, 0, sizeof(struct ha_spinlock));
}

static inline void __spin_lock(enum lock_label lbl, struct ha_spinlock *l,
			      const char *func, const char *file, int line)
{
	uint64_t start_time;

	if (unlikely(l->info.owner & tid_bit)) {
		/* the thread is already owning the lock */
		abort();
	}

	HA_ATOMIC_OR(&l->info.waiters, tid_bit);

	start_time = nsec_now();
	__SPIN_LOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_write, (nsec_now() - start_time));

	HA_ATOMIC_ADD(&lock_stats[lbl].num_write_locked, 1);


	l->info.owner                  = tid_bit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&l->info.waiters, ~tid_bit);
}

static inline int __spin_trylock(enum lock_label lbl, struct ha_spinlock *l,
				 const char *func, const char *file, int line)
{
	int r;

	if (unlikely(l->info.owner & tid_bit)) {
		/* the thread is already owning the lock */
		abort();
	}

	/* try read should never wait */
	r = __SPIN_TRYLOCK(&l->lock);
	if (unlikely(r))
		return r;
	HA_ATOMIC_ADD(&lock_stats[lbl].num_write_locked, 1);

	l->info.owner                  = tid_bit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	return 0;
}

static inline void __spin_unlock(enum lock_label lbl, struct ha_spinlock *l,
				 const char *func, const char *file, int line)
{
	if (unlikely(!(l->info.owner & tid_bit))) {
		/* the thread is not owning the lock */
		abort();
	}

	l->info.owner                  = 0;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	__SPIN_UNLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].num_write_unlocked, 1);
}

#else /* DEBUG_THREAD */

#define HA_SPINLOCK_T        unsigned long

#define HA_SPIN_INIT(l)         ({ (*l) = 0; })
#define HA_SPIN_DESTROY(l)      ({ (*l) = 0; })
#define HA_SPIN_LOCK(lbl, l)    pl_take_s(l)
#define HA_SPIN_TRYLOCK(lbl, l) !pl_try_s(l)
#define HA_SPIN_UNLOCK(lbl, l)  pl_drop_s(l)

#define HA_RWLOCK_T		unsigned long

#define HA_RWLOCK_INIT(l)          ({ (*l) = 0; })
#define HA_RWLOCK_DESTROY(l)       ({ (*l) = 0; })
#define HA_RWLOCK_WRLOCK(lbl,l)    pl_take_w(l)
#define HA_RWLOCK_TRYWRLOCK(lbl,l) !pl_try_w(l)
#define HA_RWLOCK_WRUNLOCK(lbl,l)  pl_drop_w(l)
#define HA_RWLOCK_RDLOCK(lbl,l)    pl_take_r(l)
#define HA_RWLOCK_TRYRDLOCK(lbl,l) !pl_try_r(l)
#define HA_RWLOCK_RDUNLOCK(lbl,l)  pl_drop_r(l)

#endif  /* DEBUG_THREAD */

#ifdef __x86_64__

static __inline int
__ha_cas_dw(void *target, void *compare, const void *set)
{
        char ret;

        __asm __volatile("lock cmpxchg16b %0; setz %3"
                          : "+m" (*(void **)target),
                            "=a" (((void **)compare)[0]),
                            "=d" (((void **)compare)[1]),
                            "=q" (ret)
                          : "a" (((void **)compare)[0]),
                            "d" (((void **)compare)[1]),
                            "b" (((const void **)set)[0]),
                            "c" (((const void **)set)[1])
                          : "memory", "cc");
        return (ret);
}

/* Use __ha_barrier_atomic* when you're trying to protect data that are
 * are modified using HA_ATOMIC* (except HA_ATOMIC_STORE)
 */
static __inline void
__ha_barrier_atomic_load(void)
{
	__asm __volatile("" ::: "memory");
}

static __inline void
__ha_barrier_atomic_store(void)
{
	__asm __volatile("" ::: "memory");
}

static __inline void
__ha_barrier_atomic_full(void)
{
	__asm __volatile("" ::: "memory");
}

static __inline void
__ha_barrier_load(void)
{
	__asm __volatile("lfence" ::: "memory");
}

static __inline void
__ha_barrier_store(void)
{
	__asm __volatile("sfence" ::: "memory");
}

static __inline void
__ha_barrier_full(void)
{
	__asm __volatile("mfence" ::: "memory");
}

#elif defined(__arm__) && (defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__))

/* Use __ha_barrier_atomic* when you're trying to protect data that are
 * are modified using HA_ATOMIC* (except HA_ATOMIC_STORE)
 */
static __inline void
__ha_barrier_atomic_load(void)
{
	__asm __volatile("dmb" ::: "memory");
}

static __inline void
__ha_barrier_atomic_store(void)
{
	__asm __volatile("dsb" ::: "memory");
}

static __inline void
__ha_barrier_atomic_full(void)
{
	__asm __volatile("dmb" ::: "memory");
}

static __inline void
__ha_barrier_load(void)
{
	__asm __volatile("dmb" ::: "memory");
}

static __inline void
__ha_barrier_store(void)
{
	__asm __volatile("dsb" ::: "memory");
}

static __inline void
__ha_barrier_full(void)
{
	__asm __volatile("dmb" ::: "memory");
}

static __inline int __ha_cas_dw(void *target, void *compare, const void *set)
{
	uint64_t previous;
	int tmp;

	__asm __volatile("1:"
	                 "ldrexd %0, [%4];"
			 "cmp %Q0, %Q2;"
			 "ittt eq;"
			 "cmpeq %R0, %R2;"
			 "strexdeq %1, %3, [%4];"
			 "cmpeq %1, #1;"
			 "beq 1b;"
			 : "=&r" (previous), "=&r" (tmp)
			 : "r" (*(uint64_t *)compare), "r" (*(uint64_t *)set), "r" (target)
			 : "memory", "cc");
	tmp = (previous == *(uint64_t *)compare);
	*(uint64_t *)compare = previous;
	return (tmp);
}

#elif defined (__aarch64__)

/* Use __ha_barrier_atomic* when you're trying to protect data that are
 * are modified using HA_ATOMIC* (except HA_ATOMIC_STORE)
 */
static __inline void
__ha_barrier_atomic_load(void)
{
	__asm __volatile("dmb ishld" ::: "memory");
}

static __inline void
__ha_barrier_atomic_store(void)
{
	__asm __volatile("dmb ishst" ::: "memory");
}

static __inline void
__ha_barrier_atomic_full(void)
{
	__asm __volatile("dmb ish" ::: "memory");
}

static __inline void
__ha_barrier_load(void)
{
	__asm __volatile("dmb ishld" ::: "memory");
}

static __inline void
__ha_barrier_store(void)
{
	__asm __volatile("dmb ishst" ::: "memory");
}

static __inline void
__ha_barrier_full(void)
{
	__asm __volatile("dmb ish" ::: "memory");
}

static __inline int __ha_cas_dw(void *target, void *compare, void *set)
{
	void *value[2];
	uint64_t tmp1, tmp2;

	__asm__ __volatile__("1:"
                             "ldxp %0, %1, [%4];"
                             "mov %2, %0;"
                             "mov %3, %1;"
                             "eor %0, %0, %5;"
                             "eor %1, %1, %6;"
                             "orr %1, %0, %1;"
                             "mov %w0, #0;"
                             "cbnz %1, 2f;"
                             "stxp %w0, %7, %8, [%4];"
                             "cbnz %w0, 1b;"
                             "mov %w0, #1;"
                             "2:"
                             : "=&r" (tmp1), "=&r" (tmp2), "=&r" (value[0]), "=&r" (value[1])
                             : "r" (target), "r" (((void **)(compare))[0]), "r" (((void **)(compare))[1]), "r" (((void **)(set))[0]), "r" (((void **)(set))[1])
                             : "cc", "memory");

	memcpy(compare, &value, sizeof(value));
        return (tmp1);
}

#else
#define __ha_barrier_atomic_load __sync_synchronize
#define __ha_barrier_atomic_store __sync_synchronize
#define __ha_barrier_atomic_full __sync_synchronize
#define __ha_barrier_load __sync_synchronize
#define __ha_barrier_store __sync_synchronize
#define __ha_barrier_full __sync_synchronize
#endif

void ha_spin_init(HA_SPINLOCK_T *l);
void ha_rwlock_init(HA_RWLOCK_T *l);

#endif /* USE_THREAD */

extern int thread_cpus_enabled_at_boot;

static inline void __ha_compiler_barrier(void)
{
	__asm __volatile("" ::: "memory");
}

int parse_nbthread(const char *arg, char **err);
int thread_get_default_count();

#ifndef _HA_ATOMIC_CAS
#define _HA_ATOMIC_CAS HA_ATOMIC_CAS
#endif /* !_HA_ATOMIC_CAS */

#ifndef _HA_ATOMIC_DWCAS
#define _HA_ATOMIC_DWCAS HA_ATOMIC_DWCAS
#endif /* !_HA_ATOMIC_CAS */

#ifndef _HA_ATOMIC_ADD
#define _HA_ATOMIC_ADD HA_ATOMIC_ADD
#endif /* !_HA_ATOMIC_ADD */

#ifndef _HA_ATOMIC_XADD
#define _HA_ATOMIC_XADD HA_ATOMIC_XADD
#endif /* !_HA_ATOMIC_SUB */

#ifndef _HA_ATOMIC_SUB
#define _HA_ATOMIC_SUB HA_ATOMIC_SUB
#endif /* !_HA_ATOMIC_SUB */

#ifndef _HA_ATOMIC_AND
#define _HA_ATOMIC_AND HA_ATOMIC_AND
#endif /* !_HA_ATOMIC_AND */

#ifndef _HA_ATOMIC_OR
#define _HA_ATOMIC_OR HA_ATOMIC_OR
#endif /* !_HA_ATOMIC_OR */

#ifndef _HA_ATOMIC_XCHG
#define _HA_ATOMIC_XCHG HA_ATOMIC_XCHG
#endif /* !_HA_ATOMIC_XCHG */

#ifndef _HA_ATOMIC_STORE
#define _HA_ATOMIC_STORE HA_ATOMIC_STORE
#endif /* !_HA_ATOMIC_STORE */

#ifndef _HA_ATOMIC_LOAD
#define _HA_ATOMIC_LOAD HA_ATOMIC_LOAD
#endif /* !_HA_ATOMIC_LOAD */
#endif /* _COMMON_HATHREADS_H */
