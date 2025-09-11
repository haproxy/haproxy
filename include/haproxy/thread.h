/*
 * include/haproxy/thread.h
 * definitions, macros and inline functions used by threads.
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

#ifndef _HAPROXY_THREAD_H
#define _HAPROXY_THREAD_H

#include <haproxy/api.h>
#include <haproxy/thread-t.h>
#include <haproxy/tinfo.h>


/* Note: this file mainly contains 5 sections:
 *   - a small common part, which also corresponds to the common API
 *   - one used solely when USE_THREAD is *not* set
 *   - one used solely when USE_THREAD is set
 *   - one used solely when USE_THREAD is set WITHOUT debugging
 *   - one used solely when USE_THREAD is set WITH debugging
 *
 */


/* Generic exports */
int parse_nbthread(const char *arg, char **err);
void ha_tkill(unsigned int thr, int sig);
void ha_tkillall(int sig);
void ha_thread_relax(void);
int thread_detect_binding_discrepancies(void);
int thread_detect_more_than_cpus(void);
int thread_map_to_groups();
int thread_resolve_group_mask(struct thread_set *ts, int defgrp, char **err);
void thread_detect_count(void);
int parse_thread_set(const char *arg, struct thread_set *ts, char **err);
const char *lock_label(enum lock_label label);
extern int thread_cpus_enabled_at_boot;


#ifndef USE_THREAD

/********************** THREADS DISABLED ************************/

/* Only way found to replace variables with constants that are optimized away
 * at build time.
 */
enum { all_tgroups_mask = 1UL };
enum { tid_bit = 1UL };
enum { tid = 0 };
enum { tgid = 1 };

#define HA_SPIN_INIT(l)               do { /* do nothing */ } while(0)
#define HA_SPIN_DESTROY(l)            do { /* do nothing */ } while(0)
#define HA_SPIN_LOCK(lbl, l)          do { /* do nothing */ } while(0)
#define HA_SPIN_TRYLOCK(lbl, l)       ({ 0; })
#define HA_SPIN_UNLOCK(lbl, l)        do { /* do nothing */ } while(0)

#define HA_RWLOCK_INIT(l)             do { /* do nothing */ } while(0)
#define HA_RWLOCK_DESTROY(l)          do { /* do nothing */ } while(0)
#define HA_RWLOCK_WRLOCK(lbl, l)      do { /* do nothing */ } while(0)
#define HA_RWLOCK_TRYWRLOCK(lbl, l)   ({ 0; })
#define HA_RWLOCK_WRUNLOCK(lbl, l)    do { /* do nothing */ } while(0)
#define HA_RWLOCK_RDLOCK(lbl, l)      do { /* do nothing */ } while(0)
#define HA_RWLOCK_TRYRDLOCK(lbl, l)   ({ 0; })
#define HA_RWLOCK_RDUNLOCK(lbl, l)    do { /* do nothing */ } while(0)

#define HA_RWLOCK_SKLOCK(lbl,l)         do { /* do nothing */ } while(0)
#define HA_RWLOCK_SKTOWR(lbl,l)         do { /* do nothing */ } while(0)
#define HA_RWLOCK_WRTOSK(lbl,l)         do { /* do nothing */ } while(0)
#define HA_RWLOCK_SKTORD(lbl,l)         do { /* do nothing */ } while(0)
#define HA_RWLOCK_WRTORD(lbl,l)         do { /* do nothing */ } while(0)
#define HA_RWLOCK_SKUNLOCK(lbl,l)       do { /* do nothing */ } while(0)
#define HA_RWLOCK_TRYSKLOCK(lbl,l)      ({ 0; })
#define HA_RWLOCK_TRYRDTOSK(lbl,l)      ({ 0; })
#define HA_RWLOCK_TRYRDTOWR(lbl,l)      ({ 0; })

#define ha_sigmask(how, set, oldset)  sigprocmask(how, set, oldset)

/* Sets the current thread to a valid one described by <thr>, or to any thread
 * and any group if NULL (e.g. for use during boot where they're not totally
 * initialized).
 */
static inline void ha_set_thread(const struct thread_info *thr)
{
	if (thr) {
		ti = thr;
		tg = ti->tg;
		th_ctx = &ha_thread_ctx[ti->tid];
	} else {
		ti = &ha_thread_info[0];
		tg = &ha_tgroup_info[0];
		th_ctx = &ha_thread_ctx[0];
	}
}

static inline void thread_idle_now()
{
	tg_ctx->threads_idle |= ti->ltid_bit;
}

static inline void thread_idle_end()
{
	tg_ctx->threads_idle &= ~ti->ltid_bit;
}

static inline void thread_harmless_now()
{
	tg_ctx->threads_harmless |= ti->ltid_bit;
}

static inline int is_thread_harmless()
{
	return 	!!(tg_ctx->threads_harmless & ti->ltid_bit);
}

static inline void thread_harmless_end()
{
	tg_ctx->threads_harmless &= ~ti->ltid_bit;
}

static inline void thread_harmless_end_sig()
{
	tg_ctx->threads_harmless &= ~ti->ltid_bit;
}

static inline void thread_isolate()
{
}

static inline void thread_isolate_full()
{
}

static inline void thread_release()
{
}

static inline unsigned long thread_isolated()
{
	return 1;
}

static inline void setup_extra_threads(void *(*handler)(void *))
{
}

static inline void wait_for_threads_completion()
{
}

static inline void set_thread_cpu_affinity()
{
}

static inline unsigned long long ha_get_pthread_id(unsigned int thr)
{
	return 0;
}

static inline void cshared_init(struct cshared *ctr, uint64_t *var, int lim)
{
	ctr->global = var;
	ctr->diff = 0;
	ctr->lim = 0;
}

static inline void cshared_add(struct cshared *ctr, int diff)
{
	ctr->global += diff;
}

static inline uint64_t cshared_read(struct cshared *ctr)
{
	return *ctr->global;
}

#else /* !USE_THREAD */

/********************** THREADS ENABLED ************************/

#define PLOCK_LORW_INLINE_WAIT
#include <import/plock.h>

void thread_harmless_till_end(void);
void thread_isolate(void);
void thread_isolate_full(void);
void thread_release(void);
void ha_spin_init(HA_SPINLOCK_T *l);
void ha_rwlock_init(HA_RWLOCK_T *l);
void setup_extra_threads(void *(*handler)(void *));
void wait_for_threads_completion();
void set_thread_cpu_affinity();
unsigned long long ha_get_pthread_id(unsigned int thr);

extern volatile unsigned long all_tgroups_mask;
extern volatile unsigned int rdv_requests;
extern volatile unsigned int isolated_thread;
extern THREAD_LOCAL unsigned int tid;      /* The thread id */
extern THREAD_LOCAL unsigned int tgid;     /* The thread group id (starts at 1) */

#define ha_sigmask(how, set, oldset)  pthread_sigmask(how, set, oldset)

/* Sets the current thread to a valid one described by <thr>, or to any thread
 * and any group if NULL (e.g. for use during boot where they're not totally
 * initialized).
 */
static inline void ha_set_thread(const struct thread_info *thr)
{
	if (thr) {
		BUG_ON(!thr->ltid_bit);
		BUG_ON(!thr->tg);
		BUG_ON(!thr->tgid);

		ti      = thr;
		tg      = thr->tg;
		tid     = thr->tid;
		tgid    = thr->tgid;
		th_ctx  = &ha_thread_ctx[tid];
		tg_ctx  = &ha_tgroup_ctx[tgid-1];
	} else {
		tgid    = 1;
		tid     = 0;
		ti      = &ha_thread_info[0];
		tg      = &ha_tgroup_info[0];
		th_ctx  = &ha_thread_ctx[0];
		tg_ctx  = &ha_tgroup_ctx[0];
	}
}

/* Marks the thread as idle, which means that not only it's not doing anything
 * dangerous, but in addition it has not started anything sensitive either.
 * This essentially means that the thread currently is in the poller, thus
 * outside of any execution block. Needs to be terminated using
 * thread_idle_end(). This is needed to release a concurrent call to
 * thread_isolate_full().
 */
static inline void thread_idle_now()
{
	HA_ATOMIC_OR(&tg_ctx->threads_idle, ti->ltid_bit);
}

/* Ends the harmless period started by thread_idle_now(), i.e. the thread is
 * about to restart engaging in sensitive operations. This must not be done on
 * a thread marked harmless, as it could cause a deadlock between another
 * thread waiting for idle again and thread_harmless_end() in this thread.
 *
 * The right sequence is thus:
 *    thread_idle_now();
 *      thread_harmless_now();
 *        poll();
 *      thread_harmless_end();
 *    thread_idle_end();
 */
static inline void thread_idle_end()
{
	HA_ATOMIC_AND(&tg_ctx->threads_idle, ~ti->ltid_bit);
}


/* Marks the thread as harmless. Note: this must be true, i.e. the thread must
 * not be touching any unprotected shared resource during this period. Usually
 * this is called before poll(), but it may also be placed around very slow
 * calls (eg: some crypto operations). Needs to be terminated using
 * thread_harmless_end().
 */
static inline void thread_harmless_now()
{
	HA_ATOMIC_OR(&tg_ctx->threads_harmless, ti->ltid_bit);
}

/* Returns non-zero if the current thread is already harmless */
static inline int is_thread_harmless()
{
	return !!(HA_ATOMIC_LOAD(&tg_ctx->threads_harmless) & ti->ltid_bit);
}

/* Ends the harmless period started by thread_harmless_now(). Usually this is
 * placed after the poll() call. If it is discovered that a job was running and
 * is relying on the thread still being harmless, the thread waits for the
 * other one to finish.
 */
static inline void thread_harmless_end()
{
	while (1) {
		HA_ATOMIC_AND(&tg_ctx->threads_harmless, ~ti->ltid_bit);
		if (likely(_HA_ATOMIC_LOAD(&rdv_requests) == 0))
			break;
		thread_harmless_till_end();
	}
}

/* Ends the harmless period started by thread_harmless_now(), but without
 * waiting for isolated requests. This is meant to be used from signal handlers
 * which might be called recursively while a thread already requested an
 * isolation that must be ignored. It must not be used past a checkpoint where
 * another thread could return and see the current thread as harmless before
 * this call (or this could validate an isolation request by accident).
 */
static inline void thread_harmless_end_sig()
{
	HA_ATOMIC_AND(&tg_ctx->threads_harmless, ~ti->ltid_bit);
}

/* an isolated thread has its ID in isolated_thread */
static inline unsigned long thread_isolated()
{
	return _HA_ATOMIC_LOAD(&isolated_thread) == tid;
}

/* locking levels, for history and debugging */
#define _LK_UN 0
#define _LK_RD 1
#define _LK_SK 2
#define _LK_WR 3

#if (DEBUG_THREAD < 1) && !defined(DEBUG_FULL)

#define _lock_wait(_LK_, bal, lbl, expr) do { (void)(expr); } while (0)
#define _lock_cond(_LK_, bal, lbl, expr) ({ typeof(expr) _expr = (expr); _expr; })

#else

/* principle: each lock operation takes 8 bits, 6 of which (the highest) are
 * the lock label, and two of which (the lowest) are the operation (_LK_*).
 * In order to preserve as much usable history as possible, we try to merge
 * repetitions:
 *  - if a lock is taken just after it was released, the release is erased
 *    from history and replace with the new operation ;
 *  - if, when replacing an unlock, the new operation is the same as the
 *    one before the unlock, then the new one is not added.
 * This means that sequences like "R:foo U:foo R:foo" just become "R:foo",
 * but that those like "R:foo U:foo W:foo U:foo" become "R:foo W:foo U:foo".
 */
#define _lock_wait_common(_LK_, lbl) do {				\
		ulong _lck = ((lbl + 1) << 2) + _LK_;			\
		if ((uint8_t)th_ctx->lock_history == (uint8_t)(((lbl + 1) << 2) + _LK_UN)) { \
			/* re-lock of just unlocked, try to compact and possibly merge with n-2 */ \
			th_ctx->lock_history >>= 8;			\
			if ((uint8_t)th_ctx->lock_history != (uint8_t)_lck) \
				th_ctx->lock_history = (th_ctx->lock_history << 8) + _lck; \
		}							\
		else							\
			th_ctx->lock_history = (th_ctx->lock_history << 8) + _lck; \
	} while (0)

#define _lock_wait(_LK_, bal, lbl, expr) do {				\
		uint64_t lock_start = 0;				\
		extern uint64_t now_mono_time(void);			\
		if (_LK_ != _LK_UN) {					\
			th_ctx->lock_level += bal;			\
			if (unlikely(th_ctx->flags & TH_FL_TASK_PROFILING)) \
				lock_start = now_mono_time();		\
		}							\
		(void)(expr);						\
		if (_LK_ == _LK_UN) {					\
			th_ctx->lock_level += bal;			\
			if (th_ctx->lock_level == 0 && unlikely(th_ctx->flags & TH_FL_TASK_PROFILING)) \
				th_ctx->locked_total += now_mono_time() - th_ctx->lock_start_date; \
		} else if (unlikely(th_ctx->flags & TH_FL_TASK_PROFILING)) { \
			uint64_t now = now_mono_time();			\
			if (lock_start)					\
				th_ctx->lock_wait_total += now - lock_start; \
			if (th_ctx->lock_level == 1)			\
				th_ctx->lock_start_date = now;		\
		}							\
		if (lbl != OTHER_LOCK)					\
			_lock_wait_common(_LK_, lbl);			\
	} while (0)
#define _lock_cond(_LK_, bal, lbl, expr) ({				\
		typeof(expr) _expr = (expr);				\
		if (_expr == 0) {					\
			th_ctx->lock_level += bal;			\
			if (unlikely(th_ctx->flags & TH_FL_TASK_PROFILING)) { \
				if (_LK_ == _LK_UN && th_ctx->lock_level == 0) \
					th_ctx->locked_total += now_mono_time() - th_ctx->lock_start_date; \
				else if (_LK_ != _LK_UN && th_ctx->lock_level == 1) \
					th_ctx->lock_start_date = now_mono_time(); \
			}						\
		}							\
		if (lbl != OTHER_LOCK && !_expr)			\
			_lock_wait_common(_LK_, lbl);			\
		_expr; \
	})

#endif

/* Init a shared counter <ctr> which references global value <var>. Update are
 * performed each time the shared counter exceed <lim>, either on the positive
 * or negative value.
 */
static inline void cshared_init(struct cshared *ctr, uint64_t *var, int lim)
{
	ctr->global = var;
	ctr->diff = 0;
	ctr->lim = lim;
}

/* Add <diff>, which may be positive or negative, to <ctr> shared counter. */
static inline void cshared_add(struct cshared *ctr, int diff)
{
	ctr->diff += diff;
	if (ctr->diff <= -(ctr->lim) || ctr->diff >= ctr->lim) {
		HA_ATOMIC_ADD(ctr->global, ctr->diff);
		ctr->diff = 0;
	}
}

/* Atomically get current global value from <ctr> shared counter. */
static inline uint64_t cshared_read(struct cshared *ctr)
{
	return HA_ATOMIC_LOAD(ctr->global);
}

#if (DEBUG_THREAD < 2) && !defined(DEBUG_FULL)

/* Thread debugging is DISABLED, these are the regular locking functions */

#define HA_SPIN_INIT(l)            ({ (*l) = 0; })
#define HA_SPIN_DESTROY(l)         ({ (*l) = 0; })
#define HA_SPIN_LOCK(lbl, l)       _lock_wait(_LK_SK,  1, lbl, pl_take_s(l))
#define HA_SPIN_TRYLOCK(lbl, l)    _lock_cond(_LK_SK,  1, lbl, !pl_try_s(l))
#define HA_SPIN_UNLOCK(lbl, l)     _lock_wait(_LK_UN, -1, lbl, pl_drop_s(l))

#define HA_RWLOCK_INIT(l)          ({ (*l) = 0; })
#define HA_RWLOCK_DESTROY(l)       ({ (*l) = 0; })
#define HA_RWLOCK_WRLOCK(lbl,l)    _lock_wait(_LK_WR,  1, lbl, pl_take_w(l))
#define HA_RWLOCK_TRYWRLOCK(lbl,l) _lock_cond(_LK_WR,  1, lbl, !pl_try_w(l))
#define HA_RWLOCK_WRUNLOCK(lbl,l)  _lock_wait(_LK_UN, -1, lbl, pl_drop_w(l))
#define HA_RWLOCK_RDLOCK(lbl,l)    _lock_wait(_LK_RD,  1, lbl, pl_take_r(l))
#define HA_RWLOCK_TRYRDLOCK(lbl,l) _lock_cond(_LK_RD,  1, lbl, (!pl_try_r(l)))
#define HA_RWLOCK_RDUNLOCK(lbl,l)  _lock_wait(_LK_UN, -1, lbl, pl_drop_r(l))

/* rwlock upgrades via seek locks */
#define HA_RWLOCK_SKLOCK(lbl,l)         _lock_wait(_LK_SK,  1, lbl, pl_take_s(l))      /* N --> S */
#define HA_RWLOCK_SKTOWR(lbl,l)         _lock_wait(_LK_WR,  0, lbl, pl_stow(l))        /* S --> W */
#define HA_RWLOCK_WRTOSK(lbl,l)         _lock_wait(_LK_SK,  0, lbl, pl_wtos(l))        /* W --> S */
#define HA_RWLOCK_SKTORD(lbl,l)         _lock_wait(_LK_RD,  0, lbl, pl_stor(l))        /* S --> R */
#define HA_RWLOCK_WRTORD(lbl,l)         _lock_wait(_LK_RD,  0, lbl, pl_wtor(l))        /* W --> R */
#define HA_RWLOCK_SKUNLOCK(lbl,l)       _lock_wait(_LK_UN, -1, lbl, pl_drop_s(l))      /* S --> N */
#define HA_RWLOCK_TRYSKLOCK(lbl,l)      _lock_cond(_LK_SK,  1, lbl, !pl_try_s(l))      /* N -?> S */
#define HA_RWLOCK_TRYRDTOSK(lbl,l)      _lock_cond(_LK_SK,  0, lbl, !pl_try_rtos(l))   /* R -?> S */
#define HA_RWLOCK_TRYRDTOWR(lbl, l)     _lock_cond(_LK_WR,  0, lbl, !pl_try_rtow(l))   /* R -?> W */

#else /* (DEBUG_THREAD < 2) && !defined(DEBUG_FULL) */

/* Thread debugging is ENABLED, these are the instrumented functions */

#define __SPIN_INIT(l)             ({ (*l) = 0; })
#define __SPIN_DESTROY(l)          ({ (*l) = 0; })
#define __SPIN_LOCK(l)             pl_take_s(l)
#define __SPIN_TRYLOCK(l)          (!pl_try_s(l))
#define __SPIN_UNLOCK(l)           pl_drop_s(l)

#define __RWLOCK_INIT(l)           ({ (*l) = 0; })
#define __RWLOCK_DESTROY(l)        ({ (*l) = 0; })
#define __RWLOCK_WRLOCK(l)         pl_take_w(l)
#define __RWLOCK_TRYWRLOCK(l)      (!pl_try_w(l))
#define __RWLOCK_WRUNLOCK(l)       pl_drop_w(l)
#define __RWLOCK_RDLOCK(l)         pl_take_r(l)
#define __RWLOCK_TRYRDLOCK(l)      (!pl_try_r(l))
#define __RWLOCK_RDUNLOCK(l)       pl_drop_r(l)

/* rwlock upgrades via seek locks */
#define __RWLOCK_SKLOCK(l)         pl_take_s(l)      /* N --> S */
#define __RWLOCK_SKTOWR(l)         pl_stow(l)        /* S --> W */
#define __RWLOCK_WRTOSK(l)         pl_wtos(l)        /* W --> S */
#define __RWLOCK_SKTORD(l)         pl_stor(l)        /* S --> R */
#define __RWLOCK_WRTORD(l)         pl_wtor(l)        /* W --> R */
#define __RWLOCK_SKUNLOCK(l)       pl_drop_s(l)      /* S --> N */
#define __RWLOCK_TRYSKLOCK(l)      (!pl_try_s(l))    /* N -?> S */
#define __RWLOCK_TRYRDTOSK(l)      (!pl_try_rtos(l)) /* R -?> S */
#define __RWLOCK_TRYRDTOWR(l)      (!pl_try_rtow(l)) /* R -?> W */

#define HA_SPIN_INIT(l)            __spin_init(l)
#define HA_SPIN_DESTROY(l)         __spin_destroy(l)

#define HA_SPIN_LOCK(lbl, l)       _lock_wait(_LK_SK,  1, lbl, __spin_lock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_SPIN_TRYLOCK(lbl, l)    _lock_cond(_LK_SK,  1, lbl, __spin_trylock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_SPIN_UNLOCK(lbl, l)     _lock_wait(_LK_UN, -1, lbl, __spin_unlock(lbl, l, __func__, __FILE__, __LINE__))

#define HA_RWLOCK_INIT(l)          __ha_rwlock_init((l))
#define HA_RWLOCK_DESTROY(l)       __ha_rwlock_destroy((l))
#define HA_RWLOCK_WRLOCK(lbl,l)    _lock_wait(_LK_WR,  1, lbl, __ha_rwlock_wrlock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_TRYWRLOCK(lbl,l) _lock_cond(_LK_WR,  1, lbl, __ha_rwlock_trywrlock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_WRUNLOCK(lbl,l)  _lock_wait(_LK_UN, -1, lbl, __ha_rwlock_wrunlock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_RDLOCK(lbl,l)    _lock_wait(_LK_RD,  1, lbl, __ha_rwlock_rdlock(lbl, l))
#define HA_RWLOCK_TRYRDLOCK(lbl,l) _lock_cond(_LK_RD,  1, lbl, __ha_rwlock_tryrdlock(lbl, l))
#define HA_RWLOCK_RDUNLOCK(lbl,l)  _lock_wait(_LK_UN, -1, lbl, __ha_rwlock_rdunlock(lbl, l))

#define HA_RWLOCK_SKLOCK(lbl,l)    _lock_wait(_LK_SK,  1, lbl, __ha_rwlock_sklock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_SKTOWR(lbl,l)    _lock_wait(_LK_WR,  0, lbl, __ha_rwlock_sktowr(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_WRTOSK(lbl,l)    _lock_wait(_LK_SK,  0, lbl, __ha_rwlock_wrtosk(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_SKTORD(lbl,l)    _lock_wait(_LK_RD,  0, lbl, __ha_rwlock_sktord(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_WRTORD(lbl,l)    _lock_wait(_LK_RD,  0, lbl, __ha_rwlock_wrtord(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_SKUNLOCK(lbl,l)  _lock_wait(_LK_UN, -1, lbl, __ha_rwlock_skunlock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_TRYSKLOCK(lbl,l) _lock_cond(_LK_SK,  1, lbl, __ha_rwlock_trysklock(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_TRYRDTOSK(lbl,l) _lock_cond(_LK_RD,  0, lbl, __ha_rwlock_tryrdtosk(lbl, l, __func__, __FILE__, __LINE__))
#define HA_RWLOCK_TRYRDTOWR(lbl,l) _lock_cond(_LK_WR,  0, lbl, __ha_rwlock_tryrdtowr(lbl, l, __func__, __FILE__, __LINE__))

/* Following functions are used to collect some stats about locks. We wrap
 * pthread functions to known how much time we wait in a lock. */

void show_lock_stats();
void __ha_rwlock_init(struct ha_rwlock *l);
void __ha_rwlock_destroy(struct ha_rwlock *l);
void __ha_rwlock_wrlock(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line);
int __ha_rwlock_trywrlock(enum lock_label lbl, struct ha_rwlock *l,
                          const char *func, const char *file, int line);
void __ha_rwlock_wrunlock(enum lock_label lbl,struct ha_rwlock *l,
                          const char *func, const char *file, int line);
void __ha_rwlock_rdlock(enum lock_label lbl,struct ha_rwlock *l);
int __ha_rwlock_tryrdlock(enum lock_label lbl,struct ha_rwlock *l);
void __ha_rwlock_rdunlock(enum lock_label lbl,struct ha_rwlock *l);
void __ha_rwlock_wrtord(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line);
void __ha_rwlock_wrtosk(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line);
void __ha_rwlock_sklock(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line);
void __ha_rwlock_sktowr(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line);
void __ha_rwlock_sktord(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line);
void __ha_rwlock_skunlock(enum lock_label lbl,struct ha_rwlock *l,
                          const char *func, const char *file, int line);
int __ha_rwlock_trysklock(enum lock_label lbl, struct ha_rwlock *l,
                          const char *func, const char *file, int line);
int __ha_rwlock_tryrdtosk(enum lock_label lbl, struct ha_rwlock *l,
                          const char *func, const char *file, int line);
int __ha_rwlock_tryrdtowr(enum lock_label lbl, struct ha_rwlock *l,
                          const char *func, const char *file, int line);
void __spin_init(struct ha_spinlock *l);
void __spin_destroy(struct ha_spinlock *l);
void __spin_lock(enum lock_label lbl, struct ha_spinlock *l,
                 const char *func, const char *file, int line);
int __spin_trylock(enum lock_label lbl, struct ha_spinlock *l,
                   const char *func, const char *file, int line);
void __spin_unlock(enum lock_label lbl, struct ha_spinlock *l,
                   const char *func, const char *file, int line);

#endif  /* DEBUG_THREAD */

#endif /* USE_THREAD */

#endif /* _HAPROXY_THREAD_H */
