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

#include <signal.h>
#include <unistd.h>
#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif

#ifdef USE_THREAD
#  include <pthread.h>
#endif

#ifdef USE_CPU_AFFINITY
#  include <sched.h>
#  if defined(__FreeBSD__) || defined(__DragonFly__)
#    include <sys/param.h>
#    ifdef __FreeBSD__
#      include <sys/cpuset.h>
#    endif
#    include <pthread_np.h>
#  endif
#  ifdef __APPLE__
#    include <mach/mach_types.h>
#    include <mach/thread_act.h>
#    include <mach/thread_policy.h>
#  endif
#  include <haproxy/cpuset.h>
#endif

#include <haproxy/cfgparse.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>

struct tgroup_info ha_tgroup_info[MAX_TGROUPS] = { };
THREAD_LOCAL const struct tgroup_info *tg = &ha_tgroup_info[0];

struct thread_info ha_thread_info[MAX_THREADS] = { };
THREAD_LOCAL const struct thread_info *ti = &ha_thread_info[0];

struct tgroup_ctx ha_tgroup_ctx[MAX_TGROUPS] = { };
THREAD_LOCAL struct tgroup_ctx *tg_ctx = &ha_tgroup_ctx[0];

struct thread_ctx ha_thread_ctx[MAX_THREADS] = { };
THREAD_LOCAL struct thread_ctx *th_ctx = &ha_thread_ctx[0];

#ifdef USE_THREAD

volatile unsigned long all_tgroups_mask __read_mostly  = 1; // nbtgroup 1 assumed by default
volatile unsigned int rdv_requests       = 0;  // total number of threads requesting RDV
volatile unsigned int isolated_thread    = ~0; // ID of the isolated thread, or ~0 when none
THREAD_LOCAL unsigned int  tgid          = 1; // thread ID starts at 1
THREAD_LOCAL unsigned int  tid           = 0;
int thread_cpus_enabled_at_boot          = 1;
static pthread_t ha_pthread[MAX_THREADS] = { };

/* Marks the thread as harmless until the last thread using the rendez-vous
 * point quits. Given that we can wait for a long time, sched_yield() is
 * used when available to offer the CPU resources to competing threads if
 * needed.
 */
void thread_harmless_till_end()
{
	_HA_ATOMIC_OR(&tg_ctx->threads_harmless, ti->ltid_bit);
	while (_HA_ATOMIC_LOAD(&rdv_requests) != 0) {
		ha_thread_relax();
	}
}

/* Isolates the current thread : request the ability to work while all other
 * threads are harmless, as defined by thread_harmless_now() (i.e. they're not
 * going to touch any visible memory area). Only returns once all of them are
 * harmless, with the current thread's bit in &tg_ctx->threads_harmless cleared.
 * Needs to be completed using thread_release().
 */
void thread_isolate()
{
	uint tgrp, thr;

	_HA_ATOMIC_OR(&tg_ctx->threads_harmless, ti->ltid_bit);
	__ha_barrier_atomic_store();
	_HA_ATOMIC_INC(&rdv_requests);

	/* wait for all threads to become harmless. They cannot change their
	 * mind once seen thanks to rdv_requests above, unless they pass in
	 * front of us. For this reason we proceed in 4 steps:
	 *   1) wait for all threads to declare themselves harmless
	 *   2) try to grab the isolated_thread exclusivity
	 *   3) verify again that all threads are harmless, since another one
	 *      that was isolating between 1 and 2 could have dropped its
	 *      harmless state there.
	 *   4) drop harmless flag (which also has the benefit of leaving
	 *      all other threads wait on reads instead of writes.
	 */
	while (1) {
		for (tgrp = 0; tgrp < global.nbtgroups; tgrp++) {
			do {
				ulong te = _HA_ATOMIC_LOAD(&ha_tgroup_info[tgrp].threads_enabled);
				ulong th = _HA_ATOMIC_LOAD(&ha_tgroup_ctx[tgrp].threads_harmless);

				if ((th & te) == te)
					break;
				ha_thread_relax();
			} while (1);
		}

		/* all other ones are harmless. isolated_thread will contain
		 * ~0U if no other one competes, !=tid if another one got it,
		 * tid if the current thread already grabbed it on the previous
		 * round.
		 */
		thr = _HA_ATOMIC_LOAD(&isolated_thread);
		if (thr == tid)
			break; // we won and we're certain everyone is harmless

		/* try to win the race against others */
		if (thr != ~0U || !_HA_ATOMIC_CAS(&isolated_thread, &thr, tid))
			ha_thread_relax();
	}

	/* the thread is no longer harmless as it runs */
	_HA_ATOMIC_AND(&tg_ctx->threads_harmless, ~ti->ltid_bit);

	/* the thread is isolated until it calls thread_release() which will
	 * 1) reset isolated_thread to ~0;
	 * 2) decrement rdv_requests.
	 */
}

/* Isolates the current thread : request the ability to work while all other
 * threads are idle, as defined by thread_idle_now(). It only returns once
 * all of them are both harmless and idle, with the current thread's bit in
 * &tg_ctx->threads_harmless and idle_mask cleared. Needs to be completed using
 * thread_release(). By doing so the thread also engages in being safe against
 * any actions that other threads might be about to start under the same
 * conditions. This specifically targets destruction of any internal structure,
 * which implies that the current thread may not hold references to any object.
 *
 * Note that a concurrent thread_isolate() will usually win against
 * thread_isolate_full() as it doesn't consider the idle_mask, allowing it to
 * get back to the poller or any other fully idle location, that will
 * ultimately release this one.
 */
void thread_isolate_full()
{
	uint tgrp, thr;

	_HA_ATOMIC_OR(&tg_ctx->threads_idle, ti->ltid_bit);
	_HA_ATOMIC_OR(&tg_ctx->threads_harmless, ti->ltid_bit);
	__ha_barrier_atomic_store();
	_HA_ATOMIC_INC(&rdv_requests);

	/* wait for all threads to become harmless. They cannot change their
	 * mind once seen thanks to rdv_requests above, unless they pass in
	 * front of us. For this reason we proceed in 4 steps:
	 *   1) wait for all threads to declare themselves harmless
	 *   2) try to grab the isolated_thread exclusivity
	 *   3) verify again that all threads are harmless, since another one
	 *      that was isolating between 1 and 2 could have dropped its
	 *      harmless state there.
	 *   4) drop harmless flag (which also has the benefit of leaving
	 *      all other threads wait on reads instead of writes.
	 */
	while (1) {
		for (tgrp = 0; tgrp < global.nbtgroups; tgrp++) {
			do {
				ulong te = _HA_ATOMIC_LOAD(&ha_tgroup_info[tgrp].threads_enabled);
				ulong th = _HA_ATOMIC_LOAD(&ha_tgroup_ctx[tgrp].threads_harmless);
				ulong id = _HA_ATOMIC_LOAD(&ha_tgroup_ctx[tgrp].threads_idle);

				if ((th & id & te) == te)
					break;
				ha_thread_relax();
			} while (1);
		}

		/* all other ones are harmless and idle. isolated_thread will
		 * contain ~0U if no other one competes, !=tid if another one
		 * got it, tid if the current thread already grabbed it on the
		 * previous round.
		 */
		thr = _HA_ATOMIC_LOAD(&isolated_thread);
		if (thr == tid)
			break; // we won and we're certain everyone is harmless

		if (thr != ~0U || !_HA_ATOMIC_CAS(&isolated_thread, &thr, tid))
			ha_thread_relax();
	}

	/* we're not idle nor harmless anymore at this point. Other threads
	 * waiting on this condition will need to wait until out next pass to
	 * the poller, or our next call to thread_isolate_full().
	 */
	_HA_ATOMIC_AND(&tg_ctx->threads_idle, ~ti->ltid_bit);
	_HA_ATOMIC_AND(&tg_ctx->threads_harmless, ~ti->ltid_bit);

	/* the thread is isolated until it calls thread_release() which will
	 * 1) reset isolated_thread to ~0;
	 * 2) decrement rdv_requests.
	 */
}

/* Cancels the effect of thread_isolate() by resetting the ID of the isolated
 * thread and decrementing the number of RDV requesters. This immediately allows
 * other threads to expect to be executed, though they will first have to wait
 * for this thread to become harmless again (possibly by reaching the poller
 * again).
 */
void thread_release()
{
	HA_ATOMIC_STORE(&isolated_thread, ~0U);
	HA_ATOMIC_DEC(&rdv_requests);
}

/* Sets up threads, signals and masks, and starts threads 2 and above.
 * Does nothing when threads are disabled.
 */
void setup_extra_threads(void *(*handler)(void *))
{
	sigset_t blocked_sig, old_sig;
	int i;

	/* ensure the signals will be blocked in every thread */
	sigfillset(&blocked_sig);
	sigdelset(&blocked_sig, SIGPROF);
	sigdelset(&blocked_sig, SIGBUS);
	sigdelset(&blocked_sig, SIGFPE);
	sigdelset(&blocked_sig, SIGILL);
	sigdelset(&blocked_sig, SIGSEGV);
	pthread_sigmask(SIG_SETMASK, &blocked_sig, &old_sig);

	/* Create nbthread-1 thread. The first thread is the current process */
	ha_pthread[0] = pthread_self();
	for (i = 1; i < global.nbthread; i++)
		pthread_create(&ha_pthread[i], NULL, handler, &ha_thread_info[i]);
}

/* waits for all threads to terminate. Does nothing when threads are
 * disabled.
 */
void wait_for_threads_completion()
{
	int i;

	/* Wait the end of other threads */
	for (i = 1; i < global.nbthread; i++)
		pthread_join(ha_pthread[i], NULL);

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
	show_lock_stats();
#endif
}

/* Tries to set the current thread's CPU affinity according to the cpu_map */
void set_thread_cpu_affinity()
{
#if defined(USE_CPU_AFFINITY)
	/* no affinity setting for the master process */
	if (master)
		return;

	/* Now the CPU affinity for all threads */
	if (ha_cpuset_count(&cpu_map[tgid - 1].thread[ti->ltid])) {/* only do this if the thread has a THREAD map */
#  if defined(__APPLE__)
		/* Note: this API is limited to the first 32/64 CPUs */
		unsigned long set = cpu_map[tgid - 1].thread[ti->ltid].cpuset;
		int j;

		while ((j = ffsl(set)) > 0) {
			thread_affinity_policy_data_t cpu_set = { j - 1 };
			thread_port_t mthread;

			mthread = pthread_mach_thread_np(ha_pthread[tid]);
			thread_policy_set(mthread, THREAD_AFFINITY_POLICY, (thread_policy_t)&cpu_set, 1);
			set &= ~(1UL << (j - 1));
		}
#  else
		struct hap_cpuset *set = &cpu_map[tgid - 1].thread[ti->ltid];

		pthread_setaffinity_np(ha_pthread[tid], sizeof(set->cpuset), &set->cpuset);
#  endif
	}
#endif /* USE_CPU_AFFINITY */
}

/* Retrieves the opaque pthread_t of thread <thr> cast to an unsigned long long
 * since POSIX took great care of not specifying its representation, making it
 * hard to export for post-mortem analysis. For this reason we copy it into a
 * union and will use the smallest scalar type at least as large as its size,
 * which will keep endianness and alignment for all regular sizes. As a last
 * resort we end up with a long long ligned to the first bytes in memory, which
 * will be endian-dependent if pthread_t is larger than a long long (not seen
 * yet).
 */
unsigned long long ha_get_pthread_id(unsigned int thr)
{
	union {
		pthread_t t;
		unsigned long long ll;
		unsigned int i;
		unsigned short s;
		unsigned char c;
	} u = { 0 };

	u.t = ha_pthread[thr];

	if (sizeof(u.t) <= sizeof(u.c))
		return u.c;
	else if (sizeof(u.t) <= sizeof(u.s))
		return u.s;
	else if (sizeof(u.t) <= sizeof(u.i))
		return u.i;
	return u.ll;
}

/* send signal <sig> to thread <thr> */
void ha_tkill(unsigned int thr, int sig)
{
	pthread_kill(ha_pthread[thr], sig);
}

/* send signal <sig> to all threads. The calling thread is signaled last in
 * order to allow all threads to synchronize in the handler.
 */
void ha_tkillall(int sig)
{
	unsigned int thr;

	for (thr = 0; thr < global.nbthread; thr++) {
		if (!(ha_thread_info[thr].tg->threads_enabled & ha_thread_info[thr].ltid_bit))
			continue;
		if (thr == tid)
			continue;
		pthread_kill(ha_pthread[thr], sig);
	}
	raise(sig);
}

void ha_thread_relax(void)
{
#ifdef _POSIX_PRIORITY_SCHEDULING
	sched_yield();
#else
	pl_cpu_relax();
#endif
}

/* these calls are used as callbacks at init time when debugging is on */
void ha_spin_init(HA_SPINLOCK_T *l)
{
	HA_SPIN_INIT(l);
}

/* these calls are used as callbacks at init time when debugging is on */
void ha_rwlock_init(HA_RWLOCK_T *l)
{
	HA_RWLOCK_INIT(l);
}

/* returns the number of CPUs the current process is enabled to run on,
 * regardless of any MAX_THREADS limitation.
 */
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
#elif defined(__APPLE__)
	ret = (int)sysconf(_SC_NPROCESSORS_ONLN);
#endif
#endif
	ret = MAX(ret, 1);
	return ret;
}

/* Returns 1 if the cpu set is currently restricted for the process else 0.
 * Currently only implemented for the Linux platform.
 */
int thread_cpu_mask_forced()
{
#if defined(__linux__)
	const int cpus_avail = sysconf(_SC_NPROCESSORS_ONLN);
	return cpus_avail != thread_cpus_enabled();
#else
	return 0;
#endif
}

/* Below come the lock-debugging functions */

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)

struct lock_stat lock_stats[LOCK_LABELS];

/* this is only used below */
static const char *lock_label(enum lock_label label)
{
	switch (label) {
	case TASK_RQ_LOCK:         return "TASK_RQ";
	case TASK_WQ_LOCK:         return "TASK_WQ";
	case LISTENER_LOCK:        return "LISTENER";
	case PROXY_LOCK:           return "PROXY";
	case SERVER_LOCK:          return "SERVER";
	case LBPRM_LOCK:           return "LBPRM";
	case SIGNALS_LOCK:         return "SIGNALS";
	case STK_TABLE_LOCK:       return "STK_TABLE";
	case STK_SESS_LOCK:        return "STK_SESS";
	case APPLETS_LOCK:         return "APPLETS";
	case PEER_LOCK:            return "PEER";
	case SHCTX_LOCK:           return "SHCTX";
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
	case RING_LOCK:            return "RING";
	case DICT_LOCK:            return "DICT";
	case PROTO_LOCK:           return "PROTO";
	case QUEUE_LOCK:           return "QUEUE";
	case CKCH_LOCK:            return "CKCH";
	case SNI_LOCK:             return "SNI";
	case SSL_SERVER_LOCK:      return "SSL_SERVER";
	case SFT_LOCK:             return "SFT";
	case IDLE_CONNS_LOCK:      return "IDLE_CONNS";
	case OCSP_LOCK:            return "OCSP";
	case QC_CID_LOCK:          return "QC_CID";
	case CACHE_LOCK:           return "CACHE";
	case GUID_LOCK:            return "GUID";
	case OTHER_LOCK:           return "OTHER";
	case DEBUG1_LOCK:          return "DEBUG1";
	case DEBUG2_LOCK:          return "DEBUG2";
	case DEBUG3_LOCK:          return "DEBUG3";
	case DEBUG4_LOCK:          return "DEBUG4";
	case DEBUG5_LOCK:          return "DEBUG5";
	case LOCK_LABELS:          break; /* keep compiler happy */
	};
	/* only way to come here is consecutive to an internal bug */
	abort();
}

void show_lock_stats()
{
	int lbl;

	for (lbl = 0; lbl < LOCK_LABELS; lbl++) {
		if (!lock_stats[lbl].num_write_locked &&
		    !lock_stats[lbl].num_seek_locked &&
		    !lock_stats[lbl].num_read_locked) {
			fprintf(stderr,
			        "Stats about Lock %s: not used\n",
			        lock_label(lbl));
			continue;
		}

		fprintf(stderr,
			"Stats about Lock %s: \n",
			lock_label(lbl));

		if (lock_stats[lbl].num_write_locked)
			fprintf(stderr,
			        "\t # write lock  : %llu\n"
			        "\t # write unlock: %llu (%lld)\n"
			        "\t # wait time for write     : %.3f msec\n"
			        "\t # wait time for write/lock: %.3f nsec\n",
			        (ullong)lock_stats[lbl].num_write_locked,
			        (ullong)lock_stats[lbl].num_write_unlocked,
			        (llong)(lock_stats[lbl].num_write_unlocked - lock_stats[lbl].num_write_locked),
			        (double)lock_stats[lbl].nsec_wait_for_write / 1000000.0,
			        lock_stats[lbl].num_write_locked ? ((double)lock_stats[lbl].nsec_wait_for_write / (double)lock_stats[lbl].num_write_locked) : 0);

		if (lock_stats[lbl].num_seek_locked)
			fprintf(stderr,
			        "\t # seek lock   : %llu\n"
			        "\t # seek unlock : %llu (%lld)\n"
			        "\t # wait time for seek      : %.3f msec\n"
			        "\t # wait time for seek/lock : %.3f nsec\n",
			        (ullong)lock_stats[lbl].num_seek_locked,
			        (ullong)lock_stats[lbl].num_seek_unlocked,
			        (llong)(lock_stats[lbl].num_seek_unlocked - lock_stats[lbl].num_seek_locked),
			        (double)lock_stats[lbl].nsec_wait_for_seek / 1000000.0,
			        lock_stats[lbl].num_seek_locked ? ((double)lock_stats[lbl].nsec_wait_for_seek / (double)lock_stats[lbl].num_seek_locked) : 0);

		if (lock_stats[lbl].num_read_locked)
			fprintf(stderr,
			        "\t # read lock   : %llu\n"
			        "\t # read unlock : %llu (%lld)\n"
			        "\t # wait time for read      : %.3f msec\n"
			        "\t # wait time for read/lock : %.3f nsec\n",
			        (ullong)lock_stats[lbl].num_read_locked,
			        (ullong)lock_stats[lbl].num_read_unlocked,
			        (llong)(lock_stats[lbl].num_read_unlocked - lock_stats[lbl].num_read_locked),
			        (double)lock_stats[lbl].nsec_wait_for_read / 1000000.0,
			        lock_stats[lbl].num_read_locked ? ((double)lock_stats[lbl].nsec_wait_for_read / (double)lock_stats[lbl].num_read_locked) : 0);
	}
}

void __ha_rwlock_init(struct ha_rwlock *l)
{
	memset(l, 0, sizeof(struct ha_rwlock));
	__RWLOCK_INIT(&l->lock);
}

void __ha_rwlock_destroy(struct ha_rwlock *l)
{
	__RWLOCK_DESTROY(&l->lock);
	memset(l, 0, sizeof(struct ha_rwlock));
}


void __ha_rwlock_wrlock(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if ((st->cur_readers | st->cur_seeker | st->cur_writer) & tbit)
		abort();

	HA_ATOMIC_OR(&st->wait_writers, tbit);

	start_time = now_mono_time();
	__RWLOCK_WRLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_write, (now_mono_time() - start_time));

	HA_ATOMIC_INC(&lock_stats[lbl].num_write_locked);

	st->cur_writer                 = tbit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->wait_writers, ~tbit);
}

int __ha_rwlock_trywrlock(enum lock_label lbl, struct ha_rwlock *l,
                          const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;
	int r;

	if ((st->cur_readers | st->cur_seeker | st->cur_writer) & tbit)
		abort();

	/* We set waiting writer because trywrlock could wait for readers to quit */
	HA_ATOMIC_OR(&st->wait_writers, tbit);

	start_time = now_mono_time();
	r = __RWLOCK_TRYWRLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_write, (now_mono_time() - start_time));
	if (unlikely(r)) {
		HA_ATOMIC_AND(&st->wait_writers, ~tbit);
		return r;
	}
	HA_ATOMIC_INC(&lock_stats[lbl].num_write_locked);

	st->cur_writer                 = tbit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->wait_writers, ~tbit);

	return 0;
}

void __ha_rwlock_wrunlock(enum lock_label lbl,struct ha_rwlock *l,
                          const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];

	if (unlikely(!(st->cur_writer & tbit))) {
		/* the thread is not owning the lock for write */
		abort();
	}

	st->cur_writer                 = 0;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	__RWLOCK_WRUNLOCK(&l->lock);

	HA_ATOMIC_INC(&lock_stats[lbl].num_write_unlocked);
}

void __ha_rwlock_rdlock(enum lock_label lbl,struct ha_rwlock *l)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if ((st->cur_readers | st->cur_seeker | st->cur_writer) & tbit)
		abort();

	HA_ATOMIC_OR(&st->wait_readers, tbit);

	start_time = now_mono_time();
	__RWLOCK_RDLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_read, (now_mono_time() - start_time));
	HA_ATOMIC_INC(&lock_stats[lbl].num_read_locked);

	HA_ATOMIC_OR(&st->cur_readers, tbit);

	HA_ATOMIC_AND(&st->wait_readers, ~tbit);
}

int __ha_rwlock_tryrdlock(enum lock_label lbl,struct ha_rwlock *l)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	int r;

	if ((st->cur_readers | st->cur_seeker | st->cur_writer) & tbit)
		abort();

	/* try read should never wait */
	r = __RWLOCK_TRYRDLOCK(&l->lock);
	if (unlikely(r))
		return r;
	HA_ATOMIC_INC(&lock_stats[lbl].num_read_locked);

	HA_ATOMIC_OR(&st->cur_readers, tbit);

	return 0;
}

void __ha_rwlock_rdunlock(enum lock_label lbl,struct ha_rwlock *l)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];

	if (unlikely(!(st->cur_readers & tbit))) {
		/* the thread is not owning the lock for read */
		abort();
	}

	HA_ATOMIC_AND(&st->cur_readers, ~tbit);

	__RWLOCK_RDUNLOCK(&l->lock);

	HA_ATOMIC_INC(&lock_stats[lbl].num_read_unlocked);
}

void __ha_rwlock_wrtord(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if ((st->cur_readers | st->cur_seeker) & tbit)
		abort();

	if (!(st->cur_writer & tbit))
		abort();

	HA_ATOMIC_OR(&st->wait_readers, tbit);

	start_time = now_mono_time();
	__RWLOCK_WRTORD(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_read, (now_mono_time() - start_time));

	HA_ATOMIC_INC(&lock_stats[lbl].num_read_locked);

	HA_ATOMIC_OR(&st->cur_readers, tbit);
	HA_ATOMIC_AND(&st->cur_writer, ~tbit);
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->wait_readers, ~tbit);
}

void __ha_rwlock_wrtosk(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if ((st->cur_readers | st->cur_seeker) & tbit)
		abort();

	if (!(st->cur_writer & tbit))
		abort();

	HA_ATOMIC_OR(&st->wait_seekers, tbit);

	start_time = now_mono_time();
	__RWLOCK_WRTOSK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_seek, (now_mono_time() - start_time));

	HA_ATOMIC_INC(&lock_stats[lbl].num_seek_locked);

	HA_ATOMIC_OR(&st->cur_seeker, tbit);
	HA_ATOMIC_AND(&st->cur_writer, ~tbit);
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->wait_seekers, ~tbit);
}

void __ha_rwlock_sklock(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if ((st->cur_readers | st->cur_seeker | st->cur_writer) & tbit)
		abort();

	HA_ATOMIC_OR(&st->wait_seekers, tbit);

	start_time = now_mono_time();
	__RWLOCK_SKLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_seek, (now_mono_time() - start_time));

	HA_ATOMIC_INC(&lock_stats[lbl].num_seek_locked);

	HA_ATOMIC_OR(&st->cur_seeker, tbit);
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->wait_seekers, ~tbit);
}

void __ha_rwlock_sktowr(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if ((st->cur_readers | st->cur_writer) & tbit)
		abort();

	if (!(st->cur_seeker & tbit))
		abort();

	HA_ATOMIC_OR(&st->wait_writers, tbit);

	start_time = now_mono_time();
	__RWLOCK_SKTOWR(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_write, (now_mono_time() - start_time));

	HA_ATOMIC_INC(&lock_stats[lbl].num_write_locked);

	HA_ATOMIC_OR(&st->cur_writer, tbit);
	HA_ATOMIC_AND(&st->cur_seeker, ~tbit);
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->wait_writers, ~tbit);
}

void __ha_rwlock_sktord(enum lock_label lbl, struct ha_rwlock *l,
                        const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if ((st->cur_readers | st->cur_writer) & tbit)
		abort();

	if (!(st->cur_seeker & tbit))
		abort();

	HA_ATOMIC_OR(&st->wait_readers, tbit);

	start_time = now_mono_time();
	__RWLOCK_SKTORD(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_read, (now_mono_time() - start_time));

	HA_ATOMIC_INC(&lock_stats[lbl].num_read_locked);

	HA_ATOMIC_OR(&st->cur_readers, tbit);
	HA_ATOMIC_AND(&st->cur_seeker, ~tbit);
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->wait_readers, ~tbit);
}

void __ha_rwlock_skunlock(enum lock_label lbl,struct ha_rwlock *l,
                          const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	if (!(st->cur_seeker & tbit))
		abort();

	HA_ATOMIC_AND(&st->cur_seeker, ~tbit);
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	__RWLOCK_SKUNLOCK(&l->lock);

	HA_ATOMIC_INC(&lock_stats[lbl].num_seek_unlocked);
}

int __ha_rwlock_trysklock(enum lock_label lbl, struct ha_rwlock *l,
                          const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;
	int r;

	if ((st->cur_readers | st->cur_seeker | st->cur_writer) & tbit)
		abort();

	HA_ATOMIC_OR(&st->wait_seekers, tbit);

	start_time = now_mono_time();
	r = __RWLOCK_TRYSKLOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_seek, (now_mono_time() - start_time));

	if (likely(!r)) {
		/* got the lock ! */
		HA_ATOMIC_INC(&lock_stats[lbl].num_seek_locked);
		HA_ATOMIC_OR(&st->cur_seeker, tbit);
		l->info.last_location.function = func;
		l->info.last_location.file     = file;
		l->info.last_location.line     = line;
	}

	HA_ATOMIC_AND(&st->wait_seekers, ~tbit);
	return r;
}

int __ha_rwlock_tryrdtosk(enum lock_label lbl, struct ha_rwlock *l,
                          const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_rwlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;
	int r;

	if ((st->cur_writer | st->cur_seeker) & tbit)
		abort();

	if (!(st->cur_readers & tbit))
		abort();

	HA_ATOMIC_OR(&st->wait_seekers, tbit);

	start_time = now_mono_time();
	r = __RWLOCK_TRYRDTOSK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_seek, (now_mono_time() - start_time));

	if (likely(!r)) {
		/* got the lock ! */
		HA_ATOMIC_INC(&lock_stats[lbl].num_seek_locked);
		HA_ATOMIC_OR(&st->cur_seeker, tbit);
		HA_ATOMIC_AND(&st->cur_readers, ~tbit);
		l->info.last_location.function = func;
		l->info.last_location.file     = file;
		l->info.last_location.line     = line;
	}

	HA_ATOMIC_AND(&st->wait_seekers, ~tbit);
	return r;
}

void __spin_init(struct ha_spinlock *l)
{
	memset(l, 0, sizeof(struct ha_spinlock));
	__SPIN_INIT(&l->lock);
}

void __spin_destroy(struct ha_spinlock *l)
{
	__SPIN_DESTROY(&l->lock);
	memset(l, 0, sizeof(struct ha_spinlock));
}

void __spin_lock(enum lock_label lbl, struct ha_spinlock *l,
                 const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_spinlock_state *st = &l->info.st[tgid-1];
	uint64_t start_time;

	if (unlikely(st->owner & tbit)) {
		/* the thread is already owning the lock */
		abort();
	}

	HA_ATOMIC_OR(&st->waiters, tbit);

	start_time = now_mono_time();
	__SPIN_LOCK(&l->lock);
	HA_ATOMIC_ADD(&lock_stats[lbl].nsec_wait_for_write, (now_mono_time() - start_time));

	HA_ATOMIC_INC(&lock_stats[lbl].num_write_locked);


	st->owner                  = tbit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	HA_ATOMIC_AND(&st->waiters, ~tbit);
}

int __spin_trylock(enum lock_label lbl, struct ha_spinlock *l,
                   const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_spinlock_state *st = &l->info.st[tgid-1];
	int r;

	if (unlikely(st->owner & tbit)) {
		/* the thread is already owning the lock */
		abort();
	}

	/* try read should never wait */
	r = __SPIN_TRYLOCK(&l->lock);
	if (unlikely(r))
		return r;
	HA_ATOMIC_INC(&lock_stats[lbl].num_write_locked);

	st->owner                      = tbit;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	return 0;
}

void __spin_unlock(enum lock_label lbl, struct ha_spinlock *l,
                   const char *func, const char *file, int line)
{
	ulong tbit = (ti && ti->ltid_bit) ? ti->ltid_bit : 1;
	struct ha_spinlock_state *st = &l->info.st[tgid-1];

	if (unlikely(!(st->owner & tbit))) {
		/* the thread is not owning the lock */
		abort();
	}

	st->owner                      = 0;
	l->info.last_location.function = func;
	l->info.last_location.file     = file;
	l->info.last_location.line     = line;

	__SPIN_UNLOCK(&l->lock);
	HA_ATOMIC_INC(&lock_stats[lbl].num_write_unlocked);
}

#endif // defined(DEBUG_THREAD) || defined(DEBUG_FULL)


#if defined(USE_PTHREAD_EMULATION)

/* pthread rwlock emulation using plocks (to avoid expensive futexes).
 * these are a direct mapping on Progressive Locks, with the exception that
 * since there's a common unlock operation in pthreads, we need to know if
 * we need to unlock for reads or writes, so we set the topmost bit to 1 when
 * a write lock is acquired to indicate that a write unlock needs to be
 * performed. It's not a problem since this bit will never be used given that
 * haproxy won't support as many threads as the plocks.
 *
 * The storage is the pthread_rwlock_t cast as an ulong
 */

int pthread_rwlock_init(pthread_rwlock_t *restrict rwlock, const pthread_rwlockattr_t *restrict attr)
{
	ulong *lock = (ulong *)rwlock;

	*lock = 0;
	return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock)
{
	ulong *lock = (ulong *)rwlock;

	*lock = 0;
	return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock)
{
	pl_lorw_rdlock((unsigned long *)rwlock);
	return 0;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock)
{
	return !!pl_cmpxchg((unsigned long *)rwlock, 0, PLOCK_LORW_SHR_BASE);
}

int pthread_rwlock_timedrdlock(pthread_rwlock_t *restrict rwlock, const struct timespec *restrict abstime)
{
	return pthread_rwlock_tryrdlock(rwlock);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock)
{
	pl_lorw_wrlock((unsigned long *)rwlock);
	return 0;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock)
{
	return !!pl_cmpxchg((unsigned long *)rwlock, 0, PLOCK_LORW_EXC_BASE);
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *restrict rwlock, const struct timespec *restrict abstime)
{
	return pthread_rwlock_trywrlock(rwlock);
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock)
{
	pl_lorw_unlock((unsigned long *)rwlock);
	return 0;
}
#endif // defined(USE_PTHREAD_EMULATION)

/* Depending on the platform and how libpthread was built, pthread_exit() may
 * involve some code in libgcc_s that would be loaded on exit for the first
 * time, causing aborts if the process is chrooted. It's harmless bit very
 * dirty. There isn't much we can do to make sure libgcc_s is loaded only if
 * needed, so what we do here is that during early boot we create a dummy
 * thread that immediately exits. This will lead to libgcc_s being loaded
 * during boot on the platforms where it's required.
 */
static void *dummy_thread_function(void *data)
{
	pthread_exit(NULL);
	return NULL;
}

static inline void preload_libgcc_s(void)
{
	pthread_t dummy_thread;
	if (pthread_create(&dummy_thread, NULL, dummy_thread_function, NULL) == 0)
		pthread_join(dummy_thread, NULL);
}

static void __thread_init(void)
{
	char *ptr = NULL;

	preload_libgcc_s();

	thread_cpus_enabled_at_boot = thread_cpus_enabled();
	thread_cpus_enabled_at_boot = MIN(thread_cpus_enabled_at_boot, MAX_THREADS);

	memprintf(&ptr, "Built with multi-threading support (MAX_TGROUPS=%d, MAX_THREADS=%d, default=%d).",
		  MAX_TGROUPS, MAX_THREADS, thread_cpus_enabled_at_boot);
	hap_register_build_opts(ptr, 1);

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
	memset(lock_stats, 0, sizeof(lock_stats));
#endif
}
INITCALL0(STG_PREPARE, __thread_init);

#else

/* send signal <sig> to thread <thr> (send to process in fact) */
void ha_tkill(unsigned int thr, int sig)
{
	raise(sig);
}

/* send signal <sig> to all threads (send to process in fact) */
void ha_tkillall(int sig)
{
	raise(sig);
}

void ha_thread_relax(void)
{
#ifdef _POSIX_PRIORITY_SCHEDULING
	sched_yield();
#endif
}

REGISTER_BUILD_OPTS("Built without multi-threading support (USE_THREAD not set).");

#endif // USE_THREAD


/* Returns non-zero on anomaly (bound vs unbound), and emits a warning in this
 * case.
 */
int thread_detect_binding_discrepancies(void)
{
#if defined(USE_CPU_AFFINITY)
	uint th, tg, id;
	uint tot_b = 0, tot_u = 0;
	int first_b = -1;
	int first_u = -1;

	for (th = 0; th < global.nbthread; th++) {
		tg = ha_thread_info[th].tgid;
		id = ha_thread_info[th].ltid;

		if (ha_cpuset_count(&cpu_map[tg - 1].thread[id]) == 0) {
			tot_u++;
			if (first_u < 0)
				first_u = th;
		} else {
			tot_b++;
			if (first_b < 0)
				first_b = th;
		}
	}

	if (tot_u > 0 && tot_b > 0) {
		ha_warning("Found %u thread(s) mapped to a CPU and %u thread(s) not mapped to any CPU. "
			   "This will result in some threads being randomly assigned to the same CPU, "
			   "which will occasionally cause severe performance degradation. First thread "
			   "bound is %d and first thread not bound is %d. Please either bind all threads "
			   "or none (maybe some cpu-map directives are missing?).\n",
			   tot_b, tot_u, first_b, first_u);
		return 1;
	}
#endif
	return 0;
}

/* Returns non-zero on anomaly (more threads than CPUs), and emits a warning in
 * this case. It checks against configured cpu-map if any, otherwise against
 * the number of CPUs at boot if known. It's better to run it only after
 * thread_detect_binding_discrepancies() so that mixed cases can be eliminated.
 */
int thread_detect_more_than_cpus(void)
{
#if defined(USE_CPU_AFFINITY)
	struct hap_cpuset cpuset_map, cpuset_boot, cpuset_all;
	uint th, tg, id;
	int bound;
	int tot_map, tot_all;

	ha_cpuset_zero(&cpuset_boot);
	ha_cpuset_zero(&cpuset_map);
	ha_cpuset_zero(&cpuset_all);
	bound = 0;
	for (th = 0; th < global.nbthread; th++) {
		tg = ha_thread_info[th].tgid;
		id = ha_thread_info[th].ltid;
		if (ha_cpuset_count(&cpu_map[tg - 1].thread[id])) {
			ha_cpuset_or(&cpuset_map, &cpu_map[tg - 1].thread[id]);
			bound++;
		}
	}

	ha_cpuset_assign(&cpuset_all, &cpuset_map);
	if (bound != global.nbthread) {
		if (ha_cpuset_detect_bound(&cpuset_boot))
			ha_cpuset_or(&cpuset_all, &cpuset_boot);
	}

	tot_map = ha_cpuset_count(&cpuset_map);
	tot_all = ha_cpuset_count(&cpuset_all);

	if (tot_map && bound > tot_map) {
		ha_warning("This configuration binds %d threads to a total of %d CPUs via cpu-map "
			   "directives. This means that some threads will compete for the same CPU, "
			   "which will cause severe performance degradation. Please fix either the "
			   "'cpu-map' directives or set the global 'nbthread' value accordingly.\n",
			   bound, tot_map);
		return 1;
	}
	else if (tot_all && global.nbthread > tot_all) {
		ha_warning("This configuration enables %d threads running on a total of %d CPUs. "
			   "This means that some threads will compete for the same CPU, which will cause "
			   "severe performance degradation. Please either the 'cpu-map' directives to "
			   "adjust the CPUs to use, or fix the global 'nbthread' value.\n",
			   global.nbthread, tot_all);
		return 1;
	}
#endif
	return 0;
}


/* scans the configured thread mapping and establishes the final one. Returns <0
 * on failure, >=0 on success.
 */
int thread_map_to_groups()
{
	int t, g, ut, ug;
	int q, r;
	ulong m __maybe_unused;

	ut = ug = 0; // unassigned threads & groups

	for (t = 0; t < global.nbthread; t++) {
		if (!ha_thread_info[t].tg)
			ut++;
	}

	for (g = 0; g < global.nbtgroups; g++) {
		if (!ha_tgroup_info[g].count)
			ug++;
		ha_tgroup_info[g].tgid_bit = 1UL << g;
	}

	if (ug > ut) {
		ha_alert("More unassigned thread-groups (%d) than threads (%d). Please reduce thread-groups\n", ug, ut);
		return -1;
	}

	/* look for first unassigned thread */
	for (t = 0; t < global.nbthread && ha_thread_info[t].tg; t++)
		;

	/* assign threads to empty groups */
	for (g = 0; ug && ut; ) {
		/* due to sparse thread assignment we can end up with more threads
		 * per group on last assigned groups than former ones, so we must
		 * always try to pack the maximum remaining ones together first.
		 */
		q = ut / ug;
		r = ut % ug;
		if ((q + !!r) > MAX_THREADS_PER_GROUP) {
			ha_alert("Too many remaining unassigned threads (%d) for thread groups (%d). Please increase thread-groups or make sure to keep thread numbers contiguous\n", ut, ug);
			return -1;
		}

		/* thread <t> is the next unassigned one. Let's look for next
		 * unassigned group, we know there are some left
		 */
		while (ut >= ug && ha_tgroup_info[g].count)
			g++;

		/* group g is unassigned, try to fill it with consecutive threads */
		while (ut && ut >= ug && ha_tgroup_info[g].count < q + !!r &&
		       (!ha_tgroup_info[g].count || t == ha_tgroup_info[g].base + ha_tgroup_info[g].count)) {

			if (!ha_tgroup_info[g].count) {
				/* assign new group */
				ha_tgroup_info[g].base = t;
				ug--;
			}

			ha_tgroup_info[g].count++;
			ha_thread_info[t].tgid = g + 1;
			ha_thread_info[t].tg = &ha_tgroup_info[g];
			ha_thread_info[t].tg_ctx = &ha_tgroup_ctx[g];

			ut--;
			/* switch to next unassigned thread */
			while (++t < global.nbthread && ha_thread_info[t].tg)
				;
		}
	}

	if (ut) {
		ha_alert("Remaining unassigned threads found (%d) because all groups are in use. Please increase 'thread-groups', reduce 'nbthreads' or remove or extend 'thread-group' enumerations.\n", ut);
		return -1;
	}

	for (t = 0; t < global.nbthread; t++) {
		ha_thread_info[t].tid      = t;
		ha_thread_info[t].ltid     = t - ha_thread_info[t].tg->base;
		ha_thread_info[t].ltid_bit = 1UL << ha_thread_info[t].ltid;
	}

	m = 0;
	for (g = 0; g < global.nbtgroups; g++) {
		ha_tgroup_info[g].threads_enabled = nbits(ha_tgroup_info[g].count);
		/* for now, additional threads are not started, so we should
		 * consider them as harmless and idle.
		 * This will get automatically updated when such threads are
		 * started in run_thread_poll_loop()
		 * Without this, thread_isolate() and thread_isolate_full()
		 * will fail to work as long as secondary threads did not enter
		 * the polling loop at least once.
		 */
		ha_tgroup_ctx[g].threads_harmless = ha_tgroup_info[g].threads_enabled;
		ha_tgroup_ctx[g].threads_idle = ha_tgroup_info[g].threads_enabled;
		if (!ha_tgroup_info[g].count)
			continue;
		m |= 1UL << g;

	}

#ifdef USE_THREAD
	all_tgroups_mask = m;
#endif
	return 0;
}

/* Converts a configuration thread set based on either absolute or relative
 * thread numbers into a global group+mask. This is essentially for use with
 * the "thread" directive on "bind" lines, where "thread 4-6,10-12" might be
 * turned to "2/1-3,4/1-3". It cannot be used before the thread mapping above
 * was completed and the thread group numbers configured. The thread_set is
 * replaced by the resolved group-based one. It is possible to force a single
 * default group for unspecified sets instead of enabling all groups by passing
 * this group's non-zero value to defgrp.
 *
 * Returns <0 on failure, >=0 on success.
 */
int thread_resolve_group_mask(struct thread_set *ts, int defgrp, char **err)
{
	struct thread_set new_ts = { };
	ulong mask, imask;
	uint g;

	if (!ts->grps) {
		/* unspecified group, IDs are global */
		if (thread_set_is_empty(ts)) {
			/* all threads of all groups, unless defgrp is set and
			 * we then set it as the only group.
			 */
			for (g = defgrp ? defgrp-1 : 0; g < (defgrp ? defgrp : global.nbtgroups); g++) {
				new_ts.rel[g] = ha_tgroup_info[g].threads_enabled;
				if (new_ts.rel[g])
					new_ts.grps |= 1UL << g;
			}
		} else {
			/* some absolute threads are set, we must remap them to
			 * relative ones. Each group cannot have more than
			 * LONGBITS threads, thus it spans at most two absolute
			 * blocks.
			 */
			for (g = 0; g < global.nbtgroups; g++) {
				uint block = ha_tgroup_info[g].base / LONGBITS;
				uint base  = ha_tgroup_info[g].base % LONGBITS;

				mask = ts->abs[block] >> base;
				if (base &&
				    (block + 1) < sizeof(ts->abs) / sizeof(ts->abs[0]) &&
				    ha_tgroup_info[g].count > (LONGBITS - base))
					mask |= ts->abs[block + 1] << (LONGBITS - base);
				mask &= nbits(ha_tgroup_info[g].count);
				mask &= ha_tgroup_info[g].threads_enabled;

				/* now the mask exactly matches the threads to be enabled
				 * in this group.
				 */
				new_ts.rel[g] |= mask;
				if (new_ts.rel[g])
					new_ts.grps |= 1UL << g;
			}
		}
	} else {
		/* groups were specified */
		for (g = 0; g < MAX_TGROUPS; g++) {
			imask = ts->rel[g];
			if (!imask)
				continue;

			if (g >= global.nbtgroups) {
				memprintf(err, "'thread' directive references non-existing thread group %u", g+1);
				return -1;
			}

			/* some relative threads are set. Keep only existing ones for this group */
			mask = nbits(ha_tgroup_info[g].count);

			if (!(mask & imask)) {
				/* no intersection between the thread group's
				 * threads and the bind line's.
				 */
#ifdef THREAD_AUTO_ADJUST_GROUPS
				unsigned long new_mask = 0;

				while (imask) {
					new_mask |= imask & mask;
					imask >>= ha_tgroup_info[g].count;
				}
				imask = new_mask;
#else
				memprintf(err, "'thread' directive only references threads not belonging to group %u", g+1);
				return -1;
#endif
			}

			new_ts.rel[g] = imask & mask;
			if (new_ts.rel[g])
				new_ts.grps |= 1UL << g;
		}
	}

	/* update the thread_set */
	if (!thread_set_nth_group(&new_ts, 0)) {
		memprintf(err, "'thread' directive only references non-existing threads");
		return -1;
	}

	*ts = new_ts;
	return 0;
}

/* Parse a string representing a thread set in one of the following forms:
 *
 * - { "all" | "odd" | "even" | <abs_num> [ "-" <abs_num> ] }[,...]
 *   => these are (lists of) absolute thread numbers
 *
 * - <tgnum> "/" { "all" | "odd" | "even" | <rel_num> [ "-" <rel_num> ][,...]
 *   => these are (lists of) per-group relative thread numbers. All numbers
 *      must be lower than or equal to LONGBITS. When multiple list elements
 *      are provided, each of them must contain the thread group number.
 *
 * Minimum value for a thread or group number is always 1. Maximum value for an
 * absolute thread number is MAX_THREADS, maximum value for a relative thread
 * number is MAX_THREADS_PER_GROUP, an maximum value for a thread group is
 * MAX_TGROUPS. "all", "even" and "odd" will be bound by MAX_THREADS and/or
 * MAX_THREADS_PER_GROUP in any case. In ranges, a missing digit before "-"
 * is implicitly 1, and a missing digit after "-" is implicitly the highest of
 * its class. As such "-" is equivalent to "all", allowing to build strings
 * such as "${MIN}-${MAX}" where both MIN and MAX are optional.
 *
 * It is not valid to mix absolute and relative numbers. As such:
 * - all               valid (all absolute threads)
 * - 12-19,24-31       valid (abs threads 12 to 19 and 24 to 31)
 * - 1/all             valid (all 32 or 64 threads of group 1)
 * - 1/1-4,1/8-10,2/1  valid
 * - 1/1-4,8-10        invalid (mixes relatve "1/1-4" with absolute "8-10")
 * - 1-4,8-10,2/1      invalid (mixes absolute "1-4,8-10" with relative "2/1")
 * - 1/odd-4           invalid (mixes range with boundary)
 *
 * The target thread set is *completed* with supported threads, which means
 * that it's the caller's responsibility for pre-initializing it. If the target
 * thread set is NULL, it's not updated and the function only verifies that the
 * input parses.
 *
 * On success, it returns 0. otherwise it returns non-zero with an error
 * message in <err>.
 */
int parse_thread_set(const char *arg, struct thread_set *ts, char **err)
{
	const char *set;
	const char *sep;
	int v, min, max, tg;
	int is_rel;

	/* search for the first delimiter (',', '-' or '/') to decide whether
	 * we're facing an absolute or relative form. The relative form always
	 * starts with a number followed by a slash.
	 */
	for (sep = arg; isdigit((uchar)*sep); sep++)
		;

	is_rel = (/*sep > arg &&*/ *sep == '/'); /* relative form */

	/* from there we have to cut the thread spec around commas */

	set = arg;
	tg = 0;
	while (*set) {
		/* note: we can't use strtol() here because "-3" would parse as
		 * (-3) while we want to stop before the "-", so we find the
		 * separator ourselves and rely on atoi() whose value we may
		 * ignore depending where the separator is.
		 */
		for (sep = set; isdigit((uchar)*sep); sep++)
			;

		if (sep != set && *sep && *sep != '/' && *sep != '-' && *sep != ',') {
			memprintf(err, "invalid character '%c' in thread set specification: '%s'.", *sep, set);
			return -1;
		}

		v = (sep != set) ? atoi(set) : 0;

		/* Now we know that the string is made of an optional series of digits
		 * optionally followed by one of the delimiters above, or that it
		 * starts with a different character.
		 */

		/* first, let's search for the thread group (digits before '/') */

		if (tg || !is_rel) {
			/* thread group already specified or not expected if absolute spec */
			if (*sep == '/') {
				if (tg)
					memprintf(err, "redundant thread group specification '%s' for group %d", set, tg);
				else
					memprintf(err, "group-relative thread specification '%s' is not permitted after a absolute thread range.", set);
				return -1;
			}
		} else {
			/* this is a group-relative spec, first field is the group number */
			if (sep == set && *sep == '/') {
				memprintf(err, "thread group number expected before '%s'.", set);
				return -1;
			}

			if (*sep != '/') {
				memprintf(err, "absolute thread specification '%s' is not permitted after a group-relative thread range.", set);
				return -1;
			}

			if (v < 1 || v > MAX_TGROUPS) {
				memprintf(err, "invalid thread group number '%d', permitted range is 1..%d in '%s'.", v, MAX_TGROUPS, set);
				return -1;
			}

			tg = v;

			/* skip group number and go on with set,sep,v as if
			 * there was no group number.
			 */
			set = sep + 1;
			continue;
		}

		/* Now 'set' starts at the min thread number, whose value is in v if any,
		 * and preset the max to it, unless the range is filled at once via "all"
		 * (stored as 1:0), "odd" (stored as) 1:-1, or "even" (stored as 1:-2).
		 * 'sep' points to the next non-digit which may be set itself e.g. for
		 * "all" etc or "-xx".
		 */

		if (!*set) {
			/* empty set sets no restriction */
			min = 1;
			max = is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS;
		}
		else {
			if (sep != set && *sep && *sep != '-' && *sep != ',') {
				// Only delimiters are permitted around digits.
				memprintf(err, "invalid character '%c' in thread set specification: '%s'.", *sep, set);
				return -1;
			}

			/* for non-digits, find next delim */
			for (; *sep && *sep != '-' && *sep != ','; sep++)
				;

			min = max = 1;
			if (sep != set) {
				/* non-empty first thread */
				if (isteq(ist2(set, sep-set), ist("all")))
					max = 0;
				else if (isteq(ist2(set, sep-set), ist("odd")))
					max = -1;
				else if (isteq(ist2(set, sep-set), ist("even")))
					max = -2;
				else if (v)
					min = max = v;
				else
					max = min = 0; // throw an error below
			}

			if (min < 1 || min > MAX_THREADS || (is_rel && min > MAX_THREADS_PER_GROUP)) {
				memprintf(err, "invalid first thread number '%s', permitted range is 1..%d, or 'all', 'odd', 'even'.",
					  set, is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS);
				return -1;
			}

			/* is this a range ? */
			if (*sep == '-') {
				if (min != max) {
					memprintf(err, "extraneous range after 'all', 'odd' or 'even': '%s'.", set);
					return -1;
				}

				/* this is a seemingly valid range, there may be another number  */
				for (set = ++sep; isdigit((uchar)*sep); sep++)
					;
				v = atoi(set);

				if (sep == set) { // no digit: to the max
					max = is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS;
					if (*sep && *sep != ',')
						max = 0; // throw an error below
				} else
					max = v;

				if (max < 1 || max > MAX_THREADS || (is_rel && max > MAX_THREADS_PER_GROUP)) {
					memprintf(err, "invalid last thread number '%s', permitted range is 1..%d.",
						  set, is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS);
					return -1;
				}
			}

			/* here sep points to the first non-digit after the thread spec,
			 * must be a valid delimiter.
			 */
			if (*sep && *sep != ',') {
				memprintf(err, "invalid character '%c' after thread set specification: '%s'.", *sep, set);
				return -1;
			}
		}

		/* store values */
		if (ts) {
			if (is_rel) {
				/* group-relative thread numbers */
				ts->grps |= 1UL << (tg - 1);

				if (max >= min) {
					for (v = min; v <= max; v++)
						ts->rel[tg - 1] |= 1UL << (v - 1);
				} else {
					memset(&ts->rel[tg - 1],
					       (max == 0) ? 0xff /* all */ : (max == -1) ? 0x55 /* odd */: 0xaa /* even */,
					       sizeof(ts->rel[tg - 1]));
				}
			} else {
				/* absolute thread numbers */
				if (max >= min) {
					for (v = min; v <= max; v++)
						ts->abs[(v - 1) / LONGBITS] |= 1UL << ((v - 1) % LONGBITS);
				} else {
					memset(&ts->abs,
					       (max == 0) ? 0xff /* all */ : (max == -1) ? 0x55 /* odd */: 0xaa /* even */,
					       sizeof(ts->abs));
				}
			}
		}

		set = *sep ? sep + 1 : sep;
		tg = 0;
	}
	return 0;
}

/* Parse the "nbthread" global directive, which takes an integer argument that
 * contains the desired number of threads.
 */
static int cfg_parse_nbthread(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	long nbthread;
	char *errptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (non_global_section_parsed == 1) {
		memprintf(err, "'%s' not allowed if a non-global section was previously defined. This parameter must be declared in the first global section", args[0]);
		return -1;
	}

	nbthread = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

#ifndef USE_THREAD
	if (nbthread != 1) {
		memprintf(err, "'%s' specified with a value other than 1 while HAProxy is not compiled with threads support. Please check build options for USE_THREAD", args[0]);
		return -1;
	}
#else
	if (nbthread < 1 || nbthread > MAX_THREADS) {
		memprintf(err, "'%s' value must be between 1 and %d (was %ld)", args[0], MAX_THREADS, nbthread);
		return -1;
	}
#endif

	HA_DIAG_WARNING_COND(global.nbthread,
	                     "parsing [%s:%d] : '%s' is already defined and will be overridden.\n",
	                     file, line, args[0]);

	global.nbthread = nbthread;
	return 0;
}

/* Parse the "thread-hard-limit" global directive, which takes an integer
 * argument that contains the desired maximum number of threads that will
 * not be crossed.
 */
static int cfg_parse_thread_hard_limit(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	long nbthread;
	char *errptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	nbthread = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

	if (nbthread < 1 || nbthread > MAX_THREADS) {
		memprintf(err, "'%s' value must be at least 1 (was %ld)", args[0], nbthread);
		return -1;
	}

	global.thread_limit = nbthread;
	return 0;
}

/* Parse the "thread-group" global directive, which takes an integer argument
 * that designates a thread group, and a list of threads to put into that group.
 */
static int cfg_parse_thread_group(char **args, int section_type, struct proxy *curpx,
                                  const struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	char *errptr;
	long tnum, tend, tgroup;
	int arg, tot;

	if (non_global_section_parsed == 1) {
		memprintf(err, "'%s' not allowed if a non-global section was previously defined. This parameter must be declared in the first global section", args[0]);
		return -1;
	}

	tgroup = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

	if (tgroup < 1 || tgroup > MAX_TGROUPS) {
		memprintf(err, "'%s' thread-group number must be between 1 and %d (was %ld)", args[0], MAX_TGROUPS, tgroup);
		return -1;
	}

	/* look for a preliminary definition of any thread pointing to this
	 * group, and remove them.
	 */
	if (ha_tgroup_info[tgroup-1].count) {
		ha_warning("parsing [%s:%d] : '%s %ld' was already defined and will be overridden.\n",
		           file, line, args[0], tgroup);

		for (tnum = ha_tgroup_info[tgroup-1].base;
		     tnum < ha_tgroup_info[tgroup-1].base + ha_tgroup_info[tgroup-1].count;
		     tnum++) {
			if (ha_thread_info[tnum-1].tg == &ha_tgroup_info[tgroup-1]) {
				ha_thread_info[tnum-1].tg = NULL;
				ha_thread_info[tnum-1].tgid = 0;
				ha_thread_info[tnum-1].tg_ctx = NULL;
			}
		}
		ha_tgroup_info[tgroup-1].count = ha_tgroup_info[tgroup-1].base = 0;
	}

	tot = 0;
	for (arg = 2; args[arg] && *args[arg]; arg++) {
		tend = tnum = strtol(args[arg], &errptr, 10);

		if (*errptr == '-')
			tend = strtol(errptr + 1, &errptr, 10);

		if (*errptr || tnum < 1 || tend < 1 || tnum > MAX_THREADS || tend > MAX_THREADS) {
			memprintf(err, "'%s %ld' passed an unparsable or invalid thread number '%s' (valid range is 1 to %d)", args[0], tgroup, args[arg], MAX_THREADS);
			return -1;
		}

		for(; tnum <= tend; tnum++) {
			if (ha_thread_info[tnum-1].tg == &ha_tgroup_info[tgroup-1]) {
				ha_warning("parsing [%s:%d] : '%s %ld': thread %ld assigned more than once on the same line.\n",
				           file, line, args[0], tgroup, tnum);
			} else if (ha_thread_info[tnum-1].tg) {
				ha_warning("parsing [%s:%d] : '%s %ld': thread %ld was previously assigned to thread group %ld and will be overridden.\n",
				           file, line, args[0], tgroup, tnum,
				           (long)(ha_thread_info[tnum-1].tg - &ha_tgroup_info[0] + 1));
			}

			if (!ha_tgroup_info[tgroup-1].count) {
				ha_tgroup_info[tgroup-1].base = tnum-1;
				ha_tgroup_info[tgroup-1].count = 1;
			}
			else if (tnum >= ha_tgroup_info[tgroup-1].base + ha_tgroup_info[tgroup-1].count) {
				ha_tgroup_info[tgroup-1].count = tnum - ha_tgroup_info[tgroup-1].base;
			}
			else if (tnum < ha_tgroup_info[tgroup-1].base) {
				ha_tgroup_info[tgroup-1].count += ha_tgroup_info[tgroup-1].base - tnum-1;
				ha_tgroup_info[tgroup-1].base = tnum - 1;
			}

			ha_thread_info[tnum-1].tgid = tgroup;
			ha_thread_info[tnum-1].tg = &ha_tgroup_info[tgroup-1];
			ha_thread_info[tnum-1].tg_ctx = &ha_tgroup_ctx[tgroup-1];
			tot++;
		}
	}

	if (ha_tgroup_info[tgroup-1].count > tot) {
		memprintf(err, "'%s %ld' assigned sparse threads, only contiguous supported", args[0], tgroup);
		return -1;
	}

	if (ha_tgroup_info[tgroup-1].count > MAX_THREADS_PER_GROUP) {
		memprintf(err, "'%s %ld' assigned too many threads (%d, max=%d)", args[0], tgroup, tot, MAX_THREADS_PER_GROUP);
		return -1;
	}

	return 0;
}

/* Parse the "thread-groups" global directive, which takes an integer argument
 * that contains the desired number of thread groups.
 */
static int cfg_parse_thread_groups(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	long nbtgroups;
	char *errptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (non_global_section_parsed == 1) {
		memprintf(err, "'%s' not allowed if a non-global section was previously defined. This parameter must be declared in the first global section", args[0]);
		return -1;
	}

	nbtgroups = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

#ifndef USE_THREAD
	if (nbtgroups != 1) {
		memprintf(err, "'%s' specified with a value other than 1 while HAProxy is not compiled with threads support. Please check build options for USE_THREAD", args[0]);
		return -1;
	}
#else
	if (nbtgroups < 1 || nbtgroups > MAX_TGROUPS) {
		memprintf(err, "'%s' value must be between 1 and %d (was %ld)", args[0], MAX_TGROUPS, nbtgroups);
		return -1;
	}
#endif

	HA_DIAG_WARNING_COND(global.nbtgroups,
	                     "parsing [%s:%d] : '%s' is already defined and will be overridden.\n",
	                     file, line, args[0]);

	global.nbtgroups = nbtgroups;
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "thread-hard-limit", cfg_parse_thread_hard_limit, 0 },
	{ CFG_GLOBAL, "nbthread",       cfg_parse_nbthread, 0 },
	{ CFG_GLOBAL, "thread-group",   cfg_parse_thread_group, 0 },
	{ CFG_GLOBAL, "thread-groups",  cfg_parse_thread_groups, 0 },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
