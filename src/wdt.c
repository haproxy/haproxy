/*
 * Thread lockup detection
 *
 * Copyright 2000-2019 Willy Tarreau <willy@haproxy.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <signal.h>
#include <time.h>

#include <haproxy/api.h>
#include <haproxy/clock.h>
#include <haproxy/debug.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/signal-t.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>


/*
 * It relies on timer_create() and timer_settime() which are only available in
 * this case.
 */
#if defined(USE_RT) && defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)

/* define a dummy value to designate "no timer". Use only 32 bits. */
#ifndef TIMER_INVALID
#define TIMER_INVALID ((timer_t)(unsigned long)(0xfffffffful))
#endif

static timer_t per_thread_wd_timer[MAX_THREADS];

/* Setup (or ping) the watchdog timer for thread <thr>. Returns non-zero on
 * success, zero on failure. It interrupts once per second of CPU time. It
 * happens that timers based on the CPU time are not automatically re-armed
 * so we only use the value and leave the interval unset.
 */
int wdt_ping(int thr)
{
	struct itimerspec its;

	its.it_value.tv_sec    = 1; its.it_value.tv_nsec    = 0;
	its.it_interval.tv_sec = 0; its.it_interval.tv_nsec = 0;
	return timer_settime(per_thread_wd_timer[thr], 0, &its, NULL) == 0;
}

/* This is the WDTSIG signal handler */
void wdt_handler(int sig, siginfo_t *si, void *arg)
{
	unsigned long long n, p;
	ulong thr_bit;
	int thr, tgrp;

	switch (si->si_code) {
	case SI_TIMER:
		/* A thread's timer fired, the thread ID is in si_int. We have
		 * no guarantee that the thread handling this signal is in any
		 * way related to the one triggering it, so we need to retrieve
		 * the thread number from there. Note: this thread might
		 * continue to execute in parallel.
		 */
		thr = si->si_value.sival_int;

		/* cannot happen unless an unknown timer tries to play with our
		 * nerves. Let's die for now if this happens.
		 */
		if (thr < 0 || thr >= global.nbthread)
			break;

		tgrp = ha_thread_info[thr].tgid;
		thr_bit = ha_thread_info[thr].ltid_bit;
		p = ha_thread_ctx[thr].prev_cpu_time;
		n = now_cpu_time_thread(thr);

		/* not yet reached the deadline of 1 sec,
		 * or p wasn't initialized yet
		 */
		if (!p || n - p < 1000000000UL)
			goto update_and_leave;

		if ((_HA_ATOMIC_LOAD(&ha_thread_ctx[thr].flags) & TH_FL_SLEEPING) ||
		    (_HA_ATOMIC_LOAD(&ha_tgroup_ctx[tgrp-1].threads_harmless) & thr_bit)) {
			/* This thread is currently doing exactly nothing
			 * waiting in the poll loop (unlikely but possible),
			 * waiting for all other threads to join the rendez-vous
			 * point (common), or waiting for another thread to
			 * finish an isolated operation (unlikely but possible).
			 */
			goto update_and_leave;
		}

		/* So the thread indeed appears locked up. In order to be
		 * certain that we're not witnessing an exceptional spike of
		 * CPU usage due to a configuration issue (like running tens
		 * of thousands of tasks in a single loop), we'll check if the
		 * scheduler is still alive by setting the TH_FL_STUCK flag
		 * that the scheduler clears when switching to the next task.
		 * If it's already set, then it's our second call with no
		 * progress and the thread is dead.
		 */
		if (!(_HA_ATOMIC_LOAD(&ha_thread_ctx[thr].flags) & TH_FL_STUCK)) {
			_HA_ATOMIC_OR(&ha_thread_ctx[thr].flags, TH_FL_STUCK);
			goto update_and_leave;
		}

		/* No doubt now, there's no hop to recover, die loudly! */
		break;

#if defined(USE_THREAD) && defined(SI_TKILL) /* Linux uses this */

	case SI_TKILL:
		/* we got a pthread_kill, stop on it */
		thr = tid;
		break;

#elif defined(USE_THREAD) && defined(SI_LWP) /* FreeBSD uses this */

	case SI_LWP:
		/* we got a pthread_kill, stop on it */
		thr = tid;
		break;

#endif
	default:
		/* unhandled other conditions */
		return;
	}

	/* By default we terminate. If we're not on the victim thread, better
	 * bounce the signal there so that we produce a cleaner stack trace
	 * with the other thread interrupted exactly where it was running and
	 * the current one not involved in this.
	 */
#ifdef USE_THREAD
	if (thr != tid)
		ha_tkill(thr, sig);
	else
#endif
		ha_panic();
	return;

 update_and_leave:
	wdt_ping(thr);
}

int init_wdt_per_thread()
{
	if (!clock_setup_signal_timer(&per_thread_wd_timer[tid], WDTSIG, tid))
		goto fail1;

	if (!wdt_ping(tid))
		goto fail2;

	return 1;

 fail2:
	timer_delete(per_thread_wd_timer[tid]);
 fail1:
	per_thread_wd_timer[tid] = TIMER_INVALID;
	ha_warning("Failed to setup watchdog timer for thread %u, disabling lockup detection.\n", tid);
	return 1;
}

void deinit_wdt_per_thread()
{
	if (per_thread_wd_timer[tid] != TIMER_INVALID)
		timer_delete(per_thread_wd_timer[tid]);
}

/* registers the watchdog signal handler and returns 0. This sets up the signal
 * handler for WDTSIG, so it must be called once per process.
 */
int init_wdt()
{
	struct sigaction sa;

	sa.sa_handler = NULL;
	sa.sa_sigaction = wdt_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(WDTSIG, &sa, NULL);
	return ERR_NONE;
}

REGISTER_POST_CHECK(init_wdt);
REGISTER_PER_THREAD_INIT(init_wdt_per_thread);
REGISTER_PER_THREAD_DEINIT(deinit_wdt_per_thread);
#endif
