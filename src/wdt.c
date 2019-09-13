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

#include <common/config.h>
#include <common/debug.h>
#include <common/hathreads.h>
#include <common/initcall.h>
#include <common/standard.h>
#include <types/global.h>
#include <proto/log.h>


/*
 * It relies on timer_create() and timer_settime() which are only available in
 * this case.
 */
#if defined(USE_THREAD) && defined(USE_RT) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)

/* We'll deliver SIGALRM when we've run out of CPU as it's not intercepted by
 * gdb by default.
 */
#define WDTSIG SIGALRM

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
	return timer_settime(ha_thread_info[thr].wd_timer, 0, &its, NULL) == 0;
}

/* This is the WDTSIG signal handler */
void wdt_handler(int sig, siginfo_t *si, void *arg)
{
	unsigned long long n, p;
	int thr;

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

		p = ha_thread_info[thr].prev_cpu_time;
		n = now_cpu_time_thread(&ha_thread_info[thr]);

		/* not yet reached the deadline of 1 sec */
		if (n - p < 1000000000UL)
			goto update_and_leave;

		if ((threads_harmless_mask|sleeping_thread_mask|threads_to_dump) & (1UL << thr)) {
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
		 * scheduler is still alive by setting the TI_FL_STUCK flag
		 * that the scheduler clears when switching to the next task.
		 * If it's already set, then it's our second call with no
		 * progress and the thread is dead.
		 */
		if (!(ha_thread_info[thr].flags & TI_FL_STUCK)) {
			_HA_ATOMIC_OR(&ha_thread_info[thr].flags, TI_FL_STUCK);
			goto update_and_leave;
		}

		/* No doubt now, there's no hop to recover, die loudly! */
		break;

	case SI_TKILL:
		/* we got a pthread_kill, stop on it */
		thr = tid;
		break;

	default:
		/* unhandled other conditions */
		return;
	}

	/* By default we terminate. If we're not on the victim thread, better
	 * bounce the signal there so that we produce a cleaner stack trace
	 * with the other thread interrupted exactly where it was running and
	 * the current one not involved in this.
	 */
	if (thr != tid)
		pthread_kill(ha_thread_info[thr].pthread, sig);
	else
		ha_panic();
	return;

 update_and_leave:
	wdt_ping(thr);
}

int init_wdt_per_thread()
{
	struct sigevent sev;
	sigset_t set;

	/* unblock the WDTSIG signal we intend to use */
	sigemptyset(&set);
	sigaddset(&set, WDTSIG);
	ha_sigmask(SIG_UNBLOCK, &set, NULL);

	/* this timer will signal WDTSIG when it fires, with tid in the si_int
	 * field (important since any thread will receive the signal).
	 */
	sev.sigev_notify          = SIGEV_SIGNAL;
	sev.sigev_signo           = WDTSIG;
	sev.sigev_value.sival_int = tid;
	if (timer_create(ti->clock_id, &sev, &ti->wd_timer) == -1)
		goto fail1;

	if (!wdt_ping(tid))
		goto fail2;

	return 1;

 fail2:
	timer_delete(ti->wd_timer);
 fail1:
	ti->wd_timer = TIMER_INVALID;
	ha_warning("Failed to setup watchdog timer for thread %u, disabling lockup detection.\n", tid);
	return 0;
}

void deinit_wdt_per_thread()
{
	if (ti->wd_timer != TIMER_INVALID)
		timer_delete(ti->wd_timer);
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
	return 0;
}

REGISTER_POST_CHECK(init_wdt);
REGISTER_PER_THREAD_INIT(init_wdt_per_thread);
REGISTER_PER_THREAD_DEINIT(deinit_wdt_per_thread);
#endif
