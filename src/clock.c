/*
 * General time-keeping code and variables
 *
 * Copyright 2000-2021 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/time.h>
#include <signal.h>
#include <time.h>

#ifdef USE_THREAD
#include <pthread.h>
#endif

#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/clock.h>
#include <haproxy/signal-t.h>
#include <haproxy/time.h>
#include <haproxy/tinfo-t.h>
#include <haproxy/tools.h>

struct timeval                   start_date;      /* the process's start date in wall-clock time */
struct timeval                   ready_date;      /* date when the process was considered ready */
ullong                           start_time_ns;   /* the process's start date in internal monotonic time (ns) */
volatile ullong                  global_now_ns;   /* common monotonic date between all threads, in ns (wraps every 585 yr) */
volatile uint                    global_now_ms;   /* common monotonic date in milliseconds (may wrap) */

/* when CLOCK_MONOTONIC is supported, the offset is applied from th_ctx->prev_mono_time instead */
THREAD_ALIGNED(64) static llong  now_offset;      /* global offset between system time and global time in ns */

THREAD_LOCAL ullong              now_ns;          /* internal monotonic date derived from real clock, in ns (wraps every 585 yr) */
THREAD_LOCAL uint                now_ms;          /* internal monotonic date in milliseconds (may wrap) */
THREAD_LOCAL struct timeval      date;            /* the real current date (wall-clock time) */

static THREAD_LOCAL ullong  before_poll_mono_ns;  /* system wide monotonic time when entering poll last */
static THREAD_LOCAL struct timeval before_poll;   /* system date before calling poll() */
static THREAD_LOCAL struct timeval after_poll;    /* system date after leaving poll() */
static THREAD_LOCAL unsigned int samp_time;       /* total elapsed time over current sample */
static THREAD_LOCAL unsigned int idle_time;       /* total idle time over current sample */
static THREAD_LOCAL unsigned int iso_time_sec;     /* last iso time value for this thread */
static THREAD_LOCAL char         iso_time_str[34]; /* ISO time representation of gettimeofday() */

#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)
static clockid_t per_thread_clock_id[MAX_THREADS];
#endif

/* returns the system's monotonic time in nanoseconds if supported, otherwise zero */
uint64_t now_mono_time(void)
{
	uint64_t ret = 0;
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_MONOTONIC_CLOCK)
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		ret = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
	return ret;
}

/* Returns the system's monotonic time in nanoseconds.
 * Uses the coarse clock source if supported (for fast but
 * less precise queries with limited resource usage).
 * Fallback to now_mono_time() if coarse source is not supported,
 * which may itself return 0 if not supported either.
 */
uint64_t now_mono_time_fast(void)
{
#if defined(CLOCK_MONOTONIC_COARSE)
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) == 0)
		return (ts.tv_sec * 1000000000ULL + ts.tv_nsec);
#endif
	/* fallback to regular mono time,
	 * returns 0 if not supported
	 */
	return now_mono_time();
}

/* returns the current thread's cumulated CPU time in nanoseconds if supported, otherwise zero */
uint64_t now_cpu_time(void)
{
	uint64_t ret = 0;
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)
	struct timespec ts;
	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) == 0)
		ret = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
	return ret;
}

/* Returns the current thread's cumulated CPU time in nanoseconds.
 *
 * thread_local timer is cached so that call is less precise but also less
 * expensive if heavily used.
 * We use the mono time as a cache expiration hint since now_cpu_time() is
 * known to be much more expensive than now_mono_time_fast() on systems
 * supporting the COARSE clock source.
 *
 * Returns 0 if either now_mono_time_fast() or now_cpu_time() are not
 * supported.
 */
uint64_t now_cpu_time_fast(void)
{
	static THREAD_LOCAL uint64_t mono_cache = 0;
	static THREAD_LOCAL uint64_t cpu_cache = 0;
	uint64_t mono_cur;

	mono_cur = now_mono_time_fast();
	if (unlikely(mono_cur !=  mono_cache)) {
		/* global mono clock was updated: local cache is outdated */
		cpu_cache = now_cpu_time();
		mono_cache = mono_cur;
	}
	return cpu_cache;
}

/* returns another thread's cumulated CPU time in nanoseconds if supported, otherwise zero */
uint64_t now_cpu_time_thread(int thr)
{
	uint64_t ret = 0;
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)
	struct timespec ts;
	if (clock_gettime(per_thread_clock_id[thr], &ts) == 0)
		ret = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
	return ret;
}

/* set the clock source for the local thread */
void clock_set_local_source(void)
{
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME) && (_POSIX_THREAD_CPUTIME >= 0)
#ifdef USE_THREAD
	pthread_getcpuclockid(pthread_self(), &per_thread_clock_id[tid]);
#else
	per_thread_clock_id[tid] = CLOCK_THREAD_CPUTIME_ID;
#endif
#endif
}

/* registers a timer <tmr> of type timer_t delivering signal <sig> with value
 * <val>. It tries on the current thread's clock ID first and falls back to
 * CLOCK_REALTIME. Returns non-zero on success, 1 on failure.
 */
int clock_setup_signal_timer(void *tmr, int sig, int val)
{
	int ret = 0;

#if defined(USE_RT) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)
	struct sigevent sev = { };
	timer_t *timer = tmr;
	sigset_t set;

	/* unblock the WDTSIG signal we intend to use */
	sigemptyset(&set);
	sigaddset(&set, WDTSIG);
	ha_sigmask(SIG_UNBLOCK, &set, NULL);

	/* this timer will signal WDTSIG when it fires, with tid in the si_int
	 * field (important since any thread will receive the signal).
	 */
	sev.sigev_notify          = SIGEV_SIGNAL;
	sev.sigev_signo           = sig;
	sev.sigev_value.sival_int = val;
	if (timer_create(per_thread_clock_id[tid], &sev, timer) != -1 ||
	    timer_create(CLOCK_REALTIME, &sev, timer) != -1)
		ret = 1;
#endif
	return ret;
}

/* clock_update_date: sets <date> to system time, and sets <now_ns> to something
 * as close as possible to real time, following a monotonic function. The main
 * principle consists in detecting backwards and forwards time jumps and adjust
 * an offset to correct them. This function should be called once after each
 * poll, and never farther apart than MAX_DELAY_MS*2. The poll's timeout should
 * be passed in <max_wait>, and the return value in <interrupted> (a non-zero
 * value means that we have not expired the timeout).
 *
 * clock_init_process_date() must have been called once first, and
 * clock_init_thread_date() must also have been called once for each thread.
 *
 * An offset is used to adjust the current time (date), to figure a monotonic
 * local time (now_ns). The offset is not critical, as it is only updated after
 * a clock jump is detected. From this point all threads will apply it to their
 * locally measured time, and will then agree around a common monotonic
 * global_now_ns value that serves to further refine their local time. Both
 * now_ns and global_now_ns are 64-bit integers counting nanoseconds since a
 * vague reference (it starts roughly 20s before the next wrap-around of the
 * millisecond counter after boot). The offset is also an integral number of
 * nanoseconds, but it's signed so that the clock can be adjusted in the two
 * directions.
 */
void clock_update_local_date(int max_wait, int interrupted)
{
	struct timeval min_deadline, max_deadline;
	llong ofs = HA_ATOMIC_LOAD(&now_offset);
	llong date_ns;

	gettimeofday(&date, NULL);
	th_ctx->curr_mono_time = now_mono_time();

	date_ns = th_ctx->curr_mono_time;
	if (date_ns) {
		/* no need to go through complex calculations, we have
		 * monotonic time. The offset will never change.
		 */
		goto done;
	}

	/* compute the minimum and maximum local date we may have reached based
	 * on our past date and the associated timeout. There are three possible
	 * extremities:
	 *    - the new date cannot be older than before_poll
	 *    - if not interrupted, the new date cannot be older than
	 *      before_poll+max_wait
	 *    - in any case the new date cannot be newer than
	 *      before_poll+max_wait+some margin (100ms used here).
	 * In case of violation, we'll ignore the current date and instead
	 * restart from the last date we knew.
	 */
	_tv_ms_add(&min_deadline, &before_poll, max_wait);
	_tv_ms_add(&max_deadline, &before_poll, max_wait + 100);
	date_ns = tv_to_ns(&date);

	if (unlikely(__tv_islt(&date, &before_poll)                    || // big jump backwards
		     (!interrupted && __tv_islt(&date, &min_deadline)) || // small jump backwards
		     date_ns + ofs >= now_ns + ms_to_ns(max_wait + 100)|| // offset changed by another thread
		     __tv_islt(&max_deadline, &date))) {                  // big jump forwards
		if (!interrupted)
			now_ns += ms_to_ns(max_wait);

		/* consider the most recent known date */
		now_ns = MAX(now_ns, HA_ATOMIC_LOAD(&global_now_ns));

		/* this event is rare, but it requires proper handling because if
		 * we just left now_ns where it was, the date will not be updated
		 * by clock_update_global_date().
		 */
		HA_ATOMIC_STORE(&now_offset, now_ns - date_ns);
	} else {
	done:
		/* The date is still within expectations. Let's apply the
		 * now_offset to the system date. Note: ofs if made of two
		 * independent signed ints.
		 */
		now_ns = date_ns + ofs;
	}
	now_ms = ns_to_ms(now_ns);

	/* correct for TICK_ETNERITY (0) */
	if (unlikely(now_ms == TICK_ETERNITY))
		now_ms++;
}

void clock_update_global_date()
{
	ullong old_now_ns;
	uint old_now_ms;

	/* now that we have bounded the local time, let's check if it's
	 * realistic regarding the global date, which only moves forward,
	 * otherwise catch up.
	 */
	old_now_ns = _HA_ATOMIC_LOAD(&global_now_ns);
	old_now_ms = global_now_ms;

	do {
		if (now_ns < old_now_ns)
			now_ns = old_now_ns;

		/* now <now_ns> is expected to be the most accurate date,
		 * equal to <global_now_ns> or newer. Updating the global
		 * date too often causes extreme contention and is not
		 * needed: it's only used to help threads run at the
		 * same date in case of local drift, and the global date,
		 * which changes, is only used by freq counters (a choice
		 * which is debatable by the way since it changes under us).
		 * Tests have seen that the contention can be reduced from
		 * 37% in this function to almost 0% when keeping clocks
		 * synchronized no better than 32 microseconds, so that's
		 * what we're doing here.
		 */
		now_ms = ns_to_ms(now_ns);
		/* correct for TICK_ETNERITY (0) */
		if (unlikely(now_ms == TICK_ETERNITY))
			now_ms++;

		if (!((now_ns ^ old_now_ns) & ~0x7FFFULL))
			return;

		/* let's try to update the global_now_ns (both in nanoseconds
		 * and ms forms) or loop again.
		 */
	} while ((!_HA_ATOMIC_CAS(&global_now_ns, &old_now_ns, now_ns) ||
		  (now_ms  != old_now_ms && !_HA_ATOMIC_CAS(&global_now_ms, &old_now_ms, now_ms))) &&
		 __ha_cpu_relax());

	if (!th_ctx->curr_mono_time) {
		/* Only update the offset when monotonic time is not available.
		 * <now_ns> and <now_ms> are now updated to the last value of
		 * global_now_ns and global_now_ms, which were also monotonically
		 * updated. We can compute the latest offset, we don't care who writes
		 * it last, the variations will not break the monotonic property.
		 */
		HA_ATOMIC_STORE(&now_offset, now_ns - tv_to_ns(&date));
	}
}

/* must be called once at boot to initialize some global variables */
void clock_init_process_date(void)
{
	now_offset = 0;
	before_poll_mono_ns = now_mono_time(); // 0 if not supported
	th_ctx->prev_mono_time = th_ctx->curr_mono_time = before_poll_mono_ns;
	gettimeofday(&date, NULL);
	after_poll = before_poll = date;
	global_now_ns = th_ctx->curr_mono_time;
	if (!global_now_ns) // CLOCK_MONOTONIC not supported
		global_now_ns = tv_to_ns(&date);
	now_ns = global_now_ns;
	global_now_ms = ns_to_ms(now_ns);

	/* force time to wrap 20s after boot: we first compute the time offset
	 * that once applied to the wall-clock date will make the local time
	 * wrap in 5 seconds. This offset is applied to the process-wide time,
	 * and will be used to recompute the local time, both of which will
	 * match and continue from this shifted date.
	 */
	now_offset = sec_to_ns((uint)((uint)(-global_now_ms) / 1000U - BOOT_TIME_WRAP_SEC));
	global_now_ns += now_offset;
	now_ns = global_now_ns;
	now_ms = ns_to_ms(now_ns);
	/* correct for TICK_ETNERITY (0) */
	if (now_ms == TICK_ETERNITY)
		now_ms++;
	global_now_ms = now_ms;

	th_ctx->idle_pct = 100;
	clock_update_date(0, 1);
}

void clock_adjust_now_offset(void)
{
	/* Only update the offset when monotonic time is not available. */
	if (th_ctx->curr_mono_time)
		return;

	HA_ATOMIC_STORE(&now_offset, now_ns - tv_to_ns(&date));
}

/* must be called once per thread to initialize their thread-local variables.
 * Note that other threads might also be initializing and running in parallel.
 */
void clock_init_thread_date(void)
{
	gettimeofday(&date, NULL);
	after_poll = before_poll = date;

	now_ns = _HA_ATOMIC_LOAD(&global_now_ns);
	th_ctx->idle_pct = 100;
	th_ctx->prev_cpu_time  = now_cpu_time();
	th_ctx->prev_mono_time = now_mono_time();
	th_ctx->curr_mono_time = th_ctx->prev_mono_time;
	before_poll_mono_ns = th_ctx->curr_mono_time;
	clock_update_date(0, 1);
}

/* report the average CPU idle percentage over all running threads, between 0 and 100 */
uint clock_report_idle(void)
{
	uint total = 0;
	uint rthr = 0;
	uint thr;

	for (thr = 0; thr < MAX_THREADS; thr++) {
		if (!ha_thread_info[thr].tg ||
		    !(ha_thread_info[thr].tg->threads_enabled & ha_thread_info[thr].ltid_bit))
			continue;
		total += HA_ATOMIC_LOAD(&ha_thread_ctx[thr].idle_pct);
		rthr++;
	}
	return rthr ? total / rthr : 0;
}

/* Update the idle time value twice a second, to be called after
 * clock_update_date() when called after poll(), and currently called only by
 * clock_leaving_poll() below. It relies on <before_poll> to be updated to
 * the system time before calling poll().
 */
static inline void clock_measure_idle(void)
{
	/* Let's compute the idle to work ratio. We worked between after_poll
	 * and before_poll, and slept between before_poll and date. The idle_pct
	 * is updated at most twice every second. Note that the current second
	 * rarely changes so we avoid a multiply when not needed.
	 */
	int delta;

	if (before_poll_mono_ns) {
		/* CLOCK_MONOTONIC in use, use it and convert it to microseconds */

		idle_time += (th_ctx->curr_mono_time - before_poll_mono_ns) / 1000ull;
		samp_time += (th_ctx->curr_mono_time - th_ctx->prev_mono_time) / 1000ull;
	} else {
		/* CLOCK_MONOTONIC not used */
		if ((delta = date.tv_sec - before_poll.tv_sec))
			delta *= 1000000;
		idle_time += delta + (date.tv_usec - before_poll.tv_usec);

		if ((delta = date.tv_sec - after_poll.tv_sec))
			delta *= 1000000;
		samp_time += delta + (date.tv_usec - after_poll.tv_usec);

		after_poll.tv_sec = date.tv_sec; after_poll.tv_usec = date.tv_usec;
	}
	if (samp_time < 500000)
		return;

	HA_ATOMIC_STORE(&th_ctx->idle_pct, (100ULL * idle_time + samp_time / 2) / samp_time);
	idle_time = samp_time = 0;
}

/* Collect date and time information after leaving poll(). <timeout> must be
 * set to the maximum sleep time passed to poll (in milliseconds), and
 * <interrupted> must be zero if the poller reached the timeout or non-zero
 * otherwise, which generally is provided by the poller's return value.
 */
void clock_leaving_poll(int timeout, int interrupted)
{
	clock_measure_idle();
	th_ctx->prev_cpu_time  = now_cpu_time();
	th_ctx->prev_mono_time = th_ctx->curr_mono_time;
}

/* Collect date and time information before calling poll(). This will be used
 * to count the run time of the past loop and the sleep time of the next poll.
 * It also compares the elapsed and cpu times during the activity period to
 * estimate the amount of stolen time, which is reported if higher than half
 * a millisecond.
 */
void clock_entering_poll(void)
{
	uint64_t new_mono_time;
	uint64_t new_cpu_time;
	uint32_t run_time;
	int64_t stolen;

	new_cpu_time   = now_cpu_time();
	new_mono_time  = now_mono_time();

	/* the the time when we entere poll */
	before_poll_mono_ns = new_mono_time;

	/* The time might have jumped either backwards or forwards during tasks
	 * processing. It's easy to detect a backwards jump, but a forward jump
	 * needs a marging. Here the upper limit of 2 seconds corresponds to a
	 * large margin at which the watchdog would already trigger so it looks
	 * sufficient to avoid false positives most of the time. The goal here
	 * is to make sure that before_poll can be trusted when entering
	 * clock_update_local_date() so that we can detect and fix time jumps.
	 * All this will also make sure we don't report idle/run times that are
	 * too much wrong during such jumps.
	 */

	if (before_poll_mono_ns)
		run_time = (before_poll_mono_ns - th_ctx->curr_mono_time) / 1000ull;
	else {
		gettimeofday(&before_poll, NULL);

		if (unlikely(__tv_islt(&before_poll, &after_poll)))
			before_poll = after_poll;
		else if (unlikely(__tv_ms_elapsed(&after_poll, &before_poll) >= 2000))
			tv_ms_add(&before_poll, &after_poll, 2000);

		run_time = (before_poll.tv_sec - after_poll.tv_sec) * 1000000U + (before_poll.tv_usec - after_poll.tv_usec);
	}

	if (th_ctx->prev_cpu_time && th_ctx->prev_mono_time) {
		new_cpu_time  -= th_ctx->prev_cpu_time;
		new_mono_time -= th_ctx->prev_mono_time;
		stolen = new_mono_time - new_cpu_time;
		if (unlikely(stolen >= 500000)) {
			stolen /= 500000;
			/* more than half a millisecond difference might
			 * indicate an undesired preemption.
			 */
			report_stolen_time(stolen);
		}
	}

	/* update the average runtime */
	activity_count_runtime(run_time);
}

/* returns the current date as returned by gettimeofday() in ISO+microsecond
 * format. It uses a thread-local static variable that the reader can consume
 * for as long as it wants until next call. Thus, do not call it from a signal
 * handler. If <pad> is non-0, a trailing space will be added. It will always
 * return exactly 32 or 33 characters (depending on padding) and will always be
 * zero-terminated, thus it will always fit into a 34 bytes buffer.
 * This also always include the local timezone (in +/-HH:mm format) .
 */
char *timeofday_as_iso_us(int pad)
{
	struct timeval new_date;
	struct tm tm;
	const char *offset;
	char c;

	gettimeofday(&new_date, NULL);
	if (new_date.tv_sec != iso_time_sec || !new_date.tv_sec) {
		get_localtime(new_date.tv_sec, &tm);
		offset = get_gmt_offset(new_date.tv_sec, &tm);
		if (unlikely(strftime(iso_time_str, sizeof(iso_time_str), "%Y-%m-%dT%H:%M:%S.000000+00:00", &tm) != 32))
			strlcpy2(iso_time_str, "YYYY-mm-ddTHH:MM:SS.000000-00:00", sizeof(iso_time_str)); // make the failure visible but respect format.
		iso_time_str[26] = offset[0];
		iso_time_str[27] = offset[1];
		iso_time_str[28] = offset[2];
		iso_time_str[30] = offset[3];
		iso_time_str[31] = offset[4];
		iso_time_sec = new_date.tv_sec;
	}

	/* utoa_pad adds a trailing 0 so we save the char for restore */
	c = iso_time_str[26];
	utoa_pad(new_date.tv_usec, iso_time_str + 20, 7);
	iso_time_str[26] = c;
	if (pad) {
		iso_time_str[32] = ' ';
		iso_time_str[33] = 0;
	}
	return iso_time_str;
}
