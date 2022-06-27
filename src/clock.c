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
volatile ullong                  global_now;      /* common monotonic date between all threads (32:32) */
volatile uint                    global_now_ms;   /* common monotonic date in milliseconds (may wrap) */

THREAD_ALIGNED(64) static ullong now_offset;      /* global offset between system time and global time */

THREAD_LOCAL uint                now_ms;          /* internal monotonic date in milliseconds (may wrap) */
THREAD_LOCAL struct timeval      now;             /* internal monotonic date derived from real clock */
THREAD_LOCAL struct timeval      date;            /* the real current date (wall-clock time) */

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
#if defined(_POSIX_TIMERS) && defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_MONOTONIC_CLOCK)
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ret = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
	return ret;
}

/* returns the current thread's cumulated CPU time in nanoseconds if supported, otherwise zero */
uint64_t now_cpu_time(void)
{
	uint64_t ret = 0;
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	ret = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
	return ret;
}

/* returns another thread's cumulated CPU time in nanoseconds if supported, otherwise zero */
uint64_t now_cpu_time_thread(int thr)
{
	uint64_t ret = 0;
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)
	struct timespec ts;
	clock_gettime(per_thread_clock_id[thr], &ts);
	ret = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
	return ret;
}

/* set the clock source for the local thread */
void clock_set_local_source(void)
{
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)
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

/* clock_update_date: sets <date> to system time, and sets <now> to something as
 * close as possible to real time, following a monotonic function. The main
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
 * local time (now). The offset is not critical, as it is only updated after a
 * clock jump is detected. From this point all threads will apply it to their
 * locally measured time, and will then agree around a common monotonic
 * global_now value that serves to further refine their local time. As it is
 * not possible to atomically update a timeval, both global_now and the
 * now_offset values are instead stored as 64-bit integers made of two 32 bit
 * values for the tv_sec and tv_usec parts. The offset is made of two signed
 * ints so that the clock can be adjusted in the two directions.
 */
void clock_update_date(int max_wait, int interrupted)
{
	struct timeval min_deadline, max_deadline, tmp_now;
	uint old_now_ms;
	ullong old_now;
	ullong new_now;
	ullong ofs, ofs_new;
	uint sec_ofs, usec_ofs;

	gettimeofday(&date, NULL);

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

	ofs = HA_ATOMIC_LOAD(&now_offset);

	if (unlikely(__tv_islt(&date, &before_poll)                    || // big jump backwards
		     (!interrupted && __tv_islt(&date, &min_deadline)) || // small jump backwards
		     __tv_islt(&max_deadline, &date))) {                  // big jump forwards
		if (!interrupted)
			_tv_ms_add(&now, &now, max_wait);
	} else {
		/* The date is still within expectations. Let's apply the
		 * now_offset to the system date. Note: ofs if made of two
		 * independent signed ints.
		 */
		now.tv_sec  = date.tv_sec  + (int)(ofs >> 32); // note: may be positive or negative
		now.tv_usec = date.tv_usec + (int)ofs;         // note: may be positive or negative
		if ((int)now.tv_usec < 0) {
			now.tv_usec += 1000000;
			now.tv_sec  -= 1;
		} else if (now.tv_usec >= 1000000) {
			now.tv_usec -= 1000000;
			now.tv_sec  += 1;
		}
	}

	/* now that we have bounded the local time, let's check if it's
	 * realistic regarding the global date, which only moves forward,
	 * otherwise catch up.
	 */
	old_now    = global_now;
	old_now_ms = global_now_ms;

	do {
		tmp_now.tv_sec  = (unsigned int)(old_now >> 32);
		tmp_now.tv_usec = old_now & 0xFFFFFFFFU;

		if (__tv_islt(&now, &tmp_now))
			now = tmp_now;

		/* now <now> is expected to be the most accurate date,
		 * equal to <global_now> or newer.
		 */
		new_now = ((ullong)now.tv_sec << 32) + (uint)now.tv_usec;
		now_ms = __tv_to_ms(&now);

		/* let's try to update the global <now> (both in timeval
		 * and ms forms) or loop again.
		 */
	} while (((new_now != old_now    && !_HA_ATOMIC_CAS(&global_now, &old_now, new_now)) ||
		  (now_ms  != old_now_ms && !_HA_ATOMIC_CAS(&global_now_ms, &old_now_ms, now_ms))) &&
		 __ha_cpu_relax());

	/* <now> and <now_ms> are now updated to the last value of global_now
	 * and global_now_ms, which were also monotonically updated. We can
	 * compute the latest offset, we don't care who writes it last, the
	 * variations will not break the monotonic property.
	 */

	sec_ofs  = now.tv_sec  - date.tv_sec;
	usec_ofs = now.tv_usec - date.tv_usec;
	if ((int)usec_ofs < 0) {
		usec_ofs += 1000000;
		sec_ofs  -= 1;
	}
	ofs_new = ((ullong)sec_ofs << 32) + usec_ofs;
	if (ofs_new != ofs)
		HA_ATOMIC_STORE(&now_offset, ofs_new);
}

/* must be called once at boot to initialize some global variables */
void clock_init_process_date(void)
{
	now_offset = 0;
	gettimeofday(&date, NULL);
	now = after_poll = before_poll = date;
	global_now = ((ullong)date.tv_sec << 32) + (uint)date.tv_usec;
	global_now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
	th_ctx->idle_pct = 100;
	clock_update_date(0, 1);
}

/* must be called once per thread to initialize their thread-local variables.
 * Note that other threads might also be initializing and running in parallel.
 */
void clock_init_thread_date(void)
{
	ullong old_now;

	gettimeofday(&date, NULL);
	after_poll = before_poll = date;

	old_now = _HA_ATOMIC_LOAD(&global_now);
	now.tv_sec = old_now >> 32;
	now.tv_usec = (uint)old_now;
	th_ctx->idle_pct = 100;
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

	if ((delta = date.tv_sec - before_poll.tv_sec))
		delta *= 1000000;
	idle_time += delta + (date.tv_usec - before_poll.tv_usec);

	if ((delta = date.tv_sec - after_poll.tv_sec))
		delta *= 1000000;
	samp_time += delta + (date.tv_usec - after_poll.tv_usec);

	after_poll.tv_sec = date.tv_sec; after_poll.tv_usec = date.tv_usec;
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
	th_ctx->prev_mono_time = now_mono_time();
}

/* Collect date and time information before calling poll(). This will be used
 * to count the run time of the past loop and the sleep time of the next poll.
 * It also compares the elasped and cpu times during the activity period to
 * estimate the amount of stolen time, which is reported if higher than half
 * a millisecond.
 */
void clock_entering_poll(void)
{
	uint64_t new_mono_time;
	uint64_t new_cpu_time;
	uint32_t run_time;
	int64_t stolen;

	gettimeofday(&before_poll, NULL);

	run_time = (before_poll.tv_sec - after_poll.tv_sec) * 1000000U + (before_poll.tv_usec - after_poll.tv_usec);

	new_cpu_time   = now_cpu_time();
	new_mono_time  = now_mono_time();

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
			strcpy(iso_time_str, "YYYY-mm-ddTHH:MM:SS.000000-00:00"); // make the failure visible but respect format.
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
