/*
 * Time calculation functions.
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <unistd.h>
#include <sys/time.h>

#include <haproxy/api.h>
#include <haproxy/time.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>

THREAD_LOCAL unsigned int   now_ms;          /* internal date in milliseconds (may wrap) */
THREAD_LOCAL unsigned int   samp_time;       /* total elapsed time over current sample */
THREAD_LOCAL unsigned int   idle_time;       /* total idle time over current sample */
THREAD_LOCAL struct timeval now;             /* internal date is a monotonic function of real clock */
THREAD_LOCAL struct timeval date;            /* the real current date */
struct timeval start_date;      /* the process's start date */
THREAD_LOCAL struct timeval before_poll;     /* system date before calling poll() */
THREAD_LOCAL struct timeval after_poll;      /* system date after leaving poll() */

static THREAD_LOCAL struct timeval tv_offset;  /* per-thread time ofsset relative to global time */
volatile unsigned long long global_now;      /* common date between all threads (32:32) */
volatile unsigned int global_now_ms;         /* common date in milliseconds (may wrap) */

static THREAD_LOCAL unsigned int iso_time_sec;     /* last iso time value for this thread */
static THREAD_LOCAL char         iso_time_str[34]; /* ISO time representation of gettimeofday() */

/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
struct timeval *_tv_ms_add(struct timeval *tv, const struct timeval *from, int ms)
{
	tv->tv_usec = from->tv_usec + (ms % 1000) * 1000;
	tv->tv_sec  = from->tv_sec  + (ms / 1000);
	while (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
	return tv;
}

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_ms_cmp2() for that.
 */
int _tv_ms_cmp(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_cmp(tv1, tv2);
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything.
 */
int _tv_ms_cmp2(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_cmp2(tv1, tv2);
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 1 if tv1 <= tv2, 0 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything. Returns 0 if tv1 is
 * TV_ETERNITY, and always assumes that tv2 != TV_ETERNITY. Designed to replace
 * occurrences of (tv_ms_cmp2(tv,now) <= 0).
 */
int _tv_ms_le2(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_le2(tv1, tv2);
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Must not be used when either argument is eternity.
 */
unsigned long _tv_ms_remain(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_remain(tv1, tv2);
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Returns TIME_ETERNITY if tv2 is eternity.
 */
unsigned long _tv_ms_remain2(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv_iseternity(tv2))
		return TIME_ETERNITY;

	return __tv_ms_remain(tv1, tv2);
}

/*
 * Returns the time in ms elapsed between tv1 and tv2, assuming that tv1<=tv2.
 * Must not be used when either argument is eternity.
 */
unsigned long _tv_ms_elapsed(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_elapsed(tv1, tv2);
}

/*
 * adds <inc> to <from>, set the result to <tv> and returns a pointer <tv>
 */
struct timeval *_tv_add(struct timeval *tv, const struct timeval *from, const struct timeval *inc)
{
	return __tv_add(tv, from, inc);
}

/*
 * If <inc> is set, then add it to <from> and set the result to <tv>, then
 * return 1, otherwise return 0. It is meant to be used in if conditions.
 */
int _tv_add_ifset(struct timeval *tv, const struct timeval *from, const struct timeval *inc)
{
	return __tv_add_ifset(tv, from, inc);
}

/*
 * Computes the remaining time between tv1=now and event=tv2. if tv2 is passed,
 * 0 is returned. The result is stored into tv.
 */
struct timeval *_tv_remain(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv)
{
	return __tv_remain(tv1, tv2, tv);
}

/*
 * Computes the remaining time between tv1=now and event=tv2. if tv2 is passed,
 * 0 is returned. The result is stored into tv. Returns ETERNITY if tv2 is
 * eternity.
 */
struct timeval *_tv_remain2(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv)
{
	return __tv_remain2(tv1, tv2, tv);
}

/* tv_isle: compares <tv1> and <tv2> : returns 1 if tv1 <= tv2, otherwise 0 */
int _tv_isle(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_isle(tv1, tv2);
}

/* tv_isgt: compares <tv1> and <tv2> : returns 1 if tv1 > tv2, otherwise 0 */
int _tv_isgt(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_isgt(tv1, tv2);
}

/* tv_update_date: sets <date> to system time, and sets <now> to something as
 * close as possible to real time, following a monotonic function. The main
 * principle consists in detecting backwards and forwards time jumps and adjust
 * an offset to correct them. This function should be called once after each
 * poll, and never farther apart than MAX_DELAY_MS*2. The poll's timeout should
 * be passed in <max_wait>, and the return value in <interrupted> (a non-zero
 * value means that we have not expired the timeout).
 *
 * tv_init_process_date() must have been called once first, and
 * tv_init_thread_date() must also have been called once for each thread.
 *
 * An offset is used to adjust the current time (date), to have a monotonic time
 * (now). It must be global and thread-safe. But a timeval cannot be atomically
 * updated. So instead, we store it in a 64-bits integer (offset) whose 32 MSB
 * contain the signed seconds adjustment and the 32 LSB contain the unsigned
 * microsecond adjustment. We cannot use a timeval for this since it's never
 * clearly specified whether a timeval may hold negative values or not.
 */
void tv_update_date(int max_wait, int interrupted)
{
	struct timeval adjusted, deadline, tmp_now;
	unsigned int old_now_ms, new_now_ms;
	unsigned long long old_now;
	unsigned long long new_now;

	gettimeofday(&date, NULL);
	__tv_add(&adjusted, &date, &tv_offset);

	/* compute the minimum and maximum local date we may have reached based
	 * on our past date and the associated timeout.
	 */
	_tv_ms_add(&deadline, &now, max_wait + MAX_DELAY_MS);

	if (unlikely(__tv_islt(&adjusted, &now) || __tv_islt(&deadline, &adjusted))) {
		/* Large jump. If the poll was interrupted, we consider that the
		 * date has not changed (immediate wake-up), otherwise we add
		 * the poll time-out to the previous date. The new offset is
		 * recomputed.
		 */
		_tv_ms_add(&adjusted, &now, interrupted ? 0 : max_wait);
	}

	now = adjusted;

	/* now that we have bounded the local time, let's check if it's
	 * realistic regarding the global date, which only moves forward,
	 * otherwise catch up.
	 */
	old_now = global_now;

	do {
		tmp_now.tv_sec  = (unsigned int)(old_now >> 32);
		tmp_now.tv_usec = old_now & 0xFFFFFFFFU;

		if (__tv_islt(&now, &tmp_now))
			now = tmp_now;

		/* now <now> is expected to be the most accurate date,
		 * equal to <global_now> or newer.
		 */
		new_now = ((ullong)now.tv_sec << 32) + (uint)now.tv_usec;

		/* let's try to update the global <now> or loop again */
	} while (!_HA_ATOMIC_CAS(&global_now, &old_now, new_now));

	/* the new global date when we looked was old_now, and the new one is
	 * new_now == now. We can recompute our local offset.
	 */
	tv_offset.tv_sec  = now.tv_sec  - date.tv_sec;
	tv_offset.tv_usec = now.tv_usec - date.tv_usec;
	if (tv_offset.tv_usec < 0) {
		tv_offset.tv_usec += 1000000;
		tv_offset.tv_sec--;
	}

	now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

	/* update the global current millisecond */
	old_now_ms = global_now_ms;
	do {
		new_now_ms = old_now_ms;
		if (tick_is_lt(new_now_ms, now_ms))
			new_now_ms = now_ms;
	}  while (!_HA_ATOMIC_CAS(&global_now_ms, &old_now_ms, new_now_ms));

	return;
}

/* must be called once at boot to initialize some global variables */
void tv_init_process_date()
{
	tv_zero(&tv_offset);
	gettimeofday(&date, NULL);
	now = after_poll = before_poll = date;
	global_now = ((ullong)date.tv_sec << 32) + (uint)date.tv_usec;
	global_now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
	samp_time = idle_time = 0;
	ti->idle_pct = 100;
	tv_update_date(0, 1);
}

/* must be called once per thread to initialize their thread-local variables.
 * Note that other threads might also be initializing and running in parallel.
 */
void tv_init_thread_date()
{
	ullong old_now;

	gettimeofday(&date, NULL);
	after_poll = before_poll = date;

	old_now = _HA_ATOMIC_LOAD(&global_now);
	now.tv_sec = old_now >> 32;
	now.tv_usec = (uint)old_now;

	tv_offset.tv_sec  = now.tv_sec  - date.tv_sec;
	tv_offset.tv_usec = now.tv_usec - date.tv_usec;
	if (tv_offset.tv_usec < 0) {
		tv_offset.tv_usec += 1000000;
		tv_offset.tv_sec--;
	}

	samp_time = idle_time = 0;
	ti->idle_pct = 100;
	tv_update_date(0, 1);
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
