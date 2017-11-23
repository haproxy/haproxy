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

#include <sys/time.h>

#include <common/config.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/hathreads.h>

THREAD_LOCAL unsigned int   ms_left_scaled;  /* milliseconds left for current second (0..2^32-1) */
THREAD_LOCAL unsigned int   now_ms;          /* internal date in milliseconds (may wrap) */
THREAD_LOCAL unsigned int   samp_time;       /* total elapsed time over current sample */
THREAD_LOCAL unsigned int   idle_time;       /* total idle time over current sample */
THREAD_LOCAL unsigned int   idle_pct;        /* idle to total ratio over last sample (percent) */
THREAD_LOCAL struct timeval now;             /* internal date is a monotonic function of real clock */
THREAD_LOCAL struct timeval date;            /* the real current date */
struct timeval start_date;      /* the process's start date */
THREAD_LOCAL struct timeval before_poll;     /* system date before calling poll() */
THREAD_LOCAL struct timeval after_poll;      /* system date after leaving poll() */

/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
REGPRM3 struct timeval *_tv_ms_add(struct timeval *tv, const struct timeval *from, int ms)
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
REGPRM2 int _tv_ms_cmp(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_cmp(tv1, tv2);
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything.
 */
REGPRM2 int _tv_ms_cmp2(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_cmp2(tv1, tv2);
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 1 if tv1 <= tv2, 0 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything. Returns 0 if tv1 is
 * TV_ETERNITY, and always assumes that tv2 != TV_ETERNITY. Designed to replace
 * occurrences of (tv_ms_cmp2(tv,now) <= 0).
 */
REGPRM2 int _tv_ms_le2(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_le2(tv1, tv2);
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Must not be used when either argument is eternity.
 */
REGPRM2 unsigned long _tv_ms_remain(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_remain(tv1, tv2);
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Returns TIME_ETERNITY if tv2 is eternity.
 */
REGPRM2 unsigned long _tv_ms_remain2(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv_iseternity(tv2))
		return TIME_ETERNITY;

	return __tv_ms_remain(tv1, tv2);
}

/*
 * Returns the time in ms elapsed between tv1 and tv2, assuming that tv1<=tv2.
 * Must not be used when either argument is eternity.
 */
REGPRM2 unsigned long _tv_ms_elapsed(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_ms_elapsed(tv1, tv2);
}

/*
 * adds <inc> to <from>, set the result to <tv> and returns a pointer <tv>
 */
REGPRM3 struct timeval *_tv_add(struct timeval *tv, const struct timeval *from, const struct timeval *inc)
{
	return __tv_add(tv, from, inc);
}

/*
 * If <inc> is set, then add it to <from> and set the result to <tv>, then
 * return 1, otherwise return 0. It is meant to be used in if conditions.
 */
REGPRM3 int _tv_add_ifset(struct timeval *tv, const struct timeval *from, const struct timeval *inc)
{
	return __tv_add_ifset(tv, from, inc);
}

/*
 * Computes the remaining time between tv1=now and event=tv2. if tv2 is passed,
 * 0 is returned. The result is stored into tv.
 */
REGPRM3 struct timeval *_tv_remain(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv)
{
	return __tv_remain(tv1, tv2, tv);
}

/*
 * Computes the remaining time between tv1=now and event=tv2. if tv2 is passed,
 * 0 is returned. The result is stored into tv. Returns ETERNITY if tv2 is
 * eternity.
 */
REGPRM3 struct timeval *_tv_remain2(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv)
{
	return __tv_remain2(tv1, tv2, tv);
}

/* tv_isle: compares <tv1> and <tv2> : returns 1 if tv1 <= tv2, otherwise 0 */
REGPRM2 int _tv_isle(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_isle(tv1, tv2);
}

/* tv_isgt: compares <tv1> and <tv2> : returns 1 if tv1 > tv2, otherwise 0 */
REGPRM2 int _tv_isgt(const struct timeval *tv1, const struct timeval *tv2)
{
	return __tv_isgt(tv1, tv2);
}

/* tv_update_date: sets <date> to system time, and sets <now> to something as
 * close as possible to real time, following a monotonic function. The main
 * principle consists in detecting backwards and forwards time jumps and adjust
 * an offset to correct them. This function should be called once after each
 * poll, and never farther apart than MAX_DELAY_MS*2. The poll's timeout should
 * be passed in <max_wait>, and the return value in <interrupted> (a non-zero
 * value means that we have not expired the timeout). Calling it with (-1,*)
 * sets both <date> and <now> to current date, and calling it with (0,1) simply
 * updates the values.
 *
 * An offset is used to adjust the current time (date), to have a monotonic time
 * (now). It must be global and thread-safe. But a timeval cannot be atomically
 * updated. So instead, we store it in a 64-bits integer (offset) whose 32 MSB
 * contain the signed seconds adjustment andthe 32 LSB contain the unsigned
 * microsecond adjustment. We cannot use a timeval for this since it's never
 * clearly specified whether a timeval may hold negative values or not.
 */
REGPRM2 void tv_update_date(int max_wait, int interrupted)
{
	volatile static long long offset = 0;
	struct timeval adjusted, deadline;
	unsigned int   curr_sec_ms;     /* millisecond of current second (0..999) */
	long long new_ofs;

	gettimeofday(&date, NULL);
	if (unlikely(max_wait < 0)) {
		HA_ATOMIC_STORE(&offset, 0);
		adjusted = date;
		after_poll = date;
		samp_time = idle_time = 0;
		idle_pct = 100;
		goto to_ms;
	}

	new_ofs = offset;

	adjusted.tv_sec  = date.tv_sec  + (int)(new_ofs >> 32);
	adjusted.tv_usec = date.tv_usec + (int)(new_ofs & 0xFFFFFFFFU);
	if (adjusted.tv_usec > 999999) {
		adjusted.tv_usec -= 1000000;
		adjusted.tv_sec  += 1;
	}

	if (unlikely(__tv_islt(&adjusted, &now))) {
		goto fixup; /* jump in the past */
	}

	/* OK we did not jump backwards, let's see if we have jumped too far
	 * forwards. The poll value was in <max_wait>, we accept that plus
	 * MAX_DELAY_MS to cover additional time.
	 */
	_tv_ms_add(&deadline, &now, max_wait + MAX_DELAY_MS);
	if (likely(__tv_islt(&adjusted, &deadline)))
		goto to_ms; /* OK time is within expected range */
 fixup:
	/* Large jump. If the poll was interrupted, we consider that the date
	 * has not changed (immediate wake-up), otherwise we add the poll
	 * time-out to the previous date. The new offset is recomputed.
	 */
	_tv_ms_add(&adjusted, &now, interrupted ? 0 : max_wait);

	new_ofs = (((long)(adjusted.tv_sec  - date.tv_sec)) << 32) +
	          (unsigned int)(adjusted.tv_usec - date.tv_usec);

	if ((int)(new_ofs & 0xFFFFFFFFU) < 0)
		new_ofs = new_ofs + 1000000 - 0x100000000UL;

	HA_ATOMIC_STORE(&offset, new_ofs);
 to_ms:
	now = adjusted;
	curr_sec_ms = now.tv_usec / 1000;            /* ms of current second */

	/* For frequency counters, we'll need to know the ratio of the previous
	 * value to add to current value depending on the current millisecond.
	 * The principle is that during the first millisecond, we use 999/1000
	 * of the past value and that during the last millisecond we use 0/1000
	 * of the past value. In summary, we only use the past value during the
	 * first 999 ms of a second, and the last ms is used to complete the
	 * current measure. The value is scaled to (2^32-1) so that a simple
	 * multiply followed by a shift gives us the final value.
	 */
	ms_left_scaled = (999U - curr_sec_ms) * 4294967U;
	now_ms = now.tv_sec * 1000 + curr_sec_ms;
	return;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
