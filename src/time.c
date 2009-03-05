/*
 * Time calculation functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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

unsigned int   curr_sec_ms;      /* millisecond of current second (0..999) */
unsigned int   curr_sec_ms_scaled;  /* millisecond of current second (0..2^32-1) */
unsigned int   now_ms;          /* internal date in milliseconds (may wrap) */
struct timeval now;             /* internal date is a monotonic function of real clock */
struct timeval date;            /* the real current date */
struct timeval start_date;      /* the process's start date */

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

/* tv_udpate_date: sets <date> to system time, and sets <now> to something as
 * close as possible to real time, following a monotonic function. The main
 * principle consists in detecting backwards and forwards time jumps and adjust
 * an offset to correct them. This function should be called once after each
 * poll, and never farther apart than MAX_DELAY_MS*2. The poll's timeout should
 * be passed in <max_wait>, and the return value in <interrupted> (a non-zero
 * value means that we have not expired the timeout). Calling it with (-1,*)
 * sets both <date> and <now> to current date, and calling it with (0,1) simply
 * updates the values.
 */
REGPRM2 void tv_update_date(int max_wait, int interrupted)
{
	static struct timeval tv_offset; /* warning: signed offset! */
	struct timeval adjusted, deadline;

	gettimeofday(&date, NULL);
	if (unlikely(max_wait < 0)) {
		tv_zero(&tv_offset);
		adjusted = date;
		goto to_ms;
	}
	__tv_add(&adjusted, &date, &tv_offset);
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

	tv_offset.tv_sec  = adjusted.tv_sec  - date.tv_sec;
	tv_offset.tv_usec = adjusted.tv_usec - date.tv_usec;
	if (tv_offset.tv_usec < 0) {
		tv_offset.tv_usec += 1000000;
		tv_offset.tv_sec--;
	}
 to_ms:
	now = adjusted;
	curr_sec_ms = now.tv_usec / 1000;            /* ms of current second */
	curr_sec_ms_scaled = curr_sec_ms * 4294971;  /* ms * 2^32 / 1000 */
	now_ms = now.tv_sec * 1000 + curr_sec_ms;
	return;
}

char *human_time(int t, short hz_div) {
	static char rv[sizeof("24855d23h")+1];	// longest of "23h59m" and "59m59s"
	char *p = rv;
	int cnt=2;				// print two numbers

	if (unlikely(t < 0 || hz_div <= 0)) {
		sprintf(p, "?");
		return rv;
	}

	if (unlikely(hz_div > 1))
		t /= hz_div;

	if (t >= DAY) {
		p += sprintf(p, "%dd", t / DAY);
		cnt--;
	}

	if (cnt && t % DAY / HOUR) {
		p += sprintf(p, "%dh", t % DAY / HOUR);
		cnt--;
	}

	if (cnt && t % HOUR / MINUTE) {
		p += sprintf(p, "%dm", t % HOUR / MINUTE);
		cnt--;
	}

	if ((cnt && t % MINUTE) || !t)					// also display '0s'
		p += sprintf(p, "%ds", t % MINUTE / SEC);

	return rv;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
