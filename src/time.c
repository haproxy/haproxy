/*
 * Time calculation functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
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

struct timeval now;             /* the current date at any moment */
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
