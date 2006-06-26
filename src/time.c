/*
 * Time calculation functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/time.h>
#include <haproxy/time.h>

struct timeval now;             /* the current date at any moment */
struct timeval start_date;      /* the process's start date */

/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
struct timeval *tv_delayfrom(struct timeval *tv, struct timeval *from, int ms)
{
	if (!tv || !from)
		return NULL;
	tv->tv_usec = from->tv_usec + (ms%1000)*1000;
	tv->tv_sec  = from->tv_sec  + (ms/1000);
	while (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
	return tv;
}

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_cmp2_ms() for that.
 */
int tv_cmp_ms(struct timeval *tv1, struct timeval *tv2)
{
	if (tv1->tv_sec == tv2->tv_sec) {
		if (tv2->tv_usec >= tv1->tv_usec + 1000)
			return -1;
		else if (tv1->tv_usec >= tv2->tv_usec + 1000)
			return 1;
		else
			return 0;
	}
	else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
		 ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 >= tv1->tv_usec + 1000)))
		return -1;
	else if ((tv1->tv_sec > tv2->tv_sec + 1) ||
		 ((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 >= tv2->tv_usec + 1000)))
		return 1;
	else
		return 0;
}

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
int tv_cmp2(struct timeval *tv1, struct timeval *tv2)
{
	if (tv_iseternity(tv1))
		if (tv_iseternity(tv2))
			return 0; /* same */
		else
			return 1; /* tv1 later than tv2 */
	else if (tv_iseternity(tv2))
		return -1; /* tv2 later than tv1 */
    
	if (tv1->tv_sec > tv2->tv_sec)
		return 1;
	else if (tv1->tv_sec < tv2->tv_sec)
		return -1;
	else if (tv1->tv_usec > tv2->tv_usec)
		return 1;
	else if (tv1->tv_usec < tv2->tv_usec)
		return -1;
	else
		return 0;
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
int tv_cmp2_ms(struct timeval *tv1, struct timeval *tv2)
{
	if (tv_iseternity(tv1))
		if (tv_iseternity(tv2))
			return 0; /* same */
		else
			return 1; /* tv1 later than tv2 */
	else if (tv_iseternity(tv2))
		return -1; /* tv2 later than tv1 */
    
	if (tv1->tv_sec == tv2->tv_sec) {
		if (tv1->tv_usec >= tv2->tv_usec + 1000)
			return 1;
		else if (tv2->tv_usec >= tv1->tv_usec + 1000)
			return -1;
		else
			return 0;
	}
	else if ((tv1->tv_sec > tv2->tv_sec + 1) ||
		 ((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 >= tv2->tv_usec + 1000)))
		return 1;
	else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
		 ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 >= tv1->tv_usec + 1000)))
		return -1;
	else
		return 0;
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Returns TIME_ETERNITY if tv2 is eternity.
 */
unsigned long tv_remain2(struct timeval *tv1, struct timeval *tv2)
{
	unsigned long ret;

	if (tv_iseternity(tv2))
		return TIME_ETERNITY;

	if (tv_cmp_ms(tv1, tv2) >= 0)
		return 0; /* event elapsed */

	ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
	if (tv2->tv_usec > tv1->tv_usec)
		ret += (tv2->tv_usec - tv1->tv_usec) / 1000;
	else
		ret -= (tv1->tv_usec - tv2->tv_usec) / 1000;
	return (unsigned long) ret;
}


/*
 * returns the absolute difference, in ms, between tv1 and tv2
 * Must not be used when either argument is eternity.
 */
unsigned long tv_delta(struct timeval *tv1, struct timeval *tv2)
{
	int cmp;
	unsigned long ret;
  

	cmp = tv_cmp(tv1, tv2);
	if (!cmp)
		return 0; /* same dates, null diff */
	else if (cmp < 0) {
		struct timeval *tmp = tv1;
		tv1 = tv2;
		tv2 = tmp;
	}
	ret = (tv1->tv_sec - tv2->tv_sec) * 1000;
	if (tv1->tv_usec > tv2->tv_usec)
		ret += (tv1->tv_usec - tv2->tv_usec) / 1000;
	else
		ret -= (tv2->tv_usec - tv1->tv_usec) / 1000;
	return (unsigned long) ret;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
