/*
  include/common/time.h
  Time calculation functions and macros.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _COMMON_TIME_H
#define _COMMON_TIME_H

#include <stdlib.h>
#include <sys/time.h>
#include <common/config.h>

#define TIME_ETERNITY		-1

/* returns the lowest delay amongst <old> and <new>, and respects TIME_ETERNITY */
#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))
#define SETNOW(a)		(*a=now)

extern struct timeval now;              /* the current date at any moment */
extern struct timeval start_date;       /* the process's start date */


/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
struct timeval *tv_delayfrom(struct timeval *tv, struct timeval *from, int ms);

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_cmp2_ms() for that.
 */
int tv_cmp_ms(struct timeval *tv1, struct timeval *tv2);

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
int tv_cmp2(struct timeval *tv1, struct timeval *tv2);
/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
int tv_cmp2_ms(struct timeval *tv1, struct timeval *tv2);

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Returns TIME_ETERNITY if tv2 is eternity.
 */
unsigned long tv_remain2(struct timeval *tv1, struct timeval *tv2);


/* sets <tv> to the current time */
static inline struct timeval *tv_now(struct timeval *tv)
{
	if (tv)
		gettimeofday(tv, NULL);
	return tv;
}

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_cmp2() for that.
 */
static inline int tv_cmp(struct timeval *tv1, struct timeval *tv2)
{
	if (tv1->tv_sec < tv2->tv_sec)
		return -1;
	else if (tv1->tv_sec > tv2->tv_sec)
		return 1;
	else if (tv1->tv_usec < tv2->tv_usec)
		return -1;
	else if (tv1->tv_usec > tv2->tv_usec)
		return 1;
	else
		return 0;
}

/*
 * returns the difference, in ms, between tv1 and tv2
 * Must not be used when either argument is eternity.
 */
static inline unsigned long tv_diff(struct timeval *tv1, struct timeval *tv2)
{
	unsigned long ret;
  
	ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
	if (tv2->tv_usec > tv1->tv_usec)
		ret += (tv2->tv_usec - tv1->tv_usec) / 1000;
	else
		ret -= (tv1->tv_usec - tv2->tv_usec) / 1000;
	return (unsigned long) ret;
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Must not be used when either argument is eternity.
 */
static inline unsigned long tv_remain(struct timeval *tv1, struct timeval *tv2)
{
	unsigned long ret;
  
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
 * zeroes a struct timeval
 */

static inline struct timeval *tv_eternity(struct timeval *tv)
{
	tv->tv_sec = tv->tv_usec = 0;
	return tv;
}

/*
 * returns 1 if tv is null, else 0
 */
static inline int tv_iseternity(struct timeval *tv)
{
	if (tv->tv_sec == 0 && tv->tv_usec == 0)
		return 1;
	else
		return 0;
}

/*
 * returns the first event between tv1 and tv2 into tvmin.
 * a zero tv is ignored. tvmin is returned.
 */
static inline struct timeval *tv_min(struct timeval *tvmin,
				     struct timeval *tv1, struct timeval *tv2)
{

	if (tv_cmp2(tv1, tv2) <= 0)
		*tvmin = *tv1;
	else
		*tvmin = *tv2;

	return tvmin;
}


#endif /* _COMMON_TIME_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
