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

/* eternity when exprimed in timeval */
#ifndef TV_ETERNITY
#define TV_ETERNITY     (~0UL)
#endif

/* eternity when exprimed in ms */
#ifndef TV_ETERNITY_MS
#define TV_ETERNITY_MS  (-1)
#endif

#define TIME_ETERNITY   (TV_ETERNITY_MS)


/* returns the lowest delay amongst <old> and <new>, and respects TIME_ETERNITY */
#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))
#define SETNOW(a)		(*a=now)

extern struct timeval now;              /* the current date at any moment */
extern struct timeval start_date;       /* the process's start date */


/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
REGPRM3 struct timeval *tv_delayfrom(struct timeval *tv, const struct timeval *from, int ms);

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_cmp2_ms() for that.
 */
REGPRM2 int tv_cmp_ms(const struct timeval *tv1, const struct timeval *tv2);

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything.
 */
REGPRM2 int tv_cmp2_ms(const struct timeval *tv1, const struct timeval *tv2);

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 1 if tv1 <= tv2, 0 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything. Returns 0 if tv1 is
 * TV_ETERNITY, and always assumes that tv2 != TV_ETERNITY. Designed to replace
 * occurrences of (tv_cmp2_ms(tv,now) <= 0).
 */
REGPRM2 int tv_cmp2_le(const struct timeval *tv1, const struct timeval *tv2);

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Returns TIME_ETERNITY if tv2 is eternity.
 */
REGPRM2 unsigned long tv_remain2(const struct timeval *tv1, const struct timeval *tv2);

/* sets <tv> to the current time */
REGPRM1 static inline struct timeval *tv_now(struct timeval *tv)
{
	if (tv)
		gettimeofday(tv, NULL);
	return tv;
}

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 */
REGPRM2 static inline int tv_cmp(const struct timeval *tv1, const struct timeval *tv2)
{
	if ((unsigned)tv1->tv_sec < (unsigned)tv2->tv_sec)
		return -1;
	else if ((unsigned)tv1->tv_sec > (unsigned)tv2->tv_sec)
		return 1;
	else if ((unsigned)tv1->tv_usec < (unsigned)tv2->tv_usec)
		return -1;
	else if ((unsigned)tv1->tv_usec > (unsigned)tv2->tv_usec)
		return 1;
	else
		return 0;
}

/*
 * compares <tv1> and <tv2> : returns 0 if tv1 < tv2, 1 if tv1 >= tv2
 */
REGPRM2 static inline int tv_cmp_ge(const struct timeval *tv1, const struct timeval *tv2)
{
	if ((unsigned)tv1->tv_sec > (unsigned)tv2->tv_sec)
		return 1;
	if ((unsigned)tv1->tv_sec < (unsigned)tv2->tv_sec)
		return 0;
	if ((unsigned)tv1->tv_usec >= (unsigned)tv2->tv_usec)
		return 1;
	return 0;
}

/*
 * returns the difference, in ms, between tv1 and tv2
 * Must not be used when either argument is eternity.
 */
REGPRM2 static inline unsigned long tv_diff(const struct timeval *tv1, const struct timeval *tv2)
{
	unsigned long ret;
  
	ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
	if ((unsigned)tv2->tv_usec > (unsigned)tv1->tv_usec)
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
REGPRM2 static inline unsigned long tv_remain(const struct timeval *tv1, const struct timeval *tv2)
{
	unsigned long ret;
  
	if (tv_cmp_ms(tv1, tv2) >= 0)
		return 0; /* event elapsed */

	ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
	if ((unsigned)tv2->tv_usec > (unsigned)tv1->tv_usec)
		ret += (tv2->tv_usec - tv1->tv_usec) / 1000;
	else
		ret -= (tv1->tv_usec - tv2->tv_usec) / 1000;
	return (unsigned long) ret;
}


/*
 * sets a struct timeval to its highest value so that it can never happen
 * note that only tv_usec is necessary to detect it since a tv_usec > 999999
 * is normally not possible.
 *
 */

REGPRM1 static inline struct timeval *tv_eternity(struct timeval *tv)
{
	tv->tv_sec = tv->tv_usec = TV_ETERNITY;
	return tv;
}

/*
 * sets a struct timeval to 0
 *
 */
REGPRM1 static inline struct timeval *tv_zero(struct timeval *tv) {
	tv->tv_sec = tv->tv_usec = 0;
	return tv;
}

/*
 * returns non null if tv is [eternity], otherwise 0.
 */
#define tv_iseternity(tv)       ((tv)->tv_usec == TV_ETERNITY)

/*
 * returns non null if tv is [0], otherwise 0.
 */
#define tv_iszero(tv)           (((tv)->tv_sec | (tv)->tv_usec) == 0)

/*
 * compares <tv1> and <tv2> : returns 1 if <tv1> is before <tv2>, otherwise 0.
 * This should be very fast because it's used in schedulers.
 * It has been optimized to return 1  (so call it in a loop which continues
 * as long as tv1<=tv2)
 */

#define tv_isbefore(tv1, tv2)                                               \
	(unlikely((unsigned)(tv1)->tv_sec < (unsigned)(tv2)->tv_sec) ? 1 :  \
	 (unlikely((unsigned)(tv1)->tv_sec > (unsigned)(tv2)->tv_sec) ? 0 : \
	  unlikely((unsigned)(tv1)->tv_usec < (unsigned)(tv2)->tv_usec)))

/*
 * returns the first event between <tv1> and <tv2> into <tvmin>.
 * a zero tv is ignored. <tvmin> is returned. If <tvmin> is known
 * to be the same as <tv1> or <tv2>, it is recommended to use
 * tv_bound instead.
 */
#define tv_min(tvmin, tv1, tv2) ({      \
        if (tv_isbefore(tv1, tv2)) {    \
                *tvmin = *tv1;          \
        }                               \
        else {                          \
                *tvmin = *tv2;          \
        }                               \
        tvmin;                          \
})

/*
 * returns the first event between <tv1> and <tv2> into <tvmin>.
 * a zero tv is ignored. <tvmin> is returned. This function has been
 * optimized to be called as tv_min(a,a,b) or tv_min(b,a,b).
 */
#define tv_bound(tv1, tv2) ({      \
        if (tv_isbefore(tv2, tv1)) \
                  *tv1 = *tv2;     \
        tv1;                       \
})


#endif /* _COMMON_TIME_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
