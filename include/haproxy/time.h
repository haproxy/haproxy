/*
 * include/haproxy/time.h
 * timeval-based time calculation functions and macros.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_TIME_H
#define _HAPROXY_TIME_H

#include <haproxy/time-t.h>

#include <sys/time.h>
#include <haproxy/api.h>
#include <haproxy/ticks.h>

#define TIME_ETERNITY   (TV_ETERNITY_MS)



/**** exported functions *************************************************/
/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
struct timeval *tv_ms_add(struct timeval *tv, const struct timeval *from, int ms);

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_ms_cmp2() for that.
 */
int tv_ms_cmp(const struct timeval *tv1, const struct timeval *tv2);

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything.
 */
int tv_ms_cmp2(const struct timeval *tv1, const struct timeval *tv2);


/**** general purpose functions and macros *******************************/


/*
 * sets a struct timeval to its highest value so that it can never happen
 * note that only tv_usec is necessary to detect it since a tv_usec > 999999
 * is normally not possible.
 */
static inline struct timeval *tv_eternity(struct timeval *tv)
{
	tv->tv_sec  = (typeof(tv->tv_sec))TV_ETERNITY;
	tv->tv_usec = (typeof(tv->tv_usec))TV_ETERNITY;
	return tv;
}

/*
 * sets a struct timeval to 0
 *
 */
static inline struct timeval *tv_zero(struct timeval *tv) {
	tv->tv_sec = tv->tv_usec = 0;
	return tv;
}

/*
 * returns non null if tv is [eternity], otherwise 0.
 */
#define tv_iseternity(tv)       ((tv)->tv_usec == (typeof((tv)->tv_usec))TV_ETERNITY)

/*
 * returns 0 if tv is [eternity], otherwise non-zero.
 */
#define tv_isset(tv)       ((tv)->tv_usec != (typeof((tv)->tv_usec))TV_ETERNITY)

/*
 * returns non null if tv is [0], otherwise 0.
 */
#define tv_iszero(tv)           (((tv)->tv_sec | (tv)->tv_usec) == 0)

/*
 * Converts a struct timeval to a wrapping number of milliseconds.
 */
static inline uint __tv_to_ms(const struct timeval *tv)
{
	unsigned int ret;

	ret  = (uint)tv->tv_sec  * 1000;
	ret += (uint)tv->tv_usec / 1000;
	return ret;
}

/*
 * Converts a struct timeval to a number of milliseconds.
 */
static inline struct timeval * __tv_from_ms(struct timeval *tv, unsigned long ms)
{
	tv->tv_sec = ms / 1000;
	tv->tv_usec = (ms % 1000) * 1000;
	return tv;
}

/*
 * Converts a struct timeval to a relative timestamp in nanoseconds (only
 * wraps every 585 years, i.e. never for our purpose).
 */
static forceinline ullong tv_to_ns(const struct timeval *tv)
{
	ullong ret;

	ret  = (ullong)tv->tv_sec  * 1000000000ULL;
	ret += (ullong)tv->tv_usec * 1000ULL;
	return ret;
}

/* turns nanoseconds to seconds, just to avoid typos */
static forceinline uint ns_to_sec(ullong ns)
{
	return ns / 1000000000ULL;
}

/* turns nanoseconds to milliseconds, just to avoid typos */
static forceinline uint ns_to_ms(ullong ns)
{
	return ns / 1000000ULL;
}

/* turns seconds to nanoseconds, just to avoid typos */
static forceinline ullong sec_to_ns(uint sec)
{
	return sec * 1000000000ULL;
}

/* turns milliseconds to nanoseconds, just to avoid typos */
static forceinline ullong ms_to_ns(uint ms)
{
	return ms * 1000000ULL;
}

/* turns microseconds to nanoseconds, just to avoid typos */
static forceinline ullong us_to_ns(uint us)
{
	return us * 1000ULL;
}

/* creates a struct timeval from a relative timestamp in nanosecond */
#define NS_TO_TV(t) ((const struct timeval){ .tv_sec = (t) / 1000000000ULL, .tv_usec = ((t) % 1000000000ULL) / 1000U })

/* Return a number of 1024Hz ticks between 0 and 1023 for input number of
 * usecs between 0 and 999999. This function has been optimized to remove
 * any divide and multiply, as it is completely optimized away by the compiler
 * on CPUs which don't have a fast multiply. Its avg error rate is 305 ppm,
 * which is almost twice as low as a direct usec to ms conversion. This version
 * also has the benefit of returning 1024 for 1000000.
 */
static inline unsigned int __usec_to_1024th(unsigned int usec)
{
	return (usec * 1073 + 742516) >> 20;
}


/**** comparison functions and macros ***********************************/


/* tv_cmp: compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2. */
static inline int __tv_cmp(const struct timeval *tv1, const struct timeval *tv2)
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

/* tv_iseq: compares <tv1> and <tv2> : returns 1 if tv1 == tv2, otherwise 0 */
#define tv_iseq __tv_iseq
static inline int __tv_iseq(const struct timeval *tv1, const struct timeval *tv2)
{
	return ((unsigned)tv1->tv_sec  == (unsigned)tv2->tv_sec) &&
		((unsigned)tv1->tv_usec == (unsigned)tv2->tv_usec);
}

/* tv_isgt: compares <tv1> and <tv2> : returns 1 if tv1 > tv2, otherwise 0 */
#define tv_isgt _tv_isgt
int _tv_isgt(const struct timeval *tv1, const struct timeval *tv2);
static inline int __tv_isgt(const struct timeval *tv1, const struct timeval *tv2)
{
	return
		((unsigned)tv1->tv_sec  == (unsigned)tv2->tv_sec) ?
		((unsigned)tv1->tv_usec >  (unsigned)tv2->tv_usec) :
		((unsigned)tv1->tv_sec  >  (unsigned)tv2->tv_sec);
}

/* tv_isge: compares <tv1> and <tv2> : returns 1 if tv1 >= tv2, otherwise 0 */
#define tv_isge __tv_isge
static inline int __tv_isge(const struct timeval *tv1, const struct timeval *tv2)
{
	return
		((unsigned)tv1->tv_sec  == (unsigned)tv2->tv_sec) ?
		((unsigned)tv1->tv_usec >= (unsigned)tv2->tv_usec) :
		((unsigned)tv1->tv_sec  >  (unsigned)tv2->tv_sec);
}

/* tv_islt: compares <tv1> and <tv2> : returns 1 if tv1 < tv2, otherwise 0 */
#define tv_islt __tv_islt
static inline int __tv_islt(const struct timeval *tv1, const struct timeval *tv2)
{
	return
		((unsigned)tv1->tv_sec  == (unsigned)tv2->tv_sec) ?
		((unsigned)tv1->tv_usec <  (unsigned)tv2->tv_usec) :
		((unsigned)tv1->tv_sec  <  (unsigned)tv2->tv_sec);
}

/* tv_isle: compares <tv1> and <tv2> : returns 1 if tv1 <= tv2, otherwise 0 */
#define tv_isle _tv_isle
int _tv_isle(const struct timeval *tv1, const struct timeval *tv2);
static inline int __tv_isle(const struct timeval *tv1, const struct timeval *tv2)
{
	return
		((unsigned)tv1->tv_sec  == (unsigned)tv2->tv_sec) ?
		((unsigned)tv1->tv_usec <= (unsigned)tv2->tv_usec) :
		((unsigned)tv1->tv_sec  <  (unsigned)tv2->tv_sec);
}

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_ms_cmp2() for that.
 */
#define tv_ms_cmp _tv_ms_cmp
int _tv_ms_cmp(const struct timeval *tv1, const struct timeval *tv2);
static inline int __tv_ms_cmp(const struct timeval *tv1, const struct timeval *tv2)
{
	if ((unsigned)tv1->tv_sec == (unsigned)tv2->tv_sec) {
		if ((unsigned)tv2->tv_usec >= (unsigned)tv1->tv_usec + 1000)
			return -1;
		else if ((unsigned)tv1->tv_usec >= (unsigned)tv2->tv_usec + 1000)
			return 1;
		else
			return 0;
	}
	else if (((unsigned)tv2->tv_sec > (unsigned)tv1->tv_sec + 1) ||
		 (((unsigned)tv2->tv_sec == (unsigned)tv1->tv_sec + 1) &&
		  ((unsigned)tv2->tv_usec + 1000000 >= (unsigned)tv1->tv_usec + 1000)))
		return -1;
	else if (((unsigned)tv1->tv_sec > (unsigned)tv2->tv_sec + 1) ||
		 (((unsigned)tv1->tv_sec == (unsigned)tv2->tv_sec + 1) &&
		  ((unsigned)tv1->tv_usec + 1000000 >= (unsigned)tv2->tv_usec + 1000)))
		return 1;
	else
		return 0;
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything.
 */
#define tv_ms_cmp2 _tv_ms_cmp2
int _tv_ms_cmp2(const struct timeval *tv1, const struct timeval *tv2);
static inline int __tv_ms_cmp2(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv_iseternity(tv1))
		if (tv_iseternity(tv2))
			return 0; /* same */
		else
			return 1; /* tv1 later than tv2 */
	else if (tv_iseternity(tv2))
		return -1; /* tv2 later than tv1 */
	return tv_ms_cmp(tv1, tv2);
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 1 if tv1 <= tv2, 0 if tv1 > tv2,
 * assuming that TV_ETERNITY is greater than everything. Returns 0 if tv1 is
 * TV_ETERNITY, and always assumes that tv2 != TV_ETERNITY. Designed to replace
 * occurrences of (tv_ms_cmp2(tv,now) <= 0).
 */
#define tv_ms_le2 _tv_ms_le2
int _tv_ms_le2(const struct timeval *tv1, const struct timeval *tv2);
static inline int __tv_ms_le2(const struct timeval *tv1, const struct timeval *tv2)
{
	if (likely((unsigned)tv1->tv_sec > (unsigned)tv2->tv_sec + 1))
		return 0;

	if (likely((unsigned)tv1->tv_sec < (unsigned)tv2->tv_sec))
		return 1;

	if (likely((unsigned)tv1->tv_sec == (unsigned)tv2->tv_sec)) {
		if ((unsigned)tv2->tv_usec >= (unsigned)tv1->tv_usec + 1000)
			return 1;
		else
			return 0;
	}

	if (unlikely(((unsigned)tv1->tv_sec == (unsigned)tv2->tv_sec + 1) &&
		     ((unsigned)tv1->tv_usec + 1000000 >= (unsigned)tv2->tv_usec + 1000)))
		return 0;
	else
		return 1;
}


/**** operators **********************************************************/


/*
 * Returns the time in ms elapsed between tv1 and tv2, assuming that tv1<=tv2.
 * Must not be used when either argument is eternity.
 */
#define tv_ms_elapsed __tv_ms_elapsed
unsigned long _tv_ms_elapsed(const struct timeval *tv1, const struct timeval *tv2);
static inline unsigned long __tv_ms_elapsed(const struct timeval *tv1, const struct timeval *tv2)
{
	unsigned long ret;

	ret  = ((signed long)(tv2->tv_sec  - tv1->tv_sec))  * 1000;
	ret += ((signed long)(tv2->tv_usec - tv1->tv_usec)) / 1000;
	return ret;
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Must not be used when either argument is eternity.
 */

#define tv_ms_remain __tv_ms_remain
unsigned long _tv_ms_remain(const struct timeval *tv1, const struct timeval *tv2);
static inline unsigned long __tv_ms_remain(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv_ms_cmp(tv1, tv2) >= 0)
		return 0; /* event elapsed */

	return __tv_ms_elapsed(tv1, tv2);
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Returns TIME_ETERNITY if tv2 is eternity.
 */
#define tv_ms_remain2 _tv_ms_remain2
unsigned long _tv_ms_remain2(const struct timeval *tv1, const struct timeval *tv2);
static inline unsigned long __tv_ms_remain2(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv_iseternity(tv2))
		return TIME_ETERNITY;

	return tv_ms_remain(tv1, tv2);
}

/*
 * adds <inc> to <from>, set the result to <tv> and returns a pointer <tv>
 */
#define tv_add _tv_add
struct timeval *_tv_add(struct timeval *tv, const struct timeval *from, const struct timeval *inc);
static inline struct timeval *__tv_add(struct timeval *tv, const struct timeval *from, const struct timeval *inc)
{
	tv->tv_usec = from->tv_usec + inc->tv_usec;
	tv->tv_sec  = from->tv_sec  + inc->tv_sec;
	if (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
	return tv;
}


/*
 * If <inc> is set, then add it to <from> and set the result to <tv>, then
 * return 1, otherwise return 0. It is meant to be used in if conditions.
 */
#define tv_add_ifset _tv_add_ifset
int _tv_add_ifset(struct timeval *tv, const struct timeval *from, const struct timeval *inc);
static inline int __tv_add_ifset(struct timeval *tv, const struct timeval *from, const struct timeval *inc)
{
	if (tv_iseternity(inc))
		return 0;
	tv->tv_usec = from->tv_usec + inc->tv_usec;
	tv->tv_sec  = from->tv_sec  + inc->tv_sec;
	if (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
	return 1;
}

/*
 * adds <inc> to <tv> and returns a pointer <tv>
 */
static inline struct timeval *__tv_add2(struct timeval *tv, const struct timeval *inc)
{
	tv->tv_usec += inc->tv_usec;
	tv->tv_sec  += inc->tv_sec;
	if (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
	return tv;
}


/*
 * Computes the remaining time between tv1=now and event=tv2. if tv2 is passed,
 * 0 is returned. The result is stored into tv.
 */
#define tv_remain _tv_remain
struct timeval *_tv_remain(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv);
static inline struct timeval *__tv_remain(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv)
{
	tv->tv_usec = tv2->tv_usec - tv1->tv_usec;
	tv->tv_sec  = tv2->tv_sec  - tv1->tv_sec;
	if ((signed)tv->tv_sec > 0) {
		if ((signed)tv->tv_usec < 0) {
			tv->tv_usec += 1000000;
			tv->tv_sec--;
		}
	} else if (tv->tv_sec == 0) {
		if ((signed)tv->tv_usec < 0)
			tv->tv_usec = 0;
	} else {
		tv->tv_sec = 0;
		tv->tv_usec = 0;
	}
 	return tv;
}


/*
 * Computes the remaining time between tv1=now and event=tv2. if tv2 is passed,
 * 0 is returned. The result is stored into tv. Returns ETERNITY if tv2 is
 * eternity.
 */
#define tv_remain2 _tv_remain2
struct timeval *_tv_remain2(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv);
static inline struct timeval *__tv_remain2(const struct timeval *tv1, const struct timeval *tv2, struct timeval *tv)
{
	if (tv_iseternity(tv2))
		return tv_eternity(tv);
	return __tv_remain(tv1, tv2, tv);
}


/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
#define tv_ms_add _tv_ms_add
struct timeval *_tv_ms_add(struct timeval *tv, const struct timeval *from, int ms);
static inline struct timeval *__tv_ms_add(struct timeval *tv, const struct timeval *from, int ms)
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

/* Initialize <timer>. */
static inline void tot_time_reset(struct tot_time *timer)
{
	timer->curr = 0;
	timer->tot = 0;
}

/* Start to account with <timer>. No-op if already started. */
static inline void tot_time_start(struct tot_time *timer)
{
	if (!timer->curr)
		timer->curr = now_ms;
}

/* Stop <timer> accounting and update its total. No-op if already stopped. */
static inline void tot_time_stop(struct tot_time *timer)
{
	if (timer->curr) {
		timer->tot += now_ms - timer->curr;
		timer->curr = 0;
	}
}

/* Retrieve the total value accounted by <timer>, including the current period
 * if currently started.
 */
static inline uint32_t tot_time_read(const struct tot_time *timer)
{
	uint32_t value = timer->tot;
	if (timer->curr)
		value += now_ms - timer->curr;
	return value;
}

#endif /* _HAPROXY_TIME_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
