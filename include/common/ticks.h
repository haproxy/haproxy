/*
  include/common/ticks.h
  Functions and macros for manipulation of expiration timers

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
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

/*
 * Using a mix of milliseconds and timeval for internal timers is expensive and
 * overkill, because we don't need such a precision to compute timeouts.
 * So we're converting them to "ticks". Right now, one tick equals one
 * millisecond, but that might change in the future. Ticks are stored as 32bit
 * values, and sorted in four 30bit-wide rotating arrays, which means that any
 * timer may be 2^30 ms in the future, or 12.4 days. The ticks are designed to
 * wrap after they pass 2^32. That means that we cannot directly compare them,
 * but we can check the sign of their difference.
 *
 * We must both support absolute dates (well in fact, dates relative to now+/-
 * 12 days), and intervals (for timeouts). Both types need an "eternity" magic
 * value. For optimal code generation, we'll use zero as the magic value
 * indicating that an expiration timer or a timeout is not set. We have to
 * check that we don't return this value when adding timeouts to <now>. If a
 * computation returns 0, we must increase it to 1 (which will push the timeout
 * 1 ms further).
 */

#ifndef _COMMON_TICKS_H
#define _COMMON_TICKS_H

#include <common/config.h>
#include <common/standard.h>

#define TICK_ETERNITY   0

/* right now, ticks are milliseconds. Both negative ms and negative ticks
 * indicate eternity.
 */
#define MS_TO_TICKS(ms) (ms)
#define TICKS_TO_MS(tk) (tk)

/* return 1 if tick is set, otherwise 0 */
static inline int tick_isset(int expire)
{
	return expire != 0;
}

/* Add <timeout> to <now>, and return the resulting expiration date.
 * <timeout> will not be checked for null values.
 */
static inline int tick_add(int now, int timeout)
{
	now += timeout;
	if (unlikely(!now))
		now++;    /* unfortunate value */
	return now;
}

/* add <timeout> to <now> if it is set, otherwise set it to eternity.
 * Return the resulting expiration date.
 */
static inline int tick_add_ifset(int now, int timeout)
{
	if (!timeout)
		return TICK_ETERNITY;
	return tick_add(now, timeout);
}

/* return 1 if timer <timer> is expired at date <now>, otherwise zero */
static inline int tick_is_expired(int timer, int now)
{
	if (unlikely(!tick_isset(timer)))
		return 0;
	if (unlikely((timer - now) <= 0))
		return 1;
	return 0;
}

/* return the first one of the two timers, both of which may be infinite */
static inline int tick_first(int t1, int t2)
{
	if (!tick_isset(t1))
		return t2;
	if (!tick_isset(t2))
		return t1;
	if ((t1 - t2) <= 0)
		return t1;
	else
		return t2;
}

/* return the number of ticks remaining from <now> to <exp>, or zero if expired */
static inline int tick_remain(int now, int exp)
{
	if (tick_is_expired(exp, now))
		return 0;
	return exp - now;
}

#endif /* _COMMON_TICKS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
