/*
  include/common/ticks.h
  Functions and macros for manipulation of expiration timers

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
  
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
 * So we're converting them to "ticks".
 *
 * A tick is a representation of a date relative to another one, and is
 * measured in milliseconds. The natural usage is to represent an absolute date
 * relative to the current date. Since it is not practical to update all values
 * each time the current date changes, instead we use the absolute date rounded
 * down to fit in a tick. We then have to compare a tick to the current date to
 * know whether it is in the future or in the past. If a tick is below the
 * current date, it is in the past. If it is above, it is in the future. The
 * values will wrap so we can't compare that easily, instead we check the sign
 * of the difference between a tick and the current date.
 *
 * Proceeding like this allows us to manipulate dates that are stored in
 * scalars with enough precision and range. For this reason, we store ticks in
 * 32-bit integers. This is enough to handle dates that are between 24.85 days
 * in the past and as much in the future.
 * 
 * We must both support absolute dates (well in fact, dates relative to now+/-
 * 24 days), and intervals (for timeouts). Both types need an "eternity" magic
 * value. For optimal code generation, we'll use zero as the magic value
 * indicating that an expiration timer or a timeout is not set. We have to
 * check that we don't return this value when adding timeouts to <now>. If a
 * computation returns 0, we must increase it to 1 (which will push the timeout
 * 1 ms further). For this reason, timeouts must not be added by hand but via
 * the dedicated tick_add() function.
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

/* return 1 if timer <t1> is before <t2>, none of which can be infinite. */
static inline int tick_is_lt(int t1, int t2)
{
	return (t1 - t2) < 0;
}

/* return 1 if timer <t1> is before or equal to <t2>, none of which can be infinite. */
static inline int tick_is_le(int t1, int t2)
{
	return (t1 - t2) <= 0;
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

/* return the first one of the two timers, where only the first one may be infinite */
static inline int tick_first_2nz(int t1, int t2)
{
	if (!tick_isset(t1))
		return t2;
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
