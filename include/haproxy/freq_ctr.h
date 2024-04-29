/*
 * include/haproxy/freq_ctr.h
 * This file contains macros and inline functions for frequency counters.
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

#ifndef _HAPROXY_FREQ_CTR_H
#define _HAPROXY_FREQ_CTR_H

#include <haproxy/api.h>
#include <haproxy/freq_ctr-t.h>
#include <haproxy/intops.h>
#include <haproxy/ticks.h>

/* exported functions from freq_ctr.c */
ullong freq_ctr_total(const struct freq_ctr *ctr, uint period, int pend);
int freq_ctr_overshoot_period(const struct freq_ctr *ctr, uint period, uint freq);
uint update_freq_ctr_period_slow(struct freq_ctr *ctr, uint period, uint inc);

/* Only usable during single threaded startup phase. */
static inline void preload_freq_ctr(struct freq_ctr *ctr, uint value)
{
	ctr->curr_ctr = 0;
	ctr->prev_ctr = value;
	ctr->curr_tick = now_ms & ~1;
}

/* Update a frequency counter by <inc> incremental units. It is automatically
 * rotated if the period is over. It is important that it correctly initializes
 * a null area.
 */
static inline uint update_freq_ctr_period(struct freq_ctr *ctr, uint period, uint inc)
{
	uint curr_tick;

	/* our local clock (now_ms) is most of the time strictly equal to
	 * global_now_ms, and during the edge of the millisecond, global_now_ms
	 * might have been pushed further by another thread. Given that
	 * accessing this shared variable is extremely expensive, we first try
	 * to use our local date, which will be good almost every time. And we
	 * only switch to the global clock when we're out of the period so as
	 * to never put a date in the past there.
	 */
	curr_tick  = HA_ATOMIC_LOAD(&ctr->curr_tick);
	if (likely(now_ms - curr_tick < period))
		return HA_ATOMIC_ADD_FETCH(&ctr->curr_ctr, inc);

	return update_freq_ctr_period_slow(ctr, period, inc);
}

/* Update a 1-sec frequency counter by <inc> incremental units. It is automatically
 * rotated if the period is over. It is important that it correctly initializes
 * a null area.
 */
static inline unsigned int update_freq_ctr(struct freq_ctr *ctr, unsigned int inc)
{
	return update_freq_ctr_period(ctr, MS_TO_TICKS(1000), inc);
}

/* Reads a frequency counter taking history into account for missing time in
 * current period. The period has to be passed in number of ticks and must
 * match the one used to feed the counter. The counter value is reported for
 * current global date. The return value has the same precision as one input
 * data sample, so low rates over the period will be inaccurate but still
 * appropriate for max checking. One trick we use for low values is to specially
 * handle the case where the rate is between 0 and 1 in order to avoid flapping
 * while waiting for the next event.
 *
 * For immediate limit checking, it's recommended to use freq_ctr_period_remain()
 * instead which does not have the flapping correction, so that even frequencies
 * as low as one event/period are properly handled.
 */
static inline uint read_freq_ctr_period(const struct freq_ctr *ctr, uint period)
{
	ullong total = freq_ctr_total(ctr, period, -1);

	return div64_32(total, period);
}

/* same as read_freq_ctr_period() above except that floats are used for the
 * output so that low rates can be more precise.
 */
static inline double read_freq_ctr_period_flt(const struct freq_ctr *ctr, uint period)
{
	ullong total = freq_ctr_total(ctr, period, -1);

	return (double)total / (double)period;
}

/* Read a 1-sec frequency counter taking history into account for missing time
 * in current period.
 */
static inline unsigned int read_freq_ctr(const struct freq_ctr *ctr)
{
	return read_freq_ctr_period(ctr, MS_TO_TICKS(1000));
}

/* same as read_freq_ctr() above except that floats are used for the
 * output so that low rates can be more precise.
 */
static inline double read_freq_ctr_flt(const struct freq_ctr *ctr)
{
	return read_freq_ctr_period_flt(ctr, MS_TO_TICKS(1000));
}

/* Returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> events per period, and taking into account that
 * <pend> events are already known to be pending. Returns 0 if limit was reached.
 */
static inline uint freq_ctr_remain_period(const struct freq_ctr *ctr, uint period, uint freq, uint pend)
{
	ullong total = freq_ctr_total(ctr, period, pend);
	uint avg     = div64_32(total, period);

	if (avg > freq)
		avg = freq;
	return freq - avg;
}

/* returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> and taking into account that <pend> events are
 * already known to be pending. Returns 0 if limit was reached.
 */
static inline unsigned int freq_ctr_remain(const struct freq_ctr *ctr, unsigned int freq, unsigned int pend)
{
	return freq_ctr_remain_period(ctr, MS_TO_TICKS(1000), freq, pend);
}

/* return the expected wait time in ms before the next event may occur,
 * respecting frequency <freq>, and assuming there may already be some pending
 * events. It returns zero if we can proceed immediately, otherwise the wait
 * time, which will be rounded down 1ms for better accuracy, with a minimum
 * of one ms.
 */
static inline uint next_event_delay_period(const struct freq_ctr *ctr, uint period, uint freq, uint pend)
{
	ullong total = freq_ctr_total(ctr, period, pend);
	ullong limit = (ullong)freq * period;
	uint wait;

	if (total < limit)
		return 0;

	/* too many events already, let's count how long to wait before they're
	 * processed. For this we'll subtract from the number of pending events
	 * the ones programmed for the current period, to know how long to wait
	 * for the next period. Each event takes period/freq ticks.
	 */
	total -= limit;
	wait = div64_32(total, (freq ? freq : 1));
	return MAX(wait, 1);
}

/* Returns the expected wait time in ms before the next event may occur,
 * respecting frequency <freq> over 1 second, and assuming there may already be
 * some pending events. It returns zero if we can proceed immediately, otherwise
 * the wait time, which will be rounded down 1ms for better accuracy, with a
 * minimum of one ms.
 */
static inline unsigned int next_event_delay(const struct freq_ctr *ctr, unsigned int freq, unsigned int pend)
{
	return next_event_delay_period(ctr, MS_TO_TICKS(1000), freq, pend);
}

/* While the functions above report average event counts per period, we are
 * also interested in average values per event. For this we use a different
 * method. The principle is to rely on a long tail which sums the new value
 * with a fraction of the previous value, resulting in a sliding window of
 * infinite length depending on the precision we're interested in.
 *
 * The idea is that we always keep (N-1)/N of the sum and add the new sampled
 * value. The sum over N values can be computed with a simple program for a
 * constant value 1 at each iteration :
 *
 *     N
 *   ,---
 *    \       N - 1              e - 1
 *     >  ( --------- )^x ~= N * -----
 *    /         N                  e
 *   '---
 *   x = 1
 *
 * Note: I'm not sure how to demonstrate this but at least this is easily
 * verified with a simple program, the sum equals N * 0.632120 for any N
 * moderately large (tens to hundreds).
 *
 * Inserting a constant sample value V here simply results in :
 *
 *    sum = V * N * (e - 1) / e
 *
 * But we don't want to integrate over a small period, but infinitely. Let's
 * cut the infinity in P periods of N values. Each period M is exactly the same
 * as period M-1 with a factor of ((N-1)/N)^N applied. A test shows that given a
 * large N :
 *
 *      N - 1           1
 *   ( ------- )^N ~=  ---
 *        N             e
 *
 * Our sum is now a sum of each factor times  :
 *
 *    N*P                                     P
 *   ,---                                   ,---
 *    \         N - 1               e - 1    \     1
 *     >  v ( --------- )^x ~= VN * -----  *  >   ---
 *    /           N                   e      /    e^x
 *   '---                                   '---
 *   x = 1                                  x = 0
 *
 * For P "large enough", in tests we get this :
 *
 *    P
 *  ,---
 *   \     1        e
 *    >   --- ~=  -----
 *   /    e^x     e - 1
 *  '---
 *  x = 0
 *
 * This simplifies the sum above :
 *
 *    N*P
 *   ,---
 *    \         N - 1
 *     >  v ( --------- )^x = VN
 *    /           N
 *   '---
 *   x = 1
 *
 * So basically by summing values and applying the last result an (N-1)/N factor
 * we just get N times the values over the long term, so we can recover the
 * constant value V by dividing by N. In order to limit the impact of integer
 * overflows, we'll use this equivalence which saves us one multiply :
 *
 *               N - 1                   1             x0
 *    x1 = x0 * -------   =  x0 * ( 1 - --- )  = x0 - ----
 *                 N                     N              N
 *
 * And given that x0 is discrete here we'll have to saturate the values before
 * performing the divide, so the value insertion will become :
 *
 *               x0 + N - 1
 *    x1 = x0 - ------------
 *                    N
 *
 * A value added at the entry of the sliding window of N values will thus be
 * reduced to 1/e or 36.7% after N terms have been added. After a second batch,
 * it will only be 1/e^2, or 13.5%, and so on. So practically speaking, each
 * old period of N values represents only a quickly fading ratio of the global
 * sum :
 *
 *   period    ratio
 *     1       36.7%
 *     2       13.5%
 *     3       4.98%
 *     4       1.83%
 *     5       0.67%
 *     6       0.25%
 *     7       0.09%
 *     8       0.033%
 *     9       0.012%
 *    10       0.0045%
 *
 * So after 10N samples, the initial value has already faded out by a factor of
 * 22026, which is quite fast. If the sliding window is 1024 samples wide, it
 * means that a sample will only count for 1/22k of its initial value after 10k
 * samples went after it, which results in half of the value it would represent
 * using an arithmetic mean. The benefit of this method is that it's very cheap
 * in terms of computations when N is a power of two. This is very well suited
 * to record response times as large values will fade out faster than with an
 * arithmetic mean and will depend on sample count and not time.
 *
 * Demonstrating all the above assumptions with maths instead of a program is
 * left as an exercise for the reader.
 */

/* Adds sample value <v> to sliding window sum <sum> configured for <n> samples.
 * The sample is returned. Better if <n> is a power of two. This function is
 * thread-safe.
 */
static inline unsigned int swrate_add(unsigned int *sum, unsigned int n, unsigned int v)
{
	unsigned int new_sum, old_sum;

	old_sum = *sum;
	do {
		new_sum = old_sum - (old_sum + n - 1) / n + v;
	} while (!HA_ATOMIC_CAS(sum, &old_sum, new_sum) && __ha_cpu_relax());
	return new_sum;
}

/* Adds sample value <v> to sliding window sum <sum> configured for <n> samples.
 * The sample is returned. Better if <n> is a power of two. This function is
 * thread-safe.
 * This function should give better accuracy than swrate_add when number of
 * samples collected is lower than nominal window size. In such circumstances
 * <n> should be set to 0.
 */
static inline unsigned int swrate_add_dynamic(unsigned int *sum, unsigned int n, unsigned int v)
{
	unsigned int new_sum, old_sum;

	old_sum = *sum;
	do {
		new_sum = old_sum - (n ? (old_sum + n - 1) / n : 0) + v;
	} while (!HA_ATOMIC_CAS(sum, &old_sum, new_sum) && __ha_cpu_relax());
	return new_sum;
}

/* Adds sample value <v> spanning <s> samples to sliding window sum <sum>
 * configured for <n> samples, where <n> is supposed to be "much larger" than
 * <s>. The sample is returned. Better if <n> is a power of two. Note that this
 * is only an approximate. Indeed, as can be seen with two samples only over a
 * 8-sample window, the original function would return :
 *  sum1 = sum  - (sum + 7) / 8 + v
 *  sum2 = sum1 - (sum1 + 7) / 8 + v
 *       = (sum - (sum + 7) / 8 + v) - (sum - (sum + 7) / 8 + v + 7) / 8 + v
 *      ~= 7sum/8 - 7/8 + v - sum/8 + sum/64 - 7/64 - v/8 - 7/8 + v
 *      ~= (3sum/4 + sum/64) - (7/4 + 7/64) + 15v/8
 *
 * while the function below would return :
 *  sum  = sum + 2*v - (sum + 8) * 2 / 8
 *       = 3sum/4 + 2v - 2
 *
 * this presents an error of ~ (sum/64 + 9/64 + v/8) = (sum+n+1)/(n^s) + v/n
 *
 * Thus the simplified function effectively replaces a part of the history with
 * a linear sum instead of applying the exponential one. But as long as s/n is
 * "small enough", the error fades away and remains small for both small and
 * large values of n and s (typically < 0.2% measured).  This function is
 * thread-safe.
 */
static inline unsigned int swrate_add_scaled(unsigned int *sum, unsigned int n, unsigned int v, unsigned int s)
{
	unsigned int new_sum, old_sum;

	old_sum = *sum;
	do {
		new_sum = old_sum + v * s - div64_32((unsigned long long)old_sum * s + n - 1, n);
	} while (!HA_ATOMIC_CAS(sum, &old_sum, new_sum) && __ha_cpu_relax());
	return new_sum;
}

/* opportunistic versions of the functions above: an attempt is made to update
 * the value, but in case of contention, it's not retried. This is fine when
 * rough estimates are needed and speed is preferred over accuracy.
 */

static inline uint swrate_add_opportunistic(uint *sum, uint n, uint v)
{
	uint new_sum, old_sum;

	old_sum = *sum;
	new_sum = old_sum - (old_sum + n - 1) / n + v;
	HA_ATOMIC_CAS(sum, &old_sum, new_sum);
	return new_sum;
}

static inline uint swrate_add_dynamic_opportunistic(uint *sum, uint n, uint v)
{
	uint new_sum, old_sum;

	old_sum = *sum;
	new_sum = old_sum - (n ? (old_sum + n - 1) / n : 0) + v;
	HA_ATOMIC_CAS(sum, &old_sum, new_sum);
	return new_sum;
}

static inline uint swrate_add_scaled_opportunistic(uint *sum, uint n, uint v, uint s)
{
	uint new_sum, old_sum;

	old_sum = *sum;
	new_sum = old_sum + v * s - div64_32((unsigned long long)old_sum * s + n - 1, n);
	HA_ATOMIC_CAS(sum, &old_sum, new_sum);
	return new_sum;
}

/* Returns the average sample value for the sum <sum> over a sliding window of
 * <n> samples. Better if <n> is a power of two. It must be the same <n> as the
 * one used above in all additions.
 */
static inline unsigned int swrate_avg(unsigned int sum, unsigned int n)
{
	return (sum + n - 1) / n;
}

#endif /* _HAPROXY_FREQ_CTR_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
  */
