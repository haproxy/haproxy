/*
 * Event rate calculation functions.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/tools.h>
#include <proto/freq_ctr.h>

/* Read a frequency counter taking history into account for missing time in
 * current period. Current second is sub-divided in 1000 chunks of one ms,
 * and the missing ones are read proportionally from previous value. The
 * return value has the same precision as one input data sample, so low rates
 * will be inaccurate still appropriate for max checking. One trick we use for
 * low values is to specially handle the case where the rate is between 0 and 1
 * in order to avoid flapping while waiting for the next event.
 *
 * For immediate limit checking, it's recommended to use freq_ctr_remain() and
 * next_event_delay() instead which do not have the flapping correction, so
 * that even frequencies as low as one event/period are properly handled.
 */
unsigned int read_freq_ctr(struct freq_ctr *ctr)
{
	unsigned int curr, past;
	unsigned int age;

	age = now.tv_sec - ctr->curr_sec;
	if (unlikely(age > 1))
		return 0;

	curr = 0;		
	past = ctr->curr_ctr;
	if (likely(!age)) {
		curr = past;
		past = ctr->prev_ctr;
	}

	if (past <= 1 && !curr)
		return past; /* very low rate, avoid flapping */

	return curr + mul32hi(past, ms_left_scaled);
}

/* returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> and taking into account that <pend> events are
 * already known to be pending. Returns 0 if limit was reached.
 */
unsigned int freq_ctr_remain(struct freq_ctr *ctr, unsigned int freq, unsigned int pend)
{
	unsigned int curr, past;
	unsigned int age;

	curr = 0;		
	age = now.tv_sec - ctr->curr_sec;

	if (likely(age <= 1)) {
		past = ctr->curr_ctr;
		if (likely(!age)) {
			curr = past;
			past = ctr->prev_ctr;
		}
		curr += mul32hi(past, ms_left_scaled);
	}
	curr += pend;

	if (curr >= freq)
		return 0;
	return freq - curr;
}

/* return the expected wait time in ms before the next event may occur,
 * respecting frequency <freq>, and assuming there may already be some pending
 * events. It returns zero if we can proceed immediately, otherwise the wait
 * time, which will be rounded down 1ms for better accuracy, with a minimum
 * of one ms.
 */
unsigned int next_event_delay(struct freq_ctr *ctr, unsigned int freq, unsigned int pend)
{
	unsigned int curr, past;
	unsigned int wait, age;

	past = 0;
	curr = 0;		
	age = now.tv_sec - ctr->curr_sec;

	if (likely(age <= 1)) {
		past = ctr->curr_ctr;
		if (likely(!age)) {
			curr = past;
			past = ctr->prev_ctr;
		}
		curr += mul32hi(past, ms_left_scaled);
	}
	curr += pend;

	if (curr < freq)
		return 0;

	wait = 999 / curr;
	return MAX(wait, 1);
}

/* Reads a frequency counter taking history into account for missing time in
 * current period. The period has to be passed in number of ticks and must
 * match the one used to feed the counter. The counter value is reported for
 * current date (now_ms). The return value has the same precision as one input
 * data sample, so low rates over the period will be inaccurate but still
 * appropriate for max checking. One trick we use for low values is to specially
 * handle the case where the rate is between 0 and 1 in order to avoid flapping
 * while waiting for the next event.
 *
 * For immediate limit checking, it's recommended to use freq_ctr_period_remain()
 * instead which does not have the flapping correction, so that even frequencies
 * as low as one event/period are properly handled.
 *
 * For measures over a 1-second period, it's better to use the implicit functions
 * above.
 */
unsigned int read_freq_ctr_period(struct freq_ctr_period *ctr, unsigned int period)
{
	unsigned int curr, past;
	unsigned int remain;

	curr = ctr->curr_ctr;
	past = ctr->prev_ctr;

	remain = ctr->curr_tick + period - now_ms;
	if (unlikely((int)remain < 0)) {
		/* We're past the first period, check if we can still report a
		 * part of last period or if we're too far away.
		 */
		remain += period;
		if ((int)remain < 0)
			return 0;
		past = curr;
		curr = 0;
	}
	if (past <= 1 && !curr)
		return past; /* very low rate, avoid flapping */

	curr += div64_32((unsigned long long)past * remain, period);
	return curr;
}

/* Returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> events per period, and taking into account that
 * <pend> events are already known to be pending. Returns 0 if limit was reached.
 */
unsigned int freq_ctr_remain_period(struct freq_ctr_period *ctr, unsigned int period,
				    unsigned int freq, unsigned int pend)
{
	unsigned int curr, past;
	unsigned int remain;

	curr = ctr->curr_ctr;
	past = ctr->prev_ctr;

	remain = ctr->curr_tick + period - now_ms;
	if (likely((int)remain < 0)) {
		/* We're past the first period, check if we can still report a
		 * part of last period or if we're too far away.
		 */
		past = curr;
		curr = 0;
		remain += period;
		if ((int)remain < 0)
			past = 0;
	}
	if (likely(past))
		curr += div64_32((unsigned long long)past * remain, period);

	curr += pend;
	freq -= curr;
	if ((int)freq < 0)
		freq = 0;
	return freq;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
