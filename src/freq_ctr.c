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

#include <haproxy/api.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

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
	unsigned int curr, past, _curr, _past;
	unsigned int age, curr_sec, _curr_sec;

	while (1) {
		_curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		_past = ctr->prev_ctr;
		__ha_compiler_barrier();
		_curr_sec = ctr->curr_sec;
		__ha_compiler_barrier();
		if (_curr_sec & 0x80000000)
			continue;
		curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		past = ctr->prev_ctr;
		__ha_compiler_barrier();
		curr_sec = ctr->curr_sec;
		__ha_compiler_barrier();
		if (_curr == curr && _past == past && _curr_sec == curr_sec)
			break;
	}

	age = (global_now >> 32) - curr_sec;
	if (unlikely(age > 1))
		return 0;

	if (unlikely(age)) {
		past = curr;
		curr = 0;
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
	unsigned int curr, past, _curr, _past;
	unsigned int age, curr_sec, _curr_sec;

	while (1) {
		_curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		_past = ctr->prev_ctr;
		__ha_compiler_barrier();
		_curr_sec = ctr->curr_sec;
		__ha_compiler_barrier();
		if (_curr_sec & 0x80000000)
			continue;
		curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		past = ctr->prev_ctr;
		__ha_compiler_barrier();
		curr_sec = ctr->curr_sec;
		__ha_compiler_barrier();
		if (_curr == curr && _past == past && _curr_sec == curr_sec)
			break;
	}

	age = (global_now >> 32) - curr_sec;
	if (unlikely(age > 1))
		curr = 0;
	else {
		if (unlikely(age == 1)) {
			past = curr;
			curr = 0;
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
	unsigned int curr, past, _curr, _past;
	unsigned int wait, age, curr_sec, _curr_sec;

	while (1) {
		_curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		_past = ctr->prev_ctr;
		__ha_compiler_barrier();
		_curr_sec = ctr->curr_sec;
		__ha_compiler_barrier();
		if (_curr_sec & 0x80000000)
			continue;
		curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		past = ctr->prev_ctr;
		__ha_compiler_barrier();
		curr_sec = ctr->curr_sec;
		__ha_compiler_barrier();
		if (_curr == curr && _past == past && _curr_sec == curr_sec)
			break;
	}

	age = (global_now >> 32) - curr_sec;
	if (unlikely(age > 1))
		curr = 0;
	else {
		if (unlikely(age == 1)) {
			past = curr;
			curr = 0;
		}
		curr += mul32hi(past, ms_left_scaled);
	}
	curr += pend;

	if (curr < freq)
		return 0;

	/* too many events already, let's count how long to wait before they're
	 * processed. For this we'll subtract from the number of pending events
	 * the ones programmed for the current period, to know how long to wait
	 * for the next period. Each event takes 1/freq sec, thus 1000/freq ms.
	 */
	curr -= freq;
	wait = curr * 1000 / (freq ? freq : 1);
	return MAX(wait, 1);
}

/* Returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> events per period, and taking into account that
 * <pend> events are already known to be pending. Returns 0 if limit was reached.
 */
unsigned int freq_ctr_remain_period(struct freq_ctr_period *ctr, unsigned int period,
				    unsigned int freq, unsigned int pend)
{
	unsigned int _curr, _past, curr, past;
	unsigned int remain, _curr_tick, curr_tick;

	while (1) {
		_curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		_past = ctr->prev_ctr;
		__ha_compiler_barrier();
		_curr_tick = ctr->curr_tick;
		__ha_compiler_barrier();
		if (_curr_tick & 0x1)
			continue;
		curr = ctr->curr_ctr;
		__ha_compiler_barrier();
		past = ctr->prev_ctr;
		__ha_compiler_barrier();
		curr_tick = ctr->curr_tick;
		__ha_compiler_barrier();
		if (_curr == curr && _past == past && _curr_tick == curr_tick)
			break;
	};

	remain = curr_tick + period - global_now_ms;
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

/* Returns the total number of events over the current + last period, including
 * a number of already pending events <pend>. The average frequency will be
 * obtained by dividing the output by <period>. This is essentially made to
 * ease implementation of higher-level read functions.
 *
 * As a special case, if pend < 0, it's assumed there are no pending
 * events and a flapping correction must be applied at the end. This is used by
 * read_freq_ctr_period() to avoid reporting ups and downs on low-frequency
 * events when the past value is <= 1.
 */
ullong freq_ctr_total(struct freq_ctr_period *ctr, uint period, int pend)
{
	ullong curr, past;
	uint curr_tick;
	int remain;

	for (;; __ha_cpu_relax()) {
		curr = ctr->curr_ctr;
		past = ctr->prev_ctr;
		curr_tick = ctr->curr_tick;

		/* now let's make sure the second loads retrieve the most
		 * up-to-date values. If no value changed after a load barrier,
		 * we're certain the values we got were stable.
		 */
		__ha_barrier_load();

		if (curr_tick & 0x1)
			continue;

		if (curr != ctr->curr_ctr)
			continue;

		if (past != ctr->prev_ctr)
			continue;

		if (curr_tick != ctr->curr_tick)
			continue;
		break;
	};

	remain = curr_tick + period - global_now_ms;
	if (unlikely(remain < 0)) {
		/* We're past the first period, check if we can still report a
		 * part of last period or if we're too far away.
		 */
		remain += period;
		past = (remain >= 0) ? curr : 0;
		curr = 0;
	}

	if (pend < 0) {
		/* enable flapping correction at very low rates */
		pend = 0;
		if (!curr && past <= 1)
			return past * period;
	}

	/* compute the total number of confirmed events over the period */
	return past * remain + (curr + pend) * period;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
