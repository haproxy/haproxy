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
#include <haproxy/tools.h>

/* Update a frequency counter by <inc> incremental units. It is automatically
 * rotated if the period is over. It is important that it correctly initializes
 * a null area. This one works on frequency counters which have a period
 * different from one second. It relies on the process-wide clock that is
 * guaranteed to be monotonic. It's important to avoid forced rotates between
 * threads. A faster wrapper (update_freq_ctr_period) should be used instead,
 * which uses the thread's local time whenever possible and falls back to this
 * one when needed (less than 0.003% of the time).
 */
uint update_freq_ctr_period_slow(struct freq_ctr *ctr, uint period, uint inc)
{
	uint curr_tick;
	uint32_t now_ms_tmp;

	/* atomically update the counter if still within the period, even if
	 * a rotation is in progress (no big deal).
	 */
	for (;; __ha_cpu_relax()) {
		curr_tick  = HA_ATOMIC_LOAD(&ctr->curr_tick);
		now_ms_tmp = HA_ATOMIC_LOAD(&global_now_ms);

		if (now_ms_tmp - curr_tick < period)
			return HA_ATOMIC_ADD_FETCH(&ctr->curr_ctr, inc);

		/* a rotation is needed. While extremely rare, contention may
		 * happen because it will be triggered on time, and all threads
		 * see the time change simultaneously.
		 */
		if (!(curr_tick & 1) &&
		    HA_ATOMIC_CAS(&ctr->curr_tick, &curr_tick, curr_tick | 0x1))
			break;
	}

	/* atomically switch the new period into the old one without losing any
	 * potential concurrent update. We're the only one performing the rotate
	 * (locked above), others are only adding positive values to curr_ctr.
	 */
	HA_ATOMIC_STORE(&ctr->prev_ctr, HA_ATOMIC_XCHG(&ctr->curr_ctr, inc));
	curr_tick += period;
	if (likely(now_ms_tmp - curr_tick >= period)) {
		/* we missed at least two periods */
		HA_ATOMIC_STORE(&ctr->prev_ctr, 0);
		curr_tick = now_ms_tmp;
	}

	/* release the lock and update the time in case of rotate. */
	HA_ATOMIC_STORE(&ctr->curr_tick, curr_tick & ~1);
	return inc;
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
ullong freq_ctr_total(const struct freq_ctr *ctr, uint period, int pend)
{
	ullong curr, past, old_curr, old_past;
	uint tick, old_tick;
	int remain;

	tick = HA_ATOMIC_LOAD(&ctr->curr_tick);
	curr = HA_ATOMIC_LOAD(&ctr->curr_ctr);
	past = HA_ATOMIC_LOAD(&ctr->prev_ctr);

	while (1) {
		if (tick & 0x1) // change in progress
			goto redo0;

		old_tick = tick;
		old_curr = curr;
		old_past = past;

		/* now let's load the values a second time and make sure they
		 * did not change, which will indicate it was a stable reading.
		 */

		tick = HA_ATOMIC_LOAD(&ctr->curr_tick);
		if (tick & 0x1) // change in progress
			goto redo0;

		if (tick != old_tick)
			goto redo1;

		curr = HA_ATOMIC_LOAD(&ctr->curr_ctr);
		if (curr != old_curr)
			goto redo2;

		past = HA_ATOMIC_LOAD(&ctr->prev_ctr);
		if (past != old_past)
			goto redo3;

		/* all values match between two loads, they're stable, let's
		 * quit now.
		 */
		break;
	redo0:
		tick = HA_ATOMIC_LOAD(&ctr->curr_tick);
	redo1:
		curr = HA_ATOMIC_LOAD(&ctr->curr_ctr);
	redo2:
		past = HA_ATOMIC_LOAD(&ctr->prev_ctr);
	redo3:
		__ha_cpu_relax();
	};

	remain = tick + period - HA_ATOMIC_LOAD(&global_now_ms);
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

/* Returns the excess of events (may be negative) over the current period for
 * target frequency <freq>. It returns 0 if the counter is in the future or if
 * the counter is empty. The result considers the position of the current time
 * within the current period.
 *
 * The caller may safely add new events if result is negative or null.
 */
int freq_ctr_overshoot_period(const struct freq_ctr *ctr, uint period, uint freq)
{
	ullong curr, old_curr;
	uint tick, old_tick;
	int elapsed;

	tick = HA_ATOMIC_LOAD(&ctr->curr_tick);
	curr = HA_ATOMIC_LOAD(&ctr->curr_ctr);

	while (1) {
		if (tick & 0x1) // change in progress
			goto redo0;

		old_tick = tick;
		old_curr = curr;

		/* now let's load the values a second time and make sure they
		 * did not change, which will indicate it was a stable reading.
		 */

		tick = HA_ATOMIC_LOAD(&ctr->curr_tick);
		if (tick & 0x1) // change in progress
			goto redo0;

		if (tick != old_tick)
			goto redo1;

		curr = HA_ATOMIC_LOAD(&ctr->curr_ctr);
		if (curr != old_curr)
			goto redo2;

		/* all values match between two loads, they're stable, let's
		 * quit now.
		 */
		break;
	redo0:
		tick = HA_ATOMIC_LOAD(&ctr->curr_tick);
	redo1:
		curr = HA_ATOMIC_LOAD(&ctr->curr_ctr);
	redo2:
		__ha_cpu_relax();
	};

	if (!curr && !tick) {
		/* The counter is empty, there is no overshoot */
		return 0;
	}

	elapsed = HA_ATOMIC_LOAD(&global_now_ms) - tick;
	if (unlikely(elapsed < 0 || elapsed > period)) {
		/* The counter is in the future or the elapsed time is higher than the period, there is no overshoot */
		return 0;
	}

	return curr - div64_32((uint64_t)elapsed * freq, period);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
