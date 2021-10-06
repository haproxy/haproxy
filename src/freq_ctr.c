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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
