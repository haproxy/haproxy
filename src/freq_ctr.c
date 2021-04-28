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
