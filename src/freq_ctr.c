/*
 * Event rate calculation functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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
	unsigned int cur;
	if (unlikely(ctr->curr_sec != now.tv_sec))
		rotate_freq_ctr(ctr);

	cur = ctr->curr_ctr;
	if (ctr->prev_ctr <= 1 && !ctr->curr_ctr)
		return ctr->prev_ctr; /* very low rate, avoid flapping */

	return cur + mul32hi(ctr->prev_ctr, ~curr_sec_ms_scaled);
}

/* returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> and taking into account that <pend> events are
 * already known to be pending. Returns 0 if limit was reached.
 */
unsigned int freq_ctr_remain(struct freq_ctr *ctr, unsigned int freq, unsigned int pend)
{
	unsigned int cur;
	if (unlikely(ctr->curr_sec != now.tv_sec))
		rotate_freq_ctr(ctr);

	cur = mul32hi(ctr->prev_ctr, ~curr_sec_ms_scaled);
	cur += ctr->curr_ctr + pend;

	if (cur >= freq)
		return 0;
	return freq - cur;
}

/* return the expected wait time in ms before the next event may occur,
 * respecting frequency <freq>, and assuming there may already be some pending
 * events. It returns zero if we can proceed immediately, otherwise the wait
 * time, which will be rounded down 1ms for better accuracy, with a minimum
 * of one ms.
 */
unsigned int next_event_delay(struct freq_ctr *ctr, unsigned int freq, unsigned int pend)
{
	unsigned int cur, wait;

	if (unlikely(ctr->curr_sec != now.tv_sec))
		rotate_freq_ctr(ctr);

	cur = mul32hi(ctr->prev_ctr, ~curr_sec_ms_scaled);
	cur += ctr->curr_ctr + pend;

	if (cur < freq)
		return 0;

	wait = 999 / cur;
	return MAX(wait, 1);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
