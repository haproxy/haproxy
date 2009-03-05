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
#include <proto/freq_ctr.h>

/* Read a frequency counter taking history into account for missing time in
 * current period. Current second is sub-divided in 1000 chunks of one ms,
 * and the missing ones are read proportionally from previous value. The
 * return value has the same precision as one input data sample, so low rates
 * will be inaccurate still appropriate for max checking. One trick we use for
 * low values is to specially handle the case where the rate is between 0 and 1
 * in order to avoid flapping while waiting for the next event.
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


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
