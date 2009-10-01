/*
  include/proto/freq_ctr.h
  This file contains macros and inline functions for frequency counters.

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

#ifndef _PROTO_FREQ_CTR_H
#define _PROTO_FREQ_CTR_H

#include <common/config.h>
#include <common/time.h>
#include <types/freq_ctr.h>

/* Rotate a frequency counter when current period is over. Must not be called
 * during a valid period. It is important that it correctly initializes a null
 * area.
 */
static inline void rotate_freq_ctr(struct freq_ctr *ctr)
{
	ctr->prev_ctr = ctr->curr_ctr;
	if (likely(now.tv_sec - ctr->curr_sec != 1)) {
		/* we missed more than one second */
		ctr->prev_ctr = 0;
	}
	ctr->curr_sec = now.tv_sec;
	ctr->curr_ctr = 0; /* leave it at the end to help gcc optimize it away */
}

/* Update a frequency counter by <inc> incremental units. It is automatically
 * rotated if the period is over. It is important that it correctly initializes
 * a null area.
 */
static inline void update_freq_ctr(struct freq_ctr *ctr, unsigned int inc)
{
	if (likely(ctr->curr_sec == now.tv_sec)) {
		ctr->curr_ctr += inc;
		return;
	}
	rotate_freq_ctr(ctr);
	ctr->curr_ctr = inc;
	/* Note: later we may want to propagate the update to other counters */
}

/* Read a frequency counter taking history into account for missing time in
 * current period.
 */
unsigned int read_freq_ctr(struct freq_ctr *ctr);

/* returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> and taking into account that <pend> events are
 * already known to be pending. Returns 0 if limit was reached.
 */
unsigned int freq_ctr_remain(struct freq_ctr *ctr, unsigned int freq, unsigned int pend);

/* return the expected wait time in ms before the next event may occur,
 * respecting frequency <freq>, and assuming there may already be some pending
 * events. It returns zero if we can proceed immediately, otherwise the wait
 * time, which will be rounded down 1ms for better accuracy, with a minimum
 * of one ms.
 */
unsigned int next_event_delay(struct freq_ctr *ctr, unsigned int freq, unsigned int pend);

#endif /* _PROTO_FREQ_CTR_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
  */
