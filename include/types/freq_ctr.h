/*
 * include/types/freq_ctr.h
 * This file contains structure declarations for frequency counters.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_FREQ_CTR_H
#define _TYPES_FREQ_CTR_H

#include <common/config.h>

/* The implicit freq_ctr counter counts a rate of events per second. It is the
 * preferred form to count rates over a one-second period, because it does not
 * involve any divide.
 */
struct freq_ctr {
	unsigned int curr_sec; /* start date of current period (seconds from now.tv_sec) */
	unsigned int curr_ctr; /* cumulated value for current period */
	unsigned int prev_ctr; /* value for last period */
};

/* The generic freq_ctr_period counter counts a rate of events per period, where
 * the period has to be known by the user. The period is measured in ticks and
 * must be at least 2 ticks long. This form is slightly more CPU intensive than
 * the per-second form.
 */
struct freq_ctr_period {
	unsigned int curr_tick; /* start date of current period (wrapping ticks) */
	unsigned int curr_ctr;  /* cumulated value for current period */
	unsigned int prev_ctr;  /* value for last period */
};

#endif /* _TYPES_FREQ_CTR_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
