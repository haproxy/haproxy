/*
 * include/haproxy/freq_ctr.h
 * This file contains structure declarations for frequency counters.
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

#ifndef _HAPROXY_FREQ_CTR_T_H
#define _HAPROXY_FREQ_CTR_T_H

#include <haproxy/api-t.h>

/* The generic freq_ctr counter counts a rate of events per period, where the
 * period has to be known by the user. The period is measured in ticks and
 * must be at least 2 ticks long. This form is slightly more CPU intensive for
 * reads than the per-second form as it involves a divide.
 */
struct freq_ctr {
	unsigned int curr_tick; /* start date of current period (wrapping ticks) */
	unsigned int curr_ctr; /* cumulated value for current period */
	unsigned int prev_ctr; /* value for last period */
};

#endif /* _HAPROXY_FREQ_CTR_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
