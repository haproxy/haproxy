/*
 * include/types/quic_loss.h
 * This file contains definitions for QUIC loss detection.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _TYPES_QUIC_LOSS_H
#define _TYPES_QUIC_LOSS_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <stdint.h>

/* Maximum reordering in packets. */
#define QUIC_LOSS_PACKET_THRESHOLD         3
#define QUIC_TIMER_GRANULARITY            1U /* 1ms   */
#define QUIC_LOSS_INITIAL_RTT           333U /* 333ms */

/* Note that all the unit of variables for QUIC LOSS dectections
 * is the tick.
 */

struct quic_loss {
	/* The most recent RTT measurement. */
	unsigned int latest_rtt;
	/* Smoothed RTT << 4*/
	unsigned int srtt;
	/* RTT variation << 2 */
	unsigned int rtt_var;
	/* Minimum RTT. */
	unsigned int rtt_min;
	/* Number of NACKed sent PTO. */
	unsigned int pto_count;
};

#endif /* USE_QUIC */
#endif /* _TYPES_QUIC_LOSS_H */
