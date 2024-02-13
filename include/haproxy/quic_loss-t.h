/*
 * include/types/quic_loss.h
 * This file contains definitions for QUIC loss detection.
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#include <inttypes.h>

/* Maximum reordering in packets. */
#define QUIC_LOSS_PACKET_THRESHOLD         3
#define QUIC_TIMER_GRANULARITY            1U /* 1ms   */
#define QUIC_LOSS_INITIAL_RTT           333U /* 333ms */

/* QUIC loss time threshold expressed an RTT multiplier
 * (QUIC_LOSS_TIME_THRESHOLD_MULTIPLICAND / QUIC_LOSS_TIME_THRESHOLD_DIVISOR)
 */
#define QUIC_LOSS_TIME_THRESHOLD_MULTIPLICAND 9
#define QUIC_LOSS_TIME_THRESHOLD_DIVISOR      8

/* Note that all the unit of variables for QUIC LOSS detections
 * is the tick.
 */

struct quic_loss {
	/* The most recent RTT measurement (ms) */
	unsigned int latest_rtt;
	/* Smoothed RTT (ms) */
	unsigned int srtt;
	/* RTT variation (ms) */
	unsigned int rtt_var;
	/* Minimum RTT (ms) */
	unsigned int rtt_min;
	/* Number of NACKed sent PTO. */
	unsigned int pto_count;
	unsigned long nb_lost_pkt;
	unsigned long nb_reordered_pkt;
};

#endif /* USE_QUIC */
#endif /* _TYPES_QUIC_LOSS_H */
