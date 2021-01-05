/*
 * include/haproxy/quic_cc-t.h
 * This file contains definitions for QUIC congestion control.
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QUIC_CC_H
#define _HAPROXY_QUIC_CC_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <stddef.h> /* size_t */
#include <stdint.h>

#include <haproxy/buf-t.h>

#define QUIC_CC_INFINITE_SSTHESH ((uint64_t)-1)

extern struct quic_cc_algo quic_cc_algo_nr;
extern struct quic_cc_algo *default_quic_cc_algo;

enum quic_cc_algo_state_type {
	/* Slow start. */
	QUIC_CC_ST_SS,
	/* Congestion avoidance. */
	QUIC_CC_ST_CA,
};

enum quic_cc_event_type {
	/* ACK receipt. */
	QUIC_CC_EVT_ACK,
	/* Packet loss. */
	QUIC_CC_EVT_LOSS,
	/* ECN-CE. */
	QUIC_CC_EVT_ECN_CE,
};

struct quic_cc_event {
	enum quic_cc_event_type type;
	union {
		struct ack {
			uint64_t acked;
			unsigned int time_sent;
		} ack;
		struct loss {
			unsigned int now_ms;
			unsigned int max_ack_delay;
			size_t lost_bytes;
			unsigned int newest_time_sent;
			unsigned int period;
		} loss;
	};
};

enum quic_cc_algo_type {
	QUIC_CC_ALGO_TP_NEWRENO,
};

union quic_cc_algo_state {
	/* NewReno */
	struct nr {
		enum quic_cc_algo_state_type state;
		uint64_t cwnd;
		uint64_t ssthresh;
		uint64_t recovery_start_time;
	} nr;
};

struct quic_cc {
	/* <conn> is there only for debugging purpose. */
	struct quic_conn *qc;
	struct quic_cc_algo *algo;
	union quic_cc_algo_state algo_state;
};

struct quic_cc_algo {
	enum quic_cc_algo_type type;
	int (*init)(struct quic_cc *cc);
	void (*event)(struct quic_cc *cc, struct quic_cc_event *ev);
	void (*state_trace)(struct buffer *buf, const struct quic_cc *cc);
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CC_H */
