/*
 * include/proto/quic_cc.h
 * This file contains prototypes for QUIC congestion control.
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

#ifndef _PROTO_QUIC_CC_H
#define _PROTO_QUIC_CC_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_loss.h>

void quic_cc_init(struct quic_cc *cc, struct quic_cc_algo *algo, struct quic_conn *qc);
void quic_cc_event(struct quic_cc *cc, struct quic_cc_event *ev);
void quic_cc_state_trace(struct buffer *buf, const struct quic_cc *cc);

/* Pacing callbacks */
uint quic_cc_default_pacing_inter(const struct quic_cc *cc);

static inline const char *quic_cc_state_str(enum quic_cc_algo_state_type state)
{
	switch (state) {
	case QUIC_CC_ST_SS:
		return "ss";
	case QUIC_CC_ST_CA:
		return "ca";
	case QUIC_CC_ST_RP:
		return "rp";
	default:
		return "unknown";
	}
}

/* Return a human readable string from <ev> control congestion event type. */
static inline void quic_cc_event_trace(struct buffer *buf, const struct quic_cc_event *ev)
{
	chunk_appendf(buf, " event=");
	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
		chunk_appendf(buf, "ack acked=%llu time_sent:%dms",
		              (unsigned long long)ev->ack.acked, TICKS_TO_MS(tick_remain(ev->ack.time_sent, now_ms)));
		break;
	case QUIC_CC_EVT_LOSS:
		chunk_appendf(buf, "loss time_sent=%dms", TICKS_TO_MS(tick_remain(ev->loss.time_sent, now_ms)));
		break;
	case QUIC_CC_EVT_ECN_CE:
		chunk_appendf(buf, "ecn_ce");
		break;
	}
}

static inline void *quic_cc_priv(const struct quic_cc *cc)
{
	return (void *)cc->priv;
}

/* Initialize <p> QUIC network path depending on <ipv4> boolean
 * which is true for an IPv4 path, if not false for an IPv6 path.
 */
static inline void quic_cc_path_init(struct quic_cc_path *path, int ipv4, unsigned long max_cwnd,
                                     struct quic_cc_algo *algo,
                                     struct quic_conn *qc)
{
	unsigned int max_dgram_sz;

	max_dgram_sz = ipv4 ? QUIC_INITIAL_IPV4_MTU : QUIC_INITIAL_IPV6_MTU;
	quic_loss_init(&path->loss);
	*(size_t *)&path->mtu = max_dgram_sz;
	path->initial_wnd = QUIC_MIN(10 * max_dgram_sz, QUIC_MAX(max_dgram_sz << 1, 14720U));
	path->cwnd = path->initial_wnd;
	path->mcwnd = path->cwnd;
	path->max_cwnd = max_cwnd;
	path->min_cwnd = max_dgram_sz << 1;
	path->prep_in_flight = 0;
	path->in_flight = 0;
	path->ifae_pkts = 0;
	quic_cc_init(&path->cc, algo, qc);
	path->delivery_rate = 0;
	path->send_quantum = 64 * 1024;
	path->recovery_start_ts = TICK_ETERNITY;
}

/* Return the remaining <room> available on <path> QUIC path for prepared data
 * (before being sent). Almost the same that for the QUIC path room, except that
 * here this is the data which have been prepared which are taken into an account.
 */
static inline size_t quic_cc_path_prep_data(struct quic_cc_path *path)
{
	if (path->prep_in_flight > path->cwnd)
		return 0;

	return path->cwnd - path->prep_in_flight;
}

int quic_cwnd_may_increase(const struct quic_cc_path *path);

#endif /* USE_QUIC */
#endif /* _PROTO_QUIC_CC_H */
