/*
 * include/proto/quic_loss.h
 * This file provides interface definition for QUIC loss detection.
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

#ifndef _PROTO_QUIC_LOSS_H
#define _PROTO_QUIC_LOSS_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/quic_loss-t.h>

#include <haproxy/api.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_tls-t.h>

static inline void quic_loss_init(struct quic_loss *ql)
{
	ql->latest_rtt = 0;
	ql->srtt = QUIC_LOSS_INITIAL_RTT;
	ql->rtt_var = QUIC_LOSS_INITIAL_RTT / 2;
	ql->rtt_min = 0;
	ql->pto_count = 0;
	ql->nb_lost_pkt = 0;
	ql->nb_reordered_pkt = 0;
}

/* Return 1 if a persistent congestion is observed for a list of
 * lost packets sent during <period> period depending on <ql> loss information,
 * <now_us> the current time and <max_ack_delay_us> the maximum ACK delay of the connection
 * experiencing a packet loss. Return 0 on the contrary.
 */
static inline int quic_loss_persistent_congestion(struct quic_loss *ql,
                                                  unsigned int period,
                                                  unsigned int now_us,
                                                  unsigned int max_ack_delay)
{
	unsigned int congestion_period;

	if (!period)
		return 0;

	congestion_period = ql->srtt +
		QUIC_MAX(4 * ql->rtt_var, QUIC_TIMER_GRANULARITY) + max_ack_delay;
	congestion_period *= QUIC_LOSS_PACKET_THRESHOLD;

	return period >= congestion_period;
}

/* Return the PTO associated to <pktns> packet number space for <qc> connection */
static inline unsigned int quic_pto(struct quic_conn *qc)
{
	struct quic_loss *ql = &qc->path->loss;

	return ql->srtt + QUIC_MAX(4 * ql->rtt_var, QUIC_TIMER_GRANULARITY) +
		(HA_ATOMIC_LOAD(&qc->state) >= QUIC_HS_ST_COMPLETE ? qc->max_ack_delay : 0);
}

void quic_loss_srtt_update(struct quic_loss *ql,
                           unsigned int rtt, unsigned int ack_delay,
                           struct quic_conn *qc);

struct quic_pktns *quic_loss_pktns(struct quic_conn *qc);

struct quic_pktns *quic_pto_pktns(struct quic_conn *qc,
                                  int handshake_completed,
                                  unsigned int *pto);

void qc_packet_loss_lookup(struct quic_pktns *pktns, struct quic_conn *qc,
                           struct list *lost_pkts, uint32_t *bytes_lost);
int qc_release_lost_pkts(struct quic_conn *qc, struct quic_pktns *pktns,
                         struct list *pkts, uint64_t now_us);
#endif /* USE_QUIC */
#endif /* _PROTO_QUIC_LOSS_H */
