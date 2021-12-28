/*
 * include/proto/quic_loss.h
 * This file provides interface definition for QUIC loss detection.
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

#ifndef _PROTO_QUIC_LOSS_H
#define _PROTO_QUIC_LOSS_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/ticks.h>
#include <haproxy/xprt_quic-t.h>

#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_quic

static inline void quic_loss_init(struct quic_loss *ql)
{
	ql->srtt = QUIC_LOSS_INITIAL_RTT << 4;
	ql->rtt_var = (QUIC_LOSS_INITIAL_RTT >> 1) << 2;
	ql->rtt_min = 0;
	ql->pto_count = 0;
}

/* Update <ql> QUIC loss information with new <rtt> measurement and <ack_delay>
 * on ACK frame receipt which MUST be min(ack->ack_delay, max_ack_delay)
 * before the handshake is confirmed.
 */
static inline void quic_loss_srtt_update(struct quic_loss *ql,
                                         unsigned int rtt, unsigned int ack_delay,
                                         struct quic_conn *qc)
{
	TRACE_PROTO("Loss info update", QUIC_EV_CONN_RTTUPDT, qc, &rtt, &ack_delay, ql);
	ql->latest_rtt = rtt;
	if (!ql->rtt_min) {
		/* No previous measurement. */
		ql->srtt = rtt << 3;
		/* rttval <- rtt / 2 or 4*rttval <- 2*rtt. */
		ql->rtt_var = rtt << 1;
		ql->rtt_min = rtt;
	}
	else {
		int diff;

		ql->rtt_min = QUIC_MIN(rtt, ql->rtt_min);
		/* Specific to QUIC (RTT adjustment). */
		if (ack_delay && rtt > ql->rtt_min + ack_delay)
			rtt -= ack_delay;
		diff = ql->srtt - rtt;
		if (diff < 0)
			diff = -diff;
		/* 4*rttvar = 3*rttvar + |diff| */
		ql->rtt_var += diff - (ql->rtt_var >> 2);
		/* 8*srtt = 7*srtt + rtt */
		ql->srtt += rtt - (ql->srtt >> 3);
	}
	TRACE_PROTO("Loss info update", QUIC_EV_CONN_RTTUPDT, qc,,, ql);
}

/* Return 1 if a persitent congestion is observed for a list of
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

	congestion_period = (ql->srtt >> 3) +
		QUIC_MAX(ql->rtt_var, QUIC_TIMER_GRANULARITY) + max_ack_delay;
	congestion_period *= QUIC_LOSS_PACKET_THRESHOLD;

	return period >= congestion_period;
}

/* Returns for <qc> QUIC connection the first packet number space which
 * experienced packet loss, if any or a packet number space with
 * TICK_ETERNITY as packet loss time if not.
 */
static inline struct quic_pktns *quic_loss_pktns(struct quic_conn *qc)
{
	enum quic_tls_pktns i;
	struct quic_pktns *pktns;

	pktns = &qc->pktns[QUIC_TLS_PKTNS_INITIAL];
	TRACE_PROTO("pktns", QUIC_EV_CONN_SPTO, qc, pktns);
	for (i = QUIC_TLS_PKTNS_HANDSHAKE; i < QUIC_TLS_PKTNS_MAX; i++) {
		TRACE_PROTO("pktns", QUIC_EV_CONN_SPTO, qc, &qc->pktns[i]);
		if (!tick_isset(pktns->tx.loss_time) ||
		    qc->pktns[i].tx.loss_time < pktns->tx.loss_time)
			pktns = &qc->pktns[i];
	}

	return pktns;
}

/* Returns for <qc> QUIC connection the first packet number space to
 * arm the PTO for if any or a packet number space with TICK_ETERNITY
 * as PTO value if not.
 */
static inline struct quic_pktns *quic_pto_pktns(struct quic_conn *qc,
                                                int handshake_completed,
                                                unsigned int *pto)
{
	int i;
	unsigned int duration, lpto, time_of_last_eliciting;
	struct quic_loss *ql = &qc->path->loss;
	struct quic_pktns *pktns, *p;

	TRACE_ENTER(QUIC_EV_CONN_SPTO, qc);
	duration =
		(ql->srtt >> 3) +
		(QUIC_MAX(ql->rtt_var, QUIC_TIMER_GRANULARITY) << ql->pto_count);

	if (!qc->path->in_flight) {
		struct quic_enc_level *hel;

		hel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
		if (hel->tls_ctx.tx.flags & QUIC_FL_TLS_SECRETS_SET) {
			pktns = &qc->pktns[QUIC_TLS_PKTNS_HANDSHAKE];
		}
		else {
			pktns = &qc->pktns[QUIC_TLS_PKTNS_INITIAL];
		}
		lpto = tick_add(now_ms, duration);
		goto out;
	}

	lpto = TICK_ETERNITY;
	pktns = p = &qc->pktns[QUIC_TLS_PKTNS_INITIAL];

	for (i = QUIC_TLS_PKTNS_INITIAL; i < QUIC_TLS_PKTNS_MAX; i++) {
		unsigned int tmp_pto;

		if (!qc->pktns[i].tx.in_flight)
			continue;

		if (i == QUIC_TLS_PKTNS_01RTT) {
			if (!handshake_completed) {
				pktns = p;
				goto out;
			}

			duration += qc->max_ack_delay << ql->pto_count;
		}

		p = &qc->pktns[i];
		time_of_last_eliciting = p->tx.time_of_last_eliciting;
		tmp_pto =
			tick_first(lpto, tick_add(time_of_last_eliciting, duration));
		if (!tick_isset(lpto) || tmp_pto < lpto) {
			lpto = tmp_pto;
			pktns = p;
		}
		TRACE_PROTO("pktns", QUIC_EV_CONN_SPTO, qc, p);
	}

 out:
	if (pto)
		*pto = lpto;
	TRACE_LEAVE(QUIC_EV_CONN_SPTO, qc, pktns, &duration);

	return pktns;
}

#endif /* USE_QUIC */
#endif /* _PROTO_QUIC_LOSS_H */
