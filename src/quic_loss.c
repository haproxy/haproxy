#include <haproxy/quic_loss.h>

#include <haproxy/ticks.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_quic

/* Update <ql> QUIC loss information with new <rtt> measurement and <ack_delay>
 * on ACK frame receipt which MUST be min(ack->ack_delay, max_ack_delay)
 * before the handshake is confirmed.
 */
void quic_loss_srtt_update(struct quic_loss *ql,
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

/* Returns for <qc> QUIC connection the first packet number space which
 * experienced packet loss, if any or a packet number space with
 * TICK_ETERNITY as packet loss time if not.
 */
struct quic_pktns *quic_loss_pktns(struct quic_conn *qc)
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
struct quic_pktns *quic_pto_pktns(struct quic_conn *qc,
                                  int handshake_completed,
                                  unsigned int *pto)
{
	int i;
	unsigned int duration, lpto;
	struct quic_loss *ql = &qc->path->loss;
	struct quic_pktns *pktns, *p;

	TRACE_ENTER(QUIC_EV_CONN_SPTO, qc);
	duration =
		(ql->srtt >> 3) +
		(QUIC_MAX(ql->rtt_var, QUIC_TIMER_GRANULARITY) << ql->pto_count);

	if (!qc->path->in_flight) {
		struct quic_enc_level *hel;

		hel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
		if (hel->tls_ctx.flags & QUIC_FL_TLS_SECRETS_SET) {
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
		tmp_pto = tick_add(p->tx.time_of_last_eliciting, duration);
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
