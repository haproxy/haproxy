#include <import/eb64tree.h>

#include <haproxy/quic_cc-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_trace.h>

#include <haproxy/atomic.h>
#include <haproxy/list.h>
#include <haproxy/ticks.h>
#include <haproxy/trace.h>

/* Update <ql> QUIC loss information with new <rtt> measurement and <ack_delay>
 * on ACK frame receipt which MUST be min(ack->ack_delay, max_ack_delay)
 * before the handshake is confirmed.
 */
void quic_loss_srtt_update(struct quic_loss *ql,
                           unsigned int rtt, unsigned int ack_delay,
                           struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_RTTUPDT, qc);
	TRACE_PROTO("TX loss srtt update", QUIC_EV_CONN_RTTUPDT, qc, &rtt, &ack_delay, ql);

	ql->latest_rtt = rtt;
	if (!ql->rtt_min) {
		/* No previous measurement. */
		ql->srtt = rtt;
		ql->rtt_var = rtt / 2;
		ql->rtt_min = rtt;
	}
	else {
		int diff;

		ql->rtt_min = QUIC_MIN(rtt, ql->rtt_min);
		/* Specific to QUIC (RTT adjustment). */
		if (ack_delay && rtt >= ql->rtt_min + ack_delay)
			rtt -= ack_delay;
		diff = ql->srtt - rtt;
		if (diff < 0)
			diff = -diff;
		ql->rtt_var = (3 * ql->rtt_var + diff) / 4;
		ql->srtt = (7 * ql->srtt + rtt) / 8;
	}

	TRACE_PROTO("TX loss srtt update", QUIC_EV_CONN_RTTUPDT, qc,,, ql);
	TRACE_LEAVE(QUIC_EV_CONN_RTTUPDT, qc);
}

/* Returns for <qc> QUIC connection the first packet number space which
 * experienced packet loss, if any or a packet number space with
 * TICK_ETERNITY as packet loss time if not.
 */
struct quic_pktns *quic_loss_pktns(struct quic_conn *qc)
{
	struct quic_pktns *pktns, *p;

	TRACE_ENTER(QUIC_EV_CONN_SPTO, qc);

	BUG_ON(LIST_ISEMPTY(&qc->pktns_list));
	pktns = p = LIST_NEXT(&qc->pktns_list, struct quic_pktns *, list);

	do {
		TRACE_PROTO("TX loss pktns", QUIC_EV_CONN_SPTO, qc, p);
		if (!tick_isset(pktns->tx.loss_time) ||
		    tick_is_lt(p->tx.loss_time, pktns->tx.loss_time)) {
			pktns = p;
		}
		p = LIST_NEXT(&p->list, struct quic_pktns *, list);
	} while (&p->list != &qc->pktns_list);

	TRACE_LEAVE(QUIC_EV_CONN_SPTO, qc);

	return pktns;
}

/* Returns for <qc> QUIC connection the first packet number space to
 * arm the PTO for if any or a packet number space with TICK_ETERNITY
 * as PTO value if not.
 */
struct quic_pktns *quic_pto_pktns(struct quic_conn *qc,
                                  int handshake_confirmed,
                                  unsigned int *pto)
{
	unsigned int duration, lpto;
	struct quic_loss *ql = &qc->path->loss;
	struct quic_pktns *pktns, *p;

	TRACE_ENTER(QUIC_EV_CONN_SPTO, qc);

	BUG_ON(LIST_ISEMPTY(&qc->pktns_list));
	duration =
		ql->srtt +
		(QUIC_MAX(4 * ql->rtt_var, QUIC_TIMER_GRANULARITY) << ql->pto_count);

	/* RFC 9002 6.2.2.1. Before Address Validation
	 *
	 * the client MUST set the PTO timer if the client has not received an
	 * acknowledgment for any of its Handshake packets and the handshake is
	 * not confirmed (see Section 4.1.2 of [QUIC-TLS]), even if there are no
	 * packets in flight.
	 *
	 * TODO implement the above paragraph for QUIC on backend side. Note
	 * that if now_ms is used this function is not reentrant anymore and can
	 * not be used anytime without side-effect (for example after QUIC
	 * connection migration).
	 */

	lpto = TICK_ETERNITY;
	pktns = p = LIST_NEXT(&qc->pktns_list, struct quic_pktns *, list);

	do {
		unsigned int tmp_pto;

		if (p->tx.in_flight) {
			if (p == qc->apktns) {
				if (!handshake_confirmed) {
					TRACE_STATE("TX PTO handshake not already confirmed", QUIC_EV_CONN_SPTO, qc);
					goto out;
				}

				duration += qc->max_ack_delay << ql->pto_count;
			}

			tmp_pto = tick_add(p->tx.time_of_last_eliciting, duration);
			if (!tick_isset(lpto) || tick_is_lt(tmp_pto, lpto)) {
				lpto = tmp_pto;
				pktns = p;
			}

			TRACE_PROTO("TX PTO", QUIC_EV_CONN_SPTO, qc, p);
		}

		p = LIST_NEXT(&p->list, struct quic_pktns *, list);
	} while (&p->list != &qc->pktns_list);

 out:
	if (pto)
		*pto = lpto;
	TRACE_PROTO("TX PTO", QUIC_EV_CONN_SPTO, qc, pktns, &duration);
	TRACE_LEAVE(QUIC_EV_CONN_SPTO, qc);

	return pktns;
}

/* Look for packet loss from sent packets for <qel> encryption level of a
 * connection with <ctx> as I/O handler context. If remove is true, remove them from
 * their tree if deemed as lost or set the <loss_time> value the packet number
 * space if any not deemed lost.
 * Should be called after having received an ACK frame with newly acknowledged
 * packets or when the the loss detection timer has expired.
 * Always succeeds.
 */
void qc_packet_loss_lookup(struct quic_pktns *pktns, struct quic_conn *qc,
                           struct list *lost_pkts, uint32_t *bytes_lost)
{
	struct eb_root *pkts;
	struct eb64_node *node;
	struct quic_loss *ql;
	unsigned int loss_delay;
	uint64_t pktthresh;

	TRACE_ENTER(QUIC_EV_CONN_PKTLOSS, qc);
	TRACE_PROTO("TX loss", QUIC_EV_CONN_PKTLOSS, qc, pktns);
	pkts = &pktns->tx.pkts;
	pktns->tx.loss_time = TICK_ETERNITY;
	if (eb_is_empty(pkts))
		goto out;

	ql = &qc->path->loss;
	loss_delay = QUIC_MAX(ql->latest_rtt, ql->srtt);
	loss_delay = QUIC_MAX(loss_delay, MS_TO_TICKS(QUIC_TIMER_GRANULARITY)) *
		QUIC_LOSS_TIME_THRESHOLD_MULTIPLICAND / QUIC_LOSS_TIME_THRESHOLD_DIVISOR;

	node = eb64_first(pkts);

	/* RFC 9002 6.1.1. Packet Threshold
	 * The RECOMMENDED initial value for the packet reordering threshold
	 * (kPacketThreshold) is 3, based on best practices for TCP loss detection
	 * [RFC5681] [RFC6675]. In order to remain similar to TCP, implementations
	 * SHOULD NOT use a packet threshold less than 3; see [RFC5681].

	 * Some networks may exhibit higher degrees of packet reordering, causing a
	 * sender to detect spurious losses. Additionally, packet reordering could be
	 * more common with QUIC than TCP because network elements that could observe
	 * and reorder TCP packets cannot do that for QUIC and also because QUIC
	 * packet numbers are encrypted.
	 */

	/* Dynamic packet reordering threshold calculation depending on the distance
	 * (in packets) between the last transmitted packet and the oldest still in
	 * flight before loss detection.
	 */
	pktthresh = pktns->tx.next_pn - 1 - eb64_entry(node, struct quic_tx_packet, pn_node)->pn_node.key;
	/* Apply a ratio to this threshold and add it to QUIC_LOSS_PACKET_THRESHOLD. */
	pktthresh = pktthresh * global.tune.quic_reorder_ratio / 100 + QUIC_LOSS_PACKET_THRESHOLD;
	while (node) {
		struct quic_tx_packet *pkt;
		int64_t largest_acked_pn;
		unsigned int loss_time_limit, time_sent;
		int reordered;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		largest_acked_pn = pktns->rx.largest_acked_pn;
		node = eb64_next(node);
		if ((int64_t)pkt->pn_node.key > largest_acked_pn)
			break;

		time_sent = pkt->time_sent_ms;
		loss_time_limit = tick_add(time_sent, loss_delay);

		reordered = (int64_t)largest_acked_pn >= pkt->pn_node.key + pktthresh;
		if (reordered)
			ql->nb_reordered_pkt++;

		if (tick_is_le(loss_time_limit, now_ms) || reordered) {
			struct quic_cc *cc = &qc->path->cc;

			/* Delivery rate sampling is applied to ack-eliciting packet only. */
			if ((pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) &&
			    cc->algo->on_pkt_lost)
				cc->algo->on_pkt_lost(cc, pkt, pkt->rs.lost);
			eb64_delete(&pkt->pn_node);
			LIST_APPEND(lost_pkts, &pkt->list);
			if (bytes_lost)
				*bytes_lost += pkt->len;
			ql->nb_lost_pkt++;
		}
		else {
			if (tick_isset(pktns->tx.loss_time))
				pktns->tx.loss_time = tick_first(pktns->tx.loss_time, loss_time_limit);
			else
				pktns->tx.loss_time = loss_time_limit;
			break;
		}
	}

 out:
	TRACE_PROTO("TX loss", QUIC_EV_CONN_PKTLOSS, qc, pktns, lost_pkts);
	TRACE_LEAVE(QUIC_EV_CONN_PKTLOSS, qc);
}

/* Handle <pkts> list of lost packets detected at <now_us> handling their TX
 * frames. Send a packet loss event to the congestion controller if in flight
 * packet have been lost. Also frees the packet in <pkts> list.
 *
 * Returns 1 on success else 0 if loss limit has been exceeded. A
 * CONNECTION_CLOSE was prepared to close the connection ASAP.
 */
int qc_release_lost_pkts(struct quic_conn *qc, struct quic_pktns *pktns,
                         struct list *pkts, uint64_t now_us)
{
	struct quic_tx_packet *pkt, *tmp, *oldest_lost, *newest_lost;
	uint tot_lost = 0;
	int close = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	if (LIST_ISEMPTY(pkts))
		goto leave;

	/* Oldest will point to first list entry and newest on the last. First,
	 * initialize them to point on the same entry. Newest pointer will be
	 * updated along the loop. Release all other packet in between.
	 */
	newest_lost = oldest_lost = LIST_ELEM(pkts->n, struct quic_tx_packet *, list);
	list_for_each_entry_safe(pkt, tmp, pkts, list) {
		struct list tmp = LIST_HEAD_INIT(tmp);

		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		qc->path->prep_in_flight -= pkt->in_flight_len;
		qc->path->in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		/* Treat the frames of this lost packet. */
		if (!qc_handle_frms_of_lost_pkt(qc, pkt, &pktns->tx.frms))
			close = 1;
		LIST_DELETE(&pkt->list);

		/* Move newest so that it will point on the last list entry.
		 * Release every intermediary packet.
		 */
		if (oldest_lost != newest_lost)
			quic_tx_packet_refdec(newest_lost);
		newest_lost = pkt;
		tot_lost++;
	}

	if (!close) {
		struct quic_cc *cc = &qc->path->cc;
		/* Sent a congestion event to the controller */
		struct quic_cc_event ev = { };

		ev.type = QUIC_CC_EVT_LOSS;
		ev.loss.time_sent = newest_lost->time_sent_ms;
		ev.loss.count = tot_lost;

		quic_cc_event(cc, &ev);
		if (cc->algo->congestion_event)
		    cc->algo->congestion_event(cc, newest_lost->time_sent_ms);

		/* If an RTT have been already sampled, <rtt_min> has been set.
		 * We must check if we are experiencing a persistent congestion.
		 * If this is the case, the congestion controller must re-enter
		 * slow start state.
		 */
		if (qc->path->loss.rtt_min && newest_lost != oldest_lost) {
			unsigned int period = newest_lost->time_sent_ms - oldest_lost->time_sent_ms;

			if (quic_loss_persistent_congestion(&qc->path->loss, period,
							    now_ms, qc->max_ack_delay) &&
			    qc->path->cc.algo->slow_start)
				qc->path->cc.algo->slow_start(&qc->path->cc);
		}
	}

	quic_tx_packet_refdec(oldest_lost);
	if (newest_lost != oldest_lost)
		quic_tx_packet_refdec(newest_lost);

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
	return !close;
}
