#include <haproxy/quic_pacing.h>

#include <haproxy/qmux_trace.h>
#include <haproxy/quic_tx.h>

struct quic_conn;

int quic_pacing_expired(const struct quic_pacer *pacer)
{
	//return !pacer->next || pacer->next <= now_mono_time();
	//return !pacer->next || pacer->next <= now_ms;
	return tick_is_expired(pacer->next, now_ms);
}

enum quic_tx_err quic_pacing_send(struct quic_pacer *pacer, struct quic_conn *qc)
{
	enum quic_tx_err ret;

	if (!quic_pacing_expired(pacer))
		return QUIC_TX_ERR_AGAIN;

	BUG_ON(LIST_ISEMPTY(&pacer->frms));
	ret = qc_send_mux(qc, &pacer->frms, pacer);
	BUG_ON(ret == QUIC_TX_ERR_AGAIN && tick_is_expired(pacer->next, now_ms));

	/* TODO handle QUIC_TX_ERR_FATAL */
	return ret;
}

int quic_pacing_prepare(struct quic_pacer *pacer)
{
	if (pacer->curr == now_ms) {
		BUG_ON(pacer->sent > pacer->pkt_ms);
		return pacer->pkt_ms - pacer->sent;
	}
	else {
		int not_consumed = pacer->pkt_ms - pacer->sent;
		BUG_ON(not_consumed < 0);
		//if (not_consumed)
		//	fprintf(stderr, "not consumed %d (%d - %d)\n", not_consumed, pacer->pkt_ms, pacer->sent);

		pacer->curr = now_ms;
		pacer->sent = 0;
		pacer->pkt_ms = quic_pacing_ns_pkt(pacer, 0);
		//pacer->pkt_ms = quic_pacing_ns_pkt(pacer, 0) + not_consumed;

		BUG_ON(!pacer->pkt_ms);
		return pacer->pkt_ms;
	}

}

int quic_pacing_sent_done(struct quic_pacer *pacer, int sent, enum quic_tx_err err)
{
	//const int pkt_ms = quic_pacing_ns_pkt(pacer, 1);

#if 0
	if (pacer->curr == now_ms) {
		pacer->sent += sent;
	}
	else {
		int not_consumed = pkt_ms - pacer->sent;
		if (not_consumed < 0)
			not_consumed = 0;	
		if (not_consumed)
			fprintf(stderr, "not consumed %d (%d - %d)\n", not_consumed, pkt_ms, pacer->sent);

		//pacer->sent = 0;
		//pacer->sent -= not_consumed;

		pacer->curr = now_ms;
		pacer->sent = sent;
	}
#endif
	BUG_ON(pacer->curr != now_ms);
	pacer->sent += sent;

	if (pacer->sent >= pacer->pkt_ms) {
		//pacer->next = tick_add(now_ms, 1);
		pacer->next = tick_add(now_ms, MAX((pacer->sent / pacer->pkt_ms), 1));
		BUG_ON(tick_is_expired(pacer->next, now_ms));
		//fprintf(stderr, "pacing in %dms (%d / %d)\n", pacer->sent / pkt_ms, pacer->sent, pkt_ms);
		return 1;
	}
	else {
		return 0;
	}
}
