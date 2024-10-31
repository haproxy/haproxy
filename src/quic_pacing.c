#include <haproxy/quic_pacing.h>

#include <haproxy/quic_tx.h>

struct quic_conn;

int quic_pacing_expired(const struct quic_pacer *pacer)
{
	return tick_is_expired(pacer->next, now_ms);
}

enum quic_tx_err quic_pacing_send(struct quic_pacer *pacer, struct quic_conn *qc)
{
	enum quic_tx_err ret;

	if (!quic_pacing_expired(pacer))
		return QUIC_TX_ERR_AGAIN;

	BUG_ON(LIST_ISEMPTY(&pacer->frms));
	ret = qc_send_mux(qc, &pacer->frms, pacer);

	/* TODO handle QUIC_TX_ERR_FATAL */
	return ret;
}

void quic_pacing_sent_done(struct quic_pacer *pacer, int sent)
{
	const int pkt_ms = quic_pacing_pkt_ms(pacer);

	if (pacer->curr == now_ms) {
		pacer->sent += sent;
	}
	else {
		pacer->curr = now_ms;
		pacer->sent = sent;
	}

	if (pacer->sent >= pkt_ms) {
		pacer->next = now_ms + (pacer->sent / pkt_ms);
		fprintf(stderr, "pacing in %dms (%d / %d)\n", pacer->sent / pkt_ms, pacer->sent, pkt_ms);
	}
}
