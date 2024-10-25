#include <haproxy/quic_pacing.h>

#include <haproxy/quic_tx.h>

struct quic_conn;

int quic_pacing_expired(const struct quic_pacer *pacer)
{
	return !pacer->next || pacer->next <= now_mono_time();
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
	pacer->next = now_mono_time() + quic_pacing_ns_pkt(pacer) * sent;
}
