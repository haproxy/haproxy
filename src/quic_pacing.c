#include <haproxy/quic_pacing.h>

#include <haproxy/quic_tx.h>

/* Returns true if <pacer> timer is expired and emission can be retried. */
int quic_pacing_expired(const struct quic_pacer *pacer)
{
	return !pacer->next || pacer->next <= now_mono_time();
}

/* Notify <pacer> about an emission of <sent> count of datagrams. */
void quic_pacing_sent_done(struct quic_pacer *pacer, int sent)
{
	pacer->next = now_mono_time() + pacer->cc->algo->pacing_rate(pacer->cc) * sent;
}
