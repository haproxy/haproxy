#include <haproxy/quic_pacing.h>

#include <haproxy/quic_tx.h>
#include <haproxy/task.h>

/* Returns true if <pacer> timer is expired and emission can be retried. */
int quic_pacing_expired(const struct quic_pacer *pacer)
{
	return !pacer->next || pacer->next <= task_mono_time();
}

/* Notify <pacer> about an emission of <sent> count of datagrams. */
void quic_pacing_sent_done(struct quic_pacer *pacer, int sent)
{
	pacer->next = task_mono_time() + pacer->cc->algo->pacing_inter(pacer->cc) * sent;
	pacer->last_sent = sent;
}
