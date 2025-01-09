#include <haproxy/quic_pacing.h>

#include <haproxy/quic_tx.h>
#include <haproxy/task.h>

/* Returns true if <pacer> timer is expired and emission can be retried. */
int quic_pacing_expired(const struct quic_pacer *pacer)
{
	//return !pacer->next || pacer->next <= task_mono_time();
	return pacer->credit >= 10;
}

/* Notify <pacer> about an emission of <sent> count of datagrams. */
void quic_pacing_sent_done(struct quic_pacer *pacer, int sent)
{
	BUG_ON(pacer->credit < sent);
	pacer->credit -= sent;

	if (!pacer->credit)
		//pacer->next = task_mono_time() + pacer->cc->algo->pacing_rate(pacer->cc) * sent;
		//pacer->next = task_mono_time() + pacer->cc->algo->pacing_rate(pacer->cc) * 1;
		pacer->next = task_mono_time() + pacer->cc->algo->pacing_rate(pacer->cc) * 12;

	pacer->last_sent = sent;
}
