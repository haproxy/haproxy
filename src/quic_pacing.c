#include <haproxy/quic_pacing.h>

#include <haproxy/quic_tx.h>
#include <haproxy/task.h>

/* Notify <pacer> about an emission of <sent> count of datagrams. */
void quic_pacing_sent_done(struct quic_pacer *pacer, int sent)
{
	BUG_ON(!pacer->credit || pacer->credit < sent);
	pacer->credit -= sent;

	pacer->last_sent = sent;
}

/* Reload <pacer> credit when a new emission sequence is initiated. A maximal
 * value is calculated if previous emission occurred long time enough.
 *
 * Returns the remaining credit or 0 if emission cannot be conducted this time.
 */
int quic_pacing_reload(struct quic_pacer *pacer)
{
	const uint64_t task_now_ns = task_mono_time();
	const uint64_t inter = pacer->cc->algo->pacing_inter(pacer->cc);
	uint64_t inc;
	uint credit_max;

	if (task_now_ns > pacer->cur) {
		/* Calculate number of packets which could have been emitted since last emission sequence. Result is rounded up. */
		inc = (task_now_ns - pacer->cur + inter - 1) / inter;

		credit_max = pacer->cc->algo->pacing_burst(pacer->cc);
		pacer->credit = MIN(pacer->credit + inc, credit_max);

		/* Refresh pacing reload timer. */
		pacer->cur = task_now_ns;
	}

	return pacer->credit;
}
