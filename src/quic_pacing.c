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
	uint64_t inc, wakeup_delay;
	uint credit_max, pkt_ms;

	/* Calculate the amount of packets which could be emitted in 1ms. */
	pkt_ms = pacer->cc->algo->pacing_burst ?
	  pacer->cc->algo->pacing_burst(pacer->cc) : (1000000 + inter - 1) / inter;

	if (task_now_ns > pacer->cur) {
		/* Calculate number of packets which could have been emitted since last emission sequence. Result is rounded up. */
		inc = (pkt_ms * (task_now_ns - pacer->cur) + 999999) / 1000000;

		/* Credit must not exceed a maximal value to guarantee a
		 * smooth emission. This max value represents the number of
		 * packet based on congestion window and RTT which can be sent
		 * to cover the sleep until the next wakeup. This delay is
		 * roughly the max between the scheduler delay or 1ms.
		 */

		/* Calculate wakeup_delay to determine max credit value. */
		wakeup_delay = MAX(swrate_avg(activity[tid].avg_loop_us, TIME_STATS_SAMPLES), 1000);
		/* Convert it to nanoseconds. Use 1.5 factor tolerance to try to cover the imponderable extra system delay until the next wakeup. */
		wakeup_delay *= 1500;
		/* Determine max credit from wakeup_delay and packet rate emission. */
		credit_max = (wakeup_delay * pkt_ms + 999999) / 1000000;
		/* Ensure max credit will never be smaller than 2. */
		credit_max = MAX(credit_max, 2);
		/* Apply max credit on the new value. */
		pacer->credit = MIN(pacer->credit + inc, credit_max);

		/* Refresh pacing reload timer. */
		pacer->cur = task_now_ns;
	}

	return pacer->credit;
}
