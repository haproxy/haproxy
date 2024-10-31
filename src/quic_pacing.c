#include <haproxy/quic_pacing.h>

#include <haproxy/qmux_trace.h>
#include <haproxy/quic_tx.h>

struct quic_conn;

//int quic_pacing_expired(const struct quic_pacer *pacer)
//{
//	//return !pacer->next || pacer->next <= now_mono_time();
//	//return !pacer->next || pacer->next <= now_ms;
//	return tick_is_expired(pacer->next, now_ms);
//}

enum quic_tx_err quic_pacing_send(struct quic_pacer *pacer, struct quic_conn *qc)
{
	enum quic_tx_err ret;

	//if (!quic_pacing_expired(pacer))
	//if (!pacer->budget)
	//	return QUIC_TX_ERR_AGAIN;

	BUG_ON(LIST_ISEMPTY(&pacer->frms));
	ret = qc_send_mux(qc, &pacer->frms, pacer);
	//BUG_ON(ret == QUIC_TX_ERR_AGAIN && tick_is_expired(pacer->next, now_ms));

	/* TODO handle QUIC_TX_ERR_FATAL */
	return ret;
}

int quic_pacing_prepare(struct quic_pacer *pacer)
{
	int idle = tick_remain(pacer->last_sent, now_ms);
	int pkts = idle * pacer->path->cwnd / (pacer->path->loss.srtt * pacer->path->mtu + 1); 

	TRACE_POINT(QMUX_EV_QCC_WAKE, NULL);

	pacer->budget += pkts;
	if (pacer->budget > pacer->burst * 2) {
		TRACE_POINT(QMUX_EV_QCC_WAKE, NULL);
		pacer->budget = pacer->burst * 2;
	}
	//fprintf(stderr, "prepare = %d %d/%d\n", pkts, pacer->budget, pacer->burst);
	return MIN(pacer->budget, pacer->burst);
}

int quic_pacing_next(struct quic_pacer *pacer)
{
	//return (pacer->burst / 4) * pacer->path->loss.srtt * pacer->path->mtu / pacer->path->cwnd;
	return 1;
}

int quic_pacing_sent_done(struct quic_pacer *pacer, int sent, enum quic_tx_err err)
{
	BUG_ON(sent > pacer->budget);
	TRACE_POINT(QMUX_EV_QCC_WAKE, NULL);
	pacer->budget -= sent;
	if (sent) {
		TRACE_POINT(QMUX_EV_QCC_WAKE, NULL);
		pacer->last_sent = now_ms;
	}
	return 0;
}
