#ifndef _HAPROXY_QUIC_PACING_H
#define _HAPROXY_QUIC_PACING_H

#include <haproxy/quic_pacing-t.h>

#include <haproxy/list.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_tx-t.h>

static inline void quic_pacing_init(struct quic_pacer *pacer,
                                    const struct quic_cc_path *path)
{
	LIST_INIT(&pacer->frms);
	pacer->path = path;
	//pacer->next = TICK_ETERNITY;
	//pacer->next = now_ms;

	//pacer->curr = now_ms;
	//pacer->curr = TICK_ETERNITY;
	//pacer->pkt_ms = 0;
	//pacer->sent = 0;
	
	pacer->last_sent = now_ms;
	//pacer->budget = global.tune.quic_frontend_max_tx_burst;
	pacer->budget = 0;
	pacer->burst = global.tune.quic_frontend_max_tx_burst;
	pacer->next = TICK_ETERNITY;
}

static inline void quic_pacing_reset(struct quic_pacer *pacer)
{
	struct quic_frame *frm;

	while (!LIST_ISEMPTY(&pacer->frms)) {
		frm = LIST_ELEM(pacer->frms.n, struct quic_frame *, list);
		/* qc_frm_free is responsible to detach frm from pacer list. */
		qc_frm_free(NULL, &frm);
	}
}

static inline struct list *quic_pacing_frms(struct quic_pacer *pacer)
{
	return &pacer->frms;
}

static inline int quic_pacing_ns_pkt(const struct quic_pacer *pacer, int sent)
{
	//return pacer->path->loss.srtt * 1000000 / (pacer->path->cwnd / pacer->path->mtu + 1);
	//ullong val = pacer->path->loss.srtt / (pacer->path->cwnd / (pacer->path->mtu * sent) + 1);
	//fprintf(stderr, "val=%llu %d/(%lu/(%zu * %d) + 1\n",
	//        val, pacer->path->loss.srtt, pacer->path->cwnd, pacer->path->mtu, sent);
	//return pacer->path->loss.srtt / (pacer->path->cwnd / (pacer->path->mtu * sent) + 1);
	return (pacer->path->cwnd / (pacer->path->mtu + 1)) / (pacer->path->loss.srtt + 1) + 1;
}

//int quic_pacing_expired(const struct quic_pacer *pacer);

enum quic_tx_err quic_pacing_send(struct quic_pacer *pacer, struct quic_conn *qc);

int quic_pacing_prepare(struct quic_pacer *pacer);

//void quic_pacing_sent_done(struct quic_pacer *pacer, int sent);
int quic_pacing_sent_done(struct quic_pacer *pacer, int sent, enum quic_tx_err err);

int quic_pacing_next(struct quic_pacer *pacer);

#endif /* _HAPROXY_QUIC_PACING_H */
