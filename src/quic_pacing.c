#include <haproxy/quic_pacing.h>

#include <haproxy/quic_tx.h>

struct quic_conn;

int quic_pacing_expired(const struct quic_pacer *pacer)
{
	return !pacer->next || pacer->next <= now_mono_time();
}

void quic_pacing_sent_done(struct quic_pacer *pacer, int sent)
{
	pacer->next = now_mono_time() + quic_pacing_ns_pkt(pacer) * sent;
}
