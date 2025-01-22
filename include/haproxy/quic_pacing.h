#ifndef _HAPROXY_QUIC_PACING_H
#define _HAPROXY_QUIC_PACING_H

#include <haproxy/quic_pacing-t.h>

#include <haproxy/list.h>
#include <haproxy/quic_frame.h>

static inline void quic_pacing_init(struct quic_pacer *pacer,
                                    const struct quic_cc *cc)
{
	pacer->cc = cc;
	pacer->cur = 0;
	pacer->credit = 0;
}

void quic_pacing_sent_done(struct quic_pacer *pacer, int sent);

int quic_pacing_reload(struct quic_pacer *pacer);

#endif /* _HAPROXY_QUIC_PACING_H */
