#ifndef _HAPROXY_QUIC_PACING_H
#define _HAPROXY_QUIC_PACING_H

#include <haproxy/quic_pacing-t.h>

static inline void quic_pacing_init(struct quic_pacer *pacer,
                                    const struct quic_cc_path *path)
{
	pacer->path = path;
}

#endif /* _HAPROXY_QUIC_PACING_H */
