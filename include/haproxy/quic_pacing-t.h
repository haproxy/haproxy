#ifndef _HAPROXY_QUIC_PACING_T_H
#define _HAPROXY_QUIC_PACING_T_H

#include <haproxy/quic_cc-t.h>

struct quic_pacer {
	const struct quic_cc_path *path;
};

#endif /* _HAPROXY_QUIC_PACING_T_H */
