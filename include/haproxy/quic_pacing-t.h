#ifndef _HAPROXY_QUIC_PACING_T_H
#define _HAPROXY_QUIC_PACING_T_H

#include <haproxy/api-t.h>
#include <haproxy/quic_cc-t.h>

struct quic_pacer {
	const struct quic_cc *cc; /* Congestion controler algo used for this connection */
};

#endif /* _HAPROXY_QUIC_PACING_T_H */
