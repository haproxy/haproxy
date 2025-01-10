#ifndef _HAPROXY_QUIC_PACING_T_H
#define _HAPROXY_QUIC_PACING_T_H

#include <haproxy/api-t.h>
#include <haproxy/quic_cc-t.h>

struct quic_pacer {
	const struct quic_cc *cc; /* Congestion controler algo used for this connection */
	ullong cur;  /* Nanosecond timestamp of the last credit reloading */
	uint credit; /* Number of packets which can be emitted in a single burst */

	int last_sent; /* Number of datagrams sent during last paced emission */
};

#endif /* _HAPROXY_QUIC_PACING_T_H */
