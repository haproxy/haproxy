#ifndef _HAPROXY_QUIC_PACING_T_H
#define _HAPROXY_QUIC_PACING_T_H

#include <haproxy/api-t.h>
#include <haproxy/quic_cc-t.h>

struct quic_pacer {
	struct list frms;
	const struct quic_cc_path *path;
	//int next;
	//unsigned int curr;
	//int pkt_ms;
	//int sent;
	int burst;
	int budget;
	int last_sent;
	int next;
};

#endif /* _HAPROXY_QUIC_PACING_T_H */
