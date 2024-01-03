#ifndef _HAPROXY_QUIC_FCTL_T_H
#define _HAPROXY_QUIC_FCTL_T_H

#include <stdint.h>

struct quic_fctl {
	/* Offset set by peer which must not be exceeded on send. */
	uint64_t limit;
	/* Offset which must never exceed limit. */
	uint64_t off_real;
	/* Offset which can go beyond limit one time before being blocked. */
	uint64_t off_soft;
};

#endif /* _HAPROXY_QUIC_FCTL_T_H */
