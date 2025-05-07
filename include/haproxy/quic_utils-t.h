#ifndef _HAPROXY_QUIC_UTILS_T_H
#define _HAPROXY_QUIC_UTILS_T_H

#ifdef USE_QUIC

#include <haproxy/api-t.h>

/* Counter which can be used to measure data amount accross several buffers. */
struct bdata_ctr {
	uint64_t tot; /* sum of data present in all underlying buffers */
	uint8_t bcnt; /* current number of allocated underlying buffers */
	uint8_t bmax; /* max number of allocated buffers during stream lifetime */
};

#endif /* USE_QUIC */

#endif /* _HAPROXY_QUIC_UTILS_T_H */
