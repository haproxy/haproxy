#ifndef _HAPROXY_NCBUF2_T_H
#define _HAPROXY_NCBUF2_T_H

#include <inttypes.h>

typedef uint32_t        ncb2_sz_t;

#define NCBUF2_NULL ((struct ncbuf2){ })

struct ncbuf2 {
	char *area;
	char *bitmap;
	ncb2_sz_t size;
	ncb2_sz_t head;
};

#endif /* _HAPROXY_NCBUF2_T_H */
