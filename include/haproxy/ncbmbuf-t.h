#ifndef _HAPROXY_NCBMBUF_T_H
#define _HAPROXY_NCBMBUF_T_H

#include <haproxy/ncbuf_common-t.h>

/* Non-contiguous bitmap buffer
 *
 * This module is an alternative implementation to ncbuf type. Its main
 * difference is that filled blocks and gaps are encoded via a bitmap.
 *
 * The main advantage of the bitmap is that contrary to ncbuf type there is no
 * limitation on the minimal size of gaps. Thus, operation such as add and
 * advance are guaranteed to succeed.
 *
 * Storage is reserved for the bitmap at the end of the buffer area,
 * representing roughly 1/9 of the total space. Thus, usable buffer storage is
 * smaller than the default ncbuf type.
 */

#define NCBMBUF_NULL ((struct ncbmbuf){ })

struct ncbmbuf {
	char *area; /* allocated area used for both data and bitmap storage */
	unsigned char *bitmap; /* bitmap storage located at the end of allocated area */

	ncb_sz_t size;    /* size usable for data storage */
	ncb_sz_t size_bm; /* size of bitmap storage */

	ncb_sz_t head;
};

#endif /* _HAPROXY_NCBMBUF_T_H */
