#ifndef _HAPROXY_NCBMBUF_H
#define _HAPROXY_NCBMBUF_H

#include <haproxy/ncbmbuf-t.h>

static inline int ncbmb_is_null(const struct ncbmbuf *buf)
{
	return buf->size == 0;
}

void ncbmb_init(struct ncbmbuf *buf, ncb_sz_t head);
struct ncbmbuf ncbmb_make(char *area, ncb_sz_t size, ncb_sz_t head);

/* Returns the usable size of <buf> for data storage. This is the size of the
 * allocated buffer without the bitmap space.
 */
static inline ncb_sz_t ncbmb_size(const struct ncbmbuf *buf)
{
	if (ncbmb_is_null(buf))
		return 0;

	return buf->size;
}

int ncbmb_is_empty(const struct ncbmbuf *buf);

#endif /* _HAPROXY_NCBMBUF_H */
