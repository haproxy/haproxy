#ifndef _HAPROXY_NCBMBUF_H
#define _HAPROXY_NCBMBUF_H

#include <haproxy/ncbmbuf-t.h>

static inline int ncbmb_is_null(const struct ncbmbuf *buf)
{
	return buf->size == 0;
}

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

enum ncb_ret ncbmb_add(struct ncbmbuf *buf, ncb_sz_t off,
                      const char *data, ncb_sz_t len, enum ncb_add_mode mode);

#endif /* _HAPROXY_NCBMBUF_H */
