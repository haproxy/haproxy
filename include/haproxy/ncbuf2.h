#ifndef _HAPROXY_NCBUF2_H
#define _HAPROXY_NCBUF2_H

#include <haproxy/ncbuf2-t.h>
#include <haproxy/ncbuf_common-t.h>

struct ncbuf2 ncb2_make(char *area, ncb2_sz_t size, ncb2_sz_t head);

static inline char *ncb2_orig(const struct ncbuf2 *buf)
{
	return buf->area;
}

static inline char *ncb2_head(const struct ncbuf2 *buf)
{
	return buf->area + buf->head;
}

static inline char *ncb2_wrap(const struct ncbuf2 *buf)
{
	return buf->area + buf->size;
}

enum ncb_ret ncb2_add(struct ncbuf2 *buf, ncb2_sz_t off,
                      const char *data, ncb2_sz_t len, enum ncb_add_mode mode);

#endif /* _HAPROXY_NCBUF2_H */
