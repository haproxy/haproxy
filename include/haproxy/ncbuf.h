#ifndef _HAPROXY_NCBUF_H
#define _HAPROXY_NCBUF_H

#include <haproxy/ncbuf-t.h>

static inline int ncb_is_null(const struct ncbuf *buf)
{
	return buf->size == 0;
}

void ncb_init(struct ncbuf *buf, ncb_sz_t head);
struct ncbuf ncb_make(char *area, ncb_sz_t size, ncb_sz_t head);

/* Returns start of allocated buffer area. */
static inline char *ncb_orig(const struct ncbuf *buf)
{
	return buf->area;
}

/* Returns current head pointer into buffer area. */
static inline char *ncb_head(const struct ncbuf *buf)
{
	return buf->area + buf->head;
}

/* Returns the first byte after the allocated buffer area. */
static inline char *ncb_wrap(const struct ncbuf *buf)
{
	return buf->area + buf->size;
}

/* Returns the usable size of <buf> for data storage. This is the size of the
 * allocated buffer without the reserved header space.
 */
static inline ncb_sz_t ncb_size(const struct ncbuf *buf)
{
	if (ncb_is_null(buf))
		return 0;

	return buf->size - NCB_RESERVED_SZ;
}

ncb_sz_t ncb_total_data(const struct ncbuf *buf);
int ncb_is_empty(const struct ncbuf *buf);
int ncb_is_full(const struct ncbuf *buf);
int ncb_is_fragmented(const struct ncbuf *buf);

ncb_sz_t ncb_data(const struct ncbuf *buf, ncb_sz_t offset);

enum ncb_ret ncb_add(struct ncbuf *buf, ncb_sz_t off,
                     const char *data, ncb_sz_t len, enum ncb_add_mode mode);
enum ncb_ret ncb_advance(struct ncbuf *buf, ncb_sz_t adv);

#endif /* _HAPROXY_NCBUF_H */
