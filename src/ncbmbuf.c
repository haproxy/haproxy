#include <haproxy/ncbmbuf.h>

#include <string.h>

#ifdef DEBUG_STRICT
# include <haproxy/bug.h>
#else
# include <stdio.h>
# include <stdlib.h>

# undef  BUG_ON
# define BUG_ON(x)     if (x) { fprintf(stderr, "CRASH ON %s:%d\n", __func__, __LINE__); abort(); }

# undef  BUG_ON_HOT
# define BUG_ON_HOT(x) if (x) { fprintf(stderr, "CRASH ON %s:%d\n", __func__, __LINE__); abort(); }
#endif /* DEBUG_STRICT */

/* Initialize or reset <buf> by clearing all data. Its size is untouched.
 * Buffer is positioned to <head> offset. Use 0 to realign it. <buf> must not
 * be NCBUF_NULL.
 */
void ncbmb_init(struct ncbmbuf *buf, ncb_sz_t head)
{
	BUG_ON_HOT(ncbmb_is_null(buf));

	BUG_ON_HOT(head >= buf->size);
	buf->head = head;
	memset(buf->bitmap, 0, buf->size_bm);
}

/* Construct a ncbmbuf with all its parameters. */
struct ncbmbuf ncbmb_make(char *area, ncb_sz_t size, ncb_sz_t head)
{
	struct ncbmbuf buf;
	ncb_sz_t size_bm;

	size_bm = (size + 8) / 9;

	buf.area = area;
	buf.bitmap = (unsigned char *)area + size - size_bm;
	buf.size = size - size_bm;
	buf.size_bm = size_bm;
	buf.head = head;

	memset(area, 0, size);

	return buf;
}

ncb_sz_t ncbmb_total_data(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

/* Returns true if there is no data anywhere in <buf>. */
int ncbmb_is_empty(const struct ncbmbuf *buf)
{
	size_t i = 0;

	if (ncbmb_is_null(buf))
		return 1;

	for (i = 0; i < buf->size_bm; ++i) {
		if (buf->bitmap[i])
			return 0;
	}

	return 1;
}

int ncbmb_is_full(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

int ncbmb_is_fragmented(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

ncb_sz_t ncbmb_data(const struct ncbmbuf *buf, ncb_sz_t off)
{
	/* TODO */
	return 0;
}

enum ncb_ret ncbmb_add(struct ncbmbuf *buf, ncb_sz_t off,
                       const char *data, ncb_sz_t len, enum ncb_add_mode mode)
{
	/* TODO */
	return NCB_RET_OK;
}

enum ncb_ret ncbmb_advance(struct ncbmbuf *buf, ncb_sz_t adv)
{
	/* TODO */
	return NCB_RET_OK;
}
