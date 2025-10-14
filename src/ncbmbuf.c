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

/* ******** internal API ******** */

/* Type representing a bitmap byte. */
struct itbmap {
	char *b;
	ncb_sz_t off;
	unsigned char mask;
	unsigned char bitcount;
};

static __attribute__((unused)) int itbmap_is_full(const struct itbmap *it)
{
	if (!it->b)
		return 0;

	return (*it->b & it->mask) == it->mask;
}

static __attribute__((unused)) void itbmap_load(struct itbmap *it, ncb_sz_t off,
                                                const struct ncbmbuf *buf)
{
	const ncb_sz_t sz = ncbmb_size(buf);
	ncb_sz_t off_abs;
	ncb_sz_t off_bmap;

	off_abs = buf->head + off;
	if (off_abs >= sz)
		off_abs -= sz;
	off_bmap = off_abs / 8;
	BUG_ON_HOT(off_bmap >= buf->bitmap_sz);

	it->b = buf->bitmap + off_bmap;
	it->off = off;
	it->mask = 0xff;
	it->bitcount = 8;

	if (off_bmap == buf->bitmap_sz - 1 && (sz % 8)) {
		it->mask <<= 8 - (sz % 8);
		it->bitcount -= 8 - (sz % 8);
	}

	if (off_abs % 8) {
		it->mask &= (0xff >> (off_abs % 8));
		it->bitcount -= off_abs % 8;
	}

	if (it->off + it->bitcount > sz) {
		it->mask &= (0xff << (it->off + it->bitcount - sz));
		it->bitcount -= it->off + it->bitcount - sz;
	}
}

/* Returns an iterator on the bitmap byte corresponding to <off> offset
 * relative to <buf> head.
 */
static __attribute__((unused)) struct itbmap itbmap_get(const struct ncbmbuf *buf, ncb_sz_t off)
{
	struct itbmap it;

	BUG_ON(off >= ncbmb_size(buf));

	itbmap_load(&it, off, buf);
	return it;
}

/* Returns the next bitmap byte relative to <prev> iterator. */
static __attribute__((unused)) struct itbmap itbmap_next(const struct ncbmbuf *buf, const struct itbmap *prev)
{
	const ncb_sz_t off_next = prev->off + prev->bitcount;
	struct itbmap next;

	BUG_ON_HOT(off_next > ncbmb_size(buf));

	if (off_next == ncbmb_size(buf)) {
		next.b = NULL;
		next.off = off_next;
	}
	else {
		itbmap_load(&next, prev->off + prev->bitcount, buf);
	}

	return next;
}

/* ******** public API ******** */

/* Construct a ncbmbuf with all its parameters. */
struct ncbmbuf ncbmb_make(char *area, ncb_sz_t size, ncb_sz_t head)
{
	struct ncbmbuf buf;
	ncb_sz_t bitmap_sz;

	bitmap_sz = (size + 8) / 9;
	buf.bitmap_sz = bitmap_sz;

	buf.area = area;
	buf.bitmap = area + (size - bitmap_sz);
	buf.size = size - bitmap_sz;
	buf.head = head;

	memset(area, 0, size);

	return buf;
}

ncb_sz_t ncbmb_total_data(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

int ncbmb_is_empty(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
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

/* Add a new block at <data> of size <len> in <buf> at offset <off>. Note that
 * currently only NCB_ADD_OVERWRT mode is supported.
 *
 * Always returns NCB_RET_OK as this operation cannot fail.
 */
enum ncb_ret ncbmb_add(struct ncbmbuf *buf, ncb_sz_t off,
                       const char *data, ncb_sz_t len, enum ncb_add_mode mode)
{
	char *b;

	BUG_ON_HOT(mode != NCB_ADD_OVERWRT);

	BUG_ON_HOT(off + len > buf->size);
	/* first copy data into buffer */
	memcpy(&buf->area[off], data, len);

	/* adjust bitmap to reflect newly filled content */
	b = buf->bitmap + (off / 8);
	if (off % 8) {
		size_t to_copy = len < 8 - (off % 8) ? len : 8 - (off % 8);
		/* adjust first bitmap byte relative shifted by offset */
		*b++ |= ((unsigned char)(0xff << (8 - to_copy))) >> (off % 8);
		len -= to_copy;
	}

	if (len) {
		size_t to_copy = len / 8;
		/* bulk set bitmap as many as possible */
		if (to_copy) {
			memset(b, 0xff, to_copy);
			len -= 8 * to_copy;
			b += to_copy;
		}

		if (len) {
			/* adjust last bitmap byte shifted by remaining len */
			*b |= 0xff << (8 - len);
		}
	}

	return NCB_RET_OK;
}

enum ncb_ret ncbmb_advance(struct ncbmbuf *buf, ncb_sz_t adv)
{
	/* TODO */
	return NCB_RET_OK;
}
