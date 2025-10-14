#include <haproxy/ncbuf2.h>

#include <string.h>

#include <haproxy/bug.h>

/* ******** internal API ******** */

struct itbmap {
	char *b;
	ncb2_sz_t off;
	unsigned char mask;
	unsigned char bitcount;
};

static int itbmap_is_full(const struct itbmap *it)
{
	if (!it->b)
		return 0;

	return (*it->b & it->mask) == it->mask;
}

static void itbmap_load(struct itbmap *it, ncb2_sz_t off,
                         const struct ncbuf2 *buf)
{
	const ncb2_sz_t sz = ncb2_size(buf);
	ncb2_sz_t off_abs;
	ncb2_sz_t off_bmap;

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

static struct itbmap itbmap_get(const struct ncbuf2 *buf, ncb2_sz_t off)
{
	struct itbmap it;

	BUG_ON(off >= ncb2_size(buf));

	itbmap_load(&it, off, buf);
	return it;
}

static struct itbmap itbmap_next(const struct ncbuf2 *buf, const struct itbmap *prev)
{
	const ncb2_sz_t off_next = prev->off + prev->bitcount;
	struct itbmap next;

	BUG_ON_HOT(off_next > ncb2_size(buf));

	if (off_next == ncb2_size(buf)) {
		next.b = NULL;
		next.off = off_next;
	}
	else {
		itbmap_load(&next, prev->off + prev->bitcount, buf);
	}

	return next;
}

/* ******** public API ******** */

struct ncbuf2 ncb2_make(char *area, ncb2_sz_t size, ncb2_sz_t head)
{
	struct ncbuf2 buf;
	ncb2_sz_t bitmap_sz;

	bitmap_sz = (size + 8) / 9;
	buf.bitmap_sz = bitmap_sz;

	buf.area = area;
	buf.bitmap = area + (size - bitmap_sz);
	buf.size = size - bitmap_sz;
	buf.head = head;

	memset(area, 0, size);

	return buf;
}

ncb2_sz_t ncb2_total_data(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

int ncb2_is_empty(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

int ncb2_is_full(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

int ncb2_is_fragmented(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

ncb2_sz_t ncb2_data(const struct ncbuf2 *buf, ncb2_sz_t off)
{
	/* TODO */
	return 0;
}

enum ncb_ret ncb2_add(struct ncbuf2 *buf, ncb2_sz_t off,
                      const char *data, ncb2_sz_t len, enum ncb_add_mode mode)
{
	char *b;

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
		memset(b, 0xff, to_copy);
		len -= 8 * to_copy;
		b += to_copy;

		if (len) {
			/* adjust last bitmap byte shifted by remaining len */
			*b |= 0xff << (8 - len);
		}
	}
}

enum ncb_ret ncb2_advance(struct ncbuf2 *buf, ncb2_sz_t adv)
{
	/* TODO */
	return NCB_RET_OK;
}
