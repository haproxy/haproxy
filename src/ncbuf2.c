#include <haproxy/ncbuf2.h>

#include <string.h>


/* ******** internal API ******** */

static char *ncb2_peek(const struct ncbuf2 *buf, ncb2_sz_t off)
{
	char *ptr = ncb2_head(buf) + off;
	if (ptr >= buf->area + buf->size)
		ptr -= buf->size;
	return ptr;
}

static void ncb2_set_bitmap(struct ncbuf2 *buf, ncb2_sz_t off, ncb2_sz_t len)
{
	const ncb2_sz_t sz = ncb2_size(buf);
	ncb2_sz_t off_abs;
	unsigned char mod;
	char *b;

	off_abs = off < sz ? off : off - sz;
	b = buf->bitmap + (off_abs / 8);

	mod = off_abs % 8;
	if (mod) {
		/* adjust first bitmap byte bit by bit if not aligned on 8 */
		size_t to_copy = len < 8 - mod ? len : 8 - mod;
		*b |= (0xff << (8 - to_copy)) >> mod;
		len -= to_copy;
		++b;
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
	struct itbmap it = itbmap_get(buf, off);
	unsigned char value;
	ncb2_sz_t count = 0;

	while (itbmap_is_full(&it)) {
		count += it.bitcount;
		it = itbmap_next(buf, &it);
	}

	if (it.b) {
		value = *it.b & it.mask;
		while (it.mask && !(it.mask & 0x80)) {
			it.mask <<= 1;
			value <<= 1;
		}

		while (it.mask && (it.mask & 0x80) && (value & 0x80)) {
			it.mask <<= 1;
			value <<= 1;
			++count;
		}
	}

	return count;
}

enum ncb_ret ncb2_add(struct ncbuf2 *buf, ncb2_sz_t off,
                      const char *data, ncb2_sz_t len, enum ncb_add_mode mode)
{
	char *ptr = ncb2_peek(buf, off);

	BUG_ON_HOT(off + len > buf->size);

	if (ptr + len >= ncb2_wrap(buf)) {
		ncb2_sz_t sz1 = ncb2_wrap(buf) - ptr;

		memcpy(ptr, data, sz1);
		ncb2_set_bitmap(buf, buf->head + off, sz1);

		memcpy(ncb2_orig(buf), data + sz1, len - sz1);
		ncb2_set_bitmap(buf, 0, len - sz1);
	}
	else {
		memcpy(ptr, data, len);
		ncb2_set_bitmap(buf, buf->head + off, len);
	}

	return NCB_RET_OK;
}

enum ncb_ret ncb2_advance(struct ncbuf2 *buf, ncb2_sz_t adv)
{
	/* TODO */
	return NCB_RET_OK;
}
