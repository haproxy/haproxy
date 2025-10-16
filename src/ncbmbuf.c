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

static char *ncbmb_peek(const struct ncbmbuf *buf, ncb_sz_t off)
{
	char *ptr = ncbmb_head(buf) + off;
	if (ptr >= buf->area + buf->size)
		ptr -= buf->size;
	return ptr;
}

static void ncbmb_set_bitmap(struct ncbmbuf *buf, ncb_sz_t off, ncb_sz_t len)
{
	const ncb_sz_t sz = ncbmb_size(buf);
	ncb_sz_t off_abs;
	unsigned char mod;
	char *b;

	off_abs = off < sz ? off : off - sz;
	b = buf->bitmap + (off_abs / 8);

	mod = off_abs % 8;
	if (mod) {
		/* adjust first bitmap byte bit by bit if not aligned on 8 */
		unsigned char to_copy = len < 8 - mod ? len : 8 - mod;
		*b |= (unsigned char)(0xff << (8 - to_copy)) >> mod;
		len -= to_copy;
		++b;
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
}

/* Type representing a bitmap byte. */
struct itbmap {
	char *b;
	ncb_sz_t off;
	unsigned char mask;
	unsigned char bitcount;
};

static int itbmap_is_full(const struct itbmap *it)
{
	if (!it->b)
		return 0;

	return (*it->b & it->mask) == it->mask;
}

static void itbmap_load(struct itbmap *it, ncb_sz_t off,
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
static struct itbmap itbmap_get(const struct ncbmbuf *buf, ncb_sz_t off)
{
	struct itbmap it;

	BUG_ON(off >= ncbmb_size(buf));

	itbmap_load(&it, off, buf);
	return it;
}

/* Returns the next bitmap byte relative to <prev> iterator. */
static struct itbmap itbmap_next(const struct ncbmbuf *buf, const struct itbmap *prev)
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

/* ******** bit set/unset utilities ******** */

static void bit_unset(unsigned char *value, char i)
{
	*value &= ~(1 << (8 - i));
}

/* ******** public API ******** */

/* Initialize or reset <buf> by clearing all data. Its size is untouched.
 * Buffer is positioned to <head> offset. Use 0 to realign it. <buf> must not
 * be NCBUF_NULL.
 */
void ncbmb_init(struct ncbmbuf *buf, ncb_sz_t head)
{
	BUG_ON_HOT(ncbmb_is_null(buf));

	BUG_ON_HOT(head >= buf->size);
	buf->head = head;
	memset(buf->bitmap, 0, buf->bitmap_sz);
}

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
	size_t i = 0;

	if (ncbmb_is_null(buf))
		return 1;

	for (i = 0; i < buf->bitmap_sz; ++i) {
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

/* Returns the number of bytes of data available in <buf> starting at offset
 * <off> until the next gap or the buffer end. The counted data may wrapped if
 * the buffer storage is not aligned.
 */
ncb_sz_t ncbmb_data(const struct ncbmbuf *buf, ncb_sz_t off)
{
	struct itbmap it = itbmap_get(buf, off);
	unsigned char value;
	ncb_sz_t count = 0;

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

/* Add a new block at <data> of size <len> in <buf> at offset <off>. Note that
 * currently only NCB_ADD_OVERWRT mode is supported.
 *
 * Always returns NCB_RET_OK as this operation cannot fail.
 */
enum ncb_ret ncbmb_add(struct ncbmbuf *buf, ncb_sz_t off,
                       const char *data, ncb_sz_t len, enum ncb_add_mode mode)
{
	char *ptr = ncbmb_peek(buf, off);

	BUG_ON_HOT(mode != NCB_ADD_OVERWRT);

	BUG_ON_HOT(off + len > buf->size);

	if (ptr + len >= ncbmb_wrap(buf)) {
		ncb_sz_t sz1 = ncbmb_wrap(buf) - ptr;

		memcpy(ptr, data, sz1);
		ncbmb_set_bitmap(buf, buf->head + off, sz1);

		memcpy(ncbmb_orig(buf), data + sz1, len - sz1);
		ncbmb_set_bitmap(buf, 0, len - sz1);
	}
	else {
		memcpy(ptr, data, len);
		ncbmb_set_bitmap(buf, buf->head + off, len);
	}

	return NCB_RET_OK;
}

/* Advance the head of <buf> to the offset <adv>. Data at the start of buffer
 * will be lost while some space will be formed at the end to be able to insert
 * new data.
 *
 * Always returns NCB_RET_OK as this operation cannot fail.
 */
enum ncb_ret ncbmb_advance(struct ncbmbuf *buf, ncb_sz_t adv)
{
	struct itbmap it;

	BUG_ON_HOT(adv > ncbmb_size(buf));

	while (adv) {
		it = itbmap_get(buf, 0);
		if (it.bitcount <= adv) {
			adv -= it.bitcount;
			*it.b &= ~it.mask;
			buf->head += it.bitcount;
		}
		else {
			unsigned char mask = 0xff;
			int i = 1;

			while (!(it.mask & 0x80)) {
				it.mask <<= 1;
				++i;
			}

			while (adv && (it.mask & 0x80)) {
				bit_unset(&mask, i);
				--adv;
				++i;
				++buf->head;
			}

			BUG_ON(adv);
			*it.b &= mask;
		}
	}

	return NCB_RET_OK;
}
