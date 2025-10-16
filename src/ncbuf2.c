#include <haproxy/ncbuf2.h>

#include <string.h>

#ifdef STANDALONE
#include <stdio.h>
#endif /* STANDALONE */

#ifdef DEBUG_STRICT
# include <haproxy/bug.h>
#else
# include <stdio.h>
# include <stdlib.h>

# undef  BUG_ON
# define BUG_ON(x)     if (x) { fprintf(stderr, "CRASH ON %s:%d\n", __func__, __LINE__); abort(); }

# undef  BUG_ON_HOT
# define BUG_ON_HOT(x) if (x) { fprintf(stderr, "CRASH ON %s:%d\n", __func__, __LINE__); abort(); }
#endif /* DEBUG_DEV */

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

/* ******** bit set/unset utilities ******** */

static void bit_unset(unsigned char *value, char i)
{
	*value &= ~(1 << (8 - i));
}

/* ******** public API ******** */

void ncb2_init(struct ncbuf2 *buf, ncb2_sz_t head)
{
	BUG_ON_HOT(ncb2_is_null(buf));

	BUG_ON_HOT(head >= buf->size);
	buf->head = head;
	memset(buf->bitmap, 0, buf->bitmap_sz);
}

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
	size_t i = 0;

	if (ncb2_is_null(buf))
		return 1;

	for (i = 0; i < buf->bitmap_sz; ++i) {
		if (buf->bitmap[i])
			return 0;
	}

	return 1;
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
	struct itbmap it;

	BUG_ON_HOT(adv > ncb2_size(buf));

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

#ifdef STANDALONE

static void ncbuf2_print_buf(struct ncbuf2 *b)
{
	ncb2_sz_t data;
	int i;

	for (i = 0; i < b->size; ++i) {
		if (i && !(i % 8)) fprintf(stderr, " ");
		else if (i && !(i % 4)) fprintf(stderr, ".");
		fprintf(stderr, "%02x", (unsigned char)b->area[i]);
	}

	fprintf(stderr, " [");
	for (i = 0; i < b->bitmap_sz; ++i)
		fprintf(stderr, "%02x", (unsigned char)b->bitmap[i]);
	fprintf(stderr, "]\n");
}

static void itbmap_print(const struct ncbuf2 *buf, const struct itbmap *it)
{
	struct itbmap i = *it;

	while (1) {
		if (!i.b) {
			fprintf(stderr, "it %p\n", (unsigned char)i.b);
			break;
		}

		fprintf(stderr, "it %p:%zu mask %02x bitcount %d\n", (unsigned char)i.b, i.off, i.mask, i.bitcount);
		i = itbmap_next(buf, &i);
	}
}

#define NCB2_DATA_EQ(buf, off, data) \
  BUG_ON(ncb2_data((buf), (off)) != (data));

#if 1
int main(int argc, char **argv)
{
	char area[1024];
	char data[1024];
	struct ncbuf2 buf;
	struct itbmap it;

	memset(data, 0x11, 1024);

	buf = ncb2_make(area, 8, 0);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 0, 0);

	ncb2_add(&buf, 1, data, 3, NCB_ADD_COMPARE);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 1, 3);
	ncb2_advance(&buf, 2);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 0, 2);
	ncb2_advance(&buf, 2);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 0, 0);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 10, 0);
	ncbuf2_print_buf(&buf);

	ncb2_add(&buf, 1, data, 6, NCB_ADD_COMPARE);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 1, 6);
	ncb2_add(&buf, 7, data, 1, NCB_ADD_COMPARE);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 1, 7);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 30, 15);
	ncbuf2_print_buf(&buf);

	ncb2_add(&buf, 0, data, 17, NCB_ADD_COMPARE);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 0, 17);
	ncb2_add(&buf, 17, data, 1, NCB_ADD_COMPARE);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 0, 18);
	ncb2_add(&buf, 20, data, 6, NCB_ADD_COMPARE);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 20, 6);
	ncb2_add(&buf, 18, data, 2, NCB_ADD_COMPARE);
	ncbuf2_print_buf(&buf);
	NCB2_DATA_EQ(&buf, 0, 26);
	NCB2_DATA_EQ(&buf, 1, 25);
	ncb2_advance(&buf, 15);
	NCB2_DATA_EQ(&buf, 0, 11);
	ncbuf2_print_buf(&buf);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 8, 0); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 0); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 8, 0); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 1); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 9, 0); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 0); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 9, 0); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 6); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 9, 0); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 7); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	//buf = ncb2_make(area, 9, 0); ncbuf2_print_buf(&buf);
	//fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	//it = itbmap_get(&buf, 8); itbmap_print(&buf, &it);
	//fprintf(stderr, "\n");

	buf = ncb2_make(area, 12, 4); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 0); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 12, 4); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 3); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 12, 4); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 4); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 12, 4); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 5); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	buf = ncb2_make(area, 24, 0); ncbuf2_print_buf(&buf);
	fprintf(stderr, "bm %p\n", (unsigned char)buf.bitmap);
	it = itbmap_get(&buf, 0); itbmap_print(&buf, &it);
	fprintf(stderr, "\n");

	return 0;
}
#endif

#endif /* STANDALONE */
