#include <haproxy/ncbmbuf.h>

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
	unsigned char *b;

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
	unsigned char *b;
	ncb_sz_t off; /* offset relative to buf head */
	unsigned char mask; /* usable bits depending on <off> and buf data storage */
	unsigned char bits; /* count of bits set in <mask> */
};

/* Returns true if all bits masked in <it> are set. */
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
	BUG_ON_HOT(off_bmap >= buf->size_bm);

	it->b = buf->bitmap + off_bmap;
	it->off = off;
	it->mask = 0xff;
	it->bits = 8;

	/* Adjust mask for last bitmap byte. */
	if (off_bmap == buf->size_bm - 1 && (sz % 8)) {
		it->mask <<= 8 - (sz % 8);
		it->bits -= 8 - (sz % 8);
	}

	/* Adjust mask if iterator starts unaligned. */
	if (off_abs % 8) {
		it->mask &= (0xff >> (off_abs % 8));
		it->bits -= off_abs % 8;
	}

	/* Adjust mask if iterator ends unaligned. */
	if (it->off + it->bits > sz) {
		it->mask &= (0xff << (it->off + it->bits - sz));
		it->bits -= it->off + it->bits - sz;
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
static struct itbmap itbmap_next(const struct ncbmbuf *buf,
                                 const struct itbmap *prev)
{
	const ncb_sz_t off_next = prev->off + prev->bits;
	struct itbmap next;

	BUG_ON_HOT(off_next > ncbmb_size(buf));

	if (off_next == ncbmb_size(buf)) {
		next.b = NULL;
		next.off = off_next;
	}
	else {
		itbmap_load(&next, prev->off + prev->bits, buf);
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
		count += it.bits;
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
		if (it.bits <= adv) {
			adv -= it.bits;
			/* Reset all bits in current bitmap byte. */
			*it.b &= ~it.mask;
			buf->head += it.bits;
		}
		else {
			int i = 1;

			while (!(it.mask & 0x80)) {
				it.mask <<= 1;
				++i;
			}

			/* Last bitmap byte to adjust, unset each bit
			 * individually until new offset is reached.
			 */
			while (adv) {
				bit_unset(it.b, i);
				--adv;
				++i;
				++buf->head;
			}
		}

		/* Adjust head if pointer has wrapped. */
		if (buf->head >= ncbmb_size(buf)) {
			BUG_ON_HOT(buf->head >= ncbmb_size(buf) * 2);
			buf->head -= ncbmb_size(buf);
		}
	}

	return NCB_RET_OK;
}

#ifdef STANDALONE

static void ncbmbuf_print_buf(struct ncbmbuf *b, int line)
{
	ncb_sz_t data;
	int i;

	fprintf(stderr, "[%03d] ", line);

	for (i = 0; i < b->size; ++i) {
		if (i && !(i % 8)) fprintf(stderr, " ");
		else if (i && !(i % 4)) fprintf(stderr, ".");
		fprintf(stderr, "%02x", (unsigned char)b->area[i]);
	}

	fprintf(stderr, " [");
	for (i = 0; i < b->size_bm; ++i)
		fprintf(stderr, "%02x", (unsigned char)b->bitmap[i]);
	fprintf(stderr, "]\n");
}

#define NCBMB_DATA_EQ(buf, off, data) \
  BUG_ON(ncbmb_data((buf), (off)) != (data))

void test_ncbmb(void)
{
	char *area = calloc(16384, 1);
	char *data = calloc(16384, 1);
	struct ncbmbuf buf;

	memset(data, 0x11, 16384);

	/* 7 bytes data // 1 byte bitmap (0xfe) */
	buf = ncbmb_make(area, 8, 0);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 0);

	ncbmb_add(&buf, 1, data, 3, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 1, 3);
	ncbmb_advance(&buf, 2);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 2);
	ncbmb_advance(&buf, 7);
	ncbmb_add(&buf, 0, data, 7, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 7);

	/* 7 bytes data // 1 byte bitmap (0xfe) */
	buf = ncbmb_make(area, 8, 0);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 0);
	ncbmb_add(&buf, 0, data, 2, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 2);
	ncbmb_add(&buf, 4, data, 2, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__);
	NCBMB_DATA_EQ(&buf, 0, 2); NCBMB_DATA_EQ(&buf, 4, 2);
	ncbmb_add(&buf, 2, data, 2, NCB_ADD_OVERWRT);
	ncbmb_add(&buf, 6, data, 1, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 7);
	fprintf(stderr, "\n");

	/* 8 bytes data // 1 byte bitmap (no unused) */
	buf = ncbmb_make(area, 9, 4); ncbmbuf_print_buf(&buf, __LINE__);

	ncbmb_add(&buf, 1, data, 6, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 1, 6);
	ncbmb_add(&buf, 7, data, 1, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 1, 7);
	fprintf(stderr, "\n");

	/* 8 bytes data // 2 bytes bitmap (0x00) */
	buf = ncbmb_make(area, 10, 0);
	ncbmbuf_print_buf(&buf, __LINE__);

	ncbmb_add(&buf, 0, data, 5, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 5);
	ncbmb_add(&buf, 7, data, 1, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 7, 1);
	ncbmb_add(&buf, 5, data, 3, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 8);
	fprintf(stderr, "\n");

	/* 26 bytes data // 4 bytes bitmap (0xc0) */
	buf = ncbmb_make(area, 30, 15); ncbmbuf_print_buf(&buf, __LINE__);

	ncbmb_add(&buf, 0, data, 12, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 0, 12);
	ncbmb_add(&buf, 19, data, 1, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 19, 1);
	ncbmb_add(&buf, 20, data, 6, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__); NCBMB_DATA_EQ(&buf, 19, 7);
	ncbmb_add(&buf, 12, data, 10, NCB_ADD_OVERWRT);
	ncbmbuf_print_buf(&buf, __LINE__);
	NCBMB_DATA_EQ(&buf, 0, 26); NCBMB_DATA_EQ(&buf, 1, 25);
	ncbmb_advance(&buf, 15);
	NCBMB_DATA_EQ(&buf, 0, 11); ncbmbuf_print_buf(&buf, __LINE__);
	fprintf(stderr, "\n");

	free(area); free(data);
}

#define ITBMAP_CHECK(it, m, b) \
  BUG_ON((it).mask != (m) || (it).bits != (b))

void test_itbmap(void)
{
	struct itbmap it;
	char *area = calloc(16384, 1);
	struct ncbmbuf buf;

	/* 7 bytes data // 1 byte bitmap (0xfe) */
	buf = ncbmb_make(area, 8, 0); ncbmbuf_print_buf(&buf, __LINE__);
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0xfe, 7);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	it = itbmap_get(&buf, 1); ITBMAP_CHECK(it, 0x7e, 6);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	/* 8 bytes data // 1 byte bitmap (no unused) */
	buf = ncbmb_make(area, 9, 0); ncbmbuf_print_buf(&buf, __LINE__);
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);
	it = itbmap_get(&buf, 6); ITBMAP_CHECK(it, 0x03, 2);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);
	it = itbmap_get(&buf, 7); ITBMAP_CHECK(it, 0x01, 1);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	/* 10 bytes data // 2 bytes bitmap (0xc0) */
	buf = ncbmb_make(area, 12, 0); ncbmbuf_print_buf(&buf, __LINE__);
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	buf.head = 3;
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0x1f, 5);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xe0, 3);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	buf.head = 4;
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0x0f, 4);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xf0, 4);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	buf.head = 7;
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0x01, 1);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xfe, 7);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	buf.head = 8;
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	/* 8 bytes data // 2 bytes bitmap (0x00) */
	buf = ncbmb_make(area, 10, 0); ncbmbuf_print_buf(&buf, __LINE__);
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	it = itbmap_get(&buf, 4); ITBMAP_CHECK(it, 0x0f, 4);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	it = itbmap_get(&buf, 6); ITBMAP_CHECK(it, 0x03, 2);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	buf.head = 7;
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0x01, 1);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xfe, 7);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	/* 26 bytes data // 4 bytes bitmap (0xc0) */
	buf = ncbmb_make(area, 30, 0); ncbmbuf_print_buf(&buf, __LINE__);
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	it = itbmap_get(&buf, 15); ITBMAP_CHECK(it, 0x01, 1);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	buf.head = 15;
	it = itbmap_get(&buf, 0); ITBMAP_CHECK(it, 0x01, 1);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xc0, 2);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xff, 8);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xfe, 7);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	it = itbmap_get(&buf, 15); ITBMAP_CHECK(it, 0x0f, 4);
	it = itbmap_next(&buf, &it); ITBMAP_CHECK(it, 0xfe, 7);
	it = itbmap_next(&buf, &it); BUG_ON(it.b);

	free(area);
}

/* Real example of QUIC CRYPTO frames received from ngtcp2 client. */
void test_ngtcp2_crypto(void)
{
	char *area = calloc(16384, 1);
	char *data = calloc(16384, 1);
	struct ncbmbuf buf;

	memset(data, 0x11, 16384);

	buf = ncbmb_make(area, 16384, 0);
	ncbmb_add(&buf, 371, data, 14, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 371, 14);
	ncbmb_add(&buf, 430, data, 59, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 430, 59);
	ncbmb_add(&buf, 607, data, 472, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 607, 472);
	ncbmb_add(&buf, 489, data, 118, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 489, 590);
	ncbmb_add(&buf, 66, data, 67, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 66, 67);
	ncbmb_add(&buf, 385, data, 15, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 385, 15);
	ncbmb_add(&buf, 135, data, 118, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 135, 118);
	ncbmb_add(&buf, 0, data, 66, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 0, 133);
	ncbmb_add(&buf, 400, data, 15, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 400, 15);
	ncbmb_add(&buf, 253, data, 118, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 253, 162);
	ncbmb_add(&buf, 415, data, 15, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 400, 679);
	ncbmb_add(&buf, 133, data, 1, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 0, 134);
	ncbmb_add(&buf, 134, data, 1, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 0, 1079);

	ncbmb_add(&buf, 1265, data, 187, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1265, 187);
	ncbmb_add(&buf, 1218, data, 47, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1218, 234);
	ncbmb_add(&buf, 1192, data, 3, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1192, 3);
	ncbmb_add(&buf, 1177, data, 3, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1177, 3);
	ncbmb_add(&buf, 1125, data, 47, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1125, 47);
	ncbmb_add(&buf, 1172, data, 5, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1125, 55);
	ncbmb_add(&buf, 1079, data, 46, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 0, 1180);
	ncbmb_add(&buf, 1195, data, 23, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1192, 260);
	ncbmb_add(&buf, 1183, data, 6, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 1183, 6);
	ncbmb_add(&buf, 1180, data, 3, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 0, 1189);
	ncbmb_add(&buf, 1189, data, 3, NCB_ADD_OVERWRT);
	NCBMB_DATA_EQ(&buf, 0, 1452);

	free(area); free(data);
}

int main(int argc, char **argv)
{
	test_ncbmb();
	test_itbmap();
	test_ngtcp2_crypto();
	return 0;
}

#endif /* STANDALONE */
