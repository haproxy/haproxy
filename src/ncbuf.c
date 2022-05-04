#include <haproxy/ncbuf.h>

#ifdef DEBUG_DEV
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

#define NCB_BLK_NULL ((struct ncb_blk){ .st = NULL })

#define NCB_BK_F_GAP  0x01  /* block represents a gap */
#define NCB_BK_F_FIN  0x02  /* special reduced gap present at the end of the buffer */
struct ncb_blk {
	char *st;  /* first byte of the block */
	char *end; /* first byte after this block */

	char *sz_ptr; /* pointer to size element - NULL for reduced gap */
	ncb_sz_t sz; /* size of the block */
	ncb_sz_t sz_data; /* size of the data following the block - invalid for reduced GAP */
	ncb_sz_t off; /* offset of block in buffer */

	char flag;
};

/* Return pointer to <off> relative to <buf> head. Support buffer wrapping. */
static char *ncb_peek(const struct ncbuf *buf, ncb_sz_t off)
{
	char *ptr = ncb_head(buf) + off;
	if (ptr >= buf->area + buf->size)
		ptr -= buf->size;
	return ptr;
}

/* Returns the reserved space of <buf> which contains the size of the first
 * data block.
 */
static char *ncb_reserved(const struct ncbuf *buf)
{
	return ncb_peek(buf, buf->size - NCB_RESERVED_SZ);
}

/* Encode <off> at <st> position in <buf>. Support wrapping. */
static void ncb_write_off(const struct ncbuf *buf, char *st, ncb_sz_t off)
{
	int i;

	BUG_ON_HOT(st >= buf->area + buf->size);

	for (i = 0; i < sizeof(ncb_sz_t); ++i) {
		(*st) = off >> (8 * i) & 0xff;

		if ((++st) == ncb_wrap(buf))
			st = ncb_orig(buf);
	}
}

/* Decode offset stored at <st> position in <buf>. Support wrapping. */
static ncb_sz_t ncb_read_off(const struct ncbuf *buf, char *st)
{
	int i;
	ncb_sz_t off = 0;

	BUG_ON_HOT(st >= buf->area + buf->size);

	for (i = 0; i < sizeof(ncb_sz_t); ++i) {
		off |= (unsigned char )(*st) << (8 * i);

		if ((++st) == ncb_wrap(buf))
			st = ncb_orig(buf);
	}

	return off;
}

/* Returns true if a gap cannot be inserted at <off> : a reduced gap must be used. */
static int ncb_off_reduced(const struct ncbuf *b, ncb_sz_t off)
{
	return off + NCB_GAP_MIN_SZ > ncb_size(b);
}

/* Returns true if <blk> is the special NULL block. */
static int ncb_blk_is_null(const struct ncb_blk blk)
{
	return !blk.st;
}

/* Returns true if <blk> is the last block of <buf>. */
static int ncb_blk_is_last(const struct ncbuf *buf, const struct ncb_blk blk)
{
	BUG_ON_HOT(blk.off + blk.sz > ncb_size(buf));
	return blk.off + blk.sz == ncb_size(buf);
}

/* Returns the first block of <buf> which is always a DATA. */
static struct ncb_blk ncb_blk_first(const struct ncbuf *buf)
{
	struct ncb_blk blk;

	blk.st = ncb_head(buf);

	blk.sz_ptr = ncb_reserved(buf);
	blk.sz = ncb_read_off(buf, ncb_reserved(buf));
	BUG_ON_HOT(blk.sz > ncb_size(buf));

	blk.end = ncb_peek(buf, blk.sz);
	blk.off = 0;
	blk.flag = 0;

	return blk;
}

/* Returns the block following <prev> in the buffer <buf>. */
static struct ncb_blk ncb_blk_next(const struct ncbuf *buf,
                                   const struct ncb_blk prev)
{
	struct ncb_blk blk;

	BUG_ON_HOT(ncb_blk_is_null(prev));

	if (ncb_blk_is_last(buf, prev))
		return NCB_BLK_NULL;

	blk.st = prev.end;
	blk.off = prev.off + prev.sz;
	blk.flag = ~prev.flag & NCB_BK_F_GAP;

	if (blk.flag & NCB_BK_F_GAP) {
		if (ncb_off_reduced(buf, blk.off)) {
			blk.flag |= NCB_BK_F_FIN;
			blk.sz_ptr = NULL;
			blk.sz = ncb_size(buf) - blk.off;
			blk.sz_data = 0;

			/* A reduced gap can only be the last block. */
			BUG_ON_HOT(!ncb_blk_is_last(buf, blk));
		}
		else {
			blk.sz_ptr = ncb_peek(buf, blk.off + NCB_GAP_SZ_OFF);
			blk.sz = ncb_read_off(buf, blk.sz_ptr);
			blk.sz_data = ncb_read_off(buf, ncb_peek(buf, blk.off + NCB_GAP_SZ_DATA_OFF));
			BUG_ON_HOT(blk.sz < NCB_GAP_MIN_SZ);
		}
	}
	else {
		blk.sz_ptr = ncb_peek(buf, prev.off + NCB_GAP_SZ_DATA_OFF);
		blk.sz = prev.sz_data;
		blk.sz_data = 0;

		/* only first DATA block can be empty. If this happens, a GAP
		 * merge should have been realized.
		 */
		BUG_ON_HOT(!blk.sz);
	}

	BUG_ON_HOT(blk.off + blk.sz > ncb_size(buf));
	blk.end = ncb_peek(buf, blk.off + blk.sz);

	return blk;
}

/* Returns the block containing offset <off>. Note that if <off> is at the
 * frontier between two blocks, this function will return the preceding one.
 * This is done to easily merge blocks on insertion/deletion.
 */
static struct ncb_blk ncb_blk_find(const struct ncbuf *buf, ncb_sz_t off)
{
	struct ncb_blk blk;

	BUG_ON_HOT(off >= ncb_size(buf));

	for (blk = ncb_blk_first(buf); off > blk.off + blk.sz;
	     blk = ncb_blk_next(buf, blk)) {
	}

	return blk;
}

/* Transform absolute offset <off> to a relative one from <blk> start. */
static ncb_sz_t ncb_blk_off(const struct ncb_blk blk, ncb_sz_t off)
{
	BUG_ON_HOT(off < blk.off || off > blk.off + blk.sz);
	BUG_ON_HOT(off - blk.off > blk.sz);
	return off - blk.off;
}

/* ******** public API ******** */

int ncb_is_null(const struct ncbuf *buf)
{
	return buf->size == 0;
}

/* Initialize or reset <buf> by clearing all data. Its size is untouched.
 * Buffer is positioned to <head> offset. Use 0 to realign it.
 */
void ncb_init(struct ncbuf *buf, ncb_sz_t head)
{
	BUG_ON_HOT(head >= buf->size);
	buf->head = head;

	ncb_write_off(buf, ncb_reserved(buf), 0);
	ncb_write_off(buf, ncb_head(buf), ncb_size(buf));
	ncb_write_off(buf, ncb_peek(buf, sizeof(ncb_sz_t)), 0);
}

/* Construct a ncbuf with all its parameters. */
struct ncbuf ncb_make(char *area, ncb_sz_t size, ncb_sz_t head)
{
	struct ncbuf buf;

	/* Ensure that there is enough space for the reserved space and data.
	 * This is the minimal value to not crash later.
	 */
	BUG_ON_HOT(size <= NCB_RESERVED_SZ);

	buf.area = area;
	buf.size = size;
	buf.head = head;

	return buf;
}

/* Returns start of allocated buffer area. */
char *ncb_orig(const struct ncbuf *buf)
{
	return buf->area;
}

/* Returns current head pointer into buffer area. */
char *ncb_head(const struct ncbuf *buf)
{
	return buf->area + buf->head;
}

/* Returns the first byte after the allocated buffer area. */
char *ncb_wrap(const struct ncbuf *buf)
{
	return buf->area + buf->size;
}

/* Returns the usable size of <buf> for data storage. This is the size of the
 * allocated buffer without the reserved header space.
 */
ncb_sz_t ncb_size(const struct ncbuf *buf)
{
	return buf->size - NCB_RESERVED_SZ;
}

/* Returns the total number of bytes stored in whole <buf>. */
ncb_sz_t ncb_total_data(const struct ncbuf *buf)
{
	struct ncb_blk blk;
	int total = 0;

	for (blk = ncb_blk_first(buf); !ncb_blk_is_null(blk); blk = ncb_blk_next(buf, blk)) {
		if (!(blk.flag & NCB_BK_F_GAP))
			total += blk.sz;
	}

	return total;
}

/* Returns true if there is no data anywhere in <buf>. */
int ncb_is_empty(const struct ncbuf *buf)
{
	BUG_ON_HOT(*ncb_reserved(buf) + *ncb_head(buf) > ncb_size(buf));
	return *ncb_reserved(buf) == 0 && *ncb_head(buf) == ncb_size(buf);
}

/* Returns true if no more data can be inserted in <buf>. */
int ncb_is_full(const struct ncbuf *buf)
{
	BUG_ON_HOT(ncb_read_off(buf, ncb_reserved(buf)) > ncb_size(buf));
	return ncb_read_off(buf, ncb_reserved(buf)) == ncb_size(buf);
}

/* Returns the number of bytes of data avaiable in <buf> starting at offset
 * <off> until the next gap or the buffer end. The counted data may wrapped if
 * the buffer storage is not aligned.
 */
ncb_sz_t ncb_data(const struct ncbuf *buf, ncb_sz_t off)
{
	struct ncb_blk blk = ncb_blk_find(buf, off);
	ncb_sz_t off_blk = ncb_blk_off(blk, off);

	/* if <off> at the frontier between two and <blk> is gap, retrieve the
	 * next data block.
	 */
	if (blk.flag & NCB_BK_F_GAP && off_blk == blk.sz &&
	    !ncb_blk_is_last(buf, blk)) {
		blk = ncb_blk_next(buf, blk);
		off_blk = ncb_blk_off(blk, off);
	}

	if (blk.flag & NCB_BK_F_GAP)
		return 0;

	return blk.sz - off_blk;
}
