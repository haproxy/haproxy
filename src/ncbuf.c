#include <haproxy/ncbuf.h>

#include <string.h>

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

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

/* Add <off> to the offset stored at <st> in <buf>. Support wrapping. */
static void ncb_inc_off(const struct ncbuf *buf, char *st, ncb_sz_t off)
{
	const ncb_sz_t old = ncb_read_off(buf, st);
	ncb_write_off(buf, st, old + off);
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

/* Simulate insertion in <buf> of <data> of length <len> at offset <off>. This
 * ensures that minimal block size are respected for newly formed gaps. <blk>
 * must be the block where the insert operation begins. If <mode> is
 * NCB_ADD_COMPARE, old and new overlapped data are compared to validate the
 * insertion.
 *
 * Returns NCB_RET_OK if insertion can proceed.
 */
static enum ncb_ret ncb_check_insert(const struct ncbuf *buf,
                                     struct ncb_blk blk, ncb_sz_t off,
                                     const char *data, ncb_sz_t len,
                                     enum ncb_add_mode mode)
{
	ncb_sz_t off_blk = ncb_blk_off(blk, off);
	ncb_sz_t to_copy;
	ncb_sz_t left = len;

	/* If insertion starts in a gap, it must leave enough space to keep the
	 * gap header.
	 */
	if (left && (blk.flag & NCB_BK_F_GAP)) {
		if (off_blk < NCB_GAP_MIN_SZ)
			return NCB_RET_GAP_SIZE;
	}

	while (left) {
		off_blk = ncb_blk_off(blk, off);
		to_copy = MIN(left, blk.sz - off_blk);

		if (blk.flag & NCB_BK_F_GAP && off_blk + to_copy < blk.sz) {
			/* Insertion must leave enough space for a new gap
			 * header if stopped in a middle of a gap.
			 */
			const ncb_sz_t gap_sz = blk.sz - (off_blk + to_copy);
			if (gap_sz < NCB_GAP_MIN_SZ && !ncb_blk_is_last(buf, blk))
				return NCB_RET_GAP_SIZE;
		}
		else if (!(blk.flag & NCB_BK_F_GAP) && mode == NCB_ADD_COMPARE) {
			/* Compare memory of data block in NCB_ADD_COMPARE mode. */
			const ncb_sz_t off_blk = ncb_blk_off(blk, off);
			char *st = ncb_peek(buf, off);

			to_copy = MIN(left, blk.sz - off_blk);
			if (st + to_copy > ncb_wrap(buf)) {
				const ncb_sz_t sz1 = ncb_wrap(buf) - st;
				if (memcmp(st, data, sz1))
					return NCB_RET_DATA_REJ;
				if (memcmp(ncb_orig(buf), data + sz1, to_copy - sz1))
					return NCB_RET_DATA_REJ;
			}
			else {
				if (memcmp(st, data, to_copy))
					return NCB_RET_DATA_REJ;
			}
		}

		left -= to_copy;
		data += to_copy;
		off  += to_copy;

		blk = ncb_blk_next(buf, blk);
	}

	return NCB_RET_OK;
}

/* Fill new <data> of length <len> inside an already existing data <blk> at
 * offset <off>. Offset is relative to <blk> so it cannot be greater than the
 * block size. <mode> specifies if old data are preserved or overwritten.
 */
static ncb_sz_t ncb_fill_data_blk(const struct ncbuf *buf,
                                  struct ncb_blk blk, ncb_sz_t off,
                                  const char *data, ncb_sz_t len,
                                  enum ncb_add_mode mode)
{
	const ncb_sz_t to_copy = MIN(len, blk.sz - off);
	char *ptr = NULL;

	BUG_ON_HOT(off > blk.sz);
	/* This can happens due to previous ncb_blk_find() usage. In this
	 * case the current fill is a noop.
	 */
	if (off == blk.sz)
		return 0;

	if (mode == NCB_ADD_OVERWRT) {
		ptr = ncb_peek(buf, blk.off + off);

		if (ptr + to_copy >= ncb_wrap(buf)) {
			const ncb_sz_t sz1 = ncb_wrap(buf) - ptr;
			memcpy(ptr, data, sz1);
			memcpy(ncb_orig(buf), data + sz1, to_copy - sz1);
		}
		else {
			memcpy(ptr, data, to_copy);
		}
	}

	return to_copy;
}

/* Fill the gap <blk> starting at <off> with new <data> of length <len>. <off>
 * is relative to <blk> so it cannot be greater than the block size.
 */
static ncb_sz_t ncb_fill_gap_blk(const struct ncbuf *buf,
                                 struct ncb_blk blk, ncb_sz_t off,
                                 const char *data, ncb_sz_t len)
{
	const ncb_sz_t to_copy = MIN(len, blk.sz - off);
	char *ptr;

	BUG_ON_HOT(off > blk.sz);
	/* This can happens due to previous ncb_blk_find() usage. In this
	 * case the current fill is a noop.
	 */
	if (off == blk.sz)
		return 0;

	/* A new gap must be created if insertion stopped before gap end. */
	if (off + to_copy < blk.sz) {
		const ncb_sz_t gap_off = blk.off + off + to_copy;
		const ncb_sz_t gap_sz = blk.sz - off - to_copy;

		BUG_ON_HOT(!ncb_off_reduced(buf, gap_off) &&
		           blk.off + blk.sz - gap_off < NCB_GAP_MIN_SZ);

		/* write the new gap header unless this is a reduced gap. */
		if (!ncb_off_reduced(buf, gap_off)) {
			char *gap_ptr = ncb_peek(buf, gap_off + NCB_GAP_SZ_OFF);
			char *gap_data_ptr = ncb_peek(buf, gap_off + NCB_GAP_SZ_DATA_OFF);

			ncb_write_off(buf, gap_ptr, gap_sz);
			ncb_write_off(buf, gap_data_ptr, blk.sz_data);
		}
	}

	/* fill the gap with new data */
	ptr = ncb_peek(buf, blk.off + off);
	if (ptr + to_copy >= ncb_wrap(buf)) {
		ncb_sz_t sz1 = ncb_wrap(buf) - ptr;
		memcpy(ptr, data, sz1);
		memcpy(ncb_orig(buf), data + sz1, to_copy - sz1);
	}
	else {
		memcpy(ptr, data, to_copy);
	}

	return to_copy;
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

/* Add a new block at <data> of size <len> in <buf> at offset <off>.
 *
 * Returns NCB_RET_OK on success. On error the following codes are returned :
 * - NCB_RET_GAP_SIZE : cannot add data because the gap formed is too small
 * - NCB_RET_DATA_REJ : old data would be overwritten by different ones in
 *                      NCB_ADD_COMPARE mode.
 */
enum ncb_ret ncb_add(struct ncbuf *buf, ncb_sz_t off,
                     const char *data, ncb_sz_t len, enum ncb_add_mode mode)
{
	struct ncb_blk blk;
	ncb_sz_t left = len;
	enum ncb_ret ret;
	char *new_sz;

	if (!len)
		return NCB_RET_OK;

	BUG_ON_HOT(off + len > ncb_size(buf));

	/* Get block where insertion begins. */
	blk = ncb_blk_find(buf, off);

	/* Check if insertion is possible. */
	ret = ncb_check_insert(buf, blk, off, data, len, mode);
	if (ret != NCB_RET_OK)
		return ret;

	if (blk.flag & NCB_BK_F_GAP) {
		/* Reduce gap size if insertion begins in a gap. Gap data size
		 * is reset and will be recalculated during insertion.
		 */
		const ncb_sz_t gap_sz = off - blk.off;
		BUG_ON_HOT(gap_sz < NCB_GAP_MIN_SZ);

		/* pointer to data size to increase. */
		new_sz = ncb_peek(buf, blk.off + NCB_GAP_SZ_DATA_OFF);

		ncb_write_off(buf, blk.sz_ptr, gap_sz);
		ncb_write_off(buf, new_sz, 0);
	}
	else {
		/* pointer to data size to increase. */
		new_sz = blk.sz_ptr;
	}

	/* insert data */
	while (left) {
		struct ncb_blk next;
		const ncb_sz_t off_blk = ncb_blk_off(blk, off);
		ncb_sz_t done;

		/* retrieve the next block. This is necessary to do this
		 * before overwritting a gap.
		 */
		next = ncb_blk_next(buf, blk);

		if (blk.flag & NCB_BK_F_GAP) {
			done = ncb_fill_gap_blk(buf, blk, off_blk, data, left);

			/* update the inserted data block size */
			if (off + done == blk.off + blk.sz) {
				/* merge next data block if insertion reached gap end */
				ncb_inc_off(buf, new_sz, done + blk.sz_data);
			}
			else {
				/* insertion stopped before gap end */
				ncb_inc_off(buf, new_sz, done);
			}
		}
		else {
			done = ncb_fill_data_blk(buf, blk, off_blk, data, left, mode);
		}

		BUG_ON_HOT(done > blk.sz || done > left);
		left -= done;
		data += done;
		off  += done;

		blk = next;
	}

	return NCB_RET_OK;
}
