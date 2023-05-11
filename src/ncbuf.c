#include <haproxy/ncbuf.h>

#include <string.h>

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifdef STANDALONE
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <haproxy/list.h>
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

#include <haproxy/compiler.h>

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
static forceinline void ncb_write_off(const struct ncbuf *buf, char *st, ncb_sz_t off)
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
static forceinline ncb_sz_t ncb_read_off(const struct ncbuf *buf, char *st)
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
static forceinline void ncb_inc_off(const struct ncbuf *buf, char *st, ncb_sz_t off)
{
	const ncb_sz_t old = ncb_read_off(buf, st);
	ncb_write_off(buf, st, old + off);
}

/* Returns true if a gap cannot be inserted at <off> : a reduced gap must be used. */
static forceinline int ncb_off_reduced(const struct ncbuf *b, ncb_sz_t off)
{
	return off + NCB_GAP_MIN_SZ > ncb_size(b);
}

/* Returns true if <blk> is the special NULL block. */
static forceinline int ncb_blk_is_null(const struct ncb_blk *blk)
{
	return !blk->st;
}

/* Returns true if <blk> is the last block of <buf>. */
static forceinline int ncb_blk_is_last(const struct ncbuf *buf, const struct ncb_blk *blk)
{
	BUG_ON_HOT(blk->off + blk->sz > ncb_size(buf));
	return blk->off + blk->sz == ncb_size(buf);
}

/* Returns the first block of <buf> which is always a DATA. */
static struct ncb_blk ncb_blk_first(const struct ncbuf *buf)
{
	struct ncb_blk blk;

	if (ncb_is_null(buf))
		return NCB_BLK_NULL;

	blk.st = ncb_head(buf);

	blk.sz_ptr = ncb_reserved(buf);
	blk.sz = ncb_read_off(buf, ncb_reserved(buf));
	blk.sz_data = 0;
	BUG_ON_HOT(blk.sz > ncb_size(buf));

	blk.end = ncb_peek(buf, blk.sz);
	blk.off = 0;
	blk.flag = 0;

	return blk;
}

/* Returns the block following <prev> in the buffer <buf>. */
static struct ncb_blk ncb_blk_next(const struct ncbuf *buf,
                                   const struct ncb_blk *prev)
{
	struct ncb_blk blk;

	BUG_ON_HOT(ncb_blk_is_null(prev));

	if (ncb_blk_is_last(buf, prev))
		return NCB_BLK_NULL;

	blk.st = prev->end;
	blk.off = prev->off + prev->sz;
	blk.flag = ~prev->flag & NCB_BK_F_GAP;

	if (blk.flag & NCB_BK_F_GAP) {
		if (ncb_off_reduced(buf, blk.off)) {
			blk.flag |= NCB_BK_F_FIN;
			blk.sz_ptr = NULL;
			blk.sz = ncb_size(buf) - blk.off;
			blk.sz_data = 0;

			/* A reduced gap can only be the last block. */
			BUG_ON_HOT(!ncb_blk_is_last(buf, &blk));
		}
		else {
			blk.sz_ptr = ncb_peek(buf, blk.off + NCB_GAP_SZ_OFF);
			blk.sz = ncb_read_off(buf, blk.sz_ptr);
			blk.sz_data = ncb_read_off(buf, ncb_peek(buf, blk.off + NCB_GAP_SZ_DATA_OFF));
			BUG_ON_HOT(blk.sz < NCB_GAP_MIN_SZ);
		}
	}
	else {
		blk.sz_ptr = ncb_peek(buf, prev->off + NCB_GAP_SZ_DATA_OFF);
		blk.sz = prev->sz_data;
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

	if (ncb_is_null(buf))
		return NCB_BLK_NULL;

	BUG_ON_HOT(off >= ncb_size(buf));

	for (blk = ncb_blk_first(buf); off > blk.off + blk.sz;
	     blk = ncb_blk_next(buf, &blk)) {
	}

	return blk;
}

/* Transform absolute offset <off> to a relative one from <blk> start. */
static forceinline ncb_sz_t ncb_blk_off(const struct ncb_blk *blk, ncb_sz_t off)
{
	BUG_ON_HOT(off < blk->off || off > blk->off + blk->sz);
	BUG_ON_HOT(off - blk->off > blk->sz);
	return off - blk->off;
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
                                     const struct ncb_blk *blk, ncb_sz_t off,
                                     const char *data, ncb_sz_t len,
                                     enum ncb_add_mode mode)
{
	struct ncb_blk next;
	ncb_sz_t off_blk = ncb_blk_off(blk, off);
	ncb_sz_t to_copy;
	ncb_sz_t left = len;

	/* If insertion starts in a gap, it must leave enough space to keep the
	 * gap header.
	 */
	if (left && (blk->flag & NCB_BK_F_GAP)) {
		if (off_blk < NCB_GAP_MIN_SZ)
			return NCB_RET_GAP_SIZE;
	}

	next = *blk;
	while (left) {
		off_blk = ncb_blk_off(&next, off);
		to_copy = MIN(left, next.sz - off_blk);

		if (next.flag & NCB_BK_F_GAP && off_blk + to_copy < next.sz) {
			/* Insertion must leave enough space for a new gap
			 * header if stopped in a middle of a gap.
			 */
			const ncb_sz_t gap_sz = next.sz - (off_blk + to_copy);
			if (gap_sz < NCB_GAP_MIN_SZ && !ncb_blk_is_last(buf, &next))
				return NCB_RET_GAP_SIZE;
		}
		else if (!(next.flag & NCB_BK_F_GAP) && mode == NCB_ADD_COMPARE) {
			/* Compare memory of data block in NCB_ADD_COMPARE mode. */
			const ncb_sz_t off_blk = ncb_blk_off(&next, off);
			char *st = ncb_peek(buf, off);

			to_copy = MIN(left, next.sz - off_blk);
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

		next = ncb_blk_next(buf, &next);
	}

	return NCB_RET_OK;
}

/* Fill new <data> of length <len> inside an already existing data <blk> at
 * offset <off>. Offset is relative to <blk> so it cannot be greater than the
 * block size. <mode> specifies if old data are preserved or overwritten.
 */
static ncb_sz_t ncb_fill_data_blk(const struct ncbuf *buf,
                                  const struct ncb_blk *blk, ncb_sz_t off,
                                  const char *data, ncb_sz_t len,
                                  enum ncb_add_mode mode)
{
	const ncb_sz_t to_copy = MIN(len, blk->sz - off);
	char *ptr = NULL;

	BUG_ON_HOT(off > blk->sz);
	/* This can happens due to previous ncb_blk_find() usage. In this
	 * case the current fill is a noop.
	 */
	if (off == blk->sz)
		return 0;

	if (mode == NCB_ADD_OVERWRT) {
		ptr = ncb_peek(buf, blk->off + off);

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
                                 const struct ncb_blk *blk, ncb_sz_t off,
                                 const char *data, ncb_sz_t len)
{
	const ncb_sz_t to_copy = MIN(len, blk->sz - off);
	char *ptr;

	BUG_ON_HOT(off > blk->sz);
	/* This can happens due to previous ncb_blk_find() usage. In this
	 * case the current fill is a noop.
	 */
	if (off == blk->sz)
		return 0;

	/* A new gap must be created if insertion stopped before gap end. */
	if (off + to_copy < blk->sz) {
		const ncb_sz_t gap_off = blk->off + off + to_copy;
		const ncb_sz_t gap_sz = blk->sz - off - to_copy;

		BUG_ON_HOT(!ncb_off_reduced(buf, gap_off) &&
		           blk->off + blk->sz - gap_off < NCB_GAP_MIN_SZ);

		/* write the new gap header unless this is a reduced gap. */
		if (!ncb_off_reduced(buf, gap_off)) {
			char *gap_ptr = ncb_peek(buf, gap_off + NCB_GAP_SZ_OFF);
			char *gap_data_ptr = ncb_peek(buf, gap_off + NCB_GAP_SZ_DATA_OFF);

			ncb_write_off(buf, gap_ptr, gap_sz);
			ncb_write_off(buf, gap_data_ptr, blk->sz_data);
		}
	}

	/* fill the gap with new data */
	ptr = ncb_peek(buf, blk->off + off);
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

/* Initialize or reset <buf> by clearing all data. Its size is untouched.
 * Buffer is positioned to <head> offset. Use 0 to realign it. <buf> must not
 * be NCBUF_NULL.
 */
void ncb_init(struct ncbuf *buf, ncb_sz_t head)
{
	BUG_ON_HOT(ncb_is_null(buf));

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

/* Returns the total number of bytes stored in whole <buf>. */
ncb_sz_t ncb_total_data(const struct ncbuf *buf)
{
	struct ncb_blk blk;
	int total = 0;

	for (blk = ncb_blk_first(buf); !ncb_blk_is_null(&blk); blk = ncb_blk_next(buf, &blk)) {
		if (!(blk.flag & NCB_BK_F_GAP))
			total += blk.sz;
	}

	return total;
}

/* Returns true if there is no data anywhere in <buf>. */
int ncb_is_empty(const struct ncbuf *buf)
{
	int first_data, first_gap;

	if (ncb_is_null(buf))
		return 1;

	first_data = ncb_read_off(buf, ncb_reserved(buf));
	BUG_ON_HOT(first_data > ncb_size(buf));
	/* Buffer is not empty if first data block is not nul. */
	if (first_data)
		return 0;

	/* Head contains the first gap size if first data block is empty. */
	first_gap  = ncb_read_off(buf, ncb_head(buf));
	BUG_ON_HOT(first_gap > ncb_size(buf));
	return first_gap == ncb_size(buf);
}

/* Returns true if no more data can be inserted in <buf>. */
int ncb_is_full(const struct ncbuf *buf)
{
	int first_data;

	if (ncb_is_null(buf))
		return 0;

	/* First data block must cover whole buffer if full. */
	first_data = ncb_read_off(buf, ncb_reserved(buf));
	BUG_ON_HOT(first_data > ncb_size(buf));
	return first_data == ncb_size(buf);
}

/* Returns true if <buf> contains data fragmented by gaps. */
int ncb_is_fragmented(const struct ncbuf *buf)
{
	struct ncb_blk data, gap;

	if (ncb_is_null(buf))
		return 0;

	/* check if buffer is empty or full */
	if (ncb_is_empty(buf) || ncb_is_full(buf))
		return 0;

	/* check that following gap is the last block */
	data = ncb_blk_first(buf);
	gap = ncb_blk_next(buf, &data);
	return !ncb_blk_is_last(buf, &gap);
}

/* Returns the number of bytes of data available in <buf> starting at offset
 * <off> until the next gap or the buffer end. The counted data may wrapped if
 * the buffer storage is not aligned.
 */
ncb_sz_t ncb_data(const struct ncbuf *buf, ncb_sz_t off)
{
	struct ncb_blk blk;
	ncb_sz_t off_blk;

	if (ncb_is_null(buf))
		return 0;

	blk = ncb_blk_find(buf, off);
	off_blk = ncb_blk_off(&blk, off);

	/* if <off> at the frontier between two and <blk> is gap, retrieve the
	 * next data block.
	 */
	if (blk.flag & NCB_BK_F_GAP && off_blk == blk.sz &&
	    !ncb_blk_is_last(buf, &blk)) {
		blk = ncb_blk_next(buf, &blk);
		off_blk = ncb_blk_off(&blk, off);
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
	ret = ncb_check_insert(buf, &blk, off, data, len, mode);
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
		const ncb_sz_t off_blk = ncb_blk_off(&blk, off);
		ncb_sz_t done;

		/* retrieve the next block. This is necessary to do this
		 * before overwriting a gap.
		 */
		next = ncb_blk_next(buf, &blk);

		if (blk.flag & NCB_BK_F_GAP) {
			done = ncb_fill_gap_blk(buf, &blk, off_blk, data, left);

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
			done = ncb_fill_data_blk(buf, &blk, off_blk, data, left, mode);
		}

		BUG_ON_HOT(done > blk.sz || done > left);
		left -= done;
		data += done;
		off  += done;

		blk = next;
	}

	return NCB_RET_OK;
}

/* Advance the head of <buf> to the offset <adv>. Data at the start of buffer
 * will be lost while some space will be formed at the end to be able to insert
 * new data.
 *
 * Returns NCB_RET_OK on success. It may return NCB_RET_GAP_SIZE if operation
 * is rejected due to the formation of a too small gap in front. If advance is
 * done only inside a data block it is guaranteed to succeed.
 */
enum ncb_ret ncb_advance(struct ncbuf *buf, ncb_sz_t adv)
{
	struct ncb_blk start, last;
	ncb_sz_t off_blk;
	ncb_sz_t first_data_sz;

	BUG_ON_HOT(adv > ncb_size(buf));
	if (!adv)
		return NCB_RET_OK;

	/* Special case if adv is full size. This is equivalent to a reset. */
	if (adv == ncb_size(buf)) {
		ncb_init(buf, buf->head);
		return NCB_RET_OK;
	}

	start = ncb_blk_find(buf, adv);

	/* Special case if advance until the last block which is a GAP. The
	 * buffer will be left empty and is thus equivalent to a reset.
	 */
	if (ncb_blk_is_last(buf, &start) && (start.flag & NCB_BK_F_GAP)) {
		ncb_sz_t new_head = buf->head + adv;
		if (new_head >= buf->size)
			new_head -= buf->size;

		ncb_init(buf, new_head);
		return NCB_RET_OK;
	}

	last = start;
	while (!ncb_blk_is_last(buf, &last))
		last = ncb_blk_next(buf, &last);

	off_blk = ncb_blk_off(&start, adv);

	if (start.flag & NCB_BK_F_GAP) {
		/* If advance in a GAP, its new size must be big enough. */
		if (start.sz == off_blk) {
			/* GAP removed. Buffer will start with following DATA block. */
			first_data_sz = start.sz_data;
		}
		else if (start.sz - off_blk < NCB_GAP_MIN_SZ) {
			return NCB_RET_GAP_SIZE;
		}
		else {
			/* Buffer will start with this GAP block. */
			first_data_sz = 0;
		}
	}
	else {
		/* If off_blk less than start.sz, the data block will becomes the
		 * first block. If equal, the data block is completely removed
		 * and thus the following GAP will be the first block.
		 */
		first_data_sz = start.sz - off_blk;
	}

	if (last.flag & NCB_BK_F_GAP) {
		/* Extend last GAP unless this is a reduced gap. */
		if (!(last.flag & NCB_BK_F_FIN) || last.sz + adv >= NCB_GAP_MIN_SZ) {
			/* use .st instead of .sz_ptr which can be NULL if reduced gap */
			ncb_write_off(buf, last.st, last.sz + adv);
			ncb_write_off(buf, ncb_peek(buf, last.off + NCB_GAP_SZ_DATA_OFF), 0);
		}
	}
	else {
		/* Insert a GAP after the last DATA block. */
		if (adv >= NCB_GAP_MIN_SZ) {
			ncb_write_off(buf, ncb_peek(buf, last.off + last.sz + NCB_GAP_SZ_OFF), adv);
			ncb_write_off(buf, ncb_peek(buf, last.off + last.sz + NCB_GAP_SZ_DATA_OFF), 0);
		}
	}

	/* Advance head and update reserved header with new first data size. */
	buf->head += adv;
	if (buf->head >= buf->size)
		buf->head -= buf->size;
	ncb_write_off(buf, ncb_reserved(buf), first_data_sz);

	/* If advance in a GAP, reduce its size. */
	if (start.flag & NCB_BK_F_GAP && !first_data_sz) {
		ncb_write_off(buf, ncb_head(buf), start.sz - off_blk);
		/* Recopy the block sz_data at the new position. */
		ncb_write_off(buf, ncb_peek(buf, NCB_GAP_SZ_DATA_OFF), start.sz_data);
	}

	return NCB_RET_OK;
}

/* ******** testing API ******** */
/* To build it :
 *   gcc -Wall -DSTANDALONE -lasan -I./include -o ncbuf src/ncbuf.c
 */
#ifdef STANDALONE

int ncb_print = 0;

static void ncbuf_printf(char *str, ...)
{
	va_list args;

	va_start(args, str);
	if (ncb_print)
		vfprintf(stderr, str, args);
	va_end(args);
}

struct rand_off {
	struct list el;
	ncb_sz_t off;
	ncb_sz_t len;
};

static struct rand_off *ncb_generate_rand_off(const struct ncbuf *buf)
{
	struct rand_off *roff;
	roff = calloc(1, sizeof(*roff));
	BUG_ON(!roff);

	roff->off = rand() % (ncb_size(buf));
	if (roff->off > 0 && roff->off < NCB_GAP_MIN_SZ)
		roff->off = 0;

	roff->len = rand() % (ncb_size(buf) - roff->off + 1);

	return roff;
}

static void ncb_print_blk(const struct ncb_blk *blk)
{
	if (ncb_print) {
		fprintf(stderr, "%s(%s): %2u/%u.\n",
		        blk->flag & NCB_BK_F_GAP ? "GAP " : "DATA",
		        blk->flag & NCB_BK_F_FIN ? "F" : "-", blk->off, blk->sz);
	}
}

static int ncb_is_null_blk(const struct ncb_blk *blk)
{
	return !blk->st;
}

static void ncb_loop(const struct ncbuf *buf)
{
	struct ncb_blk blk;

	blk = ncb_blk_first(buf);
	do {
		ncb_print_blk(&blk);
		blk = ncb_blk_next(buf, &blk);
	} while (!ncb_is_null_blk(&blk));

	ncbuf_printf("\n");
}

static void ncbuf_print_buf(struct ncbuf *b, ncb_sz_t len,
                            unsigned char *area, int line)
{
	int i;

	ncbuf_printf("buffer status at line %d\n", line);
	for (i = 0; i < len; ++i) {
		ncbuf_printf("%02x.", area[i]);
		if (i && i % 32 == 31)    ncbuf_printf("\n");
		else if (i && i % 8 == 7) ncbuf_printf(" ");
	}
	ncbuf_printf("\n");

	ncb_loop(b);

	if (ncb_print)
		getchar();
}

static struct ncbuf b;
static unsigned char *bufarea = NULL;
static ncb_sz_t bufsize = 16384;
static ncb_sz_t bufhead = 15;

#define NCB_INIT(buf) \
  if ((reset)) { memset(bufarea, 0xaa, bufsize); } \
  ncb_init(buf, bufhead); \
  ncbuf_print_buf(&b, bufsize, bufarea, __LINE__);

#define NCB_ADD_EQ(buf, off, data, sz, mode, ret) \
  BUG_ON(ncb_add((buf), (off), (data), (sz), (mode)) != (ret)); \
  ncbuf_print_buf(buf, bufsize, bufarea, __LINE__);

#define NCB_ADD_NEQ(buf, off, data, sz, mode, ret) \
  BUG_ON(ncb_add((buf), (off), (data), (sz), (mode)) == (ret)); \
  ncbuf_print_buf(buf, bufsize, bufarea, __LINE__);

#define NCB_ADVANCE_EQ(buf, off, ret) \
  BUG_ON(ncb_advance((buf), (off)) != (ret)); \
  ncbuf_print_buf(buf, bufsize, bufarea, __LINE__);

#define NCB_TOTAL_DATA_EQ(buf, data) \
  BUG_ON(ncb_total_data((buf)) != (data));

#define NCB_DATA_EQ(buf, off, data) \
  BUG_ON(ncb_data((buf), (off)) != (data));

static int ncbuf_test(ncb_sz_t head, int reset, int print_delay)
{
	char *data0, data1[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	struct list list = LIST_HEAD_INIT(list);
	struct rand_off *roff, *roff_tmp;
	enum ncb_ret ret;

	data0 = malloc(bufsize);
	BUG_ON(!data0);
	memset(data0, 0xff, bufsize);

	bufarea = malloc(bufsize);
	BUG_ON(!bufarea);

	fprintf(stderr, "running unit tests\n");

	b = NCBUF_NULL;
	BUG_ON(!ncb_is_null(&b));
	NCB_DATA_EQ(&b, 0, 0);
	NCB_TOTAL_DATA_EQ(&b, 0);
	BUG_ON(ncb_size(&b) != 0);
	BUG_ON(!ncb_is_empty(&b));
	BUG_ON(ncb_is_full(&b));
	BUG_ON(ncb_is_fragmented(&b));

	b.area = (char *)bufarea;
	b.size = bufsize;
	b.head = head;
	NCB_INIT(&b);

	/* insertion test suite */
	NCB_INIT(&b);
	NCB_DATA_EQ(&b, 0, 0); NCB_DATA_EQ(&b, bufsize - NCB_RESERVED_SZ - 1, 0); /* first and last offset */
	NCB_ADD_EQ(&b, 24, data0,  9, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 24,  9);
	/* insert new data at the same offset as old */
	NCB_ADD_EQ(&b, 24, data0, 16, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 24, 16);

	NCB_INIT(&b); NCB_DATA_EQ(&b, 0, 0);
	NCB_ADD_EQ(&b,  0, data0, 16, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 0, 16);
	BUG_ON(ncb_is_fragmented(&b));
	NCB_ADD_EQ(&b, 24, data0, 16, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 0, 16);
	BUG_ON(!ncb_is_fragmented(&b));
	/* insert data overlapping two data blocks and a gap */
	NCB_ADD_EQ(&b, 12, data0, 16, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 0, 40);
	BUG_ON(ncb_is_fragmented(&b));

	NCB_INIT(&b);
	NCB_ADD_EQ(&b, 32, data0, 16, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 0,  0); NCB_DATA_EQ(&b, 16,  0); NCB_DATA_EQ(&b, 32, 16);
	BUG_ON(!ncb_is_fragmented(&b));
	NCB_ADD_EQ(&b,  0, data0, 16, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 0, 16); NCB_DATA_EQ(&b, 16,  0); NCB_DATA_EQ(&b, 32, 16);
	BUG_ON(!ncb_is_fragmented(&b));
	/* insert data to exactly cover a gap between two data blocks */
	NCB_ADD_EQ(&b, 16, data0, 16, NCB_ADD_PRESERVE, NCB_RET_OK); NCB_DATA_EQ(&b, 0, 48); NCB_DATA_EQ(&b, 16, 32); NCB_DATA_EQ(&b, 32, 16);
	BUG_ON(ncb_is_fragmented(&b));

	NCB_INIT(&b);
	NCB_ADD_EQ(&b, 0,  data0, 8, NCB_ADD_PRESERVE, NCB_RET_OK);
	/* this insertion must be rejected because of minimal gap size */
	NCB_ADD_EQ(&b, 10, data0, 8, NCB_ADD_PRESERVE, NCB_RET_GAP_SIZE);

	/* Test reduced gap support */
	NCB_INIT(&b);
	/* this insertion will form a reduced gap */
	NCB_ADD_EQ(&b, 0, data0, bufsize - (NCB_GAP_MIN_SZ - 1), NCB_ADD_COMPARE, NCB_RET_OK);

	/* Test the various insertion mode */
	NCB_INIT(&b);
	NCB_ADD_EQ(&b, 10, data1, 16, NCB_ADD_PRESERVE, NCB_RET_OK);
	NCB_ADD_EQ(&b, 12, data1, 16, NCB_ADD_COMPARE,  NCB_RET_DATA_REJ);
	NCB_ADD_EQ(&b, 12, data1, 16, NCB_ADD_PRESERVE, NCB_RET_OK); BUG_ON(*ncb_peek(&b, 12) != data1[2]);
	NCB_ADD_EQ(&b, 12, data1, 16, NCB_ADD_OVERWRT,  NCB_RET_OK); BUG_ON(*ncb_peek(&b, 12) == data1[2]);

	/* advance test suite */
	NCB_INIT(&b);
	NCB_ADVANCE_EQ(&b, 10, NCB_RET_OK); /* advance in an empty buffer; this ensures we do not leave an empty DATA in the middle of the buffer */
	NCB_ADVANCE_EQ(&b, ncb_size(&b) - 2, NCB_RET_OK);

	NCB_INIT(&b);
	/* first fill the buffer */
	NCB_ADD_EQ(&b, 0, data0, bufsize - NCB_RESERVED_SZ, NCB_ADD_COMPARE, NCB_RET_OK);
	/* delete 2 bytes : a reduced gap must be created */
	NCB_ADVANCE_EQ(&b, 2, NCB_RET_OK); NCB_TOTAL_DATA_EQ(&b, ncb_size(&b) - 2);
	/* delete 1 byte : extend the reduced gap */
	NCB_ADVANCE_EQ(&b, 1, NCB_RET_OK); NCB_TOTAL_DATA_EQ(&b, ncb_size(&b) - 3);
	/* delete 5 bytes : a full gap must be present */
	NCB_ADVANCE_EQ(&b, 5, NCB_RET_OK); NCB_TOTAL_DATA_EQ(&b, ncb_size(&b) - 8);
	/* completely clear the buffer */
	NCB_ADVANCE_EQ(&b, bufsize - NCB_RESERVED_SZ, NCB_RET_OK); NCB_TOTAL_DATA_EQ(&b, 0);


	NCB_INIT(&b);
	NCB_ADD_EQ(&b, 10, data0, 10, NCB_ADD_PRESERVE, NCB_RET_OK);
	NCB_ADVANCE_EQ(&b,  2, NCB_RET_OK); /* reduce a gap in front of the buffer */
	NCB_ADVANCE_EQ(&b,  1, NCB_RET_GAP_SIZE); /* reject */
	NCB_ADVANCE_EQ(&b,  8, NCB_RET_OK); /* remove completely the gap */
	NCB_ADVANCE_EQ(&b,  8, NCB_RET_OK); /* remove inside the data */
	NCB_ADVANCE_EQ(&b, 10, NCB_RET_OK); /* remove completely the data */

	fprintf(stderr, "first random pass\n");
	NCB_INIT(&b);

	/* generate randon data offsets until the buffer is full */
	while (!ncb_is_full(&b)) {
		roff = ncb_generate_rand_off(&b);
		LIST_INSERT(&list, &roff->el);

		ret = ncb_add(&b, roff->off, data0, roff->len, NCB_ADD_COMPARE);
		BUG_ON(ret == NCB_RET_DATA_REJ);
		ncbuf_print_buf(&b, bufsize, bufarea, __LINE__);
		usleep(print_delay);
	}

	fprintf(stderr, "buf full, prepare for reverse random\n");
	ncbuf_print_buf(&b, bufsize, bufarea, __LINE__);

	/* insert the previously generated random offsets in the reverse order.
	 * At the end, the buffer should be full.
	 */
	NCB_INIT(&b);
	list_for_each_entry_safe(roff, roff_tmp, &list, el) {
		int full = ncb_is_full(&b);
		if (!full) {
			ret = ncb_add(&b, roff->off, data0, roff->len, NCB_ADD_COMPARE);
			BUG_ON(ret == NCB_RET_DATA_REJ);
			ncbuf_print_buf(&b, bufsize, bufarea, __LINE__);
			usleep(print_delay);
		}

		LIST_DELETE(&roff->el);
		free(roff);
	}

	if (!ncb_is_full(&b))
		abort();

	fprintf(stderr, "done\n");

	free(bufarea);
	free(data0);

	return 1;
}

int main(int argc, char **argv)
{
	int reset = 0;
	int print_delay = 100000;
	char c;

	opterr = 0;
	while ((c = getopt(argc, argv, "h:s:rp::")) != -1) {
		switch (c) {
		case 'h':
			bufhead = atoi(optarg);
			break;
		case 's':
			bufsize = atoi(optarg);
			if (bufsize < 64) {
				fprintf(stderr, "bufsize should be at least 64 bytes for unit test suite\n");
				exit(127);
			}
			break;
		case 'r':
			reset = 1;
			break;
		case 'p':
			if (optarg)
				print_delay = atoi(optarg);
			ncb_print = 1;
			break;
		case '?':
		default:
			fprintf(stderr, "usage: %s [-r] [-s bufsize] [-h bufhead] [-p <delay_msec>]\n", argv[0]);
			exit(127);
		}
	}

	ncbuf_test(bufhead, reset, print_delay);
	return EXIT_SUCCESS;
}

#endif /* STANDALONE */
