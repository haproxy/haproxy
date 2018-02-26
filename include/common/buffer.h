/*
 * include/common/buffer.h
 * Buffer management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _COMMON_BUFFER_H
#define _COMMON_BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/chunk.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/memory.h>


struct buffer {
	char *p;                        /* buffer's start pointer, separates in and out data */
	unsigned int size;              /* buffer size in bytes */
	unsigned int i;                 /* number of input bytes pending for analysis in the buffer */
	unsigned int o;                 /* number of out bytes the sender can consume from this buffer */
	char data[0];                   /* <size> bytes */
};

/* an element of the <buffer_wq> list. It represents an object that need to
 * acquire a buffer to continue its process. */
struct buffer_wait {
	void *target;              /* The waiting object that should be woken up */
	int (*wakeup_cb)(void *);  /* The function used to wake up the <target>, passed as argument */
	struct list list;          /* Next element in the <buffer_wq> list */
};

extern struct pool_head *pool_head_buffer;
extern struct buffer buf_empty;
extern struct buffer buf_wanted;
extern struct list buffer_wq;
__decl_hathreads(extern HA_SPINLOCK_T buffer_wq_lock);

int init_buffer();
void deinit_buffer();
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len);
int buffer_insert_line2(struct buffer *b, char *pos, const char *str, int len);
void buffer_dump(FILE *o, struct buffer *b, int from, int to);
void buffer_slow_realign(struct buffer *buf);

/*****************************************************************/
/* These functions are used to compute various buffer area sizes */
/*****************************************************************/

/* Returns an absolute pointer for a position relative to the current buffer's
 * pointer. It is written so that it is optimal when <ofs> is a const. It is
 * written as a macro instead of an inline function so that the compiler knows
 * when it can optimize out the sign test on <ofs> when passed an unsigned int.
 * Note that callers MUST cast <ofs> to int if they expect negative values.
 */
#define b_ptr(b, ofs) \
	({            \
		char *__ret = (b)->p + (ofs);                   \
		if ((ofs) > 0 && __ret >= (b)->data + (b)->size)    \
			__ret -= (b)->size;                     \
		else if ((ofs) < 0 && __ret < (b)->data)        \
			__ret += (b)->size;                     \
		__ret;                                          \
	})

/* Returns the pointer to the buffer's end (data+size) */
static inline const char *b_end(const struct buffer *b)
{
	return b->data + b->size;
}

/* Returns the distance between <p> and the buffer's end (data+size) */
static inline unsigned int b_to_end(const struct buffer *b)
{
	return b->data + b->size - b->p;
}

/* Skips <del> bytes in a one-way buffer <b> : <p> advances by <del>, <i>
 * shrinks by <del> as well, and <o> is left untouched (supposed to be zero).
 * The caller is responsible for ensuring that <del> is always smaller than or
 * equal to b->i.
 */
static inline void bi_del(struct buffer *b, unsigned int del)
{
	b->i -= del;
	b->p = b_ptr(b, del);
}

/* Skips <del> bytes from the output of buffer <b> by simply shrinking <o>.
 * The caller is responsible for ensuring that <del> is always smaller than or
 * equal to b->o.
 */
static inline void bo_del(struct buffer *b, unsigned int del)
{
	b->o -= del;
}

/* Advances the buffer by <adv> bytes, which means that the buffer
 * pointer advances, and that as many bytes from in are transferred
 * to out. The caller is responsible for ensuring that adv is always
 * smaller than or equal to b->i.
 */
static inline void b_adv(struct buffer *b, unsigned int adv)
{
	b->i -= adv;
	b->o += adv;
	b->p = b_ptr(b, adv);
}

/* Rewinds the buffer by <adv> bytes, which means that the buffer pointer goes
 * backwards, and that as many bytes from out are moved to in. The caller is
 * responsible for ensuring that adv is always smaller than or equal to b->o.
 */
static inline void b_rew(struct buffer *b, unsigned int adv)
{
	b->i += adv;
	b->o -= adv;
	b->p = b_ptr(b, (int)-adv);
}

/* Returns the start of the input data in a buffer */
static inline char *bi_ptr(const struct buffer *b)
{
	return b->p;
}

/* Returns the end of the input data in a buffer (pointer to next
 * insertion point).
 */
static inline char *bi_end(const struct buffer *b)
{
	char *ret = b->p + b->i;

	if (ret >= b->data + b->size)
		ret -= b->size;
	return ret;
}

/* Returns the amount of input data that can contiguously be read at once */
static inline int bi_contig_data(const struct buffer *b)
{
	int data = b->data + b->size - b->p;

	if (data > b->i)
		data = b->i;
	return data;
}

/* Returns the start of the output data in a buffer */
static inline char *bo_ptr(const struct buffer *b)
{
	char *ret = b->p - b->o;

	if (ret < b->data)
		ret += b->size;
	return ret;
}

/* Returns the end of the output data in a buffer */
static inline char *bo_end(const struct buffer *b)
{
	return b->p;
}

/* Returns the amount of output data that can contiguously be read at once */
static inline int bo_contig_data(const struct buffer *b)
{
	char *beg = b->p - b->o;

	if (beg < b->data)
		return b->data - beg;
	return b->o;
}

/* Return the amount of bytes that can be written into the input area at once
 * including reserved space which may be overwritten (this is the caller
 * responsibility to know if the reserved space is protected or not).
*/
static inline int bi_contig_space(const struct buffer *b)
{
	const char *left, *right;

	left  = b->p + b->i;
	right = b->p - b->o;
	if (left >= b->data + b->size)
		left -= b->size;
	else {
		if (right < b->data)
			right += b->size;
		else
			right = b->data + b->size;
	}
	return (right - left);
}

/* Return the amount of bytes that can be written into the output area at once
 * including reserved space which may be overwritten (this is the caller
 * responsibility to know if the reserved space is protected or not). Input data
 * are assumed to not exist.
*/
static inline int bo_contig_space(const struct buffer *b)
{
	const char *left, *right;

	left  = b->p;
	right = b->p - b->o;
	if (right < b->data)
		right += b->size;
	else
		right = b->data + b->size;

	return (right - left);
}

/* Return the buffer's length in bytes by summing the input and the output */
static inline int buffer_len(const struct buffer *buf)
{
	return buf->i + buf->o;
}

/* Return non-zero only if the buffer is not empty */
static inline int buffer_not_empty(const struct buffer *buf)
{
	return buf->i | buf->o;
}

/* Return non-zero only if the buffer is empty */
static inline int buffer_empty(const struct buffer *buf)
{
	return !buffer_not_empty(buf);
}

/* Return non-zero only if the buffer's free space wraps :
 *  [     |oooo|           ]    => yes
 *  [          |iiii|      ]    => yes
 *  [     |oooo|iiii|      ]    => yes
 *  [oooo|                 ]    => no
 *  [                 |oooo]    => no
 *  [iiii|                 ]    => no
 *  [                 |iiii]    => no
 *  [oooo|iiii|            ]    => no
 *  [            |oooo|iiii]    => no
 *  [iiii|            |oooo]    => no
 *  [oo|iiii|           |oo]    => no
 *  [iiii|           |oo|ii]    => no
 *  [oooooooooo|iiiiiiiiiii]    => no
 *  [iiiiiiiiiiiii|oooooooo]    => no
 *
 *  So the only case where the buffer does not wrap is when there's data either
 *  at the beginning or at the end of the buffer. Thus we have this :
 *  - if (p+i >= size) ==> doesn't wrap
 *  - if (p-data <= o) ==> doesn't wrap
 *  - otherwise wraps
 */
static inline int buffer_space_wraps(const struct buffer *buf)
{
	if (buf->p + buf->i >= buf->data + buf->size)
		return 0;
	if (buf->p <= buf->data + buf->o)
		return 0;
	return 1;
}

/* Returns non-zero if the buffer's INPUT is considered full, which means that
 * it holds at least as much INPUT data as (size - reserve). This also means
 * that data that are scheduled for output are considered as potential free
 * space, and that the reserved space is always considered as not usable. This
 * information alone cannot be used as a general purpose free space indicator.
 * However it accurately indicates that too many data were fed in the buffer
 * for an analyzer for instance. See the channel_may_recv() function for a more
 * generic function taking everything into account.
 */
static inline int buffer_full(const struct buffer *b, unsigned int reserve)
{
	if (b == &buf_empty)
		return 0;

	return (b->i + reserve >= b->size);
}

/* Normalizes a pointer after a subtract */
static inline char *buffer_wrap_sub(const struct buffer *buf, char *ptr)
{
	if (ptr < buf->data)
		ptr += buf->size;
	return ptr;
}

/* Normalizes a pointer after an addition */
static inline char *buffer_wrap_add(const struct buffer *buf, char *ptr)
{
	if (ptr - buf->size >= buf->data)
		ptr -= buf->size;
	return ptr;
}

/* Return the maximum amount of bytes that can be written into the buffer,
 * including reserved space which may be overwritten.
 */
static inline int buffer_total_space(const struct buffer *buf)
{
	return buf->size - buffer_len(buf);
}

/* Returns the amount of byte that can be written starting from <p> into the
 * input buffer at once, including reserved space which may be overwritten.
 * This is used by Lua to insert data in the input side just before the other
 * data using buffer_replace(). The goal is to transfer these new data in the
 * output buffer.
 */
static inline int bi_space_for_replace(const struct buffer *buf)
{
	const char *end;

	/* If the input side data overflows, we cannot insert data contiguously. */
	if (buf->p + buf->i >= buf->data + buf->size)
		return 0;

	/* Check the last byte used in the buffer, it may be a byte of the output
	 * side if the buffer wraps, or its the end of the buffer.
	 */
	end = buffer_wrap_sub(buf, buf->p - buf->o);
	if (end <= buf->p)
		end = buf->data + buf->size;

	/* Compute the amount of bytes which can be written. */
	return end - (buf->p + buf->i);
}


/* Normalizes a pointer which is supposed to be relative to the beginning of a
 * buffer, so that wrapping is correctly handled. The intent is to use this
 * when increasing a pointer. Note that the wrapping test is only performed
 * once, so the original pointer must be between ->data-size and ->data+2*size-1,
 * otherwise an invalid pointer might be returned.
 */
static inline const char *buffer_pointer(const struct buffer *buf, const char *ptr)
{
	if (ptr < buf->data)
		ptr += buf->size;
	else if (ptr - buf->size >= buf->data)
		ptr -= buf->size;
	return ptr;
}

/* Returns the distance between two pointers, taking into account the ability
 * to wrap around the buffer's end.
 */
static inline int buffer_count(const struct buffer *buf, const char *from, const char *to)
{
	int count = to - from;

	count += count < 0 ? buf->size : 0;
	return count;
}

/* returns the amount of pending bytes in the buffer. It is the amount of bytes
 * that is not scheduled to be sent.
 */
static inline int buffer_pending(const struct buffer *buf)
{
	return buf->i;
}

/* Return 1 if the buffer has less than 1/4 of its capacity free, otherwise 0 */
static inline int buffer_almost_full(const struct buffer *buf)
{
	if (buf == &buf_empty)
		return 0;

	if (!buf->size || buffer_total_space(buf) < buf->size / 4)
		return 1;
	return 0;
}

/* Cut the first <n> pending bytes in a contiguous buffer. It is illegal to
 * call this function with remaining data waiting to be sent (o > 0). The
 * caller must ensure that <n> is smaller than the actual buffer's length.
 * This is mainly used to remove empty lines at the beginning of a request
 * or a response.
 */
static inline void bi_fast_delete(struct buffer *buf, int n)
{
	buf->i -= n;
	buf->p += n;
}

/* Tries to realign the given buffer. */
static inline void buffer_realign(struct buffer *buf)
{
	if (!(buf->i | buf->o)) {
		/* let's realign the buffer to optimize I/O */
		buf->p = buf->data;
	}
}

/* Schedule all remaining buffer data to be sent. ->o is not touched if it
 * already covers those data. That permits doing a flush even after a forward,
 * although not recommended.
 */
static inline void buffer_flush(struct buffer *buf)
{
	buf->p = buffer_wrap_add(buf, buf->p + buf->i);
	buf->o += buf->i;
	buf->i = 0;
}

/* This function writes the string <str> at position <pos> which must be in
 * buffer <b>, and moves <end> just after the end of <str>. <b>'s parameters
 * (l, r, lr) are updated to be valid after the shift. the shift value
 * (positive or negative) is returned. If there's no space left, the move is
 * not done. The function does not adjust ->o because it does not make sense
 * to use it on data scheduled to be sent.
 */
static inline int buffer_replace(struct buffer *b, char *pos, char *end, const char *str)
{
	return buffer_replace2(b, pos, end, str, strlen(str));
}

/* Tries to write char <c> into output data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is full.
 */
static inline void bo_putchr(struct buffer *b, char c)
{
	if (buffer_len(b) == b->size)
		return;
	*b->p = c;
	b->p = b_ptr(b, 1);
	b->o++;
}

/* Tries to copy block <blk> into output data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline int bo_putblk(struct buffer *b, const char *blk, int len)
{
	int cur_len = buffer_len(b);
	int half;

	if (len > b->size - cur_len)
		len = (b->size - cur_len);
	if (!len)
		return 0;

	half = bo_contig_space(b);
	if (half > len)
		half = len;

	memcpy(b->p, blk, half);
	b->p = b_ptr(b, half);
	if (len > half) {
		memcpy(b->p, blk + half, len - half);
		b->p = b_ptr(b, half);
	}
	b->o += len;
	return len;
}

/* Tries to copy string <str> into output data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline int bo_putstr(struct buffer *b, const char *str)
{
	return bo_putblk(b, str, strlen(str));
}

/* Tries to copy chunk <chk> into output data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline int bo_putchk(struct buffer *b, const struct chunk *chk)
{
	return bo_putblk(b, chk->str, chk->len);
}

/* Gets one full block of data at once from a buffer's output, optionally
 * starting at a specific offset. Return values :
 *   >0 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <blk> is left undefined.
 * The buffer is left unaffected.
 */
static inline int bo_getblk(const struct buffer *buf, char *blk, int len, int offset)
{
	int firstblock;

	if (len + offset > buf->o)
		return 0;

	firstblock = buf->data + buf->size - bo_ptr(buf);
	if (firstblock > offset) {
		if (firstblock >= len + offset) {
			memcpy(blk, bo_ptr(buf) + offset, len);
			return len;
		}

		memcpy(blk, bo_ptr(buf) + offset, firstblock - offset);
		memcpy(blk + firstblock - offset, buf->data, len - firstblock + offset);
		return len;
	}

	memcpy(blk, buf->data + offset - firstblock, len);
	return len;
}

/* Gets one or two blocks of data at once from a buffer's output.
 * Return values :
 *   >0 : number of blocks filled (1 or 2). blk1 is always filled before blk2.
 *   =0 : not enough data available. <blk*> are left undefined.
 * The buffer is left unaffected. Unused buffers are left in an undefined state.
 */
static inline int bo_getblk_nc(struct buffer *buf, char **blk1, int *len1, char **blk2, int *len2)
{
	if (unlikely(buf->o == 0))
		return 0;

	if (unlikely(buf->p != buf->data && buf->p - buf->o < buf->data)) {
		*blk1 = buf->p - buf->o + buf->size;
		*len1 = buf->data + buf->size - *blk1;
		*blk2 = buf->data;
		*len2 = buf->p - buf->data;
		return 2;
	}

	*blk1 = bo_ptr(buf);
	*len1 = buf->o;
	return 1;
}

/* Tries to write char <c> into input data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is full.
 */
static inline void bi_putchr(struct buffer *b, char c)
{
	if (buffer_len(b) == b->size)
		return;
	*bi_end(b) = c;
	b->i++;
}

/* Tries to copy block <blk> into input data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline int bi_putblk(struct buffer *b, const char *blk, int len)
{
	int cur_len = buffer_len(b);
	int half;

	if (len > b->size - cur_len)
		len = (b->size - cur_len);
	if (!len)
		return 0;

	half = bi_contig_space(b);
	if (half > len)
		half = len;

	memcpy(bi_end(b), blk, half);
	if (len > half)
		memcpy(b_ptr(b, b->i + half), blk + half, len - half);
	b->i += len;
	return len;
}

/* Tries to copy string <str> into input data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline int bi_putstr(struct buffer *b, const char *str)
{
	return bi_putblk(b, str, strlen(str));
}

/* Tries to copy chunk <chk> into input data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline int bi_putchk(struct buffer *b, const struct chunk *chk)
{
	return bi_putblk(b, chk->str, chk->len);
}

/* Gets one full block of data at once from a buffer's input. Return values :
 *   >0 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <blk> is left undefined.
 * The buffer is left unaffected.
 */
static inline int bi_getblk(const struct buffer *buf, char *blk, int len)
{
	int firstblock;

	if (len > buf->i)
		return 0;

	firstblock = bi_contig_data(buf);
	if (firstblock > len)
		firstblock = len;

	memcpy(blk, bi_ptr(buf), firstblock);
	if (len > firstblock)
		memcpy(blk + firstblock, buf->data, len - firstblock);
	return len;
}

/* Gets one or two blocks of data at once from a buffer's input.
 * Return values :
 *   >0 : number of blocks filled (1 or 2). blk1 is always filled before blk2.
 *   =0 : not enough data available. <blk*> are left undefined.
 * The buffer is left unaffected. Unused buffers are left in an undefined state.
 */
static inline int bi_getblk_nc(struct buffer *buf, char **blk1, int *len1, char **blk2, int *len2)
{
	if (unlikely(buf->i == 0))
		return 0;

	if (unlikely(buf->p + buf->i > buf->data + buf->size)) {
		*blk1 = buf->p;
		*len1 = buf->data + buf->size - buf->p;
		*blk2 = buf->data;
		*len2 = buf->i - *len1;
		return 2;
	}

	*blk1 = buf->p;
	*len1 = buf->i;
	return 1;
}

/* Resets a buffer. The size is not touched. */
static inline void b_reset(struct buffer *buf)
{
	buf->o = 0;
	buf->i = 0;
	buf->p = buf->data;

}

/* Allocates a buffer and replaces *buf with this buffer. If no memory is
 * available, &buf_wanted is used instead. No control is made to check if *buf
 * already pointed to another buffer. The allocated buffer is returned, or
 * NULL in case no memory is available.
 */
static inline struct buffer *b_alloc(struct buffer **buf)
{
	struct buffer *b;

	*buf = &buf_wanted;
	b = pool_alloc_dirty(pool_head_buffer);
	if (likely(b)) {
		b->size = pool_head_buffer->size - sizeof(struct buffer);
		b_reset(b);
		*buf = b;
	}
	return b;
}

/* Allocates a buffer and replaces *buf with this buffer. If no memory is
 * available, &buf_wanted is used instead. No control is made to check if *buf
 * already pointed to another buffer. The allocated buffer is returned, or
 * NULL in case no memory is available. The difference with b_alloc() is that
 * this function only picks from the pool and never calls malloc(), so it can
 * fail even if some memory is available.
 */
static inline struct buffer *b_alloc_fast(struct buffer **buf)
{
	struct buffer *b;

	*buf = &buf_wanted;
	b = pool_get_first(pool_head_buffer);
	if (likely(b)) {
		b->size = pool_head_buffer->size - sizeof(struct buffer);
		b_reset(b);
		*buf = b;
	}
	return b;
}

/* Releases buffer *buf (no check of emptiness) */
static inline void __b_drop(struct buffer **buf)
{
	pool_free(pool_head_buffer, *buf);
}

/* Releases buffer *buf if allocated. */
static inline void b_drop(struct buffer **buf)
{
	if (!(*buf)->size)
		return;
	__b_drop(buf);
}

/* Releases buffer *buf if allocated, and replaces it with &buf_empty. */
static inline void b_free(struct buffer **buf)
{
	b_drop(buf);
	*buf = &buf_empty;
}

/* Ensures that <buf> is allocated. If an allocation is needed, it ensures that
 * there are still at least <margin> buffers available in the pool after this
 * allocation so that we don't leave the pool in a condition where a session or
 * a response buffer could not be allocated anymore, resulting in a deadlock.
 * This means that we sometimes need to try to allocate extra entries even if
 * only one buffer is needed.
 *
 * We need to lock the pool here to be sure to have <margin> buffers available
 * after the allocation, regardless how many threads that doing it in the same
 * time. So, we use internal and lockless memory functions (prefixed with '__').
 */
static inline struct buffer *b_alloc_margin(struct buffer **buf, int margin)
{
	struct buffer *b;

	if ((*buf)->size)
		return *buf;

	*buf = &buf_wanted;
#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_LOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	/* fast path */
	if ((pool_head_buffer->allocated - pool_head_buffer->used) > margin) {
		b = __pool_get_first(pool_head_buffer);
		if (likely(b)) {
#ifndef CONFIG_HAP_LOCKLESS_POOLS
			HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif
			b->size = pool_head_buffer->size - sizeof(struct buffer);
			b_reset(b);
			*buf = b;
			return b;
		}
	}

	/* slow path, uses malloc() */
	b = __pool_refill_alloc(pool_head_buffer, margin);

#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	if (b) {
		b->size = pool_head_buffer->size - sizeof(struct buffer);
		b_reset(b);
		*buf = b;
	}
	return b;
}


void __offer_buffer(void *from, unsigned int threshold);

static inline void offer_buffers(void *from, unsigned int threshold)
{
	HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	if (LIST_ISEMPTY(&buffer_wq)) {
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		return;
	}
	__offer_buffer(from, threshold);
	HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
}

/*************************************************************************/
/* functions used to manipulate strings and blocks with wrapping buffers */
/*************************************************************************/

/* returns > 0 if the first <n> characters of buffer <b> starting at
 * offset <o> relative to b->p match <ist>. (empty strings do match). It is
 * designed to be use with reasonably small strings (ie matches a single byte
 * per iteration). This function is usable both with input and output data. To
 * be used like this depending on what to match :
 * - input contents  :  b_isteq(b, 0, b->i, ist);
 * - output contents :  b_isteq(b, -b->o, b->o, ist);
 * Return value :
 *   >0 : the number of matching bytes
 *   =0 : not enough bytes (or matching of empty string)
 *   <0 : non-matching byte found
 */
static inline int b_isteq(const struct buffer *b, unsigned int o, size_t n, const struct ist ist)
{
	struct ist r = ist;
	const char *p;
	const char *end = b->data + b->size;

	if (n < r.len)
		return 0;

	p = b_ptr(b, o);
	while (r.len--) {
		if (*p++ != *r.ptr++)
			return -1;
		if (unlikely(p == end))
			p = b->data;
	}
	return ist.len;
}

/* "eats" string <ist> from the input region of buffer <b>. Wrapping data is
 * explicitly supported. It matches a single byte per iteration so strings
 * should remain reasonably small. Returns :
 *   > 0 : number of bytes matched and eaten
 *   = 0 : not enough bytes (or matching an empty string)
 *   < 0 : non-matching byte found
 */
static inline int bi_eat(struct buffer *b, const struct ist ist)
{
	int ret = b_isteq(b, 0, b->i, ist);
	if (ret > 0)
		bi_del(b, ret);
	return ret;
}

/* injects string <ist> into the input region of buffer <b> provided that it
 * fits. Wrapping is supported. It's designed for small strings as it only
 * writes a single byte per iteration. Returns the number of characters copied
 * (ist.len), 0 if it temporarily does not fit or -1 if it will never fit. It
 * will only modify the buffer upon success. In all cases, the contents are
 * copied prior to reporting an error, so that the destination at least
 * contains a valid but truncated string.
 */
static inline int bi_istput(struct buffer *b, const struct ist ist)
{
	const char *end = b->data + b->size;
	struct ist r = ist;
	char *p;

	if (r.len > (size_t)(b->size - b->i - b->o))
		return r.len < b->size ? 0 : -1;

	p = b_ptr(b, b->i);
	b->i += r.len;
	while (r.len--) {
		*p++ = *r.ptr++;
		if (unlikely(p == end))
			p = b->data;
	}
	return ist.len;
}


/* injects string <ist> into the output region of buffer <b> provided that it
 * fits. Input data is assumed not to exist and will silently be overwritten.
 * Wrapping is supported. It's designed for small strings as it only writes a
 * single byte per iteration. Returns the number of characters copied (ist.len),
 * 0 if it temporarily does not fit or -1 if it will never fit. It will only
 * modify the buffer upon success. In all cases, the contents are copied prior
 * to reporting an error, so that the destination at least contains a valid
 * but truncated string.
 */
static inline int bo_istput(struct buffer *b, const struct ist ist)
{
	const char *end = b->data + b->size;
	struct ist r = ist;
	char *p;

	if (r.len > (size_t)(b->size - b->o))
		return r.len < b->size ? 0 : -1;

	p = b->p;
	b->o += r.len;
	b->p = b_ptr(b, r.len);
	while (r.len--) {
		*p++ = *r.ptr++;
		if (unlikely(p == end))
			p = b->data;
	}
	return ist.len;
}


#endif /* _COMMON_BUFFER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
