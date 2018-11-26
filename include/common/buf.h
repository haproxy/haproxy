/*
 * include/common/buf.h
 * Simple buffer handling.
 *
 * Copyright (C) 2000-2018 Willy Tarreau - w@1wt.eu
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _COMMON_BUF_H
#define _COMMON_BUF_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Structure defining a buffer's head */
struct buffer {
	size_t size;                /* buffer size in bytes */
	char  *area;                /* points to <size> bytes */
	size_t data;                /* amount of data after head including wrapping */
	size_t head;                /* start offset of remaining data relative to area */
};

/* A buffer may be in 3 different states :
 *   - unallocated : size == 0, area == 0  (b_is_null() is true)
 *   - waiting     : size == 0, area != 0
 *   - allocated   : size  > 0, area  > 0
 */

/* initializers for certain buffer states. It is important that the NULL buffer
 * remains the one with all fields initialized to zero so that a calloc() or a
 * memset() on a struct automatically sets a NULL buffer.
 */
#define BUF_NULL   ((struct buffer){ })
#define BUF_WANTED ((struct buffer){ .area = (char *)1 })


/***************************************************************************/
/* Functions used to compute offsets and pointers. Most of them exist in   */
/* both wrapping-safe and unchecked ("__" prefix) variants. Some returning */
/* a pointer are also provided with an "_ofs" suffix when they return an   */
/* offset relative to the storage area.                                    */
/***************************************************************************/

/* b_is_null() : returns true if (and only if) the buffer is not yet allocated
 * and thus points to a NULL area.
 */
static inline int b_is_null(const struct buffer *buf)
{
	return buf->area == NULL;
}

/* b_orig() : returns the pointer to the origin of the storage, which is the
 * location of byte at offset zero. This is mostly used by functions which
 * handle the wrapping by themselves.
 */
static inline char *b_orig(const struct buffer *b)
{
	return b->area;
}

/* b_size() : returns the size of the buffer. */
static inline size_t b_size(const struct buffer *b)
{
	return b->size;
}

/* b_wrap() : returns the pointer to the wrapping position of the buffer area,
 * which is by definition the first byte not part of the buffer.
 */
static inline char *b_wrap(const struct buffer *b)
{
	return b->area + b->size;
}

/* b_data() : returns the number of bytes present in the buffer. */
static inline size_t b_data(const struct buffer *b)
{
	return b->data;
}

/* b_room() : returns the amount of room left in the buffer */
static inline size_t b_room(const struct buffer *b)
{
	return b->size - b_data(b);
}

/* b_full() : returns true if the buffer is full. */
static inline size_t b_full(const struct buffer *b)
{
	return !b_room(b);
}


/* b_stop() : returns the pointer to the byte following the end of the buffer,
 * which may be out of the buffer if the buffer ends on the last byte of the
 * area.
 */
static inline size_t __b_stop_ofs(const struct buffer *b)
{
	return b->head + b->data;
}

static inline const char *__b_stop(const struct buffer *b)
{
	return b_orig(b) + __b_stop_ofs(b);
}

static inline size_t b_stop_ofs(const struct buffer *b)
{
	size_t stop = __b_stop_ofs(b);

	if (stop > b->size)
		stop -= b->size;
	return stop;
}

static inline const char *b_stop(const struct buffer *b)
{
	return b_orig(b) + b_stop_ofs(b);
}


/* b_peek() : returns a pointer to the data at position <ofs> relative to the
 * head of the buffer. Will typically point to input data if called with the
 * amount of output data. The wrapped versions will only support wrapping once
 * before the beginning or after the end.
 */
static inline size_t __b_peek_ofs(const struct buffer *b, size_t ofs)
{
	return b->head + ofs;
}

static inline char *__b_peek(const struct buffer *b, size_t ofs)
{
	return b_orig(b) + __b_peek_ofs(b, ofs);
}

static inline size_t b_peek_ofs(const struct buffer *b, size_t ofs)
{
	size_t ret = __b_peek_ofs(b, ofs);

	if (ret >= b->size)
		ret -= b->size;

	return ret;
}

static inline char *b_peek(const struct buffer *b, size_t ofs)
{
	return b_orig(b) + b_peek_ofs(b, ofs);
}


/* b_head() : returns the pointer to the buffer's head, which is the location
 * of the next byte to be dequeued. Note that for buffers of size zero, the
 * returned pointer may be outside of the buffer or even invalid.
 */
static inline size_t __b_head_ofs(const struct buffer *b)
{
	return b->head;
}

static inline char *__b_head(const struct buffer *b)
{
	return b_orig(b) + __b_head_ofs(b);
}

static inline size_t b_head_ofs(const struct buffer *b)
{
	return __b_head_ofs(b);
}

static inline char *b_head(const struct buffer *b)
{
	return __b_head(b);
}


/* b_tail() : returns the pointer to the tail of the buffer, which is the
 * location of the first byte where it is possible to enqueue new data. Note
 * that for buffers of size zero, the returned pointer may be outside of the
 * buffer or even invalid.
 */
static inline size_t __b_tail_ofs(const struct buffer *b)
{
	return __b_peek_ofs(b, b_data(b));
}

static inline char *__b_tail(const struct buffer *b)
{
	return __b_peek(b, b_data(b));
}

static inline size_t b_tail_ofs(const struct buffer *b)
{
	return b_peek_ofs(b, b_data(b));
}

static inline char *b_tail(const struct buffer *b)
{
	return b_peek(b, b_data(b));
}


/* b_next() : for an absolute pointer <p> or a relative offset <o> pointing to
 * a valid location within buffer <b>, returns either the absolute pointer or
 * the relative offset pointing to the next byte, which usually is at (p + 1)
 * unless p reaches the wrapping point and wrapping is needed.
 */
static inline size_t b_next_ofs(const struct buffer *b, size_t o)
{
	o++;
	if (o == b->size)
		o = 0;
	return o;
}

static inline char *b_next(const struct buffer *b, const char *p)
{
	p++;
	if (p == b_wrap(b))
		p = b_orig(b);
	return (char *)p;
}

/* b_dist() : returns the distance between two pointers, taking into account
 * the ability to wrap around the buffer's end. The operation is not defined if
 * either of the pointers does not belong to the buffer or if their distance is
 * greater than the buffer's size.
 */
static inline size_t b_dist(const struct buffer *b, const char *from, const char *to)
{
	ssize_t dist = to - from;

	dist += dist < 0 ? b_size(b) : 0;
	return dist;
}

/* b_almost_full() : returns 1 if the buffer uses at least 3/4 of its capacity,
 * otherwise zero. Buffers of size zero are considered full.
 */
static inline int b_almost_full(const struct buffer *b)
{
	return b_data(b) >= b_size(b) * 3 / 4;
}

/* b_space_wraps() : returns non-zero only if the buffer's free space wraps :
 *  [     |xxxx|           ]    => yes
 *  [xxxx|                 ]    => no
 *  [                 |xxxx]    => no
 *  [xxxx|            |xxxx]    => no
 *  [xxxxxxxxxx|xxxxxxxxxxx]    => no
 *
 *  So the only case where the buffer does not wrap is when there's data either
 *  at the beginning or at the end of the buffer. Thus we have this :
 *  - if (head <= 0)    ==> doesn't wrap
 *  - if (tail >= size) ==> doesn't wrap
 *  - otherwise wraps
 */
static inline int b_space_wraps(const struct buffer *b)
{
	if ((ssize_t)__b_head_ofs(b) <= 0)
		return 0;
	if (__b_tail_ofs(b) >= b_size(b))
		return 0;
	return 1;
}

/* b_contig_data() : returns the amount of data that can contiguously be read
 * at once starting from a relative offset <start> (which allows to easily
 * pre-compute blocks for memcpy). The start point will typically contain the
 * amount of past data already returned by a previous call to this function.
 */
static inline size_t b_contig_data(const struct buffer *b, size_t start)
{
	size_t data = b_wrap(b) - b_peek(b, start);
	size_t limit = b_data(b) - start;

	if (data > limit)
		data = limit;
	return data;
}

/* b_contig_space() : returns the amount of bytes that can be appended to the
 * buffer at once. We have 8 possible cases :
 *
 * [____________________]  return size
 * [______|_____________]  return size - tail_ofs
 * [XXXXXX|_____________]  return size - tail_ofs
 * [___|XXXXXX|_________]  return size - tail_ofs
 * [______________XXXXXX]  return head_ofs
 * [XXXX|___________|XXX]  return head_ofs - tail_ofs
 * [XXXXXXXXXX|XXXXXXXXX]  return 0
 * [XXXXXXXXXXXXXXXXXXXX]  return 0
 */
static inline size_t b_contig_space(const struct buffer *b)
{
	size_t left, right;

	right = b_head_ofs(b);
	left  = right + b_data(b);

	left = b_size(b) - left;
	if ((ssize_t)left <= 0)
		left += right;
	return left;
}

/* b_getblk() : gets one full block of data at once from a buffer, starting
 * from offset <offset> after the buffer's head, and limited to no more than
 * <len> bytes. The caller is responsible for ensuring that neither <offset>
 * nor <offset>+<len> exceed the total number of bytes available in the buffer.
 * Return values :
 *   >0 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <blk> is left undefined.
 * The buffer is left unaffected.
 */
static inline size_t b_getblk(const struct buffer *buf, char *blk, size_t len, size_t offset)
{
	size_t firstblock;

	if (len + offset > b_data(buf))
		return 0;

	firstblock = b_wrap(buf) - b_head(buf);
	if (firstblock > offset) {
		if (firstblock >= len + offset) {
			memcpy(blk, b_head(buf) + offset, len);
			return len;
		}

		memcpy(blk, b_head(buf) + offset, firstblock - offset);
		memcpy(blk + firstblock - offset, b_orig(buf), len - firstblock + offset);
		return len;
	}

	memcpy(blk, b_orig(buf) + offset - firstblock, len);
	return len;
}

/* b_getblk_nc() : gets one or two blocks of data at once from a buffer,
 * starting from offset <ofs> after the beginning of its output, and limited to
 * no more than <max> bytes. The caller is responsible for ensuring that
 * neither <ofs> nor <ofs>+<max> exceed the total number of bytes available in
 * the buffer. Return values :
 *   >0 : number of blocks filled (1 or 2). blk1 is always filled before blk2.
 *   =0 : not enough data available. <blk*> are left undefined.
 * The buffer is left unaffected. Unused buffers are left in an undefined state.
 */
static inline size_t b_getblk_nc(const struct buffer *buf, const char **blk1, size_t *len1, const char **blk2, size_t *len2, size_t ofs, size_t max)
{
	size_t l1;

	if (!max)
		return 0;

	*blk1 = b_peek(buf, ofs);
	l1 = b_wrap(buf) - *blk1;
	if (l1 < max) {
		*len1 = l1;
		*len2 = max - l1;
		*blk2 = b_orig(buf);
		return 2;
	}
	*len1 = max;
	return 1;
}


/*********************************************/
/* Functions used to modify the buffer state */
/*********************************************/

/* b_reset() : resets a buffer. The size is not touched. */
static inline void b_reset(struct buffer *b)
{
	b->head = 0;
	b->data = 0;
}

/* b_sub() : decreases the buffer length by <count> */
static inline void b_sub(struct buffer *b, size_t count)
{
	b->data -= count;
}

/* b_add() : increase the buffer length by <count> */
static inline void b_add(struct buffer *b, size_t count)
{
	b->data += count;
}

/* b_set_data() : sets the buffer's length */
static inline void b_set_data(struct buffer *b, size_t len)
{
	b->data = len;
}

/* b_del() : skips <del> bytes in a buffer <b>. Covers both the output and the
 * input parts so it's up to the caller to know where it plays and that <del>
 * is always smaller than the amount of data in the buffer.
 */
static inline void b_del(struct buffer *b, size_t del)
{
	b->data -= del;
	b->head += del;
	if (b->head >= b->size)
		b->head -= b->size;
}

/* b_realign_if_empty() : realigns a buffer if it's empty */
static inline void b_realign_if_empty(struct buffer *b)
{
	if (!b_data(b))
		b->head = 0;
}

/* b_slow_realign() : this function realigns a possibly wrapping buffer so that
 * the part remaining to be parsed is contiguous and starts at the beginning of
 * the buffer and the already parsed output part ends at the end of the buffer.
 * This provides the best conditions since it allows the largest inputs to be
 * processed at once and ensures that once the output data leaves, the whole
 * buffer is available at once. The number of output bytes supposedly present
 * at the beginning of the buffer and which need to be moved to the end must be
 * passed in <output>. A temporary swap area at least as large as b->size must
 * be provided in <swap>. It's up to the caller to ensure <output> is no larger
 * than the difference between the whole buffer's length and its input.
 */
static inline void b_slow_realign(struct buffer *b, char *swap, size_t output)
{
	size_t block1 = output;
	size_t block2 = 0;

	/* process output data in two steps to cover wrapping */
	if (block1 > b_size(b) - b_head_ofs(b)) {
		block2 = b_size(b) - b_head_ofs(b);
		block1 -= block2;
	}
	memcpy(swap + b_size(b) - output, b_head(b), block1);
	memcpy(swap + b_size(b) - block2, b_orig(b), block2);

	/* process input data in two steps to cover wrapping */
	block1 = b_data(b) - output;
	block2 = 0;

	if (block1 > b_tail_ofs(b)) {
		block2 = b_tail_ofs(b);
		block1 = block1 - block2;
	}
	memcpy(swap, b_peek(b, output), block1);
	memcpy(swap + block1, b_orig(b), block2);

	/* reinject changes into the buffer */
	memcpy(b_orig(b), swap, b_data(b) - output);
	memcpy(b_wrap(b) - output, swap + b_size(b) - output, output);

	b->head = (output ? b_size(b) - output : 0);
}

/* b_putchar() : tries to append char <c> at the end of buffer <b>. Supports
 * wrapping. Data are truncated if buffer is full.
 */
static inline void b_putchr(struct buffer *b, char c)
{
	if (b_full(b))
		return;
	*b_tail(b) = c;
	b->data++;
}

/* __b_putblk() : tries to append <len> bytes from block <blk> to the end of
 * buffer <b> without checking for free space (it's up to the caller to do it).
 * Supports wrapping. It must not be called with len == 0.
 */
static inline void __b_putblk(struct buffer *b, const char *blk, size_t len)
{
	size_t half = b_contig_space(b);

	if (half > len)
		half = len;

	memcpy(b_tail(b), blk, half);

	if (len > half)
		memcpy(b_peek(b, b_data(b) + half), blk + half, len - half);
	b->data += len;
}

/* b_putblk() : tries to append block <blk> at the end of buffer <b>. Supports
 * wrapping. Data are truncated if buffer is too short. It returns the number
 * of bytes copied.
 */
static inline size_t b_putblk(struct buffer *b, const char *blk, size_t len)
{
	if (len > b_room(b))
		len = b_room(b);
	if (len)
		__b_putblk(b, blk, len);
	return len;
}

/* b_xfer() : transfers at most <count> bytes from buffer <src> to buffer <dst>
 * and returns the number of bytes copied. The bytes are removed from <src> and
 * added to <dst>. The caller is responsible for ensuring that <count> is not
 * larger than b_room(dst). Whenever possible (if the destination is empty and
 * at least as much as the source was requested), the buffers are simply
 * swapped instead of copied.
 */
static inline size_t b_xfer(struct buffer *dst, struct buffer *src, size_t count)
{
	size_t ret, block1, block2;

	ret = 0;
	if (!count)
		goto leave;

	ret = b_data(src);
	if (!ret)
		goto leave;

	if (ret > count)
		ret = count;
	else if (!b_data(dst)) {
		/* zero copy is possible by just swapping buffers */
		struct buffer tmp = *dst;
		*dst = *src;
		*src = tmp;
		goto leave;
	}

	block1 = b_contig_data(src, 0);
	if (block1 > ret)
		block1 = ret;
	block2 = ret - block1;

	if (block1)
		__b_putblk(dst, b_head(src), block1);

	if (block2)
		__b_putblk(dst, b_peek(src, block1), block2);

	b_del(src, ret);
 leave:
	return ret;
}

/* b_rep_blk() : writes the block <blk> at position <pos> which must be in
 * buffer <b>, and moves the part between <end> and the buffer's tail just
 * after the end of the copy of <blk>. This effectively replaces the part
 * located between <pos> and <end> with a copy of <blk> of length <len>. The
 * buffer's length is automatically updated. This is used to replace a block
 * with another one inside a buffer. The shift value (positive or negative) is
 * returned. If there's no space left, the move is not done. If <len> is null,
 * the <blk> pointer is allowed to be null, in order to erase a block.
 */
static inline int b_rep_blk(struct buffer *b, char *pos, char *end, const char *blk, size_t len)
{
	int delta;

	delta = len - (end - pos);

	if (__b_tail(b) + delta > b_wrap(b))
		return 0;  /* no space left */

	if (b_data(b) &&
	    b_tail(b) + delta > b_head(b) &&
	    b_head(b) >= b_tail(b))
		return 0;  /* no space left before wrapping data */

	/* first, protect the end of the buffer */
	memmove(end + delta, end, b_tail(b) - end);

	/* now, copy blk over pos */
	if (len)
		memcpy(pos, blk, len);

	b_add(b, delta);
	b_realign_if_empty(b);

	return delta;
}


#endif /* _COMMON_BUF_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
