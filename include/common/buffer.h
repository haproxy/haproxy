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

extern struct pool_head *pool2_buffer;
extern struct buffer buf_empty;
extern struct buffer buf_wanted;
extern struct list buffer_wq;

int init_buffer();
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len);
int buffer_insert_line2(struct buffer *b, char *pos, const char *str, int len);
void buffer_dump(FILE *o, struct buffer *b, int from, int to);
void buffer_slow_realign(struct buffer *buf);
void buffer_bounce_realign(struct buffer *buf);

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

/* Returns the number of contiguous bytes between <start> and <start>+<count>,
 * and enforces a limit on buf->data + buf->size. <start> must be within the
 * buffer.
 */
static inline int buffer_contig_area(const struct buffer *buf, const char *start, int count)
{
	if (count > buf->data - start + buf->size)
		count = buf->data - start + buf->size;
	return count;
}

/* Return the amount of bytes that can be written into the buffer at once,
 * including reserved space which may be overwritten.
 */
static inline int buffer_contig_space(const struct buffer *buf)
{
	const char *left, *right;

	if (buf->data + buf->o <= buf->p)
		right = buf->data + buf->size;
	else
		right = buf->p + buf->size - buf->o;

	left = buffer_wrap_add(buf, buf->p + buf->i);
	return right - left;
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

/* Returns the size of the working area which the caller knows ends at <end>.
 * If <end> equals buf->r (modulo size), then it means that the free area which
 * follows is part of the working area. Otherwise, the working area stops at
 * <end>. It always starts at buf->p. The work area includes the
 * reserved area.
 */
static inline int buffer_work_area(const struct buffer *buf, const char *end)
{
	end = buffer_pointer(buf, end);
	if (end == buffer_wrap_add(buf, buf->p + buf->i))
		/* pointer exactly at end, lets push forwards */
		end = buffer_wrap_sub(buf, buf->p - buf->o);
	return buffer_count(buf, buf->p, end);
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

/*
 * Tries to realign the given buffer, and returns how many bytes can be written
 * there at once without overwriting anything.
 */
static inline int buffer_realign(struct buffer *buf)
{
	if (!(buf->i | buf->o)) {
		/* let's realign the buffer to optimize I/O */
		buf->p = buf->data;
	}
	return buffer_contig_space(buf);
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

	half = buffer_contig_space(b);
	if (half > len)
		half = len;

	memcpy(b->p, blk, half);
	b->p = b_ptr(b, half);
	if (len > half) {
		memcpy(b->p, blk, len - half);
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
	b = pool_alloc_dirty(pool2_buffer);
	if (likely(b)) {
		b->size = pool2_buffer->size - sizeof(struct buffer);
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
	b = pool_get_first(pool2_buffer);
	if (likely(b)) {
		b->size = pool2_buffer->size - sizeof(struct buffer);
		b_reset(b);
		*buf = b;
	}
	return b;
}

/* Releases buffer *buf (no check of emptiness) */
static inline void __b_drop(struct buffer **buf)
{
	pool_free2(pool2_buffer, *buf);
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
 */
static inline struct buffer *b_alloc_margin(struct buffer **buf, int margin)
{
	struct buffer *next;

	if ((*buf)->size)
		return *buf;

	/* fast path */
	if ((pool2_buffer->allocated - pool2_buffer->used) > margin)
		return b_alloc_fast(buf);

	next = pool_refill_alloc(pool2_buffer, margin);
	if (!next)
		return next;

	next->size = pool2_buffer->size - sizeof(struct buffer);
	b_reset(next);
	*buf = next;
	return next;
}


void __offer_buffer(void *from, unsigned int threshold);

static inline void offer_buffers(void *from, unsigned int threshold)
{
	if (LIST_ISEMPTY(&buffer_wq))
		return;
	__offer_buffer(from, threshold);
}

#endif /* _COMMON_BUFFER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
