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

#include <common/buf.h>
#include <common/chunk.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/memory.h>


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

/*****************************************************************/
/* These functions are used to compute various buffer area sizes */
/*****************************************************************/



/***** FIXME: OLD API BELOW *****/

/* Normalizes a pointer after an addition */
static inline char *buffer_wrap_add(const struct buffer *buf, char *ptr)
{
	if (ptr - buf->size >= b_orig(buf))
		ptr -= buf->size;
	return ptr;
}

/* Normalizes a pointer which is supposed to be relative to the beginning of a
 * buffer, so that wrapping is correctly handled. The intent is to use this
 * when increasing a pointer. Note that the wrapping test is only performed
 * once, so the original pointer must be between ->data-size and ->data+2*size-1,
 * otherwise an invalid pointer might be returned.
 */
static inline const char *buffer_pointer(const struct buffer *buf, const char *ptr)
{
	if (ptr < b_orig(buf))
		ptr += buf->size;
	else if (ptr - buf->size >= b_orig(buf))
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

/* Return 1 if the buffer has less than 1/4 of its capacity free, otherwise 0 */
static inline int buffer_almost_full(const struct buffer *buf)
{
	if (buf == &buf_empty)
		return 0;

	return b_almost_full(buf);
}

/* Cut the first <n> pending bytes in a contiguous buffer. The caller must
 * ensure that <n> is smaller than the actual buffer's length. This is mainly
 * used to remove empty lines at the beginning of a request or a response.
 */
static inline void bi_fast_delete(struct buffer *buf, int n)
{
	buf->len  -= n;
	buf->head += n;
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

/* Tries to append char <c> at the end of buffer <b>. Supports wrapping. Data
 * are truncated if buffer is full.
 */
static inline void bo_putchr(struct buffer *b, char c)
{
	if (b_data(b) == b->size)
		return;
	*b_tail(b) = c;
	b->len++;
	b->output++;
}

/* Tries to append block <blk> at the end of buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline unsigned int bo_putblk(struct buffer *b, const char *blk, unsigned int len)
{
	unsigned int half;

	if (len > b_room(b))
		len = b_room(b);
	if (!len)
		return 0;

	half = b_contig_space(b);
	if (half > len)
		half = len;

	memcpy(b_tail(b), blk, half);
	b->len += half;
	if (len > half) {
		memcpy(b_tail(b), blk + half, len - half);
		b->len += len - half;
	}
	b->output += len;
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

/* Tries to write char <c> into input data at buffer <b>. Supports wrapping.
 * Data are truncated if buffer is full.
 */
static inline void bi_putchr(struct buffer *b, char c)
{
	if (b_data(b) == b->size)
		return;
	*b_tail(b) = c;
	b->len++;
}

/* Tries to append block <blk> at the end of buffer <b>. Supports wrapping.
 * Data are truncated if buffer is too short. It returns the number of bytes
 * copied.
 */
static inline unsigned int bi_putblk(struct buffer *b, const char *blk, unsigned int len)
{
	int half;

	if (len > b_room(b))
		len = b_room(b);
	if (!len)
		return 0;

	half = b_contig_space(b);
	if (half > len)
		half = len;

	memcpy(b_tail(b), blk, half);
	b->len += half;
	if (len > half) {
		memcpy(b_tail(b), blk + half, len - half);
		b->len += len - half;
	}
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


/* Offer a buffer currently belonging to target <from> to whoever needs one.
 * Any pointer is valid for <from>, including NULL. Its purpose is to avoid
 * passing a buffer to oneself in case of failed allocations (e.g. need two
 * buffers, get one, fail, release it and wake up self again). In case of
 * normal buffer release where it is expected that the caller is not waiting
 * for a buffer, NULL is fine.
 */
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

/* returns > 0 if the first <n> characters of buffer <b> starting at offset <o>
 * relative to the buffer's head match <ist>. (empty strings do match). It is
 * designed to be use with reasonably small strings (ie matches a single byte
 * per iteration). This function is usable both with input and output data. To
 * be used like this depending on what to match :
 * - input contents  :  b_isteq(b, b->o, b->i, ist);
 * - output contents :  b_isteq(b, 0, b->o, ist);
 * Return value :
 *   >0 : the number of matching bytes
 *   =0 : not enough bytes (or matching of empty string)
 *   <0 : non-matching byte found
 */
static inline int b_isteq(const struct buffer *b, unsigned int o, size_t n, const struct ist ist)
{
	struct ist r = ist;
	const char *p;
	const char *end = b_wrap(b);

	if (n < r.len)
		return 0;

	p = b_peek(b, o);
	while (r.len--) {
		if (*p++ != *r.ptr++)
			return -1;
		if (unlikely(p == end))
			p = b_orig(b);
	}
	return ist.len;
}

/* "eats" string <ist> from the head of buffer <b>. Wrapping data is explicitly
 * supported. It matches a single byte per iteration so strings should remain
 * reasonably small. Returns :
 *   > 0 : number of bytes matched and eaten
 *   = 0 : not enough bytes (or matching an empty string)
 *   < 0 : non-matching byte found
 */
static inline int b_eat(struct buffer *b, const struct ist ist)
{
	int ret = b_isteq(b, 0, b_data(b), ist);
	if (ret > 0)
		b_del(b, ret);
	return ret;
}

/* injects string <ist> at the tail of input buffer <b> provided that it
 * fits. Wrapping is supported. It's designed for small strings as it only
 * writes a single byte per iteration. Returns the number of characters copied
 * (ist.len), 0 if it temporarily does not fit or -1 if it will never fit. It
 * will only modify the buffer upon success. In all cases, the contents are
 * copied prior to reporting an error, so that the destination at least
 * contains a valid but truncated string.
 */
static inline int bi_istput(struct buffer *b, const struct ist ist)
{
	const char *end = b_wrap(b);
	struct ist r = ist;
	char *p;

	if (r.len > (size_t)b_room(b))
		return r.len < b->size ? 0 : -1;

	p = b_tail(b);
	b->len += r.len;
	while (r.len--) {
		*p++ = *r.ptr++;
		if (unlikely(p == end))
			p = b_orig(b);
	}
	return ist.len;
}


/* injects string <ist> at the tail of output buffer <b> provided that it
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
	const char *end = b_wrap(b);
	struct ist r = ist;
	char *p;

	if (r.len > (size_t)b_room(b))
		return r.len < b->size ? 0 : -1;

	p = b_tail(b);
	b->len += r.len;
	b->output += r.len;
	while (r.len--) {
		*p++ = *r.ptr++;
		if (unlikely(p == end))
			p = b_orig(b);
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
