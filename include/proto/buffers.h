/*
 * include/proto/buffers.h
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

#ifndef _PROTO_BUFFERS_H
#define _PROTO_BUFFERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/buffers.h>
#include <types/global.h>

extern struct pool_head *pool2_buffer;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_buffer();

/* SI-to-buffer functions : buffer_{get,put}_{char,block,string,chunk} */
int bo_inject(struct buffer *buf, const char *msg, int len);
int bi_putblk(struct buffer *buf, const char *str, int len);
int bi_putchr(struct buffer *buf, char c);
int bo_getline(struct buffer *buf, char *str, int len);
int bo_getblk(struct buffer *buf, char *blk, int len, int offset);
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len);
int buffer_insert_line2(struct buffer *b, char *pos, const char *str, int len);
void buffer_dump(FILE *o, struct buffer *b, int from, int to);
void buffer_slow_realign(struct buffer *buf);
void buffer_bounce_realign(struct buffer *buf);
unsigned long long buffer_forward(struct buffer *buf, unsigned long long bytes);

/* Initialize all fields in the buffer. The BF_OUT_EMPTY flags is set. */
static inline void buffer_init(struct buffer *buf)
{
	buf->o = 0;
	buf->i = 0;
	buf->to_forward = 0;
	buf->total = 0;
	buf->pipe = NULL;
	buf->analysers = 0;
	buf->cons = NULL;
	buf->flags = BF_OUT_EMPTY;
	buf->p = buf->data;
}

/*****************************************************************/
/* These functions are used to compute various buffer area sizes */
/*****************************************************************/

/* Returns an absolute pointer for a position relative to the current buffer's
 * pointer. It is written so that it is optimal when <ofs> is a const. It is
 * written as a macro instead of an inline function so that the compiler knows
 * when it can optimize out the sign test on <ofs> when passed an unsigned int.
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

/* Return the number of reserved bytes in the buffer, which ensures that once
 * all pending data are forwarded, the buffer still has global.tune.maxrewrite
 * bytes free. The result is between 0 and global.maxrewrite, which is itself
 * smaller than any buf->size.
 */
static inline int buffer_reserved(const struct buffer *buf)
{
	int ret = global.tune.maxrewrite - buf->to_forward - buf->o;

	if (buf->to_forward == BUF_INFINITE_FORWARD)
		return 0;
	if (ret <= 0)
		return 0;
	return ret;
}

/* Return the max number of bytes the buffer can contain so that once all the
 * pending bytes are forwarded, the buffer still has global.tune.maxrewrite
 * bytes free. The result sits between buf->size - maxrewrite and buf->size.
 */
static inline int buffer_max_len(const struct buffer *buf)
{
	return buf->size - buffer_reserved(buf);
}

/* Returns non-zero if the buffer input is considered full. The reserved space
 * is taken into account if ->to_forward indicates that an end of transfer is
 * close to happen. The test is optimized to avoid as many operations as
 * possible for the fast case and to be used as an "if" condition.
 */
static inline int bi_full(const struct buffer *b)
{
	int rem = b->size;

	rem -= b->o;
	rem -= b->i;
	if (!rem)
		return 1; /* buffer already full */

	if (b->to_forward >= b->size ||
	    (BUF_INFINITE_FORWARD < MAX_RANGE(typeof(b->size)) && // just there to ensure gcc
	     b->to_forward == BUF_INFINITE_FORWARD))              // avoids the useless second
		return 0;                                         // test whenever possible

	rem -= global.tune.maxrewrite;
	rem += b->o;
	rem += b->to_forward;
	return rem <= 0;
}

/* Returns the amount of space available at the input of the buffer, taking the
 * reserved space into account if ->to_forward indicates that an end of transfer
 * is close to happen. The test is optimized to avoid as many operations as
 * possible for the fast case.
 */
static inline int bi_avail(const struct buffer *b)
{
	int rem = b->size;
	int rem2;

	rem -= b->o;
	rem -= b->i;
	if (!rem)
		return rem; /* buffer already full */

	if (b->to_forward >= b->size ||
	    (BUF_INFINITE_FORWARD < MAX_RANGE(typeof(b->size)) && // just there to ensure gcc
	     b->to_forward == BUF_INFINITE_FORWARD))              // avoids the useless second
		return rem;                                         // test whenever possible

	rem2 = rem - global.tune.maxrewrite;
	rem2 += b->o;
	rem2 += b->to_forward;

	if (rem > rem2)
		rem = rem2;
	if (rem > 0)
		return rem;
	return 0;
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

/* Advances the buffer by <adv> bytes, which means that the buffer
 * pointer advances, and that as many bytes from in are transferred
 * to out. The caller is responsible for ensuring that adv is always
 * smaller than or equal to b->i. The BF_OUT_EMPTY flag is updated.
 */
static inline void b_adv(struct buffer *b, unsigned int adv)
{
	b->i -= adv;
	b->o += adv;
	if (b->o)
		b->flags &= ~BF_OUT_EMPTY;
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
	if (!b->o && !b->pipe)
		b->flags |= BF_OUT_EMPTY;
	b->p = b_ptr(b, -adv);
}

/* Return the amount of bytes that can be written into the buffer at once,
 * excluding the amount of reserved space passed in <res>, which is
 * preserved.
 */
static inline int buffer_contig_space_with_res(const struct buffer *buf, int res)
{
	/* Proceed differently if the buffer is full, partially used or empty.
	 * The hard situation is when it's partially used and either data or
	 * reserved space wraps at the end.
	 */
	int spare = buf->size - res;

	if (buffer_len(buf) >= spare)
		spare = 0;
	else if (buffer_len(buf)) {
		spare = buffer_contig_space(buf) - res;
		if (spare < 0)
			spare = 0;
	}
	return spare;
}


/* Return the amount of bytes that can be written into the buffer at once,
 * excluding reserved space, which is preserved.
 */
static inline int buffer_contig_space_res(const struct buffer *buf)
{
	return buffer_contig_space_with_res(buf, buffer_reserved(buf));
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
	if (count < 0)
		count += buf->size;
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
	if (buffer_total_space(buf) < buf->size / 4)
		return 1;
	return 0;
}

/* Returns true if the buffer's input is already closed */
static inline int buffer_input_closed(struct buffer *buf)
{
	return ((buf->flags & BF_SHUTR) != 0);
}

/* Returns true if the buffer's output is already closed */
static inline int buffer_output_closed(struct buffer *buf)
{
	return ((buf->flags & BF_SHUTW) != 0);
}

/* Check buffer timeouts, and set the corresponding flags. The
 * likely/unlikely have been optimized for fastest normal path.
 * The read/write timeouts are not set if there was activity on the buffer.
 * That way, we don't have to update the timeout on every I/O. Note that the
 * analyser timeout is always checked.
 */
static inline void buffer_check_timeouts(struct buffer *b)
{
	if (likely(!(b->flags & (BF_SHUTR|BF_READ_TIMEOUT|BF_READ_ACTIVITY|BF_READ_NOEXP))) &&
	    unlikely(tick_is_expired(b->rex, now_ms)))
		b->flags |= BF_READ_TIMEOUT;

	if (likely(!(b->flags & (BF_SHUTW|BF_WRITE_TIMEOUT|BF_WRITE_ACTIVITY))) &&
	    unlikely(tick_is_expired(b->wex, now_ms)))
		b->flags |= BF_WRITE_TIMEOUT;

	if (likely(!(b->flags & BF_ANA_TIMEOUT)) &&
	    unlikely(tick_is_expired(b->analyse_exp, now_ms)))
		b->flags |= BF_ANA_TIMEOUT;
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
	if (buf->o)
		buf->flags &= ~BF_OUT_EMPTY;
}

/* Erase any content from buffer <buf> and adjusts flags accordingly. Note
 * that any spliced data is not affected since we may not have any access to
 * it.
 */
static inline void buffer_erase(struct buffer *buf)
{
	buf->o = 0;
	buf->i = 0;
	buf->to_forward = 0;
	buf->p = buf->data;
	buf->flags &= ~(BF_FULL | BF_OUT_EMPTY);
	if (!buf->pipe)
		buf->flags |= BF_OUT_EMPTY;
}

/* Cut the "tail" of the buffer, which means strip it to the length of unsent
 * data only, and kill any remaining unsent data. Any scheduled forwarding is
 * stopped. This is mainly to be used to send error messages after existing
 * data.
 */
static inline void bi_erase(struct buffer *buf)
{
	if (!buf->o)
		return buffer_erase(buf);

	buf->to_forward = 0;
	if (!buf->i)
		return;

	buf->i = 0;
	buf->flags &= ~BF_FULL;
	if (bi_full(buf))
		buf->flags |= BF_FULL;
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

/* marks the buffer as "shutdown" ASAP for reads */
static inline void buffer_shutr_now(struct buffer *buf)
{
	buf->flags |= BF_SHUTR_NOW;
}

/* marks the buffer as "shutdown" ASAP for writes */
static inline void buffer_shutw_now(struct buffer *buf)
{
	buf->flags |= BF_SHUTW_NOW;
}

/* marks the buffer as "shutdown" ASAP in both directions */
static inline void buffer_abort(struct buffer *buf)
{
	buf->flags |= BF_SHUTR_NOW | BF_SHUTW_NOW;
	buf->flags &= ~BF_AUTO_CONNECT;
}

/* Installs <func> as a hijacker on the buffer <b> for session <s>. The hijack
 * flag is set, and the function called once. The function is responsible for
 * clearing the hijack bit. It is possible that the function clears the flag
 * during this first call.
 */
static inline void buffer_install_hijacker(struct session *s,
					   struct buffer *b,
					   void (*func)(struct session *, struct buffer *))
{
	b->hijacker = func;
	b->flags |= BF_HIJACK;
	func(s, b);
}

/* Releases the buffer from hijacking mode. Often used by the hijack function */
static inline void buffer_stop_hijack(struct buffer *buf)
{
	buf->flags &= ~BF_HIJACK;
}

/* allow the consumer to try to establish a new connection. */
static inline void buffer_auto_connect(struct buffer *buf)
{
	buf->flags |= BF_AUTO_CONNECT;
}

/* prevent the consumer from trying to establish a new connection, and also
 * disable auto shutdown forwarding.
 */
static inline void buffer_dont_connect(struct buffer *buf)
{
	buf->flags &= ~(BF_AUTO_CONNECT|BF_AUTO_CLOSE);
}

/* allow the producer to forward shutdown requests */
static inline void buffer_auto_close(struct buffer *buf)
{
	buf->flags |= BF_AUTO_CLOSE;
}

/* prevent the producer from forwarding shutdown requests */
static inline void buffer_dont_close(struct buffer *buf)
{
	buf->flags &= ~BF_AUTO_CLOSE;
}

/* allow the producer to read / poll the input */
static inline void buffer_auto_read(struct buffer *buf)
{
	buf->flags &= ~BF_DONT_READ;
}

/* prevent the producer from read / poll the input */
static inline void buffer_dont_read(struct buffer *buf)
{
	buf->flags |= BF_DONT_READ;
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

/*
 * Advance the buffer's read pointer by <len> bytes. This is useful when data
 * have been read directly from the buffer. It is illegal to call this function
 * with <len> causing a wrapping at the end of the buffer. It's the caller's
 * responsibility to ensure that <len> is never larger than buf->o.
 */
static inline void bo_skip(struct buffer *buf, int len)
{
	buf->o -= len;
	if (!buf->o && !buf->pipe)
		buf->flags |= BF_OUT_EMPTY;

	if (buffer_len(buf) == 0)
		buf->p = buf->data;

	if (!bi_full(buf))
		buf->flags &= ~BF_FULL;

	/* notify that some data was written to the SI from the buffer */
	buf->flags |= BF_WRITE_PARTIAL;
}

/* Tries to copy chunk <chunk> into buffer <buf> after length controls.
 * The ->o and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Buffer flags FULL, EMPTY and READ_PARTIAL are updated if some data can be
 * transferred. The chunk's length is updated with the number of bytes sent.
 */
static inline int bi_putchk(struct buffer *buf, struct chunk *chunk)
{
	int ret;

	ret = bi_putblk(buf, chunk->str, chunk->len);
	if (ret > 0)
		chunk->len -= ret;
	return ret;
}

/* Tries to copy string <str> at once into buffer <buf> after length controls.
 * The ->o and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Buffer flags FULL, EMPTY and READ_PARTIAL are updated if some data can be
 * transferred.
 */
static inline int bi_putstr(struct buffer *buf, const char *str)
{
	return bi_putblk(buf, str, strlen(str));
}

/*
 * Return one char from the buffer. If the buffer is empty and closed, return -2.
 * If the buffer is just empty, return -1. The buffer's pointer is not advanced,
 * it's up to the caller to call bo_skip(buf, 1) when it has consumed the char.
 * Also note that this function respects the ->o limit.
 */
static inline int bo_getchr(struct buffer *buf)
{
	/* closed or empty + imminent close = -2; empty = -1 */
	if (unlikely(buf->flags & (BF_OUT_EMPTY|BF_SHUTW))) {
		if (buf->flags & (BF_SHUTW|BF_SHUTW_NOW))
			return -2;
		return -1;
	}
	return *buffer_wrap_sub(buf, buf->p - buf->o);
}

/* This function writes the string <str> at position <pos> which must be in
 * buffer <b>, and moves <end> just after the end of <str>. <b>'s parameters
 * (l, r, lr) are updated to be valid after the shift. the shift value
 * (positive or negative) is returned. If there's no space left, the move is
 * not done. The function does not adjust ->o nor BF_OUT_EMPTY because
 * it does not make sense to use it on data scheduled to be sent.
 */
static inline int buffer_replace(struct buffer *b, char *pos, char *end, const char *str)
{
	return buffer_replace2(b, pos, end, str, strlen(str));
}

/*
 *
 * Functions below are used to manage chunks
 *
 */

static inline void chunk_init(struct chunk *chk, char *str, size_t size) {
	chk->str  = str;
	chk->len  = 0;
	chk->size = size;
}

/* report 0 in case of error, 1 if OK. */
static inline int chunk_initlen(struct chunk *chk, char *str, size_t size, int len) {

	if (size && len > size)
		return 0;

	chk->str  = str;
	chk->len  = len;
	chk->size = size;

	return 1;
}

static inline void chunk_initstr(struct chunk *chk, char *str) {
	chk->str = str;
	chk->len = strlen(str);
	chk->size = 0;			/* mark it read-only */
}

static inline int chunk_strcpy(struct chunk *chk, const char *str) {
	size_t len;

	len = strlen(str);

	if (unlikely(len > chk->size))
		return 0;

	chk->len  = len;
	memcpy(chk->str, str, len);

	return 1;
}

int chunk_printf(struct chunk *chk, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));

int chunk_htmlencode(struct chunk *dst, struct chunk *src);
int chunk_asciiencode(struct chunk *dst, struct chunk *src, char qc);

static inline void chunk_reset(struct chunk *chk) {
	chk->str  = NULL;
	chk->len  = -1;
	chk->size = 0;
}

static inline void chunk_destroy(struct chunk *chk) {

	if (!chk->size)
		return;

	if (chk->str)
		free(chk->str);

	chunk_reset(chk);
}

/*
 * frees the destination chunk if already allocated, allocates a new string,
 * and copies the source into it. The pointer to the destination string is
 * returned, or NULL if the allocation fails or if any pointer is NULL..
 */
static inline char *chunk_dup(struct chunk *dst, const struct chunk *src) {
	if (!dst || !src || !src->str)
		return NULL;
	if (dst->str)
		free(dst->str);
	dst->len = src->len;
	dst->str = (char *)malloc(dst->len);
	memcpy(dst->str, src->str, dst->len);
	return dst->str;
}

#endif /* _PROTO_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
