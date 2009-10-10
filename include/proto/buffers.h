/*
  include/proto/buffers.h
  Buffer management definitions, macros and inline functions.

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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

extern struct pool_head *pool2_buffer;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_buffer();

/* Initializes all fields in the buffer. The ->max_len field is initialized last
 * so that the compiler can optimize it away if changed immediately after the
 * call to this function. By default, it is set to the full size of the buffer.
 * This implies that buffer_init() must only be called once ->size is set !
 * The BF_OUT_EMPTY flags is set.
 */
static inline void buffer_init(struct buffer *buf)
{
	buf->send_max = 0;
	buf->to_forward = 0;
	buf->l = buf->total = 0;
	buf->pipe = NULL;
	buf->analysers = 0;
	buf->cons = NULL;
	buf->flags = BF_OUT_EMPTY;
	buf->r = buf->lr = buf->w = buf->data;
	buf->max_len = buf->size;
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

/* Schedule <bytes> more bytes to be forwarded by the buffer without notifying
 * the task. Any pending data in the buffer is scheduled to be sent as well,
 * in the limit of the number of bytes to forward. This must be the only method
 * to use to schedule bytes to be sent. Directly touching ->to_forward will
 * cause lockups when send_max goes down to zero if nobody is ready to push the
 * remaining data.
 */
static inline void buffer_forward(struct buffer *buf, unsigned long bytes)
{
	unsigned long data_left;

	if (!bytes)
		return;
	data_left = buf->l - buf->send_max;
	if (data_left >= bytes) {
		buf->send_max += bytes;
		buf->flags &= ~BF_OUT_EMPTY;
		return;
	}

	buf->send_max += data_left;
	if (buf->send_max)
		buf->flags &= ~BF_OUT_EMPTY;

	if (buf->to_forward == BUF_INFINITE_FORWARD)
		return;

	buf->to_forward += bytes - data_left;
	if (bytes == BUF_INFINITE_FORWARD)
		buf->to_forward = bytes;
}

/* Schedule all remaining buffer data to be sent. send_max is not touched if it
 * already covers those data. That permits doing a flush even after a forward,
 * although not recommended.
 */
static inline void buffer_flush(struct buffer *buf)
{
	if (buf->send_max < buf->l)
		buf->send_max = buf->l;
	if (buf->send_max)
		buf->flags &= ~BF_OUT_EMPTY;
}

/* Erase any content from buffer <buf> and adjusts flags accordingly. Note
 * that any spliced data is not affected since we may not have any access to
 * it.
 */
static inline void buffer_erase(struct buffer *buf)
{
	buf->send_max = 0;
	buf->to_forward = 0;
	buf->r = buf->lr = buf->w = buf->data;
	buf->l = 0;
	buf->flags &= ~(BF_FULL | BF_OUT_EMPTY);
	if (!buf->pipe)
		buf->flags |= BF_OUT_EMPTY;
	if (!buf->max_len)
		buf->flags |= BF_FULL;
}

/* Cut the "tail" of the buffer, which means strip it to the length of unsent
 * data only, and kill any remaining unsent data. Any scheduled forwarding is
 * stopped. This is mainly to be used to send error messages after existing
 * data.
 */
static inline void buffer_cut_tail(struct buffer *buf)
{
	if (!buf->send_max)
		return buffer_erase(buf);

	buf->to_forward = 0;
	if (buf->l == buf->send_max)
		return;

	buf->l = buf->send_max;
	buf->r = buf->w + buf->l;
	if (buf->r >= buf->data + buf->size)
		buf->r -= buf->size;
	buf->lr = buf->r;
	buf->flags &= ~BF_FULL;
	if (buf->l >= buf->max_len)
		buf->flags |= BF_FULL;
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

/* returns the maximum number of bytes writable at once in this buffer */
static inline int buffer_max(const struct buffer *buf)
{
	if (buf->l == buf->size)
		return 0;
	else if (buf->r >= buf->w)
		return buf->data + buf->size - buf->r;
	else
		return buf->w - buf->r;
}

/* sets the buffer read limit to <size> bytes, and adjusts the FULL
 * flag accordingly.
 */
static inline void buffer_set_rlim(struct buffer *buf, int size)
{
	buf->max_len = size;
	if (buf->l < size)
		buf->flags &= ~BF_FULL;
	else
		buf->flags |= BF_FULL;
}

/*
 * Tries to realign the given buffer, and returns how many bytes can be written
 * there at once without overwriting anything.
 */
static inline int buffer_realign(struct buffer *buf)
{
	if (buf->l == 0) {
		/* let's realign the buffer to optimize I/O */
		buf->r = buf->w = buf->lr = buf->data;
	}
	return buffer_max(buf);
}

/*
 * Return the max amount of bytes that can be stuffed into the buffer at once.
 * Note that this may be lower than the actual buffer size when the free space
 * wraps after the end, so it's preferable to call this function again after
 * writing. Also note that this function respects max_len.
 */
static inline int buffer_contig_space(struct buffer *buf)
{
	int ret;

	if (buf->l == 0) {
		buf->r = buf->w = buf->lr = buf->data;
		ret = buf->max_len;
	}
	else if (buf->r > buf->w) {
		ret = buf->data + buf->max_len - buf->r;
	}
	else {
		ret = buf->w - buf->r;
		if (ret > buf->max_len)
			ret = buf->max_len;
	}
	return ret;
}

/*
 * Return the max amount of bytes that can be read from the buffer at once.
 * Note that this may be lower than the actual buffer length when the data
 * wrap after the end, so it's preferable to call this function again after
 * reading. Also note that this function respects the send_max limit.
 */
static inline int buffer_contig_data(struct buffer *buf)
{
	int ret;

	if (!buf->send_max || !buf->l)
		return 0;

	if (buf->r > buf->w)
		ret = buf->r - buf->w;
	else
		ret = buf->data + buf->size - buf->w;

	/* limit the amount of outgoing data if required */
	if (ret > buf->send_max)
		ret = buf->send_max;

	return ret;
}

/*
 * Advance the buffer's read pointer by <len> bytes. This is useful when data
 * have been read directly from the buffer. It is illegal to call this function
 * with <len> causing a wrapping at the end of the buffer. It's the caller's
 * responsibility to ensure that <len> is never larger than buf->send_max.
 */
static inline void buffer_skip(struct buffer *buf, int len)
{
	buf->w += len;
	if (buf->w >= buf->data + buf->size)
		buf->w -= buf->size; /* wrap around the buffer */

	buf->l -= len;
	if (!buf->l)
		buf->r = buf->w = buf->lr = buf->data;

	if (buf->l < buf->max_len)
		buf->flags &= ~BF_FULL;

	buf->send_max -= len;
	if (!buf->send_max && !buf->pipe)
		buf->flags |= BF_OUT_EMPTY;

	/* notify that some data was written to the SI from the buffer */
	buf->flags |= BF_WRITE_PARTIAL;
}

/*
 * Return one char from the buffer. If the buffer is empty and closed, return -1.
 * If the buffer is just empty, return -2. The buffer's pointer is not advanced,
 * it's up to the caller to call buffer_skip(buf, 1) when it has consumed the char.
 * Also note that this function respects the send_max limit.
 */
static inline int buffer_si_peekchar(struct buffer *buf)
{
	if (buf->send_max)
		return *buf->w;

	if (buf->flags & (BF_SHUTW|BF_SHUTW_NOW))
		return -1;
	else
		return -2;
}

/* Try to write character <c> into buffer <buf> after length controls. This
 * work like buffer_feed2(buf, &c, 1).
 * Returns non-zero in case of success, 0 if the buffer was full.
 * The send limit is automatically adjusted with the amount of data written.
 */
static inline int buffer_si_putchar(struct buffer *buf, char c)
{
	if (buf->flags & BF_FULL)
		return 0;

	*buf->r = c;

	buf->l++;
	if (buf->l >= buf->max_len)
		buf->flags |= BF_FULL;

	buf->r++;
	if (buf->r - buf->data == buf->size)
		buf->r -= buf->size;

	if (buf->to_forward >= 1) {
		if (buf->to_forward != BUF_INFINITE_FORWARD)
			buf->to_forward--;
		buf->send_max++;
		buf->flags &= ~BF_OUT_EMPTY;
	}

	buf->total++;
	return 1;
}

int buffer_write(struct buffer *buf, const char *msg, int len);
int buffer_feed2(struct buffer *buf, const char *str, int len);
int buffer_si_putchar(struct buffer *buf, char c);
int buffer_si_peekline(struct buffer *buf, char *str, int len);
int buffer_replace(struct buffer *b, char *pos, char *end, const char *str);
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len);
int buffer_insert_line2(struct buffer *b, char *pos, const char *str, int len);
void buffer_dump(FILE *o, struct buffer *b, int from, int to);


/* writes the chunk <chunk> to buffer <buf>. Returns -1 in case of success,
 * -2 if it is larger than the buffer size, or the number of bytes available
 * otherwise. If the chunk has been written, its size is automatically reset
 * to zero. The send limit is automatically adjusted with the amount of data
 * written.
 */
static inline int buffer_write_chunk(struct buffer *buf, struct chunk *chunk)
{
	int ret;

	ret = buffer_write(buf, chunk->str, chunk->len);
	if (ret == -1)
		chunk->len = 0;
	return ret;
}

/* Try to write chunk <chunk> into buffer <buf> after length controls. This is
 * the equivalent of buffer_write_chunk() except that to_forward and send_max
 * are updated and that max_len is respected. Returns -1 in case of success,
 * -2 if it is larger than the buffer size, or the number of bytes available
 * otherwise. If the chunk has been written, its size is automatically reset
 * to zero. The send limit is automatically adjusted with the amount of data
 * written.
 */
static inline int buffer_feed_chunk(struct buffer *buf, struct chunk *chunk)
{
	int ret;

	ret = buffer_feed2(buf, chunk->str, chunk->len);
	if (ret == -1)
		chunk->len = 0;
	return ret;
}

/* Try to write string <str> into buffer <buf> after length controls. This is
 * the equivalent of buffer_feed2() except that string length is measured by
 * the function. Returns -1 in case of success, -2 if it is larger than the
 * buffer size, or the number of bytes available otherwise. The send limit is
 * automatically adjusted with the amount of data written.
 */
static inline int buffer_feed(struct buffer *buf, const char *str)
{
	return buffer_feed2(buf, str, strlen(str));
}

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
