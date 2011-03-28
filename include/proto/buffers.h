/*
 * include/proto/buffers.h
 * Buffer management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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
int buffer_write(struct buffer *buf, const char *msg, int len);
int buffer_put_block(struct buffer *buf, const char *str, int len);
int buffer_put_char(struct buffer *buf, char c);
int buffer_get_line(struct buffer *buf, char *str, int len);
int buffer_get_block(struct buffer *buf, char *blk, int len, int offset);
int buffer_replace(struct buffer *b, char *pos, char *end, const char *str);
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len);
int buffer_insert_line2(struct buffer *b, char *pos, const char *str, int len);
void buffer_dump(FILE *o, struct buffer *b, int from, int to);
void buffer_bounce_realign(struct buffer *buf);
unsigned long long buffer_forward(struct buffer *buf, unsigned long long bytes);

/* Initialize all fields in the buffer. The BF_OUT_EMPTY flags is set. */
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
}

/* Return the max number of bytes the buffer can contain so that once all the
 * pending bytes are forwarded, the buffer still has global.tune.maxrewrite
 * bytes free. The result sits between buf->size - maxrewrite and buf->size.
 */
static inline int buffer_max_len(struct buffer *buf)
{
	if (buf->to_forward == BUF_INFINITE_FORWARD ||
	    buf->to_forward + buf->send_max >= global.tune.maxrewrite)
		return buf->size;
	else
		return buf->size - global.tune.maxrewrite + buf->to_forward + buf->send_max;
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
	if (buf->l >= buffer_max_len(buf))
		buf->flags |= BF_FULL;
}

/* Cut the <n> next unsent bytes of the buffer. The caller must ensure that <n>
 * is smaller than the actual buffer's length. This is mainly used to remove
 * empty lines at the beginning of a request or a response.
 */
static inline void buffer_ignore(struct buffer *buf, int n)
{
	buf->l -= n;
	buf->w += n;
	if (buf->w >= buf->data + buf->size)
		buf->w -= buf->size;
	buf->flags &= ~BF_FULL;
	if (buf->l >= buffer_max_len(buf))
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
 * Return the maximum amount of bytes that can be written into the buffer in
 * one call to buffer_put_*().
 */
static inline int buffer_free_space(struct buffer *buf)
{
	return buffer_max_len(buf) - buf->l;
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
		ret = buffer_max_len(buf);
	}
	else if (buf->r > buf->w) {
		ret = buf->data + buffer_max_len(buf) - buf->r;
	}
	else {
		ret = buf->w - buf->r;
		if (ret > buffer_max_len(buf))
			ret = buffer_max_len(buf);
	}
	return ret;
}

/*
 * Same as above but the caller may pass the value of buffer_max_len(buf) if it
 * knows it, thus avoiding some calculations.
 */
static inline int buffer_contig_space_with_len(struct buffer *buf, int maxlen)
{
	int ret;

	if (buf->l == 0) {
		buf->r = buf->w = buf->lr = buf->data;
		ret = maxlen;
	}
	else if (buf->r > buf->w) {
		ret = buf->data + maxlen - buf->r;
	}
	else {
		ret = buf->w - buf->r;
		if (ret > maxlen)
			ret = maxlen;
	}
	return ret;
}

/* Return 1 if the buffer has less than 1/4 of its capacity free, otherwise 0 */
static inline int buffer_almost_full(struct buffer *buf)
{
	if (buffer_free_space(buf) < buf->size / 4)
		return 1;
	return 0;
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

	if (buf->l < buffer_max_len(buf))
		buf->flags &= ~BF_FULL;

	buf->send_max -= len;
	if (!buf->send_max && !buf->pipe)
		buf->flags |= BF_OUT_EMPTY;

	/* notify that some data was written to the SI from the buffer */
	buf->flags |= BF_WRITE_PARTIAL;
}

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

/* Tries to copy chunk <chunk> into buffer <buf> after length controls.
 * The send_max and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Buffer flags FULL, EMPTY and READ_PARTIAL are updated if some data can be
 * transferred. The chunk's length is updated with the number of bytes sent.
 */
static inline int buffer_put_chunk(struct buffer *buf, struct chunk *chunk)
{
	int ret;

	ret = buffer_put_block(buf, chunk->str, chunk->len);
	if (ret > 0)
		chunk->len -= ret;
	return ret;
}

/* Tries to copy string <str> at once into buffer <buf> after length controls.
 * The send_max and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Buffer flags FULL, EMPTY and READ_PARTIAL are updated if some data can be
 * transferred.
 */
static inline int buffer_put_string(struct buffer *buf, const char *str)
{
	return buffer_put_block(buf, str, strlen(str));
}

/*
 * Return one char from the buffer. If the buffer is empty and closed, return -2.
 * If the buffer is just empty, return -1. The buffer's pointer is not advanced,
 * it's up to the caller to call buffer_skip(buf, 1) when it has consumed the char.
 * Also note that this function respects the send_max limit.
 */
static inline int buffer_get_char(struct buffer *buf)
{
	/* closed or empty + imminent close = -2; empty = -1 */
	if (unlikely(buf->flags & (BF_OUT_EMPTY|BF_SHUTW))) {
		if (buf->flags & (BF_SHUTW|BF_SHUTW_NOW))
			return -2;
		return -1;
	}
	return *buf->w;
}


/* DEPRECATED, just provided for compatibility, use buffer_put_chunk() instead !!!
 * returns >= 0 if the buffer is too small to hold the message, -1 if the
 * transfer was OK, -2 in case of failure.
 */
static inline int buffer_feed_chunk(struct buffer *buf, struct chunk *msg)
{
	int ret = buffer_put_chunk(buf, msg);
	if (ret >= 0) /* transfer OK */
		return -1;
	if (ret == -1) /* missing room */
		return 1;
	/* failure */
	return -2;
}

/* DEPRECATED, just provided for compatibility, use buffer_put_string() instead !!!
 * returns >= 0 if the buffer is too small to hold the message, -1 if the
 * transfer was OK, -2 in case of failure.
 */
static inline int buffer_feed(struct buffer *buf, const char *str)
{
	int ret = buffer_put_string(buf, str);
	if (ret >= 0) /* transfer OK */
		return -1;
	if (ret == -1) /* missing room */
		return 1;
	/* failure */
	return -2;
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
