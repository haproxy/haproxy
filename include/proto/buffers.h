/*
  include/proto/buffers.h
  Buffer management definitions, macros and inline functions.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu

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
 * The BF_EMPTY flags is set.
 */
static inline void buffer_init(struct buffer *buf)
{
	buf->send_max = 0;
	buf->to_forward = 0;
	buf->l = buf->total = 0;
	buf->pipe = NULL;
	buf->analysers = 0;
	buf->cons = NULL;
	buf->flags = BF_EMPTY;
	buf->r = buf->lr = buf->w = buf->data;
	buf->max_len = BUFSIZE;
}

/* returns 1 if the buffer is empty, 0 otherwise */
static inline int buffer_isempty(const struct buffer *buf)
{
	return buf->l == 0;
}

/* returns 1 if the buffer is full, 0 otherwise */
static inline int buffer_isfull(const struct buffer *buf) {
	return buf->l == BUFSIZE;
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
static inline void buffer_forward(struct buffer *buf, unsigned int bytes)
{
	unsigned int data_left;

	buf->to_forward += bytes;
	data_left = buf->l - buf->send_max;
	if (data_left > buf->to_forward)
		data_left = buf->to_forward;

	buf->to_forward -= data_left;
	buf->send_max += data_left;
}

/* Flush any content from buffer <buf> and adjusts flags accordingly. Note
 * that any spliced data is not affected since we may not have any access to
 * it.
 */
static inline void buffer_flush(struct buffer *buf)
{
	buf->send_max = 0;
	buf->to_forward = 0;
	buf->r = buf->lr = buf->w = buf->data;
	buf->l = 0;
	buf->flags |= BF_EMPTY | BF_FULL;
	if (buf->max_len)
		buf->flags &= ~BF_FULL;
}

/* marks the buffer as "shutdown" for reads and cancels the timeout */
static inline void buffer_shutr(struct buffer *buf)
{
	buf->rex = TICK_ETERNITY;
	buf->flags |= BF_SHUTR;
}

/* marks the buffer as "shutdown" for writes and cancels the timeout */
static inline void buffer_shutw(struct buffer *buf)
{
	buf->wex = TICK_ETERNITY;
	buf->flags |= BF_SHUTW;
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

/* allows the consumer to send the buffer contents */
static inline void buffer_write_ena(struct buffer *buf)
{
	buf->flags |= BF_WRITE_ENA;
}

/* prevents the consumer from sending the buffer contents */
static inline void buffer_write_dis(struct buffer *buf)
{
	buf->flags &= ~BF_WRITE_ENA;
}

/* check if the buffer needs to be shut down for read, and perform the shutdown
 * at the stream_interface level if needed. This must not be used with a buffer
 * for which a connection is currently in queue or turn-around.
 */
static inline void buffer_check_shutr(struct buffer *b)
{
	if (b->flags & BF_SHUTR)
		return;

	if (!(b->flags & (BF_SHUTR_NOW|BF_SHUTW)))
		return;

	/* Last read, forced read-shutdown, or other end closed. We have to
	 * close our read side and inform the stream_interface.
	 */
	b->prod->shutr(b->prod);
}

/* check if the buffer needs to be shut down for write, and perform the shutdown
 * at the stream_interface level if needed. This must not be used with a buffer
 * for which a connection is currently in queue or turn-around.
 */
static inline void buffer_check_shutw(struct buffer *b)
{
	if (b->flags & BF_SHUTW)
		return;

	if ((b->flags & BF_SHUTW_NOW) ||
	    (b->flags & (BF_EMPTY|BF_HIJACK|BF_WRITE_ENA|BF_SHUTR)) ==
	    (BF_EMPTY|BF_WRITE_ENA|BF_SHUTR)) {
		/* Application requested write-shutdown, or other end closed
		 * with empty buffer. We have to close our write side and
		 * inform the stream_interface.
		 */
		b->cons->shutw(b->cons);
	}
}

/* returns the maximum number of bytes writable at once in this buffer */
static inline int buffer_max(const struct buffer *buf)
{
	if (buf->l == BUFSIZE)
		return 0;
	else if (buf->r >= buf->w)
		return buf->data + BUFSIZE - buf->r;
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


int buffer_write(struct buffer *buf, const char *msg, int len);
int buffer_write_chunk(struct buffer *buf, struct chunk *chunk);
int buffer_replace(struct buffer *b, char *pos, char *end, const char *str);
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len);
int buffer_insert_line2(struct buffer *b, char *pos, const char *str, int len);
int chunk_printf(struct chunk *chk, int size, const char *fmt, ...);
void buffer_dump(FILE *o, struct buffer *b, int from, int to);

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
