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

/* Initializes all fields in the buffer. The ->rlim field is initialized last
 * so that the compiler can optimize it away if changed immediately after the
 * call to this function. By default, it is set to the full size of the buffer.
 * The BF_EMPTY flags is set.
 */
static inline void buffer_init(struct buffer *buf)
{
	buf->l = buf->total = 0;
	buf->analysers = 0;
	buf->cons = NULL;
	buf->flags = BF_EMPTY;
	buf->r = buf->lr = buf->w = buf->data;
	buf->rlim = buf->data + BUFSIZE;
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

/* flushes any content from buffer <buf> and adjusts flags
 * accordingly.
 */
static inline void buffer_flush(struct buffer *buf)
{
	buf->r = buf->lr = buf->w = buf->data;
	buf->l = 0;
	buf->flags |= BF_EMPTY | BF_FULL;
	if (buf->rlim)
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

/* set the buffer to hijacking mode */
static inline void buffer_start_hijack(struct buffer *buf)
{
	buf->flags |= BF_HIJACK;
}

/* releases the buffer from hijacking mode */
static inline void buffer_stop_hijack(struct buffer *buf)
{
	buf->flags &= ~BF_HIJACK;
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
	buf->rlim = buf->data + size;
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
