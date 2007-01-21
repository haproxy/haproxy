/*
  include/proto/buffers.h
  Buffer management definitions, macros and inline functions.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#include <stdlib.h>

#include <common/config.h>
#include <types/buffers.h>

/* Initializes all fields in the buffer. The ->rlim field is initialized last
 * so that the compiler can optimize it away if changed immediately after the
 * call to this function.
 */
static inline void buffer_init(struct buffer *buf)
{
	buf->l = buf->total = buf->flags = 0;
	buf->rlim = buf->h = buf->r = buf->lr = buf->w = buf->data;
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

/* flushes any content from buffer <buf> */
static inline void buffer_flush(struct buffer *buf)
{
	buf->r = buf->h = buf->lr = buf->w = buf->data;
	buf->l = 0;
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


/*
 * Tries to realign the given buffer, and returns how many bytes can be written
 * there at once without overwriting anything.
 */
static inline int buffer_realign(struct buffer *buf)
{
	if (buf->l == 0) {
		/* let's realign the buffer to optimize I/O */
		buf->r = buf->w = buf->h = buf->lr = buf->data;
	}
	return buffer_max(buf);
}


int buffer_write(struct buffer *buf, const char *msg, int len);
int buffer_write_chunk(struct buffer *buf, struct chunk *chunk);
int buffer_replace(struct buffer *b, char *pos, char *end, char *str);
int buffer_replace2(struct buffer *b, char *pos, char *end, char *str, int len);
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
