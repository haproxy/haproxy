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

/* Structure defining a buffer's head */
struct buffer {
	char *p;                    /* buffer's start pointer, separates in and out data */
	size_t size;                /* buffer size in bytes */
	size_t i;                   /* number of input bytes pending for analysis in the buffer */
	size_t o;                   /* number of out bytes the sender can consume from this buffer */
	char data[0];               /* <size> bytes of stored data */
};


/***************************************************************************/
/* Functions used to compute offsets and pointers. Most of them exist in   */
/* both wrapping-safe and unchecked ("__" prefix) variants. Some returning */
/* a pointer are also provided with an "_ofs" suffix when they return an   */
/* offset relative to the storage area.                                    */
/***************************************************************************/

/* b_orig() : returns the pointer to the origin of the storage, which is the
 * location of byte at offset zero. This is mostly used by functions which
 * handle the wrapping by themselves.
 */
static inline char *b_orig(const struct buffer *b)
{
	return (char *)b->data;
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
	return (char *)b->data + b->size;
}

/* b_data() : returns the number of bytes present in the buffer. */
static inline size_t b_data(const struct buffer *b)
{
	return b->i + b->o;
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
	return b->p - b->data + b->i;
}

static inline const char *__b_stop(const struct buffer *b)
{
	return b->p + b->i;
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
	return b->data + b_stop_ofs(b);
}


/* b_peek() : returns a pointer to the data at position <ofs> relative to the
 * head of the buffer. Will typically point to input data if called with the
 * amount of output data. The wrapped versions will only support wrapping once
 * before the beginning or after the end.
 */
static inline size_t __b_peek_ofs(const struct buffer *b, size_t ofs)
{
	return b->p - b->data + ofs - b->o;
}

static inline char *__b_peek(const struct buffer *b, size_t ofs)
{
	return b->p - b->o + ofs;
}

static inline size_t b_peek_ofs(const struct buffer *b, size_t ofs)
{
	size_t ret = __b_peek_ofs(b, ofs);

	if (ret >= b->size) {
		/* wraps either up or down */
		if ((ssize_t)ret < 0)
			ret += b->size;
		else
			ret -= b->size;
	}

	return ret;
}

static inline char *b_peek(const struct buffer *b, size_t ofs)
{
	return (char *)b->data + b_peek_ofs(b, ofs);
}


/* b_head() : returns the pointer to the buffer's head, which is the location
 * of the next byte to be dequeued. Note that for buffers of size zero, the
 * returned pointer may be outside of the buffer or even invalid.
 */
static inline size_t __b_head_ofs(const struct buffer *b)
{
	return __b_peek_ofs(b, 0);
}

static inline char *__b_head(const struct buffer *b)
{
	return __b_peek(b, 0);
}

static inline size_t b_head_ofs(const struct buffer *b)
{
	return b_peek_ofs(b, 0);
}

static inline char *b_head(const struct buffer *b)
{
	return b_peek(b, 0);
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


/*********************************************/
/* Functions used to modify the buffer state */
/*********************************************/

/* b_reset() : resets a buffer. The size is not touched. */
static inline void b_reset(struct buffer *b)
{
	b->o = 0;
	b->i = 0;
	b->p = b_orig(b);
}


#endif /* _COMMON_BUF_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
