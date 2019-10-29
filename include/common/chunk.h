/*
 * include/common/chunk.h
 * Chunk management definitions, macros and inline functions.
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

#ifndef _TYPES_CHUNK_H
#define _TYPES_CHUNK_H

#include <stdlib.h>
#include <string.h>

#include <common/buf.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/memory.h>


extern struct pool_head *pool_head_trash;

/* function prototypes */

int chunk_printf(struct buffer *chk, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));

int chunk_appendf(struct buffer *chk, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));

int chunk_htmlencode(struct buffer *dst, struct buffer *src);
int chunk_asciiencode(struct buffer *dst, struct buffer *src, char qc);
int chunk_strcmp(const struct buffer *chk, const char *str);
int chunk_strcasecmp(const struct buffer *chk, const char *str);
struct buffer *get_trash_chunk(void);
struct buffer *alloc_trash_chunk(void);
int init_trash_buffers(int first);

/*
 * free a trash chunk allocated by alloc_trash_chunk(). NOP on NULL.
 */
static inline void free_trash_chunk(struct buffer *chunk)
{
	pool_free(pool_head_trash, chunk);
}


static inline void chunk_reset(struct buffer *chk)
{
	chk->data  = 0;
}

static inline void chunk_init(struct buffer *chk, char *str, size_t size)
{
	chk->area = str;
	chk->head = 0;
	chk->data = 0;
	chk->size = size;
}

/* report 0 in case of error, 1 if OK. */
static inline int chunk_initlen(struct buffer *chk, char *str, size_t size,
				int len)
{

	if (len < 0 || (size && len > size))
		return 0;

	chk->area = str;
	chk->head = 0;
	chk->data = len;
	chk->size = size;

	return 1;
}

/* this is only for temporary manipulation, the chunk is read-only */
static inline void chunk_initstr(struct buffer *chk, const char *str)
{
	chk->area = (char *)str;
	chk->head = 0;
	chk->data = strlen(str);
	chk->size = 0;			/* mark it read-only */
}

/* copies chunk <src> into <chk>. Returns 0 in case of failure. */
static inline int chunk_cpy(struct buffer *chk, const struct buffer *src)
{
	if (unlikely(src->data > chk->size))
		return 0;

	chk->data  = src->data;
	memcpy(chk->area, src->area, src->data);
	return 1;
}

/* appends chunk <src> after <chk>. Returns 0 in case of failure. */
static inline int chunk_cat(struct buffer *chk, const struct buffer *src)
{
	if (unlikely(chk->data + src->data > chk->size))
		return 0;

	memcpy(chk->area + chk->data, src->area, src->data);
	chk->data += src->data;
	return 1;
}

/* appends ist <src> after <chk>. Returns 0 in case of failure. */
static inline int chunk_istcat(struct buffer *chk, const struct ist src)
{
	if (unlikely(chk->data + src.len > chk->size))
		return 0;

	memcpy(chk->area + chk->data, src.ptr, src.len);
	chk->data += src.len;
	return 1;
}

/* copies memory area <src> into <chk> for <len> bytes. Returns 0 in
 * case of failure. No trailing zero is added.
 */
static inline int chunk_memcpy(struct buffer *chk, const char *src,
			       size_t len)
{
	if (unlikely(len > chk->size))
		return 0;

	chk->data  = len;
	memcpy(chk->area, src, len);

	return 1;
}

/* appends memory area <src> after <chk> for <len> bytes. Returns 0 in
 * case of failure. No trailing zero is added.
 */
static inline int chunk_memcat(struct buffer *chk, const char *src,
			       size_t len)
{
	if (unlikely(chk->data + len > chk->size))
		return 0;

	memcpy(chk->area + chk->data, src, len);
	chk->data += len;
	return 1;
}

/* copies str into <chk> followed by a trailing zero. Returns 0 in
 * case of failure.
 */
static inline int chunk_strcpy(struct buffer *chk, const char *str)
{
	size_t len;

	len = strlen(str);

	if (unlikely(len >= chk->size))
		return 0;

	chk->data  = len;
	memcpy(chk->area, str, len + 1);

	return 1;
}

/* appends str after <chk> followed by a trailing zero. Returns 0 in
 * case of failure.
 */
static inline int chunk_strcat(struct buffer *chk, const char *str)
{
	size_t len;

	len = strlen(str);

	if (unlikely(chk->data + len >= chk->size))
		return 0;

	memcpy(chk->area + chk->data, str, len + 1);
	chk->data += len;
	return 1;
}

/* appends <nb> characters from str after <chk>.
 * Returns 0 in case of failure.
 */
static inline int chunk_strncat(struct buffer *chk, const char *str, int nb)
{
	if (unlikely(chk->data + nb >= chk->size))
		return 0;

	memcpy(chk->area + chk->data, str, nb);
	chk->data += nb;
	return 1;
}

/* Adds a trailing zero to the current chunk and returns the pointer to the
 * following part. The purpose is to be able to use a chunk as a series of
 * short independent strings with chunk_* functions, which do not need to be
 * released. Returns NULL if no space is available to ensure that the new
 * string will have its own trailing zero. For example :
 *   chunk_init(&trash);
 *   pid = chunk_newstr(&trash);
 *   chunk_appendf(&trash, "%d", getpid()));
 *   name = chunk_newstr(&trash);
 *   chunk_appendf(&trash, "%s", gethosname());
 *   printf("hostname=<%s>, pid=<%d>\n", name, pid);
 */
static inline char *chunk_newstr(struct buffer *chk)
{
	if (chk->data + 1 >= chk->size)
		return NULL;

	chk->area[chk->data++] = 0;
	return chk->area + chk->data;
}

static inline void chunk_drop(struct buffer *chk)
{
	chk->area  = NULL;
	chk->data  = -1;
	chk->size = 0;
}

static inline void chunk_destroy(struct buffer *chk)
{
	if (!chk->size)
		return;

	free(chk->area);
	chunk_drop(chk);
}

/*
 * frees the destination chunk if already allocated, allocates a new string,
 * and copies the source into it. The new chunk will have extra room for a
 * trailing zero unless the source chunk was actually full. The pointer to
 * the destination string is returned, or NULL if the allocation fails or if
 * any pointer is NULL.
 */
static inline char *chunk_dup(struct buffer *dst, const struct buffer *src)
{
	if (!dst || !src || !src->area)
		return NULL;

	if (dst->size)
		free(dst->area);
	dst->head = src->head;
	dst->data = src->data;
	dst->size = src->data;
	if (dst->size < src->size || !src->size)
		dst->size++;

	dst->area = (char *)malloc(dst->size);
	if (!dst->area) {
		dst->head = 0;
		dst->data = 0;
		dst->size = 0;
		return NULL;
	}

	memcpy(dst->area, src->area, dst->data);
	if (dst->data < dst->size)
		dst->area[dst->data] = 0;

	return dst->area;
}

#endif /* _TYPES_CHUNK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
