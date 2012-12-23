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

#include <common/config.h>


/* describes a chunk of string */
struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int size;	/* total size of the buffer, 0 if the *str is read-only */
	int len;	/* current size of the string from first to last char. <0 = uninit. */
};

/* function prototypes */

int chunk_printf(struct chunk *chk, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));

int chunk_appendf(struct chunk *chk, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));

int chunk_htmlencode(struct chunk *dst, struct chunk *src);
int chunk_asciiencode(struct chunk *dst, struct chunk *src, char qc);
int chunk_strcmp(const struct chunk *chk, const char *str);
int chunk_strcasecmp(const struct chunk *chk, const char *str);
int alloc_trash_buffers(int bufsize);
struct chunk *get_trash_chunk(void);

static inline void chunk_reset(struct chunk *chk)
{
	chk->len  = 0;
}

static inline void chunk_init(struct chunk *chk, char *str, size_t size)
{
	chk->str  = str;
	chk->len  = 0;
	chk->size = size;
}

/* report 0 in case of error, 1 if OK. */
static inline int chunk_initlen(struct chunk *chk, char *str, size_t size, int len)
{

	if (size && len > size)
		return 0;

	chk->str  = str;
	chk->len  = len;
	chk->size = size;

	return 1;
}

static inline void chunk_initstr(struct chunk *chk, char *str)
{
	chk->str = str;
	chk->len = strlen(str);
	chk->size = 0;			/* mark it read-only */
}

static inline int chunk_strcpy(struct chunk *chk, const char *str)
{
	size_t len;

	len = strlen(str);

	if (unlikely(len > chk->size))
		return 0;

	chk->len  = len;
	memcpy(chk->str, str, len);

	return 1;
}

static inline void chunk_drop(struct chunk *chk)
{
	chk->str  = NULL;
	chk->len  = -1;
	chk->size = 0;
}

static inline void chunk_destroy(struct chunk *chk)
{
	if (!chk->size)
		return;

	free(chk->str);
	chunk_drop(chk);
}

/*
 * frees the destination chunk if already allocated, allocates a new string,
 * and copies the source into it. The pointer to the destination string is
 * returned, or NULL if the allocation fails or if any pointer is NULL..
 */
static inline char *chunk_dup(struct chunk *dst, const struct chunk *src)
{
	if (!dst || !src || !src->str)
		return NULL;
	if (dst->str)
		free(dst->str);
	dst->len = src->len;
	dst->str = (char *)malloc(dst->len);
	memcpy(dst->str, src->str, dst->len);
	return dst->str;
}

#endif /* _TYPES_CHUNK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
