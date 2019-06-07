/*
 * Chunk management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/chunk.h>
#include <common/standard.h>

#include <types/global.h>

/* trash chunks used for various conversions */
static THREAD_LOCAL struct buffer *trash_chunk;
static THREAD_LOCAL struct buffer trash_chunk1;
static THREAD_LOCAL struct buffer trash_chunk2;

/* trash buffers used for various conversions */
static int trash_size;
static THREAD_LOCAL char *trash_buf1;
static THREAD_LOCAL char *trash_buf2;

/* the trash pool for reentrant allocations */
struct pool_head *pool_head_trash = NULL;

/* this is used to drain data, and as a temporary buffer for sprintf()... */
THREAD_LOCAL struct buffer trash = { };

/*
* Returns a pre-allocated and initialized trash chunk that can be used for any
* type of conversion. Two chunks and their respective buffers are alternatively
* returned so that it is always possible to iterate data transformations without
* losing the data being transformed. The blocks are initialized to the size of
* a standard buffer, so they should be enough for everything. For convenience,
* a zero is always emitted at the beginning of the string so that it may be
* used as an empty string as well.
*/
struct buffer *get_trash_chunk(void)
{
	char *trash_buf;

	if (trash_chunk == &trash_chunk1) {
		trash_chunk = &trash_chunk2;
		trash_buf = trash_buf2;
	}
	else {
		trash_chunk = &trash_chunk1;
		trash_buf = trash_buf1;
	}
	*trash_buf = 0;
	chunk_init(trash_chunk, trash_buf, trash_size);
	return trash_chunk;
}

/* (re)allocates the trash buffers. Returns 0 in case of failure. It is
 * possible to call this function multiple times if the trash size changes.
 */
static int alloc_trash_buffers(int bufsize)
{
	chunk_init(&trash, my_realloc2(trash.area, bufsize), bufsize);
	trash_size = bufsize;
	trash_buf1 = (char *)my_realloc2(trash_buf1, bufsize);
	trash_buf2 = (char *)my_realloc2(trash_buf2, bufsize);
	return trash.area && trash_buf1 && trash_buf2;
}

static int alloc_trash_buffers_per_thread()
{
	return alloc_trash_buffers(global.tune.bufsize);
}

static void free_trash_buffers_per_thread()
{
	chunk_destroy(&trash);
	free(trash_buf2);
	free(trash_buf1);
	trash_buf2 = NULL;
	trash_buf1 = NULL;
}

/* Initialize the trash buffers. It returns 0 if an error occurred. */
int init_trash_buffers(int first)
{
	pool_destroy(pool_head_trash);
	pool_head_trash = create_pool("trash",
				      sizeof(struct buffer) + global.tune.bufsize,
				      MEM_F_EXACT);
	if (!pool_head_trash || !alloc_trash_buffers(global.tune.bufsize))
		return 0;
	return 1;
}

/*
 * Allocate a trash chunk from the reentrant pool. The buffer starts at the
 * end of the chunk. This chunk must be freed using free_trash_chunk(). This
 * call may fail and the caller is responsible for checking that the returned
 * pointer is not NULL.
 */
struct buffer *alloc_trash_chunk(void)
{
	struct buffer *chunk;

	chunk = pool_alloc(pool_head_trash);
	if (chunk) {
		char *buf = (char *)chunk + sizeof(struct buffer);
		*buf = 0;
		chunk_init(chunk, buf,
			   pool_head_trash->size - sizeof(struct buffer));
	}
	return chunk;
}

/*
 * Does an snprintf() at the beginning of chunk <chk>, respecting the limit of
 * at most chk->size chars. If the chk->len is over, nothing is added. Returns
 * the new chunk size, or < 0 in case of failure.
 */
int chunk_printf(struct buffer *chk, const char *fmt, ...)
{
	va_list argp;
	int ret;

	if (!chk->area || !chk->size)
		return 0;

	va_start(argp, fmt);
	ret = vsnprintf(chk->area, chk->size, fmt, argp);
	va_end(argp);

	if (ret >= chk->size)
		return -1;

	chk->data = ret;
	return chk->data;
}

/*
 * Does an snprintf() at the end of chunk <chk>, respecting the limit of
 * at most chk->size chars. If the chk->len is over, nothing is added. Returns
 * the new chunk size.
 */
int chunk_appendf(struct buffer *chk, const char *fmt, ...)
{
	va_list argp;
	int ret;

	if (!chk->area || !chk->size)
		return 0;

	va_start(argp, fmt);
	ret = vsnprintf(chk->area + chk->data, chk->size - chk->data, fmt,
			argp);
	if (ret >= chk->size - chk->data)
		/* do not copy anything in case of truncation */
		chk->area[chk->data] = 0;
	else
		chk->data += ret;
	va_end(argp);
	return chk->data;
}

/*
 * Encode chunk <src> into chunk <dst>, respecting the limit of at most
 * chk->size chars. Replace non-printable or special chracters with "&#%d;".
 * If the chk->len is over, nothing is added. Returns the new chunk size.
 */
int chunk_htmlencode(struct buffer *dst, struct buffer *src)
{
	int i, l;
	int olen, free;
	char c;

	olen = dst->data;

	for (i = 0; i < src->data; i++) {
		free = dst->size - dst->data;

		if (!free) {
			dst->data = olen;
			return dst->data;
		}

		c = src->area[i];

		if (!isascii(c) || !isprint((unsigned char)c) || c == '&' || c == '"' || c == '\'' || c == '<' || c == '>') {
			l = snprintf(dst->area + dst->data, free, "&#%u;",
				     (unsigned char)c);

			if (free < l) {
				dst->data = olen;
				return dst->data;
			}

			dst->data += l;
		} else {
			dst->area[dst->data] = c;
			dst->data++;
		}
	}

	return dst->data;
}

/*
 * Encode chunk <src> into chunk <dst>, respecting the limit of at most
 * chk->size chars. Replace non-printable or char passed in qc with "<%02X>".
 * If the chk->len is over, nothing is added. Returns the new chunk size.
 */
int chunk_asciiencode(struct buffer *dst, struct buffer *src, char qc)
{
	int i, l;
	int olen, free;
	char c;

	olen = dst->data;

	for (i = 0; i < src->data; i++) {
		free = dst->size - dst->data;

		if (!free) {
			dst->data = olen;
			return dst->data;
		}

		c = src->area[i];

		if (!isascii(c) || !isprint((unsigned char)c) || c == '<' || c == '>' || c == qc) {
			l = snprintf(dst->area + dst->data, free, "<%02X>",
				     (unsigned char)c);

			if (free < l) {
				dst->data = olen;
				return dst->data;
			}

			dst->data += l;
		} else {
			dst->area[dst->data] = c;
			dst->data++;
		}
	}

	return dst->data;
}

/* Compares the string in chunk <chk> with the string in <str> which must be
 * zero-terminated. Return is the same as with strcmp(). Neither is allowed
 * to be null.
 */
int chunk_strcmp(const struct buffer *chk, const char *str)
{
	const char *s1 = chk->area;
	int len = chk->data;
	int diff = 0;

	do {
		if (--len < 0) {
			diff = (unsigned char)0 - (unsigned char)*str;
			break;
		}
		diff = (unsigned char)*(s1++) - (unsigned char)*(str++);
	} while (!diff);
	return diff;
}

/* Case-insensitively compares the string in chunk <chk> with the string in
 * <str> which must be zero-terminated. Return is the same as with strcmp().
 * Neither is allowed to be null.
 */
int chunk_strcasecmp(const struct buffer *chk, const char *str)
{
	const char *s1 = chk->area;
	int len = chk->data;
	int diff = 0;

	do {
		if (--len < 0) {
			diff = (unsigned char)0 - (unsigned char)*str;
			break;
		}
		diff = (unsigned char)*s1 - (unsigned char)*str;
		if (unlikely(diff)) {
			unsigned int l = (unsigned char)*s1;
			unsigned int r = (unsigned char)*str;

			l -= 'a';
			r -= 'a';

			if (likely(l <= (unsigned char)'z' - 'a'))
				l -= 'a' - 'A';
			if (likely(r <= (unsigned char)'z' - 'a'))
				r -= 'a' - 'A';
			diff = l - r;
		}
		s1++; str++;
	} while (!diff);
	return diff;
}

REGISTER_PER_THREAD_ALLOC(alloc_trash_buffers_per_thread);
REGISTER_PER_THREAD_FREE(free_trash_buffers_per_thread);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
