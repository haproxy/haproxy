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

/* trash chunks used for various conversions */
static struct chunk *trash_chunk;
static struct chunk trash_chunk1;
static struct chunk trash_chunk2;

/* trash buffers used for various conversions */
static int trash_size;
static char *trash_buf1;
static char *trash_buf2;

/*
* Returns a pre-allocated and initialized trash chunk that can be used for any
* type of conversion. Two chunks and their respective buffers are alternatively
* returned so that it is always possible to iterate data transformations without
* losing the data being transformed. The blocks are initialized to the size of
* a standard buffer, so they should be enough for everything. For convenience,
* a zero is always emitted at the beginning of the string so that it may be
* used as an empty string as well.
*/
struct chunk *get_trash_chunk(void)
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
int alloc_trash_buffers(int bufsize)
{
	trash_size = bufsize;
	trash_buf1 = (char *)realloc(trash_buf1, bufsize);
	trash_buf2 = (char *)realloc(trash_buf2, bufsize);
	return trash_buf1 && trash_buf2;
}

/*
 * Does an snprintf() at the beginning of chunk <chk>, respecting the limit of
 * at most chk->size chars. If the chk->len is over, nothing is added. Returns
 * the new chunk size, or < 0 in case of failure.
 */
int chunk_printf(struct chunk *chk, const char *fmt, ...)
{
	va_list argp;
	int ret;

	if (!chk->str || !chk->size)
		return 0;

	va_start(argp, fmt);
	ret = vsnprintf(chk->str, chk->size, fmt, argp);
	va_end(argp);
	chk->len = ret;

	if (ret >= chk->size)
		ret = -1;

	chk->len = ret;
	return chk->len;
}

/*
 * Does an snprintf() at the end of chunk <chk>, respecting the limit of
 * at most chk->size chars. If the chk->len is over, nothing is added. Returns
 * the new chunk size.
 */
int chunk_appendf(struct chunk *chk, const char *fmt, ...)
{
	va_list argp;
	int ret;

	if (!chk->str || !chk->size)
		return 0;

	va_start(argp, fmt);
	ret = vsnprintf(chk->str + chk->len, chk->size - chk->len, fmt, argp);
	if (ret >= chk->size - chk->len)
		/* do not copy anything in case of truncation */
		chk->str[chk->len] = 0;
	else
		chk->len += ret;
	va_end(argp);
	return chk->len;
}

/*
 * Encode chunk <src> into chunk <dst>, respecting the limit of at most
 * chk->size chars. Replace non-printable or special chracters with "&#%d;".
 * If the chk->len is over, nothing is added. Returns the new chunk size.
 */
int chunk_htmlencode(struct chunk *dst, struct chunk *src)
{
	int i, l;
	int olen, free;
	char c;

	olen = dst->len;

	for (i = 0; i < src->len; i++) {
		free = dst->size - dst->len;

		if (!free) {
			dst->len = olen;
			return dst->len;
		}

		c = src->str[i];

		if (!isascii(c) || !isprint((unsigned char)c) || c == '&' || c == '"' || c == '\'' || c == '<' || c == '>') {
			l = snprintf(dst->str + dst->len, free, "&#%u;", (unsigned char)c);

			if (free < l) {
				dst->len = olen;
				return dst->len;
			}

			dst->len += l;
		} else {
			dst->str[dst->len] = c;
			dst->len++;
		}
	}

	return dst->len;
}

/*
 * Encode chunk <src> into chunk <dst>, respecting the limit of at most
 * chk->size chars. Replace non-printable or char passed in qc with "<%02X>".
 * If the chk->len is over, nothing is added. Returns the new chunk size.
 */
int chunk_asciiencode(struct chunk *dst, struct chunk *src, char qc)
{
	int i, l;
	int olen, free;
	char c;

	olen = dst->len;

	for (i = 0; i < src->len; i++) {
		free = dst->size - dst->len;

		if (!free) {
			dst->len = olen;
			return dst->len;
		}

		c = src->str[i];

		if (!isascii(c) || !isprint((unsigned char)c) || c == '<' || c == '>' || c == qc) {
			l = snprintf(dst->str + dst->len, free, "<%02X>", (unsigned char)c);

			if (free < l) {
				dst->len = olen;
				return dst->len;
			}

			dst->len += l;
		} else {
			dst->str[dst->len] = c;
			dst->len++;
		}
	}

	return dst->len;
}

/* Compares the string in chunk <chk> with the string in <str> which must be
 * zero-terminated. Return is the same as with strcmp(). Neither is allowed
 * to be null.
 */
int chunk_strcmp(const struct chunk *chk, const char *str)
{
	const char *s1 = chk->str;
	int len = chk->len;
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
int chunk_strcasecmp(const struct chunk *chk, const char *str)
{
	const char *s1 = chk->str;
	int len = chk->len;
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
