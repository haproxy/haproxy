/*
 * include/common/ist.h
 * Very simple indirect string manipulation functions.
 *
 * Copyright (C) 2014-2017 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_IST_H
#define _COMMON_IST_H

#include <string.h>

#include <common/config.h>

/* This string definition will most often be used to represent a read-only
 * string returned from a function, based on the starting point and its length
 * in bytes. No storage is provided, only a pointer and a length. The types
 * here are important as we only want to have 2 native machine words there so
 * that on modern architectures the compiler is capable of efficiently
 * returning a register pair without having to allocate stack room from the
 * caller. This is done with -freg-struct which is often enabled by default.
 */
struct ist {
	char  *ptr;
	size_t len;
};

/* makes a constant ist from a constant string, for use in array declarations */
#define IST(str) { .ptr = str "", .len = (sizeof str "") - 1 }

/* makes an ist from a regular zero terminated string. Null has length 0.
 * Constants are detected and replaced with constant initializers. Other values
 * are measured by hand without strlen() as it's much cheaper and inlinable on
 * small strings. The construct is complex because we must never call
 * __builtin_strlen() with an expression otherwise it involves a real
 * measurement.
 */
#if __GNUC__ >= 4
// gcc >= 4 detects constant propagation of str through __x and resolves the
// length of constant strings easily.
#define ist(str) ({                                                    \
	char *__x = (void *)(str);                                     \
	(struct ist){                                                  \
		.ptr = __x,                                            \
		.len = __builtin_constant_p(str) ?                     \
			((void *)str == (void *)0) ? 0 :               \
			__builtin_strlen(__x) :                        \
			({                                             \
				size_t __l = 0;                        \
				if (__x) for (__l--; __x[++__l]; ) ;   \
				__l;                                   \
			})                                             \
	};                                                             \
})
#else
// gcc < 4 can't do this, and the side effect is a warning each time a NULL is
// passed to ist() due to the check on __builtin_strlen(). It doesn't have the
// ability to know that this code is never called.
#define ist(str) ({                                                    \
	char *__x = (void *)(str);                                     \
	(struct ist){                                                  \
		.ptr = __x,                                            \
		.len = __builtin_constant_p(str) ?                     \
			((void *)str == (void *)0) ? 0 :               \
			__builtin_strlen(str) :                        \
			({                                             \
				size_t __l = 0;                        \
				if (__x) for (__l--; __x[++__l]; ) ;   \
				__l;                                   \
			})                                             \
	};                                                             \
})
#endif

/* makes an ist struct from a string and a length */
static inline struct ist ist2(const void *ptr, size_t len)
{
	return (struct ist){ .ptr = (char *)ptr, .len = len };
}

/* This function MODIFIES the string to add a zero AFTER the end, and returns
 * the start pointer. The purpose is to use it on strings extracted by parsers
 * from larger strings cut with delimiters that are not important and can be
 * destroyed. It allows any such string to be used with regular string
 * functions. It's also convenient to use with printf() to show data extracted
 * from writable areas. The caller is obviously responsible for ensuring that
 * the string is valid and that the first byte past the end is writable. If
 * these conditions cannot be satisfied, use istpad() below instead.
 */
static inline char *ist0(struct ist ist)
{
	ist.ptr[ist.len] = 0;
	return ist.ptr;
}

/* returns the length of the string */
static inline size_t istlen(const struct ist ist)
{
	return ist.len;
}

/* skips to next character in the string, always stops at the end */
static inline struct ist istnext(const struct ist ist)
{
	struct ist ret = ist;

	if (ret.len) {
		ret.len--;
		ret.ptr++;
	}
	return ret;
}

/* copies the contents from string <ist> to buffer <buf> and adds a trailing
 * zero. The caller must ensure <buf> is large enough.
 */
static inline struct ist istpad(void *buf, const struct ist ist)
{
	struct ist ret = { .ptr = buf, .len = ist.len };

	for (ret.len = 0; ret.len < ist.len; ret.len++)
		ret.ptr[ret.len] = ist.ptr[ret.len];

	ret.ptr[ret.len] = 0;
	return ret;
}

/* trims string <ist> to no more than <size> characters. The string is
 * returned.
 */
static inline struct ist isttrim(const struct ist ist, size_t size)
{
	struct ist ret = ist;

	if (ret.len > size)
		ret.len = size;
	return ret;
}

/* trims string <ist> to no more than <size>-1 characters and ensures that a
 * zero is placed after <ist.len> (possibly reduced by one) and before <size>,
 * unless <size> is already zero. The string is returned. This is mostly aimed
 * at building printable strings that need to be zero-terminated.
 */
static inline struct ist istzero(const struct ist ist, size_t size)
{
	struct ist ret = ist;

	if (!size)
		ret.len = 0;
	else {
		if (ret.len > size - 1)
			ret.len = size - 1;
		ret.ptr[ret.len] = 0;
	}
	return ret;
}

/* returns the ordinal difference between two strings :
 *    < 0 if ist1 < ist2
 *    = 0 if ist1 == ist2
 *    > 0 if ist1 > ist2
 */
static inline int istdiff(const struct ist ist1, const struct ist ist2)
{
	struct ist l = ist1;
	struct ist r = ist2;

	do {
		if (!l.len--)
			return -r.len;
		if (!r.len--)
			return 1;
	} while (*l.ptr++ == *r.ptr++);

	return *(unsigned char *)(l.ptr - 1) - *(unsigned char *)(r.ptr - 1);
}

/* returns non-zero if <ist1> starts like <ist2> (empty strings do match) */
static inline int istmatch(const struct ist ist1, const struct ist ist2)
{
	struct ist l = ist1;
	struct ist r = ist2;

	if (l.len < r.len)
		return 0;

	while (r.len--) {
		if (*l.ptr++ != *r.ptr++)
			return 0;
	}
	return 1;
}

/* returns non-zero if <ist1> starts like <ist2> on the first <count>
 * characters (empty strings do match).
 */
static inline int istnmatch(const struct ist ist1, const struct ist ist2, size_t count)
{
	struct ist l = ist1;
	struct ist r = ist2;

	if (l.len > count)
		l.len = count;
	if (r.len > count)
		r.len = count;
	return istmatch(l, r);
}

/* returns non-zero if <ist1> equals <ist2> (empty strings are equal) */
static inline int isteq(const struct ist ist1, const struct ist ist2)
{
	struct ist l = ist1;
	struct ist r = ist2;

	if (l.len != r.len)
		return 0;

	while (l.len--) {
		if (*l.ptr++ != *r.ptr++)
			return 0;
	}
	return 1;
}

/* returns non-zero if <ist1> equals <ist2> on the first <count> characters
 * (empty strings are equal).
 */
static inline int istneq(const struct ist ist1, const struct ist ist2, size_t count)
{
	struct ist l = ist1;
	struct ist r = ist2;

	if (l.len > count)
		l.len = count;
	if (r.len > count)
		r.len = count;
	return isteq(l, r);
}

/* copies <src> over <dst> for a maximum of <count> bytes. Returns the number
 * of characters copied (src.len), or -1 if it does not fit. In all cases, the
 * contents are copied prior to reporting an error, so that the destination
 * at least contains a valid but truncated string.
 */
static inline ssize_t istcpy(struct ist *dst, const struct ist src, size_t count)
{
	dst->len = 0;

	if (count > src.len)
		count = src.len;

	while (dst->len < count) {
		dst->ptr[dst->len] = src.ptr[dst->len];
		dst->len++;
	}

	if (dst->len == src.len)
		return src.len;

	return -1;
}

/* copies <src> over <dst> for a maximum of <count> bytes. Returns the number
 * of characters copied, or -1 if it does not fit. A (possibly truncated) valid
 * copy of <src> is always left into <dst>, and a trailing \0 is appended as
 * long as <count> is not null, even if that results in reducing the string by
 * one character.
 */
static inline ssize_t istscpy(struct ist *dst, const struct ist src, size_t count)
{
	dst->len = 0;

	if (!count)
		goto fail;

	if (count > src.len)
		count = src.len + 1;

	while (dst->len < count - 1) {
		dst->ptr[dst->len] = src.ptr[dst->len];
		dst->len++;
	}

	dst->ptr[dst->len] = 0;
	if (dst->len == src.len)
		return src.len;
 fail:
	return -1;
}

/* appends <src> after <dst> for a maximum of <count> total bytes in <dst> after
 * the copy. <dst> is assumed to be <count> or less before the call. The new
 * string's length is returned, or -1 if a truncation happened. In all cases,
 * the contents are copied prior to reporting an error, so that the destination
 * at least contains a valid but truncated string.
 */
static inline ssize_t istcat(struct ist *dst, const struct ist src, size_t count)
{
	const char *s = src.ptr;

	while (dst->len < count && s != src.ptr + src.len)
		dst->ptr[dst->len++] = *s++;

	if (s == src.ptr + src.len)
		return dst->len;

	return -1;
}

/* appends <src> after <dst> for a maximum of <count> total bytes in <dst> after
 * the copy. <dst> is assumed to be <count> or less before the call. The new
 * string's length is returned, or -1 if a truncation happened. In all cases,
 * the contents are copied prior to reporting an error, so that the destination
 * at least contains a valid but truncated string.
 */
static inline ssize_t istscat(struct ist *dst, const struct ist src, size_t count)
{
	const char *s = src.ptr;

	if (!count)
		goto fail;

	while (dst->len < count - 1 && s != src.ptr + src.len) {
		dst->ptr[dst->len++] = *s++;
	}

	dst->ptr[dst->len] = 0;
	if (s == src.ptr + src.len)
		return dst->len;
 fail:
	return -1;
}

/* looks for first occurrence of character <chr> in string <ist>. Returns the
 * pointer if found, or NULL if not found.
 */
static inline char *istchr(const struct ist ist, char chr)
{
	char *s = ist.ptr;

	do {
		if (s >= ist.ptr + ist.len)
			return NULL;
	} while (*s++ != chr);
	return s - 1;
}

/* looks for first occurrence of character <chr> in string <ist> and returns
 * the tail of the string starting with this character, or (ist.end,0) if not
 * found.
 */
static inline struct ist istfind(const struct ist ist, char chr)
{
	struct ist ret = ist;

	while (ret.len--) {
		if (*ret.ptr++ == chr)
			return ist2(ret.ptr - 1, ret.len + 1);
	}
	return ist2(ret.ptr, 0);
}

/* looks for first occurrence of character different from <chr> in string <ist>
 * and returns the tail of the string starting at this character, or (ist_end,0)
 * if not found.
 */
static inline struct ist istskip(const struct ist ist, char chr)
{
	struct ist ret = ist;

	while (ret.len--) {
		if (*ret.ptr++ != chr)
			return ist2(ret.ptr - 1, ret.len + 1);
	}
	return ist2(ret.ptr, 0);
}

/* looks for first occurrence of string <pat> in string <ist> and returns the
 * tail of the string starting at this position, or (NULL,0) if not found. The
 * empty pattern is found everywhere.
 */
static inline struct ist istist(const struct ist ist, const struct ist pat)
{
	struct ist ret = ist;
	size_t pos;

	if (!pat.len)
		return ret;

	while (1) {
	loop:
		ret = istfind(ret, *pat.ptr);
		if (ret.len < pat.len)
			break;

		/* ret.len >= 1, pat.len >= 1 and *ret.ptr == *pat.ptr */

		ret = istnext(ret);
		for (pos = 0; pos < pat.len - 1; ) {
			++pos;
			if (ret.ptr[pos - 1] != pat.ptr[pos])
				goto loop;
		}
		return ist2(ret.ptr - 1, ret.len + 1);
	}
	return ist2(NULL, 0);
}

#endif
