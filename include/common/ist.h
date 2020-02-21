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

#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <common/config.h>

/* ASCII to lower case conversion table */
#define _IST_LC ((const unsigned char[256]){            \
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, \
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, \
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, \
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, \
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, \
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, \
	0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, \
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, \
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, \
	0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, \
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, \
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, \
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, \
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, \
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, \
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, \
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, \
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, \
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, \
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, \
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, \
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, \
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, \
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, \
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, \
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, \
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, \
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, \
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, \
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, \
})

/* ASCII to upper case conversion table */
#define _IST_UC ((const unsigned char[256]){            \
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, \
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, \
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, \
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, \
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, \
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, \
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, \
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, \
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, \
	0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, \
	0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, \
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, \
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, \
	0x58, 0x59, 0x5a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, \
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, \
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, \
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, \
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, \
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, \
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, \
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, \
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, \
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, \
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, \
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, \
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, \
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, \
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, \
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, \
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, \
})

#ifdef USE_OBSOLETE_LINKER
/* some old linkers and some non-ELF platforms have issues with the weak
 * attribute so we turn these arrays to literals there.
 */
#define ist_lc _IST_LC
#define ist_uc _IST_UC
#else
const unsigned char ist_lc[256] __attribute__((weak)) = _IST_LC;
const unsigned char ist_uc[256] __attribute__((weak)) = _IST_UC;
#endif

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

/* returns non-zero if <ist1> equals <ist2>, ignoring the case (empty strings are equal) */
static inline int isteqi(const struct ist ist1, const struct ist ist2)
{
	struct ist l = ist1;
	struct ist r = ist2;

	if (l.len != r.len)
		return 0;

	while (l.len--) {
		if (*l.ptr != *r.ptr &&
		    ist_lc[(unsigned char)*l.ptr] != ist_lc[(unsigned char)*r.ptr])
			return 0;

		l.ptr++;
		r.ptr++;
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

/* copies the entire <src> over <dst>, which must be allocated large enough to
 * hold the whole contents. No trailing zero is appended, this is mainly used
 * for protocol processing where the frame length has already been checked. An
 * ist made of the output and its length are returned. The destination is not
 * touched if src.len is null.
 */
static inline struct ist ist2bin(char *dst, const struct ist src)
{
	size_t ofs = 0;

	/* discourage the compiler from trying to optimize for large strings,
	 * but tell it that most of our strings are not empty.
	 */
	if (__builtin_expect(ofs < src.len, 1)) {
		do {
			dst[ofs] = src.ptr[ofs];
			ofs++;
		} while (__builtin_expect(ofs < src.len, 0));
	}
	return ist2(dst, ofs);
}

/* copies the entire <src> over <dst>, which must be allocated large enough to
 * hold the whole contents as well as a trailing zero which is always appended.
 * This is mainly used for protocol conversions where the frame length has
 * already been checked. An ist made of the output and its length (not counting
 * the trailing zero) are returned.
 */
static inline struct ist ist2str(char *dst, const struct ist src, size_t count)
{
	size_t ofs = 0;

	/* discourage the compiler from trying to optimize for large strings,
	 * but tell it that most of our strings are not empty.
	 */
	if (__builtin_expect(ofs < src.len, 1)) {
		do {
			dst[ofs] = src.ptr[ofs];
			ofs++;
		} while (__builtin_expect(ofs < src.len, 0));
	}
	dst[ofs] = 0;
	return ist2(dst, ofs);
}

/* makes a lower case copy of the entire <src> into <dst>, which must have been
 * allocated large enough to hold the whole contents. No trailing zero is
 * appended, this is mainly used for protocol processing where the frame length
 * has already been checked. An ist made of the output and its length are
 * returned. The destination is not touched if src.len is null.
 */
static inline struct ist ist2bin_lc(char *dst, const struct ist src)
{
	size_t ofs = 0;

	/* discourage the compiler from trying to optimize for large strings,
	 * but tell it that most of our strings are not empty.
	 */
	if (__builtin_expect(ofs < src.len, 1)) {
		do {
			dst[ofs] = ist_lc[(unsigned char)src.ptr[ofs]];
			ofs++;
		} while (__builtin_expect(ofs < src.len, 0));
	}
	return ist2(dst, ofs);
}

/* makes a lower case copy of the entire <src> into <dst>, which must have been
 * allocated large enough to hold the whole contents as well as a trailing zero
 * which is always appended. This is mainly used for protocol conversions where
 * the frame length has already been checked. An ist made of the output and its
 * length (not counting the trailing zero) are returned.
 */
static inline struct ist ist2str_lc(char *dst, const struct ist src, size_t count)
{
	size_t ofs = 0;

	/* discourage the compiler from trying to optimize for large strings,
	 * but tell it that most of our strings are not empty.
	 */
	if (__builtin_expect(ofs < src.len, 1)) {
		do {
			dst[ofs] = ist_lc[(unsigned char)src.ptr[ofs]];
			ofs++;
		} while (__builtin_expect(ofs < src.len, 0));
	}
	dst[ofs] = 0;
	return ist2(dst, ofs);
}

/* makes an upper case copy of the entire <src> into <dst>, which must have
 * been allocated large enough to hold the whole contents. No trailing zero is
 * appended, this is mainly used for protocol processing where the frame length
 * has already been checked. An ist made of the output and its length are
 * returned. The destination is not touched if src.len is null.
 */
static inline struct ist ist2bin_uc(char *dst, const struct ist src)
{
	size_t ofs = 0;

	/* discourage the compiler from trying to optimize for large strings,
	 * but tell it that most of our strings are not empty.
	 */
	if (__builtin_expect(ofs < src.len, 1)) {
		do {
			dst[ofs] = ist_uc[(unsigned char)src.ptr[ofs]];
			ofs++;
		} while (__builtin_expect(ofs < src.len, 0));
	}
	return ist2(dst, ofs);
}

/* makes an upper case copy of the entire <src> into <dst>, which must have been
 * allocated large enough to hold the whole contents as well as a trailing zero
 * which is always appended. This is mainly used for protocol conversions where
 * the frame length has already been checked. An ist made of the output and its
 * length (not counting the trailing zero) are returned.
 */
static inline struct ist ist2str_uc(char *dst, const struct ist src, size_t count)
{
	size_t ofs = 0;

	/* discourage the compiler from trying to optimize for large strings,
	 * but tell it that most of our strings are not empty.
	 */
	if (__builtin_expect(ofs < src.len, 1)) {
		do {
			dst[ofs] = ist_uc[(unsigned char)src.ptr[ofs]];
			ofs++;
		} while (__builtin_expect(ofs < src.len, 0));
	}
	dst[ofs] = 0;
	return ist2(dst, ofs);
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

/* Returns a pointer to the first control character found in <ist>, or NULL if
 * none is present. A control character is defined as a byte whose value is
 * between 0x00 and 0x1F included. The function is optimized for strings having
 * no CTL chars by processing up to sizeof(long) bytes at once on architectures
 * supporting efficient unaligned accesses. Despite this it is not very fast
 * (~0.43 byte/cycle) and should mostly be used on low match probability when
 * it can save a call to a much slower function.
 */
static inline const char *ist_find_ctl(const struct ist ist)
{
	const union { unsigned long v; } __attribute__((packed)) *u;
	const char *curr = (void *)ist.ptr - sizeof(long);
	const char *last = curr + ist.len;
	unsigned long l1, l2;

	do {
		curr += sizeof(long);
		if (curr > last)
			break;
		u = (void *)curr;
		/* subtract 0x202020...20 to the value to generate a carry in
		 * the lower byte if the byte contains a lower value. If we
		 * generate a bit 7 that was not there, it means the byte was
		 * within 0x00..0x1F.
		 */
		l2  = u->v;
		l1  = ~l2 & ((~0UL / 255) * 0x80); /* 0x808080...80 */
		l2 -= (~0UL / 255) * 0x20;         /* 0x202020...20 */
	} while ((l1 & l2) == 0);

	last += sizeof(long);
	if (__builtin_expect(curr < last, 0)) {
		do {
			if ((uint8_t)*curr < 0x20)
				return curr;
			curr++;
		} while (curr < last);
	}
	return NULL;
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

/*
 * looks for the first occurence of <chr> in string <ist> and returns a shorter
 * ist if char is found.
 */
static inline struct ist iststop(const struct ist ist, char chr)
{
	size_t len = 0;

	while (len++ < ist.len && ist.ptr[len - 1] != chr)
		;
	return ist2(ist.ptr, len - 1);
}
#endif
