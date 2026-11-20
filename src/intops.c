/*
 * Functions for integer operations
 *
 * SPDX-License-Identifier: GPL-2.0-or-later.
 */

#include <haproxy/intops.h>

/* rounds <i> down to the closest value having max 2 digits */
unsigned int round_2dig(unsigned int i)
{
	unsigned int mul = 1;

	while (i >= 100) {
		i /= 10;
		mul *= 10;
	}
	return i * mul;
}

/* hash a 32-bit integer to another 32-bit integer */
unsigned int full_hash(unsigned int a)
{
	return __full_hash(a);
}

/* returns the number of bytes needed to encode <v> as a varint. An inline
 * version exists for use with constants (__varint_bytes()).
 */
int varint_bytes(uint64_t v)
{
	int len = 1;

	if (v >= 240) {
		v = (v - 240) >> 4;
		while (1) {
			len++;
			if (v < 128)
				break;
			v = (v - 128) >> 7;
		}
	}
	return len;
}


/*****************************************************************************
 * Below are mostly integer parsers that extract ints from string areas,
 * between two pointers, from a position and for a length, or starting at a
 * position to the trailing NUL. They are provided in various forms, with/
 * without validity checks, range checks. Some return the position of the
 * first unread bytes, others not.
 *****************************************************************************/


/* This function reads an unsigned integer from the string pointed to by <s>
 * and returns it. The <s> pointer is adjusted to point to the first unread
 * char. The function automatically stops at <end>.
 */
unsigned int read_uint(const char **s, const char *end)
{
	return __read_uint(s, end);
}

/* This function reads an unsigned integer from the string pointed to by <s> and
 * returns it. The <s> pointer is adjusted to point to the first unread char. The
 * function automatically stops at <end>. If the number overflows, the 2^64-1
 * value is returned.
 */
unsigned long long int read_uint64(const char **s, const char *end)
{
	const char *ptr = *s;
	unsigned long long int i = 0, tmp;
	unsigned int j;

	while (ptr < end) {

		/* read next char */
		j = *ptr - '0';
		if (j > 9)
			goto read_uint64_end;

		/* add char to the number and check overflow. */
		tmp = i * 10;
		if (tmp / 10 != i) {
			i = ULLONG_MAX;
			goto read_uint64_eat;
		}
		if (ULLONG_MAX - tmp < j) {
			i = ULLONG_MAX;
			goto read_uint64_eat;
		}
		i = tmp + j;
		ptr++;
	}
read_uint64_eat:
	/* eat each numeric char */
	while (ptr < end) {
		if ((unsigned int)(*ptr - '0') > 9)
			break;
		ptr++;
	}
read_uint64_end:
	*s = ptr;
	return i;
}

/* This function reads an integer from the string pointed to by <s> and returns
 * it. The <s> pointer is adjusted to point to the first unread char. The function
 * automatically stops at <end>. Il the number is bigger than 2^63-2, the 2^63-1
 * value is returned. If the number is lowest than -2^63-1, the -2^63 value is
 * returned.
 */
long long int read_int64(const char **s, const char *end)
{
	unsigned long long int i = 0;
	int neg = 0;

	/* Look for minus char. */
	if (**s == '-') {
		neg = 1;
		(*s)++;
	}
	else if (**s == '+')
		(*s)++;

	/* convert as positive number. */
	i = read_uint64(s, end);

	if (neg) {
		if (i > 0x8000000000000000ULL)
			return LLONG_MIN;
		return -i;
	}
	if (i > 0x7fffffffffffffffULL)
		return LLONG_MAX;
	return i;
}

unsigned int str2ui(const char *s)
{
	return __str2ui(s);
}

unsigned int str2uic(const char *s)
{
	return __str2uic(s);
}

unsigned int strl2ui(const char *s, int len)
{
	return __strl2ui(s, len);
}

unsigned int strl2uic(const char *s, int len)
{
	return __strl2uic(s, len);
}

/* This one is 7 times faster than strtol() on athlon with checks.
 * It returns the value of the number composed of all valid digits read,
 * and can process negative numbers too.
 */
int strl2ic(const char *s, int len)
{
	int i = 0, k;
	unsigned int j;

	if (len > 0) {
		if (*s != '-') {
			/* positive number */
			while (len-- > 0) {
				j = (*s++) - '0';
				k = i * 10;
				if (j > 9)
					break;
				i = k + j;
			}
		} else {
			/* negative number */
			s++;
			while (--len > 0) {
				j = (*s++) - '0';
				k = i * 10;
				if (j > 9)
					break;
				i = k - j;
			}
		}
	}
	return i;
}

/* The str{,l,ll}2{,u}irc() functions read non-NUL chars from <str> and convert
 * them to a signed or unsigned int/long/long long which they store into <ret>.
 * They accurately detects any error (empty/truncated string, invalid chars,
 * positive/negative overflows). They're meant to be used on exposed contents.
 * Contrary to the libc's strtoxxx() family, they're locale-agnostic and meant
 * to be very fast. They're built around an inline version for the core loop,
 * and the user-visible parts call it and apply sign/range checks. They return
 * an error code 0 when the number has successfully been converted, non-zero
 * otherwise. When an error is returned, the <ret> value is left untouched.
 */

/* generator for the int/uint/long/ulong/llong/ullong variants, do not use
 * outside this file!
 */
#define __str2uirc(type, str, lim, err) ({			\
	__label__ _done;					\
	const char *s = (str);					\
	const type _lim = (lim);				\
	int *_err = (err);					\
	type _i = 0;						\
	type _j = 0;						\
	while ((_j = (type)(*s++ - '0')) <= 9) {		\
		if (_i > _lim / 10) {				\
			*_err = 1; /* multiply overflow */	\
			goto _done;				\
		}						\
		_i = _i * 10;					\
		if (_i + _j < _i || _i + _j > _lim) {		\
			*_err = 1; /* add overflow */		\
			goto _done;				\
		}						\
		_i = _i + _j;					\
	}							\
	if (_j != (type)(0 - '0'))				\
	        *_err = 1; /* non-NUL ? invalid char */		\
	else if (s == str + 1)					\
		*_err = 1; /* empty */				\
_done:								\
	_i;							\
})

/* core for the int/uint variant */
static forceinline uint _str2uirc(const char *str, uint lim, int *err)
{
	return __str2uirc(uint, str, lim, err);
}

/* core for the long/ulong variant */
static forceinline ulong _str2ulrc(const char *str, ulong lim, int *err)
{
	return __str2uirc(ulong, str, lim, err);
}

/* core for the long/ulong variant */
static forceinline ullong _str2ullrc(const char *str, ullong lim, int *err)
{
	return __str2uirc(ullong, str, lim, err);
}

/* parses uint in <str>, stores in <ret>, returns 0 on success, see above. */
int str2uirc(const char *str, uint *ret)
{
	uint i = 0;
	int err = 0;

	i = _str2uirc(str, UINT_MAX, &err);
	if (err)
		return 1;

	*ret = i;
	return 0;
}

/* parses int in <str>, stores in <ret>, returns 0 on success, see above. */
int str2irc(const char *str, int *ret)
{
	uint lim = INT_MAX;
	uint i = 0;
	int err = 0;

	if (*str == '-') {
		str++;
		lim = -(uint)INT_MIN;
	}

	i = _str2uirc(str, lim, &err);
	if (err)
		return 1;

	i = (lim == INT_MAX) ? i : -i;
	*ret = (int)i;
	return 0;
}

/* parses ulong in <str>, stores in <ret>, returns 0 on success, see above. */
int str2ulrc(const char *str, ulong *ret)
{
	ulong i = 0;
	int err = 0;

	i = _str2ulrc(str, ULONG_MAX, &err);
	if (err)
		return 1;

	*ret = i;
	return 0;
}

/* parses long in <str>, stores in <ret>, returns 0 on success, see above. */
int str2lrc(const char *str, long *ret)
{
	ulong lim = LONG_MAX;
	ulong i = 0;
	int err = 0;

	if (*str == '-') {
		str++;
		lim = -(ulong)LONG_MIN;
	}

	i = _str2ulrc(str, lim, &err);
	if (err)
		return 1;

	i = (lim == LONG_MAX) ? i : -i;
	*ret = (long)i;
	return 0;
}

/* parses ullong in <str>, stores in <ret>, returns 0 on success, see above. */
int str2ullrc(const char *str, ullong *ret)
{
	ullong i = 0;
	int err = 0;

	i = _str2ullrc(str, ULLONG_MAX, &err);
	if (err)
		return 1;

	*ret = i;
	return 0;
}

/* parses llong in <str>, stores in <ret>, returns 0 on success, see above. */
int str2llrc(const char *str, llong *ret)
{
	ullong lim = LLONG_MAX;
	ullong i = 0;
	int err = 0;

	if (*str == '-') {
		str++;
		lim = -(ullong)LLONG_MIN;
	}

	i = _str2ullrc(str, lim, &err);
	if (err)
		return 1;

	i = (lim == LLONG_MAX) ? i : -i;
	*ret = (llong)i;
	return 0;
}

/* This function reads exactly <len> chars from <s> and converts them to a
 * signed integer which it stores into <ret>. It accurately detects any error
 * (truncated string, invalid chars, overflows). It is meant to be used in
 * applications designed for hostile environments. It returns zero when the
 * number has successfully been converted, non-zero otherwise. When an error
 * is returned, the <ret> value is left untouched. It is yet 5 to 40 times
 * faster than strtol().
 */
int strl2irc(const char *s, int len, int *ret)
{
	int i = 0;
	int j;

	if (!len)
		return 1;

	if (*s != '-') {
		/* positive number */
		while (len-- > 0) {
			j = (*s++) - '0';
			if (j > 9)            return 1; /* invalid char */
			if (i > INT_MAX / 10) return 1; /* check for multiply overflow */
			i = i * 10;
			if (i + j < i)        return 1; /* check for addition overflow */
			i = i + j;
		}
	} else {
		/* negative number */
		if (len == 1)
			return 1; /* sign alone, no digit */
		s++;
		while (--len > 0) {
			j = (*s++) - '0';
			if (j > 9)             return 1; /* invalid char */
			if (i < INT_MIN / 10)  return 1; /* check for multiply overflow */
			i = i * 10;
			if (i - j > i)         return 1; /* check for subtract overflow */
			i = i - j;
		}
	}
	*ret = i;
	return 0;
}


/* This function reads exactly <len> chars from <s> and converts them to a
 * signed integer which it stores into <ret>. It accurately detects any error
 * (truncated string, invalid chars, overflows). It is meant to be used in
 * applications designed for hostile environments. It returns zero when the
 * number has successfully been converted, non-zero otherwise. When an error
 * is returned, the <ret> value is left untouched. It is about 3 times slower
 * than strl2irc().
 */

int strl2llrc(const char *s, int len, long long *ret)
{
	long long i = 0;
	int j;

	if (!len)
		return 1;

	if (*s != '-') {
		/* positive number */
		while (len-- > 0) {
			j = (*s++) - '0';
			if (j > 9)              return 1; /* invalid char */
			if (i > LLONG_MAX / 10LL) return 1; /* check for multiply overflow */
			i = i * 10LL;
			if (i + j < i)          return 1; /* check for addition overflow */
			i = i + j;
		}
	} else {
		/* negative number */
		if (len == 1)
			return 1; /* sign alone, no digit */
		s++;
		while (--len > 0) {
			j = (*s++) - '0';
			if (j > 9)              return 1; /* invalid char */
			if (i < LLONG_MIN / 10LL) return 1; /* check for multiply overflow */
			i = i * 10LL;
			if (i - j > i)          return 1; /* check for subtract overflow */
			i = i - j;
		}
	}
	*ret = i;
	return 0;
}
