/*
 * Functions for integer operations
 *
 * SPDX-License-Identifier: GPL-2.0-or-later.
 */

#include <string.h>
#include <haproxy/intops.h>

/* enough to store NB_ITOA_STR integers of :
 *   2^64-1 = 18446744073709551615 or
 *    -2^63 = -9223372036854775808
 *
 * The HTML version needs room for adding the 25 characters
 * '<span class="rls"></span>' around digits at positions 3N+1 in order
 * to add spacing at up to 6 positions : 18 446 744 073 709 551 615
 */
THREAD_LOCAL char itoa_str[NB_ITOA_STR][171];
THREAD_LOCAL int itoa_idx = 0; /* index of next itoa_str to use */

/*****************************************************************************
 * misc general purpose integer processing functions
 *****************************************************************************/

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


/*****************************************************************************
 * Here are a number of integer-to-string converters, with different types,
 * ranges, signedness, paddings etc.
 *****************************************************************************/

/*
 * unsigned long long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *ulltoa(unsigned long long n, char *dst, size_t size)
{
	int i = 0;
	char *res;

	switch(n) {
		case 1ULL ... 9ULL:
			i = 0;
			break;

		case 10ULL ... 99ULL:
			i = 1;
			break;

		case 100ULL ... 999ULL:
			i = 2;
			break;

		case 1000ULL ... 9999ULL:
			i = 3;
			break;

		case 10000ULL ... 99999ULL:
			i = 4;
			break;

		case 100000ULL ... 999999ULL:
			i = 5;
			break;

		case 1000000ULL ... 9999999ULL:
			i = 6;
			break;

		case 10000000ULL ... 99999999ULL:
			i = 7;
			break;

		case 100000000ULL ... 999999999ULL:
			i = 8;
			break;

		case 1000000000ULL ... 9999999999ULL:
			i = 9;
			break;

		case 10000000000ULL ... 99999999999ULL:
			i = 10;
			break;

		case 100000000000ULL ... 999999999999ULL:
			i = 11;
			break;

		case 1000000000000ULL ... 9999999999999ULL:
			i = 12;
			break;

		case 10000000000000ULL ... 99999999999999ULL:
			i = 13;
			break;

		case 100000000000000ULL ... 999999999999999ULL:
			i = 14;
			break;

		case 1000000000000000ULL ... 9999999999999999ULL:
			i = 15;
			break;

		case 10000000000000000ULL ... 99999999999999999ULL:
			i = 16;
			break;

		case 100000000000000000ULL ... 999999999999999999ULL:
			i = 17;
			break;

		case 1000000000000000000ULL ... 9999999999999999999ULL:
			i = 18;
			break;

		case 10000000000000000000ULL ... ULLONG_MAX:
			i = 19;
			break;
	}
	if (i + 2 > size) // (i + 1) + '\0'
		return NULL;  // too long
	res = dst + i + 1;
	*res = '\0';
	for (; i >= 0; i--) {
		dst[i] = n % 10ULL + '0';
		n /= 10ULL;
	}
	return res;
}

/*
 * unsigned long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *ultoa_o(unsigned long n, char *dst, size_t size)
{
	int i = 0;
	char *res;

	switch (n) {
		case 0U ... 9UL:
			i = 0;
			break;

		case 10U ... 99UL:
			i = 1;
			break;

		case 100U ... 999UL:
			i = 2;
			break;

		case 1000U ... 9999UL:
			i = 3;
			break;

		case 10000U ... 99999UL:
			i = 4;
			break;

		case 100000U ... 999999UL:
			i = 5;
			break;

		case 1000000U ... 9999999UL:
			i = 6;
			break;

		case 10000000U ... 99999999UL:
			i = 7;
			break;

		case 100000000U ... 999999999UL:
			i = 8;
			break;
#if __WORDSIZE == 32

		case 1000000000ULL ... ULONG_MAX:
			i = 9;
			break;

#elif __WORDSIZE == 64

		case 1000000000ULL ... 9999999999UL:
			i = 9;
			break;

		case 10000000000ULL ... 99999999999UL:
			i = 10;
			break;

		case 100000000000ULL ... 999999999999UL:
			i = 11;
			break;

		case 1000000000000ULL ... 9999999999999UL:
			i = 12;
			break;

		case 10000000000000ULL ... 99999999999999UL:
			i = 13;
			break;

		case 100000000000000ULL ... 999999999999999UL:
			i = 14;
			break;

		case 1000000000000000ULL ... 9999999999999999UL:
			i = 15;
			break;

		case 10000000000000000ULL ... 99999999999999999UL:
			i = 16;
			break;

		case 100000000000000000ULL ... 999999999999999999UL:
			i = 17;
			break;

		case 1000000000000000000ULL ... 9999999999999999999UL:
			i = 18;
			break;

		case 10000000000000000000ULL ... ULONG_MAX:
			i = 19;
			break;

#endif
	}
	if (i + 2 > size) // (i + 1) + '\0'
		return NULL;  // too long
	res = dst + i + 1;
	*res = '\0';
	for (; i >= 0; i--) {
		dst[i] = n % 10U + '0';
		n /= 10U;
	}
	return res;
}

/*
 * signed long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *ltoa_o(long int n, char *dst, size_t size)
{
	char *pos = dst;

	if (n < 0) {
		if (size < 3)
			return NULL; // min size is '-' + digit + '\0' but another test in ultoa
		*pos = '-';
		pos++;
		dst = ultoa_o(-n, pos, size - 1);
	} else {
		dst = ultoa_o(n, dst, size);
	}
	return dst;
}

/*
 * signed long long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *lltoa(long long n, char *dst, size_t size)
{
	char *pos = dst;

	if (n < 0) {
		if (size < 3)
			return NULL; // min size is '-' + digit + '\0' but another test in ulltoa
		*pos = '-';
		pos++;
		dst = ulltoa(-n, pos, size - 1);
	} else {
		dst = ulltoa(n, dst, size);
	}
	return dst;
}

/*
 * write a ascii representation of a unsigned into dst,
 * return a pointer to the last character
 * Pad the ascii representation with '0', using size.
 */
char *utoa_pad(unsigned int n, char *dst, size_t size)
{
	int i = 0;
	char *ret;

	switch(n) {
		case 0U ... 9U:
			i = 0;
			break;

		case 10U ... 99U:
			i = 1;
			break;

		case 100U ... 999U:
			i = 2;
			break;

		case 1000U ... 9999U:
			i = 3;
			break;

		case 10000U ... 99999U:
			i = 4;
			break;

		case 100000U ... 999999U:
			i = 5;
			break;

		case 1000000U ... 9999999U:
			i = 6;
			break;

		case 10000000U ... 99999999U:
			i = 7;
			break;

		case 100000000U ... 999999999U:
			i = 8;
			break;

		case 1000000000U ... 4294967295U:
			i = 9;
			break;
	}
	if (i + 2 > size) // (i + 1) + '\0'
		return NULL;  // too long
	i = size - 2; // padding - '\0'

	ret = dst + i + 1;
	*ret = '\0';
	for (; i >= 0; i--) {
		dst[i] = n % 10U + '0';
		n /= 10U;
	}
	return ret;
}

/*
 * This function simply returns a locally allocated string containing
 * the ascii representation for number 'n' in decimal.
 */
char *ultoa_r(unsigned long n, char *buffer, int size)
{
	char *pos;

	pos = buffer + size - 1;
	*pos-- = '\0';

	do {
		*pos-- = '0' + n % 10;
		n /= 10;
	} while (n && pos >= buffer);
	return pos + 1;
}

/*
 * This function simply returns a locally allocated string containing
 * the ascii representation for number 'n' in decimal.
 */
char *lltoa_r(long long int in, char *buffer, int size)
{
	char *pos;
	int neg = 0;
	unsigned long long int n;

	pos = buffer + size - 1;
	*pos-- = '\0';

	if (in < 0) {
		neg = 1;
		n = -in;
	}
	else
		n = in;

	do {
		*pos-- = '0' + n % 10;
		n /= 10;
	} while (n && pos >= buffer);
	if (neg && pos > buffer)
		*pos-- = '-';
	return pos + 1;
}

/*
 * This function simply returns a locally allocated string containing
 * the ascii representation for signed number 'n' in decimal.
 */
char *sltoa_r(long n, char *buffer, int size)
{
	char *pos;

	if (n >= 0)
		return ultoa_r(n, buffer, size);

	pos = ultoa_r(-n, buffer + 1, size - 1) - 1;
	*pos = '-';
	return pos;
}

/*
 * This function simply returns a locally allocated string containing
 * the ascii representation for number 'n' in decimal, formatted for
 * HTML output with tags to create visual grouping by 3 digits. The
 * output needs to support at least 171 characters.
 */
const char *ulltoh_r(unsigned long long n, char *buffer, int size)
{
	char *start;
	int digit = 0;

	start = buffer + size;
	*--start = '\0';

	do {
		if (digit == 3 && start >= buffer + 7)
			memcpy(start -= 7, "</span>", 7);

		if (start >= buffer + 1) {
			*--start = '0' + n % 10;
			n /= 10;
		}

		if (digit == 3 && start >= buffer + 18)
			memcpy(start -= 18, "<span class=\"rls\">", 18);

		if (digit++ == 3)
			digit = 1;
	} while (n && start > buffer);
	return start;
}

/*
 * This function simply returns a locally allocated string containing the ascii
 * representation for number 'n' in decimal, unless n is 0 in which case it
 * returns the alternate string (or an empty string if the alternate string is
 * NULL). It use is intended for limits reported in reports, where it's
 * desirable not to display anything if there is no limit. Warning! it shares
 * the same vector as ultoa_r().
 */
const char *limit_r(unsigned long n, char *buffer, int size, const char *alt)
{
	return (n) ? ultoa_r(n, buffer, size) : (alt ? alt : "");
}
