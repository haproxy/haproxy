/*
 * General purpose functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/config.h>
#include <common/standard.h>
#include <proto/log.h>

/* enough to store 10 integers of :
 *   2^64-1 = 18446744073709551615 or
 *    -2^63 = -9223372036854775808
 */
char itoa_str[10][21];

/*
 * copies at most <size-1> chars from <src> to <dst>. Last char is always
 * set to 0, unless <size> is 0. The number of chars copied is returned
 * (excluding the terminating zero).
 * This code has been optimized for size and speed : on x86, it's 45 bytes
 * long, uses only registers, and consumes only 4 cycles per char.
 */
int strlcpy2(char *dst, const char *src, int size)
{
	char *orig = dst;
	if (size) {
		while (--size && (*dst = *src)) {
			src++; dst++;
		}
		*dst = 0;
	}
	return dst - orig;
}

/*
 * This function simply returns a locally allocated string containing
 * the ascii representation for number 'n' in decimal.
 */
const char *ultoa_r(unsigned long n, char *buffer, int size)
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


/*
 * Returns non-zero if character <s> is a hex digit (0-9, a-f, A-F), else zero.
 *
 * It looks like this one would be a good candidate for inlining, but this is
 * not interesting because it around 35 bytes long and often called multiple
 * times within the same function.
 */
int ishex(char s)
{
	s -= '0';
	if ((unsigned char)s <= 9)
		return 1;
	s -= 'A' - '0';
	if ((unsigned char)s <= 5)
		return 1;
	s -= 'a' - 'A';
	if ((unsigned char)s <= 5)
		return 1;
	return 0;
}


/*
 * converts <str> to a struct sockaddr_in* which is locally allocated.
 * The format is "addr:port", where "addr" can be a dotted IPv4 address,
 * a host name, or empty or "*" to indicate INADDR_ANY.
 */
struct sockaddr_in *str2sa(char *str)
{
	static struct sockaddr_in sa;
	char *c;
	int port;

	memset(&sa, 0, sizeof(sa));
	str = strdup(str);
	if (str == NULL)
		goto out_nofree;

	if ((c = strrchr(str,':')) != NULL) {
		*c++ = '\0';
		port = atol(c);
	}
	else
		port = 0;

	if (*str == '*' || *str == '\0') { /* INADDR_ANY */
		sa.sin_addr.s_addr = INADDR_ANY;
	}
	else if (!inet_pton(AF_INET, str, &sa.sin_addr)) {
		struct hostent *he;

		if ((he = gethostbyname(str)) == NULL) {
			Alert("Invalid server name: '%s'\n", str);
		}
		else
			sa.sin_addr = *(struct in_addr *) *(he->h_addr_list);
	}
	sa.sin_port   = htons(port);
	sa.sin_family = AF_INET;

	free(str);
 out_nofree:
	return &sa;
}

/*
 * converts <str> to two struct in_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optionnal and either in the dotted or CIDR notation.
 * Note: "addr" can also be a hostname. Returns 1 if OK, 0 if error.
 */
int str2net(const char *str, struct in_addr *addr, struct in_addr *mask)
{
	__label__ out_free, out_err;
	char *c, *s;
	int ret_val;
	unsigned long len;

	s = strdup(str);
	if (!s)
		return 0;

	memset(mask, 0, sizeof(*mask));
	memset(addr, 0, sizeof(*addr));

	if ((c = strrchr(s, '/')) != NULL) {
		*c++ = '\0';
		/* c points to the mask */
		if (strchr(c, '.') != NULL) {	    /* dotted notation */
			if (!inet_pton(AF_INET, c, mask))
				goto out_err;
		}
		else { /* mask length */
			char *err;
			len = strtol(c, &err, 10);
			if (!*c || (err && *err) || (unsigned)len > 32)
				goto out_err;
			if (len)
				mask->s_addr = htonl(~0UL << (32 - len));
			else
				mask->s_addr = 0;
		}
	}
	else {
		mask->s_addr = ~0U;
	}
	if (!inet_pton(AF_INET, s, addr)) {
		struct hostent *he;

		if ((he = gethostbyname(s)) == NULL) {
			goto out_err;
		}
		else
			*addr = *(struct in_addr *) *(he->h_addr_list);
	}

	ret_val = 1;
 out_free:
	free(s);
	return ret_val;
 out_err:
	ret_val = 0;
	goto out_free;
}

/* will try to encode the string <string> replacing all characters tagged in
 * <map> with the hexadecimal representation of their ASCII-code (2 digits)
 * prefixed by <escape>, and will store the result between <start> (included)
 * and <stop> (excluded), and will always terminate the string with a '\0'
 * before <stop>. The position of the '\0' is returned if the conversion
 * completes. If bytes are missing between <start> and <stop>, then the
 * conversion will be incomplete and truncated. If <stop> <= <start>, the '\0'
 * cannot even be stored so we return <start> without writing the 0.
 * The input string must also be zero-terminated.
 */
const char hextab[16] = "0123456789ABCDEF";
char *encode_string(char *start, char *stop,
		    const char escape, const fd_set *map,
		    const char *string)
{
	if (start < stop) {
		stop--; /* reserve one byte for the final '\0' */
		while (start < stop && *string != '\0') {
			if (!FD_ISSET((unsigned char)(*string), map))
				*start++ = *string;
			else {
				if (start + 3 >= stop)
					break;
				*start++ = escape;
				*start++ = hextab[(*string >> 4) & 15];
				*start++ = hextab[*string & 15];
			}
			string++;
		}
		*start = '\0';
	}
	return start;
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
	int i = 0;
	int j, k;

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
 * than str2irc().
 */
#ifndef LLONG_MAX
#define LLONG_MAX 9223372036854775807LL
#define LLONG_MIN (-LLONG_MAX - 1LL)
#endif

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


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
