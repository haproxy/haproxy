/*
  include/common/standard.h
  This files contains some general purpose functions and macros.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _COMMON_STANDARD_H
#define _COMMON_STANDARD_H

#include <limits.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <common/config.h>
#include <proto/fd.h>

/****** string-specific macros and functions ******/
/* if a > max, then bound <a> to <max>. The macro returns the new <a> */
#define UBOUND(a, max)	({ typeof(a) b = (max); if ((a) > b) (a) = b; (a); })

/* if a < min, then bound <a> to <min>. The macro returns the new <a> */
#define LBOUND(a, min)	({ typeof(a) b = (min); if ((a) < b) (a) = b; (a); })

/* returns 1 only if only zero or one bit is set in X, which means that X is a
 * power of 2, and 0 otherwise */
#define POWEROF2(x) (((x) & ((x)-1)) == 0)

/*
 * Gcc >= 3 provides the ability for the programme to give hints to the
 * compiler about what branch of an if is most likely to be taken. This
 * helps the compiler produce the most compact critical paths, which is
 * generally better for the cache and to reduce the number of jumps.
 */
#if __GNUC__ < 3
#define __builtin_expect(x,y) (x)
#endif

#define likely(x) (__builtin_expect((x) != 0, 1))
#define unlikely(x) (__builtin_expect((x) != 0, 0))


/*
 * copies at most <size-1> chars from <src> to <dst>. Last char is always
 * set to 0, unless <size> is 0. The number of chars copied is returned
 * (excluding the terminating zero).
 * This code has been optimized for size and speed : on x86, it's 45 bytes
 * long, uses only registers, and consumes only 4 cycles per char.
 */
extern int strlcpy2(char *dst, const char *src, int size);

/*
 * This function simply returns a statically allocated string containing
 * the ascii representation for number 'n' in decimal.
 */
extern char *ultoa(unsigned long n);

/*
 * Returns non-zero if character <s> is a hex digit (0-9, a-f, A-F), else zero.
 */
extern int ishex(char s);

/*
 * converts <str> to a struct sockaddr_in* which is locally allocated.
 * The format is "addr:port", where "addr" can be a dotted IPv4 address,
 * a host name, or empty or "*" to indicate INADDR_ANY.
 */
struct sockaddr_in *str2sa(char *str);

/*
 * converts <str> to two struct in_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optionnal and either in the dotted or CIDR notation.
 * Note: "addr" can also be a hostname. Returns 1 if OK, 0 if error.
 */
int str2net(const char *str, struct in_addr *addr, struct in_addr *mask);

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
extern const char hextab[];
char *encode_string(char *start, char *stop,
		    const char escape, const fd_set *map,
		    const char *string);

/* This one is 6 times faster than strtoul() on athlon, but does
 * no check at all.
 */
static inline unsigned int __str2ui(const char *s)
{
	unsigned int i = 0;
	while (*s) {
		i = i * 10 - '0';
		i += (unsigned char)*s++;
	}
	return i;
}

/* This one is 5 times faster than strtoul() on athlon with checks.
 * It returns the value of the number composed of all valid digits read.
 */
static inline unsigned int __str2uic(const char *s)
{
	unsigned int i = 0;
	unsigned int j;
	while (1) {
		j = (*s++) - '0';
		if (j > 9)
			break;
		i *= 10;
		i += j;
	}
	return i;
}

/* This one is 28 times faster than strtoul() on athlon, but does
 * no check at all!
 */
static inline unsigned int __strl2ui(const char *s, int len)
{
	unsigned int i = 0;
	while (len-- > 0) {
		i = i * 10 - '0';
		i += (unsigned char)*s++;
	}
	return i;
}

/* This one is 7 times faster than strtoul() on athlon with checks.
 * It returns the value of the number composed of all valid digits read.
 */
static inline unsigned int __strl2uic(const char *s, int len)
{
	unsigned int i = 0;
	unsigned int j;

	while (len-- > 0) {
		j = (*s++) - '0';
		i = i * 10;
		if (j > 9)
			break;
		i += j;
	}
	return i;
}

extern unsigned int str2ui(const char *s);
extern unsigned int str2uic(const char *s);
extern unsigned int strl2ui(const char *s, int len);
extern unsigned int strl2uic(const char *s, int len);
extern int strl2ic(const char *s, int len);
extern int strl2irc(const char *s, int len, int *ret);
extern int strl2llrc(const char *s, int len, long long *ret);

#endif /* _COMMON_STANDARD_H */
