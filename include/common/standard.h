/*
 * include/common/standard.h
 * This files contains some general purpose functions and macros.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_STANDARD_H
#define _COMMON_STANDARD_H

#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <common/config.h>
#include <eb32tree.h>
#include <proto/fd.h>

/****** string-specific macros and functions ******/
/* if a > max, then bound <a> to <max>. The macro returns the new <a> */
#define UBOUND(a, max)	({ typeof(a) b = (max); if ((a) > b) (a) = b; (a); })

/* if a < min, then bound <a> to <min>. The macro returns the new <a> */
#define LBOUND(a, min)	({ typeof(a) b = (min); if ((a) < b) (a) = b; (a); })

/* returns 1 only if only zero or one bit is set in X, which means that X is a
 * power of 2, and 0 otherwise */
#define POWEROF2(x) (((x) & ((x)-1)) == 0)

/* operators to compare values. They're ordered that way so that the lowest bit
 * serves as a negation for the test and contains all tests that are not equal.
 */
enum {
	STD_OP_LE = 0, STD_OP_GT = 1,
	STD_OP_EQ = 2, STD_OP_NE = 3,
	STD_OP_GE = 4, STD_OP_LT = 5,
};

/*
 * copies at most <size-1> chars from <src> to <dst>. Last char is always
 * set to 0, unless <size> is 0. The number of chars copied is returned
 * (excluding the terminating zero).
 * This code has been optimized for size and speed : on x86, it's 45 bytes
 * long, uses only registers, and consumes only 4 cycles per char.
 */
extern int strlcpy2(char *dst, const char *src, int size);

/*
 * This function simply returns a locally allocated string containing
 * the ascii representation for number 'n' in decimal.
 */
extern char itoa_str[][171];
extern char *ultoa_r(unsigned long n, char *buffer, int size);
extern const char *ulltoh_r(unsigned long long n, char *buffer, int size);
static inline const char *ultoa(unsigned long n)
{
	return ultoa_r(n, itoa_str[0], sizeof(itoa_str[0]));
}

/* Fast macros to convert up to 10 different parameters inside a same call of
 * expression.
 */
#define U2A0(n) ({ ultoa_r((n), itoa_str[0], sizeof(itoa_str[0])); })
#define U2A1(n) ({ ultoa_r((n), itoa_str[1], sizeof(itoa_str[1])); })
#define U2A2(n) ({ ultoa_r((n), itoa_str[2], sizeof(itoa_str[2])); })
#define U2A3(n) ({ ultoa_r((n), itoa_str[3], sizeof(itoa_str[3])); })
#define U2A4(n) ({ ultoa_r((n), itoa_str[4], sizeof(itoa_str[4])); })
#define U2A5(n) ({ ultoa_r((n), itoa_str[5], sizeof(itoa_str[5])); })
#define U2A6(n) ({ ultoa_r((n), itoa_str[6], sizeof(itoa_str[6])); })
#define U2A7(n) ({ ultoa_r((n), itoa_str[7], sizeof(itoa_str[7])); })
#define U2A8(n) ({ ultoa_r((n), itoa_str[8], sizeof(itoa_str[8])); })
#define U2A9(n) ({ ultoa_r((n), itoa_str[9], sizeof(itoa_str[9])); })

/* The same macros provide HTML encoding of numbers */
#define U2H0(n) ({ ulltoh_r((n), itoa_str[0], sizeof(itoa_str[0])); })
#define U2H1(n) ({ ulltoh_r((n), itoa_str[1], sizeof(itoa_str[1])); })
#define U2H2(n) ({ ulltoh_r((n), itoa_str[2], sizeof(itoa_str[2])); })
#define U2H3(n) ({ ulltoh_r((n), itoa_str[3], sizeof(itoa_str[3])); })
#define U2H4(n) ({ ulltoh_r((n), itoa_str[4], sizeof(itoa_str[4])); })
#define U2H5(n) ({ ulltoh_r((n), itoa_str[5], sizeof(itoa_str[5])); })
#define U2H6(n) ({ ulltoh_r((n), itoa_str[6], sizeof(itoa_str[6])); })
#define U2H7(n) ({ ulltoh_r((n), itoa_str[7], sizeof(itoa_str[7])); })
#define U2H8(n) ({ ulltoh_r((n), itoa_str[8], sizeof(itoa_str[8])); })
#define U2H9(n) ({ ulltoh_r((n), itoa_str[9], sizeof(itoa_str[9])); })

/*
 * This function simply returns a locally allocated string containing the ascii
 * representation for number 'n' in decimal, unless n is 0 in which case it
 * returns the alternate string (or an empty string if the alternate string is
 * NULL). It use is intended for limits reported in reports, where it's
 * desirable not to display anything if there is no limit. Warning! it shares
 * the same vector as ultoa_r().
 */
extern const char *limit_r(unsigned long n, char *buffer, int size, const char *alt);

/* Fast macros to convert up to 10 different parameters inside a same call of
 * expression. Warning! they share the same vectors as U2A*!
 */
#define LIM2A0(n, alt) ({ limit_r((n), itoa_str[0], sizeof(itoa_str[0]), (alt)); })
#define LIM2A1(n, alt) ({ limit_r((n), itoa_str[1], sizeof(itoa_str[1]), (alt)); })
#define LIM2A2(n, alt) ({ limit_r((n), itoa_str[2], sizeof(itoa_str[2]), (alt)); })
#define LIM2A3(n, alt) ({ limit_r((n), itoa_str[3], sizeof(itoa_str[3]), (alt)); })
#define LIM2A4(n, alt) ({ limit_r((n), itoa_str[4], sizeof(itoa_str[4]), (alt)); })
#define LIM2A5(n, alt) ({ limit_r((n), itoa_str[5], sizeof(itoa_str[5]), (alt)); })
#define LIM2A6(n, alt) ({ limit_r((n), itoa_str[6], sizeof(itoa_str[6]), (alt)); })
#define LIM2A7(n, alt) ({ limit_r((n), itoa_str[7], sizeof(itoa_str[7]), (alt)); })
#define LIM2A8(n, alt) ({ limit_r((n), itoa_str[8], sizeof(itoa_str[8]), (alt)); })
#define LIM2A9(n, alt) ({ limit_r((n), itoa_str[9], sizeof(itoa_str[9]), (alt)); })

/*
 * Returns non-zero if character <s> is a hex digit (0-9, a-f, A-F), else zero.
 */
extern int ishex(char s);

/*
 * Return integer equivalent of character <c> for a hex digit (0-9, a-f, A-F),
 * otherwise -1.
 */
extern int hex2i(int c);

/*
 * Checks <name> for invalid characters. Valid chars are [A-Za-z0-9_:.-]. If an
 * invalid character is found, a pointer to it is returned. If everything is
 * fine, NULL is returned.
 */
extern const char *invalid_char(const char *name);

/*
 * Checks <domainname> for invalid characters. Valid chars are [A-Za-z0-9_.-].
 * If an invalid character is found, a pointer to it is returned.
 * If everything is fine, NULL is returned.
 */
extern const char *invalid_domainchar(const char *name);

/*
 * converts <str> to a struct sockaddr_un* which is locally allocated.
 * The format is "/path", where "/path" is a path to a UNIX domain socket.
 */
struct sockaddr_un *str2sun(const char *str);

/*
 * converts <str> to a struct sockaddr_storage* which is locally allocated. The
 * string is assumed to contain only an address, no port. The address can be a
 * dotted IPv4 address, an IPv6 address, a host name, or empty or "*" to
 * indicate INADDR_ANY. NULL is returned if the host part cannot be resolved.
 * The return address will only have the address family and the address set,
 * all other fields remain zero. The string is not supposed to be modified.
 * The IPv6 '::' address is IN6ADDR_ANY.
 */
struct sockaddr_storage *str2ip(const char *str);

/*
 * converts <str> to a locally allocated struct sockaddr_storage *.
 * The format is "addr[:[port]]", where "addr" can be a dotted IPv4 address, an
 * IPv6 address, a host name, or empty or "*" to indicate INADDR_ANY. If an IPv6
 * address wants to ignore port, it must be terminated by a trailing colon (':').
 * The IPv6 '::' address is IN6ADDR_ANY, so in order to bind to a given port on
 * IPv6, use ":::port". NULL is returned if the host part cannot be resolved.
 */
struct sockaddr_storage *str2sa(const char *str);

/*
 * converts <str> to a locally allocated struct sockaddr_storage *, and a
 * port range consisting in two integers. The low and high end are always set
 * even if the port is unspecified, in which case (0,0) is returned. The low
 * port is set in the sockaddr. Thus, it is enough to check the size of the
 * returned range to know if an array must be allocated or not. The format is
 * "addr[:[port[-port]]]", where "addr" can be a dotted IPv4 address, an IPv6
 * address, a host name, or empty or "*" to indicate INADDR_ANY. If an IPv6
 * address wants to ignore port, it must be terminated by a trailing colon (':').
 * The IPv6 '::' address is IN6ADDR_ANY, so in order to bind to a given port on
 * IPv6, use ":::port". NULL is returned if the host part cannot be resolved.
 */
struct sockaddr_storage *str2sa_range(const char *str, int *low, int *high);

/* converts <str> to a struct in_addr containing a network mask. It can be
 * passed in dotted form (255.255.255.0) or in CIDR form (24). It returns 1
 * if the conversion succeeds otherwise non-zero.
 */
int str2mask(const char *str, struct in_addr *mask);

/*
 * converts <str> to two struct in_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optionnal and either in the dotted or CIDR notation.
 * Note: "addr" can also be a hostname. Returns 1 if OK, 0 if error.
 */
int str2net(const char *str, struct in_addr *addr, struct in_addr *mask);

/*
 * Parse IP address found in url.
 */
int url2ipv4(const char *addr, struct in_addr *dst);

/*
 * Resolve destination server from URL. Convert <str> to a sockaddr_storage*.
 */
int url2sa(const char *url, int ulen, struct sockaddr_storage *addr);

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

/* Decode an URL-encoded string in-place. The resulting string might
 * be shorter. If some forbidden characters are found, the conversion is
 * aborted, the string is truncated before the issue and non-zero is returned,
 * otherwise the operation returns non-zero indicating success.
 */
int url_decode(char *string);

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
	unsigned int j, k;

	while (len-- > 0) {
		j = (*s++) - '0';
		k = i * 10;
		if (j > 9)
			break;
		i = k + j;
	}
	return i;
}

/* This function reads an unsigned integer from the string pointed to by <s>
 * and returns it. The <s> pointer is adjusted to point to the first unread
 * char. The function automatically stops at <end>.
 */
static inline unsigned int __read_uint(const char **s, const char *end)
{
	const char *ptr = *s;
	unsigned int i = 0;
	unsigned int j, k;

	while (ptr < end) {
		j = *ptr - '0';
		k = i * 10;
		if (j > 9)
			break;
		i = k + j;
		ptr++;
	}
	*s = ptr;
	return i;
}

extern unsigned int str2ui(const char *s);
extern unsigned int str2uic(const char *s);
extern unsigned int strl2ui(const char *s, int len);
extern unsigned int strl2uic(const char *s, int len);
extern int strl2ic(const char *s, int len);
extern int strl2irc(const char *s, int len, int *ret);
extern int strl2llrc(const char *s, int len, long long *ret);
extern unsigned int read_uint(const char **s, const char *end);
unsigned int inetaddr_host(const char *text);
unsigned int inetaddr_host_lim(const char *text, const char *stop);
unsigned int inetaddr_host_lim_ret(char *text, char *stop, char **ret);

static inline char *cut_crlf(char *s) {

	while (*s != '\r' || *s == '\n') {
		char *p = s++;

		if (!*p)
			return p;
	}

	*s++ = 0;

	return s;
}

static inline char *ltrim(char *s, char c) {

	if (c)
		while (*s == c)
			s++;

	return s;
}

static inline char *rtrim(char *s, char c) {

	char *p = s + strlen(s);

	while (p-- > s)
		if (*p == c)
			*p = '\0';
		else
			break;

	return s;
}

static inline char *alltrim(char *s, char c) {

	rtrim(s, c);

	return ltrim(s, c);
}

/* This function converts the time_t value <now> into a broken out struct tm
 * which must be allocated by the caller. It is highly recommended to use this
 * function intead of localtime() because that one requires a time_t* which
 * is not always compatible with tv_sec depending on OS/hardware combinations.
 */
static inline void get_localtime(const time_t now, struct tm *tm)
{
	localtime_r(&now, tm);
}

/* This function converts the time_t value <now> into a broken out struct tm
 * which must be allocated by the caller. It is highly recommended to use this
 * function intead of gmtime() because that one requires a time_t* which
 * is not always compatible with tv_sec depending on OS/hardware combinations.
 */
static inline void get_gmtime(const time_t now, struct tm *tm)
{
	gmtime_r(&now, tm);
}

/* This function parses a time value optionally followed by a unit suffix among
 * "d", "h", "m", "s", "ms" or "us". It converts the value into the unit
 * expected by the caller. The computation does its best to avoid overflows.
 * The value is returned in <ret> if everything is fine, and a NULL is returned
 * by the function. In case of error, a pointer to the error is returned and
 * <ret> is left untouched.
 */
extern const char *parse_time_err(const char *text, unsigned *ret, unsigned unit_flags);
extern const char *parse_size_err(const char *text, unsigned *ret);

/* unit flags to pass to parse_time_err */
#define TIME_UNIT_US   0x0000
#define TIME_UNIT_MS   0x0001
#define TIME_UNIT_S    0x0002
#define TIME_UNIT_MIN  0x0003
#define TIME_UNIT_HOUR 0x0004
#define TIME_UNIT_DAY  0x0005
#define TIME_UNIT_MASK 0x0007

/* Multiply the two 32-bit operands and shift the 64-bit result right 32 bits.
 * This is used to compute fixed ratios by setting one of the operands to
 * (2^32*ratio).
 */
static inline unsigned int mul32hi(unsigned int a, unsigned int b)
{
	return ((unsigned long long)a * b) >> 32;
}

/* gcc does not know when it can safely divide 64 bits by 32 bits. Use this
 * function when you know for sure that the result fits in 32 bits, because
 * it is optimal on x86 and on 64bit processors.
 */
static inline unsigned int div64_32(unsigned long long o1, unsigned int o2)
{
	unsigned int result;
#ifdef __i386__
	asm("divl %2"
	    : "=a" (result)
	    : "A"(o1), "rm"(o2));
#else
	result = o1 / o2;
#endif
	return result;
}

/* copies at most <n> characters from <src> and always terminates with '\0' */
char *my_strndup(const char *src, int n);

/* This function returns the first unused key greater than or equal to <key> in
 * ID tree <root>. Zero is returned if no place is found.
 */
unsigned int get_next_id(struct eb_root *root, unsigned int key);

/* This function compares a sample word possibly followed by blanks to another
 * clean word. The compare is case-insensitive. 1 is returned if both are equal,
 * otherwise zero. This intends to be used when checking HTTP headers for some
 * values.
 */
int word_match(const char *sample, int slen, const char *word, int wlen);

/* Convert a fixed-length string to an IP address. Returns 0 in case of error,
 * or the number of chars read in case of success.
 */
int buf2ip(const char *buf, size_t len, struct in_addr *dst);

/* To be used to quote config arg positions. Returns the string at <ptr>
 * surrounded by simple quotes if <ptr> is valid and non-empty, or "end of line"
 * if ptr is NULL or empty. The string is locally allocated.
 */
const char *quote_arg(const char *ptr);

/* returns an operator among STD_OP_* for string <str> or < 0 if unknown */
int get_std_op(const char *str);

/* hash a 32-bit integer to another 32-bit integer */
extern unsigned int full_hash(unsigned int a);
static inline unsigned int __full_hash(unsigned int a)
{
	/* This function is one of Bob Jenkins' full avalanche hashing
	 * functions, which when provides quite a good distribution for little
	 * input variations. The result is quite suited to fit over a 32-bit
	 * space with enough variations so that a randomly picked number falls
	 * equally before any server position.
	 * Check http://burtleburtle.net/bob/hash/integer.html for more info.
	 */
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);

	/* ensure values are better spread all around the tree by multiplying
	 * by a large prime close to 3/4 of the tree.
	 */
	return a * 3221225473U;
}

/* returns non-zero if addr has a valid and non-null IPv4 or IPv6 address,
 * otherwise zero.
 */
static inline int is_addr(struct sockaddr_storage *addr)
{
	int i;

	switch (addr->ss_family) {
	case AF_INET:
		return *(int *)&((struct sockaddr_in *)addr)->sin_addr;
	case AF_INET6:
		for (i = 0; i < sizeof(struct in6_addr) / sizeof(int); i++)
			if (((int *)&((struct sockaddr_in6 *)addr)->sin6_addr)[i] != 0)
				return ((int *)&((struct sockaddr_in6 *)addr)->sin6_addr)[i];
	}
	return 0;
}

/* returns port in network byte order */
static inline int get_net_port(struct sockaddr_storage *addr)
{
	switch (addr->ss_family) {
	case AF_INET:
		return ((struct sockaddr_in *)addr)->sin_port;
	case AF_INET6:
		return ((struct sockaddr_in6 *)addr)->sin6_port;
	}
	return 0;
}

/* returns port in host byte order */
static inline int get_host_port(struct sockaddr_storage *addr)
{
	switch (addr->ss_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)addr)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
	}
	return 0;
}

/* returns address len for <addr>'s family, 0 for unknown families */
static inline int get_addr_len(const struct sockaddr_storage *addr)
{
	switch (addr->ss_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	case AF_UNIX:
		return sizeof(struct sockaddr_un);
	}
	return 0;
}

/* set port in host byte order */
static inline int set_net_port(struct sockaddr_storage *addr, int port)
{
	switch (addr->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)addr)->sin_port = port;
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = port;
	}
	return 0;
}

/* set port in network byte order */
static inline int set_host_port(struct sockaddr_storage *addr, int port)
{
	switch (addr->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)addr)->sin_port = htons(port);
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
	}
	return 0;
}

/* Return true if IPv4 address is part of the network */
extern int in_net_ipv4(struct in_addr *addr, struct in_addr *mask, struct in_addr *net);

/* Return true if IPv6 address is part of the network */
extern int in_net_ipv6(struct in6_addr *addr, struct in6_addr *mask, struct in6_addr *net);

/* Map IPv4 adress on IPv6 address, as specified in RFC 3513. */
extern void v4tov6(struct in6_addr *sin6_addr, struct in_addr *sin_addr);

/* Map IPv6 adress on IPv4 address, as specified in RFC 3513.
 * Return true if conversion is possible and false otherwise.
 */
extern int v6tov4(struct in_addr *sin_addr, struct in6_addr *sin6_addr);

#endif /* _COMMON_STANDARD_H */
