/*
 * General purpose functions.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 16))
#include <sys/auxv.h>
#endif

#include <import/eb32sctree.h>
#include <import/eb32tree.h>

#include <haproxy/api.h>
#include <haproxy/chunk.h>
#include <haproxy/dgram.h>
#include <haproxy/dns.h>
#include <haproxy/global.h>
#include <haproxy/hlua.h>
#include <haproxy/listener.h>
#include <haproxy/namespace.h>
#include <haproxy/protocol.h>
#include <haproxy/sock.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

/* This macro returns false if the test __x is false. Many
 * of the following parsing function must be abort the processing
 * if it returns 0, so this macro is useful for writing light code.
 */
#define RET0_UNLESS(__x) do { if (!(__x)) return 0; } while (0)

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

/* sometimes we'll need to quote strings (eg: in stats), and we don't expect
 * to quote strings larger than a max configuration line.
 */
THREAD_LOCAL char quoted_str[NB_QSTR][QSTR_SIZE + 1];
THREAD_LOCAL int quoted_idx = 0;

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
	if (i < size)
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

/* returns a locally allocated string containing the quoted encoding of the
 * input string. The output may be truncated to QSTR_SIZE chars, but it is
 * guaranteed that the string will always be properly terminated. Quotes are
 * encoded by doubling them as is commonly done in CSV files. QSTR_SIZE must
 * always be at least 4 chars.
 */
const char *qstr(const char *str)
{
	char *ret = quoted_str[quoted_idx];
	char *p, *end;

	if (++quoted_idx >= NB_QSTR)
		quoted_idx = 0;

	p = ret;
	end = ret + QSTR_SIZE;

	*p++ = '"';

	/* always keep 3 chars to support passing "" and the ending " */
	while (*str && p < end - 3) {
		if (*str == '"') {
			*p++ = '"';
			*p++ = '"';
		}
		else
			*p++ = *str;
		str++;
	}
	*p++ = '"';
	return ret;
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

/*
 * Checks <name> for invalid characters. Valid chars are [A-Za-z0-9_:.-]. If an
 * invalid character is found, a pointer to it is returned. If everything is
 * fine, NULL is returned.
 */
const char *invalid_char(const char *name)
{
	if (!*name)
		return name;

	while (*name) {
		if (!isalnum((unsigned char)*name) && *name != '.' && *name != ':' &&
		    *name != '_' && *name != '-')
			return name;
		name++;
	}
	return NULL;
}

/*
 * Checks <name> for invalid characters. Valid chars are [_.-] and those
 * accepted by <f> function.
 * If an invalid character is found, a pointer to it is returned.
 * If everything is fine, NULL is returned.
 */
static inline const char *__invalid_char(const char *name, int (*f)(int)) {

	if (!*name)
		return name;

	while (*name) {
		if (!f((unsigned char)*name) && *name != '.' &&
		    *name != '_' && *name != '-')
			return name;

		name++;
	}

	return NULL;
}

/*
 * Checks <name> for invalid characters. Valid chars are [A-Za-z0-9_.-].
 * If an invalid character is found, a pointer to it is returned.
 * If everything is fine, NULL is returned.
 */
const char *invalid_domainchar(const char *name) {
	return __invalid_char(name, isalnum);
}

/*
 * Checks <name> for invalid characters. Valid chars are [A-Za-z_.-].
 * If an invalid character is found, a pointer to it is returned.
 * If everything is fine, NULL is returned.
 */
const char *invalid_prefix_char(const char *name) {
	return __invalid_char(name, isalnum);
}

/*
 * converts <str> to a struct sockaddr_storage* provided by the caller. The
 * caller must have zeroed <sa> first, and may have set sa->ss_family to force
 * parse a specific address format. If the ss_family is 0 or AF_UNSPEC, then
 * the function tries to guess the address family from the syntax. If the
 * family is forced and the format doesn't match, an error is returned. The
 * string is assumed to contain only an address, no port. The address can be a
 * dotted IPv4 address, an IPv6 address, a host name, or empty or "*" to
 * indicate INADDR_ANY. NULL is returned if the host part cannot be resolved.
 * The return address will only have the address family and the address set,
 * all other fields remain zero. The string is not supposed to be modified.
 * The IPv6 '::' address is IN6ADDR_ANY. If <resolve> is non-zero, the hostname
 * is resolved, otherwise only IP addresses are resolved, and anything else
 * returns NULL. If the address contains a port, this one is preserved.
 */
struct sockaddr_storage *str2ip2(const char *str, struct sockaddr_storage *sa, int resolve)
{
	struct hostent *he;
	/* max IPv6 length, including brackets and terminating NULL */
	char tmpip[48];
	int port = get_host_port(sa);

	/* check IPv6 with square brackets */
	if (str[0] == '[') {
		size_t iplength = strlen(str);

		if (iplength < 4) {
			/* minimal size is 4 when using brackets "[::]" */
			goto fail;
		}
		else if (iplength >= sizeof(tmpip)) {
			/* IPv6 literal can not be larger than tmpip */
			goto fail;
		}
		else {
			if (str[iplength - 1] != ']') {
				/* if address started with bracket, it should end with bracket */
				goto fail;
			}
			else {
				memcpy(tmpip, str + 1, iplength - 2);
				tmpip[iplength - 2] = '\0';
				str = tmpip;
			}
		}
	}

	/* Any IPv6 address */
	if (str[0] == ':' && str[1] == ':' && !str[2]) {
		if (!sa->ss_family || sa->ss_family == AF_UNSPEC)
			sa->ss_family = AF_INET6;
		else if (sa->ss_family != AF_INET6)
			goto fail;
		set_host_port(sa, port);
		return sa;
	}

	/* Any address for the family, defaults to IPv4 */
	if (!str[0] || (str[0] == '*' && !str[1])) {
		if (!sa->ss_family || sa->ss_family == AF_UNSPEC)
			sa->ss_family = AF_INET;
		set_host_port(sa, port);
		return sa;
	}

	/* check for IPv6 first */
	if ((!sa->ss_family || sa->ss_family == AF_UNSPEC || sa->ss_family == AF_INET6) &&
	    inet_pton(AF_INET6, str, &((struct sockaddr_in6 *)sa)->sin6_addr)) {
		sa->ss_family = AF_INET6;
		set_host_port(sa, port);
		return sa;
	}

	/* then check for IPv4 */
	if ((!sa->ss_family || sa->ss_family == AF_UNSPEC || sa->ss_family == AF_INET) &&
	    inet_pton(AF_INET, str, &((struct sockaddr_in *)sa)->sin_addr)) {
		sa->ss_family = AF_INET;
		set_host_port(sa, port);
		return sa;
	}

	if (!resolve)
		return NULL;

	if (!dns_hostname_validation(str, NULL))
		return NULL;

#ifdef USE_GETADDRINFO
	if (global.tune.options & GTUNE_USE_GAI) {
		struct addrinfo hints, *result;
		int success = 0;

		memset(&result, 0, sizeof(result));
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = sa->ss_family ? sa->ss_family : AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = 0;
		hints.ai_protocol = 0;

		if (getaddrinfo(str, NULL, &hints, &result) == 0) {
			if (!sa->ss_family || sa->ss_family == AF_UNSPEC)
				sa->ss_family = result->ai_family;
			else if (sa->ss_family != result->ai_family) {
				freeaddrinfo(result);
				goto fail;
			}

			switch (result->ai_family) {
			case AF_INET:
				memcpy((struct sockaddr_in *)sa, result->ai_addr, result->ai_addrlen);
				set_host_port(sa, port);
				success = 1;
				break;
			case AF_INET6:
				memcpy((struct sockaddr_in6 *)sa, result->ai_addr, result->ai_addrlen);
				set_host_port(sa, port);
				success = 1;
				break;
			}
		}

		if (result)
			freeaddrinfo(result);

		if (success)
			return sa;
	}
#endif
	/* try to resolve an IPv4/IPv6 hostname */
	he = gethostbyname(str);
	if (he) {
		if (!sa->ss_family || sa->ss_family == AF_UNSPEC)
			sa->ss_family = he->h_addrtype;
		else if (sa->ss_family != he->h_addrtype)
			goto fail;

		switch (sa->ss_family) {
		case AF_INET:
			((struct sockaddr_in *)sa)->sin_addr = *(struct in_addr *) *(he->h_addr_list);
			set_host_port(sa, port);
			return sa;
		case AF_INET6:
			((struct sockaddr_in6 *)sa)->sin6_addr = *(struct in6_addr *) *(he->h_addr_list);
			set_host_port(sa, port);
			return sa;
		}
	}

	/* unsupported address family */
 fail:
	return NULL;
}

/*
 * Converts <str> to a locally allocated struct sockaddr_storage *, and a port
 * range or offset consisting in two integers that the caller will have to
 * check to find the relevant input format. The following format are supported :
 *
 *   String format           | address |  port  |  low   |  high
 *    addr                   | <addr>  |   0    |   0    |   0
 *    addr:                  | <addr>  |   0    |   0    |   0
 *    addr:port              | <addr>  | <port> | <port> | <port>
 *    addr:pl-ph             | <addr>  |  <pl>  |  <pl>  |  <ph>
 *    addr:+port             | <addr>  | <port> |   0    | <port>
 *    addr:-port             | <addr>  |-<port> | <port> |   0
 *
 * The detection of a port range or increment by the caller is made by
 * comparing <low> and <high>. If both are equal, then port 0 means no port
 * was specified. The caller may pass NULL for <low> and <high> if it is not
 * interested in retrieving port ranges.
 *
 * Note that <addr> above may also be :
 *    - empty ("")  => family will be AF_INET and address will be INADDR_ANY
 *    - "*"         => family will be AF_INET and address will be INADDR_ANY
 *    - "::"        => family will be AF_INET6 and address will be IN6ADDR_ANY
 *    - a host name => family and address will depend on host name resolving.
 *
 * A prefix may be passed in before the address above to force the family :
 *    - "ipv4@"  => force address to resolve as IPv4 and fail if not possible.
 *    - "ipv6@"  => force address to resolve as IPv6 and fail if not possible.
 *    - "unix@"  => force address to be a path to a UNIX socket even if the
 *                  path does not start with a '/'
 *    - 'abns@'  -> force address to belong to the abstract namespace (Linux
 *                  only). These sockets are just like Unix sockets but without
 *                  the need for an underlying file system. The address is a
 *                  string. Technically it's like a Unix socket with a zero in
 *                  the first byte of the address.
 *    - "fd@"    => an integer must follow, and is a file descriptor number.
 *
 * IPv6 addresses can be declared with or without square brackets. When using
 * square brackets for IPv6 addresses, the port separator (colon) is optional.
 * If not using square brackets, and in order to avoid any ambiguity with
 * IPv6 addresses, the last colon ':' is mandatory even when no port is specified.
 * NULL is returned if the address cannot be parsed. The <low> and <high> ports
 * are always initialized if non-null, even for non-IP families.
 *
 * If <pfx> is non-null, it is used as a string prefix before any path-based
 * address (typically the path to a unix socket).
 *
 * if <fqdn> is non-null, it will be filled with :
 *   - a pointer to the FQDN of the server name to resolve if there's one, and
 *     that the caller will have to free(),
 *   - NULL if there was an explicit address that doesn't require resolution.
 *
 * Hostnames are only resolved if <opts> has PA_O_RESOLVE. Otherwise <fqdn> is
 * still honored so it is possible for the caller to know whether a resolution
 * failed by clearing this flag and checking if <fqdn> was filled, indicating
 * the need for a resolution.
 *
 * When a file descriptor is passed, its value is put into the s_addr part of
 * the address when cast to sockaddr_in and the address family is
 * AF_CUST_EXISTING_FD.
 *
 * The matching protocol will be set into <proto> if non-null.
 *
 * Any known file descriptor is also assigned to <fd> if non-null, otherwise it
 * is forced to -1.
 */
struct sockaddr_storage *str2sa_range(const char *str, int *port, int *low, int *high, int *fd,
                                      struct protocol **proto, char **err,
                                      const char *pfx, char **fqdn, unsigned int opts)
{
	static THREAD_LOCAL struct sockaddr_storage ss;
	struct sockaddr_storage *ret = NULL;
	struct protocol *new_proto = NULL;
	char *back, *str2;
	char *port1, *port2;
	int portl, porth, porta;
	int abstract = 0;
	int new_fd = -1;
	int sock_type, ctrl_type;

	portl = porth = porta = 0;
	if (fqdn)
		*fqdn = NULL;

	str2 = back = env_expand(strdup(str));
	if (str2 == NULL) {
		memprintf(err, "out of memory in '%s'\n", __FUNCTION__);
		goto out;
	}

	if (!*str2) {
		memprintf(err, "'%s' resolves to an empty address (environment variable missing?)\n", str);
		goto out;
	}

	memset(&ss, 0, sizeof(ss));

	/* prepare the default socket types */
	if ((opts & (PA_O_STREAM|PA_O_DGRAM)) == PA_O_DGRAM)
		sock_type = ctrl_type = SOCK_DGRAM;
	else
		sock_type = ctrl_type = SOCK_STREAM;

	if (strncmp(str2, "stream+", 7) == 0) {
		str2 += 7;
		sock_type = ctrl_type = SOCK_STREAM;
	}
	else if (strncmp(str2, "dgram+", 6) == 0) {
		str2 += 6;
		sock_type = ctrl_type = SOCK_DGRAM;
	}

	if (strncmp(str2, "unix@", 5) == 0) {
		str2 += 5;
		abstract = 0;
		ss.ss_family = AF_UNIX;
	}
	else if (strncmp(str2, "abns@", 5) == 0) {
		str2 += 5;
		abstract = 1;
		ss.ss_family = AF_UNIX;
	}
	else if (strncmp(str2, "ipv4@", 5) == 0) {
		str2 += 5;
		ss.ss_family = AF_INET;
	}
	else if (strncmp(str2, "ipv6@", 5) == 0) {
		str2 += 5;
		ss.ss_family = AF_INET6;
	}
	else if (strncmp(str2, "udp4@", 5) == 0) {
		str2 += 5;
		ss.ss_family = AF_INET;
		sock_type = ctrl_type = SOCK_DGRAM;
	}
	else if (strncmp(str2, "udp6@", 5) == 0) {
		str2 += 5;
		ss.ss_family = AF_INET6;
		sock_type = ctrl_type = SOCK_DGRAM;
	}
	else if (strncmp(str2, "udp@", 4) == 0) {
		str2 += 4;
		ss.ss_family = AF_UNSPEC;
		sock_type = ctrl_type = SOCK_DGRAM;
	}
	else if (strncmp(str2, "quic4@", 6) == 0) {
		str2 += 6;
		ss.ss_family = AF_INET;
		sock_type = SOCK_DGRAM;
		ctrl_type = SOCK_STREAM;
	}
	else if (strncmp(str2, "quic6@", 6) == 0) {
		str2 += 6;
		ss.ss_family = AF_INET6;
		sock_type = SOCK_DGRAM;
		ctrl_type = SOCK_STREAM;
	}
	else if (strncmp(str2, "fd@", 3) == 0) {
		str2 += 3;
		ss.ss_family = AF_CUST_EXISTING_FD;
	}
	else if (strncmp(str2, "sockpair@", 9) == 0) {
		str2 += 9;
		ss.ss_family = AF_CUST_SOCKPAIR;
	}
	else if (*str2 == '/') {
		ss.ss_family = AF_UNIX;
	}
	else
		ss.ss_family = AF_UNSPEC;

	if (ss.ss_family == AF_CUST_SOCKPAIR) {
		struct sockaddr_storage ss2;
		socklen_t addr_len;
		char *endptr;

		new_fd = strtol(str2, &endptr, 10);
		if (!*str2 || new_fd < 0 || *endptr) {
			memprintf(err, "file descriptor '%s' is not a valid integer in '%s'\n", str2, str);
			goto out;
		}

		/* just verify that it's a socket */
		addr_len = sizeof(ss2);
		if (getsockname(new_fd, (struct sockaddr *)&ss2, &addr_len) == -1) {
			memprintf(err, "cannot use file descriptor '%d' : %s.\n", new_fd, strerror(errno));
			goto out;
		}

		((struct sockaddr_in *)&ss)->sin_addr.s_addr = new_fd;
		((struct sockaddr_in *)&ss)->sin_port = 0;
	}
	else if (ss.ss_family == AF_CUST_EXISTING_FD) {
		char *endptr;

		new_fd = strtol(str2, &endptr, 10);
		if (!*str2 || new_fd < 0 || *endptr) {
			memprintf(err, "file descriptor '%s' is not a valid integer in '%s'\n", str2, str);
			goto out;
		}

		if (opts & PA_O_SOCKET_FD) {
			socklen_t addr_len;
			int type;

			addr_len = sizeof(ss);
			if (getsockname(new_fd, (struct sockaddr *)&ss, &addr_len) == -1) {
				memprintf(err, "cannot use file descriptor '%d' : %s.\n", new_fd, strerror(errno));
				goto out;
			}

			addr_len = sizeof(type);
			if (getsockopt(new_fd, SOL_SOCKET, SO_TYPE, &type, &addr_len) != 0 ||
			    (type == SOCK_STREAM) != (sock_type == SOCK_STREAM)) {
				memprintf(err, "socket on file descriptor '%d' is of the wrong type.\n", new_fd);
				goto out;
			}

			porta = portl = porth = get_host_port(&ss);
		} else if (opts & PA_O_RAW_FD) {
			((struct sockaddr_in *)&ss)->sin_addr.s_addr = new_fd;
			((struct sockaddr_in *)&ss)->sin_port = 0;
		} else {
			memprintf(err, "a file descriptor is not acceptable here in '%s'\n", str);
			goto out;
		}
	}
	else if (ss.ss_family == AF_UNIX) {
		struct sockaddr_un *un = (struct sockaddr_un *)&ss;
		int prefix_path_len;
		int max_path_len;
		int adr_len;

		/* complete unix socket path name during startup or soft-restart is
		 * <unix_bind_prefix><path>.<pid>.<bak|tmp>
		 */
		prefix_path_len = (pfx && !abstract) ? strlen(pfx) : 0;
		max_path_len = (sizeof(un->sun_path) - 1) -
			(abstract ? 0 : prefix_path_len + 1 + 5 + 1 + 3);

		adr_len = strlen(str2);
		if (adr_len > max_path_len) {
			memprintf(err, "socket path '%s' too long (max %d)\n", str, max_path_len);
			goto out;
		}

		/* when abstract==1, we skip the first zero and copy all bytes except the trailing zero */
		memset(un->sun_path, 0, sizeof(un->sun_path));
		if (prefix_path_len)
			memcpy(un->sun_path, pfx, prefix_path_len);
		memcpy(un->sun_path + prefix_path_len + abstract, str2, adr_len + 1 - abstract);
	}
	else { /* IPv4 and IPv6 */
		char *end = str2 + strlen(str2);
		char *chr;

		/* search for : or ] whatever comes first */
		for (chr = end-1; chr > str2; chr--) {
			if (*chr == ']' || *chr == ':')
				break;
		}

		if (*chr == ':') {
			/* Found a colon before a closing-bracket, must be a port separator.
			 * This guarantee backward compatibility.
			 */
			if (!(opts & PA_O_PORT_OK)) {
				memprintf(err, "port specification not permitted here in '%s'", str);
				goto out;
			}
			*chr++ = '\0';
			port1 = chr;
		}
		else {
			/* Either no colon and no closing-bracket
			 * or directly ending with a closing-bracket.
			 * However, no port.
			 */
			if (opts & PA_O_PORT_MAND) {
				memprintf(err, "missing port specification in '%s'", str);
				goto out;
			}
			port1 = "";
		}

		if (isdigit((unsigned char)*port1)) {	/* single port or range */
			port2 = strchr(port1, '-');
			if (port2) {
				if (!(opts & PA_O_PORT_RANGE)) {
					memprintf(err, "port range not permitted here in '%s'", str);
					goto out;
				}
				*port2++ = '\0';
			}
			else
				port2 = port1;
			portl = atoi(port1);
			porth = atoi(port2);

			if (portl < !!(opts & PA_O_PORT_MAND) || portl > 65535) {
				memprintf(err, "invalid port '%s'", port1);
				goto out;
			}

			if (porth < !!(opts & PA_O_PORT_MAND) || porth > 65535) {
				memprintf(err, "invalid port '%s'", port2);
				goto out;
			}

			if (portl > porth) {
				memprintf(err, "invalid port range '%d-%d'", portl, porth);
				goto out;
			}

			porta = portl;
		}
		else if (*port1 == '-') { /* negative offset */
			if (!(opts & PA_O_PORT_OFS)) {
				memprintf(err, "port offset not permitted here in '%s'", str);
				goto out;
			}
			portl = atoi(port1 + 1);
			porta = -portl;
		}
		else if (*port1 == '+') { /* positive offset */
			if (!(opts & PA_O_PORT_OFS)) {
				memprintf(err, "port offset not permitted here in '%s'", str);
				goto out;
			}
			porth = atoi(port1 + 1);
			porta = porth;
		}
		else if (*port1) { /* other any unexpected char */
			memprintf(err, "invalid character '%c' in port number '%s' in '%s'\n", *port1, port1, str);
			goto out;
		}
		else if (opts & PA_O_PORT_MAND) {
			memprintf(err, "missing port specification in '%s'", str);
			goto out;
		}

		/* first try to parse the IP without resolving. If it fails, it
		 * tells us we need to keep a copy of the FQDN to resolve later
		 * and to enable DNS. In this case we can proceed if <fqdn> is
		 * set or if PA_O_RESOLVE is set, otherwise it's an error.
		 */
		if (str2ip2(str2, &ss, 0) == NULL) {
			if ((!(opts & PA_O_RESOLVE) && !fqdn) ||
			    ((opts & PA_O_RESOLVE) && str2ip2(str2, &ss, 1) == NULL)) {
				memprintf(err, "invalid address: '%s' in '%s'\n", str2, str);
				goto out;
			}

			if (fqdn) {
				if (str2 != back)
					memmove(back, str2, strlen(str2) + 1);
				*fqdn = back;
				back = NULL;
			}
		}
		set_host_port(&ss, porta);
	}

	if (ctrl_type == SOCK_STREAM && !(opts & PA_O_STREAM)) {
		memprintf(err, "stream-type socket not acceptable in '%s'\n", str);
		goto out;
	}
	else if (ctrl_type == SOCK_DGRAM && !(opts & PA_O_DGRAM)) {
		memprintf(err, "dgram-type socket not acceptable in '%s'\n", str);
		goto out;
	}

	if (proto || (opts & PA_O_CONNECT)) {
		/* Note: if the caller asks for a proto, we must find one,
		 * except if we return with an fqdn that will resolve later,
		 * in which case the address is not known yet (this is only
		 * for servers actually).
		 */
		new_proto = protocol_lookup(ss.ss_family,
					    sock_type == SOCK_DGRAM,
					    ctrl_type == SOCK_DGRAM);

		if (!new_proto && (!fqdn || !*fqdn)) {
			memprintf(err, "unsupported protocol family %d for address '%s'", ss.ss_family, str);
			goto out;
		}

		if ((opts & PA_O_CONNECT) && new_proto && !new_proto->connect) {
			memprintf(err, "connect() not supported for this protocol family %d used by address '%s'", ss.ss_family, str);
			goto out;
		}
	}

	ret = &ss;
 out:
	if (port)
		*port = porta;
	if (low)
		*low = portl;
	if (high)
		*high = porth;
	if (fd)
		*fd = new_fd;
	if (proto)
		*proto = new_proto;
	free(back);
	return ret;
}

/* converts <addr> and <port> into a string representation of the address and port. This is sort
 * of an inverse of str2sa_range, with some restrictions. The supported families are AF_INET,
 * AF_INET6, AF_UNIX, and AF_CUST_SOCKPAIR. If the family is unsopported NULL is returned.
 * If map_ports is true, then the sign of the port is included in the output, to indicate it is
 * relative to the incoming port. AF_INET and AF_INET6 will be in the form "<addr>:<port>".
 * AF_UNIX will either be just the path (if using a pathname) or "abns@<path>" if it is abstract.
 * AF_CUST_SOCKPAIR will be of the form "sockpair@<fd>".
 *
 * The returned char* is allocated, and it is the responsibility of the caller to free it.
 */
char * sa2str(const struct sockaddr_storage *addr, int port, int map_ports)
{
	char buffer[INET6_ADDRSTRLEN];
	char *out = NULL;
	const void *ptr;
	const char *path;

	switch (addr->ss_family) {
	case AF_INET:
		ptr = &((struct sockaddr_in *)addr)->sin_addr;
		break;
	case AF_INET6:
		ptr = &((struct sockaddr_in6 *)addr)->sin6_addr;
		break;
	case AF_UNIX:
		path = ((struct sockaddr_un *)addr)->sun_path;
		if (path[0] == '\0') {
			const int max_length = sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path) - 1;
			return memprintf(&out, "abns@%.*s", max_length, path+1);
		} else {
			return strdup(path);
		}
	case AF_CUST_SOCKPAIR:
		return memprintf(&out, "sockpair@%d", ((struct sockaddr_in *)addr)->sin_addr.s_addr);
	default:
		return NULL;
	}
	inet_ntop(addr->ss_family, ptr, buffer, get_addr_len(addr));
	if (map_ports)
		return memprintf(&out, "%s:%+d", buffer, port);
	else
		return memprintf(&out, "%s:%d", buffer, port);
}


/* converts <str> to a struct in_addr containing a network mask. It can be
 * passed in dotted form (255.255.255.0) or in CIDR form (24). It returns 1
 * if the conversion succeeds otherwise zero.
 */
int str2mask(const char *str, struct in_addr *mask)
{
	if (strchr(str, '.') != NULL) {	    /* dotted notation */
		if (!inet_pton(AF_INET, str, mask))
			return 0;
	}
	else { /* mask length */
		char *err;
		unsigned long len = strtol(str, &err, 10);

		if (!*str || (err && *err) || (unsigned)len > 32)
			return 0;

		len2mask4(len, mask);
	}
	return 1;
}

/* converts <str> to a struct in6_addr containing a network mask. It can be
 * passed in quadruplet form (ffff:ffff::) or in CIDR form (64). It returns 1
 * if the conversion succeeds otherwise zero.
 */
int str2mask6(const char *str, struct in6_addr *mask)
{
	if (strchr(str, ':') != NULL) {	    /* quadruplet notation */
		if (!inet_pton(AF_INET6, str, mask))
			return 0;
	}
	else { /* mask length */
		char *err;
		unsigned long len = strtol(str, &err, 10);

		if (!*str || (err && *err) || (unsigned)len > 128)
			return 0;

		len2mask6(len, mask);
	}
	return 1;
}

/* convert <cidr> to struct in_addr <mask>. It returns 1 if the conversion
 * succeeds otherwise zero.
 */
int cidr2dotted(int cidr, struct in_addr *mask) {

	if (cidr < 0 || cidr > 32)
		return 0;

	mask->s_addr = cidr ? htonl(~0UL << (32 - cidr)) : 0;
	return 1;
}

/* Convert mask from bit length form to in_addr form.
 * This function never fails.
 */
void len2mask4(int len, struct in_addr *addr)
{
	if (len >= 32) {
		addr->s_addr = 0xffffffff;
		return;
	}
	if (len <= 0) {
		addr->s_addr = 0x00000000;
		return;
	}
	addr->s_addr = 0xffffffff << (32 - len);
	addr->s_addr = htonl(addr->s_addr);
}

/* Convert mask from bit length form to in6_addr form.
 * This function never fails.
 */
void len2mask6(int len, struct in6_addr *addr)
{
	len2mask4(len, (struct in_addr *)&addr->s6_addr[0]); /* msb */
	len -= 32;
	len2mask4(len, (struct in_addr *)&addr->s6_addr[4]);
	len -= 32;
	len2mask4(len, (struct in_addr *)&addr->s6_addr[8]);
	len -= 32;
	len2mask4(len, (struct in_addr *)&addr->s6_addr[12]); /* lsb */
}

/*
 * converts <str> to two struct in_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optional and either in the dotted or CIDR notation.
 * Note: "addr" can also be a hostname. Returns 1 if OK, 0 if error.
 */
int str2net(const char *str, int resolve, struct in_addr *addr, struct in_addr *mask)
{
	__label__ out_free, out_err;
	char *c, *s;
	int ret_val;

	s = strdup(str);
	if (!s)
		return 0;

	memset(mask, 0, sizeof(*mask));
	memset(addr, 0, sizeof(*addr));

	if ((c = strrchr(s, '/')) != NULL) {
		*c++ = '\0';
		/* c points to the mask */
		if (!str2mask(c, mask))
			goto out_err;
	}
	else {
		mask->s_addr = ~0U;
	}
	if (!inet_pton(AF_INET, s, addr)) {
		struct hostent *he;

		if (!resolve)
			goto out_err;

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


/*
 * converts <str> to two struct in6_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is an optional number of bits (128 being the default).
 * Returns 1 if OK, 0 if error.
 */
int str62net(const char *str, struct in6_addr *addr, unsigned char *mask)
{
	char *c, *s;
	int ret_val = 0;
	char *err;
	unsigned long len = 128;

	s = strdup(str);
	if (!s)
		return 0;

	memset(mask, 0, sizeof(*mask));
	memset(addr, 0, sizeof(*addr));

	if ((c = strrchr(s, '/')) != NULL) {
		*c++ = '\0'; /* c points to the mask */
		if (!*c)
			goto out_free;

		len = strtoul(c, &err, 10);
		if ((err && *err) || (unsigned)len > 128)
			goto out_free;
	}
	*mask = len; /* OK we have a valid mask in <len> */

	if (!inet_pton(AF_INET6, s, addr))
		goto out_free;

	ret_val = 1;
 out_free:
	free(s);
	return ret_val;
}


/*
 * Parse IPv4 address found in url.
 */
int url2ipv4(const char *addr, struct in_addr *dst)
{
	int saw_digit, octets, ch;
	u_char tmp[4], *tp;
	const char *cp = addr;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;

	while (*addr) {
		unsigned char digit = (ch = *addr++) - '0';
		if (digit > 9 && ch != '.')
			break;
		if (digit <= 9) {
			u_int new = *tp * 10 + digit;
			if (new > 255)
				return 0;
			*tp = new;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}

	if (octets < 4)
		return 0;

	memcpy(&dst->s_addr, tmp, 4);
	return addr-cp-1;
}

/*
 * Resolve destination server from URL. Convert <str> to a sockaddr_storage.
 * <out> contain the code of the detected scheme, the start and length of
 * the hostname. Actually only http and https are supported. <out> can be NULL.
 * This function returns the consumed length. It is useful if you parse complete
 * url like http://host:port/path, because the consumed length corresponds to
 * the first character of the path. If the conversion fails, it returns -1.
 *
 * This function tries to resolve the DNS name if haproxy is in starting mode.
 * So, this function may be used during the configuration parsing.
 */
int url2sa(const char *url, int ulen, struct sockaddr_storage *addr, struct split_url *out)
{
	const char *curr = url, *cp = url;
	const char *end;
	int ret, url_code = 0;
	unsigned long long int http_code = 0;
	int default_port;
	struct hostent *he;
	char *p;

	/* Firstly, try to find :// pattern */
	while (curr < url+ulen && url_code != 0x3a2f2f) {
		url_code = ((url_code & 0xffff) << 8);
		url_code += (unsigned char)*curr++;
	}

	/* Secondly, if :// pattern is found, verify parsed stuff
	 * before pattern is matching our http pattern.
	 * If so parse ip address and port in uri.
	 * 
	 * WARNING: Current code doesn't support dynamic async dns resolver.
	 */
	if (url_code != 0x3a2f2f)
		return -1;

	/* Copy scheme, and utrn to lower case. */
	while (cp < curr - 3)
		http_code = (http_code << 8) + *cp++;
	http_code |= 0x2020202020202020ULL;			/* Turn everything to lower case */
		
	/* HTTP or HTTPS url matching */
	if (http_code == 0x2020202068747470ULL) {
		default_port = 80;
		if (out)
			out->scheme = SCH_HTTP;
	}
	else if (http_code == 0x2020206874747073ULL) {
		default_port = 443;
		if (out)
			out->scheme = SCH_HTTPS;
	}
	else
		return -1;

	/* If the next char is '[', the host address is IPv6. */
	if (*curr == '[') {
		curr++;

		/* Check trash size */
		if (trash.size < ulen)
			return -1;

		/* Look for ']' and copy the address in a trash buffer. */
		p = trash.area;
		for (end = curr;
		     end < url + ulen && *end != ']';
		     end++, p++)
			*p = *end;
		if (*end != ']')
			return -1;
		*p = '\0';

		/* Update out. */
		if (out) {
			out->host = curr;
			out->host_len = end - curr;
		}

		/* Try IPv6 decoding. */
		if (!inet_pton(AF_INET6, trash.area, &((struct sockaddr_in6 *)addr)->sin6_addr))
			return -1;
		end++;

		/* Decode port. */
		if (*end == ':') {
			end++;
			default_port = read_uint(&end, url + ulen);
		}
		((struct sockaddr_in6 *)addr)->sin6_port = htons(default_port);
		((struct sockaddr_in6 *)addr)->sin6_family = AF_INET6;
		return end - url;
	}
	else {
		/* We are looking for IP address. If you want to parse and
		 * resolve hostname found in url, you can use str2sa_range(), but
		 * be warned this can slow down global daemon performances
		 * while handling lagging dns responses.
		 */
		ret = url2ipv4(curr, &((struct sockaddr_in *)addr)->sin_addr);
		if (ret) {
			/* Update out. */
			if (out) {
				out->host = curr;
				out->host_len = ret;
			}

			curr += ret;

			/* Decode port. */
			if (*curr == ':') {
				curr++;
				default_port = read_uint(&curr, url + ulen);
			}
			((struct sockaddr_in *)addr)->sin_port = htons(default_port);

			/* Set family. */
			((struct sockaddr_in *)addr)->sin_family = AF_INET;
			return curr - url;
		}
		else if (global.mode & MODE_STARTING) {
			/* The IPv4 and IPv6 decoding fails, maybe the url contain name. Try to execute
			 * synchronous DNS request only if HAProxy is in the start state.
			 */

			/* look for : or / or end */
			for (end = curr;
			     end < url + ulen && *end != '/' && *end != ':';
			     end++);
			memcpy(trash.area, curr, end - curr);
			trash.area[end - curr] = '\0';

			/* try to resolve an IPv4/IPv6 hostname */
			he = gethostbyname(trash.area);
			if (!he)
				return -1;

			/* Update out. */
			if (out) {
				out->host = curr;
				out->host_len = end - curr;
			}

			/* Decode port. */
			if (*end == ':') {
				end++;
				default_port = read_uint(&end, url + ulen);
			}

			/* Copy IP address, set port and family. */
			switch (he->h_addrtype) {
			case AF_INET:
				((struct sockaddr_in *)addr)->sin_addr = *(struct in_addr *) *(he->h_addr_list);
				((struct sockaddr_in *)addr)->sin_port = htons(default_port);
				((struct sockaddr_in *)addr)->sin_family = AF_INET;
				return end - url;

			case AF_INET6:
				((struct sockaddr_in6 *)addr)->sin6_addr = *(struct in6_addr *) *(he->h_addr_list);
				((struct sockaddr_in6 *)addr)->sin6_port = htons(default_port);
				((struct sockaddr_in6 *)addr)->sin6_family = AF_INET6;
				return end - url;
			}
		}
	}
	return -1;
}

/* Tries to convert a sockaddr_storage address to text form. Upon success, the
 * address family is returned so that it's easy for the caller to adapt to the
 * output format. Zero is returned if the address family is not supported. -1
 * is returned upon error, with errno set. AF_INET, AF_INET6 and AF_UNIX are
 * supported.
 */
int addr_to_str(const struct sockaddr_storage *addr, char *str, int size)
{

	const void *ptr;

	if (size < 5)
		return 0;
	*str = '\0';

	switch (addr->ss_family) {
	case AF_INET:
		ptr = &((struct sockaddr_in *)addr)->sin_addr;
		break;
	case AF_INET6:
		ptr = &((struct sockaddr_in6 *)addr)->sin6_addr;
		break;
	case AF_UNIX:
		memcpy(str, "unix", 5);
		return addr->ss_family;
	default:
		return 0;
	}

	if (inet_ntop(addr->ss_family, ptr, str, size))
		return addr->ss_family;

	/* failed */
	return -1;
}

/* Tries to convert a sockaddr_storage port to text form. Upon success, the
 * address family is returned so that it's easy for the caller to adapt to the
 * output format. Zero is returned if the address family is not supported. -1
 * is returned upon error, with errno set. AF_INET, AF_INET6 and AF_UNIX are
 * supported.
 */
int port_to_str(const struct sockaddr_storage *addr, char *str, int size)
{

	uint16_t port;


	if (size < 6)
		return 0;
	*str = '\0';

	switch (addr->ss_family) {
	case AF_INET:
		port = ((struct sockaddr_in *)addr)->sin_port;
		break;
	case AF_INET6:
		port = ((struct sockaddr_in6 *)addr)->sin6_port;
		break;
	case AF_UNIX:
		memcpy(str, "unix", 5);
		return addr->ss_family;
	default:
		return 0;
	}

	snprintf(str, size, "%u", ntohs(port));
	return addr->ss_family;
}

/* check if the given address is local to the system or not. It will return
 * -1 when it's not possible to know, 0 when the address is not local, 1 when
 * it is. We don't want to iterate over all interfaces for this (and it is not
 * portable). So instead we try to bind in UDP to this address on a free non
 * privileged port and to connect to the same address, port 0 (connect doesn't
 * care). If it succeeds, we own the address. Note that non-inet addresses are
 * considered local since they're most likely AF_UNIX.
 */
int addr_is_local(const struct netns_entry *ns,
                  const struct sockaddr_storage *orig)
{
	struct sockaddr_storage addr;
	int result;
	int fd;

	if (!is_inet_addr(orig))
		return 1;

	memcpy(&addr, orig, sizeof(addr));
	set_host_port(&addr, 0);

	fd = my_socketat(ns, addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return -1;

	result = -1;
	if (bind(fd, (struct sockaddr *)&addr, get_addr_len(&addr)) == 0) {
		if (connect(fd, (struct sockaddr *)&addr, get_addr_len(&addr)) == -1)
			result = 0; // fail, non-local address
		else
			result = 1; // success, local address
	}
	else {
		if (errno == EADDRNOTAVAIL)
			result = 0; // definitely not local :-)
	}
	close(fd);

	return result;
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
		    const char escape, const long *map,
		    const char *string)
{
	if (start < stop) {
		stop--; /* reserve one byte for the final '\0' */
		while (start < stop && *string != '\0') {
			if (!ha_bit_test((unsigned char)(*string), map))
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

/*
 * Same behavior as encode_string() above, except that it encodes chunk
 * <chunk> instead of a string.
 */
char *encode_chunk(char *start, char *stop,
		    const char escape, const long *map,
		    const struct buffer *chunk)
{
	char *str = chunk->area;
	char *end = chunk->area + chunk->data;

	if (start < stop) {
		stop--; /* reserve one byte for the final '\0' */
		while (start < stop && str < end) {
			if (!ha_bit_test((unsigned char)(*str), map))
				*start++ = *str;
			else {
				if (start + 3 >= stop)
					break;
				*start++ = escape;
				*start++ = hextab[(*str >> 4) & 15];
				*start++ = hextab[*str & 15];
			}
			str++;
		}
		*start = '\0';
	}
	return start;
}

/*
 * Tries to prefix characters tagged in the <map> with the <escape>
 * character. The input <string> must be zero-terminated. The result will
 * be stored between <start> (included) and <stop> (excluded). This
 * function will always try to terminate the resulting string with a '\0'
 * before <stop>, and will return its position if the conversion
 * completes.
 */
char *escape_string(char *start, char *stop,
		    const char escape, const long *map,
		    const char *string)
{
	if (start < stop) {
		stop--; /* reserve one byte for the final '\0' */
		while (start < stop && *string != '\0') {
			if (!ha_bit_test((unsigned char)(*string), map))
				*start++ = *string;
			else {
				if (start + 2 >= stop)
					break;
				*start++ = escape;
				*start++ = *string;
			}
			string++;
		}
		*start = '\0';
	}
	return start;
}

/*
 * Tries to prefix characters tagged in the <map> with the <escape>
 * character. <chunk> contains the input to be escaped. The result will be
 * stored between <start> (included) and <stop> (excluded). The function
 * will always try to terminate the resulting string with a '\0' before
 * <stop>, and will return its position if the conversion completes.
 */
char *escape_chunk(char *start, char *stop,
		   const char escape, const long *map,
		   const struct buffer *chunk)
{
	char *str = chunk->area;
	char *end = chunk->area + chunk->data;

	if (start < stop) {
		stop--; /* reserve one byte for the final '\0' */
		while (start < stop && str < end) {
			if (!ha_bit_test((unsigned char)(*str), map))
				*start++ = *str;
			else {
				if (start + 2 >= stop)
					break;
				*start++ = escape;
				*start++ = *str;
			}
			str++;
		}
		*start = '\0';
	}
	return start;
}

/* Check a string for using it in a CSV output format. If the string contains
 * one of the following four char <">, <,>, CR or LF, the string is
 * encapsulated between <"> and the <"> are escaped by a <""> sequence.
 * <str> is the input string to be escaped. The function assumes that
 * the input string is null-terminated.
 *
 * If <quote> is 0, the result is returned escaped but without double quote.
 * It is useful if the escaped string is used between double quotes in the
 * format.
 *
 *    printf("..., \"%s\", ...\r\n", csv_enc(str, 0, &trash));
 *
 * If <quote> is 1, the converter puts the quotes only if any reserved character
 * is present. If <quote> is 2, the converter always puts the quotes.
 *
 * <output> is a struct buffer used for storing the output string.
 *
 * The function returns the converted string on its output. If an error
 * occurs, the function returns an empty string. This type of output is useful
 * for using the function directly as printf() argument.
 *
 * If the output buffer is too short to contain the input string, the result
 * is truncated.
 *
 * This function appends the encoding to the existing output chunk, and it
 * guarantees that it starts immediately at the first available character of
 * the chunk. Please use csv_enc() instead if you want to replace the output
 * chunk.
 */
const char *csv_enc_append(const char *str, int quote, struct buffer *output)
{
	char *end = output->area + output->size;
	char *out = output->area + output->data;
	char *ptr = out;

	if (quote == 1) {
		/* automatic quoting: first verify if we'll have to quote the string */
		if (!strpbrk(str, "\n\r,\""))
			quote = 0;
	}

	if (quote)
		*ptr++ = '"';

	while (*str && ptr < end - 2) { /* -2 for reserving space for <"> and \0. */
		*ptr = *str;
		if (*str == '"') {
			ptr++;
			if (ptr >= end - 2) {
				ptr--;
				break;
			}
			*ptr = '"';
		}
		ptr++;
		str++;
	}

	if (quote)
		*ptr++ = '"';

	*ptr = '\0';
	output->data = ptr - output->area;
	return out;
}

/* Decode an URL-encoded string in-place. The resulting string might
 * be shorter. If some forbidden characters are found, the conversion is
 * aborted, the string is truncated before the issue and a negative value is
 * returned, otherwise the operation returns the length of the decoded string.
 * If the 'in_form' argument is non-nul the string is assumed to be part of
 * an "application/x-www-form-urlencoded" encoded string, and the '+' will be
 * turned to a space. If it's zero, this will only be done after a question
 * mark ('?').
 */
int url_decode(char *string, int in_form)
{
	char *in, *out;
	int ret = -1;

	in = string;
	out = string;
	while (*in) {
		switch (*in) {
		case '+' :
			*out++ = in_form ? ' ' : *in;
			break;
		case '%' :
			if (!ishex(in[1]) || !ishex(in[2]))
				goto end;
			*out++ = (hex2i(in[1]) << 4) + hex2i(in[2]);
			in += 2;
			break;
		case '?':
			in_form = 1;
			/* fall through */
		default:
			*out++ = *in;
			break;
		}
		in++;
	}
	ret = out - string; /* success */
 end:
	*out = 0;
	return ret;
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

/* This function is used with pat_parse_dotted_ver(). It converts a string
 * composed by two number separated by a dot. Each part must contain in 16 bits
 * because internally they will be represented as a 32-bit quantity stored in
 * a 64-bit integer. It returns zero when the number has successfully been
 * converted, non-zero otherwise. When an error is returned, the <ret> value
 * is left untouched.
 *
 *    "1.3"         -> 0x0000000000010003
 *    "65535.65535" -> 0x00000000ffffffff
 */
int strl2llrc_dotted(const char *text, int len, long long *ret)
{
	const char *end = &text[len];
	const char *p;
	long long major, minor;

	/* Look for dot. */
	for (p = text; p < end; p++)
		if (*p == '.')
			break;

	/* Convert major. */
	if (strl2llrc(text, p - text, &major) != 0)
		return 1;

	/* Check major. */
	if (major >= 65536)
		return 1;

	/* Convert minor. */
	minor = 0;
	if (p < end)
		if (strl2llrc(p + 1, end - (p + 1), &minor) != 0)
			return 1;

	/* Check minor. */
	if (minor >= 65536)
		return 1;

	/* Compose value. */
	*ret = (major << 16) | (minor & 0xffff);
	return 0;
}

/* This function parses a time value optionally followed by a unit suffix among
 * "d", "h", "m", "s", "ms" or "us". It converts the value into the unit
 * expected by the caller. The computation does its best to avoid overflows.
 * The value is returned in <ret> if everything is fine, and a NULL is returned
 * by the function. In case of error, a pointer to the error is returned and
 * <ret> is left untouched. Values are automatically rounded up when needed.
 * Values resulting in values larger than or equal to 2^31 after conversion are
 * reported as an overflow as value PARSE_TIME_OVER. Non-null values resulting
 * in an underflow are reported as an underflow as value PARSE_TIME_UNDER.
 */
const char *parse_time_err(const char *text, unsigned *ret, unsigned unit_flags)
{
	unsigned long long imult, idiv;
	unsigned long long omult, odiv;
	unsigned long long value, result;
	const char *str = text;

	if (!isdigit((unsigned char)*text))
		return text;

	omult = odiv = 1;

	switch (unit_flags & TIME_UNIT_MASK) {
	case TIME_UNIT_US:   omult = 1000000; break;
	case TIME_UNIT_MS:   omult = 1000; break;
	case TIME_UNIT_S:    break;
	case TIME_UNIT_MIN:  odiv = 60; break;
	case TIME_UNIT_HOUR: odiv = 3600; break;
	case TIME_UNIT_DAY:  odiv = 86400; break;
	default: break;
	}

	value = 0;

	while (1) {
		unsigned int j;

		j = *text - '0';
		if (j > 9)
			break;
		text++;
		value *= 10;
		value += j;
	}

	imult = idiv = 1;
	switch (*text) {
	case '\0': /* no unit = default unit */
		imult = omult = idiv = odiv = 1;
		goto end;
	case 's': /* second = unscaled unit */
		break;
	case 'u': /* microsecond : "us" */
		if (text[1] == 's') {
			idiv = 1000000;
			text++;
		}
		return text;
	case 'm': /* millisecond : "ms" or minute: "m" */
		if (text[1] == 's') {
			idiv = 1000;
			text++;
		} else
			imult = 60;
		break;
	case 'h': /* hour : "h" */
		imult = 3600;
		break;
	case 'd': /* day : "d" */
		imult = 86400;
		break;
	default:
		return text;
		break;
	}
	if (*(++text) != '\0') {
		ha_warning("unexpected character '%c' after the timer value '%s', only "
			   "(us=microseconds,ms=milliseconds,s=seconds,m=minutes,h=hours,d=days) are supported."
			   " This will be reported as an error in next versions.\n", *text, str);
	}

  end:
	if (omult % idiv == 0) { omult /= idiv; idiv = 1; }
	if (idiv % omult == 0) { idiv /= omult; omult = 1; }
	if (imult % odiv == 0) { imult /= odiv; odiv = 1; }
	if (odiv % imult == 0) { odiv /= imult; imult = 1; }

	result = (value * (imult * omult) + (idiv * odiv - 1)) / (idiv * odiv);
	if (result >= 0x80000000)
		return PARSE_TIME_OVER;
	if (!result && value)
		return PARSE_TIME_UNDER;
	*ret = result;
	return NULL;
}

/* this function converts the string starting at <text> to an unsigned int
 * stored in <ret>. If an error is detected, the pointer to the unexpected
 * character is returned. If the conversion is successful, NULL is returned.
 */
const char *parse_size_err(const char *text, unsigned *ret) {
	unsigned value = 0;

	if (!isdigit((unsigned char)*text))
		return text;

	while (1) {
		unsigned int j;

		j = *text - '0';
		if (j > 9)
			break;
		if (value > ~0U / 10)
			return text;
		value *= 10;
		if (value > (value + j))
			return text;
		value += j;
		text++;
	}

	switch (*text) {
	case '\0':
		break;
	case 'K':
	case 'k':
		if (value > ~0U >> 10)
			return text;
		value = value << 10;
		break;
	case 'M':
	case 'm':
		if (value > ~0U >> 20)
			return text;
		value = value << 20;
		break;
	case 'G':
	case 'g':
		if (value > ~0U >> 30)
			return text;
		value = value << 30;
		break;
	default:
		return text;
	}

	if (*text != '\0' && *++text != '\0')
		return text;

	*ret = value;
	return NULL;
}

/*
 * Parse binary string written in hexadecimal (source) and store the decoded
 * result into binstr and set binstrlen to the length of binstr. Memory for
 * binstr is allocated by the function. In case of error, returns 0 with an
 * error message in err. In success case, it returns the consumed length.
 */
int parse_binary(const char *source, char **binstr, int *binstrlen, char **err)
{
	int len;
	const char *p = source;
	int i,j;
	int alloc;

	len = strlen(source);
	if (len % 2) {
		memprintf(err, "an even number of hex digit is expected");
		return 0;
	}

	len = len >> 1;

	if (!*binstr) {
		*binstr = calloc(len, sizeof(**binstr));
		if (!*binstr) {
			memprintf(err, "out of memory while loading string pattern");
			return 0;
		}
		alloc = 1;
	}
	else {
		if (*binstrlen < len) {
			memprintf(err, "no space available in the buffer. expect %d, provides %d",
			          len, *binstrlen);
			return 0;
		}
		alloc = 0;
	}
	*binstrlen = len;

	i = j = 0;
	while (j < len) {
		if (!ishex(p[i++]))
			goto bad_input;
		if (!ishex(p[i++]))
			goto bad_input;
		(*binstr)[j++] =  (hex2i(p[i-2]) << 4) + hex2i(p[i-1]);
	}
	return len << 1;

bad_input:
	memprintf(err, "an hex digit is expected (found '%c')", p[i-1]);
	if (alloc) {
		free(*binstr);
		*binstr = NULL;
	}
	return 0;
}

/* copies at most <n> characters from <src> and always terminates with '\0' */
char *my_strndup(const char *src, int n)
{
	int len = 0;
	char *ret;

	while (len < n && src[len])
		len++;

	ret = malloc(len + 1);
	if (!ret)
		return ret;
	memcpy(ret, src, len);
	ret[len] = '\0';
	return ret;
}

/*
 * search needle in haystack
 * returns the pointer if found, returns NULL otherwise
 */
const void *my_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	const void *c = NULL;
	unsigned char f;

	if ((haystack == NULL) || (needle == NULL) || (haystacklen < needlelen))
		return NULL;

	f = *(char *)needle;
	c = haystack;
	while ((c = memchr(c, f, haystacklen - (c - haystack))) != NULL) {
		if ((haystacklen - (c - haystack)) < needlelen)
			return NULL;

		if (memcmp(c, needle, needlelen) == 0)
			return c;
		++c;
	}
	return NULL;
}

/* get length of the initial segment consisting entirely of bytes in <accept> */
size_t my_memspn(const void *str, size_t len, const void *accept, size_t acceptlen)
{
	size_t ret = 0;

	while (ret < len && memchr(accept, *((int *)str), acceptlen)) {
		str++;
		ret++;
	}
	return ret;
}

/* get length of the initial segment consisting entirely of bytes not in <rejcet> */
size_t my_memcspn(const void *str, size_t len, const void *reject, size_t rejectlen)
{
	size_t ret = 0;

	while (ret < len) {
		if(memchr(reject, *((int *)str), rejectlen))
			return ret;
		str++;
		ret++;
	}
	return ret;
}

/* This function returns the first unused key greater than or equal to <key> in
 * ID tree <root>. Zero is returned if no place is found.
 */
unsigned int get_next_id(struct eb_root *root, unsigned int key)
{
	struct eb32_node *used;

	do {
		used = eb32_lookup_ge(root, key);
		if (!used || used->key > key)
			return key; /* key is available */
		key++;
	} while (key);
	return key;
}

/* dump the full tree to <file> in DOT format for debugging purposes. Will
 * optionally highlight node <subj> if found, depending on operation <op> :
 *    0 : nothing
 *   >0 : insertion, node/leaf are surrounded in red
 *   <0 : removal, node/leaf are dashed with no background
 * Will optionally add "desc" as a label on the graph if set and non-null.
 */
void eb32sc_to_file(FILE *file, struct eb_root *root, const struct eb32sc_node *subj, int op, const char *desc)
{
	struct eb32sc_node *node;
	unsigned long scope = -1;

	fprintf(file, "digraph ebtree {\n");

	if (desc && *desc) {
		fprintf(file,
			"  fontname=\"fixed\";\n"
			"  fontsize=8;\n"
			"  label=\"%s\";\n", desc);
	}

	fprintf(file,
		"  node [fontname=\"fixed\" fontsize=8 shape=\"box\" style=\"filled\" color=\"black\" fillcolor=\"white\"];\n"
		"  edge [fontname=\"fixed\" fontsize=8 style=\"solid\" color=\"magenta\" dir=\"forward\"];\n"
		"  \"%lx_n\" [label=\"root\\n%lx\"]\n", (long)eb_root_to_node(root), (long)root
		);

	fprintf(file, "  \"%lx_n\" -> \"%lx_%c\" [taillabel=\"L\"];\n",
		(long)eb_root_to_node(root),
		(long)eb_root_to_node(eb_clrtag(root->b[0])),
		eb_gettag(root->b[0]) == EB_LEAF ? 'l' : 'n');

	node = eb32sc_first(root, scope);
	while (node) {
		if (node->node.node_p) {
			/* node part is used */
			fprintf(file, "  \"%lx_n\" [label=\"%lx\\nkey=%u\\nscope=%lx\\nbit=%d\" fillcolor=\"lightskyblue1\" %s];\n",
				(long)node, (long)node, node->key, node->node_s, node->node.bit,
				(node == subj) ? (op < 0 ? "color=\"red\" style=\"dashed\"" : op > 0 ? "color=\"red\"" : "") : "");

			fprintf(file, "  \"%lx_n\" -> \"%lx_n\" [taillabel=\"%c\"];\n",
				(long)node,
				(long)eb_root_to_node(eb_clrtag(node->node.node_p)),
				eb_gettag(node->node.node_p) ? 'R' : 'L');

			fprintf(file, "  \"%lx_n\" -> \"%lx_%c\" [taillabel=\"L\"];\n",
				(long)node,
				(long)eb_root_to_node(eb_clrtag(node->node.branches.b[0])),
				eb_gettag(node->node.branches.b[0]) == EB_LEAF ? 'l' : 'n');

			fprintf(file, "  \"%lx_n\" -> \"%lx_%c\" [taillabel=\"R\"];\n",
				(long)node,
				(long)eb_root_to_node(eb_clrtag(node->node.branches.b[1])),
				eb_gettag(node->node.branches.b[1]) == EB_LEAF ? 'l' : 'n');
		}

		fprintf(file, "  \"%lx_l\" [label=\"%lx\\nkey=%u\\nscope=%lx\\npfx=%u\" fillcolor=\"yellow\" %s];\n",
			(long)node, (long)node, node->key, node->leaf_s, node->node.pfx,
			(node == subj) ? (op < 0 ? "color=\"red\" style=\"dashed\"" : op > 0 ? "color=\"red\"" : "") : "");

		fprintf(file, "  \"%lx_l\" -> \"%lx_n\" [taillabel=\"%c\"];\n",
			(long)node,
			(long)eb_root_to_node(eb_clrtag(node->node.leaf_p)),
			eb_gettag(node->node.leaf_p) ? 'R' : 'L');
		node = eb32sc_next(node, scope);
	}
	fprintf(file, "}\n");
}

/* This function compares a sample word possibly followed by blanks to another
 * clean word. The compare is case-insensitive. 1 is returned if both are equal,
 * otherwise zero. This intends to be used when checking HTTP headers for some
 * values. Note that it validates a word followed only by blanks but does not
 * validate a word followed by blanks then other chars.
 */
int word_match(const char *sample, int slen, const char *word, int wlen)
{
	if (slen < wlen)
		return 0;

	while (wlen) {
		char c = *sample ^ *word;
		if (c && c != ('A' ^ 'a'))
			return 0;
		sample++;
		word++;
		slen--;
		wlen--;
	}

	while (slen) {
		if (*sample != ' ' && *sample != '\t')
			return 0;
		sample++;
		slen--;
	}
	return 1;
}

/* Converts any text-formatted IPv4 address to a host-order IPv4 address. It
 * is particularly fast because it avoids expensive operations such as
 * multiplies, which are optimized away at the end. It requires a properly
 * formatted address though (3 points).
 */
unsigned int inetaddr_host(const char *text)
{
	const unsigned int ascii_zero = ('0' << 24) | ('0' << 16) | ('0' << 8) | '0';
	register unsigned int dig100, dig10, dig1;
	int s;
	const char *p, *d;

	dig1 = dig10 = dig100 = ascii_zero;
	s = 24;

	p = text;
	while (1) {
		if (((unsigned)(*p - '0')) <= 9) {
			p++;
			continue;
		}

		/* here, we have a complete byte between <text> and <p> (exclusive) */
		if (p == text)
			goto end;

		d = p - 1;
		dig1   |= (unsigned int)(*d << s);
		if (d == text)
			goto end;

		d--;
		dig10  |= (unsigned int)(*d << s);
		if (d == text)
			goto end;

		d--;
		dig100 |= (unsigned int)(*d << s);
	end:
		if (!s || *p != '.')
			break;

		s -= 8;
		text = ++p;
	}

	dig100 -= ascii_zero;
	dig10  -= ascii_zero;
	dig1   -= ascii_zero;
	return ((dig100 * 10) + dig10) * 10 + dig1;
}

/*
 * Idem except the first unparsed character has to be passed in <stop>.
 */
unsigned int inetaddr_host_lim(const char *text, const char *stop)
{
	const unsigned int ascii_zero = ('0' << 24) | ('0' << 16) | ('0' << 8) | '0';
	register unsigned int dig100, dig10, dig1;
	int s;
	const char *p, *d;

	dig1 = dig10 = dig100 = ascii_zero;
	s = 24;

	p = text;
	while (1) {
		if (((unsigned)(*p - '0')) <= 9 && p < stop) {
			p++;
			continue;
		}

		/* here, we have a complete byte between <text> and <p> (exclusive) */
		if (p == text)
			goto end;

		d = p - 1;
		dig1   |= (unsigned int)(*d << s);
		if (d == text)
			goto end;

		d--;
		dig10  |= (unsigned int)(*d << s);
		if (d == text)
			goto end;

		d--;
		dig100 |= (unsigned int)(*d << s);
	end:
		if (!s || p == stop || *p != '.')
			break;

		s -= 8;
		text = ++p;
	}

	dig100 -= ascii_zero;
	dig10  -= ascii_zero;
	dig1   -= ascii_zero;
	return ((dig100 * 10) + dig10) * 10 + dig1;
}

/*
 * Idem except the pointer to first unparsed byte is returned into <ret> which
 * must not be NULL.
 */
unsigned int inetaddr_host_lim_ret(char *text, char *stop, char **ret)
{
	const unsigned int ascii_zero = ('0' << 24) | ('0' << 16) | ('0' << 8) | '0';
	register unsigned int dig100, dig10, dig1;
	int s;
	char *p, *d;

	dig1 = dig10 = dig100 = ascii_zero;
	s = 24;

	p = text;
	while (1) {
		if (((unsigned)(*p - '0')) <= 9 && p < stop) {
			p++;
			continue;
		}

		/* here, we have a complete byte between <text> and <p> (exclusive) */
		if (p == text)
			goto end;

		d = p - 1;
		dig1   |= (unsigned int)(*d << s);
		if (d == text)
			goto end;

		d--;
		dig10  |= (unsigned int)(*d << s);
		if (d == text)
			goto end;

		d--;
		dig100 |= (unsigned int)(*d << s);
	end:
		if (!s || p == stop || *p != '.')
			break;

		s -= 8;
		text = ++p;
	}

	*ret = p;
	dig100 -= ascii_zero;
	dig10  -= ascii_zero;
	dig1   -= ascii_zero;
	return ((dig100 * 10) + dig10) * 10 + dig1;
}

/* Convert a fixed-length string to an IP address. Returns 0 in case of error,
 * or the number of chars read in case of success. Maybe this could be replaced
 * by one of the functions above. Also, apparently this function does not support
 * hosts above 255 and requires exactly 4 octets.
 * The destination is only modified on success.
 */
int buf2ip(const char *buf, size_t len, struct in_addr *dst)
{
	const char *addr;
	int saw_digit, octets, ch;
	u_char tmp[4], *tp;
	const char *cp = buf;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;

	for (addr = buf; addr - buf < len; addr++) {
		unsigned char digit = (ch = *addr) - '0';

		if (digit > 9 && ch != '.')
			break;

		if (digit <= 9) {
			u_int new = *tp * 10 + digit;

			if (new > 255)
				return 0;

			*tp = new;

			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;

			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}

	if (octets < 4)
		return 0;

	memcpy(&dst->s_addr, tmp, 4);
	return addr - cp;
}

/* This function converts the string in <buf> of the len <len> to
 * struct in6_addr <dst> which must be allocated by the caller.
 * This function returns 1 in success case, otherwise zero.
 * The destination is only modified on success.
 */
int buf2ip6(const char *buf, size_t len, struct in6_addr *dst)
{
	char null_term_ip6[INET6_ADDRSTRLEN + 1];
	struct in6_addr out;

	if (len > INET6_ADDRSTRLEN)
		return 0;

	memcpy(null_term_ip6, buf, len);
	null_term_ip6[len] = '\0';

	if (!inet_pton(AF_INET6, null_term_ip6, &out))
		return 0;

	*dst = out;
	return 1;
}

/* To be used to quote config arg positions. Returns the short string at <ptr>
 * surrounded by simple quotes if <ptr> is valid and non-empty, or "end of line"
 * if ptr is NULL or empty. The string is locally allocated.
 */
const char *quote_arg(const char *ptr)
{
	static THREAD_LOCAL char val[32];
	int i;

	if (!ptr || !*ptr)
		return "end of line";
	val[0] = '\'';
	for (i = 1; i < sizeof(val) - 2 && *ptr; i++)
		val[i] = *ptr++;
	val[i++] = '\'';
	val[i] = '\0';
	return val;
}

/* returns an operator among STD_OP_* for string <str> or < 0 if unknown */
int get_std_op(const char *str)
{
	int ret = -1;

	if (*str == 'e' && str[1] == 'q')
		ret = STD_OP_EQ;
	else if (*str == 'n' && str[1] == 'e')
		ret = STD_OP_NE;
	else if (*str == 'l') {
		if (str[1] == 'e') ret = STD_OP_LE;
		else if (str[1] == 't') ret = STD_OP_LT;
	}
	else if (*str == 'g') {
		if (str[1] == 'e') ret = STD_OP_GE;
		else if (str[1] == 't') ret = STD_OP_GT;
	}

	if (ret == -1 || str[2] != '\0')
		return -1;
	return ret;
}

/* hash a 32-bit integer to another 32-bit integer */
unsigned int full_hash(unsigned int a)
{
	return __full_hash(a);
}

/* Return the bit position in mask <m> of the nth bit set of rank <r>, between
 * 0 and LONGBITS-1 included, starting from the left. For example ranks 0,1,2,3
 * for mask 0x55 will be 6, 4, 2 and 0 respectively. This algorithm is based on
 * a popcount variant and is described here :
 *   https://graphics.stanford.edu/~seander/bithacks.html
 */
unsigned int mask_find_rank_bit(unsigned int r, unsigned long m)
{
	unsigned long a, b, c, d;
	unsigned int s;
	unsigned int t;

	a =  m - ((m >> 1) & ~0UL/3);
	b = (a & ~0UL/5) + ((a >> 2) & ~0UL/5);
	c = (b + (b >> 4)) & ~0UL/0x11;
	d = (c + (c >> 8)) & ~0UL/0x101;

	r++; // make r be 1..64

	t = 0;
	s = LONGBITS;
	if (s > 32) {
		unsigned long d2 = (d >> 16) >> 16;
		t = d2 + (d2 >> 16);
		s -= ((t - r) & 256) >> 3; r -= (t & ((t - r) >> 8));
	}

	t  = (d >> (s - 16)) & 0xff;
	s -= ((t - r) & 256) >> 4; r -= (t & ((t - r) >> 8));
	t  = (c >> (s - 8)) & 0xf;
	s -= ((t - r) & 256) >> 5; r -= (t & ((t - r) >> 8));
	t  = (b >> (s - 4)) & 0x7;
	s -= ((t - r) & 256) >> 6; r -= (t & ((t - r) >> 8));
	t  = (a >> (s - 2)) & 0x3;
	s -= ((t - r) & 256) >> 7; r -= (t & ((t - r) >> 8));
	t  = (m >> (s - 1)) & 0x1;
	s -= ((t - r) & 256) >> 8;

       return s - 1;
}

/* Same as mask_find_rank_bit() above but makes use of pre-computed bitmaps
 * based on <m>, in <a..d>. These ones must be updated whenever <m> changes
 * using mask_prep_rank_map() below.
 */
unsigned int mask_find_rank_bit_fast(unsigned int r, unsigned long m,
                                     unsigned long a, unsigned long b,
                                     unsigned long c, unsigned long d)
{
	unsigned int s;
	unsigned int t;

	r++; // make r be 1..64

	t = 0;
	s = LONGBITS;
	if (s > 32) {
		unsigned long d2 = (d >> 16) >> 16;
		t = d2 + (d2 >> 16);
		s -= ((t - r) & 256) >> 3; r -= (t & ((t - r) >> 8));
	}

	t  = (d >> (s - 16)) & 0xff;
	s -= ((t - r) & 256) >> 4; r -= (t & ((t - r) >> 8));
	t  = (c >> (s - 8)) & 0xf;
	s -= ((t - r) & 256) >> 5; r -= (t & ((t - r) >> 8));
	t  = (b >> (s - 4)) & 0x7;
	s -= ((t - r) & 256) >> 6; r -= (t & ((t - r) >> 8));
	t  = (a >> (s - 2)) & 0x3;
	s -= ((t - r) & 256) >> 7; r -= (t & ((t - r) >> 8));
	t  = (m >> (s - 1)) & 0x1;
	s -= ((t - r) & 256) >> 8;

	return s - 1;
}

/* Prepare the bitmaps used by the fast implementation of the find_rank_bit()
 * above.
 */
void mask_prep_rank_map(unsigned long m,
                        unsigned long *a, unsigned long *b,
                        unsigned long *c, unsigned long *d)
{
	*a =  m - ((m >> 1) & ~0UL/3);
	*b = (*a & ~0UL/5) + ((*a >> 2) & ~0UL/5);
	*c = (*b + (*b >> 4)) & ~0UL/0x11;
	*d = (*c + (*c >> 8)) & ~0UL/0x101;
}

/* Return non-zero if IPv4 address is part of the network,
 * otherwise zero. Note that <addr> may not necessarily be aligned
 * while the two other ones must.
 */
int in_net_ipv4(const void *addr, const struct in_addr *mask, const struct in_addr *net)
{
	struct in_addr addr_copy;

	memcpy(&addr_copy, addr, sizeof(addr_copy));
	return((addr_copy.s_addr & mask->s_addr) == (net->s_addr & mask->s_addr));
}

/* Return non-zero if IPv6 address is part of the network,
 * otherwise zero. Note that <addr> may not necessarily be aligned
 * while the two other ones must.
 */
int in_net_ipv6(const void *addr, const struct in6_addr *mask, const struct in6_addr *net)
{
	int i;
	struct in6_addr addr_copy;

	memcpy(&addr_copy, addr, sizeof(addr_copy));
	for (i = 0; i < sizeof(struct in6_addr) / sizeof(int); i++)
		if (((((int *)&addr_copy)[i] & ((int *)mask)[i])) !=
		    (((int *)net)[i] & ((int *)mask)[i]))
			return 0;
	return 1;
}

/* RFC 4291 prefix */
const char rfc4291_pfx[] = { 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0xFF, 0xFF };

/* Map IPv4 address on IPv6 address, as specified in RFC 3513.
 * Input and output may overlap.
 */
void v4tov6(struct in6_addr *sin6_addr, struct in_addr *sin_addr)
{
	struct in_addr tmp_addr;

	tmp_addr.s_addr = sin_addr->s_addr;
	memcpy(sin6_addr->s6_addr, rfc4291_pfx, sizeof(rfc4291_pfx));
	memcpy(sin6_addr->s6_addr+12, &tmp_addr.s_addr, 4);
}

/* Map IPv6 address on IPv4 address, as specified in RFC 3513.
 * Return true if conversion is possible and false otherwise.
 */
int v6tov4(struct in_addr *sin_addr, struct in6_addr *sin6_addr)
{
	if (memcmp(sin6_addr->s6_addr, rfc4291_pfx, sizeof(rfc4291_pfx)) == 0) {
		memcpy(&(sin_addr->s_addr), &(sin6_addr->s6_addr[12]),
			sizeof(struct in_addr));
		return 1;
	}

	return 0;
}

/* compare two struct sockaddr_storage and return:
 *  0 (true)  if the addr is the same in both
 *  1 (false) if the addr is not the same in both
 *  -1 (unable) if one of the addr is not AF_INET*
 */
int ipcmp(struct sockaddr_storage *ss1, struct sockaddr_storage *ss2)
{
	if ((ss1->ss_family != AF_INET) && (ss1->ss_family != AF_INET6))
		return -1;

	if ((ss2->ss_family != AF_INET) && (ss2->ss_family != AF_INET6))
		return -1;

	if (ss1->ss_family != ss2->ss_family)
		return 1;

	switch (ss1->ss_family) {
		case AF_INET:
			return memcmp(&((struct sockaddr_in *)ss1)->sin_addr,
				      &((struct sockaddr_in *)ss2)->sin_addr,
				      sizeof(struct in_addr)) != 0;
		case AF_INET6:
			return memcmp(&((struct sockaddr_in6 *)ss1)->sin6_addr,
				      &((struct sockaddr_in6 *)ss2)->sin6_addr,
				      sizeof(struct in6_addr)) != 0;
	}

	return 1;
}

/* copy IP address from <source> into <dest>
 * The caller must allocate and clear <dest> before calling.
 * The source must be in either AF_INET or AF_INET6 family, or the destination
 * address will be undefined. If the destination address used to hold a port,
 * it is preserved, so that this function can be used to switch to another
 * address family with no risk. Returns a pointer to the destination.
 */
struct sockaddr_storage *ipcpy(struct sockaddr_storage *source, struct sockaddr_storage *dest)
{
	int prev_port;

	prev_port = get_net_port(dest);
	memset(dest, 0, sizeof(*dest));
	dest->ss_family = source->ss_family;

	/* copy new addr and apply it */
	switch (source->ss_family) {
		case AF_INET:
			((struct sockaddr_in *)dest)->sin_addr.s_addr = ((struct sockaddr_in *)source)->sin_addr.s_addr;
			((struct sockaddr_in *)dest)->sin_port = prev_port;
			break;
		case AF_INET6:
			memcpy(((struct sockaddr_in6 *)dest)->sin6_addr.s6_addr, ((struct sockaddr_in6 *)source)->sin6_addr.s6_addr, sizeof(struct in6_addr));
			((struct sockaddr_in6 *)dest)->sin6_port = prev_port;
			break;
	}

	return dest;
}

char *human_time(int t, short hz_div) {
	static char rv[sizeof("24855d23h")+1];	// longest of "23h59m" and "59m59s"
	char *p = rv;
	char *end = rv + sizeof(rv);
	int cnt=2;				// print two numbers

	if (unlikely(t < 0 || hz_div <= 0)) {
		snprintf(p, end - p, "?");
		return rv;
	}

	if (unlikely(hz_div > 1))
		t /= hz_div;

	if (t >= DAY) {
		p += snprintf(p, end - p, "%dd", t / DAY);
		cnt--;
	}

	if (cnt && t % DAY / HOUR) {
		p += snprintf(p, end - p, "%dh", t % DAY / HOUR);
		cnt--;
	}

	if (cnt && t % HOUR / MINUTE) {
		p += snprintf(p, end - p, "%dm", t % HOUR / MINUTE);
		cnt--;
	}

	if ((cnt && t % MINUTE) || !t)					// also display '0s'
		p += snprintf(p, end - p, "%ds", t % MINUTE / SEC);

	return rv;
}

const char *monthname[12] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* date2str_log: write a date in the format :
 * 	sprintf(str, "%02d/%s/%04d:%02d:%02d:%02d.%03d",
 *		tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
 *		tm.tm_hour, tm.tm_min, tm.tm_sec, (int)date.tv_usec/1000);
 *
 * without using sprintf. return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *date2str_log(char *dst, const struct tm *tm, const struct timeval *date, size_t size)
{

	if (size < 25) /* the size is fixed: 24 chars + \0 */
		return NULL;

	dst = utoa_pad((unsigned int)tm->tm_mday, dst, 3); // day
	if (!dst)
		return NULL;
	*dst++ = '/';

	memcpy(dst, monthname[tm->tm_mon], 3); // month
	dst += 3;
	*dst++ = '/';

	dst = utoa_pad((unsigned int)tm->tm_year+1900, dst, 5); // year
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_hour, dst, 3); // hour
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_min, dst, 3); // minutes
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_sec, dst, 3); // secondes
	if (!dst)
		return NULL;
	*dst++ = '.';

	dst = utoa_pad((unsigned int)(date->tv_usec/1000)%1000, dst, 4); // milliseconds
	if (!dst)
		return NULL;
	*dst = '\0';

	return dst;
}

/* Base year used to compute leap years */
#define TM_YEAR_BASE 1900

/* Return the difference in seconds between two times (leap seconds are ignored).
 * Retrieved from glibc 2.18 source code.
 */
static int my_tm_diff(const struct tm *a, const struct tm *b)
{
	/* Compute intervening leap days correctly even if year is negative.
	 * Take care to avoid int overflow in leap day calculations,
	 * but it's OK to assume that A and B are close to each other.
	 */
	int a4 = (a->tm_year >> 2) + (TM_YEAR_BASE >> 2) - ! (a->tm_year & 3);
	int b4 = (b->tm_year >> 2) + (TM_YEAR_BASE >> 2) - ! (b->tm_year & 3);
	int a100 = a4 / 25 - (a4 % 25 < 0);
	int b100 = b4 / 25 - (b4 % 25 < 0);
	int a400 = a100 >> 2;
	int b400 = b100 >> 2;
	int intervening_leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);
	int years = a->tm_year - b->tm_year;
	int days = (365 * years + intervening_leap_days
	         + (a->tm_yday - b->tm_yday));
	return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour))
	       + (a->tm_min - b->tm_min))
	       + (a->tm_sec - b->tm_sec));
}

/* Return the GMT offset for a specific local time.
 * Both t and tm must represent the same time.
 * The string returned has the same format as returned by strftime(... "%z", tm).
 * Offsets are kept in an internal cache for better performances.
 */
const char *get_gmt_offset(time_t t, struct tm *tm)
{
	/* Cache offsets from GMT (depending on whether DST is active or not) */
	static THREAD_LOCAL char gmt_offsets[2][5+1] = { "", "" };

	char *gmt_offset;
	struct tm tm_gmt;
	int diff;
	int isdst = tm->tm_isdst;

	/* Pretend DST not active if its status is unknown */
	if (isdst < 0)
		isdst = 0;

	/* Fetch the offset and initialize it if needed */
	gmt_offset = gmt_offsets[isdst & 0x01];
	if (unlikely(!*gmt_offset)) {
		get_gmtime(t, &tm_gmt);
		diff = my_tm_diff(tm, &tm_gmt);
		if (diff < 0) {
			diff = -diff;
			*gmt_offset = '-';
		} else {
			*gmt_offset = '+';
		}
		diff %= 86400U;
		diff /= 60; /* Convert to minutes */
		snprintf(gmt_offset+1, 4+1, "%02d%02d", diff/60, diff%60);
	}

	return gmt_offset;
}

/* gmt2str_log: write a date in the format :
 * "%02d/%s/%04d:%02d:%02d:%02d +0000" without using snprintf
 * return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *gmt2str_log(char *dst, struct tm *tm, size_t size)
{
	if (size < 27) /* the size is fixed: 26 chars + \0 */
		return NULL;

	dst = utoa_pad((unsigned int)tm->tm_mday, dst, 3); // day
	if (!dst)
		return NULL;
	*dst++ = '/';

	memcpy(dst, monthname[tm->tm_mon], 3); // month
	dst += 3;
	*dst++ = '/';

	dst = utoa_pad((unsigned int)tm->tm_year+1900, dst, 5); // year
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_hour, dst, 3); // hour
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_min, dst, 3); // minutes
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_sec, dst, 3); // secondes
	if (!dst)
		return NULL;
	*dst++ = ' ';
	*dst++ = '+';
	*dst++ = '0';
	*dst++ = '0';
	*dst++ = '0';
	*dst++ = '0';
	*dst = '\0';

	return dst;
}

/* localdate2str_log: write a date in the format :
 * "%02d/%s/%04d:%02d:%02d:%02d +0000(local timezone)" without using snprintf
 * Both t and tm must represent the same time.
 * return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *localdate2str_log(char *dst, time_t t, struct tm *tm, size_t size)
{
	const char *gmt_offset;
	if (size < 27) /* the size is fixed: 26 chars + \0 */
		return NULL;

	gmt_offset = get_gmt_offset(t, tm);

	dst = utoa_pad((unsigned int)tm->tm_mday, dst, 3); // day
	if (!dst)
		return NULL;
	*dst++ = '/';

	memcpy(dst, monthname[tm->tm_mon], 3); // month
	dst += 3;
	*dst++ = '/';

	dst = utoa_pad((unsigned int)tm->tm_year+1900, dst, 5); // year
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_hour, dst, 3); // hour
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_min, dst, 3); // minutes
	if (!dst)
		return NULL;
	*dst++ = ':';

	dst = utoa_pad((unsigned int)tm->tm_sec, dst, 3); // secondes
	if (!dst)
		return NULL;
	*dst++ = ' ';

	memcpy(dst, gmt_offset, 5); // Offset from local time to GMT
	dst += 5;
	*dst = '\0';

	return dst;
}

/* Returns the number of seconds since 01/01/1970 0:0:0 GMT for GMT date <tm>.
 * It is meant as a portable replacement for timegm() for use with valid inputs.
 * Returns undefined results for invalid dates (eg: months out of range 0..11).
 */
time_t my_timegm(const struct tm *tm)
{
	/* Each month has 28, 29, 30 or 31 days, or 28+N. The date in the year
	 * is thus (current month - 1)*28 + cumulated_N[month] to count the
	 * sum of the extra N days for elapsed months. The sum of all these N
	 * days doesn't exceed 30 for a complete year (366-12*28) so it fits
	 * in a 5-bit word. This means that with 60 bits we can represent a
	 * matrix of all these values at once, which is fast and efficient to
	 * access. The extra February day for leap years is not counted here.
	 *
	 * Jan : none      =  0 (0)
	 * Feb : Jan       =  3 (3)
	 * Mar : Jan..Feb  =  3 (3 + 0)
	 * Apr : Jan..Mar  =  6 (3 + 0 + 3)
	 * May : Jan..Apr  =  8 (3 + 0 + 3 + 2)
	 * Jun : Jan..May  = 11 (3 + 0 + 3 + 2 + 3)
	 * Jul : Jan..Jun  = 13 (3 + 0 + 3 + 2 + 3 + 2)
	 * Aug : Jan..Jul  = 16 (3 + 0 + 3 + 2 + 3 + 2 + 3)
	 * Sep : Jan..Aug  = 19 (3 + 0 + 3 + 2 + 3 + 2 + 3 + 3)
	 * Oct : Jan..Sep  = 21 (3 + 0 + 3 + 2 + 3 + 2 + 3 + 3 + 2)
	 * Nov : Jan..Oct  = 24 (3 + 0 + 3 + 2 + 3 + 2 + 3 + 3 + 2 + 3)
	 * Dec : Jan..Nov  = 26 (3 + 0 + 3 + 2 + 3 + 2 + 3 + 3 + 2 + 3 + 2)
	 */
	uint64_t extra =
		( 0ULL <<  0*5) + ( 3ULL <<  1*5) + ( 3ULL <<  2*5) + /* Jan, Feb, Mar, */
		( 6ULL <<  3*5) + ( 8ULL <<  4*5) + (11ULL <<  5*5) + /* Apr, May, Jun, */
		(13ULL <<  6*5) + (16ULL <<  7*5) + (19ULL <<  8*5) + /* Jul, Aug, Sep, */
		(21ULL <<  9*5) + (24ULL << 10*5) + (26ULL << 11*5);  /* Oct, Nov, Dec, */

	unsigned int y = tm->tm_year + 1900;
	unsigned int m = tm->tm_mon;
	unsigned long days = 0;

	/* days since 1/1/1970 for full years */
	days += days_since_zero(y) - days_since_zero(1970);

	/* days for full months in the current year */
	days += 28 * m + ((extra >> (m * 5)) & 0x1f);

	/* count + 1 after March for leap years. A leap year is a year multiple
	 * of 4, unless it's multiple of 100 without being multiple of 400. 2000
	 * is leap, 1900 isn't, 1904 is.
	 */
	if ((m > 1) && !(y & 3) && ((y % 100) || !(y % 400)))
		days++;

	days += tm->tm_mday - 1;
	return days * 86400ULL + tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
}

/* This function check a char. It returns true and updates
 * <date> and <len> pointer to the new position if the
 * character is found.
 */
static inline int parse_expect_char(const char **date, int *len, char c)
{
	if (*len < 1 || **date != c)
		return 0;
	(*len)--;
	(*date)++;
	return 1;
}

/* This function expects a string <str> of len <l>. It return true and updates.
 * <date> and <len> if the string matches, otherwise, it returns false.
 */
static inline int parse_strcmp(const char **date, int *len, char *str, int l)
{
	if (*len < l || strncmp(*date, str, l) != 0)
		return 0;
	(*len) -= l;
	(*date) += l;
	return 1;
}

/* This macro converts 3 chars name in integer. */
#define STR2I3(__a, __b, __c) ((__a) * 65536 + (__b) * 256 + (__c))

/* day-name     = %x4D.6F.6E ; "Mon", case-sensitive
 *              / %x54.75.65 ; "Tue", case-sensitive
 *              / %x57.65.64 ; "Wed", case-sensitive
 *              / %x54.68.75 ; "Thu", case-sensitive
 *              / %x46.72.69 ; "Fri", case-sensitive
 *              / %x53.61.74 ; "Sat", case-sensitive
 *              / %x53.75.6E ; "Sun", case-sensitive
 *
 * This array must be alphabetically sorted
 */
static inline int parse_http_dayname(const char **date, int *len, struct tm *tm)
{
	if (*len < 3)
		return 0;
	switch (STR2I3((*date)[0], (*date)[1], (*date)[2])) {
	case STR2I3('M','o','n'): tm->tm_wday = 1;  break;
	case STR2I3('T','u','e'): tm->tm_wday = 2;  break;
	case STR2I3('W','e','d'): tm->tm_wday = 3;  break;
	case STR2I3('T','h','u'): tm->tm_wday = 4;  break;
	case STR2I3('F','r','i'): tm->tm_wday = 5;  break;
	case STR2I3('S','a','t'): tm->tm_wday = 6;  break;
	case STR2I3('S','u','n'): tm->tm_wday = 7;  break;
	default: return 0;
	}
	*len -= 3;
	*date  += 3;
	return 1;
}

/* month        = %x4A.61.6E ; "Jan", case-sensitive
 *              / %x46.65.62 ; "Feb", case-sensitive
 *              / %x4D.61.72 ; "Mar", case-sensitive
 *              / %x41.70.72 ; "Apr", case-sensitive
 *              / %x4D.61.79 ; "May", case-sensitive
 *              / %x4A.75.6E ; "Jun", case-sensitive
 *              / %x4A.75.6C ; "Jul", case-sensitive
 *              / %x41.75.67 ; "Aug", case-sensitive
 *              / %x53.65.70 ; "Sep", case-sensitive
 *              / %x4F.63.74 ; "Oct", case-sensitive
 *              / %x4E.6F.76 ; "Nov", case-sensitive
 *              / %x44.65.63 ; "Dec", case-sensitive
 *
 * This array must be alphabetically sorted
 */
static inline int parse_http_monthname(const char **date, int *len, struct tm *tm)
{
	if (*len < 3)
		return 0;
	switch (STR2I3((*date)[0], (*date)[1], (*date)[2])) {
	case STR2I3('J','a','n'): tm->tm_mon = 0;  break;
	case STR2I3('F','e','b'): tm->tm_mon = 1;  break;
	case STR2I3('M','a','r'): tm->tm_mon = 2;  break;
	case STR2I3('A','p','r'): tm->tm_mon = 3;  break;
	case STR2I3('M','a','y'): tm->tm_mon = 4;  break;
	case STR2I3('J','u','n'): tm->tm_mon = 5;  break;
	case STR2I3('J','u','l'): tm->tm_mon = 6;  break;
	case STR2I3('A','u','g'): tm->tm_mon = 7;  break;
	case STR2I3('S','e','p'): tm->tm_mon = 8;  break;
	case STR2I3('O','c','t'): tm->tm_mon = 9;  break;
	case STR2I3('N','o','v'): tm->tm_mon = 10; break;
	case STR2I3('D','e','c'): tm->tm_mon = 11; break;
	default: return 0;
	}
	*len -= 3;
	*date  += 3;
	return 1;
}

/* day-name-l   = %x4D.6F.6E.64.61.79    ; "Monday", case-sensitive
 *        / %x54.75.65.73.64.61.79       ; "Tuesday", case-sensitive
 *        / %x57.65.64.6E.65.73.64.61.79 ; "Wednesday", case-sensitive
 *        / %x54.68.75.72.73.64.61.79    ; "Thursday", case-sensitive
 *        / %x46.72.69.64.61.79          ; "Friday", case-sensitive
 *        / %x53.61.74.75.72.64.61.79    ; "Saturday", case-sensitive
 *        / %x53.75.6E.64.61.79          ; "Sunday", case-sensitive
 *
 * This array must be alphabetically sorted
 */
static inline int parse_http_ldayname(const char **date, int *len, struct tm *tm)
{
	if (*len < 6) /* Minimum length. */
		return 0;
	switch (STR2I3((*date)[0], (*date)[1], (*date)[2])) {
	case STR2I3('M','o','n'):
		RET0_UNLESS(parse_strcmp(date, len, "Monday", 6));
		tm->tm_wday = 1;
		return 1;
	case STR2I3('T','u','e'):
		RET0_UNLESS(parse_strcmp(date, len, "Tuesday", 7));
		tm->tm_wday = 2;
		return 1;
	case STR2I3('W','e','d'):
		RET0_UNLESS(parse_strcmp(date, len, "Wednesday", 9));
		tm->tm_wday = 3;
		return 1;
	case STR2I3('T','h','u'):
		RET0_UNLESS(parse_strcmp(date, len, "Thursday", 8));
		tm->tm_wday = 4;
		return 1;
	case STR2I3('F','r','i'):
		RET0_UNLESS(parse_strcmp(date, len, "Friday", 6));
		tm->tm_wday = 5;
		return 1;
	case STR2I3('S','a','t'):
		RET0_UNLESS(parse_strcmp(date, len, "Saturday", 8));
		tm->tm_wday = 6;
		return 1;
	case STR2I3('S','u','n'):
		RET0_UNLESS(parse_strcmp(date, len, "Sunday", 6));
		tm->tm_wday = 7;
		return 1;
	}
	return 0;
}

/* This function parses exactly 1 digit and returns the numeric value in "digit". */
static inline int parse_digit(const char **date, int *len, int *digit)
{
	if (*len < 1 || **date < '0' || **date > '9')
		return 0;
	*digit = (**date - '0');
	(*date)++;
	(*len)--;
	return 1;
}

/* This function parses exactly 2 digits and returns the numeric value in "digit". */
static inline int parse_2digit(const char **date, int *len, int *digit)
{
	int value;

	RET0_UNLESS(parse_digit(date, len, &value));
	(*digit) = value * 10;
	RET0_UNLESS(parse_digit(date, len, &value));
	(*digit) += value;

	return 1;
}

/* This function parses exactly 4 digits and returns the numeric value in "digit". */
static inline int parse_4digit(const char **date, int *len, int *digit)
{
	int value;

	RET0_UNLESS(parse_digit(date, len, &value));
	(*digit) = value * 1000;

	RET0_UNLESS(parse_digit(date, len, &value));
	(*digit) += value * 100;

	RET0_UNLESS(parse_digit(date, len, &value));
	(*digit) += value * 10;

	RET0_UNLESS(parse_digit(date, len, &value));
	(*digit) += value;

	return 1;
}

/* time-of-day  = hour ":" minute ":" second
 *              ; 00:00:00 - 23:59:60 (leap second)
 *
 * hour         = 2DIGIT
 * minute       = 2DIGIT
 * second       = 2DIGIT
 */
static inline int parse_http_time(const char **date, int *len, struct tm *tm)
{
	RET0_UNLESS(parse_2digit(date, len, &tm->tm_hour)); /* hour 2DIGIT */
	RET0_UNLESS(parse_expect_char(date, len, ':'));     /* expect ":"  */
	RET0_UNLESS(parse_2digit(date, len, &tm->tm_min));  /* min 2DIGIT  */
	RET0_UNLESS(parse_expect_char(date, len, ':'));     /* expect ":"  */
	RET0_UNLESS(parse_2digit(date, len, &tm->tm_sec));  /* sec 2DIGIT  */
	return 1;
}

/* From RFC7231
 * https://tools.ietf.org/html/rfc7231#section-7.1.1.1
 *
 * IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT
 * ; fixed length/zone/capitalization subset of the format
 * ; see Section 3.3 of [RFC5322]
 *
 *
 * date1        = day SP month SP year
 *              ; e.g., 02 Jun 1982
 *
 * day          = 2DIGIT
 * year         = 4DIGIT
 *
 * GMT          = %x47.4D.54 ; "GMT", case-sensitive
 *
 * time-of-day  = hour ":" minute ":" second
 *              ; 00:00:00 - 23:59:60 (leap second)
 *
 * hour         = 2DIGIT
 * minute       = 2DIGIT
 * second       = 2DIGIT
 *
 * DIGIT        = decimal 0-9
 */
int parse_imf_date(const char *date, int len, struct tm *tm)
{
	/* tm_gmtoff, if present, ought to be zero'ed */
	memset(tm, 0, sizeof(*tm));

	RET0_UNLESS(parse_http_dayname(&date, &len, tm));     /* day-name */
	RET0_UNLESS(parse_expect_char(&date, &len, ','));     /* expect "," */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_2digit(&date, &len, &tm->tm_mday)); /* day 2DIGIT */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_http_monthname(&date, &len, tm));   /* Month */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_4digit(&date, &len, &tm->tm_year)); /* year = 4DIGIT */
	tm->tm_year -= 1900;
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_http_time(&date, &len, tm));        /* Parse time. */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_strcmp(&date, &len, "GMT", 3));     /* GMT = %x47.4D.54 ; "GMT", case-sensitive */
	tm->tm_isdst = -1;
	return 1;
}

/* From RFC7231
 * https://tools.ietf.org/html/rfc7231#section-7.1.1.1
 *
 * rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT
 * date2        = day "-" month "-" 2DIGIT
 *              ; e.g., 02-Jun-82
 *
 * day          = 2DIGIT
 */
int parse_rfc850_date(const char *date, int len, struct tm *tm)
{
	int year;

	/* tm_gmtoff, if present, ought to be zero'ed */
	memset(tm, 0, sizeof(*tm));

	RET0_UNLESS(parse_http_ldayname(&date, &len, tm));    /* Read the day name */
	RET0_UNLESS(parse_expect_char(&date, &len, ','));     /* expect "," */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_2digit(&date, &len, &tm->tm_mday)); /* day 2DIGIT */
	RET0_UNLESS(parse_expect_char(&date, &len, '-'));     /* expect "-" */
	RET0_UNLESS(parse_http_monthname(&date, &len, tm));   /* Month */
	RET0_UNLESS(parse_expect_char(&date, &len, '-'));     /* expect "-" */

	/* year = 2DIGIT
	 *
	 * Recipients of a timestamp value in rfc850-(*date) format, which uses a
	 * two-digit year, MUST interpret a timestamp that appears to be more
	 * than 50 years in the future as representing the most recent year in
	 * the past that had the same last two digits.
	 */
	RET0_UNLESS(parse_2digit(&date, &len, &tm->tm_year));

	/* expect SP */
	if (!parse_expect_char(&date, &len, ' ')) {
		/* Maybe we have the date with 4 digits. */
		RET0_UNLESS(parse_2digit(&date, &len, &year));
		tm->tm_year = (tm->tm_year * 100 + year) - 1900;
		/* expect SP */
		RET0_UNLESS(parse_expect_char(&date, &len, ' '));
	} else {
		/* I fix 60 as pivot: >60: +1900, <60: +2000. Note that the
		 * tm_year is the number of year since 1900, so for +1900, we
		 * do nothing, and for +2000, we add 100.
		 */
		if (tm->tm_year <= 60)
			tm->tm_year += 100;
	}

	RET0_UNLESS(parse_http_time(&date, &len, tm));    /* Parse time. */
	RET0_UNLESS(parse_expect_char(&date, &len, ' ')); /* expect SP */
	RET0_UNLESS(parse_strcmp(&date, &len, "GMT", 3)); /* GMT = %x47.4D.54 ; "GMT", case-sensitive */
	tm->tm_isdst = -1;

	return 1;
}

/* From RFC7231
 * https://tools.ietf.org/html/rfc7231#section-7.1.1.1
 *
 * asctime-date = day-name SP date3 SP time-of-day SP year
 * date3        = month SP ( 2DIGIT / ( SP 1DIGIT ))
 *              ; e.g., Jun  2
 *
 * HTTP-date is case sensitive.  A sender MUST NOT generate additional
 * whitespace in an HTTP-date beyond that specifically included as SP in
 * the grammar.
 */
int parse_asctime_date(const char *date, int len, struct tm *tm)
{
	/* tm_gmtoff, if present, ought to be zero'ed */
	memset(tm, 0, sizeof(*tm));

	RET0_UNLESS(parse_http_dayname(&date, &len, tm));   /* day-name */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));   /* expect SP */
	RET0_UNLESS(parse_http_monthname(&date, &len, tm)); /* expect month */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));   /* expect SP */

	/* expect SP and 1DIGIT or 2DIGIT */
	if (parse_expect_char(&date, &len, ' '))
		RET0_UNLESS(parse_digit(&date, &len, &tm->tm_mday));
	else
		RET0_UNLESS(parse_2digit(&date, &len, &tm->tm_mday));

	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_http_time(&date, &len, tm));        /* Parse time. */
	RET0_UNLESS(parse_expect_char(&date, &len, ' '));     /* expect SP */
	RET0_UNLESS(parse_4digit(&date, &len, &tm->tm_year)); /* year = 4DIGIT */
	tm->tm_year -= 1900;
	tm->tm_isdst = -1;
	return 1;
}

/* From RFC7231
 * https://tools.ietf.org/html/rfc7231#section-7.1.1.1
 *
 * HTTP-date    = IMF-fixdate / obs-date
 * obs-date     = rfc850-date / asctime-date
 *
 * parses an HTTP date in the RFC format and is accepted
 * alternatives. <date> is the strinf containing the date,
 * len is the len of the string. <tm> is filled with the
 * parsed time. We must considers this time as GMT.
 */
int parse_http_date(const char *date, int len, struct tm *tm)
{
	if (parse_imf_date(date, len, tm))
		return 1;

	if (parse_rfc850_date(date, len, tm))
		return 1;

	if (parse_asctime_date(date, len, tm))
		return 1;

	return 0;
}

/* Dynamically allocates a string of the proper length to hold the formatted
 * output. NULL is returned on error. The caller is responsible for freeing the
 * memory area using free(). The resulting string is returned in <out> if the
 * pointer is not NULL. A previous version of <out> might be used to build the
 * new string, and it will be freed before returning if it is not NULL, which
 * makes it possible to build complex strings from iterative calls without
 * having to care about freeing intermediate values, as in the example below :
 *
 *     memprintf(&err, "invalid argument: '%s'", arg);
 *     ...
 *     memprintf(&err, "parser said : <%s>\n", *err);
 *     ...
 *     free(*err);
 *
 * This means that <err> must be initialized to NULL before first invocation.
 * The return value also holds the allocated string, which eases error checking
 * and immediate consumption. If the output pointer is not used, NULL must be
 * passed instead and it will be ignored. The returned message will then also
 * be NULL so that the caller does not have to bother with freeing anything.
 *
 * It is also convenient to use it without any free except the last one :
 *    err = NULL;
 *    if (!fct1(err)) report(*err);
 *    if (!fct2(err)) report(*err);
 *    if (!fct3(err)) report(*err);
 *    free(*err);
 *
 * memprintf relies on memvprintf. This last version can be called from any
 * function with variadic arguments.
 */
char *memvprintf(char **out, const char *format, va_list orig_args)
{
	va_list args;
	char *ret = NULL;
	int allocated = 0;
	int needed = 0;

	if (!out)
		return NULL;

	do {
		char buf1;

		/* vsnprintf() will return the required length even when the
		 * target buffer is NULL. We do this in a loop just in case
		 * intermediate evaluations get wrong.
		 */
		va_copy(args, orig_args);
		needed = vsnprintf(ret ? ret : &buf1, allocated, format, args);
		va_end(args);
		if (needed < allocated) {
			/* Note: on Solaris 8, the first iteration always
			 * returns -1 if allocated is zero, so we force a
			 * retry.
			 */
			if (!allocated)
				needed = 0;
			else
				break;
		}

		allocated = needed + 1;
		ret = my_realloc2(ret, allocated);
	} while (ret);

	if (needed < 0) {
		/* an error was encountered */
		free(ret);
		ret = NULL;
	}

	if (out) {
		free(*out);
		*out = ret;
	}

	return ret;
}

char *memprintf(char **out, const char *format, ...)
{
	va_list args;
	char *ret = NULL;

	va_start(args, format);
	ret = memvprintf(out, format, args);
	va_end(args);

	return ret;
}

/* Used to add <level> spaces before each line of <out>, unless there is only one line.
 * The input argument is automatically freed and reassigned. The result will have to be
 * freed by the caller. It also supports being passed a NULL which results in the same
 * output.
 * Example of use :
 *   parse(cmd, &err); (callee: memprintf(&err, ...))
 *   fprintf(stderr, "Parser said: %s\n", indent_error(&err));
 *   free(err);
 */
char *indent_msg(char **out, int level)
{
	char *ret, *in, *p;
	int needed = 0;
	int lf = 0;
	int lastlf = 0;
	int len;

	if (!out || !*out)
		return NULL;

	in = *out - 1;
	while ((in = strchr(in + 1, '\n')) != NULL) {
		lastlf = in - *out;
		lf++;
	}

	if (!lf) /* single line, no LF, return it as-is */
		return *out;

	len = strlen(*out);

	if (lf == 1 && lastlf == len - 1) {
		/* single line, LF at end, strip it and return as-is */
		(*out)[lastlf] = 0;
		return *out;
	}

	/* OK now we have at least one LF, we need to process the whole string
	 * as a multi-line string. What we'll do :
	 *   - prefix with an LF if there is none
	 *   - add <level> spaces before each line
	 * This means at most ( 1 + level + (len-lf) + lf*<1+level) ) =
	 *   1 + level + len + lf * level = 1 + level * (lf + 1) + len.
	 */

	needed = 1 + level * (lf + 1) + len + 1;
	p = ret = malloc(needed);
	in = *out;

	/* skip initial LFs */
	while (*in == '\n')
		in++;

	/* copy each line, prefixed with LF and <level> spaces, and without the trailing LF */
	while (*in) {
		*p++ = '\n';
		memset(p, ' ', level);
		p += level;
		do {
			*p++ = *in++;
		} while (*in && *in != '\n');
		if (*in)
			in++;
	}
	*p = 0;

	free(*out);
	*out = ret;

	return ret;
}

/* makes a copy of message <in> into <out>, with each line prefixed with <pfx>
 * and end of lines replaced with <eol> if not 0. The first line to indent has
 * to be indicated in <first> (starts at zero), so that it is possible to skip
 * indenting the first line if it has to be appended after an existing message.
 * Empty strings are never indented, and NULL strings are considered empty both
 * for <in> and <pfx>. It returns non-zero if an EOL was appended as the last
 * character, non-zero otherwise.
 */
int append_prefixed_str(struct buffer *out, const char *in, const char *pfx, char eol, int first)
{
	int bol, lf;
	int pfxlen = pfx ? strlen(pfx) : 0;

	if (!in)
		return 0;

	bol = 1;
	lf = 0;
	while (*in) {
		if (bol && pfxlen) {
			if (first > 0)
				first--;
			else
				b_putblk(out, pfx, pfxlen);
			bol = 0;
		}

		lf = (*in == '\n');
		bol |= lf;
		b_putchr(out, (lf && eol) ? eol : *in);
		in++;
	}
	return lf;
}

/* removes environment variable <name> from the environment as found in
 * environ. This is only provided as an alternative for systems without
 * unsetenv() (old Solaris and AIX versions). THIS IS NOT THREAD SAFE.
 * The principle is to scan environ for each occurrence of variable name
 * <name> and to replace the matching pointers with the last pointer of
 * the array (since variables are not ordered).
 * It always returns 0 (success).
 */
int my_unsetenv(const char *name)
{
	extern char **environ;
	char **p = environ;
	int vars;
	int next;
	int len;

	len = strlen(name);
	for (vars = 0; p[vars]; vars++)
		;
	next = 0;
	while (next < vars) {
		if (strncmp(p[next], name, len) != 0 || p[next][len] != '=') {
			next++;
			continue;
		}
		if (next < vars - 1)
			p[next] = p[vars - 1];
		p[--vars] = NULL;
	}
	return 0;
}

/* Convert occurrences of environment variables in the input string to their
 * corresponding value. A variable is identified as a series of alphanumeric
 * characters or underscores following a '$' sign. The <in> string must be
 * free()able. NULL returns NULL. The resulting string might be reallocated if
 * some expansion is made. Variable names may also be enclosed into braces if
 * needed (eg: to concatenate alphanum characters).
 */
char *env_expand(char *in)
{
	char *txt_beg;
	char *out;
	char *txt_end;
	char *var_beg;
	char *var_end;
	char *value;
	char *next;
	int out_len;
	int val_len;

	if (!in)
		return in;

	value = out = NULL;
	out_len = 0;

	txt_beg = in;
	do {
		/* look for next '$' sign in <in> */
		for (txt_end = txt_beg; *txt_end && *txt_end != '$'; txt_end++);

		if (!*txt_end && !out) /* end and no expansion performed */
			return in;

		val_len = 0;
		next = txt_end;
		if (*txt_end == '$') {
			char save;

			var_beg = txt_end + 1;
			if (*var_beg == '{')
				var_beg++;

			var_end = var_beg;
			while (isalnum((unsigned char)*var_end) || *var_end == '_') {
				var_end++;
			}

			next = var_end;
			if (*var_end == '}' && (var_beg > txt_end + 1))
				next++;

			/* get value of the variable name at this location */
			save = *var_end;
			*var_end = '\0';
			value = getenv(var_beg);
			*var_end = save;
			val_len = value ? strlen(value) : 0;
		}

		out = my_realloc2(out, out_len + (txt_end - txt_beg) + val_len + 1);
		if (txt_end > txt_beg) {
			memcpy(out + out_len, txt_beg, txt_end - txt_beg);
			out_len += txt_end - txt_beg;
		}
		if (val_len) {
			memcpy(out + out_len, value, val_len);
			out_len += val_len;
		}
		out[out_len] = 0;
		txt_beg = next;
	} while (*txt_beg);

	/* here we know that <out> was allocated and that we don't need <in> anymore */
	free(in);
	return out;
}


/* same as strstr() but case-insensitive and with limit length */
const char *strnistr(const char *str1, int len_str1, const char *str2, int len_str2)
{
	char *pptr, *sptr, *start;
	unsigned int slen, plen;
	unsigned int tmp1, tmp2;

	if (str1 == NULL || len_str1 == 0) // search pattern into an empty string => search is not found
		return NULL;

	if (str2 == NULL || len_str2 == 0) // pattern is empty => every str1 match
		return str1;

	if (len_str1 < len_str2) // pattern is longer than string => search is not found
		return NULL;

	for (tmp1 = 0, start = (char *)str1, pptr = (char *)str2, slen = len_str1, plen = len_str2; slen >= plen; start++, slen--) {
		while (toupper((unsigned char)*start) != toupper((unsigned char)*str2)) {
			start++;
			slen--;
			tmp1++;

			if (tmp1 >= len_str1)
				return NULL;

			/* if pattern longer than string */
			if (slen < plen)
				return NULL;
		}

		sptr = start;
		pptr = (char *)str2;

		tmp2 = 0;
		while (toupper((unsigned char)*sptr) == toupper((unsigned char)*pptr)) {
			sptr++;
			pptr++;
			tmp2++;

			if (*pptr == '\0' || tmp2 == len_str2) /* end of pattern found */
				return start;
			if (*sptr == '\0' || tmp2 == len_str1) /* end of string found and the pattern is not fully found */
				return NULL;
		}
	}
	return NULL;
}

/* This function read the next valid utf8 char.
 * <s> is the byte srray to be decode, <len> is its length.
 * The function returns decoded char encoded like this:
 * The 4 msb are the return code (UTF8_CODE_*), the 4 lsb
 * are the length read. The decoded character is stored in <c>.
 */
unsigned char utf8_next(const char *s, int len, unsigned int *c)
{
	const unsigned char *p = (unsigned char *)s;
	int dec;
	unsigned char code = UTF8_CODE_OK;

	if (len < 1)
		return UTF8_CODE_OK;

	/* Check the type of UTF8 sequence
	 *
	 * 0... ....  0x00 <= x <= 0x7f : 1 byte: ascii char
	 * 10.. ....  0x80 <= x <= 0xbf : invalid sequence
	 * 110. ....  0xc0 <= x <= 0xdf : 2 bytes
	 * 1110 ....  0xe0 <= x <= 0xef : 3 bytes
	 * 1111 0...  0xf0 <= x <= 0xf7 : 4 bytes
	 * 1111 10..  0xf8 <= x <= 0xfb : 5 bytes
	 * 1111 110.  0xfc <= x <= 0xfd : 6 bytes
	 * 1111 111.  0xfe <= x <= 0xff : invalid sequence
	 */
	switch (*p) {
	case 0x00 ... 0x7f:
		*c = *p;
		return UTF8_CODE_OK | 1;

	case 0x80 ... 0xbf:
		*c = *p;
		return UTF8_CODE_BADSEQ | 1;

	case 0xc0 ... 0xdf:
		if (len < 2) {
			*c = *p;
			return UTF8_CODE_BADSEQ | 1;
		}
		*c = *p & 0x1f;
		dec = 1;
		break;

	case 0xe0 ... 0xef:
		if (len < 3) {
			*c = *p;
			return UTF8_CODE_BADSEQ | 1;
		}
		*c = *p & 0x0f;
		dec = 2;
		break;

	case 0xf0 ... 0xf7:
		if (len < 4) {
			*c = *p;
			return UTF8_CODE_BADSEQ | 1;
		}
		*c = *p & 0x07;
		dec = 3;
		break;

	case 0xf8 ... 0xfb:
		if (len < 5) {
			*c = *p;
			return UTF8_CODE_BADSEQ | 1;
		}
		*c = *p & 0x03;
		dec = 4;
		break;

	case 0xfc ... 0xfd:
		if (len < 6) {
			*c = *p;
			return UTF8_CODE_BADSEQ | 1;
		}
		*c = *p & 0x01;
		dec = 5;
		break;

	case 0xfe ... 0xff:
	default:
		*c = *p;
		return UTF8_CODE_BADSEQ | 1;
	}

	p++;

	while (dec > 0) {

		/* need 0x10 for the 2 first bits */
		if ( ( *p & 0xc0 ) != 0x80 )
			return UTF8_CODE_BADSEQ | ((p-(unsigned char *)s)&0xffff);

		/* add data at char */
		*c = ( *c << 6 ) | ( *p & 0x3f );

		dec--;
		p++;
	}

	/* Check ovelong encoding.
	 * 1 byte  : 5 + 6         : 11 : 0x80    ... 0x7ff
	 * 2 bytes : 4 + 6 + 6     : 16 : 0x800   ... 0xffff
	 * 3 bytes : 3 + 6 + 6 + 6 : 21 : 0x10000 ... 0x1fffff
	 */
	if ((                 *c <= 0x7f     && (p-(unsigned char *)s) > 1) ||
	    (*c >= 0x80    && *c <= 0x7ff    && (p-(unsigned char *)s) > 2) ||
	    (*c >= 0x800   && *c <= 0xffff   && (p-(unsigned char *)s) > 3) ||
	    (*c >= 0x10000 && *c <= 0x1fffff && (p-(unsigned char *)s) > 4))
		code |= UTF8_CODE_OVERLONG;

	/* Check invalid UTF8 range. */
	if ((*c >= 0xd800 && *c <= 0xdfff) ||
	    (*c >= 0xfffe && *c <= 0xffff))
		code |= UTF8_CODE_INVRANGE;

	return code | ((p-(unsigned char *)s)&0x0f);
}

/* append a copy of string <str> (in a wordlist) at the end of the list <li>
 * On failure : return 0 and <err> filled with an error message.
 * The caller is responsible for freeing the <err> and <str> copy
 * memory area using free()
 */
int list_append_word(struct list *li, const char *str, char **err)
{
	struct wordlist *wl;

	wl = calloc(1, sizeof(*wl));
	if (!wl) {
		memprintf(err, "out of memory");
		goto fail_wl;
	}

	wl->s = strdup(str);
	if (!wl->s) {
		memprintf(err, "out of memory");
		goto fail_wl_s;
	}

	LIST_ADDQ(li, &wl->list);

	return 1;

fail_wl_s:
	free(wl->s);
fail_wl:
	free(wl);
	return 0;
}

/* indicates if a memory location may safely be read or not. The trick consists
 * in performing a harmless syscall using this location as an input and letting
 * the operating system report whether it's OK or not. For this we have the
 * stat() syscall, which will return EFAULT when the memory location supposed
 * to contain the file name is not readable. If it is readable it will then
 * either return 0 if the area contains an existing file name, or -1 with
 * another code. This must not be abused, and some audit systems might detect
 * this as abnormal activity. It's used only for unsafe dumps.
 */
int may_access(const void *ptr)
{
	struct stat buf;

	if (stat(ptr, &buf) == 0)
		return 1;
	if (errno == EFAULT)
		return 0;
	return 1;
}

/* print a string of text buffer to <out>. The format is :
 * Non-printable chars \t, \n, \r and \e are * encoded in C format.
 * Other non-printable chars are encoded "\xHH". Space, '\', and '=' are also escaped.
 * Print stopped if null char or <bsize> is reached, or if no more place in the chunk.
 */
int dump_text(struct buffer *out, const char *buf, int bsize)
{
	unsigned char c;
	int ptr = 0;

	while (buf[ptr] && ptr < bsize) {
		c = buf[ptr];
		if (isprint((unsigned char)c) && isascii((unsigned char)c) && c != '\\' && c != ' ' && c != '=') {
			if (out->data > out->size - 1)
				break;
			out->area[out->data++] = c;
		}
		else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\' || c == ' ' || c == '=') {
			if (out->data > out->size - 2)
				break;
			out->area[out->data++] = '\\';
			switch (c) {
			case ' ': c = ' '; break;
			case '\t': c = 't'; break;
			case '\n': c = 'n'; break;
			case '\r': c = 'r'; break;
			case '\e': c = 'e'; break;
			case '\\': c = '\\'; break;
			case '=': c = '='; break;
			}
			out->area[out->data++] = c;
		}
		else {
			if (out->data > out->size - 4)
				break;
			out->area[out->data++] = '\\';
			out->area[out->data++] = 'x';
			out->area[out->data++] = hextab[(c >> 4) & 0xF];
			out->area[out->data++] = hextab[c & 0xF];
		}
		ptr++;
	}

	return ptr;
}

/* print a buffer in hexa.
 * Print stopped if <bsize> is reached, or if no more place in the chunk.
 */
int dump_binary(struct buffer *out, const char *buf, int bsize)
{
	unsigned char c;
	int ptr = 0;

	while (ptr < bsize) {
		c = buf[ptr];

		if (out->data > out->size - 2)
			break;
		out->area[out->data++] = hextab[(c >> 4) & 0xF];
		out->area[out->data++] = hextab[c & 0xF];

		ptr++;
	}
	return ptr;
}

/* Appends into buffer <out> a hex dump of memory area <buf> for <len> bytes,
 * prepending each line with prefix <pfx>. The output is *not* initialized.
 * The output will not wrap pas the buffer's end so it is more optimal if the
 * caller makes sure the buffer is aligned first. A trailing zero will always
 * be appended (and not counted) if there is room for it. The caller must make
 * sure that the area is dumpable first. If <unsafe> is non-null, the memory
 * locations are checked first for being readable.
 */
void dump_hex(struct buffer *out, const char *pfx, const void *buf, int len, int unsafe)
{
	const unsigned char *d = buf;
	int i, j, start;

	d = (const unsigned char *)(((unsigned long)buf) & -16);
	start = ((unsigned long)buf) & 15;

	for (i = 0; i < start + len; i += 16) {
		chunk_appendf(out, (sizeof(void *) == 4) ? "%s%8p: " : "%s%16p: ", pfx, d + i);

		// 0: unchecked, 1: checked safe, 2: danger
		unsafe = !!unsafe;
		if (unsafe && !may_access(d + i))
			unsafe = 2;

		for (j = 0; j < 16; j++) {
			if ((i + j < start) || (i + j >= start + len))
				chunk_strcat(out, "'' ");
			else if (unsafe > 1)
				chunk_strcat(out, "** ");
			else
				chunk_appendf(out, "%02x ", d[i + j]);

			if (j == 7)
				chunk_strcat(out, "- ");
		}
		chunk_strcat(out, "  ");
		for (j = 0; j < 16; j++) {
			if ((i + j < start) || (i + j >= start + len))
				chunk_strcat(out, "'");
			else if (unsafe > 1)
				chunk_strcat(out, "*");
			else if (isprint((unsigned char)d[i + j]))
				chunk_appendf(out, "%c", d[i + j]);
			else
				chunk_strcat(out, ".");
		}
		chunk_strcat(out, "\n");
	}
}

/* dumps <pfx> followed by <n> bytes from <addr> in hex form into buffer <buf>
 * enclosed in brackets after the address itself, formatted on 14 chars
 * including the "0x" prefix. This is meant to be used as a prefix for code
 * areas. For example:
 *    "0x7f10b6557690 [48 c7 c0 0f 00 00 00 0f]"
 * It relies on may_access() to know if the bytes are dumpable, otherwise "--"
 * is emitted. A NULL <pfx> will be considered empty.
 */
void dump_addr_and_bytes(struct buffer *buf, const char *pfx, const void *addr, int n)
{
	int ok = 0;
	int i;

	chunk_appendf(buf, "%s%#14lx [", pfx ? pfx : "", (long)addr);

	for (i = 0; i < n; i++) {
		if (i == 0 || (((long)(addr + i) ^ (long)(addr)) & 4096))
			ok = may_access(addr + i);
		if (ok)
			chunk_appendf(buf, "%02x%s", ((uint8_t*)addr)[i], (i<n-1) ? " " : "]");
		else
			chunk_appendf(buf, "--%s", (i<n-1) ? " " : "]");
	}
}

/* print a line of text buffer (limited to 70 bytes) to <out>. The format is :
 * <2 spaces> <offset=5 digits> <space or plus> <space> <70 chars max> <\n>
 * which is 60 chars per line. Non-printable chars \t, \n, \r and \e are
 * encoded in C format. Other non-printable chars are encoded "\xHH". Original
 * lines are respected within the limit of 70 output chars. Lines that are
 * continuation of a previous truncated line begin with "+" instead of " "
 * after the offset. The new pointer is returned.
 */
int dump_text_line(struct buffer *out, const char *buf, int bsize, int len,
                   int *line, int ptr)
{
	int end;
	unsigned char c;

	end = out->data + 80;
	if (end > out->size)
		return ptr;

	chunk_appendf(out, "  %05d%c ", ptr, (ptr == *line) ? ' ' : '+');

	while (ptr < len && ptr < bsize) {
		c = buf[ptr];
		if (isprint((unsigned char)c) && isascii((unsigned char)c) && c != '\\') {
			if (out->data > end - 2)
				break;
			out->area[out->data++] = c;
		} else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\') {
			if (out->data > end - 3)
				break;
			out->area[out->data++] = '\\';
			switch (c) {
			case '\t': c = 't'; break;
			case '\n': c = 'n'; break;
			case '\r': c = 'r'; break;
			case '\e': c = 'e'; break;
			case '\\': c = '\\'; break;
			}
			out->area[out->data++] = c;
		} else {
			if (out->data > end - 5)
				break;
			out->area[out->data++] = '\\';
			out->area[out->data++] = 'x';
			out->area[out->data++] = hextab[(c >> 4) & 0xF];
			out->area[out->data++] = hextab[c & 0xF];
		}
		if (buf[ptr++] == '\n') {
			/* we had a line break, let's return now */
			out->area[out->data++] = '\n';
			*line = ptr;
			return ptr;
		}
	}
	/* we have an incomplete line, we return it as-is */
	out->area[out->data++] = '\n';
	return ptr;
}

/* displays a <len> long memory block at <buf>, assuming first byte of <buf>
 * has address <baseaddr>. String <pfx> may be placed as a prefix in front of
 * each line. It may be NULL if unused. The output is emitted to file <out>.
 */
void debug_hexdump(FILE *out, const char *pfx, const char *buf,
                   unsigned int baseaddr, int len)
{
	unsigned int i;
	int b, j;

	for (i = 0; i < (len + (baseaddr & 15)); i += 16) {
		b = i - (baseaddr & 15);
		fprintf(out, "%s%08x: ", pfx ? pfx : "", i + (baseaddr & ~15));
		for (j = 0; j < 8; j++) {
			if (b + j >= 0 && b + j < len)
				fprintf(out, "%02x ", (unsigned char)buf[b + j]);
			else
				fprintf(out, "   ");
		}

		if (b + j >= 0 && b + j < len)
			fputc('-', out);
		else
			fputc(' ', out);

		for (j = 8; j < 16; j++) {
			if (b + j >= 0 && b + j < len)
				fprintf(out, " %02x", (unsigned char)buf[b + j]);
			else
				fprintf(out, "   ");
		}

		fprintf(out, "   ");
		for (j = 0; j < 16; j++) {
			if (b + j >= 0 && b + j < len) {
				if (isprint((unsigned char)buf[b + j]))
					fputc((unsigned char)buf[b + j], out);
				else
					fputc('.', out);
			}
			else
				fputc(' ', out);
		}
		fputc('\n', out);
	}
}

/* Tries to report the executable path name on platforms supporting this. If
 * not found or not possible, returns NULL.
 */
const char *get_exec_path()
{
	const char *ret = NULL;

#if (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 16))
	long execfn = getauxval(AT_EXECFN);

	if (execfn && execfn != ENOENT)
		ret = (const char *)execfn;
#endif
	return ret;
}

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
/* calls dladdr() or dladdr1() on <addr> and <dli>. If dladdr1 is available,
 * also returns the symbol size in <size>, otherwise returns 0 there.
 */
static int dladdr_and_size(const void *addr, Dl_info *dli, size_t *size)
{
	int ret;
#if (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 3)) // most detailed one
	const ElfW(Sym) *sym;

	ret = dladdr1(addr, dli, (void **)&sym, RTLD_DL_SYMENT);
	if (ret)
		*size = sym ? sym->st_size : 0;
#else
	ret = dladdr(addr, dli);
	*size = 0;
#endif
	return ret;
}
#endif

/* Tries to append to buffer <buf> some indications about the symbol at address
 * <addr> using the following form:
 *   lib:+0xoffset              (unresolvable address from lib's base)
 *   main+0xoffset              (unresolvable address from main (+/-))
 *   lib:main+0xoffset          (unresolvable lib address from main (+/-))
 *   name                       (resolved exact exec address)
 *   lib:name                   (resolved exact lib address)
 *   name+0xoffset/0xsize       (resolved address within exec symbol)
 *   lib:name+0xoffset/0xsize   (resolved address within lib symbol)
 *
 * The file name (lib or executable) is limited to what lies between the last
 * '/' and the first following '.'. An optional prefix <pfx> is prepended before
 * the output if not null. The file is not dumped when it's the same as the one
 * that contains the "main" symbol, or when __ELF__ && USE_DL are not set.
 *
 * The symbol's base address is returned, or NULL when unresolved, in order to
 * allow the caller to match it against known ones.
 */
const void *resolve_sym_name(struct buffer *buf, const char *pfx, void *addr)
{
	const struct {
		const void *func;
		const char *name;
	} fcts[] = {
		{ .func = process_stream, .name = "process_stream" },
		{ .func = task_run_applet, .name = "task_run_applet" },
		{ .func = si_cs_io_cb, .name = "si_cs_io_cb" },
		{ .func = sock_conn_iocb, .name = "sock_conn_iocb" },
		{ .func = dgram_fd_handler, .name = "dgram_fd_handler" },
		{ .func = listener_accept, .name = "listener_accept" },
		{ .func = poller_pipe_io_handler, .name = "poller_pipe_io_handler" },
		{ .func = mworker_accept_wrapper, .name = "mworker_accept_wrapper" },
#ifdef USE_LUA
		{ .func = hlua_process_task, .name = "hlua_process_task" },
#endif
#ifdef SSL_MODE_ASYNC
		{ .func = ssl_async_fd_free, .name = "ssl_async_fd_free" },
		{ .func = ssl_async_fd_handler, .name = "ssl_async_fd_handler" },
#endif
	};

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
	Dl_info dli, dli_main;
	size_t size;
	const char *fname, *p;
#endif
	int i;

	if (pfx)
		chunk_appendf(buf, "%s", pfx);

	for (i = 0; i < sizeof(fcts) / sizeof(fcts[0]); i++) {
		if (addr == fcts[i].func) {
			chunk_appendf(buf, "%s", fcts[i].name);
			return addr;
		}
	}

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
	/* Now let's try to be smarter */
	if (!dladdr_and_size(addr, &dli, &size))
		goto unknown;

	/* 1. prefix the library name if it's not the same object as the one
	 * that contains the main function. The name is picked between last '/'
	 * and first following '.'.
	 */
	if (!dladdr(main, &dli_main))
		dli_main.dli_fbase = NULL;

	if (dli_main.dli_fbase != dli.dli_fbase) {
		fname = dli.dli_fname;
		p = strrchr(fname, '/');
		if (p++)
			fname = p;
		p = strchr(fname, '.');
		if (!p)
			p = fname + strlen(fname);

		chunk_appendf(buf, "%.*s:", (int)(long)(p - fname), fname);
	}

	/* 2. symbol name */
	if (dli.dli_sname) {
		/* known, dump it and return symbol's address (exact or relative) */
		chunk_appendf(buf, "%s", dli.dli_sname);
		if (addr != dli.dli_saddr) {
			chunk_appendf(buf, "+%#lx", (long)(addr - dli.dli_saddr));
			if (size)
				chunk_appendf(buf, "/%#lx", (long)size);
		}
		return dli.dli_saddr;
	}
	else if (dli_main.dli_fbase != dli.dli_fbase) {
		/* unresolved symbol from a known library, report relative offset */
		chunk_appendf(buf, "+%#lx", (long)(addr - dli.dli_fbase));
		return NULL;
	}
#endif /* __ELF__ && !__linux__ || USE_DL */
 unknown:
	/* unresolved symbol from the main file, report relative offset to main */
	if ((void*)addr < (void*)main)
		chunk_appendf(buf, "main-%#lx", (long)((void*)main - addr));
	else
		chunk_appendf(buf, "main+%#lx", (long)(addr - (void*)main));
	return NULL;
}

/*
 * Allocate an array of unsigned int with <nums> as address from <str> string
 * made of integer separated by dot characters.
 *
 * First, initializes the value with <sz> as address to 0 and initializes the
 * array with <nums> as address to NULL. Then allocates the array with <nums> as
 * address updating <sz> pointed value to the size of this array.
 *
 * Returns 1 if succeeded, 0 if not.
 */
int parse_dotted_uints(const char *str, unsigned int **nums, size_t *sz)
{
	unsigned int *n;
	const char *s, *end;

	s = str;
	*sz = 0;
	end = str + strlen(str);
	*nums = n = NULL;

	while (1) {
		unsigned int r;

		if (s >= end)
			break;

		r = read_uint(&s, end);
		/* Expected characters after having read an uint: '\0' or '.',
		 * if '.', must not be terminal.
		 */
		if (*s != '\0'&& (*s++ != '.' || s == end))
			return 0;

		n = my_realloc2(n, (*sz + 1) * sizeof *n);
		if (!n)
			return 0;

		n[(*sz)++] = r;
	}
	*nums = n;

	return 1;
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


/* Random number generator state, see below */
static uint64_t ha_random_state[2] ALIGNED(2*sizeof(uint64_t));

/* This is a thread-safe implementation of xoroshiro128** described below:
 *     http://prng.di.unimi.it/
 * It features a 2^128 long sequence, returns 64 high-quality bits on each call,
 * supports fast jumps and passes all common quality tests. It is thread-safe,
 * uses a double-cas on 64-bit architectures supporting it, and falls back to a
 * local lock on other ones.
 */
uint64_t ha_random64()
{
	uint64_t result;
	uint64_t old[2] ALIGNED(2*sizeof(uint64_t));
	uint64_t new[2] ALIGNED(2*sizeof(uint64_t));

#if defined(USE_THREAD) && (!defined(HA_CAS_IS_8B) || !defined(HA_HAVE_CAS_DW))
	static HA_SPINLOCK_T rand_lock;

	HA_SPIN_LOCK(OTHER_LOCK, &rand_lock);
#endif

	old[0] = ha_random_state[0];
	old[1] = ha_random_state[1];

#if defined(USE_THREAD) && defined(HA_CAS_IS_8B) && defined(HA_HAVE_CAS_DW)
	do {
#endif
		result = rotl64(old[0] * 5, 7) * 9;
		new[1] = old[0] ^ old[1];
		new[0] = rotl64(old[0], 24) ^ new[1] ^ (new[1] << 16); // a, b
		new[1] = rotl64(new[1], 37); // c

#if defined(USE_THREAD) && defined(HA_CAS_IS_8B) && defined(HA_HAVE_CAS_DW)
	} while (unlikely(!_HA_ATOMIC_DWCAS(ha_random_state, old, new)));
#else
	ha_random_state[0] = new[0];
	ha_random_state[1] = new[1];
#if defined(USE_THREAD)
	HA_SPIN_UNLOCK(OTHER_LOCK, &rand_lock);
#endif
#endif
	return result;
}

/* seeds the random state using up to <len> bytes from <seed>, starting with
 * the first non-zero byte.
 */
void ha_random_seed(const unsigned char *seed, size_t len)
{
	size_t pos;

	/* the seed must not be all zeroes, so we pre-fill it with alternating
	 * bits and overwrite part of them with the block starting at the first
	 * non-zero byte from the seed.
	 */
	memset(ha_random_state, 0x55, sizeof(ha_random_state));

	for (pos = 0; pos < len; pos++)
		if (seed[pos] != 0)
			break;

	if (pos == len)
		return;

	seed += pos;
	len -= pos;

	if (len > sizeof(ha_random_state))
		len = sizeof(ha_random_state);

	memcpy(ha_random_state, seed, len);
}

/* This causes a jump to (dist * 2^96) places in the pseudo-random sequence,
 * and is equivalent to calling ha_random64() as many times. It is used to
 * provide non-overlapping sequences of 2^96 numbers (~7*10^28) to up to 2^32
 * different generators (i.e. different processes after a fork). The <dist>
 * argument is the distance to jump to and is used in a loop so it rather not
 * be too large if the processing time is a concern.
 *
 * BEWARE: this function is NOT thread-safe and must not be called during
 * concurrent accesses to ha_random64().
 */
void ha_random_jump96(uint32_t dist)
{
	while (dist--) {
		uint64_t s0 = 0;
		uint64_t s1 = 0;
		int b;

		for (b = 0; b < 64; b++) {
			if ((0xd2a98b26625eee7bULL >> b) & 1) {
				s0 ^= ha_random_state[0];
				s1 ^= ha_random_state[1];
			}
			ha_random64();
		}

		for (b = 0; b < 64; b++) {
			if ((0xdddf9b1090aa7ac1ULL >> b) & 1) {
				s0 ^= ha_random_state[0];
				s1 ^= ha_random_state[1];
			}
			ha_random64();
		}
		ha_random_state[0] = s0;
		ha_random_state[1] = s1;
	}
}

/* Generates an RFC4122 UUID into chunk <output> which must be at least 37
 * bytes large.
 */
void ha_generate_uuid(struct buffer *output)
{
	uint32_t rnd[4];
	uint64_t last;

	last = ha_random64();
	rnd[0] = last;
	rnd[1] = last >> 32;

	last = ha_random64();
	rnd[2] = last;
	rnd[3] = last >> 32;

	chunk_printf(output, "%8.8x-%4.4x-%4.4x-%4.4x-%12.12llx",
	             rnd[0],
	             rnd[1] & 0xFFFF,
	             ((rnd[1] >> 16u) & 0xFFF) | 0x4000,  // highest 4 bits indicate the uuid version
	             (rnd[2] & 0x3FFF) | 0x8000,  // the highest 2 bits indicate the UUID variant (10),
	             (long long)((rnd[2] >> 14u) | ((uint64_t) rnd[3] << 18u)) & 0xFFFFFFFFFFFFull);
}


/* only used by parse_line() below. It supports writing in place provided that
 * <in> is updated to the next location before calling it. In that case, the
 * char at <in> may be overwritten.
 */
#define EMIT_CHAR(x)						       \
	do {							       \
		char __c = (char)(x);				       \
		if ((opts & PARSE_OPT_INPLACE) && out+outpos > in)     \
			err |= PARSE_ERR_OVERLAP;		       \
		if (outpos >= outmax)				       \
			err |= PARSE_ERR_TOOLARGE;		       \
		if (!err)					       \
			out[outpos] = __c;			       \
		outpos++;					       \
	} while (0)

/* Parse <in>, copy it into <out> split into isolated words whose pointers
 * are put in <args>. If more than <outlen> bytes have to be emitted, the
 * extraneous ones are not emitted but <outlen> is updated so that the caller
 * knows how much to realloc. Similarly, <args> are not updated beyond <nbargs>
 * but the returned <nbargs> indicates how many were found. All trailing args
 * up to <nbargs> point to the trailing zero, and as long as <nbargs> is > 0,
 * it is guaranteed that at least one arg will point to the zero. It is safe
 * to call it with a NULL <args> if <nbargs> is 0.
 *
 * <out> may overlap with <in> provided that it never goes further, in which
 * case the parser will accept to perform in-place parsing and unquoting/
 * unescaping but only if environment variables do not lead to expansion that
 * causes overlapping, otherwise the input string being destroyed, the error
 * will not be recoverable. Note that even during out-of-place <in> will
 * experience temporary modifications in-place for variable resolution and must
 * be writable, and will also receive zeroes to delimit words when using
 * in-place copy. Parsing options <opts> taken from PARSE_OPT_*. Return value
 * is zero on success otherwise a bitwise-or of PARSE_ERR_*. Upon error, the
 * starting point of the first invalid character sequence or unmatched
 * quote/brace is reported in <errptr> if not NULL. When using in-place parsing
 * error reporting might be difficult since zeroes will have been inserted into
 * the string. One solution for the caller may consist in replacing all args
 * delimiters with spaces in this case.
 */
uint32_t parse_line(char *in, char *out, size_t *outlen, char **args, int *nbargs, uint32_t opts, char **errptr)
{
	char *quote = NULL;
	char *brace = NULL;
	char *word_expand = NULL;
	unsigned char hex1, hex2;
	size_t outmax = *outlen;
	int argsmax = *nbargs - 1;
	size_t outpos = 0;
	int squote = 0;
	int dquote = 0;
	int arg = 0;
	uint32_t err = 0;

	*nbargs = 0;
	*outlen = 0;

	/* argsmax may be -1 here, protecting args[] from any write */
	if (arg < argsmax)
		args[arg] = out;

	while (1) {
		if (*in >= '-' && *in != '\\') {
			/* speedup: directly send all regular chars starting
			 * with '-', '.', '/', alnum etc...
			 */
			EMIT_CHAR(*in++);
			continue;
		}
		else if (*in == '\0' || *in == '\n' || *in == '\r') {
			/* end of line */
			break;
		}
		else if (*in == '#' && (opts & PARSE_OPT_SHARP) && !squote && !dquote) {
			/* comment */
			break;
		}
		else if (*in == '"' && !squote && (opts & PARSE_OPT_DQUOTE)) {  /* double quote outside single quotes */
			if (dquote) {
				dquote = 0;
				quote = NULL;
			}
			else {
				dquote = 1;
				quote = in;
			}
			in++;
			continue;
		}
		else if (*in == '\'' && !dquote && (opts & PARSE_OPT_SQUOTE)) { /* single quote outside double quotes */
			if (squote) {
				squote = 0;
				quote = NULL;
			}
			else {
				squote = 1;
				quote = in;
			}
			in++;
			continue;
		}
		else if (*in == '\\' && !squote && (opts & PARSE_OPT_BKSLASH)) {
			/* first, we'll replace \\, \<space>, \#, \r, \n, \t, \xXX with their
			 * C equivalent value but only when they have a special meaning and within
			 * double quotes for some of them. Other combinations left unchanged (eg: \1).
			 */
			char tosend = *in;

			switch (in[1]) {
			case ' ':
			case '\\':
				tosend = in[1];
				in++;
				break;

			case 't':
				tosend = '\t';
				in++;
				break;

			case 'n':
				tosend = '\n';
				in++;
				break;

			case 'r':
				tosend = '\r';
				in++;
				break;

			case '#':
				/* escaping of "#" only if comments are supported */
				if (opts & PARSE_OPT_SHARP)
					in++;
				tosend = *in;
				break;

			case '\'':
				/* escaping of "'" only outside single quotes and only if single quotes are supported */
				if (opts & PARSE_OPT_SQUOTE && !squote)
					in++;
				tosend = *in;
				break;

			case '"':
				/* escaping of '"' only outside single quotes and only if double quotes are supported */
				if (opts & PARSE_OPT_DQUOTE && !squote)
					in++;
				tosend = *in;
				break;

			case '$':
				/* escaping of '$' only inside double quotes and only if env supported */
				if (opts & PARSE_OPT_ENV && dquote)
					in++;
				tosend = *in;
				break;

			case 'x':
				if (!ishex(in[2]) || !ishex(in[3])) {
					/* invalid or incomplete hex sequence */
					err |= PARSE_ERR_HEX;
					if (errptr)
						*errptr = in;
					goto leave;
				}
				hex1 = toupper((unsigned char)in[2]) - '0';
				hex2 = toupper((unsigned char)in[3]) - '0';
				if (hex1 > 9) hex1 -= 'A' - '9' - 1;
				if (hex2 > 9) hex2 -= 'A' - '9' - 1;
				tosend = (hex1 << 4) + hex2;
				in += 3;
				break;

			default:
				/* other combinations are not escape sequences */
				break;
			}

			in++;
			EMIT_CHAR(tosend);
		}
		else if (isspace((unsigned char)*in) && !squote && !dquote) {
			/* a non-escaped space is an argument separator */
			while (isspace((unsigned char)*in))
				in++;
			EMIT_CHAR(0);
			arg++;
			if (arg < argsmax)
				args[arg] = out + outpos;
			else
				err |= PARSE_ERR_TOOMANY;
		}
		else if (*in == '$' && (opts & PARSE_OPT_ENV) && (dquote || !(opts & PARSE_OPT_DQUOTE))) {
			/* environment variables are evaluated anywhere, or only
			 * inside double quotes if they are supported.
			 */
			char *var_name;
			char save_char;
			char *value;

			in++;

			if (*in == '{')
				brace = in++;

			if (!isalpha((unsigned char)*in) && *in != '_') {
				/* unacceptable character in variable name */
				err |= PARSE_ERR_VARNAME;
				if (errptr)
					*errptr = in;
				goto leave;
			}

			var_name = in;
			while (isalnum((unsigned char)*in) || *in == '_')
				in++;

			save_char = *in;
			*in = '\0';
			value = getenv(var_name);
			*in = save_char;

			/* support for '[*]' sequence to force word expansion,
			 * only available inside braces */
			if (*in == '[' && brace && (opts & PARSE_OPT_WORD_EXPAND)) {
				word_expand = in++;

				if (*in++ != '*' || *in++ != ']') {
					err |= PARSE_ERR_WRONG_EXPAND;
					if (errptr)
						*errptr = word_expand;
					goto leave;
				}
			}

			if (brace) {
				if (*in != '}') {
					/* unmatched brace */
					err |= PARSE_ERR_BRACE;
					if (errptr)
						*errptr = brace;
					goto leave;
				}
				in++;
				brace = NULL;
			}

			if (value) {
				while (*value) {
					/* expand as individual parameters on a space character */
					if (word_expand && isspace((unsigned char)*value)) {
						EMIT_CHAR(0);
						++arg;
						if (arg < argsmax)
							args[arg] = out + outpos;
						else
							err |= PARSE_ERR_TOOMANY;

						/* skip consecutive spaces */
						while (isspace((unsigned char)*++value))
							;
					} else {
						EMIT_CHAR(*value++);
					}
				}
			}
			word_expand = NULL;
		}
		else {
			/* any other regular char */
			EMIT_CHAR(*in++);
		}
	}

	/* end of output string */
	EMIT_CHAR(0);
	arg++;

	if (quote) {
		/* unmatched quote */
		err |= PARSE_ERR_QUOTE;
		if (errptr)
			*errptr = quote;
		goto leave;
	}
 leave:
	*nbargs = arg;
	*outlen = outpos;

	/* empty all trailing args by making them point to the trailing zero,
	 * at least the last one in any case.
	 */
	if (arg > argsmax)
		arg = argsmax;

	while (arg >= 0 && arg <= argsmax)
		args[arg++] = out + outpos - 1;

	return err;
}
#undef EMIT_CHAR

/* This is used to sanitize an input line that's about to be used for error reporting.
 * It will adjust <line> to print approximately <width> chars around <pos>, trying to
 * preserve the beginning, with leading or trailing "..." when the line is truncated.
 * If non-printable chars are present in the output. It returns the new offset <pos>
 * in the modified line. Non-printable characters are replaced with '?'. <width> must
 * be at least 6 to support two "..." otherwise the result is undefined. The line
 * itself must have at least 7 chars allocated for the same reason.
 */
size_t sanitize_for_printing(char *line, size_t pos, size_t width)
{
	size_t shift = 0;
	char *out = line;
	char *in = line;
	char *end = line + width;

	if (pos >= width) {
		/* if we have to shift, we'll be out of context, so let's
		 * try to put <pos> at the center of width.
		 */
		shift = pos - width / 2;
		in += shift + 3;
		end = out + width - 3;
		out[0] = out[1] = out[2] = '.';
		out += 3;
	}

	while (out < end && *in) {
		if (isspace((unsigned char)*in))
			*out++ = ' ';
		else if (isprint((unsigned char)*in))
			*out++ = *in;
		else
			*out++ = '?';
		in++;
	}

	if (end < line + width) {
		out[0] = out[1] = out[2] = '.';
		out += 3;
	}

	*out++ = 0;
	return pos - shift;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
