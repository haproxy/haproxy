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

#include <ctype.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/chunk.h>
#include <common/config.h>
#include <common/standard.h>
#include <types/global.h>
#include <proto/dns.h>
#include <eb32tree.h>

/* enough to store NB_ITOA_STR integers of :
 *   2^64-1 = 18446744073709551615 or
 *    -2^63 = -9223372036854775808
 *
 * The HTML version needs room for adding the 25 characters
 * '<span class="rls"></span>' around digits at positions 3N+1 in order
 * to add spacing at up to 6 positions : 18 446 744 073 709 551 615
 */
char itoa_str[NB_ITOA_STR][171];
int itoa_idx = 0; /* index of next itoa_str to use */

/* sometimes we'll need to quote strings (eg: in stats), and we don't expect
 * to quote strings larger than a max configuration line.
 */
char quoted_str[NB_QSTR][QSTR_SIZE + 1];
int quoted_idx = 0;

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
		if (!isalnum((int)(unsigned char)*name) && *name != '.' && *name != ':' &&
		    *name != '_' && *name != '-')
			return name;
		name++;
	}
	return NULL;
}

/*
 * Checks <domainname> for invalid characters. Valid chars are [A-Za-z0-9_.-].
 * If an invalid character is found, a pointer to it is returned.
 * If everything is fine, NULL is returned.
 */
const char *invalid_domainchar(const char *name) {

	if (!*name)
		return name;

	while (*name) {
		if (!isalnum((int)(unsigned char)*name) && *name != '.' &&
		    *name != '_' && *name != '-')
			return name;

		name++;
	}

	return NULL;
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
 * returns NULL.
 */
struct sockaddr_storage *str2ip2(const char *str, struct sockaddr_storage *sa, int resolve)
{
	struct hostent *he;

	/* Any IPv6 address */
	if (str[0] == ':' && str[1] == ':' && !str[2]) {
		if (!sa->ss_family || sa->ss_family == AF_UNSPEC)
			sa->ss_family = AF_INET6;
		else if (sa->ss_family != AF_INET6)
			goto fail;
		return sa;
	}

	/* Any address for the family, defaults to IPv4 */
	if (!str[0] || (str[0] == '*' && !str[1])) {
		if (!sa->ss_family || sa->ss_family == AF_UNSPEC)
			sa->ss_family = AF_INET;
		return sa;
	}

	/* check for IPv6 first */
	if ((!sa->ss_family || sa->ss_family == AF_UNSPEC || sa->ss_family == AF_INET6) &&
	    inet_pton(AF_INET6, str, &((struct sockaddr_in6 *)sa)->sin6_addr)) {
		sa->ss_family = AF_INET6;
		return sa;
	}

	/* then check for IPv4 */
	if ((!sa->ss_family || sa->ss_family == AF_UNSPEC || sa->ss_family == AF_INET) &&
	    inet_pton(AF_INET, str, &((struct sockaddr_in *)sa)->sin_addr)) {
		sa->ss_family = AF_INET;
		return sa;
	}

	if (!resolve)
		return NULL;

	if (!dns_hostname_validation(str, NULL))
		return NULL;

#ifdef USE_GETADDRINFO
	if (global.tune.options & GTUNE_USE_GAI) {
		struct addrinfo hints, *result;

		memset(&result, 0, sizeof(result));
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = sa->ss_family ? sa->ss_family : AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;
		hints.ai_protocol = 0;

		if (getaddrinfo(str, NULL, &hints, &result) == 0) {
			if (!sa->ss_family || sa->ss_family == AF_UNSPEC)
				sa->ss_family = result->ai_family;
			else if (sa->ss_family != result->ai_family)
				goto fail;

			switch (result->ai_family) {
			case AF_INET:
				memcpy((struct sockaddr_in *)sa, result->ai_addr, result->ai_addrlen);
				return sa;
			case AF_INET6:
				memcpy((struct sockaddr_in6 *)sa, result->ai_addr, result->ai_addrlen);
				return sa;
			}
		}

		if (result)
			freeaddrinfo(result);
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
			return sa;
		case AF_INET6:
			((struct sockaddr_in6 *)sa)->sin6_addr = *(struct in6_addr *) *(he->h_addr_list);
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
 * Also note that in order to avoid any ambiguity with IPv6 addresses, the ':'
 * is mandatory after the IP address even when no port is specified. NULL is
 * returned if the address cannot be parsed. The <low> and <high> ports are
 * always initialized if non-null, even for non-IP families.
 *
 * If <pfx> is non-null, it is used as a string prefix before any path-based
 * address (typically the path to a unix socket).
 *
 * When a file descriptor is passed, its value is put into the s_addr part of
 * the address when cast to sockaddr_in and the address family is AF_UNSPEC.
 */
struct sockaddr_storage *str2sa_range(const char *str, int *low, int *high, char **err, const char *pfx)
{
	static struct sockaddr_storage ss;
	struct sockaddr_storage *ret = NULL;
	char *back, *str2;
	char *port1, *port2;
	int portl, porth, porta;
	int abstract = 0;

	portl = porth = porta = 0;

	str2 = back = env_expand(strdup(str));
	if (str2 == NULL) {
		memprintf(err, "out of memory in '%s'\n", __FUNCTION__);
		goto out;
	}

	memset(&ss, 0, sizeof(ss));

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
	else if (*str2 == '/') {
		ss.ss_family = AF_UNIX;
	}
	else
		ss.ss_family = AF_UNSPEC;

	if (ss.ss_family == AF_UNSPEC && strncmp(str2, "fd@", 3) == 0) {
		char *endptr;

		str2 += 3;
		((struct sockaddr_in *)&ss)->sin_addr.s_addr = strtol(str2, &endptr, 10);

		if (!*str2 || *endptr) {
			memprintf(err, "file descriptor '%s' is not a valid integer in '%s'\n", str2, str);
			goto out;
		}

		/* we return AF_UNSPEC if we use a file descriptor number */
		ss.ss_family = AF_UNSPEC;
	}
	else if (ss.ss_family == AF_UNIX) {
		int prefix_path_len;
		int max_path_len;
		int adr_len;

		/* complete unix socket path name during startup or soft-restart is
		 * <unix_bind_prefix><path>.<pid>.<bak|tmp>
		 */
		prefix_path_len = (pfx && !abstract) ? strlen(pfx) : 0;
		max_path_len = (sizeof(((struct sockaddr_un *)&ss)->sun_path) - 1) -
			(prefix_path_len ? prefix_path_len + 1 + 5 + 1 + 3 : 0);

		adr_len = strlen(str2);
		if (adr_len > max_path_len) {
			memprintf(err, "socket path '%s' too long (max %d)\n", str, max_path_len);
			goto out;
		}

		/* when abstract==1, we skip the first zero and copy all bytes except the trailing zero */
		memset(((struct sockaddr_un *)&ss)->sun_path, 0, sizeof(((struct sockaddr_un *)&ss)->sun_path));
		if (prefix_path_len)
			memcpy(((struct sockaddr_un *)&ss)->sun_path, pfx, prefix_path_len);
		memcpy(((struct sockaddr_un *)&ss)->sun_path + prefix_path_len + abstract, str2, adr_len + 1 - abstract);
	}
	else { /* IPv4 and IPv6 */
		port1 = strrchr(str2, ':');
		if (port1)
			*port1++ = '\0';
		else
			port1 = "";

		if (str2ip(str2, &ss) == NULL) {
			memprintf(err, "invalid address: '%s' in '%s'\n", str2, str);
			goto out;
		}

		if (isdigit((int)(unsigned char)*port1)) {	/* single port or range */
			port2 = strchr(port1, '-');
			if (port2)
				*port2++ = '\0';
			else
				port2 = port1;
			portl = atoi(port1);
			porth = atoi(port2);
			porta = portl;
		}
		else if (*port1 == '-') { /* negative offset */
			portl = atoi(port1 + 1);
			porta = -portl;
		}
		else if (*port1 == '+') { /* positive offset */
			porth = atoi(port1 + 1);
			porta = porth;
		}
		else if (*port1) { /* other any unexpected char */
			memprintf(err, "invalid character '%c' in port number '%s' in '%s'\n", *port1, port1, str);
			goto out;
		}
		set_host_port(&ss, porta);
	}

	ret = &ss;
 out:
	if (low)
		*low = portl;
	if (high)
		*high = porth;
	free(back);
	return ret;
}

/* converts <str> to a struct in_addr containing a network mask. It can be
 * passed in dotted form (255.255.255.0) or in CIDR form (24). It returns 1
 * if the conversion succeeds otherwise non-zero.
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
		if (len)
			mask->s_addr = htonl(~0UL << (32 - len));
		else
			mask->s_addr = 0;
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

/*
 * converts <str> to two struct in_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optionnal and either in the dotted or CIDR notation.
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
 * is an optionnal number of bits (128 being the default).
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
 * <out> contain the code of the dectected scheme, the start and length of
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
		p = trash.str;
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
		if (!inet_pton(AF_INET6, trash.str, &((struct sockaddr_in6 *)addr)->sin6_addr))
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
			memcpy(trash.str, curr, end - curr);
			trash.str[end - curr] = '\0';

			/* try to resolve an IPv4/IPv6 hostname */
			he = gethostbyname(trash.str);
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
int addr_to_str(struct sockaddr_storage *addr, char *str, int size)
{

	void *ptr;

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
int port_to_str(struct sockaddr_storage *addr, char *str, int size)
{

	uint16_t port;


	if (size < 5)
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

/*
 * Same behavior as encode_string() above, except that it encodes chunk
 * <chunk> instead of a string.
 */
char *encode_chunk(char *start, char *stop,
		    const char escape, const fd_set *map,
		    const struct chunk *chunk)
{
	char *str = chunk->str;
	char *end = chunk->str + chunk->len;

	if (start < stop) {
		stop--; /* reserve one byte for the final '\0' */
		while (start < stop && str < end) {
			if (!FD_ISSET((unsigned char)(*str), map))
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

/* Check a string for using it in a CSV output format. If the string contains
 * one of the following four char <">, <,>, CR or LF, the string is
 * encapsulated between <"> and the <"> are escaped by a <""> sequence.
 * <str> is the input string to be escaped. The function assumes that
 * the input string is null-terminated.
 *
 * If <quote> is 0, the result is returned escaped but without double quote.
 * Is it useful if the escaped string is used between double quotes in the
 * format.
 *
 *    printf("..., \"%s\", ...\r\n", csv_enc(str, 0));
 *
 * If the <quote> is 1, the converter put the quotes only if any character is
 * escaped. If the <quote> is 2, the converter put always the quotes.
 *
 * <output> is a struct chunk used for storing the output string if any
 * change will be done.
 *
 * The function returns the converted string on this output. If an error
 * occurs, the function return an empty string. This type of output is useful
 * for using the function directly as printf() argument.
 *
 * If the output buffer is too short to contain the input string, the result
 * is truncated.
 */
const char *csv_enc(const char *str, int quote, struct chunk *output)
{
	char *end = output->str + output->size;
	char *out = output->str + 1; /* +1 for reserving space for a first <"> */

	while (*str && out < end - 2) { /* -2 for reserving space for <"> and \0. */
		*out = *str;
		if (*str == '"') {
			if (quote == 1)
				quote = 2;
			out++;
			if (out >= end - 2) {
				out--;
				break;
			}
			*out = '"';
		}
		if (quote == 1 && ( *str == '\r' || *str == '\n' || *str == ',') )
			quote = 2;
		out++;
		str++;
	}

	if (quote == 1)
		quote = 0;

	if (!quote) {
		*out = '\0';
		return output->str + 1;
	}

	/* else quote == 2 */
	*output->str = '"';
	*out = '"';
	out++;
	*out = '\0';
	return output->str;
}

/* Decode an URL-encoded string in-place. The resulting string might
 * be shorter. If some forbidden characters are found, the conversion is
 * aborted, the string is truncated before the issue and a negative value is
 * returned, otherwise the operation returns the length of the decoded string.
 */
int url_decode(char *string)
{
	char *in, *out;
	int ret = -1;

	in = string;
	out = string;
	while (*in) {
		switch (*in) {
		case '+' :
			*out++ = ' ';
			break;
		case '%' :
			if (!ishex(in[1]) || !ishex(in[2]))
				goto end;
			*out++ = (hex2i(in[1]) << 4) + hex2i(in[2]);
			in += 2;
			break;
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
 */
const char *parse_time_err(const char *text, unsigned *ret, unsigned unit_flags)
{
	unsigned imult, idiv;
	unsigned omult, odiv;
	unsigned value;

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
		break;
	case 's': /* second = unscaled unit */
		break;
	case 'u': /* microsecond : "us" */
		if (text[1] == 's') {
			idiv = 1000000;
			text++;
		}
		break;
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

	if (omult % idiv == 0) { omult /= idiv; idiv = 1; }
	if (idiv % omult == 0) { idiv /= omult; omult = 1; }
	if (imult % odiv == 0) { imult /= odiv; odiv = 1; }
	if (odiv % imult == 0) { odiv /= imult; imult = 1; }

	value = (value * (imult * omult) + (idiv * odiv - 1)) / (idiv * odiv);
	*ret = value;
	return NULL;
}

/* this function converts the string starting at <text> to an unsigned int
 * stored in <ret>. If an error is detected, the pointer to the unexpected
 * character is returned. If the conversio is succesful, NULL is returned.
 */
const char *parse_size_err(const char *text, unsigned *ret) {
	unsigned value = 0;

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
 * result into binstr and set binstrlen to the lengh of binstr. Memory for
 * binstr is allocated by the function. In case of error, returns 0 with an
 * error message in err. In succes case, it returns the consumed length.
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
		*binstr = calloc(len, sizeof(char));
		if (!*binstr) {
			memprintf(err, "out of memory while loading string pattern");
			return 0;
		}
		alloc = 1;
	}
	else {
		if (*binstrlen < len) {
			memprintf(err, "no space avalaible in the buffer. expect %d, provides %d",
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
	if (alloc)
		free(binstr);
	return 0;
}

/* copies at most <n> characters from <src> and always terminates with '\0' */
char *my_strndup(const char *src, int n)
{
	int len = 0;
	char *ret;

	while (len < n && src[len])
		len++;

	ret = (char *)malloc(len + 1);
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
 * formated address though (3 points).
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
	static char val[32];
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

/* Return non-zero if IPv4 address is part of the network,
 * otherwise zero.
 */
int in_net_ipv4(struct in_addr *addr, struct in_addr *mask, struct in_addr *net)
{
	return((addr->s_addr & mask->s_addr) == (net->s_addr & mask->s_addr));
}

/* Return non-zero if IPv6 address is part of the network,
 * otherwise zero.
 */
int in_net_ipv6(struct in6_addr *addr, struct in6_addr *mask, struct in6_addr *net)
{
	int i;

	for (i = 0; i < sizeof(struct in6_addr) / sizeof(int); i++)
		if (((((int *)addr)[i] & ((int *)mask)[i])) !=
		    (((int *)net)[i] & ((int *)mask)[i]))
			return 0;
	return 1;
}

/* RFC 4291 prefix */
const char rfc4291_pfx[] = { 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0xFF, 0xFF };

/* Map IPv4 adress on IPv6 address, as specified in RFC 3513.
 * Input and output may overlap.
 */
void v4tov6(struct in6_addr *sin6_addr, struct in_addr *sin_addr)
{
	struct in_addr tmp_addr;

	tmp_addr.s_addr = sin_addr->s_addr;
	memcpy(sin6_addr->s6_addr, rfc4291_pfx, sizeof(rfc4291_pfx));
	memcpy(sin6_addr->s6_addr+12, &tmp_addr.s_addr, 4);
}

/* Map IPv6 adress on IPv4 address, as specified in RFC 3513.
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
char *date2str_log(char *dst, struct tm *tm, struct timeval *date, size_t size)
{

	if (size < 25) /* the size is fixed: 24 chars + \0 */
		return NULL;

	dst = utoa_pad((unsigned int)tm->tm_mday, dst, 3); // day
	*dst++ = '/';
	memcpy(dst, monthname[tm->tm_mon], 3); // month
	dst += 3;
	*dst++ = '/';
	dst = utoa_pad((unsigned int)tm->tm_year+1900, dst, 5); // year
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_hour, dst, 3); // hour
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_min, dst, 3); // minutes
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_sec, dst, 3); // secondes
	*dst++ = '.';
	utoa_pad((unsigned int)(date->tv_usec/1000), dst, 4); // millisecondes
	dst += 3;  // only the 3 first digits
	*dst = '\0';

	return dst;
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
	*dst++ = '/';
	memcpy(dst, monthname[tm->tm_mon], 3); // month
	dst += 3;
	*dst++ = '/';
	dst = utoa_pad((unsigned int)tm->tm_year+1900, dst, 5); // year
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_hour, dst, 3); // hour
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_min, dst, 3); // minutes
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_sec, dst, 3); // secondes
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
 * * return a pointer to the last char written (\0) or
 * * NULL if there isn't enough space.
 */
char *localdate2str_log(char *dst, struct tm *tm, size_t size)
{
	if (size < 27) /* the size is fixed: 26 chars + \0 */
		return NULL;

	dst = utoa_pad((unsigned int)tm->tm_mday, dst, 3); // day
	*dst++ = '/';
	memcpy(dst, monthname[tm->tm_mon], 3); // month
	dst += 3;
	*dst++ = '/';
	dst = utoa_pad((unsigned int)tm->tm_year+1900, dst, 5); // year
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_hour, dst, 3); // hour
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_min, dst, 3); // minutes
	*dst++ = ':';
	dst = utoa_pad((unsigned int)tm->tm_sec, dst, 3); // secondes
	*dst++ = ' ';
	memcpy(dst, localtimezone, 5); // timezone
	dst += 5;
	*dst = '\0';

	return dst;
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
 */
char *memprintf(char **out, const char *format, ...)
{
	va_list args;
	char *ret = NULL;
	int allocated = 0;
	int needed = 0;

	if (!out)
		return NULL;

	do {
		/* vsnprintf() will return the required length even when the
		 * target buffer is NULL. We do this in a loop just in case
		 * intermediate evaluations get wrong.
		 */
		va_start(args, format);
		needed = vsnprintf(ret, allocated, format, args);
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
		ret = realloc(ret, allocated);
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
			while (isalnum((int)(unsigned char)*var_end) || *var_end == '_') {
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

		out = realloc(out, out_len + (txt_end - txt_beg) + val_len + 1);
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
		while (toupper(*start) != toupper(*str2)) {
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
		while (toupper(*sptr) == toupper(*pptr)) {
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
