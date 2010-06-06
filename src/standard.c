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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/config.h>
#include <common/standard.h>
#include <eb32tree.h>
#include <proto/log.h>

/* enough to store 10 integers of :
 *   2^64-1 = 18446744073709551615 or
 *    -2^63 = -9223372036854775808
 *
 * The HTML version needs room for adding the 25 characters
 * '<span class="rls"></span>' around digits at positions 3N+1 in order
 * to add spacing at up to 6 positions : 18 446 744 073 709 551 615
 */
char itoa_str[10][171];

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

/*
 * converts <str> to a struct sockaddr_un* which is locally allocated.
 * The format is "/path", where "/path" is a path to a UNIX domain socket.
 * NULL is returned if the socket path is invalid (too long).
 */
struct sockaddr_un *str2sun(const char *str)
{
	static struct sockaddr_un su;
	int strsz;	/* length included null */

	memset(&su, 0, sizeof(su));
	strsz = strlen(str) + 1;
	if (strsz > sizeof(su.sun_path)) {
		return NULL;
	} else {
		su.sun_family = AF_UNIX;
		memcpy(su.sun_path, str, strsz);
	}
	return &su;
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
 * Return integer equivalent of character <c> for a hex digit (0-9, a-f, A-F),
 * otherwise -1. This compact form helps gcc produce efficient code.
 */
int hex2i(int c)
{
	if ((unsigned char)(c -= '0') > 9) {
		if ((unsigned char)(c -= 'A' - '0') > 5 &&
		    (unsigned char)(c -= 'a' - 'A') > 5)
			c = -11;
		c += 10;
	}
	return c;
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
 * converts <str> to a struct sockaddr_in* which is locally allocated.
 * The format is "addr:port", where "addr" can be a dotted IPv4 address,
 * a host name, or empty or "*" to indicate INADDR_ANY. NULL is returned
 * if the host part cannot be resolved.
 */
struct sockaddr_in *str2sa(char *str)
{
	static struct sockaddr_in sa;
	struct sockaddr_in *ret = NULL;
	char *c;
	int port;

	memset(&sa, 0, sizeof(sa));
	str = strdup(str);
	if (str == NULL)
		goto out;

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
		struct hostent *he = gethostbyname(str);
		if (!he)
			goto out;
		sa.sin_addr = *(struct in_addr *) *(he->h_addr_list);
	}
	sa.sin_port   = htons(port);
	sa.sin_family = AF_INET;
	ret = &sa;
 out:
	free(str);
	return ret;
}

/*
 * converts <str> to a struct sockaddr_in* which is locally allocated, and a
 * port range consisting in two integers. The low and high end are always set
 * even if the port is unspecified, in which case (0,0) is returned. The low
 * port is set in the sockaddr_in. Thus, it is enough to check the size of the
 * returned range to know if an array must be allocated or not. The format is
 * "addr[:port[-port]]", where "addr" can be a dotted IPv4 address, a host
 * name, or empty or "*" to indicate INADDR_ANY. NULL is returned if the host
 * part cannot be resolved.
 */
struct sockaddr_in *str2sa_range(char *str, int *low, int *high)
{
	static struct sockaddr_in sa;
	struct sockaddr_in *ret = NULL;
	char *c;
	int portl, porth;

	memset(&sa, 0, sizeof(sa));
	str = strdup(str);
	if (str == NULL)
		goto out;

	if ((c = strrchr(str,':')) != NULL) {
		char *sep;
		*c++ = '\0';
		sep = strchr(c, '-');
		if (sep)
			*sep++ = '\0';
		else
			sep = c;
		portl = atol(c);
		porth = atol(sep);
	}
	else {
		portl = 0;
		porth = 0;
	}

	if (*str == '*' || *str == '\0') { /* INADDR_ANY */
		sa.sin_addr.s_addr = INADDR_ANY;
	}
	else if (!inet_pton(AF_INET, str, &sa.sin_addr)) {
		struct hostent *he = gethostbyname(str);
		if (!he)
			goto out;
		sa.sin_addr = *(struct in_addr *) *(he->h_addr_list);
	}
	sa.sin_port   = htons(portl);
	sa.sin_family = AF_INET;
	ret = &sa;

	*low = portl;
	*high = porth;

 out:
	free(str);
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
 * Parse IP address found in url.
 */
int url2ip(const char *addr, struct in_addr *dst)
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
 * Resolve destination server from URL. Convert <str> to a sockaddr_in*.
 */
int url2sa(const char *url, int ulen, struct sockaddr_in *addr)
{
	const char *curr = url, *cp = url;
	int ret, url_code = 0;
	unsigned int http_code = 0;

	/* Cleanup the room */
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = 0;
	addr->sin_port = 0;

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
	if (url_code == 0x3a2f2f) {
		while (cp < curr - 3)
			http_code = (http_code << 8) + *cp++;
		http_code |= 0x20202020;			/* Turn everything to lower case */
		
		/* HTTP url matching */
		if (http_code == 0x68747470) {
			/* We are looking for IP address. If you want to parse and
			 * resolve hostname found in url, you can use str2sa(), but
			 * be warned this can slow down global daemon performances
			 * while handling lagging dns responses.
			 */
			ret = url2ip(curr, &addr->sin_addr);
			if (!ret)
				return -1;
			curr += ret;
			addr->sin_port = (*curr == ':') ? str2uic(++curr) : 80;
			addr->sin_port = htons(addr->sin_port);
		}
		return 0;
	}

	return -1;
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

	*ret = value;
	return NULL;
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
unsigned int inetaddr_host_lim_ret(const char *text, char *stop, const char **ret)
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
