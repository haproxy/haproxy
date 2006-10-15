/*
 * General purpose functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
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

/* enough to store 2^63=18446744073709551615 */
static char itoa_str[21];

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
 * This function simply returns a statically allocated string containing
 * the ascii representation for number 'n' in decimal.
 */
char *ultoa(unsigned long n)
{
	char *pos;
	
	pos = itoa_str + sizeof(itoa_str) - 1;
	*pos-- = '\0';
	
	do {
		*pos-- = '0' + n % 10;
		n /= 10;
	} while (n && pos >= itoa_str);
	return pos + 1;
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
 * converts <str> to a two struct in_addr* which are locally allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optionnal and either in the dotted or CIDR notation.
 * Note: "addr" can also be a hostname. Returns 1 if OK, 0 if error.
 */
int str2net(char *str, struct in_addr *addr, struct in_addr *mask)
{
	char *c;
	unsigned long len;

	memset(mask, 0, sizeof(*mask));
	memset(addr, 0, sizeof(*addr));
	str = strdup(str);
	if (str == NULL)
		return 0;

	if ((c = strrchr(str, '/')) != NULL) {
		*c++ = '\0';
		/* c points to the mask */
		if (strchr(c, '.') != NULL) {	    /* dotted notation */
			if (!inet_pton(AF_INET, c, mask))
				return 0;
		}
		else { /* mask length */
			char *err;
			len = strtol(c, &err, 10);
			if (!*c || (err && *err) || (unsigned)len > 32)
				return 0;
			if (len)
				mask->s_addr = htonl(~0UL << (32 - len));
			else
				mask->s_addr = 0;
		}
	}
	else {
		mask->s_addr = ~0UL;
	}
	if (!inet_pton(AF_INET, str, addr)) {
		struct hostent *he;

		if ((he = gethostbyname(str)) == NULL) {
			return 0;
		}
		else
			*addr = *(struct in_addr *) *(he->h_addr_list);
	}
	free(str);
	return 1;
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
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
