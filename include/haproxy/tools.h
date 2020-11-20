/*
 * include/haproxy/tools.h
 * This files contains some general purpose functions and macros.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_TOOLS_H
#define _HAPROXY_TOOLS_H

#ifdef USE_BACKTRACE
#define _GNU_SOURCE
#include <execinfo.h>
#endif

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <import/eb32sctree.h>
#include <import/eb32tree.h>
#include <haproxy/api.h>
#include <haproxy/chunk.h>
#include <haproxy/intops.h>
#include <haproxy/namespace-t.h>
#include <haproxy/protocol-t.h>
#include <haproxy/tools-t.h>

/****** string-specific macros and functions ******/
/* if a > max, then bound <a> to <max>. The macro returns the new <a> */
#define UBOUND(a, max)	({ typeof(a) b = (max); if ((a) > b) (a) = b; (a); })

/* if a < min, then bound <a> to <min>. The macro returns the new <a> */
#define LBOUND(a, min)	({ typeof(a) b = (min); if ((a) < b) (a) = b; (a); })

#define SWAP(a, b) do { typeof(a) t; t = a; a = b; b = t; } while(0)

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
extern THREAD_LOCAL int itoa_idx; /* index of next itoa_str to use */
extern THREAD_LOCAL char itoa_str[][171];
extern char *ultoa_r(unsigned long n, char *buffer, int size);
extern char *lltoa_r(long long int n, char *buffer, int size);
extern char *sltoa_r(long n, char *buffer, int size);
extern const char *ulltoh_r(unsigned long long n, char *buffer, int size);
static inline const char *ultoa(unsigned long n)
{
	return ultoa_r(n, itoa_str[0], sizeof(itoa_str[0]));
}

/*
 * unsigned long long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *ulltoa(unsigned long long n, char *dst, size_t size);


/*
 * unsigned long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *ultoa_o(unsigned long n, char *dst, size_t size);

/*
 * signed long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *ltoa_o(long int n, char *dst, size_t size);

/*
 * signed long long ASCII representation
 *
 * return the last char '\0' or NULL if no enough
 * space in dst
 */
char *lltoa(long long n, char *dst, size_t size);

/*
 * write a ascii representation of a unsigned into dst,
 * return a pointer to the last character
 * Pad the ascii representation with '0', using size.
 */
char *utoa_pad(unsigned int n, char *dst, size_t size);

/*
 * This function simply returns a locally allocated string containing the ascii
 * representation for number 'n' in decimal, unless n is 0 in which case it
 * returns the alternate string (or an empty string if the alternate string is
 * NULL). It use is intended for limits reported in reports, where it's
 * desirable not to display anything if there is no limit. Warning! it shares
 * the same vector as ultoa_r().
 */
extern const char *limit_r(unsigned long n, char *buffer, int size, const char *alt);

/* returns a locally allocated string containing the ASCII representation of
 * the number 'n' in decimal. Up to NB_ITOA_STR calls may be used in the same
 * function call (eg: printf), shared with the other similar functions making
 * use of itoa_str[].
 */
static inline const char *U2A(unsigned long n)
{
	const char *ret = ultoa_r(n, itoa_str[itoa_idx], sizeof(itoa_str[0]));
	if (++itoa_idx >= NB_ITOA_STR)
		itoa_idx = 0;
	return ret;
}

/* returns a locally allocated string containing the HTML representation of
 * the number 'n' in decimal. Up to NB_ITOA_STR calls may be used in the same
 * function call (eg: printf), shared with the other similar functions making
 * use of itoa_str[].
 */
static inline const char *U2H(unsigned long long n)
{
	const char *ret = ulltoh_r(n, itoa_str[itoa_idx], sizeof(itoa_str[0]));
	if (++itoa_idx >= NB_ITOA_STR)
		itoa_idx = 0;
	return ret;
}

/* returns a locally allocated string containing the ASCII representation of
 * the number 'n' in decimal. Up to NB_ITOA_STR calls may be used in the same
 * function call (eg: printf), shared with the other similar functions making
 * use of itoa_str[].
 */
static inline const char *LIM2A(unsigned long n, const char *alt)
{
	const char *ret = limit_r(n, itoa_str[itoa_idx], sizeof(itoa_str[0]), alt);
	if (++itoa_idx >= NB_ITOA_STR)
		itoa_idx = 0;
	return ret;
}

/* returns a locally allocated string containing the quoted encoding of the
 * input string. The output may be truncated to QSTR_SIZE chars, but it is
 * guaranteed that the string will always be properly terminated. Quotes are
 * encoded by doubling them as is commonly done in CSV files. QSTR_SIZE must
 * always be at least 4 chars.
 */
const char *qstr(const char *str);

/* returns <str> or its quote-encoded equivalent if it contains at least one
 * quote or a comma. This is aimed at build CSV-compatible strings.
 */
static inline const char *cstr(const char *str)
{
	const char *p = str;

	while (*p) {
		if (*p == ',' || *p == '"')
			return qstr(str);
		p++;
	}
	return str;
}

/*
 * Returns non-zero if character <s> is a hex digit (0-9, a-f, A-F), else zero.
 */
extern int ishex(char s);

/*
 * Checks <name> for invalid characters. Valid chars are [A-Za-z0-9_:.-]. If an
 * invalid character is found, a pointer to it is returned. If everything is
 * fine, NULL is returned.
 */
extern const char *invalid_char(const char *name);

/*
 * Checks <name> for invalid characters. Valid chars are [A-Za-z0-9_.-].
 * If an invalid character is found, a pointer to it is returned.
 * If everything is fine, NULL is returned.
 */
extern const char *invalid_domainchar(const char *name);

/*
 * Checks <name> for invalid characters. Valid chars are [A-Za-z_.-].
 * If an invalid character is found, a pointer to it is returned.
 * If everything is fine, NULL is returned.
 */
extern const char *invalid_prefix_char(const char *name);

/* returns true if <c> is an identifier character, that is, a digit, a letter,
 * or '-', '+', '_', ':' or '.'. This is usable for proxy names, server names,
 * ACL names, sample fetch names, and converter names.
 */
static inline int is_idchar(char c)
{
	return isalnum((unsigned char)c) ||
	       c == '.' || c == '_' || c == '-' || c == '+' || c == ':';
}

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
 * If <pfx> is non-null, it is used as a string prefix before any path-based
 * address (typically the path to a unix socket).
 */
struct sockaddr_storage *str2sa_range(const char *str, int *port, int *low, int *high, int *fd,
                                      struct protocol **proto, char **err,
                                      const char *pfx, char **fqdn, unsigned int opts);


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
char *sa2str(const struct sockaddr_storage *addr, int port, int map_ports);

/* converts <str> to a struct in_addr containing a network mask. It can be
 * passed in dotted form (255.255.255.0) or in CIDR form (24). It returns 1
 * if the conversion succeeds otherwise zero.
 */
int str2mask(const char *str, struct in_addr *mask);

/* converts <str> to a struct in6_addr containing a network mask. It can be
 * passed in quadruplet form (ffff:ffff::) or in CIDR form (64). It returns 1
 * if the conversion succeeds otherwise zero.
 */
int str2mask6(const char *str, struct in6_addr *mask);

/* convert <cidr> to struct in_addr <mask>. It returns 1 if the conversion
 * succeeds otherwise non-zero.
 */
int cidr2dotted(int cidr, struct in_addr *mask);

/*
 * converts <str> to two struct in_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optional and either in the dotted or CIDR notation.
 * Note: "addr" can also be a hostname. Returns 1 if OK, 0 if error.
 */
int str2net(const char *str, int resolve, struct in_addr *addr, struct in_addr *mask);

/* str2ip and str2ip2:
 *
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
 * The IPv6 '::' address is IN6ADDR_ANY.
 *
 * str2ip2:
 *
 * If <resolve> is set, this function try to resolve DNS, otherwise, it returns
 * NULL result.
 */
struct sockaddr_storage *str2ip2(const char *str, struct sockaddr_storage *sa, int resolve);
static inline struct sockaddr_storage *str2ip(const char *str, struct sockaddr_storage *sa)
{
	return str2ip2(str, sa, 1);
}

/*
 * converts <str> to two struct in6_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is an optional number of bits (128 being the default).
 * Returns 1 if OK, 0 if error.
 */
int str62net(const char *str, struct in6_addr *addr, unsigned char *mask);

/*
 * Parse IP address found in url.
 */
int url2ipv4(const char *addr, struct in_addr *dst);

/*
 * Resolve destination server from URL. Convert <str> to a sockaddr_storage*.
 */
int url2sa(const char *url, int ulen, struct sockaddr_storage *addr, struct split_url *out);

/* Tries to convert a sockaddr_storage address to text form. Upon success, the
 * address family is returned so that it's easy for the caller to adapt to the
 * output format. Zero is returned if the address family is not supported. -1
 * is returned upon error, with errno set. AF_INET, AF_INET6 and AF_UNIX are
 * supported.
 */
int addr_to_str(const struct sockaddr_storage *addr, char *str, int size);

/* Tries to convert a sockaddr_storage port to text form. Upon success, the
 * address family is returned so that it's easy for the caller to adapt to the
 * output format. Zero is returned if the address family is not supported. -1
 * is returned upon error, with errno set. AF_INET, AF_INET6 and AF_UNIX are
 * supported.
 */
int port_to_str(const struct sockaddr_storage *addr, char *str, int size);

/* check if the given address is local to the system or not. It will return
 * -1 when it's not possible to know, 0 when the address is not local, 1 when
 * it is. We don't want to iterate over all interfaces for this (and it is not
 * portable). So instead we try to bind in UDP to this address on a free non
 * privileged port and to connect to the same address, port 0 (connect doesn't
 * care). If it succeeds, we own the address. Note that non-inet addresses are
 * considered local since they're most likely AF_UNIX.
 */
int addr_is_local(const struct netns_entry *ns,
                  const struct sockaddr_storage *orig);

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
		    const char escape, const long *map,
		    const char *string);

/*
 * Same behavior, except that it encodes chunk <chunk> instead of a string.
 */
char *encode_chunk(char *start, char *stop,
                   const char escape, const long *map,
                   const struct buffer *chunk);

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
		    const char *string);

/*
 * Tries to prefix characters tagged in the <map> with the <escape>
 * character. <chunk> contains the input to be escaped. The result will be
 * stored between <start> (included) and <stop> (excluded). The function
 * will always try to terminate the resulting string with a '\0' before
 * <stop>, and will return its position if the conversion completes.
 */
char *escape_chunk(char *start, char *stop,
                   const char escape, const long *map,
                   const struct buffer *chunk);


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
 * If <quote> is 1, the converter puts the quotes only if any character is
 * escaped. If <quote> is 2, the converter always puts the quotes.
 *
 * <output> is a struct chunk used for storing the output string.
 *
 * The function returns the converted string on its output. If an error
 * occurs, the function returns an empty string. This type of output is useful
 * for using the function directly as printf() argument.
 *
 * If the output buffer is too short to contain the input string, the result
 * is truncated.
 *
 * This function appends the encoding to the existing output chunk. Please
 * use csv_enc() instead if you want to replace the output chunk.
 */
const char *csv_enc_append(const char *str, int quote, struct buffer *output);

/* same as above but the output chunk is reset first */
static inline const char *csv_enc(const char *str, int quote,
				  struct buffer *output)
{
	chunk_reset(output);
	return csv_enc_append(str, quote, output);
}

/* Decode an URL-encoded string in-place. The resulting string might
 * be shorter. If some forbidden characters are found, the conversion is
 * aborted, the string is truncated before the issue and non-zero is returned,
 * otherwise the operation returns non-zero indicating success.
 * If the 'in_form' argument is non-nul the string is assumed to be part of
 * an "application/x-www-form-urlencoded" encoded string, and the '+' will be
 * turned to a space. If it's zero, this will only be done after a question
 * mark ('?').
 */
int url_decode(char *string, int in_form);

unsigned int inetaddr_host(const char *text);
unsigned int inetaddr_host_lim(const char *text, const char *stop);
unsigned int inetaddr_host_lim_ret(char *text, char *stop, char **ret);

static inline char *cut_crlf(char *s) {

	while (*s != '\r' && *s != '\n') {
		char *p = s++;

		if (!*p)
			return p;
	}

	*s++ = '\0';

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
 * function instead of localtime() because that one requires a time_t* which
 * is not always compatible with tv_sec depending on OS/hardware combinations.
 */
static inline void get_localtime(const time_t now, struct tm *tm)
{
	localtime_r(&now, tm);
}

/* This function converts the time_t value <now> into a broken out struct tm
 * which must be allocated by the caller. It is highly recommended to use this
 * function instead of gmtime() because that one requires a time_t* which
 * is not always compatible with tv_sec depending on OS/hardware combinations.
 */
static inline void get_gmtime(const time_t now, struct tm *tm)
{
	gmtime_r(&now, tm);
}

/* Counts a number of elapsed days since 01/01/0000 based solely on elapsed
 * years and assuming the regular rule for leap years applies. It's fake but
 * serves as a temporary origin. It's worth remembering that it's the first
 * year of each period that is leap and not the last one, so for instance year
 * 1 sees 366 days since year 0 was leap. For this reason we have to apply
 * modular arithmetic which is why we offset the year by 399 before
 * subtracting the excess at the end. No overflow here before ~11.7 million
 * years.
 */
static inline unsigned int days_since_zero(unsigned int y)
{
	return y * 365 + (y + 399) / 4 - (y + 399) / 100 + (y + 399) / 400
	       - 399 / 4 + 399 / 100;
}

/* Returns the number of seconds since 01/01/1970 0:0:0 GMT for GMT date <tm>.
 * It is meant as a portable replacement for timegm() for use with valid inputs.
 * Returns undefined results for invalid dates (eg: months out of range 0..11).
 */
extern time_t my_timegm(const struct tm *tm);

/* This function parses a time value optionally followed by a unit suffix among
 * "d", "h", "m", "s", "ms" or "us". It converts the value into the unit
 * expected by the caller. The computation does its best to avoid overflows.
 * The value is returned in <ret> if everything is fine, and a NULL is returned
 * by the function. In case of error, a pointer to the error is returned and
 * <ret> is left untouched.
 */
extern const char *parse_time_err(const char *text, unsigned *ret, unsigned unit_flags);
extern const char *parse_size_err(const char *text, unsigned *ret);

/*
 * Parse binary string written in hexadecimal (source) and store the decoded
 * result into binstr and set binstrlen to the length of binstr. Memory for
 * binstr is allocated by the function. In case of error, returns 0 with an
 * error message in err.
 */
int parse_binary(const char *source, char **binstr, int *binstrlen, char **err);

/* copies at most <n> characters from <src> and always terminates with '\0' */
char *my_strndup(const char *src, int n);

/*
 * search needle in haystack
 * returns the pointer if found, returns NULL otherwise
 */
const void *my_memmem(const void *, size_t, const void *, size_t);

/* get length of the initial segment consisting entirely of bytes within a given
 * mask
 */
size_t my_memspn(const void *, size_t, const void *, size_t);

/* get length of the initial segment consisting entirely of bytes not within a
 * given mask
 */
size_t my_memcspn(const void *, size_t, const void *, size_t);

/* This function returns the first unused key greater than or equal to <key> in
 * ID tree <root>. Zero is returned if no place is found.
 */
unsigned int get_next_id(struct eb_root *root, unsigned int key);

/* dump the full tree to <file> in DOT format for debugging purposes. Will
 * optionally highlight node <subj> if found, depending on operation <op> :
 *    0 : nothing
 *   >0 : insertion, node/leaf are surrounded in red
 *   <0 : removal, node/leaf are dashed with no background
 * Will optionally add "desc" as a label on the graph if set and non-null.
 */
void eb32sc_to_file(FILE *file, struct eb_root *root, const struct eb32sc_node *subj,
                    int op, const char *desc);

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
int buf2ip6(const char *buf, size_t len, struct in6_addr *dst);

/* To be used to quote config arg positions. Returns the string at <ptr>
 * surrounded by simple quotes if <ptr> is valid and non-empty, or "end of line"
 * if ptr is NULL or empty. The string is locally allocated.
 */
const char *quote_arg(const char *ptr);

/* returns an operator among STD_OP_* for string <str> or < 0 if unknown */
int get_std_op(const char *str);

/* sets the address family to AF_UNSPEC so that is_addr() does not match */
static inline void clear_addr(struct sockaddr_storage *addr)
{
	addr->ss_family = AF_UNSPEC;
}

/* returns non-zero if addr has a valid and non-null IPv4 or IPv6 address,
 * otherwise zero.
 */
static inline int is_inet_addr(const struct sockaddr_storage *addr)
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

/* returns non-zero if addr has a valid and non-null IPv4 or IPv6 address,
 * or is a unix address, otherwise returns zero.
 */
static inline int is_addr(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_UNIX || addr->ss_family == AF_CUST_SOCKPAIR)
		return 1;
	else
		return is_inet_addr(addr);
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
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = port;
		break;
	}
	return 0;
}

/* set port in network byte order */
static inline int set_host_port(struct sockaddr_storage *addr, int port)
{
	switch (addr->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)addr)->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
		break;
	}
	return 0;
}

/* Convert mask from bit length form to in_addr form.
 * This function never fails.
 */
void len2mask4(int len, struct in_addr *addr);

/* Convert mask from bit length form to in6_addr form.
 * This function never fails.
 */
void len2mask6(int len, struct in6_addr *addr);

/* Return true if IPv4 address is part of the network */
extern int in_net_ipv4(const void *addr, const struct in_addr *mask, const struct in_addr *net);

/* Return true if IPv6 address is part of the network */
extern int in_net_ipv6(const void *addr, const struct in6_addr *mask, const struct in6_addr *net);

/* Map IPv4 address on IPv6 address, as specified in RFC 3513. */
extern void v4tov6(struct in6_addr *sin6_addr, struct in_addr *sin_addr);

/* Map IPv6 address on IPv4 address, as specified in RFC 3513.
 * Return true if conversion is possible and false otherwise.
 */
extern int v6tov4(struct in_addr *sin_addr, struct in6_addr *sin6_addr);

/* compare two struct sockaddr_storage and return:
 *  0 (true)  if the addr is the same in both
 *  1 (false) if the addr is not the same in both
 */
int ipcmp(struct sockaddr_storage *ss1, struct sockaddr_storage *ss2);

/* copy ip from <source> into <dest>
 * the caller must clear <dest> before calling.
 * Returns a pointer to the destination
 */
struct sockaddr_storage *ipcpy(struct sockaddr_storage *source, struct sockaddr_storage *dest);

char *human_time(int t, short hz_div);

extern const char *monthname[];

/* date2str_log: write a date in the format :
 * 	sprintf(str, "%02d/%s/%04d:%02d:%02d:%02d.%03d",
 *		tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
 *		tm.tm_hour, tm.tm_min, tm.tm_sec, (int)date.tv_usec/1000);
 *
 * without using sprintf. return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *date2str_log(char *dest, const struct tm *tm, const struct timeval *date, size_t size);

/* Return the GMT offset for a specific local time.
 * Both t and tm must represent the same time.
 * The string returned has the same format as returned by strftime(... "%z", tm).
 * Offsets are kept in an internal cache for better performances.
 */
const char *get_gmt_offset(time_t t, struct tm *tm);

/* gmt2str_log: write a date in the format :
 * "%02d/%s/%04d:%02d:%02d:%02d +0000" without using snprintf
 * return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *gmt2str_log(char *dst, struct tm *tm, size_t size);

/* localdate2str_log: write a date in the format :
 * "%02d/%s/%04d:%02d:%02d:%02d +0000(local timezone)" without using snprintf
 * Both t and tm must represent the same time.
 * return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *localdate2str_log(char *dst, time_t t, struct tm *tm, size_t size);

/* These 3 functions parses date string and fills the
 * corresponding broken-down time in <tm>. In success case,
 * it returns 1, otherwise, it returns 0.
 */
int parse_http_date(const char *date, int len, struct tm *tm);
int parse_imf_date(const char *date, int len, struct tm *tm);
int parse_rfc850_date(const char *date, int len, struct tm *tm);
int parse_asctime_date(const char *date, int len, struct tm *tm);

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
char *memvprintf(char **out, const char *format, va_list args)
	__attribute__ ((format(printf, 2, 0)));

char *memprintf(char **out, const char *format, ...)
	__attribute__ ((format(printf, 2, 3)));

/* Used to add <level> spaces before each line of <out>, unless there is only one line.
 * The input argument is automatically freed and reassigned. The result will have to be
 * freed by the caller.
 * Example of use :
 *   parse(cmd, &err); (callee: memprintf(&err, ...))
 *   fprintf(stderr, "Parser said: %s\n", indent_error(&err));
 *   free(err);
 */
char *indent_msg(char **out, int level);
int append_prefixed_str(struct buffer *out, const char *in, const char *pfx, char eol, int first);

/* removes environment variable <name> from the environment as found in
 * environ. This is only provided as an alternative for systems without
 * unsetenv() (old Solaris and AIX versions). THIS IS NOT THREAD SAFE.
 * The principle is to scan environ for each occurrence of variable name
 * <name> and to replace the matching pointers with the last pointer of
 * the array (since variables are not ordered).
 * It always returns 0 (success).
 */
int my_unsetenv(const char *name);

/* Convert occurrences of environment variables in the input string to their
 * corresponding value. A variable is identified as a series of alphanumeric
 * characters or underscores following a '$' sign. The <in> string must be
 * free()able. NULL returns NULL. The resulting string might be reallocated if
 * some expansion is made.
 */
char *env_expand(char *in);
uint32_t parse_line(char *in, char *out, size_t *outlen, char **args, int *nbargs, uint32_t opts, char **errptr);
size_t sanitize_for_printing(char *line, size_t pos, size_t width);

/* debugging macro to emit messages using write() on fd #-1 so that strace sees
 * them.
 */
#define fddebug(msg...) do { char *_m = NULL; memprintf(&_m, ##msg); if (_m) write(-1, _m, strlen(_m)); free(_m); } while (0)

/* displays a <len> long memory block at <buf>, assuming first byte of <buf>
 * has address <baseaddr>. String <pfx> may be placed as a prefix in front of
 * each line. It may be NULL if unused. The output is emitted to file <out>.
 */
void debug_hexdump(FILE *out, const char *pfx, const char *buf, unsigned int baseaddr, int len);

/* this is used to emit call traces when building with TRACE=1 */
__attribute__((format(printf, 1, 2)))
void calltrace(char *fmt, ...);

/* same as strstr() but case-insensitive */
const char *strnistr(const char *str1, int len_str1, const char *str2, int len_str2);

/* after increasing a pointer value, it can exceed the first buffer
 * size. This function transform the value of <ptr> according with
 * the expected position. <chunks> is an array of the one or two
 * available chunks. The first value is the start of the first chunk,
 * the second value if the end+1 of the first chunks. The third value
 * is NULL or the start of the second chunk and the fourth value is
 * the end+1 of the second chunk. The function returns 1 if does a
 * wrap, else returns 0.
 */
static inline int fix_pointer_if_wrap(const char **chunks, const char **ptr)
{
	if (*ptr < chunks[1])
		return 0;
	if (!chunks[2])
		return 0;
	*ptr = chunks[2] + ( *ptr - chunks[1] );
	return 1;
}

/************************* Composite address manipulation *********************
 * Composite addresses are simply unsigned long data in which the higher bits
 * represent a pointer, and the two lower bits are flags. There are several
 * places where we just want to associate one or two flags to a pointer (eg,
 * to type it), and these functions permit this. The pointer is necessarily a
 * 32-bit aligned pointer, as its two lower bits will be cleared and replaced
 * with the flags.
 *****************************************************************************/

/* Masks the two lower bits of a composite address and converts it to a
 * pointer. This is used to mix some bits with some aligned pointers to
 * structs and to retrieve the original (32-bit aligned) pointer.
 */
static inline void *caddr_to_ptr(unsigned long caddr)
{
	return (void *)(caddr & ~3UL);
}

/* Only retrieves the two lower bits of a composite address. This is used to mix
 * some bits with some aligned pointers to structs and to retrieve the original
 * data (2 bits).
 */
static inline unsigned int caddr_to_data(unsigned long caddr)
{
	return (caddr & 3UL);
}

/* Combines the aligned pointer whose 2 lower bits will be masked with the bits
 * from <data> to form a composite address. This is used to mix some bits with
 * some aligned pointers to structs and to retrieve the original (32-bit aligned)
 * pointer.
 */
static inline unsigned long caddr_from_ptr(void *ptr, unsigned int data)
{
	return (((unsigned long)ptr) & ~3UL) + (data & 3);
}

/* sets the 2 bits of <data> in the <caddr> composite address */
static inline unsigned long caddr_set_flags(unsigned long caddr, unsigned int data)
{
	return caddr | (data & 3);
}

/* clears the 2 bits of <data> in the <caddr> composite address */
static inline unsigned long caddr_clr_flags(unsigned long caddr, unsigned int data)
{
	return caddr & ~(unsigned long)(data & 3);
}

unsigned char utf8_next(const char *s, int len, unsigned int *c);

static inline unsigned char utf8_return_code(unsigned int code)
{
	return code & 0xf0;
}

static inline unsigned char utf8_return_length(unsigned char code)
{
	return code & 0x0f;
}

/* returns a 64-bit a timestamp with the finest resolution available. The
 * unit is intentionally not specified. It's mostly used to compare dates.
 */
#if defined(__i386__) || defined(__x86_64__)
static inline unsigned long long rdtsc()
{
     unsigned int a, d;
     asm volatile("rdtsc" : "=a" (a), "=d" (d));
     return a + ((unsigned long long)d << 32);
}
#else
static inline unsigned long long rdtsc()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}
#endif

/* append a copy of string <str> (in a wordlist) at the end of the list <li>
 * On failure : return 0 and <err> filled with an error message.
 * The caller is responsible for freeing the <err> and <str> copy
 * memory area using free()
 */
struct list;
int list_append_word(struct list *li, const char *str, char **err);

int dump_text(struct buffer *out, const char *buf, int bsize);
int dump_binary(struct buffer *out, const char *buf, int bsize);
int dump_text_line(struct buffer *out, const char *buf, int bsize, int len,
                   int *line, int ptr);
void dump_addr_and_bytes(struct buffer *buf, const char *pfx, const void *addr, int n);
void dump_hex(struct buffer *out, const char *pfx, const void *buf, int len, int unsafe);
int may_access(const void *ptr);
const void *resolve_sym_name(struct buffer *buf, const char *pfx, void *addr);
const char *get_exec_path();

#if defined(USE_BACKTRACE)
/* Note that this may result in opening libgcc() on first call, so it may need
 * to have been called once before chrooting.
 */
static forceinline int my_backtrace(void **buffer, int max)
{
#ifdef HA_HAVE_WORKING_BACKTRACE
	return backtrace(buffer, max);
#else
	const struct frame {
		const struct frame *next;
		void *ra;
	} *frame;
	int count;

	frame = __builtin_frame_address(0);
	for (count = 0; count < max && may_access(frame) && may_access(frame->ra);) {
		buffer[count++] = frame->ra;
		frame = frame->next;
	}
	return count;
#endif
}
#endif

/* same as realloc() except that ptr is also freed upon failure */
static inline void *my_realloc2(void *ptr, size_t size)
{
	void *ret;

	ret = realloc(ptr, size);
	if (!ret && size)
		free(ptr);
	return ret;
}

int parse_dotted_uints(const char *s, unsigned int **nums, size_t *sz);

/* PRNG */
void ha_generate_uuid(struct buffer *output);
void ha_random_seed(const unsigned char *seed, size_t len);
void ha_random_jump96(uint32_t dist);
uint64_t ha_random64();

static inline uint32_t ha_random32()
{
	return ha_random64() >> 32;
}

static inline int32_t ha_random()
{
	return ha_random32() >> 1;
}

#endif /* _HAPROXY_TOOLS_H */
