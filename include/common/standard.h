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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <common/chunk.h>
#include <common/config.h>
#include <eb32tree.h>

#ifndef LLONG_MAX
# define LLONG_MAX 9223372036854775807LL
# define LLONG_MIN (-LLONG_MAX - 1LL)
#endif

#ifndef ULLONG_MAX
# define ULLONG_MAX	(LLONG_MAX * 2ULL + 1)
#endif

#ifndef LONGBITS
#define LONGBITS  ((unsigned int)sizeof(long) * 8)
#endif

/* size used for max length of decimal representation of long long int. */
#define NB_LLMAX_STR (sizeof("-9223372036854775807")-1)

/* number of itoa_str entries */
#define NB_ITOA_STR	10

/* maximum quoted string length (truncated above) */
#define QSTR_SIZE 200
#define NB_QSTR 10

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

enum http_scheme {
	SCH_HTTP,
	SCH_HTTPS,
};

struct split_url {
	enum http_scheme scheme;
	const char *host;
	int host_len;
};

extern int itoa_idx; /* index of next itoa_str to use */

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

/* returns a locally allocated string containing the HTML representation of
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
 * Return integer equivalent of character <c> for a hex digit (0-9, a-f, A-F),
 * otherwise -1. This compact form helps gcc produce efficient code.
 */
static inline int hex2i(int c)
{
	if (unlikely((unsigned char)(c -= '0') > 9)) {
		if (likely((unsigned char)(c -= 'A' - '0') > 5 &&
			      (unsigned char)(c -= 'a' - 'A') > 5))
			c = -11;
		c += 10;
	}
	return c;
}

/* rounds <i> down to the closest value having max 2 digits */
unsigned int round_2dig(unsigned int i);

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
struct sockaddr_storage *str2sa_range(const char *str, int *low, int *high, char **err, const char *pfx);

/* converts <str> to a struct in_addr containing a network mask. It can be
 * passed in dotted form (255.255.255.0) or in CIDR form (24). It returns 1
 * if the conversion succeeds otherwise non-zero.
 */
int str2mask(const char *str, struct in_addr *mask);

/* convert <cidr> to struct in_addr <mask>. It returns 1 if the conversion
 * succeeds otherwise non-zero.
 */
int cidr2dotted(int cidr, struct in_addr *mask);

/*
 * converts <str> to two struct in_addr* which must be pre-allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optionnal and either in the dotted or CIDR notation.
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
 * is an optionnal number of bits (128 being the default).
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
int addr_to_str(struct sockaddr_storage *addr, char *str, int size);

/* Tries to convert a sockaddr_storage port to text form. Upon success, the
 * address family is returned so that it's easy for the caller to adapt to the
 * output format. Zero is returned if the address family is not supported. -1
 * is returned upon error, with errno set. AF_INET, AF_INET6 and AF_UNIX are
 * supported.
 */
int port_to_str(struct sockaddr_storage *addr, char *str, int size);

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

/*
 * Same behavior, except that it encodes chunk <chunk> instead of a string.
 */
char *encode_chunk(char *start, char *stop,
                   const char escape, const fd_set *map,
                   const struct chunk *chunk);


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
 * If the output buffer is too short to conatin the input string, the result
 * is truncated.
 */
const char *csv_enc(const char *str, int quote, struct chunk *output);

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
extern int strl2llrc_dotted(const char *text, int len, long long *ret);
extern unsigned int read_uint(const char **s, const char *end);
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

#define SEC 1
#define MINUTE (60 * SEC)
#define HOUR (60 * MINUTE)
#define DAY (24 * HOUR)

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

/* Simple popcountl implementation. It returns the number of ones in a word */
static inline unsigned int my_popcountl(unsigned long a)
{
	unsigned int cnt;
	for (cnt = 0; a; a >>= 1) {
		if (a & 1)
			cnt++;
	}
	return cnt;
}

/* Build a word with the <bits> lower bits set (reverse of my_popcountl) */
static inline unsigned long nbits(int bits)
{
	if (--bits < 0)
		return 0;
	else
		return (2UL << bits) - 1;
}

/*
 * Parse binary string written in hexadecimal (source) and store the decoded
 * result into binstr and set binstrlen to the lengh of binstr. Memory for
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
int buf2ip6(const char *buf, size_t len, struct in6_addr *dst);

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
	if (addr->ss_family == AF_UNIX)
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

char *human_time(int t, short hz_div);

extern const char *monthname[];

/* numeric timezone (that is, the hour and minute offset from UTC) */
char localtimezone[6];

/* date2str_log: write a date in the format :
 * 	sprintf(str, "%02d/%s/%04d:%02d:%02d:%02d.%03d",
 *		tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
 *		tm.tm_hour, tm.tm_min, tm.tm_sec, (int)date.tv_usec/1000);
 *
 * without using sprintf. return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *date2str_log(char *dest, struct tm *tm, struct timeval *date, size_t size);

/* gmt2str_log: write a date in the format :
 * "%02d/%s/%04d:%02d:%02d:%02d +0000" without using snprintf
 * return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *gmt2str_log(char *dst, struct tm *tm, size_t size);

/* localdate2str_log: write a date in the format :
 * "%02d/%s/%04d:%02d:%02d:%02d +0000(local timezone)" without using snprintf
 * return a pointer to the last char written (\0) or
 * NULL if there isn't enough space.
 */
char *localdate2str_log(char *dst, struct tm *tm, size_t size);

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

/* Convert occurrences of environment variables in the input string to their
 * corresponding value. A variable is identified as a series of alphanumeric
 * characters or underscores following a '$' sign. The <in> string must be
 * free()able. NULL returns NULL. The resulting string might be reallocated if
 * some expansion is made.
 */
char *env_expand(char *in);

/* debugging macro to emit messages using write() on fd #-1 so that strace sees
 * them.
 */
#define fddebug(msg...) do { char *_m = NULL; memprintf(&_m, ##msg); if (_m) write(-1, _m, strlen(_m)); free(_m); } while (0)

/* used from everywhere just to drain results we don't want to read and which
 * recent versions of gcc increasingly and annoyingly complain about.
 */
extern int shut_your_big_mouth_gcc_int;

/* used from everywhere just to drain results we don't want to read and which
 * recent versions of gcc increasingly and annoyingly complain about.
 */
static inline void shut_your_big_mouth_gcc(int r)
{
	shut_your_big_mouth_gcc_int = r;
}

/* same as strstr() but case-insensitive */
const char *strnistr(const char *str1, int len_str1, const char *str2, int len_str2);


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

/* UTF-8 decoder status */
#define UTF8_CODE_OK       0x00
#define UTF8_CODE_OVERLONG 0x10
#define UTF8_CODE_INVRANGE 0x20
#define UTF8_CODE_BADSEQ   0x40

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

#endif /* _COMMON_STANDARD_H */
