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

/****** string-specific macros and functions ******/
/* if a > max, then bound <a> to <max>. The macro returns the new <a> */
#define UBOUND(a, max)	({ typeof(a) b = (max); if ((a) > b) (a) = b; (a); })

/* if a < min, then bound <a> to <min>. The macro returns the new <a> */
#define LBOUND(a, min)	({ typeof(a) b = (min); if ((a) < b) (a) = b; (a); })

#define SWAP(a, b) do { typeof(a) t; t = a; a = b; b = t; } while(0)

/* returns true if <c> is an identifier character, that is, a digit, a letter,
 * or '-', '+', '_', ':' or '.'. This is usable for proxy names, server names,
 * ACL names, sample fetch names, and converter names.
 */
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

/* Note that this may result in opening libgcc() on first call, so it may need
 * to have been called once before chrooting.
 */
static forceinline int my_backtrace(void **buffer, int max)
{
#if !defined(USE_BACKTRACE)
	return 0;
#elif defined(HA_HAVE_WORKING_BACKTRACE)
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

/* same as realloc() except that ptr is also freed upon failure */
static inline void *my_realloc2(void *ptr, size_t size)
{
	void *ret;

	ret = realloc(ptr, size);
	if (!ret && size)
		free(ptr);
	return ret;
}

#endif /* _HAPROXY_TOOLS_H */
