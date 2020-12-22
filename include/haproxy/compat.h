/*
 * include/haproxy/compat.h
 * Operating system compatibility interface.
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

#ifndef _HAPROXY_COMPAT_H
#define _HAPROXY_COMPAT_H

#include <limits.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
/* This is needed on Linux for Netfilter includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* set any optional field in a struct to this type to save ifdefs. Its address
 * will still be valid but it will not reserve any room nor require any
 * initialization.
 */
typedef struct { } empty_t;

// Redefine some limits that are not present everywhere
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

#ifndef BITS_PER_INT
#define BITS_PER_INT    (8*sizeof(int))
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* this is for libc5 for example */
#ifndef TCP_NODELAY
#define TCP_NODELAY     1
#endif

#ifndef SHUT_RD
#define SHUT_RD	        0
#endif

#ifndef SHUT_WR
#define SHUT_WR	        1
#endif

/* only Linux defines it */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0
#endif

/* AIX does not define MSG_DONTWAIT. We'll define it to zero, and test it
 * wherever appropriate.
 */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT	0
#endif

/* Only Linux defines MSG_MORE */
#ifndef MSG_MORE
#define MSG_MORE	0
#endif

/* On Linux 2.4 and above, MSG_TRUNC can be used on TCP sockets to drop any
 * pending data. Let's rely on NETFILTER to detect if this is supported.
 */
#ifdef USE_NETFILTER
#define MSG_TRUNC_CLEARS_INPUT
#endif

/* Maximum path length, OS-dependant */
#ifndef MAXPATHLEN
#define MAXPATHLEN 128
#endif

/* longest UNIX socket name */
#ifndef UNIX_MAX_PATH
#define UNIX_MAX_PATH 108
#endif

/* On Linux, allows pipes to be resized */
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (1024 + 7)
#endif

/* On FreeBSD we don't have SI_TKILL but SI_LWP instead */
#if !defined(SI_TKILL) && defined(SI_LWP)
#define SI_TKILL SI_LWP
#endif

/* systems without such defines do not know clockid_t or timer_t */
#if !(_POSIX_TIMERS > 0)
#undef clockid_t
#define clockid_t empty_t
#undef timer_t
#define timer_t empty_t
#endif

/* define a dummy value to designate "no timer". Use only 32 bits. */
#ifndef TIMER_INVALID
#define TIMER_INVALID ((timer_t)(unsigned long)(0xfffffffful))
#endif

#if defined(USE_TPROXY) && defined(USE_NETFILTER)
#include <linux/types.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_ipv4.h>
#endif

/* On Linux, IP_TRANSPARENT and/or IP_FREEBIND generally require a kernel patch */
#if defined(USE_LINUX_TPROXY)
#if !defined(IP_FREEBIND)
#define IP_FREEBIND 15
#endif /* !IP_FREEBIND */
#if !defined(IP_TRANSPARENT)
#define IP_TRANSPARENT 19
#endif /* !IP_TRANSPARENT */
#if !defined(IPV6_TRANSPARENT)
#define IPV6_TRANSPARENT 75
#endif /* !IPV6_TRANSPARENT */
#endif /* USE_LINUX_TPROXY */

#if defined(IP_FREEBIND)       \
 || defined(IP_BINDANY)        \
 || defined(IPV6_BINDANY)      \
 || defined(SO_BINDANY)        \
 || defined(IP_TRANSPARENT)    \
 || defined(IPV6_TRANSPARENT)
#define CONFIG_HAP_TRANSPARENT
#endif

/* We'll try to enable SO_REUSEPORT on Linux 2.4 and 2.6 if not defined.
 * There are two families of values depending on the architecture. Those
 * are at least valid on Linux 2.4 and 2.6, reason why we'll rely on the
 * USE_NETFILTER define.
 */
#if !defined(SO_REUSEPORT) && defined(USE_NETFILTER)
#if    (SO_REUSEADDR == 2)
#define SO_REUSEPORT 15
#elif  (SO_REUSEADDR == 0x0004)
#define SO_REUSEPORT 0x0200
#endif /* SO_REUSEADDR */
#endif /* SO_REUSEPORT */

/* only Linux defines TCP_FASTOPEN */
#ifdef USE_TFO
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif
#endif

/* FreeBSD doesn't define SOL_IP and prefers IPPROTO_IP */
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

/* same for SOL_TCP */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

/* If IPv6 is supported, define IN6_IS_ADDR_V4MAPPED() if missing. */
#if defined(IPV6_TCLASS) && !defined(IN6_IS_ADDR_V4MAPPED)
#define IN6_IS_ADDR_V4MAPPED(a) \
((((const uint32_t *) (a))[0] == 0) \
&& (((const uint32_t *) (a))[1] == 0) \
&& (((const uint32_t *) (a))[2] == htonl (0xffff)))
#endif

#if defined(__dietlibc__)
#include <strings.h>
#endif

/* crypt_r() has been present in glibc since 2.2 and on FreeBSD since 12.0
 * (12000002). No other OS makes any mention of it for now. Feel free to add
 * valid known combinations below if needed to relax the crypt() lock when
 * using threads.
 */
#if (defined(__GNU_LIBRARY__) && (__GLIBC__ > 2 || __GLIBC__ == 2 && __GLIBC_MINOR__ >= 2)) \
 || (defined(__FreeBSD__) && __FreeBSD_version >= 1200002)
#define HA_HAVE_CRYPT_R
#endif

/* some backtrace() implementations are broken or incomplete, in this case we
 * can replace them. We must not do it all the time as some are more accurate
 * than ours.
 */
#ifdef USE_BACKTRACE
#if defined(__aarch64__)
/* on aarch64 at least from gcc-4.7.4 to 7.4.1 we only get a single entry, which
 * is pointless. Ours works though it misses the faulty function itself,
 * probably due to an alternate stack for the signal handler which does not
 * create a new frame hence doesn't store the caller's return address.
 */
#elif defined(__clang__) && defined(__x86_64__)
/* this is on FreeBSD, clang 4.0 to 8.0 produce don't go further than the
 * sighandler.
 */
#else
#define HA_HAVE_WORKING_BACKTRACE
#endif
#endif

/* malloc_trim() can be very convenient to reclaim unused memory especially
 * from huge pattern files. It's available (and really usable) in glibc 2.8 and
 * above.
 */
#if (defined(__GNU_LIBRARY__) && (__GLIBC__ > 2 || __GLIBC__ == 2 && __GLIBC_MINOR__ >= 8))
#include <malloc.h>
#define HA_HAVE_MALLOC_TRIM
#endif

/* Max number of file descriptors we send in one sendmsg(). Linux seems to be
 * able to send 253 fds per sendmsg(), not sure about the other OSes.
 */
#define MAX_SEND_FD 253

/* Make the new complex name for the xxhash function easier to remember
 * and use.
 */
#ifndef XXH3
#define XXH3(data, len, seed) XXH3_64bits_withSeed(data, len, seed)
#endif

#endif /* _HAPROXY_COMPAT_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
