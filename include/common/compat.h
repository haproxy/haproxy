/*
 * include/common/compat.h
 * Operating system compatibility interface.
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

#ifndef _COMMON_COMPAT_H
#define _COMMON_COMPAT_H

#include <limits.h>
/* This is needed on Linux for Netfilter includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifndef BITS_PER_INT
#define BITS_PER_INT    (8*sizeof(int))
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
#ifdef NETFILTER
#define MSG_TRUNC_CLEARS_INPUT
#endif

/* Maximum path length, OS-dependant */
#ifndef MAXPATHLEN
#define MAXPATHLEN 128
#endif

/* On Linux, allows pipes to be resized */
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (1024 + 7)
#endif

#if defined(TPROXY) && defined(NETFILTER)
#include <linux/types.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_ipv4.h>
#endif

/* On Linux, IP_TRANSPARENT and/or IP_FREEBIND generally require a kernel patch */
#if defined(CONFIG_HAP_LINUX_TPROXY)
#if !defined(IP_FREEBIND)
#define IP_FREEBIND 15
#endif /* !IP_FREEBIND */
#if !defined(IP_TRANSPARENT)
#define IP_TRANSPARENT 19
#endif /* !IP_TRANSPARENT */
#if !defined(IPV6_TRANSPARENT)
#define IPV6_TRANSPARENT 75
#endif /* !IPV6_TRANSPARENT */
#endif /* CONFIG_HAP_LINUX_TPROXY */

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
 * NETFILTER define.
 */
#if !defined(SO_REUSEPORT) && defined(NETFILTER)
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

#endif /* _COMMON_COMPAT_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
