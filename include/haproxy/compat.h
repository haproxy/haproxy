/*
  include/haproxy/compat.h
  Operating system compatibility interface.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _HAPROXY_COMPAT_H
#define _HAPROXY_COMPAT_H

/* This is needed on Linux for Netfilter includes */
#include <sys/socket.h>

/* INTBITS
 * how many bits are needed to code the size of an int on the target platform.
 * (eg: 32bits -> 5)
 */
#define	INTBITS	        5

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

#if defined(TPROXY) && defined(NETFILTER)
#include <linux/netfilter_ipv4.h>
#endif

#if defined(__dietlibc__)
#include <strings.h>
#endif

#endif /* _HAPROXY_COMPAT_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
