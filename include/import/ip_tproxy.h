/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (c) 2002-2004 BalaBit IT Ltd.
 * Author: Balázs Scheidler
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _IP_TPROXY_H
#define _IP_TPROXY_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/in.h>
#else
#include <netinet/in.h>
#ifndef IP_RECVORIGADDRS
#define IP_RECVORIGADDRS	11273
#define IP_ORIGADDRS	IP_RECVORIGADDRS
struct in_origaddrs {
        struct in_addr ioa_srcaddr;
        struct in_addr ioa_dstaddr;
        unsigned short int ioa_srcport;
        unsigned short int ioa_dstport;
};
#endif
#endif

/* 
 * used in setsockopt(SOL_IP, IP_TPROXY) should not collide 
 * with values in <linux/in.h> 
 */

#define IP_TPROXY	   11274

/* tproxy operations */
enum {
	TPROXY_VERSION = 0,
	TPROXY_ASSIGN,
	TPROXY_UNASSIGN,
	TPROXY_QUERY,
	TPROXY_FLAGS,
	TPROXY_ALLOC,
	TPROXY_CONNECT
};

/* bitfields in IP_TPROXY_FLAGS */
#define ITP_CONNECT     0x00000001
#define ITP_LISTEN      0x00000002
#define ITP_ESTABLISHED 0x00000004

#define ITP_ONCE        0x00010000
#define ITP_MARK        0x00020000
#define ITP_APPLIED     0x00040000
#define ITP_UNIDIR      0x00080000

struct in_tproxy_addr{
	struct in_addr	faddr;
	u_int16_t	fport;
};

struct in_tproxy {
	/* fixed part, should not change between versions */
	u_int32_t op;
	/* extensible part */
	union _in_args {
		u_int32_t		version;
		struct in_tproxy_addr	addr;
		u_int32_t		flags;
	} v;
};

#endif
