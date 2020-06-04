/*
 * include/haproxy/capture-t.h
 * This file defines types for captures.
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

#ifndef _HAPROXY_CAPTURE_T_H
#define _HAPROXY_CAPTURE_T_H

#include <haproxy/pool-t.h>

struct cap_hdr {
    struct cap_hdr *next;
    char *name;				/* header name, case insensitive, NULL if not header */
    int namelen;			/* length of the header name, to speed-up lookups, 0 if !name */
    int len;				/* capture length, not including terminal zero */
    int index;				/* index in the output array */
    struct pool_head *pool;		/* pool of pre-allocated memory area of (len+1) bytes */
};

#endif /* _HAPROXY_CAPTURE_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
