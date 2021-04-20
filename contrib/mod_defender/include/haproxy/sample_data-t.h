/*
 * include/haproxy/sample_data-t.h
 * Definitions of sample data
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2020 Willy Tarreau <w@1wt.eu>
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

#ifndef _HAPROXY_SAMPLE_DATA_T_H
#define _HAPROXY_SAMPLE_DATA_T_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <haproxy/buf-t.h>
#include <haproxy/http-t.h>

/* Note: the strings below make use of chunks. Chunks may carry an allocated
 * size in addition to the length. The size counts from the beginning (str)
 * to the end. If the size is unknown, it MUST be zero, in which case the
 * sample will automatically be duplicated when a change larger than <len> has
 * to be performed. Thus it is safe to always set size to zero.
 */
union sample_value {
	long long int   sint;  /* used for signed 64bits integers */
	struct in_addr  ipv4;  /* used for ipv4 addresses */
	struct in6_addr ipv6;  /* used for ipv6 addresses */
	struct buffer    str;   /* used for char strings or buffers */
	struct http_meth meth;  /* used for http method */
};

/* Used to store sample constant */
struct sample_data {
	int type;                 /* SMP_T_* */
	union sample_value u;     /* sample data */
};

#endif /* _HAPROXY_SAMPLE_DATA_T_H */
