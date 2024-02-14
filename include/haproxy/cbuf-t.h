/*
 * include/haprox/cbuf-t.h
 * This file contains definition for circular buffers.
 *
 * Copyright 2021 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_CBUF_T_H
#define _HAPROXY_CBUF_T_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif
#endif

#include <stddef.h>
#include <haproxy/list-t.h>

extern struct pool_head *pool_head_cbuf;

struct cbuf {
	/* buffer */
	unsigned char *buf;
	/* buffer size */
	size_t sz;
	/* Writer index */
	size_t wr;
	/* Reader index */
	size_t rd;
};

#endif /* _HAPROXY_CBUF_T_H */
