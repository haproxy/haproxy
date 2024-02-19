/*
 * include/haproxy/dns_ring.h
 * Exported functions for ring buffers used for disposable data.
 * This is a fork of ring.h for DNS usage.
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_DNS_RING_H
#define _HAPROXY_DNS_RING_H

#include <stdlib.h>
#include <import/ist.h>
#include <haproxy/dns_ring-t.h>

struct appctx;

struct dns_ring *dns_ring_new(size_t size);
void dns_ring_init(struct dns_ring *ring, void* area, size_t size);
void dns_ring_free(struct dns_ring *ring);
ssize_t dns_ring_write(struct dns_ring *ring, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg);
int dns_ring_attach(struct dns_ring *ring);
void dns_ring_detach_appctx(struct dns_ring *ring, struct appctx *appctx, size_t ofs);

#endif /* _HAPROXY_DNS_RING_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
