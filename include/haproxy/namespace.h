/*
 * include/haproxy/namespace.h
 * Linux network namespaces management
 *
 * Copyright (C) 2014 Tamas Kovacs, Sarkozi Laszlo, Krisztian Kovacs
 * Copyright (C) 2015-2020 Willy Tarreau
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

#ifndef _HAPROXY_NAMESPACE_H
#define _HAPROXY_NAMESPACE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <import/ebistree.h>
#include <haproxy/namespace-t.h>

#ifdef USE_NS

int my_socketat(const struct netns_entry *ns, int domain, int type, int protocol);
struct netns_entry* netns_store_insert(const char *ns_name);
const struct netns_entry* netns_store_lookup(const char *ns_name, size_t ns_name_len);
int netns_init(void);

#else /* no namespace support */

static inline int my_socketat(const struct netns_entry *ns, int domain, int type, int protocol)
{
	return socket(domain, type, protocol);
}

#endif /* USE_NS */

#endif /* _HAPROXY_NAMESPACE_H */
