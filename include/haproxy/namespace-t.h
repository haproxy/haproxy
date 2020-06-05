/*
 * include/haproxy/namespace-t.h
 * Linux network namespaces types definitions
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

#ifndef _HAPROXY_NAMESPACE_T_H
#define _HAPROXY_NAMESPACE_T_H

#include <import/ebpttree.h>
#include <haproxy/api-t.h>

/* the struct is just empty if namespaces are not supported */
struct netns_entry
{
#ifdef USE_NS
	struct ebpt_node node;
	size_t name_len;
	int fd;
#endif
};

#endif /* _HAPROXY_NAMESPACE_T_H */
