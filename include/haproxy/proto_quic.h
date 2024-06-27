/*
 * AF_INET/AF_INET6 QUIC protocol layer definitions.
 *
 * Copyright 2020 Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_PROTO_QUIC_H
#define _HAPROXY_PROTO_QUIC_H

#include <import/ebtree.h>
#include <haproxy/api-t.h>
#include <haproxy/thread-t.h>

extern struct protocol proto_quic4;
extern struct protocol proto_quic6;

extern struct quic_dghdlr *quic_dghdlrs;

#endif /* _HAPROXY_PROTO_QUIC_H  */
