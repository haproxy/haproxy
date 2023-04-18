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

extern struct protocol proto_quic4;
extern struct protocol proto_quic6;

struct quic_cid_tree {
	struct eb_root root;
	__decl_thread(HA_RWLOCK_T lock);
};

extern struct quic_dghdlr *quic_dghdlrs;
extern struct quic_cid_tree *quic_cid_trees;

#endif /* _HAPROXY_PROTO_QUIC_H  */
