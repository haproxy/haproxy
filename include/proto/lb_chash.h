/*
 * include/proto/lb_chash.h
 * Function declarations for Consistent Hash LB algorithm.
 *
 * Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_LB_CHASH_H
#define _PROTO_LB_CHASH_H

#include <common/config.h>
#include <types/proxy.h>
#include <types/server.h>

void chash_init_server_tree(struct proxy *p);
struct server *chash_get_next_server(struct proxy *p, struct server *srvtoavoid);
struct server *chash_get_server_hash(struct proxy *p, unsigned int hash, const struct server *avoid);

#endif /* _PROTO_LB_CHASH_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
