/*
 * include/haproxy/lb_map-t.h
 * Types for map-based load-balancing (RR and HASH)
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

#ifndef _HAPROXY_LB_MAP_T_H
#define _HAPROXY_LB_MAP_T_H

#include <haproxy/api-t.h>
#include <haproxy/server-t.h>

struct lb_map {
	struct server **srv;	/* the server map used to apply weights */
	int rr_idx;		/* next server to be elected in round robin mode */
};

#endif /* _HAPROXY_LB_MAP_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
