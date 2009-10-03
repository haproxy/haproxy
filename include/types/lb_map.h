/*
 * include/types/lb_map.h
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

#ifndef _TYPES_LB_MAP_H
#define _TYPES_LB_MAP_H

#include <common/config.h>
#include <types/server.h>

/* values for map.state */
#define LB_MAP_RECALC  (1 << 0)

struct lb_map {
	struct server **srv;	/* the server map used to apply weights */
	int rr_idx;		/* next server to be elected in round robin mode */
	int state;		/* LB_MAP_RECALC */
};

#endif /* _TYPES_LB_MAP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
