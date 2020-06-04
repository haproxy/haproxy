/*
 * include/haproxy/lb_fwlc-t.h
 * Types for Fast Weighted Least Connection load balancing algorithm.
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

#ifndef _HAPROXY_LB_FWLC_T_H
#define _HAPROXY_LB_FWLC_T_H

#include <import/ebtree.h>

struct lb_fwlc {
	struct eb_root act;	/* weighted least conns on the active servers */
	struct eb_root bck;	/* weighted least conns on the backup servers */
};

#endif /* _HAPROXY_LB_FWLC_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
