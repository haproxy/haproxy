/*
 * include/haproxy/map-t.h
 * This file provides structures and types for MAPs.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_MAP_T_H
#define _HAPROXY_MAP_T_H

#include <haproxy/pattern-t.h>
#include <haproxy/sample-t.h>

struct map_descriptor {
	struct sample_conv *conv;      /* original converter descriptor */
	struct pattern_head pat;       /* the pattern matching associated to the map */
	int do_free;                   /* set if <pat> is the original pat and must be freed */
};

#endif /* _HAPROXY_MAP_T_H */
