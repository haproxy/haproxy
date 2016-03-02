/*
 * include/types/map.h
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

#ifndef _TYPES_MAP_H
#define _TYPES_MAP_H

#include <types/pattern.h>
#include <types/sample.h>

struct map_descriptor {
	struct sample_conv *conv;      /* original converter descriptor */
	struct pattern_head pat;       /* the pattern matching associated to the map */
	int do_free;                   /* set if <pat> is the orignal pat and must be freed */
};

#endif /* _TYPES_MAP_H */
