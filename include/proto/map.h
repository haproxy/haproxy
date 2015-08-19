/*
 * include/proto/map.h
 * This file provides structures and types for pattern matching.
 *
 * Copyright (C) 2000-2013 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_MAP_H
#define _PROTO_MAP_H

#include <types/map.h>

/* maps output sample parser */
int map_parse_ip(const char *text, struct sample_data *data);
int map_parse_ip6(const char *text, struct sample_data *data);
int map_parse_str(const char *text, struct sample_data *data);
int map_parse_int(const char *text, struct sample_data *data);

struct map_reference *map_get_reference(const char *reference);

int sample_load_map(struct arg *arg, struct sample_conv *conv,
                    const char *file, int line, char **err);

#endif /* _PROTO_PATTERN_H */
