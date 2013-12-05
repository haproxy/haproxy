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

#include <types/acl.h>

/* These structs contains a string representation of the map. These struct is
 * sorted by file. Permit to hot-add and hot-remove entries.
 *
 * "maps" is the list head. This list cotains all the mao file name identifier.
 */
extern struct list maps;

struct map_reference {
	struct list list;    /* used for listing */
	char *reference;     /* contain the unique identifier used as map identifier.
	                        in many cases this identifier is the filename that contain
	                        the patterns */
	struct list entries; /* the list of all the entries of the map. This
	                        is a list of "struct map_entry" */
	struct list maps;    /* the list of all maps associated with the file
	                        name identifier. This is a list of struct map_descriptor */
};

struct map_entry {
	struct list list; /* used for listing */
	int line;         /* The original line into the file. It is used for log reference.
	                     If the line is '> 0', this entry is from the original load,
	                     If the line is '< 0', this entry is modify by dynamux process (CLI) */
	char *key;        /* The string containing the key before conversion
	                     and indexation */
	char *value;      /* The string containing the value */
};

struct sample_storage;
struct map_descriptor {
	struct list list;              /* used for listing */
	struct map_reference *ref;     /* the reference used for unindexed entries */
	struct sample_conv *conv;      /* original converter descriptor */
	int (*parse)(const char *text, /* The function that can parse the output value */
	             struct sample_storage *smp);
	struct pattern_expr *pat;      /* the pattern matching associated to the map */
	int do_free;                   /* set if <pat> is the orignal pat and must be freed */
	char *default_value;           /* a copy of default value. This copy is
	                                  useful if the type is str */
	struct sample_storage *def;    /* contain the default value */
};

#endif /* _TYPES_MAP_H */
