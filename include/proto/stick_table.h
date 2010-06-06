/*
 * include/proto/stick_table.h
 * Functions for stick tables management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2010 Willy Tarreau <w@1wt.eu>
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

#ifndef _PROTO_STICK_TABLE_H
#define _PROTO_STICK_TABLE_H

#include <types/stick_table.h>

struct stksess *stksess_new(struct stktable *t, struct stktable_key *key);
void stksess_setkey(struct stktable *t, struct stksess *ts, struct stktable_key *key);
void stksess_free(struct stktable *t, struct stksess *ts);

int stktable_init(struct stktable *t);
int stktable_parse_type(char **args, int *idx, unsigned long *type, size_t *key_size);
struct stksess *stktable_store(struct stktable *t, struct stksess *ts);
struct stksess *stktable_lookup(struct stktable *t, struct stksess *ts);
struct stksess *stktable_lookup_key(struct stktable *t, struct stktable_key *key);
struct stktable_key *stktable_fetch_key(struct proxy *px, struct session *l4,
					void *l7, int dir, struct pattern_expr *expr,
					unsigned long table_type);
int stktable_compatible_pattern(struct pattern_expr *expr, unsigned long table_type);
int stktable_get_data_type(char *name);

/* reserve some space for data type <type>. Return non-0 if OK, or 0 if already
 * allocated (or impossible type).
 */
static inline int stktable_alloc_data_type(struct stktable *t, int type)
{
	if (type >= STKTABLE_DATA_TYPES)
		return 0;

	if (t->data_ofs[type])
		/* already allocated */
		return 0;

	t->data_size      += stktable_data_types[type].data_length;
	t->data_ofs[type]  = -t->data_size;
	return 1;
}

#endif /* _PROTO_STICK_TABLE_H */
