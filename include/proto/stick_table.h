/*
 * include/proto/stick_table.h
 * Functions for stick tables management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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
int stktable_store(struct stktable *t, struct stksess *ts, int sid);
struct stksess *stktable_lookup(struct stktable *t, struct stktable_key *key);
struct stktable_key *stktable_fetch_key(struct proxy *px, struct session *l4,
					void *l7, int dir, struct pattern_expr *expr,
					unsigned long table_type);
int stktable_compatible_pattern(struct pattern_expr *expr, unsigned long table_type);


#endif /* _PROTO_STICK_TABLE_H */
