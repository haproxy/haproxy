#ifndef SESSION_HASH_H
#define SESSION_HASH_H

/*
 * HashTable functions.
 *
 * Copyright 2007 Arnaud Cornet
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2.1 as published by the Free Software Foundation.
 *
 */

#include <common/appsession.h>

#ifndef TABLESHIFT
#define TABLESHIFT 11
#endif
#define TABLESIZE (1UL << TABLESHIFT)
#define TABLEMASK (TABLESIZE - 1)

/*
 * quick and dirty AppSession hash table, using sessid as key
 */

struct appsession_hash
{
	struct list *table;
	void (*destroy)(appsess *);
};

unsigned int appsession_hash_f(char *);
int appsession_hash_init(struct appsession_hash *hash,
		void(*destroy)(appsess*));
void appsession_hash_insert(struct appsession_hash *hash,
		struct appsessions *session);
struct appsessions *appsession_hash_lookup(struct appsession_hash *hash,
		char *key);
void appsession_hash_remove(struct appsession_hash *hash,
		struct appsessions *session);

void appsession_hash_destroy(struct appsession_hash *hash);
#if defined(DEBUG_HASH)
void appsession_hash_dump(struct appsession_hash *hash);
#endif

/*
 * Iterates <item> through a hashtable of items of type "typeof(*item)"
 * A pointer to the appsession_hash is passed in <hash>. The hash table
 * internaly uses <list_head> member of the struct. A temporary variable <back>
 * of same type as <item> is needed so that <item> may safely be deleted if
 * needed.  <idx> is a variable containing <item>'s current bucket index in the
 * hash table.
 * Example: as_hash_for_each_entry_safe(idx, item, tmp, &hash, hash_list)
 * { ... }
 */
#define as_hash_for_each_entry_safe(idx, item, back, hash, member) \
	 for (idx = 0; idx < TABLESIZE; idx++)                          \
		list_for_each_entry_safe(item, back, &((hash)->table[idx]), member)

#endif /* SESSION_HASH_H */
