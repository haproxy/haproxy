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

/*
 * quick and dirty AppSession hash table, using sessid as key
 */

#include <common/sessionhash.h>
#include <string.h>
#ifdef DEBUG_HASH
#include <stdio.h>
#endif

/*
 * This is a bernstein hash derivate
 * returns unsigned int between 0 and (TABLESIZE - 1) inclusive
 */
unsigned int appsession_hash_f(char *ptr)
{
	unsigned int h = 5381;

	while (*ptr) {
		h = (h << 5) + h + *ptr;
		ptr++;
	}
	return ((h >> 16) ^ h) & TABLEMASK;
}

int appsession_hash_init(struct appsession_hash *hash,
		void(*destroy)(appsess*))
{
	int i;

	hash->destroy = destroy;
	hash->table = malloc(TABLESIZE * sizeof(struct list));
	if (hash->table == NULL)
		return 0;
	for (i = 0; i < TABLESIZE; i++)
		LIST_INIT(&hash->table[i]);
	return 1;
}

void appsession_hash_insert(struct appsession_hash *hash, appsess *session)
{
	unsigned int idx;

	idx = appsession_hash_f(session->sessid);
	LIST_ADDQ(&hash->table[idx], &session->hash_list);
}

appsess *appsession_hash_lookup(struct appsession_hash *hash, char *sessid)
{
	unsigned int idx;
	appsess *item;

	idx = appsession_hash_f(sessid);

	list_for_each_entry(item, &hash->table[idx], hash_list) {
		if (strcmp(item->sessid, sessid) == 0)
			return item;
	}
	return NULL;
}

void appsession_hash_remove(struct appsession_hash *hash, appsess *session)
{
	unsigned int idx;
	appsess *item;

	idx = appsession_hash_f(session->sessid);

	/* we don't even need to call _safe because we return at once */
	list_for_each_entry(item, &hash->table[idx], hash_list) {
		if (strcmp(item->sessid, session->sessid) == 0) {
			LIST_DEL(&item->hash_list);
			hash->destroy(item);
			return;
		}
	}
}

void appsession_hash_destroy(struct appsession_hash *hash)
{
	unsigned int i;
	appsess *item;

	if (!hash->table)
		return;

	for (i = 0; i < TABLESIZE; i++) {
		while (!LIST_ISEMPTY(&hash->table[i])) {
			item = LIST_ELEM(hash->table[i].n, appsess *,
					hash_list);
			hash->destroy(item);
			LIST_DEL(&item->hash_list);
		}
	}
	free(hash->table);
	hash->table = NULL;
	hash->destroy = NULL;
}

#if defined(DEBUG_HASH)
void appsession_hash_dump(struct appsession_hash *hash)
{
	unsigned int idx;
	appsess *item;

	printf("Dumping hashtable 0x%p\n", hash);
	for (idx = 0; idx < TABLESIZE; idx++) {
		/* we don't even need to call _safe because we return at once */
		list_for_each_entry(item, &hash->table[idx], hash_list) {
			printf("\ttable[%d]:\t%s\t-> %s request_count %lu\n", idx, item->sessid,
					item->serverid, item->request_count);
		}
	}
	printf(".\n");
}
#endif
