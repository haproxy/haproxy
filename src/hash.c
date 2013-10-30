/*
 * Hash function implementation
 *
 * See mailing list thread on "Consistent hashing alternative to sdbm"
 * http://marc.info/?l=haproxy&m=138213693909219
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */


#include <common/hash.h>


unsigned long hash_djb2(const char *key, int len)
{
	unsigned long hash = 5381;

	/* the hash unrolled eight times */
	for (; len >= 8; len -= 8) {
		hash = ((hash << 5) + hash) + *key++;
		hash = ((hash << 5) + hash) + *key++;
		hash = ((hash << 5) + hash) + *key++;
		hash = ((hash << 5) + hash) + *key++;
		hash = ((hash << 5) + hash) + *key++;
		hash = ((hash << 5) + hash) + *key++;
		hash = ((hash << 5) + hash) + *key++;
		hash = ((hash << 5) + hash) + *key++;
	}
	switch (len) {
		case 7: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
		case 6: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
		case 5: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
		case 4: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
		case 3: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
		case 2: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
		case 1: hash = ((hash << 5) + hash) + *key++; break;
		default: /* case 0: */ break;
	}
	return hash;
}

unsigned long hash_sdbm(const char *key, int len)
{
	unsigned long hash = 0;
	int c;

	while (len--) {
		c = *key++;
		hash = c + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}


