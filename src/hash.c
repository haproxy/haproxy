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


unsigned int hash_wt6(const char *key, int len)
{
	unsigned h0 = 0xa53c965aUL;
	unsigned h1 = 0x5ca6953aUL;
	unsigned step0 = 6;
	unsigned step1 = 18;

	for (; len > 0; len--) {
		unsigned int t;

		t = ((unsigned int)*key);
		key++;

		h0 = ~(h0 ^ t);
		h1 = ~(h1 + t);

		t  = (h1 << step0) | (h1 >> (32-step0));
		h1 = (h0 << step1) | (h0 >> (32-step1));
		h0 = t;

		t = ((h0 >> 16) ^ h1) & 0xffff;
		step0 = t & 0x1F;
		step1 = t >> 11;
	}
	return h0 ^ h1;
}

unsigned int hash_djb2(const char *key, int len)
{
	unsigned int hash = 5381;

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

unsigned int hash_sdbm(const char *key, int len)
{
	unsigned int hash = 0;
	int c;

	while (len--) {
		c = *key++;
		hash = c + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}

/* Small yet efficient CRC32 calculation loosely inspired from crc32b found
 * here : http://www.hackersdelight.org/hdcodetxt/crc.c.txt
 * The magic value represents the polynom with one bit per exponent. Much
 * faster table-based versions exist but are pointless for our usage here,
 * this hash already sustains gigabit speed which is far faster than what
 * we'd ever need. Better preserve the CPU's cache instead.
 */
unsigned int hash_crc32(const char *key, int len)
{
	unsigned int hash;
	int bit;

	hash = ~0;
	while (len--) {
		hash ^= *key++;
		for (bit = 0; bit < 8; bit++)
			hash = (hash >> 1) ^ ((hash & 1) ? 0xedb88320 : 0);
	}
	return ~hash;
}
