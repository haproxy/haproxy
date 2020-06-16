/*
 * Elastic Binary Trees - exported generic functions
 * Version 6.0.6
 * (C) 2002-2011 - Willy Tarreau <w@1wt.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <import/ebtree.h>

void eb_delete(struct eb_node *node)
{
	__eb_delete(node);
}

/* used by insertion primitives */
struct eb_node *eb_insert_dup(struct eb_node *sub, struct eb_node *new)
{
	return __eb_insert_dup(sub, new);
}

/* compares memory blocks m1 and m2 for up to <len> bytes. Immediately stops at
 * the first non-matching byte. It returns 0 on full match, non-zero otherwise.
 * One byte will always be checked so this must not be called with len==0. It
 * takes 2+5cy/B on x86_64 and is ~29 bytes long.
 */
int eb_memcmp(const void *m1, const void *m2, size_t len)
{
	const char *p1 = (const char *)m1 + len;
	const char *p2 = (const char *)m2 + len;
	ssize_t ofs = -len;
	char diff;

	do {
		diff = p1[ofs] - p2[ofs];
	} while (!diff && ++ofs);
	return diff;
}
