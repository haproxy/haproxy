/*
 * Elastic Binary Trees - exported functions for Multi-Byte data nodes.
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

/* Consult ebmbtree.h for more details about those functions */

#include "ebmbtree.h"

/* Find the first occurrence of a key of <len> bytes in the tree <root>.
 * If none can be found, return NULL.
 */
REGPRM3 struct ebmb_node *
ebmb_lookup(struct eb_root *root, const void *x, unsigned int len)
{
	return __ebmb_lookup(root, x, len);
}

/* Insert ebmb_node <new> into subtree starting at node root <root>.
 * Only new->key needs be set with the key. The ebmb_node is returned.
 * If root->b[EB_RGHT]==1, the tree may only contain unique keys. The
 * len is specified in bytes.
 */
REGPRM3 struct ebmb_node *
ebmb_insert(struct eb_root *root, struct ebmb_node *new, unsigned int len)
{
	return __ebmb_insert(root, new, len);
}

/* Find the first occurrence of the longest prefix matching a key <x> in the
 * tree <root>. It's the caller's responsibility to ensure that key <x> is at
 * least as long as the keys in the tree. If none can be found, return NULL.
 */
REGPRM2 struct ebmb_node *
ebmb_lookup_longest(struct eb_root *root, const void *x)
{
	return __ebmb_lookup_longest(root, x);
}

/* Find the first occurrence of a prefix matching a key <x> of <pfx> BITS in the
 * tree <root>. If none can be found, return NULL.
 */
REGPRM3 struct ebmb_node *
ebmb_lookup_prefix(struct eb_root *root, const void *x, unsigned int pfx)
{
	return __ebmb_lookup_prefix(root, x, pfx);
}

/* Insert ebmb_node <new> into a prefix subtree starting at node root <root>.
 * Only new->key and new->pfx need be set with the key and its prefix length.
 * Note that bits between <pfx> and <len> are theorically ignored and should be
 * zero, as it is not certain yet that they will always be ignored everywhere
 * (eg in bit compare functions).
 * The ebmb_node is returned.
 * If root->b[EB_RGHT]==1, the tree may only contain unique keys. The
 * len is specified in bytes.
 */
REGPRM3 struct ebmb_node *
ebmb_insert_prefix(struct eb_root *root, struct ebmb_node *new, unsigned int len)
{
	return __ebmb_insert_prefix(root, new, len);
}
