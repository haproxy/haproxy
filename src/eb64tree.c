/*
 * Elastic Binary Trees - exported functions for operations on 64bit nodes.
 * (C) 2002-2007 - Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* Consult eb64tree.h for more details about those functions */

#include <common/eb64tree.h>

REGPRM2 struct eb64_node *eb64_insert(struct eb_root *root, struct eb64_node *new)
{
	return __eb64_insert(root, new);
}

REGPRM2 struct eb64_node *eb64i_insert(struct eb_root *root, struct eb64_node *new)
{
	return __eb64i_insert(root, new);
}

REGPRM2 struct eb64_node *eb64_lookup(struct eb_root *root, u64 x)
{
	return __eb64_lookup(root, x);
}

REGPRM2 struct eb64_node *eb64i_lookup(struct eb_root *root, s64 x)
{
	return __eb64i_lookup(root, x);
}
