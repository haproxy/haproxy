/*
 * Elastic Binary Trees - exported functions for operations on 32bit nodes.
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

/* Consult eb32tree.h for more details about those functions */

#include <common/eb32tree.h>

REGPRM2 struct eb32_node *eb32_insert(struct eb_root *root, struct eb32_node *new)
{
	return __eb32_insert(root, new);
}

REGPRM2 struct eb32_node *eb32i_insert(struct eb_root *root, struct eb32_node *new)
{
	return __eb32i_insert(root, new);
}

REGPRM2 struct eb32_node *eb32_lookup(struct eb_root *root, u32 x)
{
	return __eb32_lookup(root, x);
}

REGPRM2 struct eb32_node *eb32i_lookup(struct eb_root *root, s32 x)
{
	return __eb32i_lookup(root, x);
}
