/*
 * Elastic Binary Trees - exported generic functions
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

#include <common/ebtree.h>

void eb_delete(struct eb_node *node)
{
	__eb_delete(node);
}

/* used by insertion primitives */
REGPRM1 struct eb_node *eb_insert_dup(struct eb_node *sub, struct eb_node *new)
{
	return __eb_insert_dup(sub, new);
}
