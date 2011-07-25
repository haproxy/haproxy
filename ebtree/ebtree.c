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

#include "ebtree.h"

void eb_delete(struct eb_node *node)
{
	__eb_delete(node);
}

/* used by insertion primitives */
REGPRM1 struct eb_node *eb_insert_dup(struct eb_node *sub, struct eb_node *new)
{
	return __eb_insert_dup(sub, new);
}
