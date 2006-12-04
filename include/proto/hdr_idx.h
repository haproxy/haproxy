/*
  include/proto/hdr_idx.h
  This file defines function prototypes for fast header indexation.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_HDR_IDX_H
#define _PROTO_HDR_IDX_H

#include <common/config.h>
#include <types/hdr_idx.h>

/*
 * Initialize the list pointers.
 * list->size must already be set. If list->size is set and list->v is
 * non-null, list->v is also initialized..
 */
static inline void hdr_idx_init(struct hdr_idx *list)
{
	if (list->size && list->v) {
		register struct hdr_idx_elem e = { .len=0, .cr=0, .next=0};
		list->v[0] = e;
	}
	list->tail = 0;
	list->used = list->last = 1;
}

/*
 * Add a header entry to <list> after element <after>. <after> is ignored when
 * the list is empty or full. Common usage is to set <after> to list->tail.
 *
 * Returns the position of the new entry in the list (from 1 to size-1), or 0
 * if the array is already full. An effort is made to fill the array linearly,
 * but once the last entry has been used, we have to search for unused blocks,
 * which takes much more time. For this reason, it's important to size is
 * appropriately.
 */
int hdr_idx_add(int len, int cr, struct hdr_idx *list, int after);

#endif /* _PROTO_HDR_IDX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
