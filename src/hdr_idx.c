/*
 * Header indexation functions.
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/memory.h>
#include <proto/hdr_idx.h>

struct pool_head *pool2_hdr_idx = NULL;

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
int hdr_idx_add(int len, int cr, struct hdr_idx *list, int after)
{
	register struct hdr_idx_elem e = { .len=0, .cr=0, .next=0};
	int new;

	e.len = len;
	e.cr = cr;

	if (list->used == list->size) {
		/* list is full */
		return -1;
	}


	if (list->last < list->size) {
		/* list is not completely used, we can fill linearly */
		new = list->last++;
	} else {
		/* That's the worst situation :
		 * we have to scan the list for holes. We know that we
		 * will find a place because the list is not full.
		 */
		new = 1;
		while (list->v[new].len)
			new++;
	}
	
	/* insert the new element between <after> and the next one (or end) */
	e.next = list->v[after].next;
	list->v[after].next = new;

	list->used++;
	list->v[new] = e;
	list->tail = new;
	return new;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
