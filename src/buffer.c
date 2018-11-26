/*
 * Buffer management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/buffer.h>
#include <common/memory.h>

#include <types/global.h>

struct pool_head *pool_head_buffer;

/* list of objects waiting for at least one buffer */
struct list buffer_wq = LIST_HEAD_INIT(buffer_wq);
__decl_aligned_spinlock(buffer_wq_lock);

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_buffer()
{
	void *buffer;

	pool_head_buffer = create_pool("buffer", global.tune.bufsize, MEM_F_SHARED|MEM_F_EXACT);
	if (!pool_head_buffer)
		return 0;

	/* The reserved buffer is what we leave behind us. Thus we always need
	 * at least one extra buffer in minavail otherwise we'll end up waking
	 * up tasks with no memory available, causing a lot of useless wakeups.
	 * That means that we always want to have at least 3 buffers available
	 * (2 for current session, one for next session that might be needed to
	 * release a server connection).
	 */
	pool_head_buffer->minavail = MAX(global.tune.reserved_bufs, 3);
	if (global.tune.buf_limit)
		pool_head_buffer->limit = global.tune.buf_limit;

	buffer = pool_refill_alloc(pool_head_buffer, pool_head_buffer->minavail - 1);
	if (!buffer)
		return 0;

	pool_free(pool_head_buffer, buffer);
	return 1;
}

/*
 * Dumps part or all of a buffer.
 */
void buffer_dump(FILE *o, struct buffer *b, int from, int to)
{
	fprintf(o, "Dumping buffer %p\n", b);
	fprintf(o, "            orig=%p size=%u head=%u tail=%u data=%u\n",
		b_orig(b), (unsigned int)b_size(b), (unsigned int)b_head_ofs(b), (unsigned int)b_tail_ofs(b), (unsigned int)b_data(b));

	fprintf(o, "Dumping contents from byte %d to byte %d\n", from, to);
	fprintf(o, "         0  1  2  3  4  5  6  7    8  9  a  b  c  d  e  f\n");
	/* dump hexa */
	while (from < to) {
		int i;

		fprintf(o, "  %04x: ", from);
		for (i = 0; ((from + i) < to) && (i < 16) ; i++) {
			fprintf(o, "%02x ", (unsigned char)b_orig(b)[from + i]);
			if (((from + i)  & 15) == 7)
				fprintf(o, "- ");
		}
		if (to - from < 16) {
			int j = 0;

			for (j = 0; j <  from + 16 - to; j++)
				fprintf(o, "   ");
			if (j > 8)
				fprintf(o, "  ");
		}
		fprintf(o, "  ");
		for (i = 0; (from + i < to) && (i < 16) ; i++) {
			fprintf(o, "%c", isprint((int)b_orig(b)[from + i]) ? b_orig(b)[from + i] : '.') ;
			if ((((from + i) & 15) == 15) && ((from + i) != to-1))
				fprintf(o, "\n");
		}
		from += i;
	}
	fprintf(o, "\n--\n");
	fflush(o);
}

/* see offer_buffer() for details */
void __offer_buffer(void *from, unsigned int threshold)
{
	struct buffer_wait *wait, *bak;
	int avail;

	/* For now, we consider that all objects need 1 buffer, so we can stop
	 * waking up them once we have enough of them to eat all the available
	 * buffers. Note that we don't really know if they are streams or just
	 * other tasks, but that's a rough estimate. Similarly, for each cached
	 * event we'll need 1 buffer. If no buffer is currently used, always
	 * wake up the number of tasks we can offer a buffer based on what is
	 * allocated, and in any case at least one task per two reserved
	 * buffers.
	 */
	avail = pool_head_buffer->allocated - pool_head_buffer->used - global.tune.reserved_bufs / 2;

	list_for_each_entry_safe(wait, bak, &buffer_wq, list) {
		if (avail <= threshold)
			break;

		if (wait->target == from || !wait->wakeup_cb(wait->target))
			continue;

		LIST_DEL(&wait->list);
		LIST_INIT(&wait->list);

		avail--;
	}
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
