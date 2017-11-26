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

/* These buffers are used to always have a valid pointer to an empty buffer in
 * channels. The first buffer is set once a buffer is empty. The second one is
 * set when a buffer is desired but no more are available. It helps knowing
 * what channel wants a buffer. They can reliably be exchanged, the split
 * between the two is only an optimization.
 */
struct buffer buf_empty  = { .p = buf_empty.data };
struct buffer buf_wanted = { .p = buf_wanted.data };

/* list of objects waiting for at least one buffer */
struct list buffer_wq = LIST_HEAD_INIT(buffer_wq);
__decl_hathreads(HA_SPINLOCK_T __attribute__((aligned(64))) buffer_wq_lock);

/* this buffer is always the same size as standard buffers and is used for
 * swapping data inside a buffer.
 */
static THREAD_LOCAL char *swap_buffer = NULL;

static int init_buffer_per_thread()
{
	swap_buffer = calloc(1, global.tune.bufsize);
	if (swap_buffer == NULL)
		return 0;
	return 1;
}

static void deinit_buffer_per_thread()
{
	free(swap_buffer); swap_buffer = NULL;
}

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_buffer()
{
	void *buffer;

	pool_head_buffer = create_pool("buffer", sizeof (struct buffer) + global.tune.bufsize, MEM_F_SHARED|MEM_F_EXACT);
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

	HA_SPIN_INIT(&buffer_wq_lock);

	buffer = pool_refill_alloc(pool_head_buffer, pool_head_buffer->minavail - 1);
	if (!buffer)
		return 0;

	pool_free(pool_head_buffer, buffer);

	hap_register_per_thread_init(init_buffer_per_thread);
	hap_register_per_thread_deinit(deinit_buffer_per_thread);
	return 1;
}

void deinit_buffer()
{
	pool_destroy(pool_head_buffer);
}

/* This function writes the string <str> at position <pos> which must be in
 * buffer <b>, and moves <end> just after the end of <str>. <b>'s parameters
 * <l> and <r> are updated to be valid after the shift. The shift value
 * (positive or negative) is returned. If there's no space left, the move is
 * not done. The function does not adjust ->o because it does not make sense to
 * use it on data scheduled to be sent. For the same reason, it does not make
 * sense to call this function on unparsed data, so <orig> is not updated. The
 * string length is taken from parameter <len>. If <len> is null, the <str>
 * pointer is allowed to be null.
 */
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len)
{
	int delta;

	delta = len - (end - pos);

	if (bi_end(b) + delta > b->data + b->size)
		return 0;  /* no space left */

	if (buffer_not_empty(b) &&
	    bi_end(b) + delta > bo_ptr(b) &&
	    bo_ptr(b) >= bi_end(b))
		return 0;  /* no space left before wrapping data */

	/* first, protect the end of the buffer */
	memmove(end + delta, end, bi_end(b) - end);

	/* now, copy str over pos */
	if (len)
		memcpy(pos, str, len);

	b->i += delta;

	if (buffer_empty(b))
		b->p = b->data;

	return delta;
}

/*
 * Inserts <str> followed by "\r\n" at position <pos> in buffer <b>. The <len>
 * argument informs about the length of string <str> so that we don't have to
 * measure it. It does not include the "\r\n". If <str> is NULL, then the buffer
 * is only opened for len+2 bytes but nothing is copied in. It may be useful in
 * some circumstances. The send limit is *not* adjusted. Same comments as above
 * for the valid use cases.
 *
 * The number of bytes added is returned on success. 0 is returned on failure.
 */
int buffer_insert_line2(struct buffer *b, char *pos, const char *str, int len)
{
	int delta;

	delta = len + 2;

	if (bi_end(b) + delta >= b->data + b->size)
		return 0;  /* no space left */

	if (buffer_not_empty(b) &&
	    bi_end(b) + delta > bo_ptr(b) &&
	    bo_ptr(b) >= bi_end(b))
		return 0;  /* no space left before wrapping data */

	/* first, protect the end of the buffer */
	memmove(pos + delta, pos, bi_end(b) - pos);

	/* now, copy str over pos */
	if (len && str) {
		memcpy(pos, str, len);
		pos[len] = '\r';
		pos[len + 1] = '\n';
	}

	b->i += delta;
	return delta;
}

/* This function realigns a possibly wrapping buffer so that the input part is
 * contiguous and starts at the beginning of the buffer and the output part
 * ends at the end of the buffer. This provides the best conditions since it
 * allows the largest inputs to be processed at once and ensures that once the
 * output data leaves, the whole buffer is available at once.
 */
void buffer_slow_realign(struct buffer *buf)
{
	int block1 = buf->o;
	int block2 = 0;

	/* process output data in two steps to cover wrapping */
	if (block1 > buf->p - buf->data) {
		block2 = buf->p - buf->data;
		block1 -= block2;
	}
	memcpy(swap_buffer + buf->size - buf->o, bo_ptr(buf), block1);
	memcpy(swap_buffer + buf->size - block2, buf->data, block2);

	/* process input data in two steps to cover wrapping */
	block1 = buf->i;
	block2 = 0;

	if (block1 > buf->data + buf->size - buf->p) {
		block1 = buf->data + buf->size - buf->p;
		block2 = buf->i - block1;
	}
	memcpy(swap_buffer, bi_ptr(buf), block1);
	memcpy(swap_buffer + block1, buf->data, block2);

	/* reinject changes into the buffer */
	memcpy(buf->data, swap_buffer, buf->i);
	memcpy(buf->data + buf->size - buf->o, swap_buffer + buf->size - buf->o, buf->o);

	buf->p = buf->data;
}

/*
 * Dumps part or all of a buffer.
 */
void buffer_dump(FILE *o, struct buffer *b, int from, int to)
{
	fprintf(o, "Dumping buffer %p\n", b);
	fprintf(o, "            data=%p o=%d i=%d p=%p\n"
                   "            relative:   p=0x%04x\n",
		b->data, b->o, b->i, b->p, (unsigned int)(b->p - b->data));

	fprintf(o, "Dumping contents from byte %d to byte %d\n", from, to);
	fprintf(o, "         0  1  2  3  4  5  6  7    8  9  a  b  c  d  e  f\n");
	/* dump hexa */
	while (from < to) {
		int i;

		fprintf(o, "  %04x: ", from);
		for (i = 0; ((from + i) < to) && (i < 16) ; i++) {
			fprintf(o, "%02x ", (unsigned char)b->data[from + i]);
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
			fprintf(o, "%c", isprint((int)b->data[from + i]) ? b->data[from + i] : '.') ;
			if ((((from + i) & 15) == 15) && ((from + i) != to-1))
				fprintf(o, "\n");
		}
		from += i;
	}
	fprintf(o, "\n--\n");
	fflush(o);
}

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
