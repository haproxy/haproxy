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

#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/buffer.h>

#include <types/global.h>

/* This function realigns input data in a possibly wrapping buffer so that it
 * becomes contiguous and starts at the beginning of the buffer area. The
 * function may only be used when the buffer's output is empty.
 */
void buffer_slow_realign(struct buffer *buf)
{
	/* two possible cases :
	 *   - the buffer is in one contiguous block, we move it in-place
	 *   - the buffer is in two blocks, we move it via the swap_buffer
	 */
	if (buf->i) {
		int block1 = buf->i;
		int block2 = 0;
		if (buf->p + buf->i > buf->data + buf->size) {
			/* non-contiguous block */
			block1 = buf->data + buf->size - buf->p;
			block2 = buf->p + buf->i - (buf->data + buf->size);
		}
		if (block2)
			memcpy(swap_buffer, buf->data, block2);
		memmove(buf->data, buf->p, block1);
		if (block2)
			memcpy(buf->data + block1, swap_buffer, block2);
	}

	buf->p = buf->data;
}


/* Realigns a possibly non-contiguous buffer by bouncing bytes from source to
 * destination. It does not use any intermediate buffer and does the move in
 * place, though it will be slower than a simple memmove() on contiguous data,
 * so it's desirable to use it only on non-contiguous buffers. No pointers are
 * changed, the caller is responsible for that.
 */
void buffer_bounce_realign(struct buffer *buf)
{
	int advance, to_move;
	char *from, *to;

	from = bo_ptr(buf);
	advance = buf->data + buf->size - from;
	if (!advance)
		return;

	to_move = buffer_len(buf);
	while (to_move) {
		char last, save;

		last = *from;
		to = from + advance;
		if (to >= buf->data + buf->size)
			to -= buf->size;

		while (1) {
			save = *to;
			*to  = last;
			last = save;
			to_move--;
			if (!to_move)
				break;

			/* check if we went back home after rotating a number of bytes */
			if (to == from)
				break;

			/* if we ended up in the empty area, let's walk to next place. The
			 * empty area is either between buf->r and from or before from or
			 * after buf->r.
			 */
			if (from > bi_end(buf)) {
				if (to >= bi_end(buf) && to < from)
					break;
			} else if (from < bi_end(buf)) {
				if (to < from || to >= bi_end(buf))
					break;
			}

			/* we have overwritten a byte of the original set, let's move it */
			to += advance;
			if (to >= buf->data + buf->size)
				to -= buf->size;
		}

		from++;
		if (from >= buf->data + buf->size)
			from -= buf->size;
	}
}


/*
 * Dumps part or all of a buffer.
 */
void buffer_dump(FILE *o, struct buffer *b, int from, int to)
{
	fprintf(o, "Dumping buffer %p\n", b);
	fprintf(o, "  data=%p o=%d i=%d p=%p\n",
		b->data, b->o, b->i, b->p);

	if (!to || to > buffer_len(b))
		to = buffer_len(b);

	fprintf(o, "Dumping contents from byte %d to byte %d\n", from, to);
	for (; from < to; from++) {
		if ((from & 15) == 0)
			fprintf(o, "  %04x: ", from);
		fprintf(o, "%02x ", b->data[from]);
		if ((from & 15) == 7)
			fprintf(o, "- ");
		else if (((from & 15) == 15) && (from != to-1))
			fprintf(o, "\n");
	}
	fprintf(o, "\n--\n");
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
