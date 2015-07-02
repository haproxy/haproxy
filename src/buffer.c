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

struct pool_head *pool2_buffer;

/* These buffers are used to always have a valid pointer to an empty buffer in
 * channels. The first buffer is set once a buffer is empty. The second one is
 * set when a buffer is desired but no more are available. It helps knowing
 * what channel wants a buffer. They can reliably be exchanged, the split
 * between the two is only an optimization.
 */
struct buffer buf_empty  = { .p = buf_empty.data };
struct buffer buf_wanted = { .p = buf_wanted.data };

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_buffer()
{
	void *buffer;

	pool2_buffer = create_pool("buffer", sizeof (struct buffer) + global.tune.bufsize, MEM_F_SHARED);
	if (!pool2_buffer)
		return 0;

	/* The reserved buffer is what we leave behind us. Thus we always need
	 * at least one extra buffer in minavail otherwise we'll end up waking
	 * up tasks with no memory available, causing a lot of useless wakeups.
	 * That means that we always want to have at least 3 buffers available
	 * (2 for current session, one for next session that might be needed to
	 * release a server connection).
	 */
	pool2_buffer->minavail = MAX(global.tune.reserved_bufs, 3);
	if (global.tune.buf_limit)
		pool2_buffer->limit = global.tune.buf_limit;

	buffer = pool_refill_alloc(pool2_buffer, pool2_buffer->minavail - 1);
	if (!buffer)
		return 0;

	pool_free2(pool2_buffer, buffer);
	return 1;
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


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
