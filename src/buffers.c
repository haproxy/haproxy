/*
 * Buffer management functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <proto/buffers.h>

void **pool_buffer   = NULL;

/* writes <len> bytes from message <msg> to buffer <buf>. Returns 0 in case of
 * success, or the number of bytes available otherwise.
 * FIXME-20060521: handle unaligned data.
 */
int buffer_write(struct buffer *buf, const char *msg, int len)
{
	int max;

	max = buffer_realign(buf);

	if (len > max)
		return max;

	memcpy(buf->r, msg, len);
	buf->l += len;
	buf->r += len;
	buf->total += len;
	if (buf->r == buf->data + BUFSIZE)
		buf->r = buf->data;
	return 0;
}

/* writes the chunk <chunk> to buffer <buf>. Returns 0 in case of
 * success, or the number of bytes available otherwise. If the chunk
 * has been written, its size is automatically reset to zero.
 */
int buffer_write_chunk(struct buffer *buf, struct chunk *chunk)
{
	int max;

	if (chunk->len == 0)
		return 0;

	max = buffer_realign(buf);

	if (chunk->len > max)
		return max;

	memcpy(buf->r, chunk->str, chunk->len);
	buf->l += chunk->len;
	buf->r += chunk->len;
	buf->total += chunk->len;
	if (buf->r == buf->data + BUFSIZE)
		buf->r = buf->data;
	chunk->len = 0;
	return 0;
}

/*
 * this function writes the string <str> at position <pos> which must be in buffer <b>,
 * and moves <end> just after the end of <str>.
 * <b>'s parameters (l, r, w, h, lr) are recomputed to be valid after the shift.
 * the shift value (positive or negative) is returned.
 * If there's no space left, the move is not done.
 *
 */
int buffer_replace(struct buffer *b, char *pos, char *end, char *str)
{
	int delta;
	int len;

	len = strlen(str);
	delta = len - (end - pos);

	if (delta + b->r >= b->data + BUFSIZE)
		return 0;  /* no space left */

	/* first, protect the end of the buffer */
	memmove(end + delta, end, b->data + b->l - end);

	/* now, copy str over pos */
	memcpy(pos, str,len);

	/* we only move data after the displaced zone */
	if (b->r  > pos) b->r  += delta;
	if (b->w  > pos) b->w  += delta;
	if (b->lr > pos) b->lr += delta;
	b->l += delta;

	return delta;
}

/*
 * same except that the string length is given, which allows str to be NULL if
 * len is 0.
 */
int buffer_replace2(struct buffer *b, char *pos, char *end, char *str, int len)
{
	int delta;

	delta = len - (end - pos);

	if (delta + b->r >= b->data + BUFSIZE)
		return 0;  /* no space left */

	if (b->data + b->l < end) {
		/* The data has been stolen, we could have crashed.
		 * Maybe we should abort() ? */
		return 0;
	}

	/* first, protect the end of the buffer */
	memmove(end + delta, end, b->data + b->l - end);

	/* now, copy str over pos */
	if (len)
		memcpy(pos, str, len);

	/* we only move data after the displaced zone */
	if (b->r  > pos) b->r  += delta;
	if (b->w  > pos) b->w  += delta;
	if (b->lr > pos) b->lr += delta;
	b->l += delta;

	return delta;
}


/*
 * Does an snprintf() at the end of chunk <chk>, respecting the limit of
 * at most <size> chars. If the size is over, nothing is added. Returns
 * the new chunk size.
 */
int chunk_printf(struct chunk *chk, int size, const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	chk->len += vsnprintf(chk->str + chk->len, size - chk->len, fmt, argp);
	va_end(argp);
	return chk->len;
}

/*
 * Dumps part or all of a buffer.
 */
void buffer_dump(FILE *o, struct buffer *b, int from, int to)
{
	fprintf(o, "Dumping buffer %p\n", b);
	fprintf(o, "  data=%p l=%d r=%p w=%p lr=%p\n",
		b->data, b->l, b->r, b->w, b->lr);

	if (!to || to > b->l)
		to = b->l;

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
