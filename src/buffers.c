/*
 * Buffer management functions.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/memory.h>
#include <proto/buffers.h>
#include <types/global.h>

struct pool_head *pool2_buffer;


/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_buffer()
{
	pool2_buffer = create_pool("buffer", sizeof(struct buffer) + global.tune.bufsize, MEM_F_SHARED);
	return pool2_buffer != NULL;
}

/* Schedule up to <bytes> more bytes to be forwarded by the buffer without notifying
 * the task. Any pending data in the buffer is scheduled to be sent as well,
 * in the limit of the number of bytes to forward. This must be the only method
 * to use to schedule bytes to be sent. If the requested number is too large, it
 * is automatically adjusted. The number of bytes taken into account is returned.
 * Directly touching ->to_forward will cause lockups when ->o goes down to
 * zero if nobody is ready to push the remaining data.
 */
unsigned long long buffer_forward(struct buffer *buf, unsigned long long bytes)
{
	unsigned int new_forward;
	unsigned int forwarded;

	if (!bytes)
		return 0;
	if (bytes <= (unsigned long long)buf->i) {
		buf->p = b_ptr(buf, (unsigned int)bytes);
		buf->o += bytes;
		buf->i -= bytes;
		buf->flags &= ~BF_OUT_EMPTY;
		return bytes;
	}

	forwarded = buf->i;
	buf->p = bi_end(buf);
	buf->o += forwarded;
	buf->i = 0;

	if (buf->o)
		buf->flags &= ~BF_OUT_EMPTY;

	if (buf->o < buffer_max_len(buf))
		buf->flags &= ~BF_FULL;
	else
		buf->flags |= BF_FULL;

	/* Note: the case below is the only case where we may return
	 * a byte count that does not fit into a 32-bit number.
	 */
	if (likely(buf->to_forward == BUF_INFINITE_FORWARD))
		return bytes;

	if (likely(bytes == BUF_INFINITE_FORWARD)) {
		buf->to_forward = bytes;
		return bytes;
	}

	new_forward = buf->to_forward + bytes - forwarded;
	bytes = forwarded; /* at least those bytes were scheduled */

	if (new_forward <= buf->to_forward) {
		/* integer overflow detected, let's assume no more than 2G at once */
		new_forward = MID_RANGE(new_forward);
	}

	if (new_forward > buf->to_forward) {
		bytes += new_forward - buf->to_forward;
		buf->to_forward = new_forward;
	}
	return bytes;
}

/* writes <len> bytes from message <msg> to buffer <buf>. Returns -1 in case of
 * success, -2 if the message is larger than the buffer size, or the number of
 * bytes available otherwise. The send limit is automatically adjusted with the
 * amount of data written. FIXME-20060521: handle unaligned data.
 * Note: this function appends data to the buffer's output and possibly overwrites
 * any pending input data which are assumed not to exist.
 */
int buffer_write(struct buffer *buf, const char *msg, int len)
{
	int max;

	if (len == 0)
		return -1;

	if (len > buf->size) {
		/* we can't write this chunk and will never be able to, because
		 * it is larger than the buffer. This must be reported as an
		 * error. Then we return -2 so that writers that don't care can
		 * ignore it and go on, and others can check for this value.
		 */
		return -2;
	}

	max = buffer_realign(buf);

	if (len > max)
		return max;

	memcpy(buf->p, msg, len);
	buf->o += len;
	buf->p = b_ptr(buf, len);
	buf->total += len;

	buf->flags &= ~(BF_OUT_EMPTY|BF_FULL);
	if (buffer_len(buf) >= buffer_max_len(buf))
		buf->flags |= BF_FULL;

	return -1;
}

/* Tries to copy character <c> into buffer <buf> after length controls. The
 * ->o and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If there is not enough room left in the buffer, -1
 * is returned. Otherwise the number of bytes copied is returned (1). Buffer
 * flags FULL, EMPTY and READ_PARTIAL are updated if some data can be
 * transferred.
 */
int buffer_put_char(struct buffer *buf, char c)
{
	if (unlikely(buffer_input_closed(buf)))
		return -2;

	if (buf->flags & BF_FULL)
		return -1;

	*bi_end(buf) = c;

	buf->i++;
	if (buffer_len(buf) >= buffer_max_len(buf))
		buf->flags |= BF_FULL;
	buf->flags |= BF_READ_PARTIAL;

	if (buf->to_forward >= 1) {
		if (buf->to_forward != BUF_INFINITE_FORWARD)
			buf->to_forward--;
		buf->o++;
		buf->i--;
		buf->flags &= ~BF_OUT_EMPTY;
	}

	buf->total++;
	return 1;
}

/* Tries to copy block <blk> at once into buffer <buf> after length controls.
 * The ->o and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Buffer flags FULL, EMPTY and READ_PARTIAL are updated if some data can be
 * transferred.
 */
int buffer_put_block(struct buffer *buf, const char *blk, int len)
{
	int max;

	if (unlikely(buffer_input_closed(buf)))
		return -2;

	max = buffer_max_len(buf);
	if (unlikely(len > max - buffer_len(buf))) {
		/* we can't write this chunk right now because the buffer is
		 * almost full or because the block is too large. Return the
		 * available space or -2 if impossible.
		 */
		if (len > max)
			return -3;

		return -1;
	}

	if (unlikely(len == 0))
		return 0;

	/* OK so the data fits in the buffer in one or two blocks */
	max = buffer_contig_space_with_res(buf, buf->size - max);
	memcpy(bi_end(buf), blk, MIN(len, max));
	if (len > max)
		memcpy(buf->data, blk + max, len - max);

	buf->i += len;
	buf->total += len;
	if (buf->to_forward) {
		unsigned long fwd = len;
		if (buf->to_forward != BUF_INFINITE_FORWARD) {
			if (fwd > buf->to_forward)
				fwd = buf->to_forward;
			buf->to_forward -= fwd;
		}
		buf->o += fwd;
		buf->i -= fwd;
		buf->p = b_ptr(buf, fwd);
		buf->flags &= ~BF_OUT_EMPTY;
	}

	buf->flags &= ~BF_FULL;
	if (buffer_len(buf) >= buffer_max_len(buf))
		buf->flags |= BF_FULL;

	/* notify that some data was read from the SI into the buffer */
	buf->flags |= BF_READ_PARTIAL;
	return len;
}

/* Gets one text line out of a buffer from a stream interface.
 * Return values :
 *   >0 : number of bytes read. Includes the \n if present before len or end.
 *   =0 : no '\n' before end found. <str> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 * The buffer status is not changed. The caller must call buffer_skip() to
 * update it. The '\n' is waited for as long as neither the buffer nor the
 * output are full. If either of them is full, the string may be returned
 * as is, without the '\n'.
 */
int buffer_get_line(struct buffer *buf, char *str, int len)
{
	int ret, max;
	char *p;

	ret = 0;
	max = len;

	/* closed or empty + imminent close = -1; empty = 0 */
	if (unlikely(buf->flags & (BF_OUT_EMPTY|BF_SHUTW))) {
		if (buf->flags & (BF_SHUTW|BF_SHUTW_NOW))
			ret = -1;
		goto out;
	}

	p = bo_ptr(buf);

	if (max > buf->o) {
		max = buf->o;
		str[max-1] = 0;
	}
	while (max) {
		*str++ = *p;
		ret++;
		max--;

		if (*p == '\n')
			break;
		p = buffer_wrap_add(buf, p + 1);
	}
	if (ret > 0 && ret < len && ret < buf->o &&
	    *(str-1) != '\n' &&
	    !(buf->flags & (BF_SHUTW|BF_SHUTW_NOW)))
		ret = 0;
 out:
	if (max)
		*str = 0;
	return ret;
}

/* Gets one full block of data at once from a buffer, optionally from a
 * specific offset. Return values :
 *   >0 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <blk> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 * The buffer status is not changed. The caller must call buffer_skip() to
 * update it.
 */
int buffer_get_block(struct buffer *buf, char *blk, int len, int offset)
{
	int firstblock;

	if (buf->flags & BF_SHUTW)
		return -1;

	if (len + offset > buf->o) {
		if (buf->flags & (BF_SHUTW|BF_SHUTW_NOW))
			return -1;
		return 0;
	}

	firstblock = buf->data + buf->size - bo_ptr(buf);
	if (firstblock > offset) {
		if (firstblock >= len + offset) {
			memcpy(blk, bo_ptr(buf) + offset, len);
			return len;
		}

		memcpy(blk, bo_ptr(buf) + offset, firstblock - offset);
		memcpy(blk + firstblock - offset, buf->data, len - firstblock + offset);
		return len;
	}

	memcpy(blk, buf->data + offset - firstblock, len);
	return len;
}

/* This function writes the string <str> at position <pos> which must be in
 * buffer <b>, and moves <end> just after the end of <str>. <b>'s parameters
 * <l> and <r> are updated to be valid after the shift. The shift value
 * (positive or negative) is returned. If there's no space left, the move is
 * not done. The function does not adjust ->o nor BF_OUT_EMPTY because it
 * does not make sense to use it on data scheduled to be sent. For the same
 * reason, it does not make sense to call this function on unparsed data, so
 * <orig> is not updated. The string length is taken from parameter <len>. If
 * <len> is null, the <str> pointer is allowed to be null.
 */
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len)
{
	int delta;

	delta = len - (end - pos);

	if (bi_end(b) + delta >= b->data + b->size)
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

	b->flags &= ~BF_FULL;
	if (buffer_len(b) == 0)
		b->p = b->data;
	if (buffer_len(b) >= buffer_max_len(b))
		b->flags |= BF_FULL;

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

	/* first, protect the end of the buffer */
	memmove(pos + delta, pos, bi_end(b) - pos);

	/* now, copy str over pos */
	if (len && str) {
		memcpy(pos, str, len);
		pos[len] = '\r';
		pos[len + 1] = '\n';
	}

	b->i += delta;

	b->flags &= ~BF_FULL;
	if (buffer_len(b) >= buffer_max_len(b))
		b->flags |= BF_FULL;

	return delta;
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
 * Does an snprintf() at the end of chunk <chk>, respecting the limit of
 * at most chk->size chars. If the chk->len is over, nothing is added. Returns
 * the new chunk size.
 */
int chunk_printf(struct chunk *chk, const char *fmt, ...)
{
	va_list argp;
	int ret;

	if (!chk->str || !chk->size)
		return 0;

	va_start(argp, fmt);
	ret = vsnprintf(chk->str + chk->len, chk->size - chk->len, fmt, argp);
	if (ret >= chk->size - chk->len)
		/* do not copy anything in case of truncation */
		chk->str[chk->len] = 0;
	else
		chk->len += ret;
	va_end(argp);
	return chk->len;
}

/*
 * Encode chunk <src> into chunk <dst>, respecting the limit of at most
 * chk->size chars. Replace non-printable or special chracters with "&#%d;".
 * If the chk->len is over, nothing is added. Returns the new chunk size.
 */
int chunk_htmlencode(struct chunk *dst, struct chunk *src) {

	int i, l;
	int olen, free;
	char c;

	olen = dst->len;

	for (i = 0; i < src->len; i++) {
		free = dst->size - dst->len;

		if (!free) {
			dst->len = olen;
			return dst->len;
		}

		c = src->str[i];

		if (!isascii(c) || !isprint((unsigned char)c) || c == '&' || c == '"' || c == '\'' || c == '<' || c == '>') {
			l = snprintf(dst->str + dst->len, free, "&#%u;", (unsigned char)c);

			if (free < l) {
				dst->len = olen;
				return dst->len;
			}

			dst->len += l;
		} else {
			dst->str[dst->len] = c;
			dst->len++;
		}
	}

	return dst->len;
}

/*
 * Encode chunk <src> into chunk <dst>, respecting the limit of at most
 * chk->size chars. Replace non-printable or char passed in qc with "<%02X>".
 * If the chk->len is over, nothing is added. Returns the new chunk size.
 */
int chunk_asciiencode(struct chunk *dst, struct chunk *src, char qc) {
	int i, l;
	int olen, free;
	char c;

	olen = dst->len;

	for (i = 0; i < src->len; i++) {
		free = dst->size - dst->len;

		if (!free) {
			dst->len = olen;
			return dst->len;
		}

		c = src->str[i];

		if (!isascii(c) || !isprint((unsigned char)c) || c == '<' || c == '>' || c == qc) {
			l = snprintf(dst->str + dst->len, free, "<%02X>", (unsigned char)c);

			if (free < l) {
				dst->len = olen;
				return dst->len;
			}

			dst->len += l;
		} else {
			dst->str[dst->len] = c;
			dst->len++;
		}
	}

	return dst->len;
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
