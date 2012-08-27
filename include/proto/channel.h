/*
 * include/proto/channel.h
 * Channel management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_CHANNEL_H
#define _PROTO_CHANNEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/config.h>
#include <common/chunk.h>
#include <common/memory.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

extern struct pool_head *pool2_buffer;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_buffer();

/* SI-to-buffer functions : buffer_{get,put}_{char,block,string,chunk} */
int bo_inject(struct channel *buf, const char *msg, int len);
int bi_putblk(struct channel *buf, const char *str, int len);
int bi_putchr(struct channel *buf, char c);
int bo_getline(struct channel *buf, char *str, int len);
int bo_getblk(struct channel *buf, char *blk, int len, int offset);
unsigned long long buffer_forward(struct channel *buf, unsigned long long bytes);

/* Initialize all fields in the buffer. */
static inline void buffer_init(struct channel *buf)
{
	buf->buf.o = 0;
	buf->buf.i = 0;
	buf->buf.p = buf->buf.data;
	buf->to_forward = 0;
	buf->total = 0;
	buf->pipe = NULL;
	buf->analysers = 0;
	buf->cons = NULL;
	buf->flags = 0;
}

/*****************************************************************/
/* These functions are used to compute various buffer area sizes */
/*****************************************************************/

/* Reports non-zero if the channel is empty, which means both its
 * buffer and pipe are empty. The construct looks strange but is
 * jump-less and much more efficient on both 32 and 64-bit than
 * the boolean test.
 */
static inline unsigned int channel_is_empty(struct channel *c)
{
	return !(c->buf.o | (long)c->pipe);
}

/* Return the number of reserved bytes in the buffer, which ensures that once
 * all pending data are forwarded, the buffer still has global.tune.maxrewrite
 * bytes free. The result is between 0 and global.maxrewrite, which is itself
 * smaller than any buf->size.
 */
static inline int buffer_reserved(const struct channel *buf)
{
	int ret = global.tune.maxrewrite - buf->to_forward - buf->buf.o;

	if (buf->to_forward == CHN_INFINITE_FORWARD)
		return 0;
	if (ret <= 0)
		return 0;
	return ret;
}

/* Return the max number of bytes the buffer can contain so that once all the
 * pending bytes are forwarded, the buffer still has global.tune.maxrewrite
 * bytes free. The result sits between buf->size - maxrewrite and buf->size.
 */
static inline int buffer_max_len(const struct channel *buf)
{
	return buf->buf.size - buffer_reserved(buf);
}

/* Returns non-zero if the buffer input is considered full. The reserved space
 * is taken into account if ->to_forward indicates that an end of transfer is
 * close to happen. The test is optimized to avoid as many operations as
 * possible for the fast case and to be used as an "if" condition.
 */
static inline int channel_full(const struct channel *b)
{
	int rem = b->buf.size;

	rem -= b->buf.o;
	rem -= b->buf.i;
	if (!rem)
		return 1; /* buffer already full */

	if (b->to_forward >= b->buf.size ||
	    (CHN_INFINITE_FORWARD < MAX_RANGE(typeof(b->buf.size)) && // just there to ensure gcc
	     b->to_forward == CHN_INFINITE_FORWARD))              // avoids the useless second
		return 0;                                         // test whenever possible

	rem -= global.tune.maxrewrite;
	rem += b->buf.o;
	rem += b->to_forward;
	return rem <= 0;
}

/* Returns the amount of space available at the input of the buffer, taking the
 * reserved space into account if ->to_forward indicates that an end of transfer
 * is close to happen. The test is optimized to avoid as many operations as
 * possible for the fast case.
 */
static inline int bi_avail(const struct channel *b)
{
	int rem = b->buf.size;
	int rem2;

	rem -= b->buf.o;
	rem -= b->buf.i;
	if (!rem)
		return rem; /* buffer already full */

	if (b->to_forward >= b->buf.size ||
	    (CHN_INFINITE_FORWARD < MAX_RANGE(typeof(b->buf.size)) && // just there to ensure gcc
	     b->to_forward == CHN_INFINITE_FORWARD))              // avoids the useless second
		return rem;                                         // test whenever possible

	rem2 = rem - global.tune.maxrewrite;
	rem2 += b->buf.o;
	rem2 += b->to_forward;

	if (rem > rem2)
		rem = rem2;
	if (rem > 0)
		return rem;
	return 0;
}

/* Return the amount of bytes that can be written into the buffer at once,
 * excluding reserved space, which is preserved.
 */
static inline int buffer_contig_space_res(const struct channel *chn)
{
	return buffer_contig_space_with_res(&chn->buf, buffer_reserved(chn));
}

/* Returns true if the buffer's input is already closed */
static inline int buffer_input_closed(struct channel *buf)
{
	return ((buf->flags & CF_SHUTR) != 0);
}

/* Returns true if the buffer's output is already closed */
static inline int buffer_output_closed(struct channel *buf)
{
	return ((buf->flags & CF_SHUTW) != 0);
}

/* Check buffer timeouts, and set the corresponding flags. The
 * likely/unlikely have been optimized for fastest normal path.
 * The read/write timeouts are not set if there was activity on the buffer.
 * That way, we don't have to update the timeout on every I/O. Note that the
 * analyser timeout is always checked.
 */
static inline void buffer_check_timeouts(struct channel *b)
{
	if (likely(!(b->flags & (CF_SHUTR|CF_READ_TIMEOUT|CF_READ_ACTIVITY|CF_READ_NOEXP))) &&
	    unlikely(tick_is_expired(b->rex, now_ms)))
		b->flags |= CF_READ_TIMEOUT;

	if (likely(!(b->flags & (CF_SHUTW|CF_WRITE_TIMEOUT|CF_WRITE_ACTIVITY))) &&
	    unlikely(tick_is_expired(b->wex, now_ms)))
		b->flags |= CF_WRITE_TIMEOUT;

	if (likely(!(b->flags & CF_ANA_TIMEOUT)) &&
	    unlikely(tick_is_expired(b->analyse_exp, now_ms)))
		b->flags |= CF_ANA_TIMEOUT;
}

/* Erase any content from buffer <buf> and adjusts flags accordingly. Note
 * that any spliced data is not affected since we may not have any access to
 * it.
 */
static inline void buffer_erase(struct channel *buf)
{
	buf->buf.o = 0;
	buf->buf.i = 0;
	buf->to_forward = 0;
	buf->buf.p = buf->buf.data;
}

/* Cut the "tail" of the buffer, which means strip it to the length of unsent
 * data only, and kill any remaining unsent data. Any scheduled forwarding is
 * stopped. This is mainly to be used to send error messages after existing
 * data.
 */
static inline void bi_erase(struct channel *buf)
{
	if (!buf->buf.o)
		return buffer_erase(buf);

	buf->to_forward = 0;
	if (!buf->buf.i)
		return;

	buf->buf.i = 0;
}

/* marks the buffer as "shutdown" ASAP for reads */
static inline void buffer_shutr_now(struct channel *buf)
{
	buf->flags |= CF_SHUTR_NOW;
}

/* marks the buffer as "shutdown" ASAP for writes */
static inline void buffer_shutw_now(struct channel *buf)
{
	buf->flags |= CF_SHUTW_NOW;
}

/* marks the buffer as "shutdown" ASAP in both directions */
static inline void buffer_abort(struct channel *buf)
{
	buf->flags |= CF_SHUTR_NOW | CF_SHUTW_NOW;
	buf->flags &= ~CF_AUTO_CONNECT;
}

/* Installs <func> as a hijacker on the buffer <b> for session <s>. The hijack
 * flag is set, and the function called once. The function is responsible for
 * clearing the hijack bit. It is possible that the function clears the flag
 * during this first call.
 */
static inline void buffer_install_hijacker(struct session *s,
					   struct channel *b,
					   void (*func)(struct session *, struct channel *))
{
	b->hijacker = func;
	b->flags |= CF_HIJACK;
	func(s, b);
}

/* Releases the buffer from hijacking mode. Often used by the hijack function */
static inline void buffer_stop_hijack(struct channel *buf)
{
	buf->flags &= ~CF_HIJACK;
}

/* allow the consumer to try to establish a new connection. */
static inline void buffer_auto_connect(struct channel *buf)
{
	buf->flags |= CF_AUTO_CONNECT;
}

/* prevent the consumer from trying to establish a new connection, and also
 * disable auto shutdown forwarding.
 */
static inline void buffer_dont_connect(struct channel *buf)
{
	buf->flags &= ~(CF_AUTO_CONNECT|CF_AUTO_CLOSE);
}

/* allow the producer to forward shutdown requests */
static inline void buffer_auto_close(struct channel *buf)
{
	buf->flags |= CF_AUTO_CLOSE;
}

/* prevent the producer from forwarding shutdown requests */
static inline void buffer_dont_close(struct channel *buf)
{
	buf->flags &= ~CF_AUTO_CLOSE;
}

/* allow the producer to read / poll the input */
static inline void buffer_auto_read(struct channel *buf)
{
	buf->flags &= ~CF_DONT_READ;
}

/* prevent the producer from read / poll the input */
static inline void buffer_dont_read(struct channel *buf)
{
	buf->flags |= CF_DONT_READ;
}

/*
 * Advance the buffer's read pointer by <len> bytes. This is useful when data
 * have been read directly from the buffer. It is illegal to call this function
 * with <len> causing a wrapping at the end of the buffer. It's the caller's
 * responsibility to ensure that <len> is never larger than buf->o.
 */
static inline void bo_skip(struct channel *buf, int len)
{
	buf->buf.o -= len;

	if (buffer_len(&buf->buf) == 0)
		buf->buf.p = buf->buf.data;

	/* notify that some data was written to the SI from the buffer */
	buf->flags |= CF_WRITE_PARTIAL;
}

/* Tries to copy chunk <chunk> into buffer <buf> after length controls.
 * The ->o and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Buffer flag READ_PARTIAL is updated if some data can be transferred. The
 * chunk's length is updated with the number of bytes sent.
 */
static inline int bi_putchk(struct channel *buf, struct chunk *chunk)
{
	int ret;

	ret = bi_putblk(buf, chunk->str, chunk->len);
	if (ret > 0)
		chunk->len -= ret;
	return ret;
}

/* Tries to copy string <str> at once into buffer <buf> after length controls.
 * The ->o and to_forward pointers are updated. If the buffer's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Buffer flag READ_PARTIAL is updated if some data can be transferred.
 */
static inline int bi_putstr(struct channel *buf, const char *str)
{
	return bi_putblk(buf, str, strlen(str));
}

/*
 * Return one char from the buffer. If the buffer is empty and closed, return -2.
 * If the buffer is just empty, return -1. The buffer's pointer is not advanced,
 * it's up to the caller to call bo_skip(buf, 1) when it has consumed the char.
 * Also note that this function respects the ->o limit.
 */
static inline int bo_getchr(struct channel *buf)
{
	/* closed or empty + imminent close = -2; empty = -1 */
	if (unlikely((buf->flags & CF_SHUTW) || channel_is_empty(buf))) {
		if (buf->flags & (CF_SHUTW|CF_SHUTW_NOW))
			return -2;
		return -1;
	}
	return *buffer_wrap_sub(&buf->buf, buf->buf.p - buf->buf.o);
}


#endif /* _PROTO_CHANNEL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
