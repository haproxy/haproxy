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

extern struct pool_head *pool2_channel;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_channel();

unsigned long long __channel_forward(struct channel *chn, unsigned long long bytes);

/* SI-to-channel functions working with buffers */
int bi_putblk(struct channel *chn, const char *str, int len);
int bi_putchr(struct channel *chn, char c);
int bo_inject(struct channel *chn, const char *msg, int len);
int bo_getline(struct channel *chn, char *str, int len);
int bo_getblk(struct channel *chn, char *blk, int len, int offset);

/* Initialize all fields in the channel. */
static inline void channel_init(struct channel *chn)
{
	chn->buf->o = 0;
	chn->buf->i = 0;
	chn->buf->p = chn->buf->data;
	chn->to_forward = 0;
	chn->last_read = now_ms;
	chn->xfer_small = chn->xfer_large = 0;
	chn->total = 0;
	chn->pipe = NULL;
	chn->analysers = 0;
	chn->cons = NULL;
	chn->flags = 0;
}

/* Schedule up to <bytes> more bytes to be forwarded via the channel without
 * notifying the owner task. Any data pending in the buffer are scheduled to be
 * sent as well, in the limit of the number of bytes to forward. This must be
 * the only method to use to schedule bytes to be forwarded. If the requested
 * number is too large, it is automatically adjusted. The number of bytes taken
 * into account is returned. Directly touching ->to_forward will cause lockups
 * when buf->o goes down to zero if nobody is ready to push the remaining data.
 */
static inline unsigned long long channel_forward(struct channel *chn, unsigned long long bytes)
{
	/* hint: avoid comparisons on long long for the fast case, since if the
	 * length does not fit in an unsigned it, it will never be forwarded at
	 * once anyway.
	 */
	if (bytes <= ~0U) {
		unsigned int bytes32 = bytes;

		if (bytes32 <= chn->buf->i) {
			/* OK this amount of bytes might be forwarded at once */
			b_adv(chn->buf, bytes32);
			return bytes;
		}
	}
	return __channel_forward(chn, bytes);
}

/*********************************************************************/
/* These functions are used to compute various channel content sizes */
/*********************************************************************/

/* Reports non-zero if the channel is empty, which means both its
 * buffer and pipe are empty. The construct looks strange but is
 * jump-less and much more efficient on both 32 and 64-bit than
 * the boolean test.
 */
static inline unsigned int channel_is_empty(struct channel *c)
{
	return !(c->buf->o | (long)c->pipe);
}

/* Returns non-zero if the buffer input has all of its reserve available. This
 * is used to decide when a request or response may be parsed when some data
 * from a previous exchange might still be present.
 */
static inline int channel_reserved(const struct channel *chn)
{
	int rem = chn->buf->size;

	rem -= chn->buf->o;
	rem -= chn->buf->i;
	rem -= global.tune.maxrewrite;
	return rem >= 0;
}

/* Returns non-zero if the buffer input is considered full. This is used to
 * decide when to stop reading into a buffer when we want to ensure that we
 * leave the reserve untouched after all pending outgoing data are forwarded.
 * The reserved space is taken into account if ->to_forward indicates that an
 * end of transfer is close to happen. Note that both ->buf->o and ->to_forward
 * are considered as available since they're supposed to leave the buffer. The
 * test is optimized to avoid as many operations as possible for the fast case
 * and to be used as an "if" condition.
 */
static inline int channel_full(const struct channel *chn)
{
	int rem = chn->buf->size;

	rem -= chn->buf->o;
	rem -= chn->buf->i;
	if (!rem)
		return 1; /* buffer already full */

	if (chn->to_forward >= chn->buf->size ||
	    (CHN_INFINITE_FORWARD < MAX_RANGE(typeof(chn->buf->size)) && // just there to ensure gcc
	     chn->to_forward == CHN_INFINITE_FORWARD))                  // avoids the useless second
		return 0;                                               // test whenever possible

	rem -= global.tune.maxrewrite;
	rem += chn->buf->o;
	rem += chn->to_forward;
	return rem <= 0;
}

/* Returns true if the channel's input is already closed */
static inline int channel_input_closed(struct channel *chn)
{
	return ((chn->flags & CF_SHUTR) != 0);
}

/* Returns true if the channel's output is already closed */
static inline int channel_output_closed(struct channel *chn)
{
	return ((chn->flags & CF_SHUTW) != 0);
}

/* Check channel timeouts, and set the corresponding flags. The likely/unlikely
 * have been optimized for fastest normal path. The read/write timeouts are not
 * set if there was activity on the channel. That way, we don't have to update
 * the timeout on every I/O. Note that the analyser timeout is always checked.
 */
static inline void channel_check_timeouts(struct channel *chn)
{
	if (likely(!(chn->flags & (CF_SHUTR|CF_READ_TIMEOUT|CF_READ_ACTIVITY|CF_READ_NOEXP))) &&
	    unlikely(tick_is_expired(chn->rex, now_ms)))
		chn->flags |= CF_READ_TIMEOUT;

	if (likely(!(chn->flags & (CF_SHUTW|CF_WRITE_TIMEOUT|CF_WRITE_ACTIVITY))) &&
	    unlikely(tick_is_expired(chn->wex, now_ms)))
		chn->flags |= CF_WRITE_TIMEOUT;

	if (likely(!(chn->flags & CF_ANA_TIMEOUT)) &&
	    unlikely(tick_is_expired(chn->analyse_exp, now_ms)))
		chn->flags |= CF_ANA_TIMEOUT;
}

/* Erase any content from channel <buf> and adjusts flags accordingly. Note
 * that any spliced data is not affected since we may not have any access to
 * it.
 */
static inline void channel_erase(struct channel *chn)
{
	chn->buf->o = 0;
	chn->buf->i = 0;
	chn->to_forward = 0;
	chn->buf->p = chn->buf->data;
}

/* marks the channel as "shutdown" ASAP for reads */
static inline void channel_shutr_now(struct channel *chn)
{
	chn->flags |= CF_SHUTR_NOW;
}

/* marks the channel as "shutdown" ASAP for writes */
static inline void channel_shutw_now(struct channel *chn)
{
	chn->flags |= CF_SHUTW_NOW;
}

/* marks the channel as "shutdown" ASAP in both directions */
static inline void channel_abort(struct channel *chn)
{
	chn->flags |= CF_SHUTR_NOW | CF_SHUTW_NOW;
	chn->flags &= ~CF_AUTO_CONNECT;
}

/* allow the consumer to try to establish a new connection. */
static inline void channel_auto_connect(struct channel *chn)
{
	chn->flags |= CF_AUTO_CONNECT;
}

/* prevent the consumer from trying to establish a new connection, and also
 * disable auto shutdown forwarding.
 */
static inline void channel_dont_connect(struct channel *chn)
{
	chn->flags &= ~(CF_AUTO_CONNECT|CF_AUTO_CLOSE);
}

/* allow the producer to forward shutdown requests */
static inline void channel_auto_close(struct channel *chn)
{
	chn->flags |= CF_AUTO_CLOSE;
}

/* prevent the producer from forwarding shutdown requests */
static inline void channel_dont_close(struct channel *chn)
{
	chn->flags &= ~CF_AUTO_CLOSE;
}

/* allow the producer to read / poll the input */
static inline void channel_auto_read(struct channel *chn)
{
	chn->flags &= ~CF_DONT_READ;
}

/* prevent the producer from read / poll the input */
static inline void channel_dont_read(struct channel *chn)
{
	chn->flags |= CF_DONT_READ;
}


/*************************************************/
/* Buffer operations in the context of a channel */
/*************************************************/


/* Return the number of reserved bytes in the channel's visible
 * buffer, which ensures that once all pending data are forwarded, the
 * buffer still has global.tune.maxrewrite bytes free. The result is
 * between 0 and global.tune.maxrewrite, which is itself smaller than
 * any chn->size.
 */
static inline int buffer_reserved(const struct channel *chn)
{
	int ret = global.tune.maxrewrite - chn->to_forward - chn->buf->o;

	if (chn->to_forward == CHN_INFINITE_FORWARD)
		return 0;
	if (ret <= 0)
		return 0;
	return ret;
}

/* Return the max number of bytes the buffer can contain so that once all the
 * pending bytes are forwarded, the buffer still has global.tune.maxrewrite
 * bytes free. The result sits between chn->size - maxrewrite and chn->size.
 */
static inline int buffer_max_len(const struct channel *chn)
{
	return chn->buf->size - buffer_reserved(chn);
}

/* Returns the amount of space available at the input of the buffer, taking the
 * reserved space into account if ->to_forward indicates that an end of transfer
 * is close to happen. The test is optimized to avoid as many operations as
 * possible for the fast case.
 */
static inline int bi_avail(const struct channel *chn)
{
	int rem = chn->buf->size;
	int rem2;

	rem -= chn->buf->o;
	rem -= chn->buf->i;
	if (!rem)
		return rem; /* buffer already full */

	if (chn->to_forward >= chn->buf->size ||
	    (CHN_INFINITE_FORWARD < MAX_RANGE(typeof(chn->buf->size)) && // just there to ensure gcc
	     chn->to_forward == CHN_INFINITE_FORWARD))                  // avoids the useless second
		return rem;                                             // test whenever possible

	rem2 = rem - global.tune.maxrewrite;
	rem2 += chn->buf->o;
	rem2 += chn->to_forward;

	if (rem > rem2)
		rem = rem2;
	if (rem > 0)
		return rem;
	return 0;
}

/* Cut the "tail" of the channel's buffer, which means strip it to the length
 * of unsent data only, and kill any remaining unsent data. Any scheduled
 * forwarding is stopped. This is mainly to be used to send error messages
 * after existing data.
 */
static inline void bi_erase(struct channel *chn)
{
	if (!chn->buf->o)
		return channel_erase(chn);

	chn->to_forward = 0;
	if (!chn->buf->i)
		return;

	chn->buf->i = 0;
}

/*
 * Advance the channel buffer's read pointer by <len> bytes. This is useful
 * when data have been read directly from the buffer. It is illegal to call
 * this function with <len> causing a wrapping at the end of the buffer. It's
 * the caller's responsibility to ensure that <len> is never larger than
 * chn->o. Channel flag WRITE_PARTIAL is set.
 */
static inline void bo_skip(struct channel *chn, int len)
{
	chn->buf->o -= len;

	if (buffer_empty(chn->buf))
		chn->buf->p = chn->buf->data;

	/* notify that some data was written to the SI from the buffer */
	chn->flags |= CF_WRITE_PARTIAL;
}

/* Tries to copy chunk <chunk> into the channel's buffer after length controls.
 * The chn->o and to_forward pointers are updated. If the channel's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Channel flag READ_PARTIAL is updated if some data can be transferred. The
 * chunk's length is updated with the number of bytes sent.
 */
static inline int bi_putchk(struct channel *chn, struct chunk *chunk)
{
	int ret;

	ret = bi_putblk(chn, chunk->str, chunk->len);
	if (ret > 0)
		chunk->len -= ret;
	return ret;
}

/* Tries to copy string <str> at once into the channel's buffer after length
 * controls.  The chn->o and to_forward pointers are updated. If the channel's
 * input is closed, -2 is returned. If the block is too large for this buffer,
 * -3 is returned. If there is not enough room left in the buffer, -1 is
 * returned.  Otherwise the number of bytes copied is returned (0 being a valid
 * number).  Channel flag READ_PARTIAL is updated if some data can be
 * transferred.
 */
static inline int bi_putstr(struct channel *chn, const char *str)
{
	return bi_putblk(chn, str, strlen(str));
}

/*
 * Return one char from the channel's buffer. If the buffer is empty and the
 * channel is closed, return -2. If the buffer is just empty, return -1. The
 * buffer's pointer is not advanced, it's up to the caller to call bo_skip(buf,
 * 1) when it has consumed the char.  Also note that this function respects the
 * chn->o limit.
 */
static inline int bo_getchr(struct channel *chn)
{
	/* closed or empty + imminent close = -2; empty = -1 */
	if (unlikely((chn->flags & CF_SHUTW) || channel_is_empty(chn))) {
		if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW))
			return -2;
		return -1;
	}
	return *buffer_wrap_sub(chn->buf, chn->buf->p - chn->buf->o);
}


#endif /* _PROTO_CHANNEL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
