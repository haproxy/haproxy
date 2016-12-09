/*
 * include/proto/channel.h
 * Channel management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2014 Willy Tarreau - w@1wt.eu
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
#include <common/ticks.h>
#include <common/time.h>

#include <types/channel.h>
#include <types/global.h>
#include <types/stream.h>
#include <types/stream_interface.h>

#include <proto/applet.h>
#include <proto/task.h>

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_channel();

unsigned long long __channel_forward(struct channel *chn, unsigned long long bytes);

/* SI-to-channel functions working with buffers */
int bi_putblk(struct channel *chn, const char *str, int len);
struct buffer *bi_swpbuf(struct channel *chn, struct buffer *buf);
int bi_putchr(struct channel *chn, char c);
int bi_getline_nc(struct channel *chn, char **blk1, int *len1, char **blk2, int *len2);
int bi_getblk_nc(struct channel *chn, char **blk1, int *len1, char **blk2, int *len2);
int bo_inject(struct channel *chn, const char *msg, int len);
int bo_getline(struct channel *chn, char *str, int len);
int bo_getblk(struct channel *chn, char *blk, int len, int offset);
int bo_getline_nc(struct channel *chn, char **blk1, int *len1, char **blk2, int *len2);
int bo_getblk_nc(struct channel *chn, char **blk1, int *len1, char **blk2, int *len2);


/* returns a pointer to the stream the channel belongs to */
static inline struct stream *chn_strm(const struct channel *chn)
{
	if (chn->flags & CF_ISRESP)
		return LIST_ELEM(chn, struct stream *, res);
	else
		return LIST_ELEM(chn, struct stream *, req);
}

/* returns a pointer to the stream interface feeding the channel (producer) */
static inline struct stream_interface *chn_prod(const struct channel *chn)
{
	if (chn->flags & CF_ISRESP)
		return &LIST_ELEM(chn, struct stream *, res)->si[1];
	else
		return &LIST_ELEM(chn, struct stream *, req)->si[0];
}

/* returns a pointer to the stream interface consuming the channel (producer) */
static inline struct stream_interface *chn_cons(const struct channel *chn)
{
	if (chn->flags & CF_ISRESP)
		return &LIST_ELEM(chn, struct stream *, res)->si[0];
	else
		return &LIST_ELEM(chn, struct stream *, req)->si[1];
}

/* Initialize all fields in the channel. */
static inline void channel_init(struct channel *chn)
{
	chn->buf = &buf_empty;
	chn->to_forward = 0;
	chn->last_read = now_ms;
	chn->xfer_small = chn->xfer_large = 0;
	chn->total = 0;
	chn->pipe = NULL;
	chn->analysers = 0;
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

/* Forwards any input data and marks the channel for permanent forwarding */
static inline void channel_forward_forever(struct channel *chn)
{
	b_adv(chn->buf, chn->buf->i);
	chn->to_forward = CHN_INFINITE_FORWARD;
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

/* Returns non-zero if the channel is rewritable, which means that the buffer
 * it is attached to has at least <maxrewrite> bytes immediately available.
 * This is used to decide when a request or response may be parsed when some
 * data from a previous exchange might still be present.
 */
static inline int channel_is_rewritable(const struct channel *chn)
{
	int rem = chn->buf->size;

	rem -= chn->buf->o;
	rem -= chn->buf->i;
	rem -= global.tune.maxrewrite;
	return rem >= 0;
}

/* Returns non-zero if the channel is congested with data in transit waiting
 * for leaving, indicating to the caller that it should wait for the reserve to
 * be released before starting to process new data in case it needs the ability
 * to append data. This is meant to be used while waiting for a clean response
 * buffer before processing a request.
 */
static inline int channel_congested(const struct channel *chn)
{
	if (!chn->buf->o)
		return 0;

	if (!channel_is_rewritable(chn))
		return 1;

	if (chn->buf->p + chn->buf->i >
	    chn->buf->data + chn->buf->size - global.tune.maxrewrite)
		return 1;

	return 0;
}

/* Tells whether data are likely to leave the buffer. This is used to know when
 * we can safely ignore the reserve since we know we cannot retry a connection.
 * It returns zero if data are blocked, non-zero otherwise.
 */
static inline int channel_may_send(const struct channel *chn)
{
	return chn_cons(chn)->state == SI_ST_EST;
}

/* Returns non-zero if the channel can still receive data. This is used to
 * decide when to stop reading into a buffer when we want to ensure that we
 * leave the reserve untouched after all pending outgoing data are forwarded.
 * The reserved space is taken into account if ->to_forward indicates that an
 * end of transfer is close to happen. Note that both ->buf->o and ->to_forward
 * are considered as available since they're supposed to leave the buffer. The
 * test is optimized to avoid as many operations as possible for the fast case
 * and to be used as an "if" condition. Just like channel_recv_limit(), we
 * never allow to overwrite the reserve until the output stream interface is
 * connected, otherwise we could spin on a POST with http-send-name-header.
 */
static inline int channel_may_recv(const struct channel *chn)
{
	int rem = chn->buf->size;

	if (chn->buf == &buf_empty)
		return 1;

	rem -= chn->buf->o;
	rem -= chn->buf->i;
	if (!rem)
		return 0; /* buffer already full */

	if (rem > global.tune.maxrewrite)
		return 1; /* reserve not yet reached */

	if (!channel_may_send(chn))
		return 0; /* don't touch reserve until we can send */

	/* Now we know there's some room left in the reserve and we may
	 * forward. As long as i-to_fwd < size-maxrw, we may still
	 * receive. This is equivalent to i+maxrw-size < to_fwd,
	 * which is logical since i+maxrw-size is what overlaps with
	 * the reserve, and we want to ensure they're covered by scheduled
	 * forwards.
	 */
	rem = chn->buf->i + global.tune.maxrewrite - chn->buf->size;
	return rem < 0 || (unsigned int)rem < chn->to_forward;
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
	chn->to_forward = 0;
	b_reset(chn->buf);
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


/* Return the max number of bytes the buffer can contain so that once all the
 * pending bytes are forwarded, the buffer still has global.tune.maxrewrite
 * bytes free. The result sits between chn->size - maxrewrite and chn->size.
 * It is important to mention that if buf->i is already larger than size-maxrw
 * the condition above cannot be satisfied and the lowest size will be returned
 * anyway. The principles are the following :
 *   0) the empty buffer has a limit of zero
 *   1) a non-connected buffer cannot touch the reserve
 *   2) infinite forward can always fill the buffer since all data will leave
 *   3) all output bytes are considered in transit since they're leaving
 *   4) all input bytes covered by to_forward are considered in transit since
 *      they'll be converted to output bytes.
 *   5) all input bytes not covered by to_forward as considered remaining
 *   6) all bytes scheduled to be forwarded minus what is already in the input
 *      buffer will be in transit during future rounds.
 *   7) 4+5+6 imply that the amount of input bytes (i) is irrelevant to the max
 *      usable length, only to_forward and output count. The difference is
 *      visible when to_forward > i.
 *   8) the reserve may be covered up to the amount of bytes in transit since
 *      these bytes will only take temporary space.
 *
 * A typical buffer looks like this :
 *
 *      <-------------- max_len ----------->
 *      <---- o ----><----- i ----->        <--- 0..maxrewrite --->
 *      +------------+--------------+-------+----------------------+
 *      |////////////|\\\\\\\\\\\\\\|xxxxxxx|        reserve       |
 *      +------------+--------+-----+-------+----------------------+
 *                   <- fwd ->      <-avail->
 *
 * Or when to_forward > i :
 *
 *      <-------------- max_len ----------->
 *      <---- o ----><----- i ----->        <--- 0..maxrewrite --->
 *      +------------+--------------+-------+----------------------+
 *      |////////////|\\\\\\\\\\\\\\|xxxxxxx|        reserve       |
 *      +------------+--------+-----+-------+----------------------+
 *                                  <-avail->
 *                   <------------------ fwd ---------------->
 *
 * - the amount of buffer bytes in transit is : min(i, fwd) + o
 * - some scheduled bytes may be in transit (up to fwd - i)
 * - the reserve is max(0, maxrewrite - transit)
 * - the maximum usable buffer length is size - reserve.
 * - the available space is max_len - i - o
 *
 * So the formula to compute the buffer's maximum length to protect the reserve
 * when reading new data is :
 *
 *    max = size - maxrewrite + min(maxrewrite, transit)
 *        = size - max(maxrewrite - transit, 0)
 *
 * But WARNING! The conditions might change during the transfer and it could
 * very well happen that a buffer would contain more bytes than max_len due to
 * i+o already walking over the reserve (eg: after a header rewrite), including
 * i or o alone hitting the limit. So it is critical to always consider that
 * bounds may have already been crossed and that available space may be negative
 * for example. Due to this it is perfectly possible for this function to return
 * a value that is lower than current i+o.
 */
static inline int channel_recv_limit(const struct channel *chn)
{
	unsigned int transit;
	int reserve;

	/* return zero if empty */
	reserve = chn->buf->size;
	if (chn->buf == &buf_empty)
		goto end;

	/* return size - maxrewrite if we can't send */
	reserve = global.tune.maxrewrite;
	if (unlikely(!channel_may_send(chn)))
		goto end;

	/* We need to check what remains of the reserve after o and to_forward
	 * have been transmitted, but they can overflow together and they can
	 * cause an integer underflow in the comparison since both are unsigned
	 * while maxrewrite is signed.
	 * The code below has been verified for being a valid check for this :
	 *   - if (o + to_forward) overflow => return size  [ large enough ]
	 *   - if o + to_forward >= maxrw   => return size  [ large enough ]
	 *   - otherwise return size - (maxrw - (o + to_forward))
	 */
	transit = chn->buf->o + chn->to_forward;
	reserve -= transit;
	if (transit < chn->to_forward ||                 // addition overflow
	    transit >= (unsigned)global.tune.maxrewrite) // enough transit data
		return chn->buf->size;
 end:
	return chn->buf->size - reserve;
}

/* Returns the amount of space available at the input of the buffer, taking the
 * reserved space into account if ->to_forward indicates that an end of transfer
 * is close to happen. The test is optimized to avoid as many operations as
 * possible for the fast case.
 */
static inline int channel_recv_max(const struct channel *chn)
{
	int ret;

	ret = channel_recv_limit(chn) - chn->buf->i - chn->buf->o;
	if (ret < 0)
		ret = 0;
	return ret;
}

/* Allocates a buffer for channel <chn>, but only if it's guaranteed that it's
 * not the last available buffer or it's the response buffer. Unless the buffer
 * is the response buffer, an extra control is made so that we always keep
 * <tune.buffers.reserved> buffers available after this allocation. Returns 0 in
 * case of failure, non-zero otherwise.
 *
 * If no buffer are available, the requester, represented by <wait> pointer,
 * will be added in the list of objects waiting for an available buffer.
 */
static inline int channel_alloc_buffer(struct channel *chn, struct buffer_wait *wait)
{
	int margin = 0;

	if (!(chn->flags & CF_ISRESP))
		margin = global.tune.reserved_bufs;

	if (b_alloc_margin(&chn->buf, margin) != NULL)
		return 1;

	if (LIST_ISEMPTY(&wait->list))
		LIST_ADDQ(&buffer_wq, &wait->list);
	return 0;
}

/* Releases a possibly allocated buffer for channel <chn>. If it was not
 * allocated, this function does nothing. Else the buffer is released and we try
 * to wake up as many streams/applets as possible. */
static inline void channel_release_buffer(struct channel *chn, struct buffer_wait *wait)
{
	if (chn->buf->size && buffer_empty(chn->buf)) {
		b_free(&chn->buf);
		offer_buffers(wait->target, tasks_run_queue + applets_active_queue);
	}
}

/* Truncate any unread data in the channel's buffer, and disable forwarding.
 * Outgoing data are left intact. This is mainly to be used to send error
 * messages after existing data.
 */
static inline void channel_truncate(struct channel *chn)
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
