/*
 * include/haproxy/channel.h
 * Channel management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_CHANNEL_H
#define _HAPROXY_CHANNEL_H

#include <haproxy/api.h>
#include <haproxy/channel-t.h>
#include <haproxy/dynbuf.h>
#include <haproxy/global.h>
#include <haproxy/htx.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface-t.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools-t.h>


/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_channel();

unsigned long long __channel_forward(struct channel *chn, unsigned long long bytes);

/* SI-to-channel functions working with buffers */
int ci_putblk(struct channel *chn, const char *str, int len);
int ci_putchr(struct channel *chn, char c);
int ci_getline_nc(const struct channel *chn, char **blk1, size_t *len1, char **blk2, size_t *len2);
int ci_getblk_nc(const struct channel *chn, char **blk1, size_t *len1, char **blk2, size_t *len2);
int ci_insert_line2(struct channel *c, int pos, const char *str, int len);
int co_inject(struct channel *chn, const char *msg, int len);
int co_getchar(const struct channel *chn, char *c);
int co_getline(const struct channel *chn, char *str, int len);
int co_getdelim(const struct channel *chn, char *str, int len, const char *delim, char escape);
int co_getword(const struct channel *chn, char *str, int len, char sep);
int co_getblk(const struct channel *chn, char *blk, int len, int offset);
int co_getline_nc(const struct channel *chn, const char **blk1, size_t *len1, const char **blk2, size_t *len2);
int co_getblk_nc(const struct channel *chn, const char **blk1, size_t *len1, const char **blk2, size_t *len2);


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

/* c_orig() : returns the pointer to the channel buffer's origin */
static inline char *c_orig(const struct channel *c)
{
	return b_orig(&c->buf);
}

/* c_size() : returns the size of the channel's buffer */
static inline size_t c_size(const struct channel *c)
{
	return b_size(&c->buf);
}

/* c_wrap() : returns the pointer to the channel buffer's wrapping point */
static inline char *c_wrap(const struct channel *c)
{
	return b_wrap(&c->buf);
}

/* c_data() : returns the amount of data in the channel's buffer */
static inline size_t c_data(const struct channel *c)
{
	return b_data(&c->buf);
}

/* c_room() : returns the room left in the channel's buffer */
static inline size_t c_room(const struct channel *c)
{
	return b_size(&c->buf) - b_data(&c->buf);
}

/* c_empty() : returns a boolean indicating if the channel's buffer is empty */
static inline size_t c_empty(const struct channel *c)
{
	return !c_data(c);
}

/* c_full() : returns a boolean indicating if the channel's buffer is full */
static inline size_t c_full(const struct channel *c)
{
	return !c_room(c);
}

/* co_data() : returns the amount of output data in the channel's buffer */
static inline size_t co_data(const struct channel *c)
{
	return c->output;
}

/* ci_data() : returns the amount of input data in the channel's buffer */
static inline size_t ci_data(const struct channel *c)
{
	return c_data(c) - co_data(c);
}

/* ci_next() : for an absolute pointer <p> or a relative offset <o> pointing to
 * a valid location within channel <c>'s buffer, returns either the absolute
 * pointer or the relative offset pointing to the next byte, which usually is
 * at (p + 1) unless p reaches the wrapping point and wrapping is needed.
 */
static inline size_t ci_next_ofs(const struct channel *c, size_t o)
{
	return b_next_ofs(&c->buf, o);
}
static inline char *ci_next(const struct channel *c, const char *p)
{
	return b_next(&c->buf, p);
}


/* c_ptr() : returns a pointer to an offset relative to the beginning of the
 * input data in the buffer. If instead the offset is negative, a pointer to
 * existing output data is returned. The function only takes care of wrapping,
 * it's up to the caller to ensure the offset is always within byte count
 * bounds.
 */
static inline char *c_ptr(const struct channel *c, ssize_t ofs)
{
	return b_peek(&c->buf, co_data(c) + ofs);
}

/* c_adv() : advances the channel's buffer by <adv> bytes, which means that the
 * buffer's pointer advances, and that as many bytes from in are transferred
 * from in to out. The caller is responsible for ensuring that adv is always
 * smaller than or equal to b->i.
 */
static inline void c_adv(struct channel *c, size_t adv)
{
	c->output += adv;
}

/* c_rew() : rewinds the channel's buffer by <adv> bytes, which means that the
 * buffer's pointer goes backwards, and that as many bytes from out are moved
 * to in. The caller is responsible for ensuring that adv is always smaller
 * than or equal to b->o.
 */
static inline void c_rew(struct channel *c, size_t adv)
{
	c->output -= adv;
}

/* c_realign_if_empty() : realign the channel's buffer if it's empty */
static inline void c_realign_if_empty(struct channel *chn)
{
	b_realign_if_empty(&chn->buf);
}

/* Sets the amount of output for the channel */
static inline void co_set_data(struct channel *c, size_t output)
{
	c->output = output;
}


/* co_head() : returns a pointer to the beginning of output data in the buffer.
 *             The "__" variants don't support wrapping, "ofs" are relative to
 *             the buffer's origin.
 */
static inline size_t __co_head_ofs(const struct channel *c)
{
	return __b_peek_ofs(&c->buf, 0);
}
static inline char *__co_head(const struct channel *c)
{
	return __b_peek(&c->buf, 0);
}
static inline size_t co_head_ofs(const struct channel *c)
{
	return b_peek_ofs(&c->buf, 0);
}
static inline char *co_head(const struct channel *c)
{
	return b_peek(&c->buf, 0);
}


/* co_tail() : returns a pointer to the end of output data in the buffer.
 *             The "__" variants don't support wrapping, "ofs" are relative to
 *             the buffer's origin.
 */
static inline size_t __co_tail_ofs(const struct channel *c)
{
	return __b_peek_ofs(&c->buf, co_data(c));
}
static inline char *__co_tail(const struct channel *c)
{
	return __b_peek(&c->buf, co_data(c));
}
static inline size_t co_tail_ofs(const struct channel *c)
{
	return b_peek_ofs(&c->buf, co_data(c));
}
static inline char *co_tail(const struct channel *c)
{
	return b_peek(&c->buf, co_data(c));
}


/* ci_head() : returns a pointer to the beginning of input data in the buffer.
 *             The "__" variants don't support wrapping, "ofs" are relative to
 *             the buffer's origin.
 */
static inline size_t __ci_head_ofs(const struct channel *c)
{
	return __b_peek_ofs(&c->buf, co_data(c));
}
static inline char *__ci_head(const struct channel *c)
{
	return __b_peek(&c->buf, co_data(c));
}
static inline size_t ci_head_ofs(const struct channel *c)
{
	return b_peek_ofs(&c->buf, co_data(c));
}
static inline char *ci_head(const struct channel *c)
{
	return b_peek(&c->buf, co_data(c));
}


/* ci_tail() : returns a pointer to the end of input data in the buffer.
 *             The "__" variants don't support wrapping, "ofs" are relative to
 *             the buffer's origin.
 */
static inline size_t __ci_tail_ofs(const struct channel *c)
{
	return __b_peek_ofs(&c->buf, c_data(c));
}
static inline char *__ci_tail(const struct channel *c)
{
	return __b_peek(&c->buf, c_data(c));
}
static inline size_t ci_tail_ofs(const struct channel *c)
{
	return b_peek_ofs(&c->buf, c_data(c));
}
static inline char *ci_tail(const struct channel *c)
{
	return b_peek(&c->buf, c_data(c));
}


/* ci_stop() : returns the pointer to the byte following the end of input data
 *             in the channel buffer. It may be out of the buffer. It's used to
 *             compute lengths or stop pointers.
 */
static inline size_t __ci_stop_ofs(const struct channel *c)
{
	return __b_stop_ofs(&c->buf);
}
static inline const char *__ci_stop(const struct channel *c)
{
	return __b_stop(&c->buf);
}
static inline size_t ci_stop_ofs(const struct channel *c)
{
	return b_stop_ofs(&c->buf);
}
static inline const char *ci_stop(const struct channel *c)
{
	return b_stop(&c->buf);
}


/* Returns the amount of input data that can contiguously be read at once */
static inline size_t ci_contig_data(const struct channel *c)
{
	return b_contig_data(&c->buf, co_data(c));
}

/* Initialize all fields in the channel. */
static inline void channel_init(struct channel *chn)
{
	chn->buf = BUF_NULL;
	chn->to_forward = 0;
	chn->last_read = now_ms;
	chn->xfer_small = chn->xfer_large = 0;
	chn->total = 0;
	chn->pipe = NULL;
	chn->analysers = 0;
	chn->flags = 0;
	chn->output = 0;
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

		if (bytes32 <= ci_data(chn)) {
			/* OK this amount of bytes might be forwarded at once */
			c_adv(chn, bytes32);
			return bytes;
		}
	}
	return __channel_forward(chn, bytes);
}

/* Forwards any input data and marks the channel for permanent forwarding */
static inline void channel_forward_forever(struct channel *chn)
{
	c_adv(chn, ci_data(chn));
	chn->to_forward = CHN_INFINITE_FORWARD;
}

/* <len> bytes of input data was added into the channel <chn>. This functions
 * must be called to update the channel state. It also handles the fast
 * forwarding. */
static inline void channel_add_input(struct channel *chn, unsigned int len)
{
	if (chn->to_forward) {
		unsigned long fwd = len;
		if (chn->to_forward != CHN_INFINITE_FORWARD) {
			if (fwd > chn->to_forward)
				fwd = chn->to_forward;
			chn->to_forward -= fwd;
		}
		c_adv(chn, fwd);
	}
	/* notify that some data was read */
	chn->total += len;
	chn->flags |= CF_READ_PARTIAL;
}

static inline unsigned long long channel_htx_forward(struct channel *chn, struct htx *htx, unsigned long long bytes)
{
	unsigned long long ret = 0;

	if (htx->data) {
		b_set_data(&chn->buf, htx->data);
		ret = channel_forward(chn, bytes);
		b_set_data(&chn->buf, b_size(&chn->buf));
	}
	return ret;
}


static inline void channel_htx_forward_forever(struct channel *chn, struct htx *htx)
{
	c_adv(chn, htx->data - co_data(chn));
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
static inline unsigned int channel_is_empty(const struct channel *c)
{
	return !(co_data(c) | (long)c->pipe);
}

/* Returns non-zero if the channel is rewritable, which means that the buffer
 * it is attached to has at least <maxrewrite> bytes immediately available.
 * This is used to decide when a request or response may be parsed when some
 * data from a previous exchange might still be present.
 */
static inline int channel_is_rewritable(const struct channel *chn)
{
	int rem = chn->buf.size;

	rem -= b_data(&chn->buf);
	rem -= global.tune.maxrewrite;
	return rem >= 0;
}

/* Tells whether data are likely to leave the buffer. This is used to know when
 * we can safely ignore the reserve since we know we cannot retry a connection.
 * It returns zero if data are blocked, non-zero otherwise.
 */
static inline int channel_may_send(const struct channel *chn)
{
	return chn_cons(chn)->state == SI_ST_EST;
}

/* HTX version of channel_may_recv(). Returns non-zero if the channel can still
 * receive data. */
static inline int channel_htx_may_recv(const struct channel *chn, const struct htx *htx)
{
	uint32_t rem;

	if (!htx->size)
		return 1;

	rem = htx_free_data_space(htx);
	if (!rem)
		return 0; /* htx already full */

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
	rem += co_data(chn);
	if (rem > global.tune.maxrewrite)
		return 1;

	return (global.tune.maxrewrite - rem < chn->to_forward);
}

/* Returns non-zero if the channel can still receive data. This is used to
 * decide when to stop reading into a buffer when we want to ensure that we
 * leave the reserve untouched after all pending outgoing data are forwarded.
 * The reserved space is taken into account if ->to_forward indicates that an
 * end of transfer is close to happen. Note that both ->buf.o and ->to_forward
 * are considered as available since they're supposed to leave the buffer. The
 * test is optimized to avoid as many operations as possible for the fast case
 * and to be used as an "if" condition. Just like channel_recv_limit(), we
 * never allow to overwrite the reserve until the output stream interface is
 * connected, otherwise we could spin on a POST with http-send-name-header.
 */
static inline int channel_may_recv(const struct channel *chn)
{
	int rem = chn->buf.size;

	if (IS_HTX_STRM(chn_strm(chn)))
		return channel_htx_may_recv(chn, htxbuf(&chn->buf));

	if (b_is_null(&chn->buf))
		return 1;

	rem -= b_data(&chn->buf);
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
	rem = ci_data(chn) + global.tune.maxrewrite - chn->buf.size;
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
	chn->output = 0;
	b_reset(&chn->buf);
}

static inline void channel_htx_erase(struct channel *chn, struct htx *htx)
{
	htx_reset(htx);
	channel_erase(chn);
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
	reserve = chn->buf.size;
	if (b_is_null(&chn->buf))
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
	transit = co_data(chn) + chn->to_forward;
	reserve -= transit;
	if (transit < chn->to_forward ||                 // addition overflow
	    transit >= (unsigned)global.tune.maxrewrite) // enough transit data
		return chn->buf.size;
 end:
	return chn->buf.size - reserve;
}

/* HTX version of channel_recv_limit(). Return the max number of bytes the HTX
 * buffer can contain so that once all the pending bytes are forwarded, the
 * buffer still has global.tune.maxrewrite bytes free.
 */
static inline int channel_htx_recv_limit(const struct channel *chn, const struct htx *htx)
{
	unsigned int transit;
	int reserve;

	/* return zeor if not allocated */
	if (!htx->size)
		return 0;

	/* return max_data_space - maxrewrite if we can't send */
	reserve = global.tune.maxrewrite;
	if (unlikely(!channel_may_send(chn)))
		goto end;

	/* We need to check what remains of the reserve after o and to_forward
	 * have been transmitted, but they can overflow together and they can
	 * cause an integer underflow in the comparison since both are unsigned
	 * while maxrewrite is signed.
	 * The code below has been verified for being a valid check for this :
	 *   - if (o + to_forward) overflow => return htx->size  [ large enough ]
	 *   - if o + to_forward >= maxrw   => return htx->size  [ large enough ]
	 *   - otherwise return htx->size - (maxrw - (o + to_forward))
	 */
	transit = co_data(chn) + chn->to_forward;
	reserve -= transit;
	if (transit < chn->to_forward ||                 // addition overflow
	    transit >= (unsigned)global.tune.maxrewrite) // enough transit data
		return htx->size;
 end:
	return (htx->size - reserve);
}

/* HTX version of channel_full(). Instead of checking if INPUT data exceeds
 * (size - reserve), this function checks if the free space for data in <htx>
 * and the data scheduled for output are lower to the reserve. In such case, the
 * channel is considered as full.
 */
static inline int channel_htx_full(const struct channel *c, const struct htx *htx,
				   unsigned int reserve)
{
	if (!htx->size)
		return 0;
	return (htx_free_data_space(htx) + co_data(c) <= reserve);
}

/* Returns non-zero if the channel's INPUT buffer's is considered full, which
 * means that it holds at least as much INPUT data as (size - reserve). This
 * also means that data that are scheduled for output are considered as potential
 * free space, and that the reserved space is always considered as not usable.
 * This information alone cannot be used as a general purpose free space indicator.
 * However it accurately indicates that too many data were fed in the buffer
 * for an analyzer for instance. See the channel_may_recv() function for a more
 * generic function taking everything into account.
 */
static inline int channel_full(const struct channel *c, unsigned int reserve)
{
	if (b_is_null(&c->buf))
		return 0;

	if (IS_HTX_STRM(chn_strm(c)))
		return channel_htx_full(c, htxbuf(&c->buf), reserve);

	return (ci_data(c) + reserve >= c_size(c));
}

/* HTX version of channel_recv_max(). */
static inline int channel_htx_recv_max(const struct channel *chn, const struct htx *htx)
{
	int ret;

	ret = channel_htx_recv_limit(chn, htx) - htx_used_space(htx);
	if (ret < 0)
		ret = 0;
	return ret;
}

/* Returns the amount of space available at the input of the buffer, taking the
 * reserved space into account if ->to_forward indicates that an end of transfer
 * is close to happen. The test is optimized to avoid as many operations as
 * possible for the fast case.
 */
static inline int channel_recv_max(const struct channel *chn)
{
	int ret;

	if (IS_HTX_STRM(chn_strm(chn)))
		return channel_htx_recv_max(chn, htxbuf(&chn->buf));

	ret = channel_recv_limit(chn) - b_data(&chn->buf);
	if (ret < 0)
		ret = 0;
	return ret;
}

/* Returns the amount of bytes that can be written over the input data at once,
 * including reserved space which may be overwritten. This is used by Lua to
 * insert data in the input side just before the other data using buffer_replace().
 * The goal is to transfer these new data in the output buffer.
 */
static inline int ci_space_for_replace(const struct channel *chn)
{
	const struct buffer *buf = &chn->buf;
	const char *end;

	/* If the input side data overflows, we cannot insert data contiguously. */
	if (b_head(buf) + b_data(buf) >= b_wrap(buf))
		return 0;

	/* Check the last byte used in the buffer, it may be a byte of the output
	 * side if the buffer wraps, or its the end of the buffer.
	 */
	end = b_head(buf);
	if (end <= ci_head(chn))
		end = b_wrap(buf);

	/* Compute the amount of bytes which can be written. */
	return end - ci_tail(chn);
}

/* Allocates a buffer for channel <chn>. Returns 0 in case of failure, non-zero
 * otherwise.
 *
 * If no buffer are available, the requester, represented by <wait> pointer,
 * will be added in the list of objects waiting for an available buffer.
 */
static inline int channel_alloc_buffer(struct channel *chn, struct buffer_wait *wait)
{
	if (b_alloc(&chn->buf) != NULL)
		return 1;

	if (!LIST_INLIST(&wait->list))
		LIST_APPEND(&th_ctx->buffer_wq, &wait->list);

	return 0;
}

/* Releases a possibly allocated buffer for channel <chn>. If it was not
 * allocated, this function does nothing. Else the buffer is released and we try
 * to wake up as many streams/applets as possible. */
static inline void channel_release_buffer(struct channel *chn, struct buffer_wait *wait)
{
	if (c_size(chn) && c_empty(chn)) {
		b_free(&chn->buf);
		offer_buffers(wait->target, 1);
	}
}

/* Truncate any unread data in the channel's buffer, and disable forwarding.
 * Outgoing data are left intact. This is mainly to be used to send error
 * messages after existing data.
 */
static inline void channel_truncate(struct channel *chn)
{
	if (!co_data(chn))
		return channel_erase(chn);

	chn->to_forward = 0;
	if (!ci_data(chn))
		return;

	chn->buf.data = co_data(chn);
}

static inline void channel_htx_truncate(struct channel *chn, struct htx *htx)
{
	if (!co_data(chn))
		return channel_htx_erase(chn, htx);

	chn->to_forward = 0;
	if (htx->data == co_data(chn))
		return;
	htx_truncate(htx, co_data(chn));
}

/* This function realigns a possibly wrapping channel buffer so that the input
 * part is contiguous and starts at the beginning of the buffer and the output
 * part ends at the end of the buffer. This provides the best conditions since
 * it allows the largest inputs to be processed at once and ensures that once
 * the output data leaves, the whole buffer is available at once.
 */
static inline void channel_slow_realign(struct channel *chn, char *swap)
{
	return b_slow_realign(&chn->buf, swap, co_data(chn));
}


/* Forward all headers of an HTX message, starting from the SL to the EOH. This
 * function returns the position of the block after the EOH, if
 * found. Otherwise, it returns -1.
 */
static inline int32_t channel_htx_fwd_headers(struct channel *chn, struct htx *htx)
{
	int32_t pos;
	size_t  data = 0;

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		data += htx_get_blksz(blk);
		if (htx_get_blk_type(blk) == HTX_BLK_EOH) {
			pos = htx_get_next(htx, pos);
			break;
		}
	}
	c_adv(chn, data);
	return pos;
}

/*
 * Advance the channel buffer's read pointer by <len> bytes. This is useful
 * when data have been read directly from the buffer. It is illegal to call
 * this function with <len> causing a wrapping at the end of the buffer. It's
 * the caller's responsibility to ensure that <len> is never larger than
 * chn->o.
 */
static inline void co_skip(struct channel *chn, int len)
{
	b_del(&chn->buf, len);
	chn->output -= len;
	c_realign_if_empty(chn);
}

/* HTX version of co_skip(). This function skips at most <len> bytes from the
 * output of the channel <chn>. Depending on how data are stored in <htx> less
 * than <len> bytes can be skipped..
 */
static inline void co_htx_skip(struct channel *chn, struct htx *htx, int len)
{
	struct htx_ret htxret;

	htxret = htx_drain(htx, len);
	if (htxret.ret)
		chn->output -= htxret.ret;
}

/* Tries to copy chunk <chunk> into the channel's buffer after length controls.
 * The chn->o and to_forward pointers are updated. If the channel's input is
 * closed, -2 is returned. If the block is too large for this buffer, -3 is
 * returned. If there is not enough room left in the buffer, -1 is returned.
 * Otherwise the number of bytes copied is returned (0 being a valid number).
 * Channel flag READ_PARTIAL is updated if some data can be transferred. The
 * chunk's length is updated with the number of bytes sent.
 */
static inline int ci_putchk(struct channel *chn, struct buffer *chunk)
{
	int ret;

	ret = ci_putblk(chn, chunk->area, chunk->data);
	if (ret > 0)
		chunk->data -= ret;
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
static inline int ci_putstr(struct channel *chn, const char *str)
{
	return ci_putblk(chn, str, strlen(str));
}

/*
 * Return one char from the channel's buffer. If the buffer is empty and the
 * channel is closed, return -2. If the buffer is just empty, return -1. The
 * buffer's pointer is not advanced, it's up to the caller to call co_skip(buf,
 * 1) when it has consumed the char.  Also note that this function respects the
 * chn->o limit.
 */
static inline int co_getchr(struct channel *chn)
{
	/* closed or empty + imminent close = -2; empty = -1 */
	if (unlikely((chn->flags & CF_SHUTW) || channel_is_empty(chn))) {
		if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW))
			return -2;
		return -1;
	}
	return *co_head(chn);
}

/* Remove a block <blk> in a <htx> structure which is used by a channel <chn>
 * Update the channel output according to the size of the block removed
 * Return the size of the removed block*/
static inline int32_t co_htx_remove_blk(struct channel *chn, struct htx *htx, struct htx_blk *blk)
{
	int32_t size = htx_get_blksz(blk);

	htx_remove_blk(htx, blk);
	co_set_data(chn, co_data(chn) - size);

	return size;
}

#endif /* _HAPROXY_CHANNEL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
