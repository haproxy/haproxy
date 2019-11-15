/*
 * Ring buffer management
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#include <stdlib.h>
#include <common/buf.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/hathreads.h>
#include <types/applet.h>
#include <proto/cli.h>
#include <proto/ring.h>
#include <proto/stream_interface.h>

/* Creates and returns a ring buffer of size <size> bytes. Returns NULL on
 * allocation failure.
 */
struct ring *ring_new(size_t size)
{
	struct ring *ring = NULL;
	void *area = NULL;

	if (size < 2)
		goto fail;

	ring = malloc(sizeof(*ring));
	if (!ring)
		goto fail;

	area = malloc(size);
	if (!area)
		goto fail;

	HA_RWLOCK_INIT(&ring->lock);
	LIST_INIT(&ring->waiters);
	ring->readers_count = 0;
	ring->ofs = 0;
	ring->buf = b_make(area, size, 0, 0);
	/* write the initial RC byte */
	b_putchr(&ring->buf, 0);
	return ring;
 fail:
	free(area);
	free(ring);
	return NULL;
}

/* Resizes existing ring <ring> to <size> which must be larger, without losing
 * its contents. The new size must be at least as large as the previous one or
 * no change will be performed. The pointer to the ring is returned on success,
 * or NULL on allocation failure. This will lock the ring for writes.
 */
struct ring *ring_resize(struct ring *ring, size_t size)
{
	void *area;

	if (b_size(&ring->buf) >= size)
		return ring;

	area = malloc(size);
	if (!area)
		return NULL;

	HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);

	/* recheck the buffer's size, it may have changed during the malloc */
	if (b_size(&ring->buf) < size) {
		/* copy old contents */
		b_getblk(&ring->buf, area, ring->buf.data, 0);
		area = HA_ATOMIC_XCHG(&ring->buf.area, area);
		ring->buf.size = size;
		ring->buf.head = 0;
	}

	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);

	free(area);
	return ring;
}

/* destroys and frees ring <ring> */
void ring_free(struct ring *ring)
{
	if (!ring)
		return;
	free(ring->buf.area);
	free(ring);
}

/* Tries to send <npfx> parts from <prefix> followed by <nmsg> parts from <msg>
 * to ring <ring>. The message is sent atomically. It may be truncated to
 * <maxlen> bytes if <maxlen> is non-null. There is no distinction between the
 * two lists, it's just a convenience to help the caller prepend some prefixes
 * when necessary. It takes the ring's write lock to make sure no other thread
 * will touch the buffer during the update. Returns the number of bytes sent,
 * or <=0 on failure.
 */
ssize_t ring_write(struct ring *ring, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg)
{
	struct buffer *buf = &ring->buf;
	struct appctx *appctx;
	size_t totlen = 0;
	size_t lenlen;
	uint64_t dellen;
	int dellenlen;
	ssize_t sent = 0;
	int i;

	/* we have to find some room to add our message (the buffer is
	 * never empty and at least contains the previous counter) and
	 * to update both the buffer contents and heads at the same
	 * time (it's doable using atomic ops but not worth the
	 * trouble, let's just lock). For this we first need to know
	 * the total message's length. We cannot measure it while
	 * copying due to the varint encoding of the length.
	 */
	for (i = 0; i < npfx; i++)
		totlen += pfx[i].len;
	for (i = 0; i < nmsg; i++)
		totlen += msg[i].len;

	if (totlen > maxlen)
		totlen = maxlen;

	lenlen = varint_bytes(totlen);

	HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);
	if (lenlen + totlen + 1 + 1 > b_size(buf))
		goto done_buf;

	while (b_room(buf) < lenlen + totlen + 1) {
		/* we need to delete the oldest message (from the end),
		 * and we have to stop if there's a reader stuck there.
		 * Unless there's corruption in the buffer it's guaranteed
		 * that we have enough data to find 1 counter byte, a
		 * varint-encoded length (1 byte min) and the message
		 * payload (0 bytes min).
		 */
		if (*b_head(buf))
			goto done_buf;
		dellenlen = b_peek_varint(buf, 1, &dellen);
		if (!dellenlen)
			goto done_buf;
		BUG_ON(b_data(buf) < 1 + dellenlen + dellen);

		b_del(buf, 1 + dellenlen + dellen);
		ring->ofs += 1 + dellenlen + dellen;
	}

	/* OK now we do have room */
	__b_put_varint(buf, totlen);

	totlen = 0;
	for (i = 0; i < npfx; i++) {
		size_t len = pfx[i].len;

		if (len + totlen > maxlen)
			len = maxlen - totlen;
		if (len)
			__b_putblk(buf, pfx[i].ptr, len);
		totlen += len;
	}

	for (i = 0; i < nmsg; i++) {
		size_t len = msg[i].len;

		if (len + totlen > maxlen)
			len = maxlen - totlen;
		if (len)
			__b_putblk(buf, msg[i].ptr, len);
		totlen += len;
	}

	*b_tail(buf) = 0; buf->data++;; // new read counter
	sent = lenlen + totlen + 1;

	/* notify potential readers */
	list_for_each_entry(appctx, &ring->waiters, ctx.cli.l0)
		appctx_wakeup(appctx);

 done_buf:
	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);
	return sent;
}

/* Tries to attach CLI handler <appctx> as a new reader on ring <ring>. This is
 * meant to be used when registering a CLI function to dump a buffer, so it
 * returns zero on success, or non-zero on failure with a message in the appctx
 * CLI context. It automatically sets the io_handler and io_release callbacks if
 * they were not set.
 */
int ring_attach_cli(struct ring *ring, struct appctx *appctx)
{
	int users = ring->readers_count;

	do {
		if (users >= 255)
			return cli_err(appctx,
				       "Sorry, too many watchers (255) on this ring buffer. "
				       "What could it have so interesting to attract so many watchers ?");

	} while (!_HA_ATOMIC_CAS(&ring->readers_count, &users, users + 1));

	if (!appctx->io_handler)
		appctx->io_handler = cli_io_handler_show_ring;
	if (!appctx->io_release)
                appctx->io_release = cli_io_release_show_ring;
	appctx->ctx.cli.p0 = ring;
	appctx->ctx.cli.o0 = ~0; // start from the oldest event
	return 0;
}

/* This function dumps all events from the ring whose pointer is in <p0> into
 * the appctx's output buffer, and takes from <o0> the seek offset into the
 * buffer's history (0 for oldest known event). It looks at <i0> for boolean
 * options: bit0 means it must wait for new data or any key to be pressed. Bit1
 * means it must seek directly to the end to wait for new contents. It returns
 * 0 if the output buffer or events are missing is full and it needs to be
 * called again, otherwise non-zero. It is meant to be used with
 * cli_release_show_ring() to clean up.
 */
int cli_io_handler_show_ring(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct ring *ring = appctx->ctx.cli.p0;
	struct buffer *buf = &ring->buf;
	size_t ofs = appctx->ctx.cli.o0;
	uint64_t msg_len;
	size_t len, cnt;
	int ret;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	HA_RWLOCK_RDLOCK(LOGSRV_LOCK, &ring->lock);

	LIST_DEL_INIT(&appctx->ctx.cli.l0);

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(ofs == ~0)) {
		ofs = 0;

		/* going to the end means looking at tail-1 */
		if (appctx->ctx.cli.i0 & 2)
			ofs += b_data(buf) - 1;

		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
	}

	/* we were already there, adjust the offset to be relative to
	 * the buffer's head and remove us from the counter.
	 */
	ofs -= ring->ofs;
	BUG_ON(ofs >= buf->size);
	HA_ATOMIC_SUB(b_peek(buf, ofs), 1);

	/* in this loop, ofs always points to the counter byte that precedes
	 * the message so that we can take our reference there if we have to
	 * stop before the end (ret=0).
	 */
	ret = 1;
	while (ofs + 1 < b_data(buf)) {
		cnt = 1;
		len = b_peek_varint(buf, ofs + cnt, &msg_len);
		if (!len)
			break;
		cnt += len;
		BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));

		if (unlikely(msg_len + 1 > b_size(&trash))) {
			/* too large a message to ever fit, let's skip it */
			ofs += cnt + msg_len;
			continue;
		}

		chunk_reset(&trash);
		len = b_getblk(buf, trash.area, msg_len, ofs + cnt);
		trash.data += len;
		trash.area[trash.data++] = '\n';

		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			ret = 0;
			break;
		}
		ofs += cnt + msg_len;
	}

	HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
	ofs += ring->ofs;
	appctx->ctx.cli.o0 = ofs;
	HA_RWLOCK_RDUNLOCK(LOGSRV_LOCK, &ring->lock);

	if (ret && (appctx->ctx.cli.i0 & 1)) {
		/* we've drained everything and are configured to wait for more
		 * data or an event (keypress, close)
		 */
		if (!si_oc(si)->output && !(si_oc(si)->flags & CF_SHUTW)) {
			/* let's be woken up once new data arrive */
			LIST_ADDQ(&ring->waiters, &appctx->ctx.cli.l0);
			si_rx_endp_done(si);
			ret = 0;
		}
		/* always drain all the request */
		co_skip(si_oc(si), si_oc(si)->output);
	}
	return ret;
}

/* must be called after cli_io_handler_show_ring() above */
void cli_io_release_show_ring(struct appctx *appctx)
{
	struct ring *ring = appctx->ctx.cli.p0;
	size_t ofs = appctx->ctx.cli.o0;

	if (!ring)
		return;

	HA_RWLOCK_RDLOCK(LOGSRV_LOCK, &ring->lock);
	if (ofs != ~0) {
		/* reader was still attached */
		ofs -= ring->ofs;
		BUG_ON(ofs >= b_size(&ring->buf));
		LIST_DEL_INIT(&appctx->ctx.cli.l0);
		HA_ATOMIC_SUB(b_peek(&ring->buf, ofs), 1);
	}
	HA_ATOMIC_SUB(&ring->readers_count, 1);
	HA_RWLOCK_RDUNLOCK(LOGSRV_LOCK, &ring->lock);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
