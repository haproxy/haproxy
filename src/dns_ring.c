/*
 * Ring buffer management
 * This is a fork of ring.c for DNS usage.
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
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/buf.h>
#include <haproxy/cli.h>
#include <haproxy/dns_ring.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/thread.h>

/* Initialize a pre-allocated ring with the buffer area
 * of size */
void dns_ring_init(struct dns_ring *ring, void *area, size_t size)
{
	HA_RWLOCK_INIT(&ring->lock);
	MT_LIST_INIT(&ring->waiters);
	ring->readers_count = 0;
	ring->buf = b_make(area, size, 0, 0);
	/* write the initial RC byte */
	b_putchr(&ring->buf, 0);
}

/* Creates and returns a ring buffer of size <size> bytes. Returns NULL on
 * allocation failure.
 */
struct dns_ring *dns_ring_new(size_t size)
{
	struct dns_ring *ring = NULL;
	void *area = NULL;

	if (size < 2)
		goto fail;

	ring = malloc(sizeof(*ring));
	if (!ring)
		goto fail;

	area = malloc(size);
	if (!area)
		goto fail;

	dns_ring_init(ring, area, size);
	return ring;
 fail:
	free(area);
	free(ring);
	return NULL;
}

/* destroys and frees ring <ring> */
void dns_ring_free(struct dns_ring *ring)
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
ssize_t dns_ring_write(struct dns_ring *ring, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg)
{
	struct buffer *buf = &ring->buf;
	struct appctx *appctx;
	size_t totlen = 0;
	size_t lenlen;
	uint64_t dellen;
	int dellenlen;
	struct mt_list back;
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

	HA_RWLOCK_WRLOCK(RING_LOCK, &ring->lock);
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

	*b_tail(buf) = 0; buf->data++; // new read counter
	sent = lenlen + totlen + 1;

	/* notify potential readers */
	MT_LIST_FOR_EACH_ENTRY_LOCKED(appctx, &ring->waiters, wait_entry, back)
		appctx_wakeup(appctx);

 done_buf:
	HA_RWLOCK_WRUNLOCK(RING_LOCK, &ring->lock);
	return sent;
}

/* Tries to attach appctx <appctx> as a new reader on ring <ring>. This is
 * meant to be used by low level appctx code such as CLI or ring forwarding.
 * For higher level functions, please see the relevant parts in appctx or CLI.
 * It returns non-zero on success or zero on failure if too many users are
 * already attached. On success, the caller MUST call dns_ring_detach_appctx()
 * to detach itself, even if it was never woken up.
 */
int dns_ring_attach(struct dns_ring *ring)
{
	int users = ring->readers_count;

	do {
		if (users >= 255)
			return 0;
	} while (!_HA_ATOMIC_CAS(&ring->readers_count, &users, users + 1));
	return 1;
}

/* detach an appctx from a ring. The appctx is expected to be waiting at offset
 * <ofs> relative to the beginning of the storage, or ~0 if not waiting yet.
 * Nothing is done if <ring> is NULL.
 */
void dns_ring_detach_appctx(struct dns_ring *ring, struct appctx *appctx, size_t ofs)
{
	if (!ring)
		return;

	HA_RWLOCK_WRLOCK(RING_LOCK, &ring->lock);
	if (ofs != ~0) {
		/* reader was still attached */
		if (ofs < b_head_ofs(&ring->buf))
			ofs += b_size(&ring->buf) - b_head_ofs(&ring->buf);
		else
			ofs -= b_head_ofs(&ring->buf);

		BUG_ON(ofs >= b_size(&ring->buf));
		MT_LIST_DELETE(&appctx->wait_entry);
		HA_ATOMIC_DEC(b_peek(&ring->buf, ofs));
	}
	HA_ATOMIC_DEC(&ring->readers_count);
	HA_RWLOCK_WRUNLOCK(RING_LOCK, &ring->lock);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
