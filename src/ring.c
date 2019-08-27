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
#include <proto/ring.h>

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
	size_t totlen = 0;
	size_t lenlen;
	size_t dellen;
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
 done_buf:
	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);
	return sent;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
