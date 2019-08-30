/*
 * include/types/ring.h
 * This file provides definitions for ring buffers used for disposable data.
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

#ifndef _TYPES_RING_H
#define _TYPES_RING_H

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/ist.h>

/* The code below handles circular buffers with single-producer and multiple
 * readers (up to 255). The buffer storage area must remain always allocated.
 * It's made of series of payload blocks followed by a readers count (RC).
 * There is always a readers count at the beginning of the buffer as well. Each
 * payload block is composed of a varint-encoded size (VI) followed by the
 * actual payload (PL).
 *
 * The readers count is encoded on a single byte. It indicates how many readers
 * are still waiting at this position. The writer writes after the buffer's
 * tail, which initially starts just past the first readers count. Then it
 * knows by reading this count that it must wake up the readers to indicate
 * data availability. When a reader reads the payload block, it increments the
 * next readers count and decrements the current one. The area between the
 * initial readers count and the next one is protected from overwriting for as
 * long as the initial count is non-null. As such these readers count are
 * effective barriers against data recycling.
 *
 * Only the writer is allowed to update the buffer's tail/head. This ensures
 * that events can remain as long as possible so that late readers can get the
 * maximum history available. It also helps dealing with multi-thread accesses
 * using a simple RW lock during the buffer head's manipulation. The writer
 * will have to delete some old records starting at the head until the new
 * message can fit or a non-null readers count is encountered. If a message
 * cannot fit due to insufficient room, the message is lost and the drop
 * counted must be incremented.
 *
 * Like any buffer, this buffer naturally wraps at the end and continues at the
 * beginning. The creation process consists in immediately adding a null
 * readers count byte into the buffer. The write process consists in always
 * writing a payload block followed by a new readers count. The delete process
 * consists in removing a null readers count and payload block. As such, there
 * is always at least one readers count byte in the buffer available at the
 * head for new readers to attach to, and one before the tail, both of which
 * may be the same when the buffer doesn't contain any event. It is thus safe
 * for any reader to simply keep the absolute offset of the last visited
 * position and to restart from there. The write will update the buffer's
 * absolute offset when deleting entries. All this also has the benefit of
 * allowing a buffer to be hot-resized without losing its contents.
 *
 * Thus we have this :
 *   - init of empty buffer:
 *        head-,     ,-tail
 *             [ RC | xxxxxxxxxxxxxxxxxxxxxxxxxx ]
 *
 *   - reader attached:
 *        head-,     ,-tail
 *             [ RC | xxxxxxxxxxxxxxxxxxxxxxxxxx ]
 *               ^- +1
 *
 *   - append of one event:
 *                      appended
 *        head-,      <---------->  ,-tail
 *             [ RC | VI | PL | RC | xxxxxxxxxxx ]
 *
 *   - reader advancing:
 *        head-,     ,-tail
 *             [ RC | VI | PL | RC | xxxxxxxxxxx ]
 *               ^- -1          ^- +1
 *
 *   - writer removing older message:
 *        head-,                    ,-tail
 *             [ xxxxxxxxxxxx | RC | xxxxxxxxxxx ]
 *               <---------->
 *                 removed
 */

struct ring {
	struct buffer buf;   // storage area
	size_t ofs;          // absolute offset in history of the buffer's head
	struct list waiters; // list of waiters, for now, CLI "show event"
	__decl_hathreads(HA_RWLOCK_T lock);
	int readers_count;
};

#endif /* _TYPES_RING_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
