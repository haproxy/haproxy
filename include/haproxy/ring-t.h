/*
 * include/haproxy/ring-t.h
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

#ifndef _HAPROXY_RING_T_H
#define _HAPROXY_RING_T_H

#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/thread.h>

/* The code below handles circular buffers with single-producer and multiple
 * readers (up to 254). The buffer storage area must remain always allocated.
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

/* ring watch flags to be used when watching the ring */
#define RING_WF_WAIT_MODE  0x00000001   /* wait for new contents */
#define RING_WF_SEEK_NEW   0x00000002   /* seek to new contents  */

/* ring flags */
#define RING_FL_MAPPED     0x00000001 /* mmapped area, must not free() */

/* keep values below in decimal, they may be dumped in error messages */
#define RING_WRITING_SIZE  255  /* the next message's size is being written */
#define RING_MAX_READERS   254  /* highest supported value for RC */

/* mask used to lock the tail */
#define RING_TAIL_LOCK     (1ULL << ((sizeof(size_t) * 8) - 1))

/* A cell describing a waiting thread.
 * ->next is initialized to 0x1 before the pointer is set, so that any
 * leader thread can see that the pointer is not set yet. This allows
 * to enqueue all waiting threads very quickly using XCHG() on the head
 * without having to rely on a flaky CAS, while threads finish their setup
 * in parallel. The pointer will turn to NULL again once the thread is
 * released.
 */
struct ring_wait_cell {
	size_t to_send_self;         // size needed to serialize this msg
	size_t needed_tot;           // size needed to serialize pending msgs
	size_t maxlen;               // msg truncated to this size
	const struct ist *pfx;       // prefixes
	size_t npfx;                 // #prefixes
	const struct ist *msg;       // message parts
	size_t nmsg;                 // #message parts
	struct ring_wait_cell *next; // next waiting thread
};

/* this is the mmapped part */
struct ring_storage {
	size_t size;         // storage size
	size_t rsvd;         // header length (used for file-backed maps)
	THREAD_PAD(64 - 2 * sizeof(size_t));
	size_t tail;         // storage tail
	THREAD_PAD(64 - sizeof(size_t));
	size_t head;         // storage head
	THREAD_PAD(64 - sizeof(size_t));
	char area[0];        // storage area begins immediately here
};

/* this is the ring definition, config, waiters etc */
struct ring {
	struct ring_storage *storage; // the mapped part
	struct mt_list waiters;       // list of waiters, for now, CLI "show event"
	int readers_count;
	uint flags;             // RING_FL_*
	uint pending;           // new writes that have not yet been subject to a wakeup
	uint waking;            // indicates a thread is currently waking up readers

	/* keep the queue in a separate cache line below */
	THREAD_PAD(64 - 3*sizeof(void*) - 4*sizeof(int));
	struct {
		struct ring_wait_cell *ptr;
		THREAD_PAD(64 - sizeof(void*));
	} queue[RING_WAIT_QUEUES + 1]; // wait queue + 1 spacer
};

#endif /* _HAPROXY_RING_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
