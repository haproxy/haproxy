/*
 * include/proto/queue.h
 * This file defines everything related to queues.
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

#ifndef _PROTO_QUEUE_H
#define _PROTO_QUEUE_H

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>

#include <types/proxy.h>
#include <types/queue.h>
#include <types/stream.h>
#include <types/server.h>
#include <types/task.h>

#include <proto/backend.h>

extern struct pool_head *pool_head_pendconn;

struct pendconn *pendconn_add(struct stream *strm);
int pendconn_dequeue(struct stream *strm);
void process_srv_queue(struct server *s);
unsigned int srv_dynamic_maxconn(const struct server *s);
int pendconn_redistribute(struct server *s);
int pendconn_grab_from_px(struct server *s);
void pendconn_unlink(struct pendconn *p);

/* Removes the pendconn from the server/proxy queue. It supports being called
 * with NULL for pendconn and with a pendconn not in the list. It is the
 * function to be used by default when unsure. Do not call it with server
 * or proxy locks held however.
 */
static inline void pendconn_cond_unlink(struct pendconn *p)
{
	if (p && p->node.node.leaf_p)
		pendconn_unlink(p);
}

/* Releases the pendconn associated to stream <s> if it has any, and decreases
 * the pending count if needed. The connection might have been queued to a
 * specific server as well as to the proxy. The stream also gets marked
 * unqueued.
 *
 * This function must be called by the stream itself, so in the context of
 * process_stream, without any lock held among the pendconn, the server's queue
 * nor the proxy's queue.
 */
static inline void pendconn_free(struct stream *s)
{
	struct pendconn *p = s->pend_pos;

	if (p) {
		pendconn_cond_unlink(p);
		s->pend_pos = NULL;
		pool_free(pool_head_pendconn, p);
	}
}

/* Returns 0 if all slots are full on a server, or 1 if there are slots available. */
static inline int server_has_room(const struct server *s) {
	return !s->maxconn || s->cur_sess < srv_dynamic_maxconn(s);
}

/* returns 0 if nothing has to be done for server <s> regarding queued connections,
 * and non-zero otherwise. If the server is down, we only check its own queue. Suited
 * for and if/else usage.
 */
static inline int may_dequeue_tasks(const struct server *s, const struct proxy *p) {
	return (s && (s->nbpend || (p->nbpend && srv_currently_usable(s))) &&
		(!s->maxconn || s->cur_sess < srv_dynamic_maxconn(s)));
}

static inline int queue_limit_class(int class)
{
	if (class < -0x7ff)
		return -0x7ff;
	if (class > 0x7ff)
		return 0x7ff;
	return class;
}

static inline int queue_limit_offset(int offset)
{
	if (offset < -0x7ffff)
		return -0x7ffff;
	if (offset > 0x7ffff)
		return 0x7ffff;
	return offset;
}


#endif /* _PROTO_QUEUE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
