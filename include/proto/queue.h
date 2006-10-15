/*
  include/proto/queue.h
  This file defines everything related to queues.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_QUEUE_H
#define _PROTO_QUEUE_H

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>

#include <types/proxy.h>
#include <types/queue.h>
#include <types/session.h>
#include <types/server.h>
#include <types/task.h>

struct session *pendconn_get_next_sess(struct server *srv, struct proxy *px);
struct pendconn *pendconn_add(struct session *sess);
void pendconn_free(struct pendconn *p);
int process_srv_queue(struct task *t);
unsigned int srv_dynamic_maxconn(const struct server *s);



/* Returns the first pending connection for server <s>, which may be NULL if
 * nothing is pending.
 */
static inline struct pendconn *pendconn_from_srv(const struct server *s) {
	if (!s->nbpend)
		return NULL;

	return LIST_ELEM(s->pendconns.n, struct pendconn *, list);
}

/* Returns the first pending connection for proxy <px>, which may be NULL if
 * nothing is pending.
 */
static inline struct pendconn *pendconn_from_px(const struct proxy *px) {
	if (!px->nbpend)
		return NULL;

	return LIST_ELEM(px->pendconns.n, struct pendconn *, list);
}

/* returns 0 if nothing has to be done for server <s> regarding queued connections,
 * and non-zero otherwise. Suited for and if/else usage.
 */
static inline int may_dequeue_tasks(const struct server *s, const struct proxy *p) {
	return (s && (s->nbpend || p->nbpend) &&
		(!s->maxconn || s->cur_sess < srv_dynamic_maxconn(s)) &&
		s->queue_mgt);
}

#endif /* _PROTO_QUEUE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
