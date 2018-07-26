/*
 * Queue management functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

/* Short explanation on the locking, which is far from being trivial : a
 * pendconn is a list element which necessarily is associated with an existing
 * stream. It has pendconn->strm always valid. A pendconn may only be in one of
 * these three states :
 *   - unlinked : in this case it is an empty list head ;
 *   - linked into the server's queue ;
 *   - linked into the proxy's queue.
 *
 * A stream does not necessarily have such a pendconn. Thus the pendconn is
 * designated by the stream->pend_pos pointer. This results in some properties :
 *   - pendconn->strm->pend_pos is never NULL for any valid pendconn
 *   - if LIST_ISEMPTY(pendconn->list) is true, the element is unlinked,
 *     otherwise it necessarily belongs to one of the other lists ; this may
 *     not be atomically checked under threads though ;
 *   - pendconn->px is never NULL if pendconn->list is not empty
 *   - pendconn->srv is never NULL if pendconn->list is in the server's queue,
 *     and is always NULL if pendconn->list is in the backend's queue or empty.
 *   - pendconn->target is NULL while the element is queued, and points to the
 *     assigned server when the pendconn is picked.
 *
 * Threads complicate the design a little bit but rules remain simple :
 *   - the server's queue lock must be held at least when manipulating the
 *     server's queue, which is when adding a pendconn to the queue and when
 *     removing a pendconn from the queue. It protects the queue's integrity.
 *
 *   - the proxy's queue lock must be held at least when manipulating the
 *     proxy's queue, which is when adding a pendconn to the queue and when
 *     removing a pendconn from the queue. It protects the queue's integrity.
 *
 *   - both locks are compatible and may be held at the same time.
 *
 *   - a pendconn_add() is only performed by the stream which will own the
 *     pendconn ; the pendconn is allocated at this moment and returned ; it is
 *     added to either the server or the proxy's queue while holding this
 *     queue's lock.
 *
 *   - the pendconn is then met by a thread walking over the proxy or server's
 *     queue with the respective lock held. This lock is exclusive and the
 *     pendconn can only appear in one queue so by definition a single thread
 *     may find this pendconn at a time.
 *
 *   - the pendconn is unlinked either by its own stream upon success/abort/
 *     free, or by another one offering it its server slot. This is achieved by
 *     pendconn_process_next_strm() under either the server or proxy's lock,
 *     pendconn_redistribute() under the server's lock, pendconn_grab_from_px()
 *     under the proxy's lock, or pendconn_unlink() under either the proxy's or
 *     the server's lock depending on the queue the pendconn is attached to.
 *
 *   - no single operation except the pendconn initialisation prior to the
 *     insertion are performed without eithre a queue lock held or the element
 *     being unlinked and visible exclusively to its stream.
 *
 *   - pendconn_grab_from_px() and pendconn_process_next_strm() assign ->target
 *     so that the stream knows what server to work with (via
 *     pendconn_dequeue() which sets it on strm->target).
 *
 *   - a pendconn doesn't switch between queues, it stays where it is.
 */

#include <common/config.h>
#include <common/memory.h>
#include <common/time.h>
#include <common/hathreads.h>

#include <proto/queue.h>
#include <proto/server.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>


struct pool_head *pool_head_pendconn;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_pendconn()
{
	pool_head_pendconn = create_pool("pendconn", sizeof(struct pendconn), MEM_F_SHARED);
	return pool_head_pendconn != NULL;
}

/* returns the effective dynamic maxconn for a server, considering the minconn
 * and the proxy's usage relative to its dynamic connections limit. It is
 * expected that 0 < s->minconn <= s->maxconn when this is called. If the
 * server is currently warming up, the slowstart is also applied to the
 * resulting value, which can be lower than minconn in this case, but never
 * less than 1.
 */
unsigned int srv_dynamic_maxconn(const struct server *s)
{
	unsigned int max;

	if (s->proxy->beconn >= s->proxy->fullconn)
		/* no fullconn or proxy is full */
		max = s->maxconn;
	else if (s->minconn == s->maxconn)
		/* static limit */
		max = s->maxconn;
	else max = MAX(s->minconn,
		       s->proxy->beconn * s->maxconn / s->proxy->fullconn);

	if ((s->cur_state == SRV_ST_STARTING) &&
	    now.tv_sec < s->last_change + s->slowstart &&
	    now.tv_sec >= s->last_change) {
		unsigned int ratio;
		ratio = 100 * (now.tv_sec - s->last_change) / s->slowstart;
		max = MAX(1, max * ratio / 100);
	}
	return max;
}

/* Remove the pendconn from the server/proxy queue. At this stage, the
 * connection is not really dequeued. It will be done during the
 * process_stream. It also decreases the pending count.
 *
 * The caller must own the lock on the queue containing the pendconn. The
 * pendconn must still be queued.
 */
static void __pendconn_unlink(struct pendconn *p)
{
	if (p->srv)
		p->srv->nbpend--;
	else
		p->px->nbpend--;
	HA_ATOMIC_SUB(&p->px->totpend, 1);
	LIST_DEL(&p->list);
	LIST_INIT(&p->list);
}

/* Locks the queue the pendconn element belongs to. This relies on both p->px
 * and p->srv to be properly initialized (which is always the case once the
 * element has been added).
 */
static inline void pendconn_queue_lock(struct pendconn *p)
{
	if (p->srv)
		HA_SPIN_LOCK(SERVER_LOCK, &p->srv->lock);
	else
		HA_SPIN_LOCK(PROXY_LOCK, &p->px->lock);
}

/* Unlocks the queue the pendconn element belongs to. This relies on both p->px
 * and p->srv to be properly initialized (which is always the case once the
 * element has been added).
 */
static inline void pendconn_queue_unlock(struct pendconn *p)
{
	if (p->srv)
		HA_SPIN_UNLOCK(SERVER_LOCK, &p->srv->lock);
	else
		HA_SPIN_UNLOCK(PROXY_LOCK, &p->px->lock);
}

/* Removes the pendconn from the server/proxy queue. At this stage, the
 * connection is not really dequeued. It will be done during process_stream().
 * This function takes all the required locks for the operation. The caller is
 * responsible for ensuring that <p> is valid and still in the queue. Use
 * pendconn_cond_unlink() if unsure. When the locks are already held, please
 * use __pendconn_unlink() instead.
 */
void pendconn_unlink(struct pendconn *p)
{
	pendconn_queue_lock(p);

	__pendconn_unlink(p);

	pendconn_queue_unlock(p);
}

/* Process the next pending connection from either a server or a proxy, and
 * returns a strictly positive value on success (see below). If no pending
 * connection is found, 0 is returned.  Note that neither <srv> nor <px> may be
 * NULL.  Priority is given to the oldest request in the queue if both <srv> and
 * <px> have pending requests. This ensures that no request will be left
 * unserved.  The <px> queue is not considered if the server (or a tracked
 * server) is not RUNNING, is disabled, or has a null weight (server going
 * down). The <srv> queue is still considered in this case, because if some
 * connections remain there, it means that some requests have been forced there
 * after it was seen down (eg: due to option persist).  The stream is
 * immediately marked as "assigned", and both its <srv> and <srv_conn> are set
 * to <srv>.
 *
 * This function must only be called if the server queue _AND_ the proxy queue
 * are locked. Today it is only called by process_srv_queue. When a pending
 * connection is dequeued, this function returns 1 if the pending connection can
 * be handled by the current thread, else it returns 2.
 */
static int pendconn_process_next_strm(struct server *srv, struct proxy *px)
{
	struct pendconn *p = NULL;
	struct server   *rsrv;

	rsrv = srv->track;
	if (!rsrv)
		rsrv = srv;

	p = NULL;
	if (srv->nbpend)
		p = LIST_ELEM(srv->pendconns.n, struct pendconn *, list);

	if (srv_currently_usable(rsrv) && px->nbpend) {
		struct pendconn *pp;

		pp = LIST_ELEM(px->pendconns.n, struct pendconn *, list);

		/* If the server pendconn is older than the proxy one,
		 * we process the server one.
		 */
		if (p && !tv_islt(&pp->strm->logs.tv_request, &p->strm->logs.tv_request))
			goto pendconn_found;

		/* Let's switch from the server pendconn to the proxy pendconn */
		p = pp;
		goto pendconn_found;
	}

	if (!p)
		return 0;

  pendconn_found:
	__pendconn_unlink(p);
	p->strm_flags |= SF_ASSIGNED;
	p->target = srv;

	HA_ATOMIC_ADD(&srv->served, 1);
	HA_ATOMIC_ADD(&srv->proxy->served, 1);
	if (px->lbprm.server_take_conn)
		px->lbprm.server_take_conn(srv);
	__stream_add_srv_conn(p->strm, srv);

	task_wakeup(p->strm->task, TASK_WOKEN_RES);

	return 1;
}

/* Manages a server's connection queue. This function will try to dequeue as
 * many pending streams as possible, and wake them up.
 */
void process_srv_queue(struct server *s)
{
	struct proxy  *p = s->proxy;
	int maxconn;

	HA_SPIN_LOCK(PROXY_LOCK,  &p->lock);
	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
	maxconn = srv_dynamic_maxconn(s);
	while (s->served < maxconn) {
		int ret = pendconn_process_next_strm(s, p);
		if (!ret)
			break;
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
	HA_SPIN_UNLOCK(PROXY_LOCK,  &p->lock);
}

/* Adds the stream <strm> to the pending connection list of server <strm>->srv
 * or to the one of <strm>->proxy if srv is NULL. All counters and back pointers
 * are updated accordingly. Returns NULL if no memory is available, otherwise the
 * pendconn itself. If the stream was already marked as served, its flag is
 * cleared. It is illegal to call this function with a non-NULL strm->srv_conn.
 *
 * This function must be called by the stream itself, so in the context of
 * process_stream.
 */
struct pendconn *pendconn_add(struct stream *strm)
{
	struct pendconn *p;
	struct proxy    *px;
	struct server   *srv;

	p = pool_alloc(pool_head_pendconn);
	if (!p)
		return NULL;

	if (strm->flags & SF_ASSIGNED)
		srv = objt_server(strm->target);
	else
		srv = NULL;

	px            = strm->be;
	p->target     = NULL;
	p->srv        = srv;
	p->px         = px;
	p->strm       = strm;
	p->strm_flags = strm->flags;

	pendconn_queue_lock(p);

	if (srv) {
		srv->nbpend++;
		strm->logs.srv_queue_size += srv->nbpend;
		if (srv->nbpend > srv->counters.nbpend_max)
			srv->counters.nbpend_max = srv->nbpend;
		LIST_ADDQ(&srv->pendconns, &p->list);
	}
	else {
		px->nbpend++;
		strm->logs.prx_queue_size += px->nbpend;
		if (px->nbpend > px->be_counters.nbpend_max)
			px->be_counters.nbpend_max = px->nbpend;
		LIST_ADDQ(&px->pendconns, &p->list);
	}
	strm->pend_pos = p;

	pendconn_queue_unlock(p);

	HA_ATOMIC_ADD(&px->totpend, 1);
	return p;
}

/* Redistribute pending connections when a server goes down. The number of
 * connections redistributed is returned.
 */
int pendconn_redistribute(struct server *s)
{
	struct pendconn *p, *pback;
	int xferred = 0;

	/* The REDISP option was specified. We will ignore cookie and force to
	 * balance or use the dispatcher. */
	if ((s->proxy->options & (PR_O_REDISP|PR_O_PERSIST)) != PR_O_REDISP)
		return 0;

	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
	list_for_each_entry_safe(p, pback, &s->pendconns, list) {
		if (p->strm_flags & SF_FORCE_PRST)
			continue;

		/* it's left to the dispatcher to choose a server */
		__pendconn_unlink(p);
		p->strm_flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);

		task_wakeup(p->strm->task, TASK_WOKEN_RES);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
	return xferred;
}

/* Check for pending connections at the backend, and assign some of them to
 * the server coming up. The server's weight is checked before being assigned
 * connections it may not be able to handle. The total number of transferred
 * connections is returned.
 */
int pendconn_grab_from_px(struct server *s)
{
	struct pendconn *p, *pback;
	int maxconn, xferred = 0;

	if (!srv_currently_usable(s))
		return 0;

	HA_SPIN_LOCK(PROXY_LOCK, &s->proxy->lock);
	maxconn = srv_dynamic_maxconn(s);
	list_for_each_entry_safe(p, pback, &s->proxy->pendconns, list) {
		if (s->maxconn && s->served + xferred >= maxconn)
			break;

		__pendconn_unlink(p);
		p->target = s;

		task_wakeup(p->strm->task, TASK_WOKEN_RES);
		xferred++;
	}
	HA_SPIN_UNLOCK(PROXY_LOCK, &s->proxy->lock);
	return xferred;
}

/* Try to dequeue pending connection attached to the stream <strm>. It must
 * always exists here. If the pendconn is still linked to the server or the
 * proxy queue, nothing is done and the function returns 1. Otherwise,
 * <strm>->flags and <strm>->target are updated, the pendconn is released and 0
 * is returned.
 *
 * This function must be called by the stream itself, so in the context of
 * process_stream.
 */
int pendconn_dequeue(struct stream *strm)
{
	struct pendconn *p;
	int is_unlinked;

	if (unlikely(!strm->pend_pos)) {
		/* unexpected case because it is called by the stream itself and
		 * only the stream can release a pendconn. So it is only
		 * possible if a pendconn is released by someone else or if the
		 * stream is supposed to be queued but without its associated
		 * pendconn. In both cases it is a bug! */
		abort();
	}
	p = strm->pend_pos;

	/* note below : we need to grab the queue's lock to check for emptiness
	 * because we don't want a partial _grab_from_px() or _redistribute()
	 * to be called in parallel and show an empty list without having the
	 * time to finish. With this we know that if we see the element
	 * unlinked, these functions were completely done.
	 */
	pendconn_queue_lock(p);
	is_unlinked = LIST_ISEMPTY(&p->list);
	pendconn_queue_unlock(p);

	if (!is_unlinked)
		return 1;

	/* the pendconn is not queued anymore and will not be so we're safe
	 * to proceed.
	 */
	if (p->target)
		strm->target = &p->target->obj_type;

	strm->flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);
	strm->flags |= p->strm_flags & (SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);
	strm->pend_pos = NULL;
	pool_free(pool_head_pendconn, p);
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
