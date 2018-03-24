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
 * process_stream. This function must be called by function owning the locks on
 * the pendconn _AND_ the server/proxy. It also decreases the pending count.
 *
 * The caller must own the lock on the pendconn _AND_ the queue containing the
 * pendconn. The pendconn must still be queued.
 */
static void pendconn_unlink(struct pendconn *p)
{
	if (p->srv)
		p->srv->nbpend--;
	else
		p->px->nbpend--;
	HA_ATOMIC_SUB(&p->px->totpend, 1);
	LIST_DEL(&p->list);
	LIST_INIT(&p->list);
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
	int remote;

	rsrv = srv->track;
	if (!rsrv)
		rsrv = srv;

	if (srv->nbpend) {
		list_for_each_entry(p, &srv->pendconns, list) {
			if (!HA_SPIN_TRYLOCK(PENDCONN_LOCK, &p->lock))
				goto ps_found;
		}
		p = NULL;
	}

  ps_found:
	if (srv_currently_usable(rsrv) && px->nbpend) {
		struct pendconn *pp;

		list_for_each_entry(pp, &px->pendconns, list) {
			/* If the server pendconn is older than the proxy one,
			 * we process the server one. */
			if (p && !tv_islt(&pp->strm->logs.tv_request, &p->strm->logs.tv_request))
				goto pendconn_found;

			if (!HA_SPIN_TRYLOCK(PENDCONN_LOCK, &pp->lock)) {
				/* Let's switch from the server pendconn to the
				 * proxy pendconn. Don't forget to unlock the
				 * server pendconn, if any. */
				if (p)
					HA_SPIN_UNLOCK(PENDCONN_LOCK, &p->lock);
				p = pp;
				goto pendconn_found;
			}
		}
	}

	if (!p)
		return 0;

  pendconn_found:
	pendconn_unlink(p);
	p->strm_flags |= SF_ASSIGNED;
	p->srv = srv;

	HA_ATOMIC_ADD(&srv->served, 1);
	HA_ATOMIC_ADD(&srv->proxy->served, 1);
	if (px->lbprm.server_take_conn)
		px->lbprm.server_take_conn(srv);
	__stream_add_srv_conn(p->strm, srv);

	remote = !(p->strm->task->thread_mask & tid_bit);
	task_wakeup(p->strm->task, TASK_WOKEN_RES);
	HA_SPIN_UNLOCK(PENDCONN_LOCK, &p->lock);

	/* Returns 1 if the current thread can process the stream, otherwise returns 2. */
	return remote ? 2 : 1;
}

/* Manages a server's connection queue. This function will try to dequeue as
 * many pending streams as possible, and wake them up.
 */
void process_srv_queue(struct server *s)
{
	struct proxy  *p = s->proxy;
	int maxconn, remote = 0;

	HA_SPIN_LOCK(PROXY_LOCK,  &p->lock);
	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
	maxconn = srv_dynamic_maxconn(s);
	while (s->served < maxconn) {
		int ret = pendconn_process_next_strm(s, p);
		if (!ret)
			break;
		remote |= (ret == 2);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
	HA_SPIN_UNLOCK(PROXY_LOCK,  &p->lock);

	if (remote)
		THREAD_WANT_SYNC();
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

	srv = objt_server(strm->target);
	px  = strm->be;

	p->srv        = NULL;
	p->px         = px;
	p->strm       = strm;
	p->strm_flags = strm->flags;
	HA_SPIN_INIT(&p->lock);

	if ((strm->flags & SF_ASSIGNED) && srv) {
		p->srv = srv;
		HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
		srv->nbpend++;
		strm->logs.srv_queue_size += srv->nbpend;
		if (srv->nbpend > srv->counters.nbpend_max)
			srv->counters.nbpend_max = srv->nbpend;
		LIST_ADDQ(&srv->pendconns, &p->list);
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	}
	else {
		HA_SPIN_LOCK(PROXY_LOCK, &px->lock);
		px->nbpend++;
		strm->logs.prx_queue_size += px->nbpend;
		if (px->nbpend > px->be_counters.nbpend_max)
			px->be_counters.nbpend_max = px->nbpend;
		LIST_ADDQ(&px->pendconns, &p->list);
		HA_SPIN_UNLOCK(PROXY_LOCK, &px->lock);
	}
	HA_ATOMIC_ADD(&px->totpend, 1);
	strm->pend_pos = p;
	return p;
}

/* Redistribute pending connections when a server goes down. The number of
 * connections redistributed is returned.
 */
int pendconn_redistribute(struct server *s)
{
	struct pendconn *p, *pback;
	int xferred = 0;
	int remote = 0;

	/* The REDISP option was specified. We will ignore cookie and force to
	 * balance or use the dispatcher. */
	if ((s->proxy->options & (PR_O_REDISP|PR_O_PERSIST)) != PR_O_REDISP)
		return 0;

	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
	list_for_each_entry_safe(p, pback, &s->pendconns, list) {
		if (p->strm_flags & SF_FORCE_PRST)
			continue;

		if (HA_SPIN_TRYLOCK(PENDCONN_LOCK, &p->lock))
			continue;

		/* it's left to the dispatcher to choose a server */
		pendconn_unlink(p);
		p->strm_flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);

		remote |= !(p->strm->task->thread_mask & tid_bit);
		task_wakeup(p->strm->task, TASK_WOKEN_RES);
		HA_SPIN_UNLOCK(PENDCONN_LOCK, &p->lock);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);

	if (remote)
		THREAD_WANT_SYNC();
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
	int remote = 0;

	if (!srv_currently_usable(s))
		return 0;

	HA_SPIN_LOCK(PROXY_LOCK, &s->proxy->lock);
	maxconn = srv_dynamic_maxconn(s);
	list_for_each_entry_safe(p, pback, &s->proxy->pendconns, list) {
		if (s->maxconn && s->served + xferred >= maxconn)
			break;

		if (HA_SPIN_TRYLOCK(PENDCONN_LOCK, &p->lock))
			continue;

		pendconn_unlink(p);
		p->srv = s;

		remote |= !(p->strm->task->thread_mask & tid_bit);
		task_wakeup(p->strm->task, TASK_WOKEN_RES);
		HA_SPIN_UNLOCK(PENDCONN_LOCK, &p->lock);
		xferred++;
	}
	HA_SPIN_UNLOCK(PROXY_LOCK, &s->proxy->lock);

	if (remote)
		THREAD_WANT_SYNC();
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

	if (unlikely(!strm->pend_pos)) {
		/* unexpected case because it is called by the stream itself and
		 * only the stream can release a pendconn. So it is only
		 * possible if a pendconn is released by someone else or if the
		 * stream is supposed to be queued but without its associated
		 * pendconn. In both cases it is a bug! */
		abort();
	}
	p = strm->pend_pos;
	HA_SPIN_LOCK(PENDCONN_LOCK, &p->lock);

	/* the pendconn is still linked to the server/proxy queue, so unlock it
	 * and go away. */
	if (!LIST_ISEMPTY(&p->list)) {
		HA_SPIN_UNLOCK(PENDCONN_LOCK, &p->lock);
		return 1;
	}

	/* the pendconn must be dequeued now */
	if (p->srv)
		strm->target = &p->srv->obj_type;

	strm->flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);
	strm->flags |= p->strm_flags & (SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);
	strm->pend_pos = NULL;
	HA_SPIN_UNLOCK(PENDCONN_LOCK, &p->lock);
	pool_free(pool_head_pendconn, p);
	return 0;
}

/* Release the pending connection <p>, and decreases the pending count if
 * needed. The connection might have been queued to a specific server as well as
 * to the proxy. The stream also gets marked unqueued. <p> must always be
 * defined here. So it is the caller responsibility to check its existance.
 *
 * This function must be called by the stream itself, so in the context of
 * process_stream.
 */
void pendconn_free(struct pendconn *p)
{
	struct stream *strm = p->strm;

	HA_SPIN_LOCK(PENDCONN_LOCK, &p->lock);

	/* The pendconn was already unlinked, just release it. */
	if (LIST_ISEMPTY(&p->list))
		goto release;

	if (p->srv) {
		HA_SPIN_LOCK(SERVER_LOCK, &p->srv->lock);
		p->srv->nbpend--;
		LIST_DEL(&p->list);
		HA_SPIN_UNLOCK(SERVER_LOCK, &p->srv->lock);
	}
	else {
		HA_SPIN_LOCK(PROXY_LOCK, &p->px->lock);
		p->px->nbpend--;
		LIST_DEL(&p->list);
		HA_SPIN_UNLOCK(PROXY_LOCK, &p->px->lock);
	}
	HA_ATOMIC_SUB(&p->px->totpend, 1);

  release:
	strm->pend_pos = NULL;
	HA_SPIN_UNLOCK(PENDCONN_LOCK, &p->lock);
	pool_free(pool_head_pendconn, p);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
