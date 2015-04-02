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

#include <proto/queue.h>
#include <proto/server.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>


struct pool_head *pool2_pendconn;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_pendconn()
{
	pool2_pendconn = create_pool("pendconn", sizeof(struct pendconn), MEM_F_SHARED);
	return pool2_pendconn != NULL;
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

	if ((s->state == SRV_ST_STARTING) &&
	    now.tv_sec < s->last_change + s->slowstart &&
	    now.tv_sec >= s->last_change) {
		unsigned int ratio;
		ratio = 100 * (now.tv_sec - s->last_change) / s->slowstart;
		max = MAX(1, max * ratio / 100);
	}
	return max;
}


/*
 * Manages a server's connection queue. This function will try to dequeue as
 * many pending streams as possible, and wake them up.
 */
void process_srv_queue(struct server *s)
{
	struct proxy  *p = s->proxy;
	int maxconn;

	/* First, check if we can handle some connections queued at the proxy. We
	 * will take as many as we can handle.
	 */

	maxconn = srv_dynamic_maxconn(s);
	while (s->served < maxconn) {
		struct stream *strm = pendconn_get_next_strm(s, p);

		if (strm == NULL)
			break;
		task_wakeup(strm->task, TASK_WOKEN_RES);
	}
}

/* Detaches the next pending connection from either a server or a proxy, and
 * returns its associated stream. If no pending connection is found, NULL is
 * returned. Note that neither <srv> nor <px> may be NULL.
 * Priority is given to the oldest request in the queue if both <srv> and <px>
 * have pending requests. This ensures that no request will be left unserved.
 * The <px> queue is not considered if the server (or a tracked server) is not
 * RUNNING, is disabled, or has a null weight (server going down). The <srv>
 * queue is still considered in this case, because if some connections remain
 * there, it means that some requests have been forced there after it was seen
 * down (eg: due to option persist).
 * The stream is immediately marked as "assigned", and both its <srv> and
 * <srv_conn> are set to <srv>,
 */
struct stream *pendconn_get_next_strm(struct server *srv, struct proxy *px)
{
	struct pendconn *ps, *pp;
	struct stream *strm;
	struct server *rsrv;

	rsrv = srv->track;
	if (!rsrv)
		rsrv = srv;

	ps = pendconn_from_srv(srv);
	pp = pendconn_from_px(px);
	/* we want to get the definitive pendconn in <ps> */
	if (!pp || !srv_is_usable(rsrv)) {
		if (!ps)
			return NULL;
	} else {
		/* pendconn exists in the proxy queue */
		if (!ps || tv_islt(&pp->strm->logs.tv_request, &ps->strm->logs.tv_request))
			ps = pp;
	}
	strm = ps->strm;
	pendconn_free(ps);

	/* we want to note that the stream has now been assigned a server */
	strm->flags |= SF_ASSIGNED;
	strm->target = &srv->obj_type;
	stream_add_srv_conn(strm, srv);
	srv->served++;
	if (px->lbprm.server_take_conn)
		px->lbprm.server_take_conn(srv);

	return strm;
}

/* Adds the stream <strm> to the pending connection list of server <strm>->srv
 * or to the one of <strm>->proxy if srv is NULL. All counters and back pointers
 * are updated accordingly. Returns NULL if no memory is available, otherwise the
 * pendconn itself. If the stream was already marked as served, its flag is
 * cleared. It is illegal to call this function with a non-NULL strm->srv_conn.
 */
struct pendconn *pendconn_add(struct stream *strm)
{
	struct pendconn *p;
	struct server *srv;

	p = pool_alloc2(pool2_pendconn);
	if (!p)
		return NULL;

	strm->pend_pos = p;
	p->strm = strm;
	p->srv = srv = objt_server(strm->target);

	if (strm->flags & SF_ASSIGNED && srv) {
		LIST_ADDQ(&srv->pendconns, &p->list);
		srv->nbpend++;
		strm->logs.srv_queue_size += srv->nbpend;
		if (srv->nbpend > srv->counters.nbpend_max)
			srv->counters.nbpend_max = srv->nbpend;
	} else {
		LIST_ADDQ(&strm->be->pendconns, &p->list);
		strm->be->nbpend++;
		strm->logs.prx_queue_size += strm->be->nbpend;
		if (strm->be->nbpend > strm->be->be_counters.nbpend_max)
			strm->be->be_counters.nbpend_max = strm->be->nbpend;
	}
	strm->be->totpend++;
	return p;
}

/* Redistribute pending connections when a server goes down. The number of
 * connections redistributed is returned.
 */
int pendconn_redistribute(struct server *s)
{
	struct pendconn *pc, *pc_bck;
	int xferred = 0;

	list_for_each_entry_safe(pc, pc_bck, &s->pendconns, list) {
		struct stream *strm = pc->strm;

		if ((strm->be->options & (PR_O_REDISP|PR_O_PERSIST)) == PR_O_REDISP &&
		    !(strm->flags & SF_FORCE_PRST)) {
			/* The REDISP option was specified. We will ignore
			 * cookie and force to balance or use the dispatcher.
			 */

			/* it's left to the dispatcher to choose a server */
			strm->flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);

			pendconn_free(pc);
			task_wakeup(strm->task, TASK_WOKEN_RES);
			xferred++;
		}
	}
	return xferred;
}

/* Check for pending connections at the backend, and assign some of them to
 * the server coming up. The server's weight is checked before being assigned
 * connections it may not be able to handle. The total number of transferred
 * connections is returned.
 */
int pendconn_grab_from_px(struct server *s)
{
	int xferred;

	if (!srv_is_usable(s))
		return 0;

	for (xferred = 0; !s->maxconn || xferred < srv_dynamic_maxconn(s); xferred++) {
		struct stream *strm;
		struct pendconn *p;

		p = pendconn_from_px(s->proxy);
		if (!p)
			break;
		p->strm->target = &s->obj_type;
		strm = p->strm;
		pendconn_free(p);
		task_wakeup(strm->task, TASK_WOKEN_RES);
	}
	return xferred;
}

/*
 * Detaches pending connection <p>, decreases the pending count, and frees
 * the pending connection. The connection might have been queued to a specific
 * server as well as to the proxy. The stream also gets marked unqueued.
 */
void pendconn_free(struct pendconn *p)
{
	LIST_DEL(&p->list);
	p->strm->pend_pos = NULL;
	if (p->srv)
		p->srv->nbpend--;
	else
		p->strm->be->nbpend--;
	p->strm->be->totpend--;
	pool_free2(pool2_pendconn, p);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
