/*
 * Queue management functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/time.h>
#include <common/tools.h>

#include <types/proxy.h>
#include <types/session.h>

#include <proto/queue.h>
#include <proto/server.h>
#include <proto/task.h>


void **pool_pendconn = NULL;

/* returns the effective dynamic maxconn for a server, considering the minconn
 * and the proxy's usage relative to its saturation.
 */
unsigned int srv_dynamic_maxconn(const struct server *s)
{
	return (s->proxy->beconn >= s->proxy->maxconn) ? s->maxconn :
		(s->minconn ? 
		 MAX(s->maxconn * s->proxy->beconn / s->proxy->maxconn, s->minconn)
		 : s->maxconn);
}


/*
 * Manages a server's connection queue. If woken up, will try to dequeue as
 * many pending sessions as possible, and wake them up. The task has nothing
 * else to do, so it always returns TIME_ETERNITY.
 */
int process_srv_queue(struct task *t)
{
	struct server *s = (struct server*)t->context;
	struct proxy  *p = s->proxy;
	int xferred;

	/* First, check if we can handle some connections queued at the proxy. We
	 * will take as many as we can handle.
	 */
	for (xferred = 0; s->cur_sess + xferred < srv_dynamic_maxconn(s); xferred++) {
		struct session *sess;

		sess = pendconn_get_next_sess(s, p);
		if (sess == NULL)
			break;
		task_wakeup(&rq, sess->task);
	}

	return TIME_ETERNITY;
}

/* Detaches the next pending connection from either a server or a proxy, and
 * returns its associated session. If no pending connection is found, NULL is
 * returned. Note that neither <srv> nor <px> can be NULL.
 */
struct session *pendconn_get_next_sess(struct server *srv, struct proxy *px)
{
	struct pendconn *p;
	struct session *sess;

	p = pendconn_from_srv(srv);
	if (!p) {
		p = pendconn_from_px(px);
		if (!p)
			return NULL;
		p->sess->srv = srv;
	}
	sess = p->sess;
	pendconn_free(p);
	return sess;
}

/* Adds the session <sess> to the pending connection list of server <sess>->srv
 * or to the one of <sess>->proxy if srv is NULL. All counters and back pointers
 * are updated accordingly. Returns NULL if no memory is available, otherwise the
 * pendconn itself.
 */
struct pendconn *pendconn_add(struct session *sess)
{
	struct pendconn *p;

	p = pool_alloc(pendconn);
	if (!p)
		return NULL;

	sess->pend_pos = p;
	p->sess = sess;
	p->srv  = sess->srv;
	if (sess->srv) {
		LIST_ADDQ(&sess->srv->pendconns, &p->list);
		sess->logs.srv_queue_size += sess->srv->nbpend;
		sess->srv->nbpend++;
		if (sess->srv->nbpend > sess->srv->nbpend_max)
			sess->srv->nbpend_max = sess->srv->nbpend;
	} else {
		LIST_ADDQ(&sess->be->beprm->pendconns, &p->list);
		sess->logs.prx_queue_size += sess->be->beprm->nbpend;
		sess->be->beprm->nbpend++;
		if (sess->be->beprm->nbpend > sess->be->beprm->nbpend_max)
			sess->be->beprm->nbpend_max = sess->be->beprm->nbpend;
	}
	sess->be->beprm->totpend++;
	return p;
}

/*
 * Detaches pending connection <p>, decreases the pending count, and frees
 * the pending connection. The connection might have been queued to a specific
 * server as well as to the proxy. The session also gets marked unqueued.
 */
void pendconn_free(struct pendconn *p)
{
	LIST_DEL(&p->list);
	p->sess->pend_pos = NULL;
	if (p->srv)
		p->srv->nbpend--;
	else
		p->sess->be->beprm->nbpend--;
	p->sess->be->beprm->totpend--;
	pool_free(pendconn, p);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
