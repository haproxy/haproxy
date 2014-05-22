/*
 * Map-based load-balancing (RR and HASH)
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <eb32tree.h>

#include <types/global.h>
#include <types/server.h>

#include <proto/backend.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/queue.h>

/* this function updates the map according to server <srv>'s new state */
static void map_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (srv_is_usable(srv))
		goto out_update_state;

	/* FIXME: could be optimized since we know what changed */
	recount_servers(p);
	update_backend_weight(p);
	p->lbprm.map.state |= LB_MAP_RECALC;
 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function updates the map according to server <srv>'s new state */
static void map_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (!srv_is_usable(srv))
		goto out_update_state;

	/* FIXME: could be optimized since we know what changed */
	recount_servers(p);
	update_backend_weight(p);
	p->lbprm.map.state |= LB_MAP_RECALC;
 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function recomputes the server map for proxy px. It relies on
 * px->lbprm.tot_wact, tot_wbck, tot_used, tot_weight, so it must be
 * called after recount_servers(). It also expects px->lbprm.map.srv
 * to be allocated with the largest size needed. It updates tot_weight.
 */
void recalc_server_map(struct proxy *px)
{
	int o, tot, flag;
	struct server *cur, *best;

	switch (px->lbprm.tot_used) {
	case 0:	/* no server */
		px->lbprm.map.state &= ~LB_MAP_RECALC;
		return;
	default:
		tot = px->lbprm.tot_weight;
		break;
	}

	/* here we *know* that we have some servers */
	if (px->srv_act)
		flag = 0;
	else
		flag = SRV_F_BACKUP;

	/* this algorithm gives priority to the first server, which means that
	 * it will respect the declaration order for equivalent weights, and
	 * that whatever the weights, the first server called will always be
	 * the first declared. This is an important asumption for the backup
	 * case, where we want the first server only.
	 */
	for (cur = px->srv; cur; cur = cur->next)
		cur->wscore = 0;

	for (o = 0; o < tot; o++) {
		int max = 0;
		best = NULL;
		for (cur = px->srv; cur; cur = cur->next) {
			if ((cur->flags & SRV_F_BACKUP) == flag &&
			    srv_is_usable(cur)) {
				int v;

				/* If we are forced to return only one server, we don't want to
				 * go further, because we would return the wrong one due to
				 * divide overflow.
				 */
				if (tot == 1) {
					best = cur;
					/* note that best->wscore will be wrong but we don't care */
					break;
				}

				cur->wscore += cur->eweight;
				v = (cur->wscore + tot) / tot; /* result between 0 and 3 */
				if (best == NULL || v > max) {
					max = v;
					best = cur;
				}
			}
		}
		px->lbprm.map.srv[o] = best;
		best->wscore -= tot;
	}
	px->lbprm.map.state &= ~LB_MAP_RECALC;
}

/* This function is responsible of building the server MAP for map-based LB
 * algorithms, allocating the map, and setting p->lbprm.wmult to the GCD of the
 * weights if applicable. It should be called only once per proxy, at config
 * time.
 */
void init_server_map(struct proxy *p)
{
	struct server *srv;
	int pgcd;
	int act, bck;

	p->lbprm.set_server_status_up   = map_set_server_status_up;
	p->lbprm.set_server_status_down = map_set_server_status_down;
	p->lbprm.update_server_eweight = NULL;
 
	if (!p->srv)
		return;

	/* We will factor the weights to reduce the table,
	 * using Euclide's largest common divisor algorithm.
	 * Since we may have zero weights, we have to first
	 * find a non-zero weight server.
	 */
	pgcd = 1;
	srv = p->srv;
	while (srv && !srv->uweight)
		srv = srv->next;

	if (srv) {
		pgcd = srv->uweight; /* note: cannot be zero */
		while (pgcd > 1 && (srv = srv->next)) {
			int w = srv->uweight;
			while (w) {
				int t = pgcd % w;
				pgcd = w;
				w = t;
			}
		}
	}

	/* It is sometimes useful to know what factor to apply
	 * to the backend's effective weight to know its real
	 * weight.
	 */
	p->lbprm.wmult = pgcd;

	act = bck = 0;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->eweight = (srv->uweight * p->lbprm.wdiv + p->lbprm.wmult - 1) / p->lbprm.wmult;
		srv_lb_commit_status(srv);

		if (srv->flags & SRV_F_BACKUP)
			bck += srv->eweight;
		else
			act += srv->eweight;
	}

	/* this is the largest map we will ever need for this servers list */
	if (act < bck)
		act = bck;

	if (!act)
		act = 1;

	p->lbprm.map.srv = (struct server **)calloc(act, sizeof(struct server *));
	/* recounts servers and their weights */
	p->lbprm.map.state = LB_MAP_RECALC;
	recount_servers(p);
	update_backend_weight(p);
	recalc_server_map(p);
}

/*
 * This function tries to find a running server with free connection slots for
 * the proxy <px> following the round-robin method.
 * If any server is found, it will be returned and px->lbprm.map.rr_idx will be updated
 * to point to the next server. If no valid server is found, NULL is returned.
 */
struct server *map_get_server_rr(struct proxy *px, struct server *srvtoavoid)
{
	int newidx, avoididx;
	struct server *srv, *avoided;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	if (px->lbprm.map.state & LB_MAP_RECALC)
		recalc_server_map(px);

	if (px->lbprm.map.rr_idx < 0 || px->lbprm.map.rr_idx >= px->lbprm.tot_weight)
		px->lbprm.map.rr_idx = 0;
	newidx = px->lbprm.map.rr_idx;

	avoided = NULL;
	avoididx = 0; /* shut a gcc warning */
	do {
		srv = px->lbprm.map.srv[newidx++];
		if (!srv->maxconn || (!srv->nbpend && srv->served < srv_dynamic_maxconn(srv))) {
			/* make sure it is not the server we are try to exclude... */
			if (srv != srvtoavoid) {
				px->lbprm.map.rr_idx = newidx;
				return srv;
			}

			avoided = srv;	/* ...but remember that is was selected yet avoided */
			avoididx = newidx;
		}
		if (newidx == px->lbprm.tot_weight)
			newidx = 0;
	} while (newidx != px->lbprm.map.rr_idx);

	if (avoided)
		px->lbprm.map.rr_idx = avoididx;

	/* return NULL or srvtoavoid if found */
	return avoided;
}

/*
 * This function returns the running server from the map at the location
 * pointed to by the result of a modulo operation on <hash>. The server map may
 * be recomputed if required before being looked up. If any server is found, it
 * will be returned.  If no valid server is found, NULL is returned.
 */
struct server *map_get_server_hash(struct proxy *px, unsigned int hash)
{
	if (px->lbprm.tot_weight == 0)
		return NULL;

	if (px->lbprm.map.state & LB_MAP_RECALC)
		recalc_server_map(px);

	return px->lbprm.map.srv[hash % px->lbprm.tot_weight];
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
