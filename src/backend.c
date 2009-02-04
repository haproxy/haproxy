/*
 * Backend variables and functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/eb32tree.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/client.h>
#include <proto/fd.h>
#include <proto/httperr.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/queue.h>
#include <proto/session.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

#ifdef CONFIG_HAP_TCPSPLICE
#include <libtcpsplice.h>
#endif

static inline void fwrr_remove_from_tree(struct server *s);
static inline void fwrr_queue_by_weight(struct eb_root *root, struct server *s);
static inline void fwrr_dequeue_srv(struct server *s);
static void fwrr_get_srv(struct server *s);
static void fwrr_queue_srv(struct server *s);

/* This function returns non-zero if a server with the given weight and state
 * is usable for LB, otherwise zero.
 */
static inline int srv_is_usable(int state, int weight)
{
	if (!weight)
		return 0;
	if (state & SRV_GOINGDOWN)
		return 0;
	if (!(state & SRV_RUNNING))
		return 0;
	return 1;
}

/*
 * This function recounts the number of usable active and backup servers for
 * proxy <p>. These numbers are returned into the p->srv_act and p->srv_bck.
 * This function also recomputes the total active and backup weights. However,
 * it does not update tot_weight nor tot_used. Use update_backend_weight() for
 * this.
 */
static void recount_servers(struct proxy *px)
{
	struct server *srv;

	px->srv_act = px->srv_bck = 0;
	px->lbprm.tot_wact = px->lbprm.tot_wbck = 0;
	px->lbprm.fbck = NULL;
	for (srv = px->srv; srv != NULL; srv = srv->next) {
		if (!srv_is_usable(srv->state, srv->eweight))
			continue;

		if (srv->state & SRV_BACKUP) {
			if (!px->srv_bck &&
			    !(px->options & PR_O_USE_ALL_BK))
				px->lbprm.fbck = srv;
			px->srv_bck++;
			px->lbprm.tot_wbck += srv->eweight;
		} else {
			px->srv_act++;
			px->lbprm.tot_wact += srv->eweight;
		}
	}
}

/* This function simply updates the backend's tot_weight and tot_used values
 * after servers weights have been updated. It is designed to be used after
 * recount_servers() or equivalent.
 */
static void update_backend_weight(struct proxy *px)
{
	if (px->srv_act) {
		px->lbprm.tot_weight = px->lbprm.tot_wact;
		px->lbprm.tot_used   = px->srv_act;
	}
	else if (px->lbprm.fbck) {
		/* use only the first backup server */
		px->lbprm.tot_weight = px->lbprm.fbck->eweight;
		px->lbprm.tot_used = 1;
	}
	else {
		px->lbprm.tot_weight = px->lbprm.tot_wbck;
		px->lbprm.tot_used   = px->srv_bck;
	}
}

/* this function updates the map according to server <srv>'s new state */
static void map_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	if (srv_is_usable(srv->state, srv->eweight))
		goto out_update_state;

	/* FIXME: could be optimized since we know what changed */
	recount_servers(p);
	update_backend_weight(p);
	p->lbprm.map.state |= PR_MAP_RECALC;
 out_update_state:
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
}

/* This function updates the map according to server <srv>'s new state */
static void map_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	if (!srv_is_usable(srv->state, srv->eweight))
		goto out_update_state;

	/* FIXME: could be optimized since we know what changed */
	recount_servers(p);
	update_backend_weight(p);
	p->lbprm.map.state |= PR_MAP_RECALC;
 out_update_state:
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
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
		px->lbprm.map.state &= ~PR_MAP_RECALC;
		return;
	case 1: /* only one server, just fill first entry */
		tot = 1;
		break;
	default:
		tot = px->lbprm.tot_weight;
		break;
	}

	/* here we *know* that we have some servers */
	if (px->srv_act)
		flag = SRV_RUNNING;
	else
		flag = SRV_RUNNING | SRV_BACKUP;

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
			if (flag == (cur->state &
				     (SRV_RUNNING | SRV_GOINGDOWN | SRV_BACKUP))) {
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
	px->lbprm.map.state &= ~PR_MAP_RECALC;
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
	 * using Euclide's largest common divisor algorithm
	 */
	pgcd = p->srv->uweight;
	for (srv = p->srv->next; srv && pgcd > 1; srv = srv->next) {
		int w = srv->uweight;
		while (w) {
			int t = pgcd % w;
			pgcd = w;
			w = t;
		}
	}

	/* It is sometimes useful to know what factor to apply
	 * to the backend's effective weight to know its real
	 * weight.
	 */
	p->lbprm.wmult = pgcd;

	act = bck = 0;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->eweight = srv->uweight / pgcd;
		srv->prev_eweight = srv->eweight;
		srv->prev_state = srv->state;
		if (srv->state & SRV_BACKUP)
			bck += srv->eweight;
		else
			act += srv->eweight;
	}

	/* this is the largest map we will ever need for this servers list */
	if (act < bck)
		act = bck;

	p->lbprm.map.srv = (struct server **)calloc(act, sizeof(struct server *));
	/* recounts servers and their weights */
	p->lbprm.map.state = PR_MAP_RECALC;
	recount_servers(p);
	update_backend_weight(p);
	recalc_server_map(p);
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to down.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely down (the caller may not
 * know all the variables of a server's state).
 */
static void fwrr_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;
	struct fwrr_group *grp;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	if (srv_is_usable(srv->state, srv->eweight))
		goto out_update_state;

	if (!srv_is_usable(srv->prev_state, srv->prev_eweight))
		/* server was already down */
		goto out_update_backend;

	grp = (srv->state & SRV_BACKUP) ? &p->lbprm.fwrr.bck : &p->lbprm.fwrr.act;
	grp->next_weight -= srv->prev_eweight;

	if (srv->state & SRV_BACKUP) {
		p->lbprm.tot_wbck = p->lbprm.fwrr.bck.next_weight;
		p->srv_bck--;

		if (srv == p->lbprm.fbck) {
			/* we lost the first backup server in a single-backup
			 * configuration, we must search another one.
			 */
			struct server *srv2 = p->lbprm.fbck;
			do {
				srv2 = srv2->next;
			} while (srv2 &&
				 !((srv2->state & SRV_BACKUP) &&
				   srv_is_usable(srv2->state, srv2->eweight)));
			p->lbprm.fbck = srv2;
		}
	} else {
		p->lbprm.tot_wact = p->lbprm.fwrr.act.next_weight;
		p->srv_act--;
	}

	fwrr_dequeue_srv(srv);
	fwrr_remove_from_tree(srv);

out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to up.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely UP (the caller may not
 * know all the variables of a server's state). This function will not change
 * the weight of a server which was already up.
 */
static void fwrr_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;
	struct fwrr_group *grp;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	if (!srv_is_usable(srv->state, srv->eweight))
		goto out_update_state;

	if (srv_is_usable(srv->prev_state, srv->prev_eweight))
		/* server was already up */
		goto out_update_backend;

	grp = (srv->state & SRV_BACKUP) ? &p->lbprm.fwrr.bck : &p->lbprm.fwrr.act;
	grp->next_weight += srv->eweight;

	if (srv->state & SRV_BACKUP) {
		p->lbprm.tot_wbck = p->lbprm.fwrr.bck.next_weight;
		p->srv_bck++;

		if (!(p->options & PR_O_USE_ALL_BK)) {
			if (!p->lbprm.fbck) {
				/* there was no backup server anymore */
				p->lbprm.fbck = srv;
			} else {
				/* we may have restored a backup server prior to fbck,
				 * in which case it should replace it.
				 */
				struct server *srv2 = srv;
				do {
					srv2 = srv2->next;
				} while (srv2 && (srv2 != p->lbprm.fbck));
				if (srv2)
					p->lbprm.fbck = srv;
			}
		}
	} else {
		p->lbprm.tot_wact = p->lbprm.fwrr.act.next_weight;
		p->srv_act++;
	}

	/* note that eweight cannot be 0 here */
	fwrr_get_srv(srv);
	srv->npos = grp->curr_pos + (grp->next_weight + grp->curr_weight - grp->curr_pos) / srv->eweight;
	fwrr_queue_srv(srv);

out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
}

/* This function must be called after an update to server <srv>'s effective
 * weight. It may be called after a state change too.
 */
static void fwrr_update_server_weight(struct server *srv)
{
	int old_state, new_state;
	struct proxy *p = srv->proxy;
	struct fwrr_group *grp;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	/* If changing the server's weight changes its state, we simply apply
	 * the procedures we already have for status change. If the state
	 * remains down, the server is not in any tree, so it's as easy as
	 * updating its values. If the state remains up with different weights,
	 * there are some computations to perform to find a new place and
	 * possibly a new tree for this server.
	 */
	 
	old_state = srv_is_usable(srv->prev_state, srv->prev_eweight);
	new_state = srv_is_usable(srv->state, srv->eweight);

	if (!old_state && !new_state) {
		srv->prev_state = srv->state;
		srv->prev_eweight = srv->eweight;
		return;
	}
	else if (!old_state && new_state) {
		fwrr_set_server_status_up(srv);
		return;
	}
	else if (old_state && !new_state) {
		fwrr_set_server_status_down(srv);
		return;
	}

	grp = (srv->state & SRV_BACKUP) ? &p->lbprm.fwrr.bck : &p->lbprm.fwrr.act;
	grp->next_weight = grp->next_weight - srv->prev_eweight + srv->eweight;

	p->lbprm.tot_wact = p->lbprm.fwrr.act.next_weight;
	p->lbprm.tot_wbck = p->lbprm.fwrr.bck.next_weight;

	if (srv->lb_tree == grp->init) {
		fwrr_dequeue_srv(srv);
		fwrr_queue_by_weight(grp->init, srv);
	}
	else if (!srv->lb_tree) {
		/* FIXME: server was down. This is not possible right now but
		 * may be needed soon for slowstart or graceful shutdown.
		 */
		fwrr_dequeue_srv(srv);
		fwrr_get_srv(srv);
		srv->npos = grp->curr_pos + (grp->next_weight + grp->curr_weight - grp->curr_pos) / srv->eweight;
		fwrr_queue_srv(srv);
	} else {
		/* The server is either active or in the next queue. If it's
		 * still in the active queue and it has not consumed all of its
		 * places, let's adjust its next position.
		 */
		fwrr_get_srv(srv);

		if (srv->eweight > 0) {
			int prev_next = srv->npos;
			int step = grp->next_weight / srv->eweight;

			srv->npos = srv->lpos + step;
			srv->rweight = 0;

			if (srv->npos > prev_next)
				srv->npos = prev_next;
			if (srv->npos < grp->curr_pos + 2)
				srv->npos = grp->curr_pos + step;
		} else {
			/* push it into the next tree */
			srv->npos = grp->curr_pos + grp->curr_weight;
		}

		fwrr_dequeue_srv(srv);
		fwrr_queue_srv(srv);
	}

	update_backend_weight(p);
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
}

/* Remove a server from a tree. It must have previously been dequeued. This
 * function is meant to be called when a server is going down or has its
 * weight disabled.
 */
static inline void fwrr_remove_from_tree(struct server *s)
{
	s->lb_tree = NULL;
}

/* Queue a server in the weight tree <root>, assuming the weight is >0.
 * We want to sort them by inverted weights, because we need to place
 * heavy servers first in order to get a smooth distribution.
 */
static inline void fwrr_queue_by_weight(struct eb_root *root, struct server *s)
{
	s->lb_node.key = SRV_EWGHT_MAX - s->eweight;
	eb32_insert(root, &s->lb_node);
	s->lb_tree = root;
}

/* This function is responsible for building the weight trees in case of fast
 * weighted round-robin. It also sets p->lbprm.wdiv to the eweight to uweight
 * ratio. Both active and backup groups are initialized.
 */
void fwrr_init_server_groups(struct proxy *p)
{
	struct server *srv;
	struct eb_root init_head = EB_ROOT;

	p->lbprm.set_server_status_up   = fwrr_set_server_status_up;
	p->lbprm.set_server_status_down = fwrr_set_server_status_down;
	p->lbprm.update_server_eweight  = fwrr_update_server_weight;

	p->lbprm.wdiv = BE_WEIGHT_SCALE;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->prev_eweight = srv->eweight = srv->uweight * BE_WEIGHT_SCALE;
		srv->prev_state = srv->state;
	}

	recount_servers(p);
	update_backend_weight(p);

	/* prepare the active servers group */
	p->lbprm.fwrr.act.curr_pos = p->lbprm.fwrr.act.curr_weight =
		p->lbprm.fwrr.act.next_weight = p->lbprm.tot_wact;
	p->lbprm.fwrr.act.curr = p->lbprm.fwrr.act.t0 =
		p->lbprm.fwrr.act.t1 = init_head;
	p->lbprm.fwrr.act.init = &p->lbprm.fwrr.act.t0;
	p->lbprm.fwrr.act.next = &p->lbprm.fwrr.act.t1;

	/* prepare the backup servers group */
	p->lbprm.fwrr.bck.curr_pos = p->lbprm.fwrr.bck.curr_weight =
		p->lbprm.fwrr.bck.next_weight = p->lbprm.tot_wbck;
	p->lbprm.fwrr.bck.curr = p->lbprm.fwrr.bck.t0 =
		p->lbprm.fwrr.bck.t1 = init_head;
	p->lbprm.fwrr.bck.init = &p->lbprm.fwrr.bck.t0;
	p->lbprm.fwrr.bck.next = &p->lbprm.fwrr.bck.t1;

	/* queue active and backup servers in two distinct groups */
	for (srv = p->srv; srv; srv = srv->next) {
		if (!srv_is_usable(srv->state, srv->eweight))
			continue;
		fwrr_queue_by_weight((srv->state & SRV_BACKUP) ?
				p->lbprm.fwrr.bck.init :
				p->lbprm.fwrr.act.init,
				srv);
	}
}

/* simply removes a server from a weight tree */
static inline void fwrr_dequeue_srv(struct server *s)
{
	eb32_delete(&s->lb_node);
}

/* queues a server into the appropriate group and tree depending on its
 * backup status, and ->npos. If the server is disabled, simply assign
 * it to the NULL tree.
 */
static void fwrr_queue_srv(struct server *s)
{
	struct proxy *p = s->proxy;
	struct fwrr_group *grp;

	grp = (s->state & SRV_BACKUP) ? &p->lbprm.fwrr.bck : &p->lbprm.fwrr.act;
	
	/* Delay everything which does not fit into the window and everything
	 * which does not fit into the theorical new window.
	 */
	if (!srv_is_usable(s->state, s->eweight)) {
		fwrr_remove_from_tree(s);
	}
	else if (s->eweight <= 0 ||
		 s->npos >= 2 * grp->curr_weight ||
		 s->npos >= grp->curr_weight + grp->next_weight) {
		/* put into next tree, and readjust npos in case we could
		 * finally take this back to current. */
		s->npos -= grp->curr_weight;
		fwrr_queue_by_weight(grp->next, s);
	}
	else {
		/* The sorting key is stored in units of s->npos * user_weight
		 * in order to avoid overflows. As stated in backend.h, the
		 * lower the scale, the rougher the weights modulation, and the
		 * higher the scale, the lower the number of servers without
		 * overflow. With this formula, the result is always positive,
		 * so we can use eb3é_insert().
		 */
		s->lb_node.key = SRV_UWGHT_RANGE * s->npos +
			(unsigned)(SRV_EWGHT_MAX + s->rweight - s->eweight) / BE_WEIGHT_SCALE;

		eb32_insert(&grp->curr, &s->lb_node);
		s->lb_tree = &grp->curr;
	}
}

/* prepares a server when extracting it from the "init" tree */
static inline void fwrr_get_srv_init(struct server *s)
{
	s->npos = s->rweight = 0;
}

/* prepares a server when extracting it from the "next" tree */
static inline void fwrr_get_srv_next(struct server *s)
{
	struct fwrr_group *grp = (s->state & SRV_BACKUP) ?
		&s->proxy->lbprm.fwrr.bck :
		&s->proxy->lbprm.fwrr.act;

	s->npos += grp->curr_weight;
}

/* prepares a server when it was marked down */
static inline void fwrr_get_srv_down(struct server *s)
{
	struct fwrr_group *grp = (s->state & SRV_BACKUP) ?
		&s->proxy->lbprm.fwrr.bck :
		&s->proxy->lbprm.fwrr.act;

	s->npos = grp->curr_pos;
}

/* prepares a server when extracting it from its tree */
static void fwrr_get_srv(struct server *s)
{
	struct proxy *p = s->proxy;
	struct fwrr_group *grp = (s->state & SRV_BACKUP) ?
		&p->lbprm.fwrr.bck :
		&p->lbprm.fwrr.act;

	if (s->lb_tree == grp->init) {
		fwrr_get_srv_init(s);
	}
	else if (s->lb_tree == grp->next) {
		fwrr_get_srv_next(s);
	}
	else if (s->lb_tree == NULL) {
		fwrr_get_srv_down(s);
	}
}

/* switches trees "init" and "next" for FWRR group <grp>. "init" should be empty
 * when this happens, and "next" filled with servers sorted by weights.
 */
static inline void fwrr_switch_trees(struct fwrr_group *grp)
{
	struct eb_root *swap;
	swap = grp->init;
	grp->init = grp->next;
	grp->next = swap;
	grp->curr_weight = grp->next_weight;
	grp->curr_pos = grp->curr_weight;
}

/* return next server from the current tree in FWRR group <grp>, or a server
 * from the "init" tree if appropriate. If both trees are empty, return NULL.
 */
static struct server *fwrr_get_server_from_group(struct fwrr_group *grp)
{
	struct eb32_node *node;
	struct server *s;

	node = eb32_first(&grp->curr);
	s = eb32_entry(node, struct server, lb_node);
	
	if (!node || s->npos > grp->curr_pos) {
		/* either we have no server left, or we have a hole */
		struct eb32_node *node2;
		node2 = eb32_first(grp->init);
		if (node2) {
			node = node2;
			s = eb32_entry(node, struct server, lb_node);
			fwrr_get_srv_init(s);
			if (s->eweight == 0) /* FIXME: is it possible at all ? */
				node = NULL;
		}
	}
	if (node)
		return s;
	else
		return NULL;
}

/* Computes next position of server <s> in the group. It is mandatory for <s>
 * to have a non-zero, positive eweight.
*/
static inline void fwrr_update_position(struct fwrr_group *grp, struct server *s)
{
	if (!s->npos) {
		/* first time ever for this server */
		s->lpos = grp->curr_pos;
		s->npos = grp->curr_pos + grp->next_weight / s->eweight;
		s->rweight += grp->next_weight % s->eweight;

		if (s->rweight >= s->eweight) {
			s->rweight -= s->eweight;
			s->npos++;
		}
	} else {
		s->lpos = s->npos;
		s->npos += grp->next_weight / s->eweight;
		s->rweight += grp->next_weight % s->eweight;

		if (s->rweight >= s->eweight) {
			s->rweight -= s->eweight;
			s->npos++;
		}
	}
}

/* Return next server from the current tree in backend <p>, or a server from
 * the init tree if appropriate. If both trees are empty, return NULL.
 * Saturated servers are skipped and requeued.
 */
static struct server *fwrr_get_next_server(struct proxy *p, struct server *srvtoavoid)
{
	struct server *srv, *full, *avoided;
	struct fwrr_group *grp;
	int switched;

	if (p->srv_act)
		grp = &p->lbprm.fwrr.act;
	else if (p->lbprm.fbck)
		return p->lbprm.fbck;
	else if (p->srv_bck)
		grp = &p->lbprm.fwrr.bck;
	else
		return NULL;

	switched = 0;
	avoided = NULL;
	full = NULL; /* NULL-terminated list of saturated servers */
	while (1) {
		/* if we see an empty group, let's first try to collect weights
		 * which might have recently changed.
		 */
		if (!grp->curr_weight)
			grp->curr_pos = grp->curr_weight = grp->next_weight;

		/* get first server from the "current" tree. When the end of
		 * the tree is reached, we may have to switch, but only once.
		 */
		while (1) {
			srv = fwrr_get_server_from_group(grp);
			if (srv)
				break;
			if (switched) {
				if (avoided) {
					srv = avoided;
					break;
				}
				goto requeue_servers;
			}
			switched = 1;
			fwrr_switch_trees(grp);

		}

		/* OK, we have a server. However, it may be saturated, in which
		 * case we don't want to reconsider it for now. We'll update
		 * its position and dequeue it anyway, so that we can move it
		 * to a better place afterwards.
		 */
		fwrr_update_position(grp, srv);
		fwrr_dequeue_srv(srv);
		grp->curr_pos++;
		if (!srv->maxconn || (!srv->nbpend && srv->served < srv_dynamic_maxconn(srv))) {
			/* make sure it is not the server we are trying to exclude... */
			if (srv != srvtoavoid || avoided)
				break;

			avoided = srv; /* ...but remember that is was selected yet avoided */
		}

		/* the server is saturated or avoided, let's chain it for later reinsertion */
		srv->next_full = full;
		full = srv;
	}

	/* OK, we got the best server, let's update it */
	fwrr_queue_srv(srv);

 requeue_servers:
	/* Requeue all extracted servers. If full==srv then it was
	 * avoided (unsucessfully) and chained, omit it now.
	 */
	if (unlikely(full != NULL)) {
		if (switched) {
			/* the tree has switched, requeue all extracted servers
			 * into "init", because their place was lost, and only
			 * their weight matters.
			 */
			do {
				if (likely(full != srv))
					fwrr_queue_by_weight(grp->init, full);
				full = full->next_full;
			} while (full);
		} else {
			/* requeue all extracted servers just as if they were consumed
			 * so that they regain their expected place.
			 */
			do {
				if (likely(full != srv))
					fwrr_queue_srv(full);
				full = full->next_full;
			} while (full);
		}
	}
	return srv;
}

/* Remove a server from a tree. It must have previously been dequeued. This
 * function is meant to be called when a server is going down or has its
 * weight disabled.
 */
static inline void fwlc_remove_from_tree(struct server *s)
{
	s->lb_tree = NULL;
}

/* simply removes a server from a tree */
static inline void fwlc_dequeue_srv(struct server *s)
{
	eb32_delete(&s->lb_node);
}

/* Queue a server in its associated tree, assuming the weight is >0.
 * Servers are sorted by #conns/weight. To ensure maximum accuracy,
 * we use #conns*SRV_EWGHT_MAX/eweight as the sorting key.
 */
static inline void fwlc_queue_srv(struct server *s)
{
	s->lb_node.key = s->served * SRV_EWGHT_MAX / s->eweight;
	eb32_insert(s->lb_tree, &s->lb_node);
}

/* Re-position the server in the FWLC tree after it has been assigned one
 * connection or after it has released one. Note that it is possible that
 * the server has been moved out of the tree due to failed health-checks.
 */
static void fwlc_srv_reposition(struct server *s)
{
	if (!s->lb_tree)
		return;
	fwlc_dequeue_srv(s);
	fwlc_queue_srv(s);
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to down.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely down (the caller may not
 * know all the variables of a server's state).
 */
static void fwlc_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	if (srv_is_usable(srv->state, srv->eweight))
		goto out_update_state;

	if (!srv_is_usable(srv->prev_state, srv->prev_eweight))
		/* server was already down */
		goto out_update_backend;

	if (srv->state & SRV_BACKUP) {
		p->lbprm.tot_wbck -= srv->prev_eweight;
		p->srv_bck--;

		if (srv == p->lbprm.fbck) {
			/* we lost the first backup server in a single-backup
			 * configuration, we must search another one.
			 */
			struct server *srv2 = p->lbprm.fbck;
			do {
				srv2 = srv2->next;
			} while (srv2 &&
				 !((srv2->state & SRV_BACKUP) &&
				   srv_is_usable(srv2->state, srv2->eweight)));
			p->lbprm.fbck = srv2;
		}
	} else {
		p->lbprm.tot_wact -= srv->prev_eweight;
		p->srv_act--;
	}

	fwlc_dequeue_srv(srv);
	fwlc_remove_from_tree(srv);

out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to up.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely UP (the caller may not
 * know all the variables of a server's state). This function will not change
 * the weight of a server which was already up.
 */
static void fwlc_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	if (!srv_is_usable(srv->state, srv->eweight))
		goto out_update_state;

	if (srv_is_usable(srv->prev_state, srv->prev_eweight))
		/* server was already up */
		goto out_update_backend;

	if (srv->state & SRV_BACKUP) {
		srv->lb_tree = &p->lbprm.fwlc.bck;
		p->lbprm.tot_wbck += srv->eweight;
		p->srv_bck++;

		if (!(p->options & PR_O_USE_ALL_BK)) {
			if (!p->lbprm.fbck) {
				/* there was no backup server anymore */
				p->lbprm.fbck = srv;
			} else {
				/* we may have restored a backup server prior to fbck,
				 * in which case it should replace it.
				 */
				struct server *srv2 = srv;
				do {
					srv2 = srv2->next;
				} while (srv2 && (srv2 != p->lbprm.fbck));
				if (srv2)
					p->lbprm.fbck = srv;
			}
		}
	} else {
		srv->lb_tree = &p->lbprm.fwlc.act;
		p->lbprm.tot_wact += srv->eweight;
		p->srv_act++;
	}

	/* note that eweight cannot be 0 here */
	fwlc_queue_srv(srv);

 out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
}

/* This function must be called after an update to server <srv>'s effective
 * weight. It may be called after a state change too.
 */
static void fwlc_update_server_weight(struct server *srv)
{
	int old_state, new_state;
	struct proxy *p = srv->proxy;

	if (srv->state == srv->prev_state &&
	    srv->eweight == srv->prev_eweight)
		return;

	/* If changing the server's weight changes its state, we simply apply
	 * the procedures we already have for status change. If the state
	 * remains down, the server is not in any tree, so it's as easy as
	 * updating its values. If the state remains up with different weights,
	 * there are some computations to perform to find a new place and
	 * possibly a new tree for this server.
	 */
	 
	old_state = srv_is_usable(srv->prev_state, srv->prev_eweight);
	new_state = srv_is_usable(srv->state, srv->eweight);

	if (!old_state && !new_state) {
		srv->prev_state = srv->state;
		srv->prev_eweight = srv->eweight;
		return;
	}
	else if (!old_state && new_state) {
		fwlc_set_server_status_up(srv);
		return;
	}
	else if (old_state && !new_state) {
		fwlc_set_server_status_down(srv);
		return;
	}

	if (srv->lb_tree)
		fwlc_dequeue_srv(srv);

	if (srv->state & SRV_BACKUP) {
		p->lbprm.tot_wbck += srv->eweight - srv->prev_eweight;
		srv->lb_tree = &p->lbprm.fwlc.bck;
	} else {
		p->lbprm.tot_wact += srv->eweight - srv->prev_eweight;
		srv->lb_tree = &p->lbprm.fwlc.act;
	}

	fwlc_queue_srv(srv);

	update_backend_weight(p);
	srv->prev_state = srv->state;
	srv->prev_eweight = srv->eweight;
}

/* This function is responsible for building the trees in case of fast
 * weighted least-conns. It also sets p->lbprm.wdiv to the eweight to
 * uweight ratio. Both active and backup groups are initialized.
 */
void fwlc_init_server_tree(struct proxy *p)
{
	struct server *srv;
	struct eb_root init_head = EB_ROOT;

	p->lbprm.set_server_status_up   = fwlc_set_server_status_up;
	p->lbprm.set_server_status_down = fwlc_set_server_status_down;
	p->lbprm.update_server_eweight  = fwlc_update_server_weight;
	p->lbprm.server_take_conn = fwlc_srv_reposition;
	p->lbprm.server_drop_conn = fwlc_srv_reposition;

	p->lbprm.wdiv = BE_WEIGHT_SCALE;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->prev_eweight = srv->eweight = srv->uweight * BE_WEIGHT_SCALE;
		srv->prev_state = srv->state;
	}

	recount_servers(p);
	update_backend_weight(p);

	p->lbprm.fwlc.act = init_head;
	p->lbprm.fwlc.bck = init_head;

	/* queue active and backup servers in two distinct groups */
	for (srv = p->srv; srv; srv = srv->next) {
		if (!srv_is_usable(srv->state, srv->eweight))
			continue;
		srv->lb_tree = (srv->state & SRV_BACKUP) ? &p->lbprm.fwlc.bck : &p->lbprm.fwlc.act;
		fwlc_queue_srv(srv);
	}
}

/* Return next server from the FWLC tree in backend <p>. If the tree is empty,
 * return NULL. Saturated servers are skipped.
 */
static struct server *fwlc_get_next_server(struct proxy *p, struct server *srvtoavoid)
{
	struct server *srv, *avoided;
	struct eb32_node *node;

	srv = avoided = NULL;

	if (p->srv_act)
		node = eb32_first(&p->lbprm.fwlc.act);
	else if (p->lbprm.fbck)
		return p->lbprm.fbck;
	else if (p->srv_bck)
		node = eb32_first(&p->lbprm.fwlc.bck);
	else
		return NULL;

	while (node) {
		/* OK, we have a server. However, it may be saturated, in which
		 * case we don't want to reconsider it for now, so we'll simply
		 * skip it. Same if it's the server we try to avoid, in which
		 * case we simply remember it for later use if needed.
		 */
		struct server *s;

		s = eb32_entry(node, struct server, lb_node);
		if (!s->maxconn || (!s->nbpend && s->served < srv_dynamic_maxconn(s))) {
			if (s != srvtoavoid) {
				srv = s;
				break;
			}
			avoided = s;
		}
		node = eb32_next(node);
	}

	if (!srv)
		srv = avoided;

	return srv;
}

/* 
 * This function tries to find a running server for the proxy <px> following
 * the URL parameter hash method. It looks for a specific parameter in the
 * URL and hashes it to compute the server ID. This is useful to optimize
 * performance by avoiding bounces between servers in contexts where sessions
 * are shared but cookies are not usable. If the parameter is not found, NULL
 * is returned. If any server is found, it will be returned. If no valid server
 * is found, NULL is returned.
 */
struct server *get_server_ph(struct proxy *px, const char *uri, int uri_len)
{
	unsigned long hash = 0;
	const char *p;
	const char *params;
	int plen;

	/* when tot_weight is 0 then so is srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	if ((p = memchr(uri, '?', uri_len)) == NULL)
		return NULL;

	if (px->lbprm.map.state & PR_MAP_RECALC)
		recalc_server_map(px);

	p++;

	uri_len -= (p - uri);
	plen = px->url_param_len;
	params = p;

	while (uri_len > plen) {
		/* Look for the parameter name followed by an equal symbol */
		if (params[plen] == '=') {
			if (memcmp(params, px->url_param_name, plen) == 0) {
				/* OK, we have the parameter here at <params>, and
				 * the value after the equal sign, at <p>
				 * skip the equal symbol
				 */
				p += plen + 1;
				uri_len -= plen + 1;

				while (uri_len && *p != '&') {
					hash = *p + (hash << 6) + (hash << 16) - hash;
					uri_len--;
					p++;
				}
				return px->lbprm.map.srv[hash % px->lbprm.tot_weight];
			}
		}
		/* skip to next parameter */
		p = memchr(params, '&', uri_len);
		if (!p)
			return NULL;
		p++;
		uri_len -= (p - params);
		params = p;
	}
	return NULL;
}

/*
 * this does the same as the previous server_ph, but check the body contents
 */
struct server *get_server_ph_post(struct session *s)
{
	unsigned long    hash = 0;
	struct http_txn *txn  = &s->txn;
	struct buffer   *req  = s->req;
	struct http_msg *msg  = &txn->req;
	struct proxy    *px   = s->be;
	unsigned int     plen = px->url_param_len;
	unsigned long body;
	unsigned long len;
	const char *params;
	struct hdr_ctx ctx;
	const char   *p;

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

        body = msg->sol[msg->eoh] == '\r' ? msg->eoh + 2 : msg->eoh + 1;
        len  = req->l - body;
        params = req->data + body;

	if ( len == 0 )
		return NULL;

	if (px->lbprm.map.state & PR_MAP_RECALC)
		recalc_server_map(px);

	ctx.idx = 0;

	/* if the message is chunked, we skip the chunk size, but use the value as len */
	http_find_header2("Transfer-Encoding", 17, msg->sol, &txn->hdr_idx, &ctx);
	if (ctx.idx && ctx.vlen >= 7 && strncasecmp(ctx.line+ctx.val, "chunked", 7) == 0) {
		unsigned int chunk = 0;
		while ( params < (req->data+req->max_len) && !HTTP_IS_CRLF(*params)) {
			char c = *params;
			if (ishex(c)) {
				unsigned int hex = toupper(c) - '0';
				if ( hex > 9 )
					hex -= 'A' - '9' - 1;
				chunk = (chunk << 4) | hex;
			}
			else
				return NULL;
			params++;
			len--;
		}
		/* spec says we get CRLF */
		if (HTTP_IS_CRLF(*params) && HTTP_IS_CRLF(params[1]))
			params += 2;
		else
			return NULL;
		/* ok we have some encoded length, just inspect the first chunk */
		len = chunk;
	}

	p = params;

	while (len > plen) {
		/* Look for the parameter name followed by an equal symbol */
		if (params[plen] == '=') {
			if (memcmp(params, px->url_param_name, plen) == 0) {
				/* OK, we have the parameter here at <params>, and
				 * the value after the equal sign, at <p>
				 * skip the equal symbol
				 */
				p += plen + 1;
				len -= plen + 1;

				while (len && *p != '&') {
					if (unlikely(!HTTP_IS_TOKEN(*p))) {
					/* if in a POST, body must be URI encoded or its not a URI.
					 * Do not interprete any possible binary data as a parameter.
					 */
						if (likely(HTTP_IS_LWS(*p))) /* eol, uncertain uri len */
							break;
						return NULL;                 /* oh, no; this is not uri-encoded.
									      * This body does not contain parameters.
									      */
					}
					hash = *p + (hash << 6) + (hash << 16) - hash;
					len--;
					p++;
					/* should we break if vlen exceeds limit? */
				}
				return px->lbprm.map.srv[hash % px->lbprm.tot_weight];
			}
		}
		/* skip to next parameter */
		p = memchr(params, '&', len);
		if (!p)
			return NULL;
		p++;
		len -= (p - params);
		params = p;
	}
	return NULL;
}


/*
 * This function applies the load-balancing algorithm to the session, as
 * defined by the backend it is assigned to. The session is then marked as
 * 'assigned'.
 *
 * This function MAY NOT be called with SN_ASSIGNED already set. If the session
 * had a server previously assigned, it is rebalanced, trying to avoid the same
 * server.
 * The function tries to keep the original connection slot if it reconnects to
 * the same server, otherwise it releases it and tries to offer it.
 *
 * It is illegal to call this function with a session in a queue.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK. Session assigned to ->srv
 *   SRV_STATUS_NOSRV    if no server is available. Session is not ASSIGNED
 *   SRV_STATUS_FULL     if all servers are saturated. Session is not ASSIGNED
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ASSIGNED is set to indicate that
 * it does not need to be called anymore. This means that s->srv can be trusted
 * in balance and direct modes.
 *
 */

int assign_server(struct session *s)
{

	struct server *conn_slot;
	int err;

#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server : s=%p\n",s);
#endif

	err = SRV_STATUS_INTERNAL;
	if (unlikely(s->pend_pos || s->flags & SN_ASSIGNED))
		goto out_err;

	s->prev_srv = s->prev_srv;
	conn_slot = s->srv_conn;

	/* We have to release any connection slot before applying any LB algo,
	 * otherwise we may erroneously end up with no available slot.
	 */
	if (conn_slot)
		sess_change_server(s, NULL);

	/* We will now try to find the good server and store it into <s->srv>.
	 * Note that <s->srv> may be NULL in case of dispatch or proxy mode,
	 * as well as if no server is available (check error code).
	 */

	s->srv = NULL;
	if (s->be->lbprm.algo & BE_LB_ALGO) {
		int len;
		/* we must check if we have at least one server available */
		if (!s->be->lbprm.tot_weight) {
			err = SRV_STATUS_NOSRV;
			goto out;
		}

		switch (s->be->lbprm.algo & BE_LB_ALGO) {
		case BE_LB_ALGO_RR:
			s->srv = fwrr_get_next_server(s->be, s->prev_srv);
			if (!s->srv) {
				err = SRV_STATUS_FULL;
				goto out;
			}
			break;
		case BE_LB_ALGO_LC:
			s->srv = fwlc_get_next_server(s->be, s->prev_srv);
			if (!s->srv) {
				err = SRV_STATUS_FULL;
				goto out;
			}
			break;
		case BE_LB_ALGO_SH:
			if (s->cli_addr.ss_family == AF_INET)
				len = 4;
			else if (s->cli_addr.ss_family == AF_INET6)
				len = 16;
			else {
				/* unknown IP family */
				err = SRV_STATUS_INTERNAL;
				goto out;
			}
		
			s->srv = get_server_sh(s->be,
					       (void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
					       len);
			break;
		case BE_LB_ALGO_UH:
			/* URI hashing */
			s->srv = get_server_uh(s->be,
					       s->txn.req.sol + s->txn.req.sl.rq.u,
					       s->txn.req.sl.rq.u_l);
			break;
		case BE_LB_ALGO_PH:
			/* URL Parameter hashing */
			if (s->txn.meth == HTTP_METH_POST &&
			    memchr(s->txn.req.sol + s->txn.req.sl.rq.u, '&',
				   s->txn.req.sl.rq.u_l ) == NULL)
				s->srv = get_server_ph_post(s);
			else
				s->srv = get_server_ph(s->be,
						       s->txn.req.sol + s->txn.req.sl.rq.u,
						       s->txn.req.sl.rq.u_l);

			if (!s->srv) {
				/* parameter not found, fall back to round robin on the map */
				s->srv = get_server_rr_with_conns(s->be, s->prev_srv);
				if (!s->srv) {
					err = SRV_STATUS_FULL;
					goto out;
				}
			}
			break;
		default:
			/* unknown balancing algorithm */
			err = SRV_STATUS_INTERNAL;
			goto out;
		}
		if (s->srv != s->prev_srv) {
			s->be->cum_lbconn++;
			s->srv->cum_lbconn++;
		}
	}
	else if (s->be->options & PR_O_HTTP_PROXY) {
		if (!s->srv_addr.sin_addr.s_addr) {
			err = SRV_STATUS_NOSRV;
			goto out;
		}
	}
	else if (!*(int *)&s->be->dispatch_addr.sin_addr &&
		 !(s->be->options & PR_O_TRANSP)) {
		err = SRV_STATUS_NOSRV;
		goto out;
	}

	s->flags |= SN_ASSIGNED;
	err = SRV_STATUS_OK;
 out:

	/* Either we take back our connection slot, or we offer it to someone
	 * else if we don't need it anymore.
	 */
	if (conn_slot) {
		if (conn_slot == s->srv) {
			sess_change_server(s, s->srv);
		} else {
			if (may_dequeue_tasks(conn_slot, s->be))
				process_srv_queue(conn_slot);
		}
	}

 out_err:
	return err;
}


/*
 * This function assigns a server address to a session, and sets SN_ADDR_SET.
 * The address is taken from the currently assigned server, or from the
 * dispatch or transparent address.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ADDR_SET is set. This flag is
 * not cleared, so it's to the caller to clear it if required.
 *
 */
int assign_server_address(struct session *s)
{
#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server_address : s=%p\n",s);
#endif

	if ((s->flags & SN_DIRECT) || (s->be->lbprm.algo & BE_LB_ALGO)) {
		/* A server is necessarily known for this session */
		if (!(s->flags & SN_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		s->srv_addr = s->srv->addr;

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if (s->srv->state & SRV_MAPPORTS) {
			if (!(s->be->options & PR_O_TRANSP) && !(s->flags & SN_FRT_ADDR_SET))
				get_frt_addr(s);
			if (s->frt_addr.ss_family == AF_INET) {
				s->srv_addr.sin_port = htons(ntohs(s->srv_addr.sin_port) +
							     ntohs(((struct sockaddr_in *)&s->frt_addr)->sin_port));
			} else {
				s->srv_addr.sin_port = htons(ntohs(s->srv_addr.sin_port) +
							     ntohs(((struct sockaddr_in6 *)&s->frt_addr)->sin6_port));
			}
		}
	}
	else if (*(int *)&s->be->dispatch_addr.sin_addr) {
		/* connect to the defined dispatch addr */
		s->srv_addr = s->be->dispatch_addr;
	}
	else if (s->be->options & PR_O_TRANSP) {
		/* in transparent mode, use the original dest addr if no dispatch specified */
		if (!(s->flags & SN_FRT_ADDR_SET))
			get_frt_addr(s);

		memcpy(&s->srv_addr, &s->frt_addr, MIN(sizeof(s->srv_addr), sizeof(s->frt_addr)));
		/* when we support IPv6 on the backend, we may add other tests */
		//qfprintf(stderr, "Cannot get original server address.\n");
		//return SRV_STATUS_INTERNAL;
	}
	else if (s->be->options & PR_O_HTTP_PROXY) {
		/* If HTTP PROXY option is set, then server is already assigned
		 * during incoming client request parsing. */
	}
	else {
		/* no server and no LB algorithm ! */
		return SRV_STATUS_INTERNAL;
	}

	s->flags |= SN_ADDR_SET;
	return SRV_STATUS_OK;
}


/* This function assigns a server to session <s> if required, and can add the
 * connection to either the assigned server's queue or to the proxy's queue.
 * If ->srv_conn is set, the session is first released from the server.
 * It may also be called with SN_DIRECT and/or SN_ASSIGNED though. It will
 * be called before any connection and after any retry or redispatch occurs.
 *
 * It is not allowed to call this function with a session in a queue.
 *
 * Returns :
 *
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_NOSRV    if no server is available. s->srv = NULL.
 *   SRV_STATUS_QUEUED   if the connection has been queued.
 *   SRV_STATUS_FULL     if the server(s) is/are saturated and the
 *                       connection could not be queued in s->srv,
 *                       which may be NULL if we queue on the backend.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 */
int assign_server_and_queue(struct session *s)
{
	struct pendconn *p;
	int err;

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	err = SRV_STATUS_OK;
	if (!(s->flags & SN_ASSIGNED)) {
		err = assign_server(s);
		if (s->prev_srv) {
			/* This session was previously assigned to a server. We have to
			 * update the session's and the server's stats :
			 *  - if the server changed :
			 *    - set TX_CK_DOWN if txn.flags was TX_CK_VALID
			 *    - set SN_REDISP if it was successfully redispatched
			 *    - increment srv->redispatches and be->redispatches
			 *  - if the server remained the same : update retries.
			 */

			if (s->prev_srv != s->srv) {
				if ((s->txn.flags & TX_CK_MASK) == TX_CK_VALID) {
					s->txn.flags &= ~TX_CK_MASK;
					s->txn.flags |= TX_CK_DOWN;
				}
				s->flags |= SN_REDISP;
				s->prev_srv->redispatches++;
				s->be->redispatches++;
			} else {
				s->prev_srv->retries++;
				s->be->retries++;
			}
		}
	}

	switch (err) {
	case SRV_STATUS_OK:
		/* we have SN_ASSIGNED set */
		if (!s->srv)
			return SRV_STATUS_OK;   /* dispatch or proxy mode */

		/* If we already have a connection slot, no need to check any queue */
		if (s->srv_conn == s->srv)
			return SRV_STATUS_OK;

		/* OK, this session already has an assigned server, but no
		 * connection slot yet. Either it is a redispatch, or it was
		 * assigned from persistence information (direct mode).
		 */
		if ((s->flags & SN_REDIRECTABLE) && s->srv->rdr_len) {
			/* server scheduled for redirection, and already assigned. We
			 * don't want to go further nor check the queue.
			 */
			sess_change_server(s, s->srv); /* not really needed in fact */
			return SRV_STATUS_OK;
		}

		/* We might have to queue this session if the assigned server is full.
		 * We know we have to queue it into the server's queue, so if a maxqueue
		 * is set on the server, we must also check that the server's queue is
		 * not full, in which case we have to return FULL.
		 */
		if (s->srv->maxconn &&
		    (s->srv->nbpend || s->srv->served >= srv_dynamic_maxconn(s->srv))) {

			if (s->srv->maxqueue > 0 && s->srv->nbpend >= s->srv->maxqueue)
				return SRV_STATUS_FULL;

			p = pendconn_add(s);
			if (p)
				return SRV_STATUS_QUEUED;
			else
				return SRV_STATUS_INTERNAL;
		}

		/* OK, we can use this server. Let's reserve our place */
		sess_change_server(s, s->srv);
		return SRV_STATUS_OK;

	case SRV_STATUS_FULL:
		/* queue this session into the proxy's queue */
		p = pendconn_add(s);
		if (p)
			return SRV_STATUS_QUEUED;
		else
			return SRV_STATUS_INTERNAL;

	case SRV_STATUS_NOSRV:
		return err;

	case SRV_STATUS_INTERNAL:
		return err;

	default:
		return SRV_STATUS_INTERNAL;
	}
}

/*
 * This function initiates a connection to the server assigned to this session
 * (s->srv, s->srv_addr). It will assign a server if none is assigned yet.
 * It can return one of :
 *  - SN_ERR_NONE if everything's OK
 *  - SN_ERR_SRVTO if there are no more servers
 *  - SN_ERR_SRVCL if the connection was refused by the server
 *  - SN_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SN_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SN_ERR_INTERNAL for any other purely internal errors
 * Additionnally, in the case of SN_ERR_RESOURCE, an emergency log will be emitted.
 */
int connect_server(struct session *s)
{
	int fd, err;

	if (!(s->flags & SN_ADDR_SET)) {
		err = assign_server_address(s);
		if (err != SRV_STATUS_OK)
			return SN_ERR_INTERNAL;
	}

	if ((fd = s->req->cons->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		qfprintf(stderr, "Cannot get a server socket.\n");

		if (errno == ENFILE)
			send_log(s->be, LOG_EMERG,
				 "Proxy %s reached system FD limit at %d. Please check system tunables.\n",
				 s->be->id, maxfd);
		else if (errno == EMFILE)
			send_log(s->be, LOG_EMERG,
				 "Proxy %s reached process FD limit at %d. Please check 'ulimit-n' and restart.\n",
				 s->be->id, maxfd);
		else if (errno == ENOBUFS || errno == ENOMEM)
			send_log(s->be, LOG_EMERG,
				 "Proxy %s reached system memory limit at %d sockets. Please check system tunables.\n",
				 s->be->id, maxfd);
		/* this is a resource error */
		return SN_ERR_RESOURCE;
	}

	if (fd >= global.maxsock) {
		/* do not log anything there, it's a normal condition when this option
		 * is used to serialize connections to a server !
		 */
		Alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
		close(fd);
		return SN_ERR_PRXCOND; /* it is a configuration limit */
	}

#ifdef CONFIG_HAP_TCPSPLICE
	if ((global.tune.options & GTUNE_USE_SPLICE) &&
	    (s->fe->options & s->be->options) & PR_O_TCPSPLICE) {
		/* TCP splicing supported by both FE and BE */
		tcp_splice_initfd(s->req->prod->fd, fd);
	}
#endif

	if ((fcntl(fd, F_SETFL, O_NONBLOCK)==-1) ||
	    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1)) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(fd);
		return SN_ERR_INTERNAL;
	}

	if (s->be->options & PR_O_TCP_SRV_KA)
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

	if (s->be->options & PR_O_TCP_NOLING)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));

	/* allow specific binding :
	 * - server-specific at first
	 * - proxy-specific next
	 */
	if (s->srv != NULL && s->srv->state & SRV_BIND_SRC) {
		struct sockaddr_in *remote = NULL;
		int ret, flags = 0;

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
		switch (s->srv->state & SRV_TPROXY_MASK) {
		case SRV_TPROXY_ADDR:
			remote = (struct sockaddr_in *)&s->srv->tproxy_addr;
			flags  = 3;
			break;
		case SRV_TPROXY_CLI:
			flags |= 2;
			/* fall through */
		case SRV_TPROXY_CIP:
			/* FIXME: what can we do if the client connects in IPv6 ? */
			flags |= 1;
			remote = (struct sockaddr_in *)&s->cli_addr;
			break;
		}
#endif
		ret = tcpv4_bind_socket(fd, flags, &s->srv->source_addr, remote);
		if (ret) {
			close(fd);
			if (ret == 1) {
				Alert("Cannot bind to source address before connect() for server %s/%s. Aborting.\n",
				      s->be->id, s->srv->id);
				send_log(s->be, LOG_EMERG,
					 "Cannot bind to source address before connect() for server %s/%s.\n",
					 s->be->id, s->srv->id);
			} else {
				Alert("Cannot bind to tproxy source address before connect() for server %s/%s. Aborting.\n",
				      s->be->id, s->srv->id);
				send_log(s->be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for server %s/%s.\n",
					 s->be->id, s->srv->id);
			}
			return SN_ERR_RESOURCE;
		}
	}
	else if (s->be->options & PR_O_BIND_SRC) {
		struct sockaddr_in *remote = NULL;
		int ret, flags = 0;

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
		switch (s->be->options & PR_O_TPXY_MASK) {
		case PR_O_TPXY_ADDR:
			remote = (struct sockaddr_in *)&s->be->tproxy_addr;
			flags  = 3;
			break;
		case PR_O_TPXY_CLI:
			flags |= 2;
			/* fall through */
		case PR_O_TPXY_CIP:
			/* FIXME: what can we do if the client connects in IPv6 ? */
			flags |= 1;
			remote = (struct sockaddr_in *)&s->cli_addr;
			break;
		}
#endif
#ifdef SO_BINDTODEVICE
		/* Note: this might fail if not CAP_NET_RAW */
		if (s->be->iface_name)
			setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, s->be->iface_name, s->be->iface_len);
#endif
		ret = tcpv4_bind_socket(fd, flags, &s->be->source_addr, remote);
		if (ret) {
			close(fd);
			if (ret == 1) {
				Alert("Cannot bind to source address before connect() for proxy %s. Aborting.\n",
				      s->be->id);
				send_log(s->be, LOG_EMERG,
					 "Cannot bind to source address before connect() for proxy %s.\n",
					 s->be->id);
			} else {
				Alert("Cannot bind to tproxy source address before connect() for proxy %s. Aborting.\n",
				      s->be->id);
				send_log(s->be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for proxy %s.\n",
					 s->be->id);
			}
			return SN_ERR_RESOURCE;
		}
	}

	if ((connect(fd, (struct sockaddr *)&s->srv_addr, sizeof(s->srv_addr)) == -1) &&
	    (errno != EINPROGRESS) && (errno != EALREADY) && (errno != EISCONN)) {

		if (errno == EAGAIN || errno == EADDRINUSE) {
			char *msg;
			if (errno == EAGAIN) /* no free ports left, try again later */
				msg = "no free ports";
			else
				msg = "local address already in use";

			qfprintf(stderr,"Cannot connect: %s.\n",msg);
			close(fd);
			send_log(s->be, LOG_EMERG,
				 "Connect() failed for server %s/%s: %s.\n",
				 s->be->id, s->srv->id, msg);
			return SN_ERR_RESOURCE;
		} else if (errno == ETIMEDOUT) {
			//qfprintf(stderr,"Connect(): ETIMEDOUT");
			close(fd);
			return SN_ERR_SRVTO;
		} else {
			// (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EACCES || errno == EPERM)
			//qfprintf(stderr,"Connect(): %d", errno);
			close(fd);
			return SN_ERR_SRVCL;
		}
	}

	fdtab[fd].owner = s->req->cons;
	fdtab[fd].state = FD_STCONN; /* connection in progress */
	fdtab[fd].cb[DIR_RD].f = &stream_sock_read;
	fdtab[fd].cb[DIR_RD].b = s->rep;
	fdtab[fd].cb[DIR_WR].f = &stream_sock_write;
	fdtab[fd].cb[DIR_WR].b = s->req;

	fdtab[fd].peeraddr = (struct sockaddr *)&s->srv_addr;
	fdtab[fd].peerlen = sizeof(s->srv_addr);

	fd_insert(fd);
	EV_FD_SET(fd, DIR_WR);  /* for connect status */

	s->req->cons->state = SI_ST_CON;
	if (s->srv) {
		s->flags |= SN_CURR_SESS;
		s->srv->cur_sess++;
		if (s->srv->cur_sess > s->srv->cur_sess_max)
			s->srv->cur_sess_max = s->srv->cur_sess;
		if (s->be->lbprm.server_take_conn)
			s->be->lbprm.server_take_conn(s->srv);
	}

	s->req->wex = tick_add_ifset(now_ms, s->be->timeout.connect);
	return SN_ERR_NONE;  /* connection is OK */
}


/* This function performs the "redispatch" part of a connection attempt. It
 * will assign a server if required, queue the connection if required, and
 * handle errors that might arise at this level. It can change the server
 * state. It will return 1 if it encounters an error, switches the server
 * state, or has to queue a connection. Otherwise, it will return 0 indicating
 * that the connection is ready to use.
 */

int srv_redispatch_connect(struct session *t)
{
	int conn_err;

	/* We know that we don't have any connection pending, so we will
	 * try to get a new one, and wait in this state if it's queued
	 */
 redispatch:
	conn_err = assign_server_and_queue(t);
	switch (conn_err) {
	case SRV_STATUS_OK:
		break;

	case SRV_STATUS_FULL:
		/* The server has reached its maxqueue limit. Either PR_O_REDISP is set
		 * and we can redispatch to another server, or it is not and we return
		 * 503. This only makes sense in DIRECT mode however, because normal LB
		 * algorithms would never select such a server, and hash algorithms
		 * would bring us on the same server again. Note that t->srv is set in
		 * this case.
		 */
		if ((t->flags & SN_DIRECT) && (t->be->options & PR_O_REDISP)) {
			t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
			t->prev_srv = t->srv;
			goto redispatch;
		}

		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_QUEUE_ERR;
			t->req->cons->err_loc = t->srv;
		}

		t->srv->failed_conns++;
		t->be->failed_conns++;
		return 1;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that t->srv == NULL here */
		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_CONN_ERR;
			t->req->cons->err_loc = NULL;
		}

		t->be->failed_conns++;
		return 1;

	case SRV_STATUS_QUEUED:
		t->req->cons->exp = tick_add_ifset(now_ms, t->be->timeout.queue);
		t->req->cons->state = SI_ST_QUE;
		/* do nothing else and do not wake any other session up */
		return 1;

	case SRV_STATUS_INTERNAL:
	default:
		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_CONN_OTHER;
			t->req->cons->err_loc = t->srv;
		}

		if (t->srv)
			t->srv->cum_sess++;
		if (t->srv)
			t->srv->failed_conns++;
		t->be->failed_conns++;

		/* release other sessions waiting for this server */
		if (may_dequeue_tasks(t->srv, t->be))
			process_srv_queue(t->srv);
		return 1;
	}
	/* if we get here, it's because we got SRV_STATUS_OK, which also
	 * means that the connection has not been queued.
	 */
	return 0;
}

int be_downtime(struct proxy *px) {
	if (px->lbprm.tot_weight && px->last_change < now.tv_sec)  // ignore negative time
		return px->down_time;

	return now.tv_sec - px->last_change + px->down_time;
}

/* This function parses a "balance" statement in a backend section describing
 * <curproxy>. It returns -1 if there is any error, otherwise zero. If it
 * returns -1, it may write an error message into ther <err> buffer, for at
 * most <errlen> bytes, trailing zero included. The trailing '\n' will not be
 * written. The function must be called with <args> pointing to the first word
 * after "balance".
 */
int backend_parse_balance(const char **args, char *err, int errlen, struct proxy *curproxy)
{
	if (!*(args[0])) {
		/* if no option is set, use round-robin by default */
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
		return 0;
	}

	if (!strcmp(args[0], "roundrobin")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
	}
	else if (!strcmp(args[0], "leastconn")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_LC;
	}
	else if (!strcmp(args[0], "source")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SH;
	}
	else if (!strcmp(args[0], "uri")) {
		int arg = 1;

		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_UH;

		while (*args[arg]) {
			if (!strcmp(args[arg], "len")) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					snprintf(err, errlen, "'balance uri len' expects a positive integer (got '%s').", args[arg+1]);
					return -1;
				}
				curproxy->uri_len_limit = atoi(args[arg+1]);
				arg += 2;
			}
			else if (!strcmp(args[arg], "depth")) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					snprintf(err, errlen, "'balance uri depth' expects a positive integer (got '%s').", args[arg+1]);
					return -1;
				}
				/* hint: we store the position of the ending '/' (depth+1) so
				 * that we avoid a comparison while computing the hash.
				 */
				curproxy->uri_dirs_depth1 = atoi(args[arg+1]) + 1;
				arg += 2;
			}
			else {
				snprintf(err, errlen, "'balance uri' only accepts parameters 'len' and 'depth' (got '%s').", args[arg]);
				return -1;
			}
		}
	}
	else if (!strcmp(args[0], "url_param")) {
		if (!*args[1]) {
			snprintf(err, errlen, "'balance url_param' requires an URL parameter name.");
			return -1;
		}
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_PH;

		free(curproxy->url_param_name);
		curproxy->url_param_name = strdup(args[1]);
		curproxy->url_param_len  = strlen(args[1]);
		if (*args[2]) {
			if (strcmp(args[2], "check_post")) {
				snprintf(err, errlen, "'balance url_param' only accepts check_post modifier.");
				return -1;
			}
			if (*args[3]) {
				/* TODO: maybe issue a warning if there is no value, no digits or too long */
				curproxy->url_param_post_limit = str2ui(args[3]);
			}
			/* if no limit, or faul value in args[3], then default to a moderate wordlen */
			if (!curproxy->url_param_post_limit)
				curproxy->url_param_post_limit = 48;
			else if ( curproxy->url_param_post_limit < 3 )
				curproxy->url_param_post_limit = 3; /* minimum example: S=3 or \r\nS=6& */
		}
	}
	else {
		snprintf(err, errlen, "'balance' only supports 'roundrobin', 'leastconn', 'source', 'uri' and 'url_param' options.");
		return -1;
	}
	return 0;
}


/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* set test->i to the number of enabled servers on the proxy */
static int
acl_fetch_nbsrv(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_BE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	if (px->srv_act)
		test->i = px->srv_act;
	else if (px->lbprm.fbck)
		test->i = 1;
	else
		test->i = px->srv_bck;

	return 1;
}

/* set test->i to the number of enabled servers on the proxy */
static int
acl_fetch_connslots(struct proxy *px, struct session *l4, void *l7, int dir,
		    struct acl_expr *expr, struct acl_test *test)
{
	struct server *iterator;
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_BE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	test->i = 0;
	iterator = px->srv;
	while (iterator) {
		if ((iterator->state & 1) == 0) {
			iterator = iterator->next;
			continue;
		}
		if (iterator->maxconn == 0 || iterator->maxqueue == 0) {
			test->i = -1;
			return 1;
		}

		test->i += (iterator->maxconn - iterator->cur_sess)
			+  (iterator->maxqueue - iterator->nbpend);
		iterator = iterator->next;
	}

	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
	{ "nbsrv",    acl_parse_int,   acl_fetch_nbsrv,     acl_match_int, ACL_USE_NOTHING },
	{ "connlots", acl_parse_int,   acl_fetch_connslots, acl_match_int, ACL_USE_NOTHING },
	{ NULL, NULL, NULL, NULL },
}};


__attribute__((constructor))
static void __backend_init(void)
{
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
