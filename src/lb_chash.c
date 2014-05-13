/*
 * Consistent Hash implementation
 * Please consult this very well detailed article for more information :
 * http://www.spiteful.com/2008/03/17/programmers-toolbox-part-3-consistent-hashing/
 *
 * Our implementation has to support both weighted hashing and weighted round
 * robin because we'll use it to replace the previous map-based implementation
 * which offered both algorithms.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
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
#include <common/standard.h>
#include <eb32tree.h>

#include <types/global.h>
#include <types/server.h>

#include <proto/backend.h>
#include <proto/queue.h>

/* Return next tree node after <node> which must still be in the tree, or be
 * NULL. Lookup wraps around the end to the beginning. If the next node is the
 * same node, return NULL. This is designed to find a valid next node before
 * deleting one from the tree.
 */
static inline struct eb32_node *chash_skip_node(struct eb_root *root, struct eb32_node *node)
{
	struct eb32_node *stop = node;

	if (!node)
		return NULL;
	node = eb32_next(node);
	if (!node)
		node = eb32_first(root);
	if (node == stop)
		return NULL;
	return node;
}

/* Remove all of a server's entries from its tree. This may be used when
 * setting a server down.
 */
static inline void chash_dequeue_srv(struct server *s)
{
	while (s->lb_nodes_now > 0) {
		if (s->lb_nodes_now >= s->lb_nodes_tot) // should always be false anyway
			s->lb_nodes_now = s->lb_nodes_tot;
		s->lb_nodes_now--;
		if (s->proxy->lbprm.chash.last == &s->lb_nodes[s->lb_nodes_now].node)
			s->proxy->lbprm.chash.last = chash_skip_node(s->lb_tree, s->proxy->lbprm.chash.last);
		eb32_delete(&s->lb_nodes[s->lb_nodes_now].node);
	}
}

/* Adjust the number of entries of a server in its tree. The server must appear
 * as many times as its weight indicates it. If it's there too often, we remove
 * the last occurrences. If it's not there enough, we add more occurrences. To
 * remove a server from the tree, normally call this with eweight=0.
 */
static inline void chash_queue_dequeue_srv(struct server *s)
{
	while (s->lb_nodes_now > s->eweight) {
		if (s->lb_nodes_now >= s->lb_nodes_tot) // should always be false anyway
			s->lb_nodes_now = s->lb_nodes_tot;
		s->lb_nodes_now--;
		if (s->proxy->lbprm.chash.last == &s->lb_nodes[s->lb_nodes_now].node)
			s->proxy->lbprm.chash.last = chash_skip_node(s->lb_tree, s->proxy->lbprm.chash.last);
		eb32_delete(&s->lb_nodes[s->lb_nodes_now].node);
	}

	while (s->lb_nodes_now < s->eweight) {
		if (s->lb_nodes_now >= s->lb_nodes_tot) // should always be false anyway
			break;
		if (s->proxy->lbprm.chash.last == &s->lb_nodes[s->lb_nodes_now].node)
			s->proxy->lbprm.chash.last = chash_skip_node(s->lb_tree, s->proxy->lbprm.chash.last);
		eb32_insert(s->lb_tree, &s->lb_nodes[s->lb_nodes_now].node);
		s->lb_nodes_now++;
	}
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to down.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely down (the caller may not
 * know all the variables of a server's state).
 */
static void chash_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (srv_is_usable(srv))
		goto out_update_state;

	if (!srv_was_usable(srv))
		/* server was already down */
		goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
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
				 !((srv2->flags & SRV_F_BACKUP) &&
				   srv_is_usable(srv2)));
			p->lbprm.fbck = srv2;
		}
	} else {
		p->lbprm.tot_wact -= srv->prev_eweight;
		p->srv_act--;
	}

	chash_dequeue_srv(srv);

out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to up.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely UP (the caller may not
 * know all the variables of a server's state). This function will not change
 * the weight of a server which was already up.
 */
static void chash_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (!srv_is_usable(srv))
		goto out_update_state;

	if (srv_was_usable(srv))
		/* server was already up */
		goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
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
		p->lbprm.tot_wact += srv->eweight;
		p->srv_act++;
	}

	/* note that eweight cannot be 0 here */
	chash_queue_dequeue_srv(srv);

 out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function must be called after an update to server <srv>'s effective
 * weight. It may be called after a state change too.
 */
static void chash_update_server_weight(struct server *srv)
{
	int old_state, new_state;
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	/* If changing the server's weight changes its state, we simply apply
	 * the procedures we already have for status change. If the state
	 * remains down, the server is not in any tree, so it's as easy as
	 * updating its values. If the state remains up with different weights,
	 * there are some computations to perform to find a new place and
	 * possibly a new tree for this server.
	 */

	old_state = srv_was_usable(srv);
	new_state = srv_is_usable(srv);

	if (!old_state && !new_state) {
		srv_lb_commit_status(srv);
		return;
	}
	else if (!old_state && new_state) {
		chash_set_server_status_up(srv);
		return;
	}
	else if (old_state && !new_state) {
		chash_set_server_status_down(srv);
		return;
	}

	/* only adjust the server's presence in the tree */
	chash_queue_dequeue_srv(srv);

	if (srv->flags & SRV_F_BACKUP)
		p->lbprm.tot_wbck += srv->eweight - srv->prev_eweight;
	else
		p->lbprm.tot_wact += srv->eweight - srv->prev_eweight;

	update_backend_weight(p);
	srv_lb_commit_status(srv);
}

/*
 * This function returns the running server from the CHASH tree, which is at
 * the closest distance from the value of <hash>. Doing so ensures that even
 * with a well imbalanced hash, if some servers are close to each other, they
 * will still both receive traffic. If any server is found, it will be returned.
 * If no valid server is found, NULL is returned.
 */
struct server *chash_get_server_hash(struct proxy *p, unsigned int hash)
{
	struct eb32_node *next, *prev;
	struct server *nsrv, *psrv;
	struct eb_root *root;
	unsigned int dn, dp;

	if (p->srv_act)
		root = &p->lbprm.chash.act;
	else if (p->lbprm.fbck)
		return p->lbprm.fbck;
	else if (p->srv_bck)
		root = &p->lbprm.chash.bck;
	else
		return NULL;

	/* find the node after and the node before */
	next = eb32_lookup_ge(root, hash);
	if (!next)
		next = eb32_first(root);
	if (!next)
		return NULL; /* tree is empty */

	prev = eb32_prev(next);
	if (!prev)
		prev = eb32_last(root);

	nsrv = eb32_entry(next, struct tree_occ, node)->server;
	psrv = eb32_entry(prev, struct tree_occ, node)->server;
	if (nsrv == psrv)
		return nsrv;

	/* OK we're located between two distinct servers, let's
	 * compare distances between hash and the two servers
	 * and select the closest server.
	 */
	dp = hash - prev->key;
	dn = next->key - hash;

	return (dp <= dn) ? psrv : nsrv;
}

/* Return next server from the CHASH tree in backend <p>. If the tree is empty,
 * return NULL. Saturated servers are skipped.
 */
struct server *chash_get_next_server(struct proxy *p, struct server *srvtoavoid)
{
	struct server *srv, *avoided;
	struct eb32_node *node, *stop, *avoided_node;
	struct eb_root *root;

	srv = avoided = NULL;
	avoided_node = NULL;

	if (p->srv_act)
		root = &p->lbprm.chash.act;
	else if (p->lbprm.fbck)
		return p->lbprm.fbck;
	else if (p->srv_bck)
		root = &p->lbprm.chash.bck;
	else
		return NULL;

	stop = node = p->lbprm.chash.last;
	do {
		struct server *s;

		if (node)
			node = eb32_next(node);
		if (!node)
			node = eb32_first(root);

		p->lbprm.chash.last = node;
		if (!node)
			/* no node is available */
			return NULL;

		/* Note: if we came here after a down/up cycle with no last
		 * pointer, and after a redispatch (srvtoavoid is set), we
		 * must set stop to non-null otherwise we can loop forever.
		 */
		if (!stop)
			stop = node;

		/* OK, we have a server. However, it may be saturated, in which
		 * case we don't want to reconsider it for now, so we'll simply
		 * skip it. Same if it's the server we try to avoid, in which
		 * case we simply remember it for later use if needed.
		 */
		s = eb32_entry(node, struct tree_occ, node)->server;
		if (!s->maxconn || (!s->nbpend && s->served < srv_dynamic_maxconn(s))) {
			if (s != srvtoavoid) {
				srv = s;
				break;
			}
			avoided = s;
			avoided_node = node;
		}
	} while (node != stop);

	if (!srv) {
		srv = avoided;
		p->lbprm.chash.last = avoided_node;
	}

	return srv;
}

/* This function is responsible for building the active and backup trees for
 * constistent hashing. The servers receive an array of initialized nodes
 * with their assigned keys. It also sets p->lbprm.wdiv to the eweight to
 * uweight ratio.
 */
void chash_init_server_tree(struct proxy *p)
{
	struct server *srv;
	struct eb_root init_head = EB_ROOT;
	int node;

	p->lbprm.set_server_status_up   = chash_set_server_status_up;
	p->lbprm.set_server_status_down = chash_set_server_status_down;
	p->lbprm.update_server_eweight  = chash_update_server_weight;
	p->lbprm.server_take_conn = NULL;
	p->lbprm.server_drop_conn = NULL;

	p->lbprm.wdiv = BE_WEIGHT_SCALE;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->eweight = (srv->uweight * p->lbprm.wdiv + p->lbprm.wmult - 1) / p->lbprm.wmult;
		srv_lb_commit_status(srv);
	}

	recount_servers(p);
	update_backend_weight(p);

	p->lbprm.chash.act = init_head;
	p->lbprm.chash.bck = init_head;
	p->lbprm.chash.last = NULL;

	/* queue active and backup servers in two distinct groups */
	for (srv = p->srv; srv; srv = srv->next) {
		srv->lb_tree = (srv->flags & SRV_F_BACKUP) ? &p->lbprm.chash.bck : &p->lbprm.chash.act;
		srv->lb_nodes_tot = srv->uweight * BE_WEIGHT_SCALE;
		srv->lb_nodes_now = 0;
		srv->lb_nodes = (struct tree_occ *)calloc(srv->lb_nodes_tot, sizeof(struct tree_occ));

		for (node = 0; node < srv->lb_nodes_tot; node++) {
			srv->lb_nodes[node].server = srv;
			srv->lb_nodes[node].node.key = full_hash(srv->puid * SRV_EWGHT_RANGE + node);
		}

		if (srv_is_usable(srv))
			chash_queue_dequeue_srv(srv);
	}
}
