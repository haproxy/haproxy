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
 *
 * The server's lock and the lbprm's lock must be held.
 */
static inline void chash_queue_dequeue_srv(struct server *s)
{
	while (s->lb_nodes_now > s->next_eweight) {
		if (s->lb_nodes_now >= s->lb_nodes_tot) // should always be false anyway
			s->lb_nodes_now = s->lb_nodes_tot;
		s->lb_nodes_now--;
		if (s->proxy->lbprm.chash.last == &s->lb_nodes[s->lb_nodes_now].node)
			s->proxy->lbprm.chash.last = chash_skip_node(s->lb_tree, s->proxy->lbprm.chash.last);
		eb32_delete(&s->lb_nodes[s->lb_nodes_now].node);
	}

	/* Attempt to increase the total number of nodes, if the user
	 * increased the weight beyond the original weight
	 */
	if (s->lb_nodes_tot < s->next_eweight) {
		struct tree_occ *new_nodes;

		/* First we need to remove all server's entries from its tree
		 * because the realloc will change all nodes pointers */
		chash_dequeue_srv(s);

		new_nodes = realloc(s->lb_nodes, s->next_eweight * sizeof(*new_nodes));
		if (new_nodes) {
			unsigned int j;

			s->lb_nodes = new_nodes;
			memset(&s->lb_nodes[s->lb_nodes_tot], 0,
			    (s->next_eweight - s->lb_nodes_tot) * sizeof(*s->lb_nodes));
			for (j = s->lb_nodes_tot; j < s->next_eweight; j++) {
				s->lb_nodes[j].server = s;
				s->lb_nodes[j].node.key = full_hash(s->puid * SRV_EWGHT_RANGE + j);
			}
			s->lb_nodes_tot = s->next_eweight;
		}
	}
	while (s->lb_nodes_now < s->next_eweight) {
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
 *
 * The server's lock must be held. The lbprm lock will be used.
 */
static void chash_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
               return;

	HA_SPIN_LOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (srv_willbe_usable(srv))
		goto out_update_state;

	if (!srv_currently_usable(srv))
		/* server was already down */
		goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
		p->lbprm.tot_wbck -= srv->cur_eweight;
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
				   srv_willbe_usable(srv2)));
			p->lbprm.fbck = srv2;
		}
	} else {
		p->lbprm.tot_wact -= srv->cur_eweight;
		p->srv_act--;
	}

	chash_dequeue_srv(srv);

out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv_lb_commit_status(srv);

	HA_SPIN_UNLOCK(LBPRM_LOCK, &p->lbprm.lock);
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to up.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely UP (the caller may not
 * know all the variables of a server's state). This function will not change
 * the weight of a server which was already up.
 *
 * The server's lock must be held. The lbprm lock will be used.
 */
static void chash_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
               return;

	HA_SPIN_LOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (!srv_willbe_usable(srv))
		goto out_update_state;

	if (srv_currently_usable(srv))
		/* server was already up */
		goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
		p->lbprm.tot_wbck += srv->next_eweight;
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
		p->lbprm.tot_wact += srv->next_eweight;
		p->srv_act++;
	}

	/* note that eweight cannot be 0 here */
	chash_queue_dequeue_srv(srv);

 out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
 out_update_state:
	srv_lb_commit_status(srv);

	HA_SPIN_UNLOCK(LBPRM_LOCK, &p->lbprm.lock);
}

/* This function must be called after an update to server <srv>'s effective
 * weight. It may be called after a state change too.
 *
 * The server's lock must be held. The lbprm lock may be used.
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

	old_state = srv_currently_usable(srv);
	new_state = srv_willbe_usable(srv);

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

	HA_SPIN_LOCK(LBPRM_LOCK, &p->lbprm.lock);

	/* only adjust the server's presence in the tree */
	chash_queue_dequeue_srv(srv);

	if (srv->flags & SRV_F_BACKUP)
		p->lbprm.tot_wbck += srv->next_eweight - srv->cur_eweight;
	else
		p->lbprm.tot_wact += srv->next_eweight - srv->cur_eweight;

	update_backend_weight(p);
	srv_lb_commit_status(srv);

	HA_SPIN_UNLOCK(LBPRM_LOCK, &p->lbprm.lock);
}

/*
 * This function implements the "Consistent Hashing with Bounded Loads" algorithm
 * of Mirrokni, Thorup, and Zadimoghaddam (arxiv:1608.01350), adapted for use with
 * unequal server weights.
 */
int chash_server_is_eligible(struct server *s)
{
	/* The total number of slots to allocate is the total number of outstanding requests
	 * (including the one we're about to make) times the load-balance-factor, rounded up.
	 */
	unsigned tot_slots = ((s->proxy->served + 1) * s->proxy->lbprm.hash_balance_factor + 99) / 100;
	unsigned slots_per_weight = tot_slots / s->proxy->lbprm.tot_weight;
	unsigned remainder = tot_slots % s->proxy->lbprm.tot_weight;

	/* Allocate a whole number of slots per weight unit... */
	unsigned slots = s->cur_eweight * slots_per_weight;

	/* And then distribute the rest among servers proportionally to their weight. */
	slots += ((s->cumulative_weight + s->cur_eweight) * remainder) / s->proxy->lbprm.tot_weight
		- (s->cumulative_weight * remainder) / s->proxy->lbprm.tot_weight;

	/* But never leave a server with 0. */
	if (slots == 0)
		slots = 1;

	return s->served < slots;
}

/*
 * This function returns the running server from the CHASH tree, which is at
 * the closest distance from the value of <hash>. Doing so ensures that even
 * with a well imbalanced hash, if some servers are close to each other, they
 * will still both receive traffic. If any server is found, it will be returned.
 * It will also skip server <avoid> if the hash result ends on this one.
 * If no valid server is found, NULL is returned.
 */
struct server *chash_get_server_hash(struct proxy *p, unsigned int hash, const struct server *avoid)
{
	struct eb32_node *next, *prev;
	struct server *nsrv, *psrv;
	struct eb_root *root;
	unsigned int dn, dp;
	int loop;

	HA_SPIN_LOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (p->srv_act)
		root = &p->lbprm.chash.act;
	else if (p->lbprm.fbck) {
		nsrv = p->lbprm.fbck;
		goto out;
	}
	else if (p->srv_bck)
		root = &p->lbprm.chash.bck;
	else {
		nsrv = NULL;
		goto out;
	}

	/* find the node after and the node before */
	next = eb32_lookup_ge(root, hash);
	if (!next)
		next = eb32_first(root);
	if (!next) {
		nsrv = NULL; /* tree is empty */
		goto out;
	}

	prev = eb32_prev(next);
	if (!prev)
		prev = eb32_last(root);

	nsrv = eb32_entry(next, struct tree_occ, node)->server;
	psrv = eb32_entry(prev, struct tree_occ, node)->server;

	/* OK we're located between two servers, let's
	 * compare distances between hash and the two servers
	 * and select the closest server.
	 */
	dp = hash - prev->key;
	dn = next->key - hash;

	if (dp <= dn) {
		next = prev;
		nsrv = psrv;
	}

	loop = 0;
	while (nsrv == avoid || (p->lbprm.hash_balance_factor && !chash_server_is_eligible(nsrv))) {
		next = eb32_next(next);
		if (!next) {
			next = eb32_first(root);
			if (++loop > 1) // protection against accidental loop
				break;
		}
		nsrv = eb32_entry(next, struct tree_occ, node)->server;
	}

 out:
	HA_SPIN_UNLOCK(LBPRM_LOCK, &p->lbprm.lock);
	return nsrv;
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

	HA_SPIN_LOCK(LBPRM_LOCK, &p->lbprm.lock);
	if (p->srv_act)
		root = &p->lbprm.chash.act;
	else if (p->lbprm.fbck) {
		srv = p->lbprm.fbck;
		goto out;
	}
	else if (p->srv_bck)
		root = &p->lbprm.chash.bck;
	else {
		srv = NULL;
		goto out;
	}

	stop = node = p->lbprm.chash.last;
	do {
		struct server *s;

		if (node)
			node = eb32_next(node);
		if (!node)
			node = eb32_first(root);

		p->lbprm.chash.last = node;
		if (!node) {
			/* no node is available */
			srv = NULL;
			goto out;
		}

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

 out:
	HA_SPIN_UNLOCK(LBPRM_LOCK, &p->lbprm.lock);
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
		srv->next_eweight = (srv->uweight * p->lbprm.wdiv + p->lbprm.wmult - 1) / p->lbprm.wmult;
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
		srv->lb_nodes = calloc(srv->lb_nodes_tot, sizeof(struct tree_occ));
		for (node = 0; node < srv->lb_nodes_tot; node++) {
			srv->lb_nodes[node].server = srv;
			srv->lb_nodes[node].node.key = full_hash(srv->puid * SRV_EWGHT_RANGE + node);
		}

		if (srv_currently_usable(srv))
			chash_queue_dequeue_srv(srv);
	}
}
