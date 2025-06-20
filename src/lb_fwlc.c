/*
 * Fast Weighted Least Connection load balancing algorithm.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <import/eb32tree.h>
#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/queue.h>
#include <haproxy/server-t.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

struct fwlc_tree_elt {
	struct mt_list srv_list[FWLC_LISTS_NB];
	struct mt_list free_list;
	struct eb32_node lb_node;
	unsigned int elements;
};

DECLARE_STATIC_POOL(pool_head_fwlc_elt, "fwlc_tree_elt", sizeof(struct fwlc_tree_elt));

#define FWLC_LBPRM_SEQ(lbprm)		((lbprm) & 0xffffffff)
#define FWLC_LBPRM_SMALLEST(lbprm)	((lbprm) >> 32)

/*
 * Atomically try to update the sequence number, and the smallest key for which there is at least one server.
 * Returns 1 on success, and 0 on failure.
 */
static int fwlc_set_seq_and_smallest(struct lbprm *lbprm, uint64_t current, unsigned int seq, unsigned int smallest)
{
	uint64_t dst_nb = seq | ((uint64_t)smallest << 32);
	int ret;
#if defined(HA_CAS_IS_8B)
	ret =  _HA_ATOMIC_CAS(&lbprm->lb_seq, &current, dst_nb);
#elif defined(HA_HAVE_CAS_DW)
	ret = _HA_ATOMIC_DWCAS(&lbprm->lb_seq, &current, &dst_nb);
#else
	__decl_thread(static HA_SPINLOCK_T seq_lock);

	HA_SPIN_LOCK(OTHER_LOCK, &seq_lock);
	if (lbprm->lb_seq == current) {
		lbprm->lb_seq = dst_nb;
		ret = 1;
	} else
		ret = 0;
	HA_SPIN_UNLOCK(OTHER_LOCK, &seq_lock);
#endif
	return ret;

}

/* Remove a server from a tree. It must have previously been dequeued. This
 * function is meant to be called when a server is going down or has its
 * weight disabled.
 *
 * The server's lock and the lbprm's lock must be held.
 */
static inline void fwlc_remove_from_tree(struct server *s)
{
	s->lb_tree = NULL;
}

/*
 * Remove anything allocated by the proxy
 */
static void fwlc_proxy_deinit(struct proxy *p)
{
	struct fwlc_tree_elt *tree_elt;

	while ((tree_elt = MT_LIST_POP(&p->lbprm.lb_free_list, struct fwlc_tree_elt *, free_list)) != NULL) {
		pool_free(pool_head_fwlc_elt, tree_elt);
	}
}

/*
 * Remove anything allocated by the server
 */
static void fwlc_server_deinit(struct server *s)
{
	if (s->free_elt) {
		pool_free(pool_head_fwlc_elt, s->free_elt);
		s->free_elt = NULL;
	}
}

/* simply removes a server from a tree.
 *
 * The lbprm's lock must be held.
 */
static inline void fwlc_dequeue_srv(struct server *s)
{
	struct fwlc_tree_elt *tree_elt = s->tree_elt;
	unsigned int elts;

	MT_LIST_DELETE(&s->lb_mt_list);
	if (tree_elt) {
		elts = _HA_ATOMIC_FETCH_SUB(&tree_elt->elements, 1);
		/* We are the last element, we can nuke the node */
		if (elts == 1) {
			if (FWLC_LBPRM_SMALLEST(s->proxy->lbprm.lb_seq) == tree_elt->lb_node.key) {
				/*
				 * We were the smallest one, and now we're
				 * gone, reset it
				 */
				/*
				 * We're holding the lbprm lock so this should never fail,
				 * as nobody should be around to modify it
				 */
				do {
				} while (fwlc_set_seq_and_smallest(&s->proxy->lbprm, s->proxy->lbprm.lb_seq, FWLC_LBPRM_SEQ(s->proxy->lbprm.lb_seq) + 1, 0) == 0 && __ha_cpu_relax());

			}
			eb32_delete(&tree_elt->lb_node);
		}
	}
	s->tree_elt = NULL;
	if (s->free_elt) {
		pool_free(pool_head_fwlc_elt, s->free_elt);
		s->free_elt = NULL;
	}
}

/*
 * Allocate a tree element, either from the free list, from an element provided, or
 * from allocation.
 * Must be called with the wrlock
 */
static struct fwlc_tree_elt *fwlc_alloc_tree_elt(struct proxy *p, struct fwlc_tree_elt *allocated_elt)
{
	struct fwlc_tree_elt *tree_elt = NULL;
	int i = 0;

	if (p->lbprm.lb_free_list_nb >= FWLC_MIN_FREE_ENTRIES) {
		while ((tree_elt = MT_LIST_POP(&p->lbprm.lb_free_list, struct fwlc_tree_elt *, free_list)) != NULL) {
			MT_LIST_APPEND(&p->lbprm.lb_free_list, &tree_elt->free_list);
			if (tree_elt->elements == 0) {
				eb32_delete(&tree_elt->lb_node);
				if (i == 0) {
					struct fwlc_tree_elt *tmptree;

					tmptree = MT_LIST_POP(&p->lbprm.lb_free_list, struct fwlc_tree_elt *, free_list);
					/*
					 * Check if the next element still contains servers, and if not,
					 * just free it, to do some cleanup.
					 */
					if (tmptree && tmptree->elements == 0) {
						eb32_delete(&tmptree->lb_node);
						pool_free(pool_head_fwlc_elt, tmptree);
						p->lbprm.lb_free_list_nb--;
					} else if (tmptree)
						MT_LIST_APPEND(&p->lbprm.lb_free_list, &tmptree->free_list);
				}
				return tree_elt;
		}
			i++;
			if (i > 3)
				break;
		}
	}
	if (!allocated_elt)
		tree_elt = pool_alloc(pool_head_fwlc_elt);
	else
		tree_elt = allocated_elt;

	for (i = 0; i < FWLC_LISTS_NB; i++) {
		MT_LIST_INIT(&tree_elt->srv_list[i]);
	}
	MT_LIST_INIT(&tree_elt->free_list);
	MT_LIST_APPEND(&p->lbprm.lb_free_list, &tree_elt->free_list);
	p->lbprm.lb_free_list_nb++;
	tree_elt->elements = 0;
	return tree_elt;
}

/*
 * Return the tree element for the provided key, allocate it first if needed.
 * Must be called with the lbprm lock held.
 */
static struct fwlc_tree_elt *fwlc_get_tree_elt(struct server *s, u32 key)
{
	struct eb32_node *node;
	struct fwlc_tree_elt *tree_elt = NULL;

	node = eb32_lookup(s->lb_tree, key);
	if (node)
		tree_elt = container_of(node, struct fwlc_tree_elt, lb_node);
	if (!tree_elt) {
		/* No element available, we have to allocate one */
		tree_elt = fwlc_alloc_tree_elt(s->proxy, NULL);
		tree_elt->lb_node.key = key;
		eb32_insert(s->lb_tree, &tree_elt->lb_node);
	}
	return tree_elt;
}

/* Queue a server in its associated tree, assuming the <eweight> is >0.
 * Servers are sorted by (#conns+1)/weight. To ensure maximum accuracy,
 * we use (#conns+1)*SRV_EWGHT_MAX/eweight as the sorting key. The reason
 * for using #conns+1 is to sort by weights in case the server is picked
 * and not before it is picked. This provides a better load accuracy for
 * low connection counts when weights differ and makes sure the round-robin
 * applies between servers of highest weight first. However servers with no
 * connection are always picked first so that under low loads, it's not
 * always the single server with the highest weight that gets picked.
 *
 * NOTE: Depending on the calling context, we use s->next_eweight or
 *       s->cur_eweight. The next value is used when the server state is updated
 *       (because the weight changed for instance). During this step, the server
 *       state is not yet committed. The current value is used to reposition the
 *       server in the tree. This happens when the server is used.
 *
 * The lbprm's lock must be held.
 */
static inline void fwlc_queue_srv(struct server *s, unsigned int eweight)
{
	struct fwlc_tree_elt *tree_elt;
	unsigned int inflight = _HA_ATOMIC_LOAD(&s->served) + _HA_ATOMIC_LOAD(&s->queueslength);
	unsigned int list_nb;
	u32 key;

	key = inflight ? (inflight + 1) * SRV_EWGHT_MAX / eweight : 0;
	tree_elt = fwlc_get_tree_elt(s, key);
	list_nb = statistical_prng_range(FWLC_LISTS_NB);
	MT_LIST_APPEND(&tree_elt->srv_list[list_nb], &s->lb_mt_list);
	s->tree_elt = tree_elt;
	_HA_ATOMIC_INC(&tree_elt->elements);
	if (FWLC_LBPRM_SMALLEST(s->proxy->lbprm.lb_seq) > key) {
		/*
		 * We're holding the lbprm lock so this should never fail,
		 * as nobody should be around to modify it
		 */
		do {
		} while (fwlc_set_seq_and_smallest(&s->proxy->lbprm, s->proxy->lbprm.lb_seq, FWLC_LBPRM_SEQ(s->proxy->lbprm.lb_seq) + 1, key) == 0);
	}
}

/*
 * Loop across the different lists until we find an unlocked one, and lock it.
 */
static __inline struct mt_list fwlc_lock_target_list(struct fwlc_tree_elt *tree_elt)
{
	struct mt_list list = {NULL, NULL};
	int i;
	int dst_list;


	dst_list = statistical_prng_range(FWLC_LISTS_NB);

	while (list.next == NULL) {
		for (i = 0; i < FWLC_LISTS_NB; i++) {
			list = mt_list_try_lock_prev(&tree_elt->srv_list[(dst_list + i) % FWLC_LISTS_NB]);
			if (list.next != NULL)
				break;
		}
	}
	return list;
}

/*
 * Calculate the key to be used for a given server
 */
static inline unsigned int fwlc_get_key(struct server *s)
{
	unsigned int inflight;
	unsigned int eweight;
	unsigned int new_key;

	inflight = _HA_ATOMIC_LOAD(&s->served) + _HA_ATOMIC_LOAD(&s->queueslength);
	eweight = _HA_ATOMIC_LOAD(&s->cur_eweight);
	new_key = inflight ? (inflight + 1) * SRV_EWGHT_MAX / (eweight ? eweight : 1) : 0;

	return new_key;
}

/*
 * Only one thread will try to update a server position at a given time,
 * thanks to the lb_lock. However that means that by the time we are done
 * with the update, a new one might be needed, so check for that and
 * schedule the tasklet if needed, once we dropped the lock.
 */
static inline void fwlc_check_srv_key(struct server *s, unsigned int expected)
{
	unsigned int key = fwlc_get_key(s);

	if (key != expected && s->requeue_tasklet)
		tasklet_wakeup(s->requeue_tasklet);
}

/* Re-position the server in the FWLC tree after it has been assigned one
 * connection or after it has released one. Note that it is possible that
 * the server has been moved out of the tree due to failed health-checks.
 * The lbprm's lock will be used.
 */
static void fwlc_srv_reposition(struct server *s)
{
	struct mt_list to_unlock;
	struct fwlc_tree_elt *tree_elt = NULL, *allocated_elt = NULL;
	struct eb32_node *node;
	struct mt_list list;
	uint64_t cur_seq = 0;
	unsigned int eweight = _HA_ATOMIC_LOAD(&s->cur_eweight);
	unsigned int new_key;
	unsigned int smallest;
	int srv_lock;

	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);
	new_key = fwlc_get_key(s);
	/* some calls will be made for no change (e.g connect_server() after
	 * assign_server(). Let's check that first.
	 */
	if ((s->tree_elt && s->tree_elt->lb_node.node.leaf_p && eweight &&
	    s->tree_elt->lb_node.key == new_key) || !s->lb_tree) {
		HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);
		return;
	}

	srv_lock = HA_ATOMIC_XCHG(&s->lb_lock, 1);
	/* Somebody else is updating that server, give up */
	if (srv_lock == 1) {
		HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);
		return;
	}

	/*
	 * We're not in the tree, the server is probably down, don't
	 * do anything.
	 */
	if (unlikely(!s->tree_elt)) {
		HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);
		_HA_ATOMIC_STORE(&s->lb_lock, 0);
		return;
	}
	node = eb32_lookup(s->lb_tree, new_key);
	if (node)
		tree_elt = container_of(node, struct fwlc_tree_elt, lb_node);
		/*
		 * It is possible that s->tree_elt was changed since we checked
		 * As s->tree_elt is only changed while holding s->lb_lock,
		 * check again now that we acquired it, and if we're using
		 * the right element, do nothing.
		 */
	if (tree_elt == s->tree_elt) {
		HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);
		_HA_ATOMIC_STORE(&s->lb_lock, 0);
		fwlc_check_srv_key(s, new_key);
		return;
	}
	/*
	 * We have to allocate a new tree element, and/or remove the
	 * previous element, we will modify the tree, so let's get the write
	 * lock.
	 */
	if (!tree_elt) {
		unsigned int new_new_key;

		/*
		 * We don't want to allocate something while holding the lock,
		 * so make sure we have something allocated before.
		 */
		if (s->free_elt != NULL) {
			allocated_elt = s->free_elt;
			s->free_elt = NULL;
		} else
			allocated_elt = pool_alloc(pool_head_fwlc_elt);
		if (HA_RWLOCK_TRYRDTOWR(LBPRM_LOCK, &s->proxy->lbprm.lock) != 0) {
			/* there's already some contention on the tree's lock, there's
			 * no point insisting. Better wake up the server's tasklet that
			 * will let this or another thread retry later. For the time
			 * being, the server's apparent load is slightly inaccurate but
			 * we don't care, if there is contention, it will self-regulate.
			 */
			if (s->requeue_tasklet)
				tasklet_wakeup(s->requeue_tasklet);
			HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);
			s->free_elt = allocated_elt;
			_HA_ATOMIC_STORE(&s->lb_lock, 0);
			return;
		}

		/* we might have been waiting for a while on the lock above
		 * so it's worth testing again because other threads are very
		 * likely to have released a connection or taken one leading
		 * to our target value (50% of the case in measurements).
		 */

		new_new_key = fwlc_get_key(s);
		if (new_new_key != new_key) {
			if (s->tree_elt &&
			    s->tree_elt->lb_node.node.leaf_p &&
			    eweight && s->tree_elt->lb_node.key == new_new_key) {
				/* Okay after all we have nothing to do */
				HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);
				s->free_elt = allocated_elt;
				_HA_ATOMIC_STORE(&s->lb_lock, 0);
				fwlc_check_srv_key(s, new_new_key);
				return;
			}
			node = eb32_lookup(s->lb_tree, new_new_key);
			if (node) {
				tree_elt = container_of(node, struct fwlc_tree_elt, lb_node);
				HA_RWLOCK_WRTORD(LBPRM_LOCK, &s->proxy->lbprm.lock);
				s->free_elt = allocated_elt;
				allocated_elt = NULL;
			} else
				tree_elt = NULL;
			new_key = new_new_key;
		}
	}

	/*
	 * Now we increment the number of elements in the new tree_elt,
	 * we change our sequence number and smallest, and we then
	 * decrement the number of elements in the old tree_elt.
	 * It is important to keep this sequencing, as fwlc_get_next_server()
	 * uses the number of elements to know if there is something to look for,
	 * and we want to make sure we do not miss a server.
	 */
	if (!tree_elt) {
		/*
		 * There were no tree element matching our key,
		 * allocate one and insert it into the tree
		 */
		tree_elt = fwlc_alloc_tree_elt(s->proxy, allocated_elt);
		if (tree_elt == allocated_elt)
			allocated_elt = NULL;
		tree_elt->lb_node.key = new_key;
		tree_elt->elements = 1;
		__ha_barrier_store();
		/* If we allocated, then we hold the write lock */
		eb32_insert(s->lb_tree, &tree_elt->lb_node);
		HA_RWLOCK_WRTORD(LBPRM_LOCK, &s->proxy->lbprm.lock);
	} else {
		_HA_ATOMIC_INC(&tree_elt->elements);
	}

	__ha_barrier_store();
	/*
	 * Update the sequence number, and the smallest if needed.
	 * We always have to do it, even if we're not actually
	 * updating the smallest one, otherwise we'll get na
	 * ABA problem and a server may be missed when looked up.
	 * The only time we don't have to do it if is another thread
	 * increased it, and the new smallest element is not
	 * higher than our new key.
	 */
	do {
                unsigned int tmpsmallest;
		uint64_t newcurseq = _HA_ATOMIC_LOAD(&s->proxy->lbprm.lb_seq);

		if (cur_seq != 0 && FWLC_LBPRM_SEQ(newcurseq) >
		   FWLC_LBPRM_SEQ(cur_seq) && new_key >= FWLC_LBPRM_SMALLEST(newcurseq))
			break;

		cur_seq = newcurseq;
                tmpsmallest = FWLC_LBPRM_SMALLEST(cur_seq);
                if (new_key > tmpsmallest)
                        smallest = tmpsmallest;
		else
                        smallest = new_key;

        } while (fwlc_set_seq_and_smallest(&s->proxy->lbprm, cur_seq, FWLC_LBPRM_SEQ(cur_seq) + 1, smallest) == 0 && __ha_cpu_relax());

	__ha_barrier_store();

	_HA_ATOMIC_DEC(&s->tree_elt->elements);

	/*
	 * Now lock the existing element, and its target list.
	 * To prevent a deadlock, we always lock the one
	 * with the lowest key first.
	 */
	if (new_key < s->tree_elt->lb_node.key) {
		to_unlock = mt_list_lock_full(&s->lb_mt_list);
		list = fwlc_lock_target_list(tree_elt);
	} else {
		list = fwlc_lock_target_list(tree_elt);
		to_unlock = mt_list_lock_full(&s->lb_mt_list);
	}

	/*
	 * Unlock the old list, the element is now
	 * no longer in it.
	 */
	mt_list_unlock_link(to_unlock);

	/*
	 * Add the element to the new list, and unlock it.
	 */
	mt_list_unlock_full(&s->lb_mt_list, list);

	s->tree_elt = tree_elt;

	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->proxy->lbprm.lock);

	if (allocated_elt)
		s->free_elt = allocated_elt;

	__ha_barrier_store();
	_HA_ATOMIC_STORE(&s->lb_lock, 0);

	fwlc_check_srv_key(s, new_key);
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to down.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely down (the caller may not
 * know all the variables of a server's state).
 *
 * The server's lock must be held. The lbprm's lock will be used.
 */
static void fwlc_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (srv_willbe_usable(srv))
		goto out_update_state;
	HA_RWLOCK_WRLOCK(LBPRM_LOCK, &p->lbprm.lock);


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

	fwlc_dequeue_srv(srv);
	fwlc_remove_from_tree(srv);

out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
	HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function updates the server trees according to server <srv>'s new
 * state. It should be called when server <srv>'s status changes to up.
 * It is not important whether the server was already down or not. It is not
 * important either that the new state is completely UP (the caller may not
 * know all the variables of a server's state). This function will not change
 * the weight of a server which was already up.
 *
 * The server's lock must be held. The lbprm's lock will be used.
 */
static void fwlc_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (!srv_willbe_usable(srv))
		goto out_update_state;

	HA_RWLOCK_WRLOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (srv_currently_usable(srv))
		/* server was already up */
		goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
		srv->lb_tree = &p->lbprm.fwlc.bck;
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
		srv->lb_tree = &p->lbprm.fwlc.act;
		p->lbprm.tot_wact += srv->next_eweight;
		p->srv_act++;
	}

	/* note that eweight cannot be 0 here */
	fwlc_queue_srv(srv, srv->next_eweight);

 out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
	HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function must be called after an update to server <srv>'s effective
 * weight. It may be called after a state change too.
 *
 * The server's lock must be held. The lbprm's lock will be used.
 */
static void fwlc_update_server_weight(struct server *srv)
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
		fwlc_set_server_status_up(srv);
		return;
	}
	else if (old_state && !new_state) {
		fwlc_set_server_status_down(srv);
		return;
	}

	HA_RWLOCK_WRLOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (srv->lb_tree)
		fwlc_dequeue_srv(srv);

	if (srv->flags & SRV_F_BACKUP) {
		p->lbprm.tot_wbck += srv->next_eweight - srv->cur_eweight;
		srv->lb_tree = &p->lbprm.fwlc.bck;
	} else {
		p->lbprm.tot_wact += srv->next_eweight - srv->cur_eweight;
		srv->lb_tree = &p->lbprm.fwlc.act;
	}

	fwlc_queue_srv(srv, srv->next_eweight);

	update_backend_weight(p);
	HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

	srv_lb_commit_status(srv);
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
	p->lbprm.server_requeue   = fwlc_srv_reposition;
	p->lbprm.server_deinit    = fwlc_server_deinit;
	p->lbprm.proxy_deinit     = fwlc_proxy_deinit;

	p->lbprm.wdiv = BE_WEIGHT_SCALE;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->next_eweight = (srv->uweight * p->lbprm.wdiv + p->lbprm.wmult - 1) / p->lbprm.wmult;
		srv_lb_commit_status(srv);
	}

	p->lbprm.lb_seq = 0;

	recount_servers(p);
	update_backend_weight(p);

	p->lbprm.fwlc.act = init_head;
	p->lbprm.fwlc.bck = init_head;

	/* queue active and backup servers in two distinct groups */
	for (srv = p->srv; srv; srv = srv->next) {
		if (!srv_currently_usable(srv))
			continue;
		srv->lb_tree = (srv->flags & SRV_F_BACKUP) ? &p->lbprm.fwlc.bck : &p->lbprm.fwlc.act;
		fwlc_queue_srv(srv, srv->next_eweight);
	}
}

/* Return next server from the FWLC tree in backend <p>. If the tree is empty,
 * return NULL. Saturated servers are skipped.
 *
 * The lbprm's lock will be used in R/O mode. The server's lock is not used.
 */
struct server *fwlc_get_next_server(struct proxy *p, struct server *srvtoavoid)
{
	struct server *srv, *avoided;
	struct eb32_node *node;
	uint64_t curseq;
	int found = 0;

	srv = avoided = NULL;

	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &p->lbprm.lock);
	curseq = _HA_ATOMIC_LOAD(&p->lbprm.lb_seq);
redo:
	if (p->srv_act)
		node = eb32_lookup_ge(&p->lbprm.fwlc.act, FWLC_LBPRM_SMALLEST(curseq));
	else if (p->lbprm.fbck) {
		srv = p->lbprm.fbck;
		goto out;
	}
	else if (p->srv_bck)
		node = eb32_lookup_ge(&p->lbprm.fwlc.bck, FWLC_LBPRM_SMALLEST(curseq));
	else {
		srv = NULL;
		goto out;
	}

	while (node) {
		struct fwlc_tree_elt *tree_elt;
		struct server *s;
		int unusable = 0;
		int orig_nb;
		int i = 0;

		tree_elt = eb32_entry(node, struct fwlc_tree_elt, lb_node);
		orig_nb = statistical_prng_range(FWLC_LISTS_NB);

		while (_HA_ATOMIC_LOAD(&tree_elt->elements) > unusable) {
			struct mt_list mt_list;
			mt_list.next = _HA_ATOMIC_LOAD(&tree_elt->srv_list[(i + orig_nb) % FWLC_LISTS_NB].next);

			if (mt_list.next != &tree_elt->srv_list[(i + orig_nb) % FWLC_LISTS_NB] && mt_list.next != MT_LIST_BUSY) {
				unsigned int eweight;
				unsigned int planned_inflight;
				s = container_of(mt_list.next, struct server, lb_mt_list);
				eweight = _HA_ATOMIC_LOAD(&s->cur_eweight);

				planned_inflight = tree_elt->lb_node.key * eweight / SRV_EWGHT_MAX;
				if (!s->maxconn || s->served + s->queueslength < srv_dynamic_maxconn(s) + s->maxqueue) {
					if (_HA_ATOMIC_LOAD(&s->served) + _HA_ATOMIC_LOAD(&s->queueslength) > planned_inflight + 2) {
						/*
						 * The server has more requests than expected,
						 * let's try to reposition it, to avoid too
						 * many threads using the same server at the
						 * same time. From the moment we release the
						 * lock, we cannot trust the node nor tree_elt
						 * anymore, so we need to loop back to the
						 * beginning.
						 */
						if (i >= FWLC_LISTS_NB) {
							HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &p->lbprm.lock);
							fwlc_srv_reposition(s);
							HA_RWLOCK_RDLOCK(LBPRM_LOCK, &p->lbprm.lock);
							goto redo;
						}
						i++;
						continue;
					}
                                        if (s != srvtoavoid) {
                                                srv = s;
                                                found = 1;
                                                break;
                                        }
					avoided = s;
				}
				unusable++;
				i++;
			} else if (mt_list.next == &tree_elt->srv_list[(i + orig_nb) % FWLC_LISTS_NB]) {
				i++;
				continue;
			} else {
				i++;
				continue;
			}
		}
		if (found)
			break;

		do {
			node = eb32_next(node);
		} while (node && node->key < FWLC_LBPRM_SMALLEST(curseq));

		if (node) {
			uint64_t newcurseq = HA_ATOMIC_LOAD(&p->lbprm.lb_seq);

			/*
			 * If we have a bigger element than the smallest recorded, and we're up to date,
			 * update the smallest one.
			 */
			if (likely(newcurseq == curseq && FWLC_LBPRM_SMALLEST(newcurseq) < node->key)) {
				if (fwlc_set_seq_and_smallest(&p->lbprm, curseq, FWLC_LBPRM_SEQ(curseq), node->key) != 0) {
					curseq = FWLC_LBPRM_SEQ(curseq) | ((uint64_t)node->key << 32);
					__ha_barrier_store();
					continue;
				}

			}
			/*
			 * Somebody added a new server in node we already skipped, so retry from the beginning.
			 */
			if (unlikely(FWLC_LBPRM_SMALLEST(newcurseq) < node->key && FWLC_LBPRM_SEQ(newcurseq) != FWLC_LBPRM_SEQ(curseq))) {
				curseq = newcurseq;
				goto redo;
			}
			curseq = newcurseq;
		} else {
			uint64_t newcurseq = _HA_ATOMIC_LOAD(&p->lbprm.lb_seq);

			/*
			 * No more node, but somebody changed the tree, so it's
			 * worth trying again.
			 */
			if (FWLC_LBPRM_SEQ(newcurseq) != FWLC_LBPRM_SEQ(curseq)) {
				curseq = newcurseq;
				goto redo;
			}
		}
	}

	if (!srv)
		srv = avoided;
 out:
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

	return srv;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
