/*
 * Listener management functions.
 *
 * Copyright 2000-2013 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <haproxy/acl.h>
#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli-t.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/guid.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_tp.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


/* List head of all known bind keywords */
struct bind_kw_list bind_keywords = {
	.list = LIST_HEAD_INIT(bind_keywords.list)
};

/* list of the temporarily limited listeners because of lack of resource */
static struct mt_list global_listener_queue = MT_LIST_HEAD_INIT(global_listener_queue);
static struct task *global_listener_queue_task;
/* number of times an accepted connection resulted in maxconn being reached */
ullong maxconn_reached = 0;
__decl_thread(static HA_RWLOCK_T global_listener_rwlock);

/* listener status for stats */
const char* li_status_st[LI_STATE_COUNT] = {
	[LI_STATUS_WAITING] = "WAITING",
	[LI_STATUS_OPEN]    = "OPEN",
	[LI_STATUS_FULL]    = "FULL",
};

#if defined(USE_THREAD)

struct accept_queue_ring accept_queue_rings[MAX_THREADS] __attribute__((aligned(64))) = { };

/* dequeue and process a pending connection from the local accept queue (single
 * consumer). Returns the accepted connection or NULL if none was found.
 */
struct connection *accept_queue_pop_sc(struct accept_queue_ring *ring)
{
	unsigned int pos, next;
	struct connection *ptr;
	struct connection **e;
	uint32_t idx = _HA_ATOMIC_LOAD(&ring->idx);  /* (head << 16) + tail */

	pos = idx >> 16;
	if (pos == (uint16_t)idx)
		return NULL;

	next = pos + 1;
	if (next >= ACCEPT_QUEUE_SIZE)
		next = 0;

	e = &ring->entry[pos];

	/* wait for the producer to update the listener's pointer */
	while (1) {
		ptr = *e;
		__ha_barrier_load();
		if (ptr)
			break;
		pl_cpu_relax();
	}

	/* release the entry */
	*e = NULL;

	__ha_barrier_store();
	do {
		pos = (next << 16) | (idx & 0xffff);
	} while (unlikely(!HA_ATOMIC_CAS(&ring->idx, &idx, pos) && __ha_cpu_relax()));

	return ptr;
}


/* Tries to push a new accepted connection <conn> into ring <ring>.
 * <accept_push_cb> is called if not NULL just prior to the push operation.
 *
 * Returns non-zero if it succeeds, or zero if the ring is full. Supports
 * multiple producers.
 */
int accept_queue_push_mp(struct accept_queue_ring *ring, struct connection *conn,
                         void (*accept_push_cb)(struct connection *))
{
	unsigned int pos, next;
	uint32_t idx = _HA_ATOMIC_LOAD(&ring->idx);  /* (head << 16) + tail */

	do {
		pos = (uint16_t)idx;
		next = pos + 1;
		if (next >= ACCEPT_QUEUE_SIZE)
			next = 0;
		if (next == (idx >> 16))
			return 0; // ring full
		next |= (idx & 0xffff0000U);
	} while (unlikely(!_HA_ATOMIC_CAS(&ring->idx, &idx, next) && __ha_cpu_relax()));

	if (accept_push_cb)
		accept_push_cb(conn);

	ring->entry[pos] = conn;
	__ha_barrier_store();
	return 1;
}

/* proceed with accepting new connections. Don't mark it static so that it appears
 * in task dumps.
 */
struct task *accept_queue_process(struct task *t, void *context, unsigned int state)
{
	struct accept_queue_ring *ring = context;
	struct connection *conn;
	struct listener *li;
	unsigned int max_accept;
	int ret;

	/* if global.tune.maxaccept is -1, then max_accept is UINT_MAX. It
	 * is not really illimited, but it is probably enough.
	 */
	max_accept = global.tune.maxaccept ? global.tune.maxaccept : MAX_ACCEPT;
	for (; max_accept; max_accept--) {
		conn = accept_queue_pop_sc(ring);
		if (!conn)
			break;

		li = __objt_listener(conn->target);
		_HA_ATOMIC_INC(&li->thr_conn[ti->ltid]);
		ret = li->bind_conf->accept(conn);
		if (ret <= 0) {
			/* connection was terminated by the application */
			continue;
		}

		/* increase the per-process number of cumulated sessions, this
		 * may only be done once l->bind_conf->accept() has accepted the
		 * connection.
		 */
		if (!(li->bind_conf->options & BC_O_UNLIMITED)) {
			HA_ATOMIC_UPDATE_MAX(&global.sps_max,
			                     update_freq_ctr(&global.sess_per_sec, 1));
			if (li->bind_conf->options & BC_O_USE_SSL) {
				HA_ATOMIC_UPDATE_MAX(&global.ssl_max,
				                     update_freq_ctr(&global.ssl_per_sec, 1));
			}
		}
	}

	/* ran out of budget ? Let's come here ASAP */
	if (!max_accept)
		tasklet_wakeup(ring->tasklet);

	return NULL;
}

/* Initializes the accept-queues. Returns 0 on success, otherwise ERR_* flags */
static int accept_queue_init()
{
	struct tasklet *t;
	int i;

	for (i = 0; i < global.nbthread; i++) {
		t = tasklet_new();
		if (!t) {
			ha_alert("Out of memory while initializing accept queue for thread %d\n", i);
			return ERR_FATAL|ERR_ABORT;
		}
		t->tid = i;
		t->process = accept_queue_process;
		t->context = &accept_queue_rings[i];
		accept_queue_rings[i].tasklet = t;
	}
	return 0;
}

REGISTER_CONFIG_POSTPARSER("multi-threaded accept queue", accept_queue_init);

static void accept_queue_deinit()
{
	int i;

	for (i = 0; i < global.nbthread; i++) {
		tasklet_free(accept_queue_rings[i].tasklet);
	}
}

REGISTER_POST_DEINIT(accept_queue_deinit);

#endif // USE_THREAD

/* Memory allocation and initialization of the per_thr field (one entry per
 * bound thread).
 * Returns 0 if the field has been successfully initialized, -1 on failure.
 */
int li_init_per_thr(struct listener *li)
{
	int nbthr = MIN(global.nbthread, MAX_THREADS_PER_GROUP);
	int i;

	/* allocate per-thread elements for listener */
	li->per_thr = calloc(nbthr, sizeof(*li->per_thr));
	if (!li->per_thr)
		return -1;

	for (i = 0; i < nbthr; ++i) {
		MT_LIST_INIT(&li->per_thr[i].quic_accept.list);
		MT_LIST_INIT(&li->per_thr[i].quic_accept.conns);

		li->per_thr[i].li = li;
	}

	return 0;
}

/* helper to get listener status for stats */
enum li_status get_li_status(struct listener *l)
{
	if (!l->bind_conf->maxconn || l->nbconn < l->bind_conf->maxconn) {
		if (l->state == LI_LIMITED)
			return LI_STATUS_WAITING;
		else
			return LI_STATUS_OPEN;
	}
	return LI_STATUS_FULL;
}

/* adjust the listener's state and its proxy's listener counters if needed.
 * It must be called under the listener's lock, but uses atomic ops to change
 * the proxy's counters so that the proxy lock is not needed.
 */
void listener_set_state(struct listener *l, enum li_state st)
{
	struct proxy *px = l->bind_conf->frontend;

	if (px) {
		/* from state */
		switch (l->state) {
		case LI_NEW: /* first call */
			_HA_ATOMIC_INC(&px->li_all);
			break;
		case LI_INIT:
		case LI_ASSIGNED:
			break;
		case LI_PAUSED:
			_HA_ATOMIC_DEC(&px->li_paused);
			break;
		case LI_LISTEN:
			_HA_ATOMIC_DEC(&px->li_bound);
			break;
		case LI_READY:
		case LI_FULL:
		case LI_LIMITED:
			_HA_ATOMIC_DEC(&px->li_ready);
			break;
		}

		/* to state */
		switch (st) {
		case LI_NEW:
		case LI_INIT:
		case LI_ASSIGNED:
			break;
		case LI_PAUSED:
			BUG_ON(l->rx.fd == -1);
			_HA_ATOMIC_INC(&px->li_paused);
			break;
		case LI_LISTEN:
			BUG_ON(l->rx.fd == -1 && !l->rx.rhttp.task);
			_HA_ATOMIC_INC(&px->li_bound);
			break;
		case LI_READY:
		case LI_FULL:
		case LI_LIMITED:
			BUG_ON(l->rx.fd == -1 && !l->rx.rhttp.task);
			_HA_ATOMIC_INC(&px->li_ready);
			l->flags |= LI_F_FINALIZED;
			break;
		}
	}
	l->state = st;
}

/* This function adds the specified listener's file descriptor to the polling
 * lists if it is in the LI_LISTEN state. The listener enters LI_READY or
 * LI_FULL state depending on its number of connections. In daemon mode, we
 * also support binding only the relevant processes to their respective
 * listeners. We don't do that in debug mode however.
 */
void enable_listener(struct listener *listener)
{
	HA_RWLOCK_WRLOCK(LISTENER_LOCK, &listener->lock);

	/* If this listener is supposed to be only in the master, close it in
	 * the workers. Conversely, if it's supposed to be only in the workers
	 * close it in the master.
	 */
	if (!!master != !!(listener->rx.flags & RX_F_MWORKER))
		do_unbind_listener(listener);

	if (listener->state == LI_LISTEN) {
		BUG_ON(listener->rx.fd == -1 && !listener->rx.rhttp.task);
		if ((global.mode & (MODE_DAEMON | MODE_MWORKER)) &&
		    (!!master != !!(listener->rx.flags & RX_F_MWORKER))) {
			/* we don't want to enable this listener and don't
			 * want any fd event to reach it.
			 */
			do_unbind_listener(listener);
		}
		else if (!listener->bind_conf->maxconn || listener->nbconn < listener->bind_conf->maxconn) {
			listener->rx.proto->enable(listener);
			listener_set_state(listener, LI_READY);
		}
		else {
			listener_set_state(listener, LI_FULL);
		}
	}

	HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &listener->lock);
}

/*
 * This function completely stops a listener.
 * The proxy's listeners count is updated and the proxy is
 * disabled and woken up after the last one is gone.
 * It will need to operate under the proxy's lock, the protocol's lock and
 * the listener's lock. The caller is responsible for indicating in lpx,
 * lpr, lli whether the respective locks are already held (non-zero) or
 * not (zero) so that the function picks the missing ones, in this order.
 */
void stop_listener(struct listener *l, int lpx, int lpr, int lli)
{
	struct proxy *px = l->bind_conf->frontend;

	if (l->bind_conf->options & BC_O_NOSTOP) {
		/* master-worker sockpairs are never closed but don't count as a
		 * job.
		 */
		return;
	}

	if (!lpx && px)
		HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);

	if (!lpr)
		HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);

	if (!lli)
		HA_RWLOCK_WRLOCK(LISTENER_LOCK, &l->lock);

	if (l->state > LI_INIT) {
		do_unbind_listener(l);

		if (l->state >= LI_ASSIGNED)
			__delete_listener(l);

		if (px)
			proxy_cond_disable(px);
	}

	if (!lli)
		HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &l->lock);

	if (!lpr)
		HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);

	if (!lpx && px)
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);
}

/* This function adds the specified <listener> to the protocol <proto>. It
 * does nothing if the protocol was already added. The listener's state is
 * automatically updated from LI_INIT to LI_ASSIGNED. The number of listeners
 * for the protocol is updated. This must be called with the proto lock held.
 */
void default_add_listener(struct protocol *proto, struct listener *listener)
{
	if (listener->state != LI_INIT)
		return;
	listener_set_state(listener, LI_ASSIGNED);
	listener->rx.proto = proto;
	LIST_APPEND(&proto->receivers, &listener->rx.proto_list);
	proto->nb_receivers++;
}

/* default function called to suspend a listener: it simply passes the call to
 * the underlying receiver. This is find for most socket-based protocols. This
 * must be called under the listener's lock. It will return < 0 in case of
 * failure, 0 if the listener was totally stopped, or > 0 if correctly paused..
 * If no receiver-level suspend is provided, the operation is assumed
 * to succeed.
 */
int default_suspend_listener(struct listener *l)
{
	if (!l->rx.proto->rx_suspend)
		return 1;

	return l->rx.proto->rx_suspend(&l->rx);
}


/* Tries to resume a suspended listener, and returns non-zero on success or
 * zero on failure. On certain errors, an alert or a warning might be displayed.
 * It must be called with the listener's lock held. Depending on the listener's
 * state and protocol, a listen() call might be used to resume operations, or a
 * call to the receiver's resume() function might be used as well. This is
 * suitable as a default function for TCP and UDP. This must be called with the
 * listener's lock held.
 */
int default_resume_listener(struct listener *l)
{
	int ret = 1;

	if (l->state == LI_ASSIGNED) {
		char msg[100];
		char *errmsg;
		int err;

		/* first, try to bind the receiver */
		err = l->rx.proto->fam->bind(&l->rx, &errmsg);
		if (err != ERR_NONE) {
			if (err & ERR_WARN)
				ha_warning("Resuming listener: protocol %s: %s.\n", l->rx.proto->name, errmsg);
			else if (err & ERR_ALERT)
				ha_alert("Resuming listener: protocol %s: %s.\n", l->rx.proto->name, errmsg);
			ha_free(&errmsg);
			if (err & (ERR_FATAL | ERR_ABORT)) {
				ret = 0;
				goto end;
			}
		}

		/* then, try to listen:
		 * for now there's still always a listening function
		 * (same check performed in protocol_bind_all()
		 */
		BUG_ON(!l->rx.proto->listen);
		err = l->rx.proto->listen(l, msg, sizeof(msg));
		if (err & ERR_ALERT)
			ha_alert("Resuming listener: protocol %s: %s.\n", l->rx.proto->name, msg);
		else if (err & ERR_WARN)
			ha_warning("Resuming listener: protocol %s: %s.\n", l->rx.proto->name, msg);

		if (err & (ERR_FATAL | ERR_ABORT)) {
			ret = 0;
			goto end;
		}
	}

	if (l->state < LI_PAUSED) {
		ret = 0;
		goto end;
	}

	if (l->state == LI_PAUSED && l->rx.proto->rx_resume &&
	    l->rx.proto->rx_resume(&l->rx) <= 0)
		ret = 0;
 end:
	return ret;
}


/* This function tries to temporarily disable a listener, depending on the OS
 * capabilities. Linux unbinds the listen socket after a SHUT_RD, and ignores
 * SHUT_WR. Solaris refuses either shutdown(). OpenBSD ignores SHUT_RD but
 * closes upon SHUT_WR and refuses to rebind. So a common validation path
 * involves SHUT_WR && listen && SHUT_RD. In case of success, the FD's polling
 * is disabled. It normally returns non-zero, unless an error is reported.
 * suspend() may totally stop a listener if it doesn't support the PAUSED
 * state, in which case state will be set to ASSIGNED.
 * It will need to operate under the proxy's lock and the listener's lock.
 * The caller is responsible for indicating in lpx, lli whether the respective
 * locks are already held (non-zero) or not (zero) so that the function pick
 * the missing ones, in this order.
 */
int suspend_listener(struct listener *l, int lpx, int lli)
{
	struct proxy *px = l->bind_conf->frontend;
	int ret = 1;

	if (!lpx && px)
		HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);

	if (!lli)
		HA_RWLOCK_WRLOCK(LISTENER_LOCK, &l->lock);

	if (!(l->flags & LI_F_FINALIZED) || l->state <= LI_PAUSED)
		goto end;

	if (l->rx.proto->suspend) {
		ret = l->rx.proto->suspend(l);
		/* if the suspend() fails, we don't want to change the
		 * current listener state
		 */
		if (ret < 0)
			goto end;
	}

	MT_LIST_DELETE(&l->wait_queue);

	/* ret == 0 means that the suspend() has been turned into
	 * an unbind(), meaning the listener is now stopped (ie: ABNS), we need
	 * to report this state change properly
	 */
	listener_set_state(l, ((ret) ? LI_PAUSED : LI_ASSIGNED));

	if (px && !(l->flags & LI_F_SUSPENDED))
		px->li_suspended++;
	l->flags |= LI_F_SUSPENDED;

	/* at this point, everything is under control, no error should be
	 * returned to calling function
	 */
	ret = 1;

	if (px && !(px->flags & PR_FL_PAUSED) && !px->li_ready) {
		/* PROXY_LOCK is required */
		proxy_cond_pause(px);
		ha_warning("Paused %s %s.\n", proxy_cap_str(px->cap), px->id);
		send_log(px, LOG_WARNING, "Paused %s %s.\n", proxy_cap_str(px->cap), px->id);
	}
  end:
	if (!lli)
		HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &l->lock);

	if (!lpx && px)
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);

	return ret;
}

/* This function tries to resume a temporarily disabled listener. Paused, full,
 * limited and disabled listeners are handled, which means that this function
 * may replace enable_listener(). The resulting state will either be LI_READY
 * or LI_FULL. 0 is returned in case of failure to resume (eg: dead socket).
 * Listeners bound to a different process are not woken up unless we're in
 * foreground mode, and are ignored. If the listener was only in the assigned
 * state, it's totally rebound. This can happen if a suspend() has completely
 * stopped it. If the resume fails, 0 is returned and an error might be
 * displayed.
 * It will need to operate under the proxy's lock and the listener's lock.
 * The caller is responsible for indicating in lpx, lli whether the respective
 * locks are already held (non-zero) or not (zero) so that the function pick
 * the missing ones, in this order.
 */
int resume_listener(struct listener *l, int lpx, int lli)
{
	struct proxy *px = l->bind_conf->frontend;
	int ret = 1;

	if (!lpx && px)
		HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);

	if (!lli)
		HA_RWLOCK_WRLOCK(LISTENER_LOCK, &l->lock);

	/* check that another thread didn't to the job in parallel (e.g. at the
	 * end of listen_accept() while we'd come from dequeue_all_listeners().
	 */
	if (MT_LIST_INLIST(&l->wait_queue))
		goto end;

	if (!(l->flags & LI_F_FINALIZED) || l->state == LI_READY)
		goto end;

	if (l->rx.proto->resume) {
		ret = l->rx.proto->resume(l);
		if (!ret)
			goto end; /* failure to resume */
	}

	if (l->bind_conf->maxconn && l->nbconn >= l->bind_conf->maxconn) {
		l->rx.proto->disable(l);
		listener_set_state(l, LI_FULL);
		goto done;
	}

	l->rx.proto->enable(l);
	listener_set_state(l, LI_READY);

  done:
	if (px && (l->flags & LI_F_SUSPENDED))
		px->li_suspended--;
	l->flags &= ~LI_F_SUSPENDED;

	if (px && (px->flags & PR_FL_PAUSED) && !px->li_suspended) {
		/* PROXY_LOCK is required */
		proxy_cond_resume(px);
		ha_warning("Resumed %s %s.\n", proxy_cap_str(px->cap), px->id);
		send_log(px, LOG_WARNING, "Resumed %s %s.\n", proxy_cap_str(px->cap), px->id);
	}
  end:
	if (!lli)
		HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &l->lock);

	if (!lpx && px)
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);

	return ret;
}

/* Same as resume_listener(), but will only work to resume from
 * LI_FULL or LI_LIMITED states because we try to relax listeners that
 * were temporarily restricted and not to resume inactive listeners that
 * may have been paused or completely stopped in the meantime.
 * Returns positive value for success and 0 for failure.
 * It will need to operate under the proxy's lock and the listener's lock.
 * The caller is responsible for indicating in lpx, lli whether the respective
 * locks are already held (non-zero) or not (zero) so that the function pick
 * the missing ones, in this order.
 */
int relax_listener(struct listener *l, int lpx, int lli)
{
	struct proxy *px = l->bind_conf->frontend;
	int ret = 1;

	if (!lpx && px)
		HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);

	if (!lli)
		HA_RWLOCK_WRLOCK(LISTENER_LOCK, &l->lock);

	if (l->state != LI_FULL && l->state != LI_LIMITED)
		goto end; /* listener may be suspended or even stopped */
	ret = resume_listener(l, 1, 1);

 end:
	if (!lli)
		HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &l->lock);

	if (!lpx && px)
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);

	return ret;
}

/* Marks a ready listener as full so that the stream code tries to re-enable
 * it upon next close() using relax_listener().
 */
static void listener_full(struct listener *l)
{
	HA_RWLOCK_WRLOCK(LISTENER_LOCK, &l->lock);
	if (l->state >= LI_READY) {
		MT_LIST_DELETE(&l->wait_queue);
		if (l->state != LI_FULL) {
			l->rx.proto->disable(l);
			listener_set_state(l, LI_FULL);
		}
	}
	HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &l->lock);
}

/* Marks a ready listener as limited so that we only try to re-enable it when
 * resources are free again. It will be queued into the specified queue.
 */
static void limit_listener(struct listener *l, struct mt_list *list)
{
	HA_RWLOCK_WRLOCK(LISTENER_LOCK, &l->lock);
	if (l->state == LI_READY) {
		MT_LIST_TRY_APPEND(list, &l->wait_queue);
		l->rx.proto->disable(l);
		listener_set_state(l, LI_LIMITED);
	}
	HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &l->lock);
}

/* Dequeues all listeners waiting for a resource the global wait queue */
void dequeue_all_listeners()
{
	struct listener *listener;

	while ((listener = MT_LIST_POP(&global_listener_queue, struct listener *, wait_queue))) {
		/* This cannot fail because the listeners are by definition in
		 * the LI_LIMITED state.
		 */
		relax_listener(listener, 0, 0);
	}
}

/* Dequeues all listeners waiting for a resource in proxy <px>'s queue
 * The caller is responsible for indicating in lpx, whether the proxy's lock
 * is already held (non-zero) or not (zero) so that this information can be
 * passed to relax_listener
*/
void dequeue_proxy_listeners(struct proxy *px, int lpx)
{
	struct listener *listener;

	while ((listener = MT_LIST_POP(&px->listener_queue, struct listener *, wait_queue))) {
		/* This cannot fail because the listeners are by definition in
		 * the LI_LIMITED state.
		 */
		relax_listener(listener, lpx, 0);
	}
}


/* default function used to unbind a listener. This is for use by standard
 * protocols working on top of accepted sockets. The receiver's rx_unbind()
 * will automatically be used after the listener is disabled if the socket is
 * still bound. This must be used under the listener's lock.
 */
void default_unbind_listener(struct listener *listener)
{
	if (listener->state <= LI_ASSIGNED)
		goto out_close;

	if (listener->rx.fd == -1) {
		listener_set_state(listener, LI_ASSIGNED);
		goto out_close;
	}

	if (listener->state >= LI_READY) {
		listener->rx.proto->disable(listener);
		if (listener->rx.flags & RX_F_BOUND)
			listener_set_state(listener, LI_LISTEN);
	}

 out_close:
	if (listener->rx.flags & RX_F_BOUND)
		listener->rx.proto->rx_unbind(&listener->rx);
}

/* This function closes the listening socket for the specified listener,
 * provided that it's already in a listening state. The protocol's unbind()
 * is called to put the listener into LI_ASSIGNED or LI_LISTEN and handle
 * the unbinding tasks. The listener enters then the LI_ASSIGNED state if
 * the receiver is unbound. Must be called with the lock held.
 */
void do_unbind_listener(struct listener *listener)
{
	MT_LIST_DELETE(&listener->wait_queue);

	if (listener->rx.proto->unbind)
		listener->rx.proto->unbind(listener);

	/* we may have to downgrade the listener if the rx was closed */
	if (!(listener->rx.flags & RX_F_BOUND) && listener->state > LI_ASSIGNED)
		listener_set_state(listener, LI_ASSIGNED);
}

/* This function closes the listening socket for the specified listener,
 * provided that it's already in a listening state. The listener enters the
 * LI_ASSIGNED state, except if the FD is not closed, in which case it may
 * remain in LI_LISTEN. This function is intended to be used as a generic
 * function for standard protocols.
 */
void unbind_listener(struct listener *listener)
{
	HA_RWLOCK_WRLOCK(LISTENER_LOCK, &listener->lock);
	do_unbind_listener(listener);
	HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &listener->lock);
}

/* creates one or multiple listeners for bind_conf <bc> on sockaddr <ss> on port
 * range <portl> to <porth>, and possibly attached to fd <fd> (or -1 for auto
 * allocation). The address family is taken from ss->ss_family, and the protocol
 * passed in <proto> must be usable on this family. The protocol's default iocb
 * is automatically preset as the receivers' iocb. The number of jobs and
 * listeners is automatically increased by the number of listeners created. It
 * returns non-zero on success, zero on error with the error message set in <err>.
 */
int create_listeners(struct bind_conf *bc, const struct sockaddr_storage *ss,
                     int portl, int porth, int fd, struct protocol *proto, char **err)
{
	struct listener *l;
	int port;

	for (port = portl; port <= porth; port++) {
		l = calloc(1, sizeof(*l));
		if (!l) {
			memprintf(err, "out of memory");
			return 0;
		}
		l->obj_type = OBJ_TYPE_LISTENER;
		LIST_APPEND(&bc->frontend->conf.listeners, &l->by_fe);
		LIST_APPEND(&bc->listeners, &l->by_bind);
		l->bind_conf = bc;
		l->rx.settings = &bc->settings;
		l->rx.owner = l;
		l->rx.iocb = proto->default_iocb;
		l->rx.fd = fd;

		l->rx.rhttp.task = NULL;
		l->rx.rhttp.srv = NULL;
		l->rx.rhttp.pend_conn = NULL;

		memcpy(&l->rx.addr, ss, sizeof(*ss));
		if (proto->fam->set_port)
			proto->fam->set_port(&l->rx.addr, port);

		MT_LIST_INIT(&l->wait_queue);
		listener_set_state(l, LI_INIT);

		proto->add(proto, l);

		if (fd != -1)
			l->rx.flags |= RX_F_INHERITED;

		guid_init(&l->guid);

		l->extra_counters = NULL;

		HA_RWLOCK_INIT(&l->lock);
		_HA_ATOMIC_INC(&jobs);
		_HA_ATOMIC_INC(&listeners);
	}
	return 1;
}

/* Optionally allocates a new shard info (if si == NULL) for receiver rx and
 * assigns it to it, or attaches to an existing one. If the rx already had a
 * shard_info, it is simply returned. It is illegal to call this function with
 * an rx that's part of a group that is already attached. Attaching means the
 * shard_info's thread count and group count are updated so the rx's group is
 * added to the shard_info's group mask. The rx are added to the members in the
 * attachment order, though it must not matter. It is meant for boot time setup
 * and is not thread safe. NULL is returned on allocation failure.
 */
struct shard_info *shard_info_attach(struct receiver *rx, struct shard_info *si)
{
	if (rx->shard_info)
		return rx->shard_info;

	if (!si) {
		si = calloc(1, sizeof(*si));
		if (!si)
			return NULL;

		si->ref = rx;
	}

	rx->shard_info = si;
	BUG_ON (si->tgroup_mask & 1UL << (rx->bind_tgroup - 1));
	si->tgroup_mask |= 1UL << (rx->bind_tgroup - 1);
	si->nbgroups     = my_popcountl(si->tgroup_mask);
	si->nbthreads   += my_popcountl(rx->bind_thread);
	si->members[si->nbgroups - 1] = rx;
	return si;
}

/* Detaches the rx from an optional shard_info it may be attached to. If so,
 * the thread counts, group masks and refcounts are updated. The members list
 * remains contiguous by replacing the current entry with the last one. The
 * reference continues to point to the first receiver. If the group count
 * reaches zero, the shard_info is automatically released.
 */
void shard_info_detach(struct receiver *rx)
{
	struct shard_info *si = rx->shard_info;
	uint gr;

	if (!si)
		return;

	rx->shard_info = NULL;

	/* find the member slot this rx was attached to */
	for (gr = 0; gr < MAX_TGROUPS && si->members[gr] != rx; gr++)
		;

	BUG_ON(gr == MAX_TGROUPS);

	si->nbthreads   -= my_popcountl(rx->bind_thread);
	si->tgroup_mask &= ~(1UL << (rx->bind_tgroup - 1));
	si->nbgroups     = my_popcountl(si->tgroup_mask);

	/* replace the member by the last one. If we removed the reference, we
	 * have to switch to another one. It's always the first entry so we can
	 * simply enforce it upon every removal.
	 */
	si->members[gr] = si->members[si->nbgroups];
	si->members[si->nbgroups] = NULL;
	si->ref = si->members[0];

	if (!si->nbgroups)
		free(si);
}

/* clones listener <src> and returns the new one. All dynamically allocated
 * fields are reallocated (name for now). The new listener is inserted before
 * the original one in the bind_conf and frontend lists. This allows it to be
 * duplicated while iterating over the current list. The original listener must
 * only be in the INIT or ASSIGNED states, and the new listener will only be
 * placed into the INIT state. The counters are always set to NULL. Maxsock is
 * updated. Returns NULL on allocation error. The shard_info is never taken so
 * that the caller can decide what to do with it depending on how it intends to
 * clone the listener.
 */
struct listener *clone_listener(struct listener *src)
{
	struct listener *l;

	l = calloc(1, sizeof(*l));
	if (!l)
		goto oom1;
	memcpy(l, src, sizeof(*l));

	l->luid = 0; // don't dup the listener's ID!
	if (l->name) {
		l->name = strdup(l->name);
		if (!l->name)
			goto oom2;
	}

	l->rx.owner = l;
	l->rx.shard_info = NULL;
	l->state = LI_INIT;
	l->counters = NULL;
	l->extra_counters = NULL;

	LIST_APPEND(&src->by_fe,   &l->by_fe);
	LIST_APPEND(&src->by_bind, &l->by_bind);

	MT_LIST_INIT(&l->wait_queue);

	l->rx.proto->add(l->rx.proto, l);

	HA_RWLOCK_INIT(&l->lock);
	_HA_ATOMIC_INC(&jobs);
	_HA_ATOMIC_INC(&listeners);
	global.maxsock++;
	return l;

 oom2:
	free(l);
 oom1:
	return NULL;
}

/* Delete a listener from its protocol's list of listeners. The listener's
 * state is automatically updated from LI_ASSIGNED to LI_INIT. The protocol's
 * number of listeners is updated, as well as the global number of listeners
 * and jobs. Note that the listener must have previously been unbound. This
 * is a low-level function expected to be called with the proto_lock and the
 * listener's lock held.
 */
void __delete_listener(struct listener *listener)
{
	if (listener->state == LI_ASSIGNED) {
		listener_set_state(listener, LI_INIT);
		LIST_DELETE(&listener->rx.proto_list);
		shard_info_detach(&listener->rx);
		listener->rx.proto->nb_receivers--;
		_HA_ATOMIC_DEC(&jobs);
		_HA_ATOMIC_DEC(&listeners);
	}
}

/* Delete a listener from its protocol's list of listeners (please check
 * __delete_listener() above). The proto_lock and the listener's lock will
 * be grabbed in this order.
 */
void delete_listener(struct listener *listener)
{
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	HA_RWLOCK_WRLOCK(LISTENER_LOCK, &listener->lock);
	__delete_listener(listener);
	HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &listener->lock);
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* Returns a suitable value for a listener's backlog. It uses the listener's,
 * otherwise the frontend's backlog, otherwise the listener's maxconn,
 * otherwise the frontend's maxconn, otherwise 1024.
 */
int listener_backlog(const struct listener *l)
{
	if (l->bind_conf->backlog)
		return l->bind_conf->backlog;

	if (l->bind_conf->frontend->backlog)
		return l->bind_conf->frontend->backlog;

	if (l->bind_conf->maxconn)
		return l->bind_conf->maxconn;

	if (l->bind_conf->frontend->maxconn)
		return l->bind_conf->frontend->maxconn;

	return 1024;
}

/* Returns true if listener <l> must check maxconn limit prior to accept. */
static inline int listener_uses_maxconn(const struct listener *l)
{
	return !(l->bind_conf->options & (BC_O_UNLIMITED|BC_O_XPRT_MAXCONN));
}

/* This function is called on a read event from a listening socket, corresponding
 * to an accept. It tries to accept as many connections as possible, and for each
 * calls the listener's accept handler (generally the frontend's accept handler).
 */
void listener_accept(struct listener *l)
{
	void (*bind_tid_commit)(struct connection *) __maybe_unused;
	struct connection *cli_conn;
	struct proxy *p;
	unsigned int max_accept;
	int next_conn = 0;
	int next_feconn = 0;
	int next_actconn = 0;
	int expire;
	int ret;

	p = l->bind_conf->frontend;
	bind_tid_commit = l->rx.proto->bind_tid_commit;

	/* if l->bind_conf->maxaccept is -1, then max_accept is UINT_MAX. It is
	 * not really illimited, but it is probably enough.
	 */
	max_accept = l->bind_conf->maxaccept ? l->bind_conf->maxaccept : 1;

	if (!(l->bind_conf->options & BC_O_UNLIMITED) && global.sps_lim) {
		int max = freq_ctr_remain(&global.sess_per_sec, global.sps_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			expire = tick_add(now_ms, next_event_delay(&global.sess_per_sec, global.sps_lim, 0));
			goto limit_global;
		}

		if (max_accept > max)
			max_accept = max;
	}

	if (!(l->bind_conf->options & BC_O_UNLIMITED) && global.cps_lim) {
		int max = freq_ctr_remain(&global.conn_per_sec, global.cps_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			expire = tick_add(now_ms, next_event_delay(&global.conn_per_sec, global.cps_lim, 0));
			goto limit_global;
		}

		if (max_accept > max)
			max_accept = max;
	}
#ifdef USE_OPENSSL
	if (!(l->bind_conf->options & BC_O_UNLIMITED) && global.ssl_lim &&
	    l->bind_conf && l->bind_conf->options & BC_O_USE_SSL) {
		int max = freq_ctr_remain(&global.ssl_per_sec, global.ssl_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			expire = tick_add(now_ms, next_event_delay(&global.ssl_per_sec, global.ssl_lim, 0));
			goto limit_global;
		}

		if (max_accept > max)
			max_accept = max;
	}
#endif
	if (p && p->fe_sps_lim) {
		int max = freq_ctr_remain(&p->fe_counters.sess_per_sec, p->fe_sps_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			expire = tick_add(now_ms, next_event_delay(&p->fe_counters.sess_per_sec, p->fe_sps_lim, 0));
			goto limit_proxy;
		}

		if (max_accept > max)
			max_accept = max;
	}

	/* Note: if we fail to allocate a connection because of configured
	 * limits, we'll schedule a new attempt worst 1 second later in the
	 * worst case. If we fail due to system limits or temporary resource
	 * shortage, we try again 100ms later in the worst case.
	 */
	for (; max_accept; next_conn = next_feconn = next_actconn = 0, max_accept--) {
		unsigned int count;
		int status;
		__decl_thread(unsigned long mask);

		/* pre-increase the number of connections without going too far.
		 * We process the listener, then the proxy, then the process.
		 * We know which ones to unroll based on the next_xxx value.
		 */
		do {
			count = l->nbconn;
			if (unlikely(l->bind_conf->maxconn && count >= l->bind_conf->maxconn)) {
				/* the listener was marked full or another
				 * thread is going to do it.
				 */
				next_conn = 0;
				listener_full(l);
				goto end;
			}
			next_conn = count + 1;
		} while (!_HA_ATOMIC_CAS(&l->nbconn, (int *)(&count), next_conn));

		if (p) {
			do {
				count = p->feconn;
				if (unlikely(count >= p->maxconn)) {
					/* the frontend was marked full or another
					 * thread is going to do it.
					 */
					next_feconn = 0;
					expire = TICK_ETERNITY;
					goto limit_proxy;
				}
				next_feconn = count + 1;
			} while (!_HA_ATOMIC_CAS(&p->feconn, &count, next_feconn));
		}

		if (listener_uses_maxconn(l)) {
			next_actconn = increment_actconn();
			if (!next_actconn) {
				/* the process was marked full or another
				 * thread is going to do it.
				 */
				expire = tick_add(now_ms, 1000); /* try again in 1 second */
				goto limit_global;
			}
		}

		/* be careful below, the listener might be shutting down in
		 * another thread on error and we must not dereference its
		 * FD without a bit of protection.
		 */
		cli_conn = NULL;
		status = CO_AC_PERMERR;

		HA_RWLOCK_RDLOCK(LISTENER_LOCK, &l->lock);
		if (l->rx.flags & RX_F_BOUND)
			cli_conn = l->rx.proto->accept_conn(l, &status);
		HA_RWLOCK_RDUNLOCK(LISTENER_LOCK, &l->lock);

		if (!cli_conn) {
			switch (status) {
			case CO_AC_DONE:
				goto end;

			case CO_AC_RETRY: /* likely a signal */
				_HA_ATOMIC_DEC(&l->nbconn);
				if (p)
					_HA_ATOMIC_DEC(&p->feconn);
				if (listener_uses_maxconn(l))
					_HA_ATOMIC_DEC(&actconn);
				continue;

			case CO_AC_YIELD:
				max_accept = 0;
				goto end;

			default:
				goto transient_error;
			}
		}

		/* The connection was accepted, it must be counted as such */
		if (l->counters)
			HA_ATOMIC_UPDATE_MAX(&l->counters->conn_max, next_conn);

		if (p) {
			HA_ATOMIC_UPDATE_MAX(&p->fe_counters.conn_max, next_feconn);
			proxy_inc_fe_conn_ctr(l, p);
		}

		if (!(l->bind_conf->options & BC_O_UNLIMITED)) {
			count = update_freq_ctr(&global.conn_per_sec, 1);
			HA_ATOMIC_UPDATE_MAX(&global.cps_max, count);
		}

		_HA_ATOMIC_INC(&activity[tid].accepted);

		/* count the number of times an accepted connection resulted in
		 * maxconn being reached.
		 */
		if (unlikely(_HA_ATOMIC_LOAD(&actconn) + 1 >= global.maxconn))
			_HA_ATOMIC_INC(&maxconn_reached);

		/* past this point, l->bind_conf->accept() will automatically decrement
		 * l->nbconn, feconn and actconn once done. Setting next_*conn=0
		 * allows the error path not to rollback on nbconn. It's more
		 * convenient than duplicating all exit labels.
		 */
		next_conn = 0;
		next_feconn = 0;
		next_actconn = 0;


#if defined(USE_THREAD)
		if (!(global.tune.options & GTUNE_LISTENER_MQ_ANY) || stopping)
			goto local_accept;

		/* we want to perform thread rebalancing if the listener is
		 * bound to more than one thread or if it's part of a shard
		 * with more than one listener.
		 */
		mask = l->rx.bind_thread & _HA_ATOMIC_LOAD(&tg->threads_enabled);
		if (l->rx.shard_info || atleast2(mask)) {
			struct accept_queue_ring *ring;
			struct listener *new_li;
			uint r1, r2, t, t1, t2;
			ulong n0, n1;
			const struct tgroup_info *g1, *g2;
			ulong m1, m2;
			ulong *thr_idx_ptr;

			/* The principle is that we have two running indexes,
			 * each visiting in turn all threads bound to this
			 * listener's shard. The connection will be assigned to
			 * the one with the least connections, and the other
			 * one will be updated. This provides a good fairness
			 * on short connections (round robin) and on long ones
			 * (conn count), without ever missing any idle thread.
			 * Each thread number is encoded as a combination of
			 * times the receiver number and its local thread
			 * number from 0 to MAX_THREADS_PER_GROUP - 1. The two
			 * indexes are stored as 10/12 bit numbers in the thr_idx
			 * array, since there are up to LONGBITS threads and
			 * groups that can be represented. They are represented
			 * like this:
			 *           31:20    19:15   14:10    9:5     4:0
			 *   32b: [ counter | r2num | t2num | r1num | t1num ]
			 *
			 *           63:24    23:18   17:12   11:6     5:0
			 *   64b: [ counter | r2num | t2num | r1num | t1num ]
			 *
			 * The change counter is only used to avoid swapping too
			 * old a value when the value loops back.
			 *
			 * In the loop below we have this for each index:
			 *   - n is the thread index
			 *   - r is the receiver number
			 *   - g is the receiver's thread group
			 *   - t is the thread number in this receiver
			 *   - m is the receiver's thread mask shifted by the thread number
			 */

			/* keep a copy for the final update. thr_idx is composite
			 * and made of (n2<<16) + n1.
			 */
			thr_idx_ptr = l->rx.shard_info ? &((struct listener *)(l->rx.shard_info->ref->owner))->thr_idx : &l->thr_idx;
			while (1) {
				int q0, q1, q2;

				/* calculate r1/g1/t1 first (ascending idx) */
				n0 = _HA_ATOMIC_LOAD(thr_idx_ptr);
				new_li = NULL;

				t1 = (uint)n0 & (LONGBITS - 1);
				r1 = ((uint)n0 / LONGBITS) & (LONGBITS - 1);

				while (1) {
					if (l->rx.shard_info) {
						/* multiple listeners, take the group into account */
						if (r1 >= l->rx.shard_info->nbgroups)
							r1 = 0;

						g1 = &ha_tgroup_info[l->rx.shard_info->members[r1]->bind_tgroup - 1];
						m1 = l->rx.shard_info->members[r1]->bind_thread;
					} else {
						/* single listener */
						r1 = 0;
						g1 = tg;
						m1 = l->rx.bind_thread;
					}
					m1 &= _HA_ATOMIC_LOAD(&g1->threads_enabled);
					m1 >>= t1;

					/* find first existing thread */
					if (unlikely(!(m1 & 1))) {
						m1 &= ~1UL;
						if (!m1) {
							/* no more threads here, switch to
							 * first thread of next group.
							 */
							t1 = 0;
							if (l->rx.shard_info)
								r1++;
							/* loop again */
							continue;
						}
						t1 += my_ffsl(m1) - 1;
					}
					/* done: r1 and t1 are OK */
					break;
				}

				/* now r2/g2/t2 (descending idx) */
				t2 = ((uint)n0 / LONGBITS / LONGBITS) & (LONGBITS - 1);
				r2 = ((uint)n0 / LONGBITS / LONGBITS / LONGBITS) & (LONGBITS - 1);

				/* if running in round-robin mode ("fair"), we don't need
				 * to go further.
				 */
				if ((global.tune.options & GTUNE_LISTENER_MQ_ANY) == GTUNE_LISTENER_MQ_FAIR) {
					t = g1->base + t1;
					if (l->rx.shard_info && t != tid)
						new_li = l->rx.shard_info->members[r1]->owner;
					goto updt_t1;
				}

				while (1) {
					if (l->rx.shard_info) {
						/* multiple listeners, take the group into account */
						if (r2 >= l->rx.shard_info->nbgroups)
							r2 = l->rx.shard_info->nbgroups - 1;

						g2 = &ha_tgroup_info[l->rx.shard_info->members[r2]->bind_tgroup - 1];
						m2 = l->rx.shard_info->members[r2]->bind_thread;
					} else {
						/* single listener */
						r2 = 0;
						g2 = tg;
						m2 = l->rx.bind_thread;
					}
					m2 &= _HA_ATOMIC_LOAD(&g2->threads_enabled);
					m2 &= nbits(t2 + 1);

					/* find previous existing thread */
					if (unlikely(!(m2 & (1UL << t2)) || (g1 == g2 && t1 == t2))) {
						/* highest bit not set or colliding threads, let's check
						 * if we still have other threads available after this
						 * one.
						 */
						m2 &= ~(1UL << t2);
						if (!m2) {
							/* no more threads here, switch to
							 * last thread of previous group.
							 */
							t2 = MAX_THREADS_PER_GROUP - 1;
							if (l->rx.shard_info)
								r2--;
							/* loop again */
							continue;
						}
						t2 = my_flsl(m2) - 1;
					}
					/* done: r2 and t2 are OK */
					break;
				}

				/* tests show that it's worth checking that other threads have not
				 * already changed the index to save the rest of the calculation,
				 * or we'd have to redo it anyway.
				 */
				if (n0 != _HA_ATOMIC_LOAD(thr_idx_ptr))
					continue;

				/* here we have (r1,g1,t1) that designate the first receiver, its
				 * thread group and local thread, and (r2,g2,t2) that designate
				 * the second receiver, its thread group and local thread. We'll
				 * also consider the local thread with q0.
				 */
				q0 = accept_queue_ring_len(&accept_queue_rings[tid]);
				q1 = accept_queue_ring_len(&accept_queue_rings[g1->base + t1]);
				q2 = accept_queue_ring_len(&accept_queue_rings[g2->base + t2]);

				/* add to this the currently active connections */
				q0 += _HA_ATOMIC_LOAD(&l->thr_conn[ti->ltid]);
				if (l->rx.shard_info) {
					q1 += _HA_ATOMIC_LOAD(&((struct listener *)l->rx.shard_info->members[r1]->owner)->thr_conn[t1]);
					q2 += _HA_ATOMIC_LOAD(&((struct listener *)l->rx.shard_info->members[r2]->owner)->thr_conn[t2]);
				} else {
					q1 += _HA_ATOMIC_LOAD(&l->thr_conn[t1]);
					q2 += _HA_ATOMIC_LOAD(&l->thr_conn[t2]);
				}

				/* we have 3 possibilities now :
				 *   q1 < q2 : t1 is less loaded than t2, so we pick it
				 *             and update t2 (since t1 might still be
				 *             lower than another thread)
				 *   q1 > q2 : t2 is less loaded than t1, so we pick it
				 *             and update t1 (since t2 might still be
				 *             lower than another thread)
				 *   q1 = q2 : both are equally loaded, thus we pick t1
				 *             and update t1 as it will become more loaded
				 *             than t2.
				 * On top of that, if in the end the current thread appears
				 * to be as good of a deal, we'll prefer it over a foreign
				 * one as it will improve locality and avoid a migration.
				 */

				if (q1 - q2 < 0) {
					t = g1->base + t1;
					if (q0 <= q1)
						t = tid;

					if (l->rx.shard_info && t != tid)
						new_li = l->rx.shard_info->members[r1]->owner;

					t2--;
					if (t2 >= MAX_THREADS_PER_GROUP) {
						if (l->rx.shard_info)
							r2--;
						t2 = MAX_THREADS_PER_GROUP - 1;
					}
				}
				else if (q1 - q2 > 0) {
					t = g2->base + t2;
					if (q0 <= q2)
						t = tid;

					if (l->rx.shard_info && t != tid)
						new_li = l->rx.shard_info->members[r2]->owner;
					goto updt_t1;
				}
				else { // q1 == q2
					t = g1->base + t1;
					if (q0 < q1) // local must be strictly better than both
						t = tid;

					if (l->rx.shard_info && t != tid)
						new_li = l->rx.shard_info->members[r1]->owner;
				updt_t1:
					t1++;
					if (t1 >= MAX_THREADS_PER_GROUP) {
						if (l->rx.shard_info)
							r1++;
						t1 = 0;
					}
				}

				/* The target thread number is in <t> now. Let's
				 * compute the new index and try to update it.
				 */

				/* take previous counter and increment it */
				n1  = n0 & -(ulong)(LONGBITS * LONGBITS * LONGBITS * LONGBITS);
				n1 += LONGBITS * LONGBITS * LONGBITS * LONGBITS;
				n1 += (((r2 * LONGBITS) + t2) * LONGBITS * LONGBITS);
				n1 += (r1 * LONGBITS) + t1;
				if (likely(_HA_ATOMIC_CAS(thr_idx_ptr, &n0, n1)))
					break;

				/* bah we lost the race, try again */
				__ha_cpu_relax();
			} /* end of main while() loop */

			/* we may need to update the listener in the connection
			 * if we switched to another group.
			 */
			if (new_li)
				cli_conn->target = &new_li->obj_type;

			/* here we have the target thread number in <t> and we hold a
			 * reservation in the target ring.
			 */

			if (l->rx.proto->bind_tid_prep) {
				if (l->rx.proto->bind_tid_prep(cli_conn, t)) {
					/* Failed migration, stay on the same thread. */
					goto local_accept;
				}
			}

			/* We successfully selected the best thread "t" for this
			 * connection. We use deferred accepts even if it's the
			 * local thread because tests show that it's the best
			 * performing model, likely due to better cache locality
			 * when processing this loop.
			 */
			ring = &accept_queue_rings[t];
			if (accept_queue_push_mp(ring, cli_conn, bind_tid_commit)) {
				_HA_ATOMIC_INC(&activity[t].accq_pushed);
				tasklet_wakeup(ring->tasklet);

				continue;
			}
			/* If the ring is full we do a synchronous accept on
			 * the local thread here.
			 */
			_HA_ATOMIC_INC(&activity[t].accq_full);

			if (l->rx.proto->bind_tid_reset)
				l->rx.proto->bind_tid_reset(cli_conn);
		}
#endif // USE_THREAD

 local_accept:
		/* restore the connection's listener in case we failed to migrate above */
		cli_conn->target = &l->obj_type;
		_HA_ATOMIC_INC(&l->thr_conn[ti->ltid]);
		ret = l->bind_conf->accept(cli_conn);
		if (unlikely(ret <= 0)) {
			/* The connection was closed by stream_accept(). Either
			 * we just have to ignore it (ret == 0) or it's a critical
			 * error due to a resource shortage, and we must stop the
			 * listener (ret < 0).
			 */
			if (ret == 0) /* successful termination */
				continue;

			goto transient_error;
		}

		/* increase the per-process number of cumulated sessions, this
		 * may only be done once l->bind_conf->accept() has accepted the
		 * connection.
		 */
		if (!(l->bind_conf->options & BC_O_UNLIMITED)) {
			count = update_freq_ctr(&global.sess_per_sec, 1);
			HA_ATOMIC_UPDATE_MAX(&global.sps_max, count);
		}
#ifdef USE_OPENSSL
		if (!(l->bind_conf->options & BC_O_UNLIMITED) &&
		    l->bind_conf && l->bind_conf->options & BC_O_USE_SSL) {
			count = update_freq_ctr(&global.ssl_per_sec, 1);
			HA_ATOMIC_UPDATE_MAX(&global.ssl_max, count);
		}
#endif

		_HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_STUCK); // this thread is still running
	} /* end of for (max_accept--) */

 end:
	if (next_conn)
		_HA_ATOMIC_DEC(&l->nbconn);

	if (p && next_feconn)
		_HA_ATOMIC_DEC(&p->feconn);

	if (next_actconn)
		_HA_ATOMIC_DEC(&actconn);

	if ((l->state == LI_FULL && (!l->bind_conf->maxconn || l->nbconn < l->bind_conf->maxconn)) ||
	    (l->state == LI_LIMITED &&
	     ((!p || p->feconn < p->maxconn) && (actconn < global.maxconn) &&
	      (!tick_isset(global_listener_queue_task->expire) ||
	       tick_is_expired(global_listener_queue_task->expire, now_ms))))) {
		/* at least one thread has to this when quitting */
		relax_listener(l, 0, 0);

		/* Dequeues all of the listeners waiting for a resource */
		dequeue_all_listeners();

		if (p && !MT_LIST_ISEMPTY(&p->listener_queue) &&
		    (!p->fe_sps_lim || freq_ctr_remain(&p->fe_counters.sess_per_sec, p->fe_sps_lim, 0) > 0))
			dequeue_proxy_listeners(p, 0);
	}
	return;

 transient_error:
	/* pause the listener for up to 100 ms */
	expire = tick_add(now_ms, 100);

	/* This may be a shared socket that was paused by another process.
	 * Let's put it to pause in this case.
	 */
	if (l->rx.proto->rx_listening(&l->rx) == 0) {
		suspend_listener(l, 0, 0);
		goto end;
	}

 limit_global:
	/* (re-)queue the listener to the global queue and set it to expire no
	 * later than <expire> ahead. The listener turns to LI_LIMITED.
	 */
	limit_listener(l, &global_listener_queue);
	HA_RWLOCK_RDLOCK(LISTENER_LOCK, &global_listener_rwlock);
	task_schedule(global_listener_queue_task, expire);
	HA_RWLOCK_RDUNLOCK(LISTENER_LOCK, &global_listener_rwlock);
	goto end;

 limit_proxy:
	/* (re-)queue the listener to the proxy's queue and set it to expire no
	 * later than <expire> ahead. The listener turns to LI_LIMITED.
	 */
	limit_listener(l, &p->listener_queue);
	if (p->task && tick_isset(expire))
		task_schedule(p->task, expire);
	goto end;
}

/* Notify the listener that a connection initiated from it was released. This
 * is used to keep the connection count consistent and to possibly re-open
 * listening when it was limited.
 */
void listener_release(struct listener *l)
{
	struct proxy *fe = l->bind_conf->frontend;

	if (listener_uses_maxconn(l))
		_HA_ATOMIC_DEC(&actconn);
	if (fe)
		_HA_ATOMIC_DEC(&fe->feconn);
	_HA_ATOMIC_DEC(&l->nbconn);
	_HA_ATOMIC_DEC(&l->thr_conn[ti->ltid]);

	if (l->state == LI_FULL || l->state == LI_LIMITED)
		relax_listener(l, 0, 0);

	/* Dequeues all of the listeners waiting for a resource */
	dequeue_all_listeners();

	if (fe && !MT_LIST_ISEMPTY(&fe->listener_queue) &&
	    (!fe->fe_sps_lim || freq_ctr_remain(&fe->fe_counters.sess_per_sec, fe->fe_sps_lim, 0) > 0))
		dequeue_proxy_listeners(fe, 0);
	else if (fe) {
		unsigned int wait;
		int expire = TICK_ETERNITY;

		if (fe->task && fe->fe_sps_lim &&
		    (wait = next_event_delay(&fe->fe_counters.sess_per_sec,fe->fe_sps_lim, 0))) {
			/* we're blocking because a limit was reached on the number of
			 * requests/s on the frontend. We want to re-check ASAP, which
			 * means in 1 ms before estimated expiration date, because the
			 * timer will have settled down.
			 */
			expire = tick_first(fe->task->expire, tick_add(now_ms, wait));
			if (tick_isset(expire))
				task_schedule(fe->task, expire);
		}
	}
}

/* Initializes the listener queues. Returns 0 on success, otherwise ERR_* flags */
static int listener_queue_init()
{
	global_listener_queue_task = task_new_anywhere();
	if (!global_listener_queue_task) {
		ha_alert("Out of memory when initializing global listener queue\n");
		return ERR_FATAL|ERR_ABORT;
	}
	/* very simple initialization, users will queue the task if needed */
	global_listener_queue_task->context = NULL; /* not even a context! */
	global_listener_queue_task->process = manage_global_listener_queue;
	HA_RWLOCK_INIT(&global_listener_rwlock);

	return 0;
}

static void listener_queue_deinit()
{
	task_destroy(global_listener_queue_task);
	global_listener_queue_task = NULL;
}

REGISTER_CONFIG_POSTPARSER("multi-threaded listener queue", listener_queue_init);
REGISTER_POST_DEINIT(listener_queue_deinit);


/* This is the global management task for listeners. It enables listeners waiting
 * for global resources when there are enough free resource, or at least once in
 * a while. It is designed to be called as a task. It's exported so that it's easy
 * to spot in "show tasks" or "show profiling".
 */
struct task *manage_global_listener_queue(struct task *t, void *context, unsigned int state)
{
	/* If there are still too many concurrent connections, let's wait for
	 * some of them to go away. We don't need to re-arm the timer because
	 * each of them will scan the queue anyway.
	 */
	if (unlikely(actconn >= global.maxconn))
		goto out;

	/* We should periodically try to enable listeners waiting for a global
	 * resource here, because it is possible, though very unlikely, that
	 * they have been blocked by a temporary lack of global resource such
	 * as a file descriptor or memory and that the temporary condition has
	 * disappeared.
	 */
	dequeue_all_listeners();

 out:
	HA_RWLOCK_WRLOCK(LISTENER_LOCK, &global_listener_rwlock);
	t->expire = TICK_ETERNITY;
	HA_RWLOCK_WRUNLOCK(LISTENER_LOCK, &global_listener_rwlock);
	return t;
}

/* Applies the thread mask, shards etc to the bind_conf. It normally returns 0
 * otherwie the number of errors. Upon error it may set error codes (ERR_*) in
 * err_code. It is supposed to be called only once very late in the boot process
 * after the bind_conf's thread_set is fixed. The function may emit warnings and
 * alerts. Extra listeners may be created on the fly.
 */
int bind_complete_thread_setup(struct bind_conf *bind_conf, int *err_code)
{
	struct proxy *fe = bind_conf->frontend;
	struct listener *li, *new_li, *ref;
	struct thread_set new_ts;
	int shard, shards, todo, done, grp, dups;
	ulong mask, gmask, bit;
	int cfgerr = 0;
	char *err;

	err = NULL;
	if (thread_resolve_group_mask(&bind_conf->thread_set, 0, &err) < 0) {
		ha_alert("%s '%s': %s in 'bind %s' at [%s:%d].\n",
			 proxy_type_str(fe),
			 fe->id, err, bind_conf->arg, bind_conf->file, bind_conf->line);
		free(err);
		cfgerr++;
		return cfgerr;
	}

	/* apply thread masks and groups to all receivers */
	list_for_each_entry(li, &bind_conf->listeners, by_bind) {
		shards = bind_conf->settings.shards;
		todo = thread_set_count(&bind_conf->thread_set);

		/* special values: -1 = "by-thread", -2 = "by-group" */
		if (shards == -1) {
			if (protocol_supports_flag(li->rx.proto, PROTO_F_REUSEPORT_SUPPORTED))
				shards = todo;
			else {
				if (fe != global.cli_fe)
					ha_diag_warning("[%s:%d]: Disabling per-thread sharding for listener in"
					                " %s '%s' because SO_REUSEPORT is disabled for %s protocol.\n",
					                bind_conf->file, bind_conf->line, proxy_type_str(fe), fe->id, li->rx.proto->name);
				shards = 1;
			}
		}
		else if (shards == -2)
			shards = protocol_supports_flag(li->rx.proto, PROTO_F_REUSEPORT_SUPPORTED) ? my_popcountl(bind_conf->thread_set.grps) : 1;

		/* no more shards than total threads */
		if (shards > todo)
			shards = todo;

		/* We also need to check if an explicit shards count was set and cannot be honored */
		if (shards > 1 && !protocol_supports_flag(li->rx.proto, PROTO_F_REUSEPORT_SUPPORTED)) {
			ha_warning("[%s:%d]: Disabling sharding for listener in %s '%s' because SO_REUSEPORT is disabled for %s protocol.\n",
			           bind_conf->file, bind_conf->line, proxy_type_str(fe), fe->id, li->rx.proto->name);
			shards = 1;
		}

		shard = done = grp = bit = mask = 0;
		new_li = li;

		while (shard < shards) {
			memset(&new_ts, 0, sizeof(new_ts));
			while (grp < global.nbtgroups && done < todo) {
				/* enlarge mask to cover next bit of bind_thread till we
				 * have enough bits for one shard. We restart from the
				 * current grp+bit.
				 */

				/* first let's find the first non-empty group starting at <mask> */
				if (!(bind_conf->thread_set.rel[grp] & ha_tgroup_info[grp].threads_enabled & ~mask)) {
					grp++;
					mask = 0;
					continue;
				}

				/* take next unassigned bit */
				bit = (bind_conf->thread_set.rel[grp] & ~mask) & -(bind_conf->thread_set.rel[grp] & ~mask);
				new_ts.rel[grp] |= bit;
				mask |= bit;
				new_ts.grps |= 1UL << grp;

				done += shards;
			};

			BUG_ON(!new_ts.grps); // no more bits left unassigned

			/* Create all required listeners for all bound groups. If more than one group is
			 * needed, the first receiver serves as a reference, and subsequent ones point to
			 * it. We already have a listener available in new_li() so we only allocate a new
			 * one if we're not on the last one. We count the remaining groups by copying their
			 * mask into <gmask> and dropping the lowest bit at the end of the loop until there
			 * is no more. Ah yes, it's not pretty :-/
			 */
			ref = new_li;
			gmask = new_ts.grps;
			for (dups = 0; gmask; dups++) {
				/* assign the first (and only) thread and group */
				new_li->rx.bind_thread = thread_set_nth_tmask(&new_ts, dups);
				new_li->rx.bind_tgroup = thread_set_nth_group(&new_ts, dups);

				if (dups) {
					/* it has been allocated already in the previous round */
					shard_info_attach(&new_li->rx, ref->rx.shard_info);
					new_li->rx.flags |= RX_F_MUST_DUP;
				}

				gmask &= gmask - 1; // drop lowest bit
				if (gmask) {
					/* yet another listener expected in this shard, let's
					 * chain it.
					 */
					struct listener *tmp_li = clone_listener(new_li);

					if (!tmp_li) {
						ha_alert("Out of memory while trying to allocate extra listener for group %u of shard %d in %s %s\n",
							 new_li->rx.bind_tgroup, shard, proxy_type_str(fe), fe->id);
						cfgerr++;
						*err_code |= ERR_FATAL | ERR_ALERT;
						return cfgerr;
					}

					/* if we're forced to create at least two listeners, we have to
					 * allocate a shared shard_info that's linked to from the reference
					 * and each other listener, so we'll create it here.
					 */
					if (!shard_info_attach(&ref->rx, NULL)) {
						ha_alert("Out of memory while trying to allocate shard_info for listener for group %u of shard %d in %s %s\n",
							 new_li->rx.bind_tgroup, shard, proxy_type_str(fe), fe->id);
						cfgerr++;
						*err_code |= ERR_FATAL | ERR_ALERT;
						return cfgerr;
					}
					/* assign the ID to the first one only */
					new_li->luid = new_li->conf.id.key = tmp_li->luid;
					tmp_li->luid = 0;
					eb32_delete(&tmp_li->conf.id);
					if (tmp_li->luid)
						eb32_insert(&fe->conf.used_listener_id, &new_li->conf.id);
					new_li = tmp_li;
				}
			}
			done -= todo;

			shard++;
			if (shard >= shards)
				break;

			/* create another listener for new shards */
			new_li = clone_listener(li);
			if (!new_li) {
				ha_alert("Out of memory while trying to allocate extra listener for shard %d in %s %s\n",
					 shard, proxy_type_str(fe), fe->id);
				cfgerr++;
				*err_code |= ERR_FATAL | ERR_ALERT;
				return cfgerr;
			}
			/* assign the ID to the first one only */
			new_li->luid = new_li->conf.id.key = li->luid;
			li->luid = 0;
			eb32_delete(&li->conf.id);
			if (li->luid)
				eb32_insert(&fe->conf.used_listener_id, &new_li->conf.id);
		}
	}

	/* success */
	return cfgerr;
}

/* Generate and insert unique GUID for each listeners of <bind_conf> instance
 * if GUID prefix is defined.
 *
 * Returns 0 on success else non-zero.
 */
int bind_generate_guid(struct bind_conf *bind_conf)
{
	struct listener *l;
	char *guid_err = NULL;

	if (!bind_conf->guid_prefix)
		return 0;

	list_for_each_entry(l, &bind_conf->listeners, by_bind) {
		if (bind_conf->guid_idx == (size_t)-1) {
			ha_alert("[%s:%d] : error on GUID generation : Too many listeners.\n",
			         bind_conf->file, bind_conf->line);
			return 1;
		}

		chunk_printf(&trash, "%s-%lld", bind_conf->guid_prefix,
		             (ullong)bind_conf->guid_idx);

		if (guid_insert(&l->obj_type, b_head(&trash), &guid_err)) {
			ha_alert("[%s:%d] : error on GUID generation : %s. "
			         "You may fix it by adjusting guid-prefix.\n",
			         bind_conf->file, bind_conf->line, guid_err);
			ha_free(&guid_err);
			return 1;
		}

		++bind_conf->guid_idx;
	}

	return 0;
}

/*
 * Registers the bind keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void bind_register_keywords(struct bind_kw_list *kwl)
{
	LIST_APPEND(&bind_keywords.list, &kwl->list);
}

/* Return a pointer to the bind keyword <kw>, or NULL if not found. If the
 * keyword is found with a NULL ->parse() function, then an attempt is made to
 * find one with a valid ->parse() function. This way it is possible to declare
 * platform-dependant, known keywords as NULL, then only declare them as valid
 * if some options are met. Note that if the requested keyword contains an
 * opening parenthesis, everything from this point is ignored.
 */
struct bind_kw *bind_find_kw(const char *kw)
{
	int index;
	const char *kwend;
	struct bind_kw_list *kwl;
	struct bind_kw *ret = NULL;

	kwend = strchr(kw, '(');
	if (!kwend)
		kwend = kw + strlen(kw);

	list_for_each_entry(kwl, &bind_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if ((strncmp(kwl->kw[index].kw, kw, kwend - kw) == 0) &&
			    kwl->kw[index].kw[kwend-kw] == 0) {
				if (kwl->kw[index].parse)
					return &kwl->kw[index]; /* found it !*/
				else
					ret = &kwl->kw[index];  /* may be OK */
			}
		}
	}
	return ret;
}

/* Dumps all registered "bind" keywords to the <out> string pointer. The
 * unsupported keywords are only dumped if their supported form was not
 * found.
 */
void bind_dump_kws(char **out)
{
	struct bind_kw_list *kwl;
	int index;

	if (!out)
		return;

	*out = NULL;
	list_for_each_entry(kwl, &bind_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].parse ||
			    bind_find_kw(kwl->kw[index].kw) == &kwl->kw[index]) {
				memprintf(out, "%s[%4s] %s%s%s\n", *out ? *out : "",
				          kwl->scope,
				          kwl->kw[index].kw,
				          kwl->kw[index].skip ? " <arg>" : "",
				          kwl->kw[index].parse ? "" : " (not supported)");
			}
		}
	}
}

/* Try to find in srv_keyword the word that looks closest to <word> by counting
 * transitions between letters, digits and other characters. Will return the
 * best matching word if found, otherwise NULL.
 */
const char *bind_find_best_kw(const char *word)
{
	uint8_t word_sig[1024];
	uint8_t list_sig[1024];
	const struct bind_kw_list *kwl;
	const char *best_ptr = NULL;
	int dist, best_dist = INT_MAX;
	int index;

	make_word_fingerprint(word_sig, word);
	list_for_each_entry(kwl, &bind_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			make_word_fingerprint(list_sig, kwl->kw[index].kw);
			dist = word_fingerprint_distance(word_sig, list_sig);
			if (dist < best_dist) {
				best_dist = dist;
				best_ptr = kwl->kw[index].kw;
			}
		}
	}

	if (best_dist > 2 * strlen(word) || (best_ptr && best_dist > 2 * strlen(best_ptr)))
		best_ptr = NULL;

	return best_ptr;
}

/* allocate an bind_conf struct for a bind line, and chain it to the frontend <fe>.
 * If <arg> is not NULL, it is duplicated into ->arg to store useful config
 * information for error reporting. NULL is returned on error.
 */
struct bind_conf *bind_conf_alloc(struct proxy *fe, const char *file,
                                  int line, const char *arg, struct xprt_ops *xprt)
{
	struct bind_conf *bind_conf = calloc(1, sizeof(*bind_conf));

	if (!bind_conf)
		goto err;

	bind_conf->file = strdup(file);
	if (!bind_conf->file)
		goto err;
	bind_conf->line = line;
	if (arg) {
		bind_conf->arg = strdup(arg);
		if (!bind_conf->arg)
			goto err;
	}

	LIST_APPEND(&fe->conf.bind, &bind_conf->by_fe);
	bind_conf->settings.ux.uid = -1;
	bind_conf->settings.ux.gid = -1;
	bind_conf->settings.ux.mode = 0;
	bind_conf->settings.shards = global.tune.default_shards;
	bind_conf->xprt = xprt;
	bind_conf->frontend = fe;
	bind_conf->analysers = fe->fe_req_ana;
	bind_conf->severity_output = CLI_SEVERITY_NONE;
#ifdef USE_OPENSSL
	HA_RWLOCK_INIT(&bind_conf->sni_lock);
	bind_conf->sni_ctx = EB_ROOT;
	bind_conf->sni_w_ctx = EB_ROOT;
#endif
#ifdef USE_QUIC
	/* Use connection socket for QUIC by default. */
	bind_conf->quic_mode = QUIC_SOCK_MODE_CONN;
	bind_conf->max_cwnd = global.tune.quic_frontend_max_window_size;
#endif
	LIST_INIT(&bind_conf->listeners);

	bind_conf->guid_prefix = NULL;
	bind_conf->guid_idx = 0;

	bind_conf->rhttp_srvname = NULL;

	return bind_conf;

  err:
	if (bind_conf) {
		ha_free(&bind_conf->file);
		ha_free(&bind_conf->arg);
	}
	ha_free(&bind_conf);
	return NULL;
}

const char *listener_state_str(const struct listener *l)
{
	static const char *states[8] = {
		"NEW", "INI", "ASS", "PAU", "LIS", "RDY", "FUL", "LIM",
	};
	unsigned int st = l->state;

	if (st >= sizeof(states) / sizeof(*states))
		return "INVALID";
	return states[st];
}

/************************************************************************/
/*      All supported sample and ACL keywords must be declared here.    */
/************************************************************************/

/* set temp integer to the number of connexions to the same listening socket */
static int
smp_fetch_dconn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->sess->listener->nbconn;
	return 1;
}

/* set temp integer to the id of the socket (listener) */
static int
smp_fetch_so_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->sess->listener->luid;
	return 1;
}
static int
smp_fetch_so_name(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.u.str.area = smp->sess->listener->name;
	if (!smp->data.u.str.area)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
	return 1;
}

/* parse the "accept-proxy" bind keyword */
static int bind_parse_accept_proxy(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->options |= BC_O_ACC_PROXY;
	return 0;
}

/* parse the "accept-netscaler-cip" bind keyword */
static int bind_parse_accept_netscaler_cip(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	uint32_t val;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = atol(args[cur_arg + 1]);
	if (val <= 0) {
		memprintf(err, "'%s' : invalid value %d, must be >= 0", args[cur_arg], val);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->options |= BC_O_ACC_CIP;
	conf->ns_cip_magic = val;
	return 0;
}

/* parse the "backlog" bind keyword */
static int bind_parse_backlog(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int val;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = atol(args[cur_arg + 1]);
	if (val < 0) {
		memprintf(err, "'%s' : invalid value %d, must be > 0", args[cur_arg], val);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->backlog = val;
	return 0;
}

/* parse the "guid-prefix" bind keyword */
static int bind_parse_guid_prefix(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char *prefix = NULL;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : expects an argument", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	prefix = strdup(args[cur_arg + 1]);
	if (!prefix) {
		memprintf(err, "'%s' : out of memory", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->guid_prefix = prefix;
	return 0;
}

/* parse the "id" bind keyword */
static int bind_parse_id(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct eb32_node *node;
	struct listener *l, *new;
	char *error;

	if (conf->listeners.n != conf->listeners.p) {
		memprintf(err, "'%s' can only be used with a single socket", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : expects an integer argument", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	new = LIST_NEXT(&conf->listeners, struct listener *, by_bind);
	new->luid = strtol(args[cur_arg + 1], &error, 10);
	if (*error != '\0') {
		memprintf(err, "'%s' : expects an integer argument, found '%s'", args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}
	new->conf.id.key = new->luid;

	if (new->luid <= 0) {
		memprintf(err, "'%s' : custom id has to be > 0", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	node = eb32_lookup(&px->conf.used_listener_id, new->luid);
	if (node) {
		l = container_of(node, struct listener, conf.id);
		memprintf(err, "'%s' : custom id %d already used at %s:%d ('bind %s')",
		          args[cur_arg], l->luid, l->bind_conf->file, l->bind_conf->line,
		          l->bind_conf->arg);
		return ERR_ALERT | ERR_FATAL;
	}

	eb32_insert(&px->conf.used_listener_id, &new->conf.id);
	return 0;
}

/* Complete a bind_conf by parsing the args after the address. <args> is the
 * arguments array, <cur_arg> is the first one to be considered. <section> is
 * the section name to report in error messages, and <file> and <linenum> are
 * the file name and line number respectively. Note that args[0..1] are used
 * in error messages to provide some context. The return value is an error
 * code, zero on success or an OR of ERR_{FATAL,ABORT,ALERT,WARN}.
 */
int bind_parse_args_list(struct bind_conf *bind_conf, char **args, int cur_arg, const char *section, const char *file, int linenum)
{
	int err_code = 0;

	while (*(args[cur_arg])) {
		struct bind_kw *kw;
		const char *best;

		kw = bind_find_kw(args[cur_arg]);
		if (kw) {
			char *err = NULL;
			int code;

			if (!kw->parse) {
				ha_alert("parsing [%s:%d] : '%s %s' in section '%s' : '%s' option is not implemented in this version (check build options).\n",
					 file, linenum, args[0], args[1], section, args[cur_arg]);
				cur_arg += 1 + kw->skip ;
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if ((bind_conf->options & BC_O_REVERSE_HTTP) && !kw->rhttp_ok) {
				ha_alert("'%s' option is not accepted for reverse HTTP\n",
					 args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			code = kw->parse(args, cur_arg, bind_conf->frontend, bind_conf, &err);
			err_code |= code;

			if (code) {
				if (err && *err) {
					indent_msg(&err, 2);
					if (((code & (ERR_WARN|ERR_ALERT)) == ERR_WARN))
						ha_warning("parsing [%s:%d] : '%s %s' in section '%s' : %s\n", file, linenum, args[0], args[1], section, err);
					else
						ha_alert("parsing [%s:%d] : '%s %s' in section '%s' : %s\n", file, linenum, args[0], args[1], section, err);
				}
				else
					ha_alert("parsing [%s:%d] : '%s %s' in section '%s' : error encountered while processing '%s'.\n",
						 file, linenum, args[0], args[1], section, args[cur_arg]);
				if (code & ERR_FATAL) {
					free(err);
					cur_arg += 1 + kw->skip;
					goto out;
				}
			}
			free(err);
			cur_arg += 1 + kw->skip;
			continue;
		}

		best = bind_find_best_kw(args[cur_arg]);
		if (best)
			ha_alert("parsing [%s:%d] : '%s %s' in section '%s': unknown keyword '%s'; did you mean '%s' maybe ?\n",
				 file, linenum, args[0], args[1], section, args[cur_arg], best);
		else
			ha_alert("parsing [%s:%d] : '%s %s' in section '%s': unknown keyword '%s'.\n",
				 file, linenum, args[0], args[1], section, args[cur_arg]);

		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	if ((bind_conf->options & (BC_O_USE_SOCK_DGRAM|BC_O_USE_SOCK_STREAM)) == (BC_O_USE_SOCK_DGRAM|BC_O_USE_SOCK_STREAM) ||
	    (bind_conf->options & (BC_O_USE_XPRT_DGRAM|BC_O_USE_XPRT_STREAM)) == (BC_O_USE_XPRT_DGRAM|BC_O_USE_XPRT_STREAM)) {
		ha_alert("parsing [%s:%d] : '%s %s' in section '%s' : cannot mix datagram and stream protocols.\n",
			 file, linenum, args[0], args[1], section);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	/* The transport layer automatically switches to QUIC when QUIC is
	 * selected, regardless of bind_conf settings. We then need to
	 * initialize QUIC params.
	 */
	if ((bind_conf->options & (BC_O_USE_SOCK_DGRAM|BC_O_USE_XPRT_STREAM)) == (BC_O_USE_SOCK_DGRAM|BC_O_USE_XPRT_STREAM)) {
#ifdef USE_QUIC
		struct listener *l __maybe_unused;
		int listener_count __maybe_unused = 0;

		bind_conf->xprt = xprt_get(XPRT_QUIC);
		if (!(bind_conf->options & BC_O_USE_SSL)) {
			bind_conf->options |= BC_O_USE_SSL;
			ha_warning("parsing [%s:%d] : '%s %s' in section '%s' : QUIC protocol detected, enabling ssl. Use 'ssl' to shut this warning.\n",
				 file, linenum, args[0], args[1], section);
		}
		quic_transport_params_init(&bind_conf->quic_params, 1);

#if (!defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR)) || !defined(IPV6_RECVPKTINFO)
		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			if (++listener_count > 1 || !is_inet_addr(&l->rx.addr)) {
				ha_warning("parsing [%s:%d] : '%s %s' in section '%s' : UDP binding on multiple addresses without IP_PKTINFO or equivalent support may be unreliable.\n",
				           file, linenum, args[0], args[1], section);
				break;
			}
		}
#endif /* (!IP_PKTINFO && !IP_RECVDSTADDR) || !IPV6_RECVPKTINFO */

#else
		ha_alert("parsing [%s:%d] : '%s %s' in section '%s' : QUIC protocol selected but support not compiled in (check build options).\n",
			 file, linenum, args[0], args[1], section);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (bind_conf->options & BC_O_USE_SSL) {
		bind_conf->xprt = xprt_get(XPRT_SSL);
	}

 out:
	return err_code;
}

/* parse the "maxconn" bind keyword */
static int bind_parse_maxconn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int val;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = atol(args[cur_arg + 1]);
	if (val < 0) {
		memprintf(err, "'%s' : invalid value %d, must be >= 0", args[cur_arg], val);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->maxconn = val;
	return 0;
}

/* parse the "name" bind keyword */
static int bind_parse_name(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing name", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		l->name = strdup(args[cur_arg + 1]);
		if (!l->name) {
			memprintf(err, "'%s %s' : out of memory", args[cur_arg], args[cur_arg + 1]);
			return ERR_ALERT | ERR_FATAL;
		}
	}

	return 0;
}

/* parse the "nbconn" bind keyword */
static int bind_parse_nbconn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int val;
	const struct listener *l;

	/* TODO duplicated code from check_kw_experimental() */
	if (!experimental_directives_allowed) {
		memprintf(err, "'%s' is experimental, must be allowed via a global 'expose-experimental-directives'",
		          args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);

	l = LIST_NEXT(&conf->listeners, struct listener *, by_bind);
	if (l->rx.addr.ss_family != AF_CUST_RHTTP_SRV) {
		memprintf(err, "'%s' : only valid for reverse HTTP listeners.", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value.", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = atol(args[cur_arg + 1]);
	if (val <= 0) {
		memprintf(err, "'%s' : invalid value %d, must be > 0.", args[cur_arg], val);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->rhttp_nbconn = val;
	return 0;
}

/* parse the "nice" bind keyword */
static int bind_parse_nice(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int val;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = atol(args[cur_arg + 1]);
	if (val < -1024 || val > 1024) {
		memprintf(err, "'%s' : invalid value %d, allowed range is -1024..1024", args[cur_arg], val);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->nice = val;
	return 0;
}

/* parse the "process" bind keyword */
static int bind_parse_process(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	memprintf(err, "'process %s' on 'bind' lines is not supported anymore, please use 'thread' instead.", args[cur_arg+1]);
	return ERR_ALERT | ERR_FATAL;
}

/* parse the "proto" bind keyword */
static int bind_parse_proto(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct ist proto;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	proto = ist(args[cur_arg + 1]);
	conf->mux_proto = get_mux_proto(proto);
	if (!conf->mux_proto) {
		memprintf(err, "'%s' :  unknown MUX protocol '%s'", args[cur_arg], args[cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

/* parse the "shards" bind keyword. Takes an integer, "by-thread", or "by-group" */
static int bind_parse_shards(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int val;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg + 1], "by-thread") == 0) {
		val = -1; /* -1 = "by-thread", will be fixed in check_config_validity() */
	} else if (strcmp(args[cur_arg + 1], "by-group") == 0) {
		val = -2; /* -2 = "by-group", will be fixed in check_config_validity() */
	} else {
		val = atol(args[cur_arg + 1]);
		if (val < 1 || val > MAX_THREADS) {
			memprintf(err, "'%s' : invalid value %d, allowed range is %d..%d or 'by-thread'", args[cur_arg], val, 1, MAX_THREADS);
			return ERR_ALERT | ERR_FATAL;
		}
	}

	conf->settings.shards = val;
	return 0;
}

/* parse the "thread" bind keyword. This will replace any preset thread_set */
static int bind_parse_thread(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	const struct listener *l;

	/* note that the thread set is zeroed before first call, and we don't
	 * want to reset it so that it remains possible to chain multiple
	 * "thread" directives.
	 */
	if (parse_thread_set(args[cur_arg+1], &conf->thread_set, err) < 0)
		return ERR_ALERT | ERR_FATAL;

	l = LIST_NEXT(&conf->listeners, struct listener *, by_bind);
	if (l->rx.addr.ss_family == AF_CUST_RHTTP_SRV &&
	    atleast2(conf->thread_set.grps)) {
		memprintf(err, "'%s' : reverse HTTP bind cannot span multiple thread groups.", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* config parser for global "tune.listener.default-shards" */
static int cfg_parse_tune_listener_shards(char **args, int section_type, struct proxy *curpx,
                                          const struct proxy *defpx, const char *file, int line,
                                          char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "by-thread") == 0)
		global.tune.default_shards = -1;
	else if (strcmp(args[1], "by-group") == 0)
		global.tune.default_shards = -2;
	else if (strcmp(args[1], "by-process") == 0)
		global.tune.default_shards = 1;
	else {
		memprintf(err, "'%s' expects either 'by-process', 'by-group', or 'by-thread' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.listener.multi-queue", accepts "on", "fair" or "off" */
static int cfg_parse_tune_listener_mq(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.options = (global.tune.options & ~GTUNE_LISTENER_MQ_ANY) | GTUNE_LISTENER_MQ_OPT;
	else if (strcmp(args[1], "fair") == 0)
		global.tune.options = (global.tune.options & ~GTUNE_LISTENER_MQ_ANY) | GTUNE_LISTENER_MQ_FAIR;
	else if (strcmp(args[1], "off") == 0)
		global.tune.options &= ~GTUNE_LISTENER_MQ_ANY;
	else {
		memprintf(err, "'%s' expects either 'on', 'fair', or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "dst_conn", smp_fetch_dconn, 0, NULL, SMP_T_SINT, SMP_USE_FTEND, },
	{ "so_id",    smp_fetch_so_id, 0, NULL, SMP_T_SINT, SMP_USE_FTEND, },
	{ "so_name",  smp_fetch_so_name, 0, NULL, SMP_T_STR, SMP_USE_FTEND, },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, acl_register_keywords, &acl_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "ALL", { }, {
	{ "accept-netscaler-cip", bind_parse_accept_netscaler_cip, 1, 0 }, /* enable NetScaler Client IP insertion protocol */
	{ "accept-proxy", bind_parse_accept_proxy, 0, 0 }, /* enable PROXY protocol */
	{ "backlog",      bind_parse_backlog,      1, 0 }, /* set backlog of listening socket */
	{ "guid-prefix",  bind_parse_guid_prefix,  1, 1 }, /* set guid of listening socket */
	{ "id",           bind_parse_id,           1, 1 }, /* set id of listening socket */
	{ "maxconn",      bind_parse_maxconn,      1, 0 }, /* set maxconn of listening socket */
	{ "name",         bind_parse_name,         1, 1 }, /* set name of listening socket */
	{ "nbconn",       bind_parse_nbconn,       1, 1 }, /* set number of connection on active preconnect */
	{ "nice",         bind_parse_nice,         1, 0 }, /* set nice of listening socket */
	{ "process",      bind_parse_process,      1, 0 }, /* set list of allowed process for this socket */
	{ "proto",        bind_parse_proto,        1, 0 }, /* set the proto to use for all incoming connections */
	{ "shards",       bind_parse_shards,       1, 0 }, /* set number of shards */
	{ "thread",       bind_parse_thread,       1, 1 }, /* set list of allowed threads for this socket */
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.listener.default-shards",   cfg_parse_tune_listener_shards  },
	{ CFG_GLOBAL, "tune.listener.multi-queue",      cfg_parse_tune_listener_mq      },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
