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
#include <fcntl.h>

#include <haproxy/acl.h>
#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli-t.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


/* List head of all known bind keywords */
static struct bind_kw_list bind_keywords = {
	.list = LIST_HEAD_INIT(bind_keywords.list)
};

/* list of the temporarily limited listeners because of lack of resource */
static struct mt_list global_listener_queue = MT_LIST_HEAD_INIT(global_listener_queue);
static struct task *global_listener_queue_task;

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

	pos = ring->head;

	if (pos == ring->tail)
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
	ring->head = next;
	return ptr;
}


/* tries to push a new accepted connection <conn> into ring <ring>. Returns
 * non-zero if it succeeds, or zero if the ring is full. Supports multiple
 * producers.
 */
int accept_queue_push_mp(struct accept_queue_ring *ring, struct connection *conn)
{
	unsigned int pos, next;

	pos = ring->tail;
	do {
		next = pos + 1;
		if (next >= ACCEPT_QUEUE_SIZE)
			next = 0;
		if (next == ring->head)
			return 0; // ring full
	} while (unlikely(!_HA_ATOMIC_CAS(&ring->tail, &pos, next)));

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
		_HA_ATOMIC_INC(&li->thr_conn[tid]);
		ret = li->accept(conn);
		if (ret <= 0) {
			/* connection was terminated by the application */
			continue;
		}

		/* increase the per-process number of cumulated sessions, this
		 * may only be done once l->accept() has accepted the connection.
		 */
		if (!(li->options & LI_O_UNLIMITED)) {
			HA_ATOMIC_UPDATE_MAX(&global.sps_max,
			                     update_freq_ctr(&global.sess_per_sec, 1));
			if (li->bind_conf && li->bind_conf->is_ssl) {
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

#endif // USE_THREAD

/* Memory allocation and initialization of the per_thr field.
 * Returns 0 if the field has been successfully initialized, -1 on failure.
 */
int li_init_per_thr(struct listener *li)
{
	int i;

	/* allocate per-thread elements for listener */
	li->per_thr = calloc(global.nbthread, sizeof(*li->per_thr));
	if (!li->per_thr)
		return -1;

	for (i = 0; i < global.nbthread; ++i) {
		MT_LIST_INIT(&li->per_thr[i].quic_accept.list);
		MT_LIST_INIT(&li->per_thr[i].quic_accept.conns);

		li->per_thr[i].li = li;
	}

	return 0;
}

/* helper to get listener status for stats */
enum li_status get_li_status(struct listener *l)
{
	if (!l->maxconn || l->nbconn < l->maxconn) {
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
			BUG_ON(l->rx.fd == -1);
			_HA_ATOMIC_INC(&px->li_bound);
			break;
		case LI_READY:
		case LI_FULL:
		case LI_LIMITED:
			BUG_ON(l->rx.fd == -1);
			_HA_ATOMIC_INC(&px->li_ready);
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
	HA_SPIN_LOCK(LISTENER_LOCK, &listener->lock);

	/* If this listener is supposed to be only in the master, close it in
	 * the workers. Conversely, if it's supposed to be only in the workers
	 * close it in the master.
	 */
	if (!!master != !!(listener->rx.flags & RX_F_MWORKER))
		do_unbind_listener(listener);

	if (listener->state == LI_LISTEN) {
		BUG_ON(listener->rx.fd == -1);
		if ((global.mode & (MODE_DAEMON | MODE_MWORKER)) &&
		    (!!master != !!(listener->rx.flags & RX_F_MWORKER))) {
			/* we don't want to enable this listener and don't
			 * want any fd event to reach it.
			 */
			do_unbind_listener(listener);
		}
		else if (!listener->maxconn || listener->nbconn < listener->maxconn) {
			listener->rx.proto->enable(listener);
			listener_set_state(listener, LI_READY);
		}
		else {
			listener_set_state(listener, LI_FULL);
		}
	}

	HA_SPIN_UNLOCK(LISTENER_LOCK, &listener->lock);
}

/*
 * This function completely stops a listener. It will need to operate under the
 * proxy's lock, the protocol's lock, and the listener's lock. The caller is
 * responsible for indicating in lpx, lpr, lli whether the respective locks are
 * already held (non-zero) or not (zero) so that the function picks the missing
 * ones, in this order. The proxy's listeners count is updated and the proxy is
 * disabled and woken up after the last one is gone.
 */
void stop_listener(struct listener *l, int lpx, int lpr, int lli)
{
	struct proxy *px = l->bind_conf->frontend;

	if (l->options & LI_O_NOSTOP) {
		/* master-worker sockpairs are never closed but don't count as a
		 * job.
		 */
		return;
	}

	if (!lpx)
		HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);

	if (!lpr)
		HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);

	if (!lli)
		HA_SPIN_LOCK(LISTENER_LOCK, &l->lock);

	if (l->state > LI_INIT) {
		do_unbind_listener(l);

		if (l->state >= LI_ASSIGNED)
			__delete_listener(l);

		proxy_cond_disable(px);
	}

	if (!lli)
		HA_SPIN_UNLOCK(LISTENER_LOCK, &l->lock);

	if (!lpr)
		HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);

	if (!lpx)
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
 * must be called under the listener's lock. It will return non-zero on success,
 * 0 on failure. If no receiver-level suspend is provided, the operation is
 * assumed to succeed.
 */
int default_suspend_listener(struct listener *l)
{
	int ret = 1;

	if (!l->rx.proto->rx_suspend)
		return 1;

	ret = l->rx.proto->rx_suspend(&l->rx);
	return ret > 0 ? ret : 0;
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
		int err;

		err = l->rx.proto->listen(l, msg, sizeof(msg));
		if (err & ERR_ALERT)
			ha_alert("Resuming listener: %s\n", msg);
		else if (err & ERR_WARN)
			ha_warning("Resuming listener: %s\n", msg);

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
 */
int pause_listener(struct listener *l)
{
	struct proxy *px = l->bind_conf->frontend;
	int ret = 1;

	HA_SPIN_LOCK(LISTENER_LOCK, &l->lock);

	if (l->state <= LI_PAUSED)
		goto end;

	if (l->rx.proto->suspend)
		ret = l->rx.proto->suspend(l);

	MT_LIST_DELETE(&l->wait_queue);

	listener_set_state(l, LI_PAUSED);

	if (px && !px->li_ready) {
		ha_warning("Paused %s %s.\n", proxy_cap_str(px->cap), px->id);
		send_log(px, LOG_WARNING, "Paused %s %s.\n", proxy_cap_str(px->cap), px->id);
	}
  end:
	HA_SPIN_UNLOCK(LISTENER_LOCK, &l->lock);
	return ret;
}

/* This function tries to resume a temporarily disabled listener. Paused, full,
 * limited and disabled listeners are handled, which means that this function
 * may replace enable_listener(). The resulting state will either be LI_READY
 * or LI_FULL. 0 is returned in case of failure to resume (eg: dead socket).
 * Listeners bound to a different process are not woken up unless we're in
 * foreground mode, and are ignored. If the listener was only in the assigned
 * state, it's totally rebound. This can happen if a pause() has completely
 * stopped it. If the resume fails, 0 is returned and an error might be
 * displayed.
 */
int resume_listener(struct listener *l)
{
	struct proxy *px = l->bind_conf->frontend;
	int was_paused = px && px->li_paused;
	int ret = 1;

	HA_SPIN_LOCK(LISTENER_LOCK, &l->lock);

	/* check that another thread didn't to the job in parallel (e.g. at the
	 * end of listen_accept() while we'd come from dequeue_all_listeners().
	 */
	if (MT_LIST_INLIST(&l->wait_queue))
		goto end;

	if (l->state == LI_READY)
		goto end;

	if (l->rx.proto->resume)
		ret = l->rx.proto->resume(l);

	if (l->maxconn && l->nbconn >= l->maxconn) {
		l->rx.proto->disable(l);
		listener_set_state(l, LI_FULL);
		goto done;
	}

	l->rx.proto->enable(l);
	listener_set_state(l, LI_READY);

  done:
	if (was_paused && !px->li_paused) {
		ha_warning("Resumed %s %s.\n", proxy_cap_str(px->cap), px->id);
		send_log(px, LOG_WARNING, "Resumed %s %s.\n", proxy_cap_str(px->cap), px->id);
	}
  end:
	HA_SPIN_UNLOCK(LISTENER_LOCK, &l->lock);
	return ret;
}

/* Marks a ready listener as full so that the stream code tries to re-enable
 * it upon next close() using resume_listener().
 */
static void listener_full(struct listener *l)
{
	HA_SPIN_LOCK(LISTENER_LOCK, &l->lock);
	if (l->state >= LI_READY) {
		MT_LIST_DELETE(&l->wait_queue);
		if (l->state != LI_FULL) {
			l->rx.proto->disable(l);
			listener_set_state(l, LI_FULL);
		}
	}
	HA_SPIN_UNLOCK(LISTENER_LOCK, &l->lock);
}

/* Marks a ready listener as limited so that we only try to re-enable it when
 * resources are free again. It will be queued into the specified queue.
 */
static void limit_listener(struct listener *l, struct mt_list *list)
{
	HA_SPIN_LOCK(LISTENER_LOCK, &l->lock);
	if (l->state == LI_READY) {
		MT_LIST_TRY_APPEND(list, &l->wait_queue);
		l->rx.proto->disable(l);
		listener_set_state(l, LI_LIMITED);
	}
	HA_SPIN_UNLOCK(LISTENER_LOCK, &l->lock);
}

/* Dequeues all listeners waiting for a resource the global wait queue */
void dequeue_all_listeners()
{
	struct listener *listener;

	while ((listener = MT_LIST_POP(&global_listener_queue, struct listener *, wait_queue))) {
		/* This cannot fail because the listeners are by definition in
		 * the LI_LIMITED state.
		 */
		resume_listener(listener);
	}
}

/* Dequeues all listeners waiting for a resource in proxy <px>'s queue */
void dequeue_proxy_listeners(struct proxy *px)
{
	struct listener *listener;

	while ((listener = MT_LIST_POP(&px->listener_queue, struct listener *, wait_queue))) {
		/* This cannot fail because the listeners are by definition in
		 * the LI_LIMITED state.
		 */
		resume_listener(listener);
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
	HA_SPIN_LOCK(LISTENER_LOCK, &listener->lock);
	do_unbind_listener(listener);
	HA_SPIN_UNLOCK(LISTENER_LOCK, &listener->lock);
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

		memcpy(&l->rx.addr, ss, sizeof(*ss));
		if (proto->fam->set_port)
			proto->fam->set_port(&l->rx.addr, port);

		MT_LIST_INIT(&l->wait_queue);
		listener_set_state(l, LI_INIT);

		proto->add(proto, l);

		if (fd != -1)
			l->rx.flags |= RX_F_INHERITED;

		l->extra_counters = NULL;

		HA_SPIN_INIT(&l->lock);
		_HA_ATOMIC_INC(&jobs);
		_HA_ATOMIC_INC(&listeners);
	}
	return 1;
}

/* clones listener <src> and returns the new one. All dynamically allocated
 * fields are reallocated (name for now). The new listener is inserted before
 * the original one in the bind_conf and frontend lists. This allows it to be
 * duplicated while iterating over the current list. The original listener must
 * only be in the INIT or ASSIGNED states, and the new listener will only be
 * placed into the INIT state. The counters are always set to NULL. Maxsock is
 * updated. Returns NULL on allocation error.
 */
struct listener *clone_listener(struct listener *src)
{
	struct listener *l;

	l = calloc(1, sizeof(*l));
	if (!l)
		goto oom1;
	memcpy(l, src, sizeof(*l));

	if (l->name) {
		l->name = strdup(l->name);
		if (!l->name)
			goto oom2;
	}

	l->rx.owner = l;
	l->state = LI_INIT;
	l->counters = NULL;
	l->extra_counters = NULL;

	LIST_APPEND(&src->by_fe,   &l->by_fe);
	LIST_APPEND(&src->by_bind, &l->by_bind);

	MT_LIST_INIT(&l->wait_queue);

	l->rx.proto->add(l->rx.proto, l);

	HA_SPIN_INIT(&l->lock);
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
	HA_SPIN_LOCK(LISTENER_LOCK, &listener->lock);
	__delete_listener(listener);
	HA_SPIN_UNLOCK(LISTENER_LOCK, &listener->lock);
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* Returns a suitable value for a listener's backlog. It uses the listener's,
 * otherwise the frontend's backlog, otherwise the listener's maxconn,
 * otherwise the frontend's maxconn, otherwise 1024.
 */
int listener_backlog(const struct listener *l)
{
	if (l->backlog)
		return l->backlog;

	if (l->bind_conf->frontend->backlog)
		return l->bind_conf->frontend->backlog;

	if (l->maxconn)
		return l->maxconn;

	if (l->bind_conf->frontend->maxconn)
		return l->bind_conf->frontend->maxconn;

	return 1024;
}

/* This function is called on a read event from a listening socket, corresponding
 * to an accept. It tries to accept as many connections as possible, and for each
 * calls the listener's accept handler (generally the frontend's accept handler).
 */
void listener_accept(struct listener *l)
{
	struct connection *cli_conn;
	struct proxy *p;
	unsigned int max_accept;
	int next_conn = 0;
	int next_feconn = 0;
	int next_actconn = 0;
	int expire;
	int ret;

	p = l->bind_conf->frontend;

	/* if l->maxaccept is -1, then max_accept is UINT_MAX. It is not really
	 * illimited, but it is probably enough.
	 */
	max_accept = l->maxaccept ? l->maxaccept : 1;

	if (!(l->options & LI_O_UNLIMITED) && global.sps_lim) {
		int max = freq_ctr_remain(&global.sess_per_sec, global.sps_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			expire = tick_add(now_ms, next_event_delay(&global.sess_per_sec, global.sps_lim, 0));
			goto limit_global;
		}

		if (max_accept > max)
			max_accept = max;
	}

	if (!(l->options & LI_O_UNLIMITED) && global.cps_lim) {
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
	if (!(l->options & LI_O_UNLIMITED) && global.ssl_lim && l->bind_conf && l->bind_conf->is_ssl) {
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
		int max = freq_ctr_remain(&p->fe_sess_per_sec, p->fe_sps_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			expire = tick_add(now_ms, next_event_delay(&p->fe_sess_per_sec, p->fe_sps_lim, 0));
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
			if (unlikely(l->maxconn && count >= l->maxconn)) {
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

		if (!(l->options & LI_O_UNLIMITED)) {
			do {
				count = actconn;
				if (unlikely(count >= global.maxconn)) {
					/* the process was marked full or another
					 * thread is going to do it.
					 */
					next_actconn = 0;
					expire = tick_add(now_ms, 1000); /* try again in 1 second */
					goto limit_global;
				}
				next_actconn = count + 1;
			} while (!_HA_ATOMIC_CAS(&actconn, (int *)(&count), next_actconn));
		}

		cli_conn = l->rx.proto->accept_conn(l, &status);
		if (!cli_conn) {
			switch (status) {
			case CO_AC_DONE:
				goto end;

			case CO_AC_RETRY: /* likely a signal */
				_HA_ATOMIC_DEC(&l->nbconn);
				if (p)
					_HA_ATOMIC_DEC(&p->feconn);
				if (!(l->options & LI_O_UNLIMITED))
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

		if (p)
			HA_ATOMIC_UPDATE_MAX(&p->fe_counters.conn_max, next_feconn);

		proxy_inc_fe_conn_ctr(l, p);

		if (!(l->options & LI_O_UNLIMITED)) {
			count = update_freq_ctr(&global.conn_per_sec, 1);
			HA_ATOMIC_UPDATE_MAX(&global.cps_max, count);
		}

		_HA_ATOMIC_INC(&activity[tid].accepted);

		if (unlikely(cli_conn->handle.fd >= global.maxsock)) {
			send_log(p, LOG_EMERG,
				 "Proxy %s reached the configured maximum connection limit. Please check the global 'maxconn' value.\n",
				 p->id);
			close(cli_conn->handle.fd);
			conn_free(cli_conn);
			expire = tick_add(now_ms, 1000); /* try again in 1 second */
			goto limit_global;
		}

		/* past this point, l->accept() will automatically decrement
		 * l->nbconn, feconn and actconn once done. Setting next_*conn=0
		 * allows the error path not to rollback on nbconn. It's more
		 * convenient than duplicating all exit labels.
		 */
		next_conn = 0;
		next_feconn = 0;
		next_actconn = 0;


#if defined(USE_THREAD)
		if (l->rx.flags & RX_F_LOCAL_ACCEPT)
			goto local_accept;

		mask = thread_mask(l->rx.bind_thread) & all_threads_mask;
		if (atleast2(mask) && (global.tune.options & GTUNE_LISTENER_MQ) && !stopping) {
			struct accept_queue_ring *ring;
			unsigned int t, t0, t1, t2;

			/* The principle is that we have two running indexes,
			 * each visiting in turn all threads bound to this
			 * listener. The connection will be assigned to the one
			 * with the least connections, and the other one will
			 * be updated. This provides a good fairness on short
			 * connections (round robin) and on long ones (conn
			 * count), without ever missing any idle thread.
			 */

			/* keep a copy for the final update. thr_idx is composite
			 * and made of (t2<<16) + t1.
			 */
			t0 = l->thr_idx;
			do {
				unsigned long m1, m2;
				int q1, q2;

				t2 = t1 = t0;
				t2 >>= 16;
				t1 &= 0xFFFF;

				/* t1 walks low to high bits ;
				 * t2 walks high to low.
				 */
				m1 = mask >> t1;
				m2 = mask & (t2 ? nbits(t2 + 1) : ~0UL);

				if (unlikely(!(m1 & 1))) {
					m1 &= ~1UL;
					if (!m1) {
						m1 = mask;
						t1 = 0;
					}
					t1 += my_ffsl(m1) - 1;
				}

				if (unlikely(!(m2 & (1UL << t2)) || t1 == t2)) {
					/* highest bit not set */
					if (!m2)
						m2 = mask;

					t2 = my_flsl(m2) - 1;
				}

				/* now we have two distinct thread IDs belonging to the mask */
				q1 = accept_queue_rings[t1].tail - accept_queue_rings[t1].head + ACCEPT_QUEUE_SIZE;
				if (q1 >= ACCEPT_QUEUE_SIZE)
					q1 -= ACCEPT_QUEUE_SIZE;

				q2 = accept_queue_rings[t2].tail - accept_queue_rings[t2].head + ACCEPT_QUEUE_SIZE;
				if (q2 >= ACCEPT_QUEUE_SIZE)
					q2 -= ACCEPT_QUEUE_SIZE;

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
				 */

				q1 += l->thr_conn[t1];
				q2 += l->thr_conn[t2];

				if (q1 - q2 < 0) {
					t = t1;
					t2 = t2 ? t2 - 1 : LONGBITS - 1;
				}
				else if (q1 - q2 > 0) {
					t = t2;
					t1++;
					if (t1 >= LONGBITS)
						t1 = 0;
				}
				else {
					t = t1;
					t1++;
					if (t1 >= LONGBITS)
						t1 = 0;
				}

				/* new value for thr_idx */
				t1 += (t2 << 16);
			} while (unlikely(!_HA_ATOMIC_CAS(&l->thr_idx, &t0, t1)));

			/* We successfully selected the best thread "t" for this
			 * connection. We use deferred accepts even if it's the
			 * local thread because tests show that it's the best
			 * performing model, likely due to better cache locality
			 * when processing this loop.
			 */
			ring = &accept_queue_rings[t];
			if (accept_queue_push_mp(ring, cli_conn)) {
				_HA_ATOMIC_INC(&activity[t].accq_pushed);
				tasklet_wakeup(ring->tasklet);
				continue;
			}
			/* If the ring is full we do a synchronous accept on
			 * the local thread here.
			 */
			_HA_ATOMIC_INC(&activity[t].accq_full);
		}
#endif // USE_THREAD

 local_accept:
		_HA_ATOMIC_INC(&l->thr_conn[tid]);
		ret = l->accept(cli_conn);
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
		 * may only be done once l->accept() has accepted the connection.
		 */
		if (!(l->options & LI_O_UNLIMITED)) {
			count = update_freq_ctr(&global.sess_per_sec, 1);
			HA_ATOMIC_UPDATE_MAX(&global.sps_max, count);
		}
#ifdef USE_OPENSSL
		if (!(l->options & LI_O_UNLIMITED) && l->bind_conf && l->bind_conf->is_ssl) {
			count = update_freq_ctr(&global.ssl_per_sec, 1);
			HA_ATOMIC_UPDATE_MAX(&global.ssl_max, count);
		}
#endif

		th_ctx->flags &= ~TH_FL_STUCK; // this thread is still running
	} /* end of for (max_accept--) */

 end:
	if (next_conn)
		_HA_ATOMIC_DEC(&l->nbconn);

	if (p && next_feconn)
		_HA_ATOMIC_DEC(&p->feconn);

	if (next_actconn)
		_HA_ATOMIC_DEC(&actconn);

	if ((l->state == LI_FULL && (!l->maxconn || l->nbconn < l->maxconn)) ||
	    (l->state == LI_LIMITED &&
	     ((!p || p->feconn < p->maxconn) && (actconn < global.maxconn) &&
	      (!tick_isset(global_listener_queue_task->expire) ||
	       tick_is_expired(global_listener_queue_task->expire, now_ms))))) {
		/* at least one thread has to this when quitting */
		resume_listener(l);

		/* Dequeues all of the listeners waiting for a resource */
		dequeue_all_listeners();

		if (p && !MT_LIST_ISEMPTY(&p->listener_queue) &&
		    (!p->fe_sps_lim || freq_ctr_remain(&p->fe_sess_per_sec, p->fe_sps_lim, 0) > 0))
			dequeue_proxy_listeners(p);
	}
	return;

 transient_error:
	/* pause the listener for up to 100 ms */
	expire = tick_add(now_ms, 100);

	/* This may be a shared socket that was paused by another process.
	 * Let's put it to pause in this case.
	 */
	if (l->rx.proto && l->rx.proto->rx_listening(&l->rx) == 0) {
		pause_listener(l);
		goto end;
	}

 limit_global:
	/* (re-)queue the listener to the global queue and set it to expire no
	 * later than <expire> ahead. The listener turns to LI_LIMITED.
	 */
	limit_listener(l, &global_listener_queue);
	task_schedule(global_listener_queue_task, expire);
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

	if (!(l->options & LI_O_UNLIMITED))
		_HA_ATOMIC_DEC(&actconn);
	if (fe)
		_HA_ATOMIC_DEC(&fe->feconn);
	_HA_ATOMIC_DEC(&l->nbconn);
	_HA_ATOMIC_DEC(&l->thr_conn[tid]);

	if (l->state == LI_FULL || l->state == LI_LIMITED)
		resume_listener(l);

	/* Dequeues all of the listeners waiting for a resource */
	dequeue_all_listeners();

	if (!MT_LIST_ISEMPTY(&fe->listener_queue) &&
	    (!fe->fe_sps_lim || freq_ctr_remain(&fe->fe_sess_per_sec, fe->fe_sps_lim, 0) > 0))
		dequeue_proxy_listeners(fe);
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
	t->expire = TICK_ETERNITY;
	task_queue(t);
	return t;
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
	bind_conf->settings.shards = 1;
	bind_conf->xprt = xprt;
	bind_conf->frontend = fe;
	bind_conf->severity_output = CLI_SEVERITY_NONE;
#ifdef USE_OPENSSL
	HA_RWLOCK_INIT(&bind_conf->sni_lock);
	bind_conf->sni_ctx = EB_ROOT;
	bind_conf->sni_w_ctx = EB_ROOT;
#endif
	LIST_INIT(&bind_conf->listeners);
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
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind)
		l->options |= LI_O_ACC_PROXY;

	return 0;
}

/* parse the "accept-netscaler-cip" bind keyword */
static int bind_parse_accept_netscaler_cip(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
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

	list_for_each_entry(l, &conf->listeners, by_bind) {
		l->options |= LI_O_ACC_CIP;
		conf->ns_cip_magic = val;
	}

	return 0;
}

/* parse the "backlog" bind keyword */
static int bind_parse_backlog(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
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

	list_for_each_entry(l, &conf->listeners, by_bind)
		l->backlog = val;

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

/* parse the "maxconn" bind keyword */
static int bind_parse_maxconn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
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

	list_for_each_entry(l, &conf->listeners, by_bind)
		l->maxconn = val;

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

	list_for_each_entry(l, &conf->listeners, by_bind)
		l->name = strdup(args[cur_arg + 1]);

	return 0;
}

/* parse the "nice" bind keyword */
static int bind_parse_nice(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
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

	list_for_each_entry(l, &conf->listeners, by_bind)
		l->nice = val;

	return 0;
}

/* parse the "process" bind keyword */
static int bind_parse_process(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char *slash;
	unsigned long proc = 0, thread = 0;

	if ((slash = strchr(args[cur_arg + 1], '/')) != NULL)
		*slash = 0;

	if (parse_process_number(args[cur_arg + 1], &proc, 1, NULL, err)) {
		memprintf(err, "'%s' : %s", args[cur_arg], *err);
		return ERR_ALERT | ERR_FATAL;
	}

	if (slash) {
		if (parse_process_number(slash+1, &thread, MAX_THREADS, NULL, err)) {
			memprintf(err, "'%s' : %s", args[cur_arg], *err);
			return ERR_ALERT | ERR_FATAL;
		}
		*slash = '/';
	}

	conf->bind_thread |= thread;

	memprintf(err, "'process %s' on 'bind' lines is deprecated and will be removed in 2.7.", args[cur_arg+1]);
	if (slash)
		memprintf(err, "%s Please use 'thread %s' instead.", *err, slash + 1);
	return ERR_WARN;
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

/* parse the "shards" bind keyword. Takes an integer or "by-thread" */
static int bind_parse_shards(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int val;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg + 1], "by-thread") == 0) {
		val = MAX_THREADS; /* will be trimmed later anyway */
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

/* parse the "thread" bind keyword */
static int bind_parse_thread(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char *sep = NULL;
	ulong thread = 0;
	long tgroup = 0;

	tgroup = strtol(args[cur_arg + 1], &sep, 10);
	if (*sep == '/') {
		/* a thread group was present */
		if (tgroup < 1 || tgroup > MAX_TGROUPS) {
			memprintf(err, "'%s' thread-group number must be between 1 and %d (was %ld)", args[cur_arg + 1], MAX_TGROUPS, tgroup);
			return ERR_ALERT | ERR_FATAL;
		}
		sep++;
	}
	else {
		/* no thread group */
		tgroup = 0;
		sep = args[cur_arg + 1];
	}

	if ((conf->bind_tgroup || conf->bind_thread) &&
	    conf->bind_tgroup != tgroup) {
		memprintf(err, "'%s' multiple thread-groups are not supported", args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}
	
	if (parse_process_number(sep, &thread, MAX_THREADS, NULL, err)) {
		memprintf(err, "'%s' : %s", sep, *err);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->bind_thread |= thread;
	conf->bind_tgroup  = tgroup;
	return 0;
}

/* config parser for global "tune.listener.multi-queue", accepts "on" or "off" */
static int cfg_parse_tune_listener_mq(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.options |= GTUNE_LISTENER_MQ;
	else if (strcmp(args[1], "off") == 0)
		global.tune.options &= ~GTUNE_LISTENER_MQ;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
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
	{ "accept-netscaler-cip", bind_parse_accept_netscaler_cip, 1 }, /* enable NetScaler Client IP insertion protocol */
	{ "accept-proxy", bind_parse_accept_proxy, 0 }, /* enable PROXY protocol */
	{ "backlog",      bind_parse_backlog,      1 }, /* set backlog of listening socket */
	{ "id",           bind_parse_id,           1 }, /* set id of listening socket */
	{ "maxconn",      bind_parse_maxconn,      1 }, /* set maxconn of listening socket */
	{ "name",         bind_parse_name,         1 }, /* set name of listening socket */
	{ "nice",         bind_parse_nice,         1 }, /* set nice of listening socket */
	{ "process",      bind_parse_process,      1 }, /* set list of allowed process for this socket */
	{ "proto",        bind_parse_proto,        1 }, /* set the proto to use for all incoming connections */
	{ "shards",       bind_parse_shards,       1 }, /* set number of shards */
	{ "thread",       bind_parse_thread,       1 }, /* set list of allowed threads for this socket */
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
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
