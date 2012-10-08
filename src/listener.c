/*
 * Listener management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <common/accept4.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/global.h>
#include <types/protocol.h>

#include <proto/acl.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/task.h>

/* List head of all known bind keywords */
static struct bind_kw_list bind_keywords = {
	.list = LIST_HEAD_INIT(bind_keywords.list)
};

/* This function adds the specified listener's file descriptor to the polling
 * lists if it is in the LI_LISTEN state. The listener enters LI_READY or
 * LI_FULL state depending on its number of connections.
 */
void enable_listener(struct listener *listener)
{
	if (listener->state == LI_LISTEN) {
		if (listener->nbconn < listener->maxconn) {
			fd_want_recv(listener->fd);
			listener->state = LI_READY;
		} else {
			listener->state = LI_FULL;
		}
	}
}

/* This function removes the specified listener's file descriptor from the
 * polling lists if it is in the LI_READY or in the LI_FULL state. The listener
 * enters LI_LISTEN.
 */
void disable_listener(struct listener *listener)
{
	if (listener->state < LI_READY)
		return;
	if (listener->state == LI_READY)
		fd_stop_recv(listener->fd);
	if (listener->state == LI_LIMITED)
		LIST_DEL(&listener->wait_queue);
	listener->state = LI_LISTEN;
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
	if (l->state <= LI_PAUSED)
		return 1;

	if (l->proto->sock_prot == IPPROTO_TCP) {
		if (shutdown(l->fd, SHUT_WR) != 0)
			return 0; /* Solaris dies here */

		if (listen(l->fd, l->backlog ? l->backlog : l->maxconn) != 0)
			return 0; /* OpenBSD dies here */

		if (shutdown(l->fd, SHUT_RD) != 0)
			return 0; /* should always be OK */
	}

	if (l->state == LI_LIMITED)
		LIST_DEL(&l->wait_queue);

	fd_stop_recv(l->fd);
	l->state = LI_PAUSED;
	return 1;
}

/* This function tries to resume a temporarily disabled listener. Paused, full,
 * limited and disabled listeners are handled, which means that this function
 * may replace enable_listener(). The resulting state will either be LI_READY
 * or LI_FULL. 0 is returned in case of failure to resume (eg: dead socket).
 */
int resume_listener(struct listener *l)
{
	if (l->state < LI_PAUSED)
		return 0;

	if (l->proto->sock_prot == IPPROTO_TCP &&
	    l->state == LI_PAUSED &&
	    listen(l->fd, l->backlog ? l->backlog : l->maxconn) != 0)
		return 0;

	if (l->state == LI_READY)
		return 1;

	if (l->state == LI_LIMITED)
		LIST_DEL(&l->wait_queue);

	if (l->nbconn >= l->maxconn) {
		l->state = LI_FULL;
		return 1;
	}

	fd_want_recv(l->fd);
	l->state = LI_READY;
	return 1;
}

/* Marks a ready listener as full so that the session code tries to re-enable
 * it upon next close() using resume_listener().
 */
void listener_full(struct listener *l)
{
	if (l->state >= LI_READY) {
		if (l->state == LI_LIMITED)
			LIST_DEL(&l->wait_queue);

		fd_stop_recv(l->fd);
		l->state = LI_FULL;
	}
}

/* Marks a ready listener as limited so that we only try to re-enable it when
 * resources are free again. It will be queued into the specified queue.
 */
void limit_listener(struct listener *l, struct list *list)
{
	if (l->state == LI_READY) {
		LIST_ADDQ(list, &l->wait_queue);
		fd_stop_recv(l->fd);
		l->state = LI_LIMITED;
	}
}

/* This function adds all of the protocol's listener's file descriptors to the
 * polling lists when they are in the LI_LISTEN state. It is intended to be
 * used as a protocol's generic enable_all() primitive, for use after the
 * fork(). It puts the listeners into LI_READY or LI_FULL states depending on
 * their number of connections. It always returns ERR_NONE.
 */
int enable_all_listeners(struct protocol *proto)
{
	struct listener *listener;

	list_for_each_entry(listener, &proto->listeners, proto_list)
		enable_listener(listener);
	return ERR_NONE;
}

/* This function removes all of the protocol's listener's file descriptors from
 * the polling lists when they are in the LI_READY or LI_FULL states. It is
 * intended to be used as a protocol's generic disable_all() primitive. It puts
 * the listeners into LI_LISTEN, and always returns ERR_NONE.
 */
int disable_all_listeners(struct protocol *proto)
{
	struct listener *listener;

	list_for_each_entry(listener, &proto->listeners, proto_list)
		disable_listener(listener);
	return ERR_NONE;
}

/* Dequeues all of the listeners waiting for a resource in wait queue <queue>. */
void dequeue_all_listeners(struct list *list)
{
	struct listener *listener, *l_back;

	list_for_each_entry_safe(listener, l_back, list, wait_queue) {
		/* This cannot fail because the listeners are by definition in
		 * the LI_LIMITED state. The function also removes the entry
		 * from the queue.
		 */
		resume_listener(listener);
	}
}

/* This function closes the listening socket for the specified listener,
 * provided that it's already in a listening state. The listener enters the
 * LI_ASSIGNED state. It always returns ERR_NONE. This function is intended
 * to be used as a generic function for standard protocols.
 */
int unbind_listener(struct listener *listener)
{
	if (listener->state == LI_READY)
		fd_stop_recv(listener->fd);

	if (listener->state == LI_LIMITED)
		LIST_DEL(&listener->wait_queue);

	if (listener->state >= LI_PAUSED) {
		fd_delete(listener->fd);
		listener->state = LI_ASSIGNED;
	}
	return ERR_NONE;
}

/* This function closes all listening sockets bound to the protocol <proto>,
 * and the listeners end in LI_ASSIGNED state if they were higher. It does not
 * detach them from the protocol. It always returns ERR_NONE.
 */
int unbind_all_listeners(struct protocol *proto)
{
	struct listener *listener;

	list_for_each_entry(listener, &proto->listeners, proto_list)
		unbind_listener(listener);
	return ERR_NONE;
}

/* Delete a listener from its protocol's list of listeners. The listener's
 * state is automatically updated from LI_ASSIGNED to LI_INIT. The protocol's
 * number of listeners is updated. Note that the listener must have previously
 * been unbound. This is the generic function to use to remove a listener.
 */
void delete_listener(struct listener *listener)
{
	if (listener->state != LI_ASSIGNED)
		return;
	listener->state = LI_INIT;
	LIST_DEL(&listener->proto_list);
	listener->proto->nb_listeners--;
}

/* This function is called on a read event from a listening socket, corresponding
 * to an accept. It tries to accept as many connections as possible, and for each
 * calls the listener's accept handler (generally the frontend's accept handler).
 */
void listener_accept(int fd)
{
	struct listener *l = fdtab[fd].owner;
	struct proxy *p = l->frontend;
	int max_accept = global.tune.maxaccept;
	int cfd;
	int ret;

	if (unlikely(l->nbconn >= l->maxconn)) {
		listener_full(l);
		return;
	}

	if (global.cps_lim && !(l->options & LI_O_UNLIMITED)) {
		int max = freq_ctr_remain(&global.conn_per_sec, global.cps_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			limit_listener(l, &global_listener_queue);
			task_schedule(global_listener_queue_task, tick_add(now_ms, next_event_delay(&global.conn_per_sec, global.cps_lim, 0)));
			return;
		}

		if (max_accept > max)
			max_accept = max;
	}

	if (p && p->fe_sps_lim) {
		int max = freq_ctr_remain(&p->fe_sess_per_sec, p->fe_sps_lim, 0);

		if (unlikely(!max)) {
			/* frontend accept rate limit was reached */
			limit_listener(l, &p->listener_queue);
			task_schedule(p->task, tick_add(now_ms, next_event_delay(&p->fe_sess_per_sec, p->fe_sps_lim, 0)));
			return;
		}

		if (max_accept > max)
			max_accept = max;
	}

	/* Note: if we fail to allocate a connection because of configured
	 * limits, we'll schedule a new attempt worst 1 second later in the
	 * worst case. If we fail due to system limits or temporary resource
	 * shortage, we try again 100ms later in the worst case.
	 */
	while (max_accept--) {
		struct sockaddr_storage addr;
		socklen_t laddr = sizeof(addr);

		if (unlikely(actconn >= global.maxconn) && !(l->options & LI_O_UNLIMITED)) {
			limit_listener(l, &global_listener_queue);
			task_schedule(global_listener_queue_task, tick_add(now_ms, 1000)); /* try again in 1 second */
			return;
		}

		if (unlikely(p && p->feconn >= p->maxconn)) {
			limit_listener(l, &p->listener_queue);
			return;
		}

#ifdef USE_ACCEPT4
		cfd = accept4(fd, (struct sockaddr *)&addr, &laddr, SOCK_NONBLOCK);
#else
		cfd = accept(fd, (struct sockaddr *)&addr, &laddr);
#endif
		if (unlikely(cfd == -1)) {
			switch (errno) {
			case EAGAIN:
			case EINTR:
			case ECONNABORTED:
				fd_poll_recv(fd);
				return;   /* nothing more to accept */
			case ENFILE:
				if (p)
					send_log(p, LOG_EMERG,
						 "Proxy %s reached system FD limit at %d. Please check system tunables.\n",
						 p->id, maxfd);
				limit_listener(l, &global_listener_queue);
				task_schedule(global_listener_queue_task, tick_add(now_ms, 100)); /* try again in 100 ms */
				return;
			case EMFILE:
				if (p)
					send_log(p, LOG_EMERG,
						 "Proxy %s reached process FD limit at %d. Please check 'ulimit-n' and restart.\n",
						 p->id, maxfd);
				limit_listener(l, &global_listener_queue);
				task_schedule(global_listener_queue_task, tick_add(now_ms, 100)); /* try again in 100 ms */
				return;
			case ENOBUFS:
			case ENOMEM:
				if (p)
					send_log(p, LOG_EMERG,
						 "Proxy %s reached system memory limit at %d sockets. Please check system tunables.\n",
						 p->id, maxfd);
				limit_listener(l, &global_listener_queue);
				task_schedule(global_listener_queue_task, tick_add(now_ms, 100)); /* try again in 100 ms */
				return;
			default:
				/* unexpected result, let's go back to poll */
				fd_poll_recv(fd);
				return;
			}
		}

		if (unlikely(cfd >= global.maxsock)) {
			send_log(p, LOG_EMERG,
				 "Proxy %s reached the configured maximum connection limit. Please check the global 'maxconn' value.\n",
				 p->id);
			close(cfd);
			limit_listener(l, &global_listener_queue);
			task_schedule(global_listener_queue_task, tick_add(now_ms, 1000)); /* try again in 1 second */
			return;
		}

		/* increase the per-process number of cumulated connections */
		if (!(l->options & LI_O_UNLIMITED)) {
			update_freq_ctr(&global.conn_per_sec, 1);
			if (global.conn_per_sec.curr_ctr > global.cps_max)
				global.cps_max = global.conn_per_sec.curr_ctr;
			actconn++;
		}

		jobs++;
		totalconn++;
		l->nbconn++;

		if (l->counters) {
			if (l->nbconn > l->counters->conn_max)
				l->counters->conn_max = l->nbconn;
		}

		ret = l->accept(l, cfd, &addr);
		if (unlikely(ret <= 0)) {
			/* The connection was closed by session_accept(). Either
			 * we just have to ignore it (ret == 0) or it's a critical
			 * error due to a resource shortage, and we must stop the
			 * listener (ret < 0).
			 */
			if (!(l->options & LI_O_UNLIMITED))
				actconn--;
			jobs--;
			l->nbconn--;
			if (ret == 0) /* successful termination */
				continue;

			limit_listener(l, &global_listener_queue);
			task_schedule(global_listener_queue_task, tick_add(now_ms, 100)); /* try again in 100 ms */
			return;
		}

		if (l->nbconn >= l->maxconn) {
			listener_full(l);
			return;
		}

	} /* end of while (max_accept--) */

	/* we've exhausted max_accept, so there is no need to poll again */
	return;
}

/*
 * Registers the bind keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void bind_register_keywords(struct bind_kw_list *kwl)
{
	LIST_ADDQ(&bind_keywords.list, &kwl->list);
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

/************************************************************************/
/*           All supported ACL keywords must be declared here.          */
/************************************************************************/

/* set temp integer to the number of connexions to the same listening socket */
static int
acl_fetch_dconn(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                const struct arg *args, struct sample *smp)
{
	smp->type = SMP_T_UINT;
	smp->data.uint = l4->listener->nbconn;
	return 1;
}

/* set temp integer to the id of the socket (listener) */
static int
acl_fetch_so_id(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                const struct arg *args, struct sample *smp)
{
	smp->type = SMP_T_UINT;
	smp->data.uint = l4->listener->luid;
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
	if (val <= 0) {
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

	if (conf->listeners.n != conf->listeners.p) {
		memprintf(err, "'%s' can only be used with a single socket", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : expects an integer argument", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	new = LIST_NEXT(&conf->listeners, struct listener *, by_bind);
	new->luid = atol(args[cur_arg + 1]);
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
	if (val <= 0) {
		memprintf(err, "'%s' : invalid value %d, must be > 0", args[cur_arg], val);
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


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {{ },{
	{ "dst_conn",   acl_parse_int,   acl_fetch_dconn,    acl_match_int, ACL_USE_NOTHING, 0 },
	{ "so_id",      acl_parse_int,   acl_fetch_so_id,    acl_match_int, ACL_USE_NOTHING, 0 },
	{ NULL, NULL, NULL, NULL },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "ALL", { }, {
	{ "accept-proxy", bind_parse_accept_proxy, 0 }, /* enable PROXY protocol */
	{ "backlog",      bind_parse_backlog,      1 }, /* set backlog of listening socket */
	{ "id",           bind_parse_id,           1 }, /* set id of listening socket */
	{ "maxconn",      bind_parse_maxconn,      1 }, /* set maxconn of listening socket */
	{ "name",         bind_parse_name,         1 }, /* set name of listening socket */
	{ "nice",         bind_parse_nice,         1 }, /* set nice of listening socket */
	{ NULL, NULL, 0 },
}};

__attribute__((constructor))
static void __listener_init(void)
{
	acl_register_keywords(&acl_kws);
	bind_register_keywords(&bind_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
