/*
 * Proxy variables and functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <common/defaults.h>
#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/time.h>

#include <eb32tree.h>
#include <ebistree.h>

#include <types/global.h>
#include <types/obj_type.h>
#include <types/peers.h>

#include <proto/backend.h>
#include <proto/fd.h>
#include <proto/hdr_idx.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/signal.h>
#include <proto/task.h>


int listeners;	/* # of proxy listeners, set by cfgparse */
struct proxy *proxy  = NULL;	/* list of all existing proxies */
struct eb_root used_proxy_id = EB_ROOT;	/* list of proxy IDs in use */
struct eb_root proxy_by_name = EB_ROOT; /* tree of proxies sorted by name */
unsigned int error_snapshot_id = 0;     /* global ID assigned to each error then incremented */

/*
 * This function returns a string containing a name describing capabilities to
 * report comprehensible error messages. Specifically, it will return the words
 * "frontend", "backend", "ruleset" when appropriate, or "proxy" for all other
 * cases including the proxies declared in "listen" mode.
 */
const char *proxy_cap_str(int cap)
{
	if ((cap & PR_CAP_LISTEN) != PR_CAP_LISTEN) {
		if (cap & PR_CAP_FE)
			return "frontend";
		else if (cap & PR_CAP_BE)
			return "backend";
		else if (cap & PR_CAP_RS)
			return "ruleset";
	}
	return "proxy";
}

/*
 * This function returns a string containing the mode of the proxy in a format
 * suitable for error messages.
 */
const char *proxy_mode_str(int mode) {

	if (mode == PR_MODE_TCP)
		return "tcp";
	else if (mode == PR_MODE_HTTP)
		return "http";
	else if (mode == PR_MODE_HEALTH)
		return "health";
	else
		return "unknown";
}

/*
 * This function scans the list of backends and servers to retrieve the first
 * backend and the first server with the given names, and sets them in both
 * parameters. It returns zero if either is not found, or non-zero and sets
 * the ones it did not found to NULL. If a NULL pointer is passed for the
 * backend, only the pointer to the server will be updated.
 */
int get_backend_server(const char *bk_name, const char *sv_name,
		       struct proxy **bk, struct server **sv)
{
	struct proxy *p;
	struct server *s;
	int sid;

	*sv = NULL;

	sid = -1;
	if (*sv_name == '#')
		sid = atoi(sv_name + 1);

	p = findproxy(bk_name, PR_CAP_BE);
	if (bk)
		*bk = p;
	if (!p)
		return 0;

	for (s = p->srv; s; s = s->next)
		if ((sid >= 0 && s->puid == sid) ||
		    (sid < 0 && strcmp(s->id, sv_name) == 0))
			break;
	*sv = s;
	if (!s)
		return 0;
	return 1;
}

/* This function parses a "timeout" statement in a proxy section. It returns
 * -1 if there is any error, 1 for a warning, otherwise zero. If it does not
 * return zero, it will write an error or warning message into a preallocated
 * buffer returned at <err>. The trailing is not be written. The function must
 * be called with <args> pointing to the first command line word, with <proxy>
 * pointing to the proxy being parsed, and <defpx> to the default proxy or NULL.
 * As a special case for compatibility with older configs, it also accepts
 * "{cli|srv|con}timeout" in args[0].
 */
static int proxy_parse_timeout(char **args, int section, struct proxy *proxy,
                               struct proxy *defpx, const char *file, int line,
                               char **err)
{
	unsigned timeout;
	int retval, cap;
	const char *res, *name;
	int *tv = NULL;
	int *td = NULL;
	int warn = 0;

	retval = 0;

	/* simply skip "timeout" but remain compatible with old form */
	if (strcmp(args[0], "timeout") == 0)
		args++;

	name = args[0];
	if (!strcmp(args[0], "client") || (!strcmp(args[0], "clitimeout") && (warn = WARN_CLITO_DEPRECATED))) {
		name = "client";
		tv = &proxy->timeout.client;
		td = &defpx->timeout.client;
		cap = PR_CAP_FE;
	} else if (!strcmp(args[0], "tarpit")) {
		tv = &proxy->timeout.tarpit;
		td = &defpx->timeout.tarpit;
		cap = PR_CAP_FE | PR_CAP_BE;
	} else if (!strcmp(args[0], "http-keep-alive")) {
		tv = &proxy->timeout.httpka;
		td = &defpx->timeout.httpka;
		cap = PR_CAP_FE | PR_CAP_BE;
	} else if (!strcmp(args[0], "http-request")) {
		tv = &proxy->timeout.httpreq;
		td = &defpx->timeout.httpreq;
		cap = PR_CAP_FE | PR_CAP_BE;
	} else if (!strcmp(args[0], "server") || (!strcmp(args[0], "srvtimeout") && (warn = WARN_SRVTO_DEPRECATED))) {
		name = "server";
		tv = &proxy->timeout.server;
		td = &defpx->timeout.server;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "connect") || (!strcmp(args[0], "contimeout") && (warn = WARN_CONTO_DEPRECATED))) {
		name = "connect";
		tv = &proxy->timeout.connect;
		td = &defpx->timeout.connect;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "check")) {
		tv = &proxy->timeout.check;
		td = &defpx->timeout.check;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "queue")) {
		tv = &proxy->timeout.queue;
		td = &defpx->timeout.queue;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "tunnel")) {
		tv = &proxy->timeout.tunnel;
		td = &defpx->timeout.tunnel;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "client-fin")) {
		tv = &proxy->timeout.clientfin;
		td = &defpx->timeout.clientfin;
		cap = PR_CAP_FE;
	} else if (!strcmp(args[0], "server-fin")) {
		tv = &proxy->timeout.serverfin;
		td = &defpx->timeout.serverfin;
		cap = PR_CAP_BE;
	} else {
		memprintf(err,
		          "'timeout' supports 'client', 'server', 'connect', 'check', "
		          "'queue', 'http-keep-alive', 'http-request', 'tunnel', 'tarpit', "
			  "'client-fin' and 'server-fin' (got '%s')",
		          args[0]);
		return -1;
	}

	if (*args[1] == 0) {
		memprintf(err, "'timeout %s' expects an integer value (in milliseconds)", name);
		return -1;
	}

	res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);
	if (res) {
		memprintf(err, "unexpected character '%c' in 'timeout %s'", *res, name);
		return -1;
	}

	if (!(proxy->cap & cap)) {
		memprintf(err, "'timeout %s' will be ignored because %s '%s' has no %s capability",
		          name, proxy_type_str(proxy), proxy->id,
		          (cap & PR_CAP_BE) ? "backend" : "frontend");
		retval = 1;
	}
	else if (defpx && *tv != *td) {
		memprintf(err, "overwriting 'timeout %s' which was already specified", name);
		retval = 1;
	}
	else if (warn) {
		if (!already_warned(warn)) {
			memprintf(err, "the '%s' directive is now deprecated in favor of 'timeout %s', and will not be supported in future versions.",
				  args[0], name);
			retval = 1;
		}
	}

	if (*args[2] != 0) {
		memprintf(err, "'timeout %s' : unexpected extra argument '%s' after value '%s'.", name, args[2], args[1]);
		retval = -1;
	}

	*tv = MS_TO_TICKS(timeout);
	return retval;
}

/* This function parses a "rate-limit" statement in a proxy section. It returns
 * -1 if there is any error, 1 for a warning, otherwise zero. If it does not
 * return zero, it will write an error or warning message into a preallocated
 * buffer returned at <err>. The function must be called with <args> pointing
 * to the first command line word, with <proxy> pointing to the proxy being
 * parsed, and <defpx> to the default proxy or NULL.
 */
static int proxy_parse_rate_limit(char **args, int section, struct proxy *proxy,
                                  struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	int retval, cap;
	char *res;
	unsigned int *tv = NULL;
	unsigned int *td = NULL;
	unsigned int val;

	retval = 0;

	if (strcmp(args[1], "sessions") == 0) {
		tv = &proxy->fe_sps_lim;
		td = &defpx->fe_sps_lim;
		cap = PR_CAP_FE;
	}
	else {
		memprintf(err, "'%s' only supports 'sessions' (got '%s')", args[0], args[1]);
		return -1;
	}

	if (*args[2] == 0) {
		memprintf(err, "'%s %s' expects expects an integer value (in sessions/second)", args[0], args[1]);
		return -1;
	}

	val = strtoul(args[2], &res, 0);
	if (*res) {
		memprintf(err, "'%s %s' : unexpected character '%c' in integer value '%s'", args[0], args[1], *res, args[2]);
		return -1;
	}

	if (!(proxy->cap & cap)) {
		memprintf(err, "%s %s will be ignored because %s '%s' has no %s capability",
			 args[0], args[1], proxy_type_str(proxy), proxy->id,
			 (cap & PR_CAP_BE) ? "backend" : "frontend");
		retval = 1;
	}
	else if (defpx && *tv != *td) {
		memprintf(err, "overwriting %s %s which was already specified", args[0], args[1]);
		retval = 1;
	}

	*tv = val;
	return retval;
}

/* This function parses a "max-keep-alive-queue" statement in a proxy section.
 * It returns -1 if there is any error, 1 for a warning, otherwise zero. If it
 * does not return zero, it will write an error or warning message into a
 * preallocated buffer returned at <err>. The function must be called with
 * <args> pointing to the first command line word, with <proxy> pointing to
 * the proxy being parsed, and <defpx> to the default proxy or NULL.
 */
static int proxy_parse_max_ka_queue(char **args, int section, struct proxy *proxy,
                                    struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	int retval;
	char *res;
	unsigned int val;

	retval = 0;

	if (*args[1] == 0) {
		memprintf(err, "'%s' expects expects an integer value (or -1 to disable)", args[0]);
		return -1;
	}

	val = strtol(args[1], &res, 0);
	if (*res) {
		memprintf(err, "'%s' : unexpected character '%c' in integer value '%s'", args[0], *res, args[1]);
		return -1;
	}

	if (!(proxy->cap & PR_CAP_BE)) {
		memprintf(err, "%s will be ignored because %s '%s' has no backend capability",
		          args[0], proxy_type_str(proxy), proxy->id);
		retval = 1;
	}

	/* we store <val+1> so that a user-facing value of -1 is stored as zero (default) */
	proxy->max_ka_queue = val + 1;
	return retval;
}

/* This function inserts proxy <px> into the tree of known proxies. The proxy's
 * name is used as the storing key so it must already have been initialized.
 */
void proxy_store_name(struct proxy *px)
{
	px->conf.by_name.key = px->id;
	ebis_insert(&proxy_by_name, &px->conf.by_name);
}

/*
 * This function finds a proxy with matching name, mode and with satisfying
 * capabilities. It also checks if there are more matching proxies with
 * requested name as this often leads into unexpected situations.
 */

struct proxy *findproxy_mode(const char *name, int mode, int cap) {

	struct proxy *curproxy, *target = NULL;
	struct ebpt_node *node;

	for (node = ebis_lookup(&proxy_by_name, name); node; node = ebpt_next(node)) {
		curproxy = container_of(node, struct proxy, conf.by_name);

		if (strcmp(curproxy->id, name) != 0)
			break;

		if ((curproxy->cap & cap) != cap)
			continue;

		if (curproxy->mode != mode &&
		    !(curproxy->mode == PR_MODE_HTTP && mode == PR_MODE_TCP)) {
			Alert("Unable to use proxy '%s' with wrong mode, required: %s, has: %s.\n", 
				name, proxy_mode_str(mode), proxy_mode_str(curproxy->mode));
			Alert("You may want to use 'mode %s'.\n", proxy_mode_str(mode));
			return NULL;
		}

		if (!target) {
			target = curproxy;
			continue;
		}

		Alert("Refusing to use duplicated proxy '%s' with overlapping capabilities: %s/%s!\n",
			name, proxy_type_str(curproxy), proxy_type_str(target));

		return NULL;
	}

	return target;
}

/* Returns a pointer to the proxy matching either name <name>, or id <name> if
 * <name> begins with a '#'. NULL is returned if no match is found, as well as
 * if multiple matches are found (eg: too large capabilities mask).
 */
struct proxy *findproxy(const char *name, int cap) {

	struct proxy *curproxy, *target = NULL;
	int pid = -1;

	if (*name == '#') {
		struct eb32_node *node;

		pid = atoi(name + 1);

		for (node = eb32_lookup(&used_proxy_id, pid); node; node = eb32_next(node)) {
			curproxy = container_of(node, struct proxy, conf.id);

			if (curproxy->uuid != pid)
				break;

			if ((curproxy->cap & cap) != cap)
				continue;

			if (target)
				return NULL;

			target = curproxy;
		}
	}
	else {
		struct ebpt_node *node;

		for (node = ebis_lookup(&proxy_by_name, name); node; node = ebpt_next(node)) {
			curproxy = container_of(node, struct proxy, conf.by_name);

			if (strcmp(curproxy->id, name) != 0)
				break;

			if ((curproxy->cap & cap) != cap)
				continue;

			if (target)
				return NULL;

			target = curproxy;
		}
	}
	return target;
}

/*
 * This function finds a server with matching name within selected proxy.
 * It also checks if there are more matching servers with
 * requested name as this often leads into unexpected situations.
 */

struct server *findserver(const struct proxy *px, const char *name) {

	struct server *cursrv, *target = NULL;

	if (!px)
		return NULL;

	for (cursrv = px->srv; cursrv; cursrv = cursrv->next) {
		if (strcmp(cursrv->id, name))
			continue;

		if (!target) {
			target = cursrv;
			continue;
		}

		Alert("Refusing to use duplicated server '%s' found in proxy: %s!\n",
			name, px->id);

		return NULL;
	}

	return target;
}

/* This function checks that the designated proxy has no http directives
 * enabled. It will output a warning if there are, and will fix some of them.
 * It returns the number of fatal errors encountered. This should be called
 * at the end of the configuration parsing if the proxy is not in http mode.
 * The <file> argument is used to construct the error message.
 */
int proxy_cfg_ensure_no_http(struct proxy *curproxy)
{
	if (curproxy->cookie_name != NULL) {
		Warning("config : cookie will be ignored for %s '%s' (needs 'mode http').\n",
			proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->rsp_exp != NULL) {
		Warning("config : server regular expressions will be ignored for %s '%s' (needs 'mode http').\n",
			proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->req_exp != NULL) {
		Warning("config : client regular expressions will be ignored for %s '%s' (needs 'mode http').\n",
			proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->monitor_uri != NULL) {
		Warning("config : monitor-uri will be ignored for %s '%s' (needs 'mode http').\n",
			proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->lbprm.algo & BE_LB_NEED_HTTP) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
		Warning("config : Layer 7 hash not possible for %s '%s' (needs 'mode http'). Falling back to round robin.\n",
			proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->to_log & (LW_REQ | LW_RESP)) {
		curproxy->to_log &= ~(LW_REQ | LW_RESP);
		Warning("parsing [%s:%d] : HTTP log/header format not usable with %s '%s' (needs 'mode http').\n",
			curproxy->conf.lfs_file, curproxy->conf.lfs_line,
			proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->conf.logformat_string == default_http_log_format ||
	    curproxy->conf.logformat_string == clf_http_log_format) {
		/* Note: we don't change the directive's file:line number */
		curproxy->conf.logformat_string = default_tcp_log_format;
		Warning("parsing [%s:%d] : 'option httplog' not usable with %s '%s' (needs 'mode http'). Falling back to 'option tcplog'.\n",
			curproxy->conf.lfs_file, curproxy->conf.lfs_line,
			proxy_type_str(curproxy), curproxy->id);
	}

	return 0;
}

/* Perform the most basic initialization of a proxy :
 * memset(), list_init(*), reset_timeouts(*).
 * Any new proxy or peer should be initialized via this function.
 */
void init_new_proxy(struct proxy *p)
{
	memset(p, 0, sizeof(struct proxy));
	p->obj_type = OBJ_TYPE_PROXY;
	LIST_INIT(&p->pendconns);
	LIST_INIT(&p->acl);
	LIST_INIT(&p->http_req_rules);
	LIST_INIT(&p->http_res_rules);
	LIST_INIT(&p->block_rules);
	LIST_INIT(&p->redirect_rules);
	LIST_INIT(&p->mon_fail_cond);
	LIST_INIT(&p->switching_rules);
	LIST_INIT(&p->server_rules);
	LIST_INIT(&p->persist_rules);
	LIST_INIT(&p->sticking_rules);
	LIST_INIT(&p->storersp_rules);
	LIST_INIT(&p->tcp_req.inspect_rules);
	LIST_INIT(&p->tcp_rep.inspect_rules);
	LIST_INIT(&p->tcp_req.l4_rules);
	LIST_INIT(&p->req_add);
	LIST_INIT(&p->rsp_add);
	LIST_INIT(&p->listener_queue);
	LIST_INIT(&p->logsrvs);
	LIST_INIT(&p->logformat);
	LIST_INIT(&p->format_unique_id);
	LIST_INIT(&p->conf.bind);
	LIST_INIT(&p->conf.listeners);
	LIST_INIT(&p->conf.args.list);
	LIST_INIT(&p->tcpcheck_rules);

	/* Timeouts are defined as -1 */
	proxy_reset_timeouts(p);
	p->tcp_rep.inspect_delay = TICK_ETERNITY;

	/* initial uuid is unassigned (-1) */
	p->uuid = -1;
}

/*
 * This function creates all proxy sockets. It should be done very early,
 * typically before privileges are dropped. The sockets will be registered
 * but not added to any fd_set, in order not to loose them across the fork().
 * The proxies also start in READY state because they all have their listeners
 * bound.
 *
 * Its return value is composed from ERR_NONE, ERR_RETRYABLE and ERR_FATAL.
 * Retryable errors will only be printed if <verbose> is not zero.
 */
int start_proxies(int verbose)
{
	struct proxy *curproxy;
	struct listener *listener;
	int lerr, err = ERR_NONE;
	int pxerr;
	char msg[100];

	for (curproxy = proxy; curproxy != NULL; curproxy = curproxy->next) {
		if (curproxy->state != PR_STNEW)
			continue; /* already initialized */

		pxerr = 0;
		list_for_each_entry(listener, &curproxy->conf.listeners, by_fe) {
			if (listener->state != LI_ASSIGNED)
				continue; /* already started */

			lerr = listener->proto->bind(listener, msg, sizeof(msg));

			/* errors are reported if <verbose> is set or if they are fatal */
			if (verbose || (lerr & (ERR_FATAL | ERR_ABORT))) {
				if (lerr & ERR_ALERT)
					Alert("Starting %s %s: %s\n",
					      proxy_type_str(curproxy), curproxy->id, msg);
				else if (lerr & ERR_WARN)
					Warning("Starting %s %s: %s\n",
						proxy_type_str(curproxy), curproxy->id, msg);
			}

			err |= lerr;
			if (lerr & (ERR_ABORT | ERR_FATAL)) {
				pxerr |= 1;
				break;
			}
			else if (lerr & ERR_CODE) {
				pxerr |= 1;
				continue;
			}
		}

		if (!pxerr) {
			curproxy->state = PR_STREADY;
			send_log(curproxy, LOG_NOTICE, "Proxy %s started.\n", curproxy->id);
		}

		if (err & ERR_ABORT)
			break;
	}

	return err;
}


/*
 * This is the proxy management task. It enables proxies when there are enough
 * free sessions, or stops them when the table is full. It is designed to be
 * called as a task which is woken up upon stopping or when rate limiting must
 * be enforced.
 */
struct task *manage_proxy(struct task *t)
{
	struct proxy *p = t->context;
	int next = TICK_ETERNITY;
	unsigned int wait;

	/* We should periodically try to enable listeners waiting for a
	 * global resource here.
	 */

	/* first, let's check if we need to stop the proxy */
	if (unlikely(stopping && p->state != PR_STSTOPPED)) {
		int t;
		t = tick_remain(now_ms, p->stop_time);
		if (t == 0) {
			Warning("Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				p->id, p->fe_counters.cum_conn, p->be_counters.cum_conn);
			send_log(p, LOG_WARNING, "Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				 p->id, p->fe_counters.cum_conn, p->be_counters.cum_conn);
			stop_proxy(p);
			/* try to free more memory */
			pool_gc2();
		}
		else {
			next = tick_first(next, p->stop_time);
		}
	}

	/* If the proxy holds a stick table, we need to purge all unused
	 * entries. These are all the ones in the table with ref_cnt == 0
	 * and all the ones in the pool used to allocate new entries. Any
	 * entry attached to an existing session waiting for a store will
	 * be in neither list. Any entry being dumped will have ref_cnt > 0.
	 * However we protect tables that are being synced to peers.
	 */
	if (unlikely(stopping && p->state == PR_STSTOPPED && p->table.current)) {
		if (!p->table.syncing) {
			stktable_trash_oldest(&p->table, p->table.current);
			pool_gc2();
		}
		if (p->table.current) {
			/* some entries still remain, let's recheck in one second */
			next = tick_first(next, tick_add(now_ms, 1000));
		}
	}

	/* the rest below is just for frontends */
	if (!(p->cap & PR_CAP_FE))
		goto out;

	/* check the various reasons we may find to block the frontend */
	if (unlikely(p->feconn >= p->maxconn)) {
		if (p->state == PR_STREADY)
			p->state = PR_STFULL;
		goto out;
	}

	/* OK we have no reason to block, so let's unblock if we were blocking */
	if (p->state == PR_STFULL)
		p->state = PR_STREADY;

	if (p->fe_sps_lim &&
	    (wait = next_event_delay(&p->fe_sess_per_sec, p->fe_sps_lim, 0))) {
		/* we're blocking because a limit was reached on the number of
		 * requests/s on the frontend. We want to re-check ASAP, which
		 * means in 1 ms before estimated expiration date, because the
		 * timer will have settled down.
		 */
		next = tick_first(next, tick_add(now_ms, wait));
		goto out;
	}

	/* The proxy is not limited so we can re-enable any waiting listener */
	if (!LIST_ISEMPTY(&p->listener_queue))
		dequeue_all_listeners(&p->listener_queue);
 out:
	t->expire = next;
	task_queue(t);
	return t;
}


/*
 * this function disables health-check servers so that the process will quickly be ignored
 * by load balancers. Note that if a proxy was already in the PAUSED state, then its grace
 * time will not be used since it would already not listen anymore to the socket.
 */
void soft_stop(void)
{
	struct proxy *p;
	struct peers *prs;

	stopping = 1;
	p = proxy;
	tv_update_date(0,1); /* else, the old time before select will be used */
	while (p) {
		if (p->state != PR_STSTOPPED) {
			Warning("Stopping %s %s in %d ms.\n", proxy_cap_str(p->cap), p->id, p->grace);
			send_log(p, LOG_WARNING, "Stopping %s %s in %d ms.\n", proxy_cap_str(p->cap), p->id, p->grace);
			p->stop_time = tick_add(now_ms, p->grace);
		}
		if (p->table.size && p->table.sync_task)
			 task_wakeup(p->table.sync_task, TASK_WOKEN_MSG);

		/* wake every proxy task up so that they can handle the stopping */
		if (p->task)
			task_wakeup(p->task, TASK_WOKEN_MSG);
		p = p->next;
	}

	prs = peers;
	while (prs) {
		stop_proxy((struct proxy *)prs->peers_fe);
		prs = prs->next;
	}
	/* signal zero is used to broadcast the "stopping" event */
	signal_handler(0);
}


/* Temporarily disables listening on all of the proxy's listeners. Upon
 * success, the proxy enters the PR_PAUSED state. If disabling at least one
 * listener returns an error, then the proxy state is set to PR_STERROR
 * because we don't know how to resume from this. The function returns 0
 * if it fails, or non-zero on success.
 */
int pause_proxy(struct proxy *p)
{
	struct listener *l;

	if (!(p->cap & PR_CAP_FE) || p->state == PR_STERROR ||
	    p->state == PR_STSTOPPED || p->state == PR_STPAUSED)
		return 1;

	Warning("Pausing %s %s.\n", proxy_cap_str(p->cap), p->id);
	send_log(p, LOG_WARNING, "Pausing %s %s.\n", proxy_cap_str(p->cap), p->id);

	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		if (!pause_listener(l))
			p->state = PR_STERROR;
	}

	if (p->state == PR_STERROR) {
		Warning("%s %s failed to enter pause mode.\n", proxy_cap_str(p->cap), p->id);
		send_log(p, LOG_WARNING, "%s %s failed to enter pause mode.\n", proxy_cap_str(p->cap), p->id);
		return 0;
	}

	p->state = PR_STPAUSED;
	return 1;
}


/*
 * This function completely stops a proxy and releases its listeners. It has
 * to be called when going down in order to release the ports so that another
 * process may bind to them. It must also be called on disabled proxies at the
 * end of start-up. When all listeners are closed, the proxy is set to the
 * PR_STSTOPPED state.
 */
void stop_proxy(struct proxy *p)
{
	struct listener *l;

	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		unbind_listener(l);
		if (l->state >= LI_ASSIGNED) {
			delete_listener(l);
			listeners--;
			jobs--;
		}
	}
	p->state = PR_STSTOPPED;
}

/* This function resumes listening on the specified proxy. It scans all of its
 * listeners and tries to enable them all. If any of them fails, the proxy is
 * put back to the paused state. It returns 1 upon success, or zero if an error
 * is encountered.
 */
int resume_proxy(struct proxy *p)
{
	struct listener *l;
	int fail;

	if (p->state != PR_STPAUSED)
		return 1;

	Warning("Enabling %s %s.\n", proxy_cap_str(p->cap), p->id);
	send_log(p, LOG_WARNING, "Enabling %s %s.\n", proxy_cap_str(p->cap), p->id);

	fail = 0;
	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		if (!resume_listener(l)) {
			int port;

			port = get_host_port(&l->addr);
			if (port) {
				Warning("Port %d busy while trying to enable %s %s.\n",
					port, proxy_cap_str(p->cap), p->id);
				send_log(p, LOG_WARNING, "Port %d busy while trying to enable %s %s.\n",
					 port, proxy_cap_str(p->cap), p->id);
			}
			else {
				Warning("Bind on socket %d busy while trying to enable %s %s.\n",
					l->luid, proxy_cap_str(p->cap), p->id);
				send_log(p, LOG_WARNING, "Bind on socket %d busy while trying to enable %s %s.\n",
					 l->luid, proxy_cap_str(p->cap), p->id);
			}

			/* Another port might have been enabled. Let's stop everything. */
			fail = 1;
			break;
		}
	}

	p->state = PR_STREADY;
	if (fail) {
		pause_proxy(p);
		return 0;
	}
	return 1;
}

/*
 * This function temporarily disables listening so that another new instance
 * can start listening. It is designed to be called upon reception of a
 * SIGTTOU, after which either a SIGUSR1 can be sent to completely stop
 * the proxy, or a SIGTTIN can be sent to listen again.
 */
void pause_proxies(void)
{
	int err;
	struct proxy *p;
	struct peers *prs;

	err = 0;
	p = proxy;
	tv_update_date(0,1); /* else, the old time before select will be used */
	while (p) {
		err |= !pause_proxy(p);
		p = p->next;
	}

	prs = peers;
	while (prs) {
		p = prs->peers_fe;
		err |= !pause_proxy(p);
		prs = prs->next;
        }

	if (err) {
		Warning("Some proxies refused to pause, performing soft stop now.\n");
		send_log(p, LOG_WARNING, "Some proxies refused to pause, performing soft stop now.\n");
		soft_stop();
	}
}


/*
 * This function reactivates listening. This can be used after a call to
 * sig_pause(), for example when a new instance has failed starting up.
 * It is designed to be called upon reception of a SIGTTIN.
 */
void resume_proxies(void)
{
	int err;
	struct proxy *p;
	struct peers *prs;

	err = 0;
	p = proxy;
	tv_update_date(0,1); /* else, the old time before select will be used */
	while (p) {
		err |= !resume_proxy(p);
		p = p->next;
	}

	prs = peers;
	while (prs) {
		p = prs->peers_fe;
		err |= !resume_proxy(p);
		prs = prs->next;
        }

	if (err) {
		Warning("Some proxies refused to resume, a restart is probably needed to resume safe operations.\n");
		send_log(p, LOG_WARNING, "Some proxies refused to resume, a restart is probably needed to resume safe operations.\n");
	}
}

/* Set current session's backend to <be>. Nothing is done if the
 * session already had a backend assigned, which is indicated by
 * s->flags & SN_BE_ASSIGNED.
 * All flags, stats and counters which need be updated are updated.
 * Returns 1 if done, 0 in case of internal error, eg: lack of resource.
 */
int session_set_backend(struct session *s, struct proxy *be)
{
	if (s->flags & SN_BE_ASSIGNED)
		return 1;
	s->be = be;
	be->beconn++;
	if (be->beconn > be->be_counters.conn_max)
		be->be_counters.conn_max = be->beconn;
	proxy_inc_be_ctr(be);

	/* assign new parameters to the session from the new backend */
	s->si[1].flags &= ~SI_FL_INDEP_STR;
	if (be->options2 & PR_O2_INDEPSTR)
		s->si[1].flags |= SI_FL_INDEP_STR;

	if (be->options2 & PR_O2_RSPBUG_OK)
		s->txn.rsp.err_pos = -1; /* let buggy responses pass */
	s->flags |= SN_BE_ASSIGNED;

	/* If the target backend requires HTTP processing, we have to allocate
	 * a struct hdr_idx for it if we did not have one.
	 */
	if (unlikely(!s->txn.hdr_idx.v && be->http_needed)) {
		s->txn.hdr_idx.size = global.tune.max_http_hdr;
		if ((s->txn.hdr_idx.v = pool_alloc2(pool2_hdr_idx)) == NULL)
			return 0; /* not enough memory */

		/* and now initialize the HTTP transaction state */
		http_init_txn(s);
	}

	/* If an LB algorithm needs to access some pre-parsed body contents,
	 * we must not start to forward anything until the connection is
	 * confirmed otherwise we'll lose the pointer to these data and
	 * prevent the hash from being doable again after a redispatch.
	 */
	if (be->mode == PR_MODE_HTTP &&
	    (be->lbprm.algo & (BE_LB_KIND | BE_LB_PARM)) == (BE_LB_KIND_HI | BE_LB_HASH_PRM))
		s->txn.req.flags |= HTTP_MSGF_WAIT_CONN;

	if (be->options2 & PR_O2_NODELAY) {
		s->req->flags |= CF_NEVER_WAIT;
		s->rep->flags |= CF_NEVER_WAIT;
	}

	/* We want to enable the backend-specific analysers except those which
	 * were already run as part of the frontend/listener. Note that it would
	 * be more reliable to store the list of analysers that have been run,
	 * but what we do here is OK for now.
	 */
	s->req->analysers |= be->be_req_ana & ~(s->listener->analysers);

	return 1;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_LISTEN, "timeout", proxy_parse_timeout },
	{ CFG_LISTEN, "clitimeout", proxy_parse_timeout },
	{ CFG_LISTEN, "contimeout", proxy_parse_timeout },
	{ CFG_LISTEN, "srvtimeout", proxy_parse_timeout },
	{ CFG_LISTEN, "rate-limit", proxy_parse_rate_limit },
	{ CFG_LISTEN, "max-keep-alive-queue", proxy_parse_max_ka_queue },
	{ 0, NULL, NULL },
}};

__attribute__((constructor))
static void __proxy_module_init(void)
{
	cfg_register_keywords(&cfg_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
