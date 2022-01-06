/*
 * Server management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2008 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/types.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <errno.h>

#include <import/ebmbtree.h>

#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/backend.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/connection.h>
#include <haproxy/dict-t.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/mailers.h>
#include <haproxy/namespace.h>
#include <haproxy/port_range.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/queue.h>
#include <haproxy/resolvers.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/stats.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/xxhash.h>


static void srv_update_status(struct server *s);
static int srv_apply_lastaddr(struct server *srv, int *err_code);
static void srv_cleanup_connections(struct server *srv);

/* extra keywords used as value for other arguments. They are used as
 * suggestions for mistyped words.
 */
static const char *extra_kw_list[] = {
	"ipv4", "ipv6", "legacy", "octet-count",
	"fail-check", "sudden-death", "mark-down",
	NULL /* must be last */
};

/* List head of all known server keywords */
static struct srv_kw_list srv_keywords = {
	.list = LIST_HEAD_INIT(srv_keywords.list)
};

__decl_thread(HA_SPINLOCK_T idle_conn_srv_lock);
struct eb_root idle_conn_srv = EB_ROOT;
struct task *idle_conn_task __read_mostly = NULL;
struct list servers_list = LIST_HEAD_INIT(servers_list);

/* The server names dictionary */
struct dict server_key_dict = {
	.name = "server keys",
	.values = EB_ROOT_UNIQUE,
};

int srv_downtime(const struct server *s)
{
	if ((s->cur_state != SRV_ST_STOPPED) || s->last_change >= now.tv_sec)		// ignore negative time
		return s->down_time;

	return now.tv_sec - s->last_change + s->down_time;
}

int srv_lastsession(const struct server *s)
{
	if (s->counters.last_sess)
		return now.tv_sec - s->counters.last_sess;

	return -1;
}

int srv_getinter(const struct check *check)
{
	const struct server *s = check->server;

	if ((check->state & CHK_ST_CONFIGURED) && (check->health == check->rise + check->fall - 1))
		return check->inter;

	if ((s->next_state == SRV_ST_STOPPED) && check->health == 0)
		return (check->downinter)?(check->downinter):(check->inter);

	return (check->fastinter)?(check->fastinter):(check->inter);
}

/*
 * Check that we did not get a hash collision.
 * Unlikely, but it can happen. The server's proxy must be at least
 * read-locked.
 */
static inline void srv_check_for_dup_dyncookie(struct server *s)
{
	struct proxy *p = s->proxy;
	struct server *tmpserv;

	for (tmpserv = p->srv; tmpserv != NULL;
	    tmpserv = tmpserv->next) {
		if (tmpserv == s)
			continue;
		if (tmpserv->next_admin & SRV_ADMF_FMAINT)
			continue;
		if (tmpserv->cookie &&
		    strcmp(tmpserv->cookie, s->cookie) == 0) {
			ha_warning("We generated two equal cookies for two different servers.\n"
				   "Please change the secret key for '%s'.\n",
				   s->proxy->id);
		}
	}

}

/*
 * Must be called with the server lock held, and will read-lock the proxy.
 */
void srv_set_dyncookie(struct server *s)
{
	struct proxy *p = s->proxy;
	char *tmpbuf;
	unsigned long long hash_value;
	size_t key_len;
	size_t buffer_len;
	int addr_len;
	int port;

	HA_RWLOCK_RDLOCK(PROXY_LOCK, &p->lock);

	if ((s->flags & SRV_F_COOKIESET) ||
	    !(s->proxy->ck_opts & PR_CK_DYNAMIC) ||
	    s->proxy->dyncookie_key == NULL)
		goto out;
	key_len = strlen(p->dyncookie_key);

	if (s->addr.ss_family != AF_INET &&
	    s->addr.ss_family != AF_INET6)
		goto out;
	/*
	 * Buffer to calculate the cookie value.
	 * The buffer contains the secret key + the server IP address
	 * + the TCP port.
	 */
	addr_len = (s->addr.ss_family == AF_INET) ? 4 : 16;
	/*
	 * The TCP port should use only 2 bytes, but is stored in
	 * an unsigned int in struct server, so let's use 4, to be
	 * on the safe side.
	 */
	buffer_len = key_len + addr_len + 4;
	tmpbuf = trash.area;
	memcpy(tmpbuf, p->dyncookie_key, key_len);
	memcpy(&(tmpbuf[key_len]),
	    s->addr.ss_family == AF_INET ?
	    (void *)&((struct sockaddr_in *)&s->addr)->sin_addr.s_addr :
	    (void *)&(((struct sockaddr_in6 *)&s->addr)->sin6_addr.s6_addr),
	    addr_len);
	/*
	 * Make sure it's the same across all the load balancers,
	 * no matter their endianness.
	 */
	port = htonl(s->svc_port);
	memcpy(&tmpbuf[key_len + addr_len], &port, 4);
	hash_value = XXH64(tmpbuf, buffer_len, 0);
	memprintf(&s->cookie, "%016llx", hash_value);
	if (!s->cookie)
		goto out;
	s->cklen = 16;

	/* Don't bother checking if the dyncookie is duplicated if
	 * the server is marked as "disabled", maybe it doesn't have
	 * its real IP yet, but just a place holder.
	 */
	if (!(s->next_admin & SRV_ADMF_FMAINT))
		srv_check_for_dup_dyncookie(s);
 out:
	HA_RWLOCK_RDUNLOCK(PROXY_LOCK, &p->lock);
}

/* Returns true if it's possible to reuse an idle connection from server <srv>
 * for a websocket stream. This is the case if server is configured to use the
 * same protocol for both HTTP and websocket streams. This depends on the value
 * of "proto", "alpn" and "ws" keywords.
 */
int srv_check_reuse_ws(struct server *srv)
{
	if (srv->mux_proto || srv->use_ssl != 1 || !srv->ssl_ctx.alpn_str) {
		/* explicit srv.mux_proto or no ALPN : srv.mux_proto is used
		 * for mux selection.
		 */
		const struct ist srv_mux = srv->mux_proto ?
		                           srv->mux_proto->token : IST_NULL;

		switch (srv->ws) {
		/* "auto" means use the same protocol : reuse is possible. */
		case SRV_WS_AUTO:
			return 1;

		/* "h2" means use h2 for websocket : reuse is possible if
		 * server mux is h2.
		 */
		case SRV_WS_H2:
			if (srv->mux_proto && isteq(srv_mux, ist("h2")))
				return 1;
			break;

		/* "h1" means use h1 for websocket : reuse is possible if
		 * server mux is h1.
		 */
		case SRV_WS_H1:
			if (!srv->mux_proto || isteq(srv_mux, ist("h1")))
				return 1;
			break;
		}
	}
	else {
		/* ALPN selection.
		 * Based on the assumption that only "h2" and "http/1.1" token
		 * are used on server ALPN.
		 */
		const struct ist alpn = ist2(srv->ssl_ctx.alpn_str,
		                             srv->ssl_ctx.alpn_len);

		switch (srv->ws) {
		case SRV_WS_AUTO:
			/* for auto mode, consider reuse as possible if the
			 * server uses a single protocol ALPN
			 */
			if (!istchr(alpn, ','))
				return 1;
			break;

		case SRV_WS_H2:
			return isteq(alpn, ist("\x02h2"));

		case SRV_WS_H1:
			return isteq(alpn, ist("\x08http/1.1"));
		}
	}

	return 0;
}

/* Return the proto to used for a websocket stream on <srv> without ALPN. NULL
 * is a valid value indicating to use the fallback mux.
 */
const struct mux_ops *srv_get_ws_proto(struct server *srv)
{
	const struct mux_proto_list *mux = NULL;

	switch (srv->ws) {
	case SRV_WS_AUTO:
		mux = srv->mux_proto;
		break;

	case SRV_WS_H1:
		mux = get_mux_proto(ist("h1"));
		break;

	case SRV_WS_H2:
		mux = get_mux_proto(ist("h2"));
		break;
	}

	return mux ? mux->mux : NULL;
}

/*
 * Must be called with the server lock held. The server is first removed from
 * the proxy tree if it was already attached. If <reattach> is true, the server
 * will then be attached in the proxy tree. The proxy lock is held to
 * manipulate the tree.
 */
static void srv_set_addr_desc(struct server *s, int reattach)
{
	struct proxy *p = s->proxy;
	char *key;

	key = sa2str(&s->addr, s->svc_port, s->flags & SRV_F_MAPPORTS);

	if (s->addr_node.key) {
		if (key && strcmp(key, s->addr_node.key) == 0) {
			free(key);
			return;
		}

		HA_RWLOCK_WRLOCK(PROXY_LOCK, &p->lock);
		ebpt_delete(&s->addr_node);
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);

		free(s->addr_node.key);
	}

	s->addr_node.key = key;

	if (reattach) {
		if (s->addr_node.key) {
			HA_RWLOCK_WRLOCK(PROXY_LOCK, &p->lock);
			ebis_insert(&p->used_server_addr, &s->addr_node);
			HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);
		}
	}
}

/*
 * Registers the server keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void srv_register_keywords(struct srv_kw_list *kwl)
{
	LIST_APPEND(&srv_keywords.list, &kwl->list);
}

/* Return a pointer to the server keyword <kw>, or NULL if not found. If the
 * keyword is found with a NULL ->parse() function, then an attempt is made to
 * find one with a valid ->parse() function. This way it is possible to declare
 * platform-dependant, known keywords as NULL, then only declare them as valid
 * if some options are met. Note that if the requested keyword contains an
 * opening parenthesis, everything from this point is ignored.
 */
struct srv_kw *srv_find_kw(const char *kw)
{
	int index;
	const char *kwend;
	struct srv_kw_list *kwl;
	struct srv_kw *ret = NULL;

	kwend = strchr(kw, '(');
	if (!kwend)
		kwend = kw + strlen(kw);

	list_for_each_entry(kwl, &srv_keywords.list, list) {
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

/* Dumps all registered "server" keywords to the <out> string pointer. The
 * unsupported keywords are only dumped if their supported form was not
 * found.
 */
void srv_dump_kws(char **out)
{
	struct srv_kw_list *kwl;
	int index;

	if (!out)
		return;

	*out = NULL;
	list_for_each_entry(kwl, &srv_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].parse ||
			    srv_find_kw(kwl->kw[index].kw) == &kwl->kw[index]) {
				memprintf(out, "%s[%4s] %s%s%s%s\n", *out ? *out : "",
				          kwl->scope,
				          kwl->kw[index].kw,
				          kwl->kw[index].skip ? " <arg>" : "",
				          kwl->kw[index].default_ok ? " [dflt_ok]" : "",
				          kwl->kw[index].parse ? "" : " (not supported)");
			}
		}
	}
}

/* Try to find in srv_keyword the word that looks closest to <word> by counting
 * transitions between letters, digits and other characters. Will return the
 * best matching word if found, otherwise NULL. An optional array of extra
 * words to compare may be passed in <extra>, but it must then be terminated
 * by a NULL entry. If unused it may be NULL.
 */
static const char *srv_find_best_kw(const char *word)
{
	uint8_t word_sig[1024];
	uint8_t list_sig[1024];
	const struct srv_kw_list *kwl;
	const char *best_ptr = NULL;
	int dist, best_dist = INT_MAX;
	const char **extra;
	int index;

	make_word_fingerprint(word_sig, word);
	list_for_each_entry(kwl, &srv_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			make_word_fingerprint(list_sig, kwl->kw[index].kw);
			dist = word_fingerprint_distance(word_sig, list_sig);
			if (dist < best_dist) {
				best_dist = dist;
				best_ptr = kwl->kw[index].kw;
			}
		}
	}

	for (extra = extra_kw_list; *extra; extra++) {
		make_word_fingerprint(list_sig, *extra);
		dist = word_fingerprint_distance(word_sig, list_sig);
		if (dist < best_dist) {
			best_dist = dist;
			best_ptr = *extra;
		}
	}

	if (best_dist > 2 * strlen(word) || (best_ptr && best_dist > 2 * strlen(best_ptr)))
		best_ptr = NULL;

	return best_ptr;
}

/* Parse the "backup" server keyword */
static int srv_parse_backup(char **args, int *cur_arg,
                            struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->flags |= SRV_F_BACKUP;
	return 0;
}


/* Parse the "cookie" server keyword */
static int srv_parse_cookie(char **args, int *cur_arg,
                            struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' expects <value> as argument.\n", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->cookie);
	newsrv->cookie = strdup(arg);
	newsrv->cklen = strlen(arg);
	newsrv->flags |= SRV_F_COOKIESET;
	return 0;
}

/* Parse the "disabled" server keyword */
static int srv_parse_disabled(char **args, int *cur_arg,
                              struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->next_admin |= SRV_ADMF_CMAINT | SRV_ADMF_FMAINT;
	newsrv->next_state = SRV_ST_STOPPED;
	newsrv->check.state |= CHK_ST_PAUSED;
	newsrv->check.health = 0;
	return 0;
}

/* Parse the "enabled" server keyword */
static int srv_parse_enabled(char **args, int *cur_arg,
                             struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->next_admin &= ~SRV_ADMF_CMAINT & ~SRV_ADMF_FMAINT;
	newsrv->next_state = SRV_ST_RUNNING;
	newsrv->check.state &= ~CHK_ST_PAUSED;
	newsrv->check.health = newsrv->check.rise;
	return 0;
}

/* Parse the "error-limit" server keyword */
static int srv_parse_error_limit(char **args, int *cur_arg,
                                 struct proxy *curproxy, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' expects an integer argument.",
		          args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->consecutive_errors_limit = atoi(args[*cur_arg + 1]);

	if (newsrv->consecutive_errors_limit <= 0) {
		memprintf(err, "%s has to be > 0.",
		          args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Parse the "ws" keyword */
static int srv_parse_ws(char **args, int *cur_arg,
                        struct proxy *curproxy, struct server *newsrv, char **err)
{
	if (!args[*cur_arg + 1]) {
		memprintf(err, "'%s' expects 'auto', 'h1' or 'h2' value", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[*cur_arg + 1], "h1") == 0) {
		newsrv->ws = SRV_WS_H1;
	}
	else if (strcmp(args[*cur_arg + 1], "h2") == 0) {
		newsrv->ws = SRV_WS_H2;
	}
	else if (strcmp(args[*cur_arg + 1], "auto") == 0) {
		newsrv->ws = SRV_WS_AUTO;
	}
	else {
		memprintf(err, "'%s' has to be 'auto', 'h1' or 'h2'", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}


	return 0;
}

/* Parse the "init-addr" server keyword */
static int srv_parse_init_addr(char **args, int *cur_arg,
                               struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *p, *end;
	int done;
	struct sockaddr_storage sa;

	newsrv->init_addr_methods = 0;
	memset(&newsrv->init_addr, 0, sizeof(newsrv->init_addr));

	for (p = args[*cur_arg + 1]; *p; p = end) {
		/* cut on next comma */
		for (end = p; *end && *end != ','; end++);
		if (*end)
			*(end++) = 0;

		memset(&sa, 0, sizeof(sa));
		if (strcmp(p, "libc") == 0) {
			done = srv_append_initaddr(&newsrv->init_addr_methods, SRV_IADDR_LIBC);
		}
		else if (strcmp(p, "last") == 0) {
			done = srv_append_initaddr(&newsrv->init_addr_methods, SRV_IADDR_LAST);
		}
		else if (strcmp(p, "none") == 0) {
			done = srv_append_initaddr(&newsrv->init_addr_methods, SRV_IADDR_NONE);
		}
		else if (str2ip2(p, &sa, 0)) {
			if (is_addr(&newsrv->init_addr)) {
				memprintf(err, "'%s' : initial address already specified, cannot add '%s'.",
				          args[*cur_arg], p);
				return ERR_ALERT | ERR_FATAL;
			}
			newsrv->init_addr = sa;
			done = srv_append_initaddr(&newsrv->init_addr_methods, SRV_IADDR_IP);
		}
		else {
			memprintf(err, "'%s' : unknown init-addr method '%s', supported methods are 'libc', 'last', 'none'.",
			          args[*cur_arg], p);
			return ERR_ALERT | ERR_FATAL;
		}
		if (!done) {
			memprintf(err, "'%s' : too many init-addr methods when trying to add '%s'",
			          args[*cur_arg], p);
			return ERR_ALERT | ERR_FATAL;
		}
	}

	return 0;
}

/* Parse the "log-proto" server keyword */
static int srv_parse_log_proto(char **args, int *cur_arg,
                               struct proxy *curproxy, struct server *newsrv, char **err)
{
	if (strcmp(args[*cur_arg + 1], "legacy") == 0)
		newsrv->log_proto = SRV_LOG_PROTO_LEGACY;
	else if (strcmp(args[*cur_arg + 1], "octet-count") == 0)
		newsrv->log_proto = SRV_LOG_PROTO_OCTET_COUNTING;
	else {
		memprintf(err, "'%s' expects one of 'legacy' or 'octet-count' but got '%s'",
		          args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Parse the "maxconn" server keyword */
static int srv_parse_maxconn(char **args, int *cur_arg,
                             struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->maxconn = atol(args[*cur_arg + 1]);
	return 0;
}

/* Parse the "maxqueue" server keyword */
static int srv_parse_maxqueue(char **args, int *cur_arg,
                              struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->maxqueue = atol(args[*cur_arg + 1]);
	return 0;
}

/* Parse the "minconn" server keyword */
static int srv_parse_minconn(char **args, int *cur_arg,
                             struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->minconn = atol(args[*cur_arg + 1]);
	return 0;
}

static int srv_parse_max_reuse(char **args, int *cur_arg, struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' expects <value> as argument.\n", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	newsrv->max_reuse = atoi(arg);

	return 0;
}

static int srv_parse_pool_purge_delay(char **args, int *cur_arg, struct proxy *curproxy, struct server *newsrv, char **err)
{
	const char *res;
	char *arg;
	unsigned int time;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' expects <value> as argument.\n", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	res = parse_time_err(arg, &time, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[*cur_arg+1], args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[*cur_arg+1], args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.\n",
		    *res, args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	newsrv->pool_purge_delay = time;

	return 0;
}

static int srv_parse_pool_low_conn(char **args, int *cur_arg, struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' expects <value> as argument.\n", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->low_idle_conns = atoi(arg);
	return 0;
}

static int srv_parse_pool_max_conn(char **args, int *cur_arg, struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' expects <value> as argument.\n", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->max_idle_conns = atoi(arg);
	if ((int)newsrv->max_idle_conns < -1) {
		memprintf(err, "'%s' must be >= -1", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "id" server keyword */
static int srv_parse_id(char **args, int *cur_arg, struct proxy *curproxy, struct server *newsrv, char **err)
{
	struct eb32_node *node;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : expects an integer argument", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->puid = atol(args[*cur_arg + 1]);
	newsrv->conf.id.key = newsrv->puid;

	if (newsrv->puid <= 0) {
		memprintf(err, "'%s' : custom id has to be > 0", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	node = eb32_lookup(&curproxy->conf.used_server_id, newsrv->puid);
	if (node) {
		struct server *target = container_of(node, struct server, conf.id);
		memprintf(err, "'%s' : custom id %d already used at %s:%d ('server %s')",
		          args[*cur_arg], newsrv->puid, target->conf.file, target->conf.line,
		          target->id);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->flags |= SRV_F_FORCED_ID;
	return 0;
}

/* Parse the "namespace" server keyword */
static int srv_parse_namespace(char **args, int *cur_arg,
                               struct proxy *curproxy, struct server *newsrv, char **err)
{
#ifdef USE_NS
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' : expects <name> as argument", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(arg, "*") == 0) {
		/* Use the namespace associated with the connection (if present). */
		newsrv->flags |= SRV_F_USE_NS_FROM_PP;
		return 0;
	}

	/*
	 * As this parser may be called several times for the same 'default-server'
	 * object, or for a new 'server' instance deriving from a 'default-server'
	 * one with SRV_F_USE_NS_FROM_PP flag enabled, let's reset it.
	 */
	newsrv->flags &= ~SRV_F_USE_NS_FROM_PP;

	newsrv->netns = netns_store_lookup(arg, strlen(arg));
	if (!newsrv->netns)
		newsrv->netns = netns_store_insert(arg);

	if (!newsrv->netns) {
		memprintf(err, "Cannot open namespace '%s'", arg);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
#else
	memprintf(err, "'%s': '%s' option not implemented", args[0], args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* Parse the "no-backup" server keyword */
static int srv_parse_no_backup(char **args, int *cur_arg,
                               struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->flags &= ~SRV_F_BACKUP;
	return 0;
}


/* Disable server PROXY protocol flags. */
static inline int srv_disable_pp_flags(struct server *srv, unsigned int flags)
{
	srv->pp_opts &= ~flags;
	return 0;
}

/* Parse the "no-send-proxy" server keyword */
static int srv_parse_no_send_proxy(char **args, int *cur_arg,
                                   struct proxy *curproxy, struct server *newsrv, char **err)
{
	return srv_disable_pp_flags(newsrv, SRV_PP_V1);
}

/* Parse the "no-send-proxy-v2" server keyword */
static int srv_parse_no_send_proxy_v2(char **args, int *cur_arg,
                                      struct proxy *curproxy, struct server *newsrv, char **err)
{
	return srv_disable_pp_flags(newsrv, SRV_PP_V2);
}

/* Parse the "no-tfo" server keyword */
static int srv_parse_no_tfo(char **args, int *cur_arg,
                            struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->flags &= ~SRV_F_FASTOPEN;
	return 0;
}

/* Parse the "non-stick" server keyword */
static int srv_parse_non_stick(char **args, int *cur_arg,
                               struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->flags |= SRV_F_NON_STICK;
	return 0;
}

/* Enable server PROXY protocol flags. */
static inline int srv_enable_pp_flags(struct server *srv, unsigned int flags)
{
	srv->pp_opts |= flags;
	return 0;
}
/* parse the "proto" server keyword */
static int srv_parse_proto(char **args, int *cur_arg,
			   struct proxy *px, struct server *newsrv, char **err)
{
	struct ist proto;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	proto = ist(args[*cur_arg + 1]);
	newsrv->mux_proto = get_mux_proto(proto);
	if (!newsrv->mux_proto) {
		memprintf(err, "'%s' :  unknown MUX protocol '%s'", args[*cur_arg], args[*cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

/* parse the "proxy-v2-options" */
static int srv_parse_proxy_v2_options(char **args, int *cur_arg,
				      struct proxy *px, struct server *newsrv, char **err)
{
	char *p, *n;
	for (p = args[*cur_arg+1]; p; p = n) {
		n = strchr(p, ',');
		if (n)
			*n++ = '\0';
		if (strcmp(p, "ssl") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_SSL;
		} else if (strcmp(p, "cert-cn") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_SSL;
			newsrv->pp_opts |= SRV_PP_V2_SSL_CN;
		} else if (strcmp(p, "cert-key") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_SSL;
			newsrv->pp_opts |= SRV_PP_V2_SSL_KEY_ALG;
		} else if (strcmp(p, "cert-sig") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_SSL;
			newsrv->pp_opts |= SRV_PP_V2_SSL_SIG_ALG;
		} else if (strcmp(p, "ssl-cipher") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_SSL;
			newsrv->pp_opts |= SRV_PP_V2_SSL_CIPHER;
		} else if (strcmp(p, "authority") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_AUTHORITY;
		} else if (strcmp(p, "crc32c") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_CRC32C;
		} else if (strcmp(p, "unique-id") == 0) {
			newsrv->pp_opts |= SRV_PP_V2_UNIQUE_ID;
		} else
			goto fail;
	}
	return 0;
 fail:
	if (err)
		memprintf(err, "'%s' : proxy v2 option not implemented", p);
	return ERR_ALERT | ERR_FATAL;
}

/* Parse the "observe" server keyword */
static int srv_parse_observe(char **args, int *cur_arg,
                             struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' expects <mode> as argument.\n", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(arg, "none") == 0) {
		newsrv->observe = HANA_OBS_NONE;
	}
	else if (strcmp(arg, "layer4") == 0) {
		newsrv->observe = HANA_OBS_LAYER4;
	}
	else if (strcmp(arg, "layer7") == 0) {
		if (curproxy->mode != PR_MODE_HTTP) {
			memprintf(err, "'%s' can only be used in http proxies.\n", arg);
			return ERR_ALERT;
		}
		newsrv->observe = HANA_OBS_LAYER7;
	}
	else {
		memprintf(err, "'%s' expects one of 'none', 'layer4', 'layer7' "
		               "but got '%s'\n", args[*cur_arg], arg);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Parse the "on-error" server keyword */
static int srv_parse_on_error(char **args, int *cur_arg,
                              struct proxy *curproxy, struct server *newsrv, char **err)
{
	if (strcmp(args[*cur_arg + 1], "fastinter") == 0)
		newsrv->onerror = HANA_ONERR_FASTINTER;
	else if (strcmp(args[*cur_arg + 1], "fail-check") == 0)
		newsrv->onerror = HANA_ONERR_FAILCHK;
	else if (strcmp(args[*cur_arg + 1], "sudden-death") == 0)
		newsrv->onerror = HANA_ONERR_SUDDTH;
	else if (strcmp(args[*cur_arg + 1], "mark-down") == 0)
		newsrv->onerror = HANA_ONERR_MARKDWN;
	else {
		memprintf(err, "'%s' expects one of 'fastinter', "
		          "'fail-check', 'sudden-death' or 'mark-down' but got '%s'",
		          args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Parse the "on-marked-down" server keyword */
static int srv_parse_on_marked_down(char **args, int *cur_arg,
                                    struct proxy *curproxy, struct server *newsrv, char **err)
{
	if (strcmp(args[*cur_arg + 1], "shutdown-sessions") == 0)
		newsrv->onmarkeddown = HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS;
	else {
		memprintf(err, "'%s' expects 'shutdown-sessions' but got '%s'",
		          args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Parse the "on-marked-up" server keyword */
static int srv_parse_on_marked_up(char **args, int *cur_arg,
                                  struct proxy *curproxy, struct server *newsrv, char **err)
{
	if (strcmp(args[*cur_arg + 1], "shutdown-backup-sessions") == 0)
		newsrv->onmarkedup = HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS;
	else {
		memprintf(err, "'%s' expects 'shutdown-backup-sessions' but got '%s'",
		          args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Parse the "redir" server keyword */
static int srv_parse_redir(char **args, int *cur_arg,
                           struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' expects <prefix> as argument.\n", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->rdr_pfx);
	newsrv->rdr_pfx = strdup(arg);
	newsrv->rdr_len = strlen(arg);

	return 0;
}

/* Parse the "resolvers" server keyword */
static int srv_parse_resolvers(char **args, int *cur_arg,
                           struct proxy *curproxy, struct server *newsrv, char **err)
{
	free(newsrv->resolvers_id);
	newsrv->resolvers_id = strdup(args[*cur_arg + 1]);
	return 0;
}

/* Parse the "resolve-net" server keyword */
static int srv_parse_resolve_net(char **args, int *cur_arg,
                                 struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *p, *e;
	unsigned char mask;
	struct resolv_options *opt;

	if (!args[*cur_arg + 1] || args[*cur_arg + 1][0] == '\0') {
		memprintf(err, "'%s' expects a list of networks.",
		          args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	opt = &newsrv->resolv_opts;

	/* Split arguments by comma, and convert it from ipv4 or ipv6
	 * string network in in_addr or in6_addr.
	 */
	p = args[*cur_arg + 1];
	e = p;
	while (*p != '\0') {
		/* If no room available, return error. */
		if (opt->pref_net_nb >= SRV_MAX_PREF_NET) {
			memprintf(err, "'%s' exceed %d networks.",
			          args[*cur_arg], SRV_MAX_PREF_NET);
			return ERR_ALERT | ERR_FATAL;
		}
		/* look for end or comma. */
		while (*e != ',' && *e != '\0')
			e++;
		if (*e == ',') {
			*e = '\0';
			e++;
		}
		if (str2net(p, 0, &opt->pref_net[opt->pref_net_nb].addr.in4,
		                  &opt->pref_net[opt->pref_net_nb].mask.in4)) {
			/* Try to convert input string from ipv4 or ipv6 network. */
			opt->pref_net[opt->pref_net_nb].family = AF_INET;
		} else if (str62net(p, &opt->pref_net[opt->pref_net_nb].addr.in6,
		                     &mask)) {
			/* Try to convert input string from ipv6 network. */
			len2mask6(mask, &opt->pref_net[opt->pref_net_nb].mask.in6);
			opt->pref_net[opt->pref_net_nb].family = AF_INET6;
		} else {
			/* All network conversions fail, return error. */
			memprintf(err, "'%s' invalid network '%s'.",
			          args[*cur_arg], p);
			return ERR_ALERT | ERR_FATAL;
		}
		opt->pref_net_nb++;
		p = e;
	}

	return 0;
}

/* Parse the "resolve-opts" server keyword */
static int srv_parse_resolve_opts(char **args, int *cur_arg,
                                  struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *p, *end;

	for (p = args[*cur_arg + 1]; *p; p = end) {
		/* cut on next comma */
		for (end = p; *end && *end != ','; end++);
		if (*end)
			*(end++) = 0;

		if (strcmp(p, "allow-dup-ip") == 0) {
			newsrv->resolv_opts.accept_duplicate_ip = 1;
		}
		else if (strcmp(p, "ignore-weight") == 0) {
			newsrv->resolv_opts.ignore_weight = 1;
		}
		else if (strcmp(p, "prevent-dup-ip") == 0) {
			newsrv->resolv_opts.accept_duplicate_ip = 0;
		}
		else {
			memprintf(err, "'%s' : unknown resolve-opts option '%s', supported methods are 'allow-dup-ip', 'ignore-weight', and 'prevent-dup-ip'.",
			          args[*cur_arg], p);
			return ERR_ALERT | ERR_FATAL;
		}
	}

	return 0;
}

/* Parse the "resolve-prefer" server keyword */
static int srv_parse_resolve_prefer(char **args, int *cur_arg,
                                    struct proxy *curproxy, struct server *newsrv, char **err)
{
	if (strcmp(args[*cur_arg + 1], "ipv4") == 0)
		newsrv->resolv_opts.family_prio = AF_INET;
	else if (strcmp(args[*cur_arg + 1], "ipv6") == 0)
		newsrv->resolv_opts.family_prio = AF_INET6;
	else {
		memprintf(err, "'%s' expects either ipv4 or ipv6 as argument.",
		          args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Parse the "send-proxy" server keyword */
static int srv_parse_send_proxy(char **args, int *cur_arg,
                                struct proxy *curproxy, struct server *newsrv, char **err)
{
	return srv_enable_pp_flags(newsrv, SRV_PP_V1);
}

/* Parse the "send-proxy-v2" server keyword */
static int srv_parse_send_proxy_v2(char **args, int *cur_arg,
                                   struct proxy *curproxy, struct server *newsrv, char **err)
{
	return srv_enable_pp_flags(newsrv, SRV_PP_V2);
}

/* Parse the "slowstart" server keyword */
static int srv_parse_slowstart(char **args, int *cur_arg,
                               struct proxy *curproxy, struct server *newsrv, char **err)
{
	/* slowstart is stored in seconds */
	unsigned int val;
	const char *time_err = parse_time_err(args[*cur_arg + 1], &val, TIME_UNIT_MS);

	if (time_err == PARSE_TIME_OVER) {
		memprintf(err, "overflow in argument <%s> to <%s> of server %s, maximum value is 2147483647 ms (~24.8 days).",
		          args[*cur_arg+1], args[*cur_arg], newsrv->id);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (time_err == PARSE_TIME_UNDER) {
		memprintf(err, "underflow in argument <%s> to <%s> of server %s, minimum non-null value is 1 ms.",
		          args[*cur_arg+1], args[*cur_arg], newsrv->id);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (time_err) {
		memprintf(err, "unexpected character '%c' in 'slowstart' argument of server %s.",
		          *time_err, newsrv->id);
		return ERR_ALERT | ERR_FATAL;
	}
	newsrv->slowstart = (val + 999) / 1000;

	return 0;
}

/* Parse the "source" server keyword */
static int srv_parse_source(char **args, int *cur_arg,
                            struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *errmsg;
	int port_low, port_high;
	struct sockaddr_storage *sk;

	errmsg = NULL;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' expects <addr>[:<port>[-<port>]], and optionally '%s' <addr>, "
		               "and '%s' <name> as argument.\n", args[*cur_arg], "usesrc", "interface");
		goto err;
	}

	/* 'sk' is statically allocated (no need to be freed). */
	sk = str2sa_range(args[*cur_arg + 1], NULL, &port_low, &port_high, NULL, NULL,
	                  &errmsg, NULL, NULL,
		          PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_RANGE | PA_O_STREAM | PA_O_CONNECT);
	if (!sk) {
		memprintf(err, "'%s %s' : %s\n", args[*cur_arg], args[*cur_arg + 1], errmsg);
		goto err;
	}

	newsrv->conn_src.opts |= CO_SRC_BIND;
	newsrv->conn_src.source_addr = *sk;

	if (port_low != port_high) {
		int i;

		newsrv->conn_src.sport_range = port_range_alloc_range(port_high - port_low + 1);
		if (!newsrv->conn_src.sport_range) {
			ha_alert("Server '%s': Out of memory (sport_range)\n", args[0]);
			goto err;
		}
		for (i = 0; i < newsrv->conn_src.sport_range->size; i++)
			newsrv->conn_src.sport_range->ports[i] = port_low + i;
	}

	*cur_arg += 2;
	while (*(args[*cur_arg])) {
		if (strcmp(args[*cur_arg], "usesrc") == 0) {  /* address to use outside */
#if defined(CONFIG_HAP_TRANSPARENT)
			if (!*args[*cur_arg + 1]) {
				ha_alert("'usesrc' expects <addr>[:<port>], 'client', 'clientip', "
					 "or 'hdr_ip(name,#)' as argument.\n");
				goto err;
			}
			if (strcmp(args[*cur_arg + 1], "client") == 0) {
				newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
				newsrv->conn_src.opts |= CO_SRC_TPROXY_CLI;
			}
			else if (strcmp(args[*cur_arg + 1], "clientip") == 0) {
				newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
				newsrv->conn_src.opts |= CO_SRC_TPROXY_CIP;
			}
			else if (!strncmp(args[*cur_arg + 1], "hdr_ip(", 7)) {
				char *name, *end;

				name = args[*cur_arg + 1] + 7;
				while (isspace((unsigned char)*name))
					name++;

				end = name;
				while (*end && !isspace((unsigned char)*end) && *end != ',' && *end != ')')
					end++;

				newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
				newsrv->conn_src.opts |= CO_SRC_TPROXY_DYN;
				free(newsrv->conn_src.bind_hdr_name);
				newsrv->conn_src.bind_hdr_name = calloc(1, end - name + 1);
				if (!newsrv->conn_src.bind_hdr_name) {
					ha_alert("Server '%s': Out of memory (bind_hdr_name)\n", args[0]);
					goto err;
				}
				newsrv->conn_src.bind_hdr_len = end - name;
				memcpy(newsrv->conn_src.bind_hdr_name, name, end - name);
				newsrv->conn_src.bind_hdr_name[end - name] = '\0';
				newsrv->conn_src.bind_hdr_occ = -1;

				/* now look for an occurrence number */
				while (isspace((unsigned char)*end))
					end++;
				if (*end == ',') {
					end++;
					name = end;
					if (*end == '-')
						end++;
					while (isdigit((unsigned char)*end))
						end++;
					newsrv->conn_src.bind_hdr_occ = strl2ic(name, end - name);
				}

				if (newsrv->conn_src.bind_hdr_occ < -MAX_HDR_HISTORY) {
					ha_alert("usesrc hdr_ip(name,num) does not support negative"
						 " occurrences values smaller than %d.\n", MAX_HDR_HISTORY);
					goto err;
				}
			}
			else {
				struct sockaddr_storage *sk;
				int port1, port2;

				/* 'sk' is statically allocated (no need to be freed). */
				sk = str2sa_range(args[*cur_arg + 1], NULL, &port1, &port2, NULL, NULL,
				                  &errmsg, NULL, NULL,
				                  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_STREAM | PA_O_CONNECT);
				if (!sk) {
					ha_alert("'%s %s' : %s\n", args[*cur_arg], args[*cur_arg + 1], errmsg);
					goto err;
				}

				newsrv->conn_src.tproxy_addr = *sk;
				newsrv->conn_src.opts |= CO_SRC_TPROXY_ADDR;
			}
			global.last_checks |= LSTCHK_NETADM;
			*cur_arg += 2;
			continue;
#else	/* no TPROXY support */
			ha_alert("'usesrc' not allowed here because support for TPROXY was not compiled in.\n");
			goto err;
#endif /* defined(CONFIG_HAP_TRANSPARENT) */
		} /* "usesrc" */

		if (strcmp(args[*cur_arg], "interface") == 0) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
			if (!*args[*cur_arg + 1]) {
				ha_alert("'%s' : missing interface name.\n", args[0]);
				goto err;
			}
			free(newsrv->conn_src.iface_name);
			newsrv->conn_src.iface_name = strdup(args[*cur_arg + 1]);
			newsrv->conn_src.iface_len  = strlen(newsrv->conn_src.iface_name);
			global.last_checks |= LSTCHK_NETADM;
#else
			ha_alert("'%s' : '%s' option not implemented.\n", args[0], args[*cur_arg]);
			goto err;
#endif
			*cur_arg += 2;
			continue;
		}
		/* this keyword in not an option of "source" */
		break;
	} /* while */

	return 0;

 err:
	free(errmsg);
	return ERR_ALERT | ERR_FATAL;
}

/* Parse the "stick" server keyword */
static int srv_parse_stick(char **args, int *cur_arg,
                           struct proxy *curproxy, struct server *newsrv, char **err)
{
	newsrv->flags &= ~SRV_F_NON_STICK;
	return 0;
}

/* Parse the "track" server keyword */
static int srv_parse_track(char **args, int *cur_arg,
                           struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'track' expects [<proxy>/]<server> as argument.\n");
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->trackit);
	newsrv->trackit = strdup(arg);

	return 0;
}

/* Parse the "socks4" server keyword */
static int srv_parse_socks4(char **args, int *cur_arg,
                            struct proxy *curproxy, struct server *newsrv, char **err)
{
	char *errmsg;
	int port_low, port_high;
	struct sockaddr_storage *sk;

	errmsg = NULL;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' expects <addr>:<port> as argument.\n", args[*cur_arg]);
		goto err;
	}

	/* 'sk' is statically allocated (no need to be freed). */
	sk = str2sa_range(args[*cur_arg + 1], NULL, &port_low, &port_high, NULL, NULL,
	                  &errmsg, NULL, NULL,
	                  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_STREAM | PA_O_CONNECT);
	if (!sk) {
		memprintf(err, "'%s %s' : %s\n", args[*cur_arg], args[*cur_arg + 1], errmsg);
		goto err;
	}

	newsrv->flags |= SRV_F_SOCKS4_PROXY;
	newsrv->socks4_addr = *sk;

	return 0;

 err:
	free(errmsg);
	return ERR_ALERT | ERR_FATAL;
}


/* parse the "tfo" server keyword */
static int srv_parse_tfo(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->flags |= SRV_F_FASTOPEN;
	return 0;
}

/* parse the "usesrc" server keyword */
static int srv_parse_usesrc(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	memprintf(err, "'%s' only allowed after a '%s' statement.",
	          "usesrc", "source");
	return ERR_ALERT | ERR_FATAL;
}

/* parse the "weight" server keyword */
static int srv_parse_weight(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	int w;

	w = atol(args[*cur_arg + 1]);
	if (w < 0 || w > SRV_UWGHT_MAX) {
		memprintf(err, "weight of server %s is not within 0 and %d (%d).",
		          newsrv->id, SRV_UWGHT_MAX, w);
		return ERR_ALERT | ERR_FATAL;
	}
	newsrv->uweight = newsrv->iweight = w;

	return 0;
}

/* Shutdown all connections of a server. The caller must pass a termination
 * code in <why>, which must be one of SF_ERR_* indicating the reason for the
 * shutdown.
 *
 * Must be called with the server lock held.
 */
void srv_shutdown_streams(struct server *srv, int why)
{
	struct stream *stream;
	struct mt_list *elt1, elt2;
	int thr;

	for (thr = 0; thr < global.nbthread; thr++)
		mt_list_for_each_entry_safe(stream, &srv->per_thr[thr].streams, by_srv, elt1, elt2)
			if (stream->srv_conn == srv)
				stream_shutdown(stream, why);
}

/* Shutdown all connections of all backup servers of a proxy. The caller must
 * pass a termination code in <why>, which must be one of SF_ERR_* indicating
 * the reason for the shutdown.
 *
 * Must be called with the server lock held.
 */
void srv_shutdown_backup_streams(struct proxy *px, int why)
{
	struct server *srv;

	for (srv = px->srv; srv != NULL; srv = srv->next)
		if (srv->flags & SRV_F_BACKUP)
			srv_shutdown_streams(srv, why);
}

/* Appends some information to a message string related to a server going UP or
 * DOWN.  If both <forced> and <reason> are null and the server tracks another
 * one, a "via" information will be provided to know where the status came from.
 * If <check> is non-null, an entire string describing the check result will be
 * appended after a comma and a space (eg: to report some information from the
 * check that changed the state). In the other case, the string will be built
 * using the check results stored into the struct server if present.
 * If <xferred> is non-negative, some information about requeued sessions are
 * provided.
 *
 * Must be called with the server lock held.
 */
void srv_append_status(struct buffer *msg, struct server *s,
		       struct check *check, int xferred, int forced)
{
	short status = s->op_st_chg.status;
	short code = s->op_st_chg.code;
	long duration = s->op_st_chg.duration;
	char *desc = s->op_st_chg.reason;

	if (check) {
		status = check->status;
		code = check->code;
		duration = check->duration;
		desc = check->desc;
	}

	if (status != -1) {
		chunk_appendf(msg, ", reason: %s", get_check_status_description(status));

		if (status >= HCHK_STATUS_L57DATA)
			chunk_appendf(msg, ", code: %d", code);

		if (desc && *desc) {
			struct buffer src;

			chunk_appendf(msg, ", info: \"");

			chunk_initlen(&src, desc, 0, strlen(desc));
			chunk_asciiencode(msg, &src, '"');

			chunk_appendf(msg, "\"");
		}

		if (duration >= 0)
			chunk_appendf(msg, ", check duration: %ldms", duration);
	}
        else if (desc && *desc) {
                chunk_appendf(msg, ", %s", desc);
        }
	else if (!forced && s->track) {
		chunk_appendf(msg, " via %s/%s", s->track->proxy->id, s->track->id);
	}

	if (xferred >= 0) {
		if (s->next_state == SRV_ST_STOPPED)
			chunk_appendf(msg, ". %d active and %d backup servers left.%s"
				" %d sessions active, %d requeued, %d remaining in queue",
				s->proxy->srv_act, s->proxy->srv_bck,
				(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
				s->cur_sess, xferred, s->queue.length);
		else
			chunk_appendf(msg, ". %d active and %d backup servers online.%s"
				" %d sessions requeued, %d total in queue",
				s->proxy->srv_act, s->proxy->srv_bck,
				(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
				xferred, s->queue.length);
	}
}

/* Marks server <s> down, regardless of its checks' statuses. The server is
 * registered in a list to postpone the counting of the remaining servers on
 * the proxy and transfers queued streams whenever possible to other servers at
 * a sync point. Maintenance servers are ignored. It stores the <reason> if
 * non-null as the reason for going down or the available data from the check
 * struct to recompute this reason later.
 *
 * Must be called with the server lock held.
 */
void srv_set_stopped(struct server *s, const char *reason, struct check *check)
{
	struct server *srv;

	if ((s->cur_admin & SRV_ADMF_MAINT) || s->next_state == SRV_ST_STOPPED)
		return;

	s->next_state = SRV_ST_STOPPED;
	*s->op_st_chg.reason = 0;
	s->op_st_chg.status = -1;
	if (reason) {
		strlcpy2(s->op_st_chg.reason, reason, sizeof(s->op_st_chg.reason));
	}
	else if (check) {
		strlcpy2(s->op_st_chg.reason, check->desc, sizeof(s->op_st_chg.reason));
		s->op_st_chg.code = check->code;
		s->op_st_chg.status = check->status;
		s->op_st_chg.duration = check->duration;
	}

	/* propagate changes */
	srv_update_status(s);

	for (srv = s->trackers; srv; srv = srv->tracknext) {
		HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
		srv_set_stopped(srv, NULL, NULL);
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	}
}

/* Marks server <s> up regardless of its checks' statuses and provided it isn't
 * in maintenance. The server is registered in a list to postpone the counting
 * of the remaining servers on the proxy and tries to grab requests from the
 * proxy at a sync point. Maintenance servers are ignored. It stores the
 * <reason> if non-null as the reason for going down or the available data
 * from the check struct to recompute this reason later.
 *
 * Must be called with the server lock held.
 */
void srv_set_running(struct server *s, const char *reason, struct check *check)
{
	struct server *srv;

	if (s->cur_admin & SRV_ADMF_MAINT)
		return;

	if (s->next_state == SRV_ST_STARTING || s->next_state == SRV_ST_RUNNING)
		return;

	s->next_state = SRV_ST_STARTING;
	*s->op_st_chg.reason = 0;
	s->op_st_chg.status = -1;
	if (reason) {
		strlcpy2(s->op_st_chg.reason, reason, sizeof(s->op_st_chg.reason));
	}
	else if (check) {
		strlcpy2(s->op_st_chg.reason, check->desc, sizeof(s->op_st_chg.reason));
		s->op_st_chg.code = check->code;
		s->op_st_chg.status = check->status;
		s->op_st_chg.duration = check->duration;
	}

	if (s->slowstart <= 0)
		s->next_state = SRV_ST_RUNNING;

	/* propagate changes */
	srv_update_status(s);

	for (srv = s->trackers; srv; srv = srv->tracknext) {
		HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
		srv_set_running(srv, NULL, NULL);
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	}
}

/* Marks server <s> stopping regardless of its checks' statuses and provided it
 * isn't in maintenance. The server is registered in a list to postpone the
 * counting of the remaining servers on the proxy and tries to grab requests
 * from the proxy. Maintenance servers are ignored. It stores the
 * <reason> if non-null as the reason for going down or the available data
 * from the check struct to recompute this reason later.
 * up. Note that it makes use of the trash to build the log strings, so <reason>
 * must not be placed there.
 *
 * Must be called with the server lock held.
 */
void srv_set_stopping(struct server *s, const char *reason, struct check *check)
{
	struct server *srv;

	if (s->cur_admin & SRV_ADMF_MAINT)
		return;

	if (s->next_state == SRV_ST_STOPPING)
		return;

	s->next_state = SRV_ST_STOPPING;
	*s->op_st_chg.reason = 0;
	s->op_st_chg.status = -1;
	if (reason) {
		strlcpy2(s->op_st_chg.reason, reason, sizeof(s->op_st_chg.reason));
	}
	else if (check) {
		strlcpy2(s->op_st_chg.reason, check->desc, sizeof(s->op_st_chg.reason));
		s->op_st_chg.code = check->code;
		s->op_st_chg.status = check->status;
		s->op_st_chg.duration = check->duration;
	}

	/* propagate changes */
	srv_update_status(s);

	for (srv = s->trackers; srv; srv = srv->tracknext) {
		HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
		srv_set_stopping(srv, NULL, NULL);
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	}
}

/* Enables admin flag <mode> (among SRV_ADMF_*) on server <s>. This is used to
 * enforce either maint mode or drain mode. It is not allowed to set more than
 * one flag at once. The equivalent "inherited" flag is propagated to all
 * tracking servers. Maintenance mode disables health checks (but not agent
 * checks). When either the flag is already set or no flag is passed, nothing
 * is done. If <cause> is non-null, it will be displayed at the end of the log
 * lines to justify the state change.
 *
 * Must be called with the server lock held.
 */
void srv_set_admin_flag(struct server *s, enum srv_admin mode, const char *cause)
{
	struct server *srv;

	if (!mode)
		return;

	/* stop going down as soon as we meet a server already in the same state */
	if (s->next_admin & mode)
		return;

	s->next_admin |= mode;
	if (cause)
		strlcpy2(s->adm_st_chg_cause, cause, sizeof(s->adm_st_chg_cause));

	/* propagate changes */
	srv_update_status(s);

	/* stop going down if the equivalent flag was already present (forced or inherited) */
	if (((mode & SRV_ADMF_MAINT) && (s->next_admin & ~mode & SRV_ADMF_MAINT)) ||
	    ((mode & SRV_ADMF_DRAIN) && (s->next_admin & ~mode & SRV_ADMF_DRAIN)))
		return;

	/* compute the inherited flag to propagate */
	if (mode & SRV_ADMF_MAINT)
		mode = SRV_ADMF_IMAINT;
	else if (mode & SRV_ADMF_DRAIN)
		mode = SRV_ADMF_IDRAIN;

	for (srv = s->trackers; srv; srv = srv->tracknext) {
		HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
		srv_set_admin_flag(srv, mode, cause);
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	}
}

/* Disables admin flag <mode> (among SRV_ADMF_*) on server <s>. This is used to
 * stop enforcing either maint mode or drain mode. It is not allowed to set more
 * than one flag at once. The equivalent "inherited" flag is propagated to all
 * tracking servers. Leaving maintenance mode re-enables health checks. When
 * either the flag is already cleared or no flag is passed, nothing is done.
 *
 * Must be called with the server lock held.
 */
void srv_clr_admin_flag(struct server *s, enum srv_admin mode)
{
	struct server *srv;

	if (!mode)
		return;

	/* stop going down as soon as we see the flag is not there anymore */
	if (!(s->next_admin & mode))
		return;

	s->next_admin &= ~mode;

	/* propagate changes */
	srv_update_status(s);

	/* stop going down if the equivalent flag is still present (forced or inherited) */
	if (((mode & SRV_ADMF_MAINT) && (s->next_admin & SRV_ADMF_MAINT)) ||
	    ((mode & SRV_ADMF_DRAIN) && (s->next_admin & SRV_ADMF_DRAIN)))
		return;

	if (mode & SRV_ADMF_MAINT)
		mode = SRV_ADMF_IMAINT;
	else if (mode & SRV_ADMF_DRAIN)
		mode = SRV_ADMF_IDRAIN;

	for (srv = s->trackers; srv; srv = srv->tracknext) {
		HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
		srv_clr_admin_flag(srv, mode);
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	}
}

/* principle: propagate maint and drain to tracking servers. This is useful
 * upon startup so that inherited states are correct.
 */
static void srv_propagate_admin_state(struct server *srv)
{
	struct server *srv2;

	if (!srv->trackers)
		return;

	for (srv2 = srv->trackers; srv2; srv2 = srv2->tracknext) {
		HA_SPIN_LOCK(SERVER_LOCK, &srv2->lock);
		if (srv->next_admin & (SRV_ADMF_MAINT | SRV_ADMF_CMAINT))
			srv_set_admin_flag(srv2, SRV_ADMF_IMAINT, NULL);

		if (srv->next_admin & SRV_ADMF_DRAIN)
			srv_set_admin_flag(srv2, SRV_ADMF_IDRAIN, NULL);
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv2->lock);
	}
}

/* Compute and propagate the admin states for all servers in proxy <px>.
 * Only servers *not* tracking another one are considered, because other
 * ones will be handled when the server they track is visited.
 */
void srv_compute_all_admin_states(struct proxy *px)
{
	struct server *srv;

	for (srv = px->srv; srv; srv = srv->next) {
		if (srv->track)
			continue;
		srv_propagate_admin_state(srv);
	}
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 * Note: -1 as ->skip value means that the number of arguments are variable.
 */
static struct srv_kw_list srv_kws = { "ALL", { }, {
	{ "backup",              srv_parse_backup,              0,  1,  1 }, /* Flag as backup server */
	{ "cookie",              srv_parse_cookie,              1,  1,  0 }, /* Assign a cookie to the server */
	{ "disabled",            srv_parse_disabled,            0,  1,  1 }, /* Start the server in 'disabled' state */
	{ "enabled",             srv_parse_enabled,             0,  1,  1 }, /* Start the server in 'enabled' state */
	{ "error-limit",         srv_parse_error_limit,         1,  1,  1 }, /* Configure the consecutive count of check failures to consider a server on error */
	{ "ws",                  srv_parse_ws,                  1,  1,  1 }, /* websocket protocol */
	{ "id",                  srv_parse_id,                  1,  0,  1 }, /* set id# of server */
	{ "init-addr",           srv_parse_init_addr,           1,  1,  0 }, /* */
	{ "log-proto",           srv_parse_log_proto,           1,  1,  0 }, /* Set the protocol for event messages, only relevant in a ring section */
	{ "maxconn",             srv_parse_maxconn,             1,  1,  1 }, /* Set the max number of concurrent connection */
	{ "maxqueue",            srv_parse_maxqueue,            1,  1,  1 }, /* Set the max number of connection to put in queue */
	{ "max-reuse",           srv_parse_max_reuse,           1,  1,  0 }, /* Set the max number of requests on a connection, -1 means unlimited */
	{ "minconn",             srv_parse_minconn,             1,  1,  1 }, /* Enable a dynamic maxconn limit */
	{ "namespace",           srv_parse_namespace,           1,  1,  0 }, /* Namespace the server socket belongs to (if supported) */
	{ "no-backup",           srv_parse_no_backup,           0,  1,  1 }, /* Flag as non-backup server */
	{ "no-send-proxy",       srv_parse_no_send_proxy,       0,  1,  1 }, /* Disable use of PROXY V1 protocol */
	{ "no-send-proxy-v2",    srv_parse_no_send_proxy_v2,    0,  1,  1 }, /* Disable use of PROXY V2 protocol */
	{ "no-tfo",              srv_parse_no_tfo,              0,  1,  1 }, /* Disable use of TCP Fast Open */
	{ "non-stick",           srv_parse_non_stick,           0,  1,  0 }, /* Disable stick-table persistence */
	{ "observe",             srv_parse_observe,             1,  1,  1 }, /* Enables health adjusting based on observing communication with the server */
	{ "on-error",            srv_parse_on_error,            1,  1,  1 }, /* Configure the action on check failure */
	{ "on-marked-down",      srv_parse_on_marked_down,      1,  1,  1 }, /* Configure the action when a server is marked down */
	{ "on-marked-up",        srv_parse_on_marked_up,        1,  1,  1 }, /* Configure the action when a server is marked up */
	{ "pool-low-conn",       srv_parse_pool_low_conn,       1,  1,  1 }, /* Set the min number of orphan idle connecbefore being allowed to pick from other threads */
	{ "pool-max-conn",       srv_parse_pool_max_conn,       1,  1,  1 }, /* Set the max number of orphan idle connections, -1 means unlimited */
	{ "pool-purge-delay",    srv_parse_pool_purge_delay,    1,  1,  1 }, /* Set the time before we destroy orphan idle connections, defaults to 1s */
	{ "proto",               srv_parse_proto,               1,  1,  1 }, /* Set the proto to use for all outgoing connections */
	{ "proxy-v2-options",    srv_parse_proxy_v2_options,    1,  1,  1 }, /* options for send-proxy-v2 */
	{ "redir",               srv_parse_redir,               1,  1,  0 }, /* Enable redirection mode */
	{ "resolve-net",         srv_parse_resolve_net,         1,  1,  0 }, /* Set the preferred network range for name resolution */
	{ "resolve-opts",        srv_parse_resolve_opts,        1,  1,  0 }, /* Set options for name resolution */
	{ "resolve-prefer",      srv_parse_resolve_prefer,      1,  1,  0 }, /* Set the preferred family for name resolution */
	{ "resolvers",           srv_parse_resolvers,           1,  1,  0 }, /* Configure the resolver to use for name resolution */
	{ "send-proxy",          srv_parse_send_proxy,          0,  1,  1 }, /* Enforce use of PROXY V1 protocol */
	{ "send-proxy-v2",       srv_parse_send_proxy_v2,       0,  1,  1 }, /* Enforce use of PROXY V2 protocol */
	{ "slowstart",           srv_parse_slowstart,           1,  1,  1 }, /* Set the warm-up timer for a previously failed server */
	{ "source",              srv_parse_source,             -1,  1,  1 }, /* Set the source address to be used to connect to the server */
	{ "stick",               srv_parse_stick,               0,  1,  0 }, /* Enable stick-table persistence */
	{ "tfo",                 srv_parse_tfo,                 0,  1,  1 }, /* enable TCP Fast Open of server */
	{ "track",               srv_parse_track,               1,  1,  1 }, /* Set the current state of the server, tracking another one */
	{ "socks4",              srv_parse_socks4,              1,  1,  0 }, /* Set the socks4 proxy of the server*/
	{ "usesrc",              srv_parse_usesrc,              0,  1,  1 }, /* safe-guard against usesrc without preceding <source> keyword */
	{ "weight",              srv_parse_weight,              1,  1,  1 }, /* Set the load-balancing weight */
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, srv_register_keywords, &srv_kws);

/* Recomputes the server's eweight based on its state, uweight, the current time,
 * and the proxy's algorithm. To be used after updating sv->uweight. The warmup
 * state is automatically disabled if the time is elapsed. If <must_update> is
 * not zero, the update will be propagated immediately.
 *
 * Must be called with the server lock held.
 */
void server_recalc_eweight(struct server *sv, int must_update)
{
	struct proxy *px = sv->proxy;
	unsigned w;

	if (now.tv_sec < sv->last_change || now.tv_sec >= sv->last_change + sv->slowstart) {
		/* go to full throttle if the slowstart interval is reached */
		if (sv->next_state == SRV_ST_STARTING)
			sv->next_state = SRV_ST_RUNNING;
	}

	/* We must take care of not pushing the server to full throttle during slow starts.
	 * It must also start immediately, at least at the minimal step when leaving maintenance.
	 */
	if ((sv->next_state == SRV_ST_STARTING) && (px->lbprm.algo & BE_LB_PROP_DYN))
		w = (px->lbprm.wdiv * (now.tv_sec - sv->last_change) + sv->slowstart) / sv->slowstart;
	else
		w = px->lbprm.wdiv;

	sv->next_eweight = (sv->uweight * w + px->lbprm.wmult - 1) / px->lbprm.wmult;

	/* propagate changes only if needed (i.e. not recursively) */
	if (must_update)
		srv_update_status(sv);
}

/*
 * Parses weight_str and configures sv accordingly.
 * Returns NULL on success, error message string otherwise.
 *
 * Must be called with the server lock held.
 */
const char *server_parse_weight_change_request(struct server *sv,
					       const char *weight_str)
{
	struct proxy *px;
	long int w;
	char *end;

	px = sv->proxy;

	/* if the weight is terminated with '%', it is set relative to
	 * the initial weight, otherwise it is absolute.
	 */
	if (!*weight_str)
		return "Require <weight> or <weight%>.\n";

	w = strtol(weight_str, &end, 10);
	if (end == weight_str)
		return "Empty weight string empty or preceded by garbage";
	else if (end[0] == '%' && end[1] == '\0') {
		if (w < 0)
			return "Relative weight must be positive.\n";
		/* Avoid integer overflow */
		if (w > 25600)
			w = 25600;
		w = sv->iweight * w / 100;
		if (w > 256)
			w = 256;
	}
	else if (w < 0 || w > 256)
		return "Absolute weight can only be between 0 and 256 inclusive.\n";
	else if (end[0] != '\0')
		return "Trailing garbage in weight string";

	if (w && w != sv->iweight && !(px->lbprm.algo & BE_LB_PROP_DYN))
		return "Backend is using a static LB algorithm and only accepts weights '0%' and '100%'.\n";

	sv->uweight = w;
	server_recalc_eweight(sv, 1);

	return NULL;
}

/*
 * Parses <addr_str> and configures <sv> accordingly. <from> precise
 * the source of the change in the associated message log.
 * Returns:
 *  - error string on error
 *  - NULL on success
 *
 * Must be called with the server lock held.
 */
const char *server_parse_addr_change_request(struct server *sv,
                                             const char *addr_str, const char *updater)
{
	unsigned char ip[INET6_ADDRSTRLEN];

	if (inet_pton(AF_INET6, addr_str, ip)) {
		srv_update_addr(sv, ip, AF_INET6, updater);
		return NULL;
	}
	if (inet_pton(AF_INET, addr_str, ip)) {
		srv_update_addr(sv, ip, AF_INET, updater);
		return NULL;
	}

	return "Could not understand IP address format.\n";
}

/*
 * Must be called with the server lock held.
 */
const char *server_parse_maxconn_change_request(struct server *sv,
                                                const char *maxconn_str)
{
	long int v;
	char *end;

	if (!*maxconn_str)
		return "Require <maxconn>.\n";

	v = strtol(maxconn_str, &end, 10);
	if (end == maxconn_str)
		return "maxconn string empty or preceded by garbage";
	else if (end[0] != '\0')
		return "Trailing garbage in maxconn string";

	if (sv->maxconn == sv->minconn) { // static maxconn
		sv->maxconn = sv->minconn = v;
	} else { // dynamic maxconn
		sv->maxconn = v;
	}

	if (may_dequeue_tasks(sv, sv->proxy))
		process_srv_queue(sv);

	return NULL;
}

static struct sample_expr *srv_sni_sample_parse_expr(struct server *srv, struct proxy *px,
                                                     const char *file, int linenum, char **err)
{
	int idx;
	const char *args[] = {
		srv->sni_expr,
		NULL,
	};

	idx = 0;
	px->conf.args.ctx = ARGC_SRV;

	return sample_parse_expr((char **)args, &idx, file, linenum, err, &px->conf.args, NULL);
}

static int server_parse_sni_expr(struct server *newsrv, struct proxy *px, char **err)
{
	struct sample_expr *expr;

	expr = srv_sni_sample_parse_expr(newsrv, px, px->conf.file, px->conf.line, err);
	if (!expr) {
		memprintf(err, "error detected while parsing sni expression : %s", *err);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!(expr->fetch->val & SMP_VAL_BE_SRV_CON)) {
		memprintf(err, "error detected while parsing sni expression : "
		          " fetch method '%s' extracts information from '%s', "
		          "none of which is available here.",
		          newsrv->sni_expr, sample_src_names(expr->fetch->use));
		return ERR_ALERT | ERR_FATAL;
	}

	px->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);
	release_sample_expr(newsrv->ssl_ctx.sni);
	newsrv->ssl_ctx.sni = expr;

	return 0;
}

static void display_parser_err(const char *file, int linenum, char **args, int cur_arg, int err_code, char **err)
{
	char *msg = "error encountered while processing ";
	char *quote = "'";
	char *token = args[cur_arg];

	if (err && *err) {
		indent_msg(err, 2);
		msg = *err;
		quote = "";
		token = "";
	}

	if (err_code & ERR_WARN && !(err_code & ERR_ALERT))
		ha_warning("%s%s%s%s.\n", msg, quote, token, quote);
	else
		ha_alert("%s%s%s%s.\n", msg, quote, token, quote);
}

static void srv_conn_src_sport_range_cpy(struct server *srv,
                                            struct server *src)
{
	int range_sz;

	range_sz = src->conn_src.sport_range->size;
	if (range_sz > 0) {
		srv->conn_src.sport_range = port_range_alloc_range(range_sz);
		if (srv->conn_src.sport_range != NULL) {
			int i;

			for (i = 0; i < range_sz; i++) {
				srv->conn_src.sport_range->ports[i] =
					src->conn_src.sport_range->ports[i];
			}
		}
	}
}

/*
 * Copy <src> server connection source settings to <srv> server everything needed.
 */
static void srv_conn_src_cpy(struct server *srv, struct server *src)
{
	srv->conn_src.opts = src->conn_src.opts;
	srv->conn_src.source_addr = src->conn_src.source_addr;

	/* Source port range copy. */
	if (src->conn_src.sport_range != NULL)
		srv_conn_src_sport_range_cpy(srv, src);

#ifdef CONFIG_HAP_TRANSPARENT
	if (src->conn_src.bind_hdr_name != NULL) {
		srv->conn_src.bind_hdr_name = strdup(src->conn_src.bind_hdr_name);
		srv->conn_src.bind_hdr_len = strlen(src->conn_src.bind_hdr_name);
	}
	srv->conn_src.bind_hdr_occ = src->conn_src.bind_hdr_occ;
	srv->conn_src.tproxy_addr  = src->conn_src.tproxy_addr;
#endif
	if (src->conn_src.iface_name != NULL)
		srv->conn_src.iface_name = strdup(src->conn_src.iface_name);
}

/*
 * Copy <src> server SSL settings to <srv> server allocating
 * everything needed.
 */
#if defined(USE_OPENSSL)
static void srv_ssl_settings_cpy(struct server *srv, struct server *src)
{
	/* <src> is the current proxy's default server and SSL is enabled */
	BUG_ON(src->ssl_ctx.ctx != NULL); /* the SSL_CTX must never be initialized in a default-server */

	if (src == &srv->proxy->defsrv && src->use_ssl == 1)
		srv->flags |= SRV_F_DEFSRV_USE_SSL;

	if (src->ssl_ctx.ca_file != NULL)
		srv->ssl_ctx.ca_file = strdup(src->ssl_ctx.ca_file);
	if (src->ssl_ctx.crl_file != NULL)
		srv->ssl_ctx.crl_file = strdup(src->ssl_ctx.crl_file);
	if (src->ssl_ctx.client_crt != NULL)
		srv->ssl_ctx.client_crt = strdup(src->ssl_ctx.client_crt);

	srv->ssl_ctx.verify = src->ssl_ctx.verify;


	if (src->ssl_ctx.verify_host != NULL)
		srv->ssl_ctx.verify_host = strdup(src->ssl_ctx.verify_host);
	if (src->ssl_ctx.ciphers != NULL)
		srv->ssl_ctx.ciphers = strdup(src->ssl_ctx.ciphers);
	if (src->ssl_ctx.options)
		srv->ssl_ctx.options = src->ssl_ctx.options;
	if (src->ssl_ctx.methods.flags)
		srv->ssl_ctx.methods.flags = src->ssl_ctx.methods.flags;
	if (src->ssl_ctx.methods.min)
		srv->ssl_ctx.methods.min = src->ssl_ctx.methods.min;
	if (src->ssl_ctx.methods.max)
		srv->ssl_ctx.methods.max = src->ssl_ctx.methods.max;

	if (src->ssl_ctx.ciphersuites != NULL)
		srv->ssl_ctx.ciphersuites = strdup(src->ssl_ctx.ciphersuites);
	if (src->sni_expr != NULL)
		srv->sni_expr = strdup(src->sni_expr);

	if (src->ssl_ctx.alpn_str) {
		srv->ssl_ctx.alpn_str = malloc(src->ssl_ctx.alpn_len);
		if (srv->ssl_ctx.alpn_str) {
			memcpy(srv->ssl_ctx.alpn_str, src->ssl_ctx.alpn_str,
			    src->ssl_ctx.alpn_len);
			srv->ssl_ctx.alpn_len = src->ssl_ctx.alpn_len;
		}
	}

	if (src->ssl_ctx.npn_str) {
		srv->ssl_ctx.npn_str = malloc(src->ssl_ctx.npn_len);
		if (srv->ssl_ctx.npn_str) {
			memcpy(srv->ssl_ctx.npn_str, src->ssl_ctx.npn_str,
			    src->ssl_ctx.npn_len);
			srv->ssl_ctx.npn_len = src->ssl_ctx.npn_len;
		}
	}
}

/* Activate ssl on server <s>.
 * do nothing if there is no change to apply
 *
 * Must be called with the server lock held.
 */
void srv_set_ssl(struct server *s, int use_ssl)
{
	if (s->use_ssl == use_ssl)
		return;

	s->use_ssl = use_ssl;
	if (s->use_ssl)
		s->xprt = xprt_get(XPRT_SSL);
	else
		s->xprt = xprt_get(XPRT_RAW);
}

#endif /* USE_OPENSSL */

/*
 * Prepare <srv> for hostname resolution.
 * May be safely called with a default server as <src> argument (without hostname).
 * Returns -1 in case of any allocation failure, 0 if not.
 */
int srv_prepare_for_resolution(struct server *srv, const char *hostname)
{
	char *hostname_dn;
	int   hostname_len, hostname_dn_len;

	if (!hostname)
		return 0;

	hostname_len    = strlen(hostname);
	hostname_dn     = trash.area;
	hostname_dn_len = resolv_str_to_dn_label(hostname, hostname_len,
	                                         hostname_dn, trash.size);
	if (hostname_dn_len == -1)
		goto err;


	free(srv->hostname);
	free(srv->hostname_dn);
	srv->hostname        = strdup(hostname);
	srv->hostname_dn     = strdup(hostname_dn);
	srv->hostname_dn_len = hostname_dn_len;
	if (!srv->hostname || !srv->hostname_dn)
		goto err;

	return 0;

 err:
	ha_free(&srv->hostname);
	ha_free(&srv->hostname_dn);
	return -1;
}

/*
 * Copy <src> server settings to <srv> server allocating
 * everything needed.
 * This function is not supposed to be called at any time, but only
 * during server settings parsing or during server allocations from
 * a server template, and just after having calloc()'ed a new server.
 * So, <src> may only be a default server (when parsing server settings)
 * or a server template (during server allocations from a server template).
 * <srv_tmpl> distinguishes these two cases (must be 1 if <srv> is a template,
 * 0 if not).
 */
static void srv_settings_cpy(struct server *srv, struct server *src, int srv_tmpl)
{
	/* Connection source settings copy */
	srv_conn_src_cpy(srv, src);

	if (srv_tmpl) {
		srv->addr = src->addr;
		srv->svc_port = src->svc_port;
	}

	srv->pp_opts = src->pp_opts;
	if (src->rdr_pfx != NULL) {
		srv->rdr_pfx = strdup(src->rdr_pfx);
		srv->rdr_len = src->rdr_len;
	}
	if (src->cookie != NULL) {
		srv->cookie = strdup(src->cookie);
		srv->cklen  = src->cklen;
	}
	srv->use_ssl                  = src->use_ssl;
	srv->check.addr               = src->check.addr;
	srv->agent.addr               = src->agent.addr;
	srv->check.use_ssl            = src->check.use_ssl;
	srv->check.port               = src->check.port;
	srv->check.sni                = src->check.sni;
	srv->check.alpn_str           = src->check.alpn_str;
	srv->check.alpn_len           = src->check.alpn_len;
	/* Note: 'flags' field has potentially been already initialized. */
	srv->flags                   |= src->flags;
	srv->do_check                 = src->do_check;
	srv->do_agent                 = src->do_agent;
	srv->check.inter              = src->check.inter;
	srv->check.fastinter          = src->check.fastinter;
	srv->check.downinter          = src->check.downinter;
	srv->agent.use_ssl            = src->agent.use_ssl;
	srv->agent.port               = src->agent.port;

	if (src->agent.tcpcheck_rules) {
		srv->agent.tcpcheck_rules = calloc(1, sizeof(*srv->agent.tcpcheck_rules));
		if (srv->agent.tcpcheck_rules) {
			srv->agent.tcpcheck_rules->flags = src->agent.tcpcheck_rules->flags;
			srv->agent.tcpcheck_rules->list  = src->agent.tcpcheck_rules->list;
			LIST_INIT(&srv->agent.tcpcheck_rules->preset_vars);
			dup_tcpcheck_vars(&srv->agent.tcpcheck_rules->preset_vars,
					  &src->agent.tcpcheck_rules->preset_vars);
		}
	}

	srv->agent.inter              = src->agent.inter;
	srv->agent.fastinter          = src->agent.fastinter;
	srv->agent.downinter          = src->agent.downinter;
	srv->maxqueue                 = src->maxqueue;
	srv->ws                       = src->ws;
	srv->minconn                  = src->minconn;
	srv->maxconn                  = src->maxconn;
	srv->slowstart                = src->slowstart;
	srv->observe                  = src->observe;
	srv->onerror                  = src->onerror;
	srv->onmarkeddown             = src->onmarkeddown;
	srv->onmarkedup               = src->onmarkedup;
	if (src->trackit != NULL)
		srv->trackit = strdup(src->trackit);
	srv->consecutive_errors_limit = src->consecutive_errors_limit;
	srv->uweight = srv->iweight   = src->iweight;

	srv->check.send_proxy         = src->check.send_proxy;
	/* health: up, but will fall down at first failure */
	srv->check.rise = srv->check.health = src->check.rise;
	srv->check.fall               = src->check.fall;

	/* Here we check if 'disabled' is the default server state */
	if (src->next_admin & (SRV_ADMF_CMAINT | SRV_ADMF_FMAINT)) {
		srv->next_admin |= SRV_ADMF_CMAINT | SRV_ADMF_FMAINT;
		srv->next_state        = SRV_ST_STOPPED;
		srv->check.state |= CHK_ST_PAUSED;
		srv->check.health = 0;
	}

	/* health: up but will fall down at first failure */
	srv->agent.rise	= srv->agent.health = src->agent.rise;
	srv->agent.fall	              = src->agent.fall;

	if (src->resolvers_id != NULL)
		srv->resolvers_id = strdup(src->resolvers_id);
	srv->resolv_opts.family_prio = src->resolv_opts.family_prio;
	srv->resolv_opts.accept_duplicate_ip = src->resolv_opts.accept_duplicate_ip;
	srv->resolv_opts.ignore_weight = src->resolv_opts.ignore_weight;
	if (srv->resolv_opts.family_prio == AF_UNSPEC)
		srv->resolv_opts.family_prio = AF_INET6;
	memcpy(srv->resolv_opts.pref_net,
	       src->resolv_opts.pref_net,
	       sizeof srv->resolv_opts.pref_net);
	srv->resolv_opts.pref_net_nb  = src->resolv_opts.pref_net_nb;

	srv->init_addr_methods        = src->init_addr_methods;
	srv->init_addr                = src->init_addr;
#if defined(USE_OPENSSL)
	srv_ssl_settings_cpy(srv, src);
#endif
#ifdef TCP_USER_TIMEOUT
	srv->tcp_ut = src->tcp_ut;
#endif
	srv->mux_proto = src->mux_proto;
	srv->pool_purge_delay = src->pool_purge_delay;
	srv->low_idle_conns = src->low_idle_conns;
	srv->max_idle_conns = src->max_idle_conns;
	srv->max_reuse = src->max_reuse;

	if (srv_tmpl)
		srv->srvrq = src->srvrq;

	srv->check.via_socks4         = src->check.via_socks4;
	srv->socks4_addr              = src->socks4_addr;
}

/* allocate a server and attach it to the global servers_list. Returns
 * the server on success, otherwise NULL.
 */
struct server *new_server(struct proxy *proxy)
{
	struct server *srv;

	srv = calloc(1, sizeof *srv);
	if (!srv)
		return NULL;

	srv_take(srv);

	srv->obj_type = OBJ_TYPE_SERVER;
	srv->proxy = proxy;
	queue_init(&srv->queue, proxy, srv);
	LIST_APPEND(&servers_list, &srv->global_list);
	LIST_INIT(&srv->srv_rec_item);
	LIST_INIT(&srv->ip_rec_item);

	srv->next_state = SRV_ST_RUNNING; /* early server setup */
	srv->last_change = now.tv_sec;

	srv->check.obj_type = OBJ_TYPE_CHECK;
	srv->check.status = HCHK_STATUS_INI;
	srv->check.server = srv;
	srv->check.proxy = proxy;
	srv->check.tcpcheck_rules = &proxy->tcpcheck_rules;

	srv->agent.obj_type = OBJ_TYPE_CHECK;
	srv->agent.status = HCHK_STATUS_INI;
	srv->agent.server = srv;
	srv->agent.proxy = proxy;
	srv->xprt  = srv->check.xprt = srv->agent.xprt = xprt_get(XPRT_RAW);
#if defined(USE_QUIC)
	srv->cids = EB_ROOT_UNIQUE;
#endif

	srv->extra_counters = NULL;
#ifdef USE_OPENSSL
	HA_RWLOCK_INIT(&srv->ssl_ctx.lock);
#endif

	/* please don't put default server settings here, they are set in
	 * proxy_preset_defaults().
	 */
	return srv;
}

/* Increment the server refcount. */
void srv_take(struct server *srv)
{
	HA_ATOMIC_INC(&srv->refcount);
}

/* Deallocate a server <srv> and its member. <srv> must be allocated. For
 * dynamic servers, its refcount is decremented first. The free operations are
 * conducted only if the refcount is nul, unless the process is stopping.
 *
 * As a convenience, <srv.next> is returned if srv is not NULL. It may be useful
 * when calling srv_drop on the list of servers.
 */
struct server *srv_drop(struct server *srv)
{
	struct server *next = NULL;

	if (!srv)
		goto end;

	next = srv->next;

	/* For dynamic servers, decrement the reference counter. Only free the
	 * server when reaching zero.
	 */
	if (likely(!(global.mode & MODE_STOPPING))) {
		if (HA_ATOMIC_SUB_FETCH(&srv->refcount, 1))
			goto end;
	}

	task_destroy(srv->warmup);
	task_destroy(srv->srvrq_check);

	free(srv->id);
	free(srv->cookie);
	free(srv->hostname);
	free(srv->hostname_dn);
	free((char*)srv->conf.file);
	free(srv->per_thr);
	free(srv->curr_idle_thr);
	free(srv->resolvers_id);
	free(srv->addr_node.key);
	free(srv->lb_nodes);

	if (srv->use_ssl == 1 || srv->check.use_ssl == 1 || (srv->proxy->options & PR_O_TCPCHK_SSL)) {
		if (xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->destroy_srv)
			xprt_get(XPRT_SSL)->destroy_srv(srv);
	}
	HA_SPIN_DESTROY(&srv->lock);

	LIST_DELETE(&srv->global_list);

	EXTRA_COUNTERS_FREE(srv->extra_counters);

	ha_free(&srv);

 end:
	return next;
}

/* Remove a server <srv> from a tracking list if <srv> is tracking another
 * server. No special care is taken if <srv> is tracked itself by another one :
 * this situation should be avoided by the caller.
 *
 * Not thread-safe.
 */
static void release_server_track(struct server *srv)
{
	struct server *strack = srv->track;
	struct server **base;

	if (!strack)
		return;

	for (base = &strack->trackers; *base; base = &((*base)->tracknext)) {
		if (*base == srv) {
			*base = srv->tracknext;
			return;
		}
	}

	/* srv not found on the tracking list, this should never happen */
	BUG_ON(!*base);
}

/*
 * Parse as much as possible such a range string argument: low[-high]
 * Set <nb_low> and <nb_high> values so that they may be reused by this loop
 * for(int i = nb_low; i <= nb_high; i++)... with nb_low >= 1.
 * Fails if 'low' < 0 or 'high' is present and not higher than 'low'.
 * Returns 0 if succeeded, -1 if not.
 */
static int _srv_parse_tmpl_range(struct server *srv, const char *arg,
                                 int *nb_low, int *nb_high)
{
	char *nb_high_arg;

	*nb_high = 0;
	chunk_printf(&trash, "%s", arg);
	*nb_low = atoi(trash.area);

	if ((nb_high_arg = strchr(trash.area, '-'))) {
		*nb_high_arg++ = '\0';
		*nb_high = atoi(nb_high_arg);
	}
	else {
		*nb_high += *nb_low;
		*nb_low = 1;
	}

	if (*nb_low < 0 || *nb_high < *nb_low)
		return -1;

	return 0;
}

/* Parse as much as possible such a range string argument: low[-high]
 * Set <nb_low> and <nb_high> values so that they may be reused by this loop
 * for(int i = nb_low; i <= nb_high; i++)... with nb_low >= 1.
 *
 * This function is first intended to be used through parse_server to
 * initialize a new server on startup.
 *
 * Fails if 'low' < 0 or 'high' is present and not higher than 'low'.
 * Returns 0 if succeeded, -1 if not.
 */
static inline void _srv_parse_set_id_from_prefix(struct server *srv,
                                                 const char *prefix, int nb)
{
	chunk_printf(&trash, "%s%d", prefix, nb);
	free(srv->id);
	srv->id = strdup(trash.area);
}

/* Initialize as much as possible servers from <srv> server template.
 * Note that a server template is a special server with
 * a few different parameters than a server which has
 * been parsed mostly the same way as a server.
 *
 * This function is first intended to be used through parse_server to
 * initialize a new server on startup.
 *
 * Returns the number of servers successfully allocated,
 * 'srv' template included.
 */
static int _srv_parse_tmpl_init(struct server *srv, struct proxy *px)
{
	int i;
	struct server *newsrv;

	for (i = srv->tmpl_info.nb_low + 1; i <= srv->tmpl_info.nb_high; i++) {
		newsrv = new_server(px);
		if (!newsrv)
			goto err;

		newsrv->conf.file = strdup(srv->conf.file);
		newsrv->conf.line = srv->conf.line;

		srv_settings_cpy(newsrv, srv, 1);
		srv_prepare_for_resolution(newsrv, srv->hostname);

		if (newsrv->sni_expr) {
			newsrv->ssl_ctx.sni = srv_sni_sample_parse_expr(newsrv, px, NULL, 0, NULL);
			if (!newsrv->ssl_ctx.sni)
				goto err;
		}

		/* append to list of servers available to receive an hostname */
		if (newsrv->srvrq)
			LIST_APPEND(&newsrv->srvrq->attached_servers, &newsrv->srv_rec_item);

		/* Set this new server ID. */
		_srv_parse_set_id_from_prefix(newsrv, srv->tmpl_info.prefix, i);

		/* Linked backwards first. This will be restablished after parsing. */
		newsrv->next = px->srv;
		px->srv = newsrv;
	}
	_srv_parse_set_id_from_prefix(srv, srv->tmpl_info.prefix, srv->tmpl_info.nb_low);

	return i - srv->tmpl_info.nb_low;

 err:
	_srv_parse_set_id_from_prefix(srv, srv->tmpl_info.prefix, srv->tmpl_info.nb_low);
	if (newsrv)  {
		release_sample_expr(newsrv->ssl_ctx.sni);
		free_check(&newsrv->agent);
		free_check(&newsrv->check);
		LIST_DELETE(&newsrv->global_list);
	}
	free(newsrv);
	return i - srv->tmpl_info.nb_low;
}

/* Allocate a new server pointed by <srv> and try to parse the first arguments
 * in <args> as an address for a server or an address-range for a template or
 * nothing for a default-server. <cur_arg> is incremented to the next argument.
 *
 * This function is first intended to be used through parse_server to
 * initialize a new server on startup.
 *
 * A mask of errors is returned. On a parsing error, ERR_FATAL is set. In case
 * of memory exhaustion, ERR_ABORT is set. If the server cannot be allocated,
 * <srv> will be set to NULL.
 */
static int _srv_parse_init(struct server **srv, char **args, int *cur_arg,
                           struct proxy *curproxy,
                           int parse_flags)
{
	struct server *newsrv = NULL;
	const char *err = NULL;
	int err_code = 0;
	char *fqdn = NULL;
	int tmpl_range_low = 0, tmpl_range_high = 0;
	char *errmsg = NULL;

	*srv = NULL;

	/* There is no mandatory first arguments for default server. */
	if (parse_flags & SRV_PARSE_PARSE_ADDR) {
		if (parse_flags & SRV_PARSE_TEMPLATE) {
			if (!*args[3]) {
				/* 'server-template' line number of argument check. */
				ha_alert("'%s' expects <prefix> <nb | range> <addr>[:<port>] as arguments.\n",
				         args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			err = invalid_prefix_char(args[1]);
		}
		else {
			if (!*args[2]) {
				/* 'server' line number of argument check. */
				ha_alert("'%s' expects <name> and <addr>[:<port>] as arguments.\n",
				         args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			err = invalid_char(args[1]);
		}

		if (err) {
			ha_alert("character '%c' is not permitted in %s %s '%s'.\n",
			         *err, args[0], !(parse_flags & SRV_PARSE_TEMPLATE) ? "name" : "prefix", args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}

	*cur_arg = 2;
	if (parse_flags & SRV_PARSE_TEMPLATE) {
		/* Parse server-template <nb | range> arg. */
		if (_srv_parse_tmpl_range(newsrv, args[*cur_arg], &tmpl_range_low, &tmpl_range_high) < 0) {
			ha_alert("Wrong %s number or range arg '%s'.\n",
			         args[0], args[*cur_arg]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		(*cur_arg)++;
	}

	if (!(parse_flags & SRV_PARSE_DEFAULT_SERVER)) {
		struct sockaddr_storage *sk;
		int port1, port2, port;

		*srv = newsrv = new_server(curproxy);
		if (!newsrv) {
			ha_alert("out of memory.\n");
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		register_parsing_obj(&newsrv->obj_type);

		if (parse_flags & SRV_PARSE_TEMPLATE) {
			newsrv->tmpl_info.nb_low = tmpl_range_low;
			newsrv->tmpl_info.nb_high = tmpl_range_high;
		}

		if (parse_flags & SRV_PARSE_DYNAMIC)
			newsrv->flags |= SRV_F_DYNAMIC;

		/* Note: for a server template, its id is its prefix.
		 * This is a temporary id which will be used for server allocations to come
		 * after parsing.
		 */
		if (!(parse_flags & SRV_PARSE_TEMPLATE))
			newsrv->id = strdup(args[1]);
		else
			newsrv->tmpl_info.prefix = strdup(args[1]);

		/* several ways to check the port component :
		 *  - IP    => port=+0, relative (IPv4 only)
		 *  - IP:   => port=+0, relative
		 *  - IP:N  => port=N, absolute
		 *  - IP:+N => port=+N, relative
		 *  - IP:-N => port=-N, relative
		 */
		if (!(parse_flags & SRV_PARSE_PARSE_ADDR))
			goto skip_addr;

		sk = str2sa_range(args[*cur_arg], &port, &port1, &port2, NULL, NULL,
		                  &errmsg, NULL, &fqdn,
		                  (parse_flags & SRV_PARSE_INITIAL_RESOLVE ? PA_O_RESOLVE : 0) | PA_O_PORT_OK | PA_O_PORT_OFS | PA_O_STREAM | PA_O_XPRT | PA_O_CONNECT);
		if (!sk) {
			ha_alert("%s\n", errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_free(&errmsg);
			goto out;
		}

		if (!port1 || !port2) {
			/* no port specified, +offset, -offset */
			newsrv->flags |= SRV_F_MAPPORTS;
		}

		/* save hostname and create associated name resolution */
		if (fqdn) {
			if (fqdn[0] == '_') { /* SRV record */
				/* Check if a SRV request already exists, and if not, create it */
				if ((newsrv->srvrq = find_srvrq_by_name(fqdn, curproxy)) == NULL)
					newsrv->srvrq = new_resolv_srvrq(newsrv, fqdn);
				if (newsrv->srvrq == NULL) {
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				LIST_APPEND(&newsrv->srvrq->attached_servers, &newsrv->srv_rec_item);
			}
			else if (srv_prepare_for_resolution(newsrv, fqdn) == -1) {
				ha_alert("Can't create DNS resolution for server '%s'\n",
				         newsrv->id);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		newsrv->addr = *sk;
		newsrv->svc_port = port;
		/*
		 * we don't need to lock the server here, because
		 * we are in the process of initializing.
		 *
		 * Note that the server is not attached into the proxy tree if
		 * this is a dynamic server.
		 */
		srv_set_addr_desc(newsrv, !(parse_flags & SRV_PARSE_DYNAMIC));

		if (!newsrv->srvrq && !newsrv->hostname &&
		    !protocol_lookup(newsrv->addr.ss_family, PROTO_TYPE_STREAM, 0)) {
			ha_alert("Unknown protocol family %d '%s'\n",
			         newsrv->addr.ss_family, args[*cur_arg]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		(*cur_arg)++;
 skip_addr:
		if (!(parse_flags & SRV_PARSE_DYNAMIC)) {
			/* Copy default server settings to new server */
			srv_settings_cpy(newsrv, &curproxy->defsrv, 0);
		} else {
			/* Initialize dynamic server weight to 1 */
			newsrv->uweight = newsrv->iweight = 1;

			/* A dynamic server is disabled on startup */
			newsrv->next_admin = SRV_ADMF_FMAINT;
			newsrv->next_state = SRV_ST_STOPPED;
			server_recalc_eweight(newsrv, 0);

			/* Set default values for checks */
			newsrv->check.inter = DEF_CHKINTR;
			newsrv->check.rise = DEF_RISETIME;
			newsrv->check.fall = DEF_FALLTIME;

			newsrv->agent.inter = DEF_CHKINTR;
			newsrv->agent.rise = DEF_AGENT_RISETIME;
			newsrv->agent.fall = DEF_AGENT_FALLTIME;
		}
		HA_SPIN_INIT(&newsrv->lock);
	}
	else {
		*srv = newsrv = &curproxy->defsrv;
		*cur_arg = 1;
		newsrv->resolv_opts.family_prio = AF_INET6;
		newsrv->resolv_opts.accept_duplicate_ip = 0;
	}

	free(fqdn);
	return 0;

out:
	free(fqdn);
	return err_code;
}

/* Parse the server keyword in <args>.
 * <cur_arg> is incremented beyond the keyword optional value. Note that this
 * might not be the case if an error is reported.
 *
 * This function is first intended to be used through parse_server to
 * initialize a new server on startup.
 *
 * A mask of errors is returned. ERR_FATAL is set if the parsing should be
 * interrupted.
 */
static int _srv_parse_kw(struct server *srv, char **args, int *cur_arg,
                         struct proxy *curproxy,
                         int parse_flags)
{
	int err_code = 0;
	struct srv_kw *kw;
	const char *best;
	char *errmsg = NULL;

	kw = srv_find_kw(args[*cur_arg]);
	if (!kw) {
		best = srv_find_best_kw(args[*cur_arg]);
		if (best)
			ha_alert("unknown keyword '%s'; did you mean '%s' maybe ?\n",
			         args[*cur_arg], best);
		else
			ha_alert("unknown keyword '%s'.\n", args[*cur_arg]);

		return ERR_ALERT | ERR_FATAL;
	}

	if (!kw->parse) {
		ha_alert("'%s' option is not implemented in this version (check build options)\n",
		         args[*cur_arg]);
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}

	if ((parse_flags & SRV_PARSE_DEFAULT_SERVER) && !kw->default_ok) {
		ha_alert("'%s' option is not accepted in default-server sections\n",
		         args[*cur_arg]);
		err_code = ERR_ALERT;
		goto out;
	}
	else if ((parse_flags & SRV_PARSE_DYNAMIC) && !kw->dynamic_ok) {
		ha_alert("'%s' option is not accepted for dynamic server\n",
		         args[*cur_arg]);
		err_code |= ERR_ALERT;
		goto out;
	}

	err_code = kw->parse(args, cur_arg, curproxy, srv, &errmsg);
	if (err_code) {
		display_parser_err(NULL, 0, args, *cur_arg, err_code, &errmsg);
		free(errmsg);
	}

out:
	if (kw->skip != -1)
		*cur_arg += 1 + kw->skip;

	return err_code;
}

/* This function is first intended to be used through parse_server to
 * initialize a new server on startup.
 */
static int _srv_parse_sni_expr_init(char **args, int cur_arg,
                                    struct server *srv, struct proxy *proxy,
                                    char **errmsg)
{
	int ret;

	if (!srv->sni_expr)
		return 0;

	ret = server_parse_sni_expr(srv, proxy, errmsg);
	if (!ret)
	    return 0;

	return ret;
}

/* Server initializations finalization.
 * Initialize health check, agent check and SNI expression if enabled.
 * Must not be called for a default server instance.
 *
 * This function is first intended to be used through parse_server to
 * initialize a new server on startup.
 */
static int _srv_parse_finalize(char **args, int cur_arg,
                               struct server *srv, struct proxy *px,
                               int parse_flags)
{
	int ret;
	char *errmsg = NULL;

	if (srv->do_check && srv->trackit) {
		ha_alert("unable to enable checks and tracking at the same time!\n");
		return ERR_ALERT | ERR_FATAL;
	}

	if (srv->do_agent && !srv->agent.port) {
		ha_alert("server %s does not have agent port. Agent check has been disabled.\n",
		         srv->id);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((ret = _srv_parse_sni_expr_init(args, cur_arg, srv, px, &errmsg)) != 0) {
		if (errmsg) {
			ha_alert("%s\n", errmsg);
			free(errmsg);
		}
		return ret;
	}

	/* A dynamic server is disabled on startup. It must not be counted as
	 * an active backend entry.
	 */
	if (!(parse_flags & SRV_PARSE_DYNAMIC)) {
		if (srv->flags & SRV_F_BACKUP)
			px->srv_bck++;
		else
			px->srv_act++;
	}

	srv_lb_commit_status(srv);

	return 0;
}

int parse_server(const char *file, int linenum, char **args,
                 struct proxy *curproxy, const struct proxy *defproxy,
                 int parse_flags)
{
	struct server *newsrv = NULL;
	int err_code = 0;

	int cur_arg;

	set_usermsgs_ctx(file, linenum, NULL);

	if (!(parse_flags & SRV_PARSE_DEFAULT_SERVER) && curproxy == defproxy) {
		ha_alert("'%s' not allowed in 'defaults' section.\n", args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (failifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL)) {
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	if ((parse_flags & (SRV_PARSE_IN_PEER_SECTION|SRV_PARSE_PARSE_ADDR)) ==
	    (SRV_PARSE_IN_PEER_SECTION|SRV_PARSE_PARSE_ADDR)) {
		if (!*args[2])
			return 0;
	}

	err_code = _srv_parse_init(&newsrv, args, &cur_arg, curproxy,
	                           parse_flags);

	/* the servers are linked backwards first */
	if (newsrv && !(parse_flags & SRV_PARSE_DEFAULT_SERVER)) {
		newsrv->next = curproxy->srv;
		curproxy->srv = newsrv;
	}

	if (err_code & ERR_CODE)
		goto out;

	newsrv->conf.file = strdup(file);
	newsrv->conf.line = linenum;

	while (*args[cur_arg]) {
		err_code = _srv_parse_kw(newsrv, args, &cur_arg, curproxy,
		                         parse_flags);
		if (err_code & ERR_FATAL)
			goto out;
	}

	if (!(parse_flags & SRV_PARSE_DEFAULT_SERVER)) {
		err_code |= _srv_parse_finalize(args, cur_arg, newsrv, curproxy, parse_flags);
		if (err_code & ERR_FATAL)
			goto out;
	}

	if (parse_flags & SRV_PARSE_TEMPLATE)
		_srv_parse_tmpl_init(newsrv, curproxy);

	/* If the server id is fixed, insert it in the proxy used_id tree.
	 * This is needed to detect a later duplicate id via srv_parse_id.
	 *
	 * If no is specified, a dynamic one is generated in
	 * check_config_validity.
	 */
	if (newsrv->flags & SRV_F_FORCED_ID)
		eb32_insert(&curproxy->conf.used_server_id, &newsrv->conf.id);

	HA_DIAG_WARNING_COND((curproxy->cap & PR_CAP_LB) && !newsrv->uweight,
	                     "configured with weight of 0 will never be selected by load balancing algorithms\n");

	reset_usermsgs_ctx();
	return 0;

 out:
	reset_usermsgs_ctx();
	return err_code;
}

/* Returns a pointer to the first server matching either id <id>.
 * NULL is returned if no match is found.
 * the lookup is performed in the backend <bk>
 */
struct server *server_find_by_id(struct proxy *bk, int id)
{
	struct eb32_node *eb32;
	struct server *curserver;

	if (!bk || (id ==0))
		return NULL;

	/* <bk> has no backend capabilities, so it can't have a server */
	if (!(bk->cap & PR_CAP_BE))
		return NULL;

	curserver = NULL;

	eb32 = eb32_lookup(&bk->conf.used_server_id, id);
	if (eb32)
		curserver = container_of(eb32, struct server, conf.id);

	return curserver;
}

/* Returns a pointer to the first server matching either name <name>, or id
 * if <name> starts with a '#'. NULL is returned if no match is found.
 * the lookup is performed in the backend <bk>
 */
struct server *server_find_by_name(struct proxy *bk, const char *name)
{
	struct server *curserver;

	if (!bk || !name)
		return NULL;

	/* <bk> has no backend capabilities, so it can't have a server */
	if (!(bk->cap & PR_CAP_BE))
		return NULL;

	curserver = NULL;
	if (*name == '#') {
		curserver = server_find_by_id(bk, atoi(name + 1));
		if (curserver)
			return curserver;
	}
	else {
		curserver = bk->srv;

		while (curserver && (strcmp(curserver->id, name) != 0))
			curserver = curserver->next;

		if (curserver)
			return curserver;
	}

	return NULL;
}

struct server *server_find_best_match(struct proxy *bk, char *name, int id, int *diff)
{
	struct server *byname;
	struct server *byid;

	if (!name && !id)
		return NULL;

	if (diff)
		*diff = 0;

	byname = byid = NULL;

	if (name) {
		byname = server_find_by_name(bk, name);
		if (byname && (!id || byname->puid == id))
			return byname;
	}

	/* remaining possibilities :
	 *  - name not set
	 *  - name set but not found
	 *  - name found but ID doesn't match
	 */
	if (id) {
		byid = server_find_by_id(bk, id);
		if (byid) {
			if (byname) {
				/* use id only if forced by configuration */
				if (byid->flags & SRV_F_FORCED_ID) {
					if (diff)
						*diff |= 2;
					return byid;
				}
				else {
					if (diff)
						*diff |= 1;
					return byname;
				}
			}

			/* remaining possibilities:
			 *   - name not set
			 *   - name set but not found
			 */
			if (name && diff)
				*diff |= 2;
			return byid;
		}

		/* id bot found */
		if (byname) {
			if (diff)
				*diff |= 1;
			return byname;
		}
	}

	return NULL;
}

/*
 * update a server's current IP address.
 * ip is a pointer to the new IP address, whose address family is ip_sin_family.
 * ip is in network format.
 * updater is a string which contains an information about the requester of the update.
 * updater is used if not NULL.
 *
 * A log line and a stderr warning message is generated based on server's backend options.
 *
 * Must be called with the server lock held.
 */
int srv_update_addr(struct server *s, void *ip, int ip_sin_family, const char *updater)
{
	/* save the new IP family & address if necessary */
	switch (ip_sin_family) {
	case AF_INET:
		if (s->addr.ss_family == ip_sin_family &&
		    !memcmp(ip, &((struct sockaddr_in *)&s->addr)->sin_addr.s_addr, 4))
			return 0;
		break;
	case AF_INET6:
		if (s->addr.ss_family == ip_sin_family &&
		    !memcmp(ip, &((struct sockaddr_in6 *)&s->addr)->sin6_addr.s6_addr, 16))
			return 0;
		break;
	};

	/* generates a log line and a warning on stderr */
	if (1) {
		/* book enough space for both IPv4 and IPv6 */
		char oldip[INET6_ADDRSTRLEN];
		char newip[INET6_ADDRSTRLEN];

		memset(oldip, '\0', INET6_ADDRSTRLEN);
		memset(newip, '\0', INET6_ADDRSTRLEN);

		/* copy old IP address in a string */
		switch (s->addr.ss_family) {
		case AF_INET:
			inet_ntop(s->addr.ss_family, &((struct sockaddr_in *)&s->addr)->sin_addr, oldip, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			inet_ntop(s->addr.ss_family, &((struct sockaddr_in6 *)&s->addr)->sin6_addr, oldip, INET6_ADDRSTRLEN);
			break;
		default:
			strcpy(oldip, "(none)");
			break;
		};

		/* copy new IP address in a string */
		switch (ip_sin_family) {
		case AF_INET:
			inet_ntop(ip_sin_family, ip, newip, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			inet_ntop(ip_sin_family, ip, newip, INET6_ADDRSTRLEN);
			break;
		};

		/* save log line into a buffer */
		chunk_printf(&trash, "%s/%s changed its IP from %s to %s by %s",
				s->proxy->id, s->id, oldip, newip, updater);

		/* write the buffer on stderr */
		ha_warning("%s.\n", trash.area);

		/* send a log */
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.area);
	}

	/* save the new IP family */
	s->addr.ss_family = ip_sin_family;
	/* save the new IP address */
	switch (ip_sin_family) {
	case AF_INET:
		memcpy(&((struct sockaddr_in *)&s->addr)->sin_addr.s_addr, ip, 4);
		break;
	case AF_INET6:
		memcpy(((struct sockaddr_in6 *)&s->addr)->sin6_addr.s6_addr, ip, 16);
		break;
	};
	srv_set_dyncookie(s);
	srv_set_addr_desc(s, 1);

	return 0;
}

/* update agent health check address and port
 * addr can be ip4/ip6 or a hostname
 * if one error occurs, don't apply anything
 * must be called with the server lock held.
 */
const char *srv_update_agent_addr_port(struct server *s, const char *addr, const char *port)
{
	struct sockaddr_storage sk;
	struct buffer *msg;
	int new_port;

	msg = get_trash_chunk();
	chunk_reset(msg);

	if (!(s->agent.state & CHK_ST_ENABLED)) {
		chunk_strcat(msg, "agent checks are not enabled on this server");
		goto out;
	}
	if (addr) {
		memset(&sk, 0, sizeof(struct sockaddr_storage));
		if (str2ip(addr, &sk) == NULL) {
			chunk_appendf(msg, "invalid addr '%s'", addr);
			goto out;
		}
	}
	if (port) {
		if (strl2irc(port, strlen(port), &new_port) != 0) {
			chunk_appendf(msg, "provided port is not an integer");
			goto out;
		}
		if (new_port < 0 || new_port > 65535) {
			chunk_appendf(msg, "provided port is invalid");
			goto out;
		}
	}
out:
	if (msg->data)
		return msg->area;
	else {
		if (addr)
			set_srv_agent_addr(s, &sk);
		if (port)
			set_srv_agent_port(s, new_port);
	}
	return NULL;
}

/* update server health check address and port
 * addr must be ip4 or ip6, it won't be resolved
 * if one error occurs, don't apply anything
 * must be called with the server lock held.
 */
const char *srv_update_check_addr_port(struct server *s, const char *addr, const char *port)
{
	struct sockaddr_storage sk;
	struct buffer *msg;
	int new_port;

	msg = get_trash_chunk();
	chunk_reset(msg);

	if (!(s->check.state & CHK_ST_ENABLED)) {
		chunk_strcat(msg, "health checks are not enabled on this server");
		goto out;
	}
	if (addr) {
		memset(&sk, 0, sizeof(struct sockaddr_storage));
		if (str2ip2(addr, &sk, 0) == NULL) {
			chunk_appendf(msg, "invalid addr '%s'", addr);
			goto out;
		}
	}
	if (port) {
		if (strl2irc(port, strlen(port), &new_port) != 0) {
			chunk_appendf(msg, "provided port is not an integer");
			goto out;
		}
		if (new_port < 0 || new_port > 65535) {
			chunk_appendf(msg, "provided port is invalid");
			goto out;
		}
		/* prevent the update of port to 0 if MAPPORTS are in use */
		if ((s->flags & SRV_F_MAPPORTS) && new_port == 0) {
			chunk_appendf(msg, "can't unset 'port' since MAPPORTS is in use");
			goto out;
		}
	}
out:
	if (msg->data)
		return msg->area;
	else {
		if (addr)
			s->check.addr = sk;
		if (port)
			s->check.port = new_port;
	}
	return NULL;
}

/*
 * This function update a server's addr and port only for AF_INET and AF_INET6 families.
 *
 * Caller can pass its name through <updater> to get it integrated in the response message
 * returned by the function.
 *
 * The function first does the following, in that order:
 * - validates the new addr and/or port
 * - checks if an update is required (new IP or port is different than current ones)
 * - checks the update is allowed:
 *   - don't switch from/to a family other than AF_INET4 and AF_INET6
 *   - allow all changes if no CHECKS are configured
 *   - if CHECK is configured:
 *     - if switch to port map (SRV_F_MAPPORTS), ensure health check have their own ports
 * - applies required changes to both ADDR and PORT if both 'required' and 'allowed'
 *   conditions are met
 *
 * Must be called with the server lock held.
 */
const char *srv_update_addr_port(struct server *s, const char *addr, const char *port, char *updater)
{
	struct sockaddr_storage sa;
	int ret, port_change_required;
	char current_addr[INET6_ADDRSTRLEN];
	uint16_t current_port, new_port;
	struct buffer *msg;
	int changed = 0;

	msg = get_trash_chunk();
	chunk_reset(msg);

	if (addr) {
		memset(&sa, 0, sizeof(struct sockaddr_storage));
		if (str2ip2(addr, &sa, 0) == NULL) {
			chunk_printf(msg, "Invalid addr '%s'", addr);
			goto out;
		}

		/* changes are allowed on AF_INET* families only */
		if ((sa.ss_family != AF_INET) && (sa.ss_family != AF_INET6)) {
			chunk_printf(msg, "Update to families other than AF_INET and AF_INET6 supported only through configuration file");
			goto out;
		}

		/* collecting data currently setup */
		memset(current_addr, '\0', sizeof(current_addr));
		ret = addr_to_str(&s->addr, current_addr, sizeof(current_addr));
		/* changes are allowed on AF_INET* families only */
		if ((ret != AF_INET) && (ret != AF_INET6)) {
			chunk_printf(msg, "Update for the current server address family is only supported through configuration file");
			goto out;
		}

		/* applying ADDR changes if required and allowed
		 * ipcmp returns 0 when both ADDR are the same
		 */
		if (ipcmp(&s->addr, &sa) == 0) {
			chunk_appendf(msg, "no need to change the addr");
			goto port;
		}
		ipcpy(&sa, &s->addr);
		changed = 1;

		/* update report for caller */
		chunk_printf(msg, "IP changed from '%s' to '%s'", current_addr, addr);
	}

 port:
	if (port) {
		char sign = '\0';
		char *endptr;

		if (addr)
			chunk_appendf(msg, ", ");

		/* collecting data currently setup */
		current_port = s->svc_port;

		/* check if PORT change is required */
		port_change_required = 0;

		sign = *port;
		errno = 0;
		new_port = strtol(port, &endptr, 10);
		if ((errno != 0) || (port == endptr)) {
			chunk_appendf(msg, "problem converting port '%s' to an int", port);
			goto out;
		}

		/* check if caller triggers a port mapped or offset */
		if (sign == '-' || (sign == '+')) {
			/* check if server currently uses port map */
			if (!(s->flags & SRV_F_MAPPORTS)) {
				/* switch from fixed port to port map mandatorily triggers
				 * a port change */
				port_change_required = 1;
				/* check is configured
				 * we're switching from a fixed port to a SRV_F_MAPPORTS (mapped) port
				 * prevent PORT change if check doesn't have it's dedicated port while switching
				 * to port mapping */
				if (!s->check.port) {
					chunk_appendf(msg, "can't change <port> to port map because it is incompatible with current health check port configuration (use 'port' statement from the 'server' directive.");
					goto out;
				}
			}
			/* we're already using port maps */
			else {
				port_change_required = current_port != new_port;
			}
		}
		/* fixed port */
		else {
			port_change_required = current_port != new_port;
		}

		/* applying PORT changes if required and update response message */
		if (port_change_required) {
			/* apply new port */
			s->svc_port = new_port;
			changed = 1;

			/* prepare message */
			chunk_appendf(msg, "port changed from '");
			if (s->flags & SRV_F_MAPPORTS)
				chunk_appendf(msg, "+");
			chunk_appendf(msg, "%d' to '", current_port);

			if (sign == '-') {
				s->flags |= SRV_F_MAPPORTS;
				chunk_appendf(msg, "%c", sign);
				/* just use for result output */
				new_port = -new_port;
			}
			else if (sign == '+') {
				s->flags |= SRV_F_MAPPORTS;
				chunk_appendf(msg, "%c", sign);
			}
			else {
				s->flags &= ~SRV_F_MAPPORTS;
			}

			chunk_appendf(msg, "%d'", new_port);
		}
		else {
			chunk_appendf(msg, "no need to change the port");
		}
	}

out:
	if (changed) {
		/* force connection cleanup on the given server */
		srv_cleanup_connections(s);
		srv_set_dyncookie(s);
		srv_set_addr_desc(s, 1);
	}
	if (updater)
		chunk_appendf(msg, " by '%s'", updater);
	chunk_appendf(msg, "\n");
	return msg->area;
}

/*
 * update server status based on result of SRV resolution
 * returns:
 *  0 if server status is updated
 *  1 if server status has not changed
 *
 * Must be called with the server lock held.
 */
int srvrq_update_srv_status(struct server *s, int has_no_ip)
{
	if (!s->srvrq)
		return 1;

	/* since this server has an IP, it can go back in production */
	if (has_no_ip == 0) {
		srv_clr_admin_flag(s, SRV_ADMF_RMAINT);
		return 1;
	}

	if (s->next_admin & SRV_ADMF_RMAINT)
		return 1;

	srv_set_admin_flag(s, SRV_ADMF_RMAINT, "entry removed from SRV record");
	return 0;
}

/*
 * update server status based on result of name resolution
 * returns:
 *  0 if server status is updated
 *  1 if server status has not changed
 *
 * Must be called with the server lock held.
 */
int snr_update_srv_status(struct server *s, int has_no_ip)
{
	struct resolvers  *resolvers  = s->resolvers;
	struct resolv_resolution *resolution = (s->resolv_requester ? s->resolv_requester->resolution : NULL);
	int exp;

	/* If resolution is NULL we're dealing with SRV records Additional records */
	if (resolution == NULL)
		return srvrq_update_srv_status(s, has_no_ip);

	switch (resolution->status) {
		case RSLV_STATUS_NONE:
			/* status when HAProxy has just (re)started.
			 * Nothing to do, since the task is already automatically started */
			break;

		case RSLV_STATUS_VALID:
			/*
			 * resume health checks
			 * server will be turned back on if health check is safe
			 */
			if (has_no_ip) {
				if (s->next_admin & SRV_ADMF_RMAINT)
					return 1;
				srv_set_admin_flag(s, SRV_ADMF_RMAINT,
				    "No IP for server ");
				return 0;
			}

			if (!(s->next_admin & SRV_ADMF_RMAINT))
				return 1;
			srv_clr_admin_flag(s, SRV_ADMF_RMAINT);
			chunk_printf(&trash, "Server %s/%s administratively READY thanks to valid DNS answer",
			             s->proxy->id, s->id);

			ha_warning("%s.\n", trash.area);
			send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.area);
			return 0;

		case RSLV_STATUS_NX:
			/* stop server if resolution is NX for a long enough period */
			exp = tick_add(resolution->last_valid, resolvers->hold.nx);
			if (!tick_is_expired(exp, now_ms))
				break;

			if (s->next_admin & SRV_ADMF_RMAINT)
				return 1;
			srv_set_admin_flag(s, SRV_ADMF_RMAINT, "DNS NX status");
			return 0;

		case RSLV_STATUS_TIMEOUT:
			/* stop server if resolution is TIMEOUT for a long enough period */
			exp = tick_add(resolution->last_valid, resolvers->hold.timeout);
			if (!tick_is_expired(exp, now_ms))
				break;

			if (s->next_admin & SRV_ADMF_RMAINT)
				return 1;
			srv_set_admin_flag(s, SRV_ADMF_RMAINT, "DNS timeout status");
			return 0;

		case RSLV_STATUS_REFUSED:
			/* stop server if resolution is REFUSED for a long enough period */
			exp = tick_add(resolution->last_valid, resolvers->hold.refused);
			if (!tick_is_expired(exp, now_ms))
				break;

			if (s->next_admin & SRV_ADMF_RMAINT)
				return 1;
			srv_set_admin_flag(s, SRV_ADMF_RMAINT, "DNS refused status");
			return 0;

		default:
			/* stop server if resolution failed for a long enough period */
			exp = tick_add(resolution->last_valid, resolvers->hold.other);
			if (!tick_is_expired(exp, now_ms))
				break;

			if (s->next_admin & SRV_ADMF_RMAINT)
				return 1;
			srv_set_admin_flag(s, SRV_ADMF_RMAINT, "unspecified DNS error");
			return 0;
	}

	return 1;
}

/*
 * Server Name Resolution valid response callback
 * It expects:
 *  - <nameserver>: the name server which answered the valid response
 *  - <response>: buffer containing a valid DNS response
 *  - <response_len>: size of <response>
 * It performs the following actions:
 *  - ignore response if current ip found and server family not met
 *  - update with first new ip found if family is met and current IP is not found
 * returns:
 *  0 on error
 *  1 when no error or safe ignore
 *
 * Must be called with server lock held
 */
int snr_resolution_cb(struct resolv_requester *requester, struct dns_counters *counters)
{
	struct server *s = NULL;
	struct resolv_resolution *resolution = NULL;
	void *serverip, *firstip;
	short server_sin_family, firstip_sin_family;
	int ret;
	struct buffer *chk = get_trash_chunk();
	int has_no_ip = 0;

	s = objt_server(requester->owner);
	if (!s)
		return 1;

	if (s->srvrq) {
		/* If DNS resolution is disabled ignore it.
		 * This is the case if the server was associated to
		 * a SRV record and this record is now expired.
		 */
		if (s->flags & SRV_F_NO_RESOLUTION)
			return 1;
	}

	resolution = (s->resolv_requester ? s->resolv_requester->resolution : NULL);
	if (!resolution)
		return 1;

	/* initializing variables */
	firstip = NULL;		/* pointer to the first valid response found */
				/* it will be used as the new IP if a change is required */
	firstip_sin_family = AF_UNSPEC;
	serverip = NULL;	/* current server IP address */

	/* initializing server IP pointer */
	server_sin_family = s->addr.ss_family;
	switch (server_sin_family) {
		case AF_INET:
			serverip = &((struct sockaddr_in *)&s->addr)->sin_addr.s_addr;
			break;

		case AF_INET6:
			serverip = &((struct sockaddr_in6 *)&s->addr)->sin6_addr.s6_addr;
			break;

		case AF_UNSPEC:
			break;

		default:
			goto invalid;
	}

	ret = resolv_get_ip_from_response(&resolution->response, &s->resolv_opts,
	                                  serverip, server_sin_family, &firstip,
	                                  &firstip_sin_family, s);

	switch (ret) {
		case RSLV_UPD_NO:
			goto update_status;

		case RSLV_UPD_SRVIP_NOT_FOUND:
			goto save_ip;

		case RSLV_UPD_NO_IP_FOUND:
			has_no_ip = 1;
			goto update_status;

		case RSLV_UPD_NAME_ERROR:
			/* update resolution status to OTHER error type */
			resolution->status = RSLV_STATUS_OTHER;
			has_no_ip = 1;
			goto update_status;

		default:
			has_no_ip = 1;
			goto invalid;

	}

 save_ip:
	if (counters) {
		counters->app.resolver.update++;
		/* save the first ip we found */
		chunk_printf(chk, "%s/%s", counters->pid, counters->id);
	}
	else
		chunk_printf(chk, "DNS cache");
	srv_update_addr(s, firstip, firstip_sin_family, (char *) chk->area);

 update_status:
	if (!snr_update_srv_status(s, has_no_ip) && has_no_ip)
		memset(&s->addr, 0, sizeof(s->addr));
	return 1;

 invalid:
	if (counters) {
		counters->app.resolver.invalid++;
		goto update_status;
	}
	if (!snr_update_srv_status(s, has_no_ip) && has_no_ip)
		memset(&s->addr, 0, sizeof(s->addr));
	return 0;
}

/*
 * SRV record error management callback
 * returns:
 *  0 if we can trash answser items.
 *  1 when safely ignored and we must kept answer items
 *
 * Grabs the server's lock.
 */
int srvrq_resolution_error_cb(struct resolv_requester *requester, int error_code)
{
	struct resolv_srvrq *srvrq;
	struct resolv_resolution *res;
	struct resolvers *resolvers;
	int exp;

	/* SRV records */
	srvrq = objt_resolv_srvrq(requester->owner);
	if (!srvrq)
		return 0;

	resolvers = srvrq->resolvers;
	res = requester->resolution;

	switch (res->status) {

		case RSLV_STATUS_NX:
			/* stop server if resolution is NX for a long enough period */
			exp = tick_add(res->last_valid, resolvers->hold.nx);
			if (!tick_is_expired(exp, now_ms))
				return 1;
			break;

		case RSLV_STATUS_TIMEOUT:
			/* stop server if resolution is TIMEOUT for a long enough period */
			exp = tick_add(res->last_valid, resolvers->hold.timeout);
			if (!tick_is_expired(exp, now_ms))
				return 1;
			break;

		case RSLV_STATUS_REFUSED:
			/* stop server if resolution is REFUSED for a long enough period */
			exp = tick_add(res->last_valid, resolvers->hold.refused);
			if (!tick_is_expired(exp, now_ms))
				return 1;
			break;

		default:
			/* stop server if resolution failed for a long enough period */
			exp = tick_add(res->last_valid, resolvers->hold.other);
			if (!tick_is_expired(exp, now_ms))
				return 1;
	}

	/* Remove any associated server ref */
	resolv_detach_from_resolution_answer_items(res,  requester);

	return 0;
}

/*
 * Server Name Resolution error management callback
 * returns:
 *  0 if we can trash answser items.
 *  1 when safely ignored and we must kept answer items
 *
 * Grabs the server's lock.
 */
int snr_resolution_error_cb(struct resolv_requester *requester, int error_code)
{
	struct server *s;

	s = objt_server(requester->owner);
	if (!s)
		return 0;

	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
	if (!snr_update_srv_status(s, 1)) {
		memset(&s->addr, 0, sizeof(s->addr));
		HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
		resolv_detach_from_resolution_answer_items(requester->resolution, requester);
		return 0;
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);

	return 1;
}

/*
 * Function to check if <ip> is already affected to a server in the backend
 * which owns <srv> and is up.
 * It returns a pointer to the first server found or NULL if <ip> is not yet
 * assigned.
 *
 * Must be called with server lock held
 */
struct server *snr_check_ip_callback(struct server *srv, void *ip, unsigned char *ip_family)
{
	struct server *tmpsrv;
	struct proxy *be;

	if (!srv)
		return NULL;

	be = srv->proxy;
	for (tmpsrv = be->srv; tmpsrv; tmpsrv = tmpsrv->next) {
		/* we found the current server is the same, ignore it */
		if (srv == tmpsrv)
			continue;

		/* We want to compare the IP in the record with the IP of the servers in the
		 * same backend, only if:
		 *   * DNS resolution is enabled on the server
		 *   * the hostname used for the resolution by our server is the same than the
		 *     one used for the server found in the backend
		 *   * the server found in the backend is not our current server
		 */
		HA_SPIN_LOCK(SERVER_LOCK, &tmpsrv->lock);
		if ((tmpsrv->hostname_dn == NULL) ||
		    (srv->hostname_dn_len != tmpsrv->hostname_dn_len) ||
		    (strcasecmp(srv->hostname_dn, tmpsrv->hostname_dn) != 0) ||
		    (srv->puid == tmpsrv->puid)) {
			HA_SPIN_UNLOCK(SERVER_LOCK, &tmpsrv->lock);
			continue;
		}

		/* If the server has been taken down, don't consider it */
		if (tmpsrv->next_admin & SRV_ADMF_RMAINT) {
			HA_SPIN_UNLOCK(SERVER_LOCK, &tmpsrv->lock);
			continue;
		}

		/* At this point, we have 2 different servers using the same DNS hostname
		 * for their respective resolution.
		 */
		if (*ip_family == tmpsrv->addr.ss_family &&
		    ((tmpsrv->addr.ss_family == AF_INET &&
		      memcmp(ip, &((struct sockaddr_in *)&tmpsrv->addr)->sin_addr, 4) == 0) ||
		     (tmpsrv->addr.ss_family == AF_INET6 &&
		      memcmp(ip, &((struct sockaddr_in6 *)&tmpsrv->addr)->sin6_addr, 16) == 0))) {
			HA_SPIN_UNLOCK(SERVER_LOCK, &tmpsrv->lock);
			return tmpsrv;
		}
		HA_SPIN_UNLOCK(SERVER_LOCK, &tmpsrv->lock);
	}


	return NULL;
}

/* Sets the server's address (srv->addr) from srv->hostname using the libc's
 * resolver. This is suited for initial address configuration. Returns 0 on
 * success otherwise a non-zero error code. In case of error, *err_code, if
 * not NULL, is filled up.
 */
int srv_set_addr_via_libc(struct server *srv, int *err_code)
{
	if (str2ip2(srv->hostname, &srv->addr, 1) == NULL) {
		if (err_code)
			*err_code |= ERR_WARN;
		return 1;
	}
	return 0;
}

/* Set the server's FDQN (->hostname) from <hostname>.
 * Returns -1 if failed, 0 if not.
 *
 * Must be called with the server lock held.
 */
int srv_set_fqdn(struct server *srv, const char *hostname, int resolv_locked)
{
	struct resolv_resolution *resolution;
	char                  *hostname_dn;
	int                    hostname_len, hostname_dn_len;

	/* Note that the server lock is already held. */
	if (!srv->resolvers)
		return -1;

	if (!resolv_locked)
		HA_SPIN_LOCK(DNS_LOCK, &srv->resolvers->lock);
	/* run time DNS/SRV resolution was not active for this server
	 * and we can't enable it at run time for now.
	 */
	if (!srv->resolv_requester && !srv->srvrq)
		goto err;

	chunk_reset(&trash);
	hostname_len    = strlen(hostname);
	hostname_dn     = trash.area;
	hostname_dn_len = resolv_str_to_dn_label(hostname, hostname_len,
	                                         hostname_dn, trash.size);
	if (hostname_dn_len == -1)
		goto err;

	resolution = (srv->resolv_requester ? srv->resolv_requester->resolution : NULL);
	if (resolution &&
	    resolution->hostname_dn &&
	    resolution->hostname_dn_len == hostname_dn_len &&
	    strcasecmp(resolution->hostname_dn, hostname_dn) == 0)
		goto end;

	resolv_unlink_resolution(srv->resolv_requester);

	free(srv->hostname);
	free(srv->hostname_dn);
	srv->hostname        = strdup(hostname);
	srv->hostname_dn     = strdup(hostname_dn);
	srv->hostname_dn_len = hostname_dn_len;
	if (!srv->hostname || !srv->hostname_dn)
		goto err;

	if (srv->flags & SRV_F_NO_RESOLUTION)
		goto end;

	if (resolv_link_resolution(srv, OBJ_TYPE_SERVER, 1) == -1)
		goto err;

  end:
	if (!resolv_locked)
		HA_SPIN_UNLOCK(DNS_LOCK, &srv->resolvers->lock);
	return 0;

  err:
	if (!resolv_locked)
		HA_SPIN_UNLOCK(DNS_LOCK, &srv->resolvers->lock);
	return -1;
}

/* Sets the server's address (srv->addr) from srv->lastaddr which was filled
 * from the state file. This is suited for initial address configuration.
 * Returns 0 on success otherwise a non-zero error code. In case of error,
 * *err_code, if not NULL, is filled up.
 */
static int srv_apply_lastaddr(struct server *srv, int *err_code)
{
	if (!str2ip2(srv->lastaddr, &srv->addr, 0)) {
		if (err_code)
			*err_code |= ERR_WARN;
		return 1;
	}
	return 0;
}

/* returns 0 if no error, otherwise a combination of ERR_* flags */
static int srv_iterate_initaddr(struct server *srv)
{
	char *name = srv->hostname;
	int return_code = 0;
	int err_code;
	unsigned int methods;

	/* If no addr and no hostname set, get the name from the DNS SRV request */
	if (!name && srv->srvrq)
		name = srv->srvrq->name;

	methods = srv->init_addr_methods;
	if (!methods) {
		/* otherwise default to "last,libc" */
		srv_append_initaddr(&methods, SRV_IADDR_LAST);
		srv_append_initaddr(&methods, SRV_IADDR_LIBC);
		if (srv->resolvers_id) {
			/* dns resolution is configured, add "none" to not fail on startup */
			srv_append_initaddr(&methods, SRV_IADDR_NONE);
		}
	}

	/* "-dr" : always append "none" so that server addresses resolution
	 * failures are silently ignored, this is convenient to validate some
	 * configs out of their environment.
	 */
	if (global.tune.options & GTUNE_RESOLVE_DONTFAIL)
		srv_append_initaddr(&methods, SRV_IADDR_NONE);

	while (methods) {
		err_code = 0;
		switch (srv_get_next_initaddr(&methods)) {
		case SRV_IADDR_LAST:
			if (!srv->lastaddr)
				continue;
			if (srv_apply_lastaddr(srv, &err_code) == 0)
				goto out;
			return_code |= err_code;
			break;

		case SRV_IADDR_LIBC:
			if (!srv->hostname)
				continue;
			if (srv_set_addr_via_libc(srv, &err_code) == 0)
				goto out;
			return_code |= err_code;
			break;

		case SRV_IADDR_NONE:
			srv_set_admin_flag(srv, SRV_ADMF_RMAINT, NULL);
			if (return_code) {
				ha_warning("could not resolve address '%s', disabling server.\n",
					   name);
			}
			return return_code;

		case SRV_IADDR_IP:
			ipcpy(&srv->init_addr, &srv->addr);
			if (return_code) {
				ha_warning("could not resolve address '%s', falling back to configured address.\n",
					   name);
			}
			goto out;

		default: /* unhandled method */
			break;
		}
	}

	if (!return_code)
		ha_alert("no method found to resolve address '%s'.\n", name);
	else
		ha_alert("could not resolve address '%s'.\n", name);

	return_code |= ERR_ALERT | ERR_FATAL;
	return return_code;
out:
	srv_set_dyncookie(srv);
	srv_set_addr_desc(srv, 1);
	return return_code;
}

/*
 * This function parses all backends and all servers within each backend
 * and performs servers' addr resolution based on information provided by:
 *   - configuration file
 *   - server-state file (states provided by an 'old' haproxy process)
 *
 * Returns 0 if no error, otherwise, a combination of ERR_ flags.
 */
int srv_init_addr(void)
{
	struct proxy *curproxy;
	int return_code = 0;

	curproxy = proxies_list;
	while (curproxy) {
		struct server *srv;

		/* servers are in backend only */
		if (!(curproxy->cap & PR_CAP_BE) || (curproxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)))
			goto srv_init_addr_next;

		for (srv = curproxy->srv; srv; srv = srv->next) {
			set_usermsgs_ctx(srv->conf.file, srv->conf.line, &srv->obj_type);
			if (srv->hostname || srv->srvrq)
				return_code |= srv_iterate_initaddr(srv);
			reset_usermsgs_ctx();
		}

 srv_init_addr_next:
		curproxy = curproxy->next;
	}

	return return_code;
}

/*
 * Must be called with the server lock held.
 */
const char *srv_update_fqdn(struct server *server, const char *fqdn, const char *updater, int resolv_locked)
{

	struct buffer *msg;

	msg = get_trash_chunk();
	chunk_reset(msg);

	if (server->hostname && strcmp(fqdn, server->hostname) == 0) {
		chunk_appendf(msg, "no need to change the FDQN");
		goto out;
	}

	if (strlen(fqdn) > DNS_MAX_NAME_SIZE || invalid_domainchar(fqdn)) {
		chunk_appendf(msg, "invalid fqdn '%s'", fqdn);
		goto out;
	}

	chunk_appendf(msg, "%s/%s changed its FQDN from %s to %s",
	              server->proxy->id, server->id, server->hostname, fqdn);

	if (srv_set_fqdn(server, fqdn, resolv_locked) < 0) {
		chunk_reset(msg);
		chunk_appendf(msg, "could not update %s/%s FQDN",
		              server->proxy->id, server->id);
		goto out;
	}

	/* Flag as FQDN set from stats socket. */
	server->next_admin |= SRV_ADMF_HMAINT;

 out:
	if (updater)
		chunk_appendf(msg, " by '%s'", updater);
	chunk_appendf(msg, "\n");

	return msg->area;
}


/* Expects to find a backend and a server in <arg> under the form <backend>/<server>,
 * and returns the pointer to the server. Otherwise, display adequate error messages
 * on the CLI, sets the CLI's state to CLI_ST_PRINT and returns NULL. This is only
 * used for CLI commands requiring a server name.
 * Important: the <arg> is modified to remove the '/'.
 */
struct server *cli_find_server(struct appctx *appctx, char *arg)
{
	struct proxy *px;
	struct server *sv;
	char *line;

	/* split "backend/server" and make <line> point to server */
	for (line = arg; *line; line++)
		if (*line == '/') {
			*line++ = '\0';
			break;
		}

	if (!*line || !*arg) {
		cli_err(appctx, "Require 'backend/server'.\n");
		return NULL;
	}

	if (!get_backend_server(arg, line, &px, &sv)) {
		cli_err(appctx, px ? "No such server.\n" : "No such backend.\n");
		return NULL;
	}

	if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) {
		cli_err(appctx, "Proxy is disabled.\n");
		return NULL;
	}

	return sv;
}


/* grabs the server lock */
static int cli_parse_set_server(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;
	const char *warning;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	if (strcmp(args[3], "weight") == 0) {
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		warning = server_parse_weight_change_request(sv, args[4]);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
		if (warning)
			cli_err(appctx, warning);
	}
	else if (strcmp(args[3], "state") == 0) {
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		if (strcmp(args[4], "ready") == 0)
			srv_adm_set_ready(sv);
		else if (strcmp(args[4], "drain") == 0)
			srv_adm_set_drain(sv);
		else if (strcmp(args[4], "maint") == 0)
			srv_adm_set_maint(sv);
		else
			cli_err(appctx, "'set server <srv> state' expects 'ready', 'drain' and 'maint'.\n");
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	}
	else if (strcmp(args[3], "health") == 0) {
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		if (sv->track)
			cli_err(appctx, "cannot change health on a tracking server.\n");
		else if (strcmp(args[4], "up") == 0) {
			sv->check.health = sv->check.rise + sv->check.fall - 1;
			srv_set_running(sv, "changed from CLI", NULL);
		}
		else if (strcmp(args[4], "stopping") == 0) {
			sv->check.health = sv->check.rise + sv->check.fall - 1;
			srv_set_stopping(sv, "changed from CLI", NULL);
		}
		else if (strcmp(args[4], "down") == 0) {
			sv->check.health = 0;
			srv_set_stopped(sv, "changed from CLI", NULL);
		}
		else
			cli_err(appctx, "'set server <srv> health' expects 'up', 'stopping', or 'down'.\n");
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	}
	else if (strcmp(args[3], "agent") == 0) {
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		if (!(sv->agent.state & CHK_ST_ENABLED))
			cli_err(appctx, "agent checks are not enabled on this server.\n");
		else if (strcmp(args[4], "up") == 0) {
			sv->agent.health = sv->agent.rise + sv->agent.fall - 1;
			srv_set_running(sv, "changed from CLI", NULL);
		}
		else if (strcmp(args[4], "down") == 0) {
			sv->agent.health = 0;
			srv_set_stopped(sv, "changed from CLI", NULL);
		}
		else
			cli_err(appctx, "'set server <srv> agent' expects 'up' or 'down'.\n");
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	}
	else if (strcmp(args[3], "agent-addr") == 0) {
		char *addr = NULL;
		char *port = NULL;
		if (strlen(args[4]) == 0) {
			cli_err(appctx, "set server <b>/<s> agent-addr requires"
					" an address and optionally a port.\n");
			goto out;
		}
		addr = args[4];
		if (strcmp(args[5], "port") == 0)
			port = args[6];
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		warning = srv_update_agent_addr_port(sv, addr, port);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
		if (warning)
			cli_msg(appctx, LOG_WARNING, warning);
	}
	else if (strcmp(args[3], "agent-port") == 0) {
		char *port = NULL;
		if (strlen(args[4]) == 0) {
			cli_err(appctx, "set server <b>/<s> agent-port requires"
					" a port.\n");
			goto out;
		}
		port = args[4];
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		warning = srv_update_agent_addr_port(sv, NULL, port);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
		if (warning)
			cli_msg(appctx, LOG_WARNING, warning);
	}
	else if (strcmp(args[3], "agent-send") == 0) {
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		if (!(sv->agent.state & CHK_ST_ENABLED))
			cli_err(appctx, "agent checks are not enabled on this server.\n");
		else {
			if (!set_srv_agent_send(sv, args[4]))
				cli_err(appctx, "cannot allocate memory for new string.\n");
		}
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	}
	else if (strcmp(args[3], "check-addr") == 0) {
		char *addr = NULL;
		char *port = NULL;
		if (strlen(args[4]) == 0) {
			cli_err(appctx, "set server <b>/<s> check-addr requires"
					" an address and optionally a port.\n");
			goto out;
		}
		addr = args[4];
		if (strcmp(args[5], "port") == 0)
			port = args[6];
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		warning = srv_update_check_addr_port(sv, addr, port);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
		if (warning)
			cli_msg(appctx, LOG_WARNING, warning);
	}
	else if (strcmp(args[3], "check-port") == 0) {
		char *port = NULL;
		if (strlen(args[4]) == 0) {
			cli_err(appctx, "set server <b>/<s> check-port requires"
					" a port.\n");
			goto out;
		}
		port = args[4];
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		warning = srv_update_check_addr_port(sv, NULL, port);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
		if (warning)
			cli_msg(appctx, LOG_WARNING, warning);
	}
	else if (strcmp(args[3], "addr") == 0) {
		char *addr = NULL;
		char *port = NULL;
		if (strlen(args[4]) == 0) {
			cli_err(appctx, "set server <b>/<s> addr requires an address and optionally a port.\n");
			goto out;
		}
		else {
			addr = args[4];
		}
		if (strcmp(args[5], "port") == 0) {
			port = args[6];
		}
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		warning = srv_update_addr_port(sv, addr, port, "stats socket command");
		if (warning)
			cli_msg(appctx, LOG_WARNING, warning);
		srv_clr_admin_flag(sv, SRV_ADMF_RMAINT);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	}
	else if (strcmp(args[3], "fqdn") == 0) {
		if (!*args[4]) {
			cli_err(appctx, "set server <b>/<s> fqdn requires a FQDN.\n");
			goto out;
		}
		if (!sv->resolvers) {
			cli_err(appctx, "set server <b>/<s> fqdn failed because no resolution is configured.\n");
			goto out;
		}
		if (sv->srvrq) {
			cli_err(appctx, "set server <b>/<s> fqdn failed because SRV resolution is configured.\n");
			goto out;
		}
		HA_SPIN_LOCK(DNS_LOCK, &sv->resolvers->lock);
		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		/* ensure runtime resolver will process this new fqdn */
		if (sv->flags & SRV_F_NO_RESOLUTION) {
			sv->flags &= ~SRV_F_NO_RESOLUTION;
		}
		warning = srv_update_fqdn(sv, args[4], "stats socket command", 1);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
		HA_SPIN_UNLOCK(DNS_LOCK, &sv->resolvers->lock);
		if (warning)
			cli_msg(appctx, LOG_WARNING, warning);
	}
	else if (strcmp(args[3], "ssl") == 0) {
#ifdef USE_OPENSSL
		if (sv->flags & SRV_F_DYNAMIC) {
			cli_err(appctx, "'set server <srv> ssl' not supported on dynamic servers\n");
			goto out;
		}

		if (sv->ssl_ctx.ctx == NULL) {
			cli_err(appctx, "'set server <srv> ssl' cannot be set. "
					" default-server should define ssl settings\n");
			goto out;
		}

		HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
		if (strcmp(args[4], "on") == 0) {
			srv_set_ssl(sv, 1);
		} else if (strcmp(args[4], "off") == 0) {
			srv_set_ssl(sv, 0);
		} else {
			HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
			cli_err(appctx, "'set server <srv> ssl' expects 'on' or 'off'.\n");
			goto out;
		}
		srv_cleanup_connections(sv);
		HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
		cli_msg(appctx, LOG_NOTICE, "server ssl setting updated.\n");
#else
		cli_msg(appctx, LOG_NOTICE, "server ssl setting not supported.\n");
#endif
	} else {
		cli_err(appctx,
			"usage: set server <backend>/<server> "
			"addr | agent | agent-addr | agent-port | agent-send | "
			"check-addr | check-port | fqdn | health | ssl | "
			"state | weight\n");
	}
 out:
	return 1;
}

static int cli_parse_get_weight(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct stream_interface *si = appctx->owner;
	struct proxy *px;
	struct server *sv;
	char *line;


	/* split "backend/server" and make <line> point to server */
	for (line = args[2]; *line; line++)
		if (*line == '/') {
			*line++ = '\0';
			break;
		}

	if (!*line)
		return cli_err(appctx, "Require 'backend/server'.\n");

	if (!get_backend_server(args[2], line, &px, &sv))
		return cli_err(appctx, px ? "No such server.\n" : "No such backend.\n");

	/* return server's effective weight at the moment */
	snprintf(trash.area, trash.size, "%d (initial %d)\n", sv->uweight,
		 sv->iweight);
	if (ci_putstr(si_ic(si), trash.area) == -1) {
		si_rx_room_blk(si);
		return 0;
	}
	return 1;
}

/* Parse a "set weight" command.
 *
 * Grabs the server lock.
 */
static int cli_parse_set_weight(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;
	const char *warning;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);

	warning = server_parse_weight_change_request(sv, args[3]);
	if (warning)
		cli_err(appctx, warning);

	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);

	return 1;
}

/* parse a "set maxconn server" command. It always returns 1.
 *
 * Grabs the server lock.
 */
static int cli_parse_set_maxconn_server(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;
	const char *warning;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[3]);
	if (!sv)
		return 1;

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);

	warning = server_parse_maxconn_change_request(sv, args[4]);
	if (warning)
		cli_err(appctx, warning);

	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);

	return 1;
}

/* parse a "disable agent" command. It always returns 1.
 *
 * Grabs the server lock.
 */
static int cli_parse_disable_agent(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	sv->agent.state &= ~CHK_ST_ENABLED;
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* parse a "disable health" command. It always returns 1.
 *
 * Grabs the server lock.
 */
static int cli_parse_disable_health(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	sv->check.state &= ~CHK_ST_ENABLED;
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* parse a "disable server" command. It always returns 1.
 *
 * Grabs the server lock.
 */
static int cli_parse_disable_server(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	srv_adm_set_maint(sv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* parse a "enable agent" command. It always returns 1.
 *
 * Grabs the server lock.
 */
static int cli_parse_enable_agent(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	if (!(sv->agent.state & CHK_ST_CONFIGURED))
		return cli_err(appctx, "Agent was not configured on this server, cannot enable.\n");

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	sv->agent.state |= CHK_ST_ENABLED;
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* parse a "enable health" command. It always returns 1.
 *
 * Grabs the server lock.
 */
static int cli_parse_enable_health(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	if (!(sv->check.state & CHK_ST_CONFIGURED))
		return cli_err(appctx, "Health check was not configured on this server, cannot enable.\n");

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	sv->check.state |= CHK_ST_ENABLED;
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* parse a "enable server" command. It always returns 1.
 *
 * Grabs the server lock.
 */
static int cli_parse_enable_server(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct server *sv;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	sv = cli_find_server(appctx, args[2]);
	if (!sv)
		return 1;

	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	srv_adm_set_ready(sv);
	if (!(sv->flags & SRV_F_COOKIESET)
	    && (sv->proxy->ck_opts & PR_CK_DYNAMIC) &&
	    sv->cookie)
		srv_check_for_dup_dyncookie(sv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 1;
}

/* Allocates data structure related to load balancing for the server <sv>. It
 * is only required for dynamic servers.
 *
 * At the moment, the server lock is not used as this function is only called
 * for a dynamic server not yet registered.
 *
 * Returns 1 on success, 0 on allocation failure.
 */
static int srv_alloc_lb(struct server *sv, struct proxy *be)
{
	int node;

	sv->lb_tree = (sv->flags & SRV_F_BACKUP) ?
	              &be->lbprm.chash.bck : &be->lbprm.chash.act;
	sv->lb_nodes_tot = sv->uweight * BE_WEIGHT_SCALE;
	sv->lb_nodes_now = 0;

	if (((be->lbprm.algo & (BE_LB_KIND | BE_LB_PARM)) == (BE_LB_KIND_RR | BE_LB_RR_RANDOM)) ||
	    ((be->lbprm.algo & (BE_LB_KIND | BE_LB_HASH_TYPE)) == (BE_LB_KIND_HI | BE_LB_HASH_CONS))) {
		sv->lb_nodes = calloc(sv->lb_nodes_tot, sizeof(*sv->lb_nodes));

		if (!sv->lb_nodes)
			return 0;

		for (node = 0; node < sv->lb_nodes_tot; node++) {
			sv->lb_nodes[node].server = sv;
			sv->lb_nodes[node].node.key = full_hash(sv->puid * SRV_EWGHT_RANGE + node);
		}
	}

	return 1;
}

/* updates the server's weight during a warmup stage. Once the final weight is
 * reached, the task automatically stops. Note that any server status change
 * must have updated s->last_change accordingly.
 */
static struct task *server_warmup(struct task *t, void *context, unsigned int state)
{
	struct server *s = context;

	/* by default, plan on stopping the task */
	t->expire = TICK_ETERNITY;
	if ((s->next_admin & SRV_ADMF_MAINT) ||
	    (s->next_state != SRV_ST_STARTING))
		return t;

	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);

	/* recalculate the weights and update the state */
	server_recalc_eweight(s, 1);

	/* probably that we can refill this server with a bit more connections */
	pendconn_grab_from_px(s);

	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);

	/* get back there in 1 second or 1/20th of the slowstart interval,
	 * whichever is greater, resulting in small 5% steps.
	 */
	if (s->next_state == SRV_ST_STARTING)
		t->expire = tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20)));
	return t;
}

/* Allocate the slowstart task if the server is configured with a slowstart
 * timer. If server next_state is SRV_ST_STARTING, the task is scheduled.
 *
 * Returns 0 on success else non-zero.
 */
static int init_srv_slowstart(struct server *srv)
{
	struct task *t;

	if (srv->slowstart) {
		if ((t = task_new_anywhere()) == NULL) {
			ha_alert("Cannot activate slowstart for server %s/%s: out of memory.\n", srv->proxy->id, srv->id);
			return ERR_ALERT | ERR_FATAL;
		}

		/* We need a warmup task that will be called when the server
		 * state switches from down to up.
		 */
		srv->warmup = t;
		t->process = server_warmup;
		t->context = srv;

		/* server can be in this state only because of */
		if (srv->next_state == SRV_ST_STARTING) {
			task_schedule(srv->warmup,
			              tick_add(now_ms,
			                       MS_TO_TICKS(MAX(1000, (now.tv_sec - srv->last_change)) / 20)));
		}
	}

	return ERR_NONE;
}
REGISTER_POST_SERVER_CHECK(init_srv_slowstart);

/* Memory allocation and initialization of the per_thr field.
 * Returns 0 if the field has been successfully initialized, -1 on failure.
 */
int srv_init_per_thr(struct server *srv)
{
	int i;

	srv->per_thr = calloc(global.nbthread, sizeof(*srv->per_thr));
	if (!srv->per_thr)
		return -1;

	for (i = 0; i < global.nbthread; i++) {
		srv->per_thr[i].idle_conns = EB_ROOT;
		srv->per_thr[i].safe_conns = EB_ROOT;
		srv->per_thr[i].avail_conns = EB_ROOT;
		MT_LIST_INIT(&srv->per_thr[i].streams);
	}

	return 0;
}

/* Parse a "add server" command
 * Returns 0 if the server has been successfully initialized, 1 on failure.
 */
static int cli_parse_add_server(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *be;
	struct server *srv;
	char *be_name, *sv_name;
	int errcode, argc;
	int next_id;
	const int parse_flags = SRV_PARSE_DYNAMIC|SRV_PARSE_PARSE_ADDR;

	usermsgs_clr("CLI");

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	++args;

	sv_name = be_name = args[1];
	/* split backend/server arg */
	while (*sv_name && *(++sv_name)) {
		if (*sv_name == '/') {
			*sv_name = '\0';
			++sv_name;
			break;
		}
	}

	if (!*sv_name)
		return cli_err(appctx, "Require 'backend/server'.");

	be = proxy_be_by_name(be_name);
	if (!be)
		return cli_err(appctx, "No such backend.");

	if (!(be->lbprm.algo & BE_LB_PROP_DYN)) {
		cli_err(appctx, "Backend must use a dynamic load balancing to support dynamic servers.");
		return 1;
	}

	/* At this point, some operations might not be thread-safe anymore. This
	 * might be the case for parsing handlers which were designed to run
	 * only at the starting stage on single-thread mode.
	 *
	 * Activate thread isolation to ensure thread-safety.
	 */
	thread_isolate();

	args[1] = sv_name;
	errcode = _srv_parse_init(&srv, args, &argc, be, parse_flags);
	if (errcode)
		goto out;

	while (*args[argc]) {
		errcode = _srv_parse_kw(srv, args, &argc, be, parse_flags);

		if (errcode)
			goto out;
	}

	errcode = _srv_parse_finalize(args, argc, srv, be, parse_flags);
	if (errcode)
		goto out;

	/* A dynamic server does not currently support resolution.
	 *
	 * Initialize it explicitly to the "none" method to ensure no
	 * resolution will ever be executed.
	 */
	srv->init_addr_methods = SRV_IADDR_NONE;

	if (srv->mux_proto) {
		if (!conn_get_best_mux_entry(srv->mux_proto->token, PROTO_SIDE_BE, be->mode)) {
			ha_alert("MUX protocol is not usable for server.\n");
			goto out;
		}
	}

	if (srv_init_per_thr(srv) == -1) {
		ha_alert("failed to allocate per-thread lists for server.\n");
		goto out;
	}

	if (srv->max_idle_conns != 0) {
		srv->curr_idle_thr = calloc(global.nbthread, sizeof(*srv->curr_idle_thr));
		if (!srv->curr_idle_thr) {
			ha_alert("failed to allocate counters for server.\n");
			goto out;
		}
	}

	if (!srv_alloc_lb(srv, be)) {
		ha_alert("Failed to initialize load-balancing data.\n");
		goto out;
	}

	if (!stats_allocate_proxy_counters_internal(&srv->extra_counters,
	                                            COUNTERS_SV,
	                                            STATS_PX_CAP_SRV)) {
		ha_alert("failed to allocate extra counters for server.\n");
		goto out;
	}

	if (srv->use_ssl == 1 || (srv->proxy->options & PR_O_TCPCHK_SSL) ||
	    srv->check.use_ssl == 1) {
		if (xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->prepare_srv) {
			if (xprt_get(XPRT_SSL)->prepare_srv(srv))
				goto out;
		}
	}

	if (srv->trackit) {
		if (srv_apply_track(srv, be))
			goto out;
	}

	/* Init check/agent if configured. The check is manually disabled
	 * because a dynamic server is started in a disable state. It must be
	 * manually activated via a "enable health/agent" command.
	 */
	if (srv->do_check) {
		if (init_srv_check(srv))
			goto out;

		srv->check.state &= ~CHK_ST_ENABLED;
	}

	if (srv->do_agent) {
		if (init_srv_agent_check(srv))
			goto out;

		srv->agent.state &= ~CHK_ST_ENABLED;
	}

	/* Init slowstart if needed. */
	if (init_srv_slowstart(srv))
		goto out;

	/* Attach the server to the end of the proxy linked list. Note that this
	 * operation is not thread-safe so this is executed under thread
	 * isolation.
	 *
	 * If a server with the same name is found, reject the new one.
	 */

	/* TODO use a double-linked list for px->srv */
	if (be->srv) {
		struct server *next = be->srv;

		while (1) {
			/* check for duplicate server */
			if (strcmp(srv->id, next->id) == 0) {
				ha_alert("Already exists a server with the same name in backend.\n");
				goto out;
			}

			if (!next->next)
				break;

			next = next->next;
		}

		next->next = srv;
	}
	else {
		srv->next = be->srv;
		be->srv = srv;
	}

	/* generate the server id if not manually specified */
	if (!srv->puid) {
		next_id = get_next_id(&be->conf.used_server_id, 1);
		if (!next_id) {
			ha_alert("Cannot attach server : no id left in proxy\n");
			goto out;
		}

		srv->conf.id.key = srv->puid = next_id;
	}
	srv->conf.name.key = srv->id;

	/* insert the server in the backend trees */
	eb32_insert(&be->conf.used_server_id, &srv->conf.id);
	ebis_insert(&be->conf.used_server_name, &srv->conf.name);
	ebis_insert(&be->used_server_addr, &srv->addr_node);

	thread_release();

	/* Start the check task. The server must be fully initialized.
	 *
	 * <srvpos> and <nbcheck> parameters are set to 1 as there should be no
	 * need to randomly spread the task interval for dynamic servers.
	 */
	if (srv->check.state & CHK_ST_CONFIGURED) {
		if (!start_check_task(&srv->check, 0, 1, 1))
			ha_alert("System might be unstable, consider to execute a reload");
	}
	if (srv->agent.state & CHK_ST_CONFIGURED) {
		if (!start_check_task(&srv->agent, 0, 1, 1))
			ha_alert("System might be unstable, consider to execute a reload");
	}

	ha_notice("New server registered.\n");
	cli_msg(appctx, LOG_INFO, usermsgs_str());

	return 0;

out:
	if (srv) {
		if (srv->track)
			release_server_track(srv);

		if (srv->check.state & CHK_ST_CONFIGURED)
			free_check(&srv->check);
		if (srv->agent.state & CHK_ST_CONFIGURED)
			free_check(&srv->agent);

		/* remove the server from the proxy linked list */
		if (be->srv == srv) {
			be->srv = srv->next;
		}
		else {
			struct server *prev;
			for (prev = be->srv; prev && prev->next != srv; prev = prev->next)
				;
			if (prev)
				prev->next = srv->next;
		}

	}

	thread_release();

	if (!usermsgs_empty())
		cli_err(appctx, usermsgs_str());

	if (srv)
		srv_drop(srv);

	return 1;
}

/* Parse a "del server" command
 * Returns 0 if the server has been successfully initialized, 1 on failure.
 */
static int cli_parse_delete_server(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *be;
	struct server *srv;
	char *be_name, *sv_name;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	++args;

	sv_name = be_name = args[1];
	/* split backend/server arg */
	while (*sv_name && *(++sv_name)) {
		if (*sv_name == '/') {
			*sv_name = '\0';
			++sv_name;
			break;
		}
	}

	if (!*sv_name)
		return cli_err(appctx, "Require 'backend/server'.");

	/* The proxy servers list is currently not protected by a lock so this
	 * requires thread isolation. In addition, any place referencing the
	 * server about to be deleted would be unsafe after our operation, so
	 * we must be certain to be alone so that no other thread has even
	 * started to grab a temporary reference to this server.
	 */
	thread_isolate_full();

	get_backend_server(be_name, sv_name, &be, &srv);
	if (!be) {
		cli_err(appctx, "No such backend.");
		goto out;
	}

	if (!srv) {
		cli_err(appctx, "No such server.");
		goto out;
	}

	if (srv->flags & SRV_F_NON_PURGEABLE) {
		cli_err(appctx, "This server cannot be removed at runtime due to other configuration elements pointing to it.");
		goto out;
	}

	/* Only servers in maintenance can be deleted. This ensures that the
	 * server is not present anymore in the lb structures (through
	 * lbprm.set_server_status_down).
	 */
	if (!(srv->cur_admin & SRV_ADMF_MAINT)) {
		cli_err(appctx, "Only servers in maintenance mode can be deleted.");
		goto out;
	}

	/* Ensure that there is no active/idle/pending connection on the server.
	 *
	 * TODO idle connections should not prevent server deletion. A proper
	 * cleanup function should be implemented to be used here.
	 */
	if (srv->cur_sess || srv->curr_idle_conns ||
	    !eb_is_empty(&srv->queue.head)) {
		cli_err(appctx, "Server still has connections attached to it, cannot remove it.");
		goto out;
	}

	/* remove srv from tracking list */
	if (srv->track)
		release_server_track(srv);

	/* stop the check task if running */
	if (srv->check.state & CHK_ST_CONFIGURED)
		check_purge(&srv->check);
	if (srv->agent.state & CHK_ST_CONFIGURED)
		check_purge(&srv->agent);

	/* detach the server from the proxy linked list
	 * The proxy servers list is currently not protected by a lock, so this
	 * requires thread_isolate/release.
	 */

	/* be->srv cannot be empty since we have already found the server with
	 * get_backend_server */
	BUG_ON(!be->srv);
	if (be->srv == srv) {
		be->srv = srv->next;
	}
	else {
		struct server *next;
		for (next = be->srv; srv != next->next; next = next->next) {
			/* srv cannot be not found since we have already found
			 * it with get_backend_server */
			BUG_ON(!next);
		}

		next->next = srv->next;
	}

	/* remove srv from addr_node tree */
	eb32_delete(&srv->conf.id);
	ebpt_delete(&srv->conf.name);
	ebpt_delete(&srv->addr_node);

	/* remove srv from idle_node tree for idle conn cleanup */
	eb32_delete(&srv->idle_node);

	thread_release();

	ha_notice("Server deleted.\n");
	srv_drop(srv);

	cli_msg(appctx, LOG_INFO, "Server deleted.");

	return 0;

out:
	thread_release();

	return 1;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "disable", "agent",  NULL },         "disable agent                           : disable agent checks",                                        cli_parse_disable_agent, NULL },
	{ { "disable", "health",  NULL },        "disable health                          : disable health checks",                                       cli_parse_disable_health, NULL },
	{ { "disable", "server",  NULL },        "disable server (DEPRECATED)             : disable a server for maintenance (use 'set server' instead)", cli_parse_disable_server, NULL },
	{ { "enable", "agent",  NULL },          "enable agent                            : enable agent checks",                                         cli_parse_enable_agent, NULL },
	{ { "enable", "health",  NULL },         "enable health                           : enable health checks",                                        cli_parse_enable_health, NULL },
	{ { "enable", "server",  NULL },         "enable server  (DEPRECATED)             : enable a disabled server (use 'set server' instead)",         cli_parse_enable_server, NULL },
	{ { "set", "maxconn", "server",  NULL }, "set maxconn server <bk>/<srv>           : change a server's maxconn setting",                           cli_parse_set_maxconn_server, NULL },
	{ { "set", "server", NULL },             "set server <bk>/<srv> [opts]            : change a server's state, weight, address or ssl",             cli_parse_set_server },
	{ { "get", "weight", NULL },             "get weight <bk>/<srv>                   : report a server's current weight",                            cli_parse_get_weight },
	{ { "set", "weight", NULL },             "set weight <bk>/<srv>  (DEPRECATED)     : change a server's weight (use 'set server' instead)",         cli_parse_set_weight },
	{ { "add", "server", NULL },             "add server <bk>/<srv>                   : create a new server (EXPERIMENTAL)",                          cli_parse_add_server, NULL, NULL, NULL, ACCESS_EXPERIMENTAL },
	{ { "del", "server", NULL },             "del server <bk>/<srv>                   : remove a dynamically added server (EXPERIMENTAL)",            cli_parse_delete_server, NULL, NULL, NULL, ACCESS_EXPERIMENTAL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* Prepare a server <srv> to track check status of another one. <srv>.<trackit>
 * field is used to retrieve the identifier of the tracked server, either with
 * the format "proxy/server" or just "server". <curproxy> must point to the
 * backend owning <srv>; if no proxy is specified in <trackit>, it will be used
 * to find the tracked server.
 *
 * Returns 0 if the server track has been activated else non-zero.
 *
 * Not thread-safe.
 */
int srv_apply_track(struct server *srv, struct proxy *curproxy)
{
	struct proxy *px;
	struct server *strack, *loop;
	char *pname, *sname;

	if (!srv->trackit)
		return 1;

	pname = srv->trackit;
	sname = strrchr(pname, '/');

	if (sname) {
		*sname++ = '\0';
	}
	else {
		sname = pname;
		pname = NULL;
	}

	if (pname) {
		px = proxy_be_by_name(pname);
		if (!px) {
			ha_alert("unable to find required proxy '%s' for tracking.\n",
			         pname);
			return 1;
		}
	}
	else {
		px = curproxy;
	}

	strack = findserver(px, sname);
	if (!strack) {
		ha_alert("unable to find required server '%s' for tracking.\n",
		         sname);
		return 1;
	}

	if (strack->flags & SRV_F_DYNAMIC) {
		ha_alert("unable to use %s/%s for tracking as it is a dynamic server.\n",
		         px->id, strack->id);
		return 1;
	}

	if (!strack->do_check && !strack->do_agent && !strack->track &&
	    !strack->trackit) {
		ha_alert("unable to use %s/%s for "
		         "tracking as it does not have any check nor agent enabled.\n",
		         px->id, strack->id);
		return 1;
	}

	for (loop = strack->track; loop && loop != srv; loop = loop->track)
		;

	if (srv == strack || loop) {
		ha_alert("unable to track %s/%s as it "
		         "belongs to a tracking chain looping back to %s/%s.\n",
		         px->id, strack->id, px->id,
		         srv == strack ? strack->id : loop->id);
		return 1;
	}

	if (curproxy != px &&
	    (curproxy->options & PR_O_DISABLE404) != (px->options & PR_O_DISABLE404)) {
		ha_alert("unable to use %s/%s for"
		         "tracking: disable-on-404 option inconsistency.\n",
		         px->id, strack->id);
		return 1;
	}

	srv->track = strack;
	srv->tracknext = strack->trackers;
	strack->trackers = srv;
	strack->flags |= SRV_F_NON_PURGEABLE;

	ha_free(&srv->trackit);

	return 0;
}

/*
 * This function applies server's status changes, it is
 * is designed to be called asynchronously.
 *
 * Must be called with the server lock held. This may also be called at init
 * time as the result of parsing the state file, in which case no lock will be
 * held, and the server's warmup task can be null.
 */
static void srv_update_status(struct server *s)
{
	struct check *check = &s->check;
	int xferred;
	struct proxy *px = s->proxy;
	int prev_srv_count = s->proxy->srv_bck + s->proxy->srv_act;
	int srv_was_stopping = (s->cur_state == SRV_ST_STOPPING) || (s->cur_admin & SRV_ADMF_DRAIN);
	int log_level;
	struct buffer *tmptrash = NULL;

	/* If currently main is not set we try to apply pending state changes */
	if (!(s->cur_admin & SRV_ADMF_MAINT)) {
		int next_admin;

		/* Backup next admin */
		next_admin = s->next_admin;

		/* restore current admin state */
		s->next_admin = s->cur_admin;

		if ((s->cur_state != SRV_ST_STOPPED) && (s->next_state == SRV_ST_STOPPED)) {
			s->last_change = now.tv_sec;
			if (s->proxy->lbprm.set_server_status_down)
				s->proxy->lbprm.set_server_status_down(s);

			if (s->onmarkeddown & HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS)
				srv_shutdown_streams(s, SF_ERR_DOWN);

			/* we might have streams queued on this server and waiting for
			 * a connection. Those which are redispatchable will be queued
			 * to another server or to the proxy itself.
			 */
			xferred = pendconn_redistribute(s);

			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				             "%sServer %s/%s is DOWN", s->flags & SRV_F_BACKUP ? "Backup " : "",
				             s->proxy->id, s->id);

				srv_append_status(tmptrash, s, NULL, xferred, 0);
				ha_warning("%s.\n", tmptrash->area);

				/* we don't send an alert if the server was previously paused */
				log_level = srv_was_stopping ? LOG_NOTICE : LOG_ALERT;
				send_log(s->proxy, log_level, "%s.\n",
					 tmptrash->area);
				send_email_alert(s, log_level, "%s",
						 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}
			if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
				set_backend_down(s->proxy);

			s->counters.down_trans++;
		}
		else if ((s->cur_state != SRV_ST_STOPPING) && (s->next_state == SRV_ST_STOPPING)) {
			s->last_change = now.tv_sec;
			if (s->proxy->lbprm.set_server_status_down)
				s->proxy->lbprm.set_server_status_down(s);

			/* we might have streams queued on this server and waiting for
			 * a connection. Those which are redispatchable will be queued
			 * to another server or to the proxy itself.
			 */
			xferred = pendconn_redistribute(s);

			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				             "%sServer %s/%s is stopping", s->flags & SRV_F_BACKUP ? "Backup " : "",
				             s->proxy->id, s->id);

				srv_append_status(tmptrash, s, NULL, xferred, 0);

				ha_warning("%s.\n", tmptrash->area);
				send_log(s->proxy, LOG_NOTICE, "%s.\n",
					 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}

			if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
				set_backend_down(s->proxy);
		}
		else if (((s->cur_state != SRV_ST_RUNNING) && (s->next_state == SRV_ST_RUNNING))
			 || ((s->cur_state != SRV_ST_STARTING) && (s->next_state == SRV_ST_STARTING))) {
			if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
				if (s->proxy->last_change < now.tv_sec)		// ignore negative times
					s->proxy->down_time += now.tv_sec - s->proxy->last_change;
				s->proxy->last_change = now.tv_sec;
			}

			if (s->cur_state == SRV_ST_STOPPED && s->last_change < now.tv_sec)	// ignore negative times
				s->down_time += now.tv_sec - s->last_change;

			s->last_change = now.tv_sec;
			if (s->next_state == SRV_ST_STARTING && s->warmup)
				task_schedule(s->warmup, tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20))));

			server_recalc_eweight(s, 0);
			/* now propagate the status change to any LB algorithms */
			if (px->lbprm.update_server_eweight)
				px->lbprm.update_server_eweight(s);
			else if (srv_willbe_usable(s)) {
				if (px->lbprm.set_server_status_up)
					px->lbprm.set_server_status_up(s);
			}
			else {
				if (px->lbprm.set_server_status_down)
					px->lbprm.set_server_status_down(s);
			}

			/* If the server is set with "on-marked-up shutdown-backup-sessions",
			 * and it's not a backup server and its effective weight is > 0,
			 * then it can accept new connections, so we shut down all streams
			 * on all backup servers.
			 */
			if ((s->onmarkedup & HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS) &&
			    !(s->flags & SRV_F_BACKUP) && s->next_eweight)
				srv_shutdown_backup_streams(s->proxy, SF_ERR_UP);

			/* check if we can handle some connections queued at the proxy. We
			 * will take as many as we can handle.
			 */
			xferred = pendconn_grab_from_px(s);

			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				             "%sServer %s/%s is UP", s->flags & SRV_F_BACKUP ? "Backup " : "",
				             s->proxy->id, s->id);

				srv_append_status(tmptrash, s, NULL, xferred, 0);
				ha_warning("%s.\n", tmptrash->area);
				send_log(s->proxy, LOG_NOTICE, "%s.\n",
					 tmptrash->area);
				send_email_alert(s, LOG_NOTICE, "%s",
						 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}

			if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
				set_backend_down(s->proxy);
		}
		else if (s->cur_eweight != s->next_eweight) {
			/* now propagate the status change to any LB algorithms */
			if (px->lbprm.update_server_eweight)
				px->lbprm.update_server_eweight(s);
			else if (srv_willbe_usable(s)) {
				if (px->lbprm.set_server_status_up)
					px->lbprm.set_server_status_up(s);
			}
			else {
				if (px->lbprm.set_server_status_down)
					px->lbprm.set_server_status_down(s);
			}

			if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
				set_backend_down(s->proxy);
		}

		s->next_admin = next_admin;
	}

	/* reset operational state change */
	*s->op_st_chg.reason = 0;
	s->op_st_chg.status = s->op_st_chg.code = -1;
	s->op_st_chg.duration = 0;

	/* Now we try to apply pending admin changes */

	/* Maintenance must also disable health checks */
	if (!(s->cur_admin & SRV_ADMF_MAINT) && (s->next_admin & SRV_ADMF_MAINT)) {
		if (s->check.state & CHK_ST_ENABLED) {
			s->check.state |= CHK_ST_PAUSED;
			check->health = 0;
		}

		if (s->cur_state == SRV_ST_STOPPED) {	/* server was already down */
			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				    "%sServer %s/%s was DOWN and now enters maintenance%s%s%s",
				    s->flags & SRV_F_BACKUP ? "Backup " : "", s->proxy->id, s->id,
				    *(s->adm_st_chg_cause) ? " (" : "", s->adm_st_chg_cause, *(s->adm_st_chg_cause) ? ")" : "");

				srv_append_status(tmptrash, s, NULL, -1, (s->next_admin & SRV_ADMF_FMAINT));

				if (!(global.mode & MODE_STARTING)) {
					ha_warning("%s.\n", tmptrash->area);
					send_log(s->proxy, LOG_NOTICE, "%s.\n",
						 tmptrash->area);
				}
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}
			/* commit new admin status */

			s->cur_admin = s->next_admin;
		}
		else {	/* server was still running */
			check->health = 0; /* failure */
			s->last_change = now.tv_sec;

			s->next_state = SRV_ST_STOPPED;
			if (s->proxy->lbprm.set_server_status_down)
				s->proxy->lbprm.set_server_status_down(s);

			if (s->onmarkeddown & HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS)
				srv_shutdown_streams(s, SF_ERR_DOWN);

			/* force connection cleanup on the given server */
			srv_cleanup_connections(s);
			/* we might have streams queued on this server and waiting for
			 * a connection. Those which are redispatchable will be queued
			 * to another server or to the proxy itself.
			 */
			xferred = pendconn_redistribute(s);

			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				             "%sServer %s/%s is going DOWN for maintenance%s%s%s",
				             s->flags & SRV_F_BACKUP ? "Backup " : "",
				             s->proxy->id, s->id,
				             *(s->adm_st_chg_cause) ? " (" : "", s->adm_st_chg_cause, *(s->adm_st_chg_cause) ? ")" : "");

				srv_append_status(tmptrash, s, NULL, xferred, (s->next_admin & SRV_ADMF_FMAINT));

				if (!(global.mode & MODE_STARTING)) {
					ha_warning("%s.\n", tmptrash->area);
					send_log(s->proxy, srv_was_stopping ? LOG_NOTICE : LOG_ALERT, "%s.\n",
						 tmptrash->area);
				}
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}
			if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
				set_backend_down(s->proxy);

			s->counters.down_trans++;
		}
	}
	else if ((s->cur_admin & SRV_ADMF_MAINT) && !(s->next_admin & SRV_ADMF_MAINT)) {
		/* OK here we're leaving maintenance, we have many things to check,
		 * because the server might possibly be coming back up depending on
		 * its state. In practice, leaving maintenance means that we should
		 * immediately turn to UP (more or less the slowstart) under the
		 * following conditions :
		 *   - server is neither checked nor tracked
		 *   - server tracks another server which is not checked
		 *   - server tracks another server which is already up
		 * Which sums up as something simpler :
		 * "either the tracking server is up or the server's checks are disabled
		 * or up". Otherwise we only re-enable health checks. There's a special
		 * case associated to the stopping state which can be inherited. Note
		 * that the server might still be in drain mode, which is naturally dealt
		 * with by the lower level functions.
		 */

		if (s->check.state & CHK_ST_ENABLED) {
			s->check.state &= ~CHK_ST_PAUSED;
			check->health = check->rise; /* start OK but check immediately */
		}

		if ((!s->track || s->track->next_state != SRV_ST_STOPPED) &&
		    (!(s->agent.state & CHK_ST_ENABLED) || (s->agent.health >= s->agent.rise)) &&
		    (!(s->check.state & CHK_ST_ENABLED) || (s->check.health >= s->check.rise))) {
			if (s->track && s->track->next_state == SRV_ST_STOPPING) {
				s->next_state = SRV_ST_STOPPING;
			}
			else {
				s->last_change = now.tv_sec;
				s->next_state = SRV_ST_STARTING;
				if (s->slowstart > 0) {
					if (s->warmup)
						task_schedule(s->warmup, tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20))));
				}
				else
					s->next_state = SRV_ST_RUNNING;
			}

		}

		tmptrash = alloc_trash_chunk();
		if (tmptrash) {
			if (!(s->next_admin & SRV_ADMF_FMAINT) && (s->cur_admin & SRV_ADMF_FMAINT)) {
				chunk_printf(tmptrash,
					     "%sServer %s/%s is %s/%s (leaving forced maintenance)",
					     s->flags & SRV_F_BACKUP ? "Backup " : "",
					     s->proxy->id, s->id,
					     (s->next_state == SRV_ST_STOPPED) ? "DOWN" : "UP",
					     (s->next_admin & SRV_ADMF_DRAIN) ? "DRAIN" : "READY");
			}
			if (!(s->next_admin & SRV_ADMF_RMAINT) && (s->cur_admin & SRV_ADMF_RMAINT)) {
				chunk_printf(tmptrash,
					     "%sServer %s/%s ('%s') is %s/%s (resolves again)",
					     s->flags & SRV_F_BACKUP ? "Backup " : "",
					     s->proxy->id, s->id, s->hostname,
					     (s->next_state == SRV_ST_STOPPED) ? "DOWN" : "UP",
					     (s->next_admin & SRV_ADMF_DRAIN) ? "DRAIN" : "READY");
			}
			if (!(s->next_admin & SRV_ADMF_IMAINT) && (s->cur_admin & SRV_ADMF_IMAINT)) {
				chunk_printf(tmptrash,
					     "%sServer %s/%s is %s/%s (leaving maintenance)",
					     s->flags & SRV_F_BACKUP ? "Backup " : "",
					     s->proxy->id, s->id,
					     (s->next_state == SRV_ST_STOPPED) ? "DOWN" : "UP",
					     (s->next_admin & SRV_ADMF_DRAIN) ? "DRAIN" : "READY");
			}
			ha_warning("%s.\n", tmptrash->area);
			send_log(s->proxy, LOG_NOTICE, "%s.\n",
				 tmptrash->area);
			free_trash_chunk(tmptrash);
			tmptrash = NULL;
		}

		server_recalc_eweight(s, 0);
		/* now propagate the status change to any LB algorithms */
		if (px->lbprm.update_server_eweight)
			px->lbprm.update_server_eweight(s);
		else if (srv_willbe_usable(s)) {
			if (px->lbprm.set_server_status_up)
				px->lbprm.set_server_status_up(s);
		}
		else {
			if (px->lbprm.set_server_status_down)
				px->lbprm.set_server_status_down(s);
		}

		if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
			set_backend_down(s->proxy);
		else if (!prev_srv_count && (s->proxy->srv_bck || s->proxy->srv_act))
			s->proxy->last_change = now.tv_sec;

		/* If the server is set with "on-marked-up shutdown-backup-sessions",
		 * and it's not a backup server and its effective weight is > 0,
		 * then it can accept new connections, so we shut down all streams
		 * on all backup servers.
		 */
		if ((s->onmarkedup & HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS) &&
		    !(s->flags & SRV_F_BACKUP) && s->next_eweight)
			srv_shutdown_backup_streams(s->proxy, SF_ERR_UP);

		/* check if we can handle some connections queued at the proxy. We
		 * will take as many as we can handle.
		 */
		xferred = pendconn_grab_from_px(s);
	}
	else if (s->next_admin & SRV_ADMF_MAINT) {
		/* remaining in maintenance mode, let's inform precisely about the
		 * situation.
		 */
		if (!(s->next_admin & SRV_ADMF_FMAINT) && (s->cur_admin & SRV_ADMF_FMAINT)) {
			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				             "%sServer %s/%s is leaving forced maintenance but remains in maintenance",
				             s->flags & SRV_F_BACKUP ? "Backup " : "",
				             s->proxy->id, s->id);

				if (s->track) /* normally it's mandatory here */
					chunk_appendf(tmptrash, " via %s/%s",
				              s->track->proxy->id, s->track->id);
				ha_warning("%s.\n", tmptrash->area);
				send_log(s->proxy, LOG_NOTICE, "%s.\n",
					 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}
		}
		if (!(s->next_admin & SRV_ADMF_RMAINT) && (s->cur_admin & SRV_ADMF_RMAINT)) {
			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				             "%sServer %s/%s ('%s') resolves again but remains in maintenance",
				             s->flags & SRV_F_BACKUP ? "Backup " : "",
				             s->proxy->id, s->id, s->hostname);

				if (s->track) /* normally it's mandatory here */
					chunk_appendf(tmptrash, " via %s/%s",
				              s->track->proxy->id, s->track->id);
				ha_warning("%s.\n", tmptrash->area);
				send_log(s->proxy, LOG_NOTICE, "%s.\n",
					 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}
		}
		else if (!(s->next_admin & SRV_ADMF_IMAINT) && (s->cur_admin & SRV_ADMF_IMAINT)) {
			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash,
				             "%sServer %s/%s remains in forced maintenance",
				             s->flags & SRV_F_BACKUP ? "Backup " : "",
				             s->proxy->id, s->id);
				ha_warning("%s.\n", tmptrash->area);
				send_log(s->proxy, LOG_NOTICE, "%s.\n",
					 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}
		}
		/* don't report anything when leaving drain mode and remaining in maintenance */

		s->cur_admin = s->next_admin;
	}

	if (!(s->next_admin & SRV_ADMF_MAINT)) {
		if (!(s->cur_admin & SRV_ADMF_DRAIN) && (s->next_admin & SRV_ADMF_DRAIN)) {
			/* drain state is applied only if not yet in maint */

			s->last_change = now.tv_sec;
			if (px->lbprm.set_server_status_down)
				px->lbprm.set_server_status_down(s);

			/* we might have streams queued on this server and waiting for
			 * a connection. Those which are redispatchable will be queued
			 * to another server or to the proxy itself.
			 */
			xferred = pendconn_redistribute(s);

			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				chunk_printf(tmptrash, "%sServer %s/%s enters drain state%s%s%s",
					     s->flags & SRV_F_BACKUP ? "Backup " : "", s->proxy->id, s->id,
				             *(s->adm_st_chg_cause) ? " (" : "", s->adm_st_chg_cause, *(s->adm_st_chg_cause) ? ")" : "");

				srv_append_status(tmptrash, s, NULL, xferred, (s->next_admin & SRV_ADMF_FDRAIN));

				if (!(global.mode & MODE_STARTING)) {
					ha_warning("%s.\n", tmptrash->area);
					send_log(s->proxy, LOG_NOTICE, "%s.\n",
						 tmptrash->area);
					send_email_alert(s, LOG_NOTICE, "%s",
							 tmptrash->area);
				}
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}

			if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
				set_backend_down(s->proxy);
		}
		else if ((s->cur_admin & SRV_ADMF_DRAIN) && !(s->next_admin & SRV_ADMF_DRAIN)) {
			/* OK completely leaving drain mode */
			if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
				if (s->proxy->last_change < now.tv_sec)         // ignore negative times
					s->proxy->down_time += now.tv_sec - s->proxy->last_change;
				s->proxy->last_change = now.tv_sec;
			}

			if (s->last_change < now.tv_sec)                        // ignore negative times
				s->down_time += now.tv_sec - s->last_change;
			s->last_change = now.tv_sec;
			server_recalc_eweight(s, 0);

			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				if (!(s->next_admin & SRV_ADMF_FDRAIN)) {
					chunk_printf(tmptrash,
						     "%sServer %s/%s is %s (leaving forced drain)",
						     s->flags & SRV_F_BACKUP ? "Backup " : "",
					             s->proxy->id, s->id,
					             (s->next_state == SRV_ST_STOPPED) ? "DOWN" : "UP");
				}
				else {
					chunk_printf(tmptrash,
					             "%sServer %s/%s is %s (leaving drain)",
					             s->flags & SRV_F_BACKUP ? "Backup " : "",
						     s->proxy->id, s->id,
						     (s->next_state == SRV_ST_STOPPED) ? "DOWN" : "UP");
					if (s->track) /* normally it's mandatory here */
						chunk_appendf(tmptrash, " via %s/%s",
					s->track->proxy->id, s->track->id);
				}

				ha_warning("%s.\n", tmptrash->area);
				send_log(s->proxy, LOG_NOTICE, "%s.\n",
					 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}

			/* now propagate the status change to any LB algorithms */
			if (px->lbprm.update_server_eweight)
				px->lbprm.update_server_eweight(s);
			else if (srv_willbe_usable(s)) {
				if (px->lbprm.set_server_status_up)
					px->lbprm.set_server_status_up(s);
			}
			else {
				if (px->lbprm.set_server_status_down)
					px->lbprm.set_server_status_down(s);
			}
		}
		else if ((s->next_admin & SRV_ADMF_DRAIN)) {
			/* remaining in drain mode after removing one of its flags */

			tmptrash = alloc_trash_chunk();
			if (tmptrash) {
				if (!(s->next_admin & SRV_ADMF_FDRAIN)) {
					chunk_printf(tmptrash,
					             "%sServer %s/%s is leaving forced drain but remains in drain mode",
					             s->flags & SRV_F_BACKUP ? "Backup " : "",
					             s->proxy->id, s->id);

					if (s->track) /* normally it's mandatory here */
						chunk_appendf(tmptrash, " via %s/%s",
					              s->track->proxy->id, s->track->id);
				}
				else {
					chunk_printf(tmptrash,
					             "%sServer %s/%s remains in forced drain mode",
					             s->flags & SRV_F_BACKUP ? "Backup " : "",
					             s->proxy->id, s->id);
				}
				ha_warning("%s.\n", tmptrash->area);
				send_log(s->proxy, LOG_NOTICE, "%s.\n",
					 tmptrash->area);
				free_trash_chunk(tmptrash);
				tmptrash = NULL;
			}

			/* commit new admin status */

			s->cur_admin = s->next_admin;
		}
	}

	/* Re-set log strings to empty */
	*s->adm_st_chg_cause = 0;
}

struct task *srv_cleanup_toremove_conns(struct task *task, void *context, unsigned int state)
{
	struct connection *conn;

	while ((conn = MT_LIST_POP(&idle_conns[tid].toremove_conns,
	                               struct connection *, toremove_list)) != NULL) {
		conn->mux->destroy(conn->ctx);
	}

	return task;
}

/* Move toremove_nb connections from idle_tree to toremove_list, -1 means
 * moving them all.
 * Returns the number of connections moved.
 *
 * Must be called with idle_conns_lock held.
 */
static int srv_migrate_conns_to_remove(struct eb_root *idle_tree, struct mt_list *toremove_list, int toremove_nb)
{
	struct eb_node *node, *next;
	struct conn_hash_node *hash_node;
	int i = 0;

	node = eb_first(idle_tree);
	while (node) {
		next = eb_next(node);
		if (toremove_nb != -1 && i >= toremove_nb)
			break;

		hash_node = ebmb_entry(node, struct conn_hash_node, node);
		eb_delete(node);
		MT_LIST_APPEND(toremove_list, &hash_node->conn->toremove_list);
		i++;

		node = next;
	}
	return i;
}
/* cleanup connections for a given server
 * might be useful when going on forced maintenance or live changing ip/port
 */
static void srv_cleanup_connections(struct server *srv)
{
	int did_remove;
	int i;

	/* nothing to do if pool-max-conn is null */
	if (!srv->max_idle_conns)
		return;

	/* check all threads starting with ours */
	for (i = tid;;) {
		did_remove = 0;
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);
		if (srv_migrate_conns_to_remove(&srv->per_thr[i].idle_conns, &idle_conns[i].toremove_conns, -1) > 0)
			did_remove = 1;
		if (srv_migrate_conns_to_remove(&srv->per_thr[i].safe_conns, &idle_conns[i].toremove_conns, -1) > 0)
			did_remove = 1;
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);
		if (did_remove)
			task_wakeup(idle_conns[i].cleanup_task, TASK_WOKEN_OTHER);

		if ((i = ((i + 1 == global.nbthread) ? 0 : i + 1)) == tid)
			break;
	}
}

/* removes an idle conn after updating the server idle conns counters */
void srv_release_conn(struct server *srv, struct connection *conn)
{
	if (conn->flags & CO_FL_LIST_MASK) {
		/* The connection is currently in the server's idle list, so tell it
		 * there's one less connection available in that list.
		 */
		_HA_ATOMIC_DEC(&srv->curr_idle_conns);
		_HA_ATOMIC_DEC(conn->flags & CO_FL_SAFE_LIST ? &srv->curr_safe_nb : &srv->curr_idle_nb);
		_HA_ATOMIC_DEC(&srv->curr_idle_thr[tid]);
	}
	else {
		/* The connection is not private and not in any server's idle
		 * list, so decrement the current number of used connections
		 */
		_HA_ATOMIC_DEC(&srv->curr_used_conns);
	}

	/* Remove the connection from any tree (safe, idle or available) */
	HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	conn_delete_from_tree(&conn->hash_node->node);
	HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
}

/* retrieve a connection from its <hash> in <tree>
 * returns NULL if no connection found
 */
struct connection *srv_lookup_conn(struct eb_root *tree, uint64_t hash)
{
	struct ebmb_node *node = NULL;
	struct connection *conn = NULL;
	struct conn_hash_node *hash_node = NULL;

	node = ebmb_lookup(tree, &hash, sizeof(hash_node->hash));
	if (node) {
		hash_node = ebmb_entry(node, struct conn_hash_node, node);
		conn = hash_node->conn;
	}

	return conn;
}

/* retrieve the next connection sharing the same hash as <conn>
 * returns NULL if no connection found
 */
struct connection *srv_lookup_conn_next(struct connection *conn)
{
	struct ebmb_node *node = NULL;
	struct connection *next_conn = NULL;
	struct conn_hash_node *hash_node = NULL;

	node = ebmb_next_dup(&conn->hash_node->node);
	if (node) {
		hash_node = ebmb_entry(node, struct conn_hash_node, node);
		next_conn = hash_node->conn;
	}

	return next_conn;
}

/* This adds an idle connection to the server's list if the connection is
 * reusable, not held by any owner anymore, but still has available streams.
 */
int srv_add_to_idle_list(struct server *srv, struct connection *conn, int is_safe)
{
	/* we try to keep the connection in the server's idle list
	 * if we don't have too many FD in use, and if the number of
	 * idle+current conns is lower than what was observed before
	 * last purge, or if we already don't have idle conns for the
	 * current thread and we don't exceed last count by global.nbthread.
	 */
	if (!(conn->flags & CO_FL_PRIVATE) &&
	    srv && srv->pool_purge_delay > 0 &&
	    ((srv->proxy->options & PR_O_REUSE_MASK) != PR_O_REUSE_NEVR) &&
	    ha_used_fds < global.tune.pool_high_count &&
	    (srv->max_idle_conns == -1 || srv->max_idle_conns > srv->curr_idle_conns) &&
	    ((eb_is_empty(&srv->per_thr[tid].safe_conns) &&
	      (is_safe || eb_is_empty(&srv->per_thr[tid].idle_conns))) ||
	     (ha_used_fds < global.tune.pool_low_count &&
	      (srv->curr_used_conns + srv->curr_idle_conns <=
	       MAX(srv->curr_used_conns, srv->est_need_conns) + srv->low_idle_conns))) &&
	    !conn->mux->used_streams(conn) && conn->mux->avail_streams(conn)) {
		int retadd;

		retadd = _HA_ATOMIC_ADD_FETCH(&srv->curr_idle_conns, 1);
		if (retadd > srv->max_idle_conns) {
			_HA_ATOMIC_DEC(&srv->curr_idle_conns);
			return 0;
		}
		_HA_ATOMIC_DEC(&srv->curr_used_conns);

		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		conn_delete_from_tree(&conn->hash_node->node);

		if (is_safe) {
			conn->flags = (conn->flags & ~CO_FL_LIST_MASK) | CO_FL_SAFE_LIST;
			ebmb_insert(&srv->per_thr[tid].safe_conns, &conn->hash_node->node, sizeof(conn->hash_node->hash));
			_HA_ATOMIC_INC(&srv->curr_safe_nb);
		} else {
			conn->flags = (conn->flags & ~CO_FL_LIST_MASK) | CO_FL_IDLE_LIST;
			ebmb_insert(&srv->per_thr[tid].idle_conns, &conn->hash_node->node, sizeof(conn->hash_node->hash));
			_HA_ATOMIC_INC(&srv->curr_idle_nb);
		}
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		_HA_ATOMIC_INC(&srv->curr_idle_thr[tid]);

		__ha_barrier_full();
		if ((volatile void *)srv->idle_node.node.leaf_p == NULL) {
			HA_SPIN_LOCK(OTHER_LOCK, &idle_conn_srv_lock);
			if ((volatile void *)srv->idle_node.node.leaf_p == NULL) {
				srv->idle_node.key = tick_add(srv->pool_purge_delay,
				                              now_ms);
				eb32_insert(&idle_conn_srv, &srv->idle_node);
				if (!task_in_wq(idle_conn_task) && !
				    task_in_rq(idle_conn_task)) {
					task_schedule(idle_conn_task,
					              srv->idle_node.key);
				}

			}
			HA_SPIN_UNLOCK(OTHER_LOCK, &idle_conn_srv_lock);
		}
		return 1;
	}
	return 0;
}

struct task *srv_cleanup_idle_conns(struct task *task, void *context, unsigned int state)
{
	struct server *srv;
	struct eb32_node *eb;
	int i;
	unsigned int next_wakeup;

	next_wakeup = TICK_ETERNITY;
	HA_SPIN_LOCK(OTHER_LOCK, &idle_conn_srv_lock);
	while (1) {
		int exceed_conns;
		int to_kill;
		int curr_idle;

		eb = eb32_lookup_ge(&idle_conn_srv, now_ms - TIMER_LOOK_BACK);
		if (!eb) {
			/* we might have reached the end of the tree, typically because
			 * <now_ms> is in the first half and we're first scanning the last
			* half. Let's loop back to the beginning of the tree now.
			*/

			eb = eb32_first(&idle_conn_srv);
			if (likely(!eb))
				break;
		}
		if (tick_is_lt(now_ms, eb->key)) {
			/* timer not expired yet, revisit it later */
			next_wakeup = eb->key;
			break;
		}
		srv = eb32_entry(eb, struct server, idle_node);

		/* Calculate how many idle connections we want to kill :
		 * we want to remove half the difference between the total
		 * of established connections (used or idle) and the max
		 * number of used connections.
		 */
		curr_idle = srv->curr_idle_conns;
		if (curr_idle == 0)
			goto remove;
		exceed_conns = srv->curr_used_conns + curr_idle - MAX(srv->max_used_conns, srv->est_need_conns);
		exceed_conns = to_kill = exceed_conns / 2 + (exceed_conns & 1);

		srv->est_need_conns = (srv->est_need_conns + srv->max_used_conns) / 2;
		if (srv->est_need_conns < srv->max_used_conns)
			srv->est_need_conns = srv->max_used_conns;

		srv->max_used_conns = srv->curr_used_conns;

		if (exceed_conns <= 0)
			goto remove;

		/* check all threads starting with ours */
		for (i = tid;;) {
			int max_conn;
			int j;
			int did_remove = 0;

			max_conn = (exceed_conns * srv->curr_idle_thr[i]) /
			           curr_idle + 1;

			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);
			j = srv_migrate_conns_to_remove(&srv->per_thr[i].idle_conns, &idle_conns[i].toremove_conns, max_conn);
			if (j > 0)
				did_remove = 1;
			if (max_conn - j > 0 &&
			    srv_migrate_conns_to_remove(&srv->per_thr[i].safe_conns, &idle_conns[i].toremove_conns, max_conn - j) > 0)
				did_remove = 1;
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);

			if (did_remove)
				task_wakeup(idle_conns[i].cleanup_task, TASK_WOKEN_OTHER);

			if ((i = ((i + 1 == global.nbthread) ? 0 : i + 1)) == tid)
				break;
		}
remove:
		eb32_delete(&srv->idle_node);

		if (srv->curr_idle_conns) {
			/* There are still more idle connections, add the
			 * server back in the tree.
			 */
			srv->idle_node.key = tick_add(srv->pool_purge_delay, now_ms);
			eb32_insert(&idle_conn_srv, &srv->idle_node);
			next_wakeup = tick_first(next_wakeup, srv->idle_node.key);
		}
	}
	HA_SPIN_UNLOCK(OTHER_LOCK, &idle_conn_srv_lock);

	task->expire = next_wakeup;
	return task;
}

/* Close remaining idle connections. This functions is designed to be run on
 * process shutdown. This guarantees a proper socket shutdown to avoid
 * TIME_WAIT state. For a quick operation, only ctrl is closed, xprt stack is
 * bypassed.
 *
 * This function is not thread-safe so it must only be called via a global
 * deinit function.
 */
static void srv_close_idle_conns(struct server *srv)
{
	struct eb_root **cleaned_tree;
	int i;

	for (i = 0; i < global.nbthread; ++i) {
		struct eb_root *conn_trees[] = {
			&srv->per_thr[i].idle_conns,
			&srv->per_thr[i].safe_conns,
			&srv->per_thr[i].avail_conns,
			NULL
		};

		for (cleaned_tree = conn_trees; *cleaned_tree; ++cleaned_tree) {
			while (!eb_is_empty(*cleaned_tree)) {
				struct ebmb_node *node = ebmb_first(*cleaned_tree);
				struct conn_hash_node *conn_hash_node = ebmb_entry(node, struct conn_hash_node, node);
				struct connection *conn = conn_hash_node->conn;

				if (conn->ctrl->ctrl_close)
					conn->ctrl->ctrl_close(conn);
				ebmb_delete(node);
			}
		}
	}
}

REGISTER_SERVER_DEINIT(srv_close_idle_conns);

/* config parser for global "tune.idle-pool.shared", accepts "on" or "off" */
static int cfg_parse_idle_pool_shared(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.options |= GTUNE_IDLE_POOL_SHARED;
	else if (strcmp(args[1], "off") == 0)
		global.tune.options &= ~GTUNE_IDLE_POOL_SHARED;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.pool-{low,high}-fd-ratio" */
static int cfg_parse_pool_fd_ratio(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	int arg = -1;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) != 0)
		arg = atoi(args[1]);

	if (arg < 0 || arg > 100) {
		memprintf(err, "'%s' expects an integer argument between 0 and 100.", args[0]);
		return -1;
	}

	if (args[0][10] == 'h')
		global.tune.pool_high_ratio = arg;
	else
		global.tune.pool_low_ratio = arg;
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.idle-pool.shared",       cfg_parse_idle_pool_shared },
	{ CFG_GLOBAL, "tune.pool-high-fd-ratio",     cfg_parse_pool_fd_ratio },
	{ CFG_GLOBAL, "tune.pool-low-fd-ratio",      cfg_parse_pool_fd_ratio },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
