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

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <import/eb32tree.h>
#include <import/ebistree.h>

#include <haproxy/acl.h>
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/capture-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/filters.h>
#include <haproxy/global.h>
#include <haproxy/guid.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_ext.h>
#include <haproxy/http_rules.h>
#include <haproxy/mailers.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/peers.h>
#include <haproxy/pool.h>
#include <haproxy/protocol.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/proxy.h>
#include <haproxy/sc_strm.h>
#include <haproxy/quic_tp.h>
#include <haproxy/server-t.h>
#include <haproxy/signal.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth.h>


int listeners;	/* # of proxy listeners, set by cfgparse */
struct proxy *proxies_list  = NULL;	/* list of all existing proxies */
struct eb_root used_proxy_id = EB_ROOT;	/* list of proxy IDs in use */
struct eb_root proxy_by_name = EB_ROOT; /* tree of proxies sorted by name */
struct eb_root defproxy_by_name = EB_ROOT; /* tree of default proxies sorted by name (dups possible) */
struct proxy *orphaned_default_proxies = NULL; /* deleted ones with refcount != 0 */
unsigned int error_snapshot_id = 0;     /* global ID assigned to each error then incremented */

/* CLI context used during "show servers {state|conn}" */
struct show_srv_ctx {
	struct proxy *px;       /* current proxy to dump or NULL */
	struct server *sv;      /* current server to dump or NULL */
	uint only_pxid;         /* dump only this proxy ID when explicit */
	int show_conn;          /* non-zero = "conn" otherwise "state" */
	enum {
		SHOW_SRV_HEAD = 0,
		SHOW_SRV_LIST,
	} state;
};

/* proxy->options */
const struct cfg_opt cfg_opts[] =
{
	{ "abortonclose", PR_O_ABRT_CLOSE, PR_CAP_BE, 0, 0 },
	{ "allbackups",   PR_O_USE_ALL_BK, PR_CAP_BE, 0, 0 },
	{ "checkcache",   PR_O_CHK_CACHE,  PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "clitcpka",     PR_O_TCP_CLI_KA, PR_CAP_FE, 0, 0 },
	{ "contstats",    PR_O_CONTSTATS,  PR_CAP_FE, 0, 0 },
	{ "dontlognull",  PR_O_NULLNOLOG,  PR_CAP_FE, 0, 0 },
	{ "http-buffer-request", PR_O_WREQ_BODY,  PR_CAP_FE | PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "http-ignore-probes", PR_O_IGNORE_PRB, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ "idle-close-on-response", PR_O_IDLE_CLOSE_RESP, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ "prefer-last-server", PR_O_PREF_LAST,  PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "logasap",      PR_O_LOGASAP,    PR_CAP_FE, 0, 0 },
	{ "nolinger",     PR_O_TCP_NOLING, PR_CAP_FE | PR_CAP_BE, 0, 0 },
	{ "persist",      PR_O_PERSIST,    PR_CAP_BE, 0, 0 },
	{ "srvtcpka",     PR_O_TCP_SRV_KA, PR_CAP_BE, 0, 0 },
#ifdef USE_TPROXY
	{ "transparent",  PR_O_TRANSP,     PR_CAP_BE, 0, 0 },
#else
	{ "transparent",  0, 0, 0, 0 },
#endif

	{ NULL, 0, 0, 0, 0 }
};

/* proxy->options2 */
const struct cfg_opt cfg_opts2[] =
{
#ifdef USE_LINUX_SPLICE
	{ "splice-request",  PR_O2_SPLIC_REQ, PR_CAP_FE|PR_CAP_BE, 0, 0 },
	{ "splice-response", PR_O2_SPLIC_RTR, PR_CAP_FE|PR_CAP_BE, 0, 0 },
	{ "splice-auto",     PR_O2_SPLIC_AUT, PR_CAP_FE|PR_CAP_BE, 0, 0 },
#else
        { "splice-request",  0, 0, 0, 0 },
        { "splice-response", 0, 0, 0, 0 },
        { "splice-auto",     0, 0, 0, 0 },
#endif
	{ "accept-unsafe-violations-in-http-request",  PR_O2_REQBUG_OK, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ "accept-unsafe-violations-in-http-response", PR_O2_RSPBUG_OK, PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "dontlog-normal",               PR_O2_NOLOGNORM, PR_CAP_FE, 0, 0 },
	{ "log-separate-errors",          PR_O2_LOGERRORS, PR_CAP_FE, 0, 0 },
	{ "log-health-checks",            PR_O2_LOGHCHKS,  PR_CAP_BE, 0, 0 },
	{ "socket-stats",                 PR_O2_SOCKSTAT,  PR_CAP_FE, 0, 0 },
	{ "tcp-smart-accept",             PR_O2_SMARTACC,  PR_CAP_FE, 0, 0 },
	{ "tcp-smart-connect",            PR_O2_SMARTCON,  PR_CAP_BE, 0, 0 },
	{ "independent-streams",          PR_O2_INDEPSTR,  PR_CAP_FE|PR_CAP_BE, 0, 0 },
	{ "http-use-proxy-header",        PR_O2_USE_PXHDR, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ "http-pretend-keepalive",       PR_O2_FAKE_KA,   PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "http-no-delay",                PR_O2_NODELAY,   PR_CAP_FE|PR_CAP_BE, 0, PR_MODE_HTTP },

	{"h1-case-adjust-bogus-client",   PR_O2_H1_ADJ_BUGCLI, PR_CAP_FE, 0, 0 },
	{"h1-case-adjust-bogus-server",   PR_O2_H1_ADJ_BUGSRV, PR_CAP_BE, 0, 0 },
	{"disable-h2-upgrade",            PR_O2_NO_H2_UPGRADE, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ NULL, 0, 0, 0 }
};

/* Helper function to resolve a single sticking rule after config parsing.
 * Returns 1 for success and 0 for failure
 */
int resolve_stick_rule(struct proxy *curproxy, struct sticking_rule *mrule)
{
	struct stktable *target;

	if (mrule->table.name)
		target = stktable_find_by_name(mrule->table.name);
	else
		target = curproxy->table;

	if (!target) {
		ha_alert("Proxy '%s': unable to find stick-table '%s'.\n",
		         curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
		return 0;
	}
	else if (!stktable_compatible_sample(mrule->expr, target->type)) {
		ha_alert("Proxy '%s': type of fetch not usable with type of stick-table '%s'.\n",
		         curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
		return 0;
	}

	/* success */
	ha_free(&mrule->table.name);
	mrule->table.t = target;
	stktable_alloc_data_type(target, STKTABLE_DT_SERVER_ID, NULL, NULL);
	stktable_alloc_data_type(target, STKTABLE_DT_SERVER_KEY, NULL, NULL);
	if (!in_proxies_list(target->proxies_list, curproxy)) {
		curproxy->next_stkt_ref = target->proxies_list;
		target->proxies_list = curproxy;
	}
	return 1;
}

void free_stick_rules(struct list *rules)
{
	struct sticking_rule *rule, *ruleb;

	list_for_each_entry_safe(rule, ruleb, rules, list) {
		LIST_DELETE(&rule->list);
		free_acl_cond(rule->cond);
		release_sample_expr(rule->expr);
		free(rule);
	}
}

void free_server_rules(struct list *srules)
{
	struct server_rule *srule, *sruleb;

	list_for_each_entry_safe(srule, sruleb, srules, list) {
		LIST_DELETE(&srule->list);
		free_acl_cond(srule->cond);
		lf_expr_deinit(&srule->expr);
		free(srule->file);
		free(srule);
	}
}

/* Frees proxy members that are common to all proxy types (either regular or
 * default ones) for a proxy that's about to be destroyed.
 * This is a subset of the complete proxy or default proxy deinit code.
 */
static inline void proxy_free_common(struct proxy *px)
{
	struct acl *acl, *aclb;
	struct logger *log, *logb;
	struct lf_expr *lf, *lfb;
	struct eb32_node *node;

	ha_free(&px->id);
	drop_file_name(&px->conf.file);
	ha_free(&px->check_command);
	ha_free(&px->check_path);
	ha_free(&px->cookie_name);
	ha_free(&px->rdp_cookie_name);
	ha_free(&px->dyncookie_key);
	ha_free(&px->cookie_domain);
	ha_free(&px->cookie_attrs);
	ha_free(&px->lbprm.arg_str);
	ha_free(&px->capture_name);
	istfree(&px->monitor_uri);
	ha_free(&px->conn_src.iface_name);
#if defined(CONFIG_HAP_TRANSPARENT)
	ha_free(&px->conn_src.bind_hdr_name);
#endif
	istfree(&px->server_id_hdr_name);
	istfree(&px->header_unique_id);

	http_ext_clean(px);

	list_for_each_entry_safe(acl, aclb, &px->acl, list) {
		LIST_DELETE(&acl->list);
		prune_acl(acl);
		free(acl);
	}

	free_act_rules(&px->tcp_req.inspect_rules);
	free_act_rules(&px->tcp_rep.inspect_rules);
	free_act_rules(&px->tcp_req.l4_rules);
	free_act_rules(&px->tcp_req.l5_rules);
	free_act_rules(&px->http_req_rules);
	free_act_rules(&px->http_res_rules);
	free_act_rules(&px->http_after_res_rules);
#ifdef USE_QUIC
	free_act_rules(&px->quic_init_rules);
#endif

	lf_expr_deinit(&px->logformat);
	lf_expr_deinit(&px->logformat_sd);
	lf_expr_deinit(&px->logformat_error);
	lf_expr_deinit(&px->format_unique_id);

	list_for_each_entry_safe(log, logb, &px->loggers, list) {
		LIST_DEL_INIT(&log->list);
		free_logger(log);
	}

	/* ensure that remaining lf_expr that were not postchecked (ie: disabled
	 * proxy) don't keep a reference on the proxy which is about to be freed.
	 */
	list_for_each_entry_safe(lf, lfb, &px->conf.lf_checks, list)
		LIST_DEL_INIT(&lf->list);

	chunk_destroy(&px->log_tag);

	node = eb32_first(&px->conf.log_steps);
	while (node) {
		struct eb32_node *prev_node = node;

		/* log steps directly use the node key as id, they are not encapsulated */
		node = eb32_next(node);
		eb32_delete(prev_node);
		free(prev_node);
	}

	free_email_alert(px);
	stats_uri_auth_drop(px->uri_auth);
	px->uri_auth = NULL;
}

void free_proxy(struct proxy *p)
{
	struct server *s;
	struct cap_hdr *h,*h_next;
	struct listener *l,*l_next;
	struct bind_conf *bind_conf, *bind_back;
	struct acl_cond *cond, *condb;
	struct switching_rule *rule, *ruleb;
	struct redirect_rule *rdr, *rdrb;
	struct proxy_deinit_fct *pxdf;
	struct server_deinit_fct *srvdf;

	if (!p)
		return;

	proxy_free_common(p);

	/* regular proxy specific cleanup */
	release_sample_expr(p->lbprm.expr);
	free(p->server_state_file_name);
	free(p->invalid_rep);
	free(p->invalid_req);
	if ((p->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_MAP)
		free(p->lbprm.map.srv);

	list_for_each_entry_safe(cond, condb, &p->mon_fail_cond, list) {
		LIST_DELETE(&cond->list);
		free_acl_cond(cond);
	}

	guid_remove(&p->guid);

	EXTRA_COUNTERS_FREE(p->extra_counters_fe);
	EXTRA_COUNTERS_FREE(p->extra_counters_be);

	free_server_rules(&p->server_rules);

	list_for_each_entry_safe(rule, ruleb, &p->switching_rules, list) {
		LIST_DELETE(&rule->list);
		free_acl_cond(rule->cond);
		if (rule->dynamic)
			lf_expr_deinit(&rule->be.expr);
		free(rule->file);
		free(rule);
	}

	list_for_each_entry_safe(rdr, rdrb, &p->redirect_rules, list) {
		LIST_DELETE(&rdr->list);
		http_free_redirect_rule(rdr);
	}

	free_stick_rules(&p->storersp_rules);
	free_stick_rules(&p->sticking_rules);

	h = p->req_cap;
	while (h) {
		if (p->defpx && h == p->defpx->req_cap)
			break;
		h_next = h->next;
		free(h->name);
		pool_destroy(h->pool);
		free(h);
		h = h_next;
	}/* end while(h) */

	h = p->rsp_cap;
	while (h) {
		if (p->defpx && h == p->defpx->rsp_cap)
			break;
		h_next = h->next;
		free(h->name);
		pool_destroy(h->pool);
		free(h);
		h = h_next;
	}/* end while(h) */

	s = p->srv;
	while (s) {
		list_for_each_entry(srvdf, &server_deinit_list, list)
			srvdf->fct(s);
		s = srv_drop(s);
	}/* end while(s) */

	/* also free default-server parameters since some of them might have
	 * been dynamically allocated (e.g.: config hints, cookies, ssl..)
	 */
	srv_free_params(&p->defsrv);

	list_for_each_entry_safe(l, l_next, &p->conf.listeners, by_fe) {
		guid_remove(&l->guid);
		LIST_DELETE(&l->by_fe);
		LIST_DELETE(&l->by_bind);
		free(l->name);
		free(l->per_thr);
		free(l->counters);
		task_destroy(l->rx.rhttp.task);

		EXTRA_COUNTERS_FREE(l->extra_counters);
		free(l);
	}

	/* Release unused SSL configs. */
	list_for_each_entry_safe(bind_conf, bind_back, &p->conf.bind, by_fe) {
		if (bind_conf->xprt->destroy_bind_conf)
			bind_conf->xprt->destroy_bind_conf(bind_conf);
		free(bind_conf->file);
		free(bind_conf->arg);
		free(bind_conf->settings.interface);
		LIST_DELETE(&bind_conf->by_fe);
		free(bind_conf->guid_prefix);
		free(bind_conf->rhttp_srvname);
#ifdef USE_QUIC
		free(bind_conf->quic_cc_algo);
#endif
		free(bind_conf);
	}

	flt_deinit(p);

	list_for_each_entry(pxdf, &proxy_deinit_list, list)
		pxdf->fct(p);

	free(p->desc);

	task_destroy(p->task);

	pool_destroy(p->req_cap_pool);
	pool_destroy(p->rsp_cap_pool);

	stktable_deinit(p->table);
	ha_free(&p->table);
	ha_free(&p->per_tgrp);

	HA_RWLOCK_DESTROY(&p->lbprm.lock);
	HA_RWLOCK_DESTROY(&p->lock);

	proxy_unref_defaults(p);
	ha_free(&p);
}

/*
 * This function returns a string containing a name describing capabilities to
 * report comprehensible error messages. Specifically, it will return the words
 * "frontend", "backend" when appropriate, "defaults" if it corresponds to a
 * defaults section, or "proxy" for all other cases including the proxies
 * declared in "listen" mode.
 */
const char *proxy_cap_str(int cap)
{
	if (cap & PR_CAP_DEF)
		return "defaults";

	if ((cap & PR_CAP_LISTEN) != PR_CAP_LISTEN) {
		if (cap & PR_CAP_FE)
			return "frontend";
		else if (cap & PR_CAP_BE)
			return "backend";
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
	else if (mode == PR_MODE_CLI)
		return "cli";
	else if (mode == PR_MODE_SYSLOG)
		return "syslog";
	else if (mode == PR_MODE_PEERS)
		return "peers";
	else if (mode == PR_MODE_SPOP)
		return "spop";
	else
		return "unknown";
}

/* try to find among known options the one that looks closest to <word> by
 * counting transitions between letters, digits and other characters. Will
 * return the best matching word if found, otherwise NULL. An optional array
 * of extra words to compare may be passed in <extra>, but it must then be
 * terminated by a NULL entry. If unused it may be NULL.
 */
const char *proxy_find_best_option(const char *word, const char **extra)
{
	uint8_t word_sig[1024];
	uint8_t list_sig[1024];
	const char *best_ptr = NULL;
	int dist, best_dist = INT_MAX;
	int index;

	make_word_fingerprint(word_sig, word);

	for (index = 0; cfg_opts[index].name; index++) {
		make_word_fingerprint(list_sig, cfg_opts[index].name);
		dist = word_fingerprint_distance(word_sig, list_sig);
		if (dist < best_dist) {
			best_dist = dist;
			best_ptr = cfg_opts[index].name;
		}
	}

	for (index = 0; cfg_opts2[index].name; index++) {
		make_word_fingerprint(list_sig, cfg_opts2[index].name);
		dist = word_fingerprint_distance(word_sig, list_sig);
		if (dist < best_dist) {
			best_dist = dist;
			best_ptr = cfg_opts2[index].name;
		}
	}

	while (extra && *extra) {
		make_word_fingerprint(list_sig, *extra);
		dist = word_fingerprint_distance(word_sig, list_sig);
		if (dist < best_dist) {
			best_dist = dist;
			best_ptr = *extra;
		}
		extra++;
	}

	if (best_dist > 2 * strlen(word) || (best_ptr && best_dist > 2 * strlen(best_ptr)))
		best_ptr = NULL;
	return best_ptr;
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
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	unsigned timeout;
	int retval, cap;
	const char *res, *name;
	int *tv = NULL;
	const int *td = NULL;

	retval = 0;

	/* simply skip "timeout" but remain compatible with old form */
	if (strcmp(args[0], "timeout") == 0)
		args++;

	name = args[0];
	if (strcmp(args[0], "client") == 0) {
		name = "client";
		tv = &proxy->timeout.client;
		td = &defpx->timeout.client;
		cap = PR_CAP_FE;
	} else if (strcmp(args[0], "tarpit") == 0) {
		tv = &proxy->timeout.tarpit;
		td = &defpx->timeout.tarpit;
		cap = PR_CAP_FE | PR_CAP_BE;
	} else if (strcmp(args[0], "client-hs") == 0) {
		tv = &proxy->timeout.client_hs;
		td = &defpx->timeout.client_hs;
		cap = PR_CAP_FE;
	} else if (strcmp(args[0], "http-keep-alive") == 0) {
		tv = &proxy->timeout.httpka;
		td = &defpx->timeout.httpka;
		cap = PR_CAP_FE | PR_CAP_BE;
	} else if (strcmp(args[0], "http-request") == 0) {
		tv = &proxy->timeout.httpreq;
		td = &defpx->timeout.httpreq;
		cap = PR_CAP_FE | PR_CAP_BE;
	} else if (strcmp(args[0], "server") == 0) {
		name = "server";
		tv = &proxy->timeout.server;
		td = &defpx->timeout.server;
		cap = PR_CAP_BE;
	} else if (strcmp(args[0], "connect") == 0) {
		name = "connect";
		tv = &proxy->timeout.connect;
		td = &defpx->timeout.connect;
		cap = PR_CAP_BE;
	} else if (strcmp(args[0], "check") == 0) {
		tv = &proxy->timeout.check;
		td = &defpx->timeout.check;
		cap = PR_CAP_BE;
	} else if (strcmp(args[0], "queue") == 0) {
		tv = &proxy->timeout.queue;
		td = &defpx->timeout.queue;
		cap = PR_CAP_BE;
	} else if (strcmp(args[0], "tunnel") == 0) {
		tv = &proxy->timeout.tunnel;
		td = &defpx->timeout.tunnel;
		cap = PR_CAP_BE;
	} else if (strcmp(args[0], "client-fin") == 0) {
		tv = &proxy->timeout.clientfin;
		td = &defpx->timeout.clientfin;
		cap = PR_CAP_FE;
	} else if (strcmp(args[0], "server-fin") == 0) {
		tv = &proxy->timeout.serverfin;
		td = &defpx->timeout.serverfin;
		cap = PR_CAP_BE;
	} else if (strcmp(args[0], "clitimeout") == 0) {
		memprintf(err, "the '%s' directive is not supported anymore since HAProxy 2.1. Use 'timeout client'.", args[0]);
		return -1;
	} else if (strcmp(args[0], "srvtimeout") == 0) {
		memprintf(err, "the '%s' directive is not supported anymore since HAProxy 2.1. Use 'timeout server'.", args[0]);
		return -1;
	} else if (strcmp(args[0], "contimeout") == 0) {
		memprintf(err, "the '%s' directive is not supported anymore since HAProxy 2.1. Use 'timeout connect'.", args[0]);
		return -1;
	} else {
		memprintf(err,
		          "'timeout' supports 'client', 'server', 'connect', 'check', "
		          "'queue', 'handshake', 'http-keep-alive', 'http-request', 'tunnel', 'tarpit', "
			  "'client-fin' and 'server-fin' (got '%s')",
		          args[0]);
		return -1;
	}

	if (*args[1] == 0) {
		memprintf(err, "'timeout %s' expects an integer value (in milliseconds)", name);
		return -1;
	}

	res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to 'timeout %s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], name);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to 'timeout %s' (minimum non-null value is 1 ms)",
			  args[1], name);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in 'timeout %s'", *res, name);
		return -1;
	}

	if (warn_if_lower(args[1], 100)) {
		memprintf(err, "'timeout %s %u' in %s '%s' is suspiciously small for a value in milliseconds. Please use an explicit unit ('%ums') if that was the intent.",
		          name, timeout, proxy_type_str(proxy), proxy->id, timeout);
		retval = 1;
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
                                  const struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	int retval;
	char *res;
	unsigned int *tv = NULL;
	const unsigned int *td = NULL;
	unsigned int val;

	retval = 0;

	if (strcmp(args[1], "sessions") == 0) {
		tv = &proxy->fe_sps_lim;
		td = &defpx->fe_sps_lim;
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

	if (!(proxy->cap & PR_CAP_FE)) {
		memprintf(err, "%s %s will be ignored because %s '%s' has no frontend capability",
			  args[0], args[1], proxy_type_str(proxy), proxy->id);
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
                                    const struct proxy *defpx, const char *file, int line,
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

/* This function parses a "declare" statement in a proxy section. It returns -1
 * if there is any error, 1 for warning, otherwise 0. If it does not return zero,
 * it will write an error or warning message into a preallocated buffer returned
 * at <err>. The function must be called with <args> pointing to the first command
 * line word, with <proxy> pointing to the proxy being parsed, and <defpx> to the
 * default proxy or NULL.
 */
static int proxy_parse_declare(char **args, int section, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	/* Capture keyword wannot be declared in a default proxy. */
	if (curpx == defpx) {
		memprintf(err, "'%s' not available in default section", args[0]);
		return -1;
	}

	/* Capture keyword is only available in frontend. */
	if (!(curpx->cap & PR_CAP_FE)) {
		memprintf(err, "'%s' only available in frontend or listen section", args[0]);
		return -1;
	}

	/* Check mandatory second keyword. */
	if (!args[1] || !*args[1]) {
		memprintf(err, "'%s' needs a second keyword that specify the type of declaration ('capture')", args[0]);
		return -1;
	}

	/* Actually, declare is only available for declaring capture
	 * slot, but in the future it can declare maps or variables.
	 * So, this section permits to check and switch according with
	 * the second keyword.
	 */
	if (strcmp(args[1], "capture") == 0) {
		char *error = NULL;
		long len;
		struct cap_hdr *hdr;

		/* Check the next keyword. */
		if (!args[2] || !*args[2] ||
		    (strcmp(args[2], "response") != 0 &&
		     strcmp(args[2], "request") != 0)) {
			memprintf(err, "'%s %s' requires a direction ('request' or 'response')", args[0], args[1]);
			return -1;
		}

		/* Check the 'len' keyword. */
		if (!args[3] || !*args[3] || strcmp(args[3], "len") != 0) {
			memprintf(err, "'%s %s' requires a capture length ('len')", args[0], args[1]);
			return -1;
		}

		/* Check the length value. */
		if (!args[4] || !*args[4]) {
			memprintf(err, "'%s %s': 'len' requires a numeric value that represents the "
			               "capture length",
			          args[0], args[1]);
			return -1;
		}

		/* convert the length value. */
		len = strtol(args[4], &error, 10);
		if (*error != '\0') {
			memprintf(err, "'%s %s': cannot parse the length '%s'.",
			          args[0], args[1], args[3]);
			return -1;
		}

		/* check length. */
		if (len <= 0) {
			memprintf(err, "length must be > 0");
			return -1;
		}

		/* register the capture. */
		hdr = calloc(1, sizeof(*hdr));
		if (!hdr) {
			memprintf(err, "proxy '%s': out of memory while registering a capture", curpx->id);
			return -1;
		}
		hdr->name = NULL; /* not a header capture */
		hdr->namelen = 0;
		hdr->len = len;
		hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);

		if (strcmp(args[2], "request") == 0) {
			hdr->next = curpx->req_cap;
			hdr->index = curpx->nb_req_cap++;
			curpx->req_cap = hdr;
		}
		if (strcmp(args[2], "response") == 0) {
			hdr->next = curpx->rsp_cap;
			hdr->index = curpx->nb_rsp_cap++;
			curpx->rsp_cap = hdr;
		}
		return 0;
	}
	else {
		memprintf(err, "unknown declaration type '%s' (supports 'capture')", args[1]);
		return -1;
	}
}

/* This function parses a "retry-on" statement */
static int
proxy_parse_retry_on(char **args, int section, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	int i;

	if (!(*args[1])) {
		memprintf(err, "'%s' needs at least one keyword to specify when to retry", args[0]);
		return -1;
	}
	if (!(curpx->cap & PR_CAP_BE)) {
		memprintf(err, "'%s' only available in backend or listen section", args[0]);
		return -1;
	}
	curpx->retry_type = 0;
	for (i = 1; *(args[i]); i++) {
		if (strcmp(args[i], "conn-failure") == 0)
			curpx->retry_type |= PR_RE_CONN_FAILED;
		else if (strcmp(args[i], "empty-response") == 0)
			curpx->retry_type |= PR_RE_DISCONNECTED;
		else if (strcmp(args[i], "response-timeout") == 0)
			curpx->retry_type |= PR_RE_TIMEOUT;
		else if (strcmp(args[i], "401") == 0)
			curpx->retry_type |= PR_RE_401;
		else if (strcmp(args[i], "403") == 0)
			curpx->retry_type |= PR_RE_403;
		else if (strcmp(args[i], "404") == 0)
			curpx->retry_type |= PR_RE_404;
		else if (strcmp(args[i], "408") == 0)
			curpx->retry_type |= PR_RE_408;
		else if (strcmp(args[i], "421") == 0)
			curpx->retry_type |= PR_RE_421;
		else if (strcmp(args[i], "425") == 0)
			curpx->retry_type |= PR_RE_425;
		else if (strcmp(args[i], "429") == 0)
			curpx->retry_type |= PR_RE_429;
		else if (strcmp(args[i], "500") == 0)
			curpx->retry_type |= PR_RE_500;
		else if (strcmp(args[i], "501") == 0)
			curpx->retry_type |= PR_RE_501;
		else if (strcmp(args[i], "502") == 0)
			curpx->retry_type |= PR_RE_502;
		else if (strcmp(args[i], "503") == 0)
			curpx->retry_type |= PR_RE_503;
		else if (strcmp(args[i], "504") == 0)
			curpx->retry_type |= PR_RE_504;
		else if (strcmp(args[i], "0rtt-rejected") == 0)
			curpx->retry_type |= PR_RE_EARLY_ERROR;
		else if (strcmp(args[i], "junk-response") == 0)
			curpx->retry_type |= PR_RE_JUNK_REQUEST;
		else if (!(strcmp(args[i], "all-retryable-errors")))
			curpx->retry_type |= PR_RE_CONN_FAILED | PR_RE_DISCONNECTED |
			                     PR_RE_TIMEOUT | PR_RE_500 | PR_RE_502 |
					     PR_RE_503 | PR_RE_504 | PR_RE_EARLY_ERROR |
					     PR_RE_JUNK_REQUEST;
		else if (strcmp(args[i], "none") == 0) {
			if (i != 1 || *args[i + 1]) {
				memprintf(err, "'%s' 'none' keyworld only usable alone", args[0]);
				return -1;
			}
		} else {
			memprintf(err, "'%s': unknown keyword '%s'", args[0], args[i]);
			return -1;
		}

	}


	return 0;
}

#ifdef TCP_KEEPCNT
/* This function parses "{cli|srv}tcpka-cnt" statements */
static int proxy_parse_tcpka_cnt(char **args, int section, struct proxy *proxy,
                                    const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	int retval;
	char *res;
	unsigned int tcpka_cnt;

	retval = 0;

	if (*args[1] == 0) {
		memprintf(err, "'%s' expects an integer value", args[0]);
		return -1;
	}

	tcpka_cnt = strtol(args[1], &res, 0);
	if (*res) {
		memprintf(err, "'%s' : unexpected character '%c' in integer value '%s'", args[0], *res, args[1]);
		return -1;
	}

	if (strcmp(args[0], "clitcpka-cnt") == 0) {
		if (!(proxy->cap & PR_CAP_FE)) {
			memprintf(err, "%s will be ignored because %s '%s' has no frontend capability",
			          args[0], proxy_type_str(proxy), proxy->id);
			retval = 1;
		}
		proxy->clitcpka_cnt = tcpka_cnt;
	} else if (strcmp(args[0], "srvtcpka-cnt") == 0) {
		if (!(proxy->cap & PR_CAP_BE)) {
			memprintf(err, "%s will be ignored because %s '%s' has no backend capability",
			          args[0], proxy_type_str(proxy), proxy->id);
			retval = 1;
		}
		proxy->srvtcpka_cnt = tcpka_cnt;
	} else {
		/* unreachable */
		memprintf(err, "'%s': unknown keyword", args[0]);
		return -1;
	}

	return retval;
}
#endif

#ifdef TCP_KEEPIDLE
/* This function parses "{cli|srv}tcpka-idle" statements */
static int proxy_parse_tcpka_idle(char **args, int section, struct proxy *proxy,
                                  const struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	int retval;
	const char *res;
	unsigned int tcpka_idle;

	retval = 0;

	if (*args[1] == 0) {
		memprintf(err, "'%s' expects an integer value", args[0]);
		return -1;
	}
	res = parse_time_err(args[1], &tcpka_idle, TIME_UNIT_S);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.\n", *res, args[0]);
		return -1;
	}

	if (strcmp(args[0], "clitcpka-idle") == 0) {
		if (!(proxy->cap & PR_CAP_FE)) {
			memprintf(err, "%s will be ignored because %s '%s' has no frontend capability",
			          args[0], proxy_type_str(proxy), proxy->id);
			retval = 1;
		}
		proxy->clitcpka_idle = tcpka_idle;
	} else if (strcmp(args[0], "srvtcpka-idle") == 0) {
		if (!(proxy->cap & PR_CAP_BE)) {
			memprintf(err, "%s will be ignored because %s '%s' has no backend capability",
			          args[0], proxy_type_str(proxy), proxy->id);
			retval = 1;
		}
		proxy->srvtcpka_idle = tcpka_idle;
	} else {
		/* unreachable */
		memprintf(err, "'%s': unknown keyword", args[0]);
		return -1;
	}

	return retval;
}
#endif

#ifdef TCP_KEEPINTVL
/* This function parses "{cli|srv}tcpka-intvl" statements */
static int proxy_parse_tcpka_intvl(char **args, int section, struct proxy *proxy,
		                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	int retval;
	const char *res;
	unsigned int tcpka_intvl;

	retval = 0;

	if (*args[1] == 0) {
		memprintf(err, "'%s' expects an integer value", args[0]);
		return -1;
	}
	res = parse_time_err(args[1], &tcpka_intvl, TIME_UNIT_S);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.\n", *res, args[0]);
		return -1;
	}

	if (strcmp(args[0], "clitcpka-intvl") == 0) {
		if (!(proxy->cap & PR_CAP_FE)) {
			memprintf(err, "%s will be ignored because %s '%s' has no frontend capability",
			          args[0], proxy_type_str(proxy), proxy->id);
			retval = 1;
		}
		proxy->clitcpka_intvl = tcpka_intvl;
	} else if (strcmp(args[0], "srvtcpka-intvl") == 0) {
		if (!(proxy->cap & PR_CAP_BE)) {
			memprintf(err, "%s will be ignored because %s '%s' has no backend capability",
			          args[0], proxy_type_str(proxy), proxy->id);
			retval = 1;
		}
		proxy->srvtcpka_intvl = tcpka_intvl;
	} else {
		/* unreachable */
		memprintf(err, "'%s': unknown keyword", args[0]);
		return -1;
	}

	return retval;
}
#endif

static int proxy_parse_guid(char **args, int section_type, struct proxy *curpx,
                            const struct proxy *defpx, const char *file, int line,
                            char **err)
{
	const char *guid;
	char *guid_err = NULL;

	if (curpx->cap & PR_CAP_DEF) {
		ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, line, args[0]);
		return -1;
	}

	if (!*args[1]) {
		memprintf(err, "'%s' : expects an argument", args[0]);
		return -1;
	}

	guid = args[1];
	if (guid_insert(&curpx->obj_type, guid, &guid_err)) {
		memprintf(err, "'%s': %s", args[0], guid_err);
		ha_free(&guid_err);
		return -1;
	}

	return 0;
}

/* This function inserts proxy <px> into the tree of known proxies (regular
 * ones or defaults depending on px->cap & PR_CAP_DEF). The proxy's name is
 * used as the storing key so it must already have been initialized.
 */
void proxy_store_name(struct proxy *px)
{
	struct eb_root *root = (px->cap & PR_CAP_DEF) ? &defproxy_by_name : &proxy_by_name;

	px->conf.by_name.key = px->id;
	ebis_insert(root, &px->conf.by_name);
}

/* Returns a pointer to the first proxy matching capabilities <cap> and id
 * <id>. NULL is returned if no match is found. If <table> is non-zero, it
 * only considers proxies having a table.
 */
struct proxy *proxy_find_by_id(int id, int cap, int table)
{
	struct eb32_node *n;

	for (n = eb32_lookup(&used_proxy_id, id); n; n = eb32_next(n)) {
		struct proxy *px = container_of(n, struct proxy, conf.id);

		if (px->uuid != id)
			break;

		if ((px->cap & cap) != cap)
			continue;

		if (table && (!px->table || !px->table->size))
			continue;

		return px;
	}
	return NULL;
}

/* Returns a pointer to the first proxy matching either name <name>, or id
 * <name> if <name> begins with a '#'. NULL is returned if no match is found.
 * If <table> is non-zero, it only considers proxies having a table. The search
 * is made into the regular proxies, unless <cap> has PR_CAP_DEF set in which
 * case it's searched into the defproxy tree.
 */
struct proxy *proxy_find_by_name(const char *name, int cap, int table)
{
	struct proxy *curproxy;

	if (*name == '#' && !(cap & PR_CAP_DEF)) {
		curproxy = proxy_find_by_id(atoi(name + 1), cap, table);
		if (curproxy)
			return curproxy;
	}
	else {
		struct eb_root *root;
		struct ebpt_node *node;

		root = (cap & PR_CAP_DEF) ? &defproxy_by_name : &proxy_by_name;
		for (node = ebis_lookup(root, name); node; node = ebpt_next(node)) {
			curproxy = container_of(node, struct proxy, conf.by_name);

			if (strcmp(curproxy->id, name) != 0)
				break;

			if ((curproxy->cap & cap) != cap)
				continue;

			if (table && (!curproxy->table || !curproxy->table->size))
				continue;

			return curproxy;
		}
	}
	return NULL;
}

/* Finds the best match for a proxy with capabilities <cap>, name <name> and id
 * <id>. At most one of <id> or <name> may be different provided that <cap> is
 * valid. Either <id> or <name> may be left unspecified (0). The purpose is to
 * find a proxy based on some information from a previous configuration, across
 * reloads or during information exchange between peers.
 *
 * Names are looked up first if present, then IDs are compared if present. In
 * case of an inexact match whatever is forced in the configuration has
 * precedence in the following order :
 *   - 1) forced ID (proves a renaming / change of proxy type)
 *   - 2) proxy name+type (may indicate a move if ID differs)
 *   - 3) automatic ID+type (may indicate a renaming)
 *
 * Depending on what is found, we can end up in the following situations :
 *
 *   name id cap  | possible causes
 *   -------------+-----------------
 *    --  --  --  | nothing found
 *    --  --  ok  | nothing found
 *    --  ok  --  | proxy deleted, ID points to next one
 *    --  ok  ok  | proxy renamed, or deleted with ID pointing to next one
 *    ok  --  --  | proxy deleted, but other half with same name still here (before)
 *    ok  --  ok  | proxy's ID changed (proxy moved in the config file)
 *    ok  ok  --  | proxy deleted, but other half with same name still here (after)
 *    ok  ok  ok  | perfect match
 *
 * Upon return if <diff> is not NULL, it is zeroed then filled with up to 3 bits :
 *   - PR_FBM_MISMATCH_ID        : proxy was found but ID differs
 *                                 (and ID was not zero)
 *   - PR_FBM_MISMATCH_NAME      : proxy was found by ID but name differs
 *                                 (and name was not NULL)
 *   - PR_FBM_MISMATCH_PROXYTYPE : a proxy of different type was found with
 *                                 the same name and/or id
 *
 * Only a valid proxy is returned. If capabilities do not match, NULL is
 * returned. The caller can check <diff> to report detailed warnings / errors,
 * and decide whether or not to use what was found.
 */
struct proxy *proxy_find_best_match(int cap, const char *name, int id, int *diff)
{
	struct proxy *byname;
	struct proxy *byid;

	if (!name && !id)
		return NULL;

	if (diff)
		*diff = 0;

	byname = byid = NULL;

	if (name) {
		byname = proxy_find_by_name(name, cap, 0);
		if (byname && (!id || byname->uuid == id))
			return byname;
	}

	/* remaining possibilities :
	 *   - name not set
	 *   - name set but not found
	 *   - name found, but ID doesn't match.
	 */
	if (id) {
		byid = proxy_find_by_id(id, cap, 0);
		if (byid) {
			if (byname) {
				/* id+type found, name+type found, but not all 3.
				 * ID wins only if forced, otherwise name wins.
				 */
				if (byid->options & PR_O_FORCED_ID) {
					if (diff)
						*diff |= PR_FBM_MISMATCH_NAME;
					return byid;
				}
				else {
					if (diff)
						*diff |= PR_FBM_MISMATCH_ID;
					return byname;
				}
			}

			/* remaining possibilities :
			 *   - name not set
			 *   - name set but not found
			 */
			if (name && diff)
				*diff |= PR_FBM_MISMATCH_NAME;
			return byid;
		}

		/* ID not found */
		if (byname) {
			if (diff)
				*diff |= PR_FBM_MISMATCH_ID;
			return byname;
		}
	}

	/* All remaining possibilities will lead to NULL. If we can report more
	 * detailed information to the caller about changed types and/or name,
	 * we'll do it. For example, we could detect that "listen foo" was
	 * split into "frontend foo_ft" and "backend foo_bk" if IDs are forced.
	 *   - name not set, ID not found
	 *   - name not found, ID not set
	 *   - name not found, ID not found
	 */
	if (!diff)
		return NULL;

	if (name) {
		byname = proxy_find_by_name(name, 0, 0);
		if (byname && (!id || byname->uuid == id))
			*diff |= PR_FBM_MISMATCH_PROXYTYPE;
	}

	if (id) {
		byid = proxy_find_by_id(id, 0, 0);
		if (byid) {
			if (!name)
				*diff |= PR_FBM_MISMATCH_PROXYTYPE; /* only type changed */
			else if (byid->options & PR_O_FORCED_ID)
				*diff |= PR_FBM_MISMATCH_NAME | PR_FBM_MISMATCH_PROXYTYPE; /* name and type changed */
			/* otherwise it's a different proxy that was returned */
		}
	}
	return NULL;
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
		if (strcmp(cursrv->id, name) != 0)
			continue;

		if (!target) {
			target = cursrv;
			continue;
		}

		ha_alert("Refusing to use duplicated server '%s' found in proxy: %s!\n",
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
		ha_warning("cookie will be ignored for %s '%s' (needs 'mode http').\n",
			   proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->lbprm.algo & BE_LB_NEED_HTTP) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
		ha_warning("Layer 7 hash not possible for %s '%s' (needs 'mode http'). Falling back to round robin.\n",
			   proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->logformat.str == default_http_log_format) {
		/* Note: we don't change the directive's file:line number */
		curproxy->logformat.str = default_tcp_log_format;
		ha_warning("parsing [%s:%d] : 'option httplog' not usable with %s '%s' (needs 'mode http'). Falling back to 'option tcplog'.\n",
			   curproxy->logformat.conf.file, curproxy->logformat.conf.line,
			   proxy_type_str(curproxy), curproxy->id);
	}
	else if (curproxy->logformat.str == clf_http_log_format) {
		/* Note: we don't change the directive's file:line number */
		curproxy->logformat.str = clf_tcp_log_format;
		ha_warning("parsing [%s:%d] : 'option httplog clf' not usable with %s '%s' (needs 'mode http'). Falling back to 'option tcplog clf'.\n",
			   curproxy->logformat.conf.file, curproxy->logformat.conf.line,
			   proxy_type_str(curproxy), curproxy->id);
	}
	else if (curproxy->logformat.str == default_https_log_format) {
		/* Note: we don't change the directive's file:line number */
		curproxy->logformat.str = default_tcp_log_format;
		ha_warning("parsing [%s:%d] : 'option httpslog' not usable with %s '%s' (needs 'mode http'). Falling back to 'option tcplog'.\n",
			   curproxy->logformat.conf.file, curproxy->logformat.conf.line,
			   proxy_type_str(curproxy), curproxy->id);
	}

	return 0;
}

/* This function checks that the designated proxy has no log directives
 * enabled. It will output a warning if there are, and will fix some of them.
 * It returns the number of fatal errors encountered. This should be called
 * at the end of the configuration parsing if the proxy is not in log mode.
 * The <file> argument is used to construct the error message.
 */
int proxy_cfg_ensure_no_log(struct proxy *curproxy)
{
	if (curproxy->lbprm.algo & BE_LB_NEED_LOG) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
		ha_warning("Unusable balance algorithm for %s '%s' (needs 'mode log'). Falling back to round robin.\n",
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
	LIST_INIT(&p->acl);
	LIST_INIT(&p->http_req_rules);
	LIST_INIT(&p->http_res_rules);
	LIST_INIT(&p->http_after_res_rules);
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
	LIST_INIT(&p->tcp_req.l5_rules);
#ifdef USE_QUIC
	LIST_INIT(&p->quic_init_rules);
#endif
	MT_LIST_INIT(&p->listener_queue);
	LIST_INIT(&p->loggers);
	LIST_INIT(&p->conf.bind);
	LIST_INIT(&p->conf.listeners);
	LIST_INIT(&p->conf.errors);
	LIST_INIT(&p->conf.args.list);
	LIST_INIT(&p->conf.lf_checks);
	LIST_INIT(&p->filter_configs);
	LIST_INIT(&p->tcpcheck_rules.preset_vars);

	p->defsrv.id = "default-server";
	p->conf.used_listener_id = EB_ROOT;
	p->conf.used_server_id   = EB_ROOT;
	p->used_server_addr      = EB_ROOT_UNIQUE;
	p->conf.log_steps        = EB_ROOT_UNIQUE;

	/* Timeouts are defined as -1 */
	proxy_reset_timeouts(p);
	p->tcp_rep.inspect_delay = TICK_ETERNITY;

	/* initial uuid is unassigned (-1) */
	p->uuid = -1;

	/* Default to only allow L4 retries */
	p->retry_type = PR_RE_CONN_FAILED;

	guid_init(&p->guid);

	p->extra_counters_fe = NULL;
	p->extra_counters_be = NULL;

	HA_RWLOCK_INIT(&p->lock);

	/* initialize the default settings */
	proxy_preset_defaults(p);
}

/* Initialize per-thread proxy fields */
int proxy_init_per_thr(struct proxy *px)
{
	int i;

	px->per_tgrp = calloc(global.nbtgroups, sizeof(*px->per_tgrp));
	for (i = 0; i < global.nbtgroups; i++)
		queue_init(&px->per_tgrp[i].queue, px, NULL);

	return 0;
}

/* Preset default settings onto proxy <defproxy>. */
void proxy_preset_defaults(struct proxy *defproxy)
{
	defproxy->mode = PR_MODE_TCP;
	defproxy->flags = 0;
	if (!(defproxy->cap & PR_CAP_INT)) {
		defproxy->maxconn = cfg_maxpconn;
		defproxy->conn_retries = CONN_RETRIES;
	}
	defproxy->redispatch_after = 0;
	defproxy->options = PR_O_REUSE_SAFE;
	if (defproxy->cap & PR_CAP_INT)
		defproxy->options2 |= PR_O2_INDEPSTR;
	defproxy->max_out_conns = MAX_SRV_LIST;

	srv_settings_init(&defproxy->defsrv);

	lf_expr_init(&defproxy->logformat);
	lf_expr_init(&defproxy->logformat_sd);
	lf_expr_init(&defproxy->format_unique_id);
	lf_expr_init(&defproxy->logformat_error);

	defproxy->email_alert.level = LOG_ALERT;
	defproxy->load_server_state_from_file = PR_SRV_STATE_FILE_UNSPEC;

	if (defproxy->cap & PR_CAP_INT)
		defproxy->timeout.connect = 5000;
}

/* Frees all dynamic settings allocated on a default proxy that's about to be
 * destroyed. Note that most of the fields are not even reset, so extreme care
 * is required here, and calling proxy_preset_defaults() afterwards would be
 * safer.
 */
void proxy_free_defaults(struct proxy *defproxy)
{
	struct cap_hdr *h,*h_next;

	proxy_free_common(defproxy);

	/* default proxy specific cleanup */
	ha_free((char **)&defproxy->defsrv.conf.file);
	ha_free(&defproxy->defbe.name);

	h = defproxy->req_cap;
	while (h) {
		h_next = h->next;
		free(h->name);
		pool_destroy(h->pool);
		free(h);
		h = h_next;
	}

	h = defproxy->rsp_cap;
	while (h) {
		h_next = h->next;
		free(h->name);
		pool_destroy(h->pool);
		free(h);
		h = h_next;
	}

	proxy_release_conf_errors(defproxy);
	deinit_proxy_tcpcheck(defproxy);
}

/* delete a defproxy from the tree if still in it, frees its content and its
 * storage. Nothing is done if <px> is NULL or if it doesn't have PR_CAP_DEF
 * set, allowing to pass it the direct result of a lookup function.
 */
void proxy_destroy_defaults(struct proxy *px)
{
	if (!px)
		return;
	if (!(px->cap & PR_CAP_DEF))
		return;
	BUG_ON(px->conf.refcount != 0);
	ebpt_delete(&px->conf.by_name);
	proxy_free_defaults(px);
	free(px);
}

/* delete all unreferenced default proxies. A default proxy is unreferenced if
 * its refcount is equal to zero.
 */
void proxy_destroy_all_unref_defaults()
{
	struct ebpt_node *n;
	struct proxy *px, *nx;

	n = ebpt_first(&defproxy_by_name);
	while (n) {
		px = container_of(n, struct proxy, conf.by_name);
		BUG_ON(!(px->cap & PR_CAP_DEF));
		n = ebpt_next(n);
		if (!px->conf.refcount)
			proxy_destroy_defaults(px);
	}

	px = orphaned_default_proxies;
	while (px) {
		BUG_ON(!(px->cap & PR_CAP_DEF));
		nx = px->next;
		if (!px->conf.refcount)
			proxy_destroy_defaults(px);
		px = nx;
	}
}

/* Try to destroy a defaults section, or just unreference it if still
 * refcounted. In this case it's added to the orphaned_default_proxies list
 * so that it can later be found.
 */
void proxy_unref_or_destroy_defaults(struct proxy *px)
{
	if (!px || !(px->cap & PR_CAP_DEF))
		return;

	ebpt_delete(&px->conf.by_name);
	if (px->conf.refcount) {
		/* still referenced just append it to the orphaned list */
		px->next = orphaned_default_proxies;
		orphaned_default_proxies = px;
	} else
		proxy_destroy_defaults(px);
}

/* Add a reference on the default proxy <defpx> for the proxy <px> Nothing is
 * done if <px> already references <defpx>. Otherwise, the default proxy
 * refcount is incremented by one. For now, this operation is not thread safe
 * and is perform during init stage only.
 */
void proxy_ref_defaults(struct proxy *px, struct proxy *defpx)
{
	if (px->defpx == defpx)
		return;
	BUG_ON(px->defpx != NULL);
	px->defpx = defpx;
	defpx->conf.refcount++;
}

/* proxy <px> removes its reference on its default proxy. The default proxy
 * refcount is decremented by one. If it was the last reference, the
 * corresponding default proxy is destroyed. For now this operation is not
 * thread safe and is performed during deinit staged only.
*/
void proxy_unref_defaults(struct proxy *px)
{
	if (px->defpx == NULL)
		return;
	if (!--px->defpx->conf.refcount)
		proxy_destroy_defaults(px->defpx);
	px->defpx = NULL;
}

/* Allocates a new proxy <name> of type <cap>.
 * Returns the proxy instance on success. On error, NULL is returned.
 */
struct proxy *alloc_new_proxy(const char *name, unsigned int cap, char **errmsg)
{
	uint last_change;
	struct proxy *curproxy;

	if ((curproxy = calloc(1, sizeof(*curproxy))) == NULL) {
		memprintf(errmsg, "proxy '%s': out of memory", name);
		goto fail;
	}

	init_new_proxy(curproxy);

	last_change = ns_to_sec(now_ns);
	if (cap & PR_CAP_FE)
		curproxy->fe_counters.last_change = last_change;
	if (cap & PR_CAP_BE)
		curproxy->be_counters.last_change = last_change;

	curproxy->id = strdup(name);
	curproxy->cap = cap;

	if (!(cap & PR_CAP_INT))
		proxy_store_name(curproxy);

 done:
	return curproxy;

 fail:
	/* Note: in case of fatal error here, we WILL make valgrind unhappy,
	 * but its not worth trying to unroll everything here just before
	 * quitting.
	 */
	free(curproxy);
	return NULL;
}

/* Copy the proxy settings from <defproxy> to <curproxy>.
 * Returns 0 on success.
 * Returns 1 on error. <errmsg> will be allocated with an error description.
 */
static int proxy_defproxy_cpy(struct proxy *curproxy, const struct proxy *defproxy,
                              char **errmsg)
{
	struct logger *tmplogger;
	char *tmpmsg = NULL;
	struct eb32_node *node;

	/* set default values from the specified default proxy */
	srv_settings_cpy(&curproxy->defsrv, &defproxy->defsrv, 0);

	curproxy->flags = (defproxy->flags & PR_FL_DISABLED); /* Only inherit from disabled flag */
	curproxy->options = defproxy->options;
	curproxy->options2 = defproxy->options2;
	curproxy->no_options = defproxy->no_options;
	curproxy->no_options2 = defproxy->no_options2;
	curproxy->retry_type = defproxy->retry_type;
	curproxy->tcp_req.inspect_delay = defproxy->tcp_req.inspect_delay;
	curproxy->tcp_rep.inspect_delay = defproxy->tcp_rep.inspect_delay;

	http_ext_clean(curproxy);
	http_ext_dup(defproxy, curproxy);

	if (isttest(defproxy->server_id_hdr_name))
		curproxy->server_id_hdr_name = istdup(defproxy->server_id_hdr_name);

	/* initialize error relocations */
	if (!proxy_dup_default_conf_errors(curproxy, defproxy, &tmpmsg)) {
		memprintf(errmsg, "proxy '%s' : %s", curproxy->id, tmpmsg);
		free(tmpmsg);
		return 1;
	}

	if (curproxy->cap & PR_CAP_FE) {
		curproxy->maxconn = defproxy->maxconn;
		curproxy->backlog = defproxy->backlog;
		curproxy->fe_sps_lim = defproxy->fe_sps_lim;

		curproxy->to_log = defproxy->to_log & ~LW_COOKIE & ~LW_REQHDR & ~ LW_RSPHDR;
		curproxy->max_out_conns = defproxy->max_out_conns;

		curproxy->clitcpka_cnt   = defproxy->clitcpka_cnt;
		curproxy->clitcpka_idle  = defproxy->clitcpka_idle;
		curproxy->clitcpka_intvl = defproxy->clitcpka_intvl;
	}

	if (curproxy->cap & PR_CAP_BE) {
		curproxy->lbprm.algo = defproxy->lbprm.algo;
		curproxy->lbprm.hash_balance_factor = defproxy->lbprm.hash_balance_factor;
		curproxy->fullconn = defproxy->fullconn;
		curproxy->conn_retries = defproxy->conn_retries;
		curproxy->redispatch_after = defproxy->redispatch_after;
		curproxy->max_ka_queue = defproxy->max_ka_queue;

		curproxy->tcpcheck_rules.flags = (defproxy->tcpcheck_rules.flags & ~TCPCHK_RULES_UNUSED_RS);
		curproxy->tcpcheck_rules.list  = defproxy->tcpcheck_rules.list;
		if (!LIST_ISEMPTY(&defproxy->tcpcheck_rules.preset_vars)) {
			if (!dup_tcpcheck_vars(&curproxy->tcpcheck_rules.preset_vars,
					       &defproxy->tcpcheck_rules.preset_vars)) {
				memprintf(errmsg, "proxy '%s': failed to duplicate tcpcheck preset-vars", curproxy->id);
				return 1;
			}
		}

		curproxy->ck_opts = defproxy->ck_opts;

		if (defproxy->cookie_name)
			curproxy->cookie_name = strdup(defproxy->cookie_name);
		curproxy->cookie_len = defproxy->cookie_len;

		if (defproxy->dyncookie_key)
			curproxy->dyncookie_key = strdup(defproxy->dyncookie_key);
		if (defproxy->cookie_domain)
			curproxy->cookie_domain = strdup(defproxy->cookie_domain);

		if (defproxy->cookie_maxidle)
			curproxy->cookie_maxidle = defproxy->cookie_maxidle;

		if (defproxy->cookie_maxlife)
			curproxy->cookie_maxlife = defproxy->cookie_maxlife;

		if (defproxy->rdp_cookie_name)
			curproxy->rdp_cookie_name = strdup(defproxy->rdp_cookie_name);
		curproxy->rdp_cookie_len = defproxy->rdp_cookie_len;

		if (defproxy->cookie_attrs)
			curproxy->cookie_attrs = strdup(defproxy->cookie_attrs);

		if (defproxy->lbprm.arg_str)
			curproxy->lbprm.arg_str = strdup(defproxy->lbprm.arg_str);
		curproxy->lbprm.arg_len  = defproxy->lbprm.arg_len;
		curproxy->lbprm.arg_opt1 = defproxy->lbprm.arg_opt1;
		curproxy->lbprm.arg_opt2 = defproxy->lbprm.arg_opt2;
		curproxy->lbprm.arg_opt3 = defproxy->lbprm.arg_opt3;

		if (defproxy->conn_src.iface_name)
			curproxy->conn_src.iface_name = strdup(defproxy->conn_src.iface_name);
		curproxy->conn_src.iface_len = defproxy->conn_src.iface_len;
		curproxy->conn_src.opts = defproxy->conn_src.opts;
#if defined(CONFIG_HAP_TRANSPARENT)
		curproxy->conn_src.tproxy_addr = defproxy->conn_src.tproxy_addr;
#endif
		curproxy->load_server_state_from_file = defproxy->load_server_state_from_file;

		curproxy->srvtcpka_cnt   = defproxy->srvtcpka_cnt;
		curproxy->srvtcpka_idle  = defproxy->srvtcpka_idle;
		curproxy->srvtcpka_intvl = defproxy->srvtcpka_intvl;
	}

	if (curproxy->cap & PR_CAP_FE) {
		if (defproxy->capture_name)
			curproxy->capture_name = strdup(defproxy->capture_name);
		curproxy->capture_namelen = defproxy->capture_namelen;
		curproxy->capture_len = defproxy->capture_len;

		curproxy->nb_req_cap = defproxy->nb_req_cap;
		curproxy->req_cap = defproxy->req_cap;

		curproxy->nb_rsp_cap = defproxy->nb_rsp_cap;
		curproxy->rsp_cap = defproxy->rsp_cap;
	}

	if (curproxy->cap & PR_CAP_FE) {
		curproxy->timeout.client = defproxy->timeout.client;
		curproxy->timeout.client_hs = defproxy->timeout.client_hs;
		curproxy->timeout.clientfin = defproxy->timeout.clientfin;
		curproxy->timeout.tarpit = defproxy->timeout.tarpit;
		curproxy->timeout.httpreq = defproxy->timeout.httpreq;
		curproxy->timeout.httpka = defproxy->timeout.httpka;
		if (isttest(defproxy->monitor_uri))
			curproxy->monitor_uri = istdup(defproxy->monitor_uri);
		if (defproxy->defbe.name)
			curproxy->defbe.name = strdup(defproxy->defbe.name);

		lf_expr_dup(&defproxy->logformat, &curproxy->logformat);
		lf_expr_dup(&defproxy->logformat_sd, &curproxy->logformat_sd);
		lf_expr_dup(&defproxy->logformat_error, &curproxy->logformat_error);
	}

	if (curproxy->cap & PR_CAP_BE) {
		curproxy->timeout.connect = defproxy->timeout.connect;
		curproxy->timeout.server = defproxy->timeout.server;
		curproxy->timeout.serverfin = defproxy->timeout.serverfin;
		curproxy->timeout.check = defproxy->timeout.check;
		curproxy->timeout.queue = defproxy->timeout.queue;
		curproxy->timeout.tarpit = defproxy->timeout.tarpit;
		curproxy->timeout.httpreq = defproxy->timeout.httpreq;
		curproxy->timeout.httpka = defproxy->timeout.httpka;
		curproxy->timeout.tunnel = defproxy->timeout.tunnel;
		curproxy->conn_src.source_addr = defproxy->conn_src.source_addr;
	}

	curproxy->mode = defproxy->mode;

	/* for stats */
	stats_uri_auth_drop(curproxy->uri_auth);
	stats_uri_auth_take(defproxy->uri_auth);
	curproxy->uri_auth = defproxy->uri_auth;

	/* copy default loggers to curproxy */
	list_for_each_entry(tmplogger, &defproxy->loggers, list) {
		struct logger *node = dup_logger(tmplogger);

		if (!node) {
			memprintf(errmsg, "proxy '%s': out of memory", curproxy->id);
			return 1;
		}
		LIST_APPEND(&curproxy->loggers, &node->list);
	}

	lf_expr_dup(&defproxy->format_unique_id, &curproxy->format_unique_id);

	chunk_dup(&curproxy->log_tag, &defproxy->log_tag);

	/* copy default header unique id */
	if (isttest(defproxy->header_unique_id)) {
		const struct ist copy = istdup(defproxy->header_unique_id);

		if (!isttest(copy)) {
			memprintf(errmsg, "proxy '%s': out of memory for unique-id-header", curproxy->id);
			return 1;
		}
		curproxy->header_unique_id = copy;
	}

	/* default compression options */
	if (defproxy->comp != NULL) {
		curproxy->comp = calloc(1, sizeof(*curproxy->comp));
		if (!curproxy->comp) {
			memprintf(errmsg, "proxy '%s': out of memory for default compression options", curproxy->id);
			return 1;
		}
		curproxy->comp->algos_res = defproxy->comp->algos_res;
		curproxy->comp->algo_req = defproxy->comp->algo_req;
		curproxy->comp->types_res = defproxy->comp->types_res;
		curproxy->comp->types_req = defproxy->comp->types_req;
		curproxy->comp->flags = defproxy->comp->flags;
	}

	if (defproxy->check_path)
		curproxy->check_path = strdup(defproxy->check_path);
	if (defproxy->check_command)
		curproxy->check_command = strdup(defproxy->check_command);

	BUG_ON(curproxy->email_alert.flags & PR_EMAIL_ALERT_RESOLVED);
	if (defproxy->email_alert.mailers.name)
		curproxy->email_alert.mailers.name = strdup(defproxy->email_alert.mailers.name);
	if (defproxy->email_alert.from)
		curproxy->email_alert.from = strdup(defproxy->email_alert.from);
	if (defproxy->email_alert.to)
		curproxy->email_alert.to = strdup(defproxy->email_alert.to);
	if (defproxy->email_alert.myhostname)
		curproxy->email_alert.myhostname = strdup(defproxy->email_alert.myhostname);
	curproxy->email_alert.level = defproxy->email_alert.level;
	curproxy->email_alert.flags = defproxy->email_alert.flags;

	/* defproxy is const pointer, so we need to typecast log_steps to
	 * drop the const in order to use EB tree API, please note however
	 * that the operations performed below should theorically be read-only
	 */
	node = eb32_first((struct eb_root *)&defproxy->conf.log_steps);
	while (node) {
		struct eb32_node *new_node;

		new_node = malloc(sizeof(*new_node));
		if (!new_node) {
			memprintf(errmsg, "proxy '%s': out of memory for log_steps option", curproxy->id);
			return 1;
		}

		new_node->key = node->key;
		eb32_insert(&curproxy->conf.log_steps, new_node);
		node = eb32_next(node);
	}

	return 0;
}

/* Allocates a new proxy <name> of type <cap> found at position <file:linenum>,
 * preset it from the defaults of <defproxy> and returns it. In case of error,
 * an alert is printed and NULL is returned.
 */
struct proxy *parse_new_proxy(const char *name, unsigned int cap,
                              const char *file, int linenum,
                              const struct proxy *defproxy)
{
	struct proxy *curproxy = NULL;
	char *errmsg = NULL;

	if (!(curproxy = alloc_new_proxy(name, cap, &errmsg))) {
		ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
		free(errmsg);
		return NULL;
	}

	if (defproxy) {
		if (proxy_defproxy_cpy(curproxy, defproxy, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
			free(errmsg);

			ha_free(&curproxy);
			return NULL;
		}
	}

	curproxy->conf.args.file = curproxy->conf.file = copy_file_name(file);
	curproxy->conf.args.line = curproxy->conf.line = linenum;

	return curproxy;
}

/* to be called under the proxy lock after pausing some listeners. This will
 * automatically update the p->flags flag
 */
void proxy_cond_pause(struct proxy *p)
{
	if (p->li_ready)
		return;
	p->flags |= PR_FL_PAUSED;
}

/* to be called under the proxy lock after resuming some listeners. This will
 * automatically update the p->flags flag
 */
void proxy_cond_resume(struct proxy *p)
{
	if (!p->li_ready)
		return;
	p->flags &= ~PR_FL_PAUSED;
}

/* to be called under the proxy lock after stopping some listeners. This will
 * automatically update the p->flags flag after stopping the last one, and
 * will emit a log indicating the proxy's condition. The function is idempotent
 * so that it will not emit multiple logs; a proxy will be disabled only once.
 */
void proxy_cond_disable(struct proxy *p)
{
	if (p->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
		return;

	if (p->li_ready + p->li_paused > 0)
		return;

	p->flags |= PR_FL_STOPPED;

	/* Note: syslog proxies use their own loggers so while it's somewhat OK
	 * to report them being stopped as a warning, we must not spam their log
	 * servers which are in fact production servers. For other types (CLI,
	 * peers, etc) we must not report them at all as they're not really on
	 * the data plane but on the control plane.
	 */
	if ((p->mode == PR_MODE_TCP || p->mode == PR_MODE_HTTP || p->mode == PR_MODE_SYSLOG || p->mode == PR_MODE_SPOP) && !(p->cap & PR_CAP_INT))
		ha_warning("Proxy %s stopped (cumulated conns: FE: %lld, BE: %lld).\n",
			   p->id, p->fe_counters.cum_conn, p->be_counters.cum_sess);

	if ((p->mode == PR_MODE_TCP || p->mode == PR_MODE_HTTP || p->mode == PR_MODE_SPOP) && !(p->cap & PR_CAP_INT))
		send_log(p, LOG_WARNING, "Proxy %s stopped (cumulated conns: FE: %lld, BE: %lld).\n",
			 p->id, p->fe_counters.cum_conn, p->be_counters.cum_sess);

	if (p->table && p->table->size && p->table->sync_task)
		task_wakeup(p->table->sync_task, TASK_WOKEN_MSG);

	if (p->task)
		task_wakeup(p->task, TASK_WOKEN_MSG);
}

/*
 * This is the proxy management task. It enables proxies when there are enough
 * free streams, or stops them when the table is full. It is designed to be
 * called as a task which is woken up upon stopping or when rate limiting must
 * be enforced.
 */
struct task *manage_proxy(struct task *t, void *context, unsigned int state)
{
	struct proxy *p = context;
	int next = TICK_ETERNITY;
	unsigned int wait;

	/* We should periodically try to enable listeners waiting for a
	 * global resource here.
	 */

	/* If the proxy holds a stick table, we need to purge all unused
	 * entries. These are all the ones in the table with ref_cnt == 0
	 * and all the ones in the pool used to allocate new entries. Any
	 * entry attached to an existing stream waiting for a store will
	 * be in neither list. Any entry being dumped will have ref_cnt > 0.
	 * However we protect tables that are being synced to peers.
	 */
	if (unlikely(stopping && (p->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) && p->table && p->table->current)) {

		if (!p->table->refcnt) {
			/* !table->refcnt means there
			 * is no more pending full resync
			 * to push to a new process and
			 * we are free to flush the table.
			 */
			int budget;
			int cleaned_up;

			/* We purposely enforce a budget limitation since we don't want
			 * to spend too much time purging old entries
			 *
			 * This is known to cause the watchdog to occasionnaly trigger if
			 * the table is huge and all entries become available for purge
			 * at the same time
			 *
			 * Moreover, we must also anticipate the pool_gc() call which
			 * will also be much slower if there is too much work at once
			 */
			budget = MIN(p->table->current, (1 << 15)); /* max: 32K */
			cleaned_up = stktable_trash_oldest(p->table, budget);
			if (cleaned_up) {
				/* immediately release freed memory since we are stopping */
				pool_gc(NULL);
				if (cleaned_up > (budget / 2)) {
					/* most of the budget was used to purge entries,
					 * it is very likely that there are still trashable
					 * entries in the table, reschedule a new cleanup
					 * attempt ASAP
					 */
					t->expire = TICK_ETERNITY;
					task_wakeup(t, TASK_WOKEN_RES);
					return t;
				}
			}
		}
		if (p->table->current) {
			/* some entries still remain but are not yet available
			 * for cleanup, let's recheck in one second
			 */
			next = tick_first(next, tick_add(now_ms, 1000));
		}
	}

	/* the rest below is just for frontends */
	if (!(p->cap & PR_CAP_FE))
		goto out;

	/* check the various reasons we may find to block the frontend */
	if (unlikely(p->feconn >= p->maxconn))
		goto out;

	if (p->fe_sps_lim &&
	    (wait = next_event_delay(&p->fe_counters.sess_per_sec, p->fe_sps_lim, 0))) {
		/* we're blocking because a limit was reached on the number of
		 * requests/s on the frontend. We want to re-check ASAP, which
		 * means in 1 ms before estimated expiration date, because the
		 * timer will have settled down.
		 */
		next = tick_first(next, tick_add(now_ms, wait));
		goto out;
	}

	/* The proxy is not limited so we can re-enable any waiting listener */
	dequeue_proxy_listeners(p, 0);
 out:
	t->expire = next;
	task_queue(t);
	return t;
}


static int proxy_parse_grace(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err)
{
	const char *res;

	if (!*args[1]) {
		memprintf(err, "'%s' expects <time> as argument.\n", args[0]);
		return -1;
	}
	res = parse_time_err(args[1], &global.grace_delay, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.\n", *res, args[0]);
		return -1;
	}
	return 0;
}

static int proxy_parse_hard_stop_after(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	const char *res;

	if (!*args[1]) {
		memprintf(err, "'%s' expects <time> as argument.\n", args[0]);
		return -1;
	}
	res = parse_time_err(args[1], &global.hard_stop_after, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.\n", *res, args[0]);
		return -1;
	}
	return 0;
}

static int proxy_parse_close_spread_time(char **args, int section_type, struct proxy *curpx,
					 const struct proxy *defpx, const char *file, int line,
					 char **err)
{
	const char *res;

	if (!*args[1]) {
		memprintf(err, "'%s' expects <time> as argument.\n", args[0]);
		return -1;
	}

	/* If close-spread-time is set to "infinite", disable the active connection
	 * closing during soft-stop.
	 */
	if (strcmp(args[1], "infinite") == 0) {
		global.tune.options |= GTUNE_DISABLE_ACTIVE_CLOSE;
		global.close_spread_time = TICK_ETERNITY;
		return 0;
	}

	res = parse_time_err(args[1], &global.close_spread_time, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.\n", *res, args[0]);
		return -1;
	}
	global.tune.options &= ~GTUNE_DISABLE_ACTIVE_CLOSE;

	return 0;
}

struct task *hard_stop(struct task *t, void *context, unsigned int state)
{
	struct proxy *p;
	struct stream *s;
	int thr;

	if (killed) {
		ha_warning("Some tasks resisted to hard-stop, exiting now.\n");
		send_log(NULL, LOG_WARNING, "Some tasks resisted to hard-stop, exiting now.\n");
		killed = 2;
		for (thr = 0; thr < global.nbthread; thr++)
			if (_HA_ATOMIC_LOAD(&ha_thread_info[thr].tg->threads_enabled) & ha_thread_info[thr].ltid_bit)
				wake_thread(thr);
		t->expire = TICK_ETERNITY;
		return t;
	}

	ha_warning("soft-stop running for too long, performing a hard-stop.\n");
	send_log(NULL, LOG_WARNING, "soft-stop running for too long, performing a hard-stop.\n");
	p = proxies_list;
	while (p) {
		if ((p->cap & PR_CAP_FE) && (p->feconn > 0)) {
			ha_warning("Proxy %s hard-stopped (%d remaining conns will be closed).\n",
				   p->id, p->feconn);
			send_log(p, LOG_WARNING, "Proxy %s hard-stopped (%d remaining conns will be closed).\n",
				p->id, p->feconn);
		}
		p = p->next;
	}

	thread_isolate();

	for (thr = 0; thr < global.nbthread; thr++) {
		list_for_each_entry(s, &ha_thread_ctx[thr].streams, list) {
			stream_shutdown(s, SF_ERR_KILLED);
		}
	}

	thread_release();

	killed = 1;
	t->expire = tick_add(now_ms, MS_TO_TICKS(1000));
	return t;
}

/* perform the soft-stop right now (i.e. unbind listeners) */
static void do_soft_stop_now()
{
	struct proxy *p;
	struct task *task;

	/* disable busy polling to avoid cpu eating for the new process */
	global.tune.options &= ~GTUNE_BUSY_POLLING;

	if (tick_isset(global.close_spread_time)) {
		global.close_spread_end = tick_add(now_ms, global.close_spread_time);
	}

	/* schedule a hard-stop after a delay if needed */
	if (tick_isset(global.hard_stop_after)) {
		task = task_new_anywhere();
		if (task) {
			task->process = hard_stop;
			task_schedule(task, tick_add(now_ms, global.hard_stop_after));
		}
		else {
			ha_alert("out of memory trying to allocate the hard-stop task.\n");
		}
	}

	/* we isolate so that we have a chance of stopping listeners in other groups */
	thread_isolate();

	/* stop all stoppable listeners */
	protocol_stop_now();

	thread_release();

	/* Loop on proxies to stop backends */
	p = proxies_list;
	while (p) {
		HA_RWLOCK_WRLOCK(PROXY_LOCK, &p->lock);
		proxy_cond_disable(p);
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);
		p = p->next;
	}

	/* signal zero is used to broadcast the "stopping" event */
	signal_handler(0);
}

/* triggered by a soft-stop delayed with `grace` */
static struct task *grace_expired(struct task *t, void *context, unsigned int state)
{
	ha_notice("Grace period expired, proceeding with soft-stop now.\n");
	send_log(NULL, LOG_NOTICE, "Grace period expired, proceeding with soft-stop now.\n");
	do_soft_stop_now();
	task_destroy(t);
	return NULL;
}

/*
 * this function disables health-check servers so that the process will quickly be ignored
 * by load balancers.
 */
void soft_stop(void)
{
	struct task *task;

	stopping = 1;

	if (tick_isset(global.grace_delay)) {
		task = task_new_anywhere();
		if (task) {
			ha_notice("Scheduling a soft-stop in %u ms.\n", global.grace_delay);
			send_log(NULL, LOG_WARNING, "Scheduling a soft-stop in %u ms.\n", global.grace_delay);
			task->process = grace_expired;
			task_schedule(task, tick_add(now_ms, global.grace_delay));
			return;
		}
		else {
			ha_alert("out of memory trying to allocate the stop-stop task, stopping now.\n");
		}
	}

	/* no grace (or failure to enforce it): stop now */
	do_soft_stop_now();
}


/* Temporarily disables listening on all of the proxy's listeners. Upon
 * success, the proxy enters the PR_PAUSED state. The function returns 0
 * if it fails, or non-zero on success.
 * The function takes the proxy's lock so it's safe to
 * call from multiple places.
 */
int pause_proxy(struct proxy *p)
{
	struct listener *l;

	HA_RWLOCK_WRLOCK(PROXY_LOCK, &p->lock);

	if (!(p->cap & PR_CAP_FE) || (p->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) || !p->li_ready)
		goto end;

	list_for_each_entry(l, &p->conf.listeners, by_fe)
		suspend_listener(l, 1, 0);

	if (p->li_ready) {
		ha_warning("%s %s failed to enter pause mode.\n", proxy_cap_str(p->cap), p->id);
		send_log(p, LOG_WARNING, "%s %s failed to enter pause mode.\n", proxy_cap_str(p->cap), p->id);
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);
		return 0;
	}
end:
	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);
	return 1;
}

/*
 * This function completely stops a proxy and releases its listeners. It has
 * to be called when going down in order to release the ports so that another
 * process may bind to them. It must also be called on disabled proxies at the
 * end of start-up. If all listeners are closed, the proxy is set to the
 * PR_STOPPED state.
 * The function takes the proxy's lock so it's safe to
 * call from multiple places.
 */
void stop_proxy(struct proxy *p)
{
	struct listener *l;

	HA_RWLOCK_WRLOCK(PROXY_LOCK, &p->lock);

	list_for_each_entry(l, &p->conf.listeners, by_fe)
		stop_listener(l, 1, 0, 0);

	if (!(p->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) && !p->li_ready) {
		/* might be just a backend */
		p->flags |= PR_FL_STOPPED;
	}

	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);
}

/* This function resumes listening on the specified proxy. It scans all of its
 * listeners and tries to enable them all. If any of them fails, the proxy is
 * put back to the paused state. It returns 1 upon success, or zero if an error
 * is encountered.
 * The function takes the proxy's lock so it's safe to
 * call from multiple places.
 */
int resume_proxy(struct proxy *p)
{
	struct listener *l;
	int fail;

	HA_RWLOCK_WRLOCK(PROXY_LOCK, &p->lock);

	if ((p->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) || !p->li_paused)
		goto end;

	fail = 0;
	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		if (!resume_listener(l, 1, 0)) {
			int port;

			port = get_host_port(&l->rx.addr);
			if (port) {
				ha_warning("Port %d busy while trying to enable %s %s.\n",
					   port, proxy_cap_str(p->cap), p->id);
				send_log(p, LOG_WARNING, "Port %d busy while trying to enable %s %s.\n",
					 port, proxy_cap_str(p->cap), p->id);
			}
			else {
				ha_warning("Bind on socket %d busy while trying to enable %s %s.\n",
					   l->luid, proxy_cap_str(p->cap), p->id);
				send_log(p, LOG_WARNING, "Bind on socket %d busy while trying to enable %s %s.\n",
					 l->luid, proxy_cap_str(p->cap), p->id);
			}

			/* Another port might have been enabled. Let's stop everything. */
			fail = 1;
			break;
		}
	}

	if (fail) {
		HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);
		/* pause_proxy will take PROXY_LOCK */
		pause_proxy(p);
		return 0;
	}
end:
	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &p->lock);
	return 1;
}

/* Set current stream's backend to <be>. Nothing is done if the
 * stream already had a backend assigned, which is indicated by
 * s->flags & SF_BE_ASSIGNED.
 * All flags, stats and counters which need be updated are updated.
 * Returns 1 if done, 0 in case of internal error, eg: lack of resource.
 */
int stream_set_backend(struct stream *s, struct proxy *be)
{
	unsigned int req_ana;

	if (s->flags & SF_BE_ASSIGNED)
		return 1;

	if (flt_set_stream_backend(s, be) < 0)
		return 0;

	s->be = be;
	HA_ATOMIC_UPDATE_MAX(&be->be_counters.conn_max,
			     HA_ATOMIC_ADD_FETCH(&be->beconn, 1));
	proxy_inc_be_ctr(be);

	/* assign new parameters to the stream from the new backend */
	s->scb->flags &= ~SC_FL_INDEP_STR;
	if (be->options2 & PR_O2_INDEPSTR)
		s->scb->flags |= SC_FL_INDEP_STR;

	/* We want to enable the backend-specific analysers except those which
	 * were already run as part of the frontend/listener. Note that it would
	 * be more reliable to store the list of analysers that have been run,
	 * but what we do here is OK for now.
	 */
	req_ana = be->be_req_ana;
	if (!(strm_fe(s)->options & PR_O_WREQ_BODY) && be->options & PR_O_WREQ_BODY) {
		/* The backend request to parse a request body while it was not
		 * performed on the frontend, so add the corresponding analyser
		 */
		req_ana |= AN_REQ_HTTP_BODY;
	}
	if (IS_HTX_STRM(s) && strm_fe(s)->mode != PR_MODE_HTTP) {
		/* The stream was already upgraded to HTTP, so remove analysers
		 * set during the upgrade
		 */
		req_ana &= ~(AN_REQ_WAIT_HTTP|AN_REQ_HTTP_PROCESS_FE);
	}
	s->req.analysers |= req_ana & ~(strm_li(s) ? strm_li(s)->bind_conf->analysers : 0);

	if (!IS_HTX_STRM(s) && be->mode == PR_MODE_HTTP) {
		/* If we chain a TCP frontend to an HTX backend, we must upgrade
		 * the client mux */
		if (!stream_set_http_mode(s, NULL))
			return 0;
	}
	else if (IS_HTX_STRM(s) && be->mode != PR_MODE_HTTP) {
		/* If a TCP backend is assgiend to an HTX stream, return an
		 * error. It may happens for a new stream on a previously
		 * upgraded connections. */
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_INTERNAL;
		return 0;
	}
	else {
		/* If the target backend requires HTTP processing, we have to allocate
		 * the HTTP transaction if we did not have one.
		 */
		if (unlikely(!s->txn && be->http_needed && !http_create_txn(s)))
			return 0;
	}

	s->flags |= SF_BE_ASSIGNED;
	if (be->options2 & PR_O2_NODELAY) {
		s->scf->flags |= SC_FL_SND_NEVERWAIT;
		s->scb->flags |= SC_FL_SND_NEVERWAIT;
	}

	return 1;
}

/* Capture a bad request or response and archive it in the proxy's structure.
 * It is relatively protocol-agnostic so it requires that a number of elements
 * are passed :
 *  - <proxy> is the proxy where the error was detected and where the snapshot
 *    needs to be stored
 *  - <is_back> indicates that the error happened when receiving the response
 *  - <other_end> is a pointer to the proxy on the other side when known
 *  - <target> is the target of the connection, usually a server or a proxy
 *  - <sess> is the session which experienced the error
 *  - <ctx> may be NULL or should contain any info relevant to the protocol
 *  - <buf> is the buffer containing the offending data
 *  - <buf_ofs> is the position of this buffer's input data in the input
 *    stream, starting at zero. It may be passed as zero if unknown.
 *  - <buf_out> is the portion of <buf->data> which was already forwarded and
 *    which precedes the buffer's input. The buffer's input starts at
 *    buf->head + buf_out.
 *  - <err_pos> is the pointer to the faulty byte in the buffer's input.
 *  - <show> is the callback to use to display <ctx>. It may be NULL.
 */
void proxy_capture_error(struct proxy *proxy, int is_back,
			 struct proxy *other_end, enum obj_type *target,
			 const struct session *sess,
			 const struct buffer *buf, long buf_ofs,
			 unsigned int buf_out, unsigned int err_pos,
			 const union error_snapshot_ctx *ctx,
			 void (*show)(struct buffer *, const struct error_snapshot *))
{
	struct error_snapshot *es;
	unsigned int buf_len;
	int len1, len2;
	unsigned int ev_id;

	ev_id = HA_ATOMIC_FETCH_ADD(&error_snapshot_id, 1);

	buf_len = b_data(buf) - buf_out;

	es = malloc(sizeof(*es) + buf_len);
	if (!es)
		return;

	es->buf_len = buf_len;
	es->ev_id   = ev_id;

	len1 = b_size(buf) - b_peek_ofs(buf, buf_out);
	if (len1 > buf_len)
		len1 = buf_len;

	if (len1) {
		memcpy(es->buf, b_peek(buf, buf_out), len1);
		len2 = buf_len - len1;
		if (len2)
			memcpy(es->buf + len1, b_orig(buf), len2);
	}

	es->buf_err = err_pos;
	es->when    = date; // user-visible date
	es->srv     = objt_server(target);
	es->oe      = other_end;
	if (sess && objt_conn(sess->origin) && conn_get_src(__objt_conn(sess->origin)))
		es->src  = *__objt_conn(sess->origin)->src;
	else
		memset(&es->src, 0, sizeof(es->src));

	es->buf_wrap = b_wrap(buf) - b_peek(buf, buf_out);
	es->buf_out  = buf_out;
	es->buf_ofs  = buf_ofs;

	/* be sure to indicate the offset of the first IN byte */
	if (es->buf_ofs >= es->buf_len)
		es->buf_ofs -= es->buf_len;
	else
		es->buf_ofs = 0;

	/* protocol-specific part now */
	if (ctx)
		es->ctx = *ctx;
	else
		memset(&es->ctx, 0, sizeof(es->ctx));
	es->show = show;

	/* note: we still lock since we have to be certain that nobody is
	 * dumping the output while we free.
	 */
	HA_RWLOCK_WRLOCK(PROXY_LOCK, &proxy->lock);
	if (is_back) {
		es = HA_ATOMIC_XCHG(&proxy->invalid_rep, es);
	} else {
		es = HA_ATOMIC_XCHG(&proxy->invalid_req, es);
	}
	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &proxy->lock);
	ha_free(&es);
}

/* Configure all proxies which lack a maxconn setting to use the global one by
 * default. This avoids the common mistake consisting in setting maxconn only
 * in the global section and discovering the hard way that it doesn't propagate
 * through the frontends. These values are also propagated through the various
 * targeted backends, whose fullconn is finally calculated if not yet set.
 */
void proxy_adjust_all_maxconn()
{
	struct proxy *curproxy;
	struct switching_rule *swrule1, *swrule2;

	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		if (curproxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
			continue;

		if (!(curproxy->cap & PR_CAP_FE))
			continue;

		if (!curproxy->maxconn)
			curproxy->maxconn = global.maxconn;

		/* update the target backend's fullconn count : default_backend */
		if (curproxy->defbe.be)
			curproxy->defbe.be->tot_fe_maxconn += curproxy->maxconn;
		else if ((curproxy->cap & PR_CAP_LISTEN) == PR_CAP_LISTEN)
			curproxy->tot_fe_maxconn += curproxy->maxconn;

		list_for_each_entry(swrule1, &curproxy->switching_rules, list) {
			/* For each target of switching rules, we update their
			 * tot_fe_maxconn, except if a previous rule points to
			 * the same backend or to the default backend.
			 */
			if (swrule1->be.backend != curproxy->defbe.be) {
				/* note: swrule1->be.backend isn't a backend if the rule
				 * is dynamic, it's an expression instead, so it must not
				 * be dereferenced as a backend before being certain it is.
				 */
				list_for_each_entry(swrule2, &curproxy->switching_rules, list) {
					if (swrule2 == swrule1) {
						if (!swrule1->dynamic)
							swrule1->be.backend->tot_fe_maxconn += curproxy->maxconn;
						break;
					}
					else if (!swrule2->dynamic && swrule2->be.backend == swrule1->be.backend) {
						/* there are multiple refs of this backend */
						break;
					}
				}
			}
		}
	}

	/* automatically compute fullconn if not set. We must not do it in the
	 * loop above because cross-references are not yet fully resolved.
	 */
	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		if (curproxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
			continue;

		/* If <fullconn> is not set, let's set it to 10% of the sum of
		 * the possible incoming frontend's maxconns.
		 */
		if (!curproxy->fullconn && (curproxy->cap & PR_CAP_BE)) {
			/* we have the sum of the maxconns in <total>. We only
			 * keep 10% of that sum to set the default fullconn, with
			 * a hard minimum of 1 (to avoid a divide by zero).
			 */
			curproxy->fullconn = (curproxy->tot_fe_maxconn + 9) / 10;
			if (!curproxy->fullconn)
				curproxy->fullconn = 1;
		}
	}
}

/* Config keywords below */

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "grace", proxy_parse_grace },
	{ CFG_GLOBAL, "hard-stop-after", proxy_parse_hard_stop_after },
	{ CFG_GLOBAL, "close-spread-time", proxy_parse_close_spread_time },
	{ CFG_LISTEN, "timeout", proxy_parse_timeout },
	{ CFG_LISTEN, "clitimeout", proxy_parse_timeout }, /* This keyword actually fails to parse, this line remains for better error messages. */
	{ CFG_LISTEN, "contimeout", proxy_parse_timeout }, /* This keyword actually fails to parse, this line remains for better error messages. */
	{ CFG_LISTEN, "srvtimeout", proxy_parse_timeout }, /* This keyword actually fails to parse, this line remains for better error messages. */
	{ CFG_LISTEN, "rate-limit", proxy_parse_rate_limit },
	{ CFG_LISTEN, "max-keep-alive-queue", proxy_parse_max_ka_queue },
	{ CFG_LISTEN, "declare", proxy_parse_declare },
	{ CFG_LISTEN, "retry-on", proxy_parse_retry_on },
#ifdef TCP_KEEPCNT
	{ CFG_LISTEN, "clitcpka-cnt", proxy_parse_tcpka_cnt },
	{ CFG_LISTEN, "srvtcpka-cnt", proxy_parse_tcpka_cnt },
#endif
#ifdef TCP_KEEPIDLE
	{ CFG_LISTEN, "clitcpka-idle", proxy_parse_tcpka_idle },
	{ CFG_LISTEN, "srvtcpka-idle", proxy_parse_tcpka_idle },
#endif
#ifdef TCP_KEEPINTVL
	{ CFG_LISTEN, "clitcpka-intvl", proxy_parse_tcpka_intvl },
	{ CFG_LISTEN, "srvtcpka-intvl", proxy_parse_tcpka_intvl },
#endif
	{ CFG_LISTEN, "guid", proxy_parse_guid },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* Expects to find a frontend named <arg> and returns it, otherwise displays various
 * adequate error messages and returns NULL. This function is designed to be used by
 * functions requiring a frontend on the CLI.
 */
struct proxy *cli_find_frontend(struct appctx *appctx, const char *arg)
{
	struct proxy *px;

	if (!*arg) {
		cli_err(appctx, "A frontend name is expected.\n");
		return NULL;
	}

	px = proxy_fe_by_name(arg);
	if (!px) {
		cli_err(appctx, "No such frontend.\n");
		return NULL;
	}
	return px;
}

/* Expects to find a backend named <arg> and returns it, otherwise displays various
 * adequate error messages and returns NULL. This function is designed to be used by
 * functions requiring a frontend on the CLI.
 */
struct proxy *cli_find_backend(struct appctx *appctx, const char *arg)
{
	struct proxy *px;

	if (!*arg) {
		cli_err(appctx, "A backend name is expected.\n");
		return NULL;
	}

	px = proxy_be_by_name(arg);
	if (!px) {
		cli_err(appctx, "No such backend.\n");
		return NULL;
	}
	return px;
}


/* parse a "show servers [state|conn]" CLI line, returns 0 if it wants to start
 * the dump or 1 if it stops immediately. If an argument is specified, it will
 * reserve a show_srv_ctx context and set the proxy pointer into ->px, its ID
 * into ->only_pxid, and ->show_conn to 0 for "state", or 1 for "conn".
 */
static int cli_parse_show_servers(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_srv_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct proxy *px;

	ctx->show_conn = *args[2] == 'c'; // "conn" vs "state"

	/* check if a backend name has been provided */
	if (*args[3]) {
		/* read server state from local file */
		px = proxy_be_by_name(args[3]);

		if (!px)
			return cli_err(appctx, "Can't find backend.\n");

		ctx->px = px;
		ctx->only_pxid = px->uuid;
	}
	return 0;
}

/* helper to dump server addr */
static void dump_server_addr(const struct sockaddr_storage *addr, char *addr_str)
{
	addr_str[0] = '\0';
	switch (addr->ss_family) {
		case AF_INET:
		case AF_INET6:
			addr_to_str(addr, addr_str, INET6_ADDRSTRLEN + 1);
			break;
		default:
			memcpy(addr_str, "-\0", 2);
			break;
	}
}

/* dumps server state information for all the servers found in backend cli.p0.
 * These information are all the parameters which may change during HAProxy runtime.
 * By default, we only export to the last known server state file format. These
 * information can be used at next startup to recover same level of server
 * state. It takes its context from show_srv_ctx, with the proxy pointer from
 * ->px, the proxy's id ->only_pxid, the server's pointer from ->sv, and the
 * choice of what to dump from ->show_conn.
 */
static int dump_servers_state(struct appctx *appctx)
{
	struct show_srv_ctx *ctx = appctx->svcctx;
	struct proxy *px = ctx->px;
	struct server *srv;
	char srv_addr[INET6_ADDRSTRLEN + 1];
	char srv_agent_addr[INET6_ADDRSTRLEN + 1];
	char srv_check_addr[INET6_ADDRSTRLEN + 1];
	time_t srv_time_since_last_change;
	int bk_f_forced_id, srv_f_forced_id;
	char *srvrecord;

	if (!ctx->sv)
		ctx->sv = px->srv;

	for (; ctx->sv != NULL; ctx->sv = srv->next) {
		srv = ctx->sv;

		dump_server_addr(&srv->addr, srv_addr);
		dump_server_addr(&srv->check.addr, srv_check_addr);
		dump_server_addr(&srv->agent.addr, srv_agent_addr);

		srv_time_since_last_change = ns_to_sec(now_ns) - srv->counters.last_change;
		bk_f_forced_id = px->options & PR_O_FORCED_ID ? 1 : 0;
		srv_f_forced_id = srv->flags & SRV_F_FORCED_ID ? 1 : 0;

		srvrecord = NULL;
		if (srv->srvrq && srv->srvrq->name)
			srvrecord = srv->srvrq->name;

		if (ctx->show_conn == 0) {
			/* show servers state */
			chunk_printf(&trash,
			             "%d %s "
			             "%d %s %s "
			             "%d %d %d %d %ld "
			             "%d %d %d %d %d "
			             "%d %d %s %u "
				     "%s %d %d "
				     "%s %s %d"
			             "\n",
			             px->uuid, HA_ANON_CLI(px->id),
			             srv->puid, HA_ANON_CLI(srv->id),
				     hash_ipanon(appctx->cli_anon_key, srv_addr, 0),
			             srv->cur_state, srv->cur_admin, srv->uweight, srv->iweight,
				     (long int)srv_time_since_last_change,
			             srv->check.status, srv->check.result, srv->check.health,
				     srv->check.state & 0x0F, srv->agent.state & 0x1F,
			             bk_f_forced_id, srv_f_forced_id,
				     srv->hostname ? HA_ANON_CLI(srv->hostname) : "-", srv->svc_port,
			             srvrecord ? srvrecord : "-", srv->use_ssl, srv->check.port,
				     srv_check_addr, srv_agent_addr, srv->agent.port);
		} else {
			/* show servers conn */
			int thr;

			chunk_printf(&trash,
			             "%s/%s %d/%d %s %u - %u %u %u %u %u %u %d %u",
			             HA_ANON_CLI(px->id), HA_ANON_CLI(srv->id),
			             px->uuid, srv->puid, hash_ipanon(appctx->cli_anon_key, srv_addr, 0),
			             srv->svc_port, srv->pool_purge_delay,
			             srv->curr_used_conns, srv->max_used_conns, srv->est_need_conns,
			             srv->curr_idle_nb, srv->curr_safe_nb, (int)srv->max_idle_conns, srv->curr_idle_conns);

			for (thr = 0; thr < global.nbthread && srv->curr_idle_thr; thr++)
				chunk_appendf(&trash, " %u", srv->curr_idle_thr[thr]);

			chunk_appendf(&trash, "\n");
		}

		if (applet_putchk(appctx, &trash) == -1) {
			return 0;
		}
	}
	return 1;
}

/* Parses backend list or simply use backend name provided by the user to return
 * states of servers to stdout. It takes its context from show_srv_ctx and dumps
 * proxy ->px and stops if ->only_pxid is non-null.
 */
static int cli_io_handler_servers_state(struct appctx *appctx)
{
	struct show_srv_ctx *ctx = appctx->svcctx;
	struct proxy *curproxy;

	if (ctx->state == SHOW_SRV_HEAD) {
		if (ctx->show_conn == 0)
			chunk_printf(&trash, "%d\n# %s\n", SRV_STATE_FILE_VERSION, SRV_STATE_FILE_FIELD_NAMES);
		else
			chunk_printf(&trash,
			             "# bkname/svname bkid/svid addr port - purge_delay used_cur used_max need_est unsafe_nb safe_nb idle_lim idle_cur idle_per_thr[%d]\n",
			             global.nbthread);

		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		ctx->state = SHOW_SRV_LIST;

		if (!ctx->px)
			ctx->px = proxies_list;
	}

	for (; ctx->px != NULL; ctx->px = curproxy->next) {
		curproxy = ctx->px;
		/* servers are only in backends */
		if ((curproxy->cap & PR_CAP_BE) && !(curproxy->cap & PR_CAP_INT)) {
			if (!dump_servers_state(appctx))
				return 0;
		}
		/* only the selected proxy is dumped */
		if (ctx->only_pxid)
			break;
	}

	return 1;
}

/* Parses backend list and simply report backend names. It keeps the proxy
 * pointer in svcctx since there's nothing else to store there.
 */
static int cli_io_handler_show_backend(struct appctx *appctx)
{
	struct proxy *curproxy;

	chunk_reset(&trash);

	if (!appctx->svcctx) {
		chunk_printf(&trash, "# name\n");
		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		appctx->svcctx = proxies_list;
	}

	for (; appctx->svcctx != NULL; appctx->svcctx = curproxy->next) {
		curproxy = appctx->svcctx;

		/* looking for non-internal backends only */
		if ((curproxy->cap & (PR_CAP_BE|PR_CAP_INT)) != PR_CAP_BE)
			continue;

		chunk_appendf(&trash, "%s\n", curproxy->id);
		if (applet_putchk(appctx, &trash) == -1)
			return 0;
	}

	return 1;
}

/* Parses the "enable dynamic-cookies backend" directive, it always returns 1.
 *
 * Grabs the proxy lock and each server's lock.
 */
static int cli_parse_enable_dyncookie_backend(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;
	struct server *s;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	px = cli_find_backend(appctx, args[3]);
	if (!px)
		return 1;

	if (px->mode != PR_MODE_TCP && px->mode != PR_MODE_HTTP)
		return cli_err(appctx, "Not available.\n");

	/* Note: this lock is to make sure this doesn't change while another
	 * thread is in srv_set_dyncookie().
	 */
	HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);
	px->ck_opts |= PR_CK_DYNAMIC;
	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);

	for (s = px->srv; s != NULL; s = s->next) {
		HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
		srv_set_dyncookie(s);
		HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
	}

	return 1;
}

/* Parses the "disable dynamic-cookies backend" directive, it always returns 1.
 *
 * Grabs the proxy lock and each server's lock.
 */
static int cli_parse_disable_dyncookie_backend(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;
	struct server *s;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	px = cli_find_backend(appctx, args[3]);
	if (!px)
		return 1;

	if (px->mode != PR_MODE_TCP && px->mode != PR_MODE_HTTP)
		return cli_err(appctx, "Not available.\n");

	/* Note: this lock is to make sure this doesn't change while another
	 * thread is in srv_set_dyncookie().
	 */
	HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);
	px->ck_opts &= ~PR_CK_DYNAMIC;
	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);

	for (s = px->srv; s != NULL; s = s->next) {
		HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
		if (!(s->flags & SRV_F_COOKIESET))
			ha_free(&s->cookie);
		HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
	}

	return 1;
}

/* Parses the "set dynamic-cookie-key backend" directive, it always returns 1.
 *
 * Grabs the proxy lock and each server's lock.
 */
static int cli_parse_set_dyncookie_key_backend(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;
	struct server *s;
	char *newkey;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	px = cli_find_backend(appctx, args[3]);
	if (!px)
		return 1;

	if (px->mode != PR_MODE_TCP && px->mode != PR_MODE_HTTP)
		return cli_err(appctx, "Not available.\n");

	if (!*args[4])
		return cli_err(appctx, "String value expected.\n");

	newkey = strdup(args[4]);
	if (!newkey)
		return cli_err(appctx, "Failed to allocate memory.\n");

	/* Note: this lock is to make sure this doesn't change while another
	 * thread is in srv_set_dyncookie().
	 */
	HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);
	free(px->dyncookie_key);
	px->dyncookie_key = newkey;
	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);

	for (s = px->srv; s != NULL; s = s->next) {
		HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
		srv_set_dyncookie(s);
		HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
	}

	return 1;
}

/* Parses the "set maxconn frontend" directive, it always returns 1.
 *
 * Grabs the proxy lock.
 */
static int cli_parse_set_maxconn_frontend(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;
	struct listener *l;
	int v;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	px = cli_find_frontend(appctx, args[3]);
	if (!px)
		return 1;

	if (!*args[4])
		return cli_err(appctx, "Integer value expected.\n");

	v = atoi(args[4]);
	if (v < 0)
		return cli_err(appctx, "Value out of range.\n");

	/* OK, the value is fine, so we assign it to the proxy and to all of
	 * its listeners. The blocked ones will be dequeued.
	 */
	HA_RWLOCK_WRLOCK(PROXY_LOCK, &px->lock);

	px->maxconn = v;
	list_for_each_entry(l, &px->conf.listeners, by_fe) {
		if (l->state == LI_FULL)
			relax_listener(l, 1, 0);
	}

	if (px->maxconn > px->feconn)
		dequeue_proxy_listeners(px, 1);

	HA_RWLOCK_WRUNLOCK(PROXY_LOCK, &px->lock);

	return 1;
}

/* Parses the "shutdown frontend" directive, it always returns 1.
 *
 * Grabs the proxy lock.
 */
static int cli_parse_shutdown_frontend(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	px = cli_find_frontend(appctx, args[2]);
	if (!px)
		return 1;

	if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
		return cli_msg(appctx, LOG_NOTICE, "Frontend was already shut down.\n");

	stop_proxy(px);
	return 1;
}

/* Parses the "disable frontend" directive, it always returns 1.
 *
 * Grabs the proxy lock.
 */
static int cli_parse_disable_frontend(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;
	int ret;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	px = cli_find_frontend(appctx, args[2]);
	if (!px)
		return 1;

	if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
		return cli_msg(appctx, LOG_NOTICE, "Frontend was previously shut down, cannot disable.\n");

	if (!px->li_ready)
		return cli_msg(appctx, LOG_NOTICE, "All sockets are already disabled.\n");

	/* pause_proxy will take PROXY_LOCK */
	ret = pause_proxy(px);

	if (!ret)
		return cli_err(appctx, "Failed to pause frontend, check logs for precise cause.\n");

	return 1;
}

/* Parses the "enable frontend" directive, it always returns 1.
 *
 * Grabs the proxy lock.
 */
static int cli_parse_enable_frontend(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;
	int ret;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	px = cli_find_frontend(appctx, args[2]);
	if (!px)
		return 1;

	if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
		return cli_err(appctx, "Frontend was previously shut down, cannot enable.\n");

	if (px->li_ready == px->li_all)
		return cli_msg(appctx, LOG_NOTICE, "All sockets are already enabled.\n");

	/* resume_proxy will take PROXY_LOCK */
	ret = resume_proxy(px);

	if (!ret)
		return cli_err(appctx, "Failed to resume frontend, check logs for precise cause (port conflict?).\n");
	return 1;
}

/* appctx context used during "show errors" */
struct show_errors_ctx {
	struct proxy *px;	/* current proxy being dumped, NULL = not started yet. */
	unsigned int flag;	/* bit0: buffer being dumped, 0 = req, 1 = resp ; bit1=skip req ; bit2=skip resp. */
	unsigned int ev_id;	/* event ID of error being dumped */
	int iid;		/* if >= 0, ID of the proxy to filter on */
	int ptr;		/* <0: headers, >=0 : text pointer to restart from */
	int bol;		/* pointer to beginning of current line */
};

/* "show errors" handler for the CLI. Returns 0 if wants to continue, 1 to stop
 * now.
 */
static int cli_parse_show_errors(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_errors_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (*args[2]) {
		struct proxy *px;

		px = proxy_find_by_name(args[2], 0, 0);
		if (px)
			ctx->iid = px->uuid;
		else
			ctx->iid = atoi(args[2]);

		if (!ctx->iid)
			return cli_err(appctx, "No such proxy.\n");
	}
	else
		ctx->iid	= -1; // dump all proxies

	ctx->flag = 0;
	if (strcmp(args[3], "request") == 0)
		ctx->flag |= 4; // ignore response
	else if (strcmp(args[3], "response") == 0)
		ctx->flag |= 2; // ignore request
	ctx->px = NULL;
	return 0;
}

/* This function dumps all captured errors onto the stream connector's
 * read buffer. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_errors(struct appctx *appctx)
{
	struct show_errors_ctx *ctx = appctx->svcctx;
	extern const char *monthname[12];

	chunk_reset(&trash);

	if (!ctx->px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		struct tm tm;

		get_localtime(date.tv_sec, &tm);
		chunk_appendf(&trash, "Total events captured on [%02d/%s/%04d:%02d:%02d:%02d.%03d] : %u\n",
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(date.tv_usec/1000),
			     error_snapshot_id);

		if (applet_putchk(appctx, &trash) == -1)
			goto cant_send;

		ctx->px = proxies_list;
		ctx->bol = 0;
		ctx->ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (ctx->px) {
		struct error_snapshot *es;

		HA_RWLOCK_RDLOCK(PROXY_LOCK, &ctx->px->lock);

		if ((ctx->flag & 1) == 0) {
			es = ctx->px->invalid_req;
			if (ctx->flag & 2) // skip req
				goto next;
		}
		else {
			es = ctx->px->invalid_rep;
			if (ctx->flag & 4) // skip resp
				goto next;
		}

		if (!es)
			goto next;

		if (ctx->iid >= 0 &&
		    ctx->px->uuid != ctx->iid &&
		    (!es->oe || es->oe->uuid != ctx->iid))
			goto next;

		if (ctx->ptr < 0) {
			/* just print headers now */

			char pn[INET6_ADDRSTRLEN];
			struct tm tm;
			int port;

			get_localtime(es->when.tv_sec, &tm);
			chunk_appendf(&trash, " \n[%02d/%s/%04d:%02d:%02d:%02d.%03d]",
				     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
				     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(es->when.tv_usec/1000));

			switch (addr_to_str(&es->src, pn, sizeof(pn))) {
			case AF_INET:
			case AF_INET6:
				port = get_host_port(&es->src);
				break;
			default:
				port = 0;
			}

			switch (ctx->flag & 1) {
			case 0:
				chunk_appendf(&trash,
					     " frontend %s (#%d): invalid request\n"
					     "  backend %s (#%d)",
					     ctx->px->id, ctx->px->uuid,
					     (es->oe && es->oe->cap & PR_CAP_BE) ? es->oe->id : "<NONE>",
					     (es->oe && es->oe->cap & PR_CAP_BE) ? es->oe->uuid : -1);
				break;
			case 1:
				chunk_appendf(&trash,
					     " backend %s (#%d): invalid response\n"
					     "  frontend %s (#%d)",
					     ctx->px->id, ctx->px->uuid,
					     es->oe ? es->oe->id : "<NONE>" , es->oe ? es->oe->uuid : -1);
				break;
			}

			chunk_appendf(&trash,
			              ", server %s (#%d), event #%u, src %s:%d\n"
			              "  buffer starts at %llu (including %u out), %u free,\n"
			              "  len %u, wraps at %u, error at position %u\n",
			              es->srv ? es->srv->id : "<NONE>",
			              es->srv ? es->srv->puid : -1,
			              es->ev_id, pn, port,
			              es->buf_ofs, es->buf_out,
			              global.tune.bufsize - es->buf_out - es->buf_len,
			              es->buf_len, es->buf_wrap, es->buf_err);

			if (es->show)
				es->show(&trash, es);

			chunk_appendf(&trash, "  \n");

			if (applet_putchk(appctx, &trash) == -1)
				goto cant_send_unlock;

			ctx->ptr = 0;
			ctx->ev_id = es->ev_id;
		}

		if (ctx->ev_id != es->ev_id) {
			/* the snapshot changed while we were dumping it */
			chunk_appendf(&trash,
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (applet_putchk(appctx, &trash) == -1)
				goto cant_send_unlock;

			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (ctx->ptr < es->buf_len && ctx->ptr < global.tune.bufsize) {
			int newptr;
			int newline;

			newline = ctx->bol;
			newptr = dump_text_line(&trash, es->buf, global.tune.bufsize, es->buf_len, &newline, ctx->ptr);
			if (newptr == ctx->ptr) {
				applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
				goto cant_send_unlock;
			}

			if (applet_putchk(appctx, &trash) == -1)
				goto cant_send_unlock;

			ctx->ptr = newptr;
			ctx->bol = newline;
		};
	next:
		HA_RWLOCK_RDUNLOCK(PROXY_LOCK, &ctx->px->lock);
		ctx->bol = 0;
		ctx->ptr = -1;
		ctx->flag ^= 1;
		if (!(ctx->flag & 1))
			ctx->px = ctx->px->next;
	}

	/* dump complete */
	return 1;

 cant_send_unlock:
	HA_RWLOCK_RDUNLOCK(PROXY_LOCK, &ctx->px->lock);
 cant_send:
	return 0;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "disable", "frontend",  NULL },                 "disable frontend <frontend>             : temporarily disable specific frontend",                          cli_parse_disable_frontend, NULL, NULL },
	{ { "enable", "frontend",  NULL },                  "enable frontend <frontend>              : re-enable specific frontend",                                    cli_parse_enable_frontend, NULL, NULL },
	{ { "set", "maxconn", "frontend",  NULL },          "set maxconn frontend <frontend> <value> : change a frontend's maxconn setting",                            cli_parse_set_maxconn_frontend, NULL },
	{ { "show","servers", "conn",  NULL },              "show servers conn [<backend>]           : dump server connections status (all or for a single backend)",   cli_parse_show_servers, cli_io_handler_servers_state },
	{ { "show","servers", "state",  NULL },             "show servers state [<backend>]          : dump volatile server information (all or for a single backend)", cli_parse_show_servers, cli_io_handler_servers_state },
	{ { "show", "backend", NULL },                      "show backend                            : list backends in the current running config", NULL,              cli_io_handler_show_backend },
	{ { "shutdown", "frontend",  NULL },                "shutdown frontend <frontend>            : stop a specific frontend",                                       cli_parse_shutdown_frontend, NULL, NULL },
	{ { "set", "dynamic-cookie-key", "backend", NULL }, "set dynamic-cookie-key backend <bk> <k> : change a backend secret key for dynamic cookies",                cli_parse_set_dyncookie_key_backend, NULL },
	{ { "enable", "dynamic-cookie", "backend", NULL },  "enable dynamic-cookie backend <bk>      : enable dynamic cookies on a specific backend",                   cli_parse_enable_dyncookie_backend, NULL },
	{ { "disable", "dynamic-cookie", "backend", NULL }, "disable dynamic-cookie backend <bk>     : disable dynamic cookies on a specific backend",                  cli_parse_disable_dyncookie_backend, NULL },
	{ { "show", "errors", NULL },                       "show errors [<px>] [request|response]   : report last request and/or response errors for each proxy",      cli_parse_show_errors, cli_io_handler_show_errors, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
