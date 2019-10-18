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
#include <common/initcall.h>
#include <common/memory.h>
#include <common/time.h>

#include <eb32tree.h>
#include <ebistree.h>

#include <types/capture.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/obj_type.h>
#include <types/peers.h>
#include <types/stats.h>

#include <proto/applet.h>
#include <proto/cli.h>
#include <proto/backend.h>
#include <proto/fd.h>
#include <proto/filters.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/proto_tcp.h>
#include <proto/http_ana.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/signal.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>


int listeners;	/* # of proxy listeners, set by cfgparse */
struct proxy *proxies_list  = NULL;	/* list of all existing proxies */
struct eb_root used_proxy_id = EB_ROOT;	/* list of proxy IDs in use */
struct eb_root proxy_by_name = EB_ROOT; /* tree of proxies sorted by name */
unsigned int error_snapshot_id = 0;     /* global ID assigned to each error then incremented */

/* proxy->options */
const struct cfg_opt cfg_opts[] =
{
	{ "abortonclose", PR_O_ABRT_CLOSE, PR_CAP_BE, 0, 0 },
	{ "allbackups",   PR_O_USE_ALL_BK, PR_CAP_BE, 0, 0 },
	{ "checkcache",   PR_O_CHK_CACHE,  PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "clitcpka",     PR_O_TCP_CLI_KA, PR_CAP_FE, 0, 0 },
	{ "contstats",    PR_O_CONTSTATS,  PR_CAP_FE, 0, 0 },
	{ "dontlognull",  PR_O_NULLNOLOG,  PR_CAP_FE, 0, 0 },
	{ "http_proxy",	  PR_O_HTTP_PROXY, PR_CAP_FE | PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "http-buffer-request", PR_O_WREQ_BODY,  PR_CAP_FE | PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "http-ignore-probes", PR_O_IGNORE_PRB, PR_CAP_FE, 0, PR_MODE_HTTP },
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
	{ "accept-invalid-http-request",  PR_O2_REQBUG_OK, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ "accept-invalid-http-response", PR_O2_RSPBUG_OK, PR_CAP_BE, 0, PR_MODE_HTTP },
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
	{ "http-use-htx",                 0,               PR_CAP_FE|PR_CAP_BE, 0, 0 }, // deprecated

	{"h1-case-adjust-bogus-client",   PR_O2_H1_ADJ_BUGCLI, PR_CAP_FE, 0, PR_MODE_HTTP },
	{"h1-case-adjust-bogus-server",   PR_O2_H1_ADJ_BUGSRV, PR_CAP_BE, 0, PR_MODE_HTTP },
	{ NULL, 0, 0, 0 }
};

/*
 * This function returns a string containing a name describing capabilities to
 * report comprehensible error messages. Specifically, it will return the words
 * "frontend", "backend" when appropriate, or "proxy" for all other
 * cases including the proxies declared in "listen" mode.
 */
const char *proxy_cap_str(int cap)
{
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
	else if (mode == PR_MODE_HEALTH)
		return "health";
	else if (mode == PR_MODE_CLI)
		return "cli";
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

	p = proxy_be_by_name(bk_name);
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

	retval = 0;

	/* simply skip "timeout" but remain compatible with old form */
	if (strcmp(args[0], "timeout") == 0)
		args++;

	name = args[0];
	if (!strcmp(args[0], "client")) {
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
	} else if (!strcmp(args[0], "server")) {
		name = "server";
		tv = &proxy->timeout.server;
		td = &defpx->timeout.server;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "connect")) {
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
	} else if (!strcmp(args[0], "clitimeout")) {
		memprintf(err, "the '%s' directive is not supported anymore since HAProxy 2.1. Use 'timeout client'.", args[0]);
		return -1;
	} else if (!strcmp(args[0], "srvtimeout")) {
		memprintf(err, "the '%s' directive is not supported anymore since HAProxy 2.1. Use 'timeout server'.", args[0]);
		return -1;
	} else if (!strcmp(args[0], "contimeout")) {
		memprintf(err, "the '%s' directive is not supported anymore since HAProxy 2.1. Use 'timeout connect'.", args[0]);
		return -1;
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

/* This function parses a "declare" statement in a proxy section. It returns -1
 * if there is any error, 1 for warning, otherwise 0. If it does not return zero,
 * it will write an error or warning message into a preallocated buffer returned
 * at <err>. The function must be called with <args> pointing to the first command
 * line word, with <proxy> pointing to the proxy being parsed, and <defpx> to the
 * default proxy or NULL.
 */
static int proxy_parse_declare(char **args, int section, struct proxy *curpx,
                               struct proxy *defpx, const char *file, int line,
                               char **err)
{
	/* Capture keyword wannot be declared in a default proxy. */
	if (curpx == defpx) {
		memprintf(err, "'%s' not available in default section", args[0]);
		return -1;
	}

	/* Capture keywork is only available in frontend. */
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
                               struct proxy *defpx, const char *file, int line,
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
		if (!strcmp(args[i], "conn-failure"))
			curpx->retry_type |= PR_RE_CONN_FAILED;
		else if (!strcmp(args[i], "empty-response"))
			curpx->retry_type |= PR_RE_DISCONNECTED;
		else if (!strcmp(args[i], "response-timeout"))
			curpx->retry_type |= PR_RE_TIMEOUT;
		else if (!strcmp(args[i], "404"))
			curpx->retry_type |= PR_RE_404;
		else if (!strcmp(args[i], "408"))
			curpx->retry_type |= PR_RE_408;
		else if (!strcmp(args[i], "425"))
			curpx->retry_type |= PR_RE_425;
		else if (!strcmp(args[i], "500"))
			curpx->retry_type |= PR_RE_500;
		else if (!strcmp(args[i], "501"))
			curpx->retry_type |= PR_RE_501;
		else if (!strcmp(args[i], "502"))
			curpx->retry_type |= PR_RE_502;
		else if (!strcmp(args[i], "503"))
			curpx->retry_type |= PR_RE_503;
		else if (!strcmp(args[i], "504"))
			curpx->retry_type |= PR_RE_504;
		else if (!strcmp(args[i], "0rtt-rejected"))
			curpx->retry_type |= PR_RE_EARLY_ERROR;
		else if (!strcmp(args[i], "junk-response"))
			curpx->retry_type |= PR_RE_JUNK_REQUEST;
		else if (!(strcmp(args[i], "all-retryable-errors")))
			curpx->retry_type |= PR_RE_CONN_FAILED | PR_RE_DISCONNECTED |
			                     PR_RE_TIMEOUT | PR_RE_500 | PR_RE_502 |
					     PR_RE_503 | PR_RE_504 | PR_RE_EARLY_ERROR |
					     PR_RE_JUNK_REQUEST;
		else if (!strcmp(args[i], "none")) {
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

/* This function inserts proxy <px> into the tree of known proxies. The proxy's
 * name is used as the storing key so it must already have been initialized.
 */
void proxy_store_name(struct proxy *px)
{
	px->conf.by_name.key = px->id;
	ebis_insert(&proxy_by_name, &px->conf.by_name);
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
 * If <table> is non-zero, it only considers proxies having a table.
 */
struct proxy *proxy_find_by_name(const char *name, int cap, int table)
{
	struct proxy *curproxy;

	if (*name == '#') {
		curproxy = proxy_find_by_id(atoi(name + 1), cap, table);
		if (curproxy)
			return curproxy;
	}
	else {
		struct ebpt_node *node;

		for (node = ebis_lookup(&proxy_by_name, name); node; node = ebpt_next(node)) {
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
		if (strcmp(cursrv->id, name))
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
		ha_warning("config : cookie will be ignored for %s '%s' (needs 'mode http').\n",
			   proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->monitor_uri != NULL) {
		ha_warning("config : monitor-uri will be ignored for %s '%s' (needs 'mode http').\n",
			   proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->lbprm.algo & BE_LB_NEED_HTTP) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
		ha_warning("config : Layer 7 hash not possible for %s '%s' (needs 'mode http'). Falling back to round robin.\n",
			   proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->to_log & (LW_REQ | LW_RESP)) {
		curproxy->to_log &= ~(LW_REQ | LW_RESP);
		ha_warning("parsing [%s:%d] : HTTP log/header format not usable with %s '%s' (needs 'mode http').\n",
			   curproxy->conf.lfs_file, curproxy->conf.lfs_line,
			   proxy_type_str(curproxy), curproxy->id);
	}
	if (curproxy->conf.logformat_string == default_http_log_format ||
	    curproxy->conf.logformat_string == clf_http_log_format) {
		/* Note: we don't change the directive's file:line number */
		curproxy->conf.logformat_string = default_tcp_log_format;
		ha_warning("parsing [%s:%d] : 'option httplog' not usable with %s '%s' (needs 'mode http'). Falling back to 'option tcplog'.\n",
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
	p->pendconns = EB_ROOT;
	LIST_INIT(&p->acl);
	LIST_INIT(&p->http_req_rules);
	LIST_INIT(&p->http_res_rules);
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
	MT_LIST_INIT(&p->listener_queue);
	LIST_INIT(&p->logsrvs);
	LIST_INIT(&p->logformat);
	LIST_INIT(&p->logformat_sd);
	LIST_INIT(&p->format_unique_id);
	LIST_INIT(&p->conf.bind);
	LIST_INIT(&p->conf.listeners);
	LIST_INIT(&p->conf.args.list);
	LIST_INIT(&p->tcpcheck_rules);
	LIST_INIT(&p->filter_configs);

	/* Timeouts are defined as -1 */
	proxy_reset_timeouts(p);
	p->tcp_rep.inspect_delay = TICK_ETERNITY;

	/* initial uuid is unassigned (-1) */
	p->uuid = -1;

	/* Default to only allow L4 retries */
	p->retry_type = PR_RE_CONN_FAILED;

	HA_SPIN_INIT(&p->lock);
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

	for (curproxy = proxies_list; curproxy != NULL; curproxy = curproxy->next) {
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
					ha_alert("Starting %s %s: %s\n",
						 proxy_type_str(curproxy), curproxy->id, msg);
				else if (lerr & ERR_WARN)
					ha_warning("Starting %s %s: %s\n",
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
 * free streams, or stops them when the table is full. It is designed to be
 * called as a task which is woken up upon stopping or when rate limiting must
 * be enforced.
 */
struct task *manage_proxy(struct task *t, void *context, unsigned short state)
{
	struct proxy *p = context;
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
			ha_warning("Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				   p->id, p->fe_counters.cum_conn, p->be_counters.cum_conn);
			send_log(p, LOG_WARNING, "Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				 p->id, p->fe_counters.cum_conn, p->be_counters.cum_conn);
			stop_proxy(p);
			/* try to free more memory */
			pool_gc(NULL);
		}
		else {
			next = tick_first(next, p->stop_time);
		}
	}

	/* If the proxy holds a stick table, we need to purge all unused
	 * entries. These are all the ones in the table with ref_cnt == 0
	 * and all the ones in the pool used to allocate new entries. Any
	 * entry attached to an existing stream waiting for a store will
	 * be in neither list. Any entry being dumped will have ref_cnt > 0.
	 * However we protect tables that are being synced to peers.
	 */
	if (unlikely(stopping && p->state == PR_STSTOPPED && p->table && p->table->current)) {
		if (!p->table->syncing) {
			stktable_trash_oldest(p->table, p->table->current);
			pool_gc(NULL);
		}
		if (p->table->current) {
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
	if (!MT_LIST_ISEMPTY(&p->listener_queue))
		dequeue_all_listeners(&p->listener_queue);
 out:
	t->expire = next;
	task_queue(t);
	return t;
}


static int proxy_parse_hard_stop_after(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
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

struct task *hard_stop(struct task *t, void *context, unsigned short state)
{
	struct proxy *p;
	struct stream *s;

	if (killed) {
		ha_warning("Some tasks resisted to hard-stop, exiting now.\n");
		send_log(NULL, LOG_WARNING, "Some tasks resisted to hard-stop, exiting now.\n");
		killed = 2;
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
	list_for_each_entry(s, &streams, list) {
		stream_shutdown(s, SF_ERR_KILLED);
	}

	killed = 1;
	t->expire = tick_add(now_ms, MS_TO_TICKS(1000));
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
	struct task *task;

	stopping = 1;
	if (tick_isset(global.hard_stop_after)) {
		task = task_new(MAX_THREADS_MASK);
		if (task) {
			task->process = hard_stop;
			task_schedule(task, tick_add(now_ms, global.hard_stop_after));
		}
		else {
			ha_alert("out of memory trying to allocate the hard-stop task.\n");
		}
	}
	p = proxies_list;
	tv_update_date(0,1); /* else, the old time before select will be used */
	while (p) {
		/* Zombie proxy, let's close the file descriptors */
		if (p->state == PR_STSTOPPED &&
		    !LIST_ISEMPTY(&p->conf.listeners) &&
		    LIST_ELEM(p->conf.listeners.n,
		    struct listener *, by_fe)->state >= LI_ZOMBIE) {
			struct listener *l;
			list_for_each_entry(l, &p->conf.listeners, by_fe) {
				if (l->state >= LI_ZOMBIE)
					close(l->fd);
				l->state = LI_INIT;
			}
		}

		if (p->state != PR_STSTOPPED) {
			ha_warning("Stopping %s %s in %d ms.\n", proxy_cap_str(p->cap), p->id, p->grace);
			send_log(p, LOG_WARNING, "Stopping %s %s in %d ms.\n", proxy_cap_str(p->cap), p->id, p->grace);
			p->stop_time = tick_add(now_ms, p->grace);

			/* Note: do not wake up stopped proxies' task nor their tables'
			 * tasks as these ones might point to already released entries.
			 */
			if (p->table && p->table->size && p->table->sync_task)
				task_wakeup(p->table->sync_task, TASK_WOKEN_MSG);

			if (p->task)
				task_wakeup(p->task, TASK_WOKEN_MSG);
		}
		p = p->next;
	}

	prs = cfg_peers;
	while (prs) {
		if (prs->peers_fe)
			stop_proxy(prs->peers_fe);
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

	ha_warning("Pausing %s %s.\n", proxy_cap_str(p->cap), p->id);
	send_log(p, LOG_WARNING, "Pausing %s %s.\n", proxy_cap_str(p->cap), p->id);

	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		if (!pause_listener(l))
			p->state = PR_STERROR;
	}

	if (p->state == PR_STERROR) {
		ha_warning("%s %s failed to enter pause mode.\n", proxy_cap_str(p->cap), p->id);
		send_log(p, LOG_WARNING, "%s %s failed to enter pause mode.\n", proxy_cap_str(p->cap), p->id);
		return 0;
	}

	p->state = PR_STPAUSED;
	return 1;
}

/* This function makes the proxy unusable, but keeps the listening sockets
 * opened, so that if any process requests them, we are able to serve them.
 * This should only be called early, before we started accepting requests.
 */
void zombify_proxy(struct proxy *p)
{
	struct listener *l;
	struct listener *first_to_listen = NULL;

	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		enum li_state oldstate = l->state;

		unbind_listener_no_close(l);
		if (l->state >= LI_ASSIGNED) {
			delete_listener(l);
		}
		/*
		 * Pretend we're still up and running so that the fd
		 * will be sent if asked.
		 */
		l->state = LI_ZOMBIE;
		if (!first_to_listen && oldstate >= LI_LISTEN)
			first_to_listen = l;
	}
	/* Quick hack : at stop time, to know we have to close the sockets
	 * despite the proxy being marked as stopped, make the first listener
	 * of the listener list an active one, so that we don't have to
	 * parse the whole list to be sure.
	 */
	if (first_to_listen && LIST_ELEM(p->conf.listeners.n,
	    struct listener *, by_fe) != first_to_listen) {
		LIST_DEL(&l->by_fe);
		LIST_ADD(&p->conf.listeners, &l->by_fe);
	}

	p->state = PR_STSTOPPED;
}

/*
 * This function completely stops a proxy and releases its listeners. It has
 * to be called when going down in order to release the ports so that another
 * process may bind to them. It must also be called on disabled proxies at the
 * end of start-up. If all listeners are closed, the proxy is set to the
 * PR_STSTOPPED state. The function takes the proxy's lock so it's safe to
 * call from multiple places.
 */
void stop_proxy(struct proxy *p)
{
	struct listener *l;
	int nostop = 0;

	HA_SPIN_LOCK(PROXY_LOCK, &p->lock);

	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		if (l->options & LI_O_NOSTOP) {
			HA_ATOMIC_ADD(&unstoppable_jobs, 1);
			nostop = 1;
			continue;
		}
		/* The master should not close an inherited FD */
		if (master && (l->options & LI_O_INHERITED))
			unbind_listener_no_close(l);
		else
			unbind_listener(l);
		if (l->state >= LI_ASSIGNED) {
			delete_listener(l);
		}
	}
	if (!nostop)
		p->state = PR_STSTOPPED;

	HA_SPIN_UNLOCK(PROXY_LOCK, &p->lock);
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

	ha_warning("Enabling %s %s.\n", proxy_cap_str(p->cap), p->id);
	send_log(p, LOG_WARNING, "Enabling %s %s.\n", proxy_cap_str(p->cap), p->id);

	fail = 0;
	list_for_each_entry(l, &p->conf.listeners, by_fe) {
		if (!resume_listener(l)) {
			int port;

			port = get_host_port(&l->addr);
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
	p = proxies_list;
	tv_update_date(0,1); /* else, the old time before select will be used */
	while (p) {
		err |= !pause_proxy(p);
		p = p->next;
	}

	prs = cfg_peers;
	while (prs) {
		if (prs->peers_fe)
			err |= !pause_proxy(prs->peers_fe);
		prs = prs->next;
        }

	if (err) {
		ha_warning("Some proxies refused to pause, performing soft stop now.\n");
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
	p = proxies_list;
	tv_update_date(0,1); /* else, the old time before select will be used */
	while (p) {
		err |= !resume_proxy(p);
		p = p->next;
	}

	prs = cfg_peers;
	while (prs) {
		if (prs->peers_fe)
			err |= !resume_proxy(prs->peers_fe);
		prs = prs->next;
        }

	if (err) {
		ha_warning("Some proxies refused to resume, a restart is probably needed to resume safe operations.\n");
		send_log(p, LOG_WARNING, "Some proxies refused to resume, a restart is probably needed to resume safe operations.\n");
	}
}

/* Set current stream's backend to <be>. Nothing is done if the
 * stream already had a backend assigned, which is indicated by
 * s->flags & SF_BE_ASSIGNED.
 * All flags, stats and counters which need be updated are updated.
 * Returns 1 if done, 0 in case of internal error, eg: lack of resource.
 */
int stream_set_backend(struct stream *s, struct proxy *be)
{
	if (s->flags & SF_BE_ASSIGNED)
		return 1;

	if (flt_set_stream_backend(s, be) < 0)
		return 0;

	s->be = be;
	HA_ATOMIC_UPDATE_MAX(&be->be_counters.conn_max,
			     HA_ATOMIC_ADD(&be->beconn, 1));
	proxy_inc_be_ctr(be);

	/* assign new parameters to the stream from the new backend */
	s->si[1].flags &= ~SI_FL_INDEP_STR;
	if (be->options2 & PR_O2_INDEPSTR)
		s->si[1].flags |= SI_FL_INDEP_STR;

	if (tick_isset(be->timeout.serverfin))
		s->si[1].hcto = be->timeout.serverfin;

	/* We want to enable the backend-specific analysers except those which
	 * were already run as part of the frontend/listener. Note that it would
	 * be more reliable to store the list of analysers that have been run,
	 * but what we do here is OK for now.
	 */
	s->req.analysers |= be->be_req_ana & ~(strm_li(s) ? strm_li(s)->analysers : 0);

	/* If the target backend requires HTTP processing, we have to allocate
	 * the HTTP transaction if we did not have one.
	 */
	if (unlikely(!s->txn && be->http_needed)) {
		if (unlikely(!http_alloc_txn(s)))
			return 0; /* not enough memory */

		/* and now initialize the HTTP transaction state */
		http_init_txn(s);
	}

	/* Be sure to filter request headers if the backend is an HTTP proxy and
	 * if there are filters attached to the stream. */
	if (s->be->mode == PR_MODE_HTTP && HAS_FILTERS(s))
		s->req.analysers |= AN_REQ_FLT_HTTP_HDRS;

	if (s->txn) {
		/* If we chain a TCP frontend to an HTX backend, we must upgrade
		 * the client mux */
		if (!IS_HTX_STRM(s) && be->mode == PR_MODE_HTTP) {
			struct connection  *conn = objt_conn(strm_sess(s)->origin);
			struct conn_stream *cs   = objt_cs(s->si[0].end);

			if (conn && cs) {
				si_rx_endp_more(&s->si[0]);
				/* Make sure we're unsubscribed, the the new
				 * mux will probably want to subscribe to
				 * the underlying XPRT
				 */
				if (s->si[0].wait_event.events)
					conn->mux->unsubscribe(cs, s->si[0].wait_event.events,
					    &s->si[0].wait_event);
				if (conn_upgrade_mux_fe(conn, cs, &s->req.buf, ist(""), PROTO_MODE_HTTP)  == -1)
					return 0;
				if (!strcmp(conn->mux->name, "H2")) {
					/* For HTTP/2, destroy the conn_stream,
					 * disable logging, and pretend that we
					 * failed, to that the stream is
					 * silently destroyed. The new mux
					 * will create new streams.
					 */
					cs_free(cs);
					si_detach_endpoint(&s->si[0]);
					s->logs.logwait = 0;
					s->logs.level = 0;
					s->flags |= SF_IGNORE;
					return 0;
				}
				s->flags |= SF_HTX;
			}
		}

		/* we may request to parse a request body */
		if (be->options & PR_O_WREQ_BODY)
			s->req.analysers |= AN_REQ_HTTP_BODY;
	}

	s->flags |= SF_BE_ASSIGNED;
	if (be->options2 & PR_O2_NODELAY) {
		s->req.flags |= CF_NEVER_WAIT;
		s->res.flags |= CF_NEVER_WAIT;
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

	ev_id = HA_ATOMIC_XADD(&error_snapshot_id, 1);

	buf_len = b_data(buf) - buf_out;

	es = malloc(sizeof(*es) + buf_len);
	if (!es)
		return;

	es->buf_len = buf_len;
	es->ev_id   = ev_id;

	len1 = b_size(buf) - buf_len;
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
	if (objt_conn(sess->origin) && conn_get_src(__objt_conn(sess->origin)))
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
	HA_SPIN_LOCK(PROXY_LOCK, &proxy->lock);
	if (is_back) {
		es = HA_ATOMIC_XCHG(&proxy->invalid_rep, es);
	} else {
		es = HA_ATOMIC_XCHG(&proxy->invalid_req, es);
	}
	free(es);
	HA_SPIN_UNLOCK(PROXY_LOCK, &proxy->lock);
}

/* Configure all proxies which lack a maxconn setting to use the global one by
 * default. This avoids the common mistake consisting in setting maxconn only
 * in the global section and discovering the hard way that it doesn't propagate
 * through the frontends. These values are also propagated through the various
 * targetted backends, whose fullconn is finally calculated if not yet set.
 */
void proxy_adjust_all_maxconn()
{
	struct proxy *curproxy;
	struct switching_rule *swrule1, *swrule2;

	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		if (curproxy->state == PR_STSTOPPED)
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
		if (curproxy->state == PR_STSTOPPED)
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
	{ CFG_GLOBAL, "hard-stop-after", proxy_parse_hard_stop_after },
	{ CFG_LISTEN, "timeout", proxy_parse_timeout },
	{ CFG_LISTEN, "clitimeout", proxy_parse_timeout }, /* This keyword actually fails to parse, this line remains for better error messages. */
	{ CFG_LISTEN, "contimeout", proxy_parse_timeout }, /* This keyword actually fails to parse, this line remains for better error messages. */
	{ CFG_LISTEN, "srvtimeout", proxy_parse_timeout }, /* This keyword actually fails to parse, this line remains for better error messages. */
	{ CFG_LISTEN, "rate-limit", proxy_parse_rate_limit },
	{ CFG_LISTEN, "max-keep-alive-queue", proxy_parse_max_ka_queue },
	{ CFG_LISTEN, "declare", proxy_parse_declare },
	{ CFG_LISTEN, "retry-on", proxy_parse_retry_on },
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


/* parse a "show servers" CLI line, returns 0 if it wants to start the dump or
 * 1 if it stops immediately. If an argument is specified, it will set the proxy
 * pointer into cli.p0 and its ID into cli.i0.
 */
static int cli_parse_show_servers(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;

	/* check if a backend name has been provided */
	if (*args[3]) {
		/* read server state from local file */
		px = proxy_be_by_name(args[3]);

		if (!px)
			return cli_err(appctx, "Can't find backend.\n");

		appctx->ctx.cli.p0 = px;
		appctx->ctx.cli.i0 = px->uuid;
	}
	return 0;
}

/* dumps server state information into <buf> for all the servers found in backend cli.p0.
 * These information are all the parameters which may change during HAProxy runtime.
 * By default, we only export to the last known server state file format.
 * These information can be used at next startup to recover same level of server state.
 * It uses the proxy pointer from cli.p0, the proxy's id from cli.i0 and the server's
 * pointer from cli.p1.
 */
static int dump_servers_state(struct stream_interface *si, struct buffer *buf)
{
	struct appctx *appctx = __objt_appctx(si->end);
	struct proxy *px = appctx->ctx.cli.p0;
	struct server *srv;
	char srv_addr[INET6_ADDRSTRLEN + 1];
	time_t srv_time_since_last_change;
	int bk_f_forced_id, srv_f_forced_id;
	char *srvrecord;

	/* we don't want to report any state if the backend is not enabled on this process */
	if (!(proc_mask(px->bind_proc) & pid_bit))
		return 1;

	if (!appctx->ctx.cli.p1)
		appctx->ctx.cli.p1 = px->srv;

	for (; appctx->ctx.cli.p1 != NULL; appctx->ctx.cli.p1 = srv->next) {
		srv = appctx->ctx.cli.p1;
		srv_addr[0] = '\0';

		switch (srv->addr.ss_family) {
			case AF_INET:
				inet_ntop(srv->addr.ss_family, &((struct sockaddr_in *)&srv->addr)->sin_addr,
					  srv_addr, INET_ADDRSTRLEN + 1);
				break;
			case AF_INET6:
				inet_ntop(srv->addr.ss_family, &((struct sockaddr_in6 *)&srv->addr)->sin6_addr,
					  srv_addr, INET6_ADDRSTRLEN + 1);
				break;
			default:
				memcpy(srv_addr, "-\0", 2);
				break;
		}
		srv_time_since_last_change = now.tv_sec - srv->last_change;
		bk_f_forced_id = px->options & PR_O_FORCED_ID ? 1 : 0;
		srv_f_forced_id = srv->flags & SRV_F_FORCED_ID ? 1 : 0;

		srvrecord = NULL;
		if (srv->srvrq && srv->srvrq->name)
			srvrecord = srv->srvrq->name;

		chunk_appendf(buf,
				"%d %s "
				"%d %s %s "
				"%d %d %d %d %ld "
				"%d %d %d %d %d "
				"%d %d %s %u %s"
				"\n",
				px->uuid, px->id,
				srv->puid, srv->id, srv_addr,
				srv->cur_state, srv->cur_admin, srv->uweight, srv->iweight, (long int)srv_time_since_last_change,
				srv->check.status, srv->check.result, srv->check.health, srv->check.state, srv->agent.state,
				bk_f_forced_id, srv_f_forced_id, srv->hostname ? srv->hostname : "-", srv->svc_port,
				srvrecord ? srvrecord : "-");
		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}
	}
	return 1;
}

/* Parses backend list or simply use backend name provided by the user to return
 * states of servers to stdout. It dumps proxy <cli.p0> and stops if <cli.i0> is
 * non-null.
 */
static int cli_io_handler_servers_state(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct proxy *curproxy;

	chunk_reset(&trash);

	if (appctx->st2 == STAT_ST_INIT) {
		if (!appctx->ctx.cli.p0)
			appctx->ctx.cli.p0 = proxies_list;
		appctx->st2 = STAT_ST_HEAD;
	}

	if (appctx->st2 == STAT_ST_HEAD) {
		chunk_printf(&trash, "%d\n# %s\n", SRV_STATE_FILE_VERSION, SRV_STATE_FILE_FIELD_NAMES);
		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}
		appctx->st2 = STAT_ST_INFO;
	}

	/* STAT_ST_INFO */
	for (; appctx->ctx.cli.p0 != NULL; appctx->ctx.cli.p0 = curproxy->next) {
		curproxy = appctx->ctx.cli.p0;
		/* servers are only in backends */
		if (curproxy->cap & PR_CAP_BE) {
			if (!dump_servers_state(si, &trash))
				return 0;
		}
		/* only the selected proxy is dumped */
		if (appctx->ctx.cli.i0)
			break;
	}

	return 1;
}

/* Parses backend list and simply report backend names. It keeps the proxy
 * pointer in cli.p0.
 */
static int cli_io_handler_show_backend(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct proxy *curproxy;

	chunk_reset(&trash);

	if (!appctx->ctx.cli.p0) {
		chunk_printf(&trash, "# name\n");
		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}
		appctx->ctx.cli.p0 = proxies_list;
	}

	for (; appctx->ctx.cli.p0 != NULL; appctx->ctx.cli.p0 = curproxy->next) {
		curproxy = appctx->ctx.cli.p0;

		/* looking for backends only */
		if (!(curproxy->cap & PR_CAP_BE))
			continue;

		/* we don't want to list a backend which is bound to this process */
		if (!(proc_mask(curproxy->bind_proc) & pid_bit))
			continue;

		chunk_appendf(&trash, "%s\n", curproxy->id);
		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}
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

	/* Note: this lock is to make sure this doesn't change while another
	 * thread is in srv_set_dyncookie().
	 */
	HA_SPIN_LOCK(PROXY_LOCK, &px->lock);
	px->ck_opts |= PR_CK_DYNAMIC;
	HA_SPIN_UNLOCK(PROXY_LOCK, &px->lock);

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

	/* Note: this lock is to make sure this doesn't change while another
	 * thread is in srv_set_dyncookie().
	 */
	HA_SPIN_LOCK(PROXY_LOCK, &px->lock);
	px->ck_opts &= ~PR_CK_DYNAMIC;
	HA_SPIN_UNLOCK(PROXY_LOCK, &px->lock);

	for (s = px->srv; s != NULL; s = s->next) {
		HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
		if (!(s->flags & SRV_F_COOKIESET)) {
			free(s->cookie);
			s->cookie = NULL;
		}
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

	if (!*args[4])
		return cli_err(appctx, "String value expected.\n");

	newkey = strdup(args[4]);
	if (!newkey)
		return cli_err(appctx, "Failed to allocate memory.\n");

	/* Note: this lock is to make sure this doesn't change while another
	 * thread is in srv_set_dyncookie().
	 */
	HA_SPIN_LOCK(PROXY_LOCK, &px->lock);
	free(px->dyncookie_key);
	px->dyncookie_key = newkey;
	HA_SPIN_UNLOCK(PROXY_LOCK, &px->lock);

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
	HA_SPIN_LOCK(PROXY_LOCK, &px->lock);

	px->maxconn = v;
	list_for_each_entry(l, &px->conf.listeners, by_fe) {
		if (l->state == LI_FULL)
			resume_listener(l);
	}

	if (px->maxconn > px->feconn && !MT_LIST_ISEMPTY(&px->listener_queue))
		dequeue_all_listeners(&px->listener_queue);

	HA_SPIN_UNLOCK(PROXY_LOCK, &px->lock);

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

	if (px->state == PR_STSTOPPED)
		return cli_msg(appctx, LOG_NOTICE, "Frontend was already shut down.\n");

	ha_warning("Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
		   px->id, px->fe_counters.cum_conn, px->be_counters.cum_conn);
	send_log(px, LOG_WARNING, "Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
	         px->id, px->fe_counters.cum_conn, px->be_counters.cum_conn);

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

	if (px->state == PR_STSTOPPED)
		return cli_msg(appctx, LOG_NOTICE, "Frontend was previously shut down, cannot disable.\n");

	if (px->state == PR_STPAUSED)
		return cli_msg(appctx, LOG_NOTICE, "Frontend is already disabled.\n");

	HA_SPIN_LOCK(PROXY_LOCK, &px->lock);
	ret = pause_proxy(px);
	HA_SPIN_UNLOCK(PROXY_LOCK, &px->lock);

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

	if (px->state == PR_STSTOPPED)
		return cli_err(appctx, "Frontend was previously shut down, cannot enable.\n");

	if (px->state != PR_STPAUSED)
		return cli_msg(appctx, LOG_NOTICE, "Frontend is already enabled.\n");

	HA_SPIN_LOCK(PROXY_LOCK, &px->lock);
	ret = resume_proxy(px);
	HA_SPIN_UNLOCK(PROXY_LOCK, &px->lock);

	if (!ret)
		return cli_err(appctx, "Failed to resume frontend, check logs for precise cause (port conflict?).\n");
	return 1;
}

/* "show errors" handler for the CLI. Returns 0 if wants to continue, 1 to stop
 * now.
 */
static int cli_parse_show_errors(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (*args[2]) {
		struct proxy *px;

		px = proxy_find_by_name(args[2], 0, 0);
		if (px)
			appctx->ctx.errors.iid = px->uuid;
		else
			appctx->ctx.errors.iid = atoi(args[2]);

		if (!appctx->ctx.errors.iid)
			return cli_err(appctx, "No such proxy.\n");
	}
	else
		appctx->ctx.errors.iid	= -1; // dump all proxies

	appctx->ctx.errors.flag = 0;
	if (strcmp(args[3], "request") == 0)
		appctx->ctx.errors.flag |= 4; // ignore response
	else if (strcmp(args[3], "response") == 0)
		appctx->ctx.errors.flag |= 2; // ignore request
	appctx->ctx.errors.px = NULL;
	return 0;
}

/* This function dumps all captured errors onto the stream interface's
 * read buffer. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_errors(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	extern const char *monthname[12];

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	if (!appctx->ctx.errors.px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		struct tm tm;

		get_localtime(date.tv_sec, &tm);
		chunk_appendf(&trash, "Total events captured on [%02d/%s/%04d:%02d:%02d:%02d.%03d] : %u\n",
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(date.tv_usec/1000),
			     error_snapshot_id);

		if (ci_putchk(si_ic(si), &trash) == -1)
			goto cant_send;

		appctx->ctx.errors.px = proxies_list;
		appctx->ctx.errors.bol = 0;
		appctx->ctx.errors.ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (appctx->ctx.errors.px) {
		struct error_snapshot *es;

		HA_SPIN_LOCK(PROXY_LOCK, &appctx->ctx.errors.px->lock);

		if ((appctx->ctx.errors.flag & 1) == 0) {
			es = appctx->ctx.errors.px->invalid_req;
			if (appctx->ctx.errors.flag & 2) // skip req
				goto next;
		}
		else {
			es = appctx->ctx.errors.px->invalid_rep;
			if (appctx->ctx.errors.flag & 4) // skip resp
				goto next;
		}

		if (!es)
			goto next;

		if (appctx->ctx.errors.iid >= 0 &&
		    appctx->ctx.errors.px->uuid != appctx->ctx.errors.iid &&
		    es->oe->uuid != appctx->ctx.errors.iid)
			goto next;

		if (appctx->ctx.errors.ptr < 0) {
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

			switch (appctx->ctx.errors.flag & 1) {
			case 0:
				chunk_appendf(&trash,
					     " frontend %s (#%d): invalid request\n"
					     "  backend %s (#%d)",
					     appctx->ctx.errors.px->id, appctx->ctx.errors.px->uuid,
					     (es->oe->cap & PR_CAP_BE) ? es->oe->id : "<NONE>",
					     (es->oe->cap & PR_CAP_BE) ? es->oe->uuid : -1);
				break;
			case 1:
				chunk_appendf(&trash,
					     " backend %s (#%d): invalid response\n"
					     "  frontend %s (#%d)",
					     appctx->ctx.errors.px->id, appctx->ctx.errors.px->uuid,
					     es->oe->id, es->oe->uuid);
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

			if (ci_putchk(si_ic(si), &trash) == -1)
				goto cant_send_unlock;

			appctx->ctx.errors.ptr = 0;
			appctx->ctx.errors.ev_id = es->ev_id;
		}

		if (appctx->ctx.errors.ev_id != es->ev_id) {
			/* the snapshot changed while we were dumping it */
			chunk_appendf(&trash,
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (ci_putchk(si_ic(si), &trash) == -1)
				goto cant_send_unlock;

			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (appctx->ctx.errors.ptr < es->buf_len && appctx->ctx.errors.ptr < global.tune.bufsize) {
			int newptr;
			int newline;

			newline = appctx->ctx.errors.bol;
			newptr = dump_text_line(&trash, es->buf, global.tune.bufsize, es->buf_len, &newline, appctx->ctx.errors.ptr);
			if (newptr == appctx->ctx.errors.ptr)
				goto cant_send_unlock;

			if (ci_putchk(si_ic(si), &trash) == -1)
				goto cant_send_unlock;

			appctx->ctx.errors.ptr = newptr;
			appctx->ctx.errors.bol = newline;
		};
	next:
		HA_SPIN_UNLOCK(PROXY_LOCK, &appctx->ctx.errors.px->lock);
		appctx->ctx.errors.bol = 0;
		appctx->ctx.errors.ptr = -1;
		appctx->ctx.errors.flag ^= 1;
		if (!(appctx->ctx.errors.flag & 1))
			appctx->ctx.errors.px = appctx->ctx.errors.px->next;
	}

	/* dump complete */
	return 1;

 cant_send_unlock:
	HA_SPIN_UNLOCK(PROXY_LOCK, &appctx->ctx.errors.px->lock);
 cant_send:
	si_rx_room_blk(si);
	return 0;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "disable", "frontend",  NULL }, "disable frontend : temporarily disable specific frontend", cli_parse_disable_frontend, NULL, NULL },
	{ { "enable", "frontend",  NULL }, "enable frontend : re-enable specific frontend", cli_parse_enable_frontend, NULL, NULL },
	{ { "set", "maxconn", "frontend",  NULL }, "set maxconn frontend : change a frontend's maxconn setting", cli_parse_set_maxconn_frontend, NULL },
	{ { "show","servers", "state",  NULL }, "show servers state [id]: dump volatile server information (for backend <id>)", cli_parse_show_servers, cli_io_handler_servers_state },
	{ { "show", "backend", NULL }, "show backend   : list backends in the current running config", NULL, cli_io_handler_show_backend },
	{ { "shutdown", "frontend",  NULL }, "shutdown frontend : stop a specific frontend", cli_parse_shutdown_frontend, NULL, NULL },
	{ { "set", "dynamic-cookie-key", "backend", NULL }, "set dynamic-cookie-key backend : change a backend secret key for dynamic cookies", cli_parse_set_dyncookie_key_backend, NULL },
	{ { "enable", "dynamic-cookie", "backend", NULL }, "enable dynamic-cookie backend : enable dynamic cookies on a specific backend", cli_parse_enable_dyncookie_backend, NULL },
	{ { "disable", "dynamic-cookie", "backend", NULL }, "disable dynamic-cookie backend : disable dynamic cookies on a specific backend", cli_parse_disable_dyncookie_backend, NULL },
	{ { "show", "errors", NULL }, "show errors    : report last request and response errors for each proxy", cli_parse_show_errors, cli_io_handler_show_errors, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
