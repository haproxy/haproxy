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

#include <ctype.h>

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/port_range.h>
#include <proto/protocol.h>
#include <proto/raw_sock.h>
#include <proto/server.h>

/* List head of all known server keywords */
static struct srv_kw_list srv_keywords = {
	.list = LIST_HEAD_INIT(srv_keywords.list)
};

int srv_downtime(const struct server *s)
{
	if ((s->state & SRV_RUNNING) && s->last_change < now.tv_sec)		// ignore negative time
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

	if (!(s->state & SRV_RUNNING) && check->health == 0)
		return (check->downinter)?(check->downinter):(check->inter);

	return (check->fastinter)?(check->fastinter):(check->inter);
}

/*
 * Registers the server keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void srv_register_keywords(struct srv_kw_list *kwl)
{
	LIST_ADDQ(&srv_keywords.list, &kwl->list);
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

	eb32_insert(&curproxy->conf.used_server_id, &newsrv->conf.id);
	return 0;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct srv_kw_list srv_kws = { "ALL", { }, {
	{ "id",           srv_parse_id,           1,  0 }, /* set id# of server */
	{ NULL, NULL, 0 },
}};

__attribute__((constructor))
static void __listener_init(void)
{
	srv_register_keywords(&srv_kws);
}

/* Recomputes the server's eweight based on its state, uweight, the current time,
 * and the proxy's algorihtm. To be used after updating sv->uweight. The warmup
 * state is automatically disabled if the time is elapsed.
 */
void server_recalc_eweight(struct server *sv)
{
	struct proxy *px = sv->proxy;
	unsigned w;

	if (now.tv_sec < sv->last_change || now.tv_sec >= sv->last_change + sv->slowstart) {
		/* go to full throttle if the slowstart interval is reached */
		sv->state &= ~SRV_WARMINGUP;
	}

	/* We must take care of not pushing the server to full throttle during slow starts.
	 * It must also start immediately, at least at the minimal step when leaving maintenance.
	 */
	if ((sv->state & SRV_WARMINGUP) && (px->lbprm.algo & BE_LB_PROP_DYN))
		w = (px->lbprm.wdiv * (now.tv_sec - sv->last_change) + sv->slowstart) / sv->slowstart;
	else
		w = px->lbprm.wdiv;

	sv->eweight = (sv->uweight * w + px->lbprm.wmult - 1) / px->lbprm.wmult;

	/* now propagate the status change to any LB algorithms */
	if (px->lbprm.update_server_eweight)
		px->lbprm.update_server_eweight(sv);
	else if (sv->eweight) {
		if (px->lbprm.set_server_status_up)
			px->lbprm.set_server_status_up(sv);
	}
	else {
		if (px->lbprm.set_server_status_down)
			px->lbprm.set_server_status_down(sv);
	}
}

/*
 * Parses weight_str and configures sv accordingly.
 * Returns NULL on success, error message string otherwise.
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
	server_recalc_eweight(sv);

	return NULL;
}

static int init_check(struct check *check, int type, const char * file, int linenum)
{
	check->type = type;

	/* Allocate buffer for requests... */
	if ((check->bi = calloc(sizeof(struct buffer) + global.tune.chksize, sizeof(char))) == NULL) {
		Alert("parsing [%s:%d] : out of memory while allocating check buffer.\n", file, linenum);
		return ERR_ALERT | ERR_ABORT;
	}
	check->bi->size = global.tune.chksize;

	/* Allocate buffer for responses... */
	if ((check->bo = calloc(sizeof(struct buffer) + global.tune.chksize, sizeof(char))) == NULL) {
		Alert("parsing [%s:%d] : out of memory while allocating check buffer.\n", file, linenum);
		return ERR_ALERT | ERR_ABORT;
	}
	check->bo->size = global.tune.chksize;

	/* Allocate buffer for partial results... */
	if ((check->conn = calloc(1, sizeof(struct connection))) == NULL) {
		Alert("parsing [%s:%d] : out of memory while allocating check connection.\n", file, linenum);
		return ERR_ALERT | ERR_ABORT;
	}

	check->conn->t.sock.fd = -1; /* no agent in progress yet */

	return 0;
}

int parse_server(const char *file, int linenum, char **args, struct proxy *curproxy, struct proxy *defproxy)
{
	struct server *newsrv = NULL;
	const char *err;
	char *errmsg = NULL;
	int err_code = 0;
	unsigned val;

	if (!strcmp(args[0], "server") || !strcmp(args[0], "default-server")) {  /* server address */
		int cur_arg;
		short realport = 0;
		int do_agent = 0, do_check = 0, defsrv = (*args[0] == 'd');

		if (!defsrv && curproxy == defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_ALERT | ERR_FATAL;

		if (!*args[2]) {
			Alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err && !defsrv) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
			      file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!defsrv) {
			struct sockaddr_storage *sk;
			int port1, port2;
			struct protocol *proto;

			if ((newsrv = (struct server *)calloc(1, sizeof(struct server))) == NULL) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			/* the servers are linked backwards first */
			newsrv->next = curproxy->srv;
			curproxy->srv = newsrv;
			newsrv->proxy = curproxy;
			newsrv->conf.file = strdup(file);
			newsrv->conf.line = linenum;

			newsrv->obj_type = OBJ_TYPE_SERVER;
			LIST_INIT(&newsrv->actconns);
			LIST_INIT(&newsrv->pendconns);
			do_check = 0;
			do_agent = 0;
			newsrv->state = SRV_RUNNING; /* early server setup */
			newsrv->last_change = now.tv_sec;
			newsrv->id = strdup(args[1]);

			/* several ways to check the port component :
			 *  - IP    => port=+0, relative (IPv4 only)
			 *  - IP:   => port=+0, relative
			 *  - IP:N  => port=N, absolute
			 *  - IP:+N => port=+N, relative
			 *  - IP:-N => port=-N, relative
			 */
			sk = str2sa_range(args[2], &port1, &port2, &errmsg, NULL);
			if (!sk) {
				Alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			proto = protocol_by_family(sk->ss_family);
			if (!proto || !proto->connect) {
				Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!port1 || !port2) {
				/* no port specified, +offset, -offset */
				newsrv->state |= SRV_MAPPORTS;
			}
			else if (port1 != port2) {
				/* port range */
				Alert("parsing [%s:%d] : '%s %s' : port ranges are not allowed in '%s'\n",
				      file, linenum, args[0], args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else {
				/* used by checks */
				realport = port1;
			}

			newsrv->addr = *sk;
			newsrv->proto = newsrv->check_common.proto = protocol_by_family(newsrv->addr.ss_family);
			newsrv->xprt  = newsrv->check_common.xprt  = &raw_sock;

			if (!newsrv->proto) {
				Alert("parsing [%s:%d] : Unknown protocol family %d '%s'\n",
				      file, linenum, newsrv->addr.ss_family, args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			newsrv->check.use_ssl	= curproxy->defsrv.check.use_ssl;
			newsrv->check.port	= curproxy->defsrv.check.port;
			newsrv->check.inter	= curproxy->defsrv.check.inter;
			newsrv->check.fastinter	= curproxy->defsrv.check.fastinter;
			newsrv->check.downinter	= curproxy->defsrv.check.downinter;
			newsrv->agent.use_ssl	= curproxy->defsrv.agent.use_ssl;
			newsrv->agent.port	= curproxy->defsrv.agent.port;
			newsrv->agent.inter	= curproxy->defsrv.agent.inter;
			newsrv->agent.fastinter	= curproxy->defsrv.agent.fastinter;
			newsrv->agent.downinter	= curproxy->defsrv.agent.downinter;
			newsrv->maxqueue	= curproxy->defsrv.maxqueue;
			newsrv->minconn		= curproxy->defsrv.minconn;
			newsrv->maxconn		= curproxy->defsrv.maxconn;
			newsrv->slowstart	= curproxy->defsrv.slowstart;
			newsrv->onerror		= curproxy->defsrv.onerror;
			newsrv->onmarkeddown    = curproxy->defsrv.onmarkeddown;
			newsrv->onmarkedup      = curproxy->defsrv.onmarkedup;
			newsrv->consecutive_errors_limit
						= curproxy->defsrv.consecutive_errors_limit;
#ifdef OPENSSL
			newsrv->use_ssl		= curproxy->defsrv.use_ssl;
#endif
			newsrv->uweight = newsrv->iweight
						= curproxy->defsrv.iweight;

			newsrv->check.status	= HCHK_STATUS_INI;
			newsrv->check.rise	= curproxy->defsrv.check.rise;
			newsrv->check.fall	= curproxy->defsrv.check.fall;
			newsrv->check.health	= newsrv->check.rise;	/* up, but will fall down at first failure */
			newsrv->check.server	= newsrv;

			newsrv->agent.status	= HCHK_STATUS_INI;
			newsrv->agent.rise	= curproxy->defsrv.agent.rise;
			newsrv->agent.fall	= curproxy->defsrv.agent.fall;
			newsrv->agent.health	= newsrv->agent.rise;	/* up, but will fall down at first failure */
			newsrv->agent.server	= newsrv;

			cur_arg = 3;
		} else {
			newsrv = &curproxy->defsrv;
			cur_arg = 1;
		}

		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "agent-check")) {
				global.maxsock++;
				do_agent = 1;
				cur_arg += 1;
			} else if (!strcmp(args[cur_arg], "agent-inter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d] : unexpected character '%c' in 'agent-inter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->agent.inter = val;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "agent-port")) {
				global.maxsock++;
				newsrv->agent.port = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "cookie")) {
				newsrv->cookie = strdup(args[cur_arg + 1]);
				newsrv->cklen = strlen(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "redir")) {
				newsrv->rdr_pfx = strdup(args[cur_arg + 1]);
				newsrv->rdr_len = strlen(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "rise")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->check.rise = atol(args[cur_arg + 1]);
				if (newsrv->check.rise <= 0) {
					Alert("parsing [%s:%d]: '%s' has to be > 0.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (newsrv->check.health)
					newsrv->check.health = newsrv->check.rise;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "fall")) {
				newsrv->check.fall = atol(args[cur_arg + 1]);

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (newsrv->check.fall <= 0) {
					Alert("parsing [%s:%d]: '%s' has to be > 0.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "inter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d] : unexpected character '%c' in 'inter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->check.inter = val;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "fastinter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d]: unexpected character '%c' in 'fastinter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->check.fastinter = val;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "downinter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d]: unexpected character '%c' in 'downinter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->check.downinter = val;
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "addr")) {
				struct sockaddr_storage *sk;
				int port1, port2;
				struct protocol *proto;

				sk = str2sa_range(args[cur_arg + 1], &port1, &port2, &errmsg, NULL);
				if (!sk) {
					Alert("parsing [%s:%d] : '%s' : %s\n",
					      file, linenum, args[cur_arg], errmsg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				proto = protocol_by_family(sk->ss_family);
				if (!proto || !proto->connect) {
					Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
					      file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (port1 != port2) {
					Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
					      file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->check_common.addr = *sk;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "port")) {
				newsrv->check.port = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "backup")) {
				newsrv->state |= SRV_BACKUP;
				cur_arg ++;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "non-stick")) {
				newsrv->state |= SRV_NON_STICK;
				cur_arg ++;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "send-proxy")) {
				newsrv->state |= SRV_SEND_PROXY;
				cur_arg ++;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "check-send-proxy")) {
				newsrv->check.send_proxy = 1;
				cur_arg ++;
			}
			else if (!strcmp(args[cur_arg], "weight")) {
				int w;
				w = atol(args[cur_arg + 1]);
				if (w < 0 || w > SRV_UWGHT_MAX) {
					Alert("parsing [%s:%d] : weight of server %s is not within 0 and %d (%d).\n",
					      file, linenum, newsrv->id, SRV_UWGHT_MAX, w);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->uweight = newsrv->iweight = w;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "minconn")) {
				newsrv->minconn = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "maxconn")) {
				newsrv->maxconn = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "maxqueue")) {
				newsrv->maxqueue = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "slowstart")) {
				/* slowstart is stored in seconds */
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d] : unexpected character '%c' in 'slowstart' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->slowstart = (val + 999) / 1000;
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "track")) {

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: 'track' expects [<proxy>/]<server> as argument.\n",
						file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->trackit = strdup(args[cur_arg + 1]);

				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "check")) {
				global.maxsock++;
				do_check = 1;
				cur_arg += 1;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "disabled")) {
				newsrv->state |= SRV_MAINTAIN;
				newsrv->state &= ~SRV_RUNNING;
				newsrv->check.state |= CHK_ST_PAUSED;
				newsrv->check.health = 0;
				newsrv->agent.health = 0;
				cur_arg += 1;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "observe")) {
				if (!strcmp(args[cur_arg + 1], "none"))
					newsrv->observe = HANA_OBS_NONE;
				else if (!strcmp(args[cur_arg + 1], "layer4"))
					newsrv->observe = HANA_OBS_LAYER4;
				else if (!strcmp(args[cur_arg + 1], "layer7")) {
					if (curproxy->mode != PR_MODE_HTTP) {
						Alert("parsing [%s:%d]: '%s' can only be used in http proxies.\n",
							file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT;
					}
					newsrv->observe = HANA_OBS_LAYER7;
				}
				else {
					Alert("parsing [%s:%d]: '%s' expects one of 'none', "
						"'layer4', 'layer7' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "on-error")) {
				if (!strcmp(args[cur_arg + 1], "fastinter"))
					newsrv->onerror = HANA_ONERR_FASTINTER;
				else if (!strcmp(args[cur_arg + 1], "fail-check"))
					newsrv->onerror = HANA_ONERR_FAILCHK;
				else if (!strcmp(args[cur_arg + 1], "sudden-death"))
					newsrv->onerror = HANA_ONERR_SUDDTH;
				else if (!strcmp(args[cur_arg + 1], "mark-down"))
					newsrv->onerror = HANA_ONERR_MARKDWN;
				else {
					Alert("parsing [%s:%d]: '%s' expects one of 'fastinter', "
						"'fail-check', 'sudden-death' or 'mark-down' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "on-marked-down")) {
				if (!strcmp(args[cur_arg + 1], "shutdown-sessions"))
					newsrv->onmarkeddown = HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS;
				else {
					Alert("parsing [%s:%d]: '%s' expects 'shutdown-sessions' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "on-marked-up")) {
				if (!strcmp(args[cur_arg + 1], "shutdown-backup-sessions"))
					newsrv->onmarkedup = HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS;
				else {
					Alert("parsing [%s:%d]: '%s' expects 'shutdown-backup-sessions' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "error-limit")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->consecutive_errors_limit = atoi(args[cur_arg + 1]);

				if (newsrv->consecutive_errors_limit <= 0) {
					Alert("parsing [%s:%d]: %s has to be > 0.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "source")) {  /* address to which we bind when connecting */
				int port_low, port_high;
				struct sockaddr_storage *sk;
				struct protocol *proto;

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>[-<port>]], and optionally '%s' <addr>, and '%s' <name> as argument.\n",
					      file, linenum, "source", "usesrc", "interface");
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->conn_src.opts |= CO_SRC_BIND;
				sk = str2sa_range(args[cur_arg + 1], &port_low, &port_high, &errmsg, NULL);
				if (!sk) {
					Alert("parsing [%s:%d] : '%s %s' : %s\n",
					      file, linenum, args[cur_arg], args[cur_arg+1], errmsg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				proto = protocol_by_family(sk->ss_family);
				if (!proto || !proto->connect) {
					Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
					      file, linenum, args[cur_arg], args[cur_arg+1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->conn_src.source_addr = *sk;

				if (port_low != port_high) {
					int i;

					if (!port_low || !port_high) {
						Alert("parsing [%s:%d] : %s does not support port offsets (found '%s').\n",
						      file, linenum, args[cur_arg], args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					if (port_low  <= 0 || port_low > 65535 ||
					    port_high <= 0 || port_high > 65535 ||
					    port_low > port_high) {
						Alert("parsing [%s:%d] : invalid source port range %d-%d.\n",
						      file, linenum, port_low, port_high);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					newsrv->conn_src.sport_range = port_range_alloc_range(port_high - port_low + 1);
					for (i = 0; i < newsrv->conn_src.sport_range->size; i++)
						newsrv->conn_src.sport_range->ports[i] = port_low + i;
				}

				cur_arg += 2;
				while (*(args[cur_arg])) {
					if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside */
#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_TRANSPARENT)
#if !defined(CONFIG_HAP_TRANSPARENT)
						if (!is_addr(&newsrv->conn_src.source_addr)) {
							Alert("parsing [%s:%d] : '%s' requires an explicit '%s' address.\n",
							      file, linenum, "usesrc", "source");
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
#endif
						if (!*args[cur_arg + 1]) {
							Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', 'clientip', or 'hdr_ip(name,#)' as argument.\n",
							      file, linenum, "usesrc");
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
						if (!strcmp(args[cur_arg + 1], "client")) {
							newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_CLI;
						} else if (!strcmp(args[cur_arg + 1], "clientip")) {
							newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_CIP;
						} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
							char *name, *end;

							name = args[cur_arg+1] + 7;
							while (isspace(*name))
								name++;

							end = name;
							while (*end && !isspace(*end) && *end != ',' && *end != ')')
								end++;

							newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_DYN;
							newsrv->conn_src.bind_hdr_name = calloc(1, end - name + 1);
							newsrv->conn_src.bind_hdr_len = end - name;
							memcpy(newsrv->conn_src.bind_hdr_name, name, end - name);
							newsrv->conn_src.bind_hdr_name[end-name] = '\0';
							newsrv->conn_src.bind_hdr_occ = -1;

							/* now look for an occurrence number */
							while (isspace(*end))
								end++;
							if (*end == ',') {
								end++;
								name = end;
								if (*end == '-')
									end++;
								while (isdigit((int)*end))
									end++;
								newsrv->conn_src.bind_hdr_occ = strl2ic(name, end-name);
							}

							if (newsrv->conn_src.bind_hdr_occ < -MAX_HDR_HISTORY) {
								Alert("parsing [%s:%d] : usesrc hdr_ip(name,num) does not support negative"
								      " occurrences values smaller than %d.\n",
								      file, linenum, MAX_HDR_HISTORY);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
						} else {
							struct sockaddr_storage *sk;
							int port1, port2;

							sk = str2sa_range(args[cur_arg + 1], &port1, &port2, &errmsg, NULL);
							if (!sk) {
								Alert("parsing [%s:%d] : '%s %s' : %s\n",
								      file, linenum, args[cur_arg], args[cur_arg+1], errmsg);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}

							proto = protocol_by_family(sk->ss_family);
							if (!proto || !proto->connect) {
								Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
								      file, linenum, args[cur_arg], args[cur_arg+1]);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}

							if (port1 != port2) {
								Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
								      file, linenum, args[cur_arg], args[cur_arg + 1]);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
							newsrv->conn_src.tproxy_addr = *sk;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_ADDR;
						}
						global.last_checks |= LSTCHK_NETADM;
#if !defined(CONFIG_HAP_TRANSPARENT)
						global.last_checks |= LSTCHK_CTTPROXY;
#endif
						cur_arg += 2;
						continue;
#else	/* no TPROXY support */
						Alert("parsing [%s:%d] : '%s' not allowed here because support for TPROXY was not compiled in.\n",
						      file, linenum, "usesrc");
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
#endif /* defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_TRANSPARENT) */
					} /* "usesrc" */

					if (!strcmp(args[cur_arg], "interface")) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
						if (!*args[cur_arg + 1]) {
							Alert("parsing [%s:%d] : '%s' : missing interface name.\n",
							      file, linenum, args[0]);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
						free(newsrv->conn_src.iface_name);
						newsrv->conn_src.iface_name = strdup(args[cur_arg + 1]);
						newsrv->conn_src.iface_len  = strlen(newsrv->conn_src.iface_name);
						global.last_checks |= LSTCHK_NETADM;
#else
						Alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
						      file, linenum, args[0], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
#endif
						cur_arg += 2;
						continue;
					}
					/* this keyword in not an option of "source" */
					break;
				} /* while */
			}
			else if (!defsrv && !strcmp(args[cur_arg], "usesrc")) {  /* address to use outside: needs "source" first */
				Alert("parsing [%s:%d] : '%s' only allowed after a '%s' statement.\n",
				      file, linenum, "usesrc", "source");
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else {
				static int srv_dumped;
				struct srv_kw *kw;
				char *err;

				kw = srv_find_kw(args[cur_arg]);
				if (kw) {
					char *err = NULL;
					int code;

					if (!kw->parse) {
						Alert("parsing [%s:%d] : '%s %s' : '%s' option is not implemented in this version (check build options).\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						cur_arg += 1 + kw->skip ;
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					if (defsrv && !kw->default_ok) {
						Alert("parsing [%s:%d] : '%s %s' : '%s' option is not accepted in default-server sections.\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						cur_arg += 1 + kw->skip ;
						err_code |= ERR_ALERT;
						continue;
					}

					code = kw->parse(args, &cur_arg, curproxy, newsrv, &err);
					err_code |= code;

					if (code) {
						if (err && *err) {
							indent_msg(&err, 2);
							Alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], err);
						}
						else
							Alert("parsing [%s:%d] : '%s %s' : error encountered while processing '%s'.\n",
							      file, linenum, args[0], args[1], args[cur_arg]);
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

				err = NULL;
				if (!srv_dumped) {
					srv_dump_kws(&err);
					indent_msg(&err, 4);
					srv_dumped = 1;
				}

				Alert("parsing [%s:%d] : '%s %s' unknown keyword '%s'.%s%s\n",
				      file, linenum, args[0], args[1], args[cur_arg],
				      err ? " Registered keywords :" : "", err ? err : "");
				free(err);

				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		/* Set initial drain state using now-configured weight */
		set_server_drain_state(newsrv);

		if (do_check) {
			int ret;

			if (newsrv->trackit) {
				Alert("parsing [%s:%d]: unable to enable checks and tracking at the same time!\n",
					file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* If neither a port nor an addr was specified and no check transport
			 * layer is forced, then the transport layer used by the checks is the
			 * same as for the production traffic. Otherwise we use raw_sock by
			 * default, unless one is specified.
			 */
			if (!newsrv->check.port && !is_addr(&newsrv->check_common.addr)) {
#ifdef USE_OPENSSL
				newsrv->check.use_ssl |= (newsrv->use_ssl || (newsrv->proxy->options & PR_O_TCPCHK_SSL));
#endif
				newsrv->check.send_proxy |= (newsrv->state & SRV_SEND_PROXY);
			}
			/* try to get the port from check_core.addr if check.port not set */
			if (!newsrv->check.port)
				newsrv->check.port = get_host_port(&newsrv->check_common.addr);

			if (!newsrv->check.port)
				newsrv->check.port = realport; /* by default */

			if (!newsrv->check.port) {
				/* not yet valid, because no port was set on
				 * the server either. We'll check if we have
				 * a known port on the first listener.
				 */
				struct listener *l;

				list_for_each_entry(l, &curproxy->conf.listeners, by_fe) {
					newsrv->check.port = get_host_port(&l->addr);
					if (newsrv->check.port)
						break;
				}
			}
			/*
			 * We need at least a service port, a check port or the first tcp-check rule must
			 * be a 'connect' one
			 */
			if (!newsrv->check.port) {
				struct tcpcheck_rule *n = NULL, *r = NULL;
				struct list *l;

				r = (struct tcpcheck_rule *)newsrv->proxy->tcpcheck_rules.n;
				if (!r) {
					Alert("parsing [%s:%d] : server %s has neither service port nor check port. Check has been disabled.\n",
					      file, linenum, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if ((r->action != TCPCHK_ACT_CONNECT) || !r->port) {
					Alert("parsing [%s:%d] : server %s has neither service port nor check port nor tcp_check rule 'connect' with port information. Check has been disabled.\n",
					      file, linenum, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				else {
					/* scan the tcp-check ruleset to ensure a port has been configured */
					l = &newsrv->proxy->tcpcheck_rules;
					list_for_each_entry(n, l, list) {
						r = (struct tcpcheck_rule *)n->list.p;
						if ((r->action == TCPCHK_ACT_CONNECT) && (!r->port)) {
							Alert("parsing [%s:%d] : server %s has neither service port nor check port, and a tcp_check rule 'connect' with no port information. Check has been disabled.\n",
							      file, linenum, newsrv->id);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
					}
				}
			}

			/* note: check type will be set during the config review phase */
			ret = init_check(&newsrv->check, 0, file, linenum);
			if (ret) {
				err_code |= ret;
				goto out;
			}

			newsrv->check.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED;
		}

		if (do_agent) {
			int ret;

			if (!newsrv->agent.port) {
				Alert("parsing [%s:%d] : server %s does not have agent port. Agent check has been disabled.\n",
				      file, linenum, newsrv->id);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!newsrv->agent.inter)
				newsrv->agent.inter = newsrv->check.inter;

			ret = init_check(&newsrv->agent, PR_O2_LB_AGENT_CHK, file, linenum);
			if (ret) {
				err_code |= ret;
				goto out;
			}

			newsrv->agent.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED | CHK_ST_AGENT;
		}

		if (!defsrv) {
			if (newsrv->state & SRV_BACKUP)
				curproxy->srv_bck++;
			else
				curproxy->srv_act++;

			newsrv->prev_state = newsrv->state;
		}
	}
	return 0;

 out:
	free(errmsg);
	return err_code;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
