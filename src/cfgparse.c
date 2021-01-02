/*
 * Configuration parser
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifdef USE_LIBCRYPT
/* This is to have crypt() defined on Linux */
#define _GNU_SOURCE

#ifdef USE_CRYPT_H
/* some platforms such as Solaris need this */
#include <crypt.h>
#endif
#endif /* USE_LIBCRYPT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <haproxy/acl.h>
#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/auth.h>
#include <haproxy/backend.h>
#include <haproxy/capture.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/dns.h>
#include <haproxy/errors.h>
#include <haproxy/filters.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_rules.h>
#include <haproxy/lb_chash.h>
#include <haproxy/lb_fas.h>
#include <haproxy/lb_fwlc.h>
#include <haproxy/lb_fwrr.h>
#include <haproxy/lb_map.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/mailers.h>
#include <haproxy/namespace.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/peers-t.h>
#include <haproxy/peers.h>
#include <haproxy/pool.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth-t.h>
#include <haproxy/xprt_quic.h>


/* Used to chain configuration sections definitions. This list
 * stores struct cfg_section
 */
struct list sections = LIST_HEAD_INIT(sections);

struct list postparsers = LIST_HEAD_INIT(postparsers);

char *cursection = NULL;
struct proxy defproxy = { };		/* fake proxy used to assign default values on all instances */
int cfg_maxpconn = 0;                   /* # of simultaneous connections per proxy (-N) */
int cfg_maxconn = 0;			/* # of simultaneous connections, (-n) */
char *cfg_scope = NULL;                 /* the current scope during the configuration parsing */

/* List head of all known configuration keywords */
struct cfg_kw_list cfg_keywords = {
	.list = LIST_HEAD_INIT(cfg_keywords.list)
};

/*
 * converts <str> to a list of listeners which are dynamically allocated.
 * The format is "{addr|'*'}:port[-end][,{addr|'*'}:port[-end]]*", where :
 *  - <addr> can be empty or "*" to indicate INADDR_ANY ;
 *  - <port> is a numerical port from 1 to 65535 ;
 *  - <end> indicates to use the range from <port> to <end> instead (inclusive).
 * This can be repeated as many times as necessary, separated by a coma.
 * Function returns 1 for success or 0 if error. In case of errors, if <err> is
 * not NULL, it must be a valid pointer to either NULL or a freeable area that
 * will be replaced with an error message.
 */
int str2listener(char *str, struct proxy *curproxy, struct bind_conf *bind_conf, const char *file, int line, char **err)
{
	struct protocol *proto;
	char *next, *dupstr;
	int port, end;

	next = dupstr = strdup(str);

	while (next && *next) {
		struct sockaddr_storage *ss2;
		int fd = -1;

		str = next;
		/* 1) look for the end of the first address */
		if ((next = strchr(str, ',')) != NULL) {
			*next++ = 0;
		}

		ss2 = str2sa_range(str, NULL, &port, &end, &fd, &proto, err,
		                   curproxy == global.stats_fe ? NULL : global.unix_bind.prefix,
		                   NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_PORT_RANGE |
		                          PA_O_SOCKET_FD | PA_O_STREAM | PA_O_XPRT);
		if (!ss2)
			goto fail;

		/* OK the address looks correct */

#ifdef USE_QUIC
		/* The transport layer automatically switches to QUIC when QUIC
		 * is selected, regardless of bind_conf settings. We then need
		 * to initialize QUIC params.
		 */
		if (proto->sock_type == SOCK_DGRAM && proto->ctrl_type == SOCK_STREAM) {
			bind_conf->xprt = xprt_get(XPRT_QUIC);
			quic_transport_params_init(&bind_conf->quic_params, 1);
		}
#endif
		if (!create_listeners(bind_conf, ss2, port, end, fd, proto, err)) {
			memprintf(err, "%s for address '%s'.\n", *err, str);
			goto fail;
		}
	} /* end while(next) */
	free(dupstr);
	return 1;
 fail:
	free(dupstr);
	return 0;
}

/*
 * converts <str> to a list of datagram-oriented listeners which are dynamically
 * allocated.
 * The format is "{addr|'*'}:port[-end][,{addr|'*'}:port[-end]]*", where :
 *  - <addr> can be empty or "*" to indicate INADDR_ANY ;
 *  - <port> is a numerical port from 1 to 65535 ;
 *  - <end> indicates to use the range from <port> to <end> instead (inclusive).
 * This can be repeated as many times as necessary, separated by a coma.
 * Function returns 1 for success or 0 if error. In case of errors, if <err> is
 * not NULL, it must be a valid pointer to either NULL or a freeable area that
 * will be replaced with an error message.
 */
int str2receiver(char *str, struct proxy *curproxy, struct bind_conf *bind_conf, const char *file, int line, char **err)
{
	struct protocol *proto;
	char *next, *dupstr;
	int port, end;

	next = dupstr = strdup(str);

	while (next && *next) {
		struct sockaddr_storage *ss2;
		int fd = -1;

		str = next;
		/* 1) look for the end of the first address */
		if ((next = strchr(str, ',')) != NULL) {
			*next++ = 0;
		}

		ss2 = str2sa_range(str, NULL, &port, &end, &fd, &proto, err,
		                   curproxy == global.stats_fe ? NULL : global.unix_bind.prefix,
		                   NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_PORT_RANGE |
		                          PA_O_SOCKET_FD | PA_O_DGRAM | PA_O_XPRT);
		if (!ss2)
			goto fail;

		/* OK the address looks correct */
		if (!create_listeners(bind_conf, ss2, port, end, fd, proto, err)) {
			memprintf(err, "%s for address '%s'.\n", *err, str);
			goto fail;
		}
	} /* end while(next) */
	free(dupstr);
	return 1;
 fail:
	free(dupstr);
	return 0;
}

/*
 * Report an error in <msg> when there are too many arguments. This version is
 * intended to be used by keyword parsers so that the message will be included
 * into the general error message. The index is the current keyword in args.
 * Return 0 if the number of argument is correct, otherwise build a message and
 * return 1. Fill err_code with an ERR_ALERT and an ERR_FATAL if not null. The
 * message may also be null, it will simply not be produced (useful to check only).
 * <msg> and <err_code> are only affected on error.
 */
int too_many_args_idx(int maxarg, int index, char **args, char **msg, int *err_code)
{
	int i;

	if (!*args[index + maxarg + 1])
		return 0;

	if (msg) {
		*msg = NULL;
		memprintf(msg, "%s", args[0]);
		for (i = 1; i <= index; i++)
			memprintf(msg, "%s %s", *msg, args[i]);

		memprintf(msg, "'%s' cannot handle unexpected argument '%s'.", *msg, args[index + maxarg + 1]);
	}
	if (err_code)
		*err_code |= ERR_ALERT | ERR_FATAL;

	return 1;
}

/*
 * same as too_many_args_idx with a 0 index
 */
int too_many_args(int maxarg, char **args, char **msg, int *err_code)
{
	return too_many_args_idx(maxarg, 0, args, msg, err_code);
}

/*
 * Report a fatal Alert when there is too much arguments
 * The index is the current keyword in args
 * Return 0 if the number of argument is correct, otherwise emit an alert and return 1
 * Fill err_code with an ERR_ALERT and an ERR_FATAL
 */
int alertif_too_many_args_idx(int maxarg, int index, const char *file, int linenum, char **args, int *err_code)
{
	char *kw = NULL;
	int i;

	if (!*args[index + maxarg + 1])
		return 0;

	memprintf(&kw, "%s", args[0]);
	for (i = 1; i <= index; i++) {
		memprintf(&kw, "%s %s", kw, args[i]);
	}

	ha_alert("parsing [%s:%d] : '%s' cannot handle unexpected argument '%s'.\n", file, linenum, kw, args[index + maxarg + 1]);
	free(kw);
	*err_code |= ERR_ALERT | ERR_FATAL;
	return 1;
}

/*
 * same as alertif_too_many_args_idx with a 0 index
 */
int alertif_too_many_args(int maxarg, const char *file, int linenum, char **args, int *err_code)
{
	return alertif_too_many_args_idx(maxarg, 0, file, linenum, args, err_code);
}


/* Report it if a request ACL condition uses some keywords that are incompatible
 * with the place where the ACL is used. It returns either 0 or ERR_WARN so that
 * its result can be or'ed with err_code. Note that <cond> may be NULL and then
 * will be ignored.
 */
int warnif_cond_conflicts(const struct acl_cond *cond, unsigned int where, const char *file, int line)
{
	const struct acl *acl;
	const char *kw;

	if (!cond)
		return 0;

	acl = acl_cond_conflicts(cond, where);
	if (acl) {
		if (acl->name && *acl->name)
			ha_warning("parsing [%s:%d] : acl '%s' will never match because it only involves keywords that are incompatible with '%s'\n",
				   file, line, acl->name, sample_ckp_names(where));
		else
			ha_warning("parsing [%s:%d] : anonymous acl will never match because it uses keyword '%s' which is incompatible with '%s'\n",
				   file, line, LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw, sample_ckp_names(where));
		return ERR_WARN;
	}
	if (!acl_cond_kw_conflicts(cond, where, &acl, &kw))
		return 0;

	if (acl->name && *acl->name)
		ha_warning("parsing [%s:%d] : acl '%s' involves keywords '%s' which is incompatible with '%s'\n",
			   file, line, acl->name, kw, sample_ckp_names(where));
	else
		ha_warning("parsing [%s:%d] : anonymous acl involves keyword '%s' which is incompatible with '%s'\n",
			   file, line, kw, sample_ckp_names(where));
	return ERR_WARN;
}

/* Parse a string representing a process number or a set of processes. It must
 * be "all", "odd", "even", a number between 1 and <max> or a range with
 * two such numbers delimited by a dash ('-'). On success, it returns
 * 0. otherwise it returns 1 with an error message in <err>.
 *
 * Note: this function can also be used to parse a thread number or a set of
 * threads.
 */
int parse_process_number(const char *arg, unsigned long *proc, int max, int *autoinc, char **err)
{
	if (autoinc) {
		*autoinc = 0;
		if (strncmp(arg, "auto:", 5) == 0) {
			arg += 5;
			*autoinc = 1;
		}
	}

	if (strcmp(arg, "all") == 0)
		*proc |= ~0UL;
	else if (strcmp(arg, "odd") == 0)
		*proc |= ~0UL/3UL; /* 0x555....555 */
	else if (strcmp(arg, "even") == 0)
		*proc |= (~0UL/3UL) << 1; /* 0xAAA...AAA */
	else {
		const char *p, *dash = NULL;
		unsigned int low, high;

		for (p = arg; *p; p++) {
			if (*p == '-' && !dash)
				dash = p;
			else if (!isdigit((unsigned char)*p)) {
				memprintf(err, "'%s' is not a valid number/range.", arg);
				return -1;
			}
		}

		low = high = str2uic(arg);
		if (dash)
			high = ((!*(dash+1)) ? max : str2uic(dash + 1));

		if (high < low) {
			unsigned int swap = low;
			low  = high;
			high = swap;
		}

		if (low < 1 || low > max || high > max) {
			memprintf(err, "'%s' is not a valid number/range."
				  " It supports numbers from 1 to %d.\n",
				  arg, max);
			return 1;
		}

		for (;low <= high; low++)
			*proc |= 1UL << (low-1);
	}
	*proc &= ~0UL >> (LONGBITS - max);

	return 0;
}

#ifdef USE_CPU_AFFINITY
/* Parse cpu sets. Each CPU set is either a unique number between 0 and
 * <LONGBITS> or a range with two such numbers delimited by a dash
 * ('-'). Multiple CPU numbers or ranges may be specified. On success, it
 * returns 0. otherwise it returns 1 with an error message in <err>.
 */
unsigned long parse_cpu_set(const char **args, unsigned long *cpu_set, char **err)
{
	int cur_arg = 0;

	*cpu_set = 0;
	while (*args[cur_arg]) {
		char        *dash;
		unsigned int low, high;

		if (!isdigit((unsigned char)*args[cur_arg])) {
			memprintf(err, "'%s' is not a CPU range.\n", args[cur_arg]);
			return -1;
		}

		low = high = str2uic(args[cur_arg]);
		if ((dash = strchr(args[cur_arg], '-')) != NULL)
			high = ((!*(dash+1)) ? LONGBITS-1 : str2uic(dash + 1));

		if (high < low) {
			unsigned int swap = low;
			low = high;
			high = swap;
		}

		if (high >= LONGBITS) {
			memprintf(err, "supports CPU numbers from 0 to %d.\n", LONGBITS - 1);
			return 1;
		}

		while (low <= high)
			*cpu_set |= 1UL << low++;

		cur_arg++;
	}
	return 0;
}
#endif

void init_default_instance()
{
	init_new_proxy(&defproxy);
	defproxy.mode = PR_MODE_TCP;
	defproxy.disabled = 0;
	defproxy.maxconn = cfg_maxpconn;
	defproxy.conn_retries = CONN_RETRIES;
	defproxy.redispatch_after = 0;
	defproxy.options = PR_O_REUSE_SAFE;
	defproxy.max_out_conns = MAX_SRV_LIST;

	defproxy.defsrv.check.inter = DEF_CHKINTR;
	defproxy.defsrv.check.fastinter = 0;
	defproxy.defsrv.check.downinter = 0;
	defproxy.defsrv.agent.inter = DEF_CHKINTR;
	defproxy.defsrv.agent.fastinter = 0;
	defproxy.defsrv.agent.downinter = 0;
	defproxy.defsrv.check.rise = DEF_RISETIME;
	defproxy.defsrv.check.fall = DEF_FALLTIME;
	defproxy.defsrv.agent.rise = DEF_AGENT_RISETIME;
	defproxy.defsrv.agent.fall = DEF_AGENT_FALLTIME;
	defproxy.defsrv.check.port = 0;
	defproxy.defsrv.agent.port = 0;
	defproxy.defsrv.maxqueue = 0;
	defproxy.defsrv.minconn = 0;
	defproxy.defsrv.maxconn = 0;
	defproxy.defsrv.max_reuse = -1;
	defproxy.defsrv.max_idle_conns = -1;
	defproxy.defsrv.pool_purge_delay = 5000;
	defproxy.defsrv.slowstart = 0;
	defproxy.defsrv.onerror = DEF_HANA_ONERR;
	defproxy.defsrv.consecutive_errors_limit = DEF_HANA_ERRLIMIT;
	defproxy.defsrv.uweight = defproxy.defsrv.iweight = 1;

	defproxy.email_alert.level = LOG_ALERT;
	defproxy.load_server_state_from_file = PR_SRV_STATE_FILE_UNSPEC;
#if defined(USE_QUIC)
	quic_transport_params_init(&defproxy.defsrv.quic_params, 0);
#endif

}

/* Allocate and initialize the frontend of a "peers" section found in
 * file <file> at line <linenum> with <id> as ID.
 * Return 0 if succeeded, -1 if not.
 * Note that this function may be called from "default-server"
 * or "peer" lines.
 */
static int init_peers_frontend(const char *file, int linenum,
                               const char *id, struct peers *peers)
{
	struct proxy *p;

	if (peers->peers_fe) {
		p = peers->peers_fe;
		goto out;
	}

	p = calloc(1, sizeof *p);
	if (!p) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
		return -1;
	}

	init_new_proxy(p);
	peers_setup_frontend(p);
	p->parent = peers;
	/* Finally store this frontend. */
	peers->peers_fe = p;

 out:
	if (id && !p->id)
		p->id = strdup(id);
	free(p->conf.file);
	p->conf.args.file = p->conf.file = strdup(file);
	if (linenum != -1)
		p->conf.args.line = p->conf.line = linenum;

	return 0;
}

/* Only change ->file, ->line and ->arg struct bind_conf member values
 * if already present.
 */
static struct bind_conf *bind_conf_uniq_alloc(struct proxy *p,
                                              const char *file, int line,
                                              const char *arg, struct xprt_ops *xprt)
{
	struct bind_conf *bind_conf;

	if (!LIST_ISEMPTY(&p->conf.bind)) {
		bind_conf = LIST_ELEM((&p->conf.bind)->n, typeof(bind_conf), by_fe);
		free(bind_conf->file);
		bind_conf->file = strdup(file);
		bind_conf->line = line;
		if (arg) {
			free(bind_conf->arg);
			bind_conf->arg = strdup(arg);
		}
	}
	else {
		bind_conf = bind_conf_alloc(p, file, line, arg, xprt);
	}

	return bind_conf;
}

/*
 * Allocate a new struct peer parsed at line <linenum> in file <file>
 * to be added to <peers>.
 * Returns the new allocated structure if succeeded, NULL if not.
 */
static struct peer *cfg_peers_add_peer(struct peers *peers,
                                       const char *file, int linenum,
                                       const char *id, int local)
{
	struct peer *p;

	p = calloc(1, sizeof *p);
	if (!p) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
		return NULL;
	}

	/* the peers are linked backwards first */
	peers->count++;
	p->next = peers->remote;
	peers->remote = p;
	p->conf.file = strdup(file);
	p->conf.line = linenum;
	p->last_change = now.tv_sec;
	p->xprt  = xprt_get(XPRT_RAW);
	p->sock_init_arg = NULL;
	HA_SPIN_INIT(&p->lock);
	if (id)
		p->id = strdup(id);
	if (local) {
		p->local = 1;
		peers->local = p;
	}

	return p;
}

/*
 * Parse a line in a <listen>, <frontend> or <backend> section.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_peers(const char *file, int linenum, char **args, int kwm)
{
	static struct peers *curpeers = NULL;
	struct peer *newpeer = NULL;
	const char *err;
	struct bind_conf *bind_conf;
	struct listener *l;
	int err_code = 0;
	char *errmsg = NULL;
	static int bind_line, peer_line;

	if (strcmp(args[0], "bind") == 0 || strcmp(args[0], "default-bind") == 0) {
		int cur_arg;
		static int kws_dumped;
		struct bind_conf *bind_conf;
		struct bind_kw *kw;

		cur_arg = 1;

		if (init_peers_frontend(file, linenum, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		bind_conf = bind_conf_uniq_alloc(curpeers->peers_fe, file, linenum,
		                                 NULL, xprt_get(XPRT_RAW));
		if (*args[0] == 'b') {
			struct listener *l;

			if (peer_line) {
				ha_alert("parsing [%s:%d] : mixing \"peer\" and \"bind\" line is forbidden\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!str2listener(args[1], curpeers->peers_fe, bind_conf, file, linenum, &errmsg)) {
				if (errmsg && *errmsg) {
					indent_msg(&errmsg, 2);
					ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
				}
				else
					ha_alert("parsing [%s:%d] : '%s %s' : error encountered while parsing listening address %s.\n",
							 file, linenum, args[0], args[1], args[2]);
				err_code |= ERR_FATAL;
				goto out;
			}
			l = LIST_ELEM(bind_conf->listeners.n, typeof(l), by_bind);
			l->maxaccept = 1;
			l->accept = session_accept_fd;
			l->analysers |=  curpeers->peers_fe->fe_req_ana;
			l->default_target = curpeers->peers_fe->default_target;
			l->options |= LI_O_UNLIMITED; /* don't make the peers subject to global limits */
			global.maxsock++; /* for the listening socket */

			bind_line = 1;
			if (cfg_peers->local) {
				newpeer = cfg_peers->local;
			}
			else {
				/* This peer is local.
				 * Note that we do not set the peer ID. This latter is initialized
				 * when parsing "peer" or "server" line.
				 */
				newpeer = cfg_peers_add_peer(curpeers, file, linenum, NULL, 1);
				if (!newpeer) {
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}
			}
			newpeer->addr = l->rx.addr;
			newpeer->proto = l->rx.proto;
			cur_arg++;
		}

		while (*args[cur_arg] && (kw = bind_find_kw(args[cur_arg]))) {
			int ret;

			ret = kw->parse(args, cur_arg, curpeers->peers_fe, bind_conf, &errmsg);
			err_code |= ret;
			if (ret) {
				if (errmsg && *errmsg) {
					indent_msg(&errmsg, 2);
					ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
				}
				else
					ha_alert("parsing [%s:%d]: error encountered while processing '%s'\n",
					         file, linenum, args[cur_arg]);
				if (ret & ERR_FATAL)
					goto out;
			}
			cur_arg += 1 + kw->skip;
		}
		if (*args[cur_arg] != 0) {
			char *kws = NULL;

			if (!kws_dumped) {
				kws_dumped = 1;
				bind_dump_kws(&kws);
				indent_msg(&kws, 4);
			}
			ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section.%s%s\n",
			         file, linenum, args[cur_arg], cursection,
			         kws ? " Registered keywords :" : "", kws ? kws: "");
			free(kws);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "default-server") == 0) {
		if (init_peers_frontend(file, -1, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		err_code |= parse_server(file, linenum, args, curpeers->peers_fe, NULL, 0, 1, 1);
	}
	else if (strcmp(args[0], "log") == 0) {
		if (init_peers_frontend(file, linenum, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (!parse_logsrv(args, &curpeers->peers_fe->logsrvs, (kwm == KWM_NO), &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "peers") == 0) { /* new peers section */
		/* Initialize these static variables when entering a new "peers" section*/
		bind_line = peer_line = 0;
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for peers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		for (curpeers = cfg_peers; curpeers != NULL; curpeers = curpeers->next) {
			/*
			 * If there are two proxies with the same name only following
			 * combinations are allowed:
			 */
			if (strcmp(curpeers->id, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: peers section '%s' has the same name as another peers section declared at %s:%d.\n",
					 file, linenum, args[1], curpeers->conf.file, curpeers->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((curpeers = calloc(1, sizeof(*curpeers))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curpeers->next = cfg_peers;
		cfg_peers = curpeers;
		curpeers->conf.file = strdup(file);
		curpeers->conf.line = linenum;
		curpeers->last_change = now.tv_sec;
		curpeers->id = strdup(args[1]);
		curpeers->disabled = 0;
	}
	else if (strcmp(args[0], "peer") == 0 ||
	         strcmp(args[0], "server") == 0) { /* peer or server definition */
		int local_peer, peer;

		peer = *args[0] == 'p';
		local_peer = strcmp(args[1], localpeer) == 0;
		/* The local peer may have already partially been parsed on a "bind" line. */
		if (*args[0] == 'p') {
			if (bind_line) {
				ha_alert("parsing [%s:%d] : mixing \"peer\" and \"bind\" line is forbidden\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			peer_line = 1;
		}
		if (cfg_peers->local && !cfg_peers->local->id && local_peer) {
			/* The local peer has already been initialized on a "bind" line.
			 * Let's use it and store its ID.
			 */
			newpeer = cfg_peers->local;
			newpeer->id = strdup(localpeer);
		}
		else {
			if (local_peer && cfg_peers->local) {
				ha_alert("parsing [%s:%d] : '%s %s' : local peer name already referenced at %s:%d. %s\n",
				         file, linenum, args[0], args[1],
				 curpeers->peers_fe->conf.file, curpeers->peers_fe->conf.line, cfg_peers->local->id);
				err_code |= ERR_FATAL;
				goto out;
			}
			newpeer = cfg_peers_add_peer(curpeers, file, linenum, args[1], local_peer);
			if (!newpeer) {
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		}

		/* Line number and peer ID are updated only if this peer is the local one. */
		if (init_peers_frontend(file,
		                        newpeer->local ? linenum: -1,
		                        newpeer->local ? newpeer->id : NULL,
		                        curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* This initializes curpeer->peers->peers_fe->srv.
		 * The server address is parsed only if we are parsing a "peer" line,
		 * or if we are parsing a "server" line and the current peer is not the local one.
		 */
		err_code |= parse_server(file, linenum, args, curpeers->peers_fe, NULL, peer || !local_peer, 1, 1);
		if (!curpeers->peers_fe->srv) {
			/* Remove the newly allocated peer. */
			if (newpeer != curpeers->local) {
				struct peer *p;

				p = curpeers->remote;
				curpeers->remote = curpeers->remote->next;
				free(p->id);
				free(p);
			}
			goto out;
		}

		/* If the peer address has just been parsed, let's copy it to <newpeer>
		 * and initializes ->proto.
		 */
		if (peer || !local_peer) {
			newpeer->addr = curpeers->peers_fe->srv->addr;
			newpeer->proto = protocol_by_family(newpeer->addr.ss_family);
		}

		newpeer->xprt  = xprt_get(XPRT_RAW);
		newpeer->sock_init_arg = NULL;
		HA_SPIN_INIT(&newpeer->lock);

		newpeer->srv = curpeers->peers_fe->srv;
		if (!newpeer->local)
			goto out;

		/* The lines above are reserved to "peer" lines. */
		if (*args[0] == 's')
			goto out;

		bind_conf = bind_conf_uniq_alloc(curpeers->peers_fe, file, linenum, args[2], xprt_get(XPRT_RAW));

		if (!str2listener(args[2], curpeers->peers_fe, bind_conf, file, linenum, &errmsg)) {
			if (errmsg && *errmsg) {
				indent_msg(&errmsg, 2);
				ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			}
			else
				ha_alert("parsing [%s:%d] : '%s %s' : error encountered while parsing listening address %s.\n",
				         file, linenum, args[0], args[1], args[2]);
			err_code |= ERR_FATAL;
			goto out;
		}

		l = LIST_ELEM(bind_conf->listeners.n, typeof(l), by_bind);
		l->maxaccept = 1;
		l->accept = session_accept_fd;
		l->analysers |=  curpeers->peers_fe->fe_req_ana;
		l->default_target = curpeers->peers_fe->default_target;
		l->options |= LI_O_UNLIMITED; /* don't make the peers subject to global limits */
		global.maxsock++; /* for the listening socket */
	}
	else if (strcmp(args[0], "table") == 0) {
		struct stktable *t, *other;
		char *id;
		size_t prefix_len;

		/* Line number and peer ID are updated only if this peer is the local one. */
		if (init_peers_frontend(file, -1, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		other = stktable_find_by_name(args[1]);
		if (other) {
			ha_alert("parsing [%s:%d] : stick-table name '%s' conflicts with table declared in %s '%s' at %s:%d.\n",
				 file, linenum, args[1],
				 other->proxy ? proxy_cap_str(other->proxy->cap) : "peers",
				 other->proxy ? other->id : other->peers.p->id,
				 other->conf.file, other->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* Build the stick-table name, concatenating the "peers" section name
		 * followed by a '/' character and the table name argument.
		 */
		chunk_reset(&trash);
		if (!chunk_strcpy(&trash, curpeers->id)) {
			ha_alert("parsing [%s:%d]: '%s %s' : stick-table name too long.\n",
			         file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		prefix_len = trash.data;
		if (!chunk_memcat(&trash, "/", 1) || !chunk_strcat(&trash, args[1])) {
			ha_alert("parsing [%s:%d]: '%s %s' : stick-table name too long.\n",
			         file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		t = calloc(1, sizeof *t);
		id = strdup(trash.area);
		if (!t || !id) {
			ha_alert("parsing [%s:%d]: '%s %s' : memory allocation failed\n",
			         file, linenum, args[0], args[1]);
			free(t);
			free(id);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= parse_stick_table(file, linenum, args, t, id, id + prefix_len, curpeers);
		if (err_code & ERR_FATAL) {
			free(t);
			free(id);
			goto out;
		}

		stktable_store_name(t);
		t->next = stktables_list;
		stktables_list = t;
	}
	else if (strcmp(args[0], "disabled") == 0) {  /* disables this peers section */
		curpeers->disabled = 1;
	}
	else if (strcmp(args[0], "enabled") == 0) {  /* enables this peers section (used to revert a disabled default) */
		curpeers->disabled = 0;
	}
	else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

out:
	free(errmsg);
	return err_code;
}

/*
 * Parse a <resolvers> section.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_resolvers(const char *file, int linenum, char **args, int kwm)
{
	static struct dns_resolvers *curr_resolvers = NULL;
	const char *err;
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "resolvers") == 0) { /* new resolvers section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for resolvers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		list_for_each_entry(curr_resolvers, &dns_resolvers, list) {
			/* Error if two resolvers owns the same name */
			if (strcmp(curr_resolvers->id, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: resolvers '%s' has same name as another resolvers (declared at %s:%d).\n",
					 file, linenum, args[1], curr_resolvers->conf.file, curr_resolvers->conf.line);
				err_code |= ERR_ALERT | ERR_ABORT;
			}
		}

		if ((curr_resolvers = calloc(1, sizeof(*curr_resolvers))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* default values */
		LIST_ADDQ(&dns_resolvers, &curr_resolvers->list);
		curr_resolvers->conf.file = strdup(file);
		curr_resolvers->conf.line = linenum;
		curr_resolvers->id = strdup(args[1]);
		curr_resolvers->query_ids = EB_ROOT;
		/* default maximum response size */
		curr_resolvers->accepted_payload_size = 512;
		/* default hold period for nx, other, refuse and timeout is 30s */
		curr_resolvers->hold.nx = 30000;
		curr_resolvers->hold.other = 30000;
		curr_resolvers->hold.refused = 30000;
		curr_resolvers->hold.timeout = 30000;
		curr_resolvers->hold.obsolete = 0;
		/* default hold period for valid is 10s */
		curr_resolvers->hold.valid = 10000;
		curr_resolvers->timeout.resolve = 1000;
		curr_resolvers->timeout.retry   = 1000;
		curr_resolvers->resolve_retries = 3;
		curr_resolvers->nb_nameservers  = 0;
		LIST_INIT(&curr_resolvers->nameservers);
		LIST_INIT(&curr_resolvers->resolutions.curr);
		LIST_INIT(&curr_resolvers->resolutions.wait);
		HA_SPIN_INIT(&curr_resolvers->lock);
	}
	else if (strcmp(args[0], "nameserver") == 0) { /* nameserver definition */
		struct dns_nameserver *newnameserver = NULL;
		struct sockaddr_storage *sk;
		int port1, port2;

		if (!*args[2]) {
			ha_alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
				 file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		list_for_each_entry(newnameserver, &curr_resolvers->nameservers, list) {
			/* Error if two resolvers owns the same name */
			if (strcmp(newnameserver->id, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: nameserver '%s' has same name as another nameserver (declared at %s:%d).\n",
					 file, linenum, args[1], newnameserver->conf.file, newnameserver->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((newnameserver = calloc(1, sizeof(*newnameserver))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* the nameservers are linked backward first */
		LIST_ADDQ(&curr_resolvers->nameservers, &newnameserver->list);
		newnameserver->resolvers = curr_resolvers;
		newnameserver->conf.file = strdup(file);
		newnameserver->conf.line = linenum;
		newnameserver->id = strdup(args[1]);

		sk = str2sa_range(args[2], NULL, &port1, &port2, NULL, NULL,
		                  &errmsg, NULL, NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_DGRAM);
		if (!sk) {
			ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		newnameserver->addr = *sk;
	}
	else if (strcmp(args[0], "parse-resolv-conf") == 0) {
		struct dns_nameserver *newnameserver = NULL;
		const char *whitespace = "\r\n\t ";
		char *resolv_line = NULL;
		int resolv_linenum = 0;
		FILE *f = NULL;
		char *address = NULL;
		struct sockaddr_storage *sk = NULL;
		struct protocol *proto;
		int duplicate_name = 0;

		if ((resolv_line = malloc(sizeof(*resolv_line) * LINESIZE)) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto resolv_out;
		}

		if ((f = fopen("/etc/resolv.conf", "r")) == NULL) {
			ha_alert("parsing [%s:%d] : failed to open /etc/resolv.conf.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto resolv_out;
		}

		sk = calloc(1, sizeof(*sk));
		if (sk == NULL) {
			ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n",
				 resolv_linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto resolv_out;
		}

		while (fgets(resolv_line, LINESIZE, f) != NULL) {
			resolv_linenum++;
			if (strncmp(resolv_line, "nameserver", 10) != 0)
				continue;

			address = strtok(resolv_line + 10, whitespace);
			if (address == resolv_line + 10)
				continue;

			if (address == NULL) {
				ha_warning("parsing [/etc/resolv.conf:%d] : nameserver line is missing address.\n",
					   resolv_linenum);
				err_code |= ERR_WARN;
				continue;
			}

			duplicate_name = 0;
			list_for_each_entry(newnameserver, &curr_resolvers->nameservers, list) {
				if (strcmp(newnameserver->id, address) == 0) {
					ha_warning("Parsing [/etc/resolv.conf:%d] : generated name for /etc/resolv.conf nameserver '%s' conflicts with another nameserver (declared at %s:%d), it appears to be a duplicate and will be excluded.\n",
						 resolv_linenum, address, newnameserver->conf.file, newnameserver->conf.line);
					err_code |= ERR_WARN;
					duplicate_name = 1;
				}
			}

			if (duplicate_name)
				continue;

			memset(sk, 0, sizeof(*sk));
			if (!str2ip2(address, sk, 1)) {
				ha_warning("parsing [/etc/resolv.conf:%d] : address '%s' could not be recognized, nameserver will be excluded.\n",
					   resolv_linenum, address);
				err_code |= ERR_WARN;
				continue;
			}

			set_host_port(sk, 53);

			proto = protocol_by_family(sk->ss_family);
			if (!proto || !proto->connect) {
				ha_warning("parsing [/etc/resolv.conf:%d] : '%s' : connect() not supported for this address family.\n",
					   resolv_linenum, address);
				err_code |= ERR_WARN;
				continue;
			}

			if ((newnameserver = calloc(1, sizeof(*newnameserver))) == NULL) {
				ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n", resolv_linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto resolv_out;
			}

			newnameserver->conf.file = strdup("/etc/resolv.conf");
			if (newnameserver->conf.file == NULL) {
				ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n", resolv_linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(newnameserver);
				goto resolv_out;
			}

			newnameserver->id = strdup(address);
			if (newnameserver->id == NULL) {
				ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n", resolv_linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				free((char *)newnameserver->conf.file);
				free(newnameserver);
				goto resolv_out;
			}

			newnameserver->resolvers = curr_resolvers;
			newnameserver->conf.line = resolv_linenum;
			newnameserver->addr = *sk;

			LIST_ADDQ(&curr_resolvers->nameservers, &newnameserver->list);
		}

resolv_out:
		free(sk);
		free(resolv_line);
		if (f != NULL)
			fclose(f);
	}
	else if (strcmp(args[0], "hold") == 0) { /* hold periods */
		const char *res;
		unsigned int time;

		if (!*args[2]) {
			ha_alert("parsing [%s:%d] : '%s' expects an <event> and a <time> as arguments.\n",
				 file, linenum, args[0]);
			ha_alert("<event> can be either 'valid', 'nx', 'refused', 'timeout', or 'other'\n");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		res = parse_time_err(args[2], &time, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER) {
			ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s>, maximum value is 2147483647 ms (~24.8 days).\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res == PARSE_TIME_UNDER) {
			ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res) {
			ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
				 file, linenum, *res, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strcmp(args[1], "nx") == 0)
			curr_resolvers->hold.nx = time;
		else if (strcmp(args[1], "other") == 0)
			curr_resolvers->hold.other = time;
		else if (strcmp(args[1], "refused") == 0)
			curr_resolvers->hold.refused = time;
		else if (strcmp(args[1], "timeout") == 0)
			curr_resolvers->hold.timeout = time;
		else if (strcmp(args[1], "valid") == 0)
			curr_resolvers->hold.valid = time;
		else if (strcmp(args[1], "obsolete") == 0)
			curr_resolvers->hold.obsolete = time;
		else {
			ha_alert("parsing [%s:%d] : '%s' unknown <event>: '%s', expects either 'nx', 'timeout', 'valid', 'obsolete' or 'other'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

	}
	else if (strcmp(args[0], "accepted_payload_size") == 0) {
		int i = 0;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects <nb> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		i = atoi(args[1]);
		if (i < DNS_HEADER_SIZE || i > DNS_MAX_UDP_MESSAGE) {
			ha_alert("parsing [%s:%d] : '%s' must be between %d and %d inclusive (was %s).\n",
				 file, linenum, args[0], DNS_HEADER_SIZE, DNS_MAX_UDP_MESSAGE, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curr_resolvers->accepted_payload_size = i;
	}
	else if (strcmp(args[0], "resolution_pool_size") == 0) {
		ha_alert("parsing [%s:%d] : '%s' directive is not supported anymore (it never appeared in a stable release).\n",
			   file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "resolve_retries") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects <nb> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curr_resolvers->resolve_retries = atoi(args[1]);
	}
	else if (strcmp(args[0], "timeout") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects 'retry' or 'resolve' and <time> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (strcmp(args[1], "retry") == 0 ||
			 strcmp(args[1], "resolve") == 0) {
			const char *res;
			unsigned int tout;

			if (!*args[2]) {
				ha_alert("parsing [%s:%d] : '%s %s' expects <time> as argument.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			res = parse_time_err(args[2], &tout, TIME_UNIT_MS);
			if (res == PARSE_TIME_OVER) {
				ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s %s>, maximum value is 2147483647 ms (~24.8 days).\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (res == PARSE_TIME_UNDER) {
				ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s %s>, minimum non-null value is 1 ms.\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (res) {
				ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s %s>.\n",
					 file, linenum, *res, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (args[1][2] == 't')
				curr_resolvers->timeout.retry = tout;
			else
				curr_resolvers->timeout.resolve = tout;
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' expects 'retry' or 'resolve' and <time> as arguments got '%s'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

 out:
	free(errmsg);
	return err_code;
}

/*
 * Parse a line in a <listen>, <frontend> or <backend> section.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_mailers(const char *file, int linenum, char **args, int kwm)
{
	static struct mailers *curmailers = NULL;
	struct mailer *newmailer = NULL;
	const char *err;
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "mailers") == 0) { /* new mailers section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for mailers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		for (curmailers = mailers; curmailers != NULL; curmailers = curmailers->next) {
			/*
			 * If there are two proxies with the same name only following
			 * combinations are allowed:
			 */
			if (strcmp(curmailers->id, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: mailers section '%s' has the same name as another mailers section declared at %s:%d.\n",
					 file, linenum, args[1], curmailers->conf.file, curmailers->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((curmailers = calloc(1, sizeof(*curmailers))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curmailers->next = mailers;
		mailers = curmailers;
		curmailers->conf.file = strdup(file);
		curmailers->conf.line = linenum;
		curmailers->id = strdup(args[1]);
		curmailers->timeout.mail = DEF_MAILALERTTIME;/* XXX: Would like to Skip to the next alert, if any, ASAP.
			* But need enough time so that timeouts don't occur
			* during tcp procssing. For now just us an arbitrary default. */
	}
	else if (strcmp(args[0], "mailer") == 0) { /* mailer definition */
		struct sockaddr_storage *sk;
		int port1, port2;
		struct protocol *proto;

		if (!*args[2]) {
			ha_alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
				 file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((newmailer = calloc(1, sizeof(*newmailer))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* the mailers are linked backwards first */
		curmailers->count++;
		newmailer->next = curmailers->mailer_list;
		curmailers->mailer_list = newmailer;
		newmailer->mailers = curmailers;
		newmailer->conf.file = strdup(file);
		newmailer->conf.line = linenum;

		newmailer->id = strdup(args[1]);

		sk = str2sa_range(args[2], NULL, &port1, &port2, NULL, &proto,
		                  &errmsg, NULL, NULL,
		                  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_STREAM | PA_O_XPRT | PA_O_CONNECT);
		if (!sk) {
			ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (proto->sock_prot != IPPROTO_TCP) {
			ha_alert("parsing [%s:%d] : '%s %s' : TCP not supported for this address family.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		newmailer->addr = *sk;
		newmailer->proto = proto;
		newmailer->xprt  = xprt_get(XPRT_RAW);
		newmailer->sock_init_arg = NULL;
	}
	else if (strcmp(args[0], "timeout") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects 'mail' and <time> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (strcmp(args[1], "mail") == 0) {
			const char *res;
			unsigned int timeout_mail;
			if (!*args[2]) {
				ha_alert("parsing [%s:%d] : '%s %s' expects <time> as argument.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			res = parse_time_err(args[2], &timeout_mail, TIME_UNIT_MS);
			if (res == PARSE_TIME_OVER) {
				ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s %s>, maximum value is 2147483647 ms (~24.8 days).\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (res == PARSE_TIME_UNDER) {
				ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s %s>, minimum non-null value is 1 ms.\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (res) {
				ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s %s>.\n",
					 file, linenum, *res, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			curmailers->timeout.mail = timeout_mail;
		} else {
			ha_alert("parsing [%s:%d] : '%s' expects 'mail' and <time> as arguments got '%s'.\n",
				file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

out:
	free(errmsg);
	return err_code;
}

void free_email_alert(struct proxy *p)
{
	free(p->email_alert.mailers.name);
	p->email_alert.mailers.name = NULL;
	free(p->email_alert.from);
	p->email_alert.from = NULL;
	free(p->email_alert.to);
	p->email_alert.to = NULL;
	free(p->email_alert.myhostname);
	p->email_alert.myhostname = NULL;
}


int
cfg_parse_netns(const char *file, int linenum, char **args, int kwm)
{
#ifdef USE_NS
	const char *err;
	const char *item = args[0];

	if (strcmp(item, "namespace_list") == 0) {
		return 0;
	}
	else if (strcmp(item, "namespace") == 0) {
		size_t idx = 1;
		const char *current;
		while (*(current = args[idx++])) {
			err = invalid_char(current);
			if (err) {
				ha_alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
					 file, linenum, *err, item, current);
				return ERR_ALERT | ERR_FATAL;
			}

			if (netns_store_lookup(current, strlen(current))) {
				ha_alert("parsing [%s:%d]: Namespace '%s' is already added.\n",
					 file, linenum, current);
				return ERR_ALERT | ERR_FATAL;
			}
			if (!netns_store_insert(current)) {
				ha_alert("parsing [%s:%d]: Cannot open namespace '%s'.\n",
					 file, linenum, current);
				return ERR_ALERT | ERR_FATAL;
			}
		}
	}

	return 0;
#else
	ha_alert("parsing [%s:%d]: namespace support is not compiled in.",
		 file, linenum);
	return ERR_ALERT | ERR_FATAL;
#endif
}

int
cfg_parse_users(const char *file, int linenum, char **args, int kwm)
{

	int err_code = 0;
	const char *err;

	if (strcmp(args[0], "userlist") == 0) {		/* new userlist */
		struct userlist *newul;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (newul = userlist; newul; newul = newul->next)
			if (strcmp(newul->name, args[1]) == 0) {
				ha_warning("parsing [%s:%d]: ignoring duplicated userlist '%s'.\n",
					   file, linenum, args[1]);
				err_code |= ERR_WARN;
				goto out;
			}

		newul = calloc(1, sizeof(*newul));
		if (!newul) {
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		newul->name = strdup(args[1]);
		if (!newul->name) {
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			free(newul);
			goto out;
		}

		newul->next = userlist;
		userlist = newul;

	} else if (strcmp(args[0], "group") == 0) {  	/* new group */
		int cur_arg;
		const char *err;
		struct auth_groups *ag;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!userlist)
			goto out;

		for (ag = userlist->groups; ag; ag = ag->next)
			if (strcmp(ag->name, args[1]) == 0) {
				ha_warning("parsing [%s:%d]: ignoring duplicated group '%s' in userlist '%s'.\n",
					   file, linenum, args[1], userlist->name);
				err_code |= ERR_ALERT;
				goto out;
			}

		ag = calloc(1, sizeof(*ag));
		if (!ag) {
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		ag->name = strdup(args[1]);
		if (!ag->name) {
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			free(ag);
			goto out;
		}

		cur_arg = 2;

		while (*args[cur_arg]) {
			if (strcmp(args[cur_arg], "users") == 0) {
				ag->groupusers = strdup(args[cur_arg + 1]);
				cur_arg += 2;
				continue;
			} else {
				ha_alert("parsing [%s:%d]: '%s' only supports 'users' option.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(ag->groupusers);
				free(ag->name);
				free(ag);
				goto out;
			}
		}

		ag->next = userlist->groups;
		userlist->groups = ag;

	} else if (strcmp(args[0], "user") == 0) {		/* new user */
		struct auth_users *newuser;
		int cur_arg;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (!userlist)
			goto out;

		for (newuser = userlist->users; newuser; newuser = newuser->next)
			if (strcmp(newuser->user, args[1]) == 0) {
				ha_warning("parsing [%s:%d]: ignoring duplicated user '%s' in userlist '%s'.\n",
					   file, linenum, args[1], userlist->name);
				err_code |= ERR_ALERT;
				goto out;
			}

		newuser = calloc(1, sizeof(*newuser));
		if (!newuser) {
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		newuser->user = strdup(args[1]);

		newuser->next = userlist->users;
		userlist->users = newuser;

		cur_arg = 2;

		while (*args[cur_arg]) {
			if (strcmp(args[cur_arg], "password") == 0) {
#ifdef USE_LIBCRYPT
				if (!crypt("", args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d]: the encrypted password used for user '%s' is not supported by crypt(3).\n",
						 file, linenum, newuser->user);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
#else
				ha_warning("parsing [%s:%d]: no crypt(3) support compiled, encrypted passwords will not work.\n",
					   file, linenum);
				err_code |= ERR_ALERT;
#endif
				newuser->pass = strdup(args[cur_arg + 1]);
				cur_arg += 2;
				continue;
			} else if (strcmp(args[cur_arg], "insecure-password") == 0) {
				newuser->pass = strdup(args[cur_arg + 1]);
				newuser->flags |= AU_O_INSECURE;
				cur_arg += 2;
				continue;
			} else if (strcmp(args[cur_arg], "groups") == 0) {
				newuser->u.groups_names = strdup(args[cur_arg + 1]);
				cur_arg += 2;
				continue;
			} else {
				ha_alert("parsing [%s:%d]: '%s' only supports 'password', 'insecure-password' and 'groups' options.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
	} else {
		ha_alert("parsing [%s:%d]: unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "users");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

out:
	return err_code;
}

int
cfg_parse_scope(const char *file, int linenum, char *line)
{
	char *beg, *end, *scope = NULL;
	int err_code = 0;
	const char *err;

	beg = line + 1;
	end = strchr(beg, ']');

	/* Detect end of scope declaration */
	if (!end || end == beg) {
		ha_alert("parsing [%s:%d] : empty scope name is forbidden.\n",
			 file, linenum);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	/* Get scope name and check its validity */
	scope = my_strndup(beg, end-beg);
	err = invalid_char(scope);
	if (err) {
		ha_alert("parsing [%s:%d] : character '%c' is not permitted in a scope name.\n",
			 file, linenum, *err);
		err_code |= ERR_ALERT | ERR_ABORT;
		goto out;
	}

	/* Be sure to have a scope declaration alone on its line */
	line = end+1;
	while (isspace((unsigned char)*line))
		line++;
	if (*line && *line != '#' && *line != '\n' && *line != '\r') {
		ha_alert("parsing [%s:%d] : character '%c' is not permitted after scope declaration.\n",
			 file, linenum, *line);
		err_code |= ERR_ALERT | ERR_ABORT;
		goto out;
	}

	/* We have a valid scope declaration, save it */
	free(cfg_scope);
	cfg_scope = scope;
	scope = NULL;

  out:
	free(scope);
	return err_code;
}

int
cfg_parse_track_sc_num(unsigned int *track_sc_num,
                       const char *arg, const char *end, char **errmsg)
{
	const char *p;
	unsigned int num;

	p = arg;
	num = read_uint64(&arg, end);

	if (arg != end) {
		memprintf(errmsg, "Wrong track-sc number '%s'", p);
		return -1;
	}

	if (num >= MAX_SESS_STKCTR) {
		memprintf(errmsg, "%u track-sc number exceeding "
		          "%d (MAX_SESS_STKCTR-1) value", num, MAX_SESS_STKCTR - 1);
		return -1;
	}

	*track_sc_num = num;
	return 0;
}

/*
 * This function reads and parses the configuration file given in the argument.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int readcfgfile(const char *file)
{
	char *thisline;
	int linesize = LINESIZE;
	FILE *f;
	int linenum = 0;
	int err_code = 0;
	struct cfg_section *cs = NULL, *pcs = NULL;
	struct cfg_section *ics;
	int readbytes = 0;
	char *outline = NULL;
	size_t outlen = 0;
	size_t outlinesize = 0;
	int fatal = 0;
	int missing_lf = -1;

	if ((thisline = malloc(sizeof(*thisline) * linesize)) == NULL) {
		ha_alert("parsing [%s] : out of memory.\n", file);
		return -1;
	}

	if ((f=fopen(file,"r")) == NULL) {
		free(thisline);
		return -1;
	}

next_line:
	while (fgets(thisline + readbytes, linesize - readbytes, f) != NULL) {
		int arg, kwm = KWM_STD;
		char *end;
		char *args[MAX_LINE_ARGS + 1];
		char *line = thisline;

		if (missing_lf != -1) {
			ha_alert("parsing [%s:%d]: Stray NUL character at position %d.\n",
			         file, linenum, (missing_lf + 1));
			err_code |= ERR_ALERT | ERR_FATAL;
			missing_lf = -1;
			break;
		}

		linenum++;

		if (fatal >= 50) {
			ha_alert("parsing [%s:%d]: too many fatal errors (%d), stopping now.\n", file, linenum, fatal);
			break;
		}

		end = line + strlen(line);

		if (end-line == linesize-1 && *(end-1) != '\n') {
			/* Check if we reached the limit and the last char is not \n.
			 * Watch out for the last line without the terminating '\n'!
			 */
			char *newline;
			int newlinesize = linesize * 2;

			newline = realloc(thisline, sizeof(*thisline) * newlinesize);
			if (newline == NULL) {
				ha_alert("parsing [%s:%d]: line too long, cannot allocate memory.\n",
					 file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				linenum--;
				continue;
			}

			readbytes = linesize - 1;
			linesize = newlinesize;
			thisline = newline;
			linenum--;
			continue;
		}

		readbytes = 0;

		if (end > line && *(end-1) == '\n') {
			/* kill trailing LF */
			*(end - 1) = 0;
		}
		else {
			/* mark this line as truncated */
			missing_lf = end - line;
		}

		/* skip leading spaces */
		while (isspace((unsigned char)*line))
			line++;

		if (*line == '[') {/* This is the beginning if a scope */
			err_code |= cfg_parse_scope(file, linenum, line);
			goto next_line;
		}

		while (1) {
			uint32_t err;
			char *errptr;

			arg = MAX_LINE_ARGS + 1;
			outlen = outlinesize;
			err = parse_line(line, outline, &outlen, args, &arg,
					 PARSE_OPT_ENV | PARSE_OPT_DQUOTE | PARSE_OPT_SQUOTE |
					 PARSE_OPT_BKSLASH | PARSE_OPT_SHARP | PARSE_OPT_WORD_EXPAND,
					 &errptr);

			if (err & PARSE_ERR_QUOTE) {
				size_t newpos = sanitize_for_printing(line, errptr - line, 80);

				ha_alert("parsing [%s:%d]: unmatched quote at position %d:\n"
					 "  %s\n  %*s\n", file, linenum, (int)(errptr-thisline+1), line, (int)(newpos+1), "^");
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				goto next_line;
			}

			if (err & PARSE_ERR_BRACE) {
				size_t newpos = sanitize_for_printing(line, errptr - line, 80);

				ha_alert("parsing [%s:%d]: unmatched brace in environment variable name at position %d:\n"
					 "  %s\n  %*s\n", file, linenum, (int)(errptr-thisline+1), line, (int)(newpos+1), "^");
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				goto next_line;
			}

			if (err & PARSE_ERR_VARNAME) {
				size_t newpos = sanitize_for_printing(line, errptr - line, 80);

				ha_alert("parsing [%s:%d]: forbidden first char in environment variable name at position %d:\n"
					 "  %s\n  %*s\n", file, linenum, (int)(errptr-thisline+1), line, (int)(newpos+1), "^");
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				goto next_line;
			}

			if (err & PARSE_ERR_HEX) {
				size_t newpos = sanitize_for_printing(line, errptr - line, 80);

				ha_alert("parsing [%s:%d]: truncated or invalid hexadecimal sequence at position %d:\n"
					 "  %s\n  %*s\n", file, linenum, (int)(errptr-thisline+1), line, (int)(newpos+1), "^");
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				goto next_line;
			}

			if (err & PARSE_ERR_WRONG_EXPAND) {
				size_t newpos = sanitize_for_printing(line, errptr - line, 80);

				ha_alert("parsing [%s:%d]: truncated or invalid word expansion sequence at position %d:\n"
					 "  %s\n  %*s\n", file, linenum, (int)(errptr-thisline+1), line, (int)(newpos+1), "^");
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				goto next_line;
			}

			if (err & (PARSE_ERR_TOOLARGE|PARSE_ERR_OVERLAP)) {
				outlinesize = (outlen + 1023) & -1024;
				outline = realloc(outline, outlinesize);
				if (outline == NULL) {
					ha_alert("parsing [%s:%d]: line too long, cannot allocate memory.\n",
						 file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL;
					fatal++;
					goto next_line;
				}
				/* try again */
				continue;
			}

			if (err & PARSE_ERR_TOOMANY) {
				/* only check this *after* being sure the output is allocated */
				ha_alert("parsing [%s:%d]: too many words, truncating after word %d, position %ld: <%s>.\n",
					 file, linenum, MAX_LINE_ARGS, (long)(args[MAX_LINE_ARGS-1] - outline + 1), args[MAX_LINE_ARGS-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				goto next_line;
			}

			/* everything's OK */
			break;
		}

		/* empty line */
		if (!**args)
			continue;

		/* check for keyword modifiers "no" and "default" */
		if (strcmp(args[0], "no") == 0) {
			char *tmp;

			kwm = KWM_NO;
			tmp = args[0];
			for (arg=0; *args[arg+1]; arg++)
				args[arg] = args[arg+1];		// shift args after inversion
			*tmp = '\0'; 					// fix the next arg to \0
			args[arg] = tmp;
		}
		else if (strcmp(args[0], "default") == 0) {
			kwm = KWM_DEF;
			for (arg=0; *args[arg+1]; arg++)
				args[arg] = args[arg+1];		// shift args after inversion
		}

		if (kwm != KWM_STD && strcmp(args[0], "option") != 0 &&
		    strcmp(args[0], "log") != 0 && strcmp(args[0], "busy-polling") != 0 &&
		    strcmp(args[0], "set-dumpable") != 0 && strcmp(args[0], "strict-limits") != 0 &&
		    strcmp(args[0], "insecure-fork-wanted") != 0) {
			ha_alert("parsing [%s:%d]: negation/default currently "
				 "supported only for options, log, busy-polling, "
				 "set-dumpable, strict-limits, and insecure-fork-wanted.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			fatal++;
		}

		/* detect section start */
		list_for_each_entry(ics, &sections, list) {
			if (strcmp(args[0], ics->section_name) == 0) {
				cursection = ics->section_name;
				pcs = cs;
				cs = ics;
				break;
			}
		}

		if (pcs && pcs->post_section_parser) {
			int status;

			status = pcs->post_section_parser();
			err_code |= status;
			if (status & ERR_FATAL)
				fatal++;

			if (err_code & ERR_ABORT)
				goto err;
		}
		pcs = NULL;

		if (!cs) {
			ha_alert("parsing [%s:%d]: unknown keyword '%s' out of section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			fatal++;
		} else {
			int status;

			status = cs->section_parser(file, linenum, args, kwm);
			err_code |= status;
			if (status & ERR_FATAL)
				fatal++;

			if (err_code & ERR_ABORT)
				goto err;
		}
	}

	if (missing_lf != -1) {
		ha_alert("parsing [%s:%d]: Missing LF on last line, file might have been truncated at position %d.\n",
		         file, linenum, (missing_lf + 1));
		err_code |= ERR_ALERT | ERR_FATAL;
	}

	if (cs && cs->post_section_parser)
		err_code |= cs->post_section_parser();

err:
	free(cfg_scope);
	cfg_scope = NULL;
	cursection = NULL;
	free(thisline);
	free(outline);
	fclose(f);
	return err_code;
}

/* This function propagates processes from frontend <from> to backend <to> so
 * that it is always guaranteed that a backend pointed to by a frontend is
 * bound to all of its processes. After that, if the target is a "listen"
 * instance, the function recursively descends the target's own targets along
 * default_backend and use_backend rules. Since the bits are
 * checked first to ensure that <to> is already bound to all processes of
 * <from>, there is no risk of looping and we ensure to follow the shortest
 * path to the destination.
 *
 * It is possible to set <to> to NULL for the first call so that the function
 * takes care of visiting the initial frontend in <from>.
 *
 * It is important to note that the function relies on the fact that all names
 * have already been resolved.
 */
void propagate_processes(struct proxy *from, struct proxy *to)
{
	struct switching_rule *rule;

	if (to) {
		/* check whether we need to go down */
		if (from->bind_proc &&
		    (from->bind_proc & to->bind_proc) == from->bind_proc)
			return;

		if (!from->bind_proc && !to->bind_proc)
			return;

		to->bind_proc = from->bind_proc ?
			(to->bind_proc | from->bind_proc) : 0;

		/* now propagate down */
		from = to;
	}

	if (!(from->cap & PR_CAP_FE))
		return;

	if (from->disabled)
		return;

	/* default_backend */
	if (from->defbe.be)
		propagate_processes(from, from->defbe.be);

	/* use_backend */
	list_for_each_entry(rule, &from->switching_rules, list) {
		if (rule->dynamic)
			continue;
		to = rule->be.backend;
		propagate_processes(from, to);
	}
}

/*
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int check_config_validity()
{
	int cfgerr = 0;
	struct proxy *curproxy = NULL;
	struct stktable *t;
	struct server *newsrv = NULL;
	int err_code = 0;
	unsigned int next_pxid = 1;
	struct bind_conf *bind_conf;
	char *err;
	struct cfg_postparser *postparser;
	struct dns_resolvers *curr_resolvers = NULL;

	bind_conf = NULL;
	/*
	 * Now, check for the integrity of all that we have collected.
	 */

	/* will be needed further to delay some tasks */
	tv_update_date(0,1);

	if (!global.tune.max_http_hdr)
		global.tune.max_http_hdr = MAX_HTTP_HDR;

	if (!global.tune.cookie_len)
		global.tune.cookie_len = CAPTURE_LEN;

	if (!global.tune.requri_len)
		global.tune.requri_len = REQURI_LEN;

	if (!global.nbthread) {
		/* nbthread not set, thus automatic. In this case, and only if
		 * running on a single process, we enable the same number of
		 * threads as the number of CPUs the process is bound to. This
		 * allows to easily control the number of threads using taskset.
		 */
		global.nbthread = 1;
#if defined(USE_THREAD)
		if (global.nbproc == 1)
			global.nbthread = thread_cpus_enabled_at_boot;
		all_threads_mask = nbits(global.nbthread);
#endif
	}

	if (global.nbproc > 1 && global.nbthread > 1) {
		ha_alert("config : cannot enable multiple processes if multiple threads are configured. Please use either nbproc or nbthread but not both.\n");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	pool_head_requri = create_pool("requri", global.tune.requri_len , MEM_F_SHARED);

	pool_head_capture = create_pool("capture", global.tune.cookie_len, MEM_F_SHARED);

	/* Post initialisation of the users and groups lists. */
	err_code = userlist_postinit();
	if (err_code != ERR_NONE)
		goto out;

	/* first, we will invert the proxy list order */
	curproxy = NULL;
	while (proxies_list) {
		struct proxy *next;

		next = proxies_list->next;
		proxies_list->next = curproxy;
		curproxy = proxies_list;
		if (!next)
			break;
		proxies_list = next;
	}

	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		struct switching_rule *rule;
		struct server_rule *srule;
		struct sticking_rule *mrule;
		struct act_rule *arule;
		struct logsrv *tmplogsrv;
		unsigned int next_id;
		int nbproc;

		if (curproxy->uuid < 0) {
			/* proxy ID not set, use automatic numbering with first
			 * spare entry starting with next_pxid.
			 */
			next_pxid = get_next_id(&used_proxy_id, next_pxid);
			curproxy->conf.id.key = curproxy->uuid = next_pxid;
			eb32_insert(&used_proxy_id, &curproxy->conf.id);
		}
		next_pxid++;


		if (curproxy->disabled) {
			/* ensure we don't keep listeners uselessly bound. We
			 * can't disable their listeners yet (fdtab not
			 * allocated yet) but let's skip them.
			 */
			if (curproxy->table) {
				free((void *)curproxy->table->peers.name);
				curproxy->table->peers.name = NULL;
				curproxy->table->peers.p = NULL;
			}
			continue;
		}

		/* Check multi-process mode compatibility for the current proxy */

		if (curproxy->bind_proc) {
			/* an explicit bind-process was specified, let's check how many
			 * processes remain.
			 */
			nbproc = my_popcountl(curproxy->bind_proc);

			curproxy->bind_proc &= all_proc_mask;
			if (!curproxy->bind_proc && nbproc == 1) {
				ha_warning("Proxy '%s': the process specified on the 'bind-process' directive refers to a process number that is higher than global.nbproc. The proxy has been forced to run on process 1 only.\n", curproxy->id);
				curproxy->bind_proc = 1;
			}
			else if (!curproxy->bind_proc && nbproc > 1) {
				ha_warning("Proxy '%s': all processes specified on the 'bind-process' directive refer to numbers that are all higher than global.nbproc. The directive was ignored and the proxy will run on all processes.\n", curproxy->id);
				curproxy->bind_proc = 0;
			}
		}

		/* check and reduce the bind-proc of each listener */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			unsigned long mask;

			/* HTTP frontends with "h2" as ALPN/NPN will work in
			 * HTTP/2 and absolutely require buffers 16kB or larger.
			 */
#ifdef USE_OPENSSL
			if (curproxy->mode == PR_MODE_HTTP && global.tune.bufsize < 16384) {
#ifdef OPENSSL_NPN_NEGOTIATED
				/* check NPN */
				if (bind_conf->ssl_conf.npn_str && strstr(bind_conf->ssl_conf.npn_str, "\002h2")) {
					ha_alert("config : HTTP frontend '%s' enables HTTP/2 via NPN at [%s:%d], so global.tune.bufsize must be at least 16384 bytes (%d now).\n",
						 curproxy->id, bind_conf->file, bind_conf->line, global.tune.bufsize);
					cfgerr++;
				}
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
				/* check ALPN */
				if (bind_conf->ssl_conf.alpn_str && strstr(bind_conf->ssl_conf.alpn_str, "\002h2")) {
					ha_alert("config : HTTP frontend '%s' enables HTTP/2 via ALPN at [%s:%d], so global.tune.bufsize must be at least 16384 bytes (%d now).\n",
						 curproxy->id, bind_conf->file, bind_conf->line, global.tune.bufsize);
					cfgerr++;
				}
#endif
			} /* HTTP && bufsize < 16384 */
#endif

			/* detect and address thread affinity inconsistencies */
			mask = thread_mask(bind_conf->settings.bind_thread);
			if (!(mask & all_threads_mask)) {
				unsigned long new_mask = 0;

				while (mask) {
					new_mask |= mask & all_threads_mask;
					mask >>= global.nbthread;
				}

				bind_conf->settings.bind_thread = new_mask;
				ha_warning("Proxy '%s': the thread range specified on the 'process' directive of 'bind %s' at [%s:%d] only refers to thread numbers out of the range defined by the global 'nbthread' directive. The thread numbers were remapped to existing threads instead (mask 0x%lx).\n",
					   curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line, new_mask);
			}

			/* detect process and nbproc affinity inconsistencies */
			mask = proc_mask(bind_conf->settings.bind_proc) & proc_mask(curproxy->bind_proc);
			if (!(mask & all_proc_mask)) {
				mask = proc_mask(curproxy->bind_proc) & all_proc_mask;
				nbproc = my_popcountl(bind_conf->settings.bind_proc);
				bind_conf->settings.bind_proc = proc_mask(bind_conf->settings.bind_proc) & mask;

				if (!bind_conf->settings.bind_proc && nbproc == 1) {
					ha_warning("Proxy '%s': the process number specified on the 'process' directive of 'bind %s' at [%s:%d] refers to a process not covered by the proxy. This has been fixed by forcing it to run on the proxy's first process only.\n",
						   curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
					bind_conf->settings.bind_proc = mask & ~(mask - 1);
				}
				else if (!bind_conf->settings.bind_proc && nbproc > 1) {
					ha_warning("Proxy '%s': the process range specified on the 'process' directive of 'bind %s' at [%s:%d] only refers to processes not covered by the proxy. The directive was ignored so that all of the proxy's processes are used.\n",
						   curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
					bind_conf->settings.bind_proc = 0;
				}
			}
		}

		switch (curproxy->mode) {
		case PR_MODE_TCP:
			cfgerr += proxy_cfg_ensure_no_http(curproxy);
			break;

		case PR_MODE_HTTP:
			curproxy->http_needed = 1;
			break;

		case PR_MODE_CLI:
			cfgerr += proxy_cfg_ensure_no_http(curproxy);
			break;
		case PR_MODE_SYSLOG:
		case PR_MODE_PEERS:
		case PR_MODES:
			/* should not happen, bug gcc warn missing switch statement */
			ha_alert("config : %s '%s' cannot use peers or syslog mode for this proxy. NOTE: PLEASE REPORT THIS TO DEVELOPERS AS YOU'RE NOT SUPPOSED TO BE ABLE TO CREATE A CONFIGURATION TRIGGERING THIS!\n",
				 proxy_type_str(curproxy), curproxy->id);
			cfgerr++;
			break;
		}

		if (curproxy != global.stats_fe && (curproxy->cap & PR_CAP_FE) && LIST_ISEMPTY(&curproxy->conf.listeners)) {
			ha_warning("config : %s '%s' has no 'bind' directive. Please declare it as a backend if this was intended.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if (curproxy->cap & PR_CAP_BE) {
			if (curproxy->lbprm.algo & BE_LB_KIND) {
				if (curproxy->options & PR_O_TRANSP) {
					ha_alert("config : %s '%s' cannot use both transparent and balance mode.\n",
						 proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				}
#ifdef WE_DONT_SUPPORT_SERVERLESS_LISTENERS
				else if (curproxy->srv == NULL) {
					ha_alert("config : %s '%s' needs at least 1 server in balance mode.\n",
						 proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				}
#endif
				else if (curproxy->options & PR_O_DISPATCH) {
					ha_warning("config : dispatch address of %s '%s' will be ignored in balance mode.\n",
						   proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
				}
			}
			else if (!(curproxy->options & (PR_O_TRANSP | PR_O_DISPATCH | PR_O_HTTP_PROXY))) {
				/* If no LB algo is set in a backend, and we're not in
				 * transparent mode, dispatch mode nor proxy mode, we
				 * want to use balance roundrobin by default.
				 */
				curproxy->lbprm.algo &= ~BE_LB_ALGO;
				curproxy->lbprm.algo |= BE_LB_ALGO_RR;
			}
		}

		if (curproxy->options & PR_O_DISPATCH)
			curproxy->options &= ~(PR_O_TRANSP | PR_O_HTTP_PROXY);
		else if (curproxy->options & PR_O_HTTP_PROXY)
			curproxy->options &= ~(PR_O_DISPATCH | PR_O_TRANSP);
		else if (curproxy->options & PR_O_TRANSP)
			curproxy->options &= ~(PR_O_DISPATCH | PR_O_HTTP_PROXY);

		if ((curproxy->tcpcheck_rules.flags & TCPCHK_RULES_UNUSED_HTTP_RS)) {
			ha_warning("config : %s '%s' uses http-check rules without 'option httpchk', so the rules are ignored.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if ((curproxy->options2 & PR_O2_CHK_ANY) == PR_O2_TCPCHK_CHK &&
		    (curproxy->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) != TCPCHK_RULES_HTTP_CHK) {
			if (curproxy->options & PR_O_DISABLE404) {
				ha_warning("config : '%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
					   "disable-on-404", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O_DISABLE404;
			}
			if (curproxy->options2 & PR_O2_CHK_SNDST) {
				ha_warning("config : '%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
					   "send-state", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O2_CHK_SNDST;
			}
		}

		if ((curproxy->options2 & PR_O2_CHK_ANY) == PR_O2_EXT_CHK) {
			if (!global.external_check) {
				ha_alert("Proxy '%s' : '%s' unable to find required 'global.external-check'.\n",
					 curproxy->id, "option external-check");
				cfgerr++;
			}
			if (!curproxy->check_command) {
				ha_alert("Proxy '%s' : '%s' unable to find required 'external-check command'.\n",
					 curproxy->id, "option external-check");
				cfgerr++;
			}
			if (!(global.tune.options & GTUNE_INSECURE_FORK)) {
				ha_warning("Proxy '%s' : 'insecure-fork-wanted' not enabled in the global section, '%s' will likely fail.\n",
					 curproxy->id, "option external-check");
				err_code |= ERR_WARN;
			}
		}

		if (curproxy->email_alert.set) {
		    if (!(curproxy->email_alert.mailers.name && curproxy->email_alert.from && curproxy->email_alert.to)) {
			    ha_warning("config : 'email-alert' will be ignored for %s '%s' (the presence any of "
				       "'email-alert from', 'email-alert level' 'email-alert mailers', "
				       "'email-alert myhostname', or 'email-alert to' "
				       "requires each of 'email-alert from', 'email-alert mailers' and 'email-alert to' "
				       "to be present).\n",
				       proxy_type_str(curproxy), curproxy->id);
			    err_code |= ERR_WARN;
			    free_email_alert(curproxy);
		    }
		    if (!curproxy->email_alert.myhostname)
			    curproxy->email_alert.myhostname = strdup(hostname);
		}

		if (curproxy->check_command) {
			int clear = 0;
			if ((curproxy->options2 & PR_O2_CHK_ANY) != PR_O2_EXT_CHK) {
				ha_warning("config : '%s' will be ignored for %s '%s' (requires 'option external-check').\n",
					   "external-check command", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				clear = 1;
			}
			if (curproxy->check_command[0] != '/' && !curproxy->check_path) {
				ha_alert("Proxy '%s': '%s' does not have a leading '/' and 'external-check path' is not set.\n",
					 curproxy->id, "external-check command");
				cfgerr++;
			}
			if (clear) {
				free(curproxy->check_command);
				curproxy->check_command = NULL;
			}
		}

		if (curproxy->check_path) {
			if ((curproxy->options2 & PR_O2_CHK_ANY) != PR_O2_EXT_CHK) {
				ha_warning("config : '%s' will be ignored for %s '%s' (requires 'option external-check').\n",
					   "external-check path", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				free(curproxy->check_path);
				curproxy->check_path = NULL;
			}
		}

		/* if a default backend was specified, let's find it */
		if (curproxy->defbe.name) {
			struct proxy *target;

			target = proxy_be_by_name(curproxy->defbe.name);
			if (!target) {
				ha_alert("Proxy '%s': unable to find required default_backend: '%s'.\n",
					 curproxy->id, curproxy->defbe.name);
				cfgerr++;
			} else if (target == curproxy) {
				ha_alert("Proxy '%s': loop detected for default_backend: '%s'.\n",
					 curproxy->id, curproxy->defbe.name);
				cfgerr++;
			} else if (target->mode != curproxy->mode &&
				   !(curproxy->mode == PR_MODE_TCP && target->mode == PR_MODE_HTTP)) {

				ha_alert("%s %s '%s' (%s:%d) tries to use incompatible %s %s '%s' (%s:%d) as its default backend (see 'mode').\n",
					 proxy_mode_str(curproxy->mode), proxy_type_str(curproxy), curproxy->id,
					 curproxy->conf.file, curproxy->conf.line,
					 proxy_mode_str(target->mode), proxy_type_str(target), target->id,
					 target->conf.file, target->conf.line);
				cfgerr++;
			} else {
				free(curproxy->defbe.name);
				curproxy->defbe.be = target;
				/* Emit a warning if this proxy also has some servers */
				if (curproxy->srv) {
					ha_warning("In proxy '%s', the 'default_backend' rule always has precedence over the servers, which will never be used.\n",
						   curproxy->id);
					err_code |= ERR_WARN;
				}
			}
		}

		/* find the target proxy for 'use_backend' rules */
		list_for_each_entry(rule, &curproxy->switching_rules, list) {
			struct proxy *target;
			struct logformat_node *node;
			char *pxname;

			/* Try to parse the string as a log format expression. If the result
			 * of the parsing is only one entry containing a simple string, then
			 * it's a standard string corresponding to a static rule, thus the
			 * parsing is cancelled and be.name is restored to be resolved.
			 */
			pxname = rule->be.name;
			LIST_INIT(&rule->be.expr);
			curproxy->conf.args.ctx = ARGC_UBK;
			curproxy->conf.args.file = rule->file;
			curproxy->conf.args.line = rule->line;
			err = NULL;
			if (!parse_logformat_string(pxname, curproxy, &rule->be.expr, 0, SMP_VAL_FE_HRQ_HDR, &err)) {
				ha_alert("Parsing [%s:%d]: failed to parse use_backend rule '%s' : %s.\n",
					 rule->file, rule->line, pxname, err);
				free(err);
				cfgerr++;
				continue;
			}
			node = LIST_NEXT(&rule->be.expr, struct logformat_node *, list);

			if (!LIST_ISEMPTY(&rule->be.expr)) {
				if (node->type != LOG_FMT_TEXT || node->list.n != &rule->be.expr) {
					rule->dynamic = 1;
					free(pxname);
					continue;
				}
				/* Only one element in the list, a simple string: free the expression and
				 * fall back to static rule
				 */
				LIST_DEL(&node->list);
				free(node->arg);
				free(node);
			}

			rule->dynamic = 0;
			rule->be.name = pxname;

			target = proxy_be_by_name(rule->be.name);
			if (!target) {
				ha_alert("Proxy '%s': unable to find required use_backend: '%s'.\n",
					 curproxy->id, rule->be.name);
				cfgerr++;
			} else if (target == curproxy) {
				ha_alert("Proxy '%s': loop detected for use_backend: '%s'.\n",
					 curproxy->id, rule->be.name);
				cfgerr++;
			} else if (target->mode != curproxy->mode &&
				   !(curproxy->mode == PR_MODE_TCP && target->mode == PR_MODE_HTTP)) {

				ha_alert("%s %s '%s' (%s:%d) tries to use incompatible %s %s '%s' (%s:%d) in a 'use_backend' rule (see 'mode').\n",
					 proxy_mode_str(curproxy->mode), proxy_type_str(curproxy), curproxy->id,
					 curproxy->conf.file, curproxy->conf.line,
					 proxy_mode_str(target->mode), proxy_type_str(target), target->id,
					 target->conf.file, target->conf.line);
				cfgerr++;
			} else {
				free((void *)rule->be.name);
				rule->be.backend = target;
			}
		}

		/* find the target server for 'use_server' rules */
		list_for_each_entry(srule, &curproxy->server_rules, list) {
			struct server *target;
			struct logformat_node *node;
			char *server_name;

			/* We try to parse the string as a log format expression. If the result of the parsing
			 * is only one entry containing a single string, then it's a standard string corresponding
			 * to a static rule, thus the parsing is cancelled and we fall back to setting srv.ptr.
			 */
			server_name = srule->srv.name;
			LIST_INIT(&srule->expr);
			curproxy->conf.args.ctx = ARGC_USRV;
			err = NULL;
			if (!parse_logformat_string(server_name, curproxy, &srule->expr, 0, SMP_VAL_FE_HRQ_HDR, &err)) {
				ha_alert("Parsing [%s:%d]; use-server rule failed to parse log-format '%s' : %s.\n",
						srule->file, srule->line, server_name, err);
				free(err);
				cfgerr++;
				continue;
			}
			node = LIST_NEXT(&srule->expr, struct logformat_node *, list);

			if (!LIST_ISEMPTY(&srule->expr)) {
				if (node->type != LOG_FMT_TEXT || node->list.n != &srule->expr) {
					srule->dynamic = 1;
					free(server_name);
					continue;
				}
				/* Only one element in the list, a simple string: free the expression and
				 * fall back to static rule
				 */
				LIST_DEL(&node->list);
				free(node->arg);
				free(node);
			}

			srule->dynamic = 0;
			srule->srv.name = server_name;
			target = findserver(curproxy, srule->srv.name);

			if (!target) {
				ha_alert("config : %s '%s' : unable to find server '%s' referenced in a 'use-server' rule.\n",
					 proxy_type_str(curproxy), curproxy->id, srule->srv.name);
				cfgerr++;
				continue;
			}
			free((void *)srule->srv.name);
			srule->srv.ptr = target;
		}

		/* find the target table for 'stick' rules */
		list_for_each_entry(mrule, &curproxy->sticking_rules, list) {
			struct stktable *target;

			curproxy->be_req_ana |= AN_REQ_STICKING_RULES;
			if (mrule->flags & STK_IS_STORE)
				curproxy->be_rsp_ana |= AN_RES_STORE_RULES;

			if (mrule->table.name)
				target = stktable_find_by_name(mrule->table.name);
			else
				target = curproxy->table;

			if (!target) {
				ha_alert("Proxy '%s': unable to find stick-table '%s'.\n",
					 curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else if (!stktable_compatible_sample(mrule->expr,  target->type)) {
				ha_alert("Proxy '%s': type of fetch not usable with type of stick-table '%s'.\n",
					 curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else if (target->proxy && curproxy->bind_proc & ~target->proxy->bind_proc) {
				ha_alert("Proxy '%s': stick-table '%s' referenced 'stick-store' rule not present on all processes covered by proxy '%s'.\n",
				         curproxy->id, target->id, curproxy->id);
				cfgerr++;
			}
			else {
				free((void *)mrule->table.name);
				mrule->table.t = target;
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_ID, NULL);
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_KEY, NULL);
				if (!in_proxies_list(target->proxies_list, curproxy)) {
					curproxy->next_stkt_ref = target->proxies_list;
					target->proxies_list = curproxy;
				}
			}
		}

		/* find the target table for 'store response' rules */
		list_for_each_entry(mrule, &curproxy->storersp_rules, list) {
			struct stktable *target;

			curproxy->be_rsp_ana |= AN_RES_STORE_RULES;

			if (mrule->table.name)
				target = stktable_find_by_name(mrule->table.name);
			else
				target = curproxy->table;

			if (!target) {
				ha_alert("Proxy '%s': unable to find store table '%s'.\n",
					 curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else if (!stktable_compatible_sample(mrule->expr, target->type)) {
				ha_alert("Proxy '%s': type of fetch not usable with type of stick-table '%s'.\n",
					 curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else if (target->proxy && (curproxy->bind_proc & ~target->proxy->bind_proc)) {
				ha_alert("Proxy '%s': stick-table '%s' referenced 'stick-store' rule not present on all processes covered by proxy '%s'.\n",
				         curproxy->id, target->id, curproxy->id);
				cfgerr++;
			}
			else {
				free((void *)mrule->table.name);
				mrule->table.t = target;
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_ID, NULL);
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_KEY, NULL);
				if (!in_proxies_list(target->proxies_list, curproxy)) {
					curproxy->next_stkt_ref = target->proxies_list;
					target->proxies_list = curproxy;
				}
			}
		}

		/* check validity for 'tcp-request' layer 4 rules */
		list_for_each_entry(arule, &curproxy->tcp_req.l4_rules, list) {
			err = NULL;
			if (arule->check_ptr && !arule->check_ptr(arule, curproxy, &err)) {
				ha_alert("Proxy '%s': %s.\n", curproxy->id, err);
				free(err);
				cfgerr++;
			}
		}

		/* check validity for 'tcp-request' layer 5 rules */
		list_for_each_entry(arule, &curproxy->tcp_req.l5_rules, list) {
			err = NULL;
			if (arule->check_ptr && !arule->check_ptr(arule, curproxy, &err)) {
				ha_alert("Proxy '%s': %s.\n", curproxy->id, err);
				free(err);
				cfgerr++;
			}
		}

		/* check validity for 'tcp-request' layer 6 rules */
		list_for_each_entry(arule, &curproxy->tcp_req.inspect_rules, list) {
			err = NULL;
			if (arule->check_ptr && !arule->check_ptr(arule, curproxy, &err)) {
				ha_alert("Proxy '%s': %s.\n", curproxy->id, err);
				free(err);
				cfgerr++;
			}
		}

		/* check validity for 'http-request' layer 7 rules */
		list_for_each_entry(arule, &curproxy->http_req_rules, list) {
			err = NULL;
			if (arule->check_ptr && !arule->check_ptr(arule, curproxy, &err)) {
				ha_alert("Proxy '%s': %s.\n", curproxy->id, err);
				free(err);
				cfgerr++;
			}
		}

		/* check validity for 'http-response' layer 7 rules */
		list_for_each_entry(arule, &curproxy->http_res_rules, list) {
			err = NULL;
			if (arule->check_ptr && !arule->check_ptr(arule, curproxy, &err)) {
				ha_alert("Proxy '%s': %s.\n", curproxy->id, err);
				free(err);
				cfgerr++;
			}
		}

		/* check validity for 'http-after-response' layer 7 rules */
		list_for_each_entry(arule, &curproxy->http_after_res_rules, list) {
			err = NULL;
			if (arule->check_ptr && !arule->check_ptr(arule, curproxy, &err)) {
				ha_alert("Proxy '%s': %s.\n", curproxy->id, err);
				free(err);
				cfgerr++;
			}
		}

		if (curproxy->table && curproxy->table->peers.name) {
			struct peers *curpeers;

			for (curpeers = cfg_peers; curpeers; curpeers = curpeers->next) {
				if (strcmp(curpeers->id, curproxy->table->peers.name) == 0) {
					free((void *)curproxy->table->peers.name);
					curproxy->table->peers.p = curpeers;
					break;
				}
			}

			if (!curpeers) {
				ha_alert("Proxy '%s': unable to find sync peers '%s'.\n",
					 curproxy->id, curproxy->table->peers.name);
				free((void *)curproxy->table->peers.name);
				curproxy->table->peers.p = NULL;
				cfgerr++;
			}
			else if (curpeers->disabled) {
				/* silently disable this peers section */
				curproxy->table->peers.p = NULL;
			}
			else if (!curpeers->peers_fe) {
				ha_alert("Proxy '%s': unable to find local peer '%s' in peers section '%s'.\n",
					 curproxy->id, localpeer, curpeers->id);
				curproxy->table->peers.p = NULL;
				cfgerr++;
			}
		}


		if (curproxy->email_alert.mailers.name) {
			struct mailers *curmailers = mailers;

			for (curmailers = mailers; curmailers; curmailers = curmailers->next) {
				if (strcmp(curmailers->id, curproxy->email_alert.mailers.name) == 0)
					break;
			}
			if (!curmailers) {
				ha_alert("Proxy '%s': unable to find mailers '%s'.\n",
					 curproxy->id, curproxy->email_alert.mailers.name);
				free_email_alert(curproxy);
				cfgerr++;
			}
			else {
				err = NULL;
				if (init_email_alert(curmailers, curproxy, &err)) {
					ha_alert("Proxy '%s': %s.\n", curproxy->id, err);
					free(err);
					cfgerr++;
				}
			}
		}

		if (curproxy->uri_auth && curproxy->uri_auth != defproxy.uri_auth &&
		    !LIST_ISEMPTY(&curproxy->uri_auth->http_req_rules) &&
		    (curproxy->uri_auth->userlist || curproxy->uri_auth->auth_realm )) {
			ha_alert("%s '%s': stats 'auth'/'realm' and 'http-request' can't be used at the same time.\n",
				 "proxy", curproxy->id);
			cfgerr++;
			goto out_uri_auth_compat;
		}

		if (curproxy->uri_auth && curproxy->uri_auth->userlist &&
		    (curproxy->uri_auth != defproxy.uri_auth ||
		     LIST_ISEMPTY(&curproxy->uri_auth->http_req_rules))) {
			const char *uri_auth_compat_req[10];
			struct act_rule *rule;
			int i = 0;
			/* build the ACL condition from scratch. We're relying on anonymous ACLs for that */
			uri_auth_compat_req[i++] = "auth";

			if (curproxy->uri_auth->auth_realm) {
				uri_auth_compat_req[i++] = "realm";
				uri_auth_compat_req[i++] = curproxy->uri_auth->auth_realm;
			}

			uri_auth_compat_req[i++] = "unless";
			uri_auth_compat_req[i++] = "{";
			uri_auth_compat_req[i++] = "http_auth(.internal-stats-userlist)";
			uri_auth_compat_req[i++] = "}";
			uri_auth_compat_req[i++] = "";

			rule = parse_http_req_cond(uri_auth_compat_req, "internal-stats-auth-compat", 0, curproxy);
			if (!rule) {
				cfgerr++;
				break;
			}

			LIST_ADDQ(&curproxy->uri_auth->http_req_rules, &rule->list);

			if (curproxy->uri_auth->auth_realm) {
				free(curproxy->uri_auth->auth_realm);
				curproxy->uri_auth->auth_realm = NULL;
			}
		}
out_uri_auth_compat:

		/* check whether we have a log server that uses RFC5424 log format */
		list_for_each_entry(tmplogsrv, &curproxy->logsrvs, list) {
			if (tmplogsrv->format == LOG_FORMAT_RFC5424) {
				if (!curproxy->conf.logformat_sd_string) {
					/* set the default logformat_sd_string */
					curproxy->conf.logformat_sd_string = default_rfc5424_sd_log_format;
				}
				break;
			}
		}

		/* compile the log format */
		if (!(curproxy->cap & PR_CAP_FE)) {
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = NULL;
			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = NULL;
			curproxy->conf.lfs_line = 0;

			if (curproxy->conf.logformat_sd_string != default_rfc5424_sd_log_format)
				free(curproxy->conf.logformat_sd_string);
			curproxy->conf.logformat_sd_string = NULL;
			free(curproxy->conf.lfsd_file);
			curproxy->conf.lfsd_file = NULL;
			curproxy->conf.lfsd_line = 0;
		}

		if (curproxy->conf.logformat_string) {
			curproxy->conf.args.ctx = ARGC_LOG;
			curproxy->conf.args.file = curproxy->conf.lfs_file;
			curproxy->conf.args.line = curproxy->conf.lfs_line;
			err = NULL;
			if (!parse_logformat_string(curproxy->conf.logformat_string, curproxy, &curproxy->logformat,
			                            LOG_OPT_MANDATORY|LOG_OPT_MERGE_SPACES,
			                            SMP_VAL_FE_LOG_END, &err)) {
				ha_alert("Parsing [%s:%d]: failed to parse log-format : %s.\n",
					 curproxy->conf.lfs_file, curproxy->conf.lfs_line, err);
				free(err);
				cfgerr++;
			}
			curproxy->conf.args.file = NULL;
			curproxy->conf.args.line = 0;
		}

		if (curproxy->conf.logformat_sd_string) {
			curproxy->conf.args.ctx = ARGC_LOGSD;
			curproxy->conf.args.file = curproxy->conf.lfsd_file;
			curproxy->conf.args.line = curproxy->conf.lfsd_line;
			err = NULL;
			if (!parse_logformat_string(curproxy->conf.logformat_sd_string, curproxy, &curproxy->logformat_sd,
			                            LOG_OPT_MANDATORY|LOG_OPT_MERGE_SPACES,
			                            SMP_VAL_FE_LOG_END, &err)) {
				ha_alert("Parsing [%s:%d]: failed to parse log-format-sd : %s.\n",
					 curproxy->conf.lfs_file, curproxy->conf.lfs_line, err);
				free(err);
				cfgerr++;
			} else if (!add_to_logformat_list(NULL, NULL, LF_SEPARATOR, &curproxy->logformat_sd, &err)) {
				ha_alert("Parsing [%s:%d]: failed to parse log-format-sd : %s.\n",
					 curproxy->conf.lfs_file, curproxy->conf.lfs_line, err);
				free(err);
				cfgerr++;
			}
			curproxy->conf.args.file = NULL;
			curproxy->conf.args.line = 0;
		}

		if (curproxy->conf.uniqueid_format_string) {
			curproxy->conf.args.ctx = ARGC_UIF;
			curproxy->conf.args.file = curproxy->conf.uif_file;
			curproxy->conf.args.line = curproxy->conf.uif_line;
			err = NULL;
			if (!parse_logformat_string(curproxy->conf.uniqueid_format_string, curproxy, &curproxy->format_unique_id,
			                            LOG_OPT_HTTP|LOG_OPT_MERGE_SPACES,
			                            (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR
			                                                        : SMP_VAL_BE_HRQ_HDR,
			                            &err)) {
				ha_alert("Parsing [%s:%d]: failed to parse unique-id : %s.\n",
					 curproxy->conf.uif_file, curproxy->conf.uif_line, err);
				free(err);
				cfgerr++;
			}
			curproxy->conf.args.file = NULL;
			curproxy->conf.args.line = 0;
		}

		/* only now we can check if some args remain unresolved.
		 * This must be done after the users and groups resolution.
		 */
		cfgerr += smp_resolve_args(curproxy);
		if (!cfgerr)
			cfgerr += acl_find_targets(curproxy);

		if ((curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HTTP) &&
		    (((curproxy->cap & PR_CAP_FE) && !curproxy->timeout.client) ||
		     ((curproxy->cap & PR_CAP_BE) && (curproxy->srv) &&
		      (!curproxy->timeout.connect ||
		       (!curproxy->timeout.server && (curproxy->mode == PR_MODE_HTTP || !curproxy->timeout.tunnel)))))) {
			ha_warning("config : missing timeouts for %s '%s'.\n"
				   "   | While not properly invalid, you will certainly encounter various problems\n"
				   "   | with such a configuration. To fix this, please ensure that all following\n"
				   "   | timeouts are set to a non-zero value: 'client', 'connect', 'server'.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		/* Historically, the tarpit and queue timeouts were inherited from contimeout.
		 * We must still support older configurations, so let's find out whether those
		 * parameters have been set or must be copied from contimeouts.
		 */
		if (curproxy != &defproxy) {
			if (!curproxy->timeout.tarpit ||
			    curproxy->timeout.tarpit == defproxy.timeout.tarpit) {
				/* tarpit timeout not set. We search in the following order:
				 * default.tarpit, curr.connect, default.connect.
				 */
				if (defproxy.timeout.tarpit)
					curproxy->timeout.tarpit = defproxy.timeout.tarpit;
				else if (curproxy->timeout.connect)
					curproxy->timeout.tarpit = curproxy->timeout.connect;
				else if (defproxy.timeout.connect)
					curproxy->timeout.tarpit = defproxy.timeout.connect;
			}
			if ((curproxy->cap & PR_CAP_BE) &&
			    (!curproxy->timeout.queue ||
			     curproxy->timeout.queue == defproxy.timeout.queue)) {
				/* queue timeout not set. We search in the following order:
				 * default.queue, curr.connect, default.connect.
				 */
				if (defproxy.timeout.queue)
					curproxy->timeout.queue = defproxy.timeout.queue;
				else if (curproxy->timeout.connect)
					curproxy->timeout.queue = curproxy->timeout.connect;
				else if (defproxy.timeout.connect)
					curproxy->timeout.queue = defproxy.timeout.connect;
			}
		}

		if ((curproxy->tcpcheck_rules.flags & TCPCHK_RULES_UNUSED_TCP_RS)) {
			ha_warning("config : %s '%s' uses tcp-check rules without 'option tcp-check', so the rules are ignored.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		/* ensure that cookie capture length is not too large */
		if (curproxy->capture_len >= global.tune.cookie_len) {
			ha_warning("config : truncating capture length to %d bytes for %s '%s'.\n",
				   global.tune.cookie_len - 1, proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
			curproxy->capture_len = global.tune.cookie_len - 1;
		}

		/* The small pools required for the capture lists */
		if (curproxy->nb_req_cap) {
			curproxy->req_cap_pool = create_pool("ptrcap",
			                                     curproxy->nb_req_cap * sizeof(char *),
			                                     MEM_F_SHARED);
		}

		if (curproxy->nb_rsp_cap) {
			curproxy->rsp_cap_pool = create_pool("ptrcap",
			                                     curproxy->nb_rsp_cap * sizeof(char *),
			                                     MEM_F_SHARED);
		}

		switch (curproxy->load_server_state_from_file) {
			case PR_SRV_STATE_FILE_UNSPEC:
				curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_NONE;
				break;
			case PR_SRV_STATE_FILE_GLOBAL:
				if (!global.server_state_file) {
					ha_warning("config : backend '%s' configured to load server state file from global section 'server-state-file' directive. Unfortunately, 'server-state-file' is not set!\n",
						   curproxy->id);
					err_code |= ERR_WARN;
				}
				break;
		}

		/* first, we will invert the servers list order */
		newsrv = NULL;
		while (curproxy->srv) {
			struct server *next;

			next = curproxy->srv->next;
			curproxy->srv->next = newsrv;
			newsrv = curproxy->srv;
			if (!next)
				break;
			curproxy->srv = next;
		}

		/* Check that no server name conflicts. This causes trouble in the stats.
		 * We only emit a warning for the first conflict affecting each server,
		 * in order to avoid combinatory explosion if all servers have the same
		 * name. We do that only for servers which do not have an explicit ID,
		 * because these IDs were made also for distinguishing them and we don't
		 * want to annoy people who correctly manage them.
		 */
		for (newsrv = curproxy->srv; newsrv; newsrv = newsrv->next) {
			struct server *other_srv;

			if (newsrv->puid)
				continue;

			for (other_srv = curproxy->srv; other_srv && other_srv != newsrv; other_srv = other_srv->next) {
				if (!other_srv->puid && strcmp(other_srv->id, newsrv->id) == 0) {
					ha_alert("parsing [%s:%d] : %s '%s', another server named '%s' was already defined at line %d, please use distinct names.\n",
						   newsrv->conf.file, newsrv->conf.line,
						   proxy_type_str(curproxy), curproxy->id,
						   newsrv->id, other_srv->conf.line);
					cfgerr++;
					break;
				}
			}
		}

		/* assign automatic UIDs to servers which don't have one yet */
		next_id = 1;
		newsrv = curproxy->srv;
		while (newsrv != NULL) {
			if (!newsrv->puid) {
				/* server ID not set, use automatic numbering with first
				 * spare entry starting with next_svid.
				 */
				next_id = get_next_id(&curproxy->conf.used_server_id, next_id);
				newsrv->conf.id.key = newsrv->puid = next_id;
				eb32_insert(&curproxy->conf.used_server_id, &newsrv->conf.id);
				newsrv->conf.name.key = newsrv->id;
				ebis_insert(&curproxy->conf.used_server_name, &newsrv->conf.name);
			}
			next_id++;
			newsrv = newsrv->next;
		}

		curproxy->lbprm.wmult = 1; /* default weight multiplier */
		curproxy->lbprm.wdiv  = 1; /* default weight divider */

		/*
		 * If this server supports a maxconn parameter, it needs a dedicated
		 * tasks to fill the emptied slots when a connection leaves.
		 * Also, resolve deferred tracking dependency if needed.
		 */
		newsrv = curproxy->srv;
		while (newsrv != NULL) {
			if (newsrv->minconn > newsrv->maxconn) {
				/* Only 'minconn' was specified, or it was higher than or equal
				 * to 'maxconn'. Let's turn this into maxconn and clean it, as
				 * this will avoid further useless expensive computations.
				 */
				newsrv->maxconn = newsrv->minconn;
			} else if (newsrv->maxconn && !newsrv->minconn) {
				/* minconn was not specified, so we set it to maxconn */
				newsrv->minconn = newsrv->maxconn;
			}

			/* this will also properly set the transport layer for
			 * prod and checks
			 * if default-server have use_ssl, prerare ssl init
			 * without activating it */
			if (newsrv->use_ssl == 1 || newsrv->check.use_ssl == 1 ||
				(newsrv->proxy->options & PR_O_TCPCHK_SSL) ||
				(newsrv->use_ssl != 1 && curproxy->defsrv.use_ssl == 1)) {
				if (xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->prepare_srv)
					cfgerr += xprt_get(XPRT_SSL)->prepare_srv(newsrv);
			}

			if ((newsrv->flags & SRV_F_FASTOPEN) &&
			    ((curproxy->retry_type & (PR_RE_DISCONNECTED | PR_RE_TIMEOUT)) !=
			     (PR_RE_DISCONNECTED | PR_RE_TIMEOUT)))
				ha_warning("parsing [%s:%d] : %s '%s': server '%s' has tfo activated, the backend should be configured with at least 'conn-failure', 'empty-response' and 'response-timeout' or we wouldn't be able to retry the connection on failure.\n",
				    newsrv->conf.file, newsrv->conf.line,
				    proxy_type_str(curproxy), curproxy->id,
				    newsrv->id);

			if (newsrv->trackit) {
				struct proxy *px;
				struct server *srv, *loop;
				char *pname, *sname;

				pname = newsrv->trackit;
				sname = strrchr(pname, '/');

				if (sname)
					*sname++ = '\0';
				else {
					sname = pname;
					pname = NULL;
				}

				if (pname) {
					px = proxy_be_by_name(pname);
					if (!px) {
						ha_alert("config : %s '%s', server '%s': unable to find required proxy '%s' for tracking.\n",
							 proxy_type_str(curproxy), curproxy->id,
							 newsrv->id, pname);
						cfgerr++;
						goto next_srv;
					}
				} else
					px = curproxy;

				srv = findserver(px, sname);
				if (!srv) {
					ha_alert("config : %s '%s', server '%s': unable to find required server '%s' for tracking.\n",
						 proxy_type_str(curproxy), curproxy->id,
						 newsrv->id, sname);
					cfgerr++;
					goto next_srv;
				}

				if (!srv->do_check && !srv->do_agent && !srv->track && !srv->trackit) {
					ha_alert("config : %s '%s', server '%s': unable to use %s/%s for "
						 "tracking as it does not have any check nor agent enabled.\n",
						 proxy_type_str(curproxy), curproxy->id,
						 newsrv->id, px->id, srv->id);
					cfgerr++;
					goto next_srv;
				}

				for (loop = srv->track; loop && loop != newsrv; loop = loop->track);

				if (newsrv == srv || loop) {
					ha_alert("config : %s '%s', server '%s': unable to track %s/%s as it "
						 "belongs to a tracking chain looping back to %s/%s.\n",
						 proxy_type_str(curproxy), curproxy->id,
						 newsrv->id, px->id, srv->id, px->id,
						 newsrv == srv ? srv->id : loop->id);
					cfgerr++;
					goto next_srv;
				}

				if (curproxy != px &&
					(curproxy->options & PR_O_DISABLE404) != (px->options & PR_O_DISABLE404)) {
					ha_alert("config : %s '%s', server '%s': unable to use %s/%s for"
						 "tracking: disable-on-404 option inconsistency.\n",
						 proxy_type_str(curproxy), curproxy->id,
						 newsrv->id, px->id, srv->id);
					cfgerr++;
					goto next_srv;
				}

				newsrv->track = srv;
				newsrv->tracknext = srv->trackers;
				srv->trackers = newsrv;

				free(newsrv->trackit);
				newsrv->trackit = NULL;
			}

		next_srv:
			newsrv = newsrv->next;
		}

		/*
		 * Try to generate dynamic cookies for servers now.
		 * It couldn't be done earlier, since at the time we parsed
		 * the server line, we may not have known yet that we
		 * should use dynamic cookies, or the secret key may not
		 * have been provided yet.
		 */
		if (curproxy->ck_opts & PR_CK_DYNAMIC) {
			newsrv = curproxy->srv;
			while (newsrv != NULL) {
				srv_set_dyncookie(newsrv);
				newsrv = newsrv->next;
			}

		}
		/* We have to initialize the server lookup mechanism depending
		 * on what LB algorithm was chosen.
		 */

		curproxy->lbprm.algo &= ~(BE_LB_LKUP | BE_LB_PROP_DYN);
		switch (curproxy->lbprm.algo & BE_LB_KIND) {
		case BE_LB_KIND_RR:
			if ((curproxy->lbprm.algo & BE_LB_PARM) == BE_LB_RR_STATIC) {
				curproxy->lbprm.algo |= BE_LB_LKUP_MAP;
				init_server_map(curproxy);
			} else if ((curproxy->lbprm.algo & BE_LB_PARM) == BE_LB_RR_RANDOM) {
				curproxy->lbprm.algo |= BE_LB_LKUP_CHTREE | BE_LB_PROP_DYN;
				chash_init_server_tree(curproxy);
			} else {
				curproxy->lbprm.algo |= BE_LB_LKUP_RRTREE | BE_LB_PROP_DYN;
				fwrr_init_server_groups(curproxy);
			}
			break;

		case BE_LB_KIND_CB:
			if ((curproxy->lbprm.algo & BE_LB_PARM) == BE_LB_CB_LC) {
				curproxy->lbprm.algo |= BE_LB_LKUP_LCTREE | BE_LB_PROP_DYN;
				fwlc_init_server_tree(curproxy);
			} else {
				curproxy->lbprm.algo |= BE_LB_LKUP_FSTREE | BE_LB_PROP_DYN;
				fas_init_server_tree(curproxy);
			}
			break;

		case BE_LB_KIND_HI:
			if ((curproxy->lbprm.algo & BE_LB_HASH_TYPE) == BE_LB_HASH_CONS) {
				curproxy->lbprm.algo |= BE_LB_LKUP_CHTREE | BE_LB_PROP_DYN;
				chash_init_server_tree(curproxy);
			} else {
				curproxy->lbprm.algo |= BE_LB_LKUP_MAP;
				init_server_map(curproxy);
			}
			break;
		}
		HA_RWLOCK_INIT(&curproxy->lbprm.lock);

		if (curproxy->options & PR_O_LOGASAP)
			curproxy->to_log &= ~LW_BYTES;

		if ((curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HTTP) &&
		    (curproxy->cap & PR_CAP_FE) && LIST_ISEMPTY(&curproxy->logsrvs) &&
		    (!LIST_ISEMPTY(&curproxy->logformat) || !LIST_ISEMPTY(&curproxy->logformat_sd))) {
			ha_warning("config : log format ignored for %s '%s' since it has no log address.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if (curproxy->mode != PR_MODE_HTTP) {
			int optnum;

			if (curproxy->uri_auth) {
				ha_warning("config : 'stats' statement ignored for %s '%s' as it requires HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->uri_auth = NULL;
			}

			if (curproxy->capture_name) {
				ha_warning("config : 'capture' statement ignored for %s '%s' as it requires HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (!LIST_ISEMPTY(&curproxy->http_req_rules)) {
				ha_warning("config : 'http-request' rules ignored for %s '%s' as they require HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (!LIST_ISEMPTY(&curproxy->http_res_rules)) {
				ha_warning("config : 'http-response' rules ignored for %s '%s' as they require HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (!LIST_ISEMPTY(&curproxy->redirect_rules)) {
				ha_warning("config : 'redirect' rules ignored for %s '%s' as they require HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (curproxy->options & (PR_O_FWDFOR | PR_O_FF_ALWAYS)) {
				ha_warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					   "forwardfor", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~(PR_O_FWDFOR | PR_O_FF_ALWAYS);
			}

			if (curproxy->options & PR_O_ORGTO) {
				ha_warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					   "originalto", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O_ORGTO;
			}

			for (optnum = 0; cfg_opts[optnum].name; optnum++) {
				if (cfg_opts[optnum].mode == PR_MODE_HTTP &&
				    (curproxy->cap & cfg_opts[optnum].cap) &&
				    (curproxy->options & cfg_opts[optnum].val)) {
					ha_warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
						   cfg_opts[optnum].name, proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
					curproxy->options &= ~cfg_opts[optnum].val;
				}
			}

			for (optnum = 0; cfg_opts2[optnum].name; optnum++) {
				if (cfg_opts2[optnum].mode == PR_MODE_HTTP &&
				    (curproxy->cap & cfg_opts2[optnum].cap) &&
				    (curproxy->options2 & cfg_opts2[optnum].val)) {
					ha_warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
						   cfg_opts2[optnum].name, proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
					curproxy->options2 &= ~cfg_opts2[optnum].val;
				}
			}

#if defined(CONFIG_HAP_TRANSPARENT)
			if (curproxy->conn_src.bind_hdr_occ) {
				curproxy->conn_src.bind_hdr_occ = 0;
				ha_warning("config : %s '%s' : ignoring use of header %s as source IP in non-HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id, curproxy->conn_src.bind_hdr_name);
				err_code |= ERR_WARN;
			}
#endif
		}

		/*
		 * ensure that we're not cross-dressing a TCP server into HTTP.
		 */
		newsrv = curproxy->srv;
		while (newsrv != NULL) {
			if ((curproxy->mode != PR_MODE_HTTP) && newsrv->rdr_len) {
				ha_alert("config : %s '%s' : server cannot have cookie or redirect prefix in non-HTTP mode.\n",
					 proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}

			if ((curproxy->mode != PR_MODE_HTTP) && newsrv->cklen) {
				ha_warning("config : %s '%s' : ignoring cookie for server '%s' as HTTP mode is disabled.\n",
					   proxy_type_str(curproxy), curproxy->id, newsrv->id);
				err_code |= ERR_WARN;
			}

			if ((newsrv->flags & SRV_F_MAPPORTS) && (curproxy->options2 & PR_O2_RDPC_PRST)) {
				ha_warning("config : %s '%s' : RDP cookie persistence will not work for server '%s' because it lacks an explicit port number.\n",
					   proxy_type_str(curproxy), curproxy->id, newsrv->id);
				err_code |= ERR_WARN;
			}

#if defined(CONFIG_HAP_TRANSPARENT)
			if (curproxy->mode != PR_MODE_HTTP && newsrv->conn_src.bind_hdr_occ) {
				newsrv->conn_src.bind_hdr_occ = 0;
				ha_warning("config : %s '%s' : server %s cannot use header %s as source IP in non-HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id, newsrv->id, newsrv->conn_src.bind_hdr_name);
				err_code |= ERR_WARN;
			}
#endif

			if ((curproxy->mode != PR_MODE_HTTP) && (curproxy->options & PR_O_REUSE_MASK) != PR_O_REUSE_NEVR)
				curproxy->options &= ~PR_O_REUSE_MASK;

			newsrv = newsrv->next;
		}

		/* Check filter configuration, if any */
		cfgerr += flt_check(curproxy);

		if (curproxy->cap & PR_CAP_FE) {
			if (!curproxy->accept)
				curproxy->accept = frontend_accept;

			if (curproxy->tcp_req.inspect_delay ||
			    !LIST_ISEMPTY(&curproxy->tcp_req.inspect_rules))
				curproxy->fe_req_ana |= AN_REQ_INSPECT_FE;

			if (curproxy->mode == PR_MODE_HTTP) {
				curproxy->fe_req_ana |= AN_REQ_WAIT_HTTP | AN_REQ_HTTP_PROCESS_FE;
				curproxy->fe_rsp_ana |= AN_RES_WAIT_HTTP | AN_RES_HTTP_PROCESS_FE;
			}

			if (curproxy->mode == PR_MODE_CLI) {
				curproxy->fe_req_ana |= AN_REQ_WAIT_CLI;
				curproxy->fe_rsp_ana |= AN_RES_WAIT_CLI;
			}

			/* both TCP and HTTP must check switching rules */
			curproxy->fe_req_ana |= AN_REQ_SWITCHING_RULES;

			/* Add filters analyzers if needed */
			if (!LIST_ISEMPTY(&curproxy->filter_configs)) {
				curproxy->fe_req_ana |= AN_REQ_FLT_START_FE | AN_REQ_FLT_XFER_DATA | AN_REQ_FLT_END;
				curproxy->fe_rsp_ana |= AN_RES_FLT_START_FE | AN_RES_FLT_XFER_DATA | AN_RES_FLT_END;
				if (curproxy->mode == PR_MODE_HTTP) {
					curproxy->fe_req_ana |= AN_REQ_FLT_HTTP_HDRS;
					curproxy->fe_rsp_ana |= AN_RES_FLT_HTTP_HDRS;
				}
			}
		}

		if (curproxy->cap & PR_CAP_BE) {
			if (curproxy->tcp_req.inspect_delay ||
			    !LIST_ISEMPTY(&curproxy->tcp_req.inspect_rules))
				curproxy->be_req_ana |= AN_REQ_INSPECT_BE;

			if (!LIST_ISEMPTY(&curproxy->tcp_rep.inspect_rules))
                                curproxy->be_rsp_ana |= AN_RES_INSPECT;

			if (curproxy->mode == PR_MODE_HTTP) {
				curproxy->be_req_ana |= AN_REQ_WAIT_HTTP | AN_REQ_HTTP_INNER | AN_REQ_HTTP_PROCESS_BE;
				curproxy->be_rsp_ana |= AN_RES_WAIT_HTTP | AN_RES_HTTP_PROCESS_BE;
			}

			/* If the backend does requires RDP cookie persistence, we have to
			 * enable the corresponding analyser.
			 */
			if (curproxy->options2 & PR_O2_RDPC_PRST)
				curproxy->be_req_ana |= AN_REQ_PRST_RDP_COOKIE;

			/* Add filters analyzers if needed */
			if (!LIST_ISEMPTY(&curproxy->filter_configs)) {
				curproxy->be_req_ana |= AN_REQ_FLT_START_BE | AN_REQ_FLT_XFER_DATA | AN_REQ_FLT_END;
				curproxy->be_rsp_ana |= AN_RES_FLT_START_BE | AN_RES_FLT_XFER_DATA | AN_RES_FLT_END;
				if (curproxy->mode == PR_MODE_HTTP) {
					curproxy->be_req_ana |= AN_REQ_FLT_HTTP_HDRS;
					curproxy->be_rsp_ana |= AN_RES_FLT_HTTP_HDRS;
				}
			}
		}

		/* Check the mux protocols, if any, for each listener and server
		 * attached to the current proxy */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			int mode = (1 << (curproxy->mode == PR_MODE_HTTP));
			const struct mux_proto_list *mux_ent;

			if (!bind_conf->mux_proto)
				continue;

			/* it is possible that an incorrect mux was referenced
			 * due to the proxy's mode not being taken into account
			 * on first pass. Let's adjust it now.
			 */
			mux_ent = conn_get_best_mux_entry(bind_conf->mux_proto->token, PROTO_SIDE_FE, mode);

			if (!mux_ent || !isteq(mux_ent->token, bind_conf->mux_proto->token)) {
				ha_alert("config : %s '%s' : MUX protocol '%.*s' is not usable for 'bind %s' at [%s:%d].\n",
					 proxy_type_str(curproxy), curproxy->id,
					 (int)bind_conf->mux_proto->token.len,
					 bind_conf->mux_proto->token.ptr,
					 bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr++;
			}

			/* update the mux */
			bind_conf->mux_proto = mux_ent;
		}
		for (newsrv = curproxy->srv; newsrv; newsrv = newsrv->next) {
			int mode = (1 << (curproxy->mode == PR_MODE_HTTP));
			const struct mux_proto_list *mux_ent;

			if (!newsrv->mux_proto)
				continue;

			/* it is possible that an incorrect mux was referenced
			 * due to the proxy's mode not being taken into account
			 * on first pass. Let's adjust it now.
			 */
			mux_ent = conn_get_best_mux_entry(newsrv->mux_proto->token, PROTO_SIDE_BE, mode);

			if (!mux_ent || !isteq(mux_ent->token, newsrv->mux_proto->token)) {
				ha_alert("config : %s '%s' : MUX protocol '%.*s' is not usable for server '%s' at [%s:%d].\n",
					 proxy_type_str(curproxy), curproxy->id,
					 (int)newsrv->mux_proto->token.len,
					 newsrv->mux_proto->token.ptr,
					 newsrv->id, newsrv->conf.file, newsrv->conf.line);
				cfgerr++;
			}

			/* update the mux */
			newsrv->mux_proto = mux_ent;
		}

		/* initialize idle conns lists */
		for (newsrv = curproxy->srv; newsrv; newsrv = newsrv->next) {
			int i;

			newsrv->available_conns = calloc(global.nbthread, sizeof(*newsrv->available_conns));

			if (!newsrv->available_conns) {
				ha_alert("parsing [%s:%d] : failed to allocate idle connections for server '%s'.\n",
				    newsrv->conf.file, newsrv->conf.line, newsrv->id);
				cfgerr++;
				continue;
			}

			for (i = 0; i < global.nbthread; i++)
				LIST_INIT(&newsrv->available_conns[i]);

			if (newsrv->max_idle_conns != 0) {
				if (idle_conn_task == NULL) {
					idle_conn_task = task_new(MAX_THREADS_MASK);
					if (!idle_conn_task)
						goto err;

					idle_conn_task->process = srv_cleanup_idle_connections;
					idle_conn_task->context = NULL;

					for (i = 0; i < global.nbthread; i++) {
						idle_conns[i].cleanup_task = task_new(1UL << i);
						if (!idle_conns[i].cleanup_task)
							goto err;
						idle_conns[i].cleanup_task->process = srv_cleanup_toremove_connections;
						idle_conns[i].cleanup_task->context = NULL;
						HA_SPIN_INIT(&idle_conns[i].takeover_lock);
						MT_LIST_INIT(&idle_conns[i].toremove_conns);
					}
				}

				newsrv->idle_conns = calloc((unsigned short)global.nbthread, sizeof(*newsrv->idle_conns));
				if (!newsrv->idle_conns) {
					ha_alert("parsing [%s:%d] : failed to allocate idle connections for server '%s'.\n",
					    newsrv->conf.file, newsrv->conf.line, newsrv->id);
					cfgerr++;
					continue;
				}

				for (i = 0; i < global.nbthread; i++)
					MT_LIST_INIT(&newsrv->idle_conns[i]);

				newsrv->safe_conns = calloc(global.nbthread, sizeof(*newsrv->safe_conns));
				if (!newsrv->safe_conns) {
					ha_alert("parsing [%s:%d] : failed to allocate idle connections for server '%s'.\n",
					    newsrv->conf.file, newsrv->conf.line, newsrv->id);
					cfgerr++;
					continue;
				}

				for (i = 0; i < global.nbthread; i++)
					MT_LIST_INIT(&newsrv->safe_conns[i]);

				newsrv->curr_idle_thr = calloc(global.nbthread, sizeof(*newsrv->curr_idle_thr));
				if (!newsrv->curr_idle_thr)
					goto err;
				continue;
			err:
				ha_alert("parsing [%s:%d] : failed to allocate idle connection tasks for server '%s'.\n",
					 newsrv->conf.file, newsrv->conf.line, newsrv->id);
				cfgerr++;
				continue;
			}
		}
	}

	/***********************************************************/
	/* At this point, target names have already been resolved. */
	/***********************************************************/

	/* Check multi-process mode compatibility */

	if (global.nbproc > 1 && global.stats_fe) {
		list_for_each_entry(bind_conf, &global.stats_fe->conf.bind, by_fe) {
			unsigned long mask;

			mask  = proc_mask(global.stats_fe->bind_proc) && all_proc_mask;
			mask &= proc_mask(bind_conf->settings.bind_proc);

			/* stop here if more than one process is used */
			if (atleast2(mask))
				break;
		}
		if (&bind_conf->by_fe != &global.stats_fe->conf.bind) {
			ha_warning("stats socket will not work as expected in multi-process mode (nbproc > 1), you should force process binding globally using 'stats bind-process' or per socket using the 'process' attribute.\n");
		}
	}

	/* Make each frontend inherit bind-process from its listeners when not specified. */
	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		if (curproxy->bind_proc)
			continue;

		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			unsigned long mask;

			mask = proc_mask(bind_conf->settings.bind_proc);
			curproxy->bind_proc |= mask;
		}
		curproxy->bind_proc = proc_mask(curproxy->bind_proc);
	}

	if (global.stats_fe) {
		list_for_each_entry(bind_conf, &global.stats_fe->conf.bind, by_fe) {
			unsigned long mask;

			mask = bind_conf->settings.bind_proc ? bind_conf->settings.bind_proc : 0;
			global.stats_fe->bind_proc |= mask;
		}
		global.stats_fe->bind_proc = proc_mask(global.stats_fe->bind_proc);
	}

	/* propagate bindings from frontends to backends. Don't do it if there
	 * are any fatal errors as we must not call it with unresolved proxies.
	 */
	if (!cfgerr) {
		for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
			if (curproxy->cap & PR_CAP_FE)
				propagate_processes(curproxy, NULL);
		}
	}

	/* Bind each unbound backend to all processes when not specified. */
	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next)
		curproxy->bind_proc = proc_mask(curproxy->bind_proc);

	/*******************************************************/
	/* At this step, all proxies have a non-null bind_proc */
	/*******************************************************/

	/* perform the final checks before creating tasks */

	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		struct listener *listener;
		unsigned int next_id;

		/* Configure SSL for each bind line.
		 * Note: if configuration fails at some point, the ->ctx member
		 * remains NULL so that listeners can later detach.
		 */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			if (bind_conf->xprt->prepare_bind_conf &&
			    bind_conf->xprt->prepare_bind_conf(bind_conf) < 0)
				cfgerr++;
		}

		/* adjust this proxy's listeners */
		next_id = 1;
		list_for_each_entry(listener, &curproxy->conf.listeners, by_fe) {
			int nbproc;

			nbproc = my_popcountl(curproxy->bind_proc &
			                      (listener->bind_conf->settings.bind_proc ? listener->bind_conf->settings.bind_proc : curproxy->bind_proc) &
			                      all_proc_mask);

			if (!nbproc) /* no intersection between listener and frontend */
				nbproc = 1;

			if (!listener->luid) {
				/* listener ID not set, use automatic numbering with first
				 * spare entry starting with next_luid.
				 */
				next_id = get_next_id(&curproxy->conf.used_listener_id, next_id);
				listener->conf.id.key = listener->luid = next_id;
				eb32_insert(&curproxy->conf.used_listener_id, &listener->conf.id);
			}
			next_id++;

			/* enable separate counters */
			if (curproxy->options2 & PR_O2_SOCKSTAT) {
				listener->counters = calloc(1, sizeof(*listener->counters));
				if (!listener->name)
					memprintf(&listener->name, "sock-%d", listener->luid);
			}

			if (curproxy->options & PR_O_TCP_NOLING)
				listener->options |= LI_O_NOLINGER;
			if (!listener->maxaccept)
				listener->maxaccept = global.tune.maxaccept ? global.tune.maxaccept : 64;

			/* we want to have an optimal behaviour on single process mode to
			 * maximize the work at once, but in multi-process we want to keep
			 * some fairness between processes, so we target half of the max
			 * number of events to be balanced over all the processes the proxy
			 * is bound to. Remember that maxaccept = -1 must be kept as it is
			 * used to disable the limit.
			 */
			if (listener->maxaccept > 0 && nbproc > 1) {
				listener->maxaccept = (listener->maxaccept + 1) / 2;
				listener->maxaccept = (listener->maxaccept + nbproc - 1) / nbproc;
			}

			listener->accept = session_accept_fd;
			listener->analysers |= curproxy->fe_req_ana;
			listener->default_target = curproxy->default_target;

			if (!LIST_ISEMPTY(&curproxy->tcp_req.l4_rules))
				listener->options |= LI_O_TCP_L4_RULES;

			if (!LIST_ISEMPTY(&curproxy->tcp_req.l5_rules))
				listener->options |= LI_O_TCP_L5_RULES;

			/* smart accept mode is automatic in HTTP mode */
			if ((curproxy->options2 & PR_O2_SMARTACC) ||
			    ((curproxy->mode == PR_MODE_HTTP || listener->bind_conf->is_ssl) &&
			     !(curproxy->no_options2 & PR_O2_SMARTACC)))
				listener->options |= LI_O_NOQUICKACK;
		}

		/* Release unused SSL configs */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			if (!bind_conf->is_ssl && bind_conf->xprt->destroy_bind_conf)
				bind_conf->xprt->destroy_bind_conf(bind_conf);
		}

		if (atleast2(curproxy->bind_proc & all_proc_mask)) {
			if (curproxy->uri_auth) {
				int count, maxproc = 0;

				list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
					count = my_popcountl(bind_conf->settings.bind_proc);
					if (count > maxproc)
						maxproc = count;
				}
				/* backends have 0, frontends have 1 or more */
				if (maxproc != 1)
					ha_warning("Proxy '%s': in multi-process mode, stats will be"
						   " limited to process assigned to the current request.\n",
						   curproxy->id);

				if (!LIST_ISEMPTY(&curproxy->uri_auth->admin_rules)) {
					ha_warning("Proxy '%s': stats admin will not work correctly in multi-process mode.\n",
						   curproxy->id);
				}
			}
			if (!LIST_ISEMPTY(&curproxy->sticking_rules)) {
				ha_warning("Proxy '%s': sticking rules will not work correctly in multi-process mode.\n",
					   curproxy->id);
			}
		}

		/* create the task associated with the proxy */
		curproxy->task = task_new(MAX_THREADS_MASK);
		if (curproxy->task) {
			curproxy->task->context = curproxy;
			curproxy->task->process = manage_proxy;
		} else {
			ha_alert("Proxy '%s': no more memory when trying to allocate the management task\n",
				 curproxy->id);
			cfgerr++;
		}
	}

	/*
	 * Recount currently required checks.
	 */

	for (curproxy=proxies_list; curproxy; curproxy=curproxy->next) {
		int optnum;

		for (optnum = 0; cfg_opts[optnum].name; optnum++)
			if (curproxy->options & cfg_opts[optnum].val)
				global.last_checks |= cfg_opts[optnum].checks;

		for (optnum = 0; cfg_opts2[optnum].name; optnum++)
			if (curproxy->options2 & cfg_opts2[optnum].val)
				global.last_checks |= cfg_opts2[optnum].checks;
	}

	/* compute the required process bindings for the peers */
	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next)
		if (curproxy->table && curproxy->table->peers.p)
			curproxy->table->peers.p->peers_fe->bind_proc |= curproxy->bind_proc;

	/* compute the required process bindings for the peers from <stktables_list>
	 * for all the stick-tables, the ones coming with "peers" sections included.
	 */
	for (t = stktables_list; t; t = t->next) {
		struct proxy *p;

		for (p = t->proxies_list; p; p = p->next_stkt_ref) {
			if (t->peers.p && t->peers.p->peers_fe) {
				t->peers.p->peers_fe->bind_proc |= p->bind_proc;
			}
		}
	}

	if (cfg_peers) {
		struct peers *curpeers = cfg_peers, **last;
		struct peer *p, *pb;

		/* In the case the peers frontend was not initialized by a
		 stick-table used in the configuration, set its bind_proc
		 by default to the first process. */
		while (curpeers) {
			if (curpeers->peers_fe) {
				if (curpeers->peers_fe->bind_proc == 0)
					curpeers->peers_fe->bind_proc = 1;
			}
			curpeers = curpeers->next;
		}

		curpeers = cfg_peers;
		/* Remove all peers sections which don't have a valid listener,
		 * which are not used by any table, or which are bound to more
		 * than one process.
		 */
		last = &cfg_peers;
		while (*last) {
			struct stktable *t;
			curpeers = *last;

			if (curpeers->disabled) {
				/* the "disabled" keyword was present */
				if (curpeers->peers_fe)
					stop_proxy(curpeers->peers_fe);
				curpeers->peers_fe = NULL;
			}
			else if (!curpeers->peers_fe || !curpeers->peers_fe->id) {
				ha_warning("Removing incomplete section 'peers %s' (no peer named '%s').\n",
					   curpeers->id, localpeer);
				if (curpeers->peers_fe)
					stop_proxy(curpeers->peers_fe);
				curpeers->peers_fe = NULL;
			}
			else if (atleast2(curpeers->peers_fe->bind_proc)) {
				/* either it's totally stopped or too much used */
				if (curpeers->peers_fe->bind_proc) {
					ha_alert("Peers section '%s': peers referenced by sections "
						 "running in different processes (%d different ones). "
						 "Check global.nbproc and all tables' bind-process "
						 "settings.\n", curpeers->id, my_popcountl(curpeers->peers_fe->bind_proc));
					cfgerr++;
				}
				stop_proxy(curpeers->peers_fe);
				curpeers->peers_fe = NULL;
			}
			else {
				/* Initializes the transport layer of the server part of all the peers belonging to
				 * <curpeers> section if required.
				 * Note that ->srv is used by the local peer of a new process to connect to the local peer
				 * of an old process.
				 */
				p = curpeers->remote;
				while (p) {
					if (p->srv) {
						if (p->srv->use_ssl == 1 && xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->prepare_srv)
							cfgerr += xprt_get(XPRT_SSL)->prepare_srv(p->srv);
					}
					p = p->next;
				}
				/* Configure the SSL bindings of the local peer if required. */
				if (!LIST_ISEMPTY(&curpeers->peers_fe->conf.bind)) {
					struct list *l;
					struct bind_conf *bind_conf;

					l = &curpeers->peers_fe->conf.bind;
					bind_conf = LIST_ELEM(l->n, typeof(bind_conf), by_fe);
					if (bind_conf->xprt->prepare_bind_conf &&
						bind_conf->xprt->prepare_bind_conf(bind_conf) < 0)
						cfgerr++;
				}
				if (!peers_init_sync(curpeers) || !peers_alloc_dcache(curpeers)) {
					ha_alert("Peers section '%s': out of memory, giving up on peers.\n",
						 curpeers->id);
					cfgerr++;
					break;
				}
				last = &curpeers->next;
				continue;
			}

			/* clean what has been detected above */
			p = curpeers->remote;
			while (p) {
				pb = p->next;
				free(p->id);
				free(p);
				p = pb;
			}

			/* Destroy and unlink this curpeers section.
			 * Note: curpeers is backed up into *last.
			 */
			free(curpeers->id);
			curpeers = curpeers->next;
			/* Reset any refereance to this peers section in the list of stick-tables */
			for (t = stktables_list; t; t = t->next) {
				if (t->peers.p && t->peers.p == *last)
					t->peers.p = NULL;
			}
			free(*last);
			*last = curpeers;
		}
	}

	for (t = stktables_list; t; t = t->next) {
		if (t->proxy)
			continue;
		if (!stktable_init(t)) {
			ha_alert("Proxy '%s': failed to initialize stick-table.\n", t->id);
			cfgerr++;
		}
	}

	/* initialize stick-tables on backend capable proxies. This must not
	 * be done earlier because the data size may be discovered while parsing
	 * other proxies.
	 */
	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		if (curproxy->disabled || !curproxy->table)
			continue;

		if (!stktable_init(curproxy->table)) {
			ha_alert("Proxy '%s': failed to initialize stick-table.\n", curproxy->id);
			cfgerr++;
		}
	}

	if (mailers) {
		struct mailers *curmailers = mailers, **last;
		struct mailer *m, *mb;

		/* Remove all mailers sections which don't have a valid listener.
		 * This can happen when a mailers section is never referenced.
		 */
		last = &mailers;
		while (*last) {
			curmailers = *last;
			if (curmailers->users) {
				last = &curmailers->next;
				continue;
			}

			ha_warning("Removing incomplete section 'mailers %s'.\n",
				   curmailers->id);

			m = curmailers->mailer_list;
			while (m) {
				mb = m->next;
				free(m->id);
				free(m);
				m = mb;
			}

			/* Destroy and unlink this curmailers section.
			 * Note: curmailers is backed up into *last.
			 */
			free(curmailers->id);
			curmailers = curmailers->next;
			free(*last);
			*last = curmailers;
		}
	}

	/* Update server_state_file_name to backend name if backend is supposed to use
	 * a server-state file locally defined and none has been provided */
	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		if (curproxy->load_server_state_from_file == PR_SRV_STATE_FILE_LOCAL &&
		    curproxy->server_state_file_name == NULL)
			curproxy->server_state_file_name = strdup(curproxy->id);
	}

	list_for_each_entry(curr_resolvers, &dns_resolvers, list) {
		if (LIST_ISEMPTY(&curr_resolvers->nameservers)) {
			ha_warning("config : resolvers '%s' [%s:%d] has no nameservers configured!\n",
				   curr_resolvers->id, curr_resolvers->conf.file,
				   curr_resolvers->conf.line);
			err_code |= ERR_WARN;
		}
	}

	list_for_each_entry(postparser, &postparsers, list) {
		if (postparser->func)
			cfgerr += postparser->func();
	}

	if (cfgerr > 0)
		err_code |= ERR_ALERT | ERR_FATAL;
 out:
	return err_code;
}

/*
 * Registers the CFG keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void cfg_register_keywords(struct cfg_kw_list *kwl)
{
	LIST_ADDQ(&cfg_keywords.list, &kwl->list);
}

/*
 * Unregisters the CFG keyword list <kwl> from the list of valid keywords.
 */
void cfg_unregister_keywords(struct cfg_kw_list *kwl)
{
	LIST_DEL(&kwl->list);
	LIST_INIT(&kwl->list);
}

/* this function register new section in the haproxy configuration file.
 * <section_name> is the name of this new section and <section_parser>
 * is the called parser. If two section declaration have the same name,
 * only the first declared is used.
 */
int cfg_register_section(char *section_name,
                         int (*section_parser)(const char *, int, char **, int),
                         int (*post_section_parser)())
{
	struct cfg_section *cs;

	list_for_each_entry(cs, &sections, list) {
		if (strcmp(cs->section_name, section_name) == 0) {
			ha_alert("register section '%s': already registered.\n", section_name);
			return 0;
		}
	}

	cs = calloc(1, sizeof(*cs));
	if (!cs) {
		ha_alert("register section '%s': out of memory.\n", section_name);
		return 0;
	}

	cs->section_name = section_name;
	cs->section_parser = section_parser;
	cs->post_section_parser = post_section_parser;

	LIST_ADDQ(&sections, &cs->list);

	return 1;
}

/* this function register a new function which will be called once the haproxy
 * configuration file has been parsed. It's useful to check dependencies
 * between sections or to resolve items once everything is parsed.
 */
int cfg_register_postparser(char *name, int (*func)())
{
	struct cfg_postparser *cp;

	cp = calloc(1, sizeof(*cp));
	if (!cp) {
		ha_alert("register postparser '%s': out of memory.\n", name);
		return 0;
	}
	cp->name = name;
	cp->func = func;

	LIST_ADDQ(&postparsers, &cp->list);

	return 1;
}

/*
 * free all config section entries
 */
void cfg_unregister_sections(void)
{
	struct cfg_section *cs, *ics;

	list_for_each_entry_safe(cs, ics, &sections, list) {
		LIST_DEL(&cs->list);
		free(cs);
	}
}

void cfg_backup_sections(struct list *backup_sections)
{
	struct cfg_section *cs, *ics;

	list_for_each_entry_safe(cs, ics, &sections, list) {
		LIST_DEL(&cs->list);
		LIST_ADDQ(backup_sections, &cs->list);
	}
}

void cfg_restore_sections(struct list *backup_sections)
{
	struct cfg_section *cs, *ics;

	list_for_each_entry_safe(cs, ics, backup_sections, list) {
		LIST_DEL(&cs->list);
		LIST_ADDQ(&sections, &cs->list);
	}
}

/* these are the config sections handled by default */
REGISTER_CONFIG_SECTION("listen",         cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("frontend",       cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("backend",        cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("defaults",       cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("global",         cfg_parse_global,    NULL);
REGISTER_CONFIG_SECTION("userlist",       cfg_parse_users,     NULL);
REGISTER_CONFIG_SECTION("peers",          cfg_parse_peers,     NULL);
REGISTER_CONFIG_SECTION("mailers",        cfg_parse_mailers,   NULL);
REGISTER_CONFIG_SECTION("namespace_list", cfg_parse_netns,     NULL);
REGISTER_CONFIG_SECTION("resolvers",      cfg_parse_resolvers, NULL);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
