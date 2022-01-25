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

#include <dirent.h>
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
#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/auth.h>
#include <haproxy/backend.h>
#include <haproxy/capture.h>
#include <haproxy/cfgcond.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#ifdef USE_CPU_AFFINITY
#include <haproxy/cpuset.h>
#endif
#include <haproxy/connection.h>
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
#include <haproxy/quic_sock.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/peers-t.h>
#include <haproxy/peers.h>
#include <haproxy/pool.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/resolvers.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth-t.h>
#include <haproxy/xprt_quic.h>


/* Used to chain configuration sections definitions. This list
 * stores struct cfg_section
 */
struct list sections = LIST_HEAD_INIT(sections);

struct list postparsers = LIST_HEAD_INIT(postparsers);

extern struct proxy *mworker_proxy;

char *cursection = NULL;
int cfg_maxpconn = 0;                   /* # of simultaneous connections per proxy (-N) */
int cfg_maxconn = 0;			/* # of simultaneous connections, (-n) */
char *cfg_scope = NULL;                 /* the current scope during the configuration parsing */

/* how to handle default paths */
static enum default_path_mode {
	DEFAULT_PATH_CURRENT = 0,  /* "current": paths are relative to CWD (this is the default) */
	DEFAULT_PATH_CONFIG,       /* "config": paths are relative to config file */
	DEFAULT_PATH_PARENT,       /* "parent": paths are relative to config file's ".." */
	DEFAULT_PATH_ORIGIN,       /* "origin": paths are relative to default_path_origin */
} default_path_mode;

static char initial_cwd[PATH_MAX];
static char current_cwd[PATH_MAX];

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
		                   (curproxy == global.cli_fe || curproxy == mworker_proxy) ? NULL : global.unix_bind.prefix,
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
		if (proto->proto_type == PROTO_TYPE_DGRAM && proto->ctrl_type == SOCK_STREAM) {
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
		                   curproxy == global.cli_fe ? NULL : global.unix_bind.prefix,
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
 * Sends a warning if proxy <proxy> does not have at least one of the
 * capabilities in <cap>. An optional <hint> may be added at the end
 * of the warning to help the user. Returns 1 if a warning was emitted
 * or 0 if the condition is valid.
 */
int warnifnotcap(struct proxy *proxy, int cap, const char *file, int line, const char *arg, const char *hint)
{
	char *msg;

	switch (cap) {
	case PR_CAP_BE: msg = "no backend"; break;
	case PR_CAP_FE: msg = "no frontend"; break;
	case PR_CAP_BE|PR_CAP_FE: msg = "neither frontend nor backend"; break;
	default: msg = "not enough"; break;
	}

	if (!(proxy->cap & cap)) {
		ha_warning("parsing [%s:%d] : '%s' ignored because %s '%s' has %s capability.%s\n",
			   file, line, arg, proxy_type_str(proxy), proxy->id, msg, hint ? hint : "");
		return 1;
	}
	return 0;
}

/*
 * Sends an alert if proxy <proxy> does not have at least one of the
 * capabilities in <cap>. An optional <hint> may be added at the end
 * of the alert to help the user. Returns 1 if an alert was emitted
 * or 0 if the condition is valid.
 */
int failifnotcap(struct proxy *proxy, int cap, const char *file, int line, const char *arg, const char *hint)
{
	char *msg;

	switch (cap) {
	case PR_CAP_BE: msg = "no backend"; break;
	case PR_CAP_FE: msg = "no frontend"; break;
	case PR_CAP_BE|PR_CAP_FE: msg = "neither frontend nor backend"; break;
	default: msg = "not enough"; break;
	}

	if (!(proxy->cap & cap)) {
		ha_alert("parsing [%s:%d] : '%s' not allowed because %s '%s' has %s capability.%s\n",
			 file, line, arg, proxy_type_str(proxy), proxy->id, msg, hint ? hint : "");
		return 1;
	}
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

/* Report it if an ACL uses a L6 sample fetch from an HTTP proxy.  It returns
 * either 0 or ERR_WARN so that its result can be or'ed with err_code. Note that
 * <cond> may be NULL and then will be ignored.
*/
int warnif_tcp_http_cond(const struct proxy *px, const struct acl_cond *cond)
{
	if (!cond || px->mode != PR_MODE_HTTP)
		return 0;

	if (cond->use & (SMP_USE_L6REQ|SMP_USE_L6RES)) {
		ha_warning("Proxy '%s': L6 sample fetches ignored on HTTP proxies (declared at %s:%d).\n",
			   px->id, cond->file, cond->line);
		return ERR_WARN;
	}
	return 0;
}

/* try to find in <list> the word that looks closest to <word> by counting
 * transitions between letters, digits and other characters. Will return the
 * best matching word if found, otherwise NULL. An optional array of extra
 * words to compare may be passed in <extra>, but it must then be terminated
 * by a NULL entry. If unused it may be NULL.
 */
const char *cfg_find_best_match(const char *word, const struct list *list, int section, const char **extra)
{
	uint8_t word_sig[1024]; // 0..25=letter, 26=digit, 27=other, 28=begin, 29=end
	uint8_t list_sig[1024];
	const struct cfg_kw_list *kwl;
	int index;
	const char *best_ptr = NULL;
	int dist, best_dist = INT_MAX;

	make_word_fingerprint(word_sig, word);
	list_for_each_entry(kwl, list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].section != section)
				continue;

			make_word_fingerprint(list_sig, kwl->kw[index].kw);
			dist = word_fingerprint_distance(word_sig, list_sig);
			if (dist < best_dist) {
				best_dist = dist;
				best_ptr = kwl->kw[index].kw;
			}
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
 * ha_cpuset_size() - 1 or a range with two such numbers delimited by a dash
 * ('-'). If <comma_allowed> is set, each CPU set can be a list of unique
 * numbers or ranges separated by a comma. It is also possible to specify
 * multiple cpu numbers or ranges in distinct argument in <args>. On success,
 * it returns 0, otherwise it returns 1 with an error message in <err>.
 */
unsigned long parse_cpu_set(const char **args, struct hap_cpuset *cpu_set,
                            int comma_allowed, char **err)
{
	int cur_arg = 0;
	const char *arg;

	ha_cpuset_zero(cpu_set);

	arg = args[cur_arg];
	while (*arg) {
		const char *dash, *comma;
		unsigned int low, high;

		if (!isdigit((unsigned char)*args[cur_arg])) {
			memprintf(err, "'%s' is not a CPU range.", arg);
			return -1;
		}

		low = high = str2uic(arg);

		comma = comma_allowed ? strchr(arg, ',') : NULL;
		dash = strchr(arg, '-');

		if (dash && (!comma || dash < comma))
			high = *(dash+1) ? str2uic(dash + 1) : ha_cpuset_size() - 1;

		if (high < low) {
			unsigned int swap = low;
			low = high;
			high = swap;
		}

		if (high >= ha_cpuset_size()) {
			memprintf(err, "supports CPU numbers from 0 to %d.",
			          ha_cpuset_size() - 1);
			return 1;
		}

		while (low <= high)
			ha_cpuset_set(cpu_set, low++);

		/* if a comma is present, parse the rest of the arg, else
		 * skip to the next arg */
		arg = comma ? comma + 1 : args[++cur_arg];
	}
	return 0;
}
#endif

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
			const char *best = bind_find_best_kw(args[cur_arg]);
			if (best)
				ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n",
					 file, linenum, args[cur_arg], cursection, best);
			else
				ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section.\n",
					 file, linenum, args[cur_arg], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "default-server") == 0) {
		if (init_peers_frontend(file, -1, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		err_code |= parse_server(file, linenum, args, curpeers->peers_fe, NULL,
		                         SRV_PARSE_DEFAULT_SERVER|SRV_PARSE_IN_PEER_SECTION|SRV_PARSE_INITIAL_RESOLVE);
	}
	else if (strcmp(args[0], "log") == 0) {
		if (init_peers_frontend(file, linenum, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (!parse_logsrv(args, &curpeers->peers_fe->logsrvs, (kwm == KWM_NO), file, linenum, &errmsg)) {
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
		int parse_addr = 0;

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
		parse_addr = (peer || !local_peer) ? SRV_PARSE_PARSE_ADDR : 0;
		err_code |= parse_server(file, linenum, args, curpeers->peers_fe, NULL,
		                         SRV_PARSE_IN_PEER_SECTION|parse_addr|SRV_PARSE_INITIAL_RESOLVE);
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
			newpeer->proto = protocol_lookup(newpeer->addr.ss_family, PROTO_TYPE_STREAM, 0);
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
		curpeers->disabled |= PR_FL_DISABLED;
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
	ha_free(&p->email_alert.mailers.name);
	ha_free(&p->email_alert.from);
	ha_free(&p->email_alert.to);
	ha_free(&p->email_alert.myhostname);
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
 * Detect a global section after a non-global one and output a diagnostic
 * warning.
 */
static void check_section_position(char *section_name,
                                   const char *file, int linenum,
                                   int *non_global_parsed)
{
	if (strcmp(section_name, "global") == 0) {
		if (*non_global_parsed == 1)
		        _ha_diag_warning("parsing [%s:%d] : global section detected after a non-global one, the prevalence of their statements is unspecified\n", file, linenum);
	}
	else if (*non_global_parsed == 0) {
		*non_global_parsed = 1;
	}
}

/* apply the current default_path setting for config file <file>, and
 * optionally replace the current path to <origin> if not NULL while the
 * default-path mode is set to "origin". Errors are returned into an
 * allocated string passed to <err> if it's not NULL. Returns 0 on failure
 * or non-zero on success.
 */
static int cfg_apply_default_path(const char *file, const char *origin, char **err)
{
	const char *beg, *end;

	/* make path start at <beg> and end before <end>, and switch it to ""
	 * if no slash was passed.
	 */
	beg = file;
	end = strrchr(beg, '/');
	if (!end)
		end = beg;

	if (!*initial_cwd) {
		if (getcwd(initial_cwd, sizeof(initial_cwd)) == NULL) {
			if (err)
				memprintf(err, "Impossible to retrieve startup directory name: %s", strerror(errno));
			return 0;
		}
	}
	else if (chdir(initial_cwd) == -1) {
		if (err)
			memprintf(err, "Impossible to get back to initial directory '%s': %s", initial_cwd, strerror(errno));
		return 0;
	}

	/* OK now we're (back) to initial_cwd */

	switch (default_path_mode) {
	case DEFAULT_PATH_CURRENT:
		/* current_cwd never set, nothing to do */
		return 1;

	case DEFAULT_PATH_ORIGIN:
		/* current_cwd set in the config */
		if (origin &&
		    snprintf(current_cwd, sizeof(current_cwd), "%s", origin) > sizeof(current_cwd)) {
			if (err)
				memprintf(err, "Absolute path too long: '%s'", origin);
			return 0;
		}
		break;

	case DEFAULT_PATH_CONFIG:
		if (end - beg >= sizeof(current_cwd)) {
			if (err)
				memprintf(err, "Config file path too long, cannot use for relative paths: '%s'", file);
			return 0;
		}
		memcpy(current_cwd, beg, end - beg);
		current_cwd[end - beg] = 0;
		break;

	case DEFAULT_PATH_PARENT:
		if (end - beg + 3 >= sizeof(current_cwd)) {
			if (err)
				memprintf(err, "Config file path too long, cannot use for relative paths: '%s'", file);
			return 0;
		}
		memcpy(current_cwd, beg, end - beg);
		if (end > beg)
			memcpy(current_cwd + (end - beg), "/..\0", 4);
		else
			memcpy(current_cwd + (end - beg), "..\0", 3);
		break;
	}

	if (*current_cwd && chdir(current_cwd) == -1) {
		if (err)
			memprintf(err, "Impossible to get back to directory '%s': %s", initial_cwd, strerror(errno));
		return 0;
	}

	return 1;
}

/* parses a global "default-path" directive. */
static int cfg_parse_global_def_path(char **args, int section_type, struct proxy *curpx,
                                     const struct proxy *defpx, const char *file, int line,
                                     char **err)
{
	int ret = -1;

	/* "current", "config", "parent", "origin <path>" */

	if (strcmp(args[1], "current") == 0)
		default_path_mode = DEFAULT_PATH_CURRENT;
	else if (strcmp(args[1], "config") == 0)
		default_path_mode = DEFAULT_PATH_CONFIG;
	else if (strcmp(args[1], "parent") == 0)
		default_path_mode = DEFAULT_PATH_PARENT;
	else if (strcmp(args[1], "origin") == 0)
		default_path_mode = DEFAULT_PATH_ORIGIN;
	else {
		memprintf(err, "%s default-path mode '%s' for '%s', supported modes include 'current', 'config', 'parent', and 'origin'.", *args[1] ? "unsupported" : "missing", args[1], args[0]);
		goto end;
	}

	if (default_path_mode == DEFAULT_PATH_ORIGIN) {
		if (!*args[2]) {
			memprintf(err, "'%s %s' expects a directory as an argument.", args[0], args[1]);
			goto end;
		}
		if (!cfg_apply_default_path(file, args[2], err)) {
			memprintf(err, "couldn't set '%s' to origin '%s': %s.", args[0], args[2], *err);
			goto end;
		}
	}
	else if (!cfg_apply_default_path(file, NULL, err)) {
		memprintf(err, "couldn't set '%s' to '%s': %s.", args[0], args[1], *err);
		goto end;
	}

	/* note that once applied, the path is immediately updated */

	ret = 0;
 end:
	return ret;
}

/*
 * This function reads and parses the configuration file given in the argument.
 * Returns the error code, 0 if OK, -1 if the config file couldn't be opened,
 * or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int readcfgfile(const char *file)
{
	char *thisline = NULL;
	int linesize = LINESIZE;
	FILE *f = NULL;
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
	int nested_cond_lvl = 0;
	enum nested_cond_state nested_conds[MAXNESTEDCONDS];
	int non_global_section_parsed = 0;
	char *errmsg = NULL;

	global.cfg_curr_line = 0;
	global.cfg_curr_file = file;

	if ((thisline = malloc(sizeof(*thisline) * linesize)) == NULL) {
		ha_alert("Out of memory trying to allocate a buffer for a configuration line.\n");
		err_code = -1;
		goto err;
	}

	if ((f = fopen(file,"r")) == NULL) {
		err_code = -1;
		goto err;
	}

	/* change to the new dir if required */
	if (!cfg_apply_default_path(file, NULL, &errmsg)) {
		ha_alert("parsing [%s:%d]: failed to apply default-path: %s.\n", file, linenum, errmsg);
		free(errmsg);
		err_code = -1;
		goto err;
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
		global.cfg_curr_line = linenum;

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
			const char *errptr;

			arg = sizeof(args) / sizeof(*args);
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
				outline = my_realloc2(outline, outlinesize);
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

		/* check for config macros */
		if (*args[0] == '.') {
			if (strcmp(args[0], ".if") == 0) {
				const char *errptr = NULL;
				char *errmsg = NULL;
				int cond;
				char *w;

				/* remerge all words into a single expression */
				for (w = *args; (w += strlen(w)) < outline + outlen - 1; *w = ' ')
					;

				nested_cond_lvl++;
				if (nested_cond_lvl >= MAXNESTEDCONDS) {
					ha_alert("parsing [%s:%d]: too many nested '.if', max is %d.\n", file, linenum, MAXNESTEDCONDS);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto err;
				}

				if (nested_cond_lvl > 1 &&
				    (nested_conds[nested_cond_lvl - 1] == NESTED_COND_IF_DROP ||
				     nested_conds[nested_cond_lvl - 1] == NESTED_COND_IF_SKIP ||
				     nested_conds[nested_cond_lvl - 1] == NESTED_COND_ELIF_DROP ||
				     nested_conds[nested_cond_lvl - 1] == NESTED_COND_ELIF_SKIP ||
				     nested_conds[nested_cond_lvl - 1] == NESTED_COND_ELSE_DROP)) {
					nested_conds[nested_cond_lvl] = NESTED_COND_IF_SKIP;
					goto next_line;
				}

				cond = cfg_eval_condition(args + 1, &errmsg, &errptr);
				if (cond < 0) {
					size_t newpos = sanitize_for_printing(args[1], errptr - args[1], 76);

					ha_alert("parsing [%s:%d]: %s in '.if' at position %d:\n  .if %s\n  %*s\n",
						 file, linenum, errmsg,
					         (int)(errptr-args[1]+1), args[1], (int)(newpos+5), "^");

					free(errmsg);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto err;
				}

				if (cond)
					nested_conds[nested_cond_lvl] = NESTED_COND_IF_TAKE;
				else
					nested_conds[nested_cond_lvl] = NESTED_COND_IF_DROP;

				goto next_line;
			}
			else if (strcmp(args[0], ".elif") == 0) {
				const char *errptr = NULL;
				char *errmsg = NULL;
				int cond;
				char *w;

				/* remerge all words into a single expression */
				for (w = *args; (w += strlen(w)) < outline + outlen - 1; *w = ' ')
					;

				if (!nested_cond_lvl) {
					ha_alert("parsing [%s:%d]: lone '.elif' with no matching '.if'.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto err;
				}

				if (nested_conds[nested_cond_lvl] == NESTED_COND_ELSE_TAKE ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_ELSE_DROP) {
					ha_alert("parsing [%s:%d]: '.elif' after '.else' is not permitted.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto err;
				}

				if (nested_conds[nested_cond_lvl] == NESTED_COND_IF_TAKE ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_IF_SKIP ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_ELIF_TAKE ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_ELIF_SKIP) {
					nested_conds[nested_cond_lvl] = NESTED_COND_ELIF_SKIP;
					goto next_line;
				}

				cond = cfg_eval_condition(args + 1, &errmsg, &errptr);
				if (cond < 0) {
					size_t newpos = sanitize_for_printing(args[1], errptr - args[1], 74);

					ha_alert("parsing [%s:%d]: %s in '.elif' at position %d:\n  .elif %s\n  %*s\n",
						 file, linenum, errmsg,
					         (int)(errptr-args[1]+1), args[1], (int)(newpos+7), "^");

					free(errmsg);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto err;
				}

				if (cond)
					nested_conds[nested_cond_lvl] = NESTED_COND_ELIF_TAKE;
				else
					nested_conds[nested_cond_lvl] = NESTED_COND_ELIF_DROP;

				goto next_line;
			}
			else if (strcmp(args[0], ".else") == 0) {
				if (*args[1]) {
					ha_alert("parsing [%s:%d]: Unexpected argument '%s' for '%s'.\n",
					         file, linenum, args[1], args[0]);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					break;
				}

				if (!nested_cond_lvl) {
					ha_alert("parsing [%s:%d]: lone '.else' with no matching '.if'.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto err;
				}

				if (nested_conds[nested_cond_lvl] == NESTED_COND_ELSE_TAKE ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_ELSE_DROP) {
					ha_alert("parsing [%s:%d]: '.else' after '.else' is not permitted.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto err;
				}

				if (nested_conds[nested_cond_lvl] == NESTED_COND_IF_TAKE ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_IF_SKIP ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_ELIF_TAKE ||
				    nested_conds[nested_cond_lvl] == NESTED_COND_ELIF_SKIP) {
					nested_conds[nested_cond_lvl] = NESTED_COND_ELSE_DROP;
				} else {
					/* otherwise we take the "else" */
					nested_conds[nested_cond_lvl] = NESTED_COND_ELSE_TAKE;
				}
				goto next_line;
			}
			else if (strcmp(args[0], ".endif") == 0) {
				if (*args[1]) {
					ha_alert("parsing [%s:%d]: Unexpected argument '%s' for '%s'.\n",
					         file, linenum, args[1], args[0]);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					break;
				}

				if (!nested_cond_lvl) {
					ha_alert("parsing [%s:%d]: lone '.endif' with no matching '.if'.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					break;
				}
				nested_cond_lvl--;
				goto next_line;
			}
		}

		if (nested_cond_lvl &&
		    (nested_conds[nested_cond_lvl] == NESTED_COND_IF_DROP ||
		     nested_conds[nested_cond_lvl] == NESTED_COND_IF_SKIP ||
		     nested_conds[nested_cond_lvl] == NESTED_COND_ELIF_DROP ||
		     nested_conds[nested_cond_lvl] == NESTED_COND_ELIF_SKIP ||
		     nested_conds[nested_cond_lvl] == NESTED_COND_ELSE_DROP)) {
			/* The current block is masked out by the conditions */
			goto next_line;
		}

		/* .warning/.error/.notice/.diag */
		if (*args[0] == '.') {
			if (strcmp(args[0], ".alert") == 0) {
				if (*args[2]) {
					ha_alert("parsing [%s:%d]: Unexpected argument '%s' for '%s'. Use quotes if the message should contain spaces.\n",
					           file, linenum, args[2], args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto next_line;
				}

				ha_alert("parsing [%s:%d]: '%s'.\n", file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
				goto err;
			}
			else if (strcmp(args[0], ".warning") == 0) {
				if (*args[2]) {
					ha_alert("parsing [%s:%d]: Unexpected argument '%s' for '%s'. Use quotes if the message should contain spaces.\n",
					           file, linenum, args[2], args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto next_line;
				}

				ha_warning("parsing [%s:%d]: '%s'.\n", file, linenum, args[1]);
				err_code |= ERR_WARN;
				goto next_line;
			}
			else if (strcmp(args[0], ".notice") == 0) {
				if (*args[2]) {
					ha_alert("parsing [%s:%d]: Unexpected argument '%s' for '%s'. Use quotes if the message should contain spaces.\n",
					         file, linenum, args[2], args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto next_line;
				}

				ha_notice("parsing [%s:%d]: '%s'.\n", file, linenum, args[1]);
				goto next_line;
			}
			else if (strcmp(args[0], ".diag") == 0) {
				if (*args[2]) {
					ha_alert("parsing [%s:%d]: Unexpected argument '%s' for '%s'. Use quotes if the message should contain spaces.\n",
					         file, linenum, args[2], args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto next_line;
				}

				ha_diag_warning("parsing [%s:%d]: '%s'.\n", file, linenum, args[1]);
				goto next_line;
			}
			else {
				ha_alert("parsing [%s:%d]: unknown directive '%s'.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				fatal++;
				break;
			}
		}

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
		    strcmp(args[0], "insecure-fork-wanted") != 0 &&
		    strcmp(args[0], "numa-cpu-mapping") != 0) {
			ha_alert("parsing [%s:%d]: negation/default currently "
				 "supported only for options, log, busy-polling, "
				 "set-dumpable, strict-limits, insecure-fork-wanted "
				 "and numa-cpu-mapping.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			fatal++;
		}

		/* detect section start */
		list_for_each_entry(ics, &sections, list) {
			if (strcmp(args[0], ics->section_name) == 0) {
				cursection = ics->section_name;
				pcs = cs;
				cs = ics;
				free(global.cfg_curr_section);
				global.cfg_curr_section = strdup(*args[1] ? args[1] : args[0]);

				if (global.mode & MODE_DIAG) {
					check_section_position(args[0], file, linenum,
					                       &non_global_section_parsed);
				}

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

	ha_free(&global.cfg_curr_section);
	if (cs && cs->post_section_parser)
		err_code |= cs->post_section_parser();

	if (nested_cond_lvl) {
		ha_alert("parsing [%s:%d]: non-terminated '.if' block.\n", file, linenum);
		err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
	}

	if (*initial_cwd && chdir(initial_cwd) == -1) {
		ha_alert("Impossible to get back to initial directory '%s' : %s\n", initial_cwd, strerror(errno));
		err_code |= ERR_ALERT | ERR_FATAL;
	}

err:
	ha_free(&cfg_scope);
	cursection = NULL;
	free(thisline);
	free(outline);
	global.cfg_curr_line = 0;
	global.cfg_curr_file = NULL;

	if (f)
		fclose(f);

	return err_code;
}

#if defined(USE_THREAD) && defined USE_CPU_AFFINITY
#if defined(__linux__)

/* filter directory name of the pattern node<X> */
static int numa_filter(const struct dirent *dir)
{
	char *endptr;

	/* dir name must start with "node" prefix */
	if (strncmp(dir->d_name, "node", 4))
		return 0;

	/* dir name must be at least 5 characters long */
	if (!dir->d_name[4])
		return 0;

	/* dir name must end with a numeric id */
	if (strtol(&dir->d_name[4], &endptr, 10) < 0 || *endptr)
		return 0;

	/* all tests succeeded */
	return 1;
}

/* Parse a linux cpu map string representing to a numeric cpu mask map
 * The cpu map string is a list of 4-byte hex strings separated by commas, with
 * most-significant byte first, one bit per cpu number.
 */
static void parse_cpumap(char *cpumap_str, struct hap_cpuset *cpu_set)
{
	unsigned long cpumap;
	char *start, *endptr, *comma;
	int i, j;

	ha_cpuset_zero(cpu_set);

	i = 0;
	do {
		/* reverse-search for a comma, parse the string after the comma
		 * or at the beginning if no comma found
		 */
		comma = strrchr(cpumap_str, ',');
		start = comma ? comma + 1 : cpumap_str;

		cpumap = strtoul(start, &endptr, 16);
		for (j = 0; cpumap; cpumap >>= 1, ++j) {
			if (cpumap & 0x1)
				ha_cpuset_set(cpu_set, j + i * 32);
		}

		if (comma)
			*comma = '\0';
		++i;
	} while (comma);
}

/* Read the first line of a file from <path> into the trash buffer.
 * Returns 0 on success, otherwise non-zero.
 */
static int read_file_to_trash(const char *path)
{
	FILE *file;
	int ret = 1;

	file = fopen(path, "r");
	if (file) {
		if (fgets(trash.area, trash.size, file))
			ret = 0;

		fclose(file);
	}

	return ret;
}

/* Inspect the cpu topology of the machine on startup. If a multi-socket
 * machine is detected, try to bind on the first node with active cpu. This is
 * done to prevent an impact on the overall performance when the topology of
 * the machine is unknown. This function is not called if one of the conditions
 * is met :
 * - a non-null nbthread directive is active
 * - a restrictive cpu-map directive is active
 * - a restrictive affinity is already applied, for example via taskset
 *
 * Returns the count of cpus selected. If no automatic binding was required or
 * an error occurred and the topology is unknown, 0 is returned.
 */
static int numa_detect_topology()
{
	struct dirent **node_dirlist;
	int node_dirlist_size;

	struct hap_cpuset active_cpus, node_cpu_set;
	const char *parse_cpu_set_args[2];
	char cpumap_path[PATH_MAX];
	char *err = NULL;

	/* node_cpu_set count is used as return value */
	ha_cpuset_zero(&node_cpu_set);

	/* 1. count the sysfs node<X> directories */
	node_dirlist = NULL;
	node_dirlist_size = scandir(NUMA_DETECT_SYSTEM_SYSFS_PATH"/node", &node_dirlist, numa_filter, alphasort);
	if (node_dirlist_size <= 1)
		goto free_scandir_entries;

	/* 2. read and parse the list of currently online cpu */
	if (read_file_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH"/cpu/online")) {
		ha_notice("Cannot read online CPUs list, will not try to refine binding\n");
		goto free_scandir_entries;
	}

	parse_cpu_set_args[0] = trash.area;
	parse_cpu_set_args[1] = "\0";
	if (parse_cpu_set(parse_cpu_set_args, &active_cpus, 1, &err)) {
		ha_notice("Cannot read online CPUs list: '%s'. Will not try to refine binding\n", err);
		free(err);
		goto free_scandir_entries;
	}

	/* 3. loop through nodes dirs and find the first one with active cpus */
	while (node_dirlist_size--) {
		const char *node = node_dirlist[node_dirlist_size]->d_name;
		ha_cpuset_zero(&node_cpu_set);

		snprintf(cpumap_path, PATH_MAX, "%s/node/%s/cpumap",
		         NUMA_DETECT_SYSTEM_SYSFS_PATH, node);

		if (read_file_to_trash(cpumap_path)) {
			ha_notice("Cannot read CPUs list of '%s', will not select them to refine binding\n", node);
			free(node_dirlist[node_dirlist_size]);
			continue;
		}

		parse_cpumap(trash.area, &node_cpu_set);
		ha_cpuset_and(&node_cpu_set, &active_cpus);

		/* 5. set affinity on the first found node with active cpus */
		if (!ha_cpuset_count(&node_cpu_set)) {
			free(node_dirlist[node_dirlist_size]);
			continue;
		}

		ha_diag_warning("Multi-socket cpu detected, automatically binding on active CPUs of '%s' (%u active cpu(s))\n", node, ha_cpuset_count(&node_cpu_set));
		if (sched_setaffinity(getpid(), sizeof(node_cpu_set.cpuset), &node_cpu_set.cpuset) == -1) {
			ha_warning("Cannot set the cpu affinity for this multi-cpu machine\n");

			/* clear the cpuset used as return value */
			ha_cpuset_zero(&node_cpu_set);
		}

		free(node_dirlist[node_dirlist_size]);
		break;
	}

 free_scandir_entries:
	while (node_dirlist_size-- > 0)
		free(node_dirlist[node_dirlist_size]);
	free(node_dirlist);

	return ha_cpuset_count(&node_cpu_set);
}

#elif defined(__FreeBSD__)
static int numa_detect_topology()
{
	struct hap_cpuset node_cpu_set;
	int ndomains = 0, i;
	size_t len = sizeof(ndomains);

	if (sysctlbyname("vm.ndomains", &ndomains, &len, NULL, 0) == -1) {
		ha_notice("Cannot assess the number of CPUs domains\n");
		return 0;
	}

	BUG_ON(ndomains > MAXMEMDOM);
	ha_cpuset_zero(&node_cpu_set);

	/*
	 * We retrieve the first active valid CPU domain
	 * with active cpu and binding it, we returns
	 * the number of cpu from the said domain
	 */
	for (i = 0; i < ndomains; i ++) {
		struct hap_cpuset dom;
		ha_cpuset_zero(&dom);
		if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_DOMAIN, i, sizeof(dom.cpuset), &dom.cpuset) == -1)
			continue;

		if (!ha_cpuset_count(&dom))
			continue;

		ha_cpuset_assign(&node_cpu_set, &dom);

		ha_diag_warning("Multi-socket cpu detected, automatically binding on active CPUs of '%d' (%u active cpu(s))\n", i, ha_cpuset_count(&node_cpu_set));
		if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(node_cpu_set.cpuset), &node_cpu_set.cpuset) == -1) {
			ha_warning("Cannot set the cpu affinity for this multi-cpu machine\n");

			/* clear the cpuset used as return value */
			ha_cpuset_zero(&node_cpu_set);
		}
		break;
	}

	return ha_cpuset_count(&node_cpu_set);
}

#else
static int numa_detect_topology()
{
	return 0;
}

#endif
#endif /* USE_THREAD && USE_CPU_AFFINITY */

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
	struct resolvers *curr_resolvers = NULL;
	int i;

	bind_conf = NULL;
	/*
	 * Now, check for the integrity of all that we have collected.
	 */

	/* will be needed further to delay some tasks */
	clock_update_date(0,1);

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
		{
			int numa_cores = 0;
#if defined(USE_CPU_AFFINITY)
			if (global.numa_cpu_mapping && !thread_cpu_mask_forced())
				numa_cores = numa_detect_topology();
#endif
			global.nbthread = numa_cores ? numa_cores :
			                               thread_cpus_enabled_at_boot;
		}
		all_threads_mask = nbits(global.nbthread);
#endif
	}

	if (!global.nbtgroups)
		global.nbtgroups = 1;

	if (thread_map_to_groups() < 0) {
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
		struct logsrv *tmplogsrv;
		unsigned int next_id;

		if (!(curproxy->cap & PR_CAP_INT) && curproxy->uuid < 0) {
			/* proxy ID not set, use automatic numbering with first
			 * spare entry starting with next_pxid. We don't assign
			 * numbers for internal proxies as they may depend on
			 * build or config options and we don't want them to
			 * possibly reuse existing IDs.
			 */
			next_pxid = get_next_id(&used_proxy_id, next_pxid);
			curproxy->conf.id.key = curproxy->uuid = next_pxid;
			eb32_insert(&used_proxy_id, &curproxy->conf.id);
		}

		if (curproxy->mode == PR_MODE_HTTP && global.tune.bufsize >= (256 << 20) && ONLY_ONCE()) {
			ha_alert("global.tune.bufsize must be below 256 MB when HTTP is in use (current value = %d).\n",
				 global.tune.bufsize);
			cfgerr++;
		}

		/* next IDs are shifted even if the proxy is disabled, this
		 * guarantees that a proxy that is temporarily disabled in the
		 * configuration doesn't cause a renumbering. Internal proxies
		 * that are not assigned a static ID must never shift the IDs
		 * either since they may appear in any order (Lua, logs, etc).
		 * The GLOBAL proxy that carries the stats socket has its ID
		 * forced to zero.
		 */
		if (curproxy->uuid >= 0)
			next_pxid++;

		if (curproxy->flags & PR_FL_DISABLED) {
			/* ensure we don't keep listeners uselessly bound. We
			 * can't disable their listeners yet (fdtab not
			 * allocated yet) but let's skip them.
			 */
			if (curproxy->table) {
				ha_free(&curproxy->table->peers.name);
				curproxy->table->peers.p = NULL;
			}
			continue;
		}

		/* The current proxy is referencing a default proxy. We must
		 * finalize its config, but only once. If the default proxy is
		 * ready (PR_FL_READY) it means it was already fully configured.
		 */
		if (curproxy->defpx) {
			if (!(curproxy->defpx->flags & PR_FL_READY)) {
				/* check validity for 'tcp-request' layer 4/5/6/7 rules */
				cfgerr += check_action_rules(&curproxy->defpx->tcp_req.l4_rules, curproxy->defpx, &err_code);
				cfgerr += check_action_rules(&curproxy->defpx->tcp_req.l5_rules, curproxy->defpx, &err_code);
				cfgerr += check_action_rules(&curproxy->defpx->tcp_req.inspect_rules, curproxy->defpx, &err_code);
				cfgerr += check_action_rules(&curproxy->defpx->tcp_rep.inspect_rules, curproxy->defpx, &err_code);
				cfgerr += check_action_rules(&curproxy->defpx->http_req_rules, curproxy->defpx, &err_code);
				cfgerr += check_action_rules(&curproxy->defpx->http_res_rules, curproxy->defpx, &err_code);
				cfgerr += check_action_rules(&curproxy->defpx->http_after_res_rules, curproxy->defpx, &err_code);

				err = NULL;
				i = smp_resolve_args(curproxy->defpx, &err);
				cfgerr += i;
				if (i) {
					indent_msg(&err, 8);
					ha_alert("%s%s\n", i > 1 ? "multiple argument resolution errors:" : "", err);
					ha_free(&err);
				}
				else
					cfgerr += acl_find_targets(curproxy->defpx);

				/* default proxy is now ready. Set the right FE/BE capabilities */
				curproxy->defpx->flags |= PR_FL_READY;
			}
		}

		/* check and reduce the bind-proc of each listener */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			unsigned long mask;
			struct listener *li;

			/* HTTP frontends with "h2" as ALPN/NPN will work in
			 * HTTP/2 and absolutely require buffers 16kB or larger.
			 */
#ifdef USE_OPENSSL
			if (curproxy->mode == PR_MODE_HTTP && global.tune.bufsize < 16384) {
#ifdef OPENSSL_NPN_NEGOTIATED
				/* check NPN */
				if (bind_conf->ssl_conf.npn_str && strstr(bind_conf->ssl_conf.npn_str, "\002h2")) {
					ha_alert("HTTP frontend '%s' enables HTTP/2 via NPN at [%s:%d], so global.tune.bufsize must be at least 16384 bytes (%d now).\n",
						 curproxy->id, bind_conf->file, bind_conf->line, global.tune.bufsize);
					cfgerr++;
				}
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
				/* check ALPN */
				if (bind_conf->ssl_conf.alpn_str && strstr(bind_conf->ssl_conf.alpn_str, "\002h2")) {
					ha_alert("HTTP frontend '%s' enables HTTP/2 via ALPN at [%s:%d], so global.tune.bufsize must be at least 16384 bytes (%d now).\n",
						 curproxy->id, bind_conf->file, bind_conf->line, global.tune.bufsize);
					cfgerr++;
				}
#endif
			} /* HTTP && bufsize < 16384 */
#endif

			/* detect and address thread affinity inconsistencies */
			err = NULL;
			if (thread_resolve_group_mask(bind_conf->bind_tgroup, bind_conf->bind_thread,
			                              &bind_conf->bind_tgroup, &bind_conf->bind_thread, &err) < 0) {
				ha_alert("Proxy '%s': %s in 'bind %s' at [%s:%d].\n",
					   curproxy->id, err, bind_conf->arg, bind_conf->file, bind_conf->line);
				free(err);
				cfgerr++;
			} else if (!((mask = bind_conf->bind_thread) & all_threads_mask)) {
				unsigned long new_mask = 0;

				while (mask) {
					new_mask |= mask & all_threads_mask;
					mask >>= global.nbthread;
				}

				bind_conf->bind_thread = new_mask;
				ha_warning("Proxy '%s': the thread range specified on the 'thread' directive of 'bind %s' at [%s:%d] only refers to thread numbers out of the range defined by the global 'nbthread' directive. The thread numbers were remapped to existing threads instead (mask 0x%lx).\n",
					   curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line, new_mask);
			}

			/* apply thread masks and groups to all receivers */
			list_for_each_entry(li, &bind_conf->listeners, by_bind) {
				if (bind_conf->settings.shards <= 1) {
					li->rx.bind_thread = bind_conf->bind_thread;
					li->rx.bind_tgroup = bind_conf->bind_tgroup;
				} else {
					struct listener *new_li;
					int shard, shards, todo, done, bit;
					ulong mask;

					shards = bind_conf->settings.shards;
					todo = my_popcountl(bind_conf->bind_thread);

					/* no more shards than total threads */
					if (shards > todo)
						shards = todo;

					shard = done = bit = 0;
					new_li = li;

					while (1) {
						mask = 0;
						while (done < todo) {
							/* enlarge mask to cover next bit of bind_thread */
							while (!(bind_conf->bind_thread & (1UL << bit)))
								bit++;
							mask |= (1UL << bit);
							bit++;
							done += shards;
						}

						new_li->rx.bind_thread = bind_conf->bind_thread & mask;
						new_li->rx.bind_tgroup = bind_conf->bind_tgroup;
						done -= todo;

						shard++;
						if (shard >= shards)
							break;

						/* create another listener for new shards */
						new_li = clone_listener(li);
						if (!new_li) {
							ha_alert("Out of memory while trying to allocate extra listener for shard %d in %s %s\n",
								 shard, proxy_type_str(curproxy), curproxy->id);
							cfgerr++;
							err_code |= ERR_FATAL | ERR_ALERT;
							goto out;
						}
					}
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
			ha_alert("%s '%s' cannot use peers or syslog mode for this proxy. NOTE: PLEASE REPORT THIS TO DEVELOPERS AS YOU'RE NOT SUPPOSED TO BE ABLE TO CREATE A CONFIGURATION TRIGGERING THIS!\n",
				 proxy_type_str(curproxy), curproxy->id);
			cfgerr++;
			break;
		}

		if (!(curproxy->cap & PR_CAP_INT) && (curproxy->cap & PR_CAP_FE) && LIST_ISEMPTY(&curproxy->conf.listeners)) {
			ha_warning("%s '%s' has no 'bind' directive. Please declare it as a backend if this was intended.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if (curproxy->cap & PR_CAP_BE) {
			if (curproxy->lbprm.algo & BE_LB_KIND) {
				if (curproxy->options & PR_O_TRANSP) {
					ha_alert("%s '%s' cannot use both transparent and balance mode.\n",
						 proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				}
#ifdef WE_DONT_SUPPORT_SERVERLESS_LISTENERS
				else if (curproxy->srv == NULL) {
					ha_alert("%s '%s' needs at least 1 server in balance mode.\n",
						 proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				}
#endif
				else if (curproxy->options & PR_O_DISPATCH) {
					ha_warning("dispatch address of %s '%s' will be ignored in balance mode.\n",
						   proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
				}
			}
			else if (!(curproxy->options & (PR_O_TRANSP | PR_O_DISPATCH))) {
				/* If no LB algo is set in a backend, and we're not in
				 * transparent mode, dispatch mode nor proxy mode, we
				 * want to use balance roundrobin by default.
				 */
				curproxy->lbprm.algo &= ~BE_LB_ALGO;
				curproxy->lbprm.algo |= BE_LB_ALGO_RR;
			}
		}

		if (curproxy->options & PR_O_DISPATCH)
			curproxy->options &= ~PR_O_TRANSP;
		else if (curproxy->options & PR_O_TRANSP)
			curproxy->options &= ~PR_O_DISPATCH;

		if ((curproxy->tcpcheck_rules.flags & TCPCHK_RULES_UNUSED_HTTP_RS)) {
			ha_warning("%s '%s' uses http-check rules without 'option httpchk', so the rules are ignored.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if ((curproxy->options2 & PR_O2_CHK_ANY) == PR_O2_TCPCHK_CHK &&
		    (curproxy->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) != TCPCHK_RULES_HTTP_CHK) {
			if (curproxy->options & PR_O_DISABLE404) {
				ha_warning("'%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
					   "disable-on-404", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O_DISABLE404;
			}
			if (curproxy->options2 & PR_O2_CHK_SNDST) {
				ha_warning("'%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
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
			    ha_warning("'email-alert' will be ignored for %s '%s' (the presence any of "
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
				ha_warning("'%s' will be ignored for %s '%s' (requires 'option external-check').\n",
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
				ha_free(&curproxy->check_command);
			}
		}

		if (curproxy->check_path) {
			if ((curproxy->options2 & PR_O2_CHK_ANY) != PR_O2_EXT_CHK) {
				ha_warning("'%s' will be ignored for %s '%s' (requires 'option external-check').\n",
					   "external-check path", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				ha_free(&curproxy->check_path);
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
				LIST_DELETE(&node->list);
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
				ha_free(&rule->be.name);
				rule->be.backend = target;
			}
			err_code |= warnif_tcp_http_cond(curproxy, rule->cond);
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
				LIST_DELETE(&node->list);
				free(node->arg);
				free(node);
			}

			srule->dynamic = 0;
			srule->srv.name = server_name;
			target = findserver(curproxy, srule->srv.name);
			err_code |= warnif_tcp_http_cond(curproxy, srule->cond);

			if (!target) {
				ha_alert("%s '%s' : unable to find server '%s' referenced in a 'use-server' rule.\n",
					 proxy_type_str(curproxy), curproxy->id, srule->srv.name);
				cfgerr++;
				continue;
			}
			ha_free(&srule->srv.name);
			srule->srv.ptr = target;
			target->flags |= SRV_F_NON_PURGEABLE;
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
			else {
				ha_free(&mrule->table.name);
				mrule->table.t = target;
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_ID, NULL, NULL);
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_KEY, NULL, NULL);
				if (!in_proxies_list(target->proxies_list, curproxy)) {
					curproxy->next_stkt_ref = target->proxies_list;
					target->proxies_list = curproxy;
				}
			}
			err_code |= warnif_tcp_http_cond(curproxy, mrule->cond);
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
			else {
				ha_free(&mrule->table.name);
				mrule->table.t = target;
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_ID, NULL, NULL);
				stktable_alloc_data_type(target, STKTABLE_DT_SERVER_KEY, NULL, NULL);
				if (!in_proxies_list(target->proxies_list, curproxy)) {
					curproxy->next_stkt_ref = target->proxies_list;
					target->proxies_list = curproxy;
				}
			}
		}

		/* check validity for 'tcp-request' layer 4/5/6/7 rules */
		cfgerr += check_action_rules(&curproxy->tcp_req.l4_rules, curproxy, &err_code);
		cfgerr += check_action_rules(&curproxy->tcp_req.l5_rules, curproxy, &err_code);
		cfgerr += check_action_rules(&curproxy->tcp_req.inspect_rules, curproxy, &err_code);
		cfgerr += check_action_rules(&curproxy->tcp_rep.inspect_rules, curproxy, &err_code);
		cfgerr += check_action_rules(&curproxy->http_req_rules, curproxy, &err_code);
		cfgerr += check_action_rules(&curproxy->http_res_rules, curproxy, &err_code);
		cfgerr += check_action_rules(&curproxy->http_after_res_rules, curproxy, &err_code);

		/* Warn is a switch-mode http is used on a TCP listener with servers but no backend */
		if (!curproxy->defbe.name && LIST_ISEMPTY(&curproxy->switching_rules) && curproxy->srv) {
			if ((curproxy->options & PR_O_HTTP_UPG) && curproxy->mode == PR_MODE_TCP)
				ha_warning("Proxy '%s' : 'switch-mode http' configured for a %s %s with no backend. "
					   "Incoming connections upgraded to HTTP cannot be routed to TCP servers\n",
					   curproxy->id, proxy_mode_str(curproxy->mode), proxy_type_str(curproxy));
		}

		if (curproxy->table && curproxy->table->peers.name) {
			struct peers *curpeers;

			for (curpeers = cfg_peers; curpeers; curpeers = curpeers->next) {
				if (strcmp(curpeers->id, curproxy->table->peers.name) == 0) {
					ha_free(&curproxy->table->peers.name);
					curproxy->table->peers.p = curpeers;
					break;
				}
			}

			if (!curpeers) {
				ha_alert("Proxy '%s': unable to find sync peers '%s'.\n",
					 curproxy->id, curproxy->table->peers.name);
				ha_free(&curproxy->table->peers.name);
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

		if (curproxy->uri_auth && !(curproxy->uri_auth->flags & STAT_CONVDONE) &&
		    !LIST_ISEMPTY(&curproxy->uri_auth->http_req_rules) &&
		    (curproxy->uri_auth->userlist || curproxy->uri_auth->auth_realm )) {
			ha_alert("%s '%s': stats 'auth'/'realm' and 'http-request' can't be used at the same time.\n",
				 "proxy", curproxy->id);
			cfgerr++;
			goto out_uri_auth_compat;
		}

		if (curproxy->uri_auth && curproxy->uri_auth->userlist &&
		    (!(curproxy->uri_auth->flags & STAT_CONVDONE) ||
		     LIST_ISEMPTY(&curproxy->uri_auth->http_req_rules))) {
			const char *uri_auth_compat_req[10];
			struct act_rule *rule;
			i = 0;

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

			LIST_APPEND(&curproxy->uri_auth->http_req_rules, &rule->list);

			if (curproxy->uri_auth->auth_realm) {
				ha_free(&curproxy->uri_auth->auth_realm);
			}
			curproxy->uri_auth->flags |= STAT_CONVDONE;
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
			ha_free(&curproxy->conf.lfs_file);
			curproxy->conf.lfs_line = 0;

			if (curproxy->conf.logformat_sd_string != default_rfc5424_sd_log_format)
				free(curproxy->conf.logformat_sd_string);
			curproxy->conf.logformat_sd_string = NULL;
			ha_free(&curproxy->conf.lfsd_file);
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
			int where = 0;

			curproxy->conf.args.ctx = ARGC_UIF;
			curproxy->conf.args.file = curproxy->conf.uif_file;
			curproxy->conf.args.line = curproxy->conf.uif_line;
			err = NULL;
			if (curproxy->cap & PR_CAP_FE)
				where |= SMP_VAL_FE_HRQ_HDR;
			if (curproxy->cap & PR_CAP_BE)
				where |= SMP_VAL_BE_HRQ_HDR;
			if (!parse_logformat_string(curproxy->conf.uniqueid_format_string, curproxy, &curproxy->format_unique_id,
			                            LOG_OPT_HTTP|LOG_OPT_MERGE_SPACES, where, &err)) {
				ha_alert("Parsing [%s:%d]: failed to parse unique-id : %s.\n",
					 curproxy->conf.uif_file, curproxy->conf.uif_line, err);
				free(err);
				cfgerr++;
			}
			curproxy->conf.args.file = NULL;
			curproxy->conf.args.line = 0;
		}

		if (curproxy->conf.error_logformat_string) {
			curproxy->conf.args.ctx = ARGC_LOG;
			curproxy->conf.args.file = curproxy->conf.elfs_file;
			curproxy->conf.args.line = curproxy->conf.elfs_line;
			err = NULL;
			if (!parse_logformat_string(curproxy->conf.error_logformat_string, curproxy, &curproxy->logformat_error,
			                            LOG_OPT_MANDATORY|LOG_OPT_MERGE_SPACES,
			                            SMP_VAL_FE_LOG_END, &err)) {
				ha_alert("Parsing [%s:%d]: failed to parse error-log-format : %s.\n",
					 curproxy->conf.elfs_file, curproxy->conf.elfs_line, err);
				free(err);
				cfgerr++;
			}
			curproxy->conf.args.file = NULL;
			curproxy->conf.args.line = 0;
		}

		/* only now we can check if some args remain unresolved.
		 * This must be done after the users and groups resolution.
		 */
		err = NULL;
		i = smp_resolve_args(curproxy, &err);
		cfgerr += i;
		if (i) {
			indent_msg(&err, 8);
			ha_alert("%s%s\n", i > 1 ? "multiple argument resolution errors:" : "", err);
			ha_free(&err);
		} else
			cfgerr += acl_find_targets(curproxy);

		if (!(curproxy->cap & PR_CAP_INT) && (curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HTTP) &&
		    (((curproxy->cap & PR_CAP_FE) && !curproxy->timeout.client) ||
		     ((curproxy->cap & PR_CAP_BE) && (curproxy->srv) &&
		      (!curproxy->timeout.connect ||
		       (!curproxy->timeout.server && (curproxy->mode == PR_MODE_HTTP || !curproxy->timeout.tunnel)))))) {
			ha_warning("missing timeouts for %s '%s'.\n"
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
		if (!curproxy->timeout.tarpit)
			curproxy->timeout.tarpit = curproxy->timeout.connect;
		if ((curproxy->cap & PR_CAP_BE) && !curproxy->timeout.queue)
			curproxy->timeout.queue = curproxy->timeout.connect;

		if ((curproxy->tcpcheck_rules.flags & TCPCHK_RULES_UNUSED_TCP_RS)) {
			ha_warning("%s '%s' uses tcp-check rules without 'option tcp-check', so the rules are ignored.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		/* ensure that cookie capture length is not too large */
		if (curproxy->capture_len >= global.tune.cookie_len) {
			ha_warning("truncating capture length to %d bytes for %s '%s'.\n",
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
					ha_warning("backend '%s' configured to load server state file from global section 'server-state-file' directive. Unfortunately, 'server-state-file' is not set!\n",
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
			}
			newsrv->conf.name.key = newsrv->id;
			ebis_insert(&curproxy->conf.used_server_name, &newsrv->conf.name);

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
			set_usermsgs_ctx(newsrv->conf.file, newsrv->conf.line, &newsrv->obj_type);

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
			    ((newsrv->flags & SRV_F_DEFSRV_USE_SSL) && newsrv->use_ssl != 1)) {
				if (xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->prepare_srv)
					cfgerr += xprt_get(XPRT_SSL)->prepare_srv(newsrv);
			}

			if ((newsrv->flags & SRV_F_FASTOPEN) &&
			    ((curproxy->retry_type & (PR_RE_DISCONNECTED | PR_RE_TIMEOUT)) !=
			     (PR_RE_DISCONNECTED | PR_RE_TIMEOUT)))
				ha_warning("server has tfo activated, the backend should be configured with at least 'conn-failure', 'empty-response' and 'response-timeout' or we wouldn't be able to retry the connection on failure.\n");

			if (newsrv->trackit) {
				if (srv_apply_track(newsrv, curproxy)) {
					++cfgerr;
					goto next_srv;
				}
			}

		next_srv:
			reset_usermsgs_ctx();
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
				if (chash_init_server_tree(curproxy) < 0) {
					cfgerr++;
				}
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
				if (chash_init_server_tree(curproxy) < 0) {
					cfgerr++;
				}
			} else {
				curproxy->lbprm.algo |= BE_LB_LKUP_MAP;
				init_server_map(curproxy);
			}
			break;
		}
		HA_RWLOCK_INIT(&curproxy->lbprm.lock);

		if (curproxy->options & PR_O_LOGASAP)
			curproxy->to_log &= ~LW_BYTES;

		if (!(curproxy->cap & PR_CAP_INT) && (curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HTTP) &&
		    (curproxy->cap & PR_CAP_FE) && LIST_ISEMPTY(&curproxy->logsrvs) &&
		    (!LIST_ISEMPTY(&curproxy->logformat) || !LIST_ISEMPTY(&curproxy->logformat_sd))) {
			ha_warning("log format ignored for %s '%s' since it has no log address.\n",
				   proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if (curproxy->mode != PR_MODE_HTTP && !(curproxy->options & PR_O_HTTP_UPG)) {
			int optnum;

			if (curproxy->uri_auth) {
				ha_warning("'stats' statement ignored for %s '%s' as it requires HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->uri_auth = NULL;
			}

			if (curproxy->capture_name) {
				ha_warning("'capture' statement ignored for %s '%s' as it requires HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (!LIST_ISEMPTY(&curproxy->http_req_rules)) {
				ha_warning("'http-request' rules ignored for %s '%s' as they require HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (!LIST_ISEMPTY(&curproxy->http_res_rules)) {
				ha_warning("'http-response' rules ignored for %s '%s' as they require HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (!LIST_ISEMPTY(&curproxy->http_after_res_rules)) {
				ha_warning("'http-after-response' rules ignored for %s '%s' as they require HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (!LIST_ISEMPTY(&curproxy->redirect_rules)) {
				ha_warning("'redirect' rules ignored for %s '%s' as they require HTTP mode.\n",
					   proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (curproxy->options & (PR_O_FWDFOR | PR_O_FF_ALWAYS)) {
				ha_warning("'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					   "forwardfor", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~(PR_O_FWDFOR | PR_O_FF_ALWAYS);
			}

			if (curproxy->options & PR_O_ORGTO) {
				ha_warning("'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					   "originalto", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O_ORGTO;
			}

			for (optnum = 0; cfg_opts[optnum].name; optnum++) {
				if (cfg_opts[optnum].mode == PR_MODE_HTTP &&
				    (curproxy->cap & cfg_opts[optnum].cap) &&
				    (curproxy->options & cfg_opts[optnum].val)) {
					ha_warning("'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
						   cfg_opts[optnum].name, proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
					curproxy->options &= ~cfg_opts[optnum].val;
				}
			}

			for (optnum = 0; cfg_opts2[optnum].name; optnum++) {
				if (cfg_opts2[optnum].mode == PR_MODE_HTTP &&
				    (curproxy->cap & cfg_opts2[optnum].cap) &&
				    (curproxy->options2 & cfg_opts2[optnum].val)) {
					ha_warning("'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
						   cfg_opts2[optnum].name, proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
					curproxy->options2 &= ~cfg_opts2[optnum].val;
				}
			}

#if defined(CONFIG_HAP_TRANSPARENT)
			if (curproxy->conn_src.bind_hdr_occ) {
				curproxy->conn_src.bind_hdr_occ = 0;
				ha_warning("%s '%s' : ignoring use of header %s as source IP in non-HTTP mode.\n",
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
				ha_alert("%s '%s' : server cannot have cookie or redirect prefix in non-HTTP mode.\n",
					 proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}

			if ((curproxy->mode != PR_MODE_HTTP) && newsrv->cklen) {
				ha_warning("%s '%s' : ignoring cookie for server '%s' as HTTP mode is disabled.\n",
					   proxy_type_str(curproxy), curproxy->id, newsrv->id);
				err_code |= ERR_WARN;
			}

			if ((newsrv->flags & SRV_F_MAPPORTS) && (curproxy->options2 & PR_O2_RDPC_PRST)) {
				ha_warning("%s '%s' : RDP cookie persistence will not work for server '%s' because it lacks an explicit port number.\n",
					   proxy_type_str(curproxy), curproxy->id, newsrv->id);
				err_code |= ERR_WARN;
			}

#if defined(CONFIG_HAP_TRANSPARENT)
			if (curproxy->mode != PR_MODE_HTTP && newsrv->conn_src.bind_hdr_occ) {
				newsrv->conn_src.bind_hdr_occ = 0;
				ha_warning("%s '%s' : server %s cannot use header %s as source IP in non-HTTP mode.\n",
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

			if (!LIST_ISEMPTY(&curproxy->tcp_req.inspect_rules) ||
			    (curproxy->defpx && !LIST_ISEMPTY(&curproxy->defpx->tcp_req.inspect_rules)))
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
			}
		}

		if (curproxy->cap & PR_CAP_BE) {
			if (!LIST_ISEMPTY(&curproxy->tcp_req.inspect_rules) ||
			    (curproxy->defpx && !LIST_ISEMPTY(&curproxy->defpx->tcp_req.inspect_rules)))
				curproxy->be_req_ana |= AN_REQ_INSPECT_BE;

			if (!LIST_ISEMPTY(&curproxy->tcp_rep.inspect_rules) ||
			    (curproxy->defpx && !LIST_ISEMPTY(&curproxy->defpx->tcp_rep.inspect_rules)))
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
				ha_alert("%s '%s' : MUX protocol '%.*s' is not usable for 'bind %s' at [%s:%d].\n",
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
				ha_alert("%s '%s' : MUX protocol '%.*s' is not usable for server '%s' at [%s:%d].\n",
					 proxy_type_str(curproxy), curproxy->id,
					 (int)newsrv->mux_proto->token.len,
					 newsrv->mux_proto->token.ptr,
					 newsrv->id, newsrv->conf.file, newsrv->conf.line);
				cfgerr++;
			}

			/* update the mux */
			newsrv->mux_proto = mux_ent;
		}

		/* Allocate default tcp-check rules for proxies without
		 * explicit rules.
		 */
		if (curproxy->cap & PR_CAP_BE) {
			if (!(curproxy->options2 & PR_O2_CHK_ANY)) {
				struct tcpcheck_ruleset *rs = NULL;
				struct tcpcheck_rules *rules = &curproxy->tcpcheck_rules;

				curproxy->options2 |= PR_O2_TCPCHK_CHK;

				rs = find_tcpcheck_ruleset("*tcp-check");
				if (!rs) {
					rs = create_tcpcheck_ruleset("*tcp-check");
					if (rs == NULL) {
						ha_alert("config: %s '%s': out of memory.\n",
							 proxy_type_str(curproxy), curproxy->id);
						cfgerr++;
					}
				}

				free_tcpcheck_vars(&rules->preset_vars);
				rules->list = &rs->rules;
				rules->flags = 0;
			}
		}
	}

	/***********************************************************/
	/* At this point, target names have already been resolved. */
	/***********************************************************/

	/* we must finish to initialize certain things on the servers */

	list_for_each_entry(newsrv, &servers_list, global_list) {
		/* initialize idle conns lists */
		if (srv_init_per_thr(newsrv) == -1) {
			ha_alert("parsing [%s:%d] : failed to allocate per-thread lists for server '%s'.\n",
			         newsrv->conf.file, newsrv->conf.line, newsrv->id);
			cfgerr++;
			continue;
		}

		if (newsrv->max_idle_conns != 0) {
			newsrv->curr_idle_thr = calloc(global.nbthread, sizeof(*newsrv->curr_idle_thr));
			if (!newsrv->curr_idle_thr) {
				ha_alert("parsing [%s:%d] : failed to allocate idle connection tasks for server '%s'.\n",
				         newsrv->conf.file, newsrv->conf.line, newsrv->id);
				cfgerr++;
				continue;
			}

		}
	}

	idle_conn_task = task_new_anywhere();
	if (!idle_conn_task) {
		ha_alert("parsing : failed to allocate global idle connection task.\n");
		cfgerr++;
	}
	else {
		idle_conn_task->process = srv_cleanup_idle_conns;
		idle_conn_task->context = NULL;

		for (i = 0; i < global.nbthread; i++) {
			idle_conns[i].cleanup_task = task_new_on(i);
			if (!idle_conns[i].cleanup_task) {
				ha_alert("parsing : failed to allocate idle connection tasks for thread '%d'.\n", i);
				cfgerr++;
				break;
			}

			idle_conns[i].cleanup_task->process = srv_cleanup_toremove_conns;
			idle_conns[i].cleanup_task->context = NULL;
			HA_SPIN_INIT(&idle_conns[i].idle_conns_lock);
			MT_LIST_INIT(&idle_conns[i].toremove_conns);
		}
	}

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
				listener->maxaccept = global.tune.maxaccept ? global.tune.maxaccept : MAX_ACCEPT;

			/* listener accept callback */
			listener->accept = session_accept_fd;
#ifdef USE_QUIC
			/* override the accept callback for QUIC listeners. */
			if (listener->flags & LI_F_QUIC_LISTENER) {
				listener->accept = quic_session_accept;
				li_init_per_thr(listener);
			}
#endif

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

		/* create the task associated with the proxy */
		curproxy->task = task_new_anywhere();
		if (curproxy->task) {
			curproxy->task->context = curproxy;
			curproxy->task->process = manage_proxy;
			curproxy->flags |= PR_FL_READY;
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

	if (cfg_peers) {
		struct peers *curpeers = cfg_peers, **last;
		struct peer *p, *pb;

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
			else {
				/* Initializes the transport layer of the server part of all the peers belonging to
				 * <curpeers> section if required.
				 * Note that ->srv is used by the local peer of a new process to connect to the local peer
				 * of an old process.
				 */
				curpeers->peers_fe->flags |= PR_FL_READY;
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
		if ((curproxy->flags & PR_FL_DISABLED) || !curproxy->table)
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

	list_for_each_entry(curr_resolvers, &sec_resolvers, list) {
		if (LIST_ISEMPTY(&curr_resolvers->nameservers)) {
			ha_warning("resolvers '%s' [%s:%d] has no nameservers configured!\n",
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
	LIST_APPEND(&cfg_keywords.list, &kwl->list);
}

/*
 * Unregisters the CFG keyword list <kwl> from the list of valid keywords.
 */
void cfg_unregister_keywords(struct cfg_kw_list *kwl)
{
	LIST_DELETE(&kwl->list);
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

	LIST_APPEND(&sections, &cs->list);

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

	LIST_APPEND(&postparsers, &cp->list);

	return 1;
}

/*
 * free all config section entries
 */
void cfg_unregister_sections(void)
{
	struct cfg_section *cs, *ics;

	list_for_each_entry_safe(cs, ics, &sections, list) {
		LIST_DELETE(&cs->list);
		free(cs);
	}
}

void cfg_backup_sections(struct list *backup_sections)
{
	struct cfg_section *cs, *ics;

	list_for_each_entry_safe(cs, ics, &sections, list) {
		LIST_DELETE(&cs->list);
		LIST_APPEND(backup_sections, &cs->list);
	}
}

void cfg_restore_sections(struct list *backup_sections)
{
	struct cfg_section *cs, *ics;

	list_for_each_entry_safe(cs, ics, backup_sections, list) {
		LIST_DELETE(&cs->list);
		LIST_APPEND(&sections, &cs->list);
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

static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "default-path",     cfg_parse_global_def_path },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
