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

/* This is to have crypt() and sched_setaffinity() defined on Linux */
#define _GNU_SOURCE

#ifdef USE_LIBCRYPT
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
#ifdef USE_CPU_AFFINITY
#include <sched.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <import/cebis_tree.h>

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
#include <haproxy/counters.h>
#ifdef USE_CPU_AFFINITY
#include <haproxy/cpuset.h>
#include <haproxy/cpu_topo.h>
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
#include <haproxy/lb_ss.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/sink.h>
#include <haproxy/mailers.h>
#include <haproxy/namespace.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_tune.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/openssl-compat.h>
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
#include <haproxy/uri_auth.h>


/* Used to chain configuration sections definitions. This list
 * stores struct cfg_section
 */
struct list sections = LIST_HEAD_INIT(sections);

struct list postparsers = LIST_HEAD_INIT(postparsers);

extern struct proxy *mworker_proxy;

/* curproxy is only valid during parsing and will be NULL afterwards. */
struct proxy *curproxy = NULL;
/* last defaults section parsed, NULL after parsing */
struct proxy *last_defproxy = NULL;

char *cursection = NULL;
int cfg_maxpconn = 0;                   /* # of simultaneous connections per proxy (-N) */
int cfg_maxconn = 0;			/* # of simultaneous connections, (-n) */
char *cfg_scope = NULL;                 /* the current scope during the configuration parsing */
int non_global_section_parsed = 0;

/* how to handle default paths */
static enum default_path_mode {
	DEFAULT_PATH_CURRENT = 0,  /* "current": paths are relative to CWD (this is the default) */
	DEFAULT_PATH_CONFIG,       /* "config": paths are relative to config file */
	DEFAULT_PATH_PARENT,       /* "parent": paths are relative to config file's ".." */
	DEFAULT_PATH_ORIGIN,       /* "origin": paths are relative to default_path_origin */
} default_path_mode;

char initial_cwd[PATH_MAX];
static char current_cwd[PATH_MAX];

/* List head of all known configuration keywords */
struct cfg_kw_list cfg_keywords = {
	.list = LIST_HEAD_INIT(cfg_keywords.list)
};

/*
 * Shifts <args> one position to the left.
 * This function tricky preserves internal allocated structure of the
 * <args>. We defer the deallocation of the "shifted off" element, by
 * making it an empty string and moving it into the gap that appears after
 * the shift.
 */
static void
lshift_args(char **args)
{
	int i;
	char *shifted;

	shifted = args[0];
	for (i = 0; *args[i + 1]; i++)
		args[i] = args[i + 1];
	*shifted = '\0';
	args[i] = shifted;
}

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

		ss2 = str2sa_range(str, NULL, &port, &end, &fd, &proto, NULL, err,
		                   (curproxy == global.cli_fe || curproxy == mworker_proxy) ? NULL : global.unix_bind.prefix,
		                   NULL, NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_PORT_RANGE |
		                          PA_O_SOCKET_FD | PA_O_STREAM | PA_O_XPRT);
		if (!ss2)
			goto fail;

		if (ss2->ss_family == AF_CUST_RHTTP_SRV) {
			/* Check if a previous non reverse HTTP present is
			 * already defined. If DGRAM or STREAM is set, this
			 * indicates that we are currently parsing the second
			 * or more address.
			 */
			if (bind_conf->options & (BC_O_USE_SOCK_DGRAM|BC_O_USE_SOCK_STREAM) &&
			    !(bind_conf->options & BC_O_REVERSE_HTTP)) {
				memprintf(err, "Cannot mix reverse HTTP bind with others.\n");
				goto fail;
			}

			bind_conf->rhttp_srvname = strdup(str + strlen("rhttp@"));
			if (!bind_conf->rhttp_srvname) {
				memprintf(err, "Cannot allocate reverse HTTP bind.\n");
				goto fail;
			}

			bind_conf->options |= BC_O_REVERSE_HTTP;
		}
		else if (bind_conf->options & BC_O_REVERSE_HTTP) {
			/* Standard address mixed with a previous reverse HTTP one. */
			memprintf(err, "Cannot mix reverse HTTP bind with others.\n");
			goto fail;
		}

		/* OK the address looks correct */
		if (proto->proto_type == PROTO_TYPE_DGRAM)
			bind_conf->options |= BC_O_USE_SOCK_DGRAM;
		else
			bind_conf->options |= BC_O_USE_SOCK_STREAM;

		if (proto->xprt_type == PROTO_TYPE_DGRAM)
			bind_conf->options |= BC_O_USE_XPRT_DGRAM;
		else
			bind_conf->options |= BC_O_USE_XPRT_STREAM;

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

		ss2 = str2sa_range(str, NULL, &port, &end, &fd, &proto, NULL, err,
		                   curproxy == global.cli_fe ? NULL : global.unix_bind.prefix,
		                   NULL, NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_PORT_RANGE |
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


/* Report it if a request ACL condition uses some keywords that are
 * incompatible with the place where the ACL is used. It returns either 0 or
 * ERR_WARN so that its result can be or'ed with err_code. Note that <cond> may
 * be NULL and then will be ignored. In case of error, <err> is dynamically
 * allocated to contains a description.
 */
int warnif_cond_conflicts(const struct acl_cond *cond, unsigned int where,
                          char **err)
{
	const struct acl *acl;
	const char *kw;

	if (!cond)
		return 0;

	acl = acl_cond_conflicts(cond, where);
	if (acl) {
		if (acl->name && *acl->name) {
			memprintf(err, "acl '%s' will never match because it only involves keywords that are incompatible with '%s'",
			          acl->name, sample_ckp_names(where));
		}
		else {
			memprintf(err, "anonymous acl will never match because it uses keyword '%s' which is incompatible with '%s'",
			          LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw, sample_ckp_names(where));
		}
		return ERR_WARN;
	}
	if (!acl_cond_kw_conflicts(cond, where, &acl, &kw))
		return 0;

	if (acl->name && *acl->name) {
		memprintf(err, "acl '%s' involves keywords '%s' which is incompatible with '%s'",
		          acl->name, kw, sample_ckp_names(where));
	}
	else {
		memprintf(err, "anonymous acl involves keyword '%s' which is incompatible with '%s'",
		          kw, sample_ckp_names(where));
	}
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

		sk = str2sa_range(args[2], NULL, &port1, &port2, NULL, &proto, NULL,
		                  &errmsg, NULL, NULL, NULL,
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

	} else {
		const struct cfg_kw_list *kwl;
		char *errmsg = NULL;
		int index;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw; index++) {
				if ((kwl->kw[index].section & CFG_USERLIST) &&
					(strcmp(kwl->kw[index].kw, args[0]) == 0)) {
						err_code |= kwl->kw[index].parse(args, CFG_USERLIST, NULL, NULL, file, linenum, &errmsg);
						if (errmsg) {
							ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
							ha_free(&errmsg);
						}
						goto out;
					}
			}
		}

		ha_alert("parsing [%s:%d]: unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "userlist");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

out:
	return err_code;
}

int cfg_parse_users_group(char **args, int section_type, struct proxy *curproxy, const struct proxy *defproxy, const char *file, int linenum, char **err)
{
	int cur_arg;
	const char *err_str;
	struct auth_groups *ag;
	int err_code = 0;

	if (!*args[1]) {
		ha_alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
				file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	err_str = invalid_char(args[1]);
	if (err_str) {
		ha_alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
				file, linenum, *err_str, args[0], args[1]);
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
			if (ag->groupusers) {
				ha_alert("parsing [%s:%d]: 'users' option already defined in '%s' name '%s'.\n",
						file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(ag->groupusers);
				free(ag->name);
				free(ag);
				goto out;
			}
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

out:
	return err_code;
}

int cfg_parse_users_user(char **args, int section_type, struct proxy *curproxy, const struct proxy *defproxy, const char *file, int linenum, char **err)
{
	struct auth_users *newuser;
	int cur_arg;
	int err_code = 0;

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
			struct timeval tv_before, tv_after;
			ulong ms_elapsed;

			gettimeofday(&tv_before, NULL);
			if (!crypt("", args[cur_arg + 1])) {
				ha_alert("parsing [%s:%d]: the encrypted password used for user '%s' is not supported by crypt(3).\n",
					 file, linenum, newuser->user);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			gettimeofday(&tv_after, NULL);
			ms_elapsed = tv_ms_elapsed(&tv_before, &tv_after);
			if (ms_elapsed >= 10) {
				ha_warning("parsing [%s:%d]: the hash algorithm used for this password takes %lu milliseconds to verify, which can have devastating performance and stability impacts. Please hash this password using a lighter algorithm (one that is compatible with web usage).\n", file, linenum, ms_elapsed);
				err_code |= ERR_WARN;
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

	if (num >= global.tune.nb_stk_ctr) {
		if (!global.tune.nb_stk_ctr)
			memprintf(errmsg, "%u track-sc number not usable, stick-counters "
			          "are disabled by tune.stick-counters", num);
		else
			memprintf(errmsg, "%u track-sc number exceeding "
			          "%d (tune.stick-counters-1) value", num, global.tune.nb_stk_ctr - 1);
		return -1;
	}

	*track_sc_num = num;
	return 0;
}

/*
 * Detect a global section after a non-global one and output a diagnostic
 * warning.
 */
static void check_section_position(char *section_name, const char *file, int linenum)
{
	if (strcmp(section_name, "global") == 0) {
		if ((global.mode & MODE_DIAG) && non_global_section_parsed == 1)
		        _ha_diag_warning("parsing [%s:%d] : global section detected after a non-global one, the prevalence of their statements is unspecified\n", file, linenum);
	}
	else if (non_global_section_parsed == 0) {
		non_global_section_parsed = 1;
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

/* append a copy of string <filename>, ptr to some allocated memory at the at
 * the end of the list <li>.
 * On failure : return 0 and <err> filled with an error message.
 * The caller is responsible for freeing the <err> and <filename> copy
 * memory area using free().
 */
int list_append_cfgfile(struct list *li, const char *filename, char **err)
{
	struct cfgfile *entry = NULL;

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		memprintf(err, "out of memory");
		goto fail_entry;
	}

	entry->filename = strdup(filename);
	if (!entry->filename) {
		memprintf(err, "out of memory");
		goto fail_entry_name;
	}

	LIST_APPEND(li, &entry->list);

	return 1;

fail_entry_name:
	free(entry->filename);
fail_entry:
	free(entry);
	return 0;
}

/* loads the content of the given file in memory. On success, returns the number
 * of bytes successfully stored at *cfg_content until EOF. On error, emits
 * alerts, performs needed clean-up routines and returns -1.
 */
ssize_t load_cfg_in_mem(char *filename, char **cfg_content)
{
	size_t bytes_to_read = LINESIZE;
	size_t chunk_size = 0;
	size_t read_bytes = 0;
	struct stat file_stat;
	char *new_area;
	size_t ret = 0;
	FILE *f;

	/* let's try to obtain the size, if regular file */
	if (stat(filename, &file_stat) != 0) {
		ha_alert("stat() failed for configuration file %s : %s\n",
			 filename, strerror(errno));
		return -1;
	}

	if (file_stat.st_size > chunk_size)
		bytes_to_read = file_stat.st_size;


	if ((f = fopen(filename,"r")) == NULL) {
		ha_alert("Could not open configuration file %s : %s\n",
			 filename, strerror(errno));
		return -1;
	}

	*cfg_content = NULL;

	while (1) {
		if (!file_stat.st_size && ((read_bytes + bytes_to_read) > MAX_CFG_SIZE)) {
			ha_alert("Loading %s: input is too large %ldMB, limited to %dMB. Exiting.\n",
				 filename, (long)(read_bytes + bytes_to_read)/(1024*1024),
				 MAX_CFG_SIZE/(1024*1024));
			goto free_mem;
		}

		if (read_bytes + bytes_to_read > chunk_size) {
			chunk_size = (read_bytes + bytes_to_read) * 2;
			new_area  = realloc(*cfg_content, chunk_size);
			if (new_area == NULL) {
				ha_alert("Loading %s: file too long, cannot allocate memory.\n",
					 filename);
				goto free_mem;
			}
			*cfg_content = new_area;
		}

		bytes_to_read = chunk_size - read_bytes;
		ret = fread(*cfg_content + read_bytes, sizeof(char), bytes_to_read, f);
		read_bytes += ret;

		if (!ret || feof(f) || ferror(f))
			break;
	}

	fclose(f);

	return read_bytes;

free_mem:
	ha_free(cfg_content);
	fclose(f);

	return -1;
}

/*
 * This function parses the configuration file given in the argument.
 * Returns the error code, 0 if OK, -1 if we are run out of memory,
 * or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int parse_cfg(const struct cfgfile *cfg)
{
	char *thisline = NULL;
	int linesize = LINESIZE;
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
	char *errmsg = NULL;
	const char *cur_position = cfg->content;
	char *file = cfg->filename;

	global.cfg_curr_line = 0;
	global.cfg_curr_file = file;

	if ((thisline = malloc(sizeof(*thisline) * linesize)) == NULL) {
		ha_alert("Out of memory trying to allocate a buffer for a configuration line.\n");
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
	while (fgets_from_mem(thisline + readbytes, linesize - readbytes,
			      &cur_position, cfg->content + cfg->size)) {
		int arg, kwm = KWM_STD;
		char *end;
		char *args[MAX_LINE_ARGS + 1];
		char *line = thisline;
		const char *errptr = NULL; /* first error from parse_line() */

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

			arg = sizeof(args) / sizeof(*args);
			outlen = outlinesize;
			errptr = NULL;
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
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					fatal++;
					outlinesize = 0;
					goto err;
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

		/* dump cfg */
		if (global.mode & MODE_DUMP_CFG) {
			if (args[0] != NULL) {
				struct cfg_section *sect;
				int is_sect = 0;
				int i = 0;
				uint32_t g_key = HA_ATOMIC_LOAD(&global.anon_key);

				if (global.mode & MODE_DUMP_NB_L)
					qfprintf(stdout, "%d\t", linenum);

				/* if a word is in sections list, is_sect = 1 */
				list_for_each_entry(sect, &sections, list) {
					/* look for a section_name, but also a section_parser, because there might be
					 * only a post_section_parser */
					if (strcmp(args[0], sect->section_name) == 0 &&
					    sect->section_parser) {
						is_sect = 1;
						break;
					}
				}

				if (g_key == 0) {
					/* no anonymizing needed, dump the config as-is (but without comments).
					 * Note: tabs were lost during tokenizing, so we reinsert for non-section
					 * keywords.
					 */
					if (!is_sect)
						qfprintf(stdout, "\t");

					for (i = 0; i < arg; i++) {
						qfprintf(stdout, "%s ", args[i]);
					}
					qfprintf(stdout, "\n");
					continue;
				}

				/* We're anonymizing */

				if (is_sect) {
					/* new sections are optionally followed by an identifier */
					if (arg >= 2) {
						qfprintf(stdout, "%s %s\n", args[0], HA_ANON_ID(g_key, args[1]));
					}
					else {
						qfprintf(stdout, "%s\n", args[0]);
					}
					continue;
				}

				/* non-section keywords start indented */
				qfprintf(stdout, "\t");

				/* some keywords deserve special treatment */
				if (!*args[0]) {
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "anonkey") == 0) {
					qfprintf(stdout, "%s [...]\n", args[0]);
				}

				else if (strcmp(args[0], "maxconn") == 0) {
					qfprintf(stdout, "%s %s\n", args[0], args[1]);
				}

				else if (strcmp(args[0], "stats") == 0 &&
					 (strcmp(args[1], "timeout") == 0 || strcmp(args[1], "maxconn") == 0)) {
					qfprintf(stdout, "%s %s %s\n", args[0], args[1], args[2]);
				}

				else if (strcmp(args[0], "stats") == 0 && strcmp(args[1], "socket") == 0) {
					qfprintf(stdout, "%s %s ", args[0], args[1]);

					if (arg > 2) {
						qfprintf(stdout, "%s ", hash_ipanon(g_key, args[2], 1));

						if (arg > 3) {
							qfprintf(stdout, "[...]\n");
						}
						else {
							qfprintf(stdout, "\n");
						}
					}
					else {
						qfprintf(stdout, "\n");
					}
				}

				else if (strcmp(args[0], "timeout") == 0) {
					qfprintf(stdout, "%s %s %s\n", args[0], args[1], args[2]);
				}

				else if (strcmp(args[0], "mode") == 0) {
					qfprintf(stdout, "%s %s\n", args[0], args[1]);
				}

				/* It concerns user in global section and in userlist */
				else if (strcmp(args[0], "user") == 0) {
					qfprintf(stdout, "%s %s ", args[0], HA_ANON_ID(g_key, args[1]));

					if (arg > 2) {
						qfprintf(stdout, "[...]\n");
					}
					else {
						qfprintf(stdout, "\n");
					}
				}

				else if (strcmp(args[0], "bind") == 0) {
					qfprintf(stdout, "%s ", args[0]);
					qfprintf(stdout, "%s ", hash_ipanon(g_key, args[1], 1));
					if (arg > 2) {
						qfprintf(stdout, "[...]\n");
					}
					else {
						qfprintf(stdout, "\n");
					}
				}

				else if (strcmp(args[0], "server") == 0) {
					qfprintf(stdout, "%s %s ", args[0], HA_ANON_ID(g_key, args[1]));

					if (arg > 2) {
						qfprintf(stdout, "%s ", hash_ipanon(g_key, args[2], 1));
					}
					if (arg > 3) {
						qfprintf(stdout, "[...]\n");
					}
					else {
						qfprintf(stdout, "\n");
					}
				}

				else if (strcmp(args[0], "redirect") == 0) {
					qfprintf(stdout, "%s %s ", args[0], args[1]);

					if (strcmp(args[1], "prefix") == 0 || strcmp(args[1], "location") == 0) {
						qfprintf(stdout, "%s ", HA_ANON_PATH(g_key, args[2]));
					}
					else {
						qfprintf(stdout, "%s ", args[2]);
					}
					if (arg > 3) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "acl") == 0) {
					qfprintf(stdout, "%s %s %s ", args[0], HA_ANON_ID(g_key, args[1]), args[2]);

					if (arg > 3) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "log") == 0) {
					qfprintf(stdout, "log ");

					if (strcmp(args[1], "global") == 0) {
						qfprintf(stdout, "%s ", args[1]);
					}
					else {
						qfprintf(stdout, "%s ", hash_ipanon(g_key, args[1], 1));
					}
					if (arg > 2) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "peer") == 0) {
					qfprintf(stdout, "%s %s ", args[0], HA_ANON_ID(g_key, args[1]));
					qfprintf(stdout, "%s ", hash_ipanon(g_key, args[2], 1));

					if (arg > 3) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "use_backend") == 0) {
					qfprintf(stdout, "%s %s ", args[0], HA_ANON_ID(g_key, args[1]));

					if (arg > 2) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "default_backend") == 0) {
					qfprintf(stdout, "%s %s\n", args[0], HA_ANON_ID(g_key, args[1]));
				}

				else if (strcmp(args[0], "source") == 0) {
					qfprintf(stdout, "%s %s ", args[0], hash_ipanon(g_key, args[1], 1));

					if (arg > 2) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "nameserver") == 0) {
					qfprintf(stdout, "%s %s %s ", args[0],
						HA_ANON_ID(g_key, args[1]), hash_ipanon(g_key, args[2], 1));
					if (arg > 3) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "http-request") == 0) {
					qfprintf(stdout, "%s %s ", args[0], args[1]);
					if (arg > 2)
						qfprintf(stdout, "[...]");
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "http-response") == 0) {
					qfprintf(stdout, "%s %s ", args[0], args[1]);
					if (arg > 2)
						qfprintf(stdout, "[...]");
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "http-after-response") == 0) {
					qfprintf(stdout, "%s %s ", args[0], args[1]);
					if (arg > 2)
						qfprintf(stdout, "[...]");
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "filter") == 0) {
					qfprintf(stdout, "%s %s ", args[0], args[1]);
					if (arg > 2)
						qfprintf(stdout, "[...]");
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "errorfile") == 0) {
					qfprintf(stdout, "%s %s %s\n", args[0], args[1], HA_ANON_PATH(g_key, args[2]));
				}

				else if (strcmp(args[0], "cookie") == 0) {
					qfprintf(stdout, "%s %s ", args[0], HA_ANON_ID(g_key, args[1]));
					if (arg > 2)
						qfprintf(stdout, "%s ", args[2]);
					if (arg > 3)
						qfprintf(stdout, "[...]");
					qfprintf(stdout, "\n");
				}

				else if (strcmp(args[0], "stats") == 0 && strcmp(args[1], "auth") == 0) {
					qfprintf(stdout, "%s %s %s\n", args[0], args[1], HA_ANON_STR(g_key, args[2]));
				}

				else {
					/* display up to 3 words and mask the rest which might be confidential */
					for (i = 0; i < MIN(arg, 3); i++) {
						qfprintf(stdout, "%s ", args[i]);
					}
					if (arg > 3) {
						qfprintf(stdout, "[...]");
					}
					qfprintf(stdout, "\n");
				}
			}
			continue;
		}
		/* end of config dump */

		/* empty line */
		if (!*args || !**args)
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
		if (*args[0] == '.' && !(global.mode & MODE_DISCOVERY)) {
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

		/* now check for empty args on the line. Only do that in normal
		 * mode to prevent double display during discovery pass. It relies
		 * on errptr as returned by parse_line() above.
		 */
		if (!(global.mode & MODE_DISCOVERY)) {
			int check_arg;

			for (check_arg = 0; check_arg < arg; check_arg++) {
				if (!*args[check_arg]) {
					static int warned_empty;
					size_t newpos;
					int suggest = 0;

					/* if an empty arg was found, its pointer should be in <errptr>, except
					 * for rare cases such as '\x00' etc. We need to check errptr in any case
					 * and if it's not set, we'll fall back to args's position in the output
					 * string instead (less accurate but still useful).
					 */
					if (!errptr) {
						newpos = args[check_arg] - outline;
						if (newpos >= strlen(line))
							newpos = 0; // impossible to report anything, start at the beginning.
						errptr = line + newpos;
					} else if (isalnum((uchar)*errptr) || *errptr == '_') {
						/* looks like an environment variable */
						suggest = 1;
					}

					/* sanitize input line in-place */
					newpos = sanitize_for_printing(line, errptr - line, 80);
					ha_alert("parsing [%s:%d]: argument number %d at position %d is empty and marks the end of the "
					         "argument list:\n  %s\n  %*s\n%s",
					         file, linenum, check_arg, (int)(errptr - thisline + 1), line, (int)(newpos + 1),
					         "^", (warned_empty++) ? "" :
					         ("Aborting to prevent all subsequent arguments from being silently ignored. "
						  "If this is caused by an environment variable expansion, please have a look at section "
						  "2.3 of the configuration manual to find solutions to address this.\n"));

					if (suggest) {
						const char *end = errptr;
						struct ist alt;

						while (isalnum((uchar)*end) || *end == '_')
							end++;

						if (end > errptr) {
							alt = env_suggest(ist2(errptr, end - errptr));
							if (isttest(alt))
								ha_notice("Hint: maybe you meant %.*s instead ?\n", (int)istlen(alt), istptr(alt));
						}
					}

					err_code |= ERR_ALERT | ERR_FATAL;
					fatal++;
					goto next_line;
				}
			}
		}

		/* check for keyword modifiers "no" and "default" */
		if (strcmp(args[0], "no") == 0) {
			kwm = KWM_NO;
			lshift_args(args);
		}
		else if (strcmp(args[0], "default") == 0) {
			kwm = KWM_DEF;
			lshift_args(args);
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
			if (strcmp(args[0], ics->section_name) == 0 && ics->section_parser) {
				cursection = ics->section_name;
				pcs = cs;
				cs = ics;
				free(global.cfg_curr_section);
				global.cfg_curr_section = strdup(*args[1] ? args[1] : args[0]);
				check_section_position(args[0], file, linenum);
				break;
			}
		}

		if (pcs) {
			struct cfg_section *psect;
			int status;


			/* look for every post_section_parser for the previous section name */
			list_for_each_entry(psect, &sections, list) {
				if (strcmp(pcs->section_name, psect->section_name) == 0 &&
						psect->post_section_parser) {

					/* don't call post_section_parser in MODE_DISCOVERY */
					if (global.mode & MODE_DISCOVERY)
						goto section_parser;

					status = psect->post_section_parser();
					err_code |= status;
					if (status & ERR_FATAL)
						fatal++;

					if (err_code & ERR_ABORT)
						goto err;
				}
			}
		}
		pcs = NULL;

section_parser:
		if (!cs) {
			/* ignore unknown section names during the first read in MODE_DISCOVERY */
			if (global.mode & MODE_DISCOVERY)
				continue;
			ha_alert("parsing [%s:%d]: unknown keyword '%s' out of section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			fatal++;
		} else {
			int status;

			/* read only the "global" and "program" sections in MODE_DISCOVERY */
			if (((global.mode & MODE_DISCOVERY) && (strcmp(cs->section_name, "global") != 0)
			     && (strcmp(cs->section_name, "program") != 0)))
				continue;

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

	/* call post_section_parser of the last section when there is no more lines */
	if (cs) {
		struct cfg_section *psect;
		int status;

		/* don't call post_section_parser in MODE_DISCOVERY */
		if (!(global.mode & MODE_DISCOVERY)) {
			list_for_each_entry(psect, &sections, list) {
				if (strcmp(cs->section_name, psect->section_name) == 0 &&
				     psect->post_section_parser) {

					status = psect->post_section_parser();
					if (status & ERR_FATAL)
						fatal++;

					err_code |= status;

					if (err_code & ERR_ABORT)
						goto err;

				}
			}
		}
	}

	if (nested_cond_lvl) {
		ha_alert("parsing [%s:%d]: non-terminated '.if' block.\n", file, linenum);
		err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
	}

err:
	ha_free(&cfg_scope);
	cursection = NULL;
	free(thisline);
	free(outline);
	global.cfg_curr_line = 0;
	global.cfg_curr_file = NULL;

	return err_code;
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
	int cfgerr = 0, ret;
	struct proxy *init_proxies_list = NULL, *defpx;
	struct stktable *t;
	struct server *newsrv = NULL;
	struct mt_list back;
	int err_code = 0;
	/* Value forced to skip '1' due to an historical bug, see below for more details. */
	unsigned int next_pxid = 2;
	struct bind_conf *bind_conf;
	char *err;
	struct cfg_postparser *postparser;
	struct resolvers *curr_resolvers = NULL;
	int i;

	bind_conf = NULL;
	/*
	 * Now, check for the integrity of all that we have collected.
	 */

	if (!global.tune.max_http_hdr)
		global.tune.max_http_hdr = MAX_HTTP_HDR;

	if (!global.tune.cookie_len)
		global.tune.cookie_len = CAPTURE_LEN;

	if (!global.tune.requri_len)
		global.tune.requri_len = REQURI_LEN;

	if (!global.thread_limit)
		global.thread_limit = MAX_THREADS;

#if defined(USE_THREAD)
	if (thread_cpus_enabled_at_boot > global.thread_limit)
		thread_cpus_enabled_at_boot = global.thread_limit;
#endif
	if (global.nbthread > global.thread_limit) {
		ha_warning("nbthread forced to a higher value (%d) than the configured thread-hard-limit (%d), enforcing the limit. "
			   "Please fix either value to remove this warning.\n",
			   global.nbthread, global.thread_limit);
		global.nbthread = global.thread_limit;
	}

	if (global.tune.bufsize_large > 0) {
		if (global.tune.bufsize_large == global.tune.bufsize)
			global.tune.bufsize_large = 0;
		else if (global.tune.bufsize_large < global.tune.bufsize) {
			ha_warning("tune.bufsize.large (%u) is lower than tune.bufsize (%u). large buffers support is disabled. "
				   "Please fix either value to remove this warning.\n",
				   global.tune.bufsize_large, global.tune.bufsize);
			global.tune.bufsize_large = 0;
		}
	}

	/* in the worst case these were supposed to be set in thread_detect_count() */
	BUG_ON(!global.nbthread);
	BUG_ON(!global.nbtgroups);

	if (thread_map_to_groups() < 0) {
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	pool_head_requri = create_pool("requri", global.tune.requri_len , MEM_F_SHARED);

	pool_head_capture = create_pool("capture", global.tune.cookie_len, MEM_F_SHARED);

	/* both will have already emitted an error message if needed */
	if (!pool_head_requri || !pool_head_capture) {
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

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

	/*
	 * we must finish to initialize certain things on the servers,
	 * as some of the fields may be accessed soon
	 */
	MT_LIST_FOR_EACH_ENTRY_LOCKED(newsrv, &servers_list, global_list, back) {
		err_code |= srv_preinit(newsrv);
		if (err_code & ERR_CODE)
			goto out;
	}

	list_for_each_entry(defpx, &defaults_list, el) {
		/* check validity for 'tcp-request' layer 4/5/6/7 rules */
		cfgerr += check_action_rules(&defpx->tcp_req.l4_rules, defpx, &err_code);
		cfgerr += check_action_rules(&defpx->tcp_req.l5_rules, defpx, &err_code);
		cfgerr += check_action_rules(&defpx->tcp_req.inspect_rules, defpx, &err_code);
		cfgerr += check_action_rules(&defpx->tcp_rep.inspect_rules, defpx, &err_code);
		cfgerr += check_action_rules(&defpx->http_req_rules, defpx, &err_code);
		cfgerr += check_action_rules(&defpx->http_res_rules, defpx, &err_code);
		cfgerr += check_action_rules(&defpx->http_after_res_rules, defpx, &err_code);

		err = NULL;
		i = smp_resolve_args(defpx, &err);
		cfgerr += i;
		if (i) {
			indent_msg(&err, 8);
			ha_alert("%s%s\n", i > 1 ? "multiple argument resolution errors:" : "", err);
			ha_free(&err);
		}
		else {
			cfgerr += acl_find_targets(defpx);
		}
	}

	/* starting to initialize the main proxies list */
	init_proxies_list = proxies_list;

init_proxies_list_stage1:
	for (curproxy = init_proxies_list; curproxy; curproxy = curproxy->next) {
		proxy_init_per_thr(curproxy);

		/* Assign automatic UUID if unset except for internal proxies.
		 *
		 * WARNING proxy UUID initialization is buggy as value '1' is
		 * skipped if not explicitly used. This is an historical bug
		 * and should not be corrected to prevent breakage on future
		 * versions.
		 */
		if (!(curproxy->cap & PR_CAP_INT) && curproxy->uuid < 0) {
			next_pxid = proxy_get_next_id(next_pxid);
			curproxy->uuid = next_pxid;
			proxy_index_id(curproxy);
			next_pxid++;
		}

		if (curproxy->mode == PR_MODE_HTTP && global.tune.bufsize >= (256 << 20) && ONLY_ONCE()) {
			ha_alert("global.tune.bufsize must be below 256 MB when HTTP is in use (current value = %d).\n",
				 global.tune.bufsize);
			cfgerr++;
		}

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

		ret = proxy_finalize(curproxy, &err_code);
		if (ret) {
			cfgerr += ret;
			if (err_code & ERR_FATAL)
				goto out;
		}
	}

	/* Dynamic proxies IDs will never be lowered than this value. */
	dynpx_next_id = next_pxid;

	/*
	 * We have just initialized the main proxies list
	 * we must also configure the log-forward proxies list
	 */
	if (init_proxies_list == proxies_list) {
		init_proxies_list = cfg_log_forward;
		/* check if list is not null to avoid infinite loop */
		if (init_proxies_list)
			goto init_proxies_list_stage1;
	}

	if (init_proxies_list == cfg_log_forward) {
		init_proxies_list = sink_proxies_list;
		/* check if list is not null to avoid infinite loop */
		if (init_proxies_list)
			goto init_proxies_list_stage1;
	}

	/***********************************************************/
	/* At this point, target names have already been resolved. */
	/***********************************************************/

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

	/* starting to initialize the main proxies list */
	init_proxies_list = proxies_list;

init_proxies_list_stage2:
	for (curproxy = init_proxies_list; curproxy; curproxy = curproxy->next) {
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
			bind_conf->analysers |= curproxy->fe_req_ana;
			if (!bind_conf->maxaccept)
				bind_conf->maxaccept = global.tune.maxaccept ? global.tune.maxaccept : MAX_ACCEPT;
			bind_conf->accept = session_accept_fd;
			if (curproxy->options & PR_O_TCP_NOLING)
				bind_conf->options |= BC_O_NOLINGER;

			/* smart accept mode is automatic in HTTP mode */
			if ((curproxy->options2 & PR_O2_SMARTACC) ||
			    ((curproxy->mode == PR_MODE_HTTP || (bind_conf->options & BC_O_USE_SSL)) &&
			     !(curproxy->no_options2 & PR_O2_SMARTACC)))
				bind_conf->options |= BC_O_NOQUICKACK;
		}

		/* adjust this proxy's listeners */
		bind_conf = NULL;
		next_id = 1;
		list_for_each_entry(listener, &curproxy->conf.listeners, by_fe) {
			if (!listener->luid) {
				/* listener ID not set, use automatic numbering with first
				 * spare entry starting with next_luid.
				 */
				if (listener->by_fe.p != &curproxy->conf.listeners) {
					struct listener *prev_li = LIST_PREV(&listener->by_fe, typeof(prev_li), by_fe);
					if (prev_li->luid)
						next_id = prev_li->luid + 1;
				}
				next_id = listener_get_next_id(curproxy, next_id);
				listener->luid = next_id;
				listener_index_id(curproxy, listener);
			}
			next_id++;

			/* enable separate counters */
			if (curproxy->options2 & PR_O2_SOCKSTAT) {
				listener->counters = calloc(1, sizeof(*listener->counters));
				if (!listener->name)
					memprintf(&listener->name, "sock-%d", listener->luid);
			}

#ifdef USE_QUIC
			if (listener->bind_conf->xprt == xprt_get(XPRT_QUIC)) {
				/* quic_conn are counted against maxconn. */
				listener->bind_conf->options |= BC_O_XPRT_MAXCONN;
				listener->rx.quic_curr_handshake = 0;
				listener->rx.quic_curr_accept = 0;

# ifdef USE_QUIC_OPENSSL_COMPAT
				/* store the last checked bind_conf in bind_conf */
				if (!(quic_tune.fe.opts & QUIC_TUNE_FE_LISTEN_OFF) &&
				    !(global.tune.options & GTUNE_LIMITED_QUIC) &&
				    listener->bind_conf != bind_conf) {
					bind_conf = listener->bind_conf;
					ha_alert("Binding [%s:%d] for %s %s: this SSL library does not support the "
						 "QUIC protocol. A limited compatibility layer may be enabled using "
						 "the \"limited-quic\" global option if desired.\n",
						 listener->bind_conf->file, listener->bind_conf->line,
						 proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				}
# endif

				li_init_per_thr(listener);
			}
#endif
		}

		/* Release unused SSL configs */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			if (!(bind_conf->options & BC_O_USE_SSL) && bind_conf->xprt->destroy_bind_conf)
				bind_conf->xprt->destroy_bind_conf(bind_conf);
		}

		/* Create the task associated with the proxy. Only necessary
		 * for frontend or if a stick-table is defined.
		 */
		if ((curproxy->cap & PR_CAP_FE) || (curproxy->table && curproxy->table->current)) {
			curproxy->task = task_new_anywhere();
			if (curproxy->task) {
				curproxy->task->context = curproxy;
				curproxy->task->process = manage_proxy;
			}
			else {
				ha_alert("Proxy '%s': no more memory when trying to allocate the management task\n",
					 curproxy->id);
				cfgerr++;
			}
		}
	}

	/*
	 * We have just initialized the main proxies list
	 * we must also configure the log-forward proxies list
	 */
	if (init_proxies_list == proxies_list) {
		init_proxies_list = cfg_log_forward;
		/* check if list is not null to avoid infinite loop */
		if (init_proxies_list)
			goto init_proxies_list_stage2;
	}

	if (init_proxies_list == cfg_log_forward) {
		init_proxies_list = sink_proxies_list;
		/* check if list is not null to avoid infinite loop */
		if (init_proxies_list)
			goto init_proxies_list_stage2;
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
			struct peer *peer;
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
				p = curpeers->remote;
				while (p) {
					struct peer *other_peer;

					for (other_peer = curpeers->remote; other_peer && other_peer != p; other_peer = other_peer->next) {
						if (strcmp(other_peer->id, p->id) == 0) {
							ha_alert("Peer section '%s' [%s:%d]: another peer named '%s' was already defined at line %s:%d, please use distinct names.\n",
								 curpeers->peers_fe->id,
								 p->conf.file, p->conf.line,
								 other_peer->id, other_peer->conf.file, other_peer->conf.line);
							cfgerr++;
							break;
						}
					}

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

					if (curpeers->local->srv) {
						if (curpeers->local->srv->use_ssl == 1 && !(bind_conf->options & BC_O_USE_SSL)) {
							ha_warning("Peers section '%s': local peer have a non-SSL listener and a SSL server configured at line %s:%d.\n",
								   curpeers->peers_fe->id, curpeers->local->conf.file, curpeers->local->conf.line);
						}
						else if (curpeers->local->srv->use_ssl != 1 && (bind_conf->options & BC_O_USE_SSL)) {
							ha_warning("Peers section '%s': local peer have a SSL listener and a non-SSL server configured at line %s:%d.\n",
								   curpeers->peers_fe->id, curpeers->local->conf.file, curpeers->local->conf.line);
						}
					}

					/* finish the bind setup */
					ret = bind_complete_thread_setup(bind_conf, &err_code);
					if (ret != 0) {
						cfgerr += ret;
						if (err_code & ERR_FATAL)
							goto out;
					}

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

				/* Ignore the peer shard greater than the number of peer shard for this section.
				 * Also ignore the peer shard of the local peer.
				 */
				for (peer = curpeers->remote; peer; peer = peer->next) {
					if (peer == curpeers->local) {
						if (peer->srv->shard) {
							ha_warning("Peers section '%s': shard ignored for '%s' local peer\n",
									   curpeers->id, peer->id);
							peer->srv->shard = 0;
						}
					}
					else if (peer->srv->shard > curpeers->nb_shards) {
						ha_warning("Peers section '%s': shard ignored for '%s' local peer because "
								   "%d shard value is greater than the section number of shards (%d)\n",
								   curpeers->id, peer->id, peer->srv->shard, curpeers->nb_shards);
						peer->srv->shard = 0;
					}
				}

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
		err = NULL;
		if (!stktable_init(t, &err)) {
			ha_alert("Parsing [%s:%d]: failed to initialize '%s' stick-table: %s.\n", t->conf.file, t->conf.line, t->id, err);
			ha_free(&err);
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

		err = NULL;
		if (!stktable_init(curproxy->table, &err)) {
			ha_alert("Proxy '%s': failed to initialize stick-table: %s.\n", curproxy->id, err);
			ha_free(&err);
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

	if (experimental_directives_allowed &&
	    !(get_tainted() & TAINTED_CONFIG_EXP_KW_DECLARED)) {
		ha_warning("Option 'expose-experimental-directives' is set in the global section but is "
		           "no longer used. It is strongly recommended to remove it in order to avoid "
		           "using an experimental directive by accident in the future.\n");
		err_code |= ERR_WARN;
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

	if (section_parser) {
		/* only checks if we register a section parser, not a post section callback */
		list_for_each_entry(cs, &sections, list) {
			if (strcmp(cs->section_name, section_name) == 0 && cs->section_parser) {
				ha_alert("register section '%s': already registered.\n", section_name);
				return 0;
			}
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

/* dumps all registered keywords by section on stdout */
void cfg_dump_registered_keywords()
{
	/*                             CFG_GLOBAL, CFG_LISTEN, CFG_USERLIST, CFG_PEERS, CFG_CRTLIST, CFG_CRTSTORE, CFG_TRACES, CFG_ACME */
	const char* sect_names[] = { "", "global", "listen", "userlist", "peers", "crt-list", "crt-store", "traces", "acme", 0 };
	int section;
	int index;

	for (section = 1; sect_names[section]; section++) {
		struct cfg_kw_list *kwl;
		const struct cfg_keyword *kwp, *kwn;

		printf("%s\n", sect_names[section]);

		for (kwn = kwp = NULL;; kwp = kwn) {
			list_for_each_entry(kwl, &cfg_keywords.list, list) {
				for (index = 0; kwl->kw[index].kw != NULL; index++)
					if (kwl->kw[index].section == section &&
					    strordered(kwp ? kwp->kw : NULL, kwl->kw[index].kw, kwn != kwp ? kwn->kw : NULL))
						kwn = &kwl->kw[index];
			}
			if (kwn == kwp)
				break;
			printf("\t%s\n", kwn->kw);
		}

		if (section == CFG_LISTEN) {
			/* there are plenty of other keywords there */
			extern struct list tcp_req_conn_keywords, tcp_req_sess_keywords,
				tcp_req_cont_keywords, tcp_res_cont_keywords;
			extern struct bind_kw_list bind_keywords;
			extern struct srv_kw_list srv_keywords;
			struct bind_kw_list *bkwl;
			struct srv_kw_list *skwl;
			const struct bind_kw *bkwp, *bkwn;
			const struct srv_kw *skwp, *skwn;
			const struct cfg_opt *coptp, *coptn;

			/* display the non-ssl keywords */
			for (bkwn = bkwp = NULL;; bkwp = bkwn) {
				list_for_each_entry(bkwl, &bind_keywords.list, list) {
					if (strcmp(bkwl->scope, "SSL") == 0) /* skip SSL keywords */
						continue;
					for (index = 0; bkwl->kw[index].kw != NULL; index++) {
						if (strordered(bkwp ? bkwp->kw : NULL,
							       bkwl->kw[index].kw,
							       bkwn != bkwp ? bkwn->kw : NULL))
							bkwn = &bkwl->kw[index];
					}
				}
				if (bkwn == bkwp)
					break;

				if (!bkwn->skip)
					printf("\tbind <addr> %s\n", bkwn->kw);
				else
					printf("\tbind <addr> %s +%d\n", bkwn->kw, bkwn->skip);
			}
#if defined(USE_OPENSSL)
			/* displays the "ssl" keywords */
			for (bkwn = bkwp = NULL;; bkwp = bkwn) {
				list_for_each_entry(bkwl, &bind_keywords.list, list) {
					if (strcmp(bkwl->scope, "SSL") != 0) /* skip non-SSL keywords */
						continue;
					for (index = 0; bkwl->kw[index].kw != NULL; index++) {
						if (strordered(bkwp ? bkwp->kw : NULL,
						               bkwl->kw[index].kw,
						               bkwn != bkwp ? bkwn->kw : NULL))
							bkwn = &bkwl->kw[index];
					}
				}
				if (bkwn == bkwp)
					break;

				if (strcmp(bkwn->kw, "ssl") == 0) /* skip "bind <addr> ssl ssl" */
					continue;

				if (!bkwn->skip)
					printf("\tbind <addr> ssl %s\n", bkwn->kw);
				else
					printf("\tbind <addr> ssl %s +%d\n", bkwn->kw, bkwn->skip);
			}
#endif
			for (skwn = skwp = NULL;; skwp = skwn) {
				list_for_each_entry(skwl, &srv_keywords.list, list) {
					for (index = 0; skwl->kw[index].kw != NULL; index++)
						if (strordered(skwp ? skwp->kw : NULL,
							       skwl->kw[index].kw,
							       skwn != skwp ? skwn->kw : NULL))
							skwn = &skwl->kw[index];
				}
				if (skwn == skwp)
					break;

				if (!skwn->skip)
					printf("\tserver <name> <addr> %s\n", skwn->kw);
				else
					printf("\tserver <name> <addr> %s +%d\n", skwn->kw, skwn->skip);
			}

			for (coptn = coptp = NULL;; coptp = coptn) {
				for (index = 0; cfg_opts[index].name; index++)
					if (strordered(coptp ? coptp->name : NULL,
						       cfg_opts[index].name,
						       coptn != coptp ? coptn->name : NULL))
						coptn = &cfg_opts[index];

				for (index = 0; cfg_opts2[index].name; index++)
					if (strordered(coptp ? coptp->name : NULL,
						       cfg_opts2[index].name,
						       coptn != coptp ? coptn->name : NULL))
						coptn = &cfg_opts2[index];
				if (coptn == coptp)
					break;

				printf("\toption %s [ ", coptn->name);
				if (coptn->cap & PR_CAP_FE)
					printf("FE ");
				if (coptn->cap & PR_CAP_BE)
					printf("BE ");
				if (coptn->mode == PR_MODE_HTTP)
					printf("HTTP ");
				printf("]\n");
			}

			dump_act_rules(&tcp_req_conn_keywords,        "\ttcp-request connection ");
			dump_act_rules(&tcp_req_sess_keywords,        "\ttcp-request session ");
			dump_act_rules(&tcp_req_cont_keywords,        "\ttcp-request content ");
			dump_act_rules(&tcp_res_cont_keywords,        "\ttcp-response content ");
			dump_act_rules(&http_req_keywords.list,       "\thttp-request ");
			dump_act_rules(&http_res_keywords.list,       "\thttp-response ");
			dump_act_rules(&http_after_res_keywords.list, "\thttp-after-response ");
		}
		if (section == CFG_PEERS) {
			struct peers_kw_list *pkwl;
			const struct peers_keyword *pkwp, *pkwn;
			for (pkwn = pkwp = NULL;; pkwp = pkwn) {
				list_for_each_entry(pkwl, &peers_keywords.list, list) {
					for (index = 0; pkwl->kw[index].kw != NULL; index++) {
						if (strordered(pkwp ? pkwp->kw : NULL,
						               pkwl->kw[index].kw,
						               pkwn != pkwp ? pkwn->kw : NULL))
							pkwn = &pkwl->kw[index];
					}
				}
				if (pkwn == pkwp)
					break;
				printf("\t%s\n", pkwn->kw);
			}
		}
		if (section == CFG_CRTLIST) {
			/* displays the keyword available for the crt-lists */
			extern struct ssl_crtlist_kw ssl_crtlist_kws[] __maybe_unused;
			const struct ssl_crtlist_kw *sbkwp __maybe_unused, *sbkwn __maybe_unused;

#if defined(USE_OPENSSL)
			for (sbkwn = sbkwp = NULL;; sbkwp = sbkwn) {
				for (index = 0; ssl_crtlist_kws[index].kw != NULL; index++) {
					if (strordered(sbkwp ? sbkwp->kw : NULL,
						       ssl_crtlist_kws[index].kw,
						       sbkwn != sbkwp ? sbkwn->kw : NULL))
						sbkwn = &ssl_crtlist_kws[index];
				}
				if (sbkwn == sbkwp)
					break;
				if (!sbkwn->skip)
					printf("\t%s\n", sbkwn->kw);
				else
					printf("\t%s +%d\n", sbkwn->kw, sbkwn->skip);
			}
#endif

		}
	}
}

/* these are the config sections handled by default */
REGISTER_CONFIG_SECTION("listen",         cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("frontend",       cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("backend",        cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("defaults",       cfg_parse_listen,    NULL);
REGISTER_CONFIG_SECTION("global",         cfg_parse_global,    NULL);
REGISTER_CONFIG_SECTION("userlist",       cfg_parse_users,     NULL);
REGISTER_CONFIG_SECTION("mailers",        cfg_parse_mailers,   NULL);
REGISTER_CONFIG_SECTION("namespace_list", cfg_parse_netns,     NULL);
REGISTER_CONFIG_SECTION("traces",         cfg_parse_traces,    NULL);

static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "default-path",     cfg_parse_global_def_path },
	{ CFG_USERLIST, "group", cfg_parse_users_group },
	{ CFG_USERLIST, "user", cfg_parse_users_user },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
