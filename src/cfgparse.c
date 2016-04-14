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

#ifdef CONFIG_HAP_CRYPT
/* This is to have crypt() defined on Linux */
#define _GNU_SOURCE

#ifdef NEED_CRYPT_H
/* some platforms such as Solaris need this */
#include <crypt.h>
#endif
#endif /* CONFIG_HAP_CRYPT */

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

#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/namespace.h>

#include <types/capture.h>
#include <types/compression.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/obj_type.h>
#include <types/peers.h>
#include <types/mailers.h>
#include <types/dns.h>

#include <proto/acl.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/compression.h>
#include <proto/dumpstats.h>
#include <proto/filters.h>
#include <proto/frontend.h>
#include <proto/hdr_idx.h>
#include <proto/lb_chash.h>
#include <proto/lb_fas.h>
#include <proto/lb_fwlc.h>
#include <proto/lb_fwrr.h>
#include <proto/lb_map.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/protocol.h>
#include <proto/proto_tcp.h>
#include <proto/proto_uxst.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/peers.h>
#include <proto/sample.h>
#include <proto/session.h>
#include <proto/server.h>
#include <proto/stream.h>
#include <proto/raw_sock.h>
#include <proto/task.h>
#include <proto/stick_table.h>

#ifdef USE_OPENSSL
#include <types/ssl_sock.h>
#include <proto/ssl_sock.h>
#include <proto/shctx.h>
#endif /*USE_OPENSSL */

/* This is the SSLv3 CLIENT HELLO packet used in conjunction with the
 * ssl-hello-chk option to ensure that the remote server speaks SSL.
 *
 * Check RFC 2246 (TLSv1.0) sections A.3 and A.4 for details.
 */
const char sslv3_client_hello_pkt[] = {
	"\x16"                /* ContentType         : 0x16 = Hanshake           */
	"\x03\x00"            /* ProtocolVersion     : 0x0300 = SSLv3            */
	"\x00\x79"            /* ContentLength       : 0x79 bytes after this one */
	"\x01"                /* HanshakeType        : 0x01 = CLIENT HELLO       */
	"\x00\x00\x75"        /* HandshakeLength     : 0x75 bytes after this one */
	"\x03\x00"            /* Hello Version       : 0x0300 = v3               */
	"\x00\x00\x00\x00"    /* Unix GMT Time (s)   : filled with <now> (@0x0B) */
	"HAPROXYSSLCHK\nHAPROXYSSLCHK\n" /* Random   : must be exactly 28 bytes  */
	"\x00"                /* Session ID length   : empty (no session ID)     */
	"\x00\x4E"            /* Cipher Suite Length : 78 bytes after this one   */
	"\x00\x01" "\x00\x02" "\x00\x03" "\x00\x04" /* 39 most common ciphers :  */
	"\x00\x05" "\x00\x06" "\x00\x07" "\x00\x08" /* 0x01...0x1B, 0x2F...0x3A  */
	"\x00\x09" "\x00\x0A" "\x00\x0B" "\x00\x0C" /* This covers RSA/DH,       */
	"\x00\x0D" "\x00\x0E" "\x00\x0F" "\x00\x10" /* various bit lengths,      */
	"\x00\x11" "\x00\x12" "\x00\x13" "\x00\x14" /* SHA1/MD5, DES/3DES/AES... */
	"\x00\x15" "\x00\x16" "\x00\x17" "\x00\x18"
	"\x00\x19" "\x00\x1A" "\x00\x1B" "\x00\x2F"
	"\x00\x30" "\x00\x31" "\x00\x32" "\x00\x33"
	"\x00\x34" "\x00\x35" "\x00\x36" "\x00\x37"
	"\x00\x38" "\x00\x39" "\x00\x3A"
	"\x01"                /* Compression Length  : 0x01 = 1 byte for types   */
	"\x00"                /* Compression Type    : 0x00 = NULL compression   */
};

/* various keyword modifiers */
enum kw_mod {
	KWM_STD = 0,  /* normal */
	KWM_NO,       /* "no" prefixed before the keyword */
	KWM_DEF,      /* "default" prefixed before the keyword */
};

/* permit to store configuration section */
struct cfg_section {
	struct list list;
	char *section_name;
	int (*section_parser)(const char *, int, char **, int);
};

/* Used to chain configuration sections definitions. This list
 * stores struct cfg_section
 */
struct list sections = LIST_HEAD_INIT(sections);

/* some of the most common options which are also the easiest to handle */
struct cfg_opt {
	const char *name;
	unsigned int val;
	unsigned int cap;
	unsigned int checks;
	unsigned int mode;
};

/* proxy->options */
static const struct cfg_opt cfg_opts[] =
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
#ifdef TPROXY
	{ "transparent",  PR_O_TRANSP,     PR_CAP_BE, 0, 0 },
#else
	{ "transparent",  0, 0, 0, 0 },
#endif

	{ NULL, 0, 0, 0, 0 }
};

/* proxy->options2 */
static const struct cfg_opt cfg_opts2[] =
{
#ifdef CONFIG_HAP_LINUX_SPLICE
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
	{ "independant-streams",          PR_O2_INDEPSTR,  PR_CAP_FE|PR_CAP_BE, 0, 0 },
	{ "independent-streams",          PR_O2_INDEPSTR,  PR_CAP_FE|PR_CAP_BE, 0, 0 },
	{ "http-use-proxy-header",        PR_O2_USE_PXHDR, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ "http-pretend-keepalive",       PR_O2_FAKE_KA,   PR_CAP_FE|PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "http-no-delay",                PR_O2_NODELAY,   PR_CAP_FE|PR_CAP_BE, 0, PR_MODE_HTTP },
	{ NULL, 0, 0, 0 }
};

static char *cursection = NULL;
static struct proxy defproxy;		/* fake proxy used to assign default values on all instances */
int cfg_maxpconn = DEFAULT_MAXCONN;	/* # of simultaneous connections per proxy (-N) */
int cfg_maxconn = 0;			/* # of simultaneous connections, (-n) */

/* List head of all known configuration keywords */
static struct cfg_kw_list cfg_keywords = {
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
	struct listener *l;
	char *next, *dupstr;
	int port, end;

	next = dupstr = strdup(str);

	while (next && *next) {
		struct sockaddr_storage ss, *ss2;
		int fd = -1;

		str = next;
		/* 1) look for the end of the first address */
		if ((next = strchr(str, ',')) != NULL) {
			*next++ = 0;
		}

		ss2 = str2sa_range(str, &port, &end, err,
		                   curproxy == global.stats_fe ? NULL : global.unix_bind.prefix,
		                   NULL, 1);
		if (!ss2)
			goto fail;

		if (ss2->ss_family == AF_INET || ss2->ss_family == AF_INET6) {
			if (!port && !end) {
				memprintf(err, "missing port number: '%s'\n", str);
				goto fail;
			}

			if (!port || !end) {
				memprintf(err, "port offsets are not allowed in 'bind': '%s'\n", str);
				goto fail;
			}

			if (port < 1 || port > 65535) {
				memprintf(err, "invalid port '%d' specified for address '%s'.\n", port, str);
				goto fail;
			}

			if (end < 1 || end > 65535) {
				memprintf(err, "invalid port '%d' specified for address '%s'.\n", end, str);
				goto fail;
			}
		}
		else if (ss2->ss_family == AF_UNSPEC) {
			socklen_t addr_len;

			/* We want to attach to an already bound fd whose number
			 * is in the addr part of ss2 when cast to sockaddr_in.
			 * Note that by definition there is a single listener.
			 * We still have to determine the address family to
			 * register the correct protocol.
			 */
			fd = ((struct sockaddr_in *)ss2)->sin_addr.s_addr;
			addr_len = sizeof(*ss2);
			if (getsockname(fd, (struct sockaddr *)ss2, &addr_len) == -1) {
				memprintf(err, "cannot use file descriptor '%d' : %s.\n", fd, strerror(errno));
				goto fail;
			}

			port = end = get_host_port(ss2);
		}

		/* OK the address looks correct */
		ss = *ss2;

		for (; port <= end; port++) {
			l = calloc(1, sizeof(*l));
			l->obj_type = OBJ_TYPE_LISTENER;
			LIST_ADDQ(&curproxy->conf.listeners, &l->by_fe);
			LIST_ADDQ(&bind_conf->listeners, &l->by_bind);
			l->frontend = curproxy;
			l->bind_conf = bind_conf;

			l->fd = fd;
			l->addr = ss;
			l->xprt = &raw_sock;
			l->state = LI_INIT;

			if (ss.ss_family == AF_INET) {
				((struct sockaddr_in *)(&l->addr))->sin_port = htons(port);
				tcpv4_add_listener(l);
			}
			else if (ss.ss_family == AF_INET6) {
				((struct sockaddr_in6 *)(&l->addr))->sin6_port = htons(port);
				tcpv6_add_listener(l);
			}
			else {
				uxst_add_listener(l);
			}

			jobs++;
			listeners++;
		} /* end for(port) */
	} /* end while(next) */
	free(dupstr);
	return 1;
 fail:
	free(dupstr);
	return 0;
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

	Alert("parsing [%s:%d] : '%s' cannot handle unexpected argument '%s'.\n", file, linenum, kw, args[index + maxarg + 1]);
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

/* Report a warning if a rule is placed after a 'tcp-request content' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_tcp_cont(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->tcp_req.inspect_rules)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'tcp-request content' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'block' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_block(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->block_rules)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'block' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after an 'http_request' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_http_req(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->http_req_rules)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after an 'http-request' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a reqrewrite rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_reqxxx(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (proxy->req_exp) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'reqxxx' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a reqadd rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_reqadd(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->req_add)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'reqadd' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a redirect rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_redirect(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->redirect_rules)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'redirect' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'use_backend' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_use_backend(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->switching_rules)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'use_backend' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'use-server' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_use_server(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->server_rules)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'use-server' rule will still be processed before.\n",
			file, line, arg);
		return 1;
	}
	return 0;
}

/* report a warning if a "tcp request connection" rule is dangerously placed */
int warnif_misplaced_tcp_conn(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_tcp_cont(proxy, file, line, arg) ||
		warnif_rule_after_block(proxy, file, line, arg) ||
		warnif_rule_after_http_req(proxy, file, line, arg) ||
		warnif_rule_after_reqxxx(proxy, file, line, arg) ||
		warnif_rule_after_reqadd(proxy, file, line, arg) ||
		warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* report a warning if a "tcp request content" rule is dangerously placed */
int warnif_misplaced_tcp_cont(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_block(proxy, file, line, arg) ||
		warnif_rule_after_http_req(proxy, file, line, arg) ||
		warnif_rule_after_reqxxx(proxy, file, line, arg) ||
		warnif_rule_after_reqadd(proxy, file, line, arg) ||
		warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* report a warning if a block rule is dangerously placed */
int warnif_misplaced_block(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_http_req(proxy, file, line, arg) ||
		warnif_rule_after_reqxxx(proxy, file, line, arg) ||
		warnif_rule_after_reqadd(proxy, file, line, arg) ||
		warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* report a warning if an http-request rule is dangerously placed */
int warnif_misplaced_http_req(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_reqxxx(proxy, file, line, arg) ||
		warnif_rule_after_reqadd(proxy, file, line, arg) ||
		warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* report a warning if a reqxxx rule is dangerously placed */
int warnif_misplaced_reqxxx(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_reqadd(proxy, file, line, arg) ||
		warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* report a warning if a reqadd rule is dangerously placed */
int warnif_misplaced_reqadd(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* report a warning if a redirect rule is dangerously placed */
int warnif_misplaced_redirect(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* Report it if a request ACL condition uses some keywords that are incompatible
 * with the place where the ACL is used. It returns either 0 or ERR_WARN so that
 * its result can be or'ed with err_code. Note that <cond> may be NULL and then
 * will be ignored.
 */
static int warnif_cond_conflicts(const struct acl_cond *cond, unsigned int where, const char *file, int line)
{
	const struct acl *acl;
	const char *kw;

	if (!cond)
		return 0;

	acl = acl_cond_conflicts(cond, where);
	if (acl) {
		if (acl->name && *acl->name)
			Warning("parsing [%s:%d] : acl '%s' will never match because it only involves keywords that are incompatible with '%s'\n",
			        file, line, acl->name, sample_ckp_names(where));
		else
			Warning("parsing [%s:%d] : anonymous acl will never match because it uses keyword '%s' which is incompatible with '%s'\n",
			        file, line, LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw, sample_ckp_names(where));
		return ERR_WARN;
	}
	if (!acl_cond_kw_conflicts(cond, where, &acl, &kw))
		return 0;

	if (acl->name && *acl->name)
		Warning("parsing [%s:%d] : acl '%s' involves keywords '%s' which is incompatible with '%s'\n",
		        file, line, acl->name, kw, sample_ckp_names(where));
	else
		Warning("parsing [%s:%d] : anonymous acl involves keyword '%s' which is incompatible with '%s'\n",
		        file, line, kw, sample_ckp_names(where));
	return ERR_WARN;
}

/*
 * parse a line in a <global> section. Returns the error code, 0 if OK, or
 * any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_global(const char *file, int linenum, char **args, int kwm)
{
	int err_code = 0;
	char *errmsg = NULL;

	if (!strcmp(args[0], "global")) {  /* new section */
		/* no option, nothing special to do */
		alertif_too_many_args(0, file, linenum, args, &err_code);
		goto out;
	}
	else if (!strcmp(args[0], "ca-base")) {
#ifdef USE_OPENSSL
		if(alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.ca_base != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a directory path as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.ca_base = strdup(args[1]);
#else
		Alert("parsing [%s:%d] : '%s' is not implemented.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (!strcmp(args[0], "crt-base")) {
#ifdef USE_OPENSSL
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.crt_base != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a directory path as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.crt_base = strdup(args[1]);
#else
		Alert("parsing [%s:%d] : '%s' is not implemented.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (!strcmp(args[0], "daemon")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.mode |= MODE_DAEMON;
	}
	else if (!strcmp(args[0], "debug")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.mode |= MODE_DEBUG;
	}
	else if (!strcmp(args[0], "noepoll")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_EPOLL;
	}
	else if (!strcmp(args[0], "nokqueue")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_KQUEUE;
	}
	else if (!strcmp(args[0], "nopoll")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_POLL;
	}
	else if (!strcmp(args[0], "nosplice")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_SPLICE;
	}
	else if (!strcmp(args[0], "nogetaddrinfo")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_GAI;
	}
	else if (!strcmp(args[0], "quiet")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.mode |= MODE_QUIET;
	}
	else if (!strcmp(args[0], "tune.maxpollevents")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.maxpollevents != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.maxpollevents = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.maxaccept")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.maxaccept != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.maxaccept = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.chksize")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.chksize = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.recv_enough")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.recv_enough = atol(args[1]);
	}
#ifdef USE_OPENSSL
	else if (!strcmp(args[0], "tune.ssl.force-private-cache")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.sslprivatecache = 1;
	}
	else if (!strcmp(args[0], "tune.ssl.cachesize")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.sslcachesize = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.ssl.lifetime")) {
		unsigned int ssllifetime;
		const char *res;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects ssl sessions <lifetime> in seconds as argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		res = parse_time_err(args[1], &ssllifetime, TIME_UNIT_S);
		if (res) {
			Alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
			      file, linenum, *res, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		global.tune.ssllifetime = ssllifetime;
	}
	else if (!strcmp(args[0], "tune.ssl.maxrecord")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.ssl_max_record = atol(args[1]);
	}
#ifndef OPENSSL_NO_DH
	else if (!strcmp(args[0], "tune.ssl.default-dh-param")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.ssl_default_dh_param = atol(args[1]);
		if (global.tune.ssl_default_dh_param < 1024) {
			Alert("parsing [%s:%d] : '%s' expects a value >= 1024.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
#endif
	else if (!strcmp(args[0], "tune.ssl.ssl-ctx-cache-size")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.ssl_ctx_cache = atoi(args[1]);
		if (global.tune.ssl_ctx_cache < 0) {
			Alert("parsing [%s:%d] : '%s' expects a positive numeric value\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
#endif
	else if (!strcmp(args[0], "tune.buffers.limit")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.buf_limit = atol(args[1]);
		if (global.tune.buf_limit) {
			if (global.tune.buf_limit < 3)
				global.tune.buf_limit = 3;
			if (global.tune.buf_limit <= global.tune.reserved_bufs)
				global.tune.buf_limit = global.tune.reserved_bufs + 1;
		}
	}
	else if (!strcmp(args[0], "tune.buffers.reserve")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.reserved_bufs = atol(args[1]);
		if (global.tune.reserved_bufs < 2)
			global.tune.reserved_bufs = 2;
		if (global.tune.buf_limit && global.tune.buf_limit <= global.tune.reserved_bufs)
			global.tune.buf_limit = global.tune.reserved_bufs + 1;
	}
	else if (!strcmp(args[0], "tune.bufsize")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.bufsize = atol(args[1]);
		if (global.tune.bufsize <= 0) {
			Alert("parsing [%s:%d] : '%s' expects a positive integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_init(&trash, realloc(trash.str, global.tune.bufsize), global.tune.bufsize);
		alloc_trash_buffers(global.tune.bufsize);
	}
	else if (!strcmp(args[0], "tune.maxrewrite")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.maxrewrite = atol(args[1]);
		if (global.tune.maxrewrite < 0) {
			Alert("parsing [%s:%d] : '%s' expects a positive integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tune.idletimer")) {
		unsigned int idle;
		const char *res;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a timer value between 0 and 65535 ms.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		res = parse_time_err(args[1], &idle, TIME_UNIT_MS);
		if (res) {
			Alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
			      file, linenum, *res, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (idle > 65535) {
			Alert("parsing [%s:%d] : '%s' expects a timer value between 0 and 65535 ms.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.idle_timer = idle;
	}
	else if (!strcmp(args[0], "tune.rcvbuf.client")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.client_rcvbuf != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.client_rcvbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.rcvbuf.server")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.server_rcvbuf != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.server_rcvbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.sndbuf.client")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.client_sndbuf != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.client_sndbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.sndbuf.server")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.server_sndbuf != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.server_sndbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.pipesize")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.pipesize = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.http.cookielen")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.cookie_len = atol(args[1]) + 1;
	}
	else if (!strcmp(args[0], "tune.http.maxhdr")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.max_http_hdr = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.zlib.memlevel")) {
#ifdef USE_ZLIB
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*args[1]) {
			global.tune.zlibmemlevel = atoi(args[1]);
			if (global.tune.zlibmemlevel < 1 || global.tune.zlibmemlevel > 9) {
				Alert("parsing [%s:%d] : '%s' expects a numeric value between 1 and 9\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		} else {
			Alert("parsing [%s:%d] : '%s' expects a numeric value between 1 and 9\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
#else
		Alert("parsing [%s:%d] : '%s' is not implemented.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (!strcmp(args[0], "tune.zlib.windowsize")) {
#ifdef USE_ZLIB
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*args[1]) {
			global.tune.zlibwindowsize = atoi(args[1]);
			if (global.tune.zlibwindowsize < 8 || global.tune.zlibwindowsize > 15) {
				Alert("parsing [%s:%d] : '%s' expects a numeric value between 8 and 15\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		} else {
			Alert("parsing [%s:%d] : '%s' expects a numeric value between 8 and 15\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
#else
		Alert("parsing [%s:%d] : '%s' is not implemented.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (!strcmp(args[0], "tune.comp.maxlevel")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*args[1]) {
			global.tune.comp_maxlevel = atoi(args[1]);
			if (global.tune.comp_maxlevel < 1 || global.tune.comp_maxlevel > 9) {
				Alert("parsing [%s:%d] : '%s' expects a numeric value between 1 and 9\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		} else {
			Alert("parsing [%s:%d] : '%s' expects a numeric value between 1 and 9\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tune.pattern.cache-size")) {
		if (*args[1]) {
			global.tune.pattern_cache = atoi(args[1]);
			if (global.tune.pattern_cache < 0) {
				Alert("parsing [%s:%d] : '%s' expects a positive numeric value\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		} else {
			Alert("parsing [%s:%d] : '%s' expects a positive numeric value\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "uid")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.uid != 0) {
			Alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strl2irc(args[1], strlen(args[1]), &global.uid) != 0) {
			Warning("parsing [%s:%d] :  uid: string '%s' is not a number.\n   | You might want to use the 'user' parameter to use a system user name.\n", file, linenum, args[1]);
			err_code |= ERR_WARN;
			goto out;
		}

	}
	else if (!strcmp(args[0], "gid")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.gid != 0) {
			Alert("parsing [%s:%d] : group/gid already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strl2irc(args[1], strlen(args[1]), &global.gid) != 0) {
			Warning("parsing [%s:%d] :  gid: string '%s' is not a number.\n   | You might want to use the 'group' parameter to use a system group name.\n", file, linenum, args[1]);
			err_code |= ERR_WARN;
			goto out;
		}
	}
	else if (!strcmp(args[0], "external-check")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.external_check = 1;
	}
	/* user/group name handling */
	else if (!strcmp(args[0], "user")) {
		struct passwd *ha_user;
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.uid != 0) {
			Alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		errno = 0;
		ha_user = getpwnam(args[1]);
		if (ha_user != NULL) {
			global.uid = (int)ha_user->pw_uid;
		}
		else {
			Alert("parsing [%s:%d] : cannot find user id for '%s' (%d:%s)\n", file, linenum, args[1], errno, strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (!strcmp(args[0], "group")) {
		struct group *ha_group;
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.gid != 0) {
			Alert("parsing [%s:%d] : gid/group was already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		errno = 0;
		ha_group = getgrnam(args[1]);
		if (ha_group != NULL) {
			global.gid = (int)ha_group->gr_gid;
		}
		else {
			Alert("parsing [%s:%d] : cannot find group id for '%s' (%d:%s)\n", file, linenum, args[1], errno, strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	/* end of user/group name handling*/
	else if (!strcmp(args[0], "nbproc")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.nbproc = atol(args[1]);
		if (global.nbproc < 1 || global.nbproc > LONGBITS) {
			Alert("parsing [%s:%d] : '%s' must be between 1 and %d (was %d).\n",
			      file, linenum, args[0], LONGBITS, global.nbproc);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "maxconn")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.maxconn != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxconn = atol(args[1]);
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > DEFAULT_MAXCONN && cfg_maxconn <= DEFAULT_MAXCONN) {
			Alert("parsing [%s:%d] : maxconn value %d too high for this system.\nLimiting to %d. Please use '-n' to force the value.\n", file, linenum, global.maxconn, DEFAULT_MAXCONN);
			global.maxconn = DEFAULT_MAXCONN;
			err_code |= ERR_ALERT;
		}
#endif /* SYSTEM_MAXCONN */
	}
	else if (!strcmp(args[0], "maxsslconn")) {
#ifdef USE_OPENSSL
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxsslconn = atol(args[1]);
#else
		Alert("parsing [%s:%d] : '%s' is not implemented.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (!strcmp(args[0], "ssl-default-bind-ciphers")) {
#ifdef USE_OPENSSL
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a cipher suite as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(global.listen_default_ciphers);
		global.listen_default_ciphers = strdup(args[1]);
#else
		Alert("parsing [%s:%d] : '%s' is not implemented.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (!strcmp(args[0], "ssl-default-server-ciphers")) {
#ifdef USE_OPENSSL
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a cipher suite as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(global.connect_default_ciphers);
		global.connect_default_ciphers = strdup(args[1]);
#else
		Alert("parsing [%s:%d] : '%s' is not implemented.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
#ifdef USE_OPENSSL
#ifndef OPENSSL_NO_DH
	else if (!strcmp(args[0], "ssl-dh-param-file")) {
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a file path as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (ssl_sock_load_global_dh_param_from_file(args[1])) {
			Alert("parsing [%s:%d] : '%s': unable to load DH parameters from file <%s>.\n", file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
#endif
#endif
	else if (!strcmp(args[0], "ssl-server-verify")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strcmp(args[1],"none") == 0)
			global.ssl_server_verify = SSL_SERVER_VERIFY_NONE;
		else if (strcmp(args[1],"required") == 0)
			global.ssl_server_verify = SSL_SERVER_VERIFY_REQUIRED;
		else {
			Alert("parsing [%s:%d] : '%s' expects 'none' or 'required' as argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
	                goto out;
		}
	}
	else if (!strcmp(args[0], "maxconnrate")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.cps_lim != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.cps_lim = atol(args[1]);
	}
	else if (!strcmp(args[0], "maxsessrate")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.sps_lim != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.sps_lim = atol(args[1]);
	}
	else if (!strcmp(args[0], "maxsslrate")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.ssl_lim != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.ssl_lim = atol(args[1]);
	}
	else if (!strcmp(args[0], "maxcomprate")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument in kb/s.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.comp_rate_lim = atoi(args[1]) * 1024;
	}
	else if (!strcmp(args[0], "maxpipes")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.maxpipes != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxpipes = atol(args[1]);
	}
	else if (!strcmp(args[0], "maxzlibmem")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxzlibmem = atol(args[1]) * 1024L * 1024L;
	}
	else if (!strcmp(args[0], "maxcompcpuusage")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument between 0 and 100.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		compress_min_idle = 100 - atoi(args[1]);
		if (compress_min_idle > 100) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument between 0 and 100.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}

	else if (!strcmp(args[0], "ulimit-n")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.rlimit_nofile != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.rlimit_nofile = atol(args[1]);
	}
	else if (!strcmp(args[0], "chroot")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.chroot != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a directory as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.chroot = strdup(args[1]);
	}
	else if (!strcmp(args[0], "description")) {
		int i, len=0;
		char *d;

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects a string argument.\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (i = 1; *args[i]; i++)
			len += strlen(args[i]) + 1;

		if (global.desc)
			free(global.desc);

		global.desc = d = calloc(1, len);

		d += snprintf(d, global.desc + len - d, "%s", args[1]);
		for (i = 2; *args[i]; i++)
			d += snprintf(d, global.desc + len - d, " %s", args[i]);
	}
	else if (!strcmp(args[0], "node")) {
		int i;
		char c;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		for (i=0; args[1][i]; i++) {
			c = args[1][i];
			if (!isupper((unsigned char)c) && !islower((unsigned char)c) &&
			    !isdigit((unsigned char)c) && c != '_' && c != '-' && c != '.')
				break;
		}

		if (!i || args[1][i]) {
			Alert("parsing [%s:%d]: '%s' requires valid node name - non-empty string"
				" with digits(0-9), letters(A-Z, a-z), dot(.), hyphen(-) or underscode(_).\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (global.node)
			free(global.node);

		global.node = strdup(args[1]);
	}
	else if (!strcmp(args[0], "pidfile")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.pidfile != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a file name as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.pidfile = strdup(args[1]);
	}
	else if (!strcmp(args[0], "unix-bind")) {
		int cur_arg = 1;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "prefix")) {
				if (global.unix_bind.prefix != NULL) {
					Alert("parsing [%s:%d] : unix-bind '%s' already specified. Continuing.\n", file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT;
					cur_arg += 2;
					continue;
				}

				if (*(args[cur_arg+1]) == 0) {
		                        Alert("parsing [%s:%d] : unix_bind '%s' expects a path as an argument.\n", file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				global.unix_bind.prefix =  strdup(args[cur_arg+1]);
				cur_arg += 2;
				continue;
			}

			if (!strcmp(args[cur_arg], "mode")) {

				global.unix_bind.ux.mode = strtol(args[cur_arg + 1], NULL, 8);
                                cur_arg += 2;
				continue;
			}

			if (!strcmp(args[cur_arg], "uid")) {

				global.unix_bind.ux.uid = atol(args[cur_arg + 1 ]);
                                cur_arg += 2;
				continue;
                        }

			if (!strcmp(args[cur_arg], "gid")) {

				global.unix_bind.ux.gid = atol(args[cur_arg + 1 ]);
                                cur_arg += 2;
				continue;
                        }

			if (!strcmp(args[cur_arg], "user")) {
				struct passwd *user;

				user = getpwnam(args[cur_arg + 1]);
				if (!user) {
					Alert("parsing [%s:%d] : '%s' : '%s' unknown user.\n",
						file, linenum, args[0], args[cur_arg + 1 ]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				global.unix_bind.ux.uid = user->pw_uid;
				cur_arg += 2;
				continue;
                        }

			if (!strcmp(args[cur_arg], "group")) {
				struct group *group;

				group = getgrnam(args[cur_arg + 1]);
				if (!group) {
					Alert("parsing [%s:%d] : '%s' : '%s' unknown group.\n",
						file, linenum, args[0], args[cur_arg + 1 ]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				global.unix_bind.ux.gid = group->gr_gid;
				cur_arg += 2;
				continue;
			}

			Alert("parsing [%s:%d] : '%s' only supports the 'prefix', 'mode', 'uid', 'gid', 'user' and 'group' options.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }
	}
	else if (!strcmp(args[0], "log") && kwm == KWM_NO) { /* no log */
		/* delete previous herited or defined syslog servers */
		struct logsrv *back;
		struct logsrv *tmp;

		if (*(args[1]) != 0) {
			Alert("parsing [%s:%d]:%s : 'no log' does not expect arguments.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		list_for_each_entry_safe(tmp, back, &global.logsrvs, list) {
			LIST_DEL(&tmp->list);
			free(tmp);
		}
	}
	else if (!strcmp(args[0], "log")) {  /* syslog server address */
		struct sockaddr_storage *sk;
		int port1, port2;
		struct logsrv *logsrv;
		int arg = 0;
		int len = 0;

		if (alertif_too_many_args(8, file, linenum, args, &err_code)) /* does not strictly check optional arguments */
			goto out;

		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <address> and <facility> as arguments.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		logsrv = calloc(1, sizeof(*logsrv));

		/* just after the address, a length may be specified */
		if (strcmp(args[arg+2], "len") == 0) {
			len = atoi(args[arg+3]);
			if (len < 80 || len > 65535) {
				Alert("parsing [%s:%d] : invalid log length '%s', must be between 80 and 65535.\n",
				      file, linenum, args[arg+3]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			logsrv->maxlen = len;

			/* skip these two args */
			arg += 2;
		}
		else
			logsrv->maxlen = MAX_SYSLOG_LEN;

		if (logsrv->maxlen > global.max_syslog_len) {
			global.max_syslog_len = logsrv->maxlen;
			logheader = realloc(logheader, global.max_syslog_len + 1);
			logheader_rfc5424 = realloc(logheader_rfc5424, global.max_syslog_len + 1);
			logline = realloc(logline, global.max_syslog_len + 1);
			logline_rfc5424 = realloc(logline_rfc5424, global.max_syslog_len + 1);
		}

		/* after the length, a format may be specified */
		if (strcmp(args[arg+2], "format") == 0) {
			logsrv->format = get_log_format(args[arg+3]);
			if (logsrv->format < 0) {
				Alert("parsing [%s:%d] : unknown log format '%s'\n", file, linenum, args[arg+3]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* skip these two args */
			arg += 2;
		}

		if (alertif_too_many_args_idx(3, arg + 1, file, linenum, args, &err_code)) {
			free(logsrv);
			goto out;
		}

		logsrv->facility = get_log_facility(args[arg+2]);
		if (logsrv->facility < 0) {
			Alert("parsing [%s:%d] : unknown log facility '%s'\n", file, linenum, args[arg+2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			logsrv->facility = 0;
		}

		logsrv->level = 7; /* max syslog level = debug */
		if (*(args[arg+3])) {
			logsrv->level = get_log_level(args[arg+3]);
			if (logsrv->level < 0) {
				Alert("parsing [%s:%d] : unknown optional log level '%s'\n", file, linenum, args[arg+3]);
				err_code |= ERR_ALERT | ERR_FATAL;
				logsrv->level = 0;
			}
		}

		logsrv->minlvl = 0; /* limit syslog level to this level (emerg) */
		if (*(args[arg+4])) {
			logsrv->minlvl = get_log_level(args[arg+4]);
			if (logsrv->minlvl < 0) {
				Alert("parsing [%s:%d] : unknown optional minimum log level '%s'\n", file, linenum, args[arg+4]);
				err_code |= ERR_ALERT | ERR_FATAL;
				logsrv->minlvl = 0;
			}
		}

		sk = str2sa_range(args[1], &port1, &port2, &errmsg, NULL, NULL, 1);
		if (!sk) {
			Alert("parsing [%s:%d] : '%s': %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			free(logsrv);
			goto out;
		}
		logsrv->addr = *sk;

		if (sk->ss_family == AF_INET || sk->ss_family == AF_INET6) {
			if (port1 != port2) {
				Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(logsrv);
				goto out;
			}

			logsrv->addr = *sk;
			if (!port1)
				set_host_port(&logsrv->addr, SYSLOG_PORT);
		}

		LIST_ADDQ(&global.logsrvs, &logsrv->list);
	}
	else if (!strcmp(args[0], "log-send-hostname")) { /* set the hostname in syslog header */
		char *name;

		if (global.log_send_hostname != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		if (*(args[1]))
			name = args[1];
		else
			name = hostname;

		free(global.log_send_hostname);
		global.log_send_hostname = strdup(name);
	}
	else if (!strcmp(args[0], "server-state-base")) { /* path base where HAProxy can find server state files */
		if (global.server_state_base != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		if (!*(args[1])) {
			Alert("parsing [%s:%d] : '%s' expects one argument: a directory path.\n", file, linenum, args[0]);
			err_code |= ERR_FATAL;
			goto out;
		}

		global.server_state_base = strdup(args[1]);
	}
	else if (!strcmp(args[0], "server-state-file")) { /* path to the file where HAProxy can load the server states */
		if (global.server_state_file != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		if (!*(args[1])) {
			Alert("parsing [%s:%d] : '%s' expect one argument: a file path.\n", file, linenum, args[0]);
			err_code |= ERR_FATAL;
			goto out;
		}

		global.server_state_file = strdup(args[1]);
	}
	else if (!strcmp(args[0], "log-tag")) {  /* tag to report to syslog */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a tag for use in syslog.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_destroy(&global.log_tag);
		chunk_initstr(&global.log_tag, strdup(args[1]));
	}
	else if (!strcmp(args[0], "spread-checks")) {  /* random time between checks (0-50) */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.spread_checks != 0) {
			Alert("parsing [%s:%d]: spread-checks already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d]: '%s' expects an integer argument (0..50).\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.spread_checks = atol(args[1]);
		if (global.spread_checks < 0 || global.spread_checks > 50) {
			Alert("parsing [%s:%d]: 'spread-checks' needs a positive value in range 0..50.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (!strcmp(args[0], "max-spread-checks")) {  /* maximum time between first and last check */
		const char *err;
		unsigned int val;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d]: '%s' expects an integer argument (0..50).\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = parse_time_err(args[1], &val, TIME_UNIT_MS);
		if (err) {
			Alert("parsing [%s:%d]: unsupported character '%c' in '%s' (wants an integer delay).\n", file, linenum, *err, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		global.max_spread_checks = val;
		if (global.max_spread_checks < 0) {
			Alert("parsing [%s:%d]: '%s' needs a positive delay in milliseconds.\n",file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (strcmp(args[0], "cpu-map") == 0) {  /* map a process list to a CPU set */
#ifdef USE_CPU_AFFINITY
		int cur_arg, i;
		unsigned long proc = 0;
		unsigned long cpus = 0;

		if (strcmp(args[1], "all") == 0)
			proc = ~0UL;
		else if (strcmp(args[1], "odd") == 0)
			proc = ~0UL/3UL; /* 0x555....555 */
		else if (strcmp(args[1], "even") == 0)
			proc = (~0UL/3UL) << 1; /* 0xAAA...AAA */
		else {
			proc = atol(args[1]);
			if (proc >= 1 && proc <= LONGBITS)
				proc = 1UL << (proc - 1);
		}

		if (!proc || !*args[2]) {
			Alert("parsing [%s:%d]: %s expects a process number including 'all', 'odd', 'even', or a number from 1 to %d, followed by a list of CPU ranges with numbers from 0 to %d.\n",
			      file, linenum, args[0], LONGBITS, LONGBITS - 1);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		cur_arg = 2;
		while (*args[cur_arg]) {
			unsigned int low, high;

			if (isdigit((int)*args[cur_arg])) {
				char *dash = strchr(args[cur_arg], '-');

				low = high = str2uic(args[cur_arg]);
				if (dash)
					high = str2uic(dash + 1);

				if (high < low) {
					unsigned int swap = low;
					low = high;
					high = swap;
				}

				if (high >= LONGBITS) {
					Alert("parsing [%s:%d]: %s supports CPU numbers from 0 to %d.\n",
					      file, linenum, args[0], LONGBITS - 1);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				while (low <= high)
					cpus |= 1UL << low++;
			}
			else {
				Alert("parsing [%s:%d]: %s : '%s' is not a CPU range.\n",
				      file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg++;
		}
		for (i = 0; i < LONGBITS; i++)
			if (proc & (1UL << i))
				global.cpu_map[i] = cpus;
#else
		Alert("parsing [%s:%d] : '%s' is not enabled, please check build options for USE_CPU_AFFINITY.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif
	}
	else if (strcmp(args[0], "setenv") == 0 || strcmp(args[0], "presetenv") == 0) {
		if (alertif_too_many_args(3, file, linenum, args, &err_code))
			goto out;

		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d]: '%s' expects a name and a value.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* "setenv" overwrites, "presetenv" only sets if not yet set */
		if (setenv(args[1], args[2], (args[0][0] == 's')) != 0) {
			Alert("parsing [%s:%d]: '%s' failed on variable '%s' : %s.\n", file, linenum, args[0], args[1], strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "unsetenv")) {
		int arg;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d]: '%s' expects at least one variable name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (arg = 1; *args[arg]; arg++) {
			if (unsetenv(args[arg]) != 0) {
				Alert("parsing [%s:%d]: '%s' failed on variable '%s' : %s.\n", file, linenum, args[0], args[arg], strerror(errno));
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
	}
	else if (!strcmp(args[0], "resetenv")) {
		extern char **environ;
		char **env = environ;

		/* args contain variable names to keep, one per argument */
		while (*env) {
			int arg;

			/* look for current variable in among all those we want to keep */
			for (arg = 1; *args[arg]; arg++) {
				if (strncmp(*env, args[arg], strlen(args[arg])) == 0 &&
				    (*env)[strlen(args[arg])] == '=')
					break;
			}

			/* delete this variable */
			if (!*args[arg]) {
				char *delim = strchr(*env, '=');

				if (!delim || delim - *env >= trash.size) {
					Alert("parsing [%s:%d]: '%s' failed to unset invalid variable '%s'.\n", file, linenum, args[0], *env);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				memcpy(trash.str, *env, delim - *env);
				trash.str[delim - *env] = 0;

				if (unsetenv(trash.str) != 0) {
					Alert("parsing [%s:%d]: '%s' failed to unset variable '%s' : %s.\n", file, linenum, args[0], *env, strerror(errno));
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			else
				env++;
		}
	}
	else {
		struct cfg_kw_list *kwl;
		int index;
		int rc;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_GLOBAL)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
					rc = kwl->kw[index].parse(args, CFG_GLOBAL, NULL, NULL, file, linenum, &errmsg);
					if (rc < 0) {
						Alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
					}
					else if (rc > 0) {
						Warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_WARN;
						goto out;
					}
					goto out;
				}
			}
		}
		
		Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "global");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

 out:
	free(errmsg);
	return err_code;
}

void init_default_instance()
{
	init_new_proxy(&defproxy);
	defproxy.mode = PR_MODE_TCP;
	defproxy.state = PR_STNEW;
	defproxy.maxconn = cfg_maxpconn;
	defproxy.conn_retries = CONN_RETRIES;
	defproxy.redispatch_after = 0;

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
	defproxy.defsrv.slowstart = 0;
	defproxy.defsrv.onerror = DEF_HANA_ONERR;
	defproxy.defsrv.consecutive_errors_limit = DEF_HANA_ERRLIMIT;
	defproxy.defsrv.uweight = defproxy.defsrv.iweight = 1;

	defproxy.email_alert.level = LOG_ALERT;
	defproxy.load_server_state_from_file = PR_SRV_STATE_FILE_UNSPEC;
}


/* This function createss a new req* or rsp* rule to the proxy. It compiles the
 * regex and may return the ERR_WARN bit, and error bits such as ERR_ALERT and
 * ERR_FATAL in case of error.
 */
static int create_cond_regex_rule(const char *file, int line,
				  struct proxy *px, int dir, int action, int flags,
				  const char *cmd, const char *reg, const char *repl,
				  const char **cond_start)
{
	struct my_regex *preg = NULL;
	char *errmsg = NULL;
	const char *err;
	char *error;
	int ret_code = 0;
	struct acl_cond *cond = NULL;
	int cs;
	int cap;

	if (px == &defproxy) {
		Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, line, cmd);
		ret_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	if (*reg == 0) {
		Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, line, cmd);
		ret_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	if (warnifnotcap(px, PR_CAP_RS, file, line, cmd, NULL))
		ret_code |= ERR_WARN;

	if (cond_start &&
	    (strcmp(*cond_start, "if") == 0 || strcmp(*cond_start, "unless") == 0)) {
		if ((cond = build_acl_cond(file, line, px, cond_start, &errmsg)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing a '%s' condition : %s.\n",
			      file, line, cmd, errmsg);
			ret_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
	else if (cond_start && **cond_start) {
		Alert("parsing [%s:%d] : '%s' : Expecting nothing, 'if', or 'unless', got '%s'.\n",
		      file, line, cmd, *cond_start);
		ret_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	ret_code |= warnif_cond_conflicts(cond,
	                                  (dir == SMP_OPT_DIR_REQ) ?
	                                  ((px->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR) :
	                                  ((px->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR),
	                                  file, line);

	preg = calloc(1, sizeof(*preg));
	if (!preg) {
		Alert("parsing [%s:%d] : '%s' : not enough memory to build regex.\n", file, line, cmd);
		ret_code = ERR_ALERT | ERR_FATAL;
		goto err;
	}

	cs = !(flags & REG_ICASE);
	cap = !(flags & REG_NOSUB);
	error = NULL;
	if (!regex_comp(reg, preg, cs, cap, &error)) {
		Alert("parsing [%s:%d] : '%s' : regular expression '%s' : %s\n", file, line, cmd, reg, error);
		free(error);
		ret_code = ERR_ALERT | ERR_FATAL;
		goto err;
	}

	err = chain_regex((dir == SMP_OPT_DIR_REQ) ? &px->req_exp : &px->rsp_exp,
			  preg, action, repl ? strdup(repl) : NULL, cond);
	if (repl && err) {
		Alert("parsing [%s:%d] : '%s' : invalid character or unterminated sequence in replacement string near '%c'.\n",
		      file, line, cmd, *err);
		ret_code |= ERR_ALERT | ERR_FATAL;
		goto err_free;
	}

	if (dir == SMP_OPT_DIR_REQ && warnif_misplaced_reqxxx(px, file, line, cmd))
		ret_code |= ERR_WARN;

	return ret_code;

 err_free:
	regex_free(preg);
 err:
	free(preg);
	free(errmsg);
	return ret_code;
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

	if (strcmp(args[0], "peers") == 0) { /* new peers section */
		if (!*args[1]) {
			Alert("parsing [%s:%d] : missing name for peers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
			      file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		for (curpeers = peers; curpeers != NULL; curpeers = curpeers->next) {
			/*
			 * If there are two proxies with the same name only following
			 * combinations are allowed:
			 */
			if (strcmp(curpeers->id, args[1]) == 0) {
				Alert("Parsing [%s:%d]: peers section '%s' has the same name as another peers section declared at %s:%d.\n",
					file, linenum, args[1], curpeers->conf.file, curpeers->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((curpeers = calloc(1, sizeof(*curpeers))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curpeers->next = peers;
		peers = curpeers;
		curpeers->conf.file = strdup(file);
		curpeers->conf.line = linenum;
		curpeers->last_change = now.tv_sec;
		curpeers->id = strdup(args[1]);
		curpeers->state = PR_STNEW;
	}
	else if (strcmp(args[0], "peer") == 0) { /* peer definition */
		struct sockaddr_storage *sk;
		int port1, port2;
		struct protocol *proto;

		if (!*args[2]) {
			Alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
			      file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((newpeer = calloc(1, sizeof(*newpeer))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* the peers are linked backwards first */
		curpeers->count++;
		newpeer->next = curpeers->remote;
		curpeers->remote = newpeer;
		newpeer->conf.file = strdup(file);
		newpeer->conf.line = linenum;

		newpeer->last_change = now.tv_sec;
		newpeer->id = strdup(args[1]);

		sk = str2sa_range(args[2], &port1, &port2, &errmsg, NULL, NULL, 1);
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

		if (port1 != port2) {
			Alert("parsing [%s:%d] : '%s %s' : port ranges and offsets are not allowed in '%s'\n",
			      file, linenum, args[0], args[1], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!port1) {
			Alert("parsing [%s:%d] : '%s %s' : missing or invalid port in '%s'\n",
			      file, linenum, args[0], args[1], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		newpeer->addr = *sk;
		newpeer->proto = proto;
		newpeer->xprt  = &raw_sock;
		newpeer->sock_init_arg = NULL;

		if (strcmp(newpeer->id, localpeer) == 0) {
			/* Current is local peer, it define a frontend */
			newpeer->local = 1;
			peers->local = newpeer;

			if (!curpeers->peers_fe) {
				if ((curpeers->peers_fe  = calloc(1, sizeof(struct proxy))) == NULL) {
					Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}

				init_new_proxy(curpeers->peers_fe);
				curpeers->peers_fe->parent = curpeers;
				curpeers->peers_fe->id = strdup(args[1]);
				curpeers->peers_fe->conf.args.file = curpeers->peers_fe->conf.file = strdup(file);
				curpeers->peers_fe->conf.args.line = curpeers->peers_fe->conf.line = linenum;
				peers_setup_frontend(curpeers->peers_fe);

				bind_conf = bind_conf_alloc(&curpeers->peers_fe->conf.bind, file, linenum, args[2]);

				if (!str2listener(args[2], curpeers->peers_fe, bind_conf, file, linenum, &errmsg)) {
					if (errmsg && *errmsg) {
						indent_msg(&errmsg, 2);
						Alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
					}
					else
						Alert("parsing [%s:%d] : '%s %s' : error encountered while parsing listening address %s.\n",
						      file, linenum, args[0], args[1], args[2]);
					err_code |= ERR_FATAL;
					goto out;
				}

				list_for_each_entry(l, &bind_conf->listeners, by_bind) {
					l->maxaccept = 1;
					l->maxconn = curpeers->peers_fe->maxconn;
					l->backlog = curpeers->peers_fe->backlog;
					l->accept = session_accept_fd;
					l->handler = process_stream;
					l->analysers |=  curpeers->peers_fe->fe_req_ana;
					l->default_target = curpeers->peers_fe->default_target;
					l->options |= LI_O_UNLIMITED; /* don't make the peers subject to global limits */
					global.maxsock += l->maxconn;
				}
			}
			else {
				Alert("parsing [%s:%d] : '%s %s' : local peer name already referenced at %s:%d.\n",
				      file, linenum, args[0], args[1],
				      curpeers->peers_fe->conf.file, curpeers->peers_fe->conf.line);
				err_code |= ERR_FATAL;
				goto out;
			}
		}
	} /* neither "peer" nor "peers" */
	else if (!strcmp(args[0], "disabled")) {  /* disables this peers section */
		curpeers->state = PR_STSTOPPED;
	}
	else if (!strcmp(args[0], "enabled")) {  /* enables this peers section (used to revert a disabled default) */
		curpeers->state = PR_STNEW;
	}
	else if (*args[0] != 0) {
		Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
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
	struct dns_nameserver *newnameserver = NULL;
	const char *err;
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "resolvers") == 0) { /* new resolvers section */
		if (!*args[1]) {
			Alert("parsing [%s:%d] : missing name for resolvers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		list_for_each_entry(curr_resolvers, &dns_resolvers, list) {
			/* Error if two resolvers owns the same name */
			if (strcmp(curr_resolvers->id, args[1]) == 0) {
				Alert("Parsing [%s:%d]: resolvers '%s' has same name as another resolvers (declared at %s:%d).\n",
					file, linenum, args[1], curr_resolvers->conf.file, curr_resolvers->conf.line);
				err_code |= ERR_ALERT | ERR_ABORT;
			}
		}

		if ((curr_resolvers = calloc(1, sizeof(*curr_resolvers))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* default values */
		LIST_ADDQ(&dns_resolvers, &curr_resolvers->list);
		curr_resolvers->conf.file = strdup(file);
		curr_resolvers->conf.line = linenum;
		curr_resolvers->id = strdup(args[1]);
		curr_resolvers->query_ids = EB_ROOT;
		/* default hold period for valid is 10s */
		curr_resolvers->hold.valid = 10000;
		curr_resolvers->timeout.retry = 1000;
		curr_resolvers->resolve_retries = 3;
		LIST_INIT(&curr_resolvers->nameserver_list);
		LIST_INIT(&curr_resolvers->curr_resolution);
	}
	else if (strcmp(args[0], "nameserver") == 0) { /* nameserver definition */
		struct sockaddr_storage *sk;
		int port1, port2;
		struct protocol *proto;

		if (!*args[2]) {
			Alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
				file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		list_for_each_entry(newnameserver, &curr_resolvers->nameserver_list, list) {
			/* Error if two resolvers owns the same name */
			if (strcmp(newnameserver->id, args[1]) == 0) {
				Alert("Parsing [%s:%d]: nameserver '%s' has same name as another nameserver (declared at %s:%d).\n",
					file, linenum, args[1], curr_resolvers->conf.file, curr_resolvers->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((newnameserver = calloc(1, sizeof(*newnameserver))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* the nameservers are linked backward first */
		LIST_ADDQ(&curr_resolvers->nameserver_list, &newnameserver->list);
		curr_resolvers->count_nameservers++;
		newnameserver->resolvers = curr_resolvers;
		newnameserver->conf.file = strdup(file);
		newnameserver->conf.line = linenum;
		newnameserver->id = strdup(args[1]);

		sk = str2sa_range(args[2], &port1, &port2, &errmsg, NULL, NULL, 1);
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

		if (port1 != port2) {
			Alert("parsing [%s:%d] : '%s %s' : port ranges and offsets are not allowed in '%s'\n",
				file, linenum, args[0], args[1], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!port1 && !port2) {
			Alert("parsing [%s:%d] : '%s %s' : no UDP port specified\n",
				file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		newnameserver->addr = *sk;
	}
	else if (strcmp(args[0], "hold") == 0) { /* hold periods */
		const char *res;
		unsigned int time;

		if (!*args[2]) {
			Alert("parsing [%s:%d] : '%s' expects an <event> and a <time> as arguments.\n",
				file, linenum, args[0]);
			Alert("<event> can be either 'valid', 'nx', 'refused', 'timeout', or 'other'\n");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		res = parse_time_err(args[2], &time, TIME_UNIT_MS);
		if (res) {
			Alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
				file, linenum, *res, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strcmp(args[1], "valid") == 0)
			curr_resolvers->hold.valid = time;
		else {
			Alert("parsing [%s:%d] : '%s' unknown <event>: '%s', expects 'valid'\n",
			file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

	}
	else if (strcmp(args[0], "resolve_retries") == 0) {
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects <nb> as argument.\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curr_resolvers->resolve_retries = atoi(args[1]);
	}
	else if (strcmp(args[0], "timeout") == 0) {
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects 'retry' and <time> as arguments.\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (strcmp(args[1], "retry") == 0) {
			const char *res;
			unsigned int timeout_retry;

			if (!*args[2]) {
				Alert("parsing [%s:%d] : '%s %s' expects <time> as argument.\n",
					file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			res = parse_time_err(args[2], &timeout_retry, TIME_UNIT_MS);
			if (res) {
				Alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s %s>.\n",
					file, linenum, *res, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			curr_resolvers->timeout.retry = timeout_retry;
		}
		else {
			Alert("parsing [%s:%d] : '%s' expects 'retry' and <time> as arguments got '%s'.\n",
				file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	} /* neither "nameserver" nor "resolvers" */
	else if (*args[0] != 0) {
		Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
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
			Alert("parsing [%s:%d] : missing name for mailers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
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
				Alert("Parsing [%s:%d]: mailers section '%s' has the same name as another mailers section declared at %s:%d.\n",
					file, linenum, args[1], curmailers->conf.file, curmailers->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((curmailers = calloc(1, sizeof(*curmailers))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
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
			Alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
			      file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((newmailer = calloc(1, sizeof(*newmailer))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
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

		sk = str2sa_range(args[2], &port1, &port2, &errmsg, NULL, NULL, 1);
		if (!sk) {
			Alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		proto = protocol_by_family(sk->ss_family);
		if (!proto || !proto->connect || proto->sock_prot != IPPROTO_TCP) {
			Alert("parsing [%s:%d] : '%s %s' : TCP not supported for this address family.\n",
			      file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (port1 != port2) {
			Alert("parsing [%s:%d] : '%s %s' : port ranges and offsets are not allowed in '%s'\n",
			      file, linenum, args[0], args[1], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!port1) {
			Alert("parsing [%s:%d] : '%s %s' : missing or invalid port in '%s'\n",
			      file, linenum, args[0], args[1], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		newmailer->addr = *sk;
		newmailer->proto = proto;
		newmailer->xprt  = &raw_sock;
		newmailer->sock_init_arg = NULL;
	}
	else if (strcmp(args[0], "timeout") == 0) {
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects 'mail' and <time> as arguments.\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (strcmp(args[1], "mail") == 0) {
			const char *res;
			unsigned int timeout_mail;
			if (!*args[2]) {
				Alert("parsing [%s:%d] : '%s %s' expects <time> as argument.\n",
					file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			res = parse_time_err(args[2], &timeout_mail, TIME_UNIT_MS);
			if (res) {
				Alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
					file, linenum, *res, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (timeout_mail <= 0) {
				Alert("parsing [%s:%d] : '%s %s' expects a positive <time> argument.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			curmailers->timeout.mail = timeout_mail;
		} else {
			Alert("parsing [%s:%d] : '%s' expects 'mail' and <time> as arguments got '%s'.\n",
				file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (*args[0] != 0) {
		Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

out:
	free(errmsg);
	return err_code;
}

static void free_email_alert(struct proxy *p)
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

int cfg_parse_listen(const char *file, int linenum, char **args, int kwm)
{
	static struct proxy *curproxy = NULL;
	const char *err;
	char *error;
	int rc;
	unsigned val;
	int err_code = 0;
	struct acl_cond *cond = NULL;
	struct logsrv *tmplogsrv;
	char *errmsg = NULL;
	struct bind_conf *bind_conf;

	if (!strcmp(args[0], "listen"))
		rc = PR_CAP_LISTEN;
 	else if (!strcmp(args[0], "frontend"))
		rc = PR_CAP_FE | PR_CAP_RS;
	else if (!strcmp(args[0], "backend"))
		rc = PR_CAP_BE | PR_CAP_RS;
	else
		rc = PR_CAP_NONE;

	if (rc != PR_CAP_NONE) {  /* new proxy */
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects an <id> argument and\n"
			      "  optionnally supports [addr1]:port1[-end1]{,[addr]:port[-end]}...\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
			      file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		curproxy = (rc & PR_CAP_FE) ? proxy_fe_by_name(args[1]) : proxy_be_by_name(args[1]);
		if (curproxy) {
			Alert("Parsing [%s:%d]: %s '%s' has the same name as %s '%s' declared at %s:%d.\n",
			      file, linenum, proxy_cap_str(rc), args[1], proxy_type_str(curproxy),
			      curproxy->id, curproxy->conf.file, curproxy->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
		}

		if ((curproxy = calloc(1, sizeof(*curproxy))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		init_new_proxy(curproxy);
		curproxy->next = proxy;
		proxy = curproxy;
		curproxy->conf.args.file = curproxy->conf.file = strdup(file);
		curproxy->conf.args.line = curproxy->conf.line = linenum;
		curproxy->last_change = now.tv_sec;
		curproxy->id = strdup(args[1]);
		curproxy->cap = rc;
		proxy_store_name(curproxy);

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			if (curproxy->cap & PR_CAP_FE)
				Alert("parsing [%s:%d] : please use the 'bind' keyword for listening addresses.\n", file, linenum);
			goto out;
		}

		/* set default values */
		memcpy(&curproxy->defsrv, &defproxy.defsrv, sizeof(curproxy->defsrv));
		curproxy->defsrv.id = "default-server";

		curproxy->state = defproxy.state;
		curproxy->options = defproxy.options;
		curproxy->options2 = defproxy.options2;
		curproxy->no_options = defproxy.no_options;
		curproxy->no_options2 = defproxy.no_options2;
		curproxy->bind_proc = defproxy.bind_proc;
		curproxy->except_net = defproxy.except_net;
		curproxy->except_mask = defproxy.except_mask;
		curproxy->except_to = defproxy.except_to;
		curproxy->except_mask_to = defproxy.except_mask_to;

		if (defproxy.fwdfor_hdr_len) {
			curproxy->fwdfor_hdr_len  = defproxy.fwdfor_hdr_len;
			curproxy->fwdfor_hdr_name = strdup(defproxy.fwdfor_hdr_name);
		}

		if (defproxy.orgto_hdr_len) {
			curproxy->orgto_hdr_len  = defproxy.orgto_hdr_len;
			curproxy->orgto_hdr_name = strdup(defproxy.orgto_hdr_name);
		}

		if (defproxy.server_id_hdr_len) {
			curproxy->server_id_hdr_len  = defproxy.server_id_hdr_len;
			curproxy->server_id_hdr_name = strdup(defproxy.server_id_hdr_name);
		}

		if (curproxy->cap & PR_CAP_FE) {
			curproxy->maxconn = defproxy.maxconn;
			curproxy->backlog = defproxy.backlog;
			curproxy->fe_sps_lim = defproxy.fe_sps_lim;

			/* initialize error relocations */
			for (rc = 0; rc < HTTP_ERR_SIZE; rc++)
				chunk_dup(&curproxy->errmsg[rc], &defproxy.errmsg[rc]);

			curproxy->to_log = defproxy.to_log & ~LW_COOKIE & ~LW_REQHDR & ~ LW_RSPHDR;
		}

		if (curproxy->cap & PR_CAP_BE) {
			curproxy->lbprm.algo = defproxy.lbprm.algo;
			curproxy->fullconn = defproxy.fullconn;
			curproxy->conn_retries = defproxy.conn_retries;
			curproxy->redispatch_after = defproxy.redispatch_after;
			curproxy->max_ka_queue = defproxy.max_ka_queue;

			if (defproxy.check_req) {
				curproxy->check_req = calloc(1, defproxy.check_len);
				memcpy(curproxy->check_req, defproxy.check_req, defproxy.check_len);
			}
			curproxy->check_len = defproxy.check_len;

			if (defproxy.expect_str) {
				curproxy->expect_str = strdup(defproxy.expect_str);
				if (defproxy.expect_regex) {
					/* note: this regex is known to be valid */
					curproxy->expect_regex = calloc(1, sizeof(*curproxy->expect_regex));
					regex_comp(defproxy.expect_str, curproxy->expect_regex, 1, 1, NULL);
				}
			}

			curproxy->ck_opts = defproxy.ck_opts;
			if (defproxy.cookie_name)
				curproxy->cookie_name = strdup(defproxy.cookie_name);
			curproxy->cookie_len = defproxy.cookie_len;
			if (defproxy.cookie_domain)
				curproxy->cookie_domain = strdup(defproxy.cookie_domain);

			if (defproxy.cookie_maxidle)
				curproxy->cookie_maxidle = defproxy.cookie_maxidle;

			if (defproxy.cookie_maxlife)
				curproxy->cookie_maxlife = defproxy.cookie_maxlife;

			if (defproxy.rdp_cookie_name)
				 curproxy->rdp_cookie_name = strdup(defproxy.rdp_cookie_name);
			curproxy->rdp_cookie_len = defproxy.rdp_cookie_len;

			if (defproxy.url_param_name)
				curproxy->url_param_name = strdup(defproxy.url_param_name);
			curproxy->url_param_len = defproxy.url_param_len;

			if (defproxy.hh_name)
				curproxy->hh_name = strdup(defproxy.hh_name);
			curproxy->hh_len  = defproxy.hh_len;
			curproxy->hh_match_domain  = defproxy.hh_match_domain;

			if (defproxy.conn_src.iface_name)
				curproxy->conn_src.iface_name = strdup(defproxy.conn_src.iface_name);
			curproxy->conn_src.iface_len = defproxy.conn_src.iface_len;
			curproxy->conn_src.opts = defproxy.conn_src.opts;
#if defined(CONFIG_HAP_TRANSPARENT)
			curproxy->conn_src.tproxy_addr = defproxy.conn_src.tproxy_addr;
#endif
			curproxy->load_server_state_from_file = defproxy.load_server_state_from_file;
		}

		if (curproxy->cap & PR_CAP_FE) {
			if (defproxy.capture_name)
				curproxy->capture_name = strdup(defproxy.capture_name);
			curproxy->capture_namelen = defproxy.capture_namelen;
			curproxy->capture_len = defproxy.capture_len;
		}

		if (curproxy->cap & PR_CAP_FE) {
			curproxy->timeout.client = defproxy.timeout.client;
			curproxy->timeout.clientfin = defproxy.timeout.clientfin;
			curproxy->timeout.tarpit = defproxy.timeout.tarpit;
			curproxy->timeout.httpreq = defproxy.timeout.httpreq;
			curproxy->timeout.httpka = defproxy.timeout.httpka;
			curproxy->mon_net = defproxy.mon_net;
			curproxy->mon_mask = defproxy.mon_mask;
			if (defproxy.monitor_uri)
				curproxy->monitor_uri = strdup(defproxy.monitor_uri);
			curproxy->monitor_uri_len = defproxy.monitor_uri_len;
			if (defproxy.defbe.name)
				curproxy->defbe.name = strdup(defproxy.defbe.name);

			/* get either a pointer to the logformat string or a copy of it */
			curproxy->conf.logformat_string = defproxy.conf.logformat_string;
			if (curproxy->conf.logformat_string &&
			    curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format)
				curproxy->conf.logformat_string = strdup(curproxy->conf.logformat_string);

			if (defproxy.conf.lfs_file) {
				curproxy->conf.lfs_file = strdup(defproxy.conf.lfs_file);
				curproxy->conf.lfs_line = defproxy.conf.lfs_line;
			}

			/* get either a pointer to the logformat string for RFC5424 structured-data or a copy of it */
			curproxy->conf.logformat_sd_string = defproxy.conf.logformat_sd_string;
			if (curproxy->conf.logformat_sd_string &&
			    curproxy->conf.logformat_sd_string != default_rfc5424_sd_log_format)
				curproxy->conf.logformat_sd_string = strdup(curproxy->conf.logformat_sd_string);

			if (defproxy.conf.lfsd_file) {
				curproxy->conf.lfsd_file = strdup(defproxy.conf.lfsd_file);
				curproxy->conf.lfsd_line = defproxy.conf.lfsd_line;
			}
		}

		if (curproxy->cap & PR_CAP_BE) {
			curproxy->timeout.connect = defproxy.timeout.connect;
			curproxy->timeout.server = defproxy.timeout.server;
			curproxy->timeout.serverfin = defproxy.timeout.serverfin;
			curproxy->timeout.check = defproxy.timeout.check;
			curproxy->timeout.queue = defproxy.timeout.queue;
			curproxy->timeout.tarpit = defproxy.timeout.tarpit;
			curproxy->timeout.httpreq = defproxy.timeout.httpreq;
			curproxy->timeout.httpka = defproxy.timeout.httpka;
			curproxy->timeout.tunnel = defproxy.timeout.tunnel;
			curproxy->conn_src.source_addr = defproxy.conn_src.source_addr;
		}

		curproxy->mode = defproxy.mode;
		curproxy->uri_auth = defproxy.uri_auth; /* for stats */

		/* copy default logsrvs to curproxy */
		list_for_each_entry(tmplogsrv, &defproxy.logsrvs, list) {
			struct logsrv *node = malloc(sizeof(*node));
			memcpy(node, tmplogsrv, sizeof(struct logsrv));
			LIST_INIT(&node->list);
			LIST_ADDQ(&curproxy->logsrvs, &node->list);
		}

		curproxy->conf.uniqueid_format_string = defproxy.conf.uniqueid_format_string;
		if (curproxy->conf.uniqueid_format_string)
			curproxy->conf.uniqueid_format_string = strdup(curproxy->conf.uniqueid_format_string);

		chunk_dup(&curproxy->log_tag, &defproxy.log_tag);

		if (defproxy.conf.uif_file) {
			curproxy->conf.uif_file = strdup(defproxy.conf.uif_file);
			curproxy->conf.uif_line = defproxy.conf.uif_line;
		}

		/* copy default header unique id */
		if (defproxy.header_unique_id)
			curproxy->header_unique_id = strdup(defproxy.header_unique_id);

		/* default compression options */
		if (defproxy.comp != NULL) {
			curproxy->comp = calloc(1, sizeof(struct comp));
			curproxy->comp->algos = defproxy.comp->algos;
			curproxy->comp->types = defproxy.comp->types;
		}

		curproxy->grace  = defproxy.grace;
		curproxy->conf.used_listener_id = EB_ROOT;
		curproxy->conf.used_server_id = EB_ROOT;

		if (defproxy.check_path)
			curproxy->check_path = strdup(defproxy.check_path);
		if (defproxy.check_command)
			curproxy->check_command = strdup(defproxy.check_command);

		if (defproxy.email_alert.mailers.name)
			curproxy->email_alert.mailers.name = strdup(defproxy.email_alert.mailers.name);
		if (defproxy.email_alert.from)
			curproxy->email_alert.from = strdup(defproxy.email_alert.from);
		if (defproxy.email_alert.to)
			curproxy->email_alert.to = strdup(defproxy.email_alert.to);
		if (defproxy.email_alert.myhostname)
			curproxy->email_alert.myhostname = strdup(defproxy.email_alert.myhostname);
		curproxy->email_alert.level = defproxy.email_alert.level;
		curproxy->email_alert.set = defproxy.email_alert.set;

		goto out;
	}
	else if (!strcmp(args[0], "defaults")) {  /* use this one to assign default values */
		/* some variables may have already been initialized earlier */
		/* FIXME-20070101: we should do this too at the end of the
		 * config parsing to free all default values.
		 */
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		free(defproxy.check_req);
		free(defproxy.check_command);
		free(defproxy.check_path);
		free(defproxy.cookie_name);
		free(defproxy.rdp_cookie_name);
		free(defproxy.cookie_domain);
		free(defproxy.url_param_name);
		free(defproxy.hh_name);
		free(defproxy.capture_name);
		free(defproxy.monitor_uri);
		free(defproxy.defbe.name);
		free(defproxy.conn_src.iface_name);
		free(defproxy.fwdfor_hdr_name);
		defproxy.fwdfor_hdr_len = 0;
		free(defproxy.orgto_hdr_name);
		defproxy.orgto_hdr_len = 0;
		free(defproxy.server_id_hdr_name);
		defproxy.server_id_hdr_len = 0;
		free(defproxy.expect_str);
		if (defproxy.expect_regex) {
			regex_free(defproxy.expect_regex);
			free(defproxy.expect_regex);
			defproxy.expect_regex = NULL;
		}

		if (defproxy.conf.logformat_string != default_http_log_format &&
		    defproxy.conf.logformat_string != default_tcp_log_format &&
		    defproxy.conf.logformat_string != clf_http_log_format)
			free(defproxy.conf.logformat_string);

		free(defproxy.conf.uniqueid_format_string);
		free(defproxy.conf.lfs_file);
		free(defproxy.conf.uif_file);
		chunk_destroy(&defproxy.log_tag);
		free_email_alert(&defproxy);

		if (defproxy.conf.logformat_sd_string != default_rfc5424_sd_log_format)
			free(defproxy.conf.logformat_sd_string);
		free(defproxy.conf.lfsd_file);

		for (rc = 0; rc < HTTP_ERR_SIZE; rc++)
			chunk_destroy(&defproxy.errmsg[rc]);

		/* we cannot free uri_auth because it might already be used */
		init_default_instance();
		curproxy = &defproxy;
		curproxy->conf.args.file = curproxy->conf.file = strdup(file);
		curproxy->conf.args.line = curproxy->conf.line = linenum;
		defproxy.cap = PR_CAP_LISTEN; /* all caps for now */
		goto out;
	}
	else if (curproxy == NULL) {
		Alert("parsing [%s:%d] : 'listen' or 'defaults' expected.\n", file, linenum);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	/* update the current file and line being parsed */
	curproxy->conf.args.file = curproxy->conf.file;
	curproxy->conf.args.line = linenum;

	/* Now let's parse the proxy-specific keywords */
	if (!strcmp(args[0], "server") || !strcmp(args[0], "default-server")) {
		err_code |= parse_server(file, linenum, args, curproxy, &defproxy);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "bind")) {  /* new listen addresses */
		struct listener *l;
		int cur_arg;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!*(args[1])) {
			Alert("parsing [%s:%d] : '%s' expects {<path>|[addr1]:port1[-end1]}{,[addr]:port[-end]}... as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		bind_conf = bind_conf_alloc(&curproxy->conf.bind, file, linenum, args[1]);

		/* use default settings for unix sockets */
		bind_conf->ux.uid  = global.unix_bind.ux.uid;
		bind_conf->ux.gid  = global.unix_bind.ux.gid;
		bind_conf->ux.mode = global.unix_bind.ux.mode;

		/* NOTE: the following line might create several listeners if there
		 * are comma-separated IPs or port ranges. So all further processing
		 * will have to be applied to all listeners created after last_listen.
		 */
		if (!str2listener(args[1], curproxy, bind_conf, file, linenum, &errmsg)) {
			if (errmsg && *errmsg) {
				indent_msg(&errmsg, 2);
				Alert("parsing [%s:%d] : '%s' : %s\n", file, linenum, args[0], errmsg);
			}
			else
				Alert("parsing [%s:%d] : '%s' : error encountered while parsing listening address '%s'.\n",
				      file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			/* Set default global rights and owner for unix bind  */
			global.maxsock++;
		}

		cur_arg = 2;
		while (*(args[cur_arg])) {
			static int bind_dumped;
			struct bind_kw *kw;
			char *err;

			kw = bind_find_kw(args[cur_arg]);
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

				code = kw->parse(args, cur_arg, curproxy, bind_conf, &err);
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
			if (!bind_dumped) {
				bind_dump_kws(&err);
				indent_msg(&err, 4);
				bind_dumped = 1;
			}

			Alert("parsing [%s:%d] : '%s %s' unknown keyword '%s'.%s%s\n",
			      file, linenum, args[0], args[1], args[cur_arg],
			      err ? " Registered keywords :" : "", err ? err : "");
			free(err);

			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		goto out;
	}
	else if (!strcmp(args[0], "monitor-net")) {  /* set the range of IPs to ignore */
		if (!*args[1] || !str2net(args[1], 1, &curproxy->mon_net, &curproxy->mon_mask)) {
			Alert("parsing [%s:%d] : '%s' expects address[/mask].\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		/* flush useless bits */
		curproxy->mon_net.s_addr &= curproxy->mon_mask.s_addr;
		goto out;
	}
	else if (!strcmp(args[0], "monitor-uri")) {  /* set the URI to intercept */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects an URI.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		free(curproxy->monitor_uri);
		curproxy->monitor_uri_len = strlen(args[1]);
		curproxy->monitor_uri = calloc(1, curproxy->monitor_uri_len + 1);
		memcpy(curproxy->monitor_uri, args[1], curproxy->monitor_uri_len);
		curproxy->monitor_uri[curproxy->monitor_uri_len] = '\0';

		goto out;
	}
	else if (!strcmp(args[0], "mode")) {  /* sets the proxy mode */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!strcmp(args[1], "http")) curproxy->mode = PR_MODE_HTTP;
		else if (!strcmp(args[1], "tcp")) curproxy->mode = PR_MODE_TCP;
		else if (!strcmp(args[1], "health")) curproxy->mode = PR_MODE_HEALTH;
		else {
			Alert("parsing [%s:%d] : unknown proxy mode '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "id")) {
		struct eb32_node *node;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->uuid = atol(args[1]);
		curproxy->conf.id.key = curproxy->uuid;
		curproxy->options |= PR_O_FORCED_ID;

		if (curproxy->uuid <= 0) {
			Alert("parsing [%s:%d]: custom id has to be > 0.\n",
				file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		node = eb32_lookup(&used_proxy_id, curproxy->uuid);
		if (node) {
			struct proxy *target = container_of(node, struct proxy, conf.id);
			Alert("parsing [%s:%d]: %s %s reuses same custom id as %s %s (declared at %s:%d).\n",
			      file, linenum, proxy_type_str(curproxy), curproxy->id,
			      proxy_type_str(target), target->id, target->conf.file, target->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		eb32_insert(&used_proxy_id, &curproxy->conf.id);
	}
	else if (!strcmp(args[0], "description")) {
		int i, len=0;
		char *d;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects a string argument.\n",
				file, linenum, args[0]);
			return -1;
		}

		for (i = 1; *args[i]; i++)
			len += strlen(args[i]) + 1;

		d = calloc(1, len);
		curproxy->desc = d;

		d += snprintf(d, curproxy->desc + len - d, "%s", args[1]);
		for (i = 2; *args[i]; i++)
			d += snprintf(d, curproxy->desc + len - d, " %s", args[i]);

	}
	else if (!strcmp(args[0], "disabled")) {  /* disables this proxy */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		curproxy->state = PR_STSTOPPED;
	}
	else if (!strcmp(args[0], "enabled")) {  /* enables this proxy (used to revert a disabled default) */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		curproxy->state = PR_STNEW;
	}
	else if (!strcmp(args[0], "bind-process")) {  /* enable this proxy only on some processes */
		int cur_arg = 1;
		unsigned long set = 0;

		while (*args[cur_arg]) {
			unsigned int low, high;

			if (strcmp(args[cur_arg], "all") == 0) {
				set = 0;
				break;
			}
			else if (strcmp(args[cur_arg], "odd") == 0) {
				set |= ~0UL/3UL; /* 0x555....555 */
			}
			else if (strcmp(args[cur_arg], "even") == 0) {
				set |= (~0UL/3UL) << 1; /* 0xAAA...AAA */
			}
			else if (isdigit((int)*args[cur_arg])) {
				char *dash = strchr(args[cur_arg], '-');

				low = high = str2uic(args[cur_arg]);
				if (dash)
					high = str2uic(dash + 1);

				if (high < low) {
					unsigned int swap = low;
					low = high;
					high = swap;
				}

				if (low < 1 || high > LONGBITS) {
					Alert("parsing [%s:%d]: %s supports process numbers from 1 to %d.\n",
					      file, linenum, args[0], LONGBITS);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				while (low <= high)
					set |= 1UL << (low++ - 1);
			}
			else {
				Alert("parsing [%s:%d]: %s expects 'all', 'odd', 'even', or a list of process ranges with numbers from 1 to %d.\n",
				      file, linenum, args[0], LONGBITS);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg++;
		}
		curproxy->bind_proc = set;
	}
	else if (!strcmp(args[0], "acl")) {  /* add an ACL */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in acl name '%s'.\n",
			      file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (parse_acl((const char **)args + 1, &curproxy->acl, &errmsg, &curproxy->conf.args, file, linenum) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing ACL '%s' : %s.\n",
			      file, linenum, args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "cookie")) {  /* cookie name */
		int cur_arg;

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <cookie_name> as argument.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->ck_opts = 0;
		curproxy->cookie_maxidle = curproxy->cookie_maxlife = 0;
		free(curproxy->cookie_domain); curproxy->cookie_domain = NULL;
		free(curproxy->cookie_name);
		curproxy->cookie_name = strdup(args[1]);
		curproxy->cookie_len = strlen(curproxy->cookie_name);

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "rewrite")) {
				curproxy->ck_opts |= PR_CK_RW;
			}
			else if (!strcmp(args[cur_arg], "indirect")) {
				curproxy->ck_opts |= PR_CK_IND;
			}
			else if (!strcmp(args[cur_arg], "insert")) {
				curproxy->ck_opts |= PR_CK_INS;
			}
			else if (!strcmp(args[cur_arg], "nocache")) {
				curproxy->ck_opts |= PR_CK_NOC;
			}
			else if (!strcmp(args[cur_arg], "postonly")) {
				curproxy->ck_opts |= PR_CK_POST;
			}
			else if (!strcmp(args[cur_arg], "preserve")) {
				curproxy->ck_opts |= PR_CK_PSV;
			}
			else if (!strcmp(args[cur_arg], "prefix")) {
				curproxy->ck_opts |= PR_CK_PFX;
			}
			else if (!strcmp(args[cur_arg], "httponly")) {
				curproxy->ck_opts |= PR_CK_HTTPONLY;
			}
			else if (!strcmp(args[cur_arg], "secure")) {
				curproxy->ck_opts |= PR_CK_SECURE;
			}
			else if (!strcmp(args[cur_arg], "domain")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects <domain> as argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (*args[cur_arg + 1] != '.' || !strchr(args[cur_arg + 1] + 1, '.')) {
					/* rfc2109, 4.3.2 Rejecting Cookies */
					Warning("parsing [%s:%d]: domain '%s' contains no embedded"
						" dots nor does not start with a dot."
						" RFC forbids it, this configuration may not work properly.\n",
						file, linenum, args[cur_arg + 1]);
					err_code |= ERR_WARN;
				}

				err = invalid_domainchar(args[cur_arg + 1]);
				if (err) {
					Alert("parsing [%s:%d]: character '%c' is not permitted in domain name '%s'.\n",
						file, linenum, *err, args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!curproxy->cookie_domain) {
					curproxy->cookie_domain = strdup(args[cur_arg + 1]);
				} else {
					/* one domain was already specified, add another one by
					 * building the string which will be returned along with
					 * the cookie.
					 */
					char *new_ptr;
					int new_len = strlen(curproxy->cookie_domain) +
						strlen("; domain=") + strlen(args[cur_arg + 1]) + 1;
					new_ptr = malloc(new_len);
					snprintf(new_ptr, new_len, "%s; domain=%s", curproxy->cookie_domain, args[cur_arg+1]);
					free(curproxy->cookie_domain);
					curproxy->cookie_domain = new_ptr;
				}
				cur_arg++;
			}
			else if (!strcmp(args[cur_arg], "maxidle")) {
				unsigned int maxidle;
				const char *res;

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects <idletime> in seconds as argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				res = parse_time_err(args[cur_arg + 1], &maxidle, TIME_UNIT_S);
				if (res) {
					Alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
					      file, linenum, *res, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->cookie_maxidle = maxidle;
				cur_arg++;
			}
			else if (!strcmp(args[cur_arg], "maxlife")) {
				unsigned int maxlife;
				const char *res;

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects <lifetime> in seconds as argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				res = parse_time_err(args[cur_arg + 1], &maxlife, TIME_UNIT_S);
				if (res) {
					Alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
					      file, linenum, *res, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->cookie_maxlife = maxlife;
				cur_arg++;
			}
			else {
				Alert("parsing [%s:%d] : '%s' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache', 'postonly', 'domain', 'maxidle, and 'maxlife' options.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg++;
		}
		if (!POWEROF2(curproxy->ck_opts & (PR_CK_RW|PR_CK_IND))) {
			Alert("parsing [%s:%d] : cookie 'rewrite' and 'indirect' modes are incompatible.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (!POWEROF2(curproxy->ck_opts & (PR_CK_RW|PR_CK_INS|PR_CK_PFX))) {
			Alert("parsing [%s:%d] : cookie 'rewrite', 'insert' and 'prefix' modes are incompatible.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if ((curproxy->ck_opts & (PR_CK_PSV | PR_CK_INS | PR_CK_IND)) == PR_CK_PSV) {
			Alert("parsing [%s:%d] : cookie 'preserve' requires at least 'insert' or 'indirect'.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}/* end else if (!strcmp(args[0], "cookie"))  */
	else if (!strcmp(args[0], "email-alert")) {
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : missing argument after '%s'.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }

		if (!strcmp(args[1], "from")) {
			if (*(args[1]) == 0) {
				Alert("parsing [%s:%d] : missing argument after '%s'.\n",
				      file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.from);
			curproxy->email_alert.from = strdup(args[2]);
		}
		else if (!strcmp(args[1], "mailers")) {
			if (*(args[1]) == 0) {
				Alert("parsing [%s:%d] : missing argument after '%s'.\n",
				      file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.mailers.name);
			curproxy->email_alert.mailers.name = strdup(args[2]);
		}
		else if (!strcmp(args[1], "myhostname")) {
			if (*(args[1]) == 0) {
				Alert("parsing [%s:%d] : missing argument after '%s'.\n",
				      file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.myhostname);
			curproxy->email_alert.myhostname = strdup(args[2]);
		}
		else if (!strcmp(args[1], "level")) {
			curproxy->email_alert.level = get_log_level(args[2]);
			if (curproxy->email_alert.level < 0) {
				Alert("parsing [%s:%d] : unknown log level '%s' after '%s'\n",
				      file, linenum, args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else if (!strcmp(args[1], "to")) {
			if (*(args[1]) == 0) {
				Alert("parsing [%s:%d] : missing argument after '%s'.\n",
				      file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.to);
			curproxy->email_alert.to = strdup(args[2]);
		}
		else {
			Alert("parsing [%s:%d] : email-alert: unknown argument '%s'.\n",
			      file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		/* Indicate that the email_alert is at least partially configured */
		curproxy->email_alert.set = 1;
	}/* end else if (!strcmp(args[0], "email-alert"))  */
	else if (!strcmp(args[0], "external-check")) {
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : missing argument after '%s'.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }

		if (!strcmp(args[1], "command")) {
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : missing argument after '%s'.\n",
				      file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->check_command);
			curproxy->check_command = strdup(args[2]);
		}
		else if (!strcmp(args[1], "path")) {
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : missing argument after '%s'.\n",
				      file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->check_path);
			curproxy->check_path = strdup(args[2]);
		}
		else {
			Alert("parsing [%s:%d] : external-check: unknown argument '%s'.\n",
			      file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}/* end else if (!strcmp(args[0], "external-check"))  */
	else if (!strcmp(args[0], "persist")) {  /* persist */
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : missing persist method.\n",
				file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }

		if (!strncmp(args[1], "rdp-cookie", 10)) {
			curproxy->options2 |= PR_O2_RDPC_PRST;

	                if (*(args[1] + 10) == '(') { /* cookie name */
				const char *beg, *end;

				beg = args[1] + 11;
				end = strchr(beg, ')');

				if (alertif_too_many_args(1, file, linenum, args, &err_code))
					goto out;

				if (!end || end == beg) {
					Alert("parsing [%s:%d] : persist rdp-cookie(name)' requires an rdp cookie name.\n",
					      file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				free(curproxy->rdp_cookie_name);
				curproxy->rdp_cookie_name = my_strndup(beg, end - beg);
				curproxy->rdp_cookie_len = end-beg;
			}
			else if (*(args[1] + 10) == '\0') { /* default cookie name 'msts' */
				free(curproxy->rdp_cookie_name);
				curproxy->rdp_cookie_name = strdup("msts");
				curproxy->rdp_cookie_len = strlen(curproxy->rdp_cookie_name);
			}
			else { /* syntax */
				Alert("parsing [%s:%d] : persist rdp-cookie(name)' requires an rdp cookie name.\n",
				      file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			Alert("parsing [%s:%d] : unknown persist method.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "appsession")) {  /* cookie name */
		Alert("parsing [%s:%d] : '%s' is not supported anymore, please check the documentation.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "load-server-state-from-file")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;
		if (!strcmp(args[1], "global")) {  /* use the file pointed to by global server-state-file directive */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_GLOBAL;
		}
		else if (!strcmp(args[1], "local")) { /* use the server-state-file-name variable to locate the server-state file */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_LOCAL;
		}
		else if (!strcmp(args[1], "none")) {  /* don't use server-state-file directive for this backend */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_NONE;
		}
		else {
			Alert("parsing [%s:%d] : '%s' expects 'global', 'local' or 'none'. Got '%s'\n",
			      file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "server-state-file-name")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects 'use-backend-name' or a string. Got no argument\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (!strcmp(args[1], "use-backend-name"))
			curproxy->server_state_file_name = strdup(curproxy->id);
		else
			curproxy->server_state_file_name = strdup(args[1]);
	}
	else if (!strcmp(args[0], "capture")) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!strcmp(args[1], "cookie")) {  /* name of a cookie to capture */
			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (alertif_too_many_args_idx(4, 1, file, linenum, args, &err_code))
				goto out;

			if (*(args[4]) == 0) {
				Alert("parsing [%s:%d] : '%s' expects 'cookie' <cookie_name> 'len' <len>.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->capture_name);
			curproxy->capture_name = strdup(args[2]);
			curproxy->capture_namelen = strlen(curproxy->capture_name);
			curproxy->capture_len = atol(args[4]);
			curproxy->to_log |= LW_COOKIE;
		}
		else if (!strcmp(args[1], "request") && !strcmp(args[2], "header")) {
			struct cap_hdr *hdr;

			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (alertif_too_many_args_idx(4, 1, file, linenum, args, &err_code))
				goto out;

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				Alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			hdr = calloc(1, sizeof(*hdr));
			hdr->next = curproxy->req_cap;
			hdr->name = strdup(args[3]);
			hdr->namelen = strlen(args[3]);
			hdr->len = atol(args[5]);
			hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
			hdr->index = curproxy->nb_req_cap++;
			curproxy->req_cap = hdr;
			curproxy->to_log |= LW_REQHDR;
		}
		else if (!strcmp(args[1], "response") && !strcmp(args[2], "header")) {
			struct cap_hdr *hdr;

			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (alertif_too_many_args_idx(4, 1, file, linenum, args, &err_code))
				goto out;

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				Alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			hdr = calloc(1, sizeof(*hdr));
			hdr->next = curproxy->rsp_cap;
			hdr->name = strdup(args[3]);
			hdr->namelen = strlen(args[3]);
			hdr->len = atol(args[5]);
			hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
			hdr->index = curproxy->nb_rsp_cap++;
			curproxy->rsp_cap = hdr;
			curproxy->to_log |= LW_RSPHDR;
		}
		else {
			Alert("parsing [%s:%d] : '%s' expects 'cookie' or 'request header' or 'response header'.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "retries")) {  /* connection retries */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument (dispatch counts for one).\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->conn_retries = atol(args[1]);
	}
	else if (!strcmp(args[0], "http-request")) {	/* request access control: allow/deny/auth */
		struct act_rule *rule;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!LIST_ISEMPTY(&curproxy->http_req_rules) &&
		    !LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->cond &&
		    (LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_ACTION_ALLOW ||
		     LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_ACTION_DENY ||
		     LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_HTTP_REDIR ||
		     LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_HTTP_REQ_AUTH)) {
			Warning("parsing [%s:%d]: previous '%s' action is final and has no condition attached, further entries are NOOP.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		rule = parse_http_req_cond((const char **)args + 1, file, linenum, curproxy);

		if (!rule) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err_code |= warnif_misplaced_http_req(curproxy, file, linenum, args[0]);
		err_code |= warnif_cond_conflicts(rule->cond,
	                                          (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
	                                          file, linenum);

		LIST_ADDQ(&curproxy->http_req_rules, &rule->list);
	}
	else if (!strcmp(args[0], "http-response")) {	/* response access control */
		struct act_rule *rule;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!LIST_ISEMPTY(&curproxy->http_res_rules) &&
		    !LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->cond &&
		    (LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->action == ACT_ACTION_ALLOW ||
		     LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->action == ACT_ACTION_DENY)) {
			Warning("parsing [%s:%d]: previous '%s' action is final and has no condition attached, further entries are NOOP.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		rule = parse_http_res_cond((const char **)args + 1, file, linenum, curproxy);

		if (!rule) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err_code |= warnif_cond_conflicts(rule->cond,
	                                          (curproxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR,
	                                          file, linenum);

		LIST_ADDQ(&curproxy->http_res_rules, &rule->list);
	}
	else if (!strcmp(args[0], "http-send-name-header")) { /* send server name in request header */
		/* set the header name and length into the proxy structure */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' requires a header string.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* set the desired header name */
		free(curproxy->server_id_hdr_name);
		curproxy->server_id_hdr_name = strdup(args[1]);
		curproxy->server_id_hdr_len  = strlen(curproxy->server_id_hdr_name);
	}
	else if (!strcmp(args[0], "block")) {  /* early blocking based on ACLs */
		struct act_rule *rule;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* emulate "block" using "http-request block". Since these rules are supposed to
		 * be processed before all http-request rules, we put them into their own list
		 * and will insert them at the end.
		 */
		rule = parse_http_req_cond((const char **)args, file, linenum, curproxy);
		if (!rule) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		err_code |= warnif_misplaced_block(curproxy, file, linenum, args[0]);
		err_code |= warnif_cond_conflicts(rule->cond,
	                                          (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
	                                          file, linenum);
		LIST_ADDQ(&curproxy->block_rules, &rule->list);

		if (!already_warned(WARN_BLOCK_DEPRECATED))
			Warning("parsing [%s:%d] : The '%s' directive is now deprecated in favor of 'http-request deny' which uses the exact same syntax. The rules are translated but support might disappear in a future version.\n", file, linenum, args[0]);

	}
	else if (!strcmp(args[0], "redirect")) {
		struct redirect_rule *rule;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((rule = http_parse_redirect_rule(file, linenum, curproxy, (const char **)args + 1, &errmsg, 0, 0)) == NULL) {
			Alert("parsing [%s:%d] : error detected in %s '%s' while parsing redirect rule : %s.\n",
			      file, linenum, proxy_type_str(curproxy), curproxy->id, errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		LIST_ADDQ(&curproxy->redirect_rules, &rule->list);
		err_code |= warnif_misplaced_redirect(curproxy, file, linenum, args[0]);
		err_code |= warnif_cond_conflicts(rule->cond,
	                                          (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
	                                          file, linenum);
	}
	else if (!strcmp(args[0], "use_backend")) {
		struct switching_rule *rule;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a backend name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0) {
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing switching rule : %s.\n",
				      file, linenum, errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			err_code |= warnif_cond_conflicts(cond, SMP_VAL_FE_SET_BCK, file, linenum);
		}

		rule = calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->be.name = strdup(args[1]);
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->switching_rules, &rule->list);
	}
	else if (strcmp(args[0], "use-server") == 0) {
		struct server_rule *rule;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a server name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
			Alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing switching rule : %s.\n",
			      file, linenum, errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_SET_SRV, file, linenum);

		rule = calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->srv.name = strdup(args[1]);
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->server_rules, &rule->list);
		curproxy->be_req_ana |= AN_REQ_SRV_RULES;
	}
	else if ((!strcmp(args[0], "force-persist")) ||
		 (!strcmp(args[0], "ignore-persist"))) {
		struct persist_rule *rule;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_FE|PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "if") != 0 && strcmp(args[1], "unless") != 0) {
			Alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 1, &errmsg)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing a '%s' rule : %s.\n",
			      file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* note: BE_REQ_CNT is the first one after FE_SET_BCK, which is
		 * where force-persist is applied.
		 */
		err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_REQ_CNT, file, linenum);

		rule = calloc(1, sizeof(*rule));
		rule->cond = cond;
		if (!strcmp(args[0], "force-persist")) {
			rule->type = PERSIST_TYPE_FORCE;
		} else {
			rule->type = PERSIST_TYPE_IGNORE;
		}
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->persist_rules, &rule->list);
	}
	else if (!strcmp(args[0], "stick-table")) {
		int myidx = 1;
		struct proxy *other;

		other = proxy_tbl_by_name(curproxy->id);
		if (other) {
			Alert("parsing [%s:%d] : stick-table name '%s' conflicts with table declared in %s '%s' at %s:%d.\n",
			      file, linenum, curproxy->id, proxy_type_str(other), other->id, other->conf.file, other->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->table.id =  curproxy->id;
		curproxy->table.type = (unsigned int)-1;
		while (*args[myidx]) {
			const char *err;

			if (strcmp(args[myidx], "size") == 0) {
				myidx++;
				if (!*(args[myidx])) {
					Alert("parsing [%s:%d] : stick-table: missing argument after '%s'.\n",
					      file, linenum, args[myidx-1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if ((err = parse_size_err(args[myidx], &curproxy->table.size))) {
					Alert("parsing [%s:%d] : stick-table: unexpected character '%c' in argument of '%s'.\n",
					      file, linenum, *err, args[myidx-1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				myidx++;
			}
			else if (strcmp(args[myidx], "peers") == 0) {
				myidx++;
				if (!*(args[myidx])) {
					Alert("parsing [%s:%d] : stick-table: missing argument after '%s'.\n",
					      file, linenum, args[myidx-1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->table.peers.name = strdup(args[myidx++]);
			}
			else if (strcmp(args[myidx], "expire") == 0) {
				myidx++;
				if (!*(args[myidx])) {
					Alert("parsing [%s:%d] : stick-table: missing argument after '%s'.\n",
					      file, linenum, args[myidx-1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				err = parse_time_err(args[myidx], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d] : stick-table: unexpected character '%c' in argument of '%s'.\n",
					      file, linenum, *err, args[myidx-1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val > INT_MAX) {
					Alert("parsing [%s:%d] : Expire value [%u]ms exceeds maxmimum value of 24.85 days.\n",
					      file, linenum, val);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->table.expire = val;
				myidx++;
			}
			else if (strcmp(args[myidx], "nopurge") == 0) {
				curproxy->table.nopurge = 1;
				myidx++;
			}
			else if (strcmp(args[myidx], "type") == 0) {
				myidx++;
				if (stktable_parse_type(args, &myidx, &curproxy->table.type, &curproxy->table.key_size) != 0) {
					Alert("parsing [%s:%d] : stick-table: unknown type '%s'.\n",
					      file, linenum, args[myidx]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				/* myidx already points to next arg */
			}
			else if (strcmp(args[myidx], "store") == 0) {
				int type, err;
				char *cw, *nw, *sa;

				myidx++;
				nw = args[myidx];
				while (*nw) {
					/* the "store" keyword supports a comma-separated list */
					cw = nw;
					sa = NULL; /* store arg */
					while (*nw && *nw != ',') {
						if (*nw == '(') {
							*nw = 0;
							sa = ++nw;
							while (*nw != ')') {
								if (!*nw) {
									Alert("parsing [%s:%d] : %s: missing closing parenthesis after store option '%s'.\n",
									      file, linenum, args[0], cw);
									err_code |= ERR_ALERT | ERR_FATAL;
									goto out;
								}
								nw++;
							}
							*nw = '\0';
						}
						nw++;
					}
					if (*nw)
						*nw++ = '\0';
					type = stktable_get_data_type(cw);
					if (type < 0) {
						Alert("parsing [%s:%d] : %s: unknown store option '%s'.\n",
						      file, linenum, args[0], cw);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					err = stktable_alloc_data_type(&curproxy->table, type, sa);
					switch (err) {
					case PE_NONE: break;
					case PE_EXIST:
						Warning("parsing [%s:%d]: %s: store option '%s' already enabled, ignored.\n",
							file, linenum, args[0], cw);
						err_code |= ERR_WARN;
						break;

					case PE_ARG_MISSING:
						Alert("parsing [%s:%d] : %s: missing argument to store option '%s'.\n",
						      file, linenum, args[0], cw);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;

					case PE_ARG_NOT_USED:
						Alert("parsing [%s:%d] : %s: unexpected argument to store option '%s'.\n",
						      file, linenum, args[0], cw);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;

					default:
						Alert("parsing [%s:%d] : %s: error when processing store option '%s'.\n",
						      file, linenum, args[0], cw);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				}
				myidx++;
			}
			else {
				Alert("parsing [%s:%d] : stick-table: unknown argument '%s'.\n",
				      file, linenum, args[myidx]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if (!curproxy->table.size) {
			Alert("parsing [%s:%d] : stick-table: missing size.\n",
			       file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (curproxy->table.type == (unsigned int)-1) {
			Alert("parsing [%s:%d] : stick-table: missing type.\n",
			       file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "stick")) {
		struct sticking_rule *rule;
		struct sample_expr *expr;
		int myidx = 0;
		const char *name = NULL;
		int flags;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL)) {
			err_code |= ERR_WARN;
			goto out;
		}

		myidx++;
		if ((strcmp(args[myidx], "store") == 0) ||
		    (strcmp(args[myidx], "store-request") == 0)) {
			myidx++;
			flags = STK_IS_STORE;
		}
		else if (strcmp(args[myidx], "store-response") == 0) {
			myidx++;
			flags = STK_IS_STORE | STK_ON_RSP;
		}
		else if (strcmp(args[myidx], "match") == 0) {
			myidx++;
			flags = STK_IS_MATCH;
		}
		else if (strcmp(args[myidx], "on") == 0) {
			myidx++;
			flags = STK_IS_MATCH | STK_IS_STORE;
		}
		else {
			Alert("parsing [%s:%d] : '%s' expects 'on', 'match', or 'store'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (*(args[myidx]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a fetch method.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->conf.args.ctx = ARGC_STK;
		expr = sample_parse_expr(args, &myidx, file, linenum, &errmsg, &curproxy->conf.args);
		if (!expr) {
			Alert("parsing [%s:%d] : '%s': %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (flags & STK_ON_RSP) {
			if (!(expr->fetch->val & SMP_VAL_BE_STO_RUL)) {
				Alert("parsing [%s:%d] : '%s': fetch method '%s' extracts information from '%s', none of which is available for 'store-response'.\n",
				      file, linenum, args[0], expr->fetch->kw, sample_src_names(expr->fetch->use));
		                err_code |= ERR_ALERT | ERR_FATAL;
				free(expr);
			        goto out;
			}
		} else {
			if (!(expr->fetch->val & SMP_VAL_BE_SET_SRV)) {
				Alert("parsing [%s:%d] : '%s': fetch method '%s' extracts information from '%s', none of which is available during request.\n",
				      file, linenum, args[0], expr->fetch->kw, sample_src_names(expr->fetch->use));
				err_code |= ERR_ALERT | ERR_FATAL;
				free(expr);
				goto out;
			}
		}

		/* check if we need to allocate an hdr_idx struct for HTTP parsing */
		curproxy->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);

		if (strcmp(args[myidx], "table") == 0) {
			myidx++;
			name = args[myidx++];
		}

		if (strcmp(args[myidx], "if") == 0 || strcmp(args[myidx], "unless") == 0) {
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + myidx, &errmsg)) == NULL) {
				Alert("parsing [%s:%d] : '%s': error detected while parsing sticking condition : %s.\n",
				      file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(expr);
				goto out;
			}
		}
		else if (*(args[myidx])) {
			Alert("parsing [%s:%d] : '%s': unknown keyword '%s'.\n",
			      file, linenum, args[0], args[myidx]);
			err_code |= ERR_ALERT | ERR_FATAL;
			free(expr);
			goto out;
		}
		if (flags & STK_ON_RSP)
			err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_STO_RUL, file, linenum);
		else
			err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_SET_SRV, file, linenum);

		rule = calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->expr = expr;
		rule->flags = flags;
		rule->table.name = name ? strdup(name) : NULL;
		LIST_INIT(&rule->list);
		if (flags & STK_ON_RSP)
			LIST_ADDQ(&curproxy->storersp_rules, &rule->list);
		else
			LIST_ADDQ(&curproxy->sticking_rules, &rule->list);
	}
	else if (!strcmp(args[0], "stats")) {
		if (curproxy != &defproxy && curproxy->uri_auth == defproxy.uri_auth)
			curproxy->uri_auth = NULL; /* we must detach from the default config */

		if (!*args[1]) {
			goto stats_error_parsing;
		} else if (!strcmp(args[1], "admin")) {
			struct stats_admin_rule *rule;

			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d]: '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!stats_check_init_uri_auth(&curproxy->uri_auth)) {
				Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
				Alert("parsing [%s:%d] : '%s %s' requires either 'if' or 'unless' followed by a condition.\n",
				file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing a '%s %s' rule : %s.\n",
				      file, linenum, args[0], args[1], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			err_code |= warnif_cond_conflicts(cond,
			                                  (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
			                                  file, linenum);

			rule = calloc(1, sizeof(*rule));
			rule->cond = cond;
			LIST_INIT(&rule->list);
			LIST_ADDQ(&curproxy->uri_auth->admin_rules, &rule->list);
		} else if (!strcmp(args[1], "uri")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'uri' needs an URI prefix.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_uri(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "realm")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'realm' needs an realm name.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_realm(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "refresh")) {
			unsigned interval;

			err = parse_time_err(args[2], &interval, TIME_UNIT_S);
			if (err) {
				Alert("parsing [%s:%d] : unexpected character '%c' in stats refresh interval.\n",
				      file, linenum, *err);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_refresh(&curproxy->uri_auth, interval)) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "http-request")) {    /* request access control: allow/deny/auth */
			struct act_rule *rule;

			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!stats_check_init_uri_auth(&curproxy->uri_auth)) {
				Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if (!LIST_ISEMPTY(&curproxy->uri_auth->http_req_rules) &&
			    !LIST_PREV(&curproxy->uri_auth->http_req_rules, struct act_rule *, list)->cond) {
				Warning("parsing [%s:%d]: previous '%s' action has no condition attached, further entries are NOOP.\n",
					file, linenum, args[0]);
				err_code |= ERR_WARN;
			}

			rule = parse_http_req_cond((const char **)args + 2, file, linenum, curproxy);

			if (!rule) {
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			err_code |= warnif_cond_conflicts(rule->cond,
			                                  (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
			                                  file, linenum);
			LIST_ADDQ(&curproxy->uri_auth->http_req_rules, &rule->list);

		} else if (!strcmp(args[1], "auth")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'auth' needs a user:password account.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_add_auth(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "scope")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'scope' needs a proxy name.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_add_scope(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "enable")) {
			if (!stats_check_init_uri_auth(&curproxy->uri_auth)) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "hide-version")) {
			if (!stats_set_flag(&curproxy->uri_auth, ST_HIDEVER)) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "show-legends")) {
			if (!stats_set_flag(&curproxy->uri_auth, ST_SHLGNDS)) {
				Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "show-node")) {

			if (*args[2]) {
				int i;
				char c;

				for (i=0; args[2][i]; i++) {
					c = args[2][i];
					if (!isupper((unsigned char)c) && !islower((unsigned char)c) &&
					    !isdigit((unsigned char)c) && c != '_' && c != '-' && c != '.')
						break;
				}

				if (!i || args[2][i]) {
					Alert("parsing [%s:%d]: '%s %s' invalid node name - should be a string"
						"with digits(0-9), letters(A-Z, a-z), hyphen(-) or underscode(_).\n",
						file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}

			if (!stats_set_node(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "show-desc")) {
			char *desc = NULL;

			if (*args[2]) {
				int i, len=0;
				char *d;

				for (i = 2; *args[i]; i++)
					len += strlen(args[i]) + 1;

				desc = d = calloc(1, len);

				d += snprintf(d, desc + len - d, "%s", args[2]);
				for (i = 3; *args[i]; i++)
					d += snprintf(d, desc + len - d, " %s", args[i]);
			}

			if (!*args[2] && !global.desc)
				Warning("parsing [%s:%d]: '%s' requires a parameter or 'desc' to be set in the global section.\n",
					file, linenum, args[1]);
			else {
				if (!stats_set_desc(&curproxy->uri_auth, desc)) {
					free(desc);
					Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}
				free(desc);
			}
		} else {
stats_error_parsing:
			Alert("parsing [%s:%d]: %s '%s', expects 'admin', 'uri', 'realm', 'auth', 'scope', 'enable', 'hide-version', 'show-node', 'show-desc' or 'show-legends'.\n",
			      file, linenum, *args[1]?"unknown stats parameter":"missing keyword in", args[*args[1]?1:0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "option")) {
		int optnum;

		if (*(args[1]) == '\0') {
			Alert("parsing [%s:%d]: '%s' expects an option name.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (optnum = 0; cfg_opts[optnum].name; optnum++) {
			if (!strcmp(args[1], cfg_opts[optnum].name)) {
				if (cfg_opts[optnum].cap == PR_CAP_NONE) {
					Alert("parsing [%s:%d]: option '%s' is not supported due to build options.\n",
						file, linenum, cfg_opts[optnum].name);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
					goto out;

				if (warnifnotcap(curproxy, cfg_opts[optnum].cap, file, linenum, args[1], NULL)) {
					err_code |= ERR_WARN;
					goto out;
				}

				curproxy->no_options &= ~cfg_opts[optnum].val;
				curproxy->options    &= ~cfg_opts[optnum].val;

				switch (kwm) {
				case KWM_STD:
					curproxy->options |= cfg_opts[optnum].val;
					break;
				case KWM_NO:
					curproxy->no_options |= cfg_opts[optnum].val;
					break;
				case KWM_DEF: /* already cleared */
					break;
				}

				goto out;
			}
		}

		for (optnum = 0; cfg_opts2[optnum].name; optnum++) {
			if (!strcmp(args[1], cfg_opts2[optnum].name)) {
				if (cfg_opts2[optnum].cap == PR_CAP_NONE) {
					Alert("parsing [%s:%d]: option '%s' is not supported due to build options.\n",
						file, linenum, cfg_opts2[optnum].name);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
					goto out;
				if (warnifnotcap(curproxy, cfg_opts2[optnum].cap, file, linenum, args[1], NULL)) {
					err_code |= ERR_WARN;
					goto out;
				}

				curproxy->no_options2 &= ~cfg_opts2[optnum].val;
				curproxy->options2    &= ~cfg_opts2[optnum].val;

				switch (kwm) {
				case KWM_STD:
					curproxy->options2 |= cfg_opts2[optnum].val;
					break;
				case KWM_NO:
					curproxy->no_options2 |= cfg_opts2[optnum].val;
					break;
				case KWM_DEF: /* already cleared */
					break;
				}
				goto out;
			}
		}

		/* HTTP options override each other. They can be cancelled using
		 * "no option xxx" which only switches to default mode if the mode
		 * was this one (useful for cancelling options set in defaults
		 * sections).
		 */
		if (strcmp(args[1], "httpclose") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_PCL;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_PCL)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}
		else if (strcmp(args[1], "forceclose") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_FCL;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_FCL)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}
		else if (strcmp(args[1], "http-server-close") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_SCL;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}
		else if (strcmp(args[1], "http-keep-alive") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_KAL;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_KAL)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}
		else if (strcmp(args[1], "http-tunnel") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_TUN;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}

		/* Redispatch can take an integer argument that control when the
		 * resispatch occurs. All values are relative to the retries option.
		 * This can be cancelled using "no option xxx".
		 */
		if (strcmp(args[1], "redispatch") == 0) {
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL)) {
				err_code |= ERR_WARN;
				goto out;
			}

			curproxy->no_options &= ~PR_O_REDISP;
			curproxy->options &= ~PR_O_REDISP;

			switch (kwm) {
			case KWM_STD:
				curproxy->options |= PR_O_REDISP;
				curproxy->redispatch_after = -1;
				if(*args[2]) {
					curproxy->redispatch_after = atol(args[2]);
				}
				break;
			case KWM_NO:
				curproxy->no_options |= PR_O_REDISP;
				curproxy->redispatch_after = 0;
				break;
			case KWM_DEF: /* already cleared */
				break;
			}
			goto out;
		}

		if (kwm != KWM_STD) {
			Alert("parsing [%s:%d]: negation/default is not supported for option '%s'.\n",
				file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!strcmp(args[1], "httplog")) {
			char *logformat;
			/* generate a complete HTTP log */
			logformat = default_http_log_format;
			if (*(args[2]) != '\0') {
				if (!strcmp(args[2], "clf")) {
					curproxy->options2 |= PR_O2_CLFLOG;
					logformat = clf_http_log_format;
				} else {
					Alert("parsing [%s:%d] : keyword '%s' only supports option 'clf'.\n", file, linenum, args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (alertif_too_many_args_idx(1, 1, file, linenum, args, &err_code))
					goto out;
			}
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = logformat;

			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;
		}
		else if (!strcmp(args[1], "tcplog")) {
			/* generate a detailed TCP log */
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = default_tcp_log_format;

			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "tcpka")) {
			/* enable TCP keep-alives on client and server streams */
			if (warnifnotcap(curproxy, PR_CAP_BE | PR_CAP_FE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;

			if (curproxy->cap & PR_CAP_FE)
				curproxy->options |= PR_O_TCP_CLI_KA;
			if (curproxy->cap & PR_CAP_BE)
				curproxy->options |= PR_O_TCP_SRV_KA;
		}
		else if (!strcmp(args[1], "httpchk")) {
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			/* use HTTP request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_HTTP_CHK;
			if (!*args[2]) { /* no argument */
				curproxy->check_req = strdup(DEF_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_CHECK_REQ);
			} else if (!*args[3]) { /* one argument : URI */
				int reqlen = strlen(args[2]) + strlen("OPTIONS  HTTP/1.0\r\n") + 1;
				curproxy->check_req = malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "OPTIONS %s HTTP/1.0\r\n", args[2]); /* URI to use */
			} else { /* more arguments : METHOD URI [HTTP_VER] */
				int reqlen = strlen(args[2]) + strlen(args[3]) + 3 + strlen("\r\n");
				if (*args[4])
					reqlen += strlen(args[4]);
				else
					reqlen += strlen("HTTP/1.0");
		    
				curproxy->check_req = malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "%s %s %s\r\n", args[2], args[3], *args[4]?args[4]:"HTTP/1.0");
			}
			if (alertif_too_many_args_idx(3, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "ssl-hello-chk")) {
			/* use SSLv3 CLIENT HELLO to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_SSL3_CHK;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "smtpchk")) {
			/* use SMTP request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_SMTP_CHK;

			if (!*args[2] || !*args[3]) { /* no argument or incomplete EHLO host */
				curproxy->check_req = strdup(DEF_SMTP_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_SMTP_CHECK_REQ);
			} else { /* ESMTP EHLO, or SMTP HELO, and a hostname */
				if (!strcmp(args[2], "EHLO") || !strcmp(args[2], "HELO")) {
					int reqlen = strlen(args[2]) + strlen(args[3]) + strlen(" \r\n") + 1;
					curproxy->check_req = malloc(reqlen);
					curproxy->check_len = snprintf(curproxy->check_req, reqlen,
								       "%s %s\r\n", args[2], args[3]); /* HELO hostname */
				} else {
					/* this just hits the default for now, but you could potentially expand it to allow for other stuff
					   though, it's unlikely you'd want to send anything other than an EHLO or HELO */
					curproxy->check_req = strdup(DEF_SMTP_CHECK_REQ); /* default request */
					curproxy->check_len = strlen(DEF_SMTP_CHECK_REQ);
				}
			}
			if (alertif_too_many_args_idx(2, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "pgsql-check")) {
			/* use PostgreSQL request to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_PGSQL_CHK;

			if (*(args[2])) {
				int cur_arg = 2;

				while (*(args[cur_arg])) {
					if (strcmp(args[cur_arg], "user") == 0) {
						char * packet;
						uint32_t packet_len;
						uint32_t pv;

						/* suboption header - needs additional argument for it */
						if (*(args[cur_arg+1]) == 0) {
							Alert("parsing [%s:%d] : '%s %s %s' expects <username> as argument.\n",
							      file, linenum, args[0], args[1], args[cur_arg]);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}

						/* uint32_t + uint32_t + strlen("user")+1 + strlen(username)+1 + 1 */
						packet_len = 4 + 4 + 5 + strlen(args[cur_arg + 1])+1 +1;
						pv = htonl(0x30000); /* protocol version 3.0 */

						packet = calloc(1, packet_len);

						memcpy(packet + 4, &pv, 4);

						/* copy "user" */
						memcpy(packet + 8, "user", 4);

						/* copy username */
						memcpy(packet + 13, args[cur_arg+1], strlen(args[cur_arg+1]));

						free(curproxy->check_req);
						curproxy->check_req = packet;
						curproxy->check_len = packet_len;

						packet_len = htonl(packet_len);
						memcpy(packet, &packet_len, 4);
						cur_arg += 2;
					} else {
						/* unknown suboption - catchall */
						Alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user'.\n",
						      file, linenum, args[0], args[1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				} /* end while loop */
			}
			if (alertif_too_many_args_idx(2, 1, file, linenum, args, &err_code))
				goto out;
		}

		else if (!strcmp(args[1], "redis-check")) {
			/* use REDIS PING request to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_REDIS_CHK;

			curproxy->check_req = malloc(sizeof(DEF_REDIS_CHECK_REQ) - 1);
			memcpy(curproxy->check_req, DEF_REDIS_CHECK_REQ, sizeof(DEF_REDIS_CHECK_REQ) - 1);
			curproxy->check_len = sizeof(DEF_REDIS_CHECK_REQ) - 1;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}

		else if (!strcmp(args[1], "mysql-check")) {
			/* use MYSQL request to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_MYSQL_CHK;

			/* This is an example of a MySQL >=4.0 client Authentication packet kindly provided by Cyril Bonte.
			 * const char mysql40_client_auth_pkt[] = {
			 * 	"\x0e\x00\x00"	// packet length
			 * 	"\x01"		// packet number
			 * 	"\x00\x00"	// client capabilities
			 * 	"\x00\x00\x01"	// max packet
			 * 	"haproxy\x00"	// username (null terminated string)
			 * 	"\x00"		// filler (always 0x00)
			 * 	"\x01\x00\x00"	// packet length
			 * 	"\x00"		// packet number
			 * 	"\x01"		// COM_QUIT command
			 * };
			 */

			/* This is an example of a MySQL >=4.1  client Authentication packet provided by Nenad Merdanovic.
			 * const char mysql41_client_auth_pkt[] = {
			 * 	"\x0e\x00\x00\"		// packet length
			 * 	"\x01"			// packet number
			 * 	"\x00\x00\x00\x00"	// client capabilities
			 * 	"\x00\x00\x00\x01"	// max packet
			 *	"\x21"			// character set (UTF-8)
			 *	char[23]		// All zeroes
			 * 	"haproxy\x00"		// username (null terminated string)
			 * 	"\x00"			// filler (always 0x00)
			 * 	"\x01\x00\x00"		// packet length
			 * 	"\x00"			// packet number
			 * 	"\x01"			// COM_QUIT command
			 * };
			 */


			if (*(args[2])) {
				int cur_arg = 2;

				while (*(args[cur_arg])) {
					if (strcmp(args[cur_arg], "user") == 0) {
						char *mysqluser;
						int packetlen, reqlen, userlen;

						/* suboption header - needs additional argument for it */
						if (*(args[cur_arg+1]) == 0) {
							Alert("parsing [%s:%d] : '%s %s %s' expects <username> as argument.\n",
							      file, linenum, args[0], args[1], args[cur_arg]);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
						mysqluser = args[cur_arg + 1];
						userlen   = strlen(mysqluser);

						if (*(args[cur_arg+2])) {
							if (!strcmp(args[cur_arg+2], "post-41")) {
		                                                packetlen = userlen + 7 + 27;
								reqlen    = packetlen + 9;

								free(curproxy->check_req);
								curproxy->check_req = calloc(1, reqlen);
								curproxy->check_len = reqlen;

								snprintf(curproxy->check_req, 4, "%c%c%c",
									((unsigned char) packetlen & 0xff),
									((unsigned char) (packetlen >> 8) & 0xff),
									((unsigned char) (packetlen >> 16) & 0xff));

								curproxy->check_req[3] = 1;
								curproxy->check_req[5] = 130;
								curproxy->check_req[11] = 1;
								curproxy->check_req[12] = 33;
								memcpy(&curproxy->check_req[36], mysqluser, userlen);
								curproxy->check_req[36 + userlen + 1 + 1]     = 1;
								curproxy->check_req[36 + userlen + 1 + 1 + 4] = 1;
								cur_arg += 3;
							} else {
								Alert("parsing [%s:%d] : keyword '%s' only supports option 'post-41'.\n", file, linenum, args[cur_arg+2]);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
						} else {
							packetlen = userlen + 7;
							reqlen    = packetlen + 9;

							free(curproxy->check_req);
							curproxy->check_req = calloc(1, reqlen);
							curproxy->check_len = reqlen;

							snprintf(curproxy->check_req, 4, "%c%c%c",
								((unsigned char) packetlen & 0xff),
								((unsigned char) (packetlen >> 8) & 0xff),
								((unsigned char) (packetlen >> 16) & 0xff));

							curproxy->check_req[3] = 1;
							curproxy->check_req[5] = 128;
							curproxy->check_req[8] = 1;
							memcpy(&curproxy->check_req[9], mysqluser, userlen);
							curproxy->check_req[9 + userlen + 1 + 1]     = 1;
							curproxy->check_req[9 + userlen + 1 + 1 + 4] = 1;
							cur_arg += 2;
						}
					} else {
						/* unknown suboption - catchall */
						Alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user'.\n",
						      file, linenum, args[0], args[1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				} /* end while loop */
			}
		}
		else if (!strcmp(args[1], "ldap-check")) {
			/* use LDAP request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_LDAP_CHK;

			curproxy->check_req = malloc(sizeof(DEF_LDAP_CHECK_REQ) - 1);
			memcpy(curproxy->check_req, DEF_LDAP_CHECK_REQ, sizeof(DEF_LDAP_CHECK_REQ) - 1);
			curproxy->check_len = sizeof(DEF_LDAP_CHECK_REQ) - 1;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "tcp-check")) {
			/* use raw TCPCHK send/expect to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_TCPCHK_CHK;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "external-check")) {
			/* excute an external command to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_EXT_CHK;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "forwardfor")) {
			int cur_arg;

			/* insert x-forwarded-for field, but not for the IP address listed as an except.
			 * set default options (ie: bitfield, header name, etc) 
			 */

			curproxy->options |= PR_O_FWDFOR | PR_O_FF_ALWAYS;

			free(curproxy->fwdfor_hdr_name);
			curproxy->fwdfor_hdr_name = strdup(DEF_XFORWARDFOR_HDR);
			curproxy->fwdfor_hdr_len  = strlen(DEF_XFORWARDFOR_HDR);

			/* loop to go through arguments - start at 2, since 0+1 = "option" "forwardfor" */
			cur_arg = 2;
			while (*(args[cur_arg])) {
				if (!strcmp(args[cur_arg], "except")) {
					/* suboption except - needs additional argument for it */
					if (!*(args[cur_arg+1]) || !str2net(args[cur_arg+1], 1, &curproxy->except_net, &curproxy->except_mask)) {
						Alert("parsing [%s:%d] : '%s %s %s' expects <address>[/mask] as argument.\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					/* flush useless bits */
					curproxy->except_net.s_addr &= curproxy->except_mask.s_addr;
					cur_arg += 2;
				} else if (!strcmp(args[cur_arg], "header")) {
					/* suboption header - needs additional argument for it */
					if (*(args[cur_arg+1]) == 0) {
						Alert("parsing [%s:%d] : '%s %s %s' expects <header_name> as argument.\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					free(curproxy->fwdfor_hdr_name);
					curproxy->fwdfor_hdr_name = strdup(args[cur_arg+1]);
					curproxy->fwdfor_hdr_len  = strlen(curproxy->fwdfor_hdr_name);
					cur_arg += 2;
				} else if (!strcmp(args[cur_arg], "if-none")) {
					curproxy->options &= ~PR_O_FF_ALWAYS;
					cur_arg += 1;
				} else {
					/* unknown suboption - catchall */
					Alert("parsing [%s:%d] : '%s %s' only supports optional values: 'except', 'header' and 'if-none'.\n",
					      file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			} /* end while loop */
		}
		else if (!strcmp(args[1], "originalto")) {
			int cur_arg;

			/* insert x-original-to field, but not for the IP address listed as an except.
			 * set default options (ie: bitfield, header name, etc)
			 */

			curproxy->options |= PR_O_ORGTO;

			free(curproxy->orgto_hdr_name);
			curproxy->orgto_hdr_name = strdup(DEF_XORIGINALTO_HDR);
			curproxy->orgto_hdr_len  = strlen(DEF_XORIGINALTO_HDR);

			/* loop to go through arguments - start at 2, since 0+1 = "option" "originalto" */
			cur_arg = 2;
			while (*(args[cur_arg])) {
				if (!strcmp(args[cur_arg], "except")) {
					/* suboption except - needs additional argument for it */
					if (!*(args[cur_arg+1]) || !str2net(args[cur_arg+1], 1, &curproxy->except_to, &curproxy->except_mask_to)) {
						Alert("parsing [%s:%d] : '%s %s %s' expects <address>[/mask] as argument.\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					/* flush useless bits */
					curproxy->except_to.s_addr &= curproxy->except_mask_to.s_addr;
					cur_arg += 2;
				} else if (!strcmp(args[cur_arg], "header")) {
					/* suboption header - needs additional argument for it */
					if (*(args[cur_arg+1]) == 0) {
						Alert("parsing [%s:%d] : '%s %s %s' expects <header_name> as argument.\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					free(curproxy->orgto_hdr_name);
					curproxy->orgto_hdr_name = strdup(args[cur_arg+1]);
					curproxy->orgto_hdr_len  = strlen(curproxy->orgto_hdr_name);
					cur_arg += 2;
				} else {
					/* unknown suboption - catchall */
					Alert("parsing [%s:%d] : '%s %s' only supports optional values: 'except' and 'header'.\n",
					      file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			} /* end while loop */
		}
		else {
			Alert("parsing [%s:%d] : unknown option '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		goto out;
	}
	else if (!strcmp(args[0], "default_backend")) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a backend name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->defbe.name);
		curproxy->defbe.name = strdup(args[1]);

		if (alertif_too_many_args_idx(1, 0, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "redispatch") || !strcmp(args[0], "redisp")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!already_warned(WARN_REDISPATCH_DEPRECATED))
			Warning("parsing [%s:%d]: keyword '%s' is deprecated in favor of 'option redispatch', and will not be supported by future versions.\n",
				file, linenum, args[0]);
		err_code |= ERR_WARN;
		/* enable reconnections to dispatch */
		curproxy->options |= PR_O_REDISP;

		if (alertif_too_many_args_idx(1, 0, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "http-reuse")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "never") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_NEVR;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "safe") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_SAFE;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "aggressive") == 0) {
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_AGGR;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "always") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_ALWS;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else {
			Alert("parsing [%s:%d] : '%s' only supports 'never', 'safe', 'aggressive', 'always'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "http-check")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "disable-on-404") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options |= PR_O_DISABLE404;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "send-state") == 0) {
			/* enable emission of the apparent state of a server in HTTP checks */
			curproxy->options2 |= PR_O2_CHK_SNDST;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "expect") == 0) {
			const char *ptr_arg;
			int cur_arg;

			if (curproxy->options2 & PR_O2_EXP_TYPE) {
				Alert("parsing [%s:%d] : '%s %s' already specified.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			cur_arg = 2;
			/* consider exclamation marks, sole or at the beginning of a word */
			while (*(ptr_arg = args[cur_arg])) {
				while (*ptr_arg == '!') {
					curproxy->options2 ^= PR_O2_EXP_INV;
					ptr_arg++;
				}
				if (*ptr_arg)
					break;
				cur_arg++;
			}
			/* now ptr_arg points to the beginning of a word past any possible
			 * exclamation mark, and cur_arg is the argument which holds this word.
			 */
			if (strcmp(ptr_arg, "status") == 0) {
				if (!*(args[cur_arg + 1])) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <string> as an argument.\n",
					      file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_STS;
				free(curproxy->expect_str);
				curproxy->expect_str = strdup(args[cur_arg + 1]);
			}
			else if (strcmp(ptr_arg, "string") == 0) {
				if (!*(args[cur_arg + 1])) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <string> as an argument.\n",
					      file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_STR;
				free(curproxy->expect_str);
				curproxy->expect_str = strdup(args[cur_arg + 1]);
			}
			else if (strcmp(ptr_arg, "rstatus") == 0) {
				if (!*(args[cur_arg + 1])) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <regex> as an argument.\n",
					      file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_RSTS;
				free(curproxy->expect_str);
				if (curproxy->expect_regex) {
					regex_free(curproxy->expect_regex);
					free(curproxy->expect_regex);
					curproxy->expect_regex = NULL;
				}
				curproxy->expect_str = strdup(args[cur_arg + 1]);
				curproxy->expect_regex = calloc(1, sizeof(*curproxy->expect_regex));
				error = NULL;
				if (!regex_comp(args[cur_arg + 1], curproxy->expect_regex, 1, 1, &error)) {
					Alert("parsing [%s:%d] : '%s %s %s' : bad regular expression '%s': %s.\n",
					      file, linenum, args[0], args[1], ptr_arg, args[cur_arg + 1], error);
					free(error);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			else if (strcmp(ptr_arg, "rstring") == 0) {
				if (!*(args[cur_arg + 1])) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <regex> as an argument.\n",
					      file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_RSTR;
				free(curproxy->expect_str);
				if (curproxy->expect_regex) {
					regex_free(curproxy->expect_regex);
					free(curproxy->expect_regex);
					curproxy->expect_regex = NULL;
				}
				curproxy->expect_str = strdup(args[cur_arg + 1]);
				curproxy->expect_regex = calloc(1, sizeof(*curproxy->expect_regex));
				error = NULL;
				if (!regex_comp(args[cur_arg + 1], curproxy->expect_regex, 1, 1, &error)) {
					Alert("parsing [%s:%d] : '%s %s %s' : bad regular expression '%s': %s.\n",
					      file, linenum, args[0], args[1], ptr_arg, args[cur_arg + 1], error);
					free(error);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			else {
				Alert("parsing [%s:%d] : '%s %s' only supports [!] 'status', 'string', 'rstatus', 'rstring', found '%s'.\n",
				      file, linenum, args[0], args[1], ptr_arg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			Alert("parsing [%s:%d] : '%s' only supports 'disable-on-404', 'send-state', 'expect'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tcp-check")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "comment") == 0) {
			int cur_arg;
			struct tcpcheck_rule *tcpcheck;

			cur_arg = 1;
			tcpcheck = calloc(1, sizeof(*tcpcheck));
			tcpcheck->action = TCPCHK_ACT_COMMENT;

			if (!*args[cur_arg + 1]) {
				Alert("parsing [%s:%d] : '%s' expects a comment string.\n",
					file, linenum, args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			tcpcheck->comment = strdup(args[cur_arg + 1]);

			LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			if (alertif_too_many_args_idx(1, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "connect") == 0) {
			const char *ptr_arg;
			int cur_arg;
			struct tcpcheck_rule *tcpcheck;

			/* check if first rule is also a 'connect' action */
			tcpcheck = LIST_NEXT(&curproxy->tcpcheck_rules, struct tcpcheck_rule *, list);
			while (&tcpcheck->list != &curproxy->tcpcheck_rules &&
			       tcpcheck->action == TCPCHK_ACT_COMMENT) {
				tcpcheck = LIST_NEXT(&tcpcheck->list, struct tcpcheck_rule *, list);
			}

			if (&tcpcheck->list != &curproxy->tcpcheck_rules
			    && tcpcheck->action != TCPCHK_ACT_CONNECT) {
				Alert("parsing [%s:%d] : first step MUST also be a 'connect' when there is a 'connect' step in the tcp-check ruleset.\n",
				      file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			cur_arg = 2;
			tcpcheck = calloc(1, sizeof(*tcpcheck));
			tcpcheck->action = TCPCHK_ACT_CONNECT;

			/* parsing each parameters to fill up the rule */
			while (*(ptr_arg = args[cur_arg])) {
				/* tcp port */
				if (strcmp(args[cur_arg], "port") == 0) {
					if ( (atol(args[cur_arg + 1]) > 65535) ||
							(atol(args[cur_arg + 1]) < 1) ){
						Alert("parsing [%s:%d] : '%s %s %s' expects a valid TCP port (from range 1 to 65535), got %s.\n",
						      file, linenum, args[0], args[1], "port", args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->port = atol(args[cur_arg + 1]);
					cur_arg += 2;
				}
				/* send proxy protocol */
				else if (strcmp(args[cur_arg], "send-proxy") == 0) {
					tcpcheck->conn_opts |= TCPCHK_OPT_SEND_PROXY;
					cur_arg++;
				}
#ifdef USE_OPENSSL
				else if (strcmp(args[cur_arg], "ssl") == 0) {
					curproxy->options |= PR_O_TCPCHK_SSL;
					tcpcheck->conn_opts |= TCPCHK_OPT_SSL;
					cur_arg++;
				}
#endif /* USE_OPENSSL */
				/* comment for this tcpcheck line */
				else if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						Alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							file, linenum, args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
					cur_arg += 2;
				}
				else {
#ifdef USE_OPENSSL
					Alert("parsing [%s:%d] : '%s %s' expects 'comment', 'port', 'send-proxy' or 'ssl' but got '%s' as argument.\n",
#else /* USE_OPENSSL */
					Alert("parsing [%s:%d] : '%s %s' expects 'comment', 'port', 'send-proxy' or but got '%s' as argument.\n",
#endif /* USE_OPENSSL */
					      file, linenum, args[0], args[1], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

			}

			LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
		}
		else if (strcmp(args[1], "send") == 0) {
			if (! *(args[2]) ) {
				/* SEND string expected */
				Alert("parsing [%s:%d] : '%s %s %s' expects <STRING> as argument.\n",
				      file, linenum, args[0], args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else {
				struct tcpcheck_rule *tcpcheck;

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_SEND;
				tcpcheck->string_len = strlen(args[2]);
				tcpcheck->string = strdup(args[2]);
				tcpcheck->expect_regex = NULL;

				/* comment for this tcpcheck line */
				if (strcmp(args[3], "comment") == 0) {
					if (!*args[4]) {
						Alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							file, linenum, args[3]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[4]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
		}
		else if (strcmp(args[1], "send-binary") == 0) {
			if (! *(args[2]) ) {
				/* SEND binary string expected */
				Alert("parsing [%s:%d] : '%s %s %s' expects <BINARY STRING> as argument.\n",
				      file, linenum, args[0], args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else {
				struct tcpcheck_rule *tcpcheck;
				char *err = NULL;

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_SEND;
				if (parse_binary(args[2], &tcpcheck->string, &tcpcheck->string_len, &err) == 0) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <BINARY STRING> as argument, but %s\n",
					      file, linenum, args[0], args[1], args[2], err);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tcpcheck->expect_regex = NULL;

				/* comment for this tcpcheck line */
				if (strcmp(args[3], "comment") == 0) {
					if (!*args[4]) {
						Alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							file, linenum, args[3]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[4]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
		}
		else if (strcmp(args[1], "expect") == 0) {
			const char *ptr_arg;
			int cur_arg;
			int inverse = 0;

			if (curproxy->options2 & PR_O2_EXP_TYPE) {
				Alert("parsing [%s:%d] : '%s %s' already specified.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			cur_arg = 2;
			/* consider exclamation marks, sole or at the beginning of a word */
			while (*(ptr_arg = args[cur_arg])) {
				while (*ptr_arg == '!') {
					inverse = !inverse;
					ptr_arg++;
				}
				if (*ptr_arg)
					break;
				cur_arg++;
			}
			/* now ptr_arg points to the beginning of a word past any possible
			 * exclamation mark, and cur_arg is the argument which holds this word.
			 */
			if (strcmp(ptr_arg, "binary") == 0) {
				struct tcpcheck_rule *tcpcheck;
				char *err = NULL;

				if (!*(args[cur_arg + 1])) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <binary string> as an argument.\n",
					      file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_EXPECT;
				if (parse_binary(args[cur_arg + 1], &tcpcheck->string, &tcpcheck->string_len, &err) == 0) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <BINARY STRING> as argument, but %s\n",
					      file, linenum, args[0], args[1], args[2], err);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tcpcheck->expect_regex = NULL;
				tcpcheck->inverse = inverse;

				/* tcpcheck comment */
				cur_arg += 2;
				if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						Alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
			else if (strcmp(ptr_arg, "string") == 0) {
				struct tcpcheck_rule *tcpcheck;

				if (!*(args[cur_arg + 1])) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <string> as an argument.\n",
					      file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_EXPECT;
				tcpcheck->string_len = strlen(args[cur_arg + 1]);
				tcpcheck->string = strdup(args[cur_arg + 1]);
				tcpcheck->expect_regex = NULL;
				tcpcheck->inverse = inverse;

				/* tcpcheck comment */
				cur_arg += 2;
				if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						Alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
			else if (strcmp(ptr_arg, "rstring") == 0) {
				struct tcpcheck_rule *tcpcheck;

				if (!*(args[cur_arg + 1])) {
					Alert("parsing [%s:%d] : '%s %s %s' expects <regex> as an argument.\n",
					      file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_EXPECT;
				tcpcheck->string_len = 0;
				tcpcheck->string = NULL;
				tcpcheck->expect_regex = calloc(1, sizeof(*tcpcheck->expect_regex));
				error = NULL;
				if (!regex_comp(args[cur_arg + 1], tcpcheck->expect_regex, 1, 1, &error)) {
					Alert("parsing [%s:%d] : '%s %s %s' : bad regular expression '%s': %s.\n",
					      file, linenum, args[0], args[1], ptr_arg, args[cur_arg + 1], error);
					free(error);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tcpcheck->inverse = inverse;

				/* tcpcheck comment */
				cur_arg += 2;
				if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						Alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
			else {
				Alert("parsing [%s:%d] : '%s %s' only supports [!] 'binary', 'string', 'rstring', found '%s'.\n",
				      file, linenum, args[0], args[1], ptr_arg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			Alert("parsing [%s:%d] : '%s' only supports 'comment', 'connect', 'send' or 'expect'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "monitor")) {
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "fail") == 0) {
			/* add a condition to fail monitor requests */
			if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
				Alert("parsing [%s:%d] : '%s %s' requires either 'if' or 'unless' followed by a condition.\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing a '%s %s' condition : %s.\n",
				      file, linenum, args[0], args[1], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			LIST_ADDQ(&curproxy->mon_fail_cond, &cond->list);
		}
		else {
			Alert("parsing [%s:%d] : '%s' only supports 'fail'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
#ifdef TPROXY
	else if (!strcmp(args[0], "transparent")) {
		/* enable transparent proxy connections */
		curproxy->options |= PR_O_TRANSP;
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
	}
#endif
	else if (!strcmp(args[0], "maxconn")) {  /* maxconn */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], " Maybe you want 'fullconn' instead ?"))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->maxconn = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "backlog")) {  /* backlog */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->backlog = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "fullconn")) {  /* fullconn */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], " Maybe you want 'maxconn' instead ?"))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->fullconn = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "grace")) {  /* grace time (ms) */
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a time in milliseconds.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		err = parse_time_err(args[1], &val, TIME_UNIT_MS);
		if (err) {
			Alert("parsing [%s:%d] : unexpected character '%c' in grace time.\n",
			      file, linenum, *err);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->grace = val;
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "dispatch")) {  /* dispatch address */
		struct sockaddr_storage *sk;
		int port1, port2;
		struct protocol *proto;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		sk = str2sa_range(args[1], &port1, &port2, &errmsg, NULL, NULL, 1);
		if (!sk) {
			Alert("parsing [%s:%d] : '%s' : %s\n", file, linenum, args[0], errmsg);
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

		if (port1 != port2) {
			Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'.\n",
			      file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!port1) {
			Alert("parsing [%s:%d] : '%s' : missing port number in '%s', <addr:port> expected.\n",
			      file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		curproxy->dispatch_addr = *sk;
		curproxy->options |= PR_O_DISPATCH;
	}
	else if (!strcmp(args[0], "balance")) {  /* set balancing with optional algorithm */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (backend_parse_balance((const char **)args + 1, &errmsg, curproxy) < 0) {
			Alert("parsing [%s:%d] : %s %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "hash-type")) { /* set hashing method */
		/**
		 * The syntax for hash-type config element is
		 * hash-type {map-based|consistent} [[<algo>] avalanche]
		 *
		 * The default hash function is sdbm for map-based and sdbm+avalanche for consistent.
		 */
		curproxy->lbprm.algo &= ~(BE_LB_HASH_TYPE | BE_LB_HASH_FUNC | BE_LB_HASH_MOD);

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "consistent") == 0) {	/* use consistent hashing */
			curproxy->lbprm.algo |= BE_LB_HASH_CONS;
		}
		else if (strcmp(args[1], "map-based") == 0) {	/* use map-based hashing */
			curproxy->lbprm.algo |= BE_LB_HASH_MAP;
		}
		else if (strcmp(args[1], "avalanche") == 0) {
			Alert("parsing [%s:%d] : experimental feature '%s %s' is not supported anymore, please use '%s map-based sdbm avalanche' instead.\n", file, linenum, args[0], args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else {
			Alert("parsing [%s:%d] : '%s' only supports 'consistent' and 'map-based'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* set the hash function to use */
		if (!*args[2]) {
			/* the default algo is sdbm */
			curproxy->lbprm.algo |= BE_LB_HFCN_SDBM;

			/* if consistent with no argument, then avalanche modifier is also applied */
			if ((curproxy->lbprm.algo & BE_LB_HASH_TYPE) == BE_LB_HASH_CONS)
				curproxy->lbprm.algo |= BE_LB_HMOD_AVAL;
		} else {
			/* set the hash function */
			if (!strcmp(args[2], "sdbm")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_SDBM;
			}
			else if (!strcmp(args[2], "djb2")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_DJB2;
			}
			else if (!strcmp(args[2], "wt6")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_WT6;
			}
			else if (!strcmp(args[2], "crc32")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_CRC32;
			}
			else {
				Alert("parsing [%s:%d] : '%s' only supports 'sdbm', 'djb2', 'crc32', or 'wt6' hash functions.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* set the hash modifier */
			if (!strcmp(args[3], "avalanche")) {
				curproxy->lbprm.algo |= BE_LB_HMOD_AVAL;
			}
			else if (*args[3]) {
				Alert("parsing [%s:%d] : '%s' only supports 'avalanche' as a modifier for hash functions.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
	}
	else if (strcmp(args[0], "unique-id-format") == 0) {
		if (!*(args[1])) {
			Alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*(args[2])) {
			Alert("parsing [%s:%d] : %s expects only one argument, don't forget to escape spaces!\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->conf.uniqueid_format_string);
		curproxy->conf.uniqueid_format_string = strdup(args[1]);

		free(curproxy->conf.uif_file);
		curproxy->conf.uif_file = strdup(curproxy->conf.args.file);
		curproxy->conf.uif_line = curproxy->conf.args.line;
	}

	else if (strcmp(args[0], "unique-id-header") == 0) {
		if (!*(args[1])) {
			Alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->header_unique_id);
		curproxy->header_unique_id = strdup(args[1]);
	}

	else if (strcmp(args[0], "log-format") == 0) {
		if (!*(args[1])) {
			Alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*(args[2])) {
			Alert("parsing [%s:%d] : %s expects only one argument, don't forget to escape spaces!\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (curproxy->conf.logformat_string != default_http_log_format &&
		    curproxy->conf.logformat_string != default_tcp_log_format &&
		    curproxy->conf.logformat_string != clf_http_log_format)
			free(curproxy->conf.logformat_string);
		curproxy->conf.logformat_string = strdup(args[1]);

		free(curproxy->conf.lfs_file);
		curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
		curproxy->conf.lfs_line = curproxy->conf.args.line;

		/* get a chance to improve log-format error reporting by
		 * reporting the correct line-number when possible.
		 */
		if (curproxy != &defproxy && !(curproxy->cap & PR_CAP_FE)) {
			Warning("parsing [%s:%d] : backend '%s' : 'log-format' directive is ignored in backends.\n",
				file, linenum, curproxy->id);
			err_code |= ERR_WARN;
		}
	}
	else if (!strcmp(args[0], "log-format-sd")) {
		if (!*(args[1])) {
			Alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*(args[2])) {
			Alert("parsing [%s:%d] : %s expects only one argument, don't forget to escape spaces!\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (curproxy->conf.logformat_sd_string != default_rfc5424_sd_log_format)
			free(curproxy->conf.logformat_sd_string);
		curproxy->conf.logformat_sd_string = strdup(args[1]);

		free(curproxy->conf.lfsd_file);
		curproxy->conf.lfsd_file = strdup(curproxy->conf.args.file);
		curproxy->conf.lfsd_line = curproxy->conf.args.line;

		/* get a chance to improve log-format-sd error reporting by
		 * reporting the correct line-number when possible.
		 */
		if (curproxy != &defproxy && !(curproxy->cap & PR_CAP_FE)) {
			Warning("parsing [%s:%d] : backend '%s' : 'log-format-sd' directive is ignored in backends.\n",
				file, linenum, curproxy->id);
			err_code |= ERR_WARN;
		}
	}
	else if (!strcmp(args[0], "log-tag")) {  /* tag to report to syslog */
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a tag for use in syslog.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_destroy(&curproxy->log_tag);
		chunk_initstr(&curproxy->log_tag, strdup(args[1]));
	}
	else if (!strcmp(args[0], "log") && kwm == KWM_NO) {
		/* delete previous herited or defined syslog servers */
		struct logsrv *back;

		if (*(args[1]) != 0) {
			Alert("parsing [%s:%d]:%s : 'no log' does not expect arguments.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		list_for_each_entry_safe(tmplogsrv, back, &curproxy->logsrvs, list) {
			LIST_DEL(&tmplogsrv->list);
			free(tmplogsrv);
		}
	}
	else if (!strcmp(args[0], "log")) {  /* syslog server address */
		struct logsrv *logsrv;

		if (*(args[1]) && *(args[2]) == 0 && !strcmp(args[1], "global")) {
			/* copy global.logrsvs linked list to the end of curproxy->logsrvs */
			list_for_each_entry(tmplogsrv, &global.logsrvs, list) {
				struct logsrv *node = malloc(sizeof(*node));
				memcpy(node, tmplogsrv, sizeof(struct logsrv));
				LIST_INIT(&node->list);
				LIST_ADDQ(&curproxy->logsrvs, &node->list);
			}
		}
		else if (*(args[1]) && *(args[2])) {
			struct sockaddr_storage *sk;
			int port1, port2;
			int arg = 0;
			int len = 0;

			logsrv = calloc(1, sizeof(*logsrv));

			/* just after the address, a length may be specified */
			if (strcmp(args[arg+2], "len") == 0) {
				len = atoi(args[arg+3]);
				if (len < 80 || len > 65535) {
					Alert("parsing [%s:%d] : invalid log length '%s', must be between 80 and 65535.\n",
					      file, linenum, args[arg+3]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				logsrv->maxlen = len;

				/* skip these two args */
				arg += 2;
			}
			else
				logsrv->maxlen = MAX_SYSLOG_LEN;

			if (logsrv->maxlen > global.max_syslog_len) {
				global.max_syslog_len = logsrv->maxlen;
				logheader = realloc(logheader, global.max_syslog_len + 1);
				logheader_rfc5424 = realloc(logheader_rfc5424, global.max_syslog_len + 1);
				logline = realloc(logline, global.max_syslog_len + 1);
				logline_rfc5424 = realloc(logline_rfc5424, global.max_syslog_len + 1);
			}

			/* after the length, a format may be specified */
			if (strcmp(args[arg+2], "format") == 0) {
				logsrv->format = get_log_format(args[arg+3]);
				if (logsrv->format < 0) {
					Alert("parsing [%s:%d] : unknown log format '%s'\n", file, linenum, args[arg+3]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				/* skip these two args */
				arg += 2;
			}

			if (alertif_too_many_args_idx(3, arg + 1, file, linenum, args, &err_code))
				goto out;

			logsrv->facility = get_log_facility(args[arg+2]);
			if (logsrv->facility < 0) {
				Alert("parsing [%s:%d] : unknown log facility '%s'\n", file, linenum, args[arg+2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;

			}
	    
			logsrv->level = 7; /* max syslog level = debug */
			if (*(args[arg+3])) {
				logsrv->level = get_log_level(args[arg+3]);
				if (logsrv->level < 0) {
					Alert("parsing [%s:%d] : unknown optional log level '%s'\n", file, linenum, args[arg+3]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;

				}
			}

			logsrv->minlvl = 0; /* limit syslog level to this level (emerg) */
			if (*(args[arg+4])) {
				logsrv->minlvl = get_log_level(args[arg+4]);
				if (logsrv->minlvl < 0) {
					Alert("parsing [%s:%d] : unknown optional minimum log level '%s'\n", file, linenum, args[arg+4]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;

				}
			}

			sk = str2sa_range(args[1], &port1, &port2, &errmsg, NULL, NULL, 1);
			if (!sk) {
				Alert("parsing [%s:%d] : '%s': %s\n", file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			logsrv->addr = *sk;

			if (sk->ss_family == AF_INET || sk->ss_family == AF_INET6) {
				if (port1 != port2) {
					Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
					      file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!port1)
					set_host_port(&logsrv->addr, SYSLOG_PORT);
			}

			LIST_ADDQ(&curproxy->logsrvs, &logsrv->list);
		}
		else {
			Alert("parsing [%s:%d] : 'log' expects either <address[:port]> and <facility> or 'global' as arguments.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "source")) {  /* address to which we bind when connecting */
		int cur_arg;
		int port1, port2;
		struct sockaddr_storage *sk;
		struct protocol *proto;

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], and optionally '%s' <addr>, and '%s' <name>.\n",
			      file, linenum, "source", "usesrc", "interface");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* we must first clear any optional default setting */	
		curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
		free(curproxy->conn_src.iface_name);
		curproxy->conn_src.iface_name = NULL;
		curproxy->conn_src.iface_len = 0;

		sk = str2sa_range(args[1], &port1, &port2, &errmsg, NULL, NULL, 1);
		if (!sk) {
			Alert("parsing [%s:%d] : '%s %s' : %s\n",
			      file, linenum, args[0], args[1], errmsg);
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

		if (port1 != port2) {
			Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
			      file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->conn_src.source_addr = *sk;
		curproxy->conn_src.opts |= CO_SRC_BIND;

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside */
#if defined(CONFIG_HAP_TRANSPARENT)
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', or 'clientip' as argument.\n",
					      file, linenum, "usesrc");
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!strcmp(args[cur_arg + 1], "client")) {
					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_CLI;
				} else if (!strcmp(args[cur_arg + 1], "clientip")) {
					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_CIP;
				} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
					char *name, *end;

					name = args[cur_arg+1] + 7;
					while (isspace(*name))
						name++;

					end = name;
					while (*end && !isspace(*end) && *end != ',' && *end != ')')
						end++;

					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_DYN;
					curproxy->conn_src.bind_hdr_name = calloc(1, end - name + 1);
					curproxy->conn_src.bind_hdr_len = end - name;
					memcpy(curproxy->conn_src.bind_hdr_name, name, end - name);
					curproxy->conn_src.bind_hdr_name[end-name] = '\0';
					curproxy->conn_src.bind_hdr_occ = -1;

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
						curproxy->conn_src.bind_hdr_occ = strl2ic(name, end-name);
					}

					if (curproxy->conn_src.bind_hdr_occ < -MAX_HDR_HISTORY) {
						Alert("parsing [%s:%d] : usesrc hdr_ip(name,num) does not support negative"
						      " occurrences values smaller than %d.\n",
						      file, linenum, MAX_HDR_HISTORY);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				} else {
					struct sockaddr_storage *sk;

					sk = str2sa_range(args[cur_arg + 1], &port1, &port2, &errmsg, NULL, NULL, 1);
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
					curproxy->conn_src.tproxy_addr = *sk;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_ADDR;
				}
				global.last_checks |= LSTCHK_NETADM;
#else	/* no TPROXY support */
				Alert("parsing [%s:%d] : '%s' not allowed here because support for TPROXY was not compiled in.\n",
				      file, linenum, "usesrc");
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
				cur_arg += 2;
				continue;
			}

			if (!strcmp(args[cur_arg], "interface")) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s' : missing interface name.\n",
					      file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				free(curproxy->conn_src.iface_name);
				curproxy->conn_src.iface_name = strdup(args[cur_arg + 1]);
				curproxy->conn_src.iface_len  = strlen(curproxy->conn_src.iface_name);
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
			Alert("parsing [%s:%d] : '%s' only supports optional keywords '%s' and '%s'.\n",
			      file, linenum, args[0], "interface", "usesrc");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "usesrc")) {  /* address to use outside: needs "source" first */
		Alert("parsing [%s:%d] : '%s' only allowed after a '%s' statement.\n",
		      file, linenum, "usesrc", "source");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "cliexp") || !strcmp(args[0], "reqrep")) {  /* replace request header from a regex */
		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_REPLACE, 0,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqdel")) {  /* delete request header from a regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_REMOVE, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqdeny")) {  /* deny a request if a header matches this regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_DENY, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqpass")) {  /* pass this header without allowing or denying the request */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_PASS, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqallow")) {  /* allow a request if a header matches this regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_ALLOW, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqtarpit")) {  /* tarpit a request if a header matches this regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_TARPIT, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqirep")) {  /* replace request header from a regex, ignoring case */
		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_REPLACE, REG_ICASE,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqidel")) {  /* delete request header from a regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_REMOVE, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqideny")) {  /* deny a request if a header matches this regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_DENY, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqipass")) {  /* pass this header without allowing or denying the request */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_PASS, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqiallow")) {  /* allow a request if a header matches this regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_ALLOW, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqitarpit")) {  /* tarpit a request if a header matches this regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_REQ, ACT_TARPIT, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqadd")) {  /* add request header */
		struct cond_wordlist *wl;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <header> as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0)) {
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args+2, &errmsg)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing a '%s' condition : %s.\n",
				      file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			err_code |= warnif_cond_conflicts(cond,
			                                  (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
			                                  file, linenum);
		}
		else if (*args[2]) {
			Alert("parsing [%s:%d] : '%s' : Expecting nothing, 'if', or 'unless', got '%s'.\n",
			      file, linenum, args[0], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		wl = calloc(1, sizeof(*wl));
		wl->cond = cond;
		wl->s = strdup(args[1]);
		LIST_ADDQ(&curproxy->req_add, &wl->list);
		warnif_misplaced_reqadd(curproxy, file, linenum, args[0]);
	}
	else if (!strcmp(args[0], "srvexp") || !strcmp(args[0], "rsprep")) {  /* replace response header from a regex */
		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_RES, ACT_REPLACE, 0,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspdel")) {  /* delete response header from a regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_RES, ACT_REMOVE, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspdeny")) {  /* block response header from a regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_RES, ACT_DENY, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspirep")) {  /* replace response header from a regex ignoring case */
		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_RES, ACT_REPLACE, REG_ICASE,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspidel")) {  /* delete response header from a regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_RES, ACT_REMOVE, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspideny")) {  /* block response header from a regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   SMP_OPT_DIR_RES, ACT_DENY, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspadd")) {  /* add response header */
		struct cond_wordlist *wl;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <header> as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	
		if ((strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0)) {
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args+2, &errmsg)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing a '%s' condition : %s.\n",
				      file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			err_code |= warnif_cond_conflicts(cond,
			                                  (curproxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR,
			                                  file, linenum);
		}
		else if (*args[2]) {
			Alert("parsing [%s:%d] : '%s' : Expecting nothing, 'if', or 'unless', got '%s'.\n",
			      file, linenum, args[0], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		wl = calloc(1, sizeof(*wl));
		wl->cond = cond;
		wl->s = strdup(args[1]);
		LIST_ADDQ(&curproxy->rsp_add, &wl->list);
	}
	else if (!strcmp(args[0], "errorloc") ||
		 !strcmp(args[0], "errorloc302") ||
		 !strcmp(args[0], "errorloc303")) { /* error location */
		int errnum, errlen;
		char *err;

		if (warnifnotcap(curproxy, PR_CAP_FE | PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : <%s> expects <status_code> and <url> as arguments.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		errnum = atol(args[1]);
		if (!strcmp(args[0], "errorloc303")) {
			errlen = strlen(HTTP_303) + strlen(args[2]) + 5;
			err = malloc(errlen);
			errlen = snprintf(err, errlen, "%s%s\r\n\r\n", HTTP_303, args[2]);
		} else {
			errlen = strlen(HTTP_302) + strlen(args[2]) + 5;
			err = malloc(errlen);
			errlen = snprintf(err, errlen, "%s%s\r\n\r\n", HTTP_302, args[2]);
		}

		for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
			if (http_err_codes[rc] == errnum) {
				chunk_destroy(&curproxy->errmsg[rc]);
				chunk_initlen(&curproxy->errmsg[rc], err, errlen, errlen);
				break;
			}
		}

		if (rc >= HTTP_ERR_SIZE) {
			Warning("parsing [%s:%d] : status code %d not handled by '%s', error relocation will be ignored.\n",
				file, linenum, errnum, args[0]);
			free(err);
		}
	}
	else if (!strcmp(args[0], "errorfile")) { /* error message from a file */
		int errnum, errlen, fd;
		char *err;
		struct stat stat;

		if (warnifnotcap(curproxy, PR_CAP_FE | PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : <%s> expects <status_code> and <file> as arguments.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		fd = open(args[2], O_RDONLY);
		if ((fd < 0) || (fstat(fd, &stat) < 0)) {
			Alert("parsing [%s:%d] : error opening file <%s> for custom error message <%s>.\n",
			      file, linenum, args[2], args[1]);
			if (fd >= 0)
				close(fd);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (stat.st_size <= global.tune.bufsize) {
			errlen = stat.st_size;
		} else {
			Warning("parsing [%s:%d] : custom error message file <%s> larger than %d bytes. Truncating.\n",
				file, linenum, args[2], global.tune.bufsize);
			err_code |= ERR_WARN;
			errlen = global.tune.bufsize;
		}

		err = malloc(errlen); /* malloc() must succeed during parsing */
		errnum = read(fd, err, errlen);
		if (errnum != errlen) {
			Alert("parsing [%s:%d] : error reading file <%s> for custom error message <%s>.\n",
			      file, linenum, args[2], args[1]);
			close(fd);
			free(err);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		close(fd);

		errnum = atol(args[1]);
		for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
			if (http_err_codes[rc] == errnum) {
				chunk_destroy(&curproxy->errmsg[rc]);
				chunk_initlen(&curproxy->errmsg[rc], err, errlen, errlen);
				break;
			}
		}

		if (rc >= HTTP_ERR_SIZE) {
			Warning("parsing [%s:%d] : status code %d not handled by '%s', error customization will be ignored.\n",
				file, linenum, errnum, args[0]);
			err_code |= ERR_WARN;
			free(err);
		}
	}
	else {
		struct cfg_kw_list *kwl;
		int index;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_LISTEN)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
					/* prepare error message just in case */
					rc = kwl->kw[index].parse(args, CFG_LISTEN, curproxy, &defproxy, file, linenum, &errmsg);
					if (rc < 0) {
						Alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					else if (rc > 0) {
						Warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_WARN;
						goto out;
					}
					goto out;
				}
			}
		}

		Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
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
#ifdef CONFIG_HAP_NS
	const char *err;
	const char *item = args[0];

	if (!strcmp(item, "namespace_list")) {
		return 0;
	}
	else if (!strcmp(item, "namespace")) {
		size_t idx = 1;
		const char *current;
		while (*(current = args[idx++])) {
			err = invalid_char(current);
			if (err) {
				Alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
				      file, linenum, *err, item, current);
				return ERR_ALERT | ERR_FATAL;
			}

			if (netns_store_lookup(current, strlen(current))) {
				Alert("parsing [%s:%d]: Namespace '%s' is already added.\n",
				      file, linenum, current);
				return ERR_ALERT | ERR_FATAL;
			}
			if (!netns_store_insert(current)) {
				Alert("parsing [%s:%d]: Cannot open namespace '%s'.\n",
				      file, linenum, current);
				return ERR_ALERT | ERR_FATAL;
			}
		}
	}

	return 0;
#else
	Alert("parsing [%s:%d]: namespace support is not compiled in.",
			file, linenum);
	return ERR_ALERT | ERR_FATAL;
#endif
}

int
cfg_parse_users(const char *file, int linenum, char **args, int kwm)
{

	int err_code = 0;
	const char *err;

	if (!strcmp(args[0], "userlist")) {		/* new userlist */
		struct userlist *newul;

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
			      file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (newul = userlist; newul; newul = newul->next)
			if (!strcmp(newul->name, args[1])) {
				Warning("parsing [%s:%d]: ignoring duplicated userlist '%s'.\n",
					file, linenum, args[1]);
				err_code |= ERR_WARN;
				goto out;
			}

		newul = calloc(1, sizeof(*newul));
		if (!newul) {
			Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		newul->name = strdup(args[1]);
		if (!newul->name) {
			Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			free(newul);
			goto out;
		}

		newul->next = userlist;
		userlist = newul;

	} else if (!strcmp(args[0], "group")) {  	/* new group */
		int cur_arg;
		const char *err;
		struct auth_groups *ag;

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
			      file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!userlist)
			goto out;

		for (ag = userlist->groups; ag; ag = ag->next)
			if (!strcmp(ag->name, args[1])) {
				Warning("parsing [%s:%d]: ignoring duplicated group '%s' in userlist '%s'.\n",
				      file, linenum, args[1], userlist->name);
				err_code |= ERR_ALERT;
				goto out;
			}

		ag = calloc(1, sizeof(*ag));
		if (!ag) {
			Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		ag->name = strdup(args[1]);
		if (!ag) {
			Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		cur_arg = 2;

		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "users")) {
				ag->groupusers = strdup(args[cur_arg + 1]);
				cur_arg += 2;
				continue;
			} else {
				Alert("parsing [%s:%d]: '%s' only supports 'users' option.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		ag->next = userlist->groups;
		userlist->groups = ag;

	} else if (!strcmp(args[0], "user")) {		/* new user */
		struct auth_users *newuser;
		int cur_arg;

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (!userlist)
			goto out;

		for (newuser = userlist->users; newuser; newuser = newuser->next)
			if (!strcmp(newuser->user, args[1])) {
				Warning("parsing [%s:%d]: ignoring duplicated user '%s' in userlist '%s'.\n",
				      file, linenum, args[1], userlist->name);
				err_code |= ERR_ALERT;
				goto out;
			}

		newuser = calloc(1, sizeof(*newuser));
		if (!newuser) {
			Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		newuser->user = strdup(args[1]);

		newuser->next = userlist->users;
		userlist->users = newuser;

		cur_arg = 2;

		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "password")) {
#ifdef CONFIG_HAP_CRYPT
				if (!crypt("", args[cur_arg + 1])) {
					Alert("parsing [%s:%d]: the encrypted password used for user '%s' is not supported by crypt(3).\n",
						file, linenum, newuser->user);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
#else
				Warning("parsing [%s:%d]: no crypt(3) support compiled, encrypted passwords will not work.\n",
					file, linenum);
				err_code |= ERR_ALERT;
#endif
				newuser->pass = strdup(args[cur_arg + 1]);
				cur_arg += 2;
				continue;
			} else if (!strcmp(args[cur_arg], "insecure-password")) {
				newuser->pass = strdup(args[cur_arg + 1]);
				newuser->flags |= AU_O_INSECURE;
				cur_arg += 2;
				continue;
			} else if (!strcmp(args[cur_arg], "groups")) {
				newuser->u.groups_names = strdup(args[cur_arg + 1]);
				cur_arg += 2;
				continue;
			} else {
				Alert("parsing [%s:%d]: '%s' only supports 'password', 'insecure-password' and 'groups' options.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
	} else {
		Alert("parsing [%s:%d]: unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "users");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

out:
	return err_code;
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
	struct cfg_section *cs = NULL;
	struct cfg_section *ics;
	int readbytes = 0;

	if ((thisline = malloc(sizeof(*thisline) * linesize)) == NULL) {
		Alert("parsing [%s] : out of memory.\n", file);
		return -1;
	}

	/* Register internal sections */
	if (!cfg_register_section("listen",   cfg_parse_listen) ||
	    !cfg_register_section("frontend", cfg_parse_listen) ||
	    !cfg_register_section("backend",  cfg_parse_listen) ||
	    !cfg_register_section("defaults", cfg_parse_listen) ||
	    !cfg_register_section("global",   cfg_parse_global) ||
	    !cfg_register_section("userlist", cfg_parse_users)  ||
	    !cfg_register_section("peers",    cfg_parse_peers)  ||
	    !cfg_register_section("mailers",  cfg_parse_mailers) ||
	    !cfg_register_section("namespace_list",    cfg_parse_netns) ||
	    !cfg_register_section("resolvers", cfg_parse_resolvers))
		return -1;

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
		int dquote = 0;  /* double quote */
		int squote = 0;  /* simple quote */

		linenum++;

		end = line + strlen(line);

		if (end-line == linesize-1 && *(end-1) != '\n') {
			/* Check if we reached the limit and the last char is not \n.
			 * Watch out for the last line without the terminating '\n'!
			 */
			char *newline;
			int newlinesize = linesize * 2;

			newline = realloc(thisline, sizeof(*thisline) * newlinesize);
			if (newline == NULL) {
				Alert("parsing [%s:%d]: line too long, cannot allocate memory.\n",
				      file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				continue;
			}

			readbytes = linesize - 1;
			linesize = newlinesize;
			thisline = newline;
			continue;
		}

		readbytes = 0;

		/* skip leading spaces */
		while (isspace((unsigned char)*line))
			line++;

		arg = 0;
		args[arg] = line;

		while (*line && arg < MAX_LINE_ARGS) {
			if (*line == '"' && !squote) {  /* double quote outside single quotes */
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				memmove(line, line + 1, end - line);
				end--;
			}
			else if (*line == '\'' && !dquote) { /* single quote outside double quotes */
				if (squote)
					squote = 0;
				else
					squote = 1;
				memmove(line, line + 1, end - line);
				end--;
			}
			else if (*line == '\\' && !squote) {
			/* first, we'll replace \\, \<space>, \#, \r, \n, \t, \xXX with their
			 * C equivalent value. Other combinations left unchanged (eg: \1).
			 */
				int skip = 0;
				if (line[1] == ' ' || line[1] == '\\' || line[1] == '#') {
					*line = line[1];
					skip = 1;
				}
				else if (line[1] == 'r') {
					*line = '\r';
					skip = 1;
				}
				else if (line[1] == 'n') {
					*line = '\n';
					skip = 1;
				}
				else if (line[1] == 't') {
					*line = '\t';
					skip = 1;
				}
				else if (line[1] == 'x') {
					if ((line + 3 < end) && ishex(line[2]) && ishex(line[3])) {
						unsigned char hex1, hex2;
						hex1 = toupper(line[2]) - '0';
						hex2 = toupper(line[3]) - '0';
						if (hex1 > 9) hex1 -= 'A' - '9' - 1;
						if (hex2 > 9) hex2 -= 'A' - '9' - 1;
						*line = (hex1<<4) + hex2;
						skip = 3;
					}
					else {
						Alert("parsing [%s:%d] : invalid or incomplete '\\x' sequence in '%s'.\n", file, linenum, args[0]);
						err_code |= ERR_ALERT | ERR_FATAL;
					}
				} else if (line[1] == '"') {
					*line = '"';
					skip = 1;
				} else if (line[1] == '\'') {
					*line = '\'';
					skip = 1;
				} else if (line[1] == '$' && dquote) { /* escaping of $ only inside double quotes */
					*line = '$';
					skip = 1;
				}
				if (skip) {
					memmove(line + 1, line + 1 + skip, end - (line + skip));
					end -= skip;
				}
				line++;
			}
			else if ((!squote && !dquote && *line == '#') || *line == '\n' || *line == '\r') {
				/* end of string, end of loop */
				*line = 0;
				break;
			}
			else if (!squote && !dquote && isspace((unsigned char)*line)) {
				/* a non-escaped space is an argument separator */
				*line++ = '\0';
				while (isspace((unsigned char)*line))
					line++;
				args[++arg] = line;
			}
			else if (dquote && *line == '$') {
				/* environment variables are evaluated inside double quotes */
				char *var_beg;
				char *var_end;
				char save_char;
				char *value;
				int val_len;
				int newlinesize;
				int braces = 0;

				var_beg = line + 1;
				var_end = var_beg;

				if (*var_beg == '{') {
					var_beg++;
					var_end++;
					braces = 1;
				}

				if (!isalpha((int)(unsigned char)*var_beg) && *var_beg != '_') {
					Alert("parsing [%s:%d] : Variable expansion: Unrecognized character '%c' in variable name.\n", file, linenum, *var_beg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto next_line; /* skip current line */
				}

				while (isalnum((int)(unsigned char)*var_end) || *var_end == '_')
					var_end++;

				save_char = *var_end;
				*var_end = '\0';
				value = getenv(var_beg);
				*var_end = save_char;
				val_len = value ? strlen(value) : 0;

				if (braces) {
					if (*var_end == '}') {
						var_end++;
						braces = 0;
					} else {
						Alert("parsing [%s:%d] : Variable expansion: Mismatched braces.\n", file, linenum);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto next_line; /* skip current line */
					}
				}

				newlinesize = (end - thisline) - (var_end - line) + val_len + 1;

				/* if not enough space in thisline */
				if (newlinesize  > linesize) {
					char *newline;

					newline = realloc(thisline, newlinesize * sizeof(*thisline));
					if (newline == NULL) {
						Alert("parsing [%s:%d] : Variable expansion: Not enough memory.\n", file, linenum);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto next_line; /* slip current line */
					}
					/* recompute pointers if realloc returns a new pointer */
					if (newline != thisline) {
						int i;
						int diff;

						for (i = 0; i <= arg; i++) {
							diff = args[i] - thisline;
							args[i] = newline + diff;
						}

						diff = var_end - thisline;
						var_end = newline + diff;
						diff = end - thisline;
						end = newline + diff;
						diff = line - thisline;
						line = newline + diff;
						thisline = newline;
					}
					linesize = newlinesize;
				}

				/* insert value inside the line */
				memmove(line + val_len, var_end, end - var_end + 1);
				memcpy(line, value, val_len);
				end += val_len - (var_end - line);
				line += val_len;
			}
			else {
				line++;
			}
		}

		if (dquote) {
			Alert("parsing [%s:%d] : Mismatched double quotes.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (squote) {
			Alert("parsing [%s:%d] : Mismatched simple quotes.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		/* empty line */
		if (!**args)
			continue;

		if (*line) {
			/* we had to stop due to too many args.
			 * Let's terminate the string, print the offending part then cut the
			 * last arg.
			 */
			while (*line && *line != '#' && *line != '\n' && *line != '\r')
				line++;
			*line = '\0';

			Alert("parsing [%s:%d]: line too long, truncating at word %d, position %ld: <%s>.\n",
			      file, linenum, arg + 1, (long)(args[arg] - thisline + 1), args[arg]);
			err_code |= ERR_ALERT | ERR_FATAL;
			args[arg] = line;
		}

		/* zero out remaining args and ensure that at least one entry
		 * is zeroed out.
		 */
		while (++arg <= MAX_LINE_ARGS) {
			args[arg] = line;
		}

		/* check for keyword modifiers "no" and "default" */
		if (!strcmp(args[0], "no")) {
			char *tmp;

			kwm = KWM_NO;
			tmp = args[0];
			for (arg=0; *args[arg+1]; arg++)
				args[arg] = args[arg+1];		// shift args after inversion
			*tmp = '\0'; 					// fix the next arg to \0
			args[arg] = tmp;
		}
		else if (!strcmp(args[0], "default")) {
			kwm = KWM_DEF;
			for (arg=0; *args[arg+1]; arg++)
				args[arg] = args[arg+1];		// shift args after inversion
		}

		if (kwm != KWM_STD && strcmp(args[0], "option") != 0 && 	\
		     strcmp(args[0], "log") != 0) {
			Alert("parsing [%s:%d]: negation/default currently supported only for options and log.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		/* detect section start */
		list_for_each_entry(ics, &sections, list) {
			if (strcmp(args[0], ics->section_name) == 0) {
				cursection = ics->section_name;
				cs = ics;
				break;
			}
		}

		/* else it's a section keyword */
		if (cs)
			err_code |= cs->section_parser(file, linenum, args, kwm);
		else {
			Alert("parsing [%s:%d]: unknown keyword '%s' out of section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (err_code & ERR_ABORT)
			break;
	}
	cursection = NULL;
	free(thisline);
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

	if (from->state == PR_STSTOPPED)
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
	struct server *newsrv = NULL;
	int err_code = 0;
	unsigned int next_pxid = 1;
	struct bind_conf *bind_conf;

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

	pool2_capture = create_pool("capture", global.tune.cookie_len, MEM_F_SHARED);

	/* Post initialisation of the users and groups lists. */
	err_code = userlist_postinit();
	if (err_code != ERR_NONE)
		goto out;

	/* first, we will invert the proxy list order */
	curproxy = NULL;
	while (proxy) {
		struct proxy *next;

		next = proxy->next;
		proxy->next = curproxy;
		curproxy = proxy;
		if (!next)
			break;
		proxy = next;
	}

	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		struct switching_rule *rule;
		struct server_rule *srule;
		struct sticking_rule *mrule;
		struct act_rule *trule;
		struct act_rule *hrqrule;
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


		if (curproxy->state == PR_STSTOPPED) {
			/* ensure we don't keep listeners uselessly bound */
			stop_proxy(curproxy);
			free((void *)curproxy->table.peers.name);
			curproxy->table.peers.p = NULL;
			continue;
		}

		/* Check multi-process mode compatibility for the current proxy */

		if (curproxy->bind_proc) {
			/* an explicit bind-process was specified, let's check how many
			 * processes remain.
			 */
			nbproc = my_popcountl(curproxy->bind_proc);

			curproxy->bind_proc &= nbits(global.nbproc);
			if (!curproxy->bind_proc && nbproc == 1) {
				Warning("Proxy '%s': the process specified on the 'bind-process' directive refers to a process number that is higher than global.nbproc. The proxy has been forced to run on process 1 only.\n", curproxy->id);
				curproxy->bind_proc = 1;
			}
			else if (!curproxy->bind_proc && nbproc > 1) {
				Warning("Proxy '%s': all processes specified on the 'bind-process' directive refer to numbers that are all higher than global.nbproc. The directive was ignored and the proxy will run on all processes.\n", curproxy->id);
				curproxy->bind_proc = 0;
			}
		}

		/* check and reduce the bind-proc of each listener */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			unsigned long mask;

			if (!bind_conf->bind_proc)
				continue;

			mask = nbits(global.nbproc);
			if (curproxy->bind_proc)
				mask &= curproxy->bind_proc;
			/* mask cannot be null here thanks to the previous checks */

			nbproc = my_popcountl(bind_conf->bind_proc);
			bind_conf->bind_proc &= mask;

			if (!bind_conf->bind_proc && nbproc == 1) {
				Warning("Proxy '%s': the process number specified on the 'process' directive of 'bind %s' at [%s:%d] refers to a process not covered by the proxy. This has been fixed by forcing it to run on the proxy's first process only.\n",
					curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
				bind_conf->bind_proc = mask & ~(mask - 1);
			}
			else if (!bind_conf->bind_proc && nbproc > 1) {
				Warning("Proxy '%s': the process range specified on the 'process' directive of 'bind %s' at [%s:%d] only refers to processes not covered by the proxy. The directive was ignored so that all of the proxy's processes are used.\n",
					curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
				bind_conf->bind_proc = 0;
			}
		}

		switch (curproxy->mode) {
		case PR_MODE_HEALTH:
			cfgerr += proxy_cfg_ensure_no_http(curproxy);
			if (!(curproxy->cap & PR_CAP_FE)) {
				Alert("config : %s '%s' cannot be in health mode as it has no frontend capability.\n",
				      proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}

			if (curproxy->srv != NULL)
				Warning("config : servers will be ignored for %s '%s'.\n",
					proxy_type_str(curproxy), curproxy->id);
			break;

		case PR_MODE_TCP:
			cfgerr += proxy_cfg_ensure_no_http(curproxy);
			break;

		case PR_MODE_HTTP:
			curproxy->http_needed = 1;
			break;
		}

		if ((curproxy->cap & PR_CAP_FE) && LIST_ISEMPTY(&curproxy->conf.listeners)) {
			Warning("config : %s '%s' has no 'bind' directive. Please declare it as a backend if this was intended.\n",
			        proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if ((curproxy->cap & PR_CAP_BE) && (curproxy->mode != PR_MODE_HEALTH)) {
			if (curproxy->lbprm.algo & BE_LB_KIND) {
				if (curproxy->options & PR_O_TRANSP) {
					Alert("config : %s '%s' cannot use both transparent and balance mode.\n",
					      proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				}
#ifdef WE_DONT_SUPPORT_SERVERLESS_LISTENERS
				else if (curproxy->srv == NULL) {
					Alert("config : %s '%s' needs at least 1 server in balance mode.\n",
					      proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				}
#endif
				else if (curproxy->options & PR_O_DISPATCH) {
					Warning("config : dispatch address of %s '%s' will be ignored in balance mode.\n",
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

		if ((curproxy->options2 & PR_O2_CHK_ANY) != PR_O2_HTTP_CHK) {
			if (curproxy->options & PR_O_DISABLE404) {
				Warning("config : '%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
					"disable-on-404", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O_DISABLE404;
			}
			if (curproxy->options2 & PR_O2_CHK_SNDST) {
				Warning("config : '%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
					"send-state", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O2_CHK_SNDST;
			}
		}

		if ((curproxy->options2 & PR_O2_CHK_ANY) == PR_O2_EXT_CHK) {
			if (!global.external_check) {
				Alert("Proxy '%s' : '%s' unable to find required 'global.external-check'.\n",
				      curproxy->id, "option external-check");
				cfgerr++;
			}
			if (!curproxy->check_command) {
				Alert("Proxy '%s' : '%s' unable to find required 'external-check command'.\n",
				      curproxy->id, "option external-check");
				cfgerr++;
			}
		}

		if (curproxy->email_alert.set) {
		    if (!(curproxy->email_alert.mailers.name && curproxy->email_alert.from && curproxy->email_alert.to)) {
			    Warning("config : 'email-alert' will be ignored for %s '%s' (the presence any of "
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
				Warning("config : '%s' will be ignored for %s '%s' (requires 'option external-check').\n",
					"external-check command", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				clear = 1;
			}
			if (curproxy->check_command[0] != '/' && !curproxy->check_path) {
				Alert("Proxy '%s': '%s' does not have a leading '/' and 'external-check path' is not set.\n",
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
				Warning("config : '%s' will be ignored for %s '%s' (requires 'option external-check').\n",
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
				Alert("Proxy '%s': unable to find required default_backend: '%s'.\n",
					curproxy->id, curproxy->defbe.name);
				cfgerr++;
			} else if (target == curproxy) {
				Alert("Proxy '%s': loop detected for default_backend: '%s'.\n",
					curproxy->id, curproxy->defbe.name);
				cfgerr++;
			} else if (target->mode != curproxy->mode &&
				   !(curproxy->mode == PR_MODE_TCP && target->mode == PR_MODE_HTTP)) {

				Alert("%s %s '%s' (%s:%d) tries to use incompatible %s %s '%s' (%s:%d) as its default backend (see 'mode').\n",
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
					Warning("In proxy '%s', the 'default_backend' rule always has precedence over the servers, which will never be used.\n",
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
			parse_logformat_string(pxname, curproxy, &rule->be.expr, 0, SMP_VAL_FE_HRQ_HDR,
			                       curproxy->conf.args.file, curproxy->conf.args.line);
			node = LIST_NEXT(&rule->be.expr, struct logformat_node *, list);

			if (!LIST_ISEMPTY(&rule->be.expr)) {
				if (node->type != LOG_FMT_TEXT || node->list.n != &rule->be.expr) {
					rule->dynamic = 1;
					free(pxname);
					continue;
				}
				/* simple string: free the expression and fall back to static rule */
				free(node->arg);
				free(node);
			}

			rule->dynamic = 0;
			rule->be.name = pxname;

			target = proxy_be_by_name(rule->be.name);
			if (!target) {
				Alert("Proxy '%s': unable to find required use_backend: '%s'.\n",
					curproxy->id, rule->be.name);
				cfgerr++;
			} else if (target == curproxy) {
				Alert("Proxy '%s': loop detected for use_backend: '%s'.\n",
					curproxy->id, rule->be.name);
				cfgerr++;
			} else if (target->mode != curproxy->mode &&
				   !(curproxy->mode == PR_MODE_TCP && target->mode == PR_MODE_HTTP)) {

				Alert("%s %s '%s' (%s:%d) tries to use incompatible %s %s '%s' (%s:%d) in a 'use_backend' rule (see 'mode').\n",
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
			struct server *target = findserver(curproxy, srule->srv.name);

			if (!target) {
				Alert("config : %s '%s' : unable to find server '%s' referenced in a 'use-server' rule.\n",
				      proxy_type_str(curproxy), curproxy->id, srule->srv.name);
				cfgerr++;
				continue;
			}
			free((void *)srule->srv.name);
			srule->srv.ptr = target;
		}

		/* find the target table for 'stick' rules */
		list_for_each_entry(mrule, &curproxy->sticking_rules, list) {
			struct proxy *target;

			curproxy->be_req_ana |= AN_REQ_STICKING_RULES;
			if (mrule->flags & STK_IS_STORE)
				curproxy->be_rsp_ana |= AN_RES_STORE_RULES;

			if (mrule->table.name)
				target = proxy_tbl_by_name(mrule->table.name);
			else
				target = curproxy;

			if (!target) {
				Alert("Proxy '%s': unable to find stick-table '%s'.\n",
				      curproxy->id, mrule->table.name);
				cfgerr++;
			}
			else if (target->table.size == 0) {
				Alert("Proxy '%s': stick-table '%s' used but not configured.\n",
				      curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else if (!stktable_compatible_sample(mrule->expr,  target->table.type)) {
				Alert("Proxy '%s': type of fetch not usable with type of stick-table '%s'.\n",
				      curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else {
				free((void *)mrule->table.name);
				mrule->table.t = &(target->table);
				stktable_alloc_data_type(&target->table, STKTABLE_DT_SERVER_ID, NULL);
			}
		}

		/* find the target table for 'store response' rules */
		list_for_each_entry(mrule, &curproxy->storersp_rules, list) {
			struct proxy *target;

			curproxy->be_rsp_ana |= AN_RES_STORE_RULES;

			if (mrule->table.name)
				target = proxy_tbl_by_name(mrule->table.name);
			else
				target = curproxy;

			if (!target) {
				Alert("Proxy '%s': unable to find store table '%s'.\n",
				      curproxy->id, mrule->table.name);
				cfgerr++;
			}
			else if (target->table.size == 0) {
				Alert("Proxy '%s': stick-table '%s' used but not configured.\n",
				      curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else if (!stktable_compatible_sample(mrule->expr, target->table.type)) {
				Alert("Proxy '%s': type of fetch not usable with type of stick-table '%s'.\n",
				      curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else {
				free((void *)mrule->table.name);
				mrule->table.t = &(target->table);
				stktable_alloc_data_type(&target->table, STKTABLE_DT_SERVER_ID, NULL);
			}
		}

		/* find the target table for 'tcp-request' layer 4 rules */
		list_for_each_entry(trule, &curproxy->tcp_req.l4_rules, list) {
			struct proxy *target;

			if (trule->action < ACT_ACTION_TRK_SC0 || trule->action > ACT_ACTION_TRK_SCMAX)
				continue;

			if (trule->arg.trk_ctr.table.n)
				target = proxy_tbl_by_name(trule->arg.trk_ctr.table.n);
			else
				target = curproxy;

			if (!target) {
				Alert("Proxy '%s': unable to find table '%s' referenced by track-sc%d.\n",
				      curproxy->id, trule->arg.trk_ctr.table.n,
				      tcp_trk_idx(trule->action));
				cfgerr++;
			}
			else if (target->table.size == 0) {
				Alert("Proxy '%s': table '%s' used but not configured.\n",
				      curproxy->id, trule->arg.trk_ctr.table.n ? trule->arg.trk_ctr.table.n : curproxy->id);
				cfgerr++;
			}
			else if (!stktable_compatible_sample(trule->arg.trk_ctr.expr,  target->table.type)) {
				Alert("Proxy '%s': stick-table '%s' uses a type incompatible with the 'track-sc%d' rule.\n",
				      curproxy->id, trule->arg.trk_ctr.table.n ? trule->arg.trk_ctr.table.n : curproxy->id,
				      tcp_trk_idx(trule->action));
				cfgerr++;
			}
			else {
				free(trule->arg.trk_ctr.table.n);
				trule->arg.trk_ctr.table.t = &target->table;
				/* Note: if we decide to enhance the track-sc syntax, we may be able
				 * to pass a list of counters to track and allocate them right here using
				 * stktable_alloc_data_type().
				 */
			}
		}

		/* find the target table for 'tcp-request' layer 6 rules */
		list_for_each_entry(trule, &curproxy->tcp_req.inspect_rules, list) {
			struct proxy *target;

			if (trule->action < ACT_ACTION_TRK_SC0 || trule->action > ACT_ACTION_TRK_SCMAX)
				continue;

			if (trule->arg.trk_ctr.table.n)
				target = proxy_tbl_by_name(trule->arg.trk_ctr.table.n);
			else
				target = curproxy;

			if (!target) {
				Alert("Proxy '%s': unable to find table '%s' referenced by track-sc%d.\n",
				      curproxy->id, trule->arg.trk_ctr.table.n,
				      tcp_trk_idx(trule->action));
				cfgerr++;
			}
			else if (target->table.size == 0) {
				Alert("Proxy '%s': table '%s' used but not configured.\n",
				      curproxy->id, trule->arg.trk_ctr.table.n ? trule->arg.trk_ctr.table.n : curproxy->id);
				cfgerr++;
			}
			else if (!stktable_compatible_sample(trule->arg.trk_ctr.expr,  target->table.type)) {
				Alert("Proxy '%s': stick-table '%s' uses a type incompatible with the 'track-sc%d' rule.\n",
				      curproxy->id, trule->arg.trk_ctr.table.n ? trule->arg.trk_ctr.table.n : curproxy->id,
				      tcp_trk_idx(trule->action));
				cfgerr++;
			}
			else {
				free(trule->arg.trk_ctr.table.n);
				trule->arg.trk_ctr.table.t = &target->table;
				/* Note: if we decide to enhance the track-sc syntax, we may be able
				 * to pass a list of counters to track and allocate them right here using
				 * stktable_alloc_data_type().
				 */
			}
		}

		/* parse http-request capture rules to ensure id really exists */
		list_for_each_entry(hrqrule, &curproxy->http_req_rules, list) {
			if (hrqrule->action  != ACT_CUSTOM ||
			    hrqrule->action_ptr != http_action_req_capture_by_id)
				continue;

			if (hrqrule->arg.capid.idx >= curproxy->nb_req_cap) {
				Alert("Proxy '%s': unable to find capture id '%d' referenced by http-request capture rule.\n",
				      curproxy->id, hrqrule->arg.capid.idx);
				cfgerr++;
			}
		}

		/* parse http-response capture rules to ensure id really exists */
		list_for_each_entry(hrqrule, &curproxy->http_res_rules, list) {
			if (hrqrule->action  != ACT_CUSTOM ||
			    hrqrule->action_ptr != http_action_res_capture_by_id)
				continue;

			if (hrqrule->arg.capid.idx >= curproxy->nb_rsp_cap) {
				Alert("Proxy '%s': unable to find capture id '%d' referenced by http-response capture rule.\n",
				      curproxy->id, hrqrule->arg.capid.idx);
				cfgerr++;
			}
		}

		/* find the target table for 'http-request' layer 7 rules */
		list_for_each_entry(hrqrule, &curproxy->http_req_rules, list) {
			struct proxy *target;

			if (hrqrule->action < ACT_ACTION_TRK_SC0 || hrqrule->action > ACT_ACTION_TRK_SCMAX)
				continue;

			if (hrqrule->arg.trk_ctr.table.n)
				target = proxy_tbl_by_name(hrqrule->arg.trk_ctr.table.n);
			else
				target = curproxy;

			if (!target) {
				Alert("Proxy '%s': unable to find table '%s' referenced by track-sc%d.\n",
				      curproxy->id, hrqrule->arg.trk_ctr.table.n,
				      http_req_trk_idx(hrqrule->action));
				cfgerr++;
			}
			else if (target->table.size == 0) {
				Alert("Proxy '%s': table '%s' used but not configured.\n",
				      curproxy->id, hrqrule->arg.trk_ctr.table.n ? hrqrule->arg.trk_ctr.table.n : curproxy->id);
				cfgerr++;
			}
			else if (!stktable_compatible_sample(hrqrule->arg.trk_ctr.expr,  target->table.type)) {
				Alert("Proxy '%s': stick-table '%s' uses a type incompatible with the 'track-sc%d' rule.\n",
				      curproxy->id, hrqrule->arg.trk_ctr.table.n ? hrqrule->arg.trk_ctr.table.n : curproxy->id,
				      http_req_trk_idx(hrqrule->action));
				cfgerr++;
			}
			else {
				free(hrqrule->arg.trk_ctr.table.n);
				hrqrule->arg.trk_ctr.table.t = &target->table;
				/* Note: if we decide to enhance the track-sc syntax, we may be able
				 * to pass a list of counters to track and allocate them right here using
				 * stktable_alloc_data_type().
				 */
			}
		}

		/* move any "block" rules at the beginning of the http-request rules */
		if (!LIST_ISEMPTY(&curproxy->block_rules)) {
			/* insert block_rules into http_req_rules at the beginning */
			curproxy->block_rules.p->n    = curproxy->http_req_rules.n;
			curproxy->http_req_rules.n->p = curproxy->block_rules.p;
			curproxy->block_rules.n->p    = &curproxy->http_req_rules;
			curproxy->http_req_rules.n    = curproxy->block_rules.n;
			LIST_INIT(&curproxy->block_rules);
		}

		if (curproxy->table.peers.name) {
			struct peers *curpeers = peers;

			for (curpeers = peers; curpeers; curpeers = curpeers->next) {
				if (strcmp(curpeers->id, curproxy->table.peers.name) == 0) {
					free((void *)curproxy->table.peers.name);
					curproxy->table.peers.p = curpeers;
					break;
				}
			}

			if (!curpeers) {
				Alert("Proxy '%s': unable to find sync peers '%s'.\n",
				      curproxy->id, curproxy->table.peers.name);
				free((void *)curproxy->table.peers.name);
				curproxy->table.peers.p = NULL;
				cfgerr++;
			}
			else if (curpeers->state == PR_STSTOPPED) {
				/* silently disable this peers section */
				curproxy->table.peers.p = NULL;
			}
			else if (!curpeers->peers_fe) {
				Alert("Proxy '%s': unable to find local peer '%s' in peers section '%s'.\n",
				      curproxy->id, localpeer, curpeers->id);
				curproxy->table.peers.p = NULL;
				cfgerr++;
			}
		}


		if (curproxy->email_alert.mailers.name) {
			struct mailers *curmailers = mailers;

			for (curmailers = mailers; curmailers; curmailers = curmailers->next) {
				if (strcmp(curmailers->id, curproxy->email_alert.mailers.name) == 0) {
					free(curproxy->email_alert.mailers.name);
					curproxy->email_alert.mailers.m = curmailers;
					curmailers->users++;
					break;
				}
			}

			if (!curmailers) {
				Alert("Proxy '%s': unable to find mailers '%s'.\n",
				      curproxy->id, curproxy->email_alert.mailers.name);
				free_email_alert(curproxy);
				cfgerr++;
			}
		}

		if (curproxy->uri_auth && !(curproxy->uri_auth->flags & ST_CONVDONE) &&
		    !LIST_ISEMPTY(&curproxy->uri_auth->http_req_rules) &&
		    (curproxy->uri_auth->userlist || curproxy->uri_auth->auth_realm )) {
			Alert("%s '%s': stats 'auth'/'realm' and 'http-request' can't be used at the same time.\n",
			      "proxy", curproxy->id);
			cfgerr++;
			goto out_uri_auth_compat;
		}

		if (curproxy->uri_auth && curproxy->uri_auth->userlist && !(curproxy->uri_auth->flags & ST_CONVDONE)) {
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

			curproxy->uri_auth->flags |= ST_CONVDONE;
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
			parse_logformat_string(curproxy->conf.logformat_string, curproxy, &curproxy->logformat, LOG_OPT_MANDATORY,
					       SMP_VAL_FE_LOG_END, curproxy->conf.lfs_file, curproxy->conf.lfs_line);
			curproxy->conf.args.file = NULL;
			curproxy->conf.args.line = 0;
		}

		if (curproxy->conf.logformat_sd_string) {
			curproxy->conf.args.ctx = ARGC_LOGSD;
			curproxy->conf.args.file = curproxy->conf.lfsd_file;
			curproxy->conf.args.line = curproxy->conf.lfsd_line;
			parse_logformat_string(curproxy->conf.logformat_sd_string, curproxy, &curproxy->logformat_sd, LOG_OPT_MANDATORY,
					       SMP_VAL_FE_LOG_END, curproxy->conf.lfsd_file, curproxy->conf.lfsd_line);
			add_to_logformat_list(NULL, NULL, LF_SEPARATOR, &curproxy->logformat_sd);
			curproxy->conf.args.file = NULL;
			curproxy->conf.args.line = 0;
		}

		if (curproxy->conf.uniqueid_format_string) {
			curproxy->conf.args.ctx = ARGC_UIF;
			curproxy->conf.args.file = curproxy->conf.uif_file;
			curproxy->conf.args.line = curproxy->conf.uif_line;
			parse_logformat_string(curproxy->conf.uniqueid_format_string, curproxy, &curproxy->format_unique_id, LOG_OPT_HTTP,
					       (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
					       curproxy->conf.uif_file, curproxy->conf.uif_line);
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
			Warning("config : missing timeouts for %s '%s'.\n"
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

		if ((curproxy->options2 & PR_O2_CHK_ANY) == PR_O2_SSL3_CHK) {
			curproxy->check_len = sizeof(sslv3_client_hello_pkt) - 1;
			curproxy->check_req = malloc(curproxy->check_len);
			memcpy(curproxy->check_req, sslv3_client_hello_pkt, curproxy->check_len);
		}

		if (!LIST_ISEMPTY(&curproxy->tcpcheck_rules) &&
		    (curproxy->options2 & PR_O2_CHK_ANY) != PR_O2_TCPCHK_CHK) {
			Warning("config : %s '%s' uses tcp-check rules without 'option tcp-check', so the rules are ignored.\n",
				proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		/* ensure that cookie capture length is not too large */
		if (curproxy->capture_len >= global.tune.cookie_len) {
			Warning("config : truncating capture length to %d bytes for %s '%s'.\n",
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
					Warning("config : backend '%s' configured to load server state file from global section 'server-state-file' directive. Unfortunately, 'server-state-file' is not set!\n",
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
					Warning("parsing [%s:%d] : %s '%s', another server named '%s' was defined without an explicit ID at line %d, this is not recommended.\n",
						newsrv->conf.file, newsrv->conf.line,
						proxy_type_str(curproxy), curproxy->id,
						newsrv->id, other_srv->conf.line);
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

#ifdef USE_OPENSSL
			if (newsrv->use_ssl || newsrv->check.use_ssl)
				cfgerr += ssl_sock_prepare_srv_ctx(newsrv, curproxy);
#endif /* USE_OPENSSL */

			/* set the check type on the server */
			newsrv->check.type = curproxy->options2 & PR_O2_CHK_ANY;

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
						Alert("config : %s '%s', server '%s': unable to find required proxy '%s' for tracking.\n",
							proxy_type_str(curproxy), curproxy->id,
							newsrv->id, pname);
						cfgerr++;
						goto next_srv;
					}
				} else
					px = curproxy;

				srv = findserver(px, sname);
				if (!srv) {
					Alert("config : %s '%s', server '%s': unable to find required server '%s' for tracking.\n",
						proxy_type_str(curproxy), curproxy->id,
						newsrv->id, sname);
					cfgerr++;
					goto next_srv;
				}

				if (!(srv->check.state & CHK_ST_CONFIGURED) &&
				    !(srv->agent.state & CHK_ST_CONFIGURED) &&
				    !srv->track && !srv->trackit) {
					Alert("config : %s '%s', server '%s': unable to use %s/%s for "
					      "tracking as it does not have any check nor agent enabled.\n",
					      proxy_type_str(curproxy), curproxy->id,
					      newsrv->id, px->id, srv->id);
					cfgerr++;
					goto next_srv;
				}

				for (loop = srv->track; loop && loop != newsrv; loop = loop->track);

				if (loop) {
					Alert("config : %s '%s', server '%s': unable to track %s/%s as it "
					      "belongs to a tracking chain looping back to %s/%s.\n",
					      proxy_type_str(curproxy), curproxy->id,
					      newsrv->id, px->id, srv->id, px->id, loop->id);
					cfgerr++;
					goto next_srv;
				}

				if (curproxy != px &&
					(curproxy->options & PR_O_DISABLE404) != (px->options & PR_O_DISABLE404)) {
					Alert("config : %s '%s', server '%s': unable to use %s/%s for"
						"tracking: disable-on-404 option inconsistency.\n",
						proxy_type_str(curproxy), curproxy->id,
						newsrv->id, px->id, srv->id);
					cfgerr++;
					goto next_srv;
				}

				/* if the other server is forced disabled, we have to do the same here */
				if (srv->admin & SRV_ADMF_MAINT) {
					newsrv->admin |= SRV_ADMF_IMAINT;
					newsrv->state = SRV_ST_STOPPED;
					newsrv->check.health = 0;
				}

				newsrv->track = srv;
				newsrv->tracknext = srv->trackers;
				srv->trackers = newsrv;

				free(newsrv->trackit);
				newsrv->trackit = NULL;
			}

			/*
			 * resolve server's resolvers name and update the resolvers pointer
			 * accordingly
			 */
			if (newsrv->resolvers_id) {
				struct dns_resolvers *curr_resolvers;
				int found;

				found = 0;
				list_for_each_entry(curr_resolvers, &dns_resolvers, list) {
					if (!strcmp(curr_resolvers->id, newsrv->resolvers_id)) {
						found = 1;
						break;
					}
				}

				if (!found) {
					Alert("config : %s '%s', server '%s': unable to find required resolvers '%s'\n",
					proxy_type_str(curproxy), curproxy->id,
					newsrv->id, newsrv->resolvers_id);
					cfgerr++;
				} else {
					free(newsrv->resolvers_id);
					newsrv->resolvers_id = NULL;
					if (newsrv->resolution)
						newsrv->resolution->resolvers = curr_resolvers;
				}
			}
			else {
				/* if no resolvers section associated to this server
				 * we can clean up the associated resolution structure
				 */
				if (newsrv->resolution) {
					free(newsrv->resolution->hostname_dn);
					newsrv->resolution->hostname_dn = NULL;
					free(newsrv->resolution);
					newsrv->resolution = NULL;
				}
			}

		next_srv:
			newsrv = newsrv->next;
		}

		/* We have to initialize the server lookup mechanism depending
		 * on what LB algorithm was choosen.
		 */

		curproxy->lbprm.algo &= ~(BE_LB_LKUP | BE_LB_PROP_DYN);
		switch (curproxy->lbprm.algo & BE_LB_KIND) {
		case BE_LB_KIND_RR:
			if ((curproxy->lbprm.algo & BE_LB_PARM) == BE_LB_RR_STATIC) {
				curproxy->lbprm.algo |= BE_LB_LKUP_MAP;
				init_server_map(curproxy);
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

		if (curproxy->options & PR_O_LOGASAP)
			curproxy->to_log &= ~LW_BYTES;

		if ((curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HTTP) &&
		    (curproxy->cap & PR_CAP_FE) && LIST_ISEMPTY(&curproxy->logsrvs) &&
		    (!LIST_ISEMPTY(&curproxy->logformat) || !LIST_ISEMPTY(&curproxy->logformat_sd))) {
			Warning("config : log format ignored for %s '%s' since it has no log address.\n",
				proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if (curproxy->mode != PR_MODE_HTTP) {
			int optnum;

			if (curproxy->uri_auth) {
				Warning("config : 'stats' statement ignored for %s '%s' as it requires HTTP mode.\n",
					proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->uri_auth = NULL;
			}

			if (curproxy->options & (PR_O_FWDFOR | PR_O_FF_ALWAYS)) {
				Warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					"forwardfor", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~(PR_O_FWDFOR | PR_O_FF_ALWAYS);
			}

			if (curproxy->options & PR_O_ORGTO) {
				Warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					"originalto", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O_ORGTO;
			}

			for (optnum = 0; cfg_opts[optnum].name; optnum++) {
				if (cfg_opts[optnum].mode == PR_MODE_HTTP &&
				    (curproxy->cap & cfg_opts[optnum].cap) &&
				    (curproxy->options & cfg_opts[optnum].val)) {
					Warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
						cfg_opts[optnum].name, proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
					curproxy->options &= ~cfg_opts[optnum].val;
				}
			}

			for (optnum = 0; cfg_opts2[optnum].name; optnum++) {
				if (cfg_opts2[optnum].mode == PR_MODE_HTTP &&
				    (curproxy->cap & cfg_opts2[optnum].cap) &&
				    (curproxy->options2 & cfg_opts2[optnum].val)) {
					Warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
						cfg_opts2[optnum].name, proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
					curproxy->options2 &= ~cfg_opts2[optnum].val;
				}
			}

#if defined(CONFIG_HAP_TRANSPARENT)
			if (curproxy->conn_src.bind_hdr_occ) {
				curproxy->conn_src.bind_hdr_occ = 0;
				Warning("config : %s '%s' : ignoring use of header %s as source IP in non-HTTP mode.\n",
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
				Alert("config : %s '%s' : server cannot have cookie or redirect prefix in non-HTTP mode.\n",
				      proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}

			if ((curproxy->mode != PR_MODE_HTTP) && newsrv->cklen) {
				Warning("config : %s '%s' : ignoring cookie for server '%s' as HTTP mode is disabled.\n",
				        proxy_type_str(curproxy), curproxy->id, newsrv->id);
				err_code |= ERR_WARN;
			}

			if ((newsrv->flags & SRV_F_MAPPORTS) && (curproxy->options2 & PR_O2_RDPC_PRST)) {
				Warning("config : %s '%s' : RDP cookie persistence will not work for server '%s' because it lacks an explicit port number.\n",
				        proxy_type_str(curproxy), curproxy->id, newsrv->id);
				err_code |= ERR_WARN;
			}

#if defined(CONFIG_HAP_TRANSPARENT)
			if (curproxy->mode != PR_MODE_HTTP && newsrv->conn_src.bind_hdr_occ) {
				newsrv->conn_src.bind_hdr_occ = 0;
				Warning("config : %s '%s' : server %s cannot use header %s as source IP in non-HTTP mode.\n",
					proxy_type_str(curproxy), curproxy->id, newsrv->id, newsrv->conn_src.bind_hdr_name);
				err_code |= ERR_WARN;
			}
#endif
			newsrv = newsrv->next;
		}

		/* check if we have a frontend with "tcp-request content" looking at L7
		 * with no inspect-delay
		 */
		if ((curproxy->cap & PR_CAP_FE) && !curproxy->tcp_req.inspect_delay) {
			list_for_each_entry(trule, &curproxy->tcp_req.inspect_rules, list) {
				if (trule->action == ACT_TCP_CAPTURE &&
				    !(trule->arg.cap.expr->fetch->val & SMP_VAL_FE_SES_ACC))
					break;
				if  ((trule->action >= ACT_ACTION_TRK_SC0 && trule->action <= ACT_ACTION_TRK_SCMAX) &&
				     !(trule->arg.trk_ctr.expr->fetch->val & SMP_VAL_FE_SES_ACC))
					break;
			}

			if (&trule->list != &curproxy->tcp_req.inspect_rules) {
				Warning("config : %s '%s' : some 'tcp-request content' rules explicitly depending on request"
				        " contents were found in a frontend without any 'tcp-request inspect-delay' setting."
				        " This means that these rules will randomly find their contents. This can be fixed by"
					" setting the tcp-request inspect-delay.\n",
				        proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}
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

			/* both TCP and HTTP must check switching rules */
			curproxy->fe_req_ana |= AN_REQ_SWITCHING_RULES;

			/* Add filters analyzers if needed */
			if (!LIST_ISEMPTY(&curproxy->filter_configs)) {
				curproxy->fe_req_ana |= AN_FLT_ALL_FE;
				curproxy->fe_rsp_ana |= AN_FLT_ALL_FE;
				if (curproxy->mode == PR_MODE_HTTP) {
					curproxy->fe_req_ana |= AN_FLT_HTTP_HDRS;
					curproxy->fe_rsp_ana |= AN_FLT_HTTP_HDRS;
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
				curproxy->be_req_ana |= AN_FLT_ALL_BE;
				curproxy->be_rsp_ana |= AN_FLT_ALL_BE;
				if (curproxy->mode == PR_MODE_HTTP) {
					curproxy->be_req_ana |= AN_FLT_HTTP_HDRS;
					curproxy->be_rsp_ana |= AN_FLT_HTTP_HDRS;
				}
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

			mask = nbits(global.nbproc);
			if (global.stats_fe->bind_proc)
				mask &= global.stats_fe->bind_proc;

			if (bind_conf->bind_proc)
				mask &= bind_conf->bind_proc;

			/* stop here if more than one process is used */
			if (my_popcountl(mask) > 1)
				break;
		}
		if (&bind_conf->by_fe != &global.stats_fe->conf.bind) {
			Warning("stats socket will not work as expected in multi-process mode (nbproc > 1), you should force process binding globally using 'stats bind-process' or per socket using the 'process' attribute.\n");
		}
	}

	/* Make each frontend inherit bind-process from its listeners when not specified. */
	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		if (curproxy->bind_proc)
			continue;

		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			unsigned long mask;

			mask = bind_conf->bind_proc ? bind_conf->bind_proc : nbits(global.nbproc);
			curproxy->bind_proc |= mask;
		}

		if (!curproxy->bind_proc)
			curproxy->bind_proc = nbits(global.nbproc);
	}

	if (global.stats_fe) {
		list_for_each_entry(bind_conf, &global.stats_fe->conf.bind, by_fe) {
			unsigned long mask;

			mask = bind_conf->bind_proc ? bind_conf->bind_proc : 0;
			global.stats_fe->bind_proc |= mask;
		}
		if (!global.stats_fe->bind_proc)
			global.stats_fe->bind_proc = nbits(global.nbproc);
	}

	/* propagate bindings from frontends to backends. Don't do it if there
	 * are any fatal errors as we must not call it with unresolved proxies.
	 */
	if (!cfgerr) {
		for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
			if (curproxy->cap & PR_CAP_FE)
				propagate_processes(curproxy, NULL);
		}
	}

	/* Bind each unbound backend to all processes when not specified. */
	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		if (curproxy->bind_proc)
			continue;
		curproxy->bind_proc = nbits(global.nbproc);
	}

	/*******************************************************/
	/* At this step, all proxies have a non-null bind_proc */
	/*******************************************************/

	/* perform the final checks before creating tasks */

	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		struct listener *listener;
		unsigned int next_id;

#ifdef USE_OPENSSL
		/* Configure SSL for each bind line.
		 * Note: if configuration fails at some point, the ->ctx member
		 * remains NULL so that listeners can later detach.
		 */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			int alloc_ctx;

			if (!bind_conf->is_ssl) {
				if (bind_conf->default_ctx) {
					Warning("Proxy '%s': A certificate was specified but SSL was not enabled on bind '%s' at [%s:%d] (use 'ssl').\n",
					        curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
				}
				continue;
			}
			if (!bind_conf->default_ctx) {
				Alert("Proxy '%s': no SSL certificate specified for bind '%s' at [%s:%d] (use 'crt').\n",
				      curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr++;
				continue;
			}

			alloc_ctx = shared_context_init(global.tune.sslcachesize, (!global.tune.sslprivatecache && (global.nbproc > 1)) ? 1 : 0);
			if (alloc_ctx < 0) {
				if (alloc_ctx == SHCTX_E_INIT_LOCK)
					Alert("Unable to initialize the lock for the shared SSL session cache. You can retry using the global statement 'tune.ssl.force-private-cache' but it could increase CPU usage due to renegotiations if nbproc > 1.\n");
				else
					Alert("Unable to allocate SSL session cache.\n");
				cfgerr++;
				continue;
			}

			/* initialize all certificate contexts */
			cfgerr += ssl_sock_prepare_all_ctx(bind_conf, curproxy);

			/* initialize CA variables if the certificates generation is enabled */
			cfgerr += ssl_sock_load_ca(bind_conf, curproxy);
		}
#endif /* USE_OPENSSL */

		/* adjust this proxy's listeners */
		next_id = 1;
		list_for_each_entry(listener, &curproxy->conf.listeners, by_fe) {
			int nbproc;

			nbproc = my_popcountl(curproxy->bind_proc &
			                      listener->bind_conf->bind_proc &
			                      nbits(global.nbproc));

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
				listener->counters = calloc(1, sizeof(struct licounters));
				if (!listener->name)
					memprintf(&listener->name, "sock-%d", listener->luid);
			}

			if (curproxy->options & PR_O_TCP_NOLING)
				listener->options |= LI_O_NOLINGER;
			if (!listener->maxconn)
				listener->maxconn = curproxy->maxconn;
			if (!listener->backlog)
				listener->backlog = curproxy->backlog;
			if (!listener->maxaccept)
				listener->maxaccept = global.tune.maxaccept ? global.tune.maxaccept : 64;

			/* we want to have an optimal behaviour on single process mode to
			 * maximize the work at once, but in multi-process we want to keep
			 * some fairness between processes, so we target half of the max
			 * number of events to be balanced over all the processes the proxy
			 * is bound to. Rememeber that maxaccept = -1 must be kept as it is
			 * used to disable the limit.
			 */
			if (listener->maxaccept > 0) {
				if (nbproc > 1)
					listener->maxaccept = (listener->maxaccept + 1) / 2;
				listener->maxaccept = (listener->maxaccept + nbproc - 1) / nbproc;
			}

			listener->accept = session_accept_fd;
			listener->handler = process_stream;
			listener->analysers |= curproxy->fe_req_ana;
			listener->default_target = curproxy->default_target;

			if (!LIST_ISEMPTY(&curproxy->tcp_req.l4_rules))
				listener->options |= LI_O_TCP_RULES;

			if (curproxy->mon_mask.s_addr)
				listener->options |= LI_O_CHK_MONNET;

			/* smart accept mode is automatic in HTTP mode */
			if ((curproxy->options2 & PR_O2_SMARTACC) ||
			    ((curproxy->mode == PR_MODE_HTTP || listener->bind_conf->is_ssl) &&
			     !(curproxy->no_options2 & PR_O2_SMARTACC)))
				listener->options |= LI_O_NOQUICKACK;
		}

		/* Release unused SSL configs */
		list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
			if (bind_conf->is_ssl)
				continue;
#ifdef USE_OPENSSL
			ssl_sock_free_ca(bind_conf);
			ssl_sock_free_all_ctx(bind_conf);
			free(bind_conf->ca_file);
			free(bind_conf->ca_sign_file);
			free(bind_conf->ca_sign_pass);
			free(bind_conf->ciphers);
			free(bind_conf->ecdhe);
			free(bind_conf->crl_file);
			if(bind_conf->keys_ref) {
				free(bind_conf->keys_ref->filename);
				free(bind_conf->keys_ref->tlskeys);
				free(bind_conf->keys_ref);
			}
#endif /* USE_OPENSSL */
		}

		if (my_popcountl(curproxy->bind_proc & nbits(global.nbproc)) > 1) {
			if (curproxy->uri_auth) {
				int count, maxproc = 0;

				list_for_each_entry(bind_conf, &curproxy->conf.bind, by_fe) {
					count = my_popcountl(bind_conf->bind_proc);
					if (count > maxproc)
						maxproc = count;
				}
				/* backends have 0, frontends have 1 or more */
				if (maxproc != 1)
					Warning("Proxy '%s': in multi-process mode, stats will be"
					        " limited to process assigned to the current request.\n",
					        curproxy->id);

				if (!LIST_ISEMPTY(&curproxy->uri_auth->admin_rules)) {
					Warning("Proxy '%s': stats admin will not work correctly in multi-process mode.\n",
					        curproxy->id);
				}
			}
			if (!LIST_ISEMPTY(&curproxy->sticking_rules)) {
				Warning("Proxy '%s': sticking rules will not work correctly in multi-process mode.\n",
				        curproxy->id);
			}
		}

		/* create the task associated with the proxy */
		curproxy->task = task_new();
		if (curproxy->task) {
			curproxy->task->context = curproxy;
			curproxy->task->process = manage_proxy;
			/* no need to queue, it will be done automatically if some
			 * listener gets limited.
			 */
			curproxy->task->expire = TICK_ETERNITY;
		} else {
			Alert("Proxy '%s': no more memory when trying to allocate the management task\n",
			      curproxy->id);
			cfgerr++;
		}
	}

	/* automatically compute fullconn if not set. We must not do it in the
	 * loop above because cross-references are not yet fully resolved.
	 */
	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		/* If <fullconn> is not set, let's set it to 10% of the sum of
		 * the possible incoming frontend's maxconns.
		 */
		if (!curproxy->fullconn && (curproxy->cap & PR_CAP_BE)) {
			struct proxy *fe;
			int total = 0;

			/* sum up the number of maxconns of frontends which
			 * reference this backend at least once or which are
			 * the same one ('listen').
			 */
			for (fe = proxy; fe; fe = fe->next) {
				struct switching_rule *rule;
				int found = 0;

				if (!(fe->cap & PR_CAP_FE))
					continue;

				if (fe == curproxy)  /* we're on a "listen" instance */
					found = 1;

				if (fe->defbe.be == curproxy) /* "default_backend" */
					found = 1;

				/* check if a "use_backend" rule matches */
				if (!found) {
					list_for_each_entry(rule, &fe->switching_rules, list) {
						if (!rule->dynamic && rule->be.backend == curproxy) {
							found = 1;
							break;
						}
					}
				}

				/* now we've checked all possible ways to reference a backend
				 * from a frontend.
				 */
				if (!found)
					continue;
				total += fe->maxconn;
			}
			/* we have the sum of the maxconns in <total>. We only
			 * keep 10% of that sum to set the default fullconn, with
			 * a hard minimum of 1 (to avoid a divide by zero).
			 */
			curproxy->fullconn = (total + 9) / 10;
			if (!curproxy->fullconn)
				curproxy->fullconn = 1;
		}
	}

	/*
	 * Recount currently required checks.
	 */

	for (curproxy=proxy; curproxy; curproxy=curproxy->next) {
		int optnum;

		for (optnum = 0; cfg_opts[optnum].name; optnum++)
			if (curproxy->options & cfg_opts[optnum].val)
				global.last_checks |= cfg_opts[optnum].checks;

		for (optnum = 0; cfg_opts2[optnum].name; optnum++)
			if (curproxy->options2 & cfg_opts2[optnum].val)
				global.last_checks |= cfg_opts2[optnum].checks;
	}

	/* compute the required process bindings for the peers */
	for (curproxy = proxy; curproxy; curproxy = curproxy->next)
		if (curproxy->table.peers.p)
			curproxy->table.peers.p->peers_fe->bind_proc |= curproxy->bind_proc;

	if (peers) {
		struct peers *curpeers = peers, **last;
		struct peer *p, *pb;

		/* Remove all peers sections which don't have a valid listener,
		 * which are not used by any table, or which are bound to more
		 * than one process.
		 */
		last = &peers;
		while (*last) {
			curpeers = *last;

			if (curpeers->state == PR_STSTOPPED) {
				/* the "disabled" keyword was present */
				if (curpeers->peers_fe)
					stop_proxy(curpeers->peers_fe);
				curpeers->peers_fe = NULL;
			}
			else if (!curpeers->peers_fe) {
				Warning("Removing incomplete section 'peers %s' (no peer named '%s').\n",
					curpeers->id, localpeer);
			}
			else if (my_popcountl(curpeers->peers_fe->bind_proc) != 1) {
				/* either it's totally stopped or too much used */
				if (curpeers->peers_fe->bind_proc) {
					Alert("Peers section '%s': peers referenced by sections "
					      "running in different processes (%d different ones). "
					      "Check global.nbproc and all tables' bind-process "
					      "settings.\n", curpeers->id, my_popcountl(curpeers->peers_fe->bind_proc));
					cfgerr++;
				}
				stop_proxy(curpeers->peers_fe);
				curpeers->peers_fe = NULL;
			}
			else {
				peers_init_sync(curpeers);
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
			free(*last);
			*last = curpeers;
		}
	}

	/* initialize stick-tables on backend capable proxies. This must not
	 * be done earlier because the data size may be discovered while parsing
	 * other proxies.
	 */
	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		if (curproxy->state == PR_STSTOPPED)
			continue;

		if (!stktable_init(&curproxy->table)) {
			Alert("Proxy '%s': failed to initialize stick-table.\n", curproxy->id);
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

			Warning("Removing incomplete section 'mailers %s'.\n",
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
	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		if (curproxy->load_server_state_from_file == PR_SRV_STATE_FILE_LOCAL &&
		    curproxy->server_state_file_name == NULL)
			curproxy->server_state_file_name = strdup(curproxy->id);
	}

	pool2_hdr_idx = create_pool("hdr_idx",
				    global.tune.max_http_hdr * sizeof(struct hdr_idx_elem),
				    MEM_F_SHARED);

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
                         int (*section_parser)(const char *, int, char **, int))
{
	struct cfg_section *cs;

	cs = calloc(1, sizeof(*cs));
	if (!cs) {
		Alert("register section '%s': out of memory.\n", section_name);
		return 0;
	}

	cs->section_name = section_name;
	cs->section_parser = section_parser;

	LIST_ADDQ(&sections, &cs->list);

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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
