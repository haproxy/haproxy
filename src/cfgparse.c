/*
 * Configuration parser
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

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

#include <netinet/tcp.h>

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/acl.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/checks.h>
#include <proto/dumpstats.h>
#include <proto/frontend.h>
#include <proto/httperr.h>
#include <proto/lb_chash.h>
#include <proto/lb_fwlc.h>
#include <proto/lb_fwrr.h>
#include <proto/lb_map.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/port_range.h>
#include <proto/protocols.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/task.h>
#include <proto/stick_table.h>


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
	{ "forceclose",   PR_O_FORCE_CLO,  PR_CAP_FE | PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "http_proxy",	  PR_O_HTTP_PROXY, PR_CAP_FE | PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "httpclose",    PR_O_HTTP_CLOSE, PR_CAP_FE | PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "keepalive",    PR_O_KEEPALIVE,  PR_CAP_NONE, 0, PR_MODE_HTTP },
	{ "http-server-close", PR_O_SERVER_CLO,  PR_CAP_FE | PR_CAP_BE, 0, PR_MODE_HTTP },
	{ "logasap",      PR_O_LOGASAP,    PR_CAP_FE, 0, 0 },
	{ "nolinger",     PR_O_TCP_NOLING, PR_CAP_FE | PR_CAP_BE, 0, 0 },
	{ "persist",      PR_O_PERSIST,    PR_CAP_BE, 0, 0 },
	{ "redispatch",   PR_O_REDISP,     PR_CAP_BE, 0, 0 },
	{ "srvtcpka",     PR_O_TCP_SRV_KA, PR_CAP_BE, 0, 0 },
#ifdef TPROXY
	{ "transparent",  PR_O_TRANSP,     PR_CAP_BE, 0, 0 },
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
	{ "http-use-proxy-header",        PR_O2_USE_PXHDR, PR_CAP_FE, 0, PR_MODE_HTTP },
	{ "http-pretend-keepalive",       PR_O2_FAKE_KA,   PR_CAP_FE|PR_CAP_BE, 0, PR_MODE_HTTP },
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
 * Function returns 1 for success or 0 if error.
 */
static int str2listener(char *str, struct proxy *curproxy)
{
	struct listener *l;
	char *c, *next, *range, *dupstr;
	int port, end;

	next = dupstr = strdup(str);

	while (next && *next) {
		struct sockaddr_storage ss;

		str = next;
		/* 1) look for the end of the first address */
		if ((next = strchr(str, ',')) != NULL) {
			*next++ = 0;
		}

		/* 2) look for the addr/port delimiter, it's the last colon. */
		if ((range = strrchr(str, ':')) == NULL) {
			Alert("Missing port number: '%s'\n", str);
			goto fail;
		}	    

		*range++ = 0;

		if (strrchr(str, ':') != NULL) {
			/* IPv6 address contains ':' */
			memset(&ss, 0, sizeof(ss));
			ss.ss_family = AF_INET6;

			if (!inet_pton(ss.ss_family, str, &((struct sockaddr_in6 *)&ss)->sin6_addr)) {
				Alert("Invalid server address: '%s'\n", str);
				goto fail;
			}
		}
		else {
			memset(&ss, 0, sizeof(ss));
			ss.ss_family = AF_INET;

			if (*str == '*' || *str == '\0') { /* INADDR_ANY */
				((struct sockaddr_in *)&ss)->sin_addr.s_addr = INADDR_ANY;
			}
			else if (!inet_pton(ss.ss_family, str, &((struct sockaddr_in *)&ss)->sin_addr)) {
				struct hostent *he;
		
				if ((he = gethostbyname(str)) == NULL) {
					Alert("Invalid server name: '%s'\n", str);
					goto fail;
				}
				else
					((struct sockaddr_in *)&ss)->sin_addr =
						*(struct in_addr *) *(he->h_addr_list);
			}
		}

		/* 3) look for the port-end delimiter */
		if ((c = strchr(range, '-')) != NULL) {
			*c++ = 0;
			end = atol(c);
		}
		else {
			end = atol(range);
		}

		port = atol(range);

		if (port < 1 || port > 65535) {
			Alert("Invalid port '%d' specified for address '%s'.\n", port, str);
			goto fail;
		}

		if (end < 1 || end > 65535) {
			Alert("Invalid port '%d' specified for address '%s'.\n", end, str);
			goto fail;
		}

		for (; port <= end; port++) {
			l = (struct listener *)calloc(1, sizeof(struct listener));
			l->next = curproxy->listen;
			curproxy->listen = l;

			l->fd = -1;
			l->addr = ss;
			l->state = LI_INIT;

			if (ss.ss_family == AF_INET6) {
				((struct sockaddr_in6 *)(&l->addr))->sin6_port = htons(port);
				tcpv6_add_listener(l);
			} else {
				((struct sockaddr_in *)(&l->addr))->sin_port = htons(port);
				tcpv4_add_listener(l);
			}

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
 * Sends a warning if proxy <proxy> does not have at least one of the
 * capabilities in <cap>. An optionnal <hint> may be added at the end
 * of the warning to help the user. Returns 1 if a warning was emitted
 * or 0 if the condition is valid.
 */
int warnifnotcap(struct proxy *proxy, int cap, const char *file, int line, const char *arg, const char *hint)
{
	char *msg;

	switch (cap) {
	case PR_CAP_BE: msg = "no backend"; break;
	case PR_CAP_FE: msg = "no frontend"; break;
	case PR_CAP_RS: msg = "no ruleset"; break;
	case PR_CAP_BE|PR_CAP_FE: msg = "neither frontend nor backend"; break;
	default: msg = "not enough"; break;
	}

	if (!(proxy->cap & cap)) {
		Warning("parsing [%s:%d] : '%s' ignored because %s '%s' has %s capability.%s\n",
			file, line, arg, proxy_type_str(proxy), proxy->id, msg, hint ? hint : "");
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'block' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_block(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->block_cond)) {
		Warning("parsing [%s:%d] : a '%s' rule placed after a 'block' rule will still be processed before.\n",
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

/* report a warning if a block rule is dangerously placed */
int warnif_misplaced_block(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_reqxxx(proxy, file, line, arg) ||
		warnif_rule_after_reqadd(proxy, file, line, arg) ||
		warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg);
}

/* report a warning if a reqxxx rule is dangerously placed */
int warnif_misplaced_reqxxx(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_reqadd(proxy, file, line, arg) ||
		warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg);
}

/* report a warning if a reqadd rule is dangerously placed */
int warnif_misplaced_reqadd(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_rule_after_use_backend(proxy, file, line, arg);
}

/* Report it if a request ACL condition uses some response-only parameters. It
 * returns either 0 or ERR_WARN so that its result can be or'ed with err_code.
 * Note that <cond> may be NULL and then will be ignored.
 */
static int warnif_cond_requires_resp(const struct acl_cond *cond, const char *file, int line)
{
	struct acl *acl;

	if (!cond || !(cond->requires & ACL_USE_RTR_ANY))
		return 0;

	acl = cond_find_require(cond, ACL_USE_RTR_ANY);
	Warning("parsing [%s:%d] : acl '%s' involves some response-only criteria which will be ignored.\n",
		file, line, acl ? acl->name : "(unknown)");
	return ERR_WARN;
}

/* Report it if a request ACL condition uses some request-only volatile parameters.
 * It returns either 0 or ERR_WARN so that its result can be or'ed with err_code.
 * Note that <cond> may be NULL and then will be ignored.
 */
static int warnif_cond_requires_req(const struct acl_cond *cond, const char *file, int line)
{
	struct acl *acl;

	if (!cond || !(cond->requires & ACL_USE_REQ_VOLATILE))
		return 0;

	acl = cond_find_require(cond, ACL_USE_REQ_VOLATILE);
	Warning("parsing [%s:%d] : acl '%s' involves some volatile request-only criteria which will be ignored.\n",
		file, line, acl ? acl->name : "(unknown)");
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

	if (!strcmp(args[0], "global")) {  /* new section */
		/* no option, nothing special to do */
		goto out;
	}
	else if (!strcmp(args[0], "daemon")) {
		global.mode |= MODE_DAEMON;
	}
	else if (!strcmp(args[0], "debug")) {
		global.mode |= MODE_DEBUG;
	}
	else if (!strcmp(args[0], "noepoll")) {
		global.tune.options &= ~GTUNE_USE_EPOLL;
	}
	else if (!strcmp(args[0], "nosepoll")) {
		global.tune.options &= ~GTUNE_USE_SEPOLL;
	}
	else if (!strcmp(args[0], "nokqueue")) {
		global.tune.options &= ~GTUNE_USE_KQUEUE;
	}
	else if (!strcmp(args[0], "nopoll")) {
		global.tune.options &= ~GTUNE_USE_POLL;
	}
	else if (!strcmp(args[0], "nosplice")) {
		global.tune.options &= ~GTUNE_USE_SPLICE;
	}
	else if (!strcmp(args[0], "quiet")) {
		global.mode |= MODE_QUIET;
	}
	else if (!strcmp(args[0], "tune.maxpollevents")) {
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
	else if (!strcmp(args[0], "tune.bufsize")) {
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.bufsize = atol(args[1]);
		if (global.tune.maxrewrite >= global.tune.bufsize / 2)
			global.tune.maxrewrite = global.tune.bufsize / 2;
	}
	else if (!strcmp(args[0], "tune.maxrewrite")) {
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.maxrewrite = atol(args[1]);
		if (global.tune.maxrewrite >= global.tune.bufsize / 2)
			global.tune.maxrewrite = global.tune.bufsize / 2;
	}
	else if (!strcmp(args[0], "tune.rcvbuf.client")) {
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
	else if (!strcmp(args[0], "uid")) {
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
		global.uid = atol(args[1]);
	}
	else if (!strcmp(args[0], "gid")) {
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
		global.gid = atol(args[1]);
	}
	/* user/group name handling */
	else if (!strcmp(args[0], "user")) {
		struct passwd *ha_user;
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
		if (global.nbproc != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.nbproc = atol(args[1]);
	}
	else if (!strcmp(args[0], "maxconn")) {
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
	else if (!strcmp(args[0], "maxpipes")) {
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
	else if (!strcmp(args[0], "ulimit-n")) {
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

		for(i=1; *args[i]; i++)
			len += strlen(args[i])+1;

		if (global.desc)
			free(global.desc);

		global.desc = d = (char *)calloc(1, len);

		d += sprintf(d, "%s", args[1]);
		for(i=2; *args[i]; i++)
			d += sprintf(d, " %s", args[i]);
	}
	else if (!strcmp(args[0], "node")) {
		int i;
		char c;

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
	else if (!strcmp(args[0], "log")) {  /* syslog server address */
		struct logsrv logsrv;
		int facility, level, minlvl;
	
		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <address> and <facility> as arguments.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	
		facility = get_log_facility(args[2]);
		if (facility < 0) {
			Alert("parsing [%s:%d] : unknown log facility '%s'\n", file, linenum, args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			facility = 0;
		}

		level = 7; /* max syslog level = debug */
		if (*(args[3])) {
			level = get_log_level(args[3]);
			if (level < 0) {
				Alert("parsing [%s:%d] : unknown optional log level '%s'\n", file, linenum, args[3]);
				err_code |= ERR_ALERT | ERR_FATAL;
				level = 0;
			}
		}

		minlvl = 0; /* limit syslog level to this level (emerg) */
		if (*(args[4])) {
			minlvl = get_log_level(args[4]);
			if (minlvl < 0) {
				Alert("parsing [%s:%d] : unknown optional minimum log level '%s'\n", file, linenum, args[4]);
				err_code |= ERR_ALERT | ERR_FATAL;
				minlvl = 0;
			}
		}

		if (args[1][0] == '/') {
			struct sockaddr_un *sk = str2sun(args[1]);
			if (!sk) {
				Alert("parsing [%s:%d] : Socket path '%s' too long (max %d)\n", file, linenum,
				      args[1], (int)sizeof(sk->sun_path) - 1);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			logsrv.u.un = *sk;
			logsrv.u.addr.sa_family = AF_UNIX;
		} else {
			struct sockaddr_in *sk = str2sa(args[1]);
			if (!sk) {
				Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			logsrv.u.in = *sk;
			logsrv.u.addr.sa_family = AF_INET;
			if (!logsrv.u.in.sin_port)
				logsrv.u.in.sin_port = htons(SYSLOG_PORT);
		}

		if (global.logfac1 == -1) {
			global.logsrv1 = logsrv;
			global.logfac1 = facility;
			global.loglev1 = level;
			global.minlvl1 = minlvl;
		}
		else if (global.logfac2 == -1) {
			global.logsrv2 = logsrv;
			global.logfac2 = facility;
			global.loglev2 = level;
			global.minlvl2 = minlvl;
		}
		else {
			Alert("parsing [%s:%d] : too many syslog servers\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (!strcmp(args[0], "spread-checks")) {  /* random time between checks (0-50) */
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
	else {
		struct cfg_kw_list *kwl;
		int index;
		int rc;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_GLOBAL)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
					/* prepare error message just in case */
					snprintf(trash, sizeof(trash),
						 "error near '%s' in '%s' section", args[0], "global");
					rc = kwl->kw[index].parse(args, CFG_GLOBAL, NULL, NULL, trash, sizeof(trash));
					if (rc < 0) {
						Alert("parsing [%s:%d] : %s\n", file, linenum, trash);
						err_code |= ERR_ALERT | ERR_FATAL;
					}
					else if (rc > 0) {
						Warning("parsing [%s:%d] : %s\n", file, linenum, trash);
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
	return err_code;
}

/* Perform the most basic initialization of a proxy :
 * memset(), list_init(*), reset_timeouts(*).
 */
static void init_new_proxy(struct proxy *p)
{
	memset(p, 0, sizeof(struct proxy));
	LIST_INIT(&p->pendconns);
	LIST_INIT(&p->acl);
	LIST_INIT(&p->req_acl);
	LIST_INIT(&p->block_cond);
	LIST_INIT(&p->redirect_rules);
	LIST_INIT(&p->mon_fail_cond);
	LIST_INIT(&p->switching_rules);
	LIST_INIT(&p->persist_rules);
	LIST_INIT(&p->sticking_rules);
	LIST_INIT(&p->storersp_rules);
	LIST_INIT(&p->tcp_req.inspect_rules);
	LIST_INIT(&p->tcp_req.l4_rules);
	LIST_INIT(&p->req_add);
	LIST_INIT(&p->rsp_add);

	/* Timeouts are defined as -1 */
	proxy_reset_timeouts(p);
}

void init_default_instance()
{
	init_new_proxy(&defproxy);
	defproxy.mode = PR_MODE_TCP;
	defproxy.state = PR_STNEW;
	defproxy.maxconn = cfg_maxpconn;
	defproxy.conn_retries = CONN_RETRIES;
	defproxy.logfac1 = defproxy.logfac2 = -1; /* log disabled */

	defproxy.defsrv.inter = DEF_CHKINTR;
	defproxy.defsrv.fastinter = 0;
	defproxy.defsrv.downinter = 0;
	defproxy.defsrv.rise = DEF_RISETIME;
	defproxy.defsrv.fall = DEF_FALLTIME;
	defproxy.defsrv.check_port = 0;
	defproxy.defsrv.maxqueue = 0;
	defproxy.defsrv.minconn = 0;
	defproxy.defsrv.maxconn = 0;
	defproxy.defsrv.slowstart = 0;
	defproxy.defsrv.onerror = DEF_HANA_ONERR;
	defproxy.defsrv.consecutive_errors_limit = DEF_HANA_ERRLIMIT;
	defproxy.defsrv.uweight = defproxy.defsrv.iweight = 1;
}


static int create_cond_regex_rule(const char *file, int line,
				  struct proxy *px, int dir, int action, int flags,
				  const char *cmd, const char *reg, const char *repl,
				  const char **cond_start)
{
	regex_t *preg = NULL;
	const char *err;
	int err_code = 0;
	struct acl_cond *cond = NULL;

	if (px == &defproxy) {
		Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, line, cmd);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	if (*reg == 0) {
		Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, line, cmd);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	if (warnifnotcap(px, PR_CAP_RS, file, line, cmd, NULL))
		err_code |= ERR_WARN;

	if (cond_start &&
	    (strcmp(*cond_start, "if") == 0 || strcmp(*cond_start, "unless") == 0)) {
		if ((cond = build_acl_cond(file, line, px, cond_start)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing a '%s' condition.\n",
			      file, line, cmd);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
	else if (cond_start && **cond_start) {
		Alert("parsing [%s:%d] : '%s' : Expecting nothing, 'if', or 'unless', got '%s'.\n",
		      file, line, cmd, *cond_start);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	if (dir == ACL_DIR_REQ)
		err_code |= warnif_cond_requires_resp(cond, file, line);
	else
		err_code |= warnif_cond_requires_req(cond, file, line);

	preg = calloc(1, sizeof(regex_t));
	if (!preg) {
		Alert("parsing [%s:%d] : '%s' : not enough memory to build regex.\n", file, line, cmd);
		err_code = ERR_ALERT | ERR_FATAL;
		goto err;
	}

	if (regcomp(preg, reg, REG_EXTENDED | flags) != 0) {
		Alert("parsing [%s:%d] : '%s' : bad regular expression '%s'.\n", file, line, cmd, reg);
		err_code = ERR_ALERT | ERR_FATAL;
		goto err;
	}

	err = chain_regex((dir == ACL_DIR_REQ) ? &px->req_exp : &px->rsp_exp,
			  preg, action, repl ? strdup(repl) : NULL, cond);
	if (repl && err) {
		Alert("parsing [%s:%d] : '%s' : invalid character or unterminated sequence in replacement string near '%c'.\n",
		      file, line, cmd, *err);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	if (dir == ACL_DIR_REQ && warnif_misplaced_reqxxx(px, file, line, cmd))
		err_code |= ERR_WARN;

	return err_code;
 err:
	free(preg);
	return err_code;
}

/*
 * Parse a line in a <listen>, <frontend>, <backend> or <ruleset> section.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_listen(const char *file, int linenum, char **args, int kwm)
{
	static struct proxy *curproxy = NULL;
	struct server *newsrv = NULL;
	const char *err;
	int rc;
	unsigned val;
	int err_code = 0;
	struct acl_cond *cond = NULL;

	if (!strcmp(args[0], "listen"))
		rc = PR_CAP_LISTEN;
 	else if (!strcmp(args[0], "frontend"))
		rc = PR_CAP_FE | PR_CAP_RS;
 	else if (!strcmp(args[0], "backend"))
		rc = PR_CAP_BE | PR_CAP_RS;
 	else if (!strcmp(args[0], "ruleset"))
		rc = PR_CAP_RS;
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

		for (curproxy = proxy; curproxy != NULL; curproxy = curproxy->next) {
			/*
			 * If there are two proxies with the same name only following
			 * combinations are allowed:
			 *
			 *			listen backend frontend ruleset
			 *	listen             -      -       -        -
			 *	backend            -      -       OK       -
			 *	frontend           -      OK      -        -
			 *	ruleset            -      -       -        -
			 */

			if (!strcmp(curproxy->id, args[1]) &&
				(rc!=(PR_CAP_FE|PR_CAP_RS) || curproxy->cap!=(PR_CAP_BE|PR_CAP_RS)) &&
				(rc!=(PR_CAP_BE|PR_CAP_RS) || curproxy->cap!=(PR_CAP_FE|PR_CAP_RS))) {
				Warning("Parsing [%s:%d]: %s '%s' has same name as another %s (declared at %s:%d).\n",
					file, linenum, proxy_cap_str(rc), args[1], proxy_type_str(curproxy),
					curproxy->conf.file, curproxy->conf.line);
				err_code |= ERR_WARN;
			}
		}

		if ((curproxy = (struct proxy *)calloc(1, sizeof(struct proxy))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		init_new_proxy(curproxy);
		curproxy->next = proxy;
		proxy = curproxy;
		curproxy->conf.file = file;
		curproxy->conf.line = linenum;
		curproxy->last_change = now.tv_sec;
		curproxy->id = strdup(args[1]);
		curproxy->cap = rc;

		/* parse the listener address if any */
		if ((curproxy->cap & PR_CAP_FE) && *args[2]) {
			struct listener *new, *last = curproxy->listen;
			if (!str2listener(args[2], curproxy)) {
				err_code |= ERR_FATAL;
				goto out;
			}
			new = curproxy->listen;
			while (new != last) {
				new->conf.file = file;
				new->conf.line = linenum;
				new = new->next;
			}
			global.maxsock++;
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
		curproxy->lbprm.algo = defproxy.lbprm.algo;
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
			curproxy->fullconn = defproxy.fullconn;
			curproxy->conn_retries = defproxy.conn_retries;

			if (defproxy.check_req)
				curproxy->check_req = strdup(defproxy.check_req);
			curproxy->check_len = defproxy.check_len;

			if (defproxy.cookie_name)
				curproxy->cookie_name = strdup(defproxy.cookie_name);
			curproxy->cookie_len = defproxy.cookie_len;
			if (defproxy.cookie_domain)
				curproxy->cookie_domain = strdup(defproxy.cookie_domain);

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

			if (defproxy.iface_name)
				curproxy->iface_name = strdup(defproxy.iface_name);
			curproxy->iface_len  = defproxy.iface_len;
		}

		if (curproxy->cap & PR_CAP_FE) {
			if (defproxy.capture_name)
				curproxy->capture_name = strdup(defproxy.capture_name);
			curproxy->capture_namelen = defproxy.capture_namelen;
			curproxy->capture_len = defproxy.capture_len;
		}

		if (curproxy->cap & PR_CAP_FE) {
			curproxy->timeout.client = defproxy.timeout.client;
			curproxy->timeout.tarpit = defproxy.timeout.tarpit;
			curproxy->timeout.httpreq = defproxy.timeout.httpreq;
			curproxy->timeout.httpka = defproxy.timeout.httpka;
			curproxy->uri_auth  = defproxy.uri_auth;
			curproxy->mon_net = defproxy.mon_net;
			curproxy->mon_mask = defproxy.mon_mask;
			if (defproxy.monitor_uri)
				curproxy->monitor_uri = strdup(defproxy.monitor_uri);
			curproxy->monitor_uri_len = defproxy.monitor_uri_len;
			if (defproxy.defbe.name)
				curproxy->defbe.name = strdup(defproxy.defbe.name);
		}

		if (curproxy->cap & PR_CAP_BE) {
			curproxy->timeout.connect = defproxy.timeout.connect;
			curproxy->timeout.server = defproxy.timeout.server;
			curproxy->timeout.check = defproxy.timeout.check;
			curproxy->timeout.queue = defproxy.timeout.queue;
			curproxy->timeout.tarpit = defproxy.timeout.tarpit;
			curproxy->timeout.httpreq = defproxy.timeout.httpreq;
			curproxy->timeout.httpka = defproxy.timeout.httpka;
			curproxy->source_addr = defproxy.source_addr;
		}

		curproxy->mode = defproxy.mode;
		curproxy->logfac1 = defproxy.logfac1;
		curproxy->logsrv1 = defproxy.logsrv1;
		curproxy->loglev1 = defproxy.loglev1;
		curproxy->minlvl1 = defproxy.minlvl1;
		curproxy->logfac2 = defproxy.logfac2;
		curproxy->logsrv2 = defproxy.logsrv2;
		curproxy->loglev2 = defproxy.loglev2;
		curproxy->minlvl2 = defproxy.minlvl2;
		curproxy->grace  = defproxy.grace;
		curproxy->conf.used_listener_id = EB_ROOT;
		curproxy->conf.used_server_id = EB_ROOT;

		goto out;
	}
	else if (!strcmp(args[0], "defaults")) {  /* use this one to assign default values */
		/* some variables may have already been initialized earlier */
		/* FIXME-20070101: we should do this too at the end of the
		 * config parsing to free all default values.
		 */
		free(defproxy.check_req);
		free(defproxy.cookie_name);
		free(defproxy.rdp_cookie_name);
		free(defproxy.cookie_domain);
		free(defproxy.url_param_name);
		free(defproxy.hh_name);
		free(defproxy.capture_name);
		free(defproxy.monitor_uri);
		free(defproxy.defbe.name);
		free(defproxy.iface_name);
		free(defproxy.fwdfor_hdr_name);
		defproxy.fwdfor_hdr_len = 0;
		free(defproxy.orgto_hdr_name);
		defproxy.orgto_hdr_len = 0;

		for (rc = 0; rc < HTTP_ERR_SIZE; rc++)
			chunk_destroy(&defproxy.errmsg[rc]);

		/* we cannot free uri_auth because it might already be used */
		init_default_instance();
		curproxy = &defproxy;
		defproxy.cap = PR_CAP_LISTEN; /* all caps for now */
		goto out;
	}
	else if (curproxy == NULL) {
		Alert("parsing [%s:%d] : 'listen' or 'defaults' expected.\n", file, linenum);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
    

	/* Now let's parse the proxy-specific keywords */
	if (!strcmp(args[0], "bind")) {  /* new listen addresses */
		struct listener *new_listen, *last_listen;
		int cur_arg;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strchr(args[1], ':') == NULL) {
			Alert("parsing [%s:%d] : '%s' expects [addr1]:port1[-end1]{,[addr]:port[-end]}... as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		last_listen = curproxy->listen;
		if (!str2listener(args[1], curproxy)) {
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		new_listen = curproxy->listen;
		while (new_listen != last_listen) {
			new_listen->conf.file = file;
			new_listen->conf.line = linenum;
			new_listen = new_listen->next;
		}

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "interface")) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
				struct listener *l;

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s' : missing interface name.\n",
					      file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				
				for (l = curproxy->listen; l != last_listen; l = l->next)
					l->interface = strdup(args[cur_arg + 1]);

				global.last_checks |= LSTCHK_NETADM;

				cur_arg += 2;
				continue;
#else
				Alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
				      file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
			}
			if (!strcmp(args[cur_arg], "mss")) { /* set MSS of listening socket */
#ifdef TCP_MAXSEG
				struct listener *l;
				int mss;

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s' : missing MSS value.\n",
					      file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				mss = str2uic(args[cur_arg + 1]);
				if (mss < 1 || mss > 65535) {
					Alert("parsing [%s:%d]: %s expects an MSS value between 1 and 65535.\n",
					      file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				for (l = curproxy->listen; l != last_listen; l = l->next)
					l->maxseg = mss;

				cur_arg += 2;
				continue;
#else
				Alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
				      file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
			}

			if (!strcmp(args[cur_arg], "defer-accept")) { /* wait for some data for 1 second max before doing accept */
#ifdef TCP_DEFER_ACCEPT
				struct listener *l;

				for (l = curproxy->listen; l != last_listen; l = l->next)
					l->options |= LI_O_DEF_ACCEPT;

				cur_arg ++;
				continue;
#else
				Alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
				      file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
			}

			if (!strcmp(args[cur_arg], "transparent")) { /* transparently bind to these addresses */
#ifdef CONFIG_HAP_LINUX_TPROXY
				struct listener *l;

				for (l = curproxy->listen; l != last_listen; l = l->next)
					l->options |= LI_O_FOREIGN;

				cur_arg ++;
				continue;
#else
				Alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
				      file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
			}

			if (!strcmp(args[cur_arg], "name")) {
				struct listener *l;

				for (l = curproxy->listen; l != last_listen; l = l->next)
					l->name = strdup(args[cur_arg + 1]);

				cur_arg += 2;
				continue;
			}

			if (!strcmp(args[cur_arg], "id")) {
				struct eb32_node *node;
				struct listener *l;

				if (curproxy->listen->next != last_listen) {
					Alert("parsing [%s:%d]: '%s' can be only used with a single socket.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				curproxy->listen->luid = atol(args[cur_arg + 1]);
				curproxy->listen->conf.id.key = curproxy->listen->luid;

				if (curproxy->listen->luid <= 0) {
					Alert("parsing [%s:%d]: custom id has to be > 0\n",
						file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				node = eb32_lookup(&curproxy->conf.used_listener_id, curproxy->listen->luid);
				if (node) {
					l = container_of(node, struct listener, conf.id);
					Alert("parsing [%s:%d]: custom id %d for socket '%s' already used at %s:%d.\n",
					      file, linenum, l->luid, args[1], l->conf.file, l->conf.line);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				eb32_insert(&curproxy->conf.used_listener_id, &curproxy->listen->conf.id);

				cur_arg += 2;
				continue;
			}

			Alert("parsing [%s:%d] : '%s' only supports the 'transparent', 'defer-accept', 'name', 'id', 'mss' and 'interface' options.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxsock++;
		goto out;
	}
	else if (!strcmp(args[0], "monitor-net")) {  /* set the range of IPs to ignore */
		if (!*args[1] || !str2net(args[1], &curproxy->mon_net, &curproxy->mon_mask)) {
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

		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects an URI.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		free(curproxy->monitor_uri);
		curproxy->monitor_uri_len = strlen(args[1]);
		curproxy->monitor_uri = (char *)calloc(1, curproxy->monitor_uri_len + 1);
		memcpy(curproxy->monitor_uri, args[1], curproxy->monitor_uri_len);
		curproxy->monitor_uri[curproxy->monitor_uri_len] = '\0';

		goto out;
	}
	else if (!strcmp(args[0], "mode")) {  /* sets the proxy mode */
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

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
				file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->uuid = atol(args[1]);
		curproxy->conf.id.key = curproxy->uuid;

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

		for(i=1; *args[i]; i++)
			len += strlen(args[i])+1;

		d = (char *)calloc(1, len);
		curproxy->desc = d;

		d += sprintf(d, "%s", args[1]);
		for(i=2; *args[i]; i++)
			d += sprintf(d, " %s", args[i]);

	}
	else if (!strcmp(args[0], "disabled")) {  /* disables this proxy */
		curproxy->state = PR_STSTOPPED;
	}
	else if (!strcmp(args[0], "enabled")) {  /* enables this proxy (used to revert a disabled default) */
		curproxy->state = PR_STNEW;
	}
	else if (!strcmp(args[0], "bind-process")) {  /* enable this proxy only on some processes */
		int cur_arg = 1;
		unsigned int set = 0;

		while (*args[cur_arg]) {
			int u;
			if (strcmp(args[cur_arg], "all") == 0) {
				set = 0;
				break;
			}
			else if (strcmp(args[cur_arg], "odd") == 0) {
				set |= 0x55555555;
			}
			else if (strcmp(args[cur_arg], "even") == 0) {
				set |= 0xAAAAAAAA;
			}
			else {
				u = str2uic(args[cur_arg]);
				if (u < 1 || u > 32) {
					Alert("parsing [%s:%d]: %s expects 'all', 'odd', 'even', or process numbers from 1 to 32.\n",
					      file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (u > global.nbproc) {
					Warning("parsing [%s:%d]: %s references process number higher than global.nbproc.\n",
						file, linenum, args[0]);
					err_code |= ERR_WARN;
				}
				set |= 1 << (u - 1);
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

		if (parse_acl((const char **)args + 1, &curproxy->acl) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing ACL '%s'.\n",
			      file, linenum, args[1]);
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

		free(curproxy->cookie_domain); curproxy->cookie_domain = NULL;
		free(curproxy->cookie_name);
		curproxy->cookie_name = strdup(args[1]);
		curproxy->cookie_len = strlen(curproxy->cookie_name);
	
		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "rewrite")) {
				curproxy->options |= PR_O_COOK_RW;
			}
			else if (!strcmp(args[cur_arg], "indirect")) {
				curproxy->options |= PR_O_COOK_IND;
			}
			else if (!strcmp(args[cur_arg], "insert")) {
				curproxy->options |= PR_O_COOK_INS;
			}
			else if (!strcmp(args[cur_arg], "nocache")) {
				curproxy->options |= PR_O_COOK_NOC;
			}
			else if (!strcmp(args[cur_arg], "postonly")) {
				curproxy->options |= PR_O_COOK_POST;
			}
			else if (!strcmp(args[cur_arg], "prefix")) {
				curproxy->options |= PR_O_COOK_PFX;
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
			else {
				Alert("parsing [%s:%d] : '%s' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache' and 'postonly', 'domain' options.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg++;
		}
		if (!POWEROF2(curproxy->options & (PR_O_COOK_RW|PR_O_COOK_IND))) {
			Alert("parsing [%s:%d] : cookie 'rewrite' and 'indirect' modes are incompatible.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (!POWEROF2(curproxy->options & (PR_O_COOK_RW|PR_O_COOK_INS|PR_O_COOK_PFX))) {
			Alert("parsing [%s:%d] : cookie 'rewrite', 'insert' and 'prefix' modes are incompatible.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}/* end else if (!strcmp(args[0], "cookie"))  */
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
		int cur_arg;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[5]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects 'appsession' <cookie_name> 'len' <len> 'timeout' <timeout> [options*].\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		have_appsession = 1;
		free(curproxy->appsession_name);
		curproxy->appsession_name = strdup(args[1]);
		curproxy->appsession_name_len = strlen(curproxy->appsession_name);
		curproxy->appsession_len = atoi(args[3]);
		err = parse_time_err(args[5], &val, TIME_UNIT_MS);
		if (err) {
			Alert("parsing [%s:%d] : unexpected character '%c' in %s timeout.\n",
			      file, linenum, *err, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->timeout.appsession = val;

		if (appsession_hash_init(&(curproxy->htbl_proxy), destroy) == 0) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		cur_arg = 6;
		curproxy->options2 &= ~PR_O2_AS_REQL;
		curproxy->options2 &= ~PR_O2_AS_M_ANY;
		curproxy->options2 |= PR_O2_AS_M_PP;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "request-learn")) {
				curproxy->options2 |= PR_O2_AS_REQL;
			} else if (!strcmp(args[cur_arg], "prefix")) {
				curproxy->options2 |= PR_O2_AS_PFX;
			} else if (!strcmp(args[cur_arg], "mode")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s': missing argument for '%s'.\n",
					      file, linenum, args[0], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg++;
				if (!strcmp(args[cur_arg], "query-string")) {
					curproxy->options2 &= ~PR_O2_AS_M_ANY;
					curproxy->options2 |= PR_O2_AS_M_QS;
				} else if (!strcmp(args[cur_arg], "path-parameters")) {
					curproxy->options2 &= ~PR_O2_AS_M_ANY;
					curproxy->options2 |= PR_O2_AS_M_PP;
				} else {
					Alert("parsing [%s:%d] : unknown mode '%s'\n", file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			cur_arg++;
		}
	} /* Url App Session */
	else if (!strcmp(args[0], "capture")) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!strcmp(args[1], "cookie")) {  /* name of a cookie to capture */
			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

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
			if (curproxy->capture_len >= CAPTURE_LEN) {
				Warning("parsing [%s:%d] : truncating capture length to %d bytes.\n",
					file, linenum, CAPTURE_LEN - 1);
				err_code |= ERR_WARN;
				curproxy->capture_len = CAPTURE_LEN - 1;
			}
			curproxy->to_log |= LW_COOKIE;
		}
		else if (!strcmp(args[1], "request") && !strcmp(args[2], "header")) {
			struct cap_hdr *hdr;

			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				Alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			hdr = calloc(sizeof(struct cap_hdr), 1);
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

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				Alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			hdr = calloc(sizeof(struct cap_hdr), 1);
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

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument (dispatch counts for one).\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->conn_retries = atol(args[1]);
	}
	else if (!strcmp(args[0], "http-request")) {	/* request access control: allow/deny/auth */
		struct req_acl_rule *req_acl;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}


		if (!LIST_ISEMPTY(&curproxy->req_acl) && !LIST_PREV(&curproxy->req_acl, struct req_acl_rule *, list)->cond) {
			Warning("parsing [%s:%d]: previous '%s' action has no condition attached, further entries are NOOP.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		req_acl = parse_auth_cond((const char **)args + 1, file, linenum, curproxy);

		if (!req_acl) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err_code |= warnif_cond_requires_resp(req_acl->cond, file, linenum);
		LIST_ADDQ(&curproxy->req_acl, &req_acl->list);
	}
	else if (!strcmp(args[0], "block")) {  /* early blocking based on ACLs */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[1], "if") != 0 && strcmp(args[1], "unless") != 0) {
			Alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 1)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing blocking condition.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		LIST_ADDQ(&curproxy->block_cond, &cond->list);
		warnif_misplaced_block(curproxy, file, linenum, args[0]);
	}
	else if (!strcmp(args[0], "redirect")) {
		struct redirect_rule *rule;
		int cur_arg;
		int type = REDIRECT_TYPE_NONE;
		int code = 302;
		char *destination = NULL;
		char *cookie = NULL;
		int cookie_set = 0;
		unsigned int flags = REDIRECT_FLAG_NONE;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		cur_arg = 1;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "location")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s': missing argument for '%s'.\n",
					      file, linenum, args[0], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				type = REDIRECT_TYPE_LOCATION;
				cur_arg++;
				destination = args[cur_arg];
			}
			else if (!strcmp(args[cur_arg], "prefix")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s': missing argument for '%s'.\n",
					      file, linenum, args[0], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				type = REDIRECT_TYPE_PREFIX;
				cur_arg++;
				destination = args[cur_arg];
			}
			else if (!strcmp(args[cur_arg], "set-cookie")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s': missing argument for '%s'.\n",
					      file, linenum, args[0], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg++;
				cookie = args[cur_arg];
				cookie_set = 1;
			}
			else if (!strcmp(args[cur_arg], "clear-cookie")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s': missing argument for '%s'.\n",
					      file, linenum, args[0], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg++;
				cookie = args[cur_arg];
				cookie_set = 0;
			}
			else if (!strcmp(args[cur_arg],"code")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s': missing HTTP code.\n",
					      file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				cur_arg++;
				code = atol(args[cur_arg]);
				if (code < 301 || code > 303) {
					Alert("parsing [%s:%d] : '%s': unsupported HTTP code '%d'.\n",
					      file, linenum, args[0], code);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			else if (!strcmp(args[cur_arg],"drop-query")) {
				flags |= REDIRECT_FLAG_DROP_QS;
			}
			else if (!strcmp(args[cur_arg],"append-slash")) {
				flags |= REDIRECT_FLAG_APPEND_SLASH;
			}
			else if (strcmp(args[cur_arg], "if") == 0 ||
				 strcmp(args[cur_arg], "unless") == 0) {
				cond = build_acl_cond(file, linenum, curproxy, (const char **)args + cur_arg);
				if (!cond) {
					Alert("parsing [%s:%d] : '%s': error detected while parsing redirect condition.\n",
					      file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				break;
			}
			else {
				Alert("parsing [%s:%d] : '%s' expects 'code', 'prefix', 'location', 'set-cookie', 'clear-cookie', 'drop-query' or 'append-slash' (was '%s').\n",
				      file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg++;
		}

		if (type == REDIRECT_TYPE_NONE) {
			Alert("parsing [%s:%d] : '%s' expects a redirection type ('prefix' or 'location').\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		rule = (struct redirect_rule *)calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->rdr_str = strdup(destination);
		rule->rdr_len = strlen(destination);
		if (cookie) {
			/* depending on cookie_set, either we want to set the cookie, or to clear it.
			 * a clear consists in appending "; path=/; Max-Age=0;" at the end.
			 */
			rule->cookie_len = strlen(cookie);
			if (cookie_set) {
				rule->cookie_str = malloc(rule->cookie_len + 10);
				memcpy(rule->cookie_str, cookie, rule->cookie_len);
				memcpy(rule->cookie_str + rule->cookie_len, "; path=/;", 10);
				rule->cookie_len += 9;
			} else {
				rule->cookie_str = malloc(rule->cookie_len + 21);
				memcpy(rule->cookie_str, cookie, rule->cookie_len);
				memcpy(rule->cookie_str + rule->cookie_len, "; path=/; Max-Age=0;", 21);
				rule->cookie_len += 20;
			}
		}
		rule->type = type;
		rule->code = code;
		rule->flags = flags;
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->redirect_rules, &rule->list);
		warnif_rule_after_use_backend(curproxy, file, linenum, args[0]);
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

		if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
			Alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 2)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing switching rule.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= warnif_cond_requires_resp(cond, file, linenum);

		rule = (struct switching_rule *)calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->be.name = strdup(args[1]);
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->switching_rules, &rule->list);
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

		if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 1)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing a '%s' rule.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= warnif_cond_requires_resp(cond, file, linenum);

		rule = (struct persist_rule *)calloc(1, sizeof(*rule));
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
		struct pattern_expr *expr;
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

		expr = pattern_parse_expr(args, &myidx);
		if (!expr) {
			Alert("parsing [%s:%d] : '%s': unknown fetch method '%s'.\n", file, linenum, args[0], args[myidx]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (flags & STK_ON_RSP) {
			if (!(expr->fetch->dir & PATTERN_FETCH_RTR)) {
				Alert("parsing [%s:%d] : '%s': fetch method '%s' can not be used on response.\n",
				      file, linenum, args[0], expr->fetch->kw);
		                err_code |= ERR_ALERT | ERR_FATAL;
			        goto out;
			}
		} else {
			if (!(expr->fetch->dir & PATTERN_FETCH_REQ)) {
				Alert("parsing [%s:%d] : '%s': fetch method '%s' can not be used on request.\n",
				      file, linenum, args[0], expr->fetch->kw);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if (strcmp(args[myidx], "table") == 0) {
			myidx++;
			name = args[myidx++];
		}

		if (strcmp(args[myidx], "if") == 0 || strcmp(args[myidx], "unless") == 0) {
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + myidx)) == NULL) {
				Alert("parsing [%s:%d] : '%s': error detected while parsing sticking condition.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else if (*(args[myidx])) {
			Alert("parsing [%s:%d] : '%s': unknown keyword '%s'.\n",
			      file, linenum, args[0], args[myidx]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= warnif_cond_requires_resp(cond, file, linenum);

		rule = (struct sticking_rule *)calloc(1, sizeof(*rule));
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
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (curproxy != &defproxy && curproxy->uri_auth == defproxy.uri_auth)
			curproxy->uri_auth = NULL; /* we must detach from the default config */

		if (!*args[1]) {
			goto stats_error_parsing;
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
			struct req_acl_rule *req_acl;

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

			if (!LIST_ISEMPTY(&curproxy->uri_auth->req_acl) &&
			    !LIST_PREV(&curproxy->uri_auth->req_acl, struct req_acl_rule *, list)->cond) {
				Warning("parsing [%s:%d]: previous '%s' action has no condition attached, further entries are NOOP.\n",
					file, linenum, args[0]);
				err_code |= ERR_WARN;
			}

			req_acl = parse_auth_cond((const char **)args + 2, file, linenum, curproxy);

			if (!req_acl) {
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			err_code |= warnif_cond_requires_resp(req_acl->cond, file, linenum);
			LIST_ADDQ(&curproxy->uri_auth->req_acl, &req_acl->list);

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

				for(i=2; *args[i]; i++)
					len += strlen(args[i])+1;

				desc = d = (char *)calloc(1, len);

				d += sprintf(d, "%s", args[2]);
				for(i=3; *args[i]; i++)
					d += sprintf(d, " %s", args[i]);
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
			Alert("parsing [%s:%d]: %s '%s', expects 'uri', 'realm', 'auth', 'scope', 'enable', 'hide-version', 'show-node', 'show-desc' or 'show-legends'.\n",
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

		if (kwm != KWM_STD) {
			Alert("parsing [%s:%d]: negation/default is not supported for option '%s'.\n",
				file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!strcmp(args[1], "httplog")) {
			/* generate a complete HTTP log */
			curproxy->options2 &= ~PR_O2_CLFLOG;
			curproxy->to_log |= LW_DATE | LW_CLIP | LW_SVID | LW_REQ | LW_PXID | LW_RESP | LW_BYTES;
			if (*(args[2]) != '\0') {
				if (!strcmp(args[2], "clf")) {
					curproxy->options2 |= PR_O2_CLFLOG;
				} else {
					Alert("parsing [%s:%d] : keyword '%s' only supports option 'clf'.\n", file, linenum, args[2]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
		}
		else if (!strcmp(args[1], "tcplog"))
			/* generate a detailed TCP log */
			curproxy->to_log |= LW_DATE | LW_CLIP | LW_SVID | LW_PXID | LW_BYTES;
		else if (!strcmp(args[1], "tcpka")) {
			/* enable TCP keep-alives on client and server sessions */
			if (warnifnotcap(curproxy, PR_CAP_BE | PR_CAP_FE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

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
			curproxy->options &= ~PR_O_SMTP_CHK;
			curproxy->options2 &= ~PR_O2_SSL3_CHK;
			curproxy->options2 &= ~PR_O2_MYSQL_CHK;
			curproxy->options |= PR_O_HTTP_CHK;
			if (!*args[2]) { /* no argument */
				curproxy->check_req = strdup(DEF_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_CHECK_REQ);
			} else if (!*args[3]) { /* one argument : URI */
				int reqlen = strlen(args[2]) + strlen("OPTIONS  HTTP/1.0\r\n") + 1;
				curproxy->check_req = (char *)malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "OPTIONS %s HTTP/1.0\r\n", args[2]); /* URI to use */
			} else { /* more arguments : METHOD URI [HTTP_VER] */
				int reqlen = strlen(args[2]) + strlen(args[3]) + 3 + strlen("\r\n");
				if (*args[4])
					reqlen += strlen(args[4]);
				else
					reqlen += strlen("HTTP/1.0");
		    
				curproxy->check_req = (char *)malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "%s %s %s\r\n", args[2], args[3], *args[4]?args[4]:"HTTP/1.0");
			}
		}
		else if (!strcmp(args[1], "ssl-hello-chk")) {
			/* use SSLv3 CLIENT HELLO to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options &= ~PR_O_HTTP_CHK;
			curproxy->options &= ~PR_O_SMTP_CHK;
			curproxy->options2 &= ~PR_O2_MYSQL_CHK;
			curproxy->options2 |= PR_O2_SSL3_CHK;
		}
		else if (!strcmp(args[1], "smtpchk")) {
			/* use SMTP request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options &= ~PR_O_HTTP_CHK;
			curproxy->options2 &= ~PR_O2_SSL3_CHK;
			curproxy->options2 &= ~PR_O2_MYSQL_CHK;
			curproxy->options |= PR_O_SMTP_CHK;

			if (!*args[2] || !*args[3]) { /* no argument or incomplete EHLO host */
				curproxy->check_req = strdup(DEF_SMTP_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_SMTP_CHECK_REQ);
			} else { /* ESMTP EHLO, or SMTP HELO, and a hostname */
				if (!strcmp(args[2], "EHLO") || !strcmp(args[2], "HELO")) {
					int reqlen = strlen(args[2]) + strlen(args[3]) + strlen(" \r\n") + 1;
					curproxy->check_req = (char *)malloc(reqlen);
					curproxy->check_len = snprintf(curproxy->check_req, reqlen,
								       "%s %s\r\n", args[2], args[3]); /* HELO hostname */
				} else {
					/* this just hits the default for now, but you could potentially expand it to allow for other stuff
					   though, it's unlikely you'd want to send anything other than an EHLO or HELO */
					curproxy->check_req = strdup(DEF_SMTP_CHECK_REQ); /* default request */
					curproxy->check_len = strlen(DEF_SMTP_CHECK_REQ);
				}
			}
		}
		else if (!strcmp(args[1], "mysql-check")) {
			/* use MYSQL request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options &= ~PR_O_HTTP_CHK;
			curproxy->options &= ~PR_O_SMTP_CHK;
			curproxy->options2 &= ~PR_O2_SSL3_CHK;
			curproxy->options2 |= PR_O2_MYSQL_CHK;
		}
		else if (!strcmp(args[1], "forwardfor")) {
			int cur_arg;

			/* insert x-forwarded-for field, but not for the IP address listed as an except.
			 * set default options (ie: bitfield, header name, etc) 
			 */

			curproxy->options |= PR_O_FWDFOR;

			free(curproxy->fwdfor_hdr_name);
			curproxy->fwdfor_hdr_name = strdup(DEF_XFORWARDFOR_HDR);
			curproxy->fwdfor_hdr_len  = strlen(DEF_XFORWARDFOR_HDR);

			/* loop to go through arguments - start at 2, since 0+1 = "option" "forwardfor" */
			cur_arg = 2;
			while (*(args[cur_arg])) {
				if (!strcmp(args[cur_arg], "except")) {
					/* suboption except - needs additional argument for it */
					if (!*(args[cur_arg+1]) || !str2net(args[cur_arg+1], &curproxy->except_net, &curproxy->except_mask)) {
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
				} else {
					/* unknown suboption - catchall */
					Alert("parsing [%s:%d] : '%s %s' only supports optional values: 'except' and 'header'.\n",
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

			/* loop to go through arguments - start at 2, since 0+1 = "option" "forwardfor" */
			cur_arg = 2;
			while (*(args[cur_arg])) {
				if (!strcmp(args[cur_arg], "except")) {
					/* suboption except - needs additional argument for it */
					if (!*(args[cur_arg+1]) || !str2net(args[cur_arg+1], &curproxy->except_to, &curproxy->except_mask_to)) {
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
	}
	else if (!strcmp(args[0], "redispatch") || !strcmp(args[0], "redisp")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		Warning("parsing [%s:%d]: keyword '%s' is deprecated, please use 'option redispatch' instead.\n",
				file, linenum, args[0]);
		err_code |= ERR_WARN;
		/* enable reconnections to dispatch */
		curproxy->options |= PR_O_REDISP;
	}
	else if (!strcmp(args[0], "http-check")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "disable-on-404") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options |= PR_O_DISABLE404;
		}
		else if (strcmp(args[1], "send-state") == 0) {
			/* enable emission of the apparent state of a server in HTTP checks */
			curproxy->options2 |= PR_O2_CHK_SNDST;
		}
		else {
			Alert("parsing [%s:%d] : '%s' only supports 'disable-on-404'.\n", file, linenum, args[0]);
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

			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args + 2)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing a '%s %s' condition.\n",
				      file, linenum, args[0], args[1]);
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
	}
	else if (!strcmp(args[0], "dispatch")) {  /* dispatch address */
		struct sockaddr_in *sk;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strchr(args[1], ':') == NULL) {
			Alert("parsing [%s:%d] : '%s' expects <addr:port> as argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		sk = str2sa(args[1]);
		if (!sk) {
			Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->dispatch_addr = *sk;
	}
	else if (!strcmp(args[0], "balance")) {  /* set balancing with optional algorithm */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		memcpy(trash, "error near 'balance'", 21);
		if (backend_parse_balance((const char **)args + 1, trash, sizeof(trash), curproxy) < 0) {
			Alert("parsing [%s:%d] : %s\n", file, linenum, trash);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "hash-type")) { /* set hashing method */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "consistent") == 0) {	/* use consistent hashing */
			curproxy->lbprm.algo &= ~BE_LB_HASH_TYPE;
			curproxy->lbprm.algo |= BE_LB_HASH_CONS;
		}
		else if (strcmp(args[1], "map-based") == 0) {	/* use map-based hashing */
			curproxy->lbprm.algo &= ~BE_LB_HASH_TYPE;
			curproxy->lbprm.algo |= BE_LB_HASH_MAP;
		}
		else {
			Alert("parsing [%s:%d] : '%s' only supports 'consistent' and 'map-based'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "server") || !strcmp(args[0], "default-server")) {  /* server address */
		int cur_arg;
		char *rport, *raddr;
		short realport = 0;
		int do_check = 0, defsrv = (*args[0] == 'd');

		if (!defsrv && curproxy == &defproxy) {
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
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
			      file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!defsrv) {
			struct sockaddr_in *sk;

			if ((newsrv = (struct server *)calloc(1, sizeof(struct server))) == NULL) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			/* the servers are linked backwards first */
			newsrv->next = curproxy->srv;
			curproxy->srv = newsrv;
			newsrv->proxy = curproxy;
			newsrv->conf.file = file;
			newsrv->conf.line = linenum;

			LIST_INIT(&newsrv->pendconns);
			do_check = 0;
			newsrv->state = SRV_RUNNING; /* early server setup */
			newsrv->last_change = now.tv_sec;
			newsrv->id = strdup(args[1]);

			/* several ways to check the port component :
			 *  - IP    => port=+0, relative
			 *  - IP:   => port=+0, relative
			 *  - IP:N  => port=N, absolute
			 *  - IP:+N => port=+N, relative
			 *  - IP:-N => port=-N, relative
			 */
			raddr = strdup(args[2]);
			rport = strchr(raddr, ':');
			if (rport) {
				*rport++ = 0;
				realport = atol(rport);
				if (!isdigit((unsigned char)*rport))
					newsrv->state |= SRV_MAPPORTS;
			} else
				newsrv->state |= SRV_MAPPORTS;

			sk = str2sa(raddr);
			free(raddr);
			if (!sk) {
				Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			newsrv->addr = *sk;
			newsrv->addr.sin_port = htons(realport);

			newsrv->check_port	= curproxy->defsrv.check_port;
			newsrv->inter		= curproxy->defsrv.inter;
			newsrv->fastinter	= curproxy->defsrv.fastinter;
			newsrv->downinter	= curproxy->defsrv.downinter;
			newsrv->rise		= curproxy->defsrv.rise;
			newsrv->fall		= curproxy->defsrv.fall;
			newsrv->maxqueue	= curproxy->defsrv.maxqueue;
			newsrv->minconn		= curproxy->defsrv.minconn;
			newsrv->maxconn		= curproxy->defsrv.maxconn;
			newsrv->slowstart	= curproxy->defsrv.slowstart;
			newsrv->onerror		= curproxy->defsrv.onerror;
			newsrv->consecutive_errors_limit
						= curproxy->defsrv.consecutive_errors_limit;
			newsrv->uweight = newsrv->iweight
						= curproxy->defsrv.iweight;

			newsrv->curfd = -1;		/* no health-check in progress */
			newsrv->health = newsrv->rise;	/* up, but will fall down at first failure */

			cur_arg = 3;
		} else {
			newsrv = &curproxy->defsrv;
			cur_arg = 1;
		}

		while (*args[cur_arg]) {
			if (!defsrv && !strcmp(args[cur_arg], "id")) {
				struct eb32_node *node;

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->puid = atol(args[cur_arg + 1]);
				newsrv->conf.id.key = newsrv->puid;

				if (newsrv->puid <= 0) {
					Alert("parsing [%s:%d]: custom id has to be > 0.\n",
						file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				node = eb32_lookup(&curproxy->conf.used_server_id, newsrv->puid);
				if (node) {
					struct server *target = container_of(node, struct server, conf.id);
					Alert("parsing [%s:%d]: server %s reuses same custom id as server %s (declared at %s:%d).\n",
					      file, linenum, newsrv->id, target->id, target->conf.file, target->conf.line);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				eb32_insert(&curproxy->conf.used_server_id, &newsrv->conf.id);
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

				newsrv->rise = atol(args[cur_arg + 1]);
				if (newsrv->rise <= 0) {
					Alert("parsing [%s:%d]: '%s' has to be > 0.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (newsrv->health)
					newsrv->health = newsrv->rise;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "fall")) {
				newsrv->fall = atol(args[cur_arg + 1]);

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (newsrv->fall <= 0) {
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
				newsrv->inter = val;
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
				newsrv->fastinter = val;
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
				newsrv->downinter = val;
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "addr")) {
				struct sockaddr_in *sk = str2sa(args[cur_arg + 1]);
				if (!sk) {
					Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->check_addr = *sk;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "port")) {
				newsrv->check_port = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "backup")) {
				newsrv->state |= SRV_BACKUP;
				cur_arg ++;
			}
			else if (!strcmp(args[cur_arg], "weight")) {
				int w;
				w = atol(args[cur_arg + 1]);
				if (w < 0 || w > 256) {
					Alert("parsing [%s:%d] : weight of server %s is not within 0 and 256 (%d).\n",
					      file, linenum, newsrv->id, w);
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
				if (val < 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
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
				newsrv->health = 0;
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
						"'l4events', 'http-responses' but get '%s'\n",
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
						"'fail-check', 'sudden-death' or 'mark-down' but get '%s'\n",
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
				struct sockaddr_in *sk;

				if (!*args[cur_arg + 1]) {
#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>[-<port>]], and optional '%s' <addr> as argument.\n",
					      file, linenum, "source", "usesrc");
#else
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>[-<port>]] as argument.\n",
					      file, linenum, "source");
#endif
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->state |= SRV_BIND_SRC;
				sk = str2sa_range(args[cur_arg + 1], &port_low, &port_high);
				if (!sk) {
					Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->source_addr = *sk;

				if (port_low != port_high) {
					int i;
					if (port_low  <= 0 || port_low > 65535 ||
					    port_high <= 0 || port_high > 65535 ||
					    port_low > port_high) {
						Alert("parsing [%s:%d] : invalid source port range %d-%d.\n",
						      file, linenum, port_low, port_high);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					newsrv->sport_range = port_range_alloc_range(port_high - port_low + 1);
					for (i = 0; i < newsrv->sport_range->size; i++)
						newsrv->sport_range->ports[i] = port_low + i;
				}

				cur_arg += 2;
				while (*(args[cur_arg])) {
					if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside */
#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
#if !defined(CONFIG_HAP_LINUX_TPROXY)
						if (newsrv->source_addr.sin_addr.s_addr == INADDR_ANY) {
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
							newsrv->state &= ~SRV_TPROXY_MASK;
							newsrv->state |= SRV_TPROXY_CLI;
						} else if (!strcmp(args[cur_arg + 1], "clientip")) {
							newsrv->state &= ~SRV_TPROXY_MASK;
							newsrv->state |= SRV_TPROXY_CIP;
						} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
							char *name, *end;

							name = args[cur_arg+1] + 7;
							while (isspace(*name))
								name++;

							end = name;
							while (*end && !isspace(*end) && *end != ',' && *end != ')')
								end++;

							newsrv->state &= ~SRV_TPROXY_MASK;
							newsrv->state |= SRV_TPROXY_DYN;
							newsrv->bind_hdr_name = calloc(1, end - name + 1);
							newsrv->bind_hdr_len = end - name;
							memcpy(newsrv->bind_hdr_name, name, end - name);
							newsrv->bind_hdr_name[end-name] = '\0';
							newsrv->bind_hdr_occ = -1;

							/* now look for an occurrence number */
							while (isspace(*end))
								end++;
							if (*end == ',') {
								end++;
								name = end;
								if (*end == '-')
									end++;
								while (isdigit(*end))
									end++;
								newsrv->bind_hdr_occ = strl2ic(name, end-name);
							}

							if (newsrv->bind_hdr_occ < -MAX_HDR_HISTORY) {
								Alert("parsing [%s:%d] : usesrc hdr_ip(name,num) does not support negative"
								      " occurrences values smaller than %d.\n",
								      file, linenum, MAX_HDR_HISTORY);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
						} else {
							struct sockaddr_in *sk = str2sa(args[cur_arg + 1]);
							if (!sk) {
								Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[cur_arg + 1]);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
							newsrv->tproxy_addr = *sk;
							newsrv->state |= SRV_TPROXY_ADDR;
						}
						global.last_checks |= LSTCHK_NETADM;
#if !defined(CONFIG_HAP_LINUX_TPROXY)
						global.last_checks |= LSTCHK_CTTPROXY;
#endif
						cur_arg += 2;
						continue;
#else	/* no TPROXY support */
						Alert("parsing [%s:%d] : '%s' not allowed here because support for TPROXY was not compiled in.\n",
						      file, linenum, "usesrc");
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
#endif /* defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY) */
					} /* "usesrc" */

					if (!strcmp(args[cur_arg], "interface")) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
						if (!*args[cur_arg + 1]) {
							Alert("parsing [%s:%d] : '%s' : missing interface name.\n",
							      file, linenum, args[0]);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
						if (newsrv->iface_name)
							free(newsrv->iface_name);

						newsrv->iface_name = strdup(args[cur_arg + 1]);
						newsrv->iface_len  = strlen(newsrv->iface_name);
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
				if (!defsrv)
					Alert("parsing [%s:%d] : server %s only supports options 'backup', 'cookie', 'redir', 'observer', 'on-error', 'error-limit', 'check', 'disabled', 'track', 'id', 'inter', 'fastinter', 'downinter', 'rise', 'fall', 'addr', 'port', 'source', 'minconn', 'maxconn', 'maxqueue', 'slowstart' and 'weight'.\n",
					      file, linenum, newsrv->id);
				else
					Alert("parsing [%s:%d]: default-server only supports options 'on-error', 'error-limit', 'inter', 'fastinter', 'downinter', 'rise', 'fall', 'port', 'minconn', 'maxconn', 'maxqueue', 'slowstart' and 'weight'.\n",
					      file, linenum);

				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if (do_check) {
			if (newsrv->trackit) {
				Alert("parsing [%s:%d]: unable to enable checks and tracking at the same time!\n",
					file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!newsrv->check_port && newsrv->check_addr.sin_port)
				newsrv->check_port = newsrv->check_addr.sin_port;

			if (!newsrv->check_port && !(newsrv->state & SRV_MAPPORTS))
				newsrv->check_port = realport; /* by default */
			if (!newsrv->check_port) {
				/* not yet valid, because no port was set on
				 * the server either. We'll check if we have
				 * a known port on the first listener.
				 */
				struct listener *l;
				l = curproxy->listen;
				if (l) {
					int port;
					port = (l->addr.ss_family == AF_INET6)
					        ? ntohs(((struct sockaddr_in6 *)(&l->addr))->sin6_port)
						: ntohs(((struct sockaddr_in *)(&l->addr))->sin_port);
					newsrv->check_port = port;
				}
			}
			if (!newsrv->check_port) {
				Alert("parsing [%s:%d] : server %s has neither service port nor check port. Check has been disabled.\n",
				      file, linenum, newsrv->id);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* Allocate buffer for partial check results... */
			if ((newsrv->check_data = calloc(BUFSIZE, sizeof(char))) == NULL) {
				Alert("parsing [%s:%d] : out of memory while allocating check buffer.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			newsrv->check_status = HCHK_STATUS_INI;
			newsrv->state |= SRV_CHECKED;
		}

		if (!defsrv) {
			if (newsrv->state & SRV_BACKUP)
				curproxy->srv_bck++;
			else
				curproxy->srv_act++;

			newsrv->prev_state = newsrv->state;
		}
	}
	else if (!strcmp(args[0], "log")) {  /* syslog server address */
		struct logsrv logsrv;
		int facility;
	
		if (*(args[1]) && *(args[2]) == 0 && !strcmp(args[1], "global")) {
			curproxy->logfac1 = global.logfac1;
			curproxy->logsrv1 = global.logsrv1;
			curproxy->loglev1 = global.loglev1;
			curproxy->minlvl1 = global.minlvl1;
			curproxy->logfac2 = global.logfac2;
			curproxy->logsrv2 = global.logsrv2;
			curproxy->loglev2 = global.loglev2;
			curproxy->minlvl2 = global.minlvl2;
		}
		else if (*(args[1]) && *(args[2])) {
			int level, minlvl;

			facility = get_log_facility(args[2]);
			if (facility < 0) {
				Alert("parsing [%s:%d] : unknown log facility '%s'\n", file, linenum, args[2]);
				exit(1);
			}
	    
			level = 7; /* max syslog level = debug */
			if (*(args[3])) {
				level = get_log_level(args[3]);
				if (level < 0) {
					Alert("parsing [%s:%d] : unknown optional log level '%s'\n", file, linenum, args[3]);
					exit(1);
				}
			}

			minlvl = 0; /* limit syslog level to this level (emerg) */
			if (*(args[4])) {
				minlvl = get_log_level(args[4]);
				if (level < 0) {
					Alert("parsing [%s:%d] : unknown optional minimum log level '%s'\n", file, linenum, args[4]);
					exit(1);
				}
			}

			if (args[1][0] == '/') {
				struct sockaddr_un *sk = str2sun(args[1]);
				if (!sk) {
					Alert("parsing [%s:%d] : Socket path '%s' too long (max %d)\n", file, linenum,
					      args[1], (int)sizeof(sk->sun_path) - 1);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				logsrv.u.un = *sk;
				logsrv.u.addr.sa_family = AF_UNIX;
			} else {
				struct sockaddr_in *sk = str2sa(args[1]);
				if (!sk) {
					Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				logsrv.u.in = *sk;
				logsrv.u.addr.sa_family = AF_INET;
				if (!logsrv.u.in.sin_port) {
					logsrv.u.in.sin_port =
						htons(SYSLOG_PORT);
				}
			}
	    
			if (curproxy->logfac1 == -1) {
				curproxy->logsrv1 = logsrv;
				curproxy->logfac1 = facility;
				curproxy->loglev1 = level;
				curproxy->minlvl1 = minlvl;
			}
			else if (curproxy->logfac2 == -1) {
				curproxy->logsrv2 = logsrv;
				curproxy->logfac2 = facility;
				curproxy->loglev2 = level;
				curproxy->minlvl2 = minlvl;
			}
			else {
				Alert("parsing [%s:%d] : too many syslog servers\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
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
		struct sockaddr_in *sk;

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], and optionally '%s' <addr>, and '%s' <name>.\n",
			      file, linenum, "source", "usesrc", "interface");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* we must first clear any optional default setting */	
		curproxy->options &= ~PR_O_TPXY_MASK;
		free(curproxy->iface_name);
		curproxy->iface_name = NULL;
		curproxy->iface_len = 0;

		sk = str2sa(args[1]);
		if (!sk) {
			Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->source_addr = *sk;
		curproxy->options |= PR_O_BIND_SRC;

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside */
#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
#if !defined(CONFIG_HAP_LINUX_TPROXY)
				if (curproxy->source_addr.sin_addr.s_addr == INADDR_ANY) {
					Alert("parsing [%s:%d] : '%s' requires an explicit 'source' address.\n",
					      file, linenum, "usesrc");
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
#endif
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', or 'clientip' as argument.\n",
					      file, linenum, "usesrc");
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!strcmp(args[cur_arg + 1], "client")) {
					curproxy->options &= ~PR_O_TPXY_MASK;
					curproxy->options |= PR_O_TPXY_CLI;
				} else if (!strcmp(args[cur_arg + 1], "clientip")) {
					curproxy->options &= ~PR_O_TPXY_MASK;
					curproxy->options |= PR_O_TPXY_CIP;
				} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
					char *name, *end;

					name = args[cur_arg+1] + 7;
					while (isspace(*name))
						name++;

					end = name;
					while (*end && !isspace(*end) && *end != ',' && *end != ')')
						end++;

					curproxy->options &= ~PR_O_TPXY_MASK;
					curproxy->options |= PR_O_TPXY_DYN;
					curproxy->bind_hdr_name = calloc(1, end - name + 1);
					curproxy->bind_hdr_len = end - name;
					memcpy(curproxy->bind_hdr_name, name, end - name);
					curproxy->bind_hdr_name[end-name] = '\0';
					curproxy->bind_hdr_occ = -1;

					/* now look for an occurrence number */
					while (isspace(*end))
						end++;
					if (*end == ',') {
						end++;
						name = end;
						if (*end == '-')
							end++;
						while (isdigit(*end))
							end++;
						curproxy->bind_hdr_occ = strl2ic(name, end-name);
					}

					if (curproxy->bind_hdr_occ < -MAX_HDR_HISTORY) {
						Alert("parsing [%s:%d] : usesrc hdr_ip(name,num) does not support negative"
						      " occurrences values smaller than %d.\n",
						      file, linenum, MAX_HDR_HISTORY);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				} else {
					struct sockaddr_in *sk = str2sa(args[cur_arg + 1]);
					if (!sk) {
						Alert("parsing [%s:%d] : Unknown host in '%s'\n", file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					curproxy->tproxy_addr = *sk;
					curproxy->options |= PR_O_TPXY_ADDR;
				}
				global.last_checks |= LSTCHK_NETADM;
#if !defined(CONFIG_HAP_LINUX_TPROXY)
				global.last_checks |= LSTCHK_CTTPROXY;
#endif
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
				if (curproxy->iface_name)
					free(curproxy->iface_name);

				curproxy->iface_name = strdup(args[cur_arg + 1]);
				curproxy->iface_len  = strlen(curproxy->iface_name);
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
			      file, linenum, args[0], "inteface", "usesrc");
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
						   ACL_DIR_REQ, ACT_REPLACE, 0,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqdel")) {  /* delete request header from a regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_REMOVE, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqdeny")) {  /* deny a request if a header matches this regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_DENY, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqpass")) {  /* pass this header without allowing or denying the request */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_PASS, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqallow")) {  /* allow a request if a header matches this regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_ALLOW, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqtarpit")) {  /* tarpit a request if a header matches this regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_TARPIT, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqsetbe")) { /* switch the backend from a regex, respecting case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_SETBE, 0,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqisetbe")) { /* switch the backend from a regex, ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_SETBE, REG_ICASE,
						   args[0], args[1], args[2], (const char **)args+3);
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
						   ACL_DIR_REQ, ACT_REPLACE, REG_ICASE,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqidel")) {  /* delete request header from a regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_REMOVE, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqideny")) {  /* deny a request if a header matches this regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_DENY, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqipass")) {  /* pass this header without allowing or denying the request */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_PASS, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqiallow")) {  /* allow a request if a header matches this regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_ALLOW, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "reqitarpit")) {  /* tarpit a request if a header matches this regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_REQ, ACT_TARPIT, REG_ICASE,
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
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args+2)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing a '%s' condition.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			err_code |= warnif_cond_requires_resp(cond, file, linenum);
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
						   ACL_DIR_RTR, ACT_REPLACE, 0,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspdel")) {  /* delete response header from a regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_RTR, ACT_REMOVE, 0,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspdeny")) {  /* block response header from a regex */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_RTR, ACT_DENY, 0,
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
						   ACL_DIR_RTR, ACT_REPLACE, REG_ICASE,
						   args[0], args[1], args[2], (const char **)args+3);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspidel")) {  /* delete response header from a regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_RTR, ACT_REMOVE, REG_ICASE,
						   args[0], args[1], NULL, (const char **)args+2);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "rspideny")) {  /* block response header from a regex ignoring case */
		err_code |= create_cond_regex_rule(file, linenum, curproxy,
						   ACL_DIR_RTR, ACT_DENY, REG_ICASE,
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
			if ((cond = build_acl_cond(file, linenum, curproxy, (const char **)args+2)) == NULL) {
				Alert("parsing [%s:%d] : error detected while parsing a '%s' condition.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			err_code |= warnif_cond_requires_req(cond, file, linenum);
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
			err = malloc(strlen(HTTP_303) + strlen(args[2]) + 5);
			errlen = sprintf(err, "%s%s\r\n\r\n", HTTP_303, args[2]);
		} else {
			err = malloc(strlen(HTTP_302) + strlen(args[2]) + 5);
			errlen = sprintf(err, "%s%s\r\n\r\n", HTTP_302, args[2]);
		}

		for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
			if (http_err_codes[rc] == errnum) {
				chunk_destroy(&curproxy->errmsg[rc]);
				chunk_initlen(&curproxy->errmsg[rc], err, errlen, errlen);
				break;
			}
		}

		if (rc >= HTTP_ERR_SIZE) {
			Warning("parsing [%s:%d] : status code %d not handled, error relocation will be ignored.\n",
				file, linenum, errnum);
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
			Warning("parsing [%s:%d] : status code %d not handled, error customization will be ignored.\n",
				file, linenum, errnum);
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
					snprintf(trash, sizeof(trash),
						 "error near '%s' in %s section", args[0], cursection);
					rc = kwl->kw[index].parse(args, CFG_LISTEN, curproxy, &defproxy, trash, sizeof(trash));
					if (rc < 0) {
						Alert("parsing [%s:%d] : %s\n", file, linenum, trash);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					else if (rc > 0) {
						Warning("parsing [%s:%d] : %s\n", file, linenum, trash);
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
	return err_code;
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

		newul = (struct userlist *)calloc(1, sizeof(struct userlist));
		if (!newul) {
			Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		newul->groupusers = calloc(MAX_AUTH_GROUPS, sizeof(char *));
		newul->name = strdup(args[1]);

		if (!newul->groupusers | !newul->name) {
			Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		newul->next = userlist;
		userlist = newul;

	} else if (!strcmp(args[0], "group")) {  	/* new group */
		int cur_arg, i;
		const char *err;

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

		for(i = 0; i < userlist->grpcnt; i++)
			if (!strcmp(userlist->groups[i], args[1])) {
				Warning("parsing [%s:%d]: ignoring duplicated group '%s' in userlist '%s'.\n",
				      file, linenum, args[1], userlist->name);
				err_code |= ERR_ALERT;
				goto out;
			}

		if (userlist->grpcnt >= MAX_AUTH_GROUPS) {
			Alert("parsing [%s:%d]: too many groups (%u) in in userlist '%s' while adding group '%s'.\n",
			      file, linenum, MAX_AUTH_GROUPS, userlist->name, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		cur_arg = 2;

		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "users")) {
				userlist->groupusers[userlist->grpcnt] = strdup(args[cur_arg + 1]);
				cur_arg += 2;
				continue;
			} else {
				Alert("parsing [%s:%d]: '%s' only supports 'users' option.\n",
				      file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		userlist->groups[userlist->grpcnt++] = strdup(args[1]);
	} else if (!strcmp(args[0], "user")) {		/* new user */
		struct auth_users *newuser;
		int cur_arg;

		if (!*args[1]) {
			Alert("parsing [%s:%d]: '%s' expects <name> as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (newuser = userlist->users; newuser; newuser = newuser->next)
			if (!strcmp(newuser->user, args[1])) {
				Warning("parsing [%s:%d]: ignoring duplicated user '%s' in userlist '%s'.\n",
				      file, linenum, args[1], userlist->name);
				err_code |= ERR_ALERT;
				goto out;
			}

		newuser = (struct auth_users *)calloc(1, sizeof(struct auth_users));
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
#ifndef CONFIG_HAP_CRYPT
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
				newuser->u.groups = strdup(args[cur_arg + 1]);
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
	char thisline[LINESIZE];
	FILE *f;
	int linenum = 0;
	int confsect = CFG_NONE;
	int err_code = 0;

	if ((f=fopen(file,"r")) == NULL)
		return -1;

	while (fgets(thisline, sizeof(thisline), f) != NULL) {
		int arg, kwm = KWM_STD;
		char *end;
		char *args[MAX_LINE_ARGS + 1];
		char *line = thisline;

		linenum++;

		end = line + strlen(line);

		if (end-line == sizeof(thisline)-1 && *(end-1) != '\n') {
			/* Check if we reached the limit and the last char is not \n.
			 * Watch out for the last line without the terminating '\n'!
			 */
			Alert("parsing [%s:%d]: line too long, limit: %d.\n",
			      file, linenum, (int)sizeof(thisline)-1);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		/* skip leading spaces */
		while (isspace((unsigned char)*line))
			line++;
	
		arg = 0;
		args[arg] = line;

		while (*line && arg < MAX_LINE_ARGS) {
			/* first, we'll replace \\, \<space>, \#, \r, \n, \t, \xXX with their
			 * C equivalent value. Other combinations left unchanged (eg: \1).
			 */
			if (*line == '\\') {
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
				}
				if (skip) {
					memmove(line + 1, line + 1 + skip, end - (line + skip));
					end -= skip;
				}
				line++;
			}
			else if (*line == '#' || *line == '\n' || *line == '\r') {
				/* end of string, end of loop */
				*line = 0;
				break;
			}
			else if (isspace((unsigned char)*line)) {
				/* a non-escaped space is an argument separator */
				*line++ = '\0';
				while (isspace((unsigned char)*line))
					line++;
				args[++arg] = line;
			}
			else {
				line++;
			}
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
			kwm = KWM_NO;
			for (arg=0; *args[arg+1]; arg++)
				args[arg] = args[arg+1];		// shift args after inversion
		}
		else if (!strcmp(args[0], "default")) {
			kwm = KWM_DEF;
			for (arg=0; *args[arg+1]; arg++)
				args[arg] = args[arg+1];		// shift args after inversion
		}

		if (kwm != KWM_STD && strcmp(args[0], "option") != 0) {
			Alert("parsing [%s:%d]: negation/default currently supported only for options.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (!strcmp(args[0], "listen") ||
		    !strcmp(args[0], "frontend") ||
		    !strcmp(args[0], "backend") ||
		    !strcmp(args[0], "ruleset") ||
		    !strcmp(args[0], "defaults")) { /* new proxy */
			confsect = CFG_LISTEN;
			free(cursection);
			cursection = strdup(args[0]);
		}
		else if (!strcmp(args[0], "global")) { /* global config */
			confsect = CFG_GLOBAL;
			free(cursection);
			cursection = strdup(args[0]);
		} else if (!strcmp(args[0], "userlist")) {
			confsect = CFG_USERLIST;
			free(cursection);
			cursection = strdup(args[0]);
		}
		/* else it's a section keyword */

		switch (confsect) {
		case CFG_LISTEN:
			err_code |= cfg_parse_listen(file, linenum, args, kwm);
			break;
		case CFG_GLOBAL:
			err_code |= cfg_parse_global(file, linenum, args, kwm);
			break;
		case CFG_USERLIST:
			err_code |= cfg_parse_users(file, linenum, args, kwm);
			break;
		default:
			Alert("parsing [%s:%d]: unknown keyword '%s' out of section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (err_code & ERR_ABORT)
			break;
	}
	free(cursection);
	cursection = NULL;
	fclose(f);
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
	int cfgerr = 0;
	struct proxy *curproxy = NULL;
	struct server *newsrv = NULL;
	struct userlist *curuserlist = NULL;
	int err_code = 0;
	unsigned int next_pxid = 1;

	/*
	 * Now, check for the integrity of all that we have collected.
	 */

	/* will be needed further to delay some tasks */
	tv_update_date(0,1);

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

	if ((curproxy = proxy) == NULL) {
		Alert("config : no <listen> line. Nothing to do !\n");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	while (curproxy != NULL) {
		struct switching_rule *rule;
		struct sticking_rule *mrule;
		struct listener *listener;
		unsigned int next_id;

		if (!curproxy->uuid) {
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
			curproxy = curproxy->next;
			continue;
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
			curproxy->acl_requires |= ACL_USE_L7_ANY;
			if ((curproxy->cookie_name != NULL) && (curproxy->srv == NULL)) {
				Alert("config : HTTP proxy %s has a cookie but no server list !\n",
				      curproxy->id);
				cfgerr++;
			}
			break;
		}

		if ((curproxy->cap & PR_CAP_FE) && (curproxy->listen == NULL))  {
			Alert("config : %s '%s' has no listen address. Please either specify a valid address on the <listen> line, or use the <bind> keyword.\n",
			      proxy_type_str(curproxy), curproxy->id);
			cfgerr++;
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
				else if (*(int *)&curproxy->dispatch_addr.sin_addr != 0) {
					Warning("config : dispatch address of %s '%s' will be ignored in balance mode.\n",
						proxy_type_str(curproxy), curproxy->id);
					err_code |= ERR_WARN;
				}
			}
			else if (!(curproxy->options & (PR_O_TRANSP | PR_O_HTTP_PROXY)) &&
				 (*(int *)&curproxy->dispatch_addr.sin_addr == 0)) {
				/* If no LB algo is set in a backend, and we're not in
				 * transparent mode, dispatch mode nor proxy mode, we
				 * want to use balance roundrobin by default.
				 */
				curproxy->lbprm.algo &= ~BE_LB_ALGO;
				curproxy->lbprm.algo |= BE_LB_ALGO_RR;
			}
		}

		if ((curproxy->options & PR_O_DISABLE404) && !(curproxy->options & PR_O_HTTP_CHK)) {
			curproxy->options &= ~PR_O_DISABLE404;
			Warning("config : '%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
				"disable-on-404", proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if ((curproxy->options2 & PR_O2_CHK_SNDST) && !(curproxy->options & PR_O_HTTP_CHK)) {
			curproxy->options &= ~PR_O2_CHK_SNDST;
			Warning("config : '%s' will be ignored for %s '%s' (requires 'option httpchk').\n",
				"send-state", proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		/* if a default backend was specified, let's find it */
		if (curproxy->defbe.name) {
			struct proxy *target;

			target = findproxy_mode(curproxy->defbe.name, curproxy->mode, PR_CAP_BE);
			if (!target) {
				Alert("Proxy '%s': unable to find required default_backend: '%s'.\n",
					curproxy->id, curproxy->defbe.name);
				cfgerr++;
			} else if (target == curproxy) {
				Alert("Proxy '%s': loop detected for default_backend: '%s'.\n",
					curproxy->id, curproxy->defbe.name);
				cfgerr++;
			} else {
				free(curproxy->defbe.name);
				curproxy->defbe.be = target;
				/* we force the backend to be present on at least all of
				 * the frontend's processes.
				 */
				target->bind_proc = curproxy->bind_proc ?
					(target->bind_proc | curproxy->bind_proc) : 0;
			}
		}

		/* find the target proxy in setbe */
		if (curproxy->mode == PR_MODE_HTTP && curproxy->req_exp != NULL) {
			/* map jump target for ACT_SETBE in req_rep chain */ 
			struct hdr_exp *exp;
			for (exp = curproxy->req_exp; exp != NULL; exp = exp->next) {
				struct proxy *target;

				if (exp->action != ACT_SETBE)
					continue;

				target = findproxy_mode(exp->replace, PR_MODE_HTTP, PR_CAP_BE);
				if (!target) {
					Alert("Proxy '%s': unable to find required setbe: '%s'.\n",
						curproxy->id, exp->replace);
					cfgerr++;
				} else if (target == curproxy) {
					Alert("Proxy '%s': loop detected for setbe: '%s'.\n",
						curproxy->id, exp->replace);
					cfgerr++;
				} else {
					free((void *)exp->replace);
					exp->replace = (const char *)target;
					/* we force the backend to be present on at least all of
					 * the frontend's processes.
					 */
					target->bind_proc = curproxy->bind_proc ?
						(target->bind_proc | curproxy->bind_proc) : 0;
				}
			}
		}

		/* find the target proxy for 'use_backend' rules */
		list_for_each_entry(rule, &curproxy->switching_rules, list) {
			struct proxy *target;

			target = findproxy_mode(rule->be.name, curproxy->mode, PR_CAP_BE);

			if (!target) {
				Alert("Proxy '%s': unable to find required use_backend: '%s'.\n",
					curproxy->id, rule->be.name);
				cfgerr++;
			} else if (target == curproxy) {
				Alert("Proxy '%s': loop detected for use_backend: '%s'.\n",
					curproxy->id, rule->be.name);
				cfgerr++;
			} else {
				free((void *)rule->be.name);
				rule->be.backend = target;
				/* we force the backend to be present on at least all of
				 * the frontend's processes.
				 */
				target->bind_proc = curproxy->bind_proc ?
					(target->bind_proc | curproxy->bind_proc) : 0;
			}
		}

		/* find the target table for 'stick' rules */
		list_for_each_entry(mrule, &curproxy->sticking_rules, list) {
			struct proxy *target;

			curproxy->be_req_ana |= AN_REQ_STICKING_RULES;
			if (mrule->flags & STK_IS_STORE)
				curproxy->be_rsp_ana |= AN_RES_STORE_RULES;

			if (mrule->table.name)
				target = findproxy(mrule->table.name, PR_CAP_BE);
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
			else if (pattern_notusable_key(mrule->expr,  target->table.type)) {
				Alert("Proxy '%s': type of pattern not usable with type of stick-table '%s'.\n",
				      curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else {
				free((void *)mrule->table.name);
				mrule->table.t = &(target->table);
			}
		}

		/* find the target table for 'store response' rules */
		list_for_each_entry(mrule, &curproxy->storersp_rules, list) {
			struct proxy *target;

			curproxy->be_rsp_ana |= AN_RES_STORE_RULES;

			if (mrule->table.name)
				target = findproxy(mrule->table.name, PR_CAP_BE);
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
			else if (pattern_notusable_key(mrule->expr, target->table.type)) {
				Alert("Proxy '%s': type of pattern not usable with type of stick-table '%s'.\n",
				      curproxy->id, mrule->table.name ? mrule->table.name : curproxy->id);
				cfgerr++;
			}
			else {
				free((void *)mrule->table.name);
				mrule->table.t = &(target->table);
			}
		}

		if (curproxy->uri_auth && !(curproxy->uri_auth->flags & ST_CONVDONE) &&
		    !LIST_ISEMPTY(&curproxy->uri_auth->req_acl) &&
		    (curproxy->uri_auth->userlist || curproxy->uri_auth->auth_realm )) {
			Alert("%s '%s': stats 'auth'/'realm' and 'http-request' can't be used at the same time.\n",
			      "proxy", curproxy->id);
			cfgerr++;
			goto out_uri_auth_compat;
		}

		if (curproxy->uri_auth && curproxy->uri_auth->userlist && !(curproxy->uri_auth->flags & ST_CONVDONE)) {
			const char *uri_auth_compat_req[10];
			struct req_acl_rule *req_acl;
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

			req_acl = parse_auth_cond(uri_auth_compat_req, "internal-stats-auth-compat", 0, curproxy);
			if (!req_acl) {
				cfgerr++;
				break;
			}

			LIST_ADDQ(&curproxy->uri_auth->req_acl, &req_acl->list);

			if (curproxy->uri_auth->auth_realm) {
				free(curproxy->uri_auth->auth_realm);
				curproxy->uri_auth->auth_realm = NULL;
			}

			curproxy->uri_auth->flags |= ST_CONVDONE;
		}
out_uri_auth_compat:

		cfgerr += acl_find_targets(curproxy);

		if ((curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HTTP) &&
		    (((curproxy->cap & PR_CAP_FE) && !curproxy->timeout.client) ||
		     ((curproxy->cap & PR_CAP_BE) && (curproxy->srv) &&
		      (!curproxy->timeout.connect || !curproxy->timeout.server)))) {
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

		if (curproxy->options2 & PR_O2_SSL3_CHK) {
			curproxy->check_len = sizeof(sslv3_client_hello_pkt) - 1;
			curproxy->check_req = (char *)malloc(curproxy->check_len);
			memcpy(curproxy->check_req, sslv3_client_hello_pkt, curproxy->check_len);
		}

		/* The small pools required for the capture lists */
		if (curproxy->nb_req_cap)
			curproxy->req_cap_pool = create_pool("ptrcap",
							     curproxy->nb_req_cap * sizeof(char *),
							     MEM_F_SHARED);
		if (curproxy->nb_rsp_cap)
			curproxy->rsp_cap_pool = create_pool("ptrcap",
							     curproxy->nb_rsp_cap * sizeof(char *),
							     MEM_F_SHARED);

		curproxy->hdr_idx_pool = create_pool("hdr_idx",
						     MAX_HTTP_HDR * sizeof(struct hdr_idx_elem),
						     MEM_F_SHARED);

		/* for backwards compatibility with "listen" instances, if
		 * fullconn is not set but maxconn is set, then maxconn
		 * is used.
		 */
		if (!curproxy->fullconn)
			curproxy->fullconn = curproxy->maxconn;

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

		case BE_LB_KIND_LC:
			curproxy->lbprm.algo |= BE_LB_LKUP_LCTREE | BE_LB_PROP_DYN;
			fwlc_init_server_tree(curproxy);
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
		    (curproxy->cap & PR_CAP_FE) && curproxy->to_log && curproxy->logfac1 < 0) {
			Warning("config : log format ignored for %s '%s' since it has no log address.\n",
				proxy_type_str(curproxy), curproxy->id);
			err_code |= ERR_WARN;
		}

		if (curproxy->mode != PR_MODE_HTTP) {
			int optnum;

			if (curproxy->options & PR_O_COOK_ANY) {
				Warning("config : 'cookie' statement ignored for %s '%s' as it requires HTTP mode.\n",
					proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
			}

			if (curproxy->uri_auth) {
				Warning("config : 'stats' statement ignored for %s '%s' as it requires HTTP mode.\n",
					proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->uri_auth = NULL;
			}

			if (curproxy->options & PR_O_FWDFOR) {
				Warning("config : 'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					"forwardfor", proxy_type_str(curproxy), curproxy->id);
				err_code |= ERR_WARN;
				curproxy->options &= ~PR_O_FWDFOR;
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

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
			if (curproxy->bind_hdr_occ) {
				curproxy->bind_hdr_occ = 0;
				Warning("config : %s '%s' : ignoring use of header %s as source IP in non-HTTP mode.\n",
					proxy_type_str(curproxy), curproxy->id, curproxy->bind_hdr_name);
				err_code |= ERR_WARN;
			}
#endif
		}

		/*
		 * ensure that we're not cross-dressing a TCP server into HTTP.
		 */
		newsrv = curproxy->srv;
		while (newsrv != NULL) {
			if ((curproxy->mode != PR_MODE_HTTP) && (newsrv->rdr_len || newsrv->cklen)) {
				Alert("config : %s '%s' : server cannot have cookie or redirect prefix in non-HTTP mode.\n",
				      proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
			if (curproxy->mode != PR_MODE_HTTP && newsrv->bind_hdr_occ) {
				newsrv->bind_hdr_occ = 0;
				Warning("config : %s '%s' : server %s cannot use header %s as source IP in non-HTTP mode.\n",
					proxy_type_str(curproxy), curproxy->id, newsrv->id, newsrv->bind_hdr_name);
				err_code |= ERR_WARN;
			}
#endif
			newsrv = newsrv->next;
		}

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
			} else if (newsrv->minconn != newsrv->maxconn && !curproxy->fullconn) {
				Alert("config : %s '%s' : fullconn is mandatory when minconn is set on a server.\n",
				      proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}

			if (newsrv->trackit) {
				struct proxy *px;
				struct server *srv;
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
					px = findproxy(pname, PR_CAP_BE);
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

				if (!(srv->state & SRV_CHECKED)) {
					Alert("config : %s '%s', server '%s': unable to use %s/%s for "
						"tracking as it does not have checks enabled.\n",
						proxy_type_str(curproxy), curproxy->id,
						newsrv->id, px->id, srv->id);
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

				newsrv->tracked = srv;
				newsrv->tracknext = srv->tracknext;
				srv->tracknext = newsrv;

				free(newsrv->trackit);
			}
		next_srv:
			newsrv = newsrv->next;
		}

		if (curproxy->cap & PR_CAP_FE) {
			if (curproxy->tcp_req.inspect_delay ||
			    !LIST_ISEMPTY(&curproxy->tcp_req.inspect_rules))
				curproxy->fe_req_ana |= AN_REQ_INSPECT;

			if (curproxy->mode == PR_MODE_HTTP) {
				curproxy->fe_req_ana |= AN_REQ_WAIT_HTTP | AN_REQ_HTTP_PROCESS_FE;
				curproxy->fe_rsp_ana |= AN_RES_WAIT_HTTP | AN_RES_HTTP_PROCESS_FE;
			}

			/* both TCP and HTTP must check switching rules */
			curproxy->fe_req_ana |= AN_REQ_SWITCHING_RULES;
		}

		if (curproxy->cap & PR_CAP_BE) {
			if (curproxy->mode == PR_MODE_HTTP) {
				curproxy->be_req_ana |= AN_REQ_WAIT_HTTP | AN_REQ_HTTP_INNER | AN_REQ_HTTP_PROCESS_BE;
				curproxy->be_rsp_ana |= AN_RES_WAIT_HTTP | AN_RES_HTTP_PROCESS_BE;
			}

			/* init table on backend capabilities proxy */
			stktable_init(&curproxy->table);

			/* If the backend does requires RDP cookie persistence, we have to
			 * enable the corresponding analyser.
			 */
			if (curproxy->options2 & PR_O2_RDPC_PRST)
				curproxy->be_req_ana |= AN_REQ_PRST_RDP_COOKIE;
		}

		listener = NULL;
		while (curproxy->listen) {
			struct listener *next;

			next = curproxy->listen->next;
			curproxy->listen->next = listener;
			listener = curproxy->listen;

			if (!next)
				break;

			curproxy->listen = next;
		}

		/* adjust this proxy's listeners */
		next_id = 1;
		listener = curproxy->listen;
		while (listener) {
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
				listener->counters = (struct licounters *)calloc(1, sizeof(struct licounters));
				if (!listener->name) {
					sprintf(trash, "sock-%d", listener->luid);
					listener->name = strdup(trash);
				}
			}

			if (curproxy->options & PR_O_TCP_NOLING)
				listener->options |= LI_O_NOLINGER;
			listener->maxconn = curproxy->maxconn;
			listener->backlog = curproxy->backlog;
			listener->timeout = &curproxy->timeout.client;
			listener->accept = frontend_accept;
			listener->frontend = curproxy;
			listener->handler = process_session;
			listener->analysers |= curproxy->fe_req_ana;

			/* smart accept mode is automatic in HTTP mode */
			if ((curproxy->options2 & PR_O2_SMARTACC) ||
			    (curproxy->mode == PR_MODE_HTTP &&
			     !(curproxy->no_options2 & PR_O2_SMARTACC)))
				listener->options |= LI_O_NOQUICKACK;

			/* We want the use_backend and default_backend rules to apply */
			listener = listener->next;
		}

		curproxy = curproxy->next;
	}

	for (curuserlist = userlist; curuserlist; curuserlist = curuserlist->next) {
		struct auth_users *curuser;
		int g;

		for (curuser = curuserlist->users; curuser; curuser = curuser->next) {
			unsigned int group_mask = 0;
			char *group = NULL;

			if (!curuser->u.groups)
				continue;

			while ((group = strtok(group?NULL:curuser->u.groups, ","))) {

				for (g = 0; g < curuserlist->grpcnt; g++)
					if (!strcmp(curuserlist->groups[g], group))
						break;

				if (g == curuserlist->grpcnt) {
					Alert("userlist '%s': no such group '%s' specified in user '%s'\n",
					      curuserlist->name, group, curuser->user);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				group_mask |= (1 << g);
			}

			free(curuser->u.groups);
			curuser->u.group_mask = group_mask;
		}

		for (g = 0; g < curuserlist->grpcnt; g++) {
			char *user = NULL;

			if (!curuserlist->groupusers[g])
				continue;

			while ((user = strtok(user?NULL:curuserlist->groupusers[g], ","))) {
				for (curuser = curuserlist->users; curuser; curuser = curuser->next)
					if (!strcmp(curuser->user, user))
						break;

				if (!curuser) {
					Alert("userlist '%s': no such user '%s' specified in group '%s'\n",
					      curuserlist->name, user, curuserlist->groups[g]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				curuser->u.group_mask |= (1 << g);
			}

			free(curuserlist->groupusers[g]);
		}

		free(curuserlist->groupusers);

#ifdef DEBUG_AUTH
		for (g = 0; g < curuserlist->grpcnt; g++) {
			fprintf(stderr, "group %s, id %d, mask %08X, users:", curuserlist->groups[g], g , 1 << g);

			for (curuser = curuserlist->users; curuser; curuser = curuser->next) {
				if (curuser->group_mask & (1 << g))
					fprintf(stderr, " %s", curuser->user);
			}

			fprintf(stderr, "\n");
		}
#endif

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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
