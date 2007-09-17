/*
 * Configuration parser
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
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

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>

#include <types/capture.h>
#include <types/global.h>
#include <types/httperr.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/queue.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/checks.h>
#include <proto/httperr.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/task.h>


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

/* some of the most common options which are also the easiest to handle */
static const struct {
	const char *name;
	unsigned int val;
	unsigned int cap;
	unsigned int checks;
} cfg_opts[] =
{
#ifdef TPROXY
	{ "transparent",  PR_O_TRANSP,     PR_CAP_FE },
#endif
	{ "redispatch",   PR_O_REDISP,     PR_CAP_BE, 0 },
	{ "keepalive",    PR_O_KEEPALIVE,  PR_CAP_NONE, 0 },
	{ "httpclose",    PR_O_HTTP_CLOSE, PR_CAP_FE | PR_CAP_BE, 0 },
	{ "logasap",      PR_O_LOGASAP,    PR_CAP_FE, 0 },
	{ "abortonclose", PR_O_ABRT_CLOSE, PR_CAP_BE, 0 },
	{ "checkcache",   PR_O_CHK_CACHE,  PR_CAP_BE, 0 },
	{ "dontlognull",  PR_O_NULLNOLOG,  PR_CAP_FE, 0 },
	{ "clitcpka",     PR_O_TCP_CLI_KA, PR_CAP_FE, 0 },
	{ "srvtcpka",     PR_O_TCP_SRV_KA, PR_CAP_BE, 0 },
	{ "allbackups",   PR_O_USE_ALL_BK, PR_CAP_BE, 0 },
	{ "persist",      PR_O_PERSIST,    PR_CAP_BE, 0 },
	{ "forceclose",   PR_O_FORCE_CLO | PR_O_HTTP_CLOSE, PR_CAP_BE, 0 },
#ifdef CONFIG_HAP_TCPSPLICE
	{ "tcpsplice",    PR_O_TCPSPLICE , PR_CAP_BE|PR_CAP_FE, LSTCHK_TCPSPLICE|LSTCHK_NETADM },
#endif

	{ NULL, 0, 0 }
};


static struct proxy defproxy;		/* fake proxy used to assign default values on all instances */
int cfg_maxpconn = DEFAULT_MAXCONN;	/* # of simultaneous connections per proxy (-N) */
int cfg_maxconn = 0;		/* # of simultaneous connections, (-n) */

/*
 * converts <str> to a list of listeners which are dynamically allocated.
 * The format is "{addr|'*'}:port[-end][,{addr|'*'}:port[-end]]*", where :
 *  - <addr> can be empty or "*" to indicate INADDR_ANY ;
 *  - <port> is a numerical port from 1 to 65535 ;
 *  - <end> indicates to use the range from <port> to <end> instead (inclusive).
 * This can be repeated as many times as necessary, separated by a coma.
 * The <tail> argument is a pointer to a current list which should be appended
 * to the tail of the new list. The pointer to the new list is returned.
 */
static struct listener *str2listener(char *str, struct listener *tail)
{
	struct listener *l;
	char *c, *next, *range, *dupstr;
	int port, end;

	next = dupstr = strdup(str);
    
	while (next && *next) {
		struct sockaddr_storage ss;

		str = next;
		/* 1) look for the end of the first address */
		if ((next = strrchr(str, ',')) != NULL) {
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
			l->next = tail;
			tail = l;

			l->fd = -1;
			l->addr = ss;
			if (ss.ss_family == AF_INET6)
				((struct sockaddr_in6 *)(&l->addr))->sin6_port = htons(port);
			else
				((struct sockaddr_in *)(&l->addr))->sin_port = htons(port);

		} /* end for(port) */
	} /* end while(next) */
	free(dupstr);
	return tail;
 fail:
	free(dupstr);
	return NULL;
}

/*
 * Sends a warning if proxy <proxy> does not have at least one of the
 * capabilities in <cap>. An optionnal <hint> may be added at the end
 * of the warning to help the user. Returns 1 if a warning was emitted
 * or 0 if the condition is valid.
 */
int warnifnotcap(struct proxy *proxy, int cap, const char *file, int line, char *arg, char *hint)
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

/*
 * parse a line in a <global> section. Returns 0 if OK, -1 if error.
 */
int cfg_parse_global(const char *file, int linenum, char **args)
{

	if (!strcmp(args[0], "global")) {  /* new section */
		/* no option, nothing special to do */
		return 0;
	}
	else if (!strcmp(args[0], "daemon")) {
		global.mode |= MODE_DAEMON;
	}
	else if (!strcmp(args[0], "debug")) {
		global.mode |= MODE_DEBUG;
	}
	else if (!strcmp(args[0], "noepoll")) {
		cfg_polling_mechanism &= ~POLL_USE_EPOLL;
	}
	else if (!strcmp(args[0], "nosepoll")) {
		cfg_polling_mechanism &= ~POLL_USE_SEPOLL;
	}
	else if (!strcmp(args[0], "nokqueue")) {
		cfg_polling_mechanism &= ~POLL_USE_KQUEUE;
	}
	else if (!strcmp(args[0], "nopoll")) {
		cfg_polling_mechanism &= ~POLL_USE_POLL;
	}
	else if (!strcmp(args[0], "quiet")) {
		global.mode |= MODE_QUIET;
	}
	else if (!strcmp(args[0], "stats")) {
		global.mode |= MODE_STATS;
	}
	else if (!strcmp(args[0], "tune.maxpollevents")) {
		if (global.tune.maxpollevents != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.tune.maxpollevents = atol(args[1]);
	}
	else if (!strcmp(args[0], "uid")) {
		if (global.uid != 0) {
			Alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, linenum);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.uid = atol(args[1]);
	}
	else if (!strcmp(args[0], "gid")) {
		if (global.gid != 0) {
			Alert("parsing [%s:%d] : group/gid already specified. Continuing.\n", file, linenum);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.gid = atol(args[1]);
	}
	/* user/group name handling */
	else if (!strcmp(args[0], "user")) {
		struct passwd *ha_user;
		if (global.uid != 0) {
			Alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, linenum);
			return 0;
		}
		errno = 0;
		ha_user = getpwnam(args[1]);
		if (ha_user != NULL) {
			global.uid = (int)ha_user->pw_uid;
		}
		else {
			Alert("parsing [%s:%d] : cannot find user id for '%s' (%d:%s)\n", file, linenum, args[1], errno, strerror(errno));
			exit(1);
		}
	}
	else if (!strcmp(args[0], "group")) {
		struct group *ha_group;
		if (global.gid != 0) {
			Alert("parsing [%s:%d] : gid/group was already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		errno = 0;
		ha_group = getgrnam(args[1]);
		if (ha_group != NULL) {
			global.gid = (int)ha_group->gr_gid;
		}
		else {
			Alert("parsing [%s:%d] : cannot find group id for '%s' (%d:%s)\n", file, linenum, args[1], errno, strerror(errno));
			exit(1);
		}
	}
	/* end of user/group name handling*/
	else if (!strcmp(args[0], "nbproc")) {
		if (global.nbproc != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.nbproc = atol(args[1]);
	}
	else if (!strcmp(args[0], "maxconn")) {
		if (global.maxconn != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.maxconn = atol(args[1]);
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > DEFAULT_MAXCONN && cfg_maxconn <= DEFAULT_MAXCONN) {
			Alert("parsing [%s:%d] : maxconn value %d too high for this system.\nLimiting to %d. Please use '-n' to force the value.\n", file, linenum, global.maxconn, DEFAULT_MAXCONN);
			global.maxconn = DEFAULT_MAXCONN;
		}
#endif /* SYSTEM_MAXCONN */
	}
	else if (!strcmp(args[0], "ulimit-n")) {
		if (global.rlimit_nofile != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.rlimit_nofile = atol(args[1]);
	}
	else if (!strcmp(args[0], "chroot")) {
		if (global.chroot != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a directory as an argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.chroot = strdup(args[1]);
	}
	else if (!strcmp(args[0], "pidfile")) {
		if (global.pidfile != NULL) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a file name as an argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.pidfile = strdup(args[1]);
	}
	else if (!strcmp(args[0], "log")) {  /* syslog server address */
		struct sockaddr_in *sa;
		int facility, level;
	
		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <address> and <facility> as arguments.\n", file, linenum, args[0]);
			return -1;
		}
	
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

		sa = str2sa(args[1]);
		if (!sa->sin_port)
			sa->sin_port = htons(SYSLOG_PORT);

		if (global.logfac1 == -1) {
			global.logsrv1 = *sa;
			global.logfac1 = facility;
			global.loglev1 = level;
		}
		else if (global.logfac2 == -1) {
			global.logsrv2 = *sa;
			global.logfac2 = facility;
			global.loglev2 = level;
		}
		else {
			Alert("parsing [%s:%d] : too many syslog servers\n", file, linenum);
			return -1;
		}
	
	}
	else {
		Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "global");
		return -1;
	}
	return 0;
}


static void init_default_instance()
{
	memset(&defproxy, 0, sizeof(defproxy));
	defproxy.mode = PR_MODE_TCP;
	defproxy.state = PR_STNEW;
	defproxy.maxconn = cfg_maxpconn;
	defproxy.conn_retries = CONN_RETRIES;
	defproxy.logfac1 = defproxy.logfac2 = -1; /* log disabled */
}

/*
 * Parse a line in a <listen>, <frontend>, <backend> or <ruleset> section.
 * Returns 0 if OK, -1 if error.
 */
int cfg_parse_listen(const char *file, int linenum, char **args)
{
	static struct proxy *curproxy = NULL;
	struct server *newsrv = NULL;
	const char *err;
	int rc, val;

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
			return -1;
		}
	
		if ((curproxy = (struct proxy *)calloc(1, sizeof(struct proxy))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			return -1;
		}
	
		curproxy->next = proxy;
		proxy = curproxy;
		LIST_INIT(&curproxy->pendconns);
		LIST_INIT(&curproxy->acl);
		LIST_INIT(&curproxy->block_cond);
		LIST_INIT(&curproxy->switching_rules);

		/* Timeouts are defined as -1, so we cannot use the zeroed area
		 * as a default value.
		 */
		tv_eternity(&curproxy->clitimeout);
		tv_eternity(&curproxy->srvtimeout);
		tv_eternity(&curproxy->contimeout);
		tv_eternity(&curproxy->appsession_timeout);
		
		curproxy->id = strdup(args[1]);
		curproxy->cap = rc;

		/* parse the listener address if any */
		if ((curproxy->cap & PR_CAP_FE) && *args[2]) {
			curproxy->listen = str2listener(args[2], curproxy->listen);
			if (!curproxy->listen)
				return -1;
			global.maxsock++;
		}

		/* set default values */
		curproxy->state = defproxy.state;
		curproxy->options = defproxy.options;
		curproxy->except_net = defproxy.except_net;
		curproxy->except_mask = defproxy.except_mask;

		if (curproxy->cap & PR_CAP_FE) {
			curproxy->maxconn = defproxy.maxconn;

			/* initialize error relocations */
			for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
				if (defproxy.errmsg[rc].str)
					chunk_dup(&curproxy->errmsg[rc], &defproxy.errmsg[rc]);
			}

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
		}

		if (curproxy->cap & PR_CAP_RS) {
			if (defproxy.capture_name)
				curproxy->capture_name = strdup(defproxy.capture_name);
			curproxy->capture_namelen = defproxy.capture_namelen;
			curproxy->capture_len = defproxy.capture_len;
		}

		if (curproxy->cap & PR_CAP_FE) {
			curproxy->clitimeout = defproxy.clitimeout;
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
			curproxy->contimeout = defproxy.contimeout;
			curproxy->srvtimeout = defproxy.srvtimeout;
			curproxy->source_addr = defproxy.source_addr;
		}

		curproxy->mode = defproxy.mode;
		curproxy->logfac1 = defproxy.logfac1;
		curproxy->logsrv1 = defproxy.logsrv1;
		curproxy->loglev1 = defproxy.loglev1;
		curproxy->logfac2 = defproxy.logfac2;
		curproxy->logsrv2 = defproxy.logsrv2;
		curproxy->loglev2 = defproxy.loglev2;
		curproxy->grace  = defproxy.grace;

		return 0;
	}
	else if (!strcmp(args[0], "defaults")) {  /* use this one to assign default values */
		/* some variables may have already been initialized earlier */
		/* FIXME-20070101: we should do this too at the end of the
		 * config parsing to free all default values.
		 */
		if (defproxy.check_req)     free(defproxy.check_req);
		if (defproxy.cookie_name)   free(defproxy.cookie_name);
		if (defproxy.capture_name)  free(defproxy.capture_name);
		if (defproxy.monitor_uri)   free(defproxy.monitor_uri);
		if (defproxy.defbe.name)    free(defproxy.defbe.name);

		for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
			if (defproxy.errmsg[rc].len)
				free(defproxy.errmsg[rc].str);
		}

		/* we cannot free uri_auth because it might already be used */
		init_default_instance();
		curproxy = &defproxy;
		defproxy.cap = PR_CAP_LISTEN; /* all caps for now */
		return 0;
	}
	else if (curproxy == NULL) {
		Alert("parsing [%s:%d] : 'listen' or 'defaults' expected.\n", file, linenum);
		return -1;
	}
    

	/* Now let's parse the proxy-specific keywords */
	if (!strcmp(args[0], "bind")) {  /* new listen addresses */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			return 0;

		if (strchr(args[1], ':') == NULL) {
			Alert("parsing [%s:%d] : '%s' expects [addr1]:port1[-end1]{,[addr]:port[-end]}... as arguments.\n",
			      file, linenum, args[0]);
			return -1;
		}
		curproxy->listen = str2listener(args[1], curproxy->listen);
		if (!curproxy->listen)
			return -1;
		global.maxsock++;
		return 0;
	}
	else if (!strcmp(args[0], "monitor-net")) {  /* set the range of IPs to ignore */
		if (!*args[1] || !str2net(args[1], &curproxy->mon_net, &curproxy->mon_mask)) {
			Alert("parsing [%s:%d] : '%s' expects address[/mask].\n",
			      file, linenum, args[0]);
			return -1;
		}
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			return 0;

		/* flush useless bits */
		curproxy->mon_net.s_addr &= curproxy->mon_mask.s_addr;
		return 0;
	}
	else if (!strcmp(args[0], "monitor-uri")) {  /* set the URI to intercept */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			return 0;

		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects an URI.\n",
			      file, linenum, args[0]);
			return -1;
		}

		if (curproxy->monitor_uri != NULL)
			free(curproxy->monitor_uri);

		curproxy->monitor_uri_len = strlen(args[1]);
		curproxy->monitor_uri = (char *)calloc(1, curproxy->monitor_uri_len + 1);
		memcpy(curproxy->monitor_uri, args[1], curproxy->monitor_uri_len);
		curproxy->monitor_uri[curproxy->monitor_uri_len] = '\0';

		return 0;
	}
	else if (!strcmp(args[0], "mode")) {  /* sets the proxy mode */
		if (!strcmp(args[1], "http")) curproxy->mode = PR_MODE_HTTP;
		else if (!strcmp(args[1], "tcp")) curproxy->mode = PR_MODE_TCP;
		else if (!strcmp(args[1], "health")) curproxy->mode = PR_MODE_HEALTH;
		else {
			Alert("parsing [%s:%d] : unknown proxy mode '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	}
	else if (!strcmp(args[0], "disabled")) {  /* disables this proxy */
		curproxy->state = PR_STSTOPPED;
	}
	else if (!strcmp(args[0], "enabled")) {  /* enables this proxy (used to revert a disabled default) */
		curproxy->state = PR_STNEW;
	}
	else if (!strcmp(args[0], "acl")) {  /* add an ACL */
		if (parse_acl((const char **)args + 1, &curproxy->acl) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing ACL '%s'.\n",
			      file, linenum, args[1]);
			return -1;
		}
	}
	else if (!strcmp(args[0], "cookie")) {  /* cookie name */
		int cur_arg;
		//	  if (curproxy == &defproxy) {
		//	      Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
		//	      return -1;
		//	  }

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (curproxy->cookie_name != NULL) {
			//	      Alert("parsing [%s:%d] : cookie name already specified. Continuing.\n",
			//		    file, linenum);
			//	      return 0;
			free(curproxy->cookie_name);
		}
	
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <cookie_name> as argument.\n",
			      file, linenum, args[0]);
			return -1;
		}
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
			else {
				Alert("parsing [%s:%d] : '%s' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache' and 'postonly' options.\n",
				      file, linenum, args[0]);
				return -1;
			}
			cur_arg++;
		}
		if (!POWEROF2(curproxy->options & (PR_O_COOK_RW|PR_O_COOK_IND))) {
			Alert("parsing [%s:%d] : cookie 'rewrite' and 'indirect' modes are incompatible.\n",
			      file, linenum);
			return -1;
		}

		if (!POWEROF2(curproxy->options & (PR_O_COOK_RW|PR_O_COOK_INS|PR_O_COOK_PFX))) {
			Alert("parsing [%s:%d] : cookie 'rewrite', 'insert' and 'prefix' modes are incompatible.\n",
			      file, linenum);
			return -1;
		}
	}/* end else if (!strcmp(args[0], "cookie"))  */
	else if (!strcmp(args[0], "appsession")) {  /* cookie name */
		//	  if (curproxy == &defproxy) {
		//	      Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
		//	      return -1;
		//	  }

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (curproxy->appsession_name != NULL) {
			//	      Alert("parsing [%s:%d] : cookie name already specified. Continuing.\n",
			//		    file, linenum);
			//	      return 0;
			free(curproxy->appsession_name);
		}
	
		if (*(args[5]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects 'appsession' <cookie_name> 'len' <len> 'timeout' <timeout>.\n",
			      file, linenum, args[0]);
			return -1;
		}
		have_appsession = 1;
		curproxy->appsession_name = strdup(args[1]);
		curproxy->appsession_name_len = strlen(curproxy->appsession_name);
		curproxy->appsession_len = atoi(args[3]);
		val = atoi(args[5]);
		if (val > 0)
			__tv_from_ms(&curproxy->appsession_timeout, val);
		else
			tv_eternity(&curproxy->appsession_timeout);

		if (appsession_hash_init(&(curproxy->htbl_proxy), destroy) == 0) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			return -1;
		}
	} /* Url App Session */
	else if (!strcmp(args[0], "capture")) {
		if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (!strcmp(args[1], "cookie")) {  /* name of a cookie to capture */
			//	  if (curproxy == &defproxy) {
			//	      Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			//	      return -1;
			//	  }

			if (curproxy->capture_name != NULL) {
				//     Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n",
				//           file, linenum, args[0]);
				//     return 0;
				free(curproxy->capture_name);
			}
	
			if (*(args[4]) == 0) {
				Alert("parsing [%s:%d] : '%s' expects 'cookie' <cookie_name> 'len' <len>.\n",
				      file, linenum, args[0]);
				return -1;
			}
			curproxy->capture_name = strdup(args[2]);
			curproxy->capture_namelen = strlen(curproxy->capture_name);
			curproxy->capture_len = atol(args[4]);
			if (curproxy->capture_len >= CAPTURE_LEN) {
				Warning("parsing [%s:%d] : truncating capture length to %d bytes.\n",
					file, linenum, CAPTURE_LEN - 1);
				curproxy->capture_len = CAPTURE_LEN - 1;
			}
			curproxy->to_log |= LW_COOKIE;
		}
		else if (!strcmp(args[1], "request") && !strcmp(args[2], "header")) {
			struct cap_hdr *hdr;

			if (curproxy == &defproxy) {
				Alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				return -1;
			}

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				Alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
				      file, linenum, args[0], args[1]);
				return -1;
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
				return -1;
			}

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				Alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
				      file, linenum, args[0], args[1]);
				return -1;
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
			return -1;
		}
	}
	else if (!strcmp(args[0], "contimeout")) {  /* connect timeout */
		if (!__tv_iseq(&curproxy->contimeout, &defproxy.contimeout)) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer <time_in_ms> as argument.\n",
			      file, linenum, args[0]);
			return -1;
		}
		val = atoi(args[1]);
		if (val > 0)
			__tv_from_ms(&curproxy->contimeout, val);
		else
			tv_eternity(&curproxy->contimeout);
	}
	else if (!strcmp(args[0], "clitimeout")) {  /*  client timeout */
		if (!__tv_iseq(&curproxy->clitimeout, &defproxy.clitimeout)) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n",
			      file, linenum, args[0]);
			return 0;
		}
		else if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer <time_in_ms> as argument.\n",
			      file, linenum, args[0]);
			return -1;
		}
		val = atoi(args[1]);
		if (val > 0)
			__tv_from_ms(&curproxy->clitimeout, val);
		else
			tv_eternity(&curproxy->clitimeout);
	}
	else if (!strcmp(args[0], "srvtimeout")) {  /*  server timeout */
		if (!__tv_iseq(&curproxy->srvtimeout, &defproxy.srvtimeout)) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer <time_in_ms> as argument.\n",
			      file, linenum, args[0]);
			return -1;
		}
		val = atoi(args[1]);
		if (val > 0)
			__tv_from_ms(&curproxy->srvtimeout, val);
		else
			tv_eternity(&curproxy->srvtimeout);
	}
	else if (!strcmp(args[0], "retries")) {  /* connection retries */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument (dispatch counts for one).\n",
			      file, linenum, args[0]);
			return -1;
		}
		curproxy->conn_retries = atol(args[1]);
	}
	else if (!strcmp(args[0], "block")) {  /* early blocking based on ACLs */
		int pol = ACL_COND_NONE;
		struct acl_cond *cond;

		if (!strcmp(args[1], "if"))
			pol = ACL_COND_IF;
		else if (!strcmp(args[1], "unless"))
			pol = ACL_COND_UNLESS;

		if (pol == ACL_COND_NONE) {
			Alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
			      file, linenum, args[0]);
			return -1;
		}

		if ((cond = parse_acl_cond((const char **)args + 2, &curproxy->acl, pol)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing blocking condition.\n",
			      file, linenum);
			return -1;
		}
		LIST_ADDQ(&curproxy->block_cond, &cond->list);
	}
	else if (!strcmp(args[0], "use_backend")) {  /* early blocking based on ACLs */
		int pol = ACL_COND_NONE;
		struct acl_cond *cond;
		struct switching_rule *rule;

		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a backend name.\n", file, linenum, args[0]);
			return -1;
		}

		if (!strcmp(args[2], "if"))
			pol = ACL_COND_IF;
		else if (!strcmp(args[2], "unless"))
			pol = ACL_COND_UNLESS;

		if (pol == ACL_COND_NONE) {
			Alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
			      file, linenum, args[0]);
			return -1;
		}

		if ((cond = parse_acl_cond((const char **)args + 3, &curproxy->acl, pol)) == NULL) {
			Alert("parsing [%s:%d] : error detected while parsing blocking condition.\n",
			      file, linenum);
			return -1;
		}

		rule = (struct switching_rule *)calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->be.name = strdup(args[1]);
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->switching_rules, &rule->list);
	}
	else if (!strcmp(args[0], "stats")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (curproxy != &defproxy && curproxy->uri_auth == defproxy.uri_auth)
			curproxy->uri_auth = NULL; /* we must detach from the default config */

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects 'uri', 'realm', 'auth', 'scope' or 'enable'.\n", file, linenum, args[0]);
			return -1;
		} else if (!strcmp(args[1], "uri")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'uri' needs an URI prefix.\n", file, linenum);
				return -1;
			} else if (!stats_set_uri(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				return -1;
			}
		} else if (!strcmp(args[1], "realm")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'realm' needs an realm name.\n", file, linenum);
				return -1;
			} else if (!stats_set_realm(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				return -1;
			}
		} else if (!strcmp(args[1], "refresh")) {
			int interval = atoi(args[2]);
			
			if (interval < 0) {
				Alert("parsing [%s:%d] : 'refresh' needs a positive interval in seconds.\n", file, linenum);
				return -1;
			} else if (!stats_set_refresh(&curproxy->uri_auth, interval)) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				return -1;
			}
		} else if (!strcmp(args[1], "auth")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'auth' needs a user:password account.\n", file, linenum);
				return -1;
			} else if (!stats_add_auth(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				return -1;
			}
		} else if (!strcmp(args[1], "scope")) {
			if (*(args[2]) == 0) {
				Alert("parsing [%s:%d] : 'scope' needs a proxy name.\n", file, linenum);
				return -1;
			} else if (!stats_add_scope(&curproxy->uri_auth, args[2])) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				return -1;
			}
		} else if (!strcmp(args[1], "enable")) {
			if (!stats_check_init_uri_auth(&curproxy->uri_auth)) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				return -1;
			}
		} else {
			Alert("parsing [%s:%d] : unknown stats parameter '%s' (expects 'uri', 'realm', 'auth' or 'enable').\n",
			      file, linenum, args[0]);
			return -1;
		}
	}
	else if (!strcmp(args[0], "option")) {
		int optnum;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an option name.\n", file, linenum, args[0]);
			return -1;
		}

		for (optnum = 0; cfg_opts[optnum].name; optnum++) {
			if (!strcmp(args[1], cfg_opts[optnum].name)) {
				if (warnifnotcap(curproxy, cfg_opts[optnum].cap, file, linenum, args[1], NULL))
					return 0;
				curproxy->options |= cfg_opts[optnum].val;
				global.last_checks |= cfg_opts[optnum].checks;
				return 0;
			}
		}

		if (!strcmp(args[1], "httplog"))
			/* generate a complete HTTP log */
			curproxy->to_log |= LW_DATE | LW_CLIP | LW_SVID | LW_REQ | LW_PXID | LW_RESP | LW_BYTES;
		else if (!strcmp(args[1], "tcplog"))
			/* generate a detailed TCP log */
			curproxy->to_log |= LW_DATE | LW_CLIP | LW_SVID | LW_PXID | LW_BYTES;
		else if (!strcmp(args[1], "tcpka")) {
			/* enable TCP keep-alives on client and server sessions */
			if (warnifnotcap(curproxy, PR_CAP_BE | PR_CAP_FE, file, linenum, args[1], NULL))
				return 0;

			if (curproxy->cap & PR_CAP_FE)
				curproxy->options |= PR_O_TCP_CLI_KA;
			if (curproxy->cap & PR_CAP_BE)
				curproxy->options |= PR_O_TCP_SRV_KA;
		}
		else if (!strcmp(args[1], "httpchk")) {
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				return 0;
			/* use HTTP request to check servers' health */
			if (curproxy->check_req != NULL) {
				free(curproxy->check_req);
			}
			curproxy->options &= ~PR_O_SSL3_CHK;
			curproxy->options &= ~PR_O_SMTP_CHK;
			curproxy->options |= PR_O_HTTP_CHK;
			if (!*args[2]) { /* no argument */
				curproxy->check_req = strdup(DEF_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_CHECK_REQ);
			} else if (!*args[3]) { /* one argument : URI */
				int reqlen = strlen(args[2]) + strlen("OPTIONS  HTTP/1.0\r\n\r\n") + 1;
				curproxy->check_req = (char *)malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "OPTIONS %s HTTP/1.0\r\n\r\n", args[2]); /* URI to use */
			} else { /* more arguments : METHOD URI [HTTP_VER] */
				int reqlen = strlen(args[2]) + strlen(args[3]) + 3 + strlen("\r\n\r\n");
				if (*args[4])
					reqlen += strlen(args[4]);
				else
					reqlen += strlen("HTTP/1.0");
		    
				curproxy->check_req = (char *)malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "%s %s %s\r\n\r\n", args[2], args[3], *args[4]?args[4]:"HTTP/1.0");
			}
		}
		else if (!strcmp(args[1], "ssl-hello-chk")) {
			/* use SSLv3 CLIENT HELLO to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				return 0;

			if (curproxy->check_req != NULL) {
				free(curproxy->check_req);
			}
			curproxy->options &= ~PR_O_HTTP_CHK;
			curproxy->options &= ~PR_O_SMTP_CHK;
			curproxy->options |= PR_O_SSL3_CHK;
		}
		else if (!strcmp(args[1], "smtpchk")) {
			/* use SMTP request to check servers' health */
			if (curproxy->check_req != NULL) {
				free(curproxy->check_req);
			}
			curproxy->options &= ~PR_O_HTTP_CHK;
			curproxy->options &= ~PR_O_SSL3_CHK;
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
		else if (!strcmp(args[1], "forwardfor")) {
			/* insert x-forwarded-for field, but not for the
			 * IP address listed as an except.
			 */
			if (*(args[2])) {
				if (!strcmp(args[2], "except")) {
					if (!*args[3] || !str2net(args[3], &curproxy->except_net, &curproxy->except_mask)) {
						Alert("parsing [%s:%d] : '%s' only supports optional 'except' address[/mask].\n",
						      file, linenum, args[0]);
						return -1;
					}
					/* flush useless bits */
					curproxy->except_net.s_addr &= curproxy->except_mask.s_addr;
				} else {
					Alert("parsing [%s:%d] : '%s' only supports optional 'except' address[/mask].\n",
					      file, linenum, args[0]);
					return -1;
				}
			}
			curproxy->options |= PR_O_FWDFOR;
		}
		else {
			Alert("parsing [%s:%d] : unknown option '%s'.\n", file, linenum, args[1]);
			return -1;
		}
		return 0;
	}
	else if (!strcmp(args[0], "default_backend")) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a backend name.\n", file, linenum, args[0]);
			return -1;
		}
		if (curproxy->defbe.name)
			free(curproxy->defbe.name);
		curproxy->defbe.name = strdup(args[1]);
	}
	else if (!strcmp(args[0], "redispatch") || !strcmp(args[0], "redisp")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		/* enable reconnections to dispatch */
		curproxy->options |= PR_O_REDISP;
	}
#ifdef TPROXY
	else if (!strcmp(args[0], "transparent")) {
		/* enable transparent proxy connections */
		curproxy->options |= PR_O_TRANSP;
	}
#endif
	else if (!strcmp(args[0], "maxconn")) {  /* maxconn */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], " Maybe you want 'fullconn' instead ?"))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		curproxy->maxconn = atol(args[1]);
	}
	else if (!strcmp(args[0], "fullconn")) {  /* fullconn */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], " Maybe you want 'maxconn' instead ?"))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		curproxy->fullconn = atol(args[1]);
	}
	else if (!strcmp(args[0], "grace")) {  /* grace time (ms) */
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects a time in milliseconds.\n", file, linenum, args[0]);
			return -1;
		}
		curproxy->grace = atol(args[1]);
	}
	else if (!strcmp(args[0], "dispatch")) {  /* dispatch address */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (strchr(args[1], ':') == NULL) {
			Alert("parsing [%s:%d] : '%s' expects <addr:port> as argument.\n", file, linenum, args[0]);
			return -1;
		}
		curproxy->dispatch_addr = *str2sa(args[1]);
	}
	else if (!strcmp(args[0], "balance")) {  /* set balancing with optional algorithm */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1])) {
			if (!strcmp(args[1], "roundrobin")) {
				curproxy->options &= ~PR_O_BALANCE;
				curproxy->options |= PR_O_BALANCE_RR;
			}
			else if (!strcmp(args[1], "source")) {
				curproxy->options &= ~PR_O_BALANCE;
				curproxy->options |= PR_O_BALANCE_SH;
			}
			else if (!strcmp(args[1], "uri")) {
				curproxy->options &= ~PR_O_BALANCE;
				curproxy->options |= PR_O_BALANCE_UH;
			}
			else {
				Alert("parsing [%s:%d] : '%s' only supports 'roundrobin', 'source' and 'uri' options.\n", file, linenum, args[0]);
				return -1;
			}
		}
		else {/* if no option is set, use round-robin by default */
			curproxy->options &= ~PR_O_BALANCE;
			curproxy->options |= PR_O_BALANCE_RR;
		}
	}
	else if (!strcmp(args[0], "server")) {  /* server address */
		int cur_arg;
		char *rport;
		char *raddr;
		short realport;
		int do_check;

		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (!*args[2]) {
			Alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
			      file, linenum, args[0]);
			return -1;
		}
		if ((newsrv = (struct server *)calloc(1, sizeof(struct server))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			return -1;
		}

		/* the servers are linked backwards first */
		newsrv->next = curproxy->srv;
		curproxy->srv = newsrv;
		newsrv->proxy = curproxy;

		LIST_INIT(&newsrv->pendconns);
		do_check = 0;
		newsrv->state = SRV_RUNNING; /* early server setup */
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
		} else {
			realport = 0;
			newsrv->state |= SRV_MAPPORTS;
		}	    

		newsrv->addr = *str2sa(raddr);
		newsrv->addr.sin_port = htons(realport);
		free(raddr);

		newsrv->curfd = -1; /* no health-check in progress */
		newsrv->inter = DEF_CHKINTR;
		newsrv->rise = DEF_RISETIME;
		newsrv->fall = DEF_FALLTIME;
		newsrv->health = newsrv->rise; /* up, but will fall down at first failure */
		newsrv->uweight = 1;

		cur_arg = 3;
		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "cookie")) {
				newsrv->cookie = strdup(args[cur_arg + 1]);
				newsrv->cklen = strlen(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "rise")) {
				newsrv->rise = atol(args[cur_arg + 1]);
				newsrv->health = newsrv->rise;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "fall")) {
				newsrv->fall = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "inter")) {
				newsrv->inter = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "addr")) {
				newsrv->check_addr = *str2sa(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "port")) {
				newsrv->check_port = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "backup")) {
				newsrv->state |= SRV_BACKUP;
				cur_arg ++;
			}
			else if (!strcmp(args[cur_arg], "weight")) {
				int w;
				w = atol(args[cur_arg + 1]);
				if (w < 1 || w > 256) {
					Alert("parsing [%s:%d] : weight of server %s is not within 1 and 256 (%d).\n",
					      file, linenum, newsrv->id, w);
					return -1;
				}
				newsrv->uweight = w;
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
			else if (!strcmp(args[cur_arg], "check")) {
				global.maxsock++;
				do_check = 1;
				cur_arg += 1;
			}
			else if (!strcmp(args[cur_arg], "source")) {  /* address to which we bind when connecting */
				if (!*args[cur_arg + 1]) {
#ifdef CONFIG_HAP_CTTPROXY
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], and optional '%s' <addr> as argument.\n",
					      file, linenum, "source", "usesrc");
#else
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>] as argument.\n",
					      file, linenum, "source");
#endif
					return -1;
				}
				newsrv->state |= SRV_BIND_SRC;
				newsrv->source_addr = *str2sa(args[cur_arg + 1]);
				cur_arg += 2;
				if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside */
#ifdef CONFIG_HAP_CTTPROXY
					if (newsrv->source_addr.sin_addr.s_addr == INADDR_ANY) {
						Alert("parsing [%s:%d] : '%s' requires an explicit '%s' address.\n",
						      file, linenum, "usesrc", "source");
						return -1;
					}
					if (!*args[cur_arg + 1]) {
						Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', or 'clientip' as argument.\n",
						      file, linenum, "usesrc");
						return -1;
					}
					if (!strcmp(args[cur_arg + 1], "client")) {
						newsrv->state |= SRV_TPROXY_CLI;
					} else if (!strcmp(args[cur_arg + 1], "clientip")) {
						newsrv->state |= SRV_TPROXY_CIP;
					} else {
						newsrv->state |= SRV_TPROXY_ADDR;
						newsrv->tproxy_addr = *str2sa(args[cur_arg + 1]);
					}
					global.last_checks |= LSTCHK_CTTPROXY | LSTCHK_NETADM;
					cur_arg += 2;
#else	/* no CTTPROXY support */
					Alert("parsing [%s:%d] : '%s' not allowed here because support for cttproxy was not compiled in.\n",
						      file, linenum, "usesrc");
						return -1;
#endif
				}
			}
#ifdef CONFIG_HAP_CTTPROXY
			else if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside: needs "source" first */
				Alert("parsing [%s:%d] : '%s' only allowed after a '%s' statement.\n",
				      file, linenum, "usesrc", "source");
				return -1;
			}
#endif
			else {
				Alert("parsing [%s:%d] : server %s only supports options 'backup', 'cookie', 'check', 'inter', 'rise', 'fall', 'addr', 'port', 'source', 'minconn', 'maxconn' and 'weight'.\n",
				      file, linenum, newsrv->id);
				return -1;
			}
		}

		if (do_check) {
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
				return -1;
			}
			newsrv->state |= SRV_CHECKED;
		}

		if (newsrv->state & SRV_BACKUP)
			curproxy->srv_bck++;
		else
			curproxy->srv_act++;
	}
	else if (!strcmp(args[0], "log")) {  /* syslog server address */
		struct sockaddr_in *sa;
		int facility;
	
		if (*(args[1]) && *(args[2]) == 0 && !strcmp(args[1], "global")) {
			curproxy->logfac1 = global.logfac1;
			curproxy->logsrv1 = global.logsrv1;
			curproxy->loglev1 = global.loglev1;
			curproxy->logfac2 = global.logfac2;
			curproxy->logsrv2 = global.logsrv2;
			curproxy->loglev2 = global.loglev2;
		}
		else if (*(args[1]) && *(args[2])) {
			int level;

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

			sa = str2sa(args[1]);
			if (!sa->sin_port)
				sa->sin_port = htons(SYSLOG_PORT);
	    
			if (curproxy->logfac1 == -1) {
				curproxy->logsrv1 = *sa;
				curproxy->logfac1 = facility;
				curproxy->loglev1 = level;
			}
			else if (curproxy->logfac2 == -1) {
				curproxy->logsrv2 = *sa;
				curproxy->logfac2 = facility;
				curproxy->loglev2 = level;
			}
			else {
				Alert("parsing [%s:%d] : too many syslog servers\n", file, linenum);
				return -1;
			}
		}
		else {
			Alert("parsing [%s:%d] : 'log' expects either <address[:port]> and <facility> or 'global' as arguments.\n",
			      file, linenum);
			return -1;
		}
	}
	else if (!strcmp(args[0], "source")) {  /* address to which we bind when connecting */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (!*args[1]) {
#ifdef CONFIG_HAP_CTTPROXY
			Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], and optional '%s' <addr> as argument.\n",
			      file, linenum, "source", "usesrc");
#else
			Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>] as argument.\n",
			      file, linenum, "source");
#endif
			return -1;
		}
	
		curproxy->source_addr = *str2sa(args[1]);
		curproxy->options |= PR_O_BIND_SRC;
		if (!strcmp(args[2], "usesrc")) {  /* address to use outside */
#ifdef CONFIG_HAP_CTTPROXY
			if (curproxy->source_addr.sin_addr.s_addr == INADDR_ANY) {
				Alert("parsing [%s:%d] : '%s' requires an explicit 'source' address.\n",
				      file, linenum, "usesrc");
				return -1;
			}
			if (!*args[3]) {
				Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', or 'clientip' as argument.\n",
				      file, linenum, "usesrc");
				return -1;
			}

			if (!strcmp(args[3], "client")) {
				curproxy->options |= PR_O_TPXY_CLI;
			} else if (!strcmp(args[3], "clientip")) {
				curproxy->options |= PR_O_TPXY_CIP;
			} else {
				curproxy->options |= PR_O_TPXY_ADDR;
				curproxy->tproxy_addr = *str2sa(args[3]);
			}
			global.last_checks |= LSTCHK_CTTPROXY | LSTCHK_NETADM;
#else	/* no CTTPROXY support */
			Alert("parsing [%s:%d] : '%s' not allowed here because support for cttproxy was not compiled in.\n",
			      file, linenum, "usesrc");
			return -1;
#endif
		}
	}
#ifdef CONFIG_HAP_CTTPROXY
	else if (!strcmp(args[0], "usesrc")) {  /* address to use outside: needs "source" first */
		Alert("parsing [%s:%d] : '%s' only allowed after a '%s' statement.\n",
		      file, linenum, "usesrc", "source");
		return -1;
	}
#endif
	else if (!strcmp(args[0], "cliexp") || !strcmp(args[0], "reqrep")) {  /* replace request header from a regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		err = chain_regex(&curproxy->req_exp, preg, ACT_REPLACE, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "reqdel")) {  /* delete request header from a regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_REMOVE, NULL);
	}
	else if (!strcmp(args[0], "reqdeny")) {  /* deny a request if a header matches this regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_DENY, NULL);
	}
	else if (!strcmp(args[0], "reqpass")) {  /* pass this header without allowing or denying the request */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_PASS, NULL);
	}
	else if (!strcmp(args[0], "reqallow")) {  /* allow a request if a header matches this regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_ALLOW, NULL);
	}
	else if (!strcmp(args[0], "reqtarpit")) {  /* tarpit a request if a header matches this regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_TARPIT, NULL);
	}
	else if (!strcmp(args[0], "reqsetbe")) { /* switch the backend from a regex, respecting case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <target> as arguments.\n", 
				file, linenum, args[0]);
			return -1;	
		}
		
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
		}

		chain_regex(&curproxy->req_exp, preg, ACT_SETBE, strdup(args[2]));
	}
	else if (!strcmp(args[0], "reqisetbe")) { /* switch the backend from a regex, ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <target> as arguments.\n", 
			      file, linenum, args[0]);
			return -1;	
		}
		
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
		}

		chain_regex(&curproxy->req_exp, preg, ACT_SETBE, strdup(args[2]));
	}
	else if (!strcmp(args[0], "reqirep")) {  /* replace request header from a regex, ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		err = chain_regex(&curproxy->req_exp, preg, ACT_REPLACE, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "reqidel")) {  /* delete request header from a regex ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_REMOVE, NULL);
	}
	else if (!strcmp(args[0], "reqideny")) {  /* deny a request if a header matches this regex ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_DENY, NULL);
	}
	else if (!strcmp(args[0], "reqipass")) {  /* pass this header without allowing or denying the request */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_PASS, NULL);
	}
	else if (!strcmp(args[0], "reqiallow")) {  /* allow a request if a header matches this regex ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_ALLOW, NULL);
	}
	else if (!strcmp(args[0], "reqitarpit")) {  /* tarpit a request if a header matches this regex ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <regex> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		chain_regex(&curproxy->req_exp, preg, ACT_TARPIT, NULL);
	}
	else if (!strcmp(args[0], "reqadd")) {  /* add request header */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (curproxy->nb_reqadd >= MAX_NEWHDR) {
			Alert("parsing [%s:%d] : too many '%s'. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
	
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <header> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		curproxy->req_add[curproxy->nb_reqadd++] = strdup(args[1]);
	}
	else if (!strcmp(args[0], "srvexp") || !strcmp(args[0], "rsprep")) {  /* replace response header from a regex */
		regex_t *preg;
	
		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		err = chain_regex(&curproxy->rsp_exp, preg, ACT_REPLACE, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "rspdel")) {  /* delete response header from a regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> as an argument.\n", file, linenum, args[0]);
			return -1;
		}

		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		err = chain_regex(&curproxy->rsp_exp, preg, ACT_REMOVE, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "rspdeny")) {  /* block response header from a regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> as an argument.\n", file, linenum, args[0]);
			return -1;
		}

		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		err = chain_regex(&curproxy->rsp_exp, preg, ACT_DENY, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "rspirep")) {  /* replace response header from a regex ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0 || *(args[2]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> and <replace> as arguments.\n",
			      file, linenum, args[0]);
			return -1;
		}

		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	    
		err = chain_regex(&curproxy->rsp_exp, preg, ACT_REPLACE, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "rspidel")) {  /* delete response header from a regex ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> as an argument.\n", file, linenum, args[0]);
			return -1;
		}

		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		err = chain_regex(&curproxy->rsp_exp, preg, ACT_REMOVE, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "rspideny")) {  /* block response header from a regex ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <search> as an argument.\n", file, linenum, args[0]);
			return -1;
		}

		preg = calloc(1, sizeof(regex_t));
		if (regcomp(preg, args[1], REG_EXTENDED | REG_ICASE) != 0) {
			Alert("parsing [%s:%d] : bad regular expression '%s'.\n", file, linenum, args[1]);
			return -1;
		}
	
		err = chain_regex(&curproxy->rsp_exp, preg, ACT_DENY, strdup(args[2]));
		if (err) {
			Alert("parsing [%s:%d] : invalid character or unterminated sequence in replacement string near '%c'.\n",
			      file, linenum, *err);
			return -1;
		}
	}
	else if (!strcmp(args[0], "rspadd")) {  /* add response header */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
		else if (warnifnotcap(curproxy, PR_CAP_RS, file, linenum, args[0], NULL))
			return 0;

		if (curproxy->nb_rspadd >= MAX_NEWHDR) {
			Alert("parsing [%s:%d] : too many '%s'. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
	
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects <header> as an argument.\n", file, linenum, args[0]);
			return -1;
		}
	
		curproxy->rsp_add[curproxy->nb_rspadd++] = strdup(args[1]);
	}
	else if (!strcmp(args[0], "errorloc") ||
		 !strcmp(args[0], "errorloc302") ||
		 !strcmp(args[0], "errorloc303")) { /* error location */
		int errnum, errlen;
		char *err;

		if (warnifnotcap(curproxy, PR_CAP_FE | PR_CAP_BE, file, linenum, args[0], NULL))
			return 0;

		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : <%s> expects <status_code> and <url> as arguments.\n", file, linenum);
			return -1;
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
				if (curproxy->errmsg[rc].str)
					free(curproxy->errmsg[rc].str);
				curproxy->errmsg[rc].str = err;
				curproxy->errmsg[rc].len = errlen;
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
			return 0;

		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : <%s> expects <status_code> and <file> as arguments.\n", file, linenum);
			return -1;
		}

		fd = open(args[2], O_RDONLY);
		if ((fd < 0) || (fstat(fd, &stat) < 0)) {
			Alert("parsing [%s:%d] : error opening file <%s> for custom error message <%s>.\n",
			      file, linenum, args[2], args[1]);
			if (fd >= 0)
				close(fd);
			return -1;
		}

		if (stat.st_size <= BUFSIZE) {
			errlen = stat.st_size;
		} else {
			Warning("parsing [%s:%d] : custom error message file <%s> larger than %d bytes. Truncating.\n",
				file, linenum, args[2], BUFSIZE);
			errlen = BUFSIZE;
		}

		err = malloc(errlen); /* malloc() must succeed during parsing */
		errnum = read(fd, err, errlen);
		if (errnum != errlen) {
			Alert("parsing [%s:%d] : error reading file <%s> for custom error message <%s>.\n",
			      file, linenum, args[2], args[1]);
			close(fd);
			free(err);
			return -1;
		}
		close(fd);

		errnum = atol(args[1]);
		for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
			if (http_err_codes[rc] == errnum) {
				if (curproxy->errmsg[rc].str)
					free(curproxy->errmsg[rc].str);
				curproxy->errmsg[rc].str = err;
				curproxy->errmsg[rc].len = errlen;
				break;
			}
		}

		if (rc >= HTTP_ERR_SIZE) {
			Warning("parsing [%s:%d] : status code %d not handled, error customization will be ignored.\n",
				file, linenum, errnum);
			free(err);
		}
	}
	else {
		Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "listen");
		return -1;
	}
	return 0;
}


/*
 * This function reads and parses the configuration file given in the argument.
 * returns 0 if OK, -1 if error.
 */
int readcfgfile(const char *file)
{
	char thisline[256];
	char *line;
	FILE *f;
	int linenum = 0;
	char *end;
	char *args[MAX_LINE_ARGS + 1];
	int arg;
	int cfgerr = 0;
	int nbchk, mininter;
	int confsect = CFG_NONE;

	struct proxy *curproxy = NULL;
	struct server *newsrv = NULL;

	if ((f=fopen(file,"r")) == NULL)
		return -1;

	init_default_instance();

	while (fgets(line = thisline, sizeof(thisline), f) != NULL) {
		linenum++;

		end = line + strlen(line);

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
					if ((line + 3 < end ) && ishex(line[2]) && ishex(line[3])) {
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
						return -1;
					}
				}
				if (skip) {
					memmove(line + 1, line + 1 + skip, end - (line + skip + 1));
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
				*line++ = 0;
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

		/* zero out remaining args and ensure that at least one entry
		 * is zeroed out.
		 */
		while (++arg <= MAX_LINE_ARGS) {
			args[arg] = line;
		}

		if (!strcmp(args[0], "listen") ||
		    !strcmp(args[0], "frontend") ||
		    !strcmp(args[0], "backend") ||
		    !strcmp(args[0], "ruleset") ||
		    !strcmp(args[0], "defaults"))  /* new proxy */
			confsect = CFG_LISTEN;
		else if (!strcmp(args[0], "global"))  /* global config */
			confsect = CFG_GLOBAL;
		/* else it's a section keyword */

		switch (confsect) {
		case CFG_LISTEN:
			if (cfg_parse_listen(file, linenum, args) < 0)
				return -1;
			break;
		case CFG_GLOBAL:
			if (cfg_parse_global(file, linenum, args) < 0)
				return -1;
			break;
		default:
			Alert("parsing [%s:%d] : unknown keyword '%s' out of section.\n", file, linenum, args[0]);
			return -1;
		}
	}
	fclose(f);

	/*
	 * Now, check for the integrity of all that we have collected.
	 */

	/* will be needed further to delay some tasks */
	tv_now(&now);

	if ((curproxy = proxy) == NULL) {
		Alert("parsing %s : no <listen> line. Nothing to do !\n",
		      file);
		return -1;
	}

	while (curproxy != NULL) {
		struct switching_rule *rule;

		if (curproxy->state == PR_STSTOPPED) {
			curproxy = curproxy->next;
			continue;
		}

		if (curproxy->cap & PR_CAP_FE && curproxy->listen == NULL)  {
			Alert("parsing %s : %s '%s' has no listen address. Please either specify a valid address on the <listen> line, or use the <bind> keyword.\n",
			      file, proxy_type_str(curproxy), curproxy->id);
			cfgerr++;
		}
		else if (curproxy->cap & PR_CAP_BE &&
			 ((curproxy->mode != PR_MODE_HEALTH) &&
			  !(curproxy->options & (PR_O_TRANSP | PR_O_BALANCE)) &&
			  (*(int *)&curproxy->dispatch_addr.sin_addr == 0))) {
			Alert("parsing %s : %s '%s' has no dispatch address and is not in transparent or balance mode.\n",
			      file, proxy_type_str(curproxy), curproxy->id);
			cfgerr++;
		}

		if ((curproxy->mode != PR_MODE_HEALTH) && (curproxy->options & PR_O_BALANCE)) {
			if (curproxy->options & PR_O_TRANSP) {
				Alert("parsing %s : %s '%s' cannot use both transparent and balance mode.\n",
				      file, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}
#ifdef WE_DONT_SUPPORT_SERVERLESS_LISTENERS
			else if (curproxy->srv == NULL) {
				Alert("parsing %s : %s '%s' needs at least 1 server in balance mode.\n",
				      file, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			}
#endif
			else if (*(int *)&curproxy->dispatch_addr.sin_addr != 0) {
				Warning("parsing %s : dispatch address of %s '%s' will be ignored in balance mode.\n",
					file, proxy_type_str(curproxy), curproxy->id);
			}
		}

		if (curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HEALTH) { /* TCP PROXY or HEALTH CHECK */
			if (curproxy->cookie_name != NULL) {
				Warning("parsing %s : cookie will be ignored for %s '%s'.\n",
					file, proxy_type_str(curproxy), curproxy->id);
			}
			if (curproxy->rsp_exp != NULL) {
				Warning("parsing %s : server regular expressions will be ignored for %s '%s'.\n",
					file, proxy_type_str(curproxy), curproxy->id);
			}
			if (curproxy->req_exp != NULL) {
				Warning("parsing %s : client regular expressions will be ignored for %s '%s'.\n",
					file, proxy_type_str(curproxy), curproxy->id);
			}
			if (curproxy->monitor_uri != NULL) {
				Warning("parsing %s : monitor-uri will be ignored for %s '%s'.\n",
					file, proxy_type_str(curproxy), curproxy->id);
			}
			if (curproxy->options & PR_O_BALANCE_UH) {
				curproxy->options &= ~PR_O_BALANCE;
				curproxy->options |= PR_O_BALANCE_RR;

				Warning("parsing %s : URI hash will be ignored for %s '%s'. Falling back to round robin.\n",
					file, proxy_type_str(curproxy), curproxy->id);
			}
		}

		if (curproxy->mode == PR_MODE_HEALTH) { /* TCP PROXY or HEALTH CHECK */
			if ((newsrv = curproxy->srv) != NULL) {
				Warning("parsing %s : servers will be ignored for %s '%s'.\n",
					file, proxy_type_str(curproxy), curproxy->id);
			}
		}

		if (curproxy->mode == PR_MODE_HTTP) { /* HTTP PROXY */
			if ((curproxy->cookie_name != NULL) && ((newsrv = curproxy->srv) == NULL)) {
				Alert("parsing %s : HTTP proxy %s has a cookie but no server list !\n",
				      file, curproxy->id);
				cfgerr++;
			}
		}

		/* if a default backend was specified, let's find it */
		if (curproxy->defbe.name) {
			struct proxy *target;

			for (target = proxy; target != NULL; target = target->next) {
				if (strcmp(target->id, curproxy->defbe.name) == 0)
					break;
			}
			if (target == NULL) {
				Alert("parsing %s : default backend '%s' in HTTP %s '%s' was not found !\n", 
				      file, curproxy->defbe.name, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			} else if (target == curproxy) {
				Alert("parsing %s : loop detected for default backend %s !\n", file, curproxy->defbe.name);
				cfgerr++;
			} else if (!(target->cap & PR_CAP_BE)) {
				Alert("parsing %s : default backend '%s' in HTTP %s '%s' has no backend capability !\n",
				      file, curproxy->defbe.name, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			} else if (target->mode != curproxy->mode) {
				Alert("parsing %s : default backend '%s' in HTTP %s '%s' is not of same mode (tcp/http) !\n",
				      file, curproxy->defbe.name, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			} else {
				free(curproxy->defbe.name);
				curproxy->defbe.be = target;
			}
		}

		/* find the target proxy in setbe */
		if (curproxy->mode == PR_MODE_HTTP && curproxy->req_exp != NULL) {
			/* map jump target for ACT_SETBE in req_rep chain */ 
			struct hdr_exp *exp;
			struct proxy *target;
			for (exp = curproxy->req_exp; exp != NULL; exp = exp->next) {
				if (exp->action != ACT_SETBE)
					continue;
				for (target = proxy; target != NULL; target = target->next) {
					if (strcmp(target->id, exp->replace) == 0)
						break;
				}
				if (target == NULL) {
					Alert("parsing %s : backend '%s' in HTTP %s '%s' was not found !\n", 
					      file, exp->replace, proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				} else if (target == curproxy) {
					Alert("parsing %s : loop detected for backend %s !\n", file, exp->replace);
					cfgerr++;
				} else if (!(target->cap & PR_CAP_BE)) {
					Alert("parsing %s : target '%s' in HTTP %s '%s' has no backend capability !\n",
					      file, exp->replace, proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				} else if (target->mode != PR_MODE_HTTP) {
					Alert("parsing %s : backend '%s' in HTTP %s '%s' is not HTTP (use 'mode http') !\n",
					      file, exp->replace, proxy_type_str(curproxy), curproxy->id);
					cfgerr++;
				} else {
					free((void *)exp->replace);
					exp->replace = (const char *)target;
				}
			}
		}

		/* find the target proxy for 'use_backend' rules */
		list_for_each_entry(rule, &curproxy->switching_rules, list) {
			/* map jump target for ACT_SETBE in req_rep chain */ 
			struct proxy *target;

			for (target = proxy; target != NULL; target = target->next) {
				if (strcmp(target->id, rule->be.name) == 0)
					break;
			}

			if (target == NULL) {
				Alert("parsing %s : backend '%s' in HTTP %s '%s' was not found !\n", 
				      file, rule->be.name, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			} else if (target == curproxy) {
				Alert("parsing %s : loop detected for backend %s !\n", file, rule->be.name);
				cfgerr++;
			} else if (!(target->cap & PR_CAP_BE)) {
				Alert("parsing %s : target '%s' in HTTP %s '%s' has no backend capability !\n",
				      file, rule->be.name, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			} else if (target->mode != curproxy->mode) {
				Alert("parsing %s : backend '%s' referenced in %s '%s' is of different mode !\n",
				      file, rule->be.name, proxy_type_str(curproxy), curproxy->id);
				cfgerr++;
			} else {
				free((void *)rule->be.name);
				rule->be.backend = target;
			}
		}

		if ((curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HTTP) &&
		    (((curproxy->cap & PR_CAP_FE) && !tv_isset(&curproxy->clitimeout)) ||
		     ((curproxy->cap & PR_CAP_BE) && (curproxy->srv) &&
		      (!tv_isset(&curproxy->contimeout) || !tv_isset(&curproxy->srvtimeout))))) {
			Warning("parsing %s : missing timeouts for %s '%s'.\n"
				"   | While not properly invalid, you will certainly encounter various problems\n"
				"   | with such a configuration. To fix this, please ensure that all following\n"
				"   | values are set to a non-zero value: clitimeout, contimeout, srvtimeout.\n",
				file, proxy_type_str(curproxy), curproxy->id);
		}

		if (curproxy->options & PR_O_SSL3_CHK) {
			curproxy->check_len = sizeof(sslv3_client_hello_pkt);
			curproxy->check_req = (char *)malloc(sizeof(sslv3_client_hello_pkt));
			memcpy(curproxy->check_req, sslv3_client_hello_pkt, sizeof(sslv3_client_hello_pkt));
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

		/* now, newsrv == curproxy->srv */
		if (newsrv) {
			struct server *srv;
			int pgcd;
			int act, bck;

			/* We will factor the weights to reduce the table,
			 * using Euclide's largest common divisor algorithm
			 */
			pgcd = newsrv->uweight;
			for (srv = newsrv->next; srv && pgcd > 1; srv = srv->next) {
				int t, w;
		
				w = srv->uweight;
				while (w) {
					t = pgcd % w;
					pgcd = w;
					w = t;
				}
			}

			act = bck = 0;
			for (srv = newsrv; srv; srv = srv->next) {
				srv->eweight = srv->uweight / pgcd;
				if (srv->state & SRV_BACKUP)
					bck += srv->eweight;
				else
					act += srv->eweight;
			}

			/* this is the largest map we will ever need for this servers list */
			if (act < bck)
				act = bck;

			curproxy->srv_map = (struct server **)calloc(act, sizeof(struct server *));
			/* recounts servers and their weights */
			curproxy->map_state = PR_MAP_RECALC;
			recount_servers(curproxy);
			recalc_server_map(curproxy);
		}

		if (curproxy->options & PR_O_LOGASAP)
			curproxy->to_log &= ~LW_BYTES;

		/*
		 * If this server supports a maxconn parameter, it needs a dedicated
		 * tasks to fill the emptied slots when a connection leaves.
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
				Alert("parsing %s, %s '%s' : fullconn is mandatory when minconn is set on a server.\n",
				      file, proxy_type_str(curproxy), curproxy->id, linenum);
				return -1;
			}

			if (newsrv->maxconn > 0) {
				struct task *t;

				if ((t = pool_alloc2(pool2_task)) == NULL) {
					Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
					return -1;
				}
		
				t->qlist.p = NULL;
				t->wq = NULL;
				t->state = TASK_IDLE;
				t->process = process_srv_queue;
				t->context = newsrv;
				newsrv->queue_mgt = t;

				/* never run it unless specifically woken up */
				tv_eternity(&t->expire);
				task_queue(t);
			}
			newsrv = newsrv->next;
		}

		/* now we'll start this proxy's health checks if any */
		/* 1- count the checkers to run simultaneously */
		nbchk = 0;
		mininter = 0;
		newsrv = curproxy->srv;
		while (newsrv != NULL) {
			if (newsrv->state & SRV_CHECKED) {
				if (!mininter || mininter > newsrv->inter)
					mininter = newsrv->inter;
				nbchk++;
			}
			newsrv = newsrv->next;
		}

		/* 2- start them as far as possible from each others while respecting
		 * their own intervals. For this, we will start them after their own
		 * interval added to the min interval divided by the number of servers,
		 * weighted by the server's position in the list.
		 */
		if (nbchk > 0) {
			struct task *t;
			int srvpos;

			newsrv = curproxy->srv;
			srvpos = 0;
			while (newsrv != NULL) {
				/* should this server be checked ? */
				if (newsrv->state & SRV_CHECKED) {
					if ((t = pool_alloc2(pool2_task)) == NULL) {
						Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
						return -1;
					}
		
					t->wq = NULL;
					t->qlist.p = NULL;
					t->state = TASK_IDLE;
					t->process = process_chk;
					t->context = newsrv;
		
					/* check this every ms */
					tv_ms_add(&t->expire, &now,
						  newsrv->inter + mininter * srvpos / nbchk);
					task_queue(t);
					//task_wakeup(&rq, t);
					srvpos++;
				}
				newsrv = newsrv->next;
			}
		}

		curproxy = curproxy->next;
	}
	if (cfgerr > 0) {
		Alert("Errors found in configuration file, aborting.\n");
		return -1;
	}
	else
		return 0;
}



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
