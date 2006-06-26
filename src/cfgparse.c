/*
 * Configuration parser
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
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

#include <haproxy/cfgparse.h>
#include <haproxy/config.h>
#include <haproxy/memory.h>
#include <haproxy/standard.h>
#include <haproxy/time.h>
#include <haproxy/uri_auth.h>

#include <types/capture.h>
#include <types/global.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/queue.h>

#include <proto/backend.h>
#include <proto/checks.h>
#include <proto/log.h>
#include <proto/server.h>
#include <proto/task.h>


const char *HTTP_302 =
	"HTTP/1.0 302 Found\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 302 except that the browser MUST retry with the GET method */
const char *HTTP_303 =
	"HTTP/1.0 303 See Other\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

const char *HTTP_400 =
	"HTTP/1.0 400 Bad request\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n";

const char *HTTP_403 =
	"HTTP/1.0 403 Forbidden\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n";

const char *HTTP_408 =
	"HTTP/1.0 408 Request Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n";

const char *HTTP_500 =
	"HTTP/1.0 500 Server Error\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>500 Server Error</h1>\nAn internal server error occured.\n</body></html>\n";

const char *HTTP_502 =
	"HTTP/1.0 502 Bad Gateway\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n";

const char *HTTP_503 =
	"HTTP/1.0 503 Service Unavailable\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n";

const char *HTTP_504 =
	"HTTP/1.0 504 Gateway Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time.\n</body></html>\n";


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
 * parse a line in a <global> section. Returns 0 if OK, -1 if error.
 */
int cfg_parse_global(char *file, int linenum, char **args)
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
	else if (!strcmp(args[0], "nopoll")) {
		cfg_polling_mechanism &= ~POLL_USE_POLL;
	}
	else if (!strcmp(args[0], "quiet")) {
		global.mode |= MODE_QUIET;
	}
	else if (!strcmp(args[0], "stats")) {
		global.mode |= MODE_STATS;
	}
	else if (!strcmp(args[0], "uid")) {
		if (global.uid != 0) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
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
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		global.gid = atol(args[1]);
	}
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
 * parse a line in a <listen> section. Returns 0 if OK, -1 if error.
 */
int cfg_parse_listen(char *file, int linenum, char **args)
{
	static struct proxy *curproxy = NULL;
	struct server *newsrv = NULL;
	char *err;
	int rc;

	if (!strcmp(args[0], "listen")) {  /* new proxy */
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

		curproxy->id = strdup(args[1]);

		/* parse the listener address if any */
		if (*args[2]) {
			curproxy->listen = str2listener(args[2], curproxy->listen);
			if (!curproxy->listen)
				return -1;
			global.maxsock++;
		}

		/* set default values */
		curproxy->state = defproxy.state;
		curproxy->maxconn = defproxy.maxconn;
		curproxy->conn_retries = defproxy.conn_retries;
		curproxy->options = defproxy.options;

		if (defproxy.check_req)
			curproxy->check_req = strdup(defproxy.check_req);
		curproxy->check_len = defproxy.check_len;

		if (defproxy.cookie_name)
			curproxy->cookie_name = strdup(defproxy.cookie_name);
		curproxy->cookie_len = defproxy.cookie_len;

		if (defproxy.capture_name)
			curproxy->capture_name = strdup(defproxy.capture_name);
		curproxy->capture_namelen = defproxy.capture_namelen;
		curproxy->capture_len = defproxy.capture_len;

		if (defproxy.errmsg.msg400)
			curproxy->errmsg.msg400 = strdup(defproxy.errmsg.msg400);
		curproxy->errmsg.len400 = defproxy.errmsg.len400;

		if (defproxy.errmsg.msg403)
			curproxy->errmsg.msg403 = strdup(defproxy.errmsg.msg403);
		curproxy->errmsg.len403 = defproxy.errmsg.len403;

		if (defproxy.errmsg.msg408)
			curproxy->errmsg.msg408 = strdup(defproxy.errmsg.msg408);
		curproxy->errmsg.len408 = defproxy.errmsg.len408;

		if (defproxy.errmsg.msg500)
			curproxy->errmsg.msg500 = strdup(defproxy.errmsg.msg500);
		curproxy->errmsg.len500 = defproxy.errmsg.len500;

		if (defproxy.errmsg.msg502)
			curproxy->errmsg.msg502 = strdup(defproxy.errmsg.msg502);
		curproxy->errmsg.len502 = defproxy.errmsg.len502;

		if (defproxy.errmsg.msg503)
			curproxy->errmsg.msg503 = strdup(defproxy.errmsg.msg503);
		curproxy->errmsg.len503 = defproxy.errmsg.len503;

		if (defproxy.errmsg.msg504)
			curproxy->errmsg.msg504 = strdup(defproxy.errmsg.msg504);
		curproxy->errmsg.len504 = defproxy.errmsg.len504;

		curproxy->clitimeout = defproxy.clitimeout;
		curproxy->contimeout = defproxy.contimeout;
		curproxy->srvtimeout = defproxy.srvtimeout;
		curproxy->mode = defproxy.mode;
		curproxy->logfac1 = defproxy.logfac1;
		curproxy->logsrv1 = defproxy.logsrv1;
		curproxy->loglev1 = defproxy.loglev1;
		curproxy->logfac2 = defproxy.logfac2;
		curproxy->logsrv2 = defproxy.logsrv2;
		curproxy->loglev2 = defproxy.loglev2;
		curproxy->to_log = defproxy.to_log & ~LW_COOKIE & ~LW_REQHDR & ~ LW_RSPHDR;
		curproxy->grace  = defproxy.grace;
		curproxy->uri_auth  = defproxy.uri_auth;
		curproxy->source_addr = defproxy.source_addr;
		curproxy->mon_net = defproxy.mon_net;
		curproxy->mon_mask = defproxy.mon_mask;
		return 0;
	}
	else if (!strcmp(args[0], "defaults")) {  /* use this one to assign default values */
		/* some variables may have already been initialized earlier */
		if (defproxy.check_req)     free(defproxy.check_req);
		if (defproxy.cookie_name)   free(defproxy.cookie_name);
		if (defproxy.capture_name)  free(defproxy.capture_name);
		if (defproxy.errmsg.msg400) free(defproxy.errmsg.msg400);
		if (defproxy.errmsg.msg403) free(defproxy.errmsg.msg403);
		if (defproxy.errmsg.msg408) free(defproxy.errmsg.msg408);
		if (defproxy.errmsg.msg500) free(defproxy.errmsg.msg500);
		if (defproxy.errmsg.msg502) free(defproxy.errmsg.msg502);
		if (defproxy.errmsg.msg503) free(defproxy.errmsg.msg503);
		if (defproxy.errmsg.msg504) free(defproxy.errmsg.msg504);
		/* we cannot free uri_auth because it might already be used */
		init_default_instance();
		curproxy = &defproxy;
		return 0;
	}
	else if (curproxy == NULL) {
		Alert("parsing [%s:%d] : 'listen' or 'defaults' expected.\n", file, linenum);
		return -1;
	}
    
	if (!strcmp(args[0], "bind")) {  /* new listen addresses */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}

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
		/* flush useless bits */
		curproxy->mon_net.s_addr &= curproxy->mon_mask.s_addr;
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
	else if (!strcmp(args[0], "cookie")) {  /* cookie name */
		int cur_arg;
		//	  if (curproxy == &defproxy) {
		//	      Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
		//	      return -1;
		//	  }

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
		curproxy->appsession_timeout = atoi(args[5]);
		rc = chtbl_init(&(curproxy->htbl_proxy), TBLSIZ, hashpjw, match_str, destroy);
		if (rc) {
			Alert("Error Init Appsession Hashtable.\n");
			return -1;
		}
	} /* Url App Session */
	else if (!strcmp(args[0], "capture")) {
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
		if (curproxy->contimeout != defproxy.contimeout) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer <time_in_ms> as argument.\n",
			      file, linenum, args[0]);
			return -1;
		}
		curproxy->contimeout = atol(args[1]);
	}
	else if (!strcmp(args[0], "clitimeout")) {  /*  client timeout */
		if (curproxy->clitimeout != defproxy.clitimeout) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n",
			      file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer <time_in_ms> as argument.\n",
			      file, linenum, args[0]);
			return -1;
		}
		curproxy->clitimeout = atol(args[1]);
	}
	else if (!strcmp(args[0], "srvtimeout")) {  /*  server timeout */
		if (curproxy->srvtimeout != defproxy.srvtimeout) {
			Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer <time_in_ms> as argument.\n",
			      file, linenum, args[0]);
			return -1;
		}
		curproxy->srvtimeout = atol(args[1]);
	}
	else if (!strcmp(args[0], "retries")) {  /* connection retries */
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument (dispatch counts for one).\n",
			      file, linenum, args[0]);
			return -1;
		}
		curproxy->conn_retries = atol(args[1]);
	}
	else if (!strcmp(args[0], "stats")) {
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
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an option name.\n", file, linenum, args[0]);
			return -1;
		}
		if (!strcmp(args[1], "redispatch"))
			/* enable reconnections to dispatch */
			curproxy->options |= PR_O_REDISP;
#ifdef TPROXY
		else if (!strcmp(args[1], "transparent"))
			/* enable transparent proxy connections */
			curproxy->options |= PR_O_TRANSP;
#endif
		else if (!strcmp(args[1], "keepalive"))
			/* enable keep-alive */
			curproxy->options |= PR_O_KEEPALIVE;
		else if (!strcmp(args[1], "forwardfor"))
			/* insert x-forwarded-for field */
			curproxy->options |= PR_O_FWDFOR;
		else if (!strcmp(args[1], "logasap"))
			/* log as soon as possible, without waiting for the session to complete */
			curproxy->options |= PR_O_LOGASAP;
		else if (!strcmp(args[1], "abortonclose"))
			/* abort connection if client closes during queue or connect() */
			curproxy->options |= PR_O_ABRT_CLOSE;
		else if (!strcmp(args[1], "httpclose"))
			/* force connection: close in both directions in HTTP mode */
			curproxy->options |= PR_O_HTTP_CLOSE;
		else if (!strcmp(args[1], "forceclose"))
			/* force connection: close in both directions in HTTP mode and enforce end of session */
			curproxy->options |= PR_O_FORCE_CLO | PR_O_HTTP_CLOSE;
		else if (!strcmp(args[1], "checkcache"))
			/* require examination of cacheability of the 'set-cookie' field */
			curproxy->options |= PR_O_CHK_CACHE;
		else if (!strcmp(args[1], "httplog"))
			/* generate a complete HTTP log */
			curproxy->to_log |= LW_DATE | LW_CLIP | LW_SVID | LW_REQ | LW_PXID | LW_RESP | LW_BYTES;
		else if (!strcmp(args[1], "tcplog"))
			/* generate a detailed TCP log */
			curproxy->to_log |= LW_DATE | LW_CLIP | LW_SVID | LW_PXID | LW_BYTES;
		else if (!strcmp(args[1], "dontlognull")) {
			/* don't log empty requests */
			curproxy->options |= PR_O_NULLNOLOG;
		}
		else if (!strcmp(args[1], "tcpka")) {
			/* enable TCP keep-alives on client and server sessions */
			curproxy->options |= PR_O_TCP_CLI_KA | PR_O_TCP_SRV_KA;
		}
		else if (!strcmp(args[1], "clitcpka")) {
			/* enable TCP keep-alives on client sessions */
			curproxy->options |= PR_O_TCP_CLI_KA;
		}
		else if (!strcmp(args[1], "srvtcpka")) {
			/* enable TCP keep-alives on server sessions */
			curproxy->options |= PR_O_TCP_SRV_KA;
		}
		else if (!strcmp(args[1], "allbackups")) {
			/* Use all backup servers simultaneously */
			curproxy->options |= PR_O_USE_ALL_BK;
		}
		else if (!strcmp(args[1], "httpchk")) {
			/* use HTTP request to check servers' health */
			if (curproxy->check_req != NULL) {
				free(curproxy->check_req);
			}
			curproxy->options |= PR_O_HTTP_CHK;
			if (!*args[2]) { /* no argument */
				curproxy->check_req = strdup(DEF_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_CHECK_REQ);
			} else if (!*args[3]) { /* one argument : URI */
				int reqlen = strlen(args[2]) + strlen("OPTIONS / HTTP/1.0\r\n\r\n");
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
		else if (!strcmp(args[1], "persist")) {
			/* persist on using the server specified by the cookie, even when it's down */
			curproxy->options |= PR_O_PERSIST;
		}
		else {
			Alert("parsing [%s:%d] : unknown option '%s'.\n", file, linenum, args[1]);
			return -1;
		}
		return 0;
	}
	else if (!strcmp(args[0], "redispatch") || !strcmp(args[0], "redisp")) {
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
		if (*(args[1]) == 0) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			return -1;
		}
		curproxy->maxconn = atol(args[1]);
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
		if (strchr(args[1], ':') == NULL) {
			Alert("parsing [%s:%d] : '%s' expects <addr:port> as argument.\n", file, linenum, args[0]);
			return -1;
		}
		curproxy->dispatch_addr = *str2sa(args[1]);
	}
	else if (!strcmp(args[0], "balance")) {  /* set balancing with optional algorithm */
		if (*(args[1])) {
			if (!strcmp(args[1], "roundrobin")) {
				curproxy->options |= PR_O_BALANCE_RR;
			}
			else if (!strcmp(args[1], "source")) {
				curproxy->options |= PR_O_BALANCE_SH;
			}
			else {
				Alert("parsing [%s:%d] : '%s' only supports 'roundrobin' and 'source' options.\n", file, linenum, args[0]);
				return -1;
			}
		}
		else /* if no option is set, use round-robin by default */
			curproxy->options |= PR_O_BALANCE_RR;
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
			if (!isdigit((int)*rport))
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
				newsrv->uweight = w - 1;
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
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>] as argument.\n",
					      file, linenum, "source");
					return -1;
				}
				newsrv->state |= SRV_BIND_SRC;
				newsrv->source_addr = *str2sa(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else {
				Alert("parsing [%s:%d] : server %s only supports options 'backup', 'cookie', 'check', 'inter', 'rise', 'fall', 'port', 'source', 'minconn', 'maxconn' and 'weight'.\n",
				      file, linenum, newsrv->id);
				return -1;
			}
		}

		if (do_check) {
			if (!newsrv->check_port && !(newsrv->state & SRV_MAPPORTS))
				newsrv->check_port = realport; /* by default */
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
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>] as argument.\n",
			      file, linenum, "source");
			return -1;
		}
	
		curproxy->source_addr = *str2sa(args[1]);
		curproxy->options |= PR_O_BIND_SRC;
	}
	else if (!strcmp(args[0], "cliexp") || !strcmp(args[0], "reqrep")) {  /* replace request header from a regex */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
	
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
	else if (!strcmp(args[0], "reqirep")) {  /* replace request header from a regex, ignoring case */
		regex_t *preg;
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}
	
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
	else if (!strcmp(args[0], "reqadd")) {  /* add request header */
		if (curproxy == &defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			return -1;
		}

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

		// if (curproxy == &defproxy) {
		//     Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
		//     return -1;
		// }

		if (*(args[2]) == 0) {
			Alert("parsing [%s:%d] : <errorloc> expects <error> and <url> as arguments.\n", file, linenum);
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

		if (errnum == 400) {
			if (curproxy->errmsg.msg400) {
				//Warning("parsing [%s:%d] : error %d already defined.\n", file, linenum, errnum);
				free(curproxy->errmsg.msg400);
			}
			curproxy->errmsg.msg400 = err;
			curproxy->errmsg.len400 = errlen;
		}
		else if (errnum == 403) {
			if (curproxy->errmsg.msg403) {
				//Warning("parsing [%s:%d] : error %d already defined.\n", file, linenum, errnum);
				free(curproxy->errmsg.msg403);
			}
			curproxy->errmsg.msg403 = err;
			curproxy->errmsg.len403 = errlen;
		}
		else if (errnum == 408) {
			if (curproxy->errmsg.msg408) {
				//Warning("parsing [%s:%d] : error %d already defined.\n", file, linenum, errnum);
				free(curproxy->errmsg.msg408);
			}
			curproxy->errmsg.msg408 = err;
			curproxy->errmsg.len408 = errlen;
		}
		else if (errnum == 500) {
			if (curproxy->errmsg.msg500) {
				//Warning("parsing [%s:%d] : error %d already defined.\n", file, linenum, errnum);
				free(curproxy->errmsg.msg500);
			}
			curproxy->errmsg.msg500 = err;
			curproxy->errmsg.len500 = errlen;
		}
		else if (errnum == 502) {
			if (curproxy->errmsg.msg502) {
				//Warning("parsing [%s:%d] : error %d already defined.\n", file, linenum, errnum);
				free(curproxy->errmsg.msg502);
			}
			curproxy->errmsg.msg502 = err;
			curproxy->errmsg.len502 = errlen;
		}
		else if (errnum == 503) {
			if (curproxy->errmsg.msg503) {
				//Warning("parsing [%s:%d] : error %d already defined.\n", file, linenum, errnum);
				free(curproxy->errmsg.msg503);
			}
			curproxy->errmsg.msg503 = err;
			curproxy->errmsg.len503 = errlen;
		}
		else if (errnum == 504) {
			if (curproxy->errmsg.msg504) {
				//Warning("parsing [%s:%d] : error %d already defined.\n", file, linenum, errnum);
				free(curproxy->errmsg.msg504);
			}
			curproxy->errmsg.msg504 = err;
			curproxy->errmsg.len504 = errlen;
		}
		else {
			Warning("parsing [%s:%d] : error %d relocation will be ignored.\n", file, linenum, errnum);
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
int readcfgfile(char *file)
{
	char thisline[256];
	char *line;
	FILE *f;
	int linenum = 0;
	char *end;
	char *args[MAX_LINE_ARGS];
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
		while (isspace((int)*line))
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
			else if (isspace((int)*line)) {
				/* a non-escaped space is an argument separator */
				*line++ = 0;
				while (isspace((int)*line))
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

		/* zero out remaining args */
		while (++arg < MAX_LINE_ARGS) {
			args[arg] = line;
		}

		if (!strcmp(args[0], "listen") || !strcmp(args[0], "defaults"))  /* new proxy */
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
		if (curproxy->state == PR_STSTOPPED) {
			curproxy = curproxy->next;
			continue;
		}

		if (curproxy->listen == NULL) {
			Alert("parsing %s : listener %s has no listen address. Please either specify a valid address on the <listen> line, or use the <bind> keyword.\n", file, curproxy->id);
			cfgerr++;
		}
		else if ((curproxy->mode != PR_MODE_HEALTH) &&
			 !(curproxy->options & (PR_O_TRANSP | PR_O_BALANCE)) &&
			 (*(int *)&curproxy->dispatch_addr.sin_addr == 0)) {
			Alert("parsing %s : listener %s has no dispatch address and is not in transparent or balance mode.\n",
			      file, curproxy->id);
			cfgerr++;
		}
		else if ((curproxy->mode != PR_MODE_HEALTH) && (curproxy->options & PR_O_BALANCE)) {
			if (curproxy->options & PR_O_TRANSP) {
				Alert("parsing %s : listener %s cannot use both transparent and balance mode.\n",
				      file, curproxy->id);
				cfgerr++;
			}
#ifdef WE_DONT_SUPPORT_SERVERLESS_LISTENERS
			else if (curproxy->srv == NULL) {
				Alert("parsing %s : listener %s needs at least 1 server in balance mode.\n",
				      file, curproxy->id);
				cfgerr++;
			}
#endif
			else if (*(int *)&curproxy->dispatch_addr.sin_addr != 0) {
				Warning("parsing %s : dispatch address of listener %s will be ignored in balance mode.\n",
					file, curproxy->id);
			}
		}
		else if (curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HEALTH) { /* TCP PROXY or HEALTH CHECK */
			if (curproxy->cookie_name != NULL) {
				Warning("parsing %s : cookie will be ignored for listener %s.\n",
					file, curproxy->id);
			}
			if ((newsrv = curproxy->srv) != NULL) {
				Warning("parsing %s : servers will be ignored for listener %s.\n",
					file, curproxy->id);
			}
			if (curproxy->rsp_exp != NULL) {
				Warning("parsing %s : server regular expressions will be ignored for listener %s.\n",
					file, curproxy->id);
			}
			if (curproxy->req_exp != NULL) {
				Warning("parsing %s : client regular expressions will be ignored for listener %s.\n",
					file, curproxy->id);
			}
		}
		else if (curproxy->mode == PR_MODE_HTTP) { /* HTTP PROXY */
			if ((curproxy->cookie_name != NULL) && ((newsrv = curproxy->srv) == NULL)) {
				Alert("parsing %s : HTTP proxy %s has a cookie but no server list !\n",
				      file, curproxy->id);
				cfgerr++;
			}
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

		/* now, newsrv == curproxy->srv */
		if (newsrv) {
			struct server *srv;
			int pgcd;
			int act, bck;

			/* We will factor the weights to reduce the table,
			 * using Euclide's largest common divisor algorithm
			 */
			pgcd = newsrv->uweight + 1;
			for (srv = newsrv->next; srv && pgcd > 1; srv = srv->next) {
				int t, w;
		
				w = srv->uweight + 1;
				while (w) {
					t = pgcd % w;
					pgcd = w;
					w = t;
				}
			}

			act = bck = 0;
			for (srv = newsrv; srv; srv = srv->next) {
				srv->eweight = ((srv->uweight + 1) / pgcd) - 1;
				if (srv->state & SRV_BACKUP)
					bck += srv->eweight + 1;
				else
					act += srv->eweight + 1;
			}

			/* this is the largest map we will ever need for this servers list */
			if (act < bck)
				act = bck;

			curproxy->srv_map = (struct server **)calloc(act, sizeof(struct server *));
			/* recounts servers and their weights */
			recount_servers(curproxy);
			recalc_server_map(curproxy);
		}

		if (curproxy->options & PR_O_LOGASAP)
			curproxy->to_log &= ~LW_BYTES;

		if (curproxy->errmsg.msg400 == NULL) {
			curproxy->errmsg.msg400 = (char *)HTTP_400;
			curproxy->errmsg.len400 = strlen(HTTP_400);
		}
		if (curproxy->errmsg.msg403 == NULL) {
			curproxy->errmsg.msg403 = (char *)HTTP_403;
			curproxy->errmsg.len403 = strlen(HTTP_403);
		}
		if (curproxy->errmsg.msg408 == NULL) {
			curproxy->errmsg.msg408 = (char *)HTTP_408;
			curproxy->errmsg.len408 = strlen(HTTP_408);
		}
		if (curproxy->errmsg.msg500 == NULL) {
			curproxy->errmsg.msg500 = (char *)HTTP_500;
			curproxy->errmsg.len500 = strlen(HTTP_500);
		}
		if (curproxy->errmsg.msg502 == NULL) {
			curproxy->errmsg.msg502 = (char *)HTTP_502;
			curproxy->errmsg.len502 = strlen(HTTP_502);
		}
		if (curproxy->errmsg.msg503 == NULL) {
			curproxy->errmsg.msg503 = (char *)HTTP_503;
			curproxy->errmsg.len503 = strlen(HTTP_503);
		}
		if (curproxy->errmsg.msg504 == NULL) {
			curproxy->errmsg.msg504 = (char *)HTTP_504;
			curproxy->errmsg.len504 = strlen(HTTP_504);
		}

		/*
		 * If this server supports a maxconn parameter, it needs a dedicated
		 * tasks to fill the emptied slots when a connection leaves.
		 */
		newsrv = curproxy->srv;
		while (newsrv != NULL) {
			if (newsrv->minconn >= newsrv->maxconn) {
				/* Only 'minconn' was specified, or it was higher than or equal
				 * to 'maxconn'. Let's turn this into maxconn and clean it, as
				 * this will avoid further useless expensive computations.
				 */
				newsrv->maxconn = newsrv->minconn;
				newsrv->minconn = 0;
			}

			if (newsrv->maxconn > 0) {
				struct task *t;

				if ((t = pool_alloc(task)) == NULL) {
					Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
					return -1;
				}
		
				t->next = t->prev = t->rqnext = NULL; /* task not in run queue yet */
				t->wq = LIST_HEAD(wait_queue[1]); /* already assigned to the eternity queue */
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
					if ((t = pool_alloc(task)) == NULL) {
						Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
						return -1;
					}
		
					t->next = t->prev = t->rqnext = NULL; /* task not in run queue yet */
					t->wq = LIST_HEAD(wait_queue[0]); /* but already has a wait queue assigned */
					t->state = TASK_IDLE;
					t->process = process_chk;
					t->context = newsrv;
		
					/* check this every ms */
					tv_delayfrom(&t->expire, &now,
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
