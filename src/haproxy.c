/*
 * HA-Proxy : High Availability-enabled HTTP/TCP proxy
 * Copyright 2000-2008  Willy Tarreau <w@1wt.eu>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Please refer to RFC2068 or RFC2616 for informations about HTTP protocol, and
 * RFC2965 for informations about cookies usage. More generally, the IETF HTTP
 * Working Group's web site should be consulted for protocol related changes :
 *
 *     http://ftp.ics.uci.edu/pub/ietf/http/
 *
 * Pending bugs (may be not fixed because never reproduced) :
 *   - solaris only : sometimes, an HTTP proxy with only a dispatch address causes
 *     the proxy to terminate (no core) if the client breaks the connection during
 *     the response. Seen on 1.1.8pre4, but never reproduced. May not be related to
 *     the snprintf() bug since requests were simple (GET / HTTP/1.0), but may be
 *     related to missing setsid() (fixed in 1.1.15)
 *   - a proxy with an invalid config will prevent the startup even if disabled.
 *
 * ChangeLog has moved to the CHANGELOG file.
 *
 * TODO:
 *   - handle properly intermediate incomplete server headers. Done ?
 *   - handle hot-reconfiguration
 *   - fix client/server state transition when server is in connect or headers state
 *     and client suddenly disconnects. The server *should* switch to SHUT_WR, but
 *     still handle HTTP headers.
 *   - remove MAX_NEWHDR
 *   - cut this huge file into several ones
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <time.h>
#include <syslog.h>

#ifdef DEBUG_FULL
#include <assert.h>
#endif

#include <common/appsession.h>
#include <common/base64.h>
#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/defaults.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/regex.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/checks.h>
#include <proto/client.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/protocols.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/signal.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

#ifdef CONFIG_HAP_TCPSPLICE
#include <libtcpsplice.h>
#endif

#ifdef CONFIG_HAP_CTTPROXY
#include <proto/cttproxy.h>
#endif

/*********************************************************************/

/*********************************************************************/

char *cfg_cfgfile = NULL;	/* configuration file */
char *progname = NULL;		/* program name */
int  pid;			/* current process id */
int  relative_pid = 1;		/* process id starting at 1 */

/* global options */
struct global global = {
	logfac1 : -1,
	logfac2 : -1,
	loglev1 : 7, /* max syslog level : debug */
	loglev2 : 7,
	.stats_timeout = MS_TO_TICKS(10000), /* stats timeout = 10 seconds */
	.stats_sock = {
		.timeout = &global.stats_timeout,
		.maxconn = 10, /* 10 concurrent stats connections */
		.perm = {
			 .ux = {
				 .uid = -1,
				 .gid = -1,
				 .mode = 0,
			 }
		 }
	}
	/* others NULL OK */
};

/*********************************************************************/

int stopping;	/* non zero means stopping in progress */

/* Here we store informations about the pids of the processes we may pause
 * or kill. We will send them a signal every 10 ms until we can bind to all
 * our ports. With 200 retries, that's about 2 seconds.
 */
#define MAX_START_RETRIES	200
static int nb_oldpids = 0;
static int *oldpids = NULL;
static int oldpids_sig; /* use USR1 or TERM */

/* this is used to drain data, and as a temporary buffer for sprintf()... */
char trash[BUFSIZE];

const int zero = 0;
const int one = 1;
const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };

/*
 * Syslog facilities and levels. Conforming to RFC3164.
 */

#define MAX_HOSTNAME_LEN	32
static char hostname[MAX_HOSTNAME_LEN] = "";


/*********************************************************************/
/*  general purpose functions  ***************************************/
/*********************************************************************/

void display_version()
{
	printf("HA-Proxy version " HAPROXY_VERSION " " HAPROXY_DATE"\n");
	printf("Copyright 2000-2008 Willy Tarreau <w@1wt.eu>\n\n");
}

void display_build_opts()
{
	printf("Build options :"
#ifdef BUILD_TARGET
	       "\n  TARGET  = " BUILD_TARGET
#endif
#ifdef BUILD_CPU
	       "\n  CPU     = " BUILD_CPU
#endif
#ifdef BUILD_CC
	       "\n  CC      = " BUILD_CC
#endif
#ifdef BUILD_CFLAGS
	       "\n  CFLAGS  = " BUILD_CFLAGS
#endif
#ifdef BUILD_OPTIONS
	       "\n  OPTIONS = " BUILD_OPTIONS
#endif
	       "\n\n");
}

/*
 * This function prints the command line usage and exits
 */
void usage(char *name)
{
	display_version();
	fprintf(stderr,
		"Usage : %s -f <cfgfile> [ -vdV"
		"D ] [ -n <maxconn> ] [ -N <maxpconn> ]\n"
		"        [ -p <pidfile> ] [ -m <max megs> ]\n"
		"        -v displays version ; -vv shows known build options.\n"
		"        -d enters debug mode ; -db only disables background mode.\n"
		"        -V enters verbose mode (disables quiet mode)\n"
		"        -D goes daemon ; implies -q\n"
		"        -q quiet mode : don't display messages\n"
		"        -c check mode : only check config file and exit\n"
		"        -n sets the maximum total # of connections (%d)\n"
		"        -m limits the usable amount of memory (in MB)\n"
		"        -N sets the default, per-proxy maximum # of connections (%d)\n"
		"        -p writes pids of all children to this file\n"
#if defined(ENABLE_EPOLL)
		"        -de disables epoll() usage even when available\n"
#endif
#if defined(ENABLE_SEPOLL)
		"        -ds disables speculative epoll() usage even when available\n"
#endif
#if defined(ENABLE_KQUEUE)
		"        -dk disables kqueue() usage even when available\n"
#endif
#if defined(ENABLE_POLL)
		"        -dp disables poll() usage even when available\n"
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE) || defined(CONFIG_HAP_TCPSPLICE)
		"        -dS disables splice usage (broken on old kernels)\n"
#endif
		"        -sf/-st [pid ]* finishes/terminates old pids. Must be last arguments.\n"
		"\n",
		name, DEFAULT_MAXCONN, cfg_maxpconn);
	exit(1);
}



/*********************************************************************/
/*   more specific functions   ***************************************/
/*********************************************************************/

/*
 * upon SIGUSR1, let's have a soft stop.
 */
void sig_soft_stop(int sig)
{
	soft_stop();
	pool_gc2();
	signal(sig, SIG_IGN);
}

/*
 * upon SIGTTOU, we pause everything
 */
void sig_pause(int sig)
{
	pause_proxies();
	pool_gc2();
	signal(sig, sig_pause);
}

/*
 * upon SIGTTIN, let's have a soft stop.
 */
void sig_listen(int sig)
{
	listen_proxies();
	signal(sig, sig_listen);
}

/*
 * this function dumps every server's state when the process receives SIGHUP.
 */
void sig_dump_state(int sig)
{
	struct proxy *p = proxy;

	Warning("SIGHUP received, dumping servers states.\n");
	while (p) {
		struct server *s = p->srv;

		send_log(p, LOG_NOTICE, "SIGHUP received, dumping servers states for proxy %s.\n", p->id);
		while (s) {
			snprintf(trash, sizeof(trash),
				 "SIGHUP: Server %s/%s is %s. Conn: %d act, %d pend, %lld tot.",
				 p->id, s->id,
				 (s->state & SRV_RUNNING) ? "UP" : "DOWN",
				 s->cur_sess, s->nbpend, s->cum_sess);
			Warning("%s\n", trash);
			send_log(p, LOG_NOTICE, "%s\n", trash);
			s = s->next;
		}

		/* FIXME: those info are a bit outdated. We should be able to distinguish between FE and BE. */
		if (!p->srv) {
			snprintf(trash, sizeof(trash),
				 "SIGHUP: Proxy %s has no servers. Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
				 p->id,
				 p->feconn, p->beconn, p->totpend, p->nbpend, p->cum_feconn, p->cum_beconn);
		} else if (p->srv_act == 0) {
			snprintf(trash, sizeof(trash),
				 "SIGHUP: Proxy %s %s ! Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
				 p->id,
				 (p->srv_bck) ? "is running on backup servers" : "has no server available",
				 p->feconn, p->beconn, p->totpend, p->nbpend, p->cum_feconn, p->cum_beconn);
		} else {
			snprintf(trash, sizeof(trash),
				 "SIGHUP: Proxy %s has %d active servers and %d backup servers available."
				 " Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
				 p->id, p->srv_act, p->srv_bck,
				 p->feconn, p->beconn, p->totpend, p->nbpend, p->cum_feconn, p->cum_beconn);
		}
		Warning("%s\n", trash);
		send_log(p, LOG_NOTICE, "%s\n", trash);

		p = p->next;
	}
	signal(sig, sig_dump_state);
}

void dump(int sig)
{
#if 0
	struct task *t;
	struct session *s;
	struct rb_node *node;

	for(node = rb_first(&wait_queue[0]);
		node != NULL; node = rb_next(node)) {
		t = rb_entry(node, struct task, rb_node);
		s = t->context;
		qfprintf(stderr,"[dump] wq: task %p, still %ld ms, "
			 "cli=%d, srv=%d, req=%d, rep=%d\n",
			 s, tv_ms_remain(&now, &t->expire),
			 s->si[0].state,
			 s->si[1].state,
			 s->req->l, s->rep?s->rep->l:0);
	}
#endif
	/* dump memory usage then free everything possible */
	dump_pools();
	pool_gc2();
}

#ifdef DEBUG_MEMORY
static void fast_stop(void)
{
	struct proxy *p;
	p = proxy;
	while (p) {
		p->grace = 0;
		p = p->next;
	}
	soft_stop();
}

void sig_int(int sig)
{
	/* This would normally be a hard stop,
	   but we want to be sure about deallocation,
	   and so on, so we do a soft stop with
	   0 GRACE time
	*/
	fast_stop();
	pool_gc2();
	/* If we are killed twice, we decide to die*/
	signal(sig, SIG_DFL);
}

void sig_term(int sig)
{
	/* This would normally be a hard stop,
	   but we want to be sure about deallocation,
	   and so on, so we do a soft stop with
	   0 GRACE time
	*/
	fast_stop();
	pool_gc2();
	/* If we are killed twice, we decide to die*/
	signal(sig, SIG_DFL);
}
#endif


/*
 * This function initializes all the necessary variables. It only returns
 * if everything is OK. If something fails, it exits.
 */
void init(int argc, char **argv)
{
	int i;
	int arg_mode = 0;	/* MODE_DEBUG, ... */
	char *old_argv = *argv;
	char *tmp;
	char *cfg_pidfile = NULL;

	/*
	 * Initialize the previously static variables.
	 */
    
	totalconn = actconn = maxfd = listeners = stopping = 0;
    

#ifdef HAPROXY_MEMMAX
	global.rlimit_memmax = HAPROXY_MEMMAX;
#endif

	tv_update_date(-1,-1);
	start_date = now;

	signal_init();
	init_task();
	init_session();
	init_buffer();
	init_pendconn();
	init_proto_http();

	global.tune.options |= GTUNE_USE_SELECT;  /* select() is always available */
#if defined(ENABLE_POLL)
	global.tune.options |= GTUNE_USE_POLL;
#endif
#if defined(ENABLE_EPOLL)
	global.tune.options |= GTUNE_USE_EPOLL;
#endif
#if defined(ENABLE_SEPOLL)
	global.tune.options |= GTUNE_USE_SEPOLL;
#endif
#if defined(ENABLE_KQUEUE)
	global.tune.options |= GTUNE_USE_KQUEUE;
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE) || defined(CONFIG_HAP_TCPSPLICE)
	global.tune.options |= GTUNE_USE_SPLICE;
#endif

	pid = getpid();
	progname = *argv;
	while ((tmp = strchr(progname, '/')) != NULL)
		progname = tmp + 1;

	argc--; argv++;
	while (argc > 0) {
		char *flag;

		if (**argv == '-') {
			flag = *argv+1;

			/* 1 arg */
			if (*flag == 'v') {
				display_version();
				if (flag[1] == 'v')  /* -vv */
					display_build_opts();
				exit(0);
			}
#if defined(ENABLE_EPOLL)
			else if (*flag == 'd' && flag[1] == 'e')
				global.tune.options &= ~GTUNE_USE_EPOLL;
#endif
#if defined(ENABLE_SEPOLL)
			else if (*flag == 'd' && flag[1] == 's')
				global.tune.options &= ~GTUNE_USE_SEPOLL;
#endif
#if defined(ENABLE_POLL)
			else if (*flag == 'd' && flag[1] == 'p')
				global.tune.options &= ~GTUNE_USE_POLL;
#endif
#if defined(ENABLE_KQUEUE)
			else if (*flag == 'd' && flag[1] == 'k')
				global.tune.options &= ~GTUNE_USE_KQUEUE;
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE) || defined(CONFIG_HAP_TCPSPLICE)
			else if (*flag == 'd' && flag[1] == 'S')
				global.tune.options &= ~GTUNE_USE_SPLICE;
#endif
			else if (*flag == 'V')
				arg_mode |= MODE_VERBOSE;
			else if (*flag == 'd' && flag[1] == 'b')
				arg_mode |= MODE_FOREGROUND;
			else if (*flag == 'd')
				arg_mode |= MODE_DEBUG;
			else if (*flag == 'c')
				arg_mode |= MODE_CHECK;
			else if (*flag == 'D')
				arg_mode |= MODE_DAEMON | MODE_QUIET;
			else if (*flag == 'q')
				arg_mode |= MODE_QUIET;
			else if (*flag == 's' && (flag[1] == 'f' || flag[1] == 't')) {
				/* list of pids to finish ('f') or terminate ('t') */

				if (flag[1] == 'f')
					oldpids_sig = SIGUSR1; /* finish then exit */
				else
					oldpids_sig = SIGTERM; /* terminate immediately */
				argv++; argc--;

				if (argc > 0) {
					oldpids = calloc(argc, sizeof(int));
					while (argc > 0) {
						oldpids[nb_oldpids] = atol(*argv);
						if (oldpids[nb_oldpids] <= 0)
							usage(old_argv);
						argc--; argv++;
						nb_oldpids++;
					}
				}
			}
			else { /* >=2 args */
				argv++; argc--;
				if (argc == 0)
					usage(old_argv);

				switch (*flag) {
				case 'n' : cfg_maxconn = atol(*argv); break;
				case 'm' : global.rlimit_memmax = atol(*argv); break;
				case 'N' : cfg_maxpconn = atol(*argv); break;
				case 'f' : cfg_cfgfile = *argv; break;
				case 'p' : cfg_pidfile = *argv; break;
				default: usage(old_argv);
				}
			}
		}
		else
			usage(old_argv);
		argv++; argc--;
	}

	global.mode = MODE_STARTING | /* during startup, we want most of the alerts */
		(arg_mode & (MODE_DAEMON | MODE_FOREGROUND | MODE_VERBOSE
			     | MODE_QUIET | MODE_CHECK | MODE_DEBUG));

	if (!cfg_cfgfile)
		usage(old_argv);

	gethostname(hostname, MAX_HOSTNAME_LEN);

	have_appsession = 0;
	global.maxsock = 10; /* reserve 10 fds ; will be incremented by socket eaters */
	if (readcfgfile(cfg_cfgfile) < 0) {
		Alert("Error reading configuration file : %s\n", cfg_cfgfile);
		exit(1);
	}

	if (have_appsession)
		appsession_init();

	if (global.mode & MODE_CHECK) {
		qfprintf(stdout, "Configuration file is valid : %s\n", cfg_cfgfile);
		exit(0);
	}

	if (start_checks() < 0)
		exit(1);

	if (cfg_maxconn > 0)
		global.maxconn = cfg_maxconn;

	if (cfg_pidfile) {
		free(global.pidfile);
		global.pidfile = strdup(cfg_pidfile);
	}

	if (global.maxconn == 0)
		global.maxconn = DEFAULT_MAXCONN;

	if (!global.maxpipes) {
		/* maxpipes not specified. Count how many frontends and backends
		 * may be using splicing, and bound that to maxconn.
		 */
		struct proxy *cur;
		int nbfe = 0, nbbe = 0;

		for (cur = proxy; cur; cur = cur->next) {
			if (cur->options2 & (PR_O2_SPLIC_ANY)) {
				if (cur->cap & PR_CAP_FE)
					nbfe += cur->maxconn;
				if (cur->cap & PR_CAP_BE)
					nbbe += cur->fullconn ? cur->fullconn : global.maxconn;
			}
		}
		global.maxpipes = MAX(nbfe, nbbe);
		if (global.maxpipes > global.maxconn)
			global.maxpipes = global.maxconn;
		global.maxpipes /= 4;
	}


	global.maxsock += global.maxconn * 2; /* each connection needs two sockets */
	global.maxsock += global.maxpipes * 2; /* each pipe needs two FDs */

	if (global.tune.maxpollevents <= 0)
		global.tune.maxpollevents = MAX_POLL_EVENTS;

	if (global.tune.maxaccept == 0) {
		if (global.nbproc > 1)
			global.tune.maxaccept = 8;  /* leave some conns to other processes */
		else
			global.tune.maxaccept = 100; /* accept many incoming conns at once */
	}

	if (global.tune.recv_enough == 0)
		global.tune.recv_enough = MIN_RECV_AT_ONCE_ENOUGH;

	if (arg_mode & (MODE_DEBUG | MODE_FOREGROUND)) {
		/* command line debug mode inhibits configuration mode */
		global.mode &= ~(MODE_DAEMON | MODE_QUIET);
	}
	global.mode |= (arg_mode & (MODE_DAEMON | MODE_FOREGROUND | MODE_QUIET |
				    MODE_VERBOSE | MODE_DEBUG ));

	if ((global.mode & MODE_DEBUG) && (global.mode & (MODE_DAEMON | MODE_QUIET))) {
		Warning("<debug> mode incompatible with <quiet> and <daemon>. Keeping <debug> only.\n");
		global.mode &= ~(MODE_DAEMON | MODE_QUIET);
	}

	if ((global.nbproc > 1) && !(global.mode & MODE_DAEMON)) {
		if (!(global.mode & (MODE_FOREGROUND | MODE_DEBUG)))
			Warning("<nbproc> is only meaningful in daemon mode. Setting limit to 1 process.\n");
		global.nbproc = 1;
	}

	if (global.nbproc < 1)
		global.nbproc = 1;

	fdtab = (struct fdtab *)calloc(1,
				       sizeof(struct fdtab) * (global.maxsock));
	for (i = 0; i < global.maxsock; i++) {
		fdtab[i].state = FD_STCLOSE;
	}

	/*
	 * Note: we could register external pollers here.
	 * Built-in pollers have been registered before main().
	 */

	if (!(global.tune.options & GTUNE_USE_KQUEUE))
		disable_poller("kqueue");

	if (!(global.tune.options & GTUNE_USE_EPOLL))
		disable_poller("epoll");

	if (!(global.tune.options & GTUNE_USE_SEPOLL))
		disable_poller("sepoll");

	if (!(global.tune.options & GTUNE_USE_POLL))
		disable_poller("poll");

	if (!(global.tune.options & GTUNE_USE_SELECT))
		disable_poller("select");

	/* Note: we could disable any poller by name here */

	if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
		list_pollers(stderr);

	if (!init_pollers()) {
		Alert("No polling mechanism available.\n");
		exit(1);
	}
	if (global.mode & (MODE_VERBOSE|MODE_DEBUG)) {
		printf("Using %s() as the polling mechanism.\n", cur_poller.name);
	}

}

void deinit(void)
{
	struct proxy *p = proxy, *p0;
	struct cap_hdr *h,*h_next;
	struct server *s,*s_next;
	struct listener *l,*l_next;
	struct acl_cond *cond, *condb;
	struct hdr_exp *exp, *expb;
	struct acl *acl, *aclb;
	struct switching_rule *rule, *ruleb;
	struct redirect_rule *rdr, *rdrb;
	struct uri_auth *uap, *ua = NULL;
	struct user_auth *user;
	int i;

	while (p) {
		free(p->id);
		free(p->check_req);
		free(p->cookie_name);
		free(p->cookie_domain);
		free(p->url_param_name);
		free(p->capture_name);
		free(p->monitor_uri);

		for (i = 0; i < HTTP_ERR_SIZE; i++)
			free(p->errmsg[i].str);

		for (i = 0; i < p->nb_reqadd; i++)
			free(p->req_add[i]);

		for (i = 0; i < p->nb_rspadd; i++)
			free(p->rsp_add[i]);

		list_for_each_entry_safe(cond, condb, &p->block_cond, list) {
			LIST_DEL(&cond->list);
			prune_acl_cond(cond);
			free(cond);
		}

		list_for_each_entry_safe(cond, condb, &p->mon_fail_cond, list) {
			LIST_DEL(&cond->list);
			prune_acl_cond(cond);
			free(cond);
		}

		for (exp = p->req_exp; exp != NULL; ) {
			if (exp->preg) {
				regfree((regex_t *)exp->preg);
				free((regex_t *)exp->preg);
			}

			if (exp->replace && exp->action != ACT_SETBE)
				free((char *)exp->replace);
			expb = exp;
			exp = exp->next;
			free(expb);
		}

		for (exp = p->rsp_exp; exp != NULL; ) {
			if (exp->preg) {
				regfree((regex_t *)exp->preg);
				free((regex_t *)exp->preg);
			}

			if (exp->replace && exp->action != ACT_SETBE)
				free((char *)exp->replace);
			expb = exp;
			exp = exp->next;
			free(expb);
		}

		/* build a list of unique uri_auths */
		if (!ua)
			ua = p->uri_auth;
		else {
			/* check if p->uri_auth is unique */
			for (uap = ua; uap; uap=uap->next)
				if (uap == p->uri_auth)
					break;

			if (!uap && p->uri_auth) {
				/* add it, if it is */
				p->uri_auth->next = ua;
				ua = p->uri_auth;
			}
		}

		list_for_each_entry_safe(acl, aclb, &p->acl, list) {
			LIST_DEL(&acl->list);
			prune_acl(acl);
			free(acl);
		}

		list_for_each_entry_safe(rule, ruleb, &p->switching_rules, list) {
			LIST_DEL(&rule->list);
			prune_acl_cond(rule->cond);
			free(rule->cond);
			free(rule);
		}

		list_for_each_entry_safe(rdr, rdrb, &p->redirect_rules, list) {
			LIST_DEL(&rdr->list);
			prune_acl_cond(rdr->cond);
			free(rdr->cond);
			free(rdr->rdr_str);
			free(rdr);
		}

		free(p->appsession_name);

		h = p->req_cap;
		while (h) {
			h_next = h->next;
			free(h->name);
			pool_destroy2(h->pool);
			free(h);
			h = h_next;
		}/* end while(h) */

		h = p->rsp_cap;
		while (h) {
			h_next = h->next;
			free(h->name);
			pool_destroy2(h->pool);
			free(h);
			h = h_next;
		}/* end while(h) */

		s = p->srv;
		while (s) {
			s_next = s->next;

			if (s->check) {
				task_delete(s->check);
				task_free(s->check);
			}

			free(s->id);
			free(s->cookie);
			free(s);
			s = s_next;
		}/* end while(s) */

		l = p->listen;
		while (l) {
			l_next = l->next;
			free(l);
			l = l_next;
		}/* end while(l) */

		pool_destroy2(p->req_cap_pool);
		pool_destroy2(p->rsp_cap_pool);
		pool_destroy2(p->hdr_idx_pool);
		p0 = p;
		p = p->next;
		free(p0);
	}/* end while(p) */

	while (ua) {
		uap = ua;
		ua = ua->next;

		free(uap->uri_prefix);
		free(uap->auth_realm);

		while (uap->users) {
			user = uap->users;
			uap->users = uap->users->next;
			free(user->user_pwd);
			free(user);
		}
		free(uap);
	}

	protocol_unbind_all();

	free(global.chroot);  global.chroot = NULL;
	free(global.pidfile); global.pidfile = NULL;
	free(fdtab);          fdtab   = NULL;
	free(oldpids);        oldpids = NULL;

	pool_destroy2(pool2_session);
	pool_destroy2(pool2_buffer);
	pool_destroy2(pool2_requri);
	pool_destroy2(pool2_task);
	pool_destroy2(pool2_capture);
	pool_destroy2(pool2_appsess);
	pool_destroy2(pool2_pendconn);
    
	if (have_appsession) {
		pool_destroy2(apools.serverid);
		pool_destroy2(apools.sessid);
	}

	deinit_pollers();

} /* end deinit() */

/* sends the signal <sig> to all pids found in <oldpids> */
static void tell_old_pids(int sig)
{
	int p;
	for (p = 0; p < nb_oldpids; p++)
		kill(oldpids[p], sig);
}

/*
 * Runs the polling loop
 *
 * FIXME:
 * - we still use 'listeners' to check whether we want to stop or not.
 *
 */
void run_poll_loop()
{
	int next;

	tv_update_date(0,1);
	while (1) {
		/* check if we caught some signals and process them */
		signal_process_queue();

		/* Check if we can expire some tasks */
		wake_expired_tasks(&next);

		/* Process a few tasks */
		process_runnable_tasks(&next);

		/* maintain all proxies in a consistent state. This should quickly
		 * become a task because it becomes expensive when there are huge
		 * numbers of proxies. */
		maintain_proxies(&next);

		/* stop when there's no connection left and we don't allow them anymore */
		if (!actconn && listeners == 0)
			break;

		/* The poller will ensure it returns around <next> */
		cur_poller.poll(&cur_poller, next);
	}
}


int main(int argc, char **argv)
{
	int err, retry;
	struct rlimit limit;
	FILE *pidfile = NULL;
	init(argc, argv);

	signal(SIGQUIT, dump);
	signal(SIGUSR1, sig_soft_stop);
	signal(SIGHUP, sig_dump_state);
#ifdef DEBUG_MEMORY
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_term);
#endif

	/* on very high loads, a sigpipe sometimes happen just between the
	 * getsockopt() which tells "it's OK to write", and the following write :-(
	 */
#if !defined(MSG_NOSIGNAL) || defined(CONFIG_HAP_LINUX_SPLICE)
	signal(SIGPIPE, SIG_IGN);
#endif

	/* We will loop at most 100 times with 10 ms delay each time.
	 * That's at most 1 second. We only send a signal to old pids
	 * if we cannot grab at least one port.
	 */
	retry = MAX_START_RETRIES;
	err = ERR_NONE;
	while (retry >= 0) {
		struct timeval w;
		err = start_proxies(retry == 0 || nb_oldpids == 0);
		/* exit the loop on no error or fatal error */
		if ((err & (ERR_RETRYABLE|ERR_FATAL)) != ERR_RETRYABLE)
			break;
		if (nb_oldpids == 0)
			break;

		/* FIXME-20060514: Solaris and OpenBSD do not support shutdown() on
		 * listening sockets. So on those platforms, it would be wiser to
		 * simply send SIGUSR1, which will not be undoable.
		 */
		tell_old_pids(SIGTTOU);
		/* give some time to old processes to stop listening */
		w.tv_sec = 0;
		w.tv_usec = 10*1000;
		select(0, NULL, NULL, NULL, &w);
		retry--;
	}

	/* Note: start_proxies() sends an alert when it fails. */
	if ((err & ~ERR_WARN) != ERR_NONE) {
		if (retry != MAX_START_RETRIES && nb_oldpids)
			tell_old_pids(SIGTTIN);
		exit(1);
	}

	if (listeners == 0) {
		Alert("[%s.main()] No enabled listener found (check the <listen> keywords) ! Exiting.\n", argv[0]);
		/* Note: we don't have to send anything to the old pids because we
		 * never stopped them. */
		exit(1);
	}

	if ((protocol_bind_all() & ~ERR_WARN) != ERR_NONE) {
		Alert("[%s.main()] Some protocols failed to start their listeners! Exiting.\n", argv[0]);
		protocol_unbind_all(); /* cleanup everything we can */
		if (nb_oldpids)
			tell_old_pids(SIGTTIN);
		exit(1);
	}

	/* prepare pause/play signals */
	signal(SIGTTOU, sig_pause);
	signal(SIGTTIN, sig_listen);

	/* MODE_QUIET can inhibit alerts and warnings below this line */

	global.mode &= ~MODE_STARTING;
	if ((global.mode & MODE_QUIET) && !(global.mode & MODE_VERBOSE)) {
		/* detach from the tty */
		fclose(stdin); fclose(stdout); fclose(stderr);
		close(0); close(1); close(2);
	}

	/* open log & pid files before the chroot */
	if (global.mode & MODE_DAEMON && global.pidfile != NULL) {
		int pidfd;
		unlink(global.pidfile);
		pidfd = open(global.pidfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (pidfd < 0) {
			Alert("[%s.main()] Cannot create pidfile %s\n", argv[0], global.pidfile);
			if (nb_oldpids)
				tell_old_pids(SIGTTIN);
			protocol_unbind_all();
			exit(1);
		}
		pidfile = fdopen(pidfd, "w");
	}

	/* ulimits */
	if (!global.rlimit_nofile)
		global.rlimit_nofile = global.maxsock;

	if (global.rlimit_nofile) {
		limit.rlim_cur = limit.rlim_max = global.rlimit_nofile;
		if (setrlimit(RLIMIT_NOFILE, &limit) == -1) {
			Warning("[%s.main()] Cannot raise FD limit to %d.\n", argv[0], global.rlimit_nofile);
		}
	}

	if (global.rlimit_memmax) {
		limit.rlim_cur = limit.rlim_max =
			global.rlimit_memmax * 1048576 / global.nbproc;
#ifdef RLIMIT_AS
		if (setrlimit(RLIMIT_AS, &limit) == -1) {
			Warning("[%s.main()] Cannot fix MEM limit to %d megs.\n",
				argv[0], global.rlimit_memmax);
		}
#else
		if (setrlimit(RLIMIT_DATA, &limit) == -1) {
			Warning("[%s.main()] Cannot fix MEM limit to %d megs.\n",
				argv[0], global.rlimit_memmax);
		}
#endif
	}

#ifdef CONFIG_HAP_TCPSPLICE
	if ((global.tune.options & GTUNE_USE_SPLICE) && (global.last_checks & LSTCHK_TCPSPLICE)) {
		if (tcp_splice_start() < 0) {
			Alert("[%s.main()] Cannot enable tcp_splice.\n"
			      "  Make sure you have enough permissions and that the module is loadable.\n"
			      "  Alternatively, you may disable the 'tcpsplice' options in the configuration\n"
			      "  or add 'nosplice' in the global section, or start with '-dS'.\n"
			      "", argv[0], global.gid);
			protocol_unbind_all();
			exit(1);
		}
	}
#endif

#ifdef CONFIG_HAP_CTTPROXY
	if (global.last_checks & LSTCHK_CTTPROXY) {
		int ret;

		ret = check_cttproxy_version();
		if (ret < 0) {
			Alert("[%s.main()] Cannot enable cttproxy.\n%s",
			      argv[0],
			      (ret == -1) ? "  Incorrect module version.\n"
			      : "  Make sure you have enough permissions and that the module is loaded.\n");
			protocol_unbind_all();
			exit(1);
		}
	}
#endif

	if ((global.last_checks & LSTCHK_NETADM) && global.uid) {
		Alert("[%s.main()] Some configuration options require full privileges, so global.uid cannot be changed.\n"
		      "", argv[0]);
		protocol_unbind_all();
		exit(1);
	}

	/* If the user is not root, we'll still let him try the configuration
	 * but we inform him that unexpected behaviour may occur.
	 */
	if ((global.last_checks & LSTCHK_NETADM) && getuid())
		Warning("[%s.main()] Some options which require full privileges"
			" might not work well.\n"
			"", argv[0]);

	/* chroot if needed */
	if (global.chroot != NULL) {
		if (chroot(global.chroot) == -1) {
			Alert("[%s.main()] Cannot chroot(%s).\n", argv[0], global.chroot);
			if (nb_oldpids)
				tell_old_pids(SIGTTIN);
			protocol_unbind_all();
			exit(1);
		}
		chdir("/");
	}

	if (nb_oldpids)
		tell_old_pids(oldpids_sig);

	/* Note that any error at this stage will be fatal because we will not
	 * be able to restart the old pids.
	 */

	/* setgid / setuid */
	if (global.gid && setgid(global.gid) == -1) {
		Alert("[%s.main()] Cannot set gid %d.\n", argv[0], global.gid);
		protocol_unbind_all();
		exit(1);
	}

	if (global.uid && setuid(global.uid) == -1) {
		Alert("[%s.main()] Cannot set uid %d.\n", argv[0], global.uid);
		protocol_unbind_all();
		exit(1);
	}

	/* check ulimits */
	limit.rlim_cur = limit.rlim_max = 0;
	getrlimit(RLIMIT_NOFILE, &limit);
	if (limit.rlim_cur < global.maxsock) {
		Warning("[%s.main()] FD limit (%d) too low for maxconn=%d/maxsock=%d. Please raise 'ulimit-n' to %d or more to avoid any trouble.\n",
			argv[0], (int)limit.rlim_cur, global.maxconn, global.maxsock, global.maxsock);
	}

	if (global.mode & MODE_DAEMON) {
		struct proxy *px;
		int ret = 0;
		int proc;

		/* the father launches the required number of processes */
		for (proc = 0; proc < global.nbproc; proc++) {
			ret = fork();
			if (ret < 0) {
				Alert("[%s.main()] Cannot fork.\n", argv[0]);
				protocol_unbind_all();
				exit(1); /* there has been an error */
			}
			else if (ret == 0) /* child breaks here */
				break;
			if (pidfile != NULL) {
				fprintf(pidfile, "%d\n", ret);
				fflush(pidfile);
			}
			relative_pid++; /* each child will get a different one */
		}
		/* close the pidfile both in children and father */
		if (pidfile != NULL)
			fclose(pidfile);
		free(global.pidfile);
		global.pidfile = NULL;

		/* we might have to unbind some proxies from some processes */
		px = proxy;
		while (px != NULL) {
			if (px->bind_proc && px->state != PR_STSTOPPED) {
				if (!(px->bind_proc & (1 << proc)))
					stop_proxy(px);
			}
			px = px->next;
		}

		if (proc == global.nbproc)
			exit(0); /* parent must leave */

		/* if we're NOT in QUIET mode, we should now close the 3 first FDs to ensure
		 * that we can detach from the TTY. We MUST NOT do it in other cases since
		 * it would have already be done, and 0-2 would have been affected to listening
		 * sockets
		 */
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
			/* detach from the tty */
			fclose(stdin); fclose(stdout); fclose(stderr);
			close(0); close(1); close(2); /* close all fd's */
			global.mode &= ~MODE_VERBOSE;
			global.mode |= MODE_QUIET; /* ensure that we won't say anything from now */
		}
		pid = getpid(); /* update child's pid */
		setsid();
		fork_poller();
	}

	protocol_enable_all();
	/*
	 * That's it : the central polling loop. Run until we stop.
	 */
	run_poll_loop();

	/* Free all Hash Keys and all Hash elements */
	appsession_cleanup();
	/* Do some cleanup */ 
	deinit();
    
	exit(0);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
