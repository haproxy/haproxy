/*
 * HA-Proxy : High Availability-enabled HTTP/TCP proxy
 * Copyright 2000-2016  Willy Tarreau <w@1wt.eu>.
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
 */

#define _GNU_SOURCE
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
#include <sys/wait.h>
#include <time.h>
#include <syslog.h>
#include <grp.h>
#ifdef USE_CPU_AFFINITY
#include <sched.h>
#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
#endif
#endif

#ifdef DEBUG_FULL
#include <assert.h>
#endif

#include <common/base64.h>
#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/defaults.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/namespace.h>
#include <common/regex.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/compression.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/acl.h>
#include <types/peers.h>

#include <proto/acl.h>
#include <proto/applet.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/filters.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/protocol.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/signal.h>
#include <proto/task.h>
#include <proto/dns.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif

#ifdef USE_DEVICEATLAS
#include <import/da.h>
#endif

#ifdef USE_51DEGREES
#include <import/51d.h>
#endif

/*********************************************************************/

extern const struct comp_algo comp_algos[];

/*********************************************************************/

/* list of config files */
static struct list cfg_cfgfiles = LIST_HEAD_INIT(cfg_cfgfiles);
int  pid;			/* current process id */
int  relative_pid = 1;		/* process id starting at 1 */

/* global options */
struct global global = {
	.nbproc = 1,
	.req_count = 0,
	.logsrvs = LIST_HEAD_INIT(global.logsrvs),
#if defined(USE_ZLIB) && defined(DEFAULT_MAXZLIBMEM)
	.maxzlibmem = DEFAULT_MAXZLIBMEM * 1024U * 1024U,
#else
	.maxzlibmem = 0,
#endif
	.comp_rate_lim = 0,
	.ssl_server_verify = SSL_SERVER_VERIFY_REQUIRED,
	.unix_bind = {
		 .ux = {
			 .uid = -1,
			 .gid = -1,
			 .mode = 0,
		 }
	},
	.tune = {
		.bufsize = BUFSIZE,
		.maxrewrite = -1,
		.chksize = BUFSIZE,
		.reserved_bufs = RESERVED_BUFS,
		.pattern_cache = DEFAULT_PAT_LRU_SIZE,
#ifdef USE_OPENSSL
		.sslcachesize = SSLCACHESIZE,
		.ssl_default_dh_param = SSL_DEFAULT_DH_PARAM,
#ifdef DEFAULT_SSL_MAX_RECORD
		.ssl_max_record = DEFAULT_SSL_MAX_RECORD,
#endif
		.ssl_ctx_cache = DEFAULT_SSL_CTX_CACHE,
#endif
#ifdef USE_ZLIB
		.zlibmemlevel = 8,
		.zlibwindowsize = MAX_WBITS,
#endif
		.comp_maxlevel = 1,
#ifdef DEFAULT_IDLE_TIMER
		.idle_timer = DEFAULT_IDLE_TIMER,
#else
		.idle_timer = 1000, /* 1 second */
#endif
	},
#ifdef USE_OPENSSL
#ifdef DEFAULT_MAXSSLCONN
	.maxsslconn = DEFAULT_MAXSSLCONN,
#endif
#endif
#ifdef USE_DEVICEATLAS
	.deviceatlas = {
		.loglevel = 0,
		.jsonpath = 0,
		.cookiename = 0,
		.cookienamelen = 0,
		.useragentid = 0,
		.daset = 0,
		.separator = '|',
	},
#endif
#ifdef USE_51DEGREES
	._51degrees = {
		.property_separator = ',',
		.property_names = LIST_HEAD_INIT(global._51degrees.property_names),
		.data_file_path = NULL,
#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
		.data_set = { },
#endif
		.cache_size = 0,
	},
#endif
	/* others NULL OK */
};

/*********************************************************************/

int stopping;	/* non zero means stopping in progress */
int jobs = 0;   /* number of active jobs (conns, listeners, active tasks, ...) */

/* Here we store informations about the pids of the processes we may pause
 * or kill. We will send them a signal every 10 ms until we can bind to all
 * our ports. With 200 retries, that's about 2 seconds.
 */
#define MAX_START_RETRIES	200
static int *oldpids = NULL;
static int oldpids_sig; /* use USR1 or TERM */

/* this is used to drain data, and as a temporary buffer for sprintf()... */
struct chunk trash = { };

/* this buffer is always the same size as standard buffers and is used for
 * swapping data inside a buffer.
 */
char *swap_buffer = NULL;

int nb_oldpids = 0;
const int zero = 0;
const int one = 1;
const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };

char hostname[MAX_HOSTNAME_LEN];
char localpeer[MAX_HOSTNAME_LEN];

/* used from everywhere just to drain results we don't want to read and which
 * recent versions of gcc increasingly and annoyingly complain about.
 */
int shut_your_big_mouth_gcc_int = 0;

/* list of the temporarily limited listeners because of lack of resource */
struct list global_listener_queue = LIST_HEAD_INIT(global_listener_queue);
struct task *global_listener_queue_task;
static struct task *manage_global_listener_queue(struct task *t);

/* bitfield of a few warnings to emit just once (WARN_*) */
unsigned int warned = 0;

/*********************************************************************/
/*  general purpose functions  ***************************************/
/*********************************************************************/

void display_version()
{
	printf("HA-Proxy version " HAPROXY_VERSION " " HAPROXY_DATE"\n");
	printf("Copyright 2000-2016 Willy Tarreau <willy@haproxy.org>\n\n");
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
	       "\n\nDefault settings :"
	       "\n  maxconn = %d, bufsize = %d, maxrewrite = %d, maxpollevents = %d"
	       "\n\n",
	       DEFAULT_MAXCONN, BUFSIZE, MAXREWRITE, MAX_POLL_EVENTS);

	printf("Encrypted password support via crypt(3): "
#ifdef CONFIG_HAP_CRYPT
		"yes"
#else
		"no"
#endif
		"\n");

#ifdef USE_ZLIB
	printf("Built with zlib version : " ZLIB_VERSION "\n");
#elif defined(USE_SLZ)
	printf("Built with libslz for stateless compression.\n");
#else /* USE_ZLIB */
	printf("Built without compression support (neither USE_ZLIB nor USE_SLZ are set)\n");
#endif
	printf("Compression algorithms supported :");
	{
		int i;

		for (i = 0; comp_algos[i].cfg_name; i++) {
			printf("%s %s(\"%s\")", (i == 0 ? "" : ","), comp_algos[i].cfg_name, comp_algos[i].ua_name);
		}
		if (i == 0) {
			printf("none");
		}
	}
	printf("\n");

#ifdef USE_OPENSSL
	printf("Built with OpenSSL version : "
#ifdef OPENSSL_IS_BORINGSSL
	       "BoringSSL\n");
#else /* OPENSSL_IS_BORINGSSL */
	        OPENSSL_VERSION_TEXT "\n");
	printf("Running on OpenSSL version : %s%s\n",
	       SSLeay_version(SSLEAY_VERSION),
	       ((OPENSSL_VERSION_NUMBER ^ SSLeay()) >> 8) ? " (VERSIONS DIFFER!)" : "");
#endif
	printf("OpenSSL library supports TLS extensions : "
#if OPENSSL_VERSION_NUMBER < 0x00907000L
	       "no (library version too old)"
#elif defined(OPENSSL_NO_TLSEXT)
	       "no (disabled via OPENSSL_NO_TLSEXT)"
#else
	       "yes"
#endif
	       "\n");
	printf("OpenSSL library supports SNI : "
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	       "yes"
#else
#ifdef OPENSSL_NO_TLSEXT
	       "no (because of OPENSSL_NO_TLSEXT)"
#else
	       "no (version might be too old, 0.9.8f min needed)"
#endif
#endif
	       "\n");
	printf("OpenSSL library supports prefer-server-ciphers : "
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
	       "yes"
#else
	       "no (0.9.7 or later needed)"
#endif
	       "\n");
#else /* USE_OPENSSL */
	printf("Built without OpenSSL support (USE_OPENSSL not set)\n");
#endif

#ifdef USE_PCRE
	printf("Built with PCRE version : %s", pcre_version());
	printf("\nPCRE library supports JIT : ");
#ifdef USE_PCRE_JIT
	{
		int r;
		pcre_config(PCRE_CONFIG_JIT, &r);
		if (r)
			printf("yes");
		else
			printf("no (libpcre build without JIT?)");
	}
#else
	printf("no (USE_PCRE_JIT not set)");
#endif
	printf("\n");
#else
	printf("Built without PCRE support (using libc's regex instead)\n");
#endif

#ifdef USE_LUA
	printf("Built with Lua version : %s\n", LUA_RELEASE);
#else
	printf("Built without Lua support\n");
#endif

#if defined(CONFIG_HAP_TRANSPARENT)
	printf("Built with transparent proxy support using:"
#if defined(IP_TRANSPARENT)
	       " IP_TRANSPARENT"
#endif
#if defined(IPV6_TRANSPARENT)
	       " IPV6_TRANSPARENT"
#endif
#if defined(IP_FREEBIND)
	       " IP_FREEBIND"
#endif
#if defined(IP_BINDANY)
	       " IP_BINDANY"
#endif
#if defined(IPV6_BINDANY)
	       " IPV6_BINDANY"
#endif
#if defined(SO_BINDANY)
	       " SO_BINDANY"
#endif
	       "\n");
#endif

#if defined(CONFIG_HAP_NS)
	printf("Built with network namespace support\n");
#endif

#ifdef USE_DEVICEATLAS
    printf("Built with DeviceAtlas support\n");
#endif
#ifdef USE_51DEGREES
	printf("Built with 51Degrees support\n");
#endif
	putchar('\n');

	list_pollers(stdout);
	putchar('\n');
}

/*
 * This function prints the command line usage and exits
 */
void usage(char *name)
{
	display_version();
	fprintf(stderr,
		"Usage : %s [-f <cfgfile>]* [ -vdV"
		"D ] [ -n <maxconn> ] [ -N <maxpconn> ]\n"
		"        [ -p <pidfile> ] [ -m <max megs> ] [ -C <dir> ] [-- <cfgfile>*]\n"
		"        -v displays version ; -vv shows known build options.\n"
		"        -d enters debug mode ; -db only disables background mode.\n"
		"        -dM[<byte>] poisons memory with <byte> (defaults to 0x50)\n"
		"        -V enters verbose mode (disables quiet mode)\n"
		"        -D goes daemon ; -C changes to <dir> before loading files.\n"
		"        -q quiet mode : don't display messages\n"
		"        -c check mode : only check config files and exit\n"
		"        -n sets the maximum total # of connections (%d)\n"
		"        -m limits the usable amount of memory (in MB)\n"
		"        -N sets the default, per-proxy maximum # of connections (%d)\n"
		"        -L set local peer name (default to hostname)\n"
		"        -p writes pids of all children to this file\n"
#if defined(ENABLE_EPOLL)
		"        -de disables epoll() usage even when available\n"
#endif
#if defined(ENABLE_KQUEUE)
		"        -dk disables kqueue() usage even when available\n"
#endif
#if defined(ENABLE_POLL)
		"        -dp disables poll() usage even when available\n"
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE)
		"        -dS disables splice usage (broken on old kernels)\n"
#endif
#if defined(USE_GETADDRINFO)
		"        -dG disables getaddrinfo() usage\n"
#endif
		"        -dV disables SSL verify on servers side\n"
		"        -sf/-st [pid ]* finishes/terminates old pids.\n"
		"\n",
		name, DEFAULT_MAXCONN, cfg_maxpconn);
	exit(1);
}



/*********************************************************************/
/*   more specific functions   ***************************************/
/*********************************************************************/

/*
 * upon SIGUSR1, let's have a soft stop. Note that soft_stop() broadcasts
 * a signal zero to all subscribers. This means that it's as easy as
 * subscribing to signal 0 to get informed about an imminent shutdown.
 */
void sig_soft_stop(struct sig_handler *sh)
{
	soft_stop();
	signal_unregister_handler(sh);
	pool_gc2();
}

/*
 * upon SIGTTOU, we pause everything
 */
void sig_pause(struct sig_handler *sh)
{
	pause_proxies();
	pool_gc2();
}

/*
 * upon SIGTTIN, let's have a soft stop.
 */
void sig_listen(struct sig_handler *sh)
{
	resume_proxies();
}

/*
 * this function dumps every server's state when the process receives SIGHUP.
 */
void sig_dump_state(struct sig_handler *sh)
{
	struct proxy *p = proxy;

	Warning("SIGHUP received, dumping servers states.\n");
	while (p) {
		struct server *s = p->srv;

		send_log(p, LOG_NOTICE, "SIGHUP received, dumping servers states for proxy %s.\n", p->id);
		while (s) {
			chunk_printf(&trash,
			             "SIGHUP: Server %s/%s is %s. Conn: %d act, %d pend, %lld tot.",
			             p->id, s->id,
			             (s->state != SRV_ST_STOPPED) ? "UP" : "DOWN",
			             s->cur_sess, s->nbpend, s->counters.cum_sess);
			Warning("%s\n", trash.str);
			send_log(p, LOG_NOTICE, "%s\n", trash.str);
			s = s->next;
		}

		/* FIXME: those info are a bit outdated. We should be able to distinguish between FE and BE. */
		if (!p->srv) {
			chunk_printf(&trash,
			             "SIGHUP: Proxy %s has no servers. Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
			             p->id,
			             p->feconn, p->beconn, p->totpend, p->nbpend, p->fe_counters.cum_conn, p->be_counters.cum_conn);
		} else if (p->srv_act == 0) {
			chunk_printf(&trash,
			             "SIGHUP: Proxy %s %s ! Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
			             p->id,
			             (p->srv_bck) ? "is running on backup servers" : "has no server available",
			             p->feconn, p->beconn, p->totpend, p->nbpend, p->fe_counters.cum_conn, p->be_counters.cum_conn);
		} else {
			chunk_printf(&trash,
			             "SIGHUP: Proxy %s has %d active servers and %d backup servers available."
			             " Conn: act(FE+BE): %d+%d, %d pend (%d unass), tot(FE+BE): %lld+%lld.",
			             p->id, p->srv_act, p->srv_bck,
			             p->feconn, p->beconn, p->totpend, p->nbpend, p->fe_counters.cum_conn, p->be_counters.cum_conn);
		}
		Warning("%s\n", trash.str);
		send_log(p, LOG_NOTICE, "%s\n", trash.str);

		p = p->next;
	}
}

void dump(struct sig_handler *sh)
{
	/* dump memory usage then free everything possible */
	dump_pools();
	pool_gc2();
}

/*
 * This function initializes all the necessary variables. It only returns
 * if everything is OK. If something fails, it exits.
 */
void init(int argc, char **argv)
{
	int arg_mode = 0;	/* MODE_DEBUG, ... */
	char *tmp;
	char *cfg_pidfile = NULL;
	int err_code = 0;
	struct wordlist *wl;
	char *progname;
	char *change_dir = NULL;
	struct proxy *px;

	chunk_init(&trash, malloc(global.tune.bufsize), global.tune.bufsize);
	alloc_trash_buffers(global.tune.bufsize);

	/* NB: POSIX does not make it mandatory for gethostname() to NULL-terminate
	 * the string in case of truncation, and at least FreeBSD appears not to do
	 * it.
	 */
	memset(hostname, 0, sizeof(hostname));
	gethostname(hostname, sizeof(hostname) - 1);
	memset(localpeer, 0, sizeof(localpeer));
	memcpy(localpeer, hostname, (sizeof(hostname) > sizeof(localpeer) ? sizeof(localpeer) : sizeof(hostname)) - 1);

	/*
	 * Initialize the previously static variables.
	 */
    
	totalconn = actconn = maxfd = listeners = stopping = 0;
    

#ifdef HAPROXY_MEMMAX
	global.rlimit_memmax_all = HAPROXY_MEMMAX;
#endif

	tzset();
	tv_update_date(-1,-1);
	start_date = now;

	srandom(now_ms - getpid());

	init_log();
	signal_init();
	if (init_acl() != 0)
		exit(1);
	init_task();
	init_stream();
	init_session();
	init_connection();
	/* warning, we init buffers later */
	init_pendconn();
	init_proto_http();

	/* Initialise lua. */
	hlua_init();

	global.tune.options |= GTUNE_USE_SELECT;  /* select() is always available */
#if defined(ENABLE_POLL)
	global.tune.options |= GTUNE_USE_POLL;
#endif
#if defined(ENABLE_EPOLL)
	global.tune.options |= GTUNE_USE_EPOLL;
#endif
#if defined(ENABLE_KQUEUE)
	global.tune.options |= GTUNE_USE_KQUEUE;
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE)
	global.tune.options |= GTUNE_USE_SPLICE;
#endif
#if defined(USE_GETADDRINFO)
	global.tune.options |= GTUNE_USE_GAI;
#endif

	pid = getpid();
	progname = *argv;
	while ((tmp = strchr(progname, '/')) != NULL)
		progname = tmp + 1;

	/* the process name is used for the logs only */
	chunk_initstr(&global.log_tag, strdup(progname));

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
#if defined(ENABLE_POLL)
			else if (*flag == 'd' && flag[1] == 'p')
				global.tune.options &= ~GTUNE_USE_POLL;
#endif
#if defined(ENABLE_KQUEUE)
			else if (*flag == 'd' && flag[1] == 'k')
				global.tune.options &= ~GTUNE_USE_KQUEUE;
#endif
#if defined(CONFIG_HAP_LINUX_SPLICE)
			else if (*flag == 'd' && flag[1] == 'S')
				global.tune.options &= ~GTUNE_USE_SPLICE;
#endif
#if defined(USE_GETADDRINFO)
			else if (*flag == 'd' && flag[1] == 'G')
				global.tune.options &= ~GTUNE_USE_GAI;
#endif
			else if (*flag == 'd' && flag[1] == 'V')
				global.ssl_server_verify = SSL_SERVER_VERIFY_NONE;
			else if (*flag == 'V')
				arg_mode |= MODE_VERBOSE;
			else if (*flag == 'd' && flag[1] == 'b')
				arg_mode |= MODE_FOREGROUND;
			else if (*flag == 'd' && flag[1] == 'M')
				mem_poison_byte = flag[2] ? strtol(flag + 2, NULL, 0) : 'P';
			else if (*flag == 'd')
				arg_mode |= MODE_DEBUG;
			else if (*flag == 'c')
				arg_mode |= MODE_CHECK;
			else if (*flag == 'D') {
				arg_mode |= MODE_DAEMON;
				if (flag[1] == 's')  /* -Ds */
					arg_mode |= MODE_SYSTEMD;
			}
			else if (*flag == 'q')
				arg_mode |= MODE_QUIET;
			else if (*flag == 's' && (flag[1] == 'f' || flag[1] == 't')) {
				/* list of pids to finish ('f') or terminate ('t') */

				if (flag[1] == 'f')
					oldpids_sig = SIGUSR1; /* finish then exit */
				else
					oldpids_sig = SIGTERM; /* terminate immediately */

				while (argc > 1 && argv[1][0] != '-') {
					oldpids = realloc(oldpids, (nb_oldpids + 1) * sizeof(int));
					if (!oldpids) {
						Alert("Cannot allocate old pid : out of memory.\n");
						exit(1);
					}
					argc--; argv++;
					oldpids[nb_oldpids] = atol(*argv);
					if (oldpids[nb_oldpids] <= 0)
						usage(progname);
					nb_oldpids++;
				}
			}
			else if (flag[0] == '-' && flag[1] == 0) { /* "--" */
				/* now that's a cfgfile list */
				argv++; argc--;
				while (argc > 0) {
					wl = calloc(1, sizeof(*wl));
					if (!wl) {
						Alert("Cannot load configuration file %s : out of memory.\n", *argv);
						exit(1);
					}
					wl->s = *argv;
					LIST_ADDQ(&cfg_cfgfiles, &wl->list);
					argv++; argc--;
				}
				break;
			}
			else { /* >=2 args */
				argv++; argc--;
				if (argc == 0)
					usage(progname);

				switch (*flag) {
				case 'C' : change_dir = *argv; break;
				case 'n' : cfg_maxconn = atol(*argv); break;
				case 'm' : global.rlimit_memmax_all = atol(*argv); break;
				case 'N' : cfg_maxpconn = atol(*argv); break;
				case 'L' : strncpy(localpeer, *argv, sizeof(localpeer) - 1); break;
				case 'f' :
					wl = calloc(1, sizeof(*wl));
					if (!wl) {
						Alert("Cannot load configuration file %s : out of memory.\n", *argv);
						exit(1);
					}
					wl->s = *argv;
					LIST_ADDQ(&cfg_cfgfiles, &wl->list);
					break;
				case 'p' : cfg_pidfile = *argv; break;
				default: usage(progname);
				}
			}
		}
		else
			usage(progname);
		argv++; argc--;
	}

	global.mode = MODE_STARTING | /* during startup, we want most of the alerts */
		(arg_mode & (MODE_DAEMON | MODE_SYSTEMD | MODE_FOREGROUND | MODE_VERBOSE
			     | MODE_QUIET | MODE_CHECK | MODE_DEBUG));

	if (LIST_ISEMPTY(&cfg_cfgfiles))
		usage(progname);

	if (change_dir && chdir(change_dir) < 0) {
		Alert("Could not change to directory %s : %s\n", change_dir, strerror(errno));
		exit(1);
	}

	global.maxsock = 10; /* reserve 10 fds ; will be incremented by socket eaters */

	init_default_instance();

	list_for_each_entry(wl, &cfg_cfgfiles, list) {
		int ret;

		ret = readcfgfile(wl->s);
		if (ret == -1) {
			Alert("Could not open configuration file %s : %s\n",
			      wl->s, strerror(errno));
			exit(1);
		}
		if (ret & (ERR_ABORT|ERR_FATAL))
			Alert("Error(s) found in configuration file : %s\n", wl->s);
		err_code |= ret;
		if (err_code & ERR_ABORT)
			exit(1);
	}

	pattern_finalize_config();
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	tlskeys_finalize_config();
#endif

	err_code |= check_config_validity();
	if (err_code & (ERR_ABORT|ERR_FATAL)) {
		Alert("Fatal errors found in configuration.\n");
		exit(1);
	}

	/* recompute the amount of per-process memory depending on nbproc and
	 * the shared SSL cache size (allowed to exist in all processes).
	 */
	if (global.rlimit_memmax_all) {
#if defined (USE_OPENSSL) && !defined(USE_PRIVATE_CACHE)
		int64_t ssl_cache_bytes = global.tune.sslcachesize * 200LL;

		global.rlimit_memmax =
			((((int64_t)global.rlimit_memmax_all * 1048576LL) -
			  ssl_cache_bytes) / global.nbproc +
			 ssl_cache_bytes + 1048575LL) / 1048576LL;
#else
		global.rlimit_memmax = global.rlimit_memmax_all / global.nbproc;
#endif
	}

#ifdef CONFIG_HAP_NS
        err_code |= netns_init();
        if (err_code & (ERR_ABORT|ERR_FATAL)) {
                Alert("Failed to initialize namespace support.\n");
                exit(1);
        }
#endif

	if (global.mode & MODE_CHECK) {
		struct peers *pr;
		struct proxy *px;

		for (pr = peers; pr; pr = pr->next)
			if (pr->peers_fe)
				break;

		for (px = proxy; px; px = px->next)
			if (px->state == PR_STNEW && !LIST_ISEMPTY(&px->conf.listeners))
				break;

		if (pr || px) {
			/* At least one peer or one listener has been found */
			qfprintf(stdout, "Configuration file is valid\n");
			exit(0);
		}
		qfprintf(stdout, "Configuration file has no error but will not start (no listener) => exit(2).\n");
		exit(2);
	}

	/* Apply server states */
	apply_server_state();

	global_listener_queue_task = task_new();
	if (!global_listener_queue_task) {
		Alert("Out of memory when initializing global task\n");
		exit(1);
	}
	/* very simple initialization, users will queue the task if needed */
	global_listener_queue_task->context = NULL; /* not even a context! */
	global_listener_queue_task->process = manage_global_listener_queue;
	global_listener_queue_task->expire = TICK_ETERNITY;

	/* now we know the buffer size, we can initialize the channels and buffers */
	init_buffer();
#if defined(USE_DEVICEATLAS)
	init_deviceatlas();
#endif
#ifdef USE_51DEGREES
	init_51degrees();
#endif

	for (px = proxy; px; px = px->next) {
		err_code |= flt_init(px);
		if (err_code & (ERR_ABORT|ERR_FATAL)) {
			Alert("Failed to initialize filters for proxy '%s'.\n",
			      px->id);
			exit(1);
		}
	}

	if (start_checks() < 0)
		exit(1);

	if (cfg_maxconn > 0)
		global.maxconn = cfg_maxconn;

	if (cfg_pidfile) {
		free(global.pidfile);
		global.pidfile = strdup(cfg_pidfile);
	}

	/* Now we want to compute the maxconn and possibly maxsslconn values.
	 * It's a bit tricky. If memmax is not set, maxconn defaults to
	 * DEFAULT_MAXCONN and maxsslconn defaults to DEFAULT_MAXSSLCONN.
	 *
	 * If memmax is set, then it depends on which values are set. If
	 * maxsslconn is set, we use memmax to determine how many cleartext
	 * connections may be added, and set maxconn to the sum of the two.
	 * If maxconn is set and not maxsslconn, maxsslconn is computed from
	 * the remaining amount of memory between memmax and the cleartext
	 * connections. If neither are set, then it is considered that all
	 * connections are SSL-capable, and maxconn is computed based on this,
	 * then maxsslconn accordingly. We need to know if SSL is used on the
	 * frontends, backends, or both, because when it's used on both sides,
	 * we need twice the value for maxsslconn, but we only count the
	 * handshake once since it is not performed on the two sides at the
	 * same time (frontend-side is terminated before backend-side begins).
	 * The SSL stack is supposed to have filled ssl_session_cost and
	 * ssl_handshake_cost during its initialization. In any case, if
	 * SYSTEM_MAXCONN is set, we still enforce it as an upper limit for
	 * maxconn in order to protect the system.
	 */
	if (!global.rlimit_memmax) {
		if (global.maxconn == 0) {
			global.maxconn = DEFAULT_MAXCONN;
			if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
				fprintf(stderr, "Note: setting global.maxconn to %d.\n", global.maxconn);
		}
	}
#ifdef USE_OPENSSL
	else if (!global.maxconn && !global.maxsslconn &&
		 (global.ssl_used_frontend || global.ssl_used_backend)) {
		/* memmax is set, compute everything automatically. Here we want
		 * to ensure that all SSL connections will be served. We take
		 * care of the number of sides where SSL is used, and consider
		 * the worst case : SSL used on both sides and doing a handshake
		 * simultaneously. Note that we can't have more than maxconn
		 * handshakes at a time by definition, so for the worst case of
		 * two SSL conns per connection, we count a single handshake.
		 */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;

		mem -= global.tune.sslcachesize * 200; // about 200 bytes per SSL cache entry
		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		global.maxconn = mem /
			((STREAM_MAX_COST + 2 * global.tune.bufsize) +    // stream + 2 buffers per stream
			 sides * global.ssl_session_max_cost + // SSL buffers, one per side
			 global.ssl_handshake_max_cost);       // 1 handshake per connection max

		global.maxconn = round_2dig(global.maxconn);
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > DEFAULT_MAXCONN)
			global.maxconn = DEFAULT_MAXCONN;
#endif /* SYSTEM_MAXCONN */
		global.maxsslconn = sides * global.maxconn;
		if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
			fprintf(stderr, "Note: setting global.maxconn to %d and global.maxsslconn to %d.\n",
			        global.maxconn, global.maxsslconn);
	}
	else if (!global.maxsslconn &&
		 (global.ssl_used_frontend || global.ssl_used_backend)) {
		/* memmax and maxconn are known, compute maxsslconn automatically.
		 * maxsslconn being forced, we don't know how many of it will be
		 * on each side if both sides are being used. The worst case is
		 * when all connections use only one SSL instance because
		 * handshakes may be on two sides at the same time.
		 */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;
		int64_t sslmem;

		mem -= global.tune.sslcachesize * 200; // about 200 bytes per SSL cache entry
		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		sslmem = mem - global.maxconn * (int64_t)(STREAM_MAX_COST + 2 * global.tune.bufsize);
		global.maxsslconn = sslmem / (global.ssl_session_max_cost + global.ssl_handshake_max_cost);
		global.maxsslconn = round_2dig(global.maxsslconn);

		if (sslmem <= 0 || global.maxsslconn < sides) {
			Alert("Cannot compute the automatic maxsslconn because global.maxconn is already too "
			      "high for the global.memmax value (%d MB). The absolute maximum possible value "
			      "without SSL is %d, but %d was found and SSL is in use.\n",
			      global.rlimit_memmax,
			      (int)(mem / (STREAM_MAX_COST + 2 * global.tune.bufsize)),
			      global.maxconn);
			exit(1);
		}

		if (global.maxsslconn > sides * global.maxconn)
			global.maxsslconn = sides * global.maxconn;

		if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
			fprintf(stderr, "Note: setting global.maxsslconn to %d\n", global.maxsslconn);
	}
#endif
	else if (!global.maxconn) {
		/* memmax and maxsslconn are known/unused, compute maxconn automatically */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;
		int64_t clearmem;

		if (global.ssl_used_frontend || global.ssl_used_backend)
			mem -= global.tune.sslcachesize * 200; // about 200 bytes per SSL cache entry

		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		clearmem = mem;
		if (sides)
			clearmem -= (global.ssl_session_max_cost + global.ssl_handshake_max_cost) * (int64_t)global.maxsslconn;

		global.maxconn = clearmem / (STREAM_MAX_COST + 2 * global.tune.bufsize);
		global.maxconn = round_2dig(global.maxconn);
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > DEFAULT_MAXCONN)
			global.maxconn = DEFAULT_MAXCONN;
#endif /* SYSTEM_MAXCONN */

		if (clearmem <= 0 || !global.maxconn) {
			Alert("Cannot compute the automatic maxconn because global.maxsslconn is already too "
			      "high for the global.memmax value (%d MB). The absolute maximum possible value "
			      "is %d, but %d was found.\n",
			      global.rlimit_memmax,
			      (int)(mem / (global.ssl_session_max_cost + global.ssl_handshake_max_cost)),
			      global.maxsslconn);
			exit(1);
		}

		if (global.mode & (MODE_VERBOSE|MODE_DEBUG)) {
			if (sides && global.maxsslconn > sides * global.maxconn) {
				fprintf(stderr, "Note: global.maxsslconn is forced to %d which causes global.maxconn "
				        "to be limited to %d. Better reduce global.maxsslconn to get more "
				        "room for extra connections.\n", global.maxsslconn, global.maxconn);
			}
			fprintf(stderr, "Note: setting global.maxconn to %d\n", global.maxconn);
		}
	}

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


	global.hardmaxconn = global.maxconn;  /* keep this max value */
	global.maxsock += global.maxconn * 2; /* each connection needs two sockets */
	global.maxsock += global.maxpipes * 2; /* each pipe needs two FDs */

	if (global.stats_fe)
		global.maxsock += global.stats_fe->maxconn;

	if (peers) {
		/* peers also need to bypass global maxconn */
		struct peers *p = peers;

		for (p = peers; p; p = p->next)
			if (p->peers_fe)
				global.maxsock += p->peers_fe->maxconn;
	}

	if (global.tune.maxpollevents <= 0)
		global.tune.maxpollevents = MAX_POLL_EVENTS;

	if (global.tune.recv_enough == 0)
		global.tune.recv_enough = MIN_RECV_AT_ONCE_ENOUGH;

	if (global.tune.maxrewrite < 0)
		global.tune.maxrewrite = MAXREWRITE;

	if (global.tune.maxrewrite >= global.tune.bufsize / 2)
		global.tune.maxrewrite = global.tune.bufsize / 2;

	if (arg_mode & (MODE_DEBUG | MODE_FOREGROUND)) {
		/* command line debug mode inhibits configuration mode */
		global.mode &= ~(MODE_DAEMON | MODE_SYSTEMD | MODE_QUIET);
		global.mode |= (arg_mode & (MODE_DEBUG | MODE_FOREGROUND));
	}

	if (arg_mode & (MODE_DAEMON | MODE_SYSTEMD)) {
		/* command line daemon mode inhibits foreground and debug modes mode */
		global.mode &= ~(MODE_DEBUG | MODE_FOREGROUND);
		global.mode |= (arg_mode & (MODE_DAEMON | MODE_SYSTEMD));
	}

	global.mode |= (arg_mode & (MODE_QUIET | MODE_VERBOSE));

	if ((global.mode & MODE_DEBUG) && (global.mode & (MODE_DAEMON | MODE_SYSTEMD | MODE_QUIET))) {
		Warning("<debug> mode incompatible with <quiet>, <daemon> and <systemd>. Keeping <debug> only.\n");
		global.mode &= ~(MODE_DAEMON | MODE_SYSTEMD | MODE_QUIET);
	}

	if ((global.nbproc > 1) && !(global.mode & (MODE_DAEMON | MODE_SYSTEMD))) {
		if (!(global.mode & (MODE_FOREGROUND | MODE_DEBUG)))
			Warning("<nbproc> is only meaningful in daemon mode. Setting limit to 1 process.\n");
		global.nbproc = 1;
	}

	if (global.nbproc < 1)
		global.nbproc = 1;

	swap_buffer = calloc(1, global.tune.bufsize);
	get_http_auth_buff = calloc(1, global.tune.bufsize);
	static_table_key = calloc(1, sizeof(*static_table_key));

	fdinfo = calloc(1, sizeof(struct fdinfo) * (global.maxsock));
	fdtab = calloc(1, sizeof(struct fdtab) * (global.maxsock));
	/*
	 * Note: we could register external pollers here.
	 * Built-in pollers have been registered before main().
	 */

	if (!(global.tune.options & GTUNE_USE_KQUEUE))
		disable_poller("kqueue");

	if (!(global.tune.options & GTUNE_USE_EPOLL))
		disable_poller("epoll");

	if (!(global.tune.options & GTUNE_USE_POLL))
		disable_poller("poll");

	if (!(global.tune.options & GTUNE_USE_SELECT))
		disable_poller("select");

	/* Note: we could disable any poller by name here */

	if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
		list_pollers(stderr);

	if (!init_pollers()) {
		Alert("No polling mechanism available.\n"
		      "  It is likely that haproxy was built with TARGET=generic and that FD_SETSIZE\n"
		      "  is too low on this platform to support maxconn and the number of listeners\n"
		      "  and servers. You should rebuild haproxy specifying your system using TARGET=\n"
		      "  in order to support other polling systems (poll, epoll, kqueue) or reduce the\n"
		      "  global maxconn setting to accommodate the system's limitation. For reference,\n"
		      "  FD_SETSIZE=%d on this system, global.maxconn=%d resulting in a maximum of\n"
		      "  %d file descriptors. You should thus reduce global.maxconn by %d. Also,\n"
		      "  check build settings using 'haproxy -vv'.\n\n",
		      FD_SETSIZE, global.maxconn, global.maxsock, (global.maxsock + 1 - FD_SETSIZE) / 2);
		exit(1);
	}
	if (global.mode & (MODE_VERBOSE|MODE_DEBUG)) {
		printf("Using %s() as the polling mechanism.\n", cur_poller.name);
	}

	if (!global.node)
		global.node = strdup(hostname);

	if (!hlua_post_init())
		exit(1);

	/* initialize structures for name resolution */
	if (!dns_init_resolvers())
		exit(1);
}

static void deinit_acl_cond(struct acl_cond *cond)
{
	struct acl_term_suite *suite, *suiteb;
	struct acl_term *term, *termb;

	if (!cond)
		return;

	list_for_each_entry_safe(suite, suiteb, &cond->suites, list) {
		list_for_each_entry_safe(term, termb, &suite->terms, list) {
			LIST_DEL(&term->list);
			free(term);
		}
		LIST_DEL(&suite->list);
		free(suite);
	}

	free(cond);
}

static void deinit_tcp_rules(struct list *rules)
{
	struct act_rule *trule, *truleb;

	list_for_each_entry_safe(trule, truleb, rules, list) {
		LIST_DEL(&trule->list);
		deinit_acl_cond(trule->cond);
		free(trule);
	}
}

static void deinit_sample_arg(struct arg *p)
{
	struct arg *p_back = p;

	if (!p)
		return;

	while (p->type != ARGT_STOP) {
		if (p->type == ARGT_STR || p->unresolved) {
			free(p->data.str.str);
			p->data.str.str = NULL;
			p->unresolved = 0;
		}
		else if (p->type == ARGT_REG) {
			if (p->data.reg) {
				regex_free(p->data.reg);
				free(p->data.reg);
				p->data.reg = NULL;
			}
		}
		p++;
	}

	if (p_back != empty_arg_list)
		free(p_back);
}

static void deinit_stick_rules(struct list *rules)
{
	struct sticking_rule *rule, *ruleb;

	list_for_each_entry_safe(rule, ruleb, rules, list) {
		LIST_DEL(&rule->list);
		deinit_acl_cond(rule->cond);
		if (rule->expr) {
			struct sample_conv_expr *conv_expr, *conv_exprb;
			list_for_each_entry_safe(conv_expr, conv_exprb, &rule->expr->conv_exprs, list)
				deinit_sample_arg(conv_expr->arg_p);
			deinit_sample_arg(rule->expr->arg_p);
			free(rule->expr);
		}
		free(rule);
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
	struct server_rule *srule, *sruleb;
	struct redirect_rule *rdr, *rdrb;
	struct wordlist *wl, *wlb;
	struct cond_wordlist *cwl, *cwlb;
	struct uri_auth *uap, *ua = NULL;
	struct logsrv *log, *logb;
	struct logformat_node *lf, *lfb;
	struct bind_conf *bind_conf, *bind_back;
	int i;

	deinit_signals();
	while (p) {
		free(p->conf.file);
		free(p->id);
		free(p->check_req);
		free(p->cookie_name);
		free(p->cookie_domain);
		free(p->url_param_name);
		free(p->capture_name);
		free(p->monitor_uri);
		free(p->rdp_cookie_name);
		if (p->conf.logformat_string != default_http_log_format &&
		    p->conf.logformat_string != default_tcp_log_format &&
		    p->conf.logformat_string != clf_http_log_format)
			free(p->conf.logformat_string);

		free(p->conf.lfs_file);
		free(p->conf.uniqueid_format_string);
		free(p->conf.uif_file);
		free(p->lbprm.map.srv);

		if (p->conf.logformat_sd_string != default_rfc5424_sd_log_format)
			free(p->conf.logformat_sd_string);
		free(p->conf.lfsd_file);

		for (i = 0; i < HTTP_ERR_SIZE; i++)
			chunk_destroy(&p->errmsg[i]);

		list_for_each_entry_safe(cwl, cwlb, &p->req_add, list) {
			LIST_DEL(&cwl->list);
			free(cwl->s);
			free(cwl);
		}

		list_for_each_entry_safe(cwl, cwlb, &p->rsp_add, list) {
			LIST_DEL(&cwl->list);
			free(cwl->s);
			free(cwl);
		}

		list_for_each_entry_safe(cond, condb, &p->mon_fail_cond, list) {
			LIST_DEL(&cond->list);
			prune_acl_cond(cond);
			free(cond);
		}

		for (exp = p->req_exp; exp != NULL; ) {
			if (exp->preg) {
				regex_free(exp->preg);
				free(exp->preg);
			}

			free((char *)exp->replace);
			expb = exp;
			exp = exp->next;
			free(expb);
		}

		for (exp = p->rsp_exp; exp != NULL; ) {
			if (exp->preg) {
				regex_free(exp->preg);
				free(exp->preg);
			}

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

		list_for_each_entry_safe(srule, sruleb, &p->server_rules, list) {
			LIST_DEL(&srule->list);
			prune_acl_cond(srule->cond);
			free(srule->cond);
			free(srule);
		}

		list_for_each_entry_safe(rule, ruleb, &p->switching_rules, list) {
			LIST_DEL(&rule->list);
			if (rule->cond) {
				prune_acl_cond(rule->cond);
				free(rule->cond);
			}
			free(rule);
		}

		list_for_each_entry_safe(rdr, rdrb, &p->redirect_rules, list) {
			LIST_DEL(&rdr->list);
			if (rdr->cond) {
				prune_acl_cond(rdr->cond);
				free(rdr->cond);
			}
			free(rdr->rdr_str);
			list_for_each_entry_safe(lf, lfb, &rdr->rdr_fmt, list) {
				LIST_DEL(&lf->list);
				free(lf);
			}
			free(rdr);
		}

		list_for_each_entry_safe(log, logb, &p->logsrvs, list) {
			LIST_DEL(&log->list);
			free(log);
		}

		list_for_each_entry_safe(lf, lfb, &p->logformat, list) {
			LIST_DEL(&lf->list);
			free(lf);
		}

		list_for_each_entry_safe(lf, lfb, &p->logformat_sd, list) {
			LIST_DEL(&lf->list);
			free(lf);
		}

		deinit_tcp_rules(&p->tcp_req.inspect_rules);
		deinit_tcp_rules(&p->tcp_req.l4_rules);

		deinit_stick_rules(&p->storersp_rules);
		deinit_stick_rules(&p->sticking_rules);

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

			if (s->check.task) {
				task_delete(s->check.task);
				task_free(s->check.task);
			}
			if (s->agent.task) {
				task_delete(s->agent.task);
				task_free(s->agent.task);
			}

			if (s->warmup) {
				task_delete(s->warmup);
				task_free(s->warmup);
			}

			free(s->id);
			free(s->cookie);
			free(s->check.bi);
			free(s->check.bo);
			free(s->agent.bi);
			free(s->agent.bo);
			free(s->agent.send_string);
			free((char*)s->conf.file);
#ifdef USE_OPENSSL
			if (s->use_ssl || s->check.use_ssl)
				ssl_sock_free_srv_ctx(s);
#endif
			free(s);
			s = s_next;
		}/* end while(s) */

		list_for_each_entry_safe(l, l_next, &p->conf.listeners, by_fe) {
			unbind_listener(l);
			delete_listener(l);
			LIST_DEL(&l->by_fe);
			LIST_DEL(&l->by_bind);
			free(l->name);
			free(l->counters);
			free(l);
		}

		/* Release unused SSL configs. */
		list_for_each_entry_safe(bind_conf, bind_back, &p->conf.bind, by_fe) {
#ifdef USE_OPENSSL
			ssl_sock_free_ca(bind_conf);
			ssl_sock_free_all_ctx(bind_conf);
			free(bind_conf->ca_file);
			free(bind_conf->ca_sign_file);
			free(bind_conf->ca_sign_pass);
			free(bind_conf->ciphers);
			free(bind_conf->ecdhe);
			free(bind_conf->crl_file);
#endif /* USE_OPENSSL */
			free(bind_conf->file);
			free(bind_conf->arg);
			LIST_DEL(&bind_conf->by_fe);
			free(bind_conf);
		}

		flt_deinit(p);

		free(p->desc);
		free(p->fwdfor_hdr_name);

		free_http_req_rules(&p->http_req_rules);
		free_http_res_rules(&p->http_res_rules);
		free(p->task);

		pool_destroy2(p->req_cap_pool);
		pool_destroy2(p->rsp_cap_pool);
		pool_destroy2(p->table.pool);

		p0 = p;
		p = p->next;
		free(p0);
	}/* end while(p) */

	while (ua) {
		uap = ua;
		ua = ua->next;

		free(uap->uri_prefix);
		free(uap->auth_realm);
		free(uap->node);
		free(uap->desc);

		userlist_free(uap->userlist);
		free_http_req_rules(&uap->http_req_rules);

		free(uap);
	}

	userlist_free(userlist);

	cfg_unregister_sections();

	free_trash_buffers();
	chunk_destroy(&trash);

	protocol_unbind_all();

#if defined(USE_DEVICEATLAS)
	deinit_deviceatlas();
#endif

#ifdef USE_51DEGREES
	deinit_51degrees();
#endif

	free(global.log_send_hostname); global.log_send_hostname = NULL;
	chunk_destroy(&global.log_tag);
	free(global.chroot);  global.chroot = NULL;
	free(global.pidfile); global.pidfile = NULL;
	free(global.node);    global.node = NULL;
	free(global.desc);    global.desc = NULL;
	free(fdinfo);         fdinfo  = NULL;
	free(fdtab);          fdtab   = NULL;
	free(oldpids);        oldpids = NULL;
	free(static_table_key); static_table_key = NULL;
	free(get_http_auth_buff); get_http_auth_buff = NULL;
	free(swap_buffer);    swap_buffer = NULL;
	free(global_listener_queue_task); global_listener_queue_task = NULL;

	list_for_each_entry_safe(log, logb, &global.logsrvs, list) {
			LIST_DEL(&log->list);
			free(log);
		}
	list_for_each_entry_safe(wl, wlb, &cfg_cfgfiles, list) {
		LIST_DEL(&wl->list);
		free(wl);
	}

	pool_destroy2(pool2_stream);
	pool_destroy2(pool2_session);
	pool_destroy2(pool2_connection);
	pool_destroy2(pool2_buffer);
	pool_destroy2(pool2_requri);
	pool_destroy2(pool2_task);
	pool_destroy2(pool2_capture);
	pool_destroy2(pool2_pendconn);
	pool_destroy2(pool2_sig_handlers);
	pool_destroy2(pool2_hdr_idx);
	pool_destroy2(pool2_http_txn);
	deinit_pollers();
} /* end deinit() */

/* sends the signal <sig> to all pids found in <oldpids>. Returns the number of
 * pids the signal was correctly delivered to.
 */
static int tell_old_pids(int sig)
{
	int p;
	int ret = 0;
	for (p = 0; p < nb_oldpids; p++)
		if (kill(oldpids[p], sig) == 0)
			ret++;
	return ret;
}

/* Runs the polling loop */
void run_poll_loop()
{
	int next;

	tv_update_date(0,1);
	while (1) {
		/* Process a few tasks */
		process_runnable_tasks();

		/* check if we caught some signals and process them */
		signal_process_queue();

		/* Check if we can expire some tasks */
		next = wake_expired_tasks();

		/* stop when there's nothing left to do */
		if (jobs == 0)
			break;

		/* expire immediately if events are pending */
		if (fd_cache_num || run_queue || signal_queue_len || !LIST_ISEMPTY(&applet_active_queue))
			next = now_ms;

		/* The poller will ensure it returns around <next> */
		cur_poller.poll(&cur_poller, next);
		fd_process_cached_events();
		applet_run_active();
	}
}

/* This is the global management task for listeners. It enables listeners waiting
 * for global resources when there are enough free resource, or at least once in
 * a while. It is designed to be called as a task.
 */
static struct task *manage_global_listener_queue(struct task *t)
{
	int next = TICK_ETERNITY;
	/* queue is empty, nothing to do */
	if (LIST_ISEMPTY(&global_listener_queue))
		goto out;

	/* If there are still too many concurrent connections, let's wait for
	 * some of them to go away. We don't need to re-arm the timer because
	 * each of them will scan the queue anyway.
	 */
	if (unlikely(actconn >= global.maxconn))
		goto out;

	/* We should periodically try to enable listeners waiting for a global
	 * resource here, because it is possible, though very unlikely, that
	 * they have been blocked by a temporary lack of global resource such
	 * as a file descriptor or memory and that the temporary condition has
	 * disappeared.
	 */
	dequeue_all_listeners(&global_listener_queue);

 out:
	t->expire = next;
	task_queue(t);
	return t;
}

int main(int argc, char **argv)
{
	int err, retry;
	struct rlimit limit;
	char errmsg[100];
	int pidfd = -1;

	init(argc, argv);
	signal_register_fct(SIGQUIT, dump, SIGQUIT);
	signal_register_fct(SIGUSR1, sig_soft_stop, SIGUSR1);
	signal_register_fct(SIGHUP, sig_dump_state, SIGHUP);

	/* Always catch SIGPIPE even on platforms which define MSG_NOSIGNAL.
	 * Some recent FreeBSD setups report broken pipes, and MSG_NOSIGNAL
	 * was defined there, so let's stay on the safe side.
	 */
	signal_register_fct(SIGPIPE, NULL, 0);

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
			global.rlimit_memmax * 1048576ULL;
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
		if (nb_oldpids == 0 || retry == 0)
			break;

		/* FIXME-20060514: Solaris and OpenBSD do not support shutdown() on
		 * listening sockets. So on those platforms, it would be wiser to
		 * simply send SIGUSR1, which will not be undoable.
		 */
		if (tell_old_pids(SIGTTOU) == 0) {
			/* no need to wait if we can't contact old pids */
			retry = 0;
			continue;
		}
		/* give some time to old processes to stop listening */
		w.tv_sec = 0;
		w.tv_usec = 10*1000;
		select(0, NULL, NULL, NULL, &w);
		retry--;
	}

	/* Note: start_proxies() sends an alert when it fails. */
	if ((err & ~ERR_WARN) != ERR_NONE) {
		if (retry != MAX_START_RETRIES && nb_oldpids) {
			protocol_unbind_all(); /* cleanup everything we can */
			tell_old_pids(SIGTTIN);
		}
		exit(1);
	}

	if (listeners == 0) {
		Alert("[%s.main()] No enabled listener found (check for 'bind' directives) ! Exiting.\n", argv[0]);
		/* Note: we don't have to send anything to the old pids because we
		 * never stopped them. */
		exit(1);
	}

	err = protocol_bind_all(errmsg, sizeof(errmsg));
	if ((err & ~ERR_WARN) != ERR_NONE) {
		if ((err & ERR_ALERT) || (err & ERR_WARN))
			Alert("[%s.main()] %s.\n", argv[0], errmsg);

		Alert("[%s.main()] Some protocols failed to start their listeners! Exiting.\n", argv[0]);
		protocol_unbind_all(); /* cleanup everything we can */
		if (nb_oldpids)
			tell_old_pids(SIGTTIN);
		exit(1);
	} else if (err & ERR_WARN) {
		Alert("[%s.main()] %s.\n", argv[0], errmsg);
	}

	/* prepare pause/play signals */
	signal_register_fct(SIGTTOU, sig_pause, SIGTTOU);
	signal_register_fct(SIGTTIN, sig_listen, SIGTTIN);

	/* MODE_QUIET can inhibit alerts and warnings below this line */

	global.mode &= ~MODE_STARTING;
	if ((global.mode & MODE_QUIET) && !(global.mode & MODE_VERBOSE)) {
		/* detach from the tty */
		fclose(stdin); fclose(stdout); fclose(stderr);
	}

	/* open log & pid files before the chroot */
	if (global.mode & (MODE_DAEMON | MODE_SYSTEMD) && global.pidfile != NULL) {
		unlink(global.pidfile);
		pidfd = open(global.pidfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (pidfd < 0) {
			Alert("[%s.main()] Cannot create pidfile %s\n", argv[0], global.pidfile);
			if (nb_oldpids)
				tell_old_pids(SIGTTIN);
			protocol_unbind_all();
			exit(1);
		}
	}

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
		if (chroot(global.chroot) == -1 || chdir("/") == -1) {
			Alert("[%s.main()] Cannot chroot(%s).\n", argv[0], global.chroot);
			if (nb_oldpids)
				tell_old_pids(SIGTTIN);
			protocol_unbind_all();
			exit(1);
		}
	}

	if (nb_oldpids)
		nb_oldpids = tell_old_pids(oldpids_sig);

	/* Note that any error at this stage will be fatal because we will not
	 * be able to restart the old pids.
	 */

	/* setgid / setuid */
	if (global.gid) {
		if (getgroups(0, NULL) > 0 && setgroups(0, NULL) == -1)
			Warning("[%s.main()] Failed to drop supplementary groups. Using 'gid'/'group'"
				" without 'uid'/'user' is generally useless.\n", argv[0]);

		if (setgid(global.gid) == -1) {
			Alert("[%s.main()] Cannot set gid %d.\n", argv[0], global.gid);
			protocol_unbind_all();
			exit(1);
		}
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

	if (global.mode & (MODE_DAEMON | MODE_SYSTEMD)) {
		struct proxy *px;
		struct peers *curpeers;
		int ret = 0;
		int *children = calloc(global.nbproc, sizeof(int));
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
			children[proc] = ret;
			if (pidfd >= 0) {
				char pidstr[100];
				snprintf(pidstr, sizeof(pidstr), "%d\n", ret);
				shut_your_big_mouth_gcc(write(pidfd, pidstr, strlen(pidstr)));
			}
			relative_pid++; /* each child will get a different one */
		}

#ifdef USE_CPU_AFFINITY
		if (proc < global.nbproc &&  /* child */
		    proc < LONGBITS &&       /* only the first 32/64 processes may be pinned */
		    global.cpu_map[proc])    /* only do this if the process has a CPU map */
#ifdef __FreeBSD__
			cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(unsigned long), (void *)&global.cpu_map[proc]);
#else
			sched_setaffinity(0, sizeof(unsigned long), (void *)&global.cpu_map[proc]);
#endif
#endif
		/* close the pidfile both in children and father */
		if (pidfd >= 0) {
			//lseek(pidfd, 0, SEEK_SET);  /* debug: emulate eglibc bug */
			close(pidfd);
		}

		/* We won't ever use this anymore */
		free(oldpids);        oldpids = NULL;
		free(global.chroot);  global.chroot = NULL;
		free(global.pidfile); global.pidfile = NULL;

		if (proc == global.nbproc) {
			if (global.mode & MODE_SYSTEMD) {
				int i;

				protocol_unbind_all();
				for (i = 1; i < argc; i++) {
					memset(argv[i], '\0', strlen(argv[i]));
				}
				/* it's OK because "-Ds -f x" is the shortest form going here */
				memcpy(argv[0] + strlen(argv[0]), "-master", 8);
				for (proc = 0; proc < global.nbproc; proc++)
					while (waitpid(children[proc], NULL, 0) == -1 && errno == EINTR);
			}
			exit(0); /* parent must leave */
		}

		/* we might have to unbind some proxies from some processes */
		px = proxy;
		while (px != NULL) {
			if (px->bind_proc && px->state != PR_STSTOPPED) {
				if (!(px->bind_proc & (1UL << proc)))
					stop_proxy(px);
			}
			px = px->next;
		}

		/* we might have to unbind some peers sections from some processes */
		for (curpeers = peers; curpeers; curpeers = curpeers->next) {
			if (!curpeers->peers_fe)
				continue;

			if (curpeers->peers_fe->bind_proc & (1UL << proc))
				continue;

			stop_proxy(curpeers->peers_fe);
			/* disable this peer section so that it kills itself */
			signal_unregister_handler(curpeers->sighandler);
			task_delete(curpeers->sync_task);
			task_free(curpeers->sync_task);
			curpeers->sync_task = NULL;
			task_free(curpeers->peers_fe->task);
			curpeers->peers_fe->task = NULL;
			curpeers->peers_fe = NULL;
		}

		free(children);
		children = NULL;
		/* if we're NOT in QUIET mode, we should now close the 3 first FDs to ensure
		 * that we can detach from the TTY. We MUST NOT do it in other cases since
		 * it would have already be done, and 0-2 would have been affected to listening
		 * sockets
		 */
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
			/* detach from the tty */
			fclose(stdin); fclose(stdout); fclose(stderr);
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
