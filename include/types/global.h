/*
 * include/types/global.h
 * Global variables.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _TYPES_GLOBAL_H
#define _TYPES_GLOBAL_H

#include <netinet/in.h>

#include <common/config.h>
#include <common/standard.h>
#include <common/hathreads.h>

#include <types/freq_ctr.h>
#include <types/listener.h>
#include <types/proxy.h>
#include <types/task.h>
#include <types/vars.h>

#ifndef UNIX_MAX_PATH
#define UNIX_MAX_PATH 108
#endif

/* modes of operation (global.mode) */
#define	MODE_DEBUG	0x01
#define	MODE_DAEMON	0x02
#define	MODE_QUIET	0x04
#define	MODE_CHECK	0x08
#define	MODE_VERBOSE	0x10
#define	MODE_STARTING	0x20
#define	MODE_FOREGROUND	0x40
#define	MODE_MWORKER	0x80    /* Master Worker */

/* list of last checks to perform, depending on config options */
#define LSTCHK_CAP_BIND	0x00000001	/* check that we can bind to any port */
#define LSTCHK_NETADM	0x00000002	/* check that we have CAP_NET_ADMIN */

/* Global tuning options */
/* available polling mechanisms */
#define GTUNE_USE_SELECT         (1<<0)
#define GTUNE_USE_POLL           (1<<1)
#define GTUNE_USE_EPOLL          (1<<2)
#define GTUNE_USE_KQUEUE         (1<<3)
/* platform-specific options */
#define GTUNE_USE_SPLICE         (1<<4)
#define GTUNE_USE_GAI            (1<<5)
#define GTUNE_USE_REUSEPORT      (1<<6)
#define GTUNE_RESOLVE_DONTFAIL   (1<<7)

#define GTUNE_SOCKET_TRANSFER	 (1<<8)
#define GTUNE_NOEXIT_ONFAILURE   (1<<9)
#define GTUNE_USE_SYSTEMD        (1<<10)

/* Access level for a stats socket */
#define ACCESS_LVL_NONE     0
#define ACCESS_LVL_USER     1
#define ACCESS_LVL_OPER     2
#define ACCESS_LVL_ADMIN    3
#define ACCESS_LVL_MASK     0x3

#define ACCESS_FD_LISTENERS 0x4  /* expose listeners FDs on stats socket */

/* SSL server verify mode */
enum {
	SSL_SERVER_VERIFY_NONE = 0,
	SSL_SERVER_VERIFY_REQUIRED = 1,
};

/* FIXME : this will have to be redefined correctly */
struct global {
	int uid;
	int gid;
	int external_check;
	int nbproc;
	int nbthread;
	unsigned int hard_stop_after;	/* maximum time allowed to perform a soft-stop */
	int maxconn, hardmaxconn;
	int maxsslconn;
	int ssl_session_max_cost;   /* how many bytes an SSL session may cost */
	int ssl_handshake_max_cost; /* how many bytes an SSL handshake may use */
	int ssl_used_frontend;      /* non-zero if SSL is used in a frontend */
	int ssl_used_backend;       /* non-zero if SSL is used in a backend */
	int ssl_used_async_engines; /* number of used async engines */
	unsigned int ssl_server_verify; /* default verify mode on servers side */
	struct freq_ctr conn_per_sec;
	struct freq_ctr sess_per_sec;
	struct freq_ctr ssl_per_sec;
	struct freq_ctr ssl_fe_keys_per_sec;
	struct freq_ctr ssl_be_keys_per_sec;
	struct freq_ctr comp_bps_in;	/* bytes per second, before http compression */
	struct freq_ctr comp_bps_out;	/* bytes per second, after http compression */
	int cps_lim, cps_max;
	int sps_lim, sps_max;
	int ssl_lim, ssl_max;
	int ssl_fe_keys_max, ssl_be_keys_max;
	unsigned int shctx_lookups, shctx_misses;
	int comp_rate_lim;           /* HTTP compression rate limit */
	int maxpipes;		/* max # of pipes */
	int maxsock;		/* max # of sockets */
	int rlimit_nofile;	/* default ulimit-n value : 0=unset */
	int rlimit_memmax_all;	/* default all-process memory limit in megs ; 0=unset */
	int rlimit_memmax;	/* default per-process memory limit in megs ; 0=unset */
	long maxzlibmem;        /* max RAM for zlib in bytes */
	int mode;
	unsigned int req_count; /* request counter (HTTP or TCP session) for logs and unique_id */
	int last_checks;
	int spread_checks;
	int max_spread_checks;
	int max_syslog_len;
	char *chroot;
	char *pidfile;
	char *node, *desc;		/* node name & description */
	struct chunk log_tag;           /* name for syslog */
	struct list logsrvs;
	char *log_send_hostname;   /* set hostname in syslog header */
	char *server_state_base;   /* path to a directory where server state files can be found */
	char *server_state_file;   /* path to the file where server states are loaded from */
	struct {
		int maxpollevents; /* max number of poll events at once */
		int maxaccept;     /* max number of consecutive accept() */
		int options;       /* various tuning options */
		int recv_enough;   /* how many input bytes at once are "enough" */
		int bufsize;       /* buffer size in bytes, defaults to BUFSIZE */
		int maxrewrite;    /* buffer max rewrite size in bytes, defaults to MAXREWRITE */
		int reserved_bufs; /* how many buffers can only be allocated for response */
		int buf_limit;     /* if not null, how many total buffers may only be allocated */
		int client_sndbuf; /* set client sndbuf to this value if not null */
		int client_rcvbuf; /* set client rcvbuf to this value if not null */
		int server_sndbuf; /* set server sndbuf to this value if not null */
		int server_rcvbuf; /* set server rcvbuf to this value if not null */
		int chksize;       /* check buffer size in bytes, defaults to BUFSIZE */
		int pipesize;      /* pipe size in bytes, system defaults if zero */
		int max_http_hdr;  /* max number of HTTP headers, use MAX_HTTP_HDR if zero */
		int requri_len;    /* max len of request URI, use REQURI_LEN if zero */
		int cookie_len;    /* max length of cookie captures */
		int pattern_cache; /* max number of entries in the pattern cache. */
		int sslcachesize;  /* SSL cache size in session, defaults to 20000 */
		int comp_maxlevel;    /* max HTTP compression level */
		unsigned short idle_timer; /* how long before an empty buffer is considered idle (ms) */
	} tune;
	struct {
		char *prefix;           /* path prefix of unix bind socket */
		struct {                /* UNIX socket permissions */
			uid_t uid;      /* -1 to leave unchanged */
			gid_t gid;      /* -1 to leave unchanged */
			mode_t mode;    /* 0 to leave unchanged */
		} ux;
	} unix_bind;
	struct proxy *stats_fe;     /* the frontend holding the stats settings */
	struct vars   vars;         /* list of variables for the process scope. */
#ifdef USE_CPU_AFFINITY
	struct {
		unsigned long proc[LONGBITS];             /* list of CPU masks for the 32/64 first processes */
		unsigned long thread[LONGBITS][MAX_THREADS]; /* list of CPU masks for the 32/64 first threads per process */
	} cpu_map;
#endif
};

/* per-thread activity reports. It's important that it's aligned on cache lines
 * because some elements will be updated very often. Most counters are OK on
 * 32-bit since this will be used during debugging sessions for troubleshooting
 * in iterative mode.
 */
struct activity {
	unsigned int loops;        // complete loops in run_poll_loop()
	unsigned int wake_cache;   // active fd_cache prevented poll() from sleeping
	unsigned int wake_tasks;   // active tasks prevented poll() from sleeping
	unsigned int wake_applets; // active applets prevented poll() from sleeping
	unsigned int wake_signal;  // pending signal prevented poll() from sleeping
	unsigned int poll_exp;     // number of times poll() sees an expired timeout (includes wake_*)
	unsigned int poll_drop;    // poller dropped a dead FD from the update list
	unsigned int poll_dead;    // poller woke up with a dead FD
	unsigned int poll_skip;    // poller skipped another thread's FD
	unsigned int fd_skip;      // fd cache skipped another thread's FD
	unsigned int fd_lock;      // fd cache skipped a locked FD
	unsigned int fd_del;       // fd cache detected a deleted FD
	unsigned int conn_dead;    // conn_fd_handler woke up on an FD indicating a dead connection
	unsigned int stream;       // calls to process_stream()
	unsigned int empty_rq;     // calls to process_runnable_tasks() with nothing for the thread
	unsigned int long_rq;      // process_runnable_tasks() left with tasks in the run queue
	char __pad[0]; // unused except to check remaining room
	char __end[0] __attribute__((aligned(64))); // align size to 64.
};

extern struct global global;
extern struct activity activity[MAX_THREADS];
extern int  pid;                /* current process id */
extern int  relative_pid;       /* process id starting at 1 */
extern unsigned long pid_bit;   /* bit corresponding to the process id */
extern int  actconn;            /* # of active sessions */
extern int  listeners;
extern int  jobs;               /* # of active jobs (listeners, sessions, open devices) */
extern THREAD_LOCAL struct chunk trash;
extern int nb_oldpids;          /* contains the number of old pids found */
extern const int zero;
extern const int one;
extern const struct linger nolinger;
extern int stopping;	/* non zero means stopping in progress */
extern int killed;	/* non zero means a hard-stop is triggered */
extern char hostname[MAX_HOSTNAME_LEN];
extern char localpeer[MAX_HOSTNAME_LEN];
extern struct list global_listener_queue; /* list of the temporarily limited listeners */
extern struct task *global_listener_queue_task;
extern unsigned int warned;     /* bitfield of a few warnings to emit just once */

/* bit values to go with "warned" above */
#define WARN_BLOCK_DEPRECATED       0x00000001
/* unassigned : 0x00000002 */
#define WARN_REDISPATCH_DEPRECATED  0x00000004
#define WARN_CLITO_DEPRECATED       0x00000008
#define WARN_SRVTO_DEPRECATED       0x00000010
#define WARN_CONTO_DEPRECATED       0x00000020

/* to be used with warned and WARN_* */
static inline int already_warned(unsigned int warning)
{
	if (warned & warning)
		return 1;
	warned |= warning;
	return 0;
}

void deinit(void);
void hap_register_build_opts(const char *str, int must_free);
void hap_register_post_check(int (*fct)());
void hap_register_post_deinit(void (*fct)());

void hap_register_per_thread_init(int (*fct)());
void hap_register_per_thread_deinit(void (*fct)());

#endif /* _TYPES_GLOBAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
