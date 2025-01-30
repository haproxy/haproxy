/*
 * include/haproxy/global-t.h
 * Global types and macros. Please avoid adding more stuff here!
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_GLOBAL_T_H
#define _HAPROXY_GLOBAL_T_H

#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/freq_ctr-t.h>

/* modes of operation (global.mode) */
#define	MODE_DEBUG	0x01
#define	MODE_DAEMON	0x02
#define	MODE_QUIET	0x04
#define	MODE_CHECK	0x08
#define	MODE_VERBOSE	0x10
#define	MODE_STARTING	0x20
#define	MODE_FOREGROUND	0x40
#define	MODE_MWORKER	0x80    /* Master Worker */
/* (1<<8) unused */
#define	MODE_ZERO_WARNING       0x200    /* warnings cause a failure */
#define	MODE_DIAG	0x400   /* extra warnings */
#define	MODE_CHECK_CONDITION	0x800    /* -cc mode */
#define	MODE_STOPPING   0x1000  /* the process is in the deinit phase, the event loop is not running anymore. */
#define	MODE_DUMP_LIBS  0x2000  /* dump loaded libraries at the end of init phase */
#define	MODE_DUMP_KWD   0x4000  /* dump registered keywords (see kwd_dump for the list) */
#define	MODE_DUMP_CFG   0x8000  /* dump the configuration file */
#define	MODE_DUMP_NB_L  0x10000 /* dump line numbers when the configuration file is dump */
#define	MODE_DISCOVERY  0x20000 /* parse only keywords with KW_DISCOVERY flag to discover other global modes, i.e. daemon, master-worker */

/* list of last checks to perform, depending on config options */
#define LSTCHK_SYSADM	0x00000001	/* check that we have CAP_SYS_ADMIN */
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
#define GTUNE_LIMITED_QUIC       (1<<6)
#define GTUNE_RESOLVE_DONTFAIL   (1<<7)

#define GTUNE_SOCKET_TRANSFER	 (1<<8)
#define GTUNE_NOEXIT_ONFAILURE   (1<<9)
#define GTUNE_USE_SYSTEMD        (1<<10)

#define GTUNE_BUSY_POLLING       (1<<11)
/* (1<<12) unused */
#define GTUNE_SET_DUMPABLE       (1<<13)
#define GTUNE_USE_EVPORTS        (1<<14)
#define GTUNE_STRICT_LIMITS      (1<<15)
#define GTUNE_INSECURE_FORK      (1<<16)
#define GTUNE_INSECURE_SETUID    (1<<17)
#define GTUNE_FD_ET              (1<<18)
#define GTUNE_SCHED_LOW_LATENCY  (1<<19)
#define GTUNE_IDLE_POOL_SHARED   (1<<20)
#define GTUNE_DISABLE_H2_WEBSOCKET (1<<21)
#define GTUNE_DISABLE_ACTIVE_CLOSE (1<<22)
#define GTUNE_QUICK_EXIT         (1<<23)
#define GTUNE_QUIC_SOCK_PER_CONN (1<<24)
#define GTUNE_NO_QUIC            (1<<25)
#define GTUNE_USE_FAST_FWD       (1<<26)
#define GTUNE_LISTENER_MQ_FAIR   (1<<27)
#define GTUNE_LISTENER_MQ_OPT    (1<<28)
#define GTUNE_LISTENER_MQ_ANY    (GTUNE_LISTENER_MQ_FAIR | GTUNE_LISTENER_MQ_OPT)
#define GTUNE_QUIC_CC_HYSTART    (1<<29)
#define GTUNE_QUIC_NO_UDP_GSO    (1<<30)

#define NO_ZERO_COPY_FWD             0x0001 /* Globally disable zero-copy FF */
#define NO_ZERO_COPY_FWD_PT          0x0002 /* disable zero-copy FF for PT (recv & send are disabled automatically) */
#define NO_ZERO_COPY_FWD_H1_RCV      0x0004 /* disable zero-copy FF for H1 on received */
#define NO_ZERO_COPY_FWD_H1_SND      0x0008 /* disable zero-copy FF for H1 on send */
#define NO_ZERO_COPY_FWD_H2_RCV      0x0010 /* disable zero-copy FF for H2 on received */
#define NO_ZERO_COPY_FWD_H2_SND      0x0020 /* disable zero-copy FF for H2 on send */
#define NO_ZERO_COPY_FWD_QUIC_RCV    0x0040 /* disable zero-copy FF for QUIC on received */
#define NO_ZERO_COPY_FWD_QUIC_SND    0x0080 /* disable zero-copy FF for QUIC on send */
#define NO_ZERO_COPY_FWD_FCGI_RCV    0x0100 /* disable zero-copy FF for FCGI on received */
#define NO_ZERO_COPY_FWD_FCGI_SND    0x0200 /* disable zero-copy FF for FCGI on send */
#define NO_ZERO_COPY_FWD_APPLET      0x0400 /* disable zero-copy FF for applets */


extern int cluster_secret_isset; /* non zero means a cluster secret was initialized */

/* SSL server verify mode */
enum {
	SSL_SERVER_VERIFY_NONE = 0,
	SSL_SERVER_VERIFY_REQUIRED = 1,
};

/* bit values to go with "warned" above */
#define WARN_ANY                    0x00000001 /* any warning was emitted */
#define WARN_FORCECLOSE_DEPRECATED  0x00000002
#define WARN_EXEC_PATH              0x00000004 /* executable path already reported */

/* put there the forward declarations needed for global.h */
struct proxy;

/* FIXME : this will have to be redefined correctly */
struct global {
	int uid;
	int gid;
	int external_check;             /* 0=disabled, 1=enabled, 2=enabled with env */
	int nbthread;
	int mode;
	unsigned int hard_stop_after;	/* maximum time allowed to perform a soft-stop */
	unsigned int grace_delay;       /* grace delay between SIGUSR1 and soft-stop */
	unsigned int close_spread_time;	/* time window during which connection closing is spread */
	unsigned int close_spread_end;	/* end of close spread window */
	int maxconn, hardmaxconn;
	int maxsslconn;
	int ssl_session_max_cost;   /* how many bytes an SSL session may cost */
	int ssl_handshake_max_cost; /* how many bytes an SSL handshake may use */
	int ssl_used_frontend;      /* non-zero if SSL is used in a frontend */
	int ssl_used_backend;       /* non-zero if SSL is used in a backend */
	int ssl_used_async_engines; /* number of used async engines */
	unsigned int ssl_server_verify; /* default verify mode on servers side */
	int comp_rate_lim;           /* HTTP compression rate limit */
	int maxpipes;		/* max # of pipes */
	int maxsock;		/* max # of sockets */
	int rlimit_nofile;	/* default ulimit-n value : 0=unset */
	int rlimit_memmax_all;	/* default all-process memory limit in megs ; 0=unset */
	int rlimit_memmax;	/* default per-process memory limit in megs ; 0=unset */
	long maxzlibmem;        /* max RAM for zlib in bytes */
	int nbtgroups;          /* number of thread groups (IDs start at 1) */
	int spread_checks;
	int max_spread_checks;
	int max_syslog_len;
	char *chroot;
	char *pidfile;
	char *node, *desc;		/* node name & description */
	int localpeer_cmdline;		/* whether or not the commandline "-L" was set */
	int fd_hard_limit;		/* hard limit on ulimit-n : 0=unset */
	struct buffer log_tag;           /* name for syslog */
	struct list loggers;       /* one per 'log' directive */
	char *log_send_hostname;   /* set hostname in syslog header */
	char *server_state_base;   /* path to a directory where server state files can be found */
	char *server_state_file;   /* path to the file where server states are loaded from */
	char *stats_file;          /* path to stats-file */
	unsigned char cluster_secret[16]; /* 128 bits of an SHA1 digest of a secret defined as ASCII string */
	struct {
		int maxpollevents; /* max number of poll events at once */
		int maxaccept;     /* max number of consecutive accept() */
		int options;       /* various tuning options */
		int runqueue_depth;/* max number of tasks to run at once */
		uint recv_enough;  /* how many input bytes at once are "enough" */
		uint bufsize;      /* buffer size in bytes, defaults to BUFSIZE */
		uint bufsize_small;/* small buffer size in bytes */
		int maxrewrite;    /* buffer max rewrite size in bytes, defaults to MAXREWRITE */
		int reserved_bufs; /* how many buffers can only be allocated for response */
		int buf_limit;     /* if not null, how many total buffers may only be allocated */
		uint client_sndbuf;   /* set client sndbuf to this value if not null */
		uint client_rcvbuf;   /* set client rcvbuf to this value if not null */
		uint server_sndbuf;   /* set server sndbuf to this value if not null */
		uint server_rcvbuf;   /* set server rcvbuf to this value if not null */
		uint frontend_sndbuf; /* set frontend dgram sndbuf to this value if not null */
		uint frontend_rcvbuf; /* set frontend dgram rcvbuf to this value if not null */
		uint backend_sndbuf;  /* set backend dgram sndbuf to this value if not null */
		uint backend_rcvbuf;  /* set backend dgram rcvbuf to this value if not null */
		uint pipesize;     /* pipe size in bytes, system defaults if zero */
		int max_http_hdr;  /* max number of HTTP headers, use MAX_HTTP_HDR if zero */
		int requri_len;    /* max len of request URI, use REQURI_LEN if zero */
		int cookie_len;    /* max length of cookie captures */
		int pattern_cache; /* max number of entries in the pattern cache. */
		int sslcachesize;  /* SSL cache size in session, defaults to 20000 */
		int comp_maxlevel;    /* max HTTP compression level */
		int pool_low_ratio;   /* max ratio of FDs used before we stop using new idle connections */
		int pool_high_ratio;  /* max ratio of FDs used before we start killing idle connections when creating new connections */
		int pool_low_count;   /* max number of opened fd before we stop using new idle connections */
		int pool_high_count;  /* max number of opened fd before we start killing idle connections when creating new connections */
		size_t pool_cache_size;    /* per-thread cache size per pool (defaults to CONFIG_HAP_POOL_CACHE_SIZE) */
		int renice_startup;     /* startup nice()+100 value during startup; 0 = unset */
		int renice_runtime;     /* startup nice()+100 value during runtime; 0 = unset */
		unsigned short idle_timer; /* how long before an empty buffer is considered idle (ms) */
		unsigned short no_zero_copy_fwd; /* Flags to disable zero-copy fast-forwarding (global & per-protocols) */
		int nb_stk_ctr;       /* number of stick counters, defaults to MAX_SESS_STKCTR */
		int default_shards; /* default shards for listeners, or -1 (by-thread) or -2 (by-group) */
		uint max_checks_per_thread; /* if >0, no more than this concurrent checks per thread */
		uint ring_queues;   /* if >0, #ring queues, otherwise equals #thread groups */
#ifdef USE_QUIC
		unsigned int quic_backend_max_idle_timeout;
		unsigned int quic_frontend_max_idle_timeout;
		unsigned int quic_frontend_glitches_threshold;
		unsigned int quic_frontend_max_streams_bidi;
		size_t quic_frontend_max_window_size;
		unsigned int quic_retry_threshold;
		unsigned int quic_reorder_ratio;
		unsigned int quic_max_frame_loss;
		unsigned int quic_cubic_loss_tol;
#endif /* USE_QUIC */
	} tune;
	struct {
		char *prefix;           /* path prefix of unix bind socket */
		struct {                /* UNIX socket permissions */
			uid_t uid;      /* -1 to leave unchanged */
			gid_t gid;      /* -1 to leave unchanged */
			mode_t mode;    /* 0 to leave unchanged */
		} ux;
	} unix_bind;
	struct proxy *cli_fe;           /* the frontend holding the stats settings */
	int numa_cpu_mapping;
	int thread_limit;               /* hard limit on the number of threads */
	int prealloc_fd;
	uchar clt_privileged_ports;     /* bitmask to allow client privileged ports exchanges per protocol */
	unsigned char argc;		/* cast int argc to unsigned char in order to fill better the previous
					 * 3 bytes hole, it seems unreal, that oneday we could start with more
					 * than 255 arguments
					 */
	/* 2-bytes hole */
	int cfg_curr_line;              /* line number currently being parsed */
	const char *cfg_curr_file;      /* config file currently being parsed or NULL */
	char *cfg_curr_section;         /* config section name currently being parsed or NULL */
	char **argv;			/* ptr to array with args */

	/* The info above is config stuff, it doesn't change during the process' life */
	/* A number of the elements below are updated by all threads in real time and
	 * suffer high contention, so we need to put them in their own cache lines, if
	 * possible grouped by changes.
	 */
	ALWAYS_ALIGN(64);
	struct freq_ctr conn_per_sec;
	struct freq_ctr sess_per_sec;
	struct freq_ctr ssl_per_sec;
	struct freq_ctr ssl_fe_keys_per_sec;
	struct freq_ctr ssl_be_keys_per_sec;
	struct freq_ctr comp_bps_in;	/* bytes per second, before http compression */
	struct freq_ctr comp_bps_out;	/* bytes per second, after http compression */
	uint sslconns, totalsslconns;   /* active, total # of SSL conns */
	int cps_lim, cps_max;
	int sps_lim, sps_max;
	int ssl_lim, ssl_max;
	int ssl_fe_keys_max, ssl_be_keys_max;
	unsigned int shctx_lookups, shctx_misses;
	unsigned int req_count; /* request counter (HTTP or TCP session) for logs and unique_id */
	int last_checks;
	uint32_t anon_key;

	/* leave this at the end to make sure we don't share this cache line by accident */
	ALWAYS_ALIGN(64);
};

#endif /* _HAPROXY_GLOBAL_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
