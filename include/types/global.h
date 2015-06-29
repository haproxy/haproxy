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
#include <import/da.h>
#include <types/freq_ctr.h>
#include <types/listener.h>
#include <types/proxy.h>
#include <types/task.h>

#ifdef USE_51DEGREES
#include <import/51d.h>
#endif

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
#define	MODE_SYSTEMD	0x80

/* list of last checks to perform, depending on config options */
#define LSTCHK_CAP_BIND	0x00000001	/* check that we can bind to any port */
#define LSTCHK_CTTPROXY	0x00000002	/* check that tproxy is enabled */
#define LSTCHK_NETADM	0x00000004	/* check that we have CAP_NET_ADMIN */

/* Global tuning options */
/* available polling mechanisms */
#define GTUNE_USE_SELECT         (1<<0)
#define GTUNE_USE_POLL           (1<<1)
#define GTUNE_USE_EPOLL          (1<<2)
#define GTUNE_USE_KQUEUE         (1<<3)
/* platform-specific options */
#define GTUNE_USE_SPLICE         (1<<4)
#define GTUNE_USE_GAI            (1<<5)

/* Access level for a stats socket */
#define ACCESS_LVL_NONE     0
#define ACCESS_LVL_USER     1
#define ACCESS_LVL_OPER     2
#define ACCESS_LVL_ADMIN    3

/* SSL server verify mode */
enum {
	SSL_SERVER_VERIFY_NONE = 0,
	SSL_SERVER_VERIFY_REQUIRED = 1,
};

/* FIXME : this will have to be redefined correctly */
struct global {
#ifdef USE_OPENSSL
	char *crt_base;             /* base directory path for certificates */
	char *ca_base;              /* base directory path for CAs and CRLs */
#endif
	int uid;
	int gid;
	int external_check;
	int nbproc;
	int maxconn, hardmaxconn;
	int maxsslconn;
	int ssl_session_max_cost;   /* how many bytes an SSL session may cost */
	int ssl_handshake_max_cost; /* how many bytes an SSL handshake may use */
	int ssl_used_frontend;      /* non-zero if SSL is used in a frontend */
	int ssl_used_backend;       /* non-zero if SSL is used in a backend */
#ifdef USE_OPENSSL
	char *listen_default_ciphers;
	char *connect_default_ciphers;
	int listen_default_ssloptions;
	int connect_default_ssloptions;
#endif
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
	int rlimit_memmax;	/* default ulimit-d in megs value : 0=unset */
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
	char *log_tag;                  /* name for syslog */
	struct list logsrvs;
	char *log_send_hostname;   /* set hostname in syslog header */
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
		int cookie_len;    /* max length of cookie captures */
		int pattern_cache; /* max number of entries in the pattern cache. */
		int sslcachesize;  /* SSL cache size in session, defaults to 20000 */
#ifdef USE_OPENSSL
		int sslprivatecache; /* Force to use a private session cache even if nbproc > 1 */
		unsigned int ssllifetime;   /* SSL session lifetime in seconds */
		unsigned int ssl_max_record; /* SSL max record size */
		unsigned int ssl_default_dh_param; /* SSL maximum DH parameter size */
		int ssl_ctx_cache; /* max number of entries in the ssl_ctx cache. */
#endif
#ifdef USE_ZLIB
		int zlibmemlevel;    /* zlib memlevel */
		int zlibwindowsize;  /* zlib window size */
#endif
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
#ifdef USE_CPU_AFFINITY
	unsigned long cpu_map[LONGBITS];  /* list of CPU masks for the 32/64 first processes */
#endif
	struct proxy *stats_fe;     /* the frontend holding the stats settings */
#ifdef USE_DEVICEATLAS
	struct {
		void *atlasimgptr;
		char *jsonpath;
		da_atlas_t atlas;
		da_evidence_id_t useragentid;
		da_severity_t loglevel;
		char separator;
	} deviceatlas;
#endif
#ifdef USE_51DEGREES
	struct {
		char property_separator;    /* the separator to use in the response for the values. this is taken from 51degrees-property-separator from config. */
		struct list property_names; /* list of properties to load into the data set. this is taken from 51degrees-property-name-list from config. */
		char *data_file_path;
#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
		fiftyoneDegreesDataSet data_set; /* data set used with the pattern detection method. */
#endif
		int cache_size;
	} _51degrees;
#endif
};

extern struct global global;
extern int  pid;                /* current process id */
extern int  relative_pid;       /* process id starting at 1 */
extern int  actconn;            /* # of active sessions */
extern int  listeners;
extern int  jobs;               /* # of active jobs */
extern struct chunk trash;
extern char *swap_buffer;
extern int nb_oldpids;          /* contains the number of old pids found */
extern const int zero;
extern const int one;
extern const struct linger nolinger;
extern int stopping;	/* non zero means stopping in progress */
extern char hostname[MAX_HOSTNAME_LEN];
extern char localpeer[MAX_HOSTNAME_LEN];
extern struct list global_listener_queue; /* list of the temporarily limited listeners */
extern struct task *global_listener_queue_task;
extern unsigned int warned;     /* bitfield of a few warnings to emit just once */
extern struct list dns_resolvers;

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

#endif /* _TYPES_GLOBAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
