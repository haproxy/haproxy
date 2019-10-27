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
#include <common/initcall.h>
#include <common/hathreads.h>
#include <common/standard.h>

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
#define	MODE_MWORKER_WAIT	0x100    /* Master Worker wait mode */

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

#define GTUNE_BUSY_POLLING       (1<<11)
#define GTUNE_LISTENER_MQ        (1<<12)
#define GTUNE_SET_DUMPABLE       (1<<13)
#define GTUNE_USE_EVPORTS        (1<<14)
#define GTUNE_STRICT_LIMITS      (1<<15)

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
	struct freq_ctr out_32bps;      /* #of 32-byte blocks emitted per second */
	unsigned long long out_bytes;   /* total #of bytes emitted */
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
	struct buffer log_tag;           /* name for syslog */
	struct list logsrvs;
	char *log_send_hostname;   /* set hostname in syslog header */
	char *server_state_base;   /* path to a directory where server state files can be found */
	char *server_state_file;   /* path to the file where server states are loaded from */
	struct {
		int maxpollevents; /* max number of poll events at once */
		int maxaccept;     /* max number of consecutive accept() */
		int options;       /* various tuning options */
		int runqueue_depth;/* max number of tasks to run at once */
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
		int pool_low_ratio;   /* max ratio of FDs used before we stop using new idle connections */
		int pool_high_ratio;  /* max ratio of FDs used before we start killing idle connections when creating new connections */
		int pool_low_count;   /* max number of opened fd before we stop using new idle connections */
		int pool_high_count;  /* max number of opened fd before we start killing idle connections when creating new connections */
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
		unsigned long proc[MAX_PROCS];      /* list of CPU masks for the 32/64 first processes */
		unsigned long proc_t1[MAX_PROCS];   /* list of CPU masks for the 1st thread of each process */
		unsigned long thread[MAX_THREADS];  /* list of CPU masks for the 32/64 first threads of the 1st process */
	} cpu_map;
#endif
};

/* options for mworker_proc */

#define PROC_O_TYPE_MASTER           0x00000001
#define PROC_O_TYPE_WORKER           0x00000002
#define PROC_O_TYPE_PROG             0x00000004
/* 0x00000008 unused */
#define PROC_O_LEAVING               0x00000010  /* this process should be leaving */
/* 0x00000020 to 0x00000080 unused */
#define PROC_O_START_RELOAD          0x00000100  /* Start the process even if the master was re-executed */

/*
 * Structure used to describe the processes in master worker mode
 */
struct mworker_proc {
	int pid;
	int options;
	char *id;
	char **command;
	char *path;
	char *version;
	int ipc_fd[2]; /* 0 is master side, 1 is worker side */
	int relative_pid;
	int reloads;
	int timestamp;
	struct server *srv; /* the server entry in the master proxy */
	struct list list;
	int uid;
	int gid;
};

extern struct global global;
extern int  pid;                /* current process id */
extern int  relative_pid;       /* process id starting at 1 */
extern unsigned long pid_bit;   /* bit corresponding to the process id */
extern unsigned long all_proc_mask; /* mask of all processes */
extern int  actconn;            /* # of active sessions */
extern int  listeners;
extern int  jobs;               /* # of active jobs (listeners, sessions, open devices) */
extern int  unstoppable_jobs;   /* # of active jobs that can't be stopped during a soft stop */
extern int  active_peers;       /* # of active peers (connection attempts and successes) */
extern int  connected_peers;    /* # of really connected peers */
extern THREAD_LOCAL struct buffer trash;
extern int nb_oldpids;          /* contains the number of old pids found */
extern const int zero;
extern const int one;
extern const struct linger nolinger;
extern int stopping;	/* non zero means stopping in progress */
extern int killed;	/* >0 means a hard-stop is triggered, >1 means hard-stop immediately */
extern char hostname[MAX_HOSTNAME_LEN];
extern char localpeer[MAX_HOSTNAME_LEN];
extern struct mt_list global_listener_queue; /* list of the temporarily limited listeners */
extern struct task *global_listener_queue_task;
extern unsigned int warned;     /* bitfield of a few warnings to emit just once */
extern volatile unsigned long sleeping_thread_mask;
extern struct list proc_list; /* list of process in mworker mode */
extern struct mworker_proc *proc_self; /* process structure of current process */
extern int master; /* 1 if in master, 0 otherwise */
extern unsigned int rlim_fd_cur_at_boot;
extern unsigned int rlim_fd_max_at_boot;
extern int atexit_flag;

/* bit values to go with "warned" above */
/* unassigned : 0x00000001 (previously: WARN_BLOCK_DEPRECATED) */
/* unassigned : 0x00000002 */
/* unassigned : 0x00000004 (previously: WARN_REDISPATCH_DEPRECATED) */
/* unassigned : 0x00000008 (previously: WARN_CLITO_DEPRECATED) */
/* unassigned : 0x00000010 (previously: WARN_SRVTO_DEPRECATED) */
/* unassigned : 0x00000020 (previously: WARN_CONTO_DEPRECATED) */
#define WARN_FORCECLOSE_DEPRECATED  0x00000040


/* to be used with warned and WARN_* */
static inline int already_warned(unsigned int warning)
{
	if (warned & warning)
		return 1;
	warned |= warning;
	return 0;
}

/* returns a mask if set, otherwise all_proc_mask */
static inline unsigned long proc_mask(unsigned long mask)
{
	return mask ? mask : all_proc_mask;
}

/* returns a mask if set, otherwise all_threads_mask */
static inline unsigned long thread_mask(unsigned long mask)
{
	return mask ? mask : all_threads_mask;
}

int tell_old_pids(int sig);
int delete_oldpid(int pid);

void deinit(void);
void hap_register_build_opts(const char *str, int must_free);
void hap_register_post_check(int (*fct)());
void hap_register_post_proxy_check(int (*fct)(struct proxy *));
void hap_register_post_server_check(int (*fct)(struct server *));
void hap_register_post_deinit(void (*fct)());
void hap_register_proxy_deinit(void (*fct)(struct proxy *));
void hap_register_server_deinit(void (*fct)(struct server *));

void hap_register_per_thread_alloc(int (*fct)());
void hap_register_per_thread_init(int (*fct)());
void hap_register_per_thread_deinit(void (*fct)());
void hap_register_per_thread_free(int (*fct)());

void mworker_accept_wrapper(int fd);
void mworker_reload();

/* simplified way to declare static build options in a file */
#define REGISTER_BUILD_OPTS(str) \
	INITCALL2(STG_REGISTER, hap_register_build_opts, (str), 0)

/* simplified way to declare a post-check callback in a file */
#define REGISTER_POST_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_check, (fct))

/* simplified way to declare a post-proxy-check callback in a file */
#define REGISTER_POST_PROXY_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_proxy_check, (fct))

/* simplified way to declare a post-server-check callback in a file */
#define REGISTER_POST_SERVER_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_server_check, (fct))

/* simplified way to declare a post-deinit callback in a file */
#define REGISTER_POST_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_deinit, (fct))

/* simplified way to declare a proxy-deinit callback in a file */
#define REGISTER_PROXY_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_proxy_deinit, (fct))

/* simplified way to declare a proxy-deinit callback in a file */
#define REGISTER_SERVER_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_server_deinit, (fct))

/* simplified way to declare a per-thread allocation callback in a file */
#define REGISTER_PER_THREAD_ALLOC(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_alloc, (fct))

/* simplified way to declare a per-thread init callback in a file */
#define REGISTER_PER_THREAD_INIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_init, (fct))

/* simplified way to declare a per-thread deinit callback in a file */
#define REGISTER_PER_THREAD_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_deinit, (fct))

/* simplified way to declare a per-thread free callback in a file */
#define REGISTER_PER_THREAD_FREE(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_free, (fct))

#endif /* _TYPES_GLOBAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
