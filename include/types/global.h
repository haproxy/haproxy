/*
 * include/types/global.h
 * Global variables.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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
#include <types/log.h>
#include <types/protocols.h>
#include <types/proxy.h>
#include <types/task.h>

/* modes of operation (global.mode) */
#define	MODE_DEBUG	0x01
#define	MODE_DAEMON	0x02
#define	MODE_QUIET	0x04
#define	MODE_CHECK	0x08
#define	MODE_VERBOSE	0x10
#define	MODE_STARTING	0x20
#define	MODE_FOREGROUND	0x40

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
#define GTUNE_USE_SEPOLL         (1<<4)
/* platform-specific options */
#define GTUNE_USE_SPLICE         (1<<5)

/* Access level for a stats socket */
#define ACCESS_LVL_NONE     0
#define ACCESS_LVL_USER     1
#define ACCESS_LVL_OPER     2
#define ACCESS_LVL_ADMIN    3

/* FIXME : this will have to be redefined correctly */
struct global {
	int uid;
	int gid;
	int nbproc;
	int maxconn, hardmaxconn;
	struct freq_ctr conn_per_sec;
	int cps_lim, cps_max;
	int maxpipes;		/* max # of pipes */
	int maxsock;		/* max # of sockets */
	int rlimit_nofile;	/* default ulimit-n value : 0=unset */
	int rlimit_memmax;	/* default ulimit-d in megs value : 0=unset */
	int mode;
	unsigned int req_count; /* HTTP request counter */
	int last_checks;
	int spread_checks;
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
		int client_sndbuf; /* set client sndbuf to this value if not null */
		int client_rcvbuf; /* set client rcvbuf to this value if not null */
		int server_sndbuf; /* set server sndbuf to this value if not null */
		int server_rcvbuf; /* set server rcvbuf to this value if not null */
		int chksize;       /* check buffer size in bytes, defaults to BUFSIZE */
		int pipesize;      /* pipe size in bytes, system defaults if zero */
		int max_http_hdr;  /* max number of HTTP headers, use MAX_HTTP_HDR if zero */
	} tune;
	struct {
		char *prefix;           /* path prefix of unix bind socket */
		struct {                /* UNIX socket permissions */
			uid_t uid;      /* -1 to leave unchanged */
			gid_t gid;      /* -1 to leave unchanged */
			mode_t mode;    /* 0 to leave unchanged */
			int level;      /* access level (ACCESS_LVL_*) */
		} ux;
	} unix_bind;
	struct listener stats_sock; /* unix socket listener for statistics */
	struct proxy *stats_fe;     /* the frontend holding the stats settings */
};

extern struct global global;
extern int  pid;                /* current process id */
extern int  relative_pid;       /* process id starting at 1 */
extern int  actconn;            /* # of active sessions */
extern int  listeners;
extern int  jobs;               /* # of active jobs */
extern char trash[BUFSIZE];
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

#endif /* _TYPES_GLOBAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
