/*
 * include/haproxy/counters-t.h
 * This file contains structure declarations for statistics counters.
 *
 * Copyright 2008-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
 * Copyright 2011-2014 Willy Tarreau <w@1wt.eu>
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

#ifndef _HAPROXY_COUNTERS_T_H
#define _HAPROXY_COUNTERS_T_H

#include <haproxy/freq_ctr-t.h>

#define COUNTERS_SHARED_F_NONE    0x0000
#define COUNTERS_SHARED_F_LOCAL   0x0001 // shared counter struct is actually process-local

// common to fe_counters_shared and be_counters_shared
#define COUNTERS_SHARED                                                              \
	struct {                                                                     \
		uint16_t flags;                         /* COUNTERS_SHARED_F flags */\
	};
#define COUNTERS_SHARED_TG                                                           \
	struct {                                                                     \
		unsigned long last_change;              /* last time, when the state was changed */\
		long long srv_aborts;                   /* aborted responses during DATA phase caused by the server */\
		long long cli_aborts;                   /* aborted responses during DATA phase caused by the client */\
		long long internal_errors;              /* internal processing errors */\
		long long failed_rewrites;              /* failed rewrites (warning) */\
		long long bytes_out;                    /* number of bytes transferred from the server to the client */\
		long long bytes_in;                     /* number of bytes transferred from the client to the server */\
		long long denied_resp;                  /* blocked responses because of security concerns */\
		long long denied_req;                   /* blocked requests because of security concerns */\
		long long    cum_sess;                  /* cumulated number of accepted connections */\
		/* compression counters, index 0 for requests, 1 for responses */\
		long long comp_in[2];                   /* input bytes fed to the compressor */\
		long long comp_out[2];                  /* output bytes emitted by the compressor */\
		long long comp_byp[2];                  /* input bytes that bypassed the compressor (cpu/ram/bw limitation) */\
		struct freq_ctr sess_per_sec;           /* sessions per second on this server */\
	}

// for convenience (generic pointer)
struct counters_shared {
	COUNTERS_SHARED;
	struct {
		COUNTERS_SHARED_TG;
	} *tg[MAX_TGROUPS];
};

/* counters used by listeners and frontends */
struct fe_counters_shared_tg {
	COUNTERS_SHARED_TG;

	long long denied_sess;                  /* denied session requests (tcp-req-sess rules) */
	long long denied_conn;                  /* denied connection requests (tcp-req-conn rules) */
	long long intercepted_req;              /* number of monitoring or stats requests intercepted by the frontend */
	long long    cum_conn;                  /* cumulated number of received connections */
	struct freq_ctr conn_per_sec;           /* received connections per second on the frontend */

	struct freq_ctr req_per_sec;            /* HTTP requests per second on the frontend */

	long long    cum_sess_ver[3];           /* cumulated number of h1/h2/h3 sessions */
	union {
		struct {
			long long cum_req[4];   /* cumulated number of processed other/h1/h2/h3 requests */
			long long cache_hits;   /* cache hits */
			long long cache_lookups;/* cache lookups */
			long long comp_rsp;     /* number of compressed responses */
			long long rsp[6];       /* http response codes */
		} http;
	} p;                                    /* protocol-specific stats */

	long long failed_req;                   /* failed requests (eg: invalid or timeout) */
};

struct fe_counters_shared {
	COUNTERS_SHARED;
	struct fe_counters_shared_tg *tg[MAX_TGROUPS];
};

struct fe_counters {
	struct fe_counters_shared *shared;      /* shared counters */
	unsigned int conn_max;                  /* max # of active sessions */

	unsigned int cps_max;                   /* maximum of new connections received per second */
	unsigned int sps_max;                   /* maximum of new connections accepted per second (sessions) */
	struct freq_ctr _sess_per_sec;          /* sessions per second on this frontend, used to compute sps_max (internal use only) */
	struct freq_ctr _conn_per_sec;          /* connections per second on this frontend, used to compute cps_max (internal use only) */

	union {
		struct {
			unsigned int rps_max;   /* maximum of new HTTP requests second observed */
			struct freq_ctr _req_per_sec; /* HTTP requests per second on the frontend, only used to compute rps_max */
		} http;
	} p;                                    /* protocol-specific stats */
};

struct be_counters_shared_tg {
	COUNTERS_SHARED_TG;

	long long  cum_lbconn;                  /* cumulated number of sessions processed by load balancing (BE only) */

	long long connect;                      /* number of connection establishment attempts */
	long long reuse;                        /* number of connection reuses */
	unsigned long last_sess;                /* last session time */

	long long failed_checks, failed_hana;	/* failed health checks and health analyses for servers */
	long long down_trans;			/* up->down transitions */

	union {
		struct {
			long long cum_req;      /* cumulated number of processed HTTP requests */

			long long cache_hits;   /* cache hits */
			long long cache_lookups;/* cache lookups */
			long long comp_rsp;     /* number of compressed responses */
			long long rsp[6];       /* http response codes */

		} http;
	} p;                                    /* protocol-specific stats */

	long long redispatches;                 /* retried and redispatched connections (BE only) */
	long long retries;                      /* retried and redispatched connections (BE only) */
	long long failed_resp;                  /* failed responses (BE only) */
	long long failed_conns;                 /* failed connect() attempts (BE only) */
};

struct be_counters_shared {
	COUNTERS_SHARED;
	struct be_counters_shared_tg *tg[MAX_TGROUPS];
};

/* counters used by servers and backends */
struct be_counters {
	struct be_counters_shared *shared;      /* shared counters */
	unsigned int conn_max;                  /* max # of active sessions */

	unsigned int cps_max;                   /* maximum of new connections received per second */
	unsigned int sps_max;                   /* maximum of new connections accepted per second (sessions) */
	unsigned int nbpend_max;                /* max number of pending connections with no server assigned yet */
	unsigned int cur_sess_max;		/* max number of currently active sessions */

	struct freq_ctr _sess_per_sec;          /* sessions per second on this frontend, used to compute sps_max (internal use only) */

	unsigned int q_time, c_time, d_time, t_time; /* sums of conn_time, queue_time, data_time, total_time */
	unsigned int qtime_max, ctime_max, dtime_max, ttime_max; /* maximum of conn_time, queue_time, data_time, total_time observed */

	union {
		struct {
			unsigned int rps_max;   /* maximum of new HTTP requests second observed */
		} http;
	} p;                                    /* protocol-specific stats */
};

#endif /* _HAPROXY_COUNTERS_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
