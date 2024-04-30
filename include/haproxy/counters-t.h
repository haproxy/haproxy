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

/* counters used by listeners and frontends */
struct fe_counters {
	unsigned int conn_max;                  /* max # of active sessions */
	long long    cum_conn;                  /* cumulated number of received connections */
	long long    cum_sess;                  /* cumulated number of accepted connections */
	long long    cum_sess_ver[3];           /* cumulated number of h1/h2/h3 sessions */

	unsigned int cps_max;                   /* maximum of new connections received per second */
	unsigned int sps_max;                   /* maximum of new connections accepted per second (sessions) */

	long long bytes_in;                     /* number of bytes transferred from the client to the server */
	long long bytes_out;                    /* number of bytes transferred from the server to the client */

	/* compression counters, index 0 for requests, 1 for responses */
	long long comp_in[2];                   /* input bytes fed to the compressor */
	long long comp_out[2];                  /* output bytes emitted by the compressor */
	long long comp_byp[2];                  /* input bytes that bypassed the compressor (cpu/ram/bw limitation) */

	long long denied_req;                   /* blocked requests because of security concerns */
	long long denied_resp;                  /* blocked responses because of security concerns */
	long long failed_req;                   /* failed requests (eg: invalid or timeout) */
	long long denied_conn;                  /* denied connection requests (tcp-req-conn rules) */
	long long denied_sess;                  /* denied session requests (tcp-req-sess rules) */
	long long failed_rewrites;              /* failed rewrites (warning) */
	long long internal_errors;              /* internal processing errors */

	long long cli_aborts;                   /* aborted responses during DATA phase caused by the client */
	long long srv_aborts;                   /* aborted responses during DATA phase caused by the server */
	long long intercepted_req;              /* number of monitoring or stats requests intercepted by the frontend */

	union {
		struct {
			long long cum_req[4];   /* cumulated number of processed other/h1/h2/h3 requests */
			long long comp_rsp;     /* number of compressed responses */
			unsigned int rps_max;   /* maximum of new HTTP requests second observed */
			long long rsp[6];       /* http response codes */
			long long cache_lookups;/* cache lookups */
			long long cache_hits;   /* cache hits */
		} http;
	} p;                                    /* protocol-specific stats */

	struct freq_ctr sess_per_sec;           /* sessions per second on this server */
	struct freq_ctr req_per_sec;            /* HTTP requests per second on the frontend */
	struct freq_ctr conn_per_sec;           /* received connections per second on the frontend */

	unsigned long last_change;              /* last time, when the state was changed */
};

/* counters used by servers and backends */
struct be_counters {
	unsigned int conn_max;                  /* max # of active sessions */
	long long    cum_sess;                  /* cumulated number of accepted connections */
	long long  cum_lbconn;                  /* cumulated number of sessions processed by load balancing (BE only) */

	unsigned int cps_max;                   /* maximum of new connections received per second */
	unsigned int sps_max;                   /* maximum of new connections accepted per second (sessions) */
	unsigned int nbpend_max;                /* max number of pending connections with no server assigned yet */
	unsigned int cur_sess_max;		/* max number of currently active sessions */

	long long bytes_in;                     /* number of bytes transferred from the client to the server */
	long long bytes_out;                    /* number of bytes transferred from the server to the client */

	/* compression counters, index 0 for requests, 1 for responses */
	long long comp_in[2];                   /* input bytes fed to the compressor */
	long long comp_out[2];                  /* output bytes emitted by the compressor */
	long long comp_byp[2];                  /* input bytes that bypassed the compressor (cpu/ram/bw limitation) */

	long long denied_req;                   /* blocked requests because of security concerns */
	long long denied_resp;                  /* blocked responses because of security concerns */

	long long connect;                      /* number of connection establishment attempts */
	long long reuse;                        /* number of connection reuses */
	long long failed_conns;                 /* failed connect() attempts (BE only) */
	long long failed_resp;                  /* failed responses (BE only) */
	long long cli_aborts;                   /* aborted responses during DATA phase caused by the client */
	long long srv_aborts;                   /* aborted responses during DATA phase caused by the server */
	long long retries;                      /* retried and redispatched connections (BE only) */
	long long redispatches;                 /* retried and redispatched connections (BE only) */
	long long failed_rewrites;              /* failed rewrites (warning) */
	long long internal_errors;              /* internal processing errors */

	long long failed_checks, failed_hana;	/* failed health checks and health analyses for servers */
	long long down_trans;			/* up->down transitions */

	unsigned int q_time, c_time, d_time, t_time; /* sums of conn_time, queue_time, data_time, total_time */
	unsigned int qtime_max, ctime_max, dtime_max, ttime_max; /* maximum of conn_time, queue_time, data_time, total_time observed */

	union {
		struct {
			long long cum_req;      /* cumulated number of processed HTTP requests */
			long long comp_rsp;     /* number of compressed responses */
			unsigned int rps_max;   /* maximum of new HTTP requests second observed */
			long long rsp[6];       /* http response codes */
			long long cache_lookups;/* cache lookups */
			long long cache_hits;   /* cache hits */
		} http;
	} p;                                    /* protocol-specific stats */

	struct freq_ctr sess_per_sec;           /* sessions per second on this server */

	unsigned long last_sess;                /* last session time */
	unsigned long last_change;              /* last time, when the state was changed */
};

#endif /* _HAPROXY_COUNTERS_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
