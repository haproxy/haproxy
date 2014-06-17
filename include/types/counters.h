/*
 * include/types/counters.h
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

#ifndef _TYPES_COUNTERS_H
#define _TYPES_COUNTERS_H

/* maybe later we might thing about having a different struct for FE and BE */
struct pxcounters {
	unsigned int conn_max;                  /* max # of active sessions */
	long long    cum_conn;                  /* cumulated number of received connections */
	long long    cum_sess;                  /* cumulated number of accepted connections */
	long long  cum_lbconn;                  /* cumulated number of sessions processed by load balancing (BE only) */
	unsigned long last_sess;                /* last session time */

	unsigned int cps_max;                   /* maximum of new connections received per second */
	unsigned int sps_max;                   /* maximum of new connections accepted per second (sessions) */
	unsigned int nbpend_max;                /* max number of pending connections with no server assigned yet (BE only) */

	long long bytes_in;                     /* number of bytes transferred from the client to the server */
	long long bytes_out;                    /* number of bytes transferred from the server to the client */

	long long comp_in;                      /* input bytes fed to the compressor */
	long long comp_out;                     /* output bytes emitted by the compressor */
	long long comp_byp;                     /* input bytes that bypassed the compressor (cpu/ram/bw limitation) */

	long long denied_req;                   /* blocked requests/responses because of security concerns */
	long long denied_resp;                  /* blocked requests/responses because of security concerns */
	long long failed_req;                   /* failed requests (eg: invalid or timeout) */
	long long denied_conn;                  /* denied connection requests (tcp-req rules) */

	long long failed_conns;                 /* failed connect() attempts (BE only) */
	long long failed_resp;                  /* failed responses (BE only) */
	long long cli_aborts;                   /* aborted responses during DATA phase caused by the client */
	long long srv_aborts;                   /* aborted responses during DATA phase caused by the server */
	long long retries;                      /* retried and redispatched connections (BE only) */
	long long redispatches;                 /* retried and redispatched connections (BE only) */
	long long intercepted_req;              /* number of monitoring or stats requests intercepted by the frontend */

	unsigned int q_time, c_time, d_time, t_time; /* sums of conn_time, queue_time, data_time, total_time */

	union {
		struct {
			long long cum_req;      /* cumulated number of processed HTTP requests */
			long long comp_rsp;     /* number of compressed responses */
			unsigned int rps_max;   /* maximum of new HTTP requests second observed */
			long long rsp[6];       /* http response codes */
		} http;
	} p;                                    /* protocol-specific stats */
};

struct licounters {
	unsigned int conn_max;			/* max # of active listener sessions */

	long long cum_conn;			/* cumulated number of received connections */
	long long cum_sess;			/* cumulated number of accepted sessions */

	long long bytes_in;			/* number of bytes transferred from the client to the server */
	long long bytes_out;			/* number of bytes transferred from the server to the client */

	long long denied_req, denied_resp;	/* blocked requests/responses because of security concerns */
	long long failed_req;			/* failed requests (eg: invalid or timeout) */
	long long denied_conn;			/* denied connection requests (tcp-req rules) */
};

struct srvcounters {
	unsigned int cur_sess_max;		/* max number of currently active sessions */
	unsigned int nbpend_max;		/* max number of pending connections reached */
	unsigned int sps_max;			/* maximum of new sessions per second seen on this server */

	long long cum_sess;			/* cumulated number of sessions really sent to this server */
	long long cum_lbconn;			/* cumulated number of sessions directed by load balancing */
	unsigned long last_sess;                 /* last session time */

	long long bytes_in;			/* number of bytes transferred from the client to the server */
	long long bytes_out;			/* number of bytes transferred from the server to the client */

	long long failed_conns, failed_resp;	/* failed connect() and responses */
	long long cli_aborts, srv_aborts;	/* aborted responses during DATA phase due to client or server */
	long long retries, redispatches;	/* retried and redispatched connections */
	long long failed_secu;			/* blocked responses because of security concerns */

	unsigned int q_time, c_time, d_time, t_time; /* sums of conn_time, queue_time, data_time, total_time */

	union {
		struct {
			long long rsp[6];	/* http response codes */
		} http;
	} p;

	long long failed_checks, failed_hana;	/* failed health checks and health analyses */
	long long down_trans;			/* up->down transitions */
};

#endif /* _TYPES_COUNTERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
