/*
  include/types/counters.h
  This file contains structure declarations for statistics counters.

  Copyright 2008-2009 Krzysztof Piotr Oledzki <ole@ans.pl>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_COUNTERS_H
#define _TYPES_COUNTERS_H

struct pxcounters {
	unsigned int feconn_max, beconn_max;	/* max # of active frontend and backend sessions */

	long long cum_feconn, cum_beconn;	/* cumulated number of processed sessions */
	long long cum_lbconn;			/* cumulated number of sessions processed by load balancing */

	unsigned int fe_sps_max;		/* maximum of new sessions per second seen on the frontend */
	unsigned int be_sps_max;		/* maximum of new sessions per second seen on the backend */
	unsigned int nbpend_max;		/* max number of pending connections with no server assigned yet */

	long long bytes_in;			/* number of bytes transferred from the client to the server */
	long long bytes_out;			/* number of bytes transferred from the server to the client */

	long long denied_req, denied_resp;	/* blocked requests/responses because of security concerns */
	long long failed_req;			/* failed requests (eg: invalid or timeout) */

	union {
		struct {
			long long rsp[6];		/* http resonse codes */
		} http;
	} p;

	long long failed_conns, failed_resp;	/* failed connect() and responses */
	long long retries, redispatches;	/* retried and redispatched connections */
};

struct licounters {
	unsigned int conn_max;			/* max # of active listener sessions */

	long long cum_conn;			/* cumulated number of processed sessions */

	long long bytes_in;			/* number of bytes transferred from the client to the server */
	long long bytes_out;			/* number of bytes transferred from the server to the client */

	long long denied_req, denied_resp;	/* blocked requests/responses because of security concerns */
	long long failed_req;			/* failed requests (eg: invalid or timeout) */
};

struct srvcounters {
	unsigned int cur_sess_max;		/* max number of currently active sessions */
	unsigned int nbpend_max;		/* max number of pending connections reached */
	unsigned int sps_max;			/* maximum of new sessions per second seen on this server */

	long long cum_sess;			/* cumulated number of sessions really sent to this server */
	long long cum_lbconn;			/* cumulated number of sessions directed by load balancing */

	long long bytes_in;			/* number of bytes transferred from the client to the server */
	long long bytes_out;			/* number of bytes transferred from the server to the client */

	long long failed_conns, failed_resp;	/* failed connect() and responses */
	long long retries, redispatches;	/* retried and redispatched connections */
	long long failed_secu;			/* blocked responses because of security concerns */

	union {
		struct {
			long long rsp[6];		/* http resonse codes */
		} http;
	} p;

	long long failed_checks, down_trans;	/* failed checks and up->down transitions */
};

#endif /* _TYPES_COUNTERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
