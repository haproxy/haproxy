/*
 * include/types/session.h
 * This file defines everything related to sessions.
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

#ifndef _TYPES_SESSION_H
#define _TYPES_SESSION_H


#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/config.h>
#include <common/mini-clist.h>

#include <types/channel.h>
#include <types/compression.h>

#include <types/obj_type.h>
#include <types/proto_http.h>
#include <types/proxy.h>
#include <types/queue.h>
#include <types/server.h>
#include <types/stream_interface.h>
#include <types/task.h>
#include <types/stick_table.h>


/* various session flags, bits values 0x01 to 0x100 (shift 0) */
#define SN_DIRECT	0x00000001	/* connection made on the server matching the client cookie */
#define SN_ASSIGNED	0x00000002	/* no need to assign a server to this session */
#define SN_ADDR_SET	0x00000004	/* this session's server address has been set */
#define SN_BE_ASSIGNED	0x00000008	/* a backend was assigned. Conns are accounted. */

#define SN_FORCE_PRST	0x00000010	/* force persistence here, even if server is down */
#define SN_MONITOR	0x00000020	/* this session comes from a monitoring system */
#define SN_CURR_SESS	0x00000040	/* a connection is currently being counted on the server */
#define SN_INITIALIZED	0x00000080	/* the session was fully initialized */
#define SN_REDISP	0x00000100	/* set if this session was redispatched from one server to another */
#define SN_CONN_TAR	0x00000200	/* set if this session is turning around before reconnecting */
#define SN_REDIRECTABLE	0x00000400	/* set if this session is redirectable (GET or HEAD) */
#define SN_TUNNEL	0x00000800	/* tunnel-mode session, nothing to catch after data */

/* session termination conditions, bits values 0x1000 to 0x7000 (0-9 shift 12) */
#define SN_ERR_NONE     0x00000000	/* normal end of request */
#define SN_ERR_LOCAL    0x00001000	/* the proxy locally processed this request => not an error */
#define SN_ERR_CLITO    0x00002000	/* client time-out */
#define SN_ERR_CLICL    0x00003000	/* client closed (read/write error) */
#define SN_ERR_SRVTO    0x00004000	/* server time-out, connect time-out */
#define SN_ERR_SRVCL    0x00005000	/* server closed (connect/read/write error) */
#define SN_ERR_PRXCOND  0x00006000	/* the proxy decided to close (deny...) */
#define SN_ERR_RESOURCE 0x00007000	/* the proxy encountered a lack of a local resources (fd, mem, ...) */
#define SN_ERR_INTERNAL 0x00008000	/* the proxy encountered an internal error */
#define SN_ERR_DOWN     0x00009000	/* the proxy killed a session because the backend became unavailable */
#define SN_ERR_KILLED   0x0000a000	/* the proxy killed a session because it was asked to do so */
#define SN_ERR_UP       0x0000b000	/* the proxy killed a session because a preferred backend became available */
#define SN_ERR_MASK     0x0000f000	/* mask to get only session error flags */
#define SN_ERR_SHIFT    12		/* bit shift */

/* session state at termination, bits values 0x10000 to 0x70000 (0-7 shift 16) */
#define SN_FINST_R	0x00010000	/* session ended during client request */
#define SN_FINST_C	0x00020000	/* session ended during server connect */
#define SN_FINST_H	0x00030000	/* session ended during server headers */
#define SN_FINST_D	0x00040000	/* session ended during data phase */
#define SN_FINST_L	0x00050000	/* session ended while pushing last data to client */
#define SN_FINST_Q	0x00060000	/* session ended while waiting in queue for a server slot */
#define SN_FINST_T	0x00070000	/* session ended tarpitted */
#define SN_FINST_MASK	0x00070000	/* mask to get only final session state flags */
#define	SN_FINST_SHIFT	16		/* bit shift */

#define SN_IGNORE_PRST	0x00080000	/* ignore persistence */

#define SN_COMP_READY   0x00100000	/* the compression is initialized */
#define SN_SRV_REUSED   0x00200000	/* the server-side connection was reused */

/* WARNING: if new fields are added, they must be initialized in session_accept()
 * and freed in session_free() !
 */

#define STKCTR_TRACK_BACKEND 1
#define STKCTR_TRACK_CONTENT 2
/* stick counter. The <entry> member is a composite address (caddr) made of a
 * pointer to an stksess struct, and two flags among STKCTR_TRACK_* above.
 */
struct stkctr {
	unsigned long   entry;          /* entry containing counters currently being tracked by this session  */
	struct stktable *table;         /* table the counters above belong to (undefined if counters are null) */
};

/*
 * Note: some session flags have dependencies :
 *  - SN_DIRECT cannot exist without SN_ASSIGNED, because a server is
 *    immediately assigned when SN_DIRECT is determined. Both must be cleared
 *    when clearing SN_DIRECT (eg: redispatch).
 *  - ->srv has no meaning without SN_ASSIGNED and must not be checked without
 *    it. ->target may be used to check previous ->srv after a failed connection attempt.
 *  - a session being processed has srv_conn set.
 *  - srv_conn might remain after SN_DIRECT has been reset, but the assigned
 *    server should eventually be released.
 */
struct session {
	int flags;				/* some flags describing the session */
	unsigned int uniq_id;			/* unique ID used for the traces */
	enum obj_type *target;			/* target to use for this session ; for mini-sess: incoming connection */

	struct channel *req;			/* request buffer */
	struct channel *rep;			/* response buffer */

	struct proxy *fe;			/* the proxy this session depends on for the client side */
	struct proxy *be;			/* the proxy this session depends on for the server side */

	struct listener *listener;		/* the listener by which the request arrived */
	struct server *srv_conn;		/* session already has a slot on a server and is not in queue */
	struct pendconn *pend_pos;		/* if not NULL, points to the position in the pending queue */

	struct http_txn txn;			/* current HTTP transaction being processed. Should become a list. */

	struct task *task;			/* the task associated with this session */
	struct list list;			/* position in global sessions list */
	struct list by_srv;			/* position in server session list */
	struct list back_refs;			/* list of users tracking this session */

	struct {
		struct stksess *ts;
		struct stktable *table;
	} store[8];				/* tracked stickiness values to store */
	int store_count;
	/* 4 unused bytes here */

	struct stkctr stkctr[MAX_SESS_STKCTR];  /* stick counters */

	struct stream_interface si[2];          /* client and server stream interfaces */
	struct {
		int logwait;			/* log fields waiting to be collected : LW_* */
		int level;			/* log level to force + 1 if > 0, -1 = no log */
		struct timeval accept_date;	/* date of the accept() in user date */
		struct timeval tv_accept;	/* date of the accept() in internal date (monotonic) */
		struct timeval tv_request;	/* date the request arrives, {0,0} if never occurs */
		long  t_queue;			/* delay before the session gets out of the connect queue, -1 if never occurs */
		long  t_connect;		/* delay before the connect() to the server succeeds, -1 if never occurs */
		long  t_data;			/* delay before the first data byte from the server ... */
		unsigned long t_close;		/* total session duration */
		unsigned long srv_queue_size;	/* number of sessions waiting for a connect slot on this server at accept() time (in direct assignment) */
		unsigned long prx_queue_size;	/* overall number of sessions waiting for a connect slot on this instance at accept() time */
		long long bytes_in;		/* number of bytes transferred from the client to the server */
		long long bytes_out;		/* number of bytes transferred from the server to the client */
	} logs;
	void (*do_log)(struct session *s);	/* the function to call in order to log (or NULL) */
	void (*srv_error)(struct session *s,	/* the function to call upon unrecoverable server errors (or NULL) */
			  struct stream_interface *si);
	struct comp_ctx *comp_ctx;		/* HTTP compression context */
	struct comp_algo *comp_algo;		/* HTTP compression algorithm if not NULL */
	char *unique_id;			/* custom unique ID */
};

/* parameters to configure tracked counters */
struct track_ctr_prm {
	struct sample_expr *expr;		/* expression used as the key */
	union {
		struct stktable *t;		/* a pointer to the table */
		char *n;			/* or its name during parsing. */
	} table;
};


#endif /* _TYPES_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
