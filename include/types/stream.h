/*
 * include/types/stream.h
 * This file defines everything related to streams.
 *
 * Copyright (C) 2000-2015 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_STREAM_H
#define _TYPES_STREAM_H


#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/config.h>
#include <common/mini-clist.h>

#include <types/channel.h>
#include <types/compression.h>
#include <types/hlua.h>
#include <types/obj_type.h>
#include <types/proto_http.h>
#include <types/proxy.h>
#include <types/queue.h>
#include <types/server.h>
#include <types/session.h>
#include <types/stream_interface.h>
#include <types/task.h>
#include <types/stick_table.h>
#include <types/vars.h>


/* Various Stream Flags, bits values 0x01 to 0x100 (shift 0) */
#define SF_DIRECT	0x00000001	/* connection made on the server matching the client cookie */
#define SF_ASSIGNED	0x00000002	/* no need to assign a server to this stream */
#define SF_ADDR_SET	0x00000004	/* this stream's server address has been set */
#define SF_BE_ASSIGNED	0x00000008	/* a backend was assigned. Conns are accounted. */

#define SF_FORCE_PRST	0x00000010	/* force persistence here, even if server is down */
#define SF_MONITOR	0x00000020	/* this stream comes from a monitoring system */
#define SF_CURR_SESS	0x00000040	/* a connection is currently being counted on the server */
#define SF_INITIALIZED	0x00000080	/* the stream was fully initialized */
#define SF_REDISP	0x00000100	/* set if this stream was redispatched from one server to another */
#define SF_CONN_TAR	0x00000200	/* set if this stream is turning around before reconnecting */
#define SF_REDIRECTABLE	0x00000400	/* set if this stream is redirectable (GET or HEAD) */
#define SF_TUNNEL	0x00000800	/* tunnel-mode stream, nothing to catch after data */

/* stream termination conditions, bits values 0x1000 to 0x7000 (0-9 shift 12) */
#define SF_ERR_NONE     0x00000000	/* normal end of request */
#define SF_ERR_LOCAL    0x00001000	/* the proxy locally processed this request => not an error */
#define SF_ERR_CLITO    0x00002000	/* client time-out */
#define SF_ERR_CLICL    0x00003000	/* client closed (read/write error) */
#define SF_ERR_SRVTO    0x00004000	/* server time-out, connect time-out */
#define SF_ERR_SRVCL    0x00005000	/* server closed (connect/read/write error) */
#define SF_ERR_PRXCOND  0x00006000	/* the proxy decided to close (deny...) */
#define SF_ERR_RESOURCE 0x00007000	/* the proxy encountered a lack of a local resources (fd, mem, ...) */
#define SF_ERR_INTERNAL 0x00008000	/* the proxy encountered an internal error */
#define SF_ERR_DOWN     0x00009000	/* the proxy killed a stream because the backend became unavailable */
#define SF_ERR_KILLED   0x0000a000	/* the proxy killed a stream because it was asked to do so */
#define SF_ERR_UP       0x0000b000	/* the proxy killed a stream because a preferred backend became available */
#define SF_ERR_MASK     0x0000f000	/* mask to get only stream error flags */
#define SF_ERR_SHIFT    12		/* bit shift */

/* stream state at termination, bits values 0x10000 to 0x70000 (0-7 shift 16) */
#define SF_FINST_R	0x00010000	/* stream ended during client request */
#define SF_FINST_C	0x00020000	/* stream ended during server connect */
#define SF_FINST_H	0x00030000	/* stream ended during server headers */
#define SF_FINST_D	0x00040000	/* stream ended during data phase */
#define SF_FINST_L	0x00050000	/* stream ended while pushing last data to client */
#define SF_FINST_Q	0x00060000	/* stream ended while waiting in queue for a server slot */
#define SF_FINST_T	0x00070000	/* stream ended tarpitted */
#define SF_FINST_MASK	0x00070000	/* mask to get only final stream state flags */
#define	SF_FINST_SHIFT	16		/* bit shift */

#define SF_IGNORE_PRST	0x00080000	/* ignore persistence */

#define SF_COMP_READY   0x00100000	/* the compression is initialized */
#define SF_SRV_REUSED   0x00200000	/* the server-side connection was reused */

/* some external definitions */
struct strm_logs {
	int logwait;                    /* log fields waiting to be collected : LW_* */
	int level;                      /* log level to force + 1 if > 0, -1 = no log */
	struct timeval accept_date;     /* date of the stream's accept() in user date */
	struct timeval tv_accept;       /* date of the stream's accept() in internal date (monotonic) */
	struct timeval tv_request;      /* date the request arrives, {0,0} if never occurs */
	long  t_queue;                  /* delay before the stream gets out of the connect queue, -1 if never occurs */
	long  t_connect;                /* delay before the connect() to the server succeeds, -1 if never occurs */
	long  t_data;                   /* delay before the first data byte from the server ... */
	unsigned long t_close;          /* total stream duration */
	unsigned long srv_queue_size;   /* number of streams waiting for a connect slot on this server at accept() time (in direct assignment) */
	unsigned long prx_queue_size;   /* overall number of streams waiting for a connect slot on this instance at accept() time */
	long long bytes_in;             /* number of bytes transferred from the client to the server */
	long long bytes_out;            /* number of bytes transferred from the server to the client */
};

struct stream {
	int flags;                      /* some flags describing the stream */
	unsigned int uniq_id;           /* unique ID used for the traces */
	enum obj_type *target;          /* target to use for this stream */

	struct channel req;             /* request channel */
	struct channel res;             /* response channel */

	struct proxy *be;               /* the proxy this stream depends on for the server side */

	struct session *sess;           /* the session this stream is attached to */

	struct server *srv_conn;        /* stream already has a slot on a server and is not in queue */
	struct pendconn *pend_pos;      /* if not NULL, points to the position in the pending queue */

	struct http_txn *txn;           /* current HTTP transaction being processed. Should become a list. */

	struct task *task;              /* the task associated with this stream */
	struct list list;               /* position in global streams list */
	struct list by_srv;             /* position in server stream list */
	struct list back_refs;          /* list of users tracking this stream */
	struct list buffer_wait;        /* position in the list of streams waiting for a buffer */

	struct {
		struct stksess *ts;
		struct stktable *table;
	} store[8];                     /* tracked stickiness values to store */
	int store_count;
	/* 4 unused bytes here */

	struct stkctr stkctr[MAX_SESS_STKCTR];  /* content-aware stick counters */

	char **req_cap;                         /* array of captures from the request (may be NULL) */
	char **res_cap;                         /* array of captures from the response (may be NULL) */
	struct vars vars_txn;                   /* list of variables for the txn scope. */
	struct vars vars_reqres;                /* list of variables for the request and resp scope. */

	struct stream_interface si[2];          /* client and server stream interfaces */
	struct strm_logs logs;                  /* logs for this stream */

	void (*do_log)(struct stream *s);       /* the function to call in order to log (or NULL) */
	void (*srv_error)(struct stream *s,     /* the function to call upon unrecoverable server errors (or NULL) */
			  struct stream_interface *si);
	struct comp_ctx *comp_ctx;              /* HTTP compression context */
	struct comp_algo *comp_algo;            /* HTTP compression algorithm if not NULL */
	char *unique_id;                        /* custom unique ID */

	/* These two pointers are used to resume the execution of the rule lists. */
	struct list *current_rule_list;         /* this is used to store the current executed rule list. */
	void *current_rule;                     /* this is used to store the current rule to be resumed. */
	struct hlua hlua;                       /* lua runtime context */
};

#endif /* _TYPES_STREAM_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
