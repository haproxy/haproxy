/*
  include/types/session.h
  This file defines everything related to sessions.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_SESSION_H
#define _TYPES_SESSION_H


#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/config.h>
#include <common/mini-clist.h>

#include <types/buffers.h>
#include <types/proto_http.h>
#include <types/proxy.h>
#include <types/queue.h>
#include <types/server.h>
#include <types/task.h>


/* various session flags, bits values 0x01 to 0x20 (shift 0) */
#define SN_DIRECT	0x00000001	/* connection made on the server matching the client cookie */
#define SN_ASSIGNED	0x00000002	/* no need to assign a server to this session */
#define SN_ADDR_SET	0x00000004	/* this session's server address has been set */
#define SN_BE_ASSIGNED	0x00000008	/* a backend was assigned. Conns are accounted. */
#define SN_CONN_CLOSED	0x00000010	/* "Connection: close" was present or added */
#define SN_MONITOR	0x00000020	/* this session comes from a monitoring system */
#define SN_SELF_GEN	0x00000040	/* the proxy generates data for the client (eg: stats) */
#define SN_FRT_ADDR_SET	0x00000080	/* set if the frontend address has been filled */

/* session termination conditions, bits values 0x100 to 0x700 (0-7 shift 8) */
#define SN_ERR_NONE     0x00000000
#define SN_ERR_CLITO	0x00000100	/* client time-out */
#define SN_ERR_CLICL	0x00000200	/* client closed (read/write error) */
#define SN_ERR_SRVTO	0x00000300	/* server time-out, connect time-out */
#define SN_ERR_SRVCL	0x00000400	/* server closed (connect/read/write error) */
#define SN_ERR_PRXCOND	0x00000500	/* the proxy decided to close (deny...) */
#define SN_ERR_RESOURCE	0x00000600	/* the proxy encountered a lack of a local resources (fd, mem, ...) */
#define SN_ERR_INTERNAL	0x00000700	/* the proxy encountered an internal error */
#define SN_ERR_MASK	0x00000700	/* mask to get only session error flags */
#define SN_ERR_SHIFT	8		/* bit shift */
/* unused:              0x00000800 */

/* session state at termination, bits values 0x1000 to 0x7000 (0-7 shift 12) */
#define SN_FINST_R	0x00001000	/* session ended during client request */
#define SN_FINST_C	0x00002000	/* session ended during server connect */
#define SN_FINST_H	0x00003000	/* session ended during server headers */
#define SN_FINST_D	0x00004000	/* session ended during data phase */
#define SN_FINST_L	0x00005000	/* session ended while pushing last data to client */
#define SN_FINST_Q	0x00006000	/* session ended while waiting in queue for a server slot */
#define SN_FINST_T	0x00007000	/* session ended tarpitted */
#define SN_FINST_MASK	0x00007000	/* mask to get only final session state flags */
#define	SN_FINST_SHIFT	12		/* bit shift */
/* unused:              0x00008000 */

/* Note: those flags must move to another place */
#define SN_STAT_HIDEDWN	0x00010000	/* hide 'down' servers in the stats page */
#define SN_STAT_NORFRSH	0x00020000	/* do not automatically refresh the stats page */
#define SN_STAT_FMTCSV	0x00040000	/* dump the stats in CSV format instead of HTML */


/* WARNING: if new fields are added, they must be initialized in event_accept()
 * and freed in session_free() !
 */
struct session {
	struct task *task;			/* the task associated with this session */
	/* application specific below */
	struct proxy *fe;			/* the proxy this session depends on for the client side */
	struct proxy *be;			/* the proxy this session depends on for the server side */
	int cli_fd;				/* the client side fd */
	int srv_fd;				/* the server side fd */
	int cli_state;				/* state of the client side */
	int srv_state;				/* state of the server side */
	int conn_retries;			/* number of connect retries left */
	int flags;				/* some flags describing the session */
	struct buffer *req;			/* request buffer */
	struct buffer *rep;			/* response buffer */
	struct sockaddr_storage cli_addr;	/* the client address */
	struct sockaddr_storage frt_addr;	/* the frontend address reached by the client if SN_FRT_ADDR_SET is set */
	struct sockaddr_in srv_addr;		/* the address to connect to */
	struct server *srv;			/* the server being used */
	struct pendconn *pend_pos;		/* if not NULL, points to the position in the pending queue */
	struct http_txn txn;			/* current HTTP transaction being processed. Should become a list. */
	struct {
		int logwait;			/* log fields waiting to be collected : LW_* */
		struct timeval tv_accept;	/* date of the accept() (beginning of the session) */
		long  t_request;		/* delay before the end of the request arrives, -1 if never occurs */
		long  t_queue;			/* delay before the session gets out of the connect queue, -1 if never occurs */
		long  t_connect;		/* delay before the connect() to the server succeeds, -1 if never occurs */
		long  t_data;			/* delay before the first data byte from the server ... */
		unsigned long t_close;		/* total session duration */
		unsigned long srv_queue_size;	/* number of sessions waiting for a connect slot on this server at accept() time (in direct assignment) */
		unsigned long prx_queue_size;	/* overall number of sessions waiting for a connect slot on this instance at accept() time */
		long long bytes_in;		/* number of bytes transferred from the client to the server */
		long long bytes_out;		/* number of bytes transferred from the server to the client */
	} logs;
	short int data_source;			/* where to get the data we generate ourselves */
	short int data_state;			/* where to get the data we generate ourselves */
	union {
		struct {
			struct proxy *px;
			struct server *sv;
			short px_st, sv_st;	/* DATA_ST_INIT or DATA_ST_DATA */
		} stats;
	} data_ctx;				/* used by produce_content to dump the stats right now */
	unsigned int uniq_id;			/* unique ID used for the traces */
};


#endif /* _TYPES_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
