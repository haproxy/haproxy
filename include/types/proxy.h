/*
  include/types/proxy.h
  This file defines everything related to proxies.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_PROXY_H
#define _TYPES_PROXY_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/appsession.h>
#include <common/chtbl.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/regex.h>

#include <types/buffers.h>
#include <types/session.h>
#include <types/server.h>

/* values for proxy->state */
#define PR_STNEW        0
#define PR_STIDLE       1
#define PR_STRUN        2
#define PR_STSTOPPED    3
#define PR_STPAUSED     4
#define PR_STERROR      5

/* values for proxy->mode */
#define PR_MODE_TCP     0
#define PR_MODE_HTTP    1
#define PR_MODE_HEALTH  2

/* return codes for start_proxies */
#define ERR_NONE	0	/* no error */
#define ERR_RETRYABLE	1	/* retryable error, may be cumulated */
#define ERR_FATAL	2	/* fatal error, may be cumulated */


struct listener {
	int fd;				/* the listen socket */
	struct sockaddr_storage addr;	/* the address we listen to */
	struct listener *next;		/* next address or NULL */
};

struct proxy {
	struct listener *listen;		/* the listen addresses and sockets */
	struct in_addr mon_net, mon_mask;	/* don't forward connections from this net (network order) FIXME: should support IPv6 */
	int state;				/* proxy state */
	struct sockaddr_in dispatch_addr;	/* the default address to connect to */
	struct server *srv;			/* known servers */
	int srv_act, srv_bck;			/* # of running servers */
	int tot_wact, tot_wbck;			/* total weights of active and backup servers */
	struct server **srv_map;		/* the server map used to apply weights */
	int srv_map_sz;				/* the size of the effective server map */
	int srv_rr_idx;				/* next server to be elected in round robin mode */
	char *cookie_name;			/* name of the cookie to look for */
	int  cookie_len;			/* strlen(cookie_name), computed only once */
	char *appsession_name;			/* name of the cookie to look for */
	int  appsession_name_len;		/* strlen(appsession_name), computed only once */
	int  appsession_len;			/* length of the appsession cookie value to be used */
	int  appsession_timeout;
	CHTbl htbl_proxy;			/* Per Proxy hashtable */
	char *capture_name;			/* beginning of the name of the cookie to capture */
	int  capture_namelen;			/* length of the cookie name to match */
	int  capture_len;			/* length of the string to be captured */
	struct uri_auth *uri_auth;		/* if non-NULL, the (list of) per-URI authentications */
	char *monitor_uri;			/* a special URI to which we respond with HTTP/200 OK */
	int monitor_uri_len;			/* length of the string above. 0 if unused */
	int clitimeout;				/* client I/O timeout (in milliseconds) */
	int srvtimeout;				/* server I/O timeout (in milliseconds) */
	int contimeout;				/* connect timeout (in milliseconds) */
	char *id;				/* proxy id */
	struct list pendconns;			/* pending connections with no server assigned yet */
	int nbpend, nbpend_max;			/* number of pending connections with no server assigned yet */
	int totpend;				/* total number of pending connections on this instance (for stats) */
	unsigned int nbconn, nbconn_max;	/* # of active sessions */
	unsigned int cum_conn;			/* cumulated number of processed sessions */
	unsigned int maxconn;			/* max # of active sessions */
	unsigned failed_conns, failed_resp;	/* failed connect() and responses */
	unsigned failed_secu;			/* blocked responses because of security concerns */
	int conn_retries;			/* maximum number of connect retries */
	int options;				/* PR_O_REDISP, PR_O_TRANSP, ... */
	int mode;				/* mode = PR_MODE_TCP, PR_MODE_HTTP or PR_MODE_HEALTH */
	struct sockaddr_in source_addr;		/* the address to which we want to bind for connect() */
	struct proxy *next;
	struct sockaddr_in logsrv1, logsrv2;	/* 2 syslog servers */
	signed char logfac1, logfac2;		/* log facility for both servers. -1 = disabled */
	int loglev1, loglev2;			/* log level for each server, 7 by default */
	int to_log;				/* things to be logged (LW_*) */
	struct timeval stop_time;		/* date to stop listening, when stopping != 0 */
	int nb_reqadd, nb_rspadd;
	struct hdr_exp *req_exp;		/* regular expressions for request headers */
	struct hdr_exp *rsp_exp;		/* regular expressions for response headers */
	int nb_req_cap, nb_rsp_cap;		/* # of headers to be captured */
	struct cap_hdr *req_cap;		/* chained list of request headers to be captured */
	struct cap_hdr *rsp_cap;		/* chained list of response headers to be captured */
	void *req_cap_pool, *rsp_cap_pool;	/* pools of pre-allocated char ** used to build the sessions */
	char *req_add[MAX_NEWHDR], *rsp_add[MAX_NEWHDR]; /* headers to be added */
	int grace;				/* grace time after stop request */
	char *check_req;			/* HTTP or SSL request to use for PR_O_HTTP_CHK|PR_O_SSL3_CHK */
	int check_len;				/* Length of the HTTP or SSL3 request */
	struct {
		char *msg400;			/* message for error 400 */
		int len400;			/* message length for error 400 */
		char *msg403;			/* message for error 403 */
		int len403;			/* message length for error 403 */
		char *msg408;			/* message for error 408 */
		int len408;			/* message length for error 408 */
		char *msg500;			/* message for error 500 */
		int len500;			/* message length for error 500 */
		char *msg502;			/* message for error 502 */
		int len502;			/* message length for error 502 */
		char *msg503;			/* message for error 503 */
		int len503;			/* message length for error 503 */
		char *msg504;			/* message for error 504 */
		int len504;			/* message length for error 504 */
	} errmsg;
};

extern struct proxy *proxy;

#endif /* _TYPES_PROXY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
