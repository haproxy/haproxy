/*
 * include/haproxy/proxy-t.h
 * This file defines everything related to proxies.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_PROXY_T_H
#define _HAPROXY_PROXY_T_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <import/ebtree-t.h>

#include <haproxy/api-t.h>
#include <haproxy/arg-t.h>
#include <haproxy/backend-t.h>
#include <haproxy/compression-t.h>
#include <haproxy/counters-t.h>
#include <haproxy/freq_ctr-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/queue-t.h>
#include <haproxy/server-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/tcpcheck-t.h>
#include <haproxy/thread-t.h>
#include <haproxy/tools-t.h>
#include <haproxy/uri_auth-t.h>

/* values for proxy->mode */
enum pr_mode {
	PR_MODE_TCP = 0,
	PR_MODE_HTTP,
	PR_MODE_CLI,
	PR_MODE_SYSLOG,
	PR_MODE_PEERS,
	PR_MODES
} __attribute__((packed));

enum PR_SRV_STATE_FILE {
	PR_SRV_STATE_FILE_UNSPEC = 0,
	PR_SRV_STATE_FILE_NONE,
	PR_SRV_STATE_FILE_GLOBAL,
	PR_SRV_STATE_FILE_LOCAL,
};


/* flag values for proxy->cap. This is a bitmask of capabilities supported by the proxy */
#define PR_CAP_NONE    0x0000
#define PR_CAP_FE      0x0001
#define PR_CAP_BE      0x0002
#define PR_CAP_LISTEN  (PR_CAP_FE|PR_CAP_BE)
#define PR_CAP_DEF     0x0004           /* defaults section */
#define PR_CAP_INT     0x0008           /* internal proxy (used by lua engine) */
#define PR_CAP_LB      0x0010           /* load-balancing capabilities, i.e. listen/frontend/backend proxies */

/* bits for proxy->options */
#define PR_O_REDISP     0x00000001      /* allow reconnection to dispatch in case of errors */
#define PR_O_TRANSP     0x00000002      /* transparent mode : use original DEST as dispatch */

/* HTTP server-side reuse */
#define PR_O_REUSE_NEVR 0x00000000      /* never reuse a shared connection */
#define PR_O_REUSE_SAFE 0x00000004      /* only reuse a shared connection when it's safe to do so */
#define PR_O_REUSE_AGGR 0x00000008      /* aggressively reuse a shared connection */
#define PR_O_REUSE_ALWS 0x0000000C      /* always reuse a shared connection */
#define PR_O_REUSE_MASK 0x0000000C      /* mask to retrieve shared connection preferences */

#define PR_O_IDLE_CLOSE_RESP 0x00000010 /* avoid closing idle connections during a soft stop */
#define PR_O_PREF_LAST  0x00000020      /* prefer last server */
#define PR_O_DISPATCH   0x00000040      /* use dispatch mode */
#define PR_O_FORCED_ID  0x00000080      /* proxy's ID was forced in the configuration */
#define PR_O_FWDFOR     0x00000100      /* conditionally insert x-forwarded-for with client address */
#define PR_O_IGNORE_PRB 0x00000200      /* ignore empty requests (aborts and timeouts) */
#define PR_O_NULLNOLOG  0x00000400      /* a connect without request will not be logged */
#define PR_O_WREQ_BODY  0x00000800      /* always wait for the HTTP request body */
#define PR_O_HTTP_UPG   0x00001000      /* Contain a "switch-mode http" tcp-request rule */
#define PR_O_FF_ALWAYS  0x00002000      /* always set x-forwarded-for */
#define PR_O_PERSIST    0x00004000      /* server persistence stays effective even when server is down */
#define PR_O_LOGASAP    0x00008000      /* log as soon as possible, without waiting for the stream to complete */
#define PR_O_ERR_LOGFMT 0x00010000      /* use log-format for connection error message */
#define PR_O_CHK_CACHE  0x00020000      /* require examination of cacheability of the 'set-cookie' field */
#define PR_O_TCP_CLI_KA 0x00040000      /* enable TCP keep-alive on client-side streams */
#define PR_O_TCP_SRV_KA 0x00080000      /* enable TCP keep-alive on server-side streams */
#define PR_O_USE_ALL_BK 0x00100000      /* load-balance between backup servers */
/* unused: 0x00020000 */
#define PR_O_TCP_NOLING 0x00400000      /* disable lingering on client and server connections */
#define PR_O_ABRT_CLOSE 0x00800000      /* immediately abort request when client closes */

#define PR_O_HTTP_KAL   0x00000000      /* HTTP keep-alive mode (http-keep-alive) */
#define PR_O_HTTP_CLO   0x01000000      /* HTTP close mode (httpclose) */
#define PR_O_HTTP_SCL   0x02000000      /* HTTP server close mode (http-server-close) */
#define PR_O_HTTP_MODE  0x03000000      /* MASK to retrieve the HTTP mode */
/* unused: 0x04000000 */

#define PR_O_TCPCHK_SSL 0x08000000	/* at least one TCPCHECK connect rule requires SSL */
#define PR_O_CONTSTATS	0x10000000	/* continuous counters */
/* unused: 0x20000000 */
#define PR_O_DISABLE404 0x40000000      /* Disable a server on a 404 response to a health-check */
#define PR_O_ORGTO      0x80000000      /* insert x-original-to with destination address */

/* bits for proxy->options2 */
#define PR_O2_SPLIC_REQ	0x00000001      /* transfer requests using linux kernel's splice() */
#define PR_O2_SPLIC_RTR	0x00000002      /* transfer responses using linux kernel's splice() */
#define PR_O2_SPLIC_AUT	0x00000004      /* automatically use linux kernel's splice() */
#define PR_O2_SPLIC_ANY	(PR_O2_SPLIC_REQ|PR_O2_SPLIC_RTR|PR_O2_SPLIC_AUT)
#define PR_O2_REQBUG_OK	0x00000008      /* let buggy requests pass through */
#define PR_O2_RSPBUG_OK	0x00000010      /* let buggy responses pass through */
#define PR_O2_NOLOGNORM	0x00000020      /* don't log normal traffic, only errors and retries */
#define PR_O2_LOGERRORS	0x00000040      /* log errors and retries at level LOG_ERR */
#define PR_O2_SMARTACC 	0x00000080      /* don't immediately ACK request after accept */
#define PR_O2_SMARTCON 	0x00000100      /* don't immediately send empty ACK after connect */
#define PR_O2_RDPC_PRST	0x00000200      /* Actvate rdp cookie analyser */
#define PR_O2_CLFLOG	0x00000400      /* log into clf format */
#define PR_O2_LOGHCHKS	0x00000800	/* log health checks */
#define PR_O2_INDEPSTR	0x00001000	/* independent streams, don't update rex on write */
#define PR_O2_SOCKSTAT	0x00002000	/* collect & provide separate statistics for sockets */

#define PR_O2_H1_ADJ_BUGCLI 0x00008000 /* adjust the case of h1 headers of the response for bogus clients */
#define PR_O2_H1_ADJ_BUGSRV 0x00004000 /* adjust the case of h1 headers of the request for bogus servers */
#define PR_O2_NO_H2_UPGRADE 0x00010000 /* disable the implicit H2 upgrades from H1 client connections */

#define PR_O2_NODELAY   0x00020000      /* fully interactive mode, never delay outgoing data */
#define PR_O2_USE_PXHDR 0x00040000      /* use Proxy-Connection for proxy requests */
#define PR_O2_CHK_SNDST 0x00080000      /* send the state of each server along with HTTP health checks */

#define PR_O2_SRC_ADDR	0x00100000	/* get the source ip and port for logs */

#define PR_O2_FAKE_KA   0x00200000      /* pretend we do keep-alive with server even though we close */
/* unused : 0x00400000..0x80000000 */

/* server health checks */
#define PR_O2_CHK_NONE  0x00000000      /* no L7 health checks configured (TCP by default) */
#define PR_O2_TCPCHK_CHK 0x90000000     /* use TCPCHK check for server health */
#define PR_O2_EXT_CHK   0xA0000000      /* use external command for server health */
/* unused: 0xB0000000 to 0xF000000, reserved for health checks */
#define PR_O2_CHK_ANY   0xF0000000      /* Mask to cover any check */
/* end of proxy->options2 */

/* Cookie settings for pr->ck_opts */
#define PR_CK_RW        0x00000001      /* rewrite all direct cookies with the right serverid */
#define PR_CK_IND       0x00000002      /* keep only indirect cookies */
#define PR_CK_INS       0x00000004      /* insert cookies when not accessing a server directly */
#define PR_CK_PFX       0x00000008      /* rewrite all cookies by prefixing the right serverid */
#define PR_CK_ANY       (PR_CK_RW | PR_CK_IND | PR_CK_INS | PR_CK_PFX)
#define PR_CK_NOC       0x00000010      /* add a 'Cache-control' header with the cookie */
#define PR_CK_POST      0x00000020      /* don't insert cookies for requests other than a POST */
#define PR_CK_PSV       0x00000040      /* cookie ... preserve */
#define PR_CK_HTTPONLY  0x00000080      /* emit the "HttpOnly" attribute */
#define PR_CK_SECURE    0x00000100      /* emit the "Secure" attribute */
#define PR_CK_DYNAMIC   0x00000200	/* create dynamic cookies for each server */

/* bits for sticking rules */
#define STK_IS_MATCH	0x00000001	/* match on request fetch */
#define STK_IS_STORE	0x00000002	/* store on request fetch */
#define STK_ON_RSP	0x00000004	/* store on response fetch */

/* diff bits for proxy_find_best_match */
#define PR_FBM_MISMATCH_ID        0x01
#define PR_FBM_MISMATCH_NAME      0x02
#define PR_FBM_MISMATCH_PROXYTYPE 0x04

/* Bits for the different retry causes */
#define PR_RE_CONN_FAILED         0x00000001 /* Retry if we failed to connect */
#define PR_RE_DISCONNECTED        0x00000002 /* Retry if we got disconnected with no answer */
#define PR_RE_TIMEOUT             0x00000004 /* Retry if we got a server timeout before we got any data */
#define PR_RE_401                 0x00000008 /* Retry if we got a 401 */
#define PR_RE_403                 0x00000010 /* Retry if we got a 403 */
#define PR_RE_404                 0x00000020 /* Retry if we got a 404 */
#define PR_RE_408                 0x00000040 /* Retry if we got a 408 */
#define PR_RE_425                 0x00000080 /* Retry if we got a 425 */
#define PR_RE_500                 0x00000100 /* Retry if we got a 500 */
#define PR_RE_501                 0x00000200 /* Retry if we got a 501 */
#define PR_RE_502                 0x00000400 /* Retry if we got a 502 */
#define PR_RE_503                 0x00000800 /* Retry if we got a 503 */
#define PR_RE_504                 0x00001000 /* Retry if we got a 504 */
#define PR_RE_STATUS_MASK         (PR_RE_401 | PR_RE_403 | PR_RE_404 | \
                                   PR_RE_408 | PR_RE_425 | PR_RE_500 | \
                                   PR_RE_501 | PR_RE_502 | PR_RE_503 | \
                                   PR_RE_504)
/* 0x00000800, 0x00001000, 0x00002000, 0x00004000 and 0x00008000 unused,
 * reserved for eventual future status codes
 */
#define PR_RE_EARLY_ERROR         0x00010000 /* Retry if we failed at sending early data */
#define PR_RE_JUNK_REQUEST        0x00020000 /* We received an incomplete or garbage response */

/* Proxy flags */
#define PR_FL_DISABLED           0x01  /* The proxy was disabled in the configuration (not at runtime) */
#define PR_FL_STOPPED            0x02  /* The proxy was stopped */
#define PR_FL_READY              0x04  /* The proxy is ready to be used (initialized and configured) */
#define PR_FL_EXPLICIT_REF       0x08  /* The default proxy is explicitly referenced by another proxy */
#define PR_FL_IMPLICIT_REF       0x10  /* The default proxy is implicitly referenced by another proxy */

struct stream;

struct http_snapshot {
	unsigned int sid;		/* ID of the faulty stream */
	unsigned int state;		/* message state before the error (when saved) */
	unsigned int b_flags;		/* buffer flags */
	unsigned int s_flags;		/* stream flags */

	unsigned int t_flags;		/* transaction flags */
	unsigned int m_flags;		/* message flags */
	unsigned long long m_clen;	/* chunk len for this message */
	unsigned long long m_blen;	/* body len for this message */
};

struct h1_snapshot {
	unsigned int state;		/* H1 message state when the error occurred */
	unsigned int c_flags;		/* H1 connection flags */
	unsigned int s_flags;		/* H1 stream flags */
	unsigned int m_flags;		/* H1 message flags */
	unsigned long long m_clen;	/* chunk len for this message */
	unsigned long long m_blen;	/* body len for this message */
};

union error_snapshot_ctx {
	struct http_snapshot http;
	struct h1_snapshot h1;
};

struct error_snapshot {
	/**** common part ****/
	struct timeval when;            /* date of this event, (tv_sec == 0) means "never" */
	/* @16 */
	void (*show)(struct buffer *, const struct error_snapshot *); /* dump function */
	unsigned long long buf_ofs;     /* relative position of the buffer's input inside its container */
	/* @32 */
	unsigned int buf_out;           /* pending output bytes _before_ the buffer's input (0..buf->data-1) */
	unsigned int buf_len;           /* original length of the last invalid request/response (0..buf->data-1-buf_out) */
	unsigned int buf_err;           /* buffer-relative position where the error was detected (0..len-1) */
	unsigned int buf_wrap;          /* buffer-relative position where the buffer is expected to wrap (1..buf_size) */
	/* @48 */
	struct proxy *oe;               /* other end = frontend or backend involved */
	struct server *srv;             /* server associated with the error (or NULL) */
	/* @64 */
	unsigned int ev_id;             /* event number (counter incremented for each capture) */
	/* @68: 4 bytes hole here */
	struct sockaddr_storage src;    /* client's address */

	/**** protocol-specific part ****/
	union error_snapshot_ctx ctx;
	char buf[VAR_ARRAY];                    /* copy of the beginning of the message for bufsize bytes */
};

struct proxy {
	enum obj_type obj_type;                 /* object type == OBJ_TYPE_PROXY */
	char flags;                             /* bit field PR_FL_* */
	enum pr_mode mode;                      /* mode = PR_MODE_TCP, PR_MODE_HTTP, ... */
	char cap;                               /* supported capabilities (PR_CAP_*) */
	unsigned int maxconn;                   /* max # of active streams on the frontend */

	int options;				/* PR_O_REDISP, PR_O_TRANSP, ... */
	int options2;				/* PR_O2_* */
	unsigned int ck_opts;			/* PR_CK_* (cookie options) */
	unsigned int fe_req_ana, be_req_ana;	/* bitmap of common request protocol analysers for the frontend and backend */
	unsigned int fe_rsp_ana, be_rsp_ana;	/* bitmap of common response protocol analysers for the frontend and backend */
	unsigned int http_needed;               /* non-null if HTTP analyser may be used */
	union {
		struct proxy *be;		/* default backend, or NULL if none set */
		char *name;			/* default backend name during config parse */
	} defbe;
	struct proxy *defpx;                    /* default proxy used to init this one (may be NULL) */
	struct list acl;                        /* ACL declared on this proxy */
	struct list http_req_rules;		/* HTTP request rules: allow/deny/... */
	struct list http_res_rules;		/* HTTP response rules: allow/deny/... */
	struct list http_after_res_rules;	/* HTTP final response rules: set-header/del-header/... */
	struct list redirect_rules;             /* content redirecting rules (chained) */
	struct list switching_rules;            /* content switching rules (chained) */
	struct list persist_rules;		/* 'force-persist' and 'ignore-persist' rules (chained) */
	struct list sticking_rules;             /* content sticking rules (chained) */
	struct list storersp_rules;             /* content store response rules (chained) */
	struct list server_rules;               /* server switching rules (chained) */
	struct {                                /* TCP request processing */
		unsigned int inspect_delay;     /* inspection delay */
		struct list inspect_rules;      /* inspection rules */
		struct list l4_rules;           /* layer4 rules */
		struct list l5_rules;           /* layer5 rules */
	} tcp_req;
	struct {                                /* TCP request processing */
		unsigned int inspect_delay;     /* inspection delay */
		struct list inspect_rules;      /* inspection rules */
	} tcp_rep;
	struct server *srv, defsrv;		/* known servers; default server configuration */
	struct lbprm lbprm;			/* load-balancing parameters */
	int srv_act, srv_bck;			/* # of servers eligible for LB (UP|!checked) AND (enabled+weight!=0) */
	int served;				/* # of active sessions currently being served */
	int  cookie_len;			/* strlen(cookie_name), computed only once */
	char *cookie_domain;			/* domain used to insert the cookie */
	char *cookie_name;			/* name of the cookie to look for */
	char *cookie_attrs;                     /* list of attributes to add to the cookie */
	char *dyncookie_key;			/* Secret key used to generate dynamic persistent cookies */
	unsigned int cookie_maxidle;		/* max idle time for this cookie */
	unsigned int cookie_maxlife;		/* max life time for this cookie */
	char *rdp_cookie_name;			/* name of the RDP cookie to look for */
	char *capture_name;			/* beginning of the name of the cookie to capture */
	int  rdp_cookie_len;			/* strlen(rdp_cookie_name), computed only once */
	int  capture_namelen;			/* length of the cookie name to match */
	struct uri_auth *uri_auth;		/* if non-NULL, the (list of) per-URI authentications */
	int  capture_len;			/* length of the string to be captured */
	int max_out_conns;                      /* Max number of idling connections we keep for a session */
	int max_ka_queue;			/* 1+maximum requests in queue accepted for reusing a K-A conn (0=none) */
	int clitcpka_cnt;                       /* The maximum number of keepalive probes TCP should send before dropping the connection. (client side) */
	int clitcpka_idle;                      /* The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes. (client side) */
	int clitcpka_intvl;                     /* The time (in seconds) between individual keepalive probes. (client side) */
	int srvtcpka_cnt;                       /* The maximum number of keepalive probes TCP should send before dropping the connection. (server side) */
	int srvtcpka_idle;                      /* The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes. (server side) */
	int srvtcpka_intvl;                     /* The time (in seconds) between individual keepalive probes. (server side) */
	int monitor_uri_len;			/* length of the string above. 0 if unused */
	char *monitor_uri;			/* a special URI to which we respond with HTTP/200 OK */
	struct list mon_fail_cond;              /* list of conditions to fail monitoring requests (chained) */
	struct {				/* WARNING! check proxy_reset_timeouts() in proxy.h !!! */
		int client;                     /* client I/O timeout (in ticks) */
		int tarpit;                     /* tarpit timeout, defaults to connect if unspecified */
		int queue;                      /* queue timeout, defaults to connect if unspecified */
		int connect;                    /* connect timeout (in ticks) */
		int server;                     /* server I/O timeout (in ticks) */
		int httpreq;                    /* maximum time for complete HTTP request */
		int httpka;                     /* maximum time for a new HTTP request when using keep-alive */
		int check;                      /* maximum time for complete check */
		int tunnel;                     /* I/O timeout to use in tunnel mode (in ticks) */
		int clientfin;                  /* timeout to apply to client half-closed connections */
		int serverfin;                  /* timeout to apply to server half-closed connections */
	} timeout;
	__decl_thread(HA_RWLOCK_T lock);        /* may be taken under the server's lock */

	char *id, *desc;			/* proxy id (name) and description */
	struct queue queue;			/* queued requests (pendconns) */
	int totpend;				/* total number of pending connections on this instance (for stats) */
	unsigned int feconn, beconn;		/* # of active frontend and backends streams */
	struct freq_ctr fe_req_per_sec;		/* HTTP requests per second on the frontend */
	struct freq_ctr fe_conn_per_sec;	/* received connections per second on the frontend */
	struct freq_ctr fe_sess_per_sec;	/* accepted sessions per second on the frontend (after tcp rules) */
	struct freq_ctr be_sess_per_sec;	/* sessions per second on the backend */
	unsigned int fe_sps_lim;		/* limit on new sessions per second on the frontend */
	unsigned int fullconn;			/* #conns on backend above which servers are used at full load */
	unsigned int tot_fe_maxconn;		/* #maxconn of frontends linked to that backend, it is used to compute fullconn */
	struct net_addr except_xff_net;         /* don't x-forward-for for this address. */
	struct net_addr except_xot_net;         /* don't x-original-to for this address. */
	char *fwdfor_hdr_name;			/* header to use - default: "x-forwarded-for" */
	char *orgto_hdr_name;			/* header to use - default: "x-original-to" */
	int fwdfor_hdr_len;			/* length of "x-forwarded-for" header */
	int orgto_hdr_len;			/* length of "x-original-to" header */
	char *server_id_hdr_name;                   /* the header to use to send the server id (name) */
	int server_id_hdr_len;                      /* the length of the id (name) header... name */
	int conn_retries;			/* maximum number of connect retries */
	unsigned int retry_type;                /* Type of retry allowed */
	int redispatch_after;			/* number of retries before redispatch */
	unsigned down_trans;			/* up-down transitions */
	unsigned down_time;			/* total time the proxy was down */
	time_t last_change;			/* last time, when the state was changed */
	int (*accept)(struct stream *s);       /* application layer's accept() */
	struct conn_src conn_src;               /* connection source settings */
	enum obj_type *default_target;		/* default target to use for accepted streams or NULL */
	struct proxy *next;
	struct proxy *next_stkt_ref;    /* Link to the list of proxies which refer to the same stick-table. */

	struct list logsrvs;
	struct list logformat; 			/* log_format linked list */
	struct list logformat_sd;		/* log_format linked list for the RFC5424 structured-data part */
	struct list logformat_error;		/* log_format linked list used in case of connection error on the frontend */
	struct buffer log_tag;                   /* override default syslog tag */
	struct ist header_unique_id; 		/* unique-id header */
	struct list format_unique_id;		/* unique-id format */
	int to_log;				/* things to be logged (LW_*) */
	int stop_time;                          /* date to stop listening, when stopping != 0 (int ticks) */
	int nb_req_cap, nb_rsp_cap;		/* # of headers to be captured */
	struct cap_hdr *req_cap;		/* chained list of request headers to be captured */
	struct cap_hdr *rsp_cap;		/* chained list of response headers to be captured */
	struct pool_head *req_cap_pool,		/* pools of pre-allocated char ** used to build the streams */
	                 *rsp_cap_pool;
	struct be_counters be_counters;		/* backend statistics counters */
	struct fe_counters fe_counters;		/* frontend statistics counters */

	struct mt_list listener_queue;		/* list of the temporarily limited listeners because of lack of a proxy resource */
	struct stktable *table;			/* table for storing sticking streams */

	struct task *task;			/* the associated task, mandatory to manage rate limiting, stopping and resource shortage, NULL if disabled */
	struct tcpcheck_rules tcpcheck_rules;   /* tcp-check send / expect rules */
	char *check_command;			/* Command to use for external agent checks */
	char *check_path;			/* PATH environment to use for external agent checks */
	struct http_reply *replies[HTTP_ERR_SIZE]; /* HTTP replies for known errors */
	unsigned int log_count;			/* number of logs produced by the frontend */
	int uuid;				/* universally unique proxy ID, used for SNMP */
	unsigned int backlog;			/* force the frontend's listen backlog */
	unsigned int li_all;                    /* total number of listeners attached to this proxy */
	unsigned int li_paused;                 /* total number of listeners paused (LI_PAUSED) */
	unsigned int li_bound;                  /* total number of listeners ready (LI_LISTEN)  */
	unsigned int li_ready;                  /* total number of listeners ready (>=LI_READY) */

	/* warning: these structs are huge, keep them at the bottom */
	struct sockaddr_storage dispatch_addr;	/* the default address to connect to */
	struct error_snapshot *invalid_req, *invalid_rep; /* captures of last errors */

	/* used only during configuration parsing */
	int no_options;				/* PR_O_REDISP, PR_O_TRANSP, ... */
	int no_options2;			/* PR_O2_* */

	struct {
		char *file;			/* file where the section appears */
		struct eb32_node id;		/* place in the tree of used IDs */
		int line;			/* line where the section appears */
		struct eb_root used_listener_id;/* list of listener IDs in use */
		struct eb_root used_server_id;	/* list of server IDs in use */
		struct eb_root used_server_name; /* list of server names in use */
		struct list bind;		/* list of bind settings */
		struct list listeners;		/* list of listeners belonging to this frontend */
		struct list errors;             /* list of all custom error files */
		struct arg_list args;           /* sample arg list that need to be resolved */
		unsigned int refcount;          /* refcount on this proxy (only used for default proxy for now) */
		struct ebpt_node by_name;       /* proxies are stored sorted by name here */
		char *logformat_string;		/* log format string */
		char *lfs_file;                 /* file name where the logformat string appears (strdup) */
		int   lfs_line;                 /* file name where the logformat string appears */
		int   uif_line;                 /* file name where the unique-id-format string appears */
		char *uif_file;                 /* file name where the unique-id-format string appears (strdup) */
		char *uniqueid_format_string;	/* unique-id format string */
		char *logformat_sd_string;	/* log format string for the RFC5424 structured-data part */
		char *lfsd_file;		/* file name where the structured-data logformat string for RFC5424 appears (strdup) */
		int  lfsd_line;			/* file name where the structured-data logformat string for RFC5424 appears */
		char *error_logformat_string;
		char *elfs_file;
		int elfs_line;
	} conf;					/* config information */
	struct eb_root used_server_addr;        /* list of server addresses in use */
	void *parent;				/* parent of the proxy when applicable */
	struct comp *comp;			/* http compression */

	struct {
		union {
			struct mailers *m;	/* Mailer to send email alerts via */
			char *name;
		} mailers;
		char *from;			/* Address to send email alerts from */
		char *to;			/* Address(es) to send email alerts to */
		char *myhostname;		/* Identity to use in HELO command sent to mailer */
		int level;			/* Maximum syslog level of messages to send
						 * email alerts for */
		int set;			/* True if email_alert settings are present */
		struct email_alertq *queues;	/* per-mailer alerts queues */
	} email_alert;

	int load_server_state_from_file;	/* location of the file containing server state.
						 * flag PR_SRV_STATE_FILE_* */
	char *server_state_file_name;		/* used when load_server_state_from_file is set to
						 * PR_SRV_STATE_FILE_LOCAL. Give a specific file name for
						 * this backend. If not specified or void, then the backend
						 * name is used
						 */
	struct list filter_configs;		/* list of the filters that are declared on this proxy */

	EXTRA_COUNTERS(extra_counters_fe);
	EXTRA_COUNTERS(extra_counters_be);
};

struct switching_rule {
	struct list list;			/* list linked to from the proxy */
	struct acl_cond *cond;			/* acl condition to meet */
	int dynamic;				/* this is a dynamic rule using the logformat expression */
	union {
		struct proxy *backend;		/* target backend */
		char *name;			/* target backend name during config parsing */
		struct list expr;		/* logformat expression to use for dynamic rules */
	} be;
	char *file;
	int line;
};

struct server_rule {
	struct list list;			/* list linked to from the proxy */
	struct acl_cond *cond;			/* acl condition to meet */
	int dynamic;
	union {
		struct server *ptr;		/* target server */
		char *name;			/* target server name during config parsing */
	} srv;
	struct list expr;		/* logformat expression to use for dynamic rules */
	char *file;
	int line;
};

struct persist_rule {
	struct list list;			/* list linked to from the proxy */
	struct acl_cond *cond;			/* acl condition to meet */
	int type;
};

struct sticking_rule {
	struct list list;                       /* list linked to from the proxy */
	struct acl_cond *cond;                  /* acl condition to meet */
	struct sample_expr *expr;               /* fetch expr to fetch key */
	int flags;                              /* STK_* */
	union {
		struct stktable *t;	        /* target table */
		char *name;                     /* target table name during config parsing */
	} table;
};


struct redirect_rule {
	struct list list;                       /* list linked to from the proxy */
	struct acl_cond *cond;                  /* acl condition to meet */
	int type;
	int rdr_len;
	char *rdr_str;
	struct list rdr_fmt;
	int code;
	unsigned int flags;
	int cookie_len;
	char *cookie_str;
};

/* some of the most common options which are also the easiest to handle */
struct cfg_opt {
	const char *name;
	unsigned int val;
	unsigned int cap;
	unsigned int checks;
	unsigned int mode;
};

#endif /* _HAPROXY_PROXY_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
