/*
 * include/haproxy/server-t.h
 * This file defines everything related to servers.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_SERVER_T_H
#define _HAPROXY_SERVER_T_H

#include <netinet/in.h>
#include <arpa/inet.h>

#include <import/ebtree-t.h>

#include <haproxy/api-t.h>
#include <haproxy/check-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/counters-t.h>
#include <haproxy/guid-t.h>
#include <haproxy/listener-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/queue-t.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/resolvers-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/task-t.h>
#include <haproxy/thread-t.h>
#include <haproxy/event_hdl-t.h>
#include <haproxy/log-t.h>
#include <haproxy/tools-t.h>


/* server states. Only SRV_ST_STOPPED indicates a down server. */
enum srv_state {
	SRV_ST_STOPPED = 0,              /* the server is down. Please keep set to zero. */
	SRV_ST_STARTING,                 /* the server is warming up (up but throttled) */
	SRV_ST_RUNNING,                  /* the server is fully up */
	SRV_ST_STOPPING,                 /* the server is up but soft-stopping (eg: 404) */
} __attribute__((packed));

/* Administrative status : a server runs in one of these 3 stats :
 *   - READY : normal mode
 *   - DRAIN : takes no new visitor, equivalent to weight == 0
 *   - MAINT : maintenance mode, no more traffic nor health checks.
 *
 * Each server may be in maintenance by itself or may inherit this status from
 * another server it tracks. It can also be in drain mode by itself or inherit
 * it from another server. Let's store these origins here as flags. These flags
 * are combined this way :
 *
 *      FMAINT  IMAINT  FDRAIN  IDRAIN  Resulting state
 *         0       0       0       0    READY
 *         0       0       0       1    DRAIN
 *         0       0       1       x    DRAIN
 *         0       1       x       x    MAINT
 *         1       x       x       x    MAINT
 *
 * This can be simplified this way :
 *
 *   state_str = (state & MAINT) ? "MAINT" : (state & DRAIN) : "DRAIN" : "READY"
 */
enum srv_admin {
	SRV_ADMF_FMAINT    = 0x01,        /* the server was explicitly forced into maintenance */
	SRV_ADMF_IMAINT    = 0x02,        /* the server has inherited the maintenance status from a tracked server */
	SRV_ADMF_CMAINT    = 0x04,        /* the server is in maintenance because of the configuration (separate) */
	SRV_ADMF_FDRAIN    = 0x08,        /* the server was explicitly forced into drain state */
	SRV_ADMF_IDRAIN    = 0x10,        /* the server has inherited the drain status from a tracked server */
	SRV_ADMF_DRAIN     = 0x18,        /* mask to check if any drain flag is present */
	SRV_ADMF_RMAINT    = 0x20,        /* the server is down because of an IP address resolution failure */

	SRV_ADMF_MAINT     = 0x23,        /* mask to check if any maintenance flag except CMAINT is present */

	SRV_ADMF_FQDN_CHANGED = 0x40,     /* Special value: set (and never removed) if the server fqdn has
	                                   * changed (from cli or resolvers) since its initial value from
	                                   * config. This flag is exported and restored through state-file
					   */
} __attribute__((packed));

/* options for servers' "init-addr" parameter
 * this parameter may be used to drive HAProxy's behavior when parsing a server
 * address at start up time.
 * These values are stored as a list into an integer ordered from first to last
 * starting with the lowest to highest bits. SRV_IADDR_END (0) is used to
 * indicate the end of the list. 3 bits are enough to store each value.
 */
enum srv_initaddr {
	SRV_IADDR_END      = 0,           /* end of the list */
	SRV_IADDR_NONE     = 1,           /* the server won't have any address at start up */
	SRV_IADDR_LIBC     = 2,           /* address set using the libc DNS resolver */
	SRV_IADDR_LAST     = 3,           /* we set the IP address found in state-file for this server */
	SRV_IADDR_IP       = 4,           /* we set an arbitrary IP address to the server */
} __attribute__((packed));

/* options for servers' "init-state" parameter this parameter may be
 * used to drive HAProxy's behavior when determining a server's status
 * at start up time.
 */
enum srv_init_state {
	SRV_INIT_STATE_FULLY_DOWN = 0,     /* the server should initially be considered DOWN until it passes all health checks. Please keep set to zero. */
	SRV_INIT_STATE_DOWN,               /* the server should initially be considered DOWN until it passes one health check. */
	SRV_INIT_STATE_UP,                 /* the server should initially be considered UP, but will go DOWN if it fails one health check. */
	SRV_INIT_STATE_FULLY_UP,           /* the server should initially be considered UP, but will go DOWN if it fails all health checks. */
} __attribute__((packed));

/* server-state-file version */
#define SRV_STATE_FILE_VERSION 1
#define SRV_STATE_FILE_VERSION_MIN 1
#define SRV_STATE_FILE_VERSION_MAX 1
#define SRV_STATE_FILE_FIELD_NAMES \
    "be_id "                      \
    "be_name "                    \
    "srv_id "                     \
    "srv_name "                   \
    "srv_addr "                   \
    "srv_op_state "               \
    "srv_admin_state "            \
    "srv_uweight "                \
    "srv_iweight "                \
    "srv_time_since_last_change " \
    "srv_check_status "           \
    "srv_check_result "           \
    "srv_check_health "           \
    "srv_check_state "            \
    "srv_agent_state "            \
    "bk_f_forced_id "             \
    "srv_f_forced_id "            \
    "srv_fqdn "                   \
    "srv_port "                   \
    "srvrecord "                  \
    "srv_use_ssl "                \
    "srv_check_port "             \
    "srv_check_addr "             \
    "srv_agent_addr "             \
    "srv_agent_port"

#define SRV_STATE_FILE_MAX_FIELDS 25
#define SRV_STATE_FILE_MIN_FIELDS_VERSION_1 20
#define SRV_STATE_FILE_MAX_FIELDS_VERSION_1 25
#define SRV_STATE_LINE_MAXLEN 2000

/* server flags -- 32 bits */
#define SRV_F_BACKUP       0x0001        /* this server is a backup server */
#define SRV_F_MAPPORTS     0x0002        /* this server uses mapped ports */
#define SRV_F_NON_STICK    0x0004        /* never add connections allocated to this server to a stick table */
#define SRV_F_USE_NS_FROM_PP 0x0008      /* use namespace associated with connection if present */
#define SRV_F_FORCED_ID    0x0010        /* server's ID was forced in the configuration */
#define SRV_F_RHTTP        0x0020        /* reverse HTTP server which requires idle connection for transfers */
#define SRV_F_AGENTPORT    0x0040        /* this server has a agent port configured */
#define SRV_F_AGENTADDR    0x0080        /* this server has a agent addr configured */
#define SRV_F_COOKIESET    0x0100        /* this server has a cookie configured, so don't generate dynamic cookies */
#define SRV_F_FASTOPEN     0x0200        /* Use TCP Fast Open to connect to server */
#define SRV_F_SOCKS4_PROXY 0x0400        /* this server uses SOCKS4 proxy */
#define SRV_F_NO_RESOLUTION 0x0800       /* disable runtime DNS resolution on this server */
#define SRV_F_DYNAMIC      0x1000        /* dynamic server instantiated at runtime */
#define SRV_F_NON_PURGEABLE 0x2000       /* this server cannot be removed at runtime */
#define SRV_F_DEFSRV_USE_SSL 0x4000      /* default-server uses SSL */
#define SRV_F_DELETED 0x8000             /* srv is deleted but not yet purged */

/* configured server options for send-proxy (server->pp_opts) */
#define SRV_PP_V1               0x0001   /* proxy protocol version 1 */
#define SRV_PP_V2               0x0002   /* proxy protocol version 2 */
#define SRV_PP_V2_SSL           0x0004   /* proxy protocol version 2 with SSL */
#define SRV_PP_V2_SSL_CN        0x0008   /* proxy protocol version 2 with CN */
#define SRV_PP_V2_SSL_KEY_ALG   0x0010   /* proxy protocol version 2 with cert key algorithm */
#define SRV_PP_V2_SSL_SIG_ALG   0x0020   /* proxy protocol version 2 with cert signature algorithm */
#define SRV_PP_V2_SSL_CIPHER    0x0040   /* proxy protocol version 2 with cipher used */
#define SRV_PP_V2_AUTHORITY     0x0080   /* proxy protocol version 2 with authority */
#define SRV_PP_V2_CRC32C        0x0100   /* proxy protocol version 2 with crc32c */
#define SRV_PP_V2_UNIQUE_ID     0x0200   /* proxy protocol version 2 with unique ID */

/* function which act on servers need to return various errors */
#define SRV_STATUS_OK       0   /* everything is OK. */
#define SRV_STATUS_INTERNAL 1   /* other unrecoverable errors. */
#define SRV_STATUS_NOSRV    2   /* no server is available */
#define SRV_STATUS_FULL     3   /* the/all server(s) are saturated */
#define SRV_STATUS_QUEUED   4   /* the/all server(s) are saturated but the connection was queued */

/* various constants */
#define SRV_UWGHT_RANGE 256
#define SRV_UWGHT_MAX   (SRV_UWGHT_RANGE)
#define SRV_EWGHT_RANGE (SRV_UWGHT_RANGE * BE_WEIGHT_SCALE)
#define SRV_EWGHT_MAX   (SRV_UWGHT_MAX   * BE_WEIGHT_SCALE)

/* server ssl options */
#define SRV_SSL_O_NONE           0x0000
#define SRV_SSL_O_NO_TLS_TICKETS 0x0100 /* disable session resumption tickets */
#define SRV_SSL_O_NO_REUSE       0x200  /* disable session reuse */
#define SRV_SSL_O_EARLY_DATA     0x400  /* Allow using early data */

/* log servers ring's protocols options */
enum srv_log_proto {
        SRV_LOG_PROTO_LEGACY,         // messages on TCP separated by LF
        SRV_LOG_PROTO_OCTET_COUNTING, // TCP frames: MSGLEN SP MSG
};

/* srv administrative change causes */
enum srv_adm_st_chg_cause {
	SRV_ADM_STCHGC_NONE = 0,
	SRV_ADM_STCHGC_DNS_NOENT,     /* entry removed from srv record */
	SRV_ADM_STCHGC_DNS_NOIP,      /* no server ip in the srv record */
	SRV_ADM_STCHGC_DNS_NX,        /* resolution spent too much time in NX state */
	SRV_ADM_STCHGC_DNS_TIMEOUT,   /* resolution timeout */
	SRV_ADM_STCHGC_DNS_REFUSED,   /* query refused by dns server */
	SRV_ADM_STCHGC_DNS_UNSPEC,    /* unspecified dns error */
	SRV_ADM_STCHGC_STATS_DISABLE, /* legacy disable from the stats */
	SRV_ADM_STCHGC_STATS_STOP     /* legacy stop from the stats */
};

/* srv operational change causes */
enum srv_op_st_chg_cause {
	SRV_OP_STCHGC_NONE = 0,
	SRV_OP_STCHGC_HEALTH,         /* changed from a health check */
	SRV_OP_STCHGC_AGENT,          /* changed from an agent check */
	SRV_OP_STCHGC_CLI,            /* changed from the cli */
	SRV_OP_STCHGC_LUA,            /* changed from lua */
	SRV_OP_STCHGC_STATS_WEB,      /* changed from the web interface */
	SRV_OP_STCHGC_STATEFILE       /* changed from state file */
};

struct pid_list {
	struct list list;
	pid_t pid;
	struct task *t;
	int status;
	int exited;
};

/* srv methods of computing chash keys */
enum srv_hash_key {
	SRV_HASH_KEY_ID = 0,         /* derived from server puid */
	SRV_HASH_KEY_ADDR,           /* derived from server address */
	SRV_HASH_KEY_ADDR_PORT       /* derived from server address and port */
};

/* A tree occurrence is a descriptor of a place in a tree, with a pointer back
 * to the server itself.
 */
struct server;
struct tree_occ {
	struct server *server;
	struct eb32_node node;
};

/* Each server will have one occurrence of this structure per thread */
struct srv_per_thread {
	struct mt_list streams;                 /* streams using this server (used by "shutdown server sessions") */
	struct eb_root idle_conns;              /* Shareable idle connections */
	struct eb_root safe_conns;              /* Safe idle connections */
	struct eb_root avail_conns;             /* Connections in use, but with still new streams available */

	/* Secondary idle conn storage used in parallel to idle/safe trees.
	 * Used to sort them by last usage and purge them in reverse order.
	 */
	struct list idle_conn_list;
};

/* Each server will have one occurrence of this structure per thread group */
struct srv_per_tgroup {
	struct queue queue;			/* pending connections */
	unsigned int last_other_tgrp_served;	/* Last other tgrp we dequeued from */
	unsigned int self_served;		/* Number of connection we dequeued from our own queue */
	unsigned int dequeuing;                 /* non-zero = dequeuing in progress (atomic) */
	unsigned int next_takeover;             /* thread ID to try to steal connections from next time */
} THREAD_ALIGNED(64);

/* Configure the protocol selection for websocket */
enum __attribute__((__packed__)) srv_ws_mode {
	SRV_WS_AUTO = 0,
	SRV_WS_H1,
	SRV_WS_H2,
};

/* Server-side TLV list, contains the types of the TLVs that should be sent out.
 * Additionally, it can contain a format string, if specified in the config.
 */
struct srv_pp_tlv_list {
	struct list list;
	struct lf_expr fmt;
	char *fmt_string;
	unsigned char type;
};

struct proxy;
struct server {
	/* mostly config or admin stuff, doesn't change often */
	enum obj_type obj_type;                 /* object type == OBJ_TYPE_SERVER */
	enum srv_init_state init_state;         /* server's initial state among SRV_INIT_STATE */
	enum srv_state next_state, cur_state;   /* server state among SRV_ST_* */
	enum srv_admin next_admin, cur_admin;   /* server maintenance status : SRV_ADMF_* */
	signed char use_ssl;		        /* ssl enabled (1: on, 0: disabled, -1 forced off)  */
	unsigned int flags;                     /* server flags (SRV_F_*) */
	unsigned int pp_opts;                   /* proxy protocol options (SRV_PP_*) */
	struct mt_list global_list;             /* attach point in the global servers_list */
	struct server *next;
	int cklen;				/* the len of the cookie, to speed up checks */
	int rdr_len;				/* the length of the redirection prefix */
	char *cookie;				/* the id set in the cookie */
	char *rdr_pfx;				/* the redirection prefix */

	struct proxy *proxy;			/* the proxy this server belongs to */
	const struct mux_proto_list *mux_proto; /* the mux to use for all outgoing connections (specified by the "proto" keyword) */
	struct net_addr_type addr_type;         /* server address type (socket and transport hints) */
	struct log_target *log_target;          /* when 'mode log' is enabled, target facility used to transport log messages */
	unsigned maxconn, minconn;		/* max # of active sessions (0 = unlimited), min# for dynamic limit. */
	struct srv_per_thread *per_thr;         /* array of per-thread stuff such as connections lists */
	struct srv_per_tgroup *per_tgrp;        /* array of per-tgroup stuff such as idle conns and queues */
	unsigned int *curr_idle_thr;            /* Current number of orphan idling connections per thread */

	char *pool_conn_name;
	struct sample_expr *pool_conn_name_expr;
	unsigned int pool_purge_delay;          /* Delay before starting to purge the idle conns pool */
	unsigned int low_idle_conns;            /* min idle connection count to start picking from other threads */
	unsigned int max_idle_conns;            /* Max number of connection allowed in the orphan connections list */
	int max_reuse;                          /* Max number of requests on a same connection */
	struct task *warmup;                    /* the task dedicated to the warmup when slowstart is set */

	struct server *track;                   /* the server we're currently tracking, if any */
	struct server *trackers;                /* the list of servers tracking us, if any */
	struct server *tracknext;               /* next server tracking <track> in <track>'s trackers list */
	char *trackit;				/* temporary variable to make assignment deferrable */
	int consecutive_errors_limit;		/* number of consecutive errors that triggers an event */
	short observe, onerror;			/* observing mode: one of HANA_OBS_*; what to do on error: on of ANA_ONERR_* */
	short onmarkeddown;			/* what to do when marked down: one of HANA_ONMARKEDDOWN_* */
	short onmarkedup;			/* what to do when marked up: one of HANA_ONMARKEDUP_* */
	int slowstart;				/* slowstart time in seconds (ms in the conf) */

	char *id;				/* just for identification */
	uint32_t rid;				/* revision: if id has been reused for a new server, rid won't match */
	unsigned iweight,uweight, cur_eweight;	/* initial weight, user-specified weight, and effective weight */
	unsigned wscore;			/* weight score, used during srv map computation */
	unsigned next_eweight;			/* next pending eweight to commit */
	unsigned rweight;			/* remainder of weight in the current LB tree */
	unsigned cumulative_weight;		/* weight of servers prior to this one in the same group, for chash balancing */
	int maxqueue;				/* maximum number of pending connections allowed */
	unsigned int queueslength;		/* Sum of the length of each queue */
	int shard;				/* shard (in peers protocol context only) */
	int log_bufsize;			/* implicit ring bufsize (for log server only - in log backend) */

	enum srv_ws_mode ws;                    /* configure the protocol selection for websocket */
	/* 3 bytes hole here */

	struct mt_list watcher_list;		/* list of elems which currently references this server instance */
	uint refcount;                          /* refcount used to remove a server at runtime */

	/* The elements below may be changed on every single request by any
	 * thread, and generally at the same time.
	 */
	THREAD_PAD(63);
	struct eb32_node idle_node;             /* When to next do cleanup in the idle connections */
	unsigned int curr_idle_conns;           /* Current number of orphan idling connections, both the idle and the safe lists */
	unsigned int curr_idle_nb;              /* Current number of connections in the idle list */
	unsigned int curr_safe_nb;              /* Current number of connections in the safe list */
	unsigned int curr_used_conns;           /* Current number of used connections */
	unsigned int max_used_conns;            /* Max number of used connections (the counter is reset at each connection purges */
	unsigned int est_need_conns;            /* Estimate on the number of needed connections (max of curr and previous max_used) */

	struct mt_list sess_conns;		/* list of private conns managed by a session on this server */

	/* Element below are usd by LB algorithms and must be doable in
	 * parallel to other threads reusing connections above.
	 */
	THREAD_PAD(63);
	__decl_thread(HA_SPINLOCK_T lock);      /* may enclose the proxy's lock, must not be taken under */
	unsigned npos, lpos;			/* next and last positions in the LB tree, protected by LB lock */
	union {
		struct eb32_node lb_node;       /* node used for tree-based load balancing */
		struct list lb_list;            /* elem used for list-based load balancing */
	};
	struct server *next_full;               /* next server in the temporary full list */

	/* usually atomically updated by any thread during parsing or on end of request */
	THREAD_PAD(63);
	int cur_sess;				/* number of currently active sessions (including syn_sent) */
	int served;				/* # of active sessions currently being served (ie not pending) */
	int consecutive_errors;			/* current number of consecutive errors */
	struct be_counters counters;		/* statistics counters */

	/* Below are some relatively stable settings, only changed under the lock */
	THREAD_PAD(63);

	struct eb_root *lb_tree;                /* we want to know in what tree the server is */
	struct tree_occ *lb_nodes;              /* lb_nodes_tot * struct tree_occ */
	unsigned lb_nodes_tot;                  /* number of allocated lb_nodes (C-HASH) */
	unsigned lb_nodes_now;                  /* number of lb_nodes placed in the tree (C-HASH) */
	enum srv_hash_key hash_key;             /* method to compute node hash (C-HASH) */
	unsigned lb_server_key;                 /* hash of the values indicated by "hash_key" (C-HASH) */

	const struct netns_entry *netns;        /* contains network namespace name or NULL. Network namespace comes from configuration */
	struct xprt_ops *xprt;                  /* transport-layer operations */
	int alt_proto;                          /* alternate protocol to use in protocol_lookup */
	unsigned int svc_port;                  /* the port to connect to (for relevant families) */
	unsigned down_time;			/* total time the server was down */

	int puid;				/* proxy-unique server ID, used for SNMP, and "first" LB algo */
	int tcp_ut;                             /* for TCP, user timeout */

	int do_check;                           /* temporary variable used during parsing to denote if health checks must be enabled */
	int do_agent;                           /* temporary variable used during parsing to denote if an auxiliary agent check must be enabled */
	struct check check;                     /* health-check specific configuration */
	struct check agent;                     /* agent specific configuration */

	struct resolv_requester *resolv_requester; /* used to link a server to its DNS resolution */
	char *resolvers_id;			/* resolvers section used by this server */
	struct resolvers *resolvers;		/* pointer to the resolvers structure used by this server */
	char *lastaddr;				/* the address string provided by the server-state file */
	struct resolv_options resolv_opts;
	int hostname_dn_len;			/* string length of the server hostname in Domain Name format */
	char *hostname_dn;			/* server hostname in Domain Name format */
	char *hostname;				/* server hostname */
	struct sockaddr_storage init_addr;	/* plain IP address specified on the init-addr line */
	unsigned int init_addr_methods;		/* initial address setting, 3-bit per method, ends at 0, enough to store 10 entries */
	enum srv_log_proto log_proto;		/* used proto to emit messages on server lines from log or ring section */

	char *sni_expr;             /* Temporary variable to store a sample expression for SNI */
	struct {
		void *ctx;
		struct {
			/* ptr/size may be shared R/O with other threads under read lock
			 * "sess_lock", however only the owning thread may change them
			 * (under write lock).
			 */
			unsigned char *ptr;
			int size;
			int allocated_size;
			char *sni; /* SNI used for the session */
			__decl_thread(HA_RWLOCK_T sess_lock);
		} * reused_sess;
		uint last_ssl_sess_tid;         /* last tid+1 having updated reused_sess (0=none, >0=tid+1) */

		struct ckch_inst *inst; /* Instance of the ckch_store in which the certificate was loaded (might be null if server has no certificate) */
		__decl_thread(HA_RWLOCK_T lock); /* lock the cache and SSL_CTX during commit operations */

		char *ciphers;			/* cipher suite to use if non-null */
		char *ciphersuites;			/* TLS 1.3 cipher suite to use if non-null */
		char *curves;                    /* TLS curves list */
		int options;			/* ssl options */
		int verify;			/* verify method (set of SSL_VERIFY_* flags) */
		struct tls_version_filter methods;	/* ssl methods */
		char *verify_host;              /* hostname of certificate must match this host */
		char *ca_file;			/* CAfile to use on verify */
		char *crl_file;			/* CRLfile to use on verify */
		char *client_crt;		/* client certificate to send */
		char *sigalgs;			/* Signature algorithms */
		char *client_sigalgs;           /* Client Signature algorithms */
		struct sample_expr *sni;        /* sample expression for SNI */
		char *npn_str;                  /* NPN protocol string */
		int npn_len;                    /* NPN protocol string length */
		char *alpn_str;                 /* ALPN protocol string */
		int alpn_len;                   /* ALPN protocol string length */
	} ssl_ctx;
	struct resolv_srvrq *srvrq;		/* Pointer representing the DNS SRV requeest, if any */
	struct list srv_rec_item;		/* to attach server to a srv record item */
	struct list ip_rec_item;		/* to attach server to a A or AAAA record item */
	struct ebpt_node host_dn;		/* hostdn store for srvrq and state file matching*/
	struct list pp_tlvs;			/* to send out PROXY protocol v2 TLVs */
	struct task *srvrq_check;               /* Task testing SRV record expiration date for this server */
	struct {
		const char *file;		/* file where the section appears */
		struct eb32_node id;		/* place in the tree of used IDs */
		struct ebpt_node name;		/* place in the tree of used names */
		int line;			/* line where the section appears */
	} conf;					/* config information */
	struct ebpt_node addr_node;             /* Node for string representation of address for the server (including port number) */
	/* Template information used only for server objects which
	 * serve as template filled at parsing time and used during
	 * server allocations from server templates.
	 */
	struct {
		char *prefix;
		int nb_low;
		int nb_high;
	} tmpl_info;

	event_hdl_sub_list e_subs;		/* event_hdl: server's subscribers list (atomically updated) */

	struct guid_node guid;			/* GUID global tree node */

	/* warning, these structs are huge, keep them at the bottom */
	struct conn_src conn_src;               /* connection source settings */
	struct sockaddr_storage addr;           /* the address to connect to, doesn't include the port */
	struct sockaddr_storage socks4_addr;	/* the address of the SOCKS4 Proxy, including the port */

	EXTRA_COUNTERS(extra_counters);
};

/* data provided to EVENT_HDL_SUB_SERVER handlers through event_hdl facility */
struct event_hdl_cb_data_server {
	/* provided by:
	 *   EVENT_HDL_SUB_SERVER_ADD
	 *   EVENT_HDL_SUB_SERVER_DEL
	 *   EVENT_HDL_SUB_SERVER_UP
	 *   EVENT_HDL_SUB_SERVER_DOWN
	 *   EVENT_HDL_SUB_SERVER_STATE
	 *   EVENT_HDL_SUB_SERVER_ADMIN
	 *   EVENT_HDL_SUB_SERVER_CHECK
	 *   EVENT_HDL_SUB_SERVER_INETADDR
	 */
	struct {
		/* safe data can be safely used from both
		 * sync and async handlers
		 * data consistency is guaranteed
		 */
		char name[64];       /* server name/id */
		char proxy_name[64]; /* id of proxy the server belongs to */
		int proxy_uuid;      /* uuid of the proxy the server belongs to */
		int puid;            /* proxy-unique server ID */
		uint32_t rid;        /* server id revision */
		unsigned int flags;  /* server flags */
	} safe;
	struct {
		/* unsafe data may only be used from sync handlers:
		 * in async mode, data consistency cannot be guaranteed
		 * and unsafe data may already be stale, thus using
		 * it is highly discouraged because it
		 * could lead to undefined behavior (UAF, null dereference...)
		 */
		struct server *ptr;	/* server live ptr */
		/* lock hints */
		uint8_t thread_isolate;	/* 1 = thread_isolate is on, no locking required */
		uint8_t srv_lock;       /* 1 = srv lock is held */
	} unsafe;
};

/* check result snapshot provided through some event_hdl server events */
struct event_hdl_cb_data_server_checkres {
	uint8_t agent;                /* 1 = agent check, 0 = health check */
	enum chk_result result;       /* failed, passed, condpass (CHK_RES_*) */
	long duration;                /* total check duration in ms */
	struct {
		short status;         /* check status as in check->status */
		short code;           /* provided with some check statuses */
	} reason;
	struct {
		int cur;              /* dynamic (= check->health) */
		int rise, fall;       /* config dependent */
	} health;                     /* check's health, see check-t.h */
};

/* data provided to EVENT_HDL_SUB_SERVER_STATE handlers through
 * event_hdl facility
 *
 * Note that this may be casted to regular event_hdl_cb_data_server if
 * you don't care about state related optional info
 */
struct event_hdl_cb_data_server_state {
	/* provided by:
	 *   EVENT_HDL_SUB_SERVER_STATE
	 */
	struct event_hdl_cb_data_server server; /* must be at the beginning */
	struct {
		uint8_t type; /* 0 = operational, 1 = administrative */
		enum srv_state old_state, new_state; /* updated by both operational and admin changes */
		uint32_t requeued; /* requeued connections due to server state change */
		union {
			/* state change cause:
			 *
			 * look for op_st_chg for operational state change,
			 * and adm_st_chg for administrative state change
			 */
			struct {
				enum srv_op_st_chg_cause cause;
				union {
					/* check result is provided with
					 * cause == SRV_OP_STCHGC_HEALTH or cause == SRV_OP_STCHGC_AGENT
					 */
					struct event_hdl_cb_data_server_checkres check;
				};
			} op_st_chg;
			struct {
				enum srv_adm_st_chg_cause cause;
			} adm_st_chg;
		};
	} safe;
	/* no unsafe data */
};

/* data provided to EVENT_HDL_SUB_SERVER_ADMIN handlers through
 * event_hdl facility
 *
 * Note that this may be casted to regular event_hdl_cb_data_server if
 * you don't care about admin related optional info
 */
struct event_hdl_cb_data_server_admin {
	/* provided by:
	 *   EVENT_HDL_SUB_SERVER_ADMIN
	 */
	struct event_hdl_cb_data_server server; /* must be at the beginning */
	struct {
		enum srv_admin old_admin, new_admin;
		uint32_t requeued; /* requeued connections due to server admin change */
		/* admin change cause */
		enum srv_adm_st_chg_cause cause;
	} safe;
	/* no unsafe data */
};

/* data provided to EVENT_HDL_SUB_SERVER_CHECK handlers through
 * event_hdl facility
 *
 * Note that this may be casted to regular event_hdl_cb_data_server if
 * you don't care about check related optional info
 */
struct event_hdl_cb_data_server_check {
	/* provided by:
	 *   EVENT_HDL_SUB_SERVER_CHECK
	 */
	struct event_hdl_cb_data_server server;                 /* must be at the beginning */
	struct {
		struct event_hdl_cb_data_server_checkres res;   /* check result snapshot */
	} safe;
	struct {
		struct check *ptr;                              /* check ptr */
	} unsafe;
};

/* struct to store server address and port information in INET
 * context
 */
struct server_inetaddr {
	int family; /* AF_UNSPEC, AF_INET or AF_INET6 */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr; /* may hold v4 or v6 addr */
	struct {
		unsigned int svc;
		uint8_t map; /* is a mapped port? (boolean) */
	} port;
};

/* struct to store information about server's addr / port updater in
 * INET context
 */
enum server_inetaddr_updater_by {
	SERVER_INETADDR_UPDATER_BY_NONE = 0,
	SERVER_INETADDR_UPDATER_BY_CLI,
	SERVER_INETADDR_UPDATER_BY_LUA,
	SERVER_INETADDR_UPDATER_BY_DNS_AR,
	SERVER_INETADDR_UPDATER_BY_DNS_CACHE,
	SERVER_INETADDR_UPDATER_BY_DNS_RESOLVER,
	/* changes here must be reflected in SERVER_INETADDR_UPDATER_*
	 * helper macros and in server_inetaddr_updater_by_to_str() func
	 */
};
struct server_inetaddr_updater {
	enum server_inetaddr_updater_by by; // by identifier (unique)
	uint8_t dns;                        // is dns involved?
	union {
		struct {
			unsigned int ns_id; // nameserver id responsible for the update
		} dns_resolver;             // SERVER_INETADDR_UPDATER_DNS_RESOLVER specific infos
	} u;                                // per updater's additional ctx
};
#define SERVER_INETADDR_UPDATER_NONE                                           \
 (struct server_inetaddr_updater){ .by = SERVER_INETADDR_UPDATER_BY_NONE,      \
                                   .dns = 0 }

#define SERVER_INETADDR_UPDATER_CLI                                            \
 (struct server_inetaddr_updater){ .by = SERVER_INETADDR_UPDATER_BY_CLI,       \
                                   .dns = 0 }

#define SERVER_INETADDR_UPDATER_LUA                                            \
 (struct server_inetaddr_updater){ .by = SERVER_INETADDR_UPDATER_BY_LUA,       \
                                   .dns = 0 }

#define SERVER_INETADDR_UPDATER_DNS_AR                                         \
 (struct server_inetaddr_updater){ .by = SERVER_INETADDR_UPDATER_BY_DNS_AR,    \
                                   .dns = 1 }

#define SERVER_INETADDR_UPDATER_DNS_CACHE                                      \
 (struct server_inetaddr_updater){ .by = SERVER_INETADDR_UPDATER_BY_DNS_CACHE, \
                                   .dns = 1 }

#define SERVER_INETADDR_UPDATER_DNS_RESOLVER(_ns_id)                           \
 (struct server_inetaddr_updater){                                             \
    .by = SERVER_INETADDR_UPDATER_BY_DNS_RESOLVER,                             \
    .dns = 1,                                                                  \
    .u.dns_resolver.ns_id = _ns_id,                                            \
 }

/* data provided to EVENT_HDL_SUB_SERVER_INETADDR handlers through
 * event_hdl facility
 *
 * Note that this may be casted to regular event_hdl_cb_data_server if
 * you don't care about inetaddr related optional info
 */
struct event_hdl_cb_data_server_inetaddr {
	/* provided by:
	 *   EVENT_HDL_SUB_SERVER_INETADDR
	 */
	struct event_hdl_cb_data_server server;                 /* must be at the beginning */
	struct {
		struct server_inetaddr prev;
		struct server_inetaddr next;
		struct server_inetaddr_updater updater;
	} safe;
	/* no unsafe data */
};

/* Storage structure to load server-state lines from a flat file into
 * an ebtree, for faster processing
 */
struct server_state_line {
	char *line;
	char *params[SRV_STATE_FILE_MAX_FIELDS];
	struct eb64_node node;
};


/* Descriptor for a "server" keyword. The ->parse() function returns 0 in case of
 * success, or a combination of ERR_* flags if an error is encountered. The
 * function pointer can be NULL if not implemented. The function also has an
 * access to the current "server" config line. The ->skip value tells the parser
 * how many words have to be skipped after the keyword. If the function needs to
 * parse more keywords, it needs to update cur_arg.
 */
struct srv_kw {
	const char *kw;
	int (*parse)(char **args, int *cur_arg, struct proxy *px, struct server *srv, char **err);
	int skip; /* nb min of args to skip, for use when kw is not handled */
	int default_ok; /* non-zero if kw is supported in default-server section */
	int dynamic_ok; /* non-zero if kw is supported in add server cli command */
};

/*
 * A keyword list. It is a NULL-terminated array of keywords. It embeds a
 * struct list in order to be linked to other lists, allowing it to easily
 * be declared where it is needed, and linked without duplicating data nor
 * allocating memory. It is also possible to indicate a scope for the keywords.
 */
struct srv_kw_list {
	const char *scope;
	struct list list;
	struct srv_kw kw[VAR_ARRAY];
};

#define SRV_PARSE_DEFAULT_SERVER  0x01    /* 'default-server' keyword */
#define SRV_PARSE_TEMPLATE        0x02    /* 'server-template' keyword */
#define SRV_PARSE_IN_PEER_SECTION 0x04    /* keyword in a peer section */
#define SRV_PARSE_PARSE_ADDR      0x08    /* required to parse the server address in the second argument */
#define SRV_PARSE_DYNAMIC         0x10    /* dynamic server created at runtime with cli */
#define SRV_PARSE_INITIAL_RESOLVE 0x20    /* resolve immediately the fqdn to an ip address */

#endif /* _HAPROXY_SERVER_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
