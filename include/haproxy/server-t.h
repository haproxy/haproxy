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

#include <import/eb32tree.h>
#include <import/ebmbtree.h>

#include <haproxy/api-t.h>
#include <haproxy/check-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/counters-t.h>
#include <haproxy/dns-t.h>
#include <haproxy/freq_ctr-t.h>
#include <haproxy/listener-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/task-t.h>
#include <haproxy/thread-t.h>
#include <haproxy/xprt_quic-t.h>


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
	SRV_ADMF_MAINT     = 0x23,        /* mask to check if any maintenance flag is present */
	SRV_ADMF_CMAINT    = 0x04,        /* the server is in maintenance because of the configuration */
	SRV_ADMF_FDRAIN    = 0x08,        /* the server was explicitly forced into drain state */
	SRV_ADMF_IDRAIN    = 0x10,        /* the server has inherited the drain status from a tracked server */
	SRV_ADMF_DRAIN     = 0x18,        /* mask to check if any drain flag is present */
	SRV_ADMF_RMAINT    = 0x20,        /* the server is down because of an IP address resolution failure */
	SRV_ADMF_HMAINT    = 0x40,        /* the server FQDN has been set from socket stats */
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
    "srv_use_ssl"

#define SRV_STATE_FILE_MAX_FIELDS 21
#define SRV_STATE_FILE_NB_FIELDS_VERSION_1 20
#define SRV_STATE_LINE_MAXLEN 512

/* server flags -- 32 bits */
#define SRV_F_BACKUP       0x0001        /* this server is a backup server */
#define SRV_F_MAPPORTS     0x0002        /* this server uses mapped ports */
#define SRV_F_NON_STICK    0x0004        /* never add connections allocated to this server to a stick table */
#define SRV_F_USE_NS_FROM_PP 0x0008      /* use namespace associated with connection if present */
#define SRV_F_FORCED_ID    0x0010        /* server's ID was forced in the configuration */
#define SRV_F_CHECKADDR    0x0020        /* this server has a check addr configured */
#define SRV_F_CHECKPORT    0x0040        /* this server has a check port configured */
#define SRV_F_AGENTADDR    0x0080        /* this server has a agent addr configured */
#define SRV_F_COOKIESET    0x0100        /* this server has a cookie configured, so don't generate dynamic cookies */
#define SRV_F_FASTOPEN     0x0200        /* Use TCP Fast Open to connect to server */
#define SRV_F_SOCKS4_PROXY 0x0400        /* this server uses SOCKS4 proxy */
#define SRV_F_NO_RESOLUTION 0x0800       /* disable runtime DNS resolution on this server */

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

struct pid_list {
	struct list list;
	pid_t pid;
	struct task *t;
	int status;
	int exited;
};

/* A tree occurrence is a descriptor of a place in a tree, with a pointer back
 * to the server itself.
 */
struct server;
struct tree_occ {
	struct server *server;
	struct eb32_node node;
};

struct proxy;
struct server {
	enum obj_type obj_type;                 /* object type == OBJ_TYPE_SERVER */
	enum srv_state next_state, cur_state;   /* server state among SRV_ST_* */
	enum srv_admin next_admin, cur_admin;   /* server maintenance status : SRV_ADMF_* */
	signed char use_ssl;		        /* ssl enabled (1: on, 0: disabled, -1 forced off)  */
	unsigned int pp_opts;                   /* proxy protocol options (SRV_PP_*) */
	struct server *next;
	int cklen;				/* the len of the cookie, to speed up checks */
	int rdr_len;				/* the length of the redirection prefix */
	char *cookie;				/* the id set in the cookie */
	char *rdr_pfx;				/* the redirection prefix */

	struct proxy *proxy;			/* the proxy this server belongs to */
	const struct mux_proto_list *mux_proto;       /* the mux to use for all outgoing connections (specified by the "proto" keyword) */
	int served;				/* # of active sessions currently being served (ie not pending) */
	int cur_sess;				/* number of currently active sessions (including syn_sent) */
	unsigned maxconn, minconn;		/* max # of active sessions (0 = unlimited), min# for dynamic limit. */
	int nbpend;				/* number of pending connections */
	unsigned int queue_idx;			/* count of pending connections which have been de-queued */
	int maxqueue;				/* maximum number of pending connections allowed */
	struct freq_ctr sess_per_sec;		/* sessions per second on this server */
	struct be_counters counters;		/* statistics counters */

	struct eb_root pendconns;		/* pending connections */
	struct list actconns;			/* active connections */
	struct mt_list *idle_conns;		/* shareable idle connections*/
	struct mt_list *safe_conns;		/* safe idle connections */
	struct list *available_conns;           /* Connection in used, but with still new streams available */
	unsigned int pool_purge_delay;          /* Delay before starting to purge the idle conns pool */
	unsigned int low_idle_conns;            /* min idle connection count to start picking from other threads */
	unsigned int max_idle_conns;            /* Max number of connection allowed in the orphan connections list */
	unsigned int curr_idle_conns;           /* Current number of orphan idling connections, both the idle and the safe lists */
	unsigned int curr_idle_nb;              /* Current number of connections in the idle list */
	unsigned int curr_safe_nb;              /* Current number of connections in the safe list */
	unsigned int curr_used_conns;           /* Current number of used connections */
	unsigned int max_used_conns;            /* Max number of used connections (the counter is reset at each connection purges */
	unsigned int est_need_conns;            /* Estimate on the number of needed connections (max of curr and previous max_used) */
	unsigned int next_takeover;             /* thread ID to try to steal connections from next time */
	unsigned int *curr_idle_thr;            /* Current number of orphan idling connections per thread */
	int max_reuse;                          /* Max number of requests on a same connection */
	__decl_thread(HA_SPINLOCK_T lock);      /* may enclose the proxy's lock, must not be taken under */
	struct eb32_node idle_node;             /* When to next do cleanup in the idle connections */
	struct task *warmup;                    /* the task dedicated to the warmup when slowstart is set */

	struct conn_src conn_src;               /* connection source settings */

	struct server *track;                   /* the server we're currently tracking, if any */
	struct server *trackers;                /* the list of servers tracking us, if any */
	struct server *tracknext;               /* next server tracking <track> in <track>'s trackers list */
	char *trackit;				/* temporary variable to make assignment deferrable */
	int consecutive_errors;			/* current number of consecutive errors */
	int consecutive_errors_limit;		/* number of consecutive errors that triggers an event */
	short observe, onerror;			/* observing mode: one of HANA_OBS_*; what to do on error: on of ANA_ONERR_* */
	short onmarkeddown;			/* what to do when marked down: one of HANA_ONMARKEDDOWN_* */
	short onmarkedup;			/* what to do when marked up: one of HANA_ONMARKEDUP_* */
	unsigned int flags;                     /* server flags (SRV_F_*) */
	int slowstart;				/* slowstart time in seconds (ms in the conf) */

	char *id;				/* just for identification */
	unsigned iweight,uweight, cur_eweight;	/* initial weight, user-specified weight, and effective weight */
	unsigned wscore;			/* weight score, used during srv map computation */
	unsigned next_eweight;			/* next pending eweight to commit */
	unsigned rweight;			/* remainer of weight in the current LB tree */
	unsigned cumulative_weight;		/* weight of servers prior to this one in the same group, for chash balancing */
	unsigned npos, lpos;			/* next and last positions in the LB tree */
	struct eb32_node lb_node;               /* node used for tree-based load balancing */
	struct eb_root *lb_tree;                /* we want to know in what tree the server is */
	struct server *next_full;               /* next server in the temporary full list */
	unsigned lb_nodes_tot;                  /* number of allocated lb_nodes (C-HASH) */
	unsigned lb_nodes_now;                  /* number of lb_nodes placed in the tree (C-HASH) */
	struct tree_occ *lb_nodes;              /* lb_nodes_tot * struct tree_occ */

	const struct netns_entry *netns;        /* contains network namespace name or NULL. Network namespace comes from configuration */
	/* warning, these structs are huge, keep them at the bottom */
	struct sockaddr_storage addr;           /* the address to connect to, doesn't include the port */
	struct xprt_ops *xprt;                  /* transport-layer operations */
	unsigned int svc_port;                  /* the port to connect to (for relevant families) */
	unsigned down_time;			/* total time the server was down */
	time_t last_change;			/* last time, when the state was changed */

	int puid;				/* proxy-unique server ID, used for SNMP, and "first" LB algo */
	int tcp_ut;                             /* for TCP, user timeout */

	int do_check;                           /* temporary variable used during parsing to denote if health checks must be enabled */
	int do_agent;                           /* temporary variable used during parsing to denote if an auxiliary agent check must be enabled */
	struct check check;                     /* health-check specific configuration */
	struct check agent;                     /* agent specific configuration */

	struct dns_requester *dns_requester;	/* used to link a server to its DNS resolution */
	char *resolvers_id;			/* resolvers section used by this server */
	struct dns_resolvers *resolvers;	/* pointer to the resolvers structure used by this server */
	char *lastaddr;				/* the address string provided by the server-state file */
	struct dns_options dns_opts;
	int hostname_dn_len;			/* string length of the server hostname in Domain Name format */
	char *hostname_dn;			/* server hostname in Domain Name format */
	char *hostname;				/* server hostname */
	struct sockaddr_storage init_addr;	/* plain IP address specified on the init-addr line */
	unsigned int init_addr_methods;		/* initial address setting, 3-bit per method, ends at 0, enough to store 10 entries */
	enum srv_log_proto log_proto;		/* used proto to emit messages on server lines from ring section */

#ifdef USE_OPENSSL
	char *sni_expr;             /* Temporary variable to store a sample expression for SNI */
	struct {
		SSL_CTX *ctx;
		struct {
			unsigned char *ptr;
			int size;
			int allocated_size;
		} * reused_sess;
		char *ciphers;			/* cipher suite to use if non-null */
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
		char *ciphersuites;			/* TLS 1.3 cipher suite to use if non-null */
#endif
		int options;			/* ssl options */
		int verify;			/* verify method (set of SSL_VERIFY_* flags) */
		struct tls_version_filter methods;	/* ssl methods */
		char *verify_host;              /* hostname of certificate must match this host */
		char *ca_file;			/* CAfile to use on verify */
		char *crl_file;			/* CRLfile to use on verify */
		char *client_crt;		/* client certificate to send */
		struct sample_expr *sni;        /* sample expression for SNI */
#ifdef OPENSSL_NPN_NEGOTIATED
		char *npn_str;                  /* NPN protocol string */
		int npn_len;                    /* NPN protocol string length */
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
		char *alpn_str;                 /* ALPN protocol string */
		int alpn_len;                   /* ALPN protocol string length */
#endif
	} ssl_ctx;
#ifdef USE_QUIC
	struct quic_transport_params quic_params; /* QUIC transport parameters */
	struct eb_root cids;        /* QUIC connections IDs. */
#endif
#endif
	struct dns_srvrq *srvrq;		/* Pointer representing the DNS SRV requeest, if any */
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
	struct {
		long duration;
		short status, code;
		char reason[128];
	} op_st_chg;				/* operational status change's reason */
	char adm_st_chg_cause[48];		/* administrative status change's cause */

	struct sockaddr_storage socks4_addr;	/* the address of the SOCKS4 Proxy, including the port */

	EXTRA_COUNTERS(extra_counters);
};


/* Storage structure to load server-state lines from a flat file into
 * an ebtree, for faster processing
 */
struct state_line {
	char *line;
	struct ebmb_node name_name;
	/* WARNING don't put anything after name_name, it's used by the key */
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

#endif /* _HAPROXY_SERVER_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
