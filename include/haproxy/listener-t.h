/*
 * include/haproxy/listener-t.h
 * This file defines the structures needed to manage listeners.
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

#ifndef _HAPROXY_LISTENER_T_H
#define _HAPROXY_LISTENER_T_H

#include <sys/types.h>
#include <sys/socket.h>

#include <import/ebtree-t.h>

#include <haproxy/api-t.h>
#include <haproxy/guid-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/quic_sock-t.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/receiver-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/thread.h>

/* Some pointer types reference below */
struct task;
struct protocol;
struct xprt_ops;
struct proxy;
struct fe_counters;
struct connection;

/* listener state */
enum li_state {
	LI_NEW	= 0,    /* not initialized yet */
	LI_INIT,        /* all parameters filled in, but not assigned yet */
	LI_ASSIGNED,    /* assigned to the protocol, but not listening yet */
	LI_PAUSED,      /* listener was paused, it's bound but not listening  */
	LI_LISTEN,      /* started, listening but not enabled */
	LI_READY,       /* started, listening and enabled */
	LI_FULL,        /* reached its connection limit */
	LI_LIMITED,     /* transient state: limits have been reached, listener is queued */
} __attribute__((packed));

/* Listener transitions
 * calloc()     set()      add_listener()       bind()
 * -------> NEW ----> INIT ----------> ASSIGNED -----> LISTEN
 * <-------     <----      <----------          <-----
 *    free()   bzero()     del_listener()       unbind()
 *
 * The file descriptor is valid only during these three states :
 *
 *             disable()
 * LISTEN <------------ READY
 *   A|   ------------>  |A
 *   ||  !max & enable() ||
 *   ||                  ||
 *   ||              max ||
 *   || max & enable()   V| !max
 *   |+---------------> FULL
 *   +-----------------
 *            disable()
 *
 * The LIMITED state my be used when a limit has been detected just before
 * using a listener. In this case, the listener MUST be queued into the
 * appropriate wait queue (either the proxy's or the global one). It may be
 * set back to the READY state at any instant and for any reason, so one must
 * not rely on this state.
 */

/* listener status for stats */
enum li_status {
	LI_STATUS_WAITING = 0,
	LI_STATUS_OPEN,
	LI_STATUS_FULL,

	LI_STATE_COUNT /* must be last */
};

/* Note: if a bind_conf uses BC_O_UNLIMITED, it is highly recommended that it adds its own
 * maxconn setting to the global.maxsock value so that its resources are reserved.
 */

/* flags used with bind_conf->options */
#define BC_O_USE_SSL            0x00000001 /* SSL is being used on this bind_conf */
#define BC_O_GENERATE_CERTS     0x00000002 /* 1 if generate-certificates option is set, else 0 */
#define BC_O_QUIC_FORCE_RETRY   0x00000004 /* always send Retry on reception of Initial without token */
#define BC_O_USE_SOCK_DGRAM     0x00000008 /* at least one datagram-type listener is used */
#define BC_O_USE_SOCK_STREAM    0x00000010 /* at least one stream-type listener is used */
#define BC_O_USE_XPRT_DGRAM     0x00000020 /* at least one dgram-only xprt listener is used */
#define BC_O_USE_XPRT_STREAM    0x00000040 /* at least one stream-only xprt listener is used */
#define BC_O_NOLINGER           0x00000080 /* disable lingering on these listeners */
#define BC_O_NOQUICKACK         0x00000100 /* disable quick ack of immediate data (linux) */
#define BC_O_DEF_ACCEPT         0x00000200 /* wait up to 1 second for data before accepting */
#define BC_O_TCP_FO             0x00000400 /* enable TCP Fast Open (linux >= 3.7) */
#define BC_O_ACC_PROXY          0x00000800 /* find the proxied address in the first request line */
#define BC_O_ACC_CIP            0x00001000 /* find the proxied address in the NetScaler Client IP header */
#define BC_O_UNLIMITED          0x00002000 /* listeners not subject to global limits (peers & stats socket) */
#define BC_O_NOSTOP             0x00004000 /* keep the listeners active even after a soft stop */
#define BC_O_REVERSE_HTTP       0x00008000 /* a reverse HTTP bind is used */
#define BC_O_XPRT_MAXCONN       0x00010000 /* transport layer allocates its own resource prior to accept and is responsible to check maxconn limit */


/* flags used with bind_conf->ssl_options */
#ifdef USE_OPENSSL
#define BC_SSL_O_NONE           0x0000
#define BC_SSL_O_NO_TLS_TICKETS 0x0100	/* disable session resumption tickets */
#define BC_SSL_O_PREF_CLIE_CIPH 0x0200  /* prefer client ciphers */
#endif

struct tls_version_filter {
	uint16_t flags;     /* ssl options */
	uint8_t  min;      /* min TLS version */
	uint8_t  max;      /* max TLS version */
};

/* ssl "bind" settings */
struct ssl_bind_conf {
#ifdef USE_OPENSSL
	char *npn_str;             /* NPN protocol string */
	int npn_len;               /* NPN protocol string length */
	char *alpn_str;            /* ALPN protocol string */
	int alpn_len;              /* ALPN protocol string length */
	unsigned int verify:3;     /* verify method (set of SSL_VERIFY_* flags) */
	unsigned int no_ca_names:1;/* do not send ca names to clients (ca_file related) */
	unsigned int early_data:1; /* early data allowed */
	char *ca_file;             /* CAfile to use on verify and ca-names */
	char *ca_verify_file;      /* CAverify file to use on verify only */
	char *crl_file;            /* CRLfile to use on verify */
	char *ciphers;             /* cipher suite to use if non-null */
	char *ciphersuites;        /* TLS 1.3 cipher suite to use if non-null */
	char *curves;	           /* curves suite to use for ECDHE */
	char *ecdhe;               /* named curve to use for ECDHE */
	char *sigalgs;             /* Signature algorithms */
	char *client_sigalgs;      /* Client Signature algorithms */
	struct tls_version_filter ssl_methods_cfg; /* original ssl methods found in configuration */
	struct tls_version_filter ssl_methods; /* actual ssl methods used at runtime */
#endif
};

/*
 * In OpenSSL 3.0.0, the biggest verify error code's value is 94 and on the
 * latest 1.1.1 it already reaches 79 so we need to size the ca/crt-ignore-err
 * arrays accordingly. If the max error code increases, the arrays might need to
 * be resized.
 */
#define SSL_MAX_VFY_ERROR_CODE 94
#define IGNERR_BF_SIZE ((SSL_MAX_VFY_ERROR_CODE >> 6) + 1)

/* "bind" line settings */
struct bind_conf {
#ifdef USE_OPENSSL
	struct ssl_bind_conf ssl_conf; /* ssl conf for ctx setting */
	unsigned long long ca_ignerr_bitfield[IGNERR_BF_SIZE];   /* ignored verify errors in handshake if depth > 0 */
	unsigned long long crt_ignerr_bitfield[IGNERR_BF_SIZE];  /* ignored verify errors in handshake if depth == 0 */
	void *initial_ctx;             /* SSL context for initial negotiation */
	int strict_sni;            /* refuse negotiation if sni doesn't match a certificate */
	int ssl_options;           /* ssl options */
	struct eb_root sni_ctx;    /* sni_ctx tree of all known certs full-names sorted by name */
	struct eb_root sni_w_ctx;  /* sni_ctx tree of all known certs wildcards sorted by name */
	struct tls_keys_ref *keys_ref; /* TLS ticket keys reference */

	char *ca_sign_file;        /* CAFile used to generate and sign server certificates */
	char *ca_sign_pass;        /* CAKey passphrase */

	struct ckch_data *ca_sign_ckch;	/* CA and possible certificate chain for ca generation */
#endif
#ifdef USE_QUIC
	struct quic_transport_params quic_params; /* QUIC transport parameters. */
	struct quic_cc_algo *quic_cc_algo; /* QUIC control congestion algorithm */
	size_t max_cwnd;                   /* QUIC maximumu congestion control window size (kB) */
	enum quic_sock_mode quic_mode;     /* QUIC socket allocation strategy */
#endif
	struct proxy *frontend;    /* the frontend all these listeners belong to, or NULL */
	const struct mux_proto_list *mux_proto; /* the mux to use for all incoming connections (specified by the "proto" keyword) */
	struct xprt_ops *xprt;     /* transport-layer operations for all listeners */
	uint options;              /* set of BC_O_* flags */
	unsigned int analysers;    /* bitmap of required protocol analysers */
	int maxseg;                /* for TCP, advertised MSS */
	int tcp_ut;                /* for TCP, user timeout */
	int maxaccept;             /* if set, max number of connections accepted at once (-1 when disabled) */
	unsigned int backlog;      /* if set, listen backlog */
	int maxconn;               /* maximum connections allowed on this listener */
	int (*accept)(struct connection *conn); /* upper layer's accept() */
	int level;                 /* stats access level (ACCESS_LVL_*) */
	int severity_output;       /* default severity output format in cli feedback messages */
	short int nice;            /* nice value to assign to the instantiated tasks */
	/* 2-byte hole here */
	struct list listeners;     /* list of listeners using this bind config */
	uint32_t ns_cip_magic;     /* Excepted NetScaler Client IP magic number */
	struct list by_fe;         /* next binding for the same frontend, or NULL */
	char *arg;                 /* argument passed to "bind" for better error reporting */
	char *file;                /* file where the section appears */
	int line;                  /* line where the section appears */
	char *guid_prefix;         /* prefix for listeners GUID */
	size_t guid_idx;           /* next index for listeners GUID generation */
	char *rhttp_srvname;       /* name of server when using "rhttp@" address */
	int rhttp_nbconn;          /* count of connections to initiate in parallel */
	__decl_thread(HA_RWLOCK_T sni_lock); /* lock the SNI trees during add/del operations */
	struct thread_set thread_set; /* entire set of the allowed threads (0=no restriction) */
	struct rx_settings settings; /* all the settings needed for the listening socket */
};

/* Fields of a listener allocated per thread */
struct li_per_thread {
	struct {
		struct mt_list list;  /* list element in the QUIC accept queue */
		struct mt_list conns; /* list of QUIC connections from this listener ready to be accepted */
	} quic_accept;

	struct listener *li; /* back reference on the listener */
};


/* The listener will be directly referenced by the fdtab[] which holds its
 * socket. The listener provides the protocol-specific accept() function to
 * the fdtab.
 */
struct listener {
	enum obj_type obj_type;         /* object type = OBJ_TYPE_LISTENER */
	enum li_state state;            /* state: NEW, INIT, ASSIGNED, LISTEN, READY, FULL */
	uint16_t flags;                 /* listener flags: LI_F_* */
	int luid;			/* listener universally unique ID, used for SNMP */
	int nbconn;			/* current number of connections on this listener */
	unsigned long thr_idx;          /* thread indexes for queue distribution (see listener_accept()) */
	__decl_thread(HA_RWLOCK_T lock);

	struct fe_counters *counters;	/* statistics counters */
	struct mt_list wait_queue;	/* link element to make the listener wait for something (LI_LIMITED)  */
	char *name;			/* listener's name */

	unsigned int thr_conn[MAX_THREADS_PER_GROUP]; /* number of connections per thread for the group */

	struct list by_fe;              /* chaining in frontend's list of listeners */
	struct list by_bind;            /* chaining in bind_conf's list of listeners */
	struct bind_conf *bind_conf;	/* "bind" line settings, include SSL settings among other things */
	struct receiver rx;             /* network receiver parts */
	struct {
		struct eb32_node id;	/* place in the tree of used IDs */
	} conf;				/* config information */

	struct guid_node guid;		/* GUID global tree node */

	struct li_per_thread *per_thr;  /* per-thread fields (one per thread in the group) */

	EXTRA_COUNTERS(extra_counters);
};

/* listener flags (16 bits) */
#define LI_F_FINALIZED           0x0001  /* listener made it to the READY||LIMITED||FULL state at least once, may be suspended/resumed safely */
#define LI_F_SUSPENDED           0x0002  /* listener has been suspended using suspend_listener(), it is either is LI_PAUSED or LI_ASSIGNED state */
#define LI_F_UDP_GSO_NOTSUPP     0x0004  /* UDP GSO disabled after send error */

/* Descriptor for a "bind" keyword. The ->parse() function returns 0 in case of
 * success, or a combination of ERR_* flags if an error is encountered. The
 * function pointer can be NULL if not implemented. The function also has an
 * access to the current "bind" config line. The ->skip value tells the parser
 * how many words have to be skipped after the keyword.
 */
struct bind_kw {
	const char *kw;
	int (*parse)(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err);
	int skip; /* nb of args to skip */
	int rhttp_ok; /* non-zero if kw is support for reverse HTTP bind */
};

/* same as bind_kw but for crtlist keywords */
struct ssl_crtlist_kw {
	const char *kw;
	int (*parse)(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err);
	int skip; /* nb of args to skip */
};

/*
 * A keyword list. It is a NULL-terminated array of keywords. It embeds a
 * struct list in order to be linked to other lists, allowing it to easily
 * be declared where it is needed, and linked without duplicating data nor
 * allocating memory. It is also possible to indicate a scope for the keywords.
 */
struct bind_kw_list {
	const char *scope;
	struct list list;
	struct bind_kw kw[VAR_ARRAY];
};

/* The per-thread accept queue ring, must be a power of two minus 1 */
#define ACCEPT_QUEUE_SIZE ((1<<10) - 1)

/* head and tail are both 16 bits so that idx can be accessed atomically */
struct accept_queue_ring {
	uint32_t idx;             /* (head << 16) | tail */
	struct tasklet *tasklet;  /* tasklet of the thread owning this ring */
	struct connection *entry[ACCEPT_QUEUE_SIZE] __attribute((aligned(64)));
};


#endif /* _HAPROXY_LISTENER_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
