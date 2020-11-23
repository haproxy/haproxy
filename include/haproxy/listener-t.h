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

#include <import/eb32tree.h>

#include <haproxy/api-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/receiver-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/thread.h>

#ifdef USE_OPENSSL
#include <haproxy/openssl-compat.h>
#endif
#include <haproxy/xprt_quic-t.h>

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

/* listener socket options */
#define LI_O_NONE               0x0000
#define LI_O_NOLINGER           0x0001  /* disable linger on this socket */
/* unused                       0x0002  */
#define LI_O_NOQUICKACK         0x0004  /* disable quick ack of immediate data (linux) */
#define LI_O_DEF_ACCEPT         0x0008  /* wait up to 1 second for data before accepting */
#define LI_O_TCP_L4_RULES       0x0010  /* run TCP L4 rules checks on the incoming connection */
#define LI_O_TCP_L5_RULES       0x0020  /* run TCP L5 rules checks on the incoming session */
/* unused                       0x0040  */
#define LI_O_ACC_PROXY          0x0080  /* find the proxied address in the first request line */
#define LI_O_UNLIMITED          0x0100  /* listener not subject to global limits (peers & stats socket) */
#define LI_O_TCP_FO             0x0200  /* enable TCP Fast Open (linux >= 3.7) */
/* unused                       0x0400  */
/* unused                       0x0800  */
#define LI_O_ACC_CIP            0x1000  /* find the proxied address in the NetScaler Client IP header */
/* unused                       0x2000  */
/* unused                       0x4000  */
#define LI_O_NOSTOP             0x8000  /* keep the listener active even after a soft stop */

/* Note: if a listener uses LI_O_UNLIMITED, it is highly recommended that it adds its own
 * maxconn setting to the global.maxsock value so that its resources are reserved.
 */

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
#ifdef OPENSSL_NPN_NEGOTIATED
	char *npn_str;             /* NPN protocol string */
	int npn_len;               /* NPN protocol string length */
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	char *alpn_str;            /* ALPN protocol string */
	int alpn_len;              /* ALPN protocol string length */
#endif
	unsigned int verify:3;     /* verify method (set of SSL_VERIFY_* flags) */
	unsigned int no_ca_names:1;/* do not send ca names to clients (ca_file related) */
	unsigned int early_data:1; /* early data allowed */
	char *ca_file;             /* CAfile to use on verify and ca-names */
	char *ca_verify_file;      /* CAverify file to use on verify only */
	char *crl_file;            /* CRLfile to use on verify */
	char *ciphers;             /* cipher suite to use if non-null */
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	char *ciphersuites;        /* TLS 1.3 cipher suite to use if non-null */
#endif
	char *curves;	           /* curves suite to use for ECDHE */
	char *ecdhe;               /* named curve to use for ECDHE */
	struct tls_version_filter ssl_methods_cfg; /* original ssl methods found in configuration */
	struct tls_version_filter ssl_methods; /* actual ssl methods used at runtime */
#endif
};

/* "bind" line settings */
struct bind_conf {
#ifdef USE_OPENSSL
	struct ssl_bind_conf ssl_conf; /* ssl conf for ctx setting */
	unsigned long long ca_ignerr;  /* ignored verify errors in handshake if depth > 0 */
	unsigned long long crt_ignerr; /* ignored verify errors in handshake if depth == 0 */
	SSL_CTX *initial_ctx;      /* SSL context for initial negotiation */
	SSL_CTX *default_ctx;      /* SSL context of first/default certificate */
	struct ssl_bind_conf *default_ssl_conf; /* custom SSL conf of default_ctx */
	int strict_sni;            /* refuse negotiation if sni doesn't match a certificate */
	int ssl_options;           /* ssl options */
	struct eb_root sni_ctx;    /* sni_ctx tree of all known certs full-names sorted by name */
	struct eb_root sni_w_ctx;  /* sni_ctx tree of all known certs wildcards sorted by name */
	struct tls_keys_ref *keys_ref; /* TLS ticket keys reference */

	char *ca_sign_file;        /* CAFile used to generate and sign server certificates */
	char *ca_sign_pass;        /* CAKey passphrase */

	struct cert_key_and_chain * ca_sign_ckch;	/* CA and possible certificate chain for ca generation */
#endif
#ifdef USE_QUIC
	struct quic_transport_params quic_params; /* QUIC transport parameters. */
#endif
	struct proxy *frontend;    /* the frontend all these listeners belong to, or NULL */
	const struct mux_proto_list *mux_proto; /* the mux to use for all incoming connections (specified by the "proto" keyword) */
	struct xprt_ops *xprt;     /* transport-layer operations for all listeners */
	int is_ssl;                /* SSL is required for these listeners */
	int generate_certs;        /* 1 if generate-certificates option is set, else 0 */
	int level;                 /* stats access level (ACCESS_LVL_*) */
	int severity_output;       /* default severity output format in cli feedback messages */
	struct list listeners;     /* list of listeners using this bind config */
	uint32_t ns_cip_magic;     /* Excepted NetScaler Client IP magic number */
	struct list by_fe;         /* next binding for the same frontend, or NULL */
	char *arg;                 /* argument passed to "bind" for better error reporting */
	char *file;                /* file where the section appears */
	int line;                  /* line where the section appears */
	__decl_thread(HA_RWLOCK_T sni_lock); /* lock the SNI trees during add/del operations */
	struct rx_settings settings; /* all the settings needed for the listening socket */
};

/* The listener will be directly referenced by the fdtab[] which holds its
 * socket. The listener provides the protocol-specific accept() function to
 * the fdtab.
 */
struct listener {
	enum obj_type obj_type;         /* object type = OBJ_TYPE_LISTENER */
	enum li_state state;            /* state: NEW, INIT, ASSIGNED, LISTEN, READY, FULL */
	short int nice;                 /* nice value to assign to the instantiated tasks */
	int luid;			/* listener universally unique ID, used for SNMP */
	int options;			/* socket options : LI_O_* */
	__decl_thread(HA_SPINLOCK_T lock);

	struct fe_counters *counters;	/* statistics counters */
	int nbconn;			/* current number of connections on this listener */
	int maxconn;			/* maximum connections allowed on this listener */
	unsigned int backlog;		/* if set, listen backlog */
	int maxaccept;         /* if set, max number of connections accepted at once (-1 when disabled) */
	int (*accept)(struct connection *conn); /* upper layer's accept() */
	enum obj_type *default_target;  /* default target to use for accepted sessions or NULL */
	/* cache line boundary */
	struct mt_list wait_queue;	/* link element to make the listener wait for something (LI_LIMITED)  */
	unsigned int thr_idx;           /* thread indexes for queue distribution : (t2<<16)+t1 */
	unsigned int analysers;		/* bitmap of required protocol analysers */
	int maxseg;			/* for TCP, advertised MSS */
	int tcp_ut;                     /* for TCP, user timeout */
	char *name;			/* listener's name */

	/* cache line boundary */
	unsigned int thr_conn[MAX_THREADS]; /* number of connections per thread */

	/* cache line boundary */

	struct list by_fe;              /* chaining in frontend's list of listeners */
	struct list by_bind;            /* chaining in bind_conf's list of listeners */
	struct bind_conf *bind_conf;	/* "bind" line settings, include SSL settings among other things */
	struct receiver rx;             /* network receiver parts */
	struct {
		struct eb32_node id;	/* place in the tree of used IDs */
	} conf;				/* config information */

	EXTRA_COUNTERS(extra_counters);
};

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
};
struct ssl_bind_kw {
	const char *kw;
	int (*parse)(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err);
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

struct accept_queue_ring {
	unsigned int head;
	unsigned int tail;
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
