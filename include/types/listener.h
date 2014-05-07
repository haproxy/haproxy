/*
 * include/types/listener.h
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

#ifndef _TYPES_LISTENER_H
#define _TYPES_LISTENER_H

#include <sys/types.h>
#include <sys/socket.h>

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#endif

#include <common/config.h>
#include <common/mini-clist.h>
#include <types/obj_type.h>
#include <eb32tree.h>

/* Some pointer types reference below */
struct task;
struct protocol;
struct xprt_ops;
struct proxy;
struct licounters;

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
#define LI_O_NONE	0x0000
#define LI_O_NOLINGER	0x0001	/* disable linger on this socket */
#define LI_O_FOREIGN	0x0002	/* permit listening on foreing addresses */
#define LI_O_NOQUICKACK	0x0004	/* disable quick ack of immediate data (linux) */
#define LI_O_DEF_ACCEPT	0x0008	/* wait up to 1 second for data before accepting */
#define LI_O_TCP_RULES  0x0010  /* run TCP rules checks on the incoming connection */
#define LI_O_CHK_MONNET 0x0020  /* check the source against a monitor-net rule */
#define LI_O_ACC_PROXY  0x0040  /* find the proxied address in the first request line */
#define LI_O_UNLIMITED  0x0080  /* listener not subject to global limits (peers & stats socket) */
#define LI_O_TCP_FO     0x0100  /* enable TCP Fast Open (linux >= 3.7) */
#define LI_O_V6ONLY     0x0200  /* bind to IPv6 only on Linux >= 2.4.21 */
#define LI_O_V4V6       0x0400  /* bind to IPv4/IPv6 on Linux >= 2.4.21 */

/* Note: if a listener uses LI_O_UNLIMITED, it is highly recommended that it adds its own
 * maxconn setting to the global.maxsock value so that its resources are reserved.
 */

#ifdef USE_OPENSSL
/* bind_conf ssl options */
#define BC_SSL_O_NONE           0x0000
#define BC_SSL_O_NO_SSLV3       0x0001	/* disable SSLv3 */
#define BC_SSL_O_NO_TLSV10      0x0002	/* disable TLSv10 */
#define BC_SSL_O_NO_TLSV11      0x0004	/* disable TLSv11 */
#define BC_SSL_O_NO_TLSV12      0x0008	/* disable TLSv12 */
/* 0x000F reserved for 'no' protocol version options */
#define BC_SSL_O_USE_SSLV3      0x0010	/* force SSLv3 */
#define BC_SSL_O_USE_TLSV10     0x0020	/* force TLSv10 */
#define BC_SSL_O_USE_TLSV11     0x0040	/* force TLSv11 */
#define BC_SSL_O_USE_TLSV12     0x0080	/* force TLSv12 */
/* 0x00F0 reserved for 'force' protocol version options */
#define BC_SSL_O_NO_TLS_TICKETS 0x0100	/* disable session resumption tickets */
#endif

/* "bind" line settings */
struct bind_conf {
#ifdef USE_OPENSSL
	char *ca_file;             /* CAfile to use on verify */
	unsigned long long ca_ignerr;  /* ignored verify errors in handshake if depth > 0 */
	unsigned long long crt_ignerr; /* ignored verify errors in handshake if depth == 0 */
	char *ciphers;             /* cipher suite to use if non-null */
	char *crl_file;            /* CRLfile to use on verify */
	char *ecdhe;               /* named curve to use for ECDHE */
	int ssl_options;           /* ssl options */
	int verify;                /* verify method (set of SSL_VERIFY_* flags) */
	SSL_CTX *default_ctx;      /* SSL context of first/default certificate */
	char *npn_str;             /* NPN protocol string */
	int npn_len;               /* NPN protocol string length */
	char *alpn_str;            /* ALPN protocol string */
	int alpn_len;              /* ALPN protocol string length */
	int strict_sni;            /* refuse negotiation if sni doesn't match a certificate */
	struct eb_root sni_ctx;    /* sni_ctx tree of all known certs full-names sorted by name */
	struct eb_root sni_w_ctx;  /* sni_ctx tree of all known certs wildcards sorted by name */
#endif
	int is_ssl;                /* SSL is required for these listeners */
	unsigned long bind_proc;   /* bitmask of processes allowed to use these listeners */
	struct {                   /* UNIX socket permissions */
		uid_t uid;         /* -1 to leave unchanged */
		gid_t gid;         /* -1 to leave unchanged */
		mode_t mode;       /* 0 to leave unchanged */
	} ux;
	int level;                 /* stats access level (ACCESS_LVL_*) */
	struct list by_fe;         /* next binding for the same frontend, or NULL */
	struct list listeners;     /* list of listeners using this bind config */
	char *arg;                 /* argument passed to "bind" for better error reporting */
	char *file;                /* file where the section appears */
	int line;                  /* line where the section appears */
};

/* The listener will be directly referenced by the fdtab[] which holds its
 * socket. The listener provides the protocol-specific accept() function to
 * the fdtab.
 */
struct listener {
	enum obj_type obj_type;         /* object type = OBJ_TYPE_LISTENER */
	enum li_state state;            /* state: NEW, INIT, ASSIGNED, LISTEN, READY, FULL */
	short int nice;                 /* nice value to assign to the instanciated tasks */
	int fd;				/* the listen socket */
	char *name;			/* listener's name */
	int luid;			/* listener universally unique ID, used for SNMP */
	int options;			/* socket options : LI_O_* */
	struct licounters *counters;	/* statistics counters */
	struct protocol *proto;		/* protocol this listener belongs to */
	struct xprt_ops *xprt;          /* transport-layer operations for this socket */
	int nbconn;			/* current number of connections on this listener */
	int maxconn;			/* maximum connections allowed on this listener */
	unsigned int backlog;		/* if set, listen backlog */
	unsigned int maxaccept;         /* if set, max number of connections accepted at once */
	struct list proto_list;         /* list in the protocol header */
	int (*accept)(struct listener *l, int fd, struct sockaddr_storage *addr); /* upper layer's accept() */
	struct task * (*handler)(struct task *t); /* protocol handler. It is a task */
	int  *timeout;                  /* pointer to client-side timeout */
	struct proxy *frontend;		/* the frontend this listener belongs to, or NULL */
	struct list wait_queue;		/* link element to make the listener wait for something (LI_LIMITED)  */
	unsigned int analysers;		/* bitmap of required protocol analysers */
	int maxseg;			/* for TCP, advertised MSS */
	char *interface;		/* interface name or NULL */

	struct list by_fe;              /* chaining in frontend's list of listeners */
	struct list by_bind;            /* chaining in bind_conf's list of listeners */
	struct bind_conf *bind_conf;	/* "bind" line settings, include SSL settings among other things */

	/* warning: this struct is huge, keep it at the bottom */
	struct sockaddr_storage addr;	/* the address we listen to */
	struct {
		struct eb32_node id;	/* place in the tree of used IDs */
	} conf;				/* config information */
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


#endif /* _TYPES_LISTENER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
