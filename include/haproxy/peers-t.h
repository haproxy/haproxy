/*
 * include/haproxy/peers-t.h
 * This file defines everything related to peers.
 *
 * Copyright 2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _HAPROXY_PEERS_T_H
#define _HAPROXY_PEERS_T_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <import/ebtree-t.h>

#include <haproxy/api-t.h>
#include <haproxy/dict-t.h>
#include <haproxy/stick_table-t.h>
#include <haproxy/thread-t.h>

/* peer state with respects of its applet, as seen from outside */
enum peer_app_state {
	PEER_APP_ST_STOPPED = 0, /* The peer has no applet */
	PEER_APP_ST_STARTING,    /* The peer has an applet with a validated connection but sync task must ack it first */
	PEER_APP_ST_RUNNING,     /* The starting state was processed by the sync task and the peer can process messages */
	PEER_APP_ST_STOPPING,    /* The peer applet was released but the sync task must ack it before switching the peer in STOPPED state */
};

/* peer learn state */
enum peer_learn_state {
	PEER_LR_ST_NOTASSIGNED = 0,/* The peer is not assigned for a leason */
	PEER_LR_ST_ASSIGNED,       /* The peer is assigned for a leason  */
	PEER_LR_ST_PROCESSING,     /* The peer has started the leason and it is not finished */
	PEER_LR_ST_FINISHED,       /* The peer has finished the leason, this state must be ack by the sync task */
};

/******************************/
/* peers section resync flags */
/******************************/
#define PEERS_F_RESYNC_LOCAL_FINISHED     0x00000001 /* Learn from local peer finished or no more needed */
#define PEERS_F_RESYNC_REMOTE_FINISHED    0x00000002 /* Learn from remote peer finished or no more needed */
#define PEERS_F_RESYNC_ASSIGN             0x00000004 /* A peer was assigned to learn our lesson */
/* unused 0x00000008..0x00080000 */
#define PEERS_F_DBG_RESYNC_LOCALTIMEOUT   0x00100000 /* Timeout waiting for a full resync from a local node was experienced at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_REMOTETIMEOUT  0x00200000 /* Timeout waiting for a full resync from a remote node was experienced at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_LOCALABORT     0x00400000 /* Session aborted learning from a local node was experienced at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_REMOTEABORT    0x00800000 /* Session aborted learning from a remote node was experienced at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_LOCALFINISHED  0x01000000 /* A fully up to date local node teach us at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_REMOTEFINISHED 0x02000000 /* A fully up to remote node teach us at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_LOCALPARTIAL   0x04000000 /* A partially up to date local node teach us at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_REMOTEPARTIAL  0x08000000 /* A partially up to date remote node teach us at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_LOCALASSIGN    0x10000000 /* A local node was assigned for a full resync at lest once (for debugging purpose) */
#define PEERS_F_DBG_RESYNC_REMOTEASSIGN   0x20000000 /* A remote node was assigned for a full resync at lest once (for debugging purpose) */

#define PEERS_RESYNC_FROMLOCAL      0x00000000                     /* No resync finished, must be performed from local first */
#define PEERS_RESYNC_FROMREMOTE     PEERS_F_RESYNC_LOCAL_FINISHED  /* Resync from local peer finished, must be performed from remote peer now */
#define PEERS_RESYNC_STATEMASK      (PEERS_F_RESYNC_LOCAL_FINISHED|PEERS_F_RESYNC_REMOTE_FINISHED)
#define PEERS_RESYNC_FINISHED       (PEERS_F_RESYNC_LOCAL_FINISHED|PEERS_F_RESYNC_REMOTE_FINISHED)

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *peers_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(PEERS_F_RESYNC_LOCAL_FINISHED, _(PEERS_F_RESYNC_REMOTE_FINISHED, _(PEERS_F_RESYNC_ASSIGN,
        _(PEERS_F_DBG_RESYNC_LOCALTIMEOUT, _(PEERS_F_DBG_RESYNC_REMOTETIMEOUT,
        _(PEERS_F_DBG_RESYNC_LOCALABORT, _(PEERS_F_DBG_RESYNC_REMOTEABORT,
	_(PEERS_F_DBG_RESYNC_LOCALFINISHED, _(PEERS_F_DBG_RESYNC_REMOTEFINISHED,
	_(PEERS_F_DBG_RESYNC_LOCALPARTIAL, _(PEERS_F_DBG_RESYNC_REMOTEPARTIAL,
	_(PEERS_F_DBG_RESYNC_LOCALASSIGN, _(PEERS_F_DBG_RESYNC_REMOTEABORT)))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/******************************/
/* Peer flags                 */
/******************************/
#define PEER_F_TEACH_PROCESS        0x00000001 /* Teach a lesson to current peer */
#define PEER_F_TEACH_FINISHED       0x00000002 /* Teach conclude, (wait for confirm) */
#define PEER_F_LOCAL_TEACH_COMPLETE 0x00000004 /* The old local peer taught all that it known to new one */
#define PEER_F_LEARN_NOTUP2DATE     0x00000008 /* Learn from peer finished but peer is not up to date */
#define PEER_F_WAIT_SYNCTASK_ACK    0x00000010 /* Stop all processing waiting for the sync task acknowledgement when the applet state changes */
#define PEER_F_ALIVE                0x00000020 /* Used to flag a peer a alive. */
#define PEER_F_HEARTBEAT            0x00000040 /* Heartbeat message to send. */
#define PEER_F_DWNGRD               0x00000080 /* When this flag is enabled, we must downgrade the supported version announced during peer sessions. */
/* unused 0x00000100..0x00080000 */
#define PEER_F_DBG_RESYNC_REQUESTED 0x00100000 /* A resnyc was explicitly requested at least once (for debugging purpose) */

#define PEER_TEACH_FLAGS            (PEER_F_TEACH_PROCESS|PEER_F_TEACH_FINISHED)

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *peer_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(PEER_F_TEACH_PROCESS, _(PEER_F_TEACH_FINISHED, _(PEER_F_LOCAL_TEACH_COMPLETE,
        _(PEER_F_LEARN_NOTUP2DATE, _(PEER_F_WAIT_SYNCTASK_ACK,
        _(PEER_F_ALIVE, _(PEER_F_HEARTBEAT, _(PEER_F_DWNGRD,
	_(PEER_F_DBG_RESYNC_REQUESTED)))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

struct shared_table {
	struct stktable *table;       /* stick table to sync */
	int local_id;
	int remote_id;
	int flags;
	uint64_t remote_data;
	unsigned int remote_data_nbelem[STKTABLE_DATA_TYPES];
	unsigned int last_acked;
	unsigned int last_pushed;
	unsigned int last_get;
	unsigned int teaching_origin;
	unsigned int update;
	struct shared_table *next;    /* next shared table in list */
};

struct peer {
	int local;                    /* proxy state */
	enum peer_app_state appstate;    /* peer app state */
	enum peer_learn_state learnstate; /* peer learn state */
	__decl_thread(HA_SPINLOCK_T lock); /* lock used to handle this peer section */
	char *id;
	struct {
		const char *file;         /* file where the section appears */
		int line;                 /* line where the section appears */
	} conf;                       /* config information */
	time_t last_change;
	unsigned int flags;           /* peer session flags */
	unsigned int statuscode;      /* current/last session status code */
	unsigned int reconnect;       /* next connect timer */
	unsigned int heartbeat;       /* next heartbeat timer */
	unsigned int confirm;         /* confirm message counter */
	unsigned int last_hdshk;      /* Date of the last handshake. */
	uint32_t rx_hbt;              /* received heartbeats counter */
	uint32_t tx_hbt;              /* transmitted heartbeats counter */
	uint32_t no_hbt;              /* no received heartbeat counter */
	uint32_t new_conn;            /* new connection after reconnection timeout expiration counter */
	uint32_t proto_err;           /* protocol errors counter */
	uint32_t coll;                /* connection collisions counter */
	struct appctx *appctx;        /* the appctx running it */
	struct shared_table *remote_table;
	struct shared_table *last_local_table; /* Last table that emit update messages during a teach process */
	struct shared_table *stop_local_table; /* last evaluated table, used as restart point for the next teach process */
	struct shared_table *tables;
	struct server *srv;
	struct dcache *dcache;        /* dictionary cache */
	struct peers *peers;          /* associated peer section */
	struct peer *next;            /* next peer in the list */
};


struct peers {
	char *id;                       /* peer section name */
	struct task *sync_task;         /* main sync task */
	struct sig_handler *sighandler; /* signal handler */
	struct peer *remote;            /* remote peers list */
	struct peer *local;             /* local peer list */
	struct proxy *peers_fe;         /* peer frontend */
	struct {
		const char *file;           /* file where the section appears */
		int line;                   /* line where the section appears */
	} conf;                         /* config information */
	time_t last_change;
	struct peers *next;             /* next peer section */
	unsigned int flags;             /* current peers section resync state */
	unsigned int resync_timeout;    /* resync timeout timer */
	int count;                      /* total of peers */
	int nb_shards;                  /* Number of peer shards */
	int disabled;                   /* peers proxy disabled if >0 */
	int applet_count[MAX_THREADS];  /* applet count per thread */
};

/* LRU cache for dictionaies */
struct dcache_tx {
	/* The last recently used key */
	unsigned int lru_key;
	/* An array of entries to store pointers to dictionary entries. */
	struct ebpt_node *entries;
	/* The previous lookup result. */
	struct ebpt_node *prev_lookup;
	/* ebtree to store the previous entries. */
	struct eb_root cached_entries;
};

struct dcache_rx {
	unsigned int id;
	struct dict_entry *de;
};

struct dcache_tx_entry {
	unsigned int id;
	struct ebpt_node entry;
};

/* stick-table data type cache */
struct dcache {
	/* Cache used upon transmission */
	struct dcache_tx *tx;
	/* Cache used upon receipt */
	struct dcache_rx *rx;
	/* Maximum number of entries in this cache */
	size_t max_entries;
};

struct peers_keyword {
	const char *kw;
	int (*parse)(
		char **args,
		struct peers *curpeer,
		const char *file,
		int line,
		char **err);
	int flags;
};

struct peers_kw_list {
	struct list list;
	struct peers_keyword kw[VAR_ARRAY];
};

#endif /* _HAPROXY_PEERS_T_H */

