/*
 * include/haproxy/stick_table-t.h
 * Macros, variables and structures for stick tables management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2010 Willy Tarreau <w@1wt.eu>
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

#ifndef _HAPROXY_STICK_TABLE_T_H
#define _HAPROXY_STICK_TABLE_T_H

#include <sys/socket.h>
#include <netinet/in.h>

#include <import/eb32tree.h>
#include <import/ebmbtree.h>
#include <import/ebpttree.h>

#include <haproxy/api-t.h>
#include <haproxy/freq_ctr-t.h>
#include <haproxy/thread-t.h>


/* The types of extra data we can store in a stick table */
enum {
	STKTABLE_DT_SERVER_ID,    /* the server ID to use with this stream if > 0 */
	STKTABLE_DT_GPT0,         /* General Purpose Flag 0. */
	STKTABLE_DT_GPC0,         /* General Purpose Counter 0 (unsigned 32-bit integer) */
	STKTABLE_DT_GPC0_RATE,    /* General Purpose Counter 0's event rate */
	STKTABLE_DT_CONN_CNT,     /* cumulated number of connections */
	STKTABLE_DT_CONN_RATE,    /* incoming connection rate */
	STKTABLE_DT_CONN_CUR,     /* concurrent number of connections */
	STKTABLE_DT_SESS_CNT,     /* cumulated number of sessions (accepted connections) */
	STKTABLE_DT_SESS_RATE,    /* accepted sessions rate */
	STKTABLE_DT_HTTP_REQ_CNT, /* cumulated number of incoming HTTP requests */
	STKTABLE_DT_HTTP_REQ_RATE,/* incoming HTTP request rate */
	STKTABLE_DT_HTTP_ERR_CNT, /* cumulated number of HTTP requests errors (4xx) */
	STKTABLE_DT_HTTP_ERR_RATE,/* HTTP request error rate */
	STKTABLE_DT_BYTES_IN_CNT, /* cumulated bytes count from client to servers */
	STKTABLE_DT_BYTES_IN_RATE,/* bytes rate from client to servers */
	STKTABLE_DT_BYTES_OUT_CNT,/* cumulated bytes count from servers to client */
	STKTABLE_DT_BYTES_OUT_RATE,/* bytes rate from servers to client */
	STKTABLE_DT_GPC1,         /* General Purpose Counter 1 (unsigned 32-bit integer) */
	STKTABLE_DT_GPC1_RATE,    /* General Purpose Counter 1's event rate */
	STKTABLE_DT_SERVER_KEY,   /* The server key */
	STKTABLE_STATIC_DATA_TYPES,/* number of types above */
	/* up to STKTABLE_EXTRA_DATA_TYPES types may be registered here, always
	 * followed by the number of data types, must always be last.
	 */
	STKTABLE_DATA_TYPES = STKTABLE_STATIC_DATA_TYPES + STKTABLE_EXTRA_DATA_TYPES
};

/* The equivalent standard types of the stored data */
enum {
	STD_T_SINT = 0,           /* data is of type signed int */
	STD_T_UINT,               /* data is of type unsigned int */
	STD_T_ULL,                /* data is of type unsigned long long */
	STD_T_FRQP,               /* data is of type freq_ctr_period */
	STD_T_DICT,               /* data is of type key of dictionary entry */
};

/* The types of optional arguments to stored data */
enum {
	ARG_T_NONE = 0,           /* data type takes no argument (default) */
	ARG_T_INT,                /* signed integer */
	ARG_T_DELAY,              /* a delay which supports time units */
};

/* They types of keys that servers can be identified by */
enum {
	STKTABLE_SRV_NAME = 0,
	STKTABLE_SRV_ADDR,
};

/* stick table key type flags */
#define STK_F_CUSTOM_KEYSIZE      0x00000001   /* this table's key size is configurable */

/* WARNING: if new fields are added, they must be initialized in stream_accept()
 * and freed in stream_free() !
 *
 * What's the purpose of there two macro:
 *   - STKCTR_TRACK_BACKEND indicates that a tracking pointer was set from the backend
 *    and thus that when a keep-alive request goes to another backend, the track
 *    must cease.
 *
 *   - STKCTR_TRACK_CONTENT indicates that the tracking pointer was set in a
 *    content-aware rule (tcp-request content or http-request) and that the
 *    tracking has to be performed in the stream and not in the session, and
 *    will cease for a new keep-alive request over the same connection.
 *
 * These values are mixed with the stksess pointer in stkctr->entry.
 */
#define STKCTR_TRACK_BACKEND 1
#define STKCTR_TRACK_CONTENT 2

/* stick_table extra data. This is mainly used for casting or size computation */
union stktable_data {
	/* standard types for easy casting */
	int std_t_sint;
	unsigned int std_t_uint;
	unsigned long long std_t_ull;
	struct freq_ctr_period std_t_frqp;
	struct dict_entry *std_t_dict;

	/* types of each storable data */
	int server_id;
	struct dict_entry *server_key;
	unsigned int gpt0;
	unsigned int gpc0;
	struct freq_ctr_period gpc0_rate;
	unsigned int gpc1;
	struct freq_ctr_period gpc1_rate;
	unsigned int conn_cnt;
	struct freq_ctr_period conn_rate;
	unsigned int conn_cur;
	unsigned int sess_cnt;
	struct freq_ctr_period sess_rate;
	unsigned int http_req_cnt;
	struct freq_ctr_period http_req_rate;
	unsigned int http_err_cnt;
	struct freq_ctr_period http_err_rate;
	unsigned long long bytes_in_cnt;
	struct freq_ctr_period bytes_in_rate;
	unsigned long long bytes_out_cnt;
	struct freq_ctr_period bytes_out_rate;
};

/* known data types */
struct stktable_data_type {
	const char *name; /* name of the data type */
	int std_type;     /* standard type we can use for this data, STD_T_* */
	int arg_type;     /* type of optional argument, ARG_T_* */
};

/* stick table keyword type */
struct stktable_type {
	const char *kw;           /* keyword string */
	int flags;                /* type flags */
	size_t default_size;      /* default key size */
};

/* Sticky session.
 * Any additional data related to the stuck session is installed *before*
 * stksess (with negative offsets). This allows us to run variable-sized
 * keys and variable-sized data without making use of intermediate pointers.
 */
struct stksess {
	unsigned int expire;      /* session expiration date */
	unsigned int ref_cnt;     /* reference count, can only purge when zero */
	__decl_thread(HA_RWLOCK_T lock); /* lock related to the table entry */
	struct eb32_node exp;     /* ebtree node used to hold the session in expiration tree */
	struct eb32_node upd;     /* ebtree node used to hold the update sequence tree */
	struct ebmb_node key;     /* ebtree node used to hold the session in table */
	/* WARNING! do not put anything after <keys>, it's used by the key */
};


/* stick table */
struct stktable {
	char *id;		  /* local table id name. */
	char *nid;		  /* table id name sent over the network with peers protocol. */
	struct stktable *next;    /* The stick-table may be linked when belonging to
	                           * the same configuration section.
	                           */
	struct ebpt_node name;    /* Stick-table are lookup by name here. */
	struct eb_root keys;      /* head of sticky session tree */
	struct eb_root exps;      /* head of sticky session expiration tree */
	struct eb_root updates;   /* head of sticky updates sequence tree */
	struct pool_head *pool;   /* pool used to allocate sticky sessions */
	struct task *exp_task;    /* expiration task */
	struct task *sync_task;   /* sync task */
	unsigned int update;
	unsigned int localupdate;
	unsigned int commitupdate;/* used to identify the latest local updates
				     pending for sync */
	unsigned int syncing;     /* number of sync tasks watching this table now */
	union {
		struct peers *p; /* sync peers */
		char *name;
	} peers;

	unsigned long type;       /* type of table (determines key format) */
	unsigned int server_key_type; /* What type of key is used to identify servers */
	size_t key_size;          /* size of a key, maximum size in case of string */
	unsigned int size;        /* maximum number of sticky sessions in table */
	unsigned int current;     /* number of sticky sessions currently in table */
	int nopurge;              /* if non-zero, don't purge sticky sessions when full */
	int exp_next;             /* next expiration date (ticks) */
	int expire;               /* time to live for sticky sessions (milliseconds) */
	int data_size;            /* the size of the data that is prepended *before* stksess */
	int data_ofs[STKTABLE_DATA_TYPES]; /* negative offsets of present data types, or 0 if absent */
	union {
		int i;
		unsigned int u;
		void *p;
	} data_arg[STKTABLE_DATA_TYPES]; /* optional argument of each data type */
	struct proxy *proxy;      /* The proxy this stick-table is attached to, if any.*/
	struct proxy *proxies_list; /* The list of proxies which reference this stick-table. */
	struct {
		const char *file;     /* The file where the stick-table is declared. */
		int line;             /* The line in this <file> the stick-table is declared. */
	} conf;
	__decl_thread(HA_SPINLOCK_T lock); /* spin lock related to the table */
};

extern struct stktable_data_type stktable_data_types[STKTABLE_DATA_TYPES];

/* stick table key */
struct stktable_key {
	void *key;                      /* pointer on key buffer */
	size_t key_len;                 /* data len to read in buff in case of null terminated string */
};

/* stick counter. The <entry> member is a composite address (caddr) made of a
 * pointer to an stksess struct, and two flags among STKCTR_TRACK_* above.
 */
struct stkctr {
	unsigned long   entry;          /* entry containing counters currently being tracked by this stream  */
	struct stktable *table;         /* table the counters above belong to (undefined if counters are null) */
};

/* parameters to configure tracked counters */
struct track_ctr_prm {
	struct sample_expr *expr;		/* expression used as the key */
	union {
		struct stktable *t;		/* a pointer to the table */
		char *n;			/* or its name during parsing. */
	} table;
};

#endif /* _HAPROXY_STICK_TABLE_T_H */
