/*
 * include/types/sample.h
 * Macros, variables and structures for sample management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2012-2013 Willy Tarreau <w@1wt.eu>
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

#ifndef _TYPES_SAMPLE_H
#define _TYPES_SAMPLE_H

#include <sys/socket.h>
#include <netinet/in.h>

#include <common/chunk.h>
#include <common/mini-clist.h>
#include <types/arg.h>
#include <types/proto_http.h>

/* input and output sample types */
enum {
	SMP_T_BOOL = 0,  /* boolean */
	SMP_T_UINT,      /* unsigned 32bits integer type */
	SMP_T_SINT,      /* signed 32bits integer type */
	SMP_T_ADDR,      /* ipv4 or ipv6, only used for input type compatibility */
	SMP_T_IPV4,      /* ipv4 type */
	SMP_T_IPV6,      /* ipv6 type */
	SMP_T_STR,       /* char string type */
	SMP_T_BIN,       /* buffer type */
	SMP_T_METH,      /* contain method */
	SMP_TYPES        /* number of types, must always be last */
};

/* Sample sources are used to establish a relation between fetch keywords and
 * the location where they're about to be used. They're reserved for internal
 * use and are not meant to be known outside the sample management code.
 */
enum {
	SMP_SRC_INTRN,  /* internal context-less information */
	SMP_SRC_LISTN,  /* listener which accepted the connection */
	SMP_SRC_FTEND,  /* frontend which accepted the connection */
	SMP_SRC_L4CLI,  /* L4 information about the client */
	SMP_SRC_L5CLI,  /* fetch uses client information from embryonic session */
	SMP_SRC_TRACK,  /* fetch involves track counters */
	SMP_SRC_L6REQ,  /* fetch uses raw information from the request buffer */
	SMP_SRC_HRQHV,  /* fetch uses volatile information about HTTP request headers (eg: value) */
	SMP_SRC_HRQHP,  /* fetch uses persistent information about HTTP request headers (eg: meth) */
	SMP_SRC_HRQBO,  /* fetch uses information about HTTP request body */
	SMP_SRC_BKEND,  /* fetch uses information about the backend */
	SMP_SRC_SERVR,  /* fetch uses information about the selected server */
	SMP_SRC_L4SRV,  /* fetch uses information about the server L4 connection */
	SMP_SRC_L5SRV,  /* fetch uses information about the server L5 connection */
	SMP_SRC_L6RES,  /* fetch uses raw information from the response buffer */
	SMP_SRC_HRSHV,  /* fetch uses volatile information about HTTP response headers (eg: value) */
	SMP_SRC_HRSHP,  /* fetch uses persistent information about HTTP response headers (eg: status) */
	SMP_SRC_HRSBO,  /* fetch uses information about HTTP response body */
	SMP_SRC_RQFIN,  /* final information about request buffer (eg: tot bytes) */
	SMP_SRC_RSFIN,  /* final information about response buffer (eg: tot bytes) */
	SMP_SRC_TXFIN,  /* final information about the transaction (eg: #comp rate) */
	SMP_SRC_SSFIN,  /* final information about the session (eg: #requests, final flags) */
	SMP_SRC_ENTRIES /* nothing after this */
};

/* Sample checkpoints are a list of places where samples may be used. This is
 * an internal enum used only to build SMP_VAL_*.
 */
enum {
	SMP_CKP_FE_CON_ACC,  /* FE connection accept rules ("tcp request connection") */
	SMP_CKP_FE_SES_ACC,  /* FE session accept rules (to come soon) */
	SMP_CKP_FE_REQ_CNT,  /* FE request content rules ("tcp request content") */
	SMP_CKP_FE_HRQ_HDR,  /* FE HTTP request headers (rules, headers, monitor, stats, redirect) */
	SMP_CKP_FE_HRQ_BDY,  /* FE HTTP request body */
	SMP_CKP_FE_SET_BCK,  /* FE backend switching rules ("use_backend") */
	SMP_CKP_BE_REQ_CNT,  /* BE request content rules ("tcp request content") */
	SMP_CKP_BE_HRQ_HDR,  /* BE HTTP request headers (rules, headers, monitor, stats, redirect) */
	SMP_CKP_BE_HRQ_BDY,  /* BE HTTP request body */
	SMP_CKP_BE_SET_SRV,  /* BE server switching rules ("use_server", "balance", "force-persist", "stick", ...) */
	SMP_CKP_BE_SRV_CON,  /* BE server connect (eg: "source") */
	SMP_CKP_BE_RES_CNT,  /* BE response content rules ("tcp response content") */
	SMP_CKP_BE_HRS_HDR,  /* BE HTTP response headers (rules, headers) */
	SMP_CKP_BE_HRS_BDY,  /* BE HTTP response body (stick-store rules are there) */
	SMP_CKP_BE_STO_RUL,  /* BE stick-store rules */
	SMP_CKP_FE_RES_CNT,  /* FE response content rules ("tcp response content") */
	SMP_CKP_FE_HRS_HDR,  /* FE HTTP response headers (rules, headers) */
	SMP_CKP_FE_HRS_BDY,  /* FE HTTP response body */
	SMP_CKP_FE_LOG_END,  /* FE log at the end of the txn/session */
	SMP_CKP_ENTRIES /* nothing after this */
};

/* SMP_USE_* are flags used to declare fetch keywords. Fetch methods are
 * associated with bitfields composed of these values, generally only one, to
 * indicate where the contents may be sampled. Some fetches are ambiguous as
 * they apply to either the request or the response depending on the context,
 * so they will have 2 of these bits (eg: hdr(), payload(), ...). These are
 * stored in smp->use.
 */
enum {
	SMP_USE_INTRN = 1 << SMP_SRC_INTRN,  /* internal context-less information */
	SMP_USE_LISTN = 1 << SMP_SRC_LISTN,  /* listener which accepted the connection */
	SMP_USE_FTEND = 1 << SMP_SRC_FTEND,  /* frontend which accepted the connection */
	SMP_USE_L4CLI = 1 << SMP_SRC_L4CLI,  /* L4 information about the client */
	SMP_USE_L5CLI = 1 << SMP_SRC_L5CLI,  /* fetch uses client information from embryonic session */
	SMP_USE_TRACK = 1 << SMP_SRC_TRACK,  /* fetch involves track counters */
	SMP_USE_L6REQ = 1 << SMP_SRC_L6REQ,  /* fetch uses raw information from the request buffer */
	SMP_USE_HRQHV = 1 << SMP_SRC_HRQHV,  /* fetch uses volatile information about HTTP request headers (eg: value) */
	SMP_USE_HRQHP = 1 << SMP_SRC_HRQHP,  /* fetch uses persistent information about HTTP request headers (eg: meth) */
	SMP_USE_HRQBO = 1 << SMP_SRC_HRQBO,  /* fetch uses information about HTTP request body */
	SMP_USE_BKEND = 1 << SMP_SRC_BKEND,  /* fetch uses information about the backend */
	SMP_USE_SERVR = 1 << SMP_SRC_SERVR,  /* fetch uses information about the selected server */
	SMP_USE_L4SRV = 1 << SMP_SRC_L4SRV,  /* fetch uses information about the server L4 connection */
	SMP_USE_L5SRV = 1 << SMP_SRC_L5SRV,  /* fetch uses information about the server L5 connection */
	SMP_USE_L6RES = 1 << SMP_SRC_L6RES,  /* fetch uses raw information from the response buffer */
	SMP_USE_HRSHV = 1 << SMP_SRC_HRSHV,  /* fetch uses volatile information about HTTP response headers (eg: value) */
	SMP_USE_HRSHP = 1 << SMP_SRC_HRSHP,  /* fetch uses persistent information about HTTP response headers (eg: status) */
	SMP_USE_HRSBO = 1 << SMP_SRC_HRSBO,  /* fetch uses information about HTTP response body */
	SMP_USE_RQFIN = 1 << SMP_SRC_RQFIN,  /* final information about request buffer (eg: tot bytes) */
	SMP_USE_RSFIN = 1 << SMP_SRC_RSFIN,  /* final information about response buffer (eg: tot bytes) */
	SMP_USE_TXFIN = 1 << SMP_SRC_TXFIN,  /* final information about the transaction (eg: #comp rate) */
	SMP_USE_SSFIN = 1 << SMP_SRC_SSFIN,  /* final information about the session (eg: #requests, final flags) */

	/* This composite one is useful to detect if an hdr_idx needs to be allocated */
	SMP_USE_HTTP_ANY = SMP_USE_HRQHV | SMP_USE_HRQHP | SMP_USE_HRQBO |
	                   SMP_USE_HRSHV | SMP_USE_HRSHP | SMP_USE_HRSBO,
};

/* Sample validity is computed from the fetch sources above when keywords
 * are registered. Each fetch method may be used at different locations. The
 * configuration parser will check whether the fetches are compatible with the
 * location where they're used. These are stored in smp->val.
 */
enum {
	SMP_VAL___________ = 0,        /* Just used as a visual marker */
	SMP_VAL_FE_CON_ACC = 1 << SMP_CKP_FE_CON_ACC,  /* FE connection accept rules ("tcp request connection") */
	SMP_VAL_FE_SES_ACC = 1 << SMP_CKP_FE_SES_ACC,  /* FE session accept rules (to come soon) */
	SMP_VAL_FE_REQ_CNT = 1 << SMP_CKP_FE_REQ_CNT,  /* FE request content rules ("tcp request content") */
	SMP_VAL_FE_HRQ_HDR = 1 << SMP_CKP_FE_HRQ_HDR,  /* FE HTTP request headers (rules, headers, monitor, stats, redirect) */
	SMP_VAL_FE_HRQ_BDY = 1 << SMP_CKP_FE_HRQ_BDY,  /* FE HTTP request body */
	SMP_VAL_FE_SET_BCK = 1 << SMP_CKP_FE_SET_BCK,  /* FE backend switching rules ("use_backend") */
	SMP_VAL_BE_REQ_CNT = 1 << SMP_CKP_BE_REQ_CNT,  /* BE request content rules ("tcp request content") */
	SMP_VAL_BE_HRQ_HDR = 1 << SMP_CKP_BE_HRQ_HDR,  /* BE HTTP request headers (rules, headers, monitor, stats, redirect) */
	SMP_VAL_BE_HRQ_BDY = 1 << SMP_CKP_BE_HRQ_BDY,  /* BE HTTP request body */
	SMP_VAL_BE_SET_SRV = 1 << SMP_CKP_BE_SET_SRV,  /* BE server switching rules ("use_server", "balance", "force-persist", "stick", ...) */
	SMP_VAL_BE_SRV_CON = 1 << SMP_CKP_BE_SRV_CON,  /* BE server connect (eg: "source") */
	SMP_VAL_BE_RES_CNT = 1 << SMP_CKP_BE_RES_CNT,  /* BE response content rules ("tcp response content") */
	SMP_VAL_BE_HRS_HDR = 1 << SMP_CKP_BE_HRS_HDR,  /* BE HTTP response headers (rules, headers) */
	SMP_VAL_BE_HRS_BDY = 1 << SMP_CKP_BE_HRS_BDY,  /* BE HTTP response body (stick-store rules are there) */
	SMP_VAL_BE_STO_RUL = 1 << SMP_CKP_BE_STO_RUL,  /* BE stick-store rules */
	SMP_VAL_FE_RES_CNT = 1 << SMP_CKP_FE_RES_CNT,  /* FE response content rules ("tcp response content") */
	SMP_VAL_FE_HRS_HDR = 1 << SMP_CKP_FE_HRS_HDR,  /* FE HTTP response headers (rules, headers) */
	SMP_VAL_FE_HRS_BDY = 1 << SMP_CKP_FE_HRS_BDY,  /* FE HTTP response body */
	SMP_VAL_FE_LOG_END = 1 << SMP_CKP_FE_LOG_END,  /* FE log at the end of the txn/session */

	/* a few combinations to decide what direction to try to fetch (useful for logs) */
	SMP_VAL_REQUEST    = SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                     SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                     SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                     SMP_VAL_BE_SET_SRV,

	SMP_VAL_RESPONSE   = SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT | SMP_VAL_BE_HRS_HDR |
	                     SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL | SMP_VAL_FE_RES_CNT |
	                     SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY | SMP_VAL_FE_LOG_END,
};

extern const unsigned int fetch_cap[SMP_SRC_ENTRIES];

/* Sample fetch options are passed to sample fetch functions to add precision
 * about what is desired :
 *   - fetch direction (req/resp)
 *   - intermediary / final fetch
 */
enum {
	SMP_OPT_DIR_REQ = 0,    /* direction = request */
	SMP_OPT_DIR_RES = 1,    /* direction = response */
	SMP_OPT_DIR     = (SMP_OPT_DIR_REQ|SMP_OPT_DIR_RES), /* mask to get direction */
	SMP_OPT_FINAL   = 2,    /* final fetch, contents won't change anymore */
	SMP_OPT_ITERATE = 4,    /* fetches may be iterated if supported (for ACLs) */
};

/* Flags used to describe fetched samples. MAY_CHANGE indicates that the result
 * of the fetch might still evolve, for instance because of more data expected,
 * even if the fetch has failed. VOL_* indicates how long a result may be cached.
 */
enum {
	SMP_F_NOT_LAST   = 1 << 0, /* other occurrences might exist for this sample */
	SMP_F_MAY_CHANGE = 1 << 1, /* sample is unstable and might change (eg: request length) */
	SMP_F_VOL_TEST   = 1 << 2, /* result must not survive longer than the test (eg: time) */
	SMP_F_VOL_1ST    = 1 << 3, /* result sensitive to changes in first line (eg: URI) */
	SMP_F_VOL_HDR    = 1 << 4, /* result sensitive to changes in headers */
	SMP_F_VOL_TXN    = 1 << 5, /* result sensitive to new transaction (eg: HTTP version) */
	SMP_F_VOL_SESS   = 1 << 6, /* result sensitive to new session (eg: src IP) */
	SMP_F_VOLATILE   = (1<<2)|(1<<3)|(1<<4)|(1<<5)|(1<<6), /* any volatility condition */
	SMP_F_CONST      = 1 << 7, /* This sample use constant memory. May diplicate it before changes */
};

/* needed below */
struct session;

/* a sample context might be used by any sample fetch function in order to
 * store information needed across multiple calls (eg: restart point for a
 * next occurrence). By definition it may store up to 8 pointers, or any
 * scalar (double, int, long long).
 */
union smp_ctx {
	void *p;        /* any pointer */
	int i;          /* any integer */
	long long ll;   /* any long long or smaller */
	double d;       /* any float or double */
	void *a[8];     /* any array of up to 8 pointers */
};

struct meth {
	enum http_meth_t meth;
	struct chunk str;
};

/* a sample is a typed data extracted from a stream. It has a type, contents,
 * validity constraints, a context for use in iterative calls.
 */
struct sample {
	unsigned int flags;       /* SMP_F_* */
	int type;                 /* SMP_T_* */
	union {
		unsigned int    uint;  /* used for unsigned 32bits integers and booleans */
		int             sint;  /* used for signed 32bits integers */
		struct in_addr  ipv4;  /* used for ipv4 addresses */
		struct in6_addr ipv6;  /* used for ipv6 addresses */
		struct chunk    str;   /* used for char strings or buffers */
		struct meth     meth;  /* used for http method */
	} data;                        /* sample data */
	union smp_ctx ctx;
};

/* Used to store sample constant */
struct sample_storage {
	int type;                 /* SMP_T_* */
	union {
		unsigned int    uint;  /* used for unsigned 32bits integers and booleans */
		int             sint;  /* used for signed 32bits integers */
		struct in_addr  ipv4;  /* used for ipv4 addresses */
		struct in6_addr ipv6;  /* used for ipv6 addresses */
		struct chunk    str;   /* used for char strings or buffers */
		struct meth     meth;  /* used for http method */
	} data;                        /* sample data */
};

/* Descriptor for a sample conversion */
struct sample_conv {
	const char *kw;                           /* configuration keyword  */
	int (*process)(const struct arg *arg_p,
		       struct sample *smp);       /* process function */
	unsigned int arg_mask;                    /* arguments (ARG*()) */
	int (*val_args)(struct arg *arg_p,
	                struct sample_conv *smp_conv,
	                const char *file, int line,
			char **err_msg);          /* argument validation function */
	unsigned int in_type;                     /* expected input sample type */
	unsigned int out_type;                    /* output sample type */
	unsigned int private;                     /* private values. only used by maps */
};

/* sample conversion expression */
struct sample_conv_expr {
	struct list list;                         /* member of a sample_expr */
	struct sample_conv *conv;                 /* sample conversion used */
	struct arg *arg_p;                        /* optional arguments */
};

/* Descriptor for a sample fetch method */
struct sample_fetch {
	const char *kw;                           /* configuration keyword */
	int (*process)(struct proxy *px,
	               struct session *l4,
	               void *l7,
		       unsigned int opt,          /* fetch options (SMP_OPT_*) */
		       const struct arg *arg_p,
	               struct sample *smp,
	               const char *kw);           /* fetch processing function */
	unsigned int arg_mask;                    /* arguments (ARG*()) */
	int (*val_args)(struct arg *arg_p,
			char **err_msg);          /* argument validation function */
	unsigned long out_type;                   /* output sample type */
	unsigned int use;                         /* fetch source (SMP_USE_*) */
	unsigned int val;                         /* fetch validity (SMP_VAL_*) */
};

/* sample expression */
struct sample_expr {
	struct list list;                         /* member of list of sample, currently not used */
	struct sample_fetch *fetch;               /* sample fetch method */
	struct arg *arg_p;                        /* optional pointer to arguments to fetch function */
	struct list conv_exprs;                   /* list of conversion expression to apply */
};

/* sample fetch keywords list */
struct sample_fetch_kw_list {
	struct list list;                         /* head of sample fetch keyword list */
	struct sample_fetch kw[VAR_ARRAY];        /* array of sample fetch descriptors */
};

/* sample conversion keywords list */
struct sample_conv_kw_list {
	struct list list;                         /* head of sample conversion keyword list */
	struct sample_conv kw[VAR_ARRAY];         /* array of sample conversion descriptors */
};

typedef int (*sample_cast_fct)(struct sample *smp);
extern sample_cast_fct sample_casts[SMP_TYPES][SMP_TYPES];

#endif /* _TYPES_SAMPLE_H */
