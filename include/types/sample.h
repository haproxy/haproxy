/*
 * include/types/sample.h
 * Macros, variables and structures for sample management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2012 Willy Tarreau <w@1wt.eu>
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
#include <types/arg.h>

/* input and output sample types */
enum {
	SMP_T_BOOL = 0,  /* boolean */
	SMP_T_UINT,      /* unsigned 32bits integer type */
	SMP_T_SINT,      /* signed 32bits integer type */
	SMP_T_IPV4,      /* ipv4 type */
	SMP_T_IPV6,      /* ipv6 type */
	SMP_T_STR,       /* char string type */
	SMP_T_BIN,       /* buffer type */
	SMP_T_CSTR,      /* constant char string type, data need dup before conversion */
	SMP_T_CBIN,      /* constant buffer type, data need dup before conversion */
	SMP_TYPES        /* number of types, must always be last */
};

/* Sample fetch capabilities are used to declare keywords. Right now only
 * the supportd fetch directions are specified.
 */
enum {
	SMP_CAP_REQ = 1 << 0, /* fetch supported on request */
	SMP_CAP_RES = 1 << 1, /* fetch supported on response */
};

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
	} data;                        /* sample data */
	union smp_ctx ctx;
};

/* Descriptor for a sample conversion */
struct sample_conv {
	const char *kw;                           /* configuration keyword  */
	int (*process)(const struct arg *arg_p,
		       struct sample *smp);       /* process function */
	unsigned int arg_mask;                    /* arguments (ARG*()) */
	int (*val_args)(struct arg *arg_p,
			char **err_msg);          /* argument validation function */
	unsigned int in_type;                     /* expected input sample type */
	unsigned int out_type;                    /* output sample type */
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
	               struct sample *smp);       /* fetch processing function */
	unsigned int arg_mask;                    /* arguments (ARG*()) */
	int (*val_args)(struct arg *arg_p,
			char **err_msg);          /* argument validation function */
	unsigned long out_type;                   /* output sample type */
	unsigned int cap;                         /* fetch capabilities (SMP_CAP_*) */
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

#endif /* _TYPES_SAMPLE_H */
