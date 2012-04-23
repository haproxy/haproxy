/*
 * include/types/pattern.h
 * Macros, variables and structures for patterns management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _TYPES_PATTERN_H
#define _TYPES_PATTERN_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <types/arg.h>
#include <types/buffers.h>

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

/* pattern fetch direction */
#define PATTERN_FETCH_REQ	1
#define PATTERN_FETCH_RTR	2


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

/* pattern conversion */
struct pattern_conv {
	const char *kw;                           /* configuration keyword  */
	int (*process)(const struct arg *arg_p,
		       struct sample *smp);       /* process function */
	unsigned int arg_mask;                    /* arguments (ARG*()) */
	int (*val_args)(struct arg *arg_p,
			char **err_msg);          /* argument validation function */
	unsigned int in_type;                     /* input needed pattern type */
	unsigned int out_type;                    /* output pattern type */
};

/* pattern conversion expression */
struct pattern_conv_expr {
	struct list list;                         /* member of a pattern expression */
	struct pattern_conv *conv;                /* pattern conversion */
	struct arg *arg_p;                        /* pointer on args */
};

/* pattern fetch */
struct pattern_fetch {
	const char *kw;                           /* configuration keyword */
	int (*process)(struct proxy *px,
	               struct session *l4,
	               void *l7,
	               int dir, const struct arg *arg_p,
	               struct sample *smp);       /* fetch processing function */
	unsigned int arg_mask;                    /* arguments (ARG*()) */
	int (*val_args)(struct arg *arg_p,
			char **err_msg);          /* argument validation function */
	unsigned long out_type;                   /* output pattern type */
	int dir;                                  /* usable directions */
};

/* pattern expression */
struct pattern_expr {
	struct list list;                         /* member of list of pattern, currently not used */
	struct pattern_fetch *fetch;              /* pattern fetch */
	struct arg *arg_p;                        /* pointer on args */
	struct list conv_exprs;                   /* list of conversion expression to apply */
};

/* pattern fetch keywords list */
struct pattern_fetch_kw_list {
	struct list list;                         /* head of pattern fetch keyword list */
	struct pattern_fetch kw[VAR_ARRAY];       /* array of pattern fetches */
};

/* pattern conversion keywords list */
struct pattern_conv_kw_list {
	struct list list;                         /* head of pattern conversion keyword list */
	struct pattern_conv kw[VAR_ARRAY];        /* array of pattern ions */
};

#endif /* _TYPES_PATTERN_H */
