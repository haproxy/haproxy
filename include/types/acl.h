/*
 * include/types/acl.h
 * This file provides structures and types for ACLs.
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

#ifndef _TYPES_ACL_H
#define _TYPES_ACL_H

#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>

#include <types/arg.h>
#include <types/auth.h>
#include <types/proxy.h>
#include <types/sample.h>
#include <types/server.h>
#include <types/session.h>

#include <ebmbtree.h>

/* Pattern matching function result.
 *
 * We're using a 3-state matching system :
 *   - PASS : at least one pattern already matches
 *   - MISS : some data is missing to decide if some rules may finally match.
 *   - FAIL : no mattern may ever match
 *
 * We assign values 0, 1 and 3 to FAIL, MISS and PASS respectively, so that we
 * can make use of standard arithmetics for the truth tables below :
 *
 *      x  | !x          x&y | F(0) | M(1) | P(3)     x|y | F(0) | M(1) | P(3)
 *   ------+-----       -----+------+------+-----    -----+------+------+-----
 *    F(0) | P(3)        F(0)| F(0) | F(0) | F(0)     F(0)| F(0) | M(1) | P(3)
 *    M(1) | M(1)        M(1)| F(0) | M(1) | M(1)     M(1)| M(1) | M(1) | P(3)
 *    P(3) | F(0)        P(3)| F(0) | M(1) | P(3)     P(3)| P(3) | P(3) | P(3)
 *
 *  neg(x) = (3 >> x)       and(x,y) = (x & y)           or(x,y) = (x | y)
 *
 */

enum {
	ACL_PAT_FAIL = 0,           /* test failed */
	ACL_PAT_MISS = 1,           /* test may pass with more info */
	ACL_PAT_PASS = 3,           /* test passed */
};

/* Condition polarity. It makes it easier for any option to choose between
 * IF/UNLESS if it can store that information within the condition itself.
 * Those should be interpreted as "IF/UNLESS result == PASS".
 */
enum {
	ACL_COND_NONE,		/* no polarity set yet */
	ACL_COND_IF,		/* positive condition (after 'if') */
	ACL_COND_UNLESS,	/* negative condition (after 'unless') */
};

/* possible flags for expressions or patterns */
enum {
	ACL_PAT_F_IGNORE_CASE = 1 << 0,       /* ignore case */
	ACL_PAT_F_FROM_FILE   = 1 << 1,       /* pattern comes from a file */
	ACL_PAT_F_TREE_OK     = 1 << 2,       /* the pattern parser is allowed to build a tree */
	ACL_PAT_F_TREE        = 1 << 3,       /* some patterns are arranged in a tree */
};

/* ACL match methods */
enum {
	ACL_MATCH_FOUND, /* just ensure that fetch found the sample */
	ACL_MATCH_BOOL,  /* match fetch's integer value as boolean */
	ACL_MATCH_INT,   /* unsigned integer (int) */
	ACL_MATCH_IP,    /* IPv4/IPv6 address (IP) */
	ACL_MATCH_BIN,   /* hex string (bin) */
	ACL_MATCH_LEN,   /* string length (str -> int) */
	ACL_MATCH_STR,   /* exact string match (str) */
	ACL_MATCH_BEG,   /* beginning of string (str) */
	ACL_MATCH_SUB,   /* substring (str) */
	ACL_MATCH_DIR,   /* directory-like sub-string (str) */
	ACL_MATCH_DOM,   /* domain-like sub-string (str) */
	ACL_MATCH_END,   /* end of string (str) */
	ACL_MATCH_REG,   /* regex (str -> reg) */
	/* keep this one last */
	ACL_MATCH_NUM
};

/* How to store a time range and the valid days in 29 bits */
struct acl_time {
	int dow:7;              /* 1 bit per day of week: 0-6 */
	int h1:5, m1:6;         /* 0..24:0..60. Use 0:0 for all day. */
	int h2:5, m2:6;         /* 0..24:0..60. Use 24:0 for all day. */
};

/* This describes one ACL pattern, which might be a single value or a tree of
 * values. All patterns for a single ACL expression are linked together. Some
 * of them might have a type (eg: IP). Right now, the types are shared with
 * the samples, though it is possible that in the future this will change to
 * accommodate for other types (eg: meth, regex). Unsigned and constant types
 * are preferred when there is a doubt.
 */
struct acl_pattern {
	struct list list;                       /* chaining */
	int type;                               /* type of the ACL pattern (SMP_T_*) */
	union {
		int i;                          /* integer value */
		struct {
			signed long long min, max;
			int min_set :1;
			int max_set :1;
		} range; /* integer range */
		struct {
			struct in_addr addr;
			struct in_addr mask;
		} ipv4;                         /* IPv4 address */
		struct {
			struct in6_addr addr;
			unsigned char mask;     /* number of bits */
		} ipv6;                         /* IPv6 address/mask */
		struct acl_time time;           /* valid hours and days */
		unsigned int group_mask;
		struct eb_root *tree;           /* tree storing all values if any */
	} val;                                  /* direct value */
	union {
		void *ptr;              /* any data */
		char *str;              /* any string  */
		regex *reg;             /* a compiled regex */
	} ptr;                          /* indirect values, allocated */
	void(*freeptrbuf)(void *ptr);	/* a destructor able to free objects from the ptr */
	int len;                        /* data length when required  */
	int flags;                      /* expr or pattern flags. */
};

/* some dummy declarations to silent the compiler */
struct proxy;
struct session;

/*
 * ACL keyword: Associates keywords with parsers, methods to retrieve the value and testers.
 */
/*
 * NOTE:
 * The 'parse' function is called to parse words in the configuration. It must
 * return the number of valid words read. 0 = error. The 'opaque' argument may
 * be used by functions which need to maintain a context between consecutive
 * values. It is initialized to zero before the first call, and passed along
 * successive calls.
 */

struct acl_expr;
struct acl_keyword {
	const char *kw;
	char *fetch_kw;
	int (*parse)(const char **text, struct acl_pattern *pattern, int *opaque, char **err);
	int (*match)(struct sample *smp, struct acl_pattern *pattern);
	/* must be after the config params */
	struct sample_fetch *smp; /* the sample fetch we depend on */
};

/*
 * A keyword list. It is a NULL-terminated array of keywords. It embeds a
 * struct list in order to be linked to other lists, allowing it to easily
 * be declared where it is needed, and linked without duplicating data nor
 * allocating memory.
 */
struct acl_kw_list {
	struct list list;
	struct acl_keyword kw[VAR_ARRAY];
};

/*
 * Description of an ACL expression.
 * The expression is part of a list. It contains pointers to the keyword, the
 * parse and match functions which default to the keyword's, the sample fetch
 * descriptor which also defaults to the keyword's, and a list or tree of
 * patterns to test against. The structure is organized so that the hot parts
 * are grouped together in order to optimize caching.
 */
struct acl_expr {
	int (*parse)(const char **text, struct acl_pattern *pattern, int *opaque, char **err);
	int (*match)(struct sample *smp, struct acl_pattern *pattern);
	struct arg *args;             /* optional fetch argument list (eg: header or cookie name) */
	struct sample_fetch *smp;     /* the sample fetch we depend on */
	struct list patterns;         /* list of acl_patterns */
	struct eb_root pattern_tree;  /* may be used for lookup in large datasets */
	struct list list;             /* chaining */
	const char *kw;               /* points to the ACL kw's name or fetch's name (must not free) */
};

/* The acl will be linked to from the proxy where it is declared */
struct acl {
	struct list list;           /* chaining */
	char *name;		    /* acl name */
	struct list expr;	    /* list of acl_exprs */
	int cache_idx;              /* ACL index in cache */
	unsigned int use;           /* or'ed bit mask of all acl_expr's SMP_USE_* */
	unsigned int val;           /* or'ed bit mask of all acl_expr's SMP_VAL_* */
};

/* the condition will be linked to from an action in a proxy */
struct acl_term {
	struct list list;           /* chaining */
	struct acl *acl;            /* acl pointed to by this term */
	int neg;                    /* 1 if the ACL result must be negated */
};

struct acl_term_suite {
	struct list list;           /* chaining of term suites */
	struct list terms;          /* list of acl_terms */
};

struct acl_cond {
	struct list list;           /* Some specific tests may use multiple conditions */
	struct list suites;         /* list of acl_term_suites */
	int pol;                    /* polarity: ACL_COND_IF / ACL_COND_UNLESS */
	unsigned int use;           /* or'ed bit mask of all suites's SMP_USE_* */
	unsigned int val;           /* or'ed bit mask of all suites's SMP_VAL_* */
	const char *file;           /* config file where the condition is declared */
	int line;                   /* line in the config file where the condition is declared */
};


#endif /* _TYPES_ACL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
