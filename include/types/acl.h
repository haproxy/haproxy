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
#include <types/pattern.h>
#include <types/proxy.h>
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

/* ACLs can be evaluated on requests and on responses, and on partial or complete data */
enum {
	ACL_DIR_REQ = 0,        /* ACL evaluated on request */
	ACL_DIR_RTR = (1 << 0), /* ACL evaluated on response */
	ACL_DIR_MASK = (ACL_DIR_REQ | ACL_DIR_RTR),
	ACL_PARTIAL = (1 << 1), /* partial data, return MISS if data are missing */
};

/* possible flags for expressions or patterns */
enum {
	ACL_PAT_F_IGNORE_CASE = 1 << 0,       /* ignore case */
	ACL_PAT_F_FROM_FILE   = 1 << 1,       /* pattern comes from a file */
	ACL_PAT_F_TREE_OK     = 1 << 2,       /* the pattern parser is allowed to build a tree */
	ACL_PAT_F_TREE        = 1 << 3,       /* some patterns are arranged in a tree */
};

/* what capabilities an ACL uses. These flags are set during parsing, which
 * allows for flexible ACLs typed by their contents.
 */
enum {
	ACL_USE_NOTHING         = 0,            /* no need for anything beyond internal information */
	ACL_USE_TCP4_PERMANENT  = 1 <<  0,      /* unchanged TCPv4 data (eg: source IP) */
	ACL_USE_TCP4_CACHEABLE  = 1 <<  1,      /* cacheable TCPv4 data (eg: src conns) */
	ACL_USE_TCP4_VOLATILE   = 1 <<  2,      /* volatile  TCPv4 data (eg: RTT) */
	ACL_USE_TCP4_ANY        = (ACL_USE_TCP4_PERMANENT | ACL_USE_TCP4_CACHEABLE | ACL_USE_TCP4_VOLATILE),

	ACL_USE_TCP6_PERMANENT  = 1 <<  3,      /* unchanged TCPv6 data (eg: source IP) */
	ACL_USE_TCP6_CACHEABLE  = 1 <<  4,      /* cacheable TCPv6 data (eg: src conns) */
	ACL_USE_TCP6_VOLATILE   = 1 <<  5,      /* volatile  TCPv6 data (eg: RTT) */
	ACL_USE_TCP6_ANY        = (ACL_USE_TCP6_PERMANENT | ACL_USE_TCP6_CACHEABLE | ACL_USE_TCP6_VOLATILE),

	ACL_USE_TCP_PERMANENT   = 1 <<  6,      /* unchanged TCPv4/v6 data (eg: source IP) */
	ACL_USE_TCP_CACHEABLE   = 1 <<  7,      /* cacheable TCPv4/v6 data (eg: src conns) */
	ACL_USE_TCP_VOLATILE    = 1 <<  8,      /* volatile  TCPv4/v6 data (eg: RTT) */
	ACL_USE_TCP_ANY         = (ACL_USE_TCP_PERMANENT | ACL_USE_TCP_CACHEABLE | ACL_USE_TCP_VOLATILE),

	ACL_USE_L6REQ_PERMANENT = 1 <<  9,      /* unchanged layer6 request data */
	ACL_USE_L6REQ_CACHEABLE = 1 << 10,      /* cacheable layer6 request data (eg: length) */
	ACL_USE_L6REQ_VOLATILE  = 1 << 11,      /* volatile  layer6 request data (eg: contents) */
	ACL_USE_L6REQ_ANY       = (ACL_USE_L6REQ_PERMANENT | ACL_USE_L6REQ_CACHEABLE | ACL_USE_L6REQ_VOLATILE),

	ACL_USE_L6RTR_PERMANENT = 1 << 12,      /* unchanged layer6 response data */
	ACL_USE_L6RTR_CACHEABLE = 1 << 13,      /* cacheable layer6 response data (eg: length) */
	ACL_USE_L6RTR_VOLATILE  = 1 << 14,      /* volatile  layer6 response data (eg: contents) */
	ACL_USE_L6RTR_ANY       = (ACL_USE_L6RTR_PERMANENT | ACL_USE_L6RTR_CACHEABLE | ACL_USE_L6RTR_VOLATILE),

	ACL_USE_L7REQ_PERMANENT = 1 << 15,      /* unchanged layer7 request data (eg: method) */
	ACL_USE_L7REQ_CACHEABLE = 1 << 16,      /* cacheable layer7 request data (eg: content-length) */
	ACL_USE_L7REQ_VOLATILE  = 1 << 17,      /* volatile  layer7 request data (eg: cookie) */
	ACL_USE_L7REQ_ANY       = (ACL_USE_L7REQ_PERMANENT | ACL_USE_L7REQ_CACHEABLE | ACL_USE_L7REQ_VOLATILE),

	ACL_USE_L7RTR_PERMANENT = 1 << 18,      /* unchanged layer7 response data (eg: status) */
	ACL_USE_L7RTR_CACHEABLE = 1 << 19,      /* cacheable layer7 response data (eg: content-length) */
	ACL_USE_L7RTR_VOLATILE  = 1 << 20,      /* volatile  layer7 response data (eg: cookie) */
	ACL_USE_L7RTR_ANY       = (ACL_USE_L7RTR_PERMANENT | ACL_USE_L7RTR_CACHEABLE | ACL_USE_L7RTR_VOLATILE),

	/* those ones are used for ambiguous "hdr_xxx" verbs */
	ACL_USE_HDR_CACHEABLE   = 1 << 21,      /* cacheable request or response header (eg: content-length) */
	ACL_USE_HDR_VOLATILE    = 1 << 22,      /* volatile  request or response header (eg: cookie) */
	ACL_USE_HDR_ANY = (ACL_USE_HDR_CACHEABLE | ACL_USE_HDR_VOLATILE),

	/* This one indicates that we need an internal parameter known in the response only */
	ACL_USE_RTR_INTERNAL    = 1 << 23,      /* volatile response information */

	/* information which remains during response */
	ACL_USE_REQ_PERMANENT   = (ACL_USE_TCP4_PERMANENT | ACL_USE_TCP6_PERMANENT | ACL_USE_TCP_PERMANENT |
				   ACL_USE_L6REQ_PERMANENT | ACL_USE_L7REQ_PERMANENT),
	ACL_USE_REQ_CACHEABLE   = (ACL_USE_TCP4_CACHEABLE | ACL_USE_TCP6_CACHEABLE | ACL_USE_TCP_CACHEABLE |
				   ACL_USE_L6REQ_CACHEABLE | ACL_USE_L7REQ_CACHEABLE | ACL_USE_HDR_CACHEABLE),

	/* information which does not remain during response */
	ACL_USE_REQ_VOLATILE    = (ACL_USE_TCP4_VOLATILE | ACL_USE_TCP6_VOLATILE | ACL_USE_TCP_VOLATILE |
				   ACL_USE_L6REQ_VOLATILE | ACL_USE_L7REQ_VOLATILE),

	/* any type of layer 6 contents information (random data available in a buffer) */
	ACL_USE_L6_ANY          = (ACL_USE_L6REQ_ANY | ACL_USE_L6RTR_ANY),

	/* any type of layer 7 information */
	ACL_USE_L7_ANY          = (ACL_USE_L7REQ_ANY | ACL_USE_L7RTR_ANY | ACL_USE_HDR_ANY),

	/* any type of response information */
	ACL_USE_RTR_ANY         = (ACL_USE_L6RTR_ANY | ACL_USE_L7RTR_ANY | ACL_USE_RTR_INTERNAL),

	/* some flags indicating if a keyword supports exact pattern matching,
	 * so that patterns may be arranged in lookup trees. Let's put those
	 * flags at the end to leave some space for the other ones above.
	 */
	ACL_MAY_LOOKUP          =  1 << 31,  /* exact pattern lookup */
};

/* filtering hooks */
enum {
	/* hooks on the request path */
	ACL_HOOK_REQ_FE_TCP = 0,
	ACL_HOOK_REQ_FE_TCP_CONTENT,
	ACL_HOOK_REQ_FE_HTTP_IN,
	ACL_HOOK_REQ_FE_SWITCH,
	ACL_HOOK_REQ_BE_TCP_CONTENT,
	ACL_HOOK_REQ_BE_HTTP_IN,
	ACL_HOOK_REQ_BE_SWITCH,
	ACL_HOOK_REQ_FE_HTTP_OUT,
	ACL_HOOK_REQ_BE_HTTP_OUT,
	/* hooks on the response path */
	ACL_HOOK_RTR_BE_TCP_CONTENT,
	ACL_HOOK_RTR_BE_HTTP_IN,
	ACL_HOOK_RTR_FE_TCP_CONTENT,
	ACL_HOOK_RTR_FE_HTTP_IN,
	ACL_HOOK_RTR_BE_HTTP_OUT,
	ACL_HOOK_RTR_FE_HTTP_OUT,
};

/* How to store a time range and the valid days in 29 bits */
struct acl_time {
	int dow:7;              /* 1 bit per day of week: 0-6 */
	int h1:5, m1:6;         /* 0..24:0..60. Use 0:0 for all day. */
	int h2:5, m2:6;         /* 0..24:0..60. Use 24:0 for all day. */
};

/* The acl will be linked to from the proxy where it is declared */
struct acl_pattern {
	struct list list;                       /* chaining */
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
		struct acl_time time;           /* valid hours and days */
		unsigned int group_mask;
		struct eb_root *tree;           /* tree storing all values if any */
	} val;                                  /* direct value */
	union {
		void *ptr;              /* any data */
		char *str;              /* any string  */
		regex_t *reg;           /* a compiled regex */
	} ptr;                          /* indirect values, allocated */
	void(*freeptrbuf)(void *ptr);	/* a destructor able to free objects from the ptr */
	int len;                        /* data length when required  */
	int flags;                      /* expr or pattern flags. */
};

/*
 * ACL keyword: Associates keywords with parsers, methods to retrieve the value and testers.
 */

/* some dummy declarations to silent the compiler */
struct proxy;
struct session;

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
	int (*parse)(const char **text, struct acl_pattern *pattern, int *opaque);
	int (*fetch)(struct proxy *px, struct session *l4, void *l7, int dir,
	             const struct arg *args, struct sample *smp);
	int (*match)(struct sample *smp, struct acl_pattern *pattern);
	unsigned int requires;   /* bit mask of all ACL_USE_* required to evaluate this keyword */
	int arg_mask; /* mask describing up to 7 arg types */
	/* must be after the config params */
	int use_cnt;
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
 * It contains a subject and a set of patterns to test against it.
 *  - the function get() is called to retrieve the subject from the
 *    current session or transaction and build a test.
 *  - the function test() is called to evaluate the test based on the
 *    available patterns and return ACL_PAT_*
 * Both of those functions are available through the keyword.
 */
struct acl_expr {
	struct list list;           /* chaining */
	struct acl_keyword *kw;     /* back-reference to the keyword */
	struct arg *args;           /* optional argument list (eg: header or cookie name) */
	struct list patterns;       /* list of acl_patterns */
	struct eb_root pattern_tree;  /* may be used for lookup in large datasets */
};

struct acl {
	struct list list;           /* chaining */
	char *name;		    /* acl name */
	struct list expr;	    /* list of acl_exprs */
	int cache_idx;              /* ACL index in cache */
	unsigned int requires;      /* or'ed bit mask of all acl_expr's ACL_USE_* */
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
	unsigned int requires;      /* or'ed bit mask of all acl's ACL_USE_* */
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
