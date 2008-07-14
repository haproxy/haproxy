/*
  include/types/acl.h
  This file provides structures and types for ACLs.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_ACL_H
#define _TYPES_ACL_H

#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>

#include <types/proxy.h>
#include <types/session.h>


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

/* possible flags for intermediate test values. The flags are maintained
 * across consecutive fetches for a same entry (eg: parse all req lines).
 */
enum {
	ACL_TEST_F_READ_ONLY  = 1 << 0, /* test data are read-only */
	ACL_TEST_F_MUST_FREE  = 1 << 1, /* test data must be freed after end of evaluation */
	ACL_TEST_F_VOL_TEST   = 1 << 2, /* result must not survive longer than the test (eg: time) */
	ACL_TEST_F_VOL_HDR    = 1 << 3, /* result sensitive to changes in headers */
	ACL_TEST_F_VOL_1ST    = 1 << 4, /* result sensitive to changes in first line (eg: URI) */
	ACL_TEST_F_VOL_TXN    = 1 << 5, /* result sensitive to new transaction (eg: persist) */
	ACL_TEST_F_VOL_SESS   = 1 << 6, /* result sensitive to new session (eg: IP) */
	ACL_TEST_F_VOLATILE   = (1<<2)|(1<<3)|(1<<4)|(1<<5)|(1<<6),
	ACL_TEST_F_FETCH_MORE = 1 << 7, /* if test does not match, retry with next entry (for multi-match) */
	ACL_TEST_F_MAY_CHANGE = 1 << 8, /* if test does not match, retry later (eg: request size) */
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

/* The structure exchanged between an acl_fetch_* function responsible for
 * retrieving a value, and an acl_match_* function responsible for testing it.
 */
struct acl_test {
	int i;                  /* integer value */
	char *ptr;              /* pointer to beginning of value */
	int len;                /* length of value at ptr, otherwise ignored */
	int flags;              /* ACL_TEST_F_* set to 0 on first call */
	union {                 /* fetch_* functions context for any purpose */
		void *p;        /* any pointer */
		int i;          /* any integer */
		long long ll;   /* any long long or smaller */
		double d;       /* any float or double */
		void *a[8];     /* any array of up to 8 pointers */
	} ctx;
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
	             struct acl_expr *expr, struct acl_test *test);
	int (*match)(struct acl_test *test, struct acl_pattern *pattern);
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
	union {                     /* optional argument of the subject (eg: header or cookie name) */
		char *str;
	} arg;
	int arg_len;                /* optional argument length */
	struct list patterns;       /* list of acl_patterns */
};

struct acl {
	struct list list;           /* chaining */
	char *name;		    /* acl name */
	struct list expr;	    /* list of acl_exprs */
	int cache_idx;              /* ACL index in cache */
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
};


#endif /* _TYPES_ACL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
