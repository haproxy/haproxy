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

/* ACL test result.
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
 * For efficiency, the ACL return flags are directly mapped from the pattern
 * match flags. See include/pattern.h for existing values.
 */
enum acl_test_res {
	ACL_TEST_FAIL = 0,           /* test failed */
	ACL_TEST_MISS = 1,           /* test may pass with more info */
	ACL_TEST_PASS = 3,           /* test passed */
};

/* Condition polarity. It makes it easier for any option to choose between
 * IF/UNLESS if it can store that information within the condition itself.
 * Those should be interpreted as "IF/UNLESS result == PASS".
 */
enum acl_cond_pol {
	ACL_COND_NONE,		/* no polarity set yet */
	ACL_COND_IF,		/* positive condition (after 'if') */
	ACL_COND_UNLESS,	/* negative condition (after 'unless') */
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
	int match_type; /* Contain PAT_MATCH_* */
	int (*parse)(const char *text, struct pattern *pattern, int flags, char **err);
	int (*index)(struct pattern_expr *expr, struct pattern *pattern, char **err);
	void (*delete)(struct pattern_expr *expr, struct pat_ref_elt *);
	void (*prune)(struct pattern_expr *expr);
	struct pattern *(*match)(struct sample *smp, struct pattern_expr *expr, int fill);
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
 * sample fetch descriptor which defaults to the keyword's, and the associated
 * pattern matching. The structure is organized so that the hot parts are
 * grouped together in order to optimize caching.
 */
struct acl_expr {
	struct sample_expr *smp;      /* the sample expression we depend on */
	struct pattern_head pat;      /* the pattern matching expression */
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
	enum acl_cond_pol pol;      /* polarity: ACL_COND_IF / ACL_COND_UNLESS */
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
