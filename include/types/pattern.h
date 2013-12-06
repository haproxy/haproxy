/*
 * include/types/pattern.h
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

#ifndef _TYPES_PATTERN_H
#define _TYPES_PATTERN_H

#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/regex.h>

#include <types/sample.h>

#include <ebmbtree.h>

/* Pattern matching function result.
 *
 * We're using a 3-state matching system to match samples against patterns in
 * ACLs :
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
 * match flags. A pattern can't return "MISS" since it's always presented an
 * existing sample. So that leaves us with only two possible values :
 *      MATCH   = 0
 *      NOMATCH = 3
 */
enum pat_match_res {
	PAT_NOMATCH = 0,         /* sample didn't match any pattern */
	PAT_MATCH = 3,           /* sample matched at least one pattern */
};

/* This enum describe the running mode of the function pat_parse_*().
 * The lookup mode does not allocate memory. The compile mode allocate
 * memory and create any data
 */
enum pat_usage {
	PAT_U_LOOKUP,
	PAT_U_COMPILE,
};

/* possible flags for expressions or patterns */
enum {
	PAT_F_IGNORE_CASE = 1 << 0,       /* ignore case */
	PAT_F_FROM_FILE   = 1 << 1,       /* pattern comes from a file */
	PAT_F_TREE        = 1 << 2,       /* some patterns are arranged in a tree */
};

/* ACL match methods */
enum {
	PAT_MATCH_FOUND, /* just ensure that fetch found the sample */
	PAT_MATCH_BOOL,  /* match fetch's integer value as boolean */
	PAT_MATCH_INT,   /* unsigned integer (int) */
	PAT_MATCH_IP,    /* IPv4/IPv6 address (IP) */
	PAT_MATCH_BIN,   /* hex string (bin) */
	PAT_MATCH_LEN,   /* string length (str -> int) */
	PAT_MATCH_STR,   /* exact string match (str) */
	PAT_MATCH_BEG,   /* beginning of string (str) */
	PAT_MATCH_SUB,   /* substring (str) */
	PAT_MATCH_DIR,   /* directory-like sub-string (str) */
	PAT_MATCH_DOM,   /* domain-like sub-string (str) */
	PAT_MATCH_END,   /* end of string (str) */
	PAT_MATCH_REG,   /* regex (str -> reg) */
	/* keep this one last */
	PAT_MATCH_NUM
};

/* How to store a time range and the valid days in 29 bits */
struct pat_time {
	int dow:7;              /* 1 bit per day of week: 0-6 */
	int h1:5, m1:6;         /* 0..24:0..60. Use 0:0 for all day. */
	int h2:5, m2:6;         /* 0..24:0..60. Use 24:0 for all day. */
};

/* This contain each tree indexed entry. This struct permit to associate
 * "sample" with a tree entry. It is used with maps.
 */
struct pat_idx_elt {
	struct sample_storage *smp;
	struct ebmb_node node;
};

/* This describes one ACL pattern, which might be a single value or a tree of
 * values. All patterns for a single ACL expression are linked together. Some
 * of them might have a type (eg: IP). Right now, the types are shared with
 * the samples, though it is possible that in the future this will change to
 * accommodate for other types (eg: meth, regex). Unsigned and constant types
 * are preferred when there is a doubt.
 */
struct pattern {
	struct list list;                       /* chaining */
	int type;                               /* type of the ACL pattern (SMP_T_*) */
	int expect_type;                        /* type of the expected sample (SMP_T_*) */
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
		struct pat_time time;           /* valid hours and days */
		unsigned int group_mask;
		struct eb_root *tree;           /* tree storing all values if any */
	} val;                                  /* direct value */
	union {
		void *ptr;              /* any data */
		char *str;              /* any string  */
		struct my_regex *reg;   /* a compiled regex */
	} ptr;                          /* indirect values, allocated */
	void(*freeptrbuf)(void *ptr);	/* a destructor able to free objects from the ptr */
	int len;                        /* data length when required  */
	int flags;                      /* expr or pattern flags. */
	struct sample_storage *smp;     /* used to store a pointer to sample value associated
	                                   with the match. It is used with maps */

};

/* Description of a pattern expression.
 * It contains pointers to the parse and match functions, and a list or tree of
 * patterns to test against. The structure is organized so that the hot parts
 * are grouped together in order to optimize caching.
 */
struct pattern_expr {
	int (*parse)(const char **text, struct pattern *pattern, enum pat_usage usage, int *opaque, char **err);
	enum pat_match_res (*match)(struct sample *smp, struct pattern *pattern);
	struct list patterns;         /* list of acl_patterns */
	struct eb_root pattern_tree;  /* may be used for lookup in large datasets */
};

extern char *pat_match_names[PAT_MATCH_NUM];
extern int (*pat_parse_fcts[PAT_MATCH_NUM])(const char **, struct pattern *, enum pat_usage, int *, char **);
extern enum pat_match_res (*pat_match_fcts[PAT_MATCH_NUM])(struct sample *, struct pattern *);
extern int pat_match_types[PAT_MATCH_NUM];

#endif /* _TYPES_PATTERN_H */
