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

/* possible flags for patterns matching or parsing */
enum {
	PAT_MF_IGNORE_CASE = 1 << 0,       /* ignore case */
	PAT_MF_NO_DNS      = 1 << 1,       /* dont perform any DNS requests */
};

/* possible flags for patterns storage */
enum {
	PAT_SF_TREE        = 1 << 0,       /* some patterns are arranged in a tree */
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
	PAT_MATCH_REGM,  /* regex (str -> reg) with match zones */
	/* keep this one last */
	PAT_MATCH_NUM
};

#define PAT_REF_MAP 0x1 /* Set if the reference is used by at least one map. */
#define PAT_REF_ACL 0x2 /* Set if the reference is used by at least one acl. */
#define PAT_REF_SMP 0x4 /* Flag used if the reference contains a sample. */

/* This struct contain a list of reference strings for dunamically
 * updatable patterns.
 */
struct pat_ref {
	struct list list; /* Used to chain refs. */
	unsigned int flags; /* flags PAT_REF_*. */
	char *reference; /* The reference name. */
	int unique_id; /* Each pattern reference have unique id. */
	char *display; /* String displayed to identify the pattern origin. */
	struct list head; /* The head of the list of struct pat_ref_elt. */
	struct list pat; /* The head of the list of struct pattern_expr. */
	__decl_hathreads(HA_SPINLOCK_T lock); /* Lock used to protect pat ref elements */
};

/* This is a part of struct pat_ref. Each entry contain one
 * pattern and one associated value as original string.
 */
struct pat_ref_elt {
	struct list list; /* Used to chain elements. */
	struct list back_refs; /* list of users tracking this pat ref */
	char *pattern;
	char *sample;
	int line;
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
struct pattern_tree {
	struct sample_data *data;
	struct pat_ref_elt *ref;
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
		struct pat_time time;           /* valid hours and days */
		struct eb_root *tree;           /* tree storing all values if any */
	} val;                                  /* direct value */
	union {
		void *ptr;              /* any data */
		char *str;              /* any string  */
		struct my_regex *reg;   /* a compiled regex */
	} ptr;                          /* indirect values, allocated */
	int len;                        /* data length when required  */
	int sflags;                     /* flags relative to the storage method. */
	struct sample_data *data;       /* used to store a pointer to sample value associated
	                                   with the match. It is used with maps */
	struct pat_ref_elt *ref;
};

/* This struct is just used for chaining patterns */
struct pattern_list {
	struct list list;
	struct pattern pat;
};

/* Description of a pattern expression.
 * It contains pointers to the parse and match functions, and a list or tree of
 * patterns to test against. The structure is organized so that the hot parts
 * are grouped together in order to optimize caching.
 */
struct pattern_expr {
	struct list list; /* Used for chaining pattern_expr in pat_ref. */
	unsigned long long revision; /* updated for each update */
	struct pat_ref *ref; /* The pattern reference if exists. */
	struct pattern_head *pat_head; /* Point to the pattern_head that contain manipulation functions.
	                                * Note that this link point on compatible head but not on the real
	                                * head. You can use only the function, and you must not use the
	                                * "head". Dont write "(struct pattern_expr *)any->pat_head->expr".
	                                */
	struct list patterns;         /* list of acl_patterns */
	struct eb_root pattern_tree;  /* may be used for lookup in large datasets */
	struct eb_root pattern_tree_2;  /* may be used for different types */
	int mflags;                     /* flags relative to the parsing or matching method. */
	__decl_hathreads(HA_RWLOCK_T lock);               /* lock used to protect patterns */
};

/* This is a list of expression. A struct pattern_expr can be used by
 * more than one "struct pattern_head". this intermediate struct
 * permit more than one list.
 */
struct pattern_expr_list {
	struct list list; /* Used for chaining pattern_expr in pattern_head. */
	int do_free;
	struct pattern_expr *expr; /* The used expr. */
};

/* This struct contain a list of pattern expr */
struct pattern_head {
	int (*parse)(const char *text, struct pattern *pattern, int flags, char **err);
	int (*parse_smp)(const char *text, struct sample_data *data);
	int (*index)(struct pattern_expr *, struct pattern *, char **);
	void (*delete)(struct pattern_expr *, struct pat_ref_elt *);
	void (*prune)(struct pattern_expr *);
	struct pattern *(*match)(struct sample *, struct pattern_expr *, int);
	int expect_type; /* type of the expected sample (SMP_T_*) */

	struct list head; /* This is a list of struct pattern_expr_list. */
};

/* This is the root of the list of all pattern_ref avalaibles. */
extern struct list pattern_reference;

#endif /* _TYPES_PATTERN_H */
