/*
 * include/haproxy/pattern-t.h
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

#ifndef _HAPROXY_PATTERN_T_H
#define _HAPROXY_PATTERN_T_H

#include <import/ebmbtree.h>

#include <haproxy/api-t.h>
#include <haproxy/regex-t.h>
#include <haproxy/sample_data-t.h>
#include <haproxy/thread-t.h>


/* Pattern matching function result.
 *
 * We're using a 3-state matching system to match samples against patterns in
 * ACLs :
 *   - PASS : at least one pattern already matches
 *   - MISS : some data is missing to decide if some rules may finally match.
 *   - FAIL : no mattern may ever match
 *
 * We assign values 0, 1 and 3 to FAIL, MISS and PASS respectively, so that we
 * can make use of standard arithmetic for the truth tables below :
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
	PAT_MF_NO_DNS      = 1 << 1,       /* don't perform any DNS requests */
};

/* possible flags for patterns storage */
enum {
	PAT_SF_TREE        = 1 << 0,       /* some patterns are arranged in a tree */
	PAT_SF_REGFREE     = 1 << 1,       /* run regex_free() on the pointer */
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
	char *reference; /* The reference name. */
	char *display; /* String displayed to identify the pattern origin. */
	struct list head; /* The head of the list of struct pat_ref_elt. */
	struct list pat; /* The head of the list of struct pattern_expr. */
	unsigned int flags; /* flags PAT_REF_*. */
	unsigned int curr_gen; /* current generation number (anything below can be removed) */
	unsigned int next_gen; /* next generation number (insertions use this one) */
	int unique_id; /* Each pattern reference have unique id. */
	unsigned long long revision; /* updated for each update */
	__decl_thread(HA_SPINLOCK_T lock); /* Lock used to protect pat ref elements */
};

/* This is a part of struct pat_ref. Each entry contains one pattern and one
 * associated value as original string. All derivative forms (via exprs) are
 * accessed from list_head or tree_head.
 */
struct pat_ref_elt {
	struct list list; /* Used to chain elements. */
	struct list back_refs; /* list of users tracking this pat ref */
	void *list_head; /* all &pattern_list->from_ref derived from this reference, ends with NULL */
	void *tree_head; /* all &pattern_tree->from_ref derived from this reference, ends with NULL */
	char *pattern;
	char *sample;
	unsigned int gen_id; /* generation of pat_ref this was made for */
	int line;
};

/* This contain each tree indexed entry. This struct permit to associate
 * "sample" with a tree entry. It is used with maps.
 */
struct pattern_tree {
	void *from_ref;    // pattern_tree linked from pat_ref_elt, ends with NULL
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
			unsigned int min_set:1;
			unsigned int max_set:1;
		} range; /* integer range */
		struct {
			struct in_addr addr;
			struct in_addr mask;
		} ipv4;                         /* IPv4 address */
		struct {
			struct in6_addr addr;
			unsigned char mask;     /* number of bits */
		} ipv6;                         /* IPv6 address/mask */
	} val;                                  /* direct value */
	union {
		void *ptr;              /* any data */
		char *str;              /* any string  */
		struct my_regex *reg;   /* a compiled regex */
	} ptr;                          /* indirect values, allocated or NULL */
	int len;                        /* data length when required  */
	int sflags;                     /* flags relative to the storage method. */
	struct sample_data *data;       /* used to store a pointer to sample value associated
	                                   with the match. It is used with maps */
	struct pat_ref_elt *ref;
};

/* This struct is just used for chaining patterns */
struct pattern_list {
	void *from_ref;    // pattern_tree linked from pat_ref_elt, ends with NULL
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
	struct pat_ref *ref; /* The pattern reference if exists. */
	struct pattern_head *pat_head; /* Point to the pattern_head that contain manipulation functions.
	                                * Note that this link point on compatible head but not on the real
	                                * head. You can use only the function, and you must not use the
	                                * "head". Don't write "(struct pattern_expr *)any->pat_head->expr".
	                                */
	struct list patterns;         /* list of acl_patterns */
	struct eb_root pattern_tree;  /* may be used for lookup in large datasets */
	struct eb_root pattern_tree_2;  /* may be used for different types */
	int mflags;                     /* flags relative to the parsing or matching method. */
	__decl_thread(HA_RWLOCK_T lock);               /* lock used to protect patterns */
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


/* This struct contains a list of pattern expr */
struct sample;
struct pattern_head {
	int (*parse)(const char *text, struct pattern *pattern, int flags, char **err);
	int (*parse_smp)(const char *text, struct sample_data *data);
	int (*index)(struct pattern_expr *, struct pattern *, char **);
	void (*prune)(struct pattern_expr *);
	struct pattern *(*match)(struct sample *, struct pattern_expr *, int);
	int expect_type; /* type of the expected sample (SMP_T_*) */

	struct list head; /* This is a list of struct pattern_expr_list. */
};

#endif /* _HAPROXY_PATTERN_T_H */
