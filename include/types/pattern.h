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

enum {
	ACL_PAT_FAIL = 0,           /* test failed */
	ACL_PAT_MISS = 1,           /* test may pass with more info */
	ACL_PAT_PASS = 3,           /* test passed */
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

/* This contain each tree indexed entry. This struct permit to associate
 * "sample" with a tree entry. It is used with maps.
 */
struct acl_idx_elt {
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
	struct sample_storage *smp;     /* used to store a pointer to sample value associated
	                                   with the match. It is used with maps */

};

extern char *acl_match_names[ACL_MATCH_NUM];
extern int (*acl_parse_fcts[ACL_MATCH_NUM])(const char **, struct acl_pattern *, struct sample_storage *, int *, char **);
extern int (*acl_match_fcts[ACL_MATCH_NUM])(struct sample *, struct acl_pattern *);

#endif /* _TYPES_PATTERN_H */
