/*
 * include/haproxy/action-t.h
 * This file contains actions definitions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_ACTION_T_H
#define _HAPROXY_ACTION_T_H

#include <haproxy/applet-t.h>
#include <haproxy/stick_table-t.h>
#include <haproxy/vars-t.h>

struct session;
struct stream;
struct proxy;

enum act_from {
	ACT_F_TCP_REQ_CON, /* tcp-request connection */
	ACT_F_TCP_REQ_SES, /* tcp-request session */
	ACT_F_TCP_REQ_CNT, /* tcp-request content */
	ACT_F_TCP_RES_CNT, /* tcp-response content */
	ACT_F_HTTP_REQ,    /* http-request */
	ACT_F_HTTP_RES,    /* http-response */
	ACT_F_TCP_CHK,     /* tcp-check. */
	ACT_F_CFG_PARSER,  /* config parser */
	ACT_F_CLI_PARSER,  /* command line parser */
};

enum act_return {
	ACT_RET_CONT,   /* continue processing. */
	ACT_RET_STOP,   /* stop processing. */
	ACT_RET_YIELD,  /* call me again. */
	ACT_RET_ERR,    /* internal processing error. */
	ACT_RET_DONE,   /* processing done, stop processing */
	ACT_RET_DENY,   /* deny, must be handled by the caller */
	ACT_RET_ABRT,   /* abort, handled by action itsleft. */
	ACT_RET_INV,    /* invalid request/response */
};

enum act_parse_ret {
	ACT_RET_PRS_OK,    /* continue processing. */
	ACT_RET_PRS_ERR,   /* abort processing. */
};

/* Option flags passed to custom actions */
enum act_opt {
	ACT_OPT_NONE  = 0x00000000,  /* no flag */
	ACT_OPT_FINAL = 0x00000001,  /* last call, cannot yield */
	ACT_OPT_FIRST = 0x00000002,  /* first call for this action */
};

/* Flags used to describe the action. */
enum act_flag {
        ACT_FLAG_FINAL = 1 << 0, /* the action stops the rules evaluation when executed */
};


/* known actions to be used without any action function pointer. This enum is
 * typically used in a switch case, if and only if .action_ptr is undefined. So
 * if an action function is defined for one of following action types, the
 * function have the priority over the switch.
 */
enum act_name {
	ACT_CUSTOM = 0,

	/* common action */
	ACT_ACTION_ALLOW,
	ACT_ACTION_DENY,

	/* common http actions .*/
	ACT_HTTP_REDIR,

	/* http request actions. */
	ACT_HTTP_REQ_TARPIT,

	/* tcp actions */
	ACT_TCP_EXPECT_PX,
	ACT_TCP_EXPECT_CIP,
	ACT_TCP_CLOSE, /* close at the sender's */
};

/* Timeout name valid for a set-timeout rule */
enum act_timeout_name {
	ACT_TIMEOUT_SERVER,
	ACT_TIMEOUT_TUNNEL,
};

enum act_normalize_uri {
	ACT_NORMALIZE_URI_PATH_MERGE_SLASHES,
	ACT_NORMALIZE_URI_PATH_STRIP_DOT,
	ACT_NORMALIZE_URI_PATH_STRIP_DOTDOT,
	ACT_NORMALIZE_URI_PATH_STRIP_DOTDOT_FULL,
	ACT_NORMALIZE_URI_QUERY_SORT_BY_NAME,
	ACT_NORMALIZE_URI_PERCENT_TO_UPPERCASE,
	ACT_NORMALIZE_URI_PERCENT_TO_UPPERCASE_STRICT,
	ACT_NORMALIZE_URI_PERCENT_DECODE_UNRESERVED,
	ACT_NORMALIZE_URI_PERCENT_DECODE_UNRESERVED_STRICT,
	ACT_NORMALIZE_URI_FRAGMENT_STRIP,
	ACT_NORMALIZE_URI_FRAGMENT_ENCODE,
};

/* NOTE: if <.action_ptr> is defined, the referenced function will always be
 *       called regardless the action type. */
struct act_rule {
	struct list list;
	struct acl_cond *cond;                 /* acl condition to meet */
	unsigned int action;                   /* ACT_* or any meaningful value if action_ptr is defined */
	unsigned int flags;                    /* ACT_FLAG_* */
	enum act_from from;                    /* ACT_F_* */
	enum act_return (*action_ptr)(struct act_rule *rule, struct proxy *px,  /* ptr to custom action */
	                              struct session *sess, struct stream *s, int opts);
	int (*check_ptr)(struct act_rule *rule, struct proxy *px, char **err); /* ptr to check function */
	void (*release_ptr)(struct act_rule *rule); /* ptr to release function */
	const struct action_kw *kw;
	struct applet applet;                  /* used for the applet registration. */
	union {
		struct {
			struct sample_expr *expr;
			char *varname;
			char *resolvers_id;
			struct resolvers *resolvers;
			struct resolv_options *opts;
		} resolv;                      /* resolving */
		struct {
			int i;                 /* integer param (status, nice, loglevel, ..) */
			struct ist str;        /* string param (reason, header name, ...) */
			struct list fmt;       /* log-format compatible expression */
			struct my_regex *re;   /* used by replace-header/value/uri/path */
		} http;                        /* args used by some HTTP rules */
		struct http_reply *http_reply; /* HTTP response to be used by return/deny/tarpit rules */
		struct redirect_rule *redir;   /* redirect rule or "http-request redirect" */
		struct {
			char *ref;             /* MAP or ACL file name to update */
			struct list key;       /* pattern to retrieve MAP or ACL key */
			struct list value;     /* pattern to retrieve MAP value */
		} map;
		struct sample_expr *expr;
		struct {
			struct sample_expr *expr; /* expression used as the key */
			struct cap_hdr *hdr;      /* the capture storage */
		} cap;
		struct {
			struct sample_expr *expr;
			int idx;
		} capid;
		struct {
			int value;                  /* plain timeout value in ms if no expr is used */
			enum act_timeout_name type; /* timeout type */
			struct sample_expr *expr;   /* timeout value as an expression */
		} timeout;
		struct hlua_rule *hlua_rule;
		struct {
			struct list fmt;            /* log-format compatible expression */
			struct sample_expr *expr;
			uint64_t name_hash;
			enum vars_scope scope;
			uint conditions;            /* Bitfield of the conditions passed to this set-var call */
		} vars;
		struct {
			int sc;
			unsigned int idx;
		} gpc;
		struct {
			int sc;
			unsigned int idx;
			long long int value;
			struct sample_expr *expr;
		} gpt;
		struct track_ctr_prm trk_ctr;
		struct {
			void *p[4];
		} act;                         /* generic pointers to be used by custom actions */
	} arg;                                 /* arguments used by some actions */
	struct {
		char *file;                    /* file name where the rule appears (or NULL) */
		int line;                      /* line number where the rule appears */
	} conf;
};

struct action_kw {
	const char *kw;
	enum act_parse_ret (*parse)(const char **args, int *cur_arg, struct proxy *px,
	                            struct act_rule *rule, char **err);
	int flags;
	void *private;
};

struct action_kw_list {
	struct list list;
	struct action_kw kw[VAR_ARRAY];
};

#endif /* _HAPROXY_ACTION_T_H */
