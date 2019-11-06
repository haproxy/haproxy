/*
 * include/types/action.h
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

#ifndef _TYPES_ACTION_H
#define _TYPES_ACTION_H

#include <common/regex.h>

#include <types/applet.h>
#include <types/stick_table.h>

enum act_from {
	ACT_F_TCP_REQ_CON, /* tcp-request connection */
	ACT_F_TCP_REQ_SES, /* tcp-request session */
	ACT_F_TCP_REQ_CNT, /* tcp-request content */
	ACT_F_TCP_RES_CNT, /* tcp-response content */
	ACT_F_HTTP_REQ,    /* http-request */
	ACT_F_HTTP_RES,    /* http-response */
};

enum act_return {
	ACT_RET_CONT,  /* continue processing. */
	ACT_RET_STOP,  /* stop processing. */
	ACT_RET_YIELD, /* call me again. */
	ACT_RET_ERR,   /* processing error. */
	ACT_RET_DONE,  /* processing done, stop processing */
};

enum act_parse_ret {
	ACT_RET_PRS_OK,    /* continue processing. */
	ACT_RET_PRS_ERR,   /* abort processing. */
};

/* flags passed to custom actions */
enum act_flag {
	ACT_FLAG_NONE  = 0x00000000,  /* no flag */
	ACT_FLAG_FINAL = 0x00000001,  /* last call, cannot yield */
	ACT_FLAG_FIRST = 0x00000002,  /* first call for this action */
};

enum act_name {
	ACT_CUSTOM = 0,

	/* common action */
	ACT_ACTION_ALLOW,
	ACT_ACTION_DENY,

	/* common http actions .*/
	ACT_HTTP_ADD_HDR,
	ACT_HTTP_REPLACE_HDR,
	ACT_HTTP_REPLACE_VAL,
	ACT_HTTP_SET_HDR,
	ACT_HTTP_DEL_HDR,
	ACT_HTTP_REDIR,
	ACT_HTTP_SET_NICE,
	ACT_HTTP_SET_LOGL,
	ACT_HTTP_SET_TOS,
	ACT_HTTP_SET_MARK,
	ACT_HTTP_ADD_ACL,
	ACT_HTTP_DEL_ACL,
	ACT_HTTP_DEL_MAP,
	ACT_HTTP_SET_MAP,
	ACT_HTTP_EARLY_HINT,

	/* http request actions. */
	ACT_HTTP_REQ_TARPIT,
	ACT_HTTP_REQ_AUTH,

	/* tcp actions */
	ACT_TCP_EXPECT_PX,
	ACT_TCP_EXPECT_CIP,
	ACT_TCP_CLOSE, /* close at the sender's */
	ACT_TCP_CAPTURE, /* capture a fetched sample */

	/* track stick counters */
	ACT_ACTION_TRK_SC0,
	/* SC1, SC2, ... SCn */
	ACT_ACTION_TRK_SCMAX = ACT_ACTION_TRK_SC0 + MAX_SESS_STKCTR - 1,
};

struct act_rule {
	struct list list;
	struct acl_cond *cond;                 /* acl condition to meet */
	enum act_name action;                  /* ACT_ACTION_* */
	enum act_from from;                    /* ACT_F_* */
	short deny_status;                     /* HTTP status to return to user when denying */
	enum act_return (*action_ptr)(struct act_rule *rule, struct proxy *px,  /* ptr to custom action */
	                              struct session *sess, struct stream *s, int flags);
	int (*check_ptr)(struct act_rule *rule, struct proxy *px, char **err); /* ptr to check function */
	struct action_kw *kw;
	struct applet applet;                  /* used for the applet registration. */
	union {
		struct {
			struct sample_expr *expr;
			char *varname;
			char *resolvers_id;
			struct dns_resolvers *resolvers;
			struct dns_options dns_opts;
		} dns;                        /* dns resolution */
		struct {
			char *realm;
		} auth;                        /* arg used by "auth" */
		struct {
			char *name;            /* header name */
			int name_len;          /* header name's length */
			struct list fmt;       /* log-format compatible expression */
			struct my_regex *re;   /* used by replace-header and replace-value */
		} hdr_add;                     /* args used by "add-header" and "set-header" */
		struct {
			char *name;            /* header name */
			int name_len;          /* header name's length */
			struct list fmt;       /* log-format compatible expression */
		} early_hint;
		struct redirect_rule *redir;   /* redirect rule or "http-request redirect" */
		int nice;                      /* nice value for ACT_HTTP_SET_NICE */
		int loglevel;                  /* log-level value for ACT_HTTP_SET_LOGL */
		int tos;                       /* tos value for ACT_HTTP_SET_TOS */
		int mark;                      /* nfmark value for ACT_HTTP_SET_MARK */
		struct {
			char *ref;             /* MAP or ACL file name to update */
			struct list key;       /* pattern to retrieve MAP or ACL key */
			struct list value;     /* pattern to retrieve MAP value */
		} map;
		struct sample_expr *expr;
		struct {
			struct list logfmt;
			int action;
		} http;
		struct {
			struct sample_expr *expr; /* expression used as the key */
			struct cap_hdr *hdr;      /* the capture storage */
		} cap;
		struct {
			unsigned int code;     /* HTTP status code */
			const char *reason;    /* HTTP status reason */
		} status;
		struct {
			struct sample_expr *expr;
			int idx;
		} capid;
		struct hlua_rule *hlua_rule;
		struct {
			struct sample_expr *expr;
			const char *name;
			enum vars_scope scope;
		} vars;
		struct {
			int sc;
		} gpc;
		struct {
			int sc;
			long long int value;
			struct sample_expr *expr;
		} gpt;
		struct track_ctr_prm trk_ctr;
		struct {
			void *p[4];
		} act;                         /* generic pointers to be used by custom actions */
	} arg;                                 /* arguments used by some actions */
};

struct action_kw {
	const char *kw;
	enum act_parse_ret (*parse)(const char **args, int *cur_arg, struct proxy *px,
	                            struct act_rule *rule, char **err);
	int match_pfx;
	void *private;
};

struct action_kw_list {
	struct list list;
	struct action_kw kw[VAR_ARRAY];
};

#endif /* _TYPES_ACTION_H */
