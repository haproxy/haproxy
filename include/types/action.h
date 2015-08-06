/*
 * include/types/action.h
 * This file contains TCP protocol definitions.
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

#include <types/stick_table.h>

enum act_from {
	ACT_F_TCP_REQ_CON, /* tcp-request connection */
	ACT_F_TCP_REQ_CNT, /* tcp-request content */
	ACT_F_TCP_RES_CNT, /* tcp-response content */
	ACT_F_HTTP_REQ,    /* http-request */
	ACT_F_HTTP_RES,    /* http-response */
};

enum act_name {
	ACT_ACTION_CONT = 0,
	ACT_ACTION_STOP,

	/* http request actions. */
	HTTP_REQ_ACT_UNKNOWN,
	HTTP_REQ_ACT_ALLOW,
	HTTP_REQ_ACT_DENY,
	HTTP_REQ_ACT_TARPIT,
	HTTP_REQ_ACT_AUTH,
	HTTP_REQ_ACT_ADD_HDR,
	HTTP_REQ_ACT_SET_HDR,
	HTTP_REQ_ACT_DEL_HDR,
	HTTP_REQ_ACT_REPLACE_HDR,
	HTTP_REQ_ACT_REPLACE_VAL,
	HTTP_REQ_ACT_REDIR,
	HTTP_REQ_ACT_SET_NICE,
	HTTP_REQ_ACT_SET_LOGL,
	HTTP_REQ_ACT_SET_TOS,
	HTTP_REQ_ACT_SET_MARK,
	HTTP_REQ_ACT_ADD_ACL,
	HTTP_REQ_ACT_DEL_ACL,
	HTTP_REQ_ACT_DEL_MAP,
	HTTP_REQ_ACT_SET_MAP,
	HTTP_REQ_ACT_SET_SRC,
	HTTP_REQ_ACT_TRK_SC0,
	/* SC1, SC2, ... SCn */
	HTTP_REQ_ACT_TRK_SCMAX = HTTP_REQ_ACT_TRK_SC0 + MAX_SESS_STKCTR - 1,

	/* http response actions */
	HTTP_RES_ACT_UNKNOWN,
	HTTP_RES_ACT_ALLOW,
	HTTP_RES_ACT_DENY,
	HTTP_RES_ACT_ADD_HDR,
	HTTP_RES_ACT_REPLACE_HDR,
	HTTP_RES_ACT_REPLACE_VAL,
	HTTP_RES_ACT_SET_HDR,
	HTTP_RES_ACT_DEL_HDR,
	HTTP_RES_ACT_SET_NICE,
	HTTP_RES_ACT_SET_LOGL,
	HTTP_RES_ACT_SET_TOS,
	HTTP_RES_ACT_SET_MARK,
	HTTP_RES_ACT_ADD_ACL,
	HTTP_RES_ACT_DEL_ACL,
	HTTP_RES_ACT_DEL_MAP,
	HTTP_RES_ACT_SET_MAP,
	HTTP_RES_ACT_REDIR,

	/* tcp actions */
	TCP_ACT_ACCEPT,
	TCP_ACT_REJECT,
	TCP_ACT_EXPECT_PX,
	TCP_ACT_TRK_SC0, /* TCP request tracking : must be contiguous and cover up to MAX_SESS_STKCTR values */
	TCP_ACT_TRK_SC1,
	TCP_ACT_TRK_SC2,
	TCP_ACT_TRK_SCMAX = TCP_ACT_TRK_SC0 + MAX_SESS_STKCTR - 1,
	TCP_ACT_CLOSE, /* close at the sender's */
	TCP_ACT_CAPTURE, /* capture a fetched sample */
};

struct act_rule {
	struct list list;
	struct acl_cond *cond;                 /* acl condition to meet */
	enum act_name action;                  /* ACT_ACTION_* */
	enum act_from from;                    /* ACT_F_* */
	short deny_status;                     /* HTTP status to return to user when denying */
	int (*action_ptr)(struct act_rule *rule, struct proxy *px,
	                  struct session *sess, struct stream *s); /* ptr to custom action */
	union {
		struct {
			char *realm;
		} auth;                        /* arg used by "auth" */
		struct {
			char *name;            /* header name */
			int name_len;          /* header name's length */
			struct list fmt;       /* log-format compatible expression */
			struct my_regex re;    /* used by replace-header and replace-value */
		} hdr_add;                     /* args used by "add-header" and "set-header" */
		struct redirect_rule *redir;   /* redirect rule or "http-request redirect" */
		int nice;                      /* nice value for HTTP_REQ_ACT_SET_NICE */
		int loglevel;                  /* log-level value for HTTP_REQ_ACT_SET_LOGL */
		int tos;                       /* tos value for HTTP_REQ_ACT_SET_TOS */
		int mark;                      /* nfmark value for HTTP_REQ_ACT_SET_MARK */
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
			struct sample_expr *expr;
			int idx;
		} capid;
		struct hlua_rule *hlua_rule;
		struct {
			struct sample_expr *expr;
			const char *name;
			enum vars_scope scope;
		} vars;
		struct track_ctr_prm trk_ctr;
		struct {
			void *p[4];
		} act;                         /* generic pointers to be used by custom actions */
	} arg;                                 /* arguments used by some actions */
};

#endif /* _TYPES_ACTION_H */
