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

struct capture_prm {
	struct sample_expr *expr;               /* expression used as the key */
	struct cap_hdr *hdr;                    /* the capture storage */
};

struct act_rule {
	struct list list;
	struct acl_cond *cond;                 /* acl condition to meet */
	unsigned int action;                   /* HTTP_REQ_* */
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
		struct hlua_rule *hlua_rule;
		struct {
			void *p[4];
		} act;                         /* generic pointers to be used by custom actions */
	} arg;                                 /* arguments used by some actions */

	union {
		struct capture_prm cap;
		struct track_ctr_prm trk_ctr;
	} act_prm;
};

#endif /* _TYPES_ACTION_H */
