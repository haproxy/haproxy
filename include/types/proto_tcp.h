/*
 * include/types/proto_tcp.h
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

#ifndef _TYPES_PROTO_TCP_H
#define _TYPES_PROTO_TCP_H

#include <common/config.h>
#include <common/mini-clist.h>

#include <types/acl.h>
#include <types/stream.h>

/* Layer4 accept/reject rules */
enum {
	TCP_ACT_ACCEPT = 1,
	TCP_ACT_REJECT = 2,
	TCP_ACT_EXPECT_PX = 3,
	TCP_ACT_TRK_SC0 = 4, /* TCP request tracking : must be contiguous and cover up to MAX_SESS_STKCTR values */
	TCP_ACT_TRK_SC1 = 5,
	TCP_ACT_TRK_SC2 = 6,
	TCP_ACT_TRK_SCMAX = TCP_ACT_TRK_SC0 + MAX_SESS_STKCTR - 1,
	TCP_ACT_CLOSE, /* close at the sender's */
	TCP_ACT_CAPTURE, /* capture a fetched sample */
	TCP_ACT_CUSTOM, /* Use for custom registered keywords. */
	TCP_ACT_CUSTOM_CONT, /* Use for custom registered keywords. */
};

struct capture_prm {
	struct sample_expr *expr;               /* expression used as the key */
	struct cap_hdr *hdr;                    /* the capture storage */
};

struct tcp_rule {
	struct list list;
	struct acl_cond *cond;
	int action;
	int (*action_ptr)(struct tcp_rule *rule, struct proxy *px,
	                  struct stream *s);
	union {
		struct track_ctr_prm trk_ctr;
		struct capture_prm cap;
		void *data[4];
	} act_prm;
};

struct tcp_action_kw {
	const char *kw;
	int (*parse)(const char **args, int *cur_arg, struct proxy *px,
	             struct tcp_rule *rule, char **err);
	int match_pfx;
};

struct tcp_action_kw_list {
	const char *scope;
	struct list list;
	struct tcp_action_kw kw[VAR_ARRAY];
};

#endif /* _TYPES_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
