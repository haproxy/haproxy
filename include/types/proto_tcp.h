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

#include <types/action.h>
#include <types/acl.h>
#include <types/stream.h>

struct tcp_action_kw {
	const char *kw;
	int (*parse)(const char **args, int *cur_arg, struct proxy *px,
	             struct act_rule *rule, char **err);
	int match_pfx;
};

struct tcp_action_kw_list {
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
