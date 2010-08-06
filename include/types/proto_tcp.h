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
#include <types/session.h>

/* Layer4 accept/reject rules */
enum {
	TCP_ACT_ACCEPT = 1,
	TCP_ACT_REJECT = 2,
	TCP_ACT_TRK_SC1 = 3,
	TCP_ACT_TRK_SC2 = 4,
};

struct tcp_rule {
	struct list list;
	struct acl_cond *cond;
	int action;
	union {
		struct track_ctr_prm trk_ctr;
	} act_prm;
};

#endif /* _TYPES_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
