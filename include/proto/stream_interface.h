/*
 * include/proto/stream_interface.h
 * This file contains stream_interface function prototypes
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_STREAM_INTERFACE_H
#define _PROTO_STREAM_INTERFACE_H

#include <stdlib.h>

#include <common/config.h>
#include <types/stream_interface.h>


/* main event functions used to move data between sockets and buffers */
int stream_int_check_timeouts(struct stream_interface *si);
void stream_int_report_error(struct stream_interface *si);
void stream_int_retnclose(struct stream_interface *si, const struct chunk *msg);

/* functions used when running a stream interface as a task */
void stream_int_update(struct stream_interface *si);
void stream_int_update_embedded(struct stream_interface *si);
void stream_int_shutr(struct stream_interface *si);
void stream_int_shutw(struct stream_interface *si);
void stream_int_chk_rcv(struct stream_interface *si);
void stream_int_chk_snd(struct stream_interface *si);

struct task *stream_int_register_handler(struct stream_interface *si,
					 struct si_applet *app);
struct task *stream_int_register_handler_task(struct stream_interface *si,
					      struct task *(*fct)(struct task *));
void stream_int_unregister_handler(struct stream_interface *si);

static inline void clear_target(struct target *dest)
{
	dest->type = TARG_TYPE_NONE;
	dest->ptr.v = NULL;
}

static inline void set_target_server(struct target *dest, struct server *s)
{
	dest->type = TARG_TYPE_SERVER;
	dest->ptr.s = s;
}

static inline void set_target_proxy(struct target *dest, struct proxy *p)
{
	dest->type = TARG_TYPE_PROXY;
	dest->ptr.p = p;
}

static inline void set_target_applet(struct target *dest, struct si_applet *a)
{
	dest->type = TARG_TYPE_APPLET;
	dest->ptr.a = a;
}

static inline void set_target_task(struct target *dest, struct task *t)
{
	dest->type = TARG_TYPE_TASK;
	dest->ptr.t = t;
}

static inline struct target *copy_target(struct target *dest, struct target *src)
{
	*dest = *src;
	return dest;
}

static inline int target_match(struct target *a, struct target *b)
{
	return a->type == b->type && a->ptr.v == b->ptr.v;
}

static inline struct server *target_srv(struct target *t)
{
	if (!t || t->type != TARG_TYPE_SERVER)
		return NULL;
	return t->ptr.s;
}

#endif /* _PROTO_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
