/*
 * include/proto/protocol.h
 * This file declares generic protocol management primitives.
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

#ifndef _PROTO_PROTOCOL_H
#define _PROTO_PROTOCOL_H

#include <sys/socket.h>
#include <common/hathreads.h>
#include <types/protocol.h>

extern struct protocol *__protocol_by_family[AF_CUST_MAX];
__decl_hathreads(extern HA_SPINLOCK_T proto_lock);

/* Registers the protocol <proto> */
void protocol_register(struct protocol *proto);

/* Unregisters the protocol <proto>. Note that all listeners must have
 * previously been unbound.
 */
void protocol_unregister(struct protocol *proto);

/* binds all listeners of all registered protocols. Returns a composition
 * of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_bind_all(char *errmsg, int errlen);

/* unbinds all listeners of all registered protocols. They are also closed.
 * This must be performed before calling exit() in order to get a chance to
 * remove file-system based sockets and pipes.
 * Returns a composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_unbind_all(void);

/* enables all listeners of all registered protocols. This is intended to be
 * used after a fork() to enable reading on all file descriptors. Returns a
 * composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_enable_all(void);

/* returns the protocol associated to family <family> or NULL if not found */
static inline struct protocol *protocol_by_family(int family)
{
	if (family >= 0 && family < AF_CUST_MAX)
		return __protocol_by_family[family];
	return NULL;
}

#endif /* _PROTO_PROTOCOL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
