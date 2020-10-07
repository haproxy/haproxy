/*
 * include/haproxy/protocol.h
 * This file declares generic protocol management primitives.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_PROTOCOL_H
#define _HAPROXY_PROTOCOL_H

#include <sys/socket.h>
#include <haproxy/protocol-t.h>
#include <haproxy/thread.h>

/* [AF][sock_dgram][ctrl_dgram] */
extern struct protocol *__protocol_by_family[AF_CUST_MAX][2][2];
__decl_thread(extern HA_SPINLOCK_T proto_lock);

/* Registers the protocol <proto> */
void protocol_register(struct protocol *proto);

/* Unregisters the protocol <proto>. Note that all listeners must have
 * previously been unbound.
 */
void protocol_unregister(struct protocol *proto);

/* binds all listeners of all registered protocols. Returns a composition
 * of ERR_NONE, ERR_RETRYABLE, ERR_FATAL, ERR_ABORT.
 */
int protocol_bind_all(int verbose);

/* unbinds all listeners of all registered protocols. They are also closed.
 * This must be performed before calling exit() in order to get a chance to
 * remove file-system based sockets and pipes.
 * Returns a composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_unbind_all(void);

/* stops all listeners of all registered protocols, except when the belong to a
 * proxy configured with a grace time. This will normally catch every single
 * listener, all protocols included, and the grace ones will have to be handled
 * by the proxy stopping loop. This is to be used during soft_stop() only. It
 * does not return any error.
 */
void protocol_stop_now(void);

/* pauses all listeners of all registered protocols. This is typically
 * used on SIG_TTOU to release all listening sockets for the time needed to
 * try to bind a new process. The listeners enter LI_PAUSED. It returns
 * ERR_NONE, with ERR_FATAL on failure.
 */
int protocol_pause_all(void);

/* resumes all listeners of all registered protocols. This is typically used on
 * SIG_TTIN to re-enable listening sockets after a new process failed to bind.
 * The listeners switch to LI_READY/LI_FULL. It returns ERR_NONE, with ERR_FATAL
 * on failure.
 */
int protocol_resume_all(void);

/* enables all listeners of all registered protocols. This is intended to be
 * used after a fork() to enable reading on all file descriptors. Returns a
 * composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_enable_all(void);

/* returns the protocol associated to family <family> with sock_type and
 * ctrl_type of SOCK_STREAM, or NULL if not found
 */
static inline struct protocol *protocol_by_family(int family)
{
	if (family >= 0 && family < AF_CUST_MAX)
		return __protocol_by_family[family][0][0];
	return NULL;
}

/* returns the protocol associated to family <family> with sock_type and
 * ctrl_type of either SOCK_STREAM or SOCK_DGRAM depending on the requested
 * values, or NULL if not found.
 */
static inline struct protocol *protocol_lookup(int family, int sock_dgram, int ctrl_dgram)
{
	if (family >= 0 && family < AF_CUST_MAX)
		return __protocol_by_family[family][!!sock_dgram][!!ctrl_dgram];
	return NULL;
}

#endif /* _HAPROXY_PROTOCOL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
