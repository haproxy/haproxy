/*
 * include/haproxy/sock-t.h
 * This file contains type definitions for native (BSD-compatible) sockets.
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

#ifndef _HAPROXY_SOCK_T_H
#define _HAPROXY_SOCK_T_H

#include <sys/socket.h>
#include <sys/types.h>

#include <haproxy/api-t.h>

#define SOCK_XFER_OPT_FOREIGN 0x000000001
#define SOCK_XFER_OPT_V6ONLY  0x000000002
#define SOCK_XFER_OPT_DGRAM   0x000000004

/* The list used to transfer sockets between old and new processes */
struct xfer_sock_list {
	int fd;
	int options; /* socket options as SOCK_XFER_OPT_* */
	char *iface;
	char *namespace;
	int if_namelen;
	int ns_namelen;
	struct xfer_sock_list *prev;
	struct xfer_sock_list *next;
	struct sockaddr_storage addr;
};

#endif /* _HAPROXY_SOCK_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
