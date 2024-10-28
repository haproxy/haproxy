/*
 * include/haproxy/sock_unix.h
 * This file contains declarations for AF_UNIX sockets.
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

#ifndef _HAPROXY_SOCK_UNIX_H
#define _HAPROXY_SOCK_UNIX_H

#include <sys/socket.h>
#include <sys/types.h>

#include <haproxy/api.h>
#include <haproxy/receiver-t.h>

extern struct proto_fam proto_fam_unix;
extern struct proto_fam proto_fam_abns;
extern struct proto_fam proto_fam_abnsz;

int sock_unix_addrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
int sock_abns_addrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
int sock_abnsz_addrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
int sock_unix_bind_receiver(struct receiver *rx, char **errmsg);

#endif /* _HAPROXY_SOCK_UNIX_H */
