/*
 * include/haproxy/dns.h
 * This file provides functions related to DNS protocol
 *
 * Copyright (C) 2020 HAProxy Technologies
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

#ifndef _HAPROXY_DNS_H
#define _HAPROXY_DNS_H

#include <haproxy/dns-t.h>
#include <haproxy/server-t.h>

int dns_send_nameserver(struct dns_nameserver *ns, enum dns_server_type type, void *buf, size_t len);
ssize_t dns_recv_nameserver(struct dns_nameserver *ns, enum dns_server_type type, void *data, size_t size);
int dns_dgram_init(struct dns_nameserver *ns, struct sockaddr_storage *sk);
int dns_stream_init(struct dns_nameserver *ns, struct server *s);
void dns_nameserver_deinit(struct dns_nameserver *ns);

/* Returns nonzero if <type> selects a datagram server. */
static inline int dns_server_type_is_dgram(enum dns_server_type type)
{
	return type == DNS_SERVER_DGRAM;
}

/* Returns nonzero if <type> selects a stream server. */
static inline int dns_server_type_is_stream(enum dns_server_type type)
{
	return type == DNS_SERVER_STREAM;
}

#endif // _HAPROXY_DNS_H
