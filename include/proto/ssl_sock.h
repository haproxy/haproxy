/*
 * include/proto/ssl_sock.h
 * This file contains definition for ssl stream socket operations
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _PROTO_SSL_SOCK_H
#define _PROTO_SSL_SOCK_H
#include <openssl/ssl.h>

#include <types/connection.h>
#include <types/listener.h>
#include <types/proxy.h>
#include <types/stream_interface.h>

extern struct xprt_ops ssl_sock;
int ssl_sock_handshake(struct connection *conn, unsigned int flag);
int ssl_sock_prepare_ctx(struct bind_conf *bind_conf, SSL_CTX *ctx, struct proxy *proxy);
void ssl_sock_free_certs(struct bind_conf *bind_conf);
int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf, struct proxy *px);
int ssl_sock_prepare_srv_ctx(struct server *srv, struct proxy *px);
void ssl_sock_free_all_ctx(struct bind_conf *bind_conf);
const char *ssl_sock_get_cipher_name(struct connection *conn);
const char *ssl_sock_get_proto_version(struct connection *conn);

#endif /* _PROTO_SSL_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
