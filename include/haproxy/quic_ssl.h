/*
 * include/haproxy/quic_ssl.h
 * This file contains QUIC over TLS/SSL api definitions.
 *
 * Copyright (C) 2023
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
#ifndef _HAPROXY_QUIC_SSL_H
#define _HAPROXY_QUIC_SSL_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/listener-t.h>
#include <haproxy/ncbuf-t.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/pool.h>
#include <haproxy/quic_ssl-t.h>
#include <haproxy/ssl_sock-t.h>

int ssl_quic_initial_ctx(struct bind_conf *bind_conf);
int qc_alloc_ssl_sock_ctx(struct quic_conn *qc);
int qc_ssl_provide_all_quic_data(struct quic_conn *qc, struct ssl_sock_ctx *ctx);

static inline void qc_free_ssl_sock_ctx(struct ssl_sock_ctx **ctx)
{
	if (!*ctx)
		return;

	SSL_free((*ctx)->ssl);
	pool_free(pool_head_quic_ssl_sock_ctx, *ctx);
	*ctx = NULL;
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SSL_H */
