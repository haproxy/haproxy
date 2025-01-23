/*
 * include/haproxy/ssl_gencert.h
 * This file contains definition for ssl 'generate-certificates' option.
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

#ifndef _HAPROXY_SSL_GENCERT_H
#define _HAPROXY_SSL_GENCERT_H
#ifdef USE_OPENSSL

#include <haproxy/listener-t.h>
#include <haproxy/ssl_sock-t.h>

int ssl_sock_generate_certificate(const char *servername, struct bind_conf *bind_conf, SSL *ssl);
int ssl_sock_generate_certificate_from_conn(struct bind_conf *bind_conf, SSL *ssl);
SSL_CTX *ssl_sock_assign_generated_cert(unsigned int key, struct bind_conf *bind_conf, SSL *ssl);
SSL_CTX *ssl_sock_get_generated_cert(unsigned int key, struct bind_conf *bind_conf);
int ssl_sock_set_generated_cert(SSL_CTX *ctx, unsigned int key, struct bind_conf *bind_conf);
unsigned int ssl_sock_generated_cert_key(const void *data, size_t len);
int ssl_sock_gencert_load_ca(struct bind_conf *bind_conf);
void ssl_sock_gencert_free_ca(struct bind_conf *bind_conf);

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_GENCERT_H */
