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
extern int sslconns;
extern int totalsslconns;

/* boolean, returns true if connection is over SSL */
static inline
int ssl_sock_is_ssl(struct connection *conn)
{
	if (!conn || conn->xprt != &ssl_sock || !conn->xprt_ctx)
		return 0;
	else
		return 1;
}

int ssl_sock_handshake(struct connection *conn, unsigned int flag);
int ssl_sock_prepare_ctx(struct bind_conf *bind_conf, SSL_CTX *ctx, struct proxy *proxy);
int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf, struct proxy *px);
int ssl_sock_prepare_srv_ctx(struct server *srv, struct proxy *px);
void ssl_sock_free_all_ctx(struct bind_conf *bind_conf);
int ssl_sock_load_ca(struct bind_conf *bind_conf, struct proxy *px);
void ssl_sock_free_ca(struct bind_conf *bind_conf);
const char *ssl_sock_get_cipher_name(struct connection *conn);
const char *ssl_sock_get_proto_version(struct connection *conn);
char *ssl_sock_get_version(struct connection *conn);
void ssl_sock_set_servername(struct connection *conn, const char *hostname);
int ssl_sock_get_cert_used_sess(struct connection *conn);
int ssl_sock_get_cert_used_conn(struct connection *conn);
int ssl_sock_get_remote_common_name(struct connection *conn, struct chunk *out);
unsigned int ssl_sock_get_verify_result(struct connection *conn);
#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
int ssl_sock_update_ocsp_response(struct chunk *ocsp_response, char **err);
#endif
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
int ssl_sock_update_tlskey(char *filename, struct chunk *tlskey, char **err);
struct tls_keys_ref *tlskeys_ref_lookup(const char *filename);
struct tls_keys_ref *tlskeys_ref_lookupid(int unique_id);
void tlskeys_finalize_config(void);
#endif
#ifndef OPENSSL_NO_DH
int ssl_sock_load_global_dh_param_from_file(const char *filename);
#endif

SSL_CTX *ssl_sock_create_cert(const char *servername, unsigned int serial, X509 *cacert, EVP_PKEY *capkey);
SSL_CTX *ssl_sock_get_generated_cert(unsigned int serial, X509 *cacert);
void ssl_sock_set_generated_cert(SSL_CTX *ctx, unsigned int serial, X509 *cacert);
unsigned int ssl_sock_generated_cert_serial(const void *data, size_t len);

#endif /* _PROTO_SSL_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
