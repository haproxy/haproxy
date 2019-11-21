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
#ifdef USE_OPENSSL

#include <common/openssl-compat.h>

#include <types/connection.h>
#include <types/listener.h>
#include <types/proxy.h>
#include <types/stream_interface.h>

#include <proto/connection.h>

extern int sslconns;
extern int totalsslconns;

/* boolean, returns true if connection is over SSL */
static inline
int ssl_sock_is_ssl(struct connection *conn)
{
	if (!conn || conn->xprt != xprt_get(XPRT_SSL) || !conn->xprt_ctx)
		return 0;
	else
		return 1;
}

int ssl_sock_prepare_ctx(struct bind_conf *bind_conf, struct ssl_bind_conf *, SSL_CTX *ctx, char **err);
int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf);
int ssl_sock_prepare_bind_conf(struct bind_conf *bind_conf);
int ssl_sock_prepare_srv_ctx(struct server *srv);
void ssl_sock_free_srv_ctx(struct server *srv);
void ssl_sock_free_all_ctx(struct bind_conf *bind_conf);
int ssl_sock_load_ca(struct bind_conf *bind_conf);
void ssl_sock_free_ca(struct bind_conf *bind_conf);
const char *ssl_sock_get_sni(struct connection *conn);
const char *ssl_sock_get_cert_sig(struct connection *conn);
const char *ssl_sock_get_cipher_name(struct connection *conn);
const char *ssl_sock_get_proto_version(struct connection *conn);
void ssl_sock_set_alpn(struct connection *conn, const unsigned char *, int);
void ssl_sock_set_servername(struct connection *conn, const char *hostname);

int ssl_sock_get_cert_used_sess(struct connection *conn);
int ssl_sock_get_cert_used_conn(struct connection *conn);
int ssl_sock_get_remote_common_name(struct connection *conn,
				    struct buffer *out);
int ssl_sock_get_pkey_algo(struct connection *conn, struct buffer *out);
unsigned int ssl_sock_get_verify_result(struct connection *conn);
#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
int ssl_sock_update_ocsp_response(struct buffer *ocsp_response, char **err);
#endif
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
int ssl_sock_update_tlskey_ref(struct tls_keys_ref *ref,
				struct buffer *tlskey);
int ssl_sock_update_tlskey(char *filename, struct buffer *tlskey, char **err);
struct tls_keys_ref *tlskeys_ref_lookup(const char *filename);
struct tls_keys_ref *tlskeys_ref_lookupid(int unique_id);
#endif
#ifndef OPENSSL_NO_DH
int ssl_sock_load_global_dh_param_from_file(const char *filename);
void ssl_free_dh(void);
#endif
void ssl_free_engines(void);

SSL_CTX *ssl_sock_create_cert(struct connection *conn, const char *servername, unsigned int key);
SSL_CTX *ssl_sock_assign_generated_cert(unsigned int key, struct bind_conf *bind_conf, SSL *ssl);
SSL_CTX *ssl_sock_get_generated_cert(unsigned int key, struct bind_conf *bind_conf);
int ssl_sock_set_generated_cert(SSL_CTX *ctx, unsigned int key, struct bind_conf *bind_conf);
unsigned int ssl_sock_generated_cert_key(const void *data, size_t len);

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC) && !defined(LIBRESSL_VERSION_NUMBER)
void ssl_async_fd_handler(int fd);
void ssl_async_fd_free(int fd);
#endif

/* ssl shctx macro */

#define sh_ssl_sess_tree_delete(s)     ebmb_delete(&(s)->key);

#define sh_ssl_sess_tree_insert(s)     (struct sh_ssl_sess_hdr *)ebmb_insert(sh_ssl_sess_tree, \
                                                                    &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define sh_ssl_sess_tree_lookup(k)     (struct sh_ssl_sess_hdr *)ebmb_lookup(sh_ssl_sess_tree, \
                                                                    (k), SSL_MAX_SSL_SESSION_ID_LENGTH);
#endif /* USE_OPENSSL */
#endif /* _PROTO_SSL_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
