/*
 * include/haproxy/ssl_sock.h
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

#ifndef _HAPROXY_SSL_SOCK_H
#define _HAPROXY_SSL_SOCK_H
#ifdef USE_OPENSSL


#include <haproxy/connection.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/pool-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/thread.h>

extern struct list tlskeys_reference;
extern struct eb_root ckchs_tree;
extern struct eb_root crtlists_tree;
extern struct eb_root cafile_tree;
extern int sctl_ex_index;
extern struct global_ssl global_ssl;
extern struct ssl_bind_kw ssl_bind_kws[];
extern struct methodVersions methodVersions[];
__decl_thread(extern HA_SPINLOCK_T ckch_lock);
extern struct pool_head *pool_head_ssl_capture;
extern int ssl_app_data_index;
#ifdef USE_QUIC
extern int ssl_qc_app_data_index;
#endif /* USE_QUIC */
extern unsigned int openssl_engines_initialized;
extern int nb_engines;
extern struct xprt_ops ssl_sock;
extern int ssl_capture_ptr_index;
extern int ssl_keylog_index;
extern int ssl_client_sni_index;
extern struct pool_head *pool_head_ssl_keylog;
extern struct pool_head *pool_head_ssl_keylog_str;

int ssl_sock_prep_ctx_and_inst(struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf,
			       SSL_CTX *ctx, struct ckch_inst *ckch_inst, char **err);
int ssl_sock_prep_srv_ctx_and_inst(const struct server *srv, SSL_CTX *ctx,
				   struct ckch_inst *ckch_inst);
int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf);
int ssl_sock_prepare_bind_conf(struct bind_conf *bind_conf);
void ssl_sock_destroy_bind_conf(struct bind_conf *bind_conf);
int ssl_sock_prepare_srv_ctx(struct server *srv);
void ssl_sock_free_srv_ctx(struct server *srv);
void ssl_sock_free_all_ctx(struct bind_conf *bind_conf);
int ssl_sock_get_alpn(const struct connection *conn, void *xprt_ctx,
                      const char **str, int *len);
int ssl_sock_load_ca(struct bind_conf *bind_conf);
void ssl_sock_free_ca(struct bind_conf *bind_conf);
int ssl_bio_and_sess_init(struct connection *conn, SSL_CTX *ssl_ctx,
                          SSL **ssl, BIO **bio, BIO_METHOD *bio_meth, void *ctx);
const char *ssl_sock_get_sni(struct connection *conn);
const char *ssl_sock_get_cert_sig(struct connection *conn);
const char *ssl_sock_get_cipher_name(struct connection *conn);
const char *ssl_sock_get_proto_version(struct connection *conn);
int ssl_sock_parse_alpn(char *arg, char **alpn_str, int *alpn_len, char **err);
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
#ifdef HAVE_SSL_CLIENT_HELLO_CB
int ssl_sock_switchctx_err_cbk(SSL *ssl, int *al, void *priv);
#ifdef OPENSSL_IS_BORINGSSL
int ssl_sock_switchctx_cbk(const struct ssl_early_callback_ctx *ctx);
#else
int ssl_sock_switchctx_cbk(SSL *ssl, int *al, void *arg);
#endif
#endif

SSL_CTX *ssl_sock_create_cert(struct connection *conn, const char *servername, unsigned int key);
SSL_CTX *ssl_sock_assign_generated_cert(unsigned int key, struct bind_conf *bind_conf, SSL *ssl);
SSL_CTX *ssl_sock_get_generated_cert(unsigned int key, struct bind_conf *bind_conf);
int ssl_sock_set_generated_cert(SSL_CTX *ctx, unsigned int key, struct bind_conf *bind_conf);
unsigned int ssl_sock_generated_cert_key(const void *data, size_t len);
void ssl_sock_load_cert_sni(struct ckch_inst *ckch_inst, struct bind_conf *bind_conf);
#ifdef SSL_MODE_ASYNC
void ssl_async_fd_handler(int fd);
void ssl_async_fd_free(int fd);
#endif
struct issuer_chain* ssl_get0_issuer_chain(X509 *cert);
int ssl_load_global_issuer_from_BIO(BIO *in, char *fp, char **err);
int ssl_sock_load_cert(char *path, struct bind_conf *bind_conf, char **err);
int ssl_sock_load_srv_cert(char *path, struct server *server, int create_if_none, char **err);
void ssl_free_global_issuers(void);
int ssl_initialize_random(void);
int ssl_sock_load_cert_list_file(char *file, int dir, struct bind_conf *bind_conf, struct proxy *curproxy, char **err);
int ssl_init_single_engine(const char *engine_id, const char *def_algorithms);
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) && !defined OPENSSL_IS_BORINGSSL)
int ssl_get_ocspresponse_detail(unsigned char *ocsp_certid, struct buffer *out);
int ssl_ocsp_response_print(struct buffer *ocsp_response, struct buffer *out);
#endif

/* ssl shctx macro */

#define sh_ssl_sess_tree_delete(s)     ebmb_delete(&(s)->key);

#define sh_ssl_sess_tree_insert(s)     (struct sh_ssl_sess_hdr *)ebmb_insert(sh_ssl_sess_tree, \
                                                                    &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define sh_ssl_sess_tree_lookup(k)     (struct sh_ssl_sess_hdr *)ebmb_lookup(sh_ssl_sess_tree, \
                                                                    (k), SSL_MAX_SSL_SESSION_ID_LENGTH);

/* Registers the function <func> in order to be called on SSL/TLS protocol
 * message processing.
 */
int ssl_sock_register_msg_callback(ssl_sock_msg_callback_func func);

SSL *ssl_sock_get_ssl_object(struct connection *conn);


#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
