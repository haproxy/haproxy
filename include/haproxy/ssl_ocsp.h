/*
 * include/haproxy/ssl_ocsp.h
 * This file contains definition for ssl OCSP operations
 *
 * Copyright (C) 2022 Remi Tricot-Le Breton - rlebreton@haproxy.com
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

#ifndef _HAPROXY_SSL_OCSP_H
#define _HAPROXY_SSL_OCSP_H
#ifdef USE_OPENSSL

#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_ckch-t.h>
#include <haproxy/ssl_crtlist-t.h>
#include <haproxy/ssl_ocsp-t.h>

#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)

int ssl_ocsp_build_response_key(OCSP_CERTID *ocsp_cid, unsigned char certid[OCSP_MAX_CERTID_ASN1_LENGTH], unsigned int *key_length);

int ssl_sock_get_ocsp_arg_kt_index(int evp_keytype);
int ssl_sock_ocsp_stapling_cbk(SSL *ssl, void *arg);

void ssl_sock_free_ocsp(struct certificate_ocsp *ocsp);
void ssl_sock_free_ocsp_instance(struct certificate_ocsp *ocsp);

int ssl_sock_load_ocsp_response(struct buffer *ocsp_response,
                                struct certificate_ocsp *ocsp,
                                OCSP_CERTID *cid, char **err);
int ssl_sock_update_ocsp_response(struct buffer *ocsp_response, char **err);
void ssl_sock_ocsp_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);

int ssl_ocsp_get_uri_from_cert(X509 *cert, struct buffer *out, char **err);
int ssl_ocsp_create_request_details(const OCSP_CERTID *certid, struct buffer *req_url,
                                    struct buffer *req_body, char **err);
int ssl_ocsp_check_response(STACK_OF(X509) *chain, X509 *issuer,
                            struct buffer *respbuf, char **err);

int ssl_create_ocsp_update_task(char **err);
void ssl_destroy_ocsp_update_task(void);

int ssl_ocsp_update_insert(struct certificate_ocsp *ocsp);

int ocsp_update_init(void *value, char *buf, struct ckch_data *d, int cli, char **err);

#endif /* (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) */

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_OCSP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
