/*
 * include/haproxy/ssl_utils.h
 *
 * Utility functions for SSL:
 * Mostly generic functions that retrieve information from certificates
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2020 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
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

#ifndef _HAPROXY_SSL_UTILS_H
#define _HAPROXY_SSL_UTILS_H

#ifdef USE_OPENSSL

#include <haproxy/buf-t.h>
#include <haproxy/openssl-compat.h>

int cert_get_pkey_algo(X509 *crt, struct buffer *out);
int ssl_sock_get_serial(X509 *crt, struct buffer *out);
int ssl_sock_crt2der(X509 *crt, struct buffer *out);
int ssl_sock_get_time(ASN1_TIME *tm, struct buffer *out);
int ssl_sock_get_dn_entry(X509_NAME *a, const struct buffer *entry, int pos,
                          struct buffer *out);
int ssl_sock_get_dn_formatted(X509_NAME *a, const struct buffer *format, struct buffer *out);
int ssl_sock_get_dn_oneline(X509_NAME *a, struct buffer *out);
X509* ssl_sock_get_peer_certificate(SSL *ssl);
X509* ssl_sock_get_verified_chain_root(SSL *ssl);
unsigned int openssl_version_parser(const char *version);
void exclude_tls_grease(char *input, int len, struct buffer *output);
int x509_v_err_str_to_int(const char *str);
const char *x509_v_err_int_to_str(int code);
long asn1_generalizedtime_to_epoch(ASN1_GENERALIZEDTIME *d);
const char *x509_get_notbefore(X509 *cert);
const char *x509_get_notafter(X509 *cert);
#ifdef HAVE_ASN1_TIME_TO_TM
time_t ASN1_to_time_t(ASN1_TIME *asn1_time);
time_t x509_get_notafter_time_t(X509 *cert);
#endif

#endif /* _HAPROXY_SSL_UTILS_H */
#endif /* USE_OPENSSL */

