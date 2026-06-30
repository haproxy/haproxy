/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _HAPROXY_FIPS_H
#define _HAPROXY_FIPS_H

#ifdef USE_OPENSSL
#include <haproxy/obj_type-t.h>
#include <haproxy/openssl-compat.h>

#if defined(OPENSSL_IS_AWSLC)
int ssl_fips_check_ciphers(SSL_CTX *ctx, const enum obj_type *obj);
int ssl_fips_check_ciphersuites(const char *ciphersuites, const enum obj_type *obj);
int ssl_fips_check_version(int min_ver, const enum obj_type *obj);
#endif

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_FIPS_H */
