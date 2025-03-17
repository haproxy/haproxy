/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _HAPROXY_JWK_H_
#define _HAPROXY_JWK_H_

#include <haproxy/openssl-compat.h>

int bn2base64url(const BIGNUM *bn, char *dst, size_t dsize);
int EVP_PKEY_to_pub_jwk(EVP_PKEY *pkey, char *dst, size_t dsize);

int jws_b64_payload(char *payload, char *dst, size_t dsize);
int jws_b64_protected(const char *alg, char *kid, char *jwk, char *nonce, char *url, char *dst, size_t dsize);
int jws_b64_signature(EVP_PKEY *pkey, char *b64protected, char *b64payload, char *dst, size_t dsize);
int jws_flattened(char *protected, char *payload, char *signature, char *dst, size_t dsize);

#endif /* ! _HAPROXY_JWK_H_ */
