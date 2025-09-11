/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _HAPROXY_JWK_H_
#define _HAPROXY_JWK_H_

#include <haproxy/openssl-compat.h>
#include <haproxy/jwt-t.h>

size_t bn2base64url(const BIGNUM *bn, char *dst, size_t dsize);
size_t EVP_PKEY_to_pub_jwk(EVP_PKEY *pkey, char *dst, size_t dsize);
enum jwt_alg EVP_PKEY_to_jws_alg(EVP_PKEY *pkey);
size_t jws_b64_payload(char *payload, char *dst, size_t dsize);
size_t jws_b64_protected(enum jwt_alg alg, char *kid, char *jwk, char *nonce, char *url, char *dst, size_t dsize);
size_t jws_b64_signature(EVP_PKEY *pkey, enum jwt_alg alg, char *b64protected, char *b64payload, char *dst, size_t dsize);
size_t jws_flattened(char *protected, char *payload, char *signature, char *dst, size_t dsize);
size_t jws_thumbprint(EVP_PKEY *pkey, char *dst, size_t dsize);

#endif /* ! _HAPROXY_JWK_H_ */
