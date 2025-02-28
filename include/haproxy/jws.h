/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _HAPROXY_JWK_H_
#define _HAPROXY_JWK_H_

int bn2base64url(const BIGNUM *bn, char *dst, size_t dsize);
int EVP_PKEY_to_pub_jwk(EVP_PKEY *pkey, char *dst, size_t dsize);

#endif /* ! _HAPROXY_JWK_H_ */
