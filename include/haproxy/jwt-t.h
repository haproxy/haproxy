/*
 * include/haproxy/jwt-t.h
 * Macros, variables and structures for JWT management.
 *
 * Copyright (C) 2021 HAProxy Technologies, Remi Tricot-Le Breton <rlebreton@haproxy.com>
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

#ifndef _HAPROXY_JWT_T_H
#define _HAPROXY_JWT_T_H

#include <import/ebmbtree.h>
#include <haproxy/openssl-compat.h>

#ifdef USE_OPENSSL
enum jwt_alg {
	JWT_ALG_DEFAULT,
	JWS_ALG_NONE,
	JWS_ALG_HS256,
	JWS_ALG_HS384,
	JWS_ALG_HS512,
	JWS_ALG_RS256,
	JWS_ALG_RS384,
	JWS_ALG_RS512,
	JWS_ALG_ES256,
	JWS_ALG_ES384,
	JWS_ALG_ES512,
	JWS_ALG_PS256,
	JWS_ALG_PS384,
	JWS_ALG_PS512,
};

struct jwt_item {
	char *start;
	size_t length;
};

struct jwt_ctx {
	enum jwt_alg alg;
	struct jwt_item jose;
	struct jwt_item claims;
	struct jwt_item signature;
	char *key;
	unsigned int key_length;
};

enum jwt_elt {
	JWT_ELT_JOSE = 0,
	JWT_ELT_CLAIMS,
	JWT_ELT_SIG,
	JWT_ELT_MAX
};

struct jwt_cert_tree_entry {
	EVP_PKEY *pkey;
	struct ebmb_node node;
	char path[VAR_ARRAY];
};

enum jwt_vrfy_status {
	JWT_VRFY_KO = 0,
	JWT_VRFY_OK = 1,

	JWT_VRFY_UNKNOWN_ALG   = -1,
	JWT_VRFY_UNMANAGED_ALG = -2,
	JWT_VRFY_INVALID_TOKEN = -3,
	JWT_VRFY_OUT_OF_MEMORY = -4,
	JWT_VRFY_UNKNOWN_CERT  = -5
};

#endif /* USE_OPENSSL */


#endif /* _HAPROXY_JWT_T_H */
