/*
 * JSON Web Token (JWT) processing
 *
 * Copyright 2021 HAProxy Technologies
 * Remi Tricot-Le Breton <rlebreton@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <import/ebmbtree.h>
#include <import/ebsttree.h>

#include <haproxy/api.h>
#include <haproxy/tools.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/base64.h>
#include <haproxy/jwt.h>


#ifdef USE_OPENSSL
/*
 * The possible algorithm strings that can be found in a JWS's JOSE header are
 * defined in section 3.1 of RFC7518.
 */
enum jwt_alg jwt_parse_alg(const char *alg_str, unsigned int alg_len)
{
	enum jwt_alg alg = JWT_ALG_DEFAULT;

	/* Algorithms are all 5 characters long apart from "none". */
	if (alg_len < sizeof("HS256")-1) {
		if (strncmp("none", alg_str, alg_len) == 0)
			alg = JWS_ALG_NONE;
		return alg;
	}

	if (alg == JWT_ALG_DEFAULT) {
		switch(*alg_str++) {
		case 'H':
			if (strncmp(alg_str, "S256", alg_len-1) == 0)
				alg = JWS_ALG_HS256;
			else if (strncmp(alg_str, "S384", alg_len-1) == 0)
				alg = JWS_ALG_HS384;
			else if (strncmp(alg_str, "S512", alg_len-1) == 0)
				alg = JWS_ALG_HS512;
			break;
		case 'R':
			if (strncmp(alg_str, "S256", alg_len-1) == 0)
				alg = JWS_ALG_RS256;
			else if (strncmp(alg_str, "S384", alg_len-1) == 0)
				alg = JWS_ALG_RS384;
			else if (strncmp(alg_str, "S512", alg_len-1) == 0)
				alg = JWS_ALG_RS512;
			break;
		case 'E':
			if (strncmp(alg_str, "S256", alg_len-1) == 0)
				alg = JWS_ALG_ES256;
			else if (strncmp(alg_str, "S384", alg_len-1) == 0)
				alg = JWS_ALG_ES384;
			else if (strncmp(alg_str, "S512", alg_len-1) == 0)
				alg = JWS_ALG_ES512;
			break;
		case 'P':
			if (strncmp(alg_str, "S256", alg_len-1) == 0)
				alg = JWS_ALG_PS256;
			else if (strncmp(alg_str, "S384", alg_len-1) == 0)
				alg = JWS_ALG_PS384;
			else if (strncmp(alg_str, "S512", alg_len-1) == 0)
				alg = JWS_ALG_PS512;
			break;
		default:
			break;
		}
	}

	return alg;
}
#endif /* USE_OPENSSL */
