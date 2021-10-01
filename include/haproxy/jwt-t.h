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
#endif /* USE_OPENSSL */


#endif /* _HAPROXY_JWT_T_H */
