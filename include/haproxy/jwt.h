/*
 * include/haproxy/jwt.h
 * Functions for JSON Web Token (JWT) management.
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

#ifndef _HAPROXY_JWT_H
#define _HAPROXY_JWT_H

#include <haproxy/jwt-t.h>
#include <haproxy/buf-t.h>

#ifdef USE_OPENSSL
enum jwt_alg jwt_parse_alg(const char *alg_str, unsigned int alg_len);
int jwt_tokenize(const struct buffer *jwt, struct jwt_item *items, unsigned int *item_num);
int jwt_tree_load_cert(char *path, int pathlen, char **err);

enum jwt_vrfy_status jwt_verify(const struct buffer *token, const struct buffer *alg,
				const struct buffer *key);
#endif /* USE_OPENSSL */

#endif /* _HAPROXY_JWT_H */
