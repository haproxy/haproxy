/*
 * include/proto/ssl_ckch.h
 * ckch function prototypes
 *
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

#ifndef _PROTO_SSL_CKCH_H
#define _PROTO_SSL_CKCH_H
#ifdef USE_OPENSSL

#include <types/ssl_ckch.h>

/* ckch_store functions */
struct ckch_store *ckchs_load_cert_file(char *path, int multi, char **err);
struct ckch_store *ckchs_lookup(char *path);

/* ckch_inst functions */
void ckch_inst_free(struct ckch_inst *inst);
struct ckch_inst *ckch_inst_new();


#endif /* USE_OPENSSL */
#endif /* _PROTO_SSL_CRTLIST_H */
