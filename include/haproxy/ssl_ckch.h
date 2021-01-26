/*
 * include/haproxy/ssl_ckch.h
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

#ifndef _HAPROXY_SSL_CKCH_H
#define _HAPROXY_SSL_CKCH_H
#ifdef USE_OPENSSL

#include <haproxy/ssl_ckch-t.h>

/* cert_key_and_chain functions */

int ssl_sock_load_files_into_ckch(const char *path, struct cert_key_and_chain *ckch, char **err);
int ssl_sock_load_pem_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch , char **err);
void ssl_sock_free_cert_key_and_chain_contents(struct cert_key_and_chain *ckch);

int ssl_sock_load_key_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch , char **err);
int ssl_sock_load_ocsp_response_from_file(const char *ocsp_path, char *buf, struct cert_key_and_chain *ckch, char **err);
int ssl_sock_load_sctl_from_file(const char *sctl_path, char *buf, struct cert_key_and_chain *ckch, char **err);
int ssl_sock_load_issuer_file_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch, char **err);

/* ckch_store functions */
struct ckch_store *ckchs_load_cert_file(char *path, char **err);
struct ckch_store *ckchs_lookup(char *path);
struct ckch_store *ckchs_dup(const struct ckch_store *src);
struct ckch_store *ckch_store_new(const char *filename);
void ckch_store_free(struct ckch_store *store);


/* ckch_inst functions */
void ckch_inst_free(struct ckch_inst *inst);
struct ckch_inst *ckch_inst_new();
int ckch_inst_new_load_store(const char *path, struct ckch_store *ckchs, struct bind_conf *bind_conf,
                             struct ssl_bind_conf *ssl_conf, char **sni_filter, int fcount, struct ckch_inst **ckchi, char **err);
int ckch_inst_new_load_srv_store(const char *path, struct ckch_store *ckchs,
                                 struct ckch_inst **ckchi, char **err);

void ckch_deinit();

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_CRTLIST_H */
