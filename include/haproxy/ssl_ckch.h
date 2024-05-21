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

int ssl_sock_load_files_into_ckch(const char *path, struct ckch_data *data, char **err);
int ssl_sock_load_pem_into_ckch(const char *path, char *buf, struct ckch_data *datackch , char **err);
void ssl_sock_free_cert_key_and_chain_contents(struct ckch_data *data);

int ssl_sock_load_key_into_ckch(const char *path, char *buf, struct ckch_data *data , char **err);
int ssl_sock_load_ocsp_response_from_file(const char *ocsp_path, char *buf, struct ckch_data *data, char **err);
int ssl_sock_load_sctl_from_file(const char *sctl_path, char *buf, struct ckch_data *data, char **err);
int ssl_sock_load_issuer_file_into_ckch(const char *path, char *buf, struct ckch_data *data, char **err);

/* ckch_store functions */
struct ckch_store *ckch_store_new_load_files_path(char *path, char **err);
struct ckch_store *ckch_store_new_load_files_conf(char *name, struct ckch_conf *conf, char **err);
struct ckch_store *ckchs_lookup(char *path);
struct ckch_store *ckchs_dup(const struct ckch_store *src);
struct ckch_store *ckch_store_new(const char *filename);
void ckch_store_free(struct ckch_store *store);
void ckch_store_replace(struct ckch_store *old_ckchs, struct ckch_store *new_ckchs);
int ckch_store_load_files(struct ckch_conf *f, struct ckch_store *c, int cli, char **err);

/* ckch_conf functions */

int ckch_conf_parse(char **args, int cur_arg, struct ckch_conf *f, int *found, const char *file, int linenum, char **err);
void ckch_conf_clean(struct ckch_conf *conf);
int ckch_conf_cmp(struct ckch_conf *conf1, struct ckch_conf *conf2, char **err);
int ckch_conf_cmp_empty(struct ckch_conf *prev, char **err);

/* ckch_inst functions */
void ckch_inst_free(struct ckch_inst *inst);
struct ckch_inst *ckch_inst_new();
int ckch_inst_new_load_store(const char *path, struct ckch_store *ckchs, struct bind_conf *bind_conf,
                             struct ssl_bind_conf *ssl_conf, char **sni_filter, int fcount, int is_default, struct ckch_inst **ckchi, char **err);
int ckch_inst_new_load_srv_store(const char *path, struct ckch_store *ckchs,
                                 struct ckch_inst **ckchi, char **err);
int ckch_inst_rebuild(struct ckch_store *ckch_store, struct ckch_inst *ckchi,
                      struct ckch_inst **new_inst, char **err);

void ckch_deinit();
void ckch_inst_add_cafile_link(struct ckch_inst *ckch_inst, struct bind_conf *bind_conf,
			       struct ssl_bind_conf *ssl_conf, const struct server *srv);

/* ssl_store functions */
struct cafile_entry *ssl_store_get_cafile_entry(char *path, int oldest_entry);
X509_STORE* ssl_store_get0_locations_file(char *path);
int ssl_store_add_uncommitted_cafile_entry(struct cafile_entry *entry);
struct cafile_entry *ssl_store_create_cafile_entry(char *path, X509_STORE *store, enum cafile_type type);
struct cafile_entry *ssl_store_dup_cafile_entry(struct cafile_entry *src);
void ssl_store_delete_cafile_entry(struct cafile_entry *ca_e);
int ssl_store_load_ca_from_buf(struct cafile_entry *ca_e, char *cert_buf, int append);
int ssl_store_load_locations_file(char *path, int create_if_none, enum cafile_type type);
int __ssl_store_load_locations_file(char *path, int create_if_none, enum cafile_type type, int shuterror);

extern struct cert_exts cert_exts[];
extern int (*ssl_commit_crlfile_cb)(const char *path, X509_STORE *ctx, char **err);

/* ckch_conf keyword loading */
static inline int ckch_conf_load_pem(void *value, char *buf, struct ckch_data *d, int cli, char **err) { if (cli) return 0; return ssl_sock_load_pem_into_ckch(value, buf, d, err); }
static inline int ckch_conf_load_key(void *value, char *buf, struct ckch_data *d, int cli, char **err) { if (cli) return 0; return ssl_sock_load_key_into_ckch(value, buf, d, err); }
static inline int ckch_conf_load_ocsp_response(void *value, char *buf, struct ckch_data *d, int cli, char **err) { if (cli) return 0; return ssl_sock_load_ocsp_response_from_file(value, buf, d, err); }
static inline int ckch_conf_load_ocsp_issuer(void *value, char *buf, struct ckch_data *d, int cli, char **err) { if (cli) return 0; return ssl_sock_load_issuer_file_into_ckch(value, buf, d, err); }
static inline int ckch_conf_load_sctl(void *value, char *buf, struct ckch_data *d, int cli, char **err) { if (cli) return 0; return ssl_sock_load_sctl_from_file(value, buf, d, err); }

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_CRTLIST_H */
