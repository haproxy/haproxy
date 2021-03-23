/*
 * include/haproxy/ssl_crtlist.h
 * crt-list function prototypes
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

#ifndef _HAPROXY_SSL_CRTLIST_H
#define _HAPROXY_SSL_CRTLIST_H
#ifdef USE_OPENSSL

#include <haproxy/ssl_crtlist-t.h>


/* crt-list entry functions */
void ssl_sock_free_ssl_conf(struct ssl_bind_conf *conf);
char **crtlist_dup_filters(char **args, int fcount);
void crtlist_free_filters(char **args);
void crtlist_entry_free(struct crtlist_entry *entry);
struct crtlist_entry *crtlist_entry_new();

/* crt-list functions */
void crtlist_free(struct crtlist *crtlist);
struct crtlist *crtlist_new(const char *filename, int unique);

/* file loading */
int crtlist_parse_line(char *line, char **crt_path, struct crtlist_entry *entry, const char *file, int linenum, int from_cli, char **err);
int crtlist_parse_file(char *file, struct bind_conf *bind_conf, struct proxy *curproxy, struct crtlist **crtlist, char **err);
int crtlist_load_cert_dir(char *path, struct bind_conf *bind_conf, struct crtlist **crtlist, char **err);

void crtlist_deinit();

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_CRTLIST_H */
