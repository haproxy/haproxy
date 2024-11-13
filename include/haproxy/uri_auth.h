/*
 * include/haproxy/uri_auth.h
 * Functions for URI-based user authentication using the HTTP basic method.
 *
 * Copyright 2006-2020 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_URI_AUTH_H
#define _HAPROXY_URI_AUTH_H

#include <haproxy/api.h>
#include <haproxy/uri_auth-t.h>

/* Various functions used to set the fields during the configuration parsing.
 * Please that all those function can initialize the root entry in order not to
 * force the user to respect a certain order in the configuration file.
 *
 * Default values are used during initialization. Check STATS_DEFAULT_* for
 * more information.
 */
struct uri_auth *stats_check_init_uri_auth(struct uri_auth **root);
struct uri_auth *stats_set_uri(struct uri_auth **root, char *uri);
struct uri_auth *stats_set_realm(struct uri_auth **root, char *realm);
struct uri_auth *stats_set_refresh(struct uri_auth **root, int interval);
struct uri_auth *stats_set_flag(struct uri_auth **root, int flag);
struct uri_auth *stats_add_auth(struct uri_auth **root, char *user);
struct uri_auth *stats_add_scope(struct uri_auth **root, char *scope);
struct uri_auth *stats_set_node(struct uri_auth **root, char *name);
struct uri_auth *stats_set_desc(struct uri_auth **root, char *desc);
void stats_uri_auth_free(struct uri_auth *uri_auth);
void stats_uri_auth_take(struct uri_auth *uri_auth);
void stats_uri_auth_drop(struct uri_auth *uri_auth);

#endif /* _HAPROXY_URI_AUTH_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
