/*
 * URI-based user authentication using the HTTP basic method.
 *
 * Copyright 2006 Willy Tarreau <willy@w.ods.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef URI_AUTH_H
#define URI_AUTH_H
/* here we find a very basic list of base64-encoded 'user:passwd' strings */
struct user_auth {
	struct user_auth *next;		/* next entry, NULL if none */
	int user_len;			/* user:passwd length */
	char *user_pwd;			/* auth as base64("user":"passwd") (see RFC2617) */
};

/* This is a list of proxies we are allowed to see. Later, it should go in the
 * user list, but before this we need to support de/re-authentication.
 */
struct stat_scope {
	struct stat_scope *next;	/* next entry, NULL if none */
	int px_len;			/* proxy name length */
	char *px_id;			/* proxy id */
};

/* later we may link them to support multiple URI matching */
struct uri_auth {
	int uri_len;			/* the prefix length */
	char *uri_prefix;		/* the prefix we want to match */
	char *auth_realm;		/* the realm reported to the client */
	struct user_auth *users;	/* linked list of valid user:passwd couples */
	struct stat_scope *scope;	/* linked list of authorized proxies */
};

/* This is the default statistics URI */
#ifdef CONFIG_STATS_DEFAULT_URI
#define STATS_DEFAULT_URI CONFIG_STATS_DEFAULT_URI
#else
#define STATS_DEFAULT_URI "/haproxy?stats"
#endif

/* This is the default statistics realm */
#ifdef CONFIG_STATS_DEFAULT_REALM
#define STATS_DEFAULT_REALM CONFIG_STATS_DEFAULT_REALM
#else
#define STATS_DEFAULT_REALM "HAProxy Statistics"
#endif


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
struct uri_auth *stats_add_auth(struct uri_auth **root, char *user);
struct uri_auth *stats_add_scope(struct uri_auth **root, char *scope);

#endif /* URI_AUTH_H */
