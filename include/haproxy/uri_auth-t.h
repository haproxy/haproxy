/*
 * include/haproxy/uri_auth-t.h
 * Definitions for URI-based user authentication using the HTTP basic method.
 *
 * Copyright 2006-2020 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_URI_AUTH_T_H
#define _HAPROXY_URI_AUTH_T_H

#include <haproxy/acl-t.h>
#include <haproxy/auth-t.h>

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
	uint refcount;                  /* to free when unused */
	char *uri_prefix;		/* the prefix we want to match */
	char *auth_realm;		/* the realm reported to the client */
	char *node, *desc;		/* node name & description reported in this stats */
	int refresh;			/* refresh interval for the browser (in seconds) */
	unsigned int flags;		/* STAT_* flags from stats.h and for applet.ctx.stats.flags */
	struct stat_scope *scope;	/* linked list of authorized proxies */
	struct userlist *userlist;	/* private userlist to emulate legacy "stats auth user:password" */
	struct list http_req_rules;	/* stats http-request rules : allow/deny/auth */
	struct list admin_rules;	/* 'stats admin' rules (chained) */
	struct uri_auth *next;		/* Used at deinit() to build a list of unique elements */
};

struct stats_admin_rule {
	struct list list;	/* list linked to from the proxy */
	struct acl_cond *cond;	/* acl condition to meet */
};

#endif /* _HAPROXY_URI_AUTH_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
