/*
 * User authentication & authorization.
 *
 * Copyright 2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _PROTO_AUTH_H
#define _PROTO_AUTH_H

#include <common/config.h>
#include <types/auth.h>

extern struct userlist *userlist;

struct userlist *auth_find_userlist(char *name);
unsigned int auth_resolve_groups(struct userlist *l, char *groups);
struct req_acl_rule *parse_auth_cond(const char **args, const char *file, int linenum, struct proxy *proxy);
void userlist_free(struct userlist *ul);
void req_acl_free(struct list *r);
int acl_match_auth(struct acl_test *test, struct acl_pattern *pattern);

#endif /* _PROTO_AUTH_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */

