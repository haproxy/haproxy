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
int userlist_postinit();
void userlist_free(struct userlist *ul);
struct pattern *pat_match_auth(struct sample *smp, struct pattern_expr *expr, int fill);
int check_user(struct userlist *ul, const char *user, const char *pass);
int check_group(struct userlist *ul, char *name);

#endif /* _PROTO_AUTH_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */

