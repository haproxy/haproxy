/*
 * User authentication & authorization
 *
 * Copyright 2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifdef CONFIG_HAP_CRYPT
/* This is to have crypt() defined on Linux */
#define _GNU_SOURCE

#ifdef NEED_CRYPT_H
/* some platforms such as Solaris need this */
#include <crypt.h>
#endif
#endif /* CONFIG_HAP_CRYPT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <common/config.h>

#include <proto/acl.h>
#include <proto/log.h>

#include <types/auth.h>

struct userlist *userlist = NULL;    /* list of all existing userlists */

/* find targets for selected gropus. The function returns pointer to
 * the userlist struct ot NULL if name is NULL/empty or unresolvable.
 */

struct userlist *
auth_find_userlist(char *name)
{
	struct userlist *l;

	if (!name || !*name)
		return NULL;

	for (l = userlist; l; l = l->next)
		if (!strcmp(l->name, name))
			return l;

	return NULL;
}

/* find group_mask for selected gropus. The function returns 1 if OK or nothing to do,
 * 0 if case of unresolved groupname.
 * WARING: the function destroys the list (strtok), so it can only be used once.
 */

unsigned int
auth_resolve_groups(struct userlist *l, char *groups)
{

	char *group = NULL;
	unsigned int g, group_mask = 0;

	if (!groups || !*groups)
		return 0;

	while ((group = strtok(group?NULL:groups," "))) {
		for (g = 0; g < l->grpcnt; g++)
			if (!strcmp(l->groups[g], group))
				break;

		if (g == l->grpcnt) {
			Alert("No such group '%s' in userlist '%s'.\n",
				group, l->name);
			return 0;
		}

		group_mask |= (1 << g);
	}

	return group_mask;
}

void
userlist_free(struct userlist *ul)
{
	struct userlist *tul;
	struct auth_users *au, *tau;
	int i;

	while (ul) {
		au = ul->users;
		while (au) {
			tau = au;
			au = au->next;
			free(tau->user);
			free(tau->pass);
			free(tau);
		}

		tul = ul;
		ul = ul->next;

		for (i = 0; i < tul->grpcnt; i++)
			free(tul->groups[i]);

		free(tul->name);
		free(tul);
	};
}

/*
 * Authenticate and authorize user; return 1 if OK, 0 if case of error.
 */
int
check_user(struct userlist *ul, unsigned int group_mask, const char *user, const char *pass)
{

	struct auth_users *u;
	const char *ep;

#ifdef DEBUG_AUTH
	fprintf(stderr, "req: userlist=%s, user=%s, pass=%s, group_mask=%u\n",
		ul->name, user, pass, group_mask);
#endif

	for (u = ul->users; u; u = u->next)
		if (!strcmp(user, u->user))
			break;

	if (!u)
		return 0;

#ifdef DEBUG_AUTH
	fprintf(stderr, "cfg: user=%s, pass=%s, group_mask=%u, flags=%X",
		u->user, u->pass, u->group_mask, u->flags);
#endif

	/*
	 * if user matches but group does not,
	 * it makes no sens to check passwords
	 */
	if (group_mask && !(group_mask & u->u.group_mask))
		return 0;

	if (!(u->flags & AU_O_INSECURE)) {
#ifdef CONFIG_HAP_CRYPT
		ep = crypt(pass, u->pass);
#else
		return 0;
#endif
	} else
		ep = pass;

#ifdef DEBUG_AUTH
	fprintf(stderr, ", crypt=%s\n", ep);
#endif

	if (!strcmp(ep, u->pass))
		return 1;
	else
		return 0;
}

int
acl_match_auth(struct acl_test *test, struct acl_pattern *pattern)
{

	struct userlist *ul = test->ctx.a[0];
	char *user = test->ctx.a[1];
	char *pass = test->ctx.a[2];
	unsigned int group_mask = pattern->val.group_mask;

	if (check_user(ul, group_mask, user, pass))
		return ACL_PAT_PASS;
	else
		return ACL_PAT_FAIL;
}
