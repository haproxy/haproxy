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

#define _XOPEN_SOURCE 500

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

struct req_acl_rule *
parse_auth_cond(const char **args, const char *file, int linenum, struct list *known_acl, int *acl_requires)
{
	struct req_acl_rule *req_acl;
	int cur_arg;

	req_acl = (struct req_acl_rule*)calloc(1, sizeof(struct req_acl_rule));
	if (!req_acl) {
		Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		return NULL;
	}

	if (!*args[0]) {
		goto req_error_parsing;
	} else if (!strcmp(args[0], "allow")) {
		req_acl->action = PR_REQ_ACL_ACT_ALLOW;
		cur_arg = 1;
	} else if (!strcmp(args[0], "deny")) {
		req_acl->action = PR_REQ_ACL_ACT_DENY;
		cur_arg = 1;
	} else if (!strcmp(args[0], "auth")) {
		req_acl->action = PR_REQ_ACL_ACT_HTTP_AUTH;
		cur_arg = 1;

		while(*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "realm")) {
				req_acl->http_auth.realm = strdup(args[cur_arg + 1]);
				cur_arg+=2;
				continue;
			} else
				break;
		}
	} else {
req_error_parsing:
		Alert("parsing [%s:%d]: %s '%s', expects 'allow', 'deny', 'auth'.\n",
			file, linenum, *args[1]?"unknown parameter":"missing keyword in", args[*args[1]?1:0]);
		return NULL;
	}

	if (*args[cur_arg]) {
		int pol = ACL_COND_NONE;
		struct acl_cond *cond;

		if (!strcmp(args[cur_arg], "if"))
			pol = ACL_COND_IF;
		else if (!strcmp(args[cur_arg], "unless"))
			pol = ACL_COND_UNLESS;
		else {
			Alert("parsing [%s:%d]: '%s' expects 'realm' for 'auth' or"
			      " either 'if' or 'unless' followed by a condition but found '%s'.\n",
			      file, linenum, args[0], args[cur_arg]);
			return NULL;
		}

		if ((cond = parse_acl_cond((const char **)args + cur_arg + 1, known_acl, pol)) == NULL) {
			Alert("parsing [%s:%d]: error detected while parsing 'req' condition.\n",
			      file, linenum);
			return NULL;
		}

		cond->file = file;
		cond->line = linenum;
		*acl_requires |= cond->requires;
		req_acl->cond = cond;
	}

	return req_acl;
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

void
req_acl_free(struct list *r) {
	struct req_acl_rule *tr, *pr;

	list_for_each_entry_safe(pr, tr, r, list) {
		LIST_DEL(&pr->list);
		if (pr->action == PR_REQ_ACL_ACT_HTTP_AUTH)
			free(pr->http_auth.realm);

		free(pr);
	}
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
	if (group_mask && !(group_mask & u->group_mask))
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
