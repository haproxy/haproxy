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
#include <common/errors.h>

#include <proto/acl.h>
#include <proto/log.h>

#include <types/auth.h>
#include <types/pattern.h>

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

int check_group(struct userlist *ul, char *name)
{
	struct auth_groups *ag;

	for (ag = ul->groups; ag; ag = ag->next)
		if (strcmp(name, ag->name) == 0)
			return 1;
	return 0;
}

void
userlist_free(struct userlist *ul)
{
	struct userlist *tul;
	struct auth_users *au, *tau;
	struct auth_groups_list *agl, *tagl;
	struct auth_groups *ag, *tag;

	while (ul) {
		/* Free users. */
		au = ul->users;
		while (au) {
			/* Free groups that own current user. */
			agl = au->u.groups;
			while (agl) {
				tagl = agl;
				agl = agl->next;
				free(tagl);
			}

			tau = au;
			au = au->next;
			free(tau->user);
			free(tau->pass);
			free(tau);
		}

		/* Free grouplist. */
		ag = ul->groups;
		while (ag) {
			tag = ag;
			ag = ag->next;
			free(tag->name);
			free(tag);
		}

		tul = ul;
		ul = ul->next;
		free(tul->name);
		free(tul);
	};
}

int userlist_postinit()
{
	struct userlist *curuserlist = NULL;

	/* Resolve usernames and groupnames. */
	for (curuserlist = userlist; curuserlist; curuserlist = curuserlist->next) {
		struct auth_groups *ag;
		struct auth_users *curuser;
		struct auth_groups_list *grl;

		for (curuser = curuserlist->users; curuser; curuser = curuser->next) {
			char *group = NULL;
			struct auth_groups_list *groups = NULL;

			if (!curuser->u.groups_names)
				continue;

			while ((group = strtok(group?NULL:curuser->u.groups_names, ","))) {
				for (ag = curuserlist->groups; ag; ag = ag->next) {
					if (!strcmp(ag->name, group))
						break;
				}

				if (!ag) {
					Alert("userlist '%s': no such group '%s' specified in user '%s'\n",
					      curuserlist->name, group, curuser->user);
					free(groups);
					return ERR_ALERT | ERR_FATAL;
				}

				/* Add this group at the group userlist. */
				grl = calloc(1, sizeof(*grl));
				if (!grl) {
					Alert("userlist '%s': no more memory when trying to allocate the user groups.\n",
					      curuserlist->name);
					free(groups);
					return ERR_ALERT | ERR_FATAL;
				}

				grl->group = ag;
				grl->next = groups;
				groups = grl;
			}

			free(curuser->u.groups);
			curuser->u.groups = groups;
		}

		for (ag = curuserlist->groups; ag; ag = ag->next) {
			char *user = NULL;

			if (!ag->groupusers)
				continue;

			while ((user = strtok(user?NULL:ag->groupusers, ","))) {
				for (curuser = curuserlist->users; curuser; curuser = curuser->next) {
					if (!strcmp(curuser->user, user))
						break;
				}

				if (!curuser) {
					Alert("userlist '%s': no such user '%s' specified in group '%s'\n",
					      curuserlist->name, user, ag->name);
					return ERR_ALERT | ERR_FATAL;
				}

				/* Add this group at the group userlist. */
				grl = calloc(1, sizeof(*grl));
				if (!grl) {
					Alert("userlist '%s': no more memory when trying to allocate the user groups.\n",
					      curuserlist->name);
					return  ERR_ALERT | ERR_FATAL;
				}

				grl->group = ag;
				grl->next = curuser->u.groups;
				curuser->u.groups = grl;
			}

			free(ag->groupusers);
			ag->groupusers = NULL;
		}

#ifdef DEBUG_AUTH
		for (ag = curuserlist->groups; ag; ag = ag->next) {
			struct auth_groups_list *agl;

			fprintf(stderr, "group %s, id %p, users:", ag->name, ag);
			for (curuser = curuserlist->users; curuser; curuser = curuser->next) {
				for (agl = curuser->u.groups; agl; agl = agl->next) {
					if (agl->group == ag)
						fprintf(stderr, " %s", curuser->user);
				}
			}
			fprintf(stderr, "\n");
		}
#endif
	}

	return ERR_NONE;
}

/*
 * Authenticate and authorize user; return 1 if OK, 0 if case of error.
 */
int
check_user(struct userlist *ul, const char *user, const char *pass)
{

	struct auth_users *u;
	const char *ep;

#ifdef DEBUG_AUTH
	fprintf(stderr, "req: userlist=%s, user=%s, pass=%s, group=%s\n",
		ul->name, user, pass, group);
#endif

	for (u = ul->users; u; u = u->next)
		if (!strcmp(user, u->user))
			break;

	if (!u)
		return 0;

#ifdef DEBUG_AUTH
	fprintf(stderr, "cfg: user=%s, pass=%s, flags=%X, groups=",
		u->user, u->pass, u->flags);
	for (agl = u->u.groups; agl; agl = agl->next)
		fprintf(stderr, " %s", agl->group->name);
#endif

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

struct pattern *
pat_match_auth(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct userlist *ul = smp->ctx.a[0];
	struct pattern_list *lst;
	struct auth_users *u;
	struct auth_groups_list *agl;
	struct pattern *pattern;

	/* Check if the userlist is present in the context data. */
	if (!ul)
		return NULL;

	/* Browse the userlist for searching user. */
	for (u = ul->users; u; u = u->next) {
		if (strcmp(smp->data.str.str, u->user) == 0)
			break;
	}
	if (!u)
		return NULL;

	/* Browse each pattern. */
	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		/* Browse each group for searching group name that match the pattern. */
		for (agl = u->u.groups; agl; agl = agl->next) {
			if (strcmp(agl->group->name, pattern->ptr.str) == 0)
				return pattern;
		}
	}
	return NULL;
}
