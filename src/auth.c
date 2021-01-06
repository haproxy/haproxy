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

#ifdef USE_LIBCRYPT
/* This is to have crypt() defined on Linux */
#define _GNU_SOURCE

#ifdef USE_CRYPT_H
/* some platforms such as Solaris need this */
#include <crypt.h>
#endif
#endif /* USE_LIBCRYPT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <haproxy/api.h>
#include <haproxy/auth-t.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/pattern-t.h>
#include <haproxy/sample-t.h>
#include <haproxy/thread.h>

struct userlist *userlist = NULL;    /* list of all existing userlists */

#ifdef USE_LIBCRYPT
#define CRYPT_STATE_MSG "yes"
#ifdef HA_HAVE_CRYPT_R
/* context for crypt_r() */
static THREAD_LOCAL struct crypt_data crypt_data = { .initialized = 0 };
#else
/* lock for crypt() */
__decl_thread(static HA_SPINLOCK_T auth_lock);
#endif
#else /* USE_LIBCRYPT */
#define CRYPT_STATE_MSG "no"
#endif

/* find targets for selected groups. The function returns pointer to
 * the userlist struct or NULL if name is NULL/empty or unresolvable.
 */

struct userlist *
auth_find_userlist(char *name)
{
	struct userlist *l;

	if (!name || !*name)
		return NULL;

	for (l = userlist; l; l = l->next)
		if (strcmp(l->name, name) == 0)
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
					if (strcmp(ag->name, group) == 0)
						break;
				}

				if (!ag) {
					ha_alert("userlist '%s': no such group '%s' specified in user '%s'\n",
						 curuserlist->name, group, curuser->user);
					free(groups);
					return ERR_ALERT | ERR_FATAL;
				}

				/* Add this group at the group userlist. */
				grl = calloc(1, sizeof(*grl));
				if (!grl) {
					ha_alert("userlist '%s': no more memory when trying to allocate the user groups.\n",
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
					if (strcmp(curuser->user, user) == 0)
						break;
				}

				if (!curuser) {
					ha_alert("userlist '%s': no such user '%s' specified in group '%s'\n",
						 curuserlist->name, user, ag->name);
					return ERR_ALERT | ERR_FATAL;
				}

				/* Add this group at the group userlist. */
				grl = calloc(1, sizeof(*grl));
				if (!grl) {
					ha_alert("userlist '%s': no more memory when trying to allocate the user groups.\n",
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
#ifdef DEBUG_AUTH
	struct auth_groups_list *agl;
#endif
	const char *ep;

#ifdef DEBUG_AUTH
	fprintf(stderr, "req: userlist=%s, user=%s, pass=%s\n",
	        ul->name, user, pass);
#endif

	for (u = ul->users; u; u = u->next)
		if (strcmp(user, u->user) == 0)
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
#ifdef USE_LIBCRYPT
#ifdef HA_HAVE_CRYPT_R
		ep = crypt_r(pass, u->pass, &crypt_data);
#else
		HA_SPIN_LOCK(AUTH_LOCK, &auth_lock);
		ep = crypt(pass, u->pass);
		HA_SPIN_UNLOCK(AUTH_LOCK, &auth_lock);
#endif
#else
		return 0;
#endif
	} else
		ep = pass;

#ifdef DEBUG_AUTH
	fprintf(stderr, ", crypt=%s\n", ep);
#endif

	if (ep && strcmp(ep, u->pass) == 0)
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
		if (strcmp(smp->data.u.str.area, u->user) == 0)
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

REGISTER_BUILD_OPTS("Encrypted password support via crypt(3): "CRYPT_STATE_MSG);
