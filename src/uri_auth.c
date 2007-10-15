/*
 * URI-based user authentication using the HTTP basic method.
 *
 * Copyright 2006-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>
#include <string.h>

#include <common/base64.h>
#include <common/config.h>
#include <common/uri_auth.h>


/*
 * Initializes a basic uri_auth structure header and returns a pointer to it.
 * Uses the pointer provided if not NULL and not initialized.
 */
struct uri_auth *stats_check_init_uri_auth(struct uri_auth **root)
{
	struct uri_auth *u;

	if (!root || !*root) {
		if ((u = (struct uri_auth *)calloc(1, sizeof (*u))) == NULL)
			goto out_u;
	} else
		u = *root;

	if (!u->uri_prefix) {
		u->uri_len = strlen(STATS_DEFAULT_URI);
		if ((u->uri_prefix = strdup(STATS_DEFAULT_URI)) == NULL)
			goto out_uri;
	}

	if (!u->auth_realm)
		if ((u->auth_realm = strdup(STATS_DEFAULT_REALM)) == NULL)
			goto out_realm;

	if (root && !*root)
		*root = u;

	return u;

 out_realm:
	free(u->uri_prefix);
 out_uri:
	if (!root || !*root)
		free(u);
 out_u:
	return NULL;
}

/*
 * Returns a default uri_auth with <uri> set as the uri_prefix.
 * Uses the pointer provided if not NULL and not initialized.
 */
struct uri_auth *stats_set_uri(struct uri_auth **root, char *uri)
{
	struct uri_auth *u;
	char *uri_copy;
	int uri_len;

	uri_len  = strlen(uri);
	if ((uri_copy = strdup(uri)) == NULL)
		goto out_uri;
	
	if ((u = stats_check_init_uri_auth(root)) == NULL)
		goto out_u;
	
	if (u->uri_prefix)
		free(u->uri_prefix);

	u->uri_len = uri_len;
	u->uri_prefix = uri_copy;
	return u;

 out_u:
	free(uri_copy);
 out_uri:
	return NULL;
}

/*
 * Returns a default uri_auth with <realm> set as the realm.
 * Uses the pointer provided if not NULL and not initialized.
 */
struct uri_auth *stats_set_realm(struct uri_auth **root, char *realm)
{
	struct uri_auth *u;
	char *realm_copy;

	if ((realm_copy = strdup(realm)) == NULL)
		goto out_realm;
	
	if ((u = stats_check_init_uri_auth(root)) == NULL)
		goto out_u;
	
	if (u->auth_realm)
		free(u->auth_realm);

	u->auth_realm = realm_copy;
	return u;

 out_u:
	free(realm_copy);
 out_realm:
	return NULL;
}

/*
 * Returns a default uri_auth with the <refresh> refresh interval.
 * Uses the pointer provided if not NULL and not initialized.
 */
struct uri_auth *stats_set_refresh(struct uri_auth **root, int interval)
{
	struct uri_auth *u;
	
	if ((u = stats_check_init_uri_auth(root)) != NULL)
		u->refresh = interval;
	return u;
}

/*
 * Returns a default uri_auth with the <flag> set.
 * Uses the pointer provided if not NULL and not initialized.
 */
struct uri_auth *stats_set_flag(struct uri_auth **root, int flag)
{
	struct uri_auth *u;
	
	if ((u = stats_check_init_uri_auth(root)) != NULL)
		u->flags |= flag;
	return u;
}

/*
 * Returns a default uri_auth with a <user:passwd> entry added to the list of
 * authorized users. If a matching entry is found, no update will be performed.
 * Uses the pointer provided if not NULL and not initialized.
 */
struct uri_auth *stats_add_auth(struct uri_auth **root, char *auth)
{
	struct uri_auth *u;
	char *auth_base64;
	int alen, blen;
	struct user_auth *users, **ulist;

	alen = strlen(auth);
	blen = ((alen + 2) / 3) * 4;

	if ((auth_base64 = (char *)calloc(1, blen + 1)) == NULL)
		goto out_ubase64;

	/* convert user:passwd to base64. It should return exactly blen */
	if (a2base64(auth, alen, auth_base64, blen + 1) != blen)
		goto out_base64;

	if ((u = stats_check_init_uri_auth(root)) == NULL)
		goto out_base64;

	ulist = &u->users;
	while ((users = *ulist)) {
		if (!strcmp(users->user_pwd, auth_base64))
			break;
		ulist = &users->next;
	}

	if (!users) {
		if ((users = (struct user_auth *)calloc(1, sizeof(*users))) == NULL)
			goto out_u;
		*ulist = users;
		users->user_pwd = auth_base64;
		users->user_len = blen;
	}
	return u;

 out_u:
	free(u);
 out_base64:
	free(auth_base64);
 out_ubase64:
	return NULL;
}

/*
 * Returns a default uri_auth with a <scope> entry added to the list of
 * allowed scopes. If a matching entry is found, no update will be performed.
 * Uses the pointer provided if not NULL and not initialized.
 */
struct uri_auth *stats_add_scope(struct uri_auth **root, char *scope)
{
	struct uri_auth *u;
	char *new_name;
	struct stat_scope *old_scope, **scope_list;

	if ((u = stats_check_init_uri_auth(root)) == NULL)
		goto out;

	scope_list = &u->scope;
	while ((old_scope = *scope_list)) {
		if (!strcmp(old_scope->px_id, scope))
			break;
		scope_list = &old_scope->next;
	}

	if (!old_scope) {
		if ((new_name = strdup(scope)) == NULL)
			goto out_u;

		if ((old_scope = (struct stat_scope *)calloc(1, sizeof(*old_scope))) == NULL)
			goto out_name;

		old_scope->px_id = new_name;
		old_scope->px_len = strlen(new_name);
		*scope_list = old_scope;
	}
	return u;

 out_name:
	free(new_name);
 out_u:
	free(u);
 out:
	return NULL;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
