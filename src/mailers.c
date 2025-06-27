/*
 * Mailer management.
 *
 * Copyright 2015 Horms Solutions Ltd, Simon Horman <horms@verge.net.au>
 * Copyright 2020 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>

#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/mailers.h>
#include <haproxy/proxy.h>
#include <haproxy/server-t.h>
#include <haproxy/task.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

int mailers_used_from_lua = 0;

struct mailers *mailers = NULL;

/* Initializes mailer alerts for the proxy <p> using <mls> parameters.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int init_email_alert(struct mailers *mls, struct proxy *p, char **err)
{
	mls->users++;
	free(p->email_alert.mailers.name);
	p->email_alert.mailers.m = mls;
	p->email_alert.flags |= PR_EMAIL_ALERT_RESOLVED;
	return 0;
}

void free_email_alert(struct proxy *p)
{
	if (!(p->email_alert.flags & PR_EMAIL_ALERT_RESOLVED))
		ha_free(&p->email_alert.mailers.name);
	ha_free(&p->email_alert.from);
	ha_free(&p->email_alert.to);
	ha_free(&p->email_alert.myhostname);
}

static int mailers_post_check(void)
{
	struct mailers *cur;

	for (cur = mailers; cur != NULL; cur = cur->next) {
		if (cur->users && !mailers_used_from_lua) {
			ha_warning("mailers '%s' is referenced on at least one proxy but Lua "
			           "mailers are not configured so the setting will be ignored. "
			           "Use 'examples/lua/mailers.lua' file for basic mailers support.\n", cur->id);
			return ERR_WARN;
		}
	}
	return ERR_NONE;
}
REGISTER_POST_CHECK(mailers_post_check);
