/*
 * include/proto/action.h
 * This file contains actions prototypes.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_ACTION_H
#define _PROTO_ACTION_H

#include <types/action.h>

int act_resolution_cb(struct dns_requester *requester, struct dns_nameserver *nameserver);
int act_resolution_error_cb(struct dns_requester *requester, int error_code);

static inline struct action_kw *action_lookup(struct list *keywords, const char *kw)
{
	struct action_kw_list *kw_list;
	int i;

	if (LIST_ISEMPTY(keywords))
		return NULL;

	list_for_each_entry(kw_list, keywords, list) {
		for (i = 0; kw_list->kw[i].kw != NULL; i++) {
			if (kw_list->kw[i].match_pfx &&
			    strncmp(kw, kw_list->kw[i].kw, strlen(kw_list->kw[i].kw)) == 0)
				return &kw_list->kw[i];
			if (!strcmp(kw, kw_list->kw[i].kw))
				return &kw_list->kw[i];
		}
	}
	return NULL;
}

static inline void action_build_list(struct list *keywords,
				     struct buffer *chk)
{
	struct action_kw_list *kw_list;
	int i;
	char *p;
	char *end;
	int l;

	p = chk->area;
	end = p + chk->size - 1;
	list_for_each_entry(kw_list, keywords, list) {
		for (i = 0; kw_list->kw[i].kw != NULL; i++) {
			l = snprintf(p, end - p, "'%s%s', ", kw_list->kw[i].kw, kw_list->kw[i].match_pfx ? "(*)" : "");
			if (l > end - p)
				continue;
			p += l;
		}
	}
	if (p > chk->area)
		*(p-2) = '\0';
	else
		*p = '\0';
}

/* for an action ACT_ACTION_TRK_SC*, return a tracking index starting at zero
 * for SC0. Unknown actions also return zero.
 */
static inline int trk_idx(int trk_action)
{
	return trk_action - ACT_ACTION_TRK_SC0;
}

/* Find and check the target table used by an action ACT_ACTION_TRK_*. This
 * function should be called during the configuration validity check.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_trk_action(struct act_rule *rule, struct proxy *px, char **err);

#endif /* _PROTO_ACTION_H */
