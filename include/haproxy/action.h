/*
 * include/haproxy/action.h
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

#ifndef _HAPROXY_ACTION_H
#define _HAPROXY_ACTION_H

#include <stdio.h>
#include <haproxy/action-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/list.h>
#include <haproxy/sample.h>

struct resolv_requester;
struct dns_counters;

int act_resolution_cb(struct resolv_requester *requester, struct dns_counters *counters);
int act_resolution_error_cb(struct resolv_requester *requester, int error_code);
const char *action_suggest(const char *word, const struct list *keywords, const char **extra);
void free_act_rule(struct act_rule *rule);

static inline struct action_kw *action_lookup(struct list *keywords, const char *kw)
{
	struct action_kw_list *kw_list;
	struct action_kw *best = NULL;
	int len, bestlen = 0;
	int i;

	if (LIST_ISEMPTY(keywords))
		return NULL;

	list_for_each_entry(kw_list, keywords, list) {
		for (i = 0; kw_list->kw[i].kw != NULL; i++) {
			if ((kw_list->kw[i].flags & KWF_MATCH_PREFIX) &&
			    (len = strlen(kw_list->kw[i].kw)) > bestlen &&
			    strncmp(kw, kw_list->kw[i].kw, len) == 0) {
				if (len > bestlen) {
					bestlen = len;
					best = &kw_list->kw[i];
				}
			}
			if (strcmp(kw, kw_list->kw[i].kw) == 0)
				return &kw_list->kw[i];
		}
	}
	return best;
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
			l = snprintf(p, end - p, "'%s%s', ", kw_list->kw[i].kw, (kw_list->kw[i].flags & KWF_MATCH_PREFIX) ? "(*)" : "");
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

/* Check an action ruleset validity. It returns the number of error encountered
 * and err_code is updated if a warning is emitted.
 */
int check_action_rules(struct list *rules, struct proxy *px, int *err_code);

/* Find and check the target table used by an action track-sc*. This
 * function should be called during the configuration validity check.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_trk_action(struct act_rule *rule, struct proxy *px, char **err);

/* check a capture rule. This function should be called during the configuration
 * validity check.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_capture(struct act_rule *rule, struct proxy *px, char **err);

int cfg_parse_rule_set_timeout(const char **args, int idx, struct act_rule *rule,
			       struct proxy *px, char **err);

static inline void release_timeout_action(struct act_rule *rule)
{
	release_sample_expr(rule->arg.timeout.expr);
}

/*
 * Release expr_int rule argument when action is no longer used
 */
static inline void release_expr_int_action(struct act_rule *rule)
{
	release_sample_expr(rule->arg.expr_int.expr);
}

struct act_rule *new_act_rule(enum act_from from, const char *file, int linenum);
void free_act_rules(struct list *rules);
void dump_act_rules(const struct list *rules, const char *pfx);

#endif /* _HAPROXY_ACTION_H */
