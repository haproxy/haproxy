/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "include.h"


#define FLT_OT_GROUP_DEF(a,b,c)   { a, b, c },
const struct flt_ot_group_data flt_ot_group_data[] = { FLT_OT_GROUP_DEFINES };
#undef FLT_OT_GROUP_DEF


/***
 * NAME
 *   flt_ot_group_action -
 *
 * ARGUMENTS
 *   rule -
 *   px   -
 *   sess -
 *   s    -
 *   opts -
 *
 * DESCRIPTION
 *   This is the action_ptr callback of a rule associated to the
 *   FLT_OT_ACTION_GROUP action.
 *
 * RETURN VALUE
 *   The function returns ACT_RET_CONT if processing is finished (with error or
 *   not), otherwise, it returns ACT_RET_YIELD if the action is in progress.
 */
static enum act_return flt_ot_group_action(struct act_rule *rule, struct proxy *px, struct session *sess, struct stream *s, int opts)
{
	const struct filter                 *filter;
	const struct flt_conf               *fconf;
	const struct flt_ot_conf            *conf;
	const struct flt_ot_conf_group      *conf_group;
	const struct flt_ot_runtime_context *rt_ctx = NULL;
	const struct flt_ot_conf_ph         *ph_scope;
	char                                *err = NULL;
	int                                  i, rc;

	FLT_OT_FUNC("%p, %p, %p, %p, %d", rule, px, sess, s, opts);

	FLT_OT_DBG(3, "from: %d, arg.act %p:{ %p %p %p %p }", rule->from, &(rule->arg.act), rule->arg.act.p[0], rule->arg.act.p[1], rule->arg.act.p[2], rule->arg.act.p[3]);

	fconf      = rule->arg.act.p[FLT_OT_ARG_FLT_CONF];
	conf       = rule->arg.act.p[FLT_OT_ARG_CONF];
	conf_group = ((const struct flt_ot_conf_ph *)(rule->arg.act.p[FLT_OT_ARG_GROUP]))->ptr;

	if ((fconf == NULL) || (conf == NULL) || (conf_group == NULL)) {
		FLT_OT_LOG(LOG_ERR, FLT_OT_ACTION_GROUP ": internal error, invalid group action");

		FLT_OT_RETURN(ACT_RET_CONT);
	}

	if (conf->tracer->flag_disabled) {
		FLT_OT_DBG(1, "filter '%s' disabled, group action '%s' ignored", conf->id, conf_group->id);

		FLT_OT_RETURN(ACT_RET_CONT);
	}

	/* Find the OpenTracing filter instance from the current stream. */
	list_for_each_entry(filter, &(s->strm_flt.filters), list)
		if (filter->config == fconf) {
			rt_ctx = filter->ctx;

			break;
		}

	if (rt_ctx == NULL) {
		FLT_OT_DBG(1, "cannot find filter, probably not attached to the stream");

		FLT_OT_RETURN(ACT_RET_CONT);
	}
	else if (flt_ot_is_disabled(filter FLT_OT_DBG_ARGS(, -1))) {
		FLT_OT_RETURN(ACT_RET_CONT);
	}
	else {
		FLT_OT_DBG(3, "run group '%s'", conf_group->id);
		FLT_OT_DBG_CONF_GROUP("run group ", conf_group);
	}

	/*
	 * Check the value of rule->from; in case it is incorrect,
	 * report an error.
	 */
	for (i = 0; i < FLT_OT_TABLESIZE(flt_ot_group_data); i++)
		if (flt_ot_group_data[i].act_from == rule->from)
			break;

	if (i >= FLT_OT_TABLESIZE(flt_ot_group_data)) {
		FLT_OT_LOG(LOG_ERR, FLT_OT_ACTION_GROUP ": internal error, invalid rule->from=%d", rule->from);

		FLT_OT_RETURN(ACT_RET_CONT);
	}

	list_for_each_entry(ph_scope, &(conf_group->ph_scopes), list) {
		rc = flt_ot_scope_run(s, rt_ctx->filter, &(s->res), ph_scope->ptr, NULL, SMP_OPT_DIR_RES, &err);
		if ((rc == FLT_OT_RET_ERROR) && (opts & ACT_OPT_FINAL)) {
			/* XXX */
		}
	}

	FLT_OT_RETURN(ACT_RET_CONT);
}


/***
 * NAME
 *   flt_ot_group_check -
 *
 * ARGUMENTS
 *   rule -
 *   px   -
 *   err  -
 *
 * DESCRIPTION
 *   This is the check_ptr callback of a rule associated to the
 *   FLT_OT_ACTION_GROUP action.
 *
 * RETURN VALUE
 *   The function returns 1 in success case, otherwise,
 *   it returns 0 and err is filled.
 */
static int flt_ot_group_check(struct act_rule *rule, struct proxy *px, char **err)
{
	struct flt_conf       *fconf_tmp, *fconf = NULL;
	struct flt_ot_conf    *conf;
	struct flt_ot_conf_ph *ph_group;
	const char            *filter_id;
	const char            *group_id;
	bool                   flag_found = 0;
	int                    i;

	FLT_OT_FUNC("%p, %p, %p:%p", rule, px, FLT_OT_DPTR_ARGS(err));

	filter_id = rule->arg.act.p[FLT_OT_ARG_FILTER_ID];
	group_id  = rule->arg.act.p[FLT_OT_ARG_GROUP_ID];

	FLT_OT_DBG(2, "checking filter_id='%s', group_id='%s'", filter_id, group_id);

	/*
	 * Check the value of rule->from; in case it is incorrect,
	 * report an error.
	 */
	for (i = 0; i < FLT_OT_TABLESIZE(flt_ot_group_data); i++)
		if (flt_ot_group_data[i].act_from == rule->from)
			break;

	if (i >= FLT_OT_TABLESIZE(flt_ot_group_data)) {
		FLT_OT_ERR("internal error, unexpected rule->from=%d, please report this bug!", rule->from);

		FLT_OT_RETURN(0);
	}

	/*
	 * Try to find the OpenTracing filter by checking all filters
	 * for the proxy <px>.
	 */
	list_for_each_entry(fconf_tmp, &(px->filter_configs), list) {
		conf = fconf_tmp->conf;

		if (fconf_tmp->id != ot_flt_id) {
			/* This is not an OpenTracing filter. */
			continue;
		}
		else if (strcmp(conf->id, filter_id) == 0) {
			/* This is the good filter ID. */
			fconf = fconf_tmp;

			break;
		}
	}

	if (fconf == NULL) {
		FLT_OT_ERR("unable to find the OpenTracing filter '%s' used by the " FLT_OT_ACTION_GROUP " '%s'", filter_id, group_id);

		FLT_OT_RETURN(0);
	}

	/*
	 * Attempt to find if the group is defined in the OpenTracing filter
	 * configuration.
	 */
	list_for_each_entry(ph_group, &(conf->tracer->ph_groups), list)
		if (strcmp(ph_group->id, group_id) == 0) {
			flag_found = 1;

			break;
		}

	if (!flag_found) {
		FLT_OT_ERR("unable to find group '%s' in the OpenTracing filter '%s' configuration", group_id, filter_id);

		FLT_OT_RETURN(0);
	}

	FLT_OT_FREE_CLEAR(rule->arg.act.p[FLT_OT_ARG_FILTER_ID]);
	FLT_OT_FREE_CLEAR(rule->arg.act.p[FLT_OT_ARG_GROUP_ID]);

	rule->arg.act.p[FLT_OT_ARG_FLT_CONF] = fconf;
	rule->arg.act.p[FLT_OT_ARG_CONF]     = conf;
	rule->arg.act.p[FLT_OT_ARG_GROUP]    = ph_group;

	FLT_OT_RETURN(1);
}


/***
 * NAME
 *   flt_ot_group_release -
 *
 * ARGUMENTS
 *   rule -
 *
 * DESCRIPTION
 *   This is the release_ptr callback of a rule associated to the
 *   FLT_OT_ACTION_GROUP action.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_group_release(struct act_rule *rule)
{
	FLT_OT_FUNC("%p", rule);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_group_parse -
 *
 * ARGUMENTS
 *   args    -
 *   cur_arg -
 *   px      -
 *   rule    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ACT_RET_PRS_ERR if an error occurs, ACT_RET_PRS_OK otherwise.
 */
static enum act_parse_ret flt_ot_group_parse(const char **args, int *cur_arg, struct proxy *px, struct act_rule *rule, char **err)
{
	FLT_OT_FUNC("%p, %p, %p, %p, %p:%p", args, cur_arg, px, rule, FLT_OT_DPTR_ARGS(err));

	if (!FLT_OT_ARG_ISVALID(*cur_arg) ||
	    !FLT_OT_ARG_ISVALID(*cur_arg + 1) ||
	    (FLT_OT_ARG_ISVALID(*cur_arg + 2) &&
	     (strcmp(args[*cur_arg + 2], FLT_OT_CONDITION_IF) != 0) &&
	     (strcmp(args[*cur_arg + 2], FLT_OT_CONDITION_UNLESS) != 0))) {
		FLT_OT_ERR("expects: <filter-id> <group-id> [{ if | unless } ...]");

		FLT_OT_RETURN(ACT_RET_PRS_ERR);
	}

	/* Copy the OpenTracing filter id. */
	rule->arg.act.p[FLT_OT_ARG_FILTER_ID] = FLT_OT_STRDUP(args[*cur_arg]);
	if (rule->arg.act.p[FLT_OT_ARG_FILTER_ID] == NULL) {
		FLT_OT_ERR("%s : out of memory", args[*cur_arg]);

		FLT_OT_RETURN(ACT_RET_PRS_ERR);
	}

	/* Copy the OpenTracing group id. */
	rule->arg.act.p[FLT_OT_ARG_GROUP_ID] = FLT_OT_STRDUP(args[*cur_arg + 1]);
	if (rule->arg.act.p[FLT_OT_ARG_GROUP_ID] == NULL) {
		FLT_OT_ERR("%s : out of memory", args[*cur_arg + 1]);

		FLT_OT_FREE_CLEAR(rule->arg.act.p[FLT_OT_ARG_FILTER_ID]);

		FLT_OT_RETURN(ACT_RET_PRS_ERR);
	}

	rule->action      = ACT_CUSTOM;
	rule->action_ptr  = flt_ot_group_action;
	rule->check_ptr   = flt_ot_group_check;
	rule->release_ptr = flt_ot_group_release;

	*cur_arg += 2;

	FLT_OT_RETURN(ACT_RET_PRS_OK);
}


static struct action_kw_list tcp_req_action_kws = { ILH, {
		{ FLT_OT_ACTION_GROUP, flt_ot_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_action_kws);

static struct action_kw_list tcp_res_action_kws = { ILH, {
		{ FLT_OT_ACTION_GROUP, flt_ot_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_action_kws);

static struct action_kw_list http_req_action_kws = { ILH, {
		{ FLT_OT_ACTION_GROUP, flt_ot_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_action_kws);

static struct action_kw_list http_res_action_kws = { ILH, {
		{ FLT_OT_ACTION_GROUP, flt_ot_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_action_kws);

static struct action_kw_list http_after_res_actions_kws = { ILH, {
		{ FLT_OT_ACTION_GROUP, flt_ot_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, http_after_res_keywords_register, &http_after_res_actions_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
