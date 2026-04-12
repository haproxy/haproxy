/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/* Group data table built from the X-macro list. */
#define FLT_OTEL_GROUP_DEF(a,b,c)   { a, b, c },
const struct flt_otel_group_data flt_otel_group_data[] = { FLT_OTEL_GROUP_DEFINES };
#undef FLT_OTEL_GROUP_DEF


/***
 * NAME
 *   flt_otel_group_action - group action execution callback
 *
 * SYNOPSIS
 *   static enum act_return flt_otel_group_action(struct act_rule *rule, struct proxy *px, struct session *sess, struct stream *s, int opts)
 *
 * ARGUMENTS
 *   rule - action rule containing group configuration references
 *   px   - proxy instance
 *   sess - current session
 *   s    - current stream
 *   opts - action options (ACT_OPT_* flags)
 *
 * DESCRIPTION
 *   Executes the action_ptr callback for the FLT_OTEL_ACTION_GROUP action.
 *   Retrieves the filter configuration, group definition, and runtime context
 *   from the rule's argument pointers.  If the filter is disabled or not
 *   attached to the stream, processing is skipped.  Otherwise, iterates over
 *   all scopes defined in the group and runs each via flt_otel_scope_run().
 *   Scope execution errors are logged but do not prevent the remaining scopes
 *   from executing.
 *
 * RETURN VALUE
 *   Returns ACT_RET_CONT.
 */
static enum act_return flt_otel_group_action(struct act_rule *rule, struct proxy *px, struct session *sess, struct stream *s, int opts)
{
	const struct filter                   *filter;
	const struct flt_conf                 *fconf;
	const struct flt_otel_conf            *conf;
	const struct flt_otel_conf_group      *conf_group;
	const struct flt_otel_runtime_context *rt_ctx = NULL;
	const struct flt_otel_conf_ph         *ph_scope;
	char                                  *err = NULL;
	int                                    i, rc;

	OTELC_FUNC("%p, %p, %p, %p, %d", rule, px, sess, s, opts);

	OTELC_DBG(DEBUG, "from: %d, arg.act %p:{ %p %p %p %p }", rule->from, &(rule->arg.act), rule->arg.act.p[0], rule->arg.act.p[1], rule->arg.act.p[2], rule->arg.act.p[3]);

	fconf      = rule->arg.act.p[FLT_OTEL_ARG_FLT_CONF];
	conf       = rule->arg.act.p[FLT_OTEL_ARG_CONF];
	conf_group = ((const struct flt_otel_conf_ph *)(rule->arg.act.p[FLT_OTEL_ARG_GROUP]))->ptr;

	if ((fconf == NULL) || (conf == NULL) || (conf_group == NULL)) {
		FLT_OTEL_LOG(LOG_ERR, FLT_OTEL_ACTION_GROUP ": internal error, invalid group action");

		OTELC_RETURN_EX(ACT_RET_CONT, enum act_return, "%d");
	}

	if (_HA_ATOMIC_LOAD(&(conf->instr->flag_disabled))) {
		OTELC_DBG(INFO, "filter '%s' disabled, group action '%s' ignored", conf->id, conf_group->id);

		OTELC_RETURN_EX(ACT_RET_CONT, enum act_return, "%d");
	}

	/* Find the OpenTelemetry filter instance from the current stream. */
	list_for_each_entry(filter, &(s->strm_flt.filters), list)
		if (filter->config == fconf) {
			rt_ctx = filter->ctx;

			break;
		}

	if (rt_ctx == NULL) {
		OTELC_DBG(INFO, "cannot find filter, probably not attached to the stream");

		OTELC_RETURN_EX(ACT_RET_CONT, enum act_return, "%d");
	}
	else if (flt_otel_is_disabled(filter FLT_OTEL_DBG_ARGS(, -1))) {
		OTELC_RETURN_EX(ACT_RET_CONT, enum act_return, "%d");
	}
	else {
		OTELC_DBG(DEBUG, "run group '%s'", conf_group->id);
		FLT_OTEL_DBG_CONF_GROUP("run group ", conf_group);
	}

	/*
	 * Check the value of rule->from; in case it is incorrect,
	 * report an error.
	 */
	for (i = 0; i < OTELC_TABLESIZE(flt_otel_group_data); i++)
		if (flt_otel_group_data[i].act_from == rule->from)
			break;

	if (i >= OTELC_TABLESIZE(flt_otel_group_data)) {
		FLT_OTEL_LOG(LOG_ERR, FLT_OTEL_ACTION_GROUP ": internal error, invalid rule->from=%d", rule->from);

		OTELC_RETURN_EX(ACT_RET_CONT, enum act_return, "%d");
	}

	/* Execute each scope defined in this group. */
	list_for_each_entry(ph_scope, &(conf_group->ph_scopes), list) {
		rc = flt_otel_scope_run(s, rt_ctx->filter, (flt_otel_group_data[i].smp_opt_dir == SMP_OPT_DIR_REQ) ? &(s->req) : &(s->res), ph_scope->ptr, NULL, NULL, flt_otel_group_data[i].smp_opt_dir, &err);
		if ((rc == FLT_OTEL_RET_ERROR) && (opts & ACT_OPT_FINAL)) {
			FLT_OTEL_LOG(LOG_ERR, FLT_OTEL_ACTION_GROUP ": scope '%s' failed in group '%s'", ph_scope->id, conf_group->id);
			OTELC_SFREE_CLEAR(err);
		}
	}

	OTELC_RETURN_EX(ACT_RET_CONT, enum act_return, "%d");
}


/***
 * NAME
 *   flt_otel_group_check - group action post-parse check callback
 *
 * SYNOPSIS
 *   static int flt_otel_group_check(struct act_rule *rule, struct proxy *px, char **err)
 *
 * ARGUMENTS
 *   rule - action rule to validate
 *   px   - proxy instance
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Validates the check_ptr callback for the FLT_OTEL_ACTION_GROUP action.
 *   Resolves the filter ID and group ID string references stored during parsing
 *   into direct pointers to the filter configuration and group configuration
 *   structures.  Searches the proxy's filter list for a matching OTel filter,
 *   then locates the named group within that filter's configuration.  On
 *   success, replaces the string ID pointers in <rule>->arg.act.p with the
 *   resolved configuration pointers.
 *
 * RETURN VALUE
 *   Returns 1 on success, or 0 on failure with <err> filled.
 */
static int flt_otel_group_check(struct act_rule *rule, struct proxy *px, char **err)
{
	struct flt_conf         *fconf_tmp, *fconf = NULL;
	struct flt_otel_conf    *conf;
	struct flt_otel_conf_ph *ph_group;
	const char              *filter_id;
	const char              *group_id;
	bool                     flag_found = 0;
	int                      i;

	OTELC_FUNC("%p, %p, %p:%p", rule, px, OTELC_DPTR_ARGS(err));

	filter_id = rule->arg.act.p[FLT_OTEL_ARG_FILTER_ID];
	group_id  = rule->arg.act.p[FLT_OTEL_ARG_GROUP_ID];

	OTELC_DBG(NOTICE, "checking filter_id='%s', group_id='%s'", filter_id, group_id);

	/*
	 * Check the value of rule->from; in case it is incorrect, report an
	 * error.
	 */
	for (i = 0; i < OTELC_TABLESIZE(flt_otel_group_data); i++)
		if (flt_otel_group_data[i].act_from == rule->from)
			break;

	if (i >= OTELC_TABLESIZE(flt_otel_group_data)) {
		FLT_OTEL_ERR("internal error, unexpected rule->from=%d, please report this bug!", rule->from);

		OTELC_RETURN_INT(0);
	}

	/*
	 * Try to find the OpenTelemetry filter by checking all filters for the
	 * proxy <px>.
	 */
	list_for_each_entry(fconf_tmp, &(px->filter_configs), list) {
		conf = fconf_tmp->conf;

		if (fconf_tmp->id != otel_flt_id) {
			/* This is not an OpenTelemetry filter. */
			continue;
		}
		else if (strcmp(conf->id, filter_id) == 0) {
			/* This is the good filter ID. */
			fconf = fconf_tmp;

			break;
		}
	}

	if (fconf == NULL) {
		FLT_OTEL_ERR("unable to find the OpenTelemetry filter '%s' used by the " FLT_OTEL_ACTION_GROUP " '%s'", filter_id, group_id);

		OTELC_RETURN_INT(0);
	}

	/*
	 * Attempt to find if the group is defined in the OpenTelemetry filter
	 * configuration.
	 */
	list_for_each_entry(ph_group, &(conf->instr->ph_groups), list)
		if (strcmp(ph_group->id, group_id) == 0) {
			flag_found = 1;

			break;
		}

	if (!flag_found) {
		FLT_OTEL_ERR("unable to find group '%s' in the OpenTelemetry filter '%s' configuration", group_id, filter_id);

		OTELC_RETURN_INT(0);
	}

	OTELC_SFREE_CLEAR(rule->arg.act.p[FLT_OTEL_ARG_FILTER_ID]);
	OTELC_SFREE_CLEAR(rule->arg.act.p[FLT_OTEL_ARG_GROUP_ID]);

	/* Replace string IDs with resolved configuration pointers. */
	rule->arg.act.p[FLT_OTEL_ARG_FLT_CONF] = fconf;
	rule->arg.act.p[FLT_OTEL_ARG_CONF]     = conf;
	rule->arg.act.p[FLT_OTEL_ARG_GROUP]    = ph_group;

	OTELC_RETURN_INT(1);
}


/***
 * NAME
 *   flt_otel_group_release - group action release callback
 *
 * SYNOPSIS
 *   static void flt_otel_group_release(struct act_rule *rule)
 *
 * ARGUMENTS
 *   rule - action rule being released
 *
 * DESCRIPTION
 *   Provides the release_ptr callback for the FLT_OTEL_ACTION_GROUP action.
 *   This is a no-op because the group action's argument pointers reference
 *   shared configuration structures that are freed separately during filter
 *   deinitialization.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_group_release(struct act_rule *rule)
{
	OTELC_FUNC("%p", rule);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_group_parse - group action keyword parser
 *
 * SYNOPSIS
 *   static enum act_parse_ret flt_otel_group_parse(const char **args, int *cur_arg, struct proxy *px, struct act_rule *rule, char **err)
 *
 * ARGUMENTS
 *   args    - configuration line arguments array
 *   cur_arg - pointer to the current argument index
 *   px      - proxy instance
 *   rule    - action rule to populate
 *   err     - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses the FLT_OTEL_ACTION_GROUP action keyword from HAProxy configuration
 *   rules.  Expects two arguments: a filter ID and a group ID, optionally
 *   followed by "if" or "unless" conditions.  The filter ID and group ID are
 *   duplicated and stored in the <rule>'s argument pointers for later
 *   resolution by flt_otel_group_check().  The <rule>'s callbacks are set to
 *   flt_otel_group_action(), flt_otel_group_check(), and
 *   flt_otel_group_release().  This parser is registered for tcp-request,
 *   tcp-response, http-request, http-response, and http-after-response action
 *   contexts.
 *
 * RETURN VALUE
 *   Returns ACT_RET_PRS_OK on success, or ACT_RET_PRS_ERR on failure.
 */
static enum act_parse_ret flt_otel_group_parse(const char **args, int *cur_arg, struct proxy *px, struct act_rule *rule, char **err)
{
	OTELC_FUNC("%p, %p, %p, %p, %p:%p", args, cur_arg, px, rule, OTELC_DPTR_ARGS(err));

	FLT_OTEL_ARGS_DUMP();

	if (!FLT_OTEL_ARG_ISVALID(*cur_arg) || !FLT_OTEL_ARG_ISVALID(*cur_arg + 1) ||
	    (FLT_OTEL_ARG_ISVALID(*cur_arg + 2) &&
	     !FLT_OTEL_PARSE_KEYWORD(*cur_arg + 2, FLT_OTEL_CONDITION_IF) &&
	     !FLT_OTEL_PARSE_KEYWORD(*cur_arg + 2, FLT_OTEL_CONDITION_UNLESS))) {
		FLT_OTEL_ERR("expects: <filter-id> <group-id> [{ if | unless } ...]");

		OTELC_RETURN_EX(ACT_RET_PRS_ERR, enum act_parse_ret, "%d");
	}

	/* Copy the OpenTelemetry filter id. */
	rule->arg.act.p[FLT_OTEL_ARG_FILTER_ID] = OTELC_STRDUP(args[*cur_arg]);
	if (rule->arg.act.p[FLT_OTEL_ARG_FILTER_ID] == NULL) {
		FLT_OTEL_ERR("%s : out of memory", args[*cur_arg]);

		OTELC_RETURN_EX(ACT_RET_PRS_ERR, enum act_parse_ret, "%d");
	}

	/* Copy the OpenTelemetry group id. */
	rule->arg.act.p[FLT_OTEL_ARG_GROUP_ID] = OTELC_STRDUP(args[*cur_arg + 1]);
	if (rule->arg.act.p[FLT_OTEL_ARG_GROUP_ID] == NULL) {
		FLT_OTEL_ERR("%s : out of memory", args[*cur_arg + 1]);

		OTELC_SFREE_CLEAR(rule->arg.act.p[FLT_OTEL_ARG_FILTER_ID]);

		OTELC_RETURN_EX(ACT_RET_PRS_ERR, enum act_parse_ret, "%d");
	}

	/* Wire up the rule callbacks. */
	rule->action      = ACT_CUSTOM;
	rule->action_ptr  = flt_otel_group_action;
	rule->check_ptr   = flt_otel_group_check;
	rule->release_ptr = flt_otel_group_release;

	*cur_arg += 2;

	OTELC_RETURN_EX(ACT_RET_PRS_OK, enum act_parse_ret, "%d");
}


/* TCP request content action keywords for the OTel group action. */
static struct action_kw_list tcp_req_action_kws = { ILH, {
		{ FLT_OTEL_ACTION_GROUP, flt_otel_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_action_kws);

/* TCP response content action keywords for the OTel group action. */
static struct action_kw_list tcp_res_action_kws = { ILH, {
		{ FLT_OTEL_ACTION_GROUP, flt_otel_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_action_kws);

/* HTTP request action keywords for the OTel group action. */
static struct action_kw_list http_req_action_kws = { ILH, {
		{ FLT_OTEL_ACTION_GROUP, flt_otel_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_action_kws);

/* HTTP response action keywords for the OTel group action. */
static struct action_kw_list http_res_action_kws = { ILH, {
		{ FLT_OTEL_ACTION_GROUP, flt_otel_group_parse },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_action_kws);

/* HTTP after-response action keywords for the OTel group action. */
static struct action_kw_list http_after_res_actions_kws = { ILH, {
		{ FLT_OTEL_ACTION_GROUP, flt_otel_group_parse },
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
