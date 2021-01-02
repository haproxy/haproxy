/*
 * Action management functions.
 *
 * Copyright 2017 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/obj_type.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/stick_table.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>


/* Find and check the target table used by an action track-sc*. This
 * function should be called during the configuration validity check.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_trk_action(struct act_rule *rule, struct proxy *px, char **err)
{
	struct stktable *target;

	if (rule->arg.trk_ctr.table.n)
		target = stktable_find_by_name(rule->arg.trk_ctr.table.n);
	else
		target = px->table;

	if (!target) {
		memprintf(err, "unable to find table '%s' referenced by track-sc%d",
			  rule->arg.trk_ctr.table.n ?  rule->arg.trk_ctr.table.n : px->id,
			  rule->action);
		return 0;
	}

	if (!stktable_compatible_sample(rule->arg.trk_ctr.expr,  target->type)) {
		memprintf(err, "stick-table '%s' uses a type incompatible with the 'track-sc%d' rule",
			  rule->arg.trk_ctr.table.n ? rule->arg.trk_ctr.table.n : px->id,
			  rule->action);
		return 0;
	}
	else if (target->proxy && (px->bind_proc & ~target->proxy->bind_proc)) {
		memprintf(err, "stick-table '%s' referenced by 'track-sc%d' rule not present on all processes covered by proxy '%s'",
			  target->id, rule->action, px->id);
		return 0;
	}
	else {
		if (!in_proxies_list(target->proxies_list, px)) {
			px->next_stkt_ref = target->proxies_list;
			target->proxies_list = px;
		}
		free(rule->arg.trk_ctr.table.n);
		rule->arg.trk_ctr.table.t = target;
		/* Note: if we decide to enhance the track-sc syntax, we may be
		 * able to pass a list of counters to track and allocate them
		 * right here using stktable_alloc_data_type().
		 */
	}

	if (rule->from == ACT_F_TCP_REQ_CNT && (px->cap & PR_CAP_FE)) {
		if (!px->tcp_req.inspect_delay && !(rule->arg.trk_ctr.expr->fetch->val & SMP_VAL_FE_SES_ACC)) {
			ha_warning("config : %s '%s' : a 'tcp-request content track-sc*' rule explicitly depending on request"
				   " contents without any 'tcp-request inspect-delay' setting."
				   " This means that this rule will randomly find its contents. This can be fixed by"
				   " setting the tcp-request inspect-delay.\n",
				   proxy_type_str(px), px->id);
		}

		/* The following warning is emitted because HTTP multiplexers are able to catch errors
		 * or timeouts at the session level, before instantiating any stream.
		 * Thus the tcp-request content ruleset will not be evaluated in such case. It means,
		 * http_req and http_err counters will not be incremented as expected, even if the tracked
		 * counter does not use the request content. To track invalid requests it should be
		 * performed at the session level using a tcp-request session rule.
		 */
		if (px->mode == PR_MODE_HTTP &&
		    !(rule->arg.trk_ctr.expr->fetch->use & (SMP_USE_L6REQ|SMP_USE_HRQHV|SMP_USE_HRQHP|SMP_USE_HRQBO)) &&
		    (!rule->cond || !(rule->cond->use & (SMP_USE_L6REQ|SMP_USE_HRQHV|SMP_USE_HRQHP|SMP_USE_HRQBO)))) {
			ha_warning("config : %s '%s' : a 'tcp-request content track-sc*' rule not depending on request"
				   " contents for an HTTP frontend should be executed at the session level, using a"
				   " 'tcp-request session' rule (mandatory to track invalid HTTP requests).\n",
				   proxy_type_str(px), px->id);
		}
	}

	return 1;
}

/* check a capture rule. This function should be called during the configuration
 * validity check.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_capture(struct act_rule *rule, struct proxy *px, char **err)
{
	if (rule->from == ACT_F_TCP_REQ_CNT && (px->cap & PR_CAP_FE) && !px->tcp_req.inspect_delay &&
	    !(rule->arg.trk_ctr.expr->fetch->val & SMP_VAL_FE_SES_ACC)) {
		ha_warning("config : %s '%s' : a 'tcp-request capture' rule explicitly depending on request"
			   " contents without any 'tcp-request inspect-delay' setting."
			   " This means that this rule will randomly find its contents. This can be fixed by"
			   " setting the tcp-request inspect-delay.\n",
			   proxy_type_str(px), px->id);
	}

	return 1;
}

int act_resolution_cb(struct dns_requester *requester, struct dns_nameserver *nameserver)
{
	struct stream *stream;

	if (requester->resolution == NULL)
		return 0;

	stream = objt_stream(requester->owner);
	if (stream == NULL)
		return 0;

	task_wakeup(stream->task, TASK_WOKEN_MSG);

	return 0;
}

int act_resolution_error_cb(struct dns_requester *requester, int error_code)
{
	struct stream *stream;

	if (requester->resolution == NULL)
		return 0;

	stream = objt_stream(requester->owner);
	if (stream == NULL)
		return 0;

	task_wakeup(stream->task, TASK_WOKEN_MSG);

	return 0;
}

/* Parse a set-timeout rule statement. It first checks if the timeout name is
 * valid and returns it in <name>. Then the timeout is parsed as a plain value
 * and * returned in <out_timeout>. If there is a parsing error, the value is
 * reparsed as an expression and returned in <expr>.
 *
 * Returns -1 if the name is invalid or neither a time or an expression can be
 * parsed, or if the timeout value is 0.
 */
int cfg_parse_rule_set_timeout(const char **args, int idx, int *out_timeout,
                               enum act_timeout_name *name,
                               struct sample_expr **expr, char **err,
                               const char *file, int line, struct arg_list *al)
{
	const char *res;
	const char *timeout_name = args[idx++];

	if (strcmp(timeout_name, "server") == 0) {
		*name = ACT_TIMEOUT_SERVER;
	}
	else if (strcmp(timeout_name, "tunnel") == 0) {
		*name = ACT_TIMEOUT_TUNNEL;
	}
	else {
		memprintf(err,
		          "'set-timeout' rule supports 'server'/'tunnel' (got '%s')",
		          timeout_name);
		return -1;
	}

	res = parse_time_err(args[idx], (unsigned int *)out_timeout, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to rule 'set-timeout %s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[idx], timeout_name);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to rule 'set-timeout %s' (minimum value is 1 ms)",
			  args[idx], timeout_name);
		return -1;
	}
	/* res not NULL, parsing error */
	else if (res) {
		*expr = sample_parse_expr((char **)args, &idx, file, line, err, al, NULL);
		if (!*expr) {
			memprintf(err, "unexpected character '%c' in rule 'set-timeout %s'", *res, timeout_name);
			return -1;
		}
	}
	/* res NULL, parsing ok but value is 0 */
	else if (!(*out_timeout)) {
		memprintf(err, "null value is not valid for a 'set-timeout %s' rule",
			  timeout_name);
		return -1;
	}

	return 0;
}
