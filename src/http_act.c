/*
 * HTTP actions
 *
 * Copyright 2000-2018 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/types.h>

#include <ctype.h>
#include <string.h>
#include <time.h>

#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/http.h>
#include <common/initcall.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/http_rules.h>
#include <proto/http_htx.h>
#include <proto/log.h>
#include <proto/http_ana.h>
#include <proto/stream_interface.h>


/* This function executes one of the set-{method,path,query,uri} actions. It
 * builds a string in the trash from the specified format string. It finds
 * the action to be performed in <http.action>, previously filled by function
 * parse_set_req_line(). The replacement action is excuted by the function
 * http_action_set_req_line(). It always returns ACT_RET_CONT. If an error
 * occurs the action is canceled, but the rule processing continue.
 */
static enum act_return http_action_set_req_line(struct act_rule *rule, struct proxy *px,
                                                struct session *sess, struct stream *s, int flags)
{
	struct buffer *replace;
	enum act_return ret = ACT_RET_ERR;

	replace = alloc_trash_chunk();
	if (!replace)
		goto leave;

	/* If we have to create a query string, prepare a '?'. */
	if (rule->arg.http.action == 2)
		replace->area[replace->data++] = '?';
	replace->data += build_logline(s, replace->area + replace->data,
				       replace->size - replace->data,
				       &rule->arg.http.logfmt);

	http_req_replace_stline(rule->arg.http.action, replace->area,
				replace->data, px, s);

	ret = ACT_RET_CONT;

leave:
	free_trash_chunk(replace);
	return ret;
}

/* parse an http-request action among :
 *   set-method
 *   set-path
 *   set-query
 *   set-uri
 *
 * All of them accept a single argument of type string representing a log-format.
 * The resulting rule makes use of arg->act.p[0..1] to store the log-format list
 * head, and p[2] to store the action as an int (0=method, 1=path, 2=query, 3=uri).
 * It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_set_req_line(const char **args, int *orig_arg, struct proxy *px,
                                             struct act_rule *rule, char **err)
{
	int cur_arg = *orig_arg;

	rule->action = ACT_CUSTOM;

	switch (args[0][4]) {
	case 'm' :
		rule->arg.http.action = 0;
		rule->action_ptr = http_action_set_req_line;
		break;
	case 'p' :
		rule->arg.http.action = 1;
		rule->action_ptr = http_action_set_req_line;
		break;
	case 'q' :
		rule->arg.http.action = 2;
		rule->action_ptr = http_action_set_req_line;
		break;
	case 'u' :
		rule->arg.http.action = 3;
		rule->action_ptr = http_action_set_req_line;
		break;
	default:
		memprintf(err, "internal error: unhandled action '%s'", args[0]);
		return ACT_RET_PRS_ERR;
	}

	if (!*args[cur_arg] ||
	    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
		memprintf(err, "expects exactly 1 argument <format>");
		return ACT_RET_PRS_ERR;
	}

	LIST_INIT(&rule->arg.http.logfmt);
	px->conf.args.ctx = ARGC_HRQ;
	if (!parse_logformat_string(args[cur_arg], px, &rule->arg.http.logfmt, LOG_OPT_HTTP,
	                            (px->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, err)) {
		return ACT_RET_PRS_ERR;
	}

	(*orig_arg)++;
	return ACT_RET_PRS_OK;
}

/* This function executes a replace-uri action. It finds its arguments in
 * <rule>.arg.act.p[]. It builds a string in the trash from the format string
 * previously filled by function parse_replace_uri() and will execute the regex
 * in p[1] to replace the URI. It uses the format string present in act.p[2..3].
 * It always returns ACT_RET_CONT. If an error occurs, the action is canceled,
 * but the rule processing continues.
 */
static enum act_return http_action_replace_uri(struct act_rule *rule, struct proxy *px,
                                               struct session *sess, struct stream *s, int flags)
{
	enum act_return ret = ACT_RET_ERR;
	struct buffer *replace, *output;
	struct ist uri;
	int len;

	replace = alloc_trash_chunk();
	output  = alloc_trash_chunk();
	if (!replace || !output)
		goto leave;
	uri = htx_sl_req_uri(http_get_stline(htxbuf(&s->req.buf)));
	if (!regex_exec_match2(rule->arg.act.p[1], uri.ptr, uri.len, MAX_MATCH, pmatch, 0))
		goto leave;

	replace->data = build_logline(s, replace->area, replace->size, (struct list *)&rule->arg.act.p[2]);

	/* note: uri.ptr doesn't need to be zero-terminated because it will
	 * only be used to pick pmatch references.
	 */
	len = exp_replace(output->area, output->size, uri.ptr, replace->area, pmatch);
	if (len == -1)
		goto leave;

	/* 3 is the set-uri action */
	http_req_replace_stline(3, output->area, len, px, s);

	ret = ACT_RET_CONT;

leave:
	free_trash_chunk(output);
	free_trash_chunk(replace);
	return ret;
}

/* parse a "replace-uri" http-request action.
 * This action takes 2 arguments (a regex and a replacement format string).
 * The resulting rule makes use of arg->act.p[0] to store the action (0 for now),
 * p[1] to store the compiled regex, and arg->act.p[2..3] to store the log-format
 * list head. It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_replace_uri(const char **args, int *orig_arg, struct proxy *px,
                                            struct act_rule *rule, char **err)
{
	int cur_arg = *orig_arg;
	char *error = NULL;

	rule->action = ACT_CUSTOM;
	rule->arg.act.p[0] = (void *)0; // replace-uri
	rule->action_ptr = http_action_replace_uri;

	if (!*args[cur_arg] || !*args[cur_arg+1] ||
	    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
		memprintf(err, "expects exactly 2 arguments <match-regex> and <replace-format>");
		return ACT_RET_PRS_ERR;
	}

	if (!(rule->arg.act.p[1] = regex_comp(args[cur_arg], 1, 1, &error))) {
		memprintf(err, "failed to parse the regex : %s", error);
		free(error);
		return ACT_RET_PRS_ERR;
	}

	LIST_INIT((struct list *)&rule->arg.act.p[2]);
	px->conf.args.ctx = ARGC_HRQ;
	if (!parse_logformat_string(args[cur_arg + 1], px, (struct list *)&rule->arg.act.p[2], LOG_OPT_HTTP,
	                            (px->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, err)) {
		return ACT_RET_PRS_ERR;
	}

	(*orig_arg) += 2;
	return ACT_RET_PRS_OK;
}

/* This function is just a compliant action wrapper for "set-status". */
static enum act_return action_http_set_status(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	http_res_set_status(rule->arg.status.code, rule->arg.status.reason, s);
	return ACT_RET_CONT;
}

/* parse set-status action:
 * This action accepts a single argument of type int representing
 * an http status code. It returns ACT_RET_PRS_OK on success,
 * ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_http_set_status(const char **args, int *orig_arg, struct proxy *px,
                                                struct act_rule *rule, char **err)
{
	char *error;

	rule->action = ACT_CUSTOM;
	rule->action_ptr = action_http_set_status;

	/* Check if an argument is available */
	if (!*args[*orig_arg]) {
		memprintf(err, "expects 1 argument: <status>; or 3 arguments: <status> reason <fmt>");
		return ACT_RET_PRS_ERR;
	}

	/* convert status code as integer */
	rule->arg.status.code = strtol(args[*orig_arg], &error, 10);
	if (*error != '\0' || rule->arg.status.code < 100 || rule->arg.status.code > 999) {
		memprintf(err, "expects an integer status code between 100 and 999");
		return ACT_RET_PRS_ERR;
	}

	(*orig_arg)++;

	/* set custom reason string */
	rule->arg.status.reason = NULL; // If null, we use the default reason for the status code.
	if (*args[*orig_arg] && strcmp(args[*orig_arg], "reason") == 0 &&
	    (*args[*orig_arg + 1] && strcmp(args[*orig_arg + 1], "if") != 0 && strcmp(args[*orig_arg + 1], "unless") != 0)) {
		(*orig_arg)++;
		rule->arg.status.reason = strdup(args[*orig_arg]);
		(*orig_arg)++;
	}

	return ACT_RET_PRS_OK;
}

/* This function executes the "reject" HTTP action. It clears the request and
 * response buffer without sending any response. It can be useful as an HTTP
 * alternative to the silent-drop action to defend against DoS attacks, and may
 * also be used with HTTP/2 to close a connection instead of just a stream.
 * The txn status is unchanged, indicating no response was sent. The termination
 * flags will indicate "PR". It always returns ACT_RET_DONE.
 */
static enum act_return http_action_reject(struct act_rule *rule, struct proxy *px,
                                          struct session *sess, struct stream *s, int flags)
{
	si_must_kill_conn(chn_prod(&s->req));
	channel_abort(&s->req);
	channel_abort(&s->res);
	s->req.analysers = 0;
	s->res.analysers = 0;

	_HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	return ACT_RET_DONE;
}

/* parse the "reject" action:
 * This action takes no argument and returns ACT_RET_PRS_OK on success,
 * ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_http_action_reject(const char **args, int *orig_arg, struct proxy *px,
                                                   struct act_rule *rule, char **err)
{
	rule->action = ACT_CUSTOM;
	rule->action_ptr = http_action_reject;
	return ACT_RET_PRS_OK;
}

/* This function executes the "disable-l7-retry" HTTP action.
 * It disables L7 retries (all retry except for a connection failure). This
 * can be useful for example to avoid retrying on POST requests.
 * It just removes the L7 retry flag on the stream_interface, and always
 * return ACT_RET_CONT;
 */
static enum act_return http_req_disable_l7_retry(struct act_rule *rule, struct proxy *px,
                                          struct session *sess, struct stream *s, int flags)
{
	struct stream_interface *si = &s->si[1];

	/* In theory, the SI_FL_L7_RETRY flags isn't set at this point, but
	 * let's be future-proof and remove it anyway.
	 */
	si->flags &= ~SI_FL_L7_RETRY;
	si->flags |= SI_FL_D_L7_RETRY;
	return ACT_RET_CONT;
}

/* parse the "disable-l7-retry" action:
 * This action takes no argument and returns ACT_RET_PRS_OK on success,
 * ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_http_req_disable_l7_retry(const char **args,
							  int *orig_args, struct proxy *px,
							  struct act_rule *rule, char **err)
{
	rule->action = ACT_CUSTOM;
	rule->action_ptr = http_req_disable_l7_retry;
	return ACT_RET_PRS_OK;
}

/* This function executes the "capture" action. It executes a fetch expression,
 * turns the result into a string and puts it in a capture slot. It always
 * returns 1. If an error occurs the action is cancelled, but the rule
 * processing continues.
 */
static enum act_return http_action_req_capture(struct act_rule *rule, struct proxy *px,
                                               struct session *sess, struct stream *s, int flags)
{
	struct sample *key;
	struct cap_hdr *h = rule->arg.cap.hdr;
	char **cap = s->req_cap;
	int len;

	key = sample_fetch_as_type(s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.cap.expr, SMP_T_STR);
	if (!key)
		return ACT_RET_CONT;

	if (cap[h->index] == NULL)
		cap[h->index] = pool_alloc(h->pool);

	if (cap[h->index] == NULL) /* no more capture memory */
		return ACT_RET_CONT;

	len = key->data.u.str.data;
	if (len > h->len)
		len = h->len;

	memcpy(cap[h->index], key->data.u.str.area, len);
	cap[h->index][len] = 0;
	return ACT_RET_CONT;
}

/* This function executes the "capture" action and store the result in a
 * capture slot if exists. It executes a fetch expression, turns the result
 * into a string and puts it in a capture slot. It always returns 1. If an
 * error occurs the action is cancelled, but the rule processing continues.
 */
static enum act_return http_action_req_capture_by_id(struct act_rule *rule, struct proxy *px,
                                                     struct session *sess, struct stream *s, int flags)
{
	struct sample *key;
	struct cap_hdr *h;
	char **cap = s->req_cap;
	struct proxy *fe = strm_fe(s);
	int len;
	int i;

	/* Look for the original configuration. */
	for (h = fe->req_cap, i = fe->nb_req_cap - 1;
	     h != NULL && i != rule->arg.capid.idx ;
	     i--, h = h->next);
	if (!h)
		return ACT_RET_CONT;

	key = sample_fetch_as_type(s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.capid.expr, SMP_T_STR);
	if (!key)
		return ACT_RET_CONT;

	if (cap[h->index] == NULL)
		cap[h->index] = pool_alloc(h->pool);

	if (cap[h->index] == NULL) /* no more capture memory */
		return ACT_RET_CONT;

	len = key->data.u.str.data;
	if (len > h->len)
		len = h->len;

	memcpy(cap[h->index], key->data.u.str.area, len);
	cap[h->index][len] = 0;
	return ACT_RET_CONT;
}

/* Check an "http-request capture" action.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
static int check_http_req_capture(struct act_rule *rule, struct proxy *px, char **err)
{
	if (rule->action_ptr != http_action_req_capture_by_id)
		return 1;

	if (rule->arg.capid.idx >= px->nb_req_cap) {
		memprintf(err, "unable to find capture id '%d' referenced by http-request capture rule",
			  rule->arg.capid.idx);
		return 0;
	}

	return 1;
}

/* parse an "http-request capture" action. It takes a single argument which is
 * a sample fetch expression. It stores the expression into arg->act.p[0] and
 * the allocated hdr_cap struct or the preallocated "id" into arg->act.p[1].
 * It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_http_req_capture(const char **args, int *orig_arg, struct proxy *px,
                                                 struct act_rule *rule, char **err)
{
	struct sample_expr *expr;
	struct cap_hdr *hdr;
	int cur_arg;
	int len = 0;

	for (cur_arg = *orig_arg; cur_arg < *orig_arg + 3 && *args[cur_arg]; cur_arg++)
		if (strcmp(args[cur_arg], "if") == 0 ||
		    strcmp(args[cur_arg], "unless") == 0)
			break;

	if (cur_arg < *orig_arg + 3) {
		memprintf(err, "expects <expression> [ 'len' <length> | id <idx> ]");
		return ACT_RET_PRS_ERR;
	}

	cur_arg = *orig_arg;
	expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args);
	if (!expr)
		return ACT_RET_PRS_ERR;

	if (!(expr->fetch->val & SMP_VAL_FE_HRQ_HDR)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  args[cur_arg-1], sample_src_names(expr->fetch->use));
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (!args[cur_arg] || !*args[cur_arg]) {
		memprintf(err, "expects 'len or 'id'");
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (strcmp(args[cur_arg], "len") == 0) {
		cur_arg++;

		if (!(px->cap & PR_CAP_FE)) {
			memprintf(err, "proxy '%s' has no frontend capability", px->id);
			return ACT_RET_PRS_ERR;
		}

		px->conf.args.ctx = ARGC_CAP;

		if (!args[cur_arg]) {
			memprintf(err, "missing length value");
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		/* we copy the table name for now, it will be resolved later */
		len = atoi(args[cur_arg]);
		if (len <= 0) {
			memprintf(err, "length must be > 0");
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		cur_arg++;

		hdr = calloc(1, sizeof(*hdr));
		hdr->next = px->req_cap;
		hdr->name = NULL; /* not a header capture */
		hdr->namelen = 0;
		hdr->len = len;
		hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
		hdr->index = px->nb_req_cap++;

		px->req_cap = hdr;
		px->to_log |= LW_REQHDR;

		rule->action       = ACT_CUSTOM;
		rule->action_ptr   = http_action_req_capture;
		rule->arg.cap.expr = expr;
		rule->arg.cap.hdr  = hdr;
	}

	else if (strcmp(args[cur_arg], "id") == 0) {
		int id;
		char *error;

		cur_arg++;

		if (!args[cur_arg]) {
			memprintf(err, "missing id value");
			free(expr);
			return ACT_RET_PRS_ERR;
		}

		id = strtol(args[cur_arg], &error, 10);
		if (*error != '\0') {
			memprintf(err, "cannot parse id '%s'", args[cur_arg]);
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		cur_arg++;

		px->conf.args.ctx = ARGC_CAP;

		rule->action       = ACT_CUSTOM;
		rule->action_ptr   = http_action_req_capture_by_id;
		rule->check_ptr    = check_http_req_capture;
		rule->arg.capid.expr = expr;
		rule->arg.capid.idx  = id;
	}

	else {
		memprintf(err, "expects 'len' or 'id', found '%s'", args[cur_arg]);
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	*orig_arg = cur_arg;
	return ACT_RET_PRS_OK;
}

/* This function executes the "capture" action and store the result in a
 * capture slot if exists. It executes a fetch expression, turns the result
 * into a string and puts it in a capture slot. It always returns 1. If an
 * error occurs the action is cancelled, but the rule processing continues.
 */
static enum act_return http_action_res_capture_by_id(struct act_rule *rule, struct proxy *px,
                                                     struct session *sess, struct stream *s, int flags)
{
	struct sample *key;
	struct cap_hdr *h;
	char **cap = s->res_cap;
	struct proxy *fe = strm_fe(s);
	int len;
	int i;

	/* Look for the original configuration. */
	for (h = fe->rsp_cap, i = fe->nb_rsp_cap - 1;
	     h != NULL && i != rule->arg.capid.idx ;
	     i--, h = h->next);
	if (!h)
		return ACT_RET_CONT;

	key = sample_fetch_as_type(s->be, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL, rule->arg.capid.expr, SMP_T_STR);
	if (!key)
		return ACT_RET_CONT;

	if (cap[h->index] == NULL)
		cap[h->index] = pool_alloc(h->pool);

	if (cap[h->index] == NULL) /* no more capture memory */
		return ACT_RET_CONT;

	len = key->data.u.str.data;
	if (len > h->len)
		len = h->len;

	memcpy(cap[h->index], key->data.u.str.area, len);
	cap[h->index][len] = 0;
	return ACT_RET_CONT;
}

/* Check an "http-response capture" action.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
static int check_http_res_capture(struct act_rule *rule, struct proxy *px, char **err)
{
	if (rule->action_ptr != http_action_res_capture_by_id)
		return 1;

	if (rule->arg.capid.idx >= px->nb_rsp_cap) {
		memprintf(err, "unable to find capture id '%d' referenced by http-response capture rule",
			  rule->arg.capid.idx);
		return 0;
	}

	return 1;
}

/* parse an "http-response capture" action. It takes a single argument which is
 * a sample fetch expression. It stores the expression into arg->act.p[0] and
 * the allocated hdr_cap struct od the preallocated id into arg->act.p[1].
 * It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_http_res_capture(const char **args, int *orig_arg, struct proxy *px,
                                                 struct act_rule *rule, char **err)
{
	struct sample_expr *expr;
	int cur_arg;
	int id;
	char *error;

	for (cur_arg = *orig_arg; cur_arg < *orig_arg + 3 && *args[cur_arg]; cur_arg++)
		if (strcmp(args[cur_arg], "if") == 0 ||
		    strcmp(args[cur_arg], "unless") == 0)
			break;

	if (cur_arg < *orig_arg + 3) {
		memprintf(err, "expects <expression> id <idx>");
		return ACT_RET_PRS_ERR;
	}

	cur_arg = *orig_arg;
	expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args);
	if (!expr)
		return ACT_RET_PRS_ERR;

	if (!(expr->fetch->val & SMP_VAL_FE_HRS_HDR)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  args[cur_arg-1], sample_src_names(expr->fetch->use));
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (!args[cur_arg] || !*args[cur_arg]) {
		memprintf(err, "expects 'id'");
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	if (strcmp(args[cur_arg], "id") != 0) {
		memprintf(err, "expects 'id', found '%s'", args[cur_arg]);
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	cur_arg++;

	if (!args[cur_arg]) {
		memprintf(err, "missing id value");
		free(expr);
		return ACT_RET_PRS_ERR;
	}

	id = strtol(args[cur_arg], &error, 10);
	if (*error != '\0') {
		memprintf(err, "cannot parse id '%s'", args[cur_arg]);
		free(expr);
		return ACT_RET_PRS_ERR;
	}
	cur_arg++;

	px->conf.args.ctx = ARGC_CAP;

	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_res_capture_by_id;
	rule->check_ptr    = check_http_res_capture;
	rule->arg.capid.expr = expr;
	rule->arg.capid.idx  = id;

	*orig_arg = cur_arg;
	return ACT_RET_PRS_OK;
}

/************************************************************************/
/*   All supported http-request action keywords must be declared here.  */
/************************************************************************/

static struct action_kw_list http_req_actions = {
	.kw = {
		{ "capture",    parse_http_req_capture },
		{ "reject",     parse_http_action_reject },
		{ "disable-l7-retry", parse_http_req_disable_l7_retry },
		{ "replace-uri", parse_replace_uri },
		{ "set-method", parse_set_req_line },
		{ "set-path",   parse_set_req_line },
		{ "set-query",  parse_set_req_line },
		{ "set-uri",    parse_set_req_line },
		{ NULL, NULL }
	}
};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_actions);

static struct action_kw_list http_res_actions = {
	.kw = {
		{ "capture",    parse_http_res_capture },
		{ "set-status", parse_http_set_status },
		{ NULL, NULL }
	}
};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_actions);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
