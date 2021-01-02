/*
 * HTTP rules parsing and registration
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

#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/capture-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/pool.h>
#include <haproxy/sample.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>


/* List head of all known action keywords for "http-request" */
struct action_kw_list http_req_keywords = {
       .list = LIST_HEAD_INIT(http_req_keywords.list)
};

/* List head of all known action keywords for "http-response" */
struct action_kw_list http_res_keywords = {
       .list = LIST_HEAD_INIT(http_res_keywords.list)
};

/* List head of all known action keywords for "http-after-response" */
struct action_kw_list http_after_res_keywords = {
       .list = LIST_HEAD_INIT(http_after_res_keywords.list)
};

/*
 * Return the struct http_req_action_kw associated to a keyword.
 */
struct action_kw *action_http_req_custom(const char *kw)
{
	return action_lookup(&http_req_keywords.list, kw);
}

/*
 * Return the struct http_res_action_kw associated to a keyword.
 */
struct action_kw *action_http_res_custom(const char *kw)
{
	return action_lookup(&http_res_keywords.list, kw);
}

/*
 * Return the struct http_after_res_action_kw associated to a keyword.
 */
struct action_kw *action_http_after_res_custom(const char *kw)
{
	return action_lookup(&http_after_res_keywords.list, kw);
}

/* parse an "http-request" rule */
struct act_rule *parse_http_req_cond(const char **args, const char *file, int linenum, struct proxy *proxy)
{
	struct act_rule *rule;
	struct action_kw *custom = NULL;
	int cur_arg;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		goto out_err;
	}
	rule->from = ACT_F_HTTP_REQ;

	if (((custom = action_http_req_custom(args[0])) != NULL)) {
		char *errmsg = NULL;

		cur_arg = 1;
		/* try in the module list */
		rule->kw = custom;
		if (custom->parse(args, &cur_arg, proxy, rule, &errmsg) == ACT_RET_PRS_ERR) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		else if (errmsg) {
			ha_warning("parsing [%s:%d] : %s.\n", file, linenum, errmsg);
			free(errmsg);
		}
	}
	else {
		action_build_list(&http_req_keywords.list, &trash);
		ha_alert("parsing [%s:%d]: 'http-request' expects %s%s, but got '%s'%s.\n",
			 file, linenum, *trash.area ? ", " : "", trash.area,
			 args[0], *args[0] ? "" : " (missing argument)");
		goto out_err;
	}

	if (strcmp(args[cur_arg], "if") == 0 || strcmp(args[cur_arg], "unless") == 0) {
		struct acl_cond *cond;
		char *errmsg = NULL;

		if ((cond = build_acl_cond(file, linenum, &proxy->acl, proxy, args+cur_arg, &errmsg)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing an 'http-request %s' condition : %s.\n",
				 file, linenum, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		rule->cond = cond;
	}
	else if (*args[cur_arg]) {
		ha_alert("parsing [%s:%d]: 'http-request %s' expects"
			 " either 'if' or 'unless' followed by a condition but found '%s'.\n",
			 file, linenum, args[0], args[cur_arg]);
		goto out_err;
	}

	return rule;
 out_err:
	free(rule);
	return NULL;
}

/* parse an "http-respose" rule */
struct act_rule *parse_http_res_cond(const char **args, const char *file, int linenum, struct proxy *proxy)
{
	struct act_rule *rule;
	struct action_kw *custom = NULL;
	int cur_arg;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		goto out_err;
	}
	rule->from = ACT_F_HTTP_RES;

	if (((custom = action_http_res_custom(args[0])) != NULL)) {
		char *errmsg = NULL;

		cur_arg = 1;
		/* try in the module list */
		rule->kw = custom;
		if (custom->parse(args, &cur_arg, proxy, rule, &errmsg) == ACT_RET_PRS_ERR) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		else if (errmsg) {
			ha_warning("parsing [%s:%d] : %s.\n", file, linenum, errmsg);
			free(errmsg);
		}
	}
	else {
		action_build_list(&http_res_keywords.list, &trash);
		ha_alert("parsing [%s:%d]: 'http-response' expects %s%s, but got '%s'%s.\n",
			 file, linenum, *trash.area ? ", " : "", trash.area,
			 args[0], *args[0] ? "" : " (missing argument)");
		goto out_err;
	}

	if (strcmp(args[cur_arg], "if") == 0 || strcmp(args[cur_arg], "unless") == 0) {
		struct acl_cond *cond;
		char *errmsg = NULL;

		if ((cond = build_acl_cond(file, linenum, &proxy->acl, proxy, args+cur_arg, &errmsg)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing an 'http-response %s' condition : %s.\n",
				 file, linenum, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		rule->cond = cond;
	}
	else if (*args[cur_arg]) {
		ha_alert("parsing [%s:%d]: 'http-response %s' expects"
			 " either 'if' or 'unless' followed by a condition but found '%s'.\n",
			 file, linenum, args[0], args[cur_arg]);
		goto out_err;
	}

	return rule;
 out_err:
	free(rule);
	return NULL;
}


/* parse an "http-after-response" rule */
struct act_rule *parse_http_after_res_cond(const char **args, const char *file, int linenum, struct proxy *proxy)
{
	struct act_rule *rule;
	struct action_kw *custom = NULL;
	int cur_arg;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		goto out_err;
	}
	rule->from = ACT_F_HTTP_RES;

	if (((custom = action_http_after_res_custom(args[0])) != NULL)) {
		char *errmsg = NULL;

		cur_arg = 1;
		/* try in the module list */
		rule->kw = custom;
		if (custom->parse(args, &cur_arg, proxy, rule, &errmsg) == ACT_RET_PRS_ERR) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-after-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		else if (errmsg) {
			ha_warning("parsing [%s:%d] : %s.\n", file, linenum, errmsg);
			free(errmsg);
		}
	}
	else {
		action_build_list(&http_after_res_keywords.list, &trash);
		ha_alert("parsing [%s:%d]: 'http-after-response' expects %s%s, but got '%s'%s.\n",
			 file, linenum, *trash.area ? ", " : "", trash.area,
			 args[0], *args[0] ? "" : " (missing argument)");
		goto out_err;
	}

	if (strcmp(args[cur_arg], "if") == 0 || strcmp(args[cur_arg], "unless") == 0) {
		struct acl_cond *cond;
		char *errmsg = NULL;

		if ((cond = build_acl_cond(file, linenum, &proxy->acl, proxy, args+cur_arg, &errmsg)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing an 'http-after-response %s' condition : %s.\n",
				 file, linenum, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
		rule->cond = cond;
	}
	else if (*args[cur_arg]) {
		ha_alert("parsing [%s:%d]: 'http-after-response %s' expects"
			 " either 'if' or 'unless' followed by a condition but found '%s'.\n",
			 file, linenum, args[0], args[cur_arg]);
		goto out_err;
	}

	return rule;
 out_err:
	free(rule);
	return NULL;
}

/* Parses a redirect rule. Returns the redirect rule on success or NULL on error,
 * with <err> filled with the error message. If <use_fmt> is not null, builds a
 * dynamic log-format rule instead of a static string. Parameter <dir> indicates
 * the direction of the rule, and equals 0 for request, non-zero for responses.
 */
struct redirect_rule *http_parse_redirect_rule(const char *file, int linenum, struct proxy *curproxy,
                                               const char **args, char **errmsg, int use_fmt, int dir)
{
	struct redirect_rule *rule;
	int cur_arg;
	int type = REDIRECT_TYPE_NONE;
	int code = 302;
	const char *destination = NULL;
	const char *cookie = NULL;
	int cookie_set = 0;
	unsigned int flags = (!dir ? REDIRECT_FLAG_FROM_REQ : REDIRECT_FLAG_NONE);
	struct acl_cond *cond = NULL;

	cur_arg = 0;
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "location") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			type = REDIRECT_TYPE_LOCATION;
			cur_arg++;
			destination = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "prefix") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;
			type = REDIRECT_TYPE_PREFIX;
			cur_arg++;
			destination = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "scheme") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			type = REDIRECT_TYPE_SCHEME;
			cur_arg++;
			destination = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "set-cookie") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			cur_arg++;
			cookie = args[cur_arg];
			cookie_set = 1;
		}
		else if (strcmp(args[cur_arg], "clear-cookie") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			cur_arg++;
			cookie = args[cur_arg];
			cookie_set = 0;
		}
		else if (strcmp(args[cur_arg], "code") == 0) {
			if (!*args[cur_arg + 1])
				goto missing_arg;

			cur_arg++;
			code = atol(args[cur_arg]);
			if (code < 301 || code > 308 || (code > 303 && code < 307)) {
				memprintf(errmsg,
				          "'%s': unsupported HTTP code '%s' (must be one of 301, 302, 303, 307 or 308)",
				          args[cur_arg - 1], args[cur_arg]);
				return NULL;
			}
		}
		else if (strcmp(args[cur_arg], "drop-query") == 0) {
			flags |= REDIRECT_FLAG_DROP_QS;
		}
		else if (strcmp(args[cur_arg], "append-slash") == 0) {
			flags |= REDIRECT_FLAG_APPEND_SLASH;
		}
		else if (strcmp(args[cur_arg], "if") == 0 ||
			 strcmp(args[cur_arg], "unless") == 0) {
			cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + cur_arg, errmsg);
			if (!cond) {
				memprintf(errmsg, "error in condition: %s", *errmsg);
				return NULL;
			}
			break;
		}
		else {
			memprintf(errmsg,
			          "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'clear-cookie', 'drop-query' or 'append-slash' (was '%s')",
			          args[cur_arg]);
			return NULL;
		}
		cur_arg++;
	}

	if (type == REDIRECT_TYPE_NONE) {
		memprintf(errmsg, "redirection type expected ('prefix', 'location', or 'scheme')");
		return NULL;
	}

	if (dir && type != REDIRECT_TYPE_LOCATION) {
		memprintf(errmsg, "response only supports redirect type 'location'");
		return NULL;
	}

	rule = calloc(1, sizeof(*rule));
	rule->cond = cond;
	LIST_INIT(&rule->rdr_fmt);

	if (!use_fmt) {
		/* old-style static redirect rule */
		rule->rdr_str = strdup(destination);
		rule->rdr_len = strlen(destination);
	}
	else {
		/* log-format based redirect rule */

		/* Parse destination. Note that in the REDIRECT_TYPE_PREFIX case,
		 * if prefix == "/", we don't want to add anything, otherwise it
		 * makes it hard for the user to configure a self-redirection.
		 */
		curproxy->conf.args.ctx = ARGC_RDR;
		if (!(type == REDIRECT_TYPE_PREFIX && destination[0] == '/' && destination[1] == '\0')) {
			if (!parse_logformat_string(destination, curproxy, &rule->rdr_fmt, LOG_OPT_HTTP,
			                            dir ? (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRS_HDR : SMP_VAL_BE_HRS_HDR
			                                : (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
			                            errmsg)) {
				return  NULL;
			}
			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;
		}
	}

	if (cookie) {
		/* depending on cookie_set, either we want to set the cookie, or to clear it.
		 * a clear consists in appending "; path=/; Max-Age=0;" at the end.
		 */
		rule->cookie_len = strlen(cookie);
		if (cookie_set) {
			rule->cookie_str = malloc(rule->cookie_len + 10);
			memcpy(rule->cookie_str, cookie, rule->cookie_len);
			memcpy(rule->cookie_str + rule->cookie_len, "; path=/;", 10);
			rule->cookie_len += 9;
		} else {
			rule->cookie_str = malloc(rule->cookie_len + 21);
			memcpy(rule->cookie_str, cookie, rule->cookie_len);
			memcpy(rule->cookie_str + rule->cookie_len, "; path=/; Max-Age=0;", 21);
			rule->cookie_len += 20;
		}
	}
	rule->type = type;
	rule->code = code;
	rule->flags = flags;
	LIST_INIT(&rule->list);
	return rule;

 missing_arg:
	memprintf(errmsg, "missing argument for '%s'", args[cur_arg]);
	return NULL;
}

__attribute__((constructor))
static void __http_rules_init(void)
{
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
