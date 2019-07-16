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

#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/http.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/acl.h>
#include <proto/action.h>
#include <proto/arg.h>
#include <proto/http_rules.h>
#include <proto/http_ana.h>
#include <proto/sample.h>


/* List head of all known action keywords for "http-request" */
struct action_kw_list http_req_keywords = {
       .list = LIST_HEAD_INIT(http_req_keywords.list)
};

/* List head of all known action keywords for "http-response" */
struct action_kw_list http_res_keywords = {
       .list = LIST_HEAD_INIT(http_res_keywords.list)
};

/*
 * Return the struct http_req_action_kw associated to a keyword.
 */
static struct action_kw *action_http_req_custom(const char *kw)
{
	return action_lookup(&http_req_keywords.list, kw);
}

/*
 * Return the struct http_res_action_kw associated to a keyword.
 */
static struct action_kw *action_http_res_custom(const char *kw)
{
	return action_lookup(&http_res_keywords.list, kw);
}

/* parse an "http-request" rule */
struct act_rule *parse_http_req_cond(const char **args, const char *file, int linenum, struct proxy *proxy)
{
	struct act_rule *rule;
	struct action_kw *custom = NULL;
	int cur_arg;
	char *error;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		goto out_err;
	}

	if (!strcmp(args[0], "allow")) {
		rule->action = ACT_ACTION_ALLOW;
		cur_arg = 1;
	} else if (!strcmp(args[0], "deny") || !strcmp(args[0], "block") || !strcmp(args[0], "tarpit")) {
		int code;
		int hc;

		if (!strcmp(args[0], "tarpit")) {
		    rule->action = ACT_HTTP_REQ_TARPIT;
		    rule->deny_status = HTTP_ERR_500;
		}
		else {
			rule->action = ACT_ACTION_DENY;
			rule->deny_status = HTTP_ERR_403;
		}
		cur_arg = 1;
                if (strcmp(args[cur_arg], "deny_status") == 0) {
                        cur_arg++;
                        if (!args[cur_arg]) {
                                ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : missing status code.\n",
					 file, linenum, proxy_type_str(proxy), proxy->id, args[0]);
                                goto out_err;
                        }

                        code = atol(args[cur_arg]);
                        cur_arg++;
                        for (hc = 0; hc < HTTP_ERR_SIZE; hc++) {
                                if (http_err_codes[hc] == code) {
                                        rule->deny_status = hc;
                                        break;
                                }
                        }

                        if (hc >= HTTP_ERR_SIZE) {
                                ha_warning("parsing [%s:%d] : status code %d not handled, using default code %d.\n",
					   file, linenum, code, http_err_codes[rule->deny_status]);
                        }
                }
	} else if (!strcmp(args[0], "auth")) {
		rule->action = ACT_HTTP_REQ_AUTH;
		cur_arg = 1;

		while(*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "realm")) {
				rule->arg.auth.realm = strdup(args[cur_arg + 1]);
				cur_arg+=2;
				continue;
			} else
				break;
		}
	} else if (!strcmp(args[0], "set-nice")) {
		rule->action = ACT_HTTP_SET_NICE;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (integer value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		rule->arg.nice = atoi(args[cur_arg]);
		if (rule->arg.nice < -1024)
			rule->arg.nice = -1024;
		else if (rule->arg.nice > 1024)
			rule->arg.nice = 1024;
		cur_arg++;
	} else if (!strcmp(args[0], "set-tos")) {
#ifdef IP_TOS
		char *err;
		rule->action = ACT_HTTP_SET_TOS;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.tos = strtol(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-request %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
#else
		ha_alert("parsing [%s:%d]: 'http-request %s' is not supported on this platform (IP_TOS undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-mark")) {
#ifdef SO_MARK
		char *err;
		rule->action = ACT_HTTP_SET_MARK;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.mark = strtoul(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-request %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
		global.last_checks |= LSTCHK_NETADM;
#else
		ha_alert("parsing [%s:%d]: 'http-request %s' is not supported on this platform (SO_MARK undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-log-level")) {
		rule->action = ACT_HTTP_SET_LOGL;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
		bad_log_level:
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument (log level name or 'silent').\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		if (strcmp(args[cur_arg], "silent") == 0)
			rule->arg.loglevel = -1;
		else if ((rule->arg.loglevel = get_log_level(args[cur_arg]) + 1) == 0)
			goto bad_log_level;
		cur_arg++;
	} else if (strcmp(args[0], "add-header") == 0 || strcmp(args[0], "set-header") == 0 ||
	           strcmp(args[0], "early-hint") == 0) {
		char **hdr_name;
		int *hdr_name_len;
		struct list *fmt;

		rule->action = *args[0] == 'a' ? ACT_HTTP_ADD_HDR :
		               *args[0] == 's' ? ACT_HTTP_SET_HDR : ACT_HTTP_EARLY_HINT;

		hdr_name     = *args[0] == 'e' ? &rule->arg.early_hint.name     : &rule->arg.hdr_add.name;
		hdr_name_len = *args[0] == 'e' ? &rule->arg.early_hint.name_len : &rule->arg.hdr_add.name_len;
		fmt          = *args[0] == 'e' ? &rule->arg.early_hint.fmt      : &rule->arg.hdr_add.fmt;

		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		*hdr_name = strdup(args[cur_arg]);
		*hdr_name_len = strlen(*hdr_name);
		LIST_INIT(fmt);

		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 2;
	} else if (strcmp(args[0], "replace-header") == 0 || strcmp(args[0], "replace-value") == 0) {
		rule->action = args[0][8] == 'h' ? ACT_HTTP_REPLACE_HDR : ACT_HTTP_REPLACE_VAL;
		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] || !*args[cur_arg+2] ||
		    (*args[cur_arg+3] && strcmp(args[cur_arg+3], "if") != 0 && strcmp(args[cur_arg+3], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 3 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);
		LIST_INIT(&rule->arg.hdr_add.fmt);

		error = NULL;
		if (!(rule->arg.hdr_add.re = regex_comp(args[cur_arg + 1], 1, 1, &error))) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 args[cur_arg + 1], error);
			free(error);
			goto out_err;
		}

		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 2], proxy, &rule->arg.hdr_add.fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 3;
	} else if (strcmp(args[0], "del-header") == 0) {
		rule->action = ACT_HTTP_DEL_HDR;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);

		proxy->conf.args.ctx = ARGC_HRQ;
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "track-sc", 8) == 0) {
		struct sample_expr *expr;
		unsigned int where;
		char *err = NULL;
		unsigned int tsc_num;
		const char *tsc_num_str;

		cur_arg = 1;
		proxy->conf.args.ctx = ARGC_TRK;

		tsc_num_str = &args[0][8];
		if (cfg_parse_track_sc_num(&tsc_num, tsc_num_str, tsc_num_str + strlen(tsc_num_str), &err) == -1) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], err);
			free(err);
			goto out_err;
		}

		expr = sample_parse_expr((char **)args, &cur_arg, file, linenum, &err, &proxy->conf.args);
		if (!expr) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], err);
			free(err);
			goto out_err;
		}

		where = 0;
		if (proxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (proxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;

		if (!(expr->fetch->val & where)) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule :"
				 " fetch method '%s' extracts information from '%s', none of which is available here.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0],
				 args[cur_arg-1], sample_src_names(expr->fetch->use));
			free(expr);
			goto out_err;
		}

		if (strcmp(args[cur_arg], "table") == 0) {
			cur_arg++;
			if (!args[cur_arg]) {
				ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : missing table name.\n",
					 file, linenum, proxy_type_str(proxy), proxy->id, args[0]);
				free(expr);
				goto out_err;
			}
			/* we copy the table name for now, it will be resolved later */
			rule->arg.trk_ctr.table.n = strdup(args[cur_arg]);
			cur_arg++;
		}
		rule->arg.trk_ctr.expr = expr;
		rule->action = ACT_ACTION_TRK_SC0 + tsc_num;
		rule->check_ptr = check_trk_action;
	} else if (strcmp(args[0], "redirect") == 0) {
		struct redirect_rule *redir;
		char *errmsg = NULL;

		if ((redir = http_parse_redirect_rule(file, linenum, proxy, (const char **)args + 1, &errmsg, 1, 0)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			goto out_err;
		}

		/* this redirect rule might already contain a parsed condition which
		 * we'll pass to the http-request rule.
		 */
		rule->action = ACT_HTTP_REDIR;
		rule->arg.redir = redir;
		rule->cond = redir->cond;
		redir->cond = NULL;
		cur_arg = 2;
		return rule;
	} else if (strncmp(args[0], "add-acl", 7) == 0) {
		/* http-request add-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_ADD_ACL;
		/*
		 * '+ 8' for 'add-acl('
		 * '- 9' for 'add-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "del-acl", 7) == 0) {
		/* http-request del-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_ACL;
		/*
		 * '+ 8' for 'del-acl('
		 * '- 9' for 'del-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "del-map", 7) == 0) {
		/* http-request del-map(<reference (map name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_MAP;
		/*
		 * '+ 8' for 'del-map('
		 * '- 9' for 'del-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "set-map", 7) == 0) {
		/* http-request set-map(<reference (map name)>) <key pattern> <value pattern> */
		rule->action = ACT_HTTP_SET_MAP;
		/*
		 * '+ 8' for 'set-map('
		 * '- 9' for 'set-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		LIST_INIT(&rule->arg.map.value);
		proxy->conf.args.ctx = ARGC_HRQ;

		/* key pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' key: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		/* value pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, &rule->arg.map.value, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-request %s' pattern: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;

		cur_arg += 2;
	} else if (((custom = action_http_req_custom(args[0])) != NULL)) {
		char *errmsg = NULL;
		cur_arg = 1;
		/* try in the module list */
		rule->from = ACT_F_HTTP_REQ;
		rule->kw = custom;
		if (custom->parse(args, &cur_arg, proxy, rule, &errmsg) == ACT_RET_PRS_ERR) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-request %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
	} else {
		action_build_list(&http_req_keywords.list, &trash);
		ha_alert("parsing [%s:%d]: 'http-request' expects 'allow', 'deny', 'auth', 'redirect', "
			 "'tarpit', 'add-header', 'set-header', 'replace-header', 'replace-value', 'set-nice', "
			 "'set-tos', 'set-mark', 'set-log-level', 'add-acl', 'del-acl', 'del-map', 'set-map', 'track-sc*'"
			 "%s%s, but got '%s'%s.\n",
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
		ha_alert("parsing [%s:%d]: 'http-request %s' expects 'realm' for 'auth',"
			 " 'deny_status' for 'deny', or"
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
	char *error;

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
		goto out_err;
	}

	if (!strcmp(args[0], "allow")) {
		rule->action = ACT_ACTION_ALLOW;
		cur_arg = 1;
	} else if (!strcmp(args[0], "deny")) {
		rule->action = ACT_ACTION_DENY;
		cur_arg = 1;
	} else if (!strcmp(args[0], "set-nice")) {
		rule->action = ACT_HTTP_SET_NICE;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (integer value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		rule->arg.nice = atoi(args[cur_arg]);
		if (rule->arg.nice < -1024)
			rule->arg.nice = -1024;
		else if (rule->arg.nice > 1024)
			rule->arg.nice = 1024;
		cur_arg++;
	} else if (!strcmp(args[0], "set-tos")) {
#ifdef IP_TOS
		char *err;
		rule->action = ACT_HTTP_SET_TOS;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.tos = strtol(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-response %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
#else
		ha_alert("parsing [%s:%d]: 'http-response %s' is not supported on this platform (IP_TOS undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-mark")) {
#ifdef SO_MARK
		char *err;
		rule->action = ACT_HTTP_SET_MARK;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (integer/hex value).\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.mark = strtoul(args[cur_arg], &err, 0);
		if (err && *err != '\0') {
			ha_alert("parsing [%s:%d]: invalid character starting at '%s' in 'http-response %s' (integer/hex value expected).\n",
				 file, linenum, err, args[0]);
			goto out_err;
		}
		cur_arg++;
		global.last_checks |= LSTCHK_NETADM;
#else
		ha_alert("parsing [%s:%d]: 'http-response %s' is not supported on this platform (SO_MARK undefined).\n", file, linenum, args[0]);
		goto out_err;
#endif
	} else if (!strcmp(args[0], "set-log-level")) {
		rule->action = ACT_HTTP_SET_LOGL;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg + 1] && strcmp(args[cur_arg + 1], "if") != 0 && strcmp(args[cur_arg + 1], "unless") != 0)) {
		bad_log_level:
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument (log level name or 'silent').\n",
				 file, linenum, args[0]);
			goto out_err;
		}
		if (strcmp(args[cur_arg], "silent") == 0)
			rule->arg.loglevel = -1;
		else if ((rule->arg.loglevel = get_log_level(args[cur_arg]) + 1) == 0)
			goto bad_log_level;
		cur_arg++;
	} else if (strcmp(args[0], "add-header") == 0 || strcmp(args[0], "set-header") == 0) {
		rule->action = *args[0] == 'a' ? ACT_HTTP_ADD_HDR : ACT_HTTP_SET_HDR;
		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);
		LIST_INIT(&rule->arg.hdr_add.fmt);

		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, &rule->arg.hdr_add.fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 2;
	} else if (strcmp(args[0], "replace-header") == 0 || strcmp(args[0], "replace-value") == 0) {
		rule->action = args[0][8] == 'h' ? ACT_HTTP_REPLACE_HDR : ACT_HTTP_REPLACE_VAL;
		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] || !*args[cur_arg+2] ||
		    (*args[cur_arg+3] && strcmp(args[cur_arg+3], "if") != 0 && strcmp(args[cur_arg+3], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 3 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);
		LIST_INIT(&rule->arg.hdr_add.fmt);

		error = NULL;
		if (!(rule->arg.hdr_add.re = regex_comp(args[cur_arg + 1], 1, 1, &error))) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 args[cur_arg + 1], error);
			free(error);
			goto out_err;
		}

		proxy->conf.args.ctx = ARGC_HRQ;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 2], proxy, &rule->arg.hdr_add.fmt, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 3;
	} else if (strcmp(args[0], "del-header") == 0) {
		rule->action = ACT_HTTP_DEL_HDR;
		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		rule->arg.hdr_add.name = strdup(args[cur_arg]);
		rule->arg.hdr_add.name_len = strlen(rule->arg.hdr_add.name);

		proxy->conf.args.ctx = ARGC_HRS;
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "add-acl", 7) == 0) {
		/* http-request add-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_ADD_ACL;
		/*
		 * '+ 8' for 'add-acl('
		 * '- 9' for 'add-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;

		cur_arg += 1;
	} else if (strncmp(args[0], "del-acl", 7) == 0) {
		/* http-response del-acl(<reference (acl name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_ACL;
		/*
		 * '+ 8' for 'del-acl('
		 * '- 9' for 'del-acl(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s': %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "del-map", 7) == 0) {
		/* http-response del-map(<reference (map name)>) <key pattern> */
		rule->action = ACT_HTTP_DEL_MAP;
		/*
		 * '+ 8' for 'del-map('
		 * '- 9' for 'del-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] ||
		    (*args[cur_arg+1] && strcmp(args[cur_arg+1], "if") != 0 && strcmp(args[cur_arg+1], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 1 argument.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		proxy->conf.args.ctx = ARGC_HRS;
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}
		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;
		cur_arg += 1;
	} else if (strncmp(args[0], "set-map", 7) == 0) {
		/* http-response set-map(<reference (map name)>) <key pattern> <value pattern> */
		rule->action = ACT_HTTP_SET_MAP;
		/*
		 * '+ 8' for 'set-map('
		 * '- 9' for 'set-map(' + trailing ')'
		 */
		rule->arg.map.ref = my_strndup(args[0] + 8, strlen(args[0]) - 9);

		cur_arg = 1;

		if (!*args[cur_arg] || !*args[cur_arg+1] ||
		    (*args[cur_arg+2] && strcmp(args[cur_arg+2], "if") != 0 && strcmp(args[cur_arg+2], "unless") != 0)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' expects exactly 2 arguments.\n",
				 file, linenum, args[0]);
			goto out_err;
		}

		LIST_INIT(&rule->arg.map.key);
		LIST_INIT(&rule->arg.map.value);

		proxy->conf.args.ctx = ARGC_HRS;

		/* key pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg], proxy, &rule->arg.map.key, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' name: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		/* value pattern */
		error = NULL;
		if (!parse_logformat_string(args[cur_arg + 1], proxy, &rule->arg.map.value, LOG_OPT_HTTP,
		                            (proxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR, &error)) {
			ha_alert("parsing [%s:%d]: 'http-response %s' value: %s.\n",
				 file, linenum, args[0], error);
			free(error);
			goto out_err;
		}

		free(proxy->conf.lfs_file);
		proxy->conf.lfs_file = strdup(proxy->conf.args.file);
		proxy->conf.lfs_line = proxy->conf.args.line;

		cur_arg += 2;
	} else if (strcmp(args[0], "redirect") == 0) {
		struct redirect_rule *redir;
		char *errmsg = NULL;

		if ((redir = http_parse_redirect_rule(file, linenum, proxy, (const char **)args + 1, &errmsg, 1, 1)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			goto out_err;
		}

		/* this redirect rule might already contain a parsed condition which
		 * we'll pass to the http-request rule.
		 */
		rule->action = ACT_HTTP_REDIR;
		rule->arg.redir = redir;
		rule->cond = redir->cond;
		redir->cond = NULL;
		cur_arg = 2;
		return rule;
	} else if (strncmp(args[0], "track-sc", 8) == 0) {
		struct sample_expr *expr;
		unsigned int where;
		char *err = NULL;
		unsigned int tsc_num;
		const char *tsc_num_str;

		cur_arg = 1;
		proxy->conf.args.ctx = ARGC_TRK;

		tsc_num_str = &args[0][8];
		if (cfg_parse_track_sc_num(&tsc_num, tsc_num_str, tsc_num_str + strlen(tsc_num_str), &err) == -1) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], err);
			free(err);
			goto out_err;
		}

		expr = sample_parse_expr((char **)args, &cur_arg, file, linenum, &err, &proxy->conf.args);
		if (!expr) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], err);
			free(err);
			goto out_err;
		}

		where = 0;
		if (proxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRS_HDR;
		if (proxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRS_HDR;

		if (!(expr->fetch->val & where)) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule :"
				 " fetch method '%s' extracts information from '%s', none of which is available here.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0],
				 args[cur_arg-1], sample_src_names(expr->fetch->use));
			free(expr);
			goto out_err;
		}

		if (strcmp(args[cur_arg], "table") == 0) {
			cur_arg++;
			if (!args[cur_arg]) {
				ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : missing table name.\n",
					 file, linenum, proxy_type_str(proxy), proxy->id, args[0]);
				free(expr);
				goto out_err;
			}
			/* we copy the table name for now, it will be resolved later */
			rule->arg.trk_ctr.table.n = strdup(args[cur_arg]);
			cur_arg++;
		}
		rule->arg.trk_ctr.expr = expr;
		rule->action = ACT_ACTION_TRK_SC0 + tsc_num;
		rule->check_ptr = check_trk_action;
	} else if (((custom = action_http_res_custom(args[0])) != NULL)) {
		char *errmsg = NULL;
		cur_arg = 1;
		/* try in the module list */
		rule->from = ACT_F_HTTP_RES;
		rule->kw = custom;
		if (custom->parse(args, &cur_arg, proxy, rule, &errmsg) == ACT_RET_PRS_ERR) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing 'http-response %s' rule : %s.\n",
				 file, linenum, proxy_type_str(proxy), proxy->id, args[0], errmsg);
			free(errmsg);
			goto out_err;
		}
	} else {
		action_build_list(&http_res_keywords.list, &trash);
		ha_alert("parsing [%s:%d]: 'http-response' expects 'allow', 'deny', 'redirect', "
			 "'add-header', 'del-header', 'set-header', 'replace-header', 'replace-value', 'set-nice', "
			 "'set-tos', 'set-mark', 'set-log-level', 'add-acl', 'del-acl', 'del-map', 'set-map', 'track-sc*'"
			 "%s%s, but got '%s'%s.\n",
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
	unsigned int flags = REDIRECT_FLAG_NONE;
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
		else if (!strcmp(args[cur_arg],"drop-query")) {
			flags |= REDIRECT_FLAG_DROP_QS;
		}
		else if (!strcmp(args[cur_arg],"append-slash")) {
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

void free_http_res_rules(struct list *r)
{
	struct act_rule *tr, *pr;

	list_for_each_entry_safe(pr, tr, r, list) {
		LIST_DEL(&pr->list);
		regex_free(pr->arg.hdr_add.re);
		free(pr);
	}
}

void free_http_req_rules(struct list *r)
{
	struct act_rule *tr, *pr;

	list_for_each_entry_safe(pr, tr, r, list) {
		LIST_DEL(&pr->list);
		if (pr->action == ACT_HTTP_REQ_AUTH)
			free(pr->arg.auth.realm);

		regex_free(pr->arg.hdr_add.re);
		free(pr);
	}
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
