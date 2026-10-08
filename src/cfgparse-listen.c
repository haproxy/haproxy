#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <haproxy/acl.h>
#include <haproxy/buf.h>
#include <haproxy/capture-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/compression-t.h>
#include <haproxy/connection.h>
#include <haproxy/extcheck.h>
#include <haproxy/hstream.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_ext.h>
#include <haproxy/http_rules.h>
#include <haproxy/mailers-t.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/peers.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/stick_table.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth.h>

/* some keywords that are still being parsed using strcmp() and are not
 * registered anywhere. They are used as suggestions for mistyped words.
 * DO NOT ADD ANY NEW KEYWORDS HERE, THAT MUST NO LONGER BE NECESSARY!
 */
static const char *common_kw_list[] = {
	"listen", "frontend", "backend", "defaults",
	NULL /* must be last */
};

/* Options which are not described in the cfg_opts* arrays because they need a
 * dedicated parsing, and which are only used as suggestions for mistyped
 * words. This list must be kept in sync with the options which have a
 * dedicated parsing below.
 */
static const char *common_options[] = {
	"accept-invalid-http-request", "accept-invalid-http-response",
	"external-check", "forceclose", "forwarded", "forwardfor",
	"http-keep-alive", "http-restrict-req-hdr-names",
	"http-server-close", "http-tunnel", "http_proxy", "httpchk",
	"httpclose", "httplog", "httpslog", "ldap-check", "mysql-check",
	"originalto", "pgsql-check", "redis-check", "redispatch", "smtpchk",
#if defined(USE_SPOE)
	"spop-check",
#endif
	"ssl-hello-chk", "tcp-check", "tcpka", "tcplog",
	"use-small-buffers",
	NULL /* must be last */
};

/* Report a warning if a rule is placed after a 'tcp-request connection' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_tcp_conn(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->tcp_req.l4_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after a 'tcp-request connection' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'tcp-request session' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_tcp_sess(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->tcp_req.l5_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after a 'tcp-request session' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'tcp-request content' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_tcp_cont(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->tcp_req.inspect_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after a 'tcp-request content' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'monitor fail' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_monitor(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->mon_fail_cond)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after a 'monitor fail' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after an 'http_request' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_http_req(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->http_req_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after an 'http-request' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after an 'http_response' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_http_res(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->http_res_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after an 'http-response' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a redirect rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_redirect(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->redirect_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after a 'redirect' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'use_backend' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_use_backend(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->switching_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after a 'use_backend' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'use-server' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
static int warnif_rule_after_use_server(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	if (!LIST_ISEMPTY(&proxy->server_rules)) {
		ha_warning("parsing [%s:%d] : a '%s%s%s' rule placed after a 'use-server' rule will still be processed before.\n",
			   file, line, arg1, (arg2 ? " ": ""), (arg2 ? arg2 : ""));
		return 1;
	}
	return 0;
}

/* report a warning if a redirect rule is dangerously placed */
static int warnif_misplaced_redirect(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return	warnif_rule_after_use_backend(proxy, file, line, arg1, arg2) ||
		warnif_rule_after_use_server(proxy, file, line, arg1, arg2);
}

/* report a warning if an http-request rule is dangerously placed */
static int warnif_misplaced_http_req(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return	warnif_rule_after_redirect(proxy, file, line, arg1, arg2) ||
		warnif_misplaced_redirect(proxy, file, line, arg1, arg2);
}

/* report a warning if a block rule is dangerously placed */
static int warnif_misplaced_monitor(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return	warnif_rule_after_http_req(proxy, file, line, arg1, arg2) ||
		warnif_misplaced_http_req(proxy, file, line, arg1, arg2);
}

/* report a warning if a "tcp request content" rule is dangerously placed */
int warnif_misplaced_tcp_req_cont(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return	warnif_rule_after_monitor(proxy, file, line, arg1, arg2) ||
		warnif_misplaced_monitor(proxy, file, line, arg1, arg2);
}

/* report a warning if a "tcp response content" rule is dangerously placed */
int warnif_misplaced_tcp_res_cont(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return	warnif_rule_after_http_res(proxy, file, line, arg1, arg2);
}

/* report a warning if a "tcp request session" rule is dangerously placed */
int warnif_misplaced_tcp_req_sess(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return	warnif_rule_after_tcp_cont(proxy, file, line, arg1, arg2) ||
		warnif_misplaced_tcp_req_cont(proxy, file, line, arg1, arg2);
}

/* report a warning if a "tcp request connection" rule is dangerously placed */
int warnif_misplaced_tcp_req_conn(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return	warnif_rule_after_tcp_sess(proxy, file, line, arg1, arg2) ||
		warnif_misplaced_tcp_req_sess(proxy, file, line, arg1, arg2);
}

int warnif_misplaced_quic_init(struct proxy *proxy, const char *file, int line, const char *arg1, const char *arg2)
{
	return warnif_rule_after_tcp_conn(proxy, file, line, arg1, arg2) ||
	       warnif_misplaced_tcp_req_conn(proxy, file, line, arg1, arg2);
}

/* helper function that checks for a match in cfg_opt array, for a given
 * input args, capability (if <cap> != PR_CAP_NONE) and mode (if <mode> != PR_MODES)
 *
 * <options> and <no_options> will be set according to <kwm> if an option matches
 *
 * Returns 1 on success and 0 if no match
 * <err_code> is updated accordingly and must be checked upon return
 */
int cfg_parse_listen_match_option(const char *file, int linenum, int kwm,
                                  const struct cfg_opt config_opts[], int *err_code,
                                  char **args, int mode, int cap,
                                  int *options, int *no_options)
{
	int optnum;

	for (optnum = 0; config_opts[optnum].name; optnum++) {
		if (strcmp(args[1], config_opts[optnum].name) == 0) {
			if (config_opts[optnum].cap == PR_CAP_NONE) {
				if (config_opts[optnum].val)
					ha_alert("parsing [%s:%d]: support for option '%s' was removed in version %u.%u.\n",
					         file, linenum, config_opts[optnum].name,
					         (config_opts[optnum].val >> 8) & 0xff,
					         config_opts[optnum].val & 0xff);
				else
					ha_alert("parsing [%s:%d]: option '%s' is not supported due to build options.\n",
					         file, linenum, config_opts[optnum].name);

				*err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if ((mode != PR_MODES && !(config_opts[optnum].mode & mode)) ||
			    (cap != PR_CAP_NONE && !(config_opts[optnum].cap & cap))) {
				ha_alert("parsing [%s:%d]: option '%s' is not supported in this section.\n",
				         file, linenum, config_opts[optnum].name);
				*err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, err_code))
				goto out;
			if (warnifnotcap(curproxy, config_opts[optnum].cap, file, linenum, args[1], NULL)) {
				*err_code |= ERR_WARN;
				goto out;
			}

			*no_options &= ~config_opts[optnum].val;
			*options &= ~config_opts[optnum].val;

			switch (kwm) {
				case KWM_STD:
					*options |= config_opts[optnum].val;
					break;
				case KWM_NO:
					*no_options |= config_opts[optnum].val;
					break;
				case KWM_DEF: /* already cleared */
					break;
			}
			return 1;
		}
	}
 out:
	return 0;
}

/* main proxy section keyword parser */
int cfg_parse_listen(const char *file, int linenum, char **args, int kwm)
{
	static struct proxy *curr_defproxy = NULL;
	struct cfg_kw_list *kwl;
	const char *err, *best;
	int rc, index;
	int err_code = 0;
	char *errmsg = NULL;
	const char *file_prev = NULL;
	int line_prev = 0;

	if (!last_defproxy) {
		/* we need a default proxy and none was created yet */
		last_defproxy = alloc_new_proxy("", PR_CAP_DEF|PR_CAP_LISTEN, &errmsg);

		curr_defproxy = last_defproxy;
		if (!last_defproxy) {
			ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
	}

	if (strcmp(args[0], "listen") == 0)
		rc = PR_CAP_LISTEN | PR_CAP_LB;
	else if (strcmp(args[0], "frontend") == 0)
		rc = PR_CAP_FE | PR_CAP_LB;
	else if (strcmp(args[0], "backend") == 0)
		rc = PR_CAP_BE | PR_CAP_LB;
	else if (strcmp(args[0], "defaults") == 0) {
		/* "defaults" must first delete the last no-name defaults if any */
		curr_defproxy = NULL;
		rc = PR_CAP_DEF | PR_CAP_LISTEN;
	}
	else
		rc = PR_CAP_NONE;

	if ((rc & PR_CAP_LISTEN) && !(rc & PR_CAP_DEF)) {  /* new proxy */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an <id> argument\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		curproxy = NULL;
		if (rc & PR_CAP_FE)
			curproxy = proxy_fe_by_name(args[1]);

		if (!curproxy && (rc & PR_CAP_BE))
			curproxy = proxy_be_by_name(args[1]);

		if (curproxy) {
			/* same capability in common: always forbidden */
			ha_alert("Parsing [%s:%d]: %s '%s' has the same name as %s '%s' declared at %s:%d.\n",
				 file, linenum, proxy_cap_str(rc), args[1], proxy_type_str(curproxy),
				 curproxy->id, curproxy->conf.file, curproxy->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (*args[2] && (!*args[3] || strcmp(args[2], "from") != 0)) {
			/* the only form taking arguments is "<kw> <name> from <defaults>" */
			if (rc & PR_CAP_FE)
				ha_alert("parsing [%s:%d] : please use the 'bind' keyword for listening addresses.\n", file, linenum);
			else
				ha_alert("parsing [%s:%d] : '%s' cannot handle unexpected argument '%s'.\n",
					 file, linenum, args[0], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (alertif_too_many_args(3, file, linenum, args, &err_code))
			goto out;
	}

	if (rc & PR_CAP_LISTEN) {  /* new proxy or defaults section */
		const char *name = args[1];
		int arg = 2;

		/* conflict with log-forward forbidden for listen/frontend/backend/defaults */
		curproxy = log_forward_by_name(args[1]);
		if (curproxy) {
			ha_alert("Parsing [%s:%d]: %s '%s' has the same name as log forward section '%s' declared at %s:%d.\n",
			         file, linenum, proxy_cap_str(rc), args[1],
			         curproxy->id, curproxy->conf.file, curproxy->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (rc & PR_CAP_DEF) {
			/* If last defaults is unnamed, it will be made
			 * invisible by the current newer section. It must be
			 * freed unless it is still referenced by proxies.
			 */
			if (last_defproxy && last_defproxy->id[0] == '\0' &&
			    !last_defproxy->conf.def_ref) {
				defaults_px_destroy(last_defproxy);
			}
			last_defproxy = NULL;

			/* If current defaults is named, check collision with previous instances. */
			if (*args[1]) {
				curproxy = proxy_find_by_name(args[1], PR_CAP_DEF, 0);

				/* for default proxies, if another one has the same
				 * name and was explicitly referenced, this is an error
				 * that we must reject. E.g.
				 *     defaults def
				 *     backend bck from def
				 *     defaults def
				 */
				if (curproxy && curproxy->flags & PR_FL_EXPLICIT_REF) {
					ha_alert("Parsing [%s:%d]: %s '%s' has the same name as another defaults section declared at"
						 " %s:%d which was explicitly referenced hence cannot be replaced. Please remove or"
						 " rename one of the offending defaults section.\n",
						 file, linenum, proxy_cap_str(rc), args[1],
						 curproxy->conf.file, curproxy->conf.line);
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}

				/* if the other proxy exists, we don't need to keep it
				 * since neither will support being explicitly referenced
				 * so let's drop it from the index but keep a reference to
				 * its location for error messages.
				 */
				if (curproxy) {
					file_prev = curproxy->conf.file;
					line_prev = curproxy->conf.line;
					defaults_px_detach(curproxy);
					curproxy = NULL;
				}
			}
		}

		curproxy = proxy_find_by_name(args[1], 0, 0);
		if (!curproxy && !(rc & PR_CAP_DEF))
			curproxy = proxy_find_by_name(args[1], PR_CAP_DEF, 0);

		if (curproxy) {
			/* different capabilities but still same name: forbidden soon */
			ha_alert("Parsing [%s:%d]: %s '%s' has the same name as %s '%s' declared at %s:%d."
				 " This is no longer supported as of 3.3. Please rename one or the other.\n",
				   file, linenum, proxy_cap_str(rc), args[1], proxy_type_str(curproxy),
				   curproxy->id, curproxy->conf.file, curproxy->conf.line);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (rc & PR_CAP_DEF && strcmp(args[1], "from") == 0 && *args[2] && !*args[3]) {
			// also support "defaults from blah" (no name then)
			arg = 1;
			name = "";
		}

		/* only regular proxies inherit from the previous defaults section */
		if (!(rc & PR_CAP_DEF))
			curr_defproxy = last_defproxy;

		if (strcmp(args[arg], "from") == 0) {
			curr_defproxy = proxy_find_by_name(args[arg+1], PR_CAP_DEF, 0);

			if (!curr_defproxy) {
				ha_alert("parsing [%s:%d] : defaults section '%s' not found for %s '%s'.\n", file, linenum, args[arg+1], proxy_cap_str(rc), name);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if (curr_defproxy->conf.line_prev) {
				ha_alert("parsing [%s:%d] : ambiguous defaults section name '%s' referenced by %s '%s' exists at least at %s:%d and %s:%d.\n",
					 file, linenum, args[arg+1], proxy_cap_str(rc), name,
					 curr_defproxy->conf.file, curr_defproxy->conf.line,
					 curr_defproxy->conf.file_prev, curr_defproxy->conf.line_prev);
				err_code |= ERR_ALERT | ERR_FATAL;
			}

			err = invalid_char(args[arg+1]);
			if (err) {
				ha_alert("parsing [%s:%d] : character '%c' is not permitted in defaults section name '%s' when designated by its name (section found at %s:%d).\n",
					 file, linenum, *err, args[arg+1], curr_defproxy->conf.file, curr_defproxy->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
			curr_defproxy->flags |= PR_FL_EXPLICIT_REF;
		}
		else if (curr_defproxy)
			curr_defproxy->flags |= PR_FL_IMPLICIT_REF;

		if (curr_defproxy && (curr_defproxy->flags & (PR_FL_EXPLICIT_REF|PR_FL_IMPLICIT_REF)) == (PR_FL_EXPLICIT_REF|PR_FL_IMPLICIT_REF)) {
			ha_warning("parsing [%s:%d] : defaults section '%s' (declared at %s:%d) is explicitly referenced by another proxy and implicitly used here."
				   " To avoid any ambiguity don't mix both usage. Add a last defaults section not explicitly used or always use explicit references.\n",
				   file, linenum, curr_defproxy->id, curr_defproxy->conf.file, curr_defproxy->conf.line);
			err_code |= ERR_WARN;
		}

		curproxy = parse_new_proxy(name, rc, file, linenum, curr_defproxy);
		if (!curproxy) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curproxy->conf.file_prev = file_prev;
		curproxy->conf.line_prev = line_prev;

		if (curr_defproxy) {
			int ret = proxy_ref_defaults(curproxy, curr_defproxy, &errmsg);

			if (ret)
				ha_alert("parsing [%s:%d]: %s.\n", file, linenum, errmsg);
			err_code |= ret;
		}

		if (rc & PR_CAP_DEF) {
			LIST_APPEND(&defaults_list, &curproxy->el);
			/* last and current proxies must be updated to this one */
			curr_defproxy = last_defproxy = curproxy;
		} else {
			/* regular proxies are in a list */
			main_proxies_register(curproxy);
		}
		goto out;
	}
	else if (curproxy == NULL) {
		ha_alert("parsing [%s:%d] : 'listen' or 'defaults' expected.\n", file, linenum);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	/* update the current file and line being parsed */
	curproxy->conf.args.file = curproxy->conf.file;
	curproxy->conf.args.line = linenum;

	/* Now let's parse the proxy-specific keywords */
	list_for_each_entry(kwl, &cfg_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].section != CFG_LISTEN)
				continue;
			if (strcmp(kwl->kw[index].kw, args[0]) != 0)
				continue;

			if (check_kw_experimental(&kwl->kw[index], file, linenum, &errmsg)) {
				ha_alert("%s\n", errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			rc = kwl->kw[index].parse(args, CFG_LISTEN, curproxy, curr_defproxy, file, linenum, &errmsg);
			if (rc < 0) {
				if (errmsg)
					ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
			else if (rc > 0) {
				if (errmsg)
					ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
				err_code |= ERR_WARN;
			}
			goto out;
		}
	}

	best = cfg_find_best_match(args[0], &cfg_keywords.list, CFG_LISTEN, common_kw_list);
	if (best)
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n", file, linenum, args[0], cursection, best);
	else
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
	err_code |= ERR_ALERT | ERR_FATAL;

 out:
	free(errmsg);
	return err_code;
}

/* Keywords which are not supported anymore. They are still parsed so that a
 * helpful message can be emitted, pointing at the modern equivalent when there
 * is one. The message is built as "the '<kw>' keyword is not supported anymore
 * [since HAProxy <ver>]." optionally followed by <hint>.
 */
static const struct {
	const char *kw;
	const char *ver;
	const char *hint;
} removed_kw_list[] = {
	{ "appsession",   "1.6", NULL },
	{ "bind-process", "2.7", NULL },
	{ "block",        "2.1", "Use 'http-request deny' which uses the exact same syntax." },
	{ "cliexp",       "2.1", "Use 'http-request replace-path', 'http-request replace-uri' or 'http-request replace-header' instead." },
	{ "grace",        "2.5", NULL },
	{ "redisp",       "2.1", "Use 'option redispatch'." },
	{ "redispatch",   "2.1", "Use 'option redispatch'." },
	{ "reqadd",       "2.1", "Use 'http-request add-header' instead." },
	{ "reqallow",     "2.1", "Use 'http-request allow' instead." },
	{ "reqdel",       "2.1", "Use 'http-request del-header' instead." },
	{ "reqdeny",      "2.1", "Use 'http-request deny' instead." },
	{ "reqiallow",    "2.1", "Use 'http-request allow' instead." },
	{ "reqidel",      "2.1", "Use 'http-request del-header' instead." },
	{ "reqideny",     "2.1", "Use 'http-request deny' instead." },
	{ "reqipass",     "2.1", NULL },
	{ "reqirep",      "2.1", "Use 'http-request replace-header' instead." },
	{ "reqitarpit",   "2.1", "Use 'http-request tarpit' instead." },
	{ "reqpass",      "2.1", NULL },
	{ "reqrep",       "2.1", "Use 'http-request replace-path', 'http-request replace-uri' or 'http-request replace-header' instead." },
	{ "reqtarpit",    "2.1", "Use 'http-request tarpit' instead." },
	{ "rspadd",       "2.1", "Use 'http-response add-header' instead." },
	{ "rspdel",       "2.1", "Use 'http-response del-header' instead." },
	{ "rspdeny",      "2.1", "Use 'http-response deny' instead." },
	{ "rspidel",      "2.1", "Use 'http-response del-header' instead." },
	{ "rspideny",     "2.1", "Use 'http-response deny' instead." },
	{ "rspirep",      "2.1", "Use 'http-response replace-header' instead." },
	{ "rsprep",       "2.1", "Use 'http-response replace-header' instead." },
	{ "srvexp",       "2.1", "Use 'http-response replace-header' instead." },
	{ "transparent",  "3.5", "The modern way to do the same is to create a server with address 0.0.0.0." },
	{ NULL, NULL, NULL } /* must be last */
};

/* Parses the proxy keywords which are not supported anymore, and only reports
 * what to use instead.
 */
static int proxy_parse_removed_kw(char **args, int section_type, struct proxy *curpx,
                                  const struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	int i;

	/* these two report the argument they were passed, so they can't be
	 * described by a static message.
	 */
	if (strcmp(args[0], "monitor-net") == 0) {
		memprintf(err, "the '%s' keyword is not supported anymore. "
			  "Please use 'http-request return status 200 if { src %s }' instead.",
			  args[0], args[1]);
		return -1;
	}

	if (strcmp(args[0], "dispatch") == 0) {
		memprintf(err, "the '%s' keyword is not supported anymore since HAProxy 3.5. "
			  "The modern way to do the same is to create a server with the same address, "
			  "and possibly to assign any extra server a weight of zero if any:\n"
			  "    server dispatch %s", args[0], args[1]);
		return -1;
	}

	for (i = 0; removed_kw_list[i].kw; i++) {
		if (strcmp(args[0], removed_kw_list[i].kw) != 0)
			continue;

		if (removed_kw_list[i].ver)
			memprintf(err, "the '%s' keyword is not supported anymore since HAProxy %s.",
				  args[0], removed_kw_list[i].ver);
		else
			memprintf(err, "the '%s' keyword is not supported anymore.", args[0]);

		if (removed_kw_list[i].hint)
			memprintf(err, "%s %s", *err, removed_kw_list[i].hint);

		return -1;
	}

	BUG_ON(1, "unhandled keyword in proxy_parse_removed_kw().");
	return -1;
}

/* Parses the "disabled" and "enabled" keywords, which mark this proxy as
 * disabled or not. "enabled" is mostly used to revert a "disabled" inherited
 * from a defaults section.
 */
static int proxy_parse_enabled(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;

	if (strcmp(args[0], "disabled") == 0)
		curpx->flags |= PR_FL_DISABLED;
	else if (strcmp(args[0], "enabled") == 0)
		curpx->flags &= ~PR_FL_DISABLED;
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_enabled().");
		return -1;
	}

	return 0;
}

/* Parses the proxy keywords which limit the number of connections:
 * "maxconn", "backlog", "fullconn" and "max-session-srv-conns". They all take
 * a single integer argument.
 */
static int proxy_parse_conn_limits(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument.", args[0]);
		return -1;
	}

	if (strcmp(args[0], "maxconn") == 0) {
		warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], " Maybe you want 'fullconn' instead ?");
		curpx->maxconn = atol(args[1]);
	}
	else if (strcmp(args[0], "backlog") == 0) {
		warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], NULL);
		curpx->backlog = atol(args[1]);
	}
	else if (strcmp(args[0], "fullconn") == 0) {
		warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], " Maybe you want 'maxconn' instead ?");
		curpx->fullconn = atol(args[1]);
	}
	else if (strcmp(args[0], "max-session-srv-conns") == 0) {
		warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], NULL);
		curpx->max_out_conns = atoi(args[1]);
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_conn_limits().");
		return -1;
	}

	return 0;
}

/* Parses the proxy keywords which only make sense on a backend and which take
 * a single argument: "retries", "http-reuse", "http-send-name-header",
 * "dynamic-cookie-key", "load-server-state-from-file" and
 * "server-state-file-name".
 */
static int proxy_parse_be_opts(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL);

	if (strcmp(args[0], "retries") == 0) {  /* connection retries */
		if (too_many_args(1, args, err, NULL))
			return -1;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument (dispatch counts for one).", args[0]);
			return -1;
		}
		curpx->conn_retries = atol(args[1]);
	}
	else if (strcmp(args[0], "http-reuse") == 0) {
		int reuse;

		if (too_many_args(1, args, err, NULL))
			return -1;

		if (strcmp(args[1], "never") == 0)
			reuse = PR_O_REUSE_NEVR;
		else if (strcmp(args[1], "safe") == 0)
			reuse = PR_O_REUSE_SAFE;
		else if (strcmp(args[1], "aggressive") == 0)
			reuse = PR_O_REUSE_AGGR;
		else if (strcmp(args[1], "always") == 0)
			reuse = PR_O_REUSE_ALWS;
		else {
			memprintf(err, "'%s' only supports 'never', 'safe', 'aggressive', 'always'.", args[0]);
			return -1;
		}

		curpx->options &= ~PR_O_REUSE_MASK;
		curpx->options |= reuse;
	}
	else if (strcmp(args[0], "http-send-name-header") == 0) { /* send server name in request header */
		if (!*args[1]) {
			memprintf(err, "'%s' requires a header string.", args[0]);
			return -1;
		}

		if (strcasecmp(args[1], "host") == 0 ||
		    strcasecmp(args[1], "content-length") == 0 ||
		    strcasecmp(args[1], "transfer-encoding") == 0 ||
		    strcasecmp(args[1], "connection") == 0) {
			memprintf(err, "'%s' cannot be used as header name for '%s' directive.", args[1], args[0]);
			return -1;
		}

		/* set the desired header name, in lower case */
		istfree(&curpx->server_id_hdr_name);
		curpx->server_id_hdr_name = istdup(ist(args[1]));
		if (!isttest(curpx->server_id_hdr_name))
			goto alloc_error;
		ist2bin_lc(istptr(curpx->server_id_hdr_name), curpx->server_id_hdr_name);
	}
	else if (strcmp(args[0], "dynamic-cookie-key") == 0) { /* Dynamic cookies secret key */
		char *key;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects <secret_key> as argument.", args[0]);
			return -1;
		}

		key = strdup(args[1]);
		if (!key)
			goto alloc_error;

		free(curpx->dyncookie_key);
		curpx->dyncookie_key = key;
	}
	else if (strcmp(args[0], "load-server-state-from-file") == 0) {
		if (strcmp(args[1], "global") == 0)  /* use the file pointed to by the global server-state-file directive */
			curpx->load_server_state_from_file = PR_SRV_STATE_FILE_GLOBAL;
		else if (strcmp(args[1], "local") == 0) /* use the server-state-file-name variable to locate the server-state file */
			curpx->load_server_state_from_file = PR_SRV_STATE_FILE_LOCAL;
		else if (strcmp(args[1], "none") == 0)  /* don't use server-state-file directive for this backend */
			curpx->load_server_state_from_file = PR_SRV_STATE_FILE_NONE;
		else {
			memprintf(err, "'%s' expects 'global', 'local' or 'none'. Got '%s'", args[0], args[1]);
			return -1;
		}
	}
	else if (strcmp(args[0], "server-state-file-name") == 0) {
		char *name;

		if (too_many_args(1, args, err, NULL))
			return -1;

		if (*(args[1]) == 0 || strcmp(args[1], "use-backend-name") == 0)
			name = strdup(curpx->id);
		else
			name = strdup(args[1]);

		if (!name)
			goto alloc_error;

		ha_free(&curpx->server_state_file_name);
		curpx->server_state_file_name = name;
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_be_opts().");
		return -1;
	}

	return 0;

 alloc_error:
	memprintf(err, "out of memory.");
	return -1;
}

/* Parses the "mode" keyword, which sets the proxy's operating mode. */
static int proxy_parse_mode(char **args, int section_type, struct proxy *curpx,
                            const struct proxy *defpx, const char *file, int line,
                            char **err)
{
	enum pr_mode mode;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (unlikely(strcmp(args[1], "health") == 0)) {
		memprintf(err, "'mode health' doesn't exist anymore. Please use 'http-request return status 200' instead.");
		return -1;
	}

	mode = str_to_proxy_mode(args[1]);
	if (!mode) {
		if (strcmp(args[1], "haterm") == 0) {
			if (!(curpx->cap & PR_CAP_FE)) {
				memprintf(err, "mode haterm is only applicable on proxies with frontend capability.");
				return -1;
			}
			mode = PR_MODE_HTTP;
			curpx->stream_new_from_sc = hstream_new;
		}
		else {
			memprintf(err, "unknown proxy mode '%s'.", args[1]);
			return -1;
		}
	}
	else if ((mode == PR_MODE_SYSLOG || mode == PR_MODE_SPOP) &&
		 !(curpx->cap & PR_CAP_BE)) {
		memprintf(err, "mode %s is only applicable on proxies with backend capability.", proxy_mode_str(mode));
		return -1;
	}
	else {
		/* valid mode, non "haterm" mode.
		 * Possibly restore the ->stream_new_from_sc() callback
		 * if set by default for "haterm" mode.
		 */
		curpx->stream_new_from_sc = stream_new;
	}

	curpx->mode = mode;
	if (curpx->cap & PR_CAP_DEF)
		curpx->flags |= PR_FL_DEF_EXPLICIT_MODE;

	return 0;
}

/* Parses the "id" and "description" keywords, which respectively assign a
 * numeric identifier and a description to this proxy. Neither is permitted in
 * a defaults section.
 */
static int proxy_parse_id_desc(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	if (curpx->cap & PR_CAP_DEF) {
		memprintf(err, "'%s' not allowed in 'defaults' section.", args[0]);
		return -1;
	}

	if (strcmp(args[0], "id") == 0) {
		struct proxy *conflict;

		if (too_many_args(1, args, err, NULL))
			return -1;

		if (!*args[1]) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}

		curpx->uuid = atol(args[1]);
		curpx->options |= PR_O_FORCED_ID;

		if (curpx->uuid <= 0) {
			memprintf(err, "custom id has to be > 0.");
			return -1;
		}

		conflict = proxy_find_by_id(curpx->uuid, 0, 0);
		if (conflict) {
			memprintf(err, "%s %s reuses same custom id as %s %s (declared at %s:%d).",
				  proxy_type_str(curpx), curpx->id,
				  proxy_type_str(conflict), conflict->id,
				  conflict->conf.file, conflict->conf.line);
			return -1;
		}
		proxy_index_id(curpx);
	}
	else if (strcmp(args[0], "description") == 0) {
		int i, len = 0;
		char *d;

		if (!*args[1]) {
			memprintf(err, "'%s' expects a string argument.", args[0]);
			return -1;
		}

		for (i = 1; *args[i]; i++)
			len += strlen(args[i]) + 1;

		d = calloc(1, len);
		if (!d) {
			memprintf(err, "out of memory.");
			return -1;
		}

		ha_free(&curpx->desc);
		curpx->desc = d;

		d += snprintf(d, curpx->desc + len - d, "%s", args[1]);
		for (i = 2; *args[i]; i++)
			d += snprintf(d, curpx->desc + len - d, " %s", args[i]);
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_id_desc().");
		return -1;
	}

	return 0;
}

/* Parses the "acl" keyword, which declares a named ACL. */
static int proxy_parse_acl(char **args, int section_type, struct proxy *curpx,
                           const struct proxy *defpx, const char *file, int line,
                           char **err)
{
	const char *errptr;
	char *errmsg = NULL;

	if ((curpx->cap & PR_CAP_DEF) && strlen(curpx->id) == 0) {
		memprintf(err, "'%s' not allowed in anonymous 'defaults' section.", args[0]);
		return -1;
	}

	errptr = invalid_char(args[1]);
	if (errptr) {
		memprintf(err, "character '%c' is not permitted in acl name '%s'.", *errptr, args[1]);
		return -1;
	}

	if (strcasecmp(args[1], "or") == 0) {
		memprintf(err, "acl name '%s' will never match. 'or' is used to express a "
			  "logical disjunction within a condition.", args[1]);
		return -1;
	}

	if (parse_acl((const char **)args + 1, &curpx->acl, &errmsg, &curpx->conf.args, file, line) == NULL) {
		memprintf(err, "error detected while parsing ACL '%s' : %s.", args[1], errmsg);
		free(errmsg);
		return -1;
	}

	return 0;
}

/* Parses the monitoring keywords "monitor-uri" and "monitor". Both require the
 * frontend capability.
 */
static int proxy_parse_monitor(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], NULL);

	if (strcmp(args[0], "monitor-uri") == 0) {  /* set the URI to intercept */
		if (too_many_args(1, args, err, NULL))
			return -1;

		if (!*args[1]) {
			memprintf(err, "'%s' expects an URI.", args[0]);
			return -1;
		}

		istfree(&curpx->monitor_uri);
		curpx->monitor_uri = istdup(ist(args[1]));
		if (!isttest(curpx->monitor_uri)) {
			memprintf(err, "out of memory.");
			return -1;
		}
	}
	else if (strcmp(args[0], "monitor") == 0) {
		struct acl_cond *cond;
		char *errmsg = NULL;

		if (curpx->cap & PR_CAP_DEF) {
			memprintf(err, "'%s' not allowed in 'defaults' section.", args[0]);
			return -1;
		}

		if (strcmp(args[1], "fail") == 0) {
			/* add a condition to fail monitor requests */
			if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
				memprintf(err, "'%s %s' requires either 'if' or 'unless' followed by a condition.",
				          args[0], args[1]);
				return -1;
			}

			warnif_misplaced_monitor(curpx, file, line, args[0], args[1]);

			cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args + 2, &errmsg);
			if (!cond) {
				memprintf(err, "error detected while parsing a '%s %s' condition : %s.",
				          args[0], args[1], errmsg);
				free(errmsg);
				return -1;
			}
			LIST_APPEND(&curpx->mon_fail_cond, &cond->list);
		}
		else {
			memprintf(err, "'%s' only supports 'fail'.", args[0]);
			return -1;
		}
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_monitor().");
		return -1;
	}

	return 0;
}

/* Parses the persistence keywords "persist", "force-persist" and
 * "ignore-persist".
 */
static int proxy_parse_persist(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	if (strcmp(args[0], "persist") == 0) {  /* persist */
		if (too_many_args(1, args, err, NULL))
			return -1;

		if (*(args[1]) == 0) {
			memprintf(err, "missing persist method.");
			return -1;
		}

		if (strncmp(args[1], "rdp-cookie", 10) != 0) {
			memprintf(err, "unknown persist method.");
			return -1;
		}

		curpx->options2 |= PR_O2_RDPC_PRST;

		if (*(args[1] + 10) == '(') { /* cookie name */
			const char *beg, *end;
			char *name;

			beg = args[1] + 11;
			end = strchr(beg, ')');

			if (!end || end == beg) {
				memprintf(err, "persist rdp-cookie(name)' requires an rdp cookie name.");
				return -1;
			}

			name = my_strndup(beg, end - beg);
			if (!name)
				goto alloc_error;

			free(curpx->rdp_cookie_name);
			curpx->rdp_cookie_name = name;
			curpx->rdp_cookie_len = end - beg;
		}
		else if (*(args[1] + 10) == '\0') { /* default cookie name 'msts' */
			char *name = strdup("msts");

			if (!name)
				goto alloc_error;

			free(curpx->rdp_cookie_name);
			curpx->rdp_cookie_name = name;
			curpx->rdp_cookie_len = strlen(name);
		}
		else { /* syntax */
			memprintf(err, "persist rdp-cookie(name)' requires an rdp cookie name.");
			return -1;
		}
	}
	else if (strcmp(args[0], "force-persist") == 0 ||
		 strcmp(args[0], "ignore-persist") == 0) {
		struct persist_rule *rule;
		struct acl_cond *cond;
		char *errmsg = NULL;

		if (curpx->cap & PR_CAP_DEF) {
			memprintf(err, "'%s' not allowed in 'defaults' section.", args[0]);
			return -1;
		}

		warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL);

		if (strcmp(args[1], "if") != 0 && strcmp(args[1], "unless") != 0) {
			memprintf(err, "'%s' requires either 'if' or 'unless' followed by a condition.", args[0]);
			return -1;
		}

		cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args + 1, &errmsg);
		if (!cond) {
			memprintf(err, "error detected while parsing a '%s' rule : %s.", args[0], errmsg);
			free(errmsg);
			return -1;
		}

		/* note: BE_REQ_CNT is the first one after FE_SET_BCK, which is
		 * where force-persist is applied.
		 */
		if (warnif_cond_conflicts(cond, SMP_VAL_BE_REQ_CNT, &errmsg))
			ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
		free(errmsg);

		rule = calloc(1, sizeof(*rule));
		if (!rule) {
			free_acl_cond(cond);
			goto alloc_error;
		}

		rule->cond = cond;
		rule->type = (args[0][0] == 'f') ? PERSIST_TYPE_FORCE : PERSIST_TYPE_IGNORE;
		LIST_INIT(&rule->list);
		LIST_APPEND(&curpx->persist_rules, &rule->list);
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_persist().");
		return -1;
	}

	return 0;

 alloc_error:
	memprintf(err, "out of memory.");
	return -1;
}

/* Parses the "capture" keyword, which captures a cookie or a request or
 * response header for the logs.
 */
static int proxy_parse_capture(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	struct cap_hdr *hdr;

	warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], NULL);

	if (curpx->cap & PR_CAP_DEF) {
		memprintf(err, "'%s %s' not allowed in 'defaults' section.", args[0], args[1]);
		return -1;
	}

	if (too_many_args_idx(4, 1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "cookie") == 0) {  /* name of a cookie to capture */
		char *name;

		if (*(args[4]) == 0) {
			memprintf(err, "'%s' expects 'cookie' <cookie_name> 'len' <len>.", args[0]);
			return -1;
		}

		name = strdup(args[2]);
		if (!name)
			goto alloc_error;

		free(curpx->capture_name);
		curpx->capture_name = name;
		curpx->capture_namelen = strlen(name);
		curpx->capture_len = atol(args[4]);
		curpx->to_log |= LW_COOKIE;
		return 0;
	}

	if ((strcmp(args[1], "request") != 0 && strcmp(args[1], "response") != 0) ||
	    strcmp(args[2], "header") != 0) {
		memprintf(err, "'%s' expects 'cookie' or 'request header' or 'response header'.", args[0]);
		return -1;
	}

	if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
		memprintf(err, "'%s %s' expects 'header' <header_name> 'len' <len>.", args[0], args[1]);
		return -1;
	}

	hdr = calloc(1, sizeof(*hdr));
	if (!hdr)
		goto alloc_error;

	hdr->name = strdup(args[3]);
	if (!hdr->name)
		goto alloc_err_free_hdr;

	hdr->namelen = strlen(args[3]);
	hdr->len = atol(args[5]);
	hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
	if (!hdr->pool)
		goto alloc_err_free_name;

	if (strcmp(args[1], "request") == 0) {
		hdr->next = curpx->req_cap;
		hdr->index = curpx->nb_req_cap++;
		curpx->req_cap = hdr;
		curpx->to_log |= LW_REQHDR;
	}
	else {
		hdr->next = curpx->rsp_cap;
		hdr->index = curpx->nb_rsp_cap++;
		curpx->rsp_cap = hdr;
		curpx->to_log |= LW_RSPHDR;
	}
	return 0;

 alloc_err_free_name:
	free(hdr->name);
 alloc_err_free_hdr:
	free(hdr);
 alloc_error:
	memprintf(err, "out of memory.");
	return -1;
}

/* Parses the keywords which assign a log format expression to the proxy:
 * "log-format", "log-format-sd", "error-log-format" and "unique-id-format".
 */
static int proxy_parse_logformat(char **args, int section_type, struct proxy *curpx,
                                 const struct proxy *defpx, const char *file, int line,
                                 char **err)
{
	struct lf_expr *lf;
	char *str, *cfgfile;

	if (!*(args[1])) {
		memprintf(err, "%s expects an argument.", args[0]);
		return -1;
	}

	if (*(args[2])) {
		memprintf(err, "%s expects only one argument, don't forget to escape spaces!", args[0]);
		return -1;
	}

	if (strcmp(args[0], "unique-id-format") == 0)
		lf = &curpx->format_unique_id;
	else if (strcmp(args[0], "log-format") == 0)
		lf = &curpx->logformat;
	else if (strcmp(args[0], "log-format-sd") == 0)
		lf = &curpx->logformat_sd;
	else if (strcmp(args[0], "error-log-format") == 0)
		lf = &curpx->logformat_error;
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_logformat().");
		return -1;
	}

	/* in a defaults section, warn about the format we're overriding, which
	 * may have been set by an "option {tcp,http,https}log".
	 */
	if (lf->str && (curpx->cap & PR_CAP_DEF)) {
		if (lf == &curpx->logformat)
			ha_warning("parsing [%s:%d]: 'log-format' overrides previous '%s' in 'defaults' section.\n",
				   file, line, proxy_logformat_origin(curpx));
		else if (lf == &curpx->logformat_error)
			ha_warning("parsing [%s:%d]: 'error-log-format' overrides previous 'error-log-format' in 'defaults' section.\n",
				   file, line);
	}

	str = strdup(args[1]);
	cfgfile = strdup(curpx->conf.args.file);
	if (!str || !cfgfile) {
		free(str);
		free(cfgfile);
		memprintf(err, "out of memory.");
		return -1;
	}

	lf_expr_deinit(lf);
	lf->str = str;
	lf->conf.file = cfgfile;
	lf->conf.line = curpx->conf.args.line;

	/* all of them but "unique-id-format" are ignored in backends. Warn
	 * about it here since we can still report the correct line number.
	 */
	if (lf != &curpx->format_unique_id &&
	    !(curpx->cap & PR_CAP_DEF) && !(curpx->cap & PR_CAP_FE))
		ha_warning("parsing [%s:%d] : backend '%s' : '%s' directive is ignored in backends.\n",
			   file, line, curpx->id, args[0]);

	return 0;
}

/* Parses the logging keywords "log", "log-tag" and "unique-id-header". */
static int proxy_parse_log_opts(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	char *errmsg = NULL;

	if (strcmp(args[0], "log") == 0) { /* "no log" or "log ..." */

		if (!parse_logger(args, &curpx->loggers, (cfg_curr_kwm == KWM_NO), file, line, &errmsg)) {
			memprintf(err, "%s : %s", args[0], errmsg);
			goto fail;
		}
	}
	else if (strcmp(args[0], "log-tag") == 0) {  /* tag to report to syslog */
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a tag for use in syslog.", args[0]);
			goto fail;
		}

		chunk_destroy(&curpx->log_tag);
		chunk_initlen(&curpx->log_tag, strdup(args[1]), strlen(args[1]), strlen(args[1]));
		if (b_orig(&curpx->log_tag) == NULL) {
			chunk_destroy(&curpx->log_tag);
			memprintf(err, "cannot allocate memory for '%s'.", args[0]);
			goto fail;
		}
	}
	else if (strcmp(args[0], "unique-id-header") == 0) {
		char *name;

		if (!*(args[1])) {
			memprintf(err, "%s expects an argument.", args[0]);
			goto fail;
		}

		name = strdup(args[1]);
		if (!name) {
			memprintf(err, "failed to allocate memory for '%s'.", args[0]);
			goto fail;
		}

		istfree(&curpx->header_unique_id);
		curpx->header_unique_id = ist(name);
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_log_opts().");
		goto fail;
	}

	return 0;
 fail:
	free(errmsg);
	return -1;
}

/* Parses the load-balancing keywords "balance", "hash-type" and
 * "hash-balance-factor", which all require the backend capability.
 */
static int proxy_parse_balance(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL);

	if (strcmp(args[0], "balance") == 0) {  /* set balancing with optional algorithm */
		char *errmsg = NULL;

		if (backend_parse_balance((const char **)args + 1, &errmsg, curpx) < 0) {
			memprintf(err, "%s %s", args[0], errmsg);
			free(errmsg);
			return -1;
		}
	}
	else if (strcmp(args[0], "hash-type") == 0) { /* set hashing method */
		/*
		 * The syntax for hash-type config element is
		 * hash-type {map-based|consistent} [[<algo>] avalanche]
		 *
		 * The default hash function is sdbm for map-based and sdbm+avalanche for consistent.
		 */
		curpx->lbprm.algo &= ~(BE_LB_HASH_TYPE | BE_LB_HASH_FUNC | BE_LB_HASH_MOD);

		if (strcmp(args[1], "consistent") == 0) {	/* use consistent hashing */
			curpx->lbprm.algo |= BE_LB_HASH_CONS;
		}
		else if (strcmp(args[1], "map-based") == 0) {	/* use map-based hashing */
			curpx->lbprm.algo |= BE_LB_HASH_MAP;
		}
		else if (strcmp(args[1], "avalanche") == 0) {
			memprintf(err, "experimental feature '%s %s' is not supported anymore, "
				  "please use '%s map-based sdbm avalanche' instead.",
				  args[0], args[1], args[0]);
			return -1;
		}
		else {
			memprintf(err, "'%s' only supports 'consistent' and 'map-based'.", args[0]);
			return -1;
		}

		/* set the hash function to use */
		if (!*args[2]) {
			/* the default algo is sdbm */
			curpx->lbprm.algo |= BE_LB_HFCN_SDBM;

			/* if consistent with no argument, then avalanche modifier is also applied */
			if ((curpx->lbprm.algo & BE_LB_HASH_TYPE) == BE_LB_HASH_CONS)
				curpx->lbprm.algo |= BE_LB_HMOD_AVAL;
		} else {
			/* set the hash function */
			if (strcmp(args[2], "sdbm") == 0)
				curpx->lbprm.algo |= BE_LB_HFCN_SDBM;
			else if (strcmp(args[2], "djb2") == 0)
				curpx->lbprm.algo |= BE_LB_HFCN_DJB2;
			else if (strcmp(args[2], "wt6") == 0)
				curpx->lbprm.algo |= BE_LB_HFCN_WT6;
			else if (strcmp(args[2], "crc32") == 0)
				curpx->lbprm.algo |= BE_LB_HFCN_CRC32;
			else if (strcmp(args[2], "none") == 0)
				curpx->lbprm.algo |= BE_LB_HFCN_NONE;
			else {
				memprintf(err, "'%s' only supports 'sdbm', 'djb2', 'crc32', or 'wt6' hash functions.", args[0]);
				return -1;
			}

			/* set the hash modifier */
			if (strcmp(args[3], "avalanche") == 0)
				curpx->lbprm.algo |= BE_LB_HMOD_AVAL;
			else if (*args[3]) {
				memprintf(err, "'%s' only supports 'avalanche' as a modifier for hash functions.", args[0]);
				return -1;
			}
		}
	}
	else if (strcmp(args[0], "hash-balance-factor") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}

		curpx->lbprm.hash_balance_factor = atol(args[1]);
		if (curpx->lbprm.hash_balance_factor != 0 && curpx->lbprm.hash_balance_factor <= 100) {
			memprintf(err, "'%s' must be 0 or greater than 100.", args[0]);
			return -1;
		}
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_balance().");
		return -1;
	}

	return 0;
}

/* Parses the "source" keyword, which sets the address to bind to when
 * connecting to a server, as well as the "usesrc" keyword which is only valid
 * as an argument to the former.
 */
static int proxy_parse_source(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	struct sockaddr_storage *sk;
	char *errmsg = NULL;
	int port1, port2;
	int cur_arg;

	if (strcmp(args[0], "usesrc") == 0) {  /* address to use outside: needs "source" first */
		memprintf(err, "'%s' only allowed after a '%s' statement.", "usesrc", "source");
		goto fail;
	}

	warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL);

	if (!*args[1]) {
		memprintf(err, "'%s' expects <addr>[:<port>], and optionally '%s' <addr>, and '%s' <name>.",
			  "source", "usesrc", "interface");
		goto fail;
	}

	/* we must first clear any optional default setting */
	curpx->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
	ha_free(&curpx->conn_src.iface_name);
	curpx->conn_src.iface_len = 0;

	sk = str2sa_range(args[1], NULL, &port1, &port2, NULL, NULL, NULL,
			  &errmsg, NULL, NULL, NULL,
			  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_STREAM | PA_O_CONNECT);
	if (!sk) {
		memprintf(err, "'%s %s' : %s", args[0], args[1], errmsg);
		goto fail;
	}

	curpx->conn_src.source_addr = *sk;
	curpx->conn_src.opts |= CO_SRC_BIND;

	for (cur_arg = 2; *(args[cur_arg]); cur_arg += 2) {
		if (strcmp(args[cur_arg], "usesrc") == 0) {  /* address to use outside */
#if defined(CONFIG_HAP_TRANSPARENT)
			if (!*args[cur_arg + 1]) {
				memprintf(err, "'%s' expects <addr>[:<port>], 'client', or 'clientip' as argument.", "usesrc");
				goto fail;
			}

			if (strcmp(args[cur_arg + 1], "client") == 0) {
				curpx->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
				curpx->conn_src.opts |= CO_SRC_TPROXY_CLI;
			} else if (strcmp(args[cur_arg + 1], "clientip") == 0) {
				curpx->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
				curpx->conn_src.opts |= CO_SRC_TPROXY_CIP;
			} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
				char *name, *end;
				char *hdr_name;

				name = args[cur_arg+1] + 7;
				while (isspace((unsigned char)*name))
					name++;

				end = name;
				while (*end && !isspace((unsigned char)*end) && *end != ',' && *end != ')')
					end++;

				hdr_name = calloc(1, end - name + 1);
				if (!hdr_name) {
					memprintf(err, "out of memory.");
					goto fail;
				}

				curpx->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
				curpx->conn_src.opts |= CO_SRC_TPROXY_DYN;
				free(curpx->conn_src.bind_hdr_name);
				curpx->conn_src.bind_hdr_name = hdr_name;
				curpx->conn_src.bind_hdr_len = end - name;
				memcpy(hdr_name, name, end - name);
				hdr_name[end - name] = '\0';
				curpx->conn_src.bind_hdr_occ = -1;

				/* now look for an occurrence number */
				while (isspace((unsigned char)*end))
					end++;
				if (*end == ',') {
					end++;
					name = end;
					if (*end == '-')
						end++;
					while (isdigit((unsigned char)*end))
						end++;
					curpx->conn_src.bind_hdr_occ = strl2ic(name, end-name);
				}

				if (curpx->conn_src.bind_hdr_occ < -MAX_HDR_HISTORY) {
					memprintf(err, "usesrc hdr_ip(name,num) does not support negative"
						  " occurrences values smaller than %d.", MAX_HDR_HISTORY);
					goto fail;
				}
			} else {
				sk = str2sa_range(args[cur_arg + 1], NULL, &port1, &port2, NULL, NULL, NULL,
						  &errmsg, NULL, NULL, NULL,
						  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_STREAM | PA_O_CONNECT);
				if (!sk) {
					memprintf(err, "'%s %s' : %s", args[cur_arg], args[cur_arg+1], errmsg);
					goto fail;
				}

				curpx->conn_src.tproxy_addr = *sk;
				curpx->conn_src.opts |= CO_SRC_TPROXY_ADDR;
			}
			global.last_checks |= LSTCHK_NETADM;
#else	/* no TPROXY support */
			memprintf(err, "'%s' not allowed here because support for TPROXY was not compiled in.", "usesrc");
			goto fail;
#endif
		}
		else if (strcmp(args[cur_arg], "interface") == 0) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
			char *name;

			if (!*args[cur_arg + 1]) {
				memprintf(err, "'%s' : missing interface name.", args[0]);
				goto fail;
			}

			name = strdup(args[cur_arg + 1]);
			if (!name) {
				memprintf(err, "out of memory.");
				goto fail;
			}

			free(curpx->conn_src.iface_name);
			curpx->conn_src.iface_name = name;
			curpx->conn_src.iface_len  = strlen(name);
			global.last_checks |= LSTCHK_NETADM;
#else
			memprintf(err, "'%s' : '%s' option not implemented.", args[0], args[cur_arg]);
			goto fail;
#endif
		}
		else {
			memprintf(err, "'%s' only supports optional keywords '%s' and '%s'.",
				  args[0], "interface", "usesrc");
			goto fail;
		}
	}

	return 0;
 fail:
	free(errmsg);
	return -1;
}

/* Parses the backend and server selection keywords "default_backend",
 * "use_backend" and "use-server".
 */
static int proxy_parse_use_backend(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	struct acl_cond *cond = NULL;
	char *errmsg = NULL;
	char *name = NULL;
	char *cfgfile = NULL;

	if (strcmp(args[0], "default_backend") == 0) {
		warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], NULL);

		if (too_many_args_idx(1, 0, args, err, NULL))
			goto fail;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a backend name.", args[0]);
			goto fail;
		}

		name = strdup(args[1]);
		if (!name)
			goto alloc_error;

		free(curpx->defbe.name);
		curpx->defbe.name = name;

		return 0;
	}

	if (curpx->cap & PR_CAP_DEF) {
		memprintf(err, "'%s' not allowed in 'defaults' section.", args[0]);
		goto fail;
	}

	if (strcmp(args[0], "use_backend") == 0) {
		struct switching_rule *rule;

		warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], NULL);

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a backend name.", args[0]);
			goto fail;
		}

		if (strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0) {
			cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args + 2, &errmsg);
			if (!cond) {
				memprintf(err, "error detected while parsing switching rule : %s.", errmsg);
				goto fail;
			}

			if (warnif_cond_conflicts(cond, SMP_VAL_FE_SET_BCK, &errmsg))
				ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
			ha_free(&errmsg);
		}
		else if (*args[2]) {
			memprintf(err, "unexpected keyword '%s' after switching rule, only 'if' and 'unless' are allowed.",
				  args[2]);
			goto fail;
		}

		name = strdup(args[1]);
		cfgfile = strdup(file);
		rule = calloc(1, sizeof(*rule));
		if (!name || !cfgfile || !rule) {
			free(rule);
			goto alloc_error;
		}

		rule->cond = cond;
		rule->be.name = name;
		rule->file = cfgfile;
		rule->line = line;
		LIST_INIT(&rule->list);
		LIST_APPEND(&curpx->switching_rules, &rule->list);
	}
	else if (strcmp(args[0], "use-server") == 0) {
		struct server_rule *rule;

		warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL);

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a server name.", args[0]);
			goto fail;
		}

		if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
			memprintf(err, "'%s' requires either 'if' or 'unless' followed by a condition.", args[0]);
			goto fail;
		}

		cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args + 2, &errmsg);
		if (!cond) {
			memprintf(err, "error detected while parsing switching rule : %s.", errmsg);
			goto fail;
		}

		if (warnif_cond_conflicts(cond, SMP_VAL_BE_SET_SRV, &errmsg))
			ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
		ha_free(&errmsg);

		name = strdup(args[1]);
		cfgfile = strdup(file);
		rule = calloc(1, sizeof(*rule));
		if (!name || !cfgfile || !rule) {
			free(rule);
			goto alloc_error;
		}

		rule->cond = cond;
		rule->srv.name = name;
		rule->file = cfgfile;
		rule->line = line;
		LIST_INIT(&rule->list);
		LIST_APPEND(&curpx->server_rules, &rule->list);
		curpx->be_req_ana |= AN_REQ_SRV_RULES;
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_use_backend().");
		goto fail;
	}

	return 0;

 alloc_error:
	free_acl_cond(cond);
	free(name);
	free(cfgfile);
	memprintf(err, "out of memory.");
 fail:
	free(errmsg);
	return -1;
}

/* Parses the HTTP rule sets "http-request", "http-response" and
 * "http-after-response".
 */
static int proxy_parse_http_rules(char **args, int section_type, struct proxy *curpx,
                                  const struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	struct act_rule *(*parse_cond)(const char **args, const char *file, int linenum, struct proxy *px);
	struct list *rules;
	struct act_rule *rule;
	char *errmsg = NULL;
	int fe_where, be_where;
	int where = 0;

	if (strcmp(args[0], "http-request") == 0) {
		rules      = &curpx->http_req_rules;
		parse_cond = parse_http_req_cond;
		fe_where   = SMP_VAL_FE_HRQ_HDR;
		be_where   = SMP_VAL_BE_HRQ_HDR;
	}
	else if (strcmp(args[0], "http-response") == 0) {
		rules      = &curpx->http_res_rules;
		parse_cond = parse_http_res_cond;
		fe_where   = SMP_VAL_FE_HRS_HDR;
		be_where   = SMP_VAL_BE_HRS_HDR;
	}
	else if (strcmp(args[0], "http-after-response") == 0) {
		rules      = &curpx->http_after_res_rules;
		parse_cond = parse_http_after_res_cond;
		fe_where   = SMP_VAL_FE_HRS_HDR;
		be_where   = SMP_VAL_BE_HRS_HDR;
	}
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_http_rules().");
		goto fail;
	}

	if ((curpx->cap & PR_CAP_DEF) && strlen(curpx->id) == 0) {
		memprintf(err, "'%s' not allowed in anonymous 'defaults' section.", args[0]);
		goto fail;
	}

	if (!LIST_ISEMPTY(rules) &&
	    !LIST_PREV(rules, struct act_rule *, list)->cond &&
	    (LIST_PREV(rules, struct act_rule *, list)->flags & ACT_FLAG_FINAL))
		ha_warning("parsing [%s:%d]: previous '%s' action is final and has no condition attached, further entries are NOOP.\n",
		           file, line, args[0]);

	rule = parse_cond((const char **)args + 1, file, line, curpx);
	if (!rule) {
		/* the error was already reported by the action parser */
		goto fail;
	}

	if (rules == &curpx->http_req_rules)
		warnif_misplaced_http_req(curpx, file, line, args[0], NULL);

	if (curpx->cap & PR_CAP_FE)
		where |= fe_where;
	if (curpx->cap & PR_CAP_BE)
		where |= be_where;

	if (warnif_cond_conflicts(rule->cond, where, &errmsg))
		ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
	ha_free(&errmsg);

	LIST_APPEND(rules, &rule->list);

	return 0;
 fail:
	ha_free(&errmsg);
	return -1;
}

/* Parses the "redirect" keyword, which adds a redirect rule. */
static int proxy_parse_redirect(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	struct redirect_rule *rule;
	char *errmsg = NULL;
	int where = 0;

	if (curpx->cap & PR_CAP_DEF) {
		memprintf(err, "'%s' not allowed in 'defaults' section.", args[0]);
		goto fail;
	}

	rule = http_parse_redirect_rule(file, line, curpx, (const char **)args + 1, &errmsg, 0, 0);
	if (!rule) {
		memprintf(err, "error detected in %s '%s' while parsing redirect rule : %s.",
			  proxy_type_str(curpx), curpx->id, errmsg);
		goto fail;
	}

	LIST_APPEND(&curpx->redirect_rules, &rule->list);
	warnif_misplaced_redirect(curpx, file, line, args[0], NULL);

	if (curpx->cap & PR_CAP_FE)
		where |= SMP_VAL_FE_HRQ_HDR;
	if (curpx->cap & PR_CAP_BE)
		where |= SMP_VAL_BE_HRQ_HDR;

	if (warnif_cond_conflicts(rule->cond, where, &errmsg))
		ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
	ha_free(&errmsg);

	return 0;
 fail:
	ha_free(&errmsg);
	return -1;
}

/* Parses "stick-table" */
static int proxy_parse_stick_table(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	struct stktable *other;
	int ret;

	if (curpx->cap & PR_CAP_DEF) {
		memprintf(err, "'%s' is not supported in 'defaults' section.", args[0]);
		goto fail;
	}

	other = stktable_find_by_name(curpx->id);
	if (other) {
		memprintf(err, "stick-table name '%s' conflicts with table declared in %s '%s' at %s:%d.",
			  curpx->id,
			  other->proxy ? proxy_cap_str(other->proxy->cap) : "peers",
			  other->proxy ? other->id : other->peers.p->id,
			  other->conf.file, other->conf.line);
		goto fail;
	}

	curpx->table = calloc(1, sizeof *curpx->table);
	if (!curpx->table) {
		memprintf(err, "'%s %s' : memory allocation failed", args[0], args[1]);
		goto fail;
	}

	/* the messages are emitted by parse_stick_table() itself */
	ret = parse_stick_table(file, line, args, curpx->table, curpx->id, curpx->id, NULL);
	if (ret & ERR_FATAL) {
		ha_free(&curpx->table);
		goto fail;
	}

	/* Store the proxy in the stick-table. */
	curpx->table->proxy = curpx;

	stktable_store_name(curpx->table);
	curpx->table->next = stktables_list;
	stktables_list = curpx->table;

	/* Add this proxy to the list of proxies which refer to its stick-table. */
	if (curpx->table->proxies_list != curpx) {
		curpx->next_stkt_ref = curpx->table->proxies_list;
		curpx->table->proxies_list = curpx;
	}
	return 0;
 fail:
	return -1;
}

/* Parses "stick" rules */
static int proxy_parse_stick(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err)
{
	struct sample_expr *expr = NULL;
	struct acl_cond *cond = NULL;
	struct sticking_rule *rule;
	const char *name = NULL;
	char *errmsg = NULL;
	int myidx = 0;
	int flags;

	if (curpx->cap & PR_CAP_DEF) {
		memprintf(err, "'%s' is not supported in 'defaults' section.", args[0]);
		goto fail;
	}

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL))
		return 0;

	myidx++;
	if ((strcmp(args[myidx], "store") == 0) ||
	    (strcmp(args[myidx], "store-request") == 0)) {
		myidx++;
		flags = STK_IS_STORE;
	}
	else if (strcmp(args[myidx], "store-response") == 0) {
		myidx++;
		flags = STK_IS_STORE | STK_ON_RSP;
	}
	else if (strcmp(args[myidx], "match") == 0) {
		myidx++;
		flags = STK_IS_MATCH;
	}
	else if (strcmp(args[myidx], "on") == 0) {
		myidx++;
		flags = STK_IS_MATCH | STK_IS_STORE;
	}
	else {
		memprintf(err, "'%s' expects 'on', 'match', or 'store'.", args[0]);
		goto fail;
	}

	if (*(args[myidx]) == 0) {
		memprintf(err, "'%s' expects a fetch method.", args[0]);
		goto fail;
	}

	curpx->conf.args.ctx = ARGC_STK;
	expr = sample_parse_expr(args, &myidx, file, line, &errmsg, &curpx->conf.args, NULL);
	if (!expr) {
		memprintf(err, "'%s': %s", args[0], errmsg);
		goto fail;
	}

	if (flags & STK_ON_RSP) {
		if (!(expr->fetch->val & SMP_VAL_BE_STO_RUL)) {
			memprintf(err, "'%s': fetch method '%s' extracts information from '%s', none of which is available for 'store-response'.",
				  args[0], expr->fetch->kw, sample_src_names(expr->fetch->use));
			goto fail;
		}
	} else {
		if (!(expr->fetch->val & SMP_VAL_BE_SET_SRV)) {
			memprintf(err, "'%s': fetch method '%s' extracts information from '%s', none of which is available during request.",
				  args[0], expr->fetch->kw, sample_src_names(expr->fetch->use));
			goto fail;
		}
	}

	/* check if we need to allocate an http_txn struct for HTTP parsing */
	curpx->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);

	if (strcmp(args[myidx], "table") == 0) {
		myidx++;
		name = args[myidx++];
	}

	if (strcmp(args[myidx], "if") == 0 || strcmp(args[myidx], "unless") == 0) {
		cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args + myidx, &errmsg);
		if (!cond) {
			memprintf(err, "'%s': error detected while parsing sticking condition : %s.",
				  args[0], errmsg);
			goto fail;
		}
	}
	else if (*(args[myidx])) {
		memprintf(err, "'%s': unknown keyword '%s'.", args[0], args[myidx]);
		goto fail;
	}

	if (warnif_cond_conflicts(cond, (flags & STK_ON_RSP) ? SMP_VAL_BE_STO_RUL : SMP_VAL_BE_SET_SRV, &errmsg))
		ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
	ha_free(&errmsg);

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		memprintf(err, "out of memory.");
		goto fail;
	}

	rule->cond = cond;
	rule->expr = expr;
	rule->flags = flags;
	rule->table.name = name ? strdup(name) : NULL;
	LIST_INIT(&rule->list);
	if (flags & STK_ON_RSP)
		LIST_APPEND(&curpx->storersp_rules, &rule->list);
	else
		LIST_APPEND(&curpx->sticking_rules, &rule->list);

	return 0;
 fail:
	free(errmsg);
	free_acl_cond(cond);
	free(expr);
	return -1;
}

/* Parses the "cookie" keyword, which configures the cookie-based
 * persistence.
 */
static int proxy_parse_cookie(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	const char *errptr;
	char *name;
	int cur_arg;

	warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL);

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects <cookie_name> as argument.", args[0]);
		goto fail;
	}

	name = strdup(args[1]);
	if (!name)
		goto alloc_error;

	curpx->ck_opts = 0;
	curpx->cookie_maxidle = curpx->cookie_maxlife = 0;
	ha_free(&curpx->cookie_domain);
	free(curpx->cookie_name);
	curpx->cookie_name = name;
	curpx->cookie_len = strlen(name);

	for (cur_arg = 2; *(args[cur_arg]); cur_arg++) {
		if (strcmp(args[cur_arg], "rewrite") == 0) {
			curpx->ck_opts |= PR_CK_RW;
		}
		else if (strcmp(args[cur_arg], "indirect") == 0) {
			curpx->ck_opts |= PR_CK_IND;
		}
		else if (strcmp(args[cur_arg], "insert") == 0) {
			curpx->ck_opts |= PR_CK_INS;
		}
		else if (strcmp(args[cur_arg], "nocache") == 0) {
			curpx->ck_opts |= PR_CK_NOC;
		}
		else if (strcmp(args[cur_arg], "postonly") == 0) {
			curpx->ck_opts |= PR_CK_POST;
		}
		else if (strcmp(args[cur_arg], "preserve") == 0) {
			curpx->ck_opts |= PR_CK_PSV;
		}
		else if (strcmp(args[cur_arg], "prefix") == 0) {
			curpx->ck_opts |= PR_CK_PFX;
		}
		else if (strcmp(args[cur_arg], "httponly") == 0) {
			curpx->ck_opts |= PR_CK_HTTPONLY;
		}
		else if (strcmp(args[cur_arg], "secure") == 0) {
			curpx->ck_opts |= PR_CK_SECURE;
		}
		else if (strcmp(args[cur_arg], "dynamic") == 0) { /* Dynamic persistent cookies secret key */
			curpx->ck_opts |= PR_CK_DYNAMIC;
		}
		else if (strcmp(args[cur_arg], "domain") == 0) {
			if (!*args[cur_arg + 1]) {
				memprintf(err, "'%s' expects <domain> as argument.", args[cur_arg]);
				goto fail;
			}

			if (!strchr(args[cur_arg + 1], '.')) {
				/* rfc6265, 5.2.3 The Domain Attribute */
				ha_warning("parsing [%s:%d]: domain '%s' contains no embedded dot,"
					   " this configuration may not work properly (see RFC6265#5.2.3).\n",
					   file, line, args[cur_arg + 1]);
			}

			errptr = invalid_domainchar(args[cur_arg + 1]);
			if (errptr) {
				memprintf(err, "character '%c' is not permitted in domain name '%s'.",
					  *errptr, args[cur_arg + 1]);
				goto fail;
			}

			if (!curpx->cookie_domain)
				curpx->cookie_domain = strdup(args[cur_arg + 1]);
			else {
				/* one domain was already specified, add another one by
				 * building the string which will be returned along with
				 * the cookie.
				 */
				memprintf(&curpx->cookie_domain, "%s; domain=%s", curpx->cookie_domain, args[cur_arg+1]);
			}

			if (!curpx->cookie_domain)
				goto alloc_error;
			cur_arg++;
		}
		else if (strcmp(args[cur_arg], "maxidle") == 0 ||
			 strcmp(args[cur_arg], "maxlife") == 0) {
			unsigned int delay;
			const char *res;

			if (!*args[cur_arg + 1]) {
				memprintf(err, "'%s' expects <%s> in seconds as argument.", args[cur_arg],
					  (args[cur_arg][3] == 'i') ? "idletime" : "lifetime");
				goto fail;
			}

			res = parse_time_err(args[cur_arg + 1], &delay, TIME_UNIT_S);
			if (res == PARSE_TIME_OVER) {
				memprintf(err, "timer overflow in argument <%s> to <%s>, maximum value is 2147483647 s (~68 years).",
					  args[cur_arg+1], args[cur_arg]);
				goto fail;
			}
			else if (res == PARSE_TIME_UNDER) {
				memprintf(err, "timer underflow in argument <%s> to <%s>, minimum non-null value is 1 s.",
					  args[cur_arg+1], args[cur_arg]);
				goto fail;
			}
			else if (res) {
				memprintf(err, "unexpected character '%c' in argument to <%s>.", *res, args[cur_arg]);
				goto fail;
			}

			if (args[cur_arg][3] == 'i') // idle
				curpx->cookie_maxidle = delay;
			else
				curpx->cookie_maxlife = delay;
			cur_arg++;
		}
		else if (strcmp(args[cur_arg], "attr") == 0) {
			char *val;

			if (!*args[cur_arg + 1]) {
				memprintf(err, "'%s' expects <value> as argument.", args[cur_arg]);
				goto fail;
			}

			val = args[cur_arg + 1];
			while (*val) {
				if (iscntrl((unsigned char)*val) || *val == ';') {
					memprintf(err, "character '%%x%02X' is not permitted in attribute value.", *val);
					goto fail;
				}
				val++;
			}

			/* don't add ';' for the first attribute */
			if (!curpx->cookie_attrs)
				curpx->cookie_attrs = strdup(args[cur_arg + 1]);
			else
				memprintf(&curpx->cookie_attrs, "%s; %s", curpx->cookie_attrs, args[cur_arg + 1]);

			if (!curpx->cookie_attrs)
				goto alloc_error;
			cur_arg++;
		}
		else {
			memprintf(err, "'%s' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache', "
				  "'postonly', 'domain', 'maxidle', 'dynamic', 'maxlife' and 'attr' options.", args[0]);
			goto fail;
		}
	}

	if (!POWEROF2(curpx->ck_opts & (PR_CK_RW|PR_CK_IND))) {
		memprintf(err, "cookie 'rewrite' and 'indirect' modes are incompatible.");
		goto fail;
	}

	if (!POWEROF2(curpx->ck_opts & (PR_CK_RW|PR_CK_INS|PR_CK_PFX))) {
		memprintf(err, "cookie 'rewrite', 'insert' and 'prefix' modes are incompatible.");
		goto fail;
	}

	if ((curpx->ck_opts & (PR_CK_PSV | PR_CK_INS | PR_CK_IND)) == PR_CK_PSV) {
		memprintf(err, "cookie 'preserve' requires at least 'insert' or 'indirect'.");
		goto fail;
	}

	return 0;

 alloc_error:
	memprintf(err, "out of memory.");
 fail:
	return -1;
}

/* Parses the "email-alert" keyword, which configures the email alerts. */
static int proxy_parse_email_alert(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	char **dst = NULL;

	if (*(args[1]) == 0) {
		memprintf(err, "missing argument after '%s'.", args[0]);
		return -1;
	}

	if (strcmp(args[1], "from") == 0)
		dst = &curpx->email_alert.from;
	else if (strcmp(args[1], "mailers") == 0)
		dst = &curpx->email_alert.mailers.name;
	else if (strcmp(args[1], "myhostname") == 0)
		dst = &curpx->email_alert.myhostname;
	else if (strcmp(args[1], "to") == 0)
		dst = &curpx->email_alert.to;
	else if (strcmp(args[1], "level") != 0) {
		memprintf(err, "email-alert: unknown argument '%s'.", args[1]);
		goto fail;
	}

	if (*(args[2]) == 0) {
		memprintf(err, "missing argument after '%s'.", args[1]);
		goto fail;
	}

	if (dst) {
		char *val = strdup(args[2]);

		if (!val) {
			memprintf(err, "out of memory.");
			goto fail;
		}

		free(*dst);
		*dst = val;
	}
	else {
		curpx->email_alert.level = get_log_level(args[2]);
		if (curpx->email_alert.level < 0) {
			memprintf(err, "unknown log level '%s' after '%s'", args[2], args[1]);
			goto fail;
		}
	}

	/* Indicate that the email_alert is at least partially configured */
	curpx->email_alert.flags |= PR_EMAIL_ALERT_SET;

	return 0;
 fail:
	return -1;
}

/* Parses the "stats" keyword, which configures the HTML stats page of this
 * proxy.
 */
static int proxy_parse_stats(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err)
{
	char *errmsg = NULL;

	if (!(curpx->cap & PR_CAP_DEF) && curpx->uri_auth == defpx->uri_auth) {
		/* we must detach from the default config */
		stats_uri_auth_drop(curpx->uri_auth);
		curpx->uri_auth = NULL;
	}

	if (!*args[1])
		goto error_parsing;

	if (strcmp(args[1], "admin") == 0) {
		struct stats_admin_rule *rule;
		struct acl_cond *cond;
		int where = 0;

		if (curpx->cap & PR_CAP_DEF) {
			memprintf(err, "'%s %s' not allowed in 'defaults' section.", args[0], args[1]);
			goto fail;
		}

		if (!stats_check_init_uri_auth(&curpx->uri_auth))
			goto alloc_error;

		if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
			memprintf(err, "'%s %s' requires either 'if' or 'unless' followed by a condition.",
				  args[0], args[1]);
			goto fail;
		}

		cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args + 2, &errmsg);
		if (!cond) {
			memprintf(err, "error detected while parsing a '%s %s' rule : %s.",
				  args[0], args[1], errmsg);
			goto fail;
		}

		if (curpx->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (curpx->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;

		if (warnif_cond_conflicts(cond, where, &errmsg))
			ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
		ha_free(&errmsg);

		rule = calloc(1, sizeof(*rule));
		if (!rule) {
			free_acl_cond(cond);
			goto fail;
		}

		rule->cond = cond;
		LIST_INIT(&rule->list);
		LIST_APPEND(&curpx->uri_auth->admin_rules, &rule->list);
	}
	else if (strcmp(args[1], "uri") == 0) {
		if (*(args[2]) == 0) {
			memprintf(err, "'uri' needs an URI prefix.");
			goto fail;
		}
		if (!stats_set_uri(&curpx->uri_auth, args[2]))
			goto alloc_error;
	}
	else if (strcmp(args[1], "realm") == 0) {
		if (*(args[2]) == 0) {
			memprintf(err, "'realm' needs an realm name.");
			goto fail;
		}
		if (!stats_set_realm(&curpx->uri_auth, args[2]))
			goto alloc_error;
	}
	else if (strcmp(args[1], "refresh") == 0) {
		unsigned interval;
		const char *res;

		res = parse_time_err(args[2], &interval, TIME_UNIT_S);
		if (res == PARSE_TIME_OVER) {
			memprintf(err, "timer overflow in argument <%s> to stats refresh interval, maximum value is 2147483647 s (~68 years).",
				  args[2]);
			goto fail;
		}
		else if (res == PARSE_TIME_UNDER) {
			memprintf(err, "timer underflow in argument <%s> to stats refresh interval, minimum non-null value is 1 s.",
				  args[2]);
			goto fail;
		}
		else if (res) {
			memprintf(err, "unexpected character '%c' in argument to stats refresh interval.", *res);
			goto fail;
		}
		if (!stats_set_refresh(&curpx->uri_auth, interval))
			goto alloc_error;
	}
	else if (strcmp(args[1], "http-request") == 0) {    /* request access control: allow/deny/auth */
		struct act_rule *rule;
		int where = 0;

		if (curpx->cap & PR_CAP_DEF) {
			memprintf(err, "'%s' not allowed in 'defaults' section.", args[0]);
			goto fail;
		}

		if (!stats_check_init_uri_auth(&curpx->uri_auth))
			goto alloc_error;

		if (!LIST_ISEMPTY(&curpx->uri_auth->http_req_rules) &&
		    !LIST_PREV(&curpx->uri_auth->http_req_rules, struct act_rule *, list)->cond)
			ha_warning("parsing [%s:%d]: previous '%s' action has no condition attached, further entries are NOOP.\n",
				   file, line, args[0]);

		rule = parse_http_req_cond((const char **)args + 2, file, line, curpx);
		if (!rule) {
			/* the error was already reported by the action parser */
			goto fail;
		}

		if (curpx->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (curpx->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;

		if (warnif_cond_conflicts(rule->cond, where, &errmsg))
			ha_warning("parsing [%s:%d] : '%s'.\n", file, line, errmsg);
		free(errmsg);

		LIST_APPEND(&curpx->uri_auth->http_req_rules, &rule->list);
	}
	else if (strcmp(args[1], "auth") == 0) {
		if (*(args[2]) == 0) {
			memprintf(err, "'auth' needs a user:password account.");
			goto fail;
		}
		if (!stats_add_auth(&curpx->uri_auth, args[2]))
			goto alloc_error;
	}
	else if (strcmp(args[1], "scope") == 0) {
		if (*(args[2]) == 0) {
			memprintf(err, "'scope' needs a proxy name.");
			goto fail;
		}
		if (!stats_add_scope(&curpx->uri_auth, args[2]))
			goto alloc_error;
	}
	else if (strcmp(args[1], "enable") == 0) {
		if (!stats_check_init_uri_auth(&curpx->uri_auth))
			goto alloc_error;
	}
	else if (strcmp(args[1], "hide-version") == 0) {
		if (curpx->uri_auth)
			curpx->uri_auth->flags &= ~STAT_F_SHOWVER;
	}
	else if (strcmp(args[1], "show-version") == 0) {
		if (!stats_set_flag(&curpx->uri_auth, STAT_F_SHOWVER))
			goto alloc_error;
	}
	else if (strcmp(args[1], "show-legends") == 0) {
		if (!stats_set_flag(&curpx->uri_auth, STAT_F_SHLGNDS))
			goto alloc_error;
	}
	else if (strcmp(args[1], "show-modules") == 0) {
		if (!stats_set_flag(&curpx->uri_auth, STAT_F_SHMODULES))
			goto alloc_error;
	}
	else if (strcmp(args[1], "show-node") == 0) {
		if (*args[2]) {
			int i;
			char c;

			for (i = 0; args[2][i]; i++) {
				c = args[2][i];
				if (!isupper((unsigned char)c) && !islower((unsigned char)c) &&
				    !isdigit((unsigned char)c) && c != '_' && c != '-' && c != '.')
					break;
			}

			if (!i || args[2][i]) {
				memprintf(err, "'%s %s' invalid node name - should be a string"
					  "with digits(0-9), letters(A-Z, a-z), hyphen(-) or underscode(_).",
					  args[0], args[1]);
				goto fail;
			}
		}

		if (!stats_set_node(&curpx->uri_auth, args[2]))
			goto alloc_error;
	}
	else if (strcmp(args[1], "show-desc") == 0) {
		char *desc = NULL;

		if (*args[2]) {
			int i, len = 0;
			char *d;

			for (i = 2; *args[i]; i++)
				len += strlen(args[i]) + 1;

			desc = d = calloc(1, len);
			if (unlikely(!d)) {
				memprintf(err, "'%s %s' : memory allocation failed", args[0], args[1]);
				goto fail;
			}

			d += snprintf(d, desc + len - d, "%s", args[2]);
			for (i = 3; *args[i]; i++)
				d += snprintf(d, desc + len - d, " %s", args[i]);
		}

		if (!*args[2] && !global.desc)
			ha_warning("parsing [%s:%d]: '%s' requires a parameter or 'desc' to be set in the global section.\n",
				   file, line, args[1]);
		else {
			if (!stats_set_desc(&curpx->uri_auth, desc)) {
				free(desc);
				goto fail;
			}
		}
		free(desc);
	}
	else
		goto error_parsing;

	return 0;

 error_parsing:
	memprintf(err, "%s '%s', expects 'admin', 'uri', 'realm', 'auth', 'scope', 'enable', "
		  "'hide-version', 'show-node', 'show-desc' , 'show-legends' or 'show-version'.",
		  *args[1] ? "unknown stats parameter" : "missing keyword in",
		  args[*args[1] ? 1 : 0]);
	return -1;

 alloc_error:
	memprintf(err, "out of memory.");
 fail:
	free(errmsg);
	return -1;
}

/* Parses the "server", "default-server" and "server-template" keywords */
static int proxy_parse_server(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	int flags;
	int ret;

	if (strcmp(args[0], "server") == 0)
		flags = SRV_PARSE_PARSE_ADDR;
	else if (strcmp(args[0], "default-server") == 0)
		flags = SRV_PARSE_DEFAULT_SERVER;
	else if (strcmp(args[0], "server-template") == 0)
		flags = SRV_PARSE_TEMPLATE | SRV_PARSE_PARSE_ADDR;
	else {
		BUG_ON(1, "unhandled keyword in proxy_parse_server().");
		return -1;
	}

	/* the messages are emitted by parse_server() itself */
	ret = parse_server(file, line, args, curpx, (struct proxy *)defpx, flags);

	return (ret & ERR_FATAL) ? -1 : 0;
}

/* Parses the "bind" keyword, which declares new listening addresses. */
static int proxy_parse_bind(char **args, int section_type, struct proxy *curpx,
                            const struct proxy *defpx, const char *file, int line,
                            char **err)
{
	struct bind_conf *bind_conf;
	struct listener *l;
	char *errmsg = NULL;
	int ret = ERR_FATAL; // assume errors for early returns

	if (curpx->cap & PR_CAP_DEF) {
		memprintf(err, "'%s' not allowed in 'defaults' section.", args[0]);
		goto fail;
	}

	warnifnotcap(curpx, PR_CAP_FE, file, line, args[0], NULL);

	if (!*(args[1])) {
		memprintf(err, "'%s' expects {<path>|[addr1]:port1[-end1]}{,[addr]:port[-end]}... as arguments.",
		          args[0]);
		goto fail;
	}

	bind_conf = bind_conf_alloc(curpx, file, line, args[1], xprt_get(XPRT_RAW));
	if (!bind_conf) {
		memprintf(err, "out of memory.");
		goto fail;
	}

	/* use default settings for unix sockets */
	bind_conf->settings.ux.uid  = global.unix_bind.ux.uid;
	bind_conf->settings.ux.gid  = global.unix_bind.ux.gid;
	bind_conf->settings.ux.mode = global.unix_bind.ux.mode;

	/* NOTE: the following line might create several listeners if there
	 * are comma-separated IPs or port ranges. So all further processing
	 * will have to be applied to all listeners created after last_listen.
	 */
	if (!str2listener(args[1], curpx, bind_conf, file, line, &errmsg)) {
		if (errmsg) {
			indent_msg(&errmsg, 2);
			memprintf(err, "'%s' : %s", args[0], errmsg);
		}
		else
			memprintf(err, "'%s' : error encountered while parsing listening address '%s'.",
			          args[0], args[1]);
		goto fail;
	}

	list_for_each_entry(l, &bind_conf->listeners, by_bind) {
		/* Set default global rights and owner for unix bind  */
		global.maxsock++;
	}

	/* the messages are emitted by bind_parse_args_list() itself */
	ret = bind_parse_args_list(bind_conf, args, 2, cursection, file, line);
 fail:
	ha_free(&errmsg);
	return (ret & ERR_FATAL) ? -1 : 0;
}

/* Parses a proxy "option" keyword. Most of the options only set a flag in one
 * of the proxy's option sets and are listed in the cfg_opts* arrays; the ones
 * which need a dedicated processing generally take an argument or are not
 * supported anymore are handled below. Please update common_options[] at the
 * top of this file when adding an entry here, it is what allows a mistyped
 * option to be suggested. Returns <0 for fatal error, >0 on warning, otherwise
 * zero.
 */
static int proxy_parse_option(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	int kwm = cfg_curr_kwm;
	int ret = 0; // assume success

	if (*(args[1]) == '\0') {
		memprintf(err, "'%s' expects an option name.", args[0]);
		ret |= ERR_FATAL;
		goto done;
	}

	/* the functions below already emit a message if needed */

	/* try to match option within cfg_opts */
	if (cfg_parse_listen_match_option(file, line, kwm, cfg_opts, &ret, args,
	                                  PR_MODES, PR_CAP_NONE,
	                                  &curpx->options, &curpx->no_options))
		goto done;

	if (ret & ERR_CODE)
		goto done;

	if (cfg_parse_listen_match_option(file, line, kwm, cfg_opts, &ret, args,
	                                  PR_MODES, PR_CAP_NONE,
	                                  &curpx->options, &curpx->no_options))
		goto done;

	if (ret & ERR_CODE)
		goto done;

	/* try to match option within cfg_opts2 */
	if (cfg_parse_listen_match_option(file, line, kwm, cfg_opts2, &ret, args,
	                                  PR_MODES, PR_CAP_NONE,
	                                  &curpx->options2, &curpx->no_options2))
		goto done;

	if (ret & ERR_CODE)
		goto done;

	/* try to match option within cfg_opts3 */
	if (cfg_parse_listen_match_option(file, line, kwm, cfg_opts3, &ret, args,
	                                  PR_MODES, PR_CAP_NONE,
	                                  &curpx->options3, &curpx->no_options3))
		goto done;

	if (ret & ERR_CODE)
		goto done;

	/* HTTP options override each other. They can be cancelled using
	 * "no option xxx" which only switches to default mode if the mode
	 * was this one (useful for cancelling options set in defaults
	 * sections).
	 */
	if (strcmp(args[1], "forceclose") == 0) {
		memprintf(err, "option '%s' is not supported any more since HAProxy 2.0, please just remove it, "
		          "or use 'option httpclose' if absolutely needed.", args[1]);
		ret |= ERR_FATAL;
		goto done;
	}
	else if (strcmp(args[1], "httpclose") == 0 ||
		 strcmp(args[1], "http-server-close") == 0 ||
		 strcmp(args[1], "http-keep-alive") == 0) {
		int mode;

		if (too_many_args_idx(0, 1, args, err, NULL)) {
			ret |= ERR_FATAL;
			goto done;
		}

		if (strcmp(args[1], "httpclose") == 0)
			mode = PR_O_HTTP_CLO;
		else if (strcmp(args[1], "http-server-close") == 0)
			mode = PR_O_HTTP_SCL;
		else
			mode = PR_O_HTTP_KAL;

		if (kwm == KWM_STD) {
			curpx->options &= ~PR_O_HTTP_MODE;
			curpx->options |= mode;
			goto done;
		}
		else if (kwm == KWM_NO) {
			if ((curpx->options & PR_O_HTTP_MODE) == mode)
				curpx->options &= ~PR_O_HTTP_MODE;
			goto done;
		}
	}
	else if (strcmp(args[1], "http-tunnel") == 0) {
		memprintf(err, "option '%s' is not supported any more since HAProxy 2.1, please just remove it, "
		          "it shouldn't be needed.", args[1]);
		ret |= ERR_FATAL;
		goto done;
	}
	else if (strcmp(args[1], "forwarded") == 0) {
		if (kwm == KWM_STD) {
			ret = proxy_http_parse_7239(args, 0, curpx, defpx, file, line);
			goto done;
		}
		else if (kwm == KWM_NO) {
			if (curpx->http_ext)
				http_ext_7239_clean(curpx);
			goto done;
		}
	}

	/* Redispatch can take an integer argument that control when the
	 * redispatch occurs. All values are relative to the retries option.
	 * This can be cancelled using "no option xxx".
	 */
	if (strcmp(args[1], "redispatch") == 0) {
		if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[1], NULL)) {
			ret |= ERR_WARN;
			goto done;
		}

		curpx->no_options &= ~PR_O_REDISP;
		curpx->options &= ~PR_O_REDISP;

		switch (kwm) {
		case KWM_STD:
			curpx->options |= PR_O_REDISP;
			curpx->redispatch_after = -1;
			if (*args[2]) {
				curpx->redispatch_after = atol(args[2]);
				if (!curpx->redispatch_after)
					curpx->options &= ~PR_O_REDISP;
			}
			break;
		case KWM_NO:
			curpx->no_options |= PR_O_REDISP;
			curpx->redispatch_after = 0;
			break;
		case KWM_DEF: /* already cleared */
			break;
		}
		goto done;
	}

	if (strcmp(args[1], "http_proxy") == 0) {
		memprintf(err, "option '%s' is not supported any more since HAProxy 2.5. This option stopped "
			  "working in HAProxy 1.9 and usually had nasty side effects. It can be more reliably "
			  "implemented with combinations of 'http-request set-dst' and 'http-request set-uri', "
			  "and even 'http-request do-resolve' if DNS resolution is desired.", args[1]);
		ret |= ERR_FATAL;
		goto done;
	}
	else if (strcmp(args[1], "use-small-buffers") == 0) {
		unsigned int flags = PR_O2_USE_SBUF_ALL;

		if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[1], NULL)) {
			ret |= ERR_WARN;
			goto done;
		}

		if (*(args[2])) {
			int cur_arg;

			flags = 0;
			for (cur_arg = 2; *(args[cur_arg]); cur_arg++) {
				if (strcmp(args[cur_arg], "queue") == 0)
					flags |= PR_O2_USE_SBUF_QUEUE;
				else if (strcmp(args[cur_arg], "l7-retries") == 0)
					flags |= PR_O2_USE_SBUF_L7_RETRY;
				else if (strcmp(args[cur_arg], "check") == 0)
					flags |= PR_O2_USE_SBUF_CHECK;
				else {
					memprintf(err, "invalid parameter '%s'. option '%s' expects 'queue', "
						  "'l7-retries' or 'check' value.", args[cur_arg], args[1]);
					ret |= ERR_FATAL;
					goto done;
				}
			}
		}

		if (kwm == KWM_STD) {
			curpx->options2 &= ~PR_O2_USE_SBUF_ALL;
			curpx->options2 |= flags;
		}
		else if (kwm == KWM_NO)
			curpx->options2 &= ~flags;
		goto done;
	}

	if (kwm != KWM_STD) {
		memprintf(err, "negation/default is not supported for option '%s'.", args[1]);
		ret |= ERR_FATAL;
		goto done;
	}

	if (strcmp(args[1], "httplog") == 0 ||
	    strcmp(args[1], "tcplog") == 0) {
		int http = (args[1][0] == 'h');
		char *logformat = http ? default_http_log_format : default_tcp_log_format;
		char *kw = http ? "option httplog" : "option tcplog";

		if (*(args[2]) != '\0') {
			if (strcmp(args[2], "clf") != 0) {
				memprintf(err, "keyword '%s' only supports option 'clf'.", args[1]);
				ret |= ERR_FATAL;
				goto done;
			}

			if (http) {
				curpx->options2 |= PR_O2_CLFLOG;
				logformat = clf_http_log_format;
				kw = "option httplog clf";
			}
			else {
				logformat = clf_tcp_log_format;
				kw = "option tcplog clf";
			}

			if (too_many_args_idx(1, 1, args, err, NULL)) {
				ret |= ERR_FATAL;
				goto done;
			}
		}

		if (curpx->logformat.str && (curpx->cap & PR_CAP_DEF))
			ha_warning("parsing [%s:%d]: '%s' overrides previous '%s' in 'defaults' section.\n",
			           file, line, kw, proxy_logformat_origin(curpx));
		else if (!(curpx->cap & (PR_CAP_DEF | PR_CAP_FE)))
			ha_warning("parsing [%s:%d] : backend '%s' : '%s' directive is ignored in backends.\n",
			           file, line, curpx->id, kw);

		lf_expr_deinit(&curpx->logformat);
		curpx->logformat.str = logformat;
		curpx->logformat.conf.file = strdup(curpx->conf.args.file);
		curpx->logformat.conf.line = curpx->conf.args.line;
	}
	else if (strcmp(args[1], "httpslog") == 0) {
		if (curpx->logformat.str && (curpx->cap & PR_CAP_DEF))
			ha_warning("parsing [%s:%d]: '%s' overrides previous '%s' in 'defaults' section.\n",
			           file, line, "option httpslog", proxy_logformat_origin(curpx));
		else if (!(curpx->cap & (PR_CAP_DEF | PR_CAP_FE)))
			ha_warning("parsing [%s:%d] : backend '%s' : '%s' directive is ignored in backends.\n",
			           file, line, curpx->id, "option httpslog");

		lf_expr_deinit(&curpx->logformat);
		curpx->logformat.str = default_https_log_format;
		curpx->logformat.conf.file = strdup(curpx->conf.args.file);
		curpx->logformat.conf.line = curpx->conf.args.line;
	}
	else if (strcmp(args[1], "tcpka") == 0) {
		/* enable TCP keep-alives on client and server streams */
		warnifnotcap(curpx, PR_CAP_BE | PR_CAP_FE, file, line, args[1], NULL);

		if (too_many_args_idx(0, 1, args, err, NULL)) {
			ret |= ERR_FATAL;
			goto done;
		}

		if (curpx->cap & PR_CAP_FE)
			curpx->options |= PR_O_TCP_CLI_KA;
		if (curpx->cap & PR_CAP_BE)
			curpx->options |= PR_O_TCP_SRV_KA;
	}
	else if (strcmp(args[1], "httpchk") == 0)
		ret = proxy_parse_httpchk_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "ssl-hello-chk") == 0)
		ret = proxy_parse_ssl_hello_chk_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "smtpchk") == 0)
		ret = proxy_parse_smtpchk_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "pgsql-check") == 0)
		ret = proxy_parse_pgsql_check_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "redis-check") == 0)
		ret = proxy_parse_redis_check_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "mysql-check") == 0)
		ret = proxy_parse_mysql_check_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "ldap-check") == 0)
		ret = proxy_parse_ldap_check_opt(args, 0, curpx, defpx, file, line);
#if defined(USE_SPOE)
	else if (strcmp(args[1], "spop-check") == 0)
		ret = proxy_parse_spop_check_opt(args, 0, curpx, defpx, file, line);
#endif
	else if (strcmp(args[1], "tcp-check") == 0)
		ret = proxy_parse_tcp_check_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "external-check") == 0)
		ret = proxy_parse_external_check_opt(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "forwardfor") == 0)
		ret = proxy_http_parse_xff(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "originalto") == 0)
		ret = proxy_http_parse_xot(args, 0, curpx, defpx, file, line);
	else if (strcmp(args[1], "http-restrict-req-hdr-names") == 0) {
		if (too_many_args(2, args, err, NULL)) {
			ret |= ERR_FATAL;
			goto done;
		}

		if (*(args[2]) == 0) {
			memprintf(err, "missing parameter. option '%s' expects 'preserve', 'reject' or 'delete' option.", args[1]);
			ret |= ERR_FATAL;
			goto done;
		}

		curpx->options2 &= ~PR_O2_RSTRICT_REQ_HDR_NAMES_MASK;
		if (strcmp(args[2], "preserve") == 0)
			curpx->options2 |= PR_O2_RSTRICT_REQ_HDR_NAMES_NOOP;
		else if (strcmp(args[2], "reject") == 0)
			curpx->options2 |= PR_O2_RSTRICT_REQ_HDR_NAMES_BLK;
		else if (strcmp(args[2], "delete") == 0)
			curpx->options2 |= PR_O2_RSTRICT_REQ_HDR_NAMES_DEL;
		else {
			memprintf(err, "invalid parameter '%s'. option '%s' expects 'preserve', 'reject' or 'delete' option.",
			          args[2], args[1]);
			ret |= ERR_FATAL;
			goto done;
		}
	}
	else if (strcmp(args[1], "accept-invalid-http-request") == 0 ||
		 strcmp(args[1], "accept-invalid-http-response") == 0) {
		int req = (args[1][22] == 'q');
		unsigned int val;

		if (too_many_args_idx(0, 1, args, err, NULL)) {
			ret |= ERR_FATAL;
			goto done;
		}

		if (warnifnotcap(curpx, req ? PR_CAP_FE : PR_CAP_BE, file, line, args[1], NULL)) {
			ret |= ERR_WARN;
			goto done;
		}

		ha_warning("parsing [%s:%d]: option '%s' is deprecated. please use 'option accept-unsafe-violations-in-http-%s' if absolutely needed.\n",
		           file, line, args[1], req ? "request" : "response");

		val = req ? PR_O2_REQBUG_OK : PR_O2_RSPBUG_OK;
		curpx->no_options2 &= ~val;
		curpx->options2    |= val;
	}
	else {
		const char *best = proxy_find_best_option(args[1], common_options);

		if (best)
			memprintf(err, "unknown option '%s'; did you mean '%s' maybe ?", args[1], best);
		else
			memprintf(err, "unknown option '%s'.", args[1]);
		ret |= ERR_FATAL;
		goto done;
	}

 done:
	return (ret & ERR_FATAL) ? -1 : (ret & ERR_WARN) ? 1 : 0;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_LISTEN, "acl", proxy_parse_acl },
	{ CFG_LISTEN, "appsession", proxy_parse_removed_kw },
	{ CFG_LISTEN, "backlog", proxy_parse_conn_limits },
	{ CFG_LISTEN, "balance", proxy_parse_balance },
	{ CFG_LISTEN, "bind", proxy_parse_bind },
	{ CFG_LISTEN, "bind-process", proxy_parse_removed_kw },
	{ CFG_LISTEN, "block", proxy_parse_removed_kw },
	{ CFG_LISTEN, "capture", proxy_parse_capture },
	{ CFG_LISTEN, "cliexp", proxy_parse_removed_kw },
	{ CFG_LISTEN, "cookie", proxy_parse_cookie },
	{ CFG_LISTEN, "default-server", proxy_parse_server },
	{ CFG_LISTEN, "default_backend", proxy_parse_use_backend },
	{ CFG_LISTEN, "description", proxy_parse_id_desc },
	{ CFG_LISTEN, "disabled", proxy_parse_enabled },
	{ CFG_LISTEN, "dispatch", proxy_parse_removed_kw },
	{ CFG_LISTEN, "dynamic-cookie-key", proxy_parse_be_opts },
	{ CFG_LISTEN, "email-alert", proxy_parse_email_alert },
	{ CFG_LISTEN, "enabled", proxy_parse_enabled },
	{ CFG_LISTEN, "error-log-format", proxy_parse_logformat },
	{ CFG_LISTEN, "force-persist", proxy_parse_persist },
	{ CFG_LISTEN, "fullconn", proxy_parse_conn_limits },
	{ CFG_LISTEN, "grace", proxy_parse_removed_kw },
	{ CFG_LISTEN, "hash-balance-factor", proxy_parse_balance },
	{ CFG_LISTEN, "hash-type", proxy_parse_balance },
	{ CFG_LISTEN, "http-after-response", proxy_parse_http_rules },
	{ CFG_LISTEN, "http-request", proxy_parse_http_rules },
	{ CFG_LISTEN, "http-response", proxy_parse_http_rules },
	{ CFG_LISTEN, "http-reuse", proxy_parse_be_opts },
	{ CFG_LISTEN, "http-send-name-header", proxy_parse_be_opts },
	{ CFG_LISTEN, "id", proxy_parse_id_desc },
	{ CFG_LISTEN, "ignore-persist", proxy_parse_persist },
	{ CFG_LISTEN, "load-server-state-from-file", proxy_parse_be_opts },
	{ CFG_LISTEN, "log", proxy_parse_log_opts },
	{ CFG_LISTEN, "log-format", proxy_parse_logformat },
	{ CFG_LISTEN, "log-format-sd", proxy_parse_logformat },
	{ CFG_LISTEN, "log-tag", proxy_parse_log_opts },
	{ CFG_LISTEN, "max-session-srv-conns", proxy_parse_conn_limits },
	{ CFG_LISTEN, "maxconn", proxy_parse_conn_limits },
	{ CFG_LISTEN, "mode", proxy_parse_mode },
	{ CFG_LISTEN, "monitor", proxy_parse_monitor },
	{ CFG_LISTEN, "monitor-net", proxy_parse_removed_kw },
	{ CFG_LISTEN, "monitor-uri", proxy_parse_monitor },
	{ CFG_LISTEN, "option", proxy_parse_option },
	{ CFG_LISTEN, "persist", proxy_parse_persist },
	{ CFG_LISTEN, "redirect", proxy_parse_redirect },
	{ CFG_LISTEN, "redisp", proxy_parse_removed_kw },
	{ CFG_LISTEN, "redispatch", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqadd", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqallow", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqdel", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqdeny", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqiallow", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqidel", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqideny", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqipass", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqirep", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqitarpit", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqpass", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqrep", proxy_parse_removed_kw },
	{ CFG_LISTEN, "reqtarpit", proxy_parse_removed_kw },
	{ CFG_LISTEN, "retries", proxy_parse_be_opts },
	{ CFG_LISTEN, "rspadd", proxy_parse_removed_kw },
	{ CFG_LISTEN, "rspdel", proxy_parse_removed_kw },
	{ CFG_LISTEN, "rspdeny", proxy_parse_removed_kw },
	{ CFG_LISTEN, "rspidel", proxy_parse_removed_kw },
	{ CFG_LISTEN, "rspideny", proxy_parse_removed_kw },
	{ CFG_LISTEN, "rspirep", proxy_parse_removed_kw },
	{ CFG_LISTEN, "rsprep", proxy_parse_removed_kw },
	{ CFG_LISTEN, "server", proxy_parse_server },
	{ CFG_LISTEN, "server-state-file-name", proxy_parse_be_opts },
	{ CFG_LISTEN, "server-template", proxy_parse_server },
	{ CFG_LISTEN, "source", proxy_parse_source },
	{ CFG_LISTEN, "srvexp", proxy_parse_removed_kw },
	{ CFG_LISTEN, "stats", proxy_parse_stats },
	{ CFG_LISTEN, "stick", proxy_parse_stick },
	{ CFG_LISTEN, "stick-table", proxy_parse_stick_table },
	{ CFG_LISTEN, "transparent", proxy_parse_removed_kw },
	{ CFG_LISTEN, "unique-id-format", proxy_parse_logformat },
	{ CFG_LISTEN, "unique-id-header", proxy_parse_log_opts },
	{ CFG_LISTEN, "use-server", proxy_parse_use_backend },
	{ CFG_LISTEN, "use_backend", proxy_parse_use_backend },
	{ CFG_LISTEN, "usesrc", proxy_parse_source },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
