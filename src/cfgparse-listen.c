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
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_ext.h>
#include <haproxy/http_rules.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/peers.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/stats-t.h>
#include <haproxy/stick_table.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth.h>

/* some keywords that are still being parsed using strcmp() and are not
 * registered anywhere. They are used as suggestions for mistyped words.
 */
static const char *common_kw_list[] = {
	"listen", "frontend", "backend", "defaults", "server",
	"default-server", "server-template", "bind", "monitor-net",
	"monitor-uri", "mode", "id", "description", "disabled", "enabled",
	"acl", "dynamic-cookie-key", "cookie", "email-alert",
	"persist", "appsession", "load-server-state-from-file",
	"server-state-file-name", "max-session-srv-conns", "capture",
	"retries", "http-request", "http-response", "http-after-response",
	"http-send-name-header", "block", "redirect", "use_backend",
	"use-server", "force-persist", "ignore-persist", "force-persist",
	"stick-table", "stick", "stats", "option", "default_backend",
	"http-reuse", "monitor", "transparent", "maxconn", "backlog",
	"fullconn", "dispatch", "balance", "log-balance", "hash-type",
	"hash-balance-factor", "unique-id-format", "unique-id-header",
	"log-format", "log-format-sd", "log-tag", "log", "source", "usesrc",
	"error-log-format",
	NULL /* must be last */
};

static const char *common_options[] = {
	"httpclose", "http-server-close", "http-keep-alive",
	"redispatch", "httplog", "tcplog", "tcpka", "httpchk",
	"ssl-hello-chk", "smtpchk", "pgsql-check", "redis-check",
	"mysql-check", "ldap-check", "spop-check", "tcp-check",
	"external-check", "forwardfor", "original-to", "forwarded",
	NULL /* must be last */
};

/* Report a warning if a rule is placed after a 'tcp-request session' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_tcp_sess(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->tcp_req.l5_rules)) {
		ha_warning("parsing [%s:%d] : a '%s' rule placed after a 'tcp-request session' rule will still be processed before.\n",
			   file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'tcp-request content' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_tcp_cont(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->tcp_req.inspect_rules)) {
		ha_warning("parsing [%s:%d] : a '%s' rule placed after a 'tcp-request content' rule will still be processed before.\n",
			   file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'monitor fail' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_monitor(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->mon_fail_cond)) {
		ha_warning("parsing [%s:%d] : a '%s' rule placed after a 'monitor fail' rule will still be processed before.\n",
			   file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after an 'http_request' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_http_req(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->http_req_rules)) {
		ha_warning("parsing [%s:%d] : a '%s' rule placed after an 'http-request' rule will still be processed before.\n",
			   file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a redirect rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_redirect(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->redirect_rules)) {
		ha_warning("parsing [%s:%d] : a '%s' rule placed after a 'redirect' rule will still be processed before.\n",
			   file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'use_backend' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_use_backend(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->switching_rules)) {
		ha_warning("parsing [%s:%d] : a '%s' rule placed after a 'use_backend' rule will still be processed before.\n",
			   file, line, arg);
		return 1;
	}
	return 0;
}

/* Report a warning if a rule is placed after a 'use-server' rule.
 * Return 1 if the warning has been emitted, otherwise 0.
 */
int warnif_rule_after_use_server(struct proxy *proxy, const char *file, int line, const char *arg)
{
	if (!LIST_ISEMPTY(&proxy->server_rules)) {
		ha_warning("parsing [%s:%d] : a '%s' rule placed after a 'use-server' rule will still be processed before.\n",
			   file, line, arg);
		return 1;
	}
	return 0;
}

/* report a warning if a redirect rule is dangerously placed */
int warnif_misplaced_redirect(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_use_backend(proxy, file, line, arg) ||
		warnif_rule_after_use_server(proxy, file, line, arg);
}

/* report a warning if an http-request rule is dangerously placed */
int warnif_misplaced_http_req(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_redirect(proxy, file, line, arg) ||
		warnif_misplaced_redirect(proxy, file, line, arg);
}

/* report a warning if a block rule is dangerously placed */
int warnif_misplaced_monitor(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_http_req(proxy, file, line, arg) ||
		warnif_misplaced_http_req(proxy, file, line, arg);
}

/* report a warning if a "tcp request content" rule is dangerously placed */
int warnif_misplaced_tcp_cont(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_monitor(proxy, file, line, arg) ||
		warnif_misplaced_monitor(proxy, file, line, arg);
}

/* report a warning if a "tcp request session" rule is dangerously placed */
int warnif_misplaced_tcp_sess(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_tcp_cont(proxy, file, line, arg) ||
		warnif_misplaced_tcp_cont(proxy, file, line, arg);
}

/* report a warning if a "tcp request connection" rule is dangerously placed */
int warnif_misplaced_tcp_conn(struct proxy *proxy, const char *file, int line, const char *arg)
{
	return	warnif_rule_after_tcp_sess(proxy, file, line, arg) ||
		warnif_misplaced_tcp_sess(proxy, file, line, arg);
}

int cfg_parse_listen(const char *file, int linenum, char **args, int kwm)
{
	static struct proxy *curr_defproxy = NULL;
	static struct proxy *last_defproxy = NULL;
	const char *err;
	int rc;
	int err_code = 0;
	struct acl_cond *cond = NULL;
	char *errmsg = NULL;
	struct bind_conf *bind_conf;

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

		curproxy = (rc & PR_CAP_FE) ? proxy_fe_by_name(args[1]) : proxy_be_by_name(args[1]);
		if (curproxy) {
			ha_alert("Parsing [%s:%d]: %s '%s' has the same name as %s '%s' declared at %s:%d.\n",
				 file, linenum, proxy_cap_str(rc), args[1], proxy_type_str(curproxy),
				 curproxy->id, curproxy->conf.file, curproxy->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
		}

		curproxy = log_forward_by_name(args[1]);
		if (curproxy) {
			ha_alert("Parsing [%s:%d]: %s '%s' has the same name as log forward section '%s' declared at %s:%d.\n",
			         file, linenum, proxy_cap_str(rc), args[1],
			         curproxy->id, curproxy->conf.file, curproxy->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if ((*args[2] && (!*args[3] || strcmp(args[2], "from") != 0)) ||
		    alertif_too_many_args(3, file, linenum, args, &err_code)) {
			if (rc & PR_CAP_FE)
				ha_alert("parsing [%s:%d] : please use the 'bind' keyword for listening addresses.\n", file, linenum);
			goto out;
		}
	}

	if (rc & PR_CAP_LISTEN) {  /* new proxy or defaults section */
		const char *name = args[1];
		int arg = 2;

		if (rc & PR_CAP_DEF && strcmp(args[1], "from") == 0 && *args[2] && !*args[3]) {
			// also support "defaults from blah" (no name then)
			arg = 1;
			name = "";
		}

		/* only regular proxies inherit from the previous defaults section */
		if (!(rc & PR_CAP_DEF))
			curr_defproxy = last_defproxy;

		if (strcmp(args[arg], "from") == 0) {
			struct ebpt_node *next_by_name;

			curr_defproxy = proxy_find_by_name(args[arg+1], PR_CAP_DEF, 0);

			if (!curr_defproxy) {
				ha_alert("parsing [%s:%d] : defaults section '%s' not found for %s '%s'.\n", file, linenum, args[arg+1], proxy_cap_str(rc), name);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if ((next_by_name = ebpt_next_dup(&curr_defproxy->conf.by_name))) {
				struct proxy *px2 = container_of(next_by_name, struct proxy, conf.by_name);

				ha_alert("parsing [%s:%d] : ambiguous defaults section name '%s' referenced by %s '%s' exists at least at %s:%d and %s:%d.\n",
					 file, linenum, args[arg+1], proxy_cap_str(rc), name,
					 curr_defproxy->conf.file, curr_defproxy->conf.line, px2->conf.file, px2->conf.line);
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

		if (curr_defproxy && (!LIST_ISEMPTY(&curr_defproxy->http_req_rules)        ||
				      !LIST_ISEMPTY(&curr_defproxy->http_res_rules)        ||
				      !LIST_ISEMPTY(&curr_defproxy->http_after_res_rules)  ||
				      !LIST_ISEMPTY(&curr_defproxy->tcp_req.l4_rules)      ||
				      !LIST_ISEMPTY(&curr_defproxy->tcp_req.l5_rules)      ||
				      !LIST_ISEMPTY(&curr_defproxy->tcp_req.inspect_rules) ||
				      !LIST_ISEMPTY(&curr_defproxy->tcp_rep.inspect_rules))) {
			/* If the current default proxy defines TCP/HTTP rules, the
			 * current proxy will keep a reference on it. But some sanity
			 * checks are performed first:
			 *
			 * - It cannot be used to init a defaults section
			 * - It cannot be used to init a listen section
			 * - It cannot be used to init backend and frontend sections at
			 *   same time. It can be used to init several sections of the
			 *   same type only.
			 * - It cannot define L4/L5 TCP rules if it is used to init
			 *   backend sections.
			 * - It cannot define 'tcp-response content' rules if it
			 *   is used to init frontend sections.
			 *
			 * If no error is found, refcount of the default proxy is incremented.
			 */

			/* Note: Add tcpcheck_rules too if unresolve args become allowed in defaults section */
			if (rc & PR_CAP_DEF) {
				ha_alert("parsing [%s:%d]: a defaults section cannot inherit from a defaults section defining TCP/HTTP rules (defaults section at %s:%d).\n",
					 file, linenum, curr_defproxy->conf.file, curr_defproxy->conf.line);
				err_code |= ERR_ALERT | ERR_ABORT;
			}
			else if ((rc & PR_CAP_LISTEN) == PR_CAP_LISTEN) {
				ha_alert("parsing [%s:%d]: a listen section cannot inherit from a defaults section defining TCP/HTTP rules.\n",
					 file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
			}
			else {
				char defcap = (curr_defproxy->cap & PR_CAP_LISTEN);

				if ((defcap == PR_CAP_BE || defcap == PR_CAP_FE) && (rc & PR_CAP_LISTEN) != defcap) {
					ha_alert("parsing [%s:%d]: frontends and backends cannot inherit from the same defaults section"
						 " if it defines TCP/HTTP rules (defaults section at %s:%d).\n",
						 file, linenum, curr_defproxy->conf.file, curr_defproxy->conf.line);
					err_code |= ERR_ALERT | ERR_ABORT;
				}
				else if (!(rc & PR_CAP_FE) && (!LIST_ISEMPTY(&curr_defproxy->tcp_req.l4_rules) ||
							       !LIST_ISEMPTY(&curr_defproxy->tcp_req.l5_rules))) {
					ha_alert("parsing [%s:%d]: a backend section cannot inherit from a defaults section defining"
						 " 'tcp-request connection' or 'tcp-request session' rules (defaults section at %s:%d).\n",
						 file, linenum, curr_defproxy->conf.file, curr_defproxy->conf.line);
					err_code |= ERR_ALERT | ERR_ABORT;
				}
				else if (!(rc & PR_CAP_BE) && !LIST_ISEMPTY(&curr_defproxy->tcp_rep.inspect_rules)) {
					ha_alert("parsing [%s:%d]: a frontend section cannot inherit from a defaults section defining"
						 " 'tcp-response content' rules (defaults section at %s:%d).\n",
						 file, linenum, curr_defproxy->conf.file, curr_defproxy->conf.line);
					err_code |= ERR_ALERT | ERR_ABORT;
				}
				else {
					curr_defproxy->cap = (curr_defproxy->cap & ~PR_CAP_LISTEN) | (rc & PR_CAP_LISTEN);
					proxy_ref_defaults(curproxy, curr_defproxy);
				}
			}
		}

		if (curr_defproxy && (curr_defproxy->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) &&
		    (curproxy->cap & PR_CAP_LISTEN) == PR_CAP_BE) {
			/* If the current default proxy defines tcpcheck rules, the
			 * current proxy will keep a reference on it. but only if the
			 * current proxy has the backend capability.
			 */
			proxy_ref_defaults(curproxy, curr_defproxy);
		}

		if ((rc & PR_CAP_BE) && curr_defproxy && (curr_defproxy->nb_req_cap || curr_defproxy->nb_rsp_cap)) {
			ha_alert("parsing [%s:%d]: backend or defaults sections cannot inherit from a defaults section defining"
				 " capptures (defaults section at %s:%d).\n",
				 file, linenum, curr_defproxy->conf.file, curr_defproxy->conf.line);
			err_code |= ERR_ALERT | ERR_ABORT;
		}

		if (rc & PR_CAP_DEF) {
			/* last and current proxies must be updated to this one */
			curr_defproxy = last_defproxy = curproxy;
		} else {
			/* regular proxies are in a list */
			curproxy->next = proxies_list;
			proxies_list = curproxy;
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
	if ((strcmp(args[0], "server") == 0)) {
		err_code |= parse_server(file, linenum, args,
		                         curproxy, curr_defproxy,
		                         SRV_PARSE_PARSE_ADDR);

		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (strcmp(args[0], "default-server") == 0) {
		err_code |= parse_server(file, linenum, args,
		                         curproxy, curr_defproxy,
		                         SRV_PARSE_DEFAULT_SERVER);

		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (strcmp(args[0], "server-template") == 0) {
		err_code |= parse_server(file, linenum, args,
		                         curproxy, curr_defproxy,
		                         SRV_PARSE_TEMPLATE|SRV_PARSE_PARSE_ADDR);

		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (strcmp(args[0], "bind") == 0) {  /* new listen addresses */
		struct listener *l;
		int cur_arg;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects {<path>|[addr1]:port1[-end1]}{,[addr]:port[-end]}... as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		bind_conf = bind_conf_alloc(curproxy, file, linenum, args[1], xprt_get(XPRT_RAW));
		if (!bind_conf)
			goto alloc_error;

		/* use default settings for unix sockets */
		bind_conf->settings.ux.uid  = global.unix_bind.ux.uid;
		bind_conf->settings.ux.gid  = global.unix_bind.ux.gid;
		bind_conf->settings.ux.mode = global.unix_bind.ux.mode;

		/* NOTE: the following line might create several listeners if there
		 * are comma-separated IPs or port ranges. So all further processing
		 * will have to be applied to all listeners created after last_listen.
		 */
		if (!str2listener(args[1], curproxy, bind_conf, file, linenum, &errmsg)) {
			if (errmsg && *errmsg) {
				indent_msg(&errmsg, 2);
				ha_alert("parsing [%s:%d] : '%s' : %s\n", file, linenum, args[0], errmsg);
			}
			else
				ha_alert("parsing [%s:%d] : '%s' : error encountered while parsing listening address '%s'.\n",
					 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			/* Set default global rights and owner for unix bind  */
			global.maxsock++;
		}

		cur_arg = 2;
		err_code |= bind_parse_args_list(bind_conf, args, cur_arg, cursection, file, linenum);
		goto out;
	}
	else if (strcmp(args[0], "monitor-net") == 0) {  /* set the range of IPs to ignore */
		ha_alert("parsing [%s:%d] : 'monitor-net' doesn't exist anymore. Please use 'http-request return status 200 if { src %s }' instead.\n", file, linenum, args[1]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "monitor-uri") == 0) {  /* set the URI to intercept */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an URI.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		istfree(&curproxy->monitor_uri);
		curproxy->monitor_uri = istdup(ist(args[1]));
		if (!isttest(curproxy->monitor_uri))
			goto alloc_error;

		goto out;
	}
	else if (strcmp(args[0], "mode") == 0) {  /* sets the proxy mode */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (strcmp(args[1], "http") == 0) curproxy->mode = PR_MODE_HTTP;
		else if (strcmp(args[1], "tcp") == 0) curproxy->mode = PR_MODE_TCP;
		else if (strcmp(args[1], "log") == 0 && (curproxy->cap & PR_CAP_BE)) curproxy->mode = PR_MODE_SYSLOG;
		else if (strcmp(args[1], "health") == 0) {
			ha_alert("parsing [%s:%d] : 'mode health' doesn't exist anymore. Please use 'http-request return status 200' instead.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else {
			ha_alert("parsing [%s:%d] : unknown proxy mode '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "id") == 0) {
		struct eb32_node *node;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->uuid = atol(args[1]);
		curproxy->conf.id.key = curproxy->uuid;
		curproxy->options |= PR_O_FORCED_ID;

		if (curproxy->uuid <= 0) {
			ha_alert("parsing [%s:%d]: custom id has to be > 0.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		node = eb32_lookup(&used_proxy_id, curproxy->uuid);
		if (node) {
			struct proxy *target = container_of(node, struct proxy, conf.id);
			ha_alert("parsing [%s:%d]: %s %s reuses same custom id as %s %s (declared at %s:%d).\n",
				 file, linenum, proxy_type_str(curproxy), curproxy->id,
				 proxy_type_str(target), target->id, target->conf.file, target->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		eb32_insert(&used_proxy_id, &curproxy->conf.id);
	}
	else if (strcmp(args[0], "description") == 0) {
		int i, len=0;
		char *d;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: '%s' expects a string argument.\n",
				 file, linenum, args[0]);
			return -1;
		}

		for (i = 1; *args[i]; i++)
			len += strlen(args[i]) + 1;

		d = calloc(1, len);
		if (!d)
			goto alloc_error;
		curproxy->desc = d;

		d += snprintf(d, curproxy->desc + len - d, "%s", args[1]);
		for (i = 2; *args[i]; i++)
			d += snprintf(d, curproxy->desc + len - d, " %s", args[i]);

	}
	else if (strcmp(args[0], "disabled") == 0) {  /* disables this proxy */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		curproxy->flags |= PR_FL_DISABLED;
	}
	else if (strcmp(args[0], "enabled") == 0) {  /* enables this proxy (used to revert a disabled default) */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		curproxy->flags &= ~PR_FL_DISABLED;
	}
	else if (strcmp(args[0], "bind-process") == 0) {  /* enable this proxy only on some processes */
		ha_alert("parsing [%s:%d]: '%s' is not supported anymore.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	else if (strcmp(args[0], "acl") == 0) {  /* add an ACL */
		if ((curproxy->cap & PR_CAP_DEF) && strlen(curproxy->id) == 0) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in anonymous 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in acl name '%s'.\n",
				 file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcasecmp(args[1], "or") == 0) {
			ha_alert("parsing [%s:%d] : acl name '%s' will never match. 'or' is used to express a "
				   "logical disjunction within a condition.\n",
				   file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (parse_acl((const char **)args + 1, &curproxy->acl, &errmsg, &curproxy->conf.args, file, linenum) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing ACL '%s' : %s.\n",
				 file, linenum, args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "dynamic-cookie-key") == 0) { /* Dynamic cookies secret key */

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects <secret_key> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->dyncookie_key);
		curproxy->dyncookie_key = strdup(args[1]);
	}
	else if (strcmp(args[0], "cookie") == 0) {  /* cookie name */
		int cur_arg;

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects <cookie_name> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->ck_opts = 0;
		curproxy->cookie_maxidle = curproxy->cookie_maxlife = 0;
		ha_free(&curproxy->cookie_domain);
		free(curproxy->cookie_name);
		curproxy->cookie_name = strdup(args[1]);
		if (!curproxy->cookie_name)
			goto alloc_error;
		curproxy->cookie_len = strlen(curproxy->cookie_name);

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (strcmp(args[cur_arg], "rewrite") == 0) {
				curproxy->ck_opts |= PR_CK_RW;
			}
			else if (strcmp(args[cur_arg], "indirect") == 0) {
				curproxy->ck_opts |= PR_CK_IND;
			}
			else if (strcmp(args[cur_arg], "insert") == 0) {
				curproxy->ck_opts |= PR_CK_INS;
			}
			else if (strcmp(args[cur_arg], "nocache") == 0) {
				curproxy->ck_opts |= PR_CK_NOC;
			}
			else if (strcmp(args[cur_arg], "postonly") == 0) {
				curproxy->ck_opts |= PR_CK_POST;
			}
			else if (strcmp(args[cur_arg], "preserve") == 0) {
				curproxy->ck_opts |= PR_CK_PSV;
			}
			else if (strcmp(args[cur_arg], "prefix") == 0) {
				curproxy->ck_opts |= PR_CK_PFX;
			}
			else if (strcmp(args[cur_arg], "httponly") == 0) {
				curproxy->ck_opts |= PR_CK_HTTPONLY;
			}
			else if (strcmp(args[cur_arg], "secure") == 0) {
				curproxy->ck_opts |= PR_CK_SECURE;
			}
			else if (strcmp(args[cur_arg], "domain") == 0) {
				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d]: '%s' expects <domain> as argument.\n",
						 file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!strchr(args[cur_arg + 1], '.')) {
					/* rfc6265, 5.2.3 The Domain Attribute */
					ha_warning("parsing [%s:%d]: domain '%s' contains no embedded dot,"
						   " this configuration may not work properly (see RFC6265#5.2.3).\n",
						   file, linenum, args[cur_arg + 1]);
					err_code |= ERR_WARN;
				}

				err = invalid_domainchar(args[cur_arg + 1]);
				if (err) {
					ha_alert("parsing [%s:%d]: character '%c' is not permitted in domain name '%s'.\n",
						 file, linenum, *err, args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!curproxy->cookie_domain) {
					curproxy->cookie_domain = strdup(args[cur_arg + 1]);
				} else {
					/* one domain was already specified, add another one by
					 * building the string which will be returned along with
					 * the cookie.
					 */
					memprintf(&curproxy->cookie_domain, "%s; domain=%s", curproxy->cookie_domain, args[cur_arg+1]);
				}

				if (!curproxy->cookie_domain)
					goto alloc_error;
				cur_arg++;
			}
			else if (strcmp(args[cur_arg], "maxidle") == 0) {
				unsigned int maxidle;
				const char *res;

				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d]: '%s' expects <idletime> in seconds as argument.\n",
						 file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				res = parse_time_err(args[cur_arg + 1], &maxidle, TIME_UNIT_S);
				if (res == PARSE_TIME_OVER) {
					ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s>, maximum value is 2147483647 s (~68 years).\n",
						 file, linenum, args[cur_arg+1], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				else if (res == PARSE_TIME_UNDER) {
					ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s>, minimum non-null value is 1 s.\n",
						 file, linenum, args[cur_arg+1], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				else if (res) {
					ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
						 file, linenum, *res, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->cookie_maxidle = maxidle;
				cur_arg++;
			}
			else if (strcmp(args[cur_arg], "maxlife") == 0) {
				unsigned int maxlife;
				const char *res;

				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d]: '%s' expects <lifetime> in seconds as argument.\n",
						 file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}


				res = parse_time_err(args[cur_arg + 1], &maxlife, TIME_UNIT_S);
				if (res == PARSE_TIME_OVER) {
					ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s>, maximum value is 2147483647 s (~68 years).\n",
						 file, linenum, args[cur_arg+1], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				else if (res == PARSE_TIME_UNDER) {
					ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s>, minimum non-null value is 1 s.\n",
						 file, linenum, args[cur_arg+1], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				else if (res) {
					ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
						 file, linenum, *res, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->cookie_maxlife = maxlife;
				cur_arg++;
			}
			else if (strcmp(args[cur_arg], "dynamic") == 0) { /* Dynamic persistent cookies secret key */

				if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[cur_arg], NULL))
					err_code |= ERR_WARN;
				curproxy->ck_opts |= PR_CK_DYNAMIC;
			}
			else if (strcmp(args[cur_arg], "attr") == 0) {
				char *val;
				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d]: '%s' expects <value> as argument.\n",
						 file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				val = args[cur_arg + 1];
				while (*val) {
					if (iscntrl((unsigned char)*val) || *val == ';') {
						ha_alert("parsing [%s:%d]: character '%%x%02X' is not permitted in attribute value.\n",
							 file, linenum, *val);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					val++;
				}
				/* don't add ';' for the first attribute */
				if (!curproxy->cookie_attrs)
					curproxy->cookie_attrs = strdup(args[cur_arg + 1]);
				else
					memprintf(&curproxy->cookie_attrs, "%s; %s", curproxy->cookie_attrs, args[cur_arg + 1]);

				if (!curproxy->cookie_attrs)
					goto alloc_error;
				cur_arg++;
			}

			else {
				ha_alert("parsing [%s:%d] : '%s' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache', 'postonly', 'domain', 'maxidle', 'dynamic', 'maxlife' and 'attr' options.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg++;
		}
		if (!POWEROF2(curproxy->ck_opts & (PR_CK_RW|PR_CK_IND))) {
			ha_alert("parsing [%s:%d] : cookie 'rewrite' and 'indirect' modes are incompatible.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if (!POWEROF2(curproxy->ck_opts & (PR_CK_RW|PR_CK_INS|PR_CK_PFX))) {
			ha_alert("parsing [%s:%d] : cookie 'rewrite', 'insert' and 'prefix' modes are incompatible.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		if ((curproxy->ck_opts & (PR_CK_PSV | PR_CK_INS | PR_CK_IND)) == PR_CK_PSV) {
			ha_alert("parsing [%s:%d] : cookie 'preserve' requires at least 'insert' or 'indirect'.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}/* end else if (!strcmp(args[0], "cookie"))  */
	else if (strcmp(args[0], "email-alert") == 0) {
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }

		if (strcmp(args[1], "from") == 0) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.from);
			curproxy->email_alert.from = strdup(args[2]);
			if (!curproxy->email_alert.from)
				goto alloc_error;
		}
		else if (strcmp(args[1], "mailers") == 0) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.mailers.name);
			curproxy->email_alert.mailers.name = strdup(args[2]);
			if (!curproxy->email_alert.mailers.name)
				goto alloc_error;
		}
		else if (strcmp(args[1], "myhostname") == 0) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.myhostname);
			curproxy->email_alert.myhostname = strdup(args[2]);
			if (!curproxy->email_alert.myhostname)
				goto alloc_error;
		}
		else if (strcmp(args[1], "level") == 0) {
			curproxy->email_alert.level = get_log_level(args[2]);
			if (curproxy->email_alert.level < 0) {
				ha_alert("parsing [%s:%d] : unknown log level '%s' after '%s'\n",
					 file, linenum, args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else if (strcmp(args[1], "to") == 0) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.to);
			curproxy->email_alert.to = strdup(args[2]);
			if (!curproxy->email_alert.to)
				goto alloc_error;
		}
		else {
			ha_alert("parsing [%s:%d] : email-alert: unknown argument '%s'.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		/* Indicate that the email_alert is at least partially configured */
		curproxy->email_alert.set = 1;
	}/* end else if (!strcmp(args[0], "email-alert"))  */
	else if (strcmp(args[0], "persist") == 0) {  /* persist */
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : missing persist method.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }

		if (!strncmp(args[1], "rdp-cookie", 10)) {
			curproxy->options2 |= PR_O2_RDPC_PRST;

	                if (*(args[1] + 10) == '(') { /* cookie name */
				const char *beg, *end;

				beg = args[1] + 11;
				end = strchr(beg, ')');

				if (alertif_too_many_args(1, file, linenum, args, &err_code))
					goto out;

				if (!end || end == beg) {
					ha_alert("parsing [%s:%d] : persist rdp-cookie(name)' requires an rdp cookie name.\n",
						 file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				free(curproxy->rdp_cookie_name);
				curproxy->rdp_cookie_name = my_strndup(beg, end - beg);
				if (!curproxy->rdp_cookie_name)
					goto alloc_error;
				curproxy->rdp_cookie_len = end-beg;
			}
			else if (*(args[1] + 10) == '\0') { /* default cookie name 'msts' */
				free(curproxy->rdp_cookie_name);
				curproxy->rdp_cookie_name = strdup("msts");
				if (!curproxy->rdp_cookie_name)
					goto alloc_error;
				curproxy->rdp_cookie_len = strlen(curproxy->rdp_cookie_name);
			}
			else { /* syntax */
				ha_alert("parsing [%s:%d] : persist rdp-cookie(name)' requires an rdp cookie name.\n",
					 file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			ha_alert("parsing [%s:%d] : unknown persist method.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "appsession") == 0) {  /* cookie name */
		ha_alert("parsing [%s:%d] : '%s' is not supported anymore since HAProxy 1.6.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "load-server-state-from-file") == 0) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;
		if (strcmp(args[1], "global") == 0) {  /* use the file pointed to by global server-state-file directive */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_GLOBAL;
		}
		else if (strcmp(args[1], "local") == 0) { /* use the server-state-file-name variable to locate the server-state file */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_LOCAL;
		}
		else if (strcmp(args[1], "none") == 0) {  /* don't use server-state-file directive for this backend */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_NONE;
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' expects 'global', 'local' or 'none'. Got '%s'\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "server-state-file-name") == 0) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		ha_free(&curproxy->server_state_file_name);

		if (*(args[1]) == 0 || strcmp(args[1], "use-backend-name") == 0)
			curproxy->server_state_file_name = strdup(curproxy->id);
		else
			curproxy->server_state_file_name = strdup(args[1]);

		if (!curproxy->server_state_file_name)
			goto alloc_error;
	}
	else if (strcmp(args[0], "max-session-srv-conns") == 0) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;
		if (*(args[1]) == 0) {
			ha_alert("parsine [%s:%d] : '%s' expects a number. Got no argument\n",
			    file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->max_out_conns = atoi(args[1]);
	}
	else if (strcmp(args[0], "capture") == 0) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "cookie") == 0) {  /* name of a cookie to capture */
			if (curproxy->cap & PR_CAP_DEF) {
				ha_alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (alertif_too_many_args_idx(4, 1, file, linenum, args, &err_code))
				goto out;

			if (*(args[4]) == 0) {
				ha_alert("parsing [%s:%d] : '%s' expects 'cookie' <cookie_name> 'len' <len>.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->capture_name);
			curproxy->capture_name = strdup(args[2]);
			if (!curproxy->capture_name)
				goto alloc_error;
			curproxy->capture_namelen = strlen(curproxy->capture_name);
			curproxy->capture_len = atol(args[4]);
			curproxy->to_log |= LW_COOKIE;
		}
		else if (strcmp(args[1], "request") == 0 && strcmp(args[2], "header") == 0) {
			struct cap_hdr *hdr;

			if (curproxy->cap & PR_CAP_DEF) {
				ha_alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (alertif_too_many_args_idx(4, 1, file, linenum, args, &err_code))
				goto out;

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				ha_alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			hdr = calloc(1, sizeof(*hdr));
			if (!hdr)
				goto req_caphdr_alloc_error;
			hdr->next = curproxy->req_cap;
			hdr->name = strdup(args[3]);
			if (!hdr->name)
				goto req_caphdr_alloc_error;
			hdr->namelen = strlen(args[3]);
			hdr->len = atol(args[5]);
			hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
			if (!hdr->pool) {
			  req_caphdr_alloc_error:
				if (hdr)
					ha_free(&hdr->name);
				ha_free(&hdr);
				goto alloc_error;
			}
			hdr->index = curproxy->nb_req_cap++;
			curproxy->req_cap = hdr;
			curproxy->to_log |= LW_REQHDR;
		}
		else if (strcmp(args[1], "response") == 0 && strcmp(args[2], "header") == 0) {
			struct cap_hdr *hdr;

			if (curproxy->cap & PR_CAP_DEF) {
				ha_alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (alertif_too_many_args_idx(4, 1, file, linenum, args, &err_code))
				goto out;

			if (*(args[3]) == 0 || strcmp(args[4], "len") != 0 || *(args[5]) == 0) {
				ha_alert("parsing [%s:%d] : '%s %s' expects 'header' <header_name> 'len' <len>.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			hdr = calloc(1, sizeof(*hdr));
			if (!hdr)
				goto res_caphdr_alloc_error;
			hdr->next = curproxy->rsp_cap;
			hdr->name = strdup(args[3]);
			if (!hdr->name)
				goto res_caphdr_alloc_error;
			hdr->namelen = strlen(args[3]);
			hdr->len = atol(args[5]);
			hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
			if (!hdr->pool) {
			  res_caphdr_alloc_error:
				if (hdr)
					ha_free(&hdr->name);
				ha_free(&hdr);
				goto alloc_error;
			}
			hdr->index = curproxy->nb_rsp_cap++;
			curproxy->rsp_cap = hdr;
			curproxy->to_log |= LW_RSPHDR;
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' expects 'cookie' or 'request header' or 'response header'.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "retries") == 0) {  /* connection retries */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument (dispatch counts for one).\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->conn_retries = atol(args[1]);
	}
	else if (strcmp(args[0], "http-request") == 0) {	/* request access control: allow/deny/auth */
		struct act_rule *rule;
		int where = 0;

		if ((curproxy->cap & PR_CAP_DEF) && strlen(curproxy->id) == 0) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in anonymous 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!LIST_ISEMPTY(&curproxy->http_req_rules) &&
		    !LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->cond &&
		    (LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->flags & ACT_FLAG_FINAL)) {
			ha_warning("parsing [%s:%d]: previous '%s' action is final and has no condition attached, further entries are NOOP.\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		rule = parse_http_req_cond((const char **)args + 1, file, linenum, curproxy);

		if (!rule) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err_code |= warnif_misplaced_http_req(curproxy, file, linenum, args[0]);

		if (curproxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (curproxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;
		err_code |= warnif_cond_conflicts(rule->cond, where, file, linenum);

		LIST_APPEND(&curproxy->http_req_rules, &rule->list);
	}
	else if (strcmp(args[0], "http-response") == 0) {	/* response access control */
		struct act_rule *rule;
		int where = 0;

		if ((curproxy->cap & PR_CAP_DEF) && strlen(curproxy->id) == 0) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in anonymous 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!LIST_ISEMPTY(&curproxy->http_res_rules) &&
		    !LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->cond &&
		    (LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->flags & ACT_FLAG_FINAL)) {
			ha_warning("parsing [%s:%d]: previous '%s' action is final and has no condition attached, further entries are NOOP.\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		rule = parse_http_res_cond((const char **)args + 1, file, linenum, curproxy);

		if (!rule) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (curproxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRS_HDR;
		if (curproxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRS_HDR;
		err_code |= warnif_cond_conflicts(rule->cond, where, file, linenum);

		LIST_APPEND(&curproxy->http_res_rules, &rule->list);
	}
	else if (strcmp(args[0], "http-after-response") == 0) {
		struct act_rule *rule;
		int where = 0;
		if ((curproxy->cap & PR_CAP_DEF) && strlen(curproxy->id) == 0) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in anonymous 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!LIST_ISEMPTY(&curproxy->http_after_res_rules) &&
		    !LIST_PREV(&curproxy->http_after_res_rules, struct act_rule *, list)->cond &&
		    (LIST_PREV(&curproxy->http_after_res_rules, struct act_rule *, list)->flags & ACT_FLAG_FINAL)) {
			ha_warning("parsing [%s:%d]: previous '%s' action is final and has no condition attached, further entries are NOOP.\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		rule = parse_http_after_res_cond((const char **)args + 1, file, linenum, curproxy);

		if (!rule) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (curproxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRS_HDR;
		if (curproxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRS_HDR;
		err_code |= warnif_cond_conflicts(rule->cond, where, file, linenum);

		LIST_APPEND(&curproxy->http_after_res_rules, &rule->list);
	}
	else if (strcmp(args[0], "http-send-name-header") == 0) { /* send server name in request header */
		/* set the header name and length into the proxy structure */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' requires a header string.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* set the desired header name, in lower case */
		istfree(&curproxy->server_id_hdr_name);
		curproxy->server_id_hdr_name = istdup(ist(args[1]));
		if (!isttest(curproxy->server_id_hdr_name))
			goto alloc_error;
		ist2bin_lc(istptr(curproxy->server_id_hdr_name), curproxy->server_id_hdr_name);
	}
	else if (strcmp(args[0], "block") == 0) {
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. Use 'http-request deny' which uses the exact same syntax.\n", file, linenum, args[0]);

		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "redirect") == 0) {
		struct redirect_rule *rule;
		int where = 0;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((rule = http_parse_redirect_rule(file, linenum, curproxy, (const char **)args + 1, &errmsg, 0, 0)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected in %s '%s' while parsing redirect rule : %s.\n",
				 file, linenum, proxy_type_str(curproxy), curproxy->id, errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		LIST_APPEND(&curproxy->redirect_rules, &rule->list);
		err_code |= warnif_misplaced_redirect(curproxy, file, linenum, args[0]);

		if (curproxy->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (curproxy->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;
		err_code |= warnif_cond_conflicts(rule->cond, where, file, linenum);
	}
	else if (strcmp(args[0], "use_backend") == 0) {
		struct switching_rule *rule;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a backend name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0) {
			if ((cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
				ha_alert("parsing [%s:%d] : error detected while parsing switching rule : %s.\n",
					 file, linenum, errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			err_code |= warnif_cond_conflicts(cond, SMP_VAL_FE_SET_BCK, file, linenum);
		}
		else if (*args[2]) {
			ha_alert("parsing [%s:%d] : unexpected keyword '%s' after switching rule, only 'if' and 'unless' are allowed.\n",
				 file, linenum, args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		rule = calloc(1, sizeof(*rule));
		if (!rule)
			goto use_backend_alloc_error;
		rule->cond = cond;
		rule->be.name = strdup(args[1]);
		if (!rule->be.name)
			goto use_backend_alloc_error;
		rule->line = linenum;
		rule->file = strdup(file);
		if (!rule->file) {
		  use_backend_alloc_error:
			free_acl_cond(cond);
			if (rule)
				ha_free(&(rule->be.name));
			ha_free(&rule);
			goto alloc_error;
		}
		LIST_INIT(&rule->list);
		LIST_APPEND(&curproxy->switching_rules, &rule->list);
	}
	else if (strcmp(args[0], "use-server") == 0) {
		struct server_rule *rule;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a server name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
			ha_alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing switching rule : %s.\n",
				 file, linenum, errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_SET_SRV, file, linenum);

		rule = calloc(1, sizeof(*rule));
		if (!rule)
			goto use_server_alloc_error;
		rule->cond = cond;
		rule->srv.name = strdup(args[1]);
		if (!rule->srv.name)
			goto use_server_alloc_error;
		rule->line = linenum;
		rule->file = strdup(file);
		if (!rule->file) {
		  use_server_alloc_error:
			free_acl_cond(cond);
			if (rule)
				ha_free(&(rule->srv.name));
			ha_free(&rule);
			goto alloc_error;
		}
		LIST_INIT(&rule->list);
		LIST_APPEND(&curproxy->server_rules, &rule->list);
		curproxy->be_req_ana |= AN_REQ_SRV_RULES;
	}
	else if ((strcmp(args[0], "force-persist") == 0) ||
		 (strcmp(args[0], "ignore-persist") == 0)) {
		struct persist_rule *rule;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "if") != 0 && strcmp(args[1], "unless") != 0) {
			ha_alert("parsing [%s:%d] : '%s' requires either 'if' or 'unless' followed by a condition.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + 1, &errmsg)) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing a '%s' rule : %s.\n",
				 file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* note: BE_REQ_CNT is the first one after FE_SET_BCK, which is
		 * where force-persist is applied.
		 */
		err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_REQ_CNT, file, linenum);

		rule = calloc(1, sizeof(*rule));
		if (!rule) {
			free_acl_cond(cond);
			goto alloc_error;
		}
		rule->cond = cond;
		if (strcmp(args[0], "force-persist") == 0) {
			rule->type = PERSIST_TYPE_FORCE;
		} else {
			rule->type = PERSIST_TYPE_IGNORE;
		}
		LIST_INIT(&rule->list);
		LIST_APPEND(&curproxy->persist_rules, &rule->list);
	}
	else if (strcmp(args[0], "stick-table") == 0) {
		struct stktable *other;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : 'stick-table' is not supported in 'defaults' section.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		other = stktable_find_by_name(curproxy->id);
		if (other) {
			ha_alert("parsing [%s:%d] : stick-table name '%s' conflicts with table declared in %s '%s' at %s:%d.\n",
				 file, linenum, curproxy->id,
				 other->proxy ? proxy_cap_str(other->proxy->cap) : "peers",
				 other->proxy ? other->id : other->peers.p->id,
				 other->conf.file, other->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->table = calloc(1, sizeof *curproxy->table);
		if (!curproxy->table) {
			ha_alert("parsing [%s:%d]: '%s %s' : memory allocation failed\n",
			         file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err_code |= parse_stick_table(file, linenum, args, curproxy->table,
		                              curproxy->id, curproxy->id, NULL);
		if (err_code & ERR_FATAL) {
			ha_free(&curproxy->table);
			goto out;
		}

		/* Store the proxy in the stick-table. */
		curproxy->table->proxy = curproxy;

		stktable_store_name(curproxy->table);
		curproxy->table->next = stktables_list;
		stktables_list = curproxy->table;

		/* Add this proxy to the list of proxies which refer to its stick-table. */
		if (curproxy->table->proxies_list != curproxy) {
			curproxy->next_stkt_ref = curproxy->table->proxies_list;
			curproxy->table->proxies_list = curproxy;
		}
	}
	else if (strcmp(args[0], "stick") == 0) {
		struct sticking_rule *rule;
		struct sample_expr *expr;
		int myidx = 0;
		const char *name = NULL;
		int flags;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL)) {
			err_code |= ERR_WARN;
			goto out;
		}

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
			ha_alert("parsing [%s:%d] : '%s' expects 'on', 'match', or 'store'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (*(args[myidx]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a fetch method.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->conf.args.ctx = ARGC_STK;
		expr = sample_parse_expr(args, &myidx, file, linenum, &errmsg, &curproxy->conf.args, NULL);
		if (!expr) {
			ha_alert("parsing [%s:%d] : '%s': %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (flags & STK_ON_RSP) {
			if (!(expr->fetch->val & SMP_VAL_BE_STO_RUL)) {
				ha_alert("parsing [%s:%d] : '%s': fetch method '%s' extracts information from '%s', none of which is available for 'store-response'.\n",
					 file, linenum, args[0], expr->fetch->kw, sample_src_names(expr->fetch->use));
		                err_code |= ERR_ALERT | ERR_FATAL;
				free(expr);
			        goto out;
			}
		} else {
			if (!(expr->fetch->val & SMP_VAL_BE_SET_SRV)) {
				ha_alert("parsing [%s:%d] : '%s': fetch method '%s' extracts information from '%s', none of which is available during request.\n",
					 file, linenum, args[0], expr->fetch->kw, sample_src_names(expr->fetch->use));
				err_code |= ERR_ALERT | ERR_FATAL;
				free(expr);
				goto out;
			}
		}

		/* check if we need to allocate an http_txn struct for HTTP parsing */
		curproxy->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);

		if (strcmp(args[myidx], "table") == 0) {
			myidx++;
			name = args[myidx++];
		}

		if (strcmp(args[myidx], "if") == 0 || strcmp(args[myidx], "unless") == 0) {
			if ((cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + myidx, &errmsg)) == NULL) {
				ha_alert("parsing [%s:%d] : '%s': error detected while parsing sticking condition : %s.\n",
					 file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(expr);
				goto out;
			}
		}
		else if (*(args[myidx])) {
			ha_alert("parsing [%s:%d] : '%s': unknown keyword '%s'.\n",
				 file, linenum, args[0], args[myidx]);
			err_code |= ERR_ALERT | ERR_FATAL;
			free(expr);
			goto out;
		}
		if (flags & STK_ON_RSP)
			err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_STO_RUL, file, linenum);
		else
			err_code |= warnif_cond_conflicts(cond, SMP_VAL_BE_SET_SRV, file, linenum);

		rule = calloc(1, sizeof(*rule));
		if (!rule) {
			free_acl_cond(cond);
			goto alloc_error;
		}
		rule->cond = cond;
		rule->expr = expr;
		rule->flags = flags;
		rule->table.name = name ? strdup(name) : NULL;
		LIST_INIT(&rule->list);
		if (flags & STK_ON_RSP)
			LIST_APPEND(&curproxy->storersp_rules, &rule->list);
		else
			LIST_APPEND(&curproxy->sticking_rules, &rule->list);
	}
	else if (strcmp(args[0], "stats") == 0) {
		if (!(curproxy->cap & PR_CAP_DEF) && curproxy->uri_auth == curr_defproxy->uri_auth)
			curproxy->uri_auth = NULL; /* we must detach from the default config */

		if (!*args[1]) {
			goto stats_error_parsing;
		} else if (strcmp(args[1], "admin") == 0) {
			struct stats_admin_rule *rule;
			int where = 0;

			if (curproxy->cap & PR_CAP_DEF) {
				ha_alert("parsing [%s:%d]: '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!stats_check_init_uri_auth(&curproxy->uri_auth))
				goto alloc_error;

			if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
				ha_alert("parsing [%s:%d] : '%s %s' requires either 'if' or 'unless' followed by a condition.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if ((cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
				ha_alert("parsing [%s:%d] : error detected while parsing a '%s %s' rule : %s.\n",
					 file, linenum, args[0], args[1], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (curproxy->cap & PR_CAP_FE)
				where |= SMP_VAL_FE_HRQ_HDR;
			if (curproxy->cap & PR_CAP_BE)
				where |= SMP_VAL_BE_HRQ_HDR;
			err_code |= warnif_cond_conflicts(cond, where, file, linenum);

			rule = calloc(1, sizeof(*rule));
			if (!rule) {
				free_acl_cond(cond);
				goto alloc_error;
			}
			rule->cond = cond;
			LIST_INIT(&rule->list);
			LIST_APPEND(&curproxy->uri_auth->admin_rules, &rule->list);
		} else if (strcmp(args[1], "uri") == 0) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'uri' needs an URI prefix.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_uri(&curproxy->uri_auth, args[2]))
				goto alloc_error;
		} else if (strcmp(args[1], "realm") == 0) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'realm' needs an realm name.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_realm(&curproxy->uri_auth, args[2]))
				goto alloc_error;
		} else if (strcmp(args[1], "refresh") == 0) {
			unsigned interval;

			err = parse_time_err(args[2], &interval, TIME_UNIT_S);
			if (err == PARSE_TIME_OVER) {
				ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to stats refresh interval, maximum value is 2147483647 s (~68 years).\n",
					 file, linenum, args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (err == PARSE_TIME_UNDER) {
				ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to stats refresh interval, minimum non-null value is 1 s.\n",
					 file, linenum, args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (err) {
				ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to stats refresh interval.\n",
					 file, linenum, *err);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_refresh(&curproxy->uri_auth, interval))
				goto alloc_error;
		} else if (strcmp(args[1], "http-request") == 0) {    /* request access control: allow/deny/auth */
			struct act_rule *rule;
			int where = 0;

			if (curproxy->cap & PR_CAP_DEF) {
				ha_alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!stats_check_init_uri_auth(&curproxy->uri_auth))
				goto alloc_error;

			if (!LIST_ISEMPTY(&curproxy->uri_auth->http_req_rules) &&
			    !LIST_PREV(&curproxy->uri_auth->http_req_rules, struct act_rule *, list)->cond) {
				ha_warning("parsing [%s:%d]: previous '%s' action has no condition attached, further entries are NOOP.\n",
					   file, linenum, args[0]);
				err_code |= ERR_WARN;
			}

			rule = parse_http_req_cond((const char **)args + 2, file, linenum, curproxy);

			if (!rule) {
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if (curproxy->cap & PR_CAP_FE)
				where |= SMP_VAL_FE_HRQ_HDR;
			if (curproxy->cap & PR_CAP_BE)
				where |= SMP_VAL_BE_HRQ_HDR;
			err_code |= warnif_cond_conflicts(rule->cond, where, file, linenum);
			LIST_APPEND(&curproxy->uri_auth->http_req_rules, &rule->list);

		} else if (strcmp(args[1], "auth") == 0) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'auth' needs a user:password account.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_add_auth(&curproxy->uri_auth, args[2]))
				goto alloc_error;
		} else if (strcmp(args[1], "scope") == 0) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'scope' needs a proxy name.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_add_scope(&curproxy->uri_auth, args[2]))
				goto alloc_error;
		} else if (strcmp(args[1], "enable") == 0) {
			if (!stats_check_init_uri_auth(&curproxy->uri_auth))
				goto alloc_error;
		} else if (strcmp(args[1], "hide-version") == 0) {
			if (!stats_set_flag(&curproxy->uri_auth, STAT_HIDEVER))
				goto alloc_error;
		} else if (strcmp(args[1], "show-legends") == 0) {
			if (!stats_set_flag(&curproxy->uri_auth, STAT_SHLGNDS))
				goto alloc_error;
		} else if (strcmp(args[1], "show-modules") == 0) {
			if (!stats_set_flag(&curproxy->uri_auth, STAT_SHMODULES))
				goto alloc_error;
		} else if (strcmp(args[1], "show-node") == 0) {

			if (*args[2]) {
				int i;
				char c;

				for (i=0; args[2][i]; i++) {
					c = args[2][i];
					if (!isupper((unsigned char)c) && !islower((unsigned char)c) &&
					    !isdigit((unsigned char)c) && c != '_' && c != '-' && c != '.')
						break;
				}

				if (!i || args[2][i]) {
					ha_alert("parsing [%s:%d]: '%s %s' invalid node name - should be a string"
						 "with digits(0-9), letters(A-Z, a-z), hyphen(-) or underscode(_).\n",
						 file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}

			if (!stats_set_node(&curproxy->uri_auth, args[2]))
				goto alloc_error;
		} else if (strcmp(args[1], "show-desc") == 0) {
			char *desc = NULL;

			if (*args[2]) {
				int i, len=0;
				char *d;

				for (i = 2; *args[i]; i++)
					len += strlen(args[i]) + 1;

				desc = d = calloc(1, len);

				d += snprintf(d, desc + len - d, "%s", args[2]);
				for (i = 3; *args[i]; i++)
					d += snprintf(d, desc + len - d, " %s", args[i]);
			}

			if (!*args[2] && !global.desc)
				ha_warning("parsing [%s:%d]: '%s' requires a parameter or 'desc' to be set in the global section.\n",
					   file, linenum, args[1]);
			else {
				if (!stats_set_desc(&curproxy->uri_auth, desc)) {
					free(desc);
					goto alloc_error;
				}
				free(desc);
			}
		} else {
stats_error_parsing:
			ha_alert("parsing [%s:%d]: %s '%s', expects 'admin', 'uri', 'realm', 'auth', 'scope', 'enable', 'hide-version', 'show-node', 'show-desc' or 'show-legends'.\n",
				 file, linenum, *args[1]?"unknown stats parameter":"missing keyword in", args[*args[1]?1:0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "option") == 0) {
		int optnum;

		if (*(args[1]) == '\0') {
			ha_alert("parsing [%s:%d]: '%s' expects an option name.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (optnum = 0; cfg_opts[optnum].name; optnum++) {
			if (strcmp(args[1], cfg_opts[optnum].name) == 0) {
				if (cfg_opts[optnum].cap == PR_CAP_NONE) {
					ha_alert("parsing [%s:%d]: option '%s' is not supported due to build options.\n",
						 file, linenum, cfg_opts[optnum].name);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
					goto out;

				if (warnifnotcap(curproxy, cfg_opts[optnum].cap, file, linenum, args[1], NULL)) {
					err_code |= ERR_WARN;
					goto out;
				}

				curproxy->no_options &= ~cfg_opts[optnum].val;
				curproxy->options    &= ~cfg_opts[optnum].val;

				switch (kwm) {
				case KWM_STD:
					curproxy->options |= cfg_opts[optnum].val;
					break;
				case KWM_NO:
					curproxy->no_options |= cfg_opts[optnum].val;
					break;
				case KWM_DEF: /* already cleared */
					break;
				}

				goto out;
			}
		}

		for (optnum = 0; cfg_opts2[optnum].name; optnum++) {
			if (strcmp(args[1], cfg_opts2[optnum].name) == 0) {
				if (cfg_opts2[optnum].cap == PR_CAP_NONE) {
					ha_alert("parsing [%s:%d]: option '%s' is not supported due to build options.\n",
						 file, linenum, cfg_opts2[optnum].name);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
					goto out;
				if (warnifnotcap(curproxy, cfg_opts2[optnum].cap, file, linenum, args[1], NULL)) {
					err_code |= ERR_WARN;
					goto out;
				}

				curproxy->no_options2 &= ~cfg_opts2[optnum].val;
				curproxy->options2    &= ~cfg_opts2[optnum].val;

				switch (kwm) {
				case KWM_STD:
					curproxy->options2 |= cfg_opts2[optnum].val;
					break;
				case KWM_NO:
					curproxy->no_options2 |= cfg_opts2[optnum].val;
					break;
				case KWM_DEF: /* already cleared */
					break;
				}
				goto out;
			}
		}

		/* HTTP options override each other. They can be cancelled using
		 * "no option xxx" which only switches to default mode if the mode
		 * was this one (useful for cancelling options set in defaults
		 * sections).
		 */
		if (strcmp(args[1], "forceclose") == 0) {
			ha_alert("parsing [%s:%d]: option '%s' is not supported any more since HAProxy 2.0, please just remove it, or use 'option httpclose' if absolutely needed.\n",
				   file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (strcmp(args[1], "httpclose") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_CLO;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}
		else if (strcmp(args[1], "http-server-close") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_SCL;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}
		else if (strcmp(args[1], "http-keep-alive") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD) {
				curproxy->options &= ~PR_O_HTTP_MODE;
				curproxy->options |= PR_O_HTTP_KAL;
				goto out;
			}
			else if (kwm == KWM_NO) {
				if ((curproxy->options & PR_O_HTTP_MODE) == PR_O_HTTP_KAL)
					curproxy->options &= ~PR_O_HTTP_MODE;
				goto out;
			}
		}
		else if (strcmp(args[1], "http-tunnel") == 0) {
			ha_alert("parsing [%s:%d]: option '%s' is not supported any more since HAProxy 2.1, please just remove it, it shouldn't be needed.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (strcmp(args[1], "forwarded") == 0) {
			if (kwm == KWM_STD) {
				err_code |= proxy_http_parse_7239(args, 0, curproxy, curr_defproxy, file, linenum);
				goto out;
			}
			else if (kwm == KWM_NO) {
				if (curproxy->http_ext)
					http_ext_7239_clean(curproxy);
				goto out;
			}
		}

		/* Redispatch can take an integer argument that control when the
		 * resispatch occurs. All values are relative to the retries option.
		 * This can be cancelled using "no option xxx".
		 */
		if (strcmp(args[1], "redispatch") == 0) {
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL)) {
				err_code |= ERR_WARN;
				goto out;
			}

			curproxy->no_options &= ~PR_O_REDISP;
			curproxy->options &= ~PR_O_REDISP;

			switch (kwm) {
			case KWM_STD:
				curproxy->options |= PR_O_REDISP;
				curproxy->redispatch_after = -1;
				if(*args[2]) {
					curproxy->redispatch_after = atol(args[2]);
				}
				break;
			case KWM_NO:
				curproxy->no_options |= PR_O_REDISP;
				curproxy->redispatch_after = 0;
				break;
			case KWM_DEF: /* already cleared */
				break;
			}
			goto out;
		}

		if (strcmp(args[1], "http_proxy") == 0) {
			ha_alert("parsing [%s:%d]: option '%s' is not supported any more since HAProxy 2.5. This option stopped working in HAProxy 1.9 and usually had nasty side effects. It can be more reliably implemented with combinations of 'http-request set-dst' and 'http-request set-uri', and even 'http-request do-resolve' if DNS resolution is desired.\n",
				   file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (kwm != KWM_STD) {
			ha_alert("parsing [%s:%d]: negation/default is not supported for option '%s'.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[1], "httplog") == 0) {
			char *logformat;
			/* generate a complete HTTP log */
			logformat = default_http_log_format;
			if (*(args[2]) != '\0') {
				if (strcmp(args[2], "clf") == 0) {
					curproxy->options2 |= PR_O2_CLFLOG;
					logformat = clf_http_log_format;
				} else {
					ha_alert("parsing [%s:%d] : keyword '%s' only supports option 'clf'.\n", file, linenum, args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (alertif_too_many_args_idx(1, 1, file, linenum, args, &err_code))
					goto out;
			}
			if (curproxy->conf.logformat_string && curproxy->cap & PR_CAP_DEF) {
				char *oldlogformat = "log-format";
				char *clflogformat = "";

				if (curproxy->conf.logformat_string == default_http_log_format)
					oldlogformat = "option httplog";
				else if (curproxy->conf.logformat_string == default_tcp_log_format)
					oldlogformat = "option tcplog";
				else if (curproxy->conf.logformat_string == clf_http_log_format)
					oldlogformat = "option httplog clf";
				else if (curproxy->conf.logformat_string == default_https_log_format)
					oldlogformat = "option httpslog";
				if (logformat == clf_http_log_format)
					clflogformat = " clf";
				ha_warning("parsing [%s:%d]: 'option httplog%s' overrides previous '%s' in 'defaults' section.\n",
					   file, linenum, clflogformat, oldlogformat);
			}
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format &&
			    curproxy->conf.logformat_string != default_https_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = logformat;

			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;

			if (!(curproxy->cap & PR_CAP_DEF) && !(curproxy->cap & PR_CAP_FE)) {
				ha_warning("parsing [%s:%d] : backend '%s' : 'option httplog' directive is ignored in backends.\n",
					file, linenum, curproxy->id);
				err_code |= ERR_WARN;
			}
		}
		else if (strcmp(args[1], "tcplog") == 0) {
			if (curproxy->conf.logformat_string && curproxy->cap & PR_CAP_DEF) {
				char *oldlogformat = "log-format";

				if (curproxy->conf.logformat_string == default_http_log_format)
					oldlogformat = "option httplog";
				else if (curproxy->conf.logformat_string == default_tcp_log_format)
					oldlogformat = "option tcplog";
				else if (curproxy->conf.logformat_string == clf_http_log_format)
					oldlogformat = "option httplog clf";
				else if (curproxy->conf.logformat_string == default_https_log_format)
					oldlogformat = "option httpslog";
				ha_warning("parsing [%s:%d]: 'option tcplog' overrides previous '%s' in 'defaults' section.\n",
					   file, linenum, oldlogformat);
			}
			/* generate a detailed TCP log */
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format &&
			    curproxy->conf.logformat_string != default_https_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = default_tcp_log_format;

			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;

			if (!(curproxy->cap & PR_CAP_DEF) && !(curproxy->cap & PR_CAP_FE)) {
				ha_warning("parsing [%s:%d] : backend '%s' : 'option tcplog' directive is ignored in backends.\n",
					file, linenum, curproxy->id);
				err_code |= ERR_WARN;
			}
		}
		else if (strcmp(args[1], "httpslog") == 0) {
			char *logformat;
			/* generate a complete HTTP log */
			logformat = default_https_log_format;
			if (curproxy->conf.logformat_string && curproxy->cap & PR_CAP_DEF) {
				char *oldlogformat = "log-format";

				if (curproxy->conf.logformat_string == default_http_log_format)
					oldlogformat = "option httplog";
				else if (curproxy->conf.logformat_string == default_tcp_log_format)
					oldlogformat = "option tcplog";
				else if (curproxy->conf.logformat_string == clf_http_log_format)
					oldlogformat = "option httplog clf";
				else if (curproxy->conf.logformat_string == default_https_log_format)
					oldlogformat = "option httpslog";
				ha_warning("parsing [%s:%d]: 'option httplog' overrides previous '%s' in 'defaults' section.\n",
					   file, linenum, oldlogformat);
			}
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format &&
			    curproxy->conf.logformat_string != default_https_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = logformat;

			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;

			if (!(curproxy->cap & PR_CAP_DEF) && !(curproxy->cap & PR_CAP_FE)) {
				ha_warning("parsing [%s:%d] : backend '%s' : 'option httpslog' directive is ignored in backends.\n",
					file, linenum, curproxy->id);
				err_code |= ERR_WARN;
			}
		}
		else if (strcmp(args[1], "tcpka") == 0) {
			/* enable TCP keep-alives on client and server streams */
			if (warnifnotcap(curproxy, PR_CAP_BE | PR_CAP_FE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;

			if (curproxy->cap & PR_CAP_FE)
				curproxy->options |= PR_O_TCP_CLI_KA;
			if (curproxy->cap & PR_CAP_BE)
				curproxy->options |= PR_O_TCP_SRV_KA;
		}
		else if (strcmp(args[1], "httpchk") == 0) {
			err_code |= proxy_parse_httpchk_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "ssl-hello-chk") == 0) {
			err_code |= proxy_parse_ssl_hello_chk_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "smtpchk") == 0) {
			err_code |= proxy_parse_smtpchk_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "pgsql-check") == 0) {
			err_code |= proxy_parse_pgsql_check_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "redis-check") == 0) {
			err_code |= proxy_parse_redis_check_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "mysql-check") == 0) {
			err_code |= proxy_parse_mysql_check_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "ldap-check") == 0) {
			err_code |= proxy_parse_ldap_check_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "spop-check") == 0) {
			err_code |= proxy_parse_spop_check_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "tcp-check") == 0) {
			err_code |= proxy_parse_tcp_check_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "external-check") == 0) {
			err_code |= proxy_parse_external_check_opt(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "forwardfor") == 0) {
			err_code |= proxy_http_parse_xff(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "originalto") == 0) {
			err_code |= proxy_http_parse_xot(args, 0, curproxy, curr_defproxy, file, linenum);
			if (err_code & ERR_FATAL)
				goto out;
		}
		else if (strcmp(args[1], "http-restrict-req-hdr-names") == 0) {
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;

			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : missing parameter. option '%s' expects 'preserve', 'reject' or 'delete' option.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			curproxy->options2 &= ~PR_O2_RSTRICT_REQ_HDR_NAMES_MASK;
			if (strcmp(args[2], "preserve") == 0)
				curproxy->options2 |= PR_O2_RSTRICT_REQ_HDR_NAMES_NOOP;
			else if (strcmp(args[2], "reject") == 0)
				curproxy->options2 |= PR_O2_RSTRICT_REQ_HDR_NAMES_BLK;
			else if (strcmp(args[2], "delete") == 0)
				curproxy->options2 |= PR_O2_RSTRICT_REQ_HDR_NAMES_DEL;
			else {
				ha_alert("parsing [%s:%d] : invalid parameter '%s'. option '%s' expects 'preserve', 'reject' or 'delete' option.\n",
					 file, linenum, args[2], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			const char *best = proxy_find_best_option(args[1], common_options);

			if (best)
				ha_alert("parsing [%s:%d] : unknown option '%s'; did you mean '%s' maybe ?\n", file, linenum, args[1], best);
			else
				ha_alert("parsing [%s:%d] : unknown option '%s'.\n", file, linenum, args[1]);

			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		goto out;
	}
	else if (strcmp(args[0], "default_backend") == 0) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a backend name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->defbe.name);
		curproxy->defbe.name = strdup(args[1]);
		if (!curproxy->defbe.name)
			goto alloc_error;

		if (alertif_too_many_args_idx(1, 0, file, linenum, args, &err_code))
			goto out;
	}
	else if (strcmp(args[0], "redispatch") == 0 || strcmp(args[0], "redisp") == 0) {
		ha_alert("parsing [%s:%d] : keyword '%s' directive is not supported anymore since HAProxy 2.1. Use 'option redispatch'.\n", file, linenum, args[0]);

		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "http-reuse") == 0) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "never") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_NEVR;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "safe") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_SAFE;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "aggressive") == 0) {
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_AGGR;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "always") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options &= ~PR_O_REUSE_MASK;
			curproxy->options |= PR_O_REUSE_ALWS;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' only supports 'never', 'safe', 'aggressive', 'always'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "monitor") == 0) {
		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "fail") == 0) {
			/* add a condition to fail monitor requests */
			if (strcmp(args[2], "if") != 0 && strcmp(args[2], "unless") != 0) {
				ha_alert("parsing [%s:%d] : '%s %s' requires either 'if' or 'unless' followed by a condition.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			err_code |= warnif_misplaced_monitor(curproxy, file, linenum, "monitor fail");
			if ((cond = build_acl_cond(file, linenum, &curproxy->acl, curproxy, (const char **)args + 2, &errmsg)) == NULL) {
				ha_alert("parsing [%s:%d] : error detected while parsing a '%s %s' condition : %s.\n",
					 file, linenum, args[0], args[1], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			LIST_APPEND(&curproxy->mon_fail_cond, &cond->list);
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' only supports 'fail'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
#ifdef USE_TPROXY
	else if (strcmp(args[0], "transparent") == 0) {
		/* enable transparent proxy connections */
		curproxy->options |= PR_O_TRANSP;
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
	}
#endif
	else if (strcmp(args[0], "maxconn") == 0) {  /* maxconn */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], " Maybe you want 'fullconn' instead ?"))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->maxconn = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (strcmp(args[0], "backlog") == 0) {  /* backlog */
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->backlog = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (strcmp(args[0], "fullconn") == 0) {  /* fullconn */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], " Maybe you want 'maxconn' instead ?"))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->fullconn = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (strcmp(args[0], "grace") == 0) {  /* grace time (ms) */
		ha_alert("parsing [%s:%d]: the '%s' keyword is not supported any more since HAProxy version 2.5.\n",
			   file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "dispatch") == 0) {  /* dispatch address */
		struct sockaddr_storage *sk;
		int port1, port2;

		if (curproxy->cap & PR_CAP_DEF) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		sk = str2sa_range(args[1], NULL, &port1, &port2, NULL, NULL, NULL,
		                  &errmsg, NULL, NULL,
		                  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_STREAM | PA_O_XPRT | PA_O_CONNECT);
		if (!sk) {
			ha_alert("parsing [%s:%d] : '%s' : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		curproxy->dispatch_addr = *sk;
		curproxy->options |= PR_O_DISPATCH;
	}
	else if (strcmp(args[0], "balance") == 0) {  /* set balancing with optional algorithm */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (backend_parse_balance((const char **)args + 1, &errmsg, curproxy) < 0) {
			ha_alert("parsing [%s:%d] : %s %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "hash-type") == 0) { /* set hashing method */
		/**
		 * The syntax for hash-type config element is
		 * hash-type {map-based|consistent} [[<algo>] avalanche]
		 *
		 * The default hash function is sdbm for map-based and sdbm+avalanche for consistent.
		 */
		curproxy->lbprm.algo &= ~(BE_LB_HASH_TYPE | BE_LB_HASH_FUNC | BE_LB_HASH_MOD);

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "consistent") == 0) {	/* use consistent hashing */
			curproxy->lbprm.algo |= BE_LB_HASH_CONS;
		}
		else if (strcmp(args[1], "map-based") == 0) {	/* use map-based hashing */
			curproxy->lbprm.algo |= BE_LB_HASH_MAP;
		}
		else if (strcmp(args[1], "avalanche") == 0) {
			ha_alert("parsing [%s:%d] : experimental feature '%s %s' is not supported anymore, please use '%s map-based sdbm avalanche' instead.\n", file, linenum, args[0], args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' only supports 'consistent' and 'map-based'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* set the hash function to use */
		if (!*args[2]) {
			/* the default algo is sdbm */
			curproxy->lbprm.algo |= BE_LB_HFCN_SDBM;

			/* if consistent with no argument, then avalanche modifier is also applied */
			if ((curproxy->lbprm.algo & BE_LB_HASH_TYPE) == BE_LB_HASH_CONS)
				curproxy->lbprm.algo |= BE_LB_HMOD_AVAL;
		} else {
			/* set the hash function */
			if (strcmp(args[2], "sdbm") == 0) {
				curproxy->lbprm.algo |= BE_LB_HFCN_SDBM;
			}
			else if (strcmp(args[2], "djb2") == 0) {
				curproxy->lbprm.algo |= BE_LB_HFCN_DJB2;
			}
			else if (strcmp(args[2], "wt6") == 0) {
				curproxy->lbprm.algo |= BE_LB_HFCN_WT6;
			}
			else if (strcmp(args[2], "crc32") == 0) {
				curproxy->lbprm.algo |= BE_LB_HFCN_CRC32;
			}
			else if (strcmp(args[2], "none") == 0) {
				curproxy->lbprm.algo |= BE_LB_HFCN_NONE;
			}
			else {
				ha_alert("parsing [%s:%d] : '%s' only supports 'sdbm', 'djb2', 'crc32', or 'wt6' hash functions.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* set the hash modifier */
			if (strcmp(args[3], "avalanche") == 0) {
				curproxy->lbprm.algo |= BE_LB_HMOD_AVAL;
			}
			else if (*args[3]) {
				ha_alert("parsing [%s:%d] : '%s' only supports 'avalanche' as a modifier for hash functions.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
	}
	else if (strcmp(args[0], "hash-balance-factor") == 0) {
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->lbprm.hash_balance_factor = atol(args[1]);
		if (curproxy->lbprm.hash_balance_factor != 0 && curproxy->lbprm.hash_balance_factor <= 100) {
			ha_alert("parsing [%s:%d] : '%s' must be 0 or greater than 100.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "unique-id-format") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*(args[2])) {
			ha_alert("parsing [%s:%d] : %s expects only one argument, don't forget to escape spaces!\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->conf.uniqueid_format_string);
		curproxy->conf.uniqueid_format_string = strdup(args[1]);
		if (!curproxy->conf.uniqueid_format_string)
			goto alloc_error;

		free(curproxy->conf.uif_file);
		curproxy->conf.uif_file = strdup(curproxy->conf.args.file);
		curproxy->conf.uif_line = curproxy->conf.args.line;
	}

	else if (strcmp(args[0], "unique-id-header") == 0) {
		char *copy;
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		copy = strdup(args[1]);
		if (copy == NULL) {
			ha_alert("parsing [%s:%d] : failed to allocate memory for unique-id-header\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		istfree(&curproxy->header_unique_id);
		curproxy->header_unique_id = ist(copy);
	}

	else if (strcmp(args[0], "log-format") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*(args[2])) {
			ha_alert("parsing [%s:%d] : %s expects only one argument, don't forget to escape spaces!\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (curproxy->conf.logformat_string && curproxy->cap & PR_CAP_DEF) {
			char *oldlogformat = "log-format";

			if (curproxy->conf.logformat_string == default_http_log_format)
				oldlogformat = "option httplog";
			else if (curproxy->conf.logformat_string == default_tcp_log_format)
				oldlogformat = "option tcplog";
			else if (curproxy->conf.logformat_string == clf_http_log_format)
				oldlogformat = "option httplog clf";
			else if (curproxy->conf.logformat_string == default_https_log_format)
				oldlogformat = "option httpslog";
			ha_warning("parsing [%s:%d]: 'log-format' overrides previous '%s' in 'defaults' section.\n",
				   file, linenum, oldlogformat);
		}
		if (curproxy->conf.logformat_string != default_http_log_format &&
		    curproxy->conf.logformat_string != default_tcp_log_format &&
		    curproxy->conf.logformat_string != clf_http_log_format &&
		    curproxy->conf.logformat_string != default_https_log_format)
			free(curproxy->conf.logformat_string);
		curproxy->conf.logformat_string = strdup(args[1]);
		if (!curproxy->conf.logformat_string)
			goto alloc_error;

		free(curproxy->conf.lfs_file);
		curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
		curproxy->conf.lfs_line = curproxy->conf.args.line;

		/* get a chance to improve log-format error reporting by
		 * reporting the correct line-number when possible.
		 */
		if (!(curproxy->cap & PR_CAP_DEF) && !(curproxy->cap & PR_CAP_FE)) {
			ha_warning("parsing [%s:%d] : backend '%s' : 'log-format' directive is ignored in backends.\n",
				   file, linenum, curproxy->id);
			err_code |= ERR_WARN;
		}
	}
	else if (strcmp(args[0], "log-format-sd") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*(args[2])) {
			ha_alert("parsing [%s:%d] : %s expects only one argument, don't forget to escape spaces!\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (curproxy->conf.logformat_sd_string != default_rfc5424_sd_log_format)
			free(curproxy->conf.logformat_sd_string);
		curproxy->conf.logformat_sd_string = strdup(args[1]);
		if (!curproxy->conf.logformat_sd_string)
			goto alloc_error;

		free(curproxy->conf.lfsd_file);
		curproxy->conf.lfsd_file = strdup(curproxy->conf.args.file);
		curproxy->conf.lfsd_line = curproxy->conf.args.line;

		/* get a chance to improve log-format-sd error reporting by
		 * reporting the correct line-number when possible.
		 */
		if (!(curproxy->cap & PR_CAP_DEF) && !(curproxy->cap & PR_CAP_FE)) {
			ha_warning("parsing [%s:%d] : backend '%s' : 'log-format-sd' directive is ignored in backends.\n",
				   file, linenum, curproxy->id);
			err_code |= ERR_WARN;
		}
	}
	else if (strcmp(args[0], "error-log-format") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*(args[2])) {
			ha_alert("parsing [%s:%d] : %s expects only one argument, don't forget to escape spaces!\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (curproxy->conf.error_logformat_string && curproxy->cap & PR_CAP_DEF) {
			ha_warning("parsing [%s:%d]: 'error-log-format' overrides previous 'error-log-format' in 'defaults' section.\n",
				   file, linenum);
		}
		free(curproxy->conf.error_logformat_string);
		curproxy->conf.error_logformat_string = strdup(args[1]);
		if (!curproxy->conf.error_logformat_string)
			goto alloc_error;

		free(curproxy->conf.elfs_file);
		curproxy->conf.elfs_file = strdup(curproxy->conf.args.file);
		curproxy->conf.elfs_line = curproxy->conf.args.line;

		/* get a chance to improve log-format error reporting by
		 * reporting the correct line-number when possible.
		 */
		if (!(curproxy->cap & PR_CAP_DEF) && !(curproxy->cap & PR_CAP_FE)) {
			ha_warning("parsing [%s:%d] : backend '%s' : 'error-log-format' directive is ignored in backends.\n",
				   file, linenum, curproxy->id);
			err_code |= ERR_WARN;
		}
	}
	else if (strcmp(args[0], "log-tag") == 0) {  /* tag to report to syslog */
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a tag for use in syslog.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_destroy(&curproxy->log_tag);
		chunk_initlen(&curproxy->log_tag, strdup(args[1]), strlen(args[1]), strlen(args[1]));
		if (b_orig(&curproxy->log_tag) == NULL) {
			chunk_destroy(&curproxy->log_tag);
			ha_alert("parsing [%s:%d]: cannot allocate memory for '%s'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "log") == 0) { /* "no log" or "log ..." */
		if (!parse_logger(args, &curproxy->loggers, (kwm == KWM_NO), file, linenum, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "source") == 0) {  /* address to which we bind when connecting */
		int cur_arg;
		int port1, port2;
		struct sockaddr_storage *sk;

		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], and optionally '%s' <addr>, and '%s' <name>.\n",
				 file, linenum, "source", "usesrc", "interface");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* we must first clear any optional default setting */
		curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
		ha_free(&curproxy->conn_src.iface_name);
		curproxy->conn_src.iface_len = 0;

		sk = str2sa_range(args[1], NULL, &port1, &port2, NULL, NULL, NULL,
		                  &errmsg, NULL, NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_STREAM | PA_O_CONNECT);
		if (!sk) {
			ha_alert("parsing [%s:%d] : '%s %s' : %s\n",
				 file, linenum, args[0], args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->conn_src.source_addr = *sk;
		curproxy->conn_src.opts |= CO_SRC_BIND;

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (strcmp(args[cur_arg], "usesrc") == 0) {  /* address to use outside */
#if defined(CONFIG_HAP_TRANSPARENT)
				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', or 'clientip' as argument.\n",
						 file, linenum, "usesrc");
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (strcmp(args[cur_arg + 1], "client") == 0) {
					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_CLI;
				} else if (strcmp(args[cur_arg + 1], "clientip") == 0) {
					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_CIP;
				} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
					char *name, *end;

					name = args[cur_arg+1] + 7;
					while (isspace((unsigned char)*name))
						name++;

					end = name;
					while (*end && !isspace((unsigned char)*end) && *end != ',' && *end != ')')
						end++;

					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_DYN;
					free(curproxy->conn_src.bind_hdr_name);
					curproxy->conn_src.bind_hdr_name = calloc(1, end - name + 1);
					if (!curproxy->conn_src.bind_hdr_name)
						goto alloc_error;
					curproxy->conn_src.bind_hdr_len = end - name;
					memcpy(curproxy->conn_src.bind_hdr_name, name, end - name);
					curproxy->conn_src.bind_hdr_name[end-name] = '\0';
					curproxy->conn_src.bind_hdr_occ = -1;

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
						curproxy->conn_src.bind_hdr_occ = strl2ic(name, end-name);
					}

					if (curproxy->conn_src.bind_hdr_occ < -MAX_HDR_HISTORY) {
						ha_alert("parsing [%s:%d] : usesrc hdr_ip(name,num) does not support negative"
							 " occurrences values smaller than %d.\n",
							 file, linenum, MAX_HDR_HISTORY);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				} else {
					struct sockaddr_storage *sk;

					sk = str2sa_range(args[cur_arg + 1], NULL, &port1, &port2, NULL, NULL, NULL,
					                  &errmsg, NULL, NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_STREAM | PA_O_CONNECT);
					if (!sk) {
						ha_alert("parsing [%s:%d] : '%s %s' : %s\n",
							 file, linenum, args[cur_arg], args[cur_arg+1], errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					curproxy->conn_src.tproxy_addr = *sk;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_ADDR;
				}
				global.last_checks |= LSTCHK_NETADM;
#else	/* no TPROXY support */
				ha_alert("parsing [%s:%d] : '%s' not allowed here because support for TPROXY was not compiled in.\n",
					 file, linenum, "usesrc");
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
				cur_arg += 2;
				continue;
			}

			if (strcmp(args[cur_arg], "interface") == 0) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d] : '%s' : missing interface name.\n",
						 file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				free(curproxy->conn_src.iface_name);
				curproxy->conn_src.iface_name = strdup(args[cur_arg + 1]);
				if (!curproxy->conn_src.iface_name)
					goto alloc_error;
				curproxy->conn_src.iface_len  = strlen(curproxy->conn_src.iface_name);
				global.last_checks |= LSTCHK_NETADM;
#else
				ha_alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
					 file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
				cur_arg += 2;
				continue;
			}
			ha_alert("parsing [%s:%d] : '%s' only supports optional keywords '%s' and '%s'.\n",
				 file, linenum, args[0], "interface", "usesrc");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "usesrc") == 0) {  /* address to use outside: needs "source" first */
		ha_alert("parsing [%s:%d] : '%s' only allowed after a '%s' statement.\n",
			 file, linenum, "usesrc", "source");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "cliexp") == 0 || strcmp(args[0], "reqrep") == 0) {  /* replace request header from a regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request replace-path', 'http-request replace-uri' or 'http-request replace-header' instead.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqdel") == 0) {  /* delete request header from a regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request del-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqdeny") == 0) {  /* deny a request if a header matches this regex */
		ha_alert("parsing [%s:%d] : The '%s' not supported anymore since HAProxy 2.1. "
			 "Use 'http-request deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqpass") == 0) {  /* pass this header without allowing or denying the request */
		ha_alert("parsing [%s:%d] : The '%s' not supported anymore since HAProxy 2.1.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqallow") == 0) {  /* allow a request if a header matches this regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request allow' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqtarpit") == 0) {  /* tarpit a request if a header matches this regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request tarpit' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqirep") == 0) {  /* replace request header from a regex, ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request replace-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqidel") == 0) {  /* delete request header from a regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request del-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqideny") == 0) {  /* deny a request if a header matches this regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqipass") == 0) {  /* pass this header without allowing or denying the request */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqiallow") == 0) {  /* allow a request if a header matches this regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request allow' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqitarpit") == 0) {  /* tarpit a request if a header matches this regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request tarpit' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "reqadd") == 0) {  /* add request header */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-request add-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "srvexp") == 0 || strcmp(args[0], "rsprep") == 0) {  /* replace response header from a regex */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response replace-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "rspdel") == 0) {  /* delete response header from a regex */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response del-header' .\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "rspdeny") == 0) {  /* block response header from a regex */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "rspirep") == 0) {  /* replace response header from a regex ignoring case */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response replace-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "rspidel") == 0) {  /* delete response header from a regex ignoring case */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response del-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "rspideny") == 0) {  /* block response header from a regex ignoring case */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "rspadd") == 0) {  /* add response header */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response add-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else {
		struct cfg_kw_list *kwl;
		const char *best;
		int index;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_LISTEN)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
					if (check_kw_experimental(&kwl->kw[index], file, linenum, &errmsg)) {
						ha_alert("%s\n", errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					/* prepare error message just in case */
					rc = kwl->kw[index].parse(args, CFG_LISTEN, curproxy, curr_defproxy, file, linenum, &errmsg);
					if (rc < 0) {
						ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					else if (rc > 0) {
						ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_WARN;
						goto out;
					}
					goto out;
				}
			}
		}

		best = cfg_find_best_match(args[0], &cfg_keywords.list, CFG_LISTEN, common_kw_list);
		if (best)
			ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n", file, linenum, args[0], cursection, best);
		else
			ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
 out:
	free(errmsg);
	return err_code;

 alloc_error:
	ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
	err_code |= ERR_ALERT | ERR_ABORT;
	goto out;
}
