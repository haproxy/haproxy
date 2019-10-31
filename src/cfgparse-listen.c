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
#include <fcntl.h>
#include <unistd.h>

#include <common/cfgparse.h>
#include <common/uri_auth.h>

#include <types/capture.h>
#include <types/compression.h>
#include <types/stats.h>

#include <proto/acl.h>
#include <proto/checks.h>
#include <proto/connection.h>
#include <proto/http_htx.h>
#include <proto/http_rules.h>
#include <proto/listener.h>
#include <proto/protocol.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/stick_table.h>

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
	static struct proxy *curproxy = NULL;
	const char *err;
	char *error;
	int rc;
	unsigned val;
	int err_code = 0;
	struct acl_cond *cond = NULL;
	struct logsrv *tmplogsrv;
	char *errmsg = NULL;
	struct bind_conf *bind_conf;

	if (!strcmp(args[0], "listen"))
		rc = PR_CAP_LISTEN;
	else if (!strcmp(args[0], "frontend"))
		rc = PR_CAP_FE;
	else if (!strcmp(args[0], "backend"))
		rc = PR_CAP_BE;
	else
		rc = PR_CAP_NONE;

	if (rc != PR_CAP_NONE) {  /* new proxy */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an <id> argument and\n"
				 "  optionally supports [addr1]:port1[-end1]{,[addr]:port[-end]}...\n",
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

		if ((curproxy = calloc(1, sizeof(*curproxy))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		init_new_proxy(curproxy);
		curproxy->next = proxies_list;
		proxies_list = curproxy;
		curproxy->conf.args.file = curproxy->conf.file = strdup(file);
		curproxy->conf.args.line = curproxy->conf.line = linenum;
		curproxy->last_change = now.tv_sec;
		curproxy->id = strdup(args[1]);
		curproxy->cap = rc;
		proxy_store_name(curproxy);

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			if (curproxy->cap & PR_CAP_FE)
				ha_alert("parsing [%s:%d] : please use the 'bind' keyword for listening addresses.\n", file, linenum);
			goto out;
		}

		/* set default values */
		memcpy(&curproxy->defsrv, &defproxy.defsrv, sizeof(curproxy->defsrv));
		curproxy->defsrv.id = "default-server";

		curproxy->state = defproxy.state;
		curproxy->options = defproxy.options;
		curproxy->options2 = defproxy.options2;
		curproxy->no_options = defproxy.no_options;
		curproxy->no_options2 = defproxy.no_options2;
		curproxy->bind_proc = defproxy.bind_proc;
		curproxy->except_net = defproxy.except_net;
		curproxy->except_mask = defproxy.except_mask;
		curproxy->except_to = defproxy.except_to;
		curproxy->except_mask_to = defproxy.except_mask_to;
		curproxy->retry_type = defproxy.retry_type;

		if (defproxy.fwdfor_hdr_len) {
			curproxy->fwdfor_hdr_len  = defproxy.fwdfor_hdr_len;
			curproxy->fwdfor_hdr_name = strdup(defproxy.fwdfor_hdr_name);
		}

		if (defproxy.orgto_hdr_len) {
			curproxy->orgto_hdr_len  = defproxy.orgto_hdr_len;
			curproxy->orgto_hdr_name = strdup(defproxy.orgto_hdr_name);
		}

		if (defproxy.server_id_hdr_len) {
			curproxy->server_id_hdr_len  = defproxy.server_id_hdr_len;
			curproxy->server_id_hdr_name = strdup(defproxy.server_id_hdr_name);
		}

		/* initialize error relocations */
		for (rc = 0; rc < HTTP_ERR_SIZE; rc++)
			chunk_dup(&curproxy->errmsg[rc], &defproxy.errmsg[rc]);

		if (curproxy->cap & PR_CAP_FE) {
			curproxy->maxconn = defproxy.maxconn;
			curproxy->backlog = defproxy.backlog;
			curproxy->fe_sps_lim = defproxy.fe_sps_lim;

			curproxy->to_log = defproxy.to_log & ~LW_COOKIE & ~LW_REQHDR & ~ LW_RSPHDR;
			curproxy->max_out_conns = defproxy.max_out_conns;
		}

		if (curproxy->cap & PR_CAP_BE) {
			curproxy->lbprm.algo = defproxy.lbprm.algo;
			curproxy->lbprm.hash_balance_factor = defproxy.lbprm.hash_balance_factor;
			curproxy->fullconn = defproxy.fullconn;
			curproxy->conn_retries = defproxy.conn_retries;
			curproxy->redispatch_after = defproxy.redispatch_after;
			curproxy->max_ka_queue = defproxy.max_ka_queue;

			if (defproxy.check_req) {
				curproxy->check_req = calloc(1, defproxy.check_len);
				memcpy(curproxy->check_req, defproxy.check_req, defproxy.check_len);
			}
			curproxy->check_len = defproxy.check_len;

			if (defproxy.expect_str) {
				curproxy->expect_str = strdup(defproxy.expect_str);
				if (defproxy.expect_regex) {
					/* note: this regex is known to be valid */
					error = NULL;
					if (!(curproxy->expect_regex = regex_comp(defproxy.expect_str, 1, 1, &error))) {
						ha_alert("parsing [%s:%d] : regular expression '%s' : %s\n", file, linenum,
						         defproxy.expect_str, error);
						free(error);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				}
			}

			curproxy->ck_opts = defproxy.ck_opts;
			if (defproxy.cookie_name)
				curproxy->cookie_name = strdup(defproxy.cookie_name);
			curproxy->cookie_len = defproxy.cookie_len;

			if (defproxy.dyncookie_key)
				curproxy->dyncookie_key = strdup(defproxy.dyncookie_key);
			if (defproxy.cookie_domain)
				curproxy->cookie_domain = strdup(defproxy.cookie_domain);

			if (defproxy.cookie_maxidle)
				curproxy->cookie_maxidle = defproxy.cookie_maxidle;

			if (defproxy.cookie_maxlife)
				curproxy->cookie_maxlife = defproxy.cookie_maxlife;

			if (defproxy.rdp_cookie_name)
				 curproxy->rdp_cookie_name = strdup(defproxy.rdp_cookie_name);
			curproxy->rdp_cookie_len = defproxy.rdp_cookie_len;


			if (defproxy.lbprm.arg_str)
				curproxy->lbprm.arg_str = strdup(defproxy.lbprm.arg_str);
			curproxy->lbprm.arg_len  = defproxy.lbprm.arg_len;
			curproxy->lbprm.arg_opt1 = defproxy.lbprm.arg_opt1;
			curproxy->lbprm.arg_opt2 = defproxy.lbprm.arg_opt2;
			curproxy->lbprm.arg_opt3 = defproxy.lbprm.arg_opt3;

			if (defproxy.conn_src.iface_name)
				curproxy->conn_src.iface_name = strdup(defproxy.conn_src.iface_name);
			curproxy->conn_src.iface_len = defproxy.conn_src.iface_len;
			curproxy->conn_src.opts = defproxy.conn_src.opts;
#if defined(CONFIG_HAP_TRANSPARENT)
			curproxy->conn_src.tproxy_addr = defproxy.conn_src.tproxy_addr;
#endif
			curproxy->load_server_state_from_file = defproxy.load_server_state_from_file;
		}

		if (curproxy->cap & PR_CAP_FE) {
			if (defproxy.capture_name)
				curproxy->capture_name = strdup(defproxy.capture_name);
			curproxy->capture_namelen = defproxy.capture_namelen;
			curproxy->capture_len = defproxy.capture_len;
		}

		if (curproxy->cap & PR_CAP_FE) {
			curproxy->timeout.client = defproxy.timeout.client;
			curproxy->timeout.clientfin = defproxy.timeout.clientfin;
			curproxy->timeout.tarpit = defproxy.timeout.tarpit;
			curproxy->timeout.httpreq = defproxy.timeout.httpreq;
			curproxy->timeout.httpka = defproxy.timeout.httpka;
			curproxy->mon_net = defproxy.mon_net;
			curproxy->mon_mask = defproxy.mon_mask;
			if (defproxy.monitor_uri)
				curproxy->monitor_uri = strdup(defproxy.monitor_uri);
			curproxy->monitor_uri_len = defproxy.monitor_uri_len;
			if (defproxy.defbe.name)
				curproxy->defbe.name = strdup(defproxy.defbe.name);

			/* get either a pointer to the logformat string or a copy of it */
			curproxy->conf.logformat_string = defproxy.conf.logformat_string;
			if (curproxy->conf.logformat_string &&
			    curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format)
				curproxy->conf.logformat_string = strdup(curproxy->conf.logformat_string);

			if (defproxy.conf.lfs_file) {
				curproxy->conf.lfs_file = strdup(defproxy.conf.lfs_file);
				curproxy->conf.lfs_line = defproxy.conf.lfs_line;
			}

			/* get either a pointer to the logformat string for RFC5424 structured-data or a copy of it */
			curproxy->conf.logformat_sd_string = defproxy.conf.logformat_sd_string;
			if (curproxy->conf.logformat_sd_string &&
			    curproxy->conf.logformat_sd_string != default_rfc5424_sd_log_format)
				curproxy->conf.logformat_sd_string = strdup(curproxy->conf.logformat_sd_string);

			if (defproxy.conf.lfsd_file) {
				curproxy->conf.lfsd_file = strdup(defproxy.conf.lfsd_file);
				curproxy->conf.lfsd_line = defproxy.conf.lfsd_line;
			}
		}

		if (curproxy->cap & PR_CAP_BE) {
			curproxy->timeout.connect = defproxy.timeout.connect;
			curproxy->timeout.server = defproxy.timeout.server;
			curproxy->timeout.serverfin = defproxy.timeout.serverfin;
			curproxy->timeout.check = defproxy.timeout.check;
			curproxy->timeout.queue = defproxy.timeout.queue;
			curproxy->timeout.tarpit = defproxy.timeout.tarpit;
			curproxy->timeout.httpreq = defproxy.timeout.httpreq;
			curproxy->timeout.httpka = defproxy.timeout.httpka;
			curproxy->timeout.tunnel = defproxy.timeout.tunnel;
			curproxy->conn_src.source_addr = defproxy.conn_src.source_addr;
		}

		curproxy->mode = defproxy.mode;
		curproxy->uri_auth = defproxy.uri_auth; /* for stats */

		/* copy default logsrvs to curproxy */
		list_for_each_entry(tmplogsrv, &defproxy.logsrvs, list) {
			struct logsrv *node = malloc(sizeof(*node));
			memcpy(node, tmplogsrv, sizeof(struct logsrv));
			node->ref = tmplogsrv->ref;
			LIST_INIT(&node->list);
			LIST_ADDQ(&curproxy->logsrvs, &node->list);
		}

		curproxy->conf.uniqueid_format_string = defproxy.conf.uniqueid_format_string;
		if (curproxy->conf.uniqueid_format_string)
			curproxy->conf.uniqueid_format_string = strdup(curproxy->conf.uniqueid_format_string);

		chunk_dup(&curproxy->log_tag, &defproxy.log_tag);

		if (defproxy.conf.uif_file) {
			curproxy->conf.uif_file = strdup(defproxy.conf.uif_file);
			curproxy->conf.uif_line = defproxy.conf.uif_line;
		}

		/* copy default header unique id */
		if (defproxy.header_unique_id)
			curproxy->header_unique_id = strdup(defproxy.header_unique_id);

		/* default compression options */
		if (defproxy.comp != NULL) {
			curproxy->comp = calloc(1, sizeof(struct comp));
			curproxy->comp->algos = defproxy.comp->algos;
			curproxy->comp->types = defproxy.comp->types;
		}

		curproxy->grace  = defproxy.grace;
		curproxy->conf.used_listener_id = EB_ROOT;
		curproxy->conf.used_server_id = EB_ROOT;

		if (defproxy.check_path)
			curproxy->check_path = strdup(defproxy.check_path);
		if (defproxy.check_command)
			curproxy->check_command = strdup(defproxy.check_command);

		if (defproxy.email_alert.mailers.name)
			curproxy->email_alert.mailers.name = strdup(defproxy.email_alert.mailers.name);
		if (defproxy.email_alert.from)
			curproxy->email_alert.from = strdup(defproxy.email_alert.from);
		if (defproxy.email_alert.to)
			curproxy->email_alert.to = strdup(defproxy.email_alert.to);
		if (defproxy.email_alert.myhostname)
			curproxy->email_alert.myhostname = strdup(defproxy.email_alert.myhostname);
		curproxy->email_alert.level = defproxy.email_alert.level;
		curproxy->email_alert.set = defproxy.email_alert.set;

		goto out;
	}
	else if (!strcmp(args[0], "defaults")) {  /* use this one to assign default values */
		/* some variables may have already been initialized earlier */
		/* FIXME-20070101: we should do this too at the end of the
		 * config parsing to free all default values.
		 */
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		free(defproxy.check_req);
		free(defproxy.check_command);
		free(defproxy.check_path);
		free(defproxy.cookie_name);
		free(defproxy.rdp_cookie_name);
		free(defproxy.dyncookie_key);
		free(defproxy.cookie_domain);
		free(defproxy.lbprm.arg_str);
		free(defproxy.capture_name);
		free(defproxy.monitor_uri);
		free(defproxy.defbe.name);
		free(defproxy.conn_src.iface_name);
		free(defproxy.fwdfor_hdr_name);
		defproxy.fwdfor_hdr_len = 0;
		free(defproxy.orgto_hdr_name);
		defproxy.orgto_hdr_len = 0;
		free(defproxy.server_id_hdr_name);
		defproxy.server_id_hdr_len = 0;
		free(defproxy.expect_str);
		regex_free(defproxy.expect_regex);
		defproxy.expect_regex = NULL;

		if (defproxy.conf.logformat_string != default_http_log_format &&
		    defproxy.conf.logformat_string != default_tcp_log_format &&
		    defproxy.conf.logformat_string != clf_http_log_format)
			free(defproxy.conf.logformat_string);

		free(defproxy.conf.uniqueid_format_string);
		free(defproxy.conf.lfs_file);
		free(defproxy.conf.uif_file);
		chunk_destroy(&defproxy.log_tag);
		free_email_alert(&defproxy);

		if (defproxy.conf.logformat_sd_string != default_rfc5424_sd_log_format)
			free(defproxy.conf.logformat_sd_string);
		free(defproxy.conf.lfsd_file);

		for (rc = 0; rc < HTTP_ERR_SIZE; rc++)
			chunk_destroy(&defproxy.errmsg[rc]);

		/* we cannot free uri_auth because it might already be used */
		init_default_instance();
		curproxy = &defproxy;
		curproxy->conf.args.file = curproxy->conf.file = strdup(file);
		curproxy->conf.args.line = curproxy->conf.line = linenum;
		defproxy.cap = PR_CAP_LISTEN; /* all caps for now */
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
	if (!strcmp(args[0], "server")         ||
	    !strcmp(args[0], "default-server") ||
	    !strcmp(args[0], "server-template")) {
		err_code |= parse_server(file, linenum, args, curproxy, &defproxy, 1);
		if (err_code & ERR_FATAL)
			goto out;
	}
	else if (!strcmp(args[0], "bind")) {  /* new listen addresses */
		struct listener *l;
		int cur_arg;

		if (curproxy == &defproxy) {
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

		/* use default settings for unix sockets */
		bind_conf->ux.uid  = global.unix_bind.ux.uid;
		bind_conf->ux.gid  = global.unix_bind.ux.gid;
		bind_conf->ux.mode = global.unix_bind.ux.mode;

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
		while (*(args[cur_arg])) {
			static int bind_dumped;
			struct bind_kw *kw;
			char *err;

			kw = bind_find_kw(args[cur_arg]);
			if (kw) {
				char *err = NULL;
				int code;

				if (!kw->parse) {
					ha_alert("parsing [%s:%d] : '%s %s' : '%s' option is not implemented in this version (check build options).\n",
						 file, linenum, args[0], args[1], args[cur_arg]);
					cur_arg += 1 + kw->skip ;
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				code = kw->parse(args, cur_arg, curproxy, bind_conf, &err);
				err_code |= code;

				if (code) {
					if (err && *err) {
						indent_msg(&err, 2);
						if (((code & (ERR_WARN|ERR_ALERT)) == ERR_WARN))
							ha_warning("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], err);
						else
							ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], err);
					}
					else
						ha_alert("parsing [%s:%d] : '%s %s' : error encountered while processing '%s'.\n",
							 file, linenum, args[0], args[1], args[cur_arg]);
					if (code & ERR_FATAL) {
						free(err);
						cur_arg += 1 + kw->skip;
						goto out;
					}
				}
				free(err);
				cur_arg += 1 + kw->skip;
				continue;
			}

			err = NULL;
			if (!bind_dumped) {
				bind_dump_kws(&err);
				indent_msg(&err, 4);
				bind_dumped = 1;
			}

			ha_alert("parsing [%s:%d] : '%s %s' unknown keyword '%s'.%s%s\n",
				 file, linenum, args[0], args[1], args[cur_arg],
				 err ? " Registered keywords :" : "", err ? err : "");
			free(err);

			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		goto out;
	}
	else if (!strcmp(args[0], "monitor-net")) {  /* set the range of IPs to ignore */
		if (!*args[1] || !str2net(args[1], 1, &curproxy->mon_net, &curproxy->mon_mask)) {
			ha_alert("parsing [%s:%d] : '%s' expects address[/mask].\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		/* flush useless bits */
		curproxy->mon_net.s_addr &= curproxy->mon_mask.s_addr;
		goto out;
	}
	else if (!strcmp(args[0], "monitor-uri")) {  /* set the URI to intercept */
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

		free(curproxy->monitor_uri);
		curproxy->monitor_uri_len = strlen(args[1]);
		curproxy->monitor_uri = calloc(1, curproxy->monitor_uri_len + 1);
		memcpy(curproxy->monitor_uri, args[1], curproxy->monitor_uri_len);
		curproxy->monitor_uri[curproxy->monitor_uri_len] = '\0';

		goto out;
	}
	else if (!strcmp(args[0], "mode")) {  /* sets the proxy mode */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!strcmp(args[1], "http")) curproxy->mode = PR_MODE_HTTP;
		else if (!strcmp(args[1], "tcp")) curproxy->mode = PR_MODE_TCP;
		else if (!strcmp(args[1], "health")) curproxy->mode = PR_MODE_HEALTH;
		else {
			ha_alert("parsing [%s:%d] : unknown proxy mode '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "id")) {
		struct eb32_node *node;

		if (curproxy == &defproxy) {
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
	else if (!strcmp(args[0], "description")) {
		int i, len=0;
		char *d;

		if (curproxy == &defproxy) {
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
		curproxy->desc = d;

		d += snprintf(d, curproxy->desc + len - d, "%s", args[1]);
		for (i = 2; *args[i]; i++)
			d += snprintf(d, curproxy->desc + len - d, " %s", args[i]);

	}
	else if (!strcmp(args[0], "disabled")) {  /* disables this proxy */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		curproxy->state = PR_STSTOPPED;
	}
	else if (!strcmp(args[0], "enabled")) {  /* enables this proxy (used to revert a disabled default) */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		curproxy->state = PR_STNEW;
	}
	else if (!strcmp(args[0], "bind-process")) {  /* enable this proxy only on some processes */
		int cur_arg = 1;
		unsigned long set = 0;

		while (*args[cur_arg]) {
			if (strcmp(args[cur_arg], "all") == 0) {
				set = 0;
				break;
			}
			if (parse_process_number(args[cur_arg], &set, MAX_PROCS, NULL, &errmsg)) {
				ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg++;
		}
		curproxy->bind_proc = set;
	}
	else if (!strcmp(args[0], "acl")) {  /* add an ACL */
		if (curproxy == &defproxy) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
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

		if (parse_acl((const char **)args + 1, &curproxy->acl, &errmsg, &curproxy->conf.args, file, linenum) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing ACL '%s' : %s.\n",
				 file, linenum, args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "dynamic-cookie-key")) { /* Dynamic cookies secret key */

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
	else if (!strcmp(args[0], "cookie")) {  /* cookie name */
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
		free(curproxy->cookie_domain); curproxy->cookie_domain = NULL;
		free(curproxy->cookie_name);
		curproxy->cookie_name = strdup(args[1]);
		curproxy->cookie_len = strlen(curproxy->cookie_name);

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "rewrite")) {
				curproxy->ck_opts |= PR_CK_RW;
			}
			else if (!strcmp(args[cur_arg], "indirect")) {
				curproxy->ck_opts |= PR_CK_IND;
			}
			else if (!strcmp(args[cur_arg], "insert")) {
				curproxy->ck_opts |= PR_CK_INS;
			}
			else if (!strcmp(args[cur_arg], "nocache")) {
				curproxy->ck_opts |= PR_CK_NOC;
			}
			else if (!strcmp(args[cur_arg], "postonly")) {
				curproxy->ck_opts |= PR_CK_POST;
			}
			else if (!strcmp(args[cur_arg], "preserve")) {
				curproxy->ck_opts |= PR_CK_PSV;
			}
			else if (!strcmp(args[cur_arg], "prefix")) {
				curproxy->ck_opts |= PR_CK_PFX;
			}
			else if (!strcmp(args[cur_arg], "httponly")) {
				curproxy->ck_opts |= PR_CK_HTTPONLY;
			}
			else if (!strcmp(args[cur_arg], "secure")) {
				curproxy->ck_opts |= PR_CK_SECURE;
			}
			else if (!strcmp(args[cur_arg], "domain")) {
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
					char *new_ptr;
					int new_len = strlen(curproxy->cookie_domain) +
						strlen("; domain=") + strlen(args[cur_arg + 1]) + 1;
					new_ptr = malloc(new_len);
					snprintf(new_ptr, new_len, "%s; domain=%s", curproxy->cookie_domain, args[cur_arg+1]);
					free(curproxy->cookie_domain);
					curproxy->cookie_domain = new_ptr;
				}
				cur_arg++;
			}
			else if (!strcmp(args[cur_arg], "maxidle")) {
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
			else if (!strcmp(args[cur_arg], "maxlife")) {
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
			else if (!strcmp(args[cur_arg], "dynamic")) { /* Dynamic persistent cookies secret key */

				if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[cur_arg], NULL))
					err_code |= ERR_WARN;
				curproxy->ck_opts |= PR_CK_DYNAMIC;
			}

			else {
				ha_alert("parsing [%s:%d] : '%s' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache', 'postonly', 'domain', 'maxidle', 'dynamic' and 'maxlife' options.\n",
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
	else if (!strcmp(args[0], "email-alert")) {
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }

		if (!strcmp(args[1], "from")) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.from);
			curproxy->email_alert.from = strdup(args[2]);
		}
		else if (!strcmp(args[1], "mailers")) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.mailers.name);
			curproxy->email_alert.mailers.name = strdup(args[2]);
		}
		else if (!strcmp(args[1], "myhostname")) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.myhostname);
			curproxy->email_alert.myhostname = strdup(args[2]);
		}
		else if (!strcmp(args[1], "level")) {
			curproxy->email_alert.level = get_log_level(args[2]);
			if (curproxy->email_alert.level < 0) {
				ha_alert("parsing [%s:%d] : unknown log level '%s' after '%s'\n",
					 file, linenum, args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else if (!strcmp(args[1], "to")) {
			if (*(args[1]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->email_alert.to);
			curproxy->email_alert.to = strdup(args[2]);
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
	else if (!strcmp(args[0], "external-check")) {
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }

		if (!strcmp(args[1], "command")) {
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->check_command);
			curproxy->check_command = strdup(args[2]);
		}
		else if (!strcmp(args[1], "path")) {
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : missing argument after '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			free(curproxy->check_path);
			curproxy->check_path = strdup(args[2]);
		}
		else {
			ha_alert("parsing [%s:%d] : external-check: unknown argument '%s'.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}/* end else if (!strcmp(args[0], "external-check"))  */
	else if (!strcmp(args[0], "persist")) {  /* persist */
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
				curproxy->rdp_cookie_len = end-beg;
			}
			else if (*(args[1] + 10) == '\0') { /* default cookie name 'msts' */
				free(curproxy->rdp_cookie_name);
				curproxy->rdp_cookie_name = strdup("msts");
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
	else if (!strcmp(args[0], "appsession")) {  /* cookie name */
		ha_alert("parsing [%s:%d] : '%s' is not supported anymore since HAProxy 1.6.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "load-server-state-from-file")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;
		if (!strcmp(args[1], "global")) {  /* use the file pointed to by global server-state-file directive */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_GLOBAL;
		}
		else if (!strcmp(args[1], "local")) { /* use the server-state-file-name variable to locate the server-state file */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_LOCAL;
		}
		else if (!strcmp(args[1], "none")) {  /* don't use server-state-file directive for this backend */
			curproxy->load_server_state_from_file = PR_SRV_STATE_FILE_NONE;
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' expects 'global', 'local' or 'none'. Got '%s'\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "server-state-file-name")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects 'use-backend-name' or a string. Got no argument\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (!strcmp(args[1], "use-backend-name"))
			curproxy->server_state_file_name = strdup(curproxy->id);
		else
			curproxy->server_state_file_name = strdup(args[1]);
	}
	else if (!strcmp(args[0], "max-session-srv-conns")) {
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
	else if (!strcmp(args[0], "capture")) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (!strcmp(args[1], "cookie")) {  /* name of a cookie to capture */
			if (curproxy == &defproxy) {
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
			curproxy->capture_namelen = strlen(curproxy->capture_name);
			curproxy->capture_len = atol(args[4]);
			curproxy->to_log |= LW_COOKIE;
		}
		else if (!strcmp(args[1], "request") && !strcmp(args[2], "header")) {
			struct cap_hdr *hdr;

			if (curproxy == &defproxy) {
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
			hdr->next = curproxy->req_cap;
			hdr->name = strdup(args[3]);
			hdr->namelen = strlen(args[3]);
			hdr->len = atol(args[5]);
			hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
			hdr->index = curproxy->nb_req_cap++;
			curproxy->req_cap = hdr;
			curproxy->to_log |= LW_REQHDR;
		}
		else if (!strcmp(args[1], "response") && !strcmp(args[2], "header")) {
			struct cap_hdr *hdr;

			if (curproxy == &defproxy) {
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
			hdr->next = curproxy->rsp_cap;
			hdr->name = strdup(args[3]);
			hdr->namelen = strlen(args[3]);
			hdr->len = atol(args[5]);
			hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
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
	else if (!strcmp(args[0], "retries")) {  /* connection retries */
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
	else if (!strcmp(args[0], "http-request")) {	/* request access control: allow/deny/auth */
		struct act_rule *rule;

		if (curproxy == &defproxy) {
			ha_alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!LIST_ISEMPTY(&curproxy->http_req_rules) &&
		    !LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->cond &&
		    (LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_ACTION_ALLOW ||
		     LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_ACTION_DENY ||
		     LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_HTTP_REDIR ||
		     LIST_PREV(&curproxy->http_req_rules, struct act_rule *, list)->action == ACT_HTTP_REQ_AUTH)) {
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
		err_code |= warnif_cond_conflicts(rule->cond,
	                                          (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
	                                          file, linenum);

		LIST_ADDQ(&curproxy->http_req_rules, &rule->list);
	}
	else if (!strcmp(args[0], "http-response")) {	/* response access control */
		struct act_rule *rule;

		if (curproxy == &defproxy) {
			ha_alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!LIST_ISEMPTY(&curproxy->http_res_rules) &&
		    !LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->cond &&
		    (LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->action == ACT_ACTION_ALLOW ||
		     LIST_PREV(&curproxy->http_res_rules, struct act_rule *, list)->action == ACT_ACTION_DENY)) {
			ha_warning("parsing [%s:%d]: previous '%s' action is final and has no condition attached, further entries are NOOP.\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		rule = parse_http_res_cond((const char **)args + 1, file, linenum, curproxy);

		if (!rule) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err_code |= warnif_cond_conflicts(rule->cond,
	                                          (curproxy->cap & PR_CAP_BE) ? SMP_VAL_BE_HRS_HDR : SMP_VAL_FE_HRS_HDR,
	                                          file, linenum);

		LIST_ADDQ(&curproxy->http_res_rules, &rule->list);
	}
	else if (!strcmp(args[0], "http-send-name-header")) { /* send server name in request header */
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
		free(curproxy->server_id_hdr_name);
		curproxy->server_id_hdr_name = strdup(args[1]);
		curproxy->server_id_hdr_len  = strlen(curproxy->server_id_hdr_name);
		ist2bin_lc(curproxy->server_id_hdr_name, ist2(curproxy->server_id_hdr_name, curproxy->server_id_hdr_len));
	}
	else if (!strcmp(args[0], "block")) {
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. Use 'http-request deny' which uses the exact same syntax.\n", file, linenum, args[0]);

		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "redirect")) {
		struct redirect_rule *rule;

		if (curproxy == &defproxy) {
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

		LIST_ADDQ(&curproxy->redirect_rules, &rule->list);
		err_code |= warnif_misplaced_redirect(curproxy, file, linenum, args[0]);
		err_code |= warnif_cond_conflicts(rule->cond,
	                                          (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
	                                          file, linenum);
	}
	else if (!strcmp(args[0], "use_backend")) {
		struct switching_rule *rule;

		if (curproxy == &defproxy) {
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
		if (!rule) {
			ha_alert("Out of memory error.\n");
			goto out;
		}
		rule->cond = cond;
		rule->be.name = strdup(args[1]);
		rule->line = linenum;
		rule->file = strdup(file);
		if (!rule->file) {
			ha_alert("Out of memory error.\n");
			goto out;
		}
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->switching_rules, &rule->list);
	}
	else if (strcmp(args[0], "use-server") == 0) {
		struct server_rule *rule;

		if (curproxy == &defproxy) {
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
		rule->cond = cond;
		rule->srv.name = strdup(args[1]);
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->server_rules, &rule->list);
		curproxy->be_req_ana |= AN_REQ_SRV_RULES;
	}
	else if ((!strcmp(args[0], "force-persist")) ||
		 (!strcmp(args[0], "ignore-persist"))) {
		struct persist_rule *rule;

		if (curproxy == &defproxy) {
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
		rule->cond = cond;
		if (!strcmp(args[0], "force-persist")) {
			rule->type = PERSIST_TYPE_FORCE;
		} else {
			rule->type = PERSIST_TYPE_IGNORE;
		}
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curproxy->persist_rules, &rule->list);
	}
	else if (!strcmp(args[0], "stick-table")) {
		struct stktable *other;

		if (curproxy == &defproxy) {
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
		if (err_code & ERR_FATAL)
			goto out;

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
	else if (!strcmp(args[0], "stick")) {
		struct sticking_rule *rule;
		struct sample_expr *expr;
		int myidx = 0;
		const char *name = NULL;
		int flags;

		if (curproxy == &defproxy) {
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
		expr = sample_parse_expr(args, &myidx, file, linenum, &errmsg, &curproxy->conf.args);
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
		rule->cond = cond;
		rule->expr = expr;
		rule->flags = flags;
		rule->table.name = name ? strdup(name) : NULL;
		LIST_INIT(&rule->list);
		if (flags & STK_ON_RSP)
			LIST_ADDQ(&curproxy->storersp_rules, &rule->list);
		else
			LIST_ADDQ(&curproxy->sticking_rules, &rule->list);
	}
	else if (!strcmp(args[0], "stats")) {
		if (curproxy != &defproxy && curproxy->uri_auth == defproxy.uri_auth)
			curproxy->uri_auth = NULL; /* we must detach from the default config */

		if (!*args[1]) {
			goto stats_error_parsing;
		} else if (!strcmp(args[1], "admin")) {
			struct stats_admin_rule *rule;

			if (curproxy == &defproxy) {
				ha_alert("parsing [%s:%d]: '%s %s' not allowed in 'defaults' section.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!stats_check_init_uri_auth(&curproxy->uri_auth)) {
				ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

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

			err_code |= warnif_cond_conflicts(cond,
			                                  (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
			                                  file, linenum);

			rule = calloc(1, sizeof(*rule));
			rule->cond = cond;
			LIST_INIT(&rule->list);
			LIST_ADDQ(&curproxy->uri_auth->admin_rules, &rule->list);
		} else if (!strcmp(args[1], "uri")) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'uri' needs an URI prefix.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_uri(&curproxy->uri_auth, args[2])) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "realm")) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'realm' needs an realm name.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_set_realm(&curproxy->uri_auth, args[2])) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "refresh")) {
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
			} else if (!stats_set_refresh(&curproxy->uri_auth, interval)) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "http-request")) {    /* request access control: allow/deny/auth */
			struct act_rule *rule;

			if (curproxy == &defproxy) {
				ha_alert("parsing [%s:%d]: '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!stats_check_init_uri_auth(&curproxy->uri_auth)) {
				ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

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

			err_code |= warnif_cond_conflicts(rule->cond,
			                                  (curproxy->cap & PR_CAP_FE) ? SMP_VAL_FE_HRQ_HDR : SMP_VAL_BE_HRQ_HDR,
			                                  file, linenum);
			LIST_ADDQ(&curproxy->uri_auth->http_req_rules, &rule->list);

		} else if (!strcmp(args[1], "auth")) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'auth' needs a user:password account.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_add_auth(&curproxy->uri_auth, args[2])) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "scope")) {
			if (*(args[2]) == 0) {
				ha_alert("parsing [%s:%d] : 'scope' needs a proxy name.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else if (!stats_add_scope(&curproxy->uri_auth, args[2])) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "enable")) {
			if (!stats_check_init_uri_auth(&curproxy->uri_auth)) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "hide-version")) {
			if (!stats_set_flag(&curproxy->uri_auth, STAT_HIDEVER)) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "show-legends")) {
			if (!stats_set_flag(&curproxy->uri_auth, STAT_SHLGNDS)) {
				ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "show-node")) {

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

			if (!stats_set_node(&curproxy->uri_auth, args[2])) {
				ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		} else if (!strcmp(args[1], "show-desc")) {
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
					ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
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
	else if (!strcmp(args[0], "option")) {
		int optnum;

		if (*(args[1]) == '\0') {
			ha_alert("parsing [%s:%d]: '%s' expects an option name.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (optnum = 0; cfg_opts[optnum].name; optnum++) {
			if (!strcmp(args[1], cfg_opts[optnum].name)) {
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
			if (!strcmp(args[1], cfg_opts2[optnum].name)) {
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

				/* "[no] option http-use-htx" is deprecated */
				if (!strcmp(cfg_opts2[optnum].name, "http-use-htx")) {
					if (kwm ==KWM_NO) {
						ha_warning("parsing [%s:%d]: option '%s' is deprecated and ignored."
							   " The HTX mode is now the only supported mode.\n",
							   file, linenum, cfg_opts2[optnum].name);
						err_code |= ERR_WARN;
					}
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
		if (strcmp(args[1], "httpclose") == 0 || strcmp(args[1], "forceclose") == 0) {
			if (strcmp(args[1], "forceclose") == 0) {
				if (!already_warned(WARN_FORCECLOSE_DEPRECATED))
					ha_warning("parsing [%s:%d]: keyword '%s' is deprecated in favor of 'httpclose', and will not be supported by future versions.\n",
					  file, linenum, args[1]);
				err_code |= ERR_WARN;
			}
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
			ha_warning("parsing [%s:%d]: the option '%s' is deprecated and will be removed in next version.\n",
				 file, linenum, args[1]);
			err_code |= ERR_WARN;
			goto out;
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

		if (kwm != KWM_STD) {
			ha_alert("parsing [%s:%d]: negation/default is not supported for option '%s'.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!strcmp(args[1], "httplog")) {
			char *logformat;
			/* generate a complete HTTP log */
			logformat = default_http_log_format;
			if (*(args[2]) != '\0') {
				if (!strcmp(args[2], "clf")) {
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
			if (curproxy->conf.logformat_string && curproxy == &defproxy) {
				char *oldlogformat = "log-format";
				char *clflogformat = "";

				if (curproxy->conf.logformat_string == default_http_log_format)
					oldlogformat = "option httplog";
				else if (curproxy->conf.logformat_string == default_tcp_log_format)
					oldlogformat = "option tcplog";
				else if (curproxy->conf.logformat_string == clf_http_log_format)
					oldlogformat = "option httplog clf";
				if (logformat == clf_http_log_format)
					clflogformat = " clf";
				ha_warning("parsing [%s:%d]: 'option httplog%s' overrides previous '%s' in 'defaults' section.\n",
					   file, linenum, clflogformat, oldlogformat);
			}
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = logformat;

			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;

			if (curproxy != &defproxy && !(curproxy->cap & PR_CAP_FE)) {
				ha_warning("parsing [%s:%d] : backend '%s' : 'option httplog' directive is ignored in backends.\n",
					file, linenum, curproxy->id);
				err_code |= ERR_WARN;
			}
		}
		else if (!strcmp(args[1], "tcplog")) {
			if (curproxy->conf.logformat_string && curproxy == &defproxy) {
				char *oldlogformat = "log-format";

				if (curproxy->conf.logformat_string == default_http_log_format)
					oldlogformat = "option httplog";
				else if (curproxy->conf.logformat_string == default_tcp_log_format)
					oldlogformat = "option tcplog";
				else if (curproxy->conf.logformat_string == clf_http_log_format)
					oldlogformat = "option httplog clf";
				ha_warning("parsing [%s:%d]: 'option tcplog' overrides previous '%s' in 'defaults' section.\n",
					   file, linenum, oldlogformat);
			}
			/* generate a detailed TCP log */
			if (curproxy->conf.logformat_string != default_http_log_format &&
			    curproxy->conf.logformat_string != default_tcp_log_format &&
			    curproxy->conf.logformat_string != clf_http_log_format)
				free(curproxy->conf.logformat_string);
			curproxy->conf.logformat_string = default_tcp_log_format;

			free(curproxy->conf.lfs_file);
			curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
			curproxy->conf.lfs_line = curproxy->conf.args.line;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;

			if (curproxy != &defproxy && !(curproxy->cap & PR_CAP_FE)) {
				ha_warning("parsing [%s:%d] : backend '%s' : 'option tcplog' directive is ignored in backends.\n",
					file, linenum, curproxy->id);
				err_code |= ERR_WARN;
			}
		}
		else if (!strcmp(args[1], "tcpka")) {
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
		else if (!strcmp(args[1], "httpchk")) {
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			/* use HTTP request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_HTTP_CHK;
			if (!*args[2]) { /* no argument */
				curproxy->check_req = strdup(DEF_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_CHECK_REQ);
			} else if (!*args[3]) { /* one argument : URI */
				int reqlen = strlen(args[2]) + strlen("OPTIONS  HTTP/1.0\r\n") + 1;
				curproxy->check_req = malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "OPTIONS %s HTTP/1.0\r\n", args[2]); /* URI to use */
			} else { /* more arguments : METHOD URI [HTTP_VER] */
				int reqlen = strlen(args[2]) + strlen(args[3]) + 3 + strlen("\r\n");
				if (*args[4])
					reqlen += strlen(args[4]);
				else
					reqlen += strlen("HTTP/1.0");

				curproxy->check_req = malloc(reqlen);
				curproxy->check_len = snprintf(curproxy->check_req, reqlen,
							       "%s %s %s\r\n", args[2], args[3], *args[4]?args[4]:"HTTP/1.0");
			}
			if (alertif_too_many_args_idx(3, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "ssl-hello-chk")) {
			/* use SSLv3 CLIENT HELLO to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_SSL3_CHK;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "smtpchk")) {
			/* use SMTP request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_SMTP_CHK;

			if (!*args[2] || !*args[3]) { /* no argument or incomplete EHLO host */
				curproxy->check_req = strdup(DEF_SMTP_CHECK_REQ); /* default request */
				curproxy->check_len = strlen(DEF_SMTP_CHECK_REQ);
			} else { /* ESMTP EHLO, or SMTP HELO, and a hostname */
				if (!strcmp(args[2], "EHLO") || !strcmp(args[2], "HELO")) {
					int reqlen = strlen(args[2]) + strlen(args[3]) + strlen(" \r\n") + 1;
					curproxy->check_req = malloc(reqlen);
					curproxy->check_len = snprintf(curproxy->check_req, reqlen,
								       "%s %s\r\n", args[2], args[3]); /* HELO hostname */
				} else {
					/* this just hits the default for now, but you could potentially expand it to allow for other stuff
					   though, it's unlikely you'd want to send anything other than an EHLO or HELO */
					curproxy->check_req = strdup(DEF_SMTP_CHECK_REQ); /* default request */
					curproxy->check_len = strlen(DEF_SMTP_CHECK_REQ);
				}
			}
			if (alertif_too_many_args_idx(2, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "pgsql-check")) {
			/* use PostgreSQL request to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_PGSQL_CHK;

			if (*(args[2])) {
				int cur_arg = 2;

				while (*(args[cur_arg])) {
					if (strcmp(args[cur_arg], "user") == 0) {
						char * packet;
						uint32_t packet_len;
						uint32_t pv;

						/* suboption header - needs additional argument for it */
						if (*(args[cur_arg+1]) == 0) {
							ha_alert("parsing [%s:%d] : '%s %s %s' expects <username> as argument.\n",
								 file, linenum, args[0], args[1], args[cur_arg]);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}

						/* uint32_t + uint32_t + strlen("user")+1 + strlen(username)+1 + 1 */
						packet_len = 4 + 4 + 5 + strlen(args[cur_arg + 1])+1 +1;
						pv = htonl(0x30000); /* protocol version 3.0 */

						packet = calloc(1, packet_len);

						memcpy(packet + 4, &pv, 4);

						/* copy "user" */
						memcpy(packet + 8, "user", 4);

						/* copy username */
						memcpy(packet + 13, args[cur_arg+1], strlen(args[cur_arg+1]));

						free(curproxy->check_req);
						curproxy->check_req = packet;
						curproxy->check_len = packet_len;

						packet_len = htonl(packet_len);
						memcpy(packet, &packet_len, 4);
						cur_arg += 2;
					} else {
						/* unknown suboption - catchall */
						ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user'.\n",
							 file, linenum, args[0], args[1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				} /* end while loop */
			}
			if (alertif_too_many_args_idx(2, 1, file, linenum, args, &err_code))
				goto out;
		}

		else if (!strcmp(args[1], "redis-check")) {
			/* use REDIS PING request to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_REDIS_CHK;

			curproxy->check_req = malloc(sizeof(DEF_REDIS_CHECK_REQ) - 1);
			memcpy(curproxy->check_req, DEF_REDIS_CHECK_REQ, sizeof(DEF_REDIS_CHECK_REQ) - 1);
			curproxy->check_len = sizeof(DEF_REDIS_CHECK_REQ) - 1;

			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}

		else if (!strcmp(args[1], "mysql-check")) {
			/* use MYSQL request to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_MYSQL_CHK;

			/* This is an example of a MySQL >=4.0 client Authentication packet kindly provided by Cyril Bonte.
			 * const char mysql40_client_auth_pkt[] = {
			 * 	"\x0e\x00\x00"	// packet length
			 * 	"\x01"		// packet number
			 * 	"\x00\x00"	// client capabilities
			 * 	"\x00\x00\x01"	// max packet
			 * 	"haproxy\x00"	// username (null terminated string)
			 * 	"\x00"		// filler (always 0x00)
			 * 	"\x01\x00\x00"	// packet length
			 * 	"\x00"		// packet number
			 * 	"\x01"		// COM_QUIT command
			 * };
			 */

			/* This is an example of a MySQL >=4.1  client Authentication packet provided by Nenad Merdanovic.
			 * const char mysql41_client_auth_pkt[] = {
			 * 	"\x0e\x00\x00\"		// packet length
			 * 	"\x01"			// packet number
			 * 	"\x00\x00\x00\x00"	// client capabilities
			 * 	"\x00\x00\x00\x01"	// max packet
			 *	"\x21"			// character set (UTF-8)
			 *	char[23]		// All zeroes
			 * 	"haproxy\x00"		// username (null terminated string)
			 * 	"\x00"			// filler (always 0x00)
			 * 	"\x01\x00\x00"		// packet length
			 * 	"\x00"			// packet number
			 * 	"\x01"			// COM_QUIT command
			 * };
			 */


			if (*(args[2])) {
				int cur_arg = 2;

				while (*(args[cur_arg])) {
					if (strcmp(args[cur_arg], "user") == 0) {
						char *mysqluser;
						int packetlen, reqlen, userlen;

						/* suboption header - needs additional argument for it */
						if (*(args[cur_arg+1]) == 0) {
							ha_alert("parsing [%s:%d] : '%s %s %s' expects <username> as argument.\n",
								 file, linenum, args[0], args[1], args[cur_arg]);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
						mysqluser = args[cur_arg + 1];
						userlen   = strlen(mysqluser);

						if (*(args[cur_arg+2])) {
							if (!strcmp(args[cur_arg+2], "post-41")) {
		                                                packetlen = userlen + 7 + 27;
								reqlen    = packetlen + 9;

								free(curproxy->check_req);
								curproxy->check_req = calloc(1, reqlen);
								curproxy->check_len = reqlen;

								snprintf(curproxy->check_req, 4, "%c%c%c",
									((unsigned char) packetlen & 0xff),
									((unsigned char) (packetlen >> 8) & 0xff),
									((unsigned char) (packetlen >> 16) & 0xff));

								curproxy->check_req[3] = 1;
								curproxy->check_req[5] = 0x82; // 130
								curproxy->check_req[11] = 1;
								curproxy->check_req[12] = 33;
								memcpy(&curproxy->check_req[36], mysqluser, userlen);
								curproxy->check_req[36 + userlen + 1 + 1]     = 1;
								curproxy->check_req[36 + userlen + 1 + 1 + 4] = 1;
								cur_arg += 3;
							} else {
								ha_alert("parsing [%s:%d] : keyword '%s' only supports option 'post-41'.\n", file, linenum, args[cur_arg+2]);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
						} else {
							packetlen = userlen + 7;
							reqlen    = packetlen + 9;

							free(curproxy->check_req);
							curproxy->check_req = calloc(1, reqlen);
							curproxy->check_len = reqlen;

							snprintf(curproxy->check_req, 4, "%c%c%c",
								((unsigned char) packetlen & 0xff),
								((unsigned char) (packetlen >> 8) & 0xff),
								((unsigned char) (packetlen >> 16) & 0xff));

							curproxy->check_req[3] = 1;
							curproxy->check_req[5] = 0x80;
							curproxy->check_req[8] = 1;
							memcpy(&curproxy->check_req[9], mysqluser, userlen);
							curproxy->check_req[9 + userlen + 1 + 1]     = 1;
							curproxy->check_req[9 + userlen + 1 + 1 + 4] = 1;
							cur_arg += 2;
						}
					} else {
						/* unknown suboption - catchall */
						ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user'.\n",
							 file, linenum, args[0], args[1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				} /* end while loop */
			}
		}
		else if (!strcmp(args[1], "ldap-check")) {
			/* use LDAP request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_LDAP_CHK;

			curproxy->check_req = malloc(sizeof(DEF_LDAP_CHECK_REQ) - 1);
			memcpy(curproxy->check_req, DEF_LDAP_CHECK_REQ, sizeof(DEF_LDAP_CHECK_REQ) - 1);
			curproxy->check_len = sizeof(DEF_LDAP_CHECK_REQ) - 1;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "spop-check")) {
			if (curproxy == &defproxy) {
				ha_alert("parsing [%s:%d] : '%s %s' not allowed in 'defaults' section.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (curproxy->cap & PR_CAP_FE) {
				ha_alert("parsing [%s:%d] : '%s %s' not allowed in 'frontend' and 'listen' sections.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* use SPOE request to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_SPOP_CHK;

			if (spoe_prepare_healthcheck_request(&curproxy->check_req, &curproxy->check_len)) {
				ha_alert("parsing [%s:%d] : failed to prepare SPOP healthcheck request.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "tcp-check")) {
			/* use raw TCPCHK send/expect to check servers' health */
			if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[1], NULL))
				err_code |= ERR_WARN;

			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_TCPCHK_CHK;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "external-check")) {
			/* excute an external command to check servers' health */
			free(curproxy->check_req);
			curproxy->check_req = NULL;
			curproxy->options2 &= ~PR_O2_CHK_ANY;
			curproxy->options2 |= PR_O2_EXT_CHK;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (!strcmp(args[1], "forwardfor")) {
			int cur_arg;

			/* insert x-forwarded-for field, but not for the IP address listed as an except.
			 * set default options (ie: bitfield, header name, etc)
			 */

			curproxy->options |= PR_O_FWDFOR | PR_O_FF_ALWAYS;

			free(curproxy->fwdfor_hdr_name);
			curproxy->fwdfor_hdr_name = strdup(DEF_XFORWARDFOR_HDR);
			curproxy->fwdfor_hdr_len  = strlen(DEF_XFORWARDFOR_HDR);

			/* loop to go through arguments - start at 2, since 0+1 = "option" "forwardfor" */
			cur_arg = 2;
			while (*(args[cur_arg])) {
				if (!strcmp(args[cur_arg], "except")) {
					/* suboption except - needs additional argument for it */
					if (!*(args[cur_arg+1]) || !str2net(args[cur_arg+1], 1, &curproxy->except_net, &curproxy->except_mask)) {
						ha_alert("parsing [%s:%d] : '%s %s %s' expects <address>[/mask] as argument.\n",
							 file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					/* flush useless bits */
					curproxy->except_net.s_addr &= curproxy->except_mask.s_addr;
					cur_arg += 2;
				} else if (!strcmp(args[cur_arg], "header")) {
					/* suboption header - needs additional argument for it */
					if (*(args[cur_arg+1]) == 0) {
						ha_alert("parsing [%s:%d] : '%s %s %s' expects <header_name> as argument.\n",
							 file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					free(curproxy->fwdfor_hdr_name);
					curproxy->fwdfor_hdr_name = strdup(args[cur_arg+1]);
					curproxy->fwdfor_hdr_len  = strlen(curproxy->fwdfor_hdr_name);
					cur_arg += 2;
				} else if (!strcmp(args[cur_arg], "if-none")) {
					curproxy->options &= ~PR_O_FF_ALWAYS;
					cur_arg += 1;
				} else {
					/* unknown suboption - catchall */
					ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'except', 'header' and 'if-none'.\n",
						 file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			} /* end while loop */
		}
		else if (!strcmp(args[1], "originalto")) {
			int cur_arg;

			/* insert x-original-to field, but not for the IP address listed as an except.
			 * set default options (ie: bitfield, header name, etc)
			 */

			curproxy->options |= PR_O_ORGTO;

			free(curproxy->orgto_hdr_name);
			curproxy->orgto_hdr_name = strdup(DEF_XORIGINALTO_HDR);
			curproxy->orgto_hdr_len  = strlen(DEF_XORIGINALTO_HDR);

			/* loop to go through arguments - start at 2, since 0+1 = "option" "originalto" */
			cur_arg = 2;
			while (*(args[cur_arg])) {
				if (!strcmp(args[cur_arg], "except")) {
					/* suboption except - needs additional argument for it */
					if (!*(args[cur_arg+1]) || !str2net(args[cur_arg+1], 1, &curproxy->except_to, &curproxy->except_mask_to)) {
						ha_alert("parsing [%s:%d] : '%s %s %s' expects <address>[/mask] as argument.\n",
							 file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					/* flush useless bits */
					curproxy->except_to.s_addr &= curproxy->except_mask_to.s_addr;
					cur_arg += 2;
				} else if (!strcmp(args[cur_arg], "header")) {
					/* suboption header - needs additional argument for it */
					if (*(args[cur_arg+1]) == 0) {
						ha_alert("parsing [%s:%d] : '%s %s %s' expects <header_name> as argument.\n",
							 file, linenum, args[0], args[1], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					free(curproxy->orgto_hdr_name);
					curproxy->orgto_hdr_name = strdup(args[cur_arg+1]);
					curproxy->orgto_hdr_len  = strlen(curproxy->orgto_hdr_name);
					cur_arg += 2;
				} else {
					/* unknown suboption - catchall */
					ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'except' and 'header'.\n",
						 file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			} /* end while loop */
		}
		else {
			ha_alert("parsing [%s:%d] : unknown option '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		goto out;
	}
	else if (!strcmp(args[0], "default_backend")) {
		if (warnifnotcap(curproxy, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a backend name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->defbe.name);
		curproxy->defbe.name = strdup(args[1]);

		if (alertif_too_many_args_idx(1, 0, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "redispatch") || !strcmp(args[0], "redisp")) {
		ha_alert("parsing [%s:%d] : keyword '%s' directive is not supported anymore since HAProxy 2.1. Use 'option redispatch'.\n", file, linenum, args[0]);

		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "http-reuse")) {
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
	else if (!strcmp(args[0], "http-check")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "disable-on-404") == 0) {
			/* enable a graceful server shutdown on an HTTP 404 response */
			curproxy->options |= PR_O_DISABLE404;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "send-state") == 0) {
			/* enable emission of the apparent state of a server in HTTP checks */
			curproxy->options2 |= PR_O2_CHK_SNDST;
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "expect") == 0) {
			const char *ptr_arg;
			int cur_arg;

			if (curproxy->options2 & PR_O2_EXP_TYPE) {
				ha_alert("parsing [%s:%d] : '%s %s' already specified.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			cur_arg = 2;
			/* consider exclamation marks, sole or at the beginning of a word */
			while (*(ptr_arg = args[cur_arg])) {
				while (*ptr_arg == '!') {
					curproxy->options2 ^= PR_O2_EXP_INV;
					ptr_arg++;
				}
				if (*ptr_arg)
					break;
				cur_arg++;
			}
			/* now ptr_arg points to the beginning of a word past any possible
			 * exclamation mark, and cur_arg is the argument which holds this word.
			 */
			if (strcmp(ptr_arg, "status") == 0) {
				if (!*(args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <string> as an argument.\n",
						 file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_STS;
				free(curproxy->expect_str);
				curproxy->expect_str = strdup(args[cur_arg + 1]);
			}
			else if (strcmp(ptr_arg, "string") == 0) {
				if (!*(args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <string> as an argument.\n",
						 file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_STR;
				free(curproxy->expect_str);
				curproxy->expect_str = strdup(args[cur_arg + 1]);
			}
			else if (strcmp(ptr_arg, "rstatus") == 0) {
				if (!*(args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <regex> as an argument.\n",
						 file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_RSTS;
				free(curproxy->expect_str);
				regex_free(curproxy->expect_regex);
				curproxy->expect_str = strdup(args[cur_arg + 1]);
				error = NULL;
				if (!(curproxy->expect_regex = regex_comp(args[cur_arg + 1], 1, 1, &error))) {
					ha_alert("parsing [%s:%d] : '%s %s %s' : regular expression '%s': %s.\n",
						 file, linenum, args[0], args[1], ptr_arg, args[cur_arg + 1], error);
					free(error);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			else if (strcmp(ptr_arg, "rstring") == 0) {
				if (!*(args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <regex> as an argument.\n",
						 file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				curproxy->options2 |= PR_O2_EXP_RSTR;
				free(curproxy->expect_str);
				regex_free(curproxy->expect_regex);
				curproxy->expect_str = strdup(args[cur_arg + 1]);
				error = NULL;
				if (!(curproxy->expect_regex = regex_comp(args[cur_arg + 1], 1, 1, &error))) {
					ha_alert("parsing [%s:%d] : '%s %s %s' : regular expression '%s': %s.\n",
						 file, linenum, args[0], args[1], ptr_arg, args[cur_arg + 1], error);
					free(error);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			else {
				ha_alert("parsing [%s:%d] : '%s %s' only supports [!] 'status', 'string', 'rstatus', 'rstring', found '%s'.\n",
					 file, linenum, args[0], args[1], ptr_arg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' only supports 'disable-on-404', 'send-state', 'expect'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tcp-check")) {
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (strcmp(args[1], "comment") == 0) {
			int cur_arg;
			struct tcpcheck_rule *tcpcheck;

			cur_arg = 1;
			tcpcheck = calloc(1, sizeof(*tcpcheck));
			tcpcheck->action = TCPCHK_ACT_COMMENT;

			if (!*args[cur_arg + 1]) {
				ha_alert("parsing [%s:%d] : '%s' expects a comment string.\n",
					 file, linenum, args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			tcpcheck->comment = strdup(args[cur_arg + 1]);

			LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			if (alertif_too_many_args_idx(1, 1, file, linenum, args, &err_code))
				goto out;
		}
		else if (strcmp(args[1], "connect") == 0) {
			const char *ptr_arg;
			int cur_arg;
			struct tcpcheck_rule *tcpcheck;

			/* check if first rule is also a 'connect' action */
			tcpcheck = LIST_NEXT(&curproxy->tcpcheck_rules, struct tcpcheck_rule *, list);
			while (&tcpcheck->list != &curproxy->tcpcheck_rules &&
			       tcpcheck->action == TCPCHK_ACT_COMMENT) {
				tcpcheck = LIST_NEXT(&tcpcheck->list, struct tcpcheck_rule *, list);
			}

			if (&tcpcheck->list != &curproxy->tcpcheck_rules
			    && tcpcheck->action != TCPCHK_ACT_CONNECT) {
				ha_alert("parsing [%s:%d] : first step MUST also be a 'connect' when there is a 'connect' step in the tcp-check ruleset.\n",
					 file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			cur_arg = 2;
			tcpcheck = calloc(1, sizeof(*tcpcheck));
			tcpcheck->action = TCPCHK_ACT_CONNECT;

			/* parsing each parameters to fill up the rule */
			while (*(ptr_arg = args[cur_arg])) {
				/* tcp port */
				if (strcmp(args[cur_arg], "port") == 0) {
					if ( (atol(args[cur_arg + 1]) > 65535) ||
							(atol(args[cur_arg + 1]) < 1) ){
						ha_alert("parsing [%s:%d] : '%s %s %s' expects a valid TCP port (from range 1 to 65535), got %s.\n",
							 file, linenum, args[0], args[1], "port", args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->port = atol(args[cur_arg + 1]);
					cur_arg += 2;
				}
				/* send proxy protocol */
				else if (strcmp(args[cur_arg], "send-proxy") == 0) {
					tcpcheck->conn_opts |= TCPCHK_OPT_SEND_PROXY;
					cur_arg++;
				}
#ifdef USE_OPENSSL
				else if (strcmp(args[cur_arg], "ssl") == 0) {
					curproxy->options |= PR_O_TCPCHK_SSL;
					tcpcheck->conn_opts |= TCPCHK_OPT_SSL;
					cur_arg++;
				}
#endif /* USE_OPENSSL */
				/* comment for this tcpcheck line */
				else if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						ha_alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							 file, linenum, args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
					cur_arg += 2;
				}
				else {
#ifdef USE_OPENSSL
					ha_alert("parsing [%s:%d] : '%s %s' expects 'comment', 'port', 'send-proxy' or 'ssl' but got '%s' as argument.\n",
#else /* USE_OPENSSL */
					ha_alert("parsing [%s:%d] : '%s %s' expects 'comment', 'port', 'send-proxy' or but got '%s' as argument.\n",
#endif /* USE_OPENSSL */
						 file, linenum, args[0], args[1], args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

			}

			LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
		}
		else if (strcmp(args[1], "send") == 0) {
			if (! *(args[2]) ) {
				/* SEND string expected */
				ha_alert("parsing [%s:%d] : '%s %s %s' expects <STRING> as argument.\n",
					 file, linenum, args[0], args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else {
				struct tcpcheck_rule *tcpcheck;

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_SEND;
				tcpcheck->string_len = strlen(args[2]);
				tcpcheck->string = strdup(args[2]);
				tcpcheck->expect_regex = NULL;

				/* comment for this tcpcheck line */
				if (strcmp(args[3], "comment") == 0) {
					if (!*args[4]) {
						ha_alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							 file, linenum, args[3]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[4]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
		}
		else if (strcmp(args[1], "send-binary") == 0) {
			if (! *(args[2]) ) {
				/* SEND binary string expected */
				ha_alert("parsing [%s:%d] : '%s %s %s' expects <BINARY STRING> as argument.\n",
					 file, linenum, args[0], args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			} else {
				struct tcpcheck_rule *tcpcheck;
				char *err = NULL;

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_SEND;
				if (parse_binary(args[2], &tcpcheck->string, &tcpcheck->string_len, &err) == 0) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <BINARY STRING> as argument, but %s\n",
						 file, linenum, args[0], args[1], args[2], err);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tcpcheck->expect_regex = NULL;

				/* comment for this tcpcheck line */
				if (strcmp(args[3], "comment") == 0) {
					if (!*args[4]) {
						ha_alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							 file, linenum, args[3]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[4]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
		}
		else if (strcmp(args[1], "expect") == 0) {
			const char *ptr_arg;
			int cur_arg;
			int inverse = 0;

			if (curproxy->options2 & PR_O2_EXP_TYPE) {
				ha_alert("parsing [%s:%d] : '%s %s' already specified.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			cur_arg = 2;
			/* consider exclamation marks, sole or at the beginning of a word */
			while (*(ptr_arg = args[cur_arg])) {
				while (*ptr_arg == '!') {
					inverse = !inverse;
					ptr_arg++;
				}
				if (*ptr_arg)
					break;
				cur_arg++;
			}
			/* now ptr_arg points to the beginning of a word past any possible
			 * exclamation mark, and cur_arg is the argument which holds this word.
			 */
			if (strcmp(ptr_arg, "binary") == 0) {
				struct tcpcheck_rule *tcpcheck;
				char *err = NULL;

				if (!*(args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <binary string> as an argument.\n",
						 file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_EXPECT;
				if (parse_binary(args[cur_arg + 1], &tcpcheck->string, &tcpcheck->string_len, &err) == 0) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <BINARY STRING> as argument, but %s\n",
						 file, linenum, args[0], args[1], args[2], err);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tcpcheck->expect_regex = NULL;
				tcpcheck->inverse = inverse;

				/* tcpcheck comment */
				cur_arg += 2;
				if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						ha_alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							 file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
			else if (strcmp(ptr_arg, "string") == 0) {
				struct tcpcheck_rule *tcpcheck;

				if (!*(args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <string> as an argument.\n",
						 file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_EXPECT;
				tcpcheck->string_len = strlen(args[cur_arg + 1]);
				tcpcheck->string = strdup(args[cur_arg + 1]);
				tcpcheck->expect_regex = NULL;
				tcpcheck->inverse = inverse;

				/* tcpcheck comment */
				cur_arg += 2;
				if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						ha_alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							 file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
			else if (strcmp(ptr_arg, "rstring") == 0) {
				struct tcpcheck_rule *tcpcheck;

				if (!*(args[cur_arg + 1])) {
					ha_alert("parsing [%s:%d] : '%s %s %s' expects <regex> as an argument.\n",
						 file, linenum, args[0], args[1], ptr_arg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				tcpcheck = calloc(1, sizeof(*tcpcheck));

				tcpcheck->action = TCPCHK_ACT_EXPECT;
				tcpcheck->string_len = 0;
				tcpcheck->string = NULL;
				error = NULL;
				if (!(tcpcheck->expect_regex = regex_comp(args[cur_arg + 1], 1, 1, &error))) {
					ha_alert("parsing [%s:%d] : '%s %s %s' : regular expression '%s': %s.\n",
						 file, linenum, args[0], args[1], ptr_arg, args[cur_arg + 1], error);
					free(error);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tcpcheck->inverse = inverse;

				/* tcpcheck comment */
				cur_arg += 2;
				if (strcmp(args[cur_arg], "comment") == 0) {
					if (!*args[cur_arg + 1]) {
						ha_alert("parsing [%s:%d] : '%s' expects a comment string.\n",
							 file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					tcpcheck->comment = strdup(args[cur_arg + 1]);
				}

				LIST_ADDQ(&curproxy->tcpcheck_rules, &tcpcheck->list);
			}
			else {
				ha_alert("parsing [%s:%d] : '%s %s' only supports [!] 'binary', 'string', 'rstring', found '%s'.\n",
					 file, linenum, args[0], args[1], ptr_arg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' only supports 'comment', 'connect', 'send' or 'expect'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "monitor")) {
		if (curproxy == &defproxy) {
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
			LIST_ADDQ(&curproxy->mon_fail_cond, &cond->list);
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' only supports 'fail'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
#ifdef USE_TPROXY
	else if (!strcmp(args[0], "transparent")) {
		/* enable transparent proxy connections */
		curproxy->options |= PR_O_TRANSP;
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
	}
#endif
	else if (!strcmp(args[0], "maxconn")) {  /* maxconn */
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
	else if (!strcmp(args[0], "backlog")) {  /* backlog */
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
	else if (!strcmp(args[0], "fullconn")) {  /* fullconn */
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
	else if (!strcmp(args[0], "grace")) {  /* grace time (ms) */
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a time in milliseconds.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		err = parse_time_err(args[1], &val, TIME_UNIT_MS);
		if (err == PARSE_TIME_OVER) {
			ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to grace time, maximum value is 2147483647 ms (~24.8 days).\n",
			         file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (err == PARSE_TIME_UNDER) {
			ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to grace time, minimum non-null value is 1 ms.\n",
			         file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (err) {
			ha_alert("parsing [%s:%d] : unexpected character '%c' in grace time.\n",
				 file, linenum, *err);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curproxy->grace = val;
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (!strcmp(args[0], "dispatch")) {  /* dispatch address */
		struct sockaddr_storage *sk;
		int port1, port2;
		struct protocol *proto;

		if (curproxy == &defproxy) {
			ha_alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		sk = str2sa_range(args[1], NULL, &port1, &port2, &errmsg, NULL, NULL, 1);
		if (!sk) {
			ha_alert("parsing [%s:%d] : '%s' : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		proto = protocol_by_family(sk->ss_family);
		if (!proto || !proto->connect) {
			ha_alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (port1 != port2) {
			ha_alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!port1) {
			ha_alert("parsing [%s:%d] : '%s' : missing port number in '%s', <addr:port> expected.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		curproxy->dispatch_addr = *sk;
		curproxy->options |= PR_O_DISPATCH;
	}
	else if (!strcmp(args[0], "balance")) {  /* set balancing with optional algorithm */
		if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (backend_parse_balance((const char **)args + 1, &errmsg, curproxy) < 0) {
			ha_alert("parsing [%s:%d] : %s %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "hash-type")) { /* set hashing method */
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
			if (!strcmp(args[2], "sdbm")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_SDBM;
			}
			else if (!strcmp(args[2], "djb2")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_DJB2;
			}
			else if (!strcmp(args[2], "wt6")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_WT6;
			}
			else if (!strcmp(args[2], "crc32")) {
				curproxy->lbprm.algo |= BE_LB_HFCN_CRC32;
			}
			else {
				ha_alert("parsing [%s:%d] : '%s' only supports 'sdbm', 'djb2', 'crc32', or 'wt6' hash functions.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* set the hash modifier */
			if (!strcmp(args[3], "avalanche")) {
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

		free(curproxy->conf.uif_file);
		curproxy->conf.uif_file = strdup(curproxy->conf.args.file);
		curproxy->conf.uif_line = curproxy->conf.args.line;
	}

	else if (strcmp(args[0], "unique-id-header") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : %s expects an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		free(curproxy->header_unique_id);
		curproxy->header_unique_id = strdup(args[1]);
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
		if (curproxy->conf.logformat_string && curproxy == &defproxy) {
			char *oldlogformat = "log-format";

			if (curproxy->conf.logformat_string == default_http_log_format)
				oldlogformat = "option httplog";
			else if (curproxy->conf.logformat_string == default_tcp_log_format)
				oldlogformat = "option tcplog";
			else if (curproxy->conf.logformat_string == clf_http_log_format)
				oldlogformat = "option httplog clf";
			ha_warning("parsing [%s:%d]: 'log-format' overrides previous '%s' in 'defaults' section.\n",
				   file, linenum, oldlogformat);
		}
		if (curproxy->conf.logformat_string != default_http_log_format &&
		    curproxy->conf.logformat_string != default_tcp_log_format &&
		    curproxy->conf.logformat_string != clf_http_log_format)
			free(curproxy->conf.logformat_string);
		curproxy->conf.logformat_string = strdup(args[1]);

		free(curproxy->conf.lfs_file);
		curproxy->conf.lfs_file = strdup(curproxy->conf.args.file);
		curproxy->conf.lfs_line = curproxy->conf.args.line;

		/* get a chance to improve log-format error reporting by
		 * reporting the correct line-number when possible.
		 */
		if (curproxy != &defproxy && !(curproxy->cap & PR_CAP_FE)) {
			ha_warning("parsing [%s:%d] : backend '%s' : 'log-format' directive is ignored in backends.\n",
				   file, linenum, curproxy->id);
			err_code |= ERR_WARN;
		}
	}
	else if (!strcmp(args[0], "log-format-sd")) {
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

		free(curproxy->conf.lfsd_file);
		curproxy->conf.lfsd_file = strdup(curproxy->conf.args.file);
		curproxy->conf.lfsd_line = curproxy->conf.args.line;

		/* get a chance to improve log-format-sd error reporting by
		 * reporting the correct line-number when possible.
		 */
		if (curproxy != &defproxy && !(curproxy->cap & PR_CAP_FE)) {
			ha_warning("parsing [%s:%d] : backend '%s' : 'log-format-sd' directive is ignored in backends.\n",
				   file, linenum, curproxy->id);
			err_code |= ERR_WARN;
		}
	}
	else if (!strcmp(args[0], "log-tag")) {  /* tag to report to syslog */
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a tag for use in syslog.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_destroy(&curproxy->log_tag);
		chunk_initstr(&curproxy->log_tag, strdup(args[1]));
	}
	else if (!strcmp(args[0], "log")) { /* "no log" or "log ..." */
		if (!parse_logsrv(args, &curproxy->logsrvs, (kwm == KWM_NO), &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "source")) {  /* address to which we bind when connecting */
		int cur_arg;
		int port1, port2;
		struct sockaddr_storage *sk;
		struct protocol *proto;

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
		free(curproxy->conn_src.iface_name);
		curproxy->conn_src.iface_name = NULL;
		curproxy->conn_src.iface_len = 0;

		sk = str2sa_range(args[1], NULL, &port1, &port2, &errmsg, NULL, NULL, 1);
		if (!sk) {
			ha_alert("parsing [%s:%d] : '%s %s' : %s\n",
				 file, linenum, args[0], args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		proto = protocol_by_family(sk->ss_family);
		if (!proto || !proto->connect) {
			ha_alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (port1 != port2) {
			ha_alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curproxy->conn_src.source_addr = *sk;
		curproxy->conn_src.opts |= CO_SRC_BIND;

		cur_arg = 2;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside */
#if defined(CONFIG_HAP_TRANSPARENT)
				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', or 'clientip' as argument.\n",
						 file, linenum, "usesrc");
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (!strcmp(args[cur_arg + 1], "client")) {
					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_CLI;
				} else if (!strcmp(args[cur_arg + 1], "clientip")) {
					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_CIP;
				} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
					char *name, *end;

					name = args[cur_arg+1] + 7;
					while (isspace(*name))
						name++;

					end = name;
					while (*end && !isspace(*end) && *end != ',' && *end != ')')
						end++;

					curproxy->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
					curproxy->conn_src.opts |= CO_SRC_TPROXY_DYN;
					curproxy->conn_src.bind_hdr_name = calloc(1, end - name + 1);
					curproxy->conn_src.bind_hdr_len = end - name;
					memcpy(curproxy->conn_src.bind_hdr_name, name, end - name);
					curproxy->conn_src.bind_hdr_name[end-name] = '\0';
					curproxy->conn_src.bind_hdr_occ = -1;

					/* now look for an occurrence number */
					while (isspace(*end))
						end++;
					if (*end == ',') {
						end++;
						name = end;
						if (*end == '-')
							end++;
						while (isdigit((int)*end))
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

					sk = str2sa_range(args[cur_arg + 1], NULL, &port1, &port2, &errmsg, NULL, NULL, 1);
					if (!sk) {
						ha_alert("parsing [%s:%d] : '%s %s' : %s\n",
							 file, linenum, args[cur_arg], args[cur_arg+1], errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					proto = protocol_by_family(sk->ss_family);
					if (!proto || !proto->connect) {
						ha_alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
							 file, linenum, args[cur_arg], args[cur_arg+1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					if (port1 != port2) {
						ha_alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
							 file, linenum, args[cur_arg], args[cur_arg + 1]);
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

			if (!strcmp(args[cur_arg], "interface")) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
				if (!*args[cur_arg + 1]) {
					ha_alert("parsing [%s:%d] : '%s' : missing interface name.\n",
						 file, linenum, args[0]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				free(curproxy->conn_src.iface_name);
				curproxy->conn_src.iface_name = strdup(args[cur_arg + 1]);
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
	else if (!strcmp(args[0], "usesrc")) {  /* address to use outside: needs "source" first */
		ha_alert("parsing [%s:%d] : '%s' only allowed after a '%s' statement.\n",
			 file, linenum, "usesrc", "source");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "cliexp") || !strcmp(args[0], "reqrep")) {  /* replace request header from a regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request replace-uri' and 'http-request replace-header' instead.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqdel")) {  /* delete request header from a regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request del-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqdeny")) {  /* deny a request if a header matches this regex */
		ha_alert("parsing [%s:%d] : The '%s' not supported anymore since HAProxy 2.1. "
			 "Use 'http-request deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqpass")) {  /* pass this header without allowing or denying the request */
		ha_alert("parsing [%s:%d] : The '%s' not supported anymore since HAProxy 2.1.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqallow")) {  /* allow a request if a header matches this regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request allow' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqtarpit")) {  /* tarpit a request if a header matches this regex */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request tarpit' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqirep")) {  /* replace request header from a regex, ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request replace-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqidel")) {  /* delete request header from a regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request del-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqideny")) {  /* deny a request if a header matches this regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqipass")) {  /* pass this header without allowing or denying the request */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqiallow")) {  /* allow a request if a header matches this regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request allow' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqitarpit")) {  /* tarpit a request if a header matches this regex ignoring case */
		ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			 "Use 'http-request tarpit' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "reqadd")) {  /* add request header */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-request add-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "srvexp") || !strcmp(args[0], "rsprep")) {  /* replace response header from a regex */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response replace-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "rspdel")) {  /* delete response header from a regex */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response del-header' .\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "rspdeny")) {  /* block response header from a regex */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "rspirep")) {  /* replace response header from a regex ignoring case */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore sionce HAProxy 2.1. "
			"Use 'http-response replace-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "rspidel")) {  /* delete response header from a regex ignoring case */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response del-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "rspideny")) {  /* block response header from a regex ignoring case */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response deny' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "rspadd")) {  /* add response header */
	       ha_alert("parsing [%s:%d] : The '%s' directive is not supported anymore since HAProxy 2.1. "
			"Use 'http-response add-header' instead.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (!strcmp(args[0], "errorloc") ||
		 !strcmp(args[0], "errorloc302") ||
		 !strcmp(args[0], "errorloc303")) { /* error location */
		int errnum, errlen;
		char *err;

		if (warnifnotcap(curproxy, PR_CAP_FE | PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[2]) == 0) {
			ha_alert("parsing [%s:%d] : <%s> expects <status_code> and <url> as arguments.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		errnum = atol(args[1]);
		if (!strcmp(args[0], "errorloc303")) {
			errlen = strlen(HTTP_303) + strlen(args[2]) + 5;
			err = malloc(errlen);
			errlen = snprintf(err, errlen, "%s%s\r\n\r\n", HTTP_303, args[2]);
		} else {
			errlen = strlen(HTTP_302) + strlen(args[2]) + 5;
			err = malloc(errlen);
			errlen = snprintf(err, errlen, "%s%s\r\n\r\n", HTTP_302, args[2]);
		}

		for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
			if (http_err_codes[rc] == errnum) {
				struct buffer chk;

				if (!http_str_to_htx(&chk, ist2(err, errlen))) {
					ha_alert("parsing [%s:%d] : unable to convert message in HTX for HTTP return code %d.\n",
						 file, linenum, http_err_codes[rc]);
					err_code |= ERR_ALERT | ERR_FATAL;
					free(err);
					goto out;
				}
				chunk_destroy(&curproxy->errmsg[rc]);
				curproxy->errmsg[rc] = chk;
				break;
			}
		}

		if (rc >= HTTP_ERR_SIZE) {
			ha_warning("parsing [%s:%d] : status code %d not handled by '%s', error relocation will be ignored.\n",
				   file, linenum, errnum, args[0]);
			free(err);
		}
	}
	else if (!strcmp(args[0], "errorfile")) { /* error message from a file */
		int errnum, errlen, fd;
		char *err;
		struct stat stat;

		if (warnifnotcap(curproxy, PR_CAP_FE | PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[2]) == 0) {
			ha_alert("parsing [%s:%d] : <%s> expects <status_code> and <file> as arguments.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		fd = open(args[2], O_RDONLY);
		if ((fd < 0) || (fstat(fd, &stat) < 0)) {
			ha_alert("parsing [%s:%d] : error opening file <%s> for custom error message <%s>.\n",
				 file, linenum, args[2], args[1]);
			if (fd >= 0)
				close(fd);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (stat.st_size <= global.tune.bufsize) {
			errlen = stat.st_size;
		} else {
			ha_warning("parsing [%s:%d] : custom error message file <%s> larger than %d bytes. Truncating.\n",
				   file, linenum, args[2], global.tune.bufsize);
			err_code |= ERR_WARN;
			errlen = global.tune.bufsize;
		}

		err = malloc(errlen); /* malloc() must succeed during parsing */
		errnum = read(fd, err, errlen);
		if (errnum != errlen) {
			ha_alert("parsing [%s:%d] : error reading file <%s> for custom error message <%s>.\n",
				 file, linenum, args[2], args[1]);
			close(fd);
			free(err);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		close(fd);

		errnum = atol(args[1]);
		for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
			if (http_err_codes[rc] == errnum) {
				struct buffer chk;

				if (!http_str_to_htx(&chk, ist2(err, errlen))) {
					ha_alert("parsing [%s:%d] : unable to convert message in HTX for HTTP return code %d.\n",
						 file, linenum, http_err_codes[rc]);
					err_code |= ERR_ALERT | ERR_FATAL;
					free(err);
					goto out;
				}
				chunk_destroy(&curproxy->errmsg[rc]);
				curproxy->errmsg[rc] = chk;
				break;
			}
		}

		if (rc >= HTTP_ERR_SIZE) {
			ha_warning("parsing [%s:%d] : status code %d not handled by '%s', error customization will be ignored.\n",
				   file, linenum, errnum, args[0]);
			err_code |= ERR_WARN;
			free(err);
		}
	}
	else {
		struct cfg_kw_list *kwl;
		int index;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_LISTEN)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
					/* prepare error message just in case */
					rc = kwl->kw[index].parse(args, CFG_LISTEN, curproxy, &defproxy, file, linenum, &errmsg);
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

		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
 out:
	free(errmsg);
	return err_code;
}
