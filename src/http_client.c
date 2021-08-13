/*
 * HTTP Client
 *
 * Copyright (C) 2021 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This file implements an HTTP Client API.
 *
 */
#include <haproxy/connection-t.h>
#include <haproxy/server-t.h>

#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/tools.h>

#include <string.h>


static struct proxy *httpclient_proxy;
static struct server *httpclient_srv_raw;
static struct server *httpclient_srv_ssl;

/*
 * Initialize the proxy for the HTTP client with 2 servers, one for raw HTTP,
 * the other for HTTPS.
 */

static int httpclient_init()
{
	int err_code = 0;
	char *errmsg = NULL;

	httpclient_proxy = alloc_new_proxy("<HTTPCLIENT>", PR_CAP_LISTEN|PR_CAP_INT, &errmsg);
	if (!httpclient_proxy) {
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	httpclient_proxy->options2 |= PR_O2_INDEPSTR;
	httpclient_proxy->mode = PR_MODE_HTTP;
	httpclient_proxy->maxconn = 0;
	httpclient_proxy->accept = NULL;
	httpclient_proxy->timeout.client = TICK_ETERNITY;
	/* The HTTP Client use the "option httplog" with the global log server */
	httpclient_proxy->conf.logformat_string = default_http_log_format;
	httpclient_proxy->http_needed = 1;

	/* clear HTTP server */
	httpclient_srv_raw = new_server(httpclient_proxy);
	if (!httpclient_srv_raw) {
		err_code |= ERR_ALERT | ERR_FATAL;
		memprintf(&errmsg, "out of memory.");
		goto err;
	}

	httpclient_srv_raw->iweight = 0;
	httpclient_srv_raw->uweight = 0;
	httpclient_srv_raw->xprt = xprt_get(XPRT_RAW);
	httpclient_srv_raw->id = strdup("<HTTPCLIENT>");
	if (!httpclient_srv_raw->id)
		goto err;

	/* SSL HTTP server */
	httpclient_srv_ssl = new_server(httpclient_proxy);
	if (!httpclient_srv_ssl) {
		memprintf(&errmsg, "out of memory.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}
	httpclient_srv_ssl->iweight = 0;
	httpclient_srv_ssl->uweight = 0;
	httpclient_srv_ssl->xprt = xprt_get(XPRT_SSL);
	httpclient_srv_ssl->use_ssl = 1;
	httpclient_srv_ssl->id = strdup("<HTTPCLIENT>");
	if (!httpclient_srv_ssl->id)
		goto err;

	/* add the proxy in the proxy list only if everything successed */
	httpclient_proxy->next = proxies_list;
	proxies_list = httpclient_proxy;

	return 0;

err:
	ha_alert("httpclient: cannot initialize.\n");
	free(errmsg);
	free_server(httpclient_srv_raw);
	free_server(httpclient_srv_ssl);
	free_proxy(httpclient_proxy);
	return err_code;
}

/*
 *  Post config parser callback, this is used to copy the log line from the
 *  global section and put it in the server proxy
 */
static int httpclient_cfg_postparser()
{
	struct logsrv *logsrv;
	struct proxy *curproxy = httpclient_proxy;

	/* copy logs from "global" log list */
	list_for_each_entry(logsrv, &global.logsrvs, list) {
		struct logsrv *node = malloc(sizeof(*node));

		if (!node) {
			ha_alert("httpclient: cannot allocate memory.\n");
			goto err;
		}

		memcpy(node, logsrv, sizeof(*node));
		LIST_INIT(&node->list);
		LIST_APPEND(&curproxy->logsrvs, &node->list);
	}
	if (curproxy->conf.logformat_string) {
		char *err = NULL;

		curproxy->conf.args.ctx = ARGC_LOG;
		if (!parse_logformat_string(curproxy->conf.logformat_string, curproxy, &curproxy->logformat,
					    LOG_OPT_MANDATORY|LOG_OPT_MERGE_SPACES,
					    SMP_VAL_FE_LOG_END, &err)) {
			ha_alert("httpclient: failed to parse log-format : %s.\n", err);
			free(err);
			goto err;
		}
		curproxy->conf.args.file = NULL;
		curproxy->conf.args.line = 0;
	}
	return 0;
err:
	return 1;
}

static void httpclient_deinit()
{
	free_server(httpclient_srv_raw);
	free_server(httpclient_srv_ssl);
	free_proxy(httpclient_proxy);

}

/* initialize the proxy and servers for the HTTP client */

INITCALL0(STG_REGISTER, httpclient_init);
REGISTER_CONFIG_POSTPARSER("httpclient", httpclient_cfg_postparser);
REGISTER_POST_DEINIT(httpclient_deinit);
