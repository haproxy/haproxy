/*
 * Functions about FCGI applications and filters.
 *
 * Copyright (C) 2019 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/acl.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/errors.h>
#include <haproxy/fcgi-app.h>
#include <haproxy/filters.h>
#include <haproxy/global.h>
#include <haproxy/http_fetch.h>
#include <haproxy/http_htx.h>
#include <haproxy/log.h>
#include <haproxy/proxy-t.h>
#include <haproxy/regex.h>
#include <haproxy/sample.h>
#include <haproxy/server-t.h>
#include <haproxy/session.h>
#include <haproxy/sink.h>
#include <haproxy/tools.h>


/* Global list of all FCGI applications */
static struct fcgi_app *fcgi_apps = NULL;

struct flt_ops fcgi_flt_ops;
const char *fcgi_flt_id = "FCGI filter";

DECLARE_STATIC_POOL(pool_head_fcgi_flt_ctx, "fcgi_flt_ctx", sizeof(struct fcgi_flt_ctx));
DECLARE_STATIC_POOL(pool_head_fcgi_param_rule, "fcgi_param_rule", sizeof(struct fcgi_param_rule));
DECLARE_STATIC_POOL(pool_head_fcgi_hdr_rule, "fcgi_hdr_rule", sizeof(struct fcgi_hdr_rule));

/**************************************************************************/
/***************************** Uitls **************************************/
/**************************************************************************/
/* Makes a fcgi parameter name (prefixed by ':fcgi-') with <name> (in
 * lowercase). All non alphanumeric character are replaced by an underscore
 * ('_'). The result is copied into <dst>. the corrsponding ist is returned.
 */
static struct ist fcgi_param_name(char *dst, const struct ist name)
{
	size_t ofs1, ofs2;

	memcpy(dst, ":fcgi-", 6);
	ofs1 = 6;
	for (ofs2 = 0; ofs2 < name.len; ofs2++) {
		if (isalnum((unsigned char)name.ptr[ofs2]))
			dst[ofs1++] = ist_lc[(unsigned char)name.ptr[ofs2]];
		else
			dst[ofs1++] = '_';
	}
	return ist2(dst, ofs1);
}

/* Returns a pointer to the FCGi application matching the name <name>. NULL is
 * returned if no match found.
 */
struct fcgi_app *fcgi_app_find_by_name(const char *name)
{
	struct fcgi_app *app;

	for (app = fcgi_apps; app != NULL; app = app->next) {
		if (strcmp(app->name, name) == 0)
			return app;
	}

	return NULL;
}

struct fcgi_flt_conf *find_px_fcgi_conf(struct proxy *px)
{
	struct flt_conf *fconf;

	list_for_each_entry(fconf, &px->filter_configs, list) {
		if (fconf->id == fcgi_flt_id)
			return fconf->conf;
	}
	return NULL;
}

struct fcgi_flt_ctx *find_strm_fcgi_ctx(struct stream *s)
{
	struct filter *filter;

	if (!s)
		return NULL;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_ID(filter) == fcgi_flt_id)
			return FLT_CONF(filter);
	}
	return NULL;
}

struct fcgi_app *get_px_fcgi_app(struct proxy *px)
{
	struct fcgi_flt_conf *fcgi_conf = find_px_fcgi_conf(px);

	if (fcgi_conf)
		return fcgi_conf->app;
	return NULL;
}

struct fcgi_app *get_strm_fcgi_app(struct stream *s)
{
	struct fcgi_flt_ctx *fcgi_ctx = find_strm_fcgi_ctx(s);

	if (fcgi_ctx)
		return fcgi_ctx->app;
	return NULL;
}

static void fcgi_release_rule_conf(struct fcgi_rule_conf *rule)
{
	if (!rule)
		return;
	free(rule->name);
	free(rule->value);
	if (rule->cond) {
		prune_acl_cond(rule->cond);
		free(rule->cond);
	}
	free(rule);
}

static void fcgi_release_rule(struct fcgi_rule *rule)
{
	if (!rule)
		return;

	if (!LIST_ISEMPTY(&rule->value)) {
		struct logformat_node *lf, *lfb;

		list_for_each_entry_safe(lf, lfb, &rule->value, list) {
			LIST_DEL(&lf->list);
			release_sample_expr(lf->expr);
			free(lf->arg);
			free(lf);
		}
	}
	/* ->cond and ->name are not owned by the rule */
	free(rule);
}

/**************************************************************************/
/*********************** FCGI Sample fetches ******************************/
/**************************************************************************/

static int smp_fetch_fcgi_docroot(const struct arg *args, struct sample *smp,
				  const char *kw, void *private)
{
	struct fcgi_app *app = get_strm_fcgi_app(smp->strm);

	if (!app)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->data.u.str.area = app->docroot.ptr;
	smp->data.u.str.data = app->docroot.len;
	smp->flags = SMP_F_CONST;
	return 1;
}

static int smp_fetch_fcgi_index(const struct arg *args, struct sample *smp,
				const char *kw, void *private)
{
	struct fcgi_app *app = get_strm_fcgi_app(smp->strm);

	if (!app || !istlen(app->index))
		return 0;

	smp->data.type = SMP_T_STR;
	smp->data.u.str.area = app->index.ptr;
	smp->data.u.str.data = app->index.len;
	smp->flags = SMP_F_CONST;
	return 1;
}

/**************************************************************************/
/************************** FCGI filter ***********************************/
/**************************************************************************/
static int fcgi_flt_init(struct proxy *px, struct flt_conf *fconf)
{
	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

static void fcgi_flt_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct fcgi_flt_conf *fcgi_conf = fconf->conf;
	struct fcgi_rule *rule, *back;

	if (!fcgi_conf)
		return;

	free(fcgi_conf->name);

	list_for_each_entry_safe(rule, back, &fcgi_conf->param_rules, list) {
		LIST_DEL(&rule->list);
		fcgi_release_rule(rule);
	}

	list_for_each_entry_safe(rule, back, &fcgi_conf->hdr_rules, list) {
		LIST_DEL(&rule->list);
		fcgi_release_rule(rule);
	}

	free(fcgi_conf);
}

static int fcgi_flt_check(struct proxy *px, struct flt_conf *fconf)
{
	struct fcgi_flt_conf  *fcgi_conf = fconf->conf;
	struct fcgi_rule_conf *crule, *back;
	struct fcgi_rule *rule = NULL;
	struct flt_conf *f;
	char *errmsg = NULL;

	fcgi_conf->app = fcgi_app_find_by_name(fcgi_conf->name);
	if (!fcgi_conf->app) {
		ha_alert("config : proxy '%s' : fcgi-app '%s' not found.\n",
			 px->id, fcgi_conf->name);
		goto err;
	}

	list_for_each_entry(f, &px->filter_configs, list) {
		if (f->id == http_comp_flt_id || f->id == cache_store_flt_id)
			continue;
		else if ((f->id == fconf->id) && f->conf != fcgi_conf) {
			ha_alert("config : proxy '%s' : only one fcgi-app supported per backend.\n",
				 px->id);
			goto err;
		}
		else if (f->id != fconf->id) {
			/* Implicit declaration is only allowed with the
			 * compression and cache. For other filters, an implicit
			 * declaration is required. */
			ha_alert("config: proxy '%s': require an explicit filter declaration "
				 "to use the fcgi-app '%s'.\n", px->id, fcgi_conf->name);
			goto err;
		}
	}

	list_for_each_entry_safe(crule, back, &fcgi_conf->app->conf.rules, list) {
		rule = calloc(1, sizeof(*rule));
		if (!rule) {
			ha_alert("config : proxy '%s' : out of memory.\n", px->id);
			goto err;
		}
		rule->type = crule->type;
		rule->name = ist(crule->name);
		rule->cond = crule->cond;
		LIST_INIT(&rule->value);

		if (crule->value) {
			if (!parse_logformat_string(crule->value, px, &rule->value, LOG_OPT_HTTP,
						    SMP_VAL_BE_HRQ_HDR, &errmsg)) {
				ha_alert("config : proxy '%s' : %s.\n", px->id, errmsg);
				goto err;
			}
		}

		if (rule->type == FCGI_RULE_SET_PARAM || rule->type == FCGI_RULE_UNSET_PARAM)
			LIST_ADDQ(&fcgi_conf->param_rules, &rule->list);
		else /* FCGI_RULE_PASS_HDR/FCGI_RULE_HIDE_HDR */
			LIST_ADDQ(&fcgi_conf->hdr_rules, &rule->list);
		rule = NULL;
	}
	return 0;

  err:
	free(errmsg);
	free(rule);
	return 1;
}

static int fcgi_flt_start(struct stream *s, struct filter *filter)
{
	struct fcgi_flt_conf *fcgi_conf  = FLT_CONF(filter);
	struct fcgi_flt_ctx *fcgi_ctx;

	fcgi_ctx = pool_alloc_dirty(pool_head_fcgi_flt_ctx);
	if (fcgi_ctx == NULL) {
		// FIXME: send a warning
		return 0;
	}
	fcgi_ctx->filter = filter;
	fcgi_ctx->app = fcgi_conf->app;
	filter->ctx = fcgi_ctx;

	s->req.analysers |= AN_REQ_HTTP_BODY;
	return 1;
}

static void fcgi_flt_stop(struct stream *s, struct filter *filter)
{
	struct flt_fcgi_ctx *fcgi_ctx = filter->ctx;

	if (!fcgi_ctx)
		return;
	pool_free(pool_head_fcgi_flt_ctx, fcgi_ctx);
	filter->ctx = NULL;
}

static int fcgi_flt_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct session *sess = strm_sess(s);
	struct buffer *value;
	struct fcgi_flt_conf *fcgi_conf = FLT_CONF(filter);
	struct fcgi_rule *rule;
	struct fcgi_param_rule *param_rule;
	struct fcgi_hdr_rule *hdr_rule;
	struct ebpt_node *node, *next;
	struct eb_root param_rules = EB_ROOT;
	struct eb_root hdr_rules = EB_ROOT;
	struct htx *htx;
	struct http_hdr_ctx ctx;
	int ret;

	htx = htxbuf(&msg->chn->buf);

	if (msg->chn->flags & CF_ISRESP) {
		struct htx_sl *sl;

		/* Remove the header "Status:" from the response */
		ctx.blk = NULL;
		while (http_find_header(htx, ist("status"), &ctx, 1))
			http_remove_header(htx, &ctx);

		/* Add the header "Date:" if not found */
		ctx.blk = NULL;
		if (!http_find_header(htx, ist("date"), &ctx, 1)) {
			struct tm tm;

			get_gmtime(date.tv_sec, &tm);
			trash.data = strftime(trash.area, trash.size, "%a, %d %b %Y %T %Z", &tm);
			if (trash.data)
				http_add_header(htx, ist("date"), ist2(trash.area, trash.data));
		}

		/* Add the header "Content-Length:" if possible */
		sl = http_get_stline(htx);
		if (sl &&
		    (sl->flags & (HTX_SL_F_XFER_LEN|HTX_SL_F_CLEN|HTX_SL_F_CHNK)) == HTX_SL_F_XFER_LEN &&
		    htx_get_tail_type(htx) == HTX_BLK_EOM) {
			struct htx_blk * blk;
			char *end;
			size_t len = 0;

			for (blk = htx_get_first_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
				enum htx_blk_type type = htx_get_blk_type(blk);

				if (type == HTX_BLK_EOM)
					break;
				if (type == HTX_BLK_DATA)
					len += htx_get_blksz(blk);
			}
			end = ultoa_o(len, trash.area, trash.size);
			if (http_add_header(htx, ist("content-length"), ist2(trash.area, end-trash.area)))
				sl->flags |= HTX_SL_F_CLEN;
		}

		return 1;
	}

	/* Analyze the request's headers */

	value = alloc_trash_chunk();
	if (!value)
		goto end;

	list_for_each_entry(rule, &fcgi_conf->param_rules, list) {
		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			/* the rule does not match */
			if (!ret)
				continue;
		}

		param_rule = NULL;
		node = ebis_lookup_len(&param_rules, rule->name.ptr, rule->name.len);
		if (node) {
			param_rule = container_of(node, struct fcgi_param_rule, node);
			ebpt_delete(node);
		}
		else {
			param_rule = pool_alloc_dirty(pool_head_fcgi_param_rule);
			if (param_rule == NULL)
				goto param_rule_err;
		}

		param_rule->node.key = rule->name.ptr;
		param_rule->name = rule->name;
		param_rule->value = &rule->value;
		ebis_insert(&param_rules, &param_rule->node);
	}

	list_for_each_entry(rule, &fcgi_conf->hdr_rules, list) {
		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			/* the rule does not match */
			if (!ret)
				continue;
		}

		hdr_rule = NULL;
		node = ebis_lookup_len(&hdr_rules, rule->name.ptr, rule->name.len);
		if (node) {
			hdr_rule = container_of(node, struct fcgi_hdr_rule, node);
			ebpt_delete(node);
		}
		else {
			hdr_rule = pool_alloc_dirty(pool_head_fcgi_hdr_rule);
			if (hdr_rule == NULL)
				goto hdr_rule_err;
		}

		hdr_rule->node.key = rule->name.ptr;
		hdr_rule->name = rule->name;
		hdr_rule->pass = (rule->type == FCGI_RULE_PASS_HDR);
		ebis_insert(&hdr_rules, &hdr_rule->node);
	}

	node = ebpt_first(&param_rules);
	while (node) {
		next = ebpt_next(node);
		ebpt_delete(node);
		param_rule = container_of(node, struct fcgi_param_rule, node);
		node = next;

		b_reset(value);
		value->data = build_logline(s, value->area, value->size, param_rule->value);
		if (!value->data) {
			pool_free(pool_head_fcgi_param_rule, param_rule);
			continue;
		}
		if (!http_add_header(htx, param_rule->name, ist2(value->area, value->data)))
			goto rewrite_err;
		pool_free(pool_head_fcgi_param_rule, param_rule);
	}

	node = ebpt_first(&hdr_rules);
	while (node) {
		next = ebpt_next(node);
		ebpt_delete(node);
		hdr_rule = container_of(node, struct fcgi_hdr_rule, node);
		node = next;

		if (!hdr_rule->pass) {
			ctx.blk = NULL;
			while (http_find_header(htx, hdr_rule->name, &ctx, 1))
				http_remove_header(htx, &ctx);
		}
		pool_free(pool_head_fcgi_hdr_rule, hdr_rule);
	}

	goto end;

  rewrite_err:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_rewrites, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.failed_rewrites, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_rewrites, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_rewrites, 1);
  hdr_rule_err:
	node = ebpt_first(&hdr_rules);
	while (node) {
		next = ebpt_next(node);
		ebpt_delete(node);
		hdr_rule = container_of(node, struct fcgi_hdr_rule, node);
		node = next;
		pool_free(pool_head_fcgi_hdr_rule, hdr_rule);
	}
  param_rule_err:
	node = ebpt_first(&param_rules);
	while (node) {
		next = ebpt_next(node);
		ebpt_delete(node);
		param_rule = container_of(node, struct fcgi_param_rule, node);
		node = next;
		pool_free(pool_head_fcgi_param_rule, param_rule);
	}
  end:
	free_trash_chunk(value);
	return 1;
}

struct flt_ops fcgi_flt_ops = {
	.init   = fcgi_flt_init,
	.check  = fcgi_flt_check,
	.deinit = fcgi_flt_deinit,

	.attach = fcgi_flt_start,
	.detach = fcgi_flt_stop,

	.http_headers = fcgi_flt_http_headers,
};

/**************************************************************************/
/*********************** FCGI Config parsing ******************************/
/**************************************************************************/
static int
parse_fcgi_flt(char **args, int *cur_arg, struct proxy *px,
	       struct flt_conf *fconf, char **err, void *private)
{
	struct flt_conf *f, *back;
	struct fcgi_flt_conf *fcgi_conf = NULL;
	char *name = NULL;
	int pos = *cur_arg;

	/* Get the fcgi-app name*/
	if (!*args[pos + 1]) {
		memprintf(err, "%s : expects a <name> argument", args[pos]);
		goto err;
	}
	name = strdup(args[pos + 1]);
	if (!name) {
		memprintf(err, "%s '%s' : out of memory", args[pos], args[pos + 1]);
		goto err;
	}
	pos += 2;

	/* Check if an fcgi-app filter with the same name already exists */
	list_for_each_entry_safe(f, back, &px->filter_configs, list) {
		if (f->id != fcgi_flt_id)
			continue;
		fcgi_conf = f->conf;
		if (strcmp(name, fcgi_conf->name) != 0) {
			fcgi_conf = NULL;
			continue;
		}

		/* Place the filter at its right position */
		LIST_DEL(&f->list);
		free(f);
		free(name);
		name = NULL;
		break;
	}

	/* No other fcgi-app filter found, create configuration for the explicit one */
	if (!fcgi_conf) {
		fcgi_conf = calloc(1, sizeof(*fcgi_conf));
		if (!fcgi_conf) {
			memprintf(err, "%s: out of memory", args[*cur_arg]);
			goto err;
		}
		fcgi_conf->name = name;
		LIST_INIT(&fcgi_conf->param_rules);
		LIST_INIT(&fcgi_conf->hdr_rules);
	}

	fconf->id   = fcgi_flt_id;
	fconf->conf = fcgi_conf;
	fconf->ops  = &fcgi_flt_ops;

	*cur_arg = pos;
	return 0;
  err:
	free(name);
	return -1;
}

/* Parses the "use-fcgi-app" proxy keyword */
static int proxy_parse_use_fcgi_app(char **args, int section, struct proxy *curpx,
				    struct proxy *defpx, const char *file, int line,
				    char **err)
{
	struct flt_conf *fconf = NULL;
	struct fcgi_flt_conf *fcgi_conf = NULL;
	int retval = 0;

	if (!(curpx->cap & PR_CAP_BE)) {
		memprintf(err, "'%s' only available in backend or listen section", args[0]);
		retval = -1;
		goto end;
        }

	if (!*(args[1])) {
		memprintf(err, "'%s' expects <name> as argument", args[0]);
		retval = -1;
		goto end;
	}

	/* check if a fcgi filter was already registered with this name,
	 * if that's the case, must use it. */
	list_for_each_entry(fconf, &curpx->filter_configs, list) {
		if (fconf->id == fcgi_flt_id) {
			fcgi_conf = fconf->conf;
			if (fcgi_conf && strcmp((char *)fcgi_conf->name, args[1]) == 0)
				goto end;
			memprintf(err, "'%s' : only one fcgi-app supported per backend", args[0]);
			retval = -1;
			goto end;
		}
	}

	/* Create the FCGI filter config */
	fcgi_conf = calloc(1, sizeof(*fcgi_conf));
	if (!fcgi_conf)
		goto err;
	fcgi_conf->name = strdup(args[1]);
	LIST_INIT(&fcgi_conf->param_rules);
	LIST_INIT(&fcgi_conf->hdr_rules);

	/* Register the filter */
	fconf = calloc(1, sizeof(*fconf));
	if (!fconf)
		goto err;
	fconf->id = fcgi_flt_id;
	fconf->conf = fcgi_conf;
	fconf->ops  = &fcgi_flt_ops;
	LIST_ADDQ(&curpx->filter_configs, &fconf->list);

  end:
	return retval;
  err:
	if (fcgi_conf) {
		free(fcgi_conf->name);
		free(fcgi_conf);
	}
	memprintf(err, "out of memory");
	retval = -1;
	goto end;
}

/* Finishes the parsing of FCGI application of proxies and servers */
static int cfg_fcgi_apps_postparser()
{
	struct fcgi_app *curapp;
	struct proxy *px;
	struct server *srv;
	struct logsrv *logsrv;
	int err_code = 0;

	for (px = proxies_list; px; px = px->next) {
		struct fcgi_flt_conf *fcgi_conf = find_px_fcgi_conf(px);
		int nb_fcgi_srv = 0;

		if (px->mode == PR_MODE_TCP && fcgi_conf) {
			ha_alert("config : proxy '%s': FCGI application cannot be used in non-HTTP mode.\n",
				 px->id);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}

		for (srv = px->srv; srv; srv = srv->next) {
			if (srv->mux_proto && isteq(srv->mux_proto->token, ist("fcgi"))) {
				nb_fcgi_srv++;
				if (fcgi_conf)
					continue;
				ha_alert("config : proxy '%s': FCGI server '%s' has no FCGI app configured.\n",
					 px->id, srv->id);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
		}
		if (fcgi_conf && !nb_fcgi_srv) {
			ha_alert("config : proxy '%s': FCGI app configured but no FCGI server found.\n",
				 px->id);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}

	for (curapp = fcgi_apps; curapp != NULL; curapp = curapp->next) {
		if (!istlen(curapp->docroot)) {
			ha_alert("config : fcgi-app '%s': no docroot configured.\n",
				 curapp->name);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		if (!(curapp->flags & (FCGI_APP_FL_MPXS_CONNS|FCGI_APP_FL_GET_VALUES))) {
			if (curapp->maxreqs > 1) {
				ha_warning("config : fcgi-app '%s': multiplexing not supported, "
					   "ignore the option 'max-reqs'.\n",
					   curapp->name);
				err_code |= ERR_WARN;
			}
			curapp->maxreqs = 1;
		}

		list_for_each_entry(logsrv, &curapp->logsrvs, list) {
			if (logsrv->type == LOG_TARGET_BUFFER) {
				struct sink *sink = sink_find(logsrv->ring_name);

				if (!sink || sink->type != SINK_TYPE_BUFFER) {
					ha_alert("config : fcgi-app '%s' : log server uses unknown ring named '%s'.\n",
						 curapp->name, logsrv->ring_name);
					err_code |= ERR_ALERT | ERR_FATAL;
				}
				logsrv->sink = sink;
			}
		}
	}

  end:
	return err_code;
}

static int fcgi_app_add_rule(struct fcgi_app *curapp, enum fcgi_rule_type type, char *name, char *value,
			     struct acl_cond *cond, char **err)
{
	struct fcgi_rule_conf *rule;

	/* Param not found, add a new one */
	rule = calloc(1, sizeof(*rule));
	if (!rule)
		goto err;
	LIST_INIT(&rule->list);
	rule->type = type;
	if (type == FCGI_RULE_SET_PARAM || type == FCGI_RULE_UNSET_PARAM) {
		struct ist fname = fcgi_param_name(trash.area, ist(name));
		rule->name = my_strndup(fname.ptr, fname.len);
	}
	else {  /* FCGI_RULE_PASS_HDR/FCGI_RULE_HIDE_HDR */
		struct ist fname = ist2bin_lc(trash.area, ist(name));
		rule->name = my_strndup(fname.ptr, fname.len);
	}
	if (!rule->name)
		goto err;

	if (value) {
		rule->value = strdup(value);
		if (!rule->value)
			goto err;
	}
	rule->cond = cond;
	LIST_ADDQ(&curapp->conf.rules, &rule->list);
	return 1;

  err:
	if (rule) {
		free(rule->name);
		free(rule->value);
		free(rule);
	}
	if (cond) {
		prune_acl_cond(cond);
		free(cond);
	}
	memprintf(err, "out of memory");
	return 0;
}

/* Parses "fcgi-app" section */
static int cfg_parse_fcgi_app(const char *file, int linenum, char **args, int kwm)
{
	static struct fcgi_app *curapp = NULL;
	struct acl_cond *cond = NULL;
	char *name, *value = NULL;
	enum fcgi_rule_type type;
	int err_code = 0;
	const char *err;
	char *errmsg = NULL;

	if (strcmp(args[0], "fcgi-app") == 0) { /* new fcgi-app */
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d]: '%s' expects <name> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (curapp = fcgi_apps; curapp != NULL; curapp = curapp->next) {
			if (strcmp(curapp->name, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: fcgi-app section '%s' has the same name as another one declared at %s:%d.\n",
					 file, linenum, args[1], curapp->conf.file, curapp->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		curapp = calloc(1, sizeof(*curapp));
		if (!curapp) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curapp->next = fcgi_apps;
		fcgi_apps    = curapp;
		curapp->flags        = FCGI_APP_FL_KEEP_CONN;
		curapp->docroot      = ist(NULL);
		curapp->index        = ist(NULL);
		curapp->pathinfo_re  = NULL;
		curapp->name         = strdup(args[1]);
		curapp->maxreqs      = 1;
		curapp->conf.file    = strdup(file);
		curapp->conf.line    = linenum;
		LIST_INIT(&curapp->acls);
		LIST_INIT(&curapp->logsrvs);
		LIST_INIT(&curapp->conf.args.list);
		LIST_INIT(&curapp->conf.rules);

		/* Set info about authentication */
		if (!fcgi_app_add_rule(curapp, FCGI_RULE_SET_PARAM, "REMOTE_USER", "%[http_auth_user]", NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_SET_PARAM, "AUTH_TYPE",   "%[http_auth_type]", NULL, &errmsg)) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		/* Hide hop-by-hop headers by default */
		if (!fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "connection",          NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "keep-alive",          NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "authorization",       NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "proxy",               NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "proxy-authorization", NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "proxy-authenticate",  NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "te",                  NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "trailers",            NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "transfer-encoding",   NULL, NULL, &errmsg) ||
		    !fcgi_app_add_rule(curapp, FCGI_RULE_HIDE_HDR, "upgrade",             NULL, NULL, &errmsg)) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (strcmp(args[0], "docroot") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects <path> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
			goto out;
		istfree(&curapp->docroot);
		curapp->docroot = ist2(strdup(args[1]), strlen(args[1]));
		if (!isttest(curapp->docroot)) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
		}
	}
	else if (strcmp(args[0], "path-info") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects <regex> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
			goto out;
		regex_free(curapp->pathinfo_re);
		curapp->pathinfo_re = regex_comp(args[1], 1, 1, &errmsg);
		if (!curapp->pathinfo_re) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (strcmp(args[0], "index") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects <filename> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
			goto out;
		istfree(&curapp->index);
		curapp->index = ist2(strdup(args[1]), strlen(args[1]));
		if (!isttest(curapp->index)) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
		}
	}
	else if (strcmp(args[0], "acl") == 0) {
		const char *err;
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
		if (parse_acl((const char **)args+1, &curapp->acls, &errmsg, &curapp->conf.args, file, linenum) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing ACL '%s' : %s.\n",
				 file, linenum, args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "set-param") == 0) {
		if (!*(args[1]) || !*(args[2])) {
			ha_alert("parsing [%s:%d] : '%s' expects <name> and <value> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		type  = FCGI_RULE_SET_PARAM;
		name  = args[1];
		value = args[2];
		cond  = NULL;
		args += 3;

	  parse_cond_rule:
		if (!*(args[0])) /* No condition */
			goto add_rule;

		if (strcmp(args[0], "if") == 0)
			cond = parse_acl_cond((const char **)args+1, &curapp->acls, ACL_COND_IF, &errmsg, &curapp->conf.args,
					      file, linenum);
		else if (strcmp(args[0], "unless") == 0)
			cond = parse_acl_cond((const char **)args+1, &curapp->acls, ACL_COND_UNLESS, &errmsg, &curapp->conf.args,
					      file, linenum);
		if (!cond) {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 name, errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	  add_rule:
		if (!fcgi_app_add_rule(curapp, type, name, value, cond, &errmsg))  {
			ha_alert("parsing [%s:%d] : '%s' : %s.\n", file, linenum,
				 name, errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
#if 0 /* Disabled for now */
	else if (!strcmp(args[0], "unset-param")) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects <name> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		type  = FCGI_RULE_UNSET_PARAM;
		name  = args[1];
		value = NULL;
		cond  = NULL;
		args += 2;
		goto parse_cond_rule;
	}
#endif
	else if (strcmp(args[0], "pass-header") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects <name> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		type  = FCGI_RULE_PASS_HDR;
		name  = args[1];
		value = NULL;
		cond  = NULL;
		args += 2;
		goto parse_cond_rule;
	}
#if 0 /* Disabled for now */
	else if (!strcmp(args[0], "hide-header")) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects <name> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		type  = FCGI_RULE_HIDE_HDR;
		name  = args[1];
		value = NULL;
		cond  = NULL;
		args += 2;
		goto parse_cond_rule;
	}
#endif
	else if (strcmp(args[0], "option") == 0) {
		if (!*(args[1])) {
			ha_alert("parsing [%s:%d]: '%s' expects an option name.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		else if (strcmp(args[1], "keep-conn") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD)
				curapp->flags |= FCGI_APP_FL_KEEP_CONN;
			else if (kwm == KWM_NO)
				curapp->flags &= ~FCGI_APP_FL_KEEP_CONN;
		}
		else if (strcmp(args[1], "get-values") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD)
				curapp->flags |= FCGI_APP_FL_GET_VALUES;
			else if (kwm == KWM_NO)
				curapp->flags &= ~FCGI_APP_FL_GET_VALUES;
		}
		else if (strcmp(args[1], "mpxs-conns") == 0) {
			if (alertif_too_many_args_idx(0, 1, file, linenum, args, &err_code))
				goto out;
			if (kwm == KWM_STD)
				curapp->flags |= FCGI_APP_FL_MPXS_CONNS;
			else if (kwm == KWM_NO)
				curapp->flags &= ~FCGI_APP_FL_MPXS_CONNS;
		}
		else if (strcmp(args[1], "max-reqs") == 0) {
			if (kwm != KWM_STD) {
				ha_alert("parsing [%s:%d]: negation/default is not supported for option '%s'.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (!*(args[2])) {
				ha_alert("parsing [%s:%d]: option '%s' expects an integer argument.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (alertif_too_many_args_idx(1, 1, file, linenum, args, &err_code))
				goto out;

			curapp->maxreqs = atol(args[2]);
			if (!curapp->maxreqs) {
				ha_alert("parsing [%s:%d]: option '%s' expects a strictly positive integer argument.\n",
					 file, linenum, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else {
			ha_alert("parsing [%s:%d] : unknown option '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (strcmp(args[0], "log-stderr") == 0) {
		if (!parse_logsrv(args, &curapp->logsrvs, (kwm == KWM_NO), &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else {
		ha_alert("parsing [%s:%d]: unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "fcgi-app");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

out:
	free(errmsg);
	return err_code;
}


/**************************************************************************/
/*********************** FCGI Deinit functions ****************************/
/**************************************************************************/
void fcgi_apps_deinit()
{
	struct fcgi_app *curapp, *nextapp;
	struct logsrv *log, *logb;

	for (curapp = fcgi_apps; curapp != NULL; curapp = nextapp) {
		struct fcgi_rule_conf *rule, *back;

		free(curapp->name);
		istfree(&curapp->docroot);
		istfree(&curapp->index);
		regex_free(curapp->pathinfo_re);
		free(curapp->conf.file);

		list_for_each_entry_safe(log, logb, &curapp->logsrvs, list) {
			LIST_DEL(&log->list);
			free(log);
		}

		list_for_each_entry_safe(rule, back, &curapp->conf.rules, list) {
			LIST_DEL(&rule->list);
			fcgi_release_rule_conf(rule);
		}

		nextapp = curapp->next;
		free(curapp);
	}
}


/**************************************************************************/
/*************** Keywords definition and registration *********************/
/**************************************************************************/
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_LISTEN, "use-fcgi-app", proxy_parse_use_fcgi_app },
	{ 0, NULL, NULL },
}};

// FIXME: Add rep.fcgi smp_fetch
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "fcgi.docroot",        smp_fetch_fcgi_docroot,        0, NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ "fcgi.index",          smp_fetch_fcgi_index,          0, NULL,    SMP_T_STR,  SMP_USE_HRQHV },
	{ /* END */ }
}};

/* Declare the filter parser for "fcgi-app" keyword */
static struct flt_kw_list filter_kws = { "FCGI", { }, {
		{ "fcgi-app", parse_fcgi_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);
INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
INITCALL1(STG_REGISTER, flt_register_keywords, &filter_kws);

INITCALL1(STG_REGISTER, hap_register_post_deinit, fcgi_apps_deinit);

REGISTER_CONFIG_SECTION("fcgi-app", cfg_parse_fcgi_app, NULL);
REGISTER_CONFIG_POSTPARSER("fcgi-apps", cfg_fcgi_apps_postparser);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
