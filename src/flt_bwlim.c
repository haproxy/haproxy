/*
 * Bandwidth limitation filter.
 *
 * Copyright 2022 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>

#include <haproxy/api.h>
#include <haproxy/channel-t.h>
#include <haproxy/filters.h>
#include <haproxy/global.h>
#include <haproxy/http_ana-t.h>
#include <haproxy/http_rules.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

const char *bwlim_flt_id = "bandwidth limitation filter";

struct flt_ops bwlim_ops;

#define BWLIM_FL_NONE    0x00000000 /* For init purposr */
#define BWLIM_FL_IN      0x00000001 /* Limit clients uploads */
#define BWLIM_FL_OUT     0x00000002 /* Limit clients downloads */
#define BWLIM_FL_SHARED  0x00000004 /* Limit shared between clients (using stick-tables) */

#define BWLIM_ACT_LIMIT_EXPR   0x00000001
#define BWLIM_ACT_LIMIT_CONST  0x00000002
#define BWLIM_ACT_PERIOD_EXPR  0x00000004
#define BWLIM_ACT_PERIOD_CONST 0x00000008

struct bwlim_config {
	struct proxy *proxy;
	char         *name;
	unsigned int flags;
	struct sample_expr *expr;
	union {
		char *n;
		struct stktable *t;
	} table;
	unsigned int period;
	unsigned int limit;
	unsigned int min_size;
};

struct bwlim_state {
	struct freq_ctr bytes_rate;
	struct stksess *ts;
	struct act_rule *rule;
	unsigned int limit;
	unsigned int period;
	unsigned int exp;
};


/* Pools used to allocate comp_state structs */
DECLARE_STATIC_POOL(pool_head_bwlim_state, "bwlim_state", sizeof(struct bwlim_state));


/* Apply the bandwidth limitation of the filter <filter>. <len> is the maximum
 * amount of data that the filter can forward. This function applies the
 * limitation and returns what the stream is authorized to forward. Several
 * limitation can be stacked.
 */
static int bwlim_apply_limit(struct filter *filter, struct channel *chn, unsigned int len)
{
	struct bwlim_config *conf = FLT_CONF(filter);
	struct bwlim_state *st = filter->ctx;
	struct freq_ctr *bytes_rate;
	uint64_t remain;
	unsigned int period, limit, tokens, users, factor;
	unsigned int wait = 0;
	int overshoot, ret = 0;

	/* Don't forward anything if there is nothing to forward or the waiting
	 * time is not expired
	 */
	if (tick_isset(st->exp) && !tick_is_expired(st->exp, now_ms))
		goto end;

	st->exp = TICK_ETERNITY;
	if (!len)
		goto end;

	ret = len;
	if (conf->flags & BWLIM_FL_SHARED) {
		void *ptr;
		unsigned int type = ((conf->flags & BWLIM_FL_IN) ? STKTABLE_DT_BYTES_IN_RATE : STKTABLE_DT_BYTES_OUT_RATE);

		/* In shared mode, get a pointer on the stick table entry. it
		 * will be used to get the freq-counter. It is also used to get
		 * The number of users.
		 */
		ptr = stktable_data_ptr(conf->table.t, st->ts, type);
		if (!ptr)
			goto end;

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &st->ts->lock);
		bytes_rate = &stktable_data_cast(ptr, std_t_frqp);
		period = conf->table.t->data_arg[type].u;
		limit = conf->limit;
		users = st->ts->ref_cnt;
		factor = conf->table.t->brates_factor;
	}
	else {
		/* On per-stream mode, the freq-counter is private to the
		 * stream. Get it from the filter state. Rely on the custom
		 * limit/period if defined or use the default ones. In this mode,
		 * there is only one user.
		 */
		bytes_rate = &st->bytes_rate;
		period = (st->period ? st->period : conf->period);
		limit = (st->limit ? st->limit : conf->limit);
		users = 1;
		factor = 1;
	}

	/* Be sure the current rate does not exceed the limit over the current
	 * period. In this case, nothing is forwarded and the waiting time is
	 * computed to be sure to not retry too early.
	 *
	 * The test is used to avoid the initial burst. Otherwise, streams will
	 * consume the limit as fast as possible and will then be paused for
	 * long time.
	 */
	overshoot = freq_ctr_overshoot_period(bytes_rate, period, limit);
	if (overshoot > 0) {
		if (conf->flags & BWLIM_FL_SHARED)
			HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &st->ts->lock);
		wait = div64_32((uint64_t)(conf->min_size + overshoot) * period * users,
				limit);
		st->exp = tick_add(now_ms, (wait ? wait : 1));
		ret = 0;
		goto end;
	}

	/* Get the allowed quota per user. */
	remain = (uint64_t)freq_ctr_remain_period(bytes_rate, period, limit, 0) * factor;
	tokens = div64_32((uint64_t)(remain + users - 1), users);

	if (tokens < len) {
		/* The stream cannot forward all its data. But we will check if
		 * it can perform a small burst if the global quota is large
		 * enough. But, in this case, its waiting time will be
		 * increased accordingly.
		 */
		ret = tokens;
		if (tokens < conf->min_size) {
			ret = (chn_prod(chn)->flags & (SC_FL_EOI|SC_FL_EOS|SC_FL_ABRT_DONE))
				? MIN(len, conf->min_size)
				: conf->min_size;

			if (ret <= remain)
				wait = div64_32((uint64_t)(ret - tokens) * period * users + limit * factor - 1, limit * factor);
			else
				ret = (limit * factor < ret) ? remain : 0;
		}
	}

	/* At the end, update the freq-counter and compute the waiting time if
	 * the stream is limited
	 */
	update_freq_ctr_period(bytes_rate, period, div64_32((uint64_t)ret + factor -1, factor));
	if (ret < len) {
		wait += next_event_delay_period(bytes_rate, period, limit, MIN(len - ret, conf->min_size * users));
		st->exp = tick_add(now_ms, (wait ? wait : 1));
	}

	if (conf->flags & BWLIM_FL_SHARED)
		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &st->ts->lock);

  end:
	chn->analyse_exp = tick_first((tick_is_expired(chn->analyse_exp, now_ms) ? TICK_ETERNITY : chn->analyse_exp),
				      st->exp);
	BUG_ON(tick_is_expired(chn->analyse_exp, now_ms));
	return ret;
}

/***************************************************************************
 * Hooks that manage the filter lifecycle (init/check/deinit)
 **************************************************************************/
/* Initialize the filter. Returns -1 on error, else 0. */
static int bwlim_init(struct proxy *px, struct flt_conf *fconf)
{
	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

/* Free resources allocated by the bwlim filter. */
static void bwlim_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct bwlim_config *conf = fconf->conf;

	if (conf) {
		ha_free(&conf->name);
		release_sample_expr(conf->expr);
		conf->expr = NULL;
		ha_free(&fconf->conf);
	}
}

/* Check configuration of a bwlim filter for a specified proxy.
 * Return 1 on error, else 0. */
static int bwlim_check(struct proxy *px, struct flt_conf *fconf)
{
	struct bwlim_config *conf = fconf->conf;
	struct stktable *target;

	if (!(conf->flags & BWLIM_FL_SHARED))
		return 0;

	if (conf->table.n)
		target = stktable_find_by_name(conf->table.n);
	else
		target = px->table;

	if (!target) {
		ha_alert("Proxy %s : unable to find table '%s' referenced by bwlim filter '%s'\n",
			 px->id, conf->table.n ? conf->table.n : px->id, conf->name);
		return 1;
	}

	if ((conf->flags & BWLIM_FL_IN) && !target->data_ofs[STKTABLE_DT_BYTES_IN_RATE]) {
		ha_alert("Proxy %s : stick-table '%s' uses a data type incompatible with bwlim filter '%s'."
			 " It must be 'bytes_in_rate'\n",
			 px->id, conf->table.n ? conf->table.n : px->id, conf->name);
		return 1;
	}
	else if ((conf->flags & BWLIM_FL_OUT) && !target->data_ofs[STKTABLE_DT_BYTES_OUT_RATE]) {
		ha_alert("Proxy %s : stick-table '%s' uses a data type incompatible with bwlim filter '%s'."
			 " It must be 'bytes_out_rate'\n",
			 px->id, conf->table.n ? conf->table.n : px->id, conf->name);
		return 1;
	}

	if (!stktable_compatible_sample(conf->expr,  target->type)) {
		ha_alert("Proxy %s : stick-table '%s' uses a key type incompatible with bwlim filter '%s'\n",
			 px->id, conf->table.n ? conf->table.n : px->id, conf->name);
		return 1;
	}
	else {
		if (!in_proxies_list(target->proxies_list, px)) {
			px->next_stkt_ref = target->proxies_list;
			target->proxies_list = px;
		}
		ha_free(&conf->table.n);
		conf->table.t = target;
	}

	return 0;
}

/**************************************************************************
 * Hooks to handle start/stop of streams
 *************************************************************************/
/* Called when a filter instance is created and attach to a stream */
static int bwlim_attach(struct stream *s, struct filter *filter)
{
	struct bwlim_state *st;

	st = pool_zalloc(pool_head_bwlim_state);
	if (!st)
		return -1;
	filter->ctx = st;
	return 1;
}

/* Called when a filter instance is detach from a stream, just before its
 * destruction */
static void bwlim_detach(struct stream *s, struct filter *filter)
{
	struct bwlim_config *conf = FLT_CONF(filter);
	struct bwlim_state *st = filter->ctx;
	struct stktable *t = conf->table.t;

	if (!st)
		return;

	if (st->ts)
		stktable_touch_local(t, st->ts, 1);

	/* release any possible compression context */
	pool_free(pool_head_bwlim_state, st);
	filter->ctx = NULL;
}

/**************************************************************************
 * Hooks to handle channels activity
 *************************************************************************/

/* Called when analyze ends for a given channel */
static int bwlim_chn_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	chn->analyse_exp = TICK_ETERNITY;
        return 1;
}


/**************************************************************************
 * Hooks to filter HTTP messages
 *************************************************************************/
static int bwlim_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	msg->chn->analyse_exp = TICK_ETERNITY;
	return 1;
}

static int bwlim_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
			      unsigned int offset, unsigned int len)
{
	return bwlim_apply_limit(filter, msg->chn, len);
}

/**************************************************************************
 * Hooks to filter TCP data
 *************************************************************************/
static int bwlim_tcp_payload(struct stream *s, struct filter *filter, struct channel *chn,
			     unsigned int offset, unsigned int len)
{
	return bwlim_apply_limit(filter, chn, len);
}

/********************************************************************
 * Functions that manage the filter initialization
 ********************************************************************/
struct flt_ops bwlim_ops = {
	/* Manage bwlim filter, called for each filter declaration */
	.init              = bwlim_init,
	.deinit            = bwlim_deinit,
	.check             = bwlim_check,

	/* Handle start/stop of streams */
	.attach             = bwlim_attach,
	.detach             = bwlim_detach,

	        /* Handle channels activity */
        .channel_end_analyze = bwlim_chn_end_analyze,

	/* Filter HTTP requests and responses */
	.http_headers        = bwlim_http_headers,
	.http_payload        = bwlim_http_payload,

	/* Filter TCP data */
	.tcp_payload        = bwlim_tcp_payload,
};

/* Set a bandwidth limitation. It always return ACT_RET_CONT. On error, the rule
 * is ignored. First of all, it looks for the corresponding filter. Then, for a
 * shared limitation, the stick-table entry is retrieved. For a per-stream
 * limitation, the custom limit and period are computed, if necessary. At the
 * end, the filter is registered on the data filtering for the right channel
 * (bwlim-in = request, bwlim-out = response).
 */
static enum act_return bwlim_set_limit(struct act_rule *rule, struct proxy *px,
				       struct session *sess, struct stream *s, int flags)
{
	struct bwlim_config *conf = rule->arg.act.p[3];
	struct filter *filter;
	struct bwlim_state *st = NULL;
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	int opt;

	list_for_each_entry(filter, &s->strm_flt.filters, list) {
		if (FLT_ID(filter) == bwlim_flt_id && FLT_CONF(filter) == conf) {
			st = filter->ctx;
			break;
		}
	}

	if (!st)
		goto end;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CNT: opt = SMP_OPT_DIR_REQ | SMP_OPT_FINAL; break;
	case ACT_F_TCP_RES_CNT: opt = SMP_OPT_DIR_RES | SMP_OPT_FINAL; break;
	case ACT_F_HTTP_REQ:    opt = SMP_OPT_DIR_REQ | SMP_OPT_FINAL; break;
	case ACT_F_HTTP_RES:    opt = SMP_OPT_DIR_RES | SMP_OPT_FINAL; break;
	default:
		goto end;
	}

	if (conf->flags & BWLIM_FL_SHARED) {
		t = conf->table.t;
		key = stktable_fetch_key(t, px, sess, s, opt, conf->expr, NULL);
		if (!key)
			goto end;

		ts = stktable_get_entry(t, key);
		if (!ts)
			goto end;

		st->ts = ts;
		st->rule = rule;
	}
	else {
		struct sample *smp;

		st->limit = 0;
		st->period = 0;
		if (rule->action & BWLIM_ACT_LIMIT_EXPR) {
			smp = sample_fetch_as_type(px, sess, s, opt, rule->arg.act.p[1], SMP_T_SINT);
			if (smp && smp->data.u.sint > 0)
				st->limit = smp->data.u.sint;
		}
		else if (rule->action & BWLIM_ACT_LIMIT_CONST)
			st->limit = (uintptr_t)rule->arg.act.p[1];

		if (rule->action & BWLIM_ACT_PERIOD_EXPR) {
			smp = sample_fetch_as_type(px, sess, s, opt, rule->arg.act.p[2], SMP_T_SINT);
			if (smp && smp->data.u.sint > 0)
				st->period = smp->data.u.sint;
		}
		else if (rule->action & BWLIM_ACT_PERIOD_CONST)
			st->period = (uintptr_t)rule->arg.act.p[2];
	}

	st->exp = TICK_ETERNITY;
	if (conf->flags & BWLIM_FL_IN)
		register_data_filter(s, &s->req, filter);
	else
		register_data_filter(s, &s->res, filter);

  end:
	return ACT_RET_CONT;
}

/* Check function for "set-bandwidth-limit" action. It returns 1 on
 * success. Otherwise, it returns 0 and <err> is filled.
 */
int check_bwlim_action(struct act_rule *rule, struct proxy *px, char **err)
{
	struct flt_conf *fconf;
	struct bwlim_config *conf = NULL;
	unsigned int where;

	list_for_each_entry(fconf, &px->filter_configs, list) {
		conf = NULL;
		if (fconf->id == bwlim_flt_id) {
			conf = fconf->conf;
			if (strcmp(rule->arg.act.p[0], conf->name) == 0)
				break;
		}
	}
	if (!conf) {
		memprintf(err, "unable to find bwlim filter '%s' referenced by set-bandwidth-limit rule",
			  (char *)rule->arg.act.p[0]);
		return 0;
	}

	if ((conf->flags & BWLIM_FL_SHARED) && rule->arg.act.p[1]) {
		memprintf(err, "set-bandwidth-limit rule cannot define a limit for a shared bwlim filter");
		return 0;
	}

	if ((conf->flags & BWLIM_FL_SHARED) && rule->arg.act.p[2]) {
		memprintf(err, "set-bandwidth-limit rule cannot define a period for a shared bwlim filter");
		return 0;
	}

	where = 0;
	if (px->cap & PR_CAP_FE) {
		if (rule->from == ACT_F_TCP_REQ_CNT)
			where |= SMP_VAL_FE_REQ_CNT;
		else if (rule->from == ACT_F_HTTP_REQ)
			where |= SMP_VAL_FE_HRQ_HDR;
		else if (rule->from == ACT_F_TCP_RES_CNT)
			where |= SMP_VAL_FE_RES_CNT;
		else if (rule->from == ACT_F_HTTP_RES)
			where |= SMP_VAL_FE_HRS_HDR;
	}
	if (px->cap & PR_CAP_BE) {
		if (rule->from == ACT_F_TCP_REQ_CNT)
			where |= SMP_VAL_BE_REQ_CNT;
		else if (rule->from == ACT_F_HTTP_REQ)
			where |= SMP_VAL_BE_HRQ_HDR;
		else if (rule->from == ACT_F_TCP_RES_CNT)
			where |= SMP_VAL_BE_RES_CNT;
		else if (rule->from == ACT_F_HTTP_RES)
			where |= SMP_VAL_BE_HRS_HDR;
	}

	if ((rule->action & BWLIM_ACT_LIMIT_EXPR) && rule->arg.act.p[1]) {
		struct sample_expr *expr = rule->arg.act.p[1];

		if (!(expr->fetch->val & where)) {
			memprintf(err, "set-bandwidth-limit rule uses a limit extracting information from '%s', none of which is available here",
				  sample_src_names(expr->fetch->use));
			return 0;
		}

		if (rule->from == ACT_F_TCP_REQ_CNT && (px->cap & PR_CAP_FE)) {
			if (!px->tcp_req.inspect_delay && !(expr->fetch->val & SMP_VAL_FE_SES_ACC)) {
				ha_warning("%s '%s' : a 'tcp-request content set-bandwidth-limit*' rule explicitly depending on request"
					   " contents without any 'tcp-request inspect-delay' setting."
					   " This means that this rule will randomly find its contents. This can be fixed by"
					   " setting the tcp-request inspect-delay.\n",
					   proxy_type_str(px), px->id);
			}
		}
		if (rule->from == ACT_F_TCP_RES_CNT && (px->cap & PR_CAP_BE)) {
			if (!px->tcp_rep.inspect_delay && !(expr->fetch->val & SMP_VAL_BE_SRV_CON)) {
				ha_warning("%s '%s' : a 'tcp-response content set-bandwidth-limit*' rule explicitly depending on response"
					   " contents without any 'tcp-response inspect-delay' setting."
					   " This means that this rule will randomly find its contents. This can be fixed by"
					   " setting the tcp-response inspect-delay.\n",
					   proxy_type_str(px), px->id);
			}
		}
	}

	if ((rule->action & BWLIM_ACT_PERIOD_EXPR) && rule->arg.act.p[2]) {
		struct sample_expr *expr = rule->arg.act.p[2];

		if (!(expr->fetch->val & where)) {
			memprintf(err, "set-bandwidth-limit rule uses a period extracting information from '%s', none of which is available here",
				  sample_src_names(expr->fetch->use));
			return 0;
		}

		if (rule->from == ACT_F_TCP_REQ_CNT && (px->cap & PR_CAP_FE)) {
			if (!px->tcp_req.inspect_delay && !(expr->fetch->val & SMP_VAL_FE_SES_ACC)) {
				ha_warning("%s '%s' : a 'tcp-request content set-bandwidth-limit*' rule explicitly depending on request"
					   " contents without any 'tcp-request inspect-delay' setting."
					   " This means that this rule will randomly find its contents. This can be fixed by"
					   " setting the tcp-request inspect-delay.\n",
					   proxy_type_str(px), px->id);
                       }
		}
		if (rule->from == ACT_F_TCP_RES_CNT && (px->cap & PR_CAP_BE)) {
			if (!px->tcp_rep.inspect_delay && !(expr->fetch->val & SMP_VAL_BE_SRV_CON)) {
				ha_warning("%s '%s' : a 'tcp-response content set-bandwidth-limit*' rule explicitly depending on response"
					   " contents without any 'tcp-response inspect-delay' setting."
					   " This means that this rule will randomly find its contents. This can be fixed by"
					   " setting the tcp-response inspect-delay.\n",
					   proxy_type_str(px), px->id);
			}
		}
	}

	if (conf->expr) {
		if (!(conf->expr->fetch->val & where)) {
			memprintf(err, "bwlim filter '%s uses a key extracting information from '%s', none of which is available here",
				  conf->name, sample_src_names(conf->expr->fetch->use));
			return 0;
		}

		if (rule->from == ACT_F_TCP_REQ_CNT && (px->cap & PR_CAP_FE)) {
			if (!px->tcp_req.inspect_delay && !(conf->expr->fetch->val & SMP_VAL_FE_SES_ACC)) {
				ha_warning("%s '%s' : a 'tcp-request content set-bandwidth-limit*' rule explicitly depending on request"
					   " contents without any 'tcp-request inspect-delay' setting."
					   " This means that this rule will randomly find its contents. This can be fixed by"
					   " setting the tcp-request inspect-delay.\n",
					   proxy_type_str(px), px->id);
			}
		}
		if (rule->from == ACT_F_TCP_RES_CNT && (px->cap & PR_CAP_BE)) {
			if (!px->tcp_rep.inspect_delay && !(conf->expr->fetch->val & SMP_VAL_BE_SRV_CON)) {
				ha_warning("%s '%s' : a 'tcp-response content set-bandwidth-limit*' rule explicitly depending on response"
					   " contents without any 'tcp-response inspect-delay' setting."
					   " This means that this rule will randomly find its contents. This can be fixed by"
					   " setting the tcp-response inspect-delay.\n",
					   proxy_type_str(px), px->id);
			}
		}
	}

  end:
	rule->arg.act.p[3] = conf;
	return 1;
}

/* Release memory allocated by "set-bandwidth-limit" action. */
static void release_bwlim_action(struct act_rule *rule)
{
	ha_free(&rule->arg.act.p[0]);
	if ((rule->action & BWLIM_ACT_LIMIT_EXPR) && rule->arg.act.p[1]) {
		release_sample_expr(rule->arg.act.p[1]);
		rule->arg.act.p[1] = NULL;
	}
	if ((rule->action & BWLIM_ACT_PERIOD_EXPR) && rule->arg.act.p[2]) {
		release_sample_expr(rule->arg.act.p[2]);
		rule->arg.act.p[2] = NULL;
	}
	rule->arg.act.p[3] = NULL; /* points on the filter's config */
}

/* Parse "set-bandwidth-limit" action. The filter name must be specified. For
 * shared limitations, there is no other supported parameter. For per-stream
 * limitations, a custom limit and period may be specified. In both case, it
 * must be an expression. On success:
 *
 *   arg.act.p[0] will be the filter name (mandatory)
 *   arg.act.p[1] will be an expression for the custom limit (optional, may be NULL)
 *   arg.act.p[2] will be an expression for the custom period (optional, may be NULL)
 *
 * It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret parse_bandwidth_limit(const char **args, int *orig_arg, struct proxy *px,
						struct act_rule *rule, char **err)
{
	struct sample_expr *expr;
	int cur_arg;

	cur_arg = *orig_arg;

	if (!*args[cur_arg]) {
		memprintf(err, "missing bwlim filter name");
		return ACT_RET_PRS_ERR;
	}

	rule->arg.act.p[0] = strdup(args[cur_arg]);
	if (!rule->arg.act.p[0]) {
		memprintf(err, "out of memory");
		return ACT_RET_PRS_ERR;
	}
	cur_arg++;

	while (1) {
		if (strcmp(args[cur_arg], "limit") == 0) {
			const char *res;
			unsigned int limit;

			cur_arg++;
			if (!args[cur_arg]) {
				memprintf(err, "missing limit value or expression");
				goto error;
			}

			res = parse_size_err(args[cur_arg], &limit);
			if (!res) {
				rule->action |= BWLIM_ACT_LIMIT_CONST;
				rule->arg.act.p[1] = (void *)(uintptr_t)limit;
				cur_arg++;
				continue;
			}

			expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, NULL, &px->conf.args, NULL);
			if (!expr) {
				memprintf(err, "'%s': invalid size value or unknown fetch method '%s'", args[cur_arg-1], args[cur_arg]);
				goto error;
			}
			rule->action |= BWLIM_ACT_LIMIT_EXPR;
			rule->arg.act.p[1] = expr;
		}
		else if (strcmp(args[cur_arg], "period") == 0) {
			const char *res;
			unsigned int period;

			cur_arg++;
			if (!args[cur_arg]) {
				memprintf(err, "missing period value or expression");
				goto error;
			}

			res = parse_time_err(args[cur_arg], &period, TIME_UNIT_MS);
			if (!res) {
				rule->action |= BWLIM_ACT_PERIOD_CONST;
				rule->arg.act.p[2] = (void *)(uintptr_t)period;
				cur_arg++;
				continue;
			}

			expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, NULL, &px->conf.args, NULL);
			if (!expr) {
				memprintf(err, "'%s': invalid time value or unknown fetch method '%s'", args[cur_arg-1], args[cur_arg]);
				goto error;
			}
			rule->action |= BWLIM_ACT_PERIOD_EXPR;
			rule->arg.act.p[2] = expr;
		}
		else
			break;
	}

	rule->action_ptr = bwlim_set_limit;
	rule->check_ptr = check_bwlim_action;
	rule->release_ptr = release_bwlim_action;

	*orig_arg = cur_arg;
	return ACT_RET_PRS_OK;

error:
	release_bwlim_action(rule);
	return ACT_RET_PRS_ERR;
}


static struct action_kw_list tcp_req_cont_actions = {
	.kw = {
		{ "set-bandwidth-limit", parse_bandwidth_limit, 0 },
		{ NULL, NULL }
	}
};

static struct action_kw_list tcp_res_cont_actions = {
	.kw = {
		{ "set-bandwidth-limit", parse_bandwidth_limit, 0 },
		{ NULL, NULL }
	}
};

static struct action_kw_list http_req_actions = {
	.kw = {
		{ "set-bandwidth-limit", parse_bandwidth_limit, 0 },
		{ NULL, NULL }
	}
};

static struct action_kw_list http_res_actions = {
	.kw = {
		{ "set-bandwidth-limit", parse_bandwidth_limit, 0 },
		{ NULL, NULL }
	}
};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_cont_actions);
INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_cont_actions);
INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_actions);
INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_actions);


/* Generic function to parse bandwidth limitation filter configurartion. It
 * Returns -1 on error and 0 on success. It handles configuration for per-stream
 * and shared limitations.
 */
static int parse_bwlim_flt(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf,
			   char **err, void *private)
{
	struct flt_conf *fc;
	struct bwlim_config *conf;
	int shared, per_stream;
	int pos = *cur_arg + 1;

	conf = calloc(1, sizeof(*conf));
	if (!conf) {
		memprintf(err, "%s: out of memory", args[*cur_arg]);
		return -1;
	}
	conf->proxy = px;

	if (!*args[pos]) {
		memprintf(err, "'%s' : a name is expected as first argument ", args[*cur_arg]);
		goto error;
	}
	conf->flags = BWLIM_FL_NONE;
	conf->name = strdup(args[pos]);
	if (!conf->name) {
		memprintf(err, "%s: out of memory", args[*cur_arg]);
		goto error;
	}

	list_for_each_entry(fc, &px->filter_configs, list) {
		if (fc->id == bwlim_flt_id) {
			struct bwlim_config *c = fc->conf;

			if (strcmp(conf->name, c->name) == 0) {
				memprintf(err, "bwlim filter '%s' already declared for proxy '%s'\n",
					  conf->name, px->id);
				goto error;
			}
		}
	}
	shared = per_stream = 0;
	pos++;
	while (*args[pos]) {
		if (strcmp(args[pos], "key") == 0) {
			if (per_stream) {
				memprintf(err, "'%s' : cannot mix per-stream and shared parameter",
					  args[*cur_arg]);
				goto error;
			}
			if (!*args[pos + 1]) {
				memprintf(err, "'%s' : the sample expression is missing for '%s' option",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			shared = 1;
			pos++;
			conf->expr = sample_parse_expr((char **)args, &pos, px->conf.args.file, px->conf.args.line,
						       err, &px->conf.args, NULL);
			if (!conf->expr)
				goto error;
		}
		else if (strcmp(args[pos], "table") == 0) {
			if (per_stream) {
				memprintf(err, "'%s' : cannot mix per-stream and shared parameter",
					  args[*cur_arg]);
				goto error;
			}
			if (!*args[pos + 1]) {
				memprintf(err, "'%s' : the table name is missing for '%s' option",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			shared = 1;
			conf->table.n = strdup(args[pos + 1]);
			if (!conf->table.n) {
				memprintf(err, "%s: out of memory", args[*cur_arg]);
				goto error;
			}
			pos += 2;
		}
		else if (strcmp(args[pos], "default-period") == 0) {
			const char *res;

			if (shared) {
				memprintf(err, "'%s' : cannot mix per-stream and shared parameter",
					  args[*cur_arg]);
				goto error;
			}
			if (!*args[pos + 1]) {
				memprintf(err, "'%s' : the value is missing for '%s' option",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			per_stream = 1;
			res = parse_time_err(args[pos + 1], &conf->period, TIME_UNIT_MS);
                        if (res) {
                                memprintf(err, "'%s' : invalid value for option '%s' (unexpected character '%c')",
					  args[*cur_arg], args[pos], *res);
				goto error;
                        }
			pos += 2;
		}
		else if (strcmp(args[pos], "limit") == 0) {
			const char *res;

			if (per_stream) {
				memprintf(err, "'%s' : cannot mix per-stream and shared parameter",
					  args[*cur_arg]);
				goto error;
			}
			if (!*args[pos + 1]) {
				memprintf(err, "'%s' : the value is missing for '%s' option",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			shared = 1;
			res = parse_size_err(args[pos + 1], &conf->limit);
                        if (res) {
                                memprintf(err, "'%s' : invalid value for option '%s' (unexpected character '%c')",
					  args[*cur_arg], args[pos], *res);
				goto error;
                        }
			pos += 2;
		}
		else if (strcmp(args[pos], "default-limit") == 0) {
			const char *res;

			if (shared) {
				memprintf(err, "'%s' : cannot mix per-stream and shared parameter",
					  args[*cur_arg]);
				goto error;
			}
			if (!*args[pos + 1]) {
				memprintf(err, "'%s' : the value is missing for '%s' option",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			per_stream = 1;
			res = parse_size_err(args[pos + 1], &conf->limit);
                        if (res) {
                                memprintf(err, "'%s' : invalid value for option '%s' (unexpected character '%c')",
					  args[*cur_arg], args[pos], *res);
				goto error;
                        }
			pos += 2;
		}
		else if (strcmp(args[pos], "min-size") == 0) {
			const char *res;

			if (!*args[pos + 1]) {
				memprintf(err, "'%s' : the value is missing for '%s' option",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			res = parse_size_err(args[pos + 1], &conf->min_size);
                        if (res) {
                                memprintf(err, "'%s' : invalid value for option '%s' (unexpected character '%c')",
					  args[*cur_arg], args[pos], *res);
				goto error;
                        }
			pos += 2;
		}
		else
			break;
	}

	if (shared) {
		conf->flags |= BWLIM_FL_SHARED;
		if (!conf->expr) {
			memprintf(err, "'%s' : <key> option is missing", args[*cur_arg]);
			goto error;
		}
		if (!conf->limit) {
			memprintf(err, "'%s' : <limit> option is missing", args[*cur_arg]);
			goto error;
		}
	}
	else {
		/* Per-stream: limit downloads only for now */
		conf->flags |= BWLIM_FL_OUT;
		if (!conf->period) {
			memprintf(err, "'%s' : <default-period> option is missing", args[*cur_arg]);
			goto error;
		}
		if (!conf->limit) {
			memprintf(err, "'%s' : <default-limit> option is missing", args[*cur_arg]);
			goto error;
		}
	}

	*cur_arg = pos;
	fconf->id   = bwlim_flt_id;
	fconf->ops  = &bwlim_ops;
	fconf->conf = conf;
	return 0;

 error:
	if (conf->name)
		ha_free(&conf->name);
	if (conf->expr) {
		release_sample_expr(conf->expr);
		conf->expr = NULL;
	}
	if (conf->table.n)
		ha_free(&conf->table.n);
	free(conf);
	return -1;
}


static int parse_bwlim_in_flt(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf,
			      char **err, void *private)
{
	int ret;

	ret = parse_bwlim_flt(args, cur_arg, px, fconf, err, private);
	if (!ret) {
		struct bwlim_config *conf = fconf->conf;

		conf->flags |= BWLIM_FL_IN;
	}

	return ret;
}

static int parse_bwlim_out_flt(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf,
			       char **err, void *private)
{
	int ret;

	ret = parse_bwlim_flt(args, cur_arg, px, fconf, err, private);
	if (!ret) {
		struct bwlim_config *conf = fconf->conf;

		conf->flags |= BWLIM_FL_OUT;
	}
	return ret;
}

/* Declare the filter parser for "trace" keyword */
static struct flt_kw_list flt_kws = { "BWLIM", { }, {
		{ "bwlim-in",  parse_bwlim_in_flt, NULL },
		{ "bwlim-out", parse_bwlim_out_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &flt_kws);
