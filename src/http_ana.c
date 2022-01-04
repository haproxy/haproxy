/*
 * HTTP protocol analyzer
 *
 * Copyright (C) 2018 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/acl.h>
#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/base64.h>
#include <haproxy/capture-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/filters.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/log.h>
#include <haproxy/net_helper.h>
#include <haproxy/proxy.h>
#include <haproxy/regex.h>
#include <haproxy/server-t.h>
#include <haproxy/stats.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/trace.h>
#include <haproxy/uri_auth-t.h>
#include <haproxy/vars.h>


#define TRACE_SOURCE &trace_strm

extern const char *stat_status_codes[];

struct pool_head *pool_head_requri __read_mostly = NULL;
struct pool_head *pool_head_capture __read_mostly = NULL;


static void http_end_request(struct stream *s);
static void http_end_response(struct stream *s);

static void http_capture_headers(struct htx *htx, char **cap, struct cap_hdr *cap_hdr);
static int http_del_hdr_value(char *start, char *end, char **from, char *next);
static size_t http_fmt_req_line(const struct htx_sl *sl, char *str, size_t len);
static void http_debug_stline(const char *dir, struct stream *s, const struct htx_sl *sl);
static void http_debug_hdr(const char *dir, struct stream *s, const struct ist n, const struct ist v);

static enum rule_result http_req_get_intercept_rule(struct proxy *px, struct list *def_rules, struct list *rules, struct stream *s);
static enum rule_result http_res_get_intercept_rule(struct proxy *px, struct list *def_rules, struct list *rules, struct stream *s);

static void http_manage_client_side_cookies(struct stream *s, struct channel *req);
static void http_manage_server_side_cookies(struct stream *s, struct channel *res);

static int http_stats_check_uri(struct stream *s, struct http_txn *txn, struct proxy *backend);
static int http_handle_stats(struct stream *s, struct channel *req);

static int http_handle_expect_hdr(struct stream *s, struct htx *htx, struct http_msg *msg);
static int http_reply_100_continue(struct stream *s);

/* This stream analyser waits for a complete HTTP request. It returns 1 if the
 * processing can continue on next analysers, or zero if it either needs more
 * data or wants to immediately abort the request (eg: timeout, error, ...). It
 * is tied to AN_REQ_WAIT_HTTP and may may remove itself from s->req.analysers
 * when it has nothing left to do, and may remove any analyser when it wants to
 * abort.
 */
int http_wait_for_request(struct stream *s, struct channel *req, int an_bit)
{

	/*
	 * We will analyze a complete HTTP request to check the its syntax.
	 *
	 * Once the start line and all headers are received, we may perform a
	 * capture of the error (if any), and we will set a few fields. We also
	 * check for monitor-uri, logging and finally headers capture.
	 */
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct htx *htx;
	struct htx_sl *sl;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	if (unlikely(!IS_HTX_STRM(s))) {
		/* It is only possible when a TCP stream is upgrade to HTTP.
		 * There is a transition period during which there is no
		 * data. The stream is still in raw mode and SF_IGNORE flag is
		 * still set. When this happens, the new mux is responsible to
		 * handle all errors. Thus we may leave immediately.
		 */
		BUG_ON(!(s->flags & SF_IGNORE) || !c_empty(&s->req));

		/* Don't connect for now */
		channel_dont_connect(req);

		/* A SHUTR at this stage means we are performing a "destructive"
		 * HTTP upgrade (TCP>H2). In this case, we can leave.
		 */
		if (req->flags & CF_SHUTR) {
			s->logs.logwait = 0;
                        s->logs.level = 0;
			channel_abort(&s->req);
			channel_abort(&s->res);
			req->analysers &= AN_REQ_FLT_END;
			req->analyse_exp = TICK_ETERNITY;
			DBG_TRACE_LEAVE(STRM_EV_STRM_ANA, s);
			return 1;
		}
		DBG_TRACE_LEAVE(STRM_EV_STRM_ANA, s);
		return 0;
	}

	htx = htxbuf(&req->buf);

	/* Parsing errors are caught here */
	if (htx->flags & (HTX_FL_PARSING_ERROR|HTX_FL_PROCESSING_ERROR)) {
		stream_inc_http_req_ctr(s);
		proxy_inc_fe_req_ctr(sess->listener, sess->fe);
		if (htx->flags & HTX_FL_PARSING_ERROR) {
			stream_inc_http_err_ctr(s);
			goto return_bad_req;
		}
		else
			goto return_int_err;
	}

	/* we're speaking HTTP here, so let's speak HTTP to the client */
	s->srv_error = http_return_srv_error;

	msg->msg_state = HTTP_MSG_BODY;
	stream_inc_http_req_ctr(s);
	proxy_inc_fe_req_ctr(sess->listener, sess->fe); /* one more valid request for this FE */

	/* kill the pending keep-alive timeout */
	req->analyse_exp = TICK_ETERNITY;

	BUG_ON(htx_get_first_type(htx) != HTX_BLK_REQ_SL);
	sl = http_get_stline(htx);

	/* 0: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		int32_t pos;

		http_debug_stline("clireq", s, sl);

		for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
			struct htx_blk *blk = htx_get_blk(htx, pos);
			enum htx_blk_type type = htx_get_blk_type(blk);

			if (type == HTX_BLK_EOH)
				break;
			if (type != HTX_BLK_HDR)
				continue;

			http_debug_hdr("clihdr", s,
				       htx_get_blk_name(htx, blk),
				       htx_get_blk_value(htx, blk));
		}
	}

	/*
	 * 1: identify the method and the version. Also set HTTP flags
	 */
	txn->meth = sl->info.req.meth;
	if (sl->flags & HTX_SL_F_VER_11)
                msg->flags |= HTTP_MSGF_VER_11;
	msg->flags |= HTTP_MSGF_XFER_LEN;
	if (sl->flags & HTX_SL_F_CLEN)
		msg->flags |= HTTP_MSGF_CNT_LEN;
	else if (sl->flags & HTX_SL_F_CHNK)
		msg->flags |= HTTP_MSGF_TE_CHNK;
	if (sl->flags & HTX_SL_F_BODYLESS)
		msg->flags |= HTTP_MSGF_BODYLESS;
	if (sl->flags & HTX_SL_F_CONN_UPG)
		msg->flags |= HTTP_MSGF_CONN_UPG;

	/* we can make use of server redirect on GET and HEAD */
	if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
		s->flags |= SF_REDIRECTABLE;
	else if (txn->meth == HTTP_METH_OTHER && isteqi(htx_sl_req_meth(sl), ist("PRI"))) {
		/* PRI is reserved for the HTTP/2 preface */
		goto return_bad_req;
	}

	/*
	 * 2: check if the URI matches the monitor_uri.  We have to do this for
	 * every request which gets in, because the monitor-uri is defined by
	 * the frontend. If the monitor-uri starts with a '/', the matching is
	 * done against the request's path. Otherwise, the request's uri is
	 * used. It is a workaround to let HTTP/2 health-checks work as
	 * expected.
	 */
	if (unlikely(sess->fe->monitor_uri_len != 0)) {
		const struct ist monitor_uri = ist2(sess->fe->monitor_uri,
		                                    sess->fe->monitor_uri_len);
		struct http_uri_parser parser = http_uri_parser_init(htx_sl_req_uri(sl));

		if ((istptr(monitor_uri)[0] == '/' &&
		     isteq(http_parse_path(&parser), monitor_uri)) ||
		    isteq(htx_sl_req_uri(sl), monitor_uri)) {
			/*
			 * We have found the monitor URI
			 */
			struct acl_cond *cond;

			s->flags |= SF_MONITOR;
			_HA_ATOMIC_INC(&sess->fe->fe_counters.intercepted_req);

			/* Check if we want to fail this monitor request or not */
			list_for_each_entry(cond, &sess->fe->mon_fail_cond, list) {
				int ret = acl_exec_cond(cond, sess->fe, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);

				ret = acl_pass(ret);
				if (cond->pol == ACL_COND_UNLESS)
					ret = !ret;

				if (ret) {
					/* we fail this request, let's return 503 service unavail */
					txn->status = 503;
					if (!(s->flags & SF_ERR_MASK))
						s->flags |= SF_ERR_LOCAL; /* we don't want a real error here */
					goto return_prx_cond;
				}
			}

			/* nothing to fail, let's reply normally */
			txn->status = 200;
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_LOCAL; /* we don't want a real error here */
			goto return_prx_cond;
		}
	}

	/*
	 * 3: Maybe we have to copy the original REQURI for the logs ?
	 * Note: we cannot log anymore if the request has been
	 * classified as invalid.
	 */
	if (unlikely(s->logs.logwait & LW_REQ)) {
		/* we have a complete HTTP request that we must log */
		if ((txn->uri = pool_alloc(pool_head_requri)) != NULL) {
			size_t len;

			len = http_fmt_req_line(sl, txn->uri, global.tune.requri_len - 1);
			txn->uri[len] = 0;

			if (!(s->logs.logwait &= ~(LW_REQ|LW_INIT)))
				s->do_log(s);
		} else {
			ha_alert("HTTP logging : out of memory.\n");
		}
	}

	/* if the frontend has "option http-use-proxy-header", we'll check if
	 * we have what looks like a proxied connection instead of a connection,
	 * and in this case set the TX_USE_PX_CONN flag to use Proxy-connection.
	 * Note that this is *not* RFC-compliant, however browsers and proxies
	 * happen to do that despite being non-standard :-(
	 * We consider that a request not beginning with either '/' or '*' is
	 * a proxied connection, which covers both "scheme://location" and
	 * CONNECT ip:port.
	 */
	if ((sess->fe->options2 & PR_O2_USE_PXHDR) &&
	    *HTX_SL_REQ_UPTR(sl) != '/' && *HTX_SL_REQ_UPTR(sl) != '*')
		txn->flags |= TX_USE_PX_CONN;

	/* 5: we may need to capture headers */
	if (unlikely((s->logs.logwait & LW_REQHDR) && s->req_cap))
		http_capture_headers(htx, s->req_cap, sess->fe->req_cap);

	/* we may have to wait for the request's body */
	if (s->be->options & PR_O_WREQ_BODY)
		req->analysers |= AN_REQ_HTTP_BODY;

	/*
	 * RFC7234#4:
	 *   A cache MUST write through requests with methods
	 *   that are unsafe (Section 4.2.1 of [RFC7231]) to
	 *   the origin server; i.e., a cache is not allowed
	 *   to generate a reply to such a request before
	 *   having forwarded the request and having received
	 *   a corresponding response.
	 *
	 * RFC7231#4.2.1:
	 *   Of the request methods defined by this
	 *   specification, the GET, HEAD, OPTIONS, and TRACE
	 *   methods are defined to be safe.
	 */
	if (likely(txn->meth == HTTP_METH_GET ||
		   txn->meth == HTTP_METH_HEAD ||
		   txn->meth == HTTP_METH_OPTIONS ||
		   txn->meth == HTTP_METH_TRACE))
		txn->flags |= TX_CACHEABLE | TX_CACHE_COOK;

	/* end of job, return OK */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;

	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 1;

 return_int_err:
	txn->status = 500;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	goto return_prx_cond;

 return_bad_req:
	txn->status = 400;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);
	/* fall through */

 return_prx_cond:
	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;
}


/* This stream analyser runs all HTTP request processing which is common to
 * frontends and backends, which means blocking ACLs, filters, connection-close,
 * reqadd, stats and redirects. This is performed for the designated proxy.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * either needs more data or wants to immediately abort the request (eg: deny,
 * error, ...).
 */
int http_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px)
{
	struct list *def_rules, *rules;
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct htx *htx;
	struct redirect_rule *rule;
	enum rule_result verdict;
	struct connection *conn = objt_conn(sess->origin);

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	htx = htxbuf(&req->buf);

	/* just in case we have some per-backend tracking. Only called the first
	 * execution of the analyser. */
	if (!s->current_rule && !s->current_rule_list)
		stream_inc_be_http_req_ctr(s);

	def_rules = ((px->defpx && (an_bit == AN_REQ_HTTP_PROCESS_FE || px != sess->fe)) ? &px->defpx->http_req_rules : NULL);
	rules = &px->http_req_rules;

	/* evaluate http-request rules */
	if ((def_rules && !LIST_ISEMPTY(def_rules)) || !LIST_ISEMPTY(rules)) {
		verdict = http_req_get_intercept_rule(px, def_rules, rules, s);

		switch (verdict) {
		case HTTP_RULE_RES_YIELD: /* some data miss, call the function later. */
			goto return_prx_yield;

		case HTTP_RULE_RES_CONT:
		case HTTP_RULE_RES_STOP: /* nothing to do */
			break;

		case HTTP_RULE_RES_DENY: /* deny or tarpit */
			if (txn->flags & TX_CLTARPIT)
				goto tarpit;
			goto deny;

		case HTTP_RULE_RES_ABRT: /* abort request, response already sent. Eg: auth */
			goto return_prx_cond;

		case HTTP_RULE_RES_DONE: /* OK, but terminate request processing (eg: redirect) */
			goto done;

		case HTTP_RULE_RES_BADREQ: /* failed with a bad request */
			goto return_bad_req;

		case HTTP_RULE_RES_ERROR: /* failed with a bad request */
			goto return_int_err;
		}
	}

	if (conn && (conn->flags & CO_FL_EARLY_DATA) &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_SSL_WAIT_HS))) {
		struct http_hdr_ctx ctx;

		ctx.blk = NULL;
		if (!http_find_header(htx, ist("Early-Data"), &ctx, 0)) {
			if (unlikely(!http_add_header(htx, ist("Early-Data"), ist("1"))))
				goto return_int_err;
		}
	}

	/* OK at this stage, we know that the request was accepted according to
	 * the http-request rules, we can check for the stats. Note that the
	 * URI is detected *before* the req* rules in order not to be affected
	 * by a possible reqrep, while they are processed *after* so that a
	 * reqdeny can still block them. This clearly needs to change in 1.6!
	 */
	if (!s->target && http_stats_check_uri(s, txn, px)) {
		s->target = &http_stats_applet.obj_type;
		if (unlikely(!si_register_handler(&s->si[1], objt_applet(s->target)))) {
			s->logs.tv_request = now;
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			goto return_int_err;
		}

		/* parse the whole stats request and extract the relevant information */
		http_handle_stats(s, req);
		verdict = http_req_get_intercept_rule(px, NULL, &px->uri_auth->http_req_rules, s);
		/* not all actions implemented: deny, allow, auth */

		if (verdict == HTTP_RULE_RES_DENY) /* stats http-request deny */
			goto deny;

		if (verdict == HTTP_RULE_RES_ABRT) /* stats auth / stats http-request auth */
			goto return_prx_cond;

		if (verdict == HTTP_RULE_RES_BADREQ) /* failed with a bad request */
			goto return_bad_req;

		if (verdict == HTTP_RULE_RES_ERROR) /* failed with a bad request */
			goto return_int_err;
	}

	/* Proceed with the applets now. */
	if (unlikely(objt_applet(s->target))) {
		if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			_HA_ATOMIC_INC(&sess->fe->fe_counters.intercepted_req);

		if (http_handle_expect_hdr(s, htx, msg) == -1)
			goto return_int_err;

		if (!(s->flags & SF_ERR_MASK))      // this is not really an error but it is
			s->flags |= SF_ERR_LOCAL;   // to mark that it comes from the proxy
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_R;

		if (HAS_FILTERS(s))
			req->analysers |= AN_REQ_FLT_HTTP_HDRS;

		/* enable the minimally required analyzers to handle keep-alive and compression on the HTTP response */
		req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
		req->analysers &= ~AN_REQ_FLT_XFER_DATA;
		req->analysers |= AN_REQ_HTTP_XFER_BODY;

		req->flags |= CF_SEND_DONTWAIT;
		s->flags |= SF_ASSIGNED;
		goto done;
	}

	/* check whether we have some ACLs set to redirect this request */
	list_for_each_entry(rule, &px->redirect_rules, list) {
		if (rule->cond) {
			int ret;

			ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}
		if (!http_apply_redirect_rule(rule, s, txn))
			goto return_int_err;
		goto done;
	}

	/* POST requests may be accompanied with an "Expect: 100-Continue" header.
	 * If this happens, then the data will not come immediately, so we must
	 * send all what we have without waiting. Note that due to the small gain
	 * in waiting for the body of the request, it's easier to simply put the
	 * CF_SEND_DONTWAIT flag any time. It's a one-shot flag so it will remove
	 * itself once used.
	 */
	req->flags |= CF_SEND_DONTWAIT;

 done:	/* done with this analyser, continue with next ones that the calling
	 * points will have set, if any.
	 */
	req->analyse_exp = TICK_ETERNITY;
 done_without_exp: /* done with this analyser, but don't reset the analyse_exp. */
	req->analysers &= ~an_bit;
	s->current_rule = s->current_rule_list = NULL;
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 1;

 tarpit:
	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		http_manage_client_side_cookies(s, req);

	/* When a connection is tarpitted, we use the tarpit timeout,
	 * which may be the same as the connect timeout if unspecified.
	 * If unset, then set it to zero because we really want it to
	 * eventually expire. We build the tarpit as an analyser.
	 */
	channel_htx_erase(&s->req, htx);

	/* wipe the request out so that we can drop the connection early
	 * if the client closes first.
	 */
	channel_dont_connect(req);

	req->analysers &= AN_REQ_FLT_END; /* remove switching rules etc... */
	req->analysers |= AN_REQ_HTTP_TARPIT;
	req->analyse_exp = tick_add_ifset(now_ms,  s->be->timeout.tarpit);
	if (!req->analyse_exp)
		req->analyse_exp = tick_add(now_ms, 0);
	stream_inc_http_err_ctr(s);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.denied_req);
	if (s->flags & SF_BE_ASSIGNED)
		_HA_ATOMIC_INC(&s->be->be_counters.denied_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->denied_req);
	goto done_without_exp;

 deny:	/* this request was blocked (denied) */

	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		http_manage_client_side_cookies(s, req);

	s->logs.tv_request = now;
	stream_inc_http_err_ctr(s);
	_HA_ATOMIC_INC(&sess->fe->fe_counters.denied_req);
	if (s->flags & SF_BE_ASSIGNED)
		_HA_ATOMIC_INC(&s->be->be_counters.denied_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->denied_req);
	goto return_prx_err;

 return_int_err:
	txn->status = 500;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	if (s->flags & SF_BE_ASSIGNED)
		_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	goto return_prx_err;

 return_bad_req:
	txn->status = 400;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);
	/* fall through */

 return_prx_err:
	http_reply_and_close(s, txn->status, http_error_message(s));
	/* fall through */

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	s->current_rule = s->current_rule_list = NULL;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;

 return_prx_yield:
	channel_dont_connect(req);
	DBG_TRACE_DEVEL("waiting for more data",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;
}

/* This function performs all the processing enabled for the current request.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * needs more data, encounters an error, or wants to immediately abort the
 * request. It relies on buffers flags, and updates s->req.analysers.
 */
int http_process_request(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct htx *htx;
	struct connection *cli_conn = objt_conn(strm_sess(s)->origin);

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);

	/*
	 * Right now, we know that we have processed the entire headers
	 * and that unwanted requests have been filtered out. We can do
	 * whatever we want with the remaining request. Also, now we
	 * may have separate values for ->fe, ->be.
	 */
	htx = htxbuf(&req->buf);

	/*
	 * 7: Now we can work with the cookies.
	 * Note that doing so might move headers in the request, but
	 * the fields will stay coherent and the URI will not move.
	 * This should only be performed in the backend.
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		http_manage_client_side_cookies(s, req);

	/* 8: Generate unique ID if a "unique-id-format" is defined.
	 *
	 * A unique ID is generated even when it is not sent to ensure that the ID can make use of
	 * fetches only available in the HTTP request processing stage.
	 */
	if (!LIST_ISEMPTY(&sess->fe->format_unique_id)) {
		struct ist unique_id = stream_generate_unique_id(s, &sess->fe->format_unique_id);

		if (!isttest(unique_id)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			goto return_int_err;
		}

		/* send unique ID if a "unique-id-header" is defined */
		if (isttest(sess->fe->header_unique_id) &&
		    unlikely(!http_add_header(htx, sess->fe->header_unique_id, s->unique_id)))
				goto return_int_err;
	}

	/*
	 * 9: add X-Forwarded-For if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_FWDFOR) {
		const struct sockaddr_storage *src = si_src(&s->si[0]);
		struct http_hdr_ctx ctx = { .blk = NULL };
		struct ist hdr = ist2(s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_name : sess->fe->fwdfor_hdr_name,
				      s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_len : sess->fe->fwdfor_hdr_len);

		if (!((sess->fe->options | s->be->options) & PR_O_FF_ALWAYS) &&
		    http_find_header(htx, hdr, &ctx, 0)) {
			/* The header is set to be added only if none is present
			 * and we found it, so don't do anything.
			 */
		}
		else if (src && src->ss_family == AF_INET) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if (ipcmp2net(src, &sess->fe->except_xff_net) &&
			    ipcmp2net(src, &s->be->except_xff_net)) {
				unsigned char *pn = (unsigned char *)&((struct sockaddr_in *)src)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					goto return_int_err;
			}
		}
		else if (src && src->ss_family == AF_INET6) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if (ipcmp2net(src, &sess->fe->except_xff_net) &&
			    ipcmp2net(src, &s->be->except_xff_net)) {
				char pn[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(src))->sin6_addr,
					  pn, sizeof(pn));

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%s", pn);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					goto return_int_err;
			}
		}
	}

	/*
	 * 10: add X-Original-To if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_ORGTO) {
		const struct sockaddr_storage *dst = si_dst(&s->si[0]);
		struct ist hdr = ist2(s->be->orgto_hdr_len ? s->be->orgto_hdr_name : sess->fe->orgto_hdr_name,
				      s->be->orgto_hdr_len ? s->be->orgto_hdr_len  : sess->fe->orgto_hdr_len);

		if (dst && dst->ss_family == AF_INET) {
			/* Add an X-Original-To header unless the destination IP is
			 * in the 'except' network range.
			 */
			if (ipcmp2net(dst, &sess->fe->except_xot_net) &&
			    ipcmp2net(dst, &s->be->except_xot_net)) {
				unsigned char *pn = (unsigned char *)&((struct sockaddr_in *)dst)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-original-to, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					goto return_int_err;
			}
		}
		else if (dst && dst->ss_family == AF_INET6) {
			/* Add an X-Original-To header unless the source IP is
			 * in the 'except' network range.
			 */
			if (ipcmp2net(dst, &sess->fe->except_xot_net) &&
			    ipcmp2net(dst, &s->be->except_xot_net)) {
				char pn[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)dst)->sin6_addr,
					  pn, sizeof(pn));

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%s", pn);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					goto return_int_err;
			}
		}
	}

	/* Filter the request headers if there are filters attached to the
	 * stream.
	 */
	if (HAS_FILTERS(s))
		req->analysers |= AN_REQ_FLT_HTTP_HDRS;

	/* If we have no server assigned yet and we're balancing on url_param
	 * with a POST request, we may be interested in checking the body for
	 * that parameter. This will be done in another analyser.
	 */
	if (!(s->flags & (SF_ASSIGNED|SF_DIRECT)) &&
	    s->txn->meth == HTTP_METH_POST &&
	    (s->be->lbprm.algo & BE_LB_ALGO) == BE_LB_ALGO_PH) {
		channel_dont_connect(req);
		req->analysers |= AN_REQ_HTTP_BODY;
	}

	req->analysers &= ~AN_REQ_FLT_XFER_DATA;
	req->analysers |= AN_REQ_HTTP_XFER_BODY;

	/* We expect some data from the client. Unless we know for sure
	 * we already have a full request, we have to re-enable quick-ack
	 * in case we previously disabled it, otherwise we might cause
	 * the client to delay further data.
	 */
	if ((sess->listener && (sess->listener->options & LI_O_NOQUICKACK)) && !(htx->flags & HTX_FL_EOM))
		conn_set_quickack(cli_conn, 1);

	/*************************************************************
	 * OK, that's finished for the headers. We have done what we *
	 * could. Let's switch to the DATA state.                    *
	 ************************************************************/
	req->analyse_exp = TICK_ETERNITY;
	req->analysers &= ~an_bit;

	s->logs.tv_request = now;
	/* OK let's go on with the BODY now */
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 1;

 return_int_err:
	txn->status = 500;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	if (s->flags & SF_BE_ASSIGNED)
		_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);

	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;
}

/* This function is an analyser which processes the HTTP tarpit. It always
 * returns zero, at the beginning because it prevents any other processing
 * from occurring, and at the end because it terminates the request.
 */
int http_process_tarpit(struct stream *s, struct channel *req, int an_bit)
{
	struct http_txn *txn = s->txn;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, &txn->req);
	/* This connection is being tarpitted. The CLIENT side has
	 * already set the connect expiration date to the right
	 * timeout. We just have to check that the client is still
	 * there and that the timeout has not expired.
	 */
	channel_dont_connect(req);
	if ((req->flags & (CF_SHUTR|CF_READ_ERROR)) == 0 &&
	    !tick_is_expired(req->analyse_exp, now_ms)) {
		/* Be sure to drain all data from the request channel */
		channel_htx_erase(req, htxbuf(&req->buf));
		DBG_TRACE_DEVEL("waiting for tarpit timeout expiry",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 0;
	}


	/* We will set the queue timer to the time spent, just for
	 * logging purposes. We fake a 500 server error, so that the
	 * attacker will not suspect his connection has been tarpitted.
	 * It will not cause trouble to the logs because we can exclude
	 * the tarpitted connections by filtering on the 'PT' status flags.
	 */
	s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

	http_reply_and_close(s, txn->status, (!(req->flags & CF_READ_ERROR) ? http_error_message(s) : NULL));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_T;

	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;
}

/* This function is an analyser which waits for the HTTP request body. It waits
 * for either the buffer to be full, or the full advertised contents to have
 * reached the buffer. It must only be called after the standard HTTP request
 * processing has occurred, because it expects the request to be parsed and will
 * look for the Expect header. It may send a 100-Continue interim response. It
 * takes in input any state starting from HTTP_MSG_BODY and leaves with one of
 * HTTP_MSG_CHK_SIZE, HTTP_MSG_DATA or HTTP_MSG_TRAILERS. It returns zero if it
 * needs to read more data, or 1 once it has completed its analysis.
 */
int http_wait_for_request_body(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->req;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);


	switch (http_wait_for_msg_body(s, req, s->be->timeout.httpreq, 0)) {
	case HTTP_RULE_RES_CONT:
		goto http_end;
	case HTTP_RULE_RES_YIELD:
		goto missing_data_or_waiting;
	case HTTP_RULE_RES_BADREQ:
		goto return_bad_req;
	case HTTP_RULE_RES_ERROR:
		goto return_int_err;
	case HTTP_RULE_RES_ABRT:
		goto return_prx_cond;
	default:
		goto return_int_err;
	}

 http_end:
	/* The situation will not evolve, so let's give up on the analysis. */
	s->logs.tv_request = now;  /* update the request timer to reflect full request */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 1;

 missing_data_or_waiting:
	channel_dont_connect(req);
	DBG_TRACE_DEVEL("waiting for more data",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;

 return_int_err:
	txn->status = 500;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	if (s->flags & SF_BE_ASSIGNED)
		_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	goto return_prx_err;

 return_bad_req: /* let's centralize all bad requests */
	txn->status = 400;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);
	/* fall through */

 return_prx_err:
	http_reply_and_close(s, txn->status, http_error_message(s));
	/* fall through */

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= (msg->msg_state < HTTP_MSG_DATA ? SF_FINST_R : SF_FINST_D);

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;
}

/* This function is an analyser which forwards request body (including chunk
 * sizes if any). It is called as soon as we must forward, even if we forward
 * zero byte. The only situation where it must not be called is when we're in
 * tunnel mode and we want to forward till the close. It's used both to forward
 * remaining data and to resync after end of body. It expects the msg_state to
 * be between MSG_BODY and MSG_DONE (inclusive). It returns zero if it needs to
 * read more data, or 1 once we can go on with next request or end the stream.
 * When in MSG_DATA or MSG_TRAILERS, it will automatically forward chunk_len
 * bytes of pending data + the headers if not already done.
 */
int http_request_forward_body(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct htx *htx;
	short status = 0;
	int ret;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	htx = htxbuf(&req->buf);

	if (htx->flags & HTX_FL_PARSING_ERROR)
		goto return_bad_req;
	if (htx->flags & HTX_FL_PROCESSING_ERROR)
		goto return_int_err;

	if ((req->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((req->flags & CF_SHUTW) && (req->to_forward || co_data(req)))) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 *
		 * If we have finished to send the request and the response is
		 * still in progress, don't catch write error on the request
		 * side if it is in fact a read error on the server side.
		 */
		if (msg->msg_state == HTTP_MSG_DONE && (s->res.flags & CF_READ_ERROR) && s->res.analysers)
			return 0;

		/* Don't abort yet if we had L7 retries activated and it
		 * was a write error, we may recover.
		 */
		if (!(req->flags & (CF_READ_ERROR | CF_READ_TIMEOUT)) &&
		    (s->si[1].flags & SI_FL_L7_RETRY)) {
			DBG_TRACE_DEVEL("leaving on L7 retry",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
			return 0;
		}
		msg->msg_state = HTTP_MSG_ERROR;
		http_end_request(s);
		http_end_response(s);
		DBG_TRACE_DEVEL("leaving on error",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
		return 1;
	}

	/* Note that we don't have to send 100-continue back because we don't
	 * need the data to complete our job, and it's up to the server to
	 * decide whether to return 100, 417 or anything else in return of
	 * an "Expect: 100-continue" header.
	 */
	if (msg->msg_state == HTTP_MSG_BODY)
		msg->msg_state = HTTP_MSG_DATA;

	/* in most states, we should abort in case of early close */
	channel_auto_close(req);

	if (req->to_forward) {
		if (req->to_forward == CHN_INFINITE_FORWARD) {
			if (req->flags & CF_EOI)
				msg->msg_state = HTTP_MSG_ENDING;
		}
		else {
			/* We can't process the buffer's contents yet */
			req->flags |= CF_WAKE_WRITE;
			goto missing_data_or_waiting;
		}
	}

	if (msg->msg_state >= HTTP_MSG_ENDING)
		goto ending;

	if (txn->meth == HTTP_METH_CONNECT) {
		msg->msg_state = HTTP_MSG_ENDING;
		goto ending;
	}

	/* Forward input data. We get it by removing all outgoing data not
	 * forwarded yet from HTX data size. If there are some data filters, we
	 * let them decide the amount of data to forward.
	 */
	if (HAS_REQ_DATA_FILTERS(s)) {
		ret  = flt_http_payload(s, msg, htx->data);
		if (ret < 0)
			goto return_bad_req;
		c_adv(req, ret);
	}
	else {
		c_adv(req, htx->data - co_data(req));
		if (msg->flags & HTTP_MSGF_XFER_LEN)
			channel_htx_forward_forever(req, htx);
	}

	if (htx->data != co_data(req))
		goto missing_data_or_waiting;

	/* Check if the end-of-message is reached and if so, switch the message
	 * in HTTP_MSG_ENDING state. Then if all data was marked to be
	 * forwarded, set the state to HTTP_MSG_DONE.
	 */
	if (!(htx->flags & HTX_FL_EOM))
		goto missing_data_or_waiting;

	msg->msg_state = HTTP_MSG_ENDING;

  ending:
	req->flags &= ~CF_EXPECT_MORE; /* no more data are expected */

	/* other states, ENDING...TUNNEL */
	if (msg->msg_state >= HTTP_MSG_DONE)
		goto done;

	if (HAS_REQ_DATA_FILTERS(s)) {
		ret = flt_http_end(s, msg);
		if (ret <= 0) {
			if (!ret)
				goto missing_data_or_waiting;
			goto return_bad_req;
		}
	}

	if (txn->meth == HTTP_METH_CONNECT)
		msg->msg_state = HTTP_MSG_TUNNEL;
	else {
		msg->msg_state = HTTP_MSG_DONE;
		req->to_forward = 0;
	}

  done:
	/* we don't want to forward closes on DONE except in tunnel mode. */
	if (!(txn->flags & TX_CON_WANT_TUN))
		channel_dont_close(req);

	http_end_request(s);
	if (!(req->analysers & an_bit)) {
		http_end_response(s);
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (req->flags & CF_SHUTW) {
				/* request errors are most likely due to the
				 * server aborting the transfer. */
				goto return_srv_abort;
			}
			goto return_bad_req;
		}
		DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 1;
	}

	/* If "option abortonclose" is set on the backend, we want to monitor
	 * the client's connection and forward any shutdown notification to the
	 * server, which will decide whether to close or to go on processing the
	 * request. We only do that in tunnel mode, and not in other modes since
	 * it can be abused to exhaust source ports. */
	if (s->be->options & PR_O_ABRT_CLOSE) {
		channel_auto_read(req);
		if ((req->flags & (CF_SHUTR|CF_READ_NULL)) && !(txn->flags & TX_CON_WANT_TUN))
			s->si[1].flags |= SI_FL_NOLINGER;
		channel_auto_close(req);
	}
	else if (s->txn->meth == HTTP_METH_POST) {
		/* POST requests may require to read extra CRLF sent by broken
		 * browsers and which could cause an RST to be sent upon close
		 * on some systems (eg: Linux). */
		channel_auto_read(req);
	}
	DBG_TRACE_DEVEL("waiting for the end of the HTTP txn",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;

 missing_data_or_waiting:
	/* stop waiting for data if the input is closed before the end */
	if (msg->msg_state < HTTP_MSG_ENDING && req->flags & CF_SHUTR)
		goto return_cli_abort;

 waiting:
	/* waiting for the last bits to leave the buffer */
	if (req->flags & CF_SHUTW)
		goto return_srv_abort;

	/* When TE: chunked is used, we need to get there again to parse remaining
	 * chunks even if the client has closed, so we don't want to set CF_DONTCLOSE.
	 * And when content-length is used, we never want to let the possible
	 * shutdown be forwarded to the other side, as the state machine will
	 * take care of it once the client responds. It's also important to
	 * prevent TIME_WAITs from accumulating on the backend side, and for
	 * HTTP/2 where the last frame comes with a shutdown.
	 */
	if (msg->flags & HTTP_MSGF_XFER_LEN)
		channel_dont_close(req);

	/* We know that more data are expected, but we couldn't send more that
	 * what we did. So we always set the CF_EXPECT_MORE flag so that the
	 * system knows it must not set a PUSH on this first part. Interactive
	 * modes are already handled by the stream sock layer. We must not do
	 * this in content-length mode because it could present the MSG_MORE
	 * flag with the last block of forwarded data, which would cause an
	 * additional delay to be observed by the receiver.
	 */
	if (HAS_REQ_DATA_FILTERS(s))
		req->flags |= CF_EXPECT_MORE;

	DBG_TRACE_DEVEL("waiting for more data to forward",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;

  return_cli_abort:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
	_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.cli_aborts);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	status = 400;
	goto return_prx_cond;

  return_srv_abort:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
	_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.srv_aborts);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	status = 502;
	goto return_prx_cond;

  return_int_err:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.internal_errors);
	status = 500;
	goto return_prx_cond;

  return_bad_req:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);
	status = 400;
	/* fall through */

  return_prx_cond:
	if (txn->status > 0) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = status;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= ((txn->rsp.msg_state < HTTP_MSG_ERROR) ? SF_FINST_H : SF_FINST_D);
	DBG_TRACE_DEVEL("leaving on error ",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;
}

/* Reset the stream and the backend stream_interface to a situation suitable for attemption connection */
/* Returns 0 if we can attempt to retry, -1 otherwise */
static __inline int do_l7_retry(struct stream *s, struct stream_interface *si)
{
	struct channel *req, *res;
	int co_data;

	si->conn_retries--;
	if (si->conn_retries < 0)
		return -1;

	if (objt_server(s->target)) {
		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			_HA_ATOMIC_DEC(&__objt_server(s->target)->cur_sess);
		}
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.retries);
	}
	_HA_ATOMIC_INC(&s->be->be_counters.retries);

	req = &s->req;
	res = &s->res;
	/* Remove any write error from the request, and read error from the response */
	req->flags &= ~(CF_WRITE_ERROR | CF_WRITE_TIMEOUT | CF_SHUTW | CF_SHUTW_NOW);
	res->flags &= ~(CF_READ_ERROR | CF_READ_TIMEOUT | CF_SHUTR | CF_EOI | CF_READ_NULL | CF_SHUTR_NOW);
	res->analysers &= AN_RES_FLT_END;
	si->flags &= ~(SI_FL_ERR | SI_FL_EXP | SI_FL_RXBLK_SHUT);
	si->err_type = SI_ET_NONE;
	s->flags &= ~(SF_ERR_MASK | SF_FINST_MASK);
	stream_choose_redispatch(s);
	si->exp = TICK_ETERNITY;
	res->rex = TICK_ETERNITY;
	res->to_forward = 0;
	res->analyse_exp = TICK_ETERNITY;
	res->total = 0;
	si_release_endpoint(&s->si[1]);

	b_free(&req->buf);
	/* Swap the L7 buffer with the channel buffer */
	/* We know we stored the co_data as b_data, so get it there */
	co_data = b_data(&si->l7_buffer);
	b_set_data(&si->l7_buffer, b_size(&si->l7_buffer));
	b_xfer(&req->buf, &si->l7_buffer, b_data(&si->l7_buffer));
	co_set_data(req, co_data);

	DBG_TRACE_DEVEL("perform a L7 retry", STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, s->txn);

	b_reset(&res->buf);
	co_set_data(res, 0);
	return 0;
}

/* This stream analyser waits for a complete HTTP response. It returns 1 if the
 * processing can continue on next analysers, or zero if it either needs more
 * data or wants to immediately abort the response (eg: timeout, error, ...). It
 * is tied to AN_RES_WAIT_HTTP and may may remove itself from s->res.analysers
 * when it has nothing left to do, and may remove any analyser when it wants to
 * abort.
 */
int http_wait_for_response(struct stream *s, struct channel *rep, int an_bit)
{
	/*
	 * We will analyze a complete HTTP response to check the its syntax.
	 *
	 * Once the start line and all headers are received, we may perform a
	 * capture of the error (if any), and we will set a few fields. We also
	 * logging and finally headers capture.
	 */
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct htx *htx;
	struct stream_interface *si_b = &s->si[1];
	struct connection *srv_conn;
	struct htx_sl *sl;
	int n;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	htx = htxbuf(&rep->buf);

	/* Parsing errors are caught here */
	if (htx->flags & HTX_FL_PARSING_ERROR)
		goto return_bad_res;
	if (htx->flags & HTX_FL_PROCESSING_ERROR)
		goto return_int_err;

	/*
	 * Now we quickly check if we have found a full valid response.
	 * If not so, we check the FD and buffer states before leaving.
	 * A full response is indicated by the fact that we have seen
	 * the double LF/CRLF, so the state is >= HTTP_MSG_BODY. Invalid
	 * responses are checked first.
	 *
	 * Depending on whether the client is still there or not, we
	 * may send an error response back or not. Note that normally
	 * we should only check for HTTP status there, and check I/O
	 * errors somewhere else.
	 */
  next_one:
	if (unlikely(htx_is_empty(htx) || htx->first == -1)) {
		/* 1: have we encountered a read error ? */
		if (rep->flags & CF_READ_ERROR) {
			struct connection *conn = NULL;

			if (objt_cs(s->si[1].end))
				conn = __objt_cs(s->si[1].end)->conn;

			/* Perform a L7 retry because server refuses the early data. */
			if ((si_b->flags & SI_FL_L7_RETRY) &&
			    (s->be->retry_type & PR_RE_EARLY_ERROR) &&
			    conn && conn->err_code == CO_ER_SSL_EARLY_FAILED &&
			    do_l7_retry(s, si_b) == 0) {
				DBG_TRACE_DEVEL("leaving on L7 retry",
						STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
				return 0;
			}

			if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
			if (objt_server(s->target)) {
				_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_READ_ERROR);
			}

			/* if the server refused the early data, just send a 425 */
			if (conn && conn->err_code == CO_ER_SSL_EARLY_FAILED)
				txn->status = 425;
			else {
				txn->status = 502;
				stream_inc_http_fail_ctr(s);
			}

			s->si[1].flags |= SI_FL_NOLINGER;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			DBG_TRACE_DEVEL("leaving on error",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
			return 0;
		}

		/* 2: read timeout : return a 504 to the client. */
		else if (rep->flags & CF_READ_TIMEOUT) {
			if ((si_b->flags & SI_FL_L7_RETRY) &&
			    (s->be->retry_type & PR_RE_TIMEOUT)) {
				if (co_data(rep) || do_l7_retry(s, si_b) == 0) {
					DBG_TRACE_DEVEL("leaving on L7 retry",
							STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
					return 0;
				}
			}
			_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
			if (objt_server(s->target)) {
				_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_READ_TIMEOUT);
			}

			txn->status = 504;
			stream_inc_http_fail_ctr(s);
			s->si[1].flags |= SI_FL_NOLINGER;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVTO;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			DBG_TRACE_DEVEL("leaving on error",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
			return 0;
		}

		/* 3: client abort with an abortonclose */
		else if ((rep->flags & CF_SHUTR) && ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))) {
			_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
			_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
			if (sess->listener && sess->listener->counters)
				_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
			if (objt_server(s->target))
				_HA_ATOMIC_INC(&__objt_server(s->target)->counters.cli_aborts);

			txn->status = 400;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			DBG_TRACE_DEVEL("leaving on error",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
			return 0;
		}

		/* 4: close from server, capture the response if the server has started to respond */
		else if (rep->flags & CF_SHUTR) {
			if ((si_b->flags & SI_FL_L7_RETRY) &&
			    (s->be->retry_type & PR_RE_DISCONNECTED)) {
				if (co_data(rep) || do_l7_retry(s, si_b) == 0) {
					DBG_TRACE_DEVEL("leaving on L7 retry",
							STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
					return 0;
				}
			}

			if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
			if (objt_server(s->target)) {
				_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_BROKEN_PIPE);
			}

			txn->status = 502;
			stream_inc_http_fail_ctr(s);
			s->si[1].flags |= SI_FL_NOLINGER;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			DBG_TRACE_DEVEL("leaving on error",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
			return 0;
		}

		/* 5: write error to client (we don't send any message then) */
		else if (rep->flags & CF_WRITE_ERROR) {
			if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
			if (objt_server(s->target))
				_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
			rep->analysers &= AN_RES_FLT_END;

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			DBG_TRACE_DEVEL("leaving on error",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
			return 0;
		}

		channel_dont_close(rep);
		rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		DBG_TRACE_DEVEL("waiting for more data",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 0;
	}

	/* More interesting part now : we know that we have a complete
	 * response which at least looks like HTTP. We have an indicator
	 * of each header's length, so we can parse them quickly.
	 */
	BUG_ON(htx_get_first_type(htx) != HTX_BLK_RES_SL);
	sl = http_get_stline(htx);

	/* Perform a L7 retry because of the status code */
	if ((si_b->flags & SI_FL_L7_RETRY) &&
	    l7_status_match(s->be, sl->info.res.status) &&
	    do_l7_retry(s, si_b) == 0) {
		DBG_TRACE_DEVEL("leaving on L7 retry", STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 0;
	}

	/* Now, L7 buffer is useless, it can be released */
	b_free(&s->si[1].l7_buffer);

	msg->msg_state = HTTP_MSG_BODY;


	/* 0: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		int32_t pos;

		http_debug_stline("srvrep", s, sl);

		for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
			struct htx_blk *blk = htx_get_blk(htx, pos);
			enum htx_blk_type type = htx_get_blk_type(blk);

			if (type == HTX_BLK_EOH)
				break;
			if (type != HTX_BLK_HDR)
				continue;

			http_debug_hdr("srvhdr", s,
				       htx_get_blk_name(htx, blk),
				       htx_get_blk_value(htx, blk));
		}
	}

	/* 1: get the status code and the version. Also set HTTP flags */
	txn->status = sl->info.res.status;
	if (sl->flags & HTX_SL_F_VER_11)
                msg->flags |= HTTP_MSGF_VER_11;
	if (sl->flags & HTX_SL_F_XFER_LEN) {
		msg->flags |= HTTP_MSGF_XFER_LEN;
		if (sl->flags & HTX_SL_F_CLEN)
			msg->flags |= HTTP_MSGF_CNT_LEN;
		else if (sl->flags & HTX_SL_F_CHNK)
			msg->flags |= HTTP_MSGF_TE_CHNK;
	}
	if (sl->flags & HTX_SL_F_BODYLESS)
		msg->flags |= HTTP_MSGF_BODYLESS;
	if (sl->flags & HTX_SL_F_CONN_UPG)
		msg->flags |= HTTP_MSGF_CONN_UPG;

	n = txn->status / 100;
	if (n < 1 || n > 5)
		n = 0;

	/* when the client triggers a 4xx from the server, it's most often due
	 * to a missing object or permission. These events should be tracked
	 * because if they happen often, it may indicate a brute force or a
	 * vulnerability scan.
	 */
	if (n == 4)
		stream_inc_http_err_ctr(s);

	if (n == 5 && txn->status != 501 && txn->status != 505)
		stream_inc_http_fail_ctr(s);

	if (objt_server(s->target)) {
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.p.http.rsp[n]);
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.p.http.cum_req);
	}

	/* Adjust server's health based on status code. Note: status codes 501
	 * and 505 are triggered on demand by client request, so we must not
	 * count them as server failures.
	 */
	if (objt_server(s->target)) {
		if (txn->status >= 100 && (txn->status < 500 || txn->status == 501 || txn->status == 505))
			health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_OK);
		else
			health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_STS);
	}

	/*
	 * We may be facing a 100-continue response, or any other informational
	 * 1xx response which is non-final, in which case this is not the right
	 * response, and we're waiting for the next one. Let's allow this response
	 * to go to the client and wait for the next one. There's an exception for
	 * 101 which is used later in the code to switch protocols.
	 */
	if (txn->status < 200 &&
	    (txn->status == 100 || txn->status >= 102)) {
		FLT_STRM_CB(s, flt_http_reset(s, msg));
		htx->first = channel_htx_fwd_headers(rep, htx);
		msg->msg_state = HTTP_MSG_RPBEFORE;
		msg->flags = 0;
		txn->status = 0;
		s->logs.t_data = -1; /* was not a response yet */
		rep->flags |= CF_SEND_DONTWAIT; /* Send ASAP informational messages */
		goto next_one;
	}

	/* A 101-switching-protocols must contains a Connection header with the
	 * "upgrade" option and the request too. It means both are agree to
	 * upgrade. It is not so strict because there is no test on the Upgrade
	 * header content. But it is probably stronger enough for now.
	 */
	if (txn->status == 101 &&
	    (!(txn->req.flags & HTTP_MSGF_CONN_UPG) || !(txn->rsp.flags & HTTP_MSGF_CONN_UPG)))
		goto return_bad_res;

	/*
	 * 2: check for cacheability.
	 */

	switch (txn->status) {
	case 200:
	case 203:
	case 204:
	case 206:
	case 300:
	case 301:
	case 404:
	case 405:
	case 410:
	case 414:
	case 501:
		break;
	default:
		/* RFC7231#6.1:
		 *   Responses with status codes that are defined as
		 *   cacheable by default (e.g., 200, 203, 204, 206,
		 *   300, 301, 404, 405, 410, 414, and 501 in this
		 *   specification) can be reused by a cache with
		 *   heuristic expiration unless otherwise indicated
		 *   by the method definition or explicit cache
		 *   controls [RFC7234]; all other status codes are
		 *   not cacheable by default.
		 */
		txn->flags &= ~(TX_CACHEABLE | TX_CACHE_COOK);
		break;
	}

	/*
	 * 3: we may need to capture headers
	 */
	s->logs.logwait &= ~LW_RESP;
	if (unlikely((s->logs.logwait & LW_RSPHDR) && s->res_cap))
		http_capture_headers(htx, s->res_cap, sess->fe->rsp_cap);

	/* Skip parsing if no content length is possible. */
	if (unlikely((txn->meth == HTTP_METH_CONNECT && txn->status >= 200 && txn->status < 300) ||
		     txn->status == 101)) {
		/* Either we've established an explicit tunnel, or we're
		 * switching the protocol. In both cases, we're very unlikely
		 * to understand the next protocols. We have to switch to tunnel
		 * mode, so that we transfer the request and responses then let
		 * this protocol pass unmodified. When we later implement specific
		 * parsers for such protocols, we'll want to check the Upgrade
		 * header which contains information about that protocol for
		 * responses with status 101 (eg: see RFC2817 about TLS).
		 */
		txn->flags |= TX_CON_WANT_TUN;
	}

	/* check for NTML authentication headers in 401 (WWW-Authenticate) and
	 * 407 (Proxy-Authenticate) responses and set the connection to private
	 */
	srv_conn = cs_conn(objt_cs(s->si[1].end));
	if (srv_conn) {
		struct ist hdr;
		struct http_hdr_ctx ctx;

		if (txn->status == 401)
			hdr = ist("WWW-Authenticate");
		else if (txn->status == 407)
			hdr = ist("Proxy-Authenticate");
		else
			goto end;

		ctx.blk = NULL;
		while (http_find_header(htx, hdr, &ctx, 0)) {
			/* If www-authenticate contains "Negotiate", "Nego2", or "NTLM",
			 * possibly followed by blanks and a base64 string, the connection
			 * is private. Since it's a mess to deal with, we only check for
			 * values starting with "NTLM" or "Nego". Note that often multiple
			 * headers are sent by the server there.
			 */
			if ((ctx.value.len >= 4 && strncasecmp(ctx.value.ptr, "Nego", 4) == 0) ||
			    (ctx.value.len >= 4 && strncasecmp(ctx.value.ptr, "NTLM", 4) == 0)) {
				sess->flags |= SESS_FL_PREFER_LAST;
				conn_set_owner(srv_conn, sess, NULL);
				conn_set_private(srv_conn);
				/* If it fail now, the same will be done in mux->detach() callback */
				session_add_conn(srv_conn->owner, srv_conn, srv_conn->target);
				break;
			}
		}
	}

  end:
	/* we want to have the response time before we start processing it */
	s->logs.t_data = tv_ms_elapsed(&s->logs.tv_accept, &now);

	/* end of job, return OK */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	channel_auto_close(rep);
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 1;

 return_int_err:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.internal_errors);
	txn->status = 500;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	goto return_prx_cond;

  return_bad_res:
	_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
	if (objt_server(s->target)) {
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
		health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_HDRRSP);
	}
	if ((s->be->retry_type & PR_RE_JUNK_REQUEST) &&
	    (si_b->flags & SI_FL_L7_RETRY) &&
	    do_l7_retry(s, si_b) == 0) {
		DBG_TRACE_DEVEL("leaving on L7 retry",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 0;
	}
	txn->status = 502;
	stream_inc_http_fail_ctr(s);
	/* fall through */

 return_prx_cond:
	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_H;

	s->si[1].flags |= SI_FL_NOLINGER;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;

 abort_keep_alive:
	/* A keep-alive request to the server failed on a network error.
	 * The client is required to retry. We need to close without returning
	 * any other information so that the client retries.
	 */
	txn->status = 0;
	s->logs.logwait = 0;
	s->logs.level = 0;
	s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
	http_reply_and_close(s, txn->status, NULL);
	DBG_TRACE_DEVEL("leaving by closing K/A connection",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;
}

/* This function performs all the processing enabled for the current response.
 * It normally returns 1 unless it wants to break. It relies on buffers flags,
 * and updates s->res.analysers. It might make sense to explode it into several
 * other functions. It works like process_request (see indications above).
 */
int http_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct htx *htx;
	struct proxy *cur_proxy;
	enum rule_result ret = HTTP_RULE_RES_CONT;

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))	/* we need more data */
		return 0;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	htx = htxbuf(&rep->buf);

	/* The stats applet needs to adjust the Connection header but we don't
	 * apply any filter there.
	 */
	if (unlikely(objt_applet(s->target) == &http_stats_applet)) {
		rep->analysers &= ~an_bit;
		rep->analyse_exp = TICK_ETERNITY;
		goto end;
	}

	/*
	 * We will have to evaluate the filters.
	 * As opposed to version 1.2, now they will be evaluated in the
	 * filters order and not in the header order. This means that
	 * each filter has to be validated among all headers.
	 *
	 * Filters are tried with ->be first, then with ->fe if it is
	 * different from ->be.
	 *
	 * Maybe we are in resume condiion. In this case I choose the
	 * "struct proxy" which contains the rule list matching the resume
	 * pointer. If none of these "struct proxy" match, I initialise
	 * the process with the first one.
	 *
	 * In fact, I check only correspondence between the current list
	 * pointer and the ->fe rule list. If it doesn't match, I initialize
	 * the loop with the ->be.
	 */
	if (s->current_rule_list == &sess->fe->http_res_rules ||
	    (sess->fe->defpx && s->current_rule_list == &sess->fe->defpx->http_res_rules))
		cur_proxy = sess->fe;
	else
		cur_proxy = s->be;

	while (1) {
		/* evaluate http-response rules */
		if (ret == HTTP_RULE_RES_CONT || ret == HTTP_RULE_RES_STOP) {
			struct list *def_rules, *rules;

			def_rules = ((cur_proxy->defpx && (cur_proxy == s->be || cur_proxy->defpx != s->be->defpx)) ? &cur_proxy->defpx->http_res_rules : NULL);
			rules = &cur_proxy->http_res_rules;

			ret = http_res_get_intercept_rule(cur_proxy, def_rules, rules, s);

			switch (ret) {
			case HTTP_RULE_RES_YIELD: /* some data miss, call the function later. */
				goto return_prx_yield;

			case HTTP_RULE_RES_CONT:
			case HTTP_RULE_RES_STOP: /* nothing to do */
				break;

			case HTTP_RULE_RES_DENY: /* deny or tarpit */
				goto deny;

			case HTTP_RULE_RES_ABRT: /* abort request, response already sent */
				goto return_prx_cond;

			case HTTP_RULE_RES_DONE: /* OK, but terminate request processing (eg: redirect) */
				goto done;

			case HTTP_RULE_RES_BADREQ: /* failed with a bad request */
				goto return_bad_res;

			case HTTP_RULE_RES_ERROR: /* failed with a bad request */
				goto return_int_err;
			}

		}

		/* check whether we're already working on the frontend */
		if (cur_proxy == sess->fe)
			break;
		cur_proxy = sess->fe;
	}

	/* OK that's all we can do for 1xx responses */
	if (unlikely(txn->status < 200 && txn->status != 101))
		goto end;

	/*
	 * Now check for a server cookie.
	 */
	if (s->be->cookie_name || sess->fe->capture_name || (s->be->options & PR_O_CHK_CACHE))
		http_manage_server_side_cookies(s, rep);

	/*
	 * Check for cache-control or pragma headers if required.
	 */
	if ((s->be->options & PR_O_CHK_CACHE) || (s->be->ck_opts & PR_CK_NOC))
		http_check_response_for_cacheability(s, rep);

	/*
	 * Add server cookie in the response if needed
	 */
	if (objt_server(s->target) && (s->be->ck_opts & PR_CK_INS) &&
	    !((txn->flags & TX_SCK_FOUND) && (s->be->ck_opts & PR_CK_PSV)) &&
	    (!(s->flags & SF_DIRECT) ||
	     ((s->be->cookie_maxidle || txn->cookie_last_date) &&
	      (!txn->cookie_last_date || (txn->cookie_last_date - date.tv_sec) < 0)) ||
	     (s->be->cookie_maxlife && !txn->cookie_first_date) ||  // set the first_date
	     (!s->be->cookie_maxlife && txn->cookie_first_date)) && // remove the first_date
	    (!(s->be->ck_opts & PR_CK_POST) || (txn->meth == HTTP_METH_POST)) &&
	    !(s->flags & SF_IGNORE_PRST)) {
		/* the server is known, it's not the one the client requested, or the
		 * cookie's last seen date needs to be refreshed. We have to
		 * insert a set-cookie here, except if we want to insert only on POST
		 * requests and this one isn't. Note that servers which don't have cookies
		 * (eg: some backup servers) will return a full cookie removal request.
		 */
		if (!__objt_server(s->target)->cookie) {
			chunk_printf(&trash,
				     "%s=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/",
				     s->be->cookie_name);
		}
		else {
			chunk_printf(&trash, "%s=%s", s->be->cookie_name, __objt_server(s->target)->cookie);

			if (s->be->cookie_maxidle || s->be->cookie_maxlife) {
				/* emit last_date, which is mandatory */
				trash.area[trash.data++] = COOKIE_DELIM_DATE;
				s30tob64((date.tv_sec+3) >> 2,
					 trash.area + trash.data);
				trash.data += 5;

				if (s->be->cookie_maxlife) {
					/* emit first_date, which is either the original one or
					 * the current date.
					 */
					trash.area[trash.data++] = COOKIE_DELIM_DATE;
					s30tob64(txn->cookie_first_date ?
						 txn->cookie_first_date >> 2 :
						 (date.tv_sec+3) >> 2,
						 trash.area + trash.data);
					trash.data += 5;
				}
			}
			chunk_appendf(&trash, "; path=/");
		}

		if (s->be->cookie_domain)
			chunk_appendf(&trash, "; domain=%s", s->be->cookie_domain);

		if (s->be->ck_opts & PR_CK_HTTPONLY)
			chunk_appendf(&trash, "; HttpOnly");

		if (s->be->ck_opts & PR_CK_SECURE)
			chunk_appendf(&trash, "; Secure");

		if (s->be->cookie_attrs)
			chunk_appendf(&trash, "; %s", s->be->cookie_attrs);

		if (unlikely(!http_add_header(htx, ist("Set-Cookie"), ist2(trash.area, trash.data))))
			goto return_int_err;

		txn->flags &= ~TX_SCK_MASK;
		if (__objt_server(s->target)->cookie && (s->flags & SF_DIRECT))
			/* the server did not change, only the date was updated */
			txn->flags |= TX_SCK_UPDATED;
		else
			txn->flags |= TX_SCK_INSERTED;

		/* Here, we will tell an eventual cache on the client side that we don't
		 * want it to cache this reply because HTTP/1.0 caches also cache cookies !
		 * Some caches understand the correct form: 'no-cache="set-cookie"', but
		 * others don't (eg: apache <= 1.3.26). So we use 'private' instead.
		 */
		if ((s->be->ck_opts & PR_CK_NOC) && (txn->flags & TX_CACHEABLE)) {

			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;

			if (unlikely(!http_add_header(htx, ist("Cache-control"), ist("private"))))
				goto return_int_err;
		}
	}

	/*
	 * Check if result will be cacheable with a cookie.
	 * We'll block the response if security checks have caught
	 * nasty things such as a cacheable cookie.
	 */
	if (((txn->flags & (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_PRESENT)) ==
	     (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_PRESENT)) &&
	    (s->be->options & PR_O_CHK_CACHE)) {
		/* we're in presence of a cacheable response containing
		 * a set-cookie header. We'll block it as requested by
		 * the 'checkcache' option, and send an alert.
		 */
		ha_alert("Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? __objt_server(s->target)->id : "<dispatch>");
		send_log(s->be, LOG_ALERT,
			 "Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? __objt_server(s->target)->id : "<dispatch>");
		goto deny;
	}

  end:
	/*
	 * Evaluate after-response rules before forwarding the response. rules
	 * from the backend are evaluated first, then one from the frontend if
	 * it differs.
	 */
	if (!http_eval_after_res_rules(s))
		goto return_int_err;

	/* Filter the response headers if there are filters attached to the
	 * stream.
	 */
	if (HAS_FILTERS(s))
		rep->analysers |= AN_RES_FLT_HTTP_HDRS;

	/* Always enter in the body analyzer */
	rep->analysers &= ~AN_RES_FLT_XFER_DATA;
	rep->analysers |= AN_RES_HTTP_XFER_BODY;

	/* if the user wants to log as soon as possible, without counting
	 * bytes from the server, then this is the right moment. We have
	 * to temporarily assign bytes_out to log what we currently have.
	 */
	if (!LIST_ISEMPTY(&sess->fe->logformat) && !(s->logs.logwait & LW_BYTES)) {
		s->logs.t_close = s->logs.t_data; /* to get a valid end date */
		s->logs.bytes_out = htx->data;
		s->do_log(s);
		s->logs.bytes_out = 0;
	}

 done:
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	s->current_rule = s->current_rule_list = NULL;
	return 1;

 deny:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.denied_resp);
	_HA_ATOMIC_INC(&s->be->be_counters.denied_resp);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->denied_resp);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.denied_resp);
	goto return_prx_err;

 return_int_err:
	txn->status = 500;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.internal_errors);
	goto return_prx_err;

 return_bad_res:
	txn->status = 502;
	stream_inc_http_fail_ctr(s);
	_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
	if (objt_server(s->target)) {
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
		health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_RSP);
	}
	/* fall through */

 return_prx_err:
	http_reply_and_close(s, txn->status, http_error_message(s));
	/* fall through */

 return_prx_cond:
	s->logs.t_data = -1; /* was not a valid response */
	s->si[1].flags |= SI_FL_NOLINGER;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_H;

	rep->analysers &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END;
	rep->analyse_exp = TICK_ETERNITY;
	s->current_rule = s->current_rule_list = NULL;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;

 return_prx_yield:
	channel_dont_close(rep);
	DBG_TRACE_DEVEL("waiting for more data",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;
}

/* This function is an analyser which forwards response body (including chunk
 * sizes if any). It is called as soon as we must forward, even if we forward
 * zero byte. The only situation where it must not be called is when we're in
 * tunnel mode and we want to forward till the close. It's used both to forward
 * remaining data and to resync after end of body. It expects the msg_state to
 * be between MSG_BODY and MSG_DONE (inclusive). It returns zero if it needs to
 * read more data, or 1 once we can go on with next request or end the stream.
 *
 * It is capable of compressing response data both in content-length mode and
 * in chunked mode. The state machines follows different flows depending on
 * whether content-length and chunked modes are used, since there are no
 * trailers in content-length :
 *
 *       chk-mode        cl-mode
 *          ,----- BODY -----.
 *         /                  \
 *        V     size > 0       V    chk-mode
 *  .--> SIZE -------------> DATA -------------> CRLF
 *  |     | size == 0          | last byte         |
 *  |     v      final crlf    v inspected         |
 *  |  TRAILERS -----------> DONE                  |
 *  |                                              |
 *  `----------------------------------------------'
 *
 * Compression only happens in the DATA state, and must be flushed in final
 * states (TRAILERS/DONE) or when leaving on missing data. Normal forwarding
 * is performed at once on final states for all bytes parsed, or when leaving
 * on missing data.
 */
int http_response_forward_body(struct stream *s, struct channel *res, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->rsp;
	struct htx *htx;
	int ret;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	htx = htxbuf(&res->buf);

	if (htx->flags & HTX_FL_PARSING_ERROR)
		goto return_bad_res;
	if (htx->flags & HTX_FL_PROCESSING_ERROR)
		goto return_int_err;

	if ((res->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((res->flags & CF_SHUTW) && (res->to_forward || co_data(res)))) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 */
		msg->msg_state = HTTP_MSG_ERROR;
		http_end_response(s);
		http_end_request(s);
		DBG_TRACE_DEVEL("leaving on error",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
		return 1;
	}

	if (msg->msg_state == HTTP_MSG_BODY)
		msg->msg_state = HTTP_MSG_DATA;

	/* in most states, we should abort in case of early close */
	channel_auto_close(res);

	if (res->to_forward) {
		if (res->to_forward == CHN_INFINITE_FORWARD) {
			if (res->flags & CF_EOI)
				msg->msg_state = HTTP_MSG_ENDING;
		}
		else {
			/* We can't process the buffer's contents yet */
			res->flags |= CF_WAKE_WRITE;
			goto missing_data_or_waiting;
		}
	}

	if (msg->msg_state >= HTTP_MSG_ENDING)
		goto ending;

	if ((txn->meth == HTTP_METH_CONNECT && txn->status >= 200 && txn->status < 300) || txn->status == 101 ||
	    (!(msg->flags & HTTP_MSGF_XFER_LEN) && !HAS_RSP_DATA_FILTERS(s))) {
		msg->msg_state = HTTP_MSG_ENDING;
		goto ending;
	}

	/* Forward input data. We get it by removing all outgoing data not
	 * forwarded yet from HTX data size. If there are some data filters, we
	 * let them decide the amount of data to forward.
	 */
	if (HAS_RSP_DATA_FILTERS(s)) {
		ret  = flt_http_payload(s, msg, htx->data);
		if (ret < 0)
			goto return_bad_res;
		c_adv(res, ret);
	}
	else {
		c_adv(res, htx->data - co_data(res));
		if (msg->flags & HTTP_MSGF_XFER_LEN)
			channel_htx_forward_forever(res, htx);
	}

	if (htx->data != co_data(res))
		goto missing_data_or_waiting;

	if (!(msg->flags & HTTP_MSGF_XFER_LEN) && res->flags & CF_SHUTR) {
		msg->msg_state = HTTP_MSG_ENDING;
		goto ending;
	}

	/* Check if the end-of-message is reached and if so, switch the message
	 * in HTTP_MSG_ENDING state. Then if all data was marked to be
	 * forwarded, set the state to HTTP_MSG_DONE.
	 */
	if (!(htx->flags & HTX_FL_EOM))
		goto missing_data_or_waiting;

	msg->msg_state = HTTP_MSG_ENDING;

  ending:
	res->flags &= ~CF_EXPECT_MORE; /* no more data are expected */

	/* other states, ENDING...TUNNEL */
	if (msg->msg_state >= HTTP_MSG_DONE)
		goto done;

	if (HAS_RSP_DATA_FILTERS(s)) {
		ret = flt_http_end(s, msg);
		if (ret <= 0) {
			if (!ret)
				goto missing_data_or_waiting;
			goto return_bad_res;
		}
	}

	if ((txn->meth == HTTP_METH_CONNECT && txn->status >= 200 && txn->status < 300) || txn->status == 101 ||
	    !(msg->flags & HTTP_MSGF_XFER_LEN)) {
		msg->msg_state = HTTP_MSG_TUNNEL;
		goto ending;
	}
	else {
		msg->msg_state = HTTP_MSG_DONE;
		res->to_forward = 0;
	}

  done:

	channel_dont_close(res);

	http_end_response(s);
	if (!(res->analysers & an_bit)) {
		http_end_request(s);
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (res->flags & CF_SHUTW) {
				/* response errors are most likely due to the
				 * client aborting the transfer. */
				goto return_cli_abort;
			}
			goto return_bad_res;
		}
		DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 1;
	}
	DBG_TRACE_DEVEL("waiting for the end of the HTTP txn",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;

  missing_data_or_waiting:
	if (res->flags & CF_SHUTW)
		goto return_cli_abort;

	/* stop waiting for data if the input is closed before the end. If the
	 * client side was already closed, it means that the client has aborted,
	 * so we don't want to count this as a server abort. Otherwise it's a
	 * server abort.
	 */
	if (msg->msg_state < HTTP_MSG_ENDING && res->flags & CF_SHUTR) {
		if ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))
			goto return_cli_abort;
		/* If we have some pending data, we continue the processing */
		if (htx_is_empty(htx))
			goto return_srv_abort;
	}

	/* When TE: chunked is used, we need to get there again to parse
	 * remaining chunks even if the server has closed, so we don't want to
	 * set CF_DONTCLOSE. Similarly when there is a content-leng or if there
	 * are filters registered on the stream, we don't want to forward a
	 * close
	 */
	if ((msg->flags & HTTP_MSGF_XFER_LEN) || HAS_RSP_DATA_FILTERS(s))
		channel_dont_close(res);

	/* We know that more data are expected, but we couldn't send more that
	 * what we did. So we always set the CF_EXPECT_MORE flag so that the
	 * system knows it must not set a PUSH on this first part. Interactive
	 * modes are already handled by the stream sock layer. We must not do
	 * this in content-length mode because it could present the MSG_MORE
	 * flag with the last block of forwarded data, which would cause an
	 * additional delay to be observed by the receiver.
	 */
	if (HAS_RSP_DATA_FILTERS(s))
		res->flags |= CF_EXPECT_MORE;

	/* the stream handler will take care of timeouts and errors */
	DBG_TRACE_DEVEL("waiting for more data to forward",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;

  return_srv_abort:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.srv_aborts);
	_HA_ATOMIC_INC(&s->be->be_counters.srv_aborts);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->srv_aborts);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.srv_aborts);
	stream_inc_http_fail_ctr(s);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	goto return_error;

  return_cli_abort:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.cli_aborts);
	_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->cli_aborts);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.cli_aborts);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	goto return_error;

  return_int_err:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.internal_errors);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	goto return_error;

  return_bad_res:
	_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
	if (objt_server(s->target)) {
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
		health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_RSP);
	}
	stream_inc_http_fail_ctr(s);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	/* fall through */

   return_error:
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;
}

/* Perform an HTTP redirect based on the information in <rule>. The function
 * returns zero in case of an irrecoverable error such as too large a request
 * to build a valid response, 1 in case of successful redirect (hence the rule
 * is final), or 2 if the rule has to be silently skipped.
 */
int http_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn)
{
	struct channel *req = &s->req;
	struct channel *res = &s->res;
	struct htx *htx;
	struct htx_sl *sl;
	struct buffer *chunk;
	struct ist status, reason, location;
	unsigned int flags;
	int close = 0; /* Try to keep the connection alive byt default */

	chunk = alloc_trash_chunk();
	if (!chunk) {
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_RESOURCE;
		goto fail;
	}

	/*
	 * Create the location
	 */
	htx = htxbuf(&req->buf);
	switch(rule->type) {
		case REDIRECT_TYPE_SCHEME: {
			struct http_hdr_ctx ctx;
			struct ist path, host;
			struct http_uri_parser parser;

			host = ist("");
			ctx.blk = NULL;
			if (http_find_header(htx, ist("Host"), &ctx, 0))
				host = ctx.value;

			sl = http_get_stline(htx);
			parser = http_uri_parser_init(htx_sl_req_uri(sl));
			path = http_parse_path(&parser);
			/* build message using path */
			if (isttest(path)) {
				if (rule->flags & REDIRECT_FLAG_DROP_QS) {
					int qs = 0;
					while (qs < path.len) {
						if (*(path.ptr + qs) == '?') {
							path.len = qs;
							break;
						}
						qs++;
					}
				}
			}
			else
				path = ist("/");

			if (rule->rdr_str) { /* this is an old "redirect" rule */
				/* add scheme */
				if (!chunk_memcat(chunk, rule->rdr_str, rule->rdr_len))
					goto fail;
			}
			else {
				/* add scheme with executing log format */
				chunk->data += build_logline(s, chunk->area + chunk->data,
							     chunk->size - chunk->data,
							     &rule->rdr_fmt);
			}
			/* add "://" + host + path */
			if (!chunk_memcat(chunk, "://", 3) ||
			    !chunk_memcat(chunk, host.ptr, host.len) ||
			    !chunk_memcat(chunk, path.ptr, path.len))
				goto fail;

			/* append a slash at the end of the location if needed and missing */
			if (chunk->data && chunk->area[chunk->data - 1] != '/' &&
			    (rule->flags & REDIRECT_FLAG_APPEND_SLASH)) {
				if (chunk->data + 1 >= chunk->size)
					goto fail;
				chunk->area[chunk->data++] = '/';
			}
			break;
		}

		case REDIRECT_TYPE_PREFIX: {
			struct ist path;
			struct http_uri_parser parser;

			sl = http_get_stline(htx);
			parser = http_uri_parser_init(htx_sl_req_uri(sl));
			path = http_parse_path(&parser);
			/* build message using path */
			if (isttest(path)) {
				if (rule->flags & REDIRECT_FLAG_DROP_QS) {
					int qs = 0;
					while (qs < path.len) {
						if (*(path.ptr + qs) == '?') {
							path.len = qs;
							break;
						}
						qs++;
					}
				}
			}
			else
				path = ist("/");

			if (rule->rdr_str) { /* this is an old "redirect" rule */
				/* add prefix. Note that if prefix == "/", we don't want to
				 * add anything, otherwise it makes it hard for the user to
				 * configure a self-redirection.
				 */
				if (rule->rdr_len != 1 || *rule->rdr_str != '/') {
					if (!chunk_memcat(chunk, rule->rdr_str, rule->rdr_len))
						goto fail;
				}
			}
			else {
				/* add prefix with executing log format */
				chunk->data += build_logline(s, chunk->area + chunk->data,
							     chunk->size - chunk->data,
							     &rule->rdr_fmt);
			}

			/* add path */
			if (!chunk_memcat(chunk, path.ptr, path.len))
				goto fail;

			/* append a slash at the end of the location if needed and missing */
			if (chunk->data && chunk->area[chunk->data - 1] != '/' &&
			    (rule->flags & REDIRECT_FLAG_APPEND_SLASH)) {
				if (chunk->data + 1 >= chunk->size)
					goto fail;
				chunk->area[chunk->data++] = '/';
			}
			break;
		}
		case REDIRECT_TYPE_LOCATION:
		default:
			if (rule->rdr_str) { /* this is an old "redirect" rule */
				/* add location */
				if (!chunk_memcat(chunk, rule->rdr_str, rule->rdr_len))
					goto fail;
			}
			else {
				/* add location with executing log format */
				int len = build_logline(s, chunk->area + chunk->data,
				                        chunk->size - chunk->data,
				                        &rule->rdr_fmt);
				if (!len && rule->flags & REDIRECT_FLAG_IGNORE_EMPTY)
					return 2;

				chunk->data += len;
			}
			break;
	}
	location = ist2(chunk->area, chunk->data);

	/*
	 * Create the 30x response
	 */
	switch (rule->code) {
		case 308:
			status = ist("308");
			reason = ist("Permanent Redirect");
			break;
		case 307:
			status = ist("307");
			reason = ist("Temporary Redirect");
			break;
		case 303:
			status = ist("303");
			reason = ist("See Other");
			break;
		case 301:
			status = ist("301");
			reason = ist("Moved Permanently");
			break;
		case 302:
		default:
			status = ist("302");
			reason = ist("Found");
			break;
	}

	if (!(txn->req.flags & HTTP_MSGF_BODYLESS) && txn->req.msg_state != HTTP_MSG_DONE)
		close = 1;

	htx = htx_from_buf(&res->buf);
	/* Trim any possible response */
	channel_htx_truncate(&s->res, htx);
	flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), status, reason);
	if (!sl)
		goto fail;
	sl->info.res.status = rule->code;
	s->txn->status = rule->code;

	if (close && !htx_add_header(htx, ist("Connection"), ist("close")))
		goto fail;

	if (!htx_add_header(htx, ist("Content-length"), ist("0")) ||
	    !htx_add_header(htx, ist("Location"), location))
		goto fail;

	if (rule->code == 302 || rule->code == 303 || rule->code == 307) {
		if (!htx_add_header(htx, ist("Cache-Control"), ist("no-cache")))
			goto fail;
	}

	if (rule->cookie_len) {
		if (!htx_add_header(htx, ist("Set-Cookie"), ist2(rule->cookie_str, rule->cookie_len)))
			goto fail;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto fail;

	htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &res->buf);
	if (!http_forward_proxy_resp(s, 1))
		goto fail;

	if (rule->flags & REDIRECT_FLAG_FROM_REQ) {
		/* let's log the request time */
		s->logs.tv_request = now;
		req->analysers &= AN_REQ_FLT_END;

		if (s->sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			_HA_ATOMIC_INC(&s->sess->fe->fe_counters.intercepted_req);
	}

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_LOCAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= ((rule->flags & REDIRECT_FLAG_FROM_REQ) ? SF_FINST_R : SF_FINST_H);

	free_trash_chunk(chunk);
	return 1;

  fail:
	/* If an error occurred, remove the incomplete HTTP response from the
	 * buffer */
	channel_htx_truncate(res, htxbuf(&res->buf));
	free_trash_chunk(chunk);
	return 0;
}

/* Replace all headers matching the name <name>. The header value is replaced if
 * it matches the regex <re>. <str> is used for the replacement. If <full> is
 * set to 1, the full-line is matched and replaced. Otherwise, comma-separated
 * values are evaluated one by one. It returns 0 on success and -1 on error.
 */
int http_replace_hdrs(struct stream* s, struct htx *htx, struct ist name,
		     const char *str, struct my_regex *re, int full)
{
	struct http_hdr_ctx ctx;
	struct buffer *output = get_trash_chunk();

	ctx.blk = NULL;
	while (http_find_header(htx, name, &ctx, full)) {
		if (!regex_exec_match2(re, ctx.value.ptr, ctx.value.len, MAX_MATCH, pmatch, 0))
			continue;

		output->data = exp_replace(output->area, output->size, ctx.value.ptr, str, pmatch);
		if (output->data == -1)
			return -1;
		if (!http_replace_header_value(htx, &ctx, ist2(output->area, output->data)))
			return -1;
	}
	return 0;
}

/* This function executes one of the set-{method,path,query,uri} actions. It
 * takes the string from the variable 'replace' with length 'len', then modifies
 * the relevant part of the request line accordingly. Then it updates various
 * pointers to the next elements which were moved, and the total buffer length.
 * It finds the action to be performed in p[2], previously filled by function
 * parse_set_req_line(). It returns 0 in case of success, -1 in case of internal
 * error, though this can be revisited when this code is finally exploited.
 *
 * 'action' can be '0' to replace method, '1' to replace path, '2' to replace
 * query string, 3 to replace uri or 4 to replace the path+query.
 *
 * In query string case, the mark question '?' must be set at the start of the
 * string by the caller, event if the replacement query string is empty.
 */
int http_req_replace_stline(int action, const char *replace, int len,
			    struct proxy *px, struct stream *s)
{
	struct htx *htx = htxbuf(&s->req.buf);

	switch (action) {
		case 0: // method
			if (!http_replace_req_meth(htx, ist2(replace, len)))
				return -1;
			break;

		case 1: // path
			if (!http_replace_req_path(htx, ist2(replace, len), 0))
				return -1;
			break;

		case 2: // query
			if (!http_replace_req_query(htx, ist2(replace, len)))
				return -1;
			break;

		case 3: // uri
			if (!http_replace_req_uri(htx, ist2(replace, len)))
				return -1;
			break;

		case 4: // path + query
			if (!http_replace_req_path(htx, ist2(replace, len), 1))
				return -1;
			break;

		default:
			return -1;
	}
	return 0;
}

/* This function replace the HTTP status code and the associated message. The
 * variable <status> contains the new status code. This function never fails. It
 * returns 0 in case of success, -1 in case of internal error.
 */
int http_res_set_status(unsigned int status, struct ist reason, struct stream *s)
{
	struct htx *htx = htxbuf(&s->res.buf);
	char *res;

	chunk_reset(&trash);
	res = ultoa_o(status, trash.area, trash.size);
	trash.data = res - trash.area;

	/* Do we have a custom reason format string? */
	if (!isttest(reason)) {
		const char *str = http_get_reason(status);
		reason = ist(str);
	}

	if (!http_replace_res_status(htx, ist2(trash.area, trash.data), reason))
		return -1;
	return 0;
}

/* Executes the http-request rules <rules> for stream <s>, proxy <px> and
 * transaction <txn>. Returns the verdict of the first rule that prevents
 * further processing of the request (auth, deny, ...), and defaults to
 * HTTP_RULE_RES_STOP if it executed all rules or stopped on an allow, or
 * HTTP_RULE_RES_CONT if the last rule was reached. It may set the TX_CLTARPIT
 * on txn->flags if it encounters a tarpit rule. If <deny_status> is not NULL
 * and a deny/tarpit rule is matched, it will be filled with this rule's deny
 * status.
 */
static enum rule_result http_req_get_intercept_rule(struct proxy *px, struct list *def_rules,
						    struct list *rules, struct stream *s)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct act_rule *rule;
	enum rule_result rule_ret = HTTP_RULE_RES_CONT;
	int act_opts = 0;

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == rules || (def_rules && s->current_rule_list == def_rules))
			goto resume_execution;
	}
	s->current_rule_list = ((!def_rules || s->current_rule_list == def_rules) ? rules : def_rules);

  restart:
	/* start the ruleset evaluation in strict mode */
	txn->req.flags &= ~HTTP_MSGF_SOFT_RW;

	list_for_each_entry(rule, s->current_rule_list, list) {
		/* check optional condition */
		if (rule->cond) {
			int ret;

			ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);

			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (!ret) /* condition not matched */
				continue;
		}

		act_opts |= ACT_OPT_FIRST;
  resume_execution:
		if (rule->kw->flags & KWF_EXPERIMENTAL)
			mark_tainted(TAINTED_ACTION_EXP_EXECUTED);

		/* Always call the action function if defined */
		if (rule->action_ptr) {
			if ((s->req.flags & CF_READ_ERROR) ||
			    ((s->req.flags & (CF_SHUTR|CF_READ_NULL)) &&
			     (px->options & PR_O_ABRT_CLOSE)))
				act_opts |= ACT_OPT_FINAL;

			switch (rule->action_ptr(rule, px, sess, s, act_opts)) {
				case ACT_RET_CONT:
					break;
				case ACT_RET_STOP:
					rule_ret = HTTP_RULE_RES_STOP;
					goto end;
				case ACT_RET_YIELD:
					s->current_rule = rule;
					rule_ret = HTTP_RULE_RES_YIELD;
					goto end;
				case ACT_RET_ERR:
					rule_ret = HTTP_RULE_RES_ERROR;
					goto end;
				case ACT_RET_DONE:
					rule_ret = HTTP_RULE_RES_DONE;
					goto end;
				case ACT_RET_DENY:
					if (txn->status == -1)
						txn->status = 403;
					rule_ret = HTTP_RULE_RES_DENY;
					goto end;
				case ACT_RET_ABRT:
					rule_ret = HTTP_RULE_RES_ABRT;
					goto end;
				case ACT_RET_INV:
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
			}
			continue; /* eval the next rule */
		}

		/* If not action function defined, check for known actions */
		switch (rule->action) {
			case ACT_ACTION_ALLOW:
				rule_ret = HTTP_RULE_RES_STOP;
				goto end;

			case ACT_ACTION_DENY:
				txn->status = rule->arg.http_reply->status;
				txn->http_reply = rule->arg.http_reply;
				rule_ret = HTTP_RULE_RES_DENY;
				goto end;

			case ACT_HTTP_REQ_TARPIT:
				txn->flags |= TX_CLTARPIT;
				txn->status = rule->arg.http_reply->status;
				txn->http_reply = rule->arg.http_reply;
				rule_ret = HTTP_RULE_RES_DENY;
				goto end;

			case ACT_HTTP_REDIR: {
				int ret = http_apply_redirect_rule(rule->arg.redir, s, txn);

				if (ret == 2) // 2 == skip
					break;

				rule_ret = ret ? HTTP_RULE_RES_ABRT : HTTP_RULE_RES_ERROR;
				goto end;
			}

			/* other flags exists, but normally, they never be matched. */
			default:
				break;
		}
	}

	if (def_rules && s->current_rule_list == def_rules) {
		s->current_rule_list = rules;
		goto restart;
	}

  end:
	/* if the ruleset evaluation is finished reset the strict mode */
	if (rule_ret != HTTP_RULE_RES_YIELD)
		txn->req.flags &= ~HTTP_MSGF_SOFT_RW;

	/* we reached the end of the rules, nothing to report */
	return rule_ret;
}

/* Executes the http-response rules <rules> for stream <s> and proxy <px>. It
 * returns one of 5 possible statuses: HTTP_RULE_RES_CONT, HTTP_RULE_RES_STOP,
 * HTTP_RULE_RES_DONE, HTTP_RULE_RES_YIELD, or HTTP_RULE_RES_BADREQ. If *CONT
 * is returned, the process can continue the evaluation of next rule list. If
 * *STOP or *DONE is returned, the process must stop the evaluation. If *BADREQ
 * is returned, it means the operation could not be processed and a server error
 * must be returned. If *YIELD is returned, the caller must call again the
 * function with the same context.
 */
static enum rule_result http_res_get_intercept_rule(struct proxy *px, struct list *def_rules,
						    struct list *rules, struct stream *s)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct act_rule *rule;
	enum rule_result rule_ret = HTTP_RULE_RES_CONT;
	int act_opts = 0;

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == rules || (def_rules && s->current_rule_list == def_rules))
			goto resume_execution;
	}
	s->current_rule_list = ((!def_rules || s->current_rule_list == def_rules) ? rules : def_rules);

  restart:

	/* start the ruleset evaluation in strict mode */
	txn->rsp.flags &= ~HTTP_MSGF_SOFT_RW;

	list_for_each_entry(rule, s->current_rule_list, list) {
		/* check optional condition */
		if (rule->cond) {
			int ret;

			ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
			ret = acl_pass(ret);

			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (!ret) /* condition not matched */
				continue;
		}

		act_opts |= ACT_OPT_FIRST;
resume_execution:
		if (rule->kw->flags & KWF_EXPERIMENTAL)
			mark_tainted(TAINTED_ACTION_EXP_EXECUTED);

		/* Always call the action function if defined */
		if (rule->action_ptr) {
			if ((s->req.flags & CF_READ_ERROR) ||
			    ((s->req.flags & (CF_SHUTR|CF_READ_NULL)) &&
			     (px->options & PR_O_ABRT_CLOSE)))
				act_opts |= ACT_OPT_FINAL;

			switch (rule->action_ptr(rule, px, sess, s, act_opts)) {
				case ACT_RET_CONT:
					break;
				case ACT_RET_STOP:
					rule_ret = HTTP_RULE_RES_STOP;
					goto end;
				case ACT_RET_YIELD:
					s->current_rule = rule;
					rule_ret = HTTP_RULE_RES_YIELD;
					goto end;
				case ACT_RET_ERR:
					rule_ret = HTTP_RULE_RES_ERROR;
					goto end;
				case ACT_RET_DONE:
					rule_ret = HTTP_RULE_RES_DONE;
					goto end;
				case ACT_RET_DENY:
					if (txn->status == -1)
						txn->status = 502;
					rule_ret = HTTP_RULE_RES_DENY;
					goto end;
				case ACT_RET_ABRT:
					rule_ret = HTTP_RULE_RES_ABRT;
					goto end;
				case ACT_RET_INV:
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
			}
			continue; /* eval the next rule */
		}

		/* If not action function defined, check for known actions */
		switch (rule->action) {
			case ACT_ACTION_ALLOW:
				rule_ret = HTTP_RULE_RES_STOP; /* "allow" rules are OK */
				goto end;

			case ACT_ACTION_DENY:
				txn->status = rule->arg.http_reply->status;
				txn->http_reply = rule->arg.http_reply;
				rule_ret = HTTP_RULE_RES_DENY;
				goto end;

			case ACT_HTTP_REDIR: {
				int ret = http_apply_redirect_rule(rule->arg.redir, s, txn);

				if (ret == 2) // 2 == skip
					break;

				rule_ret = ret ? HTTP_RULE_RES_ABRT : HTTP_RULE_RES_ERROR;
				goto end;
			}
			/* other flags exists, but normally, they never be matched. */
			default:
				break;
		}
	}

	if (def_rules && s->current_rule_list == def_rules) {
		s->current_rule_list = rules;
		goto restart;
	}

  end:
	/* if the ruleset evaluation is finished reset the strict mode */
	if (rule_ret != HTTP_RULE_RES_YIELD)
		txn->rsp.flags &= ~HTTP_MSGF_SOFT_RW;

	/* we reached the end of the rules, nothing to report */
	return rule_ret;
}

/* Executes backend and frontend http-after-response rules for the stream <s>,
 * in that order. it return 1 on success and 0 on error. It is the caller
 * responsibility to catch error or ignore it. If it catches it, this function
 * may be called a second time, for the internal error.
 */
int http_eval_after_res_rules(struct stream *s)
{
	struct list *def_rules, *rules;
	struct session *sess = s->sess;
	enum rule_result ret = HTTP_RULE_RES_CONT;

	/* Eval after-response ruleset only if the reply is not const */
	if (s->txn->flags & TX_CONST_REPLY)
		goto end;

	/* prune the request variables if not already done and swap to the response variables. */
	if (s->vars_reqres.scope != SCOPE_RES) {
		if (!LIST_ISEMPTY(&s->vars_reqres.head))
			vars_prune(&s->vars_reqres, s->sess, s);
		vars_init_head(&s->vars_reqres, SCOPE_RES);
	}

	def_rules = (s->be->defpx ? &s->be->defpx->http_after_res_rules : NULL);
	rules = &s->be->http_after_res_rules;

	ret = http_res_get_intercept_rule(s->be, def_rules, rules, s);
	if ((ret == HTTP_RULE_RES_CONT || ret == HTTP_RULE_RES_STOP) && sess->fe != s->be) {
		def_rules = ((sess->fe->defpx && sess->fe->defpx != s->be->defpx) ? &sess->fe->defpx->http_after_res_rules : NULL);
		rules = &sess->fe->http_after_res_rules;
		ret = http_res_get_intercept_rule(sess->fe, def_rules, rules, s);
	}

  end:
	/* All other codes than CONTINUE, STOP or DONE are forbidden */
	return (ret == HTTP_RULE_RES_CONT || ret == HTTP_RULE_RES_STOP || ret == HTTP_RULE_RES_DONE);
}

/*
 * Manage client-side cookie. It can impact performance by about 2% so it is
 * desirable to call it only when needed. This code is quite complex because
 * of the multiple very crappy and ambiguous syntaxes we have to support. it
 * highly recommended not to touch this part without a good reason !
 */
static void http_manage_client_side_cookies(struct stream *s, struct channel *req)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct htx *htx;
	struct http_hdr_ctx ctx;
	char *hdr_beg, *hdr_end, *del_from;
	char *prev, *att_beg, *att_end, *equal, *val_beg, *val_end, *next;
	int preserve_hdr;

	htx = htxbuf(&req->buf);
	ctx.blk = NULL;
	while (http_find_header(htx, ist("Cookie"), &ctx, 1)) {
		int is_first = 1;
		del_from = NULL;  /* nothing to be deleted */
		preserve_hdr = 0; /* assume we may kill the whole header */

		/* Now look for cookies. Conforming to RFC2109, we have to support
		 * attributes whose name begin with a '$', and associate them with
		 * the right cookie, if we want to delete this cookie.
		 * So there are 3 cases for each cookie read :
		 * 1) it's a special attribute, beginning with a '$' : ignore it.
		 * 2) it's a server id cookie that we *MAY* want to delete : save
		 *    some pointers on it (last semi-colon, beginning of cookie...)
		 * 3) it's an application cookie : we *MAY* have to delete a previous
		 *    "special" cookie.
		 * At the end of loop, if a "special" cookie remains, we may have to
		 * remove it. If no application cookie persists in the header, we
		 * *MUST* delete it.
		 *
		 * Note: RFC2965 is unclear about the processing of spaces around
		 * the equal sign in the ATTR=VALUE form. A careful inspection of
		 * the RFC explicitly allows spaces before it, and not within the
		 * tokens (attrs or values). An inspection of RFC2109 allows that
		 * too but section 10.1.3 lets one think that spaces may be allowed
		 * after the equal sign too, resulting in some (rare) buggy
		 * implementations trying to do that. So let's do what servers do.
		 * Latest ietf draft forbids spaces all around. Also, earlier RFCs
		 * allowed quoted strings in values, with any possible character
		 * after a backslash, including control chars and delimiters, which
		 * causes parsing to become ambiguous. Browsers also allow spaces
		 * within values even without quotes.
		 *
		 * We have to keep multiple pointers in order to support cookie
		 * removal at the beginning, middle or end of header without
		 * corrupting the header. All of these headers are valid :
		 *
		 * hdr_beg                                               hdr_end
		 * |                                                        |
		 * v                                                        |
		 * NAME1=VALUE1;NAME2=VALUE2;NAME3=VALUE3                   |
		 * NAME1=VALUE1;NAME2_ONLY ;NAME3=VALUE3                    v
		 *      NAME1  =  VALUE 1  ; NAME2 = VALUE2 ; NAME3 = VALUE3
		 * |    |    | |  |      | |
		 * |    |    | |  |      | |
		 * |    |    | |  |      | +--> next
		 * |    |    | |  |      +----> val_end
		 * |    |    | |  +-----------> val_beg
		 * |    |    | +--------------> equal
		 * |    |    +----------------> att_end
		 * |    +---------------------> att_beg
		 * +--------------------------> prev
		 *
		 */
		hdr_beg = ctx.value.ptr;
		hdr_end = hdr_beg + ctx.value.len;
		for (prev = hdr_beg; prev < hdr_end; prev = next) {
			/* Iterate through all cookies on this line */

			/* find att_beg */
			att_beg = prev;
			if (!is_first)
				att_beg++;
			is_first = 0;

			while (att_beg < hdr_end && HTTP_IS_SPHT(*att_beg))
				att_beg++;

			/* find att_end : this is the first character after the last non
			 * space before the equal. It may be equal to hdr_end.
			 */
			equal = att_end = att_beg;
			while (equal < hdr_end) {
				if (*equal == '=' || *equal == ',' || *equal == ';')
					break;
				if (HTTP_IS_SPHT(*equal++))
					continue;
				att_end = equal;
			}

			/* here, <equal> points to '=', a delimiter or the end. <att_end>
			 * is between <att_beg> and <equal>, both may be identical.
			 */
			/* look for end of cookie if there is an equal sign */
			if (equal < hdr_end && *equal == '=') {
				/* look for the beginning of the value */
				val_beg = equal + 1;
				while (val_beg < hdr_end && HTTP_IS_SPHT(*val_beg))
					val_beg++;

				/* find the end of the value, respecting quotes */
				next = http_find_cookie_value_end(val_beg, hdr_end);

				/* make val_end point to the first white space or delimiter after the value */
				val_end = next;
				while (val_end > val_beg && HTTP_IS_SPHT(*(val_end - 1)))
					val_end--;
			}
			else
				val_beg = val_end = next = equal;

			/* We have nothing to do with attributes beginning with
			 * '$'. However, they will automatically be removed if a
			 * header before them is removed, since they're supposed
			 * to be linked together.
			 */
			if (*att_beg == '$')
				continue;

			/* Ignore cookies with no equal sign */
			if (equal == next) {
				/* This is not our cookie, so we must preserve it. But if we already
				 * scheduled another cookie for removal, we cannot remove the
				 * complete header, but we can remove the previous block itself.
				 */
				preserve_hdr = 1;
				if (del_from != NULL) {
					int delta = http_del_hdr_value(hdr_beg, hdr_end, &del_from, prev);
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					prev     = del_from;
					del_from = NULL;
				}
				continue;
			}

			/* if there are spaces around the equal sign, we need to
			 * strip them otherwise we'll get trouble for cookie captures,
			 * or even for rewrites. Since this happens extremely rarely,
			 * it does not hurt performance.
			 */
			if (unlikely(att_end != equal || val_beg > equal + 1)) {
				int stripped_before = 0;
				int stripped_after = 0;

				if (att_end != equal) {
					memmove(att_end, equal, hdr_end - equal);
					stripped_before = (att_end - equal);
					equal   += stripped_before;
					val_beg += stripped_before;
				}

				if (val_beg > equal + 1) {
					memmove(equal + 1, val_beg, hdr_end + stripped_before - val_beg);
					stripped_after = (equal + 1) - val_beg;
					val_beg += stripped_after;
					stripped_before += stripped_after;
				}

				val_end      += stripped_before;
				next         += stripped_before;
				hdr_end      += stripped_before;
			}
			/* now everything is as on the diagram above */

			/* First, let's see if we want to capture this cookie. We check
			 * that we don't already have a client side cookie, because we
			 * can only capture one. Also as an optimisation, we ignore
			 * cookies shorter than the declared name.
			 */
			if (sess->fe->capture_name != NULL && txn->cli_cookie == NULL &&
			    (val_end - att_beg >= sess->fe->capture_namelen) &&
			    memcmp(att_beg, sess->fe->capture_name, sess->fe->capture_namelen) == 0) {
				int log_len = val_end - att_beg;

				if ((txn->cli_cookie = pool_alloc(pool_head_capture)) == NULL) {
					ha_alert("HTTP logging : out of memory.\n");
				} else {
					if (log_len > sess->fe->capture_len)
						log_len = sess->fe->capture_len;
					memcpy(txn->cli_cookie, att_beg, log_len);
					txn->cli_cookie[log_len] = 0;
				}
			}

			/* Persistence cookies in passive, rewrite or insert mode have the
			 * following form :
			 *
			 *    Cookie: NAME=SRV[|<lastseen>[|<firstseen>]]
			 *
			 * For cookies in prefix mode, the form is :
			 *
			 *    Cookie: NAME=SRV~VALUE
			 */
			if ((att_end - att_beg == s->be->cookie_len) && (s->be->cookie_name != NULL) &&
			    (memcmp(att_beg, s->be->cookie_name, att_end - att_beg) == 0)) {
				struct server *srv = s->be->srv;
				char *delim;

				/* if we're in cookie prefix mode, we'll search the delimiter so that we
				 * have the server ID between val_beg and delim, and the original cookie between
				 * delim+1 and val_end. Otherwise, delim==val_end :
				 *
				 * hdr_beg
				 * |
				 * v
				 * NAME=SRV;          # in all but prefix modes
				 * NAME=SRV~OPAQUE ;  # in prefix mode
				 * ||   ||  |      |+-> next
				 * ||   ||  |      +--> val_end
				 * ||   ||  +---------> delim
				 * ||   |+------------> val_beg
				 * ||   +-------------> att_end = equal
				 * |+-----------------> att_beg
				 * +------------------> prev
				 *
				 */
				if (s->be->ck_opts & PR_CK_PFX) {
					for (delim = val_beg; delim < val_end; delim++)
						if (*delim == COOKIE_DELIM)
							break;
				}
				else {
					char *vbar1;
					delim = val_end;
					/* Now check if the cookie contains a date field, which would
					 * appear after a vertical bar ('|') just after the server name
					 * and before the delimiter.
					 */
					vbar1 = memchr(val_beg, COOKIE_DELIM_DATE, val_end - val_beg);
					if (vbar1) {
						/* OK, so left of the bar is the server's cookie and
						 * right is the last seen date. It is a base64 encoded
						 * 30-bit value representing the UNIX date since the
						 * epoch in 4-second quantities.
						 */
						int val;
						delim = vbar1++;
						if (val_end - vbar1 >= 5) {
							val = b64tos30(vbar1);
							if (val > 0)
								txn->cookie_last_date = val << 2;
						}
						/* look for a second vertical bar */
						vbar1 = memchr(vbar1, COOKIE_DELIM_DATE, val_end - vbar1);
						if (vbar1 && (val_end - vbar1 > 5)) {
							val = b64tos30(vbar1 + 1);
							if (val > 0)
								txn->cookie_first_date = val << 2;
						}
					}
				}

				/* if the cookie has an expiration date and the proxy wants to check
				 * it, then we do that now. We first check if the cookie is too old,
				 * then only if it has expired. We detect strict overflow because the
				 * time resolution here is not great (4 seconds). Cookies with dates
				 * in the future are ignored if their offset is beyond one day. This
				 * allows an admin to fix timezone issues without expiring everyone
				 * and at the same time avoids keeping unwanted side effects for too
				 * long.
				 */
				if (txn->cookie_first_date && s->be->cookie_maxlife &&
				    (((signed)(date.tv_sec - txn->cookie_first_date) > (signed)s->be->cookie_maxlife) ||
				     ((signed)(txn->cookie_first_date - date.tv_sec) > 86400))) {
					txn->flags &= ~TX_CK_MASK;
					txn->flags |= TX_CK_OLD;
					delim = val_beg; // let's pretend we have not found the cookie
					txn->cookie_first_date = 0;
					txn->cookie_last_date = 0;
				}
				else if (txn->cookie_last_date && s->be->cookie_maxidle &&
					 (((signed)(date.tv_sec - txn->cookie_last_date) > (signed)s->be->cookie_maxidle) ||
					  ((signed)(txn->cookie_last_date - date.tv_sec) > 86400))) {
					txn->flags &= ~TX_CK_MASK;
					txn->flags |= TX_CK_EXPIRED;
					delim = val_beg; // let's pretend we have not found the cookie
					txn->cookie_first_date = 0;
					txn->cookie_last_date = 0;
				}

				/* Here, we'll look for the first running server which supports the cookie.
				 * This allows to share a same cookie between several servers, for example
				 * to dedicate backup servers to specific servers only.
				 * However, to prevent clients from sticking to cookie-less backup server
				 * when they have incidentely learned an empty cookie, we simply ignore
				 * empty cookies and mark them as invalid.
				 * The same behaviour is applied when persistence must be ignored.
				 */
				if ((delim == val_beg) || (s->flags & (SF_IGNORE_PRST | SF_ASSIGNED)))
					srv = NULL;

				while (srv) {
					if (srv->cookie && (srv->cklen == delim - val_beg) &&
					    !memcmp(val_beg, srv->cookie, delim - val_beg)) {
						if ((srv->cur_state != SRV_ST_STOPPED) ||
						    (s->be->options & PR_O_PERSIST) ||
						    (s->flags & SF_FORCE_PRST)) {
							/* we found the server and we can use it */
							txn->flags &= ~TX_CK_MASK;
							txn->flags |= (srv->cur_state != SRV_ST_STOPPED) ? TX_CK_VALID : TX_CK_DOWN;
							s->flags |= SF_DIRECT | SF_ASSIGNED;
							s->target = &srv->obj_type;
							break;
						} else {
							/* we found a server, but it's down,
							 * mark it as such and go on in case
							 * another one is available.
							 */
							txn->flags &= ~TX_CK_MASK;
							txn->flags |= TX_CK_DOWN;
						}
					}
					srv = srv->next;
				}

				if (!srv && !(txn->flags & (TX_CK_DOWN|TX_CK_EXPIRED|TX_CK_OLD))) {
					/* no server matched this cookie or we deliberately skipped it */
					txn->flags &= ~TX_CK_MASK;
					if ((s->flags & (SF_IGNORE_PRST | SF_ASSIGNED)))
						txn->flags |= TX_CK_UNUSED;
					else
						txn->flags |= TX_CK_INVALID;
				}

				/* depending on the cookie mode, we may have to either :
				 * - delete the complete cookie if we're in insert+indirect mode, so that
				 *   the server never sees it ;
				 * - remove the server id from the cookie value, and tag the cookie as an
				 *   application cookie so that it does not get accidentally removed later,
				 *   if we're in cookie prefix mode
				 */
				if ((s->be->ck_opts & PR_CK_PFX) && (delim != val_end)) {
					int delta; /* negative */

					memmove(val_beg, delim + 1, hdr_end - (delim + 1));
					delta = val_beg - (delim + 1);
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					del_from = NULL;
					preserve_hdr = 1; /* we want to keep this cookie */
				}
				else if (del_from == NULL &&
					 (s->be->ck_opts & (PR_CK_INS | PR_CK_IND)) == (PR_CK_INS | PR_CK_IND)) {
					del_from = prev;
				}
			}
			else {
				/* This is not our cookie, so we must preserve it. But if we already
				 * scheduled another cookie for removal, we cannot remove the
				 * complete header, but we can remove the previous block itself.
				 */
				preserve_hdr = 1;

				if (del_from != NULL) {
					int delta = http_del_hdr_value(hdr_beg, hdr_end, &del_from, prev);
					if (att_beg >= del_from)
						att_beg += delta;
					if (att_end >= del_from)
						att_end += delta;
					val_beg  += delta;
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					prev     = del_from;
					del_from = NULL;
				}
			}

		} /* for each cookie */


		/* There are no more cookies on this line.
		 * We may still have one (or several) marked for deletion at the
		 * end of the line. We must do this now in two ways :
		 *  - if some cookies must be preserved, we only delete from the
		 *    mark to the end of line ;
		 *  - if nothing needs to be preserved, simply delete the whole header
		 */
		if (del_from) {
			hdr_end = (preserve_hdr ? del_from : hdr_beg);
		}
		if ((hdr_end - hdr_beg) != ctx.value.len) {
			if (hdr_beg != hdr_end)
				htx_change_blk_value_len(htx, ctx.blk, hdr_end - hdr_beg);
			else
				http_remove_header(htx, &ctx);
		}
	} /* for each "Cookie header */
}

/*
 * Manage server-side cookies. It can impact performance by about 2% so it is
 * desirable to call it only when needed. This function is also used when we
 * just need to know if there is a cookie (eg: for check-cache).
 */
static void http_manage_server_side_cookies(struct stream *s, struct channel *res)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct htx *htx;
	struct http_hdr_ctx ctx;
	struct server *srv;
	char *hdr_beg, *hdr_end;
	char *prev, *att_beg, *att_end, *equal, *val_beg, *val_end, *next;
	int is_cookie2 = 0;

	htx = htxbuf(&res->buf);

	ctx.blk = NULL;
	while (1) {
		int is_first = 1;

		if (!http_find_header(htx, ist("Set-Cookie"), &ctx, 1)) {
			if (!http_find_header(htx, ist("Set-Cookie2"), &ctx, 1))
				break;
			is_cookie2 = 1;
		}

		/* OK, right now we know we have a Set-Cookie* at hdr_beg, and
		 * <prev> points to the colon.
		 */
		txn->flags |= TX_SCK_PRESENT;

		/* Maybe we only wanted to see if there was a Set-Cookie (eg:
		 * check-cache is enabled) and we are not interested in checking
		 * them. Warning, the cookie capture is declared in the frontend.
		 */
		if (s->be->cookie_name == NULL && sess->fe->capture_name == NULL)
			break;

		/* OK so now we know we have to process this response cookie.
		 * The format of the Set-Cookie header is slightly different
		 * from the format of the Cookie header in that it does not
		 * support the comma as a cookie delimiter (thus the header
		 * cannot be folded) because the Expires attribute described in
		 * the original Netscape's spec may contain an unquoted date
		 * with a comma inside. We have to live with this because
		 * many browsers don't support Max-Age and some browsers don't
		 * support quoted strings. However the Set-Cookie2 header is
		 * clean.
		 *
		 * We have to keep multiple pointers in order to support cookie
		 * removal at the beginning, middle or end of header without
		 * corrupting the header (in case of set-cookie2). A special
		 * pointer, <scav> points to the beginning of the set-cookie-av
		 * fields after the first semi-colon. The <next> pointer points
		 * either to the end of line (set-cookie) or next unquoted comma
		 * (set-cookie2). All of these headers are valid :
		 *
		 * hdr_beg                                                  hdr_end
		 * |                                                           |
		 * v                                                           |
		 * NAME1  =  VALUE 1  ; Secure; Path="/"                       |
		 * NAME=VALUE; Secure; Expires=Thu, 01-Jan-1970 00:00:01 GMT   v
		 * NAME = VALUE ; Secure; Expires=Thu, 01-Jan-1970 00:00:01 GMT
		 * NAME1 = VALUE 1 ; Max-Age=0, NAME2=VALUE2; Discard
		 * | |   | | |     | |          |
		 * | |   | | |     | |          +-> next
		 * | |   | | |     | +------------> scav
		 * | |   | | |     +--------------> val_end
		 * | |   | | +--------------------> val_beg
		 * | |   | +----------------------> equal
		 * | |   +------------------------> att_end
		 * | +----------------------------> att_beg
		 * +------------------------------> prev
		 * -------------------------------> hdr_beg
		 */
		hdr_beg = ctx.value.ptr;
		hdr_end = hdr_beg + ctx.value.len;
		for (prev = hdr_beg; prev < hdr_end; prev = next) {

			/* Iterate through all cookies on this line */

			/* find att_beg */
			att_beg = prev;
			if (!is_first)
				att_beg++;
			is_first = 0;

			while (att_beg < hdr_end && HTTP_IS_SPHT(*att_beg))
				att_beg++;

			/* find att_end : this is the first character after the last non
			 * space before the equal. It may be equal to hdr_end.
			 */
			equal = att_end = att_beg;

			while (equal < hdr_end) {
				if (*equal == '=' || *equal == ';' || (is_cookie2 && *equal == ','))
					break;
				if (HTTP_IS_SPHT(*equal++))
					continue;
				att_end = equal;
			}

			/* here, <equal> points to '=', a delimiter or the end. <att_end>
			 * is between <att_beg> and <equal>, both may be identical.
			 */

			/* look for end of cookie if there is an equal sign */
			if (equal < hdr_end && *equal == '=') {
				/* look for the beginning of the value */
				val_beg = equal + 1;
				while (val_beg < hdr_end && HTTP_IS_SPHT(*val_beg))
					val_beg++;

				/* find the end of the value, respecting quotes */
				next = http_find_cookie_value_end(val_beg, hdr_end);

				/* make val_end point to the first white space or delimiter after the value */
				val_end = next;
				while (val_end > val_beg && HTTP_IS_SPHT(*(val_end - 1)))
					val_end--;
			}
			else {
				/* <equal> points to next comma, semi-colon or EOL */
				val_beg = val_end = next = equal;
			}

			if (next < hdr_end) {
				/* Set-Cookie2 supports multiple cookies, and <next> points to
				 * a colon or semi-colon before the end. So skip all attr-value
				 * pairs and look for the next comma. For Set-Cookie, since
				 * commas are permitted in values, skip to the end.
				 */
				if (is_cookie2)
					next = http_find_hdr_value_end(next, hdr_end);
				else
					next = hdr_end;
			}

			/* Now everything is as on the diagram above */

			/* Ignore cookies with no equal sign */
			if (equal == val_end)
				continue;

			/* If there are spaces around the equal sign, we need to
			 * strip them otherwise we'll get trouble for cookie captures,
			 * or even for rewrites. Since this happens extremely rarely,
			 * it does not hurt performance.
			 */
			if (unlikely(att_end != equal || val_beg > equal + 1)) {
				int stripped_before = 0;
				int stripped_after = 0;

				if (att_end != equal) {
					memmove(att_end, equal, hdr_end - equal);
					stripped_before = (att_end - equal);
					equal   += stripped_before;
					val_beg += stripped_before;
				}

				if (val_beg > equal + 1) {
					memmove(equal + 1, val_beg, hdr_end + stripped_before - val_beg);
					stripped_after = (equal + 1) - val_beg;
					val_beg += stripped_after;
					stripped_before += stripped_after;
				}

				val_end      += stripped_before;
				next         += stripped_before;
				hdr_end      += stripped_before;

				htx_change_blk_value_len(htx, ctx.blk, hdr_end - hdr_beg);
				ctx.value.len = hdr_end - hdr_beg;
			}

			/* First, let's see if we want to capture this cookie. We check
			 * that we don't already have a server side cookie, because we
			 * can only capture one. Also as an optimisation, we ignore
			 * cookies shorter than the declared name.
			 */
			if (sess->fe->capture_name != NULL &&
			    txn->srv_cookie == NULL &&
			    (val_end - att_beg >= sess->fe->capture_namelen) &&
			    memcmp(att_beg, sess->fe->capture_name, sess->fe->capture_namelen) == 0) {
				int log_len = val_end - att_beg;
				if ((txn->srv_cookie = pool_alloc(pool_head_capture)) == NULL) {
					ha_alert("HTTP logging : out of memory.\n");
				}
				else {
					if (log_len > sess->fe->capture_len)
						log_len = sess->fe->capture_len;
					memcpy(txn->srv_cookie, att_beg, log_len);
					txn->srv_cookie[log_len] = 0;
				}
			}

			srv = objt_server(s->target);
			/* now check if we need to process it for persistence */
			if (!(s->flags & SF_IGNORE_PRST) &&
			    (att_end - att_beg == s->be->cookie_len) && (s->be->cookie_name != NULL) &&
			    (memcmp(att_beg, s->be->cookie_name, att_end - att_beg) == 0)) {
				/* assume passive cookie by default */
				txn->flags &= ~TX_SCK_MASK;
				txn->flags |= TX_SCK_FOUND;

				/* If the cookie is in insert mode on a known server, we'll delete
				 * this occurrence because we'll insert another one later.
				 * We'll delete it too if the "indirect" option is set and we're in
				 * a direct access.
				 */
				if (s->be->ck_opts & PR_CK_PSV) {
					/* The "preserve" flag was set, we don't want to touch the
					 * server's cookie.
					 */
				}
				else if ((srv && (s->be->ck_opts & PR_CK_INS)) ||
				    ((s->flags & SF_DIRECT) && (s->be->ck_opts & PR_CK_IND))) {
					/* this cookie must be deleted */
					if (prev == hdr_beg && next == hdr_end) {
						/* whole header */
						http_remove_header(htx, &ctx);
						/* note: while both invalid now, <next> and <hdr_end>
						 * are still equal, so the for() will stop as expected.
						 */
					} else {
						/* just remove the value */
						int delta = http_del_hdr_value(hdr_beg, hdr_end, &prev, next);
						next      = prev;
						hdr_end  += delta;
					}
					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_DELETED;
					/* and go on with next cookie */
				}
				else if (srv && srv->cookie && (s->be->ck_opts & PR_CK_RW)) {
					/* replace bytes val_beg->val_end with the cookie name associated
					 * with this server since we know it.
					 */
					int sliding, delta;

					ctx.value = ist2(val_beg, val_end - val_beg);
				        ctx.lws_before = ctx.lws_after = 0;
					http_replace_header_value(htx, &ctx, ist2(srv->cookie, srv->cklen));
					delta     = srv->cklen - (val_end - val_beg);
					sliding   = (ctx.value.ptr - val_beg);
					hdr_beg  += sliding;
					val_beg  += sliding;
					next     += sliding + delta;
					hdr_end  += sliding + delta;

					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_REPLACED;
				}
				else if (srv && srv->cookie && (s->be->ck_opts & PR_CK_PFX)) {
					/* insert the cookie name associated with this server
					 * before existing cookie, and insert a delimiter between them..
					 */
					int sliding, delta;
					ctx.value = ist2(val_beg, 0);
				        ctx.lws_before = ctx.lws_after = 0;
					http_replace_header_value(htx, &ctx, ist2(srv->cookie, srv->cklen + 1));
					delta     = srv->cklen + 1;
					sliding   = (ctx.value.ptr - val_beg);
					hdr_beg  += sliding;
					val_beg  += sliding;
					next     += sliding + delta;
					hdr_end  += sliding + delta;

					val_beg[srv->cklen] = COOKIE_DELIM;
					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_REPLACED;
				}
			}
			/* that's done for this cookie, check the next one on the same
			 * line when next != hdr_end (only if is_cookie2).
			 */
		}
	}
}

/*
 * Parses the Cache-Control and Pragma request header fields to determine if
 * the request may be served from the cache and/or if it is cacheable. Updates
 * s->txn->flags.
 */
void http_check_request_for_cacheability(struct stream *s, struct channel *req)
{
	struct http_txn *txn = s->txn;
	struct htx *htx;
	struct http_hdr_ctx ctx = { .blk = NULL };
	int pragma_found, cc_found;

	if ((txn->flags & (TX_CACHEABLE|TX_CACHE_IGNORE)) == TX_CACHE_IGNORE)
		return; /* nothing more to do here */

	htx = htxbuf(&req->buf);
	pragma_found = cc_found = 0;

	/* Check "pragma" header for HTTP/1.0 compatibility. */
	if (http_find_header(htx, ist("pragma"), &ctx, 1)) {
		if (isteqi(ctx.value, ist("no-cache"))) {
			pragma_found = 1;
		}
	}

	ctx.blk = NULL;
	/* Don't use the cache and don't try to store if we found the
	 * Authorization header */
	if (http_find_header(htx, ist("authorization"), &ctx, 1)) {
		txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
		txn->flags |= TX_CACHE_IGNORE;
	}


	/* Look for "cache-control" header and iterate over all the values
	 * until we find one that specifies that caching is possible or not. */
	ctx.blk = NULL;
	while (http_find_header(htx, ist("cache-control"), &ctx, 0)) {
		cc_found = 1;
		/* We don't check the values after max-age, max-stale nor min-fresh,
		 * we simply don't use the cache when they're specified. */
		if (istmatchi(ctx.value, ist("max-age")) ||
		    istmatchi(ctx.value, ist("no-cache")) ||
		    istmatchi(ctx.value, ist("max-stale")) ||
		    istmatchi(ctx.value, ist("min-fresh"))) {
			txn->flags |= TX_CACHE_IGNORE;
			continue;
		}
		if (istmatchi(ctx.value, ist("no-store"))) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			continue;
		}
	}

	/* RFC7234#5.4:
	 *   When the Cache-Control header field is also present and
	 *   understood in a request, Pragma is ignored.
	 *   When the Cache-Control header field is not present in a
	 *   request, caches MUST consider the no-cache request
	 *   pragma-directive as having the same effect as if
	 *   "Cache-Control: no-cache" were present.
	 */
	if (!cc_found && pragma_found)
		txn->flags |= TX_CACHE_IGNORE;
}

/*
 * Check if response is cacheable or not. Updates s->txn->flags.
 */
void http_check_response_for_cacheability(struct stream *s, struct channel *res)
{
	struct http_txn *txn = s->txn;
	struct http_hdr_ctx ctx = { .blk = NULL };
	struct htx *htx;
	int has_freshness_info = 0;
	int has_validator = 0;

	if (txn->status < 200) {
		/* do not try to cache interim responses! */
		txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
		return;
	}

	htx = htxbuf(&res->buf);
	/* Check "pragma" header for HTTP/1.0 compatibility. */
	if (http_find_header(htx, ist("pragma"), &ctx, 1)) {
		if (isteqi(ctx.value, ist("no-cache"))) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			return;
		}
	}

	/* Look for "cache-control" header and iterate over all the values
	 * until we find one that specifies that caching is possible or not. */
	ctx.blk = NULL;
	while (http_find_header(htx, ist("cache-control"), &ctx, 0)) {
		if (isteqi(ctx.value, ist("public"))) {
			txn->flags |= TX_CACHEABLE | TX_CACHE_COOK;
			continue;
		}
		if (isteqi(ctx.value, ist("private")) ||
		    isteqi(ctx.value, ist("no-cache")) ||
		    isteqi(ctx.value, ist("no-store")) ||
		    isteqi(ctx.value, ist("max-age=0")) ||
		    isteqi(ctx.value, ist("s-maxage=0"))) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			continue;
		}
		/* We might have a no-cache="set-cookie" form. */
		if (istmatchi(ctx.value, ist("no-cache=\"set-cookie"))) {
			txn->flags &= ~TX_CACHE_COOK;
			continue;
		}

		if (istmatchi(ctx.value, ist("s-maxage")) ||
		    istmatchi(ctx.value, ist("max-age"))) {
			has_freshness_info = 1;
			continue;
		}
	}

	/* If no freshness information could be found in Cache-Control values,
	 * look for an Expires header. */
	if (!has_freshness_info) {
		ctx.blk = NULL;
		has_freshness_info = http_find_header(htx, ist("expires"), &ctx, 0);
	}

	/* If no freshness information could be found in Cache-Control or Expires
	 * values, look for an explicit validator. */
	if (!has_freshness_info) {
		ctx.blk = NULL;
		has_validator = 1;
		if (!http_find_header(htx, ist("etag"), &ctx, 0)) {
			ctx.blk = NULL;
			if (!http_find_header(htx, ist("last-modified"), &ctx, 0))
				has_validator = 0;
		}
	}

	/* We won't store an entry that has neither a cache validator nor an
	 * explicit expiration time, as suggested in RFC 7234#3. */
	if (!has_freshness_info && !has_validator)
		txn->flags |= TX_CACHE_IGNORE;
}

/*
 * In a GET, HEAD or POST request, check if the requested URI matches the stats uri
 * for the current backend.
 *
 * It is assumed that the request is either a HEAD, GET, or POST and that the
 * uri_auth field is valid.
 *
 * Returns 1 if stats should be provided, otherwise 0.
 */
static int http_stats_check_uri(struct stream *s, struct http_txn *txn, struct proxy *backend)
{
	struct uri_auth *uri_auth = backend->uri_auth;
	struct htx *htx;
	struct htx_sl *sl;
	struct ist uri;

	if (!uri_auth)
		return 0;

	if (txn->meth != HTTP_METH_GET && txn->meth != HTTP_METH_HEAD && txn->meth != HTTP_METH_POST)
		return 0;

	htx = htxbuf(&s->req.buf);
	sl = http_get_stline(htx);
	uri = htx_sl_req_uri(sl);
	if (*uri_auth->uri_prefix == '/') {
		struct http_uri_parser parser = http_uri_parser_init(uri);
		uri = http_parse_path(&parser);
	}

	/* check URI size */
	if (uri_auth->uri_len > uri.len)
		return 0;

	if (memcmp(uri.ptr, uri_auth->uri_prefix, uri_auth->uri_len) != 0)
		return 0;

	return 1;
}

/* This function prepares an applet to handle the stats. It can deal with the
 * "100-continue" expectation, check that admin rules are met for POST requests,
 * and program a response message if something was unexpected. It cannot fail
 * and always relies on the stats applet to complete the job. It does not touch
 * analysers nor counters, which are left to the caller. It does not touch
 * s->target which is supposed to already point to the stats applet. The caller
 * is expected to have already assigned an appctx to the stream.
 */
static int http_handle_stats(struct stream *s, struct channel *req)
{
	struct stats_admin_rule *stats_admin_rule;
	struct stream_interface *si = &s->si[1];
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct uri_auth *uri_auth = s->be->uri_auth;
	const char *h, *lookup, *end;
	struct appctx *appctx;
	struct htx *htx;
	struct htx_sl *sl;

	appctx = si_appctx(si);
	memset(&appctx->ctx.stats, 0, sizeof(appctx->ctx.stats));
	appctx->st1 = appctx->st2 = 0;
	appctx->ctx.stats.st_code = STAT_STATUS_INIT;
	appctx->ctx.stats.flags |= uri_auth->flags;
	appctx->ctx.stats.flags |= STAT_FMT_HTML; /* assume HTML mode by default */
	if ((msg->flags & HTTP_MSGF_VER_11) && (txn->meth != HTTP_METH_HEAD))
		appctx->ctx.stats.flags |= STAT_CHUNKED;

	htx = htxbuf(&req->buf);
	sl = http_get_stline(htx);
	lookup = HTX_SL_REQ_UPTR(sl) + uri_auth->uri_len;
	end = HTX_SL_REQ_UPTR(sl) + HTX_SL_REQ_ULEN(sl);

	for (h = lookup; h <= end - 3; h++) {
		if (memcmp(h, ";up", 3) == 0) {
			appctx->ctx.stats.flags |= STAT_HIDE_DOWN;
			break;
		}
	}

	for (h = lookup; h <= end - 9; h++) {
		if (memcmp(h, ";no-maint", 9) == 0) {
			appctx->ctx.stats.flags |= STAT_HIDE_MAINT;
			break;
		}
	}

	if (uri_auth->refresh) {
		for (h = lookup; h <= end - 10; h++) {
			if (memcmp(h, ";norefresh", 10) == 0) {
				appctx->ctx.stats.flags |= STAT_NO_REFRESH;
				break;
			}
		}
	}

	for (h = lookup; h <= end - 4; h++) {
		if (memcmp(h, ";csv", 4) == 0) {
			appctx->ctx.stats.flags &= ~(STAT_FMT_MASK|STAT_JSON_SCHM);
			break;
		}
	}

	for (h = lookup; h <= end - 6; h++) {
		if (memcmp(h, ";typed", 6) == 0) {
			appctx->ctx.stats.flags &= ~(STAT_FMT_MASK|STAT_JSON_SCHM);
			appctx->ctx.stats.flags |= STAT_FMT_TYPED;
			break;
		}
	}

	for (h = lookup; h <= end - 5; h++) {
		if (memcmp(h, ";json", 5) == 0) {
			appctx->ctx.stats.flags &= ~(STAT_FMT_MASK|STAT_JSON_SCHM);
			appctx->ctx.stats.flags |= STAT_FMT_JSON;
			break;
		}
	}

	for (h = lookup; h <= end - 12; h++) {
		if (memcmp(h, ";json-schema", 12) == 0) {
			appctx->ctx.stats.flags &= ~STAT_FMT_MASK;
			appctx->ctx.stats.flags |= STAT_JSON_SCHM;
			break;
		}
	}

	for (h = lookup; h <= end - 8; h++) {
		if (memcmp(h, ";st=", 4) == 0) {
			int i;
			h += 4;
			appctx->ctx.stats.st_code = STAT_STATUS_UNKN;
			for (i = STAT_STATUS_INIT + 1; i < STAT_STATUS_SIZE; i++) {
				if (strncmp(stat_status_codes[i], h, 4) == 0) {
					appctx->ctx.stats.st_code = i;
					break;
				}
			}
			break;
		}
	}

	appctx->ctx.stats.scope_str = 0;
	appctx->ctx.stats.scope_len = 0;
	for (h = lookup; h <= end - 8; h++) {
		if (memcmp(h, STAT_SCOPE_INPUT_NAME "=", strlen(STAT_SCOPE_INPUT_NAME) + 1) == 0) {
			int itx = 0;
			const char *h2;
			char scope_txt[STAT_SCOPE_TXT_MAXLEN + 1];
			const char *err;

			h += strlen(STAT_SCOPE_INPUT_NAME) + 1;
			h2 = h;
			appctx->ctx.stats.scope_str = h2 - HTX_SL_REQ_UPTR(sl);
			while (h < end) {
				if (*h == ';' || *h == '&' || *h == ' ')
					break;
				itx++;
				h++;
			}

			if (itx > STAT_SCOPE_TXT_MAXLEN)
				itx = STAT_SCOPE_TXT_MAXLEN;
			appctx->ctx.stats.scope_len = itx;

			/* scope_txt = search query, appctx->ctx.stats.scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
			memcpy(scope_txt, h2, itx);
			scope_txt[itx] = '\0';
			err = invalid_char(scope_txt);
			if (err) {
				/* bad char in search text => clear scope */
				appctx->ctx.stats.scope_str = 0;
				appctx->ctx.stats.scope_len = 0;
			}
			break;
		}
	}

	/* now check whether we have some admin rules for this request */
	list_for_each_entry(stats_admin_rule, &uri_auth->admin_rules, list) {
		int ret = 1;

		if (stats_admin_rule->cond) {
			ret = acl_exec_cond(stats_admin_rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (stats_admin_rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* no rule, or the rule matches */
			appctx->ctx.stats.flags |= STAT_ADMIN;
			break;
		}
	}

	if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
		appctx->st0 = STAT_HTTP_HEAD;
	else if (txn->meth == HTTP_METH_POST) {
		if (appctx->ctx.stats.flags & STAT_ADMIN) {
			appctx->st0 = STAT_HTTP_POST;
			if (msg->msg_state < HTTP_MSG_DATA)
				req->analysers |= AN_REQ_HTTP_BODY;
		}
		else {
			/* POST without admin level */
			appctx->ctx.stats.flags &= ~STAT_CHUNKED;
			appctx->ctx.stats.st_code = STAT_STATUS_DENY;
			appctx->st0 = STAT_HTTP_LAST;
		}
	}
	else {
		/* Unsupported method */
		appctx->ctx.stats.flags &= ~STAT_CHUNKED;
		appctx->ctx.stats.st_code = STAT_STATUS_IVAL;
		appctx->st0 = STAT_HTTP_LAST;
	}

	s->task->nice = -32; /* small boost for HTTP statistics */
	return 1;
}

/* This function waits for the message payload at most <time> milliseconds (may
 * be set to TICK_ETERNITY). It stops to wait if at least <bytes> bytes of the
 * payload are received (0 means no limit). It returns HTTP_RULE_* depending on
 * the result:
 *
 *   - HTTP_RULE_RES_CONT when  conditions are met to stop waiting
 *   - HTTP_RULE_RES_YIELD to wait for more data
 *   - HTTP_RULE_RES_ABRT when a timeout occurred.
 *   - HTTP_RULE_RES_BADREQ if a parsing error is raised by lower level
 *   - HTTP_RULE_RES_ERROR if an internal error occurred
 *
 * If a timeout occurred, this function is responsible to emit the right response
 * to the client, depending on the channel (408 on request side, 504 on response
 * side). All other errors must be handled by the caller.
 */
enum rule_result http_wait_for_msg_body(struct stream *s, struct channel *chn,
					unsigned int time, unsigned int bytes)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = ((chn->flags & CF_ISRESP) ? &txn->rsp : &txn->req);
	struct htx *htx;
	enum rule_result ret = HTTP_RULE_RES_CONT;

	htx = htxbuf(&chn->buf);

	if (htx->flags & HTX_FL_PARSING_ERROR) {
		ret = HTTP_RULE_RES_BADREQ;
		goto end;
	}
	if (htx->flags & HTX_FL_PROCESSING_ERROR) {
		ret = HTTP_RULE_RES_ERROR;
		goto end;
	}

	/* Do nothing for bodyless and CONNECT requests */
	if (txn->meth == HTTP_METH_CONNECT || (msg->flags & HTTP_MSGF_BODYLESS))
		goto end;

	if (!(chn->flags & CF_ISRESP) && msg->msg_state < HTTP_MSG_DATA) {
		if (http_handle_expect_hdr(s, htx, msg) == -1) {
			ret = HTTP_RULE_RES_ERROR;
			goto end;
		}
	}

	msg->msg_state = HTTP_MSG_DATA;

	/* Now we're in HTTP_MSG_DATA. We just need to know if all data have
	 * been received or if the buffer is full.
	 */
	if ((htx->flags & HTX_FL_EOM) ||
	    htx_get_tail_type(htx) > HTX_BLK_DATA ||
	    channel_htx_full(chn, htx, global.tune.maxrewrite) ||
	    si_rx_blocked_room(chn_prod(chn)))
		goto end;

	if (bytes) {
		struct htx_blk *blk;
		unsigned int len = 0;

		for (blk = htx_get_first_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
			if (htx_get_blk_type(blk) != HTX_BLK_DATA)
				continue;
			len += htx_get_blksz(blk);
			if (len >= bytes)
				goto end;
		}
	}

	if ((chn->flags & CF_READ_TIMEOUT) || tick_is_expired(chn->analyse_exp, now_ms)) {
		if (!(chn->flags & CF_ISRESP))
			goto abort_req;
		goto abort_res;
	}

	/* we get here if we need to wait for more data */
	if (!(chn->flags & (CF_SHUTR | CF_READ_ERROR))) {
		if (!tick_isset(chn->analyse_exp))
			chn->analyse_exp = tick_add_ifset(now_ms, time);
		ret = HTTP_RULE_RES_YIELD;
	}

  end:
	return ret;

  abort_req:
	txn->status = 408;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLITO;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);
	http_reply_and_close(s, txn->status, http_error_message(s));
	ret = HTTP_RULE_RES_ABRT;
	goto end;

  abort_res:
	txn->status = 504;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVTO;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	stream_inc_http_fail_ctr(s);
	http_reply_and_close(s, txn->status, http_error_message(s));
	ret = HTTP_RULE_RES_ABRT;
	goto end;
}

void http_perform_server_redirect(struct stream *s, struct stream_interface *si)
{
	struct channel *req = &s->req;
	struct channel *res = &s->res;
	struct server *srv;
	struct htx *htx;
	struct htx_sl *sl;
	struct ist path, location;
	unsigned int flags;
	struct http_uri_parser parser;

	/*
	 * Create the location
	 */
	chunk_reset(&trash);

	/* 1: add the server's prefix */
	/* special prefix "/" means don't change URL */
	srv = __objt_server(s->target);
	if (srv->rdr_len != 1 || *srv->rdr_pfx != '/') {
		if (!chunk_memcat(&trash, srv->rdr_pfx, srv->rdr_len))
			return;
	}

	/* 2: add the request Path */
	htx = htxbuf(&req->buf);
	sl = http_get_stline(htx);
	parser = http_uri_parser_init(htx_sl_req_uri(sl));
	path = http_parse_path(&parser);
	if (!isttest(path))
		return;

	if (!chunk_memcat(&trash, path.ptr, path.len))
		return;
	location = ist2(trash.area, trash.data);

	/*
	 * Create the 302 respone
	 */
	htx = htx_from_buf(&res->buf);
	flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
			    ist("HTTP/1.1"), ist("302"), ist("Found"));
	if (!sl)
		goto fail;
	sl->info.res.status = 302;
	s->txn->status = 302;

        if (!htx_add_header(htx, ist("Cache-Control"), ist("no-cache")) ||
	    !htx_add_header(htx, ist("Connection"), ist("close")) ||
	    !htx_add_header(htx, ist("Content-length"), ist("0")) ||
	    !htx_add_header(htx, ist("Location"), location))
		goto fail;

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto fail;

	htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &res->buf);
	if (!http_forward_proxy_resp(s, 1))
		goto fail;

	/* return without error. */
	si_shutr(si);
	si_shutw(si);
	si->err_type = SI_ET_NONE;
	si->state    = SI_ST_CLO;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_LOCAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_C;

	/* FIXME: we should increase a counter of redirects per server and per backend. */
	srv_inc_sess_ctr(srv);
	srv_set_sess_last(srv);
	return;

  fail:
	/* If an error occurred, remove the incomplete HTTP response from the
	 * buffer */
	channel_htx_truncate(res, htx);
}

/* This function terminates the request because it was completely analyzed or
 * because an error was triggered during the body forwarding.
 */
static void http_end_request(struct stream *s)
{
	struct channel *chn = &s->req;
	struct http_txn *txn = s->txn;

	DBG_TRACE_ENTER(STRM_EV_HTTP_ANA, s, txn);

	if (unlikely(txn->req.msg_state == HTTP_MSG_ERROR ||
		     txn->rsp.msg_state == HTTP_MSG_ERROR)) {
		channel_abort(chn);
		channel_htx_truncate(chn, htxbuf(&chn->buf));
		goto end;
	}

	if (unlikely(txn->req.msg_state < HTTP_MSG_DONE)) {
		DBG_TRACE_DEVEL("waiting end of the request", STRM_EV_HTTP_ANA, s, txn);
		return;
	}

	if (txn->req.msg_state == HTTP_MSG_DONE) {
		/* No need to read anymore, the request was completely parsed.
		 * We can shut the read side unless we want to abort_on_close,
		 * or we have a POST request. The issue with POST requests is
		 * that some browsers still send a CRLF after the request, and
		 * this CRLF must be read so that it does not remain in the kernel
		 * buffers, otherwise a close could cause an RST on some systems
		 * (eg: Linux).
		 */
		if (!(s->be->options & PR_O_ABRT_CLOSE) && txn->meth != HTTP_METH_POST)
			channel_dont_read(chn);

		/* if the server closes the connection, we want to immediately react
		 * and close the socket to save packets and syscalls.
		 */
		s->si[1].flags |= SI_FL_NOHALF;

		/* In any case we've finished parsing the request so we must
		 * disable Nagle when sending data because 1) we're not going
		 * to shut this side, and 2) the server is waiting for us to
		 * send pending data.
		 */
		chn->flags |= CF_NEVER_WAIT;

		if (txn->rsp.msg_state < HTTP_MSG_DONE) {
			/* The server has not finished to respond, so we
			 * don't want to move in order not to upset it.
			 */
			DBG_TRACE_DEVEL("waiting end of the response", STRM_EV_HTTP_ANA, s, txn);
			return;
		}

		/* When we get here, it means that both the request and the
		 * response have finished receiving. Depending on the connection
		 * mode, we'll have to wait for the last bytes to leave in either
		 * direction, and sometimes for a close to be effective.
		 */
		if (txn->flags & TX_CON_WANT_TUN) {
			/* Tunnel mode will not have any analyser so it needs to
			 * poll for reads.
			 */
			channel_auto_read(chn);
			if (b_data(&chn->buf)) {
				DBG_TRACE_DEVEL("waiting to flush the request", STRM_EV_HTTP_ANA, s, txn);
				return;
			}
			txn->req.msg_state = HTTP_MSG_TUNNEL;
		}
		else {
			/* we're not expecting any new data to come for this
			 * transaction, so we can close it.
			 *
			 *  However, there is an exception if the response
			 *  length is undefined. In this case, we need to wait
			 *  the close from the server. The response will be
			 *  switched in TUNNEL mode until the end.
			 */
			if (!(txn->rsp.flags & HTTP_MSGF_XFER_LEN) &&
			    txn->rsp.msg_state != HTTP_MSG_CLOSED)
				goto check_channel_flags;

			if (!(chn->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
				channel_shutr_now(chn);
				channel_shutw_now(chn);
			}
		}
		goto check_channel_flags;
	}

	if (txn->req.msg_state == HTTP_MSG_CLOSING) {
	  http_msg_closing:
		/* nothing else to forward, just waiting for the output buffer
		 * to be empty and for the shutw_now to take effect.
		 */
		if (channel_is_empty(chn)) {
			txn->req.msg_state = HTTP_MSG_CLOSED;
			goto http_msg_closed;
		}
		else if (chn->flags & CF_SHUTW) {
			txn->req.msg_state = HTTP_MSG_ERROR;
			goto end;
		}
		DBG_TRACE_LEAVE(STRM_EV_HTTP_ANA, s, txn);
		return;
	}

	if (txn->req.msg_state == HTTP_MSG_CLOSED) {
	  http_msg_closed:
		/* if we don't know whether the server will close, we need to hard close */
		if (txn->rsp.flags & HTTP_MSGF_XFER_LEN)
			s->si[1].flags |= SI_FL_NOLINGER;  /* we want to close ASAP */
		/* see above in MSG_DONE why we only do this in these states */
		if (!(s->be->options & PR_O_ABRT_CLOSE))
			channel_dont_read(chn);
		goto end;
	}

  check_channel_flags:
	/* Here, we are in HTTP_MSG_DONE or HTTP_MSG_TUNNEL */
	if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
		/* if we've just closed an output, let's switch */
		txn->req.msg_state = HTTP_MSG_CLOSING;
		goto http_msg_closing;
	}

  end:
	chn->analysers &= AN_REQ_FLT_END;
	if (txn->req.msg_state == HTTP_MSG_TUNNEL) {
		chn->flags |= CF_NEVER_WAIT;
		if (HAS_REQ_DATA_FILTERS(s))
			chn->analysers |= AN_REQ_FLT_XFER_DATA;
	}
	channel_auto_close(chn);
	channel_auto_read(chn);
	DBG_TRACE_LEAVE(STRM_EV_HTTP_ANA, s, txn);
}


/* This function terminates the response because it was completely analyzed or
 * because an error was triggered during the body forwarding.
 */
static void http_end_response(struct stream *s)
{
	struct channel *chn = &s->res;
	struct http_txn *txn = s->txn;

	DBG_TRACE_ENTER(STRM_EV_HTTP_ANA, s, txn);

	if (unlikely(txn->req.msg_state == HTTP_MSG_ERROR ||
		     txn->rsp.msg_state == HTTP_MSG_ERROR)) {
		channel_htx_truncate(&s->req, htxbuf(&s->req.buf));
		channel_abort(&s->req);
		goto end;
	}

	if (unlikely(txn->rsp.msg_state < HTTP_MSG_DONE)) {
		DBG_TRACE_DEVEL("waiting end of the response", STRM_EV_HTTP_ANA, s, txn);
		return;
	}

	if (txn->rsp.msg_state == HTTP_MSG_DONE) {
		/* In theory, we don't need to read anymore, but we must
		 * still monitor the server connection for a possible close
		 * while the request is being uploaded, so we don't disable
		 * reading.
		 */
		/* channel_dont_read(chn); */

		if (txn->req.msg_state < HTTP_MSG_DONE) {
			/* The client seems to still be sending data, probably
			 * because we got an error response during an upload.
			 * We have the choice of either breaking the connection
			 * or letting it pass through. Let's do the later.
			 */
			DBG_TRACE_DEVEL("waiting end of the request", STRM_EV_HTTP_ANA, s, txn);
			return;
		}

		/* When we get here, it means that both the request and the
		 * response have finished receiving. Depending on the connection
		 * mode, we'll have to wait for the last bytes to leave in either
		 * direction, and sometimes for a close to be effective.
		 */
		if (txn->flags & TX_CON_WANT_TUN) {
			channel_auto_read(chn);
			if (b_data(&chn->buf)) {
				DBG_TRACE_DEVEL("waiting to flush the respone", STRM_EV_HTTP_ANA, s, txn);
				return;
			}
			txn->rsp.msg_state = HTTP_MSG_TUNNEL;
		}
		else {
			/* we're not expecting any new data to come for this
			 * transaction, so we can close it.
			 */
			if (!(chn->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
				channel_shutr_now(chn);
				channel_shutw_now(chn);
			}
		}
		goto check_channel_flags;
	}

	if (txn->rsp.msg_state == HTTP_MSG_CLOSING) {
	  http_msg_closing:
		/* nothing else to forward, just waiting for the output buffer
		 * to be empty and for the shutw_now to take effect.
		 */
		if (channel_is_empty(chn)) {
			txn->rsp.msg_state = HTTP_MSG_CLOSED;
			goto http_msg_closed;
		}
		else if (chn->flags & CF_SHUTW) {
			txn->rsp.msg_state = HTTP_MSG_ERROR;
			_HA_ATOMIC_INC(&strm_sess(s)->fe->fe_counters.cli_aborts);
			_HA_ATOMIC_INC(&s->be->be_counters.cli_aborts);
			if (strm_sess(s)->listener && strm_sess(s)->listener->counters)
				_HA_ATOMIC_INC(&strm_sess(s)->listener->counters->cli_aborts);
			if (objt_server(s->target))
				_HA_ATOMIC_INC(&__objt_server(s->target)->counters.cli_aborts);
			goto end;
		}
		DBG_TRACE_LEAVE(STRM_EV_HTTP_ANA, s, txn);
		return;
	}

	if (txn->rsp.msg_state == HTTP_MSG_CLOSED) {
	  http_msg_closed:
		/* drop any pending data */
		channel_htx_truncate(&s->req, htxbuf(&s->req.buf));
		channel_abort(&s->req);
		goto end;
	}

  check_channel_flags:
	/* Here, we are in HTTP_MSG_DONE or HTTP_MSG_TUNNEL */
	if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
		/* if we've just closed an output, let's switch */
		txn->rsp.msg_state = HTTP_MSG_CLOSING;
		goto http_msg_closing;
	}

  end:
	chn->analysers &= AN_RES_FLT_END;
	if (txn->rsp.msg_state == HTTP_MSG_TUNNEL) {
		chn->flags |= CF_NEVER_WAIT;
		if (HAS_RSP_DATA_FILTERS(s))
			chn->analysers |= AN_RES_FLT_XFER_DATA;
	}
	channel_auto_close(chn);
	channel_auto_read(chn);
	DBG_TRACE_LEAVE(STRM_EV_HTTP_ANA, s, txn);
}

/* Forward a response generated by HAProxy (error/redirect/return). This
 * function forwards all pending incoming data. If <final> is set to 0, nothing
 * more is performed. It is used for 1xx informational messages. Otherwise, the
 * transaction is terminated and the request is emptied. On success 1 is
 * returned. If an error occurred, 0 is returned. If it fails, this function
 * only exits. It is the caller responsibility to do the cleanup.
 */
int http_forward_proxy_resp(struct stream *s, int final)
{
	struct channel *req = &s->req;
	struct channel *res = &s->res;
	struct htx *htx = htxbuf(&res->buf);
	size_t data;

	if (final) {
		htx->flags |= HTX_FL_PROXY_RESP;

		if (!htx_is_empty(htx) && !http_eval_after_res_rules(s))
			return 0;

		if (s->txn->meth == HTTP_METH_HEAD)
			htx_skip_msg_payload(htx);

		channel_auto_read(req);
		channel_abort(req);
		channel_auto_close(req);
		channel_htx_erase(req, htxbuf(&req->buf));

		res->wex = tick_add_ifset(now_ms, res->wto);
		channel_auto_read(res);
		channel_auto_close(res);
		channel_shutr_now(res);
		res->flags |= CF_EOI; /* The response is terminated, add EOI */
		htxbuf(&res->buf)->flags |= HTX_FL_EOM; /* no more data are expected */
	}
	else {
		/* Send ASAP informational messages. Rely on CF_EOI for final
		 * response.
		 */
		res->flags |= CF_SEND_DONTWAIT;
	}

	data = htx->data - co_data(res);
	c_adv(res, data);
	htx->first = -1;
	res->total += data;
	return 1;
}

void http_server_error(struct stream *s, struct stream_interface *si, int err,
		       int finst, struct http_reply *msg)
{
	http_reply_and_close(s, s->txn->status, msg);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= finst;
}

void http_reply_and_close(struct stream *s, short status, struct http_reply *msg)
{
	if (!msg) {
		channel_htx_truncate(&s->res, htxbuf(&s->res.buf));
		goto end;
	}

	if (http_reply_message(s, msg) == -1) {
		/* On error, return a 500 error message, but don't rewrite it if
		 * it is already an internal error. If it was already a "const"
		 * 500 error, just fail.
		 */
		if (s->txn->status == 500) {
			if (s->txn->flags & TX_CONST_REPLY)
				goto end;
			s->txn->flags |= TX_CONST_REPLY;
		}
		s->txn->status = 500;
		s->txn->http_reply = NULL;
		return http_reply_and_close(s, s->txn->status, http_error_message(s));
	}

end:
	s->res.wex = tick_add_ifset(now_ms, s->res.wto);

	/* At this staged, HTTP analysis is finished */
	s->req.analysers &= AN_REQ_FLT_END;
	s->req.analyse_exp = TICK_ETERNITY;

	s->res.analysers &= AN_RES_FLT_END;
	s->res.analyse_exp = TICK_ETERNITY;

	channel_auto_read(&s->req);
	channel_abort(&s->req);
	channel_auto_close(&s->req);
	channel_htx_erase(&s->req, htxbuf(&s->req.buf));
	channel_auto_read(&s->res);
	channel_auto_close(&s->res);
	channel_shutr_now(&s->res);
}

struct http_reply *http_error_message(struct stream *s)
{
	const int msgnum = http_get_status_idx(s->txn->status);

	if (s->txn->http_reply)
		return s->txn->http_reply;
	else if (s->be->replies[msgnum])
		return s->be->replies[msgnum];
	else if (strm_fe(s)->replies[msgnum])
		return strm_fe(s)->replies[msgnum];
	else
		return &http_err_replies[msgnum];
}

/* Produces an HTX message from an http reply. Depending on the http reply type,
 * a, errorfile, an raw file or a log-format string is used. On success, it
 * returns 0. If an error occurs -1 is returned. If it fails, this function only
 * exits. It is the caller responsibility to do the cleanup.
 */
int http_reply_to_htx(struct stream *s, struct htx *htx, struct http_reply *reply)
{
	struct buffer *errmsg;
	struct htx_sl *sl;
	struct buffer *body = NULL;
	const char *status, *reason, *clen, *ctype;
	unsigned int slflags;
	int ret = 0;

	/*
	 * - HTTP_REPLY_ERRFILES unexpected here. handled as no payload if so
	 *
	 * - HTTP_REPLY_INDIRECT: switch on another reply if defined or handled
	 *   as no payload if NULL. the TXN status code is set with the status
	 *   of the original reply.
	 */

	if (reply->type == HTTP_REPLY_INDIRECT) {
		if (reply->body.reply)
			reply = reply->body.reply;
	}
	if (reply->type == HTTP_REPLY_ERRMSG && !reply->body.errmsg)  {
		/* get default error message */
		if (reply == s->txn->http_reply)
			s->txn->http_reply = NULL;
		reply = http_error_message(s);
		if (reply->type == HTTP_REPLY_INDIRECT) {
			if (reply->body.reply)
				reply = reply->body.reply;
		}
	}

	if (reply->type == HTTP_REPLY_ERRMSG) {
		/* implicit or explicit error message*/
		errmsg = reply->body.errmsg;
		if (errmsg && !b_is_null(errmsg)) {
			if (!htx_copy_msg(htx, errmsg))
				goto fail;
		}
	}
	else {
		/* no payload, file or log-format string */
		if (reply->type == HTTP_REPLY_RAW) {
			/* file */
			body = &reply->body.obj;
		}
		else if (reply->type == HTTP_REPLY_LOGFMT) {
			/* log-format string */
			body = alloc_trash_chunk();
			if (!body)
				goto fail_alloc;
			body->data = build_logline(s, body->area, body->size, &reply->body.fmt);
		}
		/* else no payload */

		status = ultoa(reply->status);
		reason = http_get_reason(reply->status);
		slflags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_CLEN);
		if (!body || !b_data(body))
			slflags |= HTX_SL_F_BODYLESS;
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, slflags, ist("HTTP/1.1"), ist(status), ist(reason));
		if (!sl)
			goto fail;
		sl->info.res.status = reply->status;

		clen = (body ? ultoa(b_data(body)) : "0");
		ctype = reply->ctype;

		if (!LIST_ISEMPTY(&reply->hdrs)) {
			struct http_reply_hdr *hdr;
			struct buffer *value = alloc_trash_chunk();

			if (!value)
				goto fail;

			list_for_each_entry(hdr, &reply->hdrs, list) {
				chunk_reset(value);
				value->data = build_logline(s, value->area, value->size, &hdr->value);
				if (b_data(value) && !htx_add_header(htx, hdr->name, ist2(b_head(value), b_data(value)))) {
					free_trash_chunk(value);
					goto fail;
				}
				chunk_reset(value);
			}
			free_trash_chunk(value);
		}

		if (!htx_add_header(htx, ist("content-length"), ist(clen)) ||
		    (body && b_data(body) && ctype && !htx_add_header(htx, ist("content-type"), ist(ctype))) ||
		    !htx_add_endof(htx, HTX_BLK_EOH) ||
		    (body && b_data(body) && !htx_add_data_atonce(htx, ist2(b_head(body), b_data(body)))))
			goto fail;

		htx->flags |= HTX_FL_EOM;
	}

  leave:
	if (reply->type == HTTP_REPLY_LOGFMT)
		free_trash_chunk(body);
	return ret;

  fail_alloc:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_RESOURCE;
	/* fall through */
  fail:
	ret = -1;
	goto leave;
}

/* Send an http reply to the client. On success, it returns 0. If an error
 * occurs -1 is returned and the response channel is truncated, removing this
 * way the faulty reply. This function may fail when the reply is formatted
 * (http_reply_to_htx) or when the reply is forwarded
 * (http_forward_proxy_resp). On the last case, it is because a
 * http-after-response rule fails.
 */
int http_reply_message(struct stream *s, struct http_reply *reply)
{
	struct channel *res = &s->res;
	struct htx *htx = htx_from_buf(&res->buf);

	if (s->txn->status == -1)
		s->txn->status = reply->status;
	channel_htx_truncate(res, htx);

	if (http_reply_to_htx(s, htx, reply) == -1)
		goto fail;

	htx_to_buf(htx, &s->res.buf);
	if (!http_forward_proxy_resp(s, 1))
		goto fail;
	return 0;

  fail:
	channel_htx_truncate(res, htx);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	return -1;
}

/* Return the error message corresponding to si->err_type. It is assumed
 * that the server side is closed. Note that err_type is actually a
 * bitmask, where almost only aborts may be cumulated with other
 * values. We consider that aborted operations are more important
 * than timeouts or errors due to the fact that nobody else in the
 * logs might explain incomplete retries. All others should avoid
 * being cumulated. It should normally not be possible to have multiple
 * aborts at once, but just in case, the first one in sequence is reported.
 * Note that connection errors appearing on the second request of a keep-alive
 * connection are not reported since this allows the client to retry.
 */
void http_return_srv_error(struct stream *s, struct stream_interface *si)
{
	int err_type = si->err_type;

	/* set s->txn->status for http_error_message(s) */
	if (err_type & SI_ET_QUEUE_ABRT) {
		s->txn->status = -1;
		http_server_error(s, si, SF_ERR_CLICL, SF_FINST_Q, NULL);
	}
	else if (err_type & SI_ET_CONN_ABRT) {
		s->txn->status = -1;
		http_server_error(s, si, SF_ERR_CLICL, SF_FINST_C, NULL);
	}
	else if (err_type & SI_ET_QUEUE_TO) {
		s->txn->status = 503;
		http_server_error(s, si, SF_ERR_SRVTO, SF_FINST_Q,
				  http_error_message(s));
	}
	else if (err_type & SI_ET_QUEUE_ERR) {
		s->txn->status = 503;
		http_server_error(s, si, SF_ERR_SRVCL, SF_FINST_Q,
				  http_error_message(s));
	}
	else if (err_type & SI_ET_CONN_TO) {
		s->txn->status = 503;
		http_server_error(s, si, SF_ERR_SRVTO, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
	}
	else if (err_type & SI_ET_CONN_ERR) {
		s->txn->status = 503;
		http_server_error(s, si, SF_ERR_SRVCL, SF_FINST_C,
				  (s->flags & SF_SRV_REUSED) ? NULL :
				  http_error_message(s));
	}
	else if (err_type & SI_ET_CONN_RES) {
		s->txn->status = 503;
		http_server_error(s, si, SF_ERR_RESOURCE, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
	}
	else { /* SI_ET_CONN_OTHER and others */
		s->txn->status = 500;
		http_server_error(s, si, SF_ERR_INTERNAL, SF_FINST_C,
				  http_error_message(s));
	}
}


/* Handle Expect: 100-continue for HTTP/1.1 messages if necessary. It returns 0
 * on success and -1 on error.
 */
static int http_handle_expect_hdr(struct stream *s, struct htx *htx, struct http_msg *msg)
{
	/* If we have HTTP/1.1 message with a body and Expect: 100-continue,
	 * then we must send an HTTP/1.1 100 Continue intermediate response.
	 */
	if (msg->msg_state == HTTP_MSG_BODY && (msg->flags & HTTP_MSGF_VER_11) &&
	    (msg->flags & (HTTP_MSGF_CNT_LEN|HTTP_MSGF_TE_CHNK))) {
		struct ist hdr = { .ptr = "Expect", .len = 6 };
		struct http_hdr_ctx ctx;

		ctx.blk = NULL;
		/* Expect is allowed in 1.1, look for it */
		if (http_find_header(htx, hdr, &ctx, 0) &&
		    unlikely(isteqi(ctx.value, ist2("100-continue", 12)))) {
			if (http_reply_100_continue(s) == -1)
				return -1;
			http_remove_header(htx, &ctx);
		}
	}
	return 0;
}

/* Send a 100-Continue response to the client. It returns 0 on success and -1
 * on error. The response channel is updated accordingly.
 */
static int http_reply_100_continue(struct stream *s)
{
	struct channel *res = &s->res;
	struct htx *htx = htx_from_buf(&res->buf);
	struct htx_sl *sl;
	unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|
			      HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);

	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
			    ist("HTTP/1.1"), ist("100"), ist("Continue"));
	if (!sl)
		goto fail;
	sl->info.res.status = 100;

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto fail;

	if (!http_forward_proxy_resp(s, 0))
		goto fail;
	return 0;

  fail:
	/* If an error occurred, remove the incomplete HTTP response from the
	 * buffer */
	channel_htx_truncate(res, htx);
	return -1;
}


/*
 * Capture headers from message <htx> according to header list <cap_hdr>, and
 * fill the <cap> pointers appropriately.
 */
static void http_capture_headers(struct htx *htx, char **cap, struct cap_hdr *cap_hdr)
{
	struct cap_hdr *h;
	int32_t pos;

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);
		struct ist n, v;

		if (type == HTX_BLK_EOH)
			break;
		if (type != HTX_BLK_HDR)
			continue;

		n = htx_get_blk_name(htx, blk);

		for (h = cap_hdr; h; h = h->next) {
			if (h->namelen && (h->namelen == n.len) &&
			    (strncasecmp(n.ptr, h->name, h->namelen) == 0)) {
				if (cap[h->index] == NULL)
					cap[h->index] =
						pool_alloc(h->pool);

				if (cap[h->index] == NULL) {
					ha_alert("HTTP capture : out of memory.\n");
					break;
				}

				v = htx_get_blk_value(htx, blk);
				v = isttrim(v, h->len);

				memcpy(cap[h->index], v.ptr, v.len);
				cap[h->index][v.len]=0;
			}
		}
	}
}

/* Delete a value in a header between delimiters <from> and <next>. The header
 * itself is delimited by <start> and <end> pointers. The number of characters
 * displaced is returned, and the pointer to the first delimiter is updated if
 * required. The function tries as much as possible to respect the following
 * principles :
 * - replace <from> delimiter by the <next> one unless <from> points to <start>,
 *   in which case <next> is simply removed
 * - set exactly one space character after the new first delimiter, unless there
 *   are not enough characters in the block being moved to do so.
 * - remove unneeded spaces before the previous delimiter and after the new
 *   one.
 *
 * It is the caller's responsibility to ensure that :
 *   - <from> points to a valid delimiter or <start> ;
 *   - <next> points to a valid delimiter or <end> ;
 *   - there are non-space chars before <from>.
 */
static int http_del_hdr_value(char *start, char *end, char **from, char *next)
{
	char *prev = *from;

	if (prev == start) {
		/* We're removing the first value. eat the semicolon, if <next>
		 * is lower than <end> */
		if (next < end)
			next++;

		while (next < end && HTTP_IS_SPHT(*next))
			next++;
	}
	else {
		/* Remove useless spaces before the old delimiter. */
		while (HTTP_IS_SPHT(*(prev-1)))
			prev--;
		*from = prev;

		/* copy the delimiter and if possible a space if we're
		 * not at the end of the line.
		 */
		if (next < end) {
			*prev++ = *next++;
			if (prev + 1 < next)
				*prev++ = ' ';
			while (next < end && HTTP_IS_SPHT(*next))
				next++;
		}
	}
	memmove(prev, next, end - next);
	return (prev - next);
}


/* Formats the start line of the request (without CRLF) and puts it in <str> and
 * return the written length. The line can be truncated if it exceeds <len>.
 */
static size_t http_fmt_req_line(const struct htx_sl *sl, char *str, size_t len)
{
	struct ist dst = ist2(str, 0);

	if (istcat(&dst, htx_sl_req_meth(sl), len) == -1)
		goto end;
	if (dst.len + 1 > len)
		goto end;
	dst.ptr[dst.len++] = ' ';

	if (istcat(&dst, htx_sl_req_uri(sl), len) == -1)
		goto end;
	if (dst.len + 1 > len)
		goto end;
	dst.ptr[dst.len++] = ' ';

	istcat(&dst, htx_sl_req_vsn(sl), len);
  end:
	return dst.len;
}

/*
 * Print a debug line with a start line.
 */
static void http_debug_stline(const char *dir, struct stream *s, const struct htx_sl *sl)
{
        struct session *sess = strm_sess(s);
        int max;

        chunk_printf(&trash, "%08x:%s.%s[%04x:%04x]: ", s->uniq_id, s->be->id,
                     dir,
                     objt_conn(sess->origin) ? (unsigned short)__objt_conn(sess->origin)->handle.fd : -1,
                     objt_cs(s->si[1].end) ? (unsigned short)__objt_cs(s->si[1].end)->conn->handle.fd : -1);

        max = HTX_SL_P1_LEN(sl);
        UBOUND(max, trash.size - trash.data - 3);
        chunk_memcat(&trash, HTX_SL_P1_PTR(sl), max);
        trash.area[trash.data++] = ' ';

        max = HTX_SL_P2_LEN(sl);
        UBOUND(max, trash.size - trash.data - 2);
        chunk_memcat(&trash, HTX_SL_P2_PTR(sl), max);
        trash.area[trash.data++] = ' ';

        max = HTX_SL_P3_LEN(sl);
        UBOUND(max, trash.size - trash.data - 1);
        chunk_memcat(&trash, HTX_SL_P3_PTR(sl), max);
        trash.area[trash.data++] = '\n';

        DISGUISE(write(1, trash.area, trash.data));
}

/*
 * Print a debug line with a header.
 */
static void http_debug_hdr(const char *dir, struct stream *s, const struct ist n, const struct ist v)
{
        struct session *sess = strm_sess(s);
        int max;

        chunk_printf(&trash, "%08x:%s.%s[%04x:%04x]: ", s->uniq_id, s->be->id,
                     dir,
                     objt_conn(sess->origin) ? (unsigned short)__objt_conn(sess->origin)->handle.fd : -1,
                     objt_cs(s->si[1].end) ? (unsigned short)__objt_cs(s->si[1].end)->conn->handle.fd : -1);

        max = n.len;
        UBOUND(max, trash.size - trash.data - 3);
        chunk_memcat(&trash, n.ptr, max);
        trash.area[trash.data++] = ':';
        trash.area[trash.data++] = ' ';

        max = v.len;
        UBOUND(max, trash.size - trash.data - 1);
        chunk_memcat(&trash, v.ptr, max);
        trash.area[trash.data++] = '\n';

        DISGUISE(write(1, trash.area, trash.data));
}

/* Allocate a new HTTP transaction for stream <s> unless there is one already.
 * In case of allocation failure, everything allocated is freed and NULL is
 * returned. Otherwise the new transaction is assigned to the stream and
 * returned.
 */
struct http_txn *http_alloc_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;

	if (txn)
		return txn;

	txn = pool_alloc(pool_head_http_txn);
	if (!txn)
		return txn;

	s->txn = txn;
	return txn;
}

void http_txn_reset_req(struct http_txn *txn)
{
	txn->req.flags = 0;
	txn->req.msg_state = HTTP_MSG_RQBEFORE; /* at the very beginning of the request */
}

void http_txn_reset_res(struct http_txn *txn)
{
	txn->rsp.flags = 0;
	txn->rsp.msg_state = HTTP_MSG_RPBEFORE; /* at the very beginning of the response */
}

/*
 * Create and initialize a new HTTP transaction for stream <s>. This should be
 * used before processing any new request. It returns the transaction or NLULL
 * on error.
 */
struct http_txn *http_create_txn(struct stream *s)
{
	struct http_txn *txn;
	struct conn_stream *cs = objt_cs(s->si[0].end);

	txn = pool_alloc(pool_head_http_txn);
	if (!txn)
		return NULL;
	s->txn = txn;

	txn->flags = ((cs && cs->flags & CS_FL_NOT_FIRST) ? TX_NOT_FIRST : 0);
	txn->status = -1;
	txn->http_reply = NULL;
	write_u32(txn->cache_hash, 0);

	txn->cookie_first_date = 0;
	txn->cookie_last_date = 0;

	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;
	txn->uri = NULL;

	http_txn_reset_req(txn);
	http_txn_reset_res(txn);

	txn->req.chn = &s->req;
	txn->rsp.chn = &s->res;

	txn->auth.method = HTTP_AUTH_UNKNOWN;

	vars_init_head(&s->vars_txn,    SCOPE_TXN);
	vars_init_head(&s->vars_reqres, SCOPE_REQ);

	return txn;
}

/* to be used at the end of a transaction */
void http_destroy_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;

	/* these ones will have been dynamically allocated */
	pool_free(pool_head_requri, txn->uri);
	pool_free(pool_head_capture, txn->cli_cookie);
	pool_free(pool_head_capture, txn->srv_cookie);
	pool_free(pool_head_uniqueid, s->unique_id.ptr);

	s->unique_id = IST_NULL;
	txn->uri = NULL;
	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;

	if (!LIST_ISEMPTY(&s->vars_txn.head))
		vars_prune(&s->vars_txn, s->sess, s);
	if (!LIST_ISEMPTY(&s->vars_reqres.head))
		vars_prune(&s->vars_reqres, s->sess, s);

	pool_free(pool_head_http_txn, txn);
	s->txn = NULL;
}


DECLARE_POOL(pool_head_http_txn, "http_txn", sizeof(struct http_txn));

__attribute__((constructor))
static void __http_protocol_init(void)
{
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
