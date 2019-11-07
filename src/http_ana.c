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

#include <common/base64.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/htx.h>
#include <common/uri_auth.h>

#include <types/capture.h>

#include <proto/acl.h>
#include <proto/action.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/connection.h>
#include <proto/filters.h>
#include <proto/http_htx.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/http_ana.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/stats.h>
#include <proto/vars.h>

#define TRACE_SOURCE &trace_strm

extern const char *stat_status_codes[];

struct pool_head *pool_head_requri = NULL;
struct pool_head *pool_head_capture = NULL;


static void http_end_request(struct stream *s);
static void http_end_response(struct stream *s);

static void http_capture_headers(struct htx *htx, char **cap, struct cap_hdr *cap_hdr);
static int http_del_hdr_value(char *start, char *end, char **from, char *next);
static size_t http_fmt_req_line(const struct htx_sl *sl, char *str, size_t len);
static void http_debug_stline(const char *dir, struct stream *s, const struct htx_sl *sl);
static void http_debug_hdr(const char *dir, struct stream *s, const struct ist n, const struct ist v);

static enum rule_result http_req_get_intercept_rule(struct proxy *px, struct list *rules, struct stream *s, int *deny_status);
static enum rule_result http_res_get_intercept_rule(struct proxy *px, struct list *rules, struct stream *s);

static void http_manage_client_side_cookies(struct stream *s, struct channel *req);
static void http_manage_server_side_cookies(struct stream *s, struct channel *res);

static int http_stats_check_uri(struct stream *s, struct http_txn *txn, struct proxy *backend);
static int http_handle_stats(struct stream *s, struct channel *req);

static int http_handle_expect_hdr(struct stream *s, struct htx *htx, struct http_msg *msg);
static int http_reply_100_continue(struct stream *s);
static int http_reply_40x_unauthorized(struct stream *s, const char *auth_realm);

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

	htx = htxbuf(&req->buf);

	/* Parsing errors are caught here */
	if (htx->flags & (HTX_FL_PARSING_ERROR|HTX_FL_PROCESSING_ERROR)) {
		stream_inc_http_req_ctr(s);
		stream_inc_http_err_ctr(s);
		proxy_inc_fe_req_ctr(sess->fe);
		if (htx->flags & HTX_FL_PARSING_ERROR)
			goto return_bad_req;
		else
			goto return_int_err;
	}

	/* we're speaking HTTP here, so let's speak HTTP to the client */
	s->srv_error = http_return_srv_error;

	/* If there is data available for analysis, log the end of the idle time. */
	if (c_data(req) && s->logs.t_idle == -1) {
		const struct cs_info *csinfo = si_get_cs_info(objt_cs(s->si[0].end));

		s->logs.t_idle = ((csinfo)
				  ? csinfo->t_idle
				  : tv_ms_elapsed(&s->logs.tv_accept, &now) - s->logs.t_handshake);
	}

	/*
	 * Now we quickly check if we have found a full valid request.
	 * If not so, we check the FD and buffer states before leaving.
	 * A full request is indicated by the fact that we have seen
	 * the double LF/CRLF, so the state is >= HTTP_MSG_BODY. Invalid
	 * requests are checked first. When waiting for a second request
	 * on a keep-alive stream, if we encounter and error, close, t/o,
	 * we note the error in the stream flags but don't set any state.
	 * Since the error will be noted there, it will not be counted by
	 * process_stream() as a frontend error.
	 * Last, we may increase some tracked counters' http request errors on
	 * the cases that are deliberately the client's fault. For instance,
	 * a timeout or connection reset is not counted as an error. However
	 * a bad request is.
	 */
	if (unlikely(htx_is_empty(htx) || htx->first == -1)) {
		if (htx->flags & HTX_FL_UPGRADE)
			goto failed_keep_alive;

		/* 1: have we encountered a read error ? */
		if (req->flags & CF_READ_ERROR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			stream_inc_http_err_ctr(s);
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			txn->status = 400;
			http_reply_and_close(s, txn->status, NULL);
			req->analysers &= AN_REQ_FLT_END;

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 2: has the read timeout expired ? */
		else if (req->flags & CF_READ_TIMEOUT || tick_is_expired(req->analyse_exp, now_ms)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLITO;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			stream_inc_http_err_ctr(s);
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			txn->status = 408;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 3: have we encountered a close ? */
		else if (req->flags & CF_SHUTR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			stream_inc_http_err_ctr(s);
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			txn->status = 400;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		channel_dont_connect(req);
		req->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */

		if (sess->listener->options & LI_O_NOQUICKACK && htx_is_not_empty(htx) &&
		    objt_conn(sess->origin) && conn_ctrl_ready(__objt_conn(sess->origin))) {
			/* We need more data, we have to re-enable quick-ack in case we
			 * previously disabled it, otherwise we might cause the client
			 * to delay next data.
			 */
			conn_set_quickack(objt_conn(sess->origin), 1);
		}

		if ((req->flags & CF_READ_PARTIAL) && (txn->flags & TX_WAIT_NEXT_RQ)) {
			/* If the client starts to talk, let's fall back to
			 * request timeout processing.
			 */
			txn->flags &= ~TX_WAIT_NEXT_RQ;
			req->analyse_exp = TICK_ETERNITY;
		}

		/* just set the request timeout once at the beginning of the request */
		if (!tick_isset(req->analyse_exp)) {
			if ((txn->flags & TX_WAIT_NEXT_RQ) && tick_isset(s->be->timeout.httpka))
				req->analyse_exp = tick_add(now_ms, s->be->timeout.httpka);
			else
				req->analyse_exp = tick_add_ifset(now_ms, s->be->timeout.httpreq);
		}

		/* we're not ready yet */
		DBG_TRACE_DEVEL("waiting for the request",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 0;

	failed_keep_alive:
		/* Here we process low-level errors for keep-alive requests. In
		 * short, if the request is not the first one and it experiences
		 * a timeout, read error or shutdown, we just silently close so
		 * that the client can try again.
		 */
		txn->status = 0;
		msg->msg_state = HTTP_MSG_RQBEFORE;
		req->analysers &= AN_REQ_FLT_END;
		s->logs.logwait = 0;
		s->logs.level = 0;
		s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
		http_reply_and_close(s, txn->status, NULL);
		DBG_TRACE_DEVEL("leaving by closing K/A connection",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 0;
	}

	msg->msg_state = HTTP_MSG_BODY;
	stream_inc_http_req_ctr(s);
	proxy_inc_fe_req_ctr(sess->fe); /* one more valid request for this FE */

	/* kill the pending keep-alive timeout */
	txn->flags &= ~TX_WAIT_NEXT_RQ;
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
	msg->flags |= ((sl->flags & HTX_SL_F_CLEN) ? HTTP_MSGF_CNT_LEN : HTTP_MSGF_TE_CHNK);
	if (sl->flags & HTX_SL_F_BODYLESS)
		msg->flags |= HTTP_MSGF_BODYLESS;

	/* we can make use of server redirect on GET and HEAD */
	if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
		s->flags |= SF_REDIRECTABLE;
	else if (txn->meth == HTTP_METH_OTHER && isteqi(htx_sl_req_meth(sl), ist("PRI"))) {
		/* PRI is reserved for the HTTP/2 preface */
		goto return_bad_req;
	}

	/*
	 * 2: check if the URI matches the monitor_uri.
	 * We have to do this for every request which gets in, because
	 * the monitor-uri is defined by the frontend.
	 */
	if (unlikely((sess->fe->monitor_uri_len != 0) &&
		     isteqi(htx_sl_req_uri(sl), ist2(sess->fe->monitor_uri, sess->fe->monitor_uri_len)))) {
		/*
		 * We have found the monitor URI
		 */
		struct acl_cond *cond;

		s->flags |= SF_MONITOR;
		_HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

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
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);
	goto return_prx_cond;

 return_bad_req:
	txn->status = 400;
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);
	/* fall through */

 return_prx_cond:
	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
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
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct htx *htx;
	struct redirect_rule *rule;
	enum rule_result verdict;
	int deny_status = HTTP_ERR_403;
	struct connection *conn = objt_conn(sess->origin);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		goto return_prx_yield;
	}

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	htx = htxbuf(&req->buf);

	/* just in case we have some per-backend tracking. Only called the first
	 * execution of the analyser. */
	if (!s->current_rule || s->current_rule_list != &px->http_req_rules)
		stream_inc_be_http_req_ctr(s);

	/* evaluate http-request rules */
	if (!LIST_ISEMPTY(&px->http_req_rules)) {
		verdict = http_req_get_intercept_rule(px, &px->http_req_rules, s, &deny_status);

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
		}
	}

	if (conn && (conn->flags & CO_FL_EARLY_DATA) &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_HANDSHAKE))) {
		struct http_hdr_ctx ctx;

		ctx.blk = NULL;
		if (!http_find_header(htx, ist("Early-Data"), &ctx, 0)) {
			if (unlikely(!http_add_header(htx, ist("Early-Data"), ist("1"))))
				goto return_bad_req;
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
			txn->status = 500;
			s->logs.tv_request = now;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			goto return_prx_cond;
		}

		/* parse the whole stats request and extract the relevant information */
		http_handle_stats(s, req);
		verdict = http_req_get_intercept_rule(px, &px->uri_auth->http_req_rules, s, &deny_status);
		/* not all actions implemented: deny, allow, auth */

		if (verdict == HTTP_RULE_RES_DENY) /* stats http-request deny */
			goto deny;

		if (verdict == HTTP_RULE_RES_ABRT) /* stats auth / stats http-request auth */
			goto return_prx_cond;
	}

	/* Proceed with the applets now. */
	if (unlikely(objt_applet(s->target))) {
		if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			_HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

		if (http_handle_expect_hdr(s, htx, msg) == -1)
			goto return_bad_req;

		if (!(s->flags & SF_ERR_MASK))      // this is not really an error but it is
			s->flags |= SF_ERR_LOCAL;   // to mark that it comes from the proxy
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_R;

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
			goto return_bad_req;
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
 done_without_exp: /* done with this analyser, but dont reset the analyse_exp. */
	req->analysers &= ~an_bit;
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

	txn->status = http_err_codes[deny_status];

	req->analysers &= AN_REQ_FLT_END; /* remove switching rules etc... */
	req->analysers |= AN_REQ_HTTP_TARPIT;
	req->analyse_exp = tick_add_ifset(now_ms,  s->be->timeout.tarpit);
	if (!req->analyse_exp)
		req->analyse_exp = tick_add(now_ms, 0);
	stream_inc_http_err_ctr(s);
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		_HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto done_without_exp;

 deny:	/* this request was blocked (denied) */

	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		http_manage_client_side_cookies(s, req);

	txn->flags |= TX_CLDENY;
	txn->status = http_err_codes[deny_status];
	s->logs.tv_request = now;
	http_reply_and_close(s, txn->status, http_error_message(s));
	stream_inc_http_err_ctr(s);
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		_HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto return_prx_cond;

 return_bad_req:
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
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
	struct http_msg *msg = &txn->req;
	struct htx *htx;
	struct connection *cli_conn = objt_conn(strm_sess(s)->origin);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		channel_dont_connect(req);
		return 0;
	}

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	/*
	 * Right now, we know that we have processed the entire headers
	 * and that unwanted requests have been filtered out. We can do
	 * whatever we want with the remaining request. Also, now we
	 * may have separate values for ->fe, ->be.
	 */
	htx = htxbuf(&req->buf);

	/*
	 * If HTTP PROXY is set we simply get remote server address parsing
	 * incoming request.
	 */
	if ((s->be->options & PR_O_HTTP_PROXY) && !(s->flags & SF_ADDR_SET)) {
		struct htx_sl *sl;
		struct ist uri, path;

		if (!sockaddr_alloc(&s->target_addr)) {
			txn->status = 500;
			req->analysers &= AN_REQ_FLT_END;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;

			DBG_TRACE_DEVEL("leaving on error",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
			return 0;
		}
		sl = http_get_stline(htx);
		uri = htx_sl_req_uri(sl);
		path = http_get_path(uri);

		if (url2sa(uri.ptr, uri.len - path.len, s->target_addr, NULL) == -1)
			goto return_bad_req;

		s->target = &s->be->obj_type;
		s->flags |= SF_ADDR_SET | SF_ASSIGNED;

		/* if the path was found, we have to remove everything between
		 * uri.ptr and path.ptr (excluded). If it was not found, we need
		 * to replace from all the uri by a single "/".
		 *
		 * Instead of rewritting the whole start line, we just update
		 * the star-line URI. Some space will be lost but it should be
		 * insignificant.
		 */
		istcpy(&uri, (path.len ? path : ist("/")), uri.len);
	}

	/*
	 * 7: Now we can work with the cookies.
	 * Note that doing so might move headers in the request, but
	 * the fields will stay coherent and the URI will not move.
	 * This should only be performed in the backend.
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		http_manage_client_side_cookies(s, req);

	/* add unique-id if "header-unique-id" is specified */

	if (!LIST_ISEMPTY(&sess->fe->format_unique_id) && !s->unique_id) {
		if ((s->unique_id = pool_alloc(pool_head_uniqueid)) == NULL)
			goto return_bad_req;
		s->unique_id[0] = '\0';
		build_logline(s, s->unique_id, UNIQUEID_LEN, &sess->fe->format_unique_id);
	}

	if (sess->fe->header_unique_id && s->unique_id) {
		struct ist n = ist2(sess->fe->header_unique_id, strlen(sess->fe->header_unique_id));
		struct ist v = ist2(s->unique_id, strlen(s->unique_id));

		if (unlikely(!http_add_header(htx, n, v)))
			goto return_bad_req;
	}

	/*
	 * 9: add X-Forwarded-For if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_FWDFOR) {
		struct http_hdr_ctx ctx = { .blk = NULL };
		struct ist hdr = ist2(s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_name : sess->fe->fwdfor_hdr_name,
				      s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_len : sess->fe->fwdfor_hdr_len);

		if (!((sess->fe->options | s->be->options) & PR_O_FF_ALWAYS) &&
		    http_find_header(htx, hdr, &ctx, 0)) {
			/* The header is set to be added only if none is present
			 * and we found it, so don't do anything.
			 */
		}
		else if (cli_conn && conn_get_src(cli_conn) && cli_conn->src->ss_family == AF_INET) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if ((!sess->fe->except_mask.s_addr ||
			     (((struct sockaddr_in *)cli_conn->src)->sin_addr.s_addr & sess->fe->except_mask.s_addr)
			     != sess->fe->except_net.s_addr) &&
			    (!s->be->except_mask.s_addr ||
			     (((struct sockaddr_in *)cli_conn->src)->sin_addr.s_addr & s->be->except_mask.s_addr)
			     != s->be->except_net.s_addr)) {
				unsigned char *pn = (unsigned char *)&((struct sockaddr_in *)cli_conn->src)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					goto return_bad_req;
			}
		}
		else if (cli_conn && conn_get_src(cli_conn) && cli_conn->src->ss_family == AF_INET6) {
			/* FIXME: for the sake of completeness, we should also support
			 * 'except' here, although it is mostly useless in this case.
			 */
			char pn[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6,
				  (const void *)&((struct sockaddr_in6 *)(cli_conn->src))->sin6_addr,
				  pn, sizeof(pn));

			/* Note: we rely on the backend to get the header name to be used for
			 * x-forwarded-for, because the header is really meant for the backends.
			 * However, if the backend did not specify any option, we have to rely
			 * on the frontend's header name.
			 */
			chunk_printf(&trash, "%s", pn);
			if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
				goto return_bad_req;
		}
	}

	/*
	 * 10: add X-Original-To if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_ORGTO) {

		/* FIXME: don't know if IPv6 can handle that case too. */
		if (cli_conn && conn_get_src(cli_conn) && cli_conn->src->ss_family == AF_INET && conn_get_dst(cli_conn)) {
			/* Add an X-Original-To header unless the destination IP is
			 * in the 'except' network range.
			 */
			if (cli_conn->dst->ss_family == AF_INET &&
			    ((!sess->fe->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)cli_conn->dst)->sin_addr.s_addr & sess->fe->except_mask_to.s_addr)
			      != sess->fe->except_to.s_addr) &&
			     (!s->be->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)cli_conn->dst)->sin_addr.s_addr & s->be->except_mask_to.s_addr)
			      != s->be->except_to.s_addr))) {
				struct ist hdr;
				unsigned char *pn = (unsigned char *)&((struct sockaddr_in *)cli_conn->dst)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-original-to, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (s->be->orgto_hdr_len)
					hdr = ist2(s->be->orgto_hdr_name, s->be->orgto_hdr_len);
				else
					hdr = ist2(sess->fe->orgto_hdr_name, sess->fe->orgto_hdr_len);

				chunk_printf(&trash, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					goto return_bad_req;
			}
		}
	}

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
	if ((sess->listener->options & LI_O_NOQUICKACK) &&
	    (htx_get_tail_type(htx) != HTX_BLK_EOM))
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

 return_bad_req: /* let's centralize all bad requests */
	txn->status = 400;
	req->analysers &= AN_REQ_FLT_END;
	http_reply_and_close(s, txn->status, http_error_message(s));

	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

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

	if (!(req->flags & CF_READ_ERROR))
		http_reply_and_close(s, txn->status, http_error_message(s));

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;

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
	struct htx *htx;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn, msg);

	htx = htxbuf(&req->buf);

	if (htx->flags & HTX_FL_PARSING_ERROR)
		goto return_bad_req;
	if (htx->flags & HTX_FL_PROCESSING_ERROR)
		goto return_int_err;

	if (msg->msg_state < HTTP_MSG_BODY)
		goto missing_data;

	/* We have to parse the HTTP request body to find any required data.
	 * "balance url_param check_post" should have been the only way to get
	 * into this. We were brought here after HTTP header analysis, so all
	 * related structures are ready.
	 */

	if (msg->msg_state < HTTP_MSG_DATA) {
		if (http_handle_expect_hdr(s, htx, msg) == -1)
			goto return_bad_req;
	}

	msg->msg_state = HTTP_MSG_DATA;

	/* Now we're in HTTP_MSG_DATA. We just need to know if all data have
	 * been received or if the buffer is full.
	 */
	if (htx_get_tail_type(htx) > HTX_BLK_DATA ||
	    channel_htx_full(req, htx, global.tune.maxrewrite))
		goto http_end;

 missing_data:
	if ((req->flags & CF_READ_TIMEOUT) || tick_is_expired(req->analyse_exp, now_ms)) {
		txn->status = 408;

		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_CLITO;
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_D;
		goto return_err_msg;
	}

	/* we get here if we need to wait for more data */
	if (!(req->flags & (CF_SHUTR | CF_READ_ERROR))) {
		/* Not enough data. We'll re-use the http-request
		 * timeout here. Ideally, we should set the timeout
		 * relative to the accept() date. We just set the
		 * request timeout once at the beginning of the
		 * request.
		 */
		channel_dont_connect(req);
		if (!tick_isset(req->analyse_exp))
			req->analyse_exp = tick_add_ifset(now_ms, s->be->timeout.httpreq);
		DBG_TRACE_DEVEL("waiting for more data",
				STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
		return 0;
	}

 http_end:
	/* The situation will not evolve, so let's give up on the analysis. */
	s->logs.tv_request = now;  /* update the request timer to reflect full request */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 1;

 return_int_err:
	txn->status = 500;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;
	goto return_err_msg;

 return_bad_req: /* let's centralize all bad requests */
	txn->status = 400;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;
	/* fall through */

 return_err_msg:
	http_reply_and_close(s, txn->status, http_error_message(s));

	req->analysers &= AN_REQ_FLT_END;
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);
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
		 */

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
			if (req->flags & (CF_SHUTR|CF_EOI)) {
				msg->msg_state = HTTP_MSG_DONE;
				req->to_forward = 0;
				goto done;
			}
		}
		else {
			/* We can't process the buffer's contents yet */
			req->flags |= CF_WAKE_WRITE;
			goto missing_data_or_waiting;
		}
	}

	if (msg->msg_state >= HTTP_MSG_DONE)
		goto done;
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

	if (txn->meth == HTTP_METH_CONNECT) {
		msg->msg_state = HTTP_MSG_TUNNEL;
		goto done;
	}


	/* Check if the end-of-message is reached and if so, switch the message
	 * in HTTP_MSG_ENDING state. Then if all data was marked to be
	 * forwarded, set the state to HTTP_MSG_DONE.
	 */
	if (htx_get_tail_type(htx) != HTX_BLK_EOM)
		goto missing_data_or_waiting;

	msg->msg_state = HTTP_MSG_ENDING;
	if (htx->data != co_data(req))
		goto missing_data_or_waiting;
	msg->msg_state = HTTP_MSG_DONE;
	req->to_forward = 0;

  done:
	/* other states, DONE...TUNNEL */
	/* we don't want to forward closes on DONE except in tunnel mode. */
	if (!(txn->flags & TX_CON_WANT_TUN))
		channel_dont_close(req);

	if (HAS_REQ_DATA_FILTERS(s)) {
		ret = flt_http_end(s, msg);
		if (ret <= 0) {
			if (!ret)
				goto missing_data_or_waiting;
			goto return_bad_req;
		}
	}

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
	if (msg->flags & HTTP_MSGF_TE_CHNK)
		req->flags |= CF_EXPECT_MORE;

	DBG_TRACE_DEVEL("waiting for more data to forward",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;

  return_cli_abort:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	status = 400;
	goto return_error;

  return_srv_abort:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	status = 502;
	goto return_error;

  return_int_err:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	status = 500;
	goto return_error;

  return_bad_req:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	status = 400;

  return_error:
	if (txn->status > 0) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = status;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	req->analysers   &= AN_REQ_FLT_END;
	s->res.analysers &= AN_RES_FLT_END; /* we're in data phase, we want to abort both directions */
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

	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.retries, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.retries, 1);

	req = &s->req;
	res = &s->res;
	/* Remove any write error from the request, and read error from the response */
	req->flags &= ~(CF_WRITE_ERROR | CF_WRITE_TIMEOUT | CF_SHUTW | CF_SHUTW_NOW);
	res->flags &= ~(CF_READ_ERROR | CF_READ_TIMEOUT | CF_SHUTR | CF_EOI | CF_READ_NULL | CF_SHUTR_NOW);
	res->analysers = 0;
	si->flags &= ~(SI_FL_ERR | SI_FL_EXP | SI_FL_RXBLK_SHUT);
	stream_choose_redispatch(s);
	si->exp = TICK_ETERNITY;
	res->rex = TICK_ETERNITY;
	res->to_forward = 0;
	res->analyse_exp = TICK_ETERNITY;
	res->total = 0;
	s->flags &= ~(SF_ERR_SRVTO | SF_ERR_SRVCL);
	si_release_endpoint(&s->si[1]);
	b_free(&req->buf);
	/* Swap the L7 buffer with the channel buffer */
	/* We know we stored the co_data as b_data, so get it there */
	co_data = b_data(&si->l7_buffer);
	b_set_data(&si->l7_buffer, b_size(&si->l7_buffer));
	b_xfer(&req->buf, &si->l7_buffer, b_data(&si->l7_buffer));

	co_set_data(req, co_data);
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
				conn = objt_cs(s->si[1].end)->conn;

			if (si_b->flags & SI_FL_L7_RETRY &&
			    (!conn || conn->err_code != CO_ER_SSL_EARLY_FAILED)) {
				/* If we arrive here, then CF_READ_ERROR was
				 * set by si_cs_recv() because we matched a
				 * status, overwise it would have removed
				 * the SI_FL_L7_RETRY flag, so it's ok not
				 * to check s->be->retry_type.
				 */
				if (co_data(rep) || do_l7_retry(s, si_b) == 0)
					return 0;
			}

			if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_READ_ERROR);
			}

			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;

			/* Check to see if the server refused the early data.
			 * If so, just send a 425
			 */
			if (conn->err_code == CO_ER_SSL_EARLY_FAILED) {
				if ((s->be->retry_type & PR_RE_EARLY_ERROR) &&
				    (si_b->flags & SI_FL_L7_RETRY) &&
				    do_l7_retry(s, si_b) == 0) {
					DBG_TRACE_DEVEL("leaving on L7 retry",
							STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
					return 0;
				}
				txn->status = 425;
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
			_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_READ_TIMEOUT);
			}

			rep->analysers &= AN_RES_FLT_END;
			txn->status = 504;
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
			_HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
			_HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
			if (objt_server(s->target))
				_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.cli_aborts, 1);

			rep->analysers &= AN_RES_FLT_END;
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

			_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_BROKEN_PIPE);
			}

			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;
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

			_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
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
	msg->msg_state = HTTP_MSG_BODY;
	BUG_ON(htx_get_first_type(htx) != HTX_BLK_RES_SL);
	sl = http_get_stline(htx);

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
		msg->flags |= ((sl->flags & HTX_SL_F_CLEN) ? HTTP_MSGF_CNT_LEN : HTTP_MSGF_TE_CHNK);
		if (sl->flags & HTX_SL_F_BODYLESS)
			msg->flags |= HTTP_MSGF_BODYLESS;
	}

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

	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.p.http.rsp[n], 1);

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
		goto next_one;
	}

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
	if (unlikely((txn->meth == HTTP_METH_CONNECT && txn->status == 200) ||
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
			if ((ctx.value.len >= 9 && word_match(ctx.value.ptr, ctx.value.len, "Negotiate", 9)) ||
			    (ctx.value.len >= 4 && word_match(ctx.value.ptr, ctx.value.len, "NTLM", 4))) {
				sess->flags |= SESS_FL_PREFER_LAST;
				srv_conn->flags |= CO_FL_PRIVATE;
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
	_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	txn->status = 500;
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	goto return_error;

  return_bad_res:
	_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	if (objt_server(s->target)) {
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
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
	/* fall through */

 return_error:
	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_H;

	s->si[1].flags |= SI_FL_NOLINGER;
	rep->analysers &= AN_RES_FLT_END;
	rep->analyse_exp = TICK_ETERNITY;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;

 abort_keep_alive:
	/* A keep-alive request to the server failed on a network error.
	 * The client is required to retry. We need to close without returning
	 * any other information so that the client retries.
	 */
	txn->status = 0;
	rep->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END;
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
	 * pointer. If none of theses "struct proxy" match, I initialise
	 * the process with the first one.
	 *
	 * In fact, I check only correspondance betwwen the current list
	 * pointer and the ->fe rule list. If it doesn't match, I initialize
	 * the loop with the ->be.
	 */
	if (s->current_rule_list == &sess->fe->http_res_rules)
		cur_proxy = sess->fe;
	else
		cur_proxy = s->be;
	while (1) {
		/* evaluate http-response rules */
		if (ret == HTTP_RULE_RES_CONT) {
			ret = http_res_get_intercept_rule(cur_proxy, &cur_proxy->http_res_rules, s);

			if (ret == HTTP_RULE_RES_BADREQ)
				goto return_srv_prx_502;

			if (ret == HTTP_RULE_RES_DONE) {
				rep->analysers &= ~an_bit;
				rep->analyse_exp = TICK_ETERNITY;
				return 1;
			}
		}

		/* we need to be called again. */
		if (ret == HTTP_RULE_RES_YIELD) {
			channel_dont_close(rep);
			DBG_TRACE_DEVEL("waiting for more data",
					STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
			return 0;
		}

		/* has the response been denied ? */
		if (txn->flags & TX_SVDENY) {
			if (objt_server(s->target))
				_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_secu, 1);

			_HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
			_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
			if (sess->listener->counters)
				_HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);
			goto return_srv_prx_502;
		}

		/* check whether we're already working on the frontend */
		if (cur_proxy == sess->fe)
			break;
		cur_proxy = sess->fe;
	}

	/* After this point, this anayzer can't return yield, so we can
	 * remove the bit corresponding to this analyzer from the list.
	 *
	 * Note that the intermediate returns and goto found previously
	 * reset the analyzers.
	 */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;

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
		if (!objt_server(s->target)->cookie) {
			chunk_printf(&trash,
				     "%s=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/",
				     s->be->cookie_name);
		}
		else {
			chunk_printf(&trash, "%s=%s", s->be->cookie_name, objt_server(s->target)->cookie);

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

		if (unlikely(!http_add_header(htx, ist("Set-Cookie"), ist2(trash.area, trash.data))))
			goto return_bad_resp;

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
				goto return_bad_resp;
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
		if (objt_server(s->target))
			_HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_secu, 1);

		_HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
		_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
		if (sess->listener->counters)
			_HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);

		ha_alert("Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		send_log(s->be, LOG_ALERT,
			 "Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		goto return_srv_prx_502;
	}

  end:
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
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 1;

  return_bad_resp:
	if (objt_server(s->target)) {
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
		health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_RSP);
	}
	_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);

  return_srv_prx_502:
	rep->analysers &= AN_RES_FLT_END;
	txn->status = 502;
	s->logs.t_data = -1; /* was not a valid response */
	s->si[1].flags |= SI_FL_NOLINGER;
	http_reply_and_close(s, txn->status, http_error_message(s));
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_H;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
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
			if (res->flags & (CF_SHUTR|CF_EOI)) {
				msg->msg_state = HTTP_MSG_DONE;
				res->to_forward = 0;
				goto done;
			}
		}
		else {
			/* We can't process the buffer's contents yet */
			res->flags |= CF_WAKE_WRITE;
			goto missing_data_or_waiting;
		}
	}

	if (msg->msg_state >= HTTP_MSG_DONE)
		goto done;

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

	if ((txn->meth == HTTP_METH_CONNECT && txn->status == 200) || txn->status == 101 ||
	    (!(msg->flags & HTTP_MSGF_XFER_LEN) && (res->flags & CF_SHUTR || !HAS_RSP_DATA_FILTERS(s)))) {
		msg->msg_state = HTTP_MSG_TUNNEL;
		goto done;
	}

	/* Check if the end-of-message is reached and if so, switch the message
	 * in HTTP_MSG_ENDING state. Then if all data was marked to be
	 * forwarded, set the state to HTTP_MSG_DONE.
	 */
	if (htx_get_tail_type(htx) != HTX_BLK_EOM)
		goto missing_data_or_waiting;

	msg->msg_state = HTTP_MSG_ENDING;
	if (htx->data != co_data(res))
		goto missing_data_or_waiting;
	msg->msg_state = HTTP_MSG_DONE;
	res->to_forward = 0;

  done:
	/* other states, DONE...TUNNEL */
	channel_dont_close(res);

	if (HAS_RSP_DATA_FILTERS(s)) {
		ret = flt_http_end(s, msg);
		if (ret <= 0) {
			if (!ret)
				goto missing_data_or_waiting;
			goto return_bad_res;
		}
	}

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
	if ((msg->flags & HTTP_MSGF_TE_CHNK) || (msg->flags & HTTP_MSGF_COMPRESSING))
		res->flags |= CF_EXPECT_MORE;

	/* the stream handler will take care of timeouts and errors */
	DBG_TRACE_DEVEL("waiting for more data to forward",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA, s, txn);
	return 0;

  return_srv_abort:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	goto return_error;

  return_cli_abort:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	goto return_error;

  return_int_err:
	_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	goto return_error;

  return_bad_res:
	_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	if (objt_server(s->target)) {
		_HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
		health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_RSP);
	}
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;

   return_error:
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	res->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END; /* we're in data phase, we want to abort both directions */
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	DBG_TRACE_DEVEL("leaving on error",
			STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_HTTP_ERR, s, txn);
	return 0;
}

/* Perform an HTTP redirect based on the information in <rule>. The function
 * returns zero on success, or zero in case of a, irrecoverable error such
 * as too large a request to build a valid response.
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
	size_t data;
	int close = 0; /* Try to keep the connection alive byt default */

	chunk = alloc_trash_chunk();
	if (!chunk)
		goto fail;

	/*
	 * Create the location
	 */
	htx = htxbuf(&req->buf);
	switch(rule->type) {
		case REDIRECT_TYPE_SCHEME: {
			struct http_hdr_ctx ctx;
			struct ist path, host;

			host = ist("");
			ctx.blk = NULL;
			if (http_find_header(htx, ist("Host"), &ctx, 0))
				host = ctx.value;

			sl = http_get_stline(htx);
			path = http_get_path(htx_sl_req_uri(sl));
			/* build message using path */
			if (path.ptr) {
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

			sl = http_get_stline(htx);
			path = http_get_path(htx_sl_req_uri(sl));
			/* build message using path */
			if (path.ptr) {
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
				chunk->data += build_logline(s, chunk->area + chunk->data,
							     chunk->size - chunk->data,
							     &rule->rdr_fmt);
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

	if (!htx_add_endof(htx, HTX_BLK_EOH) || !htx_add_endof(htx, HTX_BLK_EOM))
		goto fail;

	/* let's log the request time */
	s->logs.tv_request = now;

	htx->flags |= HTX_FL_PROXY_RESP;
	data = htx->data - co_data(res);
	c_adv(res, data);
	res->total += data;

	channel_auto_read(req);
	channel_abort(req);
	channel_auto_close(req);
	channel_htx_erase(req, htxbuf(&req->buf));

	res->wex = tick_add_ifset(now_ms, res->wto);
	channel_auto_read(res);
	channel_auto_close(res);
	channel_shutr_now(res);

	req->analysers &= AN_REQ_FLT_END;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_LOCAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	free_trash_chunk(chunk);
	return 1;

  fail:
	/* If an error occurred, remove the incomplete HTTP response from the
	 * buffer */
	channel_htx_truncate(res, htxbuf(&res->buf));
	free_trash_chunk(chunk);
	return 0;
}

int http_transform_header_str(struct stream* s, struct channel *chn, struct htx *htx,
			      struct ist name, const char *str, struct my_regex *re, int action)
{
	struct http_hdr_ctx ctx;
	struct buffer *output = get_trash_chunk();

	/* find full header is action is ACT_HTTP_REPLACE_HDR */
	ctx.blk = NULL;
	while (http_find_header(htx, name, &ctx, (action == ACT_HTTP_REPLACE_HDR))) {
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

static int http_transform_header(struct stream* s, struct channel *chn, struct htx *htx,
				 const struct ist name, struct list *fmt, struct my_regex *re, int action)
{
	struct buffer *replace;
	int ret = -1;

	replace = alloc_trash_chunk();
	if (!replace)
		goto leave;

	replace->data = build_logline(s, replace->area, replace->size, fmt);
	if (replace->data >= replace->size - 1)
		goto leave;

	ret = http_transform_header_str(s, chn, htx, name, replace->area, re, action);

  leave:
	free_trash_chunk(replace);
	return ret;
}


/* Terminate a 103-Erly-hints response and send it to the client. It returns 0
 * on success and -1 on error. The response channel is updated accordingly.
 */
static int http_reply_103_early_hints(struct channel *res)
{
	struct htx *htx = htx_from_buf(&res->buf);
	size_t data;

	if (!htx_add_endof(htx, HTX_BLK_EOH)) {
		/* If an error occurred during an Early-hint rule,
		 * remove the incomplete HTTP 103 response from the
		 * buffer */
		channel_htx_truncate(res, htx);
		return -1;
	}

	data = htx->data - co_data(res);
	c_adv(res, data);
	res->total += data;
	return 0;
}

/*
 * Build an HTTP Early Hint HTTP 103 response header with <name> as name and with a value
 * built according to <fmt> log line format.
 * If <early_hints> is 0, it is starts a new response by adding the start
 * line. If an error occurred -1 is returned. On success 0 is returned. The
 * channel is not updated here. It must be done calling the function
 * http_reply_103_early_hints().
 */
static int http_add_early_hint_header(struct stream *s, int early_hints, const struct ist name, struct list *fmt)
{
	struct channel *res = &s->res;
	struct htx *htx = htx_from_buf(&res->buf);
	struct buffer *value = alloc_trash_chunk();

	if (!early_hints) {
		struct htx_sl *sl;
		unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|
				      HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);

		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
				    ist("HTTP/1.1"), ist("103"), ist("Early Hints"));
		if (!sl)
			goto fail;
		sl->info.res.status = 103;
	}

	value->data = build_logline(s, b_tail(value), b_room(value), fmt);
	if (!htx_add_header(htx, name, ist2(b_head(value), b_data(value))))
		goto fail;

	free_trash_chunk(value);
	return 1;

  fail:
	/* If an error occurred during an Early-hint rule, remove the incomplete
	 * HTTP 103 response from the buffer */
	channel_htx_truncate(res, htx);
	free_trash_chunk(value);
	return -1;
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
 * query string and 3 to replace uri.
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
			if (!http_replace_req_path(htx, ist2(replace, len)))
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

		default:
			return -1;
	}
	return 0;
}

/* This function replace the HTTP status code and the associated message. The
 * variable <status> contains the new status code. This function never fails.
 */
void http_res_set_status(unsigned int status, const char *reason, struct stream *s)
{
	struct htx *htx = htxbuf(&s->res.buf);
	char *res;

	chunk_reset(&trash);
	res = ultoa_o(status, trash.area, trash.size);
	trash.data = res - trash.area;

	/* Do we have a custom reason format string? */
	if (reason == NULL)
		reason = http_get_reason(status);

	if (http_replace_res_status(htx, ist2(trash.area, trash.data)))
		http_replace_res_reason(htx, ist2(reason, strlen(reason)));
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
static enum rule_result http_req_get_intercept_rule(struct proxy *px, struct list *rules,
						    struct stream *s, int *deny_status)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct htx *htx;
	struct act_rule *rule;
	struct http_hdr_ctx ctx;
	const char *auth_realm;
	enum rule_result rule_ret = HTTP_RULE_RES_CONT;
	int act_flags = 0;
	int early_hints = 0;

	htx = htxbuf(&s->req.buf);

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == rules)
			goto resume_execution;
	}
	s->current_rule_list = rules;

	list_for_each_entry(rule, rules, list) {
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

		act_flags |= ACT_FLAG_FIRST;
  resume_execution:
		if (early_hints && rule->action != ACT_HTTP_EARLY_HINT) {
			early_hints = 0;
			if (http_reply_103_early_hints(&s->res) == -1) {
				rule_ret = HTTP_RULE_RES_BADREQ;
				goto end;
			}
		}

		switch (rule->action) {
			case ACT_ACTION_ALLOW:
				rule_ret = HTTP_RULE_RES_STOP;
				goto end;

			case ACT_ACTION_DENY:
				if (deny_status)
					*deny_status = rule->deny_status;
				rule_ret = HTTP_RULE_RES_DENY;
				goto end;

			case ACT_HTTP_REQ_TARPIT:
				txn->flags |= TX_CLTARPIT;
				if (deny_status)
					*deny_status = rule->deny_status;
				rule_ret = HTTP_RULE_RES_DENY;
				goto end;

			case ACT_HTTP_REQ_AUTH:
				/* Auth might be performed on regular http-req rules as well as on stats */
				auth_realm = rule->arg.auth.realm;
				if (!auth_realm) {
					if (px->uri_auth && rules == &px->uri_auth->http_req_rules)
						auth_realm = STATS_DEFAULT_REALM;
					else
						auth_realm = px->id;
				}
				/* send 401/407 depending on whether we use a proxy or not. We still
				 * count one error, because normal browsing won't significantly
				 * increase the counter but brute force attempts will.
				 */
				rule_ret = HTTP_RULE_RES_ABRT;
				if (http_reply_40x_unauthorized(s, auth_realm) == -1)
					rule_ret = HTTP_RULE_RES_BADREQ;
				stream_inc_http_err_ctr(s);
				goto end;

			case ACT_HTTP_REDIR:
				rule_ret = HTTP_RULE_RES_DONE;
				if (!http_apply_redirect_rule(rule->arg.redir, s, txn))
					rule_ret = HTTP_RULE_RES_BADREQ;
				goto end;

			case ACT_HTTP_SET_NICE:
				s->task->nice = rule->arg.nice;
				break;

			case ACT_HTTP_SET_TOS:
				conn_set_tos(objt_conn(sess->origin), rule->arg.tos);
				break;

			case ACT_HTTP_SET_MARK:
				conn_set_mark(objt_conn(sess->origin), rule->arg.mark);
				break;

			case ACT_HTTP_SET_LOGL:
				s->logs.level = rule->arg.loglevel;
				break;

			case ACT_HTTP_REPLACE_HDR:
			case ACT_HTTP_REPLACE_VAL:
				if (http_transform_header(s, &s->req, htx,
							  ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len),
							  &rule->arg.hdr_add.fmt,
							  rule->arg.hdr_add.re, rule->action)) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}
				break;

			case ACT_HTTP_DEL_HDR:
				/* remove all occurrences of the header */
				ctx.blk = NULL;
				while (http_find_header(htx, ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len), &ctx, 1))
					http_remove_header(htx, &ctx);
				break;

			case ACT_HTTP_SET_HDR:
			case ACT_HTTP_ADD_HDR: {
				/* The scope of the trash buffer must be limited to this function. The
				 * build_logline() function can execute a lot of other function which
				 * can use the trash buffer. So for limiting the scope of this global
				 * buffer, we build first the header value using build_logline, and
				 * after we store the header name.
				 */
				struct buffer *replace;
				struct ist n, v;

				replace = alloc_trash_chunk();
				if (!replace) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				replace->data = build_logline(s, replace->area, replace->size, &rule->arg.hdr_add.fmt);
				n = ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len);
				v = ist2(replace->area, replace->data);

				if (rule->action == ACT_HTTP_SET_HDR) {
					/* remove all occurrences of the header */
					ctx.blk = NULL;
					while (http_find_header(htx, ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len), &ctx, 1))
						http_remove_header(htx, &ctx);
				}

				if (!http_add_header(htx, n, v)) {
					static unsigned char rate_limit = 0;

					if ((rate_limit++ & 255) == 0) {
						send_log(px, LOG_WARNING, "Proxy %s failed to add or set the request header '%.*s' for request #%u. You might need to increase tune.maxrewrite.", px->id, (int)n.len, n.ptr, s->uniq_id);
					}

					_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_rewrites, 1);
					if (sess->fe != s->be)
						_HA_ATOMIC_ADD(&s->be->be_counters.failed_rewrites, 1);
					if (sess->listener->counters)
						_HA_ATOMIC_ADD(&sess->listener->counters->failed_rewrites, 1);
				}
				free_trash_chunk(replace);
				break;
			}

			case ACT_HTTP_DEL_ACL:
			case ACT_HTTP_DEL_MAP: {
				struct pat_ref *ref;
				struct buffer *key;

				/* collect reference */
				ref = pat_ref_lookup(rule->arg.map.ref);
				if (!ref)
					continue;

				/* allocate key */
				key = alloc_trash_chunk();
				if (!key) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* collect key */
				key->data = build_logline(s, key->area, key->size, &rule->arg.map.key);
				key->area[key->data] = '\0';

				/* perform update */
				/* returned code: 1=ok, 0=ko */
				HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
				pat_ref_delete(ref, key->area);
				HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);

				free_trash_chunk(key);
				break;
			}

			case ACT_HTTP_ADD_ACL: {
				struct pat_ref *ref;
				struct buffer *key;

				/* collect reference */
				ref = pat_ref_lookup(rule->arg.map.ref);
				if (!ref)
					continue;

				/* allocate key */
				key = alloc_trash_chunk();
				if (!key) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* collect key */
				key->data = build_logline(s, key->area, key->size, &rule->arg.map.key);
				key->area[key->data] = '\0';

				/* perform update */
				/* add entry only if it does not already exist */
				HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
				if (pat_ref_find_elt(ref, key->area) == NULL)
					pat_ref_add(ref, key->area, NULL, NULL);
				HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);

				free_trash_chunk(key);
				break;
			}

			case ACT_HTTP_SET_MAP: {
				struct pat_ref *ref;
				struct buffer *key, *value;

				/* collect reference */
				ref = pat_ref_lookup(rule->arg.map.ref);
				if (!ref)
					continue;

				/* allocate key */
				key = alloc_trash_chunk();
				if (!key) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* allocate value */
				value = alloc_trash_chunk();
				if (!value) {
					free_trash_chunk(key);
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* collect key */
				key->data = build_logline(s, key->area, key->size, &rule->arg.map.key);
				key->area[key->data] = '\0';

				/* collect value */
				value->data = build_logline(s, value->area, value->size, &rule->arg.map.value);
				value->area[value->data] = '\0';

				/* perform update */
				HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
				if (pat_ref_find_elt(ref, key->area) != NULL)
					/* update entry if it exists */
					pat_ref_set(ref, key->area, value->area, NULL);
				else
					/* insert a new entry */
					pat_ref_add(ref, key->area, value->area, NULL);
				HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
				free_trash_chunk(key);
				free_trash_chunk(value);
				break;
			}

			case ACT_HTTP_EARLY_HINT:
				if (!(txn->req.flags & HTTP_MSGF_VER_11))
					break;
				early_hints = http_add_early_hint_header(s, early_hints,
									 ist2(rule->arg.early_hint.name, rule->arg.early_hint.name_len),
									 &rule->arg.early_hint.fmt);
				if (early_hints == -1) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}
				break;

			case ACT_CUSTOM:
				if ((s->req.flags & CF_READ_ERROR) ||
				    ((s->req.flags & (CF_SHUTR|CF_READ_NULL)) &&
				     (px->options & PR_O_ABRT_CLOSE)))
					act_flags |= ACT_FLAG_FINAL;

				switch (rule->action_ptr(rule, px, s->sess, s, act_flags)) {
					case ACT_RET_ERR:
					case ACT_RET_CONT:
						break;
					case ACT_RET_STOP:
						rule_ret = HTTP_RULE_RES_STOP;
						goto end;
					case ACT_RET_DONE:
						rule_ret = HTTP_RULE_RES_DONE;
						goto end;
					case ACT_RET_YIELD:
						s->current_rule = rule;
						rule_ret = HTTP_RULE_RES_YIELD;
						goto end;
				}
				break;

			case ACT_ACTION_TRK_SC0 ... ACT_ACTION_TRK_SCMAX:
				/* Note: only the first valid tracking parameter of each
				 * applies.
				 */

				if (stkctr_entry(&s->stkctr[trk_idx(rule->action)]) == NULL) {
					struct stktable *t;
					struct stksess *ts;
					struct stktable_key *key;
					void *ptr1, *ptr2;

					t = rule->arg.trk_ctr.table.t;
					key = stktable_fetch_key(t, s->be, sess, s, SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
								 rule->arg.trk_ctr.expr, NULL);

					if (key && (ts = stktable_get_entry(t, key))) {
						stream_track_stkctr(&s->stkctr[trk_idx(rule->action)], t, ts);

						/* let's count a new HTTP request as it's the first time we do it */
						ptr1 = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_CNT);
						ptr2 = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_RATE);
						if (ptr1 || ptr2) {
							HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

							if (ptr1)
								stktable_data_cast(ptr1, http_req_cnt)++;

							if (ptr2)
								update_freq_ctr_period(&stktable_data_cast(ptr2, http_req_rate),
										       t->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);

							HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

							/* If data was modified, we need to touch to re-schedule sync */
							stktable_touch_local(t, ts, 0);
						}

						stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_CONTENT);
						if (sess->fe != s->be)
							stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_BACKEND);
					}
				}
				break;

				/* other flags exists, but normally, they never be matched. */
			default:
				break;
		}
	}

  end:
	if (early_hints) {
		if (http_reply_103_early_hints(&s->res) == -1)
			rule_ret = HTTP_RULE_RES_BADREQ;
	}

	/* we reached the end of the rules, nothing to report */
	return rule_ret;
}

/* Executes the http-response rules <rules> for stream <s> and proxy <px>. It
 * returns one of 5 possible statuses: HTTP_RULE_RES_CONT, HTTP_RULE_RES_STOP,
 * HTTP_RULE_RES_DONE, HTTP_RULE_RES_YIELD, or HTTP_RULE_RES_BADREQ. If *CONT
 * is returned, the process can continue the evaluation of next rule list. If
 * *STOP or *DONE is returned, the process must stop the evaluation. If *BADREQ
 * is returned, it means the operation could not be processed and a server error
 * must be returned. It may set the TX_SVDENY on txn->flags if it encounters a
 * deny rule. If *YIELD is returned, the caller must call again the function
 * with the same context.
 */
static enum rule_result http_res_get_intercept_rule(struct proxy *px, struct list *rules,
						    struct stream *s)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct htx *htx;
	struct act_rule *rule;
	struct http_hdr_ctx ctx;
	enum rule_result rule_ret = HTTP_RULE_RES_CONT;
	int act_flags = 0;

	htx = htxbuf(&s->res.buf);

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == rules)
			goto resume_execution;
	}
	s->current_rule_list = rules;

	list_for_each_entry(rule, rules, list) {
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

		act_flags |= ACT_FLAG_FIRST;
resume_execution:
		switch (rule->action) {
			case ACT_ACTION_ALLOW:
				rule_ret = HTTP_RULE_RES_STOP; /* "allow" rules are OK */
				goto end;

			case ACT_ACTION_DENY:
				txn->flags |= TX_SVDENY;
				rule_ret = HTTP_RULE_RES_STOP;
				goto end;

			case ACT_HTTP_SET_NICE:
				s->task->nice = rule->arg.nice;
				break;

			case ACT_HTTP_SET_TOS:
				conn_set_tos(objt_conn(sess->origin), rule->arg.tos);
				break;

			case ACT_HTTP_SET_MARK:
				conn_set_mark(objt_conn(sess->origin), rule->arg.mark);
				break;

			case ACT_HTTP_SET_LOGL:
				s->logs.level = rule->arg.loglevel;
				break;

			case ACT_HTTP_REPLACE_HDR:
			case ACT_HTTP_REPLACE_VAL:
				if (http_transform_header(s, &s->res, htx,
							  ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len),
							  &rule->arg.hdr_add.fmt,
							  rule->arg.hdr_add.re, rule->action)) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}
				break;

			case ACT_HTTP_DEL_HDR:
				/* remove all occurrences of the header */
				ctx.blk = NULL;
				while (http_find_header(htx, ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len), &ctx, 1))
					http_remove_header(htx, &ctx);
				break;

			case ACT_HTTP_SET_HDR:
			case ACT_HTTP_ADD_HDR: {
				struct buffer *replace;
				struct ist n, v;

				replace = alloc_trash_chunk();
				if (!replace) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				replace->data = build_logline(s, replace->area, replace->size, &rule->arg.hdr_add.fmt);
				n = ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len);
				v = ist2(replace->area, replace->data);

				if (rule->action == ACT_HTTP_SET_HDR) {
					/* remove all occurrences of the header */
					ctx.blk = NULL;
					while (http_find_header(htx, ist2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len), &ctx, 1))
						http_remove_header(htx, &ctx);
				}

				if (!http_add_header(htx, n, v)) {
					static unsigned char rate_limit = 0;

					if ((rate_limit++ & 255) == 0) {
						send_log(px, LOG_WARNING, "Proxy %s failed to add or set the response header '%.*s' for request #%u. You might need to increase tune.maxrewrite.", px->id, (int)n.len, n.ptr, s->uniq_id);
					}

					_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_rewrites, 1);
					if (sess->fe != s->be)
						_HA_ATOMIC_ADD(&s->be->be_counters.failed_rewrites, 1);
					if (sess->listener->counters)
						_HA_ATOMIC_ADD(&sess->listener->counters->failed_rewrites, 1);
					if (objt_server(s->target))
						_HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_rewrites, 1);
				}
				free_trash_chunk(replace);
				break;
			}

			case ACT_HTTP_DEL_ACL:
			case ACT_HTTP_DEL_MAP: {
				struct pat_ref *ref;
				struct buffer *key;

				/* collect reference */
				ref = pat_ref_lookup(rule->arg.map.ref);
				if (!ref)
					continue;

			/* allocate key */
				key = alloc_trash_chunk();
				if (!key) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* collect key */
				key->data = build_logline(s, key->area, key->size, &rule->arg.map.key);
				key->area[key->data] = '\0';

				/* perform update */
				/* returned code: 1=ok, 0=ko */
				HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
				pat_ref_delete(ref, key->area);
				HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);

				free_trash_chunk(key);
				break;
			}

			case ACT_HTTP_ADD_ACL: {
				struct pat_ref *ref;
				struct buffer *key;

				/* collect reference */
				ref = pat_ref_lookup(rule->arg.map.ref);
				if (!ref)
					continue;

				/* allocate key */
				key = alloc_trash_chunk();
				if (!key) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* collect key */
				key->data = build_logline(s, key->area, key->size, &rule->arg.map.key);
				key->area[key->data] = '\0';

				/* perform update */
				/* check if the entry already exists */
				HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
				if (pat_ref_find_elt(ref, key->area) == NULL)
					pat_ref_add(ref, key->area, NULL, NULL);
				HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
				free_trash_chunk(key);
				break;
			}

			case ACT_HTTP_SET_MAP: {
				struct pat_ref *ref;
				struct buffer *key, *value;

				/* collect reference */
				ref = pat_ref_lookup(rule->arg.map.ref);
				if (!ref)
					continue;

				/* allocate key */
				key = alloc_trash_chunk();
				if (!key) {
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* allocate value */
				value = alloc_trash_chunk();
				if (!value) {
					free_trash_chunk(key);
					rule_ret = HTTP_RULE_RES_BADREQ;
					goto end;
				}

				/* collect key */
				key->data = build_logline(s, key->area, key->size, &rule->arg.map.key);
				key->area[key->data] = '\0';

				/* collect value */
				value->data = build_logline(s, value->area, value->size, &rule->arg.map.value);
				value->area[value->data] = '\0';

				/* perform update */
				HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
				if (pat_ref_find_elt(ref, key->area) != NULL)
					/* update entry if it exists */
					pat_ref_set(ref, key->area, value->area, NULL);
				else
					/* insert a new entry */
					pat_ref_add(ref, key->area, value->area, NULL);
				HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
				free_trash_chunk(key);
				free_trash_chunk(value);
				break;
			}

			case ACT_HTTP_REDIR:
				rule_ret = HTTP_RULE_RES_DONE;
				if (!http_apply_redirect_rule(rule->arg.redir, s, txn))
					rule_ret = HTTP_RULE_RES_BADREQ;
				goto end;

			case ACT_ACTION_TRK_SC0 ... ACT_ACTION_TRK_SCMAX:
				/* Note: only the first valid tracking parameter of each
				 * applies.
				 */
				if (stkctr_entry(&s->stkctr[trk_idx(rule->action)]) == NULL) {
					struct stktable *t;
					struct stksess *ts;
					struct stktable_key *key;
					void *ptr;

					t = rule->arg.trk_ctr.table.t;
					key = stktable_fetch_key(t, s->be, sess, s, SMP_OPT_DIR_RES | SMP_OPT_FINAL,
								 rule->arg.trk_ctr.expr, NULL);

					if (key && (ts = stktable_get_entry(t, key))) {
						stream_track_stkctr(&s->stkctr[trk_idx(rule->action)], t, ts);

						HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

						/* let's count a new HTTP request as it's the first time we do it */
						ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_CNT);
						if (ptr)
							stktable_data_cast(ptr, http_req_cnt)++;

						ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_RATE);
						if (ptr)
							update_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
									       t->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);

						/* When the client triggers a 4xx from the server, it's most often due
						 * to a missing object or permission. These events should be tracked
						 * because if they happen often, it may indicate a brute force or a
						 * vulnerability scan. Normally this is done when receiving the response
						 * but here we're tracking after this ought to have been done so we have
						 * to do it on purpose.
						 */
						if ((unsigned)(txn->status - 400) < 100) {
							ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_ERR_CNT);
							if (ptr)
								stktable_data_cast(ptr, http_err_cnt)++;

							ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_ERR_RATE);
							if (ptr)
								update_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
										       t->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u, 1);
						}

						HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

						/* If data was modified, we need to touch to re-schedule sync */
						stktable_touch_local(t, ts, 0);

						stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_CONTENT);
						if (sess->fe != s->be)
							stkctr_set_flags(&s->stkctr[trk_idx(rule->action)], STKCTR_TRACK_BACKEND);
					}
				}
				break;

			case ACT_CUSTOM:
				if ((s->req.flags & CF_READ_ERROR) ||
				    ((s->req.flags & (CF_SHUTR|CF_READ_NULL)) &&
				     (px->options & PR_O_ABRT_CLOSE)))
					act_flags |= ACT_FLAG_FINAL;

				switch (rule->action_ptr(rule, px, s->sess, s, act_flags)) {
					case ACT_RET_ERR:
					case ACT_RET_CONT:
						break;
					case ACT_RET_STOP:
						rule_ret = HTTP_RULE_RES_STOP;
						goto end;
					case ACT_RET_DONE:
						rule_ret = HTTP_RULE_RES_DONE;
						goto end;
					case ACT_RET_YIELD:
						s->current_rule = rule;
						rule_ret = HTTP_RULE_RES_YIELD;
						goto end;
				}
				break;

				/* other flags exists, but normally, they never be matched. */
			default:
				break;
		}
	}

  end:
	/* we reached the end of the rules, nothing to report */
	return rule_ret;
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
		 * after a backslash, including control chars and delimitors, which
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

			/* here, <equal> points to '=', a delimitor or the end. <att_end>
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

				/* make val_end point to the first white space or delimitor after the value */
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

				/* if we're in cookie prefix mode, we'll search the delimitor so that we
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

			/* continue with next cookie on this header line */
			att_beg = next;
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

			/* here, <equal> points to '=', a delimitor or the end. <att_end>
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

				/* make val_end point to the first white space or delimitor after the value */
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
        int32_t pos;
	int pragma_found, cc_found, i;

	if ((txn->flags & (TX_CACHEABLE|TX_CACHE_IGNORE)) == TX_CACHE_IGNORE)
		return; /* nothing more to do here */

	htx = htxbuf(&req->buf);
	pragma_found = cc_found = 0;
	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
                struct htx_blk *blk = htx_get_blk(htx, pos);
                enum htx_blk_type type = htx_get_blk_type(blk);
		struct ist n, v;

                if (type == HTX_BLK_EOH)
                        break;
                if (type != HTX_BLK_HDR)
                        continue;

		n = htx_get_blk_name(htx, blk);
		v = htx_get_blk_value(htx, blk);

		if (isteq(n, ist("pragma"))) {
			if (v.len >= 8 && strncasecmp(v.ptr, "no-cache", 8) == 0) {
				pragma_found = 1;
				continue;
			}
		}

		/* Don't use the cache and don't try to store if we found the
		 * Authorization header */
		if (isteq(n, ist("authorization"))) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			txn->flags |= TX_CACHE_IGNORE;
			continue;
		}

		if (!isteq(n, ist("cache-control")))
			continue;

		/* OK, right now we know we have a cache-control header */
		cc_found = 1;
		if (!v.len)	/* no info */
			continue;

		i = 0;
		while (i < v.len && *(v.ptr+i) != '=' && *(v.ptr+i) != ',' &&
		       !isspace((unsigned char)*(v.ptr+i)))
			i++;

		/* we have a complete value between v.ptr and (v.ptr+i). We don't check the
		 * values after max-age, max-stale nor min-fresh, we simply don't
		 * use the cache when they're specified.
		 */
		if (((i == 7) && strncasecmp(v.ptr, "max-age",   7) == 0) ||
		    ((i == 8) && strncasecmp(v.ptr, "no-cache",  8) == 0) ||
		    ((i == 9) && strncasecmp(v.ptr, "max-stale", 9) == 0) ||
		    ((i == 9) && strncasecmp(v.ptr, "min-fresh", 9) == 0)) {
			txn->flags |= TX_CACHE_IGNORE;
			continue;
		}

		if ((i == 8) && strncasecmp(v.ptr, "no-store", 8) == 0) {
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
	struct htx *htx;
        int32_t pos;
	int i;

	if (txn->status < 200) {
		/* do not try to cache interim responses! */
		txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
		return;
	}

	htx = htxbuf(&res->buf);
	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
                struct htx_blk *blk  = htx_get_blk(htx, pos);
                enum htx_blk_type type = htx_get_blk_type(blk);
		struct ist n, v;

                if (type == HTX_BLK_EOH)
                        break;
                if (type != HTX_BLK_HDR)
                        continue;

		n = htx_get_blk_name(htx, blk);
		v = htx_get_blk_value(htx, blk);

		if (isteq(n, ist("pragma"))) {
			if ((v.len >= 8) && strncasecmp(v.ptr, "no-cache", 8) == 0) {
				txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
				return;
			}
		}

		if (!isteq(n, ist("cache-control")))
			continue;

		/* OK, right now we know we have a cache-control header */
		if (!v.len)	/* no info */
			continue;

		i = 0;
		while (i < v.len && *(v.ptr+i) != '=' && *(v.ptr+i) != ',' &&
		       !isspace((unsigned char)*(v.ptr+i)))
			i++;

		/* we have a complete value between v.ptr and (v.ptr+i) */
		if (i < v.len && *(v.ptr + i) == '=') {
			if (((v.len - i) > 1 && (i == 7) && strncasecmp(v.ptr, "max-age=0", 9) == 0) ||
			    ((v.len - i) > 1 && (i == 8) && strncasecmp(v.ptr, "s-maxage=0", 10) == 0)) {
				txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
				continue;
			}

			/* we have something of the form no-cache="set-cookie" */
			if ((v.len >= 21) &&
			    strncasecmp(v.ptr, "no-cache=\"set-cookie", 20) == 0
			    && (*(v.ptr + 20) == '"' || *(v.ptr + 20 ) == ','))
				txn->flags &= ~TX_CACHE_COOK;
			continue;
		}

		/* OK, so we know that either p2 points to the end of string or to a comma */
		if (((i ==  7) && strncasecmp(v.ptr, "private", 7) == 0) ||
		    ((i ==  8) && strncasecmp(v.ptr, "no-cache", 8) == 0) ||
		    ((i ==  8) && strncasecmp(v.ptr, "no-store", 8) == 0)) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			return;
		}

		if ((i ==  6) && strncasecmp(v.ptr, "public", 6) == 0) {
			txn->flags |= TX_CACHEABLE | TX_CACHE_COOK;
			continue;
		}
	}
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
	if (*uri_auth->uri_prefix == '/')
		uri = http_get_path(uri);

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

void http_perform_server_redirect(struct stream *s, struct stream_interface *si)
{
	struct channel *req = &s->req;
	struct channel *res = &s->res;
	struct server *srv;
	struct htx *htx;
	struct htx_sl *sl;
	struct ist path, location;
	unsigned int flags;
	size_t data;

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
	path = http_get_path(htx_sl_req_uri(sl));
	if (!path.ptr)
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

	if (!htx_add_endof(htx, HTX_BLK_EOH) || !htx_add_endof(htx, HTX_BLK_EOM))
		goto fail;

	/*
	 * Send the message
	 */
	data = htx->data - co_data(res);
	c_adv(res, data);
	res->total += data;

	/* return without error. */
	si_shutr(si);
	si_shutw(si);
	si->err_type = SI_ET_NONE;
	si->state    = SI_ST_CLO;

	channel_auto_read(req);
	channel_abort(req);
	channel_auto_close(req);
	channel_htx_erase(req, htxbuf(&req->buf));
	channel_auto_read(res);
	channel_auto_close(res);

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

/* This function terminates the request because it was completly analyzed or
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
	if (txn->req.msg_state == HTTP_MSG_TUNNEL && HAS_REQ_DATA_FILTERS(s))
			chn->analysers |= AN_REQ_FLT_XFER_DATA;
	channel_auto_close(chn);
	channel_auto_read(chn);
	DBG_TRACE_LEAVE(STRM_EV_HTTP_ANA, s, txn);
}


/* This function terminates the response because it was completly analyzed or
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
			chn->flags |= CF_NEVER_WAIT;
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
			_HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
			if (objt_server(s->target))
				_HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);
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
	if (txn->rsp.msg_state == HTTP_MSG_TUNNEL && HAS_RSP_DATA_FILTERS(s))
		chn->analysers |= AN_RES_FLT_XFER_DATA;
	channel_auto_close(chn);
	channel_auto_read(chn);
	DBG_TRACE_LEAVE(STRM_EV_HTTP_ANA, s, txn);
}

void http_server_error(struct stream *s, struct stream_interface *si, int err,
		       int finst, const struct buffer *msg)
{
	channel_auto_read(si_oc(si));
	channel_abort(si_oc(si));
	channel_auto_close(si_oc(si));
	channel_htx_erase(si_oc(si), htxbuf(&(si_oc(si))->buf));
	channel_auto_close(si_ic(si));
	channel_auto_read(si_ic(si));

	/* <msg> is an HTX structure. So we copy it in the response's
	 * channel */
	if (msg && !b_is_null(msg)) {
		struct channel *chn = si_ic(si);
		struct htx *htx;

		FLT_STRM_CB(s, flt_http_reply(s, s->txn->status, msg));
		chn->buf.data = msg->data;
		memcpy(chn->buf.area, msg->area, msg->data);
		htx = htx_from_buf(&chn->buf);
		htx->flags |= HTX_FL_PROXY_RESP;
		c_adv(chn, htx->data);
		chn->total += htx->data;
	}
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= finst;
}

void http_reply_and_close(struct stream *s, short status, struct buffer *msg)
{
	channel_auto_read(&s->req);
	channel_abort(&s->req);
	channel_auto_close(&s->req);
	channel_htx_erase(&s->req, htxbuf(&s->req.buf));
	channel_htx_truncate(&s->res, htxbuf(&s->res.buf));

	s->txn->flags &= ~TX_WAIT_NEXT_RQ;

	/* <msg> is an HTX structure. So we copy it in the response's
	 * channel */
	/* FIXME: It is a problem for now if there is some outgoing data */
	if (msg && !b_is_null(msg)) {
		struct channel *chn = &s->res;
		struct htx *htx;

		FLT_STRM_CB(s, flt_http_reply(s, s->txn->status, msg));
		chn->buf.data = msg->data;
		memcpy(chn->buf.area, msg->area, msg->data);
		htx = htx_from_buf(&chn->buf);
		htx->flags |= HTX_FL_PROXY_RESP;
		c_adv(chn, htx->data);
		chn->total += htx->data;
	}

	s->res.wex = tick_add_ifset(now_ms, s->res.wto);
	channel_auto_read(&s->res);
	channel_auto_close(&s->res);
	channel_shutr_now(&s->res);
}

struct buffer *http_error_message(struct stream *s)
{
	const int msgnum = http_get_status_idx(s->txn->status);

	if (s->be->errmsg[msgnum].area)
		return &s->be->errmsg[msgnum];
	else if (strm_fe(s)->errmsg[msgnum].area)
		return &strm_fe(s)->errmsg[msgnum];
	else
		return &http_err_chunks[msgnum];
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
	s->txn->status = 503;

	if (err_type & SI_ET_QUEUE_ABRT)
		http_server_error(s, si, SF_ERR_CLICL, SF_FINST_Q,
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_ABRT)
		http_server_error(s, si, SF_ERR_CLICL, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
	else if (err_type & SI_ET_QUEUE_TO)
		http_server_error(s, si, SF_ERR_SRVTO, SF_FINST_Q,
				  http_error_message(s));
	else if (err_type & SI_ET_QUEUE_ERR)
		http_server_error(s, si, SF_ERR_SRVCL, SF_FINST_Q,
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_TO)
		http_server_error(s, si, SF_ERR_SRVTO, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_ERR)
		http_server_error(s, si, SF_ERR_SRVCL, SF_FINST_C,
				  (s->flags & SF_SRV_REUSED) ? NULL :
				  http_error_message(s));
	else if (err_type & SI_ET_CONN_RES)
		http_server_error(s, si, SF_ERR_RESOURCE, SF_FINST_C,
				  (s->txn->flags & TX_NOT_FIRST) ? NULL :
				  http_error_message(s));
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
	size_t data;

	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
			    ist("HTTP/1.1"), ist("100"), ist("Continue"));
	if (!sl)
		goto fail;
	sl->info.res.status = 100;

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto fail;

	data = htx->data - co_data(res);
	c_adv(res, data);
	res->total += data;
	return 0;

  fail:
	/* If an error occurred, remove the incomplete HTTP response from the
	 * buffer */
	channel_htx_truncate(res, htx);
	return -1;
}


/* Send a 401-Unauthorized or 407-Unauthorized response to the client, depending
 * ont whether we use a proxy or not. It returns 0 on success and -1 on
 * error. The response channel is updated accordingly.
 */
static int http_reply_40x_unauthorized(struct stream *s, const char *auth_realm)
{
	struct channel *res = &s->res;
	struct htx *htx = htx_from_buf(&res->buf);
	struct htx_sl *sl;
	struct ist code, body;
	int status;
	unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11);
	size_t data;

	if (!(s->txn->flags & TX_USE_PX_CONN)) {
		status = 401;
		code = ist("401");
		body = ist("<html><body><h1>401 Unauthorized</h1>\n"
			   "You need a valid user and password to access this content.\n"
			   "</body></html>\n");
	}
	else {
		status = 407;
		code = ist("407");
		body = ist("<html><body><h1>407 Unauthorized</h1>\n"
			   "You need a valid user and password to access this content.\n"
			   "</body></html>\n");
	}

	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
			    ist("HTTP/1.1"), code, ist("Unauthorized"));
	if (!sl)
		goto fail;
	sl->info.res.status = status;
	s->txn->status = status;

	if (chunk_printf(&trash, "Basic realm=\"%s\"", auth_realm) == -1)
		goto fail;

        if (!htx_add_header(htx, ist("Content-length"), ist("112")) ||
	    !htx_add_header(htx, ist("Cache-Control"), ist("no-cache")) ||
	    !htx_add_header(htx, ist("Connection"), ist("close")) ||
	    !htx_add_header(htx, ist("Content-Type"), ist("text/html")))
		goto fail;
	if (status == 401 && !htx_add_header(htx, ist("WWW-Authenticate"), ist2(trash.area, trash.data)))
		goto fail;
	if (status == 407 && !htx_add_header(htx, ist("Proxy-Authenticate"), ist2(trash.area, trash.data)))
		goto fail;
	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto fail;

	while (body.len) {
		size_t sent = htx_add_data(htx, body);
		if (!sent)
			goto fail;
		body.ptr += sent;
		body.len -= sent;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOM))
		goto fail;

	htx->flags |= HTX_FL_PROXY_RESP;
	data = htx->data - co_data(res);
	c_adv(res, data);
	res->total += data;

	channel_auto_read(&s->req);
	channel_abort(&s->req);
	channel_auto_close(&s->req);
	channel_htx_erase(&s->req, htxbuf(&s->req.buf));

	res->wex = tick_add_ifset(now_ms, res->wto);
	channel_auto_read(res);
	channel_auto_close(res);
	channel_shutr_now(res);
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
				if (v.len > h->len)
					v.len = h->len;

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
                     objt_conn(sess->origin) ? (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                     objt_cs(s->si[1].end) ? (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

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

        shut_your_big_mouth_gcc(write(1, trash.area, trash.data));
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
                     objt_conn(sess->origin) ? (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                     objt_cs(s->si[1].end) ? (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

        max = n.len;
        UBOUND(max, trash.size - trash.data - 3);
        chunk_memcat(&trash, n.ptr, max);
        trash.area[trash.data++] = ':';
        trash.area[trash.data++] = ' ';

        max = v.len;
        UBOUND(max, trash.size - trash.data - 1);
        chunk_memcat(&trash, v.ptr, max);
        trash.area[trash.data++] = '\n';

        shut_your_big_mouth_gcc(write(1, trash.area, trash.data));
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
 * Initialize a new HTTP transaction for stream <s>. It is assumed that all
 * the required fields are properly allocated and that we only need to (re)init
 * them. This should be used before processing any new request.
 */
void http_init_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;
	struct conn_stream *cs = objt_cs(s->si[0].end);

	txn->flags = ((cs && cs->flags & CS_FL_NOT_FIRST)
		      ? (TX_NOT_FIRST|TX_WAIT_NEXT_RQ)
		      : 0);
	txn->status = -1;
	*(unsigned int *)txn->cache_hash = 0;

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

	vars_init(&s->vars_txn,    SCOPE_TXN);
	vars_init(&s->vars_reqres, SCOPE_REQ);
}

/* to be used at the end of a transaction */
void http_end_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;

	/* these ones will have been dynamically allocated */
	pool_free(pool_head_requri, txn->uri);
	pool_free(pool_head_capture, txn->cli_cookie);
	pool_free(pool_head_capture, txn->srv_cookie);
	pool_free(pool_head_uniqueid, s->unique_id);

	s->unique_id = NULL;
	txn->uri = NULL;
	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;

	if (!LIST_ISEMPTY(&s->vars_txn.head))
		vars_prune(&s->vars_txn, s->sess, s);
	if (!LIST_ISEMPTY(&s->vars_reqres.head))
		vars_prune(&s->vars_reqres, s->sess, s);
}


DECLARE_POOL(pool_head_http_txn, "http_txn", sizeof(struct http_txn));
DECLARE_POOL(pool_head_uniqueid, "uniqueid", UNIQUEID_LEN);

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
