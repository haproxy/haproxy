/*
 * HTTP protocol analyzer
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/base64.h>
#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/h1.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/cli.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/cache.h>
#include <types/stats.h>

#include <proto/acl.h>
#include <proto/action.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/cli.h>
#include <proto/compression.h>
#include <proto/stats.h>
#include <proto/fd.h>
#include <proto/filters.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/pattern.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/pattern.h>
#include <proto/vars.h>

/* status codes available for the stats admin page (strictly 4 chars length) */
const char *stat_status_codes[STAT_STATUS_SIZE] = {
	[STAT_STATUS_DENY] = "DENY",
	[STAT_STATUS_DONE] = "DONE",
	[STAT_STATUS_ERRP] = "ERRP",
	[STAT_STATUS_EXCD] = "EXCD",
	[STAT_STATUS_NONE] = "NONE",
	[STAT_STATUS_PART] = "PART",
	[STAT_STATUS_UNKN] = "UNKN",
};

/* This function handles a server error at the stream interface level. The
 * stream interface is assumed to be already in a closed state. An optional
 * message is copied into the input buffer.
 * The error flags are set to the values in arguments. Any pending request
 * in this buffer will be lost.
 */
static void http_server_error(struct stream *s, struct stream_interface *si,
			      int err, int finst, const struct buffer *msg)
{
	if (IS_HTX_STRM(s))
		return htx_server_error(s, si, err, finst, msg);

	FLT_STRM_CB(s, flt_http_reply(s, s->txn->status, msg));
	channel_auto_read(si_oc(si));
	channel_abort(si_oc(si));
	channel_auto_close(si_oc(si));
	channel_erase(si_oc(si));
	channel_auto_close(si_ic(si));
	channel_auto_read(si_ic(si));
	if (msg)
		co_inject(si_ic(si), msg->area, msg->data);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= finst;
}

/* This function returns the appropriate error location for the given stream
 * and message.
 */

struct buffer *http_error_message(struct stream *s)
{
	const int msgnum = http_get_status_idx(s->txn->status);

	if (IS_HTX_STRM(s))
               return htx_error_message(s);

	if (s->be->errmsg[msgnum].area)
		return &s->be->errmsg[msgnum];
	else if (strm_fe(s)->errmsg[msgnum].area)
		return &strm_fe(s)->errmsg[msgnum];
	else
		return &http_err_chunks[msgnum];
}

void
http_reply_and_close(struct stream *s, short status, struct buffer *msg)
{
	if (IS_HTX_STRM(s))
		return htx_reply_and_close(s, status, msg);

	s->txn->flags &= ~TX_WAIT_NEXT_RQ;
	FLT_STRM_CB(s, flt_http_reply(s, status, msg));
	si_retnclose(&s->si[0], msg);
}

/* Parse the URI from the given transaction (which is assumed to be in request
 * phase) and look for the "/" beginning the PATH. If not found, return NULL.
 * It is returned otherwise.
 */
char *http_txn_get_path(const struct http_txn *txn)
{
	struct ist ret;

	if (!txn->req.chn->buf.size)
		return NULL;

	ret = http_get_path(ist2(ci_head(txn->req.chn) + txn->req.sl.rq.u, txn->req.sl.rq.u_l));

	return ret.ptr;
}

/* Returns a 302 for a redirectable request that reaches a server working in
 * in redirect mode. This may only be called just after the stream interface
 * has moved to SI_ST_ASS. Unprocessable requests are left unchanged and will
 * follow normal proxy processing. NOTE: this function is designed to support
 * being called once data are scheduled for forwarding.
 */
void http_perform_server_redirect(struct stream *s, struct stream_interface *si)
{
	struct http_txn *txn;
	struct server *srv;
	char *path;
	int len, rewind;

	if (IS_HTX_STRM(s))
		return htx_perform_server_redirect(s, si);

	/* 1: create the response header */
	trash.data = strlen(HTTP_302);
	memcpy(trash.area, HTTP_302, trash.data);

	srv = __objt_server(s->target);

	/* 2: add the server's prefix */
	if (trash.data + srv->rdr_len > trash.size)
		return;

	/* special prefix "/" means don't change URL */
	if (srv->rdr_len != 1 || *srv->rdr_pfx != '/') {
		memcpy(trash.area + trash.data, srv->rdr_pfx, srv->rdr_len);
		trash.data += srv->rdr_len;
	}

	/* 3: add the request URI. Since it was already forwarded, we need
	 * to temporarily rewind the buffer.
	 */
	txn = s->txn;
	c_rew(&s->req, rewind = http_hdr_rewind(&txn->req));

	path = http_txn_get_path(txn);
	len = b_dist(&s->req.buf, path, c_ptr(&s->req, txn->req.sl.rq.u + txn->req.sl.rq.u_l));

	c_adv(&s->req, rewind);

	if (!path)
		return;

	if (trash.data + len > trash.size - 4) /* 4 for CRLF-CRLF */
		return;

	memcpy(trash.area + trash.data, path, len);
	trash.data += len;

	if (unlikely(txn->flags & TX_USE_PX_CONN)) {
		memcpy(trash.area + trash.data,
		       "\r\nProxy-Connection: close\r\n\r\n", 29);
		trash.data += 29;
	} else {
		memcpy(trash.area + trash.data,
		       "\r\nConnection: close\r\n\r\n", 23);
		trash.data += 23;
	}

	/* prepare to return without error. */
	si_shutr(si);
	si_shutw(si);
	si->err_type = SI_ET_NONE;
	si->state    = SI_ST_CLO;

	/* send the message */
	txn->status = 302;
	http_server_error(s, si, SF_ERR_LOCAL, SF_FINST_C, &trash);

	/* FIXME: we should increase a counter of redirects per server and per backend. */
	srv_inc_sess_ctr(srv);
	srv_set_sess_last(srv);
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

extern const char sess_term_cond[8];
extern const char sess_fin_state[8];
extern const char *monthname[12];

DECLARE_POOL(pool_head_http_txn, "http_txn", sizeof(struct http_txn));
DECLARE_POOL(pool_head_uniqueid, "uniqueid", UNIQUEID_LEN);

struct pool_head *pool_head_requri = NULL;
struct pool_head *pool_head_capture = NULL;

/*
 * Capture headers from message starting at <som> according to header list
 * <cap_hdr>, and fill the <cap> pointers appropriately.
 */
void http_capture_headers(char *som, struct hdr_idx *idx,
			  char **cap, struct cap_hdr *cap_hdr)
{
	char *eol, *sol, *col, *sov;
	int cur_idx;
	struct cap_hdr *h;
	int len;

	sol = som + hdr_idx_first_pos(idx);
	cur_idx = hdr_idx_first_idx(idx);

	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		col = sol;
		while (col < eol && *col != ':')
			col++;

		sov = col + 1;
		while (sov < eol && HTTP_IS_LWS(*sov))
			sov++;
				
		for (h = cap_hdr; h; h = h->next) {
			if (h->namelen && (h->namelen == col - sol) &&
			    (strncasecmp(sol, h->name, h->namelen) == 0)) {
				if (cap[h->index] == NULL)
					cap[h->index] =
						pool_alloc(h->pool);

				if (cap[h->index] == NULL) {
					ha_alert("HTTP capture : out of memory.\n");
					continue;
				}
							
				len = eol - sov;
				if (len > h->len)
					len = h->len;
							
				memcpy(cap[h->index], sov, len);
				cap[h->index][len]=0;
			}
		}
		sol = eol + idx->v[cur_idx].cr + 1;
		cur_idx = idx->v[cur_idx].next;
	}
}

/* convert an HTTP/0.9 request into an HTTP/1.0 request. Returns 1 if the
 * conversion succeeded, 0 in case of error. If the request was already 1.X,
 * nothing is done and 1 is returned.
 */
int http_upgrade_v09_to_v10(struct http_txn *txn)
{
	int delta;
	char *cur_end;
	struct http_msg *msg = &txn->req;

	if (msg->sl.rq.v_l != 0)
		return 1;

	/* RFC 1945 allows only GET for HTTP/0.9 requests */
	if (txn->meth != HTTP_METH_GET)
		return 0;

	cur_end = ci_head(msg->chn) + msg->sl.rq.l;

	if (msg->sl.rq.u_l == 0) {
		/* HTTP/0.9 requests *must* have a request URI, per RFC 1945 */
		return 0;
	}
	/* add HTTP version */
	delta = b_rep_blk(&msg->chn->buf, cur_end, cur_end, " HTTP/1.0\r\n", 11);
	http_msg_move_end(msg, delta);
	cur_end += delta;
	cur_end = (char *)http_parse_reqline(msg,
					     HTTP_MSG_RQMETH,
					     ci_head(msg->chn), cur_end + 1,
					     NULL, NULL);
	if (unlikely(!cur_end))
		return 0;

	/* we have a full HTTP/1.0 request now and we know that
	 * we have either a CR or an LF at <ptr>.
	 */
	hdr_idx_set_start(&txn->hdr_idx, msg->sl.rq.l, *cur_end == '\r');
	return 1;
}

/* Parse the Connection: header of an HTTP request, looking for both "close"
 * and "keep-alive" values. If we already know that some headers may safely
 * be removed, we remove them now. The <to_del> flags are used for that :
 *  - bit 0 means remove "close" headers (in HTTP/1.0 requests/responses)
 *  - bit 1 means remove "keep-alive" headers (in HTTP/1.1 reqs/resp to 1.1).
 * Presence of the "Upgrade" token is also checked and reported.
 * The TX_HDR_CONN_* flags are adjusted in txn->flags depending on what was
 * found, and TX_CON_*_SET is adjusted depending on what is left so only
 * harmless combinations may be removed. Do not call that after changes have
 * been processed.
 */
void http_parse_connection_header(struct http_txn *txn, struct http_msg *msg, int to_del)
{
	struct hdr_ctx ctx;
	const char *hdr_val = "Connection";
	int hdr_len = 10;

	if (txn->flags & TX_HDR_CONN_PRS)
		return;

	if (unlikely(txn->flags & TX_USE_PX_CONN)) {
		hdr_val = "Proxy-Connection";
		hdr_len = 16;
	}

	ctx.idx = 0;
	txn->flags &= ~(TX_CON_KAL_SET|TX_CON_CLO_SET);
	while (http_find_header2(hdr_val, hdr_len, ci_head(msg->chn), &txn->hdr_idx, &ctx)) {
		if (ctx.vlen >= 10 && word_match(ctx.line + ctx.val, ctx.vlen, "keep-alive", 10)) {
			txn->flags |= TX_HDR_CONN_KAL;
			if (to_del & 2)
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
			else
				txn->flags |= TX_CON_KAL_SET;
		}
		else if (ctx.vlen >= 5 && word_match(ctx.line + ctx.val, ctx.vlen, "close", 5)) {
			txn->flags |= TX_HDR_CONN_CLO;
			if (to_del & 1)
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
			else
				txn->flags |= TX_CON_CLO_SET;
		}
		else if (ctx.vlen >= 7 && word_match(ctx.line + ctx.val, ctx.vlen, "upgrade", 7)) {
			txn->flags |= TX_HDR_CONN_UPG;
		}
	}

	txn->flags |= TX_HDR_CONN_PRS;
	return;
}

/* Apply desired changes on the Connection: header. Values may be removed and/or
 * added depending on the <wanted> flags, which are exclusively composed of
 * TX_CON_CLO_SET and TX_CON_KAL_SET, depending on what flags are desired. The
 * TX_CON_*_SET flags are adjusted in txn->flags depending on what is left.
 */
void http_change_connection_header(struct http_txn *txn, struct http_msg *msg, int wanted)
{
	struct hdr_ctx ctx;
	const char *hdr_val = "Connection";
	int hdr_len = 10;

	ctx.idx = 0;


	if (unlikely(txn->flags & TX_USE_PX_CONN)) {
		hdr_val = "Proxy-Connection";
		hdr_len = 16;
	}

	txn->flags &= ~(TX_CON_CLO_SET | TX_CON_KAL_SET);
	while (http_find_header2(hdr_val, hdr_len, ci_head(msg->chn), &txn->hdr_idx, &ctx)) {
		if (ctx.vlen >= 10 && word_match(ctx.line + ctx.val, ctx.vlen, "keep-alive", 10)) {
			if (wanted & TX_CON_KAL_SET)
				txn->flags |= TX_CON_KAL_SET;
			else
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
		}
		else if (ctx.vlen >= 5 && word_match(ctx.line + ctx.val, ctx.vlen, "close", 5)) {
			if (wanted & TX_CON_CLO_SET)
				txn->flags |= TX_CON_CLO_SET;
			else
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
		}
	}

	if (wanted == (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
		return;

	if ((wanted & TX_CON_CLO_SET) && !(txn->flags & TX_CON_CLO_SET)) {
		txn->flags |= TX_CON_CLO_SET;
		hdr_val = "Connection: close";
		hdr_len  = 17;
		if (unlikely(txn->flags & TX_USE_PX_CONN)) {
			hdr_val = "Proxy-Connection: close";
			hdr_len = 23;
		}
		http_header_add_tail2(msg, &txn->hdr_idx, hdr_val, hdr_len);
	}

	if ((wanted & TX_CON_KAL_SET) && !(txn->flags & TX_CON_KAL_SET)) {
		txn->flags |= TX_CON_KAL_SET;
		hdr_val = "Connection: keep-alive";
		hdr_len = 22;
		if (unlikely(txn->flags & TX_USE_PX_CONN)) {
			hdr_val = "Proxy-Connection: keep-alive";
			hdr_len = 28;
		}
		http_header_add_tail2(msg, &txn->hdr_idx, hdr_val, hdr_len);
	}
	return;
}

void http_adjust_conn_mode(struct stream *s, struct http_txn *txn, struct http_msg *msg)
{
	struct proxy *fe = strm_fe(s);
	int tmp = TX_CON_WANT_KAL;

	if (IS_HTX_STRM(s))
		return htx_adjust_conn_mode(s, txn);

	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN ||
	    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
		tmp = TX_CON_WANT_TUN;

	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL)
			tmp = TX_CON_WANT_SCL;

	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO ||
	    (s->be->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO)
		tmp = TX_CON_WANT_CLO;

	if ((txn->flags & TX_CON_WANT_MSK) < tmp)
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | tmp;

	if (!(txn->flags & TX_HDR_CONN_PRS) &&
	    (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		/* parse the Connection header and possibly clean it */
		int to_del = 0;
		if ((msg->flags & HTTP_MSGF_VER_11) ||
		    ((txn->flags & TX_CON_WANT_MSK) >= TX_CON_WANT_SCL &&
		     !((fe->options2|s->be->options2) & PR_O2_FAKE_KA)))
			to_del |= 2; /* remove "keep-alive" */
		if (!(msg->flags & HTTP_MSGF_VER_11))
			to_del |= 1; /* remove "close" */
		http_parse_connection_header(txn, msg, to_del);
	}

	/* check if client or config asks for explicit close in KAL/SCL */
	if (((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	     (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) &&
	    ((txn->flags & TX_HDR_CONN_CLO) ||                         /* "connection: close" */
	     (!(msg->flags & HTTP_MSGF_VER_11) && !(txn->flags & TX_HDR_CONN_KAL)) || /* no "connection: k-a" in 1.0 */
	     !(msg->flags & HTTP_MSGF_XFER_LEN) ||                     /* no length known => close */
	     fe->state == PR_STSTOPPED))                            /* frontend is stopping */
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_CLO;
}

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
	 * We will parse the partial (or complete) lines.
	 * We will check the request syntax, and also join multi-line
	 * headers. An index of all the lines will be elaborated while
	 * parsing.
	 *
	 * For the parsing, we use a 28 states FSM.
	 *
	 * Here is the information we currently have :
	 *   ci_head(req)             = beginning of request
	 *   ci_head(req) + msg->eoh  = end of processed headers / start of current one
	 *   ci_tail(req)             = end of input data
	 *   msg->eol                 = end of current header or line (LF or CRLF)
	 *   msg->next                = first non-visited byte
	 *
	 * At end of parsing, we may perform a capture of the error (if any), and
	 * we will set a few fields (txn->meth, sn->flags/SF_REDIRECTABLE).
	 * We also check for monitor-uri, logging, HTTP/0.9 to 1.0 conversion, and
	 * finally headers capture.
	 */

	int cur_idx;
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct hdr_ctx ctx;

	if (IS_HTX_STRM(s))
		return htx_wait_for_request(s, req, an_bit);

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	/* we're speaking HTTP here, so let's speak HTTP to the client */
	s->srv_error = http_return_srv_error;

	/* If there is data available for analysis, log the end of the idle time. */
	if (c_data(req) && s->logs.t_idle == -1)
		s->logs.t_idle = tv_ms_elapsed(&s->logs.tv_accept, &now) - s->logs.t_handshake;

	/* There's a protected area at the end of the buffer for rewriting
	 * purposes. We don't want to start to parse the request if the
	 * protected area is affected, because we may have to move processed
	 * data later, which is much more complicated.
	 */
	if (c_data(req) && msg->msg_state < HTTP_MSG_ERROR) {
		if (txn->flags & TX_NOT_FIRST) {
			if (unlikely(!channel_is_rewritable(req))) {
				if (req->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_WRITE_ERROR|CF_WRITE_TIMEOUT))
					goto failed_keep_alive;
				/* some data has still not left the buffer, wake us once that's done */
				channel_dont_connect(req);
				req->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
				req->flags |= CF_WAKE_WRITE;
				return 0;
			}
			if (unlikely(ci_tail(req) < c_ptr(req, msg->next) ||
			             ci_tail(req) > b_wrap(&req->buf) - global.tune.maxrewrite))
				channel_slow_realign(req, trash.area);
		}

		if (likely(msg->next < ci_data(req))) /* some unparsed data are available */
			http_msg_analyzer(msg, &txn->hdr_idx);
	}

	/* 1: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
		     msg->msg_state >= HTTP_MSG_BODY)) {
		char *eol, *sol;

		sol = ci_head(req);
		/* this is a bit complex : in case of error on the request line,
		 * we know that rq.l is still zero, so we display only the part
		 * up to the end of the line (truncated by debug_hdr).
		 */
		eol = sol + (msg->sl.rq.l ? msg->sl.rq.l : ci_data(req));
		debug_hdr("clireq", s, sol, eol);

		sol += hdr_idx_first_pos(&txn->hdr_idx);
		cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

		while (cur_idx) {
			eol = sol + txn->hdr_idx.v[cur_idx].len;
			debug_hdr("clihdr", s, sol, eol);
			sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
			cur_idx = txn->hdr_idx.v[cur_idx].next;
		}
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

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/*
		 * First, let's catch bad requests.
		 */
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			stream_inc_http_req_ctr(s);
			stream_inc_http_err_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			goto return_bad_req;
		}

		/* 1: Since we are in header mode, if there's no space
		 *    left for headers, we won't be able to free more
		 *    later, so the stream will never terminate. We
		 *    must terminate it now.
		 */
		if (unlikely(channel_full(req, global.tune.maxrewrite))) {
			/* FIXME: check if URI is set and return Status
			 * 414 Request URI too long instead.
			 */
			stream_inc_http_req_ctr(s);
			stream_inc_http_err_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			if (msg->err_pos < 0)
				msg->err_pos = ci_data(req);
			goto return_bad_req;
		}

		/* 2: have we encountered a read error ? */
		else if (req->flags & CF_READ_ERROR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			/* we cannot return any message on error */
			if (msg->err_pos >= 0) {
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
				stream_inc_http_err_ctr(s);
			}

			txn->status = 400;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, NULL);
			req->analysers &= AN_REQ_FLT_END;
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 3: has the read timeout expired ? */
		else if (req->flags & CF_READ_TIMEOUT || tick_is_expired(req->analyse_exp, now_ms)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLITO;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			/* read timeout : give up with an error message. */
			if (msg->err_pos >= 0) {
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
				stream_inc_http_err_ctr(s);
			}
			txn->status = 408;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;

			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 4: have we encountered a close ? */
		else if (req->flags & CF_SHUTR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			if (msg->err_pos >= 0)
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
			txn->status = 400;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;
			stream_inc_http_err_ctr(s);
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		channel_dont_connect(req);
		req->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */

		if (sess->listener->options & LI_O_NOQUICKACK && ci_data(req)) {
			/* We need more data, we have to re-enable quick-ack in case we
			 * previously disabled it, otherwise we might cause the client
			 * to delay next data.
			 */
			conn_set_quickack(objt_conn(sess->origin), 1);
		}

		if ((msg->msg_state != HTTP_MSG_RQBEFORE) && (txn->flags & TX_WAIT_NEXT_RQ)) {
			/* If the client starts to talk, let's fall back to
			 * request timeout processing.
			 */
			txn->flags &= ~TX_WAIT_NEXT_RQ;
			req->analyse_exp = TICK_ETERNITY;
		}

		/* just set the request timeout once at the beginning of the request */
		if (!tick_isset(req->analyse_exp)) {
			if ((msg->msg_state == HTTP_MSG_RQBEFORE) &&
			    (txn->flags & TX_WAIT_NEXT_RQ) &&
			    tick_isset(s->be->timeout.httpka))
				req->analyse_exp = tick_add(now_ms, s->be->timeout.httpka);
			else
				req->analyse_exp = tick_add_ifset(now_ms, s->be->timeout.httpreq);
		}

		/* we're not ready yet */
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
		return 0;
	}

	/* OK now we have a complete HTTP request with indexed headers. Let's
	 * complete the request parsing by setting a few fields we will need
	 * later. At this point, we have the last CRLF at req->buf.data + msg->eoh.
	 * If the request is in HTTP/0.9 form, the rule is still true, and eoh
	 * points to the CRLF of the request line. msg->next points to the first
	 * byte after the last LF. msg->sov points to the first byte of data.
	 * msg->eol cannot be trusted because it may have been left uninitialized
	 * (for instance in the absence of headers).
	 */

	stream_inc_http_req_ctr(s);
	proxy_inc_fe_req_ctr(sess->fe); /* one more valid request for this FE */

	if (txn->flags & TX_WAIT_NEXT_RQ) {
		/* kill the pending keep-alive timeout */
		txn->flags &= ~TX_WAIT_NEXT_RQ;
		req->analyse_exp = TICK_ETERNITY;
	}


	/* Maybe we found in invalid header name while we were configured not
	 * to block on that, so we have to capture it now.
	 */
	if (unlikely(msg->err_pos >= 0))
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);

	/*
	 * 1: identify the method
	 */
	txn->meth = find_http_meth(ci_head(req), msg->sl.rq.m_l);

	/* we can make use of server redirect on GET and HEAD */
	if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
		s->flags |= SF_REDIRECTABLE;
	else if (txn->meth == HTTP_METH_OTHER &&
		 msg->sl.rq.m_l == 3 && memcmp(ci_head(req), "PRI", 3) == 0) {
		/* PRI is reserved for the HTTP/2 preface */
		msg->err_pos = 0;
		goto return_bad_req;
	}

	/*
	 * 2: check if the URI matches the monitor_uri.
	 * We have to do this for every request which gets in, because
	 * the monitor-uri is defined by the frontend.
	 */
	if (unlikely((sess->fe->monitor_uri_len != 0) &&
		     (sess->fe->monitor_uri_len == msg->sl.rq.u_l) &&
		     !memcmp(ci_head(req) + msg->sl.rq.u,
			     sess->fe->monitor_uri,
			     sess->fe->monitor_uri_len))) {
		/*
		 * We have found the monitor URI
		 */
		struct acl_cond *cond;

		s->flags |= SF_MONITOR;
		HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

		/* Check if we want to fail this monitor request or not */
		list_for_each_entry(cond, &sess->fe->mon_fail_cond, list) {
			int ret = acl_exec_cond(cond, sess->fe, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);

			ret = acl_pass(ret);
			if (cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				/* we fail this request, let's return 503 service unavail */
				txn->status = 503;
				http_reply_and_close(s, txn->status, http_error_message(s));
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_LOCAL; /* we don't want a real error here */
				goto return_prx_cond;
			}
		}

		/* nothing to fail, let's reply normally */
		txn->status = 200;
		http_reply_and_close(s, txn->status, http_error_message(s));
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
			int urilen = msg->sl.rq.l;

			if (urilen >= global.tune.requri_len )
				urilen = global.tune.requri_len - 1;
			memcpy(txn->uri, ci_head(req), urilen);
			txn->uri[urilen] = 0;

			if (!(s->logs.logwait &= ~(LW_REQ|LW_INIT)))
				s->do_log(s);
		} else {
			ha_alert("HTTP logging : out of memory.\n");
		}
	}

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (!(sess->fe->options2 & PR_O2_REQBUG_OK)) {
		if (msg->sl.rq.v_l != 8) {
			msg->err_pos = msg->sl.rq.v;
			goto return_bad_req;
		}

		if (ci_head(req)[msg->sl.rq.v + 4] != '/' ||
		    !isdigit((unsigned char)ci_head(req)[msg->sl.rq.v + 5]) ||
		    ci_head(req)[msg->sl.rq.v + 6] != '.' ||
		    !isdigit((unsigned char)ci_head(req)[msg->sl.rq.v + 7])) {
			msg->err_pos = msg->sl.rq.v + 4;
			goto return_bad_req;
		}
	}
	else {
		/* 4. We may have to convert HTTP/0.9 requests to HTTP/1.0 */
		if (unlikely(msg->sl.rq.v_l == 0) && !http_upgrade_v09_to_v10(txn))
			goto return_bad_req;
	}

	/* ... and check if the request is HTTP/1.1 or above */
	if ((msg->sl.rq.v_l == 8) &&
	    ((ci_head(req)[msg->sl.rq.v + 5] > '1') ||
	     ((ci_head(req)[msg->sl.rq.v + 5] == '1') &&
	      (ci_head(req)[msg->sl.rq.v + 7] >= '1'))))
		msg->flags |= HTTP_MSGF_VER_11;

	/* "connection" has not been parsed yet */
	txn->flags &= ~(TX_HDR_CONN_PRS | TX_HDR_CONN_CLO | TX_HDR_CONN_KAL | TX_HDR_CONN_UPG);

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
	    ci_head(req)[msg->sl.rq.u] != '/' && ci_head(req)[msg->sl.rq.u] != '*')
		txn->flags |= TX_USE_PX_CONN;

	/* transfer length unknown*/
	msg->flags &= ~HTTP_MSGF_XFER_LEN;

	/* 5: we may need to capture headers */
	if (unlikely((s->logs.logwait & LW_REQHDR) && s->req_cap))
		http_capture_headers(ci_head(req), &txn->hdr_idx,
				     s->req_cap, sess->fe->req_cap);

	/* 6: determine the transfer-length according to RFC2616 #4.4, updated
	 * by RFC7230#3.3.3 :
	 *
	 * The length of a message body is determined by one of the following
	 *   (in order of precedence):
	 *
	 *   1.  Any response to a HEAD request and any response with a 1xx
	 *       (Informational), 204 (No Content), or 304 (Not Modified) status
	 *       code is always terminated by the first empty line after the
	 *       header fields, regardless of the header fields present in the
	 *       message, and thus cannot contain a message body.
	 *
	 *   2.  Any 2xx (Successful) response to a CONNECT request implies that
	 *       the connection will become a tunnel immediately after the empty
	 *       line that concludes the header fields.  A client MUST ignore any
	 *       Content-Length or Transfer-Encoding header fields received in
	 *       such a message.
	 *
	 *   3.  If a Transfer-Encoding header field is present and the chunked
	 *       transfer coding (Section 4.1) is the final encoding, the message
	 *       body length is determined by reading and decoding the chunked
	 *       data until the transfer coding indicates the data is complete.
	 *
	 *       If a Transfer-Encoding header field is present in a response and
	 *       the chunked transfer coding is not the final encoding, the
	 *       message body length is determined by reading the connection until
	 *       it is closed by the server.  If a Transfer-Encoding header field
	 *       is present in a request and the chunked transfer coding is not
	 *       the final encoding, the message body length cannot be determined
	 *       reliably; the server MUST respond with the 400 (Bad Request)
	 *       status code and then close the connection.
	 *
	 *       If a message is received with both a Transfer-Encoding and a
	 *       Content-Length header field, the Transfer-Encoding overrides the
	 *       Content-Length.  Such a message might indicate an attempt to
	 *       perform request smuggling (Section 9.5) or response splitting
	 *       (Section 9.4) and ought to be handled as an error.  A sender MUST
	 *       remove the received Content-Length field prior to forwarding such
	 *       a message downstream.
	 *
	 *   4.  If a message is received without Transfer-Encoding and with
	 *       either multiple Content-Length header fields having differing
	 *       field-values or a single Content-Length header field having an
	 *       invalid value, then the message framing is invalid and the
	 *       recipient MUST treat it as an unrecoverable error.  If this is a
	 *       request message, the server MUST respond with a 400 (Bad Request)
	 *       status code and then close the connection.  If this is a response
	 *       message received by a proxy, the proxy MUST close the connection
	 *       to the server, discard the received response, and send a 502 (Bad
	 *       Gateway) response to the client.  If this is a response message
	 *       received by a user agent, the user agent MUST close the
	 *       connection to the server and discard the received response.
	 *
	 *   5.  If a valid Content-Length header field is present without
	 *       Transfer-Encoding, its decimal value defines the expected message
	 *       body length in octets.  If the sender closes the connection or
	 *       the recipient times out before the indicated number of octets are
	 *       received, the recipient MUST consider the message to be
	 *       incomplete and close the connection.
	 *
	 *   6.  If this is a request message and none of the above are true, then
	 *       the message body length is zero (no message body is present).
	 *
	 *   7.  Otherwise, this is a response message without a declared message
	 *       body length, so the message body length is determined by the
	 *       number of octets received prior to the server closing the
	 *       connection.
	 */

	ctx.idx = 0;
	/* set TE_CHNK and XFER_LEN only if "chunked" is seen last */
	while (http_find_header2("Transfer-Encoding", 17, ci_head(req), &txn->hdr_idx, &ctx)) {
		if (ctx.vlen == 7 && strncasecmp(ctx.line + ctx.val, "chunked", 7) == 0)
			msg->flags |= HTTP_MSGF_TE_CHNK;
		else if (msg->flags & HTTP_MSGF_TE_CHNK) {
			/* chunked not last, return badreq */
			goto return_bad_req;
		}
	}

	/* Chunked requests must have their content-length removed */
	ctx.idx = 0;
	if (msg->flags & HTTP_MSGF_TE_CHNK) {
		while (http_find_header2("Content-Length", 14, ci_head(req), &txn->hdr_idx, &ctx))
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
	}
	else while (http_find_header2("Content-Length", 14, ci_head(req), &txn->hdr_idx, &ctx)) {
		signed long long cl;

		if (!ctx.vlen) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req;
		}

		if (strl2llrc(ctx.line + ctx.val, ctx.vlen, &cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req; /* parse failure */
		}

		if (cl < 0) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req;
		}

		if ((msg->flags & HTTP_MSGF_CNT_LEN) && (msg->chunk_len != cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req; /* already specified, was different */
		}

		msg->flags |= HTTP_MSGF_CNT_LEN;
		msg->body_len = msg->chunk_len = cl;
	}

	/* even bodyless requests have a known length */
	msg->flags |= HTTP_MSGF_XFER_LEN;

	/* Until set to anything else, the connection mode is set as Keep-Alive. It will
	 * only change if both the request and the config reference something else.
	 * Option httpclose by itself sets tunnel mode where headers are mangled.
	 * However, if another mode is set, it will affect it (eg: server-close/
	 * keep-alive + httpclose = close). Note that we avoid to redo the same work
	 * if FE and BE have the same settings (common). The method consists in
	 * checking if options changed between the two calls (implying that either
	 * one is non-null, or one of them is non-null and we are there for the first
	 * time.
	 */
	if (!(txn->flags & TX_HDR_CONN_PRS) ||
	    ((sess->fe->options & PR_O_HTTP_MODE) != (s->be->options & PR_O_HTTP_MODE)))
		http_adjust_conn_mode(s, txn, msg);

	/* we may have to wait for the request's body */
	if ((s->be->options & PR_O_WREQ_BODY) &&
	    (msg->body_len || (msg->flags & HTTP_MSGF_TE_CHNK)))
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
	return 1;

 return_bad_req:
	/* We centralize bad requests processing here */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	return 0;
}


/* This function prepares an applet to handle the stats. It can deal with the
 * "100-continue" expectation, check that admin rules are met for POST requests,
 * and program a response message if something was unexpected. It cannot fail
 * and always relies on the stats applet to complete the job. It does not touch
 * analysers nor counters, which are left to the caller. It does not touch
 * s->target which is supposed to already point to the stats applet. The caller
 * is expected to have already assigned an appctx to the stream.
 */
int http_handle_stats(struct stream *s, struct channel *req)
{
	struct stats_admin_rule *stats_admin_rule;
	struct stream_interface *si = &s->si[1];
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct uri_auth *uri_auth = s->be->uri_auth;
	const char *uri, *h, *lookup;
	struct appctx *appctx;

	appctx = si_appctx(si);
	memset(&appctx->ctx.stats, 0, sizeof(appctx->ctx.stats));
	appctx->st1 = appctx->st2 = 0;
	appctx->ctx.stats.st_code = STAT_STATUS_INIT;
	appctx->ctx.stats.flags |= STAT_FMT_HTML; /* assume HTML mode by default */
	if ((msg->flags & HTTP_MSGF_VER_11) && (s->txn->meth != HTTP_METH_HEAD))
		appctx->ctx.stats.flags |= STAT_CHUNKED;

	uri = ci_head(msg->chn) + msg->sl.rq.u;
	lookup = uri + uri_auth->uri_len;

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 3; h++) {
		if (memcmp(h, ";up", 3) == 0) {
			appctx->ctx.stats.flags |= STAT_HIDE_DOWN;
			break;
		}
	}

	if (uri_auth->refresh) {
		for (h = lookup; h <= uri + msg->sl.rq.u_l - 10; h++) {
			if (memcmp(h, ";norefresh", 10) == 0) {
				appctx->ctx.stats.flags |= STAT_NO_REFRESH;
				break;
			}
		}
	}

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 4; h++) {
		if (memcmp(h, ";csv", 4) == 0) {
			appctx->ctx.stats.flags &= ~STAT_FMT_HTML;
			break;
		}
	}

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 6; h++) {
		if (memcmp(h, ";typed", 6) == 0) {
			appctx->ctx.stats.flags &= ~STAT_FMT_HTML;
			appctx->ctx.stats.flags |= STAT_FMT_TYPED;
			break;
		}
	}

	for (h = lookup; h <= uri + msg->sl.rq.u_l - 8; h++) {
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
	for (h = lookup; h <= uri + msg->sl.rq.u_l - 8; h++) {
		if (memcmp(h, STAT_SCOPE_INPUT_NAME "=", strlen(STAT_SCOPE_INPUT_NAME) + 1) == 0) {
			int itx = 0;
			const char *h2;
			char scope_txt[STAT_SCOPE_TXT_MAXLEN + 1];
			const char *err;

			h += strlen(STAT_SCOPE_INPUT_NAME) + 1;
			h2 = h;
			appctx->ctx.stats.scope_str = h2 - ci_head(msg->chn);
			while (*h != ';' && *h != '\0' && *h != '&' && *h != ' ' && *h != '\n') {
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

	/* Was the status page requested with a POST ? */
	if (unlikely(txn->meth == HTTP_METH_POST && txn->req.body_len > 0)) {
		if (appctx->ctx.stats.flags & STAT_ADMIN) {
			/* we'll need the request body, possibly after sending 100-continue */
			if (msg->msg_state < HTTP_MSG_CHUNK_SIZE)
				req->analysers |= AN_REQ_HTTP_BODY;
			appctx->st0 = STAT_HTTP_POST;
		}
		else {
			appctx->ctx.stats.st_code = STAT_STATUS_DENY;
			appctx->st0 = STAT_HTTP_LAST;
		}
	}
	else {
		/* So it was another method (GET/HEAD) */
		appctx->st0 = STAT_HTTP_HEAD;
	}

	s->task->nice = -32; /* small boost for HTTP statistics */
	return 1;
}

int http_transform_header_str(struct stream* s, struct http_msg *msg,
                              const char* name, unsigned int name_len,
                              const char *str, struct my_regex *re,
                              int action)
{
	struct hdr_idx *idx = &s->txn->hdr_idx;
	struct buffer *output = get_trash_chunk();

	/* Choose the header browsing function. */
	switch (action) {
	case ACT_HTTP_REPLACE_VAL:
		return http_legacy_replace_header(idx, msg, name, name_len, str, re, output);
	case ACT_HTTP_REPLACE_HDR:
		return http_legacy_replace_full_header(idx, msg, name, name_len, str, re, output);
	default: /* impossible */
		return -1;
	}
}

static int http_transform_header(struct stream* s, struct http_msg *msg,
                                 const char* name, unsigned int name_len,
                                 struct list *fmt, struct my_regex *re,
                                 int action)
{
	struct buffer *replace;
	int ret = -1;

	replace = alloc_trash_chunk();
	if (!replace)
		goto leave;

	replace->data = build_logline(s, replace->area, replace->size, fmt);
	if (replace->data >= replace->size - 1)
		goto leave;

	ret = http_transform_header_str(s, msg, name, name_len, replace->area,
					re, action);

  leave:
	free_trash_chunk(replace);
	return ret;
}

/*
 * Build an HTTP Early Hint HTTP 103 response header with <name> as name and with a value
 * built according to <fmt> log line format.
 * If <early_hints> is NULL, it is allocated and the HTTP 103 response first
 * line is inserted before the header. If an error occurred <early_hints> is
 * released and NULL is returned. On success the updated buffer is returned.
 */
static struct buffer *http_apply_early_hint_rule(struct stream* s, struct buffer *early_hints,
						 const char* name, unsigned int name_len,
						 struct list *fmt)
{
	if (!early_hints) {
		early_hints = alloc_trash_chunk();
		if (!early_hints)
			goto fail;
		if (!chunk_memcat(early_hints, HTTP_103.ptr, HTTP_103.len))
			goto fail;
	}

	if (!chunk_memcat(early_hints, name, name_len) || !chunk_memcat(early_hints, ": ", 2))
		goto fail;

	early_hints->data += build_logline(s, b_tail(early_hints), b_room(early_hints), fmt);
	if (!chunk_memcat(early_hints, "\r\n", 2))
		goto fail;

	return early_hints;

  fail:
	free_trash_chunk(early_hints);
	return NULL;
}

/* Sends an HTTP 103 response. Before sending it, the last CRLF finishing the
 * response is added. If an error occurred or if another response was already
 * sent, this function does nothing.
 */
static void http_send_early_hints(struct stream *s, struct buffer *early_hints)
{
	struct channel *chn = s->txn->rsp.chn;
	char *cur_ptr = ci_head(chn);
	int ret;

	/* If a response was already sent, skip early hints */
	if (s->txn->status > 0)
		return;

	if (!chunk_memcat(early_hints, "\r\n", 2))
		return;

	ret = b_rep_blk(&chn->buf, cur_ptr, cur_ptr, b_head(early_hints), b_data(early_hints));
	c_adv(chn, ret);
	chn->total += ret;
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
enum rule_result
http_req_get_intercept_rule(struct proxy *px, struct list *rules, struct stream *s, int *deny_status)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct act_rule *rule;
	struct hdr_ctx ctx;
	const char *auth_realm;
	struct buffer *early_hints = NULL;
	enum rule_result rule_ret = HTTP_RULE_RES_CONT;
	int act_flags = 0;
	int len;

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
			/* Be sure to send any pending HTTP 103 response first */
			if (early_hints) {
				http_send_early_hints(s, early_hints);
				free_trash_chunk(early_hints);
				early_hints = NULL;
			}
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
			chunk_printf(&trash, (txn->flags & TX_USE_PX_CONN) ? HTTP_407_fmt : HTTP_401_fmt, auth_realm);
			txn->status = (txn->flags & TX_USE_PX_CONN) ? 407 : 401;
			http_reply_and_close(s, txn->status, &trash);
			stream_inc_http_err_ctr(s);
			rule_ret = HTTP_RULE_RES_ABRT;
			goto end;

		case ACT_HTTP_REDIR:
			/* Be sure to send any pending HTTP 103 response first */
			if (early_hints) {
				http_send_early_hints(s, early_hints);
				free_trash_chunk(early_hints);
				early_hints = NULL;
			}
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
			if (http_transform_header(s, &txn->req, rule->arg.hdr_add.name,
			                          rule->arg.hdr_add.name_len,
			                          &rule->arg.hdr_add.fmt,
			                          &rule->arg.hdr_add.re, rule->action)) {
				rule_ret = HTTP_RULE_RES_BADREQ;
				goto end;
			}
			break;

		case ACT_HTTP_DEL_HDR:
			ctx.idx = 0;
			/* remove all occurrences of the header */
			while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
						 ci_head(txn->req.chn), &txn->hdr_idx, &ctx)) {
				http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
			}
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

			replace = alloc_trash_chunk();
			if (!replace) {
				rule_ret = HTTP_RULE_RES_BADREQ;
				goto end;
			}

			len = rule->arg.hdr_add.name_len + 2,
			len += build_logline(s, replace->area + len,
					     replace->size - len,
					     &rule->arg.hdr_add.fmt);
			memcpy(replace->area, rule->arg.hdr_add.name,
			       rule->arg.hdr_add.name_len);
			replace->area[rule->arg.hdr_add.name_len] = ':';
			replace->area[rule->arg.hdr_add.name_len + 1] = ' ';
			replace->data = len;

			if (rule->action == ACT_HTTP_SET_HDR) {
				/* remove all occurrences of the header */
				ctx.idx = 0;
				while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
							 ci_head(txn->req.chn), &txn->hdr_idx, &ctx)) {
					http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
				}
			}

			if (http_header_add_tail2(&txn->req, &txn->hdr_idx, replace->area, replace->data) < 0) {
				static unsigned char rate_limit = 0;

				if ((rate_limit++ & 255) == 0) {
					replace->area[rule->arg.hdr_add.name_len] = 0;
					send_log(px, LOG_WARNING, "Proxy %s failed to add or set the request header '%s' for request #%u. You might need to increase tune.maxrewrite.", px->id,
						 replace->area, s->uniq_id);
				}

				HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_rewrites, 1);
				if (sess->fe != s->be)
					HA_ATOMIC_ADD(&s->be->be_counters.failed_rewrites, 1);
				if (sess->listener->counters)
					HA_ATOMIC_ADD(&sess->listener->counters->failed_rewrites, 1);
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
			key->data = build_logline(s, key->area, key->size,
						 &rule->arg.map.key);
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
			key->data = build_logline(s, key->area, key->size,
						 &rule->arg.map.key);
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
			key->data = build_logline(s, key->area, key->size,
						 &rule->arg.map.key);
			key->area[key->data] = '\0';

			/* collect value */
			value->data = build_logline(s, value->area,
						   value->size,
						   &rule->arg.map.value);
			value->area[value->data] = '\0';

			/* perform update */
			if (pat_ref_find_elt(ref, key->area) != NULL)
				/* update entry if it exists */
				pat_ref_set(ref, key->area, value->area, NULL);
			else
				/* insert a new entry */
				pat_ref_add(ref, key->area, value->area, NULL);

			free_trash_chunk(key);
			free_trash_chunk(value);
			break;
			}

		case ACT_HTTP_EARLY_HINT:
			if (!(txn->req.flags & HTTP_MSGF_VER_11))
				break;
			early_hints = http_apply_early_hint_rule(s, early_hints,
								 rule->arg.early_hint.name,
								 rule->arg.early_hint.name_len,
								 &rule->arg.early_hint.fmt);
			if (!early_hints) {
				rule_ret = HTTP_RULE_RES_DONE;
				goto end;
			}
			break;
		case ACT_CUSTOM:
			if ((s->req.flags & CF_READ_ERROR) ||
			    ((s->req.flags & (CF_SHUTR|CF_READ_NULL)) &&
			     !(s->si[0].flags & SI_FL_CLEAN_ABRT) &&
			     (px->options & PR_O_ABRT_CLOSE)))
				act_flags |= ACT_FLAG_FINAL;

			switch (rule->action_ptr(rule, px, s->sess, s, act_flags)) {
			case ACT_RET_ERR:
			case ACT_RET_CONT:
				break;
			case ACT_RET_STOP:
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
				key = stktable_fetch_key(t, s->be, sess, s, SMP_OPT_DIR_REQ | SMP_OPT_FINAL, rule->arg.trk_ctr.expr, NULL);

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
		http_send_early_hints(s, early_hints);
		free_trash_chunk(early_hints);
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
enum rule_result
http_res_get_intercept_rule(struct proxy *px, struct list *rules, struct stream *s)
{
	struct session *sess = strm_sess(s);
	struct http_txn *txn = s->txn;
	struct act_rule *rule;
	struct hdr_ctx ctx;
	enum rule_result rule_ret = HTTP_RULE_RES_CONT;
	int act_flags = 0;

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
			if (http_transform_header(s, &txn->rsp, rule->arg.hdr_add.name,
			                          rule->arg.hdr_add.name_len,
			                          &rule->arg.hdr_add.fmt,
			                          &rule->arg.hdr_add.re, rule->action)) {
				rule_ret = HTTP_RULE_RES_BADREQ;
				goto end;
			}
			break;

		case ACT_HTTP_DEL_HDR:
			ctx.idx = 0;
			/* remove all occurrences of the header */
			while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
						 ci_head(txn->rsp.chn), &txn->hdr_idx, &ctx)) {
				http_remove_header2(&txn->rsp, &txn->hdr_idx, &ctx);
			}
			break;

		case ACT_HTTP_SET_HDR:
		case ACT_HTTP_ADD_HDR: {
			struct buffer *replace;

			replace = alloc_trash_chunk();
			if (!replace) {
				rule_ret = HTTP_RULE_RES_BADREQ;
				goto end;
			}

			chunk_printf(replace, "%s: ", rule->arg.hdr_add.name);
			memcpy(replace->area, rule->arg.hdr_add.name,
			       rule->arg.hdr_add.name_len);
			replace->data = rule->arg.hdr_add.name_len;
			replace->area[replace->data++] = ':';
			replace->area[replace->data++] = ' ';
			replace->data += build_logline(s,
						      replace->area + replace->data,
						      replace->size - replace->data,
						      &rule->arg.hdr_add.fmt);

			if (rule->action == ACT_HTTP_SET_HDR) {
				/* remove all occurrences of the header */
				ctx.idx = 0;
				while (http_find_header2(rule->arg.hdr_add.name, rule->arg.hdr_add.name_len,
							 ci_head(txn->rsp.chn), &txn->hdr_idx, &ctx)) {
					http_remove_header2(&txn->rsp, &txn->hdr_idx, &ctx);
				}
			}

			if (http_header_add_tail2(&txn->rsp, &txn->hdr_idx, replace->area, replace->data) < 0) {
				static unsigned char rate_limit = 0;

				if ((rate_limit++ & 255) == 0) {
					replace->area[rule->arg.hdr_add.name_len] = 0;
					send_log(px, LOG_WARNING, "Proxy %s failed to add or set the response header '%s' for request #%u. You might need to increase tune.maxrewrite.", px->id,
						 replace->area, s->uniq_id);
				}

				HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_rewrites, 1);
				if (sess->fe != s->be)
					HA_ATOMIC_ADD(&s->be->be_counters.failed_rewrites, 1);
				if (sess->listener->counters)
					HA_ATOMIC_ADD(&sess->listener->counters->failed_rewrites, 1);
				if (objt_server(s->target))
					HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_rewrites, 1);
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
			key->data = build_logline(s, key->area, key->size,
						 &rule->arg.map.key);
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
			key->data = build_logline(s, key->area, key->size,
						 &rule->arg.map.key);
			key->area[key->data] = '\0';

			/* perform update */
			/* check if the entry already exists */
			if (pat_ref_find_elt(ref, key->area) == NULL)
				pat_ref_add(ref, key->area, NULL, NULL);

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
			key->data = build_logline(s, key->area, key->size,
						 &rule->arg.map.key);
			key->area[key->data] = '\0';

			/* collect value */
			value->data = build_logline(s, value->area,
						   value->size,
						   &rule->arg.map.value);
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
				key = stktable_fetch_key(t, s->be, sess, s, SMP_OPT_DIR_RES | SMP_OPT_FINAL, rule->arg.trk_ctr.expr, NULL);

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
			     !(s->si[0].flags & SI_FL_CLEAN_ABRT) &&
			     (px->options & PR_O_ABRT_CLOSE)))
				act_flags |= ACT_FLAG_FINAL;

			switch (rule->action_ptr(rule, px, s->sess, s, act_flags)) {
			case ACT_RET_ERR:
			case ACT_RET_CONT:
				break;
			case ACT_RET_STOP:
				rule_ret = HTTP_RULE_RES_STOP;
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


/* Perform an HTTP redirect based on the information in <rule>. The function
 * returns non-zero on success, or zero in case of a, irrecoverable error such
 * as too large a request to build a valid response.
 */
int http_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn)
{
	struct http_msg *req = &txn->req;
	struct http_msg *res = &txn->rsp;
	const char *msg_fmt;
	struct buffer *chunk;
	int ret = 0;

	if (IS_HTX_STRM(s))
		return htx_apply_redirect_rule(rule, s, txn);

	chunk = alloc_trash_chunk();
	if (!chunk)
		goto leave;

	/* build redirect message */
	switch(rule->code) {
	case 308:
		msg_fmt = HTTP_308;
		break;
	case 307:
		msg_fmt = HTTP_307;
		break;
	case 303:
		msg_fmt = HTTP_303;
		break;
	case 301:
		msg_fmt = HTTP_301;
		break;
	case 302:
	default:
		msg_fmt = HTTP_302;
		break;
	}

	if (unlikely(!chunk_strcpy(chunk, msg_fmt)))
		goto leave;

	switch(rule->type) {
	case REDIRECT_TYPE_SCHEME: {
		const char *path;
		const char *host;
		struct hdr_ctx ctx;
		int pathlen;
		int hostlen;

		host = "";
		hostlen = 0;
		ctx.idx = 0;
		if (http_find_header2("Host", 4, ci_head(req->chn), &txn->hdr_idx, &ctx)) {
			host = ctx.line + ctx.val;
			hostlen = ctx.vlen;
		}

		path = http_txn_get_path(txn);
		/* build message using path */
		if (path) {
			pathlen = req->sl.rq.u_l + (ci_head(req->chn) + req->sl.rq.u) - path;
			if (rule->flags & REDIRECT_FLAG_DROP_QS) {
				int qs = 0;
				while (qs < pathlen) {
					if (path[qs] == '?') {
						pathlen = qs;
						break;
					}
					qs++;
				}
			}
		} else {
			path = "/";
			pathlen = 1;
		}

		if (rule->rdr_str) { /* this is an old "redirect" rule */
			/* check if we can add scheme + "://" + host + path */
			if (chunk->data + rule->rdr_len + 3 + hostlen + pathlen > chunk->size - 4)
				goto leave;

			/* add scheme */
			memcpy(chunk->area + chunk->data, rule->rdr_str,
			       rule->rdr_len);
			chunk->data += rule->rdr_len;
		}
		else {
			/* add scheme with executing log format */
			chunk->data += build_logline(s,
						    chunk->area + chunk->data,
						    chunk->size - chunk->data,
						    &rule->rdr_fmt);

			/* check if we can add scheme + "://" + host + path */
			if (chunk->data + 3 + hostlen + pathlen > chunk->size - 4)
				goto leave;
		}
		/* add "://" */
		memcpy(chunk->area + chunk->data, "://", 3);
		chunk->data += 3;

		/* add host */
		memcpy(chunk->area + chunk->data, host, hostlen);
		chunk->data += hostlen;

		/* add path */
		memcpy(chunk->area + chunk->data, path, pathlen);
		chunk->data += pathlen;

		/* append a slash at the end of the location if needed and missing */
		if (chunk->data && chunk->area[chunk->data - 1] != '/' &&
		    (rule->flags & REDIRECT_FLAG_APPEND_SLASH)) {
			if (chunk->data > chunk->size - 5)
				goto leave;
			chunk->area[chunk->data] = '/';
			chunk->data++;
		}

		break;
	}
	case REDIRECT_TYPE_PREFIX: {
		const char *path;
		int pathlen;

		path = http_txn_get_path(txn);
		/* build message using path */
		if (path) {
			pathlen = req->sl.rq.u_l + (ci_head(req->chn) + req->sl.rq.u) - path;
			if (rule->flags & REDIRECT_FLAG_DROP_QS) {
				int qs = 0;
				while (qs < pathlen) {
					if (path[qs] == '?') {
						pathlen = qs;
						break;
					}
					qs++;
				}
			}
		} else {
			path = "/";
			pathlen = 1;
		}

		if (rule->rdr_str) { /* this is an old "redirect" rule */
			if (chunk->data + rule->rdr_len + pathlen > chunk->size - 4)
				goto leave;

			/* add prefix. Note that if prefix == "/", we don't want to
			 * add anything, otherwise it makes it hard for the user to
			 * configure a self-redirection.
			 */
			if (rule->rdr_len != 1 || *rule->rdr_str != '/') {
				memcpy(chunk->area + chunk->data,
				       rule->rdr_str, rule->rdr_len);
				chunk->data += rule->rdr_len;
			}
		}
		else {
			/* add prefix with executing log format */
			chunk->data += build_logline(s,
						    chunk->area + chunk->data,
						    chunk->size - chunk->data,
						    &rule->rdr_fmt);

			/* Check length */
			if (chunk->data + pathlen > chunk->size - 4)
				goto leave;
		}

		/* add path */
		memcpy(chunk->area + chunk->data, path, pathlen);
		chunk->data += pathlen;

		/* append a slash at the end of the location if needed and missing */
		if (chunk->data && chunk->area[chunk->data - 1] != '/' &&
		    (rule->flags & REDIRECT_FLAG_APPEND_SLASH)) {
			if (chunk->data > chunk->size - 5)
				goto leave;
			chunk->area[chunk->data] = '/';
			chunk->data++;
		}

		break;
	}
	case REDIRECT_TYPE_LOCATION:
	default:
		if (rule->rdr_str) { /* this is an old "redirect" rule */
			if (chunk->data + rule->rdr_len > chunk->size - 4)
				goto leave;

			/* add location */
			memcpy(chunk->area + chunk->data, rule->rdr_str,
			       rule->rdr_len);
			chunk->data += rule->rdr_len;
		}
		else {
			/* add location with executing log format */
			chunk->data += build_logline(s,
						    chunk->area + chunk->data,
						    chunk->size - chunk->data,
						    &rule->rdr_fmt);

			/* Check left length */
			if (chunk->data > chunk->size - 4)
				goto leave;
		}
		break;
	}

	if (rule->cookie_len) {
		memcpy(chunk->area + chunk->data, "\r\nSet-Cookie: ", 14);
		chunk->data += 14;
		memcpy(chunk->area + chunk->data, rule->cookie_str,
		       rule->cookie_len);
		chunk->data += rule->cookie_len;
	}

	/* add end of headers and the keep-alive/close status. */
	txn->status = rule->code;
	/* let's log the request time */
	s->logs.tv_request = now;

	if (((!(req->flags & HTTP_MSGF_TE_CHNK) && !req->body_len) || (req->msg_state == HTTP_MSG_DONE)) &&
	    ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL ||
	     (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL)) {
		/* keep-alive possible */
		if (!(req->flags & HTTP_MSGF_VER_11)) {
			if (unlikely(txn->flags & TX_USE_PX_CONN)) {
				memcpy(chunk->area + chunk->data,
				       "\r\nProxy-Connection: keep-alive", 30);
				chunk->data += 30;
			} else {
				memcpy(chunk->area + chunk->data,
				       "\r\nConnection: keep-alive", 24);
				chunk->data += 24;
			}
		}
		memcpy(chunk->area + chunk->data, "\r\n\r\n", 4);
		chunk->data += 4;
		FLT_STRM_CB(s, flt_http_reply(s, txn->status, chunk));
		co_inject(res->chn, chunk->area, chunk->data);
		/* "eat" the request */
		b_del(&req->chn->buf, req->sov);
		req->next -= req->sov;
		req->sov = 0;
		s->req.analysers = AN_REQ_HTTP_XFER_BODY | (s->req.analysers & AN_REQ_FLT_END);
		s->res.analysers = AN_RES_HTTP_XFER_BODY | (s->res.analysers & AN_RES_FLT_END);
		req->msg_state = HTTP_MSG_CLOSED;
		res->msg_state = HTTP_MSG_DONE;
		/* Trim any possible response */
		b_set_data(&res->chn->buf, co_data(res->chn));
		res->next = res->sov = 0;
		/* let the server side turn to SI_ST_CLO */
		channel_shutw_now(req->chn);
	} else {
		/* keep-alive not possible */
		if (unlikely(txn->flags & TX_USE_PX_CONN)) {
			memcpy(chunk->area + chunk->data,
			       "\r\nProxy-Connection: close\r\n\r\n", 29);
			chunk->data += 29;
		} else {
			memcpy(chunk->area + chunk->data,
			       "\r\nConnection: close\r\n\r\n", 23);
			chunk->data += 23;
		}
		http_reply_and_close(s, txn->status, chunk);
		req->chn->analysers &= AN_REQ_FLT_END;
	}

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_LOCAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	ret = 1;
 leave:
	free_trash_chunk(chunk);
	return ret;
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
	struct redirect_rule *rule;
	struct cond_wordlist *wl;
	enum rule_result verdict;
	int deny_status = HTTP_ERR_403;
	struct connection *conn = objt_conn(sess->origin);

	if (IS_HTX_STRM(s))
		return htx_process_req_common(s, req, an_bit, px);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		goto return_prx_yield;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	/* just in case we have some per-backend tracking */
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
		struct hdr_ctx ctx;

		ctx.idx = 0;
		if (!http_find_header2("Early-Data", strlen("Early-Data"),
		    ci_head(&s->req), &txn->hdr_idx, &ctx)) {
			if (unlikely(http_header_add_tail2(&txn->req,
			    &txn->hdr_idx, "Early-Data: 1",
			    strlen("Early-Data: 1")) < 0)) {
				goto return_bad_req;
			 }
		}

	}

	/* OK at this stage, we know that the request was accepted according to
	 * the http-request rules, we can check for the stats. Note that the
	 * URI is detected *before* the req* rules in order not to be affected
	 * by a possible reqrep, while they are processed *after* so that a
	 * reqdeny can still block them. This clearly needs to change in 1.6!
	 */
	if (stats_check_uri(&s->si[1], txn, px)) {
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

	/* evaluate the req* rules except reqadd */
	if (px->req_exp != NULL) {
		if (apply_filters_to_request(s, req, px) < 0)
			goto return_bad_req;

		if (txn->flags & TX_CLDENY)
			goto deny;

		if (txn->flags & TX_CLTARPIT) {
			deny_status = HTTP_ERR_500;
			goto tarpit;
		}
	}

	/* add request headers from the rule sets in the same order */
	list_for_each_entry(wl, &px->req_add, list) {
		if (wl->cond) {
			int ret = acl_exec_cond(wl->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (((struct acl_cond *)wl->cond)->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}

		if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, wl->s, strlen(wl->s)) < 0))
			goto return_bad_req;
	}


	/* Proceed with the stats now. */
	if (unlikely(objt_applet(s->target) == &http_stats_applet) ||
	    unlikely(objt_applet(s->target) == &http_cache_applet)) {
		/* process the stats request now */
		if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

		if (!(s->flags & SF_ERR_MASK))      // this is not really an error but it is
			s->flags |= SF_ERR_LOCAL;   // to mark that it comes from the proxy
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_R;

		/* enable the minimally required analyzers to handle keep-alive and compression on the HTTP response */
		req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
		req->analysers &= ~AN_REQ_FLT_XFER_DATA;
		req->analysers |= AN_REQ_HTTP_XFER_BODY;
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
	return 1;

 tarpit:
	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	/* When a connection is tarpitted, we use the tarpit timeout,
	 * which may be the same as the connect timeout if unspecified.
	 * If unset, then set it to zero because we really want it to
	 * eventually expire. We build the tarpit as an analyser.
	 */
	channel_erase(&s->req);

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
	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto done_without_exp;

 deny:	/* this request was blocked (denied) */

	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	txn->flags |= TX_CLDENY;
	txn->status = http_err_codes[deny_status];
	s->logs.tv_request = now;
	http_reply_and_close(s, txn->status, http_error_message(s));
	stream_inc_http_err_ctr(s);
	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto return_prx_cond;

 return_bad_req:
	/* We centralize bad requests processing here */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	return 0;

 return_prx_yield:
	channel_dont_connect(req);
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
	struct connection *cli_conn = objt_conn(strm_sess(s)->origin);

	if (IS_HTX_STRM(s))
		return htx_process_request(s, req, an_bit);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		channel_dont_connect(req);
		return 0;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	/*
	 * Right now, we know that we have processed the entire headers
	 * and that unwanted requests have been filtered out. We can do
	 * whatever we want with the remaining request. Also, now we
	 * may have separate values for ->fe, ->be.
	 */

	/*
	 * If HTTP PROXY is set we simply get remote server address parsing
	 * incoming request. Note that this requires that a connection is
	 * allocated on the server side.
	 */
	if ((s->be->options & PR_O_HTTP_PROXY) && !(s->flags & SF_ADDR_SET)) {
		struct connection *conn;
		char *path;

		/* Note that for now we don't reuse existing proxy connections */
		if (unlikely((conn = cs_conn(si_alloc_cs(&s->si[1], NULL))) == NULL)) {
			txn->req.err_state = txn->req.msg_state;
			txn->req.msg_state = HTTP_MSG_ERROR;
			txn->status = 500;
			req->analysers &= AN_REQ_FLT_END;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;

			return 0;
		}

		path = http_txn_get_path(txn);
		if (url2sa(ci_head(req) + msg->sl.rq.u,
			   path ? path - (ci_head(req) + msg->sl.rq.u) : msg->sl.rq.u_l,
			   &conn->addr.to, NULL) == -1)
			goto return_bad_req;

		/* if the path was found, we have to remove everything between
		 * ci_head(req) + msg->sl.rq.u and path (excluded). If it was not
		 * found, we need to replace from ci_head(req) + msg->sl.rq.u for
		 * u_l characters by a single "/".
		 */
		if (path) {
			char *cur_ptr = ci_head(req);
			char *cur_end = cur_ptr + txn->req.sl.rq.l;
			int delta;

			delta = b_rep_blk(&req->buf, cur_ptr + msg->sl.rq.u, path, NULL, 0);
			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			if (http_parse_reqline(&txn->req, HTTP_MSG_RQMETH,  cur_ptr, cur_end + 1, NULL, NULL) == NULL)
				goto return_bad_req;
		}
		else {
			char *cur_ptr = ci_head(req);
			char *cur_end = cur_ptr + txn->req.sl.rq.l;
			int delta;

			delta = b_rep_blk(&req->buf, cur_ptr + msg->sl.rq.u,
						cur_ptr + msg->sl.rq.u + msg->sl.rq.u_l, "/", 1);
			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			if (http_parse_reqline(&txn->req, HTTP_MSG_RQMETH,  cur_ptr, cur_end + 1, NULL, NULL) == NULL)
				goto return_bad_req;
		}
	}

	/*
	 * 7: Now we can work with the cookies.
	 * Note that doing so might move headers in the request, but
	 * the fields will stay coherent and the URI will not move.
	 * This should only be performed in the backend.
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	/* add unique-id if "header-unique-id" is specified */

	if (!LIST_ISEMPTY(&sess->fe->format_unique_id) && !s->unique_id) {
		if ((s->unique_id = pool_alloc(pool_head_uniqueid)) == NULL)
			goto return_bad_req;
		s->unique_id[0] = '\0';
		build_logline(s, s->unique_id, UNIQUEID_LEN, &sess->fe->format_unique_id);
	}

	if (sess->fe->header_unique_id && s->unique_id) {
		if (chunk_printf(&trash, "%s: %s", sess->fe->header_unique_id, s->unique_id) < 0)
			goto return_bad_req;
		if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, trash.data) < 0))
		   goto return_bad_req;
	}

	/*
	 * 9: add X-Forwarded-For if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_FWDFOR) {
		struct hdr_ctx ctx = { .idx = 0 };
		if (!((sess->fe->options | s->be->options) & PR_O_FF_ALWAYS) &&
			http_find_header2(s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_name : sess->fe->fwdfor_hdr_name,
			                  s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_len : sess->fe->fwdfor_hdr_len,
			                  ci_head(req), &txn->hdr_idx, &ctx)) {
			/* The header is set to be added only if none is present
			 * and we found it, so don't do anything.
			 */
		}
		else if (cli_conn && cli_conn->addr.from.ss_family == AF_INET) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if ((!sess->fe->except_mask.s_addr ||
			     (((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr & sess->fe->except_mask.s_addr)
			     != sess->fe->except_net.s_addr) &&
			    (!s->be->except_mask.s_addr ||
			     (((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr & s->be->except_mask.s_addr)
			     != s->be->except_net.s_addr)) {
				int len;
				unsigned char *pn;
				pn = (unsigned char *)&((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (s->be->fwdfor_hdr_len) {
					len = s->be->fwdfor_hdr_len;
					memcpy(trash.area,
					       s->be->fwdfor_hdr_name, len);
				} else {
					len = sess->fe->fwdfor_hdr_len;
					memcpy(trash.area,
					       sess->fe->fwdfor_hdr_name, len);
				}
				len += snprintf(trash.area + len,
						trash.size - len,
						": %d.%d.%d.%d", pn[0], pn[1],
						pn[2], pn[3]);

				if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, len) < 0))
					goto return_bad_req;
			}
		}
		else if (cli_conn && cli_conn->addr.from.ss_family == AF_INET6) {
			/* FIXME: for the sake of completeness, we should also support
			 * 'except' here, although it is mostly useless in this case.
			 */
			int len;
			char pn[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6,
				  (const void *)&((struct sockaddr_in6 *)(&cli_conn->addr.from))->sin6_addr,
				  pn, sizeof(pn));

			/* Note: we rely on the backend to get the header name to be used for
			 * x-forwarded-for, because the header is really meant for the backends.
			 * However, if the backend did not specify any option, we have to rely
			 * on the frontend's header name.
			 */
			if (s->be->fwdfor_hdr_len) {
				len = s->be->fwdfor_hdr_len;
				memcpy(trash.area, s->be->fwdfor_hdr_name,
				       len);
			} else {
				len = sess->fe->fwdfor_hdr_len;
				memcpy(trash.area, sess->fe->fwdfor_hdr_name,
				       len);
			}
			len += snprintf(trash.area + len, trash.size - len,
					": %s", pn);

			if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, len) < 0))
				goto return_bad_req;
		}
	}

	/*
	 * 10: add X-Original-To if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_ORGTO) {

		/* FIXME: don't know if IPv6 can handle that case too. */
		if (cli_conn && cli_conn->addr.from.ss_family == AF_INET) {
			/* Add an X-Original-To header unless the destination IP is
			 * in the 'except' network range.
			 */
			conn_get_to_addr(cli_conn);

			if (cli_conn->addr.to.ss_family == AF_INET &&
			    ((!sess->fe->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr & sess->fe->except_mask_to.s_addr)
			      != sess->fe->except_to.s_addr) &&
			     (!s->be->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr & s->be->except_mask_to.s_addr)
			      != s->be->except_to.s_addr))) {
				int len;
				unsigned char *pn;
				pn = (unsigned char *)&((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-original-to, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (s->be->orgto_hdr_len) {
					len = s->be->orgto_hdr_len;
					memcpy(trash.area,
					       s->be->orgto_hdr_name, len);
				} else {
					len = sess->fe->orgto_hdr_len;
					memcpy(trash.area,
					       sess->fe->orgto_hdr_name, len);
				}
				len += snprintf(trash.area + len,
						trash.size - len,
						": %d.%d.%d.%d", pn[0], pn[1],
						pn[2], pn[3]);

				if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, len) < 0))
					goto return_bad_req;
			}
		}
	}

	/* 11: add "Connection: close" or "Connection: keep-alive" if needed and not yet set.
	 * If an "Upgrade" token is found, the header is left untouched in order not to have
	 * to deal with some servers bugs : some of them fail an Upgrade if anything but
	 * "Upgrade" is present in the Connection header.
	 */
	if (!(txn->flags & TX_HDR_CONN_UPG) && (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		unsigned int want_flags = 0;

		if (msg->flags & HTTP_MSGF_VER_11) {
			if ((txn->flags & TX_CON_WANT_MSK) >= TX_CON_WANT_SCL &&
			    !((sess->fe->options2|s->be->options2) & PR_O2_FAKE_KA))
				want_flags |= TX_CON_CLO_SET;
		} else {
			if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
			    ((sess->fe->options2|s->be->options2) & PR_O2_FAKE_KA))
				want_flags |= TX_CON_KAL_SET;
		}

		if (want_flags != (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
			http_change_connection_header(txn, msg, want_flags);
	}


	/* If we have no server assigned yet and we're balancing on url_param
	 * with a POST request, we may be interested in checking the body for
	 * that parameter. This will be done in another analyser.
	 */
	if (!(s->flags & (SF_ASSIGNED|SF_DIRECT)) &&
	    s->txn->meth == HTTP_METH_POST && s->be->url_param_name != NULL &&
	    (msg->flags & (HTTP_MSGF_CNT_LEN|HTTP_MSGF_TE_CHNK))) {
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
	    ((msg->flags & HTTP_MSGF_TE_CHNK) ||
	     (msg->body_len > ci_data(req) - txn->req.eoh - 2)))
		conn_set_quickack(cli_conn, 1);

	/*************************************************************
	 * OK, that's finished for the headers. We have done what we *
	 * could. Let's switch to the DATA state.                    *
	 ************************************************************/
	req->analyse_exp = TICK_ETERNITY;
	req->analysers &= ~an_bit;

	s->logs.tv_request = now;
	/* OK let's go on with the BODY now */
	return 1;

 return_bad_req: /* let's centralize all bad requests */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	req->analysers &= AN_REQ_FLT_END;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;
	return 0;
}

/* This function is an analyser which processes the HTTP tarpit. It always
 * returns zero, at the beginning because it prevents any other processing
 * from occurring, and at the end because it terminates the request.
 */
int http_process_tarpit(struct stream *s, struct channel *req, int an_bit)
{
	struct http_txn *txn = s->txn;

	if (IS_HTX_STRM(s))
		return htx_process_tarpit(s, req, an_bit);

	/* This connection is being tarpitted. The CLIENT side has
	 * already set the connect expiration date to the right
	 * timeout. We just have to check that the client is still
	 * there and that the timeout has not expired.
	 */
	channel_dont_connect(req);
	if ((req->flags & (CF_SHUTR|CF_READ_ERROR)) == 0 &&
	    !tick_is_expired(req->analyse_exp, now_ms))
		return 0;

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

	if (IS_HTX_STRM(s))
		return htx_wait_for_request_body(s, req, an_bit);

	/* We have to parse the HTTP request body to find any required data.
	 * "balance url_param check_post" should have been the only way to get
	 * into this. We were brought here after HTTP header analysis, so all
	 * related structures are ready.
	 */

	if (msg->msg_state < HTTP_MSG_CHUNK_SIZE) {
		/* This is the first call */
		if (msg->msg_state < HTTP_MSG_BODY)
			goto missing_data;

		if (msg->msg_state < HTTP_MSG_100_SENT) {
			/* If we have HTTP/1.1 and Expect: 100-continue, then we must
			 * send an HTTP/1.1 100 Continue intermediate response.
			 */
			if (msg->flags & HTTP_MSGF_VER_11) {
				struct hdr_ctx ctx;
				ctx.idx = 0;
				/* Expect is allowed in 1.1, look for it */
				if (http_find_header2("Expect", 6, ci_head(req), &txn->hdr_idx, &ctx) &&
				    unlikely(ctx.vlen == 12 && strncasecmp(ctx.line+ctx.val, "100-continue", 12) == 0)) {
					co_inject(&s->res, HTTP_100.ptr, HTTP_100.len);
					http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
				}
			}
			msg->msg_state = HTTP_MSG_100_SENT;
		}

		/* we have msg->sov which points to the first byte of message body.
		 * ci_head(req) still points to the beginning of the message. We
		 * must save the body in msg->next because it survives buffer
		 * re-alignments.
		 */
		msg->next = msg->sov;

		if (msg->flags & HTTP_MSGF_TE_CHNK)
			msg->msg_state = HTTP_MSG_CHUNK_SIZE;
		else
			msg->msg_state = HTTP_MSG_DATA;
	}

	if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
		/* We're in content-length mode, we just have to wait for enough data. */
		if (http_body_bytes(msg) < msg->body_len)
			goto missing_data;

		/* OK we have everything we need now */
		goto http_end;
	}

	/* OK here we're parsing a chunked-encoded message */

	if (msg->msg_state == HTTP_MSG_CHUNK_SIZE) {
		/* read the chunk size and assign it to ->chunk_len, then
		 * set ->sov and ->next to point to the body and switch to DATA or
		 * TRAILERS state.
		 */
		unsigned int chunk;
		int ret = h1_parse_chunk_size(&req->buf, co_data(req) + msg->next, c_data(req), &chunk);

		if (!ret)
			goto missing_data;
		else if (ret < 0) {
			msg->err_pos = ci_data(req) + ret;
			if (msg->err_pos < 0)
				msg->err_pos += req->buf.size;
			stream_inc_http_err_ctr(s);
			goto return_bad_req;
		}

		msg->chunk_len = chunk;
		msg->body_len += chunk;

		msg->sol = ret;
		msg->next += ret;
		msg->msg_state = msg->chunk_len ? HTTP_MSG_DATA : HTTP_MSG_TRAILERS;
	}

	/* Now we're in HTTP_MSG_DATA or HTTP_MSG_TRAILERS state.
	 * We have the first data byte is in msg->sov + msg->sol. We're waiting
	 * for at least a whole chunk or the whole content length bytes after
	 * msg->sov + msg->sol.
	 */
	if (msg->msg_state == HTTP_MSG_TRAILERS)
		goto http_end;

	if (http_body_bytes(msg) >= msg->body_len)   /* we have enough bytes now */
		goto http_end;

 missing_data:
	/* we get here if we need to wait for more data. If the buffer is full,
	 * we have the maximum we can expect.
	 */
	if (channel_full(req, global.tune.maxrewrite))
		goto http_end;

	if ((req->flags & CF_READ_TIMEOUT) || tick_is_expired(req->analyse_exp, now_ms)) {
		txn->status = 408;
		http_reply_and_close(s, txn->status, http_error_message(s));

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
		return 0;
	}

 http_end:
	/* The situation will not evolve, so let's give up on the analysis. */
	s->logs.tv_request = now;  /* update the request timer to reflect full request */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;

 return_bad_req: /* let's centralize all bad requests */
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

 return_err_msg:
	req->analysers &= AN_REQ_FLT_END;
	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);
	return 0;
}

/* send a server's name with an outgoing request over an established connection.
 * Note: this function is designed to be called once the request has been scheduled
 * for being forwarded. This is the reason why it rewinds the buffer before
 * proceeding.
 */
int http_send_name_header(struct stream *s, struct proxy* be, const char* srv_name) {

	struct hdr_ctx ctx;
	struct http_txn *txn = s->txn;
	char *hdr_name = be->server_id_hdr_name;
	int hdr_name_len = be->server_id_hdr_len;
	struct channel *chn = txn->req.chn;
	char *hdr_val;
	unsigned int old_o, old_i;

	if (IS_HTX_STRM(s))
		return htx_send_name_header(s, be, srv_name);
	ctx.idx = 0;

	old_o = http_hdr_rewind(&txn->req);
	if (old_o) {
		/* The request was already skipped, let's restore it */
		c_rew(chn, old_o);
		txn->req.next += old_o;
		txn->req.sov += old_o;
	}

	old_i = ci_data(chn);
	while (http_find_header2(hdr_name, hdr_name_len, ci_head(txn->req.chn), &txn->hdr_idx, &ctx)) {
		/* remove any existing values from the header */
	        http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
	}

	/* Add the new header requested with the server value */
	hdr_val = trash.area;
	memcpy(hdr_val, hdr_name, hdr_name_len);
	hdr_val += hdr_name_len;
	*hdr_val++ = ':';
	*hdr_val++ = ' ';
	hdr_val += strlcpy2(hdr_val, srv_name,
			    trash.area + trash.size - hdr_val);
	http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area,
			      hdr_val - trash.area);

	if (old_o) {
		/* If this was a forwarded request, we must readjust the amount of
		 * data to be forwarded in order to take into account the size
		 * variations. Note that the current state is >= HTTP_MSG_BODY,
		 * so we don't have to adjust ->sol.
		 */
		old_o += ci_data(chn) - old_i;
		c_adv(chn, old_o);
		txn->req.next -= old_o;
		txn->req.sov  -= old_o;
	}

	return 0;
}

/* Terminate current transaction and prepare a new one. This is very tricky
 * right now but it works.
 */
void http_end_txn_clean_session(struct stream *s)
{
	int prev_status = s->txn->status;
	struct proxy *fe = strm_fe(s);
	struct proxy *be = s->be;
	struct conn_stream *cs;
	struct connection *srv_conn;
	struct server *srv;
	unsigned int prev_flags = s->txn->flags;

	/* FIXME: We need a more portable way of releasing a backend's and a
	 * server's connections. We need a safer way to reinitialize buffer
	 * flags. We also need a more accurate method for computing per-request
	 * data.
	 */
	cs = objt_cs(s->si[1].end);
	srv_conn = cs_conn(cs);

	/* unless we're doing keep-alive, we want to quickly close the connection
	 * to the server.
	 */
	if (((s->txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) ||
	    !si_conn_ready(&s->si[1]) || !srv_conn->owner) {
		s->si[1].flags |= SI_FL_NOLINGER | SI_FL_NOHALF;
		si_shutr(&s->si[1]);
		si_shutw(&s->si[1]);
	}

	if (s->flags & SF_BE_ASSIGNED) {
		HA_ATOMIC_SUB(&be->beconn, 1);
		if (unlikely(s->srv_conn))
			sess_change_server(s, NULL);
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	stream_process_counters(s);

	if (s->txn->status) {
		int n;

		n = s->txn->status / 100;
		if (n < 1 || n > 5)
			n = 0;

		if (fe->mode == PR_MODE_HTTP) {
			HA_ATOMIC_ADD(&fe->fe_counters.p.http.rsp[n], 1);
		}
		if ((s->flags & SF_BE_ASSIGNED) &&
		    (be->mode == PR_MODE_HTTP)) {
			HA_ATOMIC_ADD(&be->be_counters.p.http.rsp[n], 1);
			HA_ATOMIC_ADD(&be->be_counters.p.http.cum_req, 1);
		}
	}

	/* don't count other requests' data */
	s->logs.bytes_in  -= ci_data(&s->req);
	s->logs.bytes_out -= ci_data(&s->res);

	/* we may need to know the position in the queue */
	pendconn_free(s);

	/* let's do a final log if we need it */
	if (!LIST_ISEMPTY(&fe->logformat) && s->logs.logwait &&
	    !(s->flags & SF_MONITOR) &&
	    (!(fe->options & PR_O_NULLNOLOG) || s->req.total)) {
		s->do_log(s);
	}

	/* stop tracking content-based counters */
	stream_stop_content_counters(s);
	stream_update_time_stats(s);

	/* reset the profiling counter */
	s->task->calls     = 0;
	s->task->cpu_time  = 0;
	s->task->lat_time  = 0;
	s->task->call_date = (profiling & HA_PROF_TASKS) ? now_mono_time() : 0;

	s->logs.accept_date = date; /* user-visible date for logging */
	s->logs.tv_accept = now;  /* corrected date for internal use */
	s->logs.t_handshake = 0; /* There are no handshake in keep alive connection. */
	s->logs.t_idle = -1;
	tv_zero(&s->logs.tv_request);
	s->logs.t_queue = -1;
	s->logs.t_connect = -1;
	s->logs.t_data = -1;
	s->logs.t_close = 0;
	s->logs.prx_queue_pos = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_pos = 0; /* we will get this number soon */

	s->logs.bytes_in = s->req.total = ci_data(&s->req);
	s->logs.bytes_out = s->res.total = ci_data(&s->res);

	if (objt_server(s->target)) {
		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			HA_ATOMIC_SUB(&__objt_server(s->target)->cur_sess, 1);
		}
		if (may_dequeue_tasks(objt_server(s->target), be))
			process_srv_queue(objt_server(s->target));
	}

	s->target = NULL;


	/* If we're doing keepalive, first call the mux detach() method
	 * to let it know we want to detach without freing the connection.
	 * We then can call si_release_endpoint() to destroy the conn_stream
	 */
	if (((s->txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) ||
	    !si_conn_ready(&s->si[1]) ||
	    (srv_conn && srv_conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH)))
		srv_conn = NULL;
	else if (!srv_conn->owner) {
		srv_conn->owner = s->sess;
		/* Add it unconditionally to the session list, it'll be removed
		 * later if needed by session_check_idle_conn(), once we'll
		 * have released the endpoint and know if it no longer has
		 * attached streams, and so an idling connection
		 */
		if (!session_add_conn(s->sess, srv_conn, s->target)) {
			srv_conn->owner = NULL;
			/* Try to add the connection to the server idle list.
			 * If it fails, as the connection no longer has an
			 * owner, it will be destroy later by
			 * si_release_endpoint(), anyway
			 */
			srv_add_to_idle_list(objt_server(srv_conn->target), srv_conn);
			srv_conn = NULL;

		}
	}
	si_release_endpoint(&s->si[1]);
	if (srv_conn && srv_conn->owner == s->sess) {
		if (session_check_idle_conn(s->sess, srv_conn) != 0)
			srv_conn = NULL;
	}


	s->si[1].state     = s->si[1].prev_state = SI_ST_INI;
	s->si[1].err_type  = SI_ET_NONE;
	s->si[1].conn_retries = 0;  /* used for logging too */
	s->si[1].exp       = TICK_ETERNITY;
	s->si[1].flags    &= SI_FL_ISBACK | SI_FL_DONT_WAKE; /* we're in the context of process_stream */
	s->req.flags &= ~(CF_SHUTW|CF_SHUTW_NOW|CF_AUTO_CONNECT|CF_WRITE_ERROR|CF_STREAMER|CF_STREAMER_FAST|CF_NEVER_WAIT|CF_WAKE_CONNECT|CF_WROTE_DATA);
	s->res.flags &= ~(CF_SHUTR|CF_SHUTR_NOW|CF_READ_ATTACHED|CF_READ_ERROR|CF_READ_NOEXP|CF_STREAMER|CF_STREAMER_FAST|CF_WRITE_PARTIAL|CF_NEVER_WAIT|CF_WROTE_DATA);
	s->flags &= ~(SF_DIRECT|SF_ASSIGNED|SF_ADDR_SET|SF_BE_ASSIGNED|SF_FORCE_PRST|SF_IGNORE_PRST);
	s->flags &= ~(SF_CURR_SESS|SF_REDIRECTABLE|SF_SRV_REUSED);
	s->flags &= ~(SF_ERR_MASK|SF_FINST_MASK|SF_REDISP);

	hlua_ctx_destroy(s->hlua);
	s->hlua = NULL;

	s->txn->meth = 0;
	http_reset_txn(s);
	s->txn->flags |= TX_NOT_FIRST | TX_WAIT_NEXT_RQ;

	if (prev_status == 401 || prev_status == 407) {
		/* In HTTP keep-alive mode, if we receive a 401, we still have
		 * a chance of being able to send the visitor again to the same
		 * server over the same connection. This is required by some
		 * broken protocols such as NTLM, and anyway whenever there is
		 * an opportunity for sending the challenge to the proper place,
		 * it's better to do it (at least it helps with debugging), at
		 * least for non-deterministic load balancing algorithms.
		 */
		s->txn->flags |= TX_PREFER_LAST;
	}

	/* Never ever allow to reuse a connection from a non-reuse backend */
	if (srv_conn && (be->options & PR_O_REUSE_MASK) == PR_O_REUSE_NEVR)
		srv_conn->flags |= CO_FL_PRIVATE;

	if (fe->options2 & PR_O2_INDEPSTR)
		s->si[1].flags |= SI_FL_INDEP_STR;

	if (fe->options2 & PR_O2_NODELAY) {
		s->req.flags |= CF_NEVER_WAIT;
		s->res.flags |= CF_NEVER_WAIT;
	}

	/* we're removing the analysers, we MUST re-enable events detection.
	 * We don't enable close on the response channel since it's either
	 * already closed, or in keep-alive with an idle connection handler.
	 */
	channel_auto_read(&s->req);
	channel_auto_close(&s->req);
	channel_auto_read(&s->res);

	/* we're in keep-alive with an idle connection, monitor it if not already done */
	if (srv_conn && LIST_ISEMPTY(&srv_conn->list)) {
		srv = objt_server(srv_conn->target);
		if (srv) {
			if (srv_conn->flags & CO_FL_PRIVATE)
				LIST_ADD(&srv->priv_conns[tid], &srv_conn->list);
			else if (prev_flags & TX_NOT_FIRST)
				/* note: we check the request, not the connection, but
				 * this is valid for strategies SAFE and AGGR, and in
				 * case of ALWS, we don't care anyway.
				 */
				LIST_ADD(&srv->safe_conns[tid], &srv_conn->list);
			else
				LIST_ADD(&srv->idle_conns[tid], &srv_conn->list);
		}
	}
	s->req.analysers = strm_li(s) ? strm_li(s)->analysers : 0;
	s->res.analysers = 0;
}


/* This function updates the request state machine according to the response
 * state machine and buffer flags. It returns 1 if it changes anything (flag
 * or state), otherwise zero. It ignores any state before HTTP_MSG_DONE, as
 * it is only used to find when a request/response couple is complete. Both
 * this function and its equivalent should loop until both return zero. It
 * can set its own state to DONE, CLOSING, CLOSED, TUNNEL, ERROR.
 */
int http_sync_req_state(struct stream *s)
{
	struct channel *chn = &s->req;
	struct http_txn *txn = s->txn;
	unsigned int old_flags = chn->flags;
	unsigned int old_state = txn->req.msg_state;

	if (unlikely(txn->req.msg_state < HTTP_MSG_DONE))
		return 0;

	if (txn->req.msg_state == HTTP_MSG_DONE) {
		/* No need to read anymore, the request was completely parsed.
		 * We can shut the read side unless we want to abort_on_close,
		 * or we have a POST request. The issue with POST requests is
		 * that some browsers still send a CRLF after the request, and
		 * this CRLF must be read so that it does not remain in the kernel
		 * buffers, otherwise a close could cause an RST on some systems
		 * (eg: Linux).
		 * Note that if we're using keep-alive on the client side, we'd
		 * rather poll now and keep the polling enabled for the whole
		 * stream's life than enabling/disabling it between each
		 * response and next request.
		 */
		if (((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_SCL) &&
		    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) &&
		    (!(s->be->options & PR_O_ABRT_CLOSE) ||
		     (s->si[0].flags & SI_FL_CLEAN_ABRT)) &&
		    txn->meth != HTTP_METH_POST)
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

		if (txn->rsp.msg_state == HTTP_MSG_ERROR)
			goto wait_other_side;

		if (txn->rsp.msg_state < HTTP_MSG_DONE) {
			/* The server has not finished to respond, so we
			 * don't want to move in order not to upset it.
			 */
			goto wait_other_side;
		}

		/* When we get here, it means that both the request and the
		 * response have finished receiving. Depending on the connection
		 * mode, we'll have to wait for the last bytes to leave in either
		 * direction, and sometimes for a close to be effective.
		 */

		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) {
			/* Server-close mode : queue a connection close to the server */
			if (!(chn->flags & (CF_SHUTW|CF_SHUTW_NOW)))
				channel_shutw_now(chn);
		}
		else if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_CLO) {
			/* Option forceclose is set, or either side wants to close,
			 * let's enforce it now that we're not expecting any new
			 * data to come. The caller knows the stream is complete
			 * once both states are CLOSED.
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
		else {
			/* The last possible modes are keep-alive and tunnel. Tunnel mode
			 * will not have any analyser so it needs to poll for reads.
			 */
			if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_TUN) {
				channel_auto_read(chn);
				txn->req.msg_state = HTTP_MSG_TUNNEL;
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
			txn->req.err_state = txn->req.msg_state;
			txn->req.msg_state = HTTP_MSG_ERROR;
		}
		goto wait_other_side;
	}

	if (txn->req.msg_state == HTTP_MSG_CLOSED) {
	http_msg_closed:
		/* if we don't know whether the server will close, we need to hard close */
		if (txn->rsp.flags & HTTP_MSGF_XFER_LEN)
			s->si[1].flags |= SI_FL_NOLINGER;  /* we want to close ASAP */

		/* see above in MSG_DONE why we only do this in these states */
		if (((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_SCL) &&
		    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_KAL) &&
		    (!(s->be->options & PR_O_ABRT_CLOSE) ||
		     (s->si[0].flags & SI_FL_CLEAN_ABRT)))
			channel_dont_read(chn);
		goto wait_other_side;
	}

 check_channel_flags:
	/* Here, we are in HTTP_MSG_DONE or HTTP_MSG_TUNNEL */
	if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
		/* if we've just closed an output, let's switch */
		txn->req.msg_state = HTTP_MSG_CLOSING;
		goto http_msg_closing;
	}


 wait_other_side:
	return txn->req.msg_state != old_state || chn->flags != old_flags;
}


/* This function updates the response state machine according to the request
 * state machine and buffer flags. It returns 1 if it changes anything (flag
 * or state), otherwise zero. It ignores any state before HTTP_MSG_DONE, as
 * it is only used to find when a request/response couple is complete. Both
 * this function and its equivalent should loop until both return zero. It
 * can set its own state to DONE, CLOSING, CLOSED, TUNNEL, ERROR.
 */
int http_sync_res_state(struct stream *s)
{
	struct channel *chn = &s->res;
	struct http_txn *txn = s->txn;
	unsigned int old_flags = chn->flags;
	unsigned int old_state = txn->rsp.msg_state;

	if (unlikely(txn->rsp.msg_state < HTTP_MSG_DONE))
		return 0;

	if (txn->rsp.msg_state == HTTP_MSG_DONE) {
		/* In theory, we don't need to read anymore, but we must
		 * still monitor the server connection for a possible close
		 * while the request is being uploaded, so we don't disable
		 * reading.
		 */
		/* channel_dont_read(chn); */

		if (txn->req.msg_state == HTTP_MSG_ERROR)
			goto wait_other_side;

		if (txn->req.msg_state < HTTP_MSG_DONE) {
			/* The client seems to still be sending data, probably
			 * because we got an error response during an upload.
			 * We have the choice of either breaking the connection
			 * or letting it pass through. Let's do the later.
			 */
			goto wait_other_side;
		}

		/* When we get here, it means that both the request and the
		 * response have finished receiving. Depending on the connection
		 * mode, we'll have to wait for the last bytes to leave in either
		 * direction, and sometimes for a close to be effective.
		 */

		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) {
			/* Server-close mode : shut read and wait for the request
			 * side to close its output buffer. The caller will detect
			 * when we're in DONE and the other is in CLOSED and will
			 * catch that for the final cleanup.
			 */
			if (!(chn->flags & (CF_SHUTR|CF_SHUTR_NOW)))
				channel_shutr_now(chn);
		}
		else if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_CLO) {
			/* Option forceclose is set, or either side wants to close,
			 * let's enforce it now that we're not expecting any new
			 * data to come. The caller knows the stream is complete
			 * once both states are CLOSED.
			 */
			if (!(chn->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
				channel_shutr_now(chn);
				channel_shutw_now(chn);
			}
		}
		else {
			/* The last possible modes are keep-alive and tunnel. Tunnel will
			 * need to forward remaining data. Keep-alive will need to monitor
			 * for connection closing.
			 */
			channel_auto_read(chn);
			chn->flags |= CF_NEVER_WAIT;
			if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_TUN)
				txn->rsp.msg_state = HTTP_MSG_TUNNEL;
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
			txn->rsp.err_state = txn->rsp.msg_state;
			txn->rsp.msg_state = HTTP_MSG_ERROR;
			HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);
		}
		goto wait_other_side;
	}

	if (txn->rsp.msg_state == HTTP_MSG_CLOSED) {
	http_msg_closed:
		/* drop any pending data */
		channel_truncate(chn);
		channel_auto_close(chn);
		channel_auto_read(chn);
		goto wait_other_side;
	}

 check_channel_flags:
	/* Here, we are in HTTP_MSG_DONE or HTTP_MSG_TUNNEL */
	if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
		/* if we've just closed an output, let's switch */
		txn->rsp.msg_state = HTTP_MSG_CLOSING;
		goto http_msg_closing;
	}

 wait_other_side:
	/* We force the response to leave immediately if we're waiting for the
	 * other side, since there is no pending shutdown to push it out.
	 */
	if (!channel_is_empty(chn))
		chn->flags |= CF_SEND_DONTWAIT;
	return txn->rsp.msg_state != old_state || chn->flags != old_flags;
}


/* Resync the request and response state machines. */
void http_resync_states(struct stream *s)
{
	struct http_txn *txn = s->txn;
#ifdef DEBUG_FULL
	int old_req_state = txn->req.msg_state;
	int old_res_state = txn->rsp.msg_state;
#endif

	http_sync_req_state(s);
	while (1) {
		if (!http_sync_res_state(s))
			break;
		if (!http_sync_req_state(s))
			break;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p old=%s,%s cur=%s,%s "
		"req->analysers=0x%08x res->analysers=0x%08x\n",
		now_ms, __FUNCTION__, s,
		h1_msg_state_str(old_req_state), h1_msg_state_str(old_res_state),
		h1_msg_state_str(txn->req.msg_state), h1_msg_state_str(txn->rsp.msg_state),
		s->req.analysers, s->res.analysers);


	/* OK, both state machines agree on a compatible state.
	 * There are a few cases we're interested in :
	 *  - HTTP_MSG_CLOSED on both sides means we've reached the end in both
	 *    directions, so let's simply disable both analysers.
	 *  - HTTP_MSG_CLOSED on the response only or HTTP_MSG_ERROR on either
	 *    means we must abort the request.
	 *  - HTTP_MSG_TUNNEL on either means we have to disable analyser on
	 *    corresponding channel.
	 *  - HTTP_MSG_DONE or HTTP_MSG_CLOSED on the request and HTTP_MSG_DONE
	 *    on the response with server-close mode means we've completed one
	 *    request and we must re-initialize the server connection.
	 */
	if (txn->req.msg_state == HTTP_MSG_CLOSED &&
	    txn->rsp.msg_state == HTTP_MSG_CLOSED) {
		s->req.analysers &= AN_REQ_FLT_END;
		channel_auto_close(&s->req);
		channel_auto_read(&s->req);
		s->res.analysers &= AN_RES_FLT_END;
		channel_auto_close(&s->res);
		channel_auto_read(&s->res);
	}
	else if (txn->rsp.msg_state == HTTP_MSG_CLOSED ||
		 txn->rsp.msg_state == HTTP_MSG_ERROR  ||
		 txn->req.msg_state == HTTP_MSG_ERROR) {
		s->res.analysers &= AN_RES_FLT_END;
		channel_auto_close(&s->res);
		channel_auto_read(&s->res);
		s->req.analysers &= AN_REQ_FLT_END;
		channel_abort(&s->req);
		channel_auto_close(&s->req);
		channel_auto_read(&s->req);
		channel_truncate(&s->req);
	}
	else if (txn->req.msg_state == HTTP_MSG_TUNNEL ||
		 txn->rsp.msg_state == HTTP_MSG_TUNNEL) {
		if (txn->req.msg_state == HTTP_MSG_TUNNEL) {
			s->req.analysers &= AN_REQ_FLT_END;
			if (HAS_REQ_DATA_FILTERS(s))
				s->req.analysers |= AN_REQ_FLT_XFER_DATA;
		}
		if (txn->rsp.msg_state == HTTP_MSG_TUNNEL) {
			s->res.analysers &= AN_RES_FLT_END;
			if (HAS_RSP_DATA_FILTERS(s))
				s->res.analysers |= AN_RES_FLT_XFER_DATA;
		}
		channel_auto_close(&s->req);
		channel_auto_read(&s->req);
		channel_auto_close(&s->res);
		channel_auto_read(&s->res);
	}
	else if ((txn->req.msg_state == HTTP_MSG_DONE ||
		  txn->req.msg_state == HTTP_MSG_CLOSED) &&
		 txn->rsp.msg_state == HTTP_MSG_DONE &&
		 ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL ||
		  (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL)) {
		/* server-close/keep-alive: terminate this transaction,
		 * possibly killing the server connection and reinitialize
		 * a fresh-new transaction, but only once we're sure there's
		 * enough room in the request and response buffer to process
		 * another request. They must not hold any pending output data
		 * and the response buffer must realigned
		 * (realign is done is http_end_txn_clean_session).
		 */
		if (co_data(&s->req))
			s->req.flags |= CF_WAKE_WRITE;
		else if (co_data(&s->res))
			s->res.flags |= CF_WAKE_WRITE;
		else {
			s->req.analysers = AN_REQ_FLT_END;
			s->res.analysers = AN_RES_FLT_END;
			txn->flags |= TX_WAIT_CLEANUP;
		}
	}
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
	struct http_msg *msg = &s->txn->req;
	int ret;

	if (IS_HTX_STRM(s))
		return htx_request_forward_body(s, req, an_bit);

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))
		return 0;

	if ((req->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((req->flags & CF_SHUTW) && (req->to_forward || co_data(req)))) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 */
		msg->err_state = msg->msg_state;
		msg->msg_state = HTTP_MSG_ERROR;
		http_resync_states(s);
		return 1;
	}

	/* Note that we don't have to send 100-continue back because we don't
	 * need the data to complete our job, and it's up to the server to
	 * decide whether to return 100, 417 or anything else in return of
	 * an "Expect: 100-continue" header.
	 */
	if (msg->msg_state == HTTP_MSG_BODY) {
		msg->msg_state = ((msg->flags & HTTP_MSGF_TE_CHNK)
				  ? HTTP_MSG_CHUNK_SIZE
				  : HTTP_MSG_DATA);

		/* TODO/filters: when http-buffer-request option is set or if a
		 * rule on url_param exists, the first chunk size could be
		 * already parsed. In that case, msg->next is after the chunk
		 * size (including the CRLF after the size). So this case should
		 * be handled to */
	}

	/* Some post-connect processing might want us to refrain from starting to
	 * forward data. Currently, the only reason for this is "balance url_param"
	 * whichs need to parse/process the request after we've enabled forwarding.
	 */
	if (unlikely(msg->flags & HTTP_MSGF_WAIT_CONN)) {
		if (!(s->res.flags & CF_READ_ATTACHED)) {
			channel_auto_connect(req);
			req->flags |= CF_WAKE_CONNECT;
			channel_dont_close(req); /* don't fail on early shutr */
			goto waiting;
		}
		msg->flags &= ~HTTP_MSGF_WAIT_CONN;
	}

	/* in most states, we should abort in case of early close */
	channel_auto_close(req);

	if (req->to_forward) {
		/* We can't process the buffer's contents yet */
		req->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	if (msg->msg_state < HTTP_MSG_DONE) {
		ret = ((msg->flags & HTTP_MSGF_TE_CHNK)
		       ? http_msg_forward_chunked_body(s, msg)
		       : http_msg_forward_body(s, msg));
		if (!ret)
			goto missing_data_or_waiting;
		if (ret < 0)
			goto return_bad_req;
	}

	/* other states, DONE...TUNNEL */
	/* we don't want to forward closes on DONE except in tunnel mode. */
	if ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN)
		channel_dont_close(req);

	http_resync_states(s);
	if (!(req->analysers & an_bit)) {
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (req->flags & CF_SHUTW) {
				/* request errors are most likely due to the
				 * server aborting the transfer. */
				goto aborted_xfer;
			}
			if (msg->err_pos >= 0)
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, s->be);
			goto return_bad_req;
		}
		return 1;
	}

	/* If "option abortonclose" is set on the backend, we want to monitor
	 * the client's connection and forward any shutdown notification to the
	 * server, which will decide whether to close or to go on processing the
	 * request. We only do that in tunnel mode, and not in other modes since
	 * it can be abused to exhaust source ports. */
	if ((s->be->options & PR_O_ABRT_CLOSE) && !(s->si[0].flags & SI_FL_CLEAN_ABRT)) {
		channel_auto_read(req);
		if ((req->flags & (CF_SHUTR|CF_READ_NULL)) &&
		    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN))
			s->si[1].flags |= SI_FL_NOLINGER;
		channel_auto_close(req);
	}
	else if (s->txn->meth == HTTP_METH_POST) {
		/* POST requests may require to read extra CRLF sent by broken
		 * browsers and which could cause an RST to be sent upon close
		 * on some systems (eg: Linux). */
		channel_auto_read(req);
	}
	return 0;

 missing_data_or_waiting:
	/* stop waiting for data if the input is closed before the end */
	if (msg->msg_state < HTTP_MSG_ENDING && req->flags & CF_SHUTR) {
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_CLICL;
		if (!(s->flags & SF_FINST_MASK)) {
			if (txn->rsp.msg_state < HTTP_MSG_ERROR)
				s->flags |= SF_FINST_H;
			else
				s->flags |= SF_FINST_D;
		}

		HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
		HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

		goto return_bad_req_stats_ok;
	}

 waiting:
	/* waiting for the last bits to leave the buffer */
	if (req->flags & CF_SHUTW)
		goto aborted_xfer;

	/* When TE: chunked is used, we need to get there again to parse remaining
	 * chunks even if the client has closed, so we don't want to set CF_DONTCLOSE.
	 * And when content-length is used, we never want to let the possible
	 * shutdown be forwarded to the other side, as the state machine will
	 * take care of it once the client responds. It's also important to
	 * prevent TIME_WAITs from accumulating on the backend side, and for
	 * HTTP/2 where the last frame comes with a shutdown.
	 */
	if (msg->flags & (HTTP_MSGF_TE_CHNK|HTTP_MSGF_CNT_LEN))
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

	return 0;

 return_bad_req: /* let's centralize all bad requests */
	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_bad_req_stats_ok:
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	if (txn->status) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = 400;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	req->analysers   &= AN_REQ_FLT_END;
	s->res.analysers &= AN_RES_FLT_END; /* we're in data phase, we want to abort both directions */

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK)) {
		if (txn->rsp.msg_state < HTTP_MSG_ERROR)
			s->flags |= SF_FINST_H;
		else
			s->flags |= SF_FINST_D;
	}
	return 0;

 aborted_xfer:
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	if (txn->status) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = 502;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	req->analysers   &= AN_REQ_FLT_END;
	s->res.analysers &= AN_RES_FLT_END; /* we're in data phase, we want to abort both directions */

	HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
	HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	if (!(s->flags & SF_FINST_MASK)) {
		if (txn->rsp.msg_state < HTTP_MSG_ERROR)
			s->flags |= SF_FINST_H;
		else
			s->flags |= SF_FINST_D;
	}
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
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct hdr_ctx ctx;
	struct connection *srv_conn;
	int use_close_only;
	int cur_idx;
	int n;

	srv_conn = cs_conn(objt_cs(s->si[1].end));

	if (IS_HTX_STRM(s))
		return htx_wait_for_response(s, rep, an_bit);

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		ci_data(rep),
		rep->analysers);

	/*
	 * Now parse the partial (or complete) lines.
	 * We will check the response syntax, and also join multi-line
	 * headers. An index of all the lines will be elaborated while
	 * parsing.
	 *
	 * For the parsing, we use a 28 states FSM.
	 *
	 * Here is the information we currently have :
	 *   ci_head(rep)             = beginning of response
	 *   ci_head(rep) + msg->eoh  = end of processed headers / start of current one
	 *   ci_tail(rep)             = end of input data
	 *   msg->eol                 = end of current header or line (LF or CRLF)
	 *   msg->next                = first non-visited byte
	 */

 next_one:
	/* There's a protected area at the end of the buffer for rewriting
	 * purposes. We don't want to start to parse the request if the
	 * protected area is affected, because we may have to move processed
	 * data later, which is much more complicated.
	 */
	if (c_data(rep) && msg->msg_state < HTTP_MSG_ERROR) {
		if (unlikely(!channel_is_rewritable(rep))) {
			/* some data has still not left the buffer, wake us once that's done */
			if (rep->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_WRITE_ERROR|CF_WRITE_TIMEOUT))
				goto abort_response;
			channel_dont_close(rep);
			rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
			rep->flags |= CF_WAKE_WRITE;
			return 0;
		}

		if (unlikely(ci_tail(rep) < c_ptr(rep, msg->next) ||
		             ci_tail(rep) > b_wrap(&rep->buf) - global.tune.maxrewrite))
			channel_slow_realign(rep, trash.area);

		if (likely(msg->next < ci_data(rep)))
			http_msg_analyzer(msg, &txn->hdr_idx);
	}

	/* 1: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
		     msg->msg_state >= HTTP_MSG_BODY)) {
		char *eol, *sol;

		sol = ci_head(rep);
		eol = sol + (msg->sl.st.l ? msg->sl.st.l : ci_data(rep));
		debug_hdr("srvrep", s, sol, eol);

		sol += hdr_idx_first_pos(&txn->hdr_idx);
		cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

		while (cur_idx) {
			eol = sol + txn->hdr_idx.v[cur_idx].len;
			debug_hdr("srvhdr", s, sol, eol);
			sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
			cur_idx = txn->hdr_idx.v[cur_idx].next;
		}
	}

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

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* Invalid response */
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			/* we detected a parsing error. We want to archive this response
			 * in the dedicated proxy area for later troubleshooting.
			 */
		hdr_response_bad:
			if (msg->msg_state == HTTP_MSG_ERROR || msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_HDRRSP);
			}
		abort_response:
			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_PRXCOND;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			return 0;
		}

		/* too large response does not fit in buffer. */
		else if (channel_full(rep, global.tune.maxrewrite)) {
			if (msg->err_pos < 0)
				msg->err_pos = ci_data(rep);
			goto hdr_response_bad;
		}

		/* read error */
		else if (rep->flags & CF_READ_ERROR) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_READ_ERROR);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;

			/* Check to see if the server refused the early data.
			 * If so, just send a 425
			 */
			if (objt_cs(s->si[1].end)) {
				struct connection *conn = objt_cs(s->si[1].end)->conn;

				if (conn->err_code == CO_ER_SSL_EARLY_FAILED)
					txn->status = 425;
			}

			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* read timeout : return a 504 to the client. */
		else if (rep->flags & CF_READ_TIMEOUT) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_READ_TIMEOUT);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 504;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVTO;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* client abort with an abortonclose */
		else if ((rep->flags & CF_SHUTR) && ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))) {
			HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
			HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

			rep->analysers &= AN_RES_FLT_END;
			channel_auto_close(rep);

			txn->status = 400;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			return 0;
		}

		/* close from server, capture the response if the server has started to respond */
		else if (rep->flags & CF_SHUTR) {
			if (msg->msg_state >= HTTP_MSG_RPVER || msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_BROKEN_PIPE);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* write error to client (we don't send any message then) */
		else if (rep->flags & CF_WRITE_ERROR) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			rep->analysers &= AN_RES_FLT_END;
			channel_auto_close(rep);

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			return 0;
		}

		channel_dont_close(rep);
		rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		return 0;
	}

	/* More interesting part now : we know that we have a complete
	 * response which at least looks like HTTP. We have an indicator
	 * of each header's length, so we can parse them quickly.
	 */

	if (unlikely(msg->err_pos >= 0))
		http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);

	/*
	 * 1: get the status code
	 */
	n = ci_head(rep)[msg->sl.st.c] - '0';
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
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.p.http.rsp[n], 1);

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-response.
	 */
	if (!(s->be->options2 & PR_O2_RSPBUG_OK)) {
		if (msg->sl.st.v_l != 8) {
			msg->err_pos = 0;
			goto hdr_response_bad;
		}

		if (ci_head(rep)[4] != '/' ||
		    !isdigit((unsigned char)ci_head(rep)[5]) ||
		    ci_head(rep)[6] != '.' ||
		    !isdigit((unsigned char)ci_head(rep)[7])) {
			msg->err_pos = 4;
			goto hdr_response_bad;
		}
	}

	/* check if the response is HTTP/1.1 or above */
	if ((msg->sl.st.v_l == 8) &&
	    ((ci_head(rep)[5] > '1') ||
	     ((ci_head(rep)[5] == '1') && (ci_head(rep)[7] >= '1'))))
		msg->flags |= HTTP_MSGF_VER_11;

	/* "connection" has not been parsed yet */
	txn->flags &= ~(TX_HDR_CONN_PRS|TX_HDR_CONN_CLO|TX_HDR_CONN_KAL|TX_HDR_CONN_UPG|TX_CON_CLO_SET|TX_CON_KAL_SET);

	/* transfer length unknown*/
	msg->flags &= ~HTTP_MSGF_XFER_LEN;

	txn->status = strl2ui(ci_head(rep) + msg->sl.st.c, msg->sl.st.c_l);

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
		hdr_idx_init(&txn->hdr_idx);
		msg->next -= channel_forward(rep, msg->next);
		msg->msg_state = HTTP_MSG_RPBEFORE;
		txn->status = 0;
		s->logs.t_data = -1; /* was not a response yet */
		FLT_STRM_CB(s, flt_http_reset(s, msg));
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
		http_capture_headers(ci_head(rep), &txn->hdr_idx,
				     s->res_cap, sess->fe->rsp_cap);

	/* 4: determine the transfer-length according to RFC2616 #4.4, updated
	 * by RFC7230#3.3.3 :
	 *
	 * The length of a message body is determined by one of the following
	 *   (in order of precedence):
	 *
	 *   1.  Any 2xx (Successful) response to a CONNECT request implies that
	 *       the connection will become a tunnel immediately after the empty
	 *       line that concludes the header fields.  A client MUST ignore
	 *       any Content-Length or Transfer-Encoding header fields received
	 *       in such a message. Any 101 response (Switching Protocols) is
	 *       managed in the same manner.
	 *
	 *   2.  Any response to a HEAD request and any response with a 1xx
	 *       (Informational), 204 (No Content), or 304 (Not Modified) status
	 *       code is always terminated by the first empty line after the
	 *       header fields, regardless of the header fields present in the
	 *       message, and thus cannot contain a message body.
	 *
	 *   3.  If a Transfer-Encoding header field is present and the chunked
	 *       transfer coding (Section 4.1) is the final encoding, the message
	 *       body length is determined by reading and decoding the chunked
	 *       data until the transfer coding indicates the data is complete.
	 *
	 *       If a Transfer-Encoding header field is present in a response and
	 *       the chunked transfer coding is not the final encoding, the
	 *       message body length is determined by reading the connection until
	 *       it is closed by the server.  If a Transfer-Encoding header field
	 *       is present in a request and the chunked transfer coding is not
	 *       the final encoding, the message body length cannot be determined
	 *       reliably; the server MUST respond with the 400 (Bad Request)
	 *       status code and then close the connection.
	 *
	 *       If a message is received with both a Transfer-Encoding and a
	 *       Content-Length header field, the Transfer-Encoding overrides the
	 *       Content-Length.  Such a message might indicate an attempt to
	 *       perform request smuggling (Section 9.5) or response splitting
	 *       (Section 9.4) and ought to be handled as an error.  A sender MUST
	 *       remove the received Content-Length field prior to forwarding such
	 *       a message downstream.
	 *
	 *   4.  If a message is received without Transfer-Encoding and with
	 *       either multiple Content-Length header fields having differing
	 *       field-values or a single Content-Length header field having an
	 *       invalid value, then the message framing is invalid and the
	 *       recipient MUST treat it as an unrecoverable error.  If this is a
	 *       request message, the server MUST respond with a 400 (Bad Request)
	 *       status code and then close the connection.  If this is a response
	 *       message received by a proxy, the proxy MUST close the connection
	 *       to the server, discard the received response, and send a 502 (Bad
	 *       Gateway) response to the client.  If this is a response message
	 *       received by a user agent, the user agent MUST close the
	 *       connection to the server and discard the received response.
	 *
	 *   5.  If a valid Content-Length header field is present without
	 *       Transfer-Encoding, its decimal value defines the expected message
	 *       body length in octets.  If the sender closes the connection or
	 *       the recipient times out before the indicated number of octets are
	 *       received, the recipient MUST consider the message to be
	 *       incomplete and close the connection.
	 *
	 *   6.  If this is a request message and none of the above are true, then
	 *       the message body length is zero (no message body is present).
	 *
	 *   7.  Otherwise, this is a response message without a declared message
	 *       body length, so the message body length is determined by the
	 *       number of octets received prior to the server closing the
	 *       connection.
	 */

	/* Skip parsing if no content length is possible. The response flags
	 * remain 0 as well as the chunk_len, which may or may not mirror
	 * the real header value, and we note that we know the response's length.
	 * FIXME: should we parse anyway and return an error on chunked encoding ?
	 */
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
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_TUN;
		msg->flags |= HTTP_MSGF_XFER_LEN;
		goto end;
	}

	if (txn->meth == HTTP_METH_HEAD ||
	    (txn->status >= 100 && txn->status < 200) ||
	    txn->status == 204 || txn->status == 304) {
		msg->flags |= HTTP_MSGF_XFER_LEN;
		goto skip_content_length;
	}

	use_close_only = 0;
	ctx.idx = 0;
	while (http_find_header2("Transfer-Encoding", 17, ci_head(rep), &txn->hdr_idx, &ctx)) {
		if (ctx.vlen == 7 && strncasecmp(ctx.line + ctx.val, "chunked", 7) == 0)
			msg->flags |= (HTTP_MSGF_TE_CHNK | HTTP_MSGF_XFER_LEN);
		else if (msg->flags & HTTP_MSGF_TE_CHNK) {
			/* bad transfer-encoding (chunked followed by something else) */
			use_close_only = 1;
			msg->flags &= ~(HTTP_MSGF_TE_CHNK | HTTP_MSGF_XFER_LEN);
			break;
		}
	}

	/* Chunked responses must have their content-length removed */
	ctx.idx = 0;
	if (use_close_only || (msg->flags & HTTP_MSGF_TE_CHNK)) {
		while (http_find_header2("Content-Length", 14, ci_head(rep), &txn->hdr_idx, &ctx))
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
	}
	else while (http_find_header2("Content-Length", 14, ci_head(rep), &txn->hdr_idx, &ctx)) {
		signed long long cl;

		if (!ctx.vlen) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad;
		}

		if (strl2llrc(ctx.line + ctx.val, ctx.vlen, &cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad; /* parse failure */
		}

		if (cl < 0) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad;
		}

		if ((msg->flags & HTTP_MSGF_CNT_LEN) && (msg->chunk_len != cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad; /* already specified, was different */
		}

		msg->flags |= HTTP_MSGF_CNT_LEN | HTTP_MSGF_XFER_LEN;
		msg->body_len = msg->chunk_len = cl;
	}

	/* check for NTML authentication headers in 401 (WWW-Authenticate) and
	 * 407 (Proxy-Authenticate) responses and set the connection to private
	 */
	if (srv_conn && txn->status == 401) {
	    /* check for Negotiate/NTLM WWW-Authenticate headers */
	    ctx.idx = 0;
	    while (http_find_header2("WWW-Authenticate", 16, ci_head(rep), &txn->hdr_idx, &ctx)) {
	            if ((ctx.vlen >= 9 && word_match(ctx.line + ctx.val, ctx.vlen, "Negotiate", 9)) ||
	                  (ctx.vlen >= 4 && word_match(ctx.line + ctx.val, ctx.vlen, "NTLM", 4)))
				srv_conn->flags |= CO_FL_PRIVATE;
	    }
	} else if (srv_conn && txn->status == 407) {
	    /* check for Negotiate/NTLM Proxy-Authenticate headers */
	    ctx.idx = 0;
	    while (http_find_header2("Proxy-Authenticate", 18, ci_head(rep), &txn->hdr_idx, &ctx)) {
	            if ((ctx.vlen >= 9 && word_match(ctx.line + ctx.val, ctx.vlen, "Negotiate", 9)) ||
	                  (ctx.vlen >= 4 && word_match(ctx.line + ctx.val, ctx.vlen, "NTLM", 4)))
				srv_conn->flags |= CO_FL_PRIVATE;
	    }
	}

 skip_content_length:
	/* Now we have to check if we need to modify the Connection header.
	 * This is more difficult on the response than it is on the request,
	 * because we can have two different HTTP versions and we don't know
	 * how the client will interprete a response. For instance, let's say
	 * that the client sends a keep-alive request in HTTP/1.0 and gets an
	 * HTTP/1.1 response without any header. Maybe it will bound itself to
	 * HTTP/1.0 because it only knows about it, and will consider the lack
	 * of header as a close, or maybe it knows HTTP/1.1 and can consider
	 * the lack of header as a keep-alive. Thus we will use two flags
	 * indicating how a request MAY be understood by the client. In case
	 * of multiple possibilities, we'll fix the header to be explicit. If
	 * ambiguous cases such as both close and keepalive are seen, then we
	 * will fall back to explicit close. Note that we won't take risks with
	 * HTTP/1.0 clients which may not necessarily understand keep-alive.
	 * See doc/internals/connection-header.txt for the complete matrix.
	 */
	if ((txn->status >= 200) && !(txn->flags & TX_HDR_CONN_PRS) &&
	    (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		int to_del = 0;

		/* on unknown transfer length, we must close */
		if (!(msg->flags & HTTP_MSGF_XFER_LEN))
			txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_CLO;

		/* now adjust header transformations depending on current state */
		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_CLO) {
			to_del |= 2; /* remove "keep-alive" on any response */
			if (!(msg->flags & HTTP_MSGF_VER_11))
				to_del |= 1; /* remove "close" for HTTP/1.0 responses */
		}
		else { /* SCL / KAL */
			to_del |= 1; /* remove "close" on any response */
			if (txn->req.flags & msg->flags & HTTP_MSGF_VER_11)
				to_del |= 2; /* remove "keep-alive" on pure 1.1 responses */
		}

		/* Parse and remove some headers from the connection header */
		http_parse_connection_header(txn, msg, to_del);

		/* Some keep-alive responses are converted to Server-close if
		 * the server wants to close.
		 */
		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL) {
			if ((txn->flags & TX_HDR_CONN_CLO) ||
			    (!(txn->flags & TX_HDR_CONN_KAL) && !(msg->flags & HTTP_MSGF_VER_11)))
				txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_SCL;
		}
	}

 end:
	/* we want to have the response time before we start processing it */
	s->logs.t_data = tv_ms_elapsed(&s->logs.tv_accept, &now);

	/* end of job, return OK */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	channel_auto_close(rep);
	return 1;

 abort_keep_alive:
	/* A keep-alive request to the server failed on a network error.
	 * The client is required to retry. We need to close without returning
	 * any other information so that the client retries.
	 */
	txn->status = 0;
	rep->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END;
	channel_auto_close(rep);
	s->logs.logwait = 0;
	s->logs.level = 0;
	s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
	channel_truncate(rep);
	http_reply_and_close(s, txn->status, NULL);
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
	struct proxy *cur_proxy;
	struct cond_wordlist *wl;
	enum rule_result ret = HTTP_RULE_RES_CONT;

	if (IS_HTX_STRM(s))
		return htx_process_res_common(s, rep, an_bit, px);

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		ci_data(rep),
		rep->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))	/* we need more data */
		return 0;

	/* The stats applet needs to adjust the Connection header but we don't
	 * apply any filter there.
	 */
	if (unlikely(objt_applet(s->target) == &http_stats_applet)) {
		rep->analysers &= ~an_bit;
		rep->analyse_exp = TICK_ETERNITY;
		goto skip_filters;
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
		struct proxy *rule_set = cur_proxy;

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
			return 0;
		}

		/* try headers filters */
		if (rule_set->rsp_exp != NULL) {
			if (apply_filters_to_response(s, rep, rule_set) < 0) {
			return_bad_resp:
				if (objt_server(s->target)) {
					HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);
					health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_RSP);
				}
				HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			return_srv_prx_502:
				rep->analysers &= AN_RES_FLT_END;
				txn->status = 502;
				s->logs.t_data = -1; /* was not a valid response */
				s->si[1].flags |= SI_FL_NOLINGER;
				channel_truncate(rep);
				http_reply_and_close(s, txn->status, http_error_message(s));
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_PRXCOND;
				if (!(s->flags & SF_FINST_MASK))
					s->flags |= SF_FINST_H;
				return 0;
			}
		}

		/* has the response been denied ? */
		if (txn->flags & TX_SVDENY) {
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_secu, 1);

			HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);

			goto return_srv_prx_502;
		}

		/* add response headers from the rule sets in the same order */
		list_for_each_entry(wl, &rule_set->rsp_add, list) {
			if (txn->status < 200 && txn->status != 101)
				break;
			if (wl->cond) {
				int ret = acl_exec_cond(wl->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
				ret = acl_pass(ret);
				if (((struct acl_cond *)wl->cond)->pol == ACL_COND_UNLESS)
					ret = !ret;
				if (!ret)
					continue;
			}
			if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx, wl->s, strlen(wl->s)) < 0))
				goto return_bad_resp;
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
		goto skip_header_mangling;

	/*
	 * Now check for a server cookie.
	 */
	if (s->be->cookie_name || sess->fe->capture_name || (s->be->options & PR_O_CHK_CACHE))
		manage_server_side_cookies(s, rep);

	/*
	 * Check for cache-control or pragma headers if required.
	 */
	if ((s->be->options & PR_O_CHK_CACHE) || (s->be->ck_opts & PR_CK_NOC))
		check_response_for_cacheability(s, rep);

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
				     "Set-Cookie: %s=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/",
				     s->be->cookie_name);
		}
		else {
			chunk_printf(&trash, "Set-Cookie: %s=%s", s->be->cookie_name, objt_server(s->target)->cookie);

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

		if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx, trash.area, trash.data) < 0))
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

			if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx,
			                                   "Cache-control: private", 22) < 0))
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
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_secu, 1);

		HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
		HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
		if (sess->listener->counters)
			HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);

		ha_alert("Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		send_log(s->be, LOG_ALERT,
			 "Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		goto return_srv_prx_502;
	}

 skip_filters:
	/*
	 * Adjust "Connection: close" or "Connection: keep-alive" if needed.
	 * If an "Upgrade" token is found, the header is left untouched in order
	 * not to have to deal with some client bugs : some of them fail an upgrade
	 * if anything but "Upgrade" is present in the Connection header. We don't
	 * want to touch any 101 response either since it's switching to another
	 * protocol.
	 */
	if ((txn->status != 101) && !(txn->flags & TX_HDR_CONN_UPG) &&
	    (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		unsigned int want_flags = 0;

		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
		    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) {
			/* we want a keep-alive response here. Keep-alive header
			 * required if either side is not 1.1.
			 */
			if (!(txn->req.flags & msg->flags & HTTP_MSGF_VER_11))
				want_flags |= TX_CON_KAL_SET;
		}
		else { /* CLO */
			/* we want a close response here. Close header required if
			 * the server is 1.1, regardless of the client.
			 */
			if (msg->flags & HTTP_MSGF_VER_11)
				want_flags |= TX_CON_CLO_SET;
		}

		if (want_flags != (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
			http_change_connection_header(txn, msg, want_flags);
	}

 skip_header_mangling:
	/* Always enter in the body analyzer */
	rep->analysers &= ~AN_RES_FLT_XFER_DATA;
	rep->analysers |= AN_RES_HTTP_XFER_BODY;

	/* if the user wants to log as soon as possible, without counting
	 * bytes from the server, then this is the right moment. We have
	 * to temporarily assign bytes_out to log what we currently have.
	 */
	if (!LIST_ISEMPTY(&sess->fe->logformat) && !(s->logs.logwait & LW_BYTES)) {
		s->logs.t_close = s->logs.t_data; /* to get a valid end date */
		s->logs.bytes_out = txn->rsp.eoh;
		s->do_log(s);
		s->logs.bytes_out = 0;
	}
	return 1;
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
	int ret;

	if (IS_HTX_STRM(s))
		return htx_response_forward_body(s, res, an_bit);

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		res,
		res->rex, res->wex,
		res->flags,
		ci_data(res),
		res->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))
		return 0;

	if ((res->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((res->flags & CF_SHUTW) && (res->to_forward || co_data(res))) ||
	     !s->req.analysers) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 */
		msg->err_state = msg->msg_state;
		msg->msg_state = HTTP_MSG_ERROR;
		http_resync_states(s);
		return 1;
	}

	/* in most states, we should abort in case of early close */
	channel_auto_close(res);

	if (msg->msg_state == HTTP_MSG_BODY) {
		msg->msg_state = ((msg->flags & HTTP_MSGF_TE_CHNK)
				  ? HTTP_MSG_CHUNK_SIZE
				  : HTTP_MSG_DATA);
	}

	if (res->to_forward) {
                /* We can't process the buffer's contents yet */
		res->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	if (msg->msg_state < HTTP_MSG_DONE) {
		ret = ((msg->flags & HTTP_MSGF_TE_CHNK)
		       ? http_msg_forward_chunked_body(s, msg)
		       : http_msg_forward_body(s, msg));
		if (!ret)
			goto missing_data_or_waiting;
		if (ret < 0)
			goto return_bad_res;
	}

	/* other states, DONE...TUNNEL */
	/* for keep-alive we don't want to forward closes on DONE */
	if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL)
		channel_dont_close(res);

	http_resync_states(s);
	if (!(res->analysers & an_bit)) {
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (res->flags & CF_SHUTW) {
				/* response errors are most likely due to the
				 * client aborting the transfer. */
				goto aborted_xfer;
			}
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, strm_fe(s));
			goto return_bad_res;
		}
		return 1;
	}
	return 0;

  missing_data_or_waiting:
	if (res->flags & CF_SHUTW)
		goto aborted_xfer;

	/* stop waiting for data if the input is closed before the end. If the
	 * client side was already closed, it means that the client has aborted,
	 * so we don't want to count this as a server abort. Otherwise it's a
	 * server abort.
	 */
	if (msg->msg_state < HTTP_MSG_ENDING && res->flags & CF_SHUTR) {
		if ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))
			goto aborted_xfer;
		/* If we have some pending data, we continue the processing */
		if (!ci_data(res)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);
			goto return_bad_res_stats_ok;
		}
	}

	/* we need to obey the req analyser, so if it leaves, we must too */
	if (!s->req.analysers)
		goto return_bad_res;

	/* When TE: chunked is used, we need to get there again to parse
	 * remaining chunks even if the server has closed, so we don't want to
	 * set CF_DONTCLOSE. Similarly, if keep-alive is set on the client side
	 * or if there are filters registered on the stream, we don't want to
	 * forward a close
	 */
	if ((msg->flags & HTTP_MSGF_TE_CHNK) ||
	    HAS_DATA_FILTERS(s, res) ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL)
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
	return 0;

 return_bad_res: /* let's centralize all bad responses */
	HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);

 return_bad_res_stats_ok:
	txn->rsp.err_state = txn->rsp.msg_state;
	txn->rsp.msg_state = HTTP_MSG_ERROR;
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	res->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END; /* we're in data phase, we want to abort both directions */
	if (objt_server(s->target))
		health_adjust(__objt_server(s->target), HANA_STATUS_HTTP_HDRRSP);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	return 0;

 aborted_xfer:
	txn->rsp.err_state = txn->rsp.msg_state;
	txn->rsp.msg_state = HTTP_MSG_ERROR;
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	res->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END; /* we're in data phase, we want to abort both directions */

	HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
	HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	return 0;
}


int http_msg_forward_body(struct stream *s, struct http_msg *msg)
{
	struct channel *chn = msg->chn;
	int ret;

	/* Here we have the guarantee to be in HTTP_MSG_DATA or HTTP_MSG_ENDING state */

	if (msg->msg_state == HTTP_MSG_ENDING)
		goto ending;

	/* Neither content-length, nor transfer-encoding was found, so we must
	 * read the body until the server connection is closed. In that case, we
	 * eat data as they come. Of course, this happens for response only. */
	if (!(msg->flags & HTTP_MSGF_XFER_LEN)) {
		unsigned long long len = ci_data(chn) - msg->next;
		msg->chunk_len += len;
		msg->body_len  += len;
	}
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_data(s, msg),
			       /* default_ret */ MIN(msg->chunk_len, ci_data(chn) - msg->next),
			       /* on_error    */ goto error);
	msg->next     += ret;
	msg->chunk_len -= ret;
	if (msg->chunk_len) {
		/* input empty or output full */
		if (ci_data(chn) > msg->next)
			chn->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	/* This check can only be true for a response. HTTP_MSGF_XFER_LEN is
	 * always set for a request. */
	if (!(msg->flags & HTTP_MSGF_XFER_LEN)) {
		/* The server still sending data that should be filtered */
		if (!(chn->flags & CF_SHUTR) && HAS_DATA_FILTERS(s, chn))
			goto missing_data_or_waiting;
		msg->msg_state = HTTP_MSG_TUNNEL;
		goto ending;
	}

	msg->msg_state = HTTP_MSG_ENDING;

  ending:
	/* we may have some pending data starting at res->buf.p such as a last
	 * chunk of data or trailers. */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			       /* default_ret */ msg->next,
			       /* on_error    */ goto error);
	c_adv(chn, ret);
	msg->next -= ret;
	if (unlikely(!(chn->flags & CF_WROTE_DATA) || msg->sov > 0))
		msg->sov -= ret;
	if (msg->next)
		goto waiting;

	FLT_STRM_DATA_CB(s, chn, flt_http_end(s, msg),
			 /* default_ret */ 1,
			 /* on_error    */ goto error,
			 /* on_wait     */ goto waiting);
	if (msg->msg_state == HTTP_MSG_ENDING)
		msg->msg_state = HTTP_MSG_DONE;
	return 1;

  missing_data_or_waiting:
	/* we may have some pending data starting at chn->buf.p */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			       /* default_ret */ msg->next,
			       /* on_error    */ goto error);
	c_adv(chn, ret);
	msg->next -= ret;
	if (!(chn->flags & CF_WROTE_DATA) || msg->sov > 0)
		msg->sov -= ret;
	if (!HAS_DATA_FILTERS(s, chn))
		msg->chunk_len -= channel_forward(chn, msg->chunk_len);
  waiting:
	return 0;
  error:
	return -1;
}

int http_msg_forward_chunked_body(struct stream *s, struct http_msg *msg)
{
	struct channel *chn = msg->chn;
	unsigned int chunk;
	int ret;

	/* Here we have the guarantee to be in one of the following state:
	 * HTTP_MSG_DATA, HTTP_MSG_CHUNK_SIZE, HTTP_MSG_CHUNK_CRLF,
	 * HTTP_MSG_TRAILERS or HTTP_MSG_ENDING. */

	if (msg->msg_state == HTTP_MSG_ENDING)
		goto ending;

	/* Don't parse chunks if there is no input data */
	if (!ci_data(chn))
		goto waiting;

  switch_states:
	switch (msg->msg_state) {
		case HTTP_MSG_DATA:
			ret = FLT_STRM_DATA_CB(s, chn, flt_http_data(s, msg),
					       /* default_ret */ MIN(msg->chunk_len, ci_data(chn) - msg->next),
					       /* on_error    */ goto error);
			msg->next      += ret;
			msg->chunk_len -= ret;
			if (msg->chunk_len) {
				/* input empty or output full */
				if (ci_data(chn) > msg->next)
					chn->flags |= CF_WAKE_WRITE;
				goto missing_data_or_waiting;
			}

			/* nothing left to forward for this chunk*/
			msg->msg_state = HTTP_MSG_CHUNK_CRLF;
			/* fall through for HTTP_MSG_CHUNK_CRLF */

		case HTTP_MSG_CHUNK_CRLF:
			/* we want the CRLF after the data */
			ret = h1_skip_chunk_crlf(&chn->buf, co_data(chn) + msg->next, c_data(chn));
			if (ret == 0)
				goto missing_data_or_waiting;
			if (ret < 0) {
				msg->err_pos = ci_data(chn) + ret;
				if (msg->err_pos < 0)
					msg->err_pos += chn->buf.size;
				goto chunk_parsing_error;
			}
			msg->next += ret;
			msg->msg_state = HTTP_MSG_CHUNK_SIZE;
			/* fall through for HTTP_MSG_CHUNK_SIZE */

		case HTTP_MSG_CHUNK_SIZE:
			/* read the chunk size and assign it to ->chunk_len,
			 * then set ->next to point to the body and switch to
			 * DATA or TRAILERS state.
			 */
			ret = h1_parse_chunk_size(&chn->buf, co_data(chn) + msg->next, c_data(chn), &chunk);
			if (ret == 0)
				goto missing_data_or_waiting;
			if (ret < 0) {
				msg->err_pos = ci_data(chn) + ret;
				if (msg->err_pos < 0)
					msg->err_pos += chn->buf.size;
				goto chunk_parsing_error;
			}

			msg->sol = ret;
			msg->next += ret;
			msg->chunk_len = chunk;
			msg->body_len += chunk;

			if (msg->chunk_len) {
				msg->msg_state = HTTP_MSG_DATA;
				goto switch_states;
			}
			msg->msg_state = HTTP_MSG_TRAILERS;
			/* fall through for HTTP_MSG_TRAILERS */

		case HTTP_MSG_TRAILERS:
			ret = http_forward_trailers(msg);
			if (ret < 0)
				goto chunk_parsing_error;
			FLT_STRM_DATA_CB(s, chn, flt_http_chunk_trailers(s, msg),
					 /* default_ret */ 1,
					 /* on_error    */ goto error);
			msg->next += msg->sol;
			if (!ret)
				goto missing_data_or_waiting;
			break;

		default:
			/* This should no happen in this function */
			goto error;
	}

	msg->msg_state = HTTP_MSG_ENDING;
  ending:
	/* we may have some pending data starting at res->buf.p such as a last
	 * chunk of data or trailers. */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			  /* default_ret */ msg->next,
			  /* on_error    */ goto error);
	c_adv(chn, ret);
	msg->next -= ret;
	if (unlikely(!(chn->flags & CF_WROTE_DATA) || msg->sov > 0))
		msg->sov -= ret;
	if (msg->next)
		goto waiting;

	FLT_STRM_DATA_CB(s, chn, flt_http_end(s, msg),
		    /* default_ret */ 1,
		    /* on_error    */ goto error,
		    /* on_wait     */ goto waiting);
	msg->msg_state = HTTP_MSG_DONE;
	return 1;

  missing_data_or_waiting:
	/* we may have some pending data starting at chn->buf.p */
	ret = FLT_STRM_DATA_CB(s, chn, flt_http_forward_data(s, msg, msg->next),
			  /* default_ret */ msg->next,
			  /* on_error    */ goto error);
	c_adv(chn, ret);
	msg->next -= ret;
	if (!(chn->flags & CF_WROTE_DATA) || msg->sov > 0)
		msg->sov -= ret;
	if (!HAS_DATA_FILTERS(s, chn))
		msg->chunk_len -= channel_forward(chn, msg->chunk_len);
  waiting:
	return 0;

  chunk_parsing_error:
	if (msg->err_pos >= 0) {
		if (chn->flags & CF_ISRESP)
			http_capture_bad_message(s->be, s, msg,
						 msg->msg_state, strm_fe(s));
		else
			http_capture_bad_message(strm_fe(s), s,
						 msg, msg->msg_state, s->be);
	}
  error:
	return -1;
}


/* Iterate the same filter through all request headers.
 * Returns 1 if this filter can be stopped upon return, otherwise 0.
 * Since it can manage the switch to another backend, it updates the per-proxy
 * DENY stats.
 */
int apply_filter_to_req_headers(struct stream *s, struct channel *req, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, last_hdr;
	struct http_txn *txn = s->txn;
	struct hdr_idx_elem *cur_hdr;
	int delta, len;

	last_hdr = 0;

	cur_next = ci_head(req) + hdr_idx_first_pos(&txn->hdr_idx);
	old_idx = 0;

	while (!last_hdr) {
		if (unlikely(txn->flags & (TX_CLDENY | TX_CLTARPIT)))
			return 1;
		else if (unlikely(txn->flags & TX_CLALLOW) &&
			 (exp->action == ACT_ALLOW ||
			  exp->action == ACT_DENY ||
			  exp->action == ACT_TARPIT))
			return 0;

		cur_idx = txn->hdr_idx.v[old_idx].next;
		if (!cur_idx)
			break;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* Now we have one header between cur_ptr and cur_end,
		 * and the next header starts at cur_next.
		 */

		if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
			switch (exp->action) {
			case ACT_ALLOW:
				txn->flags |= TX_CLALLOW;
				last_hdr = 1;
				break;

			case ACT_DENY:
				txn->flags |= TX_CLDENY;
				last_hdr = 1;
				break;

			case ACT_TARPIT:
				txn->flags |= TX_CLTARPIT;
				last_hdr = 1;
				break;

			case ACT_REPLACE:
				len = exp_replace(trash.area,
				                  trash.size, cur_ptr,
				                  exp->replace, pmatch);
				if (len < 0)
					return -1;

				delta = b_rep_blk(&req->buf, cur_ptr, cur_end, trash.area, len);

				/* FIXME: if the user adds a newline in the replacement, the
				 * index will not be recalculated for now, and the new line
				 * will not be counted as a new header.
				 */

				cur_end += delta;
				cur_next += delta;
				cur_hdr->len += delta;
				http_msg_move_end(&txn->req, delta);
				break;

			case ACT_REMOVE:
				delta = b_rep_blk(&req->buf, cur_ptr, cur_next, NULL, 0);
				cur_next += delta;

				http_msg_move_end(&txn->req, delta);
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_end = NULL; /* null-term has been rewritten */
				cur_idx = old_idx;
				break;

			}
		}

		/* keep the link from this header to next one in case of later
		 * removal of next header.
		 */
		old_idx = cur_idx;
	}
	return 0;
}


/* Apply the filter to the request line.
 * Returns 0 if nothing has been done, 1 if the filter has been applied,
 * or -1 if a replacement resulted in an invalid request line.
 * Since it can manage the switch to another backend, it updates the per-proxy
 * DENY stats.
 */
int apply_filter_to_req_line(struct stream *s, struct channel *req, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end;
	int done;
	struct http_txn *txn = s->txn;
	int delta, len;

	if (unlikely(txn->flags & (TX_CLDENY | TX_CLTARPIT)))
		return 1;
	else if (unlikely(txn->flags & TX_CLALLOW) &&
		 (exp->action == ACT_ALLOW ||
		  exp->action == ACT_DENY ||
		  exp->action == ACT_TARPIT))
		return 0;
	else if (exp->action == ACT_REMOVE)
		return 0;

	done = 0;

	cur_ptr = ci_head(req);
	cur_end = cur_ptr + txn->req.sl.rq.l;

	/* Now we have the request line between cur_ptr and cur_end */

	if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
		switch (exp->action) {
		case ACT_ALLOW:
			txn->flags |= TX_CLALLOW;
			done = 1;
			break;

		case ACT_DENY:
			txn->flags |= TX_CLDENY;
			done = 1;
			break;

		case ACT_TARPIT:
			txn->flags |= TX_CLTARPIT;
			done = 1;
			break;

		case ACT_REPLACE:
			len = exp_replace(trash.area, trash.size,
			                  cur_ptr, exp->replace, pmatch);
			if (len < 0)
				return -1;

			delta = b_rep_blk(&req->buf, cur_ptr, cur_end, trash.area, len);

			/* FIXME: if the user adds a newline in the replacement, the
			 * index will not be recalculated for now, and the new line
			 * will not be counted as a new header.
			 */

			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			cur_end = (char *)http_parse_reqline(&txn->req,
							     HTTP_MSG_RQMETH,
							     cur_ptr, cur_end + 1,
							     NULL, NULL);
			if (unlikely(!cur_end))
				return -1;

			/* we have a full request and we know that we have either a CR
			 * or an LF at <ptr>.
			 */
			txn->meth = find_http_meth(cur_ptr, txn->req.sl.rq.m_l);
			hdr_idx_set_start(&txn->hdr_idx, txn->req.sl.rq.l, *cur_end == '\r');
			/* there is no point trying this regex on headers */
			return 1;
		}
	}
	return done;
}



/*
 * Apply all the req filters of proxy <px> to all headers in buffer <req> of stream <s>.
 * Returns 0 if everything is alright, or -1 in case a replacement lead to an
 * unparsable request. Since it can manage the switch to another backend, it
 * updates the per-proxy DENY stats.
 */
int apply_filters_to_request(struct stream *s, struct channel *req, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct hdr_exp *exp;

	for (exp = px->req_exp; exp; exp = exp->next) {
		int ret;

		/*
		 * The interleaving of transformations and verdicts
		 * makes it difficult to decide to continue or stop
		 * the evaluation.
		 */

		if (txn->flags & (TX_CLDENY|TX_CLTARPIT))
			break;

		if ((txn->flags & TX_CLALLOW) &&
		    (exp->action == ACT_ALLOW || exp->action == ACT_DENY ||
		     exp->action == ACT_TARPIT || exp->action == ACT_PASS))
			continue;

		/* if this filter had a condition, evaluate it now and skip to
		 * next filter if the condition does not match.
		 */
		if (exp->cond) {
			ret = acl_exec_cond(exp->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (((struct acl_cond *)exp->cond)->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (!ret)
				continue;
		}

		/* Apply the filter to the request line. */
		ret = apply_filter_to_req_line(s, req, exp);
		if (unlikely(ret < 0))
			return -1;

		if (likely(ret == 0)) {
			/* The filter did not match the request, it can be
			 * iterated through all headers.
			 */
			if (unlikely(apply_filter_to_req_headers(s, req, exp) < 0))
				return -1;
		}
	}
	return 0;
}


/* Delete a value in a header between delimiters <from> and <next> in buffer
 * <buf>. The number of characters displaced is returned, and the pointer to
 * the first delimiter is updated if required. The function tries as much as
 * possible to respect the following principles :
 *  - replace <from> delimiter by the <next> one unless <from> points to a
 *    colon, in which case <next> is simply removed
 *  - set exactly one space character after the new first delimiter, unless
 *    there are not enough characters in the block being moved to do so.
 *  - remove unneeded spaces before the previous delimiter and after the new
 *    one.
 *
 * It is the caller's responsibility to ensure that :
 *   - <from> points to a valid delimiter or the colon ;
 *   - <next> points to a valid delimiter or the final CR/LF ;
 *   - there are non-space chars before <from> ;
 *   - there is a CR/LF at or after <next>.
 */
static int del_hdr_value(struct buffer *buf, char **from, char *next)
{
	char *prev = *from;

	if (*prev == ':') {
		/* We're removing the first value, preserve the colon and add a
		 * space if possible.
		 */
		if (!HTTP_IS_CRLF(*next))
			next++;
		prev++;
		if (prev < next)
			*prev++ = ' ';

		while (HTTP_IS_SPHT(*next))
			next++;
	} else {
		/* Remove useless spaces before the old delimiter. */
		while (HTTP_IS_SPHT(*(prev-1)))
			prev--;
		*from = prev;

		/* copy the delimiter and if possible a space if we're
		 * not at the end of the line.
		 */
		if (!HTTP_IS_CRLF(*next)) {
			*prev++ = *next++;
			if (prev + 1 < next)
				*prev++ = ' ';
			while (HTTP_IS_SPHT(*next))
				next++;
		}
	}
	return b_rep_blk(buf, prev, next, NULL, 0);
}

/*
 * Manage client-side cookie. It can impact performance by about 2% so it is
 * desirable to call it only when needed. This code is quite complex because
 * of the multiple very crappy and ambiguous syntaxes we have to support. it
 * highly recommended not to touch this part without a good reason !
 */
void manage_client_side_cookies(struct stream *s, struct channel *req)
{
	struct http_txn *txn = s->txn;
	struct session *sess = s->sess;
	int preserve_hdr;
	int cur_idx, old_idx;
	char *hdr_beg, *hdr_end, *hdr_next, *del_from;
	char *prev, *att_beg, *att_end, *equal, *val_beg, *val_end, *next;

	/* Iterate through the headers, we start with the start line. */
	old_idx = 0;
	hdr_next = ci_head(req) + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		hdr_beg  = hdr_next;
		hdr_end  = hdr_beg + cur_hdr->len;
		hdr_next = hdr_end + cur_hdr->cr + 1;

		/* We have one full header between hdr_beg and hdr_end, and the
		 * next header starts at hdr_next. We're only interested in
		 * "Cookie:" headers.
		 */

		val = http_header_match2(hdr_beg, hdr_end, "Cookie", 6);
		if (!val) {
			old_idx = cur_idx;
			continue;
		}

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
		 * Cookie:NAME1=VALUE1;NAME2=VALUE2;NAME3=VALUE3\r\n
		 * Cookie:NAME1=VALUE1;NAME2_ONLY ;NAME3=VALUE3\r\n
		 * Cookie:    NAME1  =  VALUE 1  ; NAME2 = VALUE2 ; NAME3 = VALUE3\r\n
		 * |     |    |    | |  |      | |                                |
		 * |     |    |    | |  |      | |                     hdr_end <--+
		 * |     |    |    | |  |      | +--> next
		 * |     |    |    | |  |      +----> val_end
		 * |     |    |    | |  +-----------> val_beg
		 * |     |    |    | +--------------> equal
		 * |     |    |    +----------------> att_end
		 * |     |    +---------------------> att_beg
		 * |     +--------------------------> prev
		 * +--------------------------------> hdr_beg
		 */

		for (prev = hdr_beg + 6; prev < hdr_end; prev = next) {
			/* Iterate through all cookies on this line */

			/* find att_beg */
			att_beg = prev + 1;
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
			} else {
				val_beg = val_end = next = equal;
			}

			/* We have nothing to do with attributes beginning with '$'. However,
			 * they will automatically be removed if a header before them is removed,
			 * since they're supposed to be linked together.
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
					int delta = del_hdr_value(&req->buf, &del_from, prev);
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->req, delta);
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
					stripped_before = b_rep_blk(&req->buf, att_end, equal, NULL, 0);
					equal   += stripped_before;
					val_beg += stripped_before;
				}

				if (val_beg > equal + 1) {
					stripped_after = b_rep_blk(&req->buf, equal + 1, val_beg, NULL, 0);
					val_beg += stripped_after;
					stripped_before += stripped_after;
				}

				val_end      += stripped_before;
				next         += stripped_before;
				hdr_end      += stripped_before;
				hdr_next     += stripped_before;
				cur_hdr->len += stripped_before;
				http_msg_move_end(&txn->req, stripped_before);
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
				 * Cookie: NAME=SRV;          # in all but prefix modes
				 * Cookie: NAME=SRV~OPAQUE ;  # in prefix mode
				 * |      ||   ||  |      |+-> next
				 * |      ||   ||  |      +--> val_end
				 * |      ||   ||  +---------> delim
				 * |      ||   |+------------> val_beg
				 * |      ||   +-------------> att_end = equal
				 * |      |+-----------------> att_beg
				 * |      +------------------> prev
				 * +-------------------------> hdr_beg
				 */

				if (s->be->ck_opts & PR_CK_PFX) {
					for (delim = val_beg; delim < val_end; delim++)
						if (*delim == COOKIE_DELIM)
							break;
				} else {
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
				 *   application cookie so that it does not get accidently removed later,
				 *   if we're in cookie prefix mode
				 */
				if ((s->be->ck_opts & PR_CK_PFX) && (delim != val_end)) {
					int delta; /* negative */

					delta = b_rep_blk(&req->buf, val_beg, delim + 1, NULL, 0);
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->req, delta);

					del_from = NULL;
					preserve_hdr = 1; /* we want to keep this cookie */
				}
				else if (del_from == NULL &&
					 (s->be->ck_opts & (PR_CK_INS | PR_CK_IND)) == (PR_CK_INS | PR_CK_IND)) {
					del_from = prev;
				}
			} else {
				/* This is not our cookie, so we must preserve it. But if we already
				 * scheduled another cookie for removal, we cannot remove the
				 * complete header, but we can remove the previous block itself.
				 */
				preserve_hdr = 1;

				if (del_from != NULL) {
					int delta = del_hdr_value(&req->buf, &del_from, prev);
					if (att_beg >= del_from)
						att_beg += delta;
					if (att_end >= del_from)
						att_end += delta;
					val_beg  += delta;
					val_end  += delta;
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->req, delta);
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
			int delta;
			if (preserve_hdr) {
				delta = del_hdr_value(&req->buf, &del_from, hdr_end);
				hdr_end = del_from;
				cur_hdr->len += delta;
			} else {
				delta = b_rep_blk(&req->buf, hdr_beg, hdr_next, NULL, 0);

				/* FIXME: this should be a separate function */
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_idx = old_idx;
			}
			hdr_next += delta;
			http_msg_move_end(&txn->req, delta);
		}

		/* check next header */
		old_idx = cur_idx;
	}
}


/* Iterate the same filter through all response headers contained in <rtr>.
 * Returns 1 if this filter can be stopped upon return, otherwise 0.
 */
int apply_filter_to_resp_headers(struct stream *s, struct channel *rtr, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx, old_idx, last_hdr;
	struct http_txn *txn = s->txn;
	struct hdr_idx_elem *cur_hdr;
	int delta, len;

	last_hdr = 0;

	cur_next = ci_head(rtr) + hdr_idx_first_pos(&txn->hdr_idx);
	old_idx = 0;

	while (!last_hdr) {
		if (unlikely(txn->flags & TX_SVDENY))
			return 1;
		else if (unlikely(txn->flags & TX_SVALLOW) &&
			 (exp->action == ACT_ALLOW ||
			  exp->action == ACT_DENY))
			return 0;

		cur_idx = txn->hdr_idx.v[old_idx].next;
		if (!cur_idx)
			break;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* Now we have one header between cur_ptr and cur_end,
		 * and the next header starts at cur_next.
		 */

		if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
			switch (exp->action) {
			case ACT_ALLOW:
				txn->flags |= TX_SVALLOW;
				last_hdr = 1;
				break;

			case ACT_DENY:
				txn->flags |= TX_SVDENY;
				last_hdr = 1;
				break;

			case ACT_REPLACE:
				len = exp_replace(trash.area,
				                  trash.size, cur_ptr,
				                  exp->replace, pmatch);
				if (len < 0)
					return -1;

				delta = b_rep_blk(&rtr->buf, cur_ptr, cur_end, trash.area, len);

				/* FIXME: if the user adds a newline in the replacement, the
				 * index will not be recalculated for now, and the new line
				 * will not be counted as a new header.
				 */

				cur_end += delta;
				cur_next += delta;
				cur_hdr->len += delta;
				http_msg_move_end(&txn->rsp, delta);
				break;

			case ACT_REMOVE:
				delta = b_rep_blk(&rtr->buf, cur_ptr, cur_next, NULL, 0);
				cur_next += delta;

				http_msg_move_end(&txn->rsp, delta);
				txn->hdr_idx.v[old_idx].next = cur_hdr->next;
				txn->hdr_idx.used--;
				cur_hdr->len = 0;
				cur_end = NULL; /* null-term has been rewritten */
				cur_idx = old_idx;
				break;

			}
		}

		/* keep the link from this header to next one in case of later
		 * removal of next header.
		 */
		old_idx = cur_idx;
	}
	return 0;
}


/* Apply the filter to the status line in the response buffer <rtr>.
 * Returns 0 if nothing has been done, 1 if the filter has been applied,
 * or -1 if a replacement resulted in an invalid status line.
 */
int apply_filter_to_sts_line(struct stream *s, struct channel *rtr, struct hdr_exp *exp)
{
	char *cur_ptr, *cur_end;
	int done;
	struct http_txn *txn = s->txn;
	int delta, len;

	if (unlikely(txn->flags & TX_SVDENY))
		return 1;
	else if (unlikely(txn->flags & TX_SVALLOW) &&
		 (exp->action == ACT_ALLOW ||
		  exp->action == ACT_DENY))
		return 0;
	else if (exp->action == ACT_REMOVE)
		return 0;

	done = 0;

	cur_ptr = ci_head(rtr);
	cur_end = cur_ptr + txn->rsp.sl.st.l;

	/* Now we have the status line between cur_ptr and cur_end */

	if (regex_exec_match2(exp->preg, cur_ptr, cur_end-cur_ptr, MAX_MATCH, pmatch, 0)) {
		switch (exp->action) {
		case ACT_ALLOW:
			txn->flags |= TX_SVALLOW;
			done = 1;
			break;

		case ACT_DENY:
			txn->flags |= TX_SVDENY;
			done = 1;
			break;

		case ACT_REPLACE:
			len = exp_replace(trash.area, trash.size,
			                  cur_ptr, exp->replace, pmatch);
			if (len < 0)
				return -1;

			delta = b_rep_blk(&rtr->buf, cur_ptr, cur_end, trash.area, len);

			/* FIXME: if the user adds a newline in the replacement, the
			 * index will not be recalculated for now, and the new line
			 * will not be counted as a new header.
			 */

			http_msg_move_end(&txn->rsp, delta);
			cur_end += delta;
			cur_end = (char *)http_parse_stsline(&txn->rsp,
							     HTTP_MSG_RPVER,
							     cur_ptr, cur_end + 1,
							     NULL, NULL);
			if (unlikely(!cur_end))
				return -1;

			/* we have a full respnse and we know that we have either a CR
			 * or an LF at <ptr>.
			 */
			txn->status = strl2ui(ci_head(rtr) + txn->rsp.sl.st.c, txn->rsp.sl.st.c_l);
			hdr_idx_set_start(&txn->hdr_idx, txn->rsp.sl.st.l, *cur_end == '\r');
			/* there is no point trying this regex on headers */
			return 1;
		}
	}
	return done;
}



/*
 * Apply all the resp filters of proxy <px> to all headers in buffer <rtr> of stream <s>.
 * Returns 0 if everything is alright, or -1 in case a replacement lead to an
 * unparsable response.
 */
int apply_filters_to_response(struct stream *s, struct channel *rtr, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct hdr_exp *exp;

	for (exp = px->rsp_exp; exp; exp = exp->next) {
		int ret;

		/*
		 * The interleaving of transformations and verdicts
		 * makes it difficult to decide to continue or stop
		 * the evaluation.
		 */

		if (txn->flags & TX_SVDENY)
			break;

		if ((txn->flags & TX_SVALLOW) &&
		    (exp->action == ACT_ALLOW || exp->action == ACT_DENY ||
		     exp->action == ACT_PASS)) {
			exp = exp->next;
			continue;
		}

		/* if this filter had a condition, evaluate it now and skip to
		 * next filter if the condition does not match.
		 */
		if (exp->cond) {
			ret = acl_exec_cond(exp->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (((struct acl_cond *)exp->cond)->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}

		/* Apply the filter to the status line. */
		ret = apply_filter_to_sts_line(s, rtr, exp);
		if (unlikely(ret < 0))
			return -1;

		if (likely(ret == 0)) {
			/* The filter did not match the response, it can be
			 * iterated through all headers.
			 */
			if (unlikely(apply_filter_to_resp_headers(s, rtr, exp) < 0))
				return -1;
		}
	}
	return 0;
}


/*
 * Manage server-side cookies. It can impact performance by about 2% so it is
 * desirable to call it only when needed. This function is also used when we
 * just need to know if there is a cookie (eg: for check-cache).
 */
void manage_server_side_cookies(struct stream *s, struct channel *res)
{
	struct http_txn *txn = s->txn;
	struct session *sess = s->sess;
	struct server *srv;
	int is_cookie2;
	int cur_idx, old_idx, delta;
	char *hdr_beg, *hdr_end, *hdr_next;
	char *prev, *att_beg, *att_end, *equal, *val_beg, *val_end, *next;

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	old_idx = 0;
	hdr_next = ci_head(res) + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[old_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		hdr_beg  = hdr_next;
		hdr_end  = hdr_beg + cur_hdr->len;
		hdr_next = hdr_end + cur_hdr->cr + 1;

		/* We have one full header between hdr_beg and hdr_end, and the
		 * next header starts at hdr_next. We're only interested in
		 * "Set-Cookie" and "Set-Cookie2" headers.
		 */

		is_cookie2 = 0;
		prev = hdr_beg + 10;
		val = http_header_match2(hdr_beg, hdr_end, "Set-Cookie", 10);
		if (!val) {
			val = http_header_match2(hdr_beg, hdr_end, "Set-Cookie2", 11);
			if (!val) {
				old_idx = cur_idx;
				continue;
			}
			is_cookie2 = 1;
			prev = hdr_beg + 11;
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
			return;

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
		 * Set-Cookie:    NAME1  =  VALUE 1  ; Secure; Path="/"\r\n
		 * Set-Cookie:NAME=VALUE; Secure; Expires=Thu, 01-Jan-1970 00:00:01 GMT\r\n
		 * Set-Cookie: NAME = VALUE ; Secure; Expires=Thu, 01-Jan-1970 00:00:01 GMT\r\n
		 * Set-Cookie2: NAME1 = VALUE 1 ; Max-Age=0, NAME2=VALUE2; Discard\r\n
		 * |          | |   | | |     | |          |                      |
		 * |          | |   | | |     | |          +-> next    hdr_end <--+
		 * |          | |   | | |     | +------------> scav
		 * |          | |   | | |     +--------------> val_end
		 * |          | |   | | +--------------------> val_beg
		 * |          | |   | +----------------------> equal
		 * |          | |   +------------------------> att_end
		 * |          | +----------------------------> att_beg
		 * |          +------------------------------> prev
		 * +-----------------------------------------> hdr_beg
		 */

		for (; prev < hdr_end; prev = next) {
			/* Iterate through all cookies on this line */

			/* find att_beg */
			att_beg = prev + 1;
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
			} else {
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
					stripped_before = b_rep_blk(&res->buf, att_end, equal, NULL, 0);
					equal   += stripped_before;
					val_beg += stripped_before;
				}

				if (val_beg > equal + 1) {
					stripped_after = b_rep_blk(&res->buf, equal + 1, val_beg, NULL, 0);
					val_beg += stripped_after;
					stripped_before += stripped_after;
				}

				val_end      += stripped_before;
				next         += stripped_before;
				hdr_end      += stripped_before;
				hdr_next     += stripped_before;
				cur_hdr->len += stripped_before;
				http_msg_move_end(&txn->rsp, stripped_before);
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
					if (*prev == ':' && next == hdr_end) {
						/* whole header */
						delta = b_rep_blk(&res->buf, hdr_beg, hdr_next, NULL, 0);
						txn->hdr_idx.v[old_idx].next = cur_hdr->next;
						txn->hdr_idx.used--;
						cur_hdr->len = 0;
						cur_idx = old_idx;
						hdr_next += delta;
						http_msg_move_end(&txn->rsp, delta);
						/* note: while both invalid now, <next> and <hdr_end>
						 * are still equal, so the for() will stop as expected.
						 */
					} else {
						/* just remove the value */
						int delta = del_hdr_value(&res->buf, &prev, next);
						next      = prev;
						hdr_end  += delta;
						hdr_next += delta;
						cur_hdr->len += delta;
						http_msg_move_end(&txn->rsp, delta);
					}
					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_DELETED;
					/* and go on with next cookie */
				}
				else if (srv && srv->cookie && (s->be->ck_opts & PR_CK_RW)) {
					/* replace bytes val_beg->val_end with the cookie name associated
					 * with this server since we know it.
					 */
					delta = b_rep_blk(&res->buf, val_beg, val_end, srv->cookie, srv->cklen);
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->rsp, delta);

					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_REPLACED;
				}
				else if (srv && srv->cookie && (s->be->ck_opts & PR_CK_PFX)) {
					/* insert the cookie name associated with this server
					 * before existing cookie, and insert a delimiter between them..
					 */
					delta = b_rep_blk(&res->buf, val_beg, val_beg, srv->cookie, srv->cklen + 1);
					next     += delta;
					hdr_end  += delta;
					hdr_next += delta;
					cur_hdr->len += delta;
					http_msg_move_end(&txn->rsp, delta);

					val_beg[srv->cklen] = COOKIE_DELIM;
					txn->flags &= ~TX_SCK_MASK;
					txn->flags |= TX_SCK_REPLACED;
				}
			}
			/* that's done for this cookie, check the next one on the same
			 * line when next != hdr_end (only if is_cookie2).
			 */
		}
		/* check next header */
		old_idx = cur_idx;
	}
}


/*
 * Parses the Cache-Control and Pragma request header fields to determine if
 * the request may be served from the cache and/or if it is cacheable. Updates
 * s->txn->flags.
 */
void check_request_for_cacheability(struct stream *s, struct channel *chn)
{
	struct http_txn *txn = s->txn;
	char *p1, *p2;
	char *cur_ptr, *cur_end, *cur_next;
	int pragma_found;
	int cc_found;
	int cur_idx;

	if (IS_HTX_STRM(s))
		return htx_check_request_for_cacheability(s, chn);

	if ((txn->flags & (TX_CACHEABLE|TX_CACHE_IGNORE)) == TX_CACHE_IGNORE)
		return; /* nothing more to do here */

	cur_idx = 0;
	pragma_found = cc_found = 0;
	cur_next = ci_head(chn) + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[cur_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next.
		 */

		val = http_header_match2(cur_ptr, cur_end, "Pragma", 6);
		if (val) {
			if ((cur_end - (cur_ptr + val) >= 8) &&
			    strncasecmp(cur_ptr + val, "no-cache", 8) == 0) {
				pragma_found = 1;
				continue;
			}
		}

		/* Don't use the cache and don't try to store if we found the
		 * Authorization header */
		val = http_header_match2(cur_ptr, cur_end, "Authorization", 13);
		if (val) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			txn->flags |= TX_CACHE_IGNORE;
			continue;
		}

		val = http_header_match2(cur_ptr, cur_end, "Cache-control", 13);
		if (!val)
			continue;

		/* OK, right now we know we have a cache-control header at cur_ptr */
		cc_found = 1;
		p1 = cur_ptr + val; /* first non-space char after 'cache-control:' */

		if (p1 >= cur_end)	/* no more info */
			continue;

		/* p1 is at the beginning of the value */
		p2 = p1;
		while (p2 < cur_end && *p2 != '=' && *p2 != ',' && !isspace((unsigned char)*p2))
			p2++;

		/* we have a complete value between p1 and p2. We don't check the
		 * values after max-age, max-stale nor min-fresh, we simply don't
		 * use the cache when they're specified.
		 */
		if (((p2 - p1 == 7) && strncasecmp(p1, "max-age",   7) == 0) ||
		    ((p2 - p1 == 8) && strncasecmp(p1, "no-cache",  8) == 0) ||
		    ((p2 - p1 == 9) && strncasecmp(p1, "max-stale", 9) == 0) ||
		    ((p2 - p1 == 9) && strncasecmp(p1, "min-fresh", 9) == 0)) {
			txn->flags |= TX_CACHE_IGNORE;
			continue;
		}

		if ((p2 - p1 == 8) && strncasecmp(p1, "no-store", 8) == 0) {
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
void check_response_for_cacheability(struct stream *s, struct channel *rtr)
{
	struct http_txn *txn = s->txn;
	char *p1, *p2;

	char *cur_ptr, *cur_end, *cur_next;
	int cur_idx;


	if (IS_HTX_STRM(s))
		return htx_check_response_for_cacheability(s, rtr);

	if (txn->status < 200) {
		/* do not try to cache interim responses! */
		txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
		return;
	}

	/* Iterate through the headers.
	 * we start with the start line.
	 */
	cur_idx = 0;
	cur_next = ci_head(rtr) + hdr_idx_first_pos(&txn->hdr_idx);

	while ((cur_idx = txn->hdr_idx.v[cur_idx].next)) {
		struct hdr_idx_elem *cur_hdr;
		int val;

		cur_hdr  = &txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_end  = cur_ptr + cur_hdr->len;
		cur_next = cur_end + cur_hdr->cr + 1;

		/* We have one full header between cur_ptr and cur_end, and the
		 * next header starts at cur_next.
		 */

		val = http_header_match2(cur_ptr, cur_end, "Pragma", 6);
		if (val) {
			if ((cur_end - (cur_ptr + val) >= 8) &&
			    strncasecmp(cur_ptr + val, "no-cache", 8) == 0) {
				txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
				return;
			}
		}

		val = http_header_match2(cur_ptr, cur_end, "Cache-control", 13);
		if (!val)
			continue;

		/* OK, right now we know we have a cache-control header at cur_ptr */

		p1 = cur_ptr + val; /* first non-space char after 'cache-control:' */

		if (p1 >= cur_end)	/* no more info */
			continue;

		/* p1 is at the beginning of the value */
		p2 = p1;

		while (p2 < cur_end && *p2 != '=' && *p2 != ',' && !isspace((unsigned char)*p2))
			p2++;

		/* we have a complete value between p1 and p2 */
		if (p2 < cur_end && *p2 == '=') {
			if (((cur_end - p2) > 1 && (p2 - p1 == 7) && strncasecmp(p1, "max-age=0", 9) == 0) ||
			    ((cur_end - p2) > 1 && (p2 - p1 == 8) && strncasecmp(p1, "s-maxage=0", 10) == 0)) {
				txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
				continue;
			}

			/* we have something of the form no-cache="set-cookie" */
			if ((cur_end - p1 >= 21) &&
			    strncasecmp(p1, "no-cache=\"set-cookie", 20) == 0
			    && (p1[20] == '"' || p1[20] == ','))
				txn->flags &= ~TX_CACHE_COOK;
			continue;
		}

		/* OK, so we know that either p2 points to the end of string or to a comma */
		if (((p2 - p1 ==  7) && strncasecmp(p1, "private", 7) == 0) ||
		    ((p2 - p1 ==  8) && strncasecmp(p1, "no-cache", 8) == 0) ||
		    ((p2 - p1 ==  8) && strncasecmp(p1, "no-store", 8) == 0)) {
			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;
			return;
		}

		if ((p2 - p1 ==  6) && strncasecmp(p1, "public", 6) == 0) {
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
int stats_check_uri(struct stream_interface *si, struct http_txn *txn, struct proxy *backend)
{
	struct uri_auth *uri_auth = backend->uri_auth;
	struct http_msg *msg = &txn->req;
	const char *uri = ci_head(msg->chn)+ msg->sl.rq.u;

	if (!uri_auth)
		return 0;

	if (txn->meth != HTTP_METH_GET && txn->meth != HTTP_METH_HEAD && txn->meth != HTTP_METH_POST)
		return 0;

	/* check URI size */
	if (uri_auth->uri_len > msg->sl.rq.u_l)
		return 0;

	if (memcmp(uri, uri_auth->uri_prefix, uri_auth->uri_len) != 0)
		return 0;

	return 1;
}

/* Append the description of what is present in error snapshot <es> into <out>.
 * The description must be small enough to always fit in a trash. The output
 * buffer may be the trash so the trash must not be used inside this function.
 */
void http_show_error_snapshot(struct buffer *out, const struct error_snapshot *es)
{
	chunk_appendf(out,
	              "  stream #%d, stream flags 0x%08x, tx flags 0x%08x\n"
	              "  HTTP msg state %s(%d), msg flags 0x%08x\n"
	              "  HTTP chunk len %lld bytes, HTTP body len %lld bytes, channel flags 0x%08x :\n",
	              es->ctx.http.sid, es->ctx.http.s_flags, es->ctx.http.t_flags,
	              h1_msg_state_str(es->ctx.http.state), es->ctx.http.state,
	              es->ctx.http.m_flags, es->ctx.http.m_clen,
	              es->ctx.http.m_blen, es->ctx.http.b_flags);
}

/*
 * Capture a bad request or response and archive it in the proxy's structure.
 * By default it tries to report the error position as msg->err_pos. However if
 * this one is not set, it will then report msg->next, which is the last known
 * parsing point. The function is able to deal with wrapping buffers. It always
 * displays buffers as a contiguous area starting at buf->p. The direction is
 * determined thanks to the channel's flags.
 */
void http_capture_bad_message(struct proxy *proxy, struct stream *s,
                              struct http_msg *msg,
			      enum h1_state state, struct proxy *other_end)
{
	union error_snapshot_ctx ctx;
	long ofs;

	/* http-specific part now */
	ctx.http.sid     = s->uniq_id;
	ctx.http.state   = state;
	ctx.http.b_flags = msg->chn->flags;
	ctx.http.s_flags = s->flags;
	ctx.http.t_flags = s->txn->flags;
	ctx.http.m_flags = msg->flags;
	ctx.http.m_clen  = msg->chunk_len;
	ctx.http.m_blen  = msg->body_len;

	ofs = msg->chn->total - ci_data(msg->chn);
	if (ofs < 0)
		ofs = 0;

	proxy_capture_error(proxy, !!(msg->chn->flags & CF_ISRESP),
	                    other_end, s->target,
	                    strm_sess(s), &msg->chn->buf,
	                    ofs, co_data(msg->chn),
	                    (msg->err_pos >= 0) ? msg->err_pos : msg->next,
	                    &ctx, http_show_error_snapshot);
}

/*
 * Print a debug line with a header. Always stop at the first CR or LF char,
 * so it is safe to pass it a full buffer if needed. If <err> is not NULL, an
 * arrow is printed after the line which contains the pointer.
 */
void debug_hdr(const char *dir, struct stream *s, const char *start, const char *end)
{
	struct session *sess = strm_sess(s);
	int max;

	chunk_printf(&trash, "%08x:%s.%s[%04x:%04x]: ", s->uniq_id, s->be->id,
		      dir,
		     objt_conn(sess->origin) ? (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
		     objt_cs(s->si[1].end) ? (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

	for (max = 0; start + max < end; max++)
		if (start[max] == '\r' || start[max] == '\n')
			break;

	UBOUND(max, trash.size - trash.data - 3);
	trash.data += strlcpy2(trash.area + trash.data, start, max + 1);
	trash.area[trash.data++] = '\n';
	shut_your_big_mouth_gcc(write(1, trash.area, trash.data));
}


/* Allocate a new HTTP transaction for stream <s> unless there is one already.
 * The hdr_idx is allocated as well. In case of allocation failure, everything
 * allocated is freed and NULL is returned. Otherwise the new transaction is
 * assigned to the stream and returned.
 */
struct http_txn *http_alloc_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;

	if (txn)
		return txn;

	txn = pool_alloc(pool_head_http_txn);
	if (!txn)
		return txn;

	txn->hdr_idx.size = global.tune.max_http_hdr;
	txn->hdr_idx.v    = pool_alloc(pool_head_hdr_idx);
	if (!txn->hdr_idx.v) {
		pool_free(pool_head_http_txn, txn);
		return NULL;
	}

	s->txn = txn;
	return txn;
}

void http_txn_reset_req(struct http_txn *txn)
{
	txn->req.flags = 0;
	txn->req.sol = txn->req.eol = txn->req.eoh = 0; /* relative to the buffer */
	txn->req.next = 0;
	txn->req.chunk_len = 0LL;
	txn->req.body_len = 0LL;
	txn->req.msg_state = HTTP_MSG_RQBEFORE; /* at the very beginning of the request */
}

void http_txn_reset_res(struct http_txn *txn)
{
	txn->rsp.flags = 0;
	txn->rsp.sol = txn->rsp.eol = txn->rsp.eoh = 0; /* relative to the buffer */
	txn->rsp.next = 0;
	txn->rsp.chunk_len = 0LL;
	txn->rsp.body_len = 0LL;
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
	struct proxy *fe = strm_fe(s);
	struct conn_stream *cs = objt_cs(s->si[0].end);

	txn->flags = ((cs && cs->flags & CS_FL_NOT_FIRST)
		      ? (TX_NOT_FIRST|TX_WAIT_NEXT_RQ)
		      : 0);
	txn->status = -1;

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

	txn->req.err_pos = txn->rsp.err_pos = -2; /* block buggy requests/responses */
	if (fe->options2 & PR_O2_REQBUG_OK)
		txn->req.err_pos = -1;            /* let buggy requests pass */

	if (txn->hdr_idx.v)
		hdr_idx_init(&txn->hdr_idx);

	vars_init(&s->vars_txn,    SCOPE_TXN);
	vars_init(&s->vars_reqres, SCOPE_REQ);
}

/* to be used at the end of a transaction */
void http_end_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;
	struct proxy *fe = strm_fe(s);

	/* these ones will have been dynamically allocated */
	pool_free(pool_head_requri, txn->uri);
	pool_free(pool_head_capture, txn->cli_cookie);
	pool_free(pool_head_capture, txn->srv_cookie);
	pool_free(pool_head_uniqueid, s->unique_id);

	s->unique_id = NULL;
	txn->uri = NULL;
	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;

	if (s->req_cap) {
		struct cap_hdr *h;
		for (h = fe->req_cap; h; h = h->next)
			pool_free(h->pool, s->req_cap[h->index]);
		memset(s->req_cap, 0, fe->nb_req_cap * sizeof(void *));
	}

	if (s->res_cap) {
		struct cap_hdr *h;
		for (h = fe->rsp_cap; h; h = h->next)
			pool_free(h->pool, s->res_cap[h->index]);
		memset(s->res_cap, 0, fe->nb_rsp_cap * sizeof(void *));
	}

	if (!LIST_ISEMPTY(&s->vars_txn.head))
		vars_prune(&s->vars_txn, s->sess, s);
	if (!LIST_ISEMPTY(&s->vars_reqres.head))
		vars_prune(&s->vars_reqres, s->sess, s);
}

/* to be used at the end of a transaction to prepare a new one */
void http_reset_txn(struct stream *s)
{
	http_end_txn(s);
	http_init_txn(s);

	/* reinitialise the current rule list pointer to NULL. We are sure that
	 * any rulelist match the NULL pointer.
	 */
	s->current_rule_list = NULL;

	s->be = strm_fe(s);
	s->logs.logwait = strm_fe(s)->to_log;
	s->logs.level = 0;
	stream_del_srv_conn(s);
	s->target = NULL;
	/* re-init store persistence */
	s->store_count = 0;
	s->uniq_id = HA_ATOMIC_XADD(&global.req_count, 1);

	s->req.flags |= CF_READ_DONTWAIT; /* one read is usually enough */

	/* We must trim any excess data from the response buffer, because we
	 * may have blocked an invalid response from a server that we don't
	 * want to accidently forward once we disable the analysers, nor do
	 * we want those data to come along with next response. A typical
	 * example of such data would be from a buggy server responding to
	 * a HEAD with some data, or sending more than the advertised
	 * content-length.
	 */
	if (unlikely(ci_data(&s->res)))
		b_set_data(&s->res.buf, co_data(&s->res));

	/* Now we can realign the response buffer */
	c_realign_if_empty(&s->res);

	s->req.rto = strm_fe(s)->timeout.client;
	s->req.wto = TICK_ETERNITY;

	s->res.rto = TICK_ETERNITY;
	s->res.wto = strm_fe(s)->timeout.client;

	s->req.rex = TICK_ETERNITY;
	s->req.wex = TICK_ETERNITY;
	s->req.analyse_exp = TICK_ETERNITY;
	s->res.rex = TICK_ETERNITY;
	s->res.wex = TICK_ETERNITY;
	s->res.analyse_exp = TICK_ETERNITY;
	s->si[1].hcto = TICK_ETERNITY;
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
int http_replace_req_line(int action, const char *replace, int len,
                          struct proxy *px, struct stream *s)
{
	struct http_txn *txn = s->txn;
	char *cur_ptr, *cur_end;
	int offset = 0;
	int delta;

	if (IS_HTX_STRM(s))
		return htx_req_replace_stline(action, replace, len, px, s);

	switch (action) {
	case 0: // method
		cur_ptr = ci_head(&s->req);
		cur_end = cur_ptr + txn->req.sl.rq.m_l;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.m_l += delta;
		txn->req.sl.rq.u   += delta;
		txn->req.sl.rq.v   += delta;
		break;

	case 1: // path
		cur_ptr = http_txn_get_path(txn);
		if (!cur_ptr)
			cur_ptr = ci_head(&s->req) + txn->req.sl.rq.u;

		cur_end = cur_ptr;
		while (cur_end < ci_head(&s->req) + txn->req.sl.rq.u + txn->req.sl.rq.u_l && *cur_end != '?')
			cur_end++;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.u_l += delta;
		txn->req.sl.rq.v   += delta;
		break;

	case 2: // query
		offset = 1;
		cur_ptr = ci_head(&s->req) + txn->req.sl.rq.u;
		cur_end = cur_ptr + txn->req.sl.rq.u_l;
		while (cur_ptr < cur_end && *cur_ptr != '?')
			cur_ptr++;

		/* skip the question mark or indicate that we must insert it
		 * (but only if the format string is not empty then).
		 */
		if (cur_ptr < cur_end)
			cur_ptr++;
		else if (len > 1)
			offset = 0;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.u_l += delta;
		txn->req.sl.rq.v   += delta;
		break;

	case 3: // uri
		cur_ptr = ci_head(&s->req) + txn->req.sl.rq.u;
		cur_end = cur_ptr + txn->req.sl.rq.u_l;

		/* adjust req line offsets and lengths */
		delta = len - offset - (cur_end - cur_ptr);
		txn->req.sl.rq.u_l += delta;
		txn->req.sl.rq.v   += delta;
		break;

	default:
		return -1;
	}

	/* commit changes and adjust end of message */
	delta = b_rep_blk(&s->req.buf, cur_ptr, cur_end, replace + offset, len - offset);
	txn->req.sl.rq.l += delta;
	txn->hdr_idx.v[0].len += delta;
	http_msg_move_end(&txn->req, delta);
	return 0;
}

/* This function replace the HTTP status code and the associated message. The
 * variable <status> contains the new status code. This function never fails.
 */
void http_set_status(unsigned int status, const char *reason, struct stream *s)
{
	struct http_txn *txn = s->txn;
	char *cur_ptr, *cur_end;
	int delta;
	char *res;
	int c_l;
	const char *msg = reason;
	int msg_len;

	if (IS_HTX_STRM(s))
		return htx_res_set_status(status, reason, s);

	chunk_reset(&trash);

	res = ultoa_o(status, trash.area, trash.size);
	c_l = res - trash.area;

	trash.area[c_l] = ' ';
	trash.data = c_l + 1;

	/* Do we have a custom reason format string? */
	if (msg == NULL)
		msg = http_get_reason(status);
	msg_len = strlen(msg);
	strncpy(&trash.area[trash.data], msg, trash.size - trash.data);
	trash.data += msg_len;

	cur_ptr = ci_head(&s->res) + txn->rsp.sl.st.c;
	cur_end = ci_head(&s->res) + txn->rsp.sl.st.r + txn->rsp.sl.st.r_l;

	/* commit changes and adjust message */
	delta = b_rep_blk(&s->res.buf, cur_ptr, cur_end, trash.area,
			  trash.data);

	/* adjust res line offsets and lengths */
	txn->rsp.sl.st.r += c_l - txn->rsp.sl.st.c_l;
	txn->rsp.sl.st.c_l = c_l;
	txn->rsp.sl.st.r_l = msg_len;

	delta = trash.data - (cur_end - cur_ptr);
	txn->rsp.sl.st.l += delta;
	txn->hdr_idx.v[0].len += delta;
	http_msg_move_end(&txn->rsp, delta);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
