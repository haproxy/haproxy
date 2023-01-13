/*
 * include/haproxy/http_ana.h
 * This file contains HTTP protocol definitions.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_PROTO_HTTP_H
#define _HAPROXY_PROTO_HTTP_H

#include <haproxy/api.h>
#include <haproxy/channel-t.h>
#include <haproxy/http_ana-t.h>
#include <haproxy/htx-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/stream-t.h>

extern struct pool_head *pool_head_uniqueid;
extern struct pool_head *pool_head_http_txn;

int http_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int http_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px);
int http_process_request(struct stream *s, struct channel *req, int an_bit);
int http_process_tarpit(struct stream *s, struct channel *req, int an_bit);
int http_wait_for_request_body(struct stream *s, struct channel *req, int an_bit);
int http_wait_for_response(struct stream *s, struct channel *rep, int an_bit);
int http_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px);
int http_request_forward_body(struct stream *s, struct channel *req, int an_bit);
int http_response_forward_body(struct stream *s, struct channel *res, int an_bit);
int http_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn);
int http_eval_after_res_rules(struct stream *s);
int http_replace_hdrs(struct stream* s, struct htx *htx, struct ist name, const char *str, struct my_regex *re, int full);
int http_req_replace_stline(int action, const char *replace, int len,
			    struct proxy *px, struct stream *s);
int http_res_set_status(unsigned int status, struct ist reason, struct stream *s);
void http_check_request_for_cacheability(struct stream *s, struct channel *req);
void http_check_response_for_cacheability(struct stream *s, struct channel *res);
enum rule_result http_wait_for_msg_body(struct stream *s, struct channel *chn, unsigned int time, unsigned int bytes);
void http_perform_server_redirect(struct stream *s, struct stconn *sc);
void http_server_error(struct stream *s, struct stconn *sc, int err, int finst, struct http_reply *msg);
void http_reply_and_close(struct stream *s, short status, struct http_reply *msg);
void http_return_srv_error(struct stream *s, struct stconn *sc);
struct http_reply *http_error_message(struct stream *s);
int http_reply_to_htx(struct stream *s, struct htx *htx, struct http_reply *reply);
int http_reply_message(struct stream *s, struct http_reply *reply);
int http_forward_proxy_resp(struct stream *s, int final);

struct http_txn *http_create_txn(struct stream *s);
void http_destroy_txn(struct stream *s);

void http_set_term_flags(struct stream *s);

/* for debugging, reports the HTTP/1 message state name (legacy version) */
static inline const char *h1_msg_state_str(enum h1_state msg_state)
{
	switch (msg_state) {
	case HTTP_MSG_RQBEFORE:    return "MSG_RQBEFORE";
	case HTTP_MSG_RPBEFORE:    return "MSG_RPBEFORE";
	case HTTP_MSG_BODY:        return "MSG_BODY";
	case HTTP_MSG_DATA:        return "MSG_DATA";
	case HTTP_MSG_ENDING:      return "MSG_ENDING";
	case HTTP_MSG_DONE:        return "MSG_DONE";
	case HTTP_MSG_CLOSING:     return "MSG_CLOSING";
	case HTTP_MSG_CLOSED:      return "MSG_CLOSED";
	case HTTP_MSG_TUNNEL:      return "MSG_TUNNEL";
	default:                   return "MSG_??????";
	}
}

#endif /* _HAPROXY_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
