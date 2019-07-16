/*
 * include/proto/proto_http.h
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

#ifndef _PROTO_PROTO_HTTP_H
#define _PROTO_PROTO_HTTP_H

#include <common/config.h>
#include <common/htx.h>
#include <types/channel.h>
#include <types/proto_http.h>
#include <types/stream.h>

extern struct pool_head *pool_head_uniqueid;

int htx_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int htx_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px);
int htx_process_request(struct stream *s, struct channel *req, int an_bit);
int htx_process_tarpit(struct stream *s, struct channel *req, int an_bit);
int htx_wait_for_request_body(struct stream *s, struct channel *req, int an_bit);
int htx_wait_for_response(struct stream *s, struct channel *rep, int an_bit);
int htx_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px);
int htx_request_forward_body(struct stream *s, struct channel *req, int an_bit);
int htx_response_forward_body(struct stream *s, struct channel *res, int an_bit);
int htx_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn);
int htx_transform_header_str(struct stream* s, struct channel *chn, struct htx *htx,
			     struct ist name, const char *str, struct my_regex *re, int action);
int htx_req_replace_stline(int action, const char *replace, int len,
			   struct proxy *px, struct stream *s);
void htx_res_set_status(unsigned int status, const char *reason, struct stream *s);
void htx_check_request_for_cacheability(struct stream *s, struct channel *req);
void htx_check_response_for_cacheability(struct stream *s, struct channel *res);
int htx_send_name_header(struct stream *s, struct proxy *be, const char *srv_name);
void htx_perform_server_redirect(struct stream *s, struct stream_interface *si);
void htx_server_error(struct stream *s, struct stream_interface *si, int err, int finst, const struct buffer *msg);
void htx_reply_and_close(struct stream *s, short status, struct buffer *msg);
void htx_return_srv_error(struct stream *s, struct stream_interface *si);
struct buffer *htx_error_message(struct stream *s);

struct http_txn *http_alloc_txn(struct stream *s);
void http_init_txn(struct stream *s);
void http_end_txn(struct stream *s);
void http_reset_txn(struct stream *s);

/* for debugging, reports the HTTP/1 message state name (legacy version) */
static inline const char *h1_msg_state_str(enum h1_state msg_state)
{
	switch (msg_state) {
	case HTTP_MSG_RQBEFORE:    return "MSG_RQBEFORE";
	case HTTP_MSG_RPBEFORE:    return "MSG_RPBEFORE";
	case HTTP_MSG_ERROR:       return "MSG_ERROR";
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

#endif /* _PROTO_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
