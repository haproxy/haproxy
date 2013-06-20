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
#include <types/proto_http.h>
#include <types/session.h>
#include <types/task.h>

/*
 * some macros used for the request parsing.
 * from RFC2616:
 *   CTL                 = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
 *   SEP                 = one of the 17 defined separators or SP or HT
 *   LWS                 = CR, LF, SP or HT
 *   SPHT                = SP or HT. Use this macro and not a boolean expression for best speed.
 *   CRLF                = CR or LF. Use this macro and not a boolean expression for best speed.
 *   token               = any CHAR except CTL or SEP. Use this macro and not a boolean expression for best speed.
 *
 * added for ease of use:
 *   ver_token           = 'H', 'P', 'T', '/', '.', and digits.
 */

extern const char http_is_ctl[256];
extern const char http_is_sep[256];
extern const char http_is_lws[256];
extern const char http_is_spht[256];
extern const char http_is_crlf[256];
extern const char http_is_token[256];
extern const char http_is_ver_token[256];

extern const int http_err_codes[HTTP_ERR_SIZE];
extern struct chunk http_err_chunks[HTTP_ERR_SIZE];
extern const char *HTTP_302;
extern const char *HTTP_303;
extern char *get_http_auth_buff;

#define HTTP_IS_CTL(x)   (http_is_ctl[(unsigned char)(x)])
#define HTTP_IS_SEP(x)   (http_is_sep[(unsigned char)(x)])
#define HTTP_IS_LWS(x)   (http_is_lws[(unsigned char)(x)])
#define HTTP_IS_SPHT(x)  (http_is_spht[(unsigned char)(x)])
#define HTTP_IS_CRLF(x)  (http_is_crlf[(unsigned char)(x)])
#define HTTP_IS_TOKEN(x) (http_is_token[(unsigned char)(x)])
#define HTTP_IS_VER_TOKEN(x) (http_is_ver_token[(unsigned char)(x)])

int process_cli(struct session *t);
int process_srv_data(struct session *t);
int process_srv_conn(struct session *t);
int http_wait_for_request(struct session *s, struct channel *req, int an_bit);
int http_process_req_common(struct session *s, struct channel *req, int an_bit, struct proxy *px);
int http_process_request(struct session *t, struct channel *req, int an_bit);
int http_process_tarpit(struct session *s, struct channel *req, int an_bit);
int http_process_request_body(struct session *s, struct channel *req, int an_bit);
int http_send_name_header(struct http_txn *txn, struct proxy* be, const char* svr_name);
int http_wait_for_response(struct session *s, struct channel *rep, int an_bit);
int http_process_res_common(struct session *t, struct channel *rep, int an_bit, struct proxy *px);
int http_request_forward_body(struct session *s, struct channel *req, int an_bit);
int http_response_forward_body(struct session *s, struct channel *res, int an_bit);

void debug_hdr(const char *dir, struct session *t, const char *start, const char *end);
void get_srv_from_appsession(struct session *t, const char *begin, int len);
int apply_filter_to_req_headers(struct session *t, struct channel *req, struct hdr_exp *exp);
int apply_filter_to_req_line(struct session *t, struct channel *req, struct hdr_exp *exp);
int apply_filters_to_request(struct session *s, struct channel *req, struct proxy *px);
int apply_filters_to_response(struct session *t, struct channel *rtr, struct proxy *px);
void manage_client_side_appsession(struct session *t, const char *buf, int len);
void manage_client_side_cookies(struct session *t, struct channel *req);
void manage_server_side_cookies(struct session *t, struct channel *rtr);
void check_response_for_cacheability(struct session *t, struct channel *rtr);
int stats_check_uri(struct stream_interface *si, struct http_txn *txn, struct proxy *backend);
void init_proto_http();
int http_find_full_header2(const char *name, int len,
                           char *sol, struct hdr_idx *idx,
                           struct hdr_ctx *ctx);
int http_find_header2(const char *name, int len,
		      char *sol, struct hdr_idx *idx,
		      struct hdr_ctx *ctx);
void http_sess_log(struct session *s);
void http_perform_server_redirect(struct session *s, struct stream_interface *si);
void http_return_srv_error(struct session *s, struct stream_interface *si);
void http_capture_bad_message(struct error_snapshot *es, struct session *s,
                              struct http_msg *msg,
			      int state, struct proxy *other_end);
unsigned int http_get_hdr(const struct http_msg *msg, const char *hname, int hlen,
			  struct hdr_idx *idx, int occ,
			  struct hdr_ctx *ctx, char **vptr, int *vlen);

void http_init_txn(struct session *s);
void http_end_txn(struct session *s);
void http_reset_txn(struct session *s);

struct http_req_rule *parse_http_req_cond(const char **args, const char *file, int linenum, struct proxy *proxy);
struct http_res_rule *parse_http_res_cond(const char **args, const char *file, int linenum, struct proxy *proxy);
void free_http_req_rules(struct list *r);
struct chunk *http_error_message(struct session *s, int msgnum);
struct redirect_rule *http_parse_redirect_rule(const char *file, int line, struct proxy *curproxy,
                                               const char **args, char **errmsg);

/* to be used when contents change in an HTTP message */
#define http_msg_move_end(msg, bytes) do { \
		unsigned int _bytes = (bytes);	\
		(msg)->next += (_bytes);	\
		(msg)->sov += (_bytes);		\
		(msg)->eoh += (_bytes);		\
	} while (0)

/* for debugging, reports the HTTP message state name */
static inline const char *http_msg_state_str(int msg_state)
{
	switch (msg_state) {
	case HTTP_MSG_RQBEFORE:    return "MSG_RQBEFORE";
	case HTTP_MSG_RQBEFORE_CR: return "MSG_RQBEFORE_CR";
	case HTTP_MSG_RQMETH:      return "MSG_RQMETH";
	case HTTP_MSG_RQMETH_SP:   return "MSG_RQMETH_SP";
	case HTTP_MSG_RQURI:       return "MSG_RQURI";
	case HTTP_MSG_RQURI_SP:    return "MSG_RQURI_SP";
	case HTTP_MSG_RQVER:       return "MSG_RQVER";
	case HTTP_MSG_RQLINE_END:  return "MSG_RQLINE_END";
	case HTTP_MSG_RPBEFORE:    return "MSG_RPBEFORE";
	case HTTP_MSG_RPBEFORE_CR: return "MSG_RPBEFORE_CR";
	case HTTP_MSG_RPVER:       return "MSG_RPVER";
	case HTTP_MSG_RPVER_SP:    return "MSG_RPVER_SP";
	case HTTP_MSG_RPCODE:      return "MSG_RPCODE";
	case HTTP_MSG_RPCODE_SP:   return "MSG_RPCODE_SP";
	case HTTP_MSG_RPREASON:    return "MSG_RPREASON";
	case HTTP_MSG_RPLINE_END:  return "MSG_RPLINE_END";
	case HTTP_MSG_HDR_FIRST:   return "MSG_HDR_FIRST";
	case HTTP_MSG_HDR_NAME:    return "MSG_HDR_NAME";
	case HTTP_MSG_HDR_COL:     return "MSG_HDR_COL";
	case HTTP_MSG_HDR_L1_SP:   return "MSG_HDR_L1_SP";
	case HTTP_MSG_HDR_L1_LF:   return "MSG_HDR_L1_LF";
	case HTTP_MSG_HDR_L1_LWS:  return "MSG_HDR_L1_LWS";
	case HTTP_MSG_HDR_VAL:     return "MSG_HDR_VAL";
	case HTTP_MSG_HDR_L2_LF:   return "MSG_HDR_L2_LF";
	case HTTP_MSG_HDR_L2_LWS:  return "MSG_HDR_L2_LWS";
	case HTTP_MSG_LAST_LF:     return "MSG_LAST_LF";
	case HTTP_MSG_ERROR:       return "MSG_ERROR";
	case HTTP_MSG_BODY:        return "MSG_BODY";
	case HTTP_MSG_100_SENT:    return "MSG_100_SENT";
	case HTTP_MSG_CHUNK_SIZE:  return "MSG_CHUNK_SIZE";
	case HTTP_MSG_DATA:        return "MSG_DATA";
	case HTTP_MSG_CHUNK_CRLF:  return "MSG_CHUNK_CRLF";
	case HTTP_MSG_TRAILERS:    return "MSG_TRAILERS";
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
