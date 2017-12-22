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
#include <types/action.h>
#include <types/proto_http.h>
#include <types/stream.h>
#include <types/task.h>
#include <proto/h1.h>

/*
 * some macros used for the request parsing.
 * from RFC7230:
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

extern const int http_err_codes[HTTP_ERR_SIZE];
extern struct chunk http_err_chunks[HTTP_ERR_SIZE];
extern const char *HTTP_302;
extern const char *HTTP_303;

int process_cli(struct stream *s);
int process_srv_data(struct stream *s);
int process_srv_conn(struct stream *s);
int http_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int http_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px);
int http_process_request(struct stream *s, struct channel *req, int an_bit);
int http_process_tarpit(struct stream *s, struct channel *req, int an_bit);
int http_wait_for_request_body(struct stream *s, struct channel *req, int an_bit);
int http_send_name_header(struct http_txn *txn, struct proxy* be, const char* svr_name);
int http_wait_for_response(struct stream *s, struct channel *rep, int an_bit);
int http_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px);
int http_request_forward_body(struct stream *s, struct channel *req, int an_bit);
int http_response_forward_body(struct stream *s, struct channel *res, int an_bit);
void http_msg_analyzer(struct http_msg *msg, struct hdr_idx *idx);
void http_txn_reset_req(struct http_txn *txn);
void http_txn_reset_res(struct http_txn *txn);

void debug_hdr(const char *dir, struct stream *s, const char *start, const char *end);
int apply_filter_to_req_headers(struct stream *s, struct channel *req, struct hdr_exp *exp);
int apply_filter_to_req_line(struct stream *s, struct channel *req, struct hdr_exp *exp);
int apply_filters_to_request(struct stream *s, struct channel *req, struct proxy *px);
int apply_filters_to_response(struct stream *s, struct channel *rtr, struct proxy *px);
void manage_client_side_cookies(struct stream *s, struct channel *req);
void manage_server_side_cookies(struct stream *s, struct channel *rtr);
void check_request_for_cacheability(struct stream *s, struct channel *chn);
void check_response_for_cacheability(struct stream *s, struct channel *rtr);
int stats_check_uri(struct stream_interface *si, struct http_txn *txn, struct proxy *backend);
void init_proto_http();
int http_find_full_header2(const char *name, int len,
                           char *sol, struct hdr_idx *idx,
                           struct hdr_ctx *ctx);
int http_find_header2(const char *name, int len,
		      char *sol, struct hdr_idx *idx,
		      struct hdr_ctx *ctx);
int http_find_next_header(char *sol, struct hdr_idx *idx,
                          struct hdr_ctx *ctx);
char *find_hdr_value_end(char *s, const char *e);
char *extract_cookie_value(char *hdr, const char *hdr_end, char *cookie_name,
                           size_t cookie_name_l, int list, char **value, int *value_l);
int http_header_match2(const char *hdr, const char *end, const char *name, int len);
int http_remove_header2(struct http_msg *msg, struct hdr_idx *idx, struct hdr_ctx *ctx);
int http_header_add_tail2(struct http_msg *msg, struct hdr_idx *hdr_idx, const char *text, int len);
int http_replace_req_line(int action, const char *replace, int len, struct proxy *px, struct stream *s);
void http_set_status(unsigned int status, const char *reason, struct stream *s);
int http_transform_header_str(struct stream* s, struct http_msg *msg, const char* name,
                              unsigned int name_len, const char *str, struct my_regex *re,
                              int action);
void inet_set_tos(int fd, const struct sockaddr_storage *from, int tos);
void http_perform_server_redirect(struct stream *s, struct stream_interface *si);
void http_return_srv_error(struct stream *s, struct stream_interface *si);
void http_capture_bad_message(struct proxy *proxy, struct error_snapshot *es, struct stream *s,
                              struct http_msg *msg,
			      enum h1_state state, struct proxy *other_end);
unsigned int http_get_hdr(const struct http_msg *msg, const char *hname, int hlen,
			  struct hdr_idx *idx, int occ,
			  struct hdr_ctx *ctx, char **vptr, int *vlen);
char *http_get_path(struct http_txn *txn);
const char *get_reason(unsigned int status);

struct http_txn *http_alloc_txn(struct stream *s);
void http_init_txn(struct stream *s);
void http_end_txn(struct stream *s);
void http_reset_txn(struct stream *s);
void http_end_txn_clean_session(struct stream *s);
void http_adjust_conn_mode(struct stream *s, struct http_txn *txn, struct http_msg *msg);

struct act_rule *parse_http_req_cond(const char **args, const char *file, int linenum, struct proxy *proxy);
struct act_rule *parse_http_res_cond(const char **args, const char *file, int linenum, struct proxy *proxy);
void free_http_req_rules(struct list *r);
void free_http_res_rules(struct list *r);
void http_reply_and_close(struct stream *s, short status, struct chunk *msg);
struct chunk *http_error_message(struct stream *s);
struct redirect_rule *http_parse_redirect_rule(const char *file, int linenum, struct proxy *curproxy,
                                               const char **args, char **errmsg, int use_fmt, int dir);
int smp_fetch_cookie(const struct arg *args, struct sample *smp, const char *kw, void *private);
int smp_fetch_base32(const struct arg *args, struct sample *smp, const char *kw, void *private);

enum http_meth_t find_http_meth(const char *str, const int len);

struct action_kw *action_http_req_custom(const char *kw);
struct action_kw *action_http_res_custom(const char *kw);
int val_hdr(struct arg *arg, char **err_msg);

int smp_prefetch_http(struct proxy *px, struct stream *s, unsigned int opt,
                  const struct arg *args, struct sample *smp, int req_vol);

enum act_return http_action_req_capture_by_id(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags);
enum act_return http_action_res_capture_by_id(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags);

int parse_qvalue(const char *qvalue, const char **end);

/* Note: these functions *do* modify the sample. Even in case of success, at
 * least the type and uint value are modified.
 */
#define CHECK_HTTP_MESSAGE_FIRST() \
	do { int r = smp_prefetch_http(smp->px, smp->strm, smp->opt, args, smp, 1); if (r <= 0) return r; } while (0)

#define CHECK_HTTP_MESSAGE_FIRST_PERM() \
	do { int r = smp_prefetch_http(smp->px, smp->strm, smp->opt, args, smp, 0); if (r <= 0) return r; } while (0)

static inline void http_req_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&http_req_keywords.list, &kw_list->list);
}

static inline void http_res_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&http_res_keywords.list, &kw_list->list);
}


/* to be used when contents change in an HTTP message */
#define http_msg_move_end(msg, bytes) do { \
		unsigned int _bytes = (bytes);	\
		(msg)->next += (_bytes);	\
		(msg)->sov += (_bytes);		\
		(msg)->eoh += (_bytes);		\
	} while (0)


/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's headers. The purpose is to be able to easily fetch
 * the message's beginning before headers are forwarded, as well as after.
 * The principle is that msg->eoh and msg->eol are immutable while msg->sov
 * equals the sum of the two before forwarding and is zero after forwarding,
 * so the difference cancels the rewinding.
 */
static inline int http_hdr_rewind(const struct http_msg *msg)
{
	return msg->eoh + msg->eol - msg->sov;
}

/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's URI. The purpose is to be able to easily fetch
 * the message's beginning before headers are forwarded, as well as after.
 */
static inline int http_uri_rewind(const struct http_msg *msg)
{
	return http_hdr_rewind(msg) - msg->sl.rq.u;
}

/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's BODY. The purpose is to be able to easily fetch
 * the message's beginning before headers are forwarded, as well as after.
 */
static inline int http_body_rewind(const struct http_msg *msg)
{
	return http_hdr_rewind(msg) - msg->eoh - msg->eol;
}

/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's DATA. The difference with the function above is that
 * if a chunk is present and has already been parsed, its size is skipped so
 * that the byte pointed to is the first byte of actual data. The function is
 * safe for use in state HTTP_MSG_DATA regardless of whether the headers were
 * already forwarded or not.
 */
static inline int http_data_rewind(const struct http_msg *msg)
{
	return http_body_rewind(msg) - msg->sol;
}

/* Return the maximum amount of bytes that may be read after the beginning of
 * the message body, according to the advertised length. The function is safe
 * for use between HTTP_MSG_BODY and HTTP_MSG_DATA regardless of whether the
 * headers were already forwarded or not.
 */
static inline int http_body_bytes(const struct http_msg *msg)
{
	int len;

	len = msg->chn->buf->i - msg->sov - msg->sol;
	if (len > msg->body_len)
		len = msg->body_len;
	return len;
}

#endif /* _PROTO_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
