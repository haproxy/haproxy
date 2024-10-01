/*
 * include/haproxy/log.h
 * This file contains definitions of log-related functions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_LOG_H
#define _HAPROXY_LOG_H

#include <syslog.h>

#include <haproxy/api.h>
#include <haproxy/log-t.h>
#include <haproxy/pool-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/stream.h>

extern struct pool_head *pool_head_requri;
extern struct pool_head *pool_head_uniqueid;

extern const char *log_levels[];
extern char *log_format;
extern char httpclient_log_format[];
extern char default_tcp_log_format[];
extern char clf_tcp_log_format[];
extern char default_http_log_format[];
extern char clf_http_log_format[];
extern char default_https_log_format[];

extern char default_rfc5424_sd_log_format[];

extern const char sess_term_cond[];
extern const char sess_fin_state[];

extern unsigned int dropped_logs;

/* lof forward proxy list */
extern struct proxy *cfg_log_forward;

extern THREAD_LOCAL char *logline;
extern THREAD_LOCAL char *logline_rfc5424;

/* global syslog message counter */
extern int cum_log_messages;

/* syslog UDP message handler */
void syslog_fd_handler(int fd);

/* Initialize/Deinitialize log buffers used for syslog messages */
int init_log_buffers(void);
void deinit_log_buffers(void);

const char *log_orig_to_str(enum log_orig_id orig);
int log_orig_proxy(enum log_orig_id orig, struct proxy *px);

void lf_expr_init(struct lf_expr *expr);
int lf_expr_dup(const struct lf_expr *orig, struct lf_expr *dest);
void lf_expr_xfer(struct lf_expr *src, struct lf_expr *dst);
void lf_expr_deinit(struct lf_expr *expr);
static inline int lf_expr_isempty(const struct lf_expr *expr)
{
	return !(expr->flags & LF_FL_COMPILED) || LIST_ISEMPTY(&expr->nodes.list);
}
int lf_expr_compile(struct lf_expr *lf_expr, struct arg_list *al, int options, int cap, char **err);
int lf_expr_postcheck(struct lf_expr *lf_expr, struct proxy *px, char **err);

/* Deinitialize log buffers used for syslog messages */
void free_logformat_list(struct list *fmt);
void free_logformat_node(struct logformat_node *node);

/* helper to build log_orig struct from known id and flags values */
static inline struct log_orig log_orig(enum log_orig_id id, uint16_t flags)
{
	struct log_orig orig;

	orig.id = id;
	orig.flags = flags;
	return orig;
}

/* build a log line for the session and an optional stream */
int sess_build_logline_orig(struct session *sess, struct stream *s, char *dst, size_t maxsize,
                            struct lf_expr *lf_expr, struct log_orig orig);

/* wrapper for sess_build_logline_orig(), uses LOG_ORIG_UNSPEC log origin */
static inline int sess_build_logline(struct session *sess, struct stream *s, char *dst, size_t maxsize,
                                     struct lf_expr *lf_expr)
{
	return sess_build_logline_orig(sess, s, dst, maxsize, lf_expr,
	                               log_orig(LOG_ORIG_UNSPEC, LOG_ORIG_FL_NONE));
}

/* Parse a "do_log" action. It doesn't take any argument
 * May be used from places where per-context actions are usually registered
 */
enum act_parse_ret do_log_parse_act(enum log_orig_id id,
                                    const char **args, int *orig_arg, struct proxy *px,
                                    struct act_rule *rule, char **err);

/* opportunistic log when session already exists (<s> may be null) */
void do_log(struct session *sess, struct stream *s, struct log_orig origin);

/*
 * send a log for the stream when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
void strm_log(struct stream *s, struct log_orig origin);

/* send an error log for the session, embryonic version should be used
 * when the log is emitted for a session which is still in embryonic state
 * (originating from a connection) and requires special handling.
 */
void _sess_log(struct session *sess, int embryonic);
static inline void sess_log(struct session *sess)
{
	_sess_log(sess, 0);
}
static inline void sess_log_embryonic(struct session *sess)
{
	_sess_log(sess, 1);
}

/* send a applicative log with custom list of loggers */
void app_log(struct list *loggers, struct buffer *tag, int level, const char *format, ...)
	__attribute__ ((format(printf, 4, 5)));

/*
 * add to the logformat linked list
 */
int add_to_logformat_list(char *start, char *end, int type, struct lf_expr *lf_expr, char **err);

ssize_t syslog_applet_append_event(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len);

/*
 * Parse the log_format string and fill a linked list.
 * Refer to source file for details
 */
int parse_logformat_string(const char *str, struct proxy *curproxy, struct lf_expr *lf_expr, int options, int cap, char **err);

int postresolve_logger_list(struct proxy *px, struct list *loggers, const char *section, const char *section_name);

struct logger *dup_logger(struct logger *def);
void free_logger(struct logger *logger);
void deinit_log_target(struct log_target *target);
struct log_profile *log_profile_find_by_name(const char *name);
enum log_orig_id log_orig_register(const char *name);

/* Parse "log" keyword and update the linked list. */
int parse_logger(char **args, struct list *loggers, int do_del, const char *file, int linenum, char **err);

/*
 * This function adds a header to the message and sends the syslog message
 * using a printf format string
 */
void send_log(struct proxy *p, int level, const char *format, ...)
	__attribute__ ((format(printf, 3, 4)));

/*
 * returns log format for <fmt> or LOG_FORMAT_UNSPEC if not found.
 */
enum log_fmt get_log_format(const char *fmt);

/*
 * returns log level for <lev> or -1 if not found.
 */
int get_log_level(const char *lev);

/*
 * returns log facility for <fac> or -1 if not found.
 */
int get_log_facility(const char *fac);

/*
 * Function to handle log header building (exported for sinks)
 */
char *update_log_hdr_rfc5424(const time_t time, suseconds_t frac);
char *update_log_hdr(const time_t time);
char * get_format_pid_sep1(int format, size_t *len);
char * get_format_pid_sep2(int format, size_t *len);

/*
 * Builds a log line for the stream (must be valid).
 */
static inline int build_logline_orig(struct stream *s, char *dst, size_t maxsize,
                                     struct lf_expr *lf_expr, struct log_orig orig)
{
	return sess_build_logline_orig(strm_sess(s), s, dst, maxsize, lf_expr, orig);
}

/*
 * Wrapper for build_logline_orig, uses LOG_ORIG_UNSPEC log origin
 */
static inline int build_logline(struct stream *s, char *dst, size_t maxsize, struct lf_expr *lf_expr)
{
	return build_logline_orig(s, dst, maxsize, lf_expr,
	                          log_orig(LOG_ORIG_UNSPEC, LOG_ORIG_FL_NONE));
}

struct ist *build_log_header(struct log_header hdr, size_t *nbelem);

/*
 * lookup log forward proxy by name
 * Returns NULL if no proxy found.
 */
static inline struct proxy *log_forward_by_name(const char *name)
{
	struct proxy *px = cfg_log_forward;

	while (px) {
		if (strcmp(px->id, name) == 0)
			return px;
		px = px->next;
	}
	return NULL;
}

#endif /* _HAPROXY_LOG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
