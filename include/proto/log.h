/*
  include/proto/log.h
  This file contains definitions of log-related functions, structures,
  and macros.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_LOG_H
#define _PROTO_LOG_H

#include <stdio.h>
#include <syslog.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/hathreads.h>

#include <types/log.h>
#include <types/proxy.h>
#include <types/stream.h>

#include <proto/stream.h>

extern struct pool_head *pool_head_requri;
extern struct pool_head *pool_head_uniqueid;

extern char *log_format;
extern char default_tcp_log_format[];
extern char default_http_log_format[];
extern char clf_http_log_format[];

extern char default_rfc5424_sd_log_format[];

extern unsigned int dropped_logs;

extern THREAD_LOCAL char *logheader;
extern THREAD_LOCAL char *logheader_rfc5424;
extern THREAD_LOCAL char *logline;
extern THREAD_LOCAL char *logline_rfc5424;


/*
 * Test if <idx> index numbered from 0 is in <rg> range with low and high
 * limits of indexes numbered from 1.
 */
static inline int in_smp_log_range(struct smp_log_range *rg, unsigned int idx)
{
       if (idx + 1 <= rg->high && idx + 1 >= rg->low)
               return 1;
       return 0;
}

/* Initialize/Deinitialize log buffers used for syslog messages */
int init_log_buffers();
void deinit_log_buffers();

/*
 * Builds a log line.
 */
int sess_build_logline(struct session *sess, struct stream *s, char *dst, size_t maxsize, struct list *list_format);

static inline int build_logline(struct stream *s, char *dst, size_t maxsize, struct list *list_format)
{
	return sess_build_logline(strm_sess(s), s, dst, maxsize, list_format);
}


/*
 * send a log for the stream when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
void strm_log(struct stream *s);
void sess_log(struct session *sess);

/* send a applicative log with custom list of log servers */
void app_log(struct list *logsrvs, struct buffer *tag, int level, const char *format, ...)
	__attribute__ ((format(printf, 4, 5)));

/*
 * add to the logformat linked list
 */
int add_to_logformat_list(char *start, char *end, int type, struct list *list_format, char **err);

/*
 * Parse the log_format string and fill a linked list.
 * Variable name are preceded by % and composed by characters [a-zA-Z0-9]* : %varname
 * You can set arguments using { } : %{many arguments}varname
 */
int parse_logformat_string(const char *str, struct proxy *curproxy, struct list *list_format, int options, int cap, char **err);

/* Parse "log" keyword and update the linked list. */
int parse_logsrv(char **args, struct list *logsrvs, int do_del, char **err);

/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void ha_alert(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));

/*
 * Displays the message on stderr with the date and pid.
 */
void ha_warning(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));

/*
 * Displays the message on stderr with the date and pid.
 */
void ha_notice(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));

/*
 * Displays the message on <out> only if quiet mode is not set.
 */
void qfprintf(FILE *out, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));

/*
 * This function adds a header to the message and sends the syslog message
 * using a printf format string
 */
void send_log(struct proxy *p, int level, const char *format, ...)
	__attribute__ ((format(printf, 3, 4)));

/*
 * This function sends a syslog message to both log servers of a proxy,
 * or to global log servers if the proxy is NULL.
 * It also tries not to waste too much time computing the message header.
 * It doesn't care about errors nor does it report them.
 */

void __send_log(struct list *logsrvs, struct buffer *tag, int level, char *message, size_t size, char *sd, size_t sd_size);

/*
 * returns log format for <fmt> or -1 if not found.
 */
int get_log_format(const char *fmt);

/*
 * returns log level for <lev> or -1 if not found.
 */
int get_log_level(const char *lev);

/*
 * returns log facility for <fac> or -1 if not found.
 */
int get_log_facility(const char *fac);

/*
 * Write a string in the log string
 * Take cares of quote options
 *
 * Return the address of the \0 character, or NULL on error
 */
char *lf_text_len(char *dst, const char *src, size_t len, size_t size, const struct logformat_node *node);

/*
 * Write a IP address to the log string
 * +X option write in hexadecimal notation, most signifant byte on the left
 */
char *lf_ip(char *dst, const struct sockaddr *sockaddr, size_t size, const struct logformat_node *node);

/*
 * Write a port to the log
 * +X option write in hexadecimal notation, most signifant byte on the left
 */
char *lf_port(char *dst, const struct sockaddr *sockaddr, size_t size, const struct logformat_node *node);


#endif /* _PROTO_LOG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
