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
#include <types/log.h>
#include <types/proxy.h>
#include <types/stream.h>

extern struct pool_head *pool2_requri;
extern struct pool_head *pool2_uniqueid;

extern char *log_format;
extern char default_tcp_log_format[];
extern char default_http_log_format[];
extern char clf_http_log_format[];
extern char *logline;


int build_logline(struct stream *s, char *dst, size_t maxsize, struct list *list_format);

/*
 * send a log for the stream when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
void strm_log(struct stream *s);

/*
 * Parse args in a logformat_var
 */
int parse_logformat_var_args(char *args, struct logformat_node *node);

/*
 * Parse a variable '%varname' or '%{args}varname' in log-format
 *
 */
int parse_logformat_var(char *arg, int arg_len, char *var, int var_len, struct proxy *curproxy, struct list *list_format, int *defoptions);

/*
 * add to the logformat linked list
 */
void add_to_logformat_list(char *start, char *end, int type, struct list *list_format);

/*
 * Parse the log_format string and fill a linked list.
 * Variable name are preceded by % and composed by characters [a-zA-Z0-9]* : %varname
 * You can set arguments using { } : %{many arguments}varname
 */
void parse_logformat_string(const char *str, struct proxy *curproxy, struct list *list_format, int options, int cap, const char *file, int line);
/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void Alert(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));

/*
 * Displays the message on stderr with the date and pid.
 */
void Warning(const char *fmt, ...)
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

void __send_log(struct proxy *p, int level, char *message, size_t size);

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
 * Return the adress of the \0 character, or NULL on error
 */
char *lf_text_len(char *dst, const char *src, size_t len, size_t size, struct logformat_node *node);

/*
 * Write a IP adress to the log string
 * +X option write in hexadecimal notation, most signifant byte on the left
 */
char *lf_ip(char *dst, struct sockaddr *sockaddr, size_t size, struct logformat_node *node);

/*
 * Write a port to the log
 * +X option write in hexadecimal notation, most signifant byte on the left
 */
char *lf_port(char *dst, struct sockaddr *sockaddr, size_t size, struct logformat_node *node);


#endif /* _PROTO_LOG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
