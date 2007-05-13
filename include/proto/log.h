/*
  include/proto/log.h
  This file contains definitions of log-related functions, structures,
  and macros.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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
#include <types/session.h>

extern struct pool_head *pool2_requri;

/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void Alert(char *fmt, ...);

/*
 * Displays the message on stderr with the date and pid.
 */
void Warning(char *fmt, ...);

/*
 * Displays the message on <out> only if quiet mode is not set.
 */
void qfprintf(FILE *out, char *fmt, ...);

/*
 * This function sends a syslog message to both log servers of a proxy,
 * or to global log servers if the proxy is NULL.
 * It also tries not to waste too much time computing the message header.
 * It doesn't care about errors nor does it report them.
 */
void send_log(struct proxy *p, int level, char *message, ...);

/*
 * send a log for the session when we have enough info about it
 */
void tcp_sess_log(struct session *s);

/*
 * returns log level for <lev> or -1 if not found.
 */
int get_log_level(const char *lev);

/*
 * returns log facility for <fac> or -1 if not found.
 */
int get_log_facility(const char *fac);

#endif /* _PROTO_LOG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
