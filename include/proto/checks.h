/*
  include/proto/checks.h
  Functions prototypes for the checks.

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
  
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

#ifndef _PROTO_CHECKS_H
#define _PROTO_CHECKS_H

#include <types/task.h>
#include <common/config.h>

const char *get_check_status_description(short check_status);
const char *get_check_status_info(short check_status);
int start_checks();
void __health_adjust(struct server *s, short status);
int trigger_resolution(struct server *s);

extern struct data_cb check_conn_cb;

/* Use this one only. This inline version only ensures that we don't
 * call the function when the observe mode is disabled.
 */
static inline void health_adjust(struct server *s, short status)
{
	/* return now if observing nor health check is not enabled */
	if (!s->observe || !s->check.task)
		return;

	return __health_adjust(s, status);
}

const char *init_check(struct check *check, int type);
void free_check(struct check *check);

void send_email_alert(struct server *s, int priority, const char *format, ...)
	__attribute__ ((format(printf, 3, 4)));
#endif /* _PROTO_CHECKS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
