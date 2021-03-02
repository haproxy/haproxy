/*
 * include/haproxy/extchecks.h
 * Functions prototypes for the external checks.
 *
 * Copyright 2000-2009,2020 Willy Tarreau <w@1wt.eu>
 * Copyright 2014 Horms Solutions Ltd, Simon Horman <horms@verge.net.au>
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

#ifndef _HAPROXY_EXTCHECK_H
#define _HAPROXY_EXTCHECK_H

#include <haproxy/check-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/task-t.h>

struct task *process_chk_proc(struct task *t, void *context, unsigned int state);
int prepare_external_check(struct check *check);
int init_pid_list(void);

int proxy_parse_extcheck(char **args, int section, struct proxy *curpx,
                         struct proxy *defpx, const char *file, int line,
                         char **errmsg);

int proxy_parse_external_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
                                   const char *file, int line);


#endif /* _HAPROXY_EXTCHECK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
