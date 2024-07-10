/*
 * Handlers for process resources limits.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later.
 *
 */

#ifndef _HAPROXY_LIMITS_H
#define _HAPROXY_LIMITS_H
#include <sys/resource.h>

extern unsigned int rlim_fd_cur_at_boot;
extern unsigned int rlim_fd_max_at_boot;

/* handlers to manipulate system resources limits granted by OS to process and
 * to tie them up with the internal process limits
 */
int raise_rlim_nofile(struct rlimit *old_limit, struct rlimit *new_limit);

#endif /* _HAPROXY_LIMITS_H */
