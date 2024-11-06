/*
 * include/haproxy/debug.h
 * This files contains some macros to help debugging.
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

#ifndef _HAPROXY_DEBUG_H
#define _HAPROXY_DEBUG_H

struct task;
struct buffer;
extern unsigned int debug_commands_issued;
extern unsigned int warn_blocked_issued;

void ha_task_dump(struct buffer *buf, const struct task *task, const char *pfx);
void ha_thread_dump_one(int thr, int from_signal);
void ha_dump_backtrace(struct buffer *buf, const char *prefix, int dump);
void ha_backtrace_to_stderr(void);
void ha_panic(void);
void ha_stuck_warning(int thr);

void post_mortem_add_component(const char *name, const char *version,
			       const char *toolchain, const char *toolchain_opts,
			       const char *build_settings, const char *path);

#endif /* _HAPROXY_DEBUG_H */
