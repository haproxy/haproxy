/*
  include/common/debug.h
  This files contains some macros to help debugging.

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

#ifndef _COMMON_DEBUG_H
#define _COMMON_DEBUG_H

#include <haproxy/api.h>
#include <common/memory.h>

struct task;
struct buffer;
extern volatile unsigned long threads_to_dump;
extern unsigned int debug_commands_issued;
void ha_task_dump(struct buffer *buf, const struct task *task, const char *pfx);
void ha_thread_dump(struct buffer *buf, int thr, int calling_tid);
void ha_thread_dump_all_to_trash();
void ha_panic();

/* This one is useful to automatically apply poisonning on an area returned
 * by malloc(). Only "p_" is required to make it work, and to define a poison
 * byte using -dM.
 */
static inline void *p_malloc(size_t size)
{
	void *ret = malloc(size);
	if (mem_poison_byte >= 0 && ret)
		memset(ret, mem_poison_byte, size);
	return ret;
}

#endif /* _COMMON_DEBUG_H */
