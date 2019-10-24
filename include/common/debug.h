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

#include <common/config.h>
#include <common/memory.h>

#ifdef DEBUG_FULL
#define DPRINTF(x...) fprintf(x)
#else
#define DPRINTF(x...)
#endif

#ifdef DEBUG_FSM
#define FSM_PRINTF(x...) fprintf(x)
#else
#define FSM_PRINTF(x...)
#endif

/* This abort is more efficient than abort() because it does not mangle the
 * stack and stops at the exact location we need.
 */
#define ABORT_NOW() (*(volatile int*)1=0)

/* BUG_ON: complains if <cond> is true when DEBUG_STRICT or DEBUG_STRICT_NOCRASH
 * are set, does nothing otherwise. With DEBUG_STRICT in addition it immediately
 * crashes using ABORT_NOW() above.
 */
#if defined(DEBUG_STRICT) || defined(DEBUG_STRICT_NOCRASH)
#if defined(DEBUG_STRICT)
#define CRASH_NOW() ABORT_NOW()
#else
#define CRASH_NOW()
#endif

#define BUG_ON(cond) _BUG_ON(cond, __FILE__, __LINE__)
#define _BUG_ON(cond, file, line) __BUG_ON(cond, file, line)
#define __BUG_ON(cond, file, line)                                             \
	do {                                                                   \
		if (unlikely(cond)) {					       \
			const char msg[] = "\nFATAL: bug condition \"" #cond "\" matched at " file ":" #line "\n"; \
			(void)write(2, msg, strlen(msg));                      \
			CRASH_NOW();                                           \
		}                                                              \
	} while (0)
#else
#undef CRASH_NOW
#define BUG_ON(cond)
#endif

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
