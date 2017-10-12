/*
 * functions about threads.
 *
 * Copyright (C) 2017 Christopher Fauet - cfaulet@haproxy.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/hathreads.h>

THREAD_LOCAL unsigned int tid     = 0;
THREAD_LOCAL unsigned int tid_bit = (1UL << 0);

#ifdef USE_THREAD

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
struct lock_stat lock_stats[LOCK_LABELS];
#endif

__attribute__((constructor))
static void __hathreads_init(void)
{

#if defined(DEBUG_THREAD) || defined(DEBUG_FULL)
	memset(lock_stats, 0, sizeof(lock_stats));
#endif

}

#endif
