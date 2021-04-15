/*
 * include/haproxy/tinfo-t.h
 * Definitions of the thread_info structure.
 *
 * Copyright (C) 2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_TINFO_T_H
#define _HAPROXY_TINFO_T_H

#include <time.h>
#include <haproxy/api-t.h>
#include <haproxy/pool-t.h>

/* thread info flags, for ha_thread_info[].flags */
#define TI_FL_STUCK             0x00000001

/* This structure describes all the per-thread info we need. When threads are
 * disabled, it contains the same info for the single running thread (except
 * the pthread identifier which does not exist).
 */
struct thread_info {
	__decl_thread(pthread_t pthread);
	clockid_t clock_id;
	timer_t wd_timer;          /* valid timer or TIMER_INVALID if not set */
	uint64_t prev_cpu_time;    /* previous per thread CPU time */
	uint64_t prev_mono_time;   /* previous system wide monotonic time  */
	unsigned int idle_pct;     /* idle to total ratio over last sample (percent) */
	unsigned int flags;        /* thread info flags, TI_FL_* */

#ifdef CONFIG_HAP_POOLS
	struct list pool_lru_head;                         /* oldest objects   */
#endif
	struct list buffer_wq;     /* buffer waiters */
	struct list streams;       /* list of streams attached to this thread */

	/* pad to cache line (64B) */
	char __pad[0];            /* unused except to check remaining room */
	char __end[0] __attribute__((aligned(64)));
};

#endif /* _HAPROXY_TINFO_T_H */
