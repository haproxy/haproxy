/*
 * include/haproxy/tinfo.h
 * Export of ha_thread_info[] and ti pointer.
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

#ifndef _HAPROXY_TINFO_H
#define _HAPROXY_TINFO_H

#include <haproxy/api.h>
#include <haproxy/tinfo-t.h>

/* the struct is in thread.c */
extern struct thread_info ha_thread_info[MAX_THREADS];
extern THREAD_LOCAL struct thread_info *ti; /* thread_info for the current thread */

/* Retrieves the opaque pthread_t of thread <thr> cast to an unsigned long long
 * since POSIX took great care of not specifying its representation, making it
 * hard to export for post-mortem analysis. For this reason we copy it into a
 * union and will use the smallest scalar type at least as large as its size,
 * which will keep endianness and alignment for all regular sizes. As a last
 * resort we end up with a long long ligned to the first bytes in memory, which
 * will be endian-dependent if pthread_t is larger than a long long (not seen
 * yet).
 */
static inline unsigned long long ha_get_pthread_id(unsigned int thr)
{
#ifdef USE_THREAD
	union {
		pthread_t t;
		unsigned long long ll;
		unsigned int i;
		unsigned short s;
		unsigned char c;
	} u = { 0 };

	u.t = ha_thread_info[thr].pthread;

	if (sizeof(u.t) <= sizeof(u.c))
		return u.c;
	else if (sizeof(u.t) <= sizeof(u.s))
		return u.s;
	else if (sizeof(u.t) <= sizeof(u.i))
		return u.i;
	return u.ll;
#else
	return 0;
#endif
}

#endif /* _HAPROXY_TINFO_H */
