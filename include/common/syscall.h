/*
 * include/common/syscall.h
 * Redefinition of some missing OS-specific system calls.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


#ifndef _COMMON_SYSCALL_H
#define _COMMON_SYSCALL_H

#ifdef __linux__

#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

/* On Linux, _syscall macros were removed after 2.6.18, but we still prefer
 * them because syscall() is buggy on old libcs. If _syscall is not defined,
 * we're on a recent kernel with a recent libc and we should be safe, so we
 * emulate is using syscall().
 */
#ifndef _syscall1
#define _syscall1(tr, nr, t1, n1)              \
	tr nr(t1 n1) {	                       \
		return syscall(__NR_##nr, n1); \
	}
#endif

#ifndef _syscall2
#define _syscall2(tr, nr, t1, n1, t2, n2)          \
	tr nr(t1 n1, t2 n2) {                      \
		return syscall(__NR_##nr, n1, n2); \
	}
#endif

#ifndef _syscall3
#define _syscall3(tr, nr, t1, n1, t2, n2, t3, n3)      \
	tr nr(t1 n1, t2 n2, t3 n3) {                   \
		return syscall(__NR_##nr, n1, n2, n3); \
	}
#endif

#ifndef _syscall4
#define _syscall4(tr, nr, t1, n1, t2, n2, t3, n3, t4, n4)  \
	tr nr(t1 n1, t2 n2, t3 n3, t4 n4) {                \
		return syscall(__NR_##nr, n1, n2, n3, n4); \
	}
#endif

#ifndef _syscall5
#define _syscall5(tr, nr, t1, n1, t2, n2, t3, n3, t4, n4, t5, n5) \
	tr nr(t1 n1, t2 n2, t3 n3, t4 n4, t5 n5) {                \
		return syscall(__NR_##nr, n1, n2, n3, n4, n5);    \
	}
#endif

#ifndef _syscall6
#define _syscall6(tr, nr, t1, n1, t2, n2, t3, n3, t4, n4, t5, n5, t6, n6) \
	tr nr(t1 n1, t2 n2, t3 n3, t4 n4, t5 n5, t6 n6) {                 \
		return syscall(__NR_##nr, n1, n2, n3, n4, n5, n6);        \
	}
#endif


/* Define some syscall numbers that are sometimes needed */

/* Epoll was provided as a patch for 2.4 for a long time and was not always
 * exported as a known sysctl number by libc.
 */
#if !defined(__NR_epoll_ctl)
#if defined(__powerpc__) || defined(__powerpc64__)
#define __NR_epoll_create 236
#define __NR_epoll_ctl    237
#define __NR_epoll_wait   238
#elif defined(__sparc__) || defined(__sparc64__)
#define __NR_epoll_create 193
#define __NR_epoll_ctl    194
#define __NR_epoll_wait   195
#elif defined(__x86_64__)
#define __NR_epoll_create 213
#define __NR_epoll_ctl    214
#define __NR_epoll_wait   215
#elif defined(__alpha__)
#define __NR_epoll_create 407
#define __NR_epoll_ctl    408
#define __NR_epoll_wait   409
#elif defined (__i386__)
#define __NR_epoll_create 254
#define __NR_epoll_ctl    255
#define __NR_epoll_wait   256
#elif defined (__s390__) || defined(__s390x__)
#define __NR_epoll_create 249
#define __NR_epoll_ctl    250
#define __NR_epoll_wait   251
#endif /* $arch */
#endif /* __NR_epoll_ctl */

/* splice is even more recent than epoll. It appeared around 2.6.18 but was
 * not in libc for a while.
 */
#ifndef __NR_splice
#if defined(__powerpc__) || defined(__powerpc64__)
#define __NR_splice             283
#elif defined(__sparc__) || defined(__sparc64__)
#define __NR_splice             232
#elif defined(__x86_64__)
#define __NR_splice             275
#elif defined(__alpha__)
#define __NR_splice             468
#elif defined (__i386__)
#define __NR_splice             313
#elif defined(__s390__) || defined(__s390x__)
#define __NR_splace		306
#endif /* $arch */
#endif /* __NR_splice */

/* accept4() appeared in Linux 2.6.28, but it might not be in all libcs. Some
 * archs have it as a native syscall, other ones use the socketcall instead.
 */
#ifndef __NR_accept4
#if defined(__x86_64__)
#define __NR_accept4            288
#elif defined(__sparc__) || defined(__sparc64__)
#define __NR_accept4            323
#elif defined(__arm__) || defined(__thumb__)
#define __NR_accept4            (__NR_SYSCALL_BASE+366)
#else
#define ACCEPT4_USE_SOCKETCALL    1
#ifndef SYS_ACCEPT4
#define SYS_ACCEPT4              18
#endif /* SYS_ACCEPT4 */
#endif /* $arch */
#endif /* __NR_accept4 */

#endif /* __linux__ */
#endif /* _COMMON_SYSCALL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
