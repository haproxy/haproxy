/*
 * include/common/epoll.h
 * epoll definitions for older libc.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

/*
 * Those constants were found both in glibc and in the Linux kernel.
 * They are provided here because the epoll() syscall is featured in
 * some kernels but in not often included in the glibc, so it needs
 * just a basic definition.
 */

#ifndef _COMMON_EPOLL_H
#define _COMMON_EPOLL_H

#if defined (__linux__) && defined(USE_EPOLL)

#ifndef USE_MY_EPOLL
#include <sys/epoll.h>
#else

#include <errno.h>
#include <sys/types.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <common/config.h>
#include <common/syscall.h>

/* epoll_ctl() commands */
#ifndef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#endif

/* events types (bit fields) */
#ifndef EPOLLIN
#define EPOLLIN 1
#define EPOLLPRI 2
#define EPOLLOUT 4
#define EPOLLERR 8
#define EPOLLHUP 16
#define EPOLLONESHOT (1 << 30)
#define EPOLLET (1 << 31)
#endif

struct epoll_event {
	uint32_t events;
	union {
		void *ptr;
		int fd;
		uint32_t u32;
		uint64_t u64;
	} data;
};

#if defined(USE_LINUX_VSYSCALL) && defined(__linux__) && defined(__i386__)
/* Those are our self-defined functions */
extern int epoll_create(int size);
extern int epoll_ctl(int epfd, int op, int fd, struct epoll_event * event);
extern int epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout);
#else

/* We'll define a syscall, so for this we need __NR_splice. It should have
 * been provided by syscall.h.
 */
#if !defined(__NR_epoll_ctl)
#warning unsupported architecture, guessing __NR_epoll_create=254 like x86...
#define __NR_epoll_create 254
#define __NR_epoll_ctl    255
#define __NR_epoll_wait   256
#endif /* __NR_epoll_ctl */

static inline _syscall1 (int, epoll_create, int, size);
static inline _syscall4 (int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event);
static inline _syscall4 (int, epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout);
#endif /* VSYSCALL */

#endif /* USE_MY_EPOLL */

#endif /* __linux__ && USE_EPOLL */

#endif /* _COMMON_EPOLL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
