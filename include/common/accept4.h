/*
 * include/common/accept4.h
 * Definition of the accept4 system call for older Linux libc.
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

#ifndef _COMMON_ACCEPT4_H
#define _COMMON_ACCEPT4_H

#if defined (__linux__) && defined(USE_ACCEPT4)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <common/syscall.h>

/* On recent Linux kernels, the accept4() syscall may be used to avoid an fcntl()
 * call to set O_NONBLOCK on the resulting socket. It was introduced in Linux
 * 2.6.28 and is not present in older libcs.
 */
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#if defined(USE_MY_ACCEPT4) || (!defined(SYS_ACCEPT4) && !defined(__NR_accept4))
#if defined(CONFIG_HAP_LINUX_VSYSCALL) && defined(__linux__) && defined(__i386__)
/* The syscall is redefined somewhere else */
extern int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
#elif ACCEPT4_USE_SOCKETCALL
static inline _syscall2(int, socketcall, int, call, unsigned long *, args);
static int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	unsigned long args[4];

	args[0] = (unsigned long)sockfd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)addrlen;
	args[3] = (unsigned long)flags;
	return socketcall(SYS_ACCEPT4, args);
}
#else
static inline _syscall4(int, accept4, int, sockfd, struct sockaddr *, addr, socklen_t *, addrlen, int, flags);
#endif /* VSYSCALL etc... */
#endif /* USE_MY_ACCEPT4 */
#endif /* __linux__ && USE_ACCEPT4 */
#endif /* _COMMON_ACCEPT4_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
