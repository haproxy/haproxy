/*
 * include/common/splice.h
 * Splice definition for older Linux libc.
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
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

#ifndef _COMMON_SPLICE_H
#define _COMMON_SPLICE_H

#if defined (__linux__) && defined(CONFIG_HAP_LINUX_SPLICE)

#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <common/syscall.h>

/* On recent Linux kernels, the splice() syscall may be used for faster data copy.
 * But it's not always defined on some OS versions, and it even happens that some
 * definitions are wrong with some glibc due to an offset bug in syscall().
 */

#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE           0x1
#endif

#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK       0x2
#endif

#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE           0x4
#endif

#if defined(USE_MY_SPLICE)

#if defined(CONFIG_HAP_LINUX_VSYSCALL) && defined(__linux__) && defined(__i386__)
/* The syscall is redefined somewhere else */
extern int splice(int fdin, loff_t *off_in, int fdout, loff_t *off_out, size_t len, unsigned long flags);
#else

/* We'll define a syscall, so for this we need __NR_splice. It should have
 * been provided by syscall.h.
 */
#ifndef __NR_splice
#warning unsupported architecture, guessing __NR_splice=313 like x86...
#define __NR_splice             313
#endif /* __NR_splice */

static inline _syscall6(int, splice, int, fdin, loff_t *, off_in, int, fdout, loff_t *, off_out, size_t, len, unsigned long, flags);
#endif /* VSYSCALL */

#else
/* use the system's definition */
#include <fcntl.h>

#endif /* USE_MY_SPLICE */

#endif /* __linux__ && CONFIG_HAP_LINUX_SPLICE */

#endif /* _COMMON_SPLICE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
