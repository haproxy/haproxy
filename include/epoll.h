/*
 * Those constants were found both in glibc and in the Linux kernel.
 * They are provided here because the epoll() syscall is featured in
 * some kernels but in not often included in the glibc, so it needs
 * just a basic definition.
 */

#include <linux/unistd.h>
#include <stdint.h>

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
#else
#warning unsupported architecture, guessing __NR_epoll_create=254 like x86...
#define __NR_epoll_create 254
#define __NR_epoll_ctl    255
#define __NR_epoll_wait   256
#endif

_syscall1 (int, epoll_create, int, size);
_syscall4 (int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event);
_syscall4 (int, epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout);
