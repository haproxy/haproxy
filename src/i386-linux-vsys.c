/*
 * Fast system call support for x86 on Linux
 *
 * Copyright 2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Recent kernels support a faster syscall ABI on x86 using the VDSO page, but
 * some libc that are built for CPUs earlier than i686 do not implement it.
 * This code bypasses the libc when the VDSO is detected. It should only be
 * used when it's sure that the libc really does not support the VDSO, but
 * fixing the libc is preferred. Using the VDSO can improve the overall
 * performance by about 10%.
 */

#if defined(__linux__) && defined(__i386__)
/* Silently ignore other platforms to be friendly with distro packagers */

#include <dlfcn.h>
#include <sys/mman.h>

void int80(void);                /* declared in the assembler code */
static void *vsyscall = &int80;  /* initialize vsyscall to use int80 by default */
static __attribute__((used)) unsigned int back_ebx;

/* now we redefine some frequently used syscalls. Epoll_create is defined too
 * in order to replace old disabled implementations.
 */
asm
(
    "epoll_create: .GLOBL epoll_create\n"
    "   mov $0xfe, %eax\n"
    "   mov %ebx, back_ebx\n"
    "   mov 4(%esp), %ebx\n"
    "   jmp do_syscall\n"

    "epoll_ctl: .GLOBL epoll_ctl\n"
    "   push %esi\n"
    "   mov $0xff, %eax\n"
    "   mov %ebx, back_ebx\n"
    "   mov 20(%esp), %esi\n"
    "   mov 16(%esp), %edx\n"
    "   mov 12(%esp), %ecx\n"
    "   mov 8(%esp), %ebx\n"
    "   call do_syscall\n"
    "   pop %esi\n"
    "   ret\n"

    "epoll_wait: .GLOBL epoll_wait\n"
    "   push %esi\n"
    "   mov $0x100, %eax\n"
    "   mov %ebx, back_ebx\n"
    "   mov 20(%esp), %esi\n"
    "   mov 16(%esp), %edx\n"
    "   mov 12(%esp), %ecx\n"
    "   mov 8(%esp), %ebx\n"
    "   call do_syscall\n"
    "   pop %esi\n"
    "   ret\n"

    "splice: .GLOBL splice\n"
    "   push %ebp\n"
    "   push %edi\n"
    "   push %esi\n"
    "   mov $0x139, %eax\n"
    "   mov %ebx, back_ebx\n"
    "   mov 36(%esp), %ebp\n"
    "   mov 32(%esp), %edi\n"
    "   mov 28(%esp), %esi\n"
    "   mov 24(%esp), %edx\n"
    "   mov 20(%esp), %ecx\n"
    "   mov 16(%esp), %ebx\n"
    "   call do_syscall\n"
    "   pop %esi\n"
    "   pop %edi\n"
    "   pop %ebp\n"
    "   ret\n"

    "close: .GLOBL close\n"
    "   mov $0x06, %eax\n"
    "   mov %ebx, back_ebx\n"
    "   mov 4(%esp), %ebx\n"
    "   jmp do_syscall\n"

    "gettimeofday: .GLOBL gettimeofday\n"
    "   mov $0x4e, %eax\n"
    "   mov %ebx, back_ebx\n"
    "   mov 8(%esp), %ecx\n"
    "   mov 4(%esp), %ebx\n"
    "   jmp do_syscall\n"

    "fcntl: .GLOBL fcntl\n"
    "   mov $0xdd, %eax\n"
    "   mov %ebx, back_ebx\n"
    "   mov 12(%esp), %edx\n"
    "   mov 8(%esp), %ecx\n"
    "   mov 4(%esp), %ebx\n"
    "   jmp do_syscall\n"

    "socket: .GLOBL socket\n"
    "   mov $0x01, %eax\n"
    "   jmp socketcall\n"

    "bind: .GLOBL bind\n"
    "   mov $0x02, %eax\n"
    "   jmp socketcall\n"

    "connect: .GLOBL connect\n"
    "   mov $0x03, %eax\n"
    "   jmp socketcall\n"

    "listen: .GLOBL listen\n"
    "   mov $0x04, %eax\n"
    "   jmp socketcall\n"

    "accept: .GLOBL accept\n"
    "   mov $0x05, %eax\n"
    "   jmp socketcall\n"

    "accept4: .GLOBL accept4\n"
    "   mov $0x12, %eax\n"
    "   jmp socketcall\n"

    "getsockname: .GLOBL getsockname\n"
    "   mov $0x06, %eax\n"
    "   jmp socketcall\n"

    "send: .GLOBL send\n"
    "   mov $0x09, %eax\n"
    "   jmp socketcall\n"

    "recv: .GLOBL recv\n"
    "   mov $0x0a, %eax\n"
    "   jmp socketcall\n"

    "shutdown: .GLOBL shutdown\n"
    "   mov $0x0d, %eax\n"
    "   jmp socketcall\n"

    "setsockopt: .GLOBL setsockopt\n"
    "   mov $0x0e, %eax\n"
    "   jmp socketcall\n"

    "getsockopt: .GLOBL getsockopt\n"
    "   mov $0x0f, %eax\n"
    "   jmp socketcall\n"

    "socketcall:\n"
    "   mov %ebx, back_ebx\n"
    "   mov %eax, %ebx\n"
    "   mov $0x66, %eax\n"
    "   lea 4(%esp), %ecx\n"
    /* fall through */

    "do_syscall:\n"
    "   call *vsyscall\n"          // always valid, may be int80 or vsyscall
    "   mov  back_ebx, %ebx\n"
    "   cmpl $0xfffff000, %eax\n"  // consider -4096..-1 for errno
    "   jae 0f\n"
    "   ret\n"
    "0:\n"               // error handling
    "   neg %eax\n"      // get errno value
    "   push %eax\n"     // save it
    "   call __errno_location\n"
    "   popl (%eax)\n"   // store the pushed errno into the proper location
    "   mov $-1, %eax\n" // and return -1
    "   ret\n"

    "int80:\n"           // default compatible calling convention
    "   int $0x80\n"
    "   ret\n"
);

__attribute__((constructor))
static void __i386_linux_vsyscall_init(void)
{
	/* We can get the pointer by resolving the __kernel_vsyscall symbol
	 * from the "linux-gate.so.1" virtual shared object, but this requires
	 * libdl. Or we can also know that the vsyscall pointer is always
	 * located at 0xFFFFE018 when /proc/sys/abi/vsyscall32 contains the
	 * default value 2. So we can use that once we've checked that we can
	 * access it without faulting. The dlsym method will also work when
	 * vsyscall32 = 1, which randomizes the VDSO address.
	 */
#ifdef USE_VSYSCALL_DLSYM
	void *handle = dlopen("linux-gate.so.1", RTLD_NOW);
	if (handle) {
		void *ptr;

		ptr = dlsym(handle, "__kernel_vsyscall_kml");
		if (!ptr)
			ptr = dlsym(handle, "__kernel_vsyscall");
		if (ptr)
			vsyscall = ptr;
		dlclose(handle);
	}
#else
	/* Heuristic: trying to mprotect() the VDSO area will only succeed if
	 * it is mapped.
	 */
	if (mprotect((void *)0xffffe000, 4096, PROT_READ|PROT_EXEC) == 0) {
		unsigned long ptr = *(unsigned long *)0xFFFFE018;  /* VDSO is mapped */
		if ((ptr & 0xFFFFE000) == 0xFFFFE000)
			vsyscall = (void *)ptr;
	}
#endif
}

#endif /* defined(__linux__) && defined(__i386__) */
