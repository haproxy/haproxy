/*
 * include/types/signal.h
 * Asynchronous signal delivery functions descriptors.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _TYPES_SIGNAL_H
#define _TYPES_SIGNAL_H


#include <signal.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>

/* flags for -> flags */
#define SIG_F_ONE_SHOOT         0x0001  /* unregister handler before calling it */
#define SIG_F_TYPE_FCT          0x0002  /* handler is a function + arg */
#define SIG_F_TYPE_TASK         0x0004  /* handler is a task + reason */

/* Define WDTSIG if available */
#if defined(USE_RT) && (_POSIX_TIMERS > 0) && defined(_POSIX_THREAD_CPUTIME)


/* We'll deliver SIGALRM when we've run out of CPU as it's not intercepted by
 * gdb by default.
 */
#define WDTSIG SIGALRM

#endif

#ifdef USE_THREAD_DUMP
/* The signal to trigger a debug dump on a thread is SIGURG. It has the benefit
 * of not stopping gdb by default, so that issuing "show threads" in a process
 * being debugged has no adverse effect.
 */
#define DEBUGSIG SIGURG

#endif

/* those are highly dynamic and stored in pools */
struct sig_handler {
	struct list list;
	void *handler;                  /* function to call or task to wake up */
	int arg;                        /* arg to pass to function, or signals*/
	int flags;                      /* SIG_F_* */
};

/* one per signal */
struct signal_descriptor {
	int count;                      /* number of times raised */
	struct list handlers;           /* sig_handler */
};

#endif /* _TYPES_SIGNAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
