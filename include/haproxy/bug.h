/*
 * include/haproxy/bug.h
 * Assertions and instant crash macros needed everywhere.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _HAPROXY_BUG_H
#define _HAPROXY_BUG_H

#include <haproxy/compiler.h>

/* quick debugging hack, should really be removed ASAP */
#ifdef DEBUG_FULL
#define DPRINTF(x...) fprintf(x)
#else
#define DPRINTF(x...)
#endif

/* This abort is more efficient than abort() because it does not mangle the
 * stack and stops at the exact location we need.
 */
#define ABORT_NOW() (*(volatile int*)1=0)

/* BUG_ON: complains if <cond> is true when DEBUG_STRICT or DEBUG_STRICT_NOCRASH
 * are set, does nothing otherwise. With DEBUG_STRICT in addition it immediately
 * crashes using ABORT_NOW() above.
 */
#if defined(DEBUG_STRICT) || defined(DEBUG_STRICT_NOCRASH)
#if defined(DEBUG_STRICT)
#define CRASH_NOW() ABORT_NOW()
#else
#define CRASH_NOW()
#endif

#define BUG_ON(cond) _BUG_ON(cond, __FILE__, __LINE__)
#define _BUG_ON(cond, file, line) __BUG_ON(cond, file, line)
#define __BUG_ON(cond, file, line)                                             \
	do {                                                                   \
		if (unlikely(cond)) {					       \
			const char msg[] = "\nFATAL: bug condition \"" #cond "\" matched at " file ":" #line "\n"; \
			DISGUISE(write(2, msg, __builtin_strlen(msg)));        \
			CRASH_NOW();                                           \
		}                                                              \
	} while (0)
#else
#undef CRASH_NOW
#define BUG_ON(cond)
#endif

#endif /* _HAPROXY_BUG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
