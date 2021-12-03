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

#ifdef DEBUG_USE_ABORT
/* abort() is better recognized by code analysis tools */
#define ABORT_NOW() do { extern void ha_backtrace_to_stderr(void); ha_backtrace_to_stderr(); abort(); } while (0)
#else
/* More efficient than abort() because it does not mangle the
  * stack and stops at the exact location we need.
  */
#define ABORT_NOW() do { extern void ha_backtrace_to_stderr(void); ha_backtrace_to_stderr(); (*(volatile int*)1=0); } while (0)
#endif

/* BUG_ON: complains if <cond> is true when DEBUG_STRICT or DEBUG_STRICT_NOCRASH
 * are set, does nothing otherwise. With DEBUG_STRICT in addition it immediately
 * crashes using ABORT_NOW() above.
 */
#if defined(DEBUG_STRICT) || defined(DEBUG_STRICT_NOCRASH)
#if defined(DEBUG_STRICT)
#define CRASH_NOW() ABORT_NOW()
#else
#define CRASH_NOW() do { extern void ha_backtrace_to_stderr(void); ha_backtrace_to_stderr(); } while (0)
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

/* When not optimizing, clang won't remove that code, so only compile it in when optimizing */
#if defined(__GNUC__) && defined(__OPTIMIZE__)
#define HA_LINK_ERROR(what)                                                  \
	do {                                                                 \
		/* provoke a build-time error */                             \
		extern volatile int what;                                    \
		what = 1;                                                    \
	} while (0)
#else
#define HA_LINK_ERROR(what)                                                  \
	do {                                                                 \
	} while (0)
#endif /* __OPTIMIZE__ */

/* more reliable free() that clears the pointer */
#define ha_free(x) do {							\
		typeof(x) __x = (x);					\
		if (__builtin_constant_p((x)) || __builtin_constant_p(*(x))) { \
			HA_LINK_ERROR(call_to_ha_free_attempts_to_free_a_constant); \
		}							\
		free(*__x);						\
		*__x = NULL;						\
	} while (0)

#if defined(DEBUG_MEM_STATS)
#include <stdlib.h>
#include <string.h>

/* Memory allocation statistics are centralized into a global "mem_stats"
 * section. This will not work with some linkers.
 */
enum {
	MEM_STATS_TYPE_UNSET  = 0,
	MEM_STATS_TYPE_CALLOC,
	MEM_STATS_TYPE_FREE,
	MEM_STATS_TYPE_MALLOC,
	MEM_STATS_TYPE_REALLOC,
	MEM_STATS_TYPE_STRDUP,
};

struct mem_stats {
	size_t calls;
	size_t size;
	const char *file;
	int line;
	int type;
};

#undef calloc
#define calloc(x,y)  ({							\
	size_t __x = (x); size_t __y = (y);				\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"))) = { \
		.file = __FILE__, .line = __LINE__,			\
		.type = MEM_STATS_TYPE_CALLOC,				\
	};								\
	__asm__(".globl __start_mem_stats");				\
	__asm__(".globl __stop_mem_stats");				\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __x * __y);				\
	calloc(__x,__y);						\
})

/* note: we can't redefine free() because we have a few variables and struct
 * members called like this.
 */
#undef __free
#define __free(x)  ({							\
	void *__x = (x);						\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"))) = { \
		.file = __FILE__, .line = __LINE__,			\
		.type = MEM_STATS_TYPE_FREE,				\
	};								\
	__asm__(".globl __start_mem_stats");				\
	__asm__(".globl __stop_mem_stats");				\
	if (__x)							\
		_HA_ATOMIC_INC(&_.calls);				\
	free(__x);							\
})

#undef ha_free
#define ha_free(x)  ({							\
	typeof(x) __x = (x);						\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"))) = { \
		.file = __FILE__, .line = __LINE__,			\
		.type = MEM_STATS_TYPE_FREE,				\
	};								\
	__asm__(".globl __start_mem_stats");				\
	__asm__(".globl __stop_mem_stats");				\
	if (__builtin_constant_p((x)) || __builtin_constant_p(*(x))) {  \
		HA_LINK_ERROR(call_to_ha_free_attempts_to_free_a_constant); \
	}								\
	if (*__x)							\
		_HA_ATOMIC_INC(&_.calls);				\
	free(*__x);							\
	*__x = NULL;							\
})

#undef malloc
#define malloc(x)  ({							\
	size_t __x = (x);						\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"))) = { \
		.file = __FILE__, .line = __LINE__,			\
		.type = MEM_STATS_TYPE_MALLOC,				\
	};								\
	__asm__(".globl __start_mem_stats");				\
	__asm__(".globl __stop_mem_stats");				\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __x);					\
	malloc(__x);							\
})

#undef realloc
#define realloc(x,y)  ({						\
	void *__x = (x); size_t __y = (y);				\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"))) = { \
		.file = __FILE__, .line = __LINE__,			\
		.type = MEM_STATS_TYPE_REALLOC,				\
	};								\
	__asm__(".globl __start_mem_stats");				\
	__asm__(".globl __stop_mem_stats");				\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __y);					\
	realloc(__x,__y);						\
})

#undef strdup
#define strdup(x)  ({							\
	const char *__x = (x); size_t __y = strlen(__x); 		\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"))) = { \
		.file = __FILE__, .line = __LINE__,			\
		.type = MEM_STATS_TYPE_STRDUP,				\
	};								\
	__asm__(".globl __start_mem_stats");				\
	__asm__(".globl __stop_mem_stats");				\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __y);					\
	strdup(__x);							\
})
#endif /* DEBUG_MEM_STATS*/

#endif /* _HAPROXY_BUG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
