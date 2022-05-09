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

#include <haproxy/atomic.h>
#include <haproxy/compiler.h>

/* quick debugging hack, should really be removed ASAP */
#ifdef DEBUG_FULL
#define DPRINTF(x...) fprintf(x)
#else
#define DPRINTF(x...)
#endif

#define DUMP_TRACE() do { extern void ha_backtrace_to_stderr(void); ha_backtrace_to_stderr(); } while (0)

static inline __attribute((always_inline)) void ha_crash_now(void)
{
#if __GNUC_PREREQ__(5, 0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wnull-dereference"
#endif
	*(volatile char *)1 = 0;
#if __GNUC_PREREQ__(5, 0)
#pragma GCC diagnostic pop
#endif
	my_unreachable();
}

#ifdef DEBUG_USE_ABORT
/* abort() is better recognized by code analysis tools */
#define ABORT_NOW() do { DUMP_TRACE(); abort(); } while (0)
#else
/* More efficient than abort() because it does not mangle the
 * stack and stops at the exact location we need.
 */
#define ABORT_NOW() do { DUMP_TRACE(); ha_crash_now(); } while (0)
#endif

/* This is the generic low-level macro dealing with conditional warnings and
 * bugs. The caller decides whether to crash or not and what prefix and suffix
 * to pass. The macro returns the boolean value of the condition as an int for
 * the case where it wouldn't die. The <crash> flag is made of:
 *  - crash & 1: crash yes/no;
 *  - crash & 2: taint as bug instead of warn
 */
#define _BUG_ON(cond, file, line, crash, pfx, sfx)			\
	__BUG_ON(cond, file, line, crash, pfx, sfx)

#define __BUG_ON(cond, file, line, crash, pfx, sfx)                     \
	(unlikely(cond) ? ({						\
		complain(NULL, "\n" pfx "condition \"" #cond "\" matched at " file ":" #line "" sfx "\n", crash); \
		if (crash & 1)						\
			ABORT_NOW();					\
		else							\
			DUMP_TRACE();					\
		1; /* let's return the true condition */		\
	}) : 0)

/* This one is equivalent except that it only emits the message once by
 * maintaining a static counter. This may be used with warnings to detect
 * certain unexpected conditions in field. Later on, in cores it will be
 * possible to verify these counters.
 */
#define _BUG_ON_ONCE(cond, file, line, crash, pfx, sfx)			\
	__BUG_ON_ONCE(cond, file, line, crash, pfx, sfx)

#define __BUG_ON_ONCE(cond, file, line, crash, pfx, sfx)                \
	(unlikely(cond) ? ({						\
		static int __match_count_##line;			\
		complain(&__match_count_##line, "\n" pfx "condition \"" #cond "\" matched at " file ":" #line "" sfx "\n", crash); \
		if (crash & 1)						\
			ABORT_NOW();					\
		else							\
			DUMP_TRACE();					\
		1; /* let's return the true condition */		\
	}) : 0)

/* DEBUG_STRICT enables/disables runtime checks on condition <cond>
 * DEBUG_STRICT_ACTION indicates the level of verification on the rules when
 * <cond> is true:
 *
 *    macro   BUG_ON()    WARN_ON()    CHECK_IF()
 * value  0    warn         warn         warn
 *        1    CRASH        warn         warn
 *        2    CRASH        CRASH        warn
 *        3    CRASH        CRASH        CRASH
 */

/* The macros below are for general use */
#if defined(DEBUG_STRICT)
# if defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION < 1)
/* Lowest level: BUG_ON() warns, WARN_ON() warns, CHECK_IF() warns */
#  define BUG_ON(cond)       _BUG_ON     (cond, __FILE__, __LINE__, 2, "WARNING: bug ",   " (not crashing but process is untrusted now, please report to developers)")
#  define WARN_ON(cond)      _BUG_ON     (cond, __FILE__, __LINE__, 0, "WARNING: warn ",  " (please report to developers)")
#  define CHECK_IF(cond)     _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)")
# elif !defined(DEBUG_STRICT_ACTION) || (DEBUG_STRICT_ACTION == 1)
/* default level: BUG_ON() crashes, WARN_ON() warns, CHECK_IF() warns */
#  define BUG_ON(cond)       _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "")
#  define WARN_ON(cond)      _BUG_ON     (cond, __FILE__, __LINE__, 0, "WARNING: warn ",  " (please report to developers)")
#  define CHECK_IF(cond)     _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)")
# elif defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION == 2)
/* Stricter level: BUG_ON() crashes, WARN_ON() crashes, CHECK_IF() warns */
#  define BUG_ON(cond)       _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "")
#  define WARN_ON(cond)      _BUG_ON     (cond, __FILE__, __LINE__, 1, "FATAL: warn ",    "")
#  define CHECK_IF(cond)     _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)")
# elif defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION >= 3)
/* Developer/CI level: BUG_ON() crashes, WARN_ON() crashes, CHECK_IF() crashes */
#  define BUG_ON(cond)       _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "")
#  define WARN_ON(cond)      _BUG_ON     (cond, __FILE__, __LINE__, 1, "FATAL: warn ",    "")
#  define CHECK_IF(cond)     _BUG_ON_ONCE(cond, __FILE__, __LINE__, 1, "FATAL: check ",   "")
# endif
#else
#  define BUG_ON(cond)
#  define WARN_ON(cond)
#  define CHECK_IF(cond)
#endif

/* These macros are only for hot paths and remain disabled unless DEBUG_STRICT is 2 or above.
 * Only developers/CI should use these levels as they may significantly impact performance by
 * enabling checks in sensitive areas.
 */
#if defined(DEBUG_STRICT) && (DEBUG_STRICT > 1)
# if defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION < 1)
/* Lowest level: BUG_ON() warns, CHECK_IF() warns */
#  define BUG_ON_HOT(cond)   _BUG_ON_ONCE(cond, __FILE__, __LINE__, 2, "WARNING: bug ",   " (not crashing but process is untrusted now, please report to developers)")
#  define CHECK_IF_HOT(cond) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)")
# elif !defined(DEBUG_STRICT_ACTION) || (DEBUG_STRICT_ACTION < 3)
/* default level: BUG_ON() crashes, CHECK_IF() warns */
#  define BUG_ON_HOT(cond)   _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "")
#  define CHECK_IF_HOT(cond) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)")
# elif defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION >= 3)
/* Developer/CI level: BUG_ON() crashes, CHECK_IF() crashes */
#  define BUG_ON_HOT(cond)   _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "")
#  define CHECK_IF_HOT(cond) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 1, "FATAL: check ",   "")
# endif
#else
#  define BUG_ON_HOT(cond)
#  define CHECK_IF_HOT(cond)
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


/* handle 'tainted' status */
enum tainted_flags {
	TAINTED_CONFIG_EXP_KW_DECLARED = 0x00000001,
	TAINTED_ACTION_EXP_EXECUTED    = 0x00000002,
	TAINTED_CLI_EXPERT_MODE        = 0x00000004,
	TAINTED_CLI_EXPERIMENTAL_MODE  = 0x00000008,
	TAINTED_WARN                   = 0x00000010, /* a WARN_ON triggered */
	TAINTED_BUG                    = 0x00000020, /* a BUG_ON triggered */
};

/* this is a bit field made of TAINTED_*, and is declared in haproxy.c */
extern unsigned int tainted;

void complain(int *counter, const char *msg, int taint);

static inline void mark_tainted(const enum tainted_flags flag)
{
	HA_ATOMIC_OR(&tainted, flag);
}

static inline unsigned int get_tainted()
{
	return HA_ATOMIC_LOAD(&tainted);
}

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
	HA_WEAK("__start_mem_stats");					\
	HA_WEAK("__stop_mem_stats");					\
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
	HA_WEAK("__start_mem_stats");					\
	HA_WEAK("__stop_mem_stats");					\
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
	HA_WEAK("__start_mem_stats");					\
	HA_WEAK("__stop_mem_stats");					\
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
	HA_WEAK("__start_mem_stats");					\
	HA_WEAK("__stop_mem_stats");					\
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
	HA_WEAK("__start_mem_stats");					\
	HA_WEAK("__stop_mem_stats");					\
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
	HA_WEAK("__start_mem_stats");					\
	HA_WEAK("__stop_mem_stats");					\
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
